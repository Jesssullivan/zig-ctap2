# Linux hidraw Permissions

zig-ctap2 talks to USB security keys on Linux through `/dev/hidraw*`. By default these device nodes are owned by `root:root` with no group access, so an unprivileged process trying to enumerate or open a FIDO key will silently see "no devices" or, more often, see the device but fail to open it.

This guide covers the permission setup that makes that flow work, scoped to hidraw access. It does not cover browser WebAuthn policy, platform passkey integration, or anything that runs above the hidraw layer -- those are out of scope for this library.

## Recognizing the access failure

When zig-ctap2 sees one or more FIDO devices on the bus but cannot open any of them, the C ABI returns:

```c
#define CTAP2_ERR_NOT_ACCESSIBLE -11
```

The Zig API surfaces the same condition as `error.DevicesNotAccessible`. The mapping happens in `src/hid_linux.zig`:

```zig
// src/hid_linux.zig
if (devices.items.len == 0 and fido_found > 0 and open_failed == fido_found) {
    return Error.DevicesNotAccessible;
}
```

So `CTAP2_ERR_NOT_ACCESSIBLE` (or `error.DevicesNotAccessible`) on Linux almost always means: udev sees the FIDO interface, but the calling user is not allowed to `open(O_RDWR)` the matching `/dev/hidraw*` node.

A useful sanity check before chasing CTAP2-level bugs:

```sh
ls -l /dev/hidraw*           # look at owner/group/mode of each node
```

If the device you expect to use is `crw-rw---- root root`, this guide is your fix.

## Granting access without sudo

The portable answer is the same on every distro: install a udev rule that loosens the mode on FIDO interfaces, plug or replug the key, and never run zig-ctap2 as `root`.

Most distros either ship such a rule already (in a security-key package) or expect you to drop one in `/etc/udev/rules.d/`.

### Common security-key packages by distro family

| Family | Package | Notes |
|---|---|---|
| Debian / Ubuntu | `libu2f-udev` (Debian, Ubuntu, Mint) | Installs `/lib/udev/rules.d/70-u2f.rules` covering Yubico, SoloKeys, Nitrokey, OnlyKey, etc. |
| Fedora / RHEL | `libu2f-host` (older) or `pam-u2f` (newer Fedora) | Pulls the udev rules in. On modern Fedora, FIDO rules are also shipped via `systemd-udev` for common vendors. |
| Arch / Manjaro | `libfido2` (provides `70-u2f.rules`) | `pacman -S libfido2`. |
| openSUSE | `libfido2-udev-rules` (or `libfido2`) | `zypper in libfido2`. |
| NixOS | `services.udev.packages = [ pkgs.libfido2 ];` plus `programs.firefox.enableU2F` if relevant | Rebuild with `nixos-rebuild switch`. |
| Gentoo | `app-crypt/libfido2` with the `udev` USE flag | Re-emerge after toggling. |
| Alpine | `libfido2` plus `eudev` rules in `/etc/udev/rules.d/` | The libfido2 package installs the rule snippet. |

After installing one of these packages, replug the key (`udevadm trigger` will not re-evaluate access for an already-attached device) and re-check `ls -l /dev/hidraw*`. The mode should now be `crw-rw-r--` with group ownership pointing at `plugdev`, `wheel`, or a vendor-specific group depending on the rule.

If the rule grants access through a group, your user must be in that group. The `libu2f-udev` rules use the `plugdev` group on Debian-style systems:

```sh
sudo usermod -aG plugdev "$USER"
# log out and back in for the new group membership to take effect
```

### Drop-in udev rule (no distro package)

If your distro does not ship one and you do not want to install a package, drop a minimal rule in `/etc/udev/rules.d/70-fido.rules`:

```
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", \
  ATTRS{interface_protocol}=="00", ATTRS{bInterfaceClass}=="03", \
  ATTRS{bInterfaceSubClass}=="00", \
  TAG+="uaccess", GROUP="plugdev", MODE="0660"
```

Then:

```sh
sudo udevadm control --reload-rules
sudo udevadm trigger
# replug the key
```

`TAG+="uaccess"` is the modern (logind / seat-aware) way to grant access to the user who is currently logged in on a graphical session. `GROUP="plugdev", MODE="0660"` is the fallback for headless / SSH-only sessions where uaccess does not fire.

This rule is intentionally narrow: it matches `interface_protocol == 0` and HID class `03` so it does not loosen permissions on every USB HID device on the bus -- mice, keyboards, and game controllers stay locked down.

## Validating device enumeration without creating credentials

zig-ctap2 exposes a count-only entry point that opens each FIDO interface, sends nothing, and returns immediately. It is the right thing to call from a smoke test because it surfaces `CTAP2_ERR_NOT_ACCESSIBLE` without touching the credential store on the key:

```c
#include "ctap2.h"
#include <stdio.h>

int main(void) {
    int count = ctap2_device_count();
    if (count == -11) {
        fprintf(stderr, "FIDO devices present but not accessible -- check udev rules\n");
        return 1;
    }
    if (count < 0) {
        fprintf(stderr, "ctap2_device_count failed: %d\n", count);
        return 1;
    }
    printf("Found %d FIDO devices\n", count);
    return 0;
}
```

From Zig:

```zig
const ctap2 = @import("zig-ctap2");

pub fn main() !void {
    var allocator = std.heap.page_allocator;
    const devices = ctap2.hid_linux.enumerate(allocator) catch |err| switch (err) {
        error.DevicesNotAccessible => {
            std.debug.print("FIDO devices present but not accessible -- check udev rules\n", .{});
            return;
        },
        else => return err,
    };
    defer allocator.free(devices);
    std.debug.print("Found {d} FIDO devices\n", .{devices.len});
}
```

Neither call sends a `getInfo`, `makeCredential`, or `getAssertion` to the device, so there is no PIN prompt, no user presence touch, and no risk of dirtying state on the authenticator. A run that prints `Found N FIDO devices` with `N >= 1` confirms the udev path is working end to end.

## Common gotchas

- **`sudo` masks the problem.** Running the example as root will succeed even when your user account cannot. If your test only works under `sudo`, the udev rule is missing or the user is not in the right group.
- **Replug after rule changes.** udev only evaluates rules at device-add time. After editing `/etc/udev/rules.d/`, run `sudo udevadm control --reload-rules` and physically replug the key.
- **Containers and Flatpak.** Inside a container or Flatpak sandbox, `/dev/hidraw*` is not mapped in by default. You need an explicit `--device=/dev/hidraw0` (Docker / Podman) or a `device=all` Flatpak override; the host udev rule does not propagate into the sandbox.
- **WSL2.** WSL2 does not see USB devices without `usbipd-win`. Forward the FIDO interface from Windows with `usbipd attach` before expecting hidraw to find it.

## Out of scope

This guide intentionally does not cover:

- Browser WebAuthn policy or origin/RP rules.
- Passkey synchronization (iCloud Keychain, Google Password Manager, etc.).
- macOS IOKit access -- see [Apple Interop](apple-interop.md).
- TPM-backed credentials or platform authenticators.

Those layers sit above the hidraw transport that zig-ctap2 owns.
