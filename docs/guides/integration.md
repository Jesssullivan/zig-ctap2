# Integration Guide

## As a Zig Dependency

Add zig-ctap2 as a dependency in your `build.zig.zon`:

```zig
.dependencies = .{
    .zig_ctap2 = .{
        .url = "https://github.com/Jesssullivan/zig-ctap2/archive/refs/heads/main.tar.gz",
    },
},
```

Then in `build.zig`:

```zig
const ctap2_dep = b.dependency("zig_ctap2", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig-ctap2", ctap2_dep.module("zig-ctap2"));
```

## As a C Static Library

Build the library:

```bash
zig build -Doptimize=ReleaseFast
```

Link against `zig-out/lib/libctap2.a` and include `include/ctap2.h`:

```c
#include "ctap2.h"

int main() {
    int count = ctap2_device_count();
    printf("Found %d FIDO2 devices\n", count);
    return 0;
}
```

Compile:

```bash
gcc -o example example.c -Iinclude -Lzig-out/lib -lctap2
```

## Swift Integration (Xcode)

1. Add zig-ctap2 as a git submodule or copy `libctap2.a` + `ctap2.h` into your project
2. Add `ctap2.h` to your bridging header
3. Link `libctap2.a` in your target's build settings
4. Add `IOKit.framework` and `CoreFoundation.framework` to linked frameworks
5. Add USB entitlement to your `.entitlements` file

```swift
import Foundation

let deviceCount = ctap2_device_count()
print("Found \(deviceCount) FIDO2 devices")
```

## Git Submodule

```bash
git submodule add https://github.com/Jesssullivan/zig-ctap2.git vendor/ctap2
```

## WebView or Native App Integration

For WebView, browser-shell, or native app integrations, keep the responsibilities separate: zig-ctap2 handles external-authenticator CTAP2 USB HID operations through C FFI; the host application remains responsible for WebAuthn JSON, origin/RP policy, mediation UX, attestation policy, and credential persistence.
