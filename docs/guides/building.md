# Building

## Requirements

- Zig 0.15.2+
- macOS 13+ or Linux

## Static Library

```bash
zig build -Doptimize=ReleaseFast
```

This produces `zig-out/lib/libctap2.a` with the C header at `include/ctap2.h`.

## With just

```bash
just build         # ReleaseFast static library
just test-all      # unit + PBT tests
just info          # show library stats
just               # list all recipes
```

## With Nix

```bash
nix develop        # dev shell (zig, just, detect-secrets, pre-commit)
nix build          # build library package
```

## Running Tests

```bash
# Unit tests (no hardware required)
zig build test

# Property-based tests (1000 iterations each)
zig build test-pbt

# Hardware tests (requires YubiKey connected)
YUBIKEY_TESTS=1 zig build test-hardware
```

## Cross-Compilation

The library supports cross-compilation to any Zig target. IOKit and CoreFoundation frameworks are not linked at build time -- they resolve at final link time in the consuming application (e.g., via Xcode `OTHER_LDFLAGS`).

```bash
# Build for specific target
zig build -Dtarget=aarch64-macos
zig build -Dtarget=x86_64-linux
```

## macOS Entitlements

When embedding in a hardened-runtime macOS app, add to your entitlements:

```xml
<key>com.apple.security.device.usb</key>
<true/>
```

The user must grant **Input Monitoring** permission in System Settings > Privacy & Security.

No other entitlements needed -- no `com.apple.developer.web-browser.public-key-credential`, no provisioning profile.
