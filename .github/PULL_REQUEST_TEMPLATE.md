## Summary

-

## Scope

- [ ] Keeps the existing C ABI stable, or documents any ABI addition in `include/ctap2.h`, README, and docs.
- [ ] Keeps C FFI exports in `src/ffi.zig`.
- [ ] Keeps Zig package exports routed through `src/root.zig`.
- [ ] Keeps CTAP2 USB HID scope clear: no claims of SwiftUI, AppKit, UIKit, Cocoa, AuthenticationServices UI, passkeys/iCloud Keychain, platform authenticator, Secure Enclave, LocalAuthentication, browser policy, or full WebAuthn replacement.
- [ ] Updates docs or examples when public behavior changes.

## Validation

- [ ] `zig build test`
- [ ] `zig build test-pbt`
- [ ] `zig build docs`
- [ ] `zig build example`
- [ ] `zig build -Doptimize=ReleaseFast`

## Notes

Link related issues and call out any platform-specific caveats.
