# AGENTS.md

Instructions for AI agents working with this codebase.

## Project

zig-ctap2 is a portable CTAP2/FIDO2 USB HID library written in Zig. It communicates with external security keys via IOKit (macOS) and hidraw (Linux), exposing a C FFI for integration into Swift, C, and other languages.

## Build

```bash
zig build -Doptimize=ReleaseFast    # static library
zig build test                       # unit tests
zig build test-pbt                   # property-based tests
zig build example                    # C example build
```

## Structure

- `include/ctap2.h` -- Public C API header
- `src/root.zig` -- Zig package API root
- `src/ffi.zig` -- C FFI export layer
- `src/ctap2.zig` -- CTAP2 command encoding and response parsing
- `src/cbor.zig` -- CBOR codec (CTAP2 subset)
- `src/ctaphid.zig` -- CTAPHID packet framing
- `src/hid.zig` -- Platform HID abstraction
- `src/pin.zig` -- PIN protocol v2 (ECDH, AES-256-CBC)
- `tests/` -- Property-based tests

## Conventions

- All exported C functions use `snake_case` with `ctap2_` prefix
- Zig internal functions use `camelCase`
- All C functions are blocking with timeouts and thread-safe
- Output data is written to caller-provided buffers
- Error codes: 0 = success, negative = library error, positive = CTAP2 device status byte
- Platform-specific code lives in `_macos.zig` / `_linux.zig` suffixed files
- This repo does not replace SwiftUI, AppKit, UIKit, Cocoa, AuthenticationServices UI, passkeys/iCloud Keychain, platform authenticators, browser WebAuthn policy, Secure Enclave, LocalAuthentication, biometric prompts, attestation policy validation, origin/RP policy, account sync, or application UI lifecycle

## Testing

- Unit tests: `zig build test` (no hardware required)
- Property-based tests: `zig build test-pbt` (1000 iterations)
- Hardware tests: `YUBIKEY_TESTS=1 zig build test-hardware` (YubiKey required)
