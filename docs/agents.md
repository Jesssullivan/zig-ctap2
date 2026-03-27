# AGENTS.md

Instructions for AI agents working with this codebase.

## Project

zig-ctap2 is a portable CTAP2/FIDO2 library written in Zig. It communicates directly with USB HID security keys via IOKit (macOS) and hidraw (Linux), exposing a C FFI for integration into Swift, C, and other languages.

## Build

```bash
zig build -Doptimize=ReleaseFast    # static library
zig build test                       # unit tests
zig build test-pbt                   # property-based tests
```

## Structure

- `include/ctap2.h` -- Public C API header
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

## Testing

- Unit tests: `zig build test` (no hardware required)
- Property-based tests: `zig build test-pbt` (1000 iterations)
- Hardware tests: `YUBIKEY_TESTS=1 zig build test-hardware` (YubiKey required)
