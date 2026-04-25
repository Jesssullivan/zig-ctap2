# AGENTS.md -- zig-ctap2

## Persona

You are working on zig-ctap2, a portable CTAP2/FIDO2 library written in Zig with a C FFI surface. It communicates directly with USB security keys (YubiKey, SoloKeys, etc.) over HID -- IOKit on macOS, hidraw on Linux. No Apple entitlements or platform authentication frameworks needed. Part of the [Tinyland Zig Libraries](https://libs.tinyland.dev).

## Stack

- **Language:** Zig 0.14.1+
- **Output:** Static C library (`libctap2.a`) + Zig module
- **Dependencies:** None (pure Zig `std.crypto` for ECDH/AES/SHA/HMAC)
- **Header:** `include/ctap2.h` (17 C FFI functions)
- **Platform I/O:** IOKit + CoreFoundation (macOS), hidraw (Linux)
- **Tests:** Unit tests per module + property-based tests (1000 iterations) + hardware integration tests (YubiKey)
- **Docs:** Zig autodoc (`zig build docs`)

## Structure

```
src/ffi.zig          C FFI exports (17 functions)
src/cbor.zig         Minimal CBOR encoder/decoder (CTAP2 subset)
src/ctap2.zig        CTAP2 command encoding and response parsing
src/ctaphid.zig      CTAPHID transport framing (64-byte packets)
src/pin.zig          Client PIN protocol v2 (ECDH P-256 + AES-256-CBC + HMAC-SHA-256)
src/hid.zig          Platform-selected HID transport
src/hid_macos.zig    macOS USB HID via IOKit
src/hid_linux.zig    Linux USB HID via hidraw
include/ctap2.h      C header
tests/pbt_*.zig      Property-based tests
tests/hardware_test.zig  Hardware integration tests (YubiKey)
examples/            C usage examples
```

## Commands

```bash
zig build                              # static library -> zig-out/lib/
zig build -Doptimize=ReleaseFast       # optimized build
zig build test                         # unit tests (no hardware)
zig build test-pbt                     # property-based tests (1000 iterations)
zig build test-hardware                # hardware tests (needs YubiKey)
zig build docs                         # generate API documentation
```

## Style

- Format with `zig fmt`
- All `pub` and `export` functions require `///` doc comments
- C FFI exports live exclusively in `src/ffi.zig`
- Protocol implementations in `src/<module>.zig` (cbor, ctap2, ctaphid, pin)
- Platform HID transports in `src/hid_macos.zig` and `src/hid_linux.zig`
- Property-based tests in `tests/pbt_<module>.zig`
- Error convention: negative = library error, 0 = success, positive = CTAP2 device status byte

## Boundaries

- **Do not** add browser or WebKit dependencies -- this is a USB HID library
- **Do not** bypass USB HID framing (CTAPHID packet structure is required by spec)
- **Do not** introduce OpenSSL, BoringSSL, CommonCrypto, or any C crypto dependency
- **Do not** add allocator-dependent APIs to the FFI surface (all buffers are caller-provided)
- **Do not** link IOKit/CoreFoundation in the static library (resolved at final link by the consumer)
- **Do** keep the library stateless and thread-safe
- **Do** ensure all new commands have both unit tests and property-based tests where applicable
- **Do** test against real hardware (YubiKey) for any transport-layer changes

## C FFI Exports (ctap2.h)

| Function | Return | Description |
|----------|--------|-------------|
| `ctap2_device_count` | `int` | Get the number of connected FIDO2 devices. |
| `ctap2_make_credential` | `int` | Perform authenticatorMakeCredential. client_data_hash must be 32 bytes (SHA-256 of clientDataJSON). Returns bytes written to result_buf, or negative error code. result_buf contains the raw CTAP2 response (status byte + CBOR). |
| `ctap2_get_assertion` | `int` | Perform authenticatorGetAssertion. client_data_hash must be 32 bytes. allow_list_ids is an array of pointers to credential IDs. allow_list_id_lens is an array of lengths for each credential ID. Returns bytes written to result_buf, or negative error code. |
| `ctap2_get_info` | `int` | Perform authenticatorGetInfo. Returns bytes written to result_buf, or negative error code. result_buf contains the raw CTAP2 response (status byte + CBOR). |
| `ctap2_make_credential_parsed` | `int` | Combined: send makeCredential + parse response. Output buffers should be at least 1024 bytes for credential_id, and 4096 bytes for attestation_object. |
| `ctap2_get_assertion_parsed` | `int` | Combined: send getAssertion + parse response. Output buffers should be at least 1024 bytes each. allow_list_ids/allow_list_id_lens can be NULL when allow_list_count is 0. |
| `ctap2_parse_make_credential_response` | `int` | Parse a raw MakeCredential response (status byte + CBOR attestation object). |
| `ctap2_parse_get_assertion_response` | `int` | Parse a raw GetAssertion response (status byte + CBOR). fallback_cred_id: credential ID to use when the response omits key 1 (CTAP2 spec: single-entry allowList). Pass NULL/0 if no fallback. |
| `ctap2_get_pin_retries` | `int` | Get PIN retry count from the authenticator. out_retries: receives the number of remaining PIN retries. Returns CTAP2_OK on success, or negative error code. |
| `ctap2_get_pin_token` | `int` | Get a PIN token for authentication. Performs the full PIN protocol v2 handshake (key agreement + ECDH + PIN encryption) and returns a decrypted 32-byte PIN token. |
| `ctap2_make_credential_with_pin` | `int` | MakeCredential with optional PIN auth. Pass pin_token=NULL, pin_protocol=0 for no PIN. Pass pin_token=<32-byte token>, pin_protocol=2 for PIN-authenticated. |
| `ctap2_get_assertion_with_pin` | `int` | GetAssertion with optional PIN auth. Same token/protocol convention. |
| `ctap2_make_credential_with_keepalive` | `int` | MakeCredential with keepalive callback (status 1=processing, 2=user presence needed). Returns raw response bytes. |
| `ctap2_get_assertion_with_keepalive` | `int` | GetAssertion with keepalive callback. Returns raw response bytes. |
| `ctap2_status_message` | `const char *` | Map a CTAP2 status byte to a human-readable message string. |
| `ctap2_debug_last_ioreturn` | `int` | Debug: get the last IOReturn error code from HID operations (macOS only). |

## Error Conventions

Defined in `ctap2.h`:

| Code | Value | Meaning |
|------|-------|---------|
| `CTAP2_OK` | 0 | Success |
| `CTAP2_ERR_NO_DEVICE` | -1 | No FIDO2 device connected |
| `CTAP2_ERR_TIMEOUT` | -2 | Device communication timeout |
| `CTAP2_ERR_PROTOCOL` | -3 | CTAPHID protocol error |
| `CTAP2_ERR_BUFFER_TOO_SMALL` | -4 | Output buffer too small |
| `CTAP2_ERR_OPEN_FAILED` | -5 | Failed to open HID device |
| `CTAP2_ERR_WRITE_FAILED` | -6 | USB write failed |
| `CTAP2_ERR_READ_FAILED` | -7 | USB read failed |
| `CTAP2_ERR_CBOR` | -8 | CBOR encoding/decoding error |
| `CTAP2_ERR_DEVICE` | -9 | CTAP2 device error |
| `CTAP2_ERR_PIN` | -10 | PIN protocol error |
| `CTAP2_ERR_NOT_ACCESSIBLE` | -11 | Devices found but not openable (permissions) |

## Platform Requirements

**macOS:**
- Frameworks: CoreFoundation, IOKit (linked at final build, not in the static lib)
- Entitlement: `com.apple.security.device.usb` (hardened runtime)
- Permission: Input Monitoring (System Settings > Privacy & Security)
- Targets: arm64, x86_64

**Linux:**
- hidraw kernel support (default on most distributions)
- Read/write access to `/dev/hidraw*` devices (udev rule or group membership)
- Targets: arm64, x86_64
