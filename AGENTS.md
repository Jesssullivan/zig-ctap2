# AGENTS.md -- zig-ctap2

## Capabilities

- CBOR encoding/decoding (CTAP2 subset)
- CTAP2 command encoding and response parsing
- CTAPHID USB HID transport framing
- Platform USB HID device enumeration and I/O
- CTAP2 Client PIN protocol v2 (ECDH + AES + HMAC)

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
| `ctap2_get_pin_token` | `int` | Get a PIN token for authentication. Performs the full PIN protocol v2 handshake (key agreement + ECDH + PIN encryption) and returns a decrypted 32-byte PIN token. pin: null-terminated UTF-8 PIN string. out_pin_token: receives the 32-byte decrypted PIN token. out_pin_token_len: must be >= 32. Returns CTAP2_OK on success, positive CTAP2 status byte on device error (e.g. 0x31 = wrong PIN), or negative error code. |
| `ctap2_make_credential_with_pin` | `int` | Same as the parsed functions above, but with optional PIN auth. Pass pin_token=NULL, pin_protocol=0 for no PIN authentication. Pass pin_token=<32-byte token from ctap2_get_pin_token>, pin_protocol=2 to include pinAuth in the CTAP2 command. |
| `ctap2_get_assertion_with_pin` | `int` |  |
| `ctap2_make_credential_with_keepalive` | `int` |  |
| `ctap2_get_assertion_with_keepalive` | `int` |  |
| `ctap2_debug_last_ioreturn` | `int` | Debug: get the last IOReturn error code from HID operations. |

## Error Conventions

Defined in `ctap2.h`:

| Code | Value | Meaning |
|------|-------|---------|
| `CTAP2_OK` | 0 |  |
| `CTAP2_ERR_NO_DEVICE` | -1 |  |
| `CTAP2_ERR_TIMEOUT` | -2 |  |
| `CTAP2_ERR_PROTOCOL` | -3 |  |
| `CTAP2_ERR_BUFFER_TOO_SMALL` | -4 |  |
| `CTAP2_ERR_OPEN_FAILED` | -5 |  |
| `CTAP2_ERR_WRITE_FAILED` | -6 |  |
| `CTAP2_ERR_READ_FAILED` | -7 |  |
| `CTAP2_ERR_CBOR` | -8 |  |
| `CTAP2_ERR_DEVICE` | -9 |  |
| `CTAP2_ERR_PIN` | -10 |  |

## Platform Requirements

**macOS:**
- Frameworks: CoreFoundation, IOKit
- Targets: arm64, x86_64

**Linux:**
- Libraries: hidraw (kernel)
- Targets: arm64, x86_64

## Build

```bash
zig build                              # static library -> zig-out/lib/
zig build -Doptimize=ReleaseFast       # optimized build
zig build test                         # unit tests
zig build test-pbt                     # property-based tests
```

## Linking

The library builds as a static archive. Include the header
from `include/` and link `zig-out/lib/libctap2.a`.

At final link time, the consuming application must link platform frameworks/libraries.
The static library intentionally does not link them to support cross-compilation.

