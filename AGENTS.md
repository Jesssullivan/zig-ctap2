# zig-ctap2 -- Agent Interface

## Capabilities

- Enumerate connected FIDO2/CTAP2 USB HID security keys
- Register WebAuthn credentials (authenticatorMakeCredential)
- Authenticate with WebAuthn credentials (authenticatorGetAssertion)
- Query device capabilities (authenticatorGetInfo)
- PIN protocol v2: check retries, obtain PIN tokens, PIN-authenticated operations
- Parse raw CTAP2 CBOR responses into structured fields (no I/O needed)
- Keepalive callbacks for user touch indication during operations
- Map CTAP2 status bytes to human-readable error messages

## C FFI Exports

See `include/ctap2.h` for full parameter signatures.

- `ctap2_device_count` -- enumerate FIDO2 devices
- `ctap2_make_credential` / `ctap2_get_assertion` / `ctap2_get_info` -- raw CTAP2 commands
- `ctap2_make_credential_parsed` / `ctap2_get_assertion_parsed` -- command + CBOR parse
- `ctap2_parse_make_credential_response` / `ctap2_parse_get_assertion_response` -- pure parsing
- `ctap2_get_pin_retries` / `ctap2_get_pin_token` -- PIN protocol
- `ctap2_make_credential_with_pin` / `ctap2_get_assertion_with_pin` -- PIN-authenticated
- `ctap2_make_credential_with_keepalive` / `ctap2_get_assertion_with_keepalive` -- keepalive
- `ctap2_status_message` / `ctap2_debug_last_ioreturn` -- utilities

## Error Codes

Negative = library error. Zero = success. Positive = CTAP2 device status byte.

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | CTAP2_OK | Success |
| -1 | CTAP2_ERR_NO_DEVICE | No FIDO2 device connected |
| -2 | CTAP2_ERR_TIMEOUT | Device communication timeout |
| -3 | CTAP2_ERR_PROTOCOL | CTAPHID protocol error |
| -4 | CTAP2_ERR_BUFFER_TOO_SMALL | Output buffer too small |
| -5 | CTAP2_ERR_OPEN_FAILED | Failed to open HID device |
| -6 | CTAP2_ERR_WRITE_FAILED | USB write failed |
| -7 | CTAP2_ERR_READ_FAILED | USB read failed |
| -8 | CTAP2_ERR_CBOR | CBOR encoding/decoding error |
| -9 | CTAP2_ERR_DEVICE | CTAP2 device error |
| -10 | CTAP2_ERR_PIN | PIN protocol error |

## Thread Safety

All exported C functions are thread-safe. Each call opens its own HID device handle.

## Platform Requirements

**macOS:** IOKit.framework, CoreFoundation.framework. Entitlement: `com.apple.security.device.usb`. Input Monitoring permission required.

**Linux:** hidraw device access. No additional libraries.

## Example: Complete Usage

```c
#include "ctap2.h"
#include <string.h>

int main(void) {
    if (ctap2_device_count() <= 0) return 1;

    uint8_t cdh[32]; memset(cdh, 0x42, 32);
    int32_t algs[] = {-7};
    uint8_t cred[1024]; size_t cred_len = sizeof(cred);
    uint8_t att[4096]; size_t att_len = sizeof(att);

    int s = ctap2_make_credential_parsed(
        cdh, "example.com", "Example",
        (const uint8_t*)"u1", 2, "alice", "Alice",
        algs, 1, false,
        cred, &cred_len, att, &att_len
    );
    return (s == 0) ? 0 : 1;
}
```
