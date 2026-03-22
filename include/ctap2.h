// C header for libctap2 — portable CTAP2/FIDO2 over USB HID.
// Auto-consumed by Swift via bridging header / module map.

#ifndef CTAP2_H
#define CTAP2_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO: C function declarations will be added as ffi.zig is implemented.

// Status codes
#define CTAP2_OK 0
#define CTAP2_ERR_NO_DEVICE -1
#define CTAP2_ERR_TIMEOUT -2
#define CTAP2_ERR_PROTOCOL -3
#define CTAP2_ERR_BUFFER_TOO_SMALL -4

#ifdef __cplusplus
}
#endif

#endif // CTAP2_H
