/*
 * zig-ctap2 example: Device enumeration and CTAP2 getInfo.
 *
 * Enumerates connected FIDO2 devices and sends an authenticatorGetInfo
 * command to the first one. No user interaction needed -- getInfo just
 * queries the device's capabilities.
 *
 * Build:
 *   cd .. && zig build -Doptimize=ReleaseFast
 *   # macOS:
 *   cc examples/get_info.c -Iinclude -Lzig-out/lib -lctap2 \
 *      -framework IOKit -framework CoreFoundation -o examples/get_info
 *   # Linux:
 *   cc examples/get_info.c -Iinclude -Lzig-out/lib -lctap2 -o examples/get_info
 *
 *   ./examples/get_info
 */

#include "ctap2.h"
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

int main(void) {
    /* Step 1: Enumerate devices */
    int count = ctap2_device_count();
    printf("FIDO2 devices found: %d\n", count);

    if (count <= 0) {
        printf("No FIDO2 device connected. Plug in a YubiKey and retry.\n");
        return 1;
    }

    /* Step 2: Send authenticatorGetInfo */
    uint8_t buf[4096];
    int result = ctap2_get_info(buf, sizeof(buf));

    if (result < 0) {
        printf("ctap2_get_info failed: %d\n", result);
        return 1;
    }

    printf("getInfo response: %d bytes\n", result);

    /* First byte is the CTAP2 status (0x00 = success) */
    printf("Status: 0x%02x (%s)\n", buf[0], ctap2_status_message(buf[0]));

    if (buf[0] != 0x00) {
        printf("Device returned error status.\n");
        return 1;
    }

    /* Dump raw CBOR response (status byte + CBOR map) */
    printf("Raw response hex:\n  ");
    print_hex(buf, (size_t)result);
    printf("\n");

    /*
     * The CBOR map (starting at buf[1]) contains device info:
     *   key 1: versions (array of strings, e.g. "FIDO_2_0", "FIDO_2_1")
     *   key 2: extensions (array of strings)
     *   key 3: aaguid (16-byte identifier)
     *   key 4: options (map of capability booleans)
     *   ...
     *
     * Full CBOR parsing is left to the application.
     * See src/cbor.zig for the decoder used internally.
     */

    return 0;
}
