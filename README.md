# zig-ctap2

Portable CTAP2/FIDO2 library in Zig — direct USB HID communication with security keys (YubiKey, SoloKeys, etc.), no Apple entitlements or platform authentication frameworks needed.

## Why

Apple's `ASAuthorizationController` requires a restricted entitlement + provisioning profile for WebAuthn in general-purpose browsers. This library talks directly to FIDO2 devices over USB HID via IOKit (macOS) and hidraw (Linux), bypassing platform authentication frameworks entirely.

## Features

- **CTAP2 protocol**: makeCredential (registration), getAssertion (authentication), getInfo
- **CTAPHID framing**: 64-byte packet fragmentation/reassembly, CID management, keepalive handling
- **Minimal CBOR codec**: encoder/decoder for the CTAP2 subset (integers, byte/text strings, arrays, maps, booleans)
- **Platform HID transports**: macOS (IOKit), Linux (hidraw)
- **C FFI**: exported functions callable from Swift, C, C++, or any language with C interop
- **Property-based tests**: 1000-iteration roundtrip tests for CBOR and CTAPHID framing

## Requirements

- Zig 0.15.2+
- macOS 13+ (IOKit) or Linux (hidraw)
- USB security key (tested with YubiKey 5C NFC)

## Build

```bash
# Static library (libctap2.a)
zig build -Doptimize=ReleaseFast

# Run unit tests
zig build test

# Run property-based tests
zig build test-pbt

# Run hardware tests (requires YubiKey connected)
YUBIKEY_TESTS=1 zig build test-hardware
```

## C API

```c
#include "ctap2.h"

// Enumerate connected FIDO2 devices
int count = ctap2_device_count();

// Register a credential
int result = ctap2_make_credential(
    client_data_hash,    // 32 bytes (SHA-256 of clientDataJSON)
    "example.com",       // RP ID
    "Example",           // RP name
    user_id, user_id_len,
    "user@example.com",  // username
    "User",              // display name
    alg_ids, alg_count,  // COSE algorithm IDs (e.g., -7 for ES256)
    false,               // resident key
    result_buf, result_buf_len
);

// Authenticate with a credential
int result = ctap2_get_assertion(
    client_data_hash,
    "example.com",
    allow_list_ids, allow_list_lens, allow_list_count,
    result_buf, result_buf_len
);

// Get device info
int result = ctap2_get_info(result_buf, result_buf_len);

// Human-readable error messages
const char* msg = ctap2_status_message(0x35);
// → "PIN not set - configure a PIN on your security key first"
```

## Architecture

```
┌──────────────────────────────────────────────┐
│  Your app (Swift, C, C++, etc.)              │
└──────────────┬───────────────────────────────┘
               │ C FFI (ctap2.h)
┌──────────────▼───────────────────────────────┐
│  libctap2 (Zig)                              │
│  ┌─────────────┐  ┌──────────┐  ┌────────┐   │
│  │ ctap2.zig   │  │ cbor.zig │  │ hid.zig│   │
│  │ commands +  │  │ encode/  │  │ compat │   │
│  │ responses   │  │ decode   │  │ select │   │
│  └─────────────┘  └──────────┘  └───┬────┘   │
│                                     │        │
│  ┌──────────────────┐ ┌─────────────▼─────┐  │
│  │ hid_macos.zig    │ │ hid_linux.zig     │  │
│  │ IOKit            │ │ hidraw            │  │
│  └──────────────────┘ └───────────────────┘  │
└──────────────────────────────────────────────┘
               │ USB HID (64-byte packets)
         ┌─────▼─────┐
         │  YubiKey  │
         └───────────┘
```

## Entitlements

On macOS with hardened runtime, add to your entitlements:

```xml
<key>com.apple.security.device.usb</key>
<true/>
```

On macOS, the user must grant **Input Monitoring** permission in System Settings → Privacy & Security.

No other entitlements needed — no `com.apple.developer.web-browser.public-key-credential`, no provisioning profile, no Apple Developer portal configuration.

## Integration with cmux

This library powers the FIDO2/WebAuthn support in [cmux](https://github.com/Jesssullivan/cmux) (fork), integrated as a git submodule at `vendor/ctap2`. The JS bridge in WKWebView intercepts `navigator.credentials.create/get` and routes to libctap2 via Swift C FFI.

## Tested Devices

- YubiKey 5C NFC (USB, firmware 5.x)

## Status

- [x] makeCredential (registration) — working
- [x] getAssertion (authentication) — working
- [x] getInfo — encoded, response parsing in progress
- [x] CTAP2 error code mapping — human-readable messages
- [x] CBOR response parsing — structured result types
- [ ] PIN protocol (CTAP2 clientPIN 0x06) (in progress)
- [ ] Extensions (credProtect, hmac-secret) (in progress)
- [ ] NFC transport

