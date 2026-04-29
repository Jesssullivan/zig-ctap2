# Apple Interop

zig-ctap2 is a portable external-authenticator CTAP2 USB HID library, not an Apple application framework. It is useful when an application needs a small FIDO2 security-key capability that can move between macOS and Linux while keeping the CTAP2 transport/protocol boundary outside a single OS application framework.

## Apple Analogs

The closest Apple surfaces are:

- `ASAuthorizationController` and AuthenticationServices provider classes for passkey/WebAuthn UI flows
- `com.apple.developer.web-browser.public-key-credential` for browser-class WebAuthn entitlement workflows
- IOKit HID for USB security-key transport
- Swift or Objective-C bridging headers for C ABI calls

The current macOS backend uses IOKit and CoreFoundation for USB HID transport. It does not expose AuthenticationServices UI, passkeys/iCloud Keychain, platform authenticators, Secure Enclave flows, biometric prompts, LocalAuthentication policy, browser mediation semantics, or WebAuthn origin/RP policy.

## Available Now

- C ABI callable from Swift, Objective-C, C, C++, and other FFI hosts
- USB HID device enumeration for FIDO2 authenticators
- CTAPHID framing and CTAP2 CBOR command/response handling
- makeCredential, getAssertion, getInfo, PIN protocol v2, response parsing, and keepalive callback variants
- macOS transport through IOKit/CoreFoundation
- Linux transport through hidraw
- Direct Zig package API through `src/root.zig`

## Not Yet Available

- SwiftPM package, module map, or XCFramework packaging
- Objective-C sample app and nullability annotations
- Dedicated Swift wrapper types around the C ABI
- WebAuthn request/response helper types for clientDataJSON, authenticatorData, and PublicKeyCredential JSON
- Attestation statement verification, trust policy, origin/RP ID validation, browser mediation semantics, or credential persistence
- Platform authenticators, passkeys/iCloud Keychain, Secure Enclave, LocalAuthentication, biometric prompts, NFC, BLE, or CTAP extensions such as hmac-secret/credProtect
- A documented Linux permission guide across common udev/security-key packages

## Contributor Starting Points

Good first issues should stay small and should make one missing interop path easier to verify. Useful starting points include a SwiftPM/modulemap smoke test, an Objective-C bridge sample, C header nullability annotations, a WebAuthn mapping guide, and a Linux hidraw permission guide.
