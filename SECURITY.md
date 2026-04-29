# Security Policy

zig-ctap2 communicates with external FIDO2 authenticators and handles CTAP2/WebAuthn-adjacent data. Treat suspected memory-safety, PIN-token handling, authenticator response parsing, transport, build-chain, package metadata, or documentation issues as security-sensitive until they are triaged.

## Reporting a Vulnerability

Do not open a public issue with vulnerability details, PINs, credentials, secrets, private logs, authenticator secrets, or relying-party production data.

Use GitHub's private vulnerability reporting flow for this repository when it is available. If GitHub does not offer a private reporting button, open a minimal public issue asking for a private contact path and omit technical details until a private channel exists.

Useful initial context for a private report:

- affected version or commit
- platform and Zig version
- affected API surface (`ctap2.h`, Zig package API, CTAP2 encoding/parsing, CTAPHID framing, PIN protocol, macOS IOKit backend, Linux hidraw backend, build/package metadata, or docs)
- minimal reproduction, if it can be shared safely
- whether the issue affects confidentiality, integrity, availability, memory safety, PIN token handling, origin/RP policy assumptions, or API misuse risk

## Supported Versions

Security fixes target the latest released version and `main`. Older tags may receive follow-up notes when a vulnerability is confirmed, but active fixes should be developed against current `main`.
