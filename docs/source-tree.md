# Source Tree: zig-ctap2

```
zig-ctap2/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   ├── config.yml
│   │   ├── documentation.yml
│   │   └── feature_request.yml
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── docs.yml
│   │   └── release.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── docs/
│   ├── api/
│   │   ├── c-ffi.md  (C FFI API Reference: zig-ctap2)
│   │   └── zig-api.md  (Zig API Reference: zig-ctap2)
│   ├── guides/
│   │   ├── apple-interop.md  (Apple Interop)
│   │   ├── building.md  (Building)
│   │   └── integration.md  (Integration Guide)
│   ├── agents.md  (AGENTS.md)
│   ├── index.md  (zig-ctap2)
│   ├── llms.txt
│   └── source-tree.md  (Source Tree: zig-ctap2)
├── examples/
│   ├── device_count.c
│   └── get_info.c
├── include/
│   └── ctap2.h  (C header -- 16 functions)
├── scripts/
│   ├── gen_api_docs.py
│   └── gen_docs.py
├── src/
│   ├── cbor.zig  (Minimal CBOR encoder/decoder for CTAP2.)
│   ├── ctap2.zig  (CTAP2 command encoding and response parsing.)
│   ├── ctaphid.zig  (CTAPHID transport framing for FIDO2 USB HID communication.)
│   ├── ffi.zig  (C FFI exports for libctap2.)
│   ├── hid.zig  (Platform-selected USB HID transport for FIDO2 devices.)
│   ├── hid_linux.zig  (Linux USB HID transport via hidraw.)
│   ├── hid_macos.zig  (macOS USB HID transport via IOKit.)
│   ├── pin.zig  (CTAP2 Client PIN protocol v2 (authenticatorClientPIN comm...)
│   └── root.zig  (Public Zig package API for zig-ctap2.)
├── tests/
│   ├── hardware_test.zig  (Hardware integration tests -- require a physical YubiKey.)
│   ├── pbt_cbor.zig  (Property-based tests for CBOR encoder/decoder roundtrips.)
│   └── pbt_ctaphid.zig  (Property-based tests for CTAPHID message framing.)
├── .coderabbit.yaml
├── .envrc
├── .gitignore
├── .pre-commit-config.yaml
├── .secrets.baseline
├── AGENTS.md  (AGENTS.md -- zig-ctap2)
├── CONTRIBUTING.md  (Contributing to zig-ctap2)
├── LICENSE  (License)
├── README.md  (zig-ctap2)
├── SECURITY.md  (Security Policy)
├── build.zig
├── build.zig.zon
├── flake.lock  (Nix flake lockfile)
├── flake.nix  (Nix flake)
├── justfile  (Just task runner recipes)
├── llms-full.txt
├── llms.txt
└── mkdocs.yml  (MkDocs configuration)
```
