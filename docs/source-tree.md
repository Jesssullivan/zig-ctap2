# Source Tree: zig-ctap2

```
zig-ctap2/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── docs.yml
├── docs/
│   ├── api/
│   │   ├── c-ffi.md  (C FFI API Reference: zig-ctap2)
│   │   └── zig-api.md  (Zig API Reference: zig-ctap2)
│   ├── guides/
│   │   ├── building.md  (Building)
│   │   └── integration.md  (Integration Guide)
│   ├── agents.md  (AGENTS.md)
│   ├── index.md  (zig-ctap2)
│   └── llms.txt
├── include/
│   └── ctap2.h  (C header -- 17 functions)
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
│   └── pin.zig  (CTAP2 Client PIN protocol v2 (authenticatorClientPIN comm...)
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
├── LICENSE  (License)
├── LLMS.txt
├── README.md  (zig-ctap2)
├── build.zig
├── flake.lock  (Nix flake lockfile)
├── flake.nix  (Nix flake)
├── justfile  (Just task runner recipes)
└── mkdocs.yml  (MkDocs configuration)
```
