# Contributing to zig-ctap2

## Installation

### Zig Package Manager (recommended)

```bash
zig fetch --save git+https://github.com/Jesssullivan/zig-ctap2.git
```

Then in your `build.zig`:

```zig
const dep = b.dependency("zig-ctap2", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("zig-ctap2", dep.module("zig-ctap2"));
```

### Git Submodule (C FFI consumers)

```bash
git submodule add https://github.com/Jesssullivan/zig-ctap2.git vendor/ctap2
cd vendor/ctap2 && zig build -Doptimize=ReleaseFast
```

Link `-lctap2` and include `ctap2.h`. At final link time, add platform frameworks:
- **macOS:** `-framework IOKit -framework CoreFoundation`
- **Linux:** no extra libraries needed (uses hidraw via kernel)

## Development

### Prerequisites

- Zig 0.14.1+
- **macOS:** IOKit and CoreFoundation (available by default)
- **Linux:** hidraw kernel support (enabled by default on most distributions)
- **Hardware tests:** USB security key (YubiKey 5C NFC recommended)

### Build & Test

```bash
zig build                        # static library (libctap2.a)
zig build test                   # unit tests (no hardware needed)
zig build test-pbt               # property-based tests (1000 iterations)
zig build test-hardware          # hardware tests (requires YubiKey + YUBIKEY_TESTS=1)
zig build docs                   # generate API documentation
```

### Code Style

- `zig fmt` for formatting
- All `pub` and `export` functions need `///` doc comments
- C FFI exports go in `src/ffi.zig`
- Protocol implementations in `src/<module>.zig` (cbor, ctap2, ctaphid, pin)
- Platform HID transports in `src/hid_macos.zig` and `src/hid_linux.zig`
- Property-based tests in `tests/pbt_<module>.zig`

### Adding a new CTAP2 command

1. Add the encoder/parser in `src/ctap2.zig` (or `src/pin.zig` for PIN commands)
2. Add `export fn ctap2_<command>` wrapper in `src/ffi.zig`
3. Add the C declaration to `include/ctap2.h`
4. Add unit tests in the module
5. Wire the test file into `build.zig`
6. Update `AGENTS.md` FFI table

### Hardware Testing

Hardware tests require a physical FIDO2 security key:

```bash
# Connect a YubiKey, then:
YUBIKEY_TESTS=1 zig build test-hardware
```

Tests run getInfo, enumerate devices, and verify CTAPHID framing against real hardware. They do not create or consume credentials.

## Filing Issues

Open an issue at [github.com/Jesssullivan/zig-ctap2/issues](https://github.com/Jesssullivan/zig-ctap2/issues).

## License

Dual-licensed under [Zlib](https://opensource.org/licenses/Zlib) and [MIT](https://opensource.org/licenses/MIT).
