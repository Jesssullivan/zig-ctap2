# Contributing to zig-ctap2

## Installation

### Zig Package Manager

```bash
zig fetch --save git+https://github.com/Jesssullivan/zig-ctap2.git
```

Then in your `build.zig`:

```zig
const dep = b.dependency("zig_ctap2", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("zig-ctap2", dep.module("zig-ctap2"));
```

### Git Submodule (C FFI consumers)

```bash
git submodule add https://github.com/Jesssullivan/zig-ctap2.git vendor/ctap2
cd vendor/ctap2 && zig build -Doptimize=ReleaseFast
```

Link `-lctap2` and include `ctap2.h`. At final link time, add platform frameworks:

- macOS: `-framework IOKit -framework CoreFoundation`
- Linux: no extra libraries needed; runtime needs hidraw device access

## Development

### Prerequisites

- Zig 0.15.2+
- macOS: IOKit and CoreFoundation frameworks
- Linux: hidraw support and read/write access to `/dev/hidraw*`

### Build & Test

```bash
zig build                        # static library
zig build -Doptimize=ReleaseFast # optimized build
zig build test                   # unit tests
zig build test-pbt               # property-based tests
zig build docs                   # generate API documentation
zig build example                # build C example
```

## Where to Start

Start with issues labeled [`good first issue`](https://github.com/Jesssullivan/zig-ctap2/labels/good%20first%20issue) or [`help wanted`](https://github.com/Jesssullivan/zig-ctap2/labels/help%20wanted).

Small, useful first contributions include:

- SwiftPM/modulemap smoke tests
- Objective-C bridging samples
- C header nullability annotations
- WebAuthn request/response mapping examples
- Linux hidraw permission documentation

### Code Style

- `zig fmt` for formatting
- All `pub` and `export` functions need `///` doc comments
- C FFI exports go in `src/ffi.zig`
- Zig package exports go through `src/root.zig`
- Platform transports live in `src/hid_<platform>.zig`
- Protocol modules stay independent from app/UI frameworks

### Adding a new operation

1. Add the protocol implementation to the relevant Zig module.
2. Add or update the `src/ffi.zig` wrapper if the C ABI changes.
3. Add the C declaration to `include/ctap2.h`.
4. Add unit tests and property-based tests where applicable.
5. Update `AGENTS.md`, README, and docs when public behavior changes.

## Filing Issues

Open an issue at [github.com/Jesssullivan/zig-ctap2/issues](https://github.com/Jesssullivan/zig-ctap2/issues).

## License

Dual-licensed under [Zlib](https://opensource.org/licenses/Zlib) and [MIT](https://opensource.org/licenses/MIT).
