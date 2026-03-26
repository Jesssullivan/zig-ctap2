# zig-ctap2 — Portable CTAP2/FIDO2 library
# Run `just` to see all available recipes.
#
# NOTE: On macOS 26+, zig's internal linker can't resolve libSystem tbd
# stubs in the build runner. `zig build` is broken but `zig test` works
# with -target aarch64-macos-none. CI (macOS 15) uses `zig build` fine.

ZIG_TARGET := if os() == "macos" { "-target aarch64-macos-none" } else { "" }

default:
    @just --list

# Build static library (ReleaseFast)
build:
    zig build -Doptimize=ReleaseFast -Dtarget=aarch64-macos-none

# Build debug library
build-debug:
    zig build -Dtarget=aarch64-macos-none

# Run unit tests
test:
    zig test src/cbor.zig {{ZIG_TARGET}}
    zig test src/ctaphid.zig {{ZIG_TARGET}}
    zig test src/ctap2.zig {{ZIG_TARGET}}
    zig test src/pin.zig {{ZIG_TARGET}}

# Run property-based tests (1000 iterations)
# NOTE: PBT uses module imports which bypass -target on macOS 26 (zig bug).
# PBT runs on CI (macOS 15) via `zig build test-pbt`. Locally, use `just test`.
test-pbt:
    zig build test-pbt

# Run all tests (unit + PBT)
# On macOS 26+: unit tests pass locally, PBT requires CI
test-all: test

# Run hardware tests (requires YubiKey connected)
test-hardware:
    zig build test-hardware -Dtarget=aarch64-macos-none

# Clean build artifacts
clean:
    rm -rf .zig-cache zig-out

# Scan for leaked secrets
secrets-scan:
    detect-secrets scan --baseline .secrets.baseline
    detect-secrets audit --report --baseline .secrets.baseline

# Update secrets baseline
secrets-baseline:
    detect-secrets scan > .secrets.baseline

# Install pre-commit hooks
hooks:
    pre-commit install

# Nix: enter dev shell
dev:
    nix develop

# Nix: build library package
nix-build:
    nix build

# Nix: check flake
nix-check:
    nix flake check

# Show library info
info:
    @echo "zig-ctap2 v0.2.0"
    @echo "License: Zlib OR MIT"
    @echo ""
    @echo "Source files:"
    @wc -l src/*.zig | tail -1
    @echo "Test files:"
    @wc -l tests/*.zig | tail -1
    @echo ""
    @zig version
