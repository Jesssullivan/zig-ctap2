const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Zig module for package manager consumers.
    const zig_module = b.addModule("zig-ctap2", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addFinalLinkDeps(zig_module, target);

    // Static library for C FFI consumers.
    const ffi_module = b.createModule(.{
        .root_source_file = b.path("src/ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    const lib = b.addLibrary(.{
        .name = "ctap2",
        .root_module = ffi_module,
        .linkage = .static,
    });

    // NOTE: IOKit and CoreFoundation are NOT linked here because this builds
    // a static library. The frameworks are resolved at final link time by Xcode
    // (via OTHER_LDFLAGS). Linking them here breaks cross-compilation (zig can't
    // find frameworks when -Dtarget is set to a different arch).

    b.installArtifact(lib);

    // C example. Build only: running it enumerates real USB HID devices.
    const example_step = b.step("example", "Build the C example");
    const example_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
    });
    example_module.link_libc = true;
    example_module.addIncludePath(b.path("include"));
    example_module.addCSourceFile(.{
        .file = b.path("examples/device_count.c"),
        .flags = &.{ "-std=c99", "-Wall", "-Wextra" },
    });
    example_module.linkLibrary(lib);
    addFinalLinkDeps(example_module, target);

    const example = b.addExecutable(.{
        .name = "device_count",
        .root_module = example_module,
    });
    example_step.dependOn(&example.step);

    // Unit tests
    const test_step = b.step("test", "Run unit tests (no hardware)");

    inline for (.{
        "src/cbor.zig",
        "src/ctaphid.zig",
        "src/ctap2.zig",
        "src/pin.zig",
    }) |test_file| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(test_file),
                .target = target,
                .optimize = optimize,
            }),
        });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }

    // Property-based tests
    const pbt_step = b.step("test-pbt", "Run property-based tests");

    inline for (.{
        .{ .file = "tests/pbt_cbor.zig", .mod = "cbor" },
        .{ .file = "tests/pbt_ctaphid.zig", .mod = "ctaphid" },
    }) |entry| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(entry.file),
                .target = target,
                .optimize = optimize,

                .imports = &.{
                    .{ .name = entry.mod, .module = b.createModule(.{
                        .root_source_file = b.path("src/" ++ entry.mod ++ ".zig"),
                        .target = target,
                        .optimize = optimize,
                    }) },
                },
            }),
        });
        pbt_step.dependOn(&b.addRunArtifact(t).step);
    }

    // Hardware integration tests (require physical YubiKey + YUBIKEY_TESTS=1)
    const hw_step = b.step("test-hardware", "Run hardware tests (needs YubiKey)");

    const hid_mod = b.createModule(.{
        .root_source_file = b.path("src/hid.zig"),
        .target = target,
        .optimize = optimize,
    });
    const ctaphid_mod = b.createModule(.{
        .root_source_file = b.path("src/ctaphid.zig"),
        .target = target,
        .optimize = optimize,
    });
    const cbor_mod = b.createModule(.{
        .root_source_file = b.path("src/cbor.zig"),
        .target = target,
        .optimize = optimize,
    });
    const ctap2_mod = b.createModule(.{
        .root_source_file = b.path("src/ctap2.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "cbor.zig", .module = cbor_mod },
            .{ .name = "ctaphid.zig", .module = ctaphid_mod },
        },
    });

    const hw_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/hardware_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hid", .module = hid_mod },
                .{ .name = "ctaphid", .module = ctaphid_mod },
                .{ .name = "ctap2", .module = ctap2_mod },
                .{ .name = "cbor", .module = cbor_mod },
            },
        }),
    });

    // The hardware test binary must resolve platform HID symbols itself.
    addFinalLinkDeps(hw_test.root_module, target);

    hw_step.dependOn(&b.addRunArtifact(hw_test).step);

    // Documentation generation
    const docs_step = b.step("docs", "Generate API documentation");
    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    docs_step.dependOn(&install_docs.step);
}

fn addFinalLinkDeps(module: *std.Build.Module, target: std.Build.ResolvedTarget) void {
    switch (target.result.os.tag) {
        .macos => {
            module.linkFramework("IOKit", .{});
            module.linkFramework("CoreFoundation", .{});
        },
        else => {},
    }
}
