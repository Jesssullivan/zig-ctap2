const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Static library for C FFI
    const lib = b.addLibrary(.{
        .name = "ctap2",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });

    if (target.result.os.tag == .macos) {
        lib.root_module.linkFramework("IOKit", .{});
        lib.root_module.linkFramework("CoreFoundation", .{});
    }

    b.installArtifact(lib);

    // Unit tests
    const test_step = b.step("test", "Run unit tests (no hardware)");

    inline for (.{
        "src/cbor.zig",
        "src/ctaphid.zig",
        "src/ctap2.zig",
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
}
