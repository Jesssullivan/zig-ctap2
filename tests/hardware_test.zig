/// Hardware integration tests — require a physical YubiKey.
/// Run with: YUBIKEY_TESTS=1 zig build test-hardware
const std = @import("std");

test "hardware tests require YUBIKEY_TESTS=1" {
    const env = std.posix.getenv("YUBIKEY_TESTS");
    if (env == null or !std.mem.eql(u8, env.?, "1")) {
        std.debug.print("Skipping hardware tests (set YUBIKEY_TESTS=1 to run)\n", .{});
        return;
    }
    // TODO: enumerate devices, getInfo, makeCredential
}
