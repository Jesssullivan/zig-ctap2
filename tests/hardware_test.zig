/// Hardware integration tests -- require a physical YubiKey.
/// Run with: YUBIKEY_TESTS=1 zig build test-hardware
///
/// All tests check the YUBIKEY_TESTS environment variable and skip
/// gracefully if it is not set to "1". This allows the test binary
/// to compile and run in CI without a connected authenticator.

const std = @import("std");
const hid = @import("hid");
const ctaphid = @import("ctaphid");
const ctap2 = @import("ctap2");
const cbor = @import("cbor");

// ── Helpers ──────────────────────────────────────────────────

fn yukibeyEnabled() bool {
    const env = std.posix.getenv("YUBIKEY_TESTS");
    if (env) |val| {
        return std.mem.eql(u8, val, "1");
    }
    return false;
}

fn skipUnlessYubiKey() bool {
    if (!yukibeyEnabled()) {
        std.debug.print("SKIP: YUBIKEY_TESTS not set (set YUBIKEY_TESTS=1 with a YubiKey connected)\n", .{});
        return true;
    }
    return false;
}

// ── Test 1: Device enumeration ──────────────────────────────

test "enumerate FIDO2 devices" {
    if (skipUnlessYubiKey()) return;

    const allocator = std.testing.allocator;
    const devices = try hid.enumerate(allocator);
    defer {
        for (devices) |*dev| {
            var d = dev.*;
            d.close();
        }
        allocator.free(devices);
    }

    // At least one FIDO2 device must be present
    try std.testing.expect(devices.len >= 1);
    std.debug.print("Found {} FIDO2 device(s)\n", .{devices.len});

    // First device ref must be non-null
    try std.testing.expect(devices[0].ref != null);
}

// ── Test 2: CTAPHID_INIT roundtrip ──────────────────────────

test "CTAPHID_INIT nonce echo and CID assignment" {
    if (skipUnlessYubiKey()) return;

    const allocator = std.testing.allocator;
    var dev = try hid.openFirst(allocator);
    defer dev.close();

    // Build CTAPHID_INIT: broadcast CID, cmd 0x06 (init), 8-byte nonce
    const nonce = [8]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xF0, 0x0D };
    var init_pkt = ctaphid.buildInitPacket(ctaphid.CID_BROADCAST, .init, 8, &nonce);
    try dev.write(&init_pkt);

    // Read response (5 second timeout)
    const resp_pkt = try dev.read(5000);

    // Parse the init packet header
    const header = try ctaphid.parseInitPacket(&resp_pkt);
    try std.testing.expectEqual(ctaphid.Command.init, header.cmd);
    try std.testing.expect(header.payload_len >= 17); // CTAPHID_INIT response is 17 bytes

    // Parse the CTAPHID_INIT response body
    const resp_data = resp_pkt[7..][0..@min(@as(usize, header.payload_len), ctaphid.INIT_DATA_SIZE)];
    const init_resp = try ctaphid.parseInitResponse(resp_data);

    // Nonce must be echoed back verbatim
    try std.testing.expectEqualSlices(u8, &nonce, &init_resp.nonce);

    // Assigned CID must not be broadcast CID and must be non-zero
    try std.testing.expect(init_resp.cid != ctaphid.CID_BROADCAST);
    try std.testing.expect(init_resp.cid != 0);

    std.debug.print("Assigned CID: 0x{X:0>8}, protocol v{}, firmware {}.{}.{}\n", .{
        init_resp.cid,
        init_resp.protocol_version,
        init_resp.major,
        init_resp.minor,
        init_resp.build,
    });
}

// ── Test 3: authenticatorGetInfo roundtrip ───────────────────

test "getInfo returns success with CBOR map" {
    if (skipUnlessYubiKey()) return;

    const allocator = std.testing.allocator;
    var dev = try hid.openFirst(allocator);
    defer dev.close();

    // Negotiate a channel
    var nonce: [8]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var init_pkt = ctaphid.buildInitPacket(ctaphid.CID_BROADCAST, .init, 8, &nonce);
    try dev.write(&init_pkt);

    const init_resp_pkt = try dev.read(5000);
    const init_header = try ctaphid.parseInitPacket(&init_resp_pkt);
    const init_data = init_resp_pkt[7..][0..@min(@as(usize, init_header.payload_len), ctaphid.INIT_DATA_SIZE)];
    const init_resp = try ctaphid.parseInitResponse(init_data);
    const cid = init_resp.cid;

    // Encode getInfo command (single byte: 0x04)
    var cmd_buf: [8]u8 = undefined;
    const cmd = try ctap2.encodeGetInfo(&cmd_buf);

    // Fragment and send
    var packets: [8]ctaphid.Packet = undefined;
    const pkt_count = try ctaphid.fragmentMessage(cid, .cbor, cmd, &packets);

    for (packets[0..pkt_count]) |*pkt| {
        try dev.write(pkt);
    }

    // Read response -- handle keepalive
    var resp_pkt = try dev.read(5000);
    while (true) {
        const hdr = ctaphid.parseInitPacket(&resp_pkt) catch break;
        if (hdr.cmd == .keepalive) {
            resp_pkt = try dev.read(5000);
            continue;
        }
        break;
    }

    const resp_header = try ctaphid.parseInitPacket(&resp_pkt);
    try std.testing.expect(resp_header.payload_len >= 2); // At least status + some CBOR

    // First byte of payload is CTAP2 status code
    const status_byte = resp_pkt[7];
    try std.testing.expectEqual(@as(u8, 0x00), status_byte); // Success

    // Remaining bytes are CBOR -- collect them
    const total_len: usize = @intCast(resp_header.payload_len);
    var resp_buf: [4096]u8 = undefined;

    // Copy init packet data (skip status byte at offset 7; CBOR starts at offset 8)
    const init_copy = @min(total_len, ctaphid.INIT_DATA_SIZE);
    @memcpy(resp_buf[0..init_copy], resp_pkt[7..][0..init_copy]);
    var offset: usize = init_copy;

    // Read continuation packets if needed
    while (offset < total_len) {
        const cont_pkt = try dev.read(5000);
        if (cont_pkt[4] & 0x80 != 0) {
            const cont_hdr = ctaphid.parseInitPacket(&cont_pkt) catch continue;
            if (cont_hdr.cmd == .keepalive) continue;
        }
        const cont_copy = @min(total_len - offset, ctaphid.CONT_DATA_SIZE);
        @memcpy(resp_buf[offset..][0..cont_copy], cont_pkt[5..][0..cont_copy]);
        offset += cont_copy;
    }

    // The CBOR data starts after the status byte (index 1 of resp_buf)
    const cbor_data = resp_buf[1..total_len];

    // getInfo response is a CBOR map -- verify the first byte indicates a map (major type 5)
    try std.testing.expect(cbor_data.len > 0);
    const major_type = cbor_data[0] >> 5;
    try std.testing.expectEqual(@as(u8, 5), major_type); // CBOR map

    // Decode the map header to verify it has entries
    var dec = cbor.Decoder.init(cbor_data);
    const map_len = try dec.decodeMapHeader();
    try std.testing.expect(map_len >= 1); // getInfo has at least "versions" key

    std.debug.print("getInfo: status=0x{X:0>2}, CBOR map with {} entries, {} bytes total\n", .{
        status_byte,
        map_len,
        cbor_data.len,
    });
}

// ── Test 4: makeCredential roundtrip ────────────────────────

test "makeCredential returns attestation object" {
    if (skipUnlessYubiKey()) return;

    const allocator = std.testing.allocator;
    var dev = try hid.openFirst(allocator);
    defer dev.close();

    // Negotiate a channel
    var nonce: [8]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var init_pkt = ctaphid.buildInitPacket(ctaphid.CID_BROADCAST, .init, 8, &nonce);
    try dev.write(&init_pkt);

    const init_resp_pkt = try dev.read(5000);
    const init_header = try ctaphid.parseInitPacket(&init_resp_pkt);
    const init_data = init_resp_pkt[7..][0..@min(@as(usize, init_header.payload_len), ctaphid.INIT_DATA_SIZE)];
    const init_resp = try ctaphid.parseInitResponse(init_data);
    const cid = init_resp.cid;

    // Build makeCredential command
    var cmd_buf: [2048]u8 = undefined;
    var client_data_hash: [32]u8 = undefined;
    std.crypto.random.bytes(&client_data_hash);

    const algs = [_]i32{-7}; // ES256
    const cmd = try ctap2.encodeMakeCredential(
        &cmd_buf,
        &client_data_hash,
        "localhost",
        "localhost",
        &[_]u8{ 0x01, 0x02, 0x03, 0x04 }, // user ID
        "test-user",
        "Test User",
        &algs,
        false,
    );

    // Fragment and send
    var packets: [128]ctaphid.Packet = undefined;
    const pkt_count = try ctaphid.fragmentMessage(cid, .cbor, cmd, &packets);

    for (packets[0..pkt_count]) |*pkt| {
        try dev.write(pkt);
    }

    // Read response -- wait up to 30 seconds for user touch
    std.debug.print("Waiting for user touch (up to 30 seconds)...\n", .{});
    var resp_pkt: [64]u8 = undefined;
    var got_response = false;

    // Poll for up to 30 seconds, handling keepalive packets
    var attempts: u32 = 0;
    while (attempts < 60) : (attempts += 1) {
        resp_pkt = dev.read(1000) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };

        const hdr = ctaphid.parseInitPacket(&resp_pkt) catch continue;
        if (hdr.cmd == .keepalive) {
            // Device is waiting for touch -- keep polling
            continue;
        }
        got_response = true;
        break;
    }

    if (!got_response) {
        std.debug.print("SKIP: No user touch within 30 seconds\n", .{});
        return;
    }

    // Parse the response
    const resp_header = try ctaphid.parseInitPacket(&resp_pkt);
    const total_len: usize = @intCast(resp_header.payload_len);
    try std.testing.expect(total_len >= 1); // At least a status byte

    // Collect full response
    var resp_buf: [4096]u8 = undefined;
    const init_copy = @min(total_len, ctaphid.INIT_DATA_SIZE);
    @memcpy(resp_buf[0..init_copy], resp_pkt[7..][0..init_copy]);
    var offset: usize = init_copy;

    while (offset < total_len) {
        const cont_pkt = try dev.read(5000);
        if (cont_pkt[4] & 0x80 != 0) {
            const cont_hdr = ctaphid.parseInitPacket(&cont_pkt) catch continue;
            if (cont_hdr.cmd == .keepalive) continue;
        }
        const cont_copy = @min(total_len - offset, ctaphid.CONT_DATA_SIZE);
        @memcpy(resp_buf[offset..][0..cont_copy], cont_pkt[5..][0..cont_copy]);
        offset += cont_copy;
    }

    // Status byte
    const status = resp_buf[0];
    try std.testing.expectEqual(@as(u8, 0x00), status); // CTAP2_OK

    // Attestation object follows -- it is a CBOR map
    const attestation_data = resp_buf[1..total_len];
    try std.testing.expect(attestation_data.len > 0);

    // Verify it starts with a CBOR map (major type 5)
    const major_type = attestation_data[0] >> 5;
    try std.testing.expectEqual(@as(u8, 5), major_type);

    // Decode the map -- attestation object has keys: "fmt", "authData", "attStmt"
    var dec = cbor.Decoder.init(attestation_data);
    const map_len = try dec.decodeMapHeader();
    try std.testing.expect(map_len >= 1);

    std.debug.print("makeCredential: status=0x{X:0>2}, attestation map with {} entries, {} bytes\n", .{
        status,
        map_len,
        attestation_data.len,
    });
}

// ── Test 5: Null device guard ───────────────────────────────

test "write to null device ref returns WriteFailed" {
    if (skipUnlessYubiKey()) return;

    // Construct a Device with null ref -- this should not crash
    var dev = hid.Device{
        .ref = null,
        .manager = null,
    };

    // write() must return WriteFailed, not segfault
    var packet: [64]u8 = std.mem.zeroes([64]u8);
    const result = dev.write(&packet);
    try std.testing.expectError(hid.Error.WriteFailed, result);
}
