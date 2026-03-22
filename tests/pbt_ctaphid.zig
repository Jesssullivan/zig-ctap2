/// Property-based tests for CTAPHID message framing.
///
/// Verifies that arbitrary payloads survive fragmentation and reassembly,
/// and that structural invariants (packet size, CID, sequence numbers,
/// packet count) hold for all sizes.

const std = @import("std");
const ctaphid = @import("ctaphid");

const ITERATIONS: usize = 1000;
const SEED: u64 = 0xF1D0_2C7A_901D;

fn makeRng(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed);
}

/// Expected number of packets for a given payload length.
fn expectedPacketCount(len: usize) usize {
    if (len <= ctaphid.INIT_DATA_SIZE) return 1;
    // First packet carries INIT_DATA_SIZE bytes, each continuation carries CONT_DATA_SIZE
    const remaining = len - ctaphid.INIT_DATA_SIZE;
    return 1 + (remaining + ctaphid.CONT_DATA_SIZE - 1) / ctaphid.CONT_DATA_SIZE;
}

/// Extract CID from any packet (first 4 bytes, big-endian).
fn extractCid(pkt: *const ctaphid.Packet) u32 {
    return (@as(u32, pkt[0]) << 24) | (@as(u32, pkt[1]) << 16) |
        (@as(u32, pkt[2]) << 8) | pkt[3];
}

// ─── Property: fragment and reassemble roundtrip ────────────
// reassembleMessage uses a bare function pointer (no context), so we verify
// the roundtrip property by manually extracting data from fragmented packets.

test "property: fragment/reassemble roundtrip preserves payload" {
    var rng = makeRng(SEED);
    var payload_buf: [7609]u8 = undefined;
    var packets: [130]ctaphid.Packet = undefined;
    var reassembled: [7609]u8 = undefined;

    for (0..ITERATIONS) |_| {
        const r = rng.random();
        const len = r.intRangeAtMost(usize, 0, 7609);
        r.bytes(payload_buf[0..len]);
        const payload = payload_buf[0..len];
        const cid: u32 = r.int(u32) | 1;

        const pkt_count = try ctaphid.fragmentMessage(cid, .cbor, payload, &packets);

        // Extract data from init packet
        var offset: usize = 0;
        const init_copy = @min(len, ctaphid.INIT_DATA_SIZE);
        @memcpy(reassembled[0..init_copy], packets[0][7..][0..init_copy]);
        offset += init_copy;

        // Extract data from continuation packets
        for (1..pkt_count) |i| {
            const remaining = len - offset;
            const cont_copy = @min(remaining, ctaphid.CONT_DATA_SIZE);
            @memcpy(reassembled[offset..][0..cont_copy], packets[i][5..][0..cont_copy]);
            offset += cont_copy;
        }

        try std.testing.expectEqual(len, offset);
        try std.testing.expectEqualSlices(u8, payload, reassembled[0..len]);
    }
}

// ─── Property: packet count is correct ──────────────────────

test "property: packet count matches formula" {
    var rng = makeRng(SEED +% 1);
    var payload_buf: [7609]u8 = undefined;
    var packets: [130]ctaphid.Packet = undefined;

    for (0..ITERATIONS) |_| {
        const r = rng.random();
        const len = r.intRangeAtMost(usize, 0, 7609);
        r.bytes(payload_buf[0..len]);

        const cid: u32 = r.int(u32) | 1;
        const pkt_count = try ctaphid.fragmentMessage(cid, .cbor, payload_buf[0..len], &packets);
        const expected = expectedPacketCount(len);

        try std.testing.expectEqual(expected, pkt_count);
    }
}

// ─── Property: all packets are exactly 64 bytes ─────────────

test "property: all packets are exactly 64 bytes" {
    var rng = makeRng(SEED +% 2);
    var payload_buf: [7609]u8 = undefined;
    var packets: [130]ctaphid.Packet = undefined;

    for (0..ITERATIONS) |_| {
        const r = rng.random();
        const len = r.intRangeAtMost(usize, 0, 7609);
        r.bytes(payload_buf[0..len]);

        const cid: u32 = r.int(u32) | 1;
        const pkt_count = try ctaphid.fragmentMessage(cid, .cbor, payload_buf[0..len], &packets);

        for (0..pkt_count) |i| {
            try std.testing.expectEqual(@as(usize, 64), packets[i].len);
        }
    }
}

// ─── Property: CID is consistent across all packets ─────────

test "property: CID is consistent across all packets" {
    var rng = makeRng(SEED +% 3);
    var payload_buf: [7609]u8 = undefined;
    var packets: [130]ctaphid.Packet = undefined;

    for (0..ITERATIONS) |_| {
        const r = rng.random();
        const len = r.intRangeAtMost(usize, 0, 7609);
        r.bytes(payload_buf[0..len]);

        const cid: u32 = r.int(u32) | 1;
        const pkt_count = try ctaphid.fragmentMessage(cid, .cbor, payload_buf[0..len], &packets);

        for (0..pkt_count) |i| {
            try std.testing.expectEqual(cid, extractCid(&packets[i]));
        }
    }
}

// ─── Property: continuation sequence numbers are sequential ──

test "property: continuation sequence numbers are sequential" {
    var rng = makeRng(SEED +% 4);
    var payload_buf: [7609]u8 = undefined;
    var packets: [130]ctaphid.Packet = undefined;

    for (0..ITERATIONS) |_| {
        const r = rng.random();
        const len = r.intRangeAtMost(usize, 0, 7609);
        r.bytes(payload_buf[0..len]);

        const cid: u32 = r.int(u32) | 1;
        const pkt_count = try ctaphid.fragmentMessage(cid, .cbor, payload_buf[0..len], &packets);

        // Init packet has CMD byte with 0x80 flag
        if (pkt_count > 0) {
            try std.testing.expect(packets[0][4] & 0x80 != 0);
        }

        // Continuation packets: seq 0, 1, 2, ...
        for (1..pkt_count) |i| {
            const seq = packets[i][4];
            try std.testing.expectEqual(@as(u8, @intCast(i - 1)), seq);
        }
    }
}

// ─── Boundary sizes ─────────────────────────────────────────

test "boundary sizes: packet counts and data integrity" {
    const boundary_sizes = [_]usize{ 0, 1, 56, 57, 58, 59, 116, 117, 7609 };
    var payload_buf: [7609]u8 = undefined;
    var packets: [130]ctaphid.Packet = undefined;
    var reassembled: [7609]u8 = undefined;

    // Fill with a recognizable pattern
    for (&payload_buf, 0..) |*b, i| {
        b.* = @intCast(i % 256);
    }

    const cid: u32 = 0xAABBCCDD;

    for (boundary_sizes) |len| {
        const payload = payload_buf[0..len];
        const pkt_count = try ctaphid.fragmentMessage(cid, .cbor, payload, &packets);

        // Verify packet count
        try std.testing.expectEqual(expectedPacketCount(len), pkt_count);

        // Verify all packets are 64 bytes
        for (0..pkt_count) |i| {
            try std.testing.expectEqual(@as(usize, 64), packets[i].len);
        }

        // Verify CID consistency
        for (0..pkt_count) |i| {
            try std.testing.expectEqual(cid, extractCid(&packets[i]));
        }

        // Verify sequential continuation sequence numbers
        for (1..pkt_count) |i| {
            try std.testing.expectEqual(@as(u8, @intCast(i - 1)), packets[i][4]);
        }

        // Verify data roundtrip
        var offset: usize = 0;
        const init_copy = @min(len, ctaphid.INIT_DATA_SIZE);
        @memcpy(reassembled[0..init_copy], packets[0][7..][0..init_copy]);
        offset += init_copy;

        for (1..pkt_count) |i| {
            const remaining = len - offset;
            const cont_copy = @min(remaining, ctaphid.CONT_DATA_SIZE);
            @memcpy(reassembled[offset..][0..cont_copy], packets[i][5..][0..cont_copy]);
            offset += cont_copy;
        }

        try std.testing.expectEqual(len, offset);
        try std.testing.expectEqualSlices(u8, payload, reassembled[0..len]);
    }
}
