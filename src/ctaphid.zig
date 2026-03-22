/// CTAPHID transport framing for FIDO2 USB HID communication.
///
/// Implements the CTAPHID protocol per FIDO Alliance specification:
/// - 64-byte fixed-size HID reports
/// - Initialization and continuation packet framing
/// - Channel ID (CID) management
/// - Message fragmentation and reassembly
///
/// Reference: https://fidoalliance.org/specs/fido-v2.0-id-20180227/
///            fido-client-to-authenticator-protocol-v2.0-id-20180227.html

const std = @import("std");

/// HID report size (fixed by FIDO HID spec).
pub const PACKET_SIZE: usize = 64;

/// Maximum payload in an initialization packet (64 - 4 CID - 1 CMD - 2 BCNT).
pub const INIT_DATA_SIZE: usize = PACKET_SIZE - 7;

/// Maximum payload in a continuation packet (64 - 4 CID - 1 SEQ).
pub const CONT_DATA_SIZE: usize = PACKET_SIZE - 5;

/// Broadcast channel ID for CTAPHID_INIT.
pub const CID_BROADCAST: u32 = 0xFFFFFFFF;

/// CTAPHID command codes.
pub const Command = enum(u8) {
    ping = 0x01,
    msg = 0x03,
    lock = 0x04,
    init = 0x06,
    wink = 0x08,
    cbor = 0x10,
    cancel = 0x11,
    keepalive = 0x3B,
    err = 0x3F,
};

/// Keepalive status codes.
pub const KeepaliveStatus = enum(u8) {
    processing = 1,
    upneeded = 2, // User presence needed (touch the key)
};

pub const Error = error{
    PacketTooLarge,
    InvalidPacket,
    CidMismatch,
    SequenceError,
    DeviceError,
    Timeout,
};

/// A 64-byte HID packet ready to send.
pub const Packet = [PACKET_SIZE]u8;

/// Build an initialization packet.
pub fn buildInitPacket(cid: u32, cmd: Command, payload_len: u16, data: []const u8) Packet {
    var pkt: Packet = std.mem.zeroes(Packet);

    // CID (4 bytes, big-endian)
    pkt[0] = @intCast((cid >> 24) & 0xFF);
    pkt[1] = @intCast((cid >> 16) & 0xFF);
    pkt[2] = @intCast((cid >> 8) & 0xFF);
    pkt[3] = @intCast(cid & 0xFF);

    // CMD with frame init flag (0x80)
    pkt[4] = 0x80 | @intFromEnum(cmd);

    // BCNT (total payload length, 2 bytes big-endian)
    pkt[5] = @intCast((payload_len >> 8) & 0xFF);
    pkt[6] = @intCast(payload_len & 0xFF);

    // Data (up to INIT_DATA_SIZE bytes)
    const copy_len = @min(data.len, INIT_DATA_SIZE);
    @memcpy(pkt[7..][0..copy_len], data[0..copy_len]);

    return pkt;
}

/// Build a continuation packet.
pub fn buildContPacket(cid: u32, seq: u8, data: []const u8) Packet {
    var pkt: Packet = std.mem.zeroes(Packet);

    // CID
    pkt[0] = @intCast((cid >> 24) & 0xFF);
    pkt[1] = @intCast((cid >> 16) & 0xFF);
    pkt[2] = @intCast((cid >> 8) & 0xFF);
    pkt[3] = @intCast(cid & 0xFF);

    // SEQ (no 0x80 flag — distinguishes from init packet)
    pkt[4] = seq;

    // Data (up to CONT_DATA_SIZE bytes)
    const copy_len = @min(data.len, CONT_DATA_SIZE);
    @memcpy(pkt[5..][0..copy_len], data[0..copy_len]);

    return pkt;
}

/// Fragment a message into CTAPHID packets.
/// Returns the number of packets written to `out`.
pub fn fragmentMessage(
    cid: u32,
    cmd: Command,
    payload: []const u8,
    out: []Packet,
) Error!usize {
    if (payload.len > 7609) return Error.PacketTooLarge; // Max: 57 + 128*59

    var pkt_idx: usize = 0;
    var data_offset: usize = 0;

    // Init packet
    const init_copy = @min(payload.len, INIT_DATA_SIZE);
    out[pkt_idx] = buildInitPacket(cid, cmd, @intCast(payload.len), payload[0..init_copy]);
    pkt_idx += 1;
    data_offset += init_copy;

    // Continuation packets
    var seq: u8 = 0;
    while (data_offset < payload.len) {
        if (pkt_idx >= out.len) return Error.PacketTooLarge;
        const cont_copy = @min(payload.len - data_offset, CONT_DATA_SIZE);
        out[pkt_idx] = buildContPacket(cid, seq, payload[data_offset..][0..cont_copy]);
        pkt_idx += 1;
        data_offset += cont_copy;
        seq += 1;
    }

    return pkt_idx;
}

/// Parse an init packet header.
pub const InitHeader = struct {
    cid: u32,
    cmd: Command,
    payload_len: u16,
};

pub fn parseInitPacket(pkt: *const Packet) Error!InitHeader {
    const cid = (@as(u32, pkt[0]) << 24) | (@as(u32, pkt[1]) << 16) |
        (@as(u32, pkt[2]) << 8) | pkt[3];

    if (pkt[4] & 0x80 == 0) return Error.InvalidPacket; // Not an init packet
    const cmd_byte = pkt[4] & 0x7F;
    const cmd: Command = @enumFromInt(cmd_byte);
    const payload_len = (@as(u16, pkt[5]) << 8) | pkt[6];

    return .{ .cid = cid, .cmd = cmd, .payload_len = payload_len };
}

/// Reassemble a complete message from init + continuation packets.
/// `read_fn` is called to get each subsequent packet.
pub fn reassembleMessage(
    init_pkt: *const Packet,
    buf: []u8,
    read_fn: *const fn () Error!Packet,
) Error!struct { cmd: Command, data: []const u8 } {
    const header = try parseInitPacket(init_pkt);

    if (header.payload_len > buf.len) return Error.PacketTooLarge;

    // Copy init packet data
    const init_copy = @min(@as(usize, header.payload_len), INIT_DATA_SIZE);
    @memcpy(buf[0..init_copy], init_pkt[7..][0..init_copy]);
    var received: usize = init_copy;

    // Read continuation packets
    var expected_seq: u8 = 0;
    while (received < header.payload_len) {
        const pkt = try read_fn();

        // Verify CID
        const pkt_cid = (@as(u32, pkt[0]) << 24) | (@as(u32, pkt[1]) << 16) |
            (@as(u32, pkt[2]) << 8) | pkt[3];
        if (pkt_cid != header.cid) return Error.CidMismatch;

        // Check for keepalive
        if (pkt[4] & 0x80 != 0) {
            const resp_cmd: Command = @enumFromInt(pkt[4] & 0x7F);
            if (resp_cmd == .keepalive) {
                // Touch needed or still processing — keep reading
                continue;
            }
            return Error.InvalidPacket;
        }

        // Continuation packet
        if (pkt[4] != expected_seq) return Error.SequenceError;
        expected_seq += 1;

        const remaining = header.payload_len - received;
        const cont_copy = @min(@as(usize, remaining), CONT_DATA_SIZE);
        @memcpy(buf[received..][0..cont_copy], pkt[5..][0..cont_copy]);
        received += cont_copy;
    }

    return .{ .cmd = header.cmd, .data = buf[0..header.payload_len] };
}

/// CTAPHID_INIT response structure.
pub const InitResponse = struct {
    nonce: [8]u8,
    cid: u32,
    protocol_version: u8,
    major: u8,
    minor: u8,
    build: u8,
    capabilities: u8,
};

/// Parse a CTAPHID_INIT response payload.
pub fn parseInitResponse(data: []const u8) Error!InitResponse {
    if (data.len < 17) return Error.InvalidPacket;
    return .{
        .nonce = data[0..8].*,
        .cid = (@as(u32, data[8]) << 24) | (@as(u32, data[9]) << 16) |
            (@as(u32, data[10]) << 8) | data[11],
        .protocol_version = data[12],
        .major = data[13],
        .minor = data[14],
        .build = data[15],
        .capabilities = data[16],
    };
}

// ─── Tests ──────────────────────────────────────────────────

test "build init packet" {
    const pkt = buildInitPacket(0x12345678, .cbor, 10, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });

    // CID
    try std.testing.expectEqual(@as(u8, 0x12), pkt[0]);
    try std.testing.expectEqual(@as(u8, 0x34), pkt[1]);
    try std.testing.expectEqual(@as(u8, 0x56), pkt[2]);
    try std.testing.expectEqual(@as(u8, 0x78), pkt[3]);

    // CMD with init flag
    try std.testing.expectEqual(@as(u8, 0x80 | 0x10), pkt[4]);

    // BCNT
    try std.testing.expectEqual(@as(u8, 0), pkt[5]);
    try std.testing.expectEqual(@as(u8, 10), pkt[6]);

    // Data
    try std.testing.expectEqual(@as(u8, 1), pkt[7]);
    try std.testing.expectEqual(@as(u8, 10), pkt[16]);

    // Padding zeros
    try std.testing.expectEqual(@as(u8, 0), pkt[17]);
}

test "build continuation packet" {
    const pkt = buildContPacket(0x12345678, 0, &[_]u8{0xAA} ** 10);

    // CID
    try std.testing.expectEqual(@as(u8, 0x12), pkt[0]);

    // SEQ (no 0x80 flag)
    try std.testing.expectEqual(@as(u8, 0), pkt[4]);

    // Data
    try std.testing.expectEqual(@as(u8, 0xAA), pkt[5]);
}

test "fragment short message (single packet)" {
    var packets: [8]Packet = undefined;
    const payload = [_]u8{0x04}; // getInfo command byte

    const count = try fragmentMessage(0xABCD1234, .cbor, &payload, &packets);
    try std.testing.expectEqual(@as(usize, 1), count);

    const header = try parseInitPacket(&packets[0]);
    try std.testing.expectEqual(@as(u16, 1), header.payload_len);
    try std.testing.expectEqual(Command.cbor, header.cmd);
}

test "fragment message requiring continuation" {
    var packets: [8]Packet = undefined;
    // 100 bytes needs 1 init (57 data) + 1 continuation (43 data)
    const payload = [_]u8{0xBB} ** 100;

    const count = try fragmentMessage(0x11223344, .cbor, &payload, &packets);
    try std.testing.expectEqual(@as(usize, 2), count);

    // Verify init packet
    const header = try parseInitPacket(&packets[0]);
    try std.testing.expectEqual(@as(u16, 100), header.payload_len);

    // Verify continuation packet seq = 0
    try std.testing.expectEqual(@as(u8, 0), packets[1][4]);
}

test "parse init response" {
    const nonce = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var data: [17]u8 = undefined;
    @memcpy(data[0..8], &nonce);
    // CID = 0xDEADBEEF
    data[8] = 0xDE;
    data[9] = 0xAD;
    data[10] = 0xBE;
    data[11] = 0xEF;
    data[12] = 2; // protocol version
    data[13] = 5; // major
    data[14] = 4; // minor
    data[15] = 3; // build
    data[16] = 0x04; // capabilities (CBOR)

    const resp = try parseInitResponse(&data);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), resp.cid);
    try std.testing.expectEqual(@as(u8, 2), resp.protocol_version);
    try std.testing.expectEqual(@as(u8, 5), resp.major);
    try std.testing.expectEqualSlices(u8, &nonce, &resp.nonce);
}
