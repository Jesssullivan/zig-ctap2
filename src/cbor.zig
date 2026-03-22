/// Minimal CBOR encoder/decoder for CTAP2.
///
/// Supports only the subset required by the FIDO2 CTAP2 specification:
/// - Unsigned integers (major type 0)
/// - Negative integers (major type 1) — for COSE algorithm IDs
/// - Byte strings (major type 2)
/// - Text strings (major type 3)
/// - Arrays (major type 4)
/// - Maps (major type 5)
/// - Simple values: true, false, null (major type 7)
///
/// No tags, floats, or indefinite-length encoding.
/// Map keys are encoded in canonical order per CTAP2 spec.

const std = @import("std");

pub const Error = error{
    BufferOverflow,
    InvalidCbor,
    UnexpectedType,
    Truncated,
};

/// CBOR major types (top 3 bits of initial byte).
const MajorType = enum(u3) {
    unsigned = 0,
    negative = 1,
    bytes = 2,
    text = 3,
    array = 4,
    map = 5,
    tag = 6,
    simple = 7,
};

/// A decoded CBOR value.
pub const Value = union(enum) {
    unsigned: u64,
    negative: i64,
    bytes: []const u8,
    text: []const u8,
    array: []const Value,
    map: []const MapEntry,
    bool_val: bool,
    null_val: void,
};

pub const MapEntry = struct {
    key: Value,
    value: Value,
};

// ─── Encoder ────────────────────────────────────────────────

pub const Encoder = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Encoder {
        return .{ .buf = buf };
    }

    pub fn written(self: *const Encoder) []const u8 {
        return self.buf[0..self.pos];
    }

    fn ensureCapacity(self: *Encoder, n: usize) Error!void {
        if (self.pos + n > self.buf.len) return Error.BufferOverflow;
    }

    fn writeByte(self: *Encoder, b: u8) Error!void {
        try self.ensureCapacity(1);
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    fn writeBytes(self: *Encoder, data: []const u8) Error!void {
        try self.ensureCapacity(data.len);
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
    }

    /// Encode a CBOR type header (major type + argument).
    fn writeHeader(self: *Encoder, major: MajorType, arg: u64) Error!void {
        const mt: u8 = @as(u8, @intFromEnum(major)) << 5;
        if (arg < 24) {
            try self.writeByte(mt | @as(u8, @intCast(arg)));
        } else if (arg <= 0xFF) {
            try self.writeByte(mt | 24);
            try self.writeByte(@intCast(arg));
        } else if (arg <= 0xFFFF) {
            try self.writeByte(mt | 25);
            try self.writeBytes(&std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(arg))));
        } else if (arg <= 0xFFFFFFFF) {
            try self.writeByte(mt | 26);
            try self.writeBytes(&std.mem.toBytes(std.mem.nativeToBig(u32, @intCast(arg))));
        } else {
            try self.writeByte(mt | 27);
            try self.writeBytes(&std.mem.toBytes(std.mem.nativeToBig(u64, arg)));
        }
    }

    /// Encode an unsigned integer.
    pub fn encodeUint(self: *Encoder, val: u64) Error!void {
        try self.writeHeader(.unsigned, val);
    }

    /// Encode a negative integer (CBOR stores as -1 - n).
    pub fn encodeNegInt(self: *Encoder, val: i64) Error!void {
        std.debug.assert(val < 0);
        const n: u64 = @intCast(-(val + 1));
        try self.writeHeader(.negative, n);
    }

    /// Encode a byte string.
    pub fn encodeByteString(self: *Encoder, data: []const u8) Error!void {
        try self.writeHeader(.bytes, data.len);
        try self.writeBytes(data);
    }

    /// Encode a text string.
    pub fn encodeTextString(self: *Encoder, text: []const u8) Error!void {
        try self.writeHeader(.text, text.len);
        try self.writeBytes(text);
    }

    /// Begin an array of known length.
    pub fn beginArray(self: *Encoder, len: usize) Error!void {
        try self.writeHeader(.array, len);
    }

    /// Begin a map of known length.
    pub fn beginMap(self: *Encoder, len: usize) Error!void {
        try self.writeHeader(.map, len);
    }

    /// Encode a boolean.
    pub fn encodeBool(self: *Encoder, val: bool) Error!void {
        try self.writeByte(if (val) 0xF5 else 0xF4);
    }

    /// Encode null.
    pub fn encodeNull(self: *Encoder) Error!void {
        try self.writeByte(0xF6);
    }
};

// ─── Decoder ────────────────────────────────────────────────

/// A decoded CBOR header: major type and argument.
pub const Header = struct {
    major: MajorType,
    arg: u64,
};

pub const Decoder = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Decoder {
        return .{ .data = data };
    }

    pub fn remaining(self: *const Decoder) usize {
        return self.data.len - self.pos;
    }

    fn readByte(self: *Decoder) Error!u8 {
        if (self.pos >= self.data.len) return Error.Truncated;
        const b = self.data[self.pos];
        self.pos += 1;
        return b;
    }

    fn readBytes(self: *Decoder, n: usize) Error![]const u8 {
        if (self.pos + n > self.data.len) return Error.Truncated;
        const slice = self.data[self.pos..][0..n];
        self.pos += n;
        return slice;
    }

    /// Read a CBOR type header, returning (major type, argument).
    fn readHeader(self: *Decoder) Error!Header {
        const initial = try self.readByte();
        const major: MajorType = @enumFromInt(@as(u3, @intCast(initial >> 5)));
        const additional = initial & 0x1F;

        const arg: u64 = if (additional < 24)
            additional
        else if (additional == 24)
            try self.readByte()
        else if (additional == 25) blk: {
            const bytes = try self.readBytes(2);
            break :blk std.mem.bigToNative(u16, @bitCast(bytes[0..2].*));
        } else if (additional == 26) blk: {
            const bytes = try self.readBytes(4);
            break :blk std.mem.bigToNative(u32, @bitCast(bytes[0..4].*));
        } else if (additional == 27) blk: {
            const bytes = try self.readBytes(8);
            break :blk std.mem.bigToNative(u64, @bitCast(bytes[0..8].*));
        } else {
            return Error.InvalidCbor;
        };

        return .{ .major = major, .arg = arg };
    }

    /// Decode a single unsigned integer.
    pub fn decodeUint(self: *Decoder) Error!u64 {
        const h = try self.readHeader();
        if (h.major != .unsigned) return Error.UnexpectedType;
        return h.arg;
    }

    /// Decode a byte string, returning a slice into the source data.
    pub fn decodeByteString(self: *Decoder) Error![]const u8 {
        const h = try self.readHeader();
        if (h.major != .bytes) return Error.UnexpectedType;
        return try self.readBytes(@intCast(h.arg));
    }

    /// Decode a text string, returning a slice into the source data.
    pub fn decodeTextString(self: *Decoder) Error![]const u8 {
        const h = try self.readHeader();
        if (h.major != .text) return Error.UnexpectedType;
        return try self.readBytes(@intCast(h.arg));
    }

    /// Decode an array header, returning the element count.
    pub fn decodeArrayHeader(self: *Decoder) Error!usize {
        const h = try self.readHeader();
        if (h.major != .array) return Error.UnexpectedType;
        return @intCast(h.arg);
    }

    /// Decode a map header, returning the entry count.
    pub fn decodeMapHeader(self: *Decoder) Error!usize {
        const h = try self.readHeader();
        if (h.major != .map) return Error.UnexpectedType;
        return @intCast(h.arg);
    }

    /// Peek at the major type of the next value without consuming it.
    pub fn peekMajorType(self: *const Decoder) Error!MajorType {
        if (self.pos >= self.data.len) return Error.Truncated;
        return @enumFromInt(@as(u3, @intCast(self.data[self.pos] >> 5)));
    }

    /// Skip a single CBOR value (including nested structures).
    pub fn skipValue(self: *Decoder) Error!void {
        const h = try self.readHeader();
        switch (h.major) {
            .unsigned, .negative => {},
            .bytes, .text => {
                _ = try self.readBytes(@intCast(h.arg));
            },
            .array => {
                var i: usize = 0;
                while (i < h.arg) : (i += 1) {
                    try self.skipValue();
                }
            },
            .map => {
                var i: usize = 0;
                while (i < h.arg) : (i += 1) {
                    try self.skipValue(); // key
                    try self.skipValue(); // value
                }
            },
            .simple => {
                // Simple values and bools are self-contained in the header
            },
            .tag => {
                // Skip the tagged value
                try self.skipValue();
            },
        }
    }

    /// Decode a header and return the raw major type + arg for flexible handling.
    pub fn decodeRawHeader(self: *Decoder) Error!Header {
        return self.readHeader();
    }
};

// ─── Tests ──────────────────────────────────────────────────

test "encode/decode unsigned integers" {
    var buf: [64]u8 = undefined;
    var enc = Encoder.init(&buf);

    try enc.encodeUint(0);
    try enc.encodeUint(23);
    try enc.encodeUint(24);
    try enc.encodeUint(255);
    try enc.encodeUint(256);
    try enc.encodeUint(65535);
    try enc.encodeUint(65536);

    var dec = Decoder.init(enc.written());
    try std.testing.expectEqual(@as(u64, 0), try dec.decodeUint());
    try std.testing.expectEqual(@as(u64, 23), try dec.decodeUint());
    try std.testing.expectEqual(@as(u64, 24), try dec.decodeUint());
    try std.testing.expectEqual(@as(u64, 255), try dec.decodeUint());
    try std.testing.expectEqual(@as(u64, 256), try dec.decodeUint());
    try std.testing.expectEqual(@as(u64, 65535), try dec.decodeUint());
    try std.testing.expectEqual(@as(u64, 65536), try dec.decodeUint());
}

test "encode/decode byte strings" {
    var buf: [128]u8 = undefined;
    var enc = Encoder.init(&buf);

    try enc.encodeByteString("");
    try enc.encodeByteString("hello");
    try enc.encodeByteString(&[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF });

    var dec = Decoder.init(enc.written());
    try std.testing.expectEqualSlices(u8, "", try dec.decodeByteString());
    try std.testing.expectEqualSlices(u8, "hello", try dec.decodeByteString());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, try dec.decodeByteString());
}

test "encode/decode text strings" {
    var buf: [64]u8 = undefined;
    var enc = Encoder.init(&buf);

    try enc.encodeTextString("webauthn.io");

    var dec = Decoder.init(enc.written());
    try std.testing.expectEqualSlices(u8, "webauthn.io", try dec.decodeTextString());
}

test "encode/decode map with integer keys (CTAP2 pattern)" {
    var buf: [256]u8 = undefined;
    var enc = Encoder.init(&buf);

    // Simulate a CTAP2 getAssertion request:
    // {1: "webauthn.io", 2: <32-byte hash>}
    try enc.beginMap(2);
    try enc.encodeUint(1);
    try enc.encodeTextString("webauthn.io");
    try enc.encodeUint(2);
    try enc.encodeByteString(&([_]u8{0xAA} ** 32));

    var dec = Decoder.init(enc.written());
    const map_len = try dec.decodeMapHeader();
    try std.testing.expectEqual(@as(usize, 2), map_len);

    // Key 1 → text
    try std.testing.expectEqual(@as(u64, 1), try dec.decodeUint());
    try std.testing.expectEqualSlices(u8, "webauthn.io", try dec.decodeTextString());

    // Key 2 → bytes
    try std.testing.expectEqual(@as(u64, 2), try dec.decodeUint());
    const hash = try dec.decodeByteString();
    try std.testing.expectEqual(@as(usize, 32), hash.len);
}

test "encode negative integer (COSE algorithm ID)" {
    var buf: [16]u8 = undefined;
    var enc = Encoder.init(&buf);

    // ES256 = -7, RS256 = -257
    try enc.encodeNegInt(-7);
    try enc.encodeNegInt(-257);

    // Verify raw encoding: -7 → major type 1, arg 6 → 0x26
    try std.testing.expectEqual(@as(u8, 0x26), enc.buf[0]);
}

test "skip nested structures" {
    var buf: [256]u8 = undefined;
    var enc = Encoder.init(&buf);

    // {1: [10, 20], 2: "hello"}
    try enc.beginMap(2);
    try enc.encodeUint(1);
    try enc.beginArray(2);
    try enc.encodeUint(10);
    try enc.encodeUint(20);
    try enc.encodeUint(2);
    try enc.encodeTextString("hello");

    var dec = Decoder.init(enc.written());
    const map_len = try dec.decodeMapHeader();
    try std.testing.expectEqual(@as(usize, 2), map_len);

    // Read key 1, skip value (array)
    _ = try dec.decodeUint();
    try dec.skipValue();

    // Read key 2, read value
    try std.testing.expectEqual(@as(u64, 2), try dec.decodeUint());
    try std.testing.expectEqualSlices(u8, "hello", try dec.decodeTextString());
}
