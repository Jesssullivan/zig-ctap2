/// CTAP2 command encoding and response parsing.
///
/// Implements authenticatorMakeCredential (0x01), authenticatorGetAssertion (0x02),
/// and authenticatorGetInfo (0x04) per FIDO2 CTAP2 specification.

const std = @import("std");
const cbor = @import("cbor.zig");
const ctaphid = @import("ctaphid.zig");

pub const CommandCode = enum(u8) {
    makeCredential = 0x01,
    getAssertion = 0x02,
    getInfo = 0x04,
    clientPin = 0x06,
    reset = 0x07,
    getNextAssertion = 0x08,
};

pub const StatusCode = enum(u8) {
    success = 0x00,
    invalidCommand = 0x01,
    invalidParameter = 0x02,
    invalidLength = 0x03,
    invalidSeq = 0x04,
    timeout = 0x05,
    channelBusy = 0x06,
    lockRequired = 0x0A,
    invalidChannel = 0x0B,
    pinInvalid = 0x31,
    pinBlocked = 0x32,
    pinAuthInvalid = 0x33,
    pinAuthBlocked = 0x34,
    pinNotSet = 0x35,
    operationDenied = 0x27,
    userActionPending = 0x23,
    upRequired = 0x2B,
    noCredentials = 0x2E,
    _,
};

/// Map a CTAP2 status byte to a human-readable message string.
pub fn statusMessage(status: u8) [:0]const u8 {
    return switch (status) {
        0x00 => "Success",
        0x01 => "Invalid command",
        0x02 => "Invalid parameter",
        0x03 => "Invalid length",
        0x05 => "Timeout",
        0x06 => "Channel busy",
        0x27 => "Operation denied by user",
        0x2E => "No credentials found for this site",
        0x31 => "Incorrect PIN",
        0x32 => "PIN blocked - too many attempts",
        0x33 => "PIN authentication invalid",
        0x35 => "PIN not set - configure a PIN on your security key first",
        0x36 => "PIN policy violation (resident key requires PIN)",
        else => "Unknown authenticator error",
    };
}

/// Encode a makeCredential request into CBOR.
pub fn encodeMakeCredential(
    buf: []u8,
    client_data_hash: []const u8,
    rp_id: []const u8,
    rp_name: []const u8,
    user_id: []const u8,
    user_name: []const u8,
    user_display_name: []const u8,
    algorithms: []const i32,
    resident_key: bool,
) cbor.Error![]const u8 {
    var enc = cbor.Encoder.init(buf);

    // Command byte
    try enc.encodeUint(@intFromEnum(CommandCode.makeCredential));

    // CBOR map with 4-5 entries
    const map_entries: usize = if (resident_key) 5 else 4;
    try enc.beginMap(map_entries);

    // 1: clientDataHash (bytes)
    try enc.encodeUint(1);
    try enc.encodeByteString(client_data_hash);

    // 2: rp (map)
    try enc.encodeUint(2);
    try enc.beginMap(2);
    try enc.encodeTextString("id");
    try enc.encodeTextString(rp_id);
    try enc.encodeTextString("name");
    try enc.encodeTextString(rp_name);

    // 3: user (map)
    try enc.encodeUint(3);
    try enc.beginMap(3);
    try enc.encodeTextString("id");
    try enc.encodeByteString(user_id);
    try enc.encodeTextString("name");
    try enc.encodeTextString(user_name);
    try enc.encodeTextString("displayName");
    try enc.encodeTextString(user_display_name);

    // 4: pubKeyCredParams (array)
    try enc.encodeUint(4);
    try enc.beginArray(algorithms.len);
    for (algorithms) |alg| {
        try enc.beginMap(2);
        try enc.encodeTextString("alg");
        if (alg < 0) {
            try enc.encodeNegInt(alg);
        } else {
            try enc.encodeUint(@intCast(alg));
        }
        try enc.encodeTextString("type");
        try enc.encodeTextString("public-key");
    }

    // 7: options (map) — only if resident key requested
    if (resident_key) {
        try enc.encodeUint(7);
        try enc.beginMap(1);
        try enc.encodeTextString("rk");
        try enc.encodeBool(true);
    }

    return enc.written();
}

/// Encode a getAssertion request into CBOR.
pub fn encodeGetAssertion(
    buf: []u8,
    rp_id: []const u8,
    client_data_hash: []const u8,
    allow_list_ids: []const []const u8,
) cbor.Error![]const u8 {
    var enc = cbor.Encoder.init(buf);

    // Command byte
    try enc.encodeUint(@intFromEnum(CommandCode.getAssertion));

    // CBOR map
    const has_allow_list = allow_list_ids.len > 0;
    try enc.beginMap(if (has_allow_list) 3 else 2);

    // 1: rpId (text)
    try enc.encodeUint(1);
    try enc.encodeTextString(rp_id);

    // 2: clientDataHash (bytes)
    try enc.encodeUint(2);
    try enc.encodeByteString(client_data_hash);

    // 3: allowList (array of descriptors)
    if (has_allow_list) {
        try enc.encodeUint(3);
        try enc.beginArray(allow_list_ids.len);
        for (allow_list_ids) |cred_id| {
            try enc.beginMap(2);
            try enc.encodeTextString("id");
            try enc.encodeByteString(cred_id);
            try enc.encodeTextString("type");
            try enc.encodeTextString("public-key");
        }
    }

    return enc.written();
}

/// Encode a getInfo request.
pub fn encodeGetInfo(buf: []u8) cbor.Error![]const u8 {
    var enc = cbor.Encoder.init(buf);
    try enc.encodeUint(@intFromEnum(CommandCode.getInfo));
    return enc.written();
}

// ─── Tests ──────────────────────────────────────────────────

test "encode makeCredential" {
    var buf: [512]u8 = undefined;
    const hash = [_]u8{0xAA} ** 32;
    const algs = [_]i32{ -7, -257 };

    const encoded = try encodeMakeCredential(
        &buf,
        &hash,
        "webauthn.io",
        "webauthn.io",
        &[_]u8{ 1, 2, 3, 4 },
        "testuser",
        "Test User",
        &algs,
        false,
    );

    // First byte should be command code 0x01
    try std.testing.expectEqual(@as(u8, 0x01), encoded[0]);
    // Remaining bytes are CBOR map
    try std.testing.expect(encoded.len > 50);
}

test "encode getAssertion" {
    var buf: [512]u8 = undefined;
    const hash = [_]u8{0xBB} ** 32;
    const empty_list: []const []const u8 = &.{};

    const encoded = try encodeGetAssertion(
        &buf,
        "github.com",
        &hash,
        empty_list,
    );

    // First byte should be command code 0x02
    try std.testing.expectEqual(@as(u8, 0x02), encoded[0]);
}

test "encode getInfo" {
    var buf: [8]u8 = undefined;
    const encoded = try encodeGetInfo(&buf);

    // Single byte: command 0x04
    try std.testing.expectEqual(@as(usize, 1), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x04), encoded[0]);
}

test "statusMessage known codes" {
    try std.testing.expectEqualStrings("Success", statusMessage(0x00));
    try std.testing.expectEqualStrings("Timeout", statusMessage(0x05));
    try std.testing.expectEqualStrings("Operation denied by user", statusMessage(0x27));
    try std.testing.expectEqualStrings("No credentials found for this site", statusMessage(0x2E));
    try std.testing.expectEqualStrings("Incorrect PIN", statusMessage(0x31));
    try std.testing.expectEqualStrings("PIN blocked - too many attempts", statusMessage(0x32));
    try std.testing.expectEqualStrings("PIN not set - configure a PIN on your security key first", statusMessage(0x35));
}

test "statusMessage unknown code" {
    try std.testing.expectEqualStrings("Unknown authenticator error", statusMessage(0xFF));
}
