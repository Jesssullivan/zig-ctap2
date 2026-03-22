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

// ─── Response Parsing ────────────────────────────────────────

/// Parsed result from authenticatorMakeCredential.
pub const MakeCredentialResult = struct {
    /// CTAP2 status byte (0x00 = success).
    status: u8,
    /// Credential ID extracted from authData attested credential data.
    credential_id: []const u8,
    /// Full attestation object (CBOR bytes, starting after status byte).
    attestation_object: []const u8,
    /// Raw authenticator data (authData field from the attestation object).
    auth_data: []const u8,
};

/// Parsed result from authenticatorGetAssertion.
pub const GetAssertionResult = struct {
    /// CTAP2 status byte (0x00 = success).
    status: u8,
    /// Credential ID (from response key 1, or fallback if omitted).
    credential_id: []const u8,
    /// Raw authenticator data bytes.
    auth_data: []const u8,
    /// Signature bytes.
    signature: []const u8,
    /// User handle bytes (empty if not present).
    user_handle: []const u8,
};

/// Parse a raw CTAP2 authenticatorMakeCredential response.
///
/// The response format is: status_byte(1) + CBOR_map
/// The CBOR map has integer keys:
///   1 = fmt (text string)
///   2 = authData (byte string)
///   3 = attStmt (map)
///
/// From authData we extract the credential ID:
///   rpIdHash(32) + flags(1) + signCount(4) + [aaguid(16) + credIdLen(2) + credentialId(credIdLen) + ...]
pub fn parseMakeCredentialResponse(response_data: []const u8) cbor.Error!MakeCredentialResult {
    if (response_data.len < 1) return cbor.Error.Truncated;

    const status = response_data[0];
    if (status != 0x00) {
        return MakeCredentialResult{
            .status = status,
            .credential_id = &.{},
            .attestation_object = &.{},
            .auth_data = &.{},
        };
    }

    if (response_data.len < 2) return cbor.Error.Truncated;

    // The attestation object is everything after the status byte
    const attestation_object = response_data[1..];

    // Parse the CBOR map
    var dec = cbor.Decoder.init(attestation_object);
    const map_len = try dec.decodeMapHeader();

    var auth_data: []const u8 = &.{};

    // Iterate the map looking for key 2 (authData)
    for (0..map_len) |_| {
        const key = try dec.decodeUint();
        if (key == 2) {
            // authData is a byte string
            auth_data = try dec.decodeByteString();
        } else {
            // Skip value for other keys (1=fmt, 3=attStmt)
            try dec.skipValue();
        }
    }

    if (auth_data.len == 0) return cbor.Error.InvalidCbor;

    // Extract credential ID from authData:
    // rpIdHash(32) + flags(1) + signCount(4) = 37 bytes minimum
    // If flags bit 6 (AT) is set, attested credential data follows:
    //   aaguid(16) + credIdLen(2, big-endian) + credentialId(credIdLen)
    if (auth_data.len < 37) return cbor.Error.Truncated;

    const flags = auth_data[32];
    const has_attested_data = (flags & 0x40) != 0; // bit 6 = AT flag

    if (!has_attested_data) return cbor.Error.InvalidCbor;

    // 37 + 16 (aaguid) + 2 (credIdLen) = 55 minimum
    if (auth_data.len < 55) return cbor.Error.Truncated;

    const cred_id_len = @as(usize, auth_data[53]) << 8 | @as(usize, auth_data[54]);
    if (auth_data.len < 55 + cred_id_len) return cbor.Error.Truncated;

    const credential_id = auth_data[55..][0..cred_id_len];

    return MakeCredentialResult{
        .status = status,
        .credential_id = credential_id,
        .attestation_object = attestation_object,
        .auth_data = auth_data,
    };
}

/// Parse a raw CTAP2 authenticatorGetAssertion response.
///
/// The response format is: status_byte(1) + CBOR_map
/// The CBOR map has integer keys:
///   1 = credential (map with "id" byte string) — optional per spec
///   2 = authData (byte string)
///   3 = signature (byte string)
///   4 = user (map with "id" byte string) — optional
///
/// Per CTAP2 spec: key 1 (credential) is omitted when the allowList in the
/// request had exactly one entry. In that case, use the fallback credential ID.
pub fn parseGetAssertionResponse(
    response_data: []const u8,
    fallback_cred_id: ?[]const u8,
) cbor.Error!GetAssertionResult {
    if (response_data.len < 1) return cbor.Error.Truncated;

    const status = response_data[0];
    if (status != 0x00) {
        return GetAssertionResult{
            .status = status,
            .credential_id = &.{},
            .auth_data = &.{},
            .signature = &.{},
            .user_handle = &.{},
        };
    }

    if (response_data.len < 2) return cbor.Error.Truncated;

    var dec = cbor.Decoder.init(response_data[1..]);
    const map_len = try dec.decodeMapHeader();

    var credential_id: ?[]const u8 = null;
    var auth_data: ?[]const u8 = null;
    var signature: ?[]const u8 = null;
    var user_handle: []const u8 = &.{};

    for (0..map_len) |_| {
        const key = try dec.decodeUint();
        switch (key) {
            1 => {
                // credential: map containing "id" (byte string) and "type" (text)
                const inner_map_len = try dec.decodeMapHeader();
                for (0..inner_map_len) |_| {
                    const inner_key = try dec.decodeTextString();
                    if (std.mem.eql(u8, inner_key, "id")) {
                        credential_id = try dec.decodeByteString();
                    } else {
                        try dec.skipValue();
                    }
                }
            },
            2 => {
                auth_data = try dec.decodeByteString();
            },
            3 => {
                signature = try dec.decodeByteString();
            },
            4 => {
                // user: map containing "id" (byte string) and optionally "name", "displayName"
                const inner_map_len = try dec.decodeMapHeader();
                for (0..inner_map_len) |_| {
                    const inner_key = try dec.decodeTextString();
                    if (std.mem.eql(u8, inner_key, "id")) {
                        user_handle = try dec.decodeByteString();
                    } else {
                        try dec.skipValue();
                    }
                }
            },
            else => {
                try dec.skipValue();
            },
        }
    }

    // Use fallback credential ID if not present in response
    if (credential_id == null) {
        if (fallback_cred_id) |fb| {
            credential_id = fb;
        } else {
            return cbor.Error.InvalidCbor;
        }
    }

    // authData and signature are required
    if (auth_data == null or signature == null) return cbor.Error.InvalidCbor;

    return GetAssertionResult{
        .status = status,
        .credential_id = credential_id.?,
        .auth_data = auth_data.?,
        .signature = signature.?,
        .user_handle = user_handle,
    };
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

// ─── Response Parsing Tests ─────────────────────────────────

test "parseMakeCredentialResponse: non-zero status returns error status" {
    // Status byte 0x27 = operation denied
    const response = [_]u8{0x27};
    const result = try parseMakeCredentialResponse(&response);
    try std.testing.expectEqual(@as(u8, 0x27), result.status);
    try std.testing.expectEqual(@as(usize, 0), result.credential_id.len);
}

test "parseMakeCredentialResponse: valid attestation object" {
    // Build a synthetic MakeCredential response:
    // status(0x00) + CBOR map {1: "packed", 2: authData, 3: {}}
    var buf: [512]u8 = undefined;
    var pos: usize = 0;

    // Status byte
    buf[pos] = 0x00;
    pos += 1;

    // Build the CBOR attestation object in a separate encoder
    var cbor_buf: [512]u8 = undefined;
    var enc = cbor.Encoder.init(&cbor_buf);

    // Map with 3 entries
    try enc.beginMap(3);

    // Key 1: fmt = "packed"
    try enc.encodeUint(1);
    try enc.encodeTextString("packed");

    // Key 2: authData (byte string)
    // authData: rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credIdLen(2) + credentialId(64)
    var auth_data: [119]u8 = undefined;
    // rpIdHash: 32 bytes of 0xAA
    @memset(auth_data[0..32], 0xAA);
    // flags: 0x41 = UP (bit 0) + AT (bit 6) = attested credential data present
    auth_data[32] = 0x41;
    // signCount: 4 bytes, value 1
    auth_data[33] = 0;
    auth_data[34] = 0;
    auth_data[35] = 0;
    auth_data[36] = 1;
    // aaguid: 16 bytes of 0xBB
    @memset(auth_data[37..53], 0xBB);
    // credIdLen: 64 (big-endian)
    auth_data[53] = 0;
    auth_data[54] = 64;
    // credentialId: 64 bytes of 0xCC
    @memset(auth_data[55..119], 0xCC);

    try enc.encodeUint(2);
    try enc.encodeByteString(&auth_data);

    // Key 3: attStmt = {} (empty map)
    try enc.encodeUint(3);
    try enc.beginMap(0);

    const cbor_written = enc.written();
    @memcpy(buf[pos..][0..cbor_written.len], cbor_written);
    pos += cbor_written.len;

    const response = buf[0..pos];
    const result = try parseMakeCredentialResponse(response);

    try std.testing.expectEqual(@as(u8, 0x00), result.status);
    try std.testing.expectEqual(@as(usize, 64), result.credential_id.len);
    // Verify credential ID bytes are all 0xCC
    for (result.credential_id) |b| {
        try std.testing.expectEqual(@as(u8, 0xCC), b);
    }
    // Attestation object should be everything after the status byte
    try std.testing.expectEqual(pos - 1, result.attestation_object.len);
    // Auth data should be 119 bytes
    try std.testing.expectEqual(@as(usize, 119), result.auth_data.len);
}

test "parseGetAssertionResponse: non-zero status returns error status" {
    const response = [_]u8{0x2E}; // noCredentials
    const result = try parseGetAssertionResponse(&response, null);
    try std.testing.expectEqual(@as(u8, 0x2E), result.status);
    try std.testing.expectEqual(@as(usize, 0), result.credential_id.len);
}

test "parseGetAssertionResponse: valid assertion with credential" {
    // Build a synthetic GetAssertion response:
    // status(0x00) + CBOR map {1: {id: <cred>, type: "public-key"}, 2: authData, 3: signature}
    var buf: [512]u8 = undefined;
    var pos: usize = 0;

    // Status byte
    buf[pos] = 0x00;
    pos += 1;

    var cbor_buf: [512]u8 = undefined;
    var enc = cbor.Encoder.init(&cbor_buf);

    // Map with 3 entries (no user handle)
    try enc.beginMap(3);

    // Key 1: credential descriptor map
    try enc.encodeUint(1);
    try enc.beginMap(2);
    try enc.encodeTextString("id");
    const cred_id = [_]u8{0xDE} ** 32;
    try enc.encodeByteString(&cred_id);
    try enc.encodeTextString("type");
    try enc.encodeTextString("public-key");

    // Key 2: authData (37 bytes: rpIdHash + flags + signCount)
    try enc.encodeUint(2);
    var auth_data: [37]u8 = undefined;
    @memset(auth_data[0..32], 0xAA); // rpIdHash
    auth_data[32] = 0x01; // flags: UP
    auth_data[33] = 0;
    auth_data[34] = 0;
    auth_data[35] = 0;
    auth_data[36] = 5; // signCount = 5
    try enc.encodeByteString(&auth_data);

    // Key 3: signature
    try enc.encodeUint(3);
    const sig = [_]u8{0xFF} ** 72;
    try enc.encodeByteString(&sig);

    const cbor_written = enc.written();
    @memcpy(buf[pos..][0..cbor_written.len], cbor_written);
    pos += cbor_written.len;

    const response = buf[0..pos];
    const result = try parseGetAssertionResponse(response, null);

    try std.testing.expectEqual(@as(u8, 0x00), result.status);
    try std.testing.expectEqual(@as(usize, 32), result.credential_id.len);
    try std.testing.expectEqual(@as(u8, 0xDE), result.credential_id[0]);
    try std.testing.expectEqual(@as(usize, 37), result.auth_data.len);
    try std.testing.expectEqual(@as(usize, 72), result.signature.len);
    try std.testing.expectEqual(@as(usize, 0), result.user_handle.len);
}

test "parseGetAssertionResponse: credential omitted, fallback used" {
    // Per CTAP2 spec, key 1 is omitted when allowList had one entry.
    // Build response with only keys 2 and 3.
    var buf: [512]u8 = undefined;
    var pos: usize = 0;

    buf[pos] = 0x00;
    pos += 1;

    var cbor_buf: [512]u8 = undefined;
    var enc = cbor.Encoder.init(&cbor_buf);

    // Map with 2 entries (no credential, no user)
    try enc.beginMap(2);

    // Key 2: authData
    try enc.encodeUint(2);
    var auth_data: [37]u8 = undefined;
    @memset(&auth_data, 0x11);
    try enc.encodeByteString(&auth_data);

    // Key 3: signature
    try enc.encodeUint(3);
    const sig = [_]u8{0x22} ** 64;
    try enc.encodeByteString(&sig);

    const cbor_written = enc.written();
    @memcpy(buf[pos..][0..cbor_written.len], cbor_written);
    pos += cbor_written.len;

    const fallback = [_]u8{0xAB} ** 16;
    const response = buf[0..pos];
    const result = try parseGetAssertionResponse(response, &fallback);

    try std.testing.expectEqual(@as(u8, 0x00), result.status);
    // Should use the fallback credential ID
    try std.testing.expectEqual(@as(usize, 16), result.credential_id.len);
    try std.testing.expectEqual(@as(u8, 0xAB), result.credential_id[0]);
}

test "parseGetAssertionResponse: credential omitted, no fallback fails" {
    var buf: [512]u8 = undefined;
    var pos: usize = 0;

    buf[pos] = 0x00;
    pos += 1;

    var cbor_buf: [512]u8 = undefined;
    var enc = cbor.Encoder.init(&cbor_buf);

    try enc.beginMap(2);
    try enc.encodeUint(2);
    try enc.encodeByteString(&([_]u8{0} ** 37));
    try enc.encodeUint(3);
    try enc.encodeByteString(&([_]u8{0} ** 64));

    const cbor_written = enc.written();
    @memcpy(buf[pos..][0..cbor_written.len], cbor_written);
    pos += cbor_written.len;

    const response = buf[0..pos];
    try std.testing.expectError(cbor.Error.InvalidCbor, parseGetAssertionResponse(response, null));
}

test "parseGetAssertionResponse: with user handle" {
    var buf: [512]u8 = undefined;
    var pos: usize = 0;

    buf[pos] = 0x00;
    pos += 1;

    var cbor_buf: [512]u8 = undefined;
    var enc = cbor.Encoder.init(&cbor_buf);

    // Map with 4 entries including user
    try enc.beginMap(4);

    // Key 1: credential
    try enc.encodeUint(1);
    try enc.beginMap(2);
    try enc.encodeTextString("id");
    try enc.encodeByteString(&([_]u8{0xAA} ** 32));
    try enc.encodeTextString("type");
    try enc.encodeTextString("public-key");

    // Key 2: authData
    try enc.encodeUint(2);
    try enc.encodeByteString(&([_]u8{0xBB} ** 37));

    // Key 3: signature
    try enc.encodeUint(3);
    try enc.encodeByteString(&([_]u8{0xCC} ** 64));

    // Key 4: user with "id" field
    try enc.encodeUint(4);
    try enc.beginMap(1);
    try enc.encodeTextString("id");
    const user_id = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try enc.encodeByteString(&user_id);

    const cbor_written = enc.written();
    @memcpy(buf[pos..][0..cbor_written.len], cbor_written);
    pos += cbor_written.len;

    const response = buf[0..pos];
    const result = try parseGetAssertionResponse(response, null);

    try std.testing.expectEqual(@as(u8, 0x00), result.status);
    try std.testing.expectEqual(@as(usize, 4), result.user_handle.len);
    try std.testing.expectEqual(@as(u8, 0x01), result.user_handle[0]);
    try std.testing.expectEqual(@as(u8, 0x04), result.user_handle[3]);
}

test "parseMakeCredentialResponse: empty input returns Truncated" {
    try std.testing.expectError(cbor.Error.Truncated, parseMakeCredentialResponse(&.{}));
}

test "parseGetAssertionResponse: empty input returns Truncated" {
    try std.testing.expectError(cbor.Error.Truncated, parseGetAssertionResponse(&.{}, null));
}
