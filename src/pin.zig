/// CTAP2 Client PIN protocol v2 (authenticatorClientPIN command 0x06).
///
/// Implements PIN operations needed for YubiKeys with a PIN set and
/// enterprise environments that mandate PINs:
///   - getPINRetries (subCommand 0x01)
///   - getKeyAgreement (subCommand 0x02)
///   - getPINToken via getPinUvAuthTokenUsingPinWithPermissions (subCommand 0x09)
///
/// Uses PIN protocol v2:
///   - ECDH P-256 key agreement
///   - HMAC-SHA-256 for pinAuth
///   - AES-256-CBC for PIN encryption
///
/// Reference: CTAP2.1 spec section 6.5
/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorClientPIN

const std = @import("std");
const cbor = @import("cbor.zig");

/// PIN protocol version we use.
pub const PIN_PROTOCOL_VERSION: u8 = 2;

/// authenticatorClientPIN subcommands.
pub const SubCommand = enum(u8) {
    getPINRetries = 0x01,
    getKeyAgreement = 0x02,
    setPIN = 0x03,
    changePIN = 0x04,
    getPINToken = 0x05,
    getPinUvAuthTokenUsingUvWithPermissions = 0x06,
    getUVRetries = 0x07,
    setMinPINLength = 0x08,
    getPinUvAuthTokenUsingPinWithPermissions = 0x09,
};

/// CTAP2 clientPIN command byte.
const CLIENT_PIN_CMD: u8 = 0x06;

/// Result from getPINRetries.
pub const PINRetriesResult = struct {
    /// Number of PIN retries remaining before lockout.
    retries: u32,
    /// If true, a power cycle is required before the next PIN attempt.
    power_cycle_required: bool,
};

/// A COSE_Key for EC2 P-256 (used in key agreement).
pub const CoseKey = struct {
    /// X coordinate (32 bytes).
    x: [32]u8,
    /// Y coordinate (32 bytes).
    y: [32]u8,
};

/// Ephemeral key pair for ECDH key agreement.
pub const EphemeralKeyPair = struct {
    /// Our private scalar (32 bytes).
    private_key: [32]u8,
    /// Our public key in COSE format.
    public_key: CoseKey,
};

/// Shared secret derived from ECDH.
pub const SharedSecret = struct {
    /// The raw shared secret (SHA-256 of the ECDH point x-coordinate), 32 bytes.
    data: [32]u8,
};

/// Result from getPINToken.
pub const PINTokenResult = struct {
    /// The decrypted PIN token (typically 32 bytes).
    token: [32]u8,
};

// ─── Cryptographic Primitives ────────────────────────────────

const P256 = std.crypto.ecc.P256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Generate an ephemeral ECDH P-256 key pair for key agreement.
pub fn generateKeyPair() EphemeralKeyPair {
    // Generate a random scalar (private key)
    var private_key: [32]u8 = undefined;
    std.crypto.random.bytes(&private_key);

    // Derive the public key by multiplying the base point
    const public_point = P256.basePoint.mul(private_key, .big) catch {
        // If the random scalar is invalid (zero or >= order), retry.
        // This is astronomically unlikely but we handle it.
        std.crypto.random.bytes(&private_key);
        return generateKeyPair();
    };

    const affine = public_point.affineCoordinates();

    return .{
        .private_key = private_key,
        .public_key = .{
            .x = affine.x.toBytes(.big),
            .y = affine.y.toBytes(.big),
        },
    };
}

/// Perform ECDH: multiply their public point by our private scalar.
/// Returns SHA-256 of the x-coordinate of the shared point.
pub fn deriveSharedSecret(
    our_private: [32]u8,
    their_public: CoseKey,
) !SharedSecret {
    // Reconstruct their public point from serialized x, y coordinates
    const their_point = P256.fromSerializedAffineCoordinates(
        their_public.x,
        their_public.y,
        .big,
    ) catch return error.InvalidPublicKey;

    // Perform scalar multiplication: shared_point = our_private * their_public
    const shared_point = their_point.mul(our_private, .big) catch return error.InvalidScalar;

    const affine = shared_point.affineCoordinates();
    const x_bytes = affine.x.toBytes(.big);

    // PIN protocol v2: shared secret = SHA-256(x-coordinate)
    var hash: [32]u8 = undefined;
    Sha256.hash(&x_bytes, &hash, .{});

    return SharedSecret{ .data = hash };
}

/// Compute HMAC-SHA-256(key, message).
pub fn computeHmac(key: []const u8, message: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    HmacSha256.create(&out, message, key);
    return out;
}

/// Compute pinAuth: first 16 bytes of HMAC-SHA-256(pinToken, message).
/// Used for authenticating commands with a PIN token.
pub fn computePinAuth(pin_token: []const u8, message: []const u8) [16]u8 {
    const full_hmac = computeHmac(pin_token, message);
    return full_hmac[0..16].*;
}

/// AES-256-CBC encrypt (with zero IV, per CTAP2 PIN protocol v2 spec).
/// Input must be a multiple of 16 bytes.
/// Returns the ciphertext (same length as input).
pub fn aes256CbcEncrypt(
    key: [32]u8,
    plaintext: []const u8,
    out: []u8,
) !void {
    if (plaintext.len == 0 or plaintext.len % 16 != 0) return error.InvalidLength;
    if (out.len < plaintext.len) return error.BufferTooSmall;

    const ctx = std.crypto.core.aes.Aes256.initEnc(key);

    // CBC mode with zero IV
    var prev_block: [16]u8 = std.mem.zeroes([16]u8);
    var offset: usize = 0;

    while (offset < plaintext.len) : (offset += 16) {
        // XOR plaintext block with previous ciphertext block (or IV)
        var block: [16]u8 = undefined;
        for (0..16) |i| {
            block[i] = plaintext[offset + i] ^ prev_block[i];
        }

        // Encrypt the block
        ctx.encrypt(&prev_block, &block);

        // Copy ciphertext to output
        @memcpy(out[offset..][0..16], &prev_block);
    }
}

/// AES-256-CBC decrypt (with zero IV, per CTAP2 PIN protocol v2 spec).
/// Input must be a multiple of 16 bytes.
/// Returns the plaintext (same length as input).
pub fn aes256CbcDecrypt(
    key: [32]u8,
    ciphertext: []const u8,
    out: []u8,
) !void {
    if (ciphertext.len == 0 or ciphertext.len % 16 != 0) return error.InvalidLength;
    if (out.len < ciphertext.len) return error.BufferTooSmall;

    const ctx = std.crypto.core.aes.Aes256.initDec(key);

    // CBC mode with zero IV
    var prev_cipher_block: [16]u8 = std.mem.zeroes([16]u8);
    var offset: usize = 0;

    while (offset < ciphertext.len) : (offset += 16) {
        const cipher_block = ciphertext[offset..][0..16];

        // Decrypt the block
        var decrypted: [16]u8 = undefined;
        ctx.decrypt(&decrypted, cipher_block);

        // XOR with previous ciphertext block (or IV)
        for (0..16) |i| {
            out[offset + i] = decrypted[i] ^ prev_cipher_block[i];
        }

        // Save current ciphertext block for next iteration
        prev_cipher_block = cipher_block.*;
    }
}

// ─── CBOR Encoding for ClientPIN Commands ────────────────────

/// Encode a getPINRetries request.
/// Request: {1: pinUvAuthProtocol(2), 2: subCommand(1)}
pub fn encodeGetPINRetries(buf: []u8) cbor.Error![]const u8 {
    var enc = cbor.Encoder.init(buf);

    // Command byte
    try enc.encodeUint(CLIENT_PIN_CMD);

    // Map with 2 entries
    try enc.beginMap(2);

    // 1: pinUvAuthProtocol
    try enc.encodeUint(1);
    try enc.encodeUint(PIN_PROTOCOL_VERSION);

    // 2: subCommand
    try enc.encodeUint(2);
    try enc.encodeUint(@intFromEnum(SubCommand.getPINRetries));

    return enc.written();
}

/// Encode a getKeyAgreement request.
/// Request: {1: pinUvAuthProtocol(2), 2: subCommand(2)}
pub fn encodeGetKeyAgreement(buf: []u8) cbor.Error![]const u8 {
    var enc = cbor.Encoder.init(buf);

    // Command byte
    try enc.encodeUint(CLIENT_PIN_CMD);

    // Map with 2 entries
    try enc.beginMap(2);

    // 1: pinUvAuthProtocol
    try enc.encodeUint(1);
    try enc.encodeUint(PIN_PROTOCOL_VERSION);

    // 2: subCommand
    try enc.encodeUint(2);
    try enc.encodeUint(@intFromEnum(SubCommand.getKeyAgreement));

    return enc.written();
}

/// Encode a COSE_Key map into the CBOR encoder.
/// COSE_Key: {1: 2 (EC2), 3: -25 (ECDH-ES+HKDF-256), -1: 1 (P-256), -2: x, -3: y}
fn encodeCoseKey(enc: *cbor.Encoder, key: CoseKey) cbor.Error!void {
    try enc.beginMap(5);

    // 1: kty = 2 (EC2)
    try enc.encodeUint(1);
    try enc.encodeUint(2);

    // 3: alg = -25 (ECDH-ES+HKDF-256)
    try enc.encodeUint(3);
    try enc.encodeNegInt(-25);

    // -1: crv = 1 (P-256)
    try enc.encodeNegInt(-1);
    try enc.encodeUint(1);

    // -2: x coordinate
    try enc.encodeNegInt(-2);
    try enc.encodeByteString(&key.x);

    // -3: y coordinate
    try enc.encodeNegInt(-3);
    try enc.encodeByteString(&key.y);
}

/// Encode a getPinUvAuthTokenUsingPinWithPermissions request (subCommand 0x09).
/// Request: {1: protocol, 2: subCommand(9), 3: keyAgreement(COSE_Key), 6: pinHashEnc}
pub fn encodeGetPINToken(
    buf: []u8,
    our_public_key: CoseKey,
    pin_hash_enc: []const u8,
) cbor.Error![]const u8 {
    var enc = cbor.Encoder.init(buf);

    // Command byte
    try enc.encodeUint(CLIENT_PIN_CMD);

    // Map with 4 entries: protocol, subCommand, keyAgreement, pinHashEnc
    try enc.beginMap(4);

    // 1: pinUvAuthProtocol
    try enc.encodeUint(1);
    try enc.encodeUint(PIN_PROTOCOL_VERSION);

    // 2: subCommand
    try enc.encodeUint(2);
    try enc.encodeUint(@intFromEnum(SubCommand.getPinUvAuthTokenUsingPinWithPermissions));

    // 3: keyAgreement (COSE_Key)
    try enc.encodeUint(3);
    try encodeCoseKey(&enc, our_public_key);

    // 6: pinHashEnc
    try enc.encodeUint(6);
    try enc.encodeByteString(pin_hash_enc);

    return enc.written();
}

// ─── Response Parsing ────────────────────────────────────────

/// Parse a getPINRetries response.
/// Response CBOR (after status byte): {3: pinRetries, 4: powerCycleState(optional)}
pub fn parsePINRetriesResponse(response_data: []const u8) !PINRetriesResult {
    if (response_data.len < 1) return error.Truncated;

    const status = response_data[0];
    if (status != 0x00) return error.DeviceError;

    if (response_data.len < 2) return error.Truncated;

    var dec = cbor.Decoder.init(response_data[1..]);
    const map_len = try dec.decodeMapHeader();

    var retries: ?u32 = null;
    var power_cycle: bool = false;

    for (0..map_len) |_| {
        const key = try dec.decodeUint();
        switch (key) {
            3 => {
                retries = @intCast(try dec.decodeUint());
            },
            4 => {
                // powerCycleState is a boolean
                const h = try dec.decodeRawHeader();
                if (h.major == .simple) {
                    power_cycle = (h.arg == 21); // CBOR true = 0xF5 = simple(21)
                } else {
                    try dec.skipValue();
                }
            },
            else => {
                try dec.skipValue();
            },
        }
    }

    if (retries == null) return error.InvalidResponse;

    return PINRetriesResult{
        .retries = retries.?,
        .power_cycle_required = power_cycle,
    };
}

/// Parse a getKeyAgreement response.
/// Response CBOR (after status byte): {1: keyAgreement(COSE_Key)}
/// COSE_Key: {1: kty(2), 3: alg(-25), -1: crv(1), -2: x(32 bytes), -3: y(32 bytes)}
pub fn parseKeyAgreementResponse(response_data: []const u8) !CoseKey {
    if (response_data.len < 1) return error.Truncated;

    const status = response_data[0];
    if (status != 0x00) return error.DeviceError;

    if (response_data.len < 2) return error.Truncated;

    var dec = cbor.Decoder.init(response_data[1..]);
    const map_len = try dec.decodeMapHeader();

    var authenticator_key: ?CoseKey = null;

    for (0..map_len) |_| {
        const key = try dec.decodeUint();
        if (key == 1) {
            authenticator_key = try decodeCoseKey(&dec);
        } else {
            try dec.skipValue();
        }
    }

    if (authenticator_key == null) return error.InvalidResponse;
    return authenticator_key.?;
}

/// Decode a COSE_Key from a CBOR decoder.
/// Handles both positive and negative integer keys.
fn decodeCoseKey(dec: *cbor.Decoder) !CoseKey {
    const inner_map_len = try dec.decodeMapHeader();

    var x: ?[32]u8 = null;
    var y: ?[32]u8 = null;

    for (0..inner_map_len) |_| {
        // COSE keys can be positive (1, 3) or negative (-1, -2, -3).
        const h = try dec.decodeRawHeader();

        if (h.major == .unsigned) {
            // Positive key (1 = kty, 3 = alg)
            // We only care about -2 (x) and -3 (y), so skip these.
            try dec.skipValue();
        } else if (h.major == .negative) {
            // Negative key: CBOR negative = -1 - arg, so arg=0 means -1, arg=1 means -2, etc.
            const neg_key_val = h.arg; // 0 = -1 (crv), 1 = -2 (x), 2 = -3 (y)
            switch (neg_key_val) {
                0 => {
                    // -1: crv (skip, we know it's P-256)
                    try dec.skipValue();
                },
                1 => {
                    // -2: x coordinate
                    const x_bytes = try dec.decodeByteString();
                    if (x_bytes.len != 32) return error.InvalidResponse;
                    x = x_bytes[0..32].*;
                },
                2 => {
                    // -3: y coordinate
                    const y_bytes = try dec.decodeByteString();
                    if (y_bytes.len != 32) return error.InvalidResponse;
                    y = y_bytes[0..32].*;
                },
                else => {
                    try dec.skipValue();
                },
            }
        } else {
            try dec.skipValue();
            try dec.skipValue();
        }
    }

    if (x == null or y == null) return error.InvalidResponse;

    return CoseKey{ .x = x.?, .y = y.? };
}

/// Parse a getPINToken response.
/// Response CBOR (after status byte): {2: pinUvAuthToken(encrypted bytes)}
pub fn parsePINTokenResponse(
    response_data: []const u8,
    shared_secret: SharedSecret,
) !PINTokenResult {
    if (response_data.len < 1) return error.Truncated;

    const status = response_data[0];
    if (status != 0x00) return error.DeviceError;

    if (response_data.len < 2) return error.Truncated;

    var dec = cbor.Decoder.init(response_data[1..]);
    const map_len = try dec.decodeMapHeader();

    var encrypted_token: ?[]const u8 = null;

    for (0..map_len) |_| {
        const key = try dec.decodeUint();
        if (key == 2) {
            encrypted_token = try dec.decodeByteString();
        } else {
            try dec.skipValue();
        }
    }

    if (encrypted_token == null) return error.InvalidResponse;
    const enc_token = encrypted_token.?;

    // Decrypt the PIN token using AES-256-CBC with the shared secret
    if (enc_token.len < 16 or enc_token.len % 16 != 0) return error.InvalidResponse;

    var decrypted: [64]u8 = undefined;
    if (enc_token.len > 64) return error.InvalidResponse;

    aes256CbcDecrypt(shared_secret.data, enc_token, &decrypted) catch return error.InvalidResponse;

    // PIN token is typically 32 bytes
    var result: PINTokenResult = undefined;
    if (enc_token.len >= 32) {
        result.token = decrypted[0..32].*;
    } else {
        // Pad with zeros if shorter (unusual but handle it)
        @memset(&result.token, 0);
        @memcpy(result.token[0..enc_token.len], decrypted[0..enc_token.len]);
    }

    return result;
}

// ─── High-Level PIN Operations ───────────────────────────────

/// Prepare the encrypted PIN hash for a getPINToken request.
/// Takes a UTF-8 PIN string, hashes it with SHA-256, takes the first 16 bytes,
/// pads to 64 bytes, and encrypts with AES-256-CBC using the shared secret.
///
/// Returns the 64-byte encrypted PIN hash.
pub fn encryptPINHash(
    pin: []const u8,
    shared_secret: SharedSecret,
) ![64]u8 {
    // SHA-256 of the PIN
    var pin_hash: [32]u8 = undefined;
    Sha256.hash(pin, &pin_hash, .{});

    // Take LEFT(SHA-256(PIN), 16) and pad to 64 bytes with zeros
    var padded: [64]u8 = std.mem.zeroes([64]u8);
    @memcpy(padded[0..16], pin_hash[0..16]);

    // Encrypt with AES-256-CBC(shared_secret, padded)
    var encrypted: [64]u8 = undefined;
    aes256CbcEncrypt(shared_secret.data, &padded, &encrypted) catch return error.EncryptionFailed;

    return encrypted;
}

/// Encode a makeCredential command with pinAuth and pinUvAuthProtocol.
/// This adds parameters 8 (pinUvAuthProtocol) and 9 (pinAuth) to the command.
///
/// pinAuth = LEFT(HMAC-SHA-256(pinToken, clientDataHash), 16)
pub fn encodeMakeCredentialWithPIN(
    buf: []u8,
    client_data_hash: []const u8,
    rp_id: []const u8,
    rp_name: []const u8,
    user_id: []const u8,
    user_name: []const u8,
    user_display_name: []const u8,
    algorithms: []const i32,
    resident_key: bool,
    pin_token: [32]u8,
) cbor.Error![]const u8 {
    var enc = cbor.Encoder.init(buf);

    // Command byte: makeCredential = 0x01
    try enc.encodeUint(0x01);

    // Compute pinAuth = LEFT(HMAC-SHA-256(pinToken, clientDataHash), 16)
    const pin_auth = computePinAuth(&pin_token, client_data_hash);

    // Map with 6 or 7 entries (base 4 + rk option + pinUvAuthProtocol + pinAuth)
    const base_entries: usize = if (resident_key) 5 else 4;
    try enc.beginMap(base_entries + 2); // +2 for pinAuth fields

    // 1: clientDataHash
    try enc.encodeUint(1);
    try enc.encodeByteString(client_data_hash);

    // 2: rp
    try enc.encodeUint(2);
    try enc.beginMap(2);
    try enc.encodeTextString("id");
    try enc.encodeTextString(rp_id);
    try enc.encodeTextString("name");
    try enc.encodeTextString(rp_name);

    // 3: user
    try enc.encodeUint(3);
    try enc.beginMap(3);
    try enc.encodeTextString("id");
    try enc.encodeByteString(user_id);
    try enc.encodeTextString("name");
    try enc.encodeTextString(user_name);
    try enc.encodeTextString("displayName");
    try enc.encodeTextString(user_display_name);

    // 4: pubKeyCredParams
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

    // 7: options (only if resident key)
    if (resident_key) {
        try enc.encodeUint(7);
        try enc.beginMap(1);
        try enc.encodeTextString("rk");
        try enc.encodeBool(true);
    }

    // 8: pinUvAuthParam (pinAuth)
    try enc.encodeUint(8);
    try enc.encodeByteString(&pin_auth);

    // 9: pinUvAuthProtocol
    try enc.encodeUint(9);
    try enc.encodeUint(PIN_PROTOCOL_VERSION);

    return enc.written();
}

/// Encode a getAssertion command with pinAuth and pinUvAuthProtocol.
pub fn encodeGetAssertionWithPIN(
    buf: []u8,
    rp_id: []const u8,
    client_data_hash: []const u8,
    allow_list_ids: []const []const u8,
    pin_token: [32]u8,
) cbor.Error![]const u8 {
    var enc = cbor.Encoder.init(buf);

    // Command byte: getAssertion = 0x02
    try enc.encodeUint(0x02);

    // Compute pinAuth
    const pin_auth = computePinAuth(&pin_token, client_data_hash);

    // Map entries: rpId + clientDataHash + pinAuth + pinUvAuthProtocol + optional allowList
    const has_allow_list = allow_list_ids.len > 0;
    const map_entries: usize = if (has_allow_list) 5 else 4;
    try enc.beginMap(map_entries);

    // 1: rpId
    try enc.encodeUint(1);
    try enc.encodeTextString(rp_id);

    // 2: clientDataHash
    try enc.encodeUint(2);
    try enc.encodeByteString(client_data_hash);

    // 3: allowList
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

    // 8: pinUvAuthParam
    try enc.encodeUint(8);
    try enc.encodeByteString(&pin_auth);

    // 9: pinUvAuthProtocol
    try enc.encodeUint(9);
    try enc.encodeUint(PIN_PROTOCOL_VERSION);

    return enc.written();
}

// ─── Tests ───────────────────────────────────────────────────

test "ECDH key agreement roundtrip: two parties derive same shared secret" {
    // Generate two key pairs (simulating platform and authenticator)
    const alice = generateKeyPair();
    const bob = generateKeyPair();

    // Alice derives shared secret using her private key and Bob's public key
    const alice_secret = try deriveSharedSecret(alice.private_key, bob.public_key);

    // Bob derives shared secret using his private key and Alice's public key
    const bob_secret = try deriveSharedSecret(bob.private_key, alice.public_key);

    // Both sides must arrive at the same shared secret
    try std.testing.expectEqualSlices(u8, &alice_secret.data, &bob_secret.data);

    // Shared secret must not be all zeros
    var all_zero = true;
    for (alice_secret.data) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "AES-256-CBC encrypt/decrypt roundtrip" {
    const key = [_]u8{
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };

    // Test with 16 bytes (one block)
    const plaintext_1 = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    var ciphertext_1: [16]u8 = undefined;
    try aes256CbcEncrypt(key, &plaintext_1, &ciphertext_1);

    var decrypted_1: [16]u8 = undefined;
    try aes256CbcDecrypt(key, &ciphertext_1, &decrypted_1);
    try std.testing.expectEqualSlices(u8, &plaintext_1, &decrypted_1);

    // Test with 64 bytes (four blocks, like PIN encryption)
    var plaintext_4: [64]u8 = undefined;
    for (0..64) |i| {
        plaintext_4[i] = @intCast(i);
    }
    var ciphertext_4: [64]u8 = undefined;
    try aes256CbcEncrypt(key, &plaintext_4, &ciphertext_4);

    // Ciphertext must differ from plaintext
    try std.testing.expect(!std.mem.eql(u8, &plaintext_4, &ciphertext_4));

    var decrypted_4: [64]u8 = undefined;
    try aes256CbcDecrypt(key, &ciphertext_4, &decrypted_4);
    try std.testing.expectEqualSlices(u8, &plaintext_4, &decrypted_4);
}

test "HMAC-SHA-256 of known input matches expected output" {
    // RFC 4231 Test Case 2:
    // Key  = "Jefe" (4 bytes)
    // Data = "what do ya want for nothing?" (28 bytes)
    // Expected HMAC-SHA-256 output is the well-known test vector from the RFC.
    const key = "Jefe";
    const data = "what do ya want for nothing?";
    const expected = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };

    const result = computeHmac(key, data);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "COSE key encoding roundtrip" {
    // Create a test key
    var test_key = CoseKey{
        .x = undefined,
        .y = undefined,
    };
    for (0..32) |i| {
        test_key.x[i] = @intCast(i);
        test_key.y[i] = @intCast(i + 32);
    }

    // Encode the COSE key
    var buf: [256]u8 = undefined;
    var enc = cbor.Encoder.init(&buf);
    try encodeCoseKey(&enc, test_key);

    // Decode it back
    var dec = cbor.Decoder.init(enc.written());
    const decoded = try decodeCoseKey(&dec);

    // Verify x and y match
    try std.testing.expectEqualSlices(u8, &test_key.x, &decoded.x);
    try std.testing.expectEqualSlices(u8, &test_key.y, &decoded.y);
}

test "encodeGetPINRetries produces valid CBOR" {
    var buf: [64]u8 = undefined;
    const encoded = try encodeGetPINRetries(&buf);

    // First byte: command 0x06
    try std.testing.expectEqual(@as(u8, 0x06), encoded[0]);

    // Decode the CBOR map
    var dec = cbor.Decoder.init(encoded[1..]);
    const map_len = try dec.decodeMapHeader();
    try std.testing.expectEqual(@as(usize, 2), map_len);

    // Key 1: protocol version
    try std.testing.expectEqual(@as(u64, 1), try dec.decodeUint());
    try std.testing.expectEqual(@as(u64, PIN_PROTOCOL_VERSION), try dec.decodeUint());

    // Key 2: subCommand
    try std.testing.expectEqual(@as(u64, 2), try dec.decodeUint());
    try std.testing.expectEqual(@as(u64, @intFromEnum(SubCommand.getPINRetries)), try dec.decodeUint());
}

test "encodeGetKeyAgreement produces valid CBOR" {
    var buf: [64]u8 = undefined;
    const encoded = try encodeGetKeyAgreement(&buf);

    try std.testing.expectEqual(@as(u8, 0x06), encoded[0]);

    var dec = cbor.Decoder.init(encoded[1..]);
    const map_len = try dec.decodeMapHeader();
    try std.testing.expectEqual(@as(usize, 2), map_len);

    try std.testing.expectEqual(@as(u64, 1), try dec.decodeUint());
    try std.testing.expectEqual(@as(u64, PIN_PROTOCOL_VERSION), try dec.decodeUint());

    try std.testing.expectEqual(@as(u64, 2), try dec.decodeUint());
    try std.testing.expectEqual(@as(u64, @intFromEnum(SubCommand.getKeyAgreement)), try dec.decodeUint());
}

test "parsePINRetriesResponse parses valid response" {
    // Build a synthetic response: status(0x00) + CBOR map {3: 8, 4: false}
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    buf[pos] = 0x00; // status
    pos += 1;

    var cbor_buf: [64]u8 = undefined;
    var enc = cbor.Encoder.init(&cbor_buf);

    try enc.beginMap(2);
    try enc.encodeUint(3); // pinRetries
    try enc.encodeUint(8);
    try enc.encodeUint(4); // powerCycleState
    try enc.encodeBool(false);

    const cbor_written = enc.written();
    @memcpy(buf[pos..][0..cbor_written.len], cbor_written);
    pos += cbor_written.len;

    const result = try parsePINRetriesResponse(buf[0..pos]);
    try std.testing.expectEqual(@as(u32, 8), result.retries);
    try std.testing.expect(!result.power_cycle_required);
}

test "parsePINRetriesResponse non-zero status returns error" {
    const response = [_]u8{0x31}; // pinInvalid
    try std.testing.expectError(error.DeviceError, parsePINRetriesResponse(&response));
}

test "parseKeyAgreementResponse parses valid COSE key" {
    // Build a synthetic key agreement response
    var buf: [256]u8 = undefined;
    var pos: usize = 0;

    buf[pos] = 0x00; // status
    pos += 1;

    var cbor_buf: [256]u8 = undefined;
    var enc = cbor.Encoder.init(&cbor_buf);

    try enc.beginMap(1);
    try enc.encodeUint(1); // keyAgreement

    // Encode a COSE_Key
    var test_key = CoseKey{ .x = undefined, .y = undefined };
    @memset(&test_key.x, 0xAA);
    @memset(&test_key.y, 0xBB);
    try encodeCoseKey(&enc, test_key);

    const cbor_written = enc.written();
    @memcpy(buf[pos..][0..cbor_written.len], cbor_written);
    pos += cbor_written.len;

    const parsed_key = try parseKeyAgreementResponse(buf[0..pos]);
    try std.testing.expectEqualSlices(u8, &test_key.x, &parsed_key.x);
    try std.testing.expectEqualSlices(u8, &test_key.y, &parsed_key.y);
}

test "encryptPINHash produces 64-byte encrypted output" {
    const secret = SharedSecret{ .data = [_]u8{0x42} ** 32 };

    const encrypted = try encryptPINHash("123456", secret);
    try std.testing.expectEqual(@as(usize, 64), encrypted.len);

    // Encrypted output should not be all zeros
    var all_zero = true;
    for (encrypted) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);

    // Decrypt and verify the first 16 bytes match LEFT(SHA-256("123456"), 16)
    var decrypted: [64]u8 = undefined;
    try aes256CbcDecrypt(secret.data, &encrypted, &decrypted);

    var pin_hash: [32]u8 = undefined;
    Sha256.hash("123456", &pin_hash, .{});
    try std.testing.expectEqualSlices(u8, pin_hash[0..16], decrypted[0..16]);

    // Bytes 16-63 should be zero (padding)
    for (decrypted[16..64]) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "computePinAuth returns first 16 bytes of HMAC" {
    const token = [_]u8{0x01} ** 32;
    const message = [_]u8{0x02} ** 32;

    const pin_auth = computePinAuth(&token, &message);
    const full_hmac = computeHmac(&token, &message);

    // pinAuth is first 16 bytes of HMAC
    try std.testing.expectEqualSlices(u8, full_hmac[0..16], &pin_auth);
    try std.testing.expectEqual(@as(usize, 16), pin_auth.len);
}

test "encodeMakeCredentialWithPIN includes pinAuth parameters" {
    var buf: [2048]u8 = undefined;
    const hash = [_]u8{0xAA} ** 32;
    const algs = [_]i32{-7};
    const token = [_]u8{0x55} ** 32;

    const encoded = try encodeMakeCredentialWithPIN(
        &buf,
        &hash,
        "webauthn.io",
        "webauthn.io",
        &[_]u8{ 1, 2, 3, 4 },
        "testuser",
        "Test User",
        &algs,
        false,
        token,
    );

    // First byte = 0x01 (makeCredential)
    try std.testing.expectEqual(@as(u8, 0x01), encoded[0]);

    // Verify it's a valid CBOR map with 6 entries (4 base + pinAuth + pinProtocol)
    var dec = cbor.Decoder.init(encoded[1..]);
    const map_len = try dec.decodeMapHeader();
    try std.testing.expectEqual(@as(usize, 6), map_len);
}

test "encodeGetAssertionWithPIN includes pinAuth parameters" {
    var buf: [2048]u8 = undefined;
    const hash = [_]u8{0xBB} ** 32;
    const token = [_]u8{0x55} ** 32;
    const empty_list: []const []const u8 = &.{};

    const encoded = try encodeGetAssertionWithPIN(
        &buf,
        "github.com",
        &hash,
        empty_list,
        token,
    );

    // First byte = 0x02 (getAssertion)
    try std.testing.expectEqual(@as(u8, 0x02), encoded[0]);

    // Verify it's a valid CBOR map with 4 entries (rpId + clientDataHash + pinAuth + pinProtocol)
    var dec = cbor.Decoder.init(encoded[1..]);
    const map_len = try dec.decodeMapHeader();
    try std.testing.expectEqual(@as(usize, 4), map_len);
}
