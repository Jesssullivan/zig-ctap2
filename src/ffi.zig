/// C FFI exports for libctap2.
///
/// These functions are called from Swift via the bridging header.
/// All functions are blocking (with timeouts) and thread-safe.
/// Result data is written to caller-provided buffers.

const std = @import("std");
const cbor = @import("cbor.zig");
const ctaphid = @import("ctaphid.zig");
const ctap2 = @import("ctap2.zig");
const hid = @import("hid.zig");
const pin = @import("pin.zig");

const CTAP2_OK: c_int = 0;
const CTAP2_ERR_NO_DEVICE: c_int = -1;
const CTAP2_ERR_TIMEOUT: c_int = -2;
const CTAP2_ERR_PROTOCOL: c_int = -3;
const CTAP2_ERR_BUFFER_TOO_SMALL: c_int = -4;
const CTAP2_ERR_OPEN_FAILED: c_int = -5;
const CTAP2_ERR_WRITE_FAILED: c_int = -6;
const CTAP2_ERR_READ_FAILED: c_int = -7;
const CTAP2_ERR_CBOR: c_int = -8;
const CTAP2_ERR_DEVICE: c_int = -9;
const CTAP2_ERR_PIN: c_int = -10;

/// Keepalive callback type: receives status byte (1=processing, 2=user presence needed).
pub const KeepaliveCallback = ?*const fn (u8) callconv(.c) void;

/// Perform a full CTAPHID transaction: send command, receive response.
/// Handles CTAPHID_INIT (channel negotiation) + CTAPHID_CBOR (command).
/// If keepalive_cb is non-null, it's called with the keepalive status byte
/// whenever the device sends a keepalive packet (e.g., waiting for user touch).
fn ctaphidTransaction(
    dev: *hid.Device,
    cmd_payload: []const u8,
    result_buf: []u8,
) !usize {
    return ctaphidTransactionWithCallback(dev, cmd_payload, result_buf, null);
}

fn ctaphidTransactionWithCallback(
    dev: *hid.Device,
    cmd_payload: []const u8,
    result_buf: []u8,
    keepalive_cb: KeepaliveCallback,
) !usize {
    // Step 1: CTAPHID_INIT to get a channel ID
    var nonce: [8]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var init_pkt = ctaphid.buildInitPacket(ctaphid.CID_BROADCAST, .init, 8, &nonce);
    try dev.write(&init_pkt);

    const init_resp_pkt = try dev.read(5000); // 5 second timeout
    const init_header = try ctaphid.parseInitPacket(&init_resp_pkt);
    if (init_header.cmd != .init) return error.Protocol;

    // Parse CTAPHID_INIT response to get assigned CID
    const init_data = init_resp_pkt[7..][0..@min(@as(usize, init_header.payload_len), ctaphid.INIT_DATA_SIZE)];
    const init_resp = try ctaphid.parseInitResponse(init_data);
    const cid = init_resp.cid;

    // Step 2: Send CTAP2 CBOR command
    var packets: [128]ctaphid.Packet = undefined;
    const pkt_count = try ctaphid.fragmentMessage(cid, .cbor, cmd_payload, &packets);

    for (packets[0..pkt_count]) |*pkt| {
        try dev.write(pkt);
    }

    // Step 3: Read response (handle keepalive)
    var resp_buf: [4096]u8 = undefined;
    var first_pkt = try dev.read(30000); // 30 second timeout for user interaction

    // Handle keepalive packets (device waiting for user touch)
    while (true) {
        const hdr = ctaphid.parseInitPacket(&first_pkt) catch break;
        if (hdr.cmd == .keepalive) {
            // Status byte at position 7: 1=processing, 2=user presence needed
            if (keepalive_cb) |cb| {
                const status = first_pkt[7];
                cb(status);
            }
            first_pkt = try dev.read(30000);
            continue;
        }
        break;
    }

    // Reassemble response
    var offset: usize = 0;
    const resp_header = try ctaphid.parseInitPacket(&first_pkt);
    const total_len: usize = @intCast(resp_header.payload_len);

    if (total_len > resp_buf.len) return error.BufferTooSmall;

    // Copy init packet data
    const init_copy = @min(total_len, ctaphid.INIT_DATA_SIZE);
    @memcpy(resp_buf[0..init_copy], first_pkt[7..][0..init_copy]);
    offset = init_copy;

    // Read continuation packets
    while (offset < total_len) {
        const cont_pkt = try dev.read(5000);
        // Skip keepalive (invoke callback if set)
        if (cont_pkt[4] & 0x80 != 0) {
            const cont_hdr = ctaphid.parseInitPacket(&cont_pkt) catch continue;
            if (cont_hdr.cmd == .keepalive) {
                if (keepalive_cb) |cb| cb(cont_pkt[7]);
                continue;
            }
        }
        const cont_copy = @min(total_len - offset, ctaphid.CONT_DATA_SIZE);
        @memcpy(resp_buf[offset..][0..cont_copy], cont_pkt[5..][0..cont_copy]);
        offset += cont_copy;
    }

    // Copy to result buffer
    if (total_len > result_buf.len) return error.BufferTooSmall;
    @memcpy(result_buf[0..total_len], resp_buf[0..total_len]);
    return total_len;
}

// ─── Exported C Functions ───────────────────────────────────

/// Enumerate FIDO2 devices. Returns device count.
export fn ctap2_device_count() callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const devices = hid.enumerate(allocator) catch return 0;
    const count: c_int = @intCast(devices.len);
    for (devices) |*dev| {
        var d = dev.*;
        d.close();
    }
    allocator.free(devices);
    return count;
}

/// Perform authenticatorMakeCredential via direct USB HID.
/// Returns bytes written to result_buf, or negative error code.
export fn ctap2_make_credential(
    client_data_hash: [*]const u8, // 32 bytes
    rp_id: [*:0]const u8,
    rp_name: [*:0]const u8,
    user_id: [*]const u8,
    user_id_len: usize,
    user_name: [*:0]const u8,
    user_display_name: [*:0]const u8,
    alg_ids: [*]const i32,
    alg_count: usize,
    resident_key: bool,
    result_buf: [*]u8,
    result_buf_len: usize,
) callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Open first FIDO2 device
    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    // Encode CTAP2 makeCredential command
    var cmd_buf: [2048]u8 = undefined;
    const cmd = ctap2.encodeMakeCredential(
        &cmd_buf,
        client_data_hash[0..32],
        std.mem.span(rp_id),
        std.mem.span(rp_name),
        user_id[0..user_id_len],
        std.mem.span(user_name),
        std.mem.span(user_display_name),
        @ptrCast(alg_ids[0..alg_count]),
        resident_key,
    ) catch return CTAP2_ERR_CBOR;

    // Send and receive
    const result_len = ctaphidTransactionWithCallback(&dev, cmd, result_buf[0..result_buf_len], null) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            error.BufferTooSmall => CTAP2_ERR_BUFFER_TOO_SMALL,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    return @intCast(result_len);
}

/// Perform authenticatorGetAssertion via direct USB HID.
/// Returns bytes written to result_buf, or negative error code.
export fn ctap2_get_assertion(
    client_data_hash: [*]const u8, // 32 bytes
    rp_id: [*:0]const u8,
    allow_list_ids: [*]const [*]const u8,
    allow_list_id_lens: [*]const usize,
    allow_list_count: usize,
    result_buf: [*]u8,
    result_buf_len: usize,
) callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Open first FIDO2 device
    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    // Build allow list slices
    var ids_buf: [64][]const u8 = undefined;
    const count = @min(allow_list_count, 64);
    for (0..count) |i| {
        ids_buf[i] = allow_list_ids[i][0..allow_list_id_lens[i]];
    }

    // Encode CTAP2 getAssertion command
    var cmd_buf: [2048]u8 = undefined;
    const cmd = ctap2.encodeGetAssertion(
        &cmd_buf,
        std.mem.span(rp_id),
        client_data_hash[0..32],
        ids_buf[0..count],
    ) catch return CTAP2_ERR_CBOR;

    // Send and receive
    const result_len = ctaphidTransaction(&dev, cmd, result_buf[0..result_buf_len]) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            error.BufferTooSmall => CTAP2_ERR_BUFFER_TOO_SMALL,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    return @intCast(result_len);
}

/// Perform authenticatorGetInfo via direct USB HID.
/// Returns bytes written to result_buf, or negative error code.
export fn ctap2_get_info(
    result_buf: [*]u8,
    result_buf_len: usize,
) callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    var cmd_buf: [8]u8 = undefined;
    const cmd = ctap2.encodeGetInfo(&cmd_buf) catch return CTAP2_ERR_CBOR;

    const result_len = ctaphidTransaction(&dev, cmd, result_buf[0..result_buf_len]) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    return @intCast(result_len);
}

// ─── Parsed Response Functions ───────────────────────────────

/// Perform authenticatorMakeCredential and parse the response.
/// Sends the CTAP2 command, receives the raw response, then parses the CBOR
/// attestation object to extract the credential ID and attestation object.
///
/// Returns CTAP2_OK on success, or negative error code.
/// On CTAP2 device error (non-zero status byte), returns the positive status byte.
export fn ctap2_make_credential_parsed(
    client_data_hash: [*]const u8, // 32 bytes
    rp_id: [*:0]const u8,
    rp_name: [*:0]const u8,
    user_id: [*]const u8,
    user_id_len: usize,
    user_name: [*:0]const u8,
    user_display_name: [*:0]const u8,
    alg_ids: [*]const i32,
    alg_count: usize,
    resident_key: bool,
    // Output fields:
    out_credential_id: [*]u8,
    out_credential_id_len: *usize,
    out_attestation_object: [*]u8,
    out_attestation_object_len: *usize,
) callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Open first FIDO2 device
    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    // Encode CTAP2 makeCredential command
    var cmd_buf: [2048]u8 = undefined;
    const cmd = ctap2.encodeMakeCredential(
        &cmd_buf,
        client_data_hash[0..32],
        std.mem.span(rp_id),
        std.mem.span(rp_name),
        user_id[0..user_id_len],
        std.mem.span(user_name),
        std.mem.span(user_display_name),
        @ptrCast(alg_ids[0..alg_count]),
        resident_key,
    ) catch return CTAP2_ERR_CBOR;

    // Send and receive raw response
    var raw_buf: [4096]u8 = undefined;
    const raw_len = ctaphidTransaction(&dev, cmd, &raw_buf) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            error.BufferTooSmall => CTAP2_ERR_BUFFER_TOO_SMALL,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    // Parse the response
    const result = ctap2.parseMakeCredentialResponse(raw_buf[0..raw_len]) catch return CTAP2_ERR_CBOR;

    if (result.status != 0x00) {
        return @intCast(result.status);
    }

    // Copy credential ID to output buffer
    const cred_id = result.credential_id;
    @memcpy(out_credential_id[0..cred_id.len], cred_id);
    out_credential_id_len.* = cred_id.len;

    // Copy attestation object to output buffer
    const att_obj = result.attestation_object;
    @memcpy(out_attestation_object[0..att_obj.len], att_obj);
    out_attestation_object_len.* = att_obj.len;

    return CTAP2_OK;
}

/// Perform authenticatorGetAssertion and parse the response.
/// Sends the CTAP2 command, receives the raw response, then parses the CBOR
/// to extract credential ID, authenticator data, signature, and user handle.
///
/// Returns CTAP2_OK on success, or negative error code.
/// On CTAP2 device error (non-zero status byte), returns the positive status byte.
export fn ctap2_get_assertion_parsed(
    client_data_hash: [*]const u8, // 32 bytes
    rp_id: [*:0]const u8,
    allow_list_ids: ?[*]const [*]const u8,
    allow_list_id_lens: ?[*]const usize,
    allow_list_count: usize,
    // Output fields:
    out_credential_id: [*]u8,
    out_credential_id_len: *usize,
    out_auth_data: [*]u8,
    out_auth_data_len: *usize,
    out_signature: [*]u8,
    out_signature_len: *usize,
    out_user_handle: [*]u8,
    out_user_handle_len: *usize,
) callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Open first FIDO2 device
    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    // Build allow list slices
    var ids_buf: [64][]const u8 = undefined;
    const count = @min(allow_list_count, 64);
    if (allow_list_ids != null and allow_list_id_lens != null) {
        const ids = allow_list_ids.?;
        const lens = allow_list_id_lens.?;
        for (0..count) |i| {
            ids_buf[i] = ids[i][0..lens[i]];
        }
    }

    // Encode CTAP2 getAssertion command
    var cmd_buf: [2048]u8 = undefined;
    const cmd = ctap2.encodeGetAssertion(
        &cmd_buf,
        std.mem.span(rp_id),
        client_data_hash[0..32],
        if (allow_list_ids != null) ids_buf[0..count] else ids_buf[0..0],
    ) catch return CTAP2_ERR_CBOR;

    // Send and receive raw response
    var raw_buf: [4096]u8 = undefined;
    const raw_len = ctaphidTransaction(&dev, cmd, &raw_buf) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            error.BufferTooSmall => CTAP2_ERR_BUFFER_TOO_SMALL,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    // Build fallback credential ID (first entry in allow list, if exactly one)
    const fallback_cred_id: ?[]const u8 = if (count == 1 and allow_list_ids != null and allow_list_id_lens != null)
        allow_list_ids.?[0][0..allow_list_id_lens.?[0]]
    else
        null;

    // Parse the response
    const result = ctap2.parseGetAssertionResponse(raw_buf[0..raw_len], fallback_cred_id) catch return CTAP2_ERR_CBOR;

    if (result.status != 0x00) {
        return @intCast(result.status);
    }

    // Copy outputs
    const cred_id = result.credential_id;
    @memcpy(out_credential_id[0..cred_id.len], cred_id);
    out_credential_id_len.* = cred_id.len;

    const auth_data = result.auth_data;
    @memcpy(out_auth_data[0..auth_data.len], auth_data);
    out_auth_data_len.* = auth_data.len;

    const sig = result.signature;
    @memcpy(out_signature[0..sig.len], sig);
    out_signature_len.* = sig.len;

    const user_handle = result.user_handle;
    @memcpy(out_user_handle[0..user_handle.len], user_handle);
    out_user_handle_len.* = user_handle.len;

    return CTAP2_OK;
}

/// Parse a raw CTAP2 MakeCredential response buffer (status byte + CBOR).
/// This is a pure parsing function — no HID I/O.
/// Useful when the caller already has the raw response bytes.
///
/// Returns CTAP2_OK on success, positive status byte on device error,
/// or negative error code on parse failure.
export fn ctap2_parse_make_credential_response(
    response_data: [*]const u8,
    response_len: usize,
    out_credential_id: [*]u8,
    out_credential_id_len: *usize,
    out_attestation_object: [*]u8,
    out_attestation_object_len: *usize,
) callconv(.c) c_int {
    const result = ctap2.parseMakeCredentialResponse(response_data[0..response_len]) catch return CTAP2_ERR_CBOR;

    if (result.status != 0x00) {
        return @intCast(result.status);
    }

    const cred_id = result.credential_id;
    @memcpy(out_credential_id[0..cred_id.len], cred_id);
    out_credential_id_len.* = cred_id.len;

    const att_obj = result.attestation_object;
    @memcpy(out_attestation_object[0..att_obj.len], att_obj);
    out_attestation_object_len.* = att_obj.len;

    return CTAP2_OK;
}

/// Parse a raw CTAP2 GetAssertion response buffer (status byte + CBOR).
/// This is a pure parsing function — no HID I/O.
///
/// fallback_cred_id/fallback_cred_id_len: credential ID to use when the
/// response omits key 1 (CTAP2 spec: single-entry allowList). Pass NULL/0
/// if no fallback is available.
///
/// Returns CTAP2_OK on success, positive status byte on device error,
/// or negative error code on parse failure.
export fn ctap2_parse_get_assertion_response(
    response_data: [*]const u8,
    response_len: usize,
    fallback_cred_id: ?[*]const u8,
    fallback_cred_id_len: usize,
    out_credential_id: [*]u8,
    out_credential_id_len: *usize,
    out_auth_data: [*]u8,
    out_auth_data_len: *usize,
    out_signature: [*]u8,
    out_signature_len: *usize,
    out_user_handle: [*]u8,
    out_user_handle_len: *usize,
) callconv(.c) c_int {
    const fb: ?[]const u8 = if (fallback_cred_id) |ptr|
        ptr[0..fallback_cred_id_len]
    else
        null;

    const result = ctap2.parseGetAssertionResponse(response_data[0..response_len], fb) catch return CTAP2_ERR_CBOR;

    if (result.status != 0x00) {
        return @intCast(result.status);
    }

    const cred_id = result.credential_id;
    @memcpy(out_credential_id[0..cred_id.len], cred_id);
    out_credential_id_len.* = cred_id.len;

    const auth_data = result.auth_data;
    @memcpy(out_auth_data[0..auth_data.len], auth_data);
    out_auth_data_len.* = auth_data.len;

    const sig = result.signature;
    @memcpy(out_signature[0..sig.len], sig);
    out_signature_len.* = sig.len;

    const user_handle = result.user_handle;
    @memcpy(out_user_handle[0..user_handle.len], user_handle);
    out_user_handle_len.* = user_handle.len;

    return CTAP2_OK;
}

/// Map a CTAP2 status byte to a human-readable error message.
/// Returns a pointer to a static null-terminated string.
export fn ctap2_status_message(status: u8) callconv(.c) [*:0]const u8 {
    return ctap2.statusMessage(status);
}

/// Debug: return the last IOReturn error code from HID write.
export fn ctap2_debug_last_ioreturn() callconv(.c) c_int {
    return hid.platform.Device.last_ioreturn;
}

// ─── PIN Protocol Functions ─────────────────────────────────

/// Get PIN retry count from the authenticator.
/// Returns CTAP2_OK on success (retries written to out_retries),
/// or negative error code on failure.
export fn ctap2_get_pin_retries(
    out_retries: *c_int,
) callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    // Encode getPINRetries command
    var cmd_buf: [64]u8 = undefined;
    const cmd = pin.encodeGetPINRetries(&cmd_buf) catch return CTAP2_ERR_CBOR;

    // Send and receive
    var raw_buf: [256]u8 = undefined;
    const raw_len = ctaphidTransaction(&dev, cmd, &raw_buf) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    // Parse response
    const result = pin.parsePINRetriesResponse(raw_buf[0..raw_len]) catch return CTAP2_ERR_PIN;
    out_retries.* = @intCast(result.retries);

    return CTAP2_OK;
}

/// Get a PIN token for authentication.
/// Performs the full PIN protocol v2 handshake:
///   1. getKeyAgreement to get authenticator's public key
///   2. ECDH to derive shared secret
///   3. Encrypt the PIN hash
///   4. getPinUvAuthTokenUsingPinWithPermissions to get the token
///
/// pin_str: null-terminated UTF-8 PIN string.
/// out_pin_token: receives the decrypted 32-byte PIN token.
/// out_pin_token_len: must be >= 32.
///
/// Returns CTAP2_OK on success, or negative error code.
/// On CTAP2 device error (e.g. wrong PIN), returns the positive status byte.
export fn ctap2_get_pin_token(
    pin_str: [*:0]const u8,
    out_pin_token: [*]u8,
    out_pin_token_len: usize,
) callconv(.c) c_int {
    if (out_pin_token_len < 32) return CTAP2_ERR_BUFFER_TOO_SMALL;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    // Step 1: getKeyAgreement — get authenticator's ECDH public key
    var ka_cmd_buf: [64]u8 = undefined;
    const ka_cmd = pin.encodeGetKeyAgreement(&ka_cmd_buf) catch return CTAP2_ERR_CBOR;

    var ka_raw_buf: [512]u8 = undefined;
    const ka_raw_len = ctaphidTransaction(&dev, ka_cmd, &ka_raw_buf) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    // Check for device error status before parsing
    if (ka_raw_len >= 1 and ka_raw_buf[0] != 0x00) {
        return @intCast(ka_raw_buf[0]);
    }

    const authenticator_key = pin.parseKeyAgreementResponse(ka_raw_buf[0..ka_raw_len]) catch return CTAP2_ERR_PIN;

    // Step 2: Generate our ephemeral key pair and derive shared secret
    const our_keypair = pin.generateKeyPair();
    const shared_secret = pin.deriveSharedSecret(our_keypair.private_key, authenticator_key) catch return CTAP2_ERR_PIN;

    // Step 3: Encrypt the PIN hash
    const pin_slice = std.mem.span(pin_str);
    const pin_hash_enc = pin.encryptPINHash(pin_slice, shared_secret) catch return CTAP2_ERR_PIN;

    // Step 4: Send getPinUvAuthTokenUsingPinWithPermissions
    var pt_cmd_buf: [512]u8 = undefined;
    const pt_cmd = pin.encodeGetPINToken(
        &pt_cmd_buf,
        our_keypair.public_key,
        &pin_hash_enc,
    ) catch return CTAP2_ERR_CBOR;

    var pt_raw_buf: [512]u8 = undefined;
    const pt_raw_len = ctaphidTransaction(&dev, pt_cmd, &pt_raw_buf) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    // Check for device error status (e.g. 0x31 = wrong PIN)
    if (pt_raw_len >= 1 and pt_raw_buf[0] != 0x00) {
        return @intCast(pt_raw_buf[0]);
    }

    const token_result = pin.parsePINTokenResponse(pt_raw_buf[0..pt_raw_len], shared_secret) catch return CTAP2_ERR_PIN;

    // Copy the decrypted PIN token to the output buffer
    @memcpy(out_pin_token[0..32], &token_result.token);

    return CTAP2_OK;
}

// ─── PIN-Authenticated Parsed Functions ─────────────────────

/// Perform authenticatorMakeCredential with PIN authentication.
/// If pin_token is non-NULL and pin_protocol > 0, adds pinAuth and
/// pinUvAuthProtocol parameters to the CTAP2 command.
///
/// Returns CTAP2_OK on success, positive status byte on device error,
/// or negative error code on failure.
export fn ctap2_make_credential_with_pin(
    client_data_hash: [*]const u8, // 32 bytes
    rp_id: [*:0]const u8,
    rp_name: [*:0]const u8,
    user_id: [*]const u8,
    user_id_len: usize,
    user_name: [*:0]const u8,
    user_display_name: [*:0]const u8,
    alg_ids: [*]const i32,
    alg_count: usize,
    resident_key: bool,
    pin_token: ?[*]const u8, // 32 bytes, or NULL for no PIN
    pin_protocol: u8, // 0 = no PIN, 2 = PIN protocol v2
    // Output fields:
    out_credential_id: [*]u8,
    out_credential_id_len: *usize,
    out_attestation_object: [*]u8,
    out_attestation_object_len: *usize,
) callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    var cmd_buf: [2048]u8 = undefined;
    const cmd = if (pin_token != null and pin_protocol > 0)
        pin.encodeMakeCredentialWithPIN(
            &cmd_buf,
            client_data_hash[0..32],
            std.mem.span(rp_id),
            std.mem.span(rp_name),
            user_id[0..user_id_len],
            std.mem.span(user_name),
            std.mem.span(user_display_name),
            @ptrCast(alg_ids[0..alg_count]),
            resident_key,
            pin_token.?[0..32].*,
        ) catch return CTAP2_ERR_CBOR
    else
        ctap2.encodeMakeCredential(
            &cmd_buf,
            client_data_hash[0..32],
            std.mem.span(rp_id),
            std.mem.span(rp_name),
            user_id[0..user_id_len],
            std.mem.span(user_name),
            std.mem.span(user_display_name),
            @ptrCast(alg_ids[0..alg_count]),
            resident_key,
        ) catch return CTAP2_ERR_CBOR;

    var raw_buf: [4096]u8 = undefined;
    const raw_len = ctaphidTransaction(&dev, cmd, &raw_buf) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            error.BufferTooSmall => CTAP2_ERR_BUFFER_TOO_SMALL,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    const result = ctap2.parseMakeCredentialResponse(raw_buf[0..raw_len]) catch return CTAP2_ERR_CBOR;

    if (result.status != 0x00) {
        return @intCast(result.status);
    }

    const cred_id = result.credential_id;
    @memcpy(out_credential_id[0..cred_id.len], cred_id);
    out_credential_id_len.* = cred_id.len;

    const att_obj = result.attestation_object;
    @memcpy(out_attestation_object[0..att_obj.len], att_obj);
    out_attestation_object_len.* = att_obj.len;

    return CTAP2_OK;
}

/// Perform authenticatorGetAssertion with PIN authentication.
/// If pin_token is non-NULL and pin_protocol > 0, adds pinAuth and
/// pinUvAuthProtocol parameters to the CTAP2 command.
///
/// Returns CTAP2_OK on success, positive status byte on device error,
/// or negative error code on failure.
export fn ctap2_get_assertion_with_pin(
    client_data_hash: [*]const u8, // 32 bytes
    rp_id: [*:0]const u8,
    allow_list_ids: ?[*]const [*]const u8,
    allow_list_id_lens: ?[*]const usize,
    allow_list_count: usize,
    pin_token: ?[*]const u8, // 32 bytes, or NULL for no PIN
    pin_protocol: u8, // 0 = no PIN, 2 = PIN protocol v2
    // Output fields:
    out_credential_id: [*]u8,
    out_credential_id_len: *usize,
    out_auth_data: [*]u8,
    out_auth_data_len: *usize,
    out_signature: [*]u8,
    out_signature_len: *usize,
    out_user_handle: [*]u8,
    out_user_handle_len: *usize,
) callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    // Build allow list slices
    var ids_buf: [64][]const u8 = undefined;
    const count = @min(allow_list_count, 64);
    if (allow_list_ids != null and allow_list_id_lens != null) {
        const ids = allow_list_ids.?;
        const lens = allow_list_id_lens.?;
        for (0..count) |i| {
            ids_buf[i] = ids[i][0..lens[i]];
        }
    }
    const id_slice = if (allow_list_ids != null) ids_buf[0..count] else ids_buf[0..0];

    var cmd_buf: [2048]u8 = undefined;
    const cmd = if (pin_token != null and pin_protocol > 0)
        pin.encodeGetAssertionWithPIN(
            &cmd_buf,
            std.mem.span(rp_id),
            client_data_hash[0..32],
            id_slice,
            pin_token.?[0..32].*,
        ) catch return CTAP2_ERR_CBOR
    else
        ctap2.encodeGetAssertion(
            &cmd_buf,
            std.mem.span(rp_id),
            client_data_hash[0..32],
            id_slice,
        ) catch return CTAP2_ERR_CBOR;

    var raw_buf: [4096]u8 = undefined;
    const raw_len = ctaphidTransaction(&dev, cmd, &raw_buf) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            error.BufferTooSmall => CTAP2_ERR_BUFFER_TOO_SMALL,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    const fallback_cred_id: ?[]const u8 = if (count == 1 and allow_list_ids != null and allow_list_id_lens != null)
        allow_list_ids.?[0][0..allow_list_id_lens.?[0]]
    else
        null;

    const result = ctap2.parseGetAssertionResponse(raw_buf[0..raw_len], fallback_cred_id) catch return CTAP2_ERR_CBOR;

    if (result.status != 0x00) {
        return @intCast(result.status);
    }

    const cred_id = result.credential_id;
    @memcpy(out_credential_id[0..cred_id.len], cred_id);
    out_credential_id_len.* = cred_id.len;

    const auth_data = result.auth_data;
    @memcpy(out_auth_data[0..auth_data.len], auth_data);
    out_auth_data_len.* = auth_data.len;

    const sig = result.signature;
    @memcpy(out_signature[0..sig.len], sig);
    out_signature_len.* = sig.len;

    const user_handle = result.user_handle;
    @memcpy(out_user_handle[0..user_handle.len], user_handle);
    out_user_handle_len.* = user_handle.len;

    return CTAP2_OK;
}

// ─── Keepalive callback variants ─────────────────────────────
// Same as ctap2_make_credential / ctap2_get_assertion but with
// a keepalive callback invoked when the device is waiting for
// user presence (touch). Status byte: 1=processing, 2=upneeded.

export fn ctap2_make_credential_with_keepalive(
    client_data_hash: [*]const u8,
    rp_id: [*:0]const u8,
    rp_name: [*:0]const u8,
    user_id: [*]const u8,
    user_id_len: usize,
    user_name: [*:0]const u8,
    user_display_name: [*:0]const u8,
    alg_ids: [*]const i32,
    alg_count: usize,
    resident_key: bool,
    keepalive_cb: KeepaliveCallback,
    result_buf: [*]u8,
    result_buf_len: usize,
) callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    var cmd_buf: [2048]u8 = undefined;
    const cmd = ctap2.encodeMakeCredential(
        &cmd_buf,
        client_data_hash[0..32],
        std.mem.span(rp_id),
        std.mem.span(rp_name),
        user_id[0..user_id_len],
        std.mem.span(user_name),
        std.mem.span(user_display_name),
        @ptrCast(alg_ids[0..alg_count]),
        resident_key,
    ) catch return CTAP2_ERR_CBOR;

    const result_len = ctaphidTransactionWithCallback(&dev, cmd, result_buf[0..result_buf_len], keepalive_cb) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            error.BufferTooSmall => CTAP2_ERR_BUFFER_TOO_SMALL,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    return @intCast(result_len);
}

export fn ctap2_get_assertion_with_keepalive(
    client_data_hash: [*]const u8,
    rp_id: [*:0]const u8,
    allow_list_ids: ?[*]const ?[*]const u8,
    allow_list_id_lens: ?[*]const usize,
    allow_list_count: usize,
    keepalive_cb: KeepaliveCallback,
    result_buf: [*]u8,
    result_buf_len: usize,
) callconv(.c) c_int {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var dev = hid.openFirst(allocator) catch return CTAP2_ERR_NO_DEVICE;
    defer dev.close();

    var cmd_buf: [2048]u8 = undefined;
    const cmd = blk: {
        if (allow_list_count > 0 and allow_list_ids != null and allow_list_id_lens != null) {
            break :blk ctap2.encodeGetAssertion(
                &cmd_buf,
                client_data_hash[0..32],
                std.mem.span(rp_id),
                allow_list_ids.?[0..allow_list_count],
                allow_list_id_lens.?[0..allow_list_count],
            ) catch return CTAP2_ERR_CBOR;
        } else {
            break :blk ctap2.encodeGetAssertion(
                &cmd_buf,
                client_data_hash[0..32],
                std.mem.span(rp_id),
                &[_]?[*]const u8{},
                &[_]usize{},
            ) catch return CTAP2_ERR_CBOR;
        }
    };

    const result_len = ctaphidTransactionWithCallback(&dev, cmd, result_buf[0..result_buf_len], keepalive_cb) catch |err| {
        return switch (err) {
            error.NoDeviceFound => CTAP2_ERR_NO_DEVICE,
            error.Timeout => CTAP2_ERR_TIMEOUT,
            error.WriteFailed => CTAP2_ERR_WRITE_FAILED,
            error.ReadFailed => CTAP2_ERR_READ_FAILED,
            error.BufferTooSmall => CTAP2_ERR_BUFFER_TOO_SMALL,
            else => CTAP2_ERR_PROTOCOL,
        };
    };

    return @intCast(result_len);
}
