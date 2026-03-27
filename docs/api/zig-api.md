# Zig API Reference: zig-ctap2

## `cbor.zig`
*Minimal CBOR encoder/decoder for CTAP2.*

### Types

#### `Value` (union)
A decoded CBOR value.

#### `MapEntry` (struct)

#### `Encoder` (struct)

#### `Header` (struct)
A decoded CBOR header: major type and argument.

#### `Decoder` (struct)

### Functions

#### `init`

```zig
pub fn init(buf: []u8) Encoder
```

#### `written`

```zig
pub fn written(self: *const Encoder) []const u8
```

#### `encodeUint`
Encode an unsigned integer.

```zig
pub fn encodeUint(self: *Encoder, val: u64) Error!void
```

#### `encodeNegInt`
Encode a negative integer (CBOR stores as -1 - n).

```zig
pub fn encodeNegInt(self: *Encoder, val: i64) Error!void
```

#### `encodeByteString`
Encode a byte string.

```zig
pub fn encodeByteString(self: *Encoder, data: []const u8) Error!void
```

#### `encodeTextString`
Encode a text string.

```zig
pub fn encodeTextString(self: *Encoder, text: []const u8) Error!void
```

#### `beginArray`
Begin an array of known length.

```zig
pub fn beginArray(self: *Encoder, len: usize) Error!void
```

#### `beginMap`
Begin a map of known length.

```zig
pub fn beginMap(self: *Encoder, len: usize) Error!void
```

#### `encodeBool`
Encode a boolean.

```zig
pub fn encodeBool(self: *Encoder, val: bool) Error!void
```

#### `encodeNull`
Encode null.

```zig
pub fn encodeNull(self: *Encoder) Error!void
```

#### `init`

```zig
pub fn init(data: []const u8) Decoder
```

#### `remaining`

```zig
pub fn remaining(self: *const Decoder) usize
```

#### `decodeUint`
Decode a single unsigned integer.

```zig
pub fn decodeUint(self: *Decoder) Error!u64
```

#### `decodeByteString`
Decode a byte string, returning a slice into the source data.

```zig
pub fn decodeByteString(self: *Decoder) Error![]const u8
```

#### `decodeTextString`
Decode a text string, returning a slice into the source data.

```zig
pub fn decodeTextString(self: *Decoder) Error![]const u8
```

#### `decodeArrayHeader`
Decode an array header, returning the element count.

```zig
pub fn decodeArrayHeader(self: *Decoder) Error!usize
```

#### `decodeMapHeader`
Decode a map header, returning the entry count.

```zig
pub fn decodeMapHeader(self: *Decoder) Error!usize
```

#### `peekMajorType`
Peek at the major type of the next value without consuming it.

```zig
pub fn peekMajorType(self: *const Decoder) Error!MajorType
```

#### `skipValue`
Skip a single CBOR value (including nested structures).

```zig
pub fn skipValue(self: *Decoder) Error!void
```

#### `decodeRawHeader`
Decode a header and return the raw major type + arg for flexible handling.

```zig
pub fn decodeRawHeader(self: *Decoder) Error!Header
```

### Constants

- `Error`

## `ctap2.zig`
*CTAP2 command encoding and response parsing.*

### Types

#### `CommandCode` (enum)

#### `StatusCode` (enum)

#### `MakeCredentialResult` (struct)
Parsed result from authenticatorMakeCredential.

#### `GetAssertionResult` (struct)
Parsed result from authenticatorGetAssertion.

### Functions

#### `statusMessage`
Map a CTAP2 status byte to a human-readable message string.

```zig
pub fn statusMessage(status: u8) [:0]const u8
```

#### `encodeMakeCredential`
Encode a makeCredential request into CBOR.

```zig
pub fn encodeMakeCredential( buf: []u8, client_data_hash: []const u8, rp_id: []const u8, rp_name: []const u8, user_id: []const u8, user_name: []const u8, user_display_name: []const u8, algorithms: []const i32, resident_key: bool, ) cbor.Error![]const u8
```

#### `encodeGetAssertion`
Encode a getAssertion request into CBOR.

```zig
pub fn encodeGetAssertion( buf: []u8, rp_id: []const u8, client_data_hash: []const u8, allow_list_ids: []const []const u8, ) cbor.Error![]const u8
```

#### `encodeGetInfo`
Encode a getInfo request.

```zig
pub fn encodeGetInfo(buf: []u8) cbor.Error![]const u8
```

#### `parseMakeCredentialResponse`
Parse a raw CTAP2 authenticatorMakeCredential response.  The response format is: status_byte(1) + CBOR_map The CBOR map has integer keys: 1 = fmt (text string) 2 = authData (byte string) 3 = attStmt (map)  From authData we extract the credential ID: rpIdHash(32) + flags(1) + signCount(4) + [aaguid(16) + credIdLen(2) + credentialId(credIdLen) + ...]

```zig
pub fn parseMakeCredentialResponse(response_data: []const u8) cbor.Error!MakeCredentialResult
```

#### `parseGetAssertionResponse`
Parse a raw CTAP2 authenticatorGetAssertion response.  The response format is: status_byte(1) + CBOR_map The CBOR map has integer keys: 1 = credential (map with "id" byte string) — optional per spec 2 = authData (byte string) 3 = signature (byte string) 4 = user (map with "id" byte string) — optional  Per CTAP2 spec: key 1 (credential) is omitted when the allowList in the request had exactly one entry. In that case, use the fallback credential ID.

```zig
pub fn parseGetAssertionResponse( response_data: []const u8, fallback_cred_id: ?[]const u8, ) cbor.Error!GetAssertionResult
```

## `ctaphid.zig`
*CTAPHID transport framing for FIDO2 USB HID communication.*

### Types

#### `Command` (enum)
CTAPHID command codes.

#### `KeepaliveStatus` (enum)
Keepalive status codes.

#### `InitHeader` (struct)
Parse an init packet header.

#### `InitResponse` (struct)
CTAPHID_INIT response structure.

### Functions

#### `buildInitPacket`
Build an initialization packet.

```zig
pub fn buildInitPacket(cid: u32, cmd: Command, payload_len: u16, data: []const u8) Packet
```

#### `buildContPacket`
Build a continuation packet.

```zig
pub fn buildContPacket(cid: u32, seq: u8, data: []const u8) Packet
```

#### `fragmentMessage`
Fragment a message into CTAPHID packets. Returns the number of packets written to `out`.

```zig
pub fn fragmentMessage( cid: u32, cmd: Command, payload: []const u8, out: []Packet, ) Error!usize
```

#### `parseInitPacket`

```zig
pub fn parseInitPacket(pkt: *const Packet) Error!InitHeader
```

#### `reassembleMessage`
Reassemble a complete message from init + continuation packets. `read_fn` is called to get each subsequent packet.

```zig
pub fn reassembleMessage( init_pkt: *const Packet, buf: []u8, read_fn: *const fn () Error!Packet,
```

#### `parseInitResponse`
Parse a CTAPHID_INIT response payload.

```zig
pub fn parseInitResponse(data: []const u8) Error!InitResponse
```

### Constants

- `Error`
- `Packet` -- A 64-byte HID packet ready to send.

## `ffi.zig`
*C FFI exports for libctap2.*

### Constants

- `KeepaliveCallback` -- Keepalive callback type: receives status byte (1=processing, 2=user presence needed).

## `hid.zig`
*Platform-selected USB HID transport for FIDO2 devices.*

### Constants

- `platform`
- `Device`
- `Error`
- `enumerate`
- `openFirst`

## `hid_linux.zig`
*Linux USB HID transport via hidraw.*

### Types

#### `Device` (struct)
A handle to an open FIDO2 HID device.

### Functions

#### `write`
Write a 64-byte packet to the device.

```zig
pub fn write(self: *Device, packet: *const [64]u8) Error!void
```

#### `read`
Read a 64-byte packet from the device with timeout.

```zig
pub fn read(self: *Device, timeout_ms: u32) Error![64]u8
```

#### `close`
Close the device.

```zig
pub fn close(self: *Device) void
```

#### `enumerate`
Enumerate connected FIDO2 USB HID devices.

```zig
pub fn enumerate(allocator: std.mem.Allocator) ![]Device
```

#### `openFirst`
Find and open the first available FIDO2 device.

```zig
pub fn openFirst(allocator: std.mem.Allocator) !Device
```

### Constants

- `Error`

## `hid_macos.zig`
*macOS USB HID transport via IOKit.*

### Types

#### `Device` (struct)
A handle to an open FIDO2 HID device. Owns both the device ref and the manager that created it.

### Functions

#### `write`

```zig
pub fn write(self: *Device, packet: *const [64]u8) Error!void
```

#### `read`

```zig
pub fn read(self: *Device, timeout_ms: u32) Error![64]u8
```

#### `close`

```zig
pub fn close(self: *Device) void
```

#### `enumerate`

```zig
pub fn enumerate(allocator: std.mem.Allocator) ![]Device
```

#### `openFirst`

```zig
pub fn openFirst(allocator: std.mem.Allocator) !Device
```

### Constants

- `Error`

## `pin.zig`
*CTAP2 Client PIN protocol v2 (authenticatorClientPIN comm...*

### Types

#### `SubCommand` (enum)
authenticatorClientPIN subcommands.

#### `PINRetriesResult` (struct)
Result from getPINRetries.

#### `CoseKey` (struct)
A COSE_Key for EC2 P-256 (used in key agreement).

#### `EphemeralKeyPair` (struct)
Ephemeral key pair for ECDH key agreement.

#### `SharedSecret` (struct)
Shared secret derived from ECDH.

#### `PINTokenResult` (struct)
Result from getPINToken.

### Functions

#### `generateKeyPair`
Generate an ephemeral ECDH P-256 key pair for key agreement.

```zig
pub fn generateKeyPair() EphemeralKeyPair
```

#### `deriveSharedSecret`
Perform ECDH: multiply their public point by our private scalar. Returns SHA-256 of the x-coordinate of the shared point.

```zig
pub fn deriveSharedSecret( our_private: [32]u8, their_public: CoseKey, ) !SharedSecret
```

#### `computeHmac`
Compute HMAC-SHA-256(key, message).

```zig
pub fn computeHmac(key: []const u8, message: []const u8) [32]u8
```

#### `computePinAuth`
Compute pinAuth: first 16 bytes of HMAC-SHA-256(pinToken, message). Used for authenticating commands with a PIN token.

```zig
pub fn computePinAuth(pin_token: []const u8, message: []const u8) [16]u8
```

#### `aes256CbcEncrypt`
AES-256-CBC encrypt (with zero IV, per CTAP2 PIN protocol v2 spec). Input must be a multiple of 16 bytes. Returns the ciphertext (same length as input).

```zig
pub fn aes256CbcEncrypt( key: [32]u8, plaintext: []const u8, out: []u8, ) !void
```

#### `aes256CbcDecrypt`
AES-256-CBC decrypt (with zero IV, per CTAP2 PIN protocol v2 spec). Input must be a multiple of 16 bytes. Returns the plaintext (same length as input).

```zig
pub fn aes256CbcDecrypt( key: [32]u8, ciphertext: []const u8, out: []u8, ) !void
```

#### `encodeGetPINRetries`
Encode a getPINRetries request. Request: {1: pinUvAuthProtocol(2), 2: subCommand(1)}

```zig
pub fn encodeGetPINRetries(buf: []u8) cbor.Error![]const u8
```

#### `encodeGetKeyAgreement`
Encode a getKeyAgreement request. Request: {1: pinUvAuthProtocol(2), 2: subCommand(2)}

```zig
pub fn encodeGetKeyAgreement(buf: []u8) cbor.Error![]const u8
```

#### `encodeGetPINToken`
Encode a getPinUvAuthTokenUsingPinWithPermissions request (subCommand 0x09). Request: {1: protocol, 2: subCommand(9), 3: keyAgreement(COSE_Key), 6: pinHashEnc}

```zig
pub fn encodeGetPINToken( buf: []u8, our_public_key: CoseKey, pin_hash_enc: []const u8, ) cbor.Error![]const u8
```

#### `parsePINRetriesResponse`
Parse a getPINRetries response. Response CBOR (after status byte): {3: pinRetries, 4: powerCycleState(optional)}

```zig
pub fn parsePINRetriesResponse(response_data: []const u8) !PINRetriesResult
```

#### `parseKeyAgreementResponse`
Parse a getKeyAgreement response. Response CBOR (after status byte): {1: keyAgreement(COSE_Key)} COSE_Key: {1: kty(2), 3: alg(-25), -1: crv(1), -2: x(32 bytes), -3: y(32 bytes)}

```zig
pub fn parseKeyAgreementResponse(response_data: []const u8) !CoseKey
```

#### `parsePINTokenResponse`
Parse a getPINToken response. Response CBOR (after status byte): {2: pinUvAuthToken(encrypted bytes)}

```zig
pub fn parsePINTokenResponse( response_data: []const u8, shared_secret: SharedSecret, ) !PINTokenResult
```

#### `encryptPINHash`
Prepare the encrypted PIN hash for a getPINToken request. Takes a UTF-8 PIN string, hashes it with SHA-256, takes the first 16 bytes, pads to 64 bytes, and encrypts with AES-256-CBC using the shared secret.  Returns the 64-byte encrypted PIN hash.

```zig
pub fn encryptPINHash( pin: []const u8, shared_secret: SharedSecret, ) ![64]u8
```

#### `encodeMakeCredentialWithPIN`
Encode a makeCredential command with pinAuth and pinUvAuthProtocol. This adds parameters 8 (pinUvAuthProtocol) and 9 (pinAuth) to the command.  pinAuth = LEFT(HMAC-SHA-256(pinToken, clientDataHash), 16)

```zig
pub fn encodeMakeCredentialWithPIN( buf: []u8, client_data_hash: []const u8, rp_id: []const u8, rp_name: []const u8, user_id: []const u8, user_name: []const u8, user_display_name: []const u8, algorithms: []const i32, resident_key: bool, pin_token: [32]u8, ) cbor.Error![]const u8
```

#### `encodeGetAssertionWithPIN`
Encode a getAssertion command with pinAuth and pinUvAuthProtocol.

```zig
pub fn encodeGetAssertionWithPIN( buf: []u8, rp_id: []const u8, client_data_hash: []const u8, allow_list_ids: []const []const u8, pin_token: [32]u8, ) cbor.Error![]const u8
```

