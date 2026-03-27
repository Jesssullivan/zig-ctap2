# Zig API Reference

Auto-generated from Zig source files in [`src/`](https://github.com/Jesssullivan/zig-ctap2/tree/main/src).

These are the internal Zig modules. For C/Swift interop, see the [C FFI Reference](c-ffi.md).

### `cbor.zig`

A decoded CBOR value.
```zig
pub const Value = union(enum) {
```

```zig
pub const MapEntry = struct {
```

```zig
pub const Encoder = struct {
```

```zig
pub fn init(buf: []u8) Encoder {
```

```zig
pub fn written(self: *const Encoder) []const u8 {
```

Encode an unsigned integer.
```zig
pub fn encodeUint(self: *Encoder, val: u64) Error!void {
```

Encode a negative integer (CBOR stores as -1 - n).
```zig
pub fn encodeNegInt(self: *Encoder, val: i64) Error!void {
```

Encode a byte string.
```zig
pub fn encodeByteString(self: *Encoder, data: []const u8) Error!void {
```

Encode a text string.
```zig
pub fn encodeTextString(self: *Encoder, text: []const u8) Error!void {
```

Begin an array of known length.
```zig
pub fn beginArray(self: *Encoder, len: usize) Error!void {
```

Begin a map of known length.
```zig
pub fn beginMap(self: *Encoder, len: usize) Error!void {
```

Encode a boolean.
```zig
pub fn encodeBool(self: *Encoder, val: bool) Error!void {
```

Encode null.
```zig
pub fn encodeNull(self: *Encoder) Error!void {
```

A decoded CBOR header: major type and argument.
```zig
pub const Header = struct {
```

```zig
pub const Decoder = struct {
```

```zig
pub fn init(data: []const u8) Decoder {
```

```zig
pub fn remaining(self: *const Decoder) usize {
```

Decode a single unsigned integer.
```zig
pub fn decodeUint(self: *Decoder) Error!u64 {
```

Decode a byte string, returning a slice into the source data.
```zig
pub fn decodeByteString(self: *Decoder) Error![]const u8 {
```

Decode a text string, returning a slice into the source data.
```zig
pub fn decodeTextString(self: *Decoder) Error![]const u8 {
```

Decode an array header, returning the element count.
```zig
pub fn decodeArrayHeader(self: *Decoder) Error!usize {
```

Decode a map header, returning the entry count.
```zig
pub fn decodeMapHeader(self: *Decoder) Error!usize {
```

Peek at the major type of the next value without consuming it.
```zig
pub fn peekMajorType(self: *const Decoder) Error!MajorType {
```

Skip a single CBOR value (including nested structures).
```zig
pub fn skipValue(self: *Decoder) Error!void {
```

Decode a header and return the raw major type + arg for flexible handling.
```zig
pub fn decodeRawHeader(self: *Decoder) Error!Header {
```


### `ctap2.zig`

```zig
pub const CommandCode = enum(u8) {
```

```zig
pub const StatusCode = enum(u8) {
```

Map a CTAP2 status byte to a human-readable message string.
```zig
pub fn statusMessage(status: u8) [:0]const u8 {
```

Encode a makeCredential request into CBOR.
```zig
pub fn encodeMakeCredential(
```

Encode a getAssertion request into CBOR.
```zig
pub fn encodeGetAssertion(
```

Encode a getInfo request.
```zig
pub fn encodeGetInfo(buf: []u8) cbor.Error![]const u8 {
```

Parsed result from authenticatorMakeCredential.
```zig
pub const MakeCredentialResult = struct {
```

Parsed result from authenticatorGetAssertion.
```zig
pub const GetAssertionResult = struct {
```

Parse a raw CTAP2 authenticatorMakeCredential response.

The response format is: status_byte(1) + CBOR_map
The CBOR map has integer keys:
1 = fmt (text string)
2 = authData (byte string)
3 = attStmt (map)

From authData we extract the credential ID:
rpIdHash(32) + flags(1) + signCount(4) + [aaguid(16) + credIdLen(2) + credentialId(credIdLen) + ...]
```zig
pub fn parseMakeCredentialResponse(response_data: []const u8) cbor.Error!MakeCredentialResult {
```

Parse a raw CTAP2 authenticatorGetAssertion response.

The response format is: status_byte(1) + CBOR_map
The CBOR map has integer keys:
1 = credential (map with "id" byte string) — optional per spec
2 = authData (byte string)
3 = signature (byte string)
4 = user (map with "id" byte string) — optional

Per CTAP2 spec: key 1 (credential) is omitted when the allowList in the
request had exactly one entry. In that case, use the fallback credential ID.
```zig
pub fn parseGetAssertionResponse(
```


### `ctaphid.zig`

CTAPHID command codes.
```zig
pub const Command = enum(u8) {
```

Keepalive status codes.
```zig
pub const KeepaliveStatus = enum(u8) {
```

Build an initialization packet.
```zig
pub fn buildInitPacket(cid: u32, cmd: Command, payload_len: u16, data: []const u8) Packet {
```

Build a continuation packet.
```zig
pub fn buildContPacket(cid: u32, seq: u8, data: []const u8) Packet {
```

Fragment a message into CTAPHID packets.
Returns the number of packets written to `out`.
```zig
pub fn fragmentMessage(
```

Parse an init packet header.
```zig
pub const InitHeader = struct {
```

```zig
pub fn parseInitPacket(pkt: *const Packet) Error!InitHeader {
```

Reassemble a complete message from init + continuation packets.
`read_fn` is called to get each subsequent packet.
```zig
pub fn reassembleMessage(
```

CTAPHID_INIT response structure.
```zig
pub const InitResponse = struct {
```

Parse a CTAPHID_INIT response payload.
```zig
pub fn parseInitResponse(data: []const u8) Error!InitResponse {
```


### `hid_linux.zig`

A handle to an open FIDO2 HID device.
```zig
pub const Device = struct {
```

Write a 64-byte packet to the device.
```zig
pub fn write(self: *Device, packet: *const [64]u8) Error!void {
```

Read a 64-byte packet from the device with timeout.
```zig
pub fn read(self: *Device, timeout_ms: u32) Error![64]u8 {
```

Close the device.
```zig
pub fn close(self: *Device) void {
```

Enumerate connected FIDO2 USB HID devices.
```zig
pub fn enumerate(allocator: std.mem.Allocator) ![]Device {
```

Find and open the first available FIDO2 device.
```zig
pub fn openFirst(allocator: std.mem.Allocator) !Device {
```


### `hid_macos.zig`

A handle to an open FIDO2 HID device.
Owns both the device ref and the manager that created it.
```zig
pub const Device = struct {
```

```zig
pub fn write(self: *Device, packet: *const [64]u8) Error!void {
```

```zig
pub fn read(self: *Device, timeout_ms: u32) Error![64]u8 {
```

```zig
pub fn close(self: *Device) void {
```

```zig
pub fn enumerate(allocator: std.mem.Allocator) ![]Device {
```

```zig
pub fn openFirst(allocator: std.mem.Allocator) !Device {
```


### `pin.zig`

authenticatorClientPIN subcommands.
```zig
pub const SubCommand = enum(u8) {
```

Result from getPINRetries.
```zig
pub const PINRetriesResult = struct {
```

A COSE_Key for EC2 P-256 (used in key agreement).
```zig
pub const CoseKey = struct {
```

Ephemeral key pair for ECDH key agreement.
```zig
pub const EphemeralKeyPair = struct {
```

Shared secret derived from ECDH.
```zig
pub const SharedSecret = struct {
```

Result from getPINToken.
```zig
pub const PINTokenResult = struct {
```

Generate an ephemeral ECDH P-256 key pair for key agreement.
```zig
pub fn generateKeyPair() EphemeralKeyPair {
```

Perform ECDH: multiply their public point by our private scalar.
Returns SHA-256 of the x-coordinate of the shared point.
```zig
pub fn deriveSharedSecret(
```

Compute HMAC-SHA-256(key, message).
```zig
pub fn computeHmac(key: []const u8, message: []const u8) [32]u8 {
```

Compute pinAuth: first 16 bytes of HMAC-SHA-256(pinToken, message).
Used for authenticating commands with a PIN token.
```zig
pub fn computePinAuth(pin_token: []const u8, message: []const u8) [16]u8 {
```

AES-256-CBC encrypt (with zero IV, per CTAP2 PIN protocol v2 spec).
Input must be a multiple of 16 bytes.
Returns the ciphertext (same length as input).
```zig
pub fn aes256CbcEncrypt(
```

AES-256-CBC decrypt (with zero IV, per CTAP2 PIN protocol v2 spec).
Input must be a multiple of 16 bytes.
Returns the plaintext (same length as input).
```zig
pub fn aes256CbcDecrypt(
```

Encode a getPINRetries request.
Request: {1: pinUvAuthProtocol(2), 2: subCommand(1)}
```zig
pub fn encodeGetPINRetries(buf: []u8) cbor.Error![]const u8 {
```

Encode a getKeyAgreement request.
Request: {1: pinUvAuthProtocol(2), 2: subCommand(2)}
```zig
pub fn encodeGetKeyAgreement(buf: []u8) cbor.Error![]const u8 {
```

Encode a getPinUvAuthTokenUsingPinWithPermissions request (subCommand 0x09).
Request: {1: protocol, 2: subCommand(9), 3: keyAgreement(COSE_Key), 6: pinHashEnc}
```zig
pub fn encodeGetPINToken(
```

Parse a getPINRetries response.
Response CBOR (after status byte): {3: pinRetries, 4: powerCycleState(optional)}
```zig
pub fn parsePINRetriesResponse(response_data: []const u8) !PINRetriesResult {
```

Parse a getKeyAgreement response.
Response CBOR (after status byte): {1: keyAgreement(COSE_Key)}
COSE_Key: {1: kty(2), 3: alg(-25), -1: crv(1), -2: x(32 bytes), -3: y(32 bytes)}
```zig
pub fn parseKeyAgreementResponse(response_data: []const u8) !CoseKey {
```

Parse a getPINToken response.
Response CBOR (after status byte): {2: pinUvAuthToken(encrypted bytes)}
```zig
pub fn parsePINTokenResponse(
```

Prepare the encrypted PIN hash for a getPINToken request.
Takes a UTF-8 PIN string, hashes it with SHA-256, takes the first 16 bytes,
pads to 64 bytes, and encrypts with AES-256-CBC using the shared secret.

Returns the 64-byte encrypted PIN hash.
```zig
pub fn encryptPINHash(
```

Encode a makeCredential command with pinAuth and pinUvAuthProtocol.
This adds parameters 8 (pinUvAuthProtocol) and 9 (pinAuth) to the command.

pinAuth = LEFT(HMAC-SHA-256(pinToken, clientDataHash), 16)
```zig
pub fn encodeMakeCredentialWithPIN(
```

Encode a getAssertion command with pinAuth and pinUvAuthProtocol.
```zig
pub fn encodeGetAssertionWithPIN(
```

