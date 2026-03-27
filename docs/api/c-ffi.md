# C FFI API Reference: zig-ctap2

## `ctap2.h`

| Function | Description |
|----------|-------------|
| `ctap2_device_count` | Get the number of connected FIDO2 devices. |
| `ctap2_make_credential` | Perform authenticatorMakeCredential. client_data_hash must be 32 bytes (SHA-256 of clientDataJSON). Returns bytes written to result_buf, or negative error code. result_buf contains the raw CTAP2 response (status byte + CBOR). |
| `ctap2_get_assertion` | Perform authenticatorGetAssertion. client_data_hash must be 32 bytes. allow_list_ids is an array of pointers to credential IDs. allow_list_id_lens is an array of lengths for each credential ID. Returns bytes written to result_buf, or negative error code. |
| `ctap2_get_info` | Perform authenticatorGetInfo. Returns bytes written to result_buf, or negative error code. result_buf contains the raw CTAP2 response (status byte + CBOR). |
| `ctap2_make_credential_parsed` | Combined: send makeCredential + parse response. Output buffers should be at least 1024 bytes for credential_id, and 4096 bytes for attestation_object. |
| `ctap2_get_assertion_parsed` | Combined: send getAssertion + parse response. Output buffers should be at least 1024 bytes each. allow_list_ids/allow_list_id_lens can be NULL when allow_list_count is 0. |
| `ctap2_parse_make_credential_response` | Parse a raw MakeCredential response (status byte + CBOR attestation object). |
| `ctap2_parse_get_assertion_response` | Parse a raw GetAssertion response (status byte + CBOR). fallback_cred_id: credential ID to use when the response omits key 1 (CTAP2 spec: single-entry allowList). Pass NULL/0 if no fallback. |
| `ctap2_get_pin_retries` | Get PIN retry count from the authenticator. out_retries: receives the number of remaining PIN retries. Returns CTAP2_OK on success, or negative error code. |
| `ctap2_get_pin_token` | Get a PIN token for authentication. Performs the full PIN protocol v2 handshake (key agreement + ECDH + PIN encryption) and returns a decrypted 32-byte PIN token. pin: null-terminated UTF-8 PIN string. out_pin_token: receives the 32-byte decrypted PIN token. out_pin_token_len: must be >= 32. Returns CTAP2_OK on success, positive CTAP2 status byte on device error (e.g. 0x31 = wrong PIN), or negative error code. |
| `ctap2_make_credential_with_pin` | Same as the parsed functions above, but with optional PIN auth. Pass pin_token=NULL, pin_protocol=0 for no PIN authentication. Pass pin_token=<32-byte token from ctap2_get_pin_token>, pin_protocol=2 to include pinAuth in the CTAP2 command. |
| `ctap2_get_assertion_with_pin` | ctap2_get_assertion_with_pin |
| `ctap2_make_credential_with_keepalive` | ctap2_make_credential_with_keepalive |
| `ctap2_get_assertion_with_keepalive` | ctap2_get_assertion_with_keepalive |
| `ctap2_debug_last_ioreturn` | Debug: get the last IOReturn error code from HID operations. |

---

### `ctap2_device_count`

Get the number of connected FIDO2 devices.

```c
int ctap2_device_count(void);
```

### `ctap2_make_credential`

Perform authenticatorMakeCredential. client_data_hash must be 32 bytes (SHA-256 of clientDataJSON). Returns bytes written to result_buf, or negative error code. result_buf contains the raw CTAP2 response (status byte + CBOR).

```c
int ctap2_make_credential( const uint8_t *client_data_hash, // 32 bytes const char *rp_id, // null-terminated const char *rp_name, // null-terminated const uint8_t *user_id, size_t user_id_len, const char *user_name, // null-terminated const char *user_display_name, // null-terminated const int32_t *alg_ids, // COSE algorithm IDs size_t alg_count, bool resident_key, uint8_t *result_buf, size_t result_buf_len );
```

### `ctap2_get_assertion`

Perform authenticatorGetAssertion. client_data_hash must be 32 bytes. allow_list_ids is an array of pointers to credential IDs. allow_list_id_lens is an array of lengths for each credential ID. Returns bytes written to result_buf, or negative error code.

```c
int ctap2_get_assertion( const uint8_t *client_data_hash, // 32 bytes const char *rp_id, // null-terminated const uint8_t *const *allow_list_ids, const size_t *allow_list_id_lens, size_t allow_list_count, uint8_t *result_buf, size_t result_buf_len );
```

### `ctap2_get_info`

Perform authenticatorGetInfo. Returns bytes written to result_buf, or negative error code. result_buf contains the raw CTAP2 response (status byte + CBOR).

```c
int ctap2_get_info( uint8_t *result_buf, size_t result_buf_len );
```

### `ctap2_make_credential_parsed`

Combined: send makeCredential + parse response. Output buffers should be at least 1024 bytes for credential_id, and 4096 bytes for attestation_object.

```c
int ctap2_make_credential_parsed( const uint8_t *client_data_hash, // 32 bytes const char *rp_id, // null-terminated const char *rp_name, // null-terminated const uint8_t *user_id, size_t user_id_len, const char *user_name, // null-terminated const char *user_display_name, // null-terminated const int32_t *alg_ids, // COSE algorithm IDs size_t alg_count, bool resident_key, // Output fields: uint8_t *out_credential_id, size_t *out_credential_id_len, uint8_t *out_attestation_object, size_t *out_attestation_object_len );
```

### `ctap2_get_assertion_parsed`

Combined: send getAssertion + parse response. Output buffers should be at least 1024 bytes each. allow_list_ids/allow_list_id_lens can be NULL when allow_list_count is 0.

```c
int ctap2_get_assertion_parsed( const uint8_t *client_data_hash, // 32 bytes const char *rp_id, // null-terminated const uint8_t *const *allow_list_ids, // nullable const size_t *allow_list_id_lens, // nullable size_t allow_list_count, // Output fields: uint8_t *out_credential_id, size_t *out_credential_id_len, uint8_t *out_auth_data, size_t *out_auth_data_len, uint8_t *out_signature, size_t *out_signature_len, uint8_t *out_user_handle, size_t *out_user_handle_len );
```

### `ctap2_parse_make_credential_response`

Parse a raw MakeCredential response (status byte + CBOR attestation object).

```c
int ctap2_parse_make_credential_response( const uint8_t *response_data, size_t response_len, uint8_t *out_credential_id, size_t *out_credential_id_len, uint8_t *out_attestation_object, size_t *out_attestation_object_len );
```

### `ctap2_parse_get_assertion_response`

Parse a raw GetAssertion response (status byte + CBOR). fallback_cred_id: credential ID to use when the response omits key 1 (CTAP2 spec: single-entry allowList). Pass NULL/0 if no fallback.

```c
int ctap2_parse_get_assertion_response( const uint8_t *response_data, size_t response_len, const uint8_t *fallback_cred_id, // nullable size_t fallback_cred_id_len, uint8_t *out_credential_id, size_t *out_credential_id_len, uint8_t *out_auth_data, size_t *out_auth_data_len, uint8_t *out_signature, size_t *out_signature_len, uint8_t *out_user_handle, size_t *out_user_handle_len );
```

### `ctap2_get_pin_retries`

Get PIN retry count from the authenticator. out_retries: receives the number of remaining PIN retries. Returns CTAP2_OK on success, or negative error code.

```c
int ctap2_get_pin_retries(int *out_retries);
```

### `ctap2_get_pin_token`

Get a PIN token for authentication. Performs the full PIN protocol v2 handshake (key agreement + ECDH + PIN encryption) and returns a decrypted 32-byte PIN token. pin: null-terminated UTF-8 PIN string. out_pin_token: receives the 32-byte decrypted PIN token. out_pin_token_len: must be >= 32. Returns CTAP2_OK on success, positive CTAP2 status byte on device error (e.g. 0x31 = wrong PIN), or negative error code.

```c
int ctap2_get_pin_token( const char *pin, uint8_t *out_pin_token, size_t out_pin_token_len );
```

### `ctap2_make_credential_with_pin`

Same as the parsed functions above, but with optional PIN auth. Pass pin_token=NULL, pin_protocol=0 for no PIN authentication. Pass pin_token=<32-byte token from ctap2_get_pin_token>, pin_protocol=2 to include pinAuth in the CTAP2 command.

```c
int ctap2_make_credential_with_pin( const uint8_t *client_data_hash, // 32 bytes const char *rp_id, // null-terminated const char *rp_name, // null-terminated const uint8_t *user_id, size_t user_id_len, const char *user_name, // null-terminated const char *user_display_name, // null-terminated const int32_t *alg_ids, // COSE algorithm IDs size_t alg_count, bool resident_key, const uint8_t *pin_token, // 32 bytes, or NULL for no PIN uint8_t pin_protocol, // 0 = no PIN, 2 = PIN protocol v2 // Output fields: uint8_t *out_credential_id, size_t *out_credential_id_len, uint8_t *out_attestation_object, size_t *out_attestation_object_len );
```

### `ctap2_get_assertion_with_pin`

```c
int ctap2_get_assertion_with_pin( const uint8_t *client_data_hash, // 32 bytes const char *rp_id, // null-terminated const uint8_t *const *allow_list_ids, // nullable const size_t *allow_list_id_lens, // nullable size_t allow_list_count, const uint8_t *pin_token, // 32 bytes, or NULL for no PIN uint8_t pin_protocol, // 0 = no PIN, 2 = PIN protocol v2 // Output fields: uint8_t *out_credential_id, size_t *out_credential_id_len, uint8_t *out_auth_data, size_t *out_auth_data_len, uint8_t *out_signature, size_t *out_signature_len, uint8_t *out_user_handle, size_t *out_user_handle_len );
```

### `ctap2_make_credential_with_keepalive`

```c
int ctap2_make_credential_with_keepalive( const uint8_t *client_data_hash, const char *rp_id, const char *rp_name, const uint8_t *user_id, size_t user_id_len, const char *user_name, const char *user_display_name, const int32_t *alg_ids, size_t alg_count, bool resident_key, ctap2_keepalive_callback_t keepalive_cb, uint8_t *result_buf, size_t result_buf_len );
```

### `ctap2_get_assertion_with_keepalive`

```c
int ctap2_get_assertion_with_keepalive( const uint8_t *client_data_hash, // 32 bytes const char *rp_id, // null-terminated const uint8_t *const *allow_list_ids, const size_t *allow_list_id_lens, size_t allow_list_count, ctap2_keepalive_callback_t keepalive_cb, // nullable uint8_t *result_buf, size_t result_buf_len );
```

### `ctap2_debug_last_ioreturn`

Debug: get the last IOReturn error code from HID operations.

```c
int ctap2_debug_last_ioreturn(void);
```

