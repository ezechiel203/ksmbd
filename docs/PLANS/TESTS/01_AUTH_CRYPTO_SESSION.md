# Test Plan: Authentication, Cryptography & Session Management

## Current Coverage Summary

### Existing Test Files

| Test File | Functions Covered | Notes |
|-----------|-------------------|-------|
| `test/ksmbd_test_auth.c` | `str_to_key()` (replicated), `ksmbd_copy_gss_neg_header()` (replicated) | 10 test cases total. Does NOT call into the actual ksmbd module -- it replicates the logic locally and tests the replicated copy. |
| `test/ksmbd_test_config.c` | `ksmbd_config_init/exit`, `ksmbd_config_set_u32`, `ksmbd_config_get_u32`, `ksmbd_config_param_name` | 10 test cases. Tests configuration framework, not auth/crypto/session directly. |

### Coverage Statistics

#### auth.c -- 22 exported/non-static functions, 2 "tested" (via local replication only)

| # | Function | Has Test? | Coverage Quality |
|---|----------|-----------|------------------|
| 1 | `ksmbd_copy_gss_neg_header()` | PARTIAL | Tested via replicated logic, not actual function call |
| 2 | `ksmbd_auth_ntlm()` | NO | -- |
| 3 | `ksmbd_auth_ntlmv2()` | NO | -- |
| 4 | `ksmbd_decode_ntlmssp_auth_blob()` | NO | -- |
| 5 | `ksmbd_decode_ntlmssp_neg_blob()` | NO | -- |
| 6 | `ksmbd_build_ntlmssp_challenge_blob()` | NO | -- |
| 7 | `ksmbd_krb5_authenticate()` | NO | -- |
| 8 | `ksmbd_sign_smb1_pdu()` | NO | -- |
| 9 | `ksmbd_sign_smb2_pdu()` | NO | -- |
| 10 | `ksmbd_sign_smb3_pdu()` | NO | -- |
| 11 | `ksmbd_sign_smb3_pdu_gmac()` | NO | -- |
| 12 | `ksmbd_gen_smb30_signingkey()` | NO | -- |
| 13 | `ksmbd_gen_smb311_signingkey()` | NO | -- |
| 14 | `ksmbd_gen_smb30_encryptionkey()` | NO | -- |
| 15 | `ksmbd_gen_smb311_encryptionkey()` | NO | -- |
| 16 | `ksmbd_gen_preauth_integrity_hash()` | NO | -- |
| 17 | `ksmbd_gen_sd_hash()` | NO | -- |
| 18 | `ksmbd_crypt_message()` | NO | -- |
| 19 | `smb2_encrypt_resp_if_needed()` | NO | -- |
| 20 | `str_to_key()` (static, SMB_INSECURE_SERVER) | PARTIAL | Replicated locally in test, not the actual function |
| 21 | `smbhash()` (static) | NO | -- |
| 22 | `ksmbd_enc_p24()` (static) | NO | -- |

Effective auth.c coverage: **~0%** (the test file replicates logic rather than calling the actual functions)

#### crypto_ctx.c -- 12 exported functions, 0 tested

| # | Function | Has Test? |
|---|----------|-----------|
| 1 | `ksmbd_release_crypto_ctx()` | NO |
| 2 | `ksmbd_crypto_ctx_find_hmacmd5()` | NO |
| 3 | `ksmbd_crypto_ctx_find_hmacsha256()` | NO |
| 4 | `ksmbd_crypto_ctx_find_cmacaes()` | NO |
| 5 | `ksmbd_crypto_ctx_find_sha256()` | NO |
| 6 | `ksmbd_crypto_ctx_find_sha512()` | NO |
| 7 | `ksmbd_crypto_ctx_find_md4()` | NO |
| 8 | `ksmbd_crypto_ctx_find_md5()` | NO |
| 9 | `ksmbd_crypto_ctx_find_gcm()` | NO |
| 10 | `ksmbd_crypto_ctx_find_ccm()` | NO |
| 11 | `ksmbd_crypto_destroy()` | NO |
| 12 | `ksmbd_crypto_create()` | NO |

Effective crypto_ctx.c coverage: **0%**

#### ksmbd_md4.c -- 2 exported functions + 3 crypto_shash callbacks, 0 tested

| # | Function | Has Test? |
|---|----------|-----------|
| 1 | `ksmbd_md4_register()` | NO |
| 2 | `ksmbd_md4_unregister()` | NO |
| 3 | `ksmbd_md4_shash_init()` (callback) | NO |
| 4 | `ksmbd_md4_shash_update()` (callback) | NO |
| 5 | `ksmbd_md4_shash_final()` (callback) | NO |
| 6 | `md4_transform()` (static) | NO |
| 7 | `lshift()` (static inline) | NO |
| 8 | `F()` / `G()` / `H()` (static inline) | NO |

Effective ksmbd_md4.c coverage: **0%**

#### smb2_session.c -- 1 exported function, many static helpers, 0 tested

| # | Function | Has Test? |
|---|----------|-----------|
| 1 | `smb2_sess_setup()` (exported) | NO |
| 2 | `alloc_preauth_hash()` (static) | NO |
| 3 | `generate_preauth_hash()` (static) | NO |
| 4 | `decode_negotiation_token()` (static) | NO |
| 5 | `ntlm_negotiate()` (static) | NO |
| 6 | `user_authblob()` (static) | NO |
| 7 | `session_user()` (static) | NO |
| 8 | `ntlm_authenticate()` (static) | NO |
| 9 | `krb5_authenticate()` (static) | NO |

Effective smb2_session.c coverage: **0%**

#### smb2_negotiate.c -- 2 exported + many static, 0 tested

| # | Function | Has Test? |
|---|----------|-----------|
| 1 | `smb2_handle_negotiate()` (exported) | NO |
| 2 | `smb3_encryption_negotiated()` (exported) | NO |
| 3 | `build_preauth_ctxt()` (static) | NO |
| 4 | `build_encrypt_ctxt()` (static) | NO |
| 5 | `build_compress_ctxt()` (static) | NO |
| 6 | `build_sign_cap_ctxt()` (static) | NO |
| 7 | `build_rdma_transform_ctxt()` (static) | NO |
| 8 | `build_transport_cap_ctxt()` (static) | NO |
| 9 | `build_posix_ctxt()` (static) | NO |
| 10 | `assemble_neg_contexts()` (static) | NO |
| 11 | `decode_preauth_ctxt()` (static) | NO |
| 12 | `decode_encrypt_ctxt()` (static) | NO |
| 13 | `decode_compress_ctxt()` (static) | NO |
| 14 | `decode_sign_cap_ctxt()` (static) | NO |
| 15 | `decode_transport_cap_ctxt()` (static) | NO |
| 16 | `decode_rdma_transform_ctxt()` (static) | NO |
| 17 | `deassemble_neg_contexts()` (static) | NO |

Effective smb2_negotiate.c coverage: **0%**

#### user_session.c -- 16 exported functions, 0 tested

| # | Function | Has Test? |
|---|----------|-----------|
| 1 | `ksmbd_session_rpc_open()` | NO |
| 2 | `ksmbd_session_rpc_close()` | NO |
| 3 | `ksmbd_session_rpc_method()` | NO |
| 4 | `ksmbd_session_destroy()` | NO |
| 5 | `ksmbd_session_register()` | NO |
| 6 | `ksmbd_sessions_deregister()` | NO |
| 7 | `is_ksmbd_session_in_connection()` | NO |
| 8 | `ksmbd_session_lookup()` | NO |
| 9 | `ksmbd_session_lookup_slowpath()` | NO |
| 10 | `ksmbd_session_lookup_all()` | NO |
| 11 | `ksmbd_user_session_get()` | NO |
| 12 | `ksmbd_user_session_put()` | NO |
| 13 | `ksmbd_preauth_session_alloc()` | NO |
| 14 | `destroy_previous_session()` | NO |
| 15 | `ksmbd_preauth_session_lookup()` | NO |
| 16 | `ksmbd_preauth_session_remove()` | NO |
| 17 | `ksmbd_smb1_session_create()` | NO |
| 18 | `ksmbd_smb2_session_create()` | NO |
| 19 | `ksmbd_acquire_tree_conn_id()` | NO |
| 20 | `ksmbd_release_tree_conn_id()` | NO |

Effective user_session.c coverage: **0%**

#### user_config.c -- 5 exported functions, 0 tested

| # | Function | Has Test? |
|---|----------|-----------|
| 1 | `ksmbd_login_user()` | NO |
| 2 | `ksmbd_alloc_user()` | NO |
| 3 | `ksmbd_free_user()` | NO |
| 4 | `ksmbd_anonymous_user()` | NO |
| 5 | `ksmbd_compare_user()` | NO |

Effective user_config.c coverage: **0%**

### Overall Coverage

**Total functions across all 7 source files: ~77**
**Functions with any test coverage: 2 (replicated logic only)**
**Effective coverage: ~0%**

This is critically inadequate for a security-sensitive kernel module handling authentication, cryptography, and session management.

---

## Gap Analysis

### Completely Untested Functions

#### auth.c (20 untested exported functions)

1. **`ksmbd_auth_ntlm()`** - NTLMv1 authentication (SMB_INSECURE_SERVER). Computes DES-based p24 challenge response. Security-critical: password comparison path.
2. **`ksmbd_auth_ntlmv2()`** - NTLMv2 authentication. HMAC-MD5 based. Primary authentication mechanism for SMB2. Security-critical: password verification + session key generation.
3. **`ksmbd_decode_ntlmssp_auth_blob()`** - Parses NTLMSSP Authenticate message. Processes attacker-controlled offsets/lengths. Security-critical: buffer overflow potential, anonymous session handling.
4. **`ksmbd_decode_ntlmssp_neg_blob()`** - Parses NTLMSSP Negotiate message. Validates signature, extracts client flags.
5. **`ksmbd_build_ntlmssp_challenge_blob()`** - Builds NTLMSSP Challenge. Generates cryptographic challenge, target info structures. Security-critical: buffer size validation, challenge randomness.
6. **`ksmbd_krb5_authenticate()`** - Kerberos authentication via IPC to mountd. Security-critical: session key extraction, response size validation.
7. **`ksmbd_sign_smb1_pdu()`** - SMB1 PDU signing (MD5-based). Security-critical: signature integrity.
8. **`ksmbd_sign_smb2_pdu()`** - SMB2 PDU signing (HMAC-SHA256). Security-critical: signature integrity.
9. **`ksmbd_sign_smb3_pdu()`** - SMB3 PDU signing (AES-CMAC). Security-critical: signature integrity.
10. **`ksmbd_sign_smb3_pdu_gmac()`** - SMB3.1.1 GMAC signing (AES-GCM as MAC). Complex crypto path. Security-critical: nonce construction, AAD handling.
11. **`ksmbd_gen_smb30_signingkey()`** - SMB 3.0 signing key derivation (HMAC-SHA256 KDF). Security-critical: key material.
12. **`ksmbd_gen_smb311_signingkey()`** - SMB 3.1.1 signing key derivation using preauth hash. Security-critical: binding vs non-binding key context.
13. **`ksmbd_gen_smb30_encryptionkey()`** - SMB 3.0 encryption key derivation. Security-critical: key material for ServerOut/ServerIn.
14. **`ksmbd_gen_smb311_encryptionkey()`** - SMB 3.1.1 encryption key derivation using preauth hash. Security-critical: key material.
15. **`ksmbd_gen_preauth_integrity_hash()`** - SHA-512 hash chain for SMB 3.1.1 preauth integrity. Security-critical: hash chain correctness.
16. **`ksmbd_gen_sd_hash()`** - SHA-256 hash of security descriptor. Used for security descriptor comparison.
17. **`ksmbd_crypt_message()`** - AES-GCM/CCM encryption and decryption of SMB3 Transform messages. Security-critical: encryption correctness, nonce handling, key retrieval.
18. **`smb2_encrypt_resp_if_needed()`** - Conditional encryption wrapper. Security-critical: must never skip encryption when required.
19. **`cifs_arc4_setkey()` / `cifs_arc4_crypt()`** (static) - RC4 stream cipher for session key exchange. Security-critical: correctness of key schedule and encryption.
20. **`generate_key()`** (static) - SP800-108 Counter Mode KDF. Foundation for all SMB3 key derivation. Security-critical: correctness of KDF construction.

#### crypto_ctx.c (12 untested)

1. **`ksmbd_crypto_create()`** - Initializes crypto context pool
2. **`ksmbd_crypto_destroy()`** - Tears down crypto context pool
3. **`ksmbd_release_crypto_ctx()`** - Returns context to pool, handles overflow
4. **`ksmbd_crypto_ctx_find_hmacmd5()`** - Allocates/finds HMAC-MD5 context
5. **`ksmbd_crypto_ctx_find_hmacsha256()`** - Allocates/finds HMAC-SHA256 context
6. **`ksmbd_crypto_ctx_find_cmacaes()`** - Allocates/finds CMAC-AES context
7. **`ksmbd_crypto_ctx_find_sha256()`** - Allocates/finds SHA-256 context
8. **`ksmbd_crypto_ctx_find_sha512()`** - Allocates/finds SHA-512 context
9. **`ksmbd_crypto_ctx_find_md4()`** - Allocates/finds MD4 context
10. **`ksmbd_crypto_ctx_find_md5()`** - Allocates/finds MD5 context
11. **`ksmbd_crypto_ctx_find_gcm()`** - Allocates/finds AES-GCM context
12. **`ksmbd_crypto_ctx_find_ccm()`** - Allocates/finds AES-CCM context

#### ksmbd_md4.c (2 exported + 3 callbacks untested)

1. **`ksmbd_md4_register()`** - Registers md4 shash algorithm if kernel lacks it
2. **`ksmbd_md4_unregister()`** - Unregisters md4 shash algorithm
3. **`ksmbd_md4_shash_init()`** - Initializes MD4 state (IV constants)
4. **`ksmbd_md4_shash_update()`** - Processes data blocks through MD4
5. **`ksmbd_md4_shash_final()`** - Finalizes MD4 hash with padding

#### smb2_session.c (1 exported + 8 static untested)

All 9 functions completely untested.

#### smb2_negotiate.c (2 exported + 15 static untested)

All 17 functions completely untested.

#### user_session.c (20 exported untested)

All 20 functions completely untested.

#### user_config.c (5 exported untested)

All 5 functions completely untested.

### Insufficiently Tested Functions

#### `str_to_key()` (via ksmbd_test_auth.c)

The test replicates the function locally rather than calling the actual auth.c implementation. This means:
- A bug in the actual `str_to_key()` would NOT be caught
- Missing edge cases:
  - Alternating bit patterns (0x55, 0xAA)
  - Single-bit-set patterns at each position
  - Reversibility check (no two 7-byte inputs should produce the same 8-byte output for the top 7 bits)
  - Performance regression with large iteration counts (not applicable for DES key expansion, but worth documenting)

#### `ksmbd_copy_gss_neg_header()` (via ksmbd_test_auth.c)

The test replicates the function locally. Missing:
- Test with NULL buffer (should crash -- document expected behavior)
- Test that the actual module function produces the same output
- Verify the GSS header contains all three mechanism OIDs (Kerberos5, MS-Kerberos, NTLMSSP)

---

## New Tests Required

### ksmbd_test_auth.c Enhancements

The existing test file must be restructured to call actual auth.c functions. This requires making the test a proper module test that links against ksmbd symbols.

#### Test Case: `test_auth_str_to_key_actual`
- **What it tests**: Calls the actual `str_to_key()` function from auth.c (requires exposing it or using a wrapper)
- **Why it matters**: Current tests only validate a replicated copy, not the production code
- **Expected behavior**: Same as existing replicated tests, but validates the actual implementation

#### Test Case: `test_auth_gss_neg_header_actual`
- **What it tests**: Calls `ksmbd_copy_gss_neg_header()` from auth.c
- **Why it matters**: Validates production code, not a local copy
- **Expected behavior**: Buffer filled with exactly AUTH_GSS_LENGTH bytes matching the known GSS header

#### Test Case: `test_auth_gss_neg_header_contains_ntlmssp_oid`
- **What it tests**: Verifies the GSS header contains the NTLMSSP OID (1.3.6.1.4.1.311.2.2.10)
- **Why it matters**: Without the NTLMSSP OID, Windows clients cannot negotiate NTLM authentication
- **Expected behavior**: OID bytes `0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a` present at expected offset

#### Test Case: `test_auth_gss_neg_header_contains_kerberos_oid`
- **What it tests**: Verifies the GSS header contains the Kerberos 5 OID (1.2.840.113554.1.2.2)
- **Why it matters**: Without the Kerberos OID, Kerberos authentication cannot be negotiated
- **Expected behavior**: OID bytes present at expected offset

#### Test Case: `test_decode_ntlmssp_neg_blob_valid`
- **What it tests**: `ksmbd_decode_ntlmssp_neg_blob()` with a well-formed NTLMSSP Negotiate message
- **Why it matters**: This is the first step in NTLM authentication; parsing errors break auth entirely
- **Expected behavior**: Returns 0, conn->ntlmssp.client_flags populated correctly

#### Test Case: `test_decode_ntlmssp_neg_blob_bad_signature`
- **What it tests**: `ksmbd_decode_ntlmssp_neg_blob()` with incorrect "NTLMSSP" signature
- **Why it matters**: Must reject non-NTLMSSP blobs to prevent type confusion attacks
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_decode_ntlmssp_neg_blob_too_short`
- **What it tests**: `ksmbd_decode_ntlmssp_neg_blob()` with blob_len < sizeof(negotiate_message)
- **Why it matters**: Prevents buffer over-read on truncated packets
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_decode_ntlmssp_neg_blob_zero_length`
- **What it tests**: `ksmbd_decode_ntlmssp_neg_blob()` with blob_len = 0
- **Why it matters**: Edge case: zero-length input must not cause read beyond buffer
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_decode_ntlmssp_auth_blob_anonymous`
- **What it tests**: `ksmbd_decode_ntlmssp_auth_blob()` with NTLMSSP_ANONYMOUS flag, NtChallengeResponse.Length=0, UserName.Length=0
- **Why it matters**: Anonymous/null sessions are a defined protocol feature; must be accepted cleanly without crashing
- **Expected behavior**: Returns 0 (success, anonymous login accepted)

#### Test Case: `test_decode_ntlmssp_auth_blob_too_short`
- **What it tests**: `ksmbd_decode_ntlmssp_auth_blob()` with blob_len < sizeof(authenticate_message)
- **Why it matters**: Prevents buffer over-read
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_decode_ntlmssp_auth_blob_bad_signature`
- **What it tests**: `ksmbd_decode_ntlmssp_auth_blob()` with wrong NTLMSSP signature
- **Why it matters**: Prevents type confusion
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_decode_ntlmssp_auth_blob_offset_overflow`
- **What it tests**: `ksmbd_decode_ntlmssp_auth_blob()` with NtChallengeResponse.BufferOffset + Length > blob_len
- **Why it matters**: Security-critical: attacker-controlled offsets must not read out of bounds
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_decode_ntlmssp_auth_blob_domain_offset_overflow`
- **What it tests**: `ksmbd_decode_ntlmssp_auth_blob()` with DomainName.BufferOffset + Length > blob_len
- **Why it matters**: Same as above for domain name field
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_decode_ntlmssp_auth_blob_nt_len_too_small`
- **What it tests**: `ksmbd_decode_ntlmssp_auth_blob()` with 0 < NtChallengeResponse.Length < CIFS_ENCPWD_SIZE (16)
- **Why it matters**: This is neither anonymous (len=0) nor a valid response (len>=16)
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_decode_ntlmssp_auth_blob_session_key_offset_overflow`
- **What it tests**: `ksmbd_decode_ntlmssp_auth_blob()` with NTLMSSP_NEGOTIATE_KEY_XCH set and SessionKey.BufferOffset + Length > blob_len
- **Why it matters**: Session key exchange path parses additional attacker-controlled offsets
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_decode_ntlmssp_auth_blob_session_key_too_large`
- **What it tests**: `ksmbd_decode_ntlmssp_auth_blob()` with SessionKey.Length > CIFS_KEY_SIZE
- **Why it matters**: Prevents oversized session key from corrupting memory
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_decode_ntlmssp_auth_blob_session_key_too_small`
- **What it tests**: `ksmbd_decode_ntlmssp_auth_blob()` with SessionKey.Length < SMB2_NTLMV2_SESSKEY_SIZE (16)
- **Why it matters**: Undersized session key would produce garbled decryption
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_build_ntlmssp_challenge_blob_basic`
- **What it tests**: `ksmbd_build_ntlmssp_challenge_blob()` produces valid NTLMSSP Challenge
- **Why it matters**: Challenge blob is sent to the client during NTLM negotiate phase
- **Expected behavior**: Returns positive blob_len, output starts with "NTLMSSP\0" + NtLmChallenge type, contains target info

#### Test Case: `test_build_ntlmssp_challenge_blob_buffer_too_small`
- **What it tests**: `ksmbd_build_ntlmssp_challenge_blob()` with max_blob_sz insufficient
- **Why it matters**: Must not write past allocated buffer
- **Expected behavior**: Returns -ENOSPC

#### Test Case: `test_build_ntlmssp_challenge_blob_flags_negotiation`
- **What it tests**: Various client flag combinations (SIGN, SEAL, KEY_XCH, EXTENDED_SEC)
- **Why it matters**: Flag negotiation logic determines security capabilities
- **Expected behavior**: Response flags correctly reflect negotiated capabilities

#### Test Case: `test_auth_ntlmv2_bad_blen`
- **What it tests**: `ksmbd_auth_ntlmv2()` with blen <= 0
- **Why it matters**: Early validation prevents crypto operations on invalid data
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_auth_ntlmv2_wrong_password`
- **What it tests**: `ksmbd_auth_ntlmv2()` with incorrect NTLMv2 response hash
- **Why it matters**: Must reject wrong passwords with constant-time comparison
- **Expected behavior**: Returns -EINVAL, session key NOT generated

#### Test Case: `test_gen_sd_hash_basic`
- **What it tests**: `ksmbd_gen_sd_hash()` produces correct SHA-256 hash
- **Why it matters**: Used for security descriptor integrity verification
- **Expected behavior**: Known input produces known SHA-256 output

#### Test Case: `test_gen_sd_hash_empty_input`
- **What it tests**: `ksmbd_gen_sd_hash()` with zero-length buffer
- **Why it matters**: Edge case: empty SD should produce the SHA-256 of empty string
- **Expected behavior**: Known empty-input SHA-256 hash

#### Test Case: `test_gen_preauth_integrity_hash_wrong_hash_id`
- **What it tests**: `ksmbd_gen_preauth_integrity_hash()` when Preauth_HashId is not SHA-512
- **Why it matters**: Must reject unsupported hash algorithms
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_gen_preauth_integrity_hash_msg_too_small`
- **What it tests**: `ksmbd_gen_preauth_integrity_hash()` with msg_size < sizeof(smb2_hdr)
- **Why it matters**: Validates message size bounds check
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_gen_preauth_integrity_hash_msg_too_large`
- **What it tests**: `ksmbd_gen_preauth_integrity_hash()` with msg_size > MAX_STREAM_PROT_LEN
- **Why it matters**: Prevents processing absurdly large messages
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_sign_smb2_pdu_known_vector`
- **What it tests**: `ksmbd_sign_smb2_pdu()` with known key, known data, expected HMAC-SHA256
- **Why it matters**: Signing correctness is fundamental to SMB2 security
- **Expected behavior**: Signature matches known-good value

#### Test Case: `test_sign_smb2_pdu_zero_vecs`
- **What it tests**: `ksmbd_sign_smb2_pdu()` with n_vec = 0
- **Why it matters**: Edge case: no data to sign
- **Expected behavior**: Defined behavior (hash of just the key, or error)

#### Test Case: `test_sign_smb3_pdu_known_vector`
- **What it tests**: `ksmbd_sign_smb3_pdu()` with known key, known data, expected AES-CMAC
- **Why it matters**: AES-CMAC signing correctness
- **Expected behavior**: Signature matches known-good value from MS-SMB2 test vectors

#### Test Case: `test_sign_smb3_pdu_gmac_known_vector`
- **What it tests**: `ksmbd_sign_smb3_pdu_gmac()` with known key, known data
- **Why it matters**: AES-GMAC is a complex crypto path (GCM with zero-length plaintext)
- **Expected behavior**: Tag matches known-good AES-GMAC output

#### Test Case: `test_sign_smb3_pdu_gmac_no_vecs`
- **What it tests**: `ksmbd_sign_smb3_pdu_gmac()` with n_vec < 1
- **Why it matters**: Must return -EINVAL without crashing
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_sign_smb3_pdu_gmac_null_iov_base`
- **What it tests**: `ksmbd_sign_smb3_pdu_gmac()` with iov[0].iov_base = NULL
- **Why it matters**: Must not dereference NULL
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_encrypt_resp_if_needed_no_session`
- **What it tests**: `smb2_encrypt_resp_if_needed()` with work->sess = NULL
- **Why it matters**: Must gracefully return 0 when no session exists
- **Expected behavior**: Returns 0

#### Test Case: `test_encrypt_resp_if_needed_no_encryption`
- **What it tests**: `smb2_encrypt_resp_if_needed()` with sess->enc = false
- **Why it matters**: Must not encrypt when encryption is not negotiated
- **Expected behavior**: Returns 0

### ksmbd_test_crypto_ctx.c (NEW)

#### Test Case: `test_crypto_create_destroy`
- **What it tests**: `ksmbd_crypto_create()` followed by `ksmbd_crypto_destroy()`
- **Why it matters**: Validates pool lifecycle without leaks
- **Expected behavior**: create returns 0, destroy does not crash

#### Test Case: `test_crypto_create_returns_zero`
- **What it tests**: `ksmbd_crypto_create()` return value
- **Why it matters**: Module init depends on this succeeding
- **Expected behavior**: Returns 0

#### Test Case: `test_crypto_find_release_hmacmd5`
- **What it tests**: `ksmbd_crypto_ctx_find_hmacmd5()` returns non-NULL ctx, `ksmbd_release_crypto_ctx()` returns it
- **Why it matters**: HMAC-MD5 is required for NTLMv2 authentication
- **Expected behavior**: Non-NULL context with valid desc[CRYPTO_SHASH_HMACMD5]

#### Test Case: `test_crypto_find_release_hmacsha256`
- **What it tests**: `ksmbd_crypto_ctx_find_hmacsha256()` round-trip
- **Why it matters**: Required for SMB2 signing and key derivation
- **Expected behavior**: Non-NULL context

#### Test Case: `test_crypto_find_release_cmacaes`
- **What it tests**: `ksmbd_crypto_ctx_find_cmacaes()` round-trip
- **Why it matters**: Required for SMB3 signing
- **Expected behavior**: Non-NULL context

#### Test Case: `test_crypto_find_release_sha256`
- **What it tests**: `ksmbd_crypto_ctx_find_sha256()` round-trip
- **Why it matters**: Required for SD hash
- **Expected behavior**: Non-NULL context

#### Test Case: `test_crypto_find_release_sha512`
- **What it tests**: `ksmbd_crypto_ctx_find_sha512()` round-trip
- **Why it matters**: Required for preauth integrity hash
- **Expected behavior**: Non-NULL context

#### Test Case: `test_crypto_find_release_md4`
- **What it tests**: `ksmbd_crypto_ctx_find_md4()` round-trip
- **Why it matters**: Required for NTLMv1 password hashing (with ksmbd_md4 fallback)
- **Expected behavior**: Non-NULL context (after ksmbd_md4_register)

#### Test Case: `test_crypto_find_release_md5`
- **What it tests**: `ksmbd_crypto_ctx_find_md5()` round-trip
- **Why it matters**: Required for SMB1 signing
- **Expected behavior**: Non-NULL context

#### Test Case: `test_crypto_find_release_gcm`
- **What it tests**: `ksmbd_crypto_ctx_find_gcm()` round-trip
- **Why it matters**: Required for AES-GCM encryption and GMAC signing
- **Expected behavior**: Non-NULL context

#### Test Case: `test_crypto_find_release_ccm`
- **What it tests**: `ksmbd_crypto_ctx_find_ccm()` round-trip
- **Why it matters**: Required for AES-CCM encryption
- **Expected behavior**: Non-NULL context

#### Test Case: `test_crypto_release_null_ctx`
- **What it tests**: `ksmbd_release_crypto_ctx(NULL)`
- **Why it matters**: Must not crash on NULL
- **Expected behavior**: Returns without crash

#### Test Case: `test_crypto_pool_reuse`
- **What it tests**: Find, release, find again -- verify same context is reused
- **Why it matters**: Pool reuse is the performance optimization; verify it works
- **Expected behavior**: Second find returns quickly, desc[] already allocated

#### Test Case: `test_crypto_pool_multiple_find`
- **What it tests**: Find multiple different algorithm contexts from the same pool entry
- **Why it matters**: A single ksmbd_crypto_ctx holds all algorithm types
- **Expected behavior**: All desc[] slots populated on demand

#### Test Case: `test_crypto_pool_exhaustion`
- **What it tests**: Allocate contexts up to num_online_cpus() + 1
- **Why it matters**: Pool limit enforcement prevents unbounded allocation
- **Expected behavior**: Beyond pool limit, callers wait or fail after retries

### ksmbd_test_md4.c (NEW)

#### Test Case: `test_md4_register_unregister`
- **What it tests**: `ksmbd_md4_register()` followed by `ksmbd_md4_unregister()`
- **Why it matters**: Module lifecycle correctness
- **Expected behavior**: register returns 0 (or 0 if kernel already has md4), unregister does not crash

#### Test Case: `test_md4_double_register`
- **What it tests**: `ksmbd_md4_register()` called twice
- **Why it matters**: Must be idempotent (second call sees md4 already available)
- **Expected behavior**: Both calls return 0

#### Test Case: `test_md4_unregister_without_register`
- **What it tests**: `ksmbd_md4_unregister()` when md4_registered is false
- **Why it matters**: Must be a no-op without crash
- **Expected behavior**: No crash, no action

#### Test Case: `test_md4_empty_string`
- **What it tests**: MD4 hash of empty string (0 bytes)
- **Why it matters**: RFC 1320 test vector: MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
- **Expected behavior**: Hash matches RFC 1320 value

#### Test Case: `test_md4_rfc1320_vector_a`
- **What it tests**: MD4("a") = bde52cb31de33e46245e05fbdbd6fb24
- **Why it matters**: RFC 1320 test vector
- **Expected behavior**: Hash matches

#### Test Case: `test_md4_rfc1320_vector_abc`
- **What it tests**: MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
- **Why it matters**: RFC 1320 test vector
- **Expected behavior**: Hash matches

#### Test Case: `test_md4_rfc1320_vector_message_digest`
- **What it tests**: MD4("message digest") = d9130a8164549fe818874806e1c7014b
- **Why it matters**: RFC 1320 test vector
- **Expected behavior**: Hash matches

#### Test Case: `test_md4_rfc1320_vector_alphabet`
- **What it tests**: MD4("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9
- **Why it matters**: RFC 1320 test vector
- **Expected behavior**: Hash matches

#### Test Case: `test_md4_rfc1320_vector_alphanumeric`
- **What it tests**: MD4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = 043f8582f241db351ce627e153e7f0e4
- **Why it matters**: RFC 1320 test vector
- **Expected behavior**: Hash matches

#### Test Case: `test_md4_rfc1320_vector_numeric_repeat`
- **What it tests**: MD4("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = e33b4ddc9c38f2199c3e7b164fcc0536
- **Why it matters**: RFC 1320 test vector, tests multi-block processing
- **Expected behavior**: Hash matches

#### Test Case: `test_md4_incremental_update`
- **What it tests**: Feeding data in multiple update() calls produces same hash as single call
- **Why it matters**: Validates streaming/incremental hash logic
- **Expected behavior**: hash("ab" + "cd") == hash("abcd")

#### Test Case: `test_md4_exactly_one_block`
- **What it tests**: Input of exactly 64 bytes (one MD4 block)
- **Why it matters**: Boundary case in md4_transform_helper path
- **Expected behavior**: Produces correct hash

#### Test Case: `test_md4_block_boundary_minus_one`
- **What it tests**: Input of 55 bytes (maximum that fits in one block with padding)
- **Why it matters**: Tests the padding boundary: 55 bytes + 1 (0x80) + 0 padding + 8 (length) = 64
- **Expected behavior**: Produces correct hash

#### Test Case: `test_md4_block_boundary_plus_one`
- **What it tests**: Input of 56 bytes (forces second block for padding)
- **Why it matters**: Tests the two-block padding path
- **Expected behavior**: Produces correct hash

#### Test Case: `test_md4_large_input`
- **What it tests**: Input of 1000+ bytes spanning multiple blocks
- **Why it matters**: Tests the multi-block while loop in ksmbd_md4_shash_update
- **Expected behavior**: Produces correct hash

#### Test Case: `test_md4_init_constants`
- **What it tests**: After init(), hash state matches MD4 IV constants (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
- **Why it matters**: Incorrect IV breaks all MD4 computations
- **Expected behavior**: State matches RFC 1320 constants

#### Test Case: `test_md4_final_clears_state`
- **What it tests**: After final(), context memory is zeroed
- **Why it matters**: Security: prevents information leakage from crypto state
- **Expected behavior**: memzero_explicit called on context (verify via known output)

### ksmbd_test_session.c (NEW - session lifecycle)

#### Test Case: `test_smb2_session_create`
- **What it tests**: `ksmbd_smb2_session_create()` creates a session with valid ID
- **Why it matters**: Session creation is the first step in every SMB2 connection
- **Expected behavior**: Returns non-NULL, sess->id > 0, state == SMB2_SESSION_IN_PROGRESS

#### Test Case: `test_smb2_session_create_initializes_fields`
- **What it tests**: Newly created session has correct initial field values
- **Why it matters**: Uninitialized fields cause undefined behavior
- **Expected behavior**: refcnt == 2, sequence_number == 1, xarrays initialized, gcm_nonce_prefix non-zero (random)

#### Test Case: `test_session_destroy_null`
- **What it tests**: `ksmbd_session_destroy(NULL)`
- **Why it matters**: Must be a safe no-op
- **Expected behavior**: No crash

#### Test Case: `test_session_register_lookup`
- **What it tests**: Register session on connection, then look it up
- **Why it matters**: Session registration and lookup are used on every request
- **Expected behavior**: `ksmbd_session_lookup()` returns the registered session

#### Test Case: `test_session_lookup_nonexistent`
- **What it tests**: `ksmbd_session_lookup()` with non-existent ID
- **Why it matters**: Must return NULL without crash
- **Expected behavior**: Returns NULL

#### Test Case: `test_session_lookup_slowpath`
- **What it tests**: `ksmbd_session_lookup_slowpath()` finds session in global table
- **Why it matters**: Used for binding (multichannel) session lookup
- **Expected behavior**: Returns session with incremented refcount

#### Test Case: `test_session_lookup_slowpath_nonexistent`
- **What it tests**: `ksmbd_session_lookup_slowpath()` with non-existent ID
- **Why it matters**: Must return NULL
- **Expected behavior**: Returns NULL

#### Test Case: `test_session_lookup_all_valid_state`
- **What it tests**: `ksmbd_session_lookup_all()` with session in VALID state
- **Why it matters**: Must return session when state is valid
- **Expected behavior**: Returns session

#### Test Case: `test_session_lookup_all_expired_state`
- **What it tests**: `ksmbd_session_lookup_all()` with session in EXPIRED state
- **Why it matters**: Must NOT return expired sessions
- **Expected behavior**: Returns NULL

#### Test Case: `test_session_get_put_refcount`
- **What it tests**: `ksmbd_user_session_get()` increments refcount, `ksmbd_user_session_put()` decrements
- **Why it matters**: Refcount management prevents use-after-free
- **Expected behavior**: refcount increments/decrements correctly

#### Test Case: `test_session_put_null`
- **What it tests**: `ksmbd_user_session_put(NULL)`
- **Why it matters**: Must be a safe no-op
- **Expected behavior**: No crash

#### Test Case: `test_session_put_last_ref_destroys`
- **What it tests**: `ksmbd_user_session_put()` when refcount drops to 0
- **Why it matters**: Must trigger session destruction
- **Expected behavior**: Session is freed (verify via KASAN or by checking destroy side effects)

#### Test Case: `test_session_in_connection_true`
- **What it tests**: `is_ksmbd_session_in_connection()` with registered session
- **Why it matters**: Used to check if session is already bound to a connection
- **Expected behavior**: Returns true

#### Test Case: `test_session_in_connection_false`
- **What it tests**: `is_ksmbd_session_in_connection()` with non-existent session
- **Why it matters**: Must return false without crash
- **Expected behavior**: Returns false

#### Test Case: `test_session_deregister`
- **What it tests**: `ksmbd_sessions_deregister()` removes sessions from connection
- **Why it matters**: Connection teardown must clean up all sessions
- **Expected behavior**: Session is removed, channels cleaned up

#### Test Case: `test_preauth_session_alloc_lookup`
- **What it tests**: `ksmbd_preauth_session_alloc()` then `ksmbd_preauth_session_lookup()`
- **Why it matters**: Preauth sessions hold preauth hash state for SMB 3.1.1
- **Expected behavior**: Lookup finds the allocated preauth session

#### Test Case: `test_preauth_session_lookup_nonexistent`
- **What it tests**: `ksmbd_preauth_session_lookup()` with non-existent ID
- **Why it matters**: Must return NULL
- **Expected behavior**: Returns NULL

#### Test Case: `test_preauth_session_remove`
- **What it tests**: `ksmbd_preauth_session_remove()` removes allocated session
- **Why it matters**: Cleanup path must work correctly
- **Expected behavior**: Returns 0, subsequent lookup returns NULL

#### Test Case: `test_preauth_session_remove_nonexistent`
- **What it tests**: `ksmbd_preauth_session_remove()` with non-existent ID
- **Why it matters**: Must return -ENOENT without crash
- **Expected behavior**: Returns -ENOENT

#### Test Case: `test_destroy_previous_session_same_user`
- **What it tests**: `destroy_previous_session()` with matching user credentials
- **Why it matters**: Previous session must be destroyed when same user reconnects
- **Expected behavior**: Previous session state set to EXPIRED

#### Test Case: `test_destroy_previous_session_different_user`
- **What it tests**: `destroy_previous_session()` with different user credentials
- **Why it matters**: Must NOT destroy previous session if user does not match
- **Expected behavior**: Previous session remains valid

#### Test Case: `test_session_rpc_open_close`
- **What it tests**: `ksmbd_session_rpc_open()` with valid RPC name, then close
- **Why it matters**: RPC pipe lifecycle management
- **Expected behavior**: open returns valid ID > 0, close succeeds

#### Test Case: `test_session_rpc_open_invalid`
- **What it tests**: `ksmbd_session_rpc_open()` with unsupported RPC name
- **Why it matters**: Must reject unknown RPC pipe names
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_session_rpc_method`
- **What it tests**: `ksmbd_session_rpc_method()` returns correct method for opened pipe
- **Why it matters**: Method determines how IPC requests are dispatched
- **Expected behavior**: Returns KSMBD_RPC_SRVSVC_METHOD_INVOKE for "\\srvsvc"

#### Test Case: `test_session_rpc_close_nonexistent`
- **What it tests**: `ksmbd_session_rpc_close()` with invalid ID
- **Why it matters**: Must not crash on invalid ID
- **Expected behavior**: No crash, no action

#### Test Case: `test_acquire_release_tree_conn_id`
- **What it tests**: `ksmbd_acquire_tree_conn_id()` and `ksmbd_release_tree_conn_id()`
- **Why it matters**: Tree connect IDs must be unique and recyclable
- **Expected behavior**: Acquired ID is valid, released ID can be reacquired

#### Test Case: `test_smb1_session_create`
- **What it tests**: `ksmbd_smb1_session_create()` (CONFIG_SMB_INSECURE_SERVER)
- **Why it matters**: SMB1 sessions must work for backward compatibility
- **Expected behavior**: Returns non-NULL, ID in SMB1 range

### ksmbd_test_negotiate.c (NEW - negotiate protocol)

#### Test Case: `test_smb3_encryption_negotiated_no_ops`
- **What it tests**: `smb3_encryption_negotiated()` when conn->ops->generate_encryptionkey is NULL
- **Why it matters**: Must return false when encryption is not available
- **Expected behavior**: Returns false

#### Test Case: `test_smb3_encryption_negotiated_cap_flag`
- **What it tests**: `smb3_encryption_negotiated()` when SMB2_GLOBAL_CAP_ENCRYPTION is set
- **Why it matters**: SMB 3.0/3.0.2 use this flag
- **Expected behavior**: Returns true

#### Test Case: `test_smb3_encryption_negotiated_cipher_type`
- **What it tests**: `smb3_encryption_negotiated()` when conn->cipher_type is non-zero
- **Why it matters**: SMB 3.1.1 uses cipher_type field
- **Expected behavior**: Returns true

#### Test Case: `test_decode_preauth_ctxt_valid`
- **What it tests**: `decode_preauth_ctxt()` with valid SHA-512 context
- **Why it matters**: Must correctly set Preauth_HashId
- **Expected behavior**: Returns STATUS_SUCCESS, Preauth_HashId = SHA512

#### Test Case: `test_decode_preauth_ctxt_too_short`
- **What it tests**: `decode_preauth_ctxt()` with ctxt_len too small
- **Why it matters**: Must reject truncated contexts
- **Expected behavior**: Returns STATUS_INVALID_PARAMETER

#### Test Case: `test_decode_preauth_ctxt_zero_hash_count`
- **What it tests**: `decode_preauth_ctxt()` with HashAlgorithmCount = 0
- **Why it matters**: Spec requires count >= 1
- **Expected behavior**: Returns STATUS_INVALID_PARAMETER

#### Test Case: `test_decode_preauth_ctxt_unknown_hash`
- **What it tests**: `decode_preauth_ctxt()` with unsupported hash algorithm
- **Why it matters**: Must indicate no overlap
- **Expected behavior**: Returns STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP

#### Test Case: `test_decode_encrypt_ctxt_aes128_gcm`
- **What it tests**: `decode_encrypt_ctxt()` with AES-128-GCM offered by client
- **Why it matters**: Cipher selection correctness
- **Expected behavior**: conn->cipher_type = SMB2_ENCRYPTION_AES128_GCM

#### Test Case: `test_decode_encrypt_ctxt_server_preference`
- **What it tests**: `decode_encrypt_ctxt()` with client offering CCM then GCM
- **Why it matters**: Server must prefer GCM over CCM regardless of client order
- **Expected behavior**: conn->cipher_type = SMB2_ENCRYPTION_AES128_GCM (or AES256_GCM if available)

#### Test Case: `test_decode_encrypt_ctxt_cipher_count_overflow`
- **What it tests**: `decode_encrypt_ctxt()` with CipherCount causing integer overflow
- **Why it matters**: Security: prevents heap over-read
- **Expected behavior**: Returns without setting cipher_type

#### Test Case: `test_decode_encrypt_ctxt_encryption_disabled`
- **What it tests**: `decode_encrypt_ctxt()` when KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF is set
- **Why it matters**: Admin-disabled encryption must not be enabled
- **Expected behavior**: conn->cipher_type remains 0

#### Test Case: `test_decode_compress_ctxt_zero_count`
- **What it tests**: `decode_compress_ctxt()` with CompressionAlgorithmCount = 0
- **Why it matters**: Spec requires count > 0
- **Expected behavior**: Returns STATUS_INVALID_PARAMETER

#### Test Case: `test_decode_compress_ctxt_lz4`
- **What it tests**: `decode_compress_ctxt()` with LZ4 offered
- **Why it matters**: LZ4 is the preferred algorithm
- **Expected behavior**: conn->compress_algorithm = SMB3_COMPRESS_LZ4

#### Test Case: `test_decode_sign_cap_ctxt_zero_count`
- **What it tests**: `decode_sign_cap_ctxt()` with SigningAlgorithmCount = 0
- **Why it matters**: Spec requires count > 0
- **Expected behavior**: Returns STATUS_INVALID_PARAMETER

#### Test Case: `test_decode_sign_cap_ctxt_aes_cmac`
- **What it tests**: `decode_sign_cap_ctxt()` with AES-CMAC offered
- **Why it matters**: Must select AES-CMAC as signing algorithm
- **Expected behavior**: conn->signing_algorithm = SIGNING_ALG_AES_CMAC

#### Test Case: `test_decode_sign_cap_ctxt_no_overlap_fallback`
- **What it tests**: `decode_sign_cap_ctxt()` with only AES-GMAC offered (no AES-CMAC or HMAC-SHA256)
- **Why it matters**: Must fall back to AES-CMAC even without overlap
- **Expected behavior**: conn->signing_algorithm = SIGNING_ALG_AES_CMAC (fallback)

#### Test Case: `test_deassemble_neg_contexts_too_many`
- **What it tests**: `deassemble_neg_contexts()` with NegotiateContextCount > SMB2_MAX_NEG_CTXTS (16)
- **Why it matters**: Must reject excessive context count to prevent DoS
- **Expected behavior**: Returns STATUS_INVALID_PARAMETER

#### Test Case: `test_deassemble_neg_contexts_duplicate_preauth`
- **What it tests**: `deassemble_neg_contexts()` with two PREAUTH_INTEGRITY contexts
- **Why it matters**: MS-SMB2 requires rejection of duplicate contexts
- **Expected behavior**: Returns STATUS_INVALID_PARAMETER

#### Test Case: `test_deassemble_neg_contexts_duplicate_encrypt`
- **What it tests**: `deassemble_neg_contexts()` with two ENCRYPTION_CAPABILITIES contexts
- **Why it matters**: MS-SMB2 requires rejection of duplicate contexts
- **Expected behavior**: Returns STATUS_INVALID_PARAMETER

#### Test Case: `test_deassemble_neg_contexts_duplicate_compress`
- **What it tests**: `deassemble_neg_contexts()` with two COMPRESSION_CAPABILITIES contexts
- **Why it matters**: MS-SMB2 requires rejection of duplicate contexts
- **Expected behavior**: Returns STATUS_INVALID_PARAMETER

#### Test Case: `test_deassemble_neg_contexts_duplicate_rdma`
- **What it tests**: `deassemble_neg_contexts()` with two RDMA_TRANSFORM_CAPABILITIES contexts
- **Why it matters**: MS-SMB2 requires rejection of duplicate contexts
- **Expected behavior**: Returns STATUS_INVALID_PARAMETER

#### Test Case: `test_deassemble_neg_contexts_offset_beyond_end`
- **What it tests**: `deassemble_neg_contexts()` with NegotiateContextOffset > len_of_smb
- **Why it matters**: Must not read past end of message
- **Expected behavior**: Returns STATUS_SUCCESS (no contexts parsed)

#### Test Case: `test_assemble_neg_contexts_buf_too_small`
- **What it tests**: `assemble_neg_contexts()` with buf_len insufficient
- **Why it matters**: Must not write past buffer
- **Expected behavior**: Returns -EINVAL

#### Test Case: `test_negotiate_second_negotiate_disconnects`
- **What it tests**: `smb2_handle_negotiate()` on an already-established (good) connection
- **Why it matters**: MS-SMB2 section 3.3.5.3.1 mandates disconnect
- **Expected behavior**: conn set to exiting, send_no_response = 1

#### Test Case: `test_negotiate_zero_dialect_count`
- **What it tests**: `smb2_handle_negotiate()` with DialectCount = 0
- **Why it matters**: Must reject malformed negotiate with STATUS_INVALID_PARAMETER
- **Expected behavior**: Returns -EINVAL, rsp->hdr.Status = STATUS_INVALID_PARAMETER

### ksmbd_test_user_session_mgmt.c (NEW - session management layer)

This file tests the user_session.c management layer in isolation.

#### Test Case: `test_rpc_method_srvsvc`
- **What it tests**: `__rpc_method("\\srvsvc")` returns KSMBD_RPC_SRVSVC_METHOD_INVOKE
- **Why it matters**: RPC method dispatch correctness
- **Expected behavior**: Returns expected method constant

#### Test Case: `test_rpc_method_wkssvc`
- **What it tests**: `__rpc_method("\\wkssvc")` returns KSMBD_RPC_WKSSVC_METHOD_INVOKE
- **Why it matters**: Workstation service RPC dispatch
- **Expected behavior**: Returns expected method constant

#### Test Case: `test_rpc_method_lanman`
- **What it tests**: `__rpc_method("LANMAN")` returns KSMBD_RPC_RAP_METHOD
- **Why it matters**: Legacy RAP protocol support
- **Expected behavior**: Returns expected method constant

#### Test Case: `test_rpc_method_samr`
- **What it tests**: `__rpc_method("\\samr")` returns KSMBD_RPC_SAMR_METHOD_INVOKE
- **Why it matters**: SAM RPC dispatch
- **Expected behavior**: Returns expected method constant

#### Test Case: `test_rpc_method_lsarpc`
- **What it tests**: `__rpc_method("\\lsarpc")` returns KSMBD_RPC_LSARPC_METHOD_INVOKE
- **Why it matters**: LSA RPC dispatch
- **Expected behavior**: Returns expected method constant

#### Test Case: `test_rpc_method_unsupported`
- **What it tests**: `__rpc_method("unknown")` returns 0
- **Why it matters**: Unsupported RPC names must be rejected
- **Expected behavior**: Returns 0

#### Test Case: `test_rpc_method_without_backslash`
- **What it tests**: `__rpc_method("srvsvc")` (without leading backslash)
- **Why it matters**: Both forms must be accepted
- **Expected behavior**: Returns KSMBD_RPC_SRVSVC_METHOD_INVOKE

### ksmbd_test_user_config.c (NEW - user configuration)

#### Test Case: `test_alloc_user_basic`
- **What it tests**: `ksmbd_alloc_user()` with valid login response
- **Why it matters**: User allocation is part of every authentication
- **Expected behavior**: Returns non-NULL user with name, passkey, uid, gid set correctly

#### Test Case: `test_alloc_user_null_passkey`
- **What it tests**: `ksmbd_alloc_user()` when passkey allocation fails (hash_sz = 0 or simulated OOM)
- **Why it matters**: Must handle allocation failure gracefully
- **Expected behavior**: Returns NULL (frees partial allocations)

#### Test Case: `test_alloc_user_ngroups_exceeds_max`
- **What it tests**: `ksmbd_alloc_user()` with resp_ext->ngroups > NGROUPS_MAX
- **Why it matters**: Prevents kernel memory exhaustion from untrusted IPC response
- **Expected behavior**: Returns NULL

#### Test Case: `test_alloc_user_with_supplementary_groups`
- **What it tests**: `ksmbd_alloc_user()` with valid resp_ext containing supplementary groups
- **Why it matters**: Supplementary group support is needed for proper access control
- **Expected behavior**: user->ngroups and user->sgid set correctly

#### Test Case: `test_free_user_basic`
- **What it tests**: `ksmbd_free_user()` frees all user memory
- **Why it matters**: Memory leak prevention; passkey must be freed sensitively
- **Expected behavior**: No memory leaks (verify via kmemleak)

#### Test Case: `test_anonymous_user_empty_name`
- **What it tests**: `ksmbd_anonymous_user()` with user->name[0] = '\0'
- **Why it matters**: Anonymous user detection for null sessions
- **Expected behavior**: Returns 1 (true)

#### Test Case: `test_anonymous_user_nonempty_name`
- **What it tests**: `ksmbd_anonymous_user()` with non-empty name
- **Why it matters**: Must not misidentify named users as anonymous
- **Expected behavior**: Returns 0 (false)

#### Test Case: `test_compare_user_identical`
- **What it tests**: `ksmbd_compare_user()` with two identical users
- **Why it matters**: Used for re-authentication to detect same credentials
- **Expected behavior**: Returns true

#### Test Case: `test_compare_user_different_name`
- **What it tests**: `ksmbd_compare_user()` with different names
- **Why it matters**: Different users must not compare equal
- **Expected behavior**: Returns false

#### Test Case: `test_compare_user_different_passkey`
- **What it tests**: `ksmbd_compare_user()` with same name but different passkey
- **Why it matters**: Password change must be detected
- **Expected behavior**: Returns false

#### Test Case: `test_compare_user_different_passkey_size`
- **What it tests**: `ksmbd_compare_user()` with same name but different passkey_sz
- **Why it matters**: Short-circuit before crypto_memneq for different sizes
- **Expected behavior**: Returns false

#### Test Case: `test_compare_user_timing_safe`
- **What it tests**: `ksmbd_compare_user()` uses `crypto_memneq()` for passkey comparison
- **Why it matters**: Constant-time comparison prevents timing side-channel attacks
- **Expected behavior**: Uses crypto_memneq (verified by code inspection; runtime timing test optional)

---

## Edge Cases & Security Tests

### Buffer Overflow / Over-read

| ID | Test | Target Function | Risk |
|----|------|-----------------|------|
| SEC-01 | NtChallengeResponse.BufferOffset = 0xFFFFFFFF | `ksmbd_decode_ntlmssp_auth_blob()` | Integer overflow when added to Length |
| SEC-02 | DomainName.BufferOffset = blob_len - 1, Length = 2 | `ksmbd_decode_ntlmssp_auth_blob()` | One-byte over-read |
| SEC-03 | SessionKey.BufferOffset = 0, Length = 0xFFFF | `ksmbd_decode_ntlmssp_auth_blob()` | Massive over-read |
| SEC-04 | SecurityBufferOffset = 0, SecurityBufferLength = 0xFFFF | `smb2_sess_setup()` | OOB read of negotiate blob |
| SEC-05 | NegotiateContextOffset > msg_size | `deassemble_neg_contexts()` | OOB read of negotiate contexts |
| SEC-06 | CipherCount = 0x7FFF, ctxt_len = 8 | `decode_encrypt_ctxt()` | Array over-read |
| SEC-07 | CompressionAlgorithmCount = INT_MAX | `decode_compress_ctxt()` | Integer overflow in size calculation |
| SEC-08 | SigningAlgorithmCount = INT_MAX | `decode_sign_cap_ctxt()` | Integer overflow in size calculation |
| SEC-09 | TransformCount = 0x7FFF | `decode_rdma_transform_ctxt()` | Array over-read |
| SEC-10 | TargetName.Length > max_blob_sz | `ksmbd_build_ntlmssp_challenge_blob()` | Buffer overflow in output |
| SEC-11 | msg_size = MAX_STREAM_PROT_LEN + 1 | `ksmbd_gen_preauth_integrity_hash()` | Oversized message |
| SEC-12 | msg_size = 0 | `ksmbd_gen_preauth_integrity_hash()` | Zero-length message |
| SEC-13 | blen = INT_MAX causing CIFS_CRYPTO_KEY_SIZE + blen overflow | `ksmbd_auth_ntlmv2()` | Integer overflow in kzalloc size |
| SEC-14 | n_vec = 0 to all signing functions | `ksmbd_sign_smb{1,2,3}_pdu()` | Zero-vector signing |

### Timing Side-Channels

| ID | Test | Target Function | Risk |
|----|------|-----------------|------|
| TIM-01 | Password comparison uses crypto_memneq | `ksmbd_auth_ntlmv2()` | Timing oracle for password bytes |
| TIM-02 | Session key comparison uses crypto_memneq | `ksmbd_compare_user()` | Timing oracle for session material |
| TIM-03 | NTLMSSP signature comparison | `ksmbd_decode_ntlmssp_auth_blob()` | memcmp is NOT constant-time (acceptable for non-secret "NTLMSSP" signature) |

### Cryptographic Correctness

| ID | Test | Target Function | Risk |
|----|------|-----------------|------|
| CRY-01 | MD4 RFC 1320 test vectors | `ksmbd_md4_shash_*` | Incorrect hash breaks all NTLMv1 auth |
| CRY-02 | ARC4 known-answer tests | `cifs_arc4_setkey/crypt` | Incorrect RC4 breaks session key exchange |
| CRY-03 | SP800-108 KDF test vectors | `generate_key()` | Incorrect KDF breaks all SMB3 signing/encryption |
| CRY-04 | AES-CMAC test vectors (NIST SP 800-38B) | `ksmbd_sign_smb3_pdu()` | Incorrect signing breaks SMB3 |
| CRY-05 | AES-GCM/CCM test vectors | `ksmbd_crypt_message()` | Incorrect encryption breaks SMB3 confidentiality |
| CRY-06 | HMAC-SHA256 test vectors | `ksmbd_sign_smb2_pdu()` | Incorrect signing breaks SMB2 |
| CRY-07 | HMAC-MD5 test vectors | `ksmbd_gen_sess_key()`, `calc_ntlmv2_hash()` | Incorrect HMAC breaks NTLMv2 |
| CRY-08 | SHA-512 hash chain correctness | `ksmbd_gen_preauth_integrity_hash()` | Incorrect preauth hash breaks SMB 3.1.1 |
| CRY-09 | SHA-256 hash correctness | `ksmbd_gen_sd_hash()` | Incorrect SD hash |
| CRY-10 | DES key expansion parity | `str_to_key()` | All output bytes must have bit 0 = 0 |
| CRY-11 | GCM nonce monotonicity | `ksmbd_crypt_message()` (GCM path) | Nonce reuse breaks GCM security catastrophically |
| CRY-12 | CCM nonce birthday bound monitoring | `ksmbd_crypt_message()` (CCM path) | Warning at 2^44 messages |
| CRY-13 | AES-GMAC nonce construction from MessageId | `ksmbd_sign_smb3_pdu_gmac()` | Incorrect nonce = incorrect signature |

### Session Management Security

| ID | Test | Target Function | Risk |
|----|------|-----------------|------|
| SES-01 | Session ID prediction | `__init_smb2_session()` | Sequential IDs are predictable (known issue P1) |
| SES-02 | Session key zeroization on destroy | `ksmbd_session_destroy()` | Keys must be memzero_explicit'd |
| SES-03 | Preauth hash copied correctly | `alloc_preauth_hash()` | Wrong hash = wrong session keys |
| SES-04 | Channel signing key zeroization | `free_channel_list()` | Channel keys must be memzero_explicit'd |
| SES-05 | Passkey freed sensitively | `ksmbd_free_user()` | Uses kfree_sensitive |
| SES-06 | Refcount underflow prevention | `ksmbd_user_session_put()` | WARN_ON on refcount <= 0 |
| SES-07 | Expired session not returned by lookup_all | `ksmbd_session_lookup_all()` | Expired sessions must be rejected |
| SES-08 | Concurrent session access | All session lookup functions | Race conditions under parallel access |
| SES-09 | Session expiration timeout | `ksmbd_expire_session()` | Stale sessions must be cleaned up |
| SES-10 | Guest binding rejected | `smb2_sess_setup()` | Guest sessions must not be bindable |
| SES-11 | Binding signature verification | `smb2_sess_setup()` | Binding requests must be signed |
| SES-12 | Dialect mismatch on binding | `smb2_sess_setup()` | Different dialect must be rejected |
| SES-13 | ClientGUID mismatch on binding | `smb2_sess_setup()` | Different GUID must be rejected |
| SES-14 | Re-authentication with different credentials | `ntlm_authenticate()` | Must update sess->user |
| SES-15 | Auth failure forces reconnect | `smb2_sess_setup()` | KSMBD_USER_FLAG_DELAY_SESSION triggers reconnect |

### Negotiate Security

| ID | Test | Target Function | Risk |
|----|------|-----------------|------|
| NEG-01 | Second NEGOTIATE on established connection | `smb2_handle_negotiate()` | Must disconnect per MS-SMB2 3.3.5.3.1 |
| NEG-02 | Missing PREAUTH_INTEGRITY context for SMB 3.1.1 | `smb2_handle_negotiate()` | Must reject |
| NEG-03 | ServerGUID stability across connections | `smb2_handle_negotiate()` | Must be same for multichannel |
| NEG-04 | ServerStartTime stability | `smb2_handle_negotiate()` | Must be consistent |
| NEG-05 | Response body zeroed before use | `smb2_handle_negotiate()` | Prevents heap data leakage |
| NEG-06 | Cipher server preference order | `decode_encrypt_ctxt()` | AES-256-GCM > AES-128-GCM > AES-256-CCM > AES-128-CCM |
| NEG-07 | Signing AUTO mode | `smb2_handle_negotiate()` | Must enable signing if client advertises capability |

---

## Fuzz Targets

### FZ-01: `fuzz_decode_ntlmssp_neg_blob`
- **Input**: Arbitrary bytes as negotiate_message + blob_len
- **Target**: `ksmbd_decode_ntlmssp_neg_blob()`
- **Goal**: Find crashes, OOB reads, uninitialized memory access
- **Setup**: Requires mock ksmbd_conn with local_nls

### FZ-02: `fuzz_decode_ntlmssp_auth_blob`
- **Input**: Arbitrary bytes as authenticate_message + blob_len
- **Target**: `ksmbd_decode_ntlmssp_auth_blob()`
- **Goal**: Find crashes from malformed offset/length fields, integer overflows
- **Setup**: Requires mock ksmbd_conn + ksmbd_session with user

### FZ-03: `fuzz_build_ntlmssp_challenge_blob`
- **Input**: Varying conn->ntlmssp.client_flags, max_blob_sz values
- **Target**: `ksmbd_build_ntlmssp_challenge_blob()`
- **Goal**: Find buffer overflows in output, integer overflows in size calculations
- **Setup**: Requires mock ksmbd_conn with use_spnego, local_nls

### FZ-04: `fuzz_deassemble_neg_contexts`
- **Input**: Arbitrary bytes as smb2_negotiate_req with varying context count, offsets, lengths
- **Target**: `deassemble_neg_contexts()`
- **Goal**: Find OOB reads from malformed context structures
- **Setup**: Requires mock ksmbd_conn with preauth_info

### FZ-05: `fuzz_decode_preauth_ctxt`
- **Input**: Varying ctxt_len and pneg_ctxt content
- **Target**: `decode_preauth_ctxt()`
- **Goal**: Find boundary issues

### FZ-06: `fuzz_decode_encrypt_ctxt`
- **Input**: Varying CipherCount and Ciphers array content
- **Target**: `decode_encrypt_ctxt()`
- **Goal**: Find array over-read from large CipherCount

### FZ-07: `fuzz_decode_compress_ctxt`
- **Input**: Varying CompressionAlgorithmCount and content
- **Target**: `decode_compress_ctxt()`
- **Goal**: Find integer overflow in size computation

### FZ-08: `fuzz_decode_sign_cap_ctxt`
- **Input**: Varying SigningAlgorithmCount and content
- **Target**: `decode_sign_cap_ctxt()`
- **Goal**: Find integer overflow, array over-read

### FZ-09: `fuzz_ksmbd_crypt_message`
- **Input**: Varying iov content, nvec, enc flag, transform header fields
- **Target**: `ksmbd_crypt_message()`
- **Goal**: Find crashes in scatter-gather setup, key retrieval failures
- **Setup**: Requires full work/conn/session mock with encryption keys

### FZ-10: `fuzz_smb2_sess_setup`
- **Input**: Arbitrary smb2_sess_setup_req with varying SecurityBuffer content
- **Target**: `smb2_sess_setup()`
- **Goal**: Find crashes in the full session setup path including SPNEGO decode
- **Setup**: Requires full ksmbd_work/conn mock

### FZ-11: `fuzz_md4_shash_update`
- **Input**: Arbitrary data of varying lengths (0 to 10000 bytes)
- **Target**: `ksmbd_md4_shash_update()` + `ksmbd_md4_shash_final()`
- **Goal**: Find buffer overflows in block processing, padding logic
- **Setup**: Allocate shash_desc via crypto API

### FZ-12: `fuzz_arc4`
- **Input**: Arbitrary key (1-256 bytes) and plaintext
- **Target**: `cifs_arc4_setkey()` + `cifs_arc4_crypt()`
- **Goal**: Find crashes with edge-case key sizes, zero-length input
- **Setup**: Direct function call

### FZ-13: `fuzz_ksmbd_init_sg`
- **Input**: Varying nvec, iov with vmalloc and kmalloc-backed buffers
- **Target**: `ksmbd_init_sg()`
- **Goal**: Find scatter-gather table corruption, integer overflow in entry counting
- **Setup**: Allocate test buffers with both kmalloc and vmalloc

---

## Priority Matrix

### P0 (Must Have - Security Critical)

1. `ksmbd_decode_ntlmssp_auth_blob()` - All offset/length validation tests (SEC-01 through SEC-03)
2. `ksmbd_decode_ntlmssp_neg_blob()` - Signature and length validation
3. `ksmbd_auth_ntlmv2()` - Correct authentication and integer overflow (SEC-13)
4. `ksmbd_crypt_message()` - Encryption/decryption correctness
5. MD4 RFC 1320 test vectors (CRY-01)
6. `deassemble_neg_contexts()` - All context parsing boundary tests
7. ARC4 known-answer tests (CRY-02)
8. Session key zeroization tests (SES-02, SES-04, SES-05)
9. `ksmbd_sign_smb3_pdu()` - Known-answer vector
10. `ksmbd_build_ntlmssp_challenge_blob()` - Buffer overflow tests

### P1 (Should Have - Functional Correctness)

1. All crypto context pool tests (ksmbd_test_crypto_ctx.c)
2. All session lifecycle tests (create, register, lookup, destroy)
3. All negotiate context decode tests
4. SP800-108 KDF known-answer test (CRY-03)
5. Preauth integrity hash chain test (CRY-08)
6. User comparison timing safety (TIM-01, TIM-02)
7. Key derivation tests (smb30/smb311 signing + encryption keys)

### P2 (Nice to Have - Robustness)

1. All fuzz targets (FZ-01 through FZ-13)
2. Session expiration timeout tests
3. Concurrent session access tests
4. Crypto pool exhaustion tests
5. GMAC signing known-answer vector
6. Session ID prediction assessment (SES-01)

---

## Implementation Notes

### Test Infrastructure Requirements

1. **Module-level tests**: Most auth.c functions require crypto subsystem initialization. Tests must either:
   - Run as KUnit tests within the ksmbd module (preferred)
   - Mock the crypto context pool (complex but more isolated)

2. **Mock objects needed**:
   - `struct ksmbd_conn` with minimal fields (dialect, cipher_type, signing_algorithm, ntlmssp, local_nls, preauth_info)
   - `struct ksmbd_session` with minimal fields (sess_key, user, Preauth_HashValue, state, state_lock)
   - `struct ksmbd_work` with request/response buffers
   - `struct ksmbd_user` with name, passkey, flags

3. **Test ordering**: `ksmbd_crypto_create()` must be called before any test that uses crypto functions. Use KUnit suite init/exit callbacks.

4. **FIPS mode**: Some tests (NTLMv1, DES) must be skipped when `fips_enabled` is true. Use `KUNIT_CASE_ATTR()` with FIPS-awareness.

5. **CONFIG_SMB_INSECURE_SERVER**: NTLMv1, SMB1 signing, and DES tests only compile when this config is enabled. Use `#ifdef` guards in test files.

### Estimated Test Count

| Test File | New Tests | Priority |
|-----------|-----------|----------|
| ksmbd_test_auth.c (enhanced) | ~30 | P0/P1 |
| ksmbd_test_crypto_ctx.c (new) | ~14 | P1 |
| ksmbd_test_md4.c (new) | ~16 | P0/P1 |
| ksmbd_test_session.c (new) | ~27 | P0/P1 |
| ksmbd_test_negotiate.c (new) | ~23 | P0/P1 |
| ksmbd_test_user_session_mgmt.c (new) | ~7 | P1 |
| ksmbd_test_user_config.c (new) | ~12 | P1 |
| **Total** | **~129** | |

### Relationship to Existing smbtorture Tests

The KUnit tests proposed here are **unit-level** tests that validate individual functions in isolation. They complement the existing smbtorture-based integration tests (which test over-the-wire behavior) by:

1. Catching bugs earlier in the development cycle (compile-time rather than requiring VM setup)
2. Testing error paths that are difficult to trigger via the network
3. Providing deterministic coverage of boundary conditions
4. Enabling KASAN/KMSAN/KCSAN to detect memory safety issues in crypto paths
5. Running in seconds (vs minutes for smbtorture) as part of CI/CD
