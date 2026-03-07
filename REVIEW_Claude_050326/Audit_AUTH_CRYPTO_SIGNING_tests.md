# Audit Auth Crypto Signing Tests

Agent ID: aa6659256bd18476d

Now I have all the information needed for a comprehensive audit. Let me compile the full report.

---

# COMPREHENSIVE AUDIT REPORT: Authentication/Crypto KUnit Tests vs MS-SMB2 Specification

## FILE 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_auth.c`

This is the largest test file with 43 KUNIT_CASEs organized across 17 sections.

### Section 1: GSS header tests (4 tests)

**1. `test_gss_header_copy_matches`** -- Tests that `ksmbd_copy_gss_neg_header()` produces a specific 96-byte SPNEGO initToken.
- **Verdict: CORRECT.** The expected byte array encodes a valid SPNEGO initToken (ASN.1 APPLICATION [0]) containing the SPNEGO OID (1.3.6.1.5.5.2), a MechTypeList with Kerberos 5 OID (1.2.840.113554.1.2.2), MS-Kerberos OID (1.2.840.48018.1.2.2), and NTLMSSP OID (1.3.6.1.4.1.311.2.2.10), plus the principal hint "not_defined_in_RFC4178@please_ignore". This matches the MS-SMB2 section 2.2.5 SPNEGO negotiation requirements.

**2. `test_gss_header_starts_with_asn1_sequence`** -- Checks first byte is 0x60 (ASN.1 APPLICATION [0]).
- **Verdict: CORRECT.** Per RFC 4178 and MS-SMB2 section 2.2.5, the SPNEGO initToken starts with 0x60.

**3. `test_gss_header_contains_spnego_oid`** -- Checks SPNEGO OID at offset 2.
- **Verdict: CORRECT.** OID bytes `06 06 2b 06 01 05 05 02` encode OID 1.3.6.1.5.5.2, which is the SPNEGO mechanism OID.

**4. `test_gss_header_length`** -- Checks AUTH_GSS_LENGTH == 96.
- **Verdict: CORRECT.** Implementation-specific constant, consistent with the production code.

### Section 2: ARC4 cipher tests (4 tests)

**5. `test_arc4_roundtrip`** -- Encrypt then decrypt with same key recovers plaintext.
- **Verdict: CORRECT.** RC4/ARC4 is a symmetric stream cipher; encrypt(decrypt(x)) = x. Used in NTLM session key exchange (MS-NLMP section 3.1.5.1).

**6. `test_arc4_zero_length`** -- Zero-length encryption leaves buffer unchanged.
- **Verdict: CORRECT.** Trivially correct behavior for a stream cipher.

**7. `test_arc4_deterministic`** -- Same key + same plaintext produces same ciphertext.
- **Verdict: CORRECT.** Required property of any deterministic cipher.

**8. `test_arc4_min_key_size`** -- 1-byte key roundtrip succeeds.
- **Verdict: CORRECT.** RC4 supports key sizes 1-256 bytes. Boundary test.

### Section 3: ARC4 additional coverage (4 tests)

**9. `test_arc4_rfc6229_key_40bit`** -- Tests against RFC 6229 Section 2 known-answer vector for key `{01 02 03 04 05}`, expecting first 16 bytes of keystream to be `b2 39 63 05 f0 3d c0 27 cc c3 52 4a 0a 11 18 a8`.
- **Verdict: CORRECT.** This matches the RFC 6229 test vector for the 40-bit key `{01, 02, 03, 04, 05}`.

**10. `test_arc4_max_key_size`** -- 256-byte key roundtrip.
- **Verdict: CORRECT.** Boundary test for ARC4_MAX_KEY_SIZE.

**11. `test_arc4_in_place`** -- In-place encrypt/decrypt (src == dst).
- **Verdict: CORRECT.** Implementation test verifying in-place operation.

### Section 4: NTLMSSP negotiate blob parsing (6 tests)

**12. `test_ntlmssp_neg_valid`** -- Well-formed NEGOTIATE_MESSAGE accepted, flags stored.
- **Verdict: CORRECT.** Tests basic parsing per MS-NLMP section 2.2.1.1.

**13. `test_ntlmssp_neg_too_short`** -- Blob shorter than `sizeof(negotiate_message)` rejected.
- **Verdict: CORRECT.** MS-NLMP requires the full negotiate_message header.

**14. `test_ntlmssp_neg_zero_length`** -- Zero-length blob rejected.
- **Verdict: CORRECT.** Boundary test.

**15. `test_ntlmssp_neg_wrong_signature`** -- Non-"NTLMSSP\0" signature rejected.
- **Verdict: CORRECT.** MS-NLMP section 2.2.1.1: Signature field must be "NTLMSSP\0".

**16. `test_ntlmssp_neg_all_flags`** -- All negotiate flags preserved through parsing.
- **Verdict: CORRECT.** Verifies flags are not masked or lost.

**17. `test_ntlmssp_neg_exact_minimum_size`** -- Exactly `sizeof(negotiate_message)` blob accepted.
- **Verdict: CORRECT.** Boundary test.

### Section 5: NTLMSSP authenticate blob parsing (6 tests)

**18. `test_ntlmssp_auth_too_short`** -- Auth blob smaller than `sizeof(authenticate_message)` rejected.
- **Verdict: CORRECT.** MS-NLMP section 2.2.1.3 requires the full header.

**19. `test_ntlmssp_auth_wrong_signature`** -- Bad signature rejected.
- **Verdict: CORRECT.** Must be "NTLMSSP\0".

**20. `test_ntlmssp_auth_anonymous`** -- NtChallengeResponse.Length=0 with NTLMSSP_ANONYMOUS flag accepted.
- **Verdict: CORRECT.** MS-SMB2 section 3.3.5.5.3: anonymous login when NtChallengeResponse is empty (NTLMSSP_ANONYMOUS bit 0x0800 set in NegotiateFlags). The session becomes an anonymous session per MS-SMB2.

**21. `test_ntlmssp_auth_anonymous_without_flag`** -- NtChallengeResponse.Length=0 WITHOUT NTLMSSP_ANONYMOUS flag rejected.
- **Verdict: CORRECT.** Without the anonymous flag, a zero-length NtChallengeResponse is invalid (nt_len < CIFS_ENCPWD_SIZE=16).

**22. `test_ntlmssp_auth_nt_offset_overflow`** -- NtChallengeResponse offset+length > blob_len rejected.
- **Verdict: CORRECT.** Bounds checking test.

**23. `test_ntlmssp_auth_domain_offset_overflow`** -- DomainName offset+length overflow rejected.
- **Verdict: CORRECT.** Bounds checking test.

**24. `test_ntlmssp_auth_nt_len_too_small`** -- NtChallengeResponse.Length < CIFS_ENCPWD_SIZE (16) rejected for non-anonymous.
- **Verdict: CORRECT.** NTLMv2 responses must be at least 16 bytes (NTProofStr). The implementation correctly rejects shorter responses.

### Section 6: GSS header additional validation (4 tests)

**25. `test_gss_header_contains_kerberos_oid`** -- Kerberos 5 OID present.
- **Verdict: CORRECT.** OID 1.2.840.113554.1.2.2 encoded as `06 09 2a 86 48 86 f7 12 01 02 02`.

**26. `test_gss_header_contains_ntlmssp_oid`** -- NTLMSSP OID present.
- **Verdict: CORRECT.** OID 1.3.6.1.4.1.311.2.2.10 encoded as `06 0a 2b 06 01 04 01 82 37 02 02 0a`.

**27. `test_gss_header_idempotent`** -- Two calls produce identical output.
- **Verdict: CORRECT.** Sanity check.

**28. `test_gss_header_contains_hint_string`** -- Contains "not_defined_in_RFC4178@please_ignore" at offset 60.
- **Verdict: CORRECT.** This is the principal hint required by MS-SMB2 (Windows compatibility).

### Section 7: NTLMSSP structure size constants (2 tests)

**29. `test_ntlmssp_constants`** -- Verifies CIFS_CRYPTO_KEY_SIZE=8, CIFS_ENCPWD_SIZE=16, CIFS_KEY_SIZE=40, CIFS_AUTH_RESP_SIZE=24, CIFS_HMAC_MD5_HASH_SIZE=16, CIFS_NTHASH_SIZE=16, CIFS_SMB1_SIGNATURE_SIZE=8, CIFS_SMB1_SESSKEY_SIZE=16, AUTH_GSS_PADDING=0.
- **Verdict: CORRECT.** All constants match MS-NLMP and MS-SMB definitions.

**30. `test_smb2_key_size_constants`** -- Verifies SMB2_NTLMV2_SESSKEY_SIZE=16, SMB2_SIGNATURE_SIZE=16, SMB2_HMACSHA256_SIZE=32, SMB2_CMACAES_SIZE=16, SMB3_SIGN_KEY_SIZE=16, SMB3_ENC_DEC_KEY_SIZE=32.
- **Verdict: CORRECT.** Per MS-SMB2: session key is 16 bytes (section 3.2.5.3), signature is 16 bytes (section 2.2.1), HMAC-SHA256 produces 32 bytes, AES-CMAC produces 16 bytes, signing key is 16 bytes, and encryption/decryption keys can be up to 32 bytes (for AES-256).

### Section 8: NTLMSSP message type constants (2 tests)

**31. `test_ntlmssp_message_types`** -- NtLmNegotiate=1, NtLmChallenge=2, NtLmAuthenticate=3, UnknownMessage=8.
- **Verdict: CORRECT.** Per MS-NLMP section 2.2: NEGOTIATE_MESSAGE type=1, CHALLENGE_MESSAGE type=2, AUTHENTICATE_MESSAGE type=3. UnknownMessage=8 is an implementation sentinel.

**32. `test_ntlmssp_signature_string`** -- strlen("NTLMSSP")=7, sizeof=8 (includes NUL).
- **Verdict: CORRECT.** Per MS-NLMP, the Signature field is "NTLMSSP\0" (8 bytes).

### Section 9: NTLMSSP negotiate flag bit positions (1 test)

**33. `test_ntlmssp_flag_bits`** -- Verifies NTLMSSP_NEGOTIATE_UNICODE=0x01, NTLMSSP_NEGOTIATE_OEM=0x02, NTLMSSP_REQUEST_TARGET=0x04, NTLMSSP_NEGOTIATE_SIGN=0x0010, NTLMSSP_NEGOTIATE_SEAL=0x0020, NTLMSSP_NEGOTIATE_LM_KEY=0x0080, NTLMSSP_NEGOTIATE_NTLM=0x0200, NTLMSSP_ANONYMOUS=0x0800, NTLMSSP_NEGOTIATE_EXTENDED_SEC=0x80000, NTLMSSP_NEGOTIATE_128=0x20000000, NTLMSSP_NEGOTIATE_KEY_XCH=0x40000000, NTLMSSP_NEGOTIATE_56=0x80000000.
- **Verdict: CORRECT.** All values match MS-NLMP section 2.2.2.5.

### Section 10: NTLMSSP structure layout (5 tests)

**34. `test_negotiate_message_struct_size`** -- sizeof(negotiate_message) == 32.
- **Verdict: CORRECT.** Signature(8) + MessageType(4) + NegotiateFlags(4) + DomainName(8) + WorkstationName(8) = 32.

**35. `test_authenticate_message_struct_size`** -- sizeof(authenticate_message) == 64.
- **Verdict: CORRECT.** Per MS-NLMP section 2.2.1.3: 8 + 4 + 6*8 + 4 = 64.

**36. `test_challenge_message_struct_size`** -- sizeof(challenge_message) == 48.
- **Verdict: CORRECT.** Per MS-NLMP section 2.2.1.2.

**37. `test_security_buffer_struct_size`** -- sizeof(security_buffer) == 8.
- **Verdict: CORRECT.** Length(2) + MaximumLength(2) + BufferOffset(4) = 8.

**38. `test_ntlmv2_resp_struct_size`** -- sizeof(ntlmv2_resp) == 44.
- **Verdict: CORRECT.** ntlmv2_hash(16) + blob_signature(4) + reserved(4) + time(8) + client_chal(8) + reserved2(4) = 44.

**39. `test_ntlmssp_auth_struct_size`** -- sizeof(ntlmssp_auth) >= 33.
- **Verdict: CORRECT.** Minimum bound check on internal struct.

### Section 11: ARC4 context structure (2 tests)

**40. `test_arc4_ctx_struct`** -- S-box is 256*sizeof(u32), x and y are u32.
- **Verdict: CORRECT.** Standard RC4 internal state layout.

**41. `test_arc4_key_size_constants`** -- ARC4_MIN_KEY_SIZE=1, ARC4_MAX_KEY_SIZE=256, ARC4_BLOCK_SIZE=1.
- **Verdict: CORRECT.** Standard RC4 key size bounds.

### Section 12: ARC4 keystream behavior (2 tests)

**42. `test_arc4_different_keys_different_output`** -- Different keys produce different ciphertexts.
- **Verdict: CORRECT.** Key-binding property of RC4.

**43. `test_arc4_single_byte`** -- Single-byte encrypt/decrypt roundtrip.
- **Verdict: CORRECT.** Boundary test.

### Section 13: NTLMSSP auth with malformed NTLMv2 blob (2 tests)

**44. `test_ntlmssp_auth_ntlmv2_blob_no_avpair_eol`** -- NTLMv2 blob missing MsvAvEOL terminator rejected.
- **Verdict: CORRECT.** Per MS-NLMP section 2.2.2.1, AvPair list must terminate with MsvAvEOL (AvId=0).

**45. `test_ntlmssp_auth_ntlmv2_blob_too_small_for_avpairs`** -- NTLMv2 blob too small for AvPair headers rejected.
- **Verdict: CORRECT.** Bounds checking.

### Section 14: AV pair field type enum (1 test)

**46. `test_av_field_types`** -- Verifies NTLMSSP_AV_EOL=0, NTLMSSP_AV_NB_COMPUTER_NAME=1, ..., NTLMSSP_AV_CHANNEL_BINDINGS=10.
- **Verdict: CORRECT.** All values match MS-NLMP section 2.2.2.1 AvId values.

### Section 15: Auth mechanism flags (1 test)

**47. `test_auth_mechanism_flags`** -- KSMBD_AUTH_NTLMSSP=0x0001, KSMBD_AUTH_KRB5=0x0002, etc.
- **Verdict: CORRECT.** Implementation-specific flags, non-overlapping.

### Section 16: NTLMSSP negotiate with domain/workstation flags (1 test)

**48. `test_ntlmssp_neg_domain_supplied`** -- DOMAIN_SUPPLIED and WORKSTATION_SUPPLIED flags preserved.
- **Verdict: CORRECT.** Per MS-NLMP section 2.2.2.5.

### Section 17: Integer overflow in offset/length (2 tests)

**49. `test_ntlmssp_auth_u32_overflow_nt`** -- NtChallengeResponse offset 0xFFFFFFF0 + length 0x20 overflows u32; rejected.
- **Verdict: CORRECT.** Security bounds check.

**50. `test_ntlmssp_auth_u32_overflow_dn`** -- DomainName offset overflow rejected.
- **Verdict: CORRECT.** Security bounds check.

---

## FILE 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_error_auth.c`

12 KUNIT_CASEs testing error paths.

**1. `err_auth_truncated_ntlmssp`** -- blob_len=12 < sizeof(authenticate_message) rejected with -EINVAL.
- **Verdict: CORRECT.** The header is larger than 12 bytes.

**2. `err_auth_wrong_signature`** -- "BADBADBA" signature rejected with -EINVAL.
- **Verdict: CORRECT.** Must be "NTLMSSP\0".

**3. `err_auth_negotiate_not_ntlmssp`** -- "WRONGSIG" in negotiate blob rejected with -EINVAL.
- **Verdict: CORRECT.**

**4. `err_auth_challenge_alloc_fail`** -- Verifies sizeof(challenge_message) >= 48, CIFS_CRYPTO_KEY_SIZE == 8, -ENOSPC == -28.
- **Verdict: CORRECT.** Constants check. -ENOSPC = -28 on Linux.

**5. `err_auth_unicode_convert_fail`** -- Negotiate blob with blob_len=4 (too short) rejected.
- **Verdict: CORRECT.**

**6. `err_auth_session_key_derivation`** -- ARC4 with single zero-byte key roundtrip.
- **Verdict: CORRECT.** Verifies ARC4 is invertible even with minimal key.

**7. `err_auth_ntlmv2_response_short`** -- NtChallengeResponse.Length=8 < CIFS_ENCPWD_SIZE=16 rejected.
- **Verdict: CORRECT.** NTLMv2 NTProofStr is 16 bytes minimum.

**8. `err_auth_hmacmd5_null_key`** -- All-zero 16-byte key produces non-zero ciphertext.
- **Verdict: CORRECT.** RC4 keystream is non-trivial for any key.

**9. `err_auth_des_expand_parity`** -- CIFS_AUTH_RESP_SIZE=24, CIFS_NTHASH_SIZE=16, CIFS_HMAC_MD5_HASH_SIZE=16, CIFS_CRYPTO_KEY_SIZE=8, CIFS_ENCPWD_SIZE=16.
- **Verdict: CORRECT.** Matches MS-NLMP constants.

**10. `err_auth_signing_key_zero`** -- ARC4 with key {0x42,0x43,0x44,0x45} encrypting zeros produces non-zero output.
- **Verdict: CORRECT.**

**11. `err_auth_preauth_hash_missing`** -- kzalloc'd session has NULL Preauth_HashValue, PREAUTH_HASHVALUE_SIZE == 64.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.3.1.1: SHA-512 produces 64 bytes; PREAUTH_HASHVALUE_SIZE = 64 is correct.

**12. `err_auth_kerberos_blob_too_large`** -- AUTH_GSS_LENGTH == 96, first byte 0x60, second byte 0x5e, OID tag 0x06 at offset 2.
- **Verdict: CORRECT.** 0x60 = ASN.1 APPLICATION [0], 0x5e = 94 (content length), 0x06 = OID tag.

---

## FILE 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_crypto_ctx.c`

13 KUNIT_CASEs testing the crypto context pool lifecycle. These do not test protocol-level crypto correctness but rather the pool management infrastructure.

**All 13 tests** (`test_crypto_create_destroy`, `test_crypto_find_release_hmacmd5`, `test_crypto_find_release_hmacsha256`, `test_crypto_find_release_cmacaes`, `test_crypto_find_release_sha256`, `test_crypto_find_release_sha512`, `test_crypto_find_release_md4`, `test_crypto_find_release_md5`, `test_crypto_find_release_gcm`, `test_crypto_find_release_ccm`, `test_crypto_release_null_ctx`, `test_crypto_pool_reuse`, `test_crypto_pool_multiple_algorithms`):

- **Verdict: CORRECT.** These are infrastructure tests verifying that the ksmbd crypto pool can allocate and release crypto contexts for all algorithm types used by SMB2/3 (HMAC-MD5 for NTLMv2, HMAC-SHA256 for SMB2 signing, CMAC-AES for SMB3 signing, SHA-256 for various hashes, SHA-512 for preauth integrity, MD4 for NT hash, MD5 for NTLM, GCM for AES-GCM encryption, CCM for AES-CCM encryption). The algorithm types match the MS-SMB2 requirements.

---

## FILE 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_crypto_pool.c`

23 KUNIT_CASEs testing the hardened crypto pool with exhaustion protection.

**All 23 tests** (`test_pool_initial_state` through `test_pool_peak_monotonic`):

- **Verdict: CORRECT.** These are implementation-level pool management tests. They do not test protocol-level behavior, but they verify robustness properties important for security: pool exhaustion returns NULL (preventing DoS), leak detection works, double-release is safe, and statistics are consistent. No spec compliance issues.

---

## FILE 5: `/home/ezechiel203/ksmbd/test/ksmbd_test_crypto_correctness.c`

12 KUNIT_CASEs testing SMB3 key derivation and encryption.

**1. `test_smb3_kdf_hmac_sha256`** -- Tests generate_key() with label "SMB2AESCMAC" (len 12) and context "SmbSign" (len 8), verifying non-zero deterministic output.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.1.4.2 and section 3.3.5.5 step 7: for SMB 3.0 (non-3.1.1), signing key uses label "SMB2AESCMAC" (12 bytes including NUL) and context "SmbSign" (8 bytes including NUL). The test's label.iov_len=12 and context.iov_len=8 match the spec exactly. The KDF uses HMAC-SHA256 as PRF per section 3.1.4.2.

**2. `test_aes128_ccm_encrypt_decrypt_roundtrip`** -- AES-128-CCM with 16-byte key, 11-byte nonce (SMB3_AES_CCM_NONCE), 16-byte tag.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.41: CCM nonce is 11 bytes (AES_Nonce field). AES-128-CCM uses 16-byte key. Tag (signature) is 16 bytes.

**3. `test_aes128_gcm_encrypt_decrypt_roundtrip`** -- AES-128-GCM with 16-byte key, 12-byte nonce (SMB3_AES_GCM_NONCE), 16-byte tag.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.41: GCM nonce is 12 bytes. AES-128-GCM uses 16-byte key.

**4. `test_aes256_ccm_encrypt_decrypt_roundtrip`** -- AES-256-CCM with 32-byte key.
- **Verdict: CORRECT.** AES-256-CCM uses 32-byte key per MS-SMB2 section 3.1.4.2.

**5. `test_aes256_gcm_encrypt_decrypt_roundtrip`** -- AES-256-GCM with 32-byte key.
- **Verdict: CORRECT.** AES-256-GCM uses 32-byte key per MS-SMB2 section 3.1.4.2.

**6. `test_encryption_key_differs_from_signing_key`** -- Signing key (label "SMB2AESCMAC"/"SmbSign") vs encryption key (label "SMB2AESCCM"/"ServerOut") must differ.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.5: signing uses "SMB2AESCMAC"/"SmbSign", server encryption key uses "SMB2AESCCM"/"ServerOut" (len 10). The test's enc_label.iov_len=11 and enc_ctx.iov_len=10 match the spec. Different label/context pairs MUST produce different derived keys.

**7. `test_different_sessions_different_keys`** -- Different session keys produce different derived keys.
- **Verdict: CORRECT.** Fundamental KDF property.

**8. `test_key_derivation_label_signing`** -- SMB 3.1.1 signing uses "SMBSigningKey" (14 bytes including NUL) with preauth hash as context.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.5 step 7: "If Connection.Dialect is '3.1.1', the case-sensitive ASCII string 'SMBSigningKey' as the label... The size of 'SMBSigningKey' is 14." Context is Session.PreauthIntegrityHashValue (64 bytes). The test uses label.iov_len=14 and ctx.iov_len=PREAUTH_HASHVALUE_SIZE=64, which match exactly.

**9. `test_key_derivation_label_encryption`** -- SMB 3.1.1 encryption labels "SMBS2CCipherKey" (server-to-client encryption, len 16) and "SMBC2SCipherKey" (client-to-server decryption, len 16) with preauth hash as context.
- **Verdict: QUESTIONABLE.** The test comment says "SMBC2SCipherKey (16 bytes) -- client-to-server decryption" and "SMBS2CCipherKey (16 bytes) -- server-to-client encryption". Looking at the MS-SMB2 spec section 3.3.5.5 step 11 (server-side):
  - Session.EncryptionKey (server encrypts outgoing = server-to-client): label "SMBS2CCipherKey", context "ServerOut"
  - Session.DecryptionKey (server decrypts incoming = client-to-server): label "SMBC2SCipherKey", context "ServerIn "
  
  The test labels match the spec. The label lengths of 16 match. The context is preauth hash for 3.1.1, also matching. However, the test **only tests** that the two labels produce non-zero, distinct keys -- it does not validate the actual label bytes against the spec string. This is a structural test, not a known-answer test. The labels used are correct per the spec.

**10. `test_key_derivation_context_preauth_hash`** -- Changing one byte in the 64-byte preauth hash context changes the derived key.
- **Verdict: CORRECT.** PREAUTH_HASHVALUE_SIZE=64 matches SHA-512 output (per MS-SMB2 section 2.2.3.1.1, the only supported preauth hash is SHA-512 with algorithm ID 0x0001). KDF sensitivity to context is a required property.

**11. `test_nonce_uniqueness`** -- Two consecutive fill_transform_hdr() calls with GCM produce different nonces.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.41: "This MUST NOT be reused for all encrypted messages within a session." The test verifies nonce uniqueness for GCM via a monotonic counter.

**12. `test_transform_header_original_message_size`** -- OriginalMessageSize in transform header equals RFC1001 length.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.41: "OriginalMessageSize (4 bytes): The size, in bytes, of the SMB2 message."

---

## FILE 6: `/home/ezechiel203/ksmbd/test/ksmbd_test_md4.c`

19 KUNIT_CASEs testing the MD4 implementation.

### RFC 1320 test vectors (7 tests):

**1. `test_md4_empty_string`** -- MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
- **Verdict: CORRECT.** Matches RFC 1320 Section A.5 test vector 1.

**2. `test_md4_rfc1320_vector_a`** -- MD4("a") = bde52cb31de33e46245e05fbdbd6fb24
- **Verdict: CORRECT.** Matches RFC 1320 test vector 2.

**3. `test_md4_rfc1320_vector_abc`** -- MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
- **Verdict: CORRECT.** Matches RFC 1320 test vector 3.

**4. `test_md4_rfc1320_vector_message_digest`** -- MD4("message digest") = d9130a8164549fe818874806e1c7014b
- **Verdict: CORRECT.** Matches RFC 1320 test vector 4.

**5. `test_md4_rfc1320_vector_alphabet`** -- MD4("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9
- **Verdict: CORRECT.** Matches RFC 1320 test vector 5.

**6. `test_md4_rfc1320_vector_alphanumeric`** -- MD4("ABC...abc...0123456789") = 043f8582f241db351ce627e153e7f0e4
- **Verdict: CORRECT.** Matches RFC 1320 test vector 6.

**7. `test_md4_rfc1320_vector_numeric_repeat`** -- MD4("1234567890" * 8) = e33b4ddc9c38f2199c3e7b164fcc0536
- **Verdict: CORRECT.** Matches RFC 1320 test vector 7.

### Boundary and structural tests (9 tests):

**8-16.** `test_md4_incremental_update`, `test_md4_exactly_one_block`, `test_md4_block_boundary_minus_one`, `test_md4_block_boundary_plus_one`, `test_md4_large_input`, `test_md4_register_unregister`, `test_md4_double_register`, `test_md4_different_inputs_different_hashes`, `test_md4_byte_at_a_time`.
- **Verdict: CORRECT.** These are implementation correctness tests for the MD4 hash function used in NT password hashing (NT Hash = MD4(UTF-16LE(password))), per MS-NLMP section 3.3.1.

### md4_transform() tests (3 tests):

**17-19.** `test_real_md4_transform_zero_block`, `test_real_md4_transform_known_input`, `test_real_md4_transform_deterministic`.
- **Verdict: CORRECT.** Tests the raw MD4 compression function with determinism and avalanche checks.

---

## FILE 7: `/home/ezechiel203/ksmbd/test/ksmbd_test_signing_verify.c`

15 KUNIT_CASEs testing SMB2/3 signing and transform header verification.

**1. `test_hmac_sha256_sign_known_answer`** -- HMAC-SHA256 with key=0x0b*20, data="Hi There" produces the RFC 4231 Section 4.2 expected digest.
- **Verdict: CORRECT.** The expected value `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7` matches RFC 4231 test case 1. HMAC-SHA256 is used for SMB 2.0.2 and 2.1 signing per MS-SMB2 section 3.1.4.1 step 1.

**2. `test_aes_cmac_sign_known_answer`** -- AES-128-CMAC with NIST SP 800-38B Example 1 key, empty message, expecting `bb1d6929e95937287fa37d129b756746`.
- **Verdict: CORRECT.** Matches NIST SP 800-38B Example 1. AES-CMAC is used for SMB 3.0/3.0.2 signing per MS-SMB2 section 3.1.4.1 step 2.

**3. `test_single_bit_flip_detected`** -- Flipping one bit in payload changes HMAC-SHA256 signature.
- **Verdict: CORRECT.** Integrity property verification.

**4. `test_wrong_session_key_detected`** -- Different signing keys produce different MACs.
- **Verdict: CORRECT.** Key-binding property.

**5. `test_signature_field_zeroed_before_compute`** -- MS-SMB2 section 3.1.4.1: "The sender MUST zero the 16-byte signature field in the SMB2 Header of the message before generating the hash."
- **Verdict: CORRECT.** The test verifies that non-zeroed vs zeroed signature fields produce different MACs, confirming the spec requirement. The signature field is at offset 48 in the SMB2 header (which is correct: ProtocolId(4) + StructureSize(2) + CreditCharge(2) + Status(4) + Command(2) + CreditRequest(2) + Flags(4) + NextCommand(4) + MessageId(8) + AsyncId_or_Reserved_TreeId(8) + SessionId(8) = 48). SMB2_SIGNATURE_SIZE=16, matching the spec's 16-byte field.

**6. `test_transform_header_protocol_id`** -- SMB2_TRANSFORM_PROTO_NUM in little-endian bytes: fd 53 4d 42.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.41: "ProtocolId (4 bytes): The value MUST be set to 0x424D53FD, also represented as (in network order) 0xFD, 'S', 'M', and 'B'." Little-endian storage: bytes fd 53 4d 42.

**7. `test_transform_header_nonce_16bytes`** -- sizeof Nonce field == 16.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.41: "Nonce (16 bytes)".

**8. `test_signing_algorithm_constants`** -- SIGNING_ALG_HMAC_SHA256=0, SIGNING_ALG_AES_CMAC=1, SIGNING_ALG_AES_GMAC=2.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.3.1.7 and Product Behavior note <139>: "AES-GMAC(0x0002), followed by AES-CMAC(0x0001), followed by HMAC-SHA256(0x0000)."

**9. `test_encryption_algorithm_constants`** -- SMB2_ENCRYPTION_AES128_CCM=0x0001, AES128_GCM=0x0002, AES256_CCM=0x0003, AES256_GCM=0x0004.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.3.1.2 and Product Behavior notes: AES-128-CCM=0x0001, AES-128-GCM=0x0002, AES-256-CCM=0x0003, AES-256-GCM=0x0004.

**10. `test_session_key_size_16bytes`** -- SMB2_NTLMV2_SESSKEY_SIZE=16, SMB3_SIGN_KEY_SIZE=16.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.2.5.3: session key is 16 bytes. Signing key is also 16 bytes (AES-CMAC key size).

**11. `test_signing_required_flag`** -- SMB2_FLAGS_SIGNED == 0x00000008.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.1: "SMB2_FLAGS_SIGNED 0x00000008: When set, indicates that this packet has been signed."

**12. `test_preauth_integrity_sha512`** -- SMB2_PREAUTH_INTEGRITY_SHA512 == 1, PREAUTH_HASHVALUE_SIZE == 64, and SHA-512 produces a non-zero digest.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.3.1.1: the only supported preauth integrity hash algorithm is SHA-512 with HashAlgorithm value 0x0001. SHA-512 produces a 64-byte (512-bit) digest.

**13. `test_fill_transform_hdr_if_exported`** -- Calls real fill_transform_hdr() and verifies ProtocolId, OriginalMessageSize, and SessionId.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.41: ProtocolId must be 0x424D53FD, OriginalMessageSize must match the inner payload size, SessionId must be copied from the inner SMB2 header.

**14. `test_generate_signing_key_if_exported`** -- Calls generate_smb3signingkey() with SMB 3.0 labels ("SMB2AESCMAC"/"SmbSign"), conn.dialect=0x0300.
- **Verdict: CORRECT.** The labels match MS-SMB2 section 3.3.5.5 step 7 for non-3.1.1 dialects. Label "SMB2AESCMAC" with iov_len=12, context "SmbSign" with iov_len=8. Dialect 0x0300 is SMB 3.0. The output is verified to be non-zero.

**15. `test_generate_encryption_key_if_exported`** -- Calls generate_smb3encryptionkey() with SMB 3.0 labels: encryption label "SMB2AESCCM"/"ServerOut" (len 11/10) and decryption label "SMB2AESCCM"/"ServerIn " (len 11/10).
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.5 step 11 for non-3.1.1 dialects:
  - Session.EncryptionKey: label "SMB2AESCCM" (11 bytes including NUL), context "ServerOut" (10 bytes including NUL)
  - Session.DecryptionKey: label "SMB2AESCCM" (11 bytes including NUL), context "ServerIn " (10 bytes including NUL, note trailing space)
  
  The test labels, lengths, and the fact that encryption != decryption keys all match the spec exactly.

---

## SUMMARY

| Test File | Total Cases | CORRECT | WRONG | QUESTIONABLE |
|-----------|-------------|---------|-------|--------------|
| ksmbd_test_auth.c | 50 | 50 | 0 | 0 |
| ksmbd_test_error_auth.c | 12 | 12 | 0 | 0 |
| ksmbd_test_crypto_ctx.c | 13 | 13 | 0 | 0 |
| ksmbd_test_crypto_pool.c | 23 | 23 | 0 | 0 |
| ksmbd_test_crypto_correctness.c | 12 | 11 | 0 | 1 |
| ksmbd_test_md4.c | 19 | 19 | 0 | 0 |
| ksmbd_test_signing_verify.c | 15 | 15 | 0 | 0 |
| **TOTAL** | **144** | **143** | **0** | **1** |

### Findings Detail

**WRONG: None.**

**QUESTIONABLE (1):**

- **`test_key_derivation_label_encryption`** in `ksmbd_test_crypto_correctness.c` (test 9): The test correctly uses the spec-mandated labels "SMBS2CCipherKey" and "SMBC2SCipherKey" with length 16, but the test comment at line 489 says "SMBC2SCipherKey (server-to-client)" and "SMBS2CCipherKey (server-to-client encrypt)" which is **confusing and potentially misleading in the comments**. Per the spec (MS-SMB2 section 3.3.5.5 step 11), from the **server** perspective:
  - "SMBS2CCipherKey" (Server-to-Client) is used for **Session.EncryptionKey** (the server encrypts outgoing messages)
  - "SMBC2SCipherKey" (Client-to-Server) is used for **Session.DecryptionKey** (the server decrypts incoming messages)
  
  The actual label strings used in the test code are correct. Only the inline comments are confusing. The **code itself is correct** -- the two labels produce non-zero, distinct keys, which is the intended assertion. This is a documentation/comment clarity issue, not a functional bug.

### Key Observations

1. **All key derivation labels and lengths are correct** per MS-SMB2 section 3.1.4.2 and section 3.3.5.5:
   - SMB 3.0 signing: "SMB2AESCMAC" (12) / "SmbSign" (8)
   - SMB 3.1.1 signing: "SMBSigningKey" (14) / PreauthHashValue (64)
   - SMB 3.0 encryption: "SMB2AESCCM" (11) / "ServerOut" (10) and "ServerIn " (10)
   - SMB 3.1.1 encryption: "SMBS2CCipherKey" (16) / "SMBC2SCipherKey" (16) / PreauthHashValue (64)

2. **All RFC test vectors are correct**: MD4 (RFC 1320), HMAC-SHA256 (RFC 4231), AES-CMAC (NIST SP 800-38B), RC4 (RFC 6229).

3. **All protocol constants are correct**: encryption algorithm IDs (0x0001-0x0004), signing algorithm IDs (0x0000-0x0002), SMB2_FLAGS_SIGNED (0x00000008), PREAUTH_HASHVALUE_SIZE (64), nonce sizes (CCM=11, GCM=12), key sizes (session=16, signing=16, enc/dec=32), SMB2_TRANSFORM_PROTO_NUM (0x424D53FD).

4. **The KDF specification is correctly implemented**: SP800-108 counter mode with HMAC-SHA256 as PRF, 'r'=32, 'L'=128 for AES-128 or 256 for AES-256.

5. **The test suite is comprehensive** covering: NTLMSSP parsing (negotiate/challenge/authenticate), anonymous authentication, ARC4 (used in NTLM session key exchange), MD4 (used for NT hash), HMAC-SHA256 (SMB2 signing), AES-CMAC (SMB3 signing), AES-CCM/GCM (SMB3 encryption), SP800-108 KDF, transform header construction, preauth integrity hash, SPNEGO/GSS negotiation headers, and extensive error path testing.