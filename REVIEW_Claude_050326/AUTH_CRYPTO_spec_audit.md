# Auth Crypto Spec Audit

Agent ID: acb67f8ade3a44403

This is implementation-specific. It's used internally as a buffer size. This is fine.

Now I have a comprehensive understanding of all the tests. Let me compile my findings.

The key question is: are there any tests whose **expected outcomes** contradict the MS-SMB2 specification?

Let me do one more check -- the `SMB2_HMACSHA256_SIZE = 32`. HMAC-SHA256 produces 32 bytes. The spec uses HMAC-SHA256 for SMB 2.0.2 and 2.1 signing. The signature field is 16 bytes, and per the spec (section 3.1.4.1 line 10451): the HMAC-SHA256 is computed and then only the first 16 bytes are stored in the Signature field. But the test just checks the constant = 32, which is the full HMAC-SHA256 output size. This is correct as a constant -- the implementation truncates to 16 bytes for the signature field.

Let me also verify `SMB2_CMACAES_SIZE = 16`. AES-CMAC produces 16 bytes. Correct.

Now, let me re-examine one thing carefully -- the test_key_derivation_label_encryption test in crypto_correctness.c. The comment on line 489 says:
> SMB 3.1.1 uses "SMBC2SCipherKey" (server-to-client) and "SMBS2CCipherKey" (server-to-client encrypt)

But that comment is misleading. Let me look more carefully:

Line 517-519 of crypto_correctness.c:
```
"SMBC2SCipherKey" (16 bytes) — client-to-server decryption
"SMBS2CCipherKey" (16 bytes) — server-to-client encryption
```

Actually, looking at the spec from the CLIENT perspective (section 3.2.5.3):
- Client's EncryptionKey (for encrypting client-to-server): uses "SMBC2SCipherKey" 
- Client's DecryptionKey (for decrypting server-to-client): uses "SMBS2CCipherKey"

And from the SERVER perspective (section 3.3.5.5):
- Server's EncryptionKey (for encrypting server-to-client): uses "SMBS2CCipherKey"
- Server's DecryptionKey (for decrypting client-to-server): uses "SMBC2SCipherKey"

So:
- "SMBC2SCipherKey" = Client-to-Server cipher key = used by client for encryption, server for decryption
- "SMBS2CCipherKey" = Server-to-Client cipher key = used by server for encryption, client for decryption

The test comments say "client-to-server decryption" and "server-to-client encryption" which is a bit confusing in its wording but the _code_ assignments (label_enc = "SMBS2CCipherKey" for server-side encryption, label_dec = "SMBC2SCipherKey" for server-side decryption) are CORRECT.

The comments are somewhat misleading but this is a comment issue, not a test correctness issue.

Now let me also re-examine one subtle thing: The `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` flag is used in the test at line 413 (`test_ntlmssp_neg_all_flags`) but its value is not explicitly checked. This is fine.

Let me check whether there's any issue with the SMB2 signing constant 0x00000008 for SMB2_FLAGS_SIGNED. The spec at line 2190-2191 confirms: "SMB2_FLAGS_SIGNED 0x00000008". Correct.

Now, let me look at one more thing: `SMB3_ENC_DEC_KEY_SIZE = 32`. Let me verify this makes sense. The spec says the 'L' value can be 128 or 256 depending on the cipher. So the maximum key size is 32 bytes (256 bits for AES-256). Having the buffer be 32 bytes makes sense as a maximum. The test just checks the constant value, which is correct.

Let me do a final review to check for any WRONG or QUESTIONABLE tests.

One thing to double check: the `test_ntlmssp_auth_nt_len_too_small` test says CIFS_ENCPWD_SIZE = 16 and an NtChallengeResponse length of 8 (< 16) should be rejected. Let me think about whether this is spec-compliant. The MS-NLMP spec says the NtChallengeResponse for NTLMv2 is at least 16 + 28 = 44 bytes minimum (NTProofStr + ClientChallenge). For NTLMv1 it's 24 bytes. In any case, 8 bytes would be too small for any valid response. The implementation's check at CIFS_ENCPWD_SIZE = 16 is a reasonable lower bound. This is implementation-specific behavior but doesn't contradict the spec.

Let me also check one thing about the NTLMSSP_NEGOTIATE_EXTENDED_SEC value. The test says 0x80000 = bit 19. Per MS-NLMP section 2.2.2.5, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is bit 19, which is 0x00080000. The test uses 0x80000 = 0x00080000. Correct.

Let me also look into whether the `fill_transform_hdr` test's expected OriginalMessageSize is correct. The test sets the RFC1001 length to 64, and expects OriginalMessageSize = 64. Per the spec (line 10503): "OriginalMessageSize is set to the size of the SMB2 message being sent." The RFC1001 length field represents the length of the SMB2 message following the 4-byte length prefix. So OriginalMessageSize should equal the RFC1001 length value. The test assertion is correct.

Now I'm confident in my analysis. Let me compile the full audit report.

---

Here is my complete audit report:

## Audit Summary

### Files Audited

The user requested six test files. Two of the exact filenames exist; the other four were mapped to their closest counterparts in the repository:

| Requested File | Actual File |
|---|---|
| `test/ksmbd_test_auth.c` | `/home/ezechiel203/ksmbd/test/ksmbd_test_auth.c` (exists) |
| `test/ksmbd_test_crypto.c` | `/home/ezechiel203/ksmbd/test/ksmbd_test_crypto_correctness.c` (closest match) |
| `test/ksmbd_test_signing.c` | `/home/ezechiel203/ksmbd/test/ksmbd_test_signing_verify.c` (closest match) |
| `test/ksmbd_test_preauth.c` | Does not exist; preauth tests are embedded in `ksmbd_test_signing_verify.c` (test #12) |
| `test/ksmbd_test_encryption.c` | Does not exist; encryption tests are in `ksmbd_test_crypto_correctness.c` and `ksmbd_test_crypto_ctx.c` |
| `test/ksmbd_test_md4.c` | `/home/ezechiel203/ksmbd/test/ksmbd_test_md4.c` (exists) |

### Total Tests Audited

| File | Test Count |
|---|---|
| `ksmbd_test_auth.c` | 49 tests (4 GSS + 4 ARC4 + 5 ARC4 extended + 7 NTLMSSP neg + 7 NTLMSSP auth + 4 GSS extended + 2 constants + 3 message types + 1 flag bits + 5 struct sizes + 2 ARC4 structure + 1 AV pair types + 1 auth mechanism flags + 1 domain supplied + 2 overflow + 5 str_to_key [conditional] + 2 sg + 2 init_sg) |
| `ksmbd_test_crypto_correctness.c` | 12 tests |
| `ksmbd_test_signing_verify.c` | 15 tests |
| `ksmbd_test_crypto_ctx.c` | 13 tests |
| `ksmbd_test_md4.c` | 19 tests |
| **Total** | **108 tests** |

### Classification Results

| Classification | Count |
|---|---|
| CORRECT | 108 |
| WRONG | 0 |
| QUESTIONABLE | 0 |

---

### Detailed Analysis

#### 1. `/home/ezechiel203/ksmbd/test/ksmbd_test_auth.c` (49 tests) -- ALL CORRECT

**GSS/SPNEGO header tests (8 tests):** These test the SPNEGO negotiation token structure. The SPNEGO OID `1.3.6.1.5.5.2` (bytes `06 06 2b 06 01 05 05 02`), the Kerberos OID `1.2.840.113554.1.2.2`, and the NTLMSSP OID `1.3.6.1.4.1.311.2.2.10` are all correctly encoded. The hint string "not_defined_in_RFC4178@please_ignore" at offset 60 matches the standard SPNEGO negTokenInit mechListMIC pattern. AUTH_GSS_LENGTH = 96 is an implementation-specific buffer size, correctly tested.

**ARC4 cipher tests (9 tests):** ARC4 (RC4) is used in NTLMv1/NTLMv2 session key exchange. The RFC 6229 known-answer test vector for 40-bit key `{0x01..0x05}` with expected output `{b2 39 63 05 f0 3d c0 27 cc c3 52 4a 0a 11 18 a8}` is correct per RFC 6229 Section 2. Roundtrip, determinism, in-place, min/max key size, single byte, and different-keys-different-output tests are all algorithmically sound.

**NTLMSSP negotiate parsing (7 tests):** The tests validate MS-NLMP section 2.2.1.1 NEGOTIATE_MESSAGE structure. A valid blob with correct signature "NTLMSSP\0" and MessageType = NtLmNegotiate (1) is accepted. Blobs smaller than sizeof(negotiate_message), with zero length, or with wrong signatures are rejected with -EINVAL. All negotiate flags are stored correctly. These expectations are all consistent with MS-NLMP and the ksmbd implementation.

**NTLMSSP authenticate parsing (7 tests):** Tests validate MS-NLMP section 2.2.1.3 AUTHENTICATE_MESSAGE. A too-short blob or wrong signature returns -EINVAL. Anonymous auth (NTLMSSP_ANONYMOUS flag with zero-length NtChallengeResponse) succeeds per MS-SMB2 section 3.3.5.5.3. Zero-length NtChallengeResponse WITHOUT the anonymous flag is correctly rejected. Offset overflow and integer overflow tests are security hardening checks not explicitly in the spec but consistent with it. The NTLMv2 blob validation (missing MsvAvEOL, too-small-for-AvPairs) correctly returns -EINVAL per implementation bounds checking.

**NTLMSSP constants and structure layout (12 tests):**
- CIFS_CRYPTO_KEY_SIZE = 8: Server challenge size per MS-NLMP. CORRECT.
- CIFS_ENCPWD_SIZE = 16: NTProofStr size. CORRECT.
- CIFS_AUTH_RESP_SIZE = 24: NTLMv1 response size per MS-NLMP. CORRECT.
- CIFS_HMAC_MD5_HASH_SIZE = 16: HMAC-MD5 digest size. CORRECT.
- CIFS_NTHASH_SIZE = 16: MD4 hash size (NT Hash). CORRECT.
- SMB2_NTLMV2_SESSKEY_SIZE = 16: Session key size per MS-SMB2 section 3.3.1.8 ("first 16 bytes of the cryptographic key"). CORRECT.
- SMB2_SIGNATURE_SIZE = 16: Per MS-SMB2 section 2.2.1.2 ("Signature (16 bytes)"). CORRECT.
- SMB2_HMACSHA256_SIZE = 32: Full HMAC-SHA256 output size. CORRECT.
- SMB2_CMACAES_SIZE = 16: AES-128-CMAC output size. CORRECT.
- SMB3_SIGN_KEY_SIZE = 16: Per MS-SMB2 section 3.3.1.8 ("128-bit key used for signing"). CORRECT.
- SMB3_ENC_DEC_KEY_SIZE = 32: Maximum KDF output size (256 bits for AES-256). CORRECT.
- NtLmNegotiate = 1, NtLmChallenge = 2, NtLmAuthenticate = 3: Per MS-NLMP section 2.2.1. CORRECT.
- negotiate_message = 32 bytes, authenticate_message = 64 bytes, challenge_message = 48 bytes: All match MS-NLMP structure definitions. CORRECT.

**NTLMSSP flag bit positions (1 test):** All 12 flag values (UNICODE=0x01, OEM=0x02, REQUEST_TARGET=0x04, SIGN=0x0010, SEAL=0x0020, LM_KEY=0x0080, NTLM=0x0200, ANONYMOUS=0x0800, EXTENDED_SEC=0x80000, 128=0x20000000, KEY_XCH=0x40000000, 56=0x80000000) match MS-NLMP section 2.2.2.5 exactly. CORRECT.

**AV pair field types (1 test):** All 11 values (EOL=0 through CHANNEL_BINDINGS=10) match MS-NLMP section 2.2.2.1. CORRECT.

**str_to_key DES expansion tests (5 tests, conditional on CONFIG_SMB_INSECURE_SERVER):** These test the DES key expansion used in NTLMv1. The algorithm distributes 56 input bits across 8 bytes with parity bits. The all-zeros, all-ones, known-vector, sequential, and roundtrip-bits tests are algorithmically correct for the standard DES key parity expansion.

**scatterlist tests (4 tests):** These test internal implementation helpers (smb2_sg_set_buf, ksmbd_init_sg) used by the encryption/signing code. They verify that scatterlist entries are properly initialized. These are implementation-level tests with no direct spec requirement.

---

#### 2. `/home/ezechiel203/ksmbd/test/ksmbd_test_crypto_correctness.c` (12 tests) -- ALL CORRECT

**test_smb3_kdf_hmac_sha256:** Tests SP800-108 counter-mode KDF with HMAC-SHA256 PRF. Label "SMB2AESCMAC" (12 bytes) and context "SmbSign" (8 bytes) match the SMB 3.0 signing key derivation per MS-SMB2 section 3.3.5.5 step 7 (line 21136, 21142). CORRECT.

**test_aes128_ccm/gcm/aes256_ccm/gcm_encrypt_decrypt_roundtrip (4 tests):** All four AEAD round-trip tests use correct key sizes (16 for AES-128, 32 for AES-256), correct nonce sizes (SMB3_AES_CCM_NONCE = 11, SMB3_AES_GCM_NONCE = 12), and 16-byte authentication tags. Per MS-SMB2 section 2.2.41: CCM nonce is 11 bytes (line 9908), GCM nonce is 12 bytes (line 9931). Per MS-SMB2 section 3.1.4.2: AES-128 uses L=128 (16-byte key), AES-256 uses L=256 (32-byte key) (lines 10488-10489). CORRECT.

**test_encryption_key_differs_from_signing_key:** Uses different label/context pairs ("SMB2AESCMAC"/"SmbSign" vs "SMB2AESCCM"/"ServerOut") and verifies different keys are derived. Per MS-SMB2 section 3.3.5.5 steps 7 and 11, signing and encryption keys use different labels, so they must differ. CORRECT.

**test_different_sessions_different_keys:** Different session keys produce different derived keys. This follows from the KDF properties of HMAC-SHA256 (SP800-108). CORRECT.

**test_key_derivation_label_signing:** Uses "SMBSigningKey" (14 bytes) as label with PREAUTH_HASHVALUE_SIZE context. Per MS-SMB2 section 3.3.5.5 step 7 (lines 21135-21146): "SMBSigningKey" for SMB 3.1.1, size 14 including NUL, with PreauthIntegrityHashValue as context. CORRECT.

**test_key_derivation_label_encryption:** Uses "SMBS2CCipherKey" (16 bytes) and "SMBC2SCipherKey" (16 bytes) as labels. Per MS-SMB2 section 3.3.5.5 step 11 (lines 21230, 21250): server EncryptionKey uses "SMBS2CCipherKey", DecryptionKey uses "SMBC2SCipherKey". CORRECT.

**test_key_derivation_context_preauth_hash:** Verifies PREAUTH_HASHVALUE_SIZE = 64 and that changing one byte of the preauth hash context changes the derived key. Per MS-SMB2 section 2.2.3.1.1 (line 3178): SHA-512 produces 64-byte output. CORRECT.

**test_nonce_uniqueness:** Verifies GCM nonces differ between calls. Per MS-SMB2 section 2.2.41 (line 9882-9883): "This MUST NOT be reused for all encrypted messages within a session." CORRECT.

**test_transform_header_original_message_size:** Verifies OriginalMessageSize equals the RFC1001 length. Per MS-SMB2 section 3.1.4.3 (line 10503): "OriginalMessageSize is set to the size of the SMB2 message being sent." CORRECT.

---

#### 3. `/home/ezechiel203/ksmbd/test/ksmbd_test_signing_verify.c` (15 tests) -- ALL CORRECT

**test_hmac_sha256_sign_known_answer:** RFC 4231 test case 1 (key = 0x0b * 20, data = "Hi There") expected HMAC-SHA256 = `b0344c61...`. This is a standard known-answer test from the RFC. CORRECT.

**test_aes_cmac_sign_known_answer:** NIST SP 800-38B Example 1 (key = `2b7e1516...`, empty message) expected AES-CMAC = `bb1d6929...`. This is a standard NIST test vector. CORRECT.

**test_single_bit_flip_detected, test_wrong_session_key_detected:** Verify signing primitives detect data changes and key changes. These are fundamental crypto properties. CORRECT.

**test_signature_field_zeroed_before_compute:** Per MS-SMB2 section 3.1.4.1 (line 10425): "The sender MUST zero out the 16-byte signature field in the SMB2 Header." CORRECT.

**test_transform_header_protocol_id:** Per MS-SMB2 section 2.2.41 (line 9876): ProtocolId = 0x424D53FD, network order = 0xFD 'S' 'M' 'B'. In little-endian: bytes are fd 53 4d 42. CORRECT.

**test_transform_header_nonce_16bytes:** Per MS-SMB2 section 2.2.41 (line 9882): "Nonce (16 bytes)". CORRECT.

**test_signing_algorithm_constants:** Per MS-SMB2 section 2.2.3.1.3 (lines 3416-3422): HMAC-SHA256 = 0x0000, AES-CMAC = 0x0001, AES-GMAC = 0x0002. CORRECT.

**test_encryption_algorithm_constants:** Per MS-SMB2 section 2.2.3.1.2 (lines 3208-3214): AES-128-CCM = 0x0001, AES-128-GCM = 0x0002, AES-256-CCM = 0x0003, AES-256-GCM = 0x0004. CORRECT.

**test_session_key_size_16bytes:** Per MS-SMB2 section 3.3.1.8 (line 11018): "first 16 bytes". CORRECT.

**test_signing_required_flag:** Per MS-SMB2 section 2.2.1.2 (line 2190-2191): SMB2_FLAGS_SIGNED = 0x00000008. CORRECT.

**test_preauth_integrity_sha512:** Per MS-SMB2 section 2.2.3.1.1 (line 3178): SHA-512 hash algorithm = 0x0001, output = 64 bytes. CORRECT.

**test_fill_transform_hdr_if_exported:** Verifies ProtocolId = SMB2_TRANSFORM_PROTO_NUM, OriginalMessageSize = 64, SessionId copied from inner header. All per MS-SMB2 section 2.2.41 and 3.1.4.3. CORRECT.

**test_generate_signing_key_if_exported:** Uses SMB 3.0 signing labels ("SMB2AESCMAC"/"SmbSign") per MS-SMB2 section 3.3.5.5. CORRECT.

**test_generate_encryption_key_if_exported:** Uses SMB 3.0 encryption labels ("SMB2AESCCM"/"ServerOut" and "SMB2AESCCM"/"ServerIn ") per MS-SMB2 section 3.3.5.5. The context "ServerIn " with trailing space matches spec line 21257-21258: "the case-sensitive ASCII string 'ServerIn ' as context for the algorithm (note the blank space at the end.)". CORRECT.

---

#### 4. `/home/ezechiel203/ksmbd/test/ksmbd_test_crypto_ctx.c` (13 tests) -- ALL CORRECT

All tests in this file exercise the crypto context pool lifecycle (create/destroy, find/release for each algorithm type, NULL safety, pool reuse, multi-algorithm). These are pure implementation-level tests with no protocol specification requirements. They verify that the crypto context pool correctly manages HMAC-MD5, HMAC-SHA256, CMAC-AES, SHA-256, SHA-512, MD4, MD5, GCM, and CCM algorithm contexts. All assertions test implementation behavior rather than protocol compliance. CORRECT (not applicable to spec, but internally sound).

---

#### 5. `/home/ezechiel203/ksmbd/test/ksmbd_test_md4.c` (19 tests) -- ALL CORRECT

**RFC 1320 test vectors (7 tests):** All seven MD4 test vectors match RFC 1320 exactly:
- MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0. CORRECT.
- MD4("a") = bde52cb31de33e46245e05fbdbd6fb24. CORRECT.
- MD4("abc") = a448017aaf21d8525fc10ae87aa6729d. CORRECT.
- MD4("message digest") = d9130a8164549fe818874806e1c7014b. CORRECT.
- MD4("abcdefghijklmnopqrstuvwxyz") = d79e1c308aa5bbcdeea8ed63df412da9. CORRECT.
- MD4("ABCDEF...0123456789") = 043f8582f241db351ce627e153e7f0e4. CORRECT.
- MD4("12345...repeated") = e33b4ddc9c38f2199c3e7b164fcc0536. CORRECT.

**Boundary tests (4 tests):** Incremental update, exactly-one-block (64 bytes), boundary-minus-one (55 bytes), boundary-plus-one (56 bytes), and large input (1024 bytes) tests are all algorithmically correct boundary conditions for the Merkle-Damgard construction used by MD4 (block size = 64 bytes, padding requires at least 9 bytes). CORRECT.

**Structural and lifecycle tests (5 tests):** Register/unregister, double register, different inputs produce different hashes, byte-at-a-time. All correct implementation tests.

**md4_transform() direct tests (3 tests):** Tests the raw transform function with known initial hash values (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 -- the MD4 initial values per RFC 1320 section 3.3). Verifies determinism and collision resistance at the transform level. CORRECT.

---

### Final Tally

| Metric | Value |
|---|---|
| Total tests audited | 108 |
| CORRECT | 108 |
| WRONG | 0 |
| QUESTIONABLE | 0 |

Every test's expected outcome aligns with the MS-SMB2 specification (January 14, 2026 edition), the MS-NLMP specification, RFC 1320 (MD4), RFC 4231 (HMAC-SHA256), RFC 6229 (RC4/ARC4), and NIST SP 800-38B (AES-CMAC). The key derivation labels, context strings, buffer sizes, nonce sizes, algorithm identifiers, flag bit positions, structure sizes, and cryptographic test vectors are all correct. No test contradicts any protocol specification requirement.