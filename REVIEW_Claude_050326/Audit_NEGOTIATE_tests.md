# Audit Negotiate Tests

Agent ID: a9692922405e9f6a9

I now have all the information needed. Let me compile the complete audit report.

---

# MS-SMB2 Spec Compliance Audit: Negotiate Test Files

## File 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_negotiate.c`

This file contains 35 KUNIT_CASE tests. They cover `smb3_encryption_negotiated()`, `decode_preauth_ctxt()`, `decode_encrypt_ctxt()`, `decode_compress_ctxt()`, `decode_sign_cap_ctxt()`, `decode_transport_cap_ctxt()`, `decode_rdma_transform_ctxt()`, cipher preference, and protocol constants.

### CORRECT

1. **test_smb3_encryption_negotiated_no_ops** -- Tests that encryption is not negotiated when `generate_encryptionkey` is NULL and no cap/cipher is set. This is internal implementation logic; no direct spec section, but correctly tests code behavior.

2. **test_smb3_encryption_negotiated_cap_flag** -- Tests that SMB2_GLOBAL_CAP_ENCRYPTION in `vals->capabilities` triggers encryption. Matches spec: per section 2.2.4, SMB2_GLOBAL_CAP_ENCRYPTION (0x00000040) indicates encryption support for SMB 3.0/3.0.2.

3. **test_smb3_encryption_negotiated_cipher_type** -- Tests that a nonzero `cipher_type` (from SMB 3.1.1 negotiate context) also triggers encryption. Correct per implementation design.

4. **test_decode_preauth_ctxt_valid** -- SHA-512 (0x0001) accepted, status=STATUS_SUCCESS, `Preauth_HashId` set. Per section 2.2.3.1.1 and 3.3.5.4: SHA-512 is the only defined hash algorithm. **CORRECT**.

5. **test_decode_preauth_ctxt_too_short** -- ctxt_len=4 returns STATUS_INVALID_PARAMETER. Per section 3.3.5.4: "If the DataLength of the negotiate context is less than the size of SMB2_PREAUTH_INTEGRITY_CAPABILITIES structure, the server MUST fail the negotiate request with STATUS_INVALID_PARAMETER." **CORRECT**.

6. **test_decode_preauth_ctxt_zero_hash_count** -- HashAlgorithmCount=0 returns STATUS_INVALID_PARAMETER. Per section 2.2.3.1.1: "This value MUST be greater than zero." Implementation also checks per section 3.3.5.4 (implicit -- zero count means no overlap). The test checks the implementation's explicit zero-count rejection. **CORRECT**.

7. **test_decode_preauth_ctxt_unknown_hash** -- Unknown hash 0xFFFF returns STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP. Per section 3.3.5.4: "If the HashAlgorithms array does not contain any hash algorithms that the server supports, the server MUST fail with STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP (0xC05D0000)." **CORRECT** (STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP is ksmbd's name for 0xC05D0000).

8. **test_decode_encrypt_ctxt_aes128_gcm** -- AES-128-GCM (0x0002) is selected. Per section 2.2.3.1.2: 0x0002 = AES-128-GCM. **CORRECT**.

9. **test_decode_encrypt_ctxt_server_preference** -- When client offers AES-128-CCM then AES-128-GCM, server picks AES-128-GCM. Per section 3.3.5.4: "The server MUST set Connection.CipherId to one of the ciphers in the client's Ciphers array in an implementation-specific manner." Server preference (GCM > CCM) is implementation-specific. **CORRECT**.

10. **test_decode_encrypt_ctxt_cipher_count_overflow** -- CipherCount=0x7FFF with tiny buffer: cipher_type stays 0. The overflow check detects buffer overrun and returns early. **CORRECT** (defensive behavior).

11. **test_decode_encrypt_ctxt_encryption_disabled** -- Encryption off flag: cipher_type stays 0. Per section 3.3.5.4: "If IsEncryptionSupported is FALSE, the server MUST ignore the context." **CORRECT**.

12. **test_decode_encrypt_ctxt_no_supported_cipher** -- Unknown cipher 0xFFFF: cipher_type stays 0. Per section 3.3.5.4: "If the client and server have no common cipher, the server MUST set Connection.CipherId to 0." **CORRECT**.

13. **test_decode_compress_ctxt_zero_count** -- CompressionAlgorithmCount=0 returns STATUS_INVALID_PARAMETER. Per section 3.3.5.4: "If CompressionAlgorithmCount is equal to zero" the server MUST fail. **CORRECT**.

14. **test_decode_compress_ctxt_lz4** -- LZ4 (0x0005) selected. Per section 2.2.3.1.3: 0x0005 = LZ4. **CORRECT**.

15. **test_decode_compress_ctxt_pattern_v1** -- Pattern_V1 (0x0004) selected. Per section 2.2.3.1.3: 0x0004 = Pattern_V1. **CORRECT**.

16. **test_decode_compress_ctxt_no_supported** -- LZNT1 only offered, but server does not support it: result is SMB3_COMPRESS_NONE, status=STATUS_SUCCESS. Per section 3.3.5.4: "If the server does not support any of the algorithms, Connection.CompressionIds MUST be set to an empty list." No failure required. **CORRECT**.

17. **test_decode_compress_ctxt_lz4_preferred_over_pattern** -- LZ4 preferred over Pattern_V1. This is server preference logic. **CORRECT** (implementation-specific, matches server's actual behavior).

18. **test_decode_compress_ctxt_truncated_algo_list** -- Claims 10 algorithms but buffer too small: STATUS_INVALID_PARAMETER. **CORRECT** (buffer validation).

19. **test_decode_sign_cap_ctxt_zero_count** -- SigningAlgorithmCount=0 returns STATUS_INVALID_PARAMETER. Per section 3.3.5.4: "If SigningAlgorithmCount is equal to zero" the server MUST fail. **CORRECT**.

20. **test_decode_sign_cap_ctxt_aes_cmac** -- AES-CMAC (0x0001) selected. Per section 2.2.3.1.7: 0x0001 = AES-CMAC. **CORRECT**.

21. **test_decode_sign_cap_ctxt_hmac_sha256** -- HMAC-SHA256 (0x0000) selected. Per section 2.2.3.1.7: 0x0000 = HMAC-SHA256. **CORRECT**.

22. **test_decode_sign_cap_ctxt_aes_gmac** -- AES-GMAC (0x0002) selected. Per section 2.2.3.1.7: 0x0002 = AES-GMAC. **CORRECT**.

23. **test_decode_sign_cap_ctxt_no_overlap_fallback** -- Unknown algorithm 0xFFFF: falls back to AES-CMAC, status=STATUS_SUCCESS. Per section 3.3.5.4: "If the server does not support any of the signing algorithms provided by the client, Connection.SigningAlgorithmId MUST be set to 1 (AES-CMAC)." **CORRECT**.

24. **test_decode_sign_cap_ctxt_truncated** -- ctxt_len=2: STATUS_INVALID_PARAMETER. Per section 3.3.5.4: "If the DataLength of the negotiate context is less than the size of the SMB2_SIGNING_CAPABILITIES structure." **CORRECT**.

25. **test_decode_sign_cap_ctxt_truncated_algo_list** -- 100 algorithms claimed, tiny buffer: STATUS_INVALID_PARAMETER. **CORRECT** (buffer validation).

26. **test_decode_transport_cap_ctxt_supported** -- SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY flag sets transport_secured=true. Per section 3.3.5.4: "If SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY is set in the Flags field, the server MUST set Connection.AcceptTransportSecurity to TRUE." Note: spec also requires "underlying connection is over QUIC" and "DisableEncryptionOverSecureTransport is TRUE" conditions, but the decode function does not check those (they are checked at a higher level). The test is testing the decode function in isolation. **CORRECT** for unit-testing the decoder.

27. **test_decode_transport_cap_ctxt_too_short** -- ctxt_len=4: transport_secured stays false. Per section 3.3.5.4: "If the DataLength is less than the size of SMB2_TRANSPORT_CAPABILITIES, the server MUST fail." The implementation returns early without setting the flag. **CORRECT** at the decode level.

28. **test_decode_transport_cap_ctxt_no_flag** -- Flags=0: transport_secured stays false. Per section 3.3.5.4: the flag is only set when SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY is present. **CORRECT**.

29. **test_decode_rdma_transform_ctxt_valid** -- Three known transform IDs (NONE=0, ENCRYPTION=1, SIGNING=2) all accepted, count=3. Per section 2.2.3.1.6 and 3.3.5.4: server sets Connection.RDMATransformIds to common transforms. **CORRECT**.

30. **test_decode_rdma_transform_ctxt_unknown_ids** -- Unknown IDs 0xAAAA, 0xBBBB: skipped, count=0. Per section 3.3.5.4: "If the server does not support any of the RDMA transforms, Connection.RDMATransformIds MUST be set to an empty list." **CORRECT**.

31. **test_decode_rdma_transform_ctxt_truncated** -- ctxt_len=2: count stays 0 (early return). **CORRECT** (defensive).

32. **test_cipher_preference_aes256_gcm_first** -- Server prefers AES-256-GCM over all others. Per section 3.3.5.4: cipher selection is "implementation-specific." **CORRECT**.

33. **test_cipher_preference_aes256_ccm_over_128_ccm** -- AES-256-CCM preferred over AES-128-CCM. **CORRECT** (implementation-specific server preference).

34. **test_negotiate_context_type_values** -- Validates all context type constants:
    - SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001 (section 2.2.3.1)
    - SMB2_ENCRYPTION_CAPABILITIES = 0x0002
    - SMB2_COMPRESSION_CAPABILITIES = 0x0003
    - SMB2_NETNAME_NEGOTIATE_CONTEXT_ID = 0x0005
    - SMB2_TRANSPORT_CAPABILITIES = 0x0006
    - SMB2_RDMA_TRANSFORM_CAPABILITIES = 0x0007
    - SMB2_SIGNING_CAPABILITIES = 0x0008
    - SMB2_POSIX_EXTENSIONS_AVAILABLE = 0x100
    All match section 2.2.3.1. Note: 0x0100 is listed in the spec as `SMB2_CONTEXTTYPE_RESERVED` with "MUST be reserved and MUST be ignored on receipt." The ksmbd codebase repurposes this value as `SMB2_POSIX_EXTENSIONS_AVAILABLE` (a Samba/Linux extension). The constant value itself is correct; the naming differs from the spec (see QUESTIONABLE below). **CORRECT** for all standard context types.

35. **test_signing_algorithm_constants** -- HMAC-SHA256=0x0000, AES-CMAC=0x0001, AES-GMAC=0x0002. All match section 2.2.3.1.7. **CORRECT**.

36. **test_cipher_type_constants** -- AES-128-CCM=0x0001, AES-128-GCM=0x0002, AES-256-CCM=0x0003, AES-256-GCM=0x0004. All match section 2.2.3.1.2. **CORRECT**.

37. **test_compression_algorithm_constants** -- NONE=0x0000, LZNT1=0x0001, LZ77=0x0002, LZ77+Huffman=0x0003, Pattern_V1=0x0004, LZ4=0x0005. All match section 2.2.3.1.3. **CORRECT**.

### WRONG

None found in this file.

### QUESTIONABLE

1. **test_negotiate_context_type_values (SMB2_POSIX_EXTENSIONS_AVAILABLE = 0x100)** -- The MS-SMB2 spec (section 2.2.3.1) defines 0x0100 as `SMB2_CONTEXTTYPE_RESERVED` which "MUST be reserved and MUST be ignored on receipt." The ksmbd codebase (and Samba) redefines this value as `SMB2_POSIX_EXTENSIONS_AVAILABLE` for POSIX extension negotiation. This is a non-standard extension that happens to reuse the spec's reserved context type value. The test verifies the ksmbd implementation value, which is **correct for the implementation** but **does not match the MS-SMB2 spec's intended semantics** for this value.

2. **test_decode_rdma_transform_ctxt_zero_count** -- Tests TransformCount=0 resulting in rdma_transform_count=0 silently. Per MS-SMB2 section 3.3.5.4: "The server MUST fail the negotiate request with STATUS_INVALID_PARAMETER if... TransformCount is equal to zero." However, the ksmbd `decode_rdma_transform_ctxt()` function silently returns (with a pr_err) without returning an error status. The test matches the actual implementation behavior but **the implementation itself deviates from the spec** -- the spec says this should be a failure. The test is correct for what the code does, but the code is wrong per spec. The spec requires STATUS_INVALID_PARAMETER.

---

## File 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_negotiate.c`

This file contains 20 KUNIT_CASE tests. Many overlap with File 1.

### CORRECT

1. **test_preauth_sha512** -- Same as File 1 test. SHA-512 accepted, STATUS_SUCCESS. Per sections 2.2.3.1.1 and 3.3.5.4. **CORRECT**.

2. **test_preauth_hash_count_zero** -- HashAlgorithmCount=0 rejected with STATUS_INVALID_PARAMETER. Per section 3.3.5.4 (implicit from no-overlap) and section 2.2.3.1.1 ("MUST be greater than zero"). **CORRECT**.

3. **test_preauth_unknown_hash** -- Unknown hash 0xFFFF returns STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP. Per section 3.3.5.4. **CORRECT**.

4. **test_preauth_truncated** -- ctxt_len=4 returns STATUS_INVALID_PARAMETER. Per section 3.3.5.4. **CORRECT**.

5. **test_sign_cap_aes_cmac** -- AES-CMAC selected. Per section 2.2.3.1.7 (value 0x0001). **CORRECT**.

6. **test_sign_cap_count_zero** -- SigningAlgorithmCount=0 returns STATUS_INVALID_PARAMETER. Per section 3.3.5.4. **CORRECT**.

7. **test_sign_cap_no_overlap_fallback** -- Unknown algorithm 0xFFFF falls back to AES-CMAC. Per section 3.3.5.4: "Connection.SigningAlgorithmId MUST be set to 1 (AES-CMAC)." **CORRECT**.

8. **test_compress_count_zero** -- CompressionAlgorithmCount=0 returns STATUS_INVALID_PARAMETER. Per section 3.3.5.4. **CORRECT**.

9. **test_compress_truncated** -- ctxt_len=2 returns STATUS_INVALID_PARAMETER. Per section 3.3.5.4: data length less than structure size. **CORRECT**.

10. **test_encrypt_truncated** -- ctxt_len=2: returns early, cipher_type unchanged (0x1234 stays). Tests that `decode_encrypt_ctxt` does an early return on truncated context. Per section 3.3.5.4: "If the DataLength is less than the size of the SMB2_ENCRYPTION_CAPABILITIES structure, the server MUST fail with STATUS_INVALID_PARAMETER." Note: the implementation returns void (no error status) and just returns early. The test correctly reflects the implementation behavior. **CORRECT** for testing code, though the implementation's void return type means the spec-mandated error status is not propagated (see QUESTIONABLE).

11. **test_transport_cap_accepted** -- SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY sets transport_secured=true. Per section 3.3.5.4. **CORRECT**.

12. **test_transport_cap_no_flag** -- Flags=0 means transport not secured. **CORRECT**.

13. **test_transport_cap_truncated** -- ctxt_len=2: ignored, transport_secured stays false. **CORRECT**.

14. **test_rdma_transform_all_known** -- All 3 known IDs accepted. Per section 2.2.3.1.6. **CORRECT**.

15. **test_rdma_transform_zero_count** -- TransformCount=0: rdma_transform_count=0, no error. Same QUESTIONABLE issue as File 1. **CORRECT** for implementation, but spec says should fail.

16. **test_rdma_transform_unknown_ids** -- Unknown IDs skipped, count=0. Per section 3.3.5.4. **CORRECT**.

17. **test_rdma_transform_truncated** -- ctxt_len=2: count stays 0. **CORRECT**.

18. **test_rdma_transform_mixed_known_unknown** -- Mix of known/unknown: only known IDs retained. Verifies ordering: NONE and SIGNING accepted, unknowns skipped. Per section 3.3.5.4. **CORRECT**.

19. **test_encrypt_aes256_gcm_selected** -- AES-256-GCM picked as highest priority from 4 ciphers. Implementation-specific preference. **CORRECT**.

20. **test_encrypt_aes128_ccm_only** -- Only AES-128-CCM offered, it is selected. Per section 2.2.3.1.2 (value 0x0001). **CORRECT**.

### WRONG

None found in this file.

### QUESTIONABLE

1. **test_encrypt_truncated** -- The test expects `cipher_type` to remain at the sentinel 0x1234 after calling with a truncated context (ctxt_len=2). This tests the decode function's early-return behavior, which is correct for the implementation. However, per section 3.3.5.4, the spec says the server MUST fail with STATUS_INVALID_PARAMETER when DataLength is too small. Since `decode_encrypt_ctxt` returns `void`, the status code is lost. The test correctly verifies the behavior of the function as written, but the function's signature prevents spec compliance (it should return a status code).

2. **test_rdma_transform_zero_count** -- Same issue as File 1. Spec says TransformCount=0 MUST be rejected. Implementation silently ignores.

---

## File 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_negotiate_context_order.c`

This file contains 9 KUNIT_CASE tests. They verify context type constants, structure layouts, alignment, and algorithm IDs using standalone definitions (not importing from ksmbd).

### CORRECT

1. **test_preauth_integrity_context_type** -- SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001. Per section 2.2.3.1. **CORRECT**.

2. **test_encryption_capabilities_context_type** -- SMB2_ENCRYPTION_CAPABILITIES = 0x0002. Per section 2.2.3.1. **CORRECT**.

3. **test_compression_capabilities_context_type** -- SMB2_COMPRESSION_CAPABILITIES = 0x0003. Per section 2.2.3.1. **CORRECT**.

4. **test_negotiate_context_header_size** -- Header is 8 bytes: ContextType(2) + DataLength(2) + Reserved(4). Per section 2.2.3.1: the header layout is exactly ContextType (2), DataLength (2), Reserved (4). **CORRECT**.

5. **test_preauth_context_layout** -- Verifies offsets: HashAlgorithmCount at offset 8, SaltLength at 10, HashAlgorithms at 12, Salt at 14 from the start of the full context (including header). Per section 2.2.3.1.1: the Data field starts after the 8-byte header and contains HashAlgorithmCount(2), SaltLength(2), HashAlgorithms(variable), Salt(variable). So: 8+0=8 for HashAlgorithmCount, 8+2=10 for SaltLength, 8+4=12 for HashAlgorithms, 8+4+2=14 for Salt (with one hash algorithm). **CORRECT**.

6. **test_preauth_sha512_algorithm_id** -- SHA-512 = 0x0001. Per section 2.2.3.1.1: "0x0001: SHA-512." **CORRECT**.

7. **test_preauth_zero_hash_algorithms_rejected** -- Verifies that zero algorithms with zero salt produces DataLength=4, which is less than MIN_PREAUTH_CTXT_DATA_LEN (6). Per section 2.2.3.1.1: minimum valid data is HashAlgorithmCount(2) + SaltLength(2) + at least one HashAlgorithm(2) = 6 bytes. **CORRECT**.

8. **test_encryption_context_cipher_ids** -- AES-128-CCM=0x0001, AES-128-GCM=0x0002, AES-256-CCM=0x0003, AES-256-GCM=0x0004. Per section 2.2.3.1.2. **CORRECT**.

9. **test_context_alignment** -- Verifies 8-byte alignment of negotiate contexts. Per section 2.2.3.1: "Subsequent negotiate contexts MUST appear at the first 8-byte-aligned offset following the previous negotiate context." The test verifies: header=8 bytes (aligned), 14 -> roundup 16, 46 -> roundup 48, 16 -> already aligned. **CORRECT**.

### WRONG

None found in this file.

### QUESTIONABLE

None found in this file. All tests are structural/constant verification and match the spec perfectly.

---

## File 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_error_negotiate.c`

This file contains 10 KUNIT_CASE tests covering error paths.

### CORRECT

1. **err_neg_dialect_count_zero** -- Verifies DialectCount=0 condition is detectable. Per section 3.3.5.4: "If the DialectCount is 0, the server MUST fail the request with STATUS_INVALID_PARAMETER." The test only checks that `le16_to_cpu(req.DialectCount) == 0`, it does not call `smb2_handle_negotiate`. This is a passive constant check. **CORRECT** (but weak -- only verifies the field is 0, not the actual error path).

2. **err_neg_no_common_dialect** -- Verifies BAD_PROT_ID is distinct from all valid protocol IDs. Per section 3.3.5.4: "If a common dialect is not found, the server MUST fail the request with STATUS_NOT_SUPPORTED." BAD_PROT_ID (0xFFFF) as sentinel is implementation-specific. **CORRECT**.

3. **err_neg_preauth_zero_length** -- ctxt_len=0 returns STATUS_INVALID_PARAMETER. Per section 3.3.5.4: data length less than structure size. **CORRECT**.

4. **err_neg_preauth_minimal_undersize** -- ctxt_len = sizeof(smb2_neg_context) + MIN_PREAUTH_CTXT_DATA_LEN - 1 returns STATUS_INVALID_PARAMETER. This tests the exact boundary: one byte short of minimum. **CORRECT**.

5. **err_neg_encrypt_zero_length** -- ctxt_len=0: cipher_type unchanged (0x9999). Tests early return on zero-length context. **CORRECT** for implementation behavior (same void-return QUESTIONABLE issue).

6. **err_neg_encrypt_overflow_cipher_count** -- CipherCount=0xFFFF with sizeof-only buffer: cipher_type=0. Tests overflow protection. **CORRECT**.

7. **err_neg_compress_overflow_algo_count** -- CompressionAlgorithmCount=0x7FFF with sizeof-only buffer: STATUS_INVALID_PARAMETER. Tests overflow protection. **CORRECT**.

8. **err_neg_compress_no_supported_algo** -- Unknown algorithm 0xFFFF offered: STATUS_SUCCESS, compress_algorithm=SMB3_COMPRESS_NONE. Per section 3.3.5.4: "If the server does not support any, Connection.CompressionIds MUST be set to an empty list." No failure status. **CORRECT**.

9. **err_neg_sign_overflow_algo_count** -- SigningAlgorithmCount=0x7FFF with sizeof-only buffer: STATUS_INVALID_PARAMETER. Tests overflow protection. **CORRECT**.

### WRONG

None found in this file.

### QUESTIONABLE

1. **err_neg_context_offset_overflow** -- Sets NegotiateContextOffset=0xFFFF, NegotiateContextCount=1, len_of_smb=100, and expects `deassemble_neg_contexts` to return STATUS_SUCCESS (because the early `if (len_of_smb <= offset)` check triggers and returns the initial status which is STATUS_SUCCESS). The test documents a behavior where an out-of-bounds offset is **silently accepted** rather than rejected. Per section 3.3.5.4, the spec does not explicitly define behavior for an invalid NegotiateContextOffset, but it is implied that the server should be able to locate and parse the context list. Returning STATUS_SUCCESS for an out-of-bounds offset is debatable -- it means no contexts are processed, which for SMB 3.1.1 would subsequently fail the "exactly one PREAUTH_INTEGRITY" check. The test is **correct for the implementation** but the early-exit behavior is arguably a spec gap rather than a clear pass/fail.

---

## Summary

### Across all 4 files (74 total KUNIT_CASEs):

**CORRECT: 71 tests**
All tests listed above that validate protocol constants, context type IDs, algorithm IDs, structure layouts, alignment rules, buffer validation, and negotiate context processing logic match the MS-SMB2 specification sections 2.2.3, 2.2.3.1, 2.2.3.1.1-7, 2.2.4, 2.2.4.1.1-7, and 3.3.5.4.

**WRONG: 0 tests**
No test makes an assertion that directly contradicts the MS-SMB2 specification.

**QUESTIONABLE: 3 issues (affecting 5 tests)**

1. **SMB2_POSIX_EXTENSIONS_AVAILABLE = 0x0100** (1 test in File 1: `test_negotiate_context_type_values`)
   - MS-SMB2 section 2.2.3.1 defines 0x0100 as `SMB2_CONTEXTTYPE_RESERVED` ("MUST be reserved and MUST be ignored on receipt"). ksmbd repurposes it as `SMB2_POSIX_EXTENSIONS_AVAILABLE`. The constant value itself is correct, but the semantics differ from the spec. This is a known Linux/Samba extension.

2. **RDMA TransformCount=0 silently accepted** (2 tests: `test_decode_rdma_transform_ctxt_zero_count` in File 1, `test_rdma_transform_zero_count` in File 2)
   - MS-SMB2 section 3.3.5.4: "The server MUST fail the negotiate request with STATUS_INVALID_PARAMETER if... TransformCount is equal to zero." The implementation's `decode_rdma_transform_ctxt()` returns void, so it cannot signal failure. The tests correctly reflect the implementation but the implementation itself does not comply with this spec requirement. Note that the `decode_rdma_transform_ctxt` function returns `void` and the caller in `deassemble_neg_contexts` does not check for the zero-count condition.

3. **decode_encrypt_ctxt returns void -- truncation not reported as error** (2 tests: `test_decode_encrypt_ctxt_cipher_count_overflow`/`test_encrypt_truncated` in Files 1/2, `err_neg_encrypt_zero_length`/`err_neg_encrypt_overflow_cipher_count` in File 4)
   - MS-SMB2 section 3.3.5.4: "If the DataLength is less than the size of SMB2_ENCRYPTION_CAPABILITIES structure, the server MUST fail the negotiate request with STATUS_INVALID_PARAMETER." The implementation's `decode_encrypt_ctxt()` returns void, so truncation errors silently leave `cipher_type=0` without returning STATUS_INVALID_PARAMETER. The tests correctly verify the function's actual behavior, but the function's void return type prevents full spec compliance. The test expectation of "no error, just no cipher" matches the code but not the spec.

4. **deassemble_neg_contexts returns STATUS_SUCCESS for out-of-bounds offset** (1 test: `err_neg_context_offset_overflow` in File 4)
   - The `if (len_of_smb <= offset) return status;` path returns STATUS_SUCCESS (the initial value) when the offset is clearly invalid. While the spec does not explicitly address malformed offsets, returning success for a malformed request is surprising. In practice, the subsequent "missing PREAUTH_INTEGRITY context" check would catch this for SMB 3.1.1. The test documents current behavior accurately.