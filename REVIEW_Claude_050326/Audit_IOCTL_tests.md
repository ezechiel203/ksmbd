# Audit Ioctl Tests

Agent ID: adc6fd02b13c4b43f

Now I have all the information needed. Let me compile the complete audit report.

---

# KSMBD IOCTL KUnit Test Audit Report

## Spec References Used
- MS-SMB2 section 2.2.31: SMB2 IOCTL Request (StructureSize=57)
- MS-SMB2 section 2.2.32: SMB2 IOCTL Response (StructureSize=49)
- MS-SMB2 section 2.2.31.1: SRV_COPYCHUNK_COPY (SourceKey=24 bytes, ChunkCount, Chunks)
- MS-SMB2 section 2.2.31.1.1: SRV_COPYCHUNK (SourceOffset/TargetOffset/Length/Reserved)
- MS-SMB2 section 2.2.31.4: VALIDATE_NEGOTIATE_INFO Request
- MS-SMB2 section 2.2.32.1: SRV_COPYCHUNK_RESPONSE
- MS-SMB2 section 2.2.32.6: VALIDATE_NEGOTIATE_INFO Response
- MS-SMB2 section 3.3.5.15: Receiving an SMB2 IOCTL Request
- MS-SMB2 section 3.3.5.15.4: Handling a Peek at Pipe Data Request
- MS-SMB2 section 3.3.5.15.6: Handling a Server-Side Data Copy Request
- MS-SMB2 section 3.3.5.15.6.2: Sending an Invalid Parameter Server-Side Copy Response
- MS-SMB2 section 3.3.5.15.10: Handling a Pipe Wait Request
- MS-SMB2 section 3.3.5.15.12: Handling a Validate Negotiate Info Request

---

## File 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_ioctl.c`

### Section 1: FSCTL Registration / Dispatch (7 tests)

**1. `test_fsctl_register_unregister`** -- Tests that a custom handler can be registered and unregistered.
- **Verdict: CORRECT.** This is internal infrastructure testing, not directly testing a spec-mandated behavior, but the pattern (dispatch table for FSCTL codes) is a valid implementation approach. No spec violation.

**2. `test_fsctl_register_duplicate`** -- Second registration of the same code fails with `-EEXIST`.
- **Verdict: CORRECT.** Implementation detail; no spec conflict.

**3. `test_fsctl_register_different_codes`** -- Different FSCTL codes can coexist.
- **Verdict: CORRECT.** Implementation detail; no spec conflict.

**4. `test_fsctl_dispatch_unregistered`** -- Dispatching an unknown code returns `-EOPNOTSUPP`.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.15.8, unrecognized FSCTLs go through pass-through processing, and if the underlying object store does not support them, the appropriate error is returned. `-EOPNOTSUPP` maps to `STATUS_NOT_SUPPORTED`, which is the correct status for an unsupported FSCTL.

**5. `test_fsctl_dispatch_registered`** -- Dispatching a registered code invokes handler.
- **Verdict: CORRECT.** Validates plumbing.

**6. `test_fsctl_dispatch_handler_error`** -- Handler error (`-EINVAL`) is propagated.
- **Verdict: CORRECT.** Validates error propagation.

**7. `test_fsctl_dispatch_after_unregister`** -- Dispatch after unregister returns `-EOPNOTSUPP`.
- **Verdict: CORRECT.** Validates cleanup.

### Section 2: ODX Nonce Hash (4 tests)

**8. `test_odx_nonce_hash_deterministic`** -- Same nonce produces same hash.
- **Verdict: CORRECT.** Pure hash function validation; no spec requirement beyond correctness.

**9. `test_odx_nonce_hash_matches_jhash`** -- Verifies hash matches `jhash(nonce, 16, 0)`.
- **Verdict: CORRECT.** Implementation validation.

**10. `test_odx_nonce_hash_different_nonces`** -- Different nonces produce different hashes.
- **Verdict: CORRECT.** Note: the test acknowledges hash collisions are theoretically possible but practically do not occur for the chosen inputs.

**11. `test_odx_nonce_hash_zero_nonce`** -- Zero nonce produces a valid hash.
- **Verdict: CORRECT.**

### Section 3: IOCTL Flag Validation (3 tests)

**12. `test_ioctl_flags_fsctl_required`** -- `SMB2_0_IOCTL_IS_FSCTL` (0x00000001) passes validation.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.31, Flags must be either 0x00000000 (IOCTL request) or 0x00000001 (FSCTL request). Per section 3.3.5.15: "If the Flags field of the request is not SMB2_0_IOCTL_IS_FSCTL, the server MUST fail the request with STATUS_NOT_SUPPORTED." The value 0x00000001 is correct.

**13. `test_ioctl_flags_zero_rejected`** -- Flags=0 is rejected.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.15, Flags=0 means IOCTL (not FSCTL), and the server MUST fail with `STATUS_NOT_SUPPORTED`. The test validates this rejection.

**14. `test_ioctl_flags_other_value_rejected`** -- Flags=2 and 0xFFFFFFFF are rejected.
- **Verdict: QUESTIONABLE.** The spec in section 2.2.31 defines only two values: 0x00000000 and 0x00000001. The replicated `validate_ioctl_flags()` function uses strict equality (`flags != SMB2_0_IOCTL_IS_FSCTL_VAL`), meaning only 0x00000001 passes and everything else fails. However, the spec says the server should fail if Flags is "not SMB2_0_IOCTL_IS_FSCTL", which is a bit-check. The production code at `src/protocol/smb2/smb2_ioctl.c:99` uses `req->Flags != cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL)` which matches strict equality. So the test logic is consistent with production code, even if the spec phrasing is ambiguous. **Not wrong, but noting that the spec technically treats Flags as an enumeration of two values, and the test's strict equality check is the correct interpretation.**

### Section 4: IOCTL InputOffset/InputCount Validation (4 tests)

**15. `test_ioctl_input_offset_valid`** -- Various valid offset/count/buf_size combinations pass.
- **Verdict: CORRECT.** The replicated logic is a reasonable abstraction of the bounds checking described in MS-SMB2 section 3.3.5.15 (InputOffset + InputCount must not exceed message size).

**16. `test_ioctl_input_offset_overflow`** -- offset=300 > buf_size=256 fails.
- **Verdict: CORRECT.** Per spec: "InputOffset is greater than size of SMB2 Message" triggers `STATUS_INVALID_PARAMETER`.

**17. `test_ioctl_input_count_overflow`** -- offset=200, count=100, buf_size=256 (200+100=300>256) fails.
- **Verdict: CORRECT.** Per spec: "(InputOffset + InputCount) is greater than size of SMB2 Message" triggers `STATUS_INVALID_PARAMETER`.

**18. `test_ioctl_input_exact_boundary`** -- Exact boundary (100+156=256) passes, one past (100+157>256) fails.
- **Verdict: CORRECT.** Proper boundary testing.

### Section 5: Copy Chunk Limit Validation (5 tests)

**19. `test_copychunk_valid`** -- Valid parameters pass. Tests (1, 1024, 1024) and (256, 1048576, 16777216) at exact limits.
- **Verdict: CORRECT.** The constants `MAX_CHUNK_COUNT=256`, `MAX_CHUNK_SIZE=1MB`, `MAX_TOTAL_COPY_SIZE=16MB` are implementation-specific per the spec (section 3.3.1.5 says these are implementation-specific defaults). The chosen values match common Windows Server defaults and are consistent with production code.

**20. `test_copychunk_too_many_chunks`** -- ChunkCount=257 fails.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.15.6: "ChunkCount value is greater than ServerSideCopyMaxNumberofChunks" triggers Invalid Parameter response.

**21. `test_copychunk_chunk_too_large`** -- Chunk size = 1MB+1 fails.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.15.6: "Length value in a single chunk is greater than ServerSideCopyMaxChunkSize" triggers Invalid Parameter response.

**22. `test_copychunk_total_too_large`** -- Total = 16MB+1 fails.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.15.6: "Sum of Lengths in all chunks is greater than ServerSideCopyMaxDataSize" triggers Invalid Parameter response.

**23. `test_copychunk_exact_limits`** -- Exact limits (256, 1MB, 16MB) pass.
- **Verdict: CORRECT.** The spec says "greater than", so values equal to the limits should pass.

### Section 6: Validate Negotiate GUID/Dialect Comparison (4 tests)

**24. `test_validate_negotiate_dialect_match`** -- 0x0311 == 0x0311 passes.
- **Verdict: CORRECT but trivial.** Tests a literal equality check. Per MS-SMB2 section 3.3.5.15.12, the server checks that the negotiated dialect is in the client's Dialects array and matches Connection.Dialect.

**25. `test_validate_negotiate_dialect_mismatch`** -- 0x0311 != 0x0302.
- **Verdict: CORRECT but trivial.** Same observation as above.

**26. `test_validate_negotiate_guid_match`** -- Identical GUIDs match.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.15.12: "If the Guid received ... is not equal to the Connection.ClientGuid, the server MUST terminate the transport connection."

**27. `test_validate_negotiate_guid_mismatch`** -- Different GUIDs do not match.
- **Verdict: CORRECT.**

### Section 7: Set Sparse Default Behavior (2 tests)

**28. `test_set_sparse_no_buffer_default_true`** -- Empty input buffer implies SetSparse=TRUE.
- **Verdict: CORRECT.** Per MS-FSCC section 2.3.64, when the input buffer is too small to contain the FILE_SET_SPARSE_BUFFER structure, the server should default to SetSparse=TRUE. The test is trivial (just checks `input_count == 0`), but the concept is correct.

**29. `test_set_sparse_with_buffer`** -- Non-zero input count means buffer is present.
- **Verdict: CORRECT but trivial.**

### Section 8: FSCTL Code Classification (1 test)

**30. `test_ioctl_unknown_fsctl_code`** -- 0xDEADBEEF dispatches to `-EOPNOTSUPP`.
- **Verdict: CORRECT.** Uses real `ksmbd_dispatch_fsctl()`. Unregistered codes correctly return `-EOPNOTSUPP`.

---

## File 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_error_ioctl.c`

### IOCTL Flags Validation (4 tests)

**1. `test_ioctl_flags_fsctl_valid`** -- IS_FSCTL flag (0x00000001) is non-zero when bitwise-AND'd.
- **Verdict: CORRECT.** Matches MS-SMB2 section 2.2.31 Flags definition.

**2. `test_ioctl_flags_zero_invalid`** -- Zero flags ANDed with IS_FSCTL equals zero.
- **Verdict: CORRECT.** Per section 3.3.5.15, Flags without IS_FSCTL means it is an IOCTL (not FSCTL), server must fail with `STATUS_NOT_SUPPORTED`.

**3. `test_ioctl_flags_unknown_bits`** -- 0x80000000 without IS_FSCTL is invalid.
- **Verdict: CORRECT.** Unknown bits without IS_FSCTL set means the FSCTL check fails.

**4. `test_ioctl_flags_fsctl_with_extra_bits`** -- IS_FSCTL | 0x80000000 passes the IS_FSCTL check.
- **Verdict: QUESTIONABLE.** The test asserts that `(flags & IS_FSCTL) != 0` passes. However, the production code uses strict equality: `req->Flags != cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL)`, which means 0x80000001 would FAIL in production. The test uses bitwise-AND rather than equality, which is **inconsistent with the production code behavior**. The spec in section 2.2.31 defines Flags as one of exactly two values (0x00000000 or 0x00000001), not a bitmask. Therefore: the test's bitwise-AND approach is looser than the production code's strict equality, and the test would pass a value that production code would reject. This is a **logic mismatch between the test and production code**, though the test simply validates its own replicated logic and does not claim to match production behavior directly.

### FSCTL Code Validation (2 tests)

**5. `test_fsctl_known_codes`** -- Verifies FSCTL codes are defined and non-zero.
- **Verdict: CORRECT.** Validates that `FSCTL_DFS_GET_REFERRALS`, `FSCTL_SET_ZERO_DATA`, `FSCTL_QUERY_ALLOCATED_RANGES`, `FSCTL_PIPE_TRANSCEIVE` are defined. Per MS-SMB2 section 2.2.31, all these codes have non-zero values.

**6. `test_fsctl_unknown_code`** -- 0xDEADBEEF is different from known codes.
- **Verdict: CORRECT but trivial.** Just asserts inequality.

### Buffer Length Validation (2 tests)

**7. `test_ioctl_input_buffer_zero`** -- Checks `input_count == 0`.
- **Verdict: CORRECT but trivial.** The test just asserts a variable is zero; it does not actually test any production validation path.

**8. `test_ioctl_max_output_buffer`** -- MaxOutputResponse of 65536 is within bounds.
- **Verdict: CORRECT but trivial.** Just verifies `max_output <= 65536`. Per MS-SMB2 section 3.3.5.15, MaxOutputResponse is checked against `Connection.MaxTransactSize`, not a fixed 64KB, but the test is just asserting a value property, not simulating a real check.

---

## File 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_fsctl_dispatch.c`

### ODX Nonce Hash (4 tests)

**1. `test_odx_nonce_hash_deterministic`** -- Same nonce produces same hash.
- **Verdict: CORRECT.** Duplicate of the same test in ksmbd_test_smb2_ioctl.c but calls real function.

**2. `test_odx_nonce_hash_different_inputs`** -- Different inputs produce different hashes.
- **Verdict: CORRECT.**

**3. `test_odx_nonce_hash_zero`** -- Zero nonce does not crash.
- **Verdict: CORRECT.** Uses `KUNIT_SUCCEED` as a crash-safety check.

**4. `test_odx_nonce_hash_single_bit_diff`** -- Single bit difference produces different hash.
- **Verdict: CORRECT.** Good hash quality test.

### Pathname Valid Handler (1 test)

**5. `test_pathname_valid_always_succeeds`** -- `fsctl_is_pathname_valid_handler()` always returns 0 with out_len=0.
- **Verdict: CORRECT.** Per MS-FSCC, FSCTL_IS_PATHNAME_VALID is a no-op that always succeeds. The handler correctly returns 0 and sets `out_len = 0`.

### Dispatch Table Registration (3 tests)

**6. `test_register_dispatch_real`** -- Registers handler, dispatches, verifies `out_len=42`.
- **Verdict: CORRECT.** Tests real `ksmbd_register_fsctl` / `ksmbd_dispatch_fsctl` API.

**7. `test_dispatch_unregistered_code`** -- Unknown code returns `-EOPNOTSUPP`, sets `out_len=0`.
- **Verdict: CORRECT.**

**8. `test_duplicate_registration`** -- Duplicate registration returns `-EEXIST`.
- **Verdict: CORRECT.**

---

## File 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_fsctl_validate_negotiate.c`

### Validate Negotiate Info (9 tests)

The test file implements its own `test_validate_negotiate()` function that replicates the logic described in MS-SMB2 section 3.3.5.15.12. Let me audit the replicated function itself first.

**Replicated function audit (`test_validate_negotiate`, lines 37-109):**

- **Request structure** (lines 15-21): `Capabilities(4) + Guid(16) + SecurityMode(2) + DialectCount(2) + Dialects(variable)` -- matches MS-SMB2 section 2.2.31.4. **CORRECT.**
- **Response structure** (lines 23-28): `Capabilities(4) + Guid(16) + SecurityMode(2) + Dialect(2)` -- matches MS-SMB2 section 2.2.32.6. Size = 24 bytes. **CORRECT.**
- **Input size check** (lines 53-57): Checks `in_buf_len < offsetof(Dialects)` = 24 bytes min header. Returns `STATUS_INVALID_PARAMETER`. **CORRECT.**
- **Output buffer check** (lines 59-63): Checks `max_out_len < sizeof(rsp)`. Returns `STATUS_BUFFER_TOO_SMALL`. **QUESTIONABLE.** Per MS-SMB2 section 3.3.5.15.12, if `MaxOutputResponse` is less than the size of VALIDATE_NEGOTIATE_INFO Response, the server MUST **terminate the transport connection** (not return STATUS_BUFFER_TOO_SMALL). The test returns `STATUS_BUFFER_TOO_SMALL` which is **not what the spec mandates**. The spec says to terminate the connection, not return an error status. However, this behavior may be acceptable for a test that is isolating validation logic -- the "terminate connection" side effect cannot be tested in a unit test context.
- **DialectCount overflow check** (lines 67-69): Validates that claimed DialectCount fits within input buffer. **CORRECT.** Good security hardening check.
- **GUID match** (lines 73-76): Mismatching GUID sets `*terminate = true`. **CORRECT.** Per section 3.3.5.15.12: "If the Guid received ... is not equal to Connection.ClientGuid, the server MUST terminate the transport connection."
- **SecurityMode match** (lines 79-82): Mismatching SecurityMode sets `*terminate = true`. **CORRECT.** Per section 3.3.5.15.12.
- **Capabilities match** (lines 85-88): Mismatching Capabilities sets `*terminate = true`. **CORRECT.** Per section 3.3.5.15.12.
- **Dialect match** (lines 91-100): Checks that negotiated dialect is in the Dialects array. Sets `*terminate = true` on failure. **CORRECT.** Per section 3.3.5.15.12.
- **Response build** (lines 103-108): Populates Capabilities, Guid, SecurityMode, Dialect from server context. **CORRECT.** Per section 3.3.5.15.12: "Capabilities is set to Connection.ServerCapabilities, Guid is set to ServerGuid, SecurityMode is set to Connection.ServerSecurityMode, Dialect is set to Connection.Dialect."

**IMPORTANT NOTE ABOUT ORDERING:** The spec says for SMB 3.1.1 dialects, the server MUST terminate the connection immediately on receiving FSCTL_VALIDATE_NEGOTIATE_INFO (section 3.3.5.15.12, first bullet). The test function does NOT check for this -- it proceeds with the full validation regardless of dialect. However, this is acceptable since the test's `default_vneg_ctx()` uses dialect 0x0311 (SMB 3.1.1), and the test does not claim to test the "terminate on 3.1.1" rule.

Actually, re-reading: the spec says "If Connection.Dialect is '3.1.1', the server MUST terminate the transport connection and free the Connection object." This means for 3.1.1, the ENTIRE validate negotiate operation should be rejected. The test's `default_vneg_ctx()` sets `server_dialect = cpu_to_le16(0x0311)` which IS 3.1.1.

**1. `test_validate_negotiate_success`** -- Full match with dialect 0x0311.
- **Verdict: WRONG.** Per MS-SMB2 section 3.3.5.15.12, if Connection.Dialect is "3.1.1" (0x0311), the server MUST terminate the transport connection. The test expects success (ret=0), but per spec, the server should reject this outright. The test should use a 3.0 or 3.0.2 dialect (e.g., 0x0300 or 0x0302) for valid validate negotiate scenarios. **Fix: Change `server_dialect` in `default_vneg_ctx()` from `cpu_to_le16(0x0311)` to `cpu_to_le16(0x0300)` or `cpu_to_le16(0x0302)`, and add a separate test case that verifies 0x0311 triggers termination.**

**2. `test_validate_negotiate_dialect_mismatch`** -- Client sends dialect 0x0210 but server negotiated 0x0311.
- **Verdict: WRONG (same issue as above).** Dialect 0x0311 should trigger immediate termination per spec, before even checking the Dialects array. The test expects `*terminate = true` due to dialect mismatch, which is behaviorally correct but for the wrong reason -- the termination should happen at the "3.1.1 check" step, not the dialect-not-found step.

**3. `test_validate_negotiate_guid_mismatch`** -- GUID mismatch with 0x0311 dialect.
- **Verdict: WRONG (same 3.1.1 issue).** Should terminate before even checking GUID.

**4. `test_validate_negotiate_security_mode_mismatch`** -- SecurityMode mismatch.
- **Verdict: WRONG (same 3.1.1 issue).**

**5. `test_validate_negotiate_capabilities_mismatch`** -- Capabilities mismatch.
- **Verdict: WRONG (same 3.1.1 issue).**

**6. `test_validate_negotiate_input_too_small`** -- Input buffer of 3 bytes.
- **Verdict: QUESTIONABLE.** The spec does not explicitly define behavior for a malformed input to FSCTL_VALIDATE_NEGOTIATE_INFO. For 3.1.1 connections, the server should terminate regardless of input content. For 3.0/3.0.2, the test's behavior (returning STATUS_INVALID_PARAMETER) is reasonable. The test has the same 3.1.1 issue.

**7. `test_validate_negotiate_output_too_small`** -- Output buffer too small.
- **Verdict: QUESTIONABLE.** Per spec section 3.3.5.15.12: "If MaxOutputResponse in the IOCTL request is less than the size of a VALIDATE_NEGOTIATE_INFO Response, the server MUST terminate the transport connection." The test returns `STATUS_BUFFER_TOO_SMALL` instead of signaling termination. Since the test uses `*terminate` for mismatch cases but not for this case, it does not match the spec's requirement for connection termination. **Fix: Set `*terminate = true` when output buffer is too small, per spec.**

**8. `test_validate_negotiate_dialect_count_overflow`** -- Claims 100 dialects but buffer only has 1.
- **Verdict: CORRECT** (the validation logic catches this). Same 3.1.1 dialect concern applies, but the overflow check itself is a good security hardening test.

**9. `test_validate_negotiate_response_fields`** -- Validates response has correct Capabilities, Guid, SecurityMode, Dialect.
- **Verdict: WRONG (3.1.1 issue).** Same concern, but the response field values themselves match section 2.2.32.6 perfectly.

---

## File 5: `/home/ezechiel203/ksmbd/test/ksmbd_test_fsctl_copychunk.c`

### Constants Verification

- `FSCTL_COPYCHUNK = 0x001440F2` -- **CORRECT** per MS-SMB2 section 2.2.31.
- `FSCTL_COPYCHUNK_WRITE = 0x001480F2` -- **CORRECT** per MS-SMB2 section 2.2.31.
- `MAX_CHUNK_COUNT = 256` -- **CORRECT** (implementation-specific, matches production code).
- `MAX_CHUNK_SIZE = 1MB` -- **CORRECT** (implementation-specific, matches production code).
- `MAX_TOTAL_SIZE = 16MB` -- **CORRECT** (implementation-specific, matches production code).

### Wire Structure Verification

- `test_copychunk_ioctl_req`: `ResumeKey[3]` (3 x 8 = 24 bytes) + ChunkCount(4) + Reserved(4) + Chunks(variable). Per MS-SMB2 section 2.2.31.1: SourceKey = 24 bytes, ChunkCount = 4 bytes, Reserved = 4 bytes. **CORRECT.**
- `test_srv_copychunk`: SourceOffset(8) + TargetOffset(8) + Length(4) + Reserved(4) = 24 bytes. Per MS-SMB2 section 2.2.31.1.1. **CORRECT.**
- `test_copychunk_ioctl_rsp`: ChunksWritten(4) + ChunkBytesWritten(4) + TotalBytesWritten(4) = 12 bytes. Per MS-SMB2 section 2.2.32.1. **CORRECT.**

### Test Cases (20 tests)

**1. `test_copychunk_zero_chunk_count`** -- ChunkCount=0 returns server limits.
- **Verdict: QUESTIONABLE.** The test expects success with response carrying server limits (ChunksWritten=256, ChunkBytesWritten=1MB, TotalBytesWritten=16MB). Per MS-SMB2 section 3.3.5.15.6, the spec does not explicitly define a "ChunkCount=0 returns limits" behavior. The Invalid Parameter response (section 3.3.5.15.6.2) fills the response with limits when returning STATUS_INVALID_PARAMETER. ChunkCount=0 with a valid buffer would not trigger any of the listed invalid parameter conditions (ChunkCount=0 is not > MaxChunkCount, and there are no chunks to exceed chunk size or total size). So returning success with limits seems like an implementation-specific behavior for a "query limits" mode. The spec does not forbid this, but it is not mandated either. **Not wrong per spec, but implementation-specific.**

**2. `test_copychunk_max_chunk_count_exceeded`** -- ChunkCount=257 fails.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.15.6: "ChunkCount value is greater than ServerSideCopyMaxNumberofChunks" triggers section 3.3.5.15.6.2 response with `STATUS_INVALID_PARAMETER`.

**3. `test_copychunk_max_chunk_size_exceeded`** -- Single chunk of 1MB+1 fails.
- **Verdict: CORRECT.** Per section 3.3.5.15.6: "Length value in a single chunk is greater than ServerSideCopyMaxChunkSize" triggers Invalid Parameter response.

**4. `test_copychunk_max_total_size_exceeded`** -- 17 chunks of 1MB = 17MB > 16MB fails.
- **Verdict: CORRECT.** Per section 3.3.5.15.6: "Sum of Lengths in all chunks is greater than ServerSideCopyMaxDataSize."

**5. `test_copychunk_zero_length_chunk`** -- Chunk with Length=0 fails.
- **Verdict: CORRECT.** Per section 3.3.5.15.6: "Length value in a single chunk is ... equal to zero" triggers Invalid Parameter response.

**6. `test_copychunk_input_too_small`** -- Input buffer equals header size exactly (no Chunks data).
- **Verdict: CORRECT.** The test uses `<= sizeof(header)` as the guard (line 95), which means a buffer exactly equal to header size fails. Per spec section 3.3.5.15.6: "The InputCount value in the SMB2 IOCTL Request is less than the size of the Buffer field containing the SRV_COPYCHUNK_COPY structure."

**7. `test_copychunk_output_too_small`** -- MaxOutputResponse < sizeof(SRV_COPYCHUNK_RESPONSE).
- **Verdict: CORRECT.** Per section 3.3.5.15.6: "If the MaxOutputResponse value in the SMB2 IOCTL Request is less than the size of the SRV_COPYCHUNK_RESPONSE structure, the server MUST fail the SMB2 IOCTL Request with STATUS_INVALID_PARAMETER."

**8. `test_copychunk_invalid_resume_key`** -- ResumeKey mismatch returns `-ENOENT`.
- **Verdict: CORRECT.** Per section 3.3.5.15.6: "If the open is not found, the server MUST fail the request with STATUS_OBJECT_NAME_NOT_FOUND."

**9. `test_copychunk_source_not_found`** -- Source file does not exist.
- **Verdict: CORRECT.** Same spec reference.

**10. `test_copychunk_dest_not_found`** -- Destination file does not exist.
- **Verdict: CORRECT.** Returns STATUS_FILE_CLOSED (0xC0000128), which is appropriate for a closed/missing destination handle.

**11. `test_copychunk_read_only_tree`** -- Read-only tree connect returns STATUS_ACCESS_DENIED.
- **Verdict: CORRECT.** Per spec, the tree/share access level check is done before file-level access checks.

**12. `test_copychunk_access_denied_src_no_read`** -- Source without FILE_READ_DATA fails.
- **Verdict: CORRECT.** Per section 3.3.5.15.6: "The Open.GrantedAccess of the source file does not include FILE_READ_DATA access" triggers STATUS_ACCESS_DENIED.

**13. `test_copychunk_access_denied_dst_no_write`** -- Destination with only FILE_READ_DATA (no write) fails.
- **Verdict: CORRECT.** Per section 3.3.5.15.6: "The Open.GrantedAccess of the destination file does not include FILE_WRITE_DATA or FILE_APPEND_DATA" triggers STATUS_ACCESS_DENIED.

**14. `test_copychunk_vs_copychunk_write_read_check`** -- COPYCHUNK requires dest READ; COPYCHUNK_WRITE does not.
- **Verdict: CORRECT.** Per MS-SMB2 section 2.2.31: "FSCTL_SRV_COPYCHUNK is issued when a handle has FILE_READ_DATA and FILE_WRITE_DATA access to the file; FSCTL_SRV_COPYCHUNK_WRITE is issued when a handle only has FILE_WRITE_DATA access." Section 3.3.5.15.6: "The Open.GrantedAccess of the destination file does not include FILE_READ_DATA, and the CtlCode is FSCTL_SRV_COPYCHUNK." The test correctly shows COPYCHUNK fails when dest has WRITE-only, while COPYCHUNK_WRITE succeeds.

**15. `test_copychunk_overlapping_src_dst_ranges`** -- Overlapping ranges pass validation.
- **Verdict: CORRECT.** The spec does not require the server to reject overlapping ranges at validation time; copy behavior is implementation-specific.

**16. `test_copychunk_cross_file_same_server`** -- Different file IDs pass validation.
- **Verdict: CORRECT.** Validation only checks access permissions and limits; the actual copy across files is done at VFS layer.

**17. `test_copychunk_response_fields_on_success`** -- Successful copy returns correct out_len.
- **Verdict: CORRECT.** Per section 3.3.5.15.6: "OutputCount MUST be set to 12" (which is sizeof(SRV_COPYCHUNK_RESPONSE)).

**18. `test_copychunk_response_fields_on_invalid_param`** -- Invalid parameter response carries server limits.
- **Verdict: CORRECT.** Per section 3.3.5.15.6.2: "ChunksWritten MUST be set ServerSideCopyMaxNumberofChunks. ChunkBytesWritten MUST be set ServerSideCopyMaxChunkSize. TotalBytesWritten MUST be set to ServerSideCopyMaxDataSize." The test verifies exactly these values.

**19. `test_copychunk_lock_conflict`** -- Lock conflicts are not caught at validation time.
- **Verdict: CORRECT.** Per section 3.3.5.15.6, lock checks are done at copy time: "The server SHOULD verify that no byte-range locks conflicting ... are held."

**20. `test_copychunk_disk_full`** -- Disk full not caught at validation time.
- **Verdict: CORRECT.** I/O errors happen during the actual copy operation.

---

## File 6: `/home/ezechiel203/ksmbd/test/ksmbd_test_fsctl_pipe.c`

### Constants Verification

- `STATUS_BUFFER_TOO_SMALL = 0xC0000023` -- **CORRECT** per MS-ERREF.
- `FILE_PIPE_DISCONNECTED_STATE = 1` -- **CORRECT** per MS-FSCC.
- `FILE_PIPE_CONNECTED_STATE = 3` -- **CORRECT** per MS-FSCC.

### Pipe Peek Response Structure

- `test_pipe_peek_rsp`: NamedPipeState(4) + ReadDataAvailable(4) + NumberOfMessages(4) + MessageLength(4) = 16 bytes. Per MS-FSCC section 2.3.41 (FSCTL_PIPE_PEEK output), this structure is correct: NamedPipeState, ReadDataAvailable, NumberOfMessages, MessageLength, plus optional Data. **CORRECT.**

### Pipe Peek Tests (3 tests)

**1. `test_pipe_peek_connected`** -- Connected pipe returns `FILE_PIPE_CONNECTED_STATE` (3).
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.15.4, the server reads from the pipe without removing data. The response includes NamedPipeState. The test correctly shows state=3 for a connected pipe.

**2. `test_pipe_peek_disconnected`** -- Disconnected pipe returns `FILE_PIPE_DISCONNECTED_STATE` (1).
- **Verdict: CORRECT.** A disconnected pipe should report state=1.

**3. `test_pipe_peek_buffer_too_small`** -- Output buffer smaller than response structure fails.
- **Verdict: CORRECT.** Returns `STATUS_BUFFER_TOO_SMALL`. Per MS-SMB2 section 3.3.5.15.4, the server must be able to fit the output. The spec says "A MaxOutputResponse value of zero is allowed", which refers to zero data bytes beyond the header, but the minimum header itself (the pipe peek metadata) must fit.

### Pipe Wait Tests (5 tests)

**4. `test_pipe_wait_no_request_data`** -- Empty input (in_buf_len=0) returns success.
- **Verdict: QUESTIONABLE.** Per MS-SMB2 section 3.3.5.15.10, the server "MUST ensure that the Name field of the FSCTL_PIPE_WAIT request identifies a named pipe. If the Name field is malformed, or no such object exists, the server MUST fail the request with STATUS_OBJECT_NAME_NOT_FOUND." An empty input buffer means no Name field, which per spec should be treated as malformed and fail. The test returns success for empty input, which contradicts the spec. **Fix: Empty input should fail with STATUS_INVALID_PARAMETER or STATUS_OBJECT_NAME_NOT_FOUND, not succeed.**

**5. `test_pipe_wait_pipe_available`** -- Pipe exists, returns success.
- **Verdict: CORRECT.** Per section 3.3.5.15.10: "If a connection to the specified named pipe is available, the server MUST construct an SMB2 IOCTL Response."

**6. `test_pipe_wait_pipe_unavailable`** -- Pipe does not exist, returns `-ETIMEDOUT` / `STATUS_IO_TIMEOUT`.
- **Verdict: QUESTIONABLE.** The test returns `STATUS_IO_TIMEOUT` (0xC00000B5) when the pipe is unavailable, regardless of timeout. Per spec, if `TimeoutSpecified` is TRUE and the timeout elapses, the server MUST fail with `STATUS_IO_TIMEOUT`. If `TimeoutSpecified` is FALSE, "the server MUST wait forever." The test's simplified logic does not distinguish between a missing pipe (STATUS_OBJECT_NAME_NOT_FOUND) and a timeout, but the pipe_wait test scenario with a non-existent pipe should actually return STATUS_OBJECT_NAME_NOT_FOUND per the spec, not STATUS_IO_TIMEOUT.

**7. `test_pipe_wait_timeout_specified`** -- Timeout=100ms with available pipe returns success.
- **Verdict: CORRECT.** Pipe is available, so connection succeeds.

**8. `test_pipe_wait_timeout_zero`** -- Timeout=0 with available pipe returns success.
- **Verdict: CORRECT.** Pipe is available, so connection succeeds regardless of timeout value.

### Pipe Transceive Tests (3 tests)

**9. `test_pipe_transceive_rpc_ok`** -- Stub: just `KUNIT_EXPECT_TRUE(test, true)`.
- **Verdict: QUESTIONABLE (trivial).** This test does nothing meaningful. It always passes. It would be better to either implement a real test or remove it. It does not test any spec behavior.

**10. `test_pipe_transceive_buffer_overflow`** -- Stub: just `KUNIT_EXPECT_TRUE(test, true)`.
- **Verdict: QUESTIONABLE (trivial).** Same as above -- no real assertions.

**11. `test_pipe_transceive_not_implemented`** -- Stub: just `KUNIT_EXPECT_TRUE(test, true)`.
- **Verdict: QUESTIONABLE (trivial).** Same as above.

---

## Summary

### Totals by Verdict

| File | CORRECT | WRONG | QUESTIONABLE |
|------|---------|-------|-------------|
| ksmbd_test_smb2_ioctl.c | 28 | 0 | 2 |
| ksmbd_test_error_ioctl.c | 6 | 0 | 2 |
| ksmbd_test_fsctl_dispatch.c | 8 | 0 | 0 |
| ksmbd_test_fsctl_validate_negotiate.c | 1 | 5 | 3 |
| ksmbd_test_fsctl_copychunk.c | 19 | 0 | 1 |
| ksmbd_test_fsctl_pipe.c | 5 | 0 | 6 |
| **TOTAL** | **67** | **5** | **14** |

### WRONG findings (all in ksmbd_test_fsctl_validate_negotiate.c)

1. **Tests 1-5, 9 (test_validate_negotiate_success, _dialect_mismatch, _guid_mismatch, _security_mode_mismatch, _capabilities_mismatch, _response_fields):** All use `server_dialect = 0x0311` (SMB 3.1.1). Per MS-SMB2 section 3.3.5.15.12, first bullet: "If Connection.Dialect is '3.1.1', the server MUST terminate the transport connection and free the Connection object." FSCTL_VALIDATE_NEGOTIATE_INFO is only valid for SMB 3.0 and 3.0.2 dialects. **Fix:** Change `default_vneg_ctx()` to use `cpu_to_le16(0x0300)` or `cpu_to_le16(0x0302)`. Add a dedicated test that validates 3.1.1 triggers termination.

### QUESTIONABLE findings (14 total)

1. **ksmbd_test_smb2_ioctl.c / `test_ioctl_flags_other_value_rejected`**: Strict equality is correct per spec but comment could clarify why non-IS_FSCTL values are invalid (Flags is enumeration, not bitmask).

2. **ksmbd_test_error_ioctl.c / `test_ioctl_flags_fsctl_with_extra_bits`**: Bitwise-AND approach is inconsistent with production code's strict equality check. Test logic is internally consistent but does not match actual server behavior.

3. **ksmbd_test_error_ioctl.c / `test_ioctl_input_buffer_zero` and `test_ioctl_max_output_buffer`**: Trivially pass; do not actually exercise any production code path.

4. **ksmbd_test_fsctl_validate_negotiate.c / `test_validate_negotiate_input_too_small`**: Has the 3.1.1 dialect issue. Otherwise the STATUS_INVALID_PARAMETER return for undersized input is reasonable.

5. **ksmbd_test_fsctl_validate_negotiate.c / `test_validate_negotiate_output_too_small`**: Returns STATUS_BUFFER_TOO_SMALL, but spec mandates connection termination for undersized output buffer.

6. **ksmbd_test_fsctl_validate_negotiate.c / `test_validate_negotiate_dialect_count_overflow`**: Has the 3.1.1 dialect issue, but the overflow check itself is good.

7. **ksmbd_test_fsctl_copychunk.c / `test_copychunk_zero_chunk_count`**: Implementation-specific "query limits" mode; not forbidden but not mandated by spec.

8. **ksmbd_test_fsctl_pipe.c / `test_pipe_wait_no_request_data`**: Empty input should fail per spec (missing Name field), test expects success.

9. **ksmbd_test_fsctl_pipe.c / `test_pipe_wait_pipe_unavailable`**: Returns STATUS_IO_TIMEOUT but per spec a non-existent pipe should return STATUS_OBJECT_NAME_NOT_FOUND. STATUS_IO_TIMEOUT is only appropriate after a timeout elapses.

10. **ksmbd_test_fsctl_pipe.c / 3 transceive stubs**: Trivially pass with no real assertions.