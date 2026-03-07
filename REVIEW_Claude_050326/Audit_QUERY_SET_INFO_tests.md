# Audit Query Set Info Tests

Agent ID: a7814fae54527bc84

4*8 + 2*4 = 32+8 = 40 bytes. Correct.

Now let me also check how the error test file's `test_err_buffer_check_sets_status` expects `STATUS_INFO_LENGTH_MISMATCH`. With `buffer_check_err(10, rsp, rsp_org)` -- this is 3 args but the function takes 4. This will not compile. But if we imagine it being called with min_output_length=0 (or some default), then reqOutputBufferLength(10) >= min_output_length(0), so it passes the first check. Then reqOutputBufferLength(10) < OutputBufferLength(100), so it hits `STATUS_BUFFER_OVERFLOW`, NOT `STATUS_INFO_LENGTH_MISMATCH`.

Now I have all the information to produce the comprehensive audit report.

---

# AUDIT REPORT: KSMBD KUnit Test Files vs. MS-SMB2 Specification

## File 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_query_set.c`

This file tests `buffer_check_err()`, pipe info helpers, file info class constants, structure sizes, set_file_mode_info validation, and get_file_access_info.

### buffer_check_err tests (10 test cases)

**test_buffer_check_err_sufficient** -- Tests reqOutputBufferLength(100) >= OutputBufferLength(40) with min_output_length=0. Expects return 0.
- **CORRECT.** Per MS-SMB2 section 3.3.5.20.1: if OutputBufferLength fits within the requested buffer, the operation succeeds.

**test_buffer_check_err_exact** -- Tests reqOutputBufferLength(40) == OutputBufferLength(40) with min_output_length=0. Expects return 0.
- **CORRECT.** Exact match is valid.

**test_buffer_check_err_insufficient** -- Tests reqOutputBufferLength(10) < OutputBufferLength(100) with min_output_length=0. Expects return -EINVAL.
- **QUESTIONABLE.** The test expects -EINVAL, but the production code returns -EINVAL AND sets STATUS_BUFFER_OVERFLOW. Per MS-SMB2 section 3.3.5.20.1, the spec says the server "MUST construct a response... but set the Status field in the SMB2 header to STATUS_BUFFER_OVERFLOW" -- it does NOT say to fail with -EINVAL. However, this is an internal kernel return code, not a wire status, so the behavior depends on the caller. The test correctly checks the return value, but does not verify the hdr.Status is STATUS_BUFFER_OVERFLOW. **Recommend adding a STATUS_BUFFER_OVERFLOW assertion for completeness.**

**test_buffer_check_err_status_set** -- Tests that when reqOutputBufferLength(10) < OutputBufferLength(100), the rsp->hdr.Status becomes STATUS_BUFFER_OVERFLOW.
- **CORRECT.** Per MS-SMB2 section 3.3.5.20.1: "set the Status field in the SMB2 header to STATUS_BUFFER_OVERFLOW."

**test_buffer_check_err_zero_output** -- Tests reqOutputBufferLength(0) and OutputBufferLength(0) with min_output_length=0. Expects return 0.
- **CORRECT.** Zero-length queries are permitted to succeed when no output is requested or produced.

**test_buffer_check_err_min_output_too_small** -- Tests reqOutputBufferLength(10) < min_output_length(20). Expects -EINVAL with STATUS_INFO_LENGTH_MISMATCH.
- **CORRECT.** Per MS-SMB2 section 3.3.5.20.1: "If the OutputBufferLength given in the client request is zero or is insufficient to hold the fixed length part of the information requested, the server MUST fail the request with STATUS_INFO_LENGTH_MISMATCH."

**test_buffer_check_err_min_output_exact** -- Tests reqOutputBufferLength(20) == min_output_length(20) and OutputBufferLength(10) <= req. Expects return 0.
- **CORRECT.** Exact match of minimum passes the fixed-length check, and output fits.

**test_buffer_check_err_overflow_status** -- Tests reqOutputBufferLength(50) >= min_output_length(4) but < OutputBufferLength(100). Expects STATUS_BUFFER_OVERFLOW.
- **CORRECT.** Per MS-SMB2 section 3.3.5.20.1.

**test_buffer_check_err_large_values** -- Tests reqOutputBufferLength(2000) >= OutputBufferLength(1000). Expects return 0.
- **CORRECT.**

**test_buffer_check_err_multiple_calls** -- Two sequential calls: first succeeds, second fails. Tests state is independent.
- **CORRECT.**

### buffer_check_err boundary tests (3 test cases)

**test_buffer_check_err_min_equals_req_equals_output** -- All three equal to 50. Expects 0.
- **CORRECT.**

**test_buffer_check_err_min_gt_req_gt_output** -- req(30) < min(50). Expects -EINVAL with STATUS_INFO_LENGTH_MISMATCH.
- **CORRECT.** Per MS-SMB2 section 3.3.5.20.1.

**test_buffer_check_err_header_written** -- Checks that rsp_org gets sizeof(smb2_hdr) in big-endian on error.
- **CORRECT.** This is a ksmbd internal behavior (4-byte TCP length prefix), not directly spec-mandated, but the test accurately checks the production code's contract.

### Pipe info tests (9 test cases)

**test_standard_info_pipe_alloc** -- Checks AllocationSize=4096, EndOfFile=0, NumberOfLinks=1, DeletePending=1, Directory=0.
- **CORRECT.** Per MS-FSCC FileStandardInformation: pipes have AllocationSize representing pipe buffer size, EndOfFile=0, one link, always delete-pending, never a directory. These are reasonable defaults for a named pipe.

**test_standard_info_pipe_output_len** -- Checks OutputBufferLength == sizeof(smb2_file_standard_info).
- **CORRECT.** The output must be exactly the size of the FileStandardInformation structure.

**test_standard_info_pipe_not_directory** -- Directory=0, DeletePending=1.
- **CORRECT.**

**test_standard_info_pipe_all_fields** -- Poisons buffer, then checks all fields written correctly.
- **CORRECT.**

**test_internal_info_pipe_index** -- num=42, expects IndexNumber = 42 | (1<<63).
- **CORRECT.** The bit-63 OR is a ksmbd convention to distinguish pipe IDs from file inode numbers. Not directly spec-mandated, but a valid implementation choice.

**test_internal_info_pipe_zero** -- num=0, expects IndexNumber = (1<<63).
- **CORRECT.**

**test_internal_info_pipe_output_len** -- OutputBufferLength == sizeof(smb2_file_internal_info) == 8 bytes.
- **CORRECT.** Per MS-FSCC FileInternalInformation: 8 bytes (single UINT64).

**test_internal_info_pipe_large_num** -- num=0x7FFFFFFFFFFFFFFFULL. Result should be num | (1<<63).
- **CORRECT.**

**test_internal_info_pipe_max_u64** -- num=0xFFFFFFFFFFFFFFFFULL. Result should be U64_MAX (bit 63 already set).
- **CORRECT.**

### Additional pipe/info boundary tests (4 test cases)

**test_internal_info_pipe_bit63_set_in_input** -- Verifies OR is idempotent when bit 63 already set.
- **CORRECT.**

**test_internal_info_pipe_powers_of_two** -- Loops 0..62, verifies bit-63 OR for each.
- **CORRECT.**

**test_pipe_queries_sequential** -- Tests sequential pipe info queries.
- **CORRECT.**

**test_alignment_info_after_ea_info** -- Tests sequential info queries overwrite each other.
- **CORRECT.**

### FileInfoClass constants (12 test cases)

These tests verify the numeric values of FileInfoClass constants against MS-FSCC section 2.4.

| Test | Constant | Expected | MS-FSCC Value | Verdict |
|------|----------|----------|---------------|---------|
| test_file_info_class_basic | FILE_BASIC_INFORMATION | 4 | 4 | **CORRECT** |
| test_file_info_class_standard | FILE_STANDARD_INFORMATION | 5 | 5 | **CORRECT** |
| test_file_info_class_internal | FILE_INTERNAL_INFORMATION | 6 | 6 | **CORRECT** |
| test_file_info_class_ea | FILE_EA_INFORMATION | 7 | 7 | **CORRECT** |
| test_file_info_class_access | FILE_ACCESS_INFORMATION | 8 | 8 | **CORRECT** |
| test_file_info_class_position | FILE_POSITION_INFORMATION | 14 | 14 | **CORRECT** |
| test_file_info_class_mode | FILE_MODE_INFORMATION | 16 | 16 | **CORRECT** |
| test_file_info_class_alignment | FILE_ALIGNMENT_INFORMATION | 17 | 17 | **CORRECT** |
| test_file_info_class_all | FILE_ALL_INFORMATION | 18 | 18 | **CORRECT** |
| test_file_info_class_compression | FILE_COMPRESSION_INFORMATION | 28 | 28 | **CORRECT** |
| test_file_info_class_network_open | FILE_NETWORK_OPEN_INFORMATION | 34 | 34 | **CORRECT** |
| test_file_info_class_attribute_tag | FILE_ATTRIBUTE_TAG_INFORMATION | 35 | 35 | **CORRECT** |

All 12 FileInfoClass enum values match MS-FSCC section 2.4 exactly.

### Structure size and encoding tests (12 test cases)

| Test | Structure | Expected Size | Actual Computation | Verdict |
|------|-----------|---------------|-------------------|---------|
| test_file_pos_info_struct_size | smb2_file_pos_info | 8 bytes | UINT64 CurrentByteOffset = 8 | **CORRECT** per MS-FSCC 2.4.40 |
| test_file_mode_info_struct_size | smb2_file_mode_info | 4 bytes | UINT32 Mode = 4 | **CORRECT** per MS-FSCC 2.4.29 |
| test_file_comp_info_struct_size | smb2_file_comp_info | 16 bytes | 8+2+1+1+1+3 = 16 | **CORRECT** per MS-FSCC 2.4.8 |
| test_file_ea_info_struct_size | smb2_file_ea_info | 4 bytes | UINT32 EASize = 4 | **CORRECT** per MS-FSCC 2.4.12 |
| test_file_access_info_struct_size | smb2_file_access_info | 4 bytes | UINT32 AccessFlags = 4 | **CORRECT** per MS-FSCC 2.4.1 |
| test_file_alloc_info_struct_size | smb2_file_alloc_info | 8 bytes | UINT64 AllocationSize = 8 | **CORRECT** per MS-FSCC 2.4.3 |
| test_file_disposition_info_struct_size | smb2_file_disposition_info | 1 byte | BOOLEAN DeletePending = 1 | **CORRECT** per MS-FSCC 2.4.10 |
| test_file_attr_tag_info_struct_size | smb2_file_attr_tag_info | 8 bytes | UINT32+UINT32 = 8 | **CORRECT** per MS-FSCC 2.4.5 |
| test_file_standard_info_struct_size | smb2_file_standard_info | 24 bytes | 8+8+4+1+1+2 = 24 | **CORRECT** per MS-FSCC 2.4.47 (includes Reserved padding) |
| test_file_internal_info_struct_size | smb2_file_internal_info | 8 bytes | UINT64 IndexNumber = 8 | **CORRECT** per MS-FSCC 2.4.22 |
| test_file_basic_info_struct_size | smb2_file_basic_info | 40 bytes | 4*8+4+4 = 40 | **CORRECT** per MS-FSCC 2.4.6 |
| test_file_ntwrk_info_struct_size | smb2_file_ntwrk_info | 56 bytes | 6*8+2*4 = 56 | **CORRECT** per MS-FSCC 2.4.30 |

**test_file_pos_info_encoding** -- Tests le64 endian round-trip.
- **CORRECT.** Verifies correct wire encoding.

**test_file_mode_info_mask_value** -- FILE_MODE_INFO_MASK == 0x0000103e.
- **CORRECT.** Per MS-FSCC 2.4.29: valid bits are FILE_WRITE_THROUGH(0x02) | FILE_SEQUENTIAL_ONLY(0x04) | FILE_NO_INTERMEDIATE_BUFFERING(0x08) | FILE_SYNCHRONOUS_IO_ALERT(0x10) | FILE_SYNCHRONOUS_IO_NONALERT(0x20) | FILE_DELETE_ON_CLOSE(0x1000) = 0x103e.

**test_file_mode_info_invalid_bits_masked** -- 0xFFFF103e & 0x103e == 0x103e.
- **CORRECT.**

**test_compression_format_none** -- 0x0000.
- **CORRECT** per MS-FSCC.

**test_compression_format_lznt1** -- 0x0002.
- **CORRECT** per MS-FSCC.

### Alignment info tests (3 test cases)

**test_alignment_info_zero** -- AlignmentRequirement = 0.
- **CORRECT.** Per MS-FSCC 2.4.2: FILE_BYTE_ALIGNMENT (0) indicates byte-aligned access.

**test_alignment_info_output_len** -- OutputBufferLength = sizeof(smb2_file_alignment_info) = 4.
- **CORRECT.**

**test_alignment_info_idempotent** -- Two calls give same result.
- **CORRECT.**

### EA info tests (5 test cases)

**test_ea_info_no_fp** -- With NULL fp, EASize=0.
- **CORRECT.** When there's no file pointer, extended attributes cannot be queried, so EASize=0 is the safe default.

**test_ea_info_output_len** -- OutputBufferLength = sizeof(smb2_file_ea_info) = 4.
- **CORRECT.**

**test_ea_info_null_fp_ea_size_zero** -- Same as above, redundant but correct.
- **CORRECT.**

**test_ea_info_output_buffer_length** -- Same check, redundant.
- **CORRECT.**

**test_ea_info_null_fp_repeated** -- Poisons buffer, calls again, still EASize=0.
- **CORRECT.**

### get_file_access_info tests (5 test cases)

**test_access_info_read_daccess** -- Tests daccess=0x001F01FF echoed as AccessFlags.
- **CORRECT.** Per MS-FSCC 2.4.1: FileAccessInformation returns the access flags from the open.

**test_access_info_output_len** -- OutputBufferLength = sizeof(smb2_file_access_info) = 4.
- **CORRECT.**

**test_access_info_zero_daccess** -- daccess=0 returns AccessFlags=0.
- **CORRECT.**

**test_access_info_max_daccess** -- daccess=0xFFFFFFFF returns 0xFFFFFFFF.
- **CORRECT.** (Though such a value is not a valid combination of access rights, the function correctly mirrors the stored value.)

**test_access_info_read_only** -- Tests FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES.
- **QUESTIONABLE.** The test computes daccess as `0x00000081 | 0x00000008 | 0x00000080 = 0x00000089`. However, FILE_READ_DATA=0x01, FILE_READ_EA=0x08, FILE_READ_ATTRIBUTES=0x80. The value 0x81 is FILE_READ_DATA(0x01) | FILE_READ_ATTRIBUTES(0x80) = 0x81. Then OR with 0x08 = 0x89, and OR with 0x80 = 0x89 (already set). So daccess=0x89. But the comment says `0x00000081 | 0x00000008 | 0x00000080` which equals 0x89. The comment "FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES" does not match the values: 0x81 is not FILE_READ_DATA alone (0x01); it appears to be FILE_READ_DATA | FILE_READ_ATTRIBUTES combined. The test itself is functionally correct (it verifies echoing), but **the comment/decomposition is misleading**. The actual flags for FILE_READ_DATA=0x01, FILE_READ_EA=0x08, FILE_READ_ATTRIBUTES=0x80, and 0x01|0x08|0x80=0x89, but the code writes `0x00000081 | 0x00000008 | 0x00000080` which is 0x89 as well but via a confusing decomposition where 0x81 is already 0x01|0x80.

### set_file_mode_info validation tests (5 test cases)

**test_set_mode_invalid_bits_rejected** -- Mode=0x00008000 (outside mask). Expects -EINVAL.
- **CORRECT.** Per MS-FSCC 2.4.29: only bits in FILE_MODE_INFO_MASK are valid.

**test_set_mode_conflicting_sync_flags** -- Mode=0x30 (both SYNCHRONOUS_IO_ALERT and SYNCHRONOUS_IO_NONALERT). Expects -EINVAL.
- **CORRECT.** Per MS-FSCC 2.4.29: these two flags are mutually exclusive.

**test_set_mode_all_invalid_bits** -- Mode=0xFFFFFFFF. Expects -EINVAL.
- **CORRECT.** Contains invalid bits outside the mask.

**test_set_mode_high_bit_invalid** -- Mode=0x80000000. Expects -EINVAL.
- **CORRECT.**

**test_set_mode_bit1_invalid** -- Mode=0x01 (bit 0, outside mask 0x103e). Expects -EINVAL.
- **CORRECT.** Bit 0 is not in the valid set.

---

## File 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_error_query_set.c`

### CRITICAL ISSUE: Wrong function signatures

This file calls `buffer_check_err()` with **3 arguments** throughout, but the production function signature is:
```c
int buffer_check_err(int reqOutputBufferLength,
                     struct smb2_query_info_rsp *rsp,
                     void *rsp_org,
                     int min_output_length);  // 4th arg missing in all calls
```

Similarly, `get_file_ea_info()` is called with **2 arguments** (line 145: `get_file_ea_info(ctx->rsp, ctx->rsp_org)`) but the production function requires 3:
```c
void get_file_ea_info(struct smb2_query_info_rsp *rsp,
                      struct ksmbd_file *fp, void *rsp_org);
```

**WRONG: This file will not compile against the current production code.** All 14 test cases are affected.

### Individual test case analysis (assuming the signature issue is fixed with min_output_length=0):

**test_err_buffer_check_zero_req_nonzero_output** -- req=0, output=50. Would expect -EINVAL.
- **CORRECT** (after fix). With min_output_length=0: 0 >= 0 passes first check, 0 < 50 triggers STATUS_BUFFER_OVERFLOW/-EINVAL.

**test_err_buffer_check_sets_status** -- req=10, output=100. Expects STATUS_INFO_LENGTH_MISMATCH.
- **WRONG.** With min_output_length=0 (the missing 4th arg), the first check passes (10 >= 0). Then 10 < 100 triggers the second check which sets `STATUS_BUFFER_OVERFLOW`, **not** `STATUS_INFO_LENGTH_MISMATCH`. Per MS-SMB2 section 3.3.5.20.1, when the buffer is too small for the variable-length data, the status should be STATUS_BUFFER_OVERFLOW. The test expects the wrong status code.

**test_err_buffer_check_sets_rsp_org** -- Checks rsp_org gets sizeof(smb2_hdr) in BE.
- **CORRECT** (logic correct, but will not compile due to 3-arg call).

**test_err_buffer_check_negative_req** -- req=-1, output=10.
- **CORRECT** (assuming fix). With min_output_length=0: -1 < 0 passes (since -1 >= 0 is false). Actually wait: -1 < 0 (min_output_length), so STATUS_INFO_LENGTH_MISMATCH is set. Then returns -EINVAL. The test expects -EINVAL, which is correct.

**test_err_buffer_check_max_output** -- req=100, output=0xFFFFFFFF.
- **CORRECT** (assuming fix). 100 < 4294967295 triggers overflow, returns -EINVAL.

**test_err_pipe_info_double_call** -- Calls get_standard_info_pipe twice, checks idempotency.
- **CORRECT.**

**test_err_internal_pipe_max_num** -- U64_MAX | (1<<63) == U64_MAX.
- **CORRECT.**

**test_err_internal_pipe_bit63_already_set** -- (1<<63)|0x42 stays the same after OR with (1<<63).
- **CORRECT.**

**test_err_ea_info_always_zero** -- Calls get_file_ea_info with 2 args (missing fp parameter).
- **WRONG.** This will not compile. The production function requires `fp` as the second parameter. The call `get_file_ea_info(ctx->rsp, ctx->rsp_org)` passes rsp_org as the `fp` parameter, which is a type mismatch.

**test_err_alignment_always_zero** -- AlignmentRequirement=0.
- **CORRECT.**

**test_err_buffer_check_one_byte_short** -- req=40, output=41. Expects -EINVAL.
- **CORRECT** (after fix). 40 < 41 triggers overflow.

**test_err_buffer_check_one_byte_over** -- req=41, output=40. Expects 0.
- **CORRECT** (after fix).

**test_err_buffer_zero_output_nonzero_req** -- req=100, output=0. Expects 0.
- **CORRECT** (after fix).

**test_err_buffer_both_zero** -- req=0, output=0. Expects 0.
- **CORRECT** (after fix).

---

## File 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_info_dispatch.c`

### Hash key tests (6 test cases)

**test_hash_key_unique_all_different** -- Keys (1,2,0) != (3,4,1).
- **CORRECT.** Tests the hash key packing function, which is consistent with production code.

**test_hash_key_same_type_class_diff_op** -- (1,5,0) != (1,5,1).
- **CORRECT.** GET vs SET operations must produce different keys.

**test_hash_key_same_type_diff_class** -- (1,5,0) != (1,6,0).
- **CORRECT.**

**test_hash_key_diff_type_same_class** -- (1,5,0) != (2,5,0).
- **CORRECT.** Per MS-SMB2, SMB2_0_INFO_FILE(0x01) vs SMB2_0_INFO_FILESYSTEM(0x02) must dispatch differently.

**test_hash_key_identical_inputs** -- (1,5,0) == (1,5,0).
- **CORRECT.**

**test_hash_key_boundary_values** -- (0,0,0)==0; (255,255,1)==(255<<16|255<<8|1).
- **CORRECT.**

### buffer_check_err integration via dispatch (2 test cases)

**test_dispatch_buffer_check_err_ok** -- output=40, req=100. Expects 0.
- **WRONG: Calls buffer_check_err with 3 arguments.** Same compilation issue as error_query_set.c. The production function requires 4 arguments.

**test_dispatch_buffer_check_err_fail** -- output=200, req=10. Expects -EINVAL.
- **WRONG: Calls buffer_check_err with 3 arguments.** Same issue.

### Pipe info dispatch tests (2 test cases)

**test_dispatch_standard_pipe** -- Tests standard pipe info via dispatch.
- **CORRECT.**

**test_dispatch_internal_pipe** -- Tests internal pipe info via dispatch.
- **CORRECT.**

---

## File 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_info_file.c`

This file uses **replicated (mock) handlers** rather than calling production code. All the tests exercise the test's own local functions, not real ksmbd code.

### General observation

**QUESTIONABLE across all 44 test cases:** This entire file tests mock/replicated handler functions defined locally in the test file. None of these tests exercise the actual production ksmbd code. They test the test author's understanding of the spec, not the implementation. While the mock logic appears consistent with MS-FSCC/MS-SMB2 behavior, they provide zero coverage of the production code paths.

### FILE_NAME_INFORMATION tests (3 test cases)

**test_file_name_normal** -- Buffer=256, expects success.
- **CORRECT** (as a spec-behavior mock).

**test_file_name_buffer_too_small** -- Buffer=3, expects -ENOSPC.
- **CORRECT.**

**test_file_name_no_fp** -- No file pointer, expects -EINVAL.
- **CORRECT.**

### PIPE_INFO tests (2 test cases)

**test_pipe_info_get_defaults** -- ReadMode=0, CompletionMode=0.
- **CORRECT.** Per MS-FSCC 2.4.34: default pipe mode values.

**test_pipe_info_get_buffer_too_small** -- Expects -ENOSPC.
- **CORRECT.**

### PIPE_LOCAL_INFORMATION tests (2 test cases)

**test_pipe_local_info_defaults** -- MaximumInstances=0xFFFFFFFF (unlimited).
- **CORRECT.** Per MS-FSCC 2.4.35: MaximumInstances of 0xFFFFFFFF means unlimited.

**test_pipe_local_info_buffer_too_small** -- Expects -ENOSPC.
- **CORRECT.**

### PIPE_REMOTE_INFORMATION tests (2 test cases)

All zeroed defaults, buffer check.
- **CORRECT.**

### MAILSLOT_QUERY tests (2 test cases)

All zeroed defaults, buffer check.
- **CORRECT.** Note: mailslot queries are not part of the MS-SMB2 QUERY_INFO spec (mailslots are MS-MAIL). This is an extended info class.

### HARD_LINK tests (4 test cases)

**test_hard_link_single_link** -- Expects success for sufficient buffer.
- **CORRECT.**

**test_hard_link_buffer_too_small** -- Expects -ENOSPC.
- **CORRECT.**

**test_hard_link_no_fp** -- Expects -EINVAL.
- **CORRECT.**

### NORMALIZED_NAME tests (5 test cases)

**test_normalized_name_smb311** -- Dialect 0x0311, expects success.
- **CORRECT.** Per MS-SMB2 section 3.3.5.20.1: FileNormalizedNameInformation requires Connection.Dialect >= "3.1.1".

**test_normalized_name_pre_311** -- Dialect 0x0302, expects -ENOSYS.
- **CORRECT.** Per MS-SMB2 section 3.3.5.20.1: "if Connection.Dialect is '2.0.2', '2.1' or '3.0.2', the server MUST fail the request with STATUS_NOT_SUPPORTED." (Note: the spec also says "3.0" should be accepted, but the mock code uses `< 0x0311` which would also reject dialect 0x0300. This is **QUESTIONABLE** -- dialect 0x0300 (SMB 3.0) is not listed among the rejected dialects in the spec, but this is a mock function.)

**test_normalized_name_root** -- Expects success (same as smb311).
- **CORRECT.**

**test_normalized_name_stream** -- Expects success.
- **CORRECT.**

**test_normalized_name_buffer_too_small** -- Buffer=3, expects -ENOSPC.
- **CORRECT.**

### PROCESS_IDS tests (2 test cases)

**test_process_ids_returns_empty** -- NumberOfProcessIdsInList=0.
- **CORRECT.** This is an optional info class; returning empty is valid.

**test_process_ids_buffer_too_small** -- Expects -ENOSPC.
- **CORRECT.**

### NETWORK_PHYSICAL_NAME, VOLUME_NAME tests (4 test cases)

All test normal and buffer-too-small cases.
- **CORRECT.**

### IS_REMOTE_DEVICE tests (2 test cases)

**test_is_remote_device_returns_zero** -- Flags=0.
- **CORRECT.** The server is local, so it is not remote.

**test_is_remote_device_buffer_too_small** -- Expects -ENOSPC.
- **CORRECT.**

### REMOTE_PROTOCOL tests (3 test cases)

**test_remote_protocol_smb311** -- Major=3, Minor=1, Revision=1.
- **CORRECT.** Per MS-FSCC FileRemoteProtocolInformation: protocol version should match negotiated dialect.

**test_remote_protocol_smb20** -- Major=2, Minor=0, Revision=0.
- **CORRECT.**

**test_remote_protocol_buffer_too_small** -- Expects -ENOSPC.
- **CORRECT.**

### CASE_SENSITIVE tests (5 test cases)

**test_case_sensitive_get_returns_zero** -- Flags=0 (case-insensitive by default).
- **CORRECT.**

**test_case_sensitive_set_enable** -- FILE_CS_FLAG_CASE_SENSITIVE_DIR=0x01.
- **CORRECT.** Per MS-FSCC 2.4.9: setting the flag enables case-sensitive lookups.

**test_case_sensitive_set_invalid_flags** -- Flags=0xDEAD. Expects -EINVAL.
- **CORRECT.** Only bit 0 is valid per MS-FSCC.

**Buffer too small tests** -- Correct.

### FILE_STAT tests (4 test cases)

**test_file_stat_normal** -- Expects 56 bytes output.
- **QUESTIONABLE.** The test struct `test_file_stat_info` is 56 bytes, but MS-FSCC FileStatInformation (info class 0x46/70) should be 72 bytes (includes FileId=8, CreationTime=8, LastAccessTime=8, LastWriteTime=8, ChangeTime=8, AllocationSize=8, EndOfFile=8, FileAttributes=4, ReparseTag=4, NumberOfLinks=4, EffectiveAccess=4). The mock struct is missing FileAttributes, ReparseTag, and EffectiveAccess fields. The test_file_stat_info structure appears to be an incomplete representation. However, since this tests a mock function, not production code, it only tests the mock.

**test_file_stat_buffer_too_small** -- 55 bytes, expects -ENOSPC.
- **CORRECT** (relative to the mock's 56-byte struct).

**test_file_stat_no_fp** -- Expects -EINVAL.
- **CORRECT.**

### FILE_STAT_LX tests (2 test cases)

These reuse the FILE_STAT mock, which has the same struct size issue noted above.
- **QUESTIONABLE.** FileStatLxInformation is a different info class (0x47/71) with additional Linux-specific fields. The mock doesn't differentiate.

### VALID_DATA_LENGTH tests (4 test cases)

**test_valid_data_length_set_normal** -- ValidDataLength=4096. Expects success.
- **CORRECT.** Per MS-FSCC 2.4.50: sets the valid data length for the file.

**test_valid_data_length_set_negative** -- ValidDataLength=-1 (as u64). Expects -EINVAL.
- **CORRECT.** Negative values (when interpreted as signed) are invalid.

**test_valid_data_length_set_buffer_too_small** -- Expects -EMSGSIZE.
- **CORRECT.**

**test_valid_data_length_set_no_fp** -- Expects -EINVAL.
- **CORRECT.**

---

## File 5: `/home/ezechiel203/ksmbd/test/ksmbd_test_info_file_set.c`

This file also uses **replicated (mock) handlers**. Same general concern about not testing production code.

### PIPE_INFO SET tests (2 test cases)

**test_pipe_info_set_normal** -- Accepts sizeof(test_pipe_info)=8 bytes.
- **CORRECT.** Per MS-FSCC 2.4.34: setting pipe info requires ReadMode and CompletionMode fields.

**test_pipe_info_set_buffer_too_small** -- Expects -EMSGSIZE.
- **CORRECT.**

### PIPE_REMOTE SET tests (2 test cases)

**test_pipe_remote_set_normal** -- Accepts sizeof(test_pipe_remote_info)=16 bytes.
- **CORRECT.** Per MS-FSCC 2.4.37.

**test_pipe_remote_set_buffer_too_small** -- Expects -EMSGSIZE.
- **CORRECT.**

### MAILSLOT SET tests (2 test cases)

**test_mailslot_set_normal** -- Accepts sizeof(test_mailslot_set_info)=8 bytes.
- **CORRECT.**

**test_mailslot_set_buffer_too_small** -- Expects -EMSGSIZE.
- **CORRECT.**

### NOOP consumers (5 test cases)

**test_move_cluster_set_consumes_all**, **test_tracking_set_consumes_all**, **test_short_name_set_consumes_all**, **test_sfio_reserve_set_consumes_all**, **test_sfio_volume_set_consumes_all** -- All expect the noop handler to return 0 and consume all bytes.
- **CORRECT.** These info classes are accepted but effectively ignored by the server, which is a valid implementation behavior for optional/deprecated info classes.

---

## File 6: `/home/ezechiel203/ksmbd/test/ksmbd_test_info_fs.c`

Uses **replicated (mock) handlers**.

### FS_CONTROL SET tests (2 test cases)

**test_fs_control_set_normal** -- Accepts full struct.
- **CORRECT.** Per MS-FSCC 2.5.3: FileFsControlInformation.

**test_fs_control_set_buffer_too_small** -- Expects -EMSGSIZE.
- **CORRECT.**

### FS_DRIVER_PATH GET tests (2 test cases)

**test_fs_driver_path_get_normal** -- DriverInPath=0.
- **CORRECT.** Per MS-FSCC 2.5.5: FileFsDriverPathInformation.

**test_fs_driver_path_get_buffer_too_small** -- Expects -ENOSPC.
- **CORRECT.**

### FS_LABEL SET tests (4 test cases)

**test_fs_label_set_normal** -- 4 bytes header + 4 bytes label = 8 bytes consumed.
- **CORRECT.** Per MS-FSCC 2.5.6: FileFsLabelInformation.

**test_fs_label_set_buffer_too_small** -- 3 bytes, expects -EMSGSIZE.
- **CORRECT.**

**test_fs_label_set_odd_label_length** -- VolumeLabelLength=3 (odd). Expects -EINVAL.
- **CORRECT.** Labels are in UTF-16LE, which requires even byte lengths.

**test_fs_label_set_length_exceeds_buffer** -- VolumeLabelLength=100 but buffer=8. Expects -EINVAL.
- **CORRECT.**

### FS_OBJECT_ID SET tests (2 test cases)

**test_fs_object_id_set_normal** -- 48 bytes (3x16 byte GUIDs).
- **CORRECT.** Per MS-FSCC 2.5.7: FileFsObjectIdInformation.

**test_fs_object_id_set_buffer_too_small** -- Expects -EMSGSIZE.
- **CORRECT.**

---

## File 7: `/home/ezechiel203/ksmbd/test/ksmbd_test_info_quota.c`

Uses **replicated (mock) handlers**.

### Quota tests (3 test cases)

**test_quota_get_returns_empty** -- Returns out_len=0.
- **CORRECT.** Per MS-SMB2 section 3.3.5.20.4: quota query results depend on object store support. Returning empty when quotas are not supported is valid.

**test_quota_set_consumes_all** -- Consumes all input bytes.
- **CORRECT.** Per MS-SMB2 section 3.3.5.21.4: quota set passes data to object store.

**test_quota_set_zero_bytes** -- Zero-length set, out_len=0.
- **CORRECT.**

---

## File 8: `/home/ezechiel203/ksmbd/test/ksmbd_test_info_security.c`

### Security info dispatch test (1 test case)

**test_security_info_not_in_dispatch** -- Verifies empty hashtable has no SMB2_O_INFO_SECURITY entries.
- **CORRECT but trivially so.** The test initializes its own empty hashtable and verifies lookups return NULL. This confirms the design choice that security info is handled inline (not via the dispatch table), per MS-SMB2 section 3.3.5.20.3 and 3.3.5.21.3. The test validates architecture but does not test any production code behavior.
- **The constant SMB2_O_INFO_SECURITY = 3 is CORRECT** per MS-SMB2 section 2.2.37.

---

## SUMMARY OF FINDINGS

### WRONG (will not compile / incorrect assertions):

1. **`ksmbd_test_error_query_set.c` -- ALL 14 test cases**: `buffer_check_err()` called with 3 arguments instead of required 4. `get_file_ea_info()` called with 2 arguments instead of required 3. **This file will not compile.**

2. **`ksmbd_test_error_query_set.c::test_err_buffer_check_sets_status` (line 52-62)**: Even if the argument count were fixed (with min_output_length=0), the test expects `STATUS_INFO_LENGTH_MISMATCH` but the correct status would be `STATUS_BUFFER_OVERFLOW` per MS-SMB2 section 3.3.5.20.1. STATUS_INFO_LENGTH_MISMATCH is only triggered when `reqOutputBufferLength < min_output_length` (the fixed-length portion check), not when `reqOutputBufferLength < OutputBufferLength`.

3. **`ksmbd_test_info_dispatch.c::test_dispatch_buffer_check_err_ok` and `test_dispatch_buffer_check_err_fail` (lines 103, 119)**: `buffer_check_err()` called with 3 arguments instead of required 4. **Will not compile.**

### QUESTIONABLE:

4. **`ksmbd_test_smb2_query_set.c::test_access_info_read_only` (line 649)**: The comment says "FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES" but the expression `0x00000081 | 0x00000008 | 0x00000080` decomposes strangely -- 0x81 is already FILE_READ_DATA(0x01) | FILE_READ_ATTRIBUTES(0x80) combined, making the OR with 0x80 redundant. While the final value (0x89) is correct, the decomposition is misleading.

5. **`ksmbd_test_info_file.c::test_normalized_name_pre_311` (line 569)**: The mock uses `dialect < 0x0311` to reject, but MS-SMB2 section 3.3.5.20.1 says dialects "2.0.2", "2.1" or "3.0.2" should be rejected. Dialect "3.0" (0x0300) is NOT in the rejection list per spec, but the mock rejects it. The correct check per spec should reject only specific dialect versions, not use a blanket `< 0x0311`.

6. **`ksmbd_test_info_file.c::test_file_stat_normal` (line 803)**: The mock struct `test_file_stat_info` is 56 bytes but the real FileStatInformation (MS-FSCC) should be 72 bytes. The mock is incomplete.

7. **`ksmbd_test_info_file.c`, `ksmbd_test_info_file_set.c`, `ksmbd_test_info_fs.c`, `ksmbd_test_info_quota.c`**: All 4 files test only mock/replicated handlers, not production code. They validate spec understanding but provide zero coverage of actual ksmbd implementation.

### CORRECT:

All remaining test cases (69 across all files except those noted above) have correct FileInfoClass enum values, correct structure sizes, correct error code expectations, and behavior consistent with MS-SMB2 sections 2.2.37-40, 3.3.5.20, and 3.3.5.21, and MS-FSCC section 2.4/2.5.

### Key spec verification summary:

| Spec Item | Test Coverage | Status |
|-----------|---------------|--------|
| QUERY_INFO StructureSize = 41 (section 2.2.37) | Not directly tested | N/A |
| QUERY_INFO Response StructureSize = 9 (section 2.2.38) | Not directly tested | N/A |
| SET_INFO StructureSize = 33 (section 2.2.39) | Not directly tested | N/A |
| InfoType SMB2_0_INFO_FILE = 0x01 | Implicit via dispatch hash | CORRECT |
| InfoType SMB2_0_INFO_FILESYSTEM = 0x02 | Implicit via dispatch hash | CORRECT |
| InfoType SMB2_0_INFO_SECURITY = 0x03 | Tested in info_security.c | CORRECT |
| InfoType SMB2_0_INFO_QUOTA = 0x04 | Not tested | N/A |
| All 12 tested FileInfoClass enum values | Tested in smb2_query_set.c | CORRECT |
| STATUS_BUFFER_OVERFLOW on partial data | buffer_check_err tests | CORRECT |
| STATUS_INFO_LENGTH_MISMATCH on insufficient fixed buffer | buffer_check_err tests | CORRECT |