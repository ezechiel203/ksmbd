# Part 14: Concurrency, Error Path & Regression Test Implementation Plan

**Date:** 2026-03-03
**Scope:** All missing concurrency tests, error path tests, and regression tests for ksmbd
**Current state:** 0 concurrency tests, 0 dedicated regression tests, ~400 error path assertions
spread across 85 KUnit files but covering <10% of production error paths

**PREREQUISITE:** [15_TESTABILITY_REFACTOR.md](15_TESTABILITY_REFACTOR.md) MUST be implemented
first. All KUnit tests in this plan call **real production functions** via `VISIBLE_IF_KUNIT` +
`EXPORT_SYMBOL_IF_KUNIT` + `MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING")`.
**No replicated logic is permitted.** Every test function must call at least one real
production function.

---

## Executive Summary

The ksmbd test suite has **three critical blind spots**:

| Category | Current | Gap | Target |
|----------|---------|-----|--------|
| **Concurrency tests** | 0 (KUnit is single-threaded) | No race, deadlock, or ordering tests | 85 tests |
| **Error path tests** | ~400 scattered assertions | 500+ untested error paths in production | 220 new tests |
| **Regression tests** | 0 dedicated | 55 documented bug fixes with 0 regression tests | 55 tests |
| **Total** | ~400 indirect | **860 gaps** | **360 new tests** |

**Implementation strategy:**
- KUnit tests for deterministic error path and regression testing (replicated-logic style)
- VM-based shell scripts for concurrency/stress testing (real server, real connections)
- New KUnit test files where none exist; extend existing files where appropriate

---

## Part A: Regression Tests (55 tests)

Every bug fix documented in MEMORY.md must have a dedicated regression test that will
fail if the fix is reverted. Organized by subsystem.

### A.1 New File: `test/ksmbd_test_regression_negotiate.c`

Tests for protocol negotiation bug fixes.

| Test Name | Regression | Description | Method |
|-----------|-----------|-------------|--------|
| `reg_smb202_credit_non_large_mtu` | REG-001 | SMB 2.0.2 credit tracking without LARGE_MTU flag | Replicate credit_charge_calc() for dialect < SMB2.1; verify charge=1 always for non-LARGE_MTU; verify no underflow when outstanding > granted |
| `reg_smb202_validate_negotiate_client_guid` | REG-002 | ClientGUID copied for SMB2.0.2 in validate negotiate | Replicate dialect >= SMB2_02 check (was `>`); verify ClientGUID field set for 0x0202 dialect |
| `reg_smb1_nt_lanman_dialect` | REG-003 | "\2NT LANMAN 1.0" dialect string recognized | Replicate ksmbd_lookup_protocol_idx(); feed "\2NT LANMAN 1.0"; expect SMB1 match |
| `reg_smb1_upgrade_wildcard_dialect` | REG-004 | SMB1→SMB2 upgrade uses 0x02FF wildcard | Replicate upgrade response builder; verify DialectRevision == 0x02FF, not specific version |
| `reg_conn_vals_realloc_no_leak` | REG-005 | conn->vals freed before re-alloc on repeated negotiate | Simulate two negotiate calls on same conn struct; verify first vals pointer freed |
| `reg_second_negotiate_rejected` | REG-020 | Second NEGOTIATE on same connection disconnects | Replicate need_neg check; second call returns send_no_response=1 |
| `reg_duplicate_negotiate_contexts` | REG-021 | Duplicate PREAUTH/ENCRYPT/COMPRESS/RDMA rejected | Build negotiate blob with duplicate context types; expect -EINVAL |
| `reg_signing_algo_count_zero` | REG-030 | SigningAlgorithmCount==0 rejected | Build signing context with count=0; expect -EINVAL |
| `reg_compression_algo_count_zero` | REG-031 | CompressionAlgorithmCount==0 rejected | Build compress context with count=0; expect -EINVAL |

**9 tests**, priority P0.

### A.2 New File: `test/ksmbd_test_regression_lock.c`

Tests for lock and byte-range handling bug fixes.

| Test Name | Regression | Description | Method |
|-----------|-----------|-------------|--------|
| `reg_lock_fl_end_inclusive` | REG-006 | POSIX fl_end = fl_start + length - 1 | Compute fl_end for length=10 at offset=0; expect fl_end=9 (not 10) |
| `reg_lock_offset_max_skip` | REG-007 | Ranges > OFFSET_MAX skip vfs_lock_file | Replicate check: if (start > OFFSET_MAX) skip VFS; verify no -EINVAL for offset=LLONG_MAX+1 |
| `reg_lock_wraparound_overlap` | REG-008 | Overlap check with wrap-around at offset ~0 | Lock at offset=U64_MAX, length=1; second lock at offset=0, length=1; expect no overlap |
| `reg_lock_seq_array_65` | REG-017 | lock_seq array holds indices 1-64 | Access lock_seq[64]; must not crash; verify sentinel 0xFF at init |
| `reg_lock_seq_stored_after_success` | REG-019 | Sequence stored only after lock succeeds | Simulate lock conflict → sequence NOT stored; simulate lock success → sequence stored |
| `reg_lock_seq_bit_extraction` | REG-015 | Bit extraction: idx = val & 0xF, num = (val >> 4) & 0xF | For val=0x35: idx=5, num=3; was reversed (idx=3, num=5 at old code) |
| `reg_lock_seq_replay_returns_ok` | REG-016 | Lock replay detection returns STATUS_OK immediately | Store sequence, replay same → expect 0 (not -EAGAIN) |
| `reg_lock_seq_sentinel_0xff` | REG-018 | Uninitialized entries have 0xFF sentinel | Fresh lock_seq array: all entries == 0xFF; replay check on unused index → no false match |

**8 tests**, priority P0.

### A.3 New File: `test/ksmbd_test_regression_compound.c`

Tests for compound request and error propagation fixes.

| Test Name | Regression | Description | Method |
|-----------|-----------|-------------|--------|
| `reg_compound_only_create_cascades` | REG-009 | Only CREATE failures cascade to subsequent commands | Simulate FLUSH error in compound; verify next command NOT failed |
| `reg_compound_fid_from_non_create` | REG-034 | FID extracted from FLUSH/READ/WRITE/CLOSE/etc | For each of: READ, WRITE, FLUSH, CLOSE, LOCK, IOCTL, QUERY_DIR, NOTIFY, QUERY_INFO, SET_INFO — verify compound_fid captured |
| `reg_compound_create_err_cascades` | REG-009b | CREATE failure DOES cascade | Simulate CREATE returning STATUS_ACCESS_DENIED; verify next command gets same error |

**3 tests**, priority P0.

### A.4 New File: `test/ksmbd_test_regression_access.c`

Tests for access control and create path fixes.

| Test Name | Regression | Description | Method |
|-----------|-----------|-------------|--------|
| `reg_desired_access_mask_synchronize` | REG-011 | DESIRED_ACCESS_MASK includes SYNCHRONIZE (bit 20) | Verify mask == 0xF21F01FF; verify bit 20 set |
| `reg_delete_on_close_needs_delete_access` | REG-023 | FILE_DELETE_ON_CLOSE without DELETE access → STATUS_ACCESS_DENIED | Simulate daccess without FILE_DELETE_LE; request DOC; expect -EACCES |
| `reg_append_only_rejects_non_eof_write` | REG-024 | Append-only handle rejects write at offset != EOF | Simulate FILE_APPEND_DATA-only handle; write at offset 0 → expect error |
| `reg_doc_readonly_status_cannot_delete` | REG-036 | DOC + readonly → STATUS_CANNOT_DELETE | Simulate readonly file attrs + DOC request; expect STATUS_CANNOT_DELETE |
| `reg_generic_execute_pre_expansion` | REG-037 | GENERIC_EXECUTE mapped to specific bits before check | Expand GENERIC_EXECUTE; verify includes READ_ATTR, EXECUTE, SYNCHRONIZE |
| `reg_odd_name_length_rejected` | HI-05 | Odd NameLength in CREATE returns EINVAL | NameLength=5 (odd) → expect -EINVAL |
| `reg_dotdot_path_traversal` | REG-043 | ".." in mkdir path → STATUS_OBJECT_PATH_SYNTAX_BAD | Path "..\\etc" → expect rejection |
| `reg_tree_connect_share_name_80chars` | REG-042 | Share name >= 80 chars → BAD_NETWORK_NAME | 80-char share name → expect -EINVAL |

**8 tests**, priority P0.

### A.5 New File: `test/ksmbd_test_regression_session.c`

Tests for session, authentication, and channel fixes.

| Test Name | Regression | Description | Method |
|-----------|-----------|-------------|--------|
| `reg_anonymous_zero_nt_challenge` | REG-012 | NTLMSSP_ANONYMOUS with NtChallengeResponse.Length==0 accepted | Replicate anonymous auth check; zero-length NtCR → expect success |
| `reg_session_null_flag` | SESS-1 | SMB2_SESSION_FLAG_IS_NULL_LE set for anonymous sessions | Verify flag set when NTLMSSP_ANONYMOUS + zero NtCR |
| `reg_encrypted_session_enforcement` | REG-025 | Unencrypted request on encrypted session → STATUS_ACCESS_DENIED | Set session->enc_flag; simulate unencrypted request; expect rejection |
| `reg_channel_sequence_stale_reject` | REG-026 | Stale ChannelSequence → STATUS_FILE_NOT_AVAILABLE | Set fp->channel_sequence=5; request with seq=3 → stale (negative diff) → reject |
| `reg_channel_sequence_advance` | REG-026b | Valid ChannelSequence advance accepted | fp->channel_sequence=5; request with seq=6 → accept + update to 6 |
| `reg_durable_reconnect_no_client_guid` | REG-045 | Durable reconnect v1 doesn't require ClientGUID match | Different ClientGUID → reconnect still succeeds |
| `reg_ipc_pipe_skips_channel_check` | REG-046 | IPC pipe FID skips channel sequence validation | Simulate NULL from ksmbd_lookup_fd_fast for pipe → skip check, no error |

**7 tests**, priority P0.

### A.6 New File: `test/ksmbd_test_regression_rw.c`

Tests for read/write operation fixes.

| Test Name | Regression | Description | Method |
|-----------|-----------|-------------|--------|
| `reg_write_append_sentinel` | REG-029 | Offset 0xFFFFFFFFFFFFFFFF = append-to-EOF | Verify sentinel detected before loff_t conversion; verify FILE_APPEND_DATA required |
| `reg_flush_access_check` | REG-032 | Flush requires WRITE_DATA or APPEND_DATA access | Simulate read-only handle; flush → expect STATUS_ACCESS_DENIED |
| `reg_flush_invalid_fid_file_closed` | REG-033 | Flush on invalid FID → STATUS_FILE_CLOSED | Not STATUS_INVALID_HANDLE |
| `reg_ioctl_flags_zero_rejected` | REG-022 | IOCTL Flags!=0x1 rejected | Flags=0 → expect STATUS_INVALID_PARAMETER |
| `reg_set_sparse_no_buffer_default` | REG-035 | FSCTL_SET_SPARSE with no buffer defaults sparse=TRUE | Empty input buffer → file marked sparse per MS-FSCC §2.3.64 |

**5 tests**, priority P0.

### A.7 New File: `test/ksmbd_test_regression_oplock.c`

Tests for oplock, lease, and directory lease fixes.

| Test Name | Regression | Description | Method |
|-----------|-----------|-------------|--------|
| `reg_dir_lease_rh_granted` | REG-038 | Directory open with RH lease gets RH (not stripped) | Simulate directory open + RH lease request → expect RH granted |
| `reg_dir_lease_handle_break` | REG-039 | Second open on dir with RH lease breaks handle → R | Simulate first open=RH, second open → expect break to R |
| `reg_outstanding_async_counter` | REG-010 | Async counter decremented on cancel/completion | Increment, cancel → verify counter == 0; no leak |
| `reg_parent_dir_lease_break` | REG-040 | Child create/rename/delete breaks parent directory lease | Simulate parent RH lease; child create → expect parent lease break |

**4 tests**, priority P0.

### A.8 New File: `test/ksmbd_test_regression_vfs.c`

Tests for VFS, delete-on-close, and durable handle fixes.

| Test Name | Regression | Description | Method |
|-----------|-----------|-------------|--------|
| `reg_delete_on_close_deferred` | REG-014 | File not unlinked while other handles open | Two handles; DOC on first; close first → file still exists (second handle open) |
| `reg_durable_doc_not_reconnectable` | REG-044 | Durable handle with DOC not reconnectable | is_reconnectable() returns false when is_delete_on_close set |
| `reg_dotdotdot_restart_scans` | REG-013 | dot_dotdot[0/1] reset on RESTART_SCANS | Set dot_dotdot[0]=1; set RESTART_SCANS flag → expect dot_dotdot[0]=0 |
| `reg_tree_connect_extension_path` | REG-027 | EXTENSION_PRESENT: PathOffset relative to Buffer[0] | Build tree connect with extension flag; verify path extracted correctly |
| `reg_empty_dacl_hidden_vs_denied` | REG-041 | Empty DACL → STATUS_OBJECT_NAME_NOT_FOUND (hidden) | 0 ACEs → -EBADF; partial DACL → -EACCES |

**5 tests**, priority P0.

### A.9 Extend: `test/ksmbd_test_smb2_negotiate.c`

Add to existing file.

| Test Name | Regression | Description |
|-----------|-----------|-------------|
| `reg_smb311_missing_preauth` | ME-05 | Preauth_HashId not set → STATUS_INVALID_PARAMETER |
| `reg_no_signing_overlap_fallback` | NEG-5 | No signing algorithm overlap → fallback to AES-CMAC |

**2 tests**, priority P0.

### Summary: 55 regression tests across 8 new files + 1 extended file

---

## Part B: Error Path Tests (220 tests)

Production code has 1,037 error returns, 854 goto cleanup paths, and 122 memory allocation
failure checks. Current tests exercise <10% of these. This section targets the most critical
untested error paths by file.

### B.1 New File: `test/ksmbd_test_error_create.c`

Error paths in `smb2_create.c` (109 gotos, 60 error returns, 24 STATUS codes).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_create_disposition_invalid` | Line 1616-1622 | Disposition > 5 | -EINVAL |
| `err_create_dir_nondir_conflict` | Line 1607-1609 | DIR + NON_DIR flags | -EINVAL |
| `err_create_dir_temporary_conflict` | Line 1638-1642 | DIR + ATTR_TEMPORARY | -EINVAL |
| `err_create_reserve_opfilter` | Line 1593-1596 | FILE_RESERVE_OPFILTER | STATUS_NOT_SUPPORTED |
| `err_create_tree_connection` | Line 1588-1591 | CREATE_TREE_CONNECTION | STATUS_NOT_SUPPORTED |
| `err_create_name_overflow` | Line 1364-1368 | NameOffset+NameLength > buffer | -EINVAL |
| `err_create_desired_access_zero` | Line 1624-1629 | DesiredAccess has no valid bits | STATUS_ACCESS_DENIED |
| `err_create_file_attrs_invalid` | Line 1631-1636 | FileAttributes=0x10000 (no valid bits) | -EINVAL |
| `err_create_impersonation_invalid` | Line 1570-1576 | Level > IL_DELEGATE (5) | STATUS_BAD_IMPERSONATION_LEVEL |
| `err_create_supersede_on_root` | Line 645 | FILE_SUPERSEDE on share root | STATUS_ACCESS_DENIED |
| `err_create_overwrite_nonexistent` | Line 120-123 | FILE_OVERWRITE on missing file | STATUS_OBJECT_NAME_NOT_FOUND |
| `err_create_exclusive_existing` | Line 115 | FILE_CREATE on existing file | STATUS_OBJECT_NAME_COLLISION |
| `err_create_stream_on_dir` | Line 1849-1853 | Named stream + FILE_DIRECTORY_FILE | STATUS_NOT_A_DIRECTORY |
| `err_create_default_stream_on_dir` | Line 1917-1923 | ::$DATA on directory without DIR flag | STATUS_FILE_IS_A_DIRECTORY |
| `err_create_streams_disabled` | Line 1418-1421 | Colon in name, streams disabled | STATUS_OBJECT_NAME_NOT_FOUND |
| `err_create_dh2c_guid_mismatch` | Line 1003-1008 | DH2C with wrong CreateGuid | STATUS_OBJECT_NAME_NOT_FOUND |
| `err_create_dh2c_dhnq_conflict` | Line 968-972 | DH2C + DHnQ together | -EINVAL |
| `err_create_dhnc_dh2q_conflict` | Line 1029-1033 | DHnC + DH2Q together | -EINVAL |
| `err_create_twrp_short_data` | Line 1696-1701 | TWrp DataLength < 8 | -EINVAL |
| `err_create_symlink_no_reparse_flag` | Line 1821-1827 | Open symlink without FILE_OPEN_REPARSE_POINT | STATUS_ACCESS_DENIED |

**20 tests**, priority P0.

### B.2 New File: `test/ksmbd_test_error_query_set.c`

Error paths in `smb2_query_set.c` (46 gotos, 74 error returns).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_query_buffer_too_small` | Buffer < required | OutputBufferLength=0 | STATUS_BUFFER_TOO_SMALL |
| `err_query_invalid_info_class` | Unknown class | InfoType=0xFF | STATUS_INVALID_PARAMETER |
| `err_query_invalid_file_info_class` | Unknown file class | FileInfoClass=0xFF | STATUS_INVALID_INFO_CLASS |
| `err_query_invalid_fs_info_class` | Unknown FS class | FsInfoClass=0xFF | STATUS_INVALID_INFO_CLASS |
| `err_set_info_readonly_file` | Set on readonly | BasicInfo on readonly with wrong attrs | STATUS_ACCESS_DENIED |
| `err_set_info_rename_special` | Rename "." | RenameInfo with "." target | STATUS_ACCESS_DENIED |
| `err_set_info_rename_conflict` | Rename collision | RenameInfo, target exists, no replace | STATUS_OBJECT_NAME_COLLISION |
| `err_set_info_alloc_zero` | AllocationInfo size=0 | AllocationSize=0 | File truncated to 0 (success) |
| `err_set_info_eof_negative` | EOF negative | EndOfFile=-1 | STATUS_INVALID_PARAMETER |
| `err_set_info_disposition_readonly` | Disposition on readonly | DispositionInfo=DELETE on readonly | STATUS_CANNOT_DELETE |
| `err_query_ea_overflow` | EA list overflow | EaList exceeds output buffer | STATUS_BUFFER_OVERFLOW |
| `err_query_security_no_sacl_priv` | SACL without SeSecurityPrivilege | SecurityInfo=SACL_SECURITY_INFORMATION | STATUS_PRIVILEGE_NOT_HELD |
| `err_set_security_null_sd` | NULL security descriptor | Empty SecurityBuffer | STATUS_INVALID_PARAMETER |
| `err_query_quota_no_quota_support` | Quota on non-quota FS | QueryQuota on ext4 | STATUS_NOT_SUPPORTED |
| `err_set_info_link_directory` | Link on directory | LinkInfo on directory | STATUS_FILE_IS_A_DIRECTORY |

**15 tests**, priority P0.

### B.3 New File: `test/ksmbd_test_error_auth.c`

Error paths in `auth.c` (66 gotos, 36 error returns, 8 allocations).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_auth_truncated_ntlmssp` | Short blob | NTLMSSP blob < 12 bytes | -EINVAL |
| `err_auth_wrong_signature` | Bad NTLMSSP sig | "NTLMXSP\0" | -EINVAL |
| `err_auth_negotiate_not_ntlmssp` | Wrong message type | MessageType != NtLmNegotiate | -EINVAL |
| `err_auth_challenge_alloc_fail` | NULL from kzalloc | Simulated OOM | -ENOMEM |
| `err_auth_unicode_convert_fail` | Invalid UTF-16 | Unpaired surrogate | -EINVAL |
| `err_auth_session_key_derivation` | Zero-length key | Empty session key input | -EINVAL |
| `err_auth_ntlmv2_response_short` | NtCR < 24 bytes | Short NtChallengeResponse | -EINVAL |
| `err_auth_hmacmd5_null_key` | NULL key | hmacmd5 with key=NULL, keylen=0 | -EINVAL |
| `err_auth_des_expand_parity` | Known vectors | Standard DES key expansion test vectors | Expected parity bits set |
| `err_auth_signing_key_zero` | Zero signing key | All-zero SessionKey | Signing still works (key accepted) |
| `err_auth_preauth_hash_missing` | No preauth hash | SMB3.1.1 with empty PreauthIntegrityHashValue | -EINVAL |
| `err_auth_kerberos_blob_too_large` | 64KB + 1 | SPNEGO blob exceeding KSMBD_MAX_SPNEGO_BLOB_SZ | -EMSGSIZE |

**12 tests**, priority P0.

### B.4 New File: `test/ksmbd_test_error_vfs.c`

Error paths in `vfs.c` (72 gotos, 61 error returns).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_vfs_path_null` | NULL path | ksmbd_vfs_create() with NULL path | -EINVAL |
| `err_vfs_path_empty` | Empty path | ksmbd_vfs_create() with "" | -ENOENT |
| `err_vfs_read_negative_offset` | offset < 0 | ksmbd_vfs_read() with offset=-1 | -EINVAL |
| `err_vfs_write_negative_offset` | offset < 0 | ksmbd_vfs_write() with offset=-1 | -EINVAL |
| `err_vfs_read_zero_length` | length=0 | ksmbd_vfs_read() with length=0 | 0 bytes read (success) |
| `err_vfs_truncate_negative` | length < 0 | ksmbd_vfs_truncate() with length=-1 | -EINVAL |
| `err_vfs_remove_nonexistent` | File missing | ksmbd_vfs_remove_file() on absent path | -ENOENT |
| `err_vfs_rename_to_self` | Same src and dst | ksmbd_vfs_rename() src=dst | -EINVAL or success |
| `err_vfs_getattr_closed_fd` | Closed FD | ksmbd_vfs_getattr() on closed fd | -EBADF |
| `err_vfs_setattr_readonly_fs` | Readonly mount | ksmbd_vfs_setattr() on RO mount | -EROFS |
| `err_vfs_lock_deadlock` | EDEADLK | Two conflicting blocking locks | -EDEADLK |
| `err_vfs_xattr_too_large` | ERANGE | setxattr with value > 64KB | -ERANGE |
| `err_vfs_symlink_depth` | ELOOP | Symlink chain > 40 levels | -ELOOP |
| `err_vfs_permission_denied` | EACCES | Open file with mode 000 | -EACCES |
| `err_vfs_disk_full` | ENOSPC | Write to full filesystem | -ENOSPC |

**15 tests**, priority P1 (many require VFS mock or real FS).

### B.5 New File: `test/ksmbd_test_error_fsctl.c`

Error paths in `ksmbd_fsctl.c` (89 error returns, 20 gotos).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_fsctl_unknown_code` | Unsupported FSCTL | CtlCode=0xDEADBEEF | STATUS_NOT_SUPPORTED |
| `err_fsctl_copychunk_zero_chunks` | ChunkCount=0 | Zero-length chunk array | STATUS_INVALID_PARAMETER |
| `err_fsctl_copychunk_too_many` | ChunkCount > max | count > KSMBD_CFG_COPY_CHUNK_MAX_COUNT | STATUS_INVALID_PARAMETER |
| `err_fsctl_copychunk_chunk_too_large` | Single chunk > max | Length > KSMBD_CFG_COPY_CHUNK_MAX_SIZE | STATUS_INVALID_PARAMETER |
| `err_fsctl_copychunk_total_too_large` | Sum > total max | Sum(Length) > KSMBD_CFG_COPY_CHUNK_TOTAL_SIZE | STATUS_INVALID_PARAMETER |
| `err_fsctl_copychunk_bad_resume_key` | Wrong resume key | 24-byte key mismatch | STATUS_OBJECT_NAME_NOT_FOUND |
| `err_fsctl_set_zero_beyond_eof` | BeyondFinalZero > EOF | Range extends past file | STATUS_INVALID_PARAMETER |
| `err_fsctl_set_zero_inverted_range` | FileOffset > BeyondFinalZero | Inverted range | STATUS_INVALID_PARAMETER |
| `err_fsctl_integrity_bad_algorithm` | Unknown algorithm | ChecksumAlgorithm=0xFFFF | STATUS_INVALID_PARAMETER |
| `err_fsctl_object_id_exists` | Object ID already set | CREATE_OR_GET on file with OID | Returns existing OID |
| `err_fsctl_pipe_peek_no_pipe` | Not a pipe | PIPE_PEEK on regular file | STATUS_INVALID_DEVICE_REQUEST |
| `err_fsctl_validate_negotiate_mismatch` | Parameter mismatch | Wrong Capabilities/GUID | STATUS_ACCESS_DENIED + disconnect |
| `err_fsctl_duplicate_extents_overlap` | Overlapping src/dst | Source and dest ranges overlap in same file | STATUS_NOT_SUPPORTED |
| `err_fsctl_query_allocated_empty_file` | Zero-length file | QUERY_ALLOCATED_RANGES on empty file | Zero ranges returned |
| `err_fsctl_request_resume_key_no_fp` | Invalid FID | REQUEST_RESUME_KEY on bad FID | STATUS_INVALID_HANDLE |

**15 tests**, priority P0.

### B.6 New File: `test/ksmbd_test_error_negotiate.c`

Error paths in `smb2_negotiate.c` (16 gotos, negotiate-specific errors).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_neg_dialect_count_zero` | DialectCount=0 | Negotiate with 0 dialects | STATUS_INVALID_PARAMETER |
| `err_neg_dialect_count_overflow` | DialectCount > buffer | Count causes buffer overflow | STATUS_INVALID_PARAMETER |
| `err_neg_no_common_dialect` | No overlap | Dialects=[0x9999] | STATUS_NOT_SUPPORTED |
| `err_neg_security_mode_zero` | SecurityMode=0 | Neither signing_enabled nor signing_required | Accepted (signing optional) |
| `err_neg_context_offset_overflow` | Bad NegotiateContextOffset | Offset points past buffer | STATUS_INVALID_PARAMETER |
| `err_neg_context_count_overflow` | NegotiateContextCount > buffer | Count causes iteration past buffer | STATUS_INVALID_PARAMETER |
| `err_neg_preauth_hash_unknown` | Unknown HashAlgorithm | HashAlgorithm=0x9999 | STATUS_INVALID_PARAMETER (no overlap) |
| `err_neg_encrypt_no_overlap` | No cipher overlap | CipherCount=1, Cipher=0x9999 | Proceed without encryption |
| `err_neg_multi_protocol_fallback` | Multi-dialect negotiate | [SMB2_02, SMB2_10, SMB3_00, SMB3_11] | Highest common selected |
| `err_neg_smb1_protocol_string` | "NT1" style negotiate | SMB1 protocol string | SMB1 path selected or upgrade |

**10 tests**, priority P0.

### B.7 New File: `test/ksmbd_test_error_session.c`

Error paths in `smb2_session.c` (26 gotos, session setup errors).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_sess_buffer_overflow` | SecurityBufferOffset past end | Offset+Length > packet size | STATUS_INVALID_PARAMETER |
| `err_sess_reauth_wrong_user` | Re-auth with different user | SessionId=existing, different credentials | STATUS_REQUEST_NOT_ACCEPTED |
| `err_sess_binding_wrong_flags` | Binding without SMB2_SESSION_FLAG_BINDING | SessionId=existing, no binding flag | STATUS_REQUEST_NOT_ACCEPTED |
| `err_sess_binding_smb20` | Channel binding on SMB2.0.2 | Binding request with dialect 0x0202 | STATUS_REQUEST_NOT_ACCEPTED |
| `err_sess_max_sessions` | Sessions at capacity | sessions_cap reached, new session | STATUS_INSUFFICIENT_RESOURCES |
| `err_sess_expired` | Timed-out session | Session past session_timeout | STATUS_NETWORK_SESSION_EXPIRED |
| `err_sess_logoff_invalid_session` | Logoff with bad SessionId | Non-existent SessionId | STATUS_USER_SESSION_DELETED |
| `err_sess_setup_more_processing` | Incomplete NTLMSSP | NtLmNegotiate (phase 1 only) | STATUS_MORE_PROCESSING_REQUIRED |
| `err_sess_preauth_hash_chain` | Hash chain verification | Multiple session setup rounds | Hash matches expected chain |
| `err_sess_signing_required_mismatch` | Server requires signing, client doesn't | signing_required=1, client SecurityMode=0 | STATUS_ACCESS_DENIED |

**10 tests**, priority P0.

### B.8 New File: `test/ksmbd_test_error_tree.c`

Error paths in `smb2_tree.c` (11 gotos, tree connect errors).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_tree_invalid_path_format` | No \\ in path | TreePath="noslash" | STATUS_BAD_NETWORK_NAME |
| `err_tree_nonexistent_share` | Share not configured | \\\\server\\NOSUCH | STATUS_BAD_NETWORK_NAME |
| `err_tree_user_denied` | User not in valid_users | User not authorized for share | STATUS_ACCESS_DENIED |
| `err_tree_guest_on_encrypted` | Guest on encrypted share | Guest session + encrypted share | STATUS_ACCESS_DENIED |
| `err_tree_disconnect_bad_tid` | Bad TreeId | TreeDisconnect with non-existent TID | STATUS_NETWORK_NAME_DELETED |
| `err_tree_max_tree_connects` | At capacity | Too many tree connects on session | STATUS_INSUFFICIENT_RESOURCES |
| `err_tree_ipc_dollar` | IPC$ share type | Connect to IPC$ | ShareType=SMB2_SHARE_TYPE_PIPE |
| `err_tree_extension_present_smb311` | Extension flag on < SMB3.1.1 | EXTENSION_PRESENT on SMB3.0 | Ignored silently |

**8 tests**, priority P1.

### B.9 New File: `test/ksmbd_test_error_readwrite.c`

Error paths in `smb2_read_write.c` (35 gotos).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_read_invalid_fid` | Bad FID | Non-existent FID | STATUS_FILE_CLOSED |
| `err_read_zero_length` | Length=0 | Read with Length=0 | STATUS_INVALID_PARAMETER |
| `err_read_data_offset_invalid` | DataOffset misaligned | DataOffset < SMB2_HEADER_STRUCTURE_SIZE + 48 | STATUS_INVALID_PARAMETER |
| `err_write_invalid_fid` | Bad FID | Non-existent FID | STATUS_FILE_CLOSED |
| `err_write_readonly_handle` | No WRITE_DATA access | Handle opened with READ_DATA only | STATUS_ACCESS_DENIED |
| `err_write_zero_length` | Length=0 | Write with Length=0 | 0 bytes written (success) |
| `err_write_offset_overflow` | Offset+Length > LLONG_MAX | Huge offset + length | STATUS_INVALID_PARAMETER |
| `err_read_pipe_empty` | Pipe with no data | Read on empty pipe | STATUS_PIPE_EMPTY or block |
| `err_write_pipe_disconnected` | Disconnected pipe | Write to closed pipe | STATUS_PIPE_DISCONNECTED |
| `err_read_max_length` | Length > MaxReadSize | Read exceeding negotiated max | STATUS_INVALID_PARAMETER |

**10 tests**, priority P0.

### B.10 New File: `test/ksmbd_test_error_lock.c`

Error paths in `smb2_lock.c` (27 gotos).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_lock_invalid_fid` | Bad FID | Non-existent FID | STATUS_FILE_CLOSED |
| `err_lock_shared_exclusive_both` | Both flags | SHARED + EXCLUSIVE | STATUS_INVALID_PARAMETER |
| `err_lock_no_type` | No flags | flags=0 | STATUS_INVALID_PARAMETER |
| `err_lock_unlock_with_lock` | UNLOCK + SHARED | Conflicting flags | STATUS_INVALID_PARAMETER |
| `err_lock_count_zero` | LockCount=0 | Empty lock array | STATUS_INVALID_PARAMETER |
| `err_lock_count_exceeds_max` | LockCount > 64 | 65 elements | STATUS_INVALID_PARAMETER |
| `err_lock_array_exceeds_buffer` | LockCount vs buffer | 10 elements but buffer holds 5 | STATUS_INVALID_PARAMETER |
| `err_lock_range_wrap` | offset + length wraps | offset=U64_MAX, length=2 | Wrapped range handled |
| `err_lock_conflict_exclusive` | Two exclusive on same range | Same range, both exclusive | STATUS_LOCK_NOT_GRANTED |
| `err_lock_conflict_shared_then_exclusive` | Shared then exclusive | Same range, shared → exclusive | STATUS_LOCK_NOT_GRANTED |
| `err_lock_cancel_invalid_async` | Cancel with bad AsyncId | Non-existent async operation | STATUS_NOT_FOUND |
| `err_lock_blocking_timeout` | Timeout on blocking lock | FAIL_IMMEDIATELY not set, conflict → timeout | STATUS_CANCELLED or STATUS_LOCK_NOT_GRANTED |

**12 tests**, priority P0.

### B.11 New File: `test/ksmbd_test_error_ioctl.c`

Error paths in `smb2_ioctl.c` (6 gotos, IOCTL dispatch errors).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_ioctl_not_fsctl` | Flags != IS_FSCTL | Flags=0x0 | STATUS_INVALID_PARAMETER |
| `err_ioctl_invalid_fid_non_ipc` | Bad FID on non-IPC | Non-IPC CtlCode + bad FID | STATUS_FILE_CLOSED |
| `err_ioctl_buffer_too_small` | Input too short | Short buffer for FSCTL | STATUS_INVALID_PARAMETER |
| `err_ioctl_output_too_small` | MaxOutputResponse=0 | No room for response | STATUS_BUFFER_TOO_SMALL |
| `err_ioctl_pipe_transact_no_pipe` | PIPE_TRANSACT on file | FSCTL_PIPE_TRANSACT on non-pipe FID | STATUS_INVALID_DEVICE_REQUEST |
| `err_ioctl_unknown_fsctl` | Unsupported CtlCode | CtlCode=0xDEADBEEF | STATUS_NOT_SUPPORTED |
| `err_ioctl_srv_copychunk_write_bad_key` | Bad resume key | SRV_COPYCHUNK_WRITE + wrong key | STATUS_OBJECT_NAME_NOT_FOUND |
| `err_ioctl_network_interface_no_rdma` | No RDMA interfaces | QUERY_NETWORK_INTERFACE_INFO, no RDMA | STATUS_NOT_SUPPORTED |

**8 tests**, priority P0.

### B.12 New File: `test/ksmbd_test_error_transport.c`

Error paths in transport layer (transport_tcp.c, transport_quic.c).

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_tcp_recv_timeout` | Recv timeout | No data for tcp_recv_timeout seconds | Connection marked for disconnect |
| `err_tcp_send_timeout` | Send timeout | Blocked send for tcp_send_timeout seconds | Connection marked for disconnect |
| `err_tcp_invalid_nbt_length` | NBT length > MAX_STREAM_PROT_LEN | Length=0x01000000 (>16MB) | Connection dropped |
| `err_tcp_zero_length_message` | Length=0 | Zero-byte NBT frame | STATUS_INVALID_PARAMETER or skip |
| `err_quic_invalid_initial` | Bad QUIC Initial | Malformed QUIC Initial packet | Connection rejected |
| `err_quic_client_hello_too_large` | ClientHello > 2048 | Oversized ClientHello | CRYPTO_ALERT |
| `err_quic_handshake_data_too_large` | HS data > 8192 | Oversized handshake data | CRYPTO_ALERT |
| `err_quic_unknown_frame_type` | Bad frame type | Frame type 0xFF | Connection error |
| `err_ipc_payload_too_large` | Payload > 4096 | Oversized IPC message | Truncated or rejected |
| `err_ipc_timeout` | IPC response timeout | Daemon not responding for ipc_timeout seconds | -ETIMEDOUT |

**10 tests**, priority P1 (transport tests need VM integration).

### B.13 Extend: `test/ksmbd_test_connection.c`

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_conn_max_connections_reached` | At max_connections | N+1 connection attempt | Rejected |
| `err_conn_max_per_ip_reached` | At max_ip_connections | Same-IP N+1 connection | Rejected |
| `err_conn_refcount_zero_access` | Refcount=0, inc_not_zero | Access after last put | Returns false |
| `err_conn_double_set_exiting` | Set exiting twice | Two calls to set_exiting() | Idempotent |
| `err_conn_enqueue_on_exiting` | Enqueue on exiting conn | New request on EXITING conn | Rejected |

**5 tests**, priority P0.

### B.14 Extend: `test/ksmbd_test_config.c`

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_config_set_invalid_param` | Unknown param ID | param_id=9999 | -EINVAL |
| `err_config_get_before_init` | Pre-init get | Call get before init | Returns default or error |
| `err_config_below_min` | Value < min | Set max_lock_count=0 | Clamped to min (1) |
| `err_config_above_max` | Value > max | Set max_lock_count=9999 | Clamped to max (1024) |
| `err_config_double_init` | Init called twice | Two ksmbd_config_init() | Idempotent or error |

**5 tests**, priority P0.

### B.15 Extend: `test/ksmbd_test_compress.c`

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_compress_null_input` | NULL buffer | Decompress(NULL, 0) | -EINVAL |
| `err_compress_zero_output_size` | output_size=0 | Compress to 0-byte buffer | -ENOSPC |
| `err_compress_invalid_algorithm` | algorithm=0xFFFF | Invalid compression type | -EINVAL |
| `err_decompress_truncated` | Short compressed data | LZNT1 data truncated mid-chunk | -EINVAL |
| `err_decompress_bomb` | 10 bytes → 1GB | Crafted decompression bomb | -ENOSPC (buffer limit) |
| `err_lz77_invalid_offset` | Back-reference offset=0 | Zero offset in LZ77 stream | -EINVAL |
| `err_lznt1_chunk_header_corrupt` | Bad chunk header | Chunk size > remaining data | -EINVAL |
| `err_huffman_incomplete_tree` | Truncated Huffman table | Short prefix code table | -EINVAL |

**8 tests**, priority P0.

### B.16 Extend: `test/ksmbd_test_acl.c`

| Test Name | Error Path | Input | Expected |
|-----------|-----------|-------|----------|
| `err_acl_sd_too_short` | SD < 20 bytes | Truncated security descriptor | -EINVAL |
| `err_acl_dacl_offset_overflow` | DaclOffset > buffer | Points past buffer end | -EINVAL |
| `err_acl_ace_count_overflow` | AceCount vs buffer | 100 ACEs but buffer holds 2 | -EINVAL |
| `err_acl_unknown_ace_type` | AceType=0xFF | Unknown ACE type | Skipped or -EINVAL |
| `err_acl_sid_too_short` | SID SubAuthorityCount > buf | Truncated SID | -EINVAL |
| `err_acl_owner_sid_null` | NULL owner SID | SD with OwnerOffset=0 | Default owner used |
| `err_acl_group_sid_null` | NULL group SID | SD with GroupOffset=0 | Default group used |

**7 tests**, priority P0.

### Summary: 220 error path tests across 12 new files + 4 extended files

---

## Part C: Concurrency Tests (85 tests)

KUnit runs single-threaded, so true concurrency testing requires either:
1. **KUnit with kthread spawning** (kernel threads within a test function)
2. **VM-based integration scripts** (multiple smbclient/smbcalltool processes in parallel)

This section specifies both approaches.

### C.1 New File: `test/ksmbd_test_concurrency_refcount.c` (KUnit + kthreads)

Tests for refcount safety under concurrent access.

| Test Name | Target | Description | Method |
|-----------|--------|-------------|--------|
| `conc_conn_refcount_inc_dec_parallel` | connection.c | Parallel inc/dec don't lose counts | Spawn 4 kthreads; each does 1000 inc+dec; final refcount == initial |
| `conc_conn_refcount_inc_not_zero_race` | connection.c | inc_not_zero fails after last dec | Thread A: dec_and_test; Thread B: inc_not_zero → must fail |
| `conc_session_refcount_parallel` | user_session.c | Session refcount under parallel access | 4 threads: inc/dec 1000 times; final == initial |
| `conc_tree_connect_refcount_race` | tree_connect.c | Tree connect refcount vs logoff | Thread A: logoff (dec_and_test); Thread B: new request (inc_not_zero) → must fail after logoff |
| `conc_share_config_rcu_read` | share_config.c | RCU read during share update | Thread A: rcu_read_lock + access; Thread B: share_config_put → no crash |
| `conc_fp_refcount_close_race` | vfs_cache.c | File handle refcount during close | Thread A: close (dec_and_test); Thread B: lookup (inc_not_zero) → must fail after close |
| `conc_oplock_refcount_break` | oplock.c | Oplock refcount during break | Thread A: oplock_break; Thread B: oplock_put → no use-after-free |

**7 tests**, priority P0.

### C.2 New File: `test/ksmbd_test_concurrency_state.c` (KUnit + kthreads)

Tests for state machine transitions under concurrent access.

| Test Name | Target | Description | Method |
|-----------|--------|-------------|--------|
| `conc_conn_state_transitions` | connection.c | State transitions are atomic | 2 threads: set_good vs set_exiting; final state must be one or the other |
| `conc_conn_enqueue_during_exit` | connection.c | No enqueue on exiting connection | Thread A: set_exiting; Thread B: enqueue → must fail |
| `conc_session_logoff_during_request` | user_session.c | Request processing vs session logoff | Thread A: processing request; Thread B: logoff → request completes or fails cleanly |
| `conc_tree_disconnect_during_io` | tree_connect.c | I/O vs tree disconnect | Thread A: tree_disconnect; Thread B: file I/O → clean error |
| `conc_delete_pending_new_open` | vfs_cache.c | New open vs delete-pending | Thread A: set delete_pending; Thread B: new open → STATUS_DELETE_PENDING |
| `conc_oplock_break_during_create` | oplock.c | Create triggers break while break in progress | Thread A: oplock_break (slow); Thread B: create → waits for break |

**6 tests**, priority P0.

### C.3 New File: `test/ksmbd_test_concurrency_hash.c` (KUnit + kthreads)

Tests for hash table operations under concurrent access.

| Test Name | Target | Description | Method |
|-----------|--------|-------------|--------|
| `conc_conn_hash_add_remove_parallel` | connection.c | Hash add/remove race | 4 threads: add/remove different entries; no corruption |
| `conc_conn_hash_lookup_during_remove` | connection.c | Lookup during remove | Thread A: hash_del; Thread B: hash_find → NULL or valid (no crash) |
| `conc_session_table_concurrent_add` | user_session.c | Concurrent session creation | 4 threads: each creates a session; all succeed with unique IDs |
| `conc_file_table_concurrent_open` | vfs_cache.c | Concurrent file opens | 4 threads: open same file; all get valid FIDs |
| `conc_file_table_close_during_lookup` | vfs_cache.c | Close during FID lookup | Thread A: close FID; Thread B: lookup same FID → NULL or valid |
| `conc_tree_table_add_remove` | tree_connect.c | Tree table concurrent access | 4 threads: add/remove tree connects; no corruption |

**6 tests**, priority P0.

### C.4 New File: `test/ksmbd_test_concurrency_lock.c` (KUnit + kthreads)

Tests for lock contention and ordering.

| Test Name | Target | Description | Method |
|-----------|--------|-------------|--------|
| `conc_lock_exclusive_contention` | smb2_lock.c | Two exclusive locks on same range | Thread A locks; Thread B attempts → blocked or fails immediately |
| `conc_lock_shared_concurrent` | smb2_lock.c | Multiple shared locks on same range | 4 threads: all acquire shared → all succeed |
| `conc_lock_unlock_during_wait` | smb2_lock.c | Unlock while another waits | Thread A: exclusive lock; Thread B: blocked; Thread A: unlock → B wakes |
| `conc_lock_sequence_concurrent_store` | smb2_lock.c | Concurrent sequence store | 2 threads: store different indices; no data corruption |
| `conc_lock_cancel_during_acquire` | smb2_lock.c | Cancel while lock pending | Thread A: blocking lock; Thread B: cancel A → A returns STATUS_CANCELLED |
| `conc_lock_table_exhaustion` | smb2_lock.c | 64 concurrent lock requests | 64 threads: each locks different range → all succeed |

**6 tests**, priority P0.

### C.5 New File: `test/ksmbd_test_concurrency_notify.c` (KUnit + kthreads)

Tests for notify/watch operations under concurrent access.

| Test Name | Target | Description | Method |
|-----------|--------|-------------|--------|
| `conc_notify_add_remove_watch` | ksmbd_notify.c | Add watch during remove | Thread A: add_watch; Thread B: remove_watch; no crash |
| `conc_notify_fire_during_cleanup` | ksmbd_notify.c | Notification fires during cleanup | Thread A: fire event; Thread B: cleanup file → clean ordering |
| `conc_notify_cancel_during_wait` | ksmbd_notify.c | Cancel while waiting | Thread A: wait for notification; Thread B: cancel → STATUS_CANCELLED |
| `conc_notify_many_watchers` | ksmbd_notify.c | 100 concurrent watchers | 100 threads watching same directory → all receive events |

**4 tests**, priority P1.

### C.6 New File: `tests/ksmbd_concurrency_test.sh` (VM Integration)

Real-server concurrency tests using smbclient and custom SMB clients.

| Test Name | Description | Method |
|-----------|-------------|--------|
| `conc_vm_parallel_connections` | 100 parallel connection attempts | 100 concurrent smbclient instances |
| `conc_vm_parallel_auth` | 50 concurrent authentication attempts | 50 smbclient -U user%pass in parallel |
| `conc_vm_parallel_file_create` | 50 threads creating files simultaneously | 50 smbclient "put" in parallel |
| `conc_vm_parallel_read_same_file` | 20 readers on same file | 20 smbclient "get" in parallel |
| `conc_vm_parallel_write_same_file` | 10 writers on same file | 10 smbclient "put" with offset writes |
| `conc_vm_parallel_lock_contention` | 20 threads locking same range | smbclient with lock commands |
| `conc_vm_connect_disconnect_storm` | Rapid connect/disconnect cycling | 200 cycles in 10 seconds |
| `conc_vm_parallel_tree_connect` | 50 tree connects on same session | Multi-channel or rapid tree_connect |
| `conc_vm_parallel_dir_enum` | 10 threads enumerating same 10K-file directory | Concurrent ls on large dir |
| `conc_vm_parallel_rename` | 2 threads renaming same file | Competing rename operations |
| `conc_vm_session_logoff_during_io` | Logoff while I/O in progress | Thread A: large read; Thread B: logoff |
| `conc_vm_tree_disconnect_during_io` | Tree disconnect while file open | Thread A: file I/O; Thread B: tree disconnect |
| `conc_vm_oplock_break_under_load` | Oplock break during heavy I/O | Thread A: opens with batch oplock; Thread B: opens same file |
| `conc_vm_notify_under_load` | Notify while creating 1000 files | Watch dir + create 1000 files in parallel |
| `conc_vm_durable_reconnect_race` | Durable handle reconnect during I/O | Disconnect + immediate reconnect while I/O pending |
| `conc_vm_multichannel_io` | I/O across multiple channels | Open 4 channels, parallel reads on each |
| `conc_vm_credit_exhaustion_recovery` | Credits exhausted then recovered | Send max_credits requests, wait for grant |
| `conc_vm_compound_under_load` | Compound requests during heavy load | 10 compound requests while 50 simple I/Os running |
| `conc_vm_smb1_smb2_mixed` | SMB1 and SMB2 clients simultaneously | smbclient -m NT1 + smbclient -m SMB3 in parallel |
| `conc_vm_parallel_share_enum` | 20 NetShareEnum in parallel | Concurrent share enumeration RPC calls |

**20 tests**, priority P0.

### C.7 New File: `tests/ksmbd_deadlock_test.sh` (VM Integration)

Deadlock and livelock detection tests.

| Test Name | Description | Method |
|-----------|-------------|--------|
| `deadlock_lock_order_ab_ba` | Two files locked in opposite order | Thread A: lock(F1,F2); Thread B: lock(F2,F1) → must not deadlock |
| `deadlock_notify_close` | Notify on file being closed | Watch file → close file → must complete (no hang) |
| `deadlock_session_logoff_tree` | Session logoff during tree disconnect | Simultaneous logoff + tree disconnect → must complete |
| `deadlock_oplock_break_close` | Oplock break during file close | Close triggers oplock break; break handler closes → must complete |
| `deadlock_compound_chain_lock` | Compound: CREATE + LOCK + READ + CLOSE | All in one compound → must not deadlock on lock ordering |
| `deadlock_rename_parent_child` | Rename file into its parent's directory | Rename + parent lease break → must complete |
| `deadlock_many_locks_single_file` | 64 overlapping locks on same file | Sequential lock of all 64 ranges → must complete |
| `deadlock_server_shutdown_during_io` | Server stop while I/O active | ksmbdctl stop while 50 clients active → must complete within 30s |
| `livelock_credit_starvation` | All credits consumed, new requests | Exhaust credits → new request → must eventually get credit |
| `livelock_lock_contention_cycle` | 10 threads cycling locks | Lock/unlock in cycle → all must make progress |

**10 tests**, priority P0.

### C.8 New File: `tests/ksmbd_race_condition_test.sh` (VM Integration)

TOCTOU and race condition tests.

| Test Name | Description | Method |
|-----------|-------------|--------|
| `race_symlink_swap` | Symlink swapped between open and use | Thread A: create symlink; Thread B: open; Thread A: repoint symlink; verify no escape |
| `race_rename_during_read` | File renamed during read | Thread A: large read; Thread B: rename file → STATUS_FILE_NOT_AVAILABLE or completes |
| `race_delete_during_write` | File deleted during write | Thread A: write; Thread B: delete → write fails cleanly |
| `race_chmod_during_access_check` | Permissions changed between check and use | Thread A: open (access check); Thread B: chmod 000 → must not allow unauthorized access |
| `race_session_expire_during_op` | Session expires mid-operation | Set session_timeout=1; start long operation → clean error |
| `race_share_config_reload` | Share config reloaded during I/O | Reload config while I/O active → no crash |
| `race_tree_disconnect_reconnect` | Tree disconnect + reconnect | Thread A: disconnect; Thread B: reconnect → clean state |
| `race_durable_timeout_reconnect` | Durable handle times out during reconnect | Set durable_handle_timeout=1; reconnect after 2s → must fail cleanly |
| `race_conn_drop_during_compound` | Connection drops mid-compound | Network break during compound request → no resource leak |
| `race_parallel_create_same_name` | Two creates for same file simultaneously | Thread A+B: FILE_CREATE → one succeeds, one gets NAME_COLLISION |
| `race_parallel_delete_same_file` | Two deletes on same file | Thread A+B: delete → one succeeds, one gets NOT_FOUND |
| `race_lock_during_close` | Lock request arrives as file is closing | Thread A: close FID; Thread B: lock same FID → clean error |

**12 tests**, priority P0.

### C.9 Extend: `test/ksmbd_test_vfs_cache.c`

| Test Name | Description | Method |
|-----------|-------------|--------|
| `conc_vfs_cache_fp_close_race` | Parallel close and lookup | kthread: close; kthread: lookup → no use-after-free |
| `conc_vfs_cache_delete_pending_race` | Parallel set delete_pending | Two kthreads set delete_pending → idempotent |
| `conc_vfs_cache_durable_timeout_cleanup` | Durable timeout during reconnect attempt | kthread: timeout cleanup; kthread: reconnect → clean ordering |
| `conc_vfs_cache_inode_deref_race` | Inode dereference during close | kthread: dec refcount to 0; kthread: inc_not_zero → fails |

**4 tests**, priority P0.

### Summary: 85 concurrency tests across 5 new KUnit files + 3 VM scripts + 1 extended file

---

## Part D: Implementation Guide

### D.1 KUnit Concurrency Test Pattern (kthread spawning)

```c
#include <kunit/test.h>
#include <linux/kthread.h>
#include <linux/completion.h>

struct conc_test_ctx {
    struct kunit *test;
    atomic_t counter;
    struct completion start;
    struct completion done;
    int thread_count;
};

static int conc_worker(void *data)
{
    struct conc_test_ctx *ctx = data;
    int i;

    /* Wait for all threads to be ready */
    wait_for_completion(&ctx->start);

    for (i = 0; i < 1000; i++) {
        atomic_inc(&ctx->counter);
        atomic_dec(&ctx->counter);
    }

    if (atomic_dec_and_test(&ctx->done_count))
        complete(&ctx->done);
    return 0;
}

static void conc_refcount_parallel(struct kunit *test)
{
    struct conc_test_ctx ctx;
    struct task_struct *threads[4];
    int i;

    atomic_set(&ctx.counter, 0);
    atomic_set(&ctx.done_count, 4);
    init_completion(&ctx.start);
    init_completion(&ctx.done);

    for (i = 0; i < 4; i++) {
        threads[i] = kthread_run(conc_worker, &ctx, "test_%d", i);
        KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
    }

    /* Release all threads simultaneously */
    complete_all(&ctx.start);

    /* Wait for all to finish */
    wait_for_completion_timeout(&ctx.done, 5 * HZ);
    KUNIT_EXPECT_EQ(test, atomic_read(&ctx.counter), 0);
}
```

### D.2 VM Integration Test Pattern

```bash
#!/bin/bash
# tests/ksmbd_concurrency_test.sh
# Run with: ./tests/ksmbd_concurrency_test.sh <VM_SSH_PORT> <VM_SMB_PORT>

SSH_PORT=${1:-13022}
SMB_PORT=${2:-13445}
SSH_CMD="sshpass -p root ssh -p $SSH_PORT root@127.0.0.1"

PASS=0 FAIL=0 SKIP=0

run_test() {
    local name=$1; shift
    local result
    result=$("$@" 2>&1)
    local rc=$?
    if [ $rc -eq 0 ]; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name (rc=$rc)"
        echo "    $result" | head -5
        FAIL=$((FAIL + 1))
    fi
}

test_parallel_connections() {
    # Launch 100 parallel smbclient connections
    local pids=()
    for i in $(seq 1 100); do
        smbclient -p $SMB_PORT //127.0.0.1/test -N -c "ls" &>/dev/null &
        pids+=($!)
    done
    local failed=0
    for pid in "${pids[@]}"; do
        wait $pid || failed=$((failed + 1))
    done
    [ $failed -lt 10 ]  # Allow up to 10% failure rate
}

run_test "parallel_connections" test_parallel_connections
# ... more tests ...

echo ""
echo "Results: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
```

### D.3 Regression Test Pattern (REAL production calls)

All regression tests MUST call real production functions. Use `VISIBLE_IF_KUNIT` +
`EXPORT_SYMBOL_IF_KUNIT` (see [15_TESTABILITY_REFACTOR.md](15_TESTABILITY_REFACTOR.md)).

```c
#include <kunit/test.h>
#include "smb2pdu.h"
#include "vfs_cache.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

static void reg_lock_fl_end_inclusive(struct kunit *test)
{
    /*
     * REG-006: POSIX fl_end is inclusive: fl_start + length - 1
     * Bug was: fl_end = fl_start + length (exclusive, off by one)
     * Fix in: smb2_lock.c — smb2_set_flock_flags()
     */
    struct file_lock flock = {};
    struct file fake_file = {};
    int ret;

    /* Call REAL production function smb2_lock_init() */
    ret = smb2_lock_init(&flock, &fake_file,
                         0 /* offset */, 10 /* length */,
                         SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_FAIL_IMMEDIATELY);
    KUNIT_ASSERT_EQ(test, ret, 0);

    /* Verify inclusive end: offset=0, length=10 → fl_end=9 */
    KUNIT_EXPECT_EQ(test, flock.fl_end, 9LL);

    /* Adjacent range: offset=10, length=10 → fl_end=19 */
    struct file_lock flock2 = {};
    ret = smb2_lock_init(&flock2, &fake_file,
                         10 /* offset */, 10 /* length */,
                         SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_FAIL_IMMEDIATELY);
    KUNIT_ASSERT_EQ(test, ret, 0);
    KUNIT_EXPECT_EQ(test, flock2.fl_start, 10LL);
    KUNIT_EXPECT_EQ(test, flock2.fl_end, 19LL);

    /* No overlap: flock.fl_end (9) < flock2.fl_start (10) */
    KUNIT_EXPECT_TRUE(test, flock.fl_end < flock2.fl_start);
}
```

### D.4 Error Path Test Pattern (REAL production calls)

```c
#include <kunit/test.h>
#include "smb2pdu.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

static void err_create_disposition_invalid(struct kunit *test)
{
    /*
     * Call REAL smb2_create_open_flags() from smb2_create.c.
     * Disposition values 0-5 are valid; value 6+ must return -EINVAL.
     */
    int ret;

    /* Valid dispositions should succeed */
    ret = smb2_create_open_flags(true, 0x001F01FF, FILE_OPEN, false);
    KUNIT_EXPECT_GE(test, ret, 0);

    /* Invalid disposition (6+) — call REAL function, expect failure */
    ret = smb2_create_open_flags(true, 0x001F01FF, 6 /* invalid */, false);
    KUNIT_EXPECT_LT(test, ret, 0);

    ret = smb2_create_open_flags(true, 0x001F01FF, 0xFF, false);
    KUNIT_EXPECT_LT(test, ret, 0);
}
```

---

## Part E: File Inventory

### New KUnit Test Files (17)

| # | File | Tests | Category |
|---|------|------:|----------|
| 1 | `test/ksmbd_test_regression_negotiate.c` | 9 | Regression |
| 2 | `test/ksmbd_test_regression_lock.c` | 8 | Regression |
| 3 | `test/ksmbd_test_regression_compound.c` | 3 | Regression |
| 4 | `test/ksmbd_test_regression_access.c` | 8 | Regression |
| 5 | `test/ksmbd_test_regression_session.c` | 7 | Regression |
| 6 | `test/ksmbd_test_regression_rw.c` | 5 | Regression |
| 7 | `test/ksmbd_test_regression_oplock.c` | 4 | Regression |
| 8 | `test/ksmbd_test_regression_vfs.c` | 5 | Regression |
| 9 | `test/ksmbd_test_error_create.c` | 20 | Error path |
| 10 | `test/ksmbd_test_error_query_set.c` | 15 | Error path |
| 11 | `test/ksmbd_test_error_auth.c` | 12 | Error path |
| 12 | `test/ksmbd_test_error_vfs.c` | 15 | Error path |
| 13 | `test/ksmbd_test_error_fsctl.c` | 15 | Error path |
| 14 | `test/ksmbd_test_error_negotiate.c` | 10 | Error path |
| 15 | `test/ksmbd_test_error_session.c` | 10 | Error path |
| 16 | `test/ksmbd_test_error_tree.c` | 8 | Error path |
| 17 | `test/ksmbd_test_error_readwrite.c` | 10 | Error path |
| 18 | `test/ksmbd_test_error_lock.c` | 12 | Error path |
| 19 | `test/ksmbd_test_error_ioctl.c` | 8 | Error path |
| 20 | `test/ksmbd_test_error_transport.c` | 10 | Error path |
| 21 | `test/ksmbd_test_concurrency_refcount.c` | 7 | Concurrency |
| 22 | `test/ksmbd_test_concurrency_state.c` | 6 | Concurrency |
| 23 | `test/ksmbd_test_concurrency_hash.c` | 6 | Concurrency |
| 24 | `test/ksmbd_test_concurrency_lock.c` | 6 | Concurrency |
| 25 | `test/ksmbd_test_concurrency_notify.c` | 4 | Concurrency |
| | **Subtotal new** | **229** | |

### Extended Existing Files (6)

| # | File | New Tests | Category |
|---|------|----------:|----------|
| 1 | `test/ksmbd_test_smb2_negotiate.c` | 2 | Regression |
| 2 | `test/ksmbd_test_connection.c` | 5 | Error path |
| 3 | `test/ksmbd_test_config.c` | 5 | Error path |
| 4 | `test/ksmbd_test_compress.c` | 8 | Error path |
| 5 | `test/ksmbd_test_acl.c` | 7 | Error path |
| 6 | `test/ksmbd_test_vfs_cache.c` | 4 | Concurrency |
| | **Subtotal extended** | **31** | |

### New VM Integration Scripts (3)

| # | File | Tests | Category |
|---|------|------:|----------|
| 1 | `tests/ksmbd_concurrency_test.sh` | 20 | Concurrency |
| 2 | `tests/ksmbd_deadlock_test.sh` | 10 | Concurrency |
| 3 | `tests/ksmbd_race_condition_test.sh` | 12 | Concurrency |
| | **Subtotal VM** | **42** | |

### Makefile Updates

Add to `test/Makefile` `obj-$(CONFIG_KSMBD_KUNIT_TEST)`:

```makefile
    ksmbd_test_regression_negotiate.o \
    ksmbd_test_regression_lock.o \
    ksmbd_test_regression_compound.o \
    ksmbd_test_regression_access.o \
    ksmbd_test_regression_session.o \
    ksmbd_test_regression_rw.o \
    ksmbd_test_regression_oplock.o \
    ksmbd_test_regression_vfs.o \
    ksmbd_test_error_create.o \
    ksmbd_test_error_query_set.o \
    ksmbd_test_error_auth.o \
    ksmbd_test_error_vfs.o \
    ksmbd_test_error_fsctl.o \
    ksmbd_test_error_negotiate.o \
    ksmbd_test_error_session.o \
    ksmbd_test_error_tree.o \
    ksmbd_test_error_readwrite.o \
    ksmbd_test_error_lock.o \
    ksmbd_test_error_ioctl.o \
    ksmbd_test_error_transport.o \
    ksmbd_test_concurrency_refcount.o \
    ksmbd_test_concurrency_state.o \
    ksmbd_test_concurrency_hash.o \
    ksmbd_test_concurrency_lock.o \
    ksmbd_test_concurrency_notify.o \
```

---

## Part F: Implementation Priority

### Phase 0 (PREREQUISITE): Testability refactor
**MUST be done first.** See [15_TESTABILITY_REFACTOR.md](15_TESTABILITY_REFACTOR.md).
- Apply `VISIBLE_IF_KUNIT` to 136 static functions across 12 production files
- Add `EXPORT_SYMBOL_IF_KUNIT()` after each
- Add declarations to headers inside `#if IS_ENABLED(CONFIG_KUNIT)` guards
- Without this step, ALL tests below would be forced to use replicated logic (useless)

### Phase 1 (P0): Regression tests — 55 tests
All 55 regression tests for documented bug fixes. These are the highest priority because
they protect against re-introduction of known security and correctness bugs.
**Every test calls real production functions** — no replicated logic.

**New files:** 8 regression test files (all with `MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING")`)
**Estimated effort:** 2-3 sessions

### Phase 2 (P0): Critical error paths — 145 tests
Error path tests for the top-6 most error-dense production files:
- `ksmbd_test_error_create.c` (20 tests)
- `ksmbd_test_error_fsctl.c` (15 tests)
- `ksmbd_test_error_lock.c` (12 tests)
- `ksmbd_test_error_auth.c` (12 tests)
- `ksmbd_test_error_negotiate.c` (10 tests)
- `ksmbd_test_error_session.c` (10 tests)
- `ksmbd_test_error_readwrite.c` (10 tests)
- `ksmbd_test_error_ioctl.c` (8 tests)
- Extensions to compress, acl, config, connection (25 tests)

Plus concurrency KUnit tests:
- All 5 concurrency KUnit files (29 tests)
- Extensions to vfs_cache (4 tests)

**New files:** 8 error path + 5 concurrency KUnit files
**Estimated effort:** 3-4 sessions

### Phase 3 (P1): Secondary error paths + VM integration — 117 tests
- `ksmbd_test_error_query_set.c` (15 tests)
- `ksmbd_test_error_vfs.c` (15 tests)
- `ksmbd_test_error_tree.c` (8 tests)
- `ksmbd_test_error_transport.c` (10 tests)
- VM concurrency tests (20 tests)
- VM deadlock tests (10 tests)
- VM race condition tests (12 tests)
- Remaining extended file tests

**New files:** 4 error path + 3 VM scripts
**Estimated effort:** 2-3 sessions

---

## Part G: Verification Criteria

### All Regression Tests Must:
1. **Fail if the fix is reverted** — each test targets the exact bug mechanism
2. **Reference the REG-NNN identifier** in a comment
3. **Be deterministic** — no timing-dependent assertions in KUnit tests
4. **Document the original bug** in a comment block at the top

### All Error Path Tests Must:
1. **Cover the specific goto/return path** identified by line number
2. **Test boundary values** (min, max, min-1, max+1)
3. **Verify error code accuracy** (correct STATUS_* or -E* code)
4. **Not leak resources** — KUnit test cleanup must free all allocations

### All Concurrency Tests Must:
1. **Use proper synchronization** (completions, barriers)
2. **Have bounded runtime** (timeout on wait_for_completion)
3. **Be repeatable** — run 100 times without flake
4. **Test the specific race window** described, not just parallel execution

### Build Verification:
```bash
# Kernel module (all new test files)
make KDIR=/lib/modules/$(uname -r)/build EXTERNAL_SMBDIRECT=n all

# VM integration tests
./tests/ksmbd_concurrency_test.sh 13022 13445
./tests/ksmbd_deadlock_test.sh 13022 13445
./tests/ksmbd_race_condition_test.sh 13022 13445
```
