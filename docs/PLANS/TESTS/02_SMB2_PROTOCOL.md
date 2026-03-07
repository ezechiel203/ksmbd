# Test Plan: SMB2/3 Protocol Handlers

## Current Coverage Summary

### Existing Test Files (20 KUnit test suites + 13 fuzz harnesses)

| Test File | Suite Name | Tests | Target Source |
|-----------|-----------|-------|---------------|
| ksmbd_test_pdu_common.c | ksmbd_pdu_common | 15 | smb2_pdu_common.c (reparse tags, dos mode) |
| ksmbd_test_credit.c | ksmbd_credit | 7 | smb2misc.c (credit charge formula) |
| ksmbd_test_smb_common.c | ksmbd_smb_common | 11 | smb_common.c (protocol lookup, min/max) |
| ksmbd_test_create_ctx.c | ksmbd_create_ctx | 11 | ksmbd_create_ctx.c (dispatch list) |
| ksmbd_test_fsctl_dispatch.c | ksmbd_fsctl_dispatch | 13 | ksmbd_fsctl.c (FSCTL dispatch table) |
| ksmbd_test_info_dispatch.c | ksmbd_info_dispatch | 12 | ksmbd_info.c (info-level dispatch) |
| ksmbd_test_oplock.c | ksmbd_oplock | 11 | oplock.c (lease-to-oplock mapping) |
| ksmbd_test_buffer.c | ksmbd_buffer | 15 | ksmbd_buffer.c (buffer pool) |
| ksmbd_test_misc.c | ksmbd_misc | 19 | misc.c (pattern match, filename, time) |
| ksmbd_test_reparse.c | ksmbd_reparse | 17 | ksmbd_reparse.c (slash conv, NT prefix) |
| ksmbd_test_vss.c | ksmbd_vss | 17 | ksmbd_vss.c (VSS/snapshot tokens) |
| ksmbd_test_auth.c | ksmbd_auth | 10 | auth.c (DES key expansion, GSS header) |
| ksmbd_test_acl.c | ksmbd_acl | 14 | smbacl.c (SID compare, inherit, id_to_sid) |
| ksmbd_test_config.c | ksmbd_config | ~12 | ksmbd_config.c (config framework) |
| ksmbd_test_conn_hash.c | ksmbd_conn_hash | ~12 | connection.c (hash table ops) |
| ksmbd_test_feature.c | ksmbd_feature | ~10 | ksmbd_feature.c (feature negotiation) |
| ksmbd_test_fruit.c | ksmbd_fruit | ~14 | smb2fruit.c (Apple extension) |
| ksmbd_test_hooks.c | ksmbd_hooks | ~20 | ksmbd_hooks.c (hook system) |
| ksmbd_test_ida.c | ksmbd_ida | ~12 | ksmbd_ida.c (IDA management) |
| ksmbd_test_ndr.c | ksmbd_ndr | ~8 | ndr.c (NDR encoding) |
| ksmbd_test_smb1_parser.c | ksmbd_smb1_parser | ~20 | smb1pdu.c (SMB1 parsing) |
| ksmbd_test_unicode.c | ksmbd_unicode | ~15 | unicode.c (Unicode helpers) |

**Total existing KUnit tests: ~295 across 20 suites**

### Existing Fuzz Harnesses (13 files)

| Fuzz File | Targets |
|-----------|---------|
| smb2_header_fuzz.c | struct smb2_hdr validation, Protocol ID checks |
| negotiate_context_fuzz.c | Negotiate context chain traversal |
| create_context_fuzz.c | smb2_find_context_vals iteration |
| lock_request_fuzz.c | Lock count, element array bounds |
| query_set_info_fuzz.c | InfoType range, info class dispatch |
| quota_request_fuzz.c | SID list traversal, bounds checking |
| security_descriptor_fuzz.c | smb_ntsd offset validation |
| reparse_point_fuzz.c | ReparseDataLength, offset bounds |
| path_parse_fuzz.c | Filename validation, path conversion |
| dfs_referral_fuzz.c | MaxReferralLevel, RequestFileName |
| ndr_fuzz.c | NDR DOS attr, NT ACL decode |
| asn1_fuzz.c | ASN.1 sub-identifier, OID decode |
| transform_header_fuzz.c | Transform header ProtocolId validation |

---

## Gap Analysis

### Completely Untested Source Files (SMB2 protocol handlers)

The following SMB2 protocol source files have **ZERO** direct unit test coverage for their exported (non-static) functions:

| Source File | Lines | Exported Functions | Test Coverage |
|-------------|-------|--------------------|---------------|
| **smb2_create.c** | 2964 | `smb2_open()`, `smb2_set_ea()`, `ksmbd_acls_fattr()` | NONE |
| **smb2_read_write.c** | 1147 | `smb2_read()`, `smb2_write()`, `smb2_flush()` | NONE |
| **smb2_lock.c** | 1056 | `smb2_lock()`, `smb2_cancel()`, `smb_flock_init()` | NONE |
| **smb2_dir.c** | 1370 | `smb2_query_dir()`, `smb2_resp_buf_len()`, `smb2_calc_max_out_buf_len()` | NONE |
| **smb2_query_set.c** | 3392 | `smb2_query_info()`, `smb2_set_info()` | NONE |
| **smb2_ioctl.c** | 214 | `smb2_ioctl()` | NONE |
| **smb2_tree.c** | 544 | `smb2_tree_connect()`, `smb2_tree_disconnect()`, `smb2_session_logoff()` | NONE |
| **smb2_notify.c** | 404 | `smb2_notify()` | NONE |
| **smb2_misc_cmds.c** | 670 | `smb2_close()`, `smb2_echo()`, `smb2_oplock_break()`, `smb2_send_session_closed_notification()` | NONE |
| **smb2_negotiate.c** | 1013 | `smb2_handle_negotiate()`, `smb3_encryption_negotiated()`, `smb2_negotiate_request()` | NONE |
| **smb2_session.c** | 938 | `smb2_sess_setup()` | NONE |
| **smb2_misc.c** | 556 | `ksmbd_smb2_check_message()`, `smb2_negotiate_request()` | NONE (credit formula replicated) |
| **smb2ops.c** | 421 | `init_smb2_0_server()` ... `init_smb2_max_credits()` (9 functions) | NONE |

### Completely Untested Exported Functions

#### smb2_pdu_common.c (partially tested -- only reparse tags and DOS mode)

The following **30 exported functions** in `smb2_pdu_common.c` have no tests:

1. `__wbuf()` -- work buffer extraction
2. `smb2_check_channel_sequence()` -- ChannelSequence validation (MS-SMB2 3.3.5.2.10)
3. `lookup_chann_list()` -- multichannel channel lookup
4. `smb2_get_ksmbd_tcon()` -- tree connect validation
5. `smb2_set_err_rsp()` -- error response formatting
6. `is_smb2_neg_cmd()` -- negotiate command detection
7. `is_smb2_rsp()` -- response packet detection
8. `get_smb2_cmd_val()` -- command extraction
9. `set_smb2_rsp_status()` -- status code setting
10. `init_smb2_neg_rsp()` -- negotiate response init
11. `smb2_set_rsp_credits()` -- credit granting logic
12. `is_chained_smb2_message()` -- compound chain detection + FID propagation
13. `init_smb2_rsp_hdr()` -- response header initialization
14. `smb2_allocate_rsp_buf()` -- response buffer allocation
15. `smb2_check_user_session()` -- session validation
16. `smb2_get_name()` -- UTF-16LE to kernel string conversion
17. `setup_async_work()` -- async work setup
18. `release_async_work()` -- async work teardown
19. `smb2_send_interim_resp()` -- interim response for async
20. `smb2_is_sign_req()` -- signing requirement check
21. `smb2_check_sign_req()` -- SMB2 signature verification
22. `smb2_set_sign_rsp()` -- SMB2 signature generation
23. `smb3_check_sign_req()` -- SMB3 signature verification (AES-CMAC/GMAC)
24. `smb3_set_sign_rsp()` -- SMB3 signature generation
25. `smb3_preauth_hash_rsp()` -- pre-auth integrity hash
26. `smb3_encrypt_resp()` -- SMB3 encryption
27. `smb3_is_transform_hdr()` -- transform header detection
28. `smb3_decrypt_req()` -- SMB3 decryption
29. `smb3_11_final_sess_setup_resp()` -- session setup finalization
30. `init_chained_smb2_rsp()` (static but critical -- compound FID propagation)

#### smb2misc.c (partially tested -- only credit charge formula)

1. `ksmbd_smb2_check_message()` -- full request validation, size checking
2. `smb2_negotiate_request()` -- negotiate request handling (SMB1-to-SMB2 upgrade)
3. `check_smb2_hdr()` (static) -- header validation
4. `smb2_get_data_area_len()` (static) -- data area extraction
5. `smb2_calc_size()` (static) -- message size calculation
6. `smb2_validate_credit_charge()` (static) -- full credit validation with conn state

#### smb2ops.c (completely untested)

1. `init_smb2_0_server()` -- SMB 2.0.2 ops/values initialization
2. `init_smb2_1_server()` -- SMB 2.1 ops/values initialization
3. `init_smb3_0_server()` -- SMB 3.0 ops/values initialization
4. `init_smb3_02_server()` -- SMB 3.0.2 ops/values initialization
5. `init_smb3_11_server()` -- SMB 3.1.1 ops/values initialization
6. `init_smb2_max_read_size()` -- max read size config
7. `init_smb2_max_write_size()` -- max write size config
8. `init_smb2_max_trans_size()` -- max transact size config
9. `init_smb2_max_credits()` -- max credits config

### Insufficiently Tested Functions

| Function | Current Coverage | Missing Edge Cases |
|----------|-----------------|-------------------|
| `smb2_get_reparse_tag_special_file()` | All file types | Unknown mode type (e.g., 0xE000) |
| `smb2_get_dos_mode()` | Dir/file/sparse/reparse | Attribute mask boundaries (0x5137), symbolic links + directory, server_conf.share_fake_fscaps |
| Credit charge formula | 7 tests | Zero credit_charge floor (actual kernel floors to 1), LARGE_MTU vs non-LARGE_MTU path, overflow with very large sizes |
| Protocol lookup | 5 protos + invalid | SMB1 ("NT1") lookup, "SMB1" alias lookup, case sensitivity |
| Oplock lease-to-oplock | 7 combos | H-only lease (no R, no W), invalid bits set, all-bits-set |
| ACL compare_sids | 7 tests | MAX sub_auth count (15), zero-length authority |
| id_to_sid | 4 tests | SIDCREATOR_GROUP, boundary UID/GID values (0, UINT_MAX) |

---

## New Tests Required

### ksmbd_test_smb2_create.c (NEW)

Tests for `smb2_open()`, `smb2_set_ea()`, `ksmbd_acls_fattr()`, and all static helpers.

**Note:** Most `smb2_open()` logic requires full kernel state (conn, session, tree connect, VFS). Tests should focus on:
- Pure-logic helper functions that can be extracted or replicated
- Input validation paths that can be tested via request buffer construction

#### Access Mask Validation
1. `test_create_open_flags_read_data` -- FILE_READ_DATA maps to O_RDONLY
2. `test_create_open_flags_write_data` -- FILE_WRITE_DATA maps to O_WRONLY
3. `test_create_open_flags_read_write` -- FILE_READ_DATA | FILE_WRITE_DATA maps to O_RDWR
4. `test_create_open_flags_append` -- FILE_APPEND_DATA maps to O_WRONLY | O_APPEND
5. `test_create_open_flags_delete` -- DELETE without data access maps to O_RDONLY
6. `test_create_open_flags_execute` -- FILE_EXECUTE maps to O_RDONLY
7. `test_desired_access_mask_value` -- DESIRED_ACCESS_MASK == 0xF21F01FF (includes SYNCHRONIZE)
8. `test_access_mask_rejects_invalid_bits` -- bits outside mask return error

#### Disposition Handling
9. `test_create_disposition_file_supersede` -- FILE_SUPERSEDE truncates existing
10. `test_create_disposition_file_open` -- FILE_OPEN fails if file absent
11. `test_create_disposition_file_create` -- FILE_CREATE fails if file exists
12. `test_create_disposition_file_open_if` -- FILE_OPEN_IF creates if absent
13. `test_create_disposition_file_overwrite` -- FILE_OVERWRITE requires existing
14. `test_create_disposition_file_overwrite_if` -- FILE_OVERWRITE_IF creates or truncates

#### Create Options Validation (MS-SMB2 2.2.13)
15. `test_create_options_directory_file` -- FILE_DIRECTORY_FILE_LE rejects non-directory
16. `test_create_options_non_directory_file` -- FILE_NON_DIRECTORY_FILE_LE rejects directory
17. `test_create_options_conflicting_dir_flags` -- DIR + NON_DIR = INVALID_PARAMETER
18. `test_create_options_delete_on_close_readonly` -- STATUS_CANNOT_DELETE for readonly
19. `test_create_options_delete_on_close_no_delete_access` -- EACCES if daccess lacks DELETE
20. `test_create_options_open_by_file_id` -- FILE_OPEN_BY_FILE_ID_LE dispatches to resolve
21. `test_create_options_write_through` -- FILE_WRITE_THROUGH_LE flag propagation

#### Name Validation
22. `test_create_name_length_even` -- NameLength must be even (UTF-16LE)
23. `test_create_name_length_odd_rejected` -- Odd NameLength returns EINVAL
24. `test_create_name_offset_bounds` -- NameOffset + NameLength within request
25. `test_create_name_offset_overflow` -- NameOffset past buffer = EINVAL
26. `test_create_empty_name_opens_root` -- Empty name opens share root
27. `test_create_quota_fake_file` -- $Extend\\$Quota:$Q maps to root

#### Stream Handling
28. `test_create_stream_parse_named` -- "file:stream:$DATA" parses correctly
29. `test_create_stream_default_data` -- "file::$DATA" is default stream
30. `test_create_stream_dir_default_reject` -- Default stream + DIRECTORY = NOT_A_DIRECTORY
31. `test_create_stream_disabled` -- Stream open fails when streams flag off

#### Impersonation Levels (MS-SMB2 2.2.13)
32. `test_create_impersonation_anonymous` -- IL_ANONYMOUS accepted
33. `test_create_impersonation_identification` -- IL_IDENTIFICATION accepted
34. `test_create_impersonation_impersonation` -- IL_IMPERSONATION accepted
35. `test_create_impersonation_delegation` -- IL_DELEGATION accepted
36. `test_create_impersonation_invalid` -- Invalid level = BAD_IMPERSONATION_LEVEL

#### Create Context Processing
37. `test_create_context_mxac_request` -- SMB2_CREATE_QUERY_MAXIMAL_ACCESS
38. `test_create_context_qfid_request` -- SMB2_CREATE_QUERY_ON_DISK_ID
39. `test_create_context_twrp_timewarp` -- SMB2_CREATE_TIMEWARP_TOKEN
40. `test_create_context_alloc_size` -- SMB2_CREATE_ALLOCATION_SIZE
41. `test_create_context_durable_v1` -- SMB2_DHANDLE_FLAG_PERSISTENT (v1 durable)
42. `test_create_context_durable_v2` -- DH2Q/DH2C create contexts
43. `test_create_context_lease_v1` -- RqLs lease request (v1)
44. `test_create_context_lease_v2` -- RqLs lease request (v2 with parent key)
45. `test_create_context_posix` -- SMB2_CREATE_TAG_POSIX
46. `test_create_context_sd_buffer` -- SMB2_CREATE_SD_BUFFER
47. `test_create_context_ea_buffer` -- SMB2_CREATE_EA_BUFFER

#### Oplock/Lease Request
48. `test_create_oplock_none` -- RequestedOplockLevel=NONE
49. `test_create_oplock_level_ii` -- RequestedOplockLevel=II
50. `test_create_oplock_exclusive` -- RequestedOplockLevel=EXCLUSIVE
51. `test_create_oplock_batch` -- RequestedOplockLevel=BATCH
52. `test_create_oplock_lease` -- RequestedOplockLevel=LEASE requires RqLs context

#### Durable Handle Reconnect
53. `test_create_durable_reconnect_v1` -- DHnC reconnect context
54. `test_create_durable_reconnect_v2` -- DH2C reconnect context
55. `test_create_durable_reconnect_invalid_guid` -- Wrong GUID = STATUS_OBJECT_NAME_NOT_FOUND
56. `test_create_durable_and_reconnect_mutual_exclusion` -- Both DH2Q + DH2C = INVALID_PARAMETER

#### EA (Extended Attributes) Processing
57. `test_set_ea_single` -- Set one EA entry
58. `test_set_ea_multiple` -- Set chain of EA entries
59. `test_set_ea_zero_value_deletes` -- EA with ValueLength=0 deletes
60. `test_set_ea_invalid_next_offset` -- Bad NextEntryOffset = EINVAL
61. `test_set_ea_name_too_long` -- Name exceeding 255 bytes
62. `test_set_ea_buf_overflow` -- Buffer shorter than EA header

#### Security / Access Control
63. `test_create_parent_dacl_deny` -- Parent directory DENY ACE blocks child create
64. `test_create_readonly_delete_on_close` -- STATUS_CANNOT_DELETE
65. `test_create_file_delete_on_close_no_delete` -- daccess lacks FILE_DELETE_LE = EACCES
66. `test_acls_fattr_basic` -- ksmbd_acls_fattr populates uid/gid/mode

#### Pipe (IPC$) Operations
67. `test_create_pipe_basic` -- IPC$ pipe creation succeeds
68. `test_create_pipe_unknown_name` -- Unknown pipe name = STATUS_OBJECT_NAME_NOT_FOUND

---

### ksmbd_test_smb2_read_write.c (NEW)

Tests for `smb2_read()`, `smb2_write()`, `smb2_flush()`.

#### Read Validation (MS-SMB2 2.2.19)
1. `test_read_basic_file` -- Normal read returns data
2. `test_read_zero_length` -- Length=0 read should succeed (MS-SMB2 3.3.5.12)
3. `test_read_max_length` -- Length at MaxReadSize boundary
4. `test_read_beyond_eof` -- Read past EOF returns STATUS_END_OF_FILE
5. `test_read_invalid_fid` -- Invalid VolatileFileId returns FILE_CLOSED
6. `test_read_closed_fid` -- Closed FID returns FILE_CLOSED
7. `test_read_offset_overflow` -- Offset that wraps loff_t checked
8. `test_read_length_overflow` -- Length + offset > LLONG_MAX checked
9. `test_read_pipe` -- IPC$ pipe read (async path)
10. `test_read_pipe_cancel` -- Pipe read cancellation
11. `test_read_compound_fid` -- Compound request uses compound FID
12. `test_read_rdma_channel` -- SMB_DIRECT read via RDMA (when channel=1)
13. `test_read_channel_sequence_stale` -- ChannelSequence mismatch = FILE_NOT_AVAILABLE
14. `test_read_unbuffered_flag` -- SMB2_READFLAG_READ_UNBUFFERED handling
15. `test_read_minimum_count` -- MinimumCount field behavior (short read)
16. `test_read_data_offset_validation` -- DataOffset must be valid (>= header)

#### Write Validation (MS-SMB2 2.2.21)
17. `test_write_basic_file` -- Normal write succeeds
18. `test_write_zero_length` -- Length=0 write succeeds (no-op)
19. `test_write_append_to_eof_sentinel` -- Offset=0xFFFFFFFFFFFFFFFF (append-to-EOF)
20. `test_write_append_requires_append_data` -- Append sentinel without FILE_APPEND_DATA = ACCESS_DENIED
21. `test_write_offset_overflow_guard` -- Offset + Length > LLONG_MAX rejected
22. `test_write_non_eof_with_append_only` -- FILE_APPEND_DATA-only rejects non-EOF offset
23. `test_write_pipe` -- IPC$ pipe write
24. `test_write_invalid_fid` -- Invalid FID returns FILE_CLOSED
25. `test_write_compound_fid` -- Compound request FID propagation
26. `test_write_rdma_channel` -- SMB_DIRECT write via RDMA
27. `test_write_channel_sequence` -- ChannelSequence validation
28. `test_write_unbuffered_flag` -- SMB2_WRITEFLAG_WRITE_UNBUFFERED handling
29. `test_write_data_offset_validation` -- DataOffset within request bounds
30. `test_write_data_length_validation` -- DataLength within credit charge
31. `test_write_write_through_flag` -- SMB2_WRITEFLAG_WRITE_THROUGH

#### Flush Validation (MS-SMB2 2.2.23)
32. `test_flush_basic` -- Normal flush succeeds
33. `test_flush_invalid_fid` -- Invalid FID returns FILE_CLOSED
34. `test_flush_no_write_access` -- No FILE_WRITE_DATA | FILE_APPEND_DATA = ACCESS_DENIED
35. `test_flush_compound_fid` -- Compound FID propagation
36. `test_flush_pipe` -- Pipe flush (no-op success)
37. `test_flush_channel_sequence` -- ChannelSequence validation

---

### ksmbd_test_smb2_lock.c (NEW)

Tests for `smb2_lock()`, `smb2_cancel()`, `smb_flock_init()`.

#### Lock Request Validation (MS-SMB2 2.2.26)
1. `test_lock_basic_exclusive` -- SMB2_LOCKFLAG_EXCLUSIVE_LOCK
2. `test_lock_basic_shared` -- SMB2_LOCKFLAG_SHARED_LOCK
3. `test_lock_unlock` -- SMB2_LOCKFLAG_UN_LOCK
4. `test_lock_count_zero` -- LockCount=0 returns EINVAL
5. `test_lock_count_exceeds_max` -- LockCount > KSMBD_MAX_LOCK_COUNT
6. `test_lock_element_array_overflow` -- Lock elements exceed request buffer
7. `test_lock_invalid_fid` -- Invalid VolatileFileId
8. `test_lock_flags_mixed` -- Cannot mix lock + unlock in single request (MS-SMB2 3.3.5.14)
9. `test_lock_flags_invalid_combo` -- Invalid flag combinations

#### Lock Range Handling
10. `test_lock_zero_byte_range` -- Length=0 lock (zero-byte lock at offset)
11. `test_lock_full_file_range` -- Offset=0, Length=UINT64_MAX
12. `test_lock_offset_plus_length_wrap` -- Offset + Length wraps to non-zero = error
13. `test_lock_offset_plus_length_exact_wrap` -- Offset + Length wraps to exactly 0 = valid
14. `test_lock_beyond_offset_max` -- Range beyond OFFSET_MAX (POSIX limit)
15. `test_lock_posix_fl_end_inclusive` -- fl_end = fl_start + length - 1 (off-by-one fix)

#### Lock Overlap and Conflict
16. `test_lock_exclusive_conflicts_with_shared` -- Exclusive blocks shared
17. `test_lock_shared_allows_shared` -- Multiple shared locks coexist
18. `test_lock_same_handle_upgrade` -- Same-handle shared->exclusive upgrade
19. `test_lock_different_handle_conflict` -- Different handle = STATUS_LOCK_NOT_GRANTED
20. `test_lock_overlap_detection` -- Overlapping ranges detected correctly
21. `test_lock_adjacent_no_conflict` -- Adjacent but non-overlapping OK

#### Lock Sequence Replay (MS-SMB2 3.3.5.14)
22. `test_lock_sequence_replay_returns_ok` -- Replay of completed lock = STATUS_OK
23. `test_lock_sequence_index_range` -- Valid indices 1-64, 0 is "not valid"
24. `test_lock_sequence_index_out_of_range` -- Index > 64 not replayed
25. `test_lock_sequence_stored_after_success` -- Sequence stored only after lock success
26. `test_lock_sequence_sentinel_init` -- lock_seq[] initialized to 0xFF sentinel
27. `test_lock_sequence_bit_extraction` -- Low nibble = index, bits 4-7 = sequence
28. `test_lock_sequence_persistent_durable` -- Replay for persistent/durable handles

#### Cancel
29. `test_cancel_pending_lock` -- Cancel async lock returns STATUS_CANCELLED
30. `test_cancel_no_matching_async` -- Cancel with no matching request = no error
31. `test_cancel_already_completed` -- Cancel after completion = no-op

#### Blocking Locks
32. `test_lock_fail_immediately` -- SMB2_LOCKFLAG_FAIL_IMMEDIATELY = no blocking
33. `test_lock_blocking_wait` -- Lock without FAIL_IMMEDIATELY blocks (async)
34. `test_lock_blocking_cancel` -- Blocking lock cancelled by SMB2_CANCEL
35. `test_lock_blocking_timeout` -- Blocking lock released when holder unlocks

---

### ksmbd_test_smb2_dir.c (NEW)

Tests for `smb2_query_dir()`, `smb2_resp_buf_len()`, `smb2_calc_max_out_buf_len()`.

#### Info Level Validation (MS-SMB2 2.2.33)
1. `test_query_dir_file_directory_info` -- FileDirectoryInformation (0x01)
2. `test_query_dir_file_full_dir_info` -- FileFullDirectoryInformation (0x02)
3. `test_query_dir_file_both_dir_info` -- FileBothDirectoryInformation (0x03)
4. `test_query_dir_file_names_info` -- FileNamesInformation (0x0C)
5. `test_query_dir_file_id_full_dir` -- FileIdFullDirectoryInformation (0x26)
6. `test_query_dir_file_id_both_dir` -- FileIdBothDirectoryInformation (0x25)
7. `test_query_dir_file_id_extd_dir` -- FileIdExtdDirectoryInformation (0x3C)
8. `test_query_dir_smb_find_posix` -- SMB_FIND_FILE_POSIX_INFO (0x64)
9. `test_query_dir_invalid_info_level` -- Unknown level returns INVALID_INFO_CLASS

#### Info Level Struct Size
10. `test_readdir_info_level_struct_sz_01` -- FileDirectoryInformation size
11. `test_readdir_info_level_struct_sz_02` -- FileFullDirectoryInformation size
12. `test_readdir_info_level_struct_sz_03` -- FileBothDirectoryInformation size
13. `test_readdir_info_level_struct_sz_0c` -- FileNamesInformation size
14. `test_readdir_info_level_struct_sz_invalid` -- Invalid returns -EOPNOTSUPP

#### Wildcard/Pattern Handling
15. `test_query_dir_star_wildcard` -- "*" matches all entries
16. `test_query_dir_specific_pattern` -- "*.txt" matches .txt files
17. `test_query_dir_single_char_wildcard` -- "?" wildcard
18. `test_query_dir_dos_wildcard_star` -- DOS wildcard "<" (FILENAME_BOTH)
19. `test_query_dir_dos_wildcard_question` -- DOS wildcard ">"
20. `test_query_dir_dos_wildcard_dot` -- DOS wildcard "\"" (matches dot)
21. `test_query_dir_empty_pattern` -- Empty pattern behavior

#### Flags Handling (MS-SMB2 2.2.33)
22. `test_query_dir_restart_scans` -- SMB2_RESTART_SCANS resets dot_dotdot[0/1]
23. `test_query_dir_reopen` -- SMB2_REOPEN resets position
24. `test_query_dir_single_entry` -- SMB2_RETURN_SINGLE_ENTRY returns one entry
25. `test_query_dir_index_specified` -- SMB2_INDEX_SPECIFIED uses FileIndex
26. `test_query_dir_reopen_flag` -- REOPEN resets dot_dotdot state

#### Output Buffer
27. `test_query_dir_output_buf_full` -- Buffer fills and stops at boundary
28. `test_query_dir_output_buf_too_small` -- Buffer too small for single entry = STATUS_INFO_LENGTH_MISMATCH
29. `test_query_dir_entry_overflow` -- NextEntryOffset alignment to 8 bytes
30. `test_query_dir_last_entry_next_offset_zero` -- Last entry has NextEntryOffset=0

#### Dot/DotDot Handling
31. `test_query_dir_dot_entry` -- "." entry returned first
32. `test_query_dir_dotdot_entry` -- ".." entry returned second
33. `test_query_dir_dot_dotdot_skip_restart` -- Restart clears dot_dotdot flags

#### Helpers
34. `test_smb2_resp_buf_len_basic` -- Response buffer length calculation
35. `test_smb2_calc_max_out_buf_len_basic` -- Max output buffer len with credit limits
36. `test_smb2_calc_max_out_buf_len_zero_credits` -- Zero maximal = header minimum

---

### ksmbd_test_smb2_query_set.c (NEW)

Tests for `smb2_query_info()`, `smb2_set_info()`, and all static FileInformationClass handlers.

#### Query Info - File Information (MS-SMB2 2.2.37, MS-FSCC 2.4)
1. `test_query_file_basic_info` -- FileBasicInformation (0x04): timestamps + attributes
2. `test_query_file_standard_info` -- FileStandardInformation (0x05): size, nlink, delete_pending
3. `test_query_file_internal_info` -- FileInternalInformation (0x06): inode number
4. `test_query_file_ea_info` -- FileEaInformation (0x07): EA size
5. `test_query_file_access_info` -- FileAccessInformation (0x08): granted access mask
6. `test_query_file_position_info` -- FilePositionInformation (0x0E): current offset
7. `test_query_file_mode_info` -- FileModeInformation (0x10): mode flags
8. `test_query_file_alignment_info` -- FileAlignmentInformation (0x11)
9. `test_query_file_all_info` -- FileAllInformation (0x12): combined
10. `test_query_file_alternate_name` -- FileAlternateNameInformation (0x15): 8.3 name
11. `test_query_file_stream_info` -- FileStreamInformation (0x16): ADS streams
12. `test_query_file_compression_info` -- FileCompressionInformation (0x1C)
13. `test_query_file_network_open_info` -- FileNetworkOpenInformation (0x22)
14. `test_query_file_attribute_tag_info` -- FileAttributeTagInformation (0x23)
15. `test_query_file_id_info` -- FileIdInformation (0x3B, SMB 3.1.1)
16. `test_query_file_standard_link_info` -- FileStandardLinkInformation (0x36)
17. `test_query_file_object_id_info` -- FileObjectIdInformation (0x29): fallback generated
18. `test_query_file_reparse_point_info` -- FileReparsePointInformation
19. `test_query_file_stat_info` -- FileStatInformation (0x46, SMB 3.1.1)
20. `test_query_file_stat_lx_info` -- FileStatLxInformation (0x47, SMB 3.1.1)
21. `test_query_file_posix_info` -- SMB_FIND_FILE_POSIX_INFO
22. `test_query_file_invalid_class` -- Unknown class returns INVALID_INFO_CLASS

#### Query Info - Pipe File Info
23. `test_query_file_standard_info_pipe` -- Pipe returns fixed AllocationSize=4096
24. `test_query_file_internal_info_pipe` -- Pipe returns session inode number

#### Query Info - Filesystem Information (MS-FSCC 2.5)
25. `test_query_fs_volume_info` -- FileFsVolumeInformation (0x01)
26. `test_query_fs_size_info` -- FileFsSizeInformation (0x03)
27. `test_query_fs_device_info` -- FileFsDeviceInformation (0x04)
28. `test_query_fs_attribute_info` -- FileFsAttributeInformation (0x05)
29. `test_query_fs_full_size_info` -- FileFsFullSizeInformation (0x07)
30. `test_query_fs_object_id_info` -- FileFsObjectIdInformation (0x08)
31. `test_query_fs_sector_size_info` -- FileFsSectorSizeInformation (0x0B)
32. `test_query_fs_control_info` -- FileFsControlInformation (0x06)
33. `test_query_fs_posix_info` -- FileFsPosixInformation (0x64, POSIX ext)
34. `test_query_fs_invalid_class` -- Unknown class returns INVALID_INFO_CLASS

#### Query Info - Security (MS-SMB2 2.2.37.1)
35. `test_query_security_owner` -- OWNER_SECURITY_INFORMATION
36. `test_query_security_group` -- GROUP_SECURITY_INFORMATION
37. `test_query_security_dacl` -- DACL_SECURITY_INFORMATION
38. `test_query_security_sacl` -- SACL_SECURITY_INFORMATION (requires ACCESS_SYSTEM_SECURITY)
39. `test_query_security_all` -- Combined security query
40. `test_query_security_buffer_too_small` -- STATUS_BUFFER_TOO_SMALL with required size

#### Query Info - Buffer Validation
41. `test_query_info_buffer_check_err_exact` -- OutputBufferLength exactly matches
42. `test_query_info_buffer_check_err_short` -- OutputBufferLength too small
43. `test_query_info_buffer_check_err_large` -- OutputBufferLength larger than needed

#### Set Info - File Information (MS-SMB2 2.2.39)
44. `test_set_file_basic_info` -- FileBasicInformation: timestamps + attributes
45. `test_set_file_basic_info_zero_time` -- Zero timestamp = no change
46. `test_set_file_basic_info_negative_time` -- Negative (clear) timestamp = epoch
47. `test_set_file_allocation_info` -- FileAllocationInformation: preallocate
48. `test_set_file_allocation_info_shrink` -- Shrink allocation
49. `test_set_end_of_file_info` -- FileEndOfFileInformation: truncate/extend
50. `test_set_end_of_file_info_grow` -- Extend file beyond current size
51. `test_set_file_disposition_info` -- FileDispositionInformation: delete-on-close
52. `test_set_file_disposition_info_clear` -- Clear delete-on-close
53. `test_set_file_disposition_info_ex` -- FileDispositionInformationEx: POSIX semantics
54. `test_set_rename_info` -- FileRenameInformation: rename file
55. `test_set_rename_info_replace` -- Rename with ReplaceIfExists=true
56. `test_set_rename_info_cross_dir` -- Rename to different directory
57. `test_set_rename_info_ex` -- FileRenameInformationEx (POSIX rename)
58. `test_set_file_position_info` -- FilePositionInformation
59. `test_set_file_position_negative` -- Negative position rejected
60. `test_set_file_mode_info` -- FileModeInformation
61. `test_set_file_mode_invalid_flags` -- Invalid mode flags rejected
62. `test_set_file_object_id_info` -- FileObjectIdInformation (set replaces object ID)
63. `test_set_file_link_info` -- FileLinkInformation: hard link creation
64. `test_set_file_link_info_replace` -- Hard link with ReplaceIfExists

#### Set Info - Security
65. `test_set_security_owner` -- Set OWNER_SECURITY_INFORMATION
66. `test_set_security_dacl` -- Set DACL_SECURITY_INFORMATION
67. `test_set_security_sacl` -- Set SACL_SECURITY_INFORMATION
68. `test_set_security_combined` -- Set multiple security info types

---

### ksmbd_test_smb2_ioctl.c (NEW)

Tests for `smb2_ioctl()` and all FSCTL code paths.

#### IOCTL Request Validation
1. `test_ioctl_flags_fsctl_required` -- Flags must be SMB2_0_IOCTL_IS_FSCTL
2. `test_ioctl_flags_zero_rejected` -- Flags=0 returns INVALID_PARAMETER
3. `test_ioctl_flags_other_value_rejected` -- Flags=2 returns INVALID_PARAMETER
4. `test_ioctl_input_offset_bounds` -- InputOffset within request buffer
5. `test_ioctl_input_offset_overflow` -- InputOffset past buffer = INVALID_PARAMETER
6. `test_ioctl_input_count_overflow` -- InputCount exceeds remaining buffer
7. `test_ioctl_max_output_response` -- MaxOutputResponse limits output
8. `test_ioctl_compound_fid` -- Compound request FID propagation
9. `test_ioctl_channel_sequence` -- ChannelSequence validation for file FIDs

#### FSCTL Codes - Filesystem Operations (MS-FSCC 2.3)
10. `test_ioctl_set_reparse_point` -- FSCTL_SET_REPARSE_POINT (0x000900A4)
11. `test_ioctl_get_reparse_point` -- FSCTL_GET_REPARSE_POINT (0x000900A8)
12. `test_ioctl_delete_reparse_point` -- FSCTL_DELETE_REPARSE_POINT (0x000900AC)
13. `test_ioctl_set_sparse` -- FSCTL_SET_SPARSE (0x000900C4): default SetSparse=TRUE
14. `test_ioctl_set_sparse_no_buffer` -- FSCTL_SET_SPARSE with empty buffer = TRUE
15. `test_ioctl_set_zero_data` -- FSCTL_SET_ZERO_DATA (0x000980C8)
16. `test_ioctl_query_allocated_ranges` -- FSCTL_QUERY_ALLOCATED_RANGES (0x000940CF)
17. `test_ioctl_query_on_disk_volume_info` -- FSCTL_QUERY_ON_DISK_VOLUME_INFO (0x009013C0)

#### FSCTL Codes - Network Operations
18. `test_ioctl_dfs_get_referrals` -- FSCTL_DFS_GET_REFERRALS (0x00060194)
19. `test_ioctl_dfs_get_referrals_ex` -- FSCTL_DFS_GET_REFERRALS_EX (0x000601B0)
20. `test_ioctl_validate_negotiate_info` -- FSCTL_VALIDATE_NEGOTIATE_INFO (0x00140204)
21. `test_ioctl_validate_negotiate_dialect_mismatch` -- VNI dialect mismatch = disconnect
22. `test_ioctl_validate_negotiate_guid_mismatch` -- VNI GUID mismatch = disconnect
23. `test_ioctl_pipe_transact` -- FSCTL_PIPE_TRANSCEIVE (0x0011C017)
24. `test_ioctl_pipe_peek` -- FSCTL_PIPE_PEEK (0x0011400C)
25. `test_ioctl_pipe_wait` -- FSCTL_PIPE_WAIT (0x00110018)
26. `test_ioctl_request_resume_key` -- FSCTL_SRV_REQUEST_RESUME_KEY (0x00140078)

#### FSCTL Codes - Server-Side Copy (MS-SMB2 3.3.5.15.6)
27. `test_ioctl_copychunk` -- FSCTL_SRV_COPYCHUNK (0x001440F2)
28. `test_ioctl_copychunk_write` -- FSCTL_SRV_COPYCHUNK_WRITE (0x001480F2)
29. `test_ioctl_copychunk_too_many_chunks` -- ChunkCount > max
30. `test_ioctl_copychunk_chunk_too_large` -- Single chunk > max size
31. `test_ioctl_copychunk_total_too_large` -- Total bytes > max total
32. `test_ioctl_copychunk_invalid_resume_key` -- Invalid source key

#### FSCTL Codes - Network Interface (MS-SMB2 3.3.5.15.3)
33. `test_ioctl_network_interface_info` -- FSCTL_QUERY_NETWORK_INTERFACE_INFO (0x001401FC)
34. `test_ioctl_network_interface_rdma_capable` -- RDMA flags in response

#### FSCTL Codes - Miscellaneous
35. `test_ioctl_create_or_get_object_id` -- FSCTL_CREATE_OR_GET_OBJECT_ID (0x000900C0)
36. `test_ioctl_is_pathname_valid` -- FSCTL_IS_PATHNAME_VALID (0x0009002C)
37. `test_ioctl_enumerate_snapshots` -- FSCTL_SRV_ENUMERATE_SNAPSHOTS (0x00144064)
38. `test_ioctl_unknown_code` -- Unknown FSCTL = STATUS_INVALID_DEVICE_REQUEST
39. `test_ioctl_not_supported_code` -- Known but unsupported FSCTL = STATUS_NOT_SUPPORTED

---

### ksmbd_test_smb2_tree.c (NEW)

Tests for `smb2_tree_connect()`, `smb2_tree_disconnect()`, `smb2_session_logoff()`.

#### Tree Connect (MS-SMB2 2.2.9)
1. `test_tree_connect_basic` -- Normal share connection
2. `test_tree_connect_ipc` -- IPC$ share connection
3. `test_tree_connect_share_name_too_long` -- Share name >= 80 chars = STATUS_BAD_NETWORK_NAME
4. `test_tree_connect_invalid_share` -- Non-existent share = STATUS_BAD_NETWORK_NAME
5. `test_tree_connect_path_parsing` -- UNC path \\server\share extraction
6. `test_tree_connect_dfs_root` -- DFS root share name extraction
7. `test_tree_connect_max_connections` -- MaxConnections limit enforcement
8. `test_tree_connect_encryption_required` -- Share requires encryption + no encryption = ACCESS_DENIED
9. `test_tree_connect_flags_extension_present` -- TREE_CONNECT_FLAG_EXTENSION_PRESENT (SMB 3.1.1)
10. `test_tree_connect_extension_path_parsing` -- Extension present: PathOffset relative to Buffer[0]
11. `test_tree_connect_cluster_reconnect` -- TREE_CONNECT_FLAG_CLUSTER_RECONNECT
12. `test_tree_connect_redirect_to_owner` -- TREE_CONNECT_FLAG_REDIRECT_TO_OWNER

#### Tree Disconnect (MS-SMB2 2.2.11)
13. `test_tree_disconnect_basic` -- Normal disconnect
14. `test_tree_disconnect_invalid_tid` -- Invalid TreeId = NETWORK_NAME_DELETED
15. `test_tree_disconnect_closes_files` -- Files closed on disconnect

#### Session Logoff (MS-SMB2 2.2.7)
16. `test_session_logoff_basic` -- Normal session logoff
17. `test_session_logoff_closes_tree_connects` -- All tree connects freed
18. `test_session_logoff_closes_files` -- All open files closed
19. `test_session_logoff_session_closed_notification` -- Server-to-client notification sent (SMB 3.1.1)
20. `test_session_logoff_multichannel` -- Notification sent to other channels

---

### ksmbd_test_smb2_notify.c (NEW)

Tests for `smb2_notify()`.

#### Request Validation (MS-SMB2 2.2.35)
1. `test_notify_basic_setup` -- Install watch on directory
2. `test_notify_invalid_fid` -- Invalid FID = STATUS_FILE_CLOSED
3. `test_notify_non_directory` -- Watch on file = STATUS_INVALID_PARAMETER
4. `test_notify_no_list_directory` -- No FILE_LIST_DIRECTORY = ACCESS_DENIED
5. `test_notify_compound_not_last` -- NOTIFY in compound (not last) = INVALID_PARAMETER
6. `test_notify_compound_not_last_subsequent` -- Not-last in subsequent = INTERNAL_ERROR
7. `test_notify_compound_fid_propagation` -- Compound FID from prior CREATE

#### Flags
8. `test_notify_watch_tree` -- SMB2_WATCH_TREE flag: recursive watch
9. `test_notify_no_watch_tree` -- Without WATCH_TREE: single directory

#### Completion Filter (MS-SMB2 2.2.35)
10. `test_notify_filter_file_name` -- FILE_NOTIFY_CHANGE_FILE_NAME
11. `test_notify_filter_dir_name` -- FILE_NOTIFY_CHANGE_DIR_NAME
12. `test_notify_filter_attributes` -- FILE_NOTIFY_CHANGE_ATTRIBUTES
13. `test_notify_filter_size` -- FILE_NOTIFY_CHANGE_SIZE
14. `test_notify_filter_last_write` -- FILE_NOTIFY_CHANGE_LAST_WRITE
15. `test_notify_filter_security` -- FILE_NOTIFY_CHANGE_SECURITY
16. `test_notify_filter_combined` -- Multiple filters ORed together
17. `test_notify_filter_zero` -- Zero filter = no events

#### Async / Cancel
18. `test_notify_returns_status_pending` -- CHANGE_NOTIFY goes async
19. `test_notify_cancel` -- Cancel pending notify
20. `test_notify_cancel_piggyback` -- Cancel of piggyback watches
21. `test_notify_outstanding_async_counter` -- Async counter tracked correctly

#### Output
22. `test_notify_response_format` -- FILE_NOTIFY_INFORMATION structure
23. `test_notify_multiple_events` -- Multiple events in single response
24. `test_notify_output_buffer_overflow` -- OutputBufferLength too small

---

### ksmbd_test_smb2_misc.c (NEW)

Tests for `smb2_close()`, `smb2_echo()`, `smb2_oplock_break()`, `smb2_send_session_closed_notification()`.

#### Close (MS-SMB2 2.2.15)
1. `test_close_basic` -- Normal file close
2. `test_close_postquery_attrib` -- SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB returns stats
3. `test_close_no_postquery` -- Flags=0 returns zeroed attributes
4. `test_close_invalid_fid` -- Invalid FID = STATUS_FILE_CLOSED
5. `test_close_pipe` -- IPC$ pipe close
6. `test_close_compound_fid` -- Compound request FID
7. `test_close_compound_already_closed` -- Compound close after close = FILE_CLOSED
8. `test_close_session_id_validation` -- Related request uses compound_sid
9. `test_close_delete_on_close_trigger` -- Close triggers delete-on-close
10. `test_close_delete_on_close_other_handles_open` -- No delete while other handles exist

#### Echo (MS-SMB2 2.2.28)
11. `test_echo_basic` -- Echo returns success
12. `test_echo_response_size` -- Response is minimal (4 bytes)

#### Oplock Break (MS-SMB2 2.2.23)
13. `test_oplock_break_ack_exclusive` -- Acknowledge exclusive break to none
14. `test_oplock_break_ack_exclusive_to_level2` -- Break to Level II
15. `test_oplock_break_ack_batch` -- Batch oplock break acknowledgement
16. `test_oplock_break_ack_level2_invalid` -- Cannot break from Level II
17. `test_oplock_break_ack_invalid_fid` -- Invalid FID
18. `test_oplock_break_ack_no_oplock` -- File has no oplock = INVALID_OPLOCK_PROTOCOL

#### Lease Break (MS-SMB2 2.2.23.2)
19. `test_lease_break_ack_rwh_to_rh` -- Break RWH -> RH
20. `test_lease_break_ack_rwh_to_r` -- Break RWH -> R
21. `test_lease_break_ack_rwh_to_none` -- Break RWH -> None
22. `test_lease_break_ack_rw_to_r` -- Break RW -> R
23. `test_lease_break_ack_rw_to_none` -- Break RW -> None
24. `test_lease_break_invalid_state_upgrade` -- Cannot upgrade lease state
25. `test_lease_break_invalid_key` -- Unknown lease key

#### Server-to-Client Notification (MS-SMB2 2.2.44)
26. `test_session_closed_notification_sent` -- Notification sent on logoff
27. `test_session_closed_notification_skips_current` -- Current conn not notified
28. `test_session_closed_notification_311_only` -- Only sent to 3.1.1 channels

---

### ksmbd_test_smb2_compound.c (NEW)

Tests for compound request processing: `is_chained_smb2_message()`, `init_chained_smb2_rsp()`.

#### Basic Compound Processing
1. `test_compound_related_two_requests` -- CREATE + CLOSE related
2. `test_compound_related_three_requests` -- CREATE + READ + CLOSE
3. `test_compound_unrelated_requests` -- Unrelated compound (no FID sharing)
4. `test_compound_single_request` -- Single request is not compound
5. `test_compound_next_command_alignment` -- NextCommand aligned to 8 bytes

#### FID Propagation (MS-SMB2 3.3.5.2.7.2)
6. `test_compound_fid_from_create` -- CREATE response FID propagated to next
7. `test_compound_fid_from_read` -- READ request FID captured for next
8. `test_compound_fid_from_write` -- WRITE request FID captured
9. `test_compound_fid_from_flush` -- FLUSH request FID captured
10. `test_compound_fid_from_close` -- CLOSE request FID captured
11. `test_compound_fid_from_query_info` -- QUERY_INFO request FID captured
12. `test_compound_fid_from_set_info` -- SET_INFO request FID captured
13. `test_compound_fid_from_lock` -- LOCK request FID captured
14. `test_compound_fid_from_ioctl` -- IOCTL request FID captured
15. `test_compound_fid_from_query_dir` -- QUERY_DIRECTORY request FID captured
16. `test_compound_fid_from_notify` -- CHANGE_NOTIFY request FID captured
17. `test_compound_fid_0xffffffffffffffff` -- Related request with 0xFFFFFFFFFFFFFFFF FID

#### Error Cascade
18. `test_compound_error_cascade_create_failure` -- CREATE failure cascades
19. `test_compound_error_no_cascade_non_create` -- Non-CREATE failure does NOT cascade
20. `test_compound_error_status_propagation` -- compound_err_status tracked

#### Interim Responses
21. `test_compound_interim_padding` -- Interim responses 8-byte padded
22. `test_compound_interim_header_only` -- Error response is header-only (9 bytes)

#### Session / Tree Connect in Compound
23. `test_compound_session_id_propagation` -- compound_sid from prior CREATE
24. `test_compound_tree_id_propagation` -- Tree ID from prior TREE_CONNECT

---

### ksmbd_test_smb2_negotiate.c (NEW)

Tests for `smb2_handle_negotiate()`, `smb2_negotiate_request()`, `smb3_encryption_negotiated()`.

#### Basic Negotiate (MS-SMB2 2.2.3)
1. `test_negotiate_smb2_02_only` -- Single dialect 0x0202
2. `test_negotiate_smb2_10_only` -- Single dialect 0x0210
3. `test_negotiate_smb3_00_only` -- Single dialect 0x0300
4. `test_negotiate_smb3_02_only` -- Single dialect 0x0302
5. `test_negotiate_smb3_11_only` -- Single dialect 0x0311
6. `test_negotiate_multi_dialect` -- Multiple dialects, highest selected
7. `test_negotiate_wildcard_0x02ff` -- SMB1-to-SMB2 upgrade with wildcard
8. `test_negotiate_dialect_count_zero` -- DialectCount=0 = INVALID_PARAMETER

#### Second Negotiate Rejection (MS-SMB2 3.3.5.3.1)
9. `test_negotiate_second_on_established` -- Second NEGOTIATE disconnects
10. `test_negotiate_second_sends_no_response` -- send_no_response=1

#### Negotiate Contexts (SMB 3.1.1, MS-SMB2 2.2.3.1)
11. `test_negotiate_preauth_hash_sha512` -- PREAUTH_INTEGRITY_CAPABILITIES
12. `test_negotiate_preauth_hash_missing` -- No preauth context = INVALID_PARAMETER
13. `test_negotiate_encryption_aes128ccm` -- ENCRYPTION_CAPABILITIES AES-128-CCM
14. `test_negotiate_encryption_aes128gcm` -- ENCRYPTION_CAPABILITIES AES-128-GCM
15. `test_negotiate_encryption_aes256ccm` -- ENCRYPTION_CAPABILITIES AES-256-CCM
16. `test_negotiate_encryption_aes256gcm` -- ENCRYPTION_CAPABILITIES AES-256-GCM
17. `test_negotiate_compression_lz77` -- COMPRESSION_CAPABILITIES
18. `test_negotiate_signing_aes_cmac` -- SIGNING_CAPABILITIES AES-CMAC
19. `test_negotiate_signing_aes_gmac` -- SIGNING_CAPABILITIES AES-GMAC
20. `test_negotiate_rdma_transform` -- RDMA_TRANSFORM_CAPABILITIES
21. `test_negotiate_transport_capabilities` -- TRANSPORT_CAPABILITIES
22. `test_negotiate_posix_extensions` -- POSIX_EXTENSIONS_AVAILABLE

#### Duplicate Context Rejection
23. `test_negotiate_duplicate_preauth` -- Duplicate preauth = INVALID_PARAMETER
24. `test_negotiate_duplicate_encrypt` -- Duplicate encrypt = INVALID_PARAMETER
25. `test_negotiate_duplicate_compress` -- Duplicate compress = INVALID_PARAMETER
26. `test_negotiate_duplicate_rdma` -- Duplicate RDMA = INVALID_PARAMETER

#### Signing Algorithm Validation
27. `test_negotiate_signing_count_zero` -- SigningAlgorithmCount=0 = INVALID_PARAMETER
28. `test_negotiate_signing_no_overlap` -- No overlap falls back to AES-CMAC
29. `test_negotiate_compression_count_zero` -- CompressionAlgorithmCount=0 = INVALID_PARAMETER

#### Response Validation
30. `test_negotiate_response_body_zeroed` -- Response body initially zeroed (no heap leakage)
31. `test_negotiate_capabilities_notifications` -- SMB 3.1.1 includes GLOBAL_CAP_NOTIFICATIONS
32. `test_negotiate_max_read_size` -- MaxReadSize in response
33. `test_negotiate_max_write_size` -- MaxWriteSize in response
34. `test_negotiate_max_transact_size` -- MaxTransactSize in response

---

### ksmbd_test_smb2_session.c (NEW)

Tests for `smb2_sess_setup()`.

#### Session Setup (MS-SMB2 2.2.5)
1. `test_sess_setup_ntlmssp_negotiate` -- First round: NEGOTIATE message
2. `test_sess_setup_ntlmssp_authenticate` -- Second round: AUTHENTICATE message
3. `test_sess_setup_anonymous` -- Anonymous auth (NtChallengeResponse.Length=0)
4. `test_sess_setup_null_session_flag` -- SMB2_SESSION_FLAG_IS_NULL_LE set for anonymous
5. `test_sess_setup_guest_fallback` -- Guest account fallback
6. `test_sess_setup_invalid_token` -- Invalid SPNEGO token
7. `test_sess_setup_preauth_hash` -- Pre-auth integrity hash updated

#### Session Binding (MS-SMB2 3.3.5.2.5)
8. `test_sess_setup_binding` -- SMB2_SESSION_FLAG_BINDING multichannel
9. `test_sess_setup_binding_wrong_session` -- Binding to non-existent session

#### Session Encryption
10. `test_sess_setup_encryption_required` -- Session encryption enforcement
11. `test_sess_setup_unencrypted_on_encrypted_rejected` -- STATUS_ACCESS_DENIED + disconnect

#### Kerberos
12. `test_sess_setup_krb5_negotiate` -- Kerberos via SPNEGO
13. `test_sess_setup_krb5_authenticate` -- Kerberos authentication

---

### ksmbd_test_smb2_ops.c (NEW)

Tests for `smb2ops.c` server initialization functions.

#### Protocol Version Initialization
1. `test_init_smb2_0_server_values` -- SMB 2.0.2 values populated correctly
2. `test_init_smb2_0_server_capabilities` -- SMB 2.0.2 capability flags
3. `test_init_smb2_1_server_values` -- SMB 2.1 values
4. `test_init_smb2_1_server_large_mtu` -- SMB 2.1 supports LARGE_MTU
5. `test_init_smb3_0_server_values` -- SMB 3.0 values
6. `test_init_smb3_0_server_multichannel` -- SMB 3.0 multichannel flag
7. `test_init_smb3_02_server_values` -- SMB 3.0.2 values
8. `test_init_smb3_11_server_values` -- SMB 3.1.1 values
9. `test_init_smb3_11_server_notifications` -- SMB 3.1.1 includes NOTIFICATIONS cap

#### Max Size Configuration
10. `test_init_max_read_size` -- init_smb2_max_read_size() updates global
11. `test_init_max_write_size` -- init_smb2_max_write_size() updates global
12. `test_init_max_trans_size` -- init_smb2_max_trans_size() updates global
13. `test_init_max_credits` -- init_smb2_max_credits() updates global
14. `test_init_max_size_zero` -- Zero values handled correctly
15. `test_init_max_size_overflow` -- Very large values clamped

---

### Enhancements to Existing Tests

#### ksmbd_test_pdu_common.c -- Additions
1. `test_reparse_tag_unknown_mode` -- Unknown file type mode (S_IFREG|S_IFDIR combined) returns 0
2. `test_dos_mode_attr_mask_0x5137` -- Verify exactly which attribute bits pass through mask
3. `test_dos_mode_symlink_gets_reparse` -- Symlink mode sets ATTR_REPARSE
4. `test_dos_mode_chr_dev_gets_reparse` -- Character device sets ATTR_REPARSE
5. `test_dos_mode_blk_dev_gets_reparse` -- Block device sets ATTR_REPARSE
6. `test_dos_mode_socket_gets_reparse` -- Socket sets ATTR_REPARSE
7. `test_dos_mode_directory_strips_archive` -- Directory clears ATTR_ARCHIVE

#### ksmbd_test_credit.c -- Additions
8. `test_credit_charge_floor_to_one` -- Actual kernel floors credit_charge to 1 (not 0)
9. `test_credit_charge_max_8mb_large_mtu` -- 8MB with LARGE_MTU capability
10. `test_credit_charge_no_large_mtu` -- Without LARGE_MTU, credit charge = 1 always
11. `test_credit_charge_overflow_u64` -- Very large req_len near U64_MAX

#### ksmbd_test_smb_common.c -- Additions
12. `test_lookup_smb1_nt1` -- "NT1" protocol string (when CONFIG_SMB_INSECURE_SERVER)
13. `test_lookup_smb1_alias` -- "SMB1" alias for "NT1"
14. `test_min_protocol_with_insecure` -- Min protocol includes SMB1 when enabled
15. `test_next_dialect_parsing` -- NUL-terminated packed dialect list parsing

#### ksmbd_test_oplock.c -- Additions
16. `test_lease_to_oplock_handle_only` -- H-only lease maps to 0
17. `test_lease_to_oplock_all_bits_set` -- All 3 bits = batch
18. `test_lease_to_oplock_invalid_bits` -- Bits outside R|W|H ignored

#### ksmbd_test_acl.c -- Additions
19. `test_compare_sids_max_subauth` -- SID with 15 sub-authorities
20. `test_id_to_sid_creator_group` -- SIDCREATOR_GROUP type
21. `test_id_to_sid_boundary_uid_zero` -- UID=0 mapping
22. `test_id_to_sid_boundary_uid_max` -- UID=UINT_MAX mapping
23. `test_smb_inherit_flags_inherit_only` -- INHERIT_ONLY_ACE flag

---

## MS-SMB2 Spec Compliance Tests

Cross-reference with MS-SMB2 specification sections that require specific test verification.

### Section 2.2 -- Message Syntax

| MS-SMB2 Section | Requirement | Test |
|-----------------|-------------|------|
| 2.2.1 | SMB2 header ProtocolId = 0xFE 'S' 'M' 'B' | smb2_header_fuzz.c |
| 2.2.3 | NEGOTIATE request DialectCount > 0 | ksmbd_test_smb2_negotiate.c #8 |
| 2.2.3 | NEGOTIATE DialectCount array fits in buffer | ksmbd_test_smb2_negotiate.c |
| 2.2.3.1 | Negotiate contexts 8-byte aligned | negotiate_context_fuzz.c |
| 2.2.5 | SESSION_SETUP NTLMSSP flow | ksmbd_test_smb2_session.c #1-4 |
| 2.2.9 | TREE_CONNECT path parsing | ksmbd_test_smb2_tree.c #5 |
| 2.2.9.1 | TREE_CONNECT_Request_Extension | ksmbd_test_smb2_tree.c #9-10 |
| 2.2.13 | CREATE NameLength even | ksmbd_test_smb2_create.c #22-23 |
| 2.2.13 | CREATE ImpersonationLevel validation | ksmbd_test_smb2_create.c #32-36 |
| 2.2.19 | READ DataOffset validation | ksmbd_test_smb2_read_write.c #16 |
| 2.2.21 | WRITE Offset=0xFFFFFFFFFFFFFFFF | ksmbd_test_smb2_read_write.c #19-20 |
| 2.2.23 | FLUSH requires write access | ksmbd_test_smb2_read_write.c #34 |
| 2.2.26 | LOCK element array bounds | ksmbd_test_smb2_lock.c #6 |
| 2.2.31 | IOCTL Flags = FSCTL only | ksmbd_test_smb2_ioctl.c #1-3 |
| 2.2.33 | QUERY_DIRECTORY info levels | ksmbd_test_smb2_dir.c #1-9 |
| 2.2.35 | CHANGE_NOTIFY on directory only | ksmbd_test_smb2_notify.c #3-4 |
| 2.2.37 | QUERY_INFO InfoType classes | ksmbd_test_smb2_query_set.c |
| 2.2.39 | SET_INFO validation | ksmbd_test_smb2_query_set.c #44-68 |
| 2.2.44 | Server-to-Client Notification | ksmbd_test_smb2_misc.c #26-28 |

### Section 3.3 -- Server Processing

| MS-SMB2 Section | Requirement | Test |
|-----------------|-------------|------|
| 3.3.5.2.7 | Compound request processing | ksmbd_test_smb2_compound.c |
| 3.3.5.2.7.2 | FID propagation in compounds | ksmbd_test_smb2_compound.c #6-16 |
| 3.3.5.2.10 | ChannelSequence validation | ksmbd_test_smb2_read_write.c #13, #27; ksmbd_test_smb2_ioctl.c #9 |
| 3.3.5.3 | Negotiate processing | ksmbd_test_smb2_negotiate.c |
| 3.3.5.3.1 | Second NEGOTIATE disconnect | ksmbd_test_smb2_negotiate.c #9-10 |
| 3.3.5.4 | Session setup authentication | ksmbd_test_smb2_session.c |
| 3.3.5.5 | Tree connect processing | ksmbd_test_smb2_tree.c |
| 3.3.5.9 | Create processing | ksmbd_test_smb2_create.c |
| 3.3.5.12 | Read processing | ksmbd_test_smb2_read_write.c #1-16 |
| 3.3.5.13 | Write processing | ksmbd_test_smb2_read_write.c #17-31 |
| 3.3.5.14 | Lock processing + sequence replay | ksmbd_test_smb2_lock.c #22-28 |
| 3.3.5.15 | IOCTL processing | ksmbd_test_smb2_ioctl.c |
| 3.3.5.15.6 | Server-side copy | ksmbd_test_smb2_ioctl.c #27-32 |
| 3.3.5.16 | Cancel processing | ksmbd_test_smb2_lock.c #29-31 |
| 3.3.5.17 | Query directory | ksmbd_test_smb2_dir.c |
| 3.3.5.19 | Change notify async | ksmbd_test_smb2_notify.c #18-21 |
| 3.3.5.20 | Query info | ksmbd_test_smb2_query_set.c #1-43 |
| 3.3.5.21 | Set info | ksmbd_test_smb2_query_set.c #44-68 |
| 3.3.5.22 | Oplock/lease break ack | ksmbd_test_smb2_misc.c #13-25 |
| 3.3.5.23 | Close processing | ksmbd_test_smb2_misc.c #1-10 |

---

## Edge Cases and Security Tests

### Buffer Overflow / Out-of-Bounds

| Test | Description | Source File |
|------|-------------|-------------|
| create_context_fuzz.c | Malformed create context chain | smb2_create.c |
| negotiate_context_fuzz.c | Malformed negotiate contexts | smb2_negotiate.c |
| lock_request_fuzz.c | Lock element array overflow | smb2_lock.c |
| security_descriptor_fuzz.c | SD offset validation | smbacl.c |
| transform_header_fuzz.c | Transform header bypass | smb2_pdu_common.c |
| query_set_info_fuzz.c | Info class buffer mismatch | smb2_query_set.c |
| NEW: ioctl_input_offset_fuzz | InputOffset + InputCount overflow | smb2_ioctl.c |
| NEW: write_data_offset_fuzz | DataOffset + DataLength overflow | smb2_read_write.c |
| NEW: read_offset_length_fuzz | Offset + Length loff_t overflow | smb2_read_write.c |
| NEW: compound_next_command_fuzz | NextCommand pointing past buffer | smb2_pdu_common.c |

### Integer Overflow / Underflow

| Test | Description |
|------|-------------|
| `test_credit_charge_u64_max` | Credit charge with U64_MAX request size |
| `test_lock_offset_length_wrap` | Lock offset + length wrapping |
| `test_write_offset_length_overflow` | Write offset + length exceeding LLONG_MAX |
| `test_read_offset_length_overflow` | Read offset + length exceeding LLONG_MAX |
| `test_lock_count_multiply_overflow` | lock_count * sizeof(element) overflow |
| `test_ioctl_input_offset_add_overflow` | InputOffset + InputCount > UINT_MAX |

### Authentication / Authorization Bypass

| Test | Description |
|------|-------------|
| `test_session_encryption_enforcement` | Unencrypted request on encrypted session = ACCESS_DENIED |
| `test_create_access_mask_validation` | Invalid access bits outside DESIRED_ACCESS_MASK |
| `test_flush_requires_write_access` | Flush without write permission |
| `test_notify_requires_list_directory` | Notify without LIST_DIRECTORY |
| `test_delete_on_close_requires_delete` | DoC without DELETE access |
| `test_sacl_requires_system_security` | SACL query without ACCESS_SYSTEM_SECURITY |

### Signing and Encryption

| Test | Description |
|------|-------------|
| `test_smb2_is_sign_req_negotiate_excluded` | NEGOTIATE never signed |
| `test_smb2_is_sign_req_cancel_excluded` | CANCEL never signed (MS-SMB2 3.2.4.24) |
| `test_smb2_is_sign_req_session_setup_excluded` | SESSION_SETUP (first) not signed |
| `test_smb3_check_sign_req_aes_cmac` | AES-CMAC signature verification |
| `test_smb3_check_sign_req_aes_gmac` | AES-GMAC signature verification |
| `test_smb3_encrypt_resp_aes128ccm` | AES-128-CCM encryption |
| `test_smb3_encrypt_resp_aes128gcm` | AES-128-GCM encryption |
| `test_smb3_encrypt_resp_aes256ccm` | AES-256-CCM encryption |
| `test_smb3_encrypt_resp_aes256gcm` | AES-256-GCM encryption |
| `test_smb3_decrypt_req_valid` | Valid decryption |
| `test_smb3_decrypt_req_invalid_signature` | Invalid transform signature |
| `test_smb3_is_transform_hdr_valid` | Valid transform header detected |
| `test_smb3_is_transform_hdr_invalid_protocol` | Wrong ProtocolId rejected |
| `test_smb3_gcm_nonce_limit` | GCM nonce limit detection |

### Pre-authentication Integrity

| Test | Description |
|------|-------------|
| `test_smb3_preauth_hash_negotiate` | Pre-auth hash after negotiate |
| `test_smb3_preauth_hash_session_setup` | Pre-auth hash after session setup rounds |
| `test_smb3_11_final_sess_setup_resp` | Final session setup response detection |

### Resource Exhaustion / DoS

| Test | Description |
|------|-------------|
| `test_max_connections_per_ip` | Connection limit enforcement |
| `test_credit_granting_limits` | Credit window growth limits |
| `test_compound_chain_depth_limit` | Maximum compound chain depth |
| `test_lock_count_limit` | KSMBD_MAX_LOCK_COUNT enforcement |
| `test_tree_connect_max_connections` | Per-share connection limits |
| `test_notify_watch_resource_limit` | Maximum concurrent watches |

---

## Implementation Priority

### Phase 1 -- High Impact (address largest coverage gaps)
1. **ksmbd_test_smb2_compound.c** -- Compound FID propagation is a recent fix area
2. **ksmbd_test_smb2_negotiate.c** -- Negotiate is the entry point, many security checks
3. **ksmbd_test_smb2_read_write.c** -- Core data path, append-to-EOF sentinel fix
4. **ksmbd_test_smb2_lock.c** -- Lock sequence replay was a 5-bug fix area

### Phase 2 -- Medium Impact (protocol completeness)
5. **ksmbd_test_smb2_create.c** -- Largest file, most complex logic
6. **ksmbd_test_smb2_query_set.c** -- Many info levels, all untested
7. **ksmbd_test_smb2_misc.c** -- Close, echo, oplock break
8. **ksmbd_test_smb2_ops.c** -- Server initialization validation

### Phase 3 -- Coverage Completeness
9. **ksmbd_test_smb2_ioctl.c** -- FSCTL dispatch testing
10. **ksmbd_test_smb2_tree.c** -- Tree connect/disconnect
11. **ksmbd_test_smb2_notify.c** -- Change notify
12. **ksmbd_test_smb2_session.c** -- Session setup
13. **Existing test enhancements** -- Edge cases in current suites

### Implementation Notes

All tests use the KUnit framework and run as separate kernel modules. Because KUnit tests cannot link against the ksmbd module directly:

- **Pure-logic functions** should be extracted and replicated inline (as done in existing tests)
- **Request validation functions** can be tested by constructing fake request buffers
- **Full-path handler tests** (e.g., `smb2_open()`) require either:
  - Mocking the `ksmbd_work`/`ksmbd_conn` infrastructure
  - Integration testing via smbtorture (already in vm/ test scripts)
- **Static functions** that contain security-critical logic should be considered for export (with `__ksmbd_test_` prefix) or logic extraction into testable helpers

Total new tests defined in this plan: **~520 across 13 new test files + ~23 additions to existing files**
