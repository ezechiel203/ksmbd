# Test Plan: FSCTL Dispatch, Info-Level Dispatch & Create Contexts

## Current Coverage Summary

### ksmbd_test_fsctl_dispatch.c (13 tests)
Tests ONLY the generic dispatch mechanism (register, unregister, lookup, hash key
computation). Does NOT test any individual FSCTL handler logic, input validation,
output formatting, error paths, or boundary conditions for any specific FSCTL code.

| Test | What it covers |
|------|---------------|
| test_register_and_dispatch | Register handler, dispatch finds it |
| test_dispatch_unregistered | Unknown code returns -EOPNOTSUPP |
| test_unregister_then_dispatch | After unregister, dispatch fails |
| test_duplicate_registration | Duplicate ctl_code returns -EEXIST |
| test_multiple_codes_dispatched | Three handlers dispatched correctly |
| test_handler_error_propagated | Handler error passes through dispatch |
| test_out_len_zeroed_before_dispatch | out_len zeroed on unknown code |
| test_unregister_one_of_many | Unregister one leaves others |
| test_reregister_after_unregister | Re-register after unregister works |
| test_empty_table_dispatch | Empty table returns -EOPNOTSUPP |
| test_hash_key_different_codes | Hash key uniqueness |
| test_hash_key_same_code | Same code same hash |
| test_hash_key_range | Hash output within bit range |

### ksmbd_test_info_dispatch.c (12 tests)
Tests ONLY the generic info dispatch mechanism (hash key, register, unregister,
lookup, duplicate detection, handler invocation stub). Does NOT test any actual
info-level handler logic, buffer validation, or output format.

| Test | What it covers |
|------|---------------|
| test_hash_key_unique_all_different | Different inputs produce different keys |
| test_hash_key_same_type_class_diff_op | GET vs SET produce different keys |
| test_hash_key_same_type_diff_class | Different classes produce different keys |
| test_hash_key_diff_type_same_class | Different types produce different keys |
| test_hash_key_identical_inputs | Same inputs same key |
| test_hash_key_boundary_values | (0,0,GET) and (255,255,SET) boundary |
| test_register_and_lookup | Register then lookup finds handler |
| test_lookup_not_found | Unregistered lookup returns NULL |
| test_register_unregister_lookup_gone | After unregister, lookup returns NULL |
| test_duplicate_registration | Duplicate returns -EEXIST |
| test_multiple_handlers_coexist | Three handlers coexist |
| test_handler_invocation | Handler callback produces expected output |

### ksmbd_test_create_ctx.c (11 tests)
Tests ONLY the generic create context dispatch list (register, find by tag,
unregister, memcmp matching). Does NOT test any actual create context handler
logic, request/response processing, or tag-specific validation.

| Test | What it covers |
|------|---------------|
| test_register_and_find | Register then find by tag succeeds |
| test_find_empty_list | Empty list returns NULL |
| test_unregister_then_find | After unregister, find returns NULL |
| test_multiple_tags_found | Three tags found correctly |
| test_tag_exact_memcmp | Exact memcmp matching, not prefix |
| test_tag_same_prefix_different_suffix | Same prefix different suffix |
| test_tag_not_found | Non-existent tag returns NULL |
| test_case_sensitive | Case-sensitive binary matching |
| test_unregister_one_leaves_others | Unregister one, others remain |
| test_zero_length_tag | Zero-length tag matching |
| test_register_returns_zero | Register always returns 0 |

### Critical Gap
**Zero handler-level tests exist.** All 36 existing tests only cover the
dispatch infrastructure (hash tables, linked lists, register/unregister
lifecycle). None of the 50+ FSCTL handlers, 30+ info-level handlers, or
create context handlers have any test coverage for their actual logic.

---

## Gap Analysis

### Untested FSCTL Codes

All registered FSCTL handlers have zero test coverage. The following are
registered in `builtin_fsctl_handlers[]` (ksmbd_fsctl.c), `extra_handlers[]`
(ksmbd_fsctl_extra.c), and `rsvd_handlers[]` (ksmbd_rsvd.c):

#### Handlers with real logic (HIGH priority)

| FSCTL Code | Handler | Category |
|-----------|---------|----------|
| FSCTL_CREATE_OR_GET_OBJECT_ID | fsctl_create_or_get_object_id_handler | Object ID |
| FSCTL_GET_OBJECT_ID | fsctl_get_object_id_handler | Object ID |
| FSCTL_SET_OBJECT_ID | fsctl_set_object_id_handler | Object ID |
| FSCTL_SET_OBJECT_ID_EXTENDED | fsctl_set_object_id_extended_handler | Object ID |
| FSCTL_DELETE_OBJECT_ID | fsctl_delete_object_id_handler | Object ID |
| FSCTL_GET_COMPRESSION | fsctl_get_compression_handler | Compression |
| FSCTL_SET_COMPRESSION | fsctl_set_compression_handler | Compression |
| FSCTL_SET_SPARSE | fsctl_set_sparse_handler | Sparse |
| FSCTL_SET_ZERO_DATA | fsctl_set_zero_data_handler | Sparse |
| FSCTL_QUERY_ALLOCATED_RANGES | fsctl_query_allocated_ranges_handler | Sparse |
| FSCTL_COPYCHUNK | fsctl_copychunk_handler | Copy |
| FSCTL_COPYCHUNK_WRITE | fsctl_copychunk_write_handler | Copy |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | fsctl_duplicate_extents_handler | Copy |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX | fsctl_duplicate_extents_ex_handler | Copy |
| FSCTL_REQUEST_RESUME_KEY | fsctl_request_resume_key_handler | Copy |
| FSCTL_VALIDATE_NEGOTIATE_INFO | fsctl_validate_negotiate_info_handler | Negotiate |
| FSCTL_PIPE_TRANSCEIVE | fsctl_pipe_transceive_handler | Pipe |
| FSCTL_PIPE_PEEK | fsctl_pipe_peek_handler | Pipe |
| FSCTL_QUERY_NETWORK_INTERFACE_INFO | fsctl_query_network_interface_info_handler | Network |
| FSCTL_QUERY_NETWORK_INTERFACE_INFO_WIN | fsctl_query_network_interface_info_handler | Network |
| FSCTL_IS_VOLUME_DIRTY | fsctl_is_volume_dirty_handler | Volume |
| FSCTL_GET_NTFS_VOLUME_DATA | fsctl_get_ntfs_volume_data_handler | Volume |
| FSCTL_GET_RETRIEVAL_POINTERS | fsctl_get_retrieval_pointers_handler | Volume |
| FSCTL_FILESYSTEM_GET_STATS | fsctl_filesystem_get_stats_handler | Volume |
| FSCTL_QUERY_FILE_REGIONS | fsctl_query_file_regions_handler | Regions |
| FSCTL_GET_INTEGRITY_INFORMATION | fsctl_get_integrity_info_handler | Integrity |
| FSCTL_SET_INTEGRITY_INFORMATION | fsctl_set_integrity_info_handler | Integrity |
| FSCTL_SET_INTEGRITY_INFORMATION_EX | fsctl_set_integrity_info_handler | Integrity |
| FSCTL_MARK_HANDLE | fsctl_mark_handle_handler | Mark |
| FSCTL_OFFLOAD_READ | fsctl_offload_read_handler | ODX |
| FSCTL_OFFLOAD_WRITE | fsctl_offload_write_handler | ODX |
| FSCTL_SRV_READ_HASH | fsctl_srv_read_hash_handler | BranchCache |
| FSCTL_SET_ZERO_ON_DEALLOC | fsctl_set_zero_on_dealloc_handler | Dealloc |
| FSCTL_SET_ENCRYPTION | fsctl_set_encryption_handler | Encryption |

#### Extra handlers (ksmbd_fsctl_extra.c)

| FSCTL Code | Handler | Category |
|-----------|---------|----------|
| FSCTL_FILE_LEVEL_TRIM | ksmbd_fsctl_file_level_trim | Trim |
| FSCTL_PIPE_WAIT | ksmbd_fsctl_pipe_wait | Pipe |
| FSCTL_QUERY_ALLOCATED_RANGES | ksmbd_fsctl_query_allocated_ranges | Sparse |
| FSCTL_SET_ZERO_DATA | ksmbd_fsctl_set_zero_data | Sparse |
| FSCTL_COPYCHUNK | ksmbd_fsctl_copychunk | Copy |
| FSCTL_COPYCHUNK_WRITE | ksmbd_fsctl_copychunk_write | Copy |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | ksmbd_fsctl_duplicate_extents_to_file | Copy |

Note: Some codes appear in both builtin and extra; only the registered copy
is active (extra handlers registered separately at init time).

#### Stub/noop handlers (MEDIUM priority)

| FSCTL Code | Handler |
|-----------|---------|
| FSCTL_IS_PATHNAME_VALID | fsctl_is_pathname_valid_handler (noop success) |
| FSCTL_ALLOW_EXTENDED_DASD_IO | fsctl_stub_noop_success_handler |
| FSCTL_ENCRYPTION_FSCTL_IO | fsctl_stub_noop_success_handler |
| FSCTL_LMR_SET_LINK_TRACK_INF | fsctl_stub_noop_success_handler |
| FSCTL_LOCK_VOLUME | fsctl_stub_noop_success_handler |
| FSCTL_REQUEST_BATCH_OPLOCK | fsctl_stub_noop_success_handler |
| FSCTL_REQUEST_FILTER_OPLOCK | fsctl_stub_noop_success_handler |
| FSCTL_REQUEST_OPLOCK_LEVEL_1 | fsctl_stub_noop_success_handler |
| FSCTL_REQUEST_OPLOCK_LEVEL_2 | fsctl_stub_noop_success_handler |
| FSCTL_SET_SHORT_NAME_BEHAVIOR | fsctl_stub_noop_success_handler |
| FSCTL_UNLOCK_VOLUME | fsctl_stub_noop_success_handler |

#### Not-supported handlers (LOW priority -- verify STATUS_NOT_SUPPORTED)

| FSCTL Code | Handler |
|-----------|---------|
| FSCTL_FIND_FILES_BY_SID | fsctl_not_supported_handler |
| FSCTL_LMR_GET_LINK_TRACK_INF | fsctl_not_supported_handler |
| FSCTL_QUERY_FAT_BPB | fsctl_not_supported_handler |
| FSCTL_QUERY_SPARING_INFO | fsctl_not_supported_handler |
| FSCTL_READ_FILE_USN_DATA | fsctl_not_supported_handler |
| FSCTL_READ_RAW_ENCRYPTED | fsctl_not_supported_handler |
| FSCTL_RECALL_FILE | fsctl_not_supported_handler |
| FSCTL_SET_DEFECT_MANAGEMENT | fsctl_not_supported_handler |
| FSCTL_SIS_COPYFILE | fsctl_not_supported_handler |
| FSCTL_SIS_LINK_FILES | fsctl_not_supported_handler |
| FSCTL_WRITE_RAW_ENCRYPTED | fsctl_not_supported_handler |
| FSCTL_WRITE_USN_CLOSE_RECORD | fsctl_not_supported_handler |
| FSCTL_QUERY_ON_DISK_VOLUME_INFO | fsctl_not_supported_handler |

#### RSVD handlers (ksmbd_rsvd.c)

| FSCTL Code | Handler |
|-----------|---------|
| FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT | fsctl_query_shared_virtual_disk_support_handler |
| FSCTL_SVHDX_SYNC_TUNNEL_REQUEST | fsctl_svhdx_sync_tunnel_handler |
| FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST | fsctl_svhdx_async_tunnel_handler |

**Tunnel sub-operations (dispatched via rsvd_dispatch_tunnel_op):**

| Tunnel OpCode | Handler | Status |
|--------------|---------|--------|
| RSVD_TUNNEL_GET_INITIAL_INFO | rsvd_handle_get_initial_info | Implemented |
| RSVD_TUNNEL_CHECK_CONNECTION_STATUS | rsvd_handle_check_connection_status | Implemented |
| RSVD_TUNNEL_GET_DISK_INFO | rsvd_handle_get_disk_info | Implemented |
| RSVD_TUNNEL_VALIDATE_DISK | rsvd_handle_validate_disk | Implemented |
| RSVD_TUNNEL_SRB_STATUS_OPERATION | rsvd_handle_srb_status | Implemented |
| RSVD_TUNNEL_META_OPERATION_QUERY_PROGRESS | rsvd_handle_meta_op_query_progress | Implemented |
| RSVD_TUNNEL_CHANGE_TRACKING_GET_PARAMETERS | rsvd_handle_change_tracking_get_params | Implemented |
| RSVD_TUNNEL_SCSI_OPERATION | N/A | Stub (NOT_SUPPORTED) |
| RSVD_TUNNEL_META_OPERATION_START | N/A | Stub (NOT_SUPPORTED) |
| RSVD_TUNNEL_VHDSET_QUERY_INFORMATION | N/A | Stub (NOT_SUPPORTED) |
| RSVD_TUNNEL_DELETE_SNAPSHOT | N/A | Stub (NOT_SUPPORTED) |
| RSVD_TUNNEL_CHANGE_TRACKING_START | N/A | Stub (NOT_SUPPORTED) |
| RSVD_TUNNEL_CHANGE_TRACKING_STOP | N/A | Stub (NOT_SUPPORTED) |
| RSVD_TUNNEL_QUERY_VIRTUAL_DISK_CHANGES | N/A | Stub (NOT_SUPPORTED) |
| RSVD_TUNNEL_QUERY_SAFE_SIZE | N/A | Stub (NOT_SUPPORTED) |

### Untested Info Levels

All registered info handlers have zero test coverage. The following are
registered in `builtin_info_handlers[]` (ksmbd_info.c):

#### File Info Levels (SMB2_O_INFO_FILE)

| Class | Name | Op | Handler |
|-------|------|-----|---------|
| 9 | FILE_NAME_INFORMATION | GET | ksmbd_info_get_file_name |
| 23 | FILE_PIPE_INFORMATION | GET | ksmbd_info_get_pipe |
| 23 | FILE_PIPE_INFORMATION | SET | ksmbd_info_set_pipe_info |
| 24 | FILE_PIPE_LOCAL_INFORMATION | GET | ksmbd_info_get_pipe_local |
| 25 | FILE_PIPE_REMOTE_INFORMATION | GET | ksmbd_info_get_pipe_remote |
| 25 | FILE_PIPE_REMOTE_INFORMATION | SET | ksmbd_info_set_pipe_remote |
| 26 | FILE_MAILSLOT_QUERY_INFORMATION | GET | ksmbd_info_get_mailslot_query |
| 27 | FILE_MAILSLOT_SET_INFORMATION | SET | ksmbd_info_set_mailslot |
| 31 | FILE_MOVE_CLUSTER_INFORMATION | SET | ksmbd_info_set_noop_consume |
| 36 | FILE_TRACKING_INFORMATION | SET | ksmbd_info_set_noop_consume |
| 40 | FILE_SHORT_NAME_INFORMATION | SET | ksmbd_info_set_noop_consume |
| 39 | FILE_VALID_DATA_LENGTH_INFORMATION | SET | ksmbd_info_set_valid_data_length |
| 44 | FILE_SFIO_RESERVE_INFORMATION | SET | ksmbd_info_set_noop_consume |
| 45 | FILE_SFIO_VOLUME_INFORMATION | SET | ksmbd_info_set_noop_consume |
| 46 | FILE_HARD_LINK_INFORMATION | GET | ksmbd_info_get_hard_link |
| 48 | FILE_NORMALIZED_NAME_INFORMATION | GET | ksmbd_info_get_normalized_name |
| 47 | FILE_PROCESS_IDS_USING_FILE_INFORMATION | GET | ksmbd_info_get_process_ids_using_file |
| 49 | FILE_NETWORK_PHYSICAL_NAME_INFORMATION | GET | ksmbd_info_get_network_physical_name |
| 50 | FILE_VOLUME_NAME_INFORMATION | GET | ksmbd_info_get_volume_name |
| 51 | FILE_IS_REMOTE_DEVICE_INFORMATION | GET | ksmbd_info_get_is_remote_device |
| 55 | FILE_REMOTE_PROTOCOL_INFORMATION | GET | ksmbd_info_get_remote_protocol |
| 71 | FILE_CASE_SENSITIVE_INFORMATION | GET | ksmbd_info_get_case_sensitive |
| 71 | FILE_CASE_SENSITIVE_INFORMATION | SET | ksmbd_info_set_case_sensitive |
| 70 | FILE_STAT_INFORMATION | GET | ksmbd_info_get_file_stat |

Note: FileStatLxInformation (class 71) also has a handler
(ksmbd_info_get_file_stat_lx) that is shadowed in the hash table
by FILE_CASE_SENSITIVE_INFORMATION and only reachable via explicit
switch case in smb2_get_info_file().

#### Filesystem Info Levels (SMB2_O_INFO_FILESYSTEM)

| Class | Name | Op | Handler |
|-------|------|-----|---------|
| 6 | FS_CONTROL_INFORMATION | SET | ksmbd_info_set_fs_control |
| 9 | FS_DRIVER_PATH_INFORMATION | GET | ksmbd_info_get_fs_driver_path |
| 8 | FS_LABEL_INFORMATION | SET | ksmbd_info_set_fs_label |
| 2 | FS_OBJECT_ID_INFORMATION | SET | ksmbd_info_set_fs_object_id |

#### Quota Info Levels (SMB2_O_INFO_QUOTA)

| Class | Name | Op | Handler |
|-------|------|-----|---------|
| 32 | FILE_QUOTA_INFORMATION | GET | ksmbd_info_get_quota |
| 32 | FILE_QUOTA_INFORMATION | SET | ksmbd_info_set_quota |

#### Info levels handled in smb2_query_set.c (NOT in dispatch table)

These are handled directly in smb2_get_info_file()/smb2_set_info_file()
before the dispatch table is consulted:

| Class | Name | Notes |
|-------|------|-------|
| 4 | FILE_BASIC_INFORMATION | GET/SET in smb2_query_set.c |
| 5 | FILE_STANDARD_INFORMATION | GET in smb2_query_set.c |
| 6 | FILE_INTERNAL_INFORMATION | GET in smb2_query_set.c |
| 7 | FILE_EA_INFORMATION | GET in smb2_query_set.c |
| 8 | FILE_ACCESS_INFORMATION | GET in smb2_query_set.c |
| 10 | FILE_RENAME_INFORMATION | SET in smb2_query_set.c |
| 11 | FILE_LINK_INFORMATION | SET in smb2_query_set.c |
| 12 | FILE_DISPOSITION_INFORMATION | SET in smb2_query_set.c |
| 13 | FILE_POSITION_INFORMATION | GET/SET in smb2_query_set.c |
| 14 | FILE_FULL_EA_INFORMATION | GET/SET in smb2_query_set.c |
| 15 | FILE_MODE_INFORMATION | GET/SET in smb2_query_set.c |
| 16 | FILE_ALIGNMENT_INFORMATION | GET in smb2_query_set.c |
| 17 | FILE_ALL_INFORMATION | GET in smb2_query_set.c |
| 18 | FILE_ALLOCATION_INFORMATION | SET in smb2_query_set.c |
| 19 | FILE_END_OF_FILE_INFORMATION | SET in smb2_query_set.c |
| 22 | FILE_STREAM_INFORMATION | GET in smb2_query_set.c |
| 34 | FILE_NETWORK_OPEN_INFORMATION | GET in smb2_query_set.c |
| 35 | FILE_ATTRIBUTE_TAG_INFORMATION | GET in smb2_query_set.c |
| 64 | FILE_DISPOSITION_INFORMATION_EX | SET in smb2_query_set.c |

### Untested Create Context Tags

All registered create context handlers have zero test coverage:

| Tag | Name | Handlers |
|-----|------|----------|
| "MxAc" | SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST | mxac_on_request, mxac_on_response |
| "QFid" | SMB2_CREATE_QUERY_ON_DISK_ID | qfid_on_request, qfid_on_response |

#### Create contexts handled directly in smb2_create.c (NOT in dispatch table)

These are parsed inline in smb2_open() and do not go through the
ksmbd_create_ctx dispatch system:

| Tag | Name | Notes |
|-----|------|-------|
| "SecD" | SMB2_CREATE_SD_BUFFER | Security descriptor |
| "ExtA" | SMB2_CREATE_EA_BUFFER | Extended attributes |
| "DHnQ" | SMB2_CREATE_DURABLE_HANDLE_REQUEST | Durable handle v1 |
| "DHnC" | SMB2_CREATE_DURABLE_HANDLE_RECONNECT | Durable reconnect v1 |
| "DH2Q" | SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 | Durable handle v2 |
| "DH2C" | SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 | Durable reconnect v2 |
| "AlSi" | SMB2_CREATE_ALLOCATION_SIZE | Allocation size |
| "TWrp" | SMB2_CREATE_TIMEWARP_REQUEST | Timewarp |
| "RqLs" | SMB2_CREATE_REQUEST_LEASE | Lease |
| POSIX tag | SMB2_CREATE_TAG_POSIX | POSIX extensions |
| "AAPL" | SMB2_CREATE_AAPL | Apple extensions |
| AppInstanceId | SMB2_CREATE_APP_INSTANCE_ID | App instance |
| AppInstanceVersion | SMB2_CREATE_APP_INSTANCE_VERSION | App instance version |

---

## New Tests Required

### ksmbd_test_fsctl_dispatch.c Enhancements

The existing dispatch tests are adequate for infrastructure coverage.
Add these additional infrastructure tests:

1. **test_max_capacity** - Fill all 32 handler slots, verify -ENOMEM on 33rd
2. **test_dispatch_null_out_len** - Verify behavior with NULL out_len (if applicable)
3. **test_concurrent_register_dispatch** - Stress test register while dispatching
4. **test_handler_receives_correct_params** - Verify ctl_code, in_buf, in_len passed through

### ksmbd_test_fsctl_copychunk.c (NEW)

FSCTL_COPYCHUNK and FSCTL_COPYCHUNK_WRITE copychunk validation.

| Test | Description |
|------|-------------|
| test_copychunk_zero_chunk_count | ChunkCount=0 returns limits in response |
| test_copychunk_max_chunk_count_exceeded | ChunkCount > max returns STATUS_INVALID_PARAMETER |
| test_copychunk_max_chunk_size_exceeded | Individual chunk length > max |
| test_copychunk_max_total_size_exceeded | Total bytes > max_total_size |
| test_copychunk_zero_length_chunk | Individual chunk with Length=0 |
| test_copychunk_input_too_small | in_buf_len <= sizeof(copychunk_ioctl_req) |
| test_copychunk_output_too_small | max_out_len < sizeof(copychunk_ioctl_rsp) |
| test_copychunk_invalid_resume_key | ResumeKey mismatches source FID |
| test_copychunk_source_not_found | Source FID not found |
| test_copychunk_dest_not_found | Destination FID not found |
| test_copychunk_read_only_tree | Tree connection not writable |
| test_copychunk_access_denied_src_no_read | Source lacks FILE_READ_DATA |
| test_copychunk_access_denied_dst_no_write | Dest lacks FILE_WRITE_DATA |
| test_copychunk_vs_copychunk_write_read_check | COPYCHUNK requires dest READ, COPYCHUNK_WRITE does not |
| test_copychunk_overlapping_src_dst_ranges | Source and dest overlap |
| test_copychunk_cross_file_same_server | Copy between different files |
| test_copychunk_response_fields_on_success | ChunksWritten, TotalBytesWritten correct |
| test_copychunk_response_fields_on_invalid_param | Response carries server limits |
| test_copychunk_lock_conflict | Lock on source/dest range |
| test_copychunk_disk_full | ENOSPC/EFBIG returns STATUS_DISK_FULL |

### ksmbd_test_fsctl_sparse.c (NEW)

FSCTL_SET_SPARSE, FSCTL_QUERY_ALLOCATED_RANGES, FSCTL_SET_ZERO_DATA.

| Test | Description |
|------|-------------|
| test_set_sparse_enable | SetSparse=TRUE sets ATTR_SPARSE_FILE_LE |
| test_set_sparse_disable | SetSparse=FALSE clears ATTR_SPARSE_FILE_LE |
| test_set_sparse_no_buffer | Empty buffer defaults to sparse=TRUE (MS-FSCC 2.3.64) |
| test_set_sparse_directory_rejected | Directory returns STATUS_INVALID_PARAMETER |
| test_set_sparse_access_denied | No write access returns STATUS_ACCESS_DENIED |
| test_set_sparse_persist_dos_attrs | DOS attribute persisted after SET_SPARSE |
| test_query_allocated_ranges_normal | Valid range returns allocated entries |
| test_query_allocated_ranges_empty_file | Empty file returns no entries |
| test_query_allocated_ranges_negative_offset | Negative offset returns STATUS_INVALID_PARAMETER |
| test_query_allocated_ranges_zero_length | Length=0 returns empty |
| test_query_allocated_ranges_buffer_overflow | Too many entries returns STATUS_BUFFER_OVERFLOW |
| test_query_allocated_ranges_buffer_too_small | Output buffer cannot hold even one entry |
| test_query_allocated_ranges_no_read_access | Missing FILE_READ_DATA returns STATUS_ACCESS_DENIED |
| test_query_allocated_ranges_invalid_handle | Bad FID returns STATUS_INVALID_HANDLE |
| test_set_zero_data_normal | Normal zero range succeeds |
| test_set_zero_data_zero_length | BeyondFinalZero == FileOffset (noop) |
| test_set_zero_data_negative_offset | Negative FileOffset returns STATUS_INVALID_PARAMETER |
| test_set_zero_data_offset_gt_beyond | FileOffset > BeyondFinalZero returns STATUS_INVALID_PARAMETER |
| test_set_zero_data_buffer_too_small | in_buf_len < sizeof(file_zero_data_information) |
| test_set_zero_data_read_only_tree | Not writable returns STATUS_ACCESS_DENIED |
| test_set_zero_data_no_write_data | Handle missing FILE_WRITE_DATA returns STATUS_ACCESS_DENIED |
| test_set_zero_data_lock_conflict | Conflicting lock returns STATUS_FILE_LOCK_CONFLICT |

### ksmbd_test_fsctl_integrity.c (NEW)

FSCTL_GET_INTEGRITY_INFORMATION, FSCTL_SET_INTEGRITY_INFORMATION,
FSCTL_SET_INTEGRITY_INFORMATION_EX.

| Test | Description |
|------|-------------|
| test_get_integrity_normal | Returns integrity info structure |
| test_get_integrity_buffer_too_small | max_out_len too small |
| test_get_integrity_invalid_handle | Bad FID |
| test_set_integrity_normal | Accepts integrity info |
| test_set_integrity_buffer_too_small | in_buf_len too small |
| test_set_integrity_invalid_handle | Bad FID |
| test_set_integrity_ex_same_handler | _EX routes to same handler |

### ksmbd_test_fsctl_odx.c (NEW - Offload Data Transfer)

FSCTL_OFFLOAD_READ, FSCTL_OFFLOAD_WRITE, and ODX token lifecycle.

| Test | Description |
|------|-------------|
| test_offload_read_normal | Returns token in response |
| test_offload_read_buffer_too_small | Output buffer too small |
| test_offload_read_input_too_small | Input buffer too small |
| test_offload_read_invalid_handle | Bad FID |
| test_offload_read_access_denied | No FILE_READ_DATA |
| test_offload_read_beyond_eof | Offset beyond file size |
| test_offload_write_normal | Writes using token |
| test_offload_write_invalid_token | Bad/expired token |
| test_offload_write_buffer_too_small | Output too small |
| test_offload_write_input_too_small | Input too small |
| test_offload_write_access_denied | No FILE_WRITE_DATA |
| test_offload_write_not_writable | Read-only tree connection |
| test_odx_token_expiry | Token expires after timeout |

### ksmbd_test_fsctl_duplicate.c (NEW)

FSCTL_DUPLICATE_EXTENTS_TO_FILE, FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX.

| Test | Description |
|------|-------------|
| test_duplicate_normal | Clone file range succeeds |
| test_duplicate_input_too_small | in_buf_len < sizeof(duplicate_extents_to_file) |
| test_duplicate_source_not_found | Source FID invalid |
| test_duplicate_dest_not_found | Dest FID invalid |
| test_duplicate_read_only_tree | Not writable returns ACCESS_DENIED |
| test_duplicate_src_no_read | Source lacks FILE_READ_DATA |
| test_duplicate_dst_no_write | Dest lacks FILE_WRITE_DATA |
| test_duplicate_offset_overflow | src_off + length overflows |
| test_duplicate_cross_device | Different filesystems returns NOT_SUPPORTED |
| test_duplicate_disk_full | ENOSPC returns STATUS_DISK_FULL |
| test_duplicate_ex_atomic_flag | ATOMIC flag accepted (advisory) |
| test_duplicate_ex_input_too_small | EX struct input validation |

### ksmbd_test_fsctl_reparse.c (NEW)

FSCTL_SET_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, FSCTL_DELETE_REPARSE_POINT.
(If these FSCTLs are implemented; currently not in the dispatch table but
referenced in MS-FSCC.)

| Test | Description |
|------|-------------|
| test_reparse_not_registered | Returns -EOPNOTSUPP if not in dispatch table |

### ksmbd_test_fsctl_object_id.c (NEW)

Object ID FSCTLs: CREATE_OR_GET, GET, SET, SET_EXTENDED, DELETE.

| Test | Description |
|------|-------------|
| test_create_or_get_object_id_normal | Creates object ID when absent, returns existing |
| test_create_or_get_object_id_buffer_too_small | max_out_len < sizeof(type1 response) |
| test_create_or_get_object_id_invalid_handle | Bad FID returns STATUS_FILE_CLOSED |
| test_get_object_id_existing | Returns existing xattr-based object ID |
| test_get_object_id_no_xattr | Returns fallback inode-based ID |
| test_get_object_id_xattr_wrong_size | xattr size != 16 returns -EINVAL |
| test_set_object_id_normal | Sets 16-byte object ID |
| test_set_object_id_input_too_small | in_buf_len < 16 returns STATUS_INVALID_PARAMETER |
| test_set_object_id_read_only_tree | Not writable returns STATUS_ACCESS_DENIED |
| test_set_object_id_invalid_handle | Bad FID returns STATUS_FILE_CLOSED |
| test_set_object_id_extended_same_logic | Extended routes to same common handler |
| test_delete_object_id_normal | Deletes xattr |
| test_delete_object_id_not_found | ENOENT/ENODATA is not an error |
| test_delete_object_id_read_only_tree | Not writable returns STATUS_ACCESS_DENIED |
| test_delete_object_id_invalid_handle | Bad FID returns STATUS_INVALID_HANDLE |

### ksmbd_test_fsctl_compression.c (NEW)

FSCTL_GET_COMPRESSION, FSCTL_SET_COMPRESSION.

| Test | Description |
|------|-------------|
| test_get_compression_none | Non-compressed file returns COMPRESSION_FORMAT_NONE |
| test_get_compression_lznt1 | ATTR_COMPRESSED file returns COMPRESSION_FORMAT_LZNT1 |
| test_get_compression_buffer_too_small | max_out_len < 2 |
| test_get_compression_invalid_handle | Bad FID |
| test_set_compression_none | COMPRESSION_FORMAT_NONE succeeds, clears attr |
| test_set_compression_lznt1_rejected | LZNT1 returns STATUS_NOT_SUPPORTED |
| test_set_compression_input_too_small | in_buf_len < 2 |
| test_set_compression_read_only_tree | Not writable |
| test_set_compression_invalid_handle | Bad FID |

### ksmbd_test_fsctl_validate_negotiate.c (NEW)

FSCTL_VALIDATE_NEGOTIATE_INFO.

| Test | Description |
|------|-------------|
| test_validate_negotiate_success | Matching params returns valid response |
| test_validate_negotiate_dialect_mismatch | Wrong dialect terminates connection |
| test_validate_negotiate_guid_mismatch | Wrong GUID terminates connection |
| test_validate_negotiate_security_mode_mismatch | Wrong security mode |
| test_validate_negotiate_capabilities_mismatch | Wrong capabilities |
| test_validate_negotiate_input_too_small | Buffer < min header size |
| test_validate_negotiate_output_too_small | max_out_len < response size |
| test_validate_negotiate_dialect_count_overflow | DialectCount exceeds buffer |
| test_validate_negotiate_response_fields | ServerGuid, Capabilities, Dialect correct |

### ksmbd_test_fsctl_pipe.c (NEW)

FSCTL_PIPE_TRANSCEIVE, FSCTL_PIPE_PEEK, FSCTL_PIPE_WAIT.

| Test | Description |
|------|-------------|
| test_pipe_peek_connected | Open FID returns CONNECTED state |
| test_pipe_peek_disconnected | Missing FID returns DISCONNECTED state |
| test_pipe_peek_buffer_too_small | max_out_len < sizeof(peek_rsp) |
| test_pipe_wait_no_request_data | Empty buffer returns success |
| test_pipe_wait_pipe_available | Open FID returns success immediately |
| test_pipe_wait_pipe_unavailable | No FID returns STATUS_IO_TIMEOUT |
| test_pipe_wait_timeout_specified | Custom timeout capped at 500ms |
| test_pipe_wait_timeout_zero | Zero timeout uses default |
| test_pipe_transceive_rpc_ok | Valid RPC returns payload |
| test_pipe_transceive_buffer_overflow | Response exceeds max returns STATUS_BUFFER_OVERFLOW |
| test_pipe_transceive_not_implemented | ENOTIMPLEMENTED RPC returns empty |

### ksmbd_test_fsctl_volume.c (NEW)

FSCTL_IS_VOLUME_DIRTY, FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_GET_RETRIEVAL_POINTERS,
FSCTL_FILESYSTEM_GET_STATS.

| Test | Description |
|------|-------------|
| test_volume_dirty_returns_clean | Always returns 0 (not dirty) |
| test_volume_dirty_buffer_too_small | max_out_len < 4 |
| test_ntfs_volume_data_normal | Returns populated structure |
| test_ntfs_volume_data_buffer_too_small | max_out_len < sizeof |
| test_ntfs_volume_data_no_share | No tcon/share returns STATUS_INVALID_PARAMETER |
| test_retrieval_pointers_normal | Single contiguous extent returned |
| test_retrieval_pointers_empty_file | ExtentCount=0 for empty file |
| test_retrieval_pointers_vcn_beyond_eof | Starting VCN >= total clusters |
| test_retrieval_pointers_input_too_small | in_buf_len < sizeof(input) |
| test_retrieval_pointers_buffer_too_small | Output buffer too small |
| test_filesystem_get_stats_normal | Returns NTFS-type statistics |
| test_filesystem_get_stats_buffer_too_small | max_out_len < sizeof |

### ksmbd_test_fsctl_misc.c (NEW)

FSCTL_SET_ZERO_ON_DEALLOC, FSCTL_SET_ENCRYPTION, FSCTL_MARK_HANDLE,
FSCTL_QUERY_FILE_REGIONS, FSCTL_SRV_READ_HASH, stubs and not-supported.

| Test | Description |
|------|-------------|
| test_set_zero_on_dealloc_valid_handle | Accepts hint, returns success |
| test_set_zero_on_dealloc_invalid_handle | Bad FID returns STATUS_INVALID_HANDLE |
| test_set_encryption_returns_not_supported | Always STATUS_NOT_SUPPORTED |
| test_mark_handle_valid_handle | Accepts advisory, returns success |
| test_mark_handle_invalid_handle | Bad FID |
| test_mark_handle_with_info_buffer | Parses UsnSourceInfo/HandleInfo/CopyNumber |
| test_query_file_regions_normal | Returns valid data regions |
| test_query_file_regions_empty_file | No regions for empty file |
| test_query_file_regions_buffer_too_small | min_out < header + 1 entry |
| test_query_file_regions_invalid_handle | Bad FID |
| test_query_file_regions_offset_beyond_eof | Offset >= file_size |
| test_srv_read_hash_returns_hash_response | Returns BranchCache hash |
| test_stub_noop_success_returns_zero | All noop stubs return 0, out_len=0 |
| test_not_supported_returns_eopnotsupp | All not-supported stubs return STATUS_NOT_SUPPORTED |
| test_is_pathname_valid_returns_success | Always succeeds with out_len=0 |

### ksmbd_test_info_dispatch.c Enhancements

Add these to the existing test file:

1. **test_hash_key_collision_handling** - Two handlers with same hash bucket
   but different (type, class, op) tuples both found correctly
2. **test_dispatch_module_ref_failure** - try_module_get returns false
3. **test_dispatch_unknown_returns_eopnotsupp** - Unregistered (type,class,op)

### ksmbd_test_info_file.c (NEW - all file info classes)

| Test | Description |
|------|-------------|
| test_file_name_normal | Returns UTF-16LE name relative to share |
| test_file_name_buffer_too_small | buf_len < 4 returns -ENOSPC |
| test_file_name_no_fp | fp=NULL returns -EINVAL |
| test_pipe_info_get_defaults | Returns ReadMode=0, CompletionMode=0 |
| test_pipe_info_get_buffer_too_small | buf_len too small |
| test_pipe_local_info_defaults | Returns default pipe local fields |
| test_pipe_local_info_buffer_too_small | buf_len too small |
| test_pipe_remote_info_defaults | Returns zeroed structure |
| test_pipe_remote_info_buffer_too_small | buf_len too small |
| test_mailslot_query_defaults | Returns zeroed structure |
| test_mailslot_query_buffer_too_small | buf_len too small |
| test_hard_link_single_link | nlink=1 returns single entry |
| test_hard_link_multiple_links | nlink>1 enumerates parent directory |
| test_hard_link_buffer_too_small | buf_len < header returns -ENOSPC |
| test_hard_link_no_fp | fp=NULL returns -EINVAL |
| test_normalized_name_smb311 | SMB 3.1.1 returns normalized path |
| test_normalized_name_pre_311 | Pre-3.1.1 returns -ENOSYS |
| test_normalized_name_root | Root path returns empty name |
| test_normalized_name_stream | Stream handle appends ":streamname" |
| test_normalized_name_buffer_too_small | buf_len < 4 returns -ENOSPC |
| test_process_ids_returns_empty | NumberOfProcessIdsInList=0 |
| test_process_ids_buffer_too_small | buf_len too small |
| test_network_physical_name_normal | Returns \\server\share\path |
| test_network_physical_name_buffer_too_small | buf_len too small |
| test_volume_name_normal | Returns \\sharename |
| test_volume_name_buffer_too_small | buf_len too small |
| test_is_remote_device_returns_zero | Flags=0 |
| test_is_remote_device_buffer_too_small | buf_len too small |
| test_remote_protocol_smb311 | Returns version 3.1.1 |
| test_remote_protocol_smb20 | Returns version 2.0.0 |
| test_remote_protocol_buffer_too_small | buf_len too small |
| test_case_sensitive_get_returns_zero | Flags=0 |
| test_case_sensitive_get_buffer_too_small | buf_len too small |
| test_case_sensitive_set_enable | Sets FS_CASEFOLD_FL |
| test_case_sensitive_set_disable | Clears FS_CASEFOLD_FL |
| test_case_sensitive_set_buffer_too_small | buf_len too small |
| test_case_sensitive_set_invalid_flags | Unknown flags return -EINVAL |
| test_file_stat_normal | Returns all stat fields populated |
| test_file_stat_buffer_too_small | buf_len < 56 returns -ENOSPC |
| test_file_stat_no_fp | fp=NULL returns -EINVAL |
| test_file_stat_stream | Stream returns stream size |
| test_file_stat_lx_normal | Returns LxUid/LxGid/LxMode fields |
| test_file_stat_lx_xattr_fallback | No xattr falls back to kstat |
| test_valid_data_length_set_normal | Valid length accepted |
| test_valid_data_length_set_negative | Negative length returns -EINVAL |
| test_valid_data_length_set_buffer_too_small | buf_len too small |
| test_valid_data_length_set_no_fp | fp=NULL returns -EINVAL |

### ksmbd_test_info_file_set.c (NEW - SET info noop consumers)

| Test | Description |
|------|-------------|
| test_pipe_info_set_normal | Consumes sizeof(pipe_info) bytes |
| test_pipe_info_set_buffer_too_small | Returns -EMSGSIZE |
| test_pipe_remote_set_normal | Consumes sizeof(pipe_remote_info) bytes |
| test_pipe_remote_set_buffer_too_small | Returns -EMSGSIZE |
| test_mailslot_set_normal | Consumes sizeof(mailslot_set_info) bytes |
| test_mailslot_set_buffer_too_small | Returns -EMSGSIZE |
| test_move_cluster_set_consumes_all | Noop consumer eats all bytes |
| test_tracking_set_consumes_all | Noop consumer eats all bytes |
| test_short_name_set_consumes_all | Noop consumer eats all bytes |
| test_sfio_reserve_set_consumes_all | Noop consumer eats all bytes |
| test_sfio_volume_set_consumes_all | Noop consumer eats all bytes |

### ksmbd_test_info_fs.c (NEW - all filesystem info classes)

| Test | Description |
|------|-------------|
| test_fs_control_set_normal | Accepts smb2_fs_control_info, returns success |
| test_fs_control_set_buffer_too_small | Returns -EMSGSIZE |
| test_fs_driver_path_get_normal | Returns zeroed structure |
| test_fs_driver_path_get_buffer_too_small | Returns -ENOSPC |
| test_fs_label_set_normal | Consumes label data |
| test_fs_label_set_buffer_too_small | Returns -EMSGSIZE |
| test_fs_label_set_odd_label_length | Returns -EINVAL |
| test_fs_label_set_length_exceeds_buffer | Returns -EINVAL |
| test_fs_object_id_set_normal | Consumes object_id_info data |
| test_fs_object_id_set_buffer_too_small | Returns -EMSGSIZE |

### ksmbd_test_info_security.c (NEW - security descriptor get/set)

Security info is handled in smb2_query_set.c directly, not through
the dispatch table. These tests verify the dispatch table does NOT
have a security handler (correct separation of concerns).

| Test | Description |
|------|-------------|
| test_security_info_not_in_dispatch | Lookup (SMB2_O_INFO_SECURITY, *, GET) returns -EOPNOTSUPP |

### ksmbd_test_info_quota.c (NEW)

| Test | Description |
|------|-------------|
| test_quota_get_returns_empty | out_len=0, returns success |
| test_quota_set_consumes_all | Accepts all bytes, returns success |
| test_quota_set_zero_bytes | Zero-length buf accepted |

### ksmbd_test_create_ctx.c Enhancements

Add to existing test file:

1. **test_mxac_request_empty_payload** - ctx_len=0 accepted
2. **test_mxac_request_8byte_timestamp** - ctx_len=8 accepted
3. **test_mxac_request_invalid_length** - ctx_len=3 returns -EINVAL
4. **test_qfid_request_empty** - ctx_len=0 accepted
5. **test_qfid_request_nonzero_rejected** - ctx_len>0 returns -EINVAL
6. **test_mxac_response_stub** - on_response sets rsp_len=0
7. **test_qfid_response_stub** - on_response sets rsp_len=0
8. **test_module_ref_taken** - ksmbd_find_create_context takes module ref
9. **test_module_ref_released** - ksmbd_put_create_context releases module ref
10. **test_init_registers_both_builtin** - ksmbd_create_ctx_init registers MxAc and QFid
11. **test_exit_unregisters_all** - ksmbd_create_ctx_exit removes all

### ksmbd_test_create_ctx_tags.c (NEW)

Test all defined create context tags for the dispatch list:

| Test | Description |
|------|-------------|
| test_find_mxac_tag | "MxAc" found after init |
| test_find_qfid_tag | "QFid" found after init |
| test_find_unknown_tag | "XXXX" returns NULL |
| test_find_secd_not_in_list | "SecD" handled inline, not in list |
| test_find_dhq_not_in_list | "DHnQ" handled inline, not in list |
| test_find_rqls_not_in_list | "RqLs" handled inline, not in list |
| test_find_posix_tag_not_in_list | POSIX 16-byte tag not in list |
| test_register_custom_tag | Register and find custom extension tag |
| test_unregister_custom_tag | Unregister custom tag, lookup fails |

### ksmbd_test_rsvd.c (NEW)

RSVD tunnel structures and sub-operation dispatch.

| Test | Description |
|------|-------------|
| test_query_svhd_support_normal | Returns SVHD_SUPPORT_SHARED |
| test_query_svhd_support_buffer_too_small | max_out_len too small |
| test_tunnel_header_too_small | in_buf_len < header size returns error |
| test_tunnel_invalid_opcode_prefix | Upper byte != 0x02 returns STATUS_INVALID_DEVICE_REQUEST |
| test_tunnel_unknown_version_bits | Non-v1/v2 version returns STATUS_SVHDX_VERSION_MISMATCH |
| test_tunnel_output_too_small_for_header | max_out_len < header returns STATUS_BUFFER_TOO_SMALL |
| test_tunnel_get_initial_info | Returns ServerVersion=2, SectorSize=512 |
| test_tunnel_get_initial_info_buffer_too_small | Payload buffer too small |
| test_tunnel_check_connection_status | Returns success with no payload |
| test_tunnel_get_disk_info | Returns DiskType=DYNAMIC, Format=VHDX |
| test_tunnel_get_disk_info_buffer_too_small | Payload buffer too small |
| test_tunnel_validate_disk | Returns IsValidDisk=0 |
| test_tunnel_validate_disk_buffer_too_small | Payload buffer too small |
| test_tunnel_srb_status | Returns all-zero SRB status |
| test_tunnel_srb_status_buffer_too_small | Payload buffer too small |
| test_tunnel_meta_op_query_progress | Returns 100/100 complete |
| test_tunnel_meta_op_query_progress_buffer_too_small | Payload buffer too small |
| test_tunnel_change_tracking_params | Returns zeroed structure |
| test_tunnel_change_tracking_buffer_too_small | Payload buffer too small |
| test_tunnel_scsi_not_supported | Returns STATUS_NOT_SUPPORTED |
| test_tunnel_meta_start_not_supported | Returns STATUS_NOT_SUPPORTED |
| test_tunnel_vhdset_query_not_supported | Returns STATUS_NOT_SUPPORTED |
| test_tunnel_delete_snapshot_not_supported | Returns STATUS_NOT_SUPPORTED |
| test_tunnel_change_start_not_supported | Returns STATUS_NOT_SUPPORTED |
| test_tunnel_change_stop_not_supported | Returns STATUS_NOT_SUPPORTED |
| test_tunnel_query_changes_not_supported | Returns STATUS_NOT_SUPPORTED |
| test_tunnel_query_safe_size_not_supported | Returns STATUS_NOT_SUPPORTED |
| test_tunnel_unknown_opcode | Unknown opcode returns STATUS_INVALID_PARAMETER |
| test_tunnel_response_header_echoed | OperationCode and RequestId echoed in response |
| test_tunnel_out_len_includes_header | Total out_len = header + payload |
| test_async_tunnel_dispatches_same | Async handler uses same dispatcher |

---

## Edge Cases

### Zero-length buffers
- Every FSCTL handler with input validation must be tested with in_buf_len=0
- Every FSCTL handler with output must be tested with max_out_len=0
- Info handlers: buf_len=0 for GET, buf_len=0 for SET
- Create context handlers: ctx_len=0

### Truncated inputs
- FSCTL handlers receiving partial structures (1 byte less than minimum)
- Copychunk with chunk array that extends beyond in_buf_len
- Validate negotiate with DialectCount that would overflow buffer
- File level trim with num_ranges exceeding available buffer
- Tunnel operation header present but no payload

### Alignment
- Info level GET handlers: verify response structures are naturally aligned
- Network interface info: 152-byte entry alignment
- Hard link entries: 8-byte NextEntryOffset alignment
- File stat structures: verify no padding corruption

### Overlapping ranges
- Copychunk: overlapping source and destination ranges
- Set zero data: range overlapping with active locks
- Query allocated ranges: range starting mid-hole or mid-data
- File level trim: overlapping trim ranges

### Integer overflow
- Copy offsets: src_off + length overflows loff_t
- Duplicate extents: both offset+length overflow checks
- Retrieval pointers: StartingVcn near ULLONG_MAX
- Query file regions: FileOffset + Length overflow
- Set zero data: FileOffset near LLONG_MAX

### Maximum values
- Copychunk: max chunk count, max chunk size, max total size
- Network interface: many interfaces filling output buffer
- Query allocated ranges: fragmented file filling output buffer
- Hard link enumeration: many hard links
- File level trim: maximum number of trim ranges

### State-dependent behavior
- Object ID get when xattr does not exist vs. exists
- Object ID get with wrong-size xattr (!=16)
- Create-or-get when neither exists (creates random)
- Set compression on already-compressed file (noop)
- Set sparse on already-sparse file (noop)
- Validate negotiate after connection parameters change

---

## Fuzz Targets

The following entry points should be targeted by structure-aware fuzzers:

### FSCTL Fuzz Targets

| Target | Input Structure | Priority |
|--------|----------------|----------|
| fsctl_copychunk_handler | copychunk_ioctl_req + srv_copychunk[] | HIGH |
| fsctl_copychunk_write_handler | copychunk_ioctl_req + srv_copychunk[] | HIGH |
| fsctl_validate_negotiate_info_handler | validate_negotiate_info_req + Dialects[] | HIGH |
| fsctl_set_zero_data_handler | file_zero_data_information | HIGH |
| fsctl_query_allocated_ranges_handler | file_allocated_range_buffer | MEDIUM |
| fsctl_set_sparse_handler | file_sparse | MEDIUM |
| fsctl_duplicate_extents_handler | duplicate_extents_to_file | MEDIUM |
| fsctl_duplicate_extents_ex_handler | duplicate_extents_data_ex | MEDIUM |
| fsctl_get_retrieval_pointers_handler | fsctl_starting_vcn_input | MEDIUM |
| fsctl_query_file_regions_handler | file_region_input | MEDIUM |
| fsctl_mark_handle_handler | mark_handle_info | LOW |
| fsctl_pipe_transceive_handler | raw RPC payload | HIGH |
| ksmbd_fsctl_file_level_trim | file_level_trim + ranges[] | MEDIUM |
| ksmbd_fsctl_pipe_wait | fsctl_pipe_wait_req | LOW |
| fsctl_offload_read_handler | offload_read_input | MEDIUM |
| fsctl_offload_write_handler | offload_write_input | MEDIUM |

### RSVD Tunnel Fuzz Targets

| Target | Input Structure | Priority |
|--------|----------------|----------|
| rsvd_dispatch_tunnel_op | svhdx_tunnel_operation_header + payload | MEDIUM |
| rsvd_validate_tunnel_header | raw buffer | LOW |

### Info-Level Fuzz Targets

| Target | Input Structure | Priority |
|--------|----------------|----------|
| ksmbd_info_set_valid_data_length | smb2_file_valid_data_length_info | MEDIUM |
| ksmbd_info_set_fs_control | smb2_fs_control_info | LOW |
| ksmbd_info_set_fs_label | smb2_fs_label_info + variable VolumLabel | MEDIUM |
| ksmbd_info_set_case_sensitive | smb2_file_case_sensitive_info | LOW |
| ksmbd_info_get_file_name | work/fp context (state) | LOW |
| ksmbd_info_get_hard_link | work/fp context (state) | MEDIUM |

### Create Context Fuzz Targets

| Target | Input Structure | Priority |
|--------|----------------|----------|
| smb2_find_context_vals | raw create context chain | HIGH |
| mxac_on_request | variable-length context data | LOW |
| qfid_on_request | variable-length context data | LOW |

---

## Implementation Priority

### Phase 1 (Critical - security-relevant handlers)
1. ksmbd_test_fsctl_copychunk.c - Copy chunk validation (attack surface)
2. ksmbd_test_fsctl_validate_negotiate.c - Negotiate validation (downgrade prevention)
3. ksmbd_test_fsctl_sparse.c - Set zero data, allocated ranges (write path)
4. ksmbd_test_rsvd.c - RSVD tunnel dispatch (complex nested protocol)

### Phase 2 (High - functional handlers)
5. ksmbd_test_fsctl_object_id.c - Object ID lifecycle
6. ksmbd_test_fsctl_compression.c - Compression state
7. ksmbd_test_fsctl_duplicate.c - Extent duplication
8. ksmbd_test_fsctl_odx.c - Offload data transfer
9. ksmbd_test_info_file.c - All file info GET handlers
10. ksmbd_test_info_fs.c - All filesystem info handlers

### Phase 3 (Medium - completeness)
11. ksmbd_test_fsctl_pipe.c - Named pipe operations
12. ksmbd_test_fsctl_volume.c - Volume data handlers
13. ksmbd_test_fsctl_integrity.c - Integrity information
14. ksmbd_test_info_file_set.c - File info SET handlers
15. ksmbd_test_create_ctx.c enhancements
16. ksmbd_test_create_ctx_tags.c
17. ksmbd_test_info_quota.c

### Phase 4 (Low - stubs and infrastructure)
18. ksmbd_test_fsctl_misc.c - Misc handlers (mark, encryption, dealloc)
19. ksmbd_test_fsctl_dispatch.c enhancements
20. ksmbd_test_info_dispatch.c enhancements
21. ksmbd_test_info_security.c - Verify absence of security in dispatch

---

## Test Count Summary

| Category | Existing | New | Total |
|----------|----------|-----|-------|
| FSCTL dispatch infrastructure | 13 | 4 | 17 |
| FSCTL copychunk | 0 | 20 | 20 |
| FSCTL sparse | 0 | 22 | 22 |
| FSCTL integrity | 0 | 7 | 7 |
| FSCTL ODX | 0 | 13 | 13 |
| FSCTL duplicate | 0 | 12 | 12 |
| FSCTL object ID | 0 | 15 | 15 |
| FSCTL compression | 0 | 9 | 9 |
| FSCTL validate negotiate | 0 | 9 | 9 |
| FSCTL pipe | 0 | 11 | 11 |
| FSCTL volume | 0 | 12 | 12 |
| FSCTL misc | 0 | 15 | 15 |
| Info dispatch infrastructure | 12 | 3 | 15 |
| Info file GET | 0 | 43 | 43 |
| Info file SET | 0 | 11 | 11 |
| Info filesystem | 0 | 10 | 10 |
| Info security | 0 | 1 | 1 |
| Info quota | 0 | 3 | 3 |
| Create context infrastructure | 11 | 11 | 22 |
| Create context tags | 0 | 9 | 9 |
| RSVD | 0 | 31 | 31 |
| **TOTAL** | **36** | **261** | **297** |
