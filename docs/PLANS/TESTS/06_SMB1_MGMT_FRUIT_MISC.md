# Test Plan: SMB1, Management, Fruit, Hooks & Miscellaneous

## Current Coverage Summary

### Existing Test Files and Their Scope

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `ksmbd_test_smb1_parser.c` | 15 | AndX chain bounds (6), SMB_TRANS prevalidation (9) |
| `ksmbd_test_fruit.c` | 22 | AfpInfo stream detection (5), volume caps (4), AFP magic/version (4), signature (3), client name (3), version string (3) |
| `ksmbd_test_hooks.c` | 17 | Init (1), register (4), dispatch (3), priority (1), stop/drop/continue (3), unregister (2), isolation (2), FIFO (1) |
| `ksmbd_test_feature.c` | 11 | Compiled check (3), global enabled (3), three-tier (5) |
| `ksmbd_test_buffer.c` | 15 | Pool selection (3), entry/buf roundtrip (2), init counts (1), get/put (6), exhaustion (1), zero/null safety (2) |
| `ksmbd_test_ida.c` | 12 | Generic IDA (3), SMB1 TID (2), SMB2 TID (3), SMB2 UID (1), async msg (1), sequential (1), release/reuse (1) |
| `ksmbd_test_misc.c` | 19 | match_pattern (6), validate_filename (5), path conversion (2), strip_slash (1), get_nlink (3), time conversion (2) |
| `ksmbd_test_config.c` | 10 | Init/defaults (1), set/get (1), clamp above/below (2), invalid param (2), param name (1), boundary (1), IPC timeout (1), deadtime (1) |
| `ksmbd_test_smb_common.c` | 11 | Protocol lookup (6), min/max protocol (2), copy chunk defaults (3) |

**Total existing tests: 132 across 9 files**

---

## Gap Analysis

### Completely Untested Source Files

| Source File | Functions | Notes |
|-------------|-----------|-------|
| `src/core/ksmbd_debugfs.c` | `ksmbd_debugfs_init()`, `ksmbd_debugfs_exit()`, `ksmbd_debugfs_connections_show()`, `ksmbd_debugfs_stats_show()`, `ksmbd_conn_status_str()` | Hard to unit test (requires debugfs + live connections), but status string mapping and snapshot logic are testable |
| `src/mgmt/share_config.c` | `ksmbd_share_config_get()`, `ksmbd_share_config_del()`, `__ksmbd_share_config_put()`, `ksmbd_share_veto_filename()`, `share_config_request()`, `parse_veto_list()`, `ksmbd_path_has_dotdot_component()` | Veto filename, dotdot detection, and path validation are unit-testable |
| `src/mgmt/tree_connect.c` | `ksmbd_tree_conn_connect()`, `ksmbd_tree_connect_put()`, `ksmbd_tree_conn_disconnect()`, `ksmbd_tree_conn_lookup()`, `ksmbd_tree_conn_session_logoff()` | Requires session/IPC mocking; lifecycle and refcounting logic testable |
| `src/mgmt/ksmbd_witness.c` | `ksmbd_witness_resource_add()`, `ksmbd_witness_resource_del()`, `ksmbd_witness_resource_lookup()`, `ksmbd_witness_register()`, `ksmbd_witness_unregister()`, `ksmbd_witness_unregister_session()`, `ksmbd_witness_registration_count()`, `ksmbd_witness_notify_state_change()`, `ksmbd_witness_init()`, `ksmbd_witness_exit()` | Resource/registration management is mostly self-contained and testable |
| `src/protocol/common/netmisc.c` | `ntstatus_to_dos()` | Pure mapping table, trivially unit-testable |

### Completely Untested Functions (in partially tested files)

#### smb1pdu.c (40 non-static functions, only 0 tested directly -- test file tests replicated logic)

All SMB1 command handlers are completely untested at the unit level:

| Function | Description |
|----------|-------------|
| `set_smb_rsp_status()` | Set error status in SMB1 response header |
| `init_smb_rsp_hdr()` | Initialize SMB1 response header from request |
| `smb_allocate_rsp_buf()` | Allocate response buffer |
| `smb_check_user_session()` | Session validation |
| `smb_get_ksmbd_tcon()` | Tree connect lookup |
| `smb_session_disconnect()` | Logoff handler |
| `smb_tree_disconnect()` | Tree disconnect handler |
| `smb_tree_connect_andx()` | Tree connect AndX handler |
| `smb_rename()` | Rename handler |
| `smb_handle_negotiate()` | Negotiate handler |
| `smb_session_setup_andx()` | Session setup AndX handler |
| `smb_locking_andx()` | Lock handler |
| `smb_trans()` | TRANSACTION handler |
| `smb_nt_create_andx()` | NT CREATE AndX handler |
| `smb_close()` | Close handler |
| `smb_read_andx()` | Read AndX handler |
| `smb_write()` / `smb_write_andx()` | Write handlers |
| `smb_echo()` | Echo handler |
| `smb_flush()` | Flush handler |
| `smb_trans2()` | TRANSACTION2 handler |
| `smb_mkdir()` | Create directory |
| `smb_checkdir()` | Check directory |
| `smb_process_exit()` | Process exit |
| `smb_rmdir()` | Remove directory |
| `smb_unlink()` | Delete file |
| `smb_nt_cancel()` | NT cancel |
| `smb_nt_rename()` | NT rename |
| `smb_query_info()` | Query information |
| `smb_closedir()` | Close directory search |
| `smb_open_andx()` | Open AndX handler |
| `smb_setattr()` | Set attributes |
| `smb_query_information_disk()` | Disk info query |
| `smb1_is_sign_req()` | Signing requirement check |
| `smb_query_information2()` | Query information2 |
| `smb_set_information2()` | Set information2 |
| `smb1_check_sign_req()` | Check request signing |
| `smb1_set_sign_rsp()` | Set response signing |
| `smb_nt_transact()` | NT TRANSACT handler |
| `smb_nt_transact_secondary()` | NT TRANSACT secondary handler |

#### smb1misc.c (1 non-static function tested indirectly)

| Function | Status |
|----------|--------|
| `ksmbd_smb1_check_message()` | Untested directly (smb1_req_struct_size, smb1_calc_size, smb1_get_byte_count, smb1_get_data_len are all static helpers) |
| `smb_negotiate_request()` | Untested |

#### smb1ops.c (1 non-static function)

| Function | Status |
|----------|--------|
| `init_smb1_server()` | Untested |

#### smb2fruit.c (24+ non-static functions)

Only stream detection, volume caps, signature, client name, and version strings are tested. Missing:

| Function | Description |
|----------|-------------|
| `fruit_is_client_request()` | Detect AAPL create context in buffer |
| `fruit_parse_client_info()` | Parse fruit client info structure |
| `fruit_negotiate_capabilities()` | Negotiate AAPL capabilities |
| `fruit_supports_capability()` | Check single capability bit |
| `fruit_detect_client_version()` | Detect client version from data |
| `fruit_validate_create_context()` | Validate AAPL create context structure |
| `fruit_init_connection_state()` | Init per-connection fruit state |
| `fruit_cleanup_connection_state()` | Cleanup per-connection fruit state |
| `fruit_update_connection_state()` | Update connection state |
| `fruit_debug_client_info()` | Debug logging |
| `fruit_get_context_size()` | Get size for context name |
| `fruit_build_server_response()` | Build AAPL server response |
| `fruit_process_looker_info()` | Process looker info |
| `fruit_process_savebox_info()` | Process savebox info |
| `fruit_handle_savebox_bundle()` | Handle savebox bundle |
| `fruit_synthesize_afpinfo()` | Synthesize AFP_AfpInfo stream |
| `ksmbd_fruit_read_afpinfo()` | Read AFP_AfpInfo from file |
| `ksmbd_fruit_check_tm_quota()` | Time Machine quota check |
| `ksmbd_fruit_fill_readdir_attr()` | Fill readdir attributes |
| `fruit_init_module()` / `fruit_cleanup_module()` | Module lifecycle |
| `fruit_process_server_query()` | Process server query |
| `fruit_debug_capabilities()` | Debug capabilities |
| `smb2_read_dir_attr()` | Read directory attribute |
| `smb2_read_dir_attr_fill()` | Fill directory attribute |

#### ksmbd_hooks.c

Test file tests replicated logic. Missing tests against actual RCU/static-key behavior:

| Function | Status |
|----------|--------|
| `ksmbd_hooks_init()` | Untested (module lifecycle) |
| `ksmbd_hooks_exit()` | Untested (RCU teardown) |
| `ksmbd_register_hook()` | Tested via replica only |
| `ksmbd_unregister_hook()` | Tested via replica only |
| `__ksmbd_run_hooks()` | Tested via replica only |

#### misc.c

| Function | Status |
|----------|--------|
| `ksmbd_check_dotdot_name()` | Untested |
| `parse_stream_name()` | Untested |
| `convert_to_nt_pathname()` | Untested (requires VFS) |
| `convert_to_unix_name()` | Untested (requires share config) |
| `ksmbd_casefold_sharename()` | Untested |
| `ksmbd_extract_sharename()` | Untested |
| `ksmbd_convert_dir_info_name()` | Untested |
| `ksmbd_systime()` | Untested (trivial wrapper) |

#### smb_common.c

| Function | Status |
|----------|--------|
| `ksmbd_verify_smb_message()` | Untested |
| `ksmbd_smb_request()` | Untested |
| `ksmbd_init_smb_server()` | Untested |
| `ksmbd_negotiate_smb_dialect()` (static) | Untested |
| `ksmbd_lookup_dialect_by_name()` (static) | Untested |
| `ksmbd_lookup_dialect_by_id()` | Untested |
| `ksmbd_smb_negotiate_common()` | Untested |
| `ksmbd_smb_check_shared_mode()` | Untested |
| `ksmbd_populate_dot_dotdot_entries()` | Untested |
| `ksmbd_extract_shortname()` | Untested |
| `is_asterisk()` | Untested |
| `smb_map_generic_desired_access()` | Untested |
| `__ksmbd_override_fsids()` | Untested (requires creds) |
| `ksmbd_override_fsids()` | Untested |
| `ksmbd_revert_fsids()` | Untested |

### Insufficiently Tested Functions

| Test File | Function | What Is Missing |
|-----------|----------|-----------------|
| `ksmbd_test_smb1_parser.c` | andx chain | No test for exactly depth=32 (boundary); no multi-target chain (e.g., 3-hop); no concurrent command type matching |
| `ksmbd_test_smb1_parser.c` | smb_trans precheck | No test for SetupCount=0 (valid with zero setup bytes); no zero-length name |
| `ksmbd_test_fruit.c` | stream detection | No test for resource fork stream detection (`AFP_Resource`); no test for stream name with embedded NUL |
| `ksmbd_test_fruit.c` | volume caps | No test for per-share capability variation; no test for volume caps bitmask arithmetic overflow |
| `ksmbd_test_hooks.c` | hook dispatch | No test for NULL work pointer; no test for maximum hooks per point; no test for register-during-dispatch race |
| `ksmbd_test_feature.c` | three-tier check | No negative feature enum test; no test for all features enabled simultaneously |
| `ksmbd_test_buffer.c` | pool management | No concurrent get/put test; no test for pool after destroy/reinit cycle |
| `ksmbd_test_ida.c` | SMB2 UID | No test for actual 0xFFFE skip behavior (would need 65534 allocations) |
| `ksmbd_test_misc.c` | match_pattern | No test for DOS wildcards (`<`, `>`, `"`); no test for very long patterns |
| `ksmbd_test_misc.c` | validate_filename | No test for colon (`:`) character; no test for backslash (`\`) |
| `ksmbd_test_config.c` | config | No test for concurrent set/get; no test for KSMBD_CFG_COPY_CHUNK_* parameters; no test for KSMBD_CFG_SMB_ECHO_INTERVAL |
| `ksmbd_test_smb_common.c` | protocol lookup | No SMB1 protocol lookup test (NT1, SMB1 alias); no dialect-by-id test; no test for `is_asterisk()` |

---

## New Tests Required

### ksmbd_test_smb1_parser.c Enhancements

**Priority: HIGH**

#### 1. AndX Chain Additional Tests

```
test_andx_depth_exactly_32_succeeds
    - Chain of exactly 32 AndX hops (max allowed), target at end
    - Verify returns valid pointer

test_andx_multi_hop_finds_third_command
    - 3-hop chain: SESSION_SETUP -> TREE_CONNECT -> NT_CREATE
    - Verify each command found at correct offset

test_andx_no_more_command_terminates
    - Chain where first entry is SMB_NO_MORE_ANDX_COMMAND
    - Verify returns NULL for any target command

test_andx_minimum_packet_size
    - Smallest valid packet containing one AndX entry
    - Verify boundary behavior at minimum buffer size

test_andx_overlapping_entries_rejected
    - Two entries whose offsets overlap in memory
    - Verify returns NULL (non-forward progress)
```

#### 2. SMB_TRANS Precheck Additional Tests

```
test_smb_trans_precheck_zero_setup_count
    - SetupCount=0 with valid offsets
    - Verify returns 0 (valid)

test_smb_trans_precheck_zero_length_name
    - decoded_name_len=0
    - Verify returns 0 (str_len_uni = 2, minimum spacing)

test_smb_trans_precheck_max_setup_count
    - SetupCount at maximum fitting in buffer
    - Verify returns 0 if remaining space is sufficient

test_smb_trans_precheck_data_offset_equals_req_len
    - DataOffset == req_buf_len, DataCount == 0
    - Verify returns 0 (edge case)
```

#### 3. SMB1 Message Validation (smb1misc.c replicated logic)

```
test_smb1_req_struct_size_negotiate
    - WordCount=0 for SMB_COM_NEGOTIATE
    - Verify returns 0

test_smb1_req_struct_size_session_setup_12
    - WordCount=12 for SMB_COM_SESSION_SETUP_ANDX
    - Verify returns 12

test_smb1_req_struct_size_session_setup_13
    - WordCount=13 for SMB_COM_SESSION_SETUP_ANDX
    - Verify returns 13

test_smb1_req_struct_size_invalid_negotiate
    - WordCount=1 for SMB_COM_NEGOTIATE
    - Verify returns -EINVAL

test_smb1_req_struct_size_unsupported_command
    - Unknown command byte
    - Verify returns -EOPNOTSUPP

test_smb1_byte_count_close_must_be_zero
    - SMB_COM_CLOSE with ByteCount != 0
    - Verify returns -EINVAL

test_smb1_byte_count_negotiate_min
    - SMB_COM_NEGOTIATE with ByteCount < 2
    - Verify returns -EINVAL

test_smb1_calc_size_valid_negotiate
    - Fully formed NEGOTIATE request
    - Verify calculated size matches expected

test_smb1_calc_size_invalid_byte_count
    - Malformed byte count field
    - Verify returns (unsigned int)-1
```

### ksmbd_test_smb1_session.c (NEW)

**Priority: HIGH** -- Would require mocking ksmbd_work/conn/sess structures

```
test_smb1_negotiate_dialect_selection
    - Build dialect list with NT LM 0.12 and SMB 2.???
    - Verify correct dialect index selected

test_smb1_negotiate_dialect_nt_lanman
    - Dialect list containing "\2NT LANMAN 1.0" alias
    - Verify matches as SMB1

test_smb1_negotiate_upgrade_to_smb2
    - Dialect list with SMB 2.002 and SMB 2.???
    - Verify conn->dialect set to SMB2X_PROT_ID

test_smb1_negotiate_empty_dialect_list
    - ByteCount=0 or no valid dialects
    - Verify returns BAD_PROT_ID

test_smb1_negotiate_second_negotiate_rejected
    - Already negotiated connection receives second NEGOTIATE
    - Verify STATUS_INVALID_PARAMETER / connection set to exiting

test_init_smb1_server_sets_ops
    - Verify conn->ops, conn->cmds, conn->max_cmds set correctly
    - Verify conn->smb1_conn = true

test_init_smb1_server_vals_allocated
    - Verify conn->vals != NULL after init
    - Verify conn->vals->capabilities includes SMB1_SERVER_CAPS
```

### ksmbd_test_smb1_file.c (NEW)

**Priority: MEDIUM** -- Heavy mocking required, integration-style tests

```
test_smb1_create_response_header
    - Verify NT_CREATE_ANDX response has correct WordCount and fid

test_smb1_close_invalid_fid
    - Close with non-existent FID
    - Verify returns STATUS_INVALID_HANDLE

test_smb1_read_beyond_eof
    - Read with offset past end of file
    - Verify returns 0 bytes read

test_smb1_write_at_offset
    - Write data at specified offset
    - Verify DataLengthLow/DataOffset fields parsed correctly

test_smb1_rename_cross_share_rejected
    - Rename across different shares
    - Verify fails appropriately

test_smb1_lock_basic
    - Acquire and release lock via LOCKING_ANDX
    - Verify lock fields parsed correctly

test_smb1_lock_conflicting
    - Two conflicting locks on same range
    - Verify STATUS_LOCK_NOT_GRANTED

test_smb1_echo_response
    - SMB_COM_ECHO request
    - Verify response echoes data and SequenceNumber
```

### ksmbd_test_smb1_trans.c (NEW)

**Priority: HIGH** -- Tests for TRANS2 and NT_TRANSACT subcommand dispatch

```
test_smb1_trans2_query_file_info
    - TRANS2_QUERY_FILE_INFORMATION with valid FID
    - Verify SubCommand dispatch

test_smb1_trans2_set_file_info
    - TRANS2_SET_FILE_INFORMATION with valid FID
    - Verify SubCommand dispatch

test_smb1_trans2_find_first
    - TRANS2_FIND_FIRST2 with search pattern
    - Verify SubCommand dispatch

test_smb1_trans2_find_next
    - TRANS2_FIND_NEXT2 continuation
    - Verify SubCommand dispatch

test_smb1_trans2_query_fs_info
    - TRANS2_QUERY_FS_INFORMATION
    - Verify info level parsing

test_smb1_nt_transact_ioctl
    - NT_TRANSACT_IOCTL subcommand
    - Verify function code dispatch

test_smb1_nt_transact_notify
    - NT_TRANSACT_NOTIFY_CHANGE subcommand
    - Verify completion filter parsing

test_smb1_nt_transact_rename
    - NT_TRANSACT_RENAME subcommand
    - Verify filename parsing

test_smb1_nt_transact_quota
    - NT_TRANSACT_QUERY_QUOTA / NT_TRANSACT_SET_QUOTA
    - Verify quota structure parsing

test_smb1_nt_transact_create
    - NT_TRANSACT_CREATE subcommand
    - Verify security descriptor parsing

test_smb1_nt_transact_secondary_continuation
    - NT_TRANSACT_SECONDARY with multi-part data
    - Verify parameter/data reassembly offsets

test_smb1_trans_invalid_subcommand
    - TRANSACTION with unknown subcommand
    - Verify appropriate error return

test_smb1_trans2_parameter_overflow
    - TRANS2 with ParameterOffset+ParameterCount > buf_len
    - Verify returns -EINVAL
```

### ksmbd_test_fruit.c Enhancements

**Priority: MEDIUM**

```
test_fruit_is_resource_stream
    - Detect "AFP_Resource" stream name
    - Verify correct detection

test_fruit_is_client_request_valid_aapl
    - Buffer containing valid AAPL create context
    - Verify returns true

test_fruit_is_client_request_invalid
    - Buffer without AAPL context
    - Verify returns false

test_fruit_is_client_request_null_buffer
    - NULL buffer input
    - Verify returns false

test_fruit_is_client_request_short_buffer
    - Buffer shorter than minimum AAPL context
    - Verify returns false

test_fruit_parse_client_info_valid
    - Valid fruit client info structure
    - Verify version and capabilities extracted correctly

test_fruit_parse_client_info_short_data
    - Data shorter than required
    - Verify returns -EINVAL

test_fruit_supports_capability_single_bit
    - Check each capability bit individually
    - Verify returns correct boolean

test_fruit_supports_capability_combined
    - Multiple capability bits set
    - Verify supports check for each

test_fruit_detect_client_version_v1
    - Data encoding version 1.0
    - Verify detected correctly

test_fruit_detect_client_version_v2
    - Data encoding version 2.0
    - Verify detected correctly

test_fruit_detect_client_version_invalid
    - Garbage data
    - Verify returns error or unknown

test_fruit_validate_create_context_valid
    - Properly formed create context
    - Verify returns 0

test_fruit_validate_create_context_short
    - Truncated context
    - Verify returns -EINVAL

test_fruit_validate_create_context_bad_name
    - Context with wrong name length or wrong name
    - Verify returns -EINVAL

test_fruit_init_cleanup_connection_state
    - Init state, verify defaults, cleanup
    - Verify no leaks

test_fruit_get_context_size_known
    - "AAPL" context
    - Verify expected size

test_fruit_get_context_size_unknown
    - Unknown context name
    - Verify returns 0 or error

test_fruit_build_server_response_basic
    - Build response with standard capabilities
    - Verify response data and length

test_fruit_afpinfo_synthesis
    - Synthesize AFP_AfpInfo for a dentry
    - Verify magic, version, size = 60 bytes

test_fruit_time_machine_quota_under_limit
    - Share with TM quota, usage under limit
    - Verify returns 0

test_fruit_time_machine_quota_over_limit
    - Share with TM quota, usage over limit
    - Verify returns -EDQUOT or appropriate error

test_fruit_time_machine_quota_no_limit
    - Share without TM quota configured
    - Verify returns 0 (no limit enforced)
```

### ksmbd_test_hooks.c Enhancements

**Priority: LOW**

```
test_hook_register_all_points
    - Register one hook at every hook point
    - Verify each chain has exactly one handler

test_hook_unregister_middle_of_chain
    - Register 3 hooks, unregister the middle one
    - Verify remaining two still called in order

test_hook_dispatch_null_work
    - Dispatch with work=NULL
    - Verify handlers still called (work is passed as-is)

test_hook_maximum_hooks_per_point
    - Register 100+ hooks on a single point
    - Verify all called in priority order

test_hook_register_duplicate_priority
    - Register two hooks with identical priority on same point
    - Verify FIFO order maintained (already partially tested)

test_hook_register_negative_priority
    - Register hook with priority=0 (lowest possible)
    - Verify called first

test_hook_register_max_int_priority
    - Register hook with priority=INT_MAX
    - Verify called last

test_hook_drop_vs_stop_semantics
    - Chain with DROP handler then STOP handler
    - Verify only DROP handler called, STOP never reached

test_hook_register_after_dispatch
    - Dispatch, then register new hook, dispatch again
    - Verify new hook called in second dispatch
```

### ksmbd_test_share_config.c (NEW)

**Priority: HIGH** -- Pure logic from share_config.c

```
test_share_path_has_dotdot_simple
    - Path "foo/../bar"
    - Verify returns true

test_share_path_has_dotdot_at_start
    - Path "../secret"
    - Verify returns true

test_share_path_has_dotdot_at_end
    - Path "/share/.."
    - Verify returns true

test_share_path_no_dotdot
    - Path "/share/folder/file"
    - Verify returns false

test_share_path_dots_in_name
    - Path "/share/..file" or "/share/file.."
    - Verify returns false (not traversal)

test_share_path_multiple_slashes
    - Path "/share///../../etc"
    - Verify returns true

test_share_path_empty
    - Empty path ""
    - Verify returns false

test_share_path_single_dot
    - Path "/share/./file"
    - Verify returns false

test_share_veto_filename_match
    - Veto list with "*.tmp", check "test.tmp"
    - Verify returns true

test_share_veto_filename_no_match
    - Veto list with "*.tmp", check "test.txt"
    - Verify returns false

test_share_veto_filename_empty_list
    - Empty veto list
    - Verify returns false for any filename

test_share_veto_filename_multiple_patterns
    - Veto list with "*.tmp", "~$*", "Thumbs.db"
    - Verify all patterns matched

test_parse_veto_list_single_entry
    - NUL-terminated single entry
    - Verify one pattern added

test_parse_veto_list_multiple_entries
    - Multiple NUL-separated entries
    - Verify correct number of patterns added

test_parse_veto_list_empty
    - Zero-length veto list
    - Verify no patterns added

test_parse_veto_list_zero_length_entry
    - Veto list with embedded empty strings
    - Verify empty strings skipped

test_share_name_hash_deterministic
    - Same name produces same hash
    - Different names produce different hashes (probabilistic)

test_share_ipc_auto_detection
    - Share name "IPC$" without PIPE flag
    - Verify PIPE flag auto-set

test_share_ipc_case_insensitive
    - Share name "ipc$" (lowercase)
    - Verify PIPE flag auto-set

test_share_path_must_be_absolute
    - Share path "relative/path"
    - Verify rejected

test_share_path_trailing_slash_stripped
    - Share path "/share/path/"
    - Verify trailing slash removed
```

### ksmbd_test_tree_connect.c (NEW)

**Priority: MEDIUM** -- Requires session/IPC mocking; focus on refcounting logic

```
test_tree_connect_put_frees_on_last_ref
    - Create tree_connect with refcount=1
    - put() should trigger free

test_tree_connect_put_decrements_ref
    - Create tree_connect with refcount=2
    - put() should decrement to 1, not free

test_tree_conn_lookup_returns_null_for_nonexistent
    - Lookup ID that does not exist in xarray
    - Verify returns NULL

test_tree_conn_lookup_rejects_disconnected
    - Tree connect with t_state=TREE_DISCONNECTED
    - Verify lookup returns NULL

test_tree_conn_session_logoff_null_session
    - Call with NULL session
    - Verify returns -EINVAL

test_tree_conn_disconnect_removes_from_xarray
    - Disconnect a tree connect
    - Verify subsequent lookup returns NULL

test_tree_conn_session_logoff_marks_disconnected
    - Multiple tree connects, logoff
    - Verify all marked TREE_DISCONNECTED
```

### ksmbd_test_witness.c (NEW)

**Priority: HIGH** -- Witness protocol state management is self-contained

```
test_witness_resource_add_basic
    - Add resource with valid name and type
    - Verify returns non-ERR pointer

test_witness_resource_add_duplicate
    - Add same resource name twice
    - Verify returns -EEXIST

test_witness_resource_add_null_name
    - NULL name
    - Verify returns -EINVAL

test_witness_resource_add_empty_name
    - Empty string name
    - Verify returns -EINVAL

test_witness_resource_del_existing
    - Add then delete resource
    - Verify lookup returns false after delete

test_witness_resource_del_nonexistent
    - Delete resource that was never added
    - Verify no crash (silent return)

test_witness_resource_lookup_existing
    - Add resource, lookup
    - Verify returns true

test_witness_resource_lookup_nonexistent
    - Lookup name that does not exist
    - Verify returns false

test_witness_register_basic
    - Register client for a resource
    - Verify reg_id assigned and > 0

test_witness_register_auto_creates_resource
    - Register for non-existent resource
    - Verify resource created automatically

test_witness_register_null_client_name
    - NULL client_name
    - Verify returns -EINVAL

test_witness_register_null_resource_name
    - NULL resource_name
    - Verify returns -EINVAL

test_witness_register_max_global_limit
    - Register KSMBD_MAX_WITNESS_REGISTRATIONS + 1
    - Verify returns -ENOSPC at limit

test_witness_register_max_per_session_limit
    - Register KSMBD_MAX_WITNESS_REGS_PER_SESSION + 1 for same session
    - Verify returns -ENOSPC at limit

test_witness_unregister_existing
    - Register then unregister
    - Verify returns 0

test_witness_unregister_nonexistent
    - Unregister ID that was never registered
    - Verify returns -ENOENT

test_witness_unregister_double
    - Unregister same ID twice
    - Verify second call returns -ENOENT

test_witness_unregister_session_basic
    - Register multiple for one session, unregister by session
    - Verify all removed

test_witness_unregister_session_zero_id
    - session_id = 0
    - Verify early return (no-op)

test_witness_unregister_session_no_match
    - Unregister session with no registrations
    - Verify no crash

test_witness_registration_count_empty
    - No registrations
    - Verify returns 0

test_witness_registration_count_after_register
    - Register N clients
    - Verify count returns N

test_witness_registration_count_after_unregister
    - Register 3, unregister 1
    - Verify count returns 2

test_witness_notify_state_change_nonexistent_resource
    - Notify for resource that does not exist
    - Verify returns -ENOENT

test_witness_notify_state_change_no_subscribers
    - Resource exists but no subscribers
    - Verify returns 0 (no notifications sent)

test_witness_resource_del_detaches_subscribers
    - Register subscriber, then delete resource
    - Verify subscriber list detached cleanly
```

### ksmbd_test_netmisc.c (NEW)

**Priority: MEDIUM** -- Pure table lookup, trivially testable

```
test_ntstatus_to_dos_success
    - NT_STATUS_OK (0)
    - Verify eclass=0, ecode=0

test_ntstatus_to_dos_access_denied
    - NT_STATUS_ACCESS_DENIED
    - Verify ERRDOS, ERRnoaccess

test_ntstatus_to_dos_no_such_file
    - NT_STATUS_NO_SUCH_FILE
    - Verify ERRDOS, ERRbadfile

test_ntstatus_to_dos_sharing_violation
    - NT_STATUS_SHARING_VIOLATION
    - Verify ERRDOS, ERRbadshare

test_ntstatus_to_dos_lock_conflict
    - NT_STATUS_FILE_LOCK_CONFLICT
    - Verify ERRDOS, ERRlock

test_ntstatus_to_dos_invalid_parameter
    - NT_STATUS_INVALID_PARAMETER
    - Verify ERRDOS, 87

test_ntstatus_to_dos_invalid_handle
    - NT_STATUS_INVALID_HANDLE
    - Verify ERRDOS, ERRbadfid

test_ntstatus_to_dos_object_name_collision
    - NT_STATUS_OBJECT_NAME_COLLISION
    - Verify ERRDOS, ERRalreadyexists

test_ntstatus_to_dos_disk_full
    - NT_STATUS_DISK_FULL
    - Verify ERRDOS, 112

test_ntstatus_to_dos_directory_not_empty
    - NT_STATUS_DIRECTORY_NOT_EMPTY
    - Verify ERRDOS, 145

test_ntstatus_to_dos_unknown_status
    - Random unmapped status code
    - Verify fallback: ERRHRD, ERRgeneral

test_ntstatus_to_dos_file_closed
    - NT_STATUS_FILE_CLOSED
    - Verify ERRDOS, ERRbadfid

test_ntstatus_to_dos_password_expired
    - NT_STATUS_PASSWORD_EXPIRED
    - Verify ERRSRV, ERRpasswordExpired

test_ntstatus_to_dos_delete_pending
    - NT_STATUS_DELETE_PENDING
    - Verify ERRDOS, ERRbadfile

test_ntstatus_to_dos_too_many_opened_files
    - NT_STATUS_TOO_MANY_OPENED_FILES
    - Verify ERRDOS, ERRnofids
```

### ksmbd_test_smb_common.c Enhancements

**Priority: HIGH**

```
test_lookup_protocol_idx_nt1
    - "NT1" lookup
    - Verify returns SMB1_PROT

test_lookup_protocol_idx_smb1_alias
    - "SMB1" alias lookup
    - Verify returns SMB1_PROT

test_lookup_dialect_by_id_smb311
    - Dialect array containing 0x0311
    - Verify returns 0x0311

test_lookup_dialect_by_id_smb2_02
    - Dialect array containing 0x0202
    - Verify returns 0x0202

test_lookup_dialect_by_id_no_match
    - Dialect array containing only unsupported values
    - Verify returns BAD_PROT_ID

test_lookup_dialect_by_id_prefers_highest
    - Array with 0x0202, 0x0210, 0x0311
    - Verify returns highest supported

test_is_asterisk_true
    - Pointer to "*"
    - Verify returns true

test_is_asterisk_false
    - Pointer to "hello"
    - Verify returns false

test_is_asterisk_null
    - NULL pointer
    - Verify returns false

test_is_asterisk_empty
    - Pointer to ""
    - Verify returns false

test_smb_map_generic_read
    - FILE_GENERIC_READ_LE set
    - Verify GENERIC_READ_FLAGS set, original flag cleared

test_smb_map_generic_write
    - FILE_GENERIC_WRITE_LE set
    - Verify GENERIC_WRITE_FLAGS set, original flag cleared

test_smb_map_generic_execute
    - FILE_GENERIC_EXECUTE_LE set
    - Verify GENERIC_EXECUTE_FLAGS set, original flag cleared

test_smb_map_generic_all
    - FILE_GENERIC_ALL_LE set
    - Verify GENERIC_ALL_FLAGS set, original flag cleared

test_smb_map_generic_no_generic
    - No generic flags set
    - Verify daccess unchanged

test_smb_map_generic_combined
    - Multiple generic flags set
    - Verify all expanded correctly

test_next_dialect_valid
    - Valid packed dialect list
    - Verify each dialect returned in sequence

test_next_dialect_empty_buffer
    - bcount=0
    - Verify returns NULL

test_next_dialect_unterminated
    - String without NUL terminator
    - Verify returns NULL
```

### ksmbd_test_misc.c Enhancements

**Priority: HIGH**

```
test_check_dotdot_name_at_start
    - "../secret"
    - Verify returns true

test_check_dotdot_name_in_middle
    - "foo/../bar"
    - Verify returns true

test_check_dotdot_name_at_end
    - "foo/bar/.."
    - Verify returns true

test_check_dotdot_name_no_dotdot
    - "foo/bar/baz"
    - Verify returns false

test_check_dotdot_name_dots_in_filename
    - "foo/..bar/baz"
    - Verify returns false (not traversal)

test_check_dotdot_name_single_dot
    - "foo/./bar"
    - Verify returns false

test_check_dotdot_name_empty
    - ""
    - Verify returns false

test_parse_stream_name_data_stream
    - "file.txt:stream1"
    - Verify stream_name="stream1", s_type=DATA_STREAM

test_parse_stream_name_explicit_data
    - "file.txt:stream1:$DATA"
    - Verify stream_name="stream1", s_type=DATA_STREAM

test_parse_stream_name_dir_stream
    - "file.txt:stream1:$INDEX_ALLOCATION"
    - Verify stream_name="stream1", s_type=DIR_STREAM

test_parse_stream_name_default_data
    - "file.txt::$DATA"
    - Verify returns -ENOENT (default stream = file itself)

test_parse_stream_name_no_stream
    - "file.txt"
    - Verify returns -ENOENT, stream_name=NULL

test_parse_stream_name_invalid_type
    - "file.txt:stream1:$INVALID"
    - Verify returns -ENOENT

test_parse_stream_name_invalid_chars
    - "file.txt:str/eam"
    - Verify returns -ENOENT

test_casefold_sharename_ascii
    - "MyShare"
    - Verify returns "myshare"

test_casefold_sharename_already_lower
    - "myshare"
    - Verify returns "myshare"

test_casefold_sharename_empty
    - ""
    - Verify returns ""

test_extract_sharename_with_backslash
    - "\\server\myshare"
    - Verify returns "myshare" (casefolded)

test_extract_sharename_no_backslash
    - "myshare"
    - Verify returns "myshare"

test_match_pattern_dos_star
    - Pattern "<.txt" matches "foo.txt" but not "foo.bar.txt"
    - Verify DOS_STAR semantics

test_match_pattern_dos_qm
    - Pattern "file>.txt" matches "file1.txt"
    - Verify DOS_QM semantics

test_match_pattern_dos_dot
    - Pattern '*"' matches "foo" (no extension)
    - Verify DOS_DOT semantics

test_match_pattern_very_long_string
    - 4096-character string with "*" wildcard
    - Verify completes without stack overflow

test_validate_filename_colon
    - Filename containing ":"
    - Verify passes (colon is allowed in filenames, only banned in stream names)

test_validate_filename_backslash
    - Filename containing "\"
    - Verify behavior

test_strip_last_slash_empty_string
    - Empty string ""
    - Verify no crash, remains ""

test_time_conversion_negative
    - Pre-epoch time (negative tv_sec)
    - Verify roundtrip correctness

test_time_conversion_nanoseconds
    - Time with non-zero nanoseconds
    - Verify roundtrip preserves ns (to 100ns granularity)

test_systime_positive
    - Verify ksmbd_systime() returns positive value
    - (Wrapper test, just ensure no crash)
```

### ksmbd_test_debugfs.c (NEW)

**Priority: LOW** -- Debugfs requires live kernel infrastructure

```
test_conn_status_str_new
    - KSMBD_SESS_NEW
    - Verify returns "new"

test_conn_status_str_good
    - KSMBD_SESS_GOOD
    - Verify returns "good"

test_conn_status_str_exiting
    - KSMBD_SESS_EXITING
    - Verify returns "exiting"

test_conn_status_str_reconnect
    - KSMBD_SESS_NEED_RECONNECT
    - Verify returns "reconnect"

test_conn_status_str_negotiate
    - KSMBD_SESS_NEED_NEGOTIATE
    - Verify returns "negotiate"

test_conn_status_str_setup
    - KSMBD_SESS_NEED_SETUP
    - Verify returns "setup"

test_conn_status_str_releasing
    - KSMBD_SESS_RELEASING
    - Verify returns "releasing"

test_conn_status_str_unknown
    - Invalid status value (e.g., 0xFF)
    - Verify returns "unknown"
```

### ksmbd_test_config.c Enhancements

**Priority: MEDIUM**

```
test_config_copy_chunk_max_count
    - Set and get KSMBD_CFG_COPY_CHUNK_MAX_COUNT
    - Verify default 256, range [1, 65535]

test_config_copy_chunk_max_size
    - Set and get KSMBD_CFG_COPY_CHUNK_MAX_SIZE
    - Verify default 1048576, range [4096, 16777216]

test_config_copy_chunk_total_size
    - Set and get KSMBD_CFG_COPY_CHUNK_TOTAL_SIZE
    - Verify default 16777216, range [4096, 268435456]

test_config_smb_echo_interval
    - Set and get KSMBD_CFG_SMB_ECHO_INTERVAL
    - Verify default 0, range [0, 3600]

test_config_max_connections_per_ip
    - Set and get KSMBD_CFG_MAX_CONNECTIONS_PER_IP
    - Verify default 64, range [0, 65535]

test_config_all_params_enumerated
    - Iterate all params from 0 to __KSMBD_CFG_MAX-1
    - Verify each has a non-NULL name
```

---

## Edge Cases

### SMB1 Buffer Overflow / Underflow

| Test ID | Description |
|---------|-------------|
| SMB1-EDGE-01 | AndX chain with offset pointing to last byte of buffer (off-by-one) |
| SMB1-EDGE-02 | SMB_COM_TRANS with ParameterOffset=0 and ParameterCount=0 |
| SMB1-EDGE-03 | SMB_COM_TRANS with DataOffset at exact end of buffer, DataCount=0 |
| SMB1-EDGE-04 | Session setup with WordCount=12 vs 13 (NTLMSSP vs extended security) |
| SMB1-EDGE-05 | NT_CREATE_ANDX with NameLength=0 (root open) |
| SMB1-EDGE-06 | WRITE with DataLength=0 (zero-length write) |
| SMB1-EDGE-07 | LOCKING_ANDX with NumberOfLocks=0 |
| SMB1-EDGE-08 | NEGOTIATE with only unsupported dialect strings |

### AndX Infinite Loops

| Test ID | Description |
|---------|-------------|
| ANDX-LOOP-01 | Self-referencing offset (A -> A) |
| ANDX-LOOP-02 | Two-entry cycle (A -> B -> A) |
| ANDX-LOOP-03 | Depth=33 (one over limit) with valid forward progress |
| ANDX-LOOP-04 | Backwards offset (forward byte in LE, but after endian swap points backward) |

### Share Name Injection

| Test ID | Description |
|---------|-------------|
| SHARE-INJ-01 | Share name containing NUL byte in middle |
| SHARE-INJ-02 | Share name containing "../" traversal |
| SHARE-INJ-03 | Share name at KSMBD_REQ_MAX_SHARE_NAME boundary |
| SHARE-INJ-04 | Share path containing symlinks (conceptual, not unit-testable) |
| SHARE-INJ-05 | Share name with Unicode homoglyph attack (case folding bypass) |

### Witness Race Conditions

| Test ID | Description |
|---------|-------------|
| WITNESS-RACE-01 | Concurrent register + resource_del for same resource |
| WITNESS-RACE-02 | Concurrent unregister + notify for same reg_id |
| WITNESS-RACE-03 | Concurrent register exceeding global limit |
| WITNESS-RACE-04 | unregister_session during notify_state_change |

### Buffer Pool Edge Cases

| Test ID | Description |
|---------|-------------|
| BUF-EDGE-01 | Get/put with size=1 (minimum) |
| BUF-EDGE-02 | Get with size=SMALL_SIZE (exact boundary) |
| BUF-EDGE-03 | Get with size=SMALL_SIZE+1 (just over boundary) |
| BUF-EDGE-04 | Get with size=LARGE_SIZE (exact boundary) |
| BUF-EDGE-05 | Get with size=LARGE_SIZE+1 (fallback) |
| BUF-EDGE-06 | Exhaust both pools, then get oversized buffer |
| BUF-EDGE-07 | Put buffer back to full pool (should kvfree, not add to list) |

### Config Edge Cases

| Test ID | Description |
|---------|-------------|
| CFG-EDGE-01 | Set value to 0 for param with min_val=0 (allowed) |
| CFG-EDGE-02 | Set value to UINT32_MAX for any param (clamped) |
| CFG-EDGE-03 | Set deadtime to 86400 (exact max) |
| CFG-EDGE-04 | Set max_connections to 0 (allowed, means unlimited) |

---

## Fuzz Targets

### SMB1 PDU Fuzz

| Target | Input | Invariant |
|--------|-------|-----------|
| `smb1_req_struct_size()` | Random Command byte + random WordCount | Must return -EINVAL or valid WC, never crash |
| `smb1_get_byte_count()` | Random header + random buffer | Must return -EINVAL or valid BC, never OOB read |
| `smb1_calc_size()` | Random full SMB1 header | Must return valid size or (unsigned int)-1 |
| `andx_request_buffer()` | Random offsets, commands, packet lengths (128 iterations) | Must return NULL or valid pointer within buffer |
| `smb_trans_precheck()` | Random ParameterOffset, DataOffset, counts (160 iterations) | Must return -EINVAL or 0, never access out-of-bounds |
| `ksmbd_smb1_check_message()` | Random 512-byte buffers with valid SMB1 magic | Must return 0 or 1, never crash |

### Share Config Fuzz

| Target | Input | Invariant |
|--------|-------|-----------|
| `ksmbd_path_has_dotdot_component()` | Random paths with embedded ".." | Must return true/false, never crash |
| `parse_veto_list()` | Random NUL-separated strings, varying lengths | Must return 0 or -ENOMEM, never leak |
| `ksmbd_share_veto_filename()` | Random filenames against random veto patterns | Must return true/false, never crash |

### Witness Message Fuzz

| Target | Input | Invariant |
|--------|-------|-----------|
| `ksmbd_witness_register()` | Random client_name, resource_name, session_id | Must return 0 or valid error, never leak memory |
| `ksmbd_witness_unregister()` | Random reg_id values | Must return 0 or -ENOENT, never double-free |
| `ksmbd_witness_resource_add()` | Random names of varying lengths | Must return valid pointer or ERR_PTR, never crash |

### Misc Function Fuzz

| Target | Input | Invariant |
|--------|-------|-----------|
| `match_pattern()` | Random strings + random patterns with wildcards | Must return true/false, never infinite loop |
| `ksmbd_validate_filename()` | Random byte sequences | Must return 0 or -ENOENT, never crash |
| `ntstatus_to_dos()` | Random __le32 status values | Must always set eclass+ecode, never crash |
| `ksmbd_NTtimeToUnix()` | Random __le64 values including 0, MAX, negative-mapped | Must return valid timespec64 |
| `parse_stream_name()` | Random filenames with embedded colons | Must return valid results or -ENOENT |

---

## Implementation Priority

1. **P0 (Critical)**: `ksmbd_test_witness.c` (NEW), `ksmbd_test_netmisc.c` (NEW), `ksmbd_test_misc.c` enhancements (dotdot, stream parsing)
2. **P1 (High)**: `ksmbd_test_smb1_parser.c` enhancements, `ksmbd_test_share_config.c` (NEW), `ksmbd_test_smb_common.c` enhancements
3. **P2 (Medium)**: `ksmbd_test_fruit.c` enhancements, `ksmbd_test_tree_connect.c` (NEW), `ksmbd_test_config.c` enhancements
4. **P3 (Low)**: `ksmbd_test_debugfs.c` (NEW), `ksmbd_test_hooks.c` enhancements, `ksmbd_test_smb1_session.c` (NEW), `ksmbd_test_smb1_file.c` (NEW), `ksmbd_test_smb1_trans.c` (NEW)

## Estimated Test Count

| Category | Existing | New/Enhanced | Total |
|----------|----------|-------------|-------|
| SMB1 Parser | 15 | 22 | 37 |
| SMB1 Session (NEW) | 0 | 7 | 7 |
| SMB1 File (NEW) | 0 | 8 | 8 |
| SMB1 Trans (NEW) | 0 | 13 | 13 |
| Fruit | 22 | 23 | 45 |
| Hooks | 17 | 9 | 26 |
| Feature | 11 | 0 | 11 |
| Buffer | 15 | 0 | 15 |
| IDA | 12 | 0 | 12 |
| Misc | 19 | 24 | 43 |
| Config | 10 | 6 | 16 |
| SMB Common | 11 | 19 | 30 |
| Share Config (NEW) | 0 | 22 | 22 |
| Tree Connect (NEW) | 0 | 7 | 7 |
| Witness (NEW) | 0 | 26 | 26 |
| Netmisc (NEW) | 0 | 15 | 15 |
| Debugfs (NEW) | 0 | 8 | 8 |
| **TOTAL** | **132** | **209** | **341** |
