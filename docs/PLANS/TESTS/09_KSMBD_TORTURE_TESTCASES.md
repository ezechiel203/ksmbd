# ksmbd-torture: Complete Test Case Catalog

**Version**: 1.0
**Date**: 2026-03-02
**Source**: 501 edge cases from ksmbd source analysis + smbtorture gap coverage + ksmbd-specific features

This document enumerates every individual test case for the ksmbd-torture test suite.
Each test has a unique ID, name, one-line description, expected result, and priority
(P0 = must-pass for release, P1 = important, P2 = nice-to-have / regression guard).

Total: **543 named test cases + 22 benchmark definitions**

---

## T01: NEGOTIATE (20 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T01-001 | negotiate_smb2_02 | Negotiate SMB 2.0.2 only | Server selects 0x0202, no negotiate contexts | P1 |
| T01-002 | negotiate_smb2_10 | Negotiate SMB 2.1 only | Server selects 0x0210, no negotiate contexts | P1 |
| T01-003 | negotiate_smb3_00 | Negotiate SMB 3.0 only | Server selects 0x0300, encryption capable | P1 |
| T01-004 | negotiate_smb3_02 | Negotiate SMB 3.0.2 only | Server selects 0x0302 | P1 |
| T01-005 | negotiate_smb3_11 | Negotiate SMB 3.1.1 only | Server selects 0x0311 with PREAUTH + ENCRYPT contexts | P0 |
| T01-006 | negotiate_multi_dialect | Offer all dialects 0x0202-0x0311 | Server selects highest (0x0311) | P0 |
| T01-007 | negotiate_smb1_upgrade | Send SMB1 NT1 negotiate then verify upgrade to SMB2 | Server responds with wildcard dialect 0x02FF, connection upgrades | P1 |
| T01-008 | negotiate_second_reject | Send two NEGOTIATE requests on same connection | Second NEGOTIATE returns error and connection is terminated (ksmbd_conn_set_exiting) | P0 |
| T01-009 | negotiate_zero_dialects | DialectCount=0 in NEGOTIATE request | STATUS_INVALID_PARAMETER | P0 |
| T01-010 | negotiate_dup_preauth_ctx | Duplicate PREAUTH_INTEGRITY_CAPABILITIES context | STATUS_INVALID_PARAMETER | P0 |
| T01-011 | negotiate_dup_encrypt_ctx | Duplicate ENCRYPTION_CAPABILITIES context | STATUS_INVALID_PARAMETER | P0 |
| T01-012 | negotiate_dup_compress_ctx | Duplicate COMPRESSION_CAPABILITIES context | STATUS_INVALID_PARAMETER | P0 |
| T01-013 | negotiate_zero_signing_alg | SIGNING_CAPABILITIES with SigningAlgorithmCount=0 | STATUS_INVALID_PARAMETER | P0 |
| T01-014 | negotiate_zero_compress_alg | COMPRESSION_CAPABILITIES with CompressionAlgorithmCount=0 | STATUS_INVALID_PARAMETER | P0 |
| T01-015 | negotiate_no_preauth_311 | SMB 3.1.1 without PREAUTH context | STATUS_INVALID_PARAMETER (Preauth_HashId not set) | P0 |
| T01-016 | negotiate_signing_fallback | No signing algorithm overlap | Server falls back to AES-CMAC, signing_negotiated=true | P1 |
| T01-017 | negotiate_cipher_prefer | Offer both AES-128-CCM and AES-128-GCM | Server selects GCM (preferred) | P1 |
| T01-018 | negotiate_capabilities | Verify SMB2_GLOBAL_CAP flags in response | Leasing, LargeMTU, MultiCredit, DFS, Encryption, Notifications present per dialect | P1 |
| T01-019 | negotiate_server_guid | Disconnect and reconnect, compare ServerGUID | ServerGUID is identical across reconnects | P1 |
| T01-020 | negotiate_max_transact | Verify MaxTransactSize, MaxReadSize, MaxWriteSize | Values match server configuration | P1 |

---

## T02: SESSION (35 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T02-001 | session_ntlmv2_auth | NTLMv2 session setup with valid credentials | STATUS_SUCCESS, SessionId assigned | P0 |
| T02-002 | session_ntlm_auth | NTLMv1 session setup with valid credentials | STATUS_SUCCESS (if SMB_INSECURE_SERVER enabled) | P1 |
| T02-003 | session_invalid_password | NTLMv2 with wrong password | STATUS_LOGON_FAILURE | P0 |
| T02-004 | session_invalid_user | NTLMv2 with nonexistent username | STATUS_LOGON_FAILURE | P0 |
| T02-005 | session_guest | Guest session setup with empty credentials | STATUS_SUCCESS, SESSION_FLAG_IS_GUEST set | P0 |
| T02-006 | session_anonymous | Anonymous session (NTLMSSP_ANONYMOUS token) | STATUS_SUCCESS, SESSION_FLAG_IS_NULL_LE set | P0 |
| T02-007 | session_anonymous_reauth | Anonymous re-auth with zero-length NtChallengeResponse | STATUS_SUCCESS, session remains anonymous | P1 |
| T02-008 | session_reauth_same_user | Re-authenticate same user on existing session | STATUS_SUCCESS, session keys updated | P1 |
| T02-009 | session_reauth_different_user | Re-authenticate with different user on existing session | STATUS_SUCCESS, session rebound to new user | P1 |
| T02-010 | session_binding_valid | SMB 3.x session binding (multichannel) with correct GUID | STATUS_SUCCESS, session bound to new channel | P1 |
| T02-011 | session_binding_wrong_guid | Session binding with mismatched ClientGUID | STATUS_USER_SESSION_DELETED or error | P1 |
| T02-012 | session_binding_wrong_dialect | Session binding with mismatched dialect | Binding rejected | P1 |
| T02-013 | session_binding_wrong_user | Session binding with different user credentials | Binding rejected | P1 |
| T02-014 | session_logoff | Normal session logoff | STATUS_SUCCESS, session resources freed | P0 |
| T02-015 | session_double_logoff | Logoff an already logged-off session | STATUS_USER_SESSION_DELETED | P1 |
| T02-016 | session_encrypt_aes128_ccm | Session setup with AES-128-CCM encryption | All subsequent traffic encrypted, operations succeed | P0 |
| T02-017 | session_encrypt_aes128_gcm | Session setup with AES-128-GCM encryption | All subsequent traffic encrypted, operations succeed | P0 |
| T02-018 | session_encrypt_aes256_ccm | Session setup with AES-256-CCM encryption | All subsequent traffic encrypted (if supported) | P1 |
| T02-019 | session_encrypt_aes256_gcm | Session setup with AES-256-GCM encryption | All subsequent traffic encrypted (if supported) | P1 |
| T02-020 | session_sign_hmac_sha256 | Session with HMAC-SHA256 signing (SMB 2.x) | Signed packets verified correctly | P0 |
| T02-021 | session_sign_aes_cmac | Session with AES-CMAC signing (SMB 3.0+) | Signed packets verified correctly | P0 |
| T02-022 | session_sign_aes_gmac | Session with AES-GMAC signing (SMB 3.1.1) | Signed packets verified correctly | P1 |
| T02-023 | session_expired | Use expired session (server-side timeout) | STATUS_NETWORK_SESSION_EXPIRED | P1 |
| T02-024 | session_previous_destroy | SESSION_SETUP with PreviousSessionId of active session | Previous session destroyed, new session created | P1 |
| T02-025 | session_encryption_enforce | Send unencrypted request on encrypted session | STATUS_ACCESS_DENIED, connection disconnected | P0 |
| T02-026 | session_preauth_integrity | Verify preauth integrity hash chain for SMB 3.1.1 | Session keys derived correctly from preauth hash | P0 |
| T02-027 | session_max_sessions | Create sessions up to max_active_sessions limit | Final session returns STATUS_INSUFFICIENT_RESOURCES | P1 |
| T02-028 | session_closed_notification | Logoff session, verify SMB2_SERVER_TO_CLIENT_NOTIFICATION | Other channels receive notification command 0x0013 with SMB2_NOTIFY_SESSION_CLOSED | P1 |
| T02-029 | session_spnego_negotiate | SPNEGO negotiate token with multiple mechTypes | Server selects NTLMSSP, returns acceptIncomplete | P1 |
| T02-030 | session_zero_security_buffer | SESSION_SETUP with zero-length SecurityBuffer | STATUS_INVALID_PARAMETER or appropriate error | P1 |
| T02-031 | session_oversized_security_buffer | SecurityBuffer exceeds MaxTransactSize | Request rejected | P2 |
| T02-032 | session_cancel_in_progress | CANCEL a pending SESSION_SETUP | Session setup aborted cleanly | P2 |
| T02-033 | session_signing_required | Server requires signing, client does not sign | Connection rejected or signing enforced | P0 |
| T02-034 | session_channel_sequence_init | Verify ChannelSequence starts at 0 | File operations succeed with ChannelSequence=0 | P1 |
| T02-035 | session_multichannel_failover | Kill one channel, verify session survives on other | Operations continue on remaining channel | P2 |

---

## T03: TREE_CONNECT (18 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T03-001 | tree_connect_disk_share | Connect to a disk share | STATUS_SUCCESS, ShareType=DISK | P0 |
| T03-002 | tree_connect_ipc | Connect to IPC$ | STATUS_SUCCESS, ShareType=PIPE | P0 |
| T03-003 | tree_connect_nonexistent | Connect to nonexistent share name | STATUS_BAD_NETWORK_NAME | P0 |
| T03-004 | tree_connect_long_name | Share name >= 80 characters | STATUS_BAD_NETWORK_NAME | P0 |
| T03-005 | tree_connect_no_session | TREE_CONNECT without valid session | STATUS_USER_SESSION_DELETED | P1 |
| T03-006 | tree_disconnect | Normal tree disconnect | STATUS_SUCCESS, tree resources freed | P0 |
| T03-007 | tree_disconnect_double | Disconnect an already-disconnected tree | STATUS_NETWORK_NAME_DELETED | P1 |
| T03-008 | tree_connect_max_connections | Connect until max_connections_per_share reached | Final connect returns STATUS_REQUEST_NOT_ACCEPTED | P1 |
| T03-009 | tree_connect_access_denied | Connect to share user is not authorized for | STATUS_ACCESS_DENIED | P1 |
| T03-010 | tree_connect_host_denied | Connect from IP not in host allow list | STATUS_ACCESS_DENIED | P1 |
| T03-011 | tree_connect_extension_present | SMB 3.1.1 TREE_CONNECT with EXTENSION_PRESENT flag | PathOffset parsed relative to Buffer[0], connection succeeds | P1 |
| T03-012 | tree_connect_extension_bad_offset | Extension with out-of-bounds PathOffset | Request rejected, no buffer overread | P1 |
| T03-013 | tree_connect_encrypt_share | Connect to share with encryption required | Subsequent operations must be encrypted | P1 |
| T03-014 | tree_connect_readonly_share | Connect to read-only share | Write operations return STATUS_ACCESS_DENIED | P1 |
| T03-015 | tree_connect_case_insensitive | Connect with mixed-case share name | Connection succeeds (case-insensitive match) | P1 |
| T03-016 | tree_connect_unc_format | Path in \\\\server\\share UNC format | Parsed correctly, connection succeeds | P0 |
| T03-017 | tree_connect_multiple_trees | Multiple TREE_CONNECT to different shares on one session | All connections active simultaneously | P1 |
| T03-018 | tree_connect_invalid_tid_usage | Use invalid TreeId in subsequent operations | STATUS_NETWORK_NAME_DELETED | P1 |

---

## T04: CREATE (60 tests)

### T04-A: Create Dispositions (14 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T04-001 | create_supersede_new | FILE_SUPERSEDE on nonexistent file | File created, FILE_CREATED | P0 |
| T04-002 | create_supersede_existing | FILE_SUPERSEDE on existing file | File truncated, FILE_SUPERSEDED | P0 |
| T04-003 | create_open_existing | FILE_OPEN on existing file | File opened, FILE_OPENED | P0 |
| T04-004 | create_open_nonexistent | FILE_OPEN on nonexistent file | STATUS_OBJECT_NAME_NOT_FOUND | P0 |
| T04-005 | create_create_new | FILE_CREATE on nonexistent file | File created, FILE_CREATED | P0 |
| T04-006 | create_create_existing | FILE_CREATE on existing file | STATUS_OBJECT_NAME_COLLISION | P0 |
| T04-007 | create_open_if_new | FILE_OPEN_IF on nonexistent file | File created, FILE_CREATED | P0 |
| T04-008 | create_open_if_existing | FILE_OPEN_IF on existing file | File opened, FILE_OPENED | P0 |
| T04-009 | create_overwrite_existing | FILE_OVERWRITE on existing file | File truncated, FILE_OVERWRITTEN | P0 |
| T04-010 | create_overwrite_nonexistent | FILE_OVERWRITE on nonexistent file | STATUS_OBJECT_NAME_NOT_FOUND | P0 |
| T04-011 | create_overwrite_if_new | FILE_OVERWRITE_IF on nonexistent file | File created, FILE_CREATED | P0 |
| T04-012 | create_overwrite_if_existing | FILE_OVERWRITE_IF on existing file | File truncated, FILE_OVERWRITTEN | P0 |
| T04-013 | create_invalid_disposition | Disposition value > 5 | STATUS_INVALID_PARAMETER | P1 |
| T04-014 | create_supersede_directory | FILE_SUPERSEDE on directory | STATUS_INVALID_PARAMETER or directory re-created | P2 |

### T04-B: Access Mask and Permissions (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T04-015 | create_access_mask_validate | DesiredAccess with bits outside 0xF21F01FF | STATUS_ACCESS_DENIED for invalid bits | P0 |
| T04-016 | create_maximum_allowed | MAXIMUM_ALLOWED access on file | Granted access matches user's effective rights | P0 |
| T04-017 | create_read_attributes_only | FILE_READ_ATTRIBUTES only (O_PATH open) | Attribute queries succeed, data read fails | P1 |
| T04-018 | create_synchronize_only | FILE_SYNCHRONIZE only | Open succeeds, minimal access granted | P2 |
| T04-019 | create_delete_access | FILE_DELETE access | Delete-on-close and rename permitted | P1 |
| T04-020 | create_write_dac | WRITE_DAC access | Security descriptor modification succeeds | P1 |
| T04-021 | create_write_owner | WRITE_OWNER access | Owner change succeeds | P2 |
| T04-022 | create_generic_all | GENERIC_ALL maps to full access | All operations permitted | P1 |
| T04-023 | create_generic_read_write | GENERIC_READ | GENERIC_WRITE mapping | Correct FILE_* bits set in granted access | P1 |
| T04-024 | create_no_access | DesiredAccess = 0 | STATUS_ACCESS_DENIED | P1 |

### T04-C: Filename Validation (8 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T04-025 | create_zero_length_name | Empty filename (NameLength=0) | Opens share root directory | P0 |
| T04-026 | create_odd_name_length | Odd NameLength (UTF-16LE must be even) | STATUS_INVALID_PARAMETER (EINVAL) | P0 |
| T04-027 | create_path_separator | Forward slash in path | Converted to backslash, open succeeds | P1 |
| T04-028 | create_trailing_backslash | Path ending with backslash | Directory open or STATUS_OBJECT_NAME_INVALID | P1 |
| T04-029 | create_dot_dot_escape | Path with ".." attempting share escape | STATUS_ACCESS_DENIED (path validation) | P0 |
| T04-030 | create_long_filename | Filename at MAX_PATH_LENGTH boundary | Open succeeds; one byte over returns error | P1 |
| T04-031 | create_special_chars | Filename with special characters (*, ?, <, >, |, ") | STATUS_OBJECT_NAME_INVALID for wildcards in create | P1 |
| T04-032 | create_case_sensitivity | Case-insensitive and case-sensitive name matching | Behavior matches share config (POSIX context) | P1 |

### T04-D: Create Options (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T04-033 | create_directory_file | FILE_DIRECTORY_FILE on existing directory | Directory opened successfully | P0 |
| T04-034 | create_directory_file_on_file | FILE_DIRECTORY_FILE on regular file | STATUS_NOT_A_DIRECTORY | P0 |
| T04-035 | create_non_directory_on_dir | FILE_NON_DIRECTORY_FILE on directory | STATUS_FILE_IS_A_DIRECTORY | P0 |
| T04-036 | create_delete_on_close | FILE_DELETE_ON_CLOSE option | File deleted when last handle closed | P0 |
| T04-037 | create_delete_on_close_no_delete | FILE_DELETE_ON_CLOSE without FILE_DELETE access | STATUS_ACCESS_DENIED (EACCES) | P0 |
| T04-038 | create_delete_on_close_readonly | FILE_DELETE_ON_CLOSE on read-only file | STATUS_CANNOT_DELETE | P0 |
| T04-039 | create_reparse_point_symlink | FILE_OPEN_REPARSE_POINT on symlink | Symlink opened, not followed | P1 |
| T04-040 | create_complete_if_oplocked | FILE_COMPLETE_IF_OPLOCKED option | Open returns STATUS_OPLOCK_BREAK_IN_PROGRESS if oplock held | P2 |
| T04-041 | create_open_requiring_oplock | FILE_OPEN_REQUIRING_OPLOCK option | Open fails if oplock cannot be granted | P2 |
| T04-042 | create_no_intermediate_buffering | FILE_NO_INTERMEDIATE_BUFFERING option | Write-through semantics enforced | P2 |

### T04-E: Create Contexts (12 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T04-043 | create_ctx_mxac | SMB2_CREATE_QUERY_MAXIMAL_ACCESS context | Response includes MxAc with maximal access mask | P0 |
| T04-044 | create_ctx_qfid | SMB2_CREATE_QUERY_ON_DISK_ID context | Response includes QFid with disk ID | P1 |
| T04-045 | create_ctx_secd | SMB2_CREATE_SD_BUFFER context | Security descriptor applied to new file | P1 |
| T04-046 | create_ctx_dhnq | DHnQ durable handle v1 request | Durable handle granted (batch oplock or lease with handle) | P1 |
| T04-047 | create_ctx_dh2q | DH2Q durable handle v2 request | Durable v2 handle with CreateGuid, timeout returned | P0 |
| T04-048 | create_ctx_dh2q_persistent | DH2Q with SMB2_DHANDLE_FLAG_PERSISTENT | Persistent handle granted on CA share | P1 |
| T04-049 | create_ctx_twrp | TWrp timewarp context with snapshot token | File opened from VSS snapshot | P1 |
| T04-050 | create_ctx_rqls | RqLs lease request context | Lease granted with requested caching state | P0 |
| T04-051 | create_ctx_aapl | AAPL (Apple) create context | Fruit capabilities negotiated | P1 |
| T04-052 | create_ctx_alsi | AlSi allocation size context | File allocation set on create | P1 |
| T04-053 | create_ctx_posix | SMB2_CREATE_TAG_POSIX context | POSIX semantics enabled (case-sensitive, umask) | P1 |
| T04-054 | create_ctx_ea_buffer | SMB2_CREATE_EA_BUFFER context | Extended attributes set on file | P1 |

### T04-F: Durable Handle Reconnect (6 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T04-055 | create_dhnc_reconnect | DHnC v1 durable reconnect after disconnect | File handle restored, operations resume | P1 |
| T04-056 | create_dh2c_reconnect | DH2C v2 durable reconnect with matching CreateGuid | Handle restored with correct state | P0 |
| T04-057 | create_dh2c_wrong_guid | DH2C reconnect with wrong ClientGUID | STATUS_OBJECT_NAME_NOT_FOUND | P1 |
| T04-058 | create_dh2c_persistent_reconnect | Persistent handle reconnect on CA share | Handle survives server restart | P1 |
| T04-059 | create_durable_timeout | Durable handle after timeout expiry | Handle expired, reconnect fails | P1 |
| T04-060 | create_pending_delete | Open file in directory with pending delete | STATUS_DELETE_PENDING | P0 |

---

## T05: READ (18 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T05-001 | read_normal | Read entire small file (< 64KB) | All bytes returned correctly | P0 |
| T05-002 | read_large | Read large file (> MaxReadSize chunks) | Multi-request read returns all data | P0 |
| T05-003 | read_at_eof | Read starting exactly at EOF | STATUS_END_OF_FILE, DataLength=0 | P0 |
| T05-004 | read_past_eof | Read range partially past EOF | Returns only available bytes (short read) | P0 |
| T05-005 | read_zero_length | Read with Length=0 | STATUS_SUCCESS with 0 bytes (or minimal response) | P1 |
| T05-006 | read_directory_handle | Read from directory handle | STATUS_INVALID_DEVICE_REQUEST | P0 |
| T05-007 | read_pipe | Read from named pipe (IPC$) | Data returned from pipe buffer | P1 |
| T05-008 | read_no_access | Read on handle without FILE_READ_DATA | STATUS_ACCESS_DENIED | P0 |
| T05-009 | read_negative_offset | Read with offset that converts to negative loff_t | Rejected before VFS call | P0 |
| T05-010 | read_offset_overflow | offset + length overflows u64 | Rejected, no wrap-around | P0 |
| T05-011 | read_rdma_channel | Read with RDMA channel descriptor | Data placed via RDMA if available, else error | P2 |
| T05-012 | read_lock_conflict | Read range held by exclusive lock (other session) | STATUS_FILE_LOCK_CONFLICT | P1 |
| T05-013 | read_shared_lock | Read range held by shared lock (same session) | Read succeeds | P1 |
| T05-014 | read_unbuffered_flag | SMB2_READFLAG_READ_UNBUFFERED (0x01) | Accepted or ignored gracefully | P2 |
| T05-015 | read_compressed_flag | SMB2_READFLAG_READ_COMPRESSED (0x02) | Accepted if compression negotiated | P2 |
| T05-016 | read_invalid_fid | Read with invalid VolatileFileId | STATUS_FILE_CLOSED | P0 |
| T05-017 | read_compound_fid | Read using compound FID sentinel (0xFFFFFFFFFFFFFFFF) | Uses FID from preceding CREATE in compound | P0 |
| T05-018 | read_mincount | Read with MinCount > 0, returned data < MinCount | Appropriate status handling | P2 |

---

## T06: WRITE (22 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T06-001 | write_normal | Write data to file at offset 0 | Data written, Count matches | P0 |
| T06-002 | write_append_sentinel | Write with offset 0xFFFFFFFFFFFFFFFF (append-to-EOF) | Data appended at current EOF, handle has FILE_APPEND_DATA | P0 |
| T06-003 | write_append_no_access | Append-to-EOF sentinel without FILE_APPEND_DATA | STATUS_ACCESS_DENIED | P0 |
| T06-004 | write_pipe | Write to named pipe (IPC$) | Data delivered to pipe | P1 |
| T06-005 | write_append_only_non_eof | Append-only handle, write at non-EOF offset | STATUS_ACCESS_DENIED (append-only handles reject explicit offsets) | P0 |
| T06-006 | write_no_access | Write on handle without FILE_WRITE_DATA/FILE_APPEND_DATA | STATUS_ACCESS_DENIED | P0 |
| T06-007 | write_negative_offset | Write offset that converts to negative loff_t | Rejected before VFS call | P0 |
| T06-008 | write_offset_overflow | offset + length overflows u64 | Rejected, no wrap-around | P0 |
| T06-009 | write_zero_length | Write with Length=0 | STATUS_SUCCESS, no data written | P1 |
| T06-010 | write_through_flag | SMB2_WRITEFLAG_WRITE_THROUGH (0x01) | fsync called after write | P1 |
| T06-011 | write_exceeds_max | Data length exceeds MaxWriteSize | Request rejected | P1 |
| T06-012 | write_readonly_share | Write on read-only share | STATUS_ACCESS_DENIED | P0 |
| T06-013 | write_channel_sequence_valid | Write with current ChannelSequence | STATUS_SUCCESS | P1 |
| T06-014 | write_channel_sequence_stale | Write with stale ChannelSequence | STATUS_FILE_NOT_AVAILABLE | P1 |
| T06-015 | write_compound_fid | Write using compound FID sentinel | Uses FID from preceding CREATE in compound | P0 |
| T06-016 | write_large_file | Write > 4GB file in chunks | All data written correctly, file size matches | P1 |
| T06-017 | write_concurrent | Two clients writing different regions concurrently | Both writes complete without corruption | P1 |
| T06-018 | write_unbuffered_flag | SMB2_WRITEFLAG_WRITE_UNBUFFERED (0x02) | Accepted or ignored gracefully | P2 |
| T06-019 | write_disk_full | Write that causes ENOSPC | STATUS_DISK_FULL | P1 |
| T06-020 | write_lock_conflict | Write to range held by lock (other session) | STATUS_FILE_LOCK_CONFLICT | P1 |
| T06-021 | write_data_offset_check | DataOffset field validation | DataOffset points to valid buffer location | P1 |
| T06-022 | write_invalid_fid | Write with invalid VolatileFileId | STATUS_FILE_CLOSED | P0 |

---

## T07: CLOSE (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T07-001 | close_normal | Close an open file handle | STATUS_SUCCESS, handle freed | P0 |
| T07-002 | close_postquery_flag | Close with SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB | STATUS_SUCCESS, file attributes returned in response | P0 |
| T07-003 | close_invalid_fid | Close with invalid VolatileFileId | STATUS_FILE_CLOSED | P0 |
| T07-004 | close_double | Close same FID twice | Second close returns STATUS_FILE_CLOSED | P0 |
| T07-005 | close_directory | Close directory handle | STATUS_SUCCESS, dir handle freed | P1 |
| T07-006 | close_delete_on_close | Close last handle with delete-on-close set | File deleted from filesystem | P0 |
| T07-007 | close_delete_on_close_multi | Close non-last handle with delete-on-close (other handles open) | File NOT deleted yet; new opens get STATUS_DELETE_PENDING | P0 |
| T07-008 | close_compound_fid | Close using compound FID sentinel | Closes FID from preceding CREATE | P0 |
| T07-009 | close_releases_locks | Close handle that holds byte-range locks | Locks released (locks_remove_posix before fput) | P1 |
| T07-010 | close_releases_oplock | Close handle that holds oplock | Oplock released, break notifications sent | P1 |

---

## T08: FLUSH (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T08-001 | flush_normal | Flush an open file with pending writes | STATUS_SUCCESS, data synced to disk | P0 |
| T08-002 | flush_no_write_access | Flush handle without FILE_WRITE_DATA or FILE_APPEND_DATA | STATUS_ACCESS_DENIED | P0 |
| T08-003 | flush_invalid_fid | Flush nonexistent FID | STATUS_FILE_CLOSED (not INVALID_HANDLE) | P0 |
| T08-004 | flush_directory | Flush directory handle | STATUS_SUCCESS or appropriate error | P1 |
| T08-005 | flush_pipe | Flush pipe handle | STATUS_SUCCESS (no-op) | P2 |
| T08-006 | flush_compound_fid | Flush using compound FID sentinel | Uses FID from preceding command | P0 |
| T08-007 | flush_channel_sequence | Flush with stale ChannelSequence | STATUS_FILE_NOT_AVAILABLE | P1 |
| T08-008 | flush_readonly_handle | Flush on read-only handle | STATUS_ACCESS_DENIED | P1 |
| T08-009 | flush_after_write | Write then flush in compound | Data persisted to disk | P0 |
| T08-010 | flush_no_pending_data | Flush with no dirty data | STATUS_SUCCESS (no-op, fast return) | P1 |

---

## T09: DIRECTORY (22 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T09-001 | dir_full_directory_info | FileFullDirectoryInformation enumeration | All entries with standard attributes | P0 |
| T09-002 | dir_both_directory_info | FileBothDirectoryInformation enumeration | Entries include short name | P0 |
| T09-003 | dir_directory_info | FileDirectoryInformation enumeration | Basic directory info entries | P1 |
| T09-004 | dir_names_only | FileNamesInformation enumeration | Only filenames returned, no attributes | P1 |
| T09-005 | dir_id_both_directory | FileIdBothDirectoryInformation enumeration | Entries include FileId | P0 |
| T09-006 | dir_id_full_directory | FileIdFullDirectoryInformation enumeration | Entries include FileId, full attributes | P1 |
| T09-007 | dir_id_extd_directory | FileIdExtdDirectoryInformation enumeration | Extended directory info with FileId | P2 |
| T09-008 | dir_wildcard_star | Wildcard pattern "*" matches all entries | All files and directories returned | P0 |
| T09-009 | dir_wildcard_question | Wildcard pattern "?" matches single char | Only matching entries returned | P1 |
| T09-010 | dir_wildcard_dos_star | DOS wildcard "<" (matches base name) | Correct DOS wildcard behavior | P2 |
| T09-011 | dir_wildcard_dos_question | DOS wildcard ">" (matches extension) | Correct DOS wildcard behavior | P2 |
| T09-012 | dir_wildcard_dos_dot | DOS wildcard '"' (matches dot) | Correct DOS wildcard behavior | P2 |
| T09-013 | dir_restart_scans | RESTART_SCANS flag resets enumeration | dot_dotdot[0/1] reset, scan restarts from beginning | P0 |
| T09-014 | dir_reopen_restart | REOPEN flag on directory handle | dot_dotdot reset, directory re-enumerated | P1 |
| T09-015 | dir_single_entry | SMB2_RETURN_SINGLE_ENTRY flag | Exactly one entry returned per request | P1 |
| T09-016 | dir_empty_directory | Enumerate empty directory | Only "." and ".." returned | P0 |
| T09-017 | dir_large_1000 | Enumerate directory with 1000 files | All entries returned across multiple responses | P1 |
| T09-018 | dir_large_10000 | Enumerate directory with 10000 files | All entries returned without errors | P2 |
| T09-019 | dir_large_100000 | Enumerate directory with 100000 files | Stress test for buffer management | P2 |
| T09-020 | dir_file_index | SMB2_INDEX_SPECIFIED flag with FileIndex | Enumeration starts at specified index | P2 |
| T09-021 | dir_invalid_info_level | Invalid FileInformationClass value | STATUS_INVALID_INFO_CLASS | P1 |
| T09-022 | dir_output_buffer_overflow | OutputBufferLength smaller than single entry | STATUS_INFO_LENGTH_MISMATCH or STATUS_BUFFER_OVERFLOW | P1 |

---

## T10: QUERY_INFO (18 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T10-001 | query_file_basic | FileBasicInformation (class 4) | CreationTime, LastAccessTime, LastWriteTime, ChangeTime, Attributes | P0 |
| T10-002 | query_file_standard | FileStandardInformation (class 5) | AllocationSize, EndOfFile, NumberOfLinks, DeletePending, Directory | P0 |
| T10-003 | query_file_internal | FileInternalInformation (class 6) | IndexNumber (inode number) | P1 |
| T10-004 | query_file_ea | FileEaInformation (class 7) | EaSize including all EAs | P1 |
| T10-005 | query_file_access | FileAccessInformation (class 8) | GrantedAccess mask | P1 |
| T10-006 | query_file_position | FilePositionInformation (class 14) | CurrentByteOffset | P2 |
| T10-007 | query_file_mode | FileModeInformation (class 16) | Mode flags | P2 |
| T10-008 | query_file_alignment | FileAlignmentInformation (class 17) | AlignmentRequirement | P2 |
| T10-009 | query_file_all | FileAllInformation (class 18) | All sub-info combined in one response | P0 |
| T10-010 | query_file_alternate_name | FileAlternateNameInformation (class 21) | 8.3 short name | P1 |
| T10-011 | query_file_stream | FileStreamInformation (class 22) | Stream names and sizes | P1 |
| T10-012 | query_file_compression | FileCompressionInformation (class 28) | Compression state | P2 |
| T10-013 | query_file_network_open | FileNetworkOpenInformation (class 34) | Combined attributes for network open | P1 |
| T10-014 | query_file_attribute_tag | FileAttributeTagInformation (class 35) | Attributes and ReparseTag | P1 |
| T10-015 | query_file_id | FileIdInformation (class 59) | VolumeSerialNumber, FileId | P1 |
| T10-016 | query_file_stat | FileStatInformation (class 0x46) | STAT info including inode/dev | P2 |
| T10-017 | query_file_stat_lx | FileStatLxInformation (class 0x47) | Linux extended stat info | P2 |
| T10-018 | query_file_full_ea | FileFullEaInformation (class 15) | Full EA list with names and values | P1 |

---

## T11: QUERY_INFO - Filesystem (8 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T11-001 | query_fs_volume | FileFsVolumeInformation | VolumeCreationTime, SerialNumber, Label | P0 |
| T11-002 | query_fs_size | FileFsSizeInformation | TotalAllocationUnits, AvailableAllocationUnits | P0 |
| T11-003 | query_fs_device | FileFsDeviceInformation | DeviceType, Characteristics | P1 |
| T11-004 | query_fs_attribute | FileFsAttributeInformation | FileSystemAttributes, MaxNameLength, FsName | P0 |
| T11-005 | query_fs_full_size | FileFsFullSizeInformation | Caller/actual available units | P1 |
| T11-006 | query_fs_sector_size | FileFsSectorSizeInformation | Physical/logical sector sizes | P1 |
| T11-007 | query_fs_object_id | FileFsObjectIdInformation | Filesystem object ID | P2 |
| T11-008 | query_fs_control | FileFsControlInformation | Quota control info | P2 |

---

## T12: SET_INFO + Timestamps (16 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T12-001 | set_file_basic | FileBasicInformation set timestamps | Timestamps updated on disk | P0 |
| T12-002 | set_file_allocation | FileAllocationInformation | Allocation size changed | P1 |
| T12-003 | set_file_eof | FileEndOfFileInformation | File truncated or extended | P0 |
| T12-004 | set_file_rename | FileRenameInformation (class 10) | File renamed | P0 |
| T12-005 | set_file_rename_ex | FileRenameInformationEx (class 65) | File renamed with replace semantics | P1 |
| T12-006 | set_file_link | FileLinkInformation | Hard link created | P1 |
| T12-007 | set_file_disposition | FileDispositionInformation | Delete-on-close set/cleared | P0 |
| T12-008 | set_file_disposition_ex | FileDispositionInformationEx | Extended delete-on-close flags | P1 |
| T12-009 | set_file_position | FilePositionInformation | Position updated | P2 |
| T12-010 | set_file_mode | FileModeInformation | Mode flags updated | P2 |
| T12-011 | set_file_full_ea | FileFullEaInformation | Extended attributes set/modified | P1 |
| T12-012 | set_security_dacl | SecurityInformation DACL | DACL modified on file | P0 |
| T12-013 | set_security_sacl | SecurityInformation SACL | SACL modified (requires SeSecurityPrivilege) | P2 |
| T12-014 | set_security_owner | SecurityInformation Owner | Owner SID changed | P1 |
| T12-015 | timestamp_preserve_on_read | Read does not update LastAccessTime (Windows compat) | atime unchanged after read | P1 |
| T12-016 | timestamp_negative_100ns | Set timestamp to -1 (preserve) per MS-SMB2 | Original timestamp preserved, not overwritten | P1 |

---

## T13: LOCK (32 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T13-001 | lock_exclusive | Exclusive lock on byte range | Lock granted, other clients get LOCK_CONFLICT | P0 |
| T13-002 | lock_shared | Shared lock on byte range | Lock granted, other shared locks allowed | P0 |
| T13-003 | lock_exclusive_fail_immediately | Exclusive lock with FAIL_IMMEDIATELY on contested range | STATUS_LOCK_NOT_GRANTED (immediate) | P0 |
| T13-004 | lock_shared_fail_immediately | Shared lock with FAIL_IMMEDIATELY on exclusive-held range | STATUS_LOCK_NOT_GRANTED (immediate) | P0 |
| T13-005 | lock_unlock | Unlock a previously locked range | Lock released, range available | P0 |
| T13-006 | lock_unlock_no_match | Unlock with no matching lock | STATUS_RANGE_NOT_LOCKED | P0 |
| T13-007 | lock_zero_byte | Lock with Length=0 (zero-byte lock) | Lock granted at offset (zero-length marker) | P1 |
| T13-008 | lock_full_range | Lock range 0 to 0xFFFFFFFFFFFFFFFF | Entire file locked | P1 |
| T13-009 | lock_wrap_past_u64 | Lock range that wraps past 2^64 | fl_end inclusive, wrap-around handled | P1 |
| T13-010 | lock_beyond_offset_max | Lock range beyond OFFSET_MAX | Skip vfs_lock_file, tracked internally only | P1 |
| T13-011 | lock_count_zero | LockCount=0 in LOCK request | STATUS_INVALID_PARAMETER | P0 |
| T13-012 | lock_count_max | LockCount exceeds server limit | STATUS_INVALID_PARAMETER | P1 |
| T13-013 | lock_same_handle_overlap | Overlapping lock on same handle | Upgrade or error depending on type | P0 |
| T13-014 | lock_cross_connection_conflict | Lock conflict across different connections | STATUS_LOCK_NOT_GRANTED | P0 |
| T13-015 | lock_blocking_async | Blocking lock becomes async (STATUS_PENDING) | Interim response sent, lock granted when available | P0 |
| T13-016 | lock_blocking_cancel | Cancel a blocking (async) lock | STATUS_CANCELLED returned, lock request abandoned | P0 |
| T13-017 | lock_rollback_partial | Multiple locks in single request, middle one fails | All locks in request rolled back | P0 |
| T13-018 | lock_mixed_lock_unlock | Mix of lock and unlock in single request | STATUS_INVALID_PARAMETER (mixed not allowed) | P0 |
| T13-019 | lock_sequence_replay_valid | Lock sequence replay with matching index (1-64) | STATUS_OK (replay detected, no-op) | P0 |
| T13-020 | lock_sequence_replay_invalid | Lock with sequence index 0 (invalid) | Treated as new lock request, not replay | P1 |
| T13-021 | lock_sequence_sentinel_0xff | Lock_seq slot initialized to 0xFF sentinel | First lock at that index proceeds normally | P1 |
| T13-022 | lock_sequence_indices_1_64 | Test all valid sequence bucket indices (1-64) | All indices tracked correctly in lock_seq[65] array | P2 |
| T13-023 | lock_sequence_store_after | Sequence stored only AFTER lock success | Failed lock does not pollute sequence table | P0 |
| T13-024 | lock_persistent_handle | Lock on persistent/resilient/durable handle | Lock sequence replay enabled | P1 |
| T13-025 | lock_channel_sequence | Lock with ChannelSequence validation | Stale sequence returns STATUS_FILE_NOT_AVAILABLE | P1 |
| T13-026 | lock_fl_end_inclusive | Verify POSIX fl_end = fl_start + length - 1 | Lock range correct (off-by-one regression test) | P0 |
| T13-027 | lock_upgrade_shared_to_excl | Upgrade shared lock to exclusive on same handle | Lock upgraded atomically | P1 |
| T13-028 | lock_downgrade_excl_to_shared | Downgrade exclusive to shared | Lock downgraded | P2 |
| T13-029 | lock_close_releases | Close file handle with active locks | All locks released | P0 |
| T13-030 | lock_many_ranges | Lock 100 non-overlapping ranges | All granted and trackable | P1 |
| T13-031 | lock_invalid_flags | Lock with undefined flag bits | STATUS_INVALID_PARAMETER | P1 |
| T13-032 | lock_invalid_fid | Lock on invalid FID | STATUS_FILE_CLOSED | P0 |

---

## T14: OPLOCK (16 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T14-001 | oplock_level_ii | Request Level II oplock | Granted on uncontested file | P0 |
| T14-002 | oplock_exclusive | Request Exclusive oplock | Granted when no other handles open | P0 |
| T14-003 | oplock_batch | Request Batch oplock | Granted when no other handles open | P0 |
| T14-004 | oplock_break_to_level_ii | Second open breaks Exclusive to Level II | Break notification sent, first client acknowledges | P0 |
| T14-005 | oplock_break_to_none | Second open breaks Level II to None | Break notification sent | P0 |
| T14-006 | oplock_break_batch_open | Batch oplock broken by second CREATE | Break sent before second open proceeds | P0 |
| T14-007 | oplock_ack_valid | Acknowledge oplock break with correct level | Break acknowledged, new level set | P0 |
| T14-008 | oplock_ack_invalid_level | Acknowledge with wrong oplock level | Error or connection disrupted | P1 |
| T14-009 | oplock_none_request | Request SMB2_OPLOCK_LEVEL_NONE | No oplock granted | P1 |
| T14-010 | oplock_break_timeout | Fail to acknowledge break within timeout | Server forces break to None | P1 |
| T14-011 | oplock_break_on_write | Write from second client breaks oplock | Break to Level II or None | P1 |
| T14-012 | oplock_break_on_lock | Byte-range lock from second client | Oplock break triggered | P1 |
| T14-013 | oplock_break_on_setinfo | SET_INFO from second client | Oplock break triggered | P2 |
| T14-014 | oplock_break_async | Oplock break uses async semantics | Break sent as unsolicited response | P0 |
| T14-015 | oplock_reconnect_preserve | Oplock state after durable reconnect | Oplock level restored | P1 |
| T14-016 | oplock_directory | Request oplock on directory | Oplock not granted (directories) | P2 |

---

## T15: LEASE (18 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T15-001 | lease_read | Request R lease | Granted on uncontested file | P0 |
| T15-002 | lease_read_write | Request RW lease | Granted when no other handles | P0 |
| T15-003 | lease_read_write_handle | Request RWH lease | Granted when no other handles | P0 |
| T15-004 | lease_break_rw_to_r | Second open breaks RW to R | Break notification, client acknowledges | P0 |
| T15-005 | lease_break_rwh_to_rw | Second open breaks RWH to RW | Handle caching break | P0 |
| T15-006 | lease_break_to_none | Conflicting access breaks to None | Full lease break | P0 |
| T15-007 | lease_ack_valid | Acknowledge lease break with correct state | New lease state applied | P0 |
| T15-008 | lease_ack_wrong_state | Acknowledge with wrong lease state | Error returned | P1 |
| T15-009 | lease_key_match | Two opens with same lease key share lease | Single lease state for both handles | P0 |
| T15-010 | lease_key_different | Two opens with different lease keys | Independent lease states | P1 |
| T15-011 | lease_upgrade | Upgrade R lease to RW | Lease upgraded on same key | P1 |
| T15-012 | lease_parent_break | Parent directory lease break on child create | Lazy parent lease break on close | P1 |
| T15-013 | lease_v2_epoch | Lease V2 with epoch tracking | Epoch incremented on break | P1 |
| T15-014 | lease_v2_parent_key | Lease V2 with parent lease key | Parent directory caching | P1 |
| T15-015 | lease_durable_requirement | Durable handle requires lease with Handle | DHnQ fails without H caching | P1 |
| T15-016 | lease_break_timeout | Lease break not acknowledged in time | Server forces break | P1 |
| T15-017 | lease_on_directory | Request lease on directory | Lease granted (directories support leasing) | P1 |
| T15-018 | lease_close_releases | Close last handle releases lease | Lease freed from table | P0 |

---

## T16: SHAREMODE (8 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T16-001 | share_none | Open with ShareAccess=0 (exclusive) | Second open gets STATUS_SHARING_VIOLATION | P0 |
| T16-002 | share_read | Open with FILE_SHARE_READ | Second reader succeeds, writer fails | P0 |
| T16-003 | share_write | Open with FILE_SHARE_WRITE | Second writer succeeds | P1 |
| T16-004 | share_delete | Open with FILE_SHARE_DELETE | Delete/rename by second client succeeds | P1 |
| T16-005 | share_read_write | Open with FILE_SHARE_READ|WRITE | Both readers and writers allowed | P0 |
| T16-006 | share_all | Open with all share flags | Fully shared access | P1 |
| T16-007 | share_conflict_matrix | Test all sharemode x access combinations | Correct conflict behavior per MS-SMB2 | P0 |
| T16-008 | share_reopen_after_close | Close exclusive handle, verify second open succeeds | No stale sharing violation | P1 |

---

## T17: COMPOUND (15 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T17-001 | compound_create_read_close | CREATE + READ + CLOSE in single compound | All three operations succeed | P0 |
| T17-002 | compound_create_write_close | CREATE + WRITE + CLOSE | Data written, file closed | P0 |
| T17-003 | compound_fid_sentinel | FID=0xFFFFFFFFFFFFFFFF in chained request | Uses FID from preceding CREATE | P0 |
| T17-004 | compound_non_create_fid | FLUSH/READ/WRITE/CLOSE chain (non-CREATE FID capture) | Compound FID extracted from FLUSH request for subsequent ops | P0 |
| T17-005 | compound_error_cascade_create | CREATE fails in compound | Subsequent related ops get STATUS_INVALID_PARAMETER (cascade) | P0 |
| T17-006 | compound_error_no_cascade | Non-CREATE failure in compound | Error does NOT cascade to subsequent ops | P0 |
| T17-007 | compound_flush_close | FLUSH + CLOSE compound | Both succeed using same FID | P0 |
| T17-008 | compound_flush_flush | FLUSH + FLUSH compound | Both succeed using same FID | P1 |
| T17-009 | compound_rename | CREATE + SET_INFO(rename) + CLOSE | File renamed via compound | P0 |
| T17-010 | compound_query_set | QUERY_INFO + SET_INFO in compound | Both succeed | P1 |
| T17-011 | compound_interim | Compound with async operation | Interim response for async part | P1 |
| T17-012 | compound_padding | Verify 8-byte alignment between messages | Responses correctly padded | P1 |
| T17-013 | compound_unrelated | Multiple unrelated operations in one compound | Each operates independently | P1 |
| T17-014 | compound_max_depth | Maximum number of chained operations | Server handles up to limit | P2 |
| T17-015 | compound_ioctl_fid | IOCTL using compound FID | IOCTL dispatched with correct FID | P1 |

---

## T18: ASYNC + CANCEL (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T18-001 | async_interim_response | Long-running operation returns interim | STATUS_PENDING with AsyncId | P0 |
| T18-002 | async_final_response | Async operation completes | Final response with matching AsyncId | P0 |
| T18-003 | cancel_by_async_id | CANCEL with valid AsyncId | Pending operation cancelled | P0 |
| T18-004 | cancel_by_message_id | CANCEL with valid MessageId (no AsyncId) | Matching pending operation cancelled | P1 |
| T18-005 | cancel_invalid_id | CANCEL with nonexistent AsyncId | No crash, silent ignore | P0 |
| T18-006 | cancel_notify | CANCEL pending CHANGE_NOTIFY | Notify returns STATUS_CANCELLED | P0 |
| T18-007 | cancel_lock | CANCEL pending blocking lock | Lock returns STATUS_CANCELLED | P0 |
| T18-008 | cancel_signing_excluded | CANCEL is not signed (MS-SMB2 spec) | Server accepts unsigned CANCEL | P0 |
| T18-009 | async_credit_management | Async operation credits charged/returned | Outstanding_async counter correct, no leak | P1 |
| T18-010 | cancel_already_completed | CANCEL for already-completed operation | No effect, no crash | P1 |

---

## T19: IOCTL - Validate Negotiate (6 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T19-001 | ioctl_validate_negotiate | FSCTL_VALIDATE_NEGOTIATE_INFO with correct data | STATUS_SUCCESS, Capabilities/GUID/Dialect match | P0 |
| T19-002 | ioctl_validate_negotiate_mismatch | FSCTL_VALIDATE_NEGOTIATE_INFO with wrong dialect | Connection terminated (MS-SMB2 §3.3.5.15.12) | P0 |
| T19-003 | ioctl_validate_flags_check | IOCTL Flags != SMB2_0_IOCTL_IS_FSCTL | STATUS_INVALID_PARAMETER | P0 |
| T19-004 | ioctl_invalid_fid | IOCTL on invalid FID (when FID required) | STATUS_FILE_CLOSED | P1 |
| T19-005 | ioctl_unknown_code | Unknown FSCTL code not in handler table | STATUS_INVALID_DEVICE_REQUEST | P1 |
| T19-006 | ioctl_channel_sequence | IOCTL with stale ChannelSequence | STATUS_FILE_NOT_AVAILABLE | P1 |

---

## T20: IOCTL - Network Interface (4 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T20-001 | ioctl_query_network_iface | FSCTL_QUERY_NETWORK_INTERFACE_INFO | Interface list with speed, capability flags | P0 |
| T20-002 | ioctl_query_network_iface_win | FSCTL_QUERY_NETWORK_INTERFACE_INFO_WIN (0x001401FC) | Same as above, Windows alternate code | P2 |
| T20-003 | ioctl_query_network_iface_rdma | Interface info includes RDMA capability (if configured) | RDMA flag set on RDMA-capable interfaces | P2 |
| T20-004 | ioctl_query_network_iface_rss | Interface info includes RSS capability | RSS flag set on capable interfaces | P2 |

---

## T21: IOCTL - Copy Chunk (8 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T21-001 | ioctl_copychunk | FSCTL_COPYCHUNK basic copy | Data copied between files | P0 |
| T21-002 | ioctl_copychunk_write | FSCTL_COPYCHUNK_WRITE basic copy | Data copied with write semantics | P0 |
| T21-003 | ioctl_copychunk_resume_key | FSCTL_REQUEST_RESUME_KEY for source file | Resume key returned | P0 |
| T21-004 | ioctl_copychunk_invalid_key | Copy chunk with wrong resume key | STATUS_OBJECT_NAME_NOT_FOUND | P1 |
| T21-005 | ioctl_copychunk_cross_file | Copy between different files | Data integrity verified | P1 |
| T21-006 | ioctl_copychunk_large | Copy > 1MB in chunks | All chunks succeed, data matches | P1 |
| T21-007 | ioctl_copychunk_max | Copy at server's max chunk limit | Server returns limits on overflow | P1 |
| T21-008 | ioctl_copychunk_zero_chunks | Copy with 0 chunks | Server returns chunk limits | P1 |

---

## T22: IOCTL - Sparse / Ranges (8 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T22-001 | ioctl_set_sparse | FSCTL_SET_SPARSE with SetSparse=TRUE | File marked sparse | P0 |
| T22-002 | ioctl_set_sparse_no_buffer | FSCTL_SET_SPARSE with empty buffer | Defaults to SetSparse=TRUE (MS-FSCC §2.3.64) | P0 |
| T22-003 | ioctl_set_sparse_clear | FSCTL_SET_SPARSE with SetSparse=FALSE | Sparse flag cleared | P1 |
| T22-004 | ioctl_query_allocated_ranges | FSCTL_QUERY_ALLOCATED_RANGES | Allocated ranges returned | P0 |
| T22-005 | ioctl_set_zero_data | FSCTL_SET_ZERO_DATA on sparse file | Hole punched, data zeroed | P0 |
| T22-006 | ioctl_set_zero_data_no_write | FSCTL_SET_ZERO_DATA without write access | STATUS_ACCESS_DENIED | P1 |
| T22-007 | ioctl_file_level_trim | FSCTL_FILE_LEVEL_TRIM | Trim ranges discarded | P1 |
| T22-008 | ioctl_file_level_trim_no_write | FSCTL_FILE_LEVEL_TRIM without write access | STATUS_ACCESS_DENIED | P1 |

---

## T23: IOCTL - Compression / Integrity (6 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T23-001 | ioctl_get_compression | FSCTL_GET_COMPRESSION | Compression state returned | P1 |
| T23-002 | ioctl_set_compression | FSCTL_SET_COMPRESSION | Compression state set | P1 |
| T23-003 | ioctl_get_integrity | FSCTL_GET_INTEGRITY_INFORMATION | Integrity info returned | P1 |
| T23-004 | ioctl_set_integrity | FSCTL_SET_INTEGRITY_INFORMATION | Integrity state set | P1 |
| T23-005 | ioctl_duplicate_extents | FSCTL_DUPLICATE_EXTENTS_TO_FILE | Data deduplicated/reflinked | P1 |
| T23-006 | ioctl_query_file_regions | FSCTL_QUERY_FILE_REGIONS | File region info returned | P2 |

---

## T24: IOCTL - Pipes (6 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T24-001 | ioctl_pipe_transceive | FSCTL_PIPE_TRANSCEIVE on IPC$ | Send and receive pipe data | P0 |
| T24-002 | ioctl_pipe_peek | FSCTL_PIPE_PEEK | Available bytes reported | P1 |
| T24-003 | ioctl_pipe_wait | FSCTL_PIPE_WAIT for named pipe | Waits for pipe availability (timeout) | P1 |
| T24-004 | ioctl_pipe_wait_timeout | FSCTL_PIPE_WAIT with short timeout, pipe unavailable | STATUS_IO_TIMEOUT | P1 |
| T24-005 | ioctl_pipe_wait_no_buffer | FSCTL_PIPE_WAIT with empty buffer | STATUS_SUCCESS (per implementation) | P2 |
| T24-006 | ioctl_pipe_transceive_large | FSCTL_PIPE_TRANSCEIVE with large payload | Data transferred correctly | P2 |

---

## T25: IOCTL - Miscellaneous (14 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T25-001 | ioctl_enumerate_snapshots | FSCTL_SRV_ENUMERATE_SNAPSHOTS | Snapshot list returned | P1 |
| T25-002 | ioctl_is_pathname_valid | FSCTL_IS_PATHNAME_VALID | STATUS_SUCCESS (always valid) | P2 |
| T25-003 | ioctl_is_volume_dirty | FSCTL_IS_VOLUME_DIRTY | Volume dirty flag returned | P2 |
| T25-004 | ioctl_lock_volume | FSCTL_LOCK_VOLUME | Volume locked or not supported | P2 |
| T25-005 | ioctl_unlock_volume | FSCTL_UNLOCK_VOLUME | Volume unlocked or not supported | P2 |
| T25-006 | ioctl_create_get_object_id | FSCTL_CREATE_OR_GET_OBJECT_ID | Object ID returned | P2 |
| T25-007 | ioctl_get_object_id | FSCTL_GET_OBJECT_ID | Object ID returned | P2 |
| T25-008 | ioctl_set_object_id | FSCTL_SET_OBJECT_ID | Object ID set | P2 |
| T25-009 | ioctl_delete_object_id | FSCTL_DELETE_OBJECT_ID | Object ID removed | P2 |
| T25-010 | ioctl_srv_read_hash | FSCTL_SRV_READ_HASH (BranchCache) | Content info or NOT_SUPPORTED | P2 |
| T25-011 | ioctl_offload_read | FSCTL_OFFLOAD_READ | Offload token or NOT_SUPPORTED | P2 |
| T25-012 | ioctl_offload_write | FSCTL_OFFLOAD_WRITE | Offload write or NOT_SUPPORTED | P2 |
| T25-013 | ioctl_mark_handle | FSCTL_MARK_HANDLE | Handle marked or NOT_SUPPORTED | P2 |
| T25-014 | ioctl_query_on_disk_volume | FSCTL_QUERY_ON_DISK_VOLUME_INFO | STATUS_NOT_SUPPORTED | P2 |

---

## T26: CHANGE_NOTIFY (15 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T26-001 | notify_file_name_change | FILE_NOTIFY_CHANGE_FILE_NAME, create file | Notification with FILE_ACTION_ADDED | P0 |
| T26-002 | notify_dir_name_change | FILE_NOTIFY_CHANGE_DIR_NAME, create subdir | Notification with FILE_ACTION_ADDED | P0 |
| T26-003 | notify_attribute_change | FILE_NOTIFY_CHANGE_ATTRIBUTES, modify attrs | Notification received | P1 |
| T26-004 | notify_size_change | FILE_NOTIFY_CHANGE_SIZE, write to file | Notification received | P1 |
| T26-005 | notify_write_change | FILE_NOTIFY_CHANGE_LAST_WRITE, modify file | Notification with LastWriteTime | P1 |
| T26-006 | notify_security_change | FILE_NOTIFY_CHANGE_SECURITY, modify ACL | Notification received | P2 |
| T26-007 | notify_stream_change | FILE_NOTIFY_CHANGE_STREAM_NAME, create stream | Notification received | P2 |
| T26-008 | notify_watch_tree | SMB2_WATCH_TREE flag for recursive watching | Changes in subdirectories reported | P0 |
| T26-009 | notify_cancel | Cancel pending CHANGE_NOTIFY | STATUS_CANCELLED returned | P0 |
| T26-010 | notify_overflow | Rapid changes exceed notification buffer | STATUS_NOTIFY_ENUM_DIR returned | P1 |
| T26-011 | notify_multiple_filters | Multiple FILE_NOTIFY_CHANGE_* bits combined | All matching changes reported | P1 |
| T26-012 | notify_dir_deleted | Directory deleted while watch active | Watch cancelled, appropriate error | P1 |
| T26-013 | notify_piggyback_cancel | Cancel notify that was piggybacked (async) | Credit management correct, no outstanding_async leak | P1 |
| T26-014 | notify_rename | FILE_NOTIFY_CHANGE_FILE_NAME, rename file | FILE_ACTION_RENAMED_OLD_NAME + RENAMED_NEW_NAME | P1 |
| T26-015 | notify_compound_fid | CHANGE_NOTIFY using compound FID | Uses correct directory handle | P1 |

---

## T27: DURABLE HANDLES v1 (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T27-001 | durable_v1_create | DHnQ with batch oplock | Durable handle granted | P0 |
| T27-002 | durable_v1_reconnect | DHnC after disconnect | Handle reconnected, operations resume | P0 |
| T27-003 | durable_v1_timeout | DHnC after timeout expiry | STATUS_OBJECT_NAME_NOT_FOUND | P1 |
| T27-004 | durable_v1_no_batch_oplock | DHnQ without batch oplock | Durable not granted | P1 |
| T27-005 | durable_v1_with_lease_h | DHnQ with lease including Handle caching | Durable granted | P1 |
| T27-006 | durable_v1_data_persist | Write data, disconnect, reconnect, read | Data preserved across reconnect | P0 |
| T27-007 | durable_v1_lock_persist | Lock, disconnect, reconnect, verify lock | Lock preserved across reconnect | P1 |
| T27-008 | durable_v1_scavenger | Many durable handles, wait for scavenger | Expired handles cleaned up | P2 |
| T27-009 | durable_v1_config_required | Durable handle requires "durable handles" config | Handles rejected if config disabled | P1 |
| T27-010 | durable_v1_oplock_break | Oplock broken on durable handle during disconnect | Handle expired, reconnect fails | P1 |

---

## T28: DURABLE HANDLES v2 (12 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T28-001 | durable_v2_create | DH2Q with CreateGuid | Durable v2 handle granted with timeout | P0 |
| T28-002 | durable_v2_reconnect | DH2C with matching CreateGuid and ClientGuid | Handle reconnected | P0 |
| T28-003 | durable_v2_wrong_create_guid | DH2C with wrong CreateGuid | STATUS_OBJECT_NAME_NOT_FOUND | P0 |
| T28-004 | durable_v2_wrong_client_guid | DH2C with wrong ClientGuid | Reconnect rejected | P0 |
| T28-005 | durable_v2_timeout | DH2C after Timeout ms expiry | STATUS_OBJECT_NAME_NOT_FOUND | P1 |
| T28-006 | durable_v2_persistent | DH2Q with PERSISTENT flag on CA share | Persistent handle granted | P1 |
| T28-007 | durable_v2_persistent_reconnect | DH2C PERSISTENT after server restart | Handle survives server restart | P1 |
| T28-008 | durable_v2_timer_expiry | Verify durable_expire_timer callback | Handle cleaned up at timeout | P1 |
| T28-009 | durable_v2_app_instance | DH2Q with AppInstanceId | Second open with same AppInstanceId closes first | P2 |
| T28-010 | durable_v2_epoch | DH2C with epoch tracking | Epoch validated on reconnect | P2 |
| T28-011 | durable_v2_data_persist | Write, disconnect, reconnect, read data | Data preserved | P0 |
| T28-012 | durable_v2_conflict | DH2C on handle that was already reconnected | Conflict detected | P1 |

---

## T29: RESILIENT HANDLES (8 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T29-001 | resilient_create | FSCTL_LMR_REQUEST_RESILIENCY with valid timeout | Resilient handle established | P1 |
| T29-002 | resilient_reconnect | Reconnect resilient handle after disconnect | Handle restored, lock sequence enabled | P1 |
| T29-003 | resilient_timeout_default | Request with timeout=0, server assigns default | Default timeout applied | P1 |
| T29-004 | resilient_timeout_large | Request with very large timeout | Capped at server maximum | P1 |
| T29-005 | resilient_lock_sequence | Lock with valid sequence on resilient handle | Lock sequence replay works | P1 |
| T29-006 | resilient_oplock_required | Resilient without batch oplock or handle lease | Not granted | P2 |
| T29-007 | resilient_and_durable | Mix resilient and durable on same file | Correct priority/conflict handling | P2 |
| T29-008 | resilient_buffer_validation | FSCTL_LMR_REQUEST_RESILIENCY with invalid buffer | STATUS_INVALID_PARAMETER | P1 |

---

## T30: ACL and Security (12 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T30-001 | acl_query_dacl | Query DACL on file | DACL returned with ACEs | P0 |
| T30-002 | acl_set_dacl | Set DACL with specific ACEs | DACL applied, access enforced | P0 |
| T30-003 | acl_query_owner | Query owner SID | Owner SID returned | P1 |
| T30-004 | acl_set_owner | Set owner SID | Owner changed | P1 |
| T30-005 | acl_query_group | Query primary group SID | Group SID returned | P1 |
| T30-006 | acl_empty_dacl | Set empty DACL (0 ACEs) | All access denied; hide_on_access_denied returns NAME_NOT_FOUND | P0 |
| T30-007 | acl_partial_dacl | DACL with FILE_READ_ATTRIBUTES ACE only | File visible (ACCESS_DENIED), not hidden (NAME_NOT_FOUND) | P0 |
| T30-008 | acl_null_dacl | Set NULL DACL (no DACL present) | Everyone gets full access | P1 |
| T30-009 | acl_inherit_file | Create file in directory with inheritable ACEs | File inherits parent ACEs | P1 |
| T30-010 | acl_inherit_directory | Create subdirectory with inheritable ACEs | Directory inherits parent ACEs | P1 |
| T30-011 | acl_maximum_allowed_dacl | MAXIMUM_ALLOWED with complex DACL | Correct effective access computed | P1 |
| T30-012 | acl_audit_sacl | Set/query SACL (audit) | SACL handled (requires SeSecurityPrivilege) | P2 |

---

## T31: DELETE_ON_CLOSE (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T31-001 | doc_basic | Create with DELETE_ON_CLOSE, close | File deleted | P0 |
| T31-002 | doc_via_set_info | Set FileDispositionInformation DeletePending=TRUE | Delete-on-close set; file deleted on close | P0 |
| T31-003 | doc_clear_via_set_info | Set FileDispositionInformation DeletePending=FALSE | Delete-on-close cleared | P0 |
| T31-004 | doc_multi_handle | Two handles, one sets DOC | File not deleted until ALL handles closed | P0 |
| T31-005 | doc_new_open_pending | Open file pending delete | STATUS_DELETE_PENDING | P0 |
| T31-006 | doc_directory_nonempty | DELETE_ON_CLOSE on non-empty directory | STATUS_DIRECTORY_NOT_EMPTY on close | P1 |
| T31-007 | doc_directory_empty | DELETE_ON_CLOSE on empty directory | Directory deleted on close | P0 |
| T31-008 | doc_readonly_file | DELETE_ON_CLOSE on read-only file | STATUS_CANNOT_DELETE | P0 |
| T31-009 | doc_permission_check | DELETE_ON_CLOSE without DELETE access | STATUS_ACCESS_DENIED | P0 |
| T31-010 | doc_disposition_ex | FileDispositionInformationEx with flags | Extended delete semantics (POSIX, etc.) | P1 |

---

## T32: COMPRESSION (12 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T32-001 | compress_negotiate_lznt1 | Negotiate LZNT1 (0x0001) compression | LZNT1 selected in negotiate response | P1 |
| T32-002 | compress_negotiate_lz77 | Negotiate LZ77 plain (0x0002) compression | LZ77 selected | P1 |
| T32-003 | compress_negotiate_lz77_huffman | Negotiate LZ77+Huffman (0x0003) compression | LZ77+Huffman selected | P1 |
| T32-004 | compress_negotiate_lz4 | Negotiate LZ4 (0x0005) compression | LZ4 selected (if supported) | P2 |
| T32-005 | compress_negotiate_pattern_v1 | Pattern_V1 compression in chained mode | Pattern_V1 selected | P2 |
| T32-006 | compress_roundtrip_lznt1 | Write compressed, read decompressed (LZNT1) | Data integrity preserved | P0 |
| T32-007 | compress_roundtrip_lz77 | Write compressed, read decompressed (LZ77) | Data integrity preserved | P0 |
| T32-008 | compress_roundtrip_lz77_huffman | Write compressed, read decompressed (LZ77+Huffman) | Data integrity preserved | P0 |
| T32-009 | compress_crafted_decompression | Decompress server-crafted compressed payload | Correct data output | P1 |
| T32-010 | compress_chained | Chained compression (multiple algorithms) | All algorithms applied in order | P1 |
| T32-011 | compress_pattern_v1_repeated | Pattern_V1 on repeated-byte input | Compressed to 8 bytes | P1 |
| T32-012 | compress_no_negotiated | Compression request without negotiated support | Not compressed, data sent raw | P1 |

---

## T33: QUIC Transport (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T33-001 | quic_connect | Establish SMB over QUIC connection (UDP 443) | QUIC handshake complete, SMB session ready | P0 |
| T33-002 | quic_negotiate | NEGOTIATE over QUIC | SMB 3.1.1 negotiated (no NetBIOS prefix) | P0 |
| T33-003 | quic_session_setup | SESSION_SETUP over QUIC with TLS 1.3 | Authenticated session | P0 |
| T33-004 | quic_file_read | Read file over QUIC | Data returned correctly | P0 |
| T33-005 | quic_file_write | Write file over QUIC | Data written correctly | P0 |
| T33-006 | quic_large_transfer | Transfer large file over QUIC | Data integrity preserved | P1 |
| T33-007 | quic_reconnect | Reconnect after QUIC connection loss | Session re-established | P1 |
| T33-008 | quic_no_netbios_prefix | Verify no RFC1002 4-byte prefix on QUIC | Raw SMB frames on QUIC stream | P1 |
| T33-009 | quic_certificate_validation | QUIC with valid/invalid server certificate | Valid connects, invalid rejected | P1 |
| T33-010 | quic_concurrent_streams | Multiple SMB sessions over QUIC | All sessions operate independently | P2 |

---

## T34: Fruit / Apple Extensions (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T34-001 | fruit_aapl_create_context | AAPL create context in CREATE request | Fruit capabilities negotiated in response | P1 |
| T34-002 | fruit_aapl_capabilities | Verify fruit capability bits | Server reports supported features | P1 |
| T34-003 | fruit_resource_fork | Access resource fork via :AFP_Resource stream | Stream data accessible | P1 |
| T34-004 | fruit_finder_info | Access Finder info via :AFP_AfpInfo stream | Finder metadata accessible | P1 |
| T34-005 | fruit_model_string | Verify server model string in fruit response | Model string matches config (fruit_model) | P2 |
| T34-006 | fruit_time_machine | Time Machine backup over ksmbd | Backup volume accessible | P2 |
| T34-007 | fruit_copyfile | macOS-style copy via AAPL extensions | Efficient server-side copy | P2 |
| T34-008 | fruit_posix_rename | POSIX rename via fruit extension | Atomic cross-directory rename | P2 |
| T34-009 | fruit_validate_context | Invalid fruit create context data | Error returned, no crash | P1 |
| T34-010 | fruit_disabled | Fruit extensions disabled in config | AAPL context not present in response | P1 |

---

## T35: DFS (6 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T35-001 | dfs_get_referrals | FSCTL_DFS_GET_REFERRALS | DFS referral list returned | P1 |
| T35-002 | dfs_get_referrals_ex | FSCTL_DFS_GET_REFERRALS_EX | Extended referral list | P2 |
| T35-003 | dfs_path_resolution | Open file via DFS path | Resolved to actual share path | P1 |
| T35-004 | dfs_capability_flag | DFS capability in negotiate | SMB2_GLOBAL_CAP_DFS set | P1 |
| T35-005 | dfs_tree_connect_flag | DFS flag in TREE_CONNECT response | Share flagged as DFS root | P2 |
| T35-006 | dfs_disabled | DFS disabled in config | Referral request returns NOT_FOUND | P2 |

---

## T36: VSS / Snapshots (6 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T36-001 | vss_enumerate | FSCTL_SRV_ENUMERATE_SNAPSHOTS | Snapshot list with timestamps | P1 |
| T36-002 | vss_timewarp_open | CREATE with TWrp context (snapshot token) | File opened from snapshot | P1 |
| T36-003 | vss_timewarp_read | Read from snapshot-opened file | Historical data returned | P1 |
| T36-004 | vss_timewarp_write | Write to snapshot-opened file | STATUS_ACCESS_DENIED (snapshot is read-only) | P1 |
| T36-005 | vss_no_snapshots | Enumerate snapshots on volume with none | Empty snapshot list returned | P1 |
| T36-006 | vss_invalid_token | TWrp with invalid snapshot token | STATUS_OBJECT_NAME_NOT_FOUND | P1 |

---

## T37: Notification (Session Closed) (4 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T37-001 | notif_session_closed_basic | Logoff triggers notification to other channels | SMB2_SERVER_TO_CLIENT_NOTIFICATION with NOTIFY_SESSION_CLOSED | P1 |
| T37-002 | notif_session_closed_dialect | Notification only sent to 3.1.1 channels | Pre-3.1.1 channels do not receive notification | P1 |
| T37-003 | notif_session_closed_before_files | Notification sent BEFORE closing files | Other channels can clean up | P2 |
| T37-004 | notif_capability_advertised | SMB2_GLOBAL_CAP_NOTIFICATIONS in negotiate | Capability bit 0x80 present for 3.1.1 | P1 |

---

## T38: Streams (8 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T38-001 | stream_create | Create named stream (file:stream) | Stream created | P0 |
| T38-002 | stream_read_write | Read/write to named stream | Data correct | P0 |
| T38-003 | stream_delete | Delete named stream | Stream removed, base file intact | P1 |
| T38-004 | stream_enumerate | FileStreamInformation query | All streams listed with sizes | P0 |
| T38-005 | stream_default_data | Access ::$DATA (default stream) | Equivalent to base file | P1 |
| T38-006 | stream_colon_parsing | Filename with colon separator | Stream name parsed correctly | P0 |
| T38-007 | stream_max_name | Maximum stream name length | Stream created or appropriate error | P2 |
| T38-008 | stream_share_flag | Share must have KSMBD_SHARE_FLAG_STREAMS | Streams work on flagged shares, fail otherwise | P1 |

---

## T39: Named Pipes / RPC (8 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T39-001 | pipe_open_srvsvc | Open \\pipe\\srvsvc | Pipe opened on IPC$ | P0 |
| T39-002 | pipe_open_wkssvc | Open \\pipe\\wkssvc | Pipe opened on IPC$ | P1 |
| T39-003 | pipe_open_samr | Open \\pipe\\samr | Pipe opened on IPC$ | P1 |
| T39-004 | pipe_open_lsarpc | Open \\pipe\\lsarpc | Pipe opened on IPC$ | P1 |
| T39-005 | pipe_netshareenum | NetShareEnum RPC via srvsvc | Share list returned | P0 |
| T39-006 | pipe_netservergetinfo | NetServerGetInfo RPC | Server info returned | P1 |
| T39-007 | pipe_read_write | Write RPC request, read response | Valid DCE/RPC exchange | P0 |
| T39-008 | pipe_transceive | FSCTL_PIPE_TRANSCEIVE for RPC | Request/response in one IOCTL | P0 |

---

## T40: SMB1 (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T40-001 | smb1_negotiate | SMB1 negotiate with NT LM 0.12 | Dialect selected, deprecation warning emitted | P1 |
| T40-002 | smb1_negotiate_lanman | SMB1 negotiate with "NT LANMAN 1.0" (smbclient format) | Both dialect strings recognized | P1 |
| T40-003 | smb1_session_setup | SMB1 SESSION_SETUP_ANDX | Session established | P1 |
| T40-004 | smb1_tree_connect | SMB1 TREE_CONNECT_ANDX | Tree connected | P1 |
| T40-005 | smb1_open_read_close | SMB1 NT_CREATE_ANDX, READ_ANDX, CLOSE | Basic file I/O | P1 |
| T40-006 | smb1_upgrade_to_smb2 | SMB1 negotiate then SMB2 upgrade | Wildcard dialect 0x02FF, smb1_conn=true | P0 |
| T40-007 | smb1_no_lock_and_read | SMB1 LOCK_AND_READ (opcode 0x13) | Command not available (CAP_LOCK_AND_READ removed) | P2 |
| T40-008 | smb1_deprecation_warning | SMB1 connection triggers deprecation | pr_warn_ratelimited message logged | P2 |
| T40-009 | smb1_andx_chain | SMB1 AndX command chaining | Chained commands processed, bounds checked | P1 |
| T40-010 | smb1_nt_transact | SMB1 NT_TRANSACT (IOCTL, NOTIFY, RENAME, QUOTA, CREATE) | Subcommands dispatched correctly | P2 |

---

## T41: Reparse Points (6 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T41-001 | reparse_set | FSCTL_SET_REPARSE_POINT | Reparse data set on file | P1 |
| T41-002 | reparse_get | FSCTL_GET_REPARSE_POINT | Reparse data retrieved | P1 |
| T41-003 | reparse_delete | FSCTL_DELETE_REPARSE_POINT | Reparse data removed | P1 |
| T41-004 | reparse_symlink_follow | Open symlink without OPEN_REPARSE_POINT | Symlink followed to target | P1 |
| T41-005 | reparse_symlink_open | Open symlink with OPEN_REPARSE_POINT | Symlink itself opened | P1 |
| T41-006 | reparse_tag_validation | Query FILE_ATTRIBUTE_REPARSE_POINT + ReparseTag | Correct tag returned | P1 |

---

## T42: Quota (4 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T42-001 | quota_query | QUERY_INFO with SMB2_O_INFO_QUOTA | Quota info returned | P2 |
| T42-002 | quota_set | SET_INFO with SMB2_O_INFO_QUOTA | Quota set | P2 |
| T42-003 | quota_enforce | Write beyond quota limit | STATUS_DISK_FULL | P2 |
| T42-004 | quota_nt_transact_smb1 | SMB1 NT_TRANSACT quota subcommand | Quota data returned | P2 |

---

## T43: Extended Attributes (6 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T43-001 | ea_create_buffer | Create file with EA buffer context | EAs set on file | P1 |
| T43-002 | ea_query_full | FileFullEaInformation query | All EAs returned | P1 |
| T43-003 | ea_set_full | FileFullEaInformation set | EAs modified | P1 |
| T43-004 | ea_delete | Set EA with zero-length value | EA deleted | P1 |
| T43-005 | ea_size_query | FileEaInformation (EaSize) | Correct total EA size including padding | P1 |
| T43-006 | ea_large | Set large EA (near max xattr size) | EA set or STATUS_EA_TOO_LARGE | P2 |

---

## T44: CREDITS (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T44-001 | credit_initial | Verify initial credit grant in negotiate | At least 1 credit granted | P0 |
| T44-002 | credit_request | Request additional credits | Credits granted up to limit | P0 |
| T44-003 | credit_charge_large | Large read/write charges multiple credits | CreditCharge field correctly calculated | P0 |
| T44-004 | credit_exhaustion | Use all credits without requesting more | Server connection not dropped, but requests queued | P1 |
| T44-005 | credit_smb2_02_no_large_mtu | SMB 2.0.2 credits without LARGE_MTU | Single-credit operations only, no underflow | P0 |
| T44-006 | credit_multicredit | Multi-credit request for large I/O | Credit charge matches data size | P1 |
| T44-007 | credit_sequence_window | Message ID within credit sequence window | Valid messages accepted, out-of-window rejected | P1 |
| T44-008 | credit_async_return | Async operation returns credits correctly | outstanding_async counter accurate | P1 |
| T44-009 | credit_zero_charge | CreditCharge=0 treated as 1 | Backward compatible behavior | P1 |
| T44-010 | credit_max_limit | Request excessive credits | Capped at server max | P1 |

---

## T45: STRESS and Concurrency (12 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T45-001 | stress_100_connections | 100 concurrent TCP connections | All connections served | P1 |
| T45-002 | stress_1000_files | Create 1000 files concurrently | All files created without error | P1 |
| T45-003 | stress_rapid_open_close | Rapid open/close cycles (10000 iterations) | No handle leaks, no crashes | P0 |
| T45-004 | stress_parallel_rw | 10 clients reading/writing same file regions | Data integrity with proper locking | P1 |
| T45-005 | stress_compound_flood | 100 compound requests per second | All processed without timeout | P1 |
| T45-006 | stress_session_flood | Rapid session setup/teardown (1000 cycles) | No session ID leaks | P1 |
| T45-007 | stress_lock_contention | 10 clients competing for same lock range | All eventually acquire lock, no deadlock | P1 |
| T45-008 | stress_notify_flood | 100 concurrent CHANGE_NOTIFY watches | All watches active, events delivered | P2 |
| T45-009 | stress_oplock_storm | 10 clients triggering oplock breaks simultaneously | All breaks processed, no hang | P1 |
| T45-010 | stress_max_connections_per_ip | Exceed max connections from single IP | Connection rejected at limit | P1 |
| T45-011 | stress_durable_scavenger | 100 durable handles, verify scavenger cleans up | Expired handles removed | P2 |
| T45-012 | stress_disconnect_reconnect | Rapid disconnect/reconnect cycles | Server stable, no resource leaks | P1 |

---

## T46: REGRESSION (12 tests)

These tests target specific bugs that were fixed in the codebase.

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T46-001 | regr_credit_underflow_202 | SMB 2.0.2 credit tracking (non-LARGE_MTU) | No credit underflow in smb2misc.c | P0 |
| T46-002 | regr_validate_neg_client_guid | FSCTL_VALIDATE_NEGOTIATE copies ClientGUID for all SMB2 | ClientGUID/cli_sec_mode set for >= SMB2.0.2 (not just >) | P0 |
| T46-003 | regr_smb1_dialect_mismatch | SMB1 "NT LANMAN 1.0" recognized | No dialect mismatch on smbclient | P1 |
| T46-004 | regr_smb1_upgrade_wildcard | SMB1 upgrade uses dialect 0x02FF | Not specific dialect, avoiding IO_TIMEOUT | P1 |
| T46-005 | regr_conn_vals_leak | Negotiate path frees conn->vals before realloc | No memory leak on re-negotiate | P1 |
| T46-006 | regr_lock_fl_end_offbyone | Lock fl_end = fl_start + length - 1 (inclusive) | No off-by-one in lock range | P0 |
| T46-007 | regr_lock_offset_max | Lock beyond OFFSET_MAX handled internally | No vfs_lock_file call for huge ranges | P1 |
| T46-008 | regr_compound_err_cascade | Compound error cascade only from CREATE | Non-CREATE errors do not cascade | P0 |
| T46-009 | regr_delete_on_close_multi_handle | DOC with other handles open does NOT unlink | File persists until last handle closed | P0 |
| T46-010 | regr_dot_dotdot_reset | RESTART_SCANS resets dot_dotdot counters | Second scan includes "." and ".." | P0 |
| T46-011 | regr_write_eof_sentinel | Write offset 0xFFFFFFFFFFFFFFFF not rejected as negative | Recognized as append-to-EOF | P0 |
| T46-012 | regr_flush_file_closed | Flush of nonexistent FID returns FILE_CLOSED | Not INVALID_HANDLE | P0 |

---

## T47: ERROR HANDLING (10 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T47-001 | err_invalid_command | Unknown SMB2 command code | STATUS_INVALID_PARAMETER | P0 |
| T47-002 | err_truncated_header | Packet shorter than SMB2 header | Connection terminated gracefully | P0 |
| T47-003 | err_bad_protocol_magic | Wrong protocol magic bytes | Connection rejected | P0 |
| T47-004 | err_structure_size_mismatch | StructureSize field incorrect | STATUS_INVALID_PARAMETER | P1 |
| T47-005 | err_buffer_overflow_response | Response larger than negotiated MaxTransactSize | STATUS_BUFFER_OVERFLOW with partial data | P1 |
| T47-006 | err_invalid_tree_id | Operation with invalid TreeId | STATUS_NETWORK_NAME_DELETED | P0 |
| T47-007 | err_invalid_session_id | Operation with invalid SessionId | STATUS_USER_SESSION_DELETED | P0 |
| T47-008 | err_server_shutdown | Operations during server shutdown | Graceful error response, no crash | P1 |
| T47-009 | err_out_of_memory | Simulate memory pressure (if possible) | STATUS_INSUFFICIENT_RESOURCES | P2 |
| T47-010 | err_readonly_filesystem | Write on read-only filesystem | STATUS_MEDIA_WRITE_PROTECTED | P1 |

---

## T48: TRANSPORT (8 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T48-001 | transport_tcp_connect | Basic TCP connection on port 445 | Connection established | P0 |
| T48-002 | transport_tcp_keepalive | TCP keepalive handling | Connection maintained | P1 |
| T48-003 | transport_tcp_disconnect | Clean TCP disconnect | Resources freed | P0 |
| T48-004 | transport_tcp_reset | TCP reset (RST) during operation | Connection cleaned up, no crash | P1 |
| T48-005 | transport_rdma_connect | RDMA connection (if available) | SMB Direct session established | P2 |
| T48-006 | transport_rdma_read_write | File I/O over RDMA | Data transferred via RDMA | P2 |
| T48-007 | transport_netlink_ipc | Kernel-userspace netlink communication | User auth and share lookup work | P0 |
| T48-008 | transport_max_packet | Send packet at MaxTransactSize | Accepted and processed | P1 |

---

## T49: ENCODING (8 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T49-001 | encoding_utf16le_basic | ASCII filename in UTF-16LE | Correct encoding/decoding | P0 |
| T49-002 | encoding_utf16le_unicode | Non-ASCII Unicode filename | Characters preserved | P0 |
| T49-003 | encoding_utf16le_surrogate | Supplementary plane characters (surrogate pairs) | Correct handling | P1 |
| T49-004 | encoding_case_folding | Case-insensitive name comparison | Correct Unicode case folding | P1 |
| T49-005 | encoding_ndr_marshalling | NDR marshalling for RPC | Correct wire format | P1 |
| T49-006 | encoding_asn1_spnego | ASN.1 SPNEGO token parsing | Valid token accepted, malformed rejected | P1 |
| T49-007 | encoding_path_separator | Backslash to forward slash conversion | Paths normalized correctly | P1 |
| T49-008 | encoding_null_in_name | Embedded NUL in filename | Rejected (name truncated at NUL) | P1 |

---

## T50: RSVD - Shared Virtual Disk (4 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T50-001 | rsvd_query_support | FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT | Capability response returned | P2 |
| T50-002 | rsvd_sync_tunnel | FSCTL_SVHDX_SYNC_TUNNEL_REQUEST | Synchronous operation handled | P2 |
| T50-003 | rsvd_async_tunnel | FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST | Async operation handled | P2 |
| T50-004 | rsvd_invalid_operation | Invalid tunnel operation code | Error returned | P2 |

---

## T51: MANAGEMENT (6 tests)

| ID | Name | Description | Expected Result | Pri |
|----|------|-------------|-----------------|-----|
| T51-001 | mgmt_user_add | Add user via ksmbdctl | User available for authentication | P0 |
| T51-002 | mgmt_user_remove | Remove user via ksmbdctl | User rejected on next auth attempt | P1 |
| T51-003 | mgmt_share_add | Add share via ksmbd.conf | Share available for tree connect | P0 |
| T51-004 | mgmt_share_remove | Remove share from config and reload | Share returns BAD_NETWORK_NAME | P1 |
| T51-005 | mgmt_debug_control | Enable/disable debug components | Debug output toggled | P2 |
| T51-006 | mgmt_server_stop | ksmbdctl stop | Server shuts down gracefully | P0 |

---

## B01: THROUGHPUT BENCHMARKS (6 benchmarks)

| ID | Name | Description | Measurement |
|----|------|-------------|-------------|
| B01-001 | bench_seq_read_1m | Sequential read, 1MB blocks | MB/s, latency p50/p99 |
| B01-002 | bench_seq_write_1m | Sequential write, 1MB blocks | MB/s, latency p50/p99 |
| B01-003 | bench_seq_read_64k | Sequential read, 64KB blocks | MB/s, IOPS |
| B01-004 | bench_seq_write_64k | Sequential write, 64KB blocks | MB/s, IOPS |
| B01-005 | bench_random_read_4k | Random read, 4KB blocks | IOPS, latency p50/p99 |
| B01-006 | bench_random_write_4k | Random write, 4KB blocks | IOPS, latency p50/p99 |

---

## B02: LATENCY BENCHMARKS (4 benchmarks)

| ID | Name | Description | Measurement |
|----|------|-------------|-------------|
| B02-001 | bench_open_close_latency | Open + close cycle latency | microseconds p50/p99/p999 |
| B02-002 | bench_create_delete_latency | Create + delete cycle latency | microseconds p50/p99/p999 |
| B02-003 | bench_getattr_latency | QUERY_INFO (basic) latency | microseconds p50/p99/p999 |
| B02-004 | bench_small_read_latency | 1-byte read latency (metadata path) | microseconds p50/p99/p999 |

---

## B03: METADATA BENCHMARKS (4 benchmarks)

| ID | Name | Description | Measurement |
|----|------|-------------|-------------|
| B03-001 | bench_readdir_100 | Enumerate 100-file directory | ms per enumeration |
| B03-002 | bench_readdir_10000 | Enumerate 10000-file directory | ms per enumeration |
| B03-003 | bench_stat_storm | 10000 QUERY_INFO requests in burst | ops/sec |
| B03-004 | bench_create_storm | 10000 CREATE+CLOSE in burst | ops/sec |

---

## B04: SCALABILITY BENCHMARKS (4 benchmarks)

| ID | Name | Description | Measurement |
|----|------|-------------|-------------|
| B04-001 | bench_connections_scaling | Throughput vs. number of connections (1-100) | MB/s per connection count |
| B04-002 | bench_session_scaling | Session setup rate (concurrent) | sessions/sec |
| B04-003 | bench_file_handle_scaling | Throughput vs. open file handles (10-10000) | MB/s, handle count |
| B04-004 | bench_lock_contention_scaling | Lock acquisition rate under contention | locks/sec vs. contenders |

---

## B05: OVERHEAD BENCHMARKS (4 benchmarks)

| ID | Name | Description | Measurement |
|----|------|-------------|-------------|
| B05-001 | bench_signing_overhead | Throughput with vs. without signing | % overhead |
| B05-002 | bench_encryption_overhead | Throughput with vs. without encryption | % overhead |
| B05-003 | bench_compression_overhead | Throughput with vs. without compression | % overhead, compression ratio |
| B05-004 | bench_quic_vs_tcp | Throughput QUIC vs. TCP | MB/s comparison |

---

## Summary Statistics

| Category | Count | P0 | P1 | P2 |
|----------|-------|-----|-----|-----|
| T01: NEGOTIATE | 20 | 9 | 11 | 0 |
| T02: SESSION | 35 | 9 | 22 | 4 |
| T03: TREE_CONNECT | 18 | 5 | 13 | 0 |
| T04: CREATE | 60 | 19 | 31 | 10 |
| T05: READ | 18 | 8 | 5 | 5 |
| T06: WRITE | 22 | 9 | 11 | 2 |
| T07: CLOSE | 10 | 6 | 4 | 0 |
| T08: FLUSH | 10 | 4 | 6 | 0 |
| T09: DIRECTORY | 22 | 5 | 10 | 7 |
| T10: QUERY_INFO (File) | 18 | 3 | 9 | 6 |
| T11: QUERY_INFO (FS) | 8 | 3 | 3 | 2 |
| T12: SET_INFO + Timestamps | 16 | 4 | 10 | 2 |
| T13: LOCK | 32 | 14 | 14 | 4 |
| T14: OPLOCK | 16 | 7 | 7 | 2 |
| T15: LEASE | 18 | 7 | 10 | 1 |
| T16: SHAREMODE | 8 | 3 | 5 | 0 |
| T17: COMPOUND | 15 | 6 | 9 | 0 |
| T18: ASYNC + CANCEL | 10 | 5 | 5 | 0 |
| T19: IOCTL - Validate | 6 | 2 | 4 | 0 |
| T20: IOCTL - Network | 4 | 1 | 0 | 3 |
| T21: IOCTL - Copy Chunk | 8 | 3 | 5 | 0 |
| T22: IOCTL - Sparse | 8 | 4 | 4 | 0 |
| T23: IOCTL - Compression | 6 | 0 | 4 | 2 |
| T24: IOCTL - Pipes | 6 | 1 | 3 | 2 |
| T25: IOCTL - Misc | 14 | 0 | 1 | 13 |
| T26: NOTIFY | 15 | 3 | 11 | 1 |
| T27: DURABLE v1 | 10 | 3 | 6 | 1 |
| T28: DURABLE v2 | 12 | 4 | 6 | 2 |
| T29: RESILIENT | 8 | 0 | 6 | 2 |
| T30: ACL | 12 | 4 | 6 | 2 |
| T31: DELETE_ON_CLOSE | 10 | 6 | 3 | 1 |
| T32: COMPRESSION | 12 | 3 | 8 | 1 |
| T33: QUIC | 10 | 4 | 5 | 1 |
| T34: FRUIT | 10 | 0 | 5 | 5 |
| T35: DFS | 6 | 0 | 3 | 3 |
| T36: VSS | 6 | 0 | 6 | 0 |
| T37: NOTIFICATION | 4 | 0 | 3 | 1 |
| T38: STREAMS | 8 | 3 | 4 | 1 |
| T39: PIPES/RPC | 8 | 4 | 4 | 0 |
| T40: SMB1 | 10 | 1 | 6 | 3 |
| T41: REPARSE | 6 | 0 | 6 | 0 |
| T42: QUOTA | 4 | 0 | 0 | 4 |
| T43: EA | 6 | 0 | 5 | 1 |
| T44: CREDITS | 10 | 3 | 7 | 0 |
| T45: STRESS | 12 | 1 | 9 | 2 |
| T46: REGRESSION | 12 | 7 | 5 | 0 |
| T47: ERROR HANDLING | 10 | 4 | 4 | 2 |
| T48: TRANSPORT | 8 | 3 | 3 | 2 |
| T49: ENCODING | 8 | 2 | 6 | 0 |
| T50: RSVD | 4 | 0 | 0 | 4 |
| T51: MANAGEMENT | 6 | 3 | 2 | 1 |
| **TOTAL TESTS** | **543** | **175** | **267** | **101** |
| B01-B05: BENCHMARKS | 22 | - | - | - |
| **GRAND TOTAL** | **565** | | | |

---

## Priority Definitions

- **P0 (175 tests)**: Must-pass for any release. Core protocol correctness, security boundaries, data integrity. Failures here block release.
- **P1 (267 tests)**: Important for quality. Edge cases, feature completeness, interoperability. Should pass before GA.
- **P2 (101 tests)**: Nice-to-have, regression guards, advanced features. May be deferred.

## Test Dependencies

Some test categories have ordering dependencies:

1. **T01 NEGOTIATE** must pass before any other category
2. **T02 SESSION** depends on T01
3. **T03 TREE_CONNECT** depends on T02
4. **T04-T49** all depend on T01+T02+T03 (basic session/tree)
5. **T13 LOCK** should run after T04 CREATE and T05/T06 READ/WRITE
6. **T17 COMPOUND** should run after individual command tests
7. **T27-T29 DURABLE/RESILIENT** depend on T14/T15 OPLOCK/LEASE
8. **B01-B05 BENCHMARKS** should run after all functional tests pass

## Mapping to Source Code Edge Cases

The 501 edge cases from source analysis map to test categories as follows:

- EDGE-001 through EDGE-112: Primarily T04 (CREATE), T13 (LOCK), T14-T16 (OPLOCK/LEASE/SHAREMODE)
- EDGE-113 through EDGE-181: T13 (LOCK) -- lock flag combinations, ranges, replay, rollback
- EDGE-182 through EDGE-197: T14/T15 (OPLOCK/LEASE) -- break sequences, timeouts, levels
- EDGE-198 through EDGE-227: T05 (READ) -- EOF, access, overflow, channels
- EDGE-228 through EDGE-236: T07/T08 (CLOSE/FLUSH) -- FID validation, access checks
- EDGE-237 through EDGE-267: T06 (WRITE) -- sentinel, append, overflow, channel sequence
- EDGE-268 through EDGE-320: T09/T10/T11/T12 (DIR/QUERY/SET) -- info levels, wildcards, timestamps
- EDGE-321 through EDGE-380: T19-T25 (IOCTL/FSCTL) -- all FSCTL codes, buffer validation
- EDGE-381 through EDGE-420: T01/T02/T03 (NEGOTIATE/SESSION/TREE) -- contexts, auth, encryption
- EDGE-421 through EDGE-460: T17/T18 (COMPOUND/ASYNC) -- FID propagation, cascade, cancel
- EDGE-461 through EDGE-501: T26-T31 (NOTIFY/DURABLE/ACL/DOC) -- watches, reconnect, permissions

Additional test cases beyond the 501 edge cases come from:
- smbtorture gap analysis (tests not covered by existing Samba smbtorture)
- ksmbd-specific features (T32-T43: compression, QUIC, fruit, DFS, VSS, etc.)
- Stress and benchmark coverage (T44-T49, B01-B05)
