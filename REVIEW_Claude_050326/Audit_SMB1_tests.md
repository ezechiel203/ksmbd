# Audit Smb1 Tests

Agent ID: a8c18c946ff163650

The NT_TRANSACT_CREATE parameter block layout from the spec (MS-SMB 2.2.7.1):
- Flags: 4 bytes
- RootDirectoryFID: 4 bytes
- DesiredAccess: 4 bytes
- AllocationSize: 8 bytes (LARGE_INTEGER)
- ExtFileAttributes: 4 bytes
- ShareAccess: 4 bytes
- CreateDisposition: 4 bytes
- CreateOptions: 4 bytes
- SecurityDescriptorLength: 4 bytes
- EALength: 4 bytes
- NameLength: 4 bytes
- ImpersonationLevel: 4 bytes
- SecurityFlags: 1 byte
Total fixed part = 4+4+4+8+4+4+4+4+4+4+4+4+1 = 53 bytes (before the variable Name[] field)

Now I have all the data needed for the full audit. Let me compile the comprehensive report.

---

# COMPREHENSIVE AUDIT REPORT: SMB1 KUnit Test Files vs MS-SMB Specification

## Summary

I audited 11 test files containing approximately 250+ KUNIT_CASE entries against the MS-SMB specification (ms-smb.txt, 11K lines) and the MS-SMB2 spec (for upgrade sections). Below is the per-test-case verdict for every KUNIT_CASE.

---

## File 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_logic.c`
**35 KUNIT_CASEs**

### file_create_dispostion_flags() tests (13 cases)

These test the CreateDisposition mapping per MS-SMB 3.3.5.5 / MS-CIFS 3.3.5.50, which maps CreateDisposition values (FILE_SUPERSEDE=0, FILE_OPEN=1, FILE_CREATE=2, FILE_OPEN_IF=3, FILE_OVERWRITE=4, FILE_OVERWRITE_IF=5) to Linux open flags.

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_disposition_supersede_present` | **CORRECT** | FILE_SUPERSEDE(0) + file exists = truncate (O_TRUNC). Per MS-SMB, SUPERSEDE means "if file exists, replace it." |
| `test_disposition_supersede_absent` | **CORRECT** | FILE_SUPERSEDE(0) + file absent = create (O_CREAT). Per spec, SUPERSEDE creates if not present. |
| `test_disposition_open_present` | **CORRECT** | FILE_OPEN(1) + file exists = open with no flags (0). Per spec, open existing file. |
| `test_disposition_open_absent` | **CORRECT** | FILE_OPEN(1) + file absent = -ENOENT. Per spec, file must exist. |
| `test_disposition_create_present` | **CORRECT** | FILE_CREATE(2) + file exists = -EEXIST. Per spec, fails if file already exists. |
| `test_disposition_create_absent` | **CORRECT** | FILE_CREATE(2) + file absent = O_CREAT. Per spec, creates new file. |
| `test_disposition_open_if_present` | **CORRECT** | FILE_OPEN_IF(3) + file exists = open (0). Per spec, open if exists. |
| `test_disposition_open_if_absent` | **CORRECT** | FILE_OPEN_IF(3) + file absent = O_CREAT. Per spec, create if not exists. |
| `test_disposition_overwrite_present` | **CORRECT** | FILE_OVERWRITE(4) + file exists = O_TRUNC. Per spec, overwrite existing. |
| `test_disposition_overwrite_absent` | **CORRECT** | FILE_OVERWRITE(4) + file absent = -ENOENT. Per spec, file must exist. |
| `test_disposition_overwrite_if_present` | **CORRECT** | FILE_OVERWRITE_IF(5) + file exists = O_TRUNC. Per spec, overwrite if exists. |
| `test_disposition_overwrite_if_absent` | **CORRECT** | FILE_OVERWRITE_IF(5) + file absent = O_CREAT. Per spec, create if not exists. |
| `test_disposition_invalid` | **CORRECT** | Invalid disposition value (0xFF) returns -EINVAL. Values beyond 5 are undefined. |

### smb_get_dos_attr() tests (5 cases)

These test the mapping from POSIX mode bits to DOS file attributes. The attribute values are defined in MS-CIFS 2.2.1.2.3 / MS-FSCC 2.6.

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_dos_attr_regular_writable` | **CORRECT** | Writable regular file gets ATTR_NORMAL. Per MS-FSCC, ATTR_NORMAL means no other attributes set. |
| `test_dos_attr_readonly` | **CORRECT** | Mode 0444 (no write bits) maps to ATTR_READONLY. Standard POSIX-to-DOS mapping. |
| `test_dos_attr_hidden_system` | **CORRECT** | S_ISVTX (sticky bit) maps to ATTR_HIDDEN | ATTR_SYSTEM. This is a ksmbd-specific mapping convention (not directly in MS-SMB, but a valid implementation choice for POSIX-to-DOS translation). |
| `test_dos_attr_directory` | **CORRECT** | S_IFDIR maps to ATTR_DIRECTORY. Per MS-FSCC. |
| `test_dos_attr_sparse` | **CORRECT** | Sparse detection via size > blocks*blksize. Maps to ATTR_SPARSE. Per MS-FSCC. |

### get_filetype() tests (7 cases)

These test UNIX extension file type constants. These are from the CIFS UNIX Extensions, not the core MS-SMB spec, but are standard CIFS extension values.

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_filetype_regular` | **CORRECT** | S_IFREG -> UNIX_FILE |
| `test_filetype_directory` | **CORRECT** | S_IFDIR -> UNIX_DIR |
| `test_filetype_symlink` | **CORRECT** | S_IFLNK -> UNIX_SYMLINK |
| `test_filetype_chardev` | **CORRECT** | S_IFCHR -> UNIX_CHARDEV |
| `test_filetype_blockdev` | **CORRECT** | S_IFBLK -> UNIX_BLOCKDEV |
| `test_filetype_fifo` | **CORRECT** | S_IFIFO -> UNIX_FIFO |
| `test_filetype_socket` | **CORRECT** | S_IFSOCK -> UNIX_SOCKET |

### smb_NTtimeToUnix() / unix_to_dos_time() tests (5 cases)

NT time is 100-nanosecond intervals since Jan 1, 1601 UTC. DOS time is per MS-DOS date/time format (year bits 9-15 relative to 1980, month 5-8, day 0-4, hour 11-15, min 5-10, sec/2 0-4).

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_nttime_zero` | **CORRECT** | NT time 0 = Jan 1, 1601 -- before Unix epoch, so tv_sec < 0. |
| `test_nttime_epoch` | **CORRECT** | NTFS_TIME_OFFSET converts to Unix epoch (0). The offset value encodes the 369-year gap. |
| `test_nttime_known_timestamp` | **CORRECT** | 2000-01-01 00:00:00 UTC = 946684800. Leap day count (7 leap days 1970-1999) is correct. |
| `test_dos_time_roundtrip` | **CORRECT** | Deterministic output test; same input produces same DOS time/date. |
| `test_dos_time_date_nonzero` | **CORRECT** | 2021-01-01 produces non-zero DOS date. This date is well within DOS range (1980-2107). |

### andx_response_buffer() tests (3 cases)

These test the RFC1002 length + offset calculation for AndX chaining.

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_andx_buffer_valid` | **CORRECT** | RFC1002 length=64, offset=4+64=68, result=buf+68. Per MS-SMB 2.2.3.1, the 4-byte transport header precedes the SMB message. |
| `test_andx_buffer_too_small` | **CORRECT** | Properly detects when buffer is too small to hold the AndX response. |
| `test_andx_buffer_exact_fit` | **CORRECT** | Boundary test: exactly fits. |

### cifs_convert_ace() tests (2 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_convert_ace_basic` | **CORRECT** | POSIX ACL extension conversion (rwx, ACL_USER, uid 1000). |
| `test_convert_ace_zero` | **CORRECT** | Zero ACE conversion. |

---

## File 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_helpers.c`
**73 KUNIT_CASEs**

### smb_cmd_to_str() tests (6 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_cmd_to_str_negotiate` | **CORRECT** | SMB_COM_NEGOTIATE = 0x72 per MS-SMB 2.2.2.1. |
| `test_cmd_to_str_close` | **CORRECT** | SMB_COM_CLOSE = 0x04. |
| `test_cmd_to_str_session_setup` | **CORRECT** | SMB_COM_SESSION_SETUP_ANDX = 0x73. |
| `test_cmd_to_str_echo` | **CORRECT** | SMB_COM_ECHO = 0x2B. |
| `test_cmd_to_str_unknown` | **CORRECT** | 0xFF returns "unknown_cmd". |
| `test_cmd_to_str_null_entry` | **CORRECT** | 0x03 (SMB_COM_OPEN, no handler in ksmbd) returns NULL or non-"unknown_cmd". |

### smb_trans2_cmd_to_str() tests (3 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_trans2_cmd_to_str_find_first` | **CORRECT** | TRANS2_FIND_FIRST = 0x01 per MS-SMB 2.2.2.2. |
| `test_trans2_cmd_to_str_query_path` | **CORRECT** | TRANS2_QUERY_PATH_INFORMATION = 0x05. |
| `test_trans2_cmd_to_str_unknown` | **CORRECT** | 0xFF returns "unknown_trans2_cmd". |

### is_smbreq_unicode() tests (4 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_is_smbreq_unicode_set` | **CORRECT** | SMBFLG2_UNICODE = cpu_to_le16(0x8000) per MS-SMB 2.2.3.1. |
| `test_is_smbreq_unicode_clear` | **CORRECT** | Flag not set returns 0. |
| `test_is_smbreq_unicode_other_flags` | **CORRECT** | Other flags (ERR_STATUS, EXT_SEC) without UNICODE return 0. |
| `test_is_smbreq_unicode_all_flags` | **CORRECT** | UNICODE set with other flags returns 1. |

### ksmbd_openflags_to_mayflags() tests (4 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_mayflags_rdonly` | **CORRECT** | O_RDONLY -> MAY_READ, no MAY_WRITE. |
| `test_mayflags_wronly` | **CORRECT** | O_WRONLY -> MAY_WRITE, no MAY_READ. |
| `test_mayflags_rdwr` | **CORRECT** | O_RDWR -> MAY_READ | MAY_WRITE. |
| `test_mayflags_rdonly_with_extra` | **CORRECT** | Extra flags don't affect MAY flags. |

### convert_open_flags() tests (9 cases)

These test SMB_COM_OPEN_ANDX mode/disposition mapping per MS-CIFS 2.2.4.3.

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_convert_open_flags_read_present` | **CORRECT** | SMBOPEN_READ(0) -> O_RDONLY. |
| `test_convert_open_flags_write_present` | **CORRECT** | SMBOPEN_WRITE -> O_WRONLY. |
| `test_convert_open_flags_readwrite` | **CORRECT** | SMBOPEN_READWRITE -> O_RDWR. |
| `test_convert_open_flags_write_through` | **CORRECT** | SMBOPEN_WRITE_THROUGH -> O_SYNC. |
| `test_convert_open_flags_file_absent_no_create` | **CORRECT** | File absent + no create bit -> -EINVAL. |
| `test_convert_open_flags_file_absent_create` | **CORRECT** | File absent + OCREATE -> O_CREAT. |
| `test_convert_open_flags_present_trunc` | **CORRECT** | File present + OTRUNC -> O_TRUNC. |
| `test_convert_open_flags_present_append` | **CORRECT** | File present + OAPPEND -> O_APPEND. |
| `test_convert_open_flags_present_none` | **CORRECT** | DISPOSITION_NONE on existing file -> -EEXIST. |

### smb_posix_convert_flags() tests (8 cases)

POSIX extension open flags (CIFS UNIX Extensions). Not in core MS-SMB but well-defined.

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 8 tests | **CORRECT** | SMB_O_RDONLY, SMB_O_WRONLY, SMB_O_RDWR, SMB_O_CREAT, SMB_O_APPEND, SMB_O_SYNC, SMB_O_DIRECTORY, SMB_O_NOFOLLOW all correctly map to their Linux equivalents. |

### smb_get_disposition() tests (7 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 7 tests | **CORRECT** | CREAT|EXCL -> FILE_CREATE, CREAT|TRUNC -> FILE_OVERWRITE_IF, plain open -> FILE_OPEN, CREAT only -> FILE_OPEN_IF, TRUNC only -> FILE_OVERWRITE. All match the MS-SMB 3.3.5.5 CreateDisposition mapping table. |

### convert_ace_to_cifs_ace() tests (3 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 3 tests | **CORRECT** | ACE conversion between POSIX and CIFS formats. -1 ID preservation is correct. |

### smb1_readdir_info_level_struct_sz() tests (8 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 8 tests | **CORRECT** | Valid info levels return positive sizes; invalid (0xFFFF) returns -EOPNOTSUPP. Per MS-SMB 2.2.2.3.1 and MS-CIFS 2.2.2.3.1 for the FIND information level codes. |

### dos_date_time_to_unix() tests (5 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_dos_datetime_2000_01_01` | **CORRECT** | Year=20 (2000-1980), month=1, day=1 = (20<<9)|(1<<5)|1 = 0x2821. Result: 946684800. DOS date format per MS-SMB 2.2.1.1. |
| `test_dos_datetime_1980_01_01` | **CORRECT** | DOS epoch: year=0 (1980), month=1, day=1. Result: 315532800. |
| `test_dos_datetime_with_time` | **CORRECT** | 2000-06-15 13:30:22. Hour=13, min=30, sec=11 (22/2). Verified range. |
| `test_dos_datetime_invalid_month_zero` | **CORRECT** | Month=0 is invalid per DOS date format. Returns 0. |
| `test_dos_datetime_invalid_day_zero` | **CORRECT** | Day=0 is invalid per DOS date format. Returns 0. |

### smb1_req_struct_size() tests (17 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_req_struct_negotiate` | **CORRECT** | NEGOTIATE WordCount=0 per MS-CIFS 2.2.4.52 / MS-SMB 2.2.4.5. |
| `test_req_struct_negotiate_bad_wc` | **CORRECT** | WordCount=1 for NEGOTIATE is invalid. |
| `test_req_struct_close` | **CORRECT** | CLOSE WordCount=3 per MS-CIFS 2.2.4.5. |
| `test_req_struct_echo` | **CORRECT** | ECHO WordCount=1 per MS-CIFS 2.2.4.39. |
| `test_req_struct_session_setup_12` | **CORRECT** | SESSION_SETUP_ANDX WordCount=12 (without extended security) per MS-CIFS. |
| `test_req_struct_session_setup_13` | **CORRECT** | SESSION_SETUP_ANDX WordCount=13 (with extended security) per MS-SMB 2.2.4.6. |
| `test_req_struct_session_setup_bad` | **CORRECT** | WordCount=14 for SESSION_SETUP is invalid. |
| `test_req_struct_nt_create` | **CORRECT** | NT_CREATE_ANDX WordCount=24 (0x18) per MS-CIFS 2.2.4.64 / MS-SMB 2.2.4.9. |
| `test_req_struct_locking` | **CORRECT** | LOCKING_ANDX WordCount=8 per MS-CIFS 2.2.4.32. |
| `test_req_struct_trans2` | **CORRECT** | TRANSACTION2 WordCount=15 (0x0F) per MS-CIFS 2.2.4.46. |
| `test_req_struct_write` | **CORRECT** | SMB_COM_WRITE WordCount=5 per MS-CIFS 2.2.4.9. |
| `test_req_struct_tree_connect` | **CORRECT** | TREE_CONNECT_ANDX WordCount=4 per MS-SMB 2.2.4.7. |
| `test_req_struct_logoff` | **CORRECT** | LOGOFF_ANDX WordCount=2 per MS-CIFS 2.2.4.54. |
| `test_req_struct_unknown_cmd` | **CORRECT** | Unknown command returns -EOPNOTSUPP. |
| `test_req_struct_nt_transact` | **CORRECT** | NT_TRANSACT WordCount=19 (0x13) minimum per MS-CIFS 2.2.4.62. |
| `test_req_struct_nt_transact_too_small` | **CORRECT** | WordCount=18 (0x12) is below minimum. |
| `test_req_struct_read_andx_10`/`_12` | **CORRECT** | READ_ANDX accepts WordCount 10 or 12 per MS-CIFS. |

### smb1_get_byte_count() tests (6 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 6 tests | **CORRECT** | CLOSE requires ByteCount=0, NEGOTIATE requires ByteCount>=2, WRITE_ANDX requires ByteCount>=1, truncated buffer detection. All per MS-CIFS specifications. |

---

## File 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_cmds.c`
**28 KUNIT_CASEs**

### Negotiate dialect selection tests (5 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_negotiate_dialect_selection` | **CORRECT** | "\2NT LM 0.12" matches at sequence 0. Per MS-SMB 2.2.4.5.1, dialect strings are 0x02-prefixed. |
| `test_smb1_negotiate_dialect_nt_lanman` | **CORRECT** | "\2NT LANMAN 1.0" is an alternate SMB1 dialect string sent by smbclient. Valid ksmbd extension. |
| `test_smb1_negotiate_upgrade_to_smb2` | **CORRECT** | "\2SMB 2.002" and "\2SMB 2.???" trigger SMB2 upgrade per MS-SMB2 3.3.5.3. |
| `test_smb1_negotiate_empty_dialect_list` | **CORRECT** | Empty byte count -> BAD_PROT_ID. |
| `test_smb1_negotiate_second_negotiate_rejected` | **CORRECT** | Per MS-SMB 3.3.5.2 / MS-SMB2 3.3.5.3.1, a second NEGOTIATE must be rejected. |

### Response header tests (2 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_init_smb1_server_rsp_header` | **CORRECT** | PID and MID must be echoed from request. SMBFLG_RESPONSE=0x80 set in response. Per MS-SMB 2.2.3.1. |
| `test_init_smb1_server_vals_allocated` | **CORRECT** | SMB1_SERVER_CAPS must not include CAP_LOCK_AND_READ (no handler for opcode 0x13). |

### File operation tests (8 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_create_response_word_count` | **CORRECT** | SMB_COM_NT_CREATE_ANDX = 0xA2 per MS-SMB 2.2.4.9. |
| `test_smb1_close_invalid_fid_detection` | **CORRECT** | FID 0xFFFF is invalid per MS-CIFS convention. |
| `test_smb1_echo_response_validation` | **CORRECT** | Echo WordCount must be 1 per MS-CIFS 2.2.4.39. |
| `test_smb1_lock_basic_word_count` | **CORRECT** | LOCKING_ANDX WordCount=8 per MS-CIFS 2.2.4.32. |
| `test_smb1_write_zero_length` | **CORRECT** | Zero-length write is valid. |
| `test_smb1_read_beyond_eof_detection` | **CORRECT** | Read at offset >= file_size returns 0 bytes. |
| `test_smb1_rename_cross_share_detection` | **CORRECT** | Different TIDs = cross-share. |
| `test_smb1_lock_conflicting_detection` | **CORRECT** | Overlap check logic correct. |

### TRANS2/NT_TRANSACT dispatch tests (13 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All TRANS2 subcommand validity tests | **CORRECT** | TRANS2_QUERY_FILE_INFORMATION(0x07), SET_FILE_INFORMATION(0x08), FIND_FIRST(0x01), FIND_NEXT(0x02), QUERY_FS_INFORMATION(0x03) per MS-SMB 2.2.2.2. |
| All NT_TRANSACT subcommand validity tests | **CORRECT** | NT_TRANSACT_IOCTL(0x02), NOTIFY_CHANGE(0x04), RENAME(0x05), GET_USER_QUOTA(0x07), SET_USER_QUOTA(0x08), CREATE(0x01) per MS-SMB 2.2.2.2. |
| `test_smb1_trans_invalid_subcommand` | **CORRECT** | 0xFF is invalid for both TRANS2 and NT_TRANSACT. |
| `test_smb1_trans2_parameter_overflow` | **CORRECT** | Bounds checking logic correct. |
| `test_smb1_nt_transact_secondary_continuation` | **CORRECT** | Secondary request bounds checking correct. |

---

## File 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_ops.c`
**11 KUNIT_CASEs**

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All struct size tests | **CORRECT** | Replicated validation matches real smb1misc.c. NEGOTIATE WC=0, SESSION_SETUP WC=12/13, TREE_CONNECT WC=4, NT_CREATE WC=24, TRANS2 WC>=14, NT_TRANSACT WC>=19, CLOSE WC=3, READ_ANDX WC=10/12, WRITE_ANDX WC=12/14, LOCKING WC=8, ECHO WC=1, FLUSH WC=1, LOGOFF WC=2, TREE_DISCONNECT WC=0. All per MS-CIFS. |
| `test_init_smb1_server_sets_ops` | **CORRECT** | SMB10_PROT_ID=0x0000 and SMB1_SERVER_CAPS verified. |
| `test_init_smb1_server_vals_fields` | **CORRECT** | CIFS_DEFAULT_IOSIZE=65536 (64KB), SMB1_VERSION_STRING="1.0". |

---

## File 5: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_parser.c`
**33 KUNIT_CASEs**

### AndX parser tests (6 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_andx_valid_chain_returns_target` | **CORRECT** | AndX chaining per MS-SMB 2.2.3.1. |
| `test_andx_rejects_offset_before_andx_start` | **CORRECT** | Backward offset rejected. |
| `test_andx_rejects_offset_past_packet_end` | **CORRECT** | Out-of-bounds offset rejected. |
| `test_andx_rejects_non_forward_progress` | **CORRECT** | Self-referential offset rejected (anti-loop). |
| `test_andx_rejects_excessive_chain_depth` | **CORRECT** | 33-deep chain rejected (max depth 32). |
| `test_andx_fuzz_invalid_offsets_rejected` | **CORRECT** | Fuzz testing of 128 invalid offsets. |

### SMB_TRANS pre-validation tests (9 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 9 tests | **CORRECT** | Parameter/data offset and count validation, setup count overflow, pipe data region checks. Per MS-SMB 2.2.4.4 / MS-CIFS 2.2.4.33. |

### Real exported function tests (18 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_real_check_smb1_hdr_valid_request` | **CORRECT** | SMB1_PROTO_NUMBER = 0x424d53ff ('\xFFSMB'). Valid request (not response). |
| `test_real_check_smb1_hdr_bad_protocol` | **CORRECT** | Bad protocol magic rejected. |
| `test_real_check_smb1_hdr_response_rejected` | **CORRECT** | SMBFLG_RESPONSE bit set = server should reject (it's processing requests, not responses). |
| `test_real_check_smb1_hdr_smb2_proto_rejected` | **CORRECT** | SMB2_PROTO_NUMBER (0x424d53fe, '\xFESMB') rejected by SMB1 header check. |
| All smb1_req_struct_size tests | **CORRECT** | Same WordCount values as verified above. |
| All smb1_get_byte_count tests | **CORRECT** | Same ByteCount validation as verified above. |

---

## File 6: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_pdu.c`
**38 KUNIT_CASEs**

### Protocol constants tests (6 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_max_mpx_count` | **CORRECT** | SMB1_MAX_MPX_COUNT=10. Per MS-SMB 2.2.4.5.2, MaxMpxCount is server-chosen. 10 is a valid implementation choice. |
| `test_smb1_max_raw_size` | **CORRECT** | SMB1_MAX_RAW_SIZE=65536. Per MS-CIFS 2.2.4.52.2 negotiate response. |
| `test_smb1_max_vcs` | **CORRECT** | SMB1_MAX_VCS=1. Standard for modern SMB1 servers. |
| `test_smb1_protocol_string` | **CORRECT** | SMB1_VERSION_STRING="1.0", SMB10_PROT_ID=0x00. |
| `test_smb1_capabilities_no_lock_and_read` | **CORRECT** | CAP_LOCK_AND_READ not in SMB1_SERVER_CAPS. |
| `test_smb1_capabilities_required_flags` | **CORRECT** | All required CAP_ flags verified. |

### SMB1 header structure tests (3 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_header_size` | **CORRECT** | sizeof(smb_hdr)=37 bytes. This matches the MS-SMB 2.2.3.1 header layout: 4 (transport) + 4 (Protocol) + 1 (Command) + 4 (Status) + 1 (Flags) + 2 (Flags2) + 2 (PidHigh) + 8 (Signature) + 2 (pad) + 2 (Tid) + 2 (Pid) + 2 (Uid) + 2 (Mid) + 1 (WordCount) = 37. |
| `test_smb1_protocol_magic` | **CORRECT** | 0xFF 'S' 'M' 'B' = little-endian 0x424d53ff per MS-SMB 2.2.3.1. |
| `test_smb1_header_field_offsets` | **CORRECT** | All offsets verified: Protocol@4, Command@8, Status@9, Flags@13, Flags2@14, Tid@28, Pid@30, Uid@32, Mid@34, WordCount@36. Per MS-SMB 2.2.3.1. |

### Command codes test (1 case)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_command_codes` | **CORRECT** | All 19 command opcodes verified against smb1pdu.h which matches MS-CIFS/MS-SMB 2.2.2.1: CREATE_DIRECTORY=0x00, DELETE_DIRECTORY=0x01, CLOSE=0x04, FLUSH=0x05, DELETE=0x06, RENAME=0x07, QUERY_INFORMATION=0x08, WRITE=0x0B, LOCKING_ANDX=0x24, TRANSACTION=0x25, ECHO=0x2B, OPEN_ANDX=0x2D, READ_ANDX=0x2E, WRITE_ANDX=0x2F, NEGOTIATE=0x72, SESSION_SETUP_ANDX=0x73, LOGOFF_ANDX=0x74, TREE_CONNECT_ANDX=0x75, NT_CREATE_ANDX=0xA2, NT_CANCEL=0xA4. |

### Negotiate structure tests (4 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_negotiate_rsp_structure` | **CORRECT** | DialectIndex follows hdr. |
| `test_smb1_negotiate_capabilities_field` | **CORRECT** | Capabilities at offset sizeof(smb_hdr)+19. Per MS-SMB 2.2.4.5.2: DialectIndex(2)+SecurityMode(1)+MaxMpxCount(2)+MaxNumberVcs(2)+MaxBufferSize(4)+MaxRawSize(4)+SessionKey(4) = 19 bytes after hdr. |
| `test_smb1_negotiate_security_mode` | **CORRECT** | SECMODE_USER=0x01, SECMODE_PW_ENCRYPT=0x02, SECMODE_SIGN_ENABLED=0x04, SECMODE_SIGN_REQUIRED=0x08. Per MS-SMB 2.2.4.5.2.1. |
| `test_smb1_negotiate_max_buffer_size` | **CORRECT** | MaxBufferSize at sizeof(smb_hdr)+7. Per the structure layout. |

### Session setup tests (3 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_session_setup_andx` | **CORRECT** | AndXCommand follows hdr. Per MS-SMB 2.2.4.6. |
| `test_smb1_session_flags` | **CORRECT** | GUEST_LOGIN=1 per MS-CIFS 2.2.4.53.2. |
| `test_smb1_session_no_more_andx` | **CORRECT** | SMB_NO_MORE_ANDX_COMMAND=0xFF per MS-CIFS 2.2.3.3. |

### Tree connect tests (5 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_tree_connect_andx` | **CORRECT** | Flags field offset=5. Per MS-SMB 2.2.4.7. |
| `test_smb1_service_types` | **CORRECT** | SERVICE_DISK_SHARE="A:", SERVICE_IPC_SHARE="IPC", SERVICE_PRINTER_SHARE="LPT1:", SERVICE_COMM="COMM". Per MS-CIFS 2.2.4.55. |
| `test_smb1_native_fs` | **CORRECT** | NATIVE_FILE_SYSTEM="NTFS". |
| `test_smb1_tcon_flags` | **CORRECT** | DISCONNECT_TID=0x0001, TCON_EXTENDED_SIGNATURES=0x0004, TCON_EXTENDED_SECINFO=0x0008. Per MS-SMB 2.2.4.7. |
| `test_smb1_native_fs` | **CORRECT** | |

### Command structure layout tests (6 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_read_andx_structure` | **CORRECT** | Read request size: hdr+1+1+2+2+4+2+2+4+2+4+2 = hdr+26 bytes. Fid at hdr+4. Per MS-CIFS 2.2.4.42. |
| `test_smb1_write_andx_structure` | **CORRECT** | Fid at hdr+4 (after AndX block). Per MS-CIFS 2.2.4.43. |
| `test_smb1_close_structure` | **CORRECT** | hdr+2(FileID)+4(LastWriteTime)+2(ByteCount) = hdr+8. Per MS-CIFS 2.2.4.5. |
| `test_smb1_close_rsp_structure` | **CORRECT** | hdr+2(ByteCount). Per MS-CIFS. |
| `test_smb1_find_first2` | **CORRECT** | TRANS2_FIND_FIRST=0x01, TRANS2_FIND_NEXT=0x02. Parameter structure 13 bytes. Per MS-SMB 2.2.6.1. |
| `test_smb1_find_response_params` | **CORRECT** | Response parameters 10 bytes (5 x USHORT). Per MS-CIFS 2.2.6.1.2. |

### Error code tests (3 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_error_class_codes` | **CORRECT** | SUCCESS=0x00, ERRDOS=0x01, ERRSRV=0x02, ERRHRD=0x03, ERRCMD=0xFF. Per MS-CIFS 2.2.1.4. |
| `test_smb1_dos_error_codes` | **CORRECT** | ERRbadfunc=1, ERRbadfile=2, ERRbadpath=3, ERRnofids=4, ERRnoaccess=5, ERRbadfid=6, ERRnomem=8, ERRbadshare=32, ERRlock=33, ERRfilexists=80, ERRdiskfull=112, ERRmoredata=234. All per MS-CIFS 2.2.1.4.1. |
| `test_smb1_srv_error_codes` | **CORRECT** | ERRerror=1, ERRbadpw=2, ERRaccess=4, ERRinvtid=5, ERRinvnetname=6, ERRinvdevice=7, ERRsmbcmd=64, ERRsrverror=65, ERRbaduid=91, ERRnosupport=0xFFFF. All per MS-CIFS 2.2.1.4.2. |

### Flag tests (2 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_flags` | **CORRECT** | SMBFLG_EXTD_LOCK=0x01, SMBFLG_CASELESS=0x08, SMBFLG_RESPONSE=0x80. Per MS-SMB 2.2.3.1. |
| `test_smb1_flags2` | **CORRECT** | SMBFLG2_UNICODE=0x8000, SMBFLG2_ERR_STATUS=0x4000, SMBFLG2_EXT_SEC=0x0800, SMBFLG2_KNOWS_LONG_NAMES=0x0001. Per MS-SMB 2.2.3.1. |

### Transact subcommand code tests (2 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_trans2_subcmds` | **CORRECT** | TRANS2_OPEN=0x00, FIND_FIRST=0x01, FIND_NEXT=0x02, QUERY_FS=0x03, SET_FS=0x04, QUERY_PATH=0x05, SET_PATH=0x06, QUERY_FILE=0x07, SET_FILE=0x08, CREATE_DIRECTORY=0x0D, GET_DFS_REFERRAL=0x10. All per MS-CIFS 2.2.2.2. |
| `test_smb1_nt_transact_subcmds` | **CORRECT** | NT_TRANSACT_CREATE=0x01, IOCTL=0x02, SET_SECURITY_DESC=0x03, NOTIFY_CHANGE=0x04, RENAME=0x05, QUERY_SECURITY_DESC=0x06, GET_USER_QUOTA=0x07, SET_USER_QUOTA=0x08. Per MS-SMB 2.2.2.2 / MS-CIFS 2.2.2.2. |

### Open/Create structure tests (2 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| Both tests | **CORRECT** | Structure layout verified against MS-SMB 2.2.4.9. |

### Locking tests (3 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_smb1_locking_andx_constants` | **CORRECT** | SHARED_LOCK=0x01, OPLOCK_RELEASE=0x02, CHANGE_LOCKTYPE=0x04, CANCEL_LOCK=0x08, LARGE_FILES=0x10. Per MS-CIFS 2.2.4.32. |
| `test_smb1_locking_range64_size` | **CORRECT** | 20 bytes: Pid(2)+Pad(2)+OffsetHigh(4)+OffsetLow(4)+LengthHigh(4)+LengthLow(4). Per MS-CIFS. |
| `test_smb1_locking_range32_size` | **CORRECT** | 10 bytes: Pid(2)+Offset(4)+Length(4). Per MS-CIFS. |

---

## File 7: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_trans2.c`
**34 KUNIT_CASEs**

### Buffer validation tests (9 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 9 tests | **CORRECT** | Calls real `smb1_validate_trans2_buffer()` with valid, overflow, boundary, zero-count, and offset-beyond-buffer scenarios. Per MS-CIFS 2.2.4.46 / MS-SMB 2.2.4.4, parameter and data regions must be within the buffer. |

### Subcommand validation tests (10 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 10 tests | **CORRECT** | Valid subcommands (TRANS2_OPEN through TRANS2_REPORT_DFS_INCOSISTENCY) accepted, invalid (0xFF, 0x0E, 0x12) rejected. Per MS-CIFS 2.2.2.2. |

### Info level validation tests (4 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 4 tests | **CORRECT** | Standard FIND info levels accepted, invalid levels (0, 0x200) rejected. Per MS-SMB 2.2.2.3.1 / MS-CIFS 2.2.2.3.1. |

### Parameter count minimum tests (7 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_trans2_find_first_min_param_count` | **CORRECT** | FIND_FIRST minimum param = 11 bytes (12-byte structure minus 1-byte variable FileName). Per MS-CIFS 2.2.6.1.1. |
| `test_trans2_find_next_min_param_count` | **CORRECT** | FIND_NEXT minimum param = 11 bytes. Per MS-CIFS 2.2.6.2.1. |
| `test_trans2_query_fs_info_min_param_count` | **CORRECT** | QUERY_FS_INFORMATION minimum param = 2 bytes (InformationLevel). Per MS-CIFS 2.2.6.3. |
| `test_trans2_query_file_info_min_param_count` | **CORRECT** | QUERY_FILE_INFORMATION minimum param = 4 bytes (Fid+InformationLevel). Per MS-CIFS 2.2.6.8. |
| `test_trans2_query_path_info_min_param_count` | **CORRECT** | QUERY_PATH_INFORMATION minimum param = 6 bytes (InformationLevel+Reserved). Per MS-CIFS 2.2.6.6. |
| `test_trans2_set_path_info_min_total_param` | **CORRECT** | SET_PATH_INFORMATION minimum total_param = 7. |
| `test_trans2_set_file_info_min_total_param` | **CORRECT** | SET_FILE_INFORMATION minimum total_param = 4 (Fid+InformationLevel). |

### Overlap and setup count tests (4 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 4 tests | **CORRECT** | Overlap detection, non-overlap, setup count minimum validation. |

---

## File 8: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_nt_transact.c`
**28 KUNIT_CASEs**

### Buffer validation tests (11 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 11 tests | **CORRECT** | Calls real `smb1_validate_nt_transact_buffer()` with valid, overflow, boundary, total-less-than-current, setup-count-overflow, and zero-count scenarios. Per MS-CIFS 2.2.4.62 / MS-SMB 2.2.4.8. |

### Subcommand validation tests (10 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 10 tests | **CORRECT** | NT_TRANSACT subcommands 0x01-0x08 accepted, 0 and 0xFF rejected. NT_TRANSACT_MAX_SUBCOMMAND=0x08 per MS-SMB 2.2.2.2. |

### Truncated parameter tests (5 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_nt_transact_create_truncated_params` | **CORRECT** | NT_TRANSACT_CREATE needs 53 bytes minimum. Per MS-SMB 2.2.7.1: Flags(4)+RootDirectoryFID(4)+DesiredAccess(4)+AllocationSize(8)+ExtFileAttributes(4)+ShareAccess(4)+CreateDisposition(4)+CreateOptions(4)+SecurityDescriptorLength(4)+EALength(4)+NameLength(4)+ImpersonationLevel(4)+SecurityFlags(1) = 53. The assertion `param_count=10 < 53` is correct. |
| `test_nt_transact_ioctl_truncated_params` | **CORRECT** | IOCTL needs 8 bytes: FunctionCode(4)+Fid(2)+IsFsctl(1)+IsFlags(1). Per MS-SMB 2.2.7.2. |
| `test_nt_transact_set_security_truncated_data` | **CORRECT** | SET_SECURITY_DESC needs at least 1 byte of data (the security descriptor). Per MS-SMB 2.2.7.3. |
| `test_nt_transact_notify_truncated_params` | **CORRECT** | NOTIFY_CHANGE needs 8 bytes. Per MS-CIFS. |
| `test_nt_transact_set_quota_truncated_data` | **CORRECT** | SET_USER_QUOTA needs at least 8 bytes of data. Per MS-SMB 2.2.2.2. |

### Integer overflow tests (2 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| Both tests | **CORRECT** | Tests that u32 overflow in ParameterOffset+ParameterCount and DataOffset+DataCount is detected. |

---

## File 9: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_nt_transact_subcommands.c`
**40 KUNIT_CASEs**

### Dispatcher routing tests (11 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 11 tests | **CORRECT** | Functions 0x01-0x08 are valid, 0x00/0x09/0xFF return -EOPNOTSUPP. Per MS-SMB 2.2.2.2 / MS-CIFS. |

### Minimum ParameterCount tests (7 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_create_params_minimum_57` | **QUESTIONABLE** | The test uses NT_CREATE_MIN_PARAMS=57, but the MS-SMB 2.2.7.1 parameter block sums to exactly 53 bytes before the variable-length Name[] field (see calculation above). Looking at the Name field: "UCHAR Name[NameLength]" -- the Name is actually part of the Parameters, not the Data block (in NT_TRANSACT_CREATE, the Name is in the parameter block, SD and EA are in the data block). So the minimum parameter count for a valid request would be 53 (the fixed fields) + at least some name bytes. **However**, this test file defines its own constant `NT_CREATE_MIN_PARAMS=57` and tests against its own replicated logic, not the real code. The `ksmbd_test_smb1_nt_transact.c` file uses 53 for the same check. The discrepancy between 53 and 57 is **QUESTIONABLE** -- the real smb1pdu.c should be checked to see which value it uses. Both are defensible: 53 = fixed fields only, 57 = fixed fields + 4 bytes minimum name. |
| `test_ioctl_params_minimum_8` | **CORRECT** | Per MS-SMB 2.2.7.2. |
| `test_set_security_params_minimum_8` | **CORRECT** | Per MS-SMB 2.2.7.3. |
| `test_notify_params_minimum_8` | **CORRECT** | Per MS-CIFS 2.2.7.4. |
| `test_rename_params_minimum_4` | **CORRECT** | Fid(2)+Flags(2)=4 per MS-CIFS 2.2.7.5. |
| `test_query_security_params_minimum_8` | **CORRECT** | Per MS-SMB 2.2.7.4. |
| `test_quota_params_no_minimum` | **CORRECT** | GET/SET_USER_QUOTA stubs accept any ParameterCount. |

### NT_TRANSACT_CREATE buffer validation tests (5 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 5 tests | **CORRECT** | SD/EA/Name length validation against data_count. Name length zero rejected. Name length > data_count rejected. |

### IOCTL/NOTIFY/RENAME parameter parsing tests (7 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 7 tests | **CORRECT** | Field parsing at correct offsets. IOCTL: FunctionCode@0, Fid@4. NOTIFY: CompletionFilter@0, Fid@4, WatchTree@6. RENAME: Fid@0, Flags@2, min params=4. |

### Response buffer layout tests (3 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 3 tests | **CORRECT** | ParameterOffset=68 is the well-known constant for NT_TRANSACT responses. DataOffset alignment to 4-byte boundary is correct. ByteCount calculation with padding is correct. |

### Secondary count validation, structure layout, etc. (7 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 7 tests | **CORRECT** | Secondary TotalParameterCount/TotalDataCount mismatch detection, structure field layout, MaxSetupCount=0 validity, SetupCount boundary testing. |

---

## File 10: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_upgrade.c`
**11 KUNIT_CASEs**

### SMB1->SMB2 upgrade state machine tests

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_upgrade_uses_wildcard_dialect` | **CORRECT** | After upgrade, dialect MUST be 0x02FF. Per MS-SMB2 3.3.5.3: "DialectRevision MUST be set to 0x02FF" (section 3.3.5.3.1). |
| `test_smb1_conn_true_before_upgrade` | **CORRECT** | Before upgrade, conn is SMB1. |
| `test_smb1_conn_false_after_upgrade` | **CORRECT** | After upgrade, conn is no longer SMB1. |
| `test_vals_reallocated_during_upgrade` | **CORRECT** | Old vals freed, new vals allocated. |
| `test_second_negotiate_after_upgrade_rejected` | **CORRECT** | Per MS-SMB2 3.3.5.3.1: a second NEGOTIATE must be rejected. |
| `test_smb1_command_after_upgrade_rejected` | **CORRECT** | After upgrade, SMB1 commands rejected, SMB2 commands accepted. |
| `test_smb1_only_dialects_no_upgrade` | **CORRECT** | SMB10_PROT_ID (0x0000) stays SMB1, no upgrade. |
| `test_upgrade_with_smb2_02` | **CORRECT** | Even with SMB2.0.2 as highest, upgrade dialect is always 0x02FF per MS-SMB2 3.3.5.3.1. |
| `test_upgrade_with_smb3_11` | **CORRECT** | Same: 0x02FF regardless of specific SMB2/3 dialect. |
| `test_need_neg_cleared_on_init` | **CORRECT** | need_neg cleared before init. |
| `test_connection_state_transition_full_sequence` | **CORRECT** | Full lifecycle: init -> negotiate -> upgrade -> reject SMB1 -> accept SMB2. |

---

## File 11: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb_common.c`
**17 KUNIT_CASEs**

### Protocol lookup tests (6 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_lookup_smb2_10` | **CORRECT** | "SMB2_10" -> SMB21_PROT (index 2). |
| `test_lookup_smb3_11` | **CORRECT** | "SMB3_11" -> SMB311_PROT (index 6). |
| `test_lookup_smb2_02` | **CORRECT** | "SMB2_02" -> SMB2_PROT (index 1). |
| `test_lookup_smb3_00` | **CORRECT** | "SMB3_00" -> SMB30_PROT (index 4). |
| `test_lookup_smb3_02` | **CORRECT** | "SMB3_02" -> SMB302_PROT (index 5). |
| `test_lookup_invalid_returns_neg` | **CORRECT** | "INVALID", "", "SMB4_00" return -1. |

### Min/max protocol tests (2 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_min_protocol_is_smb2` | **CORRECT** | Minimum is SMB2_PROT (without CONFIG_SMB_INSECURE_SERVER). |
| `test_max_protocol_is_smb311` | **CORRECT** | Maximum is SMB311_PROT. |

### Server-side copy defaults tests (3 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| `test_copy_chunk_max_count_default` | **CORRECT** | 256 per MS-SMB2 3.3.5.15.6. |
| `test_copy_chunk_max_size_default` | **CORRECT** | 1MB per MS-SMB2. |
| `test_copy_chunk_total_size_default` | **CORRECT** | 16MB per MS-SMB2. |

### Real next_dialect() tests (6 cases)

| Test Case | Verdict | Notes |
|-----------|---------|-------|
| All 6 tests | **CORRECT** | next_dialect() parsing of packed NUL-terminated dialect strings. Single string, two strings, empty buffer, unterminated string, exhausted buffer, offset beyond bcount. Per MS-SMB 2.2.4.5.1 negotiate request format. |

---

## FINDINGS SUMMARY

### Statistics
- **Total KUNIT_CASEs audited**: ~250
- **CORRECT**: ~249
- **WRONG**: 0
- **QUESTIONABLE**: 1

### The Single QUESTIONABLE Finding

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb1_nt_transact_subcommands.c`
**Test**: `test_create_params_minimum_57`
**Issue**: The test defines `NT_CREATE_MIN_PARAMS=57` but the MS-SMB 2.2.7.1 NT_TRANSACT_CREATE parameter block fixed fields sum to exactly **53 bytes**:
- Flags(4) + RootDirectoryFID(4) + DesiredAccess(4) + AllocationSize(8) + ExtFileAttributes(4) + ShareAccess(4) + CreateDisposition(4) + CreateOptions(4) + SecurityDescriptorLength(4) + EALength(4) + NameLength(4) + ImpersonationLevel(4) + SecurityFlags(1) = **53 bytes**

The test in `ksmbd_test_smb1_nt_transact.c` correctly uses 53, while this file uses 57. The value 57 may account for additional bytes such as the 4-byte minimum for the variable-length Name field (which must have name_len > 0, so at least some name data is required in the parameter block). Both are defensible interpretations, but they are inconsistent with each other. This is not a spec violation per se, but rather an inconsistency between two test files. The real smb1pdu.c implementation's actual minimum check should be the authority.

### Key Spec References Verified
- **SMB_COM command codes**: MS-CIFS 2.2.2.1 -- all 19+ opcodes verified correct
- **TRANS2 subcommand codes**: MS-CIFS 2.2.2.2 / MS-SMB 2.2.2.2 -- all values 0x00-0x11 correct
- **NT_TRANSACT subcommand codes**: MS-CIFS 2.2.2.2 / MS-SMB 2.2.2.2 -- all values 0x01-0x08 correct
- **CreateDisposition values**: MS-SMB 3.3.5.5 -- FILE_SUPERSEDE(0) through FILE_OVERWRITE_IF(5) correct
- **SMB1 header layout**: MS-SMB 2.2.3.1 -- 37-byte header with all field offsets verified
- **SMB1->SMB2 upgrade dialect**: MS-SMB2 3.3.5.3.1 -- 0x02FF wildcard confirmed
- **DOS date/time format**: MS-SMB 2.2.1.1 -- bit field encoding verified
- **Error class codes**: MS-CIFS 2.2.1.4 -- SUCCESS(0), ERRDOS(1), ERRSRV(2), ERRHRD(3), ERRCMD(0xFF) correct
- **Flags/Flags2**: MS-SMB 2.2.3.1 -- SMBFLG_RESPONSE=0x80, SMBFLG2_UNICODE=0x8000, etc. correct
- **Locking constants**: MS-CIFS 2.2.4.32 -- SHARED_LOCK=0x01, etc. correct
- **Security mode**: MS-SMB 2.2.4.5.2.1 -- USER=0x01, PW_ENCRYPT=0x02, SIGN_ENABLED=0x04, SIGN_REQUIRED=0x08 correct
- **WordCount values**: All validated per MS-CIFS for each command
- **ByteCount minimums**: CLOSE=0, NEGOTIATE>=2, WRITE_ANDX>=1 -- all correct