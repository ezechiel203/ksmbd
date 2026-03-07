# SMB1 Current Implementation Audit — KSMBD

> Generated from analysis of `src/protocol/smb1/smb1pdu.c` (9040 lines), `smb1ops.c`, `smb1misc.c`

---

## Dispatch Table (smb1ops.c lines 49–78) — 27 Commands

| Command | Opcode | Handler | Status | Key Gaps |
|---------|--------|---------|--------|----------|
| SMB_COM_CREATE_DIRECTORY | 0x00 | smb_mkdir | Complete | — |
| SMB_COM_DELETE_DIRECTORY | 0x01 | smb_rmdir | Complete | — |
| SMB_COM_CLOSE | 0x04 | smb_close | Complete | — |
| SMB_COM_FLUSH | 0x05 | smb_flush | Complete | FID=0xFFFF (flush all) not validated |
| SMB_COM_DELETE | 0x06 | smb_unlink | Complete | — |
| SMB_COM_RENAME | 0x07 | smb_rename | Complete | — |
| SMB_COM_QUERY_INFORMATION | 0x08 | smb_query_info | Complete | Legacy 8.3 only |
| SMB_COM_SETATTR | 0x09 | smb_setattr | Complete | LastWriteTime=0 handling |
| SMB_COM_WRITE | 0x0B | smb_write | Complete | 2GB limit acknowledged |
| SMB_COM_CHECK_DIRECTORY | 0x10 | smb_checkdir | Complete | — |
| SMB_COM_PROCESS_EXIT | 0x11 | smb_process_exit | Complete (trivial) | — |
| SMB_COM_LOCKING_ANDX | 0x24 | smb_locking_andx | Partial | CHANGE_LOCKTYPE returns ERRnoatomiclocks; CANCEL_LOCK logs only; no async oplock break send |
| SMB_COM_TRANSACTION | 0x25 | smb_trans | Partial | LANMAN pipe only; no TransactNmPipe, PeekNmPipe, WaitNmPipe, CallNmPipe, WriteMailslot |
| SMB_COM_OPEN_ANDX | 0x2D | smb_open_andx | Complete | — |
| SMB_COM_READ_ANDX | 0x2E | smb_read_andx | Complete | MinCount not enforced |
| SMB_COM_WRITE_ANDX | 0x2F | smb_write_andx | Complete | write-behind partially handled |
| SMB_COM_ECHO | 0x2B | smb_echo | Complete | — |
| SMB_COM_TRANSACTION2 | 0x32 | smb_trans2 | Partial | TRANS2_OPEN, DFS_REFERRAL missing |
| SMB_COM_FIND_CLOSE2 | 0x34 | smb_closedir | Complete | — |
| SMB_COM_TREE_DISCONNECT | 0x71 | smb_tree_disconnect | Complete | — |
| SMB_COM_NEGOTIATE | 0x72 | smb_negotiate_request | Complete | CAP_LOCK_AND_READ removed (correct) |
| SMB_COM_SESSION_SETUP_ANDX | 0x73 | smb_session_setup_andx | Complete | Impersonation levels ignored |
| SMB_COM_LOGOFF_ANDX | 0x74 | smb_session_disconnect | Complete | — |
| SMB_COM_TREE_CONNECT_ANDX | 0x75 | smb_tree_connect_andx | Complete | — |
| SMB_COM_QUERY_INFORMATION_DISK | 0x80 | smb_query_information_disk | Complete | — |
| SMB_COM_NT_CREATE_ANDX | 0xA2 | smb_nt_create_andx | Partial | FILE_OPEN_BY_FILE_ID unsupported; SDs informational; impersonation ignored |
| SMB_COM_NT_CANCEL | 0xA4 | smb_nt_cancel | Stub | Does not cancel in-flight requests |
| SMB_COM_NT_RENAME | 0xA5 | smb_nt_rename | Complete | — |

---

## Missing Commands (Not in Dispatch Table)

| Command | Opcode | Priority | Notes |
|---------|--------|----------|-------|
| SMB_COM_NT_TRANSACT | 0xA0 | CRITICAL | Entire dispatcher absent; all 8 subcommands missing |
| SMB_COM_NT_TRANSACT_SECONDARY | 0xA1 | CRITICAL | Multi-packet NT_TRANSACT support |
| SMB_COM_TRANSACTION_SECONDARY | 0x26 | HIGH | Multi-packet TRANSACTION support |
| SMB_COM_TRANSACTION2_SECONDARY | 0x33 | HIGH | Multi-packet TRANSACTION2 support |
| SMB_COM_COPY | 0x29 | MEDIUM | Server-side copy |
| SMB_COM_MOVE | 0x2A | LOW | Server-side move |
| SMB_COM_QUERY_INFORMATION2 | 0x23 | MEDIUM | FID-based attribute query |
| SMB_COM_SET_INFORMATION2 | 0x22 | MEDIUM | FID-based timestamp set |
| SMB_COM_WRITE_AND_CLOSE | 0x2C | LOW | Atomic write+close |
| SMB_COM_LOCK_AND_READ | 0x13 | SKIP | Explicitly removed; no handler intended |
| SMB_COM_WRITE_PRINT_FILE | 0x36 | LOW | Print spool |
| SMB_COM_CLOSE_PRINT_FILE | 0x37 | LOW | Print spool |
| SMB_COM_GET_PRINT_QUEUE | 0x38 | LOW | Print spool |
| SMB_COM_SEARCH | 0x81 | LOW | Legacy; superseded by TRANS2_FIND_FIRST |
| SMB_COM_FIND | 0x82 | LOW | Legacy; superseded by TRANS2_FIND_FIRST |
| SMB_COM_FIND_UNIQUE | 0x83 | LOW | Legacy search |
| SMB_COM_FIND_CLOSE | 0x84 | LOW | Legacy close (FIND_CLOSE2 implemented) |
| SMB_COM_SEND_MESSAGE | 0x3A–0x3D | SKIP | WinPopup; obsolete |
| SMB_COM_WRITE_RAW | 0x1D | SKIP | Deprecated; security risk |
| SMB_COM_READ_RAW | 0x1C | SKIP | Deprecated; security risk |
| SMB_COM_OPEN | 0x02 | LOW | Legacy pre-ANDX open |
| SMB_COM_CREATE | 0x03 | LOW | Legacy create |
| SMB_COM_CREATE_NEW | 0x0F | LOW | Create-if-not-exists |
| SMB_COM_CREATE_TEMPORARY | 0x0E | LOW | Create temp file |
| SMB_COM_SEEK | 0x12 | LOW | Legacy file seek |

---

## NT_TRANSACT Subcommands — All Missing

| Subcommand | Code | Priority | Description |
|------------|------|----------|-------------|
| NT_TRANSACT_CREATE | 0x01 | HIGH | Create with security descriptor + EA |
| NT_TRANSACT_IOCTL | 0x02 | HIGH | FSCTL passthrough (SPARSE, ZERO_DATA, etc.) |
| NT_TRANSACT_SET_SECURITY_DESC | 0x03 | HIGH | Set ACL/owner/group/SACL |
| NT_TRANSACT_NOTIFY_CHANGE | 0x04 | HIGH | Directory change notification (async) |
| NT_TRANSACT_RENAME | 0x05 | MEDIUM | FID-based rename |
| NT_TRANSACT_QUERY_SECURITY_DESC | 0x06 | HIGH | Query ACL/owner/group/SACL |
| NT_TRANSACT_GET_USER_QUOTA | 0x07 | LOW | Quota query |
| NT_TRANSACT_SET_USER_QUOTA | 0x08 | LOW | Quota set |

---

## TRANSACTION2 Subcommand Status

| Subcommand | Code | Status | Notes |
|------------|------|--------|-------|
| TRANS2_OPEN | 0x00 | MISSING | Returns EINVAL |
| TRANS2_FIND_FIRST2 | 0x01 | Complete | Lines 6290–6604 |
| TRANS2_FIND_NEXT2 | 0x02 | Complete | Lines 6605–6975 |
| TRANS2_QUERY_FS_INFORMATION | 0x03 | Complete | Lines 4877–5185 |
| TRANS2_SET_FS_INFORMATION | 0x04 | Partial | Not all levels |
| TRANS2_QUERY_PATH_INFORMATION | 0x05 | Complete | Lines 4311–4876 |
| TRANS2_SET_PATH_INFORMATION | 0x06 | Complete | Lines 5926–6075 |
| TRANS2_QUERY_FILE_INFORMATION | 0x07 | Complete | Lines 7034–7642 |
| TRANS2_SET_FILE_INFORMATION | 0x08 | Complete | Lines 7643–7806 |
| TRANS2_FSCTL | 0x09 | MISSING | Returns EINVAL |
| TRANS2_IOCTL2 | 0x0A | MISSING | Returns EINVAL |
| TRANS2_FIND_NOTIFY_FIRST | 0x0B | MISSING | Returns EINVAL |
| TRANS2_FIND_NOTIFY_NEXT | 0x0C | MISSING | Returns EINVAL |
| TRANS2_CREATE_DIRECTORY | 0x0D | Complete | With EA support |
| TRANS2_SESSION_SETUP | 0x0E | MISSING | Returns EINVAL |
| TRANS2_GET_DFS_REFERRAL | 0x10 | MISSING | Returns EINVAL |
| TRANS2_REPORT_DFS_INCONSISTENCY | 0x11 | MISSING | Returns EINVAL |

---

## Key Validation Gaps

1. **NT_TRANSACT dispatcher entirely absent** — most critical gap for Windows interop
2. **Security descriptors** — NT_CREATE_ANDX ignores SD; no ACL set/get path
3. **Impersonation levels** — parsed but ignored (lines 2766–2768)
4. **FILE_OPEN_BY_FILE_ID** — returns STATUS_NOT_SUPPORTED (line 2539–2542)
5. **NT_CANCEL** — does not actually cancel in-flight lock/notify requests
6. **LOCKING_ANDX CANCEL_LOCK** — logs only, no cancellation
7. **TRANSACTION multi-packet** — secondary packets (0x26, 0x33, 0xA1) not handled
8. **DFS referrals** — TRANS2_GET_DFS_REFERRAL returns EINVAL
9. **Named pipe advanced ops** — TransactNmPipe, PeekNmPipe, WaitNmPipe, CallNmPipe missing
10. **MinCount on READ_ANDX** — not enforced (blocking read semantics)
11. **FID=0xFFFF FLUSH** — "flush all open files" case not tested/enforced
12. **Error code consistency** — some legacy DOS errors remain alongside NTSTATUS

---

## AndX Chaining Support

Implemented for: SESSION_SETUP, TREE_CONNECT, OPEN_ANDX, READ_ANDX, WRITE_ANDX, LOCKING_ANDX.
Missing for: NT_CREATE_ANDX response chaining to subsequent AndX.

## Large File Support

- READ_ANDX: OffsetHigh (32-bit) extends OffsetLow → 64-bit file offset ✓
- WRITE_ANDX: OffsetHigh support ✓
- LOCKING_ANDX: LOCKING_ANDX_LARGE_FILES flag (64-bit ranges) ✓
- CAP_LARGE_READ_X / CAP_LARGE_WRITE_X advertised ✓

## Unicode / ASCII Handling

All handlers check `is_smbreq_unicode(&req->hdr)` (SMBFLG2_UNICODE flag).
Path conversion via `smb_strndup_from_utf16()`. Both UTF-16LE and ASCII supported.

## Oplock Support

- Exclusive, Batch, Level II oplocks — implemented
- Oplock grant in NT_CREATE_ANDX (lines 2598–2601)
- Oplock break receive (LOCKING_ANDX with OPLOCK_RELEASE) — implemented
- Oplock break **send** to client — partial (state machine exists, but explicit break PDU path needs verification)

---

## Estimated Compliance: ~55% of MS-SMB protocol

**Breakdown:**
- Core session/negotiate/tree: ~95%
- File I/O (open/read/write/close): ~85%
- TRANSACTION2: ~75%
- Locking: ~70%
- TRANSACTION (named pipe): ~30%
- NT_TRANSACT: 0%
- Security descriptors via SMB1: 0%
- Legacy commands (SEARCH, FIND, COPY, etc.): ~10%
- DFS referrals: 0%
- Print operations: 0%
