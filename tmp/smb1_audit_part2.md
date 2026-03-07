# SMB1 Audit Part 2: Locking / Transactions / Search / Print

**Repository:** `/home/ezechiel203/ksmbd`
**Spec:** `protocol/[MS-SMB].pdf` (v20260114, January 14, 2026)
**Primary source files audited:**
- `src/protocol/smb1/smb1pdu.c`
- `src/protocol/smb1/smb1ops.c`
- `src/protocol/smb1/smb1misc.c`
- `src/include/protocol/smb1pdu.h`

---

## Summary

- **Total commands / subcommands audited:** 32
- **Missing:** 13
- **Partial:** 12
- **Complete:** 7

---

## Command Status Table

| Command | Opcode / Sub | Status | Gap Description |
|---------|-------------|--------|-----------------|
| SMB_COM_LOCKING_ANDX | 0x24 | PARTIAL | CANCEL_LOCK logs but does nothing; CHANGE_LOCKTYPE returns error but not the correct NT status per spec |
| SMB_COM_LOCK_AND_READ | 0x13 | MISSING | Advertised via CAP_LOCK_AND_READ but no handler registered |
| SMB_COM_WRITE_AND_UNLOCK | 0x14 | MISSING | No opcode constant defined; no handler |
| SMB_COM_TRANSACTION | 0x25 | PARTIAL | Only LANMAN RAP and TRANSACT_DCERPCCMD handled; all other named-pipe subcommands return STATUS_NOT_SUPPORTED |
| SMB_COM_TRANSACTION_SECONDARY | 0x26 | MISSING | Not registered in dispatch table; multi-fragment TRANSACTION not supported |
| SMB_COM_TRANSACTION2 | 0x32 | PARTIAL | Dispatcher present; several subcommands not implemented (see below) |
| SMB_COM_TRANSACTION2_SECONDARY | 0x33 | MISSING | Not registered in dispatch table; multi-fragment TRANSACTION2 not supported |
| SMB_COM_NT_TRANSACT | 0xA0 | MISSING | Opcode constant defined and known in cmd_str table but NO handler registered |
| SMB_COM_NT_TRANSACT_SECONDARY | 0xA1 | MISSING | Not registered; no multi-fragment NT_TRANSACT support |
| TRANS2_FIND_FIRST2 (0x0001) | TRANS2 | PARTIAL | Core scan implemented; ResumeKey, CONTINUE_FROM_LAST flag, @GMT token, and CLOSE_IF_EOS flag not handled |
| TRANS2_FIND_NEXT2 (0x0002) | TRANS2 | PARTIAL | Core implemented; ResumeFileName field ignored; CONTINUE_FROM_LAST not handled |
| TRANS2_QUERY_FS_INFORMATION (0x0003) | TRANS2 | PARTIAL | 7 info levels implemented; pass-through info levels (SMB_INFO_PASSTHROUGH) not handled |
| TRANS2_SET_FS_INFORMATION (0x0004) | TRANS2 | PARTIAL | Only SMB_SET_CIFS_UNIX_INFO handled; pass-through info levels not handled |
| TRANS2_QUERY_PATH_INFORMATION (0x0005) | TRANS2 | PARTIAL | 10 info levels; pass-through levels not handled; reparse-point path flag (SMB_FLAGS2_REPARSE_PATH) not checked |
| TRANS2_SET_PATH_INFORMATION (0x0006) | TRANS2 | PARTIAL | 9 info levels; pass-through levels not handled; reparse-point path flag not checked |
| TRANS2_QUERY_FILE_INFORMATION (0x0007) | TRANS2 | PARTIAL | 6 info levels; pass-through levels not handled |
| TRANS2_SET_FILE_INFORMATION (0x0008) | TRANS2 | PARTIAL | 8 info levels; pass-through levels not handled |
| TRANS2_CREATE_DIRECTORY (0x000D) | TRANS2 | COMPLETE | Correctly implemented |
| TRANS2_GET_DFS_REFERRAL (0x0010) | TRANS2 | MISSING | Falls through to default; returns STATUS_NOT_SUPPORTED |
| TRANS2_REPORT_DFS_INCONSISTENCY (0x0011) | TRANS2 | MISSING | Not in switch; no handler |
| NT_TRANSACT_CREATE (0x0001) | NT_TRANSACT | MISSING | No NT_TRANSACT dispatcher |
| NT_TRANSACT_IOCTL (0x0002) | NT_TRANSACT | MISSING | No NT_TRANSACT dispatcher; FSCTL_SRV_ENUMERATE_SNAPSHOTS, FSCTL_SRV_COPYCHUNK etc. unavailable |
| NT_TRANSACT_SET_SECURITY_DESC (0x0003) | NT_TRANSACT | MISSING | No NT_TRANSACT dispatcher |
| NT_TRANSACT_NOTIFY_CHANGE (0x0004) | NT_TRANSACT | MISSING | No NT_TRANSACT dispatcher |
| NT_TRANSACT_RENAME (0x0005) | NT_TRANSACT | MISSING | No NT_TRANSACT dispatcher |
| NT_TRANSACT_QUERY_SECURITY_DESC (0x0006) | NT_TRANSACT | MISSING | No NT_TRANSACT dispatcher |
| SMB_COM_ECHO | 0x2B | COMPLETE | Handles EchoCount=0, limits to 10 echoes, copies data correctly |
| SMB_COM_FLUSH | 0x05 | COMPLETE | FileID=0xFFFF flushes all; otherwise syncs single file |
| SMB_COM_QUERY_INFORMATION_DISK | 0x80 | COMPLETE | Clamps block size, fits u16 fields; correct response format |
| SMB_COM_NT_CANCEL | 0xA4 | PARTIAL | Finds pending work by MID and sets send_no_response; does NOT wake sleeping lock waits |
| SMB_COM_GET_PRINT_QUEUE | 0x3D | MISSING | Not registered in dispatch table |
| SMB_COM_OPEN_PRINT_FILE | 0x43 | MISSING | Not registered in dispatch table |
| SMB_COM_WRITE_PRINT_FILE | 0x44 | MISSING | Not registered in dispatch table |
| SMB_COM_CLOSE_PRINT_FILE | 0x45 | MISSING | Not registered in dispatch table |
| SMB_COM_SEARCH | 0x81 | MISSING | Not registered in dispatch table |
| SMB_COM_IOCTL | 0x27 | MISSING | Not registered in dispatch table |
| SMB_COM_SET_INFORMATION2 | 0x22 | MISSING | No opcode constant defined; not registered |

---

## Detailed Gaps

---

### SMB_COM_LOCK_AND_READ (0x13)
- **Spec ref:** MS-SMB §2.2 (CAP_LOCK_AND_READ), [MS-CIFS] §2.2.4.26
- **Status:** MISSING
- **Required by spec:** The server capability bit `CAP_LOCK_AND_READ` (0x00000100) is advertised in `SMB1_SERVER_CAPS` (defined in `src/include/protocol/smb1pdu.h:27`). Advertising this cap signals to clients that the server supports the atomic lock-then-read command (SMB_COM_LOCK_AND_READ, opcode 0x13). No opcode constant for 0x13 is defined in `smb1pdu.h` and no handler is registered in `smb1_server_cmds[]`.
- **Current implementation:** Nothing. A client sending opcode 0x13 receives STATUS_SMB_BAD_COMMAND or is silently dropped.
- **Implementation effort:** MEDIUM — requires a combined lock (via `vfs_lock_file`) and read (via `vfs_read`) atomic handler, plus new struct definitions for the SMB_COM_LOCK_AND_READ request/response.
- **Plan:**
  1. Define `SMB_COM_LOCK_AND_READ 0x13` and the request/response structs in `smb1pdu.h`.
  2. Implement `smb_lock_and_read()` in `smb1pdu.c`: acquire byte-range lock on the specified range, perform the read, and either return data or roll back the lock on failure.
  3. Register the handler in `smb1ops.c`.
  4. Either remove `CAP_LOCK_AND_READ` from `SMB1_SERVER_CAPS` until the handler is ready, or implement step 2 first.

---

### SMB_COM_WRITE_AND_UNLOCK (0x14)
- **Spec ref:** [MS-CIFS] §2.2.4.27
- **Status:** MISSING
- **Required by spec:** Atomic write-then-unlock. Obsolescent in modern clients but used by legacy clients, especially with MS-DOS/Windows 3.x interop. The server does not advertise a specific capability for this command, but it should respond with STATUS_SMB_BAD_COMMAND if unimplemented.
- **Current implementation:** Nothing. No opcode constant; no handler.
- **Implementation effort:** MEDIUM — similar to LOCK_AND_READ but reversed.
- **Plan:**
  1. Define `SMB_COM_WRITE_AND_UNLOCK 0x14` and structs.
  2. Implement `smb_write_and_unlock()`: perform the write first, then release the lock; if the write fails, do not release the lock.
  3. Register the handler. This is low-priority given the command is obsolescent.

---

### SMB_COM_TRANSACTION_SECONDARY (0x26)
- **Spec ref:** [MS-CIFS] §2.2.4.33
- **Status:** MISSING
- **Required by spec:** MUST be supported to handle multi-fragment SMB_COM_TRANSACTION requests. When a client's initial SMB_COM_TRANSACTION request does not contain all parameter or data bytes (TotalParameterCount > ParameterCount or TotalDataCount > DataCount), the server must reassemble subsequent TRANSACTION_SECONDARY messages. Without this, any client using fragmented transactions will fail.
- **Current implementation:** `SMB_COM_TRANSACTION2_SECONDARY 0x33` is listed in `smb_cmd_str[]` (line 72 of `smb1pdu.c`) as a known string label but there is NO registered handler in `smb1_server_cmds[]`. The `smb_trans()` function does check for `incomplete` (lines 4894–4913 in `smb1pdu.c`) but contains only a comment stub — actual reassembly is never performed.
- **Implementation effort:** HIGH — requires session-level state machine to buffer partial transactions and merge parameter/data segments on secondary messages.
- **Plan:**
  1. Add a `trans_state` list to `ksmbd_session` to hold in-progress transactions keyed by (UID, MID).
  2. On `smb_trans()` detecting incomplete = true, allocate a `trans_state` entry and park the work item.
  3. Implement `smb_trans_secondary()` in `smb1pdu.c`: validate header fields, locate the pending `trans_state`, merge parameter/data bytes, and when complete dispatch to the normal handler.
  4. Register `smb_trans_secondary` at `SMB_COM_TRANSACTION_SECONDARY` in `smb1ops.c`.

---

### SMB_COM_TRANSACTION2_SECONDARY (0x33)
- **Spec ref:** [MS-CIFS] §2.2.4.47
- **Status:** MISSING
- **Required by spec:** Same reassembly requirement as TRANSACTION_SECONDARY but for TRANS2. Several TRANS2 subcommands (e.g., TRANS2_SET_FILE_INFORMATION with large EA data) can exceed MaxBufferSize and require fragmentation.
- **Current implementation:** None. The opcode is listed in `smb_cmd_str[]` but has no handler.
- **Implementation effort:** HIGH — same as TRANSACTION_SECONDARY above.
- **Plan:** Same as TRANSACTION_SECONDARY, extended for TRANS2. Shared reassembly infrastructure could serve both.

---

### SMB_COM_NT_TRANSACT (0xA0) — Entire Dispatcher
- **Spec ref:** MS-SMB §2.2.4.8, §2.2.7, §3.3.5.11
- **Status:** MISSING
- **Required by spec:** `SMB_COM_NT_TRANSACT` is the backbone of advanced Windows file operations. It is the primary mechanism for NT_TRANSACT_CREATE, NT_TRANSACT_IOCTL (FSCTL operations including copychunk and snapshot enumeration), NT_TRANSACT_NOTIFY_CHANGE, NT_TRANSACT_SET/QUERY_SECURITY_DESC. The spec states the dispatcher MUST be handled per [MS-CIFS] §3.3.5.59 with extensions in §3.3.5.11. The opcode constant `SMB_COM_NT_TRANSACT 0xA0` is defined in `smb1pdu.h:143` and listed in `smb_cmd_str[]` (line 80 of `smb1pdu.c`) but there is NO entry in `smb1_server_cmds[]`.
- **Current implementation:** Any client sending opcode 0xA0 receives no valid response.
- **Implementation effort:** HIGH — requires a full subcommand dispatcher plus individual subcommand handlers.
- **Plan:**
  1. Add `[SMB_COM_NT_TRANSACT] = { .proc = smb_nt_transact }` to `smb1_server_cmds[]` in `smb1ops.c`.
  2. Implement `smb_nt_transact()` in `smb1pdu.c` as a dispatcher that parses the `Function` field and routes to subcommand handlers.
  3. Implement each subcommand (see individual gap entries below).
  4. Also add the `SMB_COM_NT_TRANSACT_SECONDARY` handler for multi-fragment NT_TRANSACT.

---

### NT_TRANSACT_CREATE (0x0001)
- **Spec ref:** MS-SMB §2.2.7.1, §3.3.5.11.4, [MS-CIFS] §3.3.5.59.1
- **Status:** MISSING (requires NT_TRANSACT dispatcher first)
- **Required by spec:** An alternate form of NT_CREATE_ANDX sent via NT_TRANSACT. The spec at §3.3.5.11.4 states that if `MaxParameterCount` in the request is less than the NT_TRANSACT_CREATE response size, the server SHOULD fail with `STATUS_INVALID_SMB`. Extensions add: `NT_CREATE_REQUEST_EXTENDED_RESPONSE` flag, `SECURITY_DELEGATION` impersonation level, `FILE_OPEN_REPARSE_POINT` create option.
- **Current implementation:** None.
- **Implementation effort:** MEDIUM — most logic already exists in `smb_nt_create_andx()`; this subcommand re-exposes it via the NT_TRANSACT wire format.
- **Plan:** Implement `nt_transact_create()` that decodes the NT_Trans_Parameters block, then calls the common create-file logic shared with `smb_nt_create_andx()`. Response must be encoded in NT_TRANSACT response format.

---

### NT_TRANSACT_IOCTL (0x0002)
- **Spec ref:** MS-SMB §2.2.7.2, §3.3.5.11.1, §3.3.5.11.1.1–3
- **Status:** MISSING (requires NT_TRANSACT dispatcher first)
- **Required by spec:** The spec at §3.3.5.11.1 mandates:
  - If `IsFsctl` = 0, SHOULD fail with `STATUS_NOT_SUPPORTED`.
  - Pass-through FSCTLs SHOULD be forwarded to the object store.
  - Undefined FSCTLs MUST NOT be passed through; MUST fail with `STATUS_NOT_SUPPORTED`.
  - `FSCTL_SRV_ENUMERATE_SNAPSHOTS` (§3.3.5.11.1.1): if MaxDataCount too small, MUST fail `STATUS_INVALID_PARAMETER`; MUST return snapshot list.
  - `FSCTL_SRV_REQUEST_RESUME_KEY` (§3.3.5.11.1.2): MUST return 24-byte opaque key.
  - `FSCTL_SRV_COPYCHUNK` (§3.3.5.11.1.3): MUST validate key, validate chunk sizes against `Server.MaxCopyChunks` / `Server.MaxCopyChunkSize` / `Server.MaxTotalCopyChunkSize`, perform the copy and return statistics.
- **Current implementation:** None.
- **Implementation effort:** HIGH — snapshot enumeration requires VFS shadow copy integration; copychunk requires per-file resume key table and chunk-by-chunk I/O.
- **Plan:**
  1. Implement `nt_transact_ioctl()` as a secondary dispatcher on `FunctionCode`.
  2. For `FSCTL_SRV_ENUMERATE_SNAPSHOTS`: enumerate available snapshots via VFS or reject with empty list.
  3. For `FSCTL_SRV_REQUEST_RESUME_KEY`: generate a 24-byte key tied to the open file descriptor.
  4. For `FSCTL_SRV_COPYCHUNK`: validate parameters, iterate chunks, call `vfs_copy_file_range()`.
  5. All others: pass-through if `IsFsctl` is set and FSCTL meets [MS-FSCC] §2.3 criteria; otherwise return `STATUS_NOT_SUPPORTED`.

---

### NT_TRANSACT_SET_SECURITY_DESC (0x0003)
- **Spec ref:** MS-SMB §2.2.7.3, [MS-CIFS] §2.2.7.3
- **Status:** MISSING (requires NT_TRANSACT dispatcher first)
- **Required by spec:** Allows a client to set the security descriptor (owner, group, DACL, SACL, and SMB-extended bits: LABEL, ATTRIBUTE, SCOPE, BACKUP security information flags added in this spec). The MS-SMB spec at §2.2.7.3 adds four additional `SecurityInformation` bit values beyond the base [MS-CIFS] spec.
- **Current implementation:** POSIX ACL set is available in `smb_set_acl()` for TRANS2_SET_PATH_INFORMATION, but Windows-style NT security descriptors via NT_TRANSACT are entirely absent.
- **Implementation effort:** HIGH — requires SECURITY_DESCRIPTOR parsing and mapping to Linux POSIX permissions or SELinux/AppArmor xattrs; the `smbacl.c` subsystem at `src/fs/smbacl.c` provides some infrastructure.
- **Plan:**
  1. Implement `nt_transact_set_security_desc()`: extract `NT_Trans_Data.SecurityDescriptor`, parse owner SID/group SID/DACL/SACL, apply via `ksmbd_vfs_set_sd()` or the existing smbacl machinery.
  2. Honour the extended `SecurityInformation` flags introduced in MS-SMB §2.2.7.3.
  3. Return `STATUS_ACCESS_DENIED` if caller lacks WRITE_DAC/WRITE_OWNER.

---

### NT_TRANSACT_NOTIFY_CHANGE (0x0004)
- **Spec ref:** [MS-CIFS] §2.2.7.4; MS-SMB §2.2.4.8 (general NT_TRANSACT)
- **Status:** MISSING (requires NT_TRANSACT dispatcher first)
- **Required by spec:** The server must support asynchronous directory change notification. The client sends a NOTIFY_CHANGE request specifying a directory FID and completion filter. The server must queue the request and send a response when any matching change occurs in the directory tree (or sub-tree if `WatchTree` is set). The request is cancelled via SMB_COM_NT_CANCEL. ksmbd already has SMB2 change-notify infrastructure in `src/fs/ksmbd_notify.c` (and `.bak`) using Linux fsnotify.
- **Current implementation:** None for SMB1. The SMB2 implementation exists at `src/fs/ksmbd_notify.c.bak` and could be adapted.
- **Implementation effort:** HIGH — requires async work model, fsnotify integration, and proper cancel via `smb_nt_cancel()`.
- **Plan:**
  1. Implement `nt_transact_notify_change()`: validate FID, open directory for watching, install an fsnotify mark.
  2. Do not respond immediately; mark the work as async/pending.
  3. When fsnotify fires, encode a `NT_TRANSACT_NOTIFY_CHANGE` response and send it via `ksmbd_conn_write()`.
  4. Link the pending work to the FID's `ksmbd_file` so `smb_nt_cancel()` can signal cancellation.

---

### NT_TRANSACT_RENAME (0x0005)
- **Spec ref:** [MS-CIFS] §2.2.7.5
- **Status:** MISSING (requires NT_TRANSACT dispatcher first)
- **Required by spec:** Renames or hardlinks a file referenced by FID, with atomic exchange semantics not available in OPEN_ANDX-based rename. Notably this subcommand operates on already-open files.
- **Current implementation:** None. `smb_nt_rename()` at line 74 of `smb1ops.c` handles `SMB_COM_NT_RENAME` (opcode 0xA5 — a different command), not this subcommand.
- **Implementation effort:** MEDIUM — can share rename logic from `smb_nt_rename()` but must decode NT_TRANSACT parameter block and operate on FID.
- **Plan:** Implement `nt_transact_rename()` extracting the FID and new pathname from NT_Trans_Parameters, then call `ksmbd_vfs_rename()`.

---

### NT_TRANSACT_QUERY_SECURITY_DESC (0x0006)
- **Spec ref:** MS-SMB §2.2.7.4, [MS-CIFS] §2.2.7.6
- **Status:** MISSING (requires NT_TRANSACT dispatcher first)
- **Required by spec:** Returns the security descriptor for a file. The MS-SMB spec at §2.2.7.4 adds LABEL, ATTRIBUTE, SCOPE, and BACKUP `SecurityInfoFields` values beyond the base [MS-CIFS] spec. ksmbd has `smb_get_acl()` for POSIX ACLs but nothing for Windows NT security descriptors via NT_TRANSACT.
- **Current implementation:** None.
- **Implementation effort:** HIGH — requires building a SECURITY_DESCRIPTOR from Linux owner UID/GID/mode/xattrs and returning it in the NT_TRANSACT response format.
- **Plan:** Implement `nt_transact_query_security_desc()`: get file stat and optional POSIX ACL, synthesise a `SECURITY_DESCRIPTOR`, return it in the NT_Trans_Data response. The smbacl subsystem (`src/fs/smbacl.c`) should be leveraged.

---

### SMB_COM_NT_TRANSACT_SECONDARY (0xA1)
- **Spec ref:** [MS-CIFS] §2.2.4.63
- **Status:** MISSING
- **Required by spec:** Required to support multi-fragment NT_TRANSACT requests (e.g. NT_TRANSACT_CREATE with a large SecurityDescriptor or EA block). Opcode 0xA1 is listed in `smb_cmd_str[]` (line 81) but not registered in `smb1_server_cmds[]`.
- **Implementation effort:** HIGH — same reassembly state machine needed as TRANSACTION_SECONDARY.
- **Plan:** Implement after the NT_TRANSACT dispatcher; share the reassembly infrastructure with TRANSACTION_SECONDARY and TRANSACTION2_SECONDARY.

---

### TRANS2_GET_DFS_REFERRAL (0x0010)
- **Spec ref:** MS-SMB §1.4 (DFS), [MS-CIFS] §2.2.6.16, [MS-DFSC]
- **Status:** MISSING
- **Required by spec:** The spec at §5 (Capabilities) lists `CAP_DFS` — if the server advertises DFS capability, it MUST respond to TRANS2_GET_DFS_REFERRAL. Currently `smb_trans2()` routes 0x0010 to the `default:` case which returns -EINVAL → STATUS_NOT_SUPPORTED. `CAP_DFS` is NOT advertised in `SMB1_SERVER_CAPS` so this is a lower-priority gap but still prevents DFS-aware clients from discovering namespace configurations.
- **Current implementation:** Falls through to default; returns STATUS_NOT_SUPPORTED.
- **Implementation effort:** HIGH — requires MS-DFSC referral response format; the server-side `ksmbd.mountd` DFS infrastructure is partially present in `src/fs/ksmbd_dfs.c`.
- **Plan:**
  1. Implement `get_dfs_referral()` in `smb1pdu.c` that queries `ksmbd_dfs.c` for the referral data.
  2. Encode the response in [MS-DFSC] `REQ_GET_DFS_REFERRAL` format.
  3. Register in `smb_trans2()` switch.
  4. Optionally advertise `CAP_DFS` once the handler is stable.

---

### TRANS2_REPORT_DFS_INCONSISTENCY (0x0011)
- **Spec ref:** [MS-CIFS] §2.2.6.17
- **Status:** MISSING
- **Required by spec:** Optional; clients send this when they detect an inconsistency in DFS referral information. Servers may ignore it (return success with empty response) but must not crash.
- **Current implementation:** Not in switch; falls to default returning -EINVAL.
- **Implementation effort:** LOW — the server can simply return STATUS_SUCCESS with an empty response (server may silently ignore the report).
- **Plan:** Add a `case TRANS2_REPORT_DFS_INCOSISTENCY:` that returns an empty success response.

---

### Pass-Through Information Levels (Multiple TRANS2 subcommands)
- **Spec ref:** MS-SMB §2.2.2.3.5, §3.3.5.10.1
- **Status:** MISSING (affects TRANS2_QUERY_FS, QUERY_PATH, SET_PATH, QUERY_FILE, SET_FILE, SET_FS)
- **Required by spec:** When `CAP_INFOLEVEL_PASSTHRU` is advertised in the `SMB_COM_NEGOTIATE` response, the server MUST support pass-through Information Levels. A client sends an info level equal to `SMB_INFO_PASSTHROUGH (0x03e8)` + the native object-store level. The server MUST decrement the value by `SMB_INFO_PASSTHROUGH` and pass the remainder directly to the underlying object store. If the server receives a pass-through level but does NOT support it, it MUST return `STATUS_INVALID_PARAMETER`. Currently `CAP_INFOLEVEL_PASSTHRU` is defined (`smb1pdu.h:161`) but is NOT included in `SMB1_SERVER_CAPS`. No TRANS2 subcommand handler checks for info levels >= 0x03e8.
- **Current implementation:** None. If a client sends a pass-through level (>= 0x03e8) to any TRANS2 handler, it hits the `default:` branch and returns `STATUS_NOT_SUPPORTED` or `-EINVAL`.
- **Implementation effort:** MEDIUM — requires adding a passthrough dispatcher to each query/set TRANS2 handler.
- **Plan:**
  1. In each TRANS2 query/set handler's switch on `InformationLevel`, add a pre-check: if `level >= 0x03e8`, subtract 0x03e8 and dispatch to a passthrough handler that calls `vfs_ioctl` or the appropriate kernel information class.
  2. Advertise `CAP_INFOLEVEL_PASSTHRU` in `SMB1_SERVER_CAPS` once passthrough is implemented.
  3. If passthrough is not implemented, ensure `STATUS_INVALID_PARAMETER` (not `STATUS_NOT_SUPPORTED`) is returned.

---

### TRANS2_FIND_FIRST2 — Incomplete Flag / Resume Key Handling
- **Spec ref:** MS-SMB §2.2.6.1, §3.3.5.10.2
- **Status:** PARTIAL
- **Required by spec:**
  - `CIFS_SEARCH_CONTINUE_FROM_LAST` (0x0008) flag: the server must resume from the last-returned entry position. The flag constant is defined at `smb1pdu.h:843` but never checked in `find_first()` or `find_next()`.
  - `SMB_FIND_CLOSE_IF_EOS` (close-if-end-of-search): only `CIFS_SEARCH_CLOSE_AT_END` (0x0002) is checked (lines 6529-6531 and 6765-6767). The CLOSE_IF_EOS flag (0x0004, close the search at end of search results even if not at EOS of directory) is also defined in [MS-CIFS] but not handled.
  - @GMT token in FileName: the spec says if `FileName` contains `@GMT-*`, the InformationLevel SHOULD be `SMB_FIND_FILE_BOTH_DIRECTORY_INFO` and the server MAY return an enumeration of previous versions (snapshot entries). ksmbd does none of this.
  - `RETURN_RESUME_KEYS` flag: the `ResumeKey` field in `file_unix_info` (line 6212) is always set to 0; actual resume key tracking is not implemented.
- **Current implementation:** Only `CIFS_SEARCH_CLOSE_AT_END` flag is honoured. ResumeKey is hardcoded to 0. @GMT tokens are not parsed.
- **Implementation effort:** MEDIUM (flags) / HIGH (@GMT tokens + snapshot enumeration)
- **Plan:**
  1. Add handling for `CIFS_SEARCH_CONTINUE_FROM_LAST` in `find_next()` using the `ResumeKey` or `ResumeFileName` field to position the readdir cursor at the correct entry.
  2. For @GMT tokens: parse the `FileName` pattern for `@GMT-*` and if found, return `STATUS_NOT_SUPPORTED` or forward to snapshot enumeration (requires `FSCTL_SRV_ENUMERATE_SNAPSHOTS` from NT_TRANSACT_IOCTL).
  3. Track a per-`dir_fp` resume position keyed by the last `NextEntryOffset` so it can be restored.

---

### SMB_COM_NT_CANCEL — Incomplete for Sleeping Locks
- **Spec ref:** [MS-CIFS] §2.2.4.69, MS-SMB §3.3.5.x
- **Status:** PARTIAL
- **Required by spec:** The server MUST cancel any pending request for the given MID. `smb_nt_cancel()` (lines 8183–8208) finds the matching work item in `conn->requests` by MID and sets `send_no_response`. However, this only works for work items that have not yet blocked. For work items that have entered the `goto wait:` loop in `smb_locking_andx()` (line 1967), the cancel will find the work has already been dequeued from `conn->requests`. The sleeping lock wait will not be interrupted.
- **Current implementation:** Only catches requests still in the request queue. Sleeping lock waits continue indefinitely after cancel.
- **Implementation effort:** MEDIUM — requires a per-work cancellation flag checked in the lock wait loop.
- **Plan:**
  1. Add `work->cancelled` atomic flag.
  2. In `smb_nt_cancel()`, after searching `conn->requests`, also search `conn->lock_list` (or a separate pending-locks list) and set the `cancelled` flag on matching work.
  3. In the `goto wait:` loop of `smb_locking_andx()`, check `work->cancelled` after each `ksmbd_vfs_posix_lock_wait_timeout()` and break out with `STATUS_CANCELLED`.

---

### SMB_COM_TRANSACTION — Named-Pipe Subcommand Coverage
- **Spec ref:** [MS-CIFS] §2.2.4.33, §2.2.5.x; MS-SMB §2.2.5
- **Status:** PARTIAL
- **Required by spec:** `smb_trans()` handles:
  - LANMAN RAP (\\PIPE\\LANMAN) — routes to `ksmbd_rpc_rap()`.
  - `TRANSACT_DCERPCCMD` (0x0026) — routes to `ksmbd_rpc_ioctl()`.
  All other named-pipe subcommands listed in [MS-CIFS] §2.2.5 are returned as `STATUS_NOT_SUPPORTED`. MS-SMB §2.2.5 marks `TRANS_RAW_READ_NMPIPE` and `TRANS_CALL_NMPIPE` as **obsolescent** (not deprecated), meaning servers may need to implement them for legacy interop. Key missing subcommands:
  - `TRANS_SET_NMPIPE_STATE` (0x0001)
  - `TRANS_QUERY_NMPIPE_STATE` (0x0021)
  - `TRANS_QUERY_NMPIPE_INFO` (0x0022)
  - `TRANS_PEEK_NMPIPE` (0x0023)
  - `TRANS_WRITE_NMPIPE` (0x0037)
  - `TRANS_READ_NMPIPE` (0x0036)
  - `TRANS_WAIT_NMPIPE` (0x0053)
- **Current implementation:** Only LANMAN and DCERPCCMD are handled; all others return STATUS_NOT_SUPPORTED.
- **Implementation effort:** MEDIUM per subcommand (most delegate to the existing RPC framework).
- **Plan:** For each missing subcommand, implement a handler that routes to the appropriate `ksmbd_rpc_*` call (e.g., `ksmbd_rpc_read()`, `ksmbd_rpc_write()`). The session's open pipe FID (`pipe_req->fid`) is already extracted in `smb_trans()`.

---

### SMB_COM_SEARCH (0x81)
- **Spec ref:** MS-SMB §2.2.4.10, §3.3.5.9; [MS-CIFS] §2.2.4.58
- **Status:** MISSING
- **Required by spec:** The legacy directory search command (pre-TRANS2). MS-SMB §3.3.5.9 adds: if `FileName` is an empty string, the server SHOULD return the root directory information. The command is not obsolete in MS-SMB; it remains "current" status and must be supported for compatibility with MS-DOS and Win 3.x clients.
- **Current implementation:** Not in `smb1_server_cmds[]`. Client receives `STATUS_SMB_BAD_COMMAND`.
- **Implementation effort:** MEDIUM — uses the older SMB_INFO_STANDARD directory-entry format; can be built on top of the existing readdir infrastructure used by `find_first()`.
- **Plan:**
  1. Define `SMB_COM_SEARCH 0x81` (already defined in `smb1pdu.h:142` as `SMB_COM_QUERY_INFORMATION_DISK` — note: **WRONG**, `SMB_COM_QUERY_INFORMATION_DISK` is 0x80; confirm opcode 0x81 is SEARCH vs. the existing 0x80 definition). Verify the opcode and define properly.
  2. Implement `smb_search()` using the `SMB_INFO_STANDARD` format, pattern matching, and the existing page-based readdir loop.
  3. Handle the special case: empty `FileName` → return root directory entry.
  4. Register in `smb1ops.c`.

---

### Print File Commands (0x3D, 0x43, 0x44, 0x45)
- **Spec ref:** [MS-CIFS] §2.2.4.50–53
- **Status:** MISSING
- **Required by spec:** These commands enable print-queue access over SMB. They are optional for non-printer shares but are referenced in MS-SMB §3.2 as supported by Windows clients for printer shares. The spec at line 15345 notes Windows-based SMB clients use `SMB_COM_OPEN_PRINT_FILE`.
  - `SMB_COM_GET_PRINT_QUEUE (0x3D)`: Return list of print jobs.
  - `SMB_COM_OPEN_PRINT_FILE (0x43)`: Open a spool file for writing.
  - `SMB_COM_WRITE_PRINT_FILE (0x44)`: Write data to an open spool file.
  - `SMB_COM_CLOSE_PRINT_FILE (0x45)`: Close and submit the spool file.
- **Current implementation:** None. These commands are not in `smb1_server_cmds[]`.
- **Implementation effort:** MEDIUM — can use ksmbd's existing VFS file I/O; no special kernel printer integration required; the spool file can be a regular temporary file.
- **Plan:**
  1. Implement `smb_open_print_file()`: create a temporary spool file and return a FID.
  2. Implement `smb_write_print_file()`: write data to the spool FID.
  3. Implement `smb_close_print_file()`: close the spool FID; optionally submit to `lp` via userspace.
  4. Implement `smb_get_print_queue()`: return an empty or stub queue; requires interface to spooler.
  5. Register all four in `smb1ops.c`.

---

### SMB_COM_IOCTL (0x27)
- **Spec ref:** [MS-CIFS] §2.2.4.34
- **Status:** MISSING
- **Required by spec:** Generic I/O control for device-specific operations. Most uses are obsolescent in modern clients, but it is referenced for pipe operations. The server may return `STATUS_NOT_IMPLEMENTED` for unknown IOCTL codes.
- **Current implementation:** Not in `smb1_server_cmds[]`.
- **Implementation effort:** LOW — can return STATUS_NOT_IMPLEMENTED for all codes as a correct stub.
- **Plan:** Implement a minimal `smb_ioctl()` that returns `STATUS_NOT_IMPLEMENTED` for all received codes, ensuring clients don't hang. Register in `smb1ops.c`.

---

### SMB_COM_SET_INFORMATION2 (0x22)
- **Spec ref:** [MS-CIFS] §2.2.4.18
- **Status:** MISSING
- **Required by spec:** Sets extended file attribute timestamps (creation, last-access, last-write). Used by older Windows clients. Not present in any constant or handler.
- **Current implementation:** None.
- **Implementation effort:** LOW — simple timestamp update via `ksmbd_vfs_setattr()`.
- **Plan:**
  1. Define `SMB_COM_SET_INFORMATION2 0x22` in `smb1pdu.h`.
  2. Implement `smb_set_information2()`: extract the three DOS date/time fields, convert to `timespec64`, call `ksmbd_vfs_setattr()`.
  3. Register in `smb1ops.c`.

---

## Key Cross-Cutting Issues

### 1. CAP_LOCK_AND_READ Advertised Without Implementation
`SMB1_SERVER_CAPS` in `src/include/protocol/smb1pdu.h:27` includes `CAP_LOCK_AND_READ`, but no handler for opcode 0x13 exists anywhere in the codebase. Clients that negotiate this capability and attempt SMB_COM_LOCK_AND_READ will receive an error, which is a protocol violation. Either implement the handler or remove the capability bit.

### 2. No Pass-Through Information Level Support
`CAP_INFOLEVEL_PASSTHRU` is defined but not advertised. All TRANS2 query/set handlers lack pass-through logic. Per MS-SMB §3.3.5.10.1, if the capability IS advertised, the server MUST handle pass-through levels. Since it is not currently advertised, this is not a present violation but is a missing feature that modern clients (Windows Vista+) rely on.

### 3. SMB_COM_NT_TRANSACT Entirely Absent
With no NT_TRANSACT dispatcher, ksmbd silently fails (or returns STATUS_SMB_BAD_COMMAND) for a large class of Windows file operations: security descriptor get/set, FSCTL operations (copychunk, snapshot enumeration), directory change notification, and the NT_TRANSACT_CREATE alternative open path. This is the highest-impact gap for Windows client interoperability.

### 4. Multi-Fragment Transaction Support Missing
All three TRANSACTION/TRANSACTION2/NT_TRANSACT secondary commands are absent. If any TRANS2 request exceeds the negotiated MaxBufferSize, the client must send a secondary packet. ksmbd will not recognize it and the transaction will stall. This affects large EA operations, large SET_FILE_INFORMATION payloads, and large security-descriptor SET operations.
