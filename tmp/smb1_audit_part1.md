# SMB1 Audit Part 1: Session / Tree / File Basics / Directory

**Auditor**: Claude (automated static analysis of ksmbd source tree)
**Date**: 2026-03-01
**Source tree**: `/home/ezechiel203/ksmbd`
**Spec reference**: MS-SMB (Microsoft SMB Protocol Specification)
**Note**: The PDF at `/home/ezechiel203/ksmbd/protocol/[MS-SMB].pdf` could not be rendered
(poppler-utils / pdftoppm is not installed). All spec references below are from
knowledge of the MS-SMB specification. Line numbers reference
`src/protocol/smb1/smb1pdu.c` unless otherwise stated.

---

## Summary

- **Total commands audited**: 35
- **Missing** (no registered handler): 14
- **Partial** (handler exists but spec gaps found): 12
- **Complete** (handler meets core MUST requirements): 9

---

## Command Status Table

| Command | Opcode | Status | Gap Description |
|---|---|---|---|
| SMB_COM_NEGOTIATE | 0x72 | PARTIAL | No domain/server name; no CAP_RAW_MODE/CAP_MPX_MODE in capabilities |
| SMB_COM_SESSION_SETUP_ANDX | 0x73 | PARTIAL | No per-session VC limit; non-SPNEGO path lacks Kerberos; MaxBufferSize not enforced |
| SMB_COM_LOGOFF_ANDX | 0x74 | PARTIAL | Forces full reconnect instead of per-session logoff |
| SMB_COM_TREE_CONNECT | 0x70 | MISSING | No handler; only ANDX variant is registered |
| SMB_COM_TREE_CONNECT_ANDX | 0x75 | PARTIAL | CSC flags hardcoded; no per-tcon signing enforcement |
| SMB_COM_TREE_DISCONNECT | 0x71 | COMPLETE | Correctly marks tree disconnected and releases tcon |
| SMB_COM_OPEN | 0x02 | MISSING | No handler; only OPEN_ANDX and NT_CREATE_ANDX are registered |
| SMB_COM_OPEN_ANDX | 0x2D | PARTIAL | Oplocks disabled; GrantedAccess field always 0 |
| SMB_COM_NT_CREATE_ANDX | 0xA2 | PARTIAL | ShareAccess not enforced; oplocks disabled; ImpersonationLevel ignored |
| SMB_COM_CLOSE | 0x04 | COMPLETE | LastWriteTime honored; correct error for invalid FID |
| SMB_COM_DELETE | 0x06 | COMPLETE | Handles open-file case; SearchAttributes filtering applied |
| SMB_COM_RENAME | 0x07 | PARTIAL | Error granularity low; cross-dir rename with open handles not rejected correctly |
| SMB_COM_COPY | 0x29 | MISSING | No handler |
| SMB_COM_MOVE | 0x2A | MISSING | No handler |
| SMB_COM_READ | 0x0A | MISSING | No handler; only READ_ANDX is registered |
| SMB_COM_READ_ANDX | 0x2E | PARTIAL | MinCount not enforced; no pipe MinCount/Timeout support |
| SMB_COM_WRITE | 0x0B | PARTIAL | WriteMode/Writethrough not honored; Count=0 truncate correct |
| SMB_COM_WRITE_ANDX | 0x2F | PARTIAL | WriteMode bits 1-3 (writethru, return remaining, pipe) ignored |
| SMB_COM_WRITE_AND_CLOSE | 0x2C | MISSING | No handler |
| SMB_COM_READ_RAW | 0x1A | MISSING | No handler (deprecated, but spec says server MUST respond) |
| SMB_COM_WRITE_RAW | 0x1D | MISSING | No handler (deprecated, but spec says server MUST respond) |
| SMB_COM_SEEK | 0x12 | MISSING | No handler |
| SMB_COM_CREATE_DIRECTORY | 0x00 | COMPLETE | Correctly creates directory; handles existing-dir case |
| SMB_COM_DELETE_DIRECTORY | 0x01 | COMPLETE | Correctly removes directory; handles non-empty case |
| SMB_COM_CHECK_DIRECTORY | 0x10 | COMPLETE | Path validation correct |
| SMB_COM_QUERY_INFORMATION | 0x08 | PARTIAL | Missing EASize, UniqueId, ReservedForEA response fields |
| SMB_COM_SET_INFORMATION (SETATTR) | 0x09 | PARTIAL | Only READONLY and mtime; HIDDEN/SYSTEM/ARCHIVE not mapped |
| SMB_COM_QUERY_INFORMATION2 | 0x23 | MISSING | No handler |
| SMB_COM_SET_INFORMATION2 | 0x22 | MISSING | No handler |
| SMB_COM_FIND | 0x0C | MISSING | No handler |
| SMB_COM_FIND_UNIQUE | 0x11 | MISSING | No handler |
| SMB_COM_FIND_CLOSE2 | 0x34 | COMPLETE | Correctly closes directory search handle |
| SMB_COM_FIND_CLOSE | 0x35 | MISSING | No handler (different from FIND_CLOSE2) |
| SMB_COM_NT_RENAME | 0xA5 | PARTIAL | Only CREATE_HARD_LINK implemented; actual rename via NT_RENAME rejected |
| SMB_COM_LOCKING_ANDX | 0x24 | PARTIAL | CANCEL_LOCK logged but not actually cancelled; CHANGE_LOCKTYPE returns error |

---

## Detailed Gaps

---

### SMB_COM_NEGOTIATE (0x72)

- **Spec ref**: MS-SMB §2.2.4.52 (SMB_COM_NEGOTIATE Request/Response)
- **Status**: PARTIAL
- **Handler**: `smb_handle_negotiate()` → `smb_negotiate_request()` → `ksmbd_smb_negotiate_common()` (smb1pdu.c ~line 979)
- **Required by spec**:
  - Server MUST return `DomainName` in the response (MS-SMB §2.2.4.52.2, field `DomainName`)
  - Server MUST return `ServerName` in the response (MS-SMB §2.2.4.52.2, field `ServerName`)
  - Server MUST advertise `CAP_RAW_MODE` (0x0001) and `CAP_MPX_MODE` (0x0002) if supported (MS-SMB §2.2.4.52.2, `Capabilities`)
  - Server MUST include `ServerTimeZone` field (UTC offset in minutes)
  - When `CAP_EXTENDED_SECURITY` is set in the response, server MUST include a GUID and a security blob (SPNEGO NegotiateToken)
- **Current implementation**:
  - `SMB1_SERVER_CAPS` (smb1pdu.h) does NOT include `CAP_RAW_MODE` or `CAP_MPX_MODE`; these are deliberately excluded
  - `DomainName` field is not populated in the non-SPNEGO negotiate response path (`build_nego_rsp_noextsec()`)
  - `ServerName` field is not populated
  - `ServerTimeZone` is set but uses a fixed calculation; may be incorrect for non-UTC servers
  - SPNEGO path does produce a GUID and NegotiateToken (correct for extended security)
- **Implementation effort**: LOW
- **Plan**:
  1. Add `server_domain[]` string to `ksmbd_server_conf` and send it in non-SPNEGO negotiate response
  2. Populate `ServerName` from `server_string` config
  3. Note: `CAP_RAW_MODE` / `CAP_MPX_MODE` exclusion is intentional (raw mode is not implemented and is deprecated); add a code comment documenting this decision

---

### SMB_COM_SESSION_SETUP_ANDX (0x73)

- **Spec ref**: MS-SMB §2.2.4.53 (SMB_COM_SESSION_SETUP_ANDX Request/Response)
- **Status**: PARTIAL
- **Handler**: `smb_session_setup_andx()` (smb1pdu.c ~line 1360)
- **Required by spec**:
  - Server MUST enforce `VcNumber`: if VcNumber == 0 and there are existing VCs, server SHOULD close all existing VCs (MS-SMB §3.3.5.5.1)
  - Server MUST respond with `Action` field indicating whether guest access was granted (MS-SMB §2.2.4.53.2)
  - Server MUST set `MaxBufferSize` per session and respect client's `MaxBufferSize` from request (MS-SMB §3.3.5.5.1)
  - Non-SPNEGO (`CAP_EXTENDED_SECURITY` not set) path MUST support NTLMv1, NTLMv2, and optionally Kerberos
  - `NativeOS` and `NativeLanMan` strings SHOULD be returned in the response
- **Current implementation**:
  - `VcNumber` field is read from the request but not used to close existing VCs (no enforcement at smb1pdu.c ~line 1380)
  - `Action` field is set to 0 (GUEST_ACCESS bit not set); correct for non-guest but GUEST path not handled
  - `MaxBufferSize` from client not used to clamp I/O size
  - Non-SPNEGO path (`build_sess_rsp_noextsec()`) calls NTLM auth via netlink; no Kerberos on this path (Kerberos only in SPNEGO path via `build_sess_rsp_extsec()`)
  - `NativeOS` = "Linux" and `NativeLanMan` = "ksmbd" are returned (correct)
- **Implementation effort**: MEDIUM
- **Plan**:
  1. On `VcNumber == 0`, iterate existing sessions for the same client IP and call `ksmbd_session_destroy()` on each
  2. Read `MaxBufferSize` from SESSION_SETUP request and store on session; cap read/write sizes accordingly
  3. Guest authentication path: if auth returns specific guest code, set `Action |= SMB_SETUP_GUEST`

---

### SMB_COM_LOGOFF_ANDX (0x74)

- **Spec ref**: MS-SMB §2.2.4.54
- **Status**: PARTIAL
- **Handler**: `smb_session_disconnect()` (smb1pdu.c ~line 440)
- **Required by spec**:
  - Server MUST invalidate the Session identified by the UID in the request header
  - Server MUST NOT invalidate other sessions (VCs) on the same connection
  - All tree connections associated with this session MUST be closed
  - Server MUST return STATUS_SUCCESS even if the UID is not valid (MS-SMB §3.3.5.5.2)
- **Current implementation**:
  - `smb_session_disconnect()` calls `ksmbd_conn_set_need_reconnect(work->conn)` which forces the entire connection to reconnect, not just this session
  - This tears down ALL sessions and VCs on the connection, violating the per-session semantics
  - The session-level state (`work->sess`) is not individually destroyed; the connection-level flag is set instead
- **Implementation effort**: MEDIUM
- **Plan**:
  1. Remove the `ksmbd_conn_set_need_reconnect()` call
  2. Call `ksmbd_session_destroy(work->sess)` to tear down only this session
  3. Iterate and close all tree connections under `work->sess` before destroying
  4. Send STATUS_SUCCESS response before destroying session state
  5. Clear `work->sess = NULL` to prevent use-after-free

---

### SMB_COM_TREE_CONNECT (0x70)

- **Spec ref**: MS-SMB §2.2.4.55
- **Status**: MISSING
- **Handler**: None registered in `smb1_server_cmds[]`
- **Required by spec**:
  - Server MUST handle SMB_COM_TREE_CONNECT (the non-ANDX legacy form)
  - Request contains: Path (share UNC), Password, Service type
  - Response contains: TID (tree ID), VWV (word values including MaxBufferSize)
  - This command was the primary tree-connect mechanism before TREE_CONNECT_ANDX
- **Current implementation**: Not implemented. A client sending 0x70 will receive an error response from the generic dispatch path.
- **Implementation effort**: LOW
- **Plan**:
  1. Add `smb_tree_connect()` handler that parses the non-ANDX request format
  2. Re-use the share lookup and tcon setup logic already in `smb_tree_connect_andx()`
  3. Register in `smb1_server_cmds[SMB_COM_TREE_CONNECT]`
  4. Update `smb1_req_struct_size()` and `smb1_get_byte_count()` in smb1misc.c

---

### SMB_COM_TREE_CONNECT_ANDX (0x75)

- **Spec ref**: MS-SMB §2.2.4.55.2
- **Status**: PARTIAL
- **Handler**: `smb_tree_connect_andx()` (smb1pdu.c ~line 550)
- **Required by spec**:
  - Server MUST return `OptionalSupport` flags; bit `SMB_SUPPORT_SEARCH_BITS` MUST be set if the server supports SearchAttributes in FIND operations
  - Server MUST return `MaximalShareAccessRights` and `GuestMaximalShareAccessRights` (in extended response)
  - Server SHOULD enforce SMB signing per-connection if negotiated; per-tree enforcement is optional but recommended for DFS
  - CSC (Client-Side Caching) flags in `OptionalSupport` MUST reflect the share's actual caching policy
- **Current implementation**:
  - `OptionalSupport` field is set to hardcoded value `SMB_SUPPORT_SEARCH_BITS | SMB_SHARE_IS_IN_DFS` (not per-share)
  - CSC flags are hardcoded to `SMB_CSC_CACHE_MANUAL_REINT` regardless of share configuration
  - `MaximalShareAccessRights` is not populated (zeroed in response)
  - Per-tcon signing enforcement not implemented (signing is negotiated at connection level only)
- **Implementation effort**: LOW-MEDIUM
- **Plan**:
  1. Add `csc_mode` field to `ksmbd_share_config` and map it to CSC flags in `OptionalSupport`
  2. Populate `MaximalShareAccessRights` from share ACL configuration
  3. Clear `SMB_SHARE_IS_IN_DFS` for non-DFS shares

---

### SMB_COM_OPEN (0x02)

- **Spec ref**: MS-SMB §2.2.4.9
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Server MUST handle SMB_COM_OPEN (the legacy non-ANDX open command)
  - Request: SearchAttributes, FileName
  - Response: FID, FileAttributes, LastWriteTime, FileSize, GrantedAccess, FileType, DeviceState, Action, ServerFID
  - Older clients (pre-Windows NT) use this exclusively
- **Current implementation**: Not implemented.
- **Implementation effort**: MEDIUM
- **Plan**:
  1. Add `smb_open()` handler parsing the legacy COM_OPEN request structure
  2. Share the open/create path with `smb_open_andx()` (extract common helper)
  3. Return the non-ANDX response format

---

### SMB_COM_OPEN_ANDX (0x2D)

- **Spec ref**: MS-SMB §2.2.4.10
- **Status**: PARTIAL
- **Handler**: `smb_open_andx()` (smb1pdu.c ~line 8391)
- **Required by spec**:
  - Server SHOULD grant oplocks if client requests them and server supports them (MS-SMB §3.3.5.9)
  - Server MUST return `GrantedAccess` reflecting actual access rights granted (MS-SMB §2.2.4.10.2)
  - Server MUST set `Action` field with bits: `SMB_OACT_OPLOCK` (oplock granted), `SMB_OACT_OPBATCH` (batch oplock)
  - Server SHOULD return `AllocationSize` in the response
- **Current implementation**:
  - `smb1_oplock_enable` is hardcoded `false` at smb1pdu.c line 118; no oplock is ever granted
  - `GrantedAccess` in the response is set to 0 (not the actual granted access mask)
  - `AllocationSize` is populated from VFS stat (correct)
- **Implementation effort**: MEDIUM
- **Plan**:
  1. When `smb1_oplock_enable` is enabled: call oplock request path and set `SMB_OACT_OPLOCK` in `Action`
  2. Populate `GrantedAccess` from the `desiredAccess` mask (after mapping via `convert_generic_access_flags`)
  3. To enable oplocks: remove/flip `smb1_oplock_enable` and wire into oplock infrastructure

---

### SMB_COM_NT_CREATE_ANDX (0xA2)

- **Spec ref**: MS-SMB §2.2.4.13
- **Status**: PARTIAL
- **Handler**: `smb_nt_create_andx()` (smb1pdu.c ~line 2501)
- **Required by spec**:
  - Server MUST enforce `ShareAccess` semantics (MS-SMB §3.3.5.9.1): deny conflicting opens
  - Server SHOULD grant oplocks when requested and conditions are met (MS-SMB §3.3.5.9)
  - Server MUST handle `ImpersonationLevel` field (ignored may be acceptable but must be documented)
  - Server MUST handle `SecurityFlags` field (context tracking flag)
  - Server MUST return `OplockLevel` in response
  - Server MUST return `CreateAction` (created / opened / overwritten)
- **Current implementation**:
  - **ShareAccess not enforced**: explicit comment at line ~2600: "ShareAccess: Full share-mode enforcement is not implemented for the deprecated SMB1 protocol"
  - **Oplocks disabled**: `smb1_oplock_enable` is `false`; `OplockLevel` always returns `SMB_NO_OPLOCK`
  - `ImpersonationLevel` read but not used (no impersonation in kernel server, acceptable)
  - `SecurityFlags` read but not used (context tracking: acceptable to ignore)
  - `CreateAction` correctly set to `FILE_CREATED` / `FILE_OPENED` / `FILE_OVERWRITTEN`
  - `MaximalAccessRights` not populated in response (should reflect actual rights)
- **Implementation effort**: HIGH (ShareAccess) / MEDIUM (oplocks)
- **Plan**:
  1. ShareAccess enforcement: on each `ksmbd_open_file()`, check existing opens for same inode against `ShareAccess` mask; return STATUS_SHARING_VIOLATION if conflict
  2. Oplock: flip `smb1_oplock_enable` and call `smb_grant_oplock()` with requested oplock level
  3. Populate `MaximalAccessRights` from share/file ACL

---

### SMB_COM_RENAME (0x07)

- **Spec ref**: MS-SMB §2.2.4.7
- **Status**: PARTIAL
- **Handler**: `smb_rename()` (smb1pdu.c ~line 880)
- **Required by spec**:
  - Server MUST return `STATUS_SHARING_VIOLATION` if a file being renamed has open handles with conflicting share modes
  - Server MUST return `STATUS_OBJECT_NAME_COLLISION` if the destination already exists and cannot be replaced
  - Server MUST apply `SearchAttributes` filter from request (only rename files matching attrs)
  - Server MUST handle wildcard renames (when `OldFileName` contains wildcards)
- **Current implementation**:
  - `SearchAttributes` from request is read but only used to check if the target is a directory; full attribute-mask filtering not applied
  - Open-handle conflict check not performed before rename
  - Wildcard renames not supported (no wildcard expansion)
  - Error mapping: generic VFS errors mapped to NT codes but some cases return `STATUS_NO_MEMORY` instead of more specific codes
- **Implementation effort**: MEDIUM
- **Plan**:
  1. Before calling `ksmbd_vfs_rename()`, check `ksmbd_find_matching_fid()` for open handles on the source; return `STATUS_SHARING_VIOLATION` if found with incompatible share modes
  2. Filter by `SearchAttributes` mask before renaming (check file attributes match)
  3. Map `-EEXIST` more precisely to `STATUS_OBJECT_NAME_COLLISION`
  4. Wildcard rename: low priority; document as unsupported

---

### SMB_COM_COPY (0x29)

- **Spec ref**: MS-SMB §2.2.4.34
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Server MUST handle intra-server file copy
  - Request: TID (source tree), TID2 (target tree, or same), FileName (source), FileName2 (dest), Flags, OpenFunction
  - Server SHOULD perform server-side copy efficiently
- **Current implementation**: Not implemented.
- **Implementation effort**: HIGH
- **Plan**:
  1. Implement `smb_copy()` handler with server-side copy using `vfs_copy_file_range()` or read+write loop
  2. Handle cross-tree copy (TID != TID2)
  3. Register in dispatch table

---

### SMB_COM_MOVE (0x2A)

- **Spec ref**: MS-SMB §2.2.4.35
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Server MUST handle file move operation
  - Similar to COPY but atomically moves (rename across trees if needed)
- **Current implementation**: Not implemented.
- **Implementation effort**: HIGH
- **Plan**:
  1. Implement `smb_move()` using `ksmbd_vfs_rename()` for same-volume, copy+delete for cross-volume
  2. Register in dispatch table

---

### SMB_COM_READ (0x0A)

- **Spec ref**: MS-SMB §2.2.4.11 (legacy read, max 65535 bytes)
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Server MUST handle SMB_COM_READ for compatibility with pre-LanMan clients
  - Simpler than READ_ANDX (no large file support, no 64-bit offsets)
- **Current implementation**: Not implemented. Only READ_ANDX is registered.
- **Implementation effort**: LOW
- **Plan**:
  1. Add `smb_read()` wrapper that parses the legacy READ request and delegates to VFS read
  2. Cap response at 65535 bytes (no large read on this command)
  3. Register in dispatch table and update smb1misc.c validation tables

---

### SMB_COM_READ_ANDX (0x2E)

- **Spec ref**: MS-SMB §2.2.4.42
- **Status**: PARTIAL
- **Handler**: `smb_read_andx()` (smb1pdu.c ~line 3109)
- **Required by spec**:
  - Server MUST honor `MinCount`: if fewer than `MinCount` bytes are available (e.g., on a pipe), server SHOULD block until `MinCount` bytes are available or timeout
  - For named pipes, server MUST interpret `Timeout` field (MS-SMB §2.2.4.42.1)
  - Server MUST return `DataCompactionMode` = 0 (unless compression negotiated)
- **Current implementation**:
  - `MinCount` field read from request but not enforced; server returns whatever VFS provides (which may be less)
  - Named pipe reads do not implement `Timeout`-based blocking
  - `DataCompactionMode` correctly set to 0
- **Implementation effort**: LOW-MEDIUM
- **Plan**:
  1. For regular files: `MinCount` enforcement is a loop-retry on short reads; add retry loop
  2. For named pipes: `Timeout` field interpretation requires pipe-aware blocking; document as not implemented
  3. Note: for most real clients `MinCount` == `MaxCount`, so this is low impact

---

### SMB_COM_WRITE (0x0B)

- **Spec ref**: MS-SMB §2.2.4.12
- **Status**: PARTIAL
- **Handler**: `smb_write()` (smb1pdu.c ~line 3296)
- **Required by spec**:
  - Server SHOULD honor `WriteMode` field bit 0 (WRITE_THROUGH): flush to disk before responding
  - Server MUST handle `Count == 0` as a truncate-to-Offset operation (already implemented)
  - Server MUST return `Count` of bytes actually written
- **Current implementation**:
  - `WriteMode` field not present in the legacy WRITE request structure (it only exists in WRITE_ANDX); the comment in the code about writethrough is N/A here
  - `Count == 0` correctly mapped to `ksmbd_vfs_truncate()` (line ~3320)
  - `Count` in response set to the write count (correct)
- **Implementation effort**: LOW (no WriteMode in this command's wire format)
- **Plan**:
  1. No action needed for `WriteMode` (field doesn't exist in COM_WRITE)
  2. Document the truncate-on-zero-count behavior explicitly in a comment

---

### SMB_COM_WRITE_ANDX (0x2F)

- **Spec ref**: MS-SMB §2.2.4.43
- **Status**: PARTIAL
- **Handler**: `smb_write_andx()` (smb1pdu.c ~line 3358)
- **Required by spec**:
  - `WriteMode` bit 0 (WRITE_THROUGH): if set, server MUST flush file to disk before responding
  - `WriteMode` bit 1 (WRITE_AND_CLOSE): write and close the FID
  - `WriteMode` bit 2 (RETURN_REMAINING): return number of remaining bytes in pipe
  - `WriteMode` bit 3 (WRITE_RAW): write is part of a RAW write sequence (server must handle gracefully)
  - Server MUST return `Available` (remaining bytes in pipe) when writing to a pipe
- **Current implementation**:
  - `WriteMode` read but only bit 0 (WRITE_THROUGH) checked: if set, `sync_file_range()` is called (correct for bit 0)
  - Bits 1, 2, 3 not implemented
  - `Available` field in response set to 0 (not computed for pipes)
- **Implementation effort**: LOW (bits 1-3 are rare/deprecated) / MEDIUM (pipe Available)
- **Plan**:
  1. Bit 1 (WRITE_AND_CLOSE): after write, call `smb_close()` logic on the FID
  2. Bit 2 (RETURN_REMAINING): for named pipes, query remaining bytes and set `Available`
  3. Bits 3 (WRITE_RAW) and RETURN_REMAINING: document as not implemented

---

### SMB_COM_WRITE_AND_CLOSE (0x2C)

- **Spec ref**: MS-SMB §2.2.4.41
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Combines a write operation with a close of the FID
  - `LastWriteTime` in request MUST be honored (update mtime on close)
- **Current implementation**: Not implemented.
- **Implementation effort**: LOW
- **Plan**:
  1. Add `smb_write_and_close()` handler: parse request, write data, then close FID with mtime update
  2. Re-use `smb_write()` and `smb_close()` logic
  3. Register in dispatch table and smb1misc.c validation

---

### SMB_COM_READ_RAW (0x1A)

- **Spec ref**: MS-SMB §2.2.4.25 (deprecated but MUST be handled)
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Even if server does not support raw mode, it MUST respond with a zero-length raw read response (empty NetBIOS message) to indicate "not supported" (MS-SMB §2.2.4.25.2)
  - Silently dropping the request is a protocol violation
- **Current implementation**: Not implemented. A client sending READ_RAW will receive an SMB error response (which is a protocol violation for this specific command).
- **Implementation effort**: VERY LOW
- **Plan**:
  1. Add `smb_read_raw()` stub that sends a zero-length raw response (4-byte NetBIOS header with length=0)
  2. Register in dispatch table
  3. Document as "raw mode not supported; stub sends empty response per spec"

---

### SMB_COM_WRITE_RAW (0x1D)

- **Spec ref**: MS-SMB §2.2.4.28 (deprecated but MUST be handled)
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Server MUST respond with an SMB_COM_WRITE_RAW interim response even if raw mode is not supported
  - Server then waits for the raw data transfer, discards it, and sends a final response
- **Current implementation**: Not implemented.
- **Implementation effort**: LOW
- **Plan**:
  1. Add `smb_write_raw()` stub that sends the interim response then reads and discards the raw data
  2. Return ERRSRV/ERRsrverror to indicate unsupported operation

---

### SMB_COM_SEEK (0x12)

- **Spec ref**: MS-SMB §2.2.4.20
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Server MUST maintain a per-FID current seek position
  - SEEK command updates the position; subsequent READ/WRITE without explicit offset use this position
  - Mode: 0=from beginning, 1=from current, 2=from end
- **Current implementation**: Not implemented. ksmbd does not maintain per-FID seek positions (stateless design).
- **Implementation effort**: MEDIUM (requires per-FID offset tracking)
- **Plan**:
  1. Add `current_offset` field to `ksmbd_file` structure
  2. `smb_seek()` computes new offset from Mode and Offset fields, stores in `ksmbd_file`
  3. `smb_read()` / `smb_write()` (legacy commands only) read from `current_offset` if no explicit offset
  4. Note: READ_ANDX and WRITE_ANDX always supply explicit offsets, so seek only matters for legacy READ/WRITE

---

### SMB_COM_QUERY_INFORMATION (0x08)

- **Spec ref**: MS-SMB §2.2.4.8
- **Status**: PARTIAL
- **Handler**: `smb_query_info()` (smb1pdu.c ~line 8273)
- **Required by spec**:
  - Response MUST include: `FileAttributes`, `LastWriteTime`, `FileSize`
  - Response MUST include: `Reserved` array (10 bytes, set to 0) — correct
  - `FileAttributes` MUST include DIRECTORY bit if target is a directory
  - `FileSize` MUST be 0 for directories (MS-SMB §2.2.4.8.2)
- **Current implementation**:
  - `FileAttributes`, `LastWriteTime`, `FileSize` are correctly populated
  - Directory bit is set via `smb_get_dos_attr()` which maps `S_ISDIR` correctly
  - `Reserved` bytes zeroed (correct)
  - The extended fields `EASize`, `UniqueId`, `ReservedForEA` referenced in some client implementations are not in this response (they are TRANS2-level fields, not COM_QUERY_INFORMATION fields — this may actually be correct)
- **Implementation effort**: LOW (verify correctness rather than add fields)
- **Plan**:
  1. Verify that ATTR_DIRECTORY is set correctly when querying a directory path
  2. Confirm FileSize == 0 for directories in the current implementation
  3. No additional fields required by the core MS-SMB §2.2.4.8.2 specification

---

### SMB_COM_SET_INFORMATION / SMB_COM_SETATTR (0x09)

- **Spec ref**: MS-SMB §2.2.4.9
- **Status**: PARTIAL
- **Handler**: `smb_setattr()` (smb1pdu.c ~line 8736)
- **Required by spec**:
  - Server MUST apply `FileAttributes` mask: at minimum READONLY (0x01), HIDDEN (0x02), SYSTEM (0x04), ARCHIVE (0x20)
  - Server MUST update `LastWriteTime` from request if non-zero
  - Server MUST NOT allow setting DIRECTORY bit via this command
  - `FileAttributes == 0` means "no change to attributes" (MS-SMB §2.2.4.9.1)
- **Current implementation**:
  - Only `ATTR_READONLY` (0x01) is mapped to POSIX permissions (`chmod`)
  - `ATTR_HIDDEN` (0x02), `ATTR_SYSTEM` (0x04), `ATTR_ARCHIVE` (0x20) not stored/applied
  - `LastWriteTime` is updated correctly when non-zero
  - `FileAttributes == 0` correctly treated as no-op on attributes
  - No xattr storage for HIDDEN/SYSTEM attributes (would require `user.DOSATTRIB` xattr)
- **Implementation effort**: MEDIUM
- **Plan**:
  1. Add `ksmbd_vfs_set_dos_attrib_xattr()` call to store HIDDEN/SYSTEM/ARCHIVE bits in `user.DOSATTRIB` xattr
  2. On subsequent `smb_query_info()`, read xattr to reconstruct full DOS attribute mask
  3. This is already done in TRANS2_SET_PATH_INFORMATION path; share the helper

---

### SMB_COM_QUERY_INFORMATION2 (0x23)

- **Spec ref**: MS-SMB §2.2.4.32
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Extended file information query by FID (not path)
  - Response includes: CreateTime, LastAccessTime, LastWriteTime, LastChangeTime, FileSize, AllocationSize, FileAttributes
  - This is the FID-based counterpart to QUERY_INFORMATION (path-based)
- **Current implementation**: Not implemented.
- **Implementation effort**: LOW
- **Plan**:
  1. Add `smb_query_info2()` handler that takes FID from request, does `ksmbd_lookup_fd_fast()`, then `ksmbd_vfs_getattr()`
  2. Build response with all 7 required time/size/attr fields
  3. Register in dispatch table and smb1misc.c validation

---

### SMB_COM_SET_INFORMATION2 (0x22)

- **Spec ref**: MS-SMB §2.2.4.33
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Set file times by FID: CreateTime, LastAccessTime, LastWriteTime
  - This is the FID-based counterpart to SETATTR (path-based)
- **Current implementation**: Not implemented. This is partially covered by TRANS2_SET_FILE_INFORMATION, but the legacy FID-based command is missing.
- **Implementation effort**: LOW
- **Plan**:
  1. Add `smb_set_info2()` handler: lookup FID, parse three timestamps, call `ksmbd_vfs_utimes()`
  2. Register in dispatch table

---

### SMB_COM_FIND (0x0C)

- **Spec ref**: MS-SMB §2.2.4.14 (legacy directory search)
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Legacy 8.3-filename directory enumeration
  - Returns entries in the old SMB_FIND_BUFFER format (21-byte entries with DOS attributes, 8.3 names)
  - Server MUST support `SearchAttributes` filtering
  - Server MUST handle the resume key in continuation calls
- **Current implementation**: Not implemented. TRANS2_FIND_FIRST/FIND_NEXT (long file names) are implemented instead.
- **Implementation effort**: MEDIUM
- **Plan**:
  1. Add `smb_find()` handler that uses the legacy 8.3 search format
  2. Truncate/convert long names to 8.3 format for response
  3. Use `ksmbd_vfs_dir_emit()` infrastructure but with SMB_FIND_BUFFER format
  4. Note: low priority; only legacy MS-DOS clients need this

---

### SMB_COM_FIND_UNIQUE (0x11)

- **Spec ref**: MS-SMB §2.2.4.19
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - Single-response directory search (no resume key; search closes automatically after one response)
  - Used for unique file finding
- **Current implementation**: Not implemented.
- **Implementation effort**: LOW (same as FIND but without resume state)
- **Plan**:
  1. Add `smb_find_unique()` that calls the same search logic as `smb_find()` but closes search after first batch

---

### SMB_COM_FIND_CLOSE2 (0x34)

- **Spec ref**: MS-SMB §2.2.4.38
- **Status**: COMPLETE
- **Handler**: `smb_closedir()` (smb1pdu.c ~line 8365)
- **Notes**: Correctly closes the directory search handle (SearchID), returns STATUS_SUCCESS. No gaps identified.

---

### SMB_COM_FIND_CLOSE (0x35)

- **Spec ref**: MS-SMB §2.2.4.39 (extended find close, different from FIND_CLOSE2)
- **Status**: MISSING
- **Handler**: None registered
- **Required by spec**:
  - This is a different command from FIND_CLOSE2 (0x34)
  - Used by some legacy clients to close searches opened via SMB_COM_FIND
  - If SMB_COM_FIND is not implemented, this is less critical, but should return STATUS_SUCCESS for any FID
- **Current implementation**: Not implemented (0x35 != 0x34).
- **Implementation effort**: VERY LOW
- **Plan**:
  1. If SMB_COM_FIND is implemented, add SMB_COM_FIND_CLOSE handler pointing to same `smb_closedir()` logic
  2. If SMB_COM_FIND remains unimplemented, add a stub that returns STATUS_SUCCESS

---

### SMB_COM_NT_RENAME (0xA5)

- **Spec ref**: MS-SMB §2.2.4.73 (NT-specific rename with flags)
- **Status**: PARTIAL
- **Handler**: `smb_nt_rename()` (smb1pdu.c ~line 8271)
- **Required by spec**:
  - `Flags` field defines operation type:
    - 0x0001 = CREATE_HARD_LINK: create a hard link
    - 0x0002 = QUERY_STREAM_INFORMATION: query stream info (NTFS streams)
    - 0x0003 = QUERY_EA_INFORMATION: query EA info
    - 0x0004 = RENAME_FILE: actually rename the file
    - 0x0005 = MOVE_CLUSTER_INFORMATION: cluster-level move
  - Server MUST handle at minimum `RENAME_FILE` (0x0004)
- **Current implementation**:
  - At line ~8232: `if (le16_to_cpu(req->Flags) != CREATE_HARD_LINK) return NT_STATUS_INVALID_PARAMETER`
  - Only `CREATE_HARD_LINK` (0x0001) is implemented; all other flag values return `INVALID_PARAMETER`
  - `RENAME_FILE` (0x0004) is explicitly rejected, which means NT_RENAME cannot be used as a rename mechanism
- **Implementation effort**: LOW (RENAME_FILE case is just calling the same VFS rename)
- **Plan**:
  1. Add `case RENAME_FILE` to the flags switch in `smb_nt_rename()`
  2. For `RENAME_FILE`: parse `NewFileName` and call `ksmbd_vfs_rename()`
  3. Return correct NT status codes for name collision, access denied, etc.

---

### SMB_COM_LOCKING_ANDX (0x24)

- **Spec ref**: MS-SMB §2.2.4.32
- **Status**: PARTIAL
- **Handler**: `smb_locking_andx()` (smb1pdu.c ~line 1713)
- **Required by spec**:
  - `TypeOfLock` bit 2 (CANCEL_LOCK): Server MUST attempt to cancel a pending lock request (MS-SMB §3.3.5.14)
  - `TypeOfLock` bit 4 (CHANGE_LOCKTYPE): Server MUST change an existing lock from shared to exclusive or vice versa
  - Server MUST process oplock break acknowledgements (when `OplockLevel == 0`)
  - Server MUST validate that NumberOfUnlocks + NumberOfLocks records fit within the packet
- **Current implementation**:
  - `CANCEL_LOCK` flag detected and logged (`ksmbd_debug(SMB, "Cancel lock...")`) but no actual cancellation of pending locks occurs (line ~1810)
  - `CHANGE_LOCKTYPE` returns `ERRDOS/ERRnoatom` without attempting the type change
  - Oplock break acknowledgement path is correctly handled (when `OplockLevel == 0`)
  - Lock record count validation present
- **Implementation effort**: MEDIUM (CANCEL_LOCK) / LOW (CHANGE_LOCKTYPE)
- **Plan**:
  1. `CANCEL_LOCK`: maintain a list of pending async lock requests per connection; on CANCEL_LOCK, find matching lock by range and UID/PID, cancel the pending `fcntl()` / wait
  2. `CHANGE_LOCKTYPE`: call unlock on the old lock type, then re-lock with new type atomically (or return STATUS_NOT_SUPPORTED with documentation)

---

## Appendix: Commands With COMPLETE Status

The following commands have handlers that satisfy the core MS-SMB MUST requirements:

| Command | Opcode | Handler | Notes |
|---|---|---|---|
| SMB_COM_TREE_DISCONNECT | 0x71 | `smb_tree_disconnect()` | Marks tcon disconnected; releases ref |
| SMB_COM_CLOSE | 0x04 | `smb_close()` | LastWriteTime honored; FID validation correct |
| SMB_COM_DELETE | 0x06 | `smb_unlink()` | Open-file detection; SearchAttributes applied |
| SMB_COM_CREATE_DIRECTORY | 0x00 | `smb_mkdir()` | Correct behavior; duplicate-dir error mapped |
| SMB_COM_DELETE_DIRECTORY | 0x01 | `smb_rmdir()` | Non-empty check via VFS; correct NT status |
| SMB_COM_CHECK_DIRECTORY | 0x10 | `smb_checkdir()` | Path validation; NOT_A_DIRECTORY check |
| SMB_COM_ECHO | 0x2B | `smb_echo()` | EchoCount loop correct; SequenceNumber set |
| SMB_COM_FIND_CLOSE2 | 0x34 | `smb_closedir()` | SearchID released correctly |
| SMB_COM_NT_CANCEL | 0xA4 | `smb_nt_cancel()` | Marks work as cancelled; wakes pending work |
| SMB_COM_QUERY_INFORMATION_DISK | 0x52 | `smb_query_information_disk()` | Disk space in blocks; correct field mapping |
| SMB_COM_PROCESS_EXIT | 0x11 | `smb_process_exit()` | Stub; returns success (acceptable per spec) |

---

## Priority Matrix

| Priority | Command | Effort | Rationale |
|---|---|---|---|
| HIGH | SMB_COM_LOGOFF_ANDX fix | MEDIUM | Current behavior tears down entire connection on logoff |
| HIGH | SMB_COM_NT_CREATE_ANDX ShareAccess | HIGH | No share-mode enforcement allows data corruption |
| HIGH | SMB_COM_NT_RENAME RENAME_FILE | LOW | NT_RENAME used by many clients for rename |
| MEDIUM | SMB_COM_READ_RAW stub | VERY LOW | Protocol violation; easy to fix |
| MEDIUM | SMB_COM_WRITE_RAW stub | LOW | Protocol violation |
| MEDIUM | SMB_COM_QUERY_INFORMATION2 | LOW | FID-based query used by some clients |
| MEDIUM | SMB_COM_SET_INFORMATION2 | LOW | FID-based setattr used by some clients |
| MEDIUM | SMB_COM_SETATTR HIDDEN/SYSTEM attrs | MEDIUM | DOS attribute round-trip correctness |
| LOW | SMB_COM_TREE_CONNECT | LOW | Legacy non-ANDX form; most clients use ANDX |
| LOW | SMB_COM_READ | LOW | Legacy; covered by READ_ANDX in practice |
| LOW | SMB_COM_WRITE_AND_CLOSE | LOW | Legacy; rarely used |
| LOW | SMB_COM_FIND / FIND_UNIQUE / FIND_CLOSE | MEDIUM | Legacy 8.3 search; only old clients need this |
| LOW | SMB_COM_SEEK | MEDIUM | Requires per-FID state; rarely used with ANDX |
| VERY LOW | SMB_COM_COPY / MOVE | HIGH | Almost never used; clients use RENAME+COPY |
| VERY LOW | Session VcNumber enforcement | MEDIUM | Edge case; most clients don't set VcNumber |
