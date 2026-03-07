# SMB2 Plan 02: Create / Close / Flush / Echo / Cancel

**Scope**: MS-SMB2 §2.2.13–2.2.16 (CREATE/CLOSE), §2.2.17/3.3.5.11 (FLUSH),
§2.2.28/3.3.5.15 (ECHO), §2.2.30/3.3.5.16 (CANCEL).

**Files examined**:
- `src/protocol/smb2/smb2_create.c` (full, ~2494 lines)
- `src/protocol/smb2/smb2_misc_cmds.c` (full, ~669 lines — contains CLOSE, ECHO)
- `src/protocol/smb2/smb2_lock.c:67–211` (CANCEL handler)
- `src/protocol/smb2/smb2_read_write.c:976–1039` (FLUSH handler)
- `src/include/protocol/smb2pdu.h` (structs and constants)
- `src/include/fs/vfs.h` (CreateOptions constants)
- `src/include/fs/vfs_cache.h` (ksmbd_file / ksmbd_inode structs)
- `src/fs/vfs_cache.c` (close / delete-on-close logic)
- `src/protocol/common/smb_common.c:738–820` (share-mode check)

---

## Current State Summary

### SMB2 CREATE (`smb2_open`, smb2_create.c:1104)

The handler is the largest and most complex in the codebase. It handles IPC pipes
via `create_smb2_pipe` (smb2_create.c:261), then dispatches normal file opens.

**CreateDisposition**: All six values are handled in `smb2_create_open_flags`
(smb2_create.c:71–130). SUPERSEDE and OVERWRITE produce `O_TRUNC` (line 107),
OPEN_IF/CREATE/OVERWRITE_IF produce `O_CREAT` (lines 115–119). File-info values
(FILE_CREATED/OPENED/OVERWRITTEN/SUPERSEDED) are set correctly at lines 1821–1830.

**CreateOptions**: Validated against `CREATE_OPTIONS_MASK` (line 1344).
FILE_DIRECTORY_FILE + FILE_NON_DIRECTORY_FILE mutual exclusion checked (line 1373).
FILE_RESERVE_OPFILTER rejected with STATUS_NOT_SUPPORTED (line 1360).
FILE_OPEN_BY_FILE_ID partially stubbed (line 1364-1369 strips the flag but code
path at line 1197 already returns -EOPNOTSUPP before reaching there — see P1 below).
FILE_DELETE_ON_CLOSE enforced including DELETE-access check (line 2063–2073).
FILE_WRITE_THROUGH, FILE_SEQUENTIAL_ONLY, FILE_RANDOM_ACCESS handled by
`ksmbd_vfs_set_fadvise` (smb2_create.c:1832; vfs.c:2943–2963).
FILE_NO_EA_KNOWLEDGE enforced (line 1430–1434).
FILE_COMPLETE_IF_OPLOCKED, FILE_OPEN_REQUIRING_OPLOCK, FILE_OPEN_NO_RECALL,
FILE_OPEN_FOR_BACKUP_INTENT, FILE_SYNCHRONOUS_IO_ALERT, FILE_SYNCHRONOUS_IO_NONALERT
are accepted (pass mask check) but **silently ignored** — no semantic enforcement.

**DesiredAccess**: GENERIC_* bits mapped to specific bits via
`smb_map_generic_desired_access` (smb_common.c:923–946). FILE_MAXIMAL_ACCESS
triggers `ksmbd_vfs_query_maximal_access` (line 1640–1657). All FILE_* bits
carried through to `fp->daccess`.

**FileAttributes**: Mapped via `smb2_get_dos_mode` (line 2198–2199). DOS-attrib
xattr stored/read conditionally on `KSMBD_SHARE_FLAG_STORE_DOS_ATTRS` (lines
602–641). ATTR_TEMPORARY_LE + FILE_DIRECTORY_FILE rejected (line 1404–1408).

**ShareAccess**: Full bidirectional conflict checking in `ksmbd_smb_check_shared_mode`
(smb_common.c:738–820): FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE
all checked against prior and new handle daccess.

**ImpersonationLevel**: Validated to ≤ IL_DELEGATE (line 1336–1341).
Status STATUS_BAD_IMPERSONATION_LEVEL sent on failure. No deeper enforcement
(expected for a file server that does not actually impersonate).

**SecurityFlags / SmbCreateFlags / Reserved**: No field in the request struct is
named SecurityFlags at the code level. The raw `req->SecurityFlags` (smb2pdu.h:655)
and `req->SmbCreateFlags` (smb2pdu.h:658) are read but never examined — silently
ignored per-spec (MUST be zero / reserved).

**Create Contexts**:

| Context      | Tag    | Status in code |
|-------------|--------|----------------|
| EA_BUFFER    | ExtA   | Parsed (line 1418), applied after create (line 1746) |
| SD_BUFFER    | SecD   | Parsed and applied via `smb2_create_sd_buffer` (line 1877) |
| DHnQ         | DHnQ   | Parsed in `parse_durable_handle_context` (line 939–952), response built (line 2368–2373) |
| DHnC         | DHnC   | Parsed and reconnection path implemented (lines 851–890) |
| DH2Q         | DH2Q   | Parsed (lines 892–937), response built (lines 2374–2381) |
| DH2C         | DH2C   | Parsed (lines 802–850), CreateGuid and ClientGUID verified (lines 828–842) |
| AlSi         | AlSi   | Parsed and `vfs_fallocate` called (lines 2083–2113) |
| MxAc         | MxAc   | Parsed (line 1437–1446), response built (lines 2297–2327) |
| TWrp         | TWrp   | Parsed, snapshot path *resolved* but **not used** — live file opened instead (see P1) |
| QFid         | QFid   | Parsed (line 2115–2122), response built (lines 2329–2351) |
| RqLs         | RqLs   | Parsed via `parse_lease_state`, granted via `smb_grant_oplock` (line 2030–2060) |
| RqL2         | RqL2   | Same path as RqLs (smb2.1 directory lease supported via `is_dir` flag) |
| POSIX        | 16-byte | Parsed (line 1163–1181), response built (lines 2391–2413) |
| AAPL (Fruit) | AAPL   | Parsed and negotiated (lines 2124–2186, CONFIG_KSMBD_FRUIT) |
| APP_INSTANCE_ID | 16-byte GUID | Dispatched via registered context handler (line 1008–1026) |
| APP_INSTANCE_VERSION | 16-byte GUID | Same dispatch path (line 1041–1049) |

**FILE_OPEN_BY_FILE_ID**: Returns -EOPNOTSUPP immediately at smb2_create.c:1198.
The function `smb2_resolve_open_by_file_id` (line 1052) exists and appears functional
but is decorated `__maybe_unused` and is **never called**.

**Named pipes**: Fully handled by `create_smb2_pipe` (line 1158–1161). Persistent
ID set to 0 (line 307), which is technically compliant.

**Reparse point handling**: Symlinks are explicitly blocked (`d_is_symlink` check,
line 1549 returns -EACCES). `FILE_OPEN_REPARSE_POINT_LE` is defined (vfs.h:65) and
passes the mask check but is **never read** in the open path — see P2 below.

**FileId response**: VolatileFileId = per-session IDR slot (vfs_cache.c:891),
PersistentFileId = global IDR slot (vfs_cache.c:909). Both are 64-bit as required.

**Oplock/lease in response**: OplockLevel set from `rcu_dereference(fp->f_opinfo)`
(line 2232). Lease context appended when `opinfo->is_lease` (lines 2274–2295).
Durable response contexts appended at lines 2353–2389.

---

### SMB2 CLOSE (`smb2_close`, smb2_misc_cmds.c:97)

IPC pipe closed via `smb2_close_pipe` (smb2_misc_cmds.c:65). Pipe response sets all
timestamp/size fields to 0 and Flags=0 — correct per spec.

SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB handled (line 169–198): stats retrieved via
`vfs_getattr`, all required fields (Attributes, CreationTime, LastAccessTime,
LastWriteTime, ChangeTime, AllocationSize, EndOfFile) populated. CreationTime
sourced from `fp->create_time` (correct — this is the Windows-compatible birth time).

FILE_DELETE_ON_CLOSE cleanup: delegated entirely to `ksmbd_close_fd` →
`__ksmbd_close_fd` → vfs_cache.c:401–453. Implementation triggers immediate unlink
when the closing handle had DOC set and other handles remain open (lines 409–453),
with fallback to deferred deletion. This matches Windows NTFS semantics.

Compound request handling: volatile_id taken from `work->compound_fid` when the
request is part of a related chain with 0xFFFF FID (lines 142–163).

**Durable handle on close**: `ksmbd_close_fd` → `ksmbd_inode_can_reconn` (vfs_cache.c
lines 1027–1034) decides whether to preserve the handle as durable. The handle is
preserved if it has a batch oplock or a lease with HANDLE_CACHING. This is correct
per MS-SMB2 §3.3.5.10.

Close does **not** validate the PersistentFileId — it only uses VolatileFileId for
the lookup (line 162 uses req->VolatileFileId; POSTQUERY path uses `ksmbd_lookup_fd_fast`
at line 173 which is volatile-only). See P3 below.

---

### SMB2 FLUSH (`smb2_flush`, smb2_read_write.c:976)

File lookup uses `ksmbd_lookup_fd_slow` (volatile + persistent, line 989) — correct.
STATUS_FILE_CLOSED returned when FID not found (line 992) — correct.
FILE_WRITE_DATA | FILE_APPEND_DATA access check implemented (line 1001) — correct,
matches MS-SMB2 §3.3.5.11.
ChannelSequence validation via `smb2_check_channel_sequence` (line 1011) — present.
Response StructureSize=4, Reserved=0 (lines 1036–1037) — correct.

**Named pipe flush**: No `KSMBD_SHARE_FLAG_PIPE` check. The spec (MS-SMB2 §3.3.5.11)
requires STATUS_NOT_SUPPORTED for pipe handles. The current code will attempt to call
`ksmbd_vfs_fsync` on a pipe fd — see P1 below.

---

### SMB2 ECHO (`smb2_echo`, smb2_misc_cmds.c:231)

Minimal implementation. Sets StructureSize=4, Reserved=0 (lines 240–241). Correct
per MS-SMB2 §3.3.5.15. Handles compound offset (`next_smb2_rcv_hdr_off`, line 237).
No session/tree validation required by spec — correct.

---

### SMB2 CANCEL (`smb2_cancel`, smb2_lock.c:67)

Async cancel: searches `conn->async_requests` by `async_id` (lines 84–109).
Sets `iter->state = KSMBD_WORK_CANCELLED` and invokes `cancel_fn` callback (line 108).

Sync cancel: searches `conn->requests` by MessageId (lines 111–133).
Falls back to async list search by MessageId (lines 148–169).
Additional fallback for MessageId=0 by SessionId (lines 177–200) to handle the race
where the client cancels before receiving the interim STATUS_PENDING response.

No response sent: `work->send_no_response = 1` (line 210) — correct per spec
§3.3.5.16 which says "The server MUST NOT send a response".

---

## Confirmed Bugs (P1)

### P1-01 — TWrp (Timewarp) snapshot path discarded, live file opened instead

**Location**: smb2_create.c:1494–1510

The timewarp context is parsed and `ksmbd_vss_resolve_path()` is called to validate
that the snapshot exists. However, the resolved `snap_path` is immediately freed
(`kfree(snap_path)` at line 1510) without being used. The subsequent `ksmbd_vfs_kern_path()`
at line 1519 always opens the **live** file using the original `name`, not the
snapshot version. Any client request for a previous snapshot will silently receive
the current live file data — a correctness violation that could expose data the client
did not intend to access.

**Spec reference**: MS-SMB2 §2.2.13.2.7 (TWrp), §3.3.5.9.

**Fix direction**: `ksmbd_vfs_kern_path` must be called with `snap_path + relative_name`
(or an equivalent VSS-aware path) rather than the bare `name` from the request.

---

### P1-02 — FLUSH on named pipe does not return STATUS_NOT_SUPPORTED

**Location**: smb2_read_write.c:976–1039

`smb2_flush()` does not check whether the tcon is an IPC pipe share
(`KSMBD_SHARE_FLAG_PIPE`). On an IPC connection the file descriptor `fp` will be a
userspace RPC pipe pseudo-fd. Calling `ksmbd_vfs_fsync()` on it is undefined
behavior (the underlying `struct file` may not support fsync). MS-SMB2 §3.3.5.11
states: "If the share is a pipe, the server MUST return STATUS_NOT_SUPPORTED."

**Fix direction**: Add a `test_share_config_flag(work->tcon->share_conf, KSMBD_SHARE_FLAG_PIPE)`
guard at the top of `smb2_flush()` and return STATUS_NOT_SUPPORTED immediately.

---

### P1-03 — FILE_OPEN_BY_FILE_ID always rejected despite functional resolver

**Location**: smb2_create.c:1197–1199, smb2_create.c:1052–1096

When `req->NameLength != 0` and `FILE_OPEN_BY_FILE_ID_LE` is set, the code returns
`-EOPNOTSUPP` (STATUS_NOT_SUPPORTED) at line 1198. The function
`smb2_resolve_open_by_file_id()` (lines 1052–1096) implements the correct lookup
(inode → path) but is marked `__maybe_unused` and never called. This means any
client that opens files by FileId (a common pattern for backup/restore and DFS
operations) will always receive STATUS_NOT_SUPPORTED.

**Spec reference**: MS-SMB2 §2.2.13, §3.3.5.9 (FILE_OPEN_BY_FILE_ID).

---

## Missing Features (P2)

### P2-01 — FILE_OPEN_REPARSE_POINT not honored

**Location**: smb2_create.c:1519 (path lookup), smb2_create.c:1549 (symlink check)

The code uses `LOOKUP_NO_SYMLINKS` unconditionally for all opens. When
`FILE_OPEN_REPARSE_POINT_LE` is set in CreateOptions, the server should open the
reparse point (symlink) *itself* rather than following it. Currently:
- `LOOKUP_NO_SYMLINKS` is always set (line 1519)
- When a symlink is encountered, the code returns -EACCES (STATUS_ACCESS_DENIED)
  regardless of whether `FILE_OPEN_REPARSE_POINT_LE` was requested (line 1549–1554)

The consequence is that all symlinks are hard-blocked. A client requesting
`FILE_OPEN_REPARSE_POINT` should receive a handle to the symlink itself; instead it
always gets STATUS_ACCESS_DENIED.

**Spec reference**: MS-SMB2 §2.2.13 (CreateOptions), §3.3.5.9.

---

### P2-02 — SUPERSEDE does not clear xattrs (stream metadata leaks)

**Location**: smb2_create.c:2015–2019, smb2_create.c:583–600

`smb2_create_truncate()` at line 583 calls both `vfs_truncate(path, 0)` and
`smb2_remove_smb_xattrs(path)`. However, `need_truncate = 1` is only set at line
2018 when `(open_flags & O_TRUNC) && !attrib_only && !stream_name`. The flag
`O_TRUNC` is set for SUPERSEDE at line 104–107 of `smb2_create_open_flags`. So the
truncate path is reached for SUPERSEDE. However, SUPERSEDE semantically requires
resetting *all* file metadata including EAs and security descriptors to those of the
new create request — the `smb2_remove_smb_xattrs` call only removes stream-prefix
xattrs, not the full set of SMB/ACL xattrs (`XATTR_NAME_SD`, `XATTR_NAME_DOS_ATTRIBUTE`,
EAs). A Windows-compatible SUPERSEDE would need to reset the SD and all EAs.

**Spec reference**: MS-SMB2 §3.3.5.9.1 (FILE_SUPERSEDE).

---

### P2-03 — FILE_COMPLETE_IF_OPLOCKED not implemented

**Location**: smb2_create.c:1344 (mask check accepts it), no implementation

`FILE_COMPLETE_IF_OPLOCKED_LE` passes the mask validation silently. The spec requires
that if the open conflicts with an existing oplock and this flag is set, the server
MUST complete the open with STATUS_OPLOCK_BREAK_IN_PROGRESS rather than blocking.
Currently the code blocks waiting for the oplock break via `smb_grant_oplock`.

**Spec reference**: MS-SMB2 §3.3.5.9, [MS-SMB2] CreateOptions 0x00000100.

---

### P2-04 — FILE_OPEN_REQUIRING_OPLOCK not implemented

**Location**: smb2_create.c (no reference to FILE_OPEN_REQUIRING_OPLOCK anywhere)

`FILE_OPEN_REQUIRING_OPLOCK` (0x00010000) is defined in vfs.h:62 but is never
checked in the create path. Per spec, if this flag is set the server must atomically
grant the requested oplock or fail the create — the create should fail with
STATUS_OPLOCK_NOT_GRANTED if the oplock cannot be granted. The current code proceeds
as a normal open regardless.

**Spec reference**: MS-SMB2 §3.3.5.9.

---

### P2-05 — No StructureSize validation on incoming CREATE request

**Location**: smb2_create.c:1148 (WORK_BUFFERS only)

The CREATE handler does not validate `req->StructureSize == 57`. Other handlers
(ECHO, CLOSE) likewise rely on the transport-level bounds check only. While this is
not an interoperability issue in practice (well-formed clients always set it correctly),
it is a hardening gap.

**Spec reference**: MS-SMB2 §2.2.13 (StructureSize MUST be 57).

---

## Partial Implementations (P3)

### P3-01 — CLOSE does not validate PersistentFileId

**Location**: smb2_misc_cmds.c:162, smb2_misc_cmds.c:173

`smb2_close()` extracts `volatile_id` from the request (line 162) but ignores the
`req->PersistentFileId`. The POSTQUERY path calls `ksmbd_lookup_fd_fast(work, volatile_id)`
(line 173) which only matches by volatile ID. For non-durable handles this is benign,
but for durable handles the persistent ID is meaningful and omitting the check allows
a mismatch to go undetected. `smb2_flush()` correctly uses `ksmbd_lookup_fd_slow`
which validates both IDs (smb2_read_write.c:989).

**Spec reference**: MS-SMB2 §3.3.5.10 — FileId.Persistent MUST match the open.

---

### P3-02 — Timewarp TWrp context: validation only, no data access from snapshot

**Location**: smb2_create.c:1448–1511

(Cross-reference with P1-01.) The VSS snapshot is resolved and validated, but the
`snap_path` is discarded before the actual file open. The result is a *partial*
implementation: the server correctly rejects invalid timestamps (line 1502–1504) but
silently opens the live file for valid timestamps. From a client's perspective, TWrp
appears to work (no error) but returns live rather than historical data.

---

### P3-03 — FILE_OPEN_FOR_BACKUP_INTENT silently ignored (no privilege bypass)

**Location**: smb2_create.c (passes mask check at line 1344, no other reference)

On Windows, when `FILE_OPEN_FOR_BACKUP_INTENT` is set, the open proceeds under
SE_BACKUP_PRIVILEGE / SE_RESTORE_PRIVILEGE, bypassing normal DACL checks. KSMBD
ignores this flag entirely. Backup software that relies on this semantics will fail
with STATUS_ACCESS_DENIED on files it should be able to open. This is a partial
implementation: the flag is accepted but provides no privilege.

---

### P3-04 — FILE_SYNCHRONOUS_IO_ALERT / FILE_SYNCHRONOUS_IO_NONALERT accepted but MBZ check missing

**Location**: vfs.h:37–39, smb2_create.c:1344

The spec marks these flags "MUST be zero" for SMB2 (they are NT-internal flags for
synchronous I/O completion). KSMBD accepts them silently. A conformant server should
reject them with STATUS_INVALID_PARAMETER. This is low risk in practice since Windows
clients do not send them, but it is a spec violation.

---

### P3-05 — CANCEL: sync cancel search does not differentiate TreeId

**Location**: smb2_lock.c:111–133

The sync-cancel path searches `conn->requests` matching only by `MessageId` (line
117). It does not validate `TreeId` or `SessionId`. Since MessageId is unique per
connection per spec, this is technically sufficient. However, the MessageId=0
fallback path (lines 177–200) matches by `SessionId` only, which could theoretically
cancel the wrong work item if multiple sessions share a connection and both have
MessageId=0 async requests simultaneously. This is an edge case.

---

### P3-06 — CLOSE: error path uses STATUS_FILE_CLOSED as catch-all

**Location**: smb2_misc_cmds.c:216–220

When `ksmbd_close_fd` fails, the code sets `rsp->hdr.Status = STATUS_FILE_CLOSED`
if no status was already set. This is the correct status for an invalid handle but
does not distinguish between other possible failures from `ksmbd_close_fd` (e.g.,
allocation failures within the close path). In practice `ksmbd_close_fd` rarely
fails, but the error mapping is imprecise.

---

## Low Priority (P4)

### P4-01 — ECHO does not validate StructureSize or Reserved field

**Location**: smb2_misc_cmds.c:231–242

The spec states StructureSize MUST be 4 and Reserved MUST be 0. The handler sets
these in the response but does not validate the request fields. Low risk since
malformed ECHO packets are harmless.

---

### P4-02 — CREATE: FILE_DISALLOW_EXCLUSIVE (0x00020000) accepted but ignored

**Location**: vfs.h:63 (defined), smb2_create.c (passes mask check)

This flag requests that exclusive oplocks not be granted to the new handle. It is
accepted by the mask check but not enforced. In the oplock grant path
(`smb_grant_oplock`, line 2055) this flag is not consulted.

---

### P4-03 — CREATE response context Next pointer left non-zero on last context

**Location**: smb2_create.c:2383–2388, smb2_create.c:2409–2412

The `next_ptr` / `next_off` chain correctly sets the `Next` field on each context
in sequence, but the *last* context's Next field is left at whatever the previous
`next_ptr` wrote. The spec requires the last context to have `Next = 0`. The
current code never explicitly zeroes the final context's Next. This is typically
harmless because the last context is created via `create_*_rsp_buf` functions that
should zero-initialise the structure, but it is fragile.

---

### P4-04 — pipe CREATE sets PersistentFileId = 0

**Location**: smb2_create.c:307

The named pipe open response sets PersistentFileId to 0 (`rsp->PersistentFileId = 0`).
The spec does not mandate a specific persistent ID for pipe handles. Most
implementations (including Samba) use 0xFF...FF. This is benign but could cause
interoperability issues with strict clients.

---

### P4-05 — FLUSH fsync error maps to STATUS_INVALID_HANDLE

**Location**: smb2_read_write.c:1031

If `ksmbd_vfs_fsync()` fails, the response status is unconditionally STATUS_INVALID_HANDLE.
A more precise mapping would use STATUS_UNEXPECTED_IO_ERROR for I/O failures and
reserve STATUS_INVALID_HANDLE for the case where the handle is not found.

---

### P4-06 — CREATE: ATTR_TEMPORARY_LE not applied as O_TMPFILE or fadvise

**Location**: smb2_create.c:1397–1408

The code correctly rejects ATTR_TEMPORARY + FILE_DIRECTORY_FILE (line 1404). However,
for non-directory temporary files, ATTR_TEMPORARY is stored in `m_fattr` but no
hint (e.g., POSIX_FADV_NOREUSE or equivalent) is given to the Linux page cache. This
is a performance gap rather than a correctness issue.

---

## Compliance Estimate per Command (%)

These are estimates of spec coverage weighted by the significance of missing features,
not simple feature count ratios.

| Command        | Estimated Compliance | Key gaps |
|---------------|---------------------|----------|
| SMB2 CREATE   | ~72%                | TWrp broken (P1-01), FILE_OPEN_BY_FILE_ID rejected (P1-03), FILE_OPEN_REPARSE_POINT not honored (P2-01), FILE_COMPLETE_IF_OPLOCKED missing (P2-03), FILE_OPEN_REQUIRING_OPLOCK missing (P2-04) |
| SMB2 CLOSE    | ~88%                | PersistentFileId not validated (P3-01), otherwise solid |
| SMB2 FLUSH    | ~80%                | Named pipe must return STATUS_NOT_SUPPORTED (P1-02); rest correct |
| SMB2 ECHO     | ~99%                | Functionally correct; only missing MBZ field validation (P4-01) |
| SMB2 CANCEL   | ~92%                | Async/sync cancel paths both work; SessionId-only fallback is an edge case (P3-05) |

**Overall block compliance** (five commands): **~86%**

The main risk areas are in CREATE where multiple CreateOptions flags are accepted but
produce incorrect or no behavior. The TWrp (timewarp) bug is particularly dangerous
because it silently returns wrong data. The FILE_OPEN_BY_FILE_ID rejection will break
backup/restore clients that rely on inode-based opens.
