# SMB1 File I/O Commands: MS-SMB Compliance Upgrade Plan

**Scope:** MS-SMB (CIFS) specification §2.2.4 — File I/O Command Set
**Date:** 2026-03-01
**Target:** KSMBD SMB1 implementation (`src/protocol/smb1/smb1pdu.c`,
`src/include/protocol/smb1pdu.h`, `src/protocol/smb1/smb1ops.c`)
**Status basis:** Current `phase1-security-hardening` branch

---

## Executive Summary

KSMBD implements the core subset of SMB1 file I/O commands well enough for
typical Linux CIFS client use. However, full MS-SMB spec compliance requires
addressing gaps in: (1) NT_CREATE_ANDX CreateOptions coverage and oplock
response accuracy, (2) OPEN_ANDX extended response and Flags semantics,
(3) READ_ANDX MinCount/ReadMode handling, (4) WRITE_ANDX WriteMode bit
semantics, (5) CLOSE oplock-break notification path, (6) FLUSH error
reporting, and (7) a suite of legacy commands that are entirely absent from
the command dispatch table.

---

## 1. SMB_COM_NT_CREATE_ANDX (0xA2) — MS-SMB §2.2.4.64

### 1.1 Wire Format (Request — WordCount = 0x18 = 24)

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | AndXCommand | 1 | Next command or 0xFF |
| 1 | AndXReserved | 1 | Must be 0 |
| 2 | AndXOffset | 2 | Offset to next AndX block |
| 4 | Reserved | 1 | Must be 0 |
| 5 | NameLength | 2 | Byte count of FileName |
| 7 | Flags | 4 | NT_CREATE_REQUEST_* bits |
| 11 | RootDirectoryFid | 4 | 0 = relative to tree root |
| 15 | DesiredAccess | 4 | NT access mask |
| 19 | AllocationSize | 8 | Initial allocation |
| 27 | FileAttributes | 4 | DOS attributes |
| 31 | ShareAccess | 4 | FILE_SHARE_READ/WRITE/DELETE |
| 35 | CreateDisposition | 4 | FILE_SUPERSEDE … FILE_OVERWRITE_IF |
| 39 | CreateOptions | 4 | FILE_DIRECTORY_FILE etc. |
| 43 | ImpersonationLevel | 4 | Anonymous=0 … Delegation=3 |
| 47 | SecurityFlags | 1 | Dynamic tracking / effective only |
| 48 | ByteCount | 2 | Follows |
| 50 | FileName | var | Optionally padded to DWORD |

### 1.2 Response — Standard (WordCount = 0x22 = 34)

| Field | Size | Notes |
|-------|------|-------|
| AndXCommand | 1 | |
| AndXReserved | 1 | |
| AndXOffset | 2 | |
| OplockLevel | 1 | 0=None, 1=Exclusive, 2=Batch, 3=LevelII |
| Fid | 2 | |
| CreateAction | 4 | F_SUPERSEDED=0, F_OPENED=1, F_CREATED=2, F_OVERWRITTEN=3 |
| CreationTime | 8 | NT time |
| LastAccessTime | 8 | NT time |
| LastWriteTime | 8 | NT time |
| ChangeTime | 8 | NT time |
| FileAttributes | 4 | DOS attributes |
| AllocationSize | 8 | |
| EndOfFile | 8 | |
| FileType | 2 | 0=disk, 1=byte pipe, 2=msg pipe, 3=printer |
| DeviceState | 2 | IPC pipe state flags |
| DirectoryFlag | 1 | 1 if directory |
| ByteCount | 2 | 0 |

### 1.3 Extended Response (WordCount = 0x32 = 50, when NT_CREATE_REQUEST_EXTENDED_RESPONSE set)

| Field | Size | Notes |
|-------|------|-------|
| ... all standard fields ... | | |
| VolumeGuid | 16 | Volume GUID (all-zeros acceptable) |
| FileId | 8 | Unique file ID (inode number acceptable) |
| MaximalAccessRights | 4 | Maximum access the caller can obtain |
| GuestMaximalAccessRights | 4 | Maximum access for guest |
| ByteCount | 2 | 0 |

### 1.4 Flags Field Bits (NT_CREATE_ANDX Request Flags)

| Bit | Name | Value |
|-----|------|-------|
| 0 | NT_CREATE_REQUEST_OPLOCK | 0x02 |
| 1 | NT_CREATE_REQUEST_OPBATCH | 0x04 |
| 2 | NT_CREATE_OPEN_TARGET_DIR | 0x08 |
| 3 | NT_CREATE_REQUEST_EXTENDED_RESPONSE | 0x10 |

### 1.5 CreateDisposition Values

All six values are correctly handled by `file_create_dispostion_flags()` in
`smb1pdu.c`:

| Value | Constant | KSMBD Status |
|-------|----------|-------------|
| 0 | FILE_SUPERSEDE | Correct: O_TRUNC if present, O_CREAT if not |
| 1 | FILE_OPEN | Correct: -ENOENT if not present |
| 2 | FILE_CREATE | Correct: -EEXIST if present |
| 3 | FILE_OPEN_IF | Correct: O_CREAT if not present |
| 4 | FILE_OVERWRITE | Correct: -ENOENT if not present, O_TRUNC if present |
| 5 | FILE_OVERWRITE_IF | Correct: O_TRUNC if present, O_CREAT if not |

**Gap:** When FILE_SUPERSEDE produces an overwrite (existing file truncated),
`rsp->CreateAction` is correctly set to `F_SUPERSEDED` (0) by the existing
code. This path is compliant.

### 1.6 CreateOptions Field — Compliance Gap Analysis

The CreateOptions field is a 32-bit mask. KSMBD handles several bits but
leaves others unexamined.

| Bit Mask | Constant | KSMBD Handling | Gap |
|----------|----------|----------------|-----|
| 0x00000001 | FILE_DIRECTORY_FILE | Handled: sets create_directory=1 | None |
| 0x00000002 | FILE_WRITE_THROUGH | Handled: sets O_SYNC | None |
| 0x00000004 | FILE_SEQUENTIAL_ONLY | Not handled in smb1 path | GAP: Should hint readahead (see vfs.c SMB2 path) |
| 0x00000008 | FILE_NO_INTERMEDIATE_BUFFERING | Not handled | GAP: MS-SMB requires STATUS_INVALID_PARAMETER if byte-offset in a subsequent write is not sector-aligned |
| 0x00000010 | FILE_SYNCHRONOUS_IO_ALERT | Not validated | GAP: Must be zero unless FILE_NO_INTERMEDIATE_BUFFERING; else STATUS_INVALID_PARAMETER |
| 0x00000020 | FILE_SYNCHRONOUS_IO_NONALERT | Not validated | GAP: Same mutual exclusion requirement |
| 0x00000040 | FILE_NON_DIRECTORY_FILE | Handled: checked vs S_ISDIR | None |
| 0x00000100 | FILE_COMPLETE_IF_OPLOCKED | Not handled | Minor gap: should complete open without waiting for oplock break; low priority |
| 0x00000200 | FILE_NO_EA_KNOWLEDGE | Not handled | GAP: If file has EAs and client sets this, server must return STATUS_ACCESS_DENIED |
| 0x00000800 | FILE_RANDOM_ACCESS | Not handled | Minor gap: should disable readahead |
| 0x00001000 | FILE_DELETE_ON_CLOSE | Handled: permission check + fd_set_delete_on_close | None |
| 0x00002000 | FILE_OPEN_BY_FILE_ID | Handled: returns STATUS_NOT_SUPPORTED | None |
| 0x00004000 | FILE_OPEN_FOR_BACKUP_INTENT | Not handled | Minor gap: should relax permission checks for backup operators |
| 0x00008000 | FILE_NO_COMPRESSION | Not handled | Benign: Linux does not support per-file compression toggling via this flag; ignoring is safe |
| 0x00010000 | FILE_OPEN_REQUIRING_OPLOCK | Not handled | GAP: Must atomically open + grant oplock or fail with STATUS_OPLOCK_NOT_GRANTED |
| 0x00020000 | FILE_DISALLOW_EXCLUSIVE | Not handled | Minor gap: prevents exclusive oplocks on open |
| 0x00100000 | FILE_RESERVE_OPFILTER | Not handled | GAP: Must return STATUS_OPLOCK_NOT_GRANTED if no oplock is available |
| 0x00200000 | FILE_OPEN_REPARSE_POINT | Not handled | GAP: Without this flag, opens through reparse points should follow the reparse; with it, the reparse point itself is opened. KSMBD currently rejects symlinks entirely (EACCES), which is incorrect for this flag |
| 0x00400000 | FILE_OPEN_NO_RECALL | Not handled | Benign for local storage; ignore is safe |

**Priority Gaps for CreateOptions:**
1. **FILE_NO_EA_KNOWLEDGE (0x200):** Medium priority. If the target file has
   extended attributes and this bit is set, the server must deny access.
   Implementation: after path lookup, check for EAs with
   `ksmbd_vfs_listxattr()` and return STATUS_ACCESS_DENIED if any exist.
2. **FILE_OPEN_REQUIRING_OPLOCK (0x10000):** High priority for clients that
   use opportunistic locking aggressively. The open and the oplock grant must
   be atomic. Currently KSMBD opens the file first and then attempts the oplock
   grant in a separate step — a race window exists.
3. **FILE_SEQUENTIAL_ONLY / FILE_RANDOM_ACCESS:** Low priority. Implement as
   readahead hints using the same code path already present in `vfs.c` for
   SMB2 (see `ksmbd_vfs_dentry_open` options processing around
   `FILE_SEQUENTIAL_ONLY_LE`). The SMB1 path passes `req->CreateOptions` to
   `ksmbd_vfs_dentry_open()` already, so the vfs.c code will see these bits
   **only** if the LE versions match the raw values. Verify the constant
   values match — they do for these bits.

### 1.7 ShareAccess — Compliance Gap

The `smb_nt_create_andx()` stores `req->ShareAccess` in `fp->saccess` and
calls `ksmbd_smb_check_shared_mode()`. This is the correct approach. The
share-mode enforcement is handled by the shared-mode checker in
`vfs_cache.c`. No gap at the protocol level; the comment in the code is
accurate (full enforcement is delegated to the oplock/share-mode subsystem).

### 1.8 ImpersonationLevel — Compliance Gap

The spec defines four levels:

| Value | Name |
|-------|------|
| 0 | Anonymous |
| 1 | Identification |
| 2 | Impersonation |
| 3 | Delegation |

**Current behavior:** Field is read from wire (`req->ImpersonationLevel`) but
not validated. The code comment in `smb_nt_create_andx()` explicitly notes
this is treated as informational only.

**Gap:** MS-SMB §2.2.4.64.1 states the server MAY ignore levels it does not
support, but **MUST NOT** use a level higher than requested. Since KSMBD
always runs as the authenticated user (effective IDs set via
`ksmbd_override_fsids()`), this is functionally correct. No functional gap,
but the server should validate that the value is in range [0..3] and return
STATUS_INVALID_PARAMETER for out-of-range values.

### 1.9 SecurityFlags — Compliance Gap

Two bits are defined:

| Bit | Name | Value |
|-----|------|-------|
| 0 | SMB_SECURITY_DYNAMIC_TRACKING | 0x01 |
| 1 | SMB_SECURITY_EFFECTIVE_ONLY | 0x02 |

**Current behavior:** Field is accepted but not validated or acted upon.
**Gap:** Reserved bits (0xFC) must be zero; no validation exists. Low priority.

### 1.10 OplockLevel in Response — Compliance Gap

The oplock level byte in the response is set from `fp->f_opinfo->level` or 0
if no oplock is held. The mapping:

| KSMBD internal | Wire value | MS-SMB name |
|----------------|-----------|-------------|
| OPLOCK_NONE (0) | 0 | No oplock |
| OPLOCK_EXCLUSIVE (1) | 1 | Exclusive oplock |
| OPLOCK_BATCH (2) | 2 | Batch oplock |
| OPLOCK_READ (3) | 3 | Level II (shared) oplock |

**Gap:** SMB1 oplock granting is disabled by default (`smb1_oplock_enable =
false`). When disabled, the response always returns OplockLevel=0 regardless
of what the client requested. This is spec-compliant (the server may decline
any oplock), but clients that aggressively rely on batch oplocks for
performance will see degraded caching. Enabling `smb1_oplock_enable` requires
ensuring the oplock break notification path sends a valid SMB1 oplock break
request to the client (an unsolicited LOCKING_ANDX with
`LOCKING_ANDX_OPLOCK_RELEASE` set).

**Oplock break notification gap:** When a second opener breaks an existing
oplock held by an SMB1 client, KSMBD must send an unsolicited
SMB_COM_LOCKING_ANDX request to the first client. Verify that the oplock
break dispatch in `oplock.c` generates a valid SMB1 format break notification
(not SMB2 format).

### 1.11 Extended Response — Compliance Gaps

When `NT_CREATE_REQUEST_EXTENDED_RESPONSE` (bit 3 of Flags field, value 0x10)
is set, the server responds with WordCount=50 and the extended structure.

**Current behavior:**
- `ext_rsp->VolId` is zeroed (all-zeros GUID) — acceptable per spec
- `ext_rsp->fid` is set to `inode->i_ino` — compliant
- `ext_rsp->MaxAccess` is set based on open mode — partially compliant
- `ext_rsp->GuestAccess` is **not set** — **GAP**

**Gap:** `ext_rsp->GuestAccess` (offset 60 in the extended response, the
`GuestMaximalAccessRights` field) is never written. The struct field exists
(`__le32 GuestAccess` in `smb_com_open_ext_rsp`) but is not assigned in
`smb_nt_create_andx()`. This field should be set to `FILE_GENERIC_READ_LE`
for disk shares or 0 if the share has no guest access.

**Fix required in `smb_nt_create_andx()`:**
```c
ext_rsp->GuestAccess = cpu_to_le32(FILE_GENERIC_READ);
```

### 1.12 NT_CREATE_OPEN_TARGET_DIR Flag

The `NT_CREATE_OPEN_TARGET_DIR` flag (0x08 in the Flags field) instructs the
server to open the parent directory of the target path rather than the target
itself. This is used for server-side directory monitors and rename
pre-verification.

**Current behavior:** The Flags field is read for the oplock bits
(`REQ_OPLOCK | REQ_BATCHOPLOCK`) and the extended response bit
(`REQ_EXTENDED_INFO`), but `NT_CREATE_OPEN_TARGET_DIR` (which maps to the
`REQ_OPENDIRONLY` constant defined in `smb1pdu.h`) is not acted upon.

**Gap:** The `REQ_OPENDIRONLY` constant (0x08) is defined in the header but
the smb1 create handler does not implement it. MS-SMB §2.2.4.64.1 says: "If
this flag is set, the target directory for the file is opened." Implementation
should strip the last path component, look up the parent directory, and open
it instead.

**Priority:** Medium. Clients (notably Windows Explorer's shell namespace
provider and some backup software) use this for atomic rename scenarios.

### 1.13 Large File Support

The AllocationSize, EndOfFile, CreationTime, LastAccessTime, LastWriteTime,
and ChangeTime fields are all 64-bit and handled correctly. The `loff_t`
offsets in VFS calls are 64-bit. No gap.

---

## 2. SMB_COM_OPEN_ANDX (0x2D) — MS-SMB §2.2.4.30

### 2.1 Wire Format (Request — WordCount = 0x0F = 15)

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | AndXCommand | 1 | |
| 1 | AndXReserved | 1 | |
| 2 | AndXOffset | 2 | |
| 4 | OpenFlags | 2 | SMB_OPEN_QUERY_* bits |
| 6 | DesiredAccess | 2 | Old-style: read/write/share-mode encoded |
| 8 | SearchAttributes | 2 | DOS search attributes |
| 10 | FileAttributes | 2 | DOS file attributes for new files |
| 12 | CreationTime | 4 | OS/2 format (seconds since 1970) |
| 16 | OpenFunction | 2 | Create/open/truncate disposition |
| 18 | AllocationSize | 4 | For new files |
| 22 | Timeout | 4 | Milliseconds (if CIFS_TIMEOUT used) |
| 26 | Reserved | 4 | |
| 30 | ByteCount | 2 | |
| 32 | FileName | var | |

### 2.2 Wire Format (Standard Response — WordCount = 0x0F = 15)

| Field | Size | Notes |
|-------|------|-------|
| AndXCommand | 1 | |
| AndXReserved | 1 | |
| AndXOffset | 2 | |
| Fid | 2 | |
| FileAttributes | 2 | DOS attributes |
| LastWriteTime | 4 | Seconds since 1970 (OS/2 format) |
| EndOfFile (DataSize) | 4 | File size (32-bit, max 4GB-1) |
| GrantedAccess | 2 | 0=read, 1=write, 2=read-write |
| FileType | 2 | 0=disk, 1=byte pipe, 2=msg pipe, 3=printer |
| DeviceState | 2 | IPC state (pipe instance count, blocking, etc.) |
| Action | 2 | How file was opened + oplock status |
| ServerFid | 4 | Server's internal FID (optional; set to 0) |
| Reserved | 2 | Must be 0 |
| ByteCount | 2 | 0 |

### 2.3 OpenFlags Bits (SMB_OPEN_QUERY_* in request)

| Bit | Value | Meaning |
|-----|-------|---------|
| 0 | 0x0001 | SMB_OPEN_QUERY_FILE_SIZE_INFORMATION |
| 1 | 0x0002 | SMB_OPEN_QUERY_FILE_ATTRIBUTES |
| 2 | 0x0004 | SMB_OPEN_QUERY_WRITE_TIME |
| 3 | 0x0008 | SMB_OPEN_QUERY_FILE_INFORMATION (returns extended response) |
| 4..15 | 0x0010+ | REQ_OPLOCK (2), REQ_BATCHOPLOCK (4), REQ_OPENDIRONLY (8) |

The OpenFlags field in OPEN_ANDX serves dual purpose: the low nibble controls
what optional information is returned in the response, while bits 1-3 are the
oplock request bits.

### 2.4 OpenFunction Field

The `OpenFunction` field encodes both the "if-exists" behavior (low nibble)
and the "if-not-exists" behavior (bit 4):

| Low nibble | Meaning if file exists |
|------------|----------------------|
| 0x00 | OPEN_FUNC_FAIL_IF_EXISTS — return error |
| 0x01 | OPEN_FUNC_OPEN_IF_EXISTS — open existing |
| 0x02 | OPEN_FUNC_OVERWRITE_IF_EXISTS — truncate |

| Bit 4 | Meaning if file does not exist |
|-------|-------------------------------|
| 0x00 | Fail |
| 0x10 | OPEN_FUNC_CREATE_IF_NOT_EXISTS — create |

**Current implementation in `convert_open_flags()`:**
- `SMBOPEN_OCREATE` (0x0010) maps to create-if-not-exists — correct
- `SMBOPEN_OTRUNC` (0x0002) maps to overwrite-if-exists — correct
- `SMBOPEN_OAPPEND` (0x0001) maps to open-and-append — correct
- `SMBOPEN_DISPOSITION_NONE` (0x0000) returns -EEXIST or -EINVAL — correct

**Gap:** The combination `0x0010 | 0x0001` (create if not exists, append if
exists) is not explicitly handled. The current code checks `dispostion & 0x0010`
and `dispostion & 0x0003` independently; the combined case of create+append
is actually handled correctly by the O_CREAT | O_APPEND combination, but
this should be verified.

### 2.5 DesiredAccess (Old-style) — Compliance Gap

The old-style `DesiredAccess` in OPEN_ANDX packs sharing mode and access mode
into a single 16-bit word:

| Bits | Meaning |
|------|---------|
| 0-2 | Access mode: 0=read, 1=write, 2=read/write, 3=execute |
| 3 | (reserved) |
| 4-6 | Sharing mode: 0=compat, 1=deny-all, 2=deny-write, 3=deny-read, 4=deny-none |
| 7 | (reserved) |
| 14 | Write-through |
| 15 | Caching mode |

**Current KSMBD behavior:**
- Bits 0-2 (access mode) are handled by `convert_open_flags()` using the
  `SMBOPEN_READ/WRITE/READWRITE` constants
- Sharing mode (bits 4-6) is validated: if the value exceeds `SMBOPEN_DENY_NONE`
  (0x0040), the request is rejected with ERRbadaccess. This is correct — KSMBD
  does not implement DOS-era sharing modes.
- Write-through bit (0x4000 = `SMBOPEN_WRITE_THROUGH`) is handled: sets O_SYNC.

**Gaps:**
1. **Sharing mode enforcement:** The spec requires the server to enforce
   deny-all, deny-write, deny-read semantics during the sharing-mode check.
   KSMBD rejects any non-DENY_NONE sharing mode outright instead of enforcing
   it via the file table's shared-mode checker. For strict compliance, map
   the legacy sharing modes to the NT `ShareAccess` flags equivalents and
   pass them to `ksmbd_smb_check_shared_mode()`.
2. **SearchAttributes validation:** The `req->Sattr` (search attributes) field
   is silently ignored. Per spec, if the target file's attributes do not match
   the search attributes, the open should fail with ERRDOS/ERRbadfile. This
   is low priority (rarely enforced even by Windows servers).
3. **CreationTime field:** When creating a new file, the `CreationTime` field
   (OS/2 32-bit format) should be used to set the file creation timestamp.
   KSMBD currently ignores this field.
4. **FileAttributes on creation:** The `req->FileAttributes` field is used
   to set the READONLY bit (`ATTR_READONLY → mode &= ~0222`) but other DOS
   attributes (HIDDEN, SYSTEM) are not persisted on creation.

### 2.6 Extended Response (Action bit 0x8000) — Compliance Gap

When `SMB_OPEN_QUERY_FILE_INFORMATION` is set in `OpenFlags` (bit 3, value 0x0008),
the server should return an extended response with additional file information
fields appended after the standard response. These extra fields correspond to
`SMB_FILE_STANDARD_INFORMATION` content.

**Current behavior:** The `smb_open_andx()` handler does not check
`req->OpenFlags` for the extended information request bit. It always returns
the standard 15-word response regardless of what the client requested.

**Gap:** The extended response path is entirely missing from `smb_open_andx()`.
The `Action` field's high bit (0x8000) is meant to indicate that extended
information follows. Currently only the low-order oplock bit is ORed into
`file_info` via `SMBOPEN_LOCK_GRANTED (0x8000)` — which actually **collides**
with the extended-response action bit definition. This is a spec conflict that
should be resolved by verifying the exact Action bit layout:
- Bits 0-1: How file was opened (0=existed, 1=created, 2=truncated)
- Bit 15 (0x8000): Oplock was granted
The `SMB_OPEN_QUERY_FILE_INFORMATION` extended data is appended after the
ByteCount, not indicated by Action bit 15. This needs careful re-reading of
the spec.

**Recommendation:** Implement the extended response: when
`(req->OpenFlags & 0x0008)` is set, append `SMB_FILE_STANDARD_INFORMATION`
after the standard response (allocation size, end-of-file, number of links,
delete-pending, directory flag) and adjust ByteCount accordingly.

### 2.7 FileAttributes in Response — Compliance Gap

The response `rsp->FileAttributes` is always set to `ATTR_NORMAL` (0x0000)
regardless of the actual file attributes. This is incorrect.

**Fix:** Compute the real DOS attributes using `smb_get_dos_attr(&stat)` as
done in `smb_nt_create_andx()` and set them in the response.

### 2.8 EndOfFile (DataSize) Field — Compliance Gap

`rsp->EndOfFile` is set from `stat.size` using `cpu_to_le32()`. Files larger
than 4GB will have their size silently truncated to 32 bits.

**Gap:** OPEN_ANDX is a legacy command and its response has only a 32-bit size
field (`__le32 EndOfFile`). Per MS-SMB §2.2.4.30.2, the server may truncate
the reported size to UINT32_MAX if the actual file is larger. The client should
use NT_CREATE_ANDX for large files. Document this limitation clearly rather than
silently truncating.

**Fix:** If `stat.size > 0xFFFFFFFF`, set `rsp->EndOfFile = cpu_to_le32(0xFFFFFFFF)`
and log a debug message.

---

## 3. SMB_COM_READ_ANDX (0x2E) — MS-SMB §2.2.4.31

### 3.1 Wire Format (Request)

| Field | Size | Notes |
|-------|------|-------|
| AndXCommand | 1 | |
| AndXReserved | 1 | |
| AndXOffset | 2 | |
| Fid | 2 | File handle |
| OffsetLow | 4 | Low 32 bits of file offset |
| MaxCount | 2 | Maximum bytes to return |
| MinCount | 2 | Minimum bytes (blocking reads for UNIX ext.) |
| MaxCountHigh | 4 | High 16 bits of MaxCount (when CAP_LARGE_READ_X) |
| Remaining | 2 | Reserved (ignored) |
| OffsetHigh | 4 | High 32 bits (present only when WordCount=12) |
| ByteCount | 2 | 0 |

### 3.2 Wire Format (Response)

| Field | Size | Notes |
|-------|------|-------|
| AndXCommand | 1 | |
| AndXReserved | 1 | |
| AndXOffset | 2 | |
| Remaining | 2 | Bytes remaining in named-pipe message (-1 for files) |
| DataCompactionMode | 2 | 0 = no compaction |
| Reserved | 2 | Must be 0 |
| DataLength | 2 | Low 16 bits of byte count |
| DataOffset | 2 | Offset from start of SMB header to data |
| DataLengthHigh | 2 | High 16 bits of byte count |
| Reserved2 | 8 | Must be 0 |
| ByteCount | 2 | Total data bytes in payload |

### 3.3 OffsetHigh (Large File Support)

**Current behavior:** KSMBD correctly handles the 64-bit offset:
```c
pos = le32_to_cpu(req->OffsetLow);
if (req->hdr.WordCount == 12)
    pos |= ((loff_t)le32_to_cpu(req->OffsetHigh) << 32);
```
This is compliant. WordCount=10 means no OffsetHigh (old clients); WordCount=12
means OffsetHigh is present.

### 3.4 MinCount — Compliance Gap

`MinCount` is defined for UNIX extensions (blocking reads on named pipes and
regular files with `CIFS_UNIX_EXPERIMENTAL_CAP`). For POSIX clients, if
`MinCount > 0`, the read should block until at least MinCount bytes are
available before returning.

**Current behavior:** `req->MinCount` is declared in the struct but never read
in `smb_read_andx()`. All reads are performed with `ksmbd_vfs_read()` which
uses the kernel's non-blocking read path.

**Gap:** For named-pipe reads (the `smb_read_andx_pipe()` path), blocking
semantics based on MinCount are not implemented. For regular file reads,
ignoring MinCount is acceptable (files always have data available up to EOF).
For IPC pipes that need message-mode semantics, MinCount should be honored.

**Fix for pipe path:** When `req->MinCount > 0` and the pipe read returns
fewer bytes than MinCount, loop (with appropriate timeout) or return
STATUS_PIPE_NOT_AVAILABLE. Medium priority for UNIX-extension interoperability.

### 3.5 ReadMode / DataCompactionMode — Compliance Gap

The `DataCompactionMode` field in the response is defined as:

| Value | Meaning |
|-------|---------|
| 0 | No compaction (standard read) |
| 1 | Read data is compressed |
| 2 | No-cache read (direct I/O) |

**Current behavior:** `rsp->DataCompactionMode` is always set to 0. The field
is set **twice** in `smb_read_andx()` (duplicate assignment — likely a copy-paste
artifact):
```c
rsp->DataCompactionMode = 0;
rsp->DataCompactionMode = 0;  /* BUG: duplicate */
```

**Gap:** The duplicate assignment is a minor code quality issue; the value 0
is correct. No functional gap for compaction mode — KSMBD does not support
compression or direct-I/O hints from the client in this command.

**Fix:** Remove the duplicate assignment.

### 3.6 Remaining Field in Response

For disk files, `Remaining` should be set to 0xFFFF (-1 as an unsigned 16-bit
value) to indicate "unknown/not applicable." For named pipes, it should indicate
bytes remaining in the current message.

**Current behavior:** `rsp->Remaining = 0` for both disk files and pipes.

**Gap (minor):** Some Windows clients expect `Remaining = 0xFFFF` for disk
file reads as per the spec. Setting it to 0 may confuse strict clients but is
generally tolerated. Set `rsp->Remaining = cpu_to_le16(0xFFFF)` for disk
files; leave 0 for pipes where the value has meaning.

### 3.7 Error Response for Invalid FID

**Current behavior:** Returns `STATUS_INVALID_HANDLE` for all read errors.

**Gap:** Specific error cases should return specific NT status codes:
- FID not found → STATUS_FILE_CLOSED (already correct)
- FID refers to a directory → STATUS_INVALID_DEVICE_REQUEST
- Seek beyond end of file → 0 bytes read, STATUS_SUCCESS (already handled
  by `ksmbd_vfs_read()` returning 0)

---

## 4. SMB_COM_WRITE_ANDX (0x2F) — MS-SMB §2.2.4.32

### 4.1 Wire Format (Request)

| Field | Size | Notes |
|-------|------|-------|
| AndXCommand | 1 | |
| AndXReserved | 1 | |
| AndXOffset | 2 | |
| Fid | 2 | File handle |
| OffsetLow | 4 | Low 32 bits |
| Reserved | 4 | Must be 0 |
| WriteMode | 2 | Bit flags (see below) |
| Remaining | 2 | Bytes remaining to write in this request chain |
| DataLengthHigh | 2 | High 16 bits of DataLength |
| DataLengthLow | 2 | Low 16 bits |
| DataOffset | 2 | Offset from SMB header start to data |
| OffsetHigh | 4 | High 32 bits (WordCount=14 only) |
| ByteCount | 2 | |
| Pad | 1 | Alignment byte |
| Data | var | Write data |

### 4.2 WriteMode Bits — Compliance Gap

| Bit | Value | Meaning |
|-----|-------|---------|
| 0 | 0x0001 | Write-through: flush to disk before responding |
| 1 | 0x0002 | ReadBytesAvailable: for named pipes, return bytes available |
| 2 | 0x0004 | Named pipe raw mode |
| 3 | 0x0008 | Named pipe start of message |

**Current behavior:**
```c
writethrough = (le16_to_cpu(req->WriteMode) == 1);
```
This check is **incorrect**. It tests whether the entire WriteMode word equals 1,
not whether bit 0 is set. If any other bit is set alongside the write-through
bit (e.g., WriteMode = 0x0003 for write-through + read-bytes-available), the
write-through semantics are silently dropped.

**Gap (HIGH PRIORITY):** The write-through bit check must use a bitmask:
```c
writethrough = !!(le16_to_cpu(req->WriteMode) & 0x0001);
```

**Additional gaps:**
- Bit 1 (ReadBytesAvailable): not implemented. For named pipes, the `Available`
  field in the response should return the number of bytes available to read from
  the pipe. The `Remaining` field in the write response currently always returns 0.
- Bits 2-3 (named pipe raw mode, start-of-message): Not implemented. Named pipe
  write is handled by `ksmbd_rpc_write()` which does not distinguish raw vs
  message mode. Low priority for most deployments.

### 4.3 OffsetHigh (Large File Support)

**Current behavior:**
```c
pos = le32_to_cpu(req->OffsetLow);
if (req->hdr.WordCount == 14)
    pos |= ((loff_t)le32_to_cpu(req->OffsetHigh) << 32);
```
This is correct. WordCount=12 means no OffsetHigh (legacy); WordCount=14 means
OffsetHigh is present (large file support).

### 4.4 ByteCount Handling for Large Writes

**Current behavior:** `DataLengthLow` and `DataLengthHigh` are combined using
`CAP_LARGE_WRITE_X` gating:
```c
count = le16_to_cpu(req->DataLengthLow);
if (conn->vals->capabilities & CAP_LARGE_WRITE_X)
    count |= (le16_to_cpu(req->DataLengthHigh) << 16);
```
This is correct per MS-SMB §3.3.5.8.

**Gap:** The `Remaining` field in the request (bytes remaining to write in
this ANDX chain for partial writes) is not used. Some clients split a large
write across multiple WRITE_ANDX requests and use `Remaining` to indicate how
much more data will follow. The server can use this to pre-allocate space. Low
priority.

### 4.5 Response Fields

The response `Count` and `CountHigh` fields correctly report how many bytes
were written (32-bit split across two 16-bit fields). The `Available` field
(occupying the `Remaining` slot in the response) is always set to 0.

**Gap:** For named-pipe writes, `Available` should return the number of bytes
available for the client to read from the pipe (after the write triggers a
response). This is part of the DCE/RPC named-pipe semantics and is medium
priority for full IPC pipe compliance.

---

## 5. SMB_COM_WRITE (0x0B) — MS-SMB §2.2.4.12

### 5.1 Wire Format (Request — WordCount = 0x05 = 5)

| Field | Size | Notes |
|-------|------|-------|
| Fid | 2 | File handle |
| Count | 2 | Bytes to write (max 65535) |
| Offset | 4 | File offset (32-bit, 2GB limit) |
| Remaining | 2 | Reserved |
| ByteCount | 2 | >= 3 |
| BufferFormat | 1 | Must be 1 |
| DataLength | 2 | Same as Count |
| Data | var | |

### 5.2 Response (WordCount = 0x01 = 1)

| Field | Size | Notes |
|-------|------|-------|
| Count | 2 | Bytes written |
| ByteCount | 2 | 0 |

### 5.3 Current Implementation — Compliance Analysis

KSMBD uses `smb_com_write_req_32bit` for this command (wct=5). The handler
`smb_write()` extracts `req->Offset` (32-bit), `req->Length` (KSMBD struct
names it `Length` but the spec calls it `Count`), and the data buffer.

**Gaps:**
1. **BufferFormat validation:** The byte immediately before `DataLength` is
   `BufferFormat` which must be 1 (data buffer). KSMBD does not validate this.
   If a client sends a malformed packet with `BufferFormat != 1`, it is silently
   accepted.
2. **DataLength vs ByteCount consistency:** The `DataLength` field in the wire
   format should equal `Count`. If they differ, the behavior is undefined. KSMBD
   uses `req->Length` directly without cross-checking against `req->ByteCount`.
3. **Truncate-on-zero-count:** When `Count == 0`, KSMBD calls
   `ksmbd_vfs_truncate(work, fp, pos)` which truncates the file to `pos` bytes.
   This matches the MS-SMB behavior for zero-length writes (truncate to offset).
   This is correct.
4. **2GB file size limit:** The 32-bit offset enforces a 2GB limit. Files beyond
   this offset cannot be written with SMB_COM_WRITE; clients should use
   WRITE_ANDX. No code change needed, but the error response for writes beyond
   4GB would be STATUS_INVALID_PARAMETER, which should be checked.
5. **Estimate field:** `req->Estimate` (a.k.a. `Remaining`) is not used. It
   was a hint for the server to know how much total data will be written. Ignoring
   it is acceptable.

---

## 6. SMB_COM_CLOSE (0x04) — MS-SMB §2.2.4.5

### 6.1 Wire Format

**Request (WordCount = 0x03 = 3):**

| Field | Size | Notes |
|-------|------|-------|
| FileID (FID) | 2 | Handle to close |
| LastWriteTime | 4 | UTIME (seconds since 1970); 0 = no change, 0xFFFFFFFF = no change |
| ByteCount | 2 | 0 |

**Response (WordCount = 0x00):**

| Field | Size | Notes |
|-------|------|-------|
| ByteCount | 2 | 0 |

### 6.2 LastWriteTime Semantics — Compliance Analysis

**Current behavior:**
```c
if (le32_to_cpu(req->LastWriteTime) > 0 &&
    le32_to_cpu(req->LastWriteTime) < 0xFFFFFFFF) {
    /* set mtime */
}
```

Per MS-SMB §2.2.4.5.1: "If this field contains a nonzero and non-negative
value, then the server **SHOULD** set the last write time of the file to the
provided time." The value 0 means "do not change." The value 0xFFFFFFFF means
"do not change." Any other value sets the time.

**Gap (minor):** The current check correctly handles both 0 and 0xFFFFFFFF as
"no-change" cases, which is compliant. The spec says "nonzero and non-negative,"
but since the field is unsigned 32-bit, the only special "no-change" sentinel
value documented is 0xFFFFFFFF. The current implementation is correct.

**Additional gap:** After `ksmbd_close_fd(work, req->FileID)`, the error is
not checked before building the response. If the FID is invalid,
`ksmbd_close_fd()` returns an error but the response is still built with
`STATUS_SUCCESS`. The actual behavior should be to return STATUS_INVALID_HANDLE
if the FID is not found.

**Fix:**
```c
err = ksmbd_close_fd(work, req->FileID);
if (err)
    rsp->hdr.Status.CifsError = STATUS_INVALID_HANDLE;
else
    rsp->hdr.Status.CifsError = STATUS_SUCCESS;
```

### 6.3 Oplock Break Notification on Close — Compliance Gap

When a file is closed that holds an oplock:
1. The server must **not** send an oplock break to the closing client — the
   close implicitly releases the oplock.
2. If other clients were waiting for the oplock to be released, they must be
   notified that the oplock is now available.

**Current behavior:** `ksmbd_close_fd()` calls the oplock release path via
`ksmbd_release_smb_lease()` or `opinfo_put()`. This is handled at the
`ksmbd_file` destruction layer. The path should be verified to correctly
unblock waiting openers.

**Gap:** When SMB1 oplock support is enabled (`smb1_oplock_enable = true`),
closing a file that held an oplock should trigger a check of the oplock waiters
queue and wake any threads blocked in `smb_grant_oplock()`. Verify that the
oplock infrastructure handles this correctly without sending a spurious break
to the closing client.

### 6.4 FID Release and Session State

**Current behavior:** `ksmbd_close_fd()` removes the FID from the session's
file table. After close, any subsequent use of the FID by the client returns
STATUS_FILE_CLOSED. This is correct.

**Gap:** The spec requires that if `SMB_COM_CLOSE` is received for an FID that
belongs to a different session or tree connection, the server must return
STATUS_ACCESS_DENIED (not STATUS_FILE_CLOSED). The current implementation does
not distinguish between "FID exists but belongs to another session" and "FID
does not exist at all." Both cases return STATUS_INVALID_HANDLE. This is a
security consideration that should be validated.

---

## 7. SMB_COM_FLUSH (0x05) — MS-SMB §2.2.4.6

### 7.1 Wire Format

**Request (WordCount = 0x01 = 1):**

| Field | Size | Notes |
|-------|------|-------|
| FileID (FID) | 2 | 0xFFFF = flush all files |
| ByteCount | 2 | 0 |

**Response (WordCount = 0x00):**

| Field | Size | Notes |
|-------|------|-------|
| ByteCount | 2 | 0 |

### 7.2 Flush All (FID = 0xFFFF)

**Current behavior:** When `req->FileID == 0xFFFF`, KSMBD calls
`ksmbd_file_table_flush(work)` which iterates all open files in the session
and calls `ksmbd_vfs_fsync()` on each.

This is compliant with MS-SMB §2.2.4.6.1: "If FID is 0xFFFF, the server
MUST attempt to flush all files opened by the client."

### 7.3 Single File Flush

**Current behavior:** For a specific FID, `ksmbd_vfs_fsync(work, req->FileID,
KSMBD_NO_FID, false)` is called.

### 7.4 Error Response — Compliance Gap

**Gap:** When a flush fails (e.g., disk full), the error response always uses
`STATUS_INVALID_HANDLE`. However, the appropriate NT status codes for flush
failures are:
- Invalid FID → STATUS_INVALID_HANDLE
- Disk I/O error → STATUS_UNEXPECTED_IO_ERROR
- Disk full → STATUS_DISK_FULL

**Fix:**
```c
switch (err) {
case -ENOENT: /* FID not found */
    rsp->hdr.Status.CifsError = STATUS_INVALID_HANDLE;
    break;
case -ENOSPC:
    rsp->hdr.Status.CifsError = STATUS_DISK_FULL;
    break;
default:
    rsp->hdr.Status.CifsError = STATUS_UNEXPECTED_IO_ERROR;
}
```

### 7.5 Directory Flush

The spec notes that flushing a directory handle is a no-op (directories have
no data to flush). KSMBD's `ksmbd_vfs_fsync()` calls `vfs_fsync_range()` on
the underlying file, which will succeed for directories on most Linux filesystems.
No gap.

---

## 8. Missing Commands

The following commands are entirely absent from the `smb1_server_cmds[]`
dispatch table. They are either not registered or registered but point to a
null handler.

### 8.1 SMB_COM_SEEK (0x12) — MS-SMB §2.2.4.17

**Purpose:** Legacy command to set the file position pointer in a file. Used
by DOS/OS2 applications for sequential reads.

**Wire Format (Request — WordCount = 0x04 = 4):**

| Field | Size | Notes |
|-------|------|-------|
| Fid | 2 | File handle |
| Mode | 2 | 0=from start, 1=from current, 2=from end |
| Offset | 4 | Signed seek offset |
| ByteCount | 2 | 0 |

**Wire Format (Response — WordCount = 0x02 = 2):**

| Field | Size | Notes |
|-------|------|-------|
| Offset | 4 | New absolute offset |
| ByteCount | 2 | 0 |

**Current Status:** Not in dispatch table. Unhandled requests return
`STATUS_NOT_IMPLEMENTED` via the default dispatch path.

**Implementation guidance:**
- Map Mode to SEEK_SET (0), SEEK_CUR (1), SEEK_END (2)
- The server does not maintain a per-FID position counter for SMB (each
  READ/WRITE carries its own offset). SEEK is essentially informational.
- For a compliant implementation, maintain a `seek_pos` field in `ksmbd_file`
  and update it on SEEK. Subsequent READ/WRITE commands that use the old-style
  32-bit offset should use this value... but since SMB READ/WRITE always
  carry explicit offsets, SEEK is effectively a no-op for disk files.
- For named pipes, SEEK is always rejected with STATUS_NOT_SUPPORTED.

**Priority:** Low. Modern clients never use SMB_COM_SEEK with NT servers.
Implement as a stub that returns the requested offset in the response.

### 8.2 SMB_COM_WRITE_AND_CLOSE (0x0C) — MS-SMB §2.2.4.15

**Purpose:** Combined write + close in a single round trip. Reduces latency
for small file operations.

**Wire Format (Request — WordCount = 0x0C = 12 or 0x0E = 14):**

| Field | Size | Notes |
|-------|------|-------|
| Fid | 2 | File handle |
| Count | 2 | Bytes to write |
| WriteOffset | 4 | File offset |
| LastWriteTime | 4 | UTIME (0 = no change, 0xFFFFFFFF = no change) |
| (padding) | 12 | Reserved (WordCount=14 variant has two extra words) |
| ByteCount | 2 | >= 4 |
| BufferFormat | 1 | 1 = data |
| DataLength | 2 | Same as Count |
| Data | var | |

**Wire Format (Response — WordCount = 0x01 = 1):**

| Field | Size | Notes |
|-------|------|-------|
| Count | 2 | Bytes written |
| ByteCount | 2 | 0 |

**Current Status:** Not in dispatch table. Absent from header constants.

**Implementation guidance:**
1. Parse the request as write + close semantics
2. Perform the write using `ksmbd_vfs_write()`
3. Apply `LastWriteTime` if nonzero and not 0xFFFFFFFF
4. Call `ksmbd_close_fd()`
5. Respond with bytes written
6. Define struct `smb_com_write_and_close_req` and `smb_com_write_and_close_rsp`
   in `smb1pdu.h`
7. Add command constant `SMB_COM_WRITE_AND_CLOSE 0x0C` to header
8. Register in `smb1_server_cmds[]` and `smb1_req_struct_size()`

**Priority:** Medium. Some older clients (Windows for Workgroups, early Windows
9x) use this. Modern clients use WRITE_ANDX. Worth implementing for correctness.

### 8.3 SMB_COM_WRITE_RAW (0x1D) — MS-SMB §2.2.4.22

**Purpose:** High-throughput raw write that sends data in a second PDU after
the initial command PDU. Allows the client to pipeline data without waiting
for an ACK.

**Current Status:** Not implemented, not in header.

**Implementation guidance:**
This is a two-phase protocol:
1. Client sends WRITE_RAW request with header (no data yet, or partial data)
2. Server responds with an interim response indicating how much data to send
3. Client sends raw data (no SMB header)
4. Server processes the raw data and sends a final response

This requires maintaining per-connection state during the raw data transfer,
which significantly complicates the state machine. The protocol also has a
race condition with multiplexed requests.

**Recommendation:** Return STATUS_SMB_BAD_COMMAND (0x00160002) or
STATUS_NOT_SUPPORTED. MS-SMB §3.3.5.4 explicitly allows servers to decline
raw mode. Advertising `CAP_RAW_MODE` in the negotiate response would be
incorrect if raw mode is not implemented — verify that `SMB1_SERVER_CAPS` in
`smb1pdu.h` does **not** include `CAP_RAW_MODE` (0x00000001). Currently it
does not — this is correct.

**Priority:** Not recommended for implementation. The protocol is obsolete and
its complexity is unjustified.

### 8.4 SMB_COM_READ_RAW (0x1C) — MS-SMB §2.2.4.21

**Purpose:** Raw read that bypasses the SMB header for the data response,
allowing the full transport MTU to be used.

**Current Status:** Not implemented, not in header.

**Recommendation:** Same as WRITE_RAW — return STATUS_NOT_SUPPORTED or
STATUS_SMB_BAD_COMMAND. The server must not advertise `CAP_RAW_MODE` if
raw reads are not supported. This is already the case in KSMBD.

**Priority:** Not recommended for implementation.

### 8.5 SMB_COM_COPY (0x29) — MS-SMB §2.2.4.27

**Purpose:** Server-side file copy. The client provides source and destination
path/FID; the server performs the copy atomically without the client having to
read and re-write the data.

**Current Status:** The command opcode (0x29) is registered in the string table
(`smb_cmd_str[]` has `[SMB_COM_COPY] = "SMB_COM_COPY"`) and in the header
(`SMB_COM_COPY 0x29`), but there is **no handler registered** in
`smb1_server_cmds[]`. Requests for this opcode will be silently unhandled
(the dispatch table has a null entry for index 0x29).

**Wire Format (Request — WordCount = 0x03 = 3):**

| Field | Size | Notes |
|-------|------|-------|
| TreeID (source) | 2 | May differ from TID in header |
| OpenFunction | 2 | Disposition for destination |
| Flags | 2 | 0x0001=destination is dir, 0x0004=ASCII name, 0x0010=tree copy |
| ByteCount | 2 | >= 4 |
| BufferFormat1 | 1 | 4 = ASCII, ... |
| SourceFileName | var | |
| BufferFormat2 | 1 | |
| DestinationFileName | var | |

**Wire Format (Response — WordCount = 0x01 = 1):**

| Field | Size | Notes |
|-------|------|-------|
| CopyCount | 2 | Number of files copied |
| ByteCount | 2 | >= 0 |
| ErrorFile | var | Name of file that caused error (if any) |

**Implementation guidance:**
1. Resolve source path relative to the source TreeID's share root
2. Resolve destination path relative to the destination share root (may be
   different TID)
3. Use `vfs_copy_file_range()` (Linux 4.5+) for efficient server-side copy
4. Handle the `Flags` field: 0x0001 means destination is a directory (append
   source filename to destination directory path)
5. `OpenFunction` controls creation semantics for the destination

**Priority:** Medium. Windows clients (especially File Manager, robocopy with
/B flag) may use this for performance. The underlying Linux `vfs_copy_file_range()`
makes this feasible to implement efficiently.

### 8.6 SMB_COM_MOVE (0x2A) — MS-SMB §2.2.4.28

**Purpose:** Server-side rename/move operation. Similar to COPY but moves
the file.

**Current Status:** Not in dispatch table, not in header constants. The constant
`SMB_COM_MOVE` is not defined (only `SMB_COM_RENAME` 0x07 for simple renames).

**Wire Format (Request — WordCount = 0x03 = 3):**

| Field | Size | Notes |
|-------|------|-------|
| TreeID | 2 | |
| OpenFunction | 2 | (unused for moves) |
| Flags | 2 | 0x0001=destination is dir |
| ByteCount | 2 | |
| BufferFormat1 | 1 | |
| SourceFileName | var | |
| BufferFormat2 | 1 | |
| DestinationFileName | var | |

**Implementation guidance:**
- For same-filesystem moves, use `ksmbd_vfs_rename()` (already implemented for
  other paths)
- For cross-filesystem moves, deny with STATUS_NOT_SAME_DEVICE
- Handle cross-TID moves carefully (security boundary check)

**Priority:** Low. Modern clients use NT_RENAME (0xA5) which KSMBD already
implements via `smb_nt_rename()`. SMB_COM_MOVE is redundant.

### 8.7 SMB_COM_QUERY_INFORMATION2 (0x23) — MS-SMB §2.2.4.21

**Purpose:** Get file times and size by FID (as opposed to QUERY_INFORMATION
which uses a path).

**Current Status:** Not in dispatch table, not in header constants.

**Wire Format (Request — WordCount = 0x01 = 1):**

| Field | Size | Notes |
|-------|------|-------|
| Fid | 2 | |
| ByteCount | 2 | 0 |

**Wire Format (Response — WordCount = 0x0B = 11):**

| Field | Size | Notes |
|-------|------|-------|
| CreateDate | 2 | DOS date |
| CreationTime | 2 | DOS time |
| LastAccessDate | 2 | DOS date |
| LastAccessTime | 2 | DOS time |
| LastWriteDate | 2 | DOS date |
| LastWriteTime | 2 | DOS time |
| FileDataSize | 4 | File size (32-bit) |
| FileAllocationSize | 4 | Allocation size (32-bit) |
| FileAttributes | 2 | DOS attributes |
| ByteCount | 2 | 0 |

**Implementation guidance:**
- Look up FID in the session's file table
- Call `vfs_getattr()` to get stat
- Convert Unix timestamps to DOS time using `unix_to_dos_time()`
- Fill response fields

**Priority:** Medium. Some legacy clients (Windows 9x, NT 3.x) use this
instead of TRANS2_QUERY_FILE_INFORMATION. The TRANS2 equivalent is already
implemented in KSMBD and should be preferred.

### 8.8 SMB_COM_SET_INFORMATION2 (0x22) — MS-SMB §2.2.4.18

**Purpose:** Set file times by FID.

**Current Status:** Not in dispatch table, not in header constants.

**Wire Format (Request — WordCount = 0x07 = 7):**

| Field | Size | Notes |
|-------|------|-------|
| Fid | 2 | |
| CreateDate | 2 | DOS date (0 = no change) |
| CreationTime | 2 | DOS time (0 = no change) |
| LastAccessDate | 2 | DOS date (0 = no change) |
| LastAccessTime | 2 | DOS time (0 = no change) |
| LastWriteDate | 2 | DOS date (0 = no change) |
| LastWriteTime | 2 | DOS time (0 = no change) |
| ByteCount | 2 | 0 |

**Implementation guidance:**
- Look up FID
- For each nonzero date/time pair, convert from DOS time to Unix `timespec64`
  using `dos_to_unix_time()` (or equivalent)
- Call `vfs_utimes()` or `ksmbd_vfs_setattr()` with the constructed `iattr`

**Priority:** Medium. Needed for `LastWriteTime` updates on Windows 9x/NT 3.x
clients that do not use TRANS2_SET_FILE_INFORMATION.

### 8.9 SMB_COM_OPEN (0x02) — MS-SMB §2.2.4.3

**Purpose:** Legacy open command (pre-ANDX, pre-NT). Used by very old clients.

**Current Status:** Not in dispatch table, not in header constants.

**Wire Format (Request — WordCount = 0x02 = 2):**

| Field | Size | Notes |
|-------|------|-------|
| DesiredAccess | 2 | Old-style access word |
| SearchAttributes | 2 | DOS search attributes |
| ByteCount | 2 | >= 2 |
| BufferFormat | 1 | 4 = ASCII |
| FileName | var | |

**Wire Format (Response — WordCount = 0x07 = 7):**

| Field | Size | Notes |
|-------|------|-------|
| Fid | 2 | |
| FileAttributes | 2 | DOS attributes |
| LastWriteTime | 4 | UTIME |
| DataSize | 4 | File size |
| GrantedAccess | 2 | |
| ByteCount | 2 | 0 |

**Priority:** Low. Only needed for DOS clients and Windows for Workgroups.
OPEN_ANDX covers the same functionality. Implement only if DOS client support
is needed.

### 8.10 SMB_COM_CREATE (0x03) — MS-SMB §2.2.4.4

**Purpose:** Create a new file (or open existing, per search-attributes).

**Current Status:** Not in dispatch table, not in header constants.

**Wire Format (Request — WordCount = 0x03 = 3):**

| Field | Size | Notes |
|-------|------|-------|
| FileAttributes | 2 | DOS attributes |
| CreationTime | 4 | UTIME |
| ByteCount | 2 | >= 2 |
| BufferFormat | 1 | 4 = ASCII |
| FileName | var | |

**Response:** Same as SMB_COM_OPEN response (returns a FID).

**Priority:** Low. Superseded by OPEN_ANDX and NT_CREATE_ANDX.

### 8.11 SMB_COM_CREATE_NEW (0x0F) — MS-SMB §2.2.4.16

**Purpose:** Create a file; fail if it already exists (no open-if-exists
semantics). Equivalent to `O_CREAT | O_EXCL`.

**Current Status:** Not in dispatch table, not in header constants.

**Wire Format (Request — WordCount = 0x03 = 3):**

| Field | Size | Notes |
|-------|------|-------|
| FileAttributes | 2 | DOS attributes |
| CreationTime | 4 | UTIME |
| ByteCount | 2 | >= 2 |
| BufferFormat | 1 | 4 = ASCII |
| FileName | var | |

**Response:** Returns a FID.

**Priority:** Low. Only needed for pre-NT clients.

### 8.12 SMB_COM_CREATE_TEMPORARY (0x0E) — MS-SMB §2.2.4.15

**Purpose:** Create a temporary file with a server-generated unique name in a
specified directory.

**Current Status:** Not in dispatch table, not in header constants.

**Wire Format (Request — WordCount = 0x03 = 3):**

| Field | Size | Notes |
|-------|------|-------|
| FileAttributes | 2 | DOS attributes |
| CreationTime | 4 | UTIME |
| ByteCount | 2 | >= 2 |
| BufferFormat | 1 | 4 = ASCII |
| DirectoryName | var | Path where temp file is created |

**Wire Format (Response — WordCount = 0x01 = 1):**

| Field | Size | Notes |
|-------|------|-------|
| Fid | 2 | |
| ByteCount | 2 | >= 2 |
| BufferFormat | 1 | 4 = ASCII |
| FileName | var | Server-generated filename |

**Implementation guidance:**
- Use `kern_mktemp()` or similar to generate a unique name in the target directory
- Create the file with `O_CREAT | O_EXCL`
- Return the FID and the generated filename in the response

**Priority:** Low. Rarely used by modern clients.

---

## 9. Prioritized Implementation Plan

### Priority 1 — Correctness Bugs (implement immediately)

| # | Issue | File | Effort |
|---|-------|------|--------|
| P1-1 | `smb_write_andx()`: fix WriteMode bit 0 check (uses `== 1` instead of `& 0x0001`) | smb1pdu.c:3453 | Trivial |
| P1-2 | `smb_nt_create_andx()`: set `ext_rsp->GuestAccess` in extended response | smb1pdu.c:2970 | Trivial |
| P1-3 | `smb_read_andx()`: remove duplicate `rsp->DataCompactionMode = 0` | smb1pdu.c:3258 | Trivial |
| P1-4 | `smb_open_andx()`: set `rsp->FileAttributes` from `smb_get_dos_attr()`, not hardcoded ATTR_NORMAL | smb1pdu.c:8670 | Small |
| P1-5 | `smb_close()`: return STATUS_INVALID_HANDLE when FID not found (currently returns STATUS_SUCCESS) | smb1pdu.c:3095 | Small |

### Priority 2 — Spec Gaps with Client Impact (implement next)

| # | Issue | File | Effort |
|---|-------|------|--------|
| P2-1 | `smb_nt_create_andx()`: implement `NT_CREATE_OPEN_TARGET_DIR` flag (REQ_OPENDIRONLY) | smb1pdu.c:2709 | Medium |
| P2-2 | `smb_flush()`: refine error status mapping (not just STATUS_INVALID_HANDLE) | smb1pdu.c:3609 | Small |
| P2-3 | Add `SMB_COM_QUERY_INFORMATION2` (0x23) handler | smb1pdu.c (new fn) | Medium |
| P2-4 | Add `SMB_COM_SET_INFORMATION2` (0x22) handler | smb1pdu.c (new fn) | Medium |
| P2-5 | `smb_read_andx()`: set `rsp->Remaining = 0xFFFF` for disk file reads | smb1pdu.c:3256 | Trivial |
| P2-6 | `smb_nt_create_andx()`: validate ImpersonationLevel range [0..3] | smb1pdu.c:2509 | Small |
| P2-7 | `smb_nt_create_andx()`: implement FILE_NO_EA_KNOWLEDGE CreateOption check | smb1pdu.c:2557 | Medium |

### Priority 3 — Missing Commands (implement for completeness)

| # | Issue | File | Effort |
|---|-------|------|--------|
| P3-1 | Add `SMB_COM_WRITE_AND_CLOSE` (0x0C) handler | smb1pdu.c (new fn) | Medium |
| P3-2 | Add `SMB_COM_COPY` (0x29) handler | smb1pdu.c (new fn) | Large |
| P3-3 | Add `SMB_COM_SEEK` (0x12) stub | smb1pdu.c (new fn) | Small |
| P3-4 | Add `SMB_COM_MOVE` (0x2A) handler | smb1pdu.c (new fn) | Medium |

### Priority 4 — Low Priority / Legacy (implement if DOS client support is needed)

| # | Issue | File | Effort |
|---|-------|------|--------|
| P4-1 | `SMB_COM_OPEN` (0x02) | smb1pdu.c (new fn) | Medium |
| P4-2 | `SMB_COM_CREATE` (0x03) | smb1pdu.c (new fn) | Medium |
| P4-3 | `SMB_COM_CREATE_NEW` (0x0F) | smb1pdu.c (new fn) | Small |
| P4-4 | `SMB_COM_CREATE_TEMPORARY` (0x0E) | smb1pdu.c (new fn) | Medium |

### Priority 5 — Deliberately Not Implemented

| Command | Rationale |
|---------|-----------|
| SMB_COM_WRITE_RAW (0x1D) | Protocol complexity outweighs benefit; CAP_RAW_MODE not advertised |
| SMB_COM_READ_RAW (0x1C) | Same as above |

---

## 10. Struct Definitions Needed in smb1pdu.h

The following structs need to be added to `smb1pdu.h` for the missing commands:

```c
/* SMB_COM_WRITE_AND_CLOSE (0x0C) */
#define SMB_COM_WRITE_AND_CLOSE 0x0C
struct smb_com_write_and_close_req {
    struct smb_hdr hdr;     /* wct = 12 */
    __u16 Fid;
    __le16 Count;
    __le32 WriteOffset;
    __le32 LastWriteTime;
    __le32 Reserved[3];
    __le16 ByteCount;
    __u8   BufferFormat;
    __le16 DataLength;
    char   Data[0];
} __packed;

struct smb_com_write_and_close_rsp {
    struct smb_hdr hdr;     /* wct = 1 */
    __le16 Count;
    __le16 ByteCount;       /* 0 */
} __packed;

/* SMB_COM_QUERY_INFORMATION2 (0x23) */
#define SMB_COM_QUERY_INFORMATION2 0x23
struct smb_com_qinfo2_req {
    struct smb_hdr hdr;     /* wct = 1 */
    __u16 Fid;
    __le16 ByteCount;       /* 0 */
} __packed;

struct smb_com_qinfo2_rsp {
    struct smb_hdr hdr;     /* wct = 11 */
    __le16 CreateDate;
    __le16 CreationTime;
    __le16 LastAccessDate;
    __le16 LastAccessTime;
    __le16 LastWriteDate;
    __le16 LastWriteTime;
    __le32 FileDataSize;
    __le32 FileAllocationSize;
    __le16 FileAttributes;
    __le16 ByteCount;       /* 0 */
} __packed;

/* SMB_COM_SET_INFORMATION2 (0x22) */
#define SMB_COM_SET_INFORMATION2 0x22
struct smb_com_sinfo2_req {
    struct smb_hdr hdr;     /* wct = 7 */
    __u16 Fid;
    __le16 CreateDate;
    __le16 CreationTime;
    __le16 LastAccessDate;
    __le16 LastAccessTime;
    __le16 LastWriteDate;
    __le16 LastWriteTime;
    __le16 ByteCount;       /* 0 */
} __packed;

struct smb_com_sinfo2_rsp {
    struct smb_hdr hdr;     /* wct = 0 */
    __le16 ByteCount;       /* 0 */
} __packed;

/* SMB_COM_SEEK (0x12) */
#define SMB_COM_SEEK 0x12
struct smb_com_seek_req {
    struct smb_hdr hdr;     /* wct = 4 */
    __u16 Fid;
    __le16 Mode;            /* 0=from start, 1=from current, 2=from end */
    __le32 Offset;          /* signed */
    __le16 ByteCount;       /* 0 */
} __packed;

struct smb_com_seek_rsp {
    struct smb_hdr hdr;     /* wct = 2 */
    __le32 Offset;          /* new absolute offset */
    __le16 ByteCount;       /* 0 */
} __packed;

/* SMB_COM_COPY (0x29) — header only defined, no handler yet */
struct smb_com_copy_req {
    struct smb_hdr hdr;     /* wct = 3 */
    __u16  Tid2;            /* TID for destination */
    __le16 OpenFunction;
    __le16 Flags;
    __le16 ByteCount;
    /* followed by two buffer-format + name pairs */
} __packed;

struct smb_com_copy_rsp {
    struct smb_hdr hdr;     /* wct = 1 */
    __le16 CopyCount;
    __le16 ByteCount;
    /* followed by optional error file name */
} __packed;
```

---

## 11. smb1_req_struct_size() Updates Needed

The `smb1_req_struct_size()` function in `smb1misc.c` validates the WordCount
field for each command. Add validation entries for all newly registered commands:

```c
case SMB_COM_SEEK:           /* 0x12 */
    if (wc != 0x4)
        return -EINVAL;
    break;
case SMB_COM_SET_INFORMATION2: /* 0x22 */
    if (wc != 0x7)
        return -EINVAL;
    break;
case SMB_COM_QUERY_INFORMATION2: /* 0x23 */
    if (wc != 0x1)
        return -EINVAL;
    break;
case SMB_COM_COPY:           /* 0x29 */
    if (wc != 0x3)
        return -EINVAL;
    break;
case SMB_COM_WRITE_AND_CLOSE: /* 0x0C */
    if (wc != 0xc && wc != 0xe)
        return -EINVAL;
    break;
```

---

## 12. Testing Requirements

For each implemented or fixed item, the following test scenarios should be
verified:

### 12.1 NT_CREATE_ANDX Tests
- Open existing file with each CreateDisposition value (0-5)
- Create file with `FILE_DELETE_ON_CLOSE`; verify file disappears on close
- Request extended response (`NT_CREATE_REQUEST_EXTENDED_RESPONSE`); verify
  `GuestAccess` field is populated
- Set `FILE_NO_EA_KNOWLEDGE` on a file with EAs; verify STATUS_ACCESS_DENIED
- Request `FILE_WRITE_THROUGH`; verify `O_SYNC` semantics
- Request with `NT_CREATE_OPEN_TARGET_DIR` flag; verify parent directory is opened

### 12.2 OPEN_ANDX Tests
- Open existing file; verify `FileAttributes` in response matches actual file
- Open file larger than 4GB; verify `EndOfFile` is capped at 0xFFFFFFFF
- Open with `SMBOPEN_WRITE_THROUGH` (bit 14 of Mode); verify O_SYNC
- Test all `OpenFunction` values (0x0000, 0x0001, 0x0002, 0x0010)

### 12.3 READ_ANDX Tests
- Read from offset > 4GB (verify OffsetHigh is used)
- Read with `MaxCountHigh` set; verify up to 64MB can be read
- Verify `Remaining` field is 0xFFFF for disk files

### 12.4 WRITE_ANDX Tests
- Write with `WriteMode = 0x0003` (write-through + bytes-available); verify
  write-through is honored (currently broken due to `== 1` check)
- Write to offset > 4GB

### 12.5 CLOSE Tests
- Close with `LastWriteTime = 0` (no change); verify mtime unchanged
- Close with `LastWriteTime = 0xFFFFFFFF` (no change); verify mtime unchanged
- Close with valid `LastWriteTime`; verify mtime is updated
- Close with invalid FID; verify STATUS_INVALID_HANDLE

### 12.6 FLUSH Tests
- Flush FID=0xFFFF; verify all open files are synced
- Flush specific FID; verify only that file is synced
- Flush invalid FID; verify STATUS_INVALID_HANDLE (not STATUS_UNEXPECTED_IO_ERROR)

---

## 13. References

- MS-SMB: Microsoft Open Specifications — Server Message Block (SMB) Protocol
  Specification, version 2021-09-29
  - §2.2.4.3 SMB_COM_OPEN
  - §2.2.4.4 SMB_COM_CREATE
  - §2.2.4.5 SMB_COM_CLOSE
  - §2.2.4.6 SMB_COM_FLUSH
  - §2.2.4.12 SMB_COM_WRITE
  - §2.2.4.15 SMB_COM_CREATE_TEMPORARY / SMB_COM_WRITE_AND_CLOSE
  - §2.2.4.16 SMB_COM_CREATE_NEW
  - §2.2.4.17 SMB_COM_SEEK
  - §2.2.4.18 SMB_COM_SET_INFORMATION2
  - §2.2.4.21 SMB_COM_QUERY_INFORMATION2 / SMB_COM_READ_RAW
  - §2.2.4.22 SMB_COM_WRITE_RAW
  - §2.2.4.27 SMB_COM_COPY
  - §2.2.4.28 SMB_COM_MOVE
  - §2.2.4.30 SMB_COM_OPEN_ANDX
  - §2.2.4.31 SMB_COM_READ_ANDX
  - §2.2.4.32 SMB_COM_WRITE_ANDX
  - §2.2.4.64 SMB_COM_NT_CREATE_ANDX
- KSMBD source: `src/protocol/smb1/smb1pdu.c` (current branch)
- KSMBD headers: `src/include/protocol/smb1pdu.h`
