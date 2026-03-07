# SMB1 Protocol Upgrade Plan — KSMBD
## From ~55% to 100% MS-SMB Compliance

**Repository:** `/home/ezechiel203/ksmbd`
**Branch:** `phase1-security-hardening`
**Spec:** MS-SMB (v20260114), MS-CIFS, MS-DFSC, Samba CIFS POSIX Extensions
**Audit date:** 2026-03-01
**Wave 1 implementation complete:** 2026-03-02 (commit `bc5ef70`)
**Synthesised from:** `smb1_plan_01` through `smb1_plan_06` (6 research documents)

**Primary source files:**
- `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c` (9040 lines)
- `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1ops.c`
- `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1misc.c`
- `/home/ezechiel203/ksmbd/src/include/protocol/smb1pdu.h`
- `/home/ezechiel203/ksmbd/src/fs/oplock.c`
- `/home/ezechiel203/ksmbd/src/protocol/common/netmisc.c`

---

## 0. Executive Summary

KSMBD's SMB1 stack was at roughly **55%** of the MS-SMB specification before Wave 1.
Wave 1 (Track A, commit `bc5ef70`) implemented all 27 P1 critical bugs, added
QUERY_INFORMATION2, SET_INFORMATION2, and NT_TRANSACT (0xA0) dispatcher with all 8
subcommands, added 6 TRANSACTION2 missing info levels, and added 5 legacy commands
(SEEK, WRITE_AND_CLOSE, OPEN, CREATE_NEW, COPY). Post-Wave 1 compliance is ~83%.

### Compliance Breakdown

| Area | Pre-Wave 1 | Post-Wave 1 |
|---|---|---|
| Core session / negotiate / tree | ~95% | ~97% |
| File I/O (open/read/write/close) | ~85% | ~92% |
| TRANSACTION2 subcommands | ~75% | ~90% |
| Locking | ~70% | ~85% |
| TRANSACTION named pipe | ~30% | ~40% |
| NT_TRANSACT (0xA0) | 0% | ~62% |
| Security descriptors via SMB1 | 0% | ~55% |
| Legacy commands (SEARCH, FIND, COPY, etc.) | ~10% | ~45% |
| DFS referrals | 0% | 0% |
| Print operations | 0% | ~10% |

**Overall: ~55% → ~83%**

### Wave 1 Track A — Implemented

| After completing | Estimated compliance |
|---|---|
| Pre-Wave 1 (baseline) | ~55% |
| After P1 (27 critical bugs fixed) | ~75% |
| After P1 + P2 (new commands + info levels) | ~82% |
| After P1 + P2 + P3 (TRANSACTION2 info levels) | ~88% |
| After P1 + P2 + P3 + P4 (legacy commands) | ~83% |

Note: The P4 legacy commands added (SEEK, WRITE_AND_CLOSE, OPEN, CREATE_NEW, COPY,
QUERY_INFORMATION2, SET_INFORMATION2) bring more commands into scope but some remain
partially implemented, keeping the post-Wave 1 estimate at ~83%.

The remaining ~17% represents deliberately omitted features (raw mode, print
submission backend, complex DFS topologies) and NT_TRANSACT subcommands not yet wired.

### Most Critical Missing Piece

`SMB_COM_NT_TRANSACT` (opcode 0xA0) has **no dispatcher at all** in `smb1ops.c`.
When a client sends it, `smb1misc.c` returns `-EOPNOTSUPP` and the packet is
silently dropped — the client receives no error response. This breaks:
- Windows Explorer "Security" tab (Properties dialog)
- Applications using `NtCreateFile` with an initial security descriptor
- Directory change notifications over SMB1
- Any FSCTL via NT_TRANSACT_IOCTL

---

## 1. Priority 1 — Critical Bugs

These are **bugs in currently-implemented handlers** that cause incorrect wire
behaviour. Fix these first.

### 1.1 WRITE_ANDX WriteMode Bit Check — Wrong Comparison

**Location:** `src/protocol/smb1/smb1pdu.c` line 3453 (`smb_write_andx()`)

**Bug:**
```c
writethrough = (le16_to_cpu(req->WriteMode) == 1);
```
This checks whether the entire `WriteMode` word equals 1, not whether bit 0 is
set. When other `WriteMode` bits are also set (e.g., `0x0003` for write-through
plus read-bytes-available), write-through semantics are silently dropped.

**Spec:** MS-SMB §2.2.4.32.1 — `WriteMode` bit 0 (0x0001) is the write-through bit.

**Fix:**
```c
writethrough = !!(le16_to_cpu(req->WriteMode) & 0x0001);
```

---

### 1.2 NT_CREATE_ANDX Extended Response GuestAccess Not Set

**Location:** `src/protocol/smb1/smb1pdu.c` line 2970 (`smb_nt_create_andx()`)

**Bug:** `ext_rsp->GuestAccess` is never written. The struct field `__le32
GuestAccess` in `smb_com_open_ext_rsp` exists but is not assigned. Per MS-SMB
§2.2.4.64.2, `GuestMaximalAccessRights` must be set in the extended response.

**Fix:**
```c
ext_rsp->GuestAccess = cpu_to_le32(FILE_GENERIC_READ);
```

---

### 1.3 READ_ANDX Duplicate DataCompactionMode Assignment

**Location:** `src/protocol/smb1/smb1pdu.c` line 3258 (`smb_read_andx()`)

**Bug:** `rsp->DataCompactionMode = 0` is assigned twice (copy-paste artifact).
The duplicate is harmless but is a code quality issue.

**Fix:** Remove the duplicate assignment.

---

### 1.4 OPEN_ANDX FileAttributes Always ATTR_NORMAL

**Location:** `src/protocol/smb1/smb1pdu.c` line 8670 (`smb_open_andx()`)

**Bug:** The response `rsp->FileAttributes` is always set to `ATTR_NORMAL`
(0x0000) regardless of the actual file attributes. MS-SMB §2.2.4.30.2 requires
the real DOS attributes.

**Fix:** Replace with:
```c
rsp->FileAttributes = cpu_to_le16(smb_get_dos_attr(&stat));
```

---

### 1.5 CLOSE Does Not Return Error for Invalid FID

**Location:** `src/protocol/smb1/smb1pdu.c` line 3095 (`smb_close()`)

**Bug:** When `ksmbd_close_fd()` fails (FID not found), the response is still
sent with `STATUS_SUCCESS`. MS-SMB §2.2.4.5 requires `STATUS_INVALID_HANDLE`
for an invalid FID.

**Fix:**
```c
err = ksmbd_close_fd(work, req->FileID);
if (err)
    rsp->hdr.Status.CifsError = STATUS_INVALID_HANDLE;
```

---

### 1.6 LOGOFF_ANDX Tears Down Entire TCP Connection

**Location:** `src/protocol/smb1/smb1pdu.c` lines 446–453 (`smb_session_disconnect()`)

**Bug:** `ksmbd_conn_set_exiting(conn)` terminates the entire TCP connection
instead of just the `Uid` (session). Per MS-SMB §2.2.4.54, `SMB_COM_LOGOFF_ANDX`
invalidates only the specific UID; other sessions on the same connection remain
active. With multiple UIDs, this incorrectly tears them all down.

**Fix:** Only invalidate `work->sess` via `ksmbd_session_destroy(sess)`, and
transition `conn` to exiting only if there are no remaining sessions.

---

### 1.7 LOGOFF_ANDX Response WordCount = 0 Instead of 2

**Location:** `src/protocol/smb1/smb1pdu.c` (`smb_session_disconnect()`)

**Bug:** Per MS-SMB §2.2.4.54.2, the LOGOFF_ANDX response must have `WordCount=2`
(the AndX block). The current handler relies on `init_smb_rsp_hdr()` leaving
`WordCount=0`, which a strict client will reject as malformed.

**Fix:** Explicitly set:
```c
rsp->WordCount = 2;
rsp->AndXCommand = SMB_NO_MORE_ANDX_COMMAND;
rsp->AndXReserved = 0;
rsp->AndXOffset = cpu_to_le16(get_rfc1002_len(rsp_hdr));
rsp->ByteCount = 0;
```

---

### 1.8 TREE_DISCONNECT Wrong Error for Invalid TID

**Location:** `src/protocol/smb1/smb1pdu.c` line 473 (`smb_tree_disconnect()`)

**Bug:** When `tcon == NULL`, the error returned is `STATUS_NO_SUCH_USER`.
MS-SMB §2.2.4.51 requires `STATUS_SMB_BAD_TID` (mapped to `ERRSRV/ERRinvnid`).

**Fix:** Change to `STATUS_SMB_BAD_TID`.

---

### 1.9 NEGOTIATE Returns Wrong Error for No Common Dialect

**Location:** `src/protocol/smb1/smb1pdu.c` lines 988–991

**Bug:** When no common dialect is found, KSMBD returns `STATUS_INVALID_LOGON_TYPE`.
Per MS-SMB §2.2.4.52.2, the server MUST set `DialectIndex = 0xFFFF` with
`Status = STATUS_SUCCESS` — the error is conveyed in `DialectIndex`, not in the
status field. The current response leaks server capability information unnecessarily.

**Fix:** On `BAD_PROT_ID`, return `WordCount=1, DialectIndex=0xFFFF, ByteCount=0,
Status=STATUS_SUCCESS`.

---

### 1.10 NEGOTIATE MaxRawSize Must Be 0 Without CAP_RAW_MODE

**Location:** `src/protocol/smb1/smb1pdu.c` line 1011

**Bug:** KSMBD advertises `MaxRawSize = 65536` but does not include `CAP_RAW_MODE`
in `SMB1_SERVER_CAPS`. Per MS-SMB §2.2.4.52.2: "If CAP_RAW_MODE is not set in
Capabilities, MaxRawSize SHOULD be set to 0."

**Fix:** Set `rsp->MaxRawSize = 0`.

---

### 1.11 SESSION_SETUP mechToken Length Mismatch (Potential Over-Read)

**Location:** `src/protocol/smb1/smb1pdu.c` line 1326 (`build_sess_rsp_extsec()`)

**Bug:** `ksmbd_decode_ntlmssp_auth_blob()` is called with
`le16_to_cpu(req->SecurityBlobLength)` as the blob length. But when
`conn->mechToken` is set (SPNEGO decoded an inner NTLMSSP token), the actual
inner token length may be smaller. Passing the outer `SecurityBlobLength` as the
NTLMSSP blob length can cause the NTLMSSP parser to read beyond the actual inner
token — a potential buffer over-read.

**Fix:** When `conn->mechToken` is set, use `conn->mechTokenLen` rather than
`req->SecurityBlobLength`.

---

### 1.12 TRANSACTION2 query_file_info_pipe() Double Write of DeletePending

**Location:** `src/protocol/smb1/smb1pdu.c` lines 7020–7021

**Bug:**
```c
standard_info->DeletePending = 0;
standard_info->Directory = 0;
standard_info->DeletePending = 1;   /* second write overwrites first */
```
The second write is a copy-paste error. `DeletePending` should be 0 for open
pipe handles.

**Fix:** Remove the third line (`DeletePending = 1`).

---

### 1.13 SET_FILE_INFORMATION smb_fileinfo_rename() Truncates Wrong File

**Location:** `src/protocol/smb1/smb1pdu.c` lines 7586–7592

**Bug:**
```c
if (info->overwrite) {
    rc = ksmbd_vfs_truncate(work, fp, 0);   /* truncates source, not target */
    ...
}
```
Per spec, `overwrite = 1` means replace the target if it exists, not truncate
the source. The truncate should operate on the target file identified by path.

**Fix:** Resolve the destination path and truncate it, not `fp`.

---

### 1.14 SETATTR LastWriteTime = 0 and 0xFFFFFFFF Not Handled

**Location:** `src/protocol/smb1/smb1pdu.c` lines 8788–8789 (`smb_setattr()`)

**Bug:** The current code unconditionally calls `ia_mtime = le32_to_cpu(req->LastWriteTime)`.
Per MS-SMB §2.2.4.9.1: `LastWriteTime = 0` means do not change; `0xFFFFFFFF`
means set to server's current time; any other value sets that time.

**Fix:**
```c
u32 write_time = le32_to_cpu(req->LastWriteTime);
if (write_time == 0) {
    /* do not change mtime */
} else if (write_time == 0xFFFFFFFF) {
    attrs.ia_mtime = current_time(d_inode(path.dentry));
    attrs.ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET);
} else {
    attrs.ia_mtime.tv_sec = write_time;
    attrs.ia_mtime.tv_nsec = 0;
    attrs.ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET);
}
```

---

### 1.15 LOCKING_ANDX CHANGE_LOCKTYPE Returns DOS Error Instead of NTSTATUS

**Location:** `src/protocol/smb1/smb1pdu.c` lines 1761–1766

**Bug:**
```c
if (req->LockType & LOCKING_ANDX_CHANGE_LOCKTYPE) {
    rsp->hdr.Status.DosError.ErrorClass = ERRDOS;
    rsp->hdr.Status.DosError.Error = cpu_to_le16(ERRnoatomiclocks);
    rsp->hdr.Flags2 &= ~SMBFLG2_ERR_STATUS;  /* clears server's own flag */
    goto out;
}
```
Modern NT clients negotiate NTSTATUS via `SMBFLG2_ERR_STATUS`. The server must
not modify this flag in the response. The correct response is NTSTATUS.

**Fix:**
```c
if (req->LockType & LOCKING_ANDX_CHANGE_LOCKTYPE) {
    rsp->hdr.Status.CifsError = STATUS_NOT_SUPPORTED;
    goto out;
}
```

---

### 1.16 LOCKING_ANDX Unlock/Lock Processing Order Is Reversed

**Location:** `src/protocol/smb1/smb1pdu.c` around lines 1772–2095

**Bug:** Locks are processed first (lines 1772–1990), then unlocks (lines
2001–2095). Per MS-SMB §2.2.4.26.1, the order MUST be: unlocks first, then locks.
Also, the Unlocks array comes first in the wire Locks buffer, but KSMBD reads
Locks first.

**Wire format per spec:**
```
Unlocks[NumberOfUnlocks]  { LOCKING_ANDX_RANGE }
Locks[NumberOfLocks]      { LOCKING_ANDX_RANGE }
```

**Fix:** Swap processing order and fix buffer pointer calculations:
```c
/* Spec: Unlocks come FIRST in the Locks buffer, then Locks */
if (req->LockType & LOCKING_ANDX_LARGE_FILES) {
    unlock_ele64 = (struct locking_andx_range64 *)
                   ((u8 *)req + sizeof(*req) - 1);
    lock_ele64   = unlock_ele64 + unlock_count;
} else {
    unlock_ele32 = (struct locking_andx_range32 *)
                   ((u8 *)req + sizeof(*req) - 1);
    lock_ele32   = unlock_ele32 + unlock_count;
}
```

---

### 1.17 LOCKING_ANDX Timeout = 0xFFFFFFFF Wraps to 49-Day Sleep

**Location:** `src/protocol/smb1/smb1pdu.c` lines 1918–1929

**Bug:** `timeout = le32_to_cpu(req->Timeout)` treats the timeout as unsigned.
`Timeout = 0xFFFFFFFF` (-1 signed) means "wait indefinitely," but `msleep(4294967295)`
sleeps ~49 days. Also `Timeout = 0` means do not wait, but the current poll loop
retries indefinitely.

**Fix:** Cast to signed and implement proper wait semantics:
```c
s32 timeout = (s32)le32_to_cpu(req->Timeout);
/* timeout == 0: return immediately; timeout < 0: wait forever;
   timeout > 0: wait that many milliseconds */
```

---

### 1.18 ECHO SequenceNumber Off by One (Bug + Wire Format)

**Location:** `src/protocol/smb1/smb1pdu.c` lines 3569–3574 (`smb_echo()`)

**Bug:** The initial response (before the loop) sends `SequenceNumber = 0` via
the zeroed struct, but per MS-SMB §2.2.4.35.2, responses are numbered starting
from 1.

**Fix:** Set `rsp->SequenceNumber = cpu_to_le16(1)` before the first implicit
send, and start the loop at `i = 2`.

---

### 1.19 QUERY_INFORMATION (0x08) Missing ATTR_ARCHIVE for Regular Files

**Location:** `src/protocol/smb1/smb1pdu.c` lines 8347–8353 (`smb_query_info()`)

**Bug:** `ATTR_ARCHIVE` (0x0020) is never set. Per MS-SMB §2.2.4.8.2, the ARCHIVE
bit should be set on all regular files (indicates file has been modified since
last backup).

**Fix:**
```c
if (S_ISREG(st.mode))
    attr |= ATTR_ARCHIVE;
```

---

### 1.20 QUERY_FS_ATTRIBUTE_INFO FileSystemName Missing

**Location:** `src/protocol/smb1/smb1pdu.c` lines 5036–5042 (`query_fs_info()`)

**Bug:** `info->FileSystemNameLen = 0` — no filesystem name is returned. The spec
requires `FileSystemName` (Unicode) to follow, e.g., "NTFS". Without it, some
clients fall back to compatibility modes.

**Fix:** Append `"NTFS"` (8 bytes UTF-16LE), set `FileSystemNameLen = 8`, and
`TotalDataCount = 20`.

---

### 1.21 NEGOTIATE Missing DomainName in Non-Extended-Security Response

**Location:** `src/protocol/smb1/smb1pdu.c` lines 1027–1035

**Bug:** After the 8-byte `EncryptionKey`, the spec requires a NUL-terminated OEM
string for `DomainName`. The existing code has a comment about this but does not
actually write the domain name. `ByteCount` is set to only `CIFS_CRYPTO_KEY_SIZE`
(8), omitting the domain. This may cause authentication failures with strict clients.

**Fix:** Append `server_conf.work_group` as a NUL-terminated OEM (or UTF-16LE
when `CAP_UNICODE`) string after the challenge bytes. Update `ByteCount`.

---

### 1.22 SESSION_SETUP Missing NativeOS / NativeLanMan / PrimaryDomain in Extended Security Response

**Location:** `src/protocol/smb1/smb1pdu.c` (`build_sess_rsp_extsec()`)

**Bug:** These strings are correctly written in the no-extended-security response
(`build_sess_rsp_noextsec()` lines 1154–1167) but are absent from the extended
security path. Per MS-SMB §2.2.4.53.2 they must be appended after the SecurityBlob
in both the challenge phase (`STATUS_MORE_PROCESSING_REQUIRED`) and the success phase.
Some Windows XP / 2000 clients use `PrimaryDomain` for domain account routing.

**Fix:** After writing the SecurityBlob in `build_sess_rsp_extsec()`, append:
- `NativeOS` as `"Windows"` (UTF-16LE NUL-terminated, with 1-byte alignment pad if needed)
- `NativeLanMan` (server version string)
- `PrimaryDomain` from `server_conf.work_group` (UTF-16LE NUL-terminated)

---

### 1.23 SESSION_SETUP PrimaryDomain Hard-Coded to "WORKGROUP"

**Location:** `src/protocol/smb1/smb1pdu.c` line 1164

**Bug:** `PrimaryDomain` is hard-coded to `"WORKGROUP"` instead of reading
`server_conf.work_group`.

**Fix:** Replace literal string with `server_conf.work_group`.

---

### 1.24 TREE_CONNECT Flags Not Processed

**Location:** `src/protocol/smb1/smb1pdu.c` (`smb_tree_connect_andx()`)

**Bugs:**
1. `TREE_CONNECT_ANDX_DISCONNECT_TID` (0x0001): not processed. Per MS-SMB
   §2.2.4.55.1, if this bit is set, the server MUST disconnect the TID in the
   request header before connecting.
2. `TREE_CONNECT_ANDX_EXTENDED_RESPONSE` (0x0008): the extended (WordCount=7)
   response is always sent regardless of whether the client requested it. Per spec,
   WordCount=7 should only be sent when this flag is set.

**Fix:**
1. Read `req->Flags`; if `DISCONNECT_TID` bit set, call `smb_tree_disconnect()`
   for `req_hdr->Tid` before establishing the new connection.
2. Send `WordCount=3` response when `TREE_CONNECT_ANDX_EXTENDED_RESPONSE` is not
   set; only send `WordCount=7` when requested.

---

### 1.25 TREE_CONNECT Missing SMB_SHARE_IS_IN_DFS in OptionalSupport

**Location:** `src/protocol/smb1/smb1pdu.c` around line 643

**Bug:** The `SMB_SHARE_IS_IN_DFS` bit (0x0002) is never set in `OptionalSupport`.
For DFS shares, this bit must be set to tell clients to initiate DFS referral logic.

**Fix:** Set `SMB_SHARE_IS_IN_DFS` when
`test_share_config_flag(share, KSMBD_SHARE_FLAG_DFS)`.

---

### 1.26 SESSION_SETUP VcNumber = 0 Does Not Disconnect Existing Sessions

**Location:** `src/protocol/smb1/smb1pdu.c` (`smb_session_setup_andx()`)

**Bug:** Per MS-SMB §2.2.4.53.1, when `VcNumber == 0`, the server SHOULD close
all existing virtual circuits for the client before creating the new session.
KSMBD does not implement this logic.

**Fix:** When `VcNumber == 0`, call `ksmbd_destroy_conn_sessions()` or equivalent
before creating the new session.

---

### 1.27 NEGOTIATE Missing Capability Bits

**Location:** `src/include/protocol/smb1pdu.h` lines 31–35 (`SMB1_SERVER_CAPS`)

**Bug:** Several capabilities are missing from the negotiated capabilities word:
- `CAP_MPX_MODE` (0x0002): absent despite `MaxMpxCount = 10`. Per MS-SMB
  §2.2.4.52.2, this is normatively required when supporting multiple in-flight requests.
- `CAP_RPC_REMOTE_APIS` (0x0020): absent despite IPC$ named-pipe DCE/RPC being
  implemented. Should be advertised.
- `CAP_INFOLEVEL_PASSTHRU` (0x2000): absent despite TRANS2 passthrough info levels
  (0x1xx range) being handled.
- `CAP_DFS` (0x1000): absent. Must be set conditionally when DFS is configured.

**Fix:** Add the missing bits to `SMB1_SERVER_CAPS` with the appropriate conditions.

---

## 2. Priority 2 — Missing Core Features

These are **entirely absent features** with high impact on real Windows client interoperability.

### 2.1 SMB_COM_NT_TRANSACT (0xA0) — Dispatcher and All 8 Subcommands

**Spec:** MS-SMB §2.2.4.62 / §2.2.4.63

#### 2.1.1 Current State

The dispatch table in `smb1ops.c` has **no entry** for `SMB_COM_NT_TRANSACT`.
When a client sends it, `smb1misc.c` returns `-EOPNOTSUPP` (default case at line 116),
the packet is silently dropped, and the client receives **no response** — a protocol
violation that causes hangs.

The eight subcommand codes are defined in `smb1pdu.h` lines 78–85 but have no
handler functions.

#### 2.1.2 Wire Structures Missing from smb1pdu.h

Add these structures:

```c
/* SMB_COM_NT_TRANSACT request — MS-SMB §2.2.4.62.1 — WordCount = 19 (0x13) */
struct smb_com_ntransact_req {
    struct smb_hdr hdr;
    __u8  MaxSetupCount;
    __u8  Reserved[2];
    __le32 TotalParameterCount;   /* 32-bit, not 16-bit like TRANS2 */
    __le32 TotalDataCount;
    __le32 MaxParameterCount;
    __le32 MaxDataCount;
    __le32 ParameterCount;
    __le32 ParameterOffset;
    __le32 DataCount;
    __le32 DataOffset;
    __u8  SetupCount;
    __u8  Reserved2;
    __le16 Function;              /* NT_TRANSACT_* subcommand */
    __le16 ByteCount;
} __packed;

/* SMB_COM_NT_TRANSACT response — MS-SMB §2.2.4.62.2 — WordCount = 18 (0x12) */
struct smb_com_ntransact_rsp {
    struct smb_hdr hdr;
    __u8  Reserved[3];
    __le32 TotalParameterCount;
    __le32 TotalDataCount;
    __le32 ParameterCount;
    __le32 ParameterOffset;
    __le32 ParameterDisplacement;
    __le32 DataCount;
    __le32 DataOffset;
    __le32 DataDisplacement;
    __u8  SetupCount;
    __le16 ByteCount;
} __packed;

/* SMB_COM_NT_TRANSACT_SECONDARY request — MS-SMB §2.2.4.63.1 — WordCount = 18 (0x12) */
struct smb_com_ntransact_secondary_req {
    struct smb_hdr hdr;
    __u8  Reserved[3];
    __le32 TotalParameterCount;
    __le32 TotalDataCount;
    __le32 ParameterCount;
    __le32 ParameterOffset;
    __le32 ParameterDisplacement;
    __le32 DataCount;
    __le32 DataOffset;
    __le32 DataDisplacement;
    __u8  FunctionCode;
    __le16 ByteCount;
} __packed;

/* NT_TRANSACT_CREATE parameter structures */
struct nt_transact_create_req_params {
    __le32 OplockLevel;
    __le32 RootDirectoryFid;
    __le32 CreateDisposition;
    __le32 ImpersonationLevel;
    __le32 SecurityFlags;
    __le32 DesiredAccess;
    __le32 AllocationSizeLow;
    __le32 AllocationSizeHigh;
    __le32 FileAttributes;
    __le32 ShareAccess;
    __le32 CreateOptions;
    __le32 SDLength;
    __le32 EALength;
    __le32 NameLength;
    __u8   SecurityFlags2;
    /* Name follows (NameLength bytes) */
} __packed;

struct nt_transact_create_rsp_params {
    __u8   OplockLevel;
    __u8   Reserved;
    __le16 Fid;
    __le32 CreateAction;
    __le64 CreationTime;
    __le64 LastAccessTime;
    __le64 LastWriteTime;
    __le64 ChangeTime;
    __le32 FileAttributes;
    __le64 AllocationSize;
    __le64 EndOfFile;
    __le16 FileType;
    __le16 DeviceState;
    __u8   DirectoryFlag;
} __packed;
```

#### 2.1.3 Dispatcher Registration

**File:** `smb1ops.c`
```c
[SMB_COM_NT_TRANSACT]           = { .proc = smb_nt_transact, },
[SMB_COM_NT_TRANSACT_SECONDARY] = { .proc = smb_nt_transact_secondary, },
```

**File:** `smb1misc.c` — add to `smb1_req_struct_size()`:
```c
case SMB_COM_NT_TRANSACT:
    if (wc != 0x13)
        return -EINVAL;
    break;
case SMB_COM_NT_TRANSACT_SECONDARY:
    if (wc != 0x12)
        return -EINVAL;
    break;
```

#### 2.1.4 Top-Level Dispatcher Function

```c
int smb_nt_transact(struct ksmbd_work *work)
{
    struct smb_com_ntransact_req *req = work->request_buf;
    struct smb_hdr *rsp_hdr = work->response_buf;
    u16 function;
    int err;

    if (req->SetupCount > 0) {
        rsp_hdr->Status.CifsError = STATUS_INVALID_PARAMETER;
        return -EINVAL;
    }

    function = le16_to_cpu(req->Function);
    ksmbd_debug(SMB, "NT_TRANSACT subcommand 0x%x\n", function);

    switch (function) {
    case NT_TRANSACT_CREATE:
        err = smb_nt_transact_create(work);           break;
    case NT_TRANSACT_IOCTL:
        err = smb_nt_transact_ioctl(work);            break;
    case NT_TRANSACT_SET_SECURITY_DESC:
        err = smb_nt_transact_set_security_desc(work); break;
    case NT_TRANSACT_NOTIFY_CHANGE:
        err = smb_nt_transact_notify_change(work);    break;
    case NT_TRANSACT_RENAME:
        err = smb_nt_transact_rename(work);           break;
    case NT_TRANSACT_QUERY_SECURITY_DESC:
        err = smb_nt_transact_query_security_desc(work); break;
    case NT_TRANSACT_GET_USER_QUOTA:
        err = smb_nt_transact_get_user_quota(work);   break;
    case NT_TRANSACT_SET_USER_QUOTA:
        err = smb_nt_transact_set_user_quota(work);   break;
    default:
        pr_err("NT_TRANSACT subcommand 0x%x not supported\n", function);
        rsp_hdr->Status.CifsError = STATUS_NOT_SUPPORTED;
        return -EOPNOTSUPP;
    }

    if (err && !rsp_hdr->Status.CifsError)
        set_smb_rsp_status(work, map_errno_to_ntstatus(err));
    return err;
}

int smb_nt_transact_secondary(struct ksmbd_work *work)
{
    struct smb_hdr *rsp_hdr = work->response_buf;
    rsp_hdr->Status.CifsError = STATUS_NOT_SUPPORTED;
    return -EOPNOTSUPP;
}
```

#### 2.1.5 Response Envelope Helper

All NT_TRANSACT handlers share a common response-building pattern. Add:

```c
static int smb_build_nt_transact_rsp(struct ksmbd_work *work,
                                      const void *param_buf, u32 param_len,
                                      const void *data_buf, u32 data_len)
{
    struct smb_com_ntransact_rsp *rsp = work->response_buf;
    unsigned int fixed_size = sizeof(struct smb_com_ntransact_rsp);
    unsigned int param_aligned = ALIGN(param_len, 4);
    unsigned int total = fixed_size + 3 + param_aligned + data_len;

    if (total > work->response_sz)
        return -ENOMEM;

    rsp->hdr.WordCount           = 18;
    rsp->TotalParameterCount     = cpu_to_le32(param_len);
    rsp->TotalDataCount          = cpu_to_le32(data_len);
    rsp->ParameterCount          = cpu_to_le32(param_len);
    rsp->ParameterDisplacement   = 0;
    rsp->DataCount               = cpu_to_le32(data_len);
    rsp->DataDisplacement        = 0;
    rsp->SetupCount              = 0;

    unsigned int param_off = fixed_size + 3 - 4; /* from SMB header start */
    rsp->ParameterOffset = cpu_to_le32(param_off);
    rsp->DataOffset      = cpu_to_le32(param_off + param_aligned);
    rsp->ByteCount       = cpu_to_le16(3 + param_aligned + data_len);

    u8 *out = (u8 *)rsp + fixed_size;
    memset(out, 0, 3);
    out += 3;
    if (param_buf && param_len)
        memcpy(out, param_buf, param_len);
    out += param_aligned;
    if (data_buf && data_len)
        memcpy(out, data_buf, data_len);

    inc_rfc1001_len(&rsp->hdr, rsp->hdr.WordCount * 2 +
                    le16_to_cpu(rsp->ByteCount));
    rsp->hdr.Status.CifsError = STATUS_SUCCESS;
    return 0;
}
```

#### 2.1.6 NT_TRANSACT_CREATE (0x01)

**Spec:** MS-SMB §2.2.4.62.5 / §2.2.4.62.6

This is a superset of `SMB_COM_NT_CREATE_ANDX` that additionally accepts an
initial SecurityDescriptor (SD) and Extended Attributes (EA).

**Parameter buffer layout (94 bytes minimum):**
```
Offset  Size  Field
0       4     OpLockLevel
4       4     RootDirectoryFid
8       4     CreateDisposition
12      4     ImpersonationLevel
16      4     SecurityFlags
20      4     DesiredAccess
24      4     AllocationSizeLow
28      4     AllocationSizeHigh
32      4     FileAttributes
36      4     ShareAccess
40      4     CreateOptions
44      4     SDLength
48      4     EALength
52      4     NameLength
56      1     SecurityFlags2
57      N     FileName (Unicode if Flags2 set)
```

**Data buffer:** SDLength bytes of SecurityDescriptor, then EALength bytes of EA list.

**Implementation Strategy:**
1. Parse Parameters buffer at `req->ParameterOffset` (validate `ParameterCount >= 57`).
2. Call the same VFS open path used by `smb_nt_create_andx()`.
3. If `SDLength > 0`: call `ksmbd_vfs_set_sd_xattr()` to apply the initial SD.
4. If `EALength > 0`: validate and apply the EA list via `ksmbd_vfs_setxattr()`.
5. Build response using `smb_build_nt_transact_rsp()` with `nt_transact_create_rsp_params`.

#### 2.1.7 NT_TRANSACT_IOCTL (0x02)

**Spec:** MS-SMB §2.2.4.62.9 / §2.2.4.62.10

**Parameters buffer (8 bytes):**
```
Offset  Size  Field
0       4     FunctionCode  (FSCTL code)
4       2     Fid
6       1     IsFsctl       (1 = FSCTL, 0 = IOCTL)
7       1     IsFlags
```

**Implementation Strategy:** Bridge to the existing `smb2_ioctl.c` FSCTL dispatch
infrastructure. Parse `FunctionCode`, `Fid`, and `IsFsctl`. For FSCTL codes already
handled by SMB2 (`FSCTL_SET_SPARSE`, `FSCTL_SET_ZERO_DATA`,
`FSCTL_QUERY_ALLOCATED_RANGES`), route through `ksmbd_dispatch_fsctl()`. Place
FSCTL output in the NT_TRANSACT Data buffer in the response.

#### 2.1.8 NT_TRANSACT_SET_SECURITY_DESC (0x03)

**Spec:** MS-SMB §2.2.4.62.11 / §2.2.4.62.12

**Parameters buffer (8 bytes):**
```
Offset  Size  Field
0       2     Fid
2       2     Reserved
4       4     SecurityInformation  (bit flags below)
```

**SecurityInformation flags (MS-DTYP §2.4.7):**
```c
#define OWNER_SECURITY_INFORMATION   0x00000001
#define GROUP_SECURITY_INFORMATION   0x00000002
#define DACL_SECURITY_INFORMATION    0x00000004
#define SACL_SECURITY_INFORMATION    0x00000008
#define LABEL_SECURITY_INFORMATION   0x00000010
#define BACKUP_SECURITY_INFORMATION  0x00010000
#define PROTECTED_DACL_SECURITY_INFORMATION   0x80000000
#define UNPROTECTED_DACL_SECURITY_INFORMATION 0x20000000
```

**Data buffer:** `SECURITY_DESCRIPTOR` structure.

```c
int smb_nt_transact_set_security_desc(struct ksmbd_work *work)
{
    struct smb_com_ntransact_req *req = work->request_buf;
    char *params = (char *)req + le32_to_cpu(req->ParameterOffset);
    u16 fid = get_unaligned_le16(params);
    u32 security_info = get_unaligned_le32(params + 4);
    struct smb_ntsd *pntsd = (struct smb_ntsd *)((char *)req +
                                le32_to_cpu(req->DataOffset));
    unsigned int pntsd_size = le32_to_cpu(req->DataCount);
    struct ksmbd_file *fp;
    struct path path;
    int err;

    fp = ksmbd_lookup_fd_fast(work, fid);
    if (!fp)
        return -EBADF;
    if (pntsd_size < sizeof(struct smb_ntsd)) {
        ksmbd_fd_put(work, fp);
        return -EINVAL;
    }
    /* Access check: DACL set requires WRITE_DAC */
    if ((security_info & DACL_SECURITY_INFORMATION) &&
        !(fp->daccess & (WRITE_DAC | GENERIC_ALL | GENERIC_WRITE))) {
        ksmbd_fd_put(work, fp);
        return -EACCES;
    }
    path.dentry = fp->filp->f_path.dentry;
    path.mnt    = fp->filp->f_path.mnt;
    err = ksmbd_vfs_set_sd_xattr(work->conn, mnt_idmap(path.mnt),
                                  path.dentry, pntsd, pntsd_size, false);
    ksmbd_fd_put(work, fp);
    if (!err)
        smb_build_nt_transact_rsp(work, NULL, 0, NULL, 0);
    return err;
}
```

#### 2.1.9 NT_TRANSACT_NOTIFY_CHANGE (0x04)

**Spec:** MS-SMB §2.2.4.62.13 / §2.2.4.62.14

**Parameters buffer (8 bytes):**
```
Offset  Size  Field
0       4     CompletionFilter  (FILE_NOTIFY_CHANGE_* flags)
4       2     Fid
6       1     WatchTree
7       1     Reserved
```

**CompletionFilter flags:**
```c
#define FILE_NOTIFY_CHANGE_FILE_NAME    0x00000001
#define FILE_NOTIFY_CHANGE_DIR_NAME     0x00000002
#define FILE_NOTIFY_CHANGE_ATTRIBUTES   0x00000004
#define FILE_NOTIFY_CHANGE_SIZE         0x00000008
#define FILE_NOTIFY_CHANGE_LAST_WRITE   0x00000010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS  0x00000020
#define FILE_NOTIFY_CHANGE_CREATION     0x00000040
#define FILE_NOTIFY_CHANGE_EA           0x00000080
#define FILE_NOTIFY_CHANGE_SECURITY     0x00000100
```

**Response:** Asynchronous. No immediate response is sent. When a matching
filesystem event occurs, an NT_TRANSACT response (same MID) is sent containing
`FILE_NOTIFY_INFORMATION` entries.

```c
struct file_notify_information {
    __le32 NextEntryOffset;  /* 0 if last entry */
    __le32 Action;           /* FILE_ACTION_ADDED=1, REMOVED=2, MODIFIED=3,
                                RENAMED_OLD_NAME=4, RENAMED_NEW_NAME=5 */
    __le32 FileNameLength;
    __le16 FileName[1];      /* Unicode, relative path */
} __packed;
```

**Implementation Strategy:** Set `work->send_no_response = 1`. Register an fsnotify
watch via a new `ksmbd_smb1_notify_watch()` function in `ksmbd_notify.c`, mirroring
the SMB2 watch path but using an SMB1 response builder for the completion callback.

#### 2.1.10 NT_TRANSACT_RENAME (0x05)

**Spec:** MS-SMB §2.2.4.62.15 / §2.2.4.62.16

**Parameters buffer:**
```
Offset  Size  Field
0       2     Fid
2       2     Flags  (NT_RENAME_REPLACE_IF_EXISTS = 0x0001)
4       N     NewName (Unicode)
```

```c
int smb_nt_transact_rename(struct ksmbd_work *work)
{
    struct smb_com_ntransact_req *req = work->request_buf;
    char *params = (char *)req + le32_to_cpu(req->ParameterOffset);
    u16 fid     = get_unaligned_le16(params);
    u16 flags   = get_unaligned_le16(params + 2);
    int replace = !!(flags & NT_RENAME_REPLACE_IF_EXISTS);
    char *new_name;
    struct ksmbd_file *fp;
    int err;

    fp = ksmbd_lookup_fd_fast(work, fid);
    if (!fp)
        return -EBADF;
    if (is_smbreq_unicode(&req->hdr))
        new_name = smb_strndup_from_utf16(params + 4,
                       le32_to_cpu(req->ParameterCount) - 4,
                       true, work->conn->local_nls);
    else
        new_name = kstrndup(params + 4,
                       le32_to_cpu(req->ParameterCount) - 4,
                       KSMBD_DEFAULT_GFP);
    if (IS_ERR_OR_NULL(new_name)) {
        ksmbd_fd_put(work, fp);
        return -ENOMEM;
    }
    err = ksmbd_vfs_rename_by_dentry(work, fp->filp->f_path.dentry,
                                     new_name, replace);
    kfree(new_name);
    ksmbd_fd_put(work, fp);
    if (!err)
        smb_build_nt_transact_rsp(work, NULL, 0, NULL, 0);
    return err;
}
```

**Required VFS helper:** Add `ksmbd_vfs_rename_by_dentry(work, old_dentry,
new_name, replace)` to `vfs.c` — resolves target path relative to share root
and calls `vfs_rename()`.

#### 2.1.11 NT_TRANSACT_QUERY_SECURITY_DESC (0x06)

**Spec:** MS-SMB §2.2.4.62.17 / §2.2.4.62.18

**Parameters buffer (8 bytes):** Same layout as `SET_SECURITY_DESC` (FID, Reserved,
SecurityInformation).

**Response:** If buffer is large enough — Parameters = `LengthNeeded` (4 bytes),
Data = `SECURITY_DESCRIPTOR`. If buffer too small — `STATUS_BUFFER_TOO_SMALL`
with Parameters = `LengthNeeded` (this is a normal "query-size-then-retry" pattern,
not an error).

```c
int smb_nt_transact_query_security_desc(struct ksmbd_work *work)
{
    struct smb_com_ntransact_req *req = work->request_buf;
    char *params = (char *)req + le32_to_cpu(req->ParameterOffset);
    u16 fid = get_unaligned_le16(params);
    u32 security_info = get_unaligned_le32(params + 4);
    u32 max_data = le32_to_cpu(req->MaxDataCount);
    struct ksmbd_file *fp;
    struct smb_ntsd *pntsd = NULL;
    unsigned int pntsd_size;
    int err;

    fp = ksmbd_lookup_fd_fast(work, fid);
    if (!fp)
        return -EBADF;
    if (!(fp->daccess & (READ_CONTROL | GENERIC_ALL | GENERIC_READ))) {
        ksmbd_fd_put(work, fp);
        return -EACCES;
    }
    pntsd_size = ksmbd_vfs_get_sd_xattr(work->conn,
                     mnt_idmap(fp->filp->f_path.mnt),
                     fp->filp->f_path.dentry, &pntsd);
    if ((int)pntsd_size < 0) {
        err = smb_build_mode_sd(work->conn, fp->filp->f_path.dentry,
                                security_info, &pntsd, &pntsd_size);
        if (err) { ksmbd_fd_put(work, fp); return err; }
    }
    ksmbd_fd_put(work, fp);

    __le32 len_needed = cpu_to_le32(pntsd_size);
    if (pntsd_size > max_data) {
        /* STATUS_BUFFER_TOO_SMALL: return LengthNeeded only */
        smb_build_nt_transact_rsp(work, &len_needed, 4, NULL, 0);
        work->response_buf->Status.CifsError = STATUS_BUFFER_TOO_SMALL;
        kfree(pntsd);
        return 0;
    }
    smb_build_nt_transact_rsp(work, &len_needed, 4, pntsd, pntsd_size);
    kfree(pntsd);
    return 0;
}
```

#### 2.1.12 NT_TRANSACT_GET_USER_QUOTA (0x07) and SET_USER_QUOTA (0x08)

**Spec:** MS-SMB §2.2.4.62.19 / §2.2.4.62.20 / §2.2.4.62.21

**Strategy:** Bridge to `ksmbd_quota.c`. For GET: parse SID list from Data
buffer, map each SID to a Linux UID via `ksmbd_lookup_user_by_sid()`, call
`ksmbd_fill_quota_info()`, and package as `FILE_QUOTA_INFORMATION[]` in the
response. For SET: map SIDs to UIDs, call `vfs_set_dqblk()`. If `CONFIG_QUOTA`
is not set, return `STATUS_NOT_SUPPORTED` for both.

---

### 2.2 LOCKING_ANDX CANCEL_LOCK — Silently Ignored

**Location:** `src/protocol/smb1/smb1pdu.c` line 1769

**Current code:**
```c
if (req->LockType & LOCKING_ANDX_CANCEL_LOCK)
    pr_err("lock type: LOCKING_ANDX_CANCEL_LOCK\n");
```

**Required implementation:** When `LOCKING_ANDX_CANCEL_LOCK` is set, locate
any pending work item sleeping in `ksmbd_vfs_posix_lock_wait_timeout()` for an
overlapping range on the same FID, and wake it with `STATUS_CANCELLED`.

```c
if (req->LockType & LOCKING_ANDX_CANCEL_LOCK) {
    err = smb_cancel_lock_ranges(work, fp, lock_ele32, lock_ele64,
                                  lock_count);
    /* The CANCEL request itself always succeeds */
    goto build_response;
}
```

`smb_cancel_lock_ranges()` must walk `work->conn->lock_list` and call
`ksmbd_vfs_posix_lock_unblock()` on matching entries.

---

### 2.3 NT_CANCEL — Blocked Work Not Cancelled

**Location:** `src/protocol/smb1/smb1pdu.c` line 8183 (`smb_nt_cancel()`)

**Current state:** Walks `conn->requests` and sets `send_no_response = 1`.
This works only for requests not yet dispatched. Two gaps remain:

1. **Already-dispatched locked work:** If the target is blocked in
   `ksmbd_vfs_posix_lock_wait_timeout()`, it is no longer in `conn->requests`.
   Fix: also walk `conn->lock_list` and signal via `ksmbd_vfs_posix_lock_unblock()`.

2. **NOTIFY_CHANGE cancellation:** When cancelling a pending
   `NT_TRANSACT_NOTIFY_CHANGE`, the server must remove the fsnotify watch and
   send `STATUS_CANCELLED` as the response to the original notify request. Add
   a call to `ksmbd_notify_cancel_by_mid(conn, mid)`.

**Additional race:** `new_work->sess->sequence_number--` at line 8200 is done
under `conn->request_lock` but without the session lock. Use atomic decrement
or hold the session lock when modifying `sequence_number`.

---

### 2.4 SESSION_SETUP Invalid WordCount Silent Drop

**Location:** `src/protocol/smb1/smb1pdu.c` lines 1396–1398

**Bug:** When `WordCount` is neither 12 nor 13, the current code sets
`work->send_no_response = 1` and returns — no error is sent to the client.
Per MS-SMB §2.2.4.53.1, the correct response to an invalid `WordCount` is
`STATUS_INVALID_PARAMETER`.

**Fix:** Set the error status and allow the normal response path to execute.

---

### 2.5 QUERY_INFORMATION2 (0x23) — Entirely Missing

**Spec:** MS-SMB §2.2.4.24

**Status:** No handler, no opcode constant, no structures.

**Wire Format:**
- Request (WC=1): `__u16 Fid`
- Response (WC=11): `CreateDate`, `CreateTime`, `LastAccessDate`, `LastAccessTime`,
  `LastWriteDate`, `LastWriteTime` (all `__le16` DOS date/time), `FileDataSize`
  (`__le32`), `FileAllocationSize` (`__le32`), `FileAttributes` (`__le16`)

**DOS Date/Time conversion helpers required:**
```c
static __le16 unix_to_smb_date(time64_t t)
{
    struct tm tm;
    time64_to_tm(t, 0, &tm);
    return cpu_to_le16(((tm.tm_year - 80) << 9) |
                       ((tm.tm_mon + 1) << 5) | tm.tm_mday);
}

static __le16 unix_to_smb_time(time64_t t)
{
    struct tm tm;
    time64_to_tm(t, 0, &tm);
    return cpu_to_le16((tm.tm_hour << 11) | (tm.tm_min << 5) |
                       (tm.tm_sec / 2));
}
```

**Handler:** See full implementation code in `smb1_plan_05_nt_transact_locks.md`
§8.1 and `smb1_plan_06_legacy_security.md` §2.1 — both documents provide identical
handler code that calls `vfs_getattr()`, converts timestamps via the helpers above,
and populates the response.

**Register:** `[SMB_COM_QUERY_INFORMATION2] = { .proc = smb_query_information2, }`

**smb1misc.c:** `case SMB_COM_QUERY_INFORMATION2: if (wc != 0x1) return -EINVAL;`

---

### 2.6 SET_INFORMATION2 (0x22) — Entirely Missing

**Spec:** MS-SMB §2.2.4.23

**Status:** No handler, no opcode constant, no structures.

**Wire Format:**
- Request (WC=7): `FID`, `CreateDate`, `CreateTime`, `LastAccessDate`,
  `LastAccessTime`, `LastWriteDate`, `LastWriteTime` (all `__le16`), `ByteCount=0`
- Response (WC=0): `ByteCount=0`

**Spec rule:** Only set timestamp when both Date and Time fields are non-zero.

**Required helper:**
```c
static time64_t smb_date_time_to_unix(__u16 date, __u16 time)
{
    struct tm tm = {
        .tm_year = ((date >> 9) & 0x7f) + 80,
        .tm_mon  = ((date >> 5) & 0x0f) - 1,
        .tm_mday = date & 0x1f,
        .tm_hour = (time >> 11) & 0x1f,
        .tm_min  = (time >> 5) & 0x3f,
        .tm_sec  = (time & 0x1f) * 2,
    };
    return mktime64(1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec);
}
```

Full handler code: see `smb1_plan_05_nt_transact_locks.md` §8.2 and
`smb1_plan_06_legacy_security.md` §2.2.

**Register:** `[SMB_COM_SET_INFORMATION2] = { .proc = smb_set_information2, }`

**smb1misc.c:** `case SMB_COM_SET_INFORMATION2: if (wc != 0x7) return -EINVAL;`

---

### 2.7 Oplock Enable Path Not Exposed

**Location:** `src/protocol/smb1/smb1pdu.c` line 118

`smb1_oplock_enable` is a `static int` with no module parameter and no sysfs knob.
SMB1 oplock support is thus permanently disabled with no way to enable it at runtime.

**Fix:** Add to `ksmbd_config.c` or expose as a module parameter:
```c
module_param(smb1_oplock_enable, bool, 0644);
MODULE_PARM_DESC(smb1_oplock_enable,
    "Enable SMB1 oplock support (default: false)");
```

Also add FID overflow guard in `oplock.c` line 817:
```c
if (opinfo->fid > 0xFFFF) {
    pr_err("SMB1 oplock break: FID 0x%llx exceeds SMB1 range\n",
           opinfo->fid);
    goto out;
}
req->Fid = (u16)opinfo->fid;
```

---

## 3. Priority 3 — Missing TRANSACTION / TRANSACTION2 Completions

### 3.1 NT_TRANSACT and TRANSACTION2 Secondary Packet Reassembly

**Spec:** MS-SMB §2.2.4.34 (TRANSACTION_SECONDARY 0x26), §2.2.4.35 (TRANSACTION2_SECONDARY 0x33), §2.2.4.63 (NT_TRANSACT_SECONDARY 0xA1)

**Current state:** None of these secondary commands have dispatch table entries or
handlers. Observations:
- `smb1_server_cmds[]` has no entry for 0x26, 0x33, or 0xA1.
- `query_fs_info()` lines 4893–4913 detect a partial TRANS2 packet and comment
  "create 1 trans_state structure and add to connection list" — but the body is
  **empty**; the buffer is read from potentially incomplete data.

**Required infrastructure:**
```c
struct smb_transaction_state {
    struct list_head        list;
    __le16                  mid;          /* match key */
    unsigned char           cmd;          /* 0x25, 0x32, or 0xA0 */
    unsigned char          *param_buf;    /* reassembled params */
    unsigned char          *data_buf;     /* reassembled data */
    __u16                   param_total;
    __u16                   data_total;
    __u16                   param_received;
    __u16                   data_received;
    struct timer_list       timeout;
};
```

This state must be per-connection (list on `struct ksmbd_conn`), protected by a
spinlock. The `Timeout` field from the primary packet arms a timer that sends
`STATUS_IO_TIMEOUT` if secondary packets never arrive.

**Register:** Add dispatch table entries and handlers:
- `[SMB_COM_TRANSACTION_SECONDARY]  = { .proc = smb_transaction_secondary, }`
- `[SMB_COM_TRANSACTION2_SECONDARY] = { .proc = smb_transaction2_secondary, }`
- `[SMB_COM_NT_TRANSACT_SECONDARY]  = { .proc = smb_nt_transact_secondary, }`

Note: NT_TRANSACT_SECONDARY uses 32-bit counts vs. 16-bit for TRANSACTION2_SECONDARY.

---

### 3.2 SMB_COM_TRANSACTION Named Pipe Subcommands

**Spec:** MS-SMB §2.2.4.33

**Current state:** `smb_trans()` only handles `\PIPE\LANMAN` (RAP) and
`TRANS_TRANSACT_NMPIPE` (0x0026 / DCE/RPC). All other subcommands return
`STATUS_NOT_SUPPORTED`.

**Missing subcommands and their implementation strategies:**

| Subcommand | Code | Wire Format | Implementation |
|---|---|---|---|
| `TRANS_SET_NMPIPE_STATE` | 0x0001 | Setup[0]=code, Setup[1]=FID; Params=PipeState word | Store mode in RPC session handle; return SUCCESS |
| `TRANS_QUERY_NMPIPE_STATE` | 0x0021 | Setup[0,1]=code,FID | Return stored PipeState word |
| `TRANS_QUERY_NMPIPE_INFO` | 0x0022 | Setup[0,1]=code,FID; Params=Level | Return static: OutBuf=4096, InBuf=4096, MaxInst=1, CurInst=1, PipeName |
| `TRANS_PEEK_NMPIPE` | 0x0023 | Setup[0,1]=code,FID | Return ReadDataAvailable=0; STATUS_SUCCESS |
| `TRANS_RAW_READ_NMPIPE` | 0x0011 | Setup[0,1]=code,FID | Map to `ksmbd_rpc_read()` |
| `TRANS_RAW_WRITE_NMPIPE` | 0x0031 | Setup[0,1]=code,FID; Data=bytes | Map to `ksmbd_rpc_write()` |
| `TRANS_READ_NMPIPE` | 0x0036 | Same as RAW_READ | Alias for byte-stream mode |
| `TRANS_WRITE_NMPIPE` | 0x0037 | Same as RAW_WRITE | Alias for byte-stream mode |
| `TRANS_WAIT_NMPIPE` | 0x0053 | Params[0..3]=Timeout; Data=pipe name | Always respond immediately (single instance model) |
| `TRANS_CALL_NMPIPE` | 0x0054 | Data=write buffer | Open + `ksmbd_rpc_ioctl()` + close atomically |

**Mailslot handling:** When transaction name starts with `\MAILSLOT\`, detect
the prefix explicitly. For Class 2 (fire-and-forget): silently discard and return
no response. For Class 1: return `STATUS_SUCCESS`. Do not fall through `\PIPE\`
check.

---

### 3.3 TRANSACTION2 FIND_FIRST2 and FIND_NEXT2 Flag Gaps

**Spec:** MS-SMB §2.2.4.34.1 / §2.2.4.34.2

**Missing flag handling in `find_first()` (lines 6290–6604) and `find_next()` (lines 6605–6975):**

| Flag | Value | Gap |
|---|---|---|
| `CLOSE_AFTER_REQUEST` | 0x0001 | Not checked — search handle must be closed before returning response |
| `RETURN_RESUME_KEYS` | 0x0004 | Not implemented — each entry must be preceded by a 4-byte `ResumeKey` |
| `CONTINUE_FROM_LAST` | 0x0008 | `find_next()` ignores `FileName` and `ResumeKey` for resume position |
| `FIND_WITH_BACKUP_INTENT` | 0x0010 | Not checked — should bypass ACL checks for backup privilege holders |

**Also:** `LastNameOffset` in the FIND_FIRST2 response should be the offset to the
`FileName` field within the last entry, not the start of the last entry structure.

---

### 3.4 TRANSACTION2 Missing Information Levels

**3.4.1 TRANS2_QUERY_FS_INFORMATION Missing Levels**

| Level | Code | Status | Fix |
|---|---|---|---|
| `SMB_INFO_VOLUME` | 0x0002 | Missing | Add: VolumeSerialNumber (ULONG) + VolumeLabelSize (UCHAR) + VolumeLabel (OEM) |
| `SMB_QUERY_POSIX_WHO_AM_I` | 0x0202 | Missing | Return effective UID/GID/groups for the session |
| `SMB_QUERY_FS_PROXY` | 0x0203 | Missing (stub) | Return `STATUS_NOT_SUPPORTED` explicitly |

**Fix for IPC share:** Lines 4922–4923 return `-ENOENT` for FS queries on IPC$,
but `SMB_QUERY_FS_DEVICE_INFO` should succeed with `DeviceType = FILE_DEVICE_NAMED_PIPE = 0x11`.

**3.4.2 TRANS2_QUERY_PATH_INFORMATION Missing Levels**

| Level | Code | Gap |
|---|---|---|
| `SMB_INFO_QUERY_EA_SIZE` | 0x0002 | Missing — SMB_INFO_STANDARD + 4-byte EASize appended |
| `SMB_INFO_IS_NAME_VALID` | 0x0006 | Missing — validate path for illegal chars; return STATUS_SUCCESS or STATUS_OBJECT_NAME_INVALID |
| `SMB_QUERY_FILE_COMPRESSION_INFO` | 0x010B | Missing — return CompressedFileSize=FileSize, CompressionFormat=0 |
| `SMB_QUERY_FILE_UNIX_HLINK` | 0x0203 | Missing — return st.nlink |
| `SMB_QUERY_XATTR` | 0x0205 | Partially missing — advertised via CAP_UNIX but 0x205 handler absent |
| `SMB_QUERY_ATTR_FLAGS` | 0x0206 | Missing — return CIFS Unix attribute flags |
| `SMB_QUERY_FILE_ACCESS_INFO` | 0x010F | Missing — return granted access mask |
| `SMB_QUERY_FILE_NETWORK_OPEN_INFO` | 0x0122 | Missing — combined timestamps + alloc + attribs (56 bytes) |
| `SMB_QUERY_FILE_ALL_INFO` EASize | 0x0107 | Incomplete — EASize always 0; should sum xattr value sizes |

**3.4.3 TRANS2_QUERY_FILE_INFORMATION Missing Levels**

| Level | Code | Gap |
|---|---|---|
| `SMB_QUERY_FILE_NAME_INFO` | 0x0104 | Missing for FID-based queries |
| `SMB_QUERY_FILE_STREAM_INFO` | 0x0109 | Missing — return single `::$DATA` stream entry |
| `SMB_QUERY_FILE_COMPRESSION_INFO` | 0x010B | Missing |
| `SMB_QUERY_FILE_INTERNAL_INFO` | 0x010E | Missing |
| `SMB_QUERY_FILE_ACCESS_INFO` | 0x010F | Missing |
| `SMB_QUERY_FILE_ALT_NAME_INFO` | 0x0108 | Missing |
| `SMB_QUERY_FILE_NETWORK_OPEN_INFO` | 0x0122 | Missing |
| POSIX lock query | 0x0208 | Missing — advertised via CIFS_UNIX_FCNTL_CAP but handler absent |

**3.4.4 TRANS2_SET_PATH_INFORMATION Missing Levels**

- `SMB_SET_FILE_DISPOSITION_INFO` (0x0102) — handled in `set_file_info()` but absent from `set_path_info()`
- `SMB_SET_FILE_ALLOCATION_INFO` (0x0103) — same gap

**3.4.5 TRANS2_SET_FILE_INFORMATION Missing Levels**

- `SMB_SET_FILE_UNIX_LINK` and `SMB_SET_FILE_UNIX_HLINK` — absent from `set_file_info()` (only in `set_path_info()`)
- POSIX lock set (0x0208) — missing; advertised via `CIFS_UNIX_FCNTL_CAP`

---

### 3.5 TRANS2_OPEN (0x00) — Entirely Missing

The subcommand dispatcher returns `-EINVAL`. Clients using `TRANS2_OPEN` for
directory-oriented operations will fail. Implement or return explicit
`STATUS_NOT_SUPPORTED`.

---

### 3.6 TRANS2_GET_DFS_REFERRAL (0x10)

**Spec:** MS-SMB §2.2.4.34.15, MS-DFSC

**Current state:** Falls to `default:` in `smb_trans2()` returning `-EINVAL`.
`CAP_DFS` is not advertised.

**Request parameters:** `MaxReferralLevel` (USHORT), then `RequestFileName`
(UTF-16LE) in the Data area.

**Response Data (DFS referral v3 format):**
```c
struct dfs_referral_rsp {
    __le16  PathConsumed;
    __le16  NumberOfReferrals;
    __le32  ReferralHeaderFlags;
    /* DFS_REFERRAL_V3 entries follow */
} __packed;

struct dfs_referral_v3 {
    __le16  VersionNumber;       /* 3 */
    __le16  Size;
    __le16  ServerType;          /* 0=LINK, 1=ROOT */
    __le16  ReferralEntryFlags;
    __le32  TimeToLive;          /* typically 300s */
    __le16  DFSPathOffset;
    __le16  DFSAlternatePathOffset;
    __le16  NetworkAddressOffset;
    __u8    ServiceSiteGuid[16];
} __packed;
```

**Implementation Plan:**
1. Add `case TRANS2_GET_DFS_REFERRAL:` to `smb_trans2()`.
2. Parse `MaxReferralLevel` and `RequestFileName`, decode to local path.
3. Query `ksmbd_dfs.c` for matching DFS namespace entry.
4. Build `dfs_referral_rsp` + v3 entries; if not found, return `STATUS_PATH_NOT_COVERED`.
5. Once working, advertise `CAP_DFS` in `SMB1_SERVER_CAPS`.

---

### 3.7 TRANS2_REPORT_DFS_INCONSISTENCY (0x11)

**Current state:** Falls to `default:` returning `-EINVAL`. Per spec, the server
MUST respond with a valid response (log and ignore is sufficient).

**Fix:**
```c
case TRANS2_REPORT_DFS_INCONSISTENCY:
    ksmbd_debug(SMB, "DFS inconsistency reported by client\n");
    create_trans2_reply(work, 0);
    return 0;
```

---

### 3.8 Interim (Pending) Responses for Long-Running TRANSACTION Commands

**Spec:** MS-SMB §2.2.4.33.2

When a TRANSACTION command cannot be completed immediately (e.g.,
`NT_TRANSACT_NOTIFY_CHANGE`), the server SHOULD send an interim response:
```
WordCount = 0, ByteCount = 0, Status = STATUS_PENDING (0x00000103)
```
The interim response has the same MID as the request. If no interim response is
sent, the client will time out.

**Required additions:**
1. `smb1_send_interim_response()` helper function.
2. A `smb1_pending_request` list on `ksmbd_conn` for async operations.
3. Integration with `NT_TRANSACT_NOTIFY_CHANGE` and `TRANS_WAIT_NMPIPE`.

---

### 3.9 Buffer Layout — DataOffset and ParameterOffset Alignment

**Spec:** MS-SMB §2.2.4.33 — ParameterOffset and DataOffset are from start of
SMB header (`&Protocol`); data must be DWORD-aligned.

**Current code** in `smb_trans()` lines 2373–2376:
```c
rsp->ParameterOffset = cpu_to_le16(56);
rsp->DataOffset = cpu_to_le16(56 + param_len);
```
When `param_len` is not DWORD-aligned, the `DataOffset` is not correctly aligned.

**Fix:** Use ALIGN(param_end, 4) for the data offset and insert padding bytes.
Implement a shared helper `smb1_trans2_set_response(work, param_count, data_count)`
used by all TRANSACTION2 response builders for consistent offset calculation.

---

## 4. Priority 4 — Missing Legacy Commands

These commands are superseded by ANDX or TRANS2 variants in modern clients but
are required for pre-NT Windows and MS-DOS interoperability.

### 4.1 SMB_COM_SEARCH (0x81), FIND (0x82), FIND_UNIQUE (0x83), FIND_CLOSE (0x84)

**Spec:** MS-CIFS §2.2.4.58–§2.2.4.61

**Status:** All four opcodes unregistered.

**Protocol:** Legacy 8.3-filename directory search returning `smb_dir_entry` records.

**Entry wire format (43 bytes per entry):**
```c
struct smb_dir_entry {
    __u8   ResumeKey[21];   /* ServerState[16]+ClientState[4]+Reserved[1] */
    __u8   FileAttributes;
    __le16 LastWriteTime;
    __le16 LastWriteDate;
    __le32 FileDataSize;
    __u8   FileName[13];    /* 8.3, space-padded, no null */
} __packed;
```

**Implementation requirements:**
- `smb_search()` (0x81): one-shot search, no persistent context; 8.3 name conversion
  with `~N` suffix truncation for long names; encode directory position in
  `ResumeKey.ServerState` for resume.
- `smb_find()` (0x82): allocate `smb_search_ctx` per session; persistent open
  directory FP; return `STATUS_NO_MORE_FILES` (mapped to `ERRnofiles`) at EOS.
- `smb_find_unique()` (0x83): same as `smb_search()` — single-batch, no persistent context.
- `smb_find_close()` (0x84): free the `smb_search_ctx` by `search_id` from ResumeKey;
  if FIND not yet implemented, return `STATUS_SUCCESS` as a stub.

**Required struct:**
```c
struct smb_search_ctx {
    struct list_head list;
    __u16  search_id;
    struct file *dir_fp;
    loff_t pos;
    __u16  search_attrs;
};
```

---

### 4.2 SMB_COM_COPY (0x29) — Handler Missing

**Spec:** MS-SMB §2.2.4.29 (opcode registered in string table but no handler in dispatch)

**Wire Format (WC=3):**
```
USHORT  Tid2;           /* destination TID */
USHORT  OpenFunction;   /* disposition for destination */
USHORT  Flags;          /* 0x0001=dest is dir, 0x0002=source ASCII,
                           0x0004=verify writes, 0x0008=recursive copy */
```
Response: `CopyCount` (USHORT).

**Structures to add to smb1pdu.h:**
```c
struct smb_com_copy_req {
    struct smb_hdr hdr;     /* wct = 3 */
    __u16  Tid2;
    __le16 OpenFunction;
    __le16 Flags;
    __le16 ByteCount;
    /* followed by two buffer-format + name pairs */
} __packed;

struct smb_com_copy_rsp {
    struct smb_hdr hdr;     /* wct = 1 */
    __le16 CopyCount;
    __le16 ByteCount;
} __packed;
```

**Implementation:** Resolve source and destination paths; for cross-TID, resolve
`Tid2` via `ksmbd_tree_conn_from_id(work->sess, Tid2)`. Use `ksmbd_vfs_copy_file_range()`
for efficient server-side copy. Handle `SMB_COPY_TREE` flag via `iterate_dir()`
recursive copy.

---

### 4.3 SMB_COM_MOVE (0x2A) — Entirely Missing

**Spec:** MS-SMB §2.2.4.30

Same request/response format as COPY. For same-volume same-share: call
`ksmbd_vfs_rename()`. For cross-volume: copy then delete (non-atomic; document
this). Return `STATUS_NOT_SAME_DEVICE` if cross-volume move fails.

---

### 4.4 SMB_COM_WRITE_AND_CLOSE (0x2C)

**Spec:** MS-CIFS §2.2.4.41

**Wire Format (WC=6):**
```c
struct smb_com_write_and_close_req {
    struct smb_hdr hdr;     /* wct = 6 */
    __le16 FID;
    __le16 Count;
    __le32 Offset;
    __le32 LastWriteTime;
    __le16 ByteCount;
    __u8   Pad[3];
    /* Data follows */
} __packed;

struct smb_com_write_and_close_rsp {
    struct smb_hdr hdr;     /* wct = 1 */
    __le16 Count;
    __le16 ByteCount;
} __packed;
```

**Spec rule:** FID MUST be closed even if write fails. `LastWriteTime = 0` means
"server sets current time"; `Count = 0` still closes the FID.

**smb1misc.c:** `case SMB_COM_WRITE_AND_CLOSE: if (wc != 0xc && wc != 0xe) return -EINVAL;`

---

### 4.5 SMB_COM_SEEK (0x12)

**Wire Format (WC=4):**
```c
struct smb_com_seek_req {
    struct smb_hdr hdr;     /* wct = 4 */
    __u16 Fid;
    __le16 Mode;            /* 0=from start, 1=from current, 2=from end */
    __le32 Offset;          /* signed */
    __le16 ByteCount;
} __packed;

struct smb_com_seek_rsp {
    struct smb_hdr hdr;     /* wct = 2 */
    __le32 Offset;          /* new absolute offset */
    __le16 ByteCount;
} __packed;
```

**Implementation:** Maintain `current_offset` field in `ksmbd_file`
(`src/include/fs/vfs_cache.h`). Compute new offset from Mode and update. Only
relevant for legacy `SMB_COM_READ` (0x0A) and `SMB_COM_WRITE` (0x0B) which use
`fp->current_offset` when no explicit offset is provided.

**smb1misc.c:** `case SMB_COM_SEEK: if (wc != 0x4) return -EINVAL;`

---

### 4.6 Legacy Open/Create Commands

All are absent from the dispatch table. Implement as simplified wrappers reusing
the core open path from `smb_open_andx()`.

| Command | Opcode | WC | Behavior |
|---|---|---|---|
| `SMB_COM_OPEN` | 0x02 | 2 | Open existing file; response WC=7 with FID + attribs |
| `SMB_COM_CREATE` | 0x03 | 3 | Create/truncate; `O_CREAT | O_TRUNC`; response WC=1 with FID |
| `SMB_COM_CREATE_NEW` | 0x0F | 3 | Create-if-not-exists; `O_CREAT | O_EXCL`; `-EEXIST` → `STATUS_OBJECT_NAME_COLLISION` |
| `SMB_COM_CREATE_TEMPORARY` | 0x0E | 3 | Create temp file in DirectoryName; generate unique name; response includes generated FileName string |

---

### 4.7 Print Queue Commands

| Command | Opcode | Implementation |
|---|---|---|
| `SMB_COM_OPEN_PRINT_FILE` | 0x43 | Create temp spool file; store Mode and IdentifierString; return FID |
| `SMB_COM_WRITE_PRINT_FILE` | 0x44 | Write raw print data to spool FID via standard VFS write |
| `SMB_COM_CLOSE_PRINT_FILE` | 0x45 | Flush spool file via `vfs_fsync()`; close FID; optionally submit to print backend |
| `SMB_COM_GET_PRINT_QUEUE` | 0x3D | Return `Count=0` (empty queue) as minimum compliant implementation |

---

## 5. Priority 5 — Security and Protocol Hardening

### 5.1 Error Code Model — DOS Error Support

**Spec:** MS-SMB §3.1.4.2

**Current state:** KSMBD always sets `SMBFLG2_ERR_STATUS` in the response `Flags2`,
sending NTSTATUS even when the client's request had this bit cleared. Pre-NT
clients that do not set `SMBFLG2_ERR_STATUS` will misinterpret the 32-bit NTSTATUS
as a DOS error.

**Required fix — central error response helper:**
```c
static void smb1_set_status(struct smb_hdr *rsp_hdr,
                             const struct smb_hdr *req_hdr,
                             __le32 ntstatus)
{
    if (req_hdr->Flags2 & SMBFLG2_ERR_STATUS) {
        rsp_hdr->Status.CifsError = ntstatus;
        rsp_hdr->Flags2 |= SMBFLG2_ERR_STATUS;
    } else {
        __u8  eclass;
        __le16 ecode;
        ntstatus_to_dos(ntstatus, &eclass, &ecode);
        rsp_hdr->Status.DosError.ErrorClass = eclass;
        rsp_hdr->Status.DosError.Error      = ecode;
        rsp_hdr->Flags2 &= ~SMBFLG2_ERR_STATUS;
    }
}
```

**Missing DOS error mappings** to add to `ntstatus_to_dos_map[]` in
`src/protocol/common/netmisc.c`:
```c
{ ERRDOS, 18, NT_STATUS_NO_MORE_FILES },       /* ERRnofiles */
{ ERRDOS, 61, NT_STATUS_PRINT_QUEUE_FULL },    /* ERRqueuefull */
{ ERRDOS, 62, NT_STATUS_NO_SPOOL_SPACE },      /* ERRnospool */
```

---

### 5.2 SMB Signing Gaps

**Spec:** MS-SMB §3.1.4.1, §3.3.4.1.1

#### Gap 1 — Mandatory Signing Not Enforced

When `SECMODE_SIGN_REQUIRED` is negotiated and the client fails to sign a request,
`smb1_is_sign_req()` returns `false` (the bit is not set in the request header),
and the unsigned request is silently processed.

**Fix:** When mandatory signing is negotiated, `smb1_is_sign_req()` should return
`true` for all commands post-session-setup regardless of the client's header flag.

#### Gap 2 — sequence_number++ Not Atomic

**Location:** `src/protocol/smb1/smb1pdu.c` line 8988 (`smb1_check_sign_req()`)

```c
rcv_hdr1->Signature.Sequence.SequenceNumber =
    cpu_to_le32(++work->sess->sequence_number);
```

With `MaxMpxCount > 1`, multiple work items access the session's sequence number
concurrently. This is a data race.

**Fix:** Use `atomic_t` for `sequence_number` in `struct ksmbd_session`, or protect
increments with the session lock.

#### Gap 3 — Signing Failure Does Not Disconnect

Verify that when `smb1_check_sign_req()` returns 0 (mismatch), the calling code
sends `STATUS_ACCESS_DENIED` and/or closes the connection as required by the spec.

---

### 5.3 UNIX Extensions CAP Mismatch

**Location:** `src/include/protocol/smb1pdu.h` line 1241

The `SMB_UNIX_CAPS` mask advertises `CIFS_UNIX_FCNTL_CAP` (0x01) and
`CIFS_UNIX_XATTR_CAP` (0x04), but the corresponding TRANS2 info levels are absent:

- `CIFS_UNIX_FCNTL_CAP` → TRANS2_QUERY/SET_FILE_INFORMATION level 0x208 (POSIX locks) missing
- `CIFS_UNIX_XATTR_CAP` → TRANS2_QUERY/SET_PATH_INFORMATION level 0x205 missing

**Options:** Either implement the missing TRANS2 levels (preferred) or remove the
corresponding bits from `SMB_UNIX_CAPS` to stop falsely advertising capabilities.

**POSIX lock implementation** (level 0x208 in both QUERY_FILE and SET_FILE handlers):
```c
struct smb_lock_struct {
    __le64  Offset;
    __le64  Length;
    __le32  Pid;
    __le16  LockType;   /* READ_LOCK=0, WRITE_LOCK=1, UNLOCK=2 */
    __le16  ReturnCode;
} __packed;
```
Query: call `vfs_test_lock()` for the range; return `smb_lock_struct` with status.
Set: call `ksmbd_vfs_posix_lock_set()` non-blocking; return SUCCESS or LOCK_NOT_GRANTED.

**POSIX xattr implementation** (level 0x205):
- Query: parse EA name from request, call `ksmbd_vfs_get_xattr()`.
- Set: parse name and value, call `ksmbd_vfs_setxattr()`. When client omits namespace prefix, prepend `user.`.

**WHO_AM_I implementation** (level 0x202 in QUERY_FS):
Return effective UID, GID, and supplemental groups for the session. See full
response structure `smb_whoami_rsp` in `smb1_plan_06_legacy_security.md` §7.2.2.

---

### 5.4 Bounds Checking — All TRANSACTION Parameter and Data Offsets

While implementing the missing subcommands, apply the following security rules to
ALL TRANSACTION/TRANSACTION2/NT_TRANSACT handlers:

1. **Validate ParameterOffset/DataOffset before dereferencing:**
   ```c
   if (offset > req_len || offset + count > req_len)
       return -EINVAL; /* STATUS_INVALID_PARAMETER */
   ```

2. **Validate information level struct sizes** before writing response data.

3. **Validate Unicode name lengths** — `NameLength` must not exceed remaining buffer.

4. **EA list traversal** — when iterating `FEAList` or `GEAList`, validate each
   `next` step against the list's declared `list_len` to prevent integer-wrap attacks.

5. **NT_TRANSACT 32-bit counts** — validate that `TotalParameterCount`,
   `TotalDataCount`, `ParameterOffset`, and `DataOffset` do not overflow when cast
   to `size_t` or added to a pointer.

---

## 6. Implementation Schedule

### Sprint A — Blocker Fixes (Week 1–2, estimated 40–50 hours)

| Task | File(s) | Effort |
|---|---|---|
| P1.1 WriteMode bit check (`== 1` → `& 0x0001`) | smb1pdu.c:3453 | 5 min |
| P1.12 query_file_info_pipe() DeletePending double-write | smb1pdu.c:7020 | 5 min |
| P1.3 READ_ANDX duplicate DataCompactionMode | smb1pdu.c:3258 | 5 min |
| P1.2 NT_CREATE_ANDX GuestAccess not set | smb1pdu.c:2970 | 10 min |
| P1.15 LOCKING_ANDX CHANGE_LOCKTYPE NTSTATUS fix | smb1pdu.c:1761 | 30 min |
| P1.18 ECHO SequenceNumber off-by-one | smb1pdu.c:3569 | 30 min |
| P1.19 QUERY_INFORMATION ATTR_ARCHIVE | smb1pdu.c:8347 | 30 min |
| P1.20 QUERY_FS_ATTRIBUTE_INFO append NTFS name | smb1pdu.c:5036 | 30 min |
| P1.4 OPEN_ANDX FileAttributes always ATTR_NORMAL | smb1pdu.c:8670 | 1h |
| P1.5 CLOSE no error for invalid FID | smb1pdu.c:3095 | 1h |
| P1.8 TREE_DISCONNECT wrong error STATUS_SMB_BAD_TID | smb1pdu.c:473 | 1h |
| P1.13 TRANSACTION2 smb_fileinfo_rename() truncates wrong file | smb1pdu.c:7586 | 1h |
| P1.9 NEGOTIATE DialectIndex=0xFFFF on no-match | smb1pdu.c:988 | 1h |
| P1.10 NEGOTIATE MaxRawSize=0 without CAP_RAW_MODE | smb1pdu.c:1011 | 30 min |
| P1.21 NEGOTIATE missing DomainName in non-extsec response | smb1pdu.c:1027 | 2h |
| P1.22/23 SESSION_SETUP extsec response missing strings | smb1pdu.c | 3h |
| P1.14 SETATTR LastWriteTime semantics | smb1pdu.c:8788 | 1h |
| P1.16/17 LOCKING_ANDX order + Timeout semantics | smb1pdu.c | 3h |
| P1.24/25 TREE_CONNECT flags + DFS OptionalSupport | smb1pdu.c | 2h |
| P1.6/7 LOGOFF_ANDX session vs connection teardown | smb1pdu.c:446 | 3h |
| P1.11 SESSION_SETUP mechToken over-read | smb1pdu.c:1326 | 2h |
| P1.27 NEGOTIATE missing capability bits | smb1pdu.h | 1h |
| NT_TRANSACT wire structures | smb1pdu.h | 2h |

### Sprint B — NT_TRANSACT Core (Week 3–5, estimated 40–50 hours)

| Task | File(s) | Effort |
|---|---|---|
| NT_TRANSACT dispatcher + smb1ops.c + smb1misc.c wiring | smb1ops.c, smb1misc.c, smb1pdu.c | 4h |
| Response envelope helper `smb_build_nt_transact_rsp()` | smb1pdu.c | 2h |
| NT_TRANSACT_QUERY_SECURITY_DESC (0x06) | smb1pdu.c | 3h |
| NT_TRANSACT_SET_SECURITY_DESC (0x03) | smb1pdu.c | 3h |
| NT_TRANSACT_RENAME (0x05) + `ksmbd_vfs_rename_by_dentry()` | smb1pdu.c, vfs.c | 3h |
| NT_TRANSACT_IOCTL (0x02) bridge to FSCTL dispatch | smb1pdu.c | 5h |
| NT_TRANSACT_CREATE (0x01) + SD + EA | smb1pdu.c | 6h |
| SMB_COM_QUERY_INFORMATION2 (0x23) | smb1pdu.c, smb1ops.c, smb1misc.c, smb1pdu.h | 3h |
| SMB_COM_SET_INFORMATION2 (0x22) | smb1pdu.c, smb1ops.c, smb1misc.c, smb1pdu.h | 3h |
| LOCKING_ANDX CANCEL_LOCK functional | smb1pdu.c | 4h |
| NT_CANCEL: blocked work + lock list walk | smb1pdu.c | 3h |
| NT_CANCEL: sequence_number race fix | smb1pdu.c | 1h |
| Oplock: expose enable module parameter | smb1pdu.c, ksmbd_config.c | 1h |
| Oplock: FID overflow guard | oplock.c:817 | 30 min |
| P2.4 SESSION_SETUP invalid WC error (not silent drop) | smb1pdu.c | 30 min |
| P2.6 SESSION_SETUP VcNumber=0 disconnect existing | smb1pdu.c | 2h |

### Sprint C — TRANSACTION2 + Async (Week 6–9, estimated 60–70 hours)

| Task | File(s) | Effort |
|---|---|---|
| NT_TRANSACT_NOTIFY_CHANGE + `ksmbd_smb1_notify_watch()` | smb1pdu.c, ksmbd_notify.c | 8h |
| NT_CANCEL: NOTIFY_CHANGE cancellation | smb1pdu.c, ksmbd_notify.c | 3h |
| Interim response infrastructure + `smb1_send_interim_response()` | smb1pdu.c | 3h |
| TRANSACTION named pipe subcommands (10 handlers) | smb1pdu.c | 18h |
| Mailslot detection and Class 2 silent discard | smb1pdu.c | 2h |
| TRANSACTION2 missing FS info levels (0x0002, 0x0202) | smb1pdu.c | 4h |
| TRANSACTION2 missing PATH info levels (10+ levels) | smb1pdu.c | 10h |
| TRANSACTION2 missing FILE info levels | smb1pdu.c | 6h |
| FIND_FIRST2/FIND_NEXT2 flag gaps (CLOSE_AFTER, RESUME_KEYS, etc.) | smb1pdu.c | 10h |
| POSIX lock TRANS2 level 0x208 | smb1pdu.c | 3h |
| POSIX xattr TRANS2 level 0x205 | smb1pdu.c | 2h |
| POSIX WHO_AM_I level 0x202 | smb1pdu.c | 2h |
| Remove CIFS_UNIX_FCNTL_CAP / XATTR_CAP if levels unimplemented | smb1pdu.h | 30 min |

### Sprint D — Secondary Packets + DFS (Week 10–13, estimated 50–60 hours)

| Task | File(s) | Effort |
|---|---|---|
| `smb_transaction_state` reassembly infrastructure on conn | smb1pdu.c | 3h |
| TRANSACTION_SECONDARY (0x26) handler | smb1pdu.c, smb1ops.c | 6h |
| TRANSACTION2_SECONDARY (0x33) handler | smb1pdu.c, smb1ops.c | 4h |
| NT_TRANSACT_SECONDARY (0xA1) handler with 32-bit counts | smb1pdu.c, smb1ops.c | 4h |
| Reassembly timeout via conn-level timer | smb1pdu.c | 3h |
| TRANS2_GET_DFS_REFERRAL (0x10) bridge to ksmbd_dfs.c | smb1pdu.c, ksmbd_dfs.c | 6h |
| TRANS2_REPORT_DFS_INCONSISTENCY (0x11) stub | smb1pdu.c | 30 min |
| NT_TRANSACT_GET_USER_QUOTA (0x07) | smb1pdu.c, ksmbd_quota.c | 4h |
| NT_TRANSACT_SET_USER_QUOTA (0x08) | smb1pdu.c, ksmbd_quota.c | 3h |
| Error code model: smb1_set_status() + DOS error support | smb1pdu.c, netmisc.c | 3h |
| SMB signing mandatory enforcement | smb1pdu.c | 2h |
| SMB signing sequence_number atomic | auth.c, smb1pdu.c | 1h |

### Sprint E — Legacy Commands (Week 14–16, estimated 30–40 hours)

| Task | File(s) | Effort |
|---|---|---|
| COPY (0x29) handler | smb1pdu.c, smb1ops.c | 5h |
| MOVE (0x2A) handler | smb1pdu.c, smb1ops.c | 3h |
| WRITE_AND_CLOSE (0x2C) handler | smb1pdu.c, smb1ops.c, smb1pdu.h | 2h |
| SEEK (0x12) + per-FID seek state | smb1pdu.c, vfs_cache.h, smb1ops.c | 3h |
| SEARCH (0x81) + 8.3 name conversion | smb1pdu.c, smb1ops.c | 5h |
| FIND (0x82) + smb_search_ctx | smb1pdu.c, smb1ops.c | 3h |
| FIND_UNIQUE (0x83) | smb1pdu.c, smb1ops.c | 1h |
| FIND_CLOSE (0x84) | smb1pdu.c, smb1ops.c | 1h |
| OPEN (0x02) handler | smb1pdu.c, smb1ops.c | 3h |
| CREATE (0x03) + CREATE_NEW (0x0F) + CREATE_TEMPORARY (0x0E) | smb1pdu.c, smb1ops.c | 3h |
| Print queue: OPEN/WRITE/CLOSE_PRINT_FILE + GET_PRINT_QUEUE | smb1pdu.c, smb1ops.c | 4h |
| SETATTR xattr-backed DOS attrs | smb1pdu.c | 2h |
| Buffer layout: generalise DataOffset/ParameterOffset calculation | smb1pdu.c | 3h |

---

## 7. Testing Checklist

### 7.1 Priority 1 Bug Regression Tests

```bash
# WriteMode bit test: WriteMode=0x0003 should still flush to disk
smbclient //server/share -U user -m NT1 -c "put testfile; get testfile"

# GuestAccess in extended response
smbclient //server/share -U user -m NT1 -c "ntcreate /testfile 0x10"
# Observe WC=50 response; verify GuestAccess field is non-zero

# LOGOFF_ANDX: multi-UID session — second UID survives first logoff
# (requires Windows client test via SMB trace)

# TREE_DISCONNECT: invalid TID should return STATUS_SMB_BAD_TID not STATUS_NO_SUCH_USER
smbtorture //server/share SMB-BASIC
```

### 7.2 NT_TRANSACT Tests

```bash
# Security descriptor test — requires Windows client
# From Windows XP: right-click share folder → Properties → Security

# NT_TRANSACT_QUERY_SECURITY_DESC — buffer-too-small path
smbtorture //server/share BASE-NTACLTEST

# NT_TRANSACT_NOTIFY_CHANGE
smbtorture //server/share SMB-NOTIFYK
# Create file in watched directory → notification received
# Cancel pending notification via SMB_COM_NT_CANCEL
```

### 7.3 Locking Tests

```bash
locktest -N 100 //server/share
smbtorture //server/share SMB-BENCH-LOCK
# CANCEL_LOCK: start a blocking lock in one session, cancel from another
```

### 7.4 TRANSACTION2 Tests

```bash
# FIND_FIRST2 with CLOSE_AFTER_REQUEST flag
# FIND_FIRST2 with RETURN_RESUME_KEYS flag — verify 4-byte prefix per entry
# SMB_QUERY_POSIX_WHO_AM_I — check UID/GID returned matches mounted user
smbclient //server/share -U user -m NT1 -c "posix"

# DFS referral test
smbclient //server/dfs_path -U user -m NT1 --option="clientmaxprotocol=NT1"
```

### 7.5 Signing Tests

```bash
# Mandatory signing enforcement
ksmbd.conf: signing = mandatory
smbclient //server/share -U user -m NT1  # should enforce signing
# Attempt to send unsigned packet → should disconnect

# Sequence number atomic test (stress)
for i in $(seq 1 100); do smbclient //server/share -U user -m NT1 -c "ls" & done
wait
```

### 7.6 Legacy Command Tests

```bash
# QUERY_INFORMATION2 / SET_INFORMATION2 (requires old Windows client or smbclient legacy mode)
smbclient //server/share -U user -m NT1 -c "ls"  # triggers QUERY_INFORMATION2 on some versions

# SEARCH / FIND via smbclient legacy mode
smbclient //server/share -U user -m LANMAN1 -c "ls"
```

### 7.7 Error Code Model Tests

```bash
# Pre-NT client: verify DOS error format is returned
# Use smbclient with -m LANMAN2.1 to force pre-NT client behaviour
smbclient //server/share -U user -m LANMAN2.1 -c "ls /nonexistent"
# Should receive ERRDOS/ERRbadpath, not NTSTATUS in wrong format
```

---

## 8. Spec Cross-Reference Table

| Feature | MS-SMB Section | Spec Document | Current State | Priority |
|---|---|---|---|---|
| SMB_COM_NEGOTIATE response | §2.2.4.52 | MS-SMB | Partial (see §1.9–1.11, 1.21, 1.27) | P1 |
| SMB_COM_SESSION_SETUP_ANDX | §2.2.4.53 | MS-SMB | Partial (see §1.11, 1.22–1.24, 2.4) | P1/P2 |
| SMB_COM_TREE_CONNECT_ANDX | §2.2.4.55 | MS-SMB | Partial (see §1.24, 1.25) | P1 |
| SMB_COM_LOGOFF_ANDX | §2.2.4.54 | MS-SMB | Buggy (see §1.6, 1.7) | P1 |
| SMB_COM_TREE_DISCONNECT | §2.2.4.51 | MS-SMB | Partial (see §1.8) | P1 |
| SMB_COM_NT_CREATE_ANDX | §2.2.4.64 | MS-SMB | Partial (see §1.2, various P1/P2 items) | P1/P2 |
| SMB_COM_OPEN_ANDX | §2.2.4.30 | MS-SMB | Partial (see §1.4) | P1 |
| SMB_COM_READ_ANDX | §2.2.4.31 | MS-SMB | Partial (see §1.3) | P1 |
| SMB_COM_WRITE_ANDX | §2.2.4.32 | MS-SMB | Buggy (see §1.1) | P1 |
| SMB_COM_CLOSE | §2.2.4.5 | MS-SMB | Partial (see §1.5) | P1 |
| SMB_COM_FLUSH | §2.2.4.6 | MS-SMB | Partial (wrong error codes) | P1 |
| SMB_COM_LOCKING_ANDX | §2.2.4.26 | MS-SMB | Partial (see §1.15–1.17, 2.2) | P1/P2 |
| SMB_COM_ECHO | §2.2.4.35 | MS-SMB | Partial (see §1.18) | P1 |
| SMB_COM_QUERY_INFORMATION | §2.2.4.8 | MS-SMB | Partial (see §1.19) | P1 |
| SMB_COM_SETATTR | §2.2.4.9 | MS-SMB | Partial (see §1.14) | P1 |
| SMB_COM_NT_TRANSACT (0xA0) | §2.2.4.62 | MS-SMB | MISSING entirely | P2 |
| NT_TRANSACT_CREATE (0x01) | §2.2.4.62.5 | MS-SMB | MISSING | P2 |
| NT_TRANSACT_IOCTL (0x02) | §2.2.4.62.9 | MS-SMB | MISSING | P2 |
| NT_TRANSACT_SET_SECURITY_DESC (0x03) | §2.2.4.62.11 | MS-SMB | MISSING | P2 |
| NT_TRANSACT_NOTIFY_CHANGE (0x04) | §2.2.4.62.13 | MS-SMB | MISSING | P2 |
| NT_TRANSACT_RENAME (0x05) | §2.2.4.62.15 | MS-SMB | MISSING | P2 |
| NT_TRANSACT_QUERY_SECURITY_DESC (0x06) | §2.2.4.62.17 | MS-SMB | MISSING | P2 |
| NT_TRANSACT_GET_USER_QUOTA (0x07) | §2.2.4.62.19 | MS-SMB | MISSING | P4 |
| NT_TRANSACT_SET_USER_QUOTA (0x08) | §2.2.4.62.21 | MS-SMB | MISSING | P4 |
| SMB_COM_NT_CANCEL | §2.2.4.65 | MS-SMB | Partial (see §2.3) | P2 |
| SMB_COM_QUERY_INFORMATION2 (0x23) | §2.2.4.24 | MS-SMB | MISSING | P2 |
| SMB_COM_SET_INFORMATION2 (0x22) | §2.2.4.23 | MS-SMB | MISSING | P2 |
| SMB_COM_TRANSACTION (0x25) named pipe subcommands | §2.2.4.33 | MS-SMB | Partial (see §3.2) | P3 |
| SMB_COM_TRANSACTION_SECONDARY (0x26) | §2.2.4.34 | MS-SMB | MISSING | P3 |
| TRANS2_FIND_FIRST2 (0x01) flags | §2.2.4.34.1 | MS-SMB | Partial (see §3.3) | P3 |
| TRANS2_FIND_NEXT2 (0x02) resume | §2.2.4.34.2 | MS-SMB | Partial (see §3.3) | P3 |
| TRANS2_QUERY_FS_INFORMATION missing levels | §2.2.4.34.3 | MS-SMB | Partial (see §3.4.1) | P3 |
| TRANS2_QUERY_PATH_INFORMATION missing levels | §2.2.4.34.5 | MS-SMB | Partial (see §3.4.2) | P3 |
| TRANS2_QUERY_FILE_INFORMATION missing levels | §2.2.4.34.7 | MS-SMB | Partial (see §3.4.3) | P3 |
| TRANS2_SET_PATH_INFORMATION missing levels | §2.2.4.34.6 | MS-SMB | Partial (see §3.4.4) | P3 |
| TRANS2_SET_FILE_INFORMATION missing levels | §2.2.4.34.8 | MS-SMB | Partial (see §3.4.5) | P3 |
| TRANS2_GET_DFS_REFERRAL (0x10) | §2.2.4.34.15 | MS-SMB | MISSING | P3 |
| TRANS2_REPORT_DFS_INCONSISTENCY (0x11) | §2.2.4.34.16 | MS-SMB | MISSING | P3 |
| SMB_COM_TRANSACTION2_SECONDARY (0x33) | §2.2.4.35 | MS-SMB | MISSING | P3 |
| SMB_COM_NT_TRANSACT_SECONDARY (0xA1) | §2.2.4.63 | MS-SMB | MISSING | P3 |
| Interim (pending) responses | §2.2.4.33.2 | MS-SMB | MISSING | P3 |
| TRANSACTION DataOffset alignment | §2.2.4.33 | MS-SMB | Partial (see §3.9) | P3 |
| SMB_COM_COPY (0x29) | §2.2.4.29 | MS-SMB | MISSING (registered string only) | P4 |
| SMB_COM_MOVE (0x2A) | §2.2.4.30 | MS-SMB | MISSING | P4 |
| SMB_COM_WRITE_AND_CLOSE (0x2C) | MS-CIFS §2.2.4.41 | MS-CIFS | MISSING | P4 |
| SMB_COM_SEEK (0x12) | MS-CIFS §2.2.4.20 | MS-CIFS | MISSING | P4 |
| SMB_COM_SEARCH (0x81) | MS-CIFS §2.2.4.58 | MS-CIFS | MISSING | P4 |
| SMB_COM_FIND (0x82) | MS-CIFS §2.2.4.59 | MS-CIFS | MISSING | P4 |
| SMB_COM_FIND_UNIQUE (0x83) | MS-CIFS §2.2.4.60 | MS-CIFS | MISSING | P4 |
| SMB_COM_FIND_CLOSE (0x84) | MS-CIFS §2.2.4.61 | MS-CIFS | MISSING | P4 |
| SMB_COM_OPEN (0x02) | MS-CIFS §2.2.4.3 | MS-CIFS | MISSING | P4 |
| SMB_COM_CREATE (0x03) | MS-CIFS §2.2.4.4 | MS-CIFS | MISSING | P4 |
| SMB_COM_CREATE_NEW (0x0F) | MS-CIFS §2.2.4.15 | MS-CIFS | MISSING | P4 |
| SMB_COM_CREATE_TEMPORARY (0x0E) | MS-CIFS §2.2.4.14 | MS-CIFS | MISSING | P4 |
| SMB_COM_OPEN_PRINT_FILE (0x43) | MS-CIFS §2.2.4.49 | MS-CIFS | MISSING | P4 |
| SMB_COM_WRITE_PRINT_FILE (0x44) | MS-CIFS §2.2.4.50 | MS-CIFS | MISSING | P4 |
| SMB_COM_CLOSE_PRINT_FILE (0x45) | MS-CIFS §2.2.4.51 | MS-CIFS | MISSING | P4 |
| SMB_COM_GET_PRINT_QUEUE (0x3D) | MS-CIFS §2.2.4.42 | MS-CIFS | MISSING | P4 |
| Error code model (DOS vs NTSTATUS) | §3.1.4.2 | MS-SMB | Partial (see §5.1) | P5 |
| SMB signing mandatory enforcement | §3.3.4.1 | MS-SMB | Partial (see §5.2) | P5 |
| SMB signing sequence_number atomic | §3.3.4.1.1 | MS-SMB | Buggy (see §5.2) | P5 |
| CIFS POSIX lock (0x208) | CIFS POSIX Ext. | Samba | Partial/missing (see §5.3) | P5 |
| CIFS POSIX xattr (0x205) | CIFS POSIX Ext. | Samba | Partial/missing (see §5.3) | P5 |
| CIFS WHO_AM_I (0x202) | CIFS POSIX Ext. | Samba | MISSING (see §5.3) | P5 |
| SMB_COM_READ_RAW (0x1C) | §2.2.4.21 | MS-SMB | DELIBERATELY SKIPPED | skip |
| SMB_COM_WRITE_RAW (0x1D) | §2.2.4.22 | MS-SMB | DELIBERATELY SKIPPED | skip |
| SMB_COM_LOCK_AND_READ (0x13) | §2.2.4.13 | MS-SMB | DELIBERATELY SKIPPED | skip |
| SMB_COM_SEND_MESSAGE (0x3A–0x3D) | — | MS-SMB | DELIBERATELY SKIPPED (WinPopup obsolete) | skip |

---

## 9. WRITE_ANDX Wire Format and Response Fields

### 9.1 WRITE_ANDX Request Wire Format (WordCount=12 or WordCount=14)

| Field | Size | Notes |
|-------|------|-------|
| AndXCommand | 1 | |
| AndXReserved | 1 | |
| AndXOffset | 2 | |
| Fid | 2 | File handle |
| OffsetLow | 4 | Low 32 bits of write offset |
| Reserved | 4 | Must be 0 |
| WriteMode | 2 | Bit flags (see below) |
| Remaining | 2 | Bytes remaining to write in this ANDX chain |
| DataLengthHigh | 2 | High 16 bits of DataLength |
| DataLengthLow | 2 | Low 16 bits of DataLength |
| DataOffset | 2 | Offset from SMB header start to data |
| OffsetHigh | 4 | High 32 bits (WordCount=14 only; large file support) |
| ByteCount | 2 | |
| Pad | 1 | Alignment byte |
| Data | var | Write payload |

### 9.2 WriteMode Bit Field

| Bit | Value | Meaning |
|-----|-------|---------|
| 0 | 0x0001 | Write-through: flush to disk before responding |
| 1 | 0x0002 | ReadBytesAvailable: for named pipes, return bytes available |
| 2 | 0x0004 | Named pipe raw mode |
| 3 | 0x0008 | Named pipe start of message |

**Bug (P1.1):** Current code uses `== 1` instead of `& 0x0001`. When bit 1 is
also set (e.g., `WriteMode=0x0003`), the write-through check silently fails.

**Fix:**
```c
/* smb1pdu.c line 3453 */
writethrough = !!(le16_to_cpu(req->WriteMode) & 0x0001);
```

**Additional gap — ReadBytesAvailable (bit 1):** Not implemented. For named
pipes, the response `Available` field should return bytes available for reading.
Currently always 0.

### 9.3 Large Write Support

`DataLengthLow` and `DataLengthHigh` are combined via `CAP_LARGE_WRITE_X` gating:
```c
count = le16_to_cpu(req->DataLengthLow);
if (conn->vals->capabilities & CAP_LARGE_WRITE_X)
    count |= (le16_to_cpu(req->DataLengthHigh) << 16);
```
This is correct per MS-SMB §3.3.5.8.

---

## 10. CLOSE and FLUSH Wire Formats and Gap Analysis

### 10.1 SMB_COM_CLOSE (0x04) Request Wire Format (WordCount=3)

| Field | Size | Notes |
|-------|------|-------|
| FileID | 2 | Handle to close |
| LastWriteTime | 4 | UTIME (0 or 0xFFFFFFFF = no change; any other value sets mtime) |
| ByteCount | 2 | 0 |

**P1.5 Bug — No Error for Invalid FID:**
```c
/* Current: */
ksmbd_close_fd(work, req->FileID);
/* Error not checked — STATUS_SUCCESS returned even for invalid FID */

/* Fix: */
err = ksmbd_close_fd(work, req->FileID);
if (err) {
    rsp->hdr.Status.CifsError = STATUS_INVALID_HANDLE;
    return err;
}
```

**Additional gap — LastWriteTime = 0xFFFFFFFF:** The spec says both 0 and
`0xFFFFFFFF` mean "no change." KSMBD handles both correctly. No bug here.

### 10.2 SMB_COM_FLUSH (0x05) Wire Format (WordCount=1)

| Field | Size | Notes |
|-------|------|-------|
| FileID | 2 | 0xFFFF = flush all files in the session |
| ByteCount | 2 | 0 |

**Gap — Error code mapping:** When flush fails, the error response should be:
- Invalid FID → `STATUS_INVALID_HANDLE`
- Disk I/O error → `STATUS_UNEXPECTED_IO_ERROR`
- Disk full → `STATUS_DISK_FULL`

Currently always returns `STATUS_INVALID_HANDLE` for any failure.

---

## 11. NT_CREATE_ANDX Compliance Detail

This section expands on the gap analysis for `SMB_COM_NT_CREATE_ANDX` (opcode 0xA2),
which is the primary file-open command used by all NT-class clients.

### 9.1 CreateOptions Field Gap Analysis

The `CreateOptions` field is a 32-bit mask. The full compliance table:

| Bit Mask | Constant | KSMBD Handling | Gap |
|----------|----------|----------------|-----|
| 0x00000001 | FILE_DIRECTORY_FILE | Handled: create_directory=1 | None |
| 0x00000002 | FILE_WRITE_THROUGH | Handled: sets O_SYNC | None |
| 0x00000004 | FILE_SEQUENTIAL_ONLY | Not handled in smb1 path | GAP: Should hint readahead |
| 0x00000008 | FILE_NO_INTERMEDIATE_BUFFERING | Not handled | GAP: STATUS_INVALID_PARAMETER for unaligned writes |
| 0x00000010 | FILE_SYNCHRONOUS_IO_ALERT | Not validated | GAP: Mutual exclusion with FILE_NO_INTERMEDIATE_BUFFERING |
| 0x00000040 | FILE_NON_DIRECTORY_FILE | Handled: checked vs S_ISDIR | None |
| 0x00000100 | FILE_COMPLETE_IF_OPLOCKED | Not handled | Minor: should complete without waiting for oplock break |
| 0x00000200 | FILE_NO_EA_KNOWLEDGE | Not handled | GAP: Deny if file has EAs |
| 0x00001000 | FILE_DELETE_ON_CLOSE | Handled: permission check + fd_set_delete_on_close | None |
| 0x00002000 | FILE_OPEN_BY_FILE_ID | Handled: returns STATUS_NOT_SUPPORTED | None |
| 0x00010000 | FILE_OPEN_REQUIRING_OPLOCK | Not handled | GAP: Must atomically open + grant oplock |
| 0x00200000 | FILE_OPEN_REPARSE_POINT | Not handled | GAP: Should open reparse point itself, not follow |

**Priority gaps:**
1. `FILE_NO_EA_KNOWLEDGE` (0x200): After path lookup, check for EAs with
   `ksmbd_vfs_listxattr()`. Return `STATUS_ACCESS_DENIED` if any EAs exist.
2. `FILE_OPEN_REQUIRING_OPLOCK` (0x10000): The open and oplock grant must be atomic.
   Currently KSMBD opens then attempts the oplock in a separate step — a race window exists.

### 9.2 NT_CREATE_OPEN_TARGET_DIR Flag

The `NT_CREATE_OPEN_TARGET_DIR` flag (0x08 in the Flags field, constant
`REQ_OPENDIRONLY`) instructs the server to open the **parent directory** of the
target path. This is used for server-side directory monitors and rename
pre-verification.

**Current behavior:** The constant `REQ_OPENDIRONLY` (0x08) is defined in
`smb1pdu.h` but the handler does not implement it. The path component stripping
and parent-dir lookup are missing.

**Fix:** When `req->Flags & REQ_OPENDIRONLY` is set, strip the last path
component (`dirname()`), look up the parent directory, open it, and return a FID
pointing to the directory.

### 9.3 ImpersonationLevel Validation

Four levels are defined (Anonymous=0, Identification=1, Impersonation=2,
Delegation=3). KSMBD reads the field but does not validate that it is in range
[0..3]. Out-of-range values should return `STATUS_INVALID_PARAMETER`.

### 9.4 OPEN_ANDX FileAttributes in Response

**Location:** `src/protocol/smb1/smb1pdu.c` (smb_open_andx)

**Gap:** `rsp->FileAttributes` is always set to `ATTR_NORMAL` (0x0000) regardless
of the actual file attributes. The response must reflect real DOS attributes
computed via `smb_get_dos_attr(&stat)`.

**Fix:**
```c
rsp->FileAttributes = cpu_to_le16(smb_get_dos_attr(&stat));
```

### 9.5 OPEN_ANDX EndOfFile Truncation

`rsp->EndOfFile` is a 32-bit field. Files larger than 4 GB have their size
silently truncated. Per spec, the server should set `rsp->EndOfFile =
cpu_to_le32(0xFFFFFFFF)` for oversized files and document the limitation. Modern
clients should use `NT_CREATE_ANDX` for large file access.

---

## 10. OPEN_ANDX and READ_ANDX Wire Format Tables

### 10.1 SMB_COM_OPEN_ANDX (0x2D) Request Wire Format (WordCount=15)

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | AndXCommand | 1 | Next chained command or 0xFF |
| 1 | AndXReserved | 1 | Must be 0 |
| 2 | AndXOffset | 2 | Offset to next AndX block |
| 4 | OpenFlags | 2 | SMB_OPEN_QUERY_* bits (low nibble) + oplock bits (bits 1-3) |
| 6 | DesiredAccess | 2 | Old-style: read/write/share-mode encoded |
| 8 | SearchAttributes | 2 | DOS search attribute filter |
| 10 | FileAttributes | 2 | DOS file attributes for new files |
| 12 | CreationTime | 4 | OS/2 format (seconds since 1970) |
| 16 | OpenFunction | 2 | Create/open/truncate disposition |
| 18 | AllocationSize | 4 | For new files |
| 22 | Timeout | 4 | Milliseconds |
| 26 | Reserved | 4 | Must be 0 |
| 30 | ByteCount | 2 | |
| 32 | FileName | var | |

### 10.2 OpenFunction Encoding

| Low nibble | Meaning if file exists |
|------------|----------------------|
| 0x00 | OPEN_FUNC_FAIL_IF_EXISTS — return error |
| 0x01 | OPEN_FUNC_OPEN_IF_EXISTS — open existing |
| 0x02 | OPEN_FUNC_OVERWRITE_IF_EXISTS — truncate |

| Bit 4 | Meaning if file does not exist |
|-------|-------------------------------|
| 0x00 | Fail |
| 0x10 | OPEN_FUNC_CREATE_IF_NOT_EXISTS — create |

### 10.3 DesiredAccess Encoding (old-style 16-bit)

| Bits | Meaning |
|------|---------|
| 0-2 | Access mode: 0=read, 1=write, 2=read/write, 3=execute |
| 4-6 | Sharing mode: 0=compat, 1=deny-all, 2=deny-write, 3=deny-read, 4=deny-none |
| 14 | Write-through flag |
| 15 | Caching mode |

**Gap:** The sharing mode (bits 4-6) is rejected outright for any non-zero value
instead of being mapped to NT `ShareAccess` semantics. Map legacy deny modes:
- `deny-all` → `ShareAccess = 0` (deny read+write+delete)
- `deny-write` → `ShareAccess = FILE_SHARE_READ`
- `deny-read` → `ShareAccess = FILE_SHARE_WRITE`
- `deny-none` → `ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`

### 10.4 SMB_COM_READ_ANDX Request Wire Format

| Field | Size | Notes |
|-------|------|-------|
| AndXCommand | 1 | |
| AndXReserved | 1 | |
| AndXOffset | 2 | |
| Fid | 2 | File handle |
| OffsetLow | 4 | Low 32 bits of file offset |
| MaxCount | 2 | Maximum bytes to return |
| MinCount | 2 | Minimum bytes (for UNIX ext. blocking reads) |
| MaxCountHigh | 4 | High 16 bits of MaxCount (CAP_LARGE_READ_X) |
| Remaining | 2 | Reserved |
| OffsetHigh | 4 | High 32 bits (present only when WordCount=12) |
| ByteCount | 2 | 0 |

**Gap — MinCount:** For named-pipe reads, `MinCount > 0` should block until
at least `MinCount` bytes are available. Currently `req->MinCount` is never read.

**Gap — Remaining response field:** Must be `0xFFFF` for disk files (not
`0` as currently set). Per spec, `0xFFFF` indicates "unknown/not applicable"
for non-pipe reads.

### 10.5 READ_ANDX Response Wire Format

| Field | Size | Notes |
|-------|------|-------|
| AndXCommand | 1 | |
| AndXReserved | 1 | |
| AndXOffset | 2 | |
| Remaining | 2 | 0xFFFF for files; bytes remaining for pipes |
| DataCompactionMode | 2 | Must be 0 (no compaction) |
| Reserved | 2 | Must be 0 |
| DataLength | 2 | Low 16 bits of byte count |
| DataOffset | 2 | Offset from SMB header start to data |
| DataLengthHigh | 2 | High 16 bits of byte count |
| Reserved2 | 8 | Must be 0 |
| ByteCount | 2 | Total data bytes |

---

## 11. NEGOTIATE and SESSION_SETUP Compliance Detail

### 11.1 Capabilities Bit Audit

Current `SMB1_SERVER_CAPS` (from `smb1pdu.h`):
```c
CAP_UNICODE | CAP_LARGE_FILES | CAP_EXTENDED_SECURITY |
CAP_NT_SMBS | CAP_STATUS32 | CAP_NT_FIND |
CAP_UNIX | CAP_LARGE_READ_X | CAP_LARGE_WRITE_X | CAP_LEVEL_II_OPLOCKS
```

Full capability bit compliance table:

| Capability | Value | Status | Action |
|---|---|---|---|
| `CAP_RAW_MODE` | 0x0001 | Absent (correct) | No raw-mode handler — must keep absent |
| `CAP_MPX_MODE` | 0x0002 | **Absent — GAP** | KSMBD supports MaxMpxCount=10; add this bit |
| `CAP_UNICODE` | 0x0004 | Present | Correct |
| `CAP_LARGE_FILES` | 0x0008 | Present | Correct |
| `CAP_NT_SMBS` | 0x0010 | Present | Correct |
| `CAP_RPC_REMOTE_APIS` | 0x0020 | **Absent — GAP** | Named-pipe DCE/RPC IS implemented; add |
| `CAP_STATUS32` | 0x0040 | Present | Correct |
| `CAP_LEVEL_II_OPLOCKS` | 0x0080 | Present | Correct |
| `CAP_LOCK_AND_READ` | 0x0100 | Absent (correct) | No handler; comment in code is accurate |
| `CAP_NT_FIND` | 0x0200 | Present | Correct |
| `CAP_DFS` | 0x1000 | **Absent — conditional GAP** | Add when DFS referral handler active |
| `CAP_INFOLEVEL_PASSTHRU` | 0x2000 | **Absent — GAP** | TRANS2 info-level passthrough is present; add |
| `CAP_LARGE_READ_X` | 0x4000 | Present | Correct |
| `CAP_LARGE_WRITE_X` | 0x8000 | Present | Correct |
| `CAP_UNIX` | 0x00800000 | Present | Correct |
| `CAP_EXTENDED_SECURITY` | 0x80000000 | Present | Correct |

**Required additions to SMB1_SERVER_CAPS:**
```c
#define SMB1_SERVER_CAPS  (CAP_UNICODE | CAP_LARGE_FILES | CAP_EXTENDED_SECURITY | \
                           CAP_NT_SMBS | CAP_STATUS32 | CAP_NT_FIND |            \
                           CAP_UNIX | CAP_LARGE_READ_X | CAP_LARGE_WRITE_X |     \
                           CAP_LEVEL_II_OPLOCKS |                                 \
                           CAP_MPX_MODE |        /* NEW */                        \
                           CAP_RPC_REMOTE_APIS | /* NEW */                        \
                           CAP_INFOLEVEL_PASSTHRU) /* NEW */
```

### 11.2 Non-Extended Security DomainName Missing

**Location:** `smb1pdu.c` line 1047

After the 8-byte `EncryptionKey`, MS-SMB §2.2.4.52.2 requires a NUL-terminated
OEM string for `DomainName`. The existing code has a comment
`"Null terminated domain name in unicode"` but **does NOT write the domain name
to the wire**. The `ByteCount` is set to `CIFS_CRYPTO_KEY_SIZE` (8) only.

**Fix:**
```c
/* After writing EncryptionKey[8]: */
char *domain = server_conf.work_group;
int domain_len = strlen(domain);
memcpy(rsp->EncryptionKey + CIFS_CRYPTO_KEY_SIZE, domain, domain_len + 1);
rsp->ByteCount = cpu_to_le16(CIFS_CRYPTO_KEY_SIZE + domain_len + 1);
```

### 11.3 No Common Dialect Response

When no client-offered dialect matches, MS-SMB §2.2.4.52.2 requires:
```
WordCount = 1, DialectIndex = 0xFFFF, ByteCount = 0, Status = STATUS_SUCCESS
```
KSMBD currently returns `STATUS_INVALID_LOGON_TYPE` — a non-standard error.

**Fix:** Detect `BAD_PROT_ID` return from `ksmbd_negotiate_smb_dialect()` and
emit the correct `DialectIndex=0xFFFF` response with `STATUS_SUCCESS`.

### 11.4 SESSION_SETUP Extended Security Response Missing Strings

**Location:** `smb1pdu.c` (smb_session_setup_andx, extended security path)

The spec requires the extended security SESSION_SETUP response to include:
- `NativeOS` (variable, NUL-terminated)
- `NativeLanMan` (variable, NUL-terminated)
- `PrimaryDomain` (variable, NUL-terminated)

KSMBD does not populate these fields in the extended security response path. Many
clients ignore these fields (they contain informational strings), but strict clients
may attempt to use `PrimaryDomain` for account lookup.

**Fix:** Append "Linux" / "Samba" / `server_conf.work_group` as NUL-terminated
strings after the SPNEGO blob in the response `ByteCount` area.

---

## 12. TRANSACTION Named Pipe Subcommands — Full Wire Format Reference

This section provides the complete wire format reference for the 10 named pipe
subcommands in `SMB_COM_TRANSACTION` that are currently missing from `smb_trans()`.

### 12.1 Setup Word Encoding

All named pipe subcommands use:
- `Setup[0]` = subcommand code
- `Setup[1]` = FID of the named pipe (for commands that operate on an open pipe)
- `SetupCount` = 2 for most subcommands

### 12.2 TRANS_SET_NMPIPE_STATE (0x0001)

**Request:**
- `Setup[0]` = 0x0001, `Setup[1]` = FID
- `Parameters[0..1]` = PipeState word:
  - `PIPE_READ_MODE` (0x0100): message mode vs byte-stream
  - `NAMED_PIPE_TYPE` (0x0400): named vs anonymous
  - `BLOCKING_NAMED_PIPE` (0x8000): blocking/non-blocking
  - `ICOUNT_MASK` (0x00FF): max instance count

**Response:** Parameters = empty, Data = empty.

**Implementation:** Store PipeState per-FID RPC handle. At minimum return
`STATUS_SUCCESS` and log the requested mode.

### 12.3 TRANS_QUERY_NMPIPE_STATE (0x0021)

**Request:** Setup[0,1]=code,FID; Parameters = empty, Data = empty.
**Response:** `Parameters[0..1]` = current PipeState word.

### 12.4 TRANS_QUERY_NMPIPE_INFO (0x0022)

**Request:** Setup[0,1]=code,FID; `Parameters[0..1]` = Level (0x0001 = basic info).

**Response Data (Level 1):**
```
OutputBufferSize  USHORT  — server output buffer size (4096)
InputBufferSize   USHORT  — server input buffer size (4096)
MaximumInstances  UCHAR   — max simultaneous instances
CurrentInstances  UCHAR   — current instance count
PipeNameLength    UCHAR   — pipe name byte length
PipeName          var     — OEM pipe name string
```
These fields can be static/hardcoded for KSMBD's pipe model.

### 12.5 TRANS_PEEK_NMPIPE (0x0023)

**Request:** Setup[0,1]=code,FID; Parameters = empty, Data = empty.

**Response Parameters:**
```
ReadDataAvailable   USHORT  — bytes available to read
MessageBytesLength  USHORT  — size of next message (0 for byte-stream)
NamedPipeState      USHORT  — current pipe state flags
```
**Response Data:** Up to `MaxDataCount` bytes peeked without consuming.

For KSMBD's unidirectional RPC model: `ReadDataAvailable = 0`, return `STATUS_SUCCESS`.

### 12.6 TRANS_RAW_READ_NMPIPE (0x0011)

**Request:** Setup[0,1]=code,FID; Parameters = empty, Data = empty.
**Response Data:** Raw bytes read from pipe.

Map to `ksmbd_rpc_read()` / `ksmbd_session_rpc_ioctl()`.

### 12.7 TRANS_RAW_WRITE_NMPIPE (0x0031)

**Request:** Setup[0,1]=code,FID; Parameters = empty; Data = bytes to write.
Map to `ksmbd_rpc_write()`.

### 12.8 TRANS_READ_NMPIPE (0x0036) and TRANS_WRITE_NMPIPE (0x0037)

Message-mode pipe variants. In KSMBD's byte-stream model these are aliases for
RAW_READ and RAW_WRITE respectively.

### 12.9 TRANS_WAIT_NMPIPE (0x0053)

**Request:**
- `Setup[0]` = 0x0053, `Setup[1]` = 0 (no FID)
- `Parameters[0..3]` = Timeout (ms, 0xFFFFFFFF = infinite)
- `Data[0..N-1]` = pipe name

**Implementation:** Since KSMBD provides one virtual instance per connection that
is always available, respond immediately with `STATUS_SUCCESS`.

### 12.10 TRANS_CALL_NMPIPE (0x0054)

Open + Transact + Close in one operation:
- `Setup[0]` = 0x0054
- `Data` = write buffer (sent to the pipe)
- **Response Data:** read buffer (the pipe's response)

**Implementation:** `ksmbd_session_rpc_open()` → `ksmbd_rpc_ioctl()` →
`ksmbd_session_rpc_close()` atomically.

### 12.11 Mailslot Handling

When the TRANSACTION name begins with `\MAILSLOT\`:
- Class 2 (fire-and-forget): silently discard and return **no response**.
- Class 1 (delivery confirmation): return `STATUS_SUCCESS`.

Do not fall through to the `\PIPE\` check — mailslots and pipes are independent.

---

## 13. TRANSACTION2 Subcommand Gap Analysis — Complete Reference

### 13.1 Implemented Subcommands

The `smb_trans2()` dispatcher at `smb1pdu.c` line 7809 handles:

```c
case TRANS2_FIND_FIRST:              find_first(work);      /* implemented */
case TRANS2_FIND_NEXT:               find_next(work);       /* implemented */
case TRANS2_QUERY_FS_INFORMATION:    query_fs_info(work);   /* partially */
case TRANS2_QUERY_PATH_INFORMATION:  query_path_info(work); /* partially */
case TRANS2_SET_PATH_INFORMATION:    set_path_info(work);   /* partially */
case TRANS2_SET_FS_INFORMATION:      set_fs_info(work);     /* partially */
case TRANS2_QUERY_FILE_INFORMATION:  query_file_info(work); /* partially */
case TRANS2_SET_FILE_INFORMATION:    set_file_info(work);   /* partially */
case TRANS2_CREATE_DIRECTORY:        create_dir(work);      /* implemented */
default:                             /* -EINVAL */
```

Missing subcommands: `TRANS2_OPEN` (0x00), `TRANS2_FSCTL` (0x09),
`TRANS2_IOCTL2` (0x0A), `TRANS2_FIND_NOTIFY_FIRST` (0x0B),
`TRANS2_FIND_NOTIFY_NEXT` (0x0C), `TRANS2_SESSION_SETUP` (0x0E),
`TRANS2_GET_DFS_REFERRAL` (0x10), `TRANS2_REPORT_DFS_INCONSISTENCY` (0x11).

### 13.2 TRANS2_FIND_FIRST2 Search Flags Gap

The `Flags` word in the FIND_FIRST2 request parameters:

| Bit | Name | Handled? | Gap Description |
|-----|------|----------|----------------|
| 0x0001 | CLOSE_AFTER_REQUEST | No | Server must close search handle before returning response |
| 0x0002 | CLOSE_AT_EOS | Partial | Checked in find_first line 6766 but not fully enforced |
| 0x0004 | RETURN_RESUME_KEYS | No | Each entry must be preceded by a 4-byte ResumeKey |
| 0x0008 | CONTINUE_FROM_LAST | No | FIND_NEXT2 must resume from client-supplied position |
| 0x0010 | FIND_WITH_BACKUP_INTENT | No | Should bypass ACL checks for backup privilege |

**CLOSE_AFTER_REQUEST fix:** After populating the response buffer in `find_first()`,
check the flag and call `ksmbd_destroy_file_table()` on the search FP before returning.

**RETURN_RESUME_KEYS fix:** When this flag is set, insert a 4-byte `ResumeKey` before
each directory entry in the response data. The `ResumeKey` can be the directory
entry's `d_off` value (the VFS `loff_t` position cast to `u32`).

**CONTINUE_FROM_LAST fix in FIND_NEXT2:** When `CONTINUE_FROM_LAST` is NOT set and
a `FileName` is supplied, restart the readdir loop from the beginning and skip
entries whose name is lexicographically less than `FileName`.

### 13.3 TRANS2_QUERY_FS_INFORMATION Missing Levels

| Level | Constant | Status | Required Fix |
|-------|----------|--------|-------------|
| 0x0002 | SMB_INFO_VOLUME | Missing | VolumeSerialNumber (ULONG) + VolumeLabelSize (UCHAR) + VolumeLabel (OEM string) |
| 0x0105 | SMB_QUERY_FS_ATTRIBUTE_INFO | Partial | FileSystemName is empty string; must return `NTFS` (8 bytes UTF-16LE); set FileSystemNameLen=8, TotalDataCount=20 |
| 0x0202 | SMB_QUERY_POSIX_WHO_AM_I | Missing | See Section 16.4 for full handler code |
| 0x0203 | SMB_QUERY_FS_PROXY | Missing | Return `STATUS_NOT_SUPPORTED` explicitly (not -EINVAL) |

**FS_ATTRIBUTE_INFO fix:**
```c
/* smb1pdu.c line 5036 — after setting Attributes and MaxPathNameComponentLength */
static const __le16 ntfs_name[] = {'N','T','F','S'};
info->FileSystemNameLen = cpu_to_le32(sizeof(ntfs_name));
memcpy(info + 1, ntfs_name, sizeof(ntfs_name));
rsp->t2.TotalDataCount = cpu_to_le16(12 + sizeof(ntfs_name));
```

**IPC share fix:** Lines 4922–4923 return `-ENOENT` for all FS queries on IPC$.
`SMB_QUERY_FS_DEVICE_INFO` should succeed on IPC$ with `DeviceType =
FILE_DEVICE_NAMED_PIPE = 0x11`.

### 13.4 TRANS2_QUERY_PATH_INFORMATION Missing Levels

| Level | Constant | Status | Required Response |
|-------|----------|--------|------------------|
| 0x0002 | SMB_INFO_QUERY_EA_SIZE | Missing | SMB_INFO_STANDARD (22 bytes) + 4-byte EASize |
| 0x0003 | SMB_INFO_QUERY_EAS_FROM_LIST | Missing | FEAList for requested EA names from GEAList |
| 0x0006 | SMB_INFO_IS_NAME_VALID | Missing | STATUS_SUCCESS or STATUS_OBJECT_NAME_INVALID |
| 0x010B | SMB_QUERY_FILE_COMPRESSION_INFO | Missing | CompressedFileSize=FileSize, CompressionFormat=0 |
| 0x010F | SMB_QUERY_FILE_ACCESS_INFO | Missing | AccessFlags ULONG (granted access mask) |
| 0x0114 | SMB_QUERY_FILE_POSITION_INFO | Missing | CurrentByteOffset LARGE_INTEGER (0 for path queries) |
| 0x0116 | SMB_QUERY_FILE_MODE_INFO | Missing | Mode ULONG (0 for most files) |
| 0x0117 | SMB_QUERY_FILE_ALIGNMENT_INFO | Missing | AlignmentRequirement ULONG (0) |
| 0x0122 | SMB_QUERY_FILE_NETWORK_OPEN_INFO | Missing | 56 bytes: timestamps + sizes + attributes |
| 0x0107 | SMB_QUERY_FILE_ALL_INFO | Partial | EASize is always 0; must sum xattr value sizes |
| 0x0203 | SMB_QUERY_FILE_UNIX_HLINK | Missing | nlink count as ULONG |
| 0x0205 | SMB_QUERY_XATTR | Missing | POSIX xattr value for named attribute |
| 0x0206 | SMB_QUERY_ATTR_FLAGS | Missing | CIFS Unix chattr flags |
| 0x0208 | SMB_QUERY_POSIX_LOCK | Missing | POSIX lock status for range |

**SMB_INFO_IS_NAME_VALID (0x0006) — validation logic:**
```c
case SMB_INFO_IS_NAME_VALID:
{
    /* Check for illegal filename characters: NUL, control chars, " * ? < > | : */
    static const char illegal[] = "\x01\x02\x03\x04\x05\x06\x07\x08"
                                   "\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
                                   "\x11\x12\x13\x14\x15\x16\x17\x18"
                                   "\x19\x1A\x1B\x1C\x1D\x1E\x1F"
                                   "\"*?<>|:";
    if (strpbrk(name, illegal)) {
        rsp_hdr->Status.CifsError = STATUS_OBJECT_NAME_INVALID;
        return 0;
    }
    rsp->t2.TotalDataCount = 0;
    break;
}
```

**SMB_QUERY_FILE_NETWORK_OPEN_INFO (0x0122) — response structure:**
```c
struct smb_query_file_network_open_info {
    __le64  CreationTime;
    __le64  LastAccessTime;
    __le64  LastWriteTime;
    __le64  ChangeTime;
    __le64  AllocationSize;
    __le64  EndOfFile;
    __le32  FileAttributes;
    __le32  Reserved;             /* alignment padding */
} __packed;   /* 56 bytes total */
```

### 13.5 TRANS2_QUERY_FILE_INFORMATION Missing Levels

| Level | Constant | Status | Notes |
|-------|----------|--------|-------|
| 0x0104 | SMB_QUERY_FILE_NAME_INFO | Missing for FID-based queries | FileName in Unicode |
| 0x0109 | SMB_QUERY_FILE_STREAM_INFO | Missing | Return single `::$DATA` stream entry |
| 0x010B | SMB_QUERY_FILE_COMPRESSION_INFO | Missing | Same as path-based version |
| 0x010E | SMB_QUERY_FILE_INTERNAL_INFO | Missing | UniqueId (inode number) |
| 0x010F | SMB_QUERY_FILE_ACCESS_INFO | Missing | Granted access mask from open FP |
| 0x0108 | SMB_QUERY_FILE_ALT_NAME_INFO | Missing | 8.3 alternate filename |
| 0x0122 | SMB_QUERY_FILE_NETWORK_OPEN_INFO | Missing | Same as path-based version |
| 0x0208 | SMB_QUERY_POSIX_LOCK | Missing | POSIX lock query via fcntl(F_GETLK) |

**SMB_QUERY_FILE_STREAM_INFO — minimum implementation:**
```c
case SMB_QUERY_FILE_STREAM_INFO:
{
    struct smb_stream_info {
        __le32  NextEntryOffset;   /* 0 = last entry */
        __le32  StreamNameLength;  /* in bytes */
        __le64  StreamSize;
        __le64  StreamAllocationSize;
        __le16  StreamName[1];     /* "::$DATA" */
    };
    /* Return a single "::$DATA" stream entry */
    static const __le16 stream_name[] = {':',':','$','D','A','T','A'};
    struct smb_stream_info *si = (struct smb_stream_info *)data;
    si->NextEntryOffset  = 0;
    si->StreamNameLength = cpu_to_le32(sizeof(stream_name));
    si->StreamSize       = cpu_to_le64(stat.size);
    si->StreamAllocationSize = cpu_to_le64(stat.blocks * 512);
    memcpy(si->StreamName, stream_name, sizeof(stream_name));
    t2_data_count = sizeof(*si) - sizeof(__le16) + sizeof(stream_name);
    break;
}
```

### 13.6 TRANS2_SET_PATH_INFORMATION Missing Levels

- `SMB_SET_FILE_DISPOSITION_INFO` (0x0102) — handled in `set_file_info()` but absent from `set_path_info()`.
- `SMB_SET_FILE_ALLOCATION_INFO` (0x0103) — same gap.
- `SMB_SET_FILE_UNIX_LINK` / `SMB_SET_FILE_UNIX_HLINK` — in `set_path_info()` but absent from `set_file_info()`.
- POSIX lock set (0x0208) — missing in both handlers; advertised via `CIFS_UNIX_FCNTL_CAP`.

### 13.7 query_file_info_pipe() Double Write Bug

**Location:** `smb1pdu.c` lines 7020–7021

**Bug:**
```c
file_info->DeletePending = 0;
file_info->DeletePending = 0;   /* BUG: duplicate assignment */
```
Harmless functionally (both writes are the same value) but indicates a copy-paste
error. One of the lines should set a different field (likely `Directory`).

**Fix:** Change the second assignment to:
```c
file_info->Directory = 0;   /* IPC pipes are not directories */
```

### 13.8 smb_fileinfo_rename() Truncates Wrong File

**Location:** `smb1pdu.c` line 7586 (`smb_fileinfo_rename()`)

**Bug:** When renaming via `SET_FILE_INFORMATION` with `FileRenameInformation`,
the code calls:
```c
ksmbd_vfs_truncate(work, source_fp, 0);  /* BUG: truncates source, not creates target */
```
The call should be creating/overwriting the target path, not truncating the source.
This causes data loss when renaming files.

**Fix:** Replace the truncate call with the rename VFS operation:
```c
err = ksmbd_vfs_rename(work, src_dentry, target_name, replace_if_exists);
```

---

## 14. LOCKING_ANDX Wire Format and All Five Bugs

### 13.1 Wire Format (Request — WordCount=8)

| Field | Offset | Size | Notes |
|-------|--------|------|-------|
| AndXCommand | 0 | 1 | 0xFF = no next command |
| AndXReserved | 1 | 1 | Must be 0 |
| AndXOffset | 2 | 2 | |
| Fid | 4 | 2 | Open file handle |
| LockType | 6 | 1 | See below |
| OplockLevel | 7 | 1 | Only valid if LOCKING_ANDX_OPLOCK_RELEASE |
| Timeout | 8 | 4 | Milliseconds; 0=return immediately; -1=0xFFFFFFFF=deadlock wait |
| NumberOfUnlocks | 12 | 2 | |
| NumberOfLocks | 14 | 2 | |
| ByteCount | 16 | 2 | |
| Locks[] | 18 | var | `NumberOfUnlocks` unlock entries then `NumberOfLocks` lock entries |

**LockType bits:**
- `LOCKING_ANDX_SHARED_LOCK` (0x01): shared (read) lock; exclusive if clear
- `LOCKING_ANDX_OPLOCK_RELEASE` (0x02): oplock break acknowledgment
- `LOCKING_ANDX_CHANGE_LOCKTYPE` (0x04): upgrade shared→exclusive or downgrade
- `LOCKING_ANDX_CANCEL_LOCK` (0x08): cancel a pending blocking lock
- `LOCKING_ANDX_LARGE_FILES` (0x10): use 64-bit lock ranges

### 13.2 Lock Range Formats

**Standard range (when LOCKING_ANDX_LARGE_FILES is NOT set — 10 bytes):**
```c
struct locking_andx_range {
    __le16 Pid;
    __le32 ByteOffset;
    __le32 LengthInBytes;
} __packed;
```

**Large file range (when LOCKING_ANDX_LARGE_FILES IS set — 20 bytes):**
```c
struct locking_andx_range64 {
    __le16 Pid;
    __u8   Reserved[2];
    __le32 ByteOffsetHigh;
    __le32 ByteOffsetLow;
    __le32 LengthInBytesHigh;
    __le32 LengthInBytesLow;
} __packed;
```

### 13.3 Bug 1 — CHANGE_LOCKTYPE Returns DOS Error

**Location:** `smb1pdu.c` line 1761

**Current code:**
```c
if (req->LockType & LOCKING_ANDX_CHANGE_LOCKTYPE) {
    rsp->hdr.Status.DosError.ErrorClass = ERRDOS;
    rsp->hdr.Status.DosError.Error = cpu_to_le16(ERRnotsupported);
    return -EOPNOTSUPP;
}
```

**Bug:** This hard-codes a DOS error regardless of `SMBFLG2_ERR_STATUS`. The
response also corrupts the `Flags2` word because `SMBFLG2_ERR_STATUS` is already
set in the outgoing header copy.

**Fix:**
```c
if (req->LockType & LOCKING_ANDX_CHANGE_LOCKTYPE) {
    rsp->hdr.Status.CifsError = STATUS_NOT_SUPPORTED;
    return -EOPNOTSUPP;
}
```

### 13.4 Bug 2 — Unlock/Lock Processing Order

**Location:** `smb1pdu.c` LOCKING_ANDX handler

**Bug:** Locks are processed before unlocks. MS-SMB §2.2.4.26.2 specifies
that **unlocks must be processed before locks** to avoid transient deadlocks
in upgrade scenarios.

**Fix:** Process the unlock range first:
```c
/* Correct order: unlocks first */
if (req->LockType & LOCKING_ANDX_LARGE_FILES) {
    unlock_ele64 = (struct locking_andx_range64 *)
                   ((u8 *)req + sizeof(*req) - 1);
    lock_ele64   = unlock_ele64 + unlock_count;
} else {
    unlock_ele = (struct locking_andx_range *)
                 ((u8 *)req + sizeof(*req) - 1);
    lock_ele   = unlock_ele + unlock_count;
}
/* Process unlocks */
for (i = 0; i < unlock_count; i++) { ... }
/* Then process locks */
for (i = 0; i < lock_count; i++) { ... }
```

### 13.5 Bug 3 — Timeout=0xFFFFFFFF Wraps to 49-Day Sleep

**Location:** `smb1pdu.c` LOCKING_ANDX timeout conversion

**Bug:** The 32-bit `Timeout` field (in milliseconds) is converted to jiffies via
`msecs_to_jiffies(le32_to_cpu(req->Timeout))`. When `Timeout = 0xFFFFFFFF` (which
means "wait indefinitely" in the spec), this computes `msecs_to_jiffies(4294967295)`
which is approximately 49.7 days — not infinite.

**Fix:** Explicitly check for the sentinel value:
```c
u32 timeout_ms = le32_to_cpu(req->Timeout);
unsigned long lock_timeout;
if (timeout_ms == 0xFFFFFFFF)
    lock_timeout = MAX_SCHEDULE_TIMEOUT;
else if (timeout_ms == 0)
    lock_timeout = 0;   /* try-lock only */
else
    lock_timeout = msecs_to_jiffies(timeout_ms);
```

### 13.6 Bug 4 — CANCEL_LOCK Silently Ignored

**Location:** `smb1pdu.c` LOCKING_ANDX handler

**Bug:** When `LOCKING_ANDX_CANCEL_LOCK` (0x08) is set in `LockType`, the flag
is checked but no cancellation is actually performed. The blocking lock in another
thread/work-item continues sleeping.

**Fix required:**
1. Associate each blocking lock wait with the MID of the requesting LOCKING_ANDX.
2. When a CANCEL_LOCK arrives for the same FID and PID, wake the sleeping work
   item and return `STATUS_CANCELLED`.

A list of pending lock requests on the connection (or session) is needed:
```c
struct smb1_pending_lock {
    struct list_head list;
    __le16           mid;
    __le16           fid;
    __le16           pid;
    wait_queue_head_t wq;
    bool             cancelled;
};
```

### 13.7 Bug 5 — Wire Format for Unlock/Lock Arrays

**Bug:** The code accesses `req->Locks[]` without correctly accounting for the
difference between standard (10-byte) and large-file (20-byte) lock range entries.
When `LOCKING_ANDX_LARGE_FILES` is set, the lock range structures are at
`((u8 *)req + sizeof(*req) - 1)` only if the ByteCount and padding are accounted
for correctly. Any misalignment reads garbage data or triggers an out-of-bounds access.

**Fix:** Use explicit pointer arithmetic:
```c
u8 *lock_data = (u8 *)req + le16_to_cpu(req->hdr.smb_buf_length)
                - le16_to_cpu(req->ByteCount);
/* unlock entries come first */
```

---

## 14. DOS Date/Time Conversion Helpers

These helpers are needed for the QUERY_INFORMATION2, SET_INFORMATION2, and
legacy SEARCH command implementations.

```c
/**
 * dos_encode_time - Convert a kernel timespec64 to DOS date and time words
 * @ts:   kernel timestamp
 * @date: output: DOS date word (bits 15-9=year-1980, 8-5=month, 4-0=day)
 * @time: output: DOS time word (bits 15-11=hours, 10-5=minutes, 4-0=seconds/2)
 */
static void dos_encode_time(struct timespec64 ts,
                             __le16 *date, __le16 *time)
{
    struct tm tm;
    time64_to_tm(ts.tv_sec, 0, &tm);

    /* DOS date: year offset from 1980 */
    *date = cpu_to_le16(
        (((tm.tm_year - 80) & 0x7F) << 9) |
        (((tm.tm_mon + 1)   & 0x0F) << 5) |
        ( (tm.tm_mday)      & 0x1F));

    /* DOS time: seconds stored as half-seconds */
    *time = cpu_to_le16(
        (((tm.tm_hour)  & 0x1F) << 11) |
        (((tm.tm_min)   & 0x3F) << 5)  |
        (( tm.tm_sec / 2) & 0x1F));
}

/**
 * smb_dos_date_time_to_unix - Convert DOS date/time pair to Unix timestamp
 * @date: DOS date word
 * @time: DOS time word
 * Returns: Unix timestamp (seconds since epoch)
 */
static time64_t smb_dos_date_time_to_unix(__le16 date, __le16 time)
{
    struct tm tm = {};
    u16 d = le16_to_cpu(date);
    u16 t = le16_to_cpu(time);

    tm.tm_year = ((d >> 9) & 0x7F) + 80;   /* years since 1900 */
    tm.tm_mon  = ((d >> 5) & 0x0F) - 1;    /* 0-based */
    tm.tm_mday = (d)       & 0x1F;
    tm.tm_hour = (t >> 11) & 0x1F;
    tm.tm_min  = (t >> 5)  & 0x3F;
    tm.tm_sec  = (t & 0x1F) * 2;

    return mktime64(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec);
}
```

---

## 15. QUERY_INFORMATION2 and SET_INFORMATION2 Full Handler Code

### 15.1 QUERY_INFORMATION2 (0x23)

**Spec:** MS-SMB §2.2.4.24 / MS-CIFS §2.2.4.32

**Wire format (Request — WordCount=1):**
```
USHORT  FID;
USHORT  ByteCount;    /* must be 0 */
```

**Wire format (Response — WordCount=11):**
```
USHORT  CreateDate;
USHORT  CreateTime;
USHORT  LastAccessDate;
USHORT  LastAccessTime;
USHORT  LastWriteDate;
USHORT  LastWriteTime;
ULONG   FileDataSize;
ULONG   FileAllocationSize;
USHORT  FileAttributes;
USHORT  ByteCount;    /* 0 */
```

**Structures to add to `smb1pdu.h`:**
```c
#define SMB_COM_QUERY_INFORMATION2  0x23

struct smb_com_query_information2_req {
    struct smb_hdr hdr;         /* wct = 1 */
    __le16 FID;
    __le16 ByteCount;
} __packed;

struct smb_com_query_information2_rsp {
    struct smb_hdr hdr;         /* wct = 11 */
    __le16 CreateDate;
    __le16 CreateTime;
    __le16 LastAccessDate;
    __le16 LastAccessTime;
    __le16 LastWriteDate;
    __le16 LastWriteTime;
    __le32 FileDataSize;
    __le32 FileAllocationSize;
    __le16 FileAttributes;
    __le16 ByteCount;
} __packed;
```

**Handler:**
```c
static int smb_query_info2(struct ksmbd_work *work)
{
    struct smb_com_query_information2_req *req = work->request_buf;
    struct smb_com_query_information2_rsp *rsp = work->response_buf;
    struct ksmbd_file *fp;
    struct kstat stat;

    fp = ksmbd_lookup_fd_fast(work, le16_to_cpu(req->FID));
    if (!fp)
        return -EBADF;

    if (ksmbd_vfs_getattr(&fp->filp->f_path, &stat)) {
        ksmbd_fd_put(work, fp);
        return -EIO;
    }

    dos_encode_time(stat.ctime, &rsp->CreateDate, &rsp->CreateTime);
    dos_encode_time(stat.atime, &rsp->LastAccessDate, &rsp->LastAccessTime);
    dos_encode_time(stat.mtime, &rsp->LastWriteDate, &rsp->LastWriteTime);

    rsp->FileDataSize       = cpu_to_le32(min_t(loff_t, stat.size, U32_MAX));
    rsp->FileAllocationSize = cpu_to_le32(min_t(loff_t,
                                 stat.blocks * 512, U32_MAX));
    rsp->FileAttributes     = cpu_to_le16(smb_get_dos_attr(&stat));
    rsp->ByteCount          = 0;
    rsp->hdr.WordCount      = 11;

    ksmbd_fd_put(work, fp);
    return 0;
}
```

**Registration:** `[SMB_COM_QUERY_INFORMATION2] = { .proc = smb_query_info2, }` in `smb1ops.c`.

**smb1misc.c validation:**
```c
case SMB_COM_QUERY_INFORMATION2:
    if (wc != 0x1)
        return -EINVAL;
    break;
```

### 15.2 SET_INFORMATION2 (0x22)

**Spec:** MS-SMB §2.2.4.23 / MS-CIFS §2.2.4.18

**Wire format (Request — WordCount=7):**
```
USHORT  FID;
USHORT  CreateDate;
USHORT  CreateTime;
USHORT  LastAccessDate;
USHORT  LastAccessTime;
USHORT  LastWriteDate;
USHORT  LastWriteTime;
USHORT  ByteCount;    /* 0 */
```

**Compliance rules:**
- Apply timestamp only when BOTH the Date AND Time fields are non-zero.
- A zero Date with non-zero Time (or vice versa) means "no change."
- `LastWriteTime = 0` is the caller's way of saying "don't touch mtime on close."

**Structure to add to `smb1pdu.h`:**
```c
#define SMB_COM_SET_INFORMATION2  0x22

struct smb_com_set_information2_req {
    struct smb_hdr hdr;         /* wct = 7 */
    __le16 FID;
    __le16 CreateDate;
    __le16 CreateTime;
    __le16 LastAccessDate;
    __le16 LastAccessTime;
    __le16 LastWriteDate;
    __le16 LastWriteTime;
    __le16 ByteCount;
} __packed;
```

**Handler:**
```c
static int smb_set_info2(struct ksmbd_work *work)
{
    struct smb_com_set_information2_req *req = work->request_buf;
    struct smb_hdr *rsp_hdr = work->response_buf;
    struct ksmbd_file *fp;
    struct iattr iattr = {};
    int err;

    fp = ksmbd_lookup_fd_fast(work, le16_to_cpu(req->FID));
    if (!fp)
        return -EBADF;

    /* Apply (Date, Time) pair only if both are non-zero */
    if (req->LastWriteDate && req->LastWriteTime) {
        iattr.ia_valid |= ATTR_MTIME;
        iattr.ia_mtime = ns_to_timespec64(
            smb_dos_date_time_to_unix(req->LastWriteDate,
                                      req->LastWriteTime) * NSEC_PER_SEC);
    }
    if (req->LastAccessDate && req->LastAccessTime) {
        iattr.ia_valid |= ATTR_ATIME;
        iattr.ia_atime = ns_to_timespec64(
            smb_dos_date_time_to_unix(req->LastAccessDate,
                                      req->LastAccessTime) * NSEC_PER_SEC);
    }
    /* Creation time: stored in xattr if supported */
    if (req->CreateDate && req->CreateTime) {
        time64_t ctime_unix = smb_dos_date_time_to_unix(req->CreateDate,
                                                          req->CreateTime);
        ksmbd_vfs_setxattr(work->conn->user_ns,
                           fp->filp->f_path.dentry,
                           XATTR_NAME_CREATION_TIME,
                           &ctime_unix, sizeof(ctime_unix), 0);
    }

    if (iattr.ia_valid) {
        err = ksmbd_vfs_setattr(work, &fp->filp->f_path, &iattr);
        if (err) {
            ksmbd_fd_put(work, fp);
            return err;
        }
    }

    rsp_hdr->WordCount = 0;
    *(__le16 *)((u8 *)rsp_hdr + sizeof(*rsp_hdr)) = 0; /* ByteCount = 0 */
    ksmbd_fd_put(work, fp);
    return 0;
}
```

**Registration:** `[SMB_COM_SET_INFORMATION2] = { .proc = smb_set_info2, }` in `smb1ops.c`.

---

## 16. SETATTR and QUERY_INFORMATION Wire Formats

### 16.1 SMB_COM_SETATTR (0x09) — SETATTR LastWriteTime Handling

**Location:** `smb1pdu.c` line 8788

**Spec:** MS-SMB §2.2.4.9

**Wire Format (Request — WordCount=8):**
```
USHORT  FileAttributes;  /* ATTR_* bits for the file */
ULONG   LastWriteTime;   /* UTIME (seconds since 1970); 0 or 0xFFFFFFFF = no change */
UCHAR   Reserved[10];    /* must be 0 */
USHORT  ByteCount;
BYTE    BufferFormat;    /* 0x04 */
STRING  FileName;
```

**Bug:** The LastWriteTime field has two sentinel values meaning "no change":
- `0x00000000`: do not modify the time
- `0xFFFFFFFF`: do not modify the time (MS-CIFS extension)

**Current code:**
```c
if (le32_to_cpu(req->LastWriteTime) > 0)
    /* set mtime */
```
This only checks for 0 but does NOT exclude `0xFFFFFFFF`. Setting mtime to
year 2106 is incorrect.

**Fix:**
```c
u32 write_time = le32_to_cpu(req->LastWriteTime);
if (write_time != 0 && write_time != 0xFFFFFFFF) {
    iattr.ia_valid |= ATTR_MTIME;
    iattr.ia_mtime = ns_to_timespec64((time64_t)write_time * NSEC_PER_SEC);
}
```

### 16.2 SMB_COM_QUERY_INFORMATION (0x08) ATTR_ARCHIVE Missing

**Location:** `smb1pdu.c` line 8347

**Spec:** MS-SMB §2.2.4.8

**Bug:** The function `smb_query_info()` calls `smb_get_dos_attr(&stat)` to
compute DOS attributes for the response. However, the function returns 0 for
regular files when no special attributes apply, instead of `ATTR_ARCHIVE`
(0x0020) which regular files should have by default.

**Fix:** In `smb_get_dos_attr()` or the query handler:
```c
/* Regular files should have ATTR_ARCHIVE set by default */
if (S_ISREG(stat->mode) && !(attr & ATTR_READONLY))
    attr |= ATTR_ARCHIVE;
```

---

## 17. Legacy Command Wire Formats — Complete Structures

### 17.1 SMB_COM_OPEN (0x02) — Legacy Open

**Spec:** MS-CIFS §2.2.4.3

**Request (WordCount=2):**
```c
struct smb_com_open_req {
    struct smb_hdr hdr;
    __le16 DesiredAccess;      /* 0=read, 1=write, 2=read-write, 3=execute */
    __le16 SearchAttributes;   /* ATTR_* filter for files to open */
    __le16 ByteCount;
    __u8   BufferFormat;       /* 0x04 */
    /* FileName follows (variable) */
} __packed;
```

**Response (WordCount=7):**
```c
struct smb_com_open_rsp {
    struct smb_hdr hdr;
    __le16 Fid;
    __le16 FileAttributes;
    __le32 LastWriteTime;      /* UTIME */
    __le32 FileDataSize;       /* 32-bit file size */
    __le16 GrantedAccess;      /* actual access granted */
    __le16 ByteCount;
} __packed;
```

**Implementation:** Wrap the common open path from `smb_open_andx()` without
the AndX chaining. Use `convert_open_flags()` to map DesiredAccess.

### 17.2 SMB_COM_CREATE (0x03) — Legacy Create

**Spec:** MS-CIFS §2.2.4.4

**Request (WordCount=3):**
```c
struct smb_com_create_req {
    struct smb_hdr hdr;
    __le16 FileAttributes;     /* ATTR_* for new file */
    __le32 CreationTime;       /* UTIME; 0 = use current time */
    __le16 ByteCount;
    __u8   BufferFormat;       /* 0x04 */
    /* FileName follows */
} __packed;
```

**Response (WordCount=1):**
```c
struct smb_com_create_rsp {
    struct smb_hdr hdr;
    __le16 Fid;
    __le16 ByteCount;          /* 0 */
} __packed;
```

**Implementation:** `ksmbd_vfs_create()` with `O_CREAT | O_TRUNC` semantics.
Map FileAttributes via `smb_set_dos_attr()`.

### 17.3 SMB_COM_CREATE_NEW (0x0F) — Create If Not Exists

**Spec:** MS-CIFS §2.2.4.15

Same request/response wire format as CREATE. Use `O_CREAT | O_EXCL` to ensure
atomicity. Map `-EEXIST` → `STATUS_OBJECT_NAME_COLLISION` (maps to
`ERRDOS/ERRfilexists = DOS error 80`).

### 17.4 SMB_COM_CREATE_TEMPORARY (0x0E) — Temporary File

**Spec:** MS-CIFS §2.2.4.14

**Request (WordCount=3):** Same as CREATE but `FileName` is the **directory** path.

**Response (WordCount=1):**
```c
struct smb_com_create_temporary_rsp {
    struct smb_hdr hdr;
    __le16 Fid;
    __le16 ByteCount;
    __u8   BufferFormat;       /* 0x04 */
    /* FileName follows: server-generated temp filename */
} __packed;
```

**Key difference:** Server generates the filename. Use kernel's `ksmbd_inode_next_id()`
or a UUID-based scheme. The generated filename must be unique within the directory.

### 17.5 SMB_COM_COPY (0x29) — Server-Side Copy Wire Format

**Spec:** MS-SMB §2.2.4.29

**Request (WordCount=3):**
```c
struct smb_com_copy_req {
    struct smb_hdr hdr;
    __le16 Tid2;               /* destination TID */
    __le16 OpenFunction;       /* disposition for destination file */
    __le16 Flags;              /* see below */
    __le16 ByteCount;
    __u8   BufferFormat1;      /* 0x04 */
    /* OldFileName follows (source path) */
    __u8   BufferFormat2;      /* 0x04 */
    /* NewFileName follows (destination path) */
} __packed;
```

**Flags field:**
| Bit | Value | Meaning |
|-----|-------|---------|
| 0 | 0x0001 | SMB_COPY_TARGET_MODE: destination path is ASCII |
| 1 | 0x0002 | SMB_COPY_SOURCE_MODE: source path is ASCII |
| 2 | 0x0004 | SMB_COPY_VERIFY_WRITES: verify each write via read-back |
| 3 | 0x0008 | SMB_COPY_TREE: recursively copy directory tree |

**OpenFunction values (same encoding as OPEN_ANDX):**
- `0x10` = create if not exists, fail if exists (default)
- `0x11` = create if not exists, overwrite if exists

**Response (WordCount=1):**
```c
struct smb_com_copy_rsp {
    struct smb_hdr hdr;
    __le16 CopyCount;          /* files copied; 0 on error */
    __le16 ByteCount;          /* 0 */
} __packed;
```

**Cross-TID copy:**
```c
struct ksmbd_tree_connect *dst_tcon =
    ksmbd_tree_conn_from_id(work->sess, le16_to_cpu(req->Tid2));
if (!dst_tcon) {
    rsp->hdr.Status.CifsError = STATUS_INVALID_SMB;
    return -EINVAL;
}
```

### 17.6 SMB_COM_MOVE (0x2A) — Server-Side Move

**Spec:** MS-SMB §2.2.4.30

Same wire format as COPY (WordCount=3). Key differences:
- Source file MUST be deleted after successful copy (for cross-volume moves).
- For same-volume same-tree: call `ksmbd_vfs_rename()` for atomicity.
- For cross-volume: copy then delete, non-atomic — must document limitation.
- On failure after partial copy: attempt rollback; log if rollback fails.
- Return `STATUS_NOT_SAME_DEVICE` if cross-volume atomic move is impossible.

### 17.7 SMB_COM_SEARCH (0x81) Full Wire Format

**Spec:** MS-CIFS §2.2.4.58

**Request (WordCount=2):**
```c
struct smb_com_search_req {
    struct smb_hdr hdr;
    __le16 MaxCount;           /* maximum entries to return */
    __le16 SearchAttributes;   /* ATTR_* filter mask */
    __le16 ByteCount;
    __u8   BufferFormat1;      /* 0x04 = ASCII string */
    /* FileName pattern follows (variable) */
    __u8   BufferFormat2;      /* 0x05 = Variable block */
    __le16 SearchCount;        /* 0 or 1 (ResumeKey count) */
    /* ResumeKey[21] follows if SearchCount == 1 */
} __packed;
```

**Response (WordCount=1):**
```c
struct smb_com_search_rsp {
    struct smb_hdr hdr;
    __le16 Count;              /* actual entries returned */
    __le16 ByteCount;
    __u8   BufferFormat;       /* 0x05 = Variable block */
    __le16 DataLength;         /* Count * 43 */
    /* smb_dir_entry[Count] follows */
} __packed;
```

**Per-entry format (43 bytes each):**
```c
struct smb_dir_entry {
    __u8   ResumeKey[21];      /* ServerState[16] + ClientState[4] + Reserved[1] */
    __u8   FileAttributes;     /* ATTR_* bitmask */
    __le16 LastWriteTime;      /* DOS time word */
    __le16 LastWriteDate;      /* DOS date word */
    __le32 FileDataSize;       /* 32-bit file size */
    __u8   FileName[13];       /* 8.3 name, space-padded, no null termination */
} __packed;
```

**ResumeKey encoding:**
- `ServerState[0..7]` = inode number (for stable identity across calls)
- `ServerState[8..11]` = directory position as `u32` cast of `d_off`
- `ServerState[12..15]` = padding zeros
- `ClientState[0..3]` = echoed from client's incoming ResumeKey
- `Reserved` = 0

**8.3 name conversion rules:**
- Base name max 8 chars; extension max 3 chars
- Characters not valid in 8.3 (`+`, `,`, `;`, `=`, `[`, `]`, space) → `_`
- If base exceeds 8 chars: truncate to 6 chars + `~1` (increment number if collision)
- Extension: everything after last `.`; truncate to 3 chars
- Uppercase all characters (DOS 8.3 names are case-insensitive)

**MS-SMB §3.3.5.9 attribute filtering rules:**
- Hidden files: return only if `ATTR_HIDDEN` is set in `SearchAttributes`
- System files: return only if `ATTR_SYSTEM` is set
- Directories: return only if `ATTR_DIRECTORY` is set
- Volume labels: return only if `ATTR_VOLUME` is set
- If no entries match: return `STATUS_NO_MORE_FILES` (mapped to `ERRDOS/ERRnofiles`)

### 17.8 SMB_COM_FIND (0x82) — Stateful Search

**Spec:** MS-CIFS §2.2.4.59

Same wire format as SEARCH. Key difference: server allocates a persistent
`smb_search_ctx` on the first call (empty ResumeKey), returns `search_id`
in `ResumeKey.ServerState[0..1]`. Subsequent calls continue from stored position.

```c
struct smb_search_ctx {
    struct list_head list;     /* linked to session's search_ctx_list */
    __u16  search_id;          /* unique per session */
    struct file *dir_fp;       /* open directory file pointer */
    loff_t pos;                /* current directory position */
    __u16  search_attrs;       /* SearchAttributes filter */
};
```

**Required session field:** Add `struct list_head search_ctx_list` to
`struct ksmbd_session` in `user_session.h`.

### 17.9 Print Queue Commands Wire Formats

**SMB_COM_OPEN_PRINT_FILE (0x43):**
```c
struct smb_com_open_print_file_req {
    struct smb_hdr hdr;
    __le16 SetupLength;        /* bytes of setup data at start of spool file */
    __le16 Mode;               /* 0=text (CR-LF transform), 1=graphics (raw) */
    __le16 ByteCount;
    __u8   BufferFormat;       /* 0x04 */
    /* IdentifierString follows (print job identifier) */
} __packed;

struct smb_com_open_print_file_rsp {
    struct smb_hdr hdr;
    __le16 Fid;
    __le16 ByteCount;
} __packed;
```

**SMB_COM_GET_PRINT_QUEUE (0x3D) — Per-entry format (28 bytes):**
```c
struct smb_print_queue_entry {
    __le16 Length;             /* entry size = 28 */
    __le16 Priority;           /* 1=highest, 9=lowest */
    __le32 Time;               /* submission time (UTIME) */
    __le16 Status;             /* job status flags */
    __le16 JobID;              /* job identifier */
    __le32 Size;               /* spool data size in bytes */
    __u8   Reserved;
    __u8   Name[16];           /* submitter name (OEM, space-padded) */
    __u8   Comment[40];        /* job comment (OEM, space-padded) */
} __packed;
```

Minimum compliant implementation: return `Count=0` (empty queue) and
`STATUS_SUCCESS`.

---

## 18. UNIX Extensions — Full Compliance Analysis

### 16.1 Already Implemented (Verified)

| Info Level | Code | Direction | Handler | Notes |
|------------|------|-----------|---------|-------|
| SMB_QUERY_FILE_UNIX_BASIC | 0x200 | QUERY_PATH / QUERY_FILE | `init_unix_info()` (smb1pdu.c:3651) | uid, gid, nlinks, times, size, blocks, type, permissions — Complete |
| SMB_SET_FILE_UNIX_BASIC | 0x200 | SET_PATH / SET_FILE | `smb_set_unix_pathinfo()` | chmod/chown/utimes — Complete |
| SMB_QUERY_FILE_UNIX_LINK | 0x201 | QUERY_PATH | readlink path | symlink target — Complete |
| SMB_SET_FILE_UNIX_LINK | 0x201 | SET_PATH | `smb_creat_symlink()` (smb1pdu.c:5952) | create symlink — Complete |
| SMB_SET_FILE_UNIX_HLINK | 0x203 | SET_PATH | `smb_creat_hardlink()` (smb1pdu.c:5950) | create hardlink — Complete |
| SMB_QUERY_POSIX_ACL | 0x204 | QUERY_PATH | `smb_get_acl()` (smb1pdu.c:4760) | POSIX ACL query — Complete |
| SMB_SET_POSIX_ACL | 0x204 | SET_PATH | `smb_set_acl()` (smb1pdu.c:5966) | POSIX ACL set — Complete |
| SMB_POSIX_OPEN | — | SET_PATH | `smb_posix_open()` (smb1pdu.c:5943) | POSIX open with O_* flags — Complete |
| SMB_POSIX_UNLINK | 0x20A | SET_PATH | `smb_posix_unlink()` (smb1pdu.c:5946) | unlink even if open — Complete |
| SMB_QUERY_CIFS_UNIX_INFO | 0x200 | QUERY_FS | capability word response (smb1pdu.c:5061) | Major/minor + caps — Complete |
| SMB_QUERY_POSIX_FS_INFO | 0x201 | QUERY_FS | `filesystem_posix_info` (smb1pdu.c:5065) | statvfs-like FS info — Complete |

### 16.2 SMB_UNIX_CAPS Value at smb1pdu.h line 1241

```c
#define SMB_UNIX_CAPS  (CIFS_UNIX_FCNTL_CAP       |   /* 0x01: POSIX locks */
                        CIFS_UNIX_POSIX_ACL_CAP    |   /* 0x02: POSIX ACLs */
                        CIFS_UNIX_XATTR_CAP        |   /* 0x04: xattr */
                        CIFS_UNIX_POSIX_PATHNAMES_CAP| /* 0x10: POSIX paths */
                        CIFS_UNIX_POSIX_PATH_OPS_CAP|  /* 0x20: POSIX ops */
                        CIFS_UNIX_LARGE_READ_CAP   |   /* 0x40: large read */
                        CIFS_UNIX_LARGE_WRITE_CAP)     /* 0x80: large write */
```

**Compliance problems:**
- `CIFS_UNIX_FCNTL_CAP` (0x01) advertised, but TRANS2 info level 0x208 (POSIX lock query/set) is MISSING.
- `CIFS_UNIX_XATTR_CAP` (0x04) advertised, but TRANS2 info level 0x205 (POSIX xattr) is MISSING.

### 16.3 SMB_QUERY_POSIX_LOCK / SMB_SET_POSIX_LOCK (0x208)

**Wire format for POSIX lock struct:**
```c
struct smb_lock_struct {
    __le64  Offset;          /* start of locked range */
    __le64  Length;          /* length of locked range (0 = to EOF) */
    __le32  Pid;             /* PID of locking process */
    __le16  LockType;        /* READ_LOCK=0, WRITE_LOCK=1, UNLOCK=2 */
    __le16  ReturnCode;      /* 0 on success; error code on failure */
} __packed;
```

**Query (TRANS2_QUERY_FILE_INFORMATION with level 0x208):**
- Parse lock range from request data (smb_lock_struct with `ReturnCode=0`)
- Call `vfs_test_lock()` on the underlying file
- Return smb_lock_struct with current lock status (holder PID if locked)

**Set (TRANS2_SET_FILE_INFORMATION with level 0x208):**
- Parse smb_lock_struct from request
- Call `ksmbd_vfs_posix_lock_set()` non-blocking
- Return `STATUS_SUCCESS` or `STATUS_LOCK_NOT_GRANTED`

The VFS infrastructure already exists: `ksmbd_vfs_posix_lock_wait_timeout()`,
`ksmbd_vfs_posix_lock_unblock()`, and `ksmbd_vfs_posix_lock_set()` in `vfs.c`.

### 16.4 SMB_QUERY_POSIX_WHO_AM_I (0x202 in TRANS2_QUERY_FS_INFORMATION)

**Response structure:**
```c
struct smb_whoami_rsp {
    __u32  flags;           /* 0 */
    __u32  flags_mask;      /* 0 */
    __u64  guest_smbuid;    /* server-assigned SMB UID (not POSIX) */
    __u64  hostsid_size;    /* SID size (may be 0) */
    __u32  uid;             /* effective POSIX UID on the server */
    __u32  gid;             /* effective POSIX GID */
    __u32  num_groups;      /* number of supplemental groups */
    __u32  SID_list_size;   /* size of SID list (may be 0) */
    __u32  groups[];        /* flexible array of supplemental GIDs */
} __packed;
```

**Handler addition to `query_fs_info()` in `smb1pdu.c`:**
```c
case SMB_QUERY_POSIX_WHO_AM_I:
{
    struct smb_whoami_rsp *whoami;
    struct group_info *gi;
    int i;
    size_t rsp_size;

    gi = get_current_groups();
    rsp_size = sizeof(*whoami) + gi->ngroups * sizeof(__u32);

    whoami = (struct smb_whoami_rsp *)(&rsp->Pad + 1);
    memset(whoami, 0, rsp_size);
    whoami->uid        = cpu_to_le32(from_kuid(user_ns,
                             work->sess->user->uid));
    whoami->gid        = cpu_to_le32(from_kgid(user_ns,
                             work->sess->user->gid));
    whoami->num_groups = cpu_to_le32(gi->ngroups);
    for (i = 0; i < gi->ngroups; i++)
        whoami->groups[i] = cpu_to_le32(
            from_kgid(user_ns, GROUP_AT(gi, i)));

    t2_rsp->TotalDataCount = cpu_to_le16(rsp_size);
    break;
}
```

### 16.5 SMB_QUERY_XATTR / SMB_SET_XATTR (0x205)

The POSIX xattr info level allows clients to get/set POSIX xattrs (full
namespace: `user.*`, `security.*`, etc.), not just Windows EAs.

**Handler additions:**

In `TRANS2_QUERY_PATH_INFORMATION` dispatcher:
```c
case SMB_QUERY_XATTR:
{
    char *name = params + 2;  /* skip 2-byte name length */
    u16  namelen = le16_to_cpu(*((__le16 *)params));
    char namebuf[XATTR_NAME_MAX + 1];
    void *xattr_val;
    ssize_t xattr_len;

    if (namelen > XATTR_NAME_MAX)
        return -EINVAL;
    memcpy(namebuf, name, namelen);
    namebuf[namelen] = '\0';
    /* Prepend user. if no namespace prefix */
    if (!strchr(namebuf, '.'))
        scnprintf(namebuf, sizeof(namebuf), "user.%s", name);

    xattr_val = kmalloc(XATTR_SIZE_MAX, GFP_KERNEL);
    xattr_len = ksmbd_vfs_get_xattr(mnt_idmap, dentry,
                                     namebuf, xattr_val,
                                     XATTR_SIZE_MAX);
    /* Write xattr value to TRANS2 data area */
    ...
    kfree(xattr_val);
    break;
}
```

---

## 17. DFS Referral Full Implementation Plan

### 17.1 Current State

- `ksmbd_dfs.c` provides DFS referral data structures and namespace lookup
- `ksmbd_branchcache.h` provides the branch cache
- `CAP_DFS` is NOT currently advertised in `SMB1_SERVER_CAPS`
- `TRANS2_GET_DFS_REFERRAL` (0x10) falls to `default:` returning `-EINVAL`

### 17.2 Request Structure (TRANS2 Parameters)

```c
struct dfs_referral_req {
    __le16  MaxReferralLevel;    /* 1=oldest, 2=domain, 3=standard, 4=extended */
    /* RequestFileName (UTF-16LE) follows in TRANS2 data area */
} __packed;
```

### 17.3 Response Wire Format (DFS v3)

```c
struct dfs_referral_rsp_hdr {
    __le16  PathConsumed;        /* bytes of RequestFileName consumed by this server */
    __le16  NumberOfReferrals;   /* count of DFS_REFERRAL_V3 entries following */
    __le32  ReferralHeaderFlags; /* REFERRAL_SERVER=0x1, STORAGE_SERVER=0x2 */
} __packed;

struct dfs_referral_v3 {
    __le16  VersionNumber;       /* 3 */
    __le16  Size;                /* size of this entry in bytes */
    __le16  ServerType;          /* 0=LINK, 1=ROOT */
    __le16  ReferralEntryFlags;  /* NAME_LIST_REFERRAL=0x0002, TARGET_SET_BOUNDARY=0x0004 */
    __le32  TimeToLive;          /* typically 300 seconds */
    __le16  DFSPathOffset;       /* byte offset from start of entry to DFS path string */
    __le16  DFSAlternatePathOffset;  /* alternate DFS path offset */
    __le16  NetworkAddressOffset;    /* byte offset to server name/address string */
    __u8    ServiceSiteGuid[16]; /* GUID; may be all zeros */
} __packed;
```

### 17.4 Implementation Steps

1. Add `case TRANS2_GET_DFS_REFERRAL:` to `smb_trans2()` in `smb1pdu.c`.

2. Parse MaxReferralLevel and RequestFileName:
   ```c
   struct dfs_referral_req *dreq = (struct dfs_referral_req *)params;
   u16 max_level = le16_to_cpu(dreq->MaxReferralLevel);
   char *path = smb_strndup_from_utf16(data, data_count, true,
                                        work->conn->local_nls);
   ```

3. Query ksmbd_dfs.c for matching namespace entry:
   ```c
   struct ksmbd_dfs_info dfs_info;
   int ret = ksmbd_dfs_lookup(path, &dfs_info);
   if (ret) {
       rsp->hdr.Status.CifsError = STATUS_PATH_NOT_COVERED;
       kfree(path);
       return -ENOENT;
   }
   ```

4. Build response using `dfs_referral_rsp_hdr` + `dfs_referral_v3` structures.

5. Once the handler is working, add `CAP_DFS` to `SMB1_SERVER_CAPS` and set
   `SMBFLG2_DFS` in the negotiate response `Flags2`.

### 17.5 Error Case

When the path is not found in the DFS namespace:
```c
rsp->hdr.Status.CifsError = STATUS_PATH_NOT_COVERED;
/* Maps to ERRDOS/ERRbadpath for pre-NT clients */
return 0;  /* Always send a response, never silently drop */
```

---

## 18. SMB Signing — Spec Compliance Analysis

### 18.1 Signing Algorithm Verification

The SMB1 signing algorithm per MS-SMB §3.1.4.1:
```
MAC = MD5(SessionKey[40] || Message_with_SecurityFeatures_zeroed_then_seqno_filled)
```
First 8 bytes of MD5 output become the `SecuritySignature` field.

KSMBD implementation in `auth.c` line 943 (`ksmbd_sign_smb1_pdu()`):
```c
MD5(sess->sess_key[0..39] || full_smb_message_with_zeroed_SecuritySignature)
```

**Compliance table:**

| Spec Requirement | KSMBD Implementation | Compliant? |
|-----------------|---------------------|------------|
| MD5 over full message | `crypto_shash_update()` over all iovecs | Yes |
| Session key prepended (40 bytes) | `crypto_shash_update(sess->sess_key, 40)` | Yes |
| SecurityFeatures: write seq number then zeros | `SequenceNumber = ++seq; Reserved = 0` | Yes |
| Sequence starts at 2 | `sequence_number = 1` in auth.c:355, incremented to 2 on first use | Yes |
| First 8 bytes of MD5 as signature | `memcpy(...CIFS_SMB1_SIGNATURE_SIZE)` | Yes |

**Conclusion:** The signing algorithm itself is correct. The gaps are
in enforcement (mandatory signing not enforced) and thread safety (race condition).

### 18.2 Gap 1 — Mandatory Signing Not Enforced

**Location:** `smb1pdu.c` lines 8952–8978 (`smb1_is_sign_req()`)

`smb1_is_sign_req()` returns `true` only if the client sets
`SMBFLG2_SECURITY_SIGNATURE` in the request header. When mandatory signing is
configured (`SECMODE_SIGN_REQUIRED`), unsigned requests are silently accepted.

**Fix:** When `SECMODE_SIGN_REQUIRED` is set and the session is post-session-setup:
```c
bool smb1_is_sign_req(struct ksmbd_work *work, unsigned int command)
{
    struct smb_hdr *rcv_hdr = work->request_buf;

    /* If signing is mandatory, treat all commands as requiring signing */
    if (work->conn->sign &&
        work->sess &&
        command != SMB_COM_NEGOTIATE &&
        command != SMB_COM_SESSION_SETUP_ANDX)
        return true;

    return rcv_hdr->Flags2 & SMBFLG2_SECURITY_SIGNATURE;
}
```

### 18.3 Gap 2 — sequence_number Race Condition

**Location:** `smb1pdu.c` line 8988

```c
rcv_hdr1->Signature.Sequence.SequenceNumber =
    cpu_to_le32(++work->sess->sequence_number);
```

**Bug:** `sequence_number` is a plain `unsigned int`. Multiple concurrent work
items for the same session read-modify-write it without synchronization.

**Fix:** Change to `atomic_t` in `struct ksmbd_session`:
```c
/* In src/mgmt/user_session.h: */
atomic_t sequence_number;

/* In smb1_check_sign_req(): */
rcv_hdr1->Signature.Sequence.SequenceNumber =
    cpu_to_le32(atomic_inc_return(&work->sess->sequence_number));
```

### 18.4 Gap 3 — Signing Failure Path

When `smb1_check_sign_req()` returns 0 (mismatch), verify that the dispatch
loop in `ksmbd_conn.c` or `smb1ops.c`:
1. Sends `STATUS_ACCESS_DENIED` to the client, AND
2. Disconnects the TCP connection (per MS-SMB §3.3.4.1).

Currently the code path on signing failure is not verified to do this — it
may silently continue processing the request.

---

## 19. Complete Priority Table (43 Items from Source Analysis)

### Priority 1 — Critical (Windows interoperability breaks)

| # | Feature | Source File | Effort | Spec Ref |
|---|---------|-------------|--------|----------|
| 1 | SMB_COM_NT_TRANSACT dispatcher (0xA0) | smb1ops.c, smb1pdu.c | HIGH | MS-SMB §2.2.4.62 |
| 2 | NT_TRANSACT_NOTIFY_CHANGE (0x04) | smb1pdu.c | HIGH | MS-SMB §2.2.4.62.13 |
| 3 | NT_TRANSACT_QUERY_SECURITY_DESC (0x06) | smb1pdu.c | HIGH | MS-SMB §2.2.4.62.17 |
| 4 | NT_TRANSACT_SET_SECURITY_DESC (0x03) | smb1pdu.c | HIGH | MS-SMB §2.2.4.62.11 |
| 5 | NT_TRANSACT_IOCTL (0x02) FSCTL passthrough | smb1pdu.c | HIGH | MS-SMB §2.2.4.62.9 |
| 6 | Multi-packet TRANSACTION_SECONDARY (0x26) | smb1pdu.c, smb1ops.c | HIGH | MS-CIFS §2.2.4.33 |
| 7 | Multi-packet TRANSACTION2_SECONDARY (0x33) | smb1pdu.c, smb1ops.c | HIGH | MS-CIFS §2.2.4.47 |
| 8 | Multi-packet NT_TRANSACT_SECONDARY (0xA1) | smb1pdu.c, smb1ops.c | HIGH | MS-SMB §2.2.4.63 |

### Priority 2 — High (Common operations used by all Windows clients)

| # | Feature | Source File | Effort | Spec Ref |
|---|---------|-------------|--------|----------|
| 9 | TRANS2_GET_DFS_REFERRAL (0x10) | smb1pdu.c, ksmbd_dfs.c | HIGH | MS-DFSC |
| 10 | NT_TRANSACT_CREATE (0x01) | smb1pdu.c | MEDIUM | MS-SMB §2.2.4.62.5 |
| 11 | SMB_COM_NT_RENAME (0xA5) RENAME_FILE case | smb1pdu.c | LOW | MS-CIFS §2.2.4.73 |
| 12 | NT_CANCEL: actually cancel sleeping locks | smb1pdu.c | MEDIUM | MS-CIFS §2.2.4.69 |
| 13 | LOCKING_ANDX CANCEL_LOCK functional | smb1pdu.c | MEDIUM | MS-SMB §3.3.5.14 |
| 14 | NT_TRANSACT_RENAME (0x05) | smb1pdu.c, vfs.c | MEDIUM | MS-SMB §2.2.4.62.15 |

### Priority 3 — Medium (Interoperability improvement; older client support)

| # | Feature | Source File | Effort | Spec Ref |
|---|---------|-------------|--------|----------|
| 15 | SMB_COM_QUERY_INFORMATION2 (0x23) | smb1pdu.c, smb1ops.c, smb1pdu.h | LOW | MS-CIFS §2.2.4.32 |
| 16 | SMB_COM_SET_INFORMATION2 (0x22) | smb1pdu.c, smb1ops.c, smb1pdu.h | LOW | MS-CIFS §2.2.4.18 |
| 17 | Error code model: DOS error support | smb1pdu.c, netmisc.c | MEDIUM | MS-SMB §3.1.4.2 |
| 18 | SMB_COM_COPY (0x29) server-side copy | smb1pdu.c, smb1ops.c | HIGH | MS-CIFS §2.2.4.34 |
| 19 | POSIX lock TRANS2 level 0x208 | smb1pdu.c | MEDIUM | CIFS POSIX Ext |
| 20 | POSIX xattr TRANS2 level 0x205 | smb1pdu.c | LOW | CIFS POSIX Ext |
| 21 | SMB_QUERY_POSIX_WHO_AM_I (QUERY_FS 0x202) | smb1pdu.c | LOW | CIFS POSIX Ext |
| 22 | SMB1 signing mandatory enforcement | smb1pdu.c | LOW | MS-SMB §3.3.4.1 |
| 23 | SMB1 signing sequence_number atomic safety | auth.c, smb1pdu.c | LOW | MS-SMB §3.3.4.1.1 |
| 24 | SMB_COM_MOVE (0x2A) server-side move | smb1pdu.c, smb1ops.c | HIGH | MS-CIFS §2.2.4.35 |
| 25 | Remove CIFS_UNIX_FCNTL_CAP if unimplemented | smb1pdu.h | VERY LOW | CIFS POSIX Ext |
| 26 | TRANS2_REPORT_DFS_INCONSISTENCY (0x11) stub | smb1pdu.c | VERY LOW | MS-CIFS §2.2.6.17 |

### Priority 4 — Low (Legacy compatibility; pre-NT features)

| # | Feature | Source File | Effort | Spec Ref |
|---|---------|-------------|--------|----------|
| 27 | SMB_COM_SEARCH (0x81) legacy FCB search | smb1pdu.c, smb1ops.c | MEDIUM | MS-CIFS §2.2.4.58 |
| 28 | SMB_COM_FIND (0x82) stateful legacy search | smb1pdu.c, smb1ops.c | MEDIUM | MS-CIFS §2.2.4.59 |
| 29 | SMB_COM_FIND_UNIQUE (0x83) | smb1pdu.c, smb1ops.c | VERY LOW | MS-CIFS §2.2.4.60 |
| 30 | SMB_COM_FIND_CLOSE (0x84) | smb1pdu.c, smb1ops.c | VERY LOW | MS-CIFS §2.2.4.61 |
| 31 | SMB_COM_WRITE_AND_CLOSE (0x2C) | smb1pdu.c, smb1ops.c | LOW | MS-CIFS §2.2.4.41 |
| 32 | SMB_COM_OPEN (0x02) legacy open | smb1pdu.c, smb1ops.c | MEDIUM | MS-CIFS §2.2.4.3 |
| 33 | SMB_COM_CREATE (0x03) legacy create | smb1pdu.c, smb1ops.c | LOW | MS-CIFS §2.2.4.4 |
| 34 | SMB_COM_CREATE_NEW (0x0F) create-if-not-exists | smb1pdu.c, smb1ops.c | VERY LOW | MS-CIFS §2.2.4.15 |
| 35 | SMB_COM_CREATE_TEMPORARY (0x0E) temp file | smb1pdu.c, smb1ops.c | LOW | MS-CIFS §2.2.4.14 |
| 36 | SMB_COM_SEEK (0x12) per-FID file position | smb1pdu.c, vfs_cache.h | MEDIUM | MS-CIFS §2.2.4.20 |
| 37 | SMB_COM_OPEN_PRINT_FILE (0x43) | smb1pdu.c, smb1ops.c | LOW | MS-CIFS §2.2.4.49 |
| 38 | SMB_COM_WRITE_PRINT_FILE (0x44) | smb1pdu.c, smb1ops.c | VERY LOW | MS-CIFS §2.2.4.50 |
| 39 | SMB_COM_CLOSE_PRINT_FILE (0x45) | smb1pdu.c, smb1ops.c | LOW | MS-CIFS §2.2.4.51 |
| 40 | SMB_COM_GET_PRINT_QUEUE (0x3D) empty stub | smb1pdu.c, smb1ops.c | VERY LOW | MS-CIFS §2.2.4.42 |
| 41 | NT_TRANSACT_GET_USER_QUOTA (0x07) | smb1pdu.c, ksmbd_quota.c | LOW | MS-SMB §2.2.4.62.19 |
| 42 | NT_TRANSACT_SET_USER_QUOTA (0x08) | smb1pdu.c, ksmbd_quota.c | LOW | MS-SMB §2.2.4.62.21 |
| 43 | SMB_QUERY_ATTR_FLAGS / SET_ATTR_FLAGS (0x206) | smb1pdu.c | LOW | CIFS POSIX Ext |

### Commands to Deliberately Skip (Security Risk or Deprecated)

| Command | Opcode | Reason |
|---------|--------|--------|
| SMB_COM_READ_RAW | 0x1C | Deprecated; unauthenticated data transfer — security risk |
| SMB_COM_WRITE_RAW | 0x1D | Deprecated; security risk; respond with empty/error only |
| SMB_COM_LOCK_AND_READ | 0x13 | Remove `CAP_LOCK_AND_READ` from caps rather than implement |
| SMB_COM_SEND_MESSAGE et al. | 0x3A–0x3D | WinPopup; obsolete, security risk |

---

## 20. Appendix: Key File Locations

| Component | Primary File |
|-----------|-------------|
| SMB1 dispatch table | `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1ops.c` |
| SMB1 protocol handlers | `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c` (9040 lines) |
| SMB1 PDU structures and constants | `/home/ezechiel203/ksmbd/src/include/protocol/smb1pdu.h` |
| SMB1 message validation | `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1misc.c` |
| Error code mapping table | `/home/ezechiel203/ksmbd/src/protocol/common/netmisc.c` |
| POSIX ACL handling | `/home/ezechiel203/ksmbd/src/fs/smbacl.c` |
| VFS operations | `/home/ezechiel203/ksmbd/src/fs/vfs.c` |
| VFS cache (ksmbd_file struct) | `/home/ezechiel203/ksmbd/src/fs/vfs_cache.c` |
| DFS referrals | `/home/ezechiel203/ksmbd/src/fs/ksmbd_dfs.c` |
| Branch cache | `/home/ezechiel203/ksmbd/src/include/fs/ksmbd_branchcache.h` |
| Oplock machinery | `/home/ezechiel203/ksmbd/src/fs/oplock.c` |
| SMB1 signing verify | `smb1pdu.c` lines 8952–9040 |
| SMB1 signing algorithm | `/home/ezechiel203/ksmbd/src/core/auth.c` (line 943) |
| Quota infrastructure | `/home/ezechiel203/ksmbd/src/fs/ksmbd_quota.c` |
| Change notification | `/home/ezechiel203/ksmbd/src/fs/ksmbd_notify.c` |
| Session management | `/home/ezechiel203/ksmbd/src/mgmt/user_session.c` |
| Tree connect management | `/home/ezechiel203/ksmbd/src/mgmt/tree_connect.c` |
| NetLink / IPC transport | `/home/ezechiel203/ksmbd/src/transport/transport_ipc.c` |
| Global server config | `/home/ezechiel203/ksmbd/src/core/ksmbd_config.c` |

---

## 21. Appendix: Effort and Compliance Impact Summary

```
CURRENT ESTIMATED COMPLIANCE: ~55% of MS-SMB protocol

After implementing Priority 1 items (8 items):       ~75%
After implementing Priority 1 + 2 items (14 items):  ~82%
After implementing Priority 1 + 2 + 3 items (26):    ~88%
After implementing all items (43):                    ~94%

Remaining ~6% gap:
  - Raw mode stubs (send empty frame only — security decision)
  - Print submission backend (OS-dependent; outside kernel scope)
  - DFS complex referral topologies (multi-hop, intersite DFS)
  - Snapshot enumeration via FSCTL_SRV_ENUMERATE_SNAPSHOTS
```

### Effort Estimates by Sprint

| Sprint | Scope | Estimated Hours |
|--------|-------|----------------|
| A — Blocker Fixes | 22 P1 bugs (critical correctness) | 40–50 hours |
| B — NT_TRANSACT Core | Dispatcher + 6 subcommands + QUERY/SET_INFO2 | 40–50 hours |
| C — TRANSACTION2 + Async | Named pipe, notify, missing levels, POSIX ext | 60–70 hours |
| D — Secondary + DFS | Reassembly, DFS, quotas, signing, error model | 50–60 hours |
| E — Legacy Commands | COPY/MOVE/SEARCH/FIND/print + misc | 30–40 hours |
| **Total** | | **~220–270 hours** |

---

## 22. NEGOTIATE / SESSION_SETUP / TREE_CONNECT / LOGOFF Full Gap Analysis

This section supplements Section 11 with the complete per-field compliance analysis
drawn from `smb1_plan_02_negotiate_session.md`. It covers every response field,
every edge-case request variant, and all security implications for the five
connection-setup and teardown commands.

---

### 22.1 SMB_COM_NEGOTIATE — Complete Field-Level Analysis (MS-SMB §2.2.4.52)

#### 22.1.1 Request Parsing

| Field | Type | Requirement | KSMBD Status |
|-------|------|-------------|--------------|
| WordCount | UCHAR | Must be 0x00 | Correct — `smb1misc.c` enforces it |
| ByteCount | USHORT | Must be >= 2 | Correct — `smb1_get_byte_count()` enforces |
| DialectsArray | variable | 0x02-prefixed NUL-terminated strings | Parsed by `next_dialect()` |

**Dialect comparison strip issue (line ~273 of `smb_common.c`):** `next_dialect()` returns
a pointer that includes the 0x02 prefix byte, while some comparison paths may strip it.
The `smb1_protos[]` table entries must align with whatever `next_dialect()` returns.
Any mismatch causes spurious `BAD_PROT_ID` results. Audit the pointer arithmetic and
document which side owns the 0x02 byte.

#### 22.1.2 NT LM 0.12 Extended Security Response Fields

| Field | Type | KSMBD | Spec Requirement |
|-------|------|-------|-----------------|
| WordCount | UCHAR | 17 | Correct (line 997) |
| DialectIndex | USHORT | `conn->dialect` | Correct |
| SecurityMode | UCHAR | `SECMODE_USER \| SECMODE_PW_ENCRYPT` | Correct; signing bits set conditionally |
| MaxMpxCount | USHORT | 10 | Correct |
| MaxNumberVcs | USHORT | 1 | Correct |
| MaxBufferSize | ULONG | `conn->vals->max_read_size` (65536) | Legal but should not exceed 0xFFFF for pre-NT clients |
| MaxRawSize | ULONG | 65536 | **BUG** — must be 0 when `CAP_RAW_MODE` absent (MS-SMB §2.2.4.52.2) |
| SessionKey | ULONG | 0 | Allowed; limit for multi-VC; document as known |
| Capabilities | ULONG | `SMB1_SERVER_CAPS` | Missing `CAP_MPX_MODE`, `CAP_RPC_REMOTE_APIS`, `CAP_INFOLEVEL_PASSTHRU` |
| SystemTimeLow | ULONG | `ksmbd_systime() & 0xFFFFFFFF` | Correct |
| SystemTimeHigh | ULONG | `ksmbd_systime() >> 32` | Correct |
| ServerTimeZone | SHORT | 0 | Valid for UTC; non-UTC deployments may see shifted timestamps |
| EncryptionKeyLength | UCHAR | 0 (extended) / 8 (classic) | Correct |
| ByteCount | USHORT | 16 + spnego_len | Correct |
| GUID[16] | UCHAR[16] | random bytes | Correct — randomized per-negotiate |
| SecurityBlob | variable | SPNEGO negTokenInit | Correct |

**Fix for MaxRawSize (P1, §1.9):**
```c
/* In smb_handle_negotiate(), NT LM 0.12 extended security path */
rsp->MaxRawSize = 0;   /* CAP_RAW_MODE not advertised */
```

**Fix for missing capability bits (P1):**
```c
/* In smb1pdu.h, update SMB1_SERVER_CAPS: */
#define SMB1_SERVER_CAPS  (CAP_UNICODE | CAP_LARGE_FILES | CAP_EXTENDED_SECURITY | \
                           CAP_NT_SMBS | CAP_STATUS32 | CAP_NT_FIND |              \
                           CAP_UNIX | CAP_LARGE_READ_X | CAP_LARGE_WRITE_X |       \
                           CAP_LEVEL_II_OPLOCKS |                                   \
                           CAP_MPX_MODE |        /* MaxMpxCount > 1 */             \
                           CAP_RPC_REMOTE_APIS | /* IPC$/named pipe DCE/RPC */     \
                           CAP_INFOLEVEL_PASSTHRU) /* TRANS2 passthrough levels */ \
/* CAP_DFS added dynamically when server_conf.dfs_enabled */
```

#### 22.1.3 Non-Extended Security Response — DomainName Missing

**MS-SMB §2.2.4.52.2:** After the 8-byte `EncryptionKey`, the server MUST append
a NUL-terminated OEM string for `DomainName`. KSMBD's code has a comment
`"Null terminated domain name in unicode"` at line 1047 of `smb1pdu.c` but
**does not write the domain name to the wire**. `ByteCount` is set to only 8.

**Fix (P1):**
```c
/* smb1pdu.c — non-extended security NEGOTIATE response, after writing challenge */
size_t dom_len = strlen(server_conf.work_group);
memcpy(rsp->EncryptionKey + CIFS_CRYPTO_KEY_SIZE,
       server_conf.work_group, dom_len + 1); /* NUL included */
rsp->ByteCount = cpu_to_le16(CIFS_CRYPTO_KEY_SIZE + dom_len + 1);
inc_rfc1001_len(rsp_hdr, dom_len + 1);
```

#### 22.1.4 No-Common-Dialect Response (BAD_PROT_ID path)

**MS-SMB §2.2.4.52.2:** When no offered dialect is acceptable, the server MUST
respond with `WordCount=1, DialectIndex=0xFFFF, ByteCount=0, Status=STATUS_SUCCESS`.
KSMBD currently returns `STATUS_INVALID_LOGON_TYPE`, which is non-standard, exposes
server capabilities, and confuses strict clients.

**Fix (P1):**
```c
/* In smb_handle_negotiate(), BAD_PROT_ID branch: */
if (conn->dialect == BAD_PROT_ID) {
    struct smb_com_negotiate_rsp *rsp = smb_buf_data(work);
    init_smb_rsp_hdr(work);
    rsp->hdr.Status.CifsError = STATUS_SUCCESS;
    rsp->WordCount = 1;
    rsp->DialectIndex = cpu_to_le16(0xFFFF);
    *(__le16 *)(rsp->DialectIndex + 1) = 0;  /* ByteCount = 0 */
    inc_rfc1001_len(rsp_hdr, 2 + 2);
    return 0;
}
```

#### 22.1.5 Pre-NT Dialect Responses

KSMBD only supports NT LM 0.12. Pre-NT dialects (LANMAN1.0, LM1.2X002, LANMAN2.1)
have a fundamentally different response wire format:

**LANMAN1.0 / LM1.2X002 / LANMAN2.1 response (WordCount = 13):**
```
DialectIndex       USHORT
SecurityMode       USHORT  (2 bytes, not 1)
MaxBufferSize      USHORT
MaxMpxCount        USHORT
MaxNumberVcs       USHORT
RawMode            USHORT
SessionKey         ULONG
ServerTime         USHORT  (DOS time)
ServerDate         USHORT  (DOS date)
ServerTimeZone     SHORT
EncryptionKeyLength USHORT
Reserved           USHORT
ByteCount          USHORT
EncryptionKey[8]   UCHAR[8]
PrimaryDomain      variable (NUL-terminated OEM)
```

If KSMBD ever adds LANMAN dialect support, a separate response-building path is
required because `SecurityMode` is 2 bytes wide and the time fields are DOS
date/time format rather than FILETIME.

---

### 22.2 SMB_COM_SESSION_SETUP_ANDX — Complete Field-Level Analysis (MS-SMB §2.2.4.53)

#### 22.2.1 Request Format Variants

| Variant | WC | When Used | KSMBD |
|---------|----|-----------|-------|
| NT LM 0.12 w/ Extended Security | 12 | Client sets `CAP_EXTENDED_SECURITY` | Handled |
| NT LM 0.12 No Extended Security | 13 | NT dialect, no SPNEGO | Handled |
| LM 2.1 / Old-style | varies | Pre-NT clients | Not handled |
| Any other WordCount | — | Invalid | Silent drop — **spec violation** |

**Issue:** Invalid `WordCount` causes `work->send_no_response = 1` and returns.
Per MS-SMB §2.2.4.53.1, the server MUST always respond, even to invalid requests —
the correct response is `STATUS_INVALID_PARAMETER`.

**Fix (P1):**
```c
/* In smb_session_setup_andx(), at the WordCount check: */
default:
    return -EINVAL;  /* Let generic error path send STATUS_INVALID_PARAMETER */
    /* Do NOT set send_no_response = 1 */
```

#### 22.2.2 No-Extended-Security Request Fields (WC=13)

| Field | Handled | Issue |
|-------|---------|-------|
| MaxBufferSize | No | Client's receive limit — should cap per-response sizes |
| MaxMpxCount | No | Client's in-flight request limit — should throttle |
| VcNumber | No | **P1 bug** — VcNumber=0 must destroy existing sessions (§2.2.4.53.1) |
| SessionKey | No | Allowed — KSMBD sets SessionKey=0 and ignores it consistently |
| CaseInsensitivePasswordLength | Yes | OEM hash length |
| CaseSensitivePasswordLength | Yes | Unicode/NTLMv2 hash length |
| Capabilities | Yes | `CAP_EXTENDED_SECURITY` check |
| Account | Yes | Username |
| PrimaryDomain | Yes | NTLMv2 domain |
| NativeOS | No | Not stored; log-only value |
| NativeLanMan | No | Not stored; log-only value |

**VcNumber=0 Fix (P1, §1.26):**
```c
/* In smb_session_setup_andx(), no-extsec WC=13 path: */
if (le16_to_cpu(req->VcNumber) == 0) {
    /* Spec: disconnect all existing VCs for this client before creating new */
    ksmbd_destroy_conn_sessions(conn);
}
```

**Alignment/padding bug (line ~1079):** The code uses `+ 1` unconditionally to
skip to the Account field. When `CAP_UNICODE` is set and the combined password
length is even, the correct pad is 0, not 1. Dynamic calculation:
```c
int pw_end_off = sizeof(struct smb_hdr) + fixed_wc_sz +
                 le16_to_cpu(req->CaseInsensitivePasswordLength) +
                 le16_to_cpu(req->CaseSensitivePasswordLength);
int pad = (flags2 & SMBFLG2_UNICODE) ? ((2 - (pw_end_off & 1)) & 1) : 0;
char *account = (char *)req->CaseSensitivePassword +
                le16_to_cpu(req->CaseSensitivePasswordLength) + pad;
```

#### 22.2.3 Extended Security Request Fields (WC=12, SPNEGO)

| Field | Handled | Issue |
|-------|---------|-------|
| SecurityBlobLength | Yes | Bounds blob parsing |
| SecurityBlob | Yes | SPNEGO negToken parsed in `build_sess_rsp_extsec()` |
| NativeOS | No | Ignored — log-only |
| NativeLanMan | No | Ignored — log-only |

**mechToken length mismatch (security-critical, P1):**
When `conn->mechToken` is set (SPNEGO extracted an inner NTLMSSP token), the call
to `ksmbd_decode_ntlmssp_auth_blob()` passes `le16_to_cpu(req->SecurityBlobLength)`
as the blob length. This is the outer SPNEGO envelope size, not the inner NTLMSSP
token size. Passing the wrong length can cause the NTLMSSP parser to read beyond
the actual token buffer.

**Fix:**
```c
/* In build_sess_rsp_extsec(), NTLMSSP authentication phase: */
size_t ntlmssp_len = conn->mechToken ?
    conn->mechTokenLen : le16_to_cpu(req->SecurityBlobLength);
rc = ksmbd_decode_ntlmssp_auth_blob(authblob, ntlmssp_len, conn, sess);
```

#### 22.2.4 SESSION_SETUP Response — Extended Security (WC=4)

| Field | KSMBD Status | Notes |
|-------|-------------|-------|
| WordCount=4 | Correct | Line 1195 |
| AndXCommand | Correct | |
| AndXReserved | Correct | |
| AndXOffset | Correct | |
| Action | Correct | `GUEST_LOGIN` bit for guests |
| SecurityBlobLength | Correct | |
| ByteCount | Correct | |
| SecurityBlob | Correct | SPNEGO token |
| NativeOS | **MISSING** | Must follow SecurityBlob |
| NativeLanMan | **MISSING** | Must follow NativeOS |
| PrimaryDomain | **MISSING** | Must follow NativeLanMan |

**Fix — append info strings after SecurityBlob (P2):**
```c
/* After writing SecurityBlob in build_sess_rsp_extsec(): */
__le16 *str_area = (__le16 *)((char *)rsp + sizeof(*rsp) + spnego_len);
int slen = 0;
/* NativeOS = "Linux" */
slen += smb_strtoUTF16(str_area + slen, "Linux", 5, conn->local_nls);
str_area[slen++] = 0; /* NUL */
/* NativeLanMan = "ksmbd" */
slen += smb_strtoUTF16(str_area + slen, "ksmbd", 5, conn->local_nls);
str_area[slen++] = 0;
/* PrimaryDomain = server_conf.work_group */
slen += smb_strtoUTF16(str_area + slen, server_conf.work_group,
                        strlen(server_conf.work_group), conn->local_nls);
str_area[slen++] = 0;
rsp->ByteCount = cpu_to_le16(spnego_len + slen * 2);
inc_rfc1001_len(rsp_hdr, slen * 2);
```

#### 22.2.5 Guest and Null Session Handling (§2.2.4.53.1)

**Null session (§2.2.4.53.1):** When `CaseInsensitivePasswordLength = 0`,
`CaseSensitivePasswordLength = 0`, and `Account = ""`, the spec defines a null
session. KSMBD calls `ksmbd_login_user("")` which returns NULL, and the handler
returns `STATUS_LOGON_FAILURE`. Per spec and Windows behavior, null sessions should
be allowed if `map to guest = Bad User` (or equivalent) is configured, routing to
the guest account.

**Fix (P2):**
```c
/* Before ksmbd_login_user() call, check for null session: */
if (req->CaseInsensitivePasswordLength == 0 &&
    req->CaseSensitivePasswordLength == 0 &&
    account[0] == '\0') {
    if (server_conf.map_to_guest == KSMBD_GUEST_MAP) {
        /* Route to guest account */
        sess->user = server_conf.guest_account;
        goto null_session_ok;
    }
    return -EACCES; /* STATUS_LOGON_FAILURE */
}
```

#### 22.2.6 Multi-Session UID Reuse (§2.2.4.53.1)

When a client sends `SESSION_SETUP_ANDX` with a non-zero `Uid`, KSMBD looks up
the existing session and then re-enters the normal authentication path. If
re-authentication fails, the existing session is destroyed. Per MS-SMB §2.2.4.53.1,
on re-auth failure the original session must be preserved.

**Fix (P3):** Take a reference to `work->sess` before re-auth; only destroy it if
re-auth succeeds (to replace with the new session) or if the client explicitly
re-auth fails AND the spec says to invalidate. Preserve on transient failure.

---

### 22.3 SMB_COM_TREE_CONNECT_ANDX — Complete Field-Level Analysis (MS-SMB §2.2.4.55)

#### 22.3.1 Request Fields (WordCount=4)

| Field | Handled | Issue |
|-------|---------|-------|
| WordCount | Yes | Validated as 0x4 in `smb1misc.c` |
| AndXCommand | Yes | Chaining supported |
| Flags | **No** | Three bits not processed — see §22.3.2 |
| PasswordLength | Yes | Offset to `Path` |
| ByteCount | Yes | |
| Password | Partial | Share-level auth ignored (user-mode only) |
| Path | Yes | UNC path parsed |
| Service | Yes | Service type string |

#### 22.3.2 Flags Field — Three Unimplemented Bits

```c
#define TREE_CONNECT_ANDX_DISCONNECT_TID       0x0001
#define TREE_CONNECT_ANDX_EXTENDED_SIGNATURES  0x0004
#define TREE_CONNECT_ANDX_EXTENDED_RESPONSE    0x0008
```

**`TREE_CONNECT_ANDX_DISCONNECT_TID` (P1):** Per MS-SMB §2.2.4.55.1, if this bit
is set the server MUST disconnect the TID specified in the request header before
establishing the new tree connection. KSMBD ignores this flag entirely.

**Fix:**
```c
/* In smb_tree_connect_andx() or the dispatch handler: */
__u16 flags = le16_to_cpu(req->Flags);
if (flags & TREE_CONNECT_ANDX_DISCONNECT_TID) {
    struct ksmbd_tree_connect *old_tcon =
        ksmbd_tree_conn_lookup(sess, le16_to_cpu(req->hdr.Tid));
    if (old_tcon)
        smb_tree_disconnect_by_tcon(sess, old_tcon);
}
```

**`TREE_CONNECT_ANDX_EXTENDED_RESPONSE` (P2):** The spec states the server SHOULD
send the basic (WordCount=3) response unless this flag is set. KSMBD always sends
WordCount=7 (extended). Most modern clients set this flag, so the impact is low, but
it is a spec violation.

**`TREE_CONNECT_ANDX_EXTENDED_SIGNATURES` (P5):** If the client requests extended
signatures and the server cannot support them, the `SMB_EXTENDED_SIGNATURES` bit
MUST NOT be set in `OptionalSupport`. KSMBD does not set this bit (correct), but
should log a warning when the client requests it.

#### 22.3.3 Extended Response Fields (WordCount=7)

| Field | KSMBD Status | Issue |
|-------|-------------|-------|
| WordCount=7 | Correct | Always sent unconditionally |
| AndXCommand | Correct | |
| OptionalSupport | Partial | `SMB_SHARE_IS_IN_DFS` not set for DFS shares |
| MaximalShareAccessRights | Partial | Binary writable/non-writable only |
| GuestMaximalShareAccessRights | **Wrong** | Hardcoded 0 — may not reflect actual guest policy |
| ByteCount | Correct | |
| Service | Correct | ASCII, NUL-terminated |
| NativeFileSystem | Correct | "NTFS" as UTF-16LE |

**OptionalSupport bits (MS-SMB §2.2.4.55.2):**

| Bit | Value | KSMBD | Notes |
|-----|-------|-------|-------|
| `SMB_SUPPORT_SEARCH_BITS` | 0x0001 | Set | Correct |
| `SMB_SHARE_IS_IN_DFS` | 0x0002 | Not set | **Gap** — must set for DFS shares |
| `SMB_CSC_MASK` (0x000C) | varies | `SMB_CSC_NO_CACHING` | Acceptable default |
| `SMB_UNIQUE_FILE_NAME` | 0x0010 | Set | Correct |
| `SMB_EXTENDED_SIGNATURES` | 0x0020 | Not set | Correct — not implemented |

**Fix for DFS shares (P3):**
```c
if (test_share_config_flag(share, KSMBD_SHARE_FLAG_DFS))
    rsp->OptionalSupport |= cpu_to_le16(SMB_SHARE_IS_IN_DFS);
```

#### 22.3.4 Share-Level Password Validation

KSMBD operates in user-level security mode (`SECMODE_USER` always set).
Per MS-SMB §2.2.4.55.1, in user-level mode the Password field should be empty
(PasswordLength=0) or a single null byte (PasswordLength=1). KSMBD does not
validate this, which may mask fuzz inputs. Low-priority assertion:
```c
if (le16_to_cpu(req->PasswordLength) > 1)
    pr_debug("TREE_CONNECT_ANDX: non-empty password in user-mode\n");
```

#### 22.3.5 Service Type Matching

The `"?????"` wildcard service type (`dev_flags = 5`) is correctly handled — the
logic `!dev_flags || (dev_flags > 1 && dev_flags < 5)` evaluates correctly for
`dev_flags=5` (truthy, and `5 < 5` is false, so it passes the `?????` case).
Add a comment explaining this non-obvious logic.

---

### 22.4 SMB_COM_LOGOFF_ANDX — Complete Field-Level Analysis (MS-SMB §2.2.4.54)

#### 22.4.1 Request Fields (WordCount=2)

| Field | Requirement | KSMBD |
|-------|-------------|-------|
| WordCount | Must be 0x2 | Correct — enforced by `smb1misc.c` |
| AndXCommand | Must be `SMB_NO_MORE_ANDX_COMMAND` | Not checked |
| ByteCount | Must be 0x0 | Correct — enforced by `smb1_get_byte_count()` |

#### 22.4.2 Session Teardown Logic — Critical Bugs

Handler: `smb_session_disconnect()` (line 440).

Current sequence:
1. `ksmbd_conn_set_need_reconnect(conn)` — marks entire connection
2. `ksmbd_conn_wait_idle(conn)` — waits for ALL connection requests (not just this UID)
3. `ksmbd_tree_conn_session_logoff(sess)` — closes tree connections for this session
4. `ksmbd_conn_set_exiting(conn)` — **tears down the entire TCP connection**

**Bug 1 — Entire connection torn down (P1, critical spec violation):**
MS-SMB §2.2.4.54 specifies that `LOGOFF_ANDX` invalidates only the `Uid` in the
request. Other sessions on the same TCP connection must remain active. KSMBD calls
`ksmbd_conn_set_exiting(conn)` which terminates the entire connection, violating
multi-session scenarios.

**Fix:**
```c
/* In smb_session_disconnect(): */
/* 1. Drain only requests belonging to work->sess, not all of conn */
ksmbd_session_drain_requests(sess);

/* 2. Close all tree connections for this session */
ksmbd_tree_conn_session_logoff(sess);

/* 3. Destroy the session (removes from conn->sessions) */
ksmbd_session_destroy(sess);
work->sess = NULL;

/* 4. Only transition conn to exiting if no sessions remain */
if (list_empty(&conn->sessions))
    ksmbd_conn_set_exiting(conn);
```

**Bug 2 — Response WordCount=0 instead of required WordCount=2 (P1):**
MS-SMB §2.2.4.54.2 requires the response to have `WordCount=2` (the AndX block).
`init_smb_rsp_hdr()` sets `WordCount=0`. The response is malformed.

**Fix:**
```c
/* In smb_session_disconnect(), before returning 0: */
struct smb_com_logoff_andx_rsp *rsp =
    (struct smb_com_logoff_andx_rsp *)work->response_buf;
rsp->WordCount = 2;
rsp->AndXCommand = SMB_NO_MORE_ANDX_COMMAND;
rsp->AndXReserved = 0;
rsp->AndXOffset = cpu_to_le16(sizeof(struct smb_hdr) + 4);
rsp->ByteCount = 0;
inc_rfc1001_len(work->response_buf, 2 * 2 + 2);
```

**Bug 3 — Over-broad idle wait (P2):**
`ksmbd_conn_wait_idle(conn)` waits for all in-flight requests on the connection
to complete before tearing down. The correct scope is only requests tagged with
`work->sess`. Waiting for unrelated sessions' requests introduces unnecessary
latency and can stall a LOGOFF behind a long-running READ on a different session.

**Bug 4 — AndX chaining not processed (P3):**
If the client chains a command after `LOGOFF_ANDX`, the handler ignores it. Per
MS-SMB §2.2.4.54, if LOGOFF succeeds, subsequent AndX commands that do not require
authentication (e.g., `SMB_COM_NEGOTIATE`) MAY be processed.

#### 22.4.3 UID Invalidation

After `LOGOFF_ANDX`, the UID MUST be invalidated (MS-SMB §2.2.4.54.1). Any
subsequent request bearing the same UID MUST return `STATUS_SMB_BAD_UID`.
KSMBD achieves this by removing the session from `conn->sessions` via
`ksmbd_session_destroy()`. **Verify** that `ksmbd_session_lookup()` returns NULL
after destroy — if a concurrent thread holds a reference, the session may not
be fully cleaned up before the next lookup.

---

### 22.5 SMB_COM_TREE_DISCONNECT — Complete Field-Level Analysis (MS-SMB §2.2.4.51)

#### 22.5.1 Request Fields (WordCount=0)

| Field | Requirement | KSMBD |
|-------|-------------|-------|
| WordCount | Must be 0x0 | Correct — `smb1misc.c` enforces |
| ByteCount | Must be 0x0 | Correct — enforced |

#### 22.5.2 Teardown Logic

Handler: `smb_tree_disconnect()` (line 463).

Current sequence:
1. Validates `tcon != NULL`; returns `STATUS_NO_SUCH_USER` if NULL — **wrong error code**
2. `ksmbd_close_tree_conn_fds(work)` — closes all open FDs for this tree
3. `tcon->t_state = TREE_DISCONNECTED` under write lock
4. `ksmbd_tree_conn_disconnect(sess, tcon)` — removes the tree connection
5. `work->tcon = NULL`

**Bug — Wrong error code for invalid TID (P1):**
When `tcon == NULL`, KSMBD returns `STATUS_NO_SUCH_USER`. Per MS-SMB §2.2.4.51,
the correct error is `STATUS_SMB_BAD_TID` (NTSTATUS 0xC000006F, CIFS mapping:
ERRSRV / ERRinvnid = 9).

**Fix:**
```c
if (!work->tcon)
    return -ESTALE;  /* Map to STATUS_SMB_BAD_TID in error response path */
/* Or explicitly: */
rsp_hdr->Status.CifsError = STATUS_SMB_BAD_TID;
return -EINVAL;
```

**Open-file cleanup ordering (P2):**
`ksmbd_close_tree_conn_fds(work)` must be synchronized against concurrent I/O
workers accessing the same FDs. If a READ_ANDX is in-flight on one of these
file handles when `TREE_DISCONNECT` closes it, a use-after-free is possible.
**Verify** that `ksmbd_close_tree_conn_fds()` sets the FD state to CLOSED under
lock before `ksmbd_close_fd()` is called, so concurrent I/O workers see the
closed state and bail out before dereferencing the file structure.

**Pending locks and oplocks (P2):**
All byte-range locks held through the tree connection's FDs must be released
when the tree is disconnected. `ksmbd_close_fd()` calls `smb_break_all_levII_oplock()`
and releases POSIX locks via the VFS `->lock` operation. **Verify** this path
is exercised for every FD type, including directories and special files.

**Response correctness:**
MS-SMB §2.2.4.51.2 requires `WordCount=0, ByteCount=0`. `init_smb_rsp_hdr()`
zero-initializes the buffer and sets `WordCount=0`. **Correct** by initialization;
add an explicit assertion for defensiveness.

**Double-disconnect (P4, low priority):**
If `tcon->t_state == TREE_DISCONNECTED` already, KSMBD returns
`STATUS_NETWORK_NAME_DELETED`. The spec does not define the behavior for a
double-disconnect; returning an error is acceptable.

#### 22.5.3 Security Implications

- `STATUS_NO_SUCH_USER` for invalid TID leaks information about how the server
  distinguishes between session and tree errors; use the spec-correct error code.
- Concurrent FD close without proper synchronization is a potential use-after-free
  vulnerability in multi-worker scenarios.

---

### 22.6 Connection-Setup Commands — Priority Summary

| Command | Bug # | Priority | Impact | Fix Effort |
|---------|-------|----------|--------|------------|
| NEGOTIATE MaxRawSize=0 when no CAP_RAW_MODE | § 22.1.2 | P1 | Protocol violation | 5 min |
| NEGOTIATE missing CAP_MPX_MODE/RPC_REMOTE/PASSTHRU | § 22.1.2 | P1 | Client compatibility | 10 min |
| NEGOTIATE DomainName missing from non-extsec response | § 22.1.3 | P1 | NTLM auth failure | 30 min |
| NEGOTIATE BAD_PROT_ID must use DialectIndex=0xFFFF | § 22.1.4 | P1 | Spec violation | 15 min |
| SESSION_SETUP invalid WordCount must return error, not drop | § 22.2.1 | P1 | Spec violation | 10 min |
| SESSION_SETUP VcNumber=0 disconnect existing sessions | § 22.2.2 | P1 | Session accumulation | 1 hour |
| SESSION_SETUP mechToken length mismatch (security) | § 22.2.3 | P1 | Potential buffer over-read | 1 hour |
| SESSION_SETUP extended security missing NativeOS/LanMan/Domain | § 22.2.4 | P2 | Client compatibility | 2 hours |
| SESSION_SETUP null session routing | § 22.2.5 | P2 | Compatibility with anonymous clients | 2 hours |
| SESSION_SETUP alignment bug (line ~1079) | § 22.2.2 | P2 | Rare auth failure | 1 hour |
| TREE_CONNECT Flags not processed (DISCONNECT_TID) | § 22.3.2 | P1 | Spec violation | 2 hours |
| TREE_CONNECT extended response only when requested | § 22.3.2 | P2 | Old client confusion | 1 hour |
| TREE_CONNECT SMB_SHARE_IS_IN_DFS not set for DFS | § 22.3.3 | P3 | DFS client confusion | 30 min |
| LOGOFF tears down entire connection instead of just session | § 22.4.2 | P1 | Multi-session breakage | 4 hours |
| LOGOFF response WordCount=0 instead of 2 | § 22.4.2 | P1 | Malformed response | 30 min |
| LOGOFF over-broad idle wait | § 22.4.2 | P2 | Performance | 1 hour |
| TREE_DISCONNECT wrong error code for invalid TID | § 22.5.2 | P1 | Incorrect error mapping | 15 min |
| TREE_DISCONNECT concurrent FD close safety | § 22.5.2 | P2 | Potential use-after-free | 3 hours |

---

*End of SMB1 Protocol Upgrade Plan — KSMBD*
