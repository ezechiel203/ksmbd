# SMB1 TRANSACTION and TRANSACTION2 Compliance Plan for KSMBD

**Document version:** 1.0
**Date:** 2026-03-01
**Scope:** MS-SMB §2.2.4.33 (SMB_COM_TRANSACTION 0x25) and §2.2.4.34 (SMB_COM_TRANSACTION2 0x32) and all subcommands, secondary packets, and NT_TRANSACT (0xA0).

---

## 1. Executive Summary

This document is a line-by-line audit of KSMBD's current SMB1 TRANSACTION / TRANSACTION2 / NT_TRANSACT implementation against the MS-SMB specification, followed by a detailed, prioritised upgrade plan to reach 100% wire-level compliance. It covers:

- SMB_COM_TRANSACTION (0x25) and its Named Pipe / Mailslot subcommands
- SMB_COM_TRANSACTION_SECONDARY (0x26) — multi-packet reassembly
- SMB_COM_TRANSACTION2 (0x32) and all subcommand information levels
- SMB_COM_TRANSACTION2_SECONDARY (0x33) — multi-packet reassembly
- SMB_COM_NT_TRANSACT (0xA0) and NT_TRANSACT_SECONDARY (0xA1)
- Interim (pending) responses, timeout handling, and buffer layout

---

## 2. Relevant Source Files

| File | Role |
|------|------|
| `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c` | All SMB1 command handlers (9 040 lines) |
| `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1ops.c` | Command dispatch table |
| `/home/ezechiel203/ksmbd/src/include/protocol/smb1pdu.h` | Wire structs and constants |
| `/home/ezechiel203/ksmbd/src/include/protocol/smb_common.h` | Cross-version constants |
| `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1misc.c` | Misc helpers |

---

## 3. SMB_COM_TRANSACTION (0x25) — Current State

### 3.1 Dispatch Table Entry

`smb1ops.c` line 59:
```c
[SMB_COM_TRANSACTION] = { .proc = smb_trans, },
```

The handler is `smb_trans()` in `smb1pdu.c` lines 2159–2388.

### 3.2 What `smb_trans()` Does Today

1. Parses the transaction name from the `Data` field (after setup words).
2. Accepts only paths that begin with `\PIPE\` — all others immediately return `STATUS_NOT_SUPPORTED`.
3. Within `\PIPE\`:
   - `\PIPE\LANMAN` → calls `ksmbd_rpc_rap()` for Remote Administration Protocol.
   - `\PIPE\<anything-else>` but subcommand is `TRANSACT_DCERPCCMD` (0x0026) → calls `ksmbd_rpc_ioctl()`.
   - All other subcommands → `STATUS_NOT_SUPPORTED`.
4. Builds a fixed 10-word response at offset 56 (hardcoded magic number for DataOffset).

### 3.3 Gap Analysis: Named Pipe Subcommands

MS-SMB §2.2.4.33 defines the following setup word values for `SMB_COM_TRANSACTION` over named pipes. The header already defines them (smb1pdu.h lines 65–75):

```c
#define TRANS_SET_NMPIPE_STATE      0x0001
#define TRANS_RAW_READ_NMPIPE       0x0011
#define TRANS_QUERY_NMPIPE_STATE    0x0021
#define TRANS_QUERY_NMPIPE_INFO     0x0022
#define TRANS_PEEK_NMPIPE           0x0023
#define TRANS_TRANSACT_NMPIPE       0x0026   /* <- only one handled */
#define TRANS_RAW_WRITE_NMPIPE      0x0031
#define TRANS_READ_NMPIPE           0x0036
#define TRANS_WRITE_NMPIPE          0x0037
#define TRANS_WAIT_NMPIPE           0x0053
#define TRANS_CALL_NMPIPE           0x0054
```

Current `smb_trans()` only handles `TRANS_TRANSACT_NMPIPE` (0x0026) and `\PIPE\LANMAN` (RAP). All other subcommands return `STATUS_NOT_SUPPORTED`.

**Only `TRANSACT_DCERPCCMD` (≡ `TRANS_TRANSACT_NMPIPE`) and `LANMAN` RAP calls are implemented.**

### 3.4 Named Pipe Subcommand Specification

#### TRANS_TRANSACT_NMPIPE (0x0026) — Implemented

Wire format (request):
- `Setup[0]` = 0x0026
- `Setup[1]` = named-pipe FID
- `Parameters` = empty (0 bytes)
- `Data` = data to write into the pipe (the DCE/RPC fragment)

Wire format (response):
- `Parameters` = empty
- `Data` = data read back from the pipe (the DCE/RPC response fragment)
- `DataOffset` = 56 (relative to &Protocol)

KSMBD delegates to `ksmbd_rpc_ioctl()` → `ksmbd.mountd`. Functionally correct. No gap here.

#### TRANS_SET_NMPIPE_STATE (0x0001) — Missing

Request:
- `Setup[0]` = 0x0001, `Setup[1]` = FID
- `Parameters[0..1]` = PipeState word (PIPE_READ_MODE 0x0100, NAMED_PIPE_TYPE 0x0400, BLOCKING_NAMED_PIPE 0x8000, ICOUNT_MASK 0x00FF)
- `Data` = empty

Response:
- `Parameters` = empty, `Data` = empty, success or error status

Implementation note: For KSMBD's RPC pipe model (ksmbd.mountd manages the named pipe instances as in-memory objects), this subcommand's state needs to be stored per-FID. At minimum return `STATUS_SUCCESS` and log the requested mode; full fidelity requires storing PIPE_READ_MODE in the session RPC handle.

#### TRANS_QUERY_NMPIPE_STATE (0x0021) — Missing

Request:
- `Setup[0]` = 0x0021, `Setup[1]` = FID
- `Parameters` = empty, `Data` = empty

Response:
- `Parameters[0..1]` = current PipeState word (same bit layout as SET)
- `Data` = empty

#### TRANS_QUERY_NMPIPE_INFO (0x0022) — Missing

Request:
- `Setup[0]` = 0x0022, `Setup[1]` = FID
- `Parameters[0..1]` = Level (0x0001 = basic info)

Response (level 1):
- `Data`:
  - `OutputBufferSize` (USHORT): server output buffer size (suggest 4096)
  - `InputBufferSize`  (USHORT): server input buffer size (suggest 4096)
  - `MaximumInstances` (UCHAR): maximum simultaneous pipe instances
  - `CurrentInstances` (UCHAR): current instance count
  - `PipeNameLength`   (UCHAR): pipe name byte length (excluding null)
  - `PipeName`         (variable, OEM string)

This information can be static/hardcoded for KSMBD's pipe model.

#### TRANS_PEEK_NMPIPE (0x0023) — Missing

Request:
- `Setup[0]` = 0x0023, `Setup[1]` = FID
- `Parameters` = empty, `Data` = empty

Response:
- `Parameters`:
  - `ReadDataAvailable` (USHORT): bytes available to read
  - `MessageBytesLength` (USHORT): size of next message (0 for byte-stream)
  - `NamedPipeState` (USHORT): current pipe state flags
- `Data` = up to `MaxDataCount` bytes peeked without consuming

For KSMBD's unidirectional RPC pipe model, `ReadDataAvailable` = 0 and return `STATUS_SUCCESS`. Full implementation would require buffering RPC responses.

#### TRANS_RAW_READ_NMPIPE (0x0011) — Missing

Request:
- `Setup[0]` = 0x0011, `Setup[1]` = FID
- `Parameters` = empty, `Data` = empty

Response:
- `Parameters` = empty
- `Data` = raw bytes read from pipe

Equivalent to `ReadFile` on a named pipe. KSMBD can map this to `ksmbd_rpc_read()` / `ksmbd_session_rpc_ioctl()`.

#### TRANS_RAW_WRITE_NMPIPE (0x0031) — Missing

Request:
- `Setup[0]` = 0x0031, `Setup[1]` = FID
- `Parameters` = empty
- `Data` = bytes to write raw into pipe

Equivalent to `WriteFile` on a named pipe.

#### TRANS_READ_NMPIPE (0x0036) — Missing

Reads the next message from a message-mode pipe. The spec requires the server to read one complete message and return it. In KSMBD's byte-stream model this is equivalent to RAW_READ.

#### TRANS_WRITE_NMPIPE (0x0037) — Missing

Writes a single message to a message-mode pipe.

#### TRANS_WAIT_NMPIPE (0x0053) — Missing

Request:
- `Setup[0]` = 0x0053
- `Parameters[0..1]` = Timeout (ms, 0xFFFFFFFF = infinite)
- `Data[0..N-1]` = pipe name (Unicode or OEM)

The server waits until a pipe instance becomes available or timeout expires, then responds. For KSMBD, since all pipe instances are always available (one virtual instance per connection), respond immediately with `STATUS_SUCCESS`.

#### TRANS_CALL_NMPIPE (0x0054) — Missing

Open + Transact + Close in one operation:
- `Setup[0]` = 0x0054
- `Data` = write buffer
- `Parameters` = empty

Response:
- `Data` = read buffer (the pipe response)

The server opens the named pipe, writes the request data, reads the response, and closes the pipe — atomically. For KSMBD this means: `ksmbd_session_rpc_open()` → `ksmbd_rpc_ioctl()` → `ksmbd_session_rpc_close()`.

#### RAPCommand via \PIPE\LANMAN (0x0000) — Partially Implemented

Current `smb_trans()` correctly calls `ksmbd_rpc_rap()` for the `\PIPE\LANMAN` target. The gaps are:

1. **Subcommand routing**: `pipedata` is passed verbatim to `ksmbd_rpc_rap()` but the RAP subcommand value (`Function` word at offset 0 of ParameterBytes) is not validated or logged. The server should return `STATUS_NOT_SUPPORTED` for unsupported RAP functions rather than `STATUS_INVALID_PARAMETER` for all failures.
2. **Response fragmentation**: If the RAP response exceeds `work->response_sz - sizeof(smb_com_trans_rsp)`, the current code sets `STATUS_INVALID_PARAMETER` and truncates. Per spec it should return `STATUS_MORE_PROCESSING_REQUIRED` (0x00000105) with partial data and use the `DataOffset` + `TotalDataCount` fields correctly for the client to reassemble.
3. **ParameterCount in response**: The response always sets `ParameterCount = param_len = 0`. RAP responses must carry a `Converter` USHORT and `EntriesReturned`/`TotalEntries` in the parameter bytes.

#### Mailslot Write — Missing

`SMB_COM_TRANSACTION` to `\MAILSLOT\*` is not routed at all: when the name does not start with `\PIPE\`, `smb_trans()` immediately returns `STATUS_NOT_SUPPORTED`. Mailslot writes are write-only, no response is expected (one-way). The wire format is:

- Transaction name = `\MAILSLOT\<slot-name>` (Unicode or OEM)
- `Setup[0]` = Priority (1–9), `Setup[1]` = Class (2 = second class, unreliable)
- `Parameters` = empty
- `Data` = payload

Response: for Class 2, the server sends no SMB response (it is a fire-and-forget datagram). For Class 1, a short response is sent.

KSMBD currently returns `STATUS_NOT_SUPPORTED` for all mailslot traffic. Since KSMBD does not implement the mailslot subsystem, the correct response per spec is `STATUS_NOT_SUPPORTED` for Class 1 and silent discard for Class 2. However, the code should explicitly detect `\MAILSLOT\` and handle each class properly rather than falling through the `\PIPE\` check.

---

## 4. SMB_COM_TRANSACTION_SECONDARY (0x26) — Multi-Packet Reassembly

### 4.1 Current State

The command `SMB_COM_TRANSACTION_SECONDARY` (0x26) appears in the `smb_cmd_str[]` table entry (line 72 refers to TRANSACTION2_SECONDARY, but there is no `[SMB_COM_TRANSACTION_SECONDARY]` entry in the dispatch table in `smb1ops.c`). There is **no dispatch table entry** for 0x26 and **no handler function**.

`smb_allocate_rsp_buf()` correctly allocates a large buffer for `SMB_COM_TRANSACTION`, but secondary packets are ignored.

### 4.2 Specification Requirements

When a `SMB_COM_TRANSACTION` request exceeds `MaxBufferSize`, the client sends the first part with `SMB_COM_TRANSACTION` and subsequent parts with `SMB_COM_TRANSACTION_SECONDARY` (0x26).

`SMB_COM_TRANSACTION_SECONDARY` wire format:
```
WordCount           UCHAR  = 8
TotalParameterCount USHORT  total bytes of Parameters
TotalDataCount      USHORT  total bytes of Data
ParameterCount      USHORT  bytes of Parameters in this PDU
ParameterOffset     USHORT  offset from &Protocol to ParameterBytes
ParameterDisplacement USHORT where in the total param buffer these go
DataCount           USHORT  bytes of Data in this PDU
DataOffset          USHORT  offset from &Protocol to DataBytes
DataDisplacement    USHORT  where in the total data buffer these go
FID                 USHORT  (for named-pipe secondary packets)
ByteCount           USHORT
Pad+ParameterBytes+DataBytes (variable)
```

No response is sent for secondary packets; the server accumulates them and sends one response after the final piece arrives (`ParameterDisplacement + ParameterCount == TotalParameterCount` and `DataDisplacement + DataCount == TotalDataCount`).

The server must:
1. Match the secondary packet to the pending primary request via `MID` (MessageID).
2. Append the partial `ParameterBytes` and `DataBytes` into a reassembly buffer.
3. When fully assembled, call the subcommand handler.

### 4.3 Reassembly Infrastructure Required

KSMBD has no reassembly state machine for TRANSACTION or TRANSACTION2. The following must be added:

```c
struct smb_transaction_state {
    struct list_head        list;
    __le16                  mid;           /* match key */
    unsigned char           cmd;           /* 0x25 or 0x32 or 0xA0 */
    unsigned char          *param_buf;    /* reassembled params */
    unsigned char          *data_buf;     /* reassembled data */
    __u16                   param_total;
    __u16                   data_total;
    __u16                   param_received;
    __u16                   data_received;
    struct timer_list       timeout;       /* spec-defined Timeout field */
    /* ... */
};
```

This state must be per-connection (list on `struct ksmbd_conn`) and protected by a spinlock. The timeout from the primary packet's `Timeout` field (in milliseconds) must arm a timer that releases the state and sends `STATUS_IO_TIMEOUT` if the secondary packets never arrive.

---

## 5. SMB_COM_TRANSACTION2 (0x32) — Current State and Gap Analysis

### 5.1 Dispatch Table Entry

```c
[SMB_COM_TRANSACTION2] = { .proc = smb_trans2, },
```

`smb_trans2()` at line 7809 dispatches on `req->SubCommand`:

```c
case TRANS2_FIND_FIRST:      find_first(work);       /* implemented */
case TRANS2_FIND_NEXT:       find_next(work);        /* implemented */
case TRANS2_QUERY_FS_INFORMATION: query_fs_info(work); /* partially impl. */
case TRANS2_QUERY_PATH_INFORMATION: query_path_info(work); /* partially impl. */
case TRANS2_SET_PATH_INFORMATION: set_path_info(work); /* partially impl. */
case TRANS2_SET_FS_INFORMATION: set_fs_info(work);   /* partially impl. */
case TRANS2_QUERY_FILE_INFORMATION: query_file_info(work); /* partially impl. */
case TRANS2_SET_FILE_INFORMATION: set_file_info(work); /* partially impl. */
case TRANS2_CREATE_DIRECTORY: create_dir(work);       /* implemented */
case TRANS2_GET_DFS_REFERRAL:  /* falls through to default -> -EINVAL */
default: -EINVAL
```

Missing subcommands: `TRANS2_OPEN` (0x00), `TRANS2_FSCTL` (0x09), `TRANS2_IOCTL2` (0x0A), `TRANS2_FIND_NOTIFY_FIRST` (0x0B), `TRANS2_FIND_NOTIFY_NEXT` (0x0C), `TRANS2_SESSION_SETUP` (0x0E), `TRANS2_GET_DFS_REFERRAL` (0x10), `TRANS2_REPORT_DFS_INCONSISTENCY` (0x11).

---

### 5.2 TRANS2_FIND_FIRST2 (0x0001) — `find_first()`

#### What is implemented

- Parses `smb_com_trans2_ffirst_req_params` from the request.
- Opens the directory, iterates with `iterate_dir()`.
- Populates entries for the following InformationLevels:
  - `SMB_FIND_FILE_INFO_STANDARD` (0x0001) — struct `find_info_standard`
  - `SMB_FIND_FILE_QUERY_EA_SIZE` (0x0002) — struct `find_info_query_ea_size`
  - `SMB_FIND_FILE_DIRECTORY_INFO` (0x0101) — struct `file_directory_info`
  - `SMB_FIND_FILE_FULL_DIRECTORY_INFO` (0x0102) — struct `file_full_directory_info`
  - `SMB_FIND_FILE_NAMES_INFO` (0x0103) — struct `file_names_info`
  - `SMB_FIND_FILE_BOTH_DIRECTORY_INFO` (0x0104) — struct `file_both_directory_info`
  - `SMB_FIND_FILE_ID_FULL_DIR_INFO` (0x0105) — struct `file_id_full_dir_info`
  - `SMB_FIND_FILE_ID_BOTH_DIR_INFO` (0x0106) — struct `file_id_both_directory_info`
  - `SMB_FIND_FILE_UNIX` (0x0202) — struct `file_unix_info`

#### Gaps

**1. `SMB_FIND_FILE_EAS_FROM_LIST` (0x0003) — Missing**

The request includes a GEAList specifying which EAs to retrieve per entry. The response for each directory entry must include a `FEAList` with values for those EAs (or zeros if not present). This level is defined in MS-SMB §2.2.4.34.8 and requires calling `ksmbd_vfs_getxattr()` per entry.

**2. Search Flags — Partially handled**

The `Flags` word in the request parameters has the following bits:

| Bit | Name | Handled? |
|-----|------|----------|
| 0x0001 | CLOSE_AFTER_REQUEST | No |
| 0x0002 | CLOSE_AT_EOS | Partially (see find_first line 6766) |
| 0x0004 | RETURN_RESUME_KEYS | No |
| 0x0008 | CONTINUE_FROM_LAST | No |
| 0x0010 | FIND_WITH_BACKUP_INTENT | No |

`CLOSE_AFTER_REQUEST`: if set, the server must close the search handle immediately after sending the response. The current code does not check this flag in `find_first()`.

`RETURN_RESUME_KEYS`: if set, each entry must be preceded by a 4-byte `ResumeKey` that the client can pass to `TRANS2_FIND_NEXT2` to resume. KSMBD uses `dirent.offset` for internal tracking but does not expose `ResumeKey` in the wire response.

`CONTINUE_FROM_LAST`: when set in `FIND_NEXT2`, resume from the position indicated by `ResumeKey` or `FileName`. KSMBD currently always continues from where `dir_fp->dirent_offset` left off; it does not honour a client-supplied resume position.

`FIND_WITH_BACKUP_INTENT`: if set, the client wants to perform a backup-style traversal (bypass access checks where the user has backup privilege). Not implemented.

**3. Response `SearchCount` vs actual count**

In `find_first()` the `params->SearchCount` in the response is set correctly (line 6516+), but `EndOfSearch` is determined by whether the readdir buffer was fully consumed. This is correct for the common case, but when `CLOSE_AT_EOS` is set and `EndOfSearch == 1`, the search FID must be auto-closed.

**4. `EaErrorOffset` in response**

`smb_com_trans2_ffirst_rsp_parms.EaErrorOffset` is always set to 0. Per spec it must be the byte offset within the `ResultData` buffer of the first EA error, or 0 if no errors. For level `SMB_FIND_FILE_EAS_FROM_LIST` this field is significant.

**5. `LastNameOffset` correctness**

`LastNameOffset` in the response should be the byte offset from the start of `ResultData` to the last entry's `FileName` field, for resume purposes. Currently `d_info.last_entry_offset` is the offset to the start of the last entry structure, not specifically to its `FileName` sub-field. For the `SMB_FIND_FILE_INFO_STANDARD` level (which has a fixed-length record), this does not matter, but for variable-length levels it is technically incorrect.

---

### 5.3 TRANS2_FIND_NEXT2 (0x0002) — `find_next()`

#### What is implemented

- Looks up `dir_fp` by `SearchHandle` (SID).
- Iterates the directory continuing from where `dir_fp->dirent_offset` left off.
- Populates entries with the same information levels as `find_first()`.
- Honoring `CIFS_SEARCH_CLOSE_AT_END` flag (line 6765).

#### Gaps

**1. Resume by `FileName` — Missing**

The spec requires: if `CONTINUE_FROM_LAST` is clear and a `FileName` is provided, the server must restart the enumeration from the first entry whose name is >= the given name. KSMBD ignores `req_params->FileName` in `find_next()` entirely.

**2. Resume by `ResumeKey` — Missing**

If `RETURN_RESUME_KEYS` was set in `FIND_FIRST2` and a `ResumeKey` is provided, the server must resume from the matching entry. Not implemented.

**3. `CLOSE_AFTER_REQUEST` flag in FIND_NEXT2**

Same gap as FIND_FIRST2: the flag is not checked.

---

### 5.4 TRANS2_QUERY_FS_INFORMATION (0x0003) — `query_fs_info()`

#### What is implemented

| Level | Constant | Handled |
|-------|----------|---------|
| 0x0001 | SMB_INFO_ALLOCATION | Yes |
| 0x0102 | SMB_QUERY_FS_VOLUME_INFO | Yes |
| 0x0103 | SMB_QUERY_FS_SIZE_INFO | Yes |
| 0x0104 | SMB_QUERY_FS_DEVICE_INFO | Yes |
| 0x0105 | SMB_QUERY_FS_ATTRIBUTE_INFO | Yes (partially) |
| 0x0200 | SMB_QUERY_CIFS_UNIX_INFO | Yes |
| 0x0201 | SMB_QUERY_POSIX_FS_INFO | Yes |
| 0x0106 (not standard) | SMB_QUERY_FS_FULL_SIZE_INFO | Yes |

#### Gaps

**1. `SMB_INFO_VOLUME` (0x0002) — Missing**

Response layout:
```
VolumeSerialNumber  ULONG
VolumeLabelSize     UCHAR  (byte length of label, not char count)
VolumeLabel         variable (OEM string, not Unicode)
```
This is the legacy (pre-NT) volume info level. It differs from `SMB_QUERY_FS_VOLUME_INFO` (0x0102) in that it returns an OEM string and a ULONG serial number. Windows XP and some legacy clients use this level.

**2. `SMB_QUERY_FS_ATTRIBUTE_INFO` (0x0105) — Incomplete**

Current code (line 5036–5042):
```c
info->Attributes = cpu_to_le32(FILE_CASE_PRESERVED_NAMES |
                               FILE_CASE_SENSITIVE_SEARCH |
                               FILE_VOLUME_QUOTAS);
info->MaxPathNameComponentLength = cpu_to_le32(stfs.f_namelen);
info->FileSystemNameLen = 0;
rsp->t2.TotalDataCount = cpu_to_le16(12);
```

`FileSystemNameLen = 0` means no file system name is returned. The spec requires `FileSystemName` (Unicode) to follow, e.g. "NTFS". The `TotalDataCount` must include `12 + FileSystemNameLen`. Without the filesystem name some clients fall back to compatibility modes.

Fix: append the string `NTFS` (8 bytes Unicode) and set `FileSystemNameLen = 8` and `TotalDataCount = 20`.

**3. `SMB_QUERY_POSIX_WHO_AM_I` (0x0202) — Missing**

Response:
```
MappedUID     ULONG  (effective UID as seen by the server)
MappedGID     ULONG  (effective GID)
NumSIDs       ULONG  (number of SIDs, always 0 for this level)
PadSID...
```
This is used by the CIFS Linux client to verify credential mapping.

**4. `SMB_QUERY_FS_PROXY` (0x0203) — Missing**

Defined for DFS proxy filesystems. Should return `STATUS_NOT_SUPPORTED` explicitly (not just fall through to the `default:` clause with `-EINVAL`).

**5. Incomplete `query_fs_info()` for IPC shares**

Lines 4922–4923:
```c
if (test_share_config_flag(share, KSMBD_SHARE_FLAG_PIPE))
    return -ENOENT;
```
This is incorrect: the spec requires a valid response (or `STATUS_ACCESS_DENIED`) for FS queries on IPC$. Some levels (e.g., `SMB_QUERY_FS_DEVICE_INFO` with DeviceType = FILE_DEVICE_NAMED_PIPE) should succeed on IPC$.

---

### 5.5 TRANS2_SET_FS_INFORMATION (0x0004) — `set_fs_info()`

#### What is implemented

Only `SMB_SET_CIFS_UNIX_INFO` (0x200). All other levels return `-EINVAL`.

#### Gaps

The spec defines very few settable FS levels; most are read-only. The following need explicit `STATUS_NOT_SUPPORTED` (not `STATUS_INVALID_PARAMETER`) for unrecognised levels:

- 0x0001 `SMB_INFO_VOLUME` — read-only, not settable
- 0x0002 `SMB_INFO_VOLUME_ALLOCATION` — not settable
- 0x0102–0x0105 — read-only

Current code returns `-EINVAL` which maps to `STATUS_NOT_SUPPORTED` (line 7865). This is acceptable but the correct NTSTATUS is `STATUS_INVALID_LEVEL` (0xC0000148) for unknown levels and `STATUS_ACCESS_DENIED` for known read-only levels.

---

### 5.6 TRANS2_QUERY_PATH_INFORMATION (0x0005) — `query_path_info()`

#### What is implemented

| Level | Constant | Handled |
|-------|----------|---------|
| 0x0001 | SMB_INFO_STANDARD | Yes |
| 0x0101 | SMB_QUERY_FILE_BASIC_INFO | Yes |
| 0x0102 | SMB_QUERY_FILE_STANDARD_INFO | Yes |
| 0x0103 | SMB_QUERY_FILE_EA_INFO | Yes (stub, EaSize=0) |
| 0x0104 | SMB_QUERY_FILE_NAME_INFO | Yes |
| 0x0107 | SMB_QUERY_FILE_ALL_INFO | Yes (partial — FileName populated) |
| 0x0108 | SMB_QUERY_ALT_NAME_INFO | Yes |
| 0x0200 | SMB_QUERY_FILE_UNIX_BASIC | Yes |
| 0x0201 | SMB_QUERY_FILE_UNIX_LINK | Yes (readlink) |
| 0x0204 | SMB_QUERY_POSIX_ACL | Yes (getxattr POSIX ACL) |
| 0x010E | SMB_QUERY_FILE_INTERNAL_INFO | Yes |
| 0x0004 | SMB_INFO_QUERY_ALL_EAS | Yes (list xattrs) |

#### Gaps

**1. `SMB_INFO_QUERY_EA_SIZE` (0x0002) — Missing**

Response:
```
CreationDate    DOS_DATE
CreationTime    DOS_TIME
LastAccessDate  DOS_DATE
LastAccessTime  DOS_TIME
LastWriteDate   DOS_DATE
LastWriteTime   DOS_TIME
DataSize        ULONG
AllocationSize  ULONG
Attributes      USHORT
EASize          ULONG   <- total size of all EAs
```
This is the SMB_INFO_STANDARD layout (22 bytes) plus a 4-byte `EASize` appended. The current handler for `SMB_INFO_STANDARD` does not append `EASize`. Since `SMB_INFO_QUERY_EA_SIZE` has a different level code, it falls to the `default:` clause.

**2. `SMB_INFO_QUERY_EAS_FROM_LIST` (0x0003) — Missing**

Request includes a `GEAList` parameter specifying which EA names to retrieve.
Response: `FEAList` with values of the requested EAs (or zeros for absent EAs).
This requires per-name xattr lookups.

**3. `SMB_INFO_IS_NAME_VALID` (0x0006) — Missing**

Request: the path to validate.
Response: `STATUS_SUCCESS` if the path is a valid name (does not need to exist), `STATUS_OBJECT_NAME_INVALID` otherwise.
Implementation: check for illegal characters (NUL, control chars, `"`, `*`, `?`, `<`, `>`, `|`, `:`) per MS-SMB §2.2.4.34.5.3.

**4. `SMB_QUERY_FILE_COMPRESSION_INFO` (0x010B) — Missing**

Response:
```
CompressedFileSize  LARGE_INTEGER  (same as file size if uncompressed)
CompressionFormat   USHORT         (0 = none)
CompressionUnitShift UCHAR
ChunkShift          UCHAR
ClusterShift        UCHAR
Reserved            UCHAR[3]
```
For Linux filesystems (not NTFS), return `CompressedFileSize = FileSize`, `CompressionFormat = 0`. This is purely informational.

**5. `SMB_QUERY_FILE_UNIX_HLINK` (0x0203) — Missing**

Response: the number of hard links (`st.nlink`). A simple 4-byte ULONG or LARGE_INTEGER depending on the client's request.

**6. `SMB_QUERY_FILE_UNIX_XATTR` / `SMB_QUERY_XATTR` (0x0205) — Missing**

Extended attribute query for CIFS Unix extensions. Similar to `SMB_INFO_QUERY_ALL_EAS` but using the CIFS Unix xattr namespace.

**7. `SMB_QUERY_ATTR_FLAGS` (0x0206) — Missing**

Returns CIFS Unix attribute flags (dosattr field). Requires reading xattr-stored DOS attributes.

**8. `SMB_QUERY_FILE_ACCESS_INFO` (0x010F) — Missing**

Response: `AccessFlags` ULONG (the granted access mask for the file at the given path).
For path-based queries this requires a temporary open to determine access.

**9. `SMB_QUERY_FILE_POSITION_INFO` (0x0114) — Missing**

Response: `CurrentByteOffset` LARGE_INTEGER. Only meaningful for an open FID; for path queries, 0.

**10. `SMB_QUERY_FILE_MODE_INFO` (0x0116) — Missing**

Response: `Mode` ULONG (file mode flags like `FILE_WRITE_THROUGH`, `FILE_NO_INTERMEDIATE_BUFFERING`). Return 0 for path queries.

**11. `SMB_QUERY_FILE_ALIGNMENT_INFO` (0x0117) — Missing**

Response: `AlignmentRequirement` ULONG (0 for no alignment requirement).

**12. `SMB_QUERY_FILE_NETWORK_OPEN_INFO` (0x0122) — Missing**

Response: 56 bytes combining basic info + standard info + access flags:
```
CreationTime        LARGE_INTEGER
LastAccessTime      LARGE_INTEGER
LastWriteTime       LARGE_INTEGER
ChangeTime          LARGE_INTEGER
AllocationSize      LARGE_INTEGER
EndOfFile           LARGE_INTEGER
FileAttributes      ULONG
```
This is essentially `FILE_NETWORK_OPEN_INFORMATION` from the NT passthrough range.

**13. `SMB_QUERY_FILE_ALL_INFO` (0x0107) — Incomplete**

Current code (line 4579–4655) populates the struct but `EASize = 0` is always set. The spec says `EASize` must be the total size of the file's EA store. For Linux xattr compliance, call `ksmbd_vfs_listxattr()` + sum up value sizes.

---

### 5.7 TRANS2_SET_PATH_INFORMATION (0x0006) — `set_path_info()`

#### What is implemented

| Level | Constant | Handled |
|-------|----------|---------|
| 0x0101 / 0x0102 | SMB_SET_FILE_BASIC_INFO / SMB_SET_FILE_BASIC_INFO2 | Yes |
| 0x0200 | SMB_SET_FILE_UNIX_BASIC | Yes |
| 0x0201 | SMB_SET_FILE_UNIX_LINK (symlink create) | Yes |
| 0x0203 | SMB_SET_FILE_UNIX_HLINK (hardlink create) | Yes |
| 0x0204 | SMB_SET_POSIX_ACL | Yes |
| 0x0205 | SMB_POSIX_OPEN | Yes (via smb_posix_open) |
| 0x0206 | SMB_POSIX_UNLINK | Yes |
| SMB_SET_FILE_EA | SMB_SET_FILE_EA | Yes |
| 0x0104 | SMB_SET_FILE_END_OF_FILE_INFO / INFO2 | Yes |

#### Gaps

**1. `SMB_SET_FILE_DISPOSITION_INFO` (0x0102 = DELETE_ON_CLOSE) — Missing from `set_path_info()`**

This is handled in `set_file_info()` but not in `set_path_info()`. Per spec, both the path-based and FID-based variants exist. A path-based disposition set opens the file, sets delete-on-close, and closes it.

**2. `SMB_SET_FILE_ALLOCATION_INFO` (0x0103) — Missing from `set_path_info()`**

Present in `set_file_info()` but not `set_path_info()`. Should open the file by path, truncate, and close.

**3. `SMB_INFO_STANDARD` (0x0001) — Missing**

Setting timestamps via the legacy DOS format (CreationDate/Time + LastAccessDate/Time + LastWriteDate/Time + DataSize + AllocationSize + Attributes). A simple extension of `smb_set_time_pathinfo()` to parse the DOS timestamp format.

**4. Parameter block minimum size validation**

`set_path_info()` checks `total_param < 7`. This minimum should be `sizeof(trans2_qpi_req_params)` = 6 bytes (USHORT InformationLevel + ULONG Reserved + FileName). Some subcommands have no data payload at all (e.g., `SMB_INFO_IS_NAME_VALID`). The check should be per-level.

---

### 5.8 TRANS2_QUERY_FILE_INFORMATION (0x0007) — `query_file_info()`

#### What is implemented

| Level | Handled |
|-------|---------|
| SMB_QUERY_FILE_STANDARD_INFO (0x0102) | Yes |
| SMB_QUERY_FILE_BASIC_INFO (0x0101) | Yes |
| SMB_QUERY_FILE_EA_INFO (0x0103) | Yes (stub) |
| SMB_QUERY_FILE_UNIX_BASIC (0x0200) | Yes |
| SMB_QUERY_FILE_ALL_INFO (0x0107) | Yes (FileNameLength=0) |

For IPC shares, only `SMB_QUERY_FILE_STANDARD_INFO` is handled and `DeletePending` is hardcoded to 1 (line 7020–7021 — **bug**: two assignments to `DeletePending`).

#### Gaps

Same set as `TRANS2_QUERY_PATH_INFORMATION` except the lookup is by FID rather than path:

1. `SMB_QUERY_FILE_NAME_INFO` (0x0104) — Missing for FID-based queries.
2. `SMB_QUERY_ALT_NAME_INFO` / `SMB_QUERY_FILE_ALT_NAME_INFO` (0x0108) — Missing.
3. `SMB_QUERY_FILE_STREAM_INFO` (0x0109) — Missing. Should return one stream entry (`::$DATA`) with size and allocation size. Named streams are not supported.
4. `SMB_QUERY_FILE_COMPRESSION_INFO` (0x010B) — Missing.
5. `SMB_QUERY_FILE_INTERNAL_INFO` (0x010E) — Missing.
6. `SMB_QUERY_FILE_ACCESS_INFO` (0x010F) — Missing.
7. `SMB_QUERY_FILE_NETWORK_OPEN_INFO` (0x0122) — Missing.

**Bug in `query_file_info_pipe()`:**
Lines 7020–7021:
```c
standard_info->DeletePending = 0;
standard_info->Directory = 0;
standard_info->DeletePending = 1;   /* <-- second write overwrites first */
```
The second write is likely a copy-paste error. `DeletePending` should be 0 for open pipe handles.

---

### 5.9 TRANS2_SET_FILE_INFORMATION (0x0008) — `set_file_info()`

#### What is implemented

| Level | Handled |
|-------|---------|
| SMB_SET_FILE_EA | Yes |
| SMB_SET_FILE_ALLOCATION_INFO / INFO2 | Yes |
| SMB_SET_FILE_END_OF_FILE_INFO / INFO2 | Yes |
| SMB_SET_FILE_UNIX_BASIC | Yes |
| SMB_SET_FILE_DISPOSITION_INFO / INFORMATION | Yes |
| SMB_SET_FILE_BASIC_INFO / INFO2 | Yes |
| SMB_SET_FILE_RENAME_INFORMATION | Yes |

#### Gaps

**1. `SMB_SET_FILE_ALLOCATION_INFO` path vs FID semantics**

`smb_set_alloc_size()` rounds up the new size using `alloc_roundup_size` (default 1 MiB). Per spec, `AllocationSize` is advisory only: the server SHOULD try to preallocate but is not required to. The rounding should be documented explicitly.

**2. `SMB_SET_FILE_UNIX_LINK` and `SMB_SET_FILE_UNIX_HLINK` — Missing**

The FID-based variants of symlink/hardlink creation are not in `set_file_info()`, only in `set_path_info()`. They should be forwarded to the same `smb_creat_symlink()` / `smb_creat_hardlink()` helpers, dereferencing the path from the FID's `fp->filename`.

**3. `SMB_SET_FILE_RENAME_INFORMATION` — race condition**

`smb_fileinfo_rename()` line 7586–7592:
```c
if (info->overwrite) {
    rc = ksmbd_vfs_truncate(work, fp, 0);   /* truncate destination */
    ...
}
```
Per spec, `overwrite = 1` means replace the target if it exists, not truncate-then-rename. The truncate should be on the target file (identified by path), not the source FID. This is a semantic bug.

---

### 5.10 TRANS2_FSCTL (0x0009) — Missing

This subcommand passes FSCTL codes through a TRANS2 interface. It is equivalent to `NT_TRANSACT_IOCTL` for file-system-level controls. No handler exists; the dispatch falls to `default: -EINVAL`.

Per spec, unimplemented FSCTL codes should return `STATUS_NOT_SUPPORTED`, not `STATUS_NOT_SUPPORTED` via `-EINVAL` mapping. The `smb_trans2()` error mapping for `-EINVAL` is `STATUS_NOT_SUPPORTED` (line 7865), so the net result is correct but should be explicit.

---

### 5.11 TRANS2_IOCTL2 (0x000A) — Missing

Similar to FSCTL. Should return `STATUS_NOT_SUPPORTED` for all IOCTL codes not understood.

---

### 5.12 TRANS2_FIND_NOTIFY_FIRST (0x000B) / TRANS2_FIND_NOTIFY_NEXT (0x000C) — Missing

These are legacy directory-change-notification subcommands predating `NT_TRANSACT_NOTIFY_CHANGE`. They are obsolete and Windows Vista+ clients do not send them. The correct response is `STATUS_NOT_SUPPORTED`.

---

### 5.13 TRANS2_CREATE_DIRECTORY (0x000D) — `create_dir()`

#### What is implemented

`create_dir()` parses the directory name from `ParameterOffset + 4` and calls `smb_common_mkdir()`.

#### Gaps

**1. Optional `EaList` in the `Data` block — Missing**

The spec allows the client to supply an `FEAList` (extended attribute list) in the Data block. `create_dir()` ignores the Data block entirely. For POSIX compliance, after creating the directory, the server should call `ksmbd_vfs_fsetxattr()` for each EA in the list.

**2. Response `EaErrorOffset` — Not set**

The response must include `EaErrorOffset` (a 4-byte parameter block) pointing to the first EA that could not be set, or 0 if all EAs were set successfully. `create_dir()` currently sets `ByteCount = 0` without a proper parameter block.

---

### 5.14 TRANS2_SESSION_SETUP (0x000E) — Missing

This is an obscure subcommand for additional session capabilities exchange (used by some OS/2 and older NT clients). For practical purposes, return `STATUS_NOT_SUPPORTED`. No modern client sends this; however, the dispatch table should explicitly handle it.

---

### 5.15 TRANS2_GET_DFS_REFERRAL (0x0010) — Missing

#### Current State

The dispatch (`smb_trans2()` lines 7855–7859):
```c
case TRANS2_GET_DFS_REFERRAL:
default:
    ksmbd_debug(SMB, "sub command 0x%x not implemented yet\n", sub_command);
    err = -EINVAL;
```

`TRANS2_GET_DFS_REFERRAL` falls through to the default and returns `-EINVAL` → `STATUS_NOT_SUPPORTED`.

The `smb_cmd_str[]` has entries for `TRANS2_GET_DFS_REFERRAL` and `TRANS2_REPORT_DFS_INCOSISTENCY` (the latter is misspelled in source).

#### Specification

Request:
- `Setup[0]` = 0x0010
- `Parameters`:
  - `MaxReferralLevel` (USHORT): highest referral level the client supports (1–4)
- `Data`:
  - `RequestFileName` (Unicode): the UNC path for which a referral is requested

Response `Data`:
- `PathConsumed` (USHORT): how many bytes of the path the server consumed
- `NumberOfReferrals` (USHORT): number of referral entries
- `ReferralHeaderFlags` (ULONG): `REFERRAL_FLAGS_SERVER_NAME_DECODED` etc.
- Followed by one or more `RESP_GET_DFS_REFERRAL_Entry` structures

#### Implementation Strategy

KSMBD has a DFS module (`src/fs/ksmbd_dfs.c`). The SMB2 path for DFS referrals is in `smb2_ioctl.c`. The SMB1 path needs a bridge:

1. Parse `MaxReferralLevel` and `RequestFileName` from the TRANS2 parameter+data blocks.
2. Call the existing DFS referral resolution code used by SMB2 (`ksmbd_dfs_get_referral()` or equivalent).
3. Serialise the result as TRANS2 response data using `RESP_GET_DFS_REFERRAL` wire format.
4. Cap at `MaxDataCount` and return `STATUS_MORE_PROCESSING_REQUIRED` if the referral list is too large (unlikely in practice).

The `CAP_DFS` bit is not currently set in `SMB1_SERVER_CAPS`. It must be set before implementing this subcommand, otherwise clients will not send DFS requests.

---

### 5.16 TRANS2_REPORT_DFS_INCONSISTENCY (0x0011) — Missing

The client sends this when it detects an inconsistency in DFS referrals. The server is expected to log the report and return `STATUS_SUCCESS`. No data need be returned.

---

## 6. SMB_COM_TRANSACTION2_SECONDARY (0x33)

### 6.1 Current State

The dispatch table string table records `SMB_COM_TRANSACTION2_SECONDARY` (line 72):
```c
[SMB_COM_TRANSACTION2_SECONDARY] = "SMB_COM_TRANSACTION2_SECONDARY",
```

There is **no handler** in `smb1ops.c`'s `smb1_server_cmds[]`. The command falls to "unknown" and returns `STATUS_NOT_IMPLEMENTED` via the connection's fallback.

### 6.2 Specification Requirements

`SMB_COM_TRANSACTION2_SECONDARY` (0x33) wire format:
```
WordCount               UCHAR  = 9
TotalParameterCount     USHORT
TotalDataCount          USHORT
ParameterCount          USHORT
ParameterOffset         USHORT
ParameterDisplacement   USHORT
DataCount               USHORT
DataOffset              USHORT
DataDisplacement        USHORT
FID                     USHORT (if SetupCount > 0 in the primary)
ByteCount               USHORT
Pad+ParameterBytes+DataBytes
```

This PDU carries the remaining pieces of a `SMB_COM_TRANSACTION2` request when:
- `TotalParameterCount > MaxParameterCount` advertised in negotiate, OR
- `TotalDataCount > MaxDataCount` advertised in negotiate

The reassembly state machine described in §4.3 (for `TRANSACTION_SECONDARY`) applies equally here.

### 6.3 Observed Behaviour

`query_fs_info()` at line 4893–4913 already detects partial TRANS2 packets:
```c
if (le16_to_cpu(req->TotalParameterCount) != le16_to_cpu(req->ParameterCount)) {
    ...
    incomplete = true;
}
/* ... */
if (incomplete) {
    /* create 1 trans_state structure
     * and add to connection list
     */
}
```

The comment says the state structure should be created but the body is **empty** — no reassembly is performed. The `TRANS2_QUERY_FS_INFORMATION` handler silently reads from a potentially incomplete buffer.

---

## 7. SMB_COM_NT_TRANSACT (0xA0)

### 7.1 Current State

`SMB_COM_NT_TRANSACT` has a string table entry (line 80):
```c
[SMB_COM_NT_TRANSACT] = "SMB_COM_NT_TRANSACT",
```

There is **no dispatch table entry** in `smb1ops.c`. When a client sends `SMB_COM_NT_TRANSACT`, `smb1_server_cmds[0xA0].proc` is NULL, and the connection's generic fallback sends `STATUS_NOT_IMPLEMENTED`.

The NT_TRANSACT subcommands are defined in `smb1pdu.h` lines 77–85:
```c
#define NT_TRANSACT_CREATE              0x01
#define NT_TRANSACT_IOCTL               0x02
#define NT_TRANSACT_SET_SECURITY_DESC   0x03
#define NT_TRANSACT_NOTIFY_CHANGE       0x04
#define NT_TRANSACT_RENAME              0x05
#define NT_TRANSACT_QUERY_SECURITY_DESC 0x06
#define NT_TRANSACT_GET_USER_QUOTA      0x07
#define NT_TRANSACT_SET_USER_QUOTA      0x08
```

### 7.2 NT_TRANSACT Wire Format Differences

NT_TRANSACT uses a different wire structure from TRANSACTION2:
```
WordCount           UCHAR  = 19 (max)
MaxSetupCount       UCHAR
Reserved            USHORT
TotalParameterCount ULONG  (32-bit, not 16-bit!)
TotalDataCount      ULONG
MaxParameterCount   ULONG
MaxDataCount        ULONG
ParameterCount      ULONG
ParameterOffset     ULONG
DataCount           ULONG
DataOffset          ULONG
SetupCount          UCHAR
Function            USHORT  <- subcommand
ByteCount           USHORT
Setup[]             variable
ParameterBytes      variable (aligned to DWORD)
DataBytes           variable (aligned to DWORD)
```

Key difference: all counts and offsets are **32-bit** (`ULONG`), unlike TRANSACTION2 which uses **16-bit** (`USHORT`). This allows transfers up to 4 GiB instead of 64 KiB.

### 7.3 Subcommand Analysis

#### NT_TRANSACT_CREATE (0x0001) — Missing

This is the most important NT_TRANSACT subcommand. It is equivalent to `SMB_COM_NT_CREATE_ANDX` but adds:
- **Security Descriptor**: initial SD for the new file/dir (in DataBytes)
- **Extended Attributes**: initial EAs (in ParameterBytes, after the create params)
- **Allocation Size**: specified as LARGE_INTEGER in parameters

Request parameters (94 bytes):
```
Flags                   ULONG   (extended create flags)
RootDirectoryFID        ULONG   (relative-to parent, or 0)
DesiredAccess           ACCESS_MASK
AllocationSize          LARGE_INTEGER
FileAttributes          ULONG
ShareAccess             ULONG
CreateDisposition       ULONG
CreateOptions           ULONG
SecurityDescriptorLength ULONG
EaLength                ULONG
NameLength              ULONG
ImpersonationLevel      ULONG
SecurityFlags           UCHAR
FileName                variable (unicode, NameLength bytes)
```

The handler would share code with `smb_nt_create_andx()`. Key additional steps:
1. Parse the SD from DataBytes and apply it on file creation (call `ksmbd_vfs_set_init_posix_acl()` or equivalent).
2. Parse the EA list from DataBytes (after the SD) and set xattrs.

#### NT_TRANSACT_IOCTL (0x0002) — Missing

This is the primary way NT clients issue IOCTLs/FSCTLs in SMB1. It replaces `TRANS2_FSCTL` for post-NT4 clients.

Request parameters (8 bytes):
```
FunctionCode    ULONG  (FSCTL/IOCTL code)
FID             USHORT (file handle)
IsFsctl         UCHAR  (1 = FSCTL, 0 = IOCTL)
IsFlags         UCHAR  (flags: copy-chunk source copy, etc.)
```

Request DataBytes: input buffer for the IOCTL.
Response DataBytes: output buffer.

This subcommand is required for:
- `FSCTL_SRV_REQUEST_RESUME_KEY` (0x00140078) — used by SMB1 copy chunk
- `FSCTL_SRV_COPYCHUNK` (0x001440F2) — server-side copy
- `FSCTL_GET_REPARSE_POINT` (0x000900A8)
- Various other NTFS FSCTLs

KSMBD has SMB2 FSCTL support in `smb2_ioctl.c`; a bridge from NT_TRANSACT_IOCTL to the same kernel FSCTL dispatch is the right approach.

#### NT_TRANSACT_SET_SECURITY_DESC (0x0003) — Missing

Request parameters (8 bytes):
```
FID                 USHORT
Reserved            USHORT
SecurityInformation ULONG  (owner, group, DACL, SACL flags)
```
Request DataBytes: `SECURITY_DESCRIPTOR` structure.

This is the SMB1 way to set NT security descriptors. KSMBD's ACL module (`smbacl.c`) can set security descriptors; the missing piece is the NT_TRANSACT wrapper.

#### NT_TRANSACT_NOTIFY_CHANGE (0x0004) — Missing

This is the SMB1 directory change notification mechanism. Most modern clients (Samba, cifs.ko) send this over SMB1 for legacy directories.

Request parameters (8 bytes):
```
CompletionFilter    ULONG  (FILE_NOTIFY_CHANGE_* flags)
FID                 USHORT (directory handle)
WatchTree           UCHAR  (1 = recursive)
Reserved            UCHAR
```

The server holds the request pending (no response is sent immediately). When a matching change occurs, the server sends an unsolicited response (MID matches the pending request):
```
ResponseData:
FILE_NOTIFY_INFORMATION[] array (Action + FileNameLength + FileName)
```

This is the hardest subcommand to implement because it requires:
1. An asynchronous notification infrastructure (Linux `inotify` or `fanotify` or VFS hooks).
2. The ability to send unsolicited SMB1 responses to a specific MID.
3. Integration with KSMBD's existing notification code (`ksmbd_notify.c`).

The existing `ksmbd_notify.c` and `smb2_notify.c` provide the SMB2 path; a SMB1 frontend is required.

#### NT_TRANSACT_RENAME (0x0005) — Missing

Request parameters:
```
FID         USHORT
ReplaceIfExists USHORT (bool)
Reserved    ULONG
FileName    variable (unicode)
```

This is the NT-style rename-by-FID. The current `SMB_COM_NT_RENAME` handler (`smb_nt_rename()`) handles hard-links only, not renames. `NT_TRANSACT_RENAME` is the rename path. Delegate to `ksmbd_vfs_rename()`.

#### NT_TRANSACT_QUERY_SECURITY_DESC (0x0006) — Missing

Request parameters (8 bytes):
```
FID                 USHORT
Reserved            USHORT
SecurityInformation ULONG
```

Response DataBytes: `SECURITY_DESCRIPTOR` structure.
If the output buffer is too small, return `STATUS_BUFFER_TOO_SMALL` with `ParameterBytes` = `LengthNeeded` (ULONG).

KSMBD's `smbacl.c` has `smb_check_perm_dacl()` and related functions. A helper to serialise the security descriptor to wire format is needed.

#### NT_TRANSACT_GET_USER_QUOTA (0x0007) — Missing

Returns quota information per user. For Linux filesystems with quota support (`ksmbd_quota.c`): query using `dquot_get_dqblk()` and format as `FILE_QUOTA_INFORMATION`. For filesystems without quota support, return `STATUS_NOT_SUPPORTED`.

#### NT_TRANSACT_SET_USER_QUOTA (0x0008) — Missing

Sets quota limits per user. Requires `dquot_set_dqblk()` on Linux quota-enabled filesystems.

---

## 8. NT_TRANSACT_SECONDARY (0xA1)

`SMB_COM_NT_TRANSACT_SECONDARY` (0xA1): No handler, no dispatch table entry. Same reassembly requirement as TRANSACTION_SECONDARY and TRANSACTION2_SECONDARY, but with 32-bit counts.

---

## 9. Interim (Pending) Responses

### 9.1 Specification Requirement

MS-SMB §2.2.4.33.2 states: when a TRANSACTION request cannot be completed immediately (e.g., `NT_TRANSACT_NOTIFY_CHANGE` waiting for a change, or a long-running IOCTL), the server SHOULD send an interim response:

```
WordCount   = 0
ByteCount   = 0
Status      = STATUS_PENDING (0x00000103)
```

The interim response has the same MID as the request. The actual final response is sent later when the operation completes, also with the same MID.

### 9.2 Current State

KSMBD does not send interim responses for any SMB1 TRANSACTION command. For `NT_TRANSACT_NOTIFY_CHANGE` this is mandatory: if no interim response is sent, the client will time out waiting for a response to the MID.

### 9.3 Implementation Requirements

1. Detect long-running TRANSACTION subcommands (`NT_TRANSACT_NOTIFY_CHANGE`, `TRANS_WAIT_NMPIPE`).
2. Send an interim response immediately using a new `smb1_send_interim_response()` helper.
3. Park the `ksmbd_work` on a pending list associated with the FID or directory.
4. When the triggering event occurs (via the notification callback), create a new response and dispatch it.

The `work->send_no_response` mechanism already exists for `SMB_COM_NT_CANCEL`. The inverse — sending multiple responses to one MID — requires careful work-queue integration.

---

## 10. Timeout Handling

### 10.1 Specification

`SMB_COM_TRANSACTION` and `SMB_COM_TRANSACTION2` contain a `Timeout` field (ULONG, milliseconds):
- `0x00000000` = return immediately if not ready (`STATUS_NO_MORE_FILES` or similar)
- `0xFFFFFFFF` = wait indefinitely
- other = wait up to that many milliseconds

For named-pipe operations (`TRANS_WAIT_NMPIPE`), `Timeout` governs how long to wait for a pipe instance. For TRANSACTION2, `Timeout` is usually 0 (file operations complete synchronously).

### 10.2 Current State

The `Timeout` field from `struct smb_com_trans_req` is never read by `smb_trans()`. The field position is at `req->Timeout` (ULONG at offset 16 in the parameter words). It is silently ignored.

For the current implementation (synchronous RPC pipes), ignoring `Timeout` is acceptable because operations complete before the function returns. Once `TRANS_WAIT_NMPIPE` is implemented, the `Timeout` must be honoured via a `wait_event_interruptible_timeout()` or equivalent.

---

## 11. Buffer Layout Compliance

### 11.1 `DataOffset` and `ParameterOffset` Calculation

MS-SMB §2.2.4.33 specifies that `ParameterOffset` and `DataOffset` are byte offsets from the start of the SMB header (`&Protocol`, i.e., the `0xFF 'S' 'M' 'B'` bytes at offset 4 of the NetBIOS frame).

Current code in `smb_trans()` line 2373–2376:
```c
rsp->ParameterOffset = cpu_to_le16(56);
rsp->DataOffset = cpu_to_le16(56 + param_len);
```

56 bytes is `sizeof(struct smb_hdr) + 10 * 2` (header + 10 parameter words). This is correct for a response with `WordCount = 10` and 0 setup words. However, if `param_len > 0`, the `DataOffset` must also account for any padding to align `Data` to a 4-byte boundary. Current code does not insert padding when `param_len` is odd or not DWORD-aligned.

The `smb_trans2()` response builders use 56 and 60 (56 + 4 for the 2-byte EaErrorOffset parameter + 2 bytes pad). This is correct for `TotalParameterCount = 2`.

**In the general case**, the calculation must be:
```
ParameterOffset = sizeof(smb_hdr) - 4  /* Protocol offset */
                + WordCount * 2         /* parameter words */
                + 1                     /* ByteCount word (2 bytes) */
                + 1                     /* Pad byte */
# Align to DWORD
DataOffset      = ALIGN(ParameterOffset + ParameterCount, 4)
```

---

## 12. Prioritised Implementation Plan

### Phase 1 — Critical Correctness (Immediate)

**Priority: Blocker for Windows client interoperability**

| Task | File(s) | Effort |
|------|---------|--------|
| Fix `query_file_info_pipe()` double-write of `DeletePending` | `smb1pdu.c` line 7020 | 5 min |
| Fix `smb_trans2()` default: should not lump `TRANS2_GET_DFS_REFERRAL` in the `default` clause; give it its own `case` returning `STATUS_NOT_SUPPORTED` with a log message | `smb1pdu.c` line 7855 | 15 min |
| Fix `SMB_QUERY_FS_ATTRIBUTE_INFO`: append `NTFS` unicode name and set `FileSystemNameLen = 8`, `TotalDataCount = 20` | `smb1pdu.c` line 5036 | 30 min |
| Fix `set_path_info()` param minimum size check to be per-level | `smb1pdu.c` line 5935 | 20 min |
| Fix IPC share `query_fs_info()` to return a proper response for `SMB_QUERY_FS_DEVICE_INFO` (DeviceType = FILE_DEVICE_NAMED_PIPE = 0x11) | `smb1pdu.c` line 4922 | 30 min |
| Fix `smb_fileinfo_rename()` overwrite semantics: truncate target, not source | `smb1pdu.c` line 7586 | 30 min |

### Phase 2 — TRANSACTION2 Missing Information Levels (Short Term)

**Priority: Required for full Windows SMB1 client support**

| Task | Information Level | Effort |
|------|------------------|--------|
| `SMB_INFO_VOLUME` (0x0002) in `query_fs_info()` | TRANS2_QUERY_FS_INFORMATION | 2h |
| `SMB_QUERY_POSIX_WHO_AM_I` (0x0202) in `query_fs_info()` | TRANS2_QUERY_FS_INFORMATION | 2h |
| `SMB_INFO_QUERY_EA_SIZE` (0x0002) in `query_path_info()` — append EASize to INFO_STANDARD | TRANS2_QUERY_PATH_INFORMATION | 2h |
| `SMB_INFO_IS_NAME_VALID` (0x0006) in `query_path_info()` | TRANS2_QUERY_PATH_INFORMATION | 1h |
| `SMB_QUERY_FILE_COMPRESSION_INFO` (0x010B) in `query_path_info()` and `query_file_info()` | Both | 1h |
| `SMB_QUERY_FILE_STREAM_INFO` (0x0109) in `query_file_info()` — return single `::$DATA` stream | TRANS2_QUERY_FILE_INFORMATION | 2h |
| `SMB_QUERY_FILE_UNIX_HLINK` (0x0203) in `query_path_info()` | TRANS2_QUERY_PATH_INFORMATION | 1h |
| `SMB_QUERY_FILE_NAME_INFO` (0x0104) in `query_file_info()` — get path from `fp->filename` | TRANS2_QUERY_FILE_INFORMATION | 1h |
| `SMB_QUERY_FILE_ALT_NAME_INFO` (0x0108) in `query_file_info()` | TRANS2_QUERY_FILE_INFORMATION | 1h |
| `SMB_QUERY_FILE_ACCESS_INFO` (0x010F) in both | TRANS2_QUERY_PATH_INFORMATION, TRANS2_QUERY_FILE_INFORMATION | 2h |
| `SMB_QUERY_FILE_INTERNAL_INFO` (0x010E) in `query_file_info()` | TRANS2_QUERY_FILE_INFORMATION | 1h |
| `SMB_QUERY_FILE_NETWORK_OPEN_INFO` (0x0122) in both | Both | 2h |
| `SMB_SET_FILE_DISPOSITION_INFO` in `set_path_info()` | TRANS2_SET_PATH_INFORMATION | 2h |
| `SMB_SET_FILE_ALLOCATION_INFO` in `set_path_info()` | TRANS2_SET_PATH_INFORMATION | 2h |
| `SMB_SET_FILE_UNIX_LINK` and `SMB_SET_FILE_UNIX_HLINK` in `set_file_info()` | TRANS2_SET_FILE_INFORMATION | 2h |
| EA support in `TRANS2_CREATE_DIRECTORY` | TRANS2_CREATE_DIRECTORY | 3h |
| `SMB_INFO_QUERY_EAS_FROM_LIST` (0x0003) in `query_path_info()` | TRANS2_QUERY_PATH_INFORMATION | 4h |

### Phase 3 — FIND_FIRST2 / FIND_NEXT2 Flags (Short Term)

| Task | Effort |
|------|--------|
| `CLOSE_AFTER_REQUEST` flag in `find_first()` and `find_next()` — close search handle before returning | 1h |
| `RETURN_RESUME_KEYS` flag — prepend 4-byte `ResumeKey` (use `dirent.offset`) per entry | 3h |
| `CONTINUE_FROM_LAST` in `find_next()` — seek to position matching `FileName` or `ResumeKey` | 4h |
| `FIND_WITH_BACKUP_INTENT` — check backup privilege and bypass ACL checks | 2h |
| Correct `LastNameOffset` to point to the `FileName` field within the last entry | 1h |
| `SMB_FIND_FILE_EAS_FROM_LIST` (0x0003) information level | 4h |

### Phase 4 — TRANSACTION Named Pipe Subcommands (Medium Term)

| Subcommand | Implementation Strategy | Effort |
|------------|------------------------|--------|
| `TRANS_SET_NMPIPE_STATE` (0x0001) | Store mode in RPC session handle; return SUCCESS | 2h |
| `TRANS_QUERY_NMPIPE_STATE` (0x0021) | Return stored mode | 1h |
| `TRANS_QUERY_NMPIPE_INFO` (0x0022) | Return static pipe info (4096/4096/1/1/pipename) | 2h |
| `TRANS_PEEK_NMPIPE` (0x0023) | Return ReadDataAvailable=0, SUCCESS | 1h |
| `TRANS_RAW_READ_NMPIPE` (0x0011) | Map to `ksmbd_rpc_read()` | 3h |
| `TRANS_RAW_WRITE_NMPIPE` (0x0031) | Map to `ksmbd_rpc_write()` | 3h |
| `TRANS_READ_NMPIPE` (0x0036) | Alias for RAW_READ in byte-stream mode | 1h |
| `TRANS_WRITE_NMPIPE` (0x0037) | Alias for RAW_WRITE in byte-stream mode | 1h |
| `TRANS_WAIT_NMPIPE` (0x0053) | Always return SUCCESS immediately (single instance model) | 2h |
| `TRANS_CALL_NMPIPE` (0x0054) | Open + `ksmbd_rpc_ioctl()` + close; reuse `smb_trans()` code | 4h |
| Mailslot `\MAILSLOT\*` detection and silent discard (Class 2) | Detect prefix, return SUCCESS for Class 1 no-op | 2h |

### Phase 5 — RAP Response Improvements (Medium Term)

| Task | Effort |
|------|--------|
| Fix `smb_trans()` RAP response: include `Converter` + `EntriesReturned` in ParameterBytes | 3h |
| Fix RAP overflow: return `STATUS_MORE_PROCESSING_REQUIRED` with partial data instead of `STATUS_INVALID_PARAMETER` | 2h |
| Log unsupported RAP Function codes and return `STATUS_NOT_SUPPORTED` | 1h |

### Phase 6 — NT_TRANSACT Infrastructure (Medium Term)

| Task | Effort |
|------|--------|
| Create `smb_nt_transact()` dispatcher in `smb1pdu.c` with 32-bit offset parsing | 4h |
| Register `[SMB_COM_NT_TRANSACT] = { .proc = smb_nt_transact }` in `smb1ops.c` | 0.5h |
| `NT_TRANSACT_QUERY_SECURITY_DESC` (0x0006) — bridge to `smbacl.c` SD serialisation | 4h |
| `NT_TRANSACT_SET_SECURITY_DESC` (0x0003) — bridge to `smbacl.c` SD parsing | 4h |
| `NT_TRANSACT_RENAME` (0x0005) — FID-based rename | 3h |
| `NT_TRANSACT_CREATE` (0x0001) — with SD + EA in DataBytes | 6h |
| `NT_TRANSACT_IOCTL` (0x0002) — bridge to `smb2_ioctl.c` FSCTL dispatch | 5h |
| `NT_TRANSACT_GET_USER_QUOTA` (0x0007) — bridge to `ksmbd_quota.c` | 3h |
| `NT_TRANSACT_SET_USER_QUOTA` (0x0008) — bridge to `ksmbd_quota.c` | 3h |

### Phase 7 — NT_TRANSACT_NOTIFY_CHANGE + Interim Responses (Long Term)

| Task | Effort |
|------|--------|
| Design and implement `smb1_pending_request` list on `ksmbd_conn` | 4h |
| Implement `smb1_send_interim_response()` helper | 2h |
| `NT_TRANSACT_NOTIFY_CHANGE` (0x0004) — integrate with `ksmbd_notify.c` | 8h |
| `TRANS_WAIT_NMPIPE` (0x0053) with real timeout using `wait_event_interruptible_timeout()` | 2h |
| Handle `SMB_COM_NT_CANCEL` cancellation of pending NT_TRANSACT requests | 2h |

### Phase 8 — Multi-Packet Reassembly (Long Term)

| Task | Effort |
|------|--------|
| Design `smb_transaction_state` reassembly structure on `ksmbd_conn` | 3h |
| Implement `SMB_COM_TRANSACTION_SECONDARY` (0x26) handler with MID-based matching | 6h |
| Implement `SMB_COM_TRANSACTION2_SECONDARY` (0x33) handler | 4h |
| Implement `SMB_COM_NT_TRANSACT_SECONDARY` (0xA1) handler with 32-bit counts | 4h |
| Implement reassembly timeout via `work->conn`-level timer | 3h |
| Send `STATUS_IO_TIMEOUT` when secondary packets do not arrive before timeout | 1h |

### Phase 9 — DFS Referral (Long Term)

| Task | Effort |
|------|--------|
| Enable `CAP_DFS` in `SMB1_SERVER_CAPS` when DFS is enabled in config | 1h |
| Implement `TRANS2_GET_DFS_REFERRAL` handler bridging to `ksmbd_dfs.c` | 6h |
| Implement `TRANS2_REPORT_DFS_INCONSISTENCY` (log + STATUS_SUCCESS) | 1h |
| Implement NT_TRANSACT FSCTL path for `FSCTL_DFS_GET_REFERRALS` via `NT_TRANSACT_IOCTL` | 4h |

---

## 13. Buffer Layout Fix Plan

The following `DataOffset` and alignment fixes apply across all TRANS2 response builders:

### 13.1 Correct DWORD Alignment

All parameter blocks and data blocks in TRANSACTION/TRANS2 responses must start at a DWORD-aligned offset. The current code uses a fixed `DataOffset = 60` (= 56 + 4) which is correct for a 2-byte parameter block with 2-byte pad. This pattern must be generalised:

```c
/* After parameter bytes ending at param_end: */
data_offset = ALIGN(param_end, 4);
pad_len     = data_offset - param_end;
/* Insert pad_len bytes of zero padding */
```

### 13.2 Byte Count Consistency

The `ByteCount` field must equal `1 (Pad byte) + param_count + pad_len + data_count`. Current handlers compute `ByteCount` differently across subcommands:
- Some use `data_count + 5` (= 2 + 1 + 2 for params=2, pad=1, data_offset_pad=2)
- Some use `data_count + params_count + 1 + alignment_offset`
- Some use fixed magic values (3, 27, 13)

All handlers should use a single helper `smb1_trans2_set_response(work, param_count, data_count)` that computes all offsets consistently.

---

## 14. Security Hardening Notes

While adding the missing subcommands:

1. **Bounds check all `ParameterOffset` and `DataOffset` fields** before dereferencing: `if (offset > req_len || offset + count > req_len) → STATUS_INVALID_PARAMETER`.
2. **Bounds check all information level struct sizes**: before writing response data, verify `sizeof(struct) + header_size <= response_sz`.
3. **Unicode name lengths**: all Unicode path extractions must validate `NameLength` against the remaining buffer.
4. **EA list traversal**: when iterating `FEAList` or `GEAList`, validate each `next` step against the list's declared `list_len` to prevent integer-wrap attacks.
5. **NT_TRANSACT 32-bit counts**: validate that `TotalParameterCount`, `TotalDataCount`, `ParameterOffset`, `DataOffset` do not overflow when cast to `size_t` or added to a pointer.

---

## 15. Capability Advertisement Consistency

When the above subcommands are implemented, the following capability bits must be updated in `SMB1_SERVER_CAPS` (currently defined in `smb1pdu.h` lines 31–35):

| Capability | Currently Set | Required When |
|------------|---------------|---------------|
| `CAP_DFS` (0x00001000) | No | `TRANS2_GET_DFS_REFERRAL` implemented |
| `CAP_RPC_REMOTE_APIS` (0x00000020) | No | Full RAP support implemented |
| `CAP_NT_FIND` (0x00000200) | Yes (via CAP_NT_SMBS) | Already correct |
| `CAP_UNIX` (0x00800000) | Yes | Already correct |

`CAP_INFOLEVEL_PASSTHRU` (0x00002000) allows clients to use NT passthrough information levels (0x1xx range) in TRANS2. It is currently not set but the server does handle those levels. Setting it will tell clients they can use the full NT level set — which is correct.

---

## 16. Test Vectors

For each newly implemented subcommand, the following test scenarios should be validated:

### TRANSACTION2 / FIND_FIRST2
- Search with `SearchCount = 0` (must return exactly 1 entry)
- Search with `CLOSE_AFTER_REQUEST` flag (handle must be gone afterward)
- Information level `SMB_FIND_FILE_INFO_STANDARD` with resume key
- Information level `SMB_FIND_FILE_NAMES_INFO` (most minimal)
- Pattern matching: `*.txt`, `file??.c`, exact name

### NT_TRANSACT_QUERY_SECURITY_DESC
- Buffer-too-small: set `MaxDataCount = 4`; expect `STATUS_BUFFER_TOO_SMALL` + `LengthNeeded`
- Full owner + DACL query on a regular file
- Query on a directory

### NT_TRANSACT_NOTIFY_CHANGE
- Create a file in a watched directory → notification received
- Delete a file in a watched directory → notification received
- Cancel pending notification via `SMB_COM_NT_CANCEL`

### Secondary Packets
- Large path query that exceeds `MaxBufferSize` → requires reassembly
- Timeout test: send primary without secondary → `STATUS_IO_TIMEOUT`

---

## 17. Summary Compliance Matrix

| Subcommand / Level | Spec Reference | Current State | Target State |
|--------------------|---------------|---------------|--------------|
| SMB_COM_TRANSACTION dispatch | MS-SMB §2.2.4.33 | Partial (pipe+LANMAN only) | Full |
| TRANS_TRANSACT_NMPIPE (0x0026) | §2.2.4.33.6 | Implemented | Complete |
| TRANS_SET_NMPIPE_STATE (0x0001) | §2.2.4.33.1 | Missing | Phase 4 |
| TRANS_QUERY_NMPIPE_STATE (0x0021) | §2.2.4.33.2 | Missing | Phase 4 |
| TRANS_QUERY_NMPIPE_INFO (0x0022) | §2.2.4.33.3 | Missing | Phase 4 |
| TRANS_PEEK_NMPIPE (0x0023) | §2.2.4.33.4 | Missing | Phase 4 |
| TRANS_RAW_READ_NMPIPE (0x0011) | §2.2.4.33.5 | Missing | Phase 4 |
| TRANS_RAW_WRITE_NMPIPE (0x0031) | §2.2.4.33.7 | Missing | Phase 4 |
| TRANS_READ_NMPIPE (0x0036) | §2.2.4.33.8 | Missing | Phase 4 |
| TRANS_WRITE_NMPIPE (0x0037) | §2.2.4.33.9 | Missing | Phase 4 |
| TRANS_WAIT_NMPIPE (0x0053) | §2.2.4.33.10 | Missing | Phase 4 |
| TRANS_CALL_NMPIPE (0x0054) | §2.2.4.33.11 | Missing | Phase 4 |
| RAPCommand via \PIPE\LANMAN | §2.2.4.33 | Partial (no fragment/param) | Phase 5 |
| Mailslot write | §2.2.4.33 | Incorrect (STATUS_NOT_SUPPORTED instead of silent) | Phase 4 |
| SMB_COM_TRANSACTION_SECONDARY (0x26) | MS-SMB §2.2.4.34 | Missing | Phase 8 |
| TRANS2_FIND_FIRST2 (0x0001) | MS-SMB §2.2.4.34.1 | Partial (missing flags, levels) | Phase 2+3 |
| TRANS2_FIND_NEXT2 (0x0002) | MS-SMB §2.2.4.34.2 | Partial (missing resume, flags) | Phase 3 |
| TRANS2_QUERY_FS_INFORMATION (0x0003) | MS-SMB §2.2.4.34.3 | Partial (missing 0x0002, 0x0202) | Phase 2 |
| TRANS2_SET_FS_INFORMATION (0x0004) | MS-SMB §2.2.4.34.4 | Partial (unix only) | Phase 2 |
| TRANS2_QUERY_PATH_INFORMATION (0x0005) | MS-SMB §2.2.4.34.5 | Partial (many levels missing) | Phase 2 |
| TRANS2_SET_PATH_INFORMATION (0x0006) | MS-SMB §2.2.4.34.6 | Partial (missing disposition, alloc) | Phase 2 |
| TRANS2_QUERY_FILE_INFORMATION (0x0007) | MS-SMB §2.2.4.34.7 | Partial (bug + missing levels) | Phase 1+2 |
| TRANS2_SET_FILE_INFORMATION (0x0008) | MS-SMB §2.2.4.34.8 | Partial (missing link levels, rename bug) | Phase 1+2 |
| TRANS2_FSCTL (0x0009) | MS-SMB §2.2.4.34.9 | Missing | Phase 6 |
| TRANS2_IOCTL2 (0x000A) | MS-SMB §2.2.4.34.10 | Missing | Phase 6 |
| TRANS2_FIND_NOTIFY_FIRST (0x000B) | MS-SMB §2.2.4.34.11 | Missing | STATUS_NOT_SUPPORTED |
| TRANS2_FIND_NOTIFY_NEXT (0x000C) | MS-SMB §2.2.4.34.12 | Missing | STATUS_NOT_SUPPORTED |
| TRANS2_CREATE_DIRECTORY (0x000D) | MS-SMB §2.2.4.34.13 | Partial (no EA in data) | Phase 2 |
| TRANS2_SESSION_SETUP (0x000E) | MS-SMB §2.2.4.34.14 | Missing | STATUS_NOT_SUPPORTED |
| TRANS2_GET_DFS_REFERRAL (0x0010) | MS-SMB §2.2.4.34.15 | Missing | Phase 9 |
| TRANS2_REPORT_DFS_INCONSISTENCY (0x0011) | MS-SMB §2.2.4.34.16 | Missing | Phase 9 |
| SMB_COM_TRANSACTION2_SECONDARY (0x33) | MS-SMB §2.2.4.35 | Missing | Phase 8 |
| SMB_COM_NT_TRANSACT (0xA0) dispatcher | MS-SMB §2.2.4.36 | Missing entirely | Phase 6 |
| NT_TRANSACT_CREATE (0x0001) | MS-SMB §2.2.4.36.1 | Missing | Phase 6 |
| NT_TRANSACT_IOCTL (0x0002) | MS-SMB §2.2.4.36.2 | Missing | Phase 6 |
| NT_TRANSACT_SET_SECURITY_DESC (0x0003) | MS-SMB §2.2.4.36.3 | Missing | Phase 6 |
| NT_TRANSACT_NOTIFY_CHANGE (0x0004) | MS-SMB §2.2.4.36.4 | Missing | Phase 7 |
| NT_TRANSACT_RENAME (0x0005) | MS-SMB §2.2.4.36.5 | Missing | Phase 6 |
| NT_TRANSACT_QUERY_SECURITY_DESC (0x0006) | MS-SMB §2.2.4.36.6 | Missing | Phase 6 |
| NT_TRANSACT_GET_USER_QUOTA (0x0007) | MS-SMB §2.2.4.36.7 | Missing | Phase 6 |
| NT_TRANSACT_SET_USER_QUOTA (0x0008) | MS-SMB §2.2.4.36.8 | Missing | Phase 6 |
| NT_TRANSACT_SECONDARY (0xA1) | MS-SMB §2.2.4.37 | Missing | Phase 8 |
| Interim responses | MS-SMB §2.2.4.33.2 | Missing | Phase 7 |
| Timeout handling | MS-SMB §2.2.4.33 | Ignored | Phase 7 |
| Multi-packet reassembly | MS-SMB §2.2.4.34.1 | Infrastructure missing | Phase 8 |
