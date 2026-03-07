# SMB2 File Operations Audit

**Audit date:** 2026-03-01
**Specification:** MS-SMB2 (Open Specification)
**Source tree:** `/home/ezechiel203/ksmbd/src/`
**Branch:** `phase1-security-hardening`

---

## Summary Table

| Command / FSCTL | Status | Key Gaps |
|---|---|---|
| SMB2 READ (0x0008) | PARTIAL | No `READ_COMPRESSED` flag; no `READ_UNBUFFERED` flag |
| SMB2 WRITE (0x0009) | PARTIAL | No `WRITE_UNBUFFERED` flag; offset=0xFFFF…FFFF append sentinel not handled |
| SMB2 LOCK (0x000A) | MOSTLY COMPLETE | `INDEX_SPECIFIED` flag has no effect; minor rollback gap |
| SMB2 IOCTL (0x000B) | MOSTLY COMPLETE | `FSCTL_QUERY_ON_DISK_VOLUME_INFO` (0x009013C0) missing; duplicate registrations |
| SMB2 QUERY_DIRECTORY (0x000E) | MOSTLY COMPLETE | `INDEX_SPECIFIED` flag read but `FileIndex` field never consumed |
| SMB2 CHANGE_NOTIFY (0x000F) | COMPLETE | None identified |
| SMB2 QUERY_INFO (0x0010) | MOSTLY COMPLETE | `FS_QUOTA_INFORMATION` has no built-in; falls to plugin (returns empty) |
| SMB2 SET_INFO (0x0011) | MOSTLY COMPLETE | Unknown classes delegated silently; no explicit reject path |

---

## Detailed Analysis

### 1. SMB2 READ (0x0008)

**Source file:** `src/protocol/smb2/smb2_read_write.c` — function `smb2_read()`

#### What is implemented

| Feature | Status | Location |
|---|---|---|
| RDMA channel `SMB2_CHANNEL_RDMA_V1` | IMPLEMENTED | `smb2_read()` channel-type switch |
| RDMA channel `SMB2_CHANNEL_RDMA_V1_INVALIDATE` | IMPLEMENTED | same switch, sets `invalidate` flag |
| `ReadChannelInfoOffset` / `ReadChannelInfoLength` validation | IMPLEMENTED | bounds-checked before SGL build |
| `MinimumCount` enforcement → `STATUS_END_OF_FILE` | IMPLEMENTED | both buffered and sendfile paths |
| Zero-copy sendfile path | IMPLEMENTED | `ksmbd_vfs_sendfile()` branch |
| Buffered read path | IMPLEMENTED | `ksmbd_vfs_read()` branch |
| `Offset` validation (< `MAX_LFS_FILESIZE`) | IMPLEMENTED | early guard |

**MinimumCount code path (both paths):**
```c
if ((nbytes == 0 && length != 0) || nbytes < mincount) {
    rsp->hdr.Status = STATUS_END_OF_FILE;
    smb2_set_err_rsp(work);
    ...
    return -ENODATA;
}
```

#### What is missing

**1. `SMB2_READFLAG_READ_COMPRESSED` (bit 1, value 0x00000002)**

Spec ref: MS-SMB2 §2.2.19 — If `ReadFlags` has `SMB2_READFLAG_READ_COMPRESSED` set, the server SHOULD return data in compressed form when compression is negotiated.

- No constant `SMB2_READFLAG_READ_COMPRESSED` is defined anywhere in `smb2pdu.h` or `smb2pdu_internal.h`.
- The `ReadFlags` field is extracted but only checked for validity; no bit is tested for compression.
- The `smb2_compress.c` file implements LZ77+Huffman compression but is only invoked on the response side for outbound data; the read handler never requests compressed data from the VFS.

**2. `SMB2_READFLAG_READ_UNBUFFERED` (bit 2, value 0x00000004)**

Spec ref: MS-SMB2 §2.2.19 — If set, the server SHOULD read data directly from disk without buffering.

- No constant defined; no `O_DIRECT` or `RWF_UNCACHED` flag applied to the underlying VFS read.
- This is an advisory flag; the server MAY ignore it, but the spec says SHOULD, making it a compliance gap.

**3. `SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION` (bit 3, 0x00000008)**

Spec ref: MS-SMB2 §2.2.19 — The server MUST return `STATUS_NOT_SUPPORTED` if not encrypted. The current handler does not check this flag; it is not defined.

#### Spec reference

MS-SMB2 §2.2.19 (SMB2 READ Request), §3.3.5.12 (Receiving an SMB2 READ Request)

#### Implementation plan

1. Define missing flag constants in `src/include/protocol/smb2pdu.h`:
   ```c
   #define SMB2_READFLAG_READ_COMPRESSED             0x00000002
   #define SMB2_READFLAG_READ_UNBUFFERED             0x00000004
   #define SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION 0x00000008
   ```
2. For `READ_UNBUFFERED`: pass `RWF_UNCACHED` (or open with `O_DIRECT` semantics) to `ksmbd_vfs_read()` when the flag is set and the dialect is SMB3+.
3. For `READ_COMPRESSED`: gate on whether compression capability was negotiated in the session; if so, pass through to `smb2_compress.c` after reading. Return `STATUS_NOT_SUPPORTED` if compression not negotiated.
4. For `REQUEST_TRANSPORT_ENCRYPTION`: return `STATUS_NOT_SUPPORTED` when flag is set but session has no encryption context.

---

### 2. SMB2 WRITE (0x0009)

**Source file:** `src/protocol/smb2/smb2_read_write.c` — function `smb2_write()`

#### What is implemented

| Feature | Status | Location |
|---|---|---|
| `SMB2_WRITEFLAG_WRITE_THROUGH` (0x00000001) | IMPLEMENTED | `fp->filp->f_flags |= O_SYNC` when set |
| `FILE_APPEND_DATA`-only handle restriction | IMPLEMENTED | offset checked against `i_size_read(inode)` |
| RDMA channel write | IMPLEMENTED | same channel-type switch as READ |
| `RemainingBytes` used for RDMA SGL length | IMPLEMENTED | passed to `smb2_build_rdma_sgl()` |
| `Offset` range validation | IMPLEMENTED | `0 <= offset <= MAX_LFS_FILESIZE` |

**FILE_APPEND_DATA enforcement:**
```c
if (!(fp->daccess & FILE_WRITE_DATA_LE) &&
    (fp->daccess & FILE_APPEND_DATA_LE)) {
    loff_t fsize = i_size_read(file_inode(fp->filp));
    if (offset != fsize) { err = -EACCES; goto out; }
}
```

#### What is missing

**1. `SMB2_WRITEFLAG_WRITE_UNBUFFERED` (bit 2, value 0x00000004)**

Spec ref: MS-SMB2 §2.2.21 — If set the server SHOULD write directly to disk without buffering.

- Not defined in `smb2pdu.h`; no `O_DIRECT` / `RWF_UNCACHED` applied on the write path.

**2. Offset = `0xFFFFFFFFFFFFFFFF` append sentinel**

Spec ref: MS-SMB2 §2.2.21 — If `Offset` is `0xFFFFFFFFFFFFFFFF` and the file was opened with `FILE_APPEND_DATA`, the server MUST append the data to the end of file.

Current validation:
```c
offset = le64_to_cpu(req->Offset);
if (offset < 0 || offset > MAX_LFS_FILESIZE)
    return -EINVAL;
```

Since `0xFFFFFFFFFFFFFFFF` interpreted as `int64_t` is `-1`, the guard `offset < 0` rejects it with `STATUS_INVALID_PARAMETER`, which violates the spec.

**3. `SMB2_WRITEFLAG_REQUEST_TRANSPORT_ENCRYPTION` (bit 3, 0x00000008)**

Same issue as READ — not defined, not checked.

#### Spec reference

MS-SMB2 §2.2.21 (SMB2 WRITE Request), §3.3.5.13 (Receiving an SMB2 WRITE Request)

#### Implementation plan

1. Define missing constants:
   ```c
   #define SMB2_WRITEFLAG_WRITE_UNBUFFERED              0x00000004
   #define SMB2_WRITEFLAG_REQUEST_TRANSPORT_ENCRYPTION  0x00000008
   ```
2. For `WRITE_UNBUFFERED`: add `RWF_SYNC | RWF_UNCACHED` (or equivalent `O_DIRECT` path) when the flag is set.
3. For offset = `0xFFFFFFFFFFFFFFFF`: before the range check, test for the sentinel and convert to file-end semantics:
   ```c
   if (req->Offset == cpu_to_le64(0xFFFFFFFFFFFFFFFFULL)) {
       /* Append: treat as write at current EOF */
       offset = i_size_read(file_inode(fp->filp));
   } else {
       offset = le64_to_cpu(req->Offset);
       if (offset > MAX_LFS_FILESIZE)
           return -EINVAL;
   }
   ```
   Note: this sentinel is only meaningful if the handle has `FILE_APPEND_DATA` access; the server SHOULD fail with `STATUS_INVALID_PARAMETER` otherwise.

---

### 3. SMB2 LOCK (0x000A)

**Source file:** `src/protocol/smb2/smb2_lock.c` — functions `smb2_lock()`, `check_lock_sequence()`, `store_lock_sequence()`

#### What is implemented

| Feature | Status | Location |
|---|---|---|
| `SMB2_LOCKFLAG_SHARED_LOCK` (0x0001) | IMPLEMENTED | `ksmbd_vfs_lock()` with `F_RDLCK` |
| `SMB2_LOCKFLAG_EXCLUSIVE_LOCK` (0x0002) | IMPLEMENTED | `ksmbd_vfs_lock()` with `F_WRLCK` |
| `SMB2_LOCKFLAG_UNLOCK` (0x0004) | IMPLEMENTED | `ksmbd_vfs_lock()` with `F_UNLCK` |
| `SMB2_LOCKFLAG_FAIL_IMMEDIATELY` (0x0010) | IMPLEMENTED | `F_SETLK` vs `F_SETLKW` selection |
| Multiple lock elements in one request | IMPLEMENTED | loop with individual POSIX lock calls |
| Rollback on partial failure | IMPLEMENTED | unlocks already-acquired locks on error |
| Async blocking lock | IMPLEMENTED | `FILE_LOCK_DEFERRED` → `STATUS_PENDING` path |
| Lock sequence replay (`LockSequenceNumber` / `LockSequenceIndex`) | IMPLEMENTED | `check_lock_sequence()` / `store_lock_sequence()` |
| Lock sequence index range validation (1–64) | IMPLEMENTED | index range check in `check_lock_sequence()` |

**Async deferred lock path:**
```c
if (rc == FILE_LOCK_DEFERRED) {
    ...
    smb2_send_interim_resp(work, STATUS_PENDING);
    smb2_wait_for_posix_lock(work, flock);
    ...
    goto retry;
}
```

#### What is missing / partially implemented

**1. `SMB2_LOCKFLAG_INDEX_SPECIFIED` flag handling**

While the `LockSequenceIndex` field is parsed in `check_lock_sequence()`, the `SMB2_LOCKFLAG_INDEX_SPECIFIED` flag value is not defined as a named constant. The spec (MS-SMB2 §2.2.26) does not define such a flag for locks (it exists for QUERY_DIRECTORY), so this is not actually a gap — confirmed by re-reading the spec.

**2. Atomicity of multiple locks**

Spec ref: MS-SMB2 §3.3.5.14 — If any lock in the list fails, all previously successful locks in the same request MUST be released.

Current implementation does attempt rollback on failure, but uses POSIX locks (`fcntl F_SETLK`) sequentially. There is no kernel-level atomic multi-range lock primitive, so there is a window between individual lock acquisitions. This is an inherent Linux VFS limitation, not a code defect, but worth documenting.

**3. Lock sequence for non-resilient handles**

Spec ref: MS-SMB2 §3.3.5.14 — Lock sequence checking applies only to resilient, durable, or persistent handles.

Current implementation checks `fp->persistent_id` to gate lock sequence checking, which is correct. However, the code does not distinguish between resilient and durable handles explicitly — both use the same `persistent_id` check. This is acceptable for the current implementation scope.

#### Spec reference

MS-SMB2 §2.2.26 (SMB2 LOCK Request), §3.3.5.14 (Receiving an SMB2 LOCK Request)

#### Implementation plan

No critical issues. The implementation is substantially complete. Documentation and comments clarifying the atomicity limitation are recommended.

---

### 4. SMB2 IOCTL (0x000B) / FSCTL Coverage

**Source files:**
- `src/protocol/smb2/smb2_ioctl.c` — IOCTL dispatcher
- `src/fs/ksmbd_fsctl.c` — handler registration table and built-in implementations
- `src/fs/ksmbd_dfs.c`, `ksmbd_vss.c`, `ksmbd_reparse.c`, `ksmbd_resilient.c`, `ksmbd_branchcache.c`, `ksmbd_fsctl_extra.c` — registered handlers

#### Architecture note

The IOCTL handler first calls `ksmbd_dispatch_fsctl()`, which looks up the FSCTL code in a RCU-protected hash table populated at module init by `ksmbd_fsctl_register_builtins()` and by each subsystem module. If no handler is found in the hash table, it falls through to a legacy `switch` statement inside `smb2_ioctl()`. Several FSCTLs are thus registered in **both** the hash table and the legacy switch — the hash table entry always wins. This creates dead code in the legacy switch.

#### FSCTL coverage table (MS-SMB2 §2.2.31 mandatory FSCTLs)

| FSCTL Code | Name | Status | Notes |
|---|---|---|---|
| 0x00060194 | `FSCTL_DFS_GET_REFERRALS` | IMPLEMENTED | `ksmbd_dfs.c` |
| 0x0011400C | `FSCTL_PIPE_PEEK` | STUB | Returns zeroed struct; no real pipe state |
| 0x00110018 | `FSCTL_PIPE_WAIT` | IMPLEMENTED | `ksmbd_fsctl_extra.c` |
| 0x0011C017 | `FSCTL_PIPE_TRANSCEIVE` | IMPLEMENTED | Delegates to RPC daemon via IPC |
| 0x001001D4 | `FSCTL_SRV_COPYCHUNK` | IMPLEMENTED | `ksmbd_fsctl_extra.c` + legacy fallback |
| 0x001001D5 | `FSCTL_SRV_COPYCHUNK_WRITE` | IMPLEMENTED | Same as above |
| 0x00144064 | `FSCTL_SRV_ENUMERATE_SNAPSHOTS` | IMPLEMENTED | `ksmbd_vss.c` |
| 0x00140078 | `FSCTL_SRV_REQUEST_RESUME_KEY` | IMPLEMENTED | Hash table + legacy (duplicate) |
| 0x00144200 | `FSCTL_SRV_READ_HASH` | IMPLEMENTED | `ksmbd_branchcache.c` |
| 0x001401D4 | `FSCTL_LMR_REQUEST_RESILIENCY` | IMPLEMENTED | `ksmbd_resilient.c` |
| 0x001401FC | `FSCTL_QUERY_NETWORK_INTERFACE_INFO` | IMPLEMENTED | Hash table + legacy (duplicate) |
| 0x000900A4 | `FSCTL_SET_REPARSE_POINT` | IMPLEMENTED | `ksmbd_reparse.c` |
| 0x000900AC | `FSCTL_DELETE_REPARSE_POINT` | IMPLEMENTED | `ksmbd_reparse.c` |
| 0x000900A8 | `FSCTL_GET_REPARSE_POINT` | IMPLEMENTED | `ksmbd_reparse.c` (full) + legacy stub (dead code) |
| 0x000980C8 | `FSCTL_SET_ZERO_DATA` | IMPLEMENTED | Hash table + legacy (duplicate) |
| 0x000940CF | `FSCTL_QUERY_ALLOCATED_RANGES` | IMPLEMENTED | Hash table + legacy (duplicate) |
| 0x000900C0 | `FSCTL_SET_SPARSE` | IMPLEMENTED | Hash table + legacy (duplicate) |
| 0x000900C0 | `FSCTL_CREATE_OR_GET_OBJECT_ID` | IMPLEMENTED | `ksmbd_fsctl.c` built-in |
| 0x00098208 | `FSCTL_FILE_LEVEL_TRIM` | IMPLEMENTED | `ksmbd_fsctl_extra.c` |
| 0x00090118 | `FSCTL_VALIDATE_NEGOTIATE_INFO` | IMPLEMENTED | `ksmbd_fsctl.c` built-in |
| **0x009013C0** | **`FSCTL_QUERY_ON_DISK_VOLUME_INFO`** | **NOT IMPLEMENTED** | Not in handler table; not in smbfsctl.h |

#### Additional FSCTLs in handler table (not in MS-SMB2 §2.2.31 mandatory list)

The following are implemented beyond the mandatory set:
- `FSCTL_OFFLOAD_READ` / `FSCTL_OFFLOAD_WRITE` (ODX with server-side token table)
- `FSCTL_DUPLICATE_EXTENTS_TO_FILE` / `_EX`
- `FSCTL_GET_INTEGRITY_INFORMATION` / `FSCTL_SET_INTEGRITY_INFORMATION` / `_EX`
- `FSCTL_QUERY_FILE_REGIONS`
- `FSCTL_GET_OBJECT_ID`, `FSCTL_SET_OBJECT_ID`, `FSCTL_DELETE_OBJECT_ID`, `FSCTL_SET_OBJECT_ID_EXTENDED`
- `FSCTL_GET_COMPRESSION` / `FSCTL_SET_COMPRESSION`
- `FSCTL_MARK_HANDLE`
- Many others returning `STATUS_NOT_SUPPORTED` (correct behavior per spec when optional)

#### Duplicate registration issue

The following FSCTLs appear in **both** `builtin_fsctl_handlers[]` in `ksmbd_fsctl.c` AND in the legacy `switch` inside `smb2_ioctl.c`:

- `FSCTL_QUERY_NETWORK_INTERFACE_INFO`
- `FSCTL_SRV_REQUEST_RESUME_KEY`
- `FSCTL_SRV_COPYCHUNK` / `FSCTL_SRV_COPYCHUNK_WRITE`
- `FSCTL_SET_SPARSE`
- `FSCTL_SET_ZERO_DATA`
- `FSCTL_QUERY_ALLOCATED_RANGES`
- `FSCTL_GET_REPARSE_POINT` (legacy is minimal stub; new handler is full implementation)
- `FSCTL_DUPLICATE_EXTENTS_TO_FILE`

Since the hash table dispatch runs first, the legacy switch cases are dead code. The legacy `FSCTL_GET_REPARSE_POINT` stub returning a zeroed `reparse_data_buffer` would be incorrect if ever reached, but it cannot be reached because `ksmbd_reparse.c` registers the full handler first.

#### Spec reference

MS-SMB2 §2.2.31 (SMB2 IOCTL Request), §3.3.5.15 (Receiving an SMB2 IOCTL Request)

#### Implementation plan

1. **`FSCTL_QUERY_ON_DISK_VOLUME_INFO` (0x009013C0)**:
   - Add `#define FSCTL_QUERY_ON_DISK_VOLUME_INFO 0x009013C0` to `src/include/protocol/smbfsctl.h`.
   - Register a handler in `ksmbd_fsctl.c` that returns `QUERY_ON_DISK_VOLUME_INFO_RESPONSE` (DataBlockSize=4096, NumberOfDataBlocks, etc. derived from `statfs()`).
   - If the volume does not support this (e.g., not ReFS/NTFS), return `STATUS_NOT_SUPPORTED`.

2. **Remove dead legacy switch cases**: After confirming hash-table handlers are correct, remove duplicate entries from the `switch` in `smb2_ioctl.c` to eliminate dead code and confusion.

3. **`FSCTL_PIPE_PEEK` stub**: Consider returning `STATUS_NOT_SUPPORTED` instead of a zeroed struct, as the stub is misleading.

---

### 5. SMB2 QUERY_DIRECTORY (0x000E)

**Source file:** `src/protocol/smb2/smb2_dir.c` — function `smb2_query_dir()`

#### What is implemented

| Feature | Status | Location |
|---|---|---|
| `FileDirectoryInformation` (class 1) | IMPLEMENTED | `smb2_query_dir()` switch |
| `FileFullDirectoryInformation` (class 2) | IMPLEMENTED | same |
| `FileBothDirectoryInformation` (class 3) | IMPLEMENTED | same |
| `FileNamesInformation` (class 12) | IMPLEMENTED | same |
| `FileIdBothDirectoryInformation` (class 37) | IMPLEMENTED | same |
| `FileIdFullDirectoryInformation` (class 38) | IMPLEMENTED | same |
| `FileIdExtdDirectoryInformation` (class 60) | IMPLEMENTED | same |
| `FileIdAllExtdDirectoryInformation` | IMPLEMENTED | same |
| `SMB2_QUERY_DIRECTORY_FLAG_RESTART_SCANS` (0x01) | IMPLEMENTED | seeks directory to start |
| `SMB2_QUERY_DIRECTORY_FLAG_RETURN_SINGLE_ENTRY` (0x02) | IMPLEMENTED | breaks after first match |
| `SMB2_QUERY_DIRECTORY_FLAG_REOPEN` (0x10) | IMPLEMENTED | re-initializes dir context |
| Wildcard pattern matching | IMPLEMENTED | `match_pattern()` helper |
| Entry count rate-limit (100,000) | IMPLEMENTED | loop guard |
| Buffer fill with `NextEntryOffset` chaining | IMPLEMENTED | per-entry offset update |

#### What is missing

**1. `SMB2_QUERY_DIRECTORY_FLAG_INDEX_SPECIFIED` (0x04)**

Spec ref: MS-SMB2 §2.2.33 — If `SMB2_INDEX_SPECIFIED` is set, the server MUST return entries starting at the entry indicated by `FileIndex`.

The constant `SMB2_INDEX_SPECIFIED` (value 0x04) is defined in `smb2pdu.h` and extracted from the request flags. However, the `FileIndex` field from the `smb2_query_directory_req` structure is **never read**. The code does not seek the directory to the requested index position before beginning enumeration. The flag is parsed but silently ignored:

```c
/* In smb2_query_dir(): */
flags = req->Flags;
/* SMB2_INDEX_SPECIFIED is in flags but FileIndex (req->FileIndex) is never accessed */
```

**2. Partial buffer fill behavior**

Spec ref: MS-SMB2 §3.3.5.18 — If the output buffer is too small to hold even one entry, the server MUST return `STATUS_INFO_LENGTH_MISMATCH`. If the buffer holds at least one entry but not all, return `STATUS_SUCCESS` with the data available.

The current implementation returns `STATUS_NO_MORE_FILES` when no entries fit rather than `STATUS_INFO_LENGTH_MISMATCH`. The distinction matters for the very first call with an undersized buffer.

**3. `FileIdGlobalTxDirectoryInformation` (class 50)**

Spec ref: MS-SMB2 §2.2.37.1 — Required for SMB2 compliance but only relevant for TxF (Transactional NTFS), which Linux does not support. Returning `STATUS_NOT_SUPPORTED` would be correct; currently this class falls to the `default` case which returns `STATUS_INVALID_INFO_CLASS`.

#### Spec reference

MS-SMB2 §2.2.33 (SMB2 QUERY_DIRECTORY Request), §3.3.5.18 (Receiving an SMB2 QUERY_DIRECTORY Request)

#### Implementation plan

1. **`INDEX_SPECIFIED`**: When the flag is set, after resetting the directory seek position, seek to `le32_to_cpu(req->FileIndex)` using `vfs_llseek()`. Since POSIX directories do not have reliable numeric indexes, this may require mapping to directory position cookies. Document this as a known limitation if exact compliance is not achievable.

2. **`STATUS_INFO_LENGTH_MISMATCH`**: Add a check before the fill loop: if `OutputBufferLength` is less than the minimum size of a single directory entry struct for the requested class, return `STATUS_INFO_LENGTH_MISMATCH` immediately.

3. **`FileIdGlobalTxDirectoryInformation`**: Add explicit `STATUS_NOT_SUPPORTED` return for class 50.

---

### 6. SMB2 CHANGE_NOTIFY (0x000F)

**Source file:** `src/protocol/smb2/smb2_notify.c` — function `smb2_notify()`

#### What is implemented

| Feature | Status | Location |
|---|---|---|
| `FILE_NOTIFY_CHANGE_FILE_NAME` (0x001) | IMPLEMENTED | passed to `ksmbd_notify_add_watch()` |
| `FILE_NOTIFY_CHANGE_DIR_NAME` (0x002) | IMPLEMENTED | same |
| `FILE_NOTIFY_CHANGE_ATTRIBUTES` (0x004) | IMPLEMENTED | same |
| `FILE_NOTIFY_CHANGE_SIZE` (0x008) | IMPLEMENTED | same |
| `FILE_NOTIFY_CHANGE_LAST_WRITE` (0x010) | IMPLEMENTED | same |
| `FILE_NOTIFY_CHANGE_LAST_ACCESS` (0x020) | IMPLEMENTED | same |
| `FILE_NOTIFY_CHANGE_CREATION` (0x040) | IMPLEMENTED | same |
| `FILE_NOTIFY_CHANGE_EA` (0x080) | IMPLEMENTED | same |
| `FILE_NOTIFY_CHANGE_SECURITY` (0x100) | IMPLEMENTED | same |
| `FILE_NOTIFY_CHANGE_STREAM_NAME` (0x200) | IMPLEMENTED | same |
| `FILE_NOTIFY_CHANGE_STREAM_SIZE` (0x400) | IMPLEMENTED | same |
| `FILE_NOTIFY_CHANGE_STREAM_WRITE` (0x800) | IMPLEMENTED | same |
| `SMB2_WATCH_TREE` flag | IMPLEMENTED | extracted, passed to watch subsystem |
| Async STATUS_PENDING + interim response | IMPLEMENTED | full async work pattern |
| Cancellation via `ksmbd_notify_cancel()` | IMPLEMENTED | callback registered |
| Compound request handling | IMPLEMENTED | separate async_work for compound chains |
| `ksmbd_notify_enabled()` guard | IMPLEMENTED | returns `STATUS_NOT_SUPPORTED` when disabled |

#### What is missing

No significant compliance gaps found. The implementation correctly handles all `CompletionFilter` bits defined in MS-SMB2 §2.2.35, the `WATCH_TREE` flag, asynchronous operation, and cancellation.

Minor observation: The spec requires the server to return `STATUS_NOTIFY_ENUM_DIR` when the internal event buffer overflows (too many changes accumulated before the client reads them). It is unclear from the code whether `ksmbd_notify_add_watch()` handles this edge case in the underlying notify subsystem — this should be verified in `src/fs/ksmbd_notify.c`.

#### Spec reference

MS-SMB2 §2.2.35 (SMB2 CHANGE_NOTIFY Request), §3.3.5.19 (Receiving an SMB2 CHANGE_NOTIFY Request)

#### Implementation plan

Verify that `ksmbd_notify.c` returns `STATUS_NOTIFY_ENUM_DIR` when the watch queue overflows. No other action required.

---

### 7. SMB2 QUERY_INFO (0x0010)

**Source file:** `src/protocol/smb2/smb2_query_set.c` — functions `smb2_get_info_file()`, `smb2_get_info_filesystem()`, `smb2_get_info_sec()`, `smb2_query_info()`

#### What is implemented

**`SMB2_0_INFO_FILE` (InfoType = 0x01):**

| FileInformationClass | Status |
|---|---|
| `FileAccessInformation` (8) | IMPLEMENTED |
| `FileAlignmentInformation` (17) | IMPLEMENTED |
| `FileAllInformation` (18) | IMPLEMENTED |
| `FileAlternateNameInformation` (21) | IMPLEMENTED |
| `FileAttributeTagInformation` (35) | IMPLEMENTED |
| `FileBasicInformation` (4) | IMPLEMENTED |
| `FileCompressionInformation` (28) | IMPLEMENTED |
| `FileEaInformation` (7) | IMPLEMENTED |
| `FileFullEaInformation` (15) | IMPLEMENTED |
| `FileIdInformation` (59) | IMPLEMENTED |
| `FileInternalInformation` (6) | IMPLEMENTED |
| `FileModeInformation` (16) | IMPLEMENTED |
| `FileNetworkOpenInformation` (34) | IMPLEMENTED |
| `FileObjectIdInformation` (29) | IMPLEMENTED |
| `FilePositionInformation` (14) | IMPLEMENTED |
| `FileReparsePointInformation` (33) | IMPLEMENTED |
| `FileStandardInformation` (5) | IMPLEMENTED |
| `FileStandardLinkInformation` (54) | IMPLEMENTED |
| `FileStreamInformation` (22) | IMPLEMENTED |
| `SMB_FIND_FILE_POSIX_INFO` (POSIX ext.) | IMPLEMENTED |
| Unknown classes | Dispatched to `ksmbd_dispatch_info()` |

**`SMB2_0_INFO_FILESYSTEM` (InfoType = 0x02):**

| FilesystemInfoClass | Status |
|---|---|
| `FileFsAttributeInformation` (5) | IMPLEMENTED |
| `FileFsControlInformation` (6) | IMPLEMENTED |
| `FileFsDeviceInformation` (4) | IMPLEMENTED |
| `FileFsFullSizeInformation` (7) | IMPLEMENTED |
| `FileFsObjectIdInformation` (8) | IMPLEMENTED |
| `FileFsSectorSizeInformation` (11) | IMPLEMENTED |
| `FileFsSizeInformation` (3) | IMPLEMENTED |
| `FileFsVolumeInformation` (1) | IMPLEMENTED |
| `FileFsPosixInformation` (100) | IMPLEMENTED (POSIX ext.) |
| `FileFsQuotaInformation` (2) | NOT BUILT-IN (see below) |

**`SMB2_0_INFO_SECURITY` (InfoType = 0x03):**

| Feature | Status |
|---|---|
| `OWNER_SECURITY_INFORMATION` | IMPLEMENTED |
| `GROUP_SECURITY_INFORMATION` | IMPLEMENTED |
| `DACL_SECURITY_INFORMATION` (requires `READ_CONTROL`) | IMPLEMENTED |
| `SACL_SECURITY_INFORMATION` (requires `ACCESS_SYSTEM_SECURITY`) | IMPLEMENTED |
| Access check before returning SD | IMPLEMENTED |

**`SMB2_0_INFO_QUOTA` (InfoType = 0x04):** Dispatched to `ksmbd_dispatch_info()`; returns empty response (0 bytes) on `EOPNOTSUPP` from plugin.

#### What is missing

**1. `FileFsQuotaInformation` (FilesystemInfoClass = 2)**

Spec ref: MS-SMB2 §2.2.37.2 — The server MUST handle `FileFsQuotaInformation` in `SMB2_QUERY_INFO`.

The `smb2_get_info_filesystem()` switch does not have a case for `FileFsQuotaInformation` (class 2). The `SMB2_O_INFO_QUOTA` info type (0x04) is dispatched to `ksmbd_dispatch_info()` (the plugin system), which returns empty when no plugin handles it. There is no built-in fallback.

This means a client querying quota information will receive an empty or incorrect response rather than `STATUS_NOT_SUPPORTED` or actual quota data.

**2. `FileNormalizedNameInformation` (class 48)**

Spec ref: MS-SMB2 §2.2.38 — Servers SHOULD support this class for QUERY_INFO on files.

Not found in the switch. Falls to `ksmbd_dispatch_info()`.

**3. `FileHardLinkInformation` (class 46)**

Optional per spec but commonly expected. Not found in the switch.

#### Spec reference

MS-SMB2 §2.2.37 (SMB2 QUERY_INFO Request), §3.3.5.20 (Receiving an SMB2 QUERY_INFO Request)

#### Implementation plan

1. **`FileFsQuotaInformation`**: Add a case in `smb2_get_info_filesystem()`:
   - If Linux quota support is available via `quotactl()`, query and return the data.
   - If not available, return `STATUS_NOT_SUPPORTED` explicitly (do not return empty data).

2. **`FileNormalizedNameInformation`**: Implement using the canonical path derived from `dentry` → `d_absolute_path()`. This is the case-normalized, fully resolved name.

3. **`FileHardLinkInformation`**: Mark as `STATUS_NOT_SUPPORTED` with an explicit case rather than silently falling to the dispatch hook.

---

### 8. SMB2 SET_INFO (0x0011)

**Source file:** `src/protocol/smb2/smb2_query_set.c` — functions `smb2_set_info_file()`, `smb2_set_info_sec()`, `smb2_set_info()`

#### What is implemented

**`SMB2_0_INFO_FILE` (InfoType = 0x01) — file info classes:**

| FileInformationClass | Status |
|---|---|
| `FileAllocationInformation` (19) | IMPLEMENTED |
| `FileBasicInformation` (4) | IMPLEMENTED |
| `FileDispositionInformation` (13) | IMPLEMENTED |
| `FileDispositionInformationEx` | IMPLEMENTED |
| `FileEndOfFileInformation` (20) | IMPLEMENTED |
| `FileFullEaInformation` (15) | IMPLEMENTED |
| `FileLinkInformation` (11) | IMPLEMENTED |
| `FileLinkInformationBypassAccessCheck` | IMPLEMENTED |
| `FileModeInformation` (16) | IMPLEMENTED |
| `FileObjectIdInformation` (29) | IMPLEMENTED |
| `FilePositionInformation` (14) | IMPLEMENTED |
| `FileRenameInformation` (10) | IMPLEMENTED |
| `FileRenameInformationBypassAccessCheck` | IMPLEMENTED |
| `FileRenameInformationEx` | IMPLEMENTED |
| `FileRenameInformationExBypassAccessCheck` | IMPLEMENTED |
| Unknown classes | Dispatched to `ksmbd_dispatch_info()` |

**`SMB2_0_INFO_SECURITY` (InfoType = 0x03):**

| Feature | Status |
|---|---|
| `OWNER_SECURITY_INFORMATION` (requires `WRITE_OWNER`) | IMPLEMENTED |
| `GROUP_SECURITY_INFORMATION` (requires `WRITE_OWNER`) | IMPLEMENTED |
| `DACL_SECURITY_INFORMATION` (requires `WRITE_DAC`) | IMPLEMENTED |
| `SACL_SECURITY_INFORMATION` (requires `ACCESS_SYSTEM_SECURITY`) | IMPLEMENTED |

#### What is missing

**1. `FileShortNameInformation` (class 40)**

Spec ref: MS-SMB2 §2.2.39 — SET_INFO with `FileShortNameInformation` allows setting the 8.3 short name.

Not in the switch. Silently dispatched to `ksmbd_dispatch_info()`. On Linux, 8.3 short names are a FAT/NTFS concept; returning `STATUS_NOT_SUPPORTED` explicitly would be more correct than silent dispatch.

**2. `FileValidDataLengthInformation` (class 39)**

Spec ref: MS-SMB2 §2.2.39 — Valid data length control (similar to `fallocate(FALLOC_FL_KEEP_SIZE)`).

Not in the switch. Dispatched silently.

**3. `FileQuotaInformation` via SET_INFO**

Spec ref: MS-SMB2 §2.2.39 — quota modification.

Not implemented; same situation as QUERY_INFO quota.

**4. No explicit rejection for unknown SetInfo classes**

When `ksmbd_dispatch_info()` returns `EOPNOTSUPP` for an unknown class, the caller converts this to `STATUS_NOT_SUPPORTED`. This is technically correct behavior but could mask implementation errors. An explicit log message or debug print when an unrecognized class is dispatched would improve debuggability.

#### Spec reference

MS-SMB2 §2.2.39 (SMB2 SET_INFO Request), §3.3.5.21 (Receiving an SMB2 SET_INFO Request)

#### Implementation plan

1. **`FileShortNameInformation`**: Add explicit `STATUS_NOT_SUPPORTED` return.
2. **`FileValidDataLengthInformation`**: Implement using `fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, length)` to pre-allocate disk space up to the valid data length.
3. **`FileQuotaInformation`**: Same recommendation as QUERY_INFO quota — implement via `quotactl()` or return `STATUS_NOT_SUPPORTED` explicitly.
4. **Unknown class handling**: Add `pr_debug()` for unknown classes dispatched to the plugin system.

---

## Cross-Cutting Issues

### Issue 1: Missing flag constant definitions (`smb2pdu.h`)

The following constants referenced in MS-SMB2 are not defined:
- `SMB2_READFLAG_READ_COMPRESSED` (0x00000002)
- `SMB2_READFLAG_READ_UNBUFFERED` (0x00000004)
- `SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION` (0x00000008)
- `SMB2_WRITEFLAG_WRITE_UNBUFFERED` (0x00000004)
- `SMB2_WRITEFLAG_REQUEST_TRANSPORT_ENCRYPTION` (0x00000008)
- `FSCTL_QUERY_ON_DISK_VOLUME_INFO` (in `smbfsctl.h`)

These should be added even if the feature is not yet implemented, so that future code can reference them by name rather than by magic number.

### Issue 2: Duplicate FSCTL handler registrations

Eight FSCTLs are registered in both the hash table (`ksmbd_fsctl.c`) and the legacy switch in `smb2_ioctl.c`. Since the hash table dispatch runs first, the legacy cases are unreachable dead code. The legacy switch should be pruned to only contain FSCTLs not in the hash table (currently: `FSCTL_DUPLICATE_EXTENTS_TO_FILE` in legacy only, and `FSCTL_DFS_GET_REFERRALS` via DFS).

### Issue 3: Write offset=0xFFFFFFFFFFFFFFFF sentinel

This is the only outright protocol violation found. The spec explicitly defines this sentinel value for FILE_APPEND_DATA handles, and the current code rejects it with `STATUS_INVALID_PARAMETER`. Clients relying on spec-defined behavior will receive an incorrect error. This should be treated as a bug fix, not a feature addition.

### Issue 4: Quota support absence

Both QUERY_INFO and SET_INFO for quota information silently return empty or delegate to an unimplemented plugin. Per spec, the server MUST respond to quota queries. The correct behavior when quotas are not supported is to return `STATUS_NOT_SUPPORTED` (explicitly), not empty data.

---

## Priority Summary

| Priority | Issue | Command | Effort |
|---|---|---|---|
| HIGH (bug) | Write offset 0xFFFFFFFFFFFFFFFF not handled | SMB2 WRITE | Low — one guard clause |
| HIGH | `FSCTL_QUERY_ON_DISK_VOLUME_INFO` missing | SMB2 IOCTL | Medium — new handler |
| MEDIUM | `SMB2_READFLAG_READ_COMPRESSED` / `READ_UNBUFFERED` | SMB2 READ | Medium — flag + VFS path |
| MEDIUM | `SMB2_WRITEFLAG_WRITE_UNBUFFERED` | SMB2 WRITE | Low — one VFS flag |
| MEDIUM | `INDEX_SPECIFIED` not functional | SMB2 QUERY_DIRECTORY | High — dir seek semantics |
| MEDIUM | `FileFsQuotaInformation` empty response | SMB2 QUERY_INFO | Medium — quotactl or explicit ENOTSUP |
| LOW | Missing flag constants in headers | ALL | Low — define-only |
| LOW | Dead code in legacy IOCTL switch | SMB2 IOCTL | Low — cleanup |
| LOW | `STATUS_INFO_LENGTH_MISMATCH` vs `STATUS_NO_MORE_FILES` | SMB2 QUERY_DIRECTORY | Low — one condition |
| LOW | `FileShortNameInformation` / `FileValidDataLengthInformation` | SMB2 SET_INFO | Low — explicit ENOTSUP |
| LOW | `STATUS_NOTIFY_ENUM_DIR` on queue overflow | SMB2 CHANGE_NOTIFY | Low — verify existing code |
