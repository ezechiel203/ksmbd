# SMB2 Plan 06: QueryInfo / SetInfo

Audit of SMB2 QUERY_INFO (MS-SMB2 §2.2.37/§2.2.38/§3.3.5.20) and SMB2 SET_INFO
(MS-SMB2 §2.2.39/§3.3.5.21) against the implementation in
`src/protocol/smb2/smb2_query_set.c`, `src/fs/ksmbd_info.c`,
`src/fs/smbacl.c`, and supporting headers.

---

## Current State Summary

### QUERY_INFO — InfoType = SMB2_0_INFO_FILE (0x01)

| FileInfoClass | Value | Status | Notes |
|---|---|---|---|
| FileBasicInformation | 0x04 | Implemented | Minor issue: EASize always 0 in all-info path |
| FileStandardInformation | 0x05 | Implemented | Correct |
| FileInternalInformation | 0x06 | Implemented | Correct (stat.ino) |
| FileEaInformation | 0x07 | Partial | EASize hardcoded to 0; does not compute real EA size |
| FileAccessInformation | 0x08 | Implemented | Correct (fp->daccess) |
| FileNameInformation | 0x09 | Implemented | Via ksmbd_info.c dispatch handler |
| FileAlternateNameInformation | 0x15 | Implemented | Uses ksmbd_extract_shortname |
| FileStreamInformation | 0x16 | Partial (Bug P1) | StreamSize/StreamAllocationSize wrong for named streams |
| FilePipeInformation | 0x17 | Implemented (Stub) | Default zeroed values; ksmbd_info.c handler |
| FilePipeLocalInformation | 0x18 | Implemented (Stub) | Default zeroed values; ksmbd_info.c handler |
| FilePipeRemoteInformation | 0x19 | Implemented (Stub) | Default zeroed values; ksmbd_info.c handler |
| FileCompressionInformation | 0x1C | Partial | CompressedFileSize uses stat.blocks<<9, not real compressed size |
| FileAttributeTagInformation | 0x23 | Implemented | Checks xattr reparse data correctly |
| FileNormalizedNameInformation | 0x30 | Implemented | Via ksmbd_info.c dispatch handler |
| FileNetworkOpenInformation | 0x22 | Implemented | Correct |
| FileFullEaInformation | 0x0F | Implemented | SL_RETURN_SINGLE_ENTRY flag not enforced (P3) |
| FileIdInformation | 0x3B | Partial (Bug P1) | Wrong struct: only 8-byte FileId; missing VolumeSerialNumber |
| FileStatInformation | 0x46 | Missing | No handler registered |
| FileStatLxInformation | 0x47 | Missing | No handler registered |
| FileCaseSensitiveInformation | 0x48 | Implemented | Via ksmbd_info.c dispatch handler |
| FileHardLinkInformation | 0x2E | Partial | Returns only current file's link; no enumeration of other links |
| FileAllInformation | 0x12 | Partial | EASize always 0; otherwise correct |
| FileAlignmentInformation | 0x11 | Implemented | AlignmentRequirement = 0 |
| FilePositionInformation | 0x0E | Implemented | Correct |
| FileModeInformation | 0x10 | Implemented | Correct |
| FileObjectIdInformation | 0x1D | Implemented | Fallback generation from ino+generation+dev |
| FileReparsePointInformation | 0x21 | Implemented | Checks xattr reparse data |
| FileStandardLinkInformation | 0x36 | Implemented | Non-standard info class, implemented |
| FilePosixInformation (0x64) | 0x64 | Partial (Bug P2) | ReparseTag not read from xattr; only smb2_get_reparse_tag_special_file() |

### QUERY_INFO — InfoType = SMB2_0_INFO_FILESYSTEM (0x02)

| FsInformationClass | Value | Status | Notes |
|---|---|---|---|
| FileFsVolumeInformation | 0x01 | Implemented | VolumeCreationTime always 0; serial from CRC |
| FileFsSizeInformation | 0x03 | Implemented | SectorsPerAllocationUnit=1; accurate representation |
| FileFsDeviceInformation | 0x04 | Implemented | Correct |
| FileFsAttributeInformation | 0x05 | Implemented | Reports "NTFS"; configurable via share_fake_fscaps |
| FileFsFullSizeInformation | 0x07 | Implemented | Correct |
| FileFsObjectIdInformation | 0x08 | Implemented | ObjectId zeroed intentionally; extended_info present |
| FileFsControlInformation | 0x06 | Partial | GET: stub (TODO comment in code); SET: accepted/no-op |
| FileFsSectorSizeInformation | 0x0B | Implemented | Correct |
| FileFsDataCopyInformation | 0x0C | Missing | No handler registered |
| FileFsMetadataSizeInformation | 0x0D | Missing | No handler registered |
| FileFsLabelInformation | 0x02 | Implemented (SET only) | ksmbd_info.c: no-op accept |
| FileFsDriverPathInformation | 0x09 | Implemented | ksmbd_info.c: DriverInPath=0 |
| FileFsPosixInformation | 0x64 | Implemented | SMB3.1.1 POSIX extension |

### QUERY_INFO — InfoType = SMB2_0_INFO_SECURITY (0x03)

| Security Flag | Status | Notes |
|---|---|---|
| OWNER_SECINFO | Implemented | build_sec_desc() path; requires READ_CONTROL |
| GROUP_SECINFO | Implemented | build_sec_desc() path; requires READ_CONTROL |
| DACL_SECINFO | Implemented | Full ACL from stored NTSD or POSIX ACL conversion |
| SACL_SECINFO | Partial | Returns empty SACL (0 ACEs); audit ACEs never populated |
| LABEL_SECINFO | Accepted/No-op | Included in validation mask but not actioned |
| ATTRIBUTE_SECINFO | Accepted/No-op | Included in validation mask but not actioned |
| SCOPE_SECINFO | Accepted/No-op | Included in validation mask but not actioned |
| BACKUP_SECINFO | Accepted/No-op | Included in validation mask but not actioned |

### QUERY_INFO — InfoType = SMB2_0_INFO_QUOTA (0x04)

| Feature | Status | Notes |
|---|---|---|
| Quota query (SID-based) | Partial | ksmbd_quota.c: maps SIDs to UIDs, queries dquot_get_dqblk() when CONFIG_QUOTA; stub in ksmbd_info.c returns empty |
| RestartScan / ReturnSingle | Partial | RestartScan not fully stateful; no per-session scan cursor |

---

### SET_INFO — InfoType = SMB2_0_INFO_FILE (0x01)

| FileInfoClass | Value | Status | Notes |
|---|---|---|---|
| FileBasicInformation | 0x04 | Implemented | ctime save/restore logic; STORE_DOS_ATTRS path |
| FileRenameInformation | 0x0A | Implemented | ReplaceIfExists; POSIX semantics; veto check |
| FileRenameInformationEx | 0x41 | Implemented | Extended flags (POSIX_SEMANTICS, IGNORE_READONLY, etc.) |
| FileLinkInformation | 0x0B | Implemented | Hard link creation; ReplaceIfExists |
| FileDispositionInformation | 0x0D | Implemented | delete-on-close; directory empty check |
| FileDispositionInformationEx | 0x40 | Implemented | Extended flags (POSIX_SEMANTICS, IGNORE_READONLY, etc.) |
| FileEndOfFileInformation | 0x14 | Implemented | ksmbd_vfs_truncate(); FAT32 workaround |
| FileAllocationInformation | 0x13 | Implemented | fallocate; allocation size cache invalidation |
| FileShortNameInformation | 0x28 | Partial (Stub) | ksmbd_info.c: noop_consume; not persisted |
| FileValidDataLengthInformation | 0x27 | Partial | ksmbd_info.c: fallocate; limited permission checks |
| FileFullEaInformation | 0x0F | Implemented | smb2_set_ea() via user.* xattrs |
| FileCaseSensitiveInformation | 0x48 | Partial (Stub) | ksmbd_info.c: validates flags but does not apply to inode |
| FilePipeInformation | 0x17 | Partial (Stub) | ksmbd_info.c: validates size, consumes |
| FilePipeRemoteInformation | 0x19 | Partial (Stub) | ksmbd_info.c: validates size, consumes |
| FilePositionInformation | 0x0E | Implemented | Correct |
| FileModeInformation | 0x10 | Partial | Accepts all modes; FILE_SYNCHRONOUS_IO_* not enforced |
| FileObjectIdInformation | 0x1D | Implemented | Stored in XATTR_NAME_OBJECT_ID; only first 16 bytes |

### SET_INFO — InfoType = SMB2_0_INFO_SECURITY (0x03)

| Feature | Status | Notes |
|---|---|---|
| DACL_SECINFO | Implemented | set_info_sec() -> stores NTSD xattr when ACL_XATTR enabled |
| OWNER_SECINFO | Implemented | Requires FILE_WRITE_OWNER_LE access |
| GROUP_SECINFO | Implemented | Requires FILE_WRITE_OWNER_LE access |
| SACL_SECINFO | Partial | Requires FILE_ACCESS_SYSTEM_SECURITY_LE; stored but SACL ACEs not audited |
| LABEL/ATTRIBUTE/SCOPE/BACKUP | Accepted | Mask validated; silently ignored |

### SET_INFO — InfoType = SMB2_0_INFO_FILESYSTEM (0x02)

| Feature | Status | Notes |
|---|---|---|
| FS_CONTROL_INFORMATION | Accepted (No-op) | ksmbd_info.c: no quota enforcement |
| FS_LABEL_INFORMATION | Accepted (No-op) | ksmbd_info.c: label not persisted |
| FS_OBJECT_ID_INFORMATION | Accepted (No-op) | ksmbd_info.c: accepted but not stored |

### SET_INFO — InfoType = SMB2_0_INFO_QUOTA (0x04)

| Feature | Status | Notes |
|---|---|---|
| Quota set | Partial (Stub) | ksmbd_info.c: silently accepts; no enforcement |

---

## Confirmed Bugs (P1)

### BUG-P1-01: FileIdInformation struct is incomplete

**File:** `src/protocol/smb2/smb2_query_set.c:962-977`

The local `smb2_file_id_info` struct is defined as:
```c
struct smb2_file_id_info {
    __le64 FileId;
} __packed;
```

Per MS-FSCC §2.4.20, FileIdInformation MUST be:
```
VolumeSerialNumber: 8 bytes (ULONGLONG)
FileId:             16 bytes (128-bit file ID, ULONGLONG[2])
```

Total: 24 bytes. The current implementation writes only 8 bytes and uses `i_ino`
as the `FileId` field at `src/protocol/smb2/smb2_query_set.c:975`. This means:

1. The response is 16 bytes too small (8 bytes vs the required 24 bytes).
2. `VolumeSerialNumber` is completely absent.
3. `FileId` is 64-bit (inode number) instead of the required 128-bit persistent ID.

Windows clients use FileIdInformation for tracking open files. An undersized
response will cause clients to read past the valid data (information disclosure)
or reject the response.

**Impact:** Client file tracking incorrect; potential information disclosure.

---

### BUG-P1-02: FileStreamInformation reports wrong StreamSize and StreamAllocationSize for named streams

**File:** `src/protocol/smb2/smb2_query_set.c:618-619`

```c
file_info->StreamSize = cpu_to_le64(stream_name_len);
file_info->StreamAllocationSize = cpu_to_le64(stream_name_len);
```

`stream_name_len` at this point is the **length of the xattr name suffix** (i.e.,
the number of characters in the stream name after the `user.DOSATTRIB:` prefix),
not the actual size of the stream's data content. The code never calls
`ksmbd_vfs_getxattr()` to retrieve the stored data length.

For comparison, the `::$DATA` default stream (lines 698-699) correctly uses
`stat.size` and `ksmbd_alloc_size()`. Named streams report a nonsensical length
equal to the string length of their name.

**Impact:** Applications relying on named stream sizes (e.g., ADS-aware backup
software, Office 365 metadata streams) will see wrong file sizes.

---

## Missing Features (P2)

### GAP-P2-01: FileStatInformation (0x46) — Not implemented

Per MS-FSCC §2.4.47, FileStatInformation is an SMB3.1.1 extension providing
`LargeFileSize`, `AllocationSize`, `EndOfFile`, `NumberOfLinks`,
`ChangeTime`, `LastAccessTime`, `Flags`. No handler is registered in either
`smb2_query_set.c` or `ksmbd_info.c`. Any client requesting this level
will receive `STATUS_INVALID_INFO_CLASS`.

---

### GAP-P2-02: FileStatLxInformation (0x47) — Not implemented

Per MS-FSCC §2.4.48 (WSL/POSIX extension), FileStatLxInformation provides
`FileAttributes`, `ReparseTag`, `NumberOfLinks`, `ChangeTime`, `LastAccessTime`,
`LxFlags`, `LxUid`, `LxGid`, `LxMode`, `LxDeviceIdMajor`, `LxDeviceIdMinor`.
No handler registered. Clients using WSL2 on Windows may request this level.

---

### GAP-P2-03: FileFsDataCopyInformation (0x0C) — Not implemented

Per MS-FSCC §2.5.4, returns the number of data copies stored. No handler
registered; any query returns `STATUS_INVALID_INFO_CLASS`.

---

### GAP-P2-04: FileFsMetadataSizeInformation (0x0D) — Not implemented

Per MS-FSCC §2.5.5, reports metadata cluster size and allocation info. No
handler registered.

---

### GAP-P2-05: FilePosixInformation ReparseTag missing xattr path

**File:** `src/protocol/smb2/smb2_query_set.c:1085-1086`

```c
file_info->ReparseTag =
    smb2_get_reparse_tag_special_file(stat.mode);
```

Unlike `get_file_attribute_tag_info()` (which also reads
`XATTR_NAME_REPARSE_DATA` via `ksmbd_vfs_getxattr()`), `find_file_posix_info()`
never queries the reparse xattr. Files with xattr-backed reparse points (e.g.,
Windows symlinks stored via NFSv4 reparse) will report `ReparseTag = 0` in the
POSIX info response, even though `FileAttributeTagInformation` for the same file
would correctly report the tag.

---

### GAP-P2-06: FileEaInformation EASize always zero

**File:** `src/protocol/smb2/smb2_query_set.c:774-782`

```c
static void get_file_ea_info(struct smb2_query_info_rsp *rsp, void *rsp_org)
{
    struct smb2_file_ea_info *file_info;
    file_info = (struct smb2_file_ea_info *)rsp->Buffer;
    file_info->EASize = 0;
    ...
}
```

Per MS-FSCC §2.4.13, `EaSize` must contain the combined size of all EA
entries. The server always returns 0. The same hardcoded zero also appears in
`get_file_all_info()` at line 496. Applications that check the EA size before
issuing `FileFullEaInformation` queries will incorrectly skip EAs.

---

## Partial Implementations (P3)

### PARTIAL-P3-01: SACL query returns empty SACL (0 ACEs)

**File:** `src/fs/smbacl.c:1355-1372` (build_sec_desc SACL_SECINFO branch)

When `SACL_SECINFO` is requested, `build_sec_desc()` creates an SACL with
`num_aces = 0`. No audit ACEs are ever populated. The stored NTSD xattr is read
as `ppntsd` but the code does not extract existing SACL ACEs from it before
constructing the output. Windows audit policy enforcement will not function.

---

### PARTIAL-P3-02: SACL set accepted but audit ACEs not enforced

**File:** `src/protocol/smb2/smb2_query_set.c:2883-2913`

`smb2_set_info_sec()` accepts `SACL_SECINFO` writes and calls `set_info_sec()`
which stores the full NTSD in an xattr. The SACL is stored but the kernel never
evaluates audit ACEs during file access. This is a semantic gap: the stored SACL
will be returned to clients on a subsequent `QUERY_INFO(SACL_SECINFO)` call but
will never trigger audit events.

---

### PARTIAL-P3-03: FileFsControlInformation GET is a stub

**File:** `src/protocol/smb2/smb2_query_set.c:1487-1506`

```c
case FS_CONTROL_INFORMATION:
{
    /*
     * TODO : The current implementation is based on
     * test result with win7(NTFS) server. It's need to
     * modify this to get valid Quota values
     * from Linux kernel
     */
```

`DefaultQuotaThreshold` and `DefaultQuotaLimit` are set to `SMB2_NO_FID`
(0xFFFFFFFFFFFFFFFF). This should reflect actual filesystem quota settings
(e.g., from `/proc/fs/*/quota` or `dquot_get_dqblk()`). The TODO comment has
been present since the original Samsung upstream code.

---

### PARTIAL-P3-04: SL_RETURN_SINGLE_ENTRY not enforced in FileFullEaInformation

**File:** `src/protocol/smb2/smb2_query_set.c:215-219`

```c
if (le32_to_cpu(req->Flags) & SL_RETURN_SINGLE_ENTRY)
    ksmbd_debug(SMB,
                "All EAs are requested but need to send single EA entry...\n");
```

Per MS-SMB2 §3.3.5.20.1, when `SL_RETURN_SINGLE_ENTRY` is set in `Flags` and
no `InputBuffer` is provided, the server MUST return only the first EA entry.
The code logs the flag but continues to return all EA entries.

---

### PARTIAL-P3-05: FileHardLinkInformation returns stub with single link

**File:** `src/fs/ksmbd_info.c:484-545` (`ksmbd_info_get_hard_link`)

The handler returns the current file's own name in the link list with
`EntriesReturned = 1`. Per MS-FSCC §2.4.18, `FileHardLinkInformation` must
enumerate ALL hard links to the inode (all directory entries pointing to the
same inode number). This requires walking the filesystem or maintaining a
reverse inode-to-path index, which is not implemented. Only the open-file path
is returned.

---

### PARTIAL-P3-06: FileCaseSensitiveInformation SET does not apply to inode

**File:** `src/fs/ksmbd_info.c:1011-1030` (`ksmbd_info_set_case_sensitive`)

The handler validates the `FILE_CS_FLAG_CASE_SENSITIVE_DIR` flag but does not
actually toggle the `S_CASEFOLD` inode flag (or Linux 5.2+ `FS_CASEFOLD_FL`
via `ioctl(FS_IOC_SETFLAGS)`). Directories therefore remain at their kernel-
default case sensitivity regardless of client requests.

---

### PARTIAL-P3-07: FileModeInformation SET does not enforce FILE_SYNCHRONOUS_IO

**File:** `src/protocol/smb2/smb2_query_set.c:2683-2703`

The mode field is stored in `fp->coption` and the validation is correct.
However, there is a `TODO` comment at line 2697:
```c
/* TODO : need to implement consideration for
 * FILE_SYNCHRONOUS_IO_ALERT and FILE_SYNCHRONOUS_IO_NONALERT
```

When either synchronous IO flag is set, all subsequent I/O on the file handle
MUST complete synchronously (no pending/async I/O). This is not enforced.

---

### PARTIAL-P3-08: FileCompressionInformation uses block count as compressed size

**File:** `src/protocol/smb2/smb2_query_set.c:823`

```c
file_info->CompressedFileSize = cpu_to_le64(stat.blocks << 9);
```

`stat.blocks` is the number of 512-byte blocks allocated on disk (including
any holes in sparse files). For a non-compressed file, this is the logical
allocation size, not a "compressed" size. The field should reflect the actual
compressed byte count (via `ioctl(BTRFS_IOC_COMPRESS_INFO)` or equivalent).
For non-compressed filesystems the spec says `CompressedFileSize` SHOULD equal
the file size. Using `stat.blocks << 9` is inaccurate for sparse files.

---

### PARTIAL-P3-09: FileFsVolumeInformation — VolumeCreationTime always zero

**File:** `src/protocol/smb2/smb2_query_set.c:1395`

```c
info->VolumeCreationTime = 0;
```

MS-FSCC §2.5.9 requires `VolumeCreationTime` to be the creation time of the
volume. Linux exposes this via `statfs.f_fsid` or through
`/proc/fs/<fs>/*/info` on some filesystems. The zero value is harmless but
non-compliant.

---

### PARTIAL-P3-10: FS_SIZE_INFORMATION / FS_FULL_SIZE_INFORMATION block unit mismatch

**File:** `src/protocol/smb2/smb2_query_set.c:1422-1423, 1438-1439`

```c
info->SectorsPerAllocationUnit = cpu_to_le32(1);
info->BytesPerSector = cpu_to_le32(stfs.f_bsize);
```

Windows interprets this as: 1 sector per cluster, sector size = `f_bsize`
(typically 4096 bytes). While mathematically correct (`TotalBytes =
TotalAllocationUnits * 1 * f_bsize`), Windows disk defrag and storage analysis
tools expect `BytesPerSector` to be 512 and `SectorsPerAllocationUnit` to
represent the cluster factor. This can cause incorrect free-space display in
Windows Explorer for large volumes.

---

## Low Priority (P4)

### P4-01: FileAlternateNameInformation — short name generation is heuristic

**File:** `src/protocol/smb2/smb2_query_set.c:517-536`

`ksmbd_extract_shortname()` generates an 8.3 name from the long name using a
heuristic. It does not persist or retrieve short names from the filesystem. On
NTFS volumes, short names are stored alongside long names. The generated names
may differ across calls or server restarts.

---

### P4-02: LABEL_SECINFO / ATTRIBUTE_SECINFO / SCOPE_SECINFO / BACKUP_SECINFO

**File:** `src/protocol/smb2/smb2_query_set.c:1564-1571` (QUERY),
`src/protocol/smb2/smb2_query_set.c:2892-2898` (SET)

These flags are accepted in the validation masks but are never actioned:

- **LABEL_SECINFO (0x10):** Mandatory integrity label (Windows Integrity Levels).
  Not applicable to Linux-based servers; silent acceptance is correct.
- **ATTRIBUTE_SECINFO (0x20):** Resource attributes. Not implemented.
- **SCOPE_SECINFO (0x40):** Central Access Policy. Not implemented.
- **BACKUP_SECINFO (0x10000):** Allows reading the entire SD during backup.
  Should bypass access-check restrictions (requires SeBackupPrivilege). The
  server currently does not relax the READ_CONTROL check for this flag.

---

### P4-03: FileFsObjectIdInformation — ObjectId always zeroed

**File:** `src/protocol/smb2/smb2_query_set.c:1454`

```c
memset(info->objid, 0, 16);
```

The comment explains this is intentional to avoid leaking sensitive data.
Windows file system object IDs are used for reparse-point tracking. The
all-zeroes response is safe but prevents clients from using object IDs for
cross-reparse tracking.

---

### P4-04: Quota query ignores RestartScan semantics

**File:** `src/fs/ksmbd_quota.c`

`RestartScan` in the query quota input buffer is read but the server has no
per-session cursor for quota enumeration. Each call starts from the beginning
regardless of the RestartScan value. For large domains with many users this
would require multiple round trips that currently re-enumerate from scratch.

---

### P4-05: FileRenameInformation — RootDirectory field ignored

**File:** `src/protocol/smb2/smb2_query_set.c:1839-1912` (smb2_rename)

Per MS-FSCC §2.4.34, if `RootDirectory` is non-zero, it contains a file ID
that the `FileName` should be relative to. Both the `smb2_file_rename_info`
and `smb2_file_rename_info_ex` structs have this field. The code does not
validate or use `RootDirectory`; only `FileName` as an absolute share path
is processed.

---

## Compliance Estimate

| Domain | Implemented | Partial | Missing | Estimate |
|---|---|---|---|---|
| QUERY FILE info levels (core 20 levels) | 13 | 5 | 2 | ~70% |
| QUERY FILESYSTEM info levels (10 levels) | 7 | 2 | 2 | ~72% |
| QUERY SECURITY | 3 | 2 | 0 | ~75% |
| QUERY QUOTA | 1 | 1 | 0 | ~50% |
| SET FILE info levels (12 levels) | 7 | 5 | 0 | ~78% |
| SET SECURITY | 3 | 1 | 0 | ~80% |
| SET FILESYSTEM | 3 | 0 | 0 | ~85% (stubs) |
| SET QUOTA | 0 | 1 | 0 | ~40% (stub) |

**Overall QUERY_INFO / SET_INFO compliance estimate: ~72%**

The two P1 bugs (FileIdInformation struct wrong, StreamSize wrong for named
streams) would each cause interoperability failures with applications relying
on those fields. The most impactful missing features are FileStatInformation
and FileStatLxInformation (used by WSL2 and modern Windows storage APIs).

---

## Remediation Priority

1. **P1-01** — Fix `smb2_file_id_info` struct to include VolumeSerialNumber (8
   bytes) and expand FileId to 128 bits; populate VolumeSerialNumber from
   `s_dev`; set high 64 bits of FileId to inode generation or zero.
   (`src/protocol/smb2/smb2_query_set.c:962-977`)

2. **P1-02** — Fix `get_file_stream_info()` to call `ksmbd_vfs_getxattr()` for
   each discovered stream and set `StreamSize`/`StreamAllocationSize` to the
   actual xattr value length.
   (`src/protocol/smb2/smb2_query_set.c:618-619`)

3. **P2-06** — Implement real EA size computation in `get_file_ea_info()` by
   calling `ksmbd_vfs_listxattr()` and summing `smb2_ea_info` entry sizes.

4. **P2-01/P2-02** — Add FileStatInformation and FileStatLxInformation handlers
   in `ksmbd_info.c`.

5. **P3-04** — Enforce `SL_RETURN_SINGLE_ENTRY` in `smb2_get_ea()`.

6. **P3-06** — Implement `FileCaseSensitiveInformation` SET to call
   `ioctl(FS_IOC_SETFLAGS)` or `FS_IOC_FSSETXATTR` to toggle `FS_CASEFOLD_FL`.

7. **P2-05** — Add xattr reparse data lookup to `find_file_posix_info()`.
