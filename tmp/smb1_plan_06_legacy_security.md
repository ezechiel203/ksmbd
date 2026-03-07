# SMB1 MS-SMB Compliance Upgrade Plan — Section 06: Legacy Commands, Security Model, and UNIX Extensions

**Repository:** `/home/ezechiel203/ksmbd`
**Spec references:** MS-SMB (v20260114), MS-CIFS, MS-DFSC, Samba CIFS POSIX Extensions
**Date:** 2026-03-01
**Auditor:** Claude (automated analysis of ksmbd source tree)

> This document is part of the KSMBD SMB1 compliance series. It covers: legacy directory
> search commands (SEARCH/FIND family), file attribute commands (QUERY_INFORMATION2,
> SET_INFORMATION2), copy/move commands, legacy create/open commands, print queue
> commands, the error code model (DOS vs. NTSTATUS), UNIX/POSIX extensions, SMB1 signing
> correctness, DFS integration, and a consolidated implementation priority table.
>
> Cross-references to earlier parts:
> - `smb1_audit_part1.md` — Session, Tree, File Basics
> - `smb1_audit_part2.md` — Locking, Transactions, Search, Print
> - `smb1_plan_01_current_impl.md` — Dispatch table and NT_TRANSACT gaps

---

## Table of Contents

1. [Legacy Directory Search Commands](#1-legacy-directory-search-commands)
2. [File Attribute Commands (FID-Based)](#2-file-attribute-commands-fid-based)
3. [Copy and Move Commands](#3-copy-and-move-commands)
4. [Legacy File Create and Open Commands](#4-legacy-file-create-and-open-commands)
5. [Print Queue Commands](#5-print-queue-commands)
6. [Error Code Model](#6-error-code-model)
7. [UNIX Extensions (CIFS POSIX Extensions)](#7-unix-extensions-cifs-posix-extensions)
8. [SMB Signing Correctness](#8-smb-signing-correctness)
9. [DFS Integration](#9-dfs-integration)
10. [Implementation Priority Summary](#10-implementation-priority-summary)

---

## 1. Legacy Directory Search Commands

These commands pre-date the TRANS2_FIND_FIRST2/FIND_NEXT2 mechanism. They use the
older FCB (File Control Block) style 8.3-filename directory enumeration format.
None of them are registered in `smb1_server_cmds[]` in
`/home/ezechiel203/ksmbd/src/protocol/smb1/smb1ops.c`.

---

### 1.1 SMB_COM_SEARCH (0x81)

**Spec ref:** MS-SMB §2.2.4.10, §3.3.5.9; MS-CIFS §2.2.4.58

**Status:** NOT IMPLEMENTED — no entry in `smb1_server_cmds[]`

**Protocol Behavior:**

SMB_COM_SEARCH is the canonical legacy directory search command, used by MS-DOS,
Windows 3.x, and OS/2 clients. Unlike TRANS2_FIND_FIRST2 (which returns long
filenames and extended attributes), SEARCH returns entries in the classic
SMB_DATA.DirectoryInformationData format:

```
Per-entry layout (43 bytes total):
  ResumeKey[21]     — resume handle: ServerState[16] + ClientState[4] + Reserved[1]
  FileAttributes    — ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM |
                      ATTR_VOLUME | ATTR_DIRECTORY | ATTR_ARCHIVE
  LastWriteTime     — DOS time: Date[2] + Time[2]
  FileDataSize      — 32-bit file size
  FileName[13]      — 8.3 name, padded with spaces, no null termination
```

**Request Parameters:**
- `MaxCount` (u16): maximum entries to return in one response
- `SearchAttributes` (u16): attribute filter mask (ATTR_* bitmask)
- `FileName` (variable): search pattern with wildcards `*` and `?` in 8.3 format
- `ResumeKey[21]` (when continuing): opaque resume key from previous response

**MS-SMB §3.3.5.9 Additions:**
- If `FileName` is an empty string, the server SHOULD return the root directory entry
- Server MUST handle `FileName` containing `*.*` as "all files"
- Server MUST handle a lone `*` as equivalent to `*.*`
- Server MUST filter returned entries against `SearchAttributes`:
  - Hidden files returned only if ATTR_HIDDEN is set in SearchAttributes
  - System files returned only if ATTR_SYSTEM is set
  - Directories returned only if ATTR_DIRECTORY is set
- Server MUST NOT return volume labels unless ATTR_VOLUME is set

**ResumeKey Format (MS-SMB §2.2.4.10.2):**
```
Byte  0–15: ServerState  — opaque server-side state (directory position)
Byte 16–19: ClientState  — echoed back from client's resume key
Byte 20:    Reserved     — must be 0
```
The server encodes its directory position in `ServerState[16]`. On a subsequent
SEARCH with a non-zero ResumeKey, the server resumes from the encoded position.

**Current KSMBD State:**
The opcode 0x81 is not registered. Any client sending SMB_COM_SEARCH receives
`STATUS_SMB_BAD_COMMAND`. The TRANS2_FIND_FIRST2 infrastructure in
`smb1pdu.c` (lines 6290–6975) provides the readdir loop foundation, but the
response format and 8.3 name conversion are absent.

**Implementation Plan:**

1. Define the request/response structures in
   `/home/ezechiel203/ksmbd/src/include/protocol/smb1pdu.h`:
   ```c
   #define SMB_COM_SEARCH  0x81

   struct smb_com_search_req {
       struct smb_hdr hdr;
       __le16 MaxCount;
       __le16 SearchAttributes;
       __le16 ByteCount;
       __u8   BufferFormat1;       /* 0x04 = ASCII */
       /* FileName follows (variable) */
       __u8   BufferFormat2;       /* 0x05 = Variable block */
       __le16 SearchCount;         /* ResumeKey count (0 or 1) */
       /* ResumeKey[21] follows if SearchCount == 1 */
   } __packed;

   #define SMB_DIR_ENTRY_SIZE  43

   struct smb_dir_entry {
       __u8   ResumeKey[21];
       __u8   FileAttributes;
       __le16 LastWriteTime;
       __le16 LastWriteDate;
       __le32 FileDataSize;
       __u8   FileName[13];        /* 8.3, space-padded, no null */
   } __packed;
   ```

2. Implement `smb_search()` in
   `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c`:
   - Parse `FileName` pattern; convert to uppercase for case-insensitive match
   - If `FileName` is empty or null, use the root of the tree
   - Open directory using `ksmbd_vfs_opendir()` infrastructure
   - If incoming `ResumeKey` is non-zero, seek directory to encoded position
   - Iterate via `iterate_dir()`, filtering by `SearchAttributes` mask
   - For each matching entry, truncate/convert long name to 8.3 form:
     - Base name max 8 chars, extension max 3 chars (`.` separator)
     - Characters not valid in 8.3 (spaces, `+`, `,`, `;`, `=`, `[`, `]`) replaced with `_`
     - If name too long, use `~N` suffix (e.g. `LONGFI~1.TXT`)
   - Encode each entry as `smb_dir_entry`; fill `ResumeKey.ServerState` with inode+offset
   - Stop when `MaxCount` entries filled or directory exhausted
   - Set `Count` in response header to actual number of entries returned
   - If no entries match, return `STATUS_NO_MORE_FILES` (mapped to DOS `ERRnofiles`)

3. Register: `[SMB_COM_SEARCH] = { .proc = smb_search, }` in `smb1ops.c`

4. Add validation entry in `smb1_get_byte_count()` in `smb1misc.c`

**Implementation Effort:** MEDIUM (3–5 days)

**Priority:** Low — only MS-DOS and Windows 3.x clients use this command;
all Windows NT 3.1+ clients use TRANS2_FIND_FIRST2 instead.

---

### 1.2 SMB_COM_FIND (0x82)

**Spec ref:** MS-CIFS §2.2.4.59

**Status:** NOT IMPLEMENTED

**Protocol Behavior:**

SMB_COM_FIND is identical in wire format to SMB_COM_SEARCH but maintains a
persistent open search context on the server. The client can call FIND multiple
times with the same ResumeKey to enumerate additional entries. The search context
is closed by SMB_COM_FIND_CLOSE (0x84) when the client is done.

Key differences from SEARCH:
- Server allocates a server-side `SearchID` on the first call (stored in `ResumeKey.ServerState`)
- Subsequent calls supply the same `ResumeKey` to continue enumeration
- Search contexts must be tracked per-session (not per-connection)
- If the directory changes between FIND calls, server behavior is implementation-defined

**Current KSMBD State:** Not implemented (opcode 0x82 has no handler).

**Implementation Plan:**

1. Allocate a lightweight `smb_search_ctx` structure attached to the session:
   ```c
   struct smb_search_ctx {
       struct list_head list;
       __u16  search_id;       /* unique ID per session */
       struct file *dir_fp;    /* open directory file pointer */
       loff_t pos;             /* current directory position */
       __u16  search_attrs;    /* SearchAttributes filter */
   };
   ```

2. On first FIND call (ResumeKey all-zero): allocate context, open directory,
   store `search_id` in `ResumeKey.ServerState[0..1]`

3. On subsequent FIND calls: look up context by `search_id` from ResumeKey,
   seek directory to `ctx->pos`, continue iteration

4. Reuse the 8.3 conversion and entry encoding from `smb_search()`

5. Register: `[SMB_COM_FIND] = { .proc = smb_find, }` in `smb1ops.c`

**Implementation Effort:** MEDIUM (2–3 days, building on smb_search)

**Priority:** Low — only legacy MS-DOS clients require this.

---

### 1.3 SMB_COM_FIND_UNIQUE (0x83)

**Spec ref:** MS-CIFS §2.2.4.60

**Status:** NOT IMPLEMENTED

**Protocol Behavior:**

SMB_COM_FIND_UNIQUE behaves like FIND but automatically closes the search after
the first response batch. It is semantically equivalent to:
1. FIND (open search, get first batch)
2. FIND_CLOSE (immediately close search)

The server MUST NOT require a subsequent FIND_CLOSE for searches opened via
FIND_UNIQUE. The response format is identical to FIND.

**Current KSMBD State:** Not implemented (opcode 0x83 has no handler).

**Implementation Plan:**

1. Implement `smb_find_unique()`: call the same single-batch search logic as
   `smb_search()` (not `smb_find()` — no persistent context)

2. Return entries in the same 43-byte format

3. After populating the response, do NOT allocate a persistent search context

4. Register: `[SMB_COM_FIND_UNIQUE] = { .proc = smb_find_unique, }` in `smb1ops.c`

**Implementation Effort:** Very Low (1 day — trivial wrapper over smb_search)

**Priority:** Low — rarely used; superseded by TRANS2_FIND_FIRST2.

---

### 1.4 SMB_COM_FIND_CLOSE (0x84)

**Spec ref:** MS-CIFS §2.2.4.61

**Status:** NOT IMPLEMENTED

**IMPORTANT NOTE:** This is opcode 0x84, completely distinct from
SMB_COM_FIND_CLOSE2 (0x34) which IS implemented in KSMBD as `smb_closedir()`.

**Protocol Behavior:**

SMB_COM_FIND_CLOSE closes a persistent search context that was opened by
SMB_COM_FIND (0x82). The request carries the same `ResumeKey` that was returned
in the FIND response.

- If FIND (0x82) is not implemented, FIND_CLOSE (0x84) should return
  `STATUS_SUCCESS` for any input to avoid client hangs
- If FIND is implemented, FIND_CLOSE must locate and free the `smb_search_ctx`
  by `search_id`

**Current KSMBD State:** Not implemented. Clients sending 0x84 receive
`STATUS_SMB_BAD_COMMAND`.

**Implementation Plan:**

1. If SMB_COM_FIND (0x82) is implemented:
   - Extract `search_id` from the ResumeKey in the request
   - Locate and free the `smb_search_ctx` from the session's search list
   - Close `ctx->dir_fp` via `fput()`
   - Return `STATUS_SUCCESS`

2. If SMB_COM_FIND (0x82) is not yet implemented:
   - Add a stub that always returns `STATUS_SUCCESS` (harmless for non-existent contexts)

3. Register: `[SMB_COM_FIND_CLOSE] = { .proc = smb_find_close, }` in `smb1ops.c`

**Implementation Effort:** Very Low (stub: 0.5 days; full: 1 day with FIND)

**Priority:** Low — only needed when SMB_COM_FIND is implemented.

---

## 2. File Attribute Commands (FID-Based)

These commands operate on an already-open file handle (FID) rather than a path.
They provide a way to query and set attributes without re-opening the file.

---

### 2.1 SMB_COM_QUERY_INFORMATION2 (0x23)

**Spec ref:** MS-SMB §2.2.4.24; MS-CIFS §2.2.4.32

**Status:** NOT IMPLEMENTED — confirmed absent from `smb1_server_cmds[]`.
No opcode constant for 0x23 is defined in `smb1pdu.h`.

**Protocol Behavior:**

This is the FID-based counterpart to SMB_COM_QUERY_INFORMATION (0x08, path-based).
It queries extended file timestamps and sizes for an already-open file descriptor.

**Request Wire Format (WordCount = 1):**
```
USHORT  FID;               /* open file handle */
```

**Response Wire Format (WordCount = 11):**
```
USHORT  CreateDate;        /* DOS date of file creation */
USHORT  CreateTime;        /* DOS time of file creation */
USHORT  LastAccessDate;    /* DOS date of last access */
USHORT  LastAccessTime;    /* DOS time of last access */
USHORT  LastWriteDate;     /* DOS date of last write */
USHORT  LastWriteTime;     /* DOS time of last write */
ULONG   FileDataSize;      /* 32-bit file size in bytes */
ULONG   FileAllocationSize;/* 32-bit allocation size */
USHORT  FileAttributes;    /* ATTR_* attribute flags */
```

**Key Difference from QUERY_INFORMATION (0x08):**
- Takes FID instead of path (works even for files opened without sharing)
- Returns more timestamp detail: creation, last-access, and last-write separately
- Returns both data size and allocation size (QUERY_INFORMATION only returns size)

**Current KSMBD State:**

`smb_query_info()` (line ~8273 in `smb1pdu.c`) handles path-based 0x08 queries
but no FID-based handler exists for 0x23. Clients that use FID-based queries
(older Win16 applications, some backup software) will fail.

The infrastructure needed is already present:
- `ksmbd_lookup_fd_fast()` to resolve FID to `ksmbd_file`
- `ksmbd_vfs_getattr()` to query attributes
- `ksmbd_unix_time_to_dos_time()` for time conversion

**Implementation Plan:**

1. Add structures to `smb1pdu.h`:
   ```c
   #define SMB_COM_QUERY_INFORMATION2  0x23

   struct smb_com_query_information2_req {
       struct smb_hdr hdr;
       __le16 FID;
       __le16 ByteCount;       /* must be 0 */
   } __packed;

   struct smb_com_query_information2_rsp {
       struct smb_hdr hdr;
       __le16 CreateDate;
       __le16 CreateTime;
       __le16 LastAccessDate;
       __le16 LastAccessTime;
       __le16 LastWriteDate;
       __le16 LastWriteTime;
       __le32 FileDataSize;
       __le32 FileAllocationSize;
       __le16 FileAttributes;
       __le16 ByteCount;       /* 0 */
   } __packed;
   ```

2. Implement `smb_query_info2()` in `smb1pdu.c`:
   ```c
   static int smb_query_info2(struct ksmbd_work *work)
   {
       struct smb_com_query_information2_req *req = work->request_buf;
       struct smb_com_query_information2_rsp *rsp = work->response_buf;
       struct ksmbd_file *fp;
       struct kstat stat;
       u16 attr;

       fp = ksmbd_lookup_fd_fast(work, le16_to_cpu(req->FID));
       if (!fp)
           return -EBADF;  /* maps to STATUS_INVALID_HANDLE */

       if (ksmbd_vfs_getattr(&fp->filp->f_path, &stat)) {
           ksmbd_fd_put(work, fp);
           return -EIO;
       }

       /* Populate creation time from xattr or fallback to mtime */
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

3. Register: `[SMB_COM_QUERY_INFORMATION2] = { .proc = smb_query_info2, }` in `smb1ops.c`

4. Add size validation in `smb1_get_byte_count()` and `smb1_calc_size()` in `smb1misc.c`

**Implementation Effort:** Low (1–2 days)

**Priority:** Medium — used by older Windows applications and some backup utilities.
Covered partially by TRANS2_QUERY_FILE_INFORMATION for modern clients.

---

### 2.2 SMB_COM_SET_INFORMATION2 (0x22)

**Spec ref:** MS-SMB §2.2.4.23; MS-CIFS §2.2.4.18

**Status:** NOT IMPLEMENTED — no opcode constant for 0x22 is defined in `smb1pdu.h`.
Confirmed absent from dispatch table (`smb1_server_cmds[]` in `smb1ops.c`).

**Protocol Behavior:**

This is the FID-based counterpart to SMB_COM_SET_INFORMATION (0x09 / SETATTR,
path-based). It sets file timestamps for an already-open file handle.

**Request Wire Format (WordCount = 7):**
```
USHORT  FID;               /* open file handle */
USHORT  CreateDate;        /* DOS date for creation (0 = no change) */
USHORT  CreateTime;        /* DOS time for creation (0 = no change) */
USHORT  LastAccessDate;    /* DOS date for last access (0 = no change) */
USHORT  LastAccessTime;    /* DOS time for last access (0 = no change) */
USHORT  LastWriteDate;     /* DOS date for last write (0 = no change) */
USHORT  LastWriteTime;     /* DOS time for last write (0 = no change) */
USHORT  ByteCount;         /* 0 */
```

**Compliance Rules (MS-CIFS §3.3.5.37):**
- Server MUST apply timestamps with non-zero date AND non-zero time fields
- A zero date with a non-zero time (or vice versa) SHOULD be treated as "no change"
- Server MUST NOT update the creation time stored in the file if the `CreateDate`
  or `CreateTime` field is 0 (unchanged semantics)
- Server SHOULD update `LastWriteTime` on close when the file has been written
  since the SMB_COM_SET_INFORMATION2 call, per MS-SMB §3.3.5.10

**Current KSMBD State:**

No handler. TRANS2_SET_FILE_INFORMATION (FileBasicInformation level) provides
equivalent functionality for modern clients, but pre-NT Windows applications and
legacy SMB clients use SET_INFORMATION2.

The infrastructure is available:
- `ksmbd_lookup_fd_fast()` for FID resolution
- `ksmbd_vfs_utimes()` / `notify_change()` for timestamp update

**Implementation Plan:**

1. Add structures to `smb1pdu.h`:
   ```c
   #define SMB_COM_SET_INFORMATION2  0x22

   struct smb_com_set_information2_req {
       struct smb_hdr hdr;
       __le16 FID;
       __le16 CreateDate;
       __le16 CreateTime;
       __le16 LastAccessDate;
       __le16 LastAccessTime;
       __le16 LastWriteDate;
       __le16 LastWriteTime;
       __le16 ByteCount;       /* must be 0 */
   } __packed;
   ```

2. Implement `smb_set_info2()` in `smb1pdu.c`:
   - Resolve FID via `ksmbd_lookup_fd_fast()`
   - For each (Date, Time) pair where both are non-zero:
     - Convert DOS date/time to `timespec64` via `smb_DosDateTimeToUnix()`
     - Set the appropriate field in `struct iattr`
   - Call `ksmbd_vfs_setattr()` with the populated `iattr`
   - Return `STATUS_SUCCESS` on success

3. Register: `[SMB_COM_SET_INFORMATION2] = { .proc = smb_set_info2, }` in `smb1ops.c`

4. Update validation tables in `smb1misc.c`

**Implementation Effort:** Low (1–2 days)

**Priority:** Medium — used by older Windows and some POSIX-interop clients for
setting file timestamps by open handle.

---

## 3. Copy and Move Commands

---

### 3.1 SMB_COM_COPY (0x29)

**Spec ref:** MS-SMB §2.2.4.29; MS-CIFS §2.2.4.34

**Status:** NOT IMPLEMENTED — no handler registered in `smb1_server_cmds[]`.

**Protocol Behavior:**

SMB_COM_COPY performs a server-side file copy without transferring data to the
client. The client specifies a source path (relative to the request's TID) and
a destination path (relative to `Tid2`, which may be a different tree connection).

**Request Wire Format (WordCount = 3):**
```
USHORT  Tid2;              /* destination TID; same as request TID for intra-share */
USHORT  OpenFunction;      /* open/create disposition for destination */
USHORT  Flags;             /* operation modifier flags */
USHORT  ByteCount;
BYTE    BufferFormat1;     /* 0x04 = ASCII; 0x00 ignored */
STRING  OldFileName;       /* source path */
BYTE    BufferFormat2;
STRING  NewFileName;       /* destination path */
```

**`Flags` field bits:**
- `SMB_COPY_TARGET_MODE` (0x0001): if set, destination is ASCII; else matches request encoding
- `SMB_COPY_SOURCE_MODE` (0x0002): if set, source is ASCII
- `SMB_COPY_VERIFY_WRITES` (0x0004): verify each write via read-back
- `SMB_COPY_TREE` (0x0008): recursively copy a directory tree

**`OpenFunction` values:**
- 0x00: fail if destination exists
- 0x01: open and overwrite if exists, fail if not
- 0x10: fail if exists, create if not (default copy behavior)
- 0x11: overwrite if exists, create if not

**Response:**
```
USHORT  CopyCount;         /* number of files successfully copied */
```

**Error Handling:**
- If destination exists and `OpenFunction` disallows overwrite: `STATUS_OBJECT_NAME_COLLISION`
- If source does not exist: `STATUS_OBJECT_NAME_NOT_FOUND`
- If `Tid2` refers to a disconnected tree: `STATUS_INVALID_SMB`
- For recursive copy (SMB_COPY_TREE flag), `CopyCount` reflects total files copied

**Current KSMBD State:**

No handler for 0x29. The server already has `ksmbd_vfs_copy_file_range()` (wrapping
`vfs_copy_file_range()`) for SMB2 server-side copy (ODX). The rename/copy
infrastructure in `vfs.c` can be reused.

**Implementation Plan:**

1. Implement `smb_copy()` in `smb1pdu.c`:
   - Resolve source path relative to `work->tcon`
   - Resolve `Tid2` to a `ksmbd_tree_connect` for the destination
   - If `SMB_COPY_TREE` flag is set, implement recursive copy using `iterate_dir()`
   - For each source file:
     - Open source with read access
     - Open/create destination based on `OpenFunction`
     - Call `ksmbd_vfs_copy_file_range()` or fall back to read+write loop
     - Copy file attributes and timestamps
     - Increment `CopyCount` on success
   - If `SMB_COPY_VERIFY_WRITES` is set: after each chunk write, read back and compare
     (this flag is rarely set in practice; a stub returning STATUS_SUCCESS is acceptable)

2. Register: `[SMB_COM_COPY] = { .proc = smb_copy, }` in `smb1ops.c`

3. Cross-share copy requires resolving `Tid2` independently from `work->tcon`:
   ```c
   struct ksmbd_tree_connect *dst_tcon =
       ksmbd_tree_conn_from_id(work->sess, le16_to_cpu(req->Tid2));
   ```

**Implementation Effort:** High (5–7 days including recursive copy and cross-TID logic)

**Priority:** Medium — rarely invoked by modern clients (Windows Vista+ uses
IOCTL-based server-side copy through SMB2), but needed for Windows 9x/NT4 interop.

---

### 3.2 SMB_COM_MOVE (0x2A)

**Spec ref:** MS-SMB §2.2.4.30; MS-CIFS §2.2.4.35

**Status:** NOT IMPLEMENTED — no handler registered in `smb1_server_cmds[]`.

**Protocol Behavior:**

SMB_COM_MOVE is similar to SMB_COM_COPY but atomically moves (renames) a file or
directory, potentially across tree connections. For same-volume moves, this maps
to an atomic `rename()`. For cross-volume moves, it requires copy-then-delete.

**Request Wire Format:** Same as SMB_COM_COPY (WordCount = 3), same `Flags` and
`OpenFunction` fields.

**Key Semantic Differences from COPY:**
- Source file MUST be deleted after successful copy (for cross-volume moves)
- For same-volume same-share moves: use `ksmbd_vfs_rename()` for atomicity
- For cross-share moves: copy then delete, non-atomic — must document this limitation
- If move fails midway (after copy but before delete): server should attempt rollback;
  if rollback fails, log and return `STATUS_UNEXPECTED_IO_ERROR`

**Current KSMBD State:** No handler for 0x2A.

**Implementation Plan:**

1. Implement `smb_move()` in `smb1pdu.c`:
   - Determine if source and destination are on the same volume by comparing device IDs
   - If same volume/same tree: call `ksmbd_vfs_rename()` for atomic rename
   - If cross-volume: call `smb_copy()` logic, then delete source on success
   - Set `CopyCount = 1` in response on success, `CopyCount = 0` on failure

2. Register: `[SMB_COM_MOVE] = { .proc = smb_move, }` in `smb1ops.c`

**Implementation Effort:** High (3–5 days, building on smb_copy infrastructure)

**Priority:** Medium — needed for Windows 9x/NT4; modern clients use SMB2
CREATE + IOCTL or RENAME instead.

---

## 4. Legacy File Create and Open Commands

These commands predate SMB_COM_OPEN_ANDX and SMB_COM_NT_CREATE_ANDX. They are
rarely needed for Windows XP+ clients but may be required for DOS/Windows 3.x/9x
interoperability.

---

### 4.1 SMB_COM_OPEN (0x02)

**Spec ref:** MS-CIFS §2.2.4.3

**Status:** NOT IMPLEMENTED — no entry in `smb1_server_cmds[]`.

**Protocol Behavior:**

The original CIFS open command. Simpler than OPEN_ANDX: no AndX chaining, no
CreateDisposition control (always opens existing or fails).

**Request (WordCount = 2):**
```
USHORT  DesiredAccess;     /* mode: 0=read, 1=write, 2=read-write, 3=execute */
USHORT  SearchAttributes;  /* files to open: ATTR_* filter */
USHORT  ByteCount;
BYTE    BufferFormat;      /* 0x04 */
STRING  FileName;
```

**Response (WordCount = 7):**
```
USHORT  FID;
USHORT  FileAttributes;
ULONG   LastWriteTime;     /* UTC seconds since epoch (POSIX time) */
ULONG   FileDataSize;      /* 32-bit file size */
USHORT  GrantedAccess;     /* actual access mode granted */
```

**Implementation Plan:**

1. Add `SMB_COM_OPEN 0x02` to `smb1pdu.h` if not already defined (check; the
   constant may exist but have no handler)

2. Implement `smb_open()` as a simplified wrapper:
   - Parse DesiredAccess, SearchAttributes, FileName
   - Call the common open path shared with `smb_open_andx()` (extract a helper
     `__smb_open_file()` that both OPEN and OPEN_ANDX call)
   - Populate the non-ANDX response format
   - No AndX chaining to implement

3. Register: `[SMB_COM_OPEN] = { .proc = smb_open, }` in `smb1ops.c`

**Implementation Effort:** Medium (2–3 days)

**Priority:** Low — only pre-NT clients use this command.

---

### 4.2 SMB_COM_CREATE (0x03)

**Spec ref:** MS-CIFS §2.2.4.4

**Status:** NOT IMPLEMENTED

**Protocol Behavior:**

Creates a new file, or truncates an existing one to zero length.

**Request (WordCount = 3):**
```
USHORT  FileAttributes;    /* ATTR_* for new file */
ULONG   CreationTime;      /* file creation time (0 = use current) */
USHORT  ByteCount;
BYTE    BufferFormat;
STRING  FileName;
```

**Response (WordCount = 1):**
```
USHORT  FID;
```

**Implementation Plan:**

1. Implement `smb_create()` using `ksmbd_vfs_create()` with `O_CREAT | O_TRUNC`
2. Set file attributes and creation time via `ksmbd_vfs_setattr()`
3. Register in dispatch table

**Implementation Effort:** Low (1–2 days)

**Priority:** Low — Windows NT 3.1+ always uses NT_CREATE_ANDX instead.

---

### 4.3 SMB_COM_CREATE_NEW (0x0F)

**Spec ref:** MS-CIFS §2.2.4.15

**Status:** NOT IMPLEMENTED

**Protocol Behavior:**

Creates a file only if it does NOT exist. If the file already exists, server MUST
return `STATUS_OBJECT_NAME_COLLISION` (maps to DOS `ERRfilexists`).
This provides atomic "create-if-not-exists" semantics.

**Request (WordCount = 3):** Same as SMB_COM_CREATE
**Response (WordCount = 1):** `FID`

**Implementation Plan:**

1. Implement `smb_create_new()` using `ksmbd_vfs_create()` with `O_CREAT | O_EXCL`
2. Map `-EEXIST` to `STATUS_OBJECT_NAME_COLLISION`
3. Register in dispatch table

**Implementation Effort:** Very Low (1 day — shares create path with SMB_COM_CREATE)

**Priority:** Low — pre-NT clients only.

---

### 4.4 SMB_COM_CREATE_TEMPORARY (0x0E)

**Spec ref:** MS-CIFS §2.2.4.14

**Status:** NOT IMPLEMENTED

**Protocol Behavior:**

Creates a temporary file with a unique server-generated name in the specified directory.
The server returns the generated filename in the response (this is the only legacy
command where the server generates the filename).

**Request (WordCount = 3):**
```
USHORT  FileAttributes;    /* ATTR_* for the temp file */
ULONG   CreationTime;
USHORT  ByteCount;
BYTE    BufferFormat;
STRING  DirectoryName;     /* target directory */
```

**Response (WordCount = 1):**
```
USHORT  FID;
USHORT  ByteCount;
BYTE    BufferFormat;
STRING  FileName;          /* server-generated temp filename */
```

**Implementation Plan:**

1. Generate a unique filename using `ksmbd_inode_next_id()` or equivalent
2. Create the file using `ksmbd_vfs_create()` with `O_CREAT | O_EXCL`
3. Return the generated filename in the response string
4. Register in dispatch table

**Implementation Effort:** Low (1–2 days)

**Priority:** Low — rarely used; OS-level temp file creation is preferred.

---

### 4.5 SMB_COM_WRITE_AND_CLOSE (0x2C)

**Spec ref:** MS-CIFS §2.2.4.41

**Status:** NOT IMPLEMENTED — confirmed absent from `smb1_server_cmds[]`.

**Protocol Behavior:**

Combines a write operation and a file close into a single PDU. Used by applications
that write the final block of data and immediately close. The `LastWriteTime` field
in the request specifies the modification time to set on close.

**Request (WordCount = 6 or 12 with padding):**
```
USHORT  FID;
USHORT  Count;             /* bytes to write */
ULONG   Offset;            /* file offset for write */
ULONG   LastWriteTime;     /* mtime to set on close (0 = server sets) */
USHORT  ByteCount;
BYTE    Pad[3];            /* alignment padding (WordCount == 12 variant) */
BYTE    Data[Count];
```

**Compliance Rules:**
- Server MUST write `Count` bytes at `Offset`
- Server MUST close the FID after the write, even if the write fails
- Server MUST update file mtime to `LastWriteTime` if it is non-zero
- If `Count == 0`, server MUST still close the FID (write-zero-and-close)
- Server MUST return `STATUS_SUCCESS` if close succeeds even if write returned error

**Current KSMBD State:** No handler. The separate operations exist:
- `smb_write()` in `smb1pdu.c`
- `smb_close()` in `smb1pdu.c`

**Implementation Plan:**

1. Add structure to `smb1pdu.h`:
   ```c
   #define SMB_COM_WRITE_AND_CLOSE  0x2C

   struct smb_com_write_and_close_req {
       struct smb_hdr hdr;
       __le16 FID;
       __le16 Count;
       __le32 Offset;
       __le32 LastWriteTime;
       __le16 ByteCount;
       __u8   Pad[3];
       /* Data follows */
   } __packed;
   ```

2. Implement `smb_write_and_close()` in `smb1pdu.c`:
   - Validate FID via `ksmbd_lookup_fd_fast()`
   - If `Count > 0`: call VFS write at `Offset` (reuse `__smb_write()` helper)
   - If `LastWriteTime != 0`: update mtime via `ksmbd_vfs_utimes()`
   - Close FID unconditionally via `ksmbd_close_fd()` / `ksmbd_put_file()`
   - Return count of bytes written (0 if Count was 0)

3. Register: `[SMB_COM_WRITE_AND_CLOSE] = { .proc = smb_write_and_close, }` in `smb1ops.c`

**Implementation Effort:** Low (1–2 days)

**Priority:** Low — WRITE_ANDX + CLOSE is used by modern clients instead.

---

### 4.6 SMB_COM_SEEK (0x12)

**Spec ref:** MS-CIFS §2.2.4.20

**Status:** NOT IMPLEMENTED — no handler and no per-FID seek state in KSMBD.

**Protocol Behavior:**

Maintains a per-FID "current file position" on the server. Subsequent SMB_COM_READ
(0x0A) and SMB_COM_WRITE (0x0B) calls (the legacy non-ANDX variants) use this
position when no explicit offset is provided.

**Request (WordCount = 4):**
```
USHORT  FID;
USHORT  Mode;              /* 0=from beginning, 1=from current, 2=from end */
LONG    Offset;            /* signed offset (can be negative for mode 1 and 2) */
```

**Response (WordCount = 2):**
```
ULONG   Offset;            /* new absolute file position */
```

**Current KSMBD State:**

KSMBD is stateless with respect to file position — READ_ANDX and WRITE_ANDX
always supply explicit 64-bit offsets, so no seek state is needed for them.
Adding seek state requires a per-FID `current_offset` field.

**NOTE:** SMB_COM_SEEK only matters for the legacy SMB_COM_READ (0x0A) and
SMB_COM_WRITE (0x0B). Since READ_ANDX and WRITE_ANDX always carry explicit
offsets, SEEK is entirely irrelevant for any client using ANDX variants.

**Implementation Plan:**

1. Add `current_offset` field to `ksmbd_file` structure in
   `/home/ezechiel203/ksmbd/src/include/fs/vfs_cache.h`:
   ```c
   loff_t  current_offset;   /* per-FID seek position for legacy COM_READ/WRITE */
   ```

2. Implement `smb_seek()` in `smb1pdu.c`:
   - Resolve FID
   - Compute new offset based on Mode (beginning/current/end):
     ```c
     switch (mode) {
     case 0: new_off = signed_offset; break;
     case 1: new_off = fp->current_offset + signed_offset; break;
     case 2: new_off = stat.size + signed_offset; break;
     }
     if (new_off < 0) new_off = 0;
     fp->current_offset = new_off;
     ```
   - Return new absolute offset in response

3. Modify `smb_read()` (legacy 0x0A) to use `fp->current_offset` when the
   request does not carry an explicit offset (the legacy COM_READ format uses
   a fixed offset field, but SEEK updates it)

4. Register: `[SMB_COM_SEEK] = { .proc = smb_seek, }` in `smb1ops.c`

**Implementation Effort:** Medium (2–3 days including per-FID state addition)

**Priority:** Low — only relevant for legacy SMB_COM_READ/WRITE which themselves
are not implemented. Implement only if those legacy commands are added.

---

## 5. Print Queue Commands

The following print queue commands are absent from KSMBD. They operate on SMB
printer shares (share type `STYPE_PRINTQ`).

---

### 5.1 SMB_COM_WRITE_PRINT_FILE (0x36)

**Spec ref:** MS-CIFS §2.2.4.50 (note: opcode assignment varies; see §2.2 command table)

**Actual opcode in MS-CIFS §2.2 table:** 0x44 (`SMB_COM_WRITE_PRINT_FILE`)
Confirmed in `smb1_audit_part2.md`: the opcode is 0x44.

**Status:** NOT IMPLEMENTED — no handler in `smb1_server_cmds[]`.

**Protocol Behavior:**

Writes raw print data to an open spool file descriptor. The FID must have been
opened via SMB_COM_OPEN_PRINT_FILE (0x43).

**Request:**
```
USHORT  FID;               /* open spool file handle */
USHORT  ByteCount;
BYTE    BufferFormat;      /* 0x01 = Data block */
USHORT  DataLength;
BYTE    Data[DataLength];  /* raw print data */
```

**Implementation Plan:**

1. Implement `smb_write_print_file()`: resolve FID, write data to the underlying
   spool file using standard VFS write (`ksmbd_vfs_write()`)
2. The spool file is a temporary file created by `smb_open_print_file()`
3. Register at opcode 0x44

**Implementation Effort:** Very Low (write is identical to regular file write)

**Priority:** Low — only printer shares need this.

---

### 5.2 SMB_COM_CLOSE_PRINT_FILE (0x45)

**Spec ref:** MS-CIFS §2.2.4.51

**Status:** NOT IMPLEMENTED — opcode 0x45 has no handler.

**Protocol Behavior:**

Closes a spool file and submits it to the print queue. The server should:
1. Flush all pending data to the spool file
2. Close the file descriptor
3. Submit the spool file to the underlying print system (e.g., `lpr`, CUPS)

The submission mechanism is implementation-defined. KSMBD does not manage printers
directly; the spool file can be placed in a configurable spool directory, and an
external process (configured via `ksmbd.conf`) can pick it up.

**Implementation Plan:**

1. Implement `smb_close_print_file()`:
   - Flush the spool file via `vfs_fsync()`
   - Close the FID via standard `ksmbd_close_fd()`
   - Optionally: invoke a userspace print submission script via kernel-to-user IPC
     (the transport_ipc.c netlink channel can carry print job notifications)
   - If no print backend is configured: simply close the file and return success

2. Register at opcode 0x45

**Implementation Effort:** Low-Medium (2–3 days including spool submission stub)

**Priority:** Low — only printer shares need this.

---

### 5.3 SMB_COM_GET_PRINT_QUEUE (0x3D)

**Spec ref:** MS-CIFS §2.2.4.42

**Status:** NOT IMPLEMENTED — opcode 0x3D has no handler.

**Protocol Behavior:**

Returns a list of pending print jobs in the queue. Used by clients to display
print queue status.

**Request:**
```
USHORT  MaxCount;          /* maximum entries to return */
USHORT  StartIndex;        /* starting index in queue */
```

**Response:**
```
USHORT  Count;             /* number of entries returned */
USHORT  RestartIndex;      /* index for next call */
PrintQueueEntry Entries[Count];
```

Each `PrintQueueEntry` (28 bytes) contains:
```
USHORT  Length;            /* entry length */
USHORT  Priority;          /* job priority (1=highest, 9=lowest) */
ULONG   Time;              /* job submission time */
USHORT  Status;            /* job status */
USHORT  JobID;             /* job identifier */
ULONG   Size;              /* job size in bytes */
BYTE    Reserved;
CHAR    Name[16];          /* submitter name */
CHAR    Comment[40];       /* job comment */
```

**Implementation Plan:**

1. Implement `smb_get_print_queue()`:
   - If no print backend is configured: return `Count = 0` (empty queue) — valid response
   - If a spool directory is configured: enumerate pending spool files and populate entries
   - Return `STATUS_SUCCESS` with empty queue as the minimum compliant implementation

2. Register at opcode 0x3D

**Implementation Effort:** Low (stub returning empty queue: 0.5 days)

**Priority:** Low — rarely used; Windows clients typically use LANMAN RAP
`NetPrintQEnum` via TRANSACTION instead.

---

### 5.4 SMB_COM_OPEN_PRINT_FILE (0x43)

**Spec ref:** MS-CIFS §2.2.4.49

**Status:** NOT IMPLEMENTED — opcode 0x43 has no handler.

**Protocol Behavior:**

Creates a new spool file on the server and returns a FID for writing print data.

**Request:**
```
USHORT  SetupLength;       /* bytes of setup data at start of file */
USHORT  Mode;              /* 0=text (CR-LF transform), 1=graphics (raw) */
USHORT  ByteCount;
BYTE    BufferFormat;
STRING  IdentifierString;  /* print job identifier */
```

**Implementation Plan:**

1. Create a temporary file in a configurable spool directory
2. Return a FID that maps to this spool file
3. Store `Mode` and `IdentifierString` as metadata (xattr or in-memory)
4. Register at opcode 0x43

**Implementation Effort:** Low (1–2 days)

**Priority:** Low — only printer shares need this; implement alongside the other
print commands as a coherent unit.

---

## 6. Error Code Model

### 6.1 Current State in KSMBD

KSMBD uses NTSTATUS codes as the primary and only error format for SMB1 responses.
The `smb_hdr.Status` union carries either:
- A 32-bit NTSTATUS in the `CifsError` field, or
- A DOS error in the `DosError.ErrorClass` / `DosError.Error` fields

The `SMBFLG2_ERR_STATUS` bit in `smb_hdr.Flags2` tells the client which format
is in use. KSMBD always sets this bit (indicating NTSTATUS), regardless of what
the client requested.

The mapping function `ntstatus_to_dos()` exists at
`/home/ezechiel203/ksmbd/src/protocol/common/netmisc.c` and is declared in
`/home/ezechiel203/ksmbd/src/include/core/glob.h`. The table
`ntstatus_to_dos_map[]` contains over 200 entries covering the most common
NTSTATUS codes. The function IS callable today.

However, inspection of `smb1pdu.c` reveals that only a few scattered locations
call `ntstatus_to_dos()` or manually set DOS error fields (lines 1763, 1765,
2680–2681, 2697–2699, 2719–2720, 7726–7727, 8480–8482). The code checks
`!(rsp->hdr.Flags2 & SMBFLG2_ERR_STATUS)` at these specific sites, but the
general error-setting path (`smb1_set_err_rsp()` or equivalent) does NOT
perform this conversion.

### 6.2 Specification Requirements

**MS-SMB §3.1.4.2 — Error Response:**

> The server MUST check the client's `Flags2.ERR_STATUS` bit:
> - If `Flags2.ERR_STATUS` is SET (0x4000): use NTSTATUS format
> - If `Flags2.ERR_STATUS` is CLEAR: use DOS error format
>   (ErrorClass + 16-bit ErrorCode)

**MS-SMB §2.2.1 — SMB Header:**

> `Status.DosError.ErrorClass`: `ERRDOS` (0x01), `ERRSRV` (0x02),
>   `ERRHRD` (0x03), `ERRCMD` (0xFF)
> `Status.DosError.Error`: 16-bit error code within the class

**Affected Clients:**

Clients that do NOT set `SMBFLG2_ERR_STATUS` in their request include:
- Pre-NT LM 0.12 clients (OS/2, MS-DOS/MSNET clients)
- Some embedded SMB clients (network printers, NAS firmware)
- Clients negotiating dialect below "NT LM 0.12"

When KSMBD sends NTSTATUS to these clients with the ERR_STATUS bit clear in the
request, the client interprets the 32-bit NTSTATUS as a DOS error, producing
incorrect error messages or fatal client errors.

### 6.3 Compliance Gap

**CRITICAL:** The `smb1_set_err_rsp()` or equivalent central error response function
must check the client's `Flags2` bit and map NTSTATUS to DOS errors when required.

Currently, KSMBD always responds with `SMBFLG2_ERR_STATUS` set in `Flags2`, even
if the client's request had this bit cleared. This is a protocol violation per
MS-SMB §3.3.4.1.

### 6.4 Critical DOS Error Mappings Required

The `ntstatus_to_dos_map[]` table in `netmisc.c` already contains correct mappings.
The critical ones are verified present:

| NTSTATUS | DOS Class | DOS Code | DOS Constant | Verified in netmisc.c |
|----------|-----------|----------|--------------|----------------------|
| STATUS_NO_SUCH_FILE | ERRDOS | 2 | ERRnosuchfile | Yes (ERRbadfile maps) |
| STATUS_PATH_NOT_FOUND | ERRDOS | 3 | ERRbadpath | Yes (line 92) |
| STATUS_ACCESS_DENIED | ERRDOS | 5 | ERRnoaccess | Yes (line 67) |
| STATUS_OBJECT_NAME_COLLISION | ERRDOS | 80 | ERRfilexists | Yes (line 87) |
| STATUS_DISK_FULL | ERRDOS | 112 | ERRdiskfull | Yes (line 171) |
| STATUS_NOT_SUPPORTED | ERRDOS | 0x32 | ERRunsup | Yes (line 236) |
| STATUS_INVALID_PARAMETER | ERRDOS | 87 | 87 | Yes (line 37) |
| STATUS_SHARING_VIOLATION | ERRDOS | 32 | ERRbadshare | Yes (line 101) |
| STATUS_LOCK_NOT_GRANTED | ERRDOS | 33 | ERRlock | Yes (line 119) |
| STATUS_FILE_LOCK_CONFLICT | ERRDOS | 33 | ERRlock | Yes (line 118) |
| STATUS_WRONG_PASSWORD | ERRSRV | 86 | ERRbadpw | Yes (line 150) |
| STATUS_NOT_IMPLEMENTED | ERRDOS | 1 | ERRbadfunc | Yes (line 26) |

**Additional mappings needed but absent from table:**

| NTSTATUS | DOS Class | DOS Code | Notes |
|----------|-----------|----------|-------|
| STATUS_NO_MORE_FILES | ERRDOS | 18 | ERRnofiles — needed for SEARCH/FIND |
| STATUS_PRINT_QUEUE_FULL | ERRDOS | 61 | Needed for print commands |
| STATUS_NO_SPOOL_SPACE | ERRDOS | 62 | Needed for print commands |

### 6.5 Implementation Plan

**Step 1: Fix central error response path**

In `smb1pdu.c`, identify the function that sets `rsp->hdr.Status.CifsError`
from an NTSTATUS code (likely inline in each handler or in `smb1misc.c`).
Add a helper:

```c
/* In smb1pdu.c or smb1misc.c */
static void smb1_set_status(struct smb_hdr *rsp_hdr,
                             const struct smb_hdr *req_hdr,
                             __le32 ntstatus)
{
    if (req_hdr->Flags2 & SMBFLG2_ERR_STATUS) {
        /* Client wants NTSTATUS format — already the default */
        rsp_hdr->Status.CifsError = ntstatus;
        rsp_hdr->Flags2 |= SMBFLG2_ERR_STATUS;
    } else {
        /* Client wants DOS error format */
        __u8  eclass;
        __le16 ecode;
        ntstatus_to_dos(ntstatus, &eclass, &ecode);
        rsp_hdr->Status.DosError.ErrorClass = eclass;
        rsp_hdr->Status.DosError.Error      = ecode;
        rsp_hdr->Flags2 &= ~SMBFLG2_ERR_STATUS;
    }
}
```

**Step 2: Replace all direct `Status.CifsError =` assignments**

Audit all error-setting paths in `smb1pdu.c` and replace direct assignments with
`smb1_set_status(rsp_hdr, req_hdr, STATUS_*)` calls.

**Step 3: Preserve `SMBFLG2_ERR_STATUS` echo**

In the negotiate response, the server echoes back `SMBFLG2_ERR_STATUS` in `Flags2`
only if the server intends to use NTSTATUS. The server SHOULD set this bit only
if negotiating "NT LM 0.12" or higher. For older dialects, the server MUST use
DOS error format exclusively.

**Step 4: Add missing DOS error codes to ntstatus_to_dos_map[]**

```c
/* Add to ntstatus_to_dos_map[] in netmisc.c */
{ ERRDOS, 18, NT_STATUS_NO_MORE_FILES },       /* ERRnofiles */
{ ERRDOS, 61, NT_STATUS_PRINT_QUEUE_FULL },    /* ERRqueuefull */
{ ERRDOS, 62, NT_STATUS_NO_SPOOL_SPACE },      /* ERRnospool */
```

**Implementation Effort:** Medium (2–3 days — auditing and replacing error-setting calls)

**Priority:** Medium — primarily affects legacy clients (pre-NT); NT LM 0.12 clients
(Windows 9x+, Windows NT 3.51+) all set `SMBFLG2_ERR_STATUS`.

---

## 7. UNIX Extensions (CIFS POSIX Extensions)

KSMBD advertises UNIX extension support via the `CAP_UNIX` capability bit and
responds to TRANS2 info levels 0x200+. The capabilities word advertised in
`SMB_QUERY_CIFS_UNIX_INFO` (level 0x200 of TRANS2_QUERY_FS_INFORMATION) is
defined at line 1241 of `smb1pdu.h`:

```c
#define SMB_UNIX_CAPS  (CIFS_UNIX_FCNTL_CAP | CIFS_UNIX_POSIX_ACL_CAP | \
                        CIFS_UNIX_XATTR_CAP | CIFS_UNIX_POSIX_PATHNAMES_CAP | \
                        CIFS_UNIX_POSIX_PATH_OPS_CAP | CIFS_UNIX_LARGE_READ_CAP | \
                        CIFS_UNIX_LARGE_WRITE_CAP)
```

This advertises:
- `CIFS_UNIX_FCNTL_CAP` (0x01): POSIX byte-range locking
- `CIFS_UNIX_POSIX_ACL_CAP` (0x02): POSIX ACL get/set
- `CIFS_UNIX_XATTR_CAP` (0x04): extended attributes
- `CIFS_UNIX_POSIX_PATHNAMES_CAP` (0x10): POSIX path characters
- `CIFS_UNIX_POSIX_PATH_OPS_CAP` (0x20): POSIX open/unlink
- `CIFS_UNIX_LARGE_READ_CAP` (0x40): reads > 128K
- `CIFS_UNIX_LARGE_WRITE_CAP` (0x80): large writes

The problem: some of these advertised capabilities have incomplete or missing
server-side handlers, creating a compliance gap between the advertised and
actually-supported feature set.

---

### 7.1 Already Implemented (Verified in smb1pdu.c)

| Info Level | Code | Direction | Handler | Notes |
|------------|------|-----------|---------|-------|
| SMB_QUERY_FILE_UNIX_BASIC | 0x200 | QUERY_PATH / QUERY_FILE | `init_unix_info()` (line 3651) | uid, gid, nlinks, times, size, blocks, type, permissions — Complete |
| SMB_SET_FILE_UNIX_BASIC | 0x200 | SET_PATH / SET_FILE | `smb_set_unix_pathinfo()` | chmod/chown/utimes — Complete |
| SMB_QUERY_FILE_UNIX_LINK | 0x201 | QUERY_PATH | readlink path | symlink target read — Complete |
| SMB_SET_FILE_UNIX_LINK | 0x201 | SET_PATH | `smb_creat_symlink()` (line 5952) | create symlink — Complete |
| SMB_SET_FILE_UNIX_HLINK | 0x203 | SET_PATH | `smb_creat_hardlink()` (line 5950) | create hardlink — Complete |
| SMB_QUERY_POSIX_ACL | 0x204 | QUERY_PATH | `smb_get_acl()` (line 4760–4764) | POSIX ACL query — Complete |
| SMB_SET_POSIX_ACL | 0x204 | SET_PATH | `smb_set_acl()` (line 5966–5968) | POSIX ACL set — Complete |
| SMB_POSIX_OPEN | — | SET_PATH | `smb_posix_open()` (line 5943) | POSIX open with O_* flags — Complete |
| SMB_POSIX_UNLINK | 0x20A | SET_PATH | `smb_posix_unlink()` (line 5946) | unlink even if open — Complete |
| SMB_QUERY_CIFS_UNIX_INFO | 0x200 | QUERY_FS | capability word response (line 5061) | Major/minor version + caps — Complete |
| SMB_QUERY_POSIX_FS_INFO | 0x201 | QUERY_FS | `filesystem_posix_info` block (line 5065) | statvfs-like FS info — Complete |

---

### 7.2 Missing or Incomplete UNIX Extension Levels

#### 7.2.1 SMB_QUERY_POSIX_LOCK / SMB_SET_POSIX_LOCK (0x208)

**Spec ref:** Samba CIFS POSIX Extensions, `posix_lock_info` structure

**Status:** PARTIALLY MISSING

The info level 0x208 (`SMB_QUERY_POSIX_LOCK` / `SMB_SET_POSIX_LOCK`) allows a
client to query or set a POSIX byte-range lock on an open file. Unlike Windows
oplocks/byte-range locks (which use LOCKING_ANDX), POSIX locks:
- Include the locking PID
- Are non-blocking (return immediately with lock status)
- Map directly to Linux `fcntl(F_GETLK)` / `fcntl(F_SETLK)`

**Wire Format for POSIX Lock (`smb_lock_struct`):**
```c
struct smb_lock_struct {
    __le64  Offset;          /* start of locked range */
    __le64  Length;          /* length of locked range (0 = to EOF) */
    __le32  Pid;             /* PID of locking process */
    __le16  LockType;        /* READ_LOCK (0), WRITE_LOCK (1), UNLOCK (2) */
    __le16  ReturnCode;      /* 0 on success; error code on failure */
} __packed;
```

**Query (TRANS2_QUERY_FILE_INFORMATION with level 0x208):**
- Client sends a lock range
- Server returns the lock's current status (held/not held, holder PID)
- Maps to `fcntl(F_GETLK)` on the underlying file

**Set (TRANS2_SET_FILE_INFORMATION with level 0x208):**
- Client requests a lock or unlock with PID
- Server calls `fcntl(F_SETLK)` (non-blocking)
- Returns `STATUS_SUCCESS` or `STATUS_LOCK_NOT_GRANTED` immediately

**Current KSMBD State:**

Inspection of `smb1pdu.c` shows that neither `TRANS2_QUERY_FILE_INFORMATION` nor
`TRANS2_SET_FILE_INFORMATION` dispatchers include a `case 0x208:` branch. The
`default:` branch returns `STATUS_NOT_IMPLEMENTED`. KSMBD advertises
`CIFS_UNIX_FCNTL_CAP` but does not handle the TRANS2 info level for it.

The VFS infrastructure exists: `ksmbd_vfs_posix_lock_wait_timeout()`,
`ksmbd_vfs_posix_lock_unblock()`, and `ksmbd_vfs_posix_lock_set()` in `vfs.c`.

**Implementation Plan:**

1. Add `case SMB_QUERY_POSIX_LOCK:` in `TRANS2_QUERY_FILE_INFORMATION` handler:
   - Resolve FID, extract lock range from request parameters
   - Call `vfs_test_lock()` or `fcntl(F_GETLK)` via `ksmbd_vfs_posix_lock_set()`
   - Return `smb_lock_struct` with current lock status

2. Add `case SMB_SET_POSIX_LOCK:` in `TRANS2_SET_FILE_INFORMATION` handler:
   - Parse `smb_lock_struct` from request data
   - Call `ksmbd_vfs_posix_lock_set()` with non-blocking flag
   - Return `STATUS_SUCCESS` or `STATUS_LOCK_NOT_GRANTED`

**Implementation Effort:** Medium (2–3 days)

**Priority:** Medium — advertised via `CIFS_UNIX_FCNTL_CAP`; Linux CIFS clients
use this for interoperability.

---

#### 7.2.2 SMB_QUERY_POSIX_WHO_AM_I (0x202, TRANS2_QUERY_FS_INFORMATION)

**Spec ref:** Samba CIFS POSIX Extensions, `SMB_QUERY_POSIX_WHO_AM_I`

**Status:** NOT IMPLEMENTED

**Protocol Behavior:**

The info level 0x202 on `TRANS2_QUERY_FS_INFORMATION` asks the server: "Who does
the server think I am?" The server responds with the effective UID, GID, and
supplemental groups that will be used for this client's file access decisions.

**Response structure:**
```c
struct smb_whoami_rsp {
    __u32  flags;           /* 0 */
    __u32  flags_mask;      /* 0 */
    __u64  guest_smbuid;    /* server-assigned UID (not POSIX uid) */
    __u64  hostsid_size;    /* SID size (may be 0) */
    __u32  uid;             /* effective POSIX UID on the server */
    __u32  gid;             /* effective POSIX GID */
    __u32  num_groups;      /* number of supplemental groups */
    __u32  SID_list_size;   /* size of SID list (may be 0) */
    __u32  groups[num_groups];  /* supplemental GIDs */
    /* Optional SID data follows */
} __packed;
```

**Current KSMBD State:**

`smb1pdu.c` TRANS2_QUERY_FS_INFORMATION dispatcher has cases for `0x200`
(SMB_QUERY_CIFS_UNIX_INFO) and `0x201` (SMB_QUERY_POSIX_FS_INFO), but no `0x202`
case. Any `WHO_AM_I` request falls to `default:` returning `-EINVAL`.

**Implementation Plan:**

1. Add `case SMB_QUERY_POSIX_WHO_AM_I:` in `query_fs_info()` handler:
   ```c
   case SMB_QUERY_POSIX_WHO_AM_I:
   {
       struct smb_whoami_rsp *whoami;
       struct group_info *gi;
       int i;

       whoami = (struct smb_whoami_rsp *)(&rsp->Pad + 1);
       whoami->flags      = 0;
       whoami->flags_mask = 0;
       whoami->uid = cpu_to_le32(from_kuid(user_ns,
                                 work->sess->user->uid));
       whoami->gid = cpu_to_le32(from_kgid(user_ns,
                                 work->sess->user->gid));
       gi = get_current_groups();
       whoami->num_groups = cpu_to_le32(gi->ngroups);
       for (i = 0; i < gi->ngroups; i++)
           whoami->groups[i] = cpu_to_le32(
               from_kgid(user_ns, GROUP_AT(gi, i)));
       /* Set TotalDataCount accordingly */
       break;
   }
   ```

**Implementation Effort:** Low (1–2 days)

**Priority:** Medium — useful for POSIX-interop clients (Linux CIFS) to verify
their effective identity on the server.

---

#### 7.2.3 SMB_QUERY_XATTR / SMB_SET_XATTR (0x205)

**Spec ref:** Samba CIFS POSIX Extensions, xattr extension levels

**Status:** PARTIALLY MISSING

**Note on Level Numbering:** The `smb1pdu.h` file defines:
```c
#define SMB_QUERY_XATTR   0x205  /* e.g. system EA name space */
#define SMB_SET_XATTR     0x205
```

These are the POSIX extended attribute query/set levels, distinct from Windows EA
(Extended Attributes) which use `SMB_INFO_QUERY_ALL_EAS` (0x104) / `SMB_SET_FILE_EA`.

**Protocol Behavior:**

Allows clients to get/set POSIX xattrs (e.g., `user.checksum`, `security.selinux`)
in the full POSIX xattr namespace, not just the Windows EA namespace.

**Current KSMBD State:**

`smb_get_ea()` and `smb_set_ea()` handle Windows EA (via `user.` xattr namespace).
The POSIX xattr levels at 0x205 are not handled in TRANS2_QUERY_PATH_INFORMATION
or TRANS2_SET_PATH_INFORMATION dispatchers. The `default:` branch returns
`-EINVAL`.

KSMBD DOES have xattr infrastructure: `ksmbd_vfs_get_xattr()`, `ksmbd_vfs_setxattr()`
in `vfs.c`.

**Implementation Plan:**

1. Add `case SMB_QUERY_XATTR:` to TRANS2_QUERY_PATH_INFORMATION handler:
   - Parse EA name from request
   - Call `ksmbd_vfs_get_xattr()` with full xattr name
   - Return value in response data

2. Add `case SMB_SET_XATTR:` to TRANS2_SET_PATH_INFORMATION handler:
   - Parse xattr name and value from request
   - Call `ksmbd_vfs_setxattr()` with full namespace prefix preserved

3. When the client passes a name without a namespace prefix, prepend `user.`
   (Samba behavior for Linux CIFS compatibility)

**Implementation Effort:** Low (1–2 days)

**Priority:** Medium — `CIFS_UNIX_XATTR_CAP` (0x04) is advertised; Linux CIFS
clients may use this for POSIX xattr access.

---

#### 7.2.4 SMB_QUERY_ATTR_FLAGS / SMB_SET_ATTR_FLAGS (0x206)

**Spec ref:** Samba CIFS POSIX Extensions, `chattr`/`chflags` extension

**Status:** NOT IMPLEMENTED

**Protocol Behavior:**

Allows setting Linux-style immutable/append-only/nodump file flags (the `chattr`
flags: `FS_IMMUTABLE_FL`, `FS_APPEND_FL`, `FS_NODUMP_FL`, etc.).

**Response/Request Data:**
```c
struct file_chattr_info {
    __le64  mask;    /* flags to change */
    __le64  mode;    /* new flag values (anded with mask) */
} __packed;
```

**Current KSMBD State:** Not handled; falls to default branch returning `-EINVAL`.

`CIFS_UNIX_EXTATTR_CAP` (0x08) is NOT advertised in `SMB_UNIX_CAPS`, so this is
consistent — KSMBD does not claim to support `chattr` flags. However, if a client
negotiates with a server advertising POSIX extensions broadly, it may try 0x206.

**Implementation Plan:**

1. Optionally add `case SMB_QUERY_ATTR_FLAGS:` returning the current ioctl flags
   via `FS_IOC_GETFLAGS`
2. Add `case SMB_SET_ATTR_FLAGS:` applying the requested flags via `FS_IOC_SETFLAGS`
3. If not implementing, remove claim of `CIFS_UNIX_EXTATTR_CAP` from `SMB_UNIX_CAPS`
   (it is NOT currently in the mask, which is correct)

**Implementation Effort:** Low (1–2 days)

**Priority:** Low — `CIFS_UNIX_EXTATTR_CAP` is not advertised; only implement if
`chattr` flag semantics are desired.

---

### 7.3 CAP_UNIX Capabilities Word Compliance

The `SMB_UNIX_CAPS` mask in `smb1pdu.h` line 1241 advertises:
- `CIFS_UNIX_FCNTL_CAP` (0x01) — POSIX locks: PARTIAL (TRANS2 level missing)
- `CIFS_UNIX_POSIX_ACL_CAP` (0x02) — POSIX ACL: COMPLETE
- `CIFS_UNIX_XATTR_CAP` (0x04) — xattr: PARTIAL (TRANS2 level missing)
- `CIFS_UNIX_POSIX_PATHNAMES_CAP` (0x10) — POSIX paths: COMPLETE
- `CIFS_UNIX_POSIX_PATH_OPS_CAP` (0x20) — POSIX open/unlink: COMPLETE
- `CIFS_UNIX_LARGE_READ_CAP` (0x40) — large reads: COMPLETE
- `CIFS_UNIX_LARGE_WRITE_CAP` (0x80) — large writes: COMPLETE

**NOT advertised (correct decisions):**
- `CIFS_UNIX_EXTATTR_CAP` (0x08) — `chattr` flags: not implemented, correctly absent
- `CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP` (0x100) — SPNEGO encryption: not SMB1
- `CIFS_UNIX_PROXY_CAP` (0x400) — proxy: not implemented

**Action Required:** Remove `CIFS_UNIX_FCNTL_CAP` from `SMB_UNIX_CAPS` if
SMB_SET_POSIX_LOCK (0x208) and SMB_QUERY_POSIX_LOCK (0x208) remain unimplemented,
OR implement those TRANS2 info levels to match the advertised capability.

Similarly, if `SMB_QUERY_XATTR` / `SMB_SET_XATTR` (0x205) handlers are absent,
remove `CIFS_UNIX_XATTR_CAP` from the advertised mask until the handlers are added.

---

## 8. SMB Signing Correctness

### 8.1 Current Implementation Status

KSMBD implements SMB1 signing via three functions in `smb1pdu.c`:
- `smb1_is_sign_req()` (line 8952) — determines if this request should be verified
- `smb1_check_sign_req()` (line 8979) — verifies the incoming signature
- `smb1_set_sign_rsp()` (line 9011) — sets the signature on the outgoing response

The underlying signing algorithm in `auth.c` (line 943, `ksmbd_sign_smb1_pdu()`):
```c
MD5(sess->sess_key[0..39] || full_smb_message_with_zeroed_SecuritySignature)
```

This uses MD5 directly (not HMAC-MD5) with the session key prepended as a data
prefix — matching the algorithm documented in MS-SMB §3.1.4.1.

### 8.2 Spec Compliance Analysis

**MS-SMB §3.1.4.1 — SMB Signing Algorithm:**

Per the specification, the SMB1 signing computation is:
```
MAC = MD5(SessionKey || ConcatenationOf(Message_with_SecurityFeatures_zeroed))
```

Where:
- `SessionKey` is the 40-byte session key (NT session key + 24 bytes padding or UserSessionKey)
- `SecurityFeatures[8]` in the SMB header is zeroed before computing the MAC
- The first 8 bytes of the MD5 output become the `SecuritySignature` (truncated to 8 bytes)
- The sequence number occupies bytes 0–3 of `SecurityFeatures`, with bytes 4–7 = 0

**KSMBD Implementation vs. Spec:**

| Spec Requirement | KSMBD Implementation | Compliant? |
|-----------------|---------------------|------------|
| MD5 over full message | `crypto_shash_update()` over all iovecs | Yes |
| Session key prepended (40 bytes) | `crypto_shash_update(sess->sess_key, 40)` | Yes |
| SecurityFeatures zeroed before MAC | `rcv_hdr1->Signature.Sequence.SequenceNumber = cpu_to_le32(++)` then MAC | Partially — but zeroes the Sequence field with the new seq number, not all-zeros |
| Sequence number incremented per PDU | `++work->sess->sequence_number` | Yes |
| Sequence starts at 2 | `sess->sequence_number = 1` (line 355 in auth.c), incremented to 2 on first use | Yes |
| First 8 bytes of MD5 as signature | `memcpy(rsp_hdr->Signature.SecuritySignature, signature, CIFS_SMB1_SIGNATURE_SIZE)` | Yes |

**Gap Identified:**

In `smb1_check_sign_req()` (line 8988), the code sets:
```c
rcv_hdr1->Signature.Sequence.SequenceNumber = cpu_to_le32(++work->sess->sequence_number);
rcv_hdr1->Signature.Sequence.Reserved = 0;
```

Per MS-SMB §3.3.4.1.1, when computing the MAC for verification, the
`SecurityFeatures` field of the received message MUST be replaced with the
sequence number (bytes 0–3) and zeros (bytes 4–7). KSMBD does this by writing
the seq number into `Sequence.SequenceNumber` and setting `Reserved = 0`.
This is correct: the SecuritySignature field in the received header is overwritten
with the 4-byte sequence number and 4 zero bytes before MAC computation.

However, the original 8-byte client signature was saved via `memcpy(signature_req, ...)`.
The comparison is: `memcmp(computed_mac, saved_client_signature, 8)`.

This logic appears correct. **No critical bug identified in the signing algorithm.**

### 8.3 Signing Enforcement Gaps

**Gap 1: Signing not enforced after mandatory signing negotiation**

When the server advertises `SECMODE_SIGN_REQUIRED` (i.e., `server_conf.signing ==
KSMBD_CONFIG_OPT_MANDATORY`) and the client negotiates signing, the server MUST
reject any unsigned request with `STATUS_ACCESS_DENIED` after session setup.

`smb1_is_sign_req()` returns `true` only if the client sets `SMBFLG2_SECURITY_SIGNATURE`
in the request header. But if `SECMODE_SIGN_REQUIRED` is set and the client fails
to sign a request, `smb1_is_sign_req()` returns `false` (since the bit is not
set in the request), and no signing check is performed — the unsigned request
is processed silently.

**Fix:** When `SECMODE_SIGN_REQUIRED` is negotiated, `smb1_is_sign_req()` should
return `true` for all commands post-session-setup, regardless of the client's
`SMBFLG2_SECURITY_SIGNATURE` flag. The caller (in `ksmbd_conn.c` or the work
handler) should then enforce signing and reject unsigned requests.

**Gap 2: Per-session sequence number race condition**

`work->sess->sequence_number` is read and incremented without atomic protection:
```c
rcv_hdr1->Signature.Sequence.SequenceNumber =
    cpu_to_le32(++work->sess->sequence_number);
```

For SMB1 with multiple multiplexed requests (MaxMpxCount > 1), multiple work
items can access the session's sequence number concurrently. The sequence number
MUST be serialized (MS-SMB §3.3.4.1.1 specifies that "the client sends requests
with monotonically increasing sequence numbers").

**Fix:** Protect `sequence_number` increments with `atomic_t` or the session lock.

**Gap 3: Signing verification failure does not disconnect**

When `smb1_check_sign_req()` returns 0 (signature mismatch), the calling code in
`smb1ops.c`/`connection.c` must disconnect the session. Verify that the caller
handles `check_sign_req` returning 0 by:
1. Sending `STATUS_ACCESS_DENIED` in response, OR
2. Closing the connection

**Implementation Plan:**

1. Modify `smb1_is_sign_req()`: if signing was negotiated as mandatory (store a
   flag on `ksmbd_conn` or session), return `true` for all post-session commands

2. Replace `++work->sess->sequence_number` with an atomic increment:
   ```c
   atomic_inc_return(&work->sess->sequence_number)
   ```
   (requires changing `sequence_number` from `unsigned int` to `atomic_t` in
   `struct ksmbd_session`, or protecting with `spin_lock`)

3. Verify the signing-failure code path disconnects correctly (audit callers
   of `check_sign_req` in the request dispatch loop)

**Implementation Effort:** Low-Medium (1–2 days)

**Priority:** Medium — critical for servers configured with mandatory signing.

---

## 9. DFS Integration

### 9.1 TRANS2_GET_DFS_REFERRAL (0x10)

**Spec ref:** MS-SMB §1.4 (DFS), MS-CIFS §2.2.6.16, MS-DFSC (DFS Referral Protocol)

**Status:** MISSING — falls through to `default:` in the TRANS2 dispatcher,
returning `-EINVAL` → `STATUS_NOT_SUPPORTED`.

**Current KSMBD State:**

The DFS infrastructure exists in:
- `/home/ezechiel203/ksmbd/src/fs/ksmbd_dfs.c` — DFS referral data structures
- `/home/ezechiel203/ksmbd/src/include/fs/ksmbd_branchcache.h` — branch cache
- `/home/ezechiel203/ksmbd/ksmbd-tools/` — userspace DFS configuration

`CAP_DFS` is NOT advertised in `SMB1_SERVER_CAPS` (correct — without a working
handler, advertising it would be wrong).

**Protocol Requirements:**

**Request (TRANS2 Parameters):**
```c
struct dfs_referral_req {
    __le16  MaxReferralLevel;    /* 1, 2, 3, or 4 */
    /* RequestFileName (UTF-16LE) follows in data area */
} __packed;
```

**MaxReferralLevel meanings:**
- 1: Very old format (Windows 3.x era) — rarely needed
- 2: Current domain-relative referrals
- 3: Standard referral format (most clients use this)
- 4: Extended referrals with extended flags

**Response (DFSC REQ_GET_DFS_REFERRAL_EX format for v3):**
```c
struct dfs_referral_rsp {
    __le16  PathConsumed;        /* bytes of RequestFileName consumed */
    __le16  NumberOfReferrals;   /* number of referral entries */
    __le32  ReferralHeaderFlags; /* REFERRAL_SERVER=0x1, STORAGE_SERVER=0x2 */
    /* DFS_REFERRAL_V3 entries follow */
} __packed;

struct dfs_referral_v3 {
    __le16  VersionNumber;       /* 3 */
    __le16  Size;                /* size of this entry */
    __le16  ServerType;          /* 0=LINK, 1=ROOT */
    __le16  ReferralEntryFlags;
    __le32  TimeToLive;          /* seconds; typically 300 */
    __le16  DFSPathOffset;       /* offset from start of entry to DFSPath string */
    __le16  DFSAlternatePathOffset;
    __le16  NetworkAddressOffset; /* offset to the server name/address */
    __u8    ServiceSiteGuid[16]; /* GUID, may be zeros */
} __packed;
```

**Implementation Plan:**

1. Add `case TRANS2_GET_DFS_REFERRAL:` to `smb_trans2()` dispatcher in `smb1pdu.c`

2. Implement `get_dfs_referral()`:
   - Extract `RequestFileName` (UTF-16LE path) from the TRANS2 data area
   - Decode to a local path using `smb_strndup_from_utf16()`
   - Query `ksmbd_dfs.c` for matching DFS namespace entry
   - If found: build `dfs_referral_rsp` + v3 entry with server address
   - If not found: return `STATUS_PATH_NOT_COVERED` (maps to `ERRDOS/ERRbadpath`)

3. Once working, advertise `CAP_DFS` in `SMB1_SERVER_CAPS`:
   ```c
   #define SMB1_SERVER_CAPS  (... | CAP_DFS)
   ```

4. Handle the case where `ksmbd.mountd` provides DFS referral data via netlink
   (check if `transport_ipc.c` has a DFS referral IPC channel; if not, add one)

**Implementation Effort:** High (5–7 days — DFS referral format is complex;
requires coordination with userspace DFS configuration)

**Priority:** High — DFS is commonly used in enterprise environments. Without it,
clients in a DFS namespace cannot traverse referrals to reach shares.

---

### 9.2 TRANS2_REPORT_DFS_INCONSISTENCY (0x11)

**Spec ref:** MS-CIFS §2.2.6.17

**Status:** MISSING — falls to `default:` branch.

**Protocol Behavior:**

A client sends this when it detects an inconsistency in DFS referral information
(e.g., server listed in referral is unreachable). The server may silently ignore
this notification. The only compliant requirement is that the server MUST respond
with a valid SMB response (not silently drop or return a transport error).

**Implementation Plan:**

Add a minimal handler:
```c
case TRANS2_REPORT_DFS_INCONSISTENCY:
    /* Spec: server may log and ignore; MUST respond with success */
    ksmbd_debug(SMB, "DFS inconsistency reported by client\n");
    create_trans2_reply(work, 0);
    return 0;
```

**Implementation Effort:** Very Low (30 minutes)

**Priority:** Low — no functional change; purely a compliance correctness fix.

---

## 10. Implementation Priority Summary

The following table consolidates all gaps identified in this document and the
companion audit documents, ordered by compliance impact.

### Priority 1 — Critical (Windows interoperability breaks without these)

| # | Feature | Source File | Effort | Spec Reference |
|---|---------|-------------|--------|----------------|
| 1 | SMB_COM_NT_TRANSACT dispatcher (0xA0) | `smb1ops.c`, `smb1pdu.c` | HIGH | MS-SMB §2.2.4.8 |
| 2 | NT_TRANSACT_NOTIFY_CHANGE (0x04) | `smb1pdu.c` | HIGH | MS-CIFS §2.2.7.4 |
| 3 | NT_TRANSACT_QUERY_SECURITY_DESC (0x06) | `smb1pdu.c` | HIGH | MS-SMB §2.2.7.4 |
| 4 | NT_TRANSACT_SET_SECURITY_DESC (0x03) | `smb1pdu.c` | HIGH | MS-SMB §2.2.7.3 |
| 5 | NT_TRANSACT_IOCTL (0x02) — FSCTL passthrough | `smb1pdu.c` | HIGH | MS-SMB §2.2.7.2 |
| 6 | Multi-packet TRANSACTION_SECONDARY (0x26) | `smb1pdu.c`, `smb1ops.c` | HIGH | MS-CIFS §2.2.4.33 |
| 7 | Multi-packet TRANSACTION2_SECONDARY (0x33) | `smb1pdu.c`, `smb1ops.c` | HIGH | MS-CIFS §2.2.4.47 |
| 8 | Multi-packet NT_TRANSACT_SECONDARY (0xA1) | `smb1pdu.c`, `smb1ops.c` | HIGH | MS-CIFS §2.2.4.63 |

### Priority 2 — High (Common operations used by all Windows clients)

| # | Feature | Source File | Effort | Spec Reference |
|---|---------|-------------|--------|----------------|
| 9 | TRANS2_GET_DFS_REFERRAL (0x10) | `smb1pdu.c`, `ksmbd_dfs.c` | HIGH | MS-DFSC |
| 10 | NT_TRANSACT_CREATE (0x01) | `smb1pdu.c` | MEDIUM | MS-SMB §2.2.7.1 |
| 11 | SMB_COM_NT_RENAME — RENAME_FILE case (0xA5) | `smb1pdu.c` | LOW | MS-CIFS §2.2.4.73 |
| 12 | NT_CANCEL actually cancel sleeping locks (0xA4) | `smb1pdu.c` | MEDIUM | MS-CIFS §2.2.4.69 |
| 13 | LOCKING_ANDX CANCEL_LOCK functional (0x24) | `smb1pdu.c` | MEDIUM | MS-SMB §3.3.5.14 |
| 14 | NT_TRANSACT_RENAME (0x05) | `smb1pdu.c` | MEDIUM | MS-CIFS §2.2.7.5 |

### Priority 3 — Medium (Interoperability improvement; older client support)

| # | Feature | Source File | Effort | Spec Reference |
|---|---------|-------------|--------|----------------|
| 15 | SMB_COM_QUERY_INFORMATION2 (0x23) | `smb1pdu.c`, `smb1ops.c` | LOW | MS-CIFS §2.2.4.32 |
| 16 | SMB_COM_SET_INFORMATION2 (0x22) | `smb1pdu.c`, `smb1ops.c` | LOW | MS-CIFS §2.2.4.18 |
| 17 | Error code model: DOS error support (FLAGS2_ERR_STATUS) | `smb1pdu.c`, `netmisc.c` | MEDIUM | MS-SMB §3.1.4.2 |
| 18 | SMB_COM_COPY (0x29) — server-side copy | `smb1pdu.c`, `smb1ops.c` | HIGH | MS-CIFS §2.2.4.34 |
| 19 | POSIX lock TRANS2 levels 0x208 (fcntl-based) | `smb1pdu.c` | MEDIUM | CIFS POSIX Ext |
| 20 | POSIX xattr TRANS2 level 0x205 | `smb1pdu.c` | LOW | CIFS POSIX Ext |
| 21 | SMB_QUERY_POSIX_WHO_AM_I (0x202 / QUERY_FS) | `smb1pdu.c` | LOW | CIFS POSIX Ext |
| 22 | SMB1 signing mandatory enforcement fix | `smb1pdu.c` | LOW | MS-SMB §3.3.4.1 |
| 23 | SMB1 signing sequence_number atomic safety | `auth.c`, `smb1pdu.c` | LOW | MS-SMB §3.3.4.1.1 |
| 24 | SMB_COM_MOVE (0x2A) — server-side move | `smb1pdu.c`, `smb1ops.c` | HIGH | MS-CIFS §2.2.4.35 |
| 25 | Remove `CIFS_UNIX_FCNTL_CAP` if POSIX locks unimplemented | `smb1pdu.h` | LOW | CIFS POSIX Ext |
| 26 | TRANS2_REPORT_DFS_INCONSISTENCY (0x11) stub | `smb1pdu.c` | VERY LOW | MS-CIFS §2.2.6.17 |

### Priority 4 — Low (Legacy compatibility; rarely-used or pre-NT features)

| # | Feature | Source File | Effort | Spec Reference |
|---|---------|-------------|--------|----------------|
| 27 | SMB_COM_SEARCH (0x81) — legacy FCB search | `smb1pdu.c`, `smb1ops.c` | MEDIUM | MS-CIFS §2.2.4.58 |
| 28 | SMB_COM_FIND (0x82) — stateful legacy search | `smb1pdu.c`, `smb1ops.c` | MEDIUM | MS-CIFS §2.2.4.59 |
| 29 | SMB_COM_FIND_UNIQUE (0x83) | `smb1pdu.c`, `smb1ops.c` | VERY LOW | MS-CIFS §2.2.4.60 |
| 30 | SMB_COM_FIND_CLOSE (0x84) | `smb1pdu.c`, `smb1ops.c` | VERY LOW | MS-CIFS §2.2.4.61 |
| 31 | SMB_COM_WRITE_AND_CLOSE (0x2C) | `smb1pdu.c`, `smb1ops.c` | LOW | MS-CIFS §2.2.4.41 |
| 32 | SMB_COM_OPEN (0x02) — legacy open | `smb1pdu.c`, `smb1ops.c` | MEDIUM | MS-CIFS §2.2.4.3 |
| 33 | SMB_COM_CREATE (0x03) — legacy create | `smb1pdu.c`, `smb1ops.c` | LOW | MS-CIFS §2.2.4.4 |
| 34 | SMB_COM_CREATE_NEW (0x0F) — create-if-not-exists | `smb1pdu.c`, `smb1ops.c` | VERY LOW | MS-CIFS §2.2.4.15 |
| 35 | SMB_COM_CREATE_TEMPORARY (0x0E) — temp file | `smb1pdu.c`, `smb1ops.c` | LOW | MS-CIFS §2.2.4.14 |
| 36 | SMB_COM_SEEK (0x12) — per-FID file position | `smb1pdu.c`, `vfs_cache.h` | MEDIUM | MS-CIFS §2.2.4.20 |
| 37 | SMB_COM_OPEN_PRINT_FILE (0x43) | `smb1pdu.c`, `smb1ops.c` | LOW | MS-CIFS §2.2.4.49 |
| 38 | SMB_COM_WRITE_PRINT_FILE (0x44) | `smb1pdu.c`, `smb1ops.c` | VERY LOW | MS-CIFS §2.2.4.50 |
| 39 | SMB_COM_CLOSE_PRINT_FILE (0x45) | `smb1pdu.c`, `smb1ops.c` | LOW | MS-CIFS §2.2.4.51 |
| 40 | SMB_COM_GET_PRINT_QUEUE (0x3D) — empty stub | `smb1pdu.c`, `smb1ops.c` | VERY LOW | MS-CIFS §2.2.4.42 |
| 41 | NT_TRANSACT_GET_USER_QUOTA (0x07) | `smb1pdu.c` | LOW | MS-SMB §2.2.7 |
| 42 | NT_TRANSACT_SET_USER_QUOTA (0x08) | `smb1pdu.c` | LOW | MS-SMB §2.2.7 |
| 43 | SMB_QUERY_ATTR_FLAGS / SMB_SET_ATTR_FLAGS (0x206) | `smb1pdu.c` | LOW | CIFS POSIX Ext |

### Items to SKIP (Security Risk or Explicitly Deprecated)

| Command | Opcode | Reason |
|---------|--------|--------|
| SMB_COM_READ_RAW | 0x1C | Deprecated; major security risk (unauthenticated data transfer) |
| SMB_COM_WRITE_RAW | 0x1D | Deprecated; security risk; respond with empty/error frame only |
| SMB_COM_LOCK_AND_READ | 0x13 | Remove `CAP_LOCK_AND_READ` from `SMB1_SERVER_CAPS` rather than implement |
| SMB_COM_SEND_MESSAGE et al. | 0x3A–0x3D | WinPopup messages; obsolete, security risk |

---

## Appendix A: Effort and Compliance Impact Summary

```
CURRENT ESTIMATED COMPLIANCE: ~55% of MS-SMB protocol

After implementing Priority 1 items: ~75%
After implementing Priority 1+2 items: ~82%
After implementing Priority 1+2+3 items: ~88%
After implementing all items: ~94%

Remaining ~6% gap:
  - Raw mode stubs (send empty frame only)
  - Print submission backend (OS-dependent)
  - DFS complex referral topologies
  - Snapshot enumeration via FSCTL
```

---

## Appendix B: Key File Locations

| Component | Primary File |
|-----------|-------------|
| SMB1 dispatch table | `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1ops.c` |
| SMB1 protocol handlers | `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c` |
| SMB1 PDU structures | `/home/ezechiel203/ksmbd/src/include/protocol/smb1pdu.h` |
| SMB1 validation | `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1misc.c` |
| Error code mapping | `/home/ezechiel203/ksmbd/src/protocol/common/netmisc.c` |
| POSIX ACL handling | `/home/ezechiel203/ksmbd/src/fs/smbacl.c` |
| VFS operations | `/home/ezechiel203/ksmbd/src/fs/vfs.c` |
| DFS referrals | `/home/ezechiel203/ksmbd/src/fs/ksmbd_dfs.c` |
| SMB1 signing (verify/generate) | `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c` (lines 8952–9040) |
| Signing algorithm | `/home/ezechiel203/ksmbd/src/core/auth.c` (line 943) |
| Session management | `/home/ezechiel203/ksmbd/src/mgmt/user_session.c` |
