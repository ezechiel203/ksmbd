# SMB2 Plan 05: QueryDirectory / ChangeNotify

Audit date: 2026-03-01
Reference specifications: MS-SMB2 §2.2.33–2.2.36, §3.3.5.17–3.3.5.18; MS-FSCC §2.4.13–2.4.18

---

## Current state summary

### SMB2 QUERY_DIRECTORY

The handler lives in `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_dir.c`.  The
implementation uses the Linux `iterate_dir()` / `dir_context` callback mechanism.
It is a two-pass design: the first pass (`__query_dir`, `reserve_populate_dentry`)
pre-allocates slots in the output buffer and filters names against the search
pattern; the second pass (`process_query_dir_entries`, `smb2_populate_readdir_entry`)
performs a dentry lookup for each matched name and fills the wire structure with
stat data.

**Info-level coverage** — the following levels are accepted by `verify_info_level()`
(line 1011) and fully encoded:

| Class value | Name | Status |
|-------------|------|--------|
| 0x01 | FileDirectoryInformation | Implemented |
| 0x02 | FileFullDirectoryInformation | Implemented |
| 0x03 | FileBothDirectoryInformation | Implemented |
| 0x0C | FileNamesInformation | Implemented |
| 0x25 | FileIdBothDirectoryInformation | Implemented |
| 0x26 | FileIdFullDirectoryInformation | Implemented |
| 0x3C | FileIdExtdDirectoryInformation | Implemented (SMB 3.1.1) |
| 0x3E | FileIdExtdBothDirectoryInformation | Implemented (SMB 3.1.1) |
| 0x34 | FileIdGlobalTxDirectoryInformation | Accepted, encoded as FileIdBothDir |
| 0x64 | FileId64ExtdDirectoryInformation | Implemented (non-standard extension) |
| 0x66 | FileId64ExtdBothDirectoryInformation | Implemented (non-standard extension) |
| 0x68 | FileIdAllExtdDirectoryInformation | Implemented (non-standard extension) |
| 0x6A | FileIdAllExtdBothDirectoryInformation | Implemented (non-standard extension) |
| SMB_FIND_FILE_POSIX_INFO | POSIX extension | Implemented |

All mandatory MS-SMB2 info classes (0x01, 0x02, 0x03, 0x0C, 0x25, 0x26, 0x3C, 0x3E)
are present.

**Flags coverage:**

| Flag | Macro | Handled |
|------|-------|---------|
| 0x01 | SMB2_RESTART_SCANS | Yes — llseek to 0 (line 1140–1144) |
| 0x02 | SMB2_RETURN_SINGLE_ENTRY | Yes — sets `d_info.out_buf_len = 0` after first match (line 996–1003) |
| 0x04 | SMB2_INDEX_SPECIFIED | No — field parsed but completely ignored |
| 0x10 | SMB2_REOPEN | Partially — treated identically to SMB2_RESTART_SCANS (line 1140) |

### SMB2 CHANGE_NOTIFY

The handler lives in
`/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_notify.c` and
`/home/ezechiel203/ksmbd/src/fs/ksmbd_notify.c`.  The implementation uses the
Linux `fsnotify` backend.  One `fsnotify_mark` is allocated per inode on first
CHANGE_NOTIFY; subsequent NOTIFY requests on the same inode "piggyback" on the
existing mark.  The watch persists for the lifetime of the file handle so that
events occurring between a NOTIFY completion and the next NOTIFY request are
buffered (up to 256 changes, with STATUS_NOTIFY_ENUM_DIR on overflow).

**Completion filter mapping** (kernel fsnotify -> SMB2 filter, `ksmbd_notify.c` lines 73–99):

| SMB2 filter | Mapped FS event | Correct? |
|-------------|-----------------|----------|
| FILE_NOTIFY_CHANGE_FILE_NAME | FS_CREATE / FS_DELETE / FS_MOVED_FROM / FS_MOVED_TO | Yes |
| FILE_NOTIFY_CHANGE_DIR_NAME  | Same events + FS_ISDIR check | Yes (partial — see P3) |
| FILE_NOTIFY_CHANGE_ATTRIBUTES | FS_ATTRIB | Yes |
| FILE_NOTIFY_CHANGE_SIZE | FS_MODIFY | Approximate only |
| FILE_NOTIFY_CHANGE_LAST_WRITE | FS_MODIFY | Yes |
| FILE_NOTIFY_CHANGE_LAST_ACCESS | FS_ACCESS | Yes |
| FILE_NOTIFY_CHANGE_CREATION | FS_CREATE | Conflated with file-name events |
| FILE_NOTIFY_CHANGE_EA | FS_ATTRIB | Approximate |
| FILE_NOTIFY_CHANGE_SECURITY | FS_ATTRIB | Approximate |
| FILE_NOTIFY_CHANGE_STREAM_NAME/SIZE/WRITE | FS_MODIFY | Approximate (streams not native) |

**Action values** generated (`ksmbd_notify.c` lines 101–112):

| MS-SMB2 action | Generated |
|----------------|-----------|
| FILE_ACTION_ADDED (1) | Yes |
| FILE_ACTION_REMOVED (2) | Yes |
| FILE_ACTION_MODIFIED (3) | Yes (default/fallback) |
| FILE_ACTION_RENAMED_OLD_NAME (4) | Yes |
| FILE_ACTION_RENAMED_NEW_NAME (5) | Yes |
| FILE_ACTION_ADDED_STREAM (6) | No — never generated |
| FILE_ACTION_REMOVED_STREAM (7) | No — never generated |
| FILE_ACTION_MODIFIED_STREAM (8) | No — never generated |
| FILE_ACTION_REMOVED_BY_DELETE (9) | No — replaced by STATUS_DELETE_PENDING |

---

## Confirmed Bugs (P1)

### P1-01: SMB2_INDEX_SPECIFIED completely ignored

**Location:** `smb2_dir.c` lines 1122–1144

**Problem:** The `SMB2_INDEX_SPECIFIED` flag (0x04) is defined in `smb2pdu.h`
line 1293 and is parsed into `srch_flag` at line 1122, but there is no code path
that examines it.  MS-SMB2 §3.3.5.17 states that when this flag is set, the
server MUST seek to the directory entry at the `FileIndex` position indicated in
`req->FileIndex` before beginning enumeration.  The `req->FileIndex` field is
declared in the wire struct (`smb2pdu.h` line 1301) but is never read.

**Impact:** Clients using `SMB2_INDEX_SPECIFIED` to resume a scan from an
arbitrary offset will silently get incorrect results — enumeration always starts
from the current cursor position, not the requested FileIndex.

**Fix required:** Read `req->FileIndex` when the flag is set and use
`vfs_llseek()` / `dir->f_pos` to position the directory stream before calling
`iterate_dir()`.

---

### P1-02: FileIndex field always zero in directory entries

**Location:** `vfs.c` line 3634: `info->FileIndex = 0;`

**Problem:** `ksmbd_vfs_init_kstat()` hard-codes `FileIndex = 0` in every
directory entry for all info classes that contain this field
(`file_directory_info`, `file_full_directory_info`, `file_both_directory_info`,
`file_id_full_dir_info`, `file_id_both_directory_info`, all the EXTD variants).
MS-SMB2 §2.2.34 / MS-FSCC §2.4 specify that `FileIndex` MUST contain the
file-system-specific position index of the file within the parent directory.
Setting it to zero breaks clients that use it as a resume key and also violates
the interoperability requirements of some applications.

**Impact:** Clients that use `FileIndex` for seek-resume will silently mis-behave
(correlates with P1-01).

**Fix required:** Populate `FileIndex` with the `d_off` / `loff_t offset` value
provided by the `dir_context` callback (currently passed as the `offset`
parameter to `__query_dir` at line 955 but discarded at line 967 after skipping
dot/dotdot).

---

### P1-03: SMB2_REOPEN does not reopen the directory handle

**Location:** `smb2_dir.c` lines 1140–1144

**Problem:** MS-SMB2 §3.3.5.17 specifies that when `SMB2_REOPEN` (0x10) is set,
the server MUST close the existing open and reopen the directory, resetting the
search pattern and scanning from the beginning.  The implementation treats
`SMB2_REOPEN` identically to `SMB2_RESTART_SCANS`: it simply seeks to position 0
and resets the dot/dotdot counters.  The distinction matters because `SMB2_REOPEN`
also allows the client to change the `FileInformationClass` and search pattern on
an existing volatile FID.

**Impact:** Clients relying on `SMB2_REOPEN` to change the information class or
pattern may observe stale results or incorrect info-class encoding.

---

### P1-04: STATUS_NO_SUCH_FILE condition is mis-gated

**Location:** `smb2_dir.c` lines 1224–1230

**Problem:** The code emits `STATUS_NO_SUCH_FILE` only when
`SMB2_RETURN_SINGLE_ENTRY` is set AND the search pattern is not `"*"`.
MS-SMB2 §3.3.5.17 specifies that `STATUS_NO_SUCH_FILE` MUST be returned when
the search pattern does not match any file on the *first* call for a given
directory position (irrespective of the `SMB2_RETURN_SINGLE_ENTRY` flag).
Subsequent calls after the directory is exhausted should return
`STATUS_NO_MORE_FILES`.  The current logic returns `STATUS_NO_MORE_FILES` for
non-`SMB2_RETURN_SINGLE_ENTRY` cases even on the first empty result, which is
wrong when the pattern never matched anything.

**Impact:** Clients that test `STATUS_NO_SUCH_FILE` to detect an absent file
(e.g., some macOS SMB clients) will get the wrong error code, potentially
causing incorrect "not found" vs "enumeration complete" disambiguation.

---

### P1-05: Single buffered change delivered on STATUS_NOTIFY_ENUM_DIR overflow, but buffered list not fully delivered

**Location:** `ksmbd_notify.c` lines 687–725

**Problem:** When buffered changes accumulate and their total byte size exceeds
`output_buf_len`, the code discards all buffered changes and returns
`STATUS_NOTIFY_ENUM_DIR` with an empty payload.  This is correct per MS-SMB2
§3.3.4.4.  However, the implementation only delivers a *single* buffered change
per synchronous flush (line 728: `ksmbd_notify_flush_one()`).  When multiple
changes are buffered and fit within the output buffer, MS-SMB2 requires the
server to coalesce them into a single response with multiple
`FILE_NOTIFY_INFORMATION` entries (linked via `NextEntryOffset`).  The current
implementation returns only the first buffered entry and leaves the rest
unreported until the next NOTIFY request.

**Impact:** On a busy directory, clients may issue many more NOTIFY round-trips
than necessary, increasing latency and breaking applications that expect to see
all queued changes in one response.

---

## Missing Features (P2)

### P2-01: SMB2_WATCH_TREE (recursive subtree monitoring) not implemented

**Location:** `ksmbd_notify.c` lines 640, 674, 829

**Problem:** The `watch_tree` boolean is stored in `ksmbd_notify_watch` and
propagated correctly from the CHANGE_NOTIFY request, but it is never used to
configure the `fsnotify` mark.  The `fsnotify_add_inode_mark()` call at line 868
always installs an inode mark with `FS_EVENT_ON_CHILD` only, which covers direct
children of the directory.  MS-SMB2 §3.3.5.18 requires that when
`SMB2_WATCH_TREE` is set, the server MUST monitor the entire subtree.

Linux `fsnotify` can provide recursive monitoring via a directory mark with
`FS_ISDIR` and traversal; however, this is complex to implement correctly for
deep subtrees without a dedicated `fanotify`-style mark on the mount point.  The
feature is currently silently ignored: the server accepts the flag and returns
`STATUS_PENDING` as if it will do recursive monitoring, but it only monitors
direct children.

**Impact:** Applications that set `SMB2_WATCH_TREE` (e.g., Windows Explorer,
backup software) will miss events in subdirectories.

---

### P2-02: Multiple FILE_NOTIFY_INFORMATION entries not coalesced in response

**Location:** `ksmbd_notify.c` — `ksmbd_notify_build_response()` (line 118) and
`ksmbd_notify_complete_piggyback()` (line 303)

**Problem:** Both response-building functions produce exactly one
`FILE_NOTIFY_INFORMATION` record per response, with `NextEntryOffset = 0`.
MS-SMB2 §2.2.36 permits (and Windows always tries to) pack multiple
`FILE_NOTIFY_INFORMATION` structures into a single response buffer.  When the
fsnotify callback fires for a single event, only that one event is emitted.
There is no mechanism to batch events that arrive within the same fsnotify
delivery window.

**Impact:** Higher round-trip count on busy directories; applications sensitive
to atomic change batching may behave incorrectly.

---

### P2-03: FILE_ACTION_ADDED_STREAM / REMOVED_STREAM / MODIFIED_STREAM never generated

**Location:** `ksmbd_notify.c` lines 101–112; `smb2pdu.h` lines 1234–1236

**Problem:** The action constants `FILE_ACTION_ADDED_STREAM` (0x06),
`FILE_ACTION_REMOVED_STREAM` (0x07), and `FILE_ACTION_MODIFIED_STREAM` (0x08)
are defined but never emitted.  The `ksmbd_fsnotify_to_action()` function maps
FS_CREATE → ADDED, FS_DELETE → REMOVED, FS_MOVED_FROM → RENAMED_OLD,
FS_MOVED_TO → RENAMED_NEW, and everything else → MODIFIED.  When
`FILE_NOTIFY_CHANGE_STREAM_*` filters are requested, clients expect stream-
specific actions.  Although Linux VFS does not natively support NTFS alternate
data streams, the action codes should be emitted at minimum when
`FILE_NOTIFY_CHANGE_STREAM_*` bits are in the completion filter and a relevant
event occurs.

---

### P2-04: FILE_NOTIFY_CHANGE_CREATION mis-mapped

**Location:** `ksmbd_notify.c` lines 854–855

**Problem:** When `FILE_NOTIFY_CHANGE_CREATION` is in the client's filter, the
code adds `FS_CREATE` to the fsnotify mask.  However, `FS_CREATE` is already
added by `FILE_NOTIFY_CHANGE_FILE_NAME`.  The `ksmbd_fsnotify_to_smb2_filter()`
function maps `FS_CREATE` to `FILE_NOTIFY_CHANGE_FILE_NAME` (line 78), so a
creation event will match a `FILE_NOTIFY_CHANGE_CREATION`-only filter only if
the filter-check at line 493 (`smb2_filter & watch->completion_filter`) happens
to overlap.  In practice a pure `CREATION`-only filter will not trigger on a
file create because the reverse mapping returns `FILE_NOTIFY_CHANGE_FILE_NAME`
from `FS_CREATE`, not `FILE_NOTIFY_CHANGE_CREATION`.

**Impact:** Clients watching only for creation-time changes (rare but valid) will
not receive notifications.

---

### P2-05: Partial entry at OutputBufferLength boundary never returned

**Location:** `smb2_dir.c` lines 284–288, 790–793

**Problem:** When an entry exactly fits at the end of the output buffer, the code
correctly includes it.  When an entry would overflow, `reserve_populate_dentry()`
sets `d_info.out_buf_len = 0` and returns `-ENOSPC`, which stops filling.  This
is the standard behavior.  However, MS-SMB2 §3.3.5.17 also states: "If the
current entry does not fit in the OutputBuffer, the server MUST return the last
complete entry."  The code does implement this correctly via the two-pass
design — the slot is reserved conservatively and the real data fills it later.

This item is *not* a bug for the common path, but there is a subtle issue: the
alignment padding `last_entry_off_align` (line 282) is subtracted from
`d_info.data_count` at line 1247 to shrink the reported `OutputBufferLength`.
This is correct for removing tail padding on the last entry.  No issue here.

Status: Correctly implemented.

---

## Partial implementations (P3)

### P3-01: search_pattern DOS wildcard characters not handled

**Location:** `misc.c` lines 21–71; code comment: "TODO: implement consideration
about DOS_DOT, DOS_QM and DOS_STAR"

**Problem:** MS-SMB2 §3.3.5.17 and MS-FSCC §2.1.4 specify three special
"DOS wildcard" characters that MUST be treated as wildcards in search patterns:
- `<` (DOS_STAR) — matches any sequence of characters that does not include a
  final dot
- `>` (DOS_QM) — matches any single character or the end of a name if the next
  character is a dot
- `"` (DOS_DOT) — matches a dot or the end of name

The `match_pattern()` function handles only `*` and `?`.  The three DOS-specific
characters are left as literals.  The in-source `TODO` comment (line 23)
acknowledges this gap.

**Impact:** Clients that rely on DOS-wildcard semantics (e.g., applications
searching for `*.` or `*<` patterns) will get incorrect or empty results.  This
is a compliance gap for §3.3.5.17 item 5 (pattern matching rules).

---

### P3-02: EaSize field in FileFullDirectory / FileIdFullDirectory conflated with reparse tag

**Location:** `smb2_dir.c` lines 301–304, 362–364

**Problem:** MS-FSCC §2.4.14 specifies that `EaSize` in `FileFullDirectoryInformation`
contains the combined size of the extended attributes when the
`FILE_ATTRIBUTE_REPARSE_POINT` flag is NOT set.  When the flag IS set, Windows
uses this field for the reparse tag.  The implementation always sets `EaSize` to
the reparse tag value returned by `smb2_get_reparse_tag_special_file()`, even
for files that have no reparse point.  For normal files (non-reparse), `EaSize`
should reflect the actual EA size, which would require an xattr lookup.  The
field is simply left as 0 by `ksmbd_vfs_init_kstat()` and then potentially
overwritten only if a reparse tag is found.  The result for non-reparse, non-EA
files is correct (0), but for files with EAs and no reparse point the EA size
is never reported.

**Impact:** Windows applications that read EA size from directory listings will
see 0 instead of the actual size.

---

### P3-03: ShortName (8.3) generation quality

**Location:** `smb_common.c` `ksmbd_extract_shortname()` — called from
`smb2_dir.c` lines 323–325, 417–420, 468–471, 515–518, 568–571

**Problem:** The code comment in `smb_common.c` acknowledges "the result is
different with Windows 7's one — need to check."  The 8.3 name is generated by
`ksmbd_extract_shortname()` but the algorithm for handling name collisions
(tilde-numbering) and Unicode characters is incomplete compared to the Windows
NTFS algorithm.  Short names are present in response structures
(`FileBothDirectoryInformation`, `FileIdBothDirectoryInformation`,
`FileIdExtdBothDirectoryInformation`, all `*Both*` variants) which is correct,
but the values may not match what Windows generates.

**Impact:** Applications that rely on 8.3 names for compatibility with legacy
16-bit software may encounter mismatches.

---

### P3-04: DIR_NAME vs FILE_NAME filter distinction in fsnotify reverse mapping

**Location:** `ksmbd_notify.c` lines 91–97

**Problem:** `ksmbd_fsnotify_to_smb2_filter()` attempts to differentiate
`FILE_NOTIFY_CHANGE_FILE_NAME` from `FILE_NOTIFY_CHANGE_DIR_NAME` by testing
`FS_ISDIR` in the event mask (lines 91–96).  However, this conversion only
works for the final filter-check at line 493.  The watch mask installed on the
inode (lines 839–864) maps both `FILE_NOTIFY_CHANGE_FILE_NAME` and
`FILE_NOTIFY_CHANGE_DIR_NAME` to the same `FS_CREATE | FS_DELETE | FS_MOVED_*`
events.  The distinction exists only in the event delivery path.  This means a
watch that requests only `FILE_NOTIFY_CHANGE_DIR_NAME` will also receive
events for file renames/deletions (these events arrive with `FS_ISDIR` unset),
which will not match the filter and thus be silently discarded — correct
behavior.  However, directory events without `FS_ISDIR` set (rare on some
filesystems) may be misclassified.

**Impact:** Minor; primarily affects edge cases on unusual filesystems.

---

### P3-05: Piggyback watch completion uses `request_buf` for `output_buf_len`

**Location:** `ksmbd_notify.c` lines 316–319

**Problem:** In `ksmbd_notify_complete_piggyback()`, the `output_buf_len` is
re-read from the original `work->request_buf` (`req->OutputBufferLength`),
whereas the primary watch path uses the `watch->output_buf_len` field which is
set during `ksmbd_notify_add_watch()`.  These should be equivalent, but reading
from `request_buf` in the piggyback path means the original work struct's request
buffer must remain valid until the piggyback is completed.  If the buffer is
freed early (e.g., due to connection reset), this is a use-after-free.  The
primary path (using `watch->output_buf_len`) is safer.

**Impact:** Potential use-after-free under specific connection teardown ordering.

---

## Low priority (P4)

### P4-01: Non-standard info classes accepted without negotiation check

**Location:** `smb2_dir.c` `verify_info_level()` lines 1011–1034

**Problem:** `FILEID_64_EXTD_DIRECTORY_INFORMATION` (0x64),
`FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION` (0x66),
`FILEID_ALL_EXTD_DIRECTORY_INFORMATION` (0x68),
`FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION` (0x6A) are non-standard extensions
not present in MS-SMB2.  They are accepted for any dialect and connection without
any capability negotiation check.  MS-SMB2 §3.3.5.17 requires
`FileIdExtdDirectoryInformation` (0x3C) and `FileIdExtdBothDirectoryInformation`
(0x3E) to be gated on `SMB2_GLOBAL_CAP_LARGE_MTU` or similar.

**Impact:** Spurious server behavior for clients that send unknown info classes.

---

### P4-02: SMB2_REOPEN does not update the open state in ksmbd_file

**Location:** `smb2_dir.c` lines 1140–1144

**Problem:** Beyond the protocol-level REOPEN gap (P1-03), the SMB2_REOPEN path
does not update `dir_fp->f_state`, does not re-validate access rights, and does
not reset the file position via `vfs_llseek()` instead of the direct
`generic_file_llseek()` call.  Using `generic_file_llseek()` bypasses any
filesystem-specific seek validation.

---

### P4-03: CHANGE_NOTIFY buffered-change limit (256) is global per watch, not per connection

**Location:** `ksmbd_notify.c` line 503

**Problem:** The hard-coded limit of 256 buffered changes applies per
`ksmbd_notify_watch`.  MS-SMB2 does not mandate a specific limit but
recommends the limit be configurable.  There is no sysctl or module parameter to
tune this value.

---

### P4-04: CHANGE_NOTIFY disable path (ksmbd_notify_enabled = false) leaves compound works pending forever

**Location:** `smb2_notify.c` lines 118–123, 229–230

**Problem:** When `ksmbd_notify_enabled()` returns false (fsnotify group
allocation failed), standalone CHANGE_NOTIFY returns `STATUS_NOT_SUPPORTED`
immediately.  For compound requests, the code creates an async work and goes to
`compound_set_pending` with `argv[0] = NULL`, returning `STATUS_PENDING` in the
compound slot.  The async work is never signalled (no fsnotify event, no cancel
until the connection closes).  On a connection with a long lifetime this produces
a perpetually pending async work that leaks resources.

---

### P4-05: CHANGE_NOTIFY response OutputBufferOffset value

**Location:** `ksmbd_notify.c` line 203

**Problem:** The `OutputBufferOffset` is computed as:
```
sizeof(struct smb2_hdr) +
sizeof(rsp->StructureSize) +
sizeof(rsp->OutputBufferOffset) +
sizeof(rsp->OutputBufferLength)
```
which totals `64 + 2 + 2 + 4 = 72` bytes.  MS-SMB2 §2.2.36 specifies this
field as the byte offset from the beginning of the SMB2 header to the output
buffer, and the fixed-size response header is 64 bytes, so the StructureSize
(9), OutputBufferOffset (2), and OutputBufferLength (4) fields occupy bytes
64–71 and the Buffer starts at byte 72.  The computation is correct.

Status: Correctly implemented; no issue.

---

### P4-06: query_dir scan limit (100,000) returns STATUS_NO_MORE_FILES instead of continuing across requests

**Location:** `smb2_dir.c` lines 1199–1206

**Problem:** When `total_scan > 100000` and no entries matched, the server
returns `STATUS_NO_MORE_FILES`.  This is incorrect for large directories where
entries exist but none match the search pattern in the first 100,000 entries.
The correct behavior is to return all matching entries; stopping early is a
server-imposed rate limit that violates §3.3.5.17.  The implementation preserves
the directory cursor so the client *can* resume, but the response code
`STATUS_NO_MORE_FILES` signals to the client that enumeration is complete.

**Impact:** On very large directories with sparse matches, the client may
prematurely believe the directory is exhausted.  This is also a security concern
(artificially limits directory visibility).

---

## Compliance estimate per command (%)

### SMB2 QUERY_DIRECTORY

| Area | Compliance | Notes |
|------|-----------|-------|
| FileInformationClass coverage (all 8 mandatory classes) | 100% | All mandatory classes implemented |
| SMB2_RESTART_SCANS flag | 95% | Correctly resets cursor |
| SMB2_RETURN_SINGLE_ENTRY flag | 90% | Implemented; STATUS_NO_SUCH_FILE condition slightly off |
| SMB2_INDEX_SPECIFIED flag | 0% | Completely unimplemented (P1-01) |
| SMB2_REOPEN flag | 30% | Treated as RESTART_SCANS only (P1-03) |
| FileIndex field in responses | 0% | Always zero (P1-02) |
| STATUS_NO_MORE_FILES / STATUS_NO_SUCH_FILE | 70% | Mis-gated (P1-04) |
| DOS wildcard characters (<, >, ") | 0% | Not implemented (P3-01) |
| EaSize field accuracy | 50% | Reparse tag only, no EA size |
| ShortName (8.3) generation | 60% | Present but algorithm incomplete |
| NextEntryOffset alignment (8-byte) | 100% | KSMBD_DIR_INFO_ALIGNMENT=8 |
| Last entry NextEntryOffset = 0 | 100% | Lines 1243–1248 |
| OutputBufferLength truncation | 90% | Correct; alignment padding removed |

**Overall SMB2 QUERY_DIRECTORY: ~72%**

### SMB2 CHANGE_NOTIFY

| Area | Compliance | Notes |
|------|-----------|-------|
| Basic async response (STATUS_PENDING interim) | 95% | Correctly implemented |
| CompletionFilter — FILE_NAME / DIR_NAME | 80% | Functional; reverse mapping has edge cases |
| CompletionFilter — ATTRIBUTES / SIZE / LAST_WRITE | 85% | Approximate via FS_ATTRIB/FS_MODIFY |
| CompletionFilter — LAST_ACCESS / CREATION | 70% | CREATION mis-mapped (P2-04) |
| CompletionFilter — EA / SECURITY | 50% | Both mapped to FS_ATTRIB; not distinct |
| CompletionFilter — STREAM_* | 20% | Mapped to FS_MODIFY only; no stream actions |
| SMB2_WATCH_TREE (recursive) | 0% | Stored but never applied (P2-01) |
| STATUS_NOTIFY_ENUM_DIR on overflow | 90% | Correct for total overflow; single-entry delivery gap |
| Multiple FILE_NOTIFY_INFORMATION in one response | 0% | Always single entry (P2-02) |
| Action values (ADDED/REMOVED/MODIFIED) | 90% | Core 5 actions correct |
| Action values (stream-specific) | 0% | Never generated (P2-03) |
| CANCEL of pending NOTIFY | 95% | Correctly sends STATUS_CANCELLED |
| Handle closed while pending (NOTIFY_CLEANUP) | 95% | STATUS_NOTIFY_CLEANUP sent |
| Multiple pending NOTIFY on same directory | 80% | Piggyback mechanism works; edge cases exist |
| Signing / encryption of async response | 90% | Implemented in all paths |
| Compound CHANGE_NOTIFY handling | 80% | Implemented; disable-path leak (P4-04) |

**Overall SMB2 CHANGE_NOTIFY: ~67%**

---

## Summary of top issues by priority

| ID | Priority | Command | Description |
|----|----------|---------|-------------|
| P1-01 | Critical | QUERY_DIRECTORY | SMB2_INDEX_SPECIFIED completely ignored |
| P1-02 | Critical | QUERY_DIRECTORY | FileIndex always zero in all responses |
| P1-03 | High | QUERY_DIRECTORY | SMB2_REOPEN not properly implemented |
| P1-04 | High | QUERY_DIRECTORY | STATUS_NO_SUCH_FILE mis-gated |
| P1-05 | High | CHANGE_NOTIFY | Multiple buffered changes not coalesced |
| P2-01 | High | CHANGE_NOTIFY | SMB2_WATCH_TREE not implemented |
| P2-02 | Medium | CHANGE_NOTIFY | No multi-entry response packing |
| P2-03 | Medium | CHANGE_NOTIFY | Stream action codes never generated |
| P2-04 | Medium | CHANGE_NOTIFY | FILE_NOTIFY_CHANGE_CREATION mis-mapped |
| P2-05 | Medium | QUERY_DIRECTORY | (No issue — correctly implemented) |
| P3-01 | Medium | QUERY_DIRECTORY | DOS wildcards (<, >, ") not handled |
| P3-02 | Low | QUERY_DIRECTORY | EaSize not populated for EAs |
| P3-03 | Low | QUERY_DIRECTORY | Short-name algorithm incomplete |
| P3-04 | Low | CHANGE_NOTIFY | DIR_NAME vs FILE_NAME filter edge case |
| P3-05 | Low | CHANGE_NOTIFY | Piggyback uses request_buf (UAF risk) |
| P4-01 | Low | QUERY_DIRECTORY | Non-standard info classes without negotiation |
| P4-02 | Low | QUERY_DIRECTORY | REOPEN does not reset f_state |
| P4-03 | Low | CHANGE_NOTIFY | Buffer limit not configurable |
| P4-04 | Low | CHANGE_NOTIFY | Disabled-notify path leaks async work |
| P4-06 | Medium | QUERY_DIRECTORY | 100k scan limit emits NO_MORE_FILES incorrectly |
