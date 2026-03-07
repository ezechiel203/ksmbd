# TODO_STELLAR_V9.md — ksmbd Cycle 9 Full Protocol Coverage Audit

**Audit scope**: Exhaustive line-by-line review of ALL MS-SMB2, MS-CIFS, and MS-FSCC commands/sub-commands
against the ksmbd codebase, using 8 parallel agents covering every protocol domain.

Progressive audit: V1(66)→V2(37)→V3(16)→V4(20)→V5(31)→V6(22)→V7(12)→V8(0)→**V9(24)**

**V9 Status**: 12 DONE, 11 VERIFIED_FALSE_POSITIVE, 1 DEFERRED (M-11 was already implemented)

---

## False Positives Excluded (verified by code reading)

- **Oplock break timeout** — `OPLOCK_WAIT_TIME` IS used in `wait_for_break_ack()` (oplock.c:742-745)
  with force-to-NONE on timeout; correctly implemented.
- **Epoch=0 for v1 leases** — v1 leases have no epoch concept; `br_info->epoch = 0` for v1 is correct.
- **FS_EVENT_ON_CHILD unconditional** — needed for immediate-child events in all cases; `watch_tree`
  adds FS_MODIFY/ATTRIB for deeper monitoring; correct by design.
- **MinimumCount logic** — `nbytes < mincount → STATUS_END_OF_FILE` IS correct per MS-SMB2 §3.3.5.12.
- **FILE_NAMES_INFORMATION missing EaSize** — that structure has no EaSize field (MS-FSCC §2.4.28).
- **Lease break ACK wrong-client risk** — `lookup_lease_in_table(conn, key)` validates by
  `conn->ClientGUID` (oplock.c:2807); only the owning client can ACK.
- **wait_for_break_ack indefinite wait** — times out after 35s, then revokes (oplock.c:748-752).
- **SMB1** — 90%+ complete; all handlers return clean NTSTATUS; no crash risk.
- **QUERY_DIR/NOTIFY** — CompletionFilter=0 check, FILE_LIST_DIRECTORY check, compound chain
  validation, NOTIFY_ENUM_DIR on overflow: all correctly implemented.
- **MinimumCount** (CREATE) — MxAc context conditional on MAXIMUM_ALLOWED: verified separately below.

---

## HIGH

### H-01 [PROTOCOL] smb2_create.c — Persistent handles fully stubbed
**File**: `src/protocol/smb2/smb2_create.c` lines 896–931
**Spec**: MS-SMB2 §3.3.5.9.9 (CREATE_DURABLE_HANDLE_REQUEST_V2 with PERSISTENT flag)

**Issue**: `ksmbd_ph_save()`, `ksmbd_ph_restore()`, and `ksmbd_ph_delete()` all contain only a
`pr_warn` and return immediately. The server returns `SMB2_DHANDLE_FLAG_PERSISTENT` in the CREATE
response (line 2572) and advertises `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` in NEGOTIATE, but
`ksmbd_ph_restore()` always returns NULL. Reconnecting clients after server crash get
`STATUS_OBJECT_NAME_NOT_FOUND` instead of their handle being restored.

**Fix**: Either:
1. Implement with `kernel_write()/kernel_read()` to a stable-path file (e.g., `/var/lib/ksmbd/ph/`),
   or
2. Never set `SMB2_DHANDLE_FLAG_PERSISTENT` in response and do not advertise
   `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` — clients will gracefully fall back to durable v2.

Option 2 is safe in 10 lines; Option 1 is complex and requires cluster coordination.

---

### H-02 [SECURITY] ksmbd_fsctl.c — FSCTL_SET_ENCRYPTION silently no-ops
**FSCTL code**: 0x000900D7
**Spec**: MS-FSCC §2.3.64

**Issue**: `fsctl_set_encryption_handler` accepts the request, sets a per-file attribute flag, and
returns STATUS_SUCCESS. Data is **not** encrypted. Windows clients use this to set encrypted-at-rest
status; they trust the STATUS_SUCCESS and believe the file is encrypted when it is not.

**Fix**: Return `STATUS_NOT_SUPPORTED` (or `STATUS_INVALID_DEVICE_REQUEST`) so clients know
encryption is unavailable and can choose an alternative (e.g., client-side encryption or different
share). A misleading SUCCESS is a semantic security issue.

---

### H-03 [PROTOCOL] smb2_create.c — POSIX create context mode bits not applied
**File**: `src/protocol/smb2/smb2_create.c` ~lines 1381–1391
**Spec**: SMB POSIX Extensions

**Issue**: When a client sends `SMB2_CREATE_TAG_POSIX` with mode bits in the create context, the
code validates the context is present and sets a flag, but does NOT pass the mode bits to the VFS
`vfs_create()`/`vfs_mkdir()` call. Files are always created with the share's default umask.

**Fix**: Extract the mode from the POSIX context and pass it to the VFS create call.
Complexity: MEDIUM.

---

## MEDIUM

### M-01 [PROTOCOL] smb2_negotiate.c — CipherCount always 1 in response
**File**: `src/protocol/smb2/smb2_negotiate.c` line 81
**Spec**: MS-SMB2 §2.2.3.1.2 (SMB2_ENCRYPTION_CAPABILITIES negotiate context)

**Issue**: `build_encrypt_ctxt()` hardcodes `pneg_ctxt->CipherCount = cpu_to_le16(1)` and sends
only the single selected cipher. Windows Server advertises all supported ciphers (4: AES-128-CCM,
AES-128-GCM, AES-256-CCM, AES-256-GCM) in its response so the client knows the full capability set.

**Fix**: Build the response context with all 4 supported cipher IDs; the server-selected cipher
is implicit as the first entry. ~10 lines.

---

### M-02 [PROTOCOL] smb2_negotiate.c — SigningAlgorithmCount always 1
**File**: `src/protocol/smb2/smb2_negotiate.c` line 105
**Spec**: MS-SMB2 §2.2.3.1.7 (SMB2_SIGNING_CAPABILITIES negotiate context)

**Issue**: `build_sign_cap_ctxt()` hardcodes `SigningAlgorithmCount = cpu_to_le16(1)`. All 3
algorithms (HMAC-SHA256, AES-CMAC, AES-GMAC) should be listed.

**Fix**: List all supported algorithm IDs in the response. ~10 lines.

---

### M-03 [PROTOCOL] smb2_dir.c — FILE_DIRECTORY_INFORMATION missing EaSize/reparse tag
**File**: `src/protocol/smb2/smb2_dir.c` lines 334–344
**Spec**: MS-FSCC §2.4.10 (FileDirectoryInformation)

**Issue**: The `FILE_DIRECTORY_INFORMATION` case does not populate `EaSize` with the reparse tag
when the entry is a reparse point (symlink/junction), nor does it set `ATTR_REPARSE_POINT_LE` in
`ExtFileAttributes`. All other directory enumeration classes
(`FILE_FULL_DIRECTORY_INFORMATION`, `FILE_BOTH_DIRECTORY_INFORMATION`,
`FILEID_FULL_DIRECTORY_INFORMATION`, `FILEID_BOTH_DIRECTORY_INFORMATION`) correctly call
`smb2_get_reparse_tag_special_file()` and set the attribute. CLASS 1 is the odd one out.

**Fix**: Add the same 4-line pattern used in the adjacent `FILE_FULL_DIRECTORY_INFORMATION` case.

---

### M-04 [PROTOCOL] ksmbd_fsctl.c — FSCTL_DFS_GET_REFERRALS returns wrong error
**FSCTL code**: 0x00060194
**Spec**: MS-SMB2 §3.3.5.15.2, MS-DFSC §2.2.2

**Issue**: No handler registered; falls through to "unknown FSCTL" path returning
`STATUS_INVALID_DEVICE_REQUEST`. Windows clients expect `STATUS_DFS_UNAVAILABLE` (0xC000026D)
when a server does not host DFS namespaces, allowing them to display a clean error rather than
interpreting it as a protocol error.

**Fix**: Add a stub handler that returns `STATUS_DFS_UNAVAILABLE`. 5 lines.

---

### M-05 [PROTOCOL] ksmbd_fsctl.c — FSCTL_SET/GET/DELETE_REPARSE_POINT not implemented
**FSCTL codes**: 0x000900A4, 0x000900A8, 0x000900AC
**Spec**: MS-FSCC §2.3.61–2.3.63

**Issue**: All three reparse point FSCTLs have no handler and return
`STATUS_INVALID_DEVICE_REQUEST`. Reparse points are used for symlinks, junctions, and WSL
paths. Without GET_REPARSE_POINT, clients cannot read symlinks created by Linux-side tools.

**Fix**:
- `GET_REPARSE_POINT`: Read symlink target via VFS `vfs_readlink()`, build IO_REPARSE_TAG_SYMLINK
  buffer. ~50 lines.
- `SET_REPARSE_POINT`: Create symlink via `vfs_symlink()` or write reparse data to xattr. ~60 lines.
- `DELETE_REPARSE_POINT`: Remove xattr / convert symlink to file. ~20 lines.

---

### M-06 [PROTOCOL] ksmbd_fsctl.c — FSCTL_LMR_REQUEST_RESILIENCY not implemented
**FSCTL code**: 0x001401D4
**Spec**: MS-SMB2 §3.3.5.15.11 (LMR = Lease Management Resource)

**Issue**: Returns `STATUS_INVALID_DEVICE_REQUEST`. Per spec, if the server does not support
resilient handles, it MUST return `STATUS_NOT_SUPPORTED`. Clients interpret the wrong status
as a protocol fault.

**Fix**: Return `STATUS_NOT_SUPPORTED`. 5 lines.

---

### M-07 [PROTOCOL] ksmbd_fsctl.c — FSCTL_SRV_ENUMERATE_SNAPSHOTS returns wrong error
**FSCTL code**: 0x00144064
**Spec**: MS-SMB2 §3.3.5.15.1

**Issue**: No handler; returns `STATUS_INVALID_DEVICE_REQUEST`. When no VSS snapshots exist,
the server should return a valid response with `NumberOfSnapshots = 0` and
`NumberOfSnapshotsReturned = 0`. Many backup clients send this FSCTL and expect a valid empty
response, not an error.

**Fix**: Add handler returning `struct smb2_ioctl_rsp` with zero-snapshot counts. ~30 lines.

---

### M-08 [PROTOCOL] smb2_create.c — SecurityFlags field not validated
**File**: `src/protocol/smb2/smb2_create.c` (request parsing, ~line 1400)
**Spec**: MS-SMB2 §2.2.13 — "SecurityFlags MUST be 0"

**Issue**: The `SecurityFlags` field in CREATE requests is never checked. Non-zero values should
return `STATUS_INVALID_PARAMETER`.

**Fix**: Add `if (req->SecurityFlags != 0) return -EINVAL;` after the request is obtained. 3 lines.

---

### M-09 [PROTOCOL] smb2_create.c — QueryMaximalAccess context conditional on MAXIMUM_ALLOWED
**File**: `src/protocol/smb2/smb2_create.c` lines 1773–1778
**Spec**: MS-SMB2 §2.2.14.2.1 (CREATE_QUERY_MAXIMAL_ACCESS_REQUEST)

**Issue**: The `maximal_access_ctxt` flag (which triggers MxAc response generation) is only set
when `req->DesiredAccess & MAXIMUM_ALLOWED_LE`. If a client requests the `MxAc` create context
without setting MAXIMUM_ALLOWED in DesiredAccess, no response context is generated. Per spec,
the server MUST return the MxAc response context when the client sends the request context,
regardless of DesiredAccess.

**Fix**: Set `maximal_access_ctxt = true` when the MxAc context is parsed, irrespective of
DesiredAccess flags. ~3 lines.

---

### M-10 [PROTOCOL] smb2_tree.c — ShareFlags caching modes not advertised
**File**: `src/protocol/smb2/smb2_tree.c` ~lines 377–379
**Spec**: MS-SMB2 §2.2.10 (ShareFlags field)

**Issue**: ShareFlags always returns `SMB2_SHAREFLAG_MANUAL_CACHING` (0x00000000). Shares
configured with auto-caching, VDO caching, or no-caching never have those bits set in responses.
Clients default to manual caching without this information.

**Fix**: Add `caching_mode` field to `ksmbd_share_config` (or read from `smb.conf` via IPC),
and set the appropriate `SMB2_SHAREFLAG_*_CACHING` bit in the response.
Fix complexity: MEDIUM (requires ksmbd-tools ABI extension for the new config field).

---

### M-11 [PROTOCOL] smb2_create.c — APP_INSTANCE_VERSION close-older-instance not implemented
**File**: `src/protocol/smb2/smb2_create.c` ~lines 1225–1280
**Spec**: MS-SMB2 §2.2.13.2.13 (SMB2_CREATE_APP_INSTANCE_VERSION)

**Issue**: When a client opens a named pipe and supplies an `AppInstanceVersion` that is higher
than an existing open on the same pipe from the same `AppInstanceId`, the server MUST close the
older handle. Currently the version is parsed but not compared against existing opens.

**Fix**: On pipe open with APP_INSTANCE_VERSION, iterate open handles with matching AppInstanceId,
close those with lower version. Complexity: MEDIUM.

---

### M-12 [QUALITY] oplock.c — Lease break BreakReason never set for parent rename
**File**: `src/fs/oplock.c` ~line 1085
**Spec**: MS-SMB2 §2.2.23.2 (SMB2_LEASE_BREAK_NOTIFICATION)

**Issue**: `rsp->BreakReason` is always 0 (`SMB2_LEASE_BREAK_REASON_NONE`). When a lease break
is triggered by a parent directory rename, `BreakReason` should be 2
(`SMB2_LEASE_BREAK_REASON_PARENT_LEASE_KEY_CHANGED`). Clients use this hint to decide
whether to invalidate cached path information.

**Fix**: Pass break reason through `smb_break_info` and populate `BreakReason` in the
notification builder. Also populate `AccessMaskHint`/`ShareMaskHint` where feasible. ~20 lines.

---

### M-13 [QUALITY] ksmbd_notify.c — No per-handle limit on CHANGE_NOTIFY async requests
**File**: `src/fs/ksmbd_notify.c`
**Spec**: MS-SMB2 §3.3.5.19 (resource limits)

**Issue**: A client can issue unlimited concurrent CHANGE_NOTIFY requests on a single file handle.
Each allocates async work and watch structures. There is a server-wide limit
(`KSMBD_MAX_NOTIFY_WATCHES` = 4096) and per-connection limit (1024) but no per-handle limit.
A single authenticated client can exhaust the per-connection quota by issuing 1024 NOTIFY
requests on one handle.

**Fix**: Track outstanding NOTIFY count per `ksmbd_file`, reject additional requests when over a
per-handle threshold (e.g., 4). Complexity: LOW.

---

### M-14 [PROTOCOL] ksmbd_notify.c — FILE_ACTION_REMOVED_BY_DELETE never emitted
**File**: `src/fs/ksmbd_notify.c` lines 118–129
**Spec**: MS-FSCC §2.4.42 (FILE_NOTIFY_INFORMATION Action)

**Issue**: `ksmbd_fsnotify_to_action()` maps `FS_DELETE` to `FILE_ACTION_REMOVED` (0x2) always.
`FILE_ACTION_REMOVED_BY_DELETE` (0x9) should be sent when a file is deleted by an explicit
SMB2 delete (DELETE_ON_CLOSE or by a SetInfo FILE_DISPOSITION). Clients distinguish these to
properly invalidate or update caches.

**Fix**: Track whether the deletion was initiated by the SMB server (set a flag in `ksmbd_file`
when delete-on-close is set), then emit `FILE_ACTION_REMOVED_BY_DELETE` from that path.
Complexity: MEDIUM.

---

### M-15 [PROTOCOL] smb2ops.c — SMB2_GLOBAL_CAP_PERSISTENT_HANDLES missing on SMB 3.0
**File**: `src/core/smb2ops.c` ~lines 333–334
**Spec**: MS-SMB2 §2.2.4 (Capabilities for SMB 3.0)

**Issue**: `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` is advertised in SMB 3.0.2+ values but not in
SMB 3.0. The same conditional applies (enabled only when `KSMBD_GLOBAL_FLAG_DURABLE_HANDLE` is
set), so the fix is symmetric.

**Note**: If H-01 is resolved by disabling persistent handles entirely, this item is moot.
Otherwise, add the capability bit to the SMB 3.0 values table.

---

## LOW

### L-01 [PROTOCOL] smb2_query_set.c — Quota information not even rejected cleanly
**File**: `src/protocol/smb2/smb2_query_set.c` + info handler
**Spec**: MS-SMB2 §2.2.37 (InfoType = QUOTA)

**Issue**: QUERY_INFO for quota returns empty data (no quota entries); SET_INFO for quota
silently discards the input. Clients expecting STATUS_NOT_SUPPORTED or at minimum an empty-but-
valid quota response get corrupted/empty results.

**Fix**: Return `STATUS_NOT_SUPPORTED` for quota SET (server doesn't implement quotas).
For quota GET, return a valid zero-entry response so clients can enumerate cleanly.

---

### L-02 [PROTOCOL] smbacl.c — LABEL_SECINFO (integrity labels) not applied
**File**: `src/fs/smbacl.c`
**Spec**: MS-SMB2 §3.3.5.20.3 (LABEL_SECURITY_INFORMATION = 0x10)

**Issue**: `LABEL_SECINFO` is validated in the bitmask check but never written to the security
descriptor. Windows 8+ uses integrity labels (Low/Medium/High) for UAC policy. Accepted and
discarded silently.

**Fix**: Store label in an xattr (`user.smb.label`) on filesystems that support xattrs;
return STATUS_NOT_SUPPORTED on those that don't. Complexity: MEDIUM.

---

### L-03 [QUALITY] ksmbd_info.c — FILE_SHORT_NAME_INFORMATION SET is silent no-op
**File**: `src/fs/ksmbd_info.c`
**Spec**: MS-FSCC §2.4.41

**Issue**: SET_INFO for FILE_SHORT_NAME_INFORMATION (class 40) calls
`ksmbd_info_set_noop_consume()` which logs and returns SUCCESS. Changes are silently discarded.
Clients expect short name changes to persist; if not supported, server should say so.

**Fix**: Return `STATUS_NOT_SUPPORTED` (or `STATUS_INVALID_PARAMETER` if admin only). 1 line.

---

### L-04 [QUALITY] ksmbd_info.c — FS_LABEL_INFORMATION SET accepted but not persisted
**File**: `src/fs/ksmbd_info.c` (`ksmbd_info_set_fs_label`)
**Spec**: MS-FSCC §2.5.2

**Issue**: Volume label SET validates input but takes no action. The label returned in
`FS_VOLUME_INFORMATION` is the share name or a fixed string; it never changes.

**Fix**: Store label in a per-share xattr (e.g., `trusted.ksmbd.volume_label`) and read it
back in `ksmbd_info_get_fs_volume()`. Complexity: LOW.

---

### L-05 [PROTOCOL] smb2_create.c — ALLOCATION_SIZE create context not applied
**File**: `src/protocol/smb2/smb2_create.c`
**Spec**: MS-SMB2 §2.2.13.2.4 (SMB2_CREATE_ALLOCATION_SIZE)

**Issue**: The `AlSi` create context is parsed (size hint extracted) but the hint is never
passed to `vfs_fallocate()`. File pre-allocation improves write performance for large files.

**Fix**: After file creation, if `allocation_size > 0` and file is a regular file, call
`vfs_fallocate(FALLOC_FL_KEEP_SIZE)`. ~10 lines.

---

### L-06 [PROTOCOL] smb2ops.c — SMB2_GLOBAL_CAP_MULTI_CHANNEL missing on SMB 3.0
**File**: `src/core/smb2ops.c`
**Spec**: MS-SMB2 §2.2.4

**Issue**: `SMB2_GLOBAL_CAP_MULTI_CHANNEL` is advertised on SMB 3.0.2 (behind
`KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL`) but not on SMB 3.0. This means SMB 3.0 clients
cannot establish secondary channels even if the server is configured to support them.

**Fix**: Add same conditional capability bit to SMB 3.0 values table. 3 lines.

---

## Summary Table

| ID   | Sev    | File                        | Topic                                            | Status |
|------|--------|-----------------------------|--------------------------------------------------|--------|
| H-01 | HIGH   | smb2_create.c:896-931       | Persistent handles fully stubbed                 | DONE (option 2: cap disabled) |
| H-02 | HIGH   | ksmbd_fsctl.c               | FSCTL_SET_ENCRYPTION misleading success          | VERIFIED_FALSE_POSITIVE (already returns NOT_SUPPORTED) |
| H-03 | HIGH   | smb2_create.c:1381          | POSIX create context mode bits not applied       | VERIFIED_FALSE_POSITIVE (mode passed via vfs_create iattr) |
| M-01 | MEDIUM | smb2_negotiate.c:81         | CipherCount=1 always (should list all 4)         | VERIFIED_FALSE_POSITIVE (spec §3.3.5.4 requires CipherCount=1 in response) |
| M-02 | MEDIUM | smb2_negotiate.c:105        | SigningAlgorithmCount=1 always (should list all) | VERIFIED_FALSE_POSITIVE (spec §3.3.5.4 requires count=1 in response) |
| M-03 | MEDIUM | smb2_dir.c:334-344          | FILE_DIRECTORY_INFO missing EaSize/reparse tag   | VERIFIED_FALSE_POSITIVE (MS-FSCC §2.4.10: struct has no EaSize field) |
| M-04 | MEDIUM | ksmbd_fsctl.c               | FSCTL_DFS_GET_REFERRALS wrong error code         | VERIFIED_FALSE_POSITIVE (already returns STATUS_DFS_UNAVAILABLE) |
| M-05 | MEDIUM | ksmbd_fsctl.c               | FSCTL_SET/GET/DELETE_REPARSE_POINT not impl      | VERIFIED_FALSE_POSITIVE (implemented in ksmbd_reparse.c) |
| M-06 | MEDIUM | ksmbd_fsctl.c               | FSCTL_LMR_REQUEST_RESILIENCY wrong error         | VERIFIED_FALSE_POSITIVE (returns STATUS_NOT_SUPPORTED) |
| M-07 | MEDIUM | ksmbd_fsctl.c               | FSCTL_SRV_ENUMERATE_SNAPSHOTS wrong error        | VERIFIED_FALSE_POSITIVE (returns zero-snapshot response) |
| M-08 | MEDIUM | smb2_create.c:~1400         | SecurityFlags not validated (must be 0)          | DONE |
| M-09 | MEDIUM | smb2_create.c:1773          | MxAc response not always generated              | VERIFIED_FALSE_POSITIVE (MxAc set unconditionally when context present) |
| M-10 | MEDIUM | smb2_tree.c:377             | ShareFlags caching modes not advertised          | DONE (bits 21-22 in netlink flags; no ABI struct change) |
| M-11 | MEDIUM | smb2_create.c:1225          | APP_INSTANCE_VERSION semantics missing           | DONE (ksmbd_app_instance.c via create ctx framework) |
| M-12 | MEDIUM | oplock.c:1085               | Lease BreakReason=0 always (parent rename)       | DONE |
| M-13 | MEDIUM | ksmbd_notify.c              | No per-handle NOTIFY limit (DoS)                 | DONE |
| M-14 | MEDIUM | ksmbd_notify.c:118          | FILE_ACTION_REMOVED_BY_DELETE never emitted      | DONE (S_SMB_DELETE flag + ksmbd_inode_is_smb_delete()) |
| M-15 | MEDIUM | smb2ops.c:333               | PERSISTENT_HANDLES cap missing on SMB 3.0        | DONE (moot — cap disabled by H-01 fix) |
| L-01 | LOW    | smb2_query_set.c            | Quota not rejected cleanly                       | DONE |
| L-02 | LOW    | smbacl.c                    | LABEL_SECINFO not applied                        | DONE (XATTR_NAME_SD_LABEL; SET stores SACL, GET retrieves) |
| L-03 | LOW    | ksmbd_info.c                | FILE_SHORT_NAME_INFORMATION SET silent no-op     | DONE |
| L-04 | LOW    | ksmbd_info.c                | FS_LABEL_INFORMATION SET not persisted           | DONE |
| L-05 | LOW    | smb2_create.c               | ALLOCATION_SIZE context not applied              | VERIFIED_FALSE_POSITIVE (vfs_fallocate called after create) |
| L-06 | LOW    | smb2ops.c                   | MULTI_CHANNEL cap missing on SMB 3.0             | VERIFIED_FALSE_POSITIVE (SMB3_MULTICHANNEL flag applies to both 3.0/3.0.2) |

**Total: 24 findings** (3 HIGH, 12 MEDIUM, 6 LOW — including M-15 and L-06 as extras)

---

## Fix Order (recommended)

**Group 1 — HIGH (fix first, highest interop impact):**
1. H-02 — FSCTL_SET_ENCRYPTION: return STATUS_NOT_SUPPORTED (5 min, 1 line)
2. M-08 — SecurityFlags validation (5 min, 3 lines)
3. M-03 — FILE_DIRECTORY_INFORMATION EaSize (10 min, 4 lines)
4. M-04, M-06, M-07 — FSCTL error codes (15 min total, stubs)
5. M-09 — MxAc unconditional generation (10 min, 3 lines)
6. M-01, M-02 — Negotiate cipher/signing lists (1 hr, refactor build_encrypt_ctxt/build_sign_cap_ctxt)
7. H-03 — POSIX create mode bits (2 hr, extract mode → VFS create call)

**Group 2 — MEDIUM (second pass):**
8. M-05 — Reparse point FSCTLs (symlink GET/SET/DELETE) (~1 day)
9. M-13 — Per-handle NOTIFY limit (30 min)
10. L-03, L-04 — Short name SET → STATUS_NOT_SUPPORTED, volume label xattr (30 min)
11. L-01 — Quota returns STATUS_NOT_SUPPORTED (10 min)
12. M-12 — Lease BreakReason for parent rename (2 hr)
13. M-14 — FILE_ACTION_REMOVED_BY_DELETE (2 hr)
14. M-11 — APP_INSTANCE_VERSION semantics (half day)
15. L-05 — ALLOCATION_SIZE pre-alloc (30 min)
16. L-06, M-15, M-06 — Capability bits SMB 3.0 (15 min)

**Group 3 — COMPLEX (plan separately):**
17. H-01 — Persistent handles: implement or disable advertisement (1 week if implementing)
18. M-10 — ShareFlags caching modes (requires ksmbd-tools ABI extension)
19. L-02 — LABEL_SECINFO xattr (half day + testing)

After fixes: run full smbtorture sweep on VM3 + VM7 to verify no regressions.
