# KSMBD SMB2 Protocol Upgrade Plan
## Target: 100% MS-SMB2 Compliance

**Branch:** `phase1-security-hardening`
**Audit date:** 2026-03-01
**Wave 1 implementation complete:** 2026-03-02 (commit bc5ef70 — 98 files, +10550/-1640)
**Specification baseline:** MS-SMB2 v52.0, MS-FSCC (latest)

---

## Overview

### Wave 1 Summary (Tracks A–J + Integration)

Wave 1 implemented all P1 critical bugs, the majority of P2 missing features, many P3
partial implementations, and selected P4 quick wins across 10 parallel tracks.
All 10 "Top Critical Bugs" from the pre-Wave 1 audit are now resolved.
Smoke tests (TCP + QUIC): **PASS=7 FAIL=0 SKIP=0** on both VM3 and VM4.

### Estimated Compliance per Command Area

| Command / Area | Pre-Wave 1 | Post-Wave 1 | Plan File |
|---|---|---|---|
| SMB2 NEGOTIATE | ~82% | ~95% | Plan 01 |
| SMB2 SESSION_SETUP | ~78% | ~92% | Plan 01 |
| SMB2 LOGOFF | ~85% | ~97% | Plan 01 |
| SMB2 TREE_CONNECT | ~72% | ~90% | Plan 01 |
| SMB2 TREE_DISCONNECT | ~88% | ~93% | Plan 01 |
| SMB2 CREATE | ~72% | ~88% | Plan 02 |
| SMB2 CLOSE | ~88% | ~92% | Plan 02 |
| SMB2 FLUSH | ~80% | ~93% | Plan 02 |
| SMB2 ECHO | ~99% | ~99% | Plan 02 |
| SMB2 CANCEL | ~92% | ~97% | Plan 02 |
| SMB2 READ | ~62% | ~80% | Plan 03 |
| SMB2 WRITE | ~62% | ~82% | Plan 03 |
| SMB2 LOCK | ~75% | ~91% | Plan 04 |
| SMB2 IOCTL / FSCTL | ~68% | ~86% | Plan 04 |
| SMB2 QUERY_DIRECTORY | ~72% | ~90% | Plan 05 |
| SMB2 CHANGE_NOTIFY | ~67% | ~85% | Plan 05 |
| SMB2 QUERY_INFO | ~72% | ~88% | Plan 06 |
| SMB2 SET_INFO | ~74% | ~89% | Plan 06 |
| SMB3 Oplocks / Leases | ~80% | ~89% | Plan 07 |
| SMB3 Durable Handles | ~60% | ~82% | Plan 07 |
| SMB3 Multichannel | ~60% | ~72% | Plan 07 |
| SMB3 Encryption | ~70% | ~88% | Plan 07 |
| SMB3 Compression | ~50% | ~62% | Plan 07 |
| SMB3 Signing | ~85% | ~97% | Plan 07 |
| SMB3 Pre-Auth Integrity | ~90% | ~95% | Plan 07 |
| SMB3 Credit System | ~60% | ~68% | Plan 07 |
| SMB3 QUIC Transport | ~30% | ~42% | Plan 07 |

**Pre-Wave 1 unweighted average: ~74%**
**Post-Wave 1 unweighted average: ~88%**

---

### Wave 1 Key Fixes — Former Top 10 P1 Items (All Resolved)

All 10 critical bugs identified in the pre-Wave 1 audit have been fixed in commit
`bc5ef70` (branch `phase1-security-hardening`, 2026-03-02):

1. **[FIXED — Track F]** `FSCTL_QUERY_NETWORK_INTERFACE_INFO` opcode corrected
   (`0x001401FC` → `0x001400FC`); LinkSpeed unit fixed (bits/s → bytes/s).

2. **[FIXED — Track B]** `SMB2_GLOBAL_CAP_ENCRYPTION` now set for SMB 3.1.1 in
   `init_smb3_11_server()`.

3. **[FIXED — Track B + prior sessions]** Per-tree-connect encryption enforcement
   added in `server.c` request dispatch; session-level encryption enforcement
   added with session disconnect on violation.

4. **[FIXED — Track G]** `FileIdInformation` struct corrected to 24 bytes
   (`VolumeSerialNumber` u64 + `FileId` 16-byte array); populated from `stat.dev`
   and `stat.ino`.

5. **[FIXED — Track C]** TWrp snapshot path: `snap_path` lifetime extended past
   VFS open; server now opens the actual historical snapshot, not the live file.

6. **[FIXED — Track B]** `SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA` (0x04) now checked
   in SESSION_SETUP; `sess->enc_forced` set; session flags updated.

7. **[FIXED — Track G]** `FileStreamInformation` `StreamSize` now reports actual
   xattr value length (via `ksmbd_vfs_getxattr()`), not the xattr name length.

8. **[FIXED — Track E + Wave 2]** Cancelled blocking lock now sends a proper final
   `STATUS_CANCELLED` LOCK response; async cancel path fixed for compound work.

9. **[FIXED — Track C]** DH2Q persistent-handle on non-CA share now returns
   `STATUS_INVALID_PARAMETER`.

10. **[FIXED — Track F]** `FSCTL_COPYCHUNK` off-by-one corrected (`>=` → `>`);
    exactly `max_chunk_count` chunks now accepted.

---

### Plan Files Index

| File | Area | Compliance | Key Gaps |
|---|---|---|---|
| `smb2_plan_01_negotiate_session_tree.md` | NEGOTIATE / SESSION_SETUP / LOGOFF / TREE_CONNECT / TREE_DISCONNECT | ~81% avg | ServerGUID zeroed; SESSION encrypt flag ignored; MaximalAccess static; LOGOFF wrong NTSTATUS |
| `smb2_plan_02_create_close_flush.md` | CREATE / CLOSE / FLUSH / ECHO / CANCEL | ~86% avg | TWrp opens live file; FILE_OPEN_BY_FILE_ID rejected; FLUSH on pipe crashes |
| `smb2_plan_03_read_write.md` | READ / WRITE | ~62% | READ_UNBUFFERED/WRITE_UNBUFFERED missing; compressed reads never work; pipe DataRemaining wrong |
| `smb2_plan_04_lock_ioctl.md` | LOCK / IOCTL-FSCTL | ~72% avg | QUERY_NETWORK_INTERFACE wrong code; cancelled lock bad response; COPYCHUNK off-by-one |
| `smb2_plan_05_querydir_notify.md` | QUERY_DIRECTORY / CHANGE_NOTIFY | ~70% avg | INDEX_SPECIFIED ignored; FileIndex always zero; WATCH_TREE not implemented |
| `smb2_plan_06_queryinfo_setinfo.md` | QUERY_INFO / SET_INFO | ~72% avg | FileIdInformation struct wrong; StreamSize wrong; EASize always zero; FileStatInformation missing |
| `smb2_plan_07_smb3_advanced.md` | SMB3 Encryption / Signing / Compression / Multichannel / Durable Handles / QUIC / Credits | ~68% avg | ENC cap not set for 3.1.1; per-tree encryption absent; chained compression crashes; nonce reuse risk |

---

## P1 Critical Bugs — Status After Wave 1

All P1 items listed below were resolved in Wave 1 (commit `bc5ef70`, 2026-03-02).
Items marked **[FIXED]** have been implemented and smoke-tested. A small number of
items confirmed as non-bugs or already correct are marked **[N/A]**.

The following entries are retained as a historical record; they now serve as the
regression prevention specification — any reversion of these fixes should be treated
as a blocker.

---

### From Plan 01 — Negotiate / Session / Tree

**[FIXED — Track B] BUG-01**: ServerGUID persistence — random GUID generated at init,
stored in `server_conf.server_guid`, emitted unchanged in NEGOTIATE response and
VALIDATE_NEGOTIATE_INFO response.

**[FIXED — Track B] BUG-03**: `SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA` (0x04) now checked
in SESSION_SETUP; encryption forced on session when flag is set.

**[FIXED — Track B] BUG-04**: `ServerStartTime` now populated from `server_conf.start_time`
(recorded at module init, converted to FILETIME epoch) in every NEGOTIATE response.

**[FIXED — Track B] BUG-05**: LOGOFF now returns `STATUS_USER_SESSION_DELETED` (was
`STATUS_NETWORK_NAME_DELETED`) on the session-not-found error path.

---

### From Plan 02 — Create / Close / Flush

**[FIXED — Track C] P1-01 (Plan 02)**: TWrp timewarp snapshot path fixed; `snap_path`
lifetime extended past VFS open; server now opens the actual historical snapshot.

**[FIXED — prior sessions] P1-02 (Plan 02)**: FLUSH on named pipe now returns
`STATUS_NOT_SUPPORTED`; added `KSMBD_SHARE_FLAG_PIPE` guard in `smb2_flush()`.

**[FIXED — Track C] P1-03 (Plan 02)**: `FILE_OPEN_BY_FILE_ID` now routed to
`smb2_resolve_open_by_file_id()`; the early `return -EOPNOTSUPP` has been removed.

---

### From Plan 03 — Read / Write

**[FIXED — Track D] B3 (Plan 03)**: Named pipe write error path now returns a
negative error code; `STATUS_PIPE_NOT_AVAILABLE` used instead of `STATUS_INVALID_HANDLE`.

**[FIXED — Track D] B4 (Plan 03)**: WRITE RDMA zero-length guard added before
`ksmbd_conn_rdma_read()`; returns `STATUS_INVALID_PARAMETER` for zero-length RDMA writes.

---

### From Plan 04 — Lock / IOCTL-FSCTL

**[FIXED — prior sessions] P1-LOCK-01**: Lock sequence bits corrected (5-bug fix in
prior sessions): bit extraction, replay return value, array size (65 entries),
`0xFF` sentinel for uninitialized slots, sequence stored after success only.
Extended to persistent handles as well as durable/resilient.

**[FIXED — Track E + Wave 2] P1-LOCK-02**: Cancelled blocking lock now sends a proper
final `STATUS_CANCELLED` response. Async cancel path fixed to match compound-spawned
CHANGE_NOTIFY work items by `async_id` (not `request_buf`) to avoid hanging clients.

**[FIXED — Track F] P1-IOCTL-01**: `FSCTL_QUERY_NETWORK_INTERFACE_INFO` opcode
corrected to `0x001400FC`; LinkSpeed fixed from bits/s to bytes/s.

**[FIXED — Track F] P1-IOCTL-02**: Dead legacy `FSCTL_GET_REPARSE_POINT` handler
removed from the `switch(cnt_code)` block in `smb2_ioctl()`.

**[FIXED — Track F] P1-IOCTL-03**: `FSCTL_COPYCHUNK` off-by-one corrected (`>=` → `>`).

---

### From Plan 05 — QueryDirectory / ChangeNotify

**[FIXED — Track H] P1-01 (Plan 05)**: `SMB2_INDEX_SPECIFIED` now reads `req->FileIndex`
and seeks the directory fd via `vfs_llseek()` before iterating.

**[FIXED — Track H] P1-02 (Plan 05)**: `FileIndex` now populated from `ctx->pos` in
`ksmbd_vfs_init_kstat()` for all directory info levels.

**[FIXED — Track H] P1-03 (Plan 05)**: `SMB2_REOPEN` now closes and reopens the directory
fd and resets all search state (distinct from `SMB2_RESTART_SCANS`).

**[FIXED — Track H] P1-04 (Plan 05)**: `STATUS_NO_SUCH_FILE` returned on first call with
no matches; `STATUS_NO_MORE_FILES` reserved for subsequent calls after at least one match.

**[FIXED — Track H] P1-05 (Plan 05)**: CHANGE_NOTIFY response now packs multiple buffered
events into a single response using `NextEntryOffset` chaining.

---

### From Plan 06 — QueryInfo / SetInfo

**[FIXED — Track G] BUG-P1-01 (Plan 06)**: `FileIdInformation` corrected to 24 bytes
(`VolumeSerialNumber` u64 from `stat.dev`, `FileId` 16-byte array from `stat.ino`).

**[FIXED — Track G] BUG-P1-02 (Plan 06)**: `FileStreamInformation` `StreamSize` now
reports actual xattr value length via `ksmbd_vfs_getxattr()`; `StreamAllocationSize`
computed correctly for both the `::$DATA` default stream and named streams.

---

### From Plan 07 — SMB3 Advanced Features

**[N/A] B2 (Plan 07)**: Session key truncation concern — verified that `SMB2_NTLMV2_SESSKEY_SIZE`
is 16 bytes and the KDF input is always bounded correctly. No code change needed.

**[FIXED — Track B] B4 (Plan 07)**: `SMB2_GLOBAL_CAP_ENCRYPTION` now set for SMB 3.1.1
in `init_smb3_11_server()`.

**[FIXED — Track B + prior sessions] B5 (Plan 07)**: Per-tree-connect and per-session
encryption enforcement added; unencrypted requests on encrypted sessions return
`STATUS_ACCESS_DENIED` and the connection is disconnected.

**[FIXED — Track C] B6 (Plan 07)**: DHnC now validates lease context against the
original handle's `is_lease` flag; returns `STATUS_OBJECT_NAME_NOT_FOUND` on mismatch.

**[FIXED — Track C] B7 (Plan 07)**: DH2Q persistent-handle on non-CA share now returns
`STATUS_INVALID_PARAMETER` instead of silently downgrading.

---

## P2 Missing Features — High Windows Interop Impact

### Connection Establishment (Plan 01)

- **P2-01**: `SMB2_NETNAME_NEGOTIATE_CONTEXT_ID` (type 5) content is parsed but never validated against the server's own hostname/addresses; a misdirected connection silently succeeds.
  File: `src/protocol/smb2/smb2_negotiate.c:627–629`
  Spec: MS-SMB2 §2.2.3.1.4, §3.3.5.4

- **P2-02**: Session-binding signature verification may accept compound requests where only the first PDU signature covers the binding SESSION_SETUP; each binding must be individually verified using the session's `smb3signingkey`.
  File: `src/protocol/smb2/smb2_session.c:678–685`
  Spec: MS-SMB2 §3.3.5.2.7

- **P2-03**: `TREE_CONNECT MaximalAccess` is a hard-coded read-only or read-write bitmask; it is not derived from actual filesystem permissions of the share root for the authenticated user — causes confusing `STATUS_ACCESS_DENIED` after TREE_CONNECT succeeds.
  File: `src/protocol/smb2/smb2_tree.c:223–234`
  Spec: MS-SMB2 §2.2.10, §3.3.5.7 step 6

- **P2-04**: `SMB2_SHARE_TYPE_PRINT` (0x03) is never returned for print shares.
  File: `src/protocol/smb2/smb2_tree.c:213–235`
  Spec: MS-SMB2 §2.2.10 (ShareType)

- **P2-05**: LOGOFF does not explicitly cancel outstanding async requests on other multichannel connections for the same session.
  File: `src/protocol/smb2/smb2_tree.c:393–403`
  Spec: MS-SMB2 §3.3.5.6 step 3

### Create / Close (Plan 02)

- **P2-01 (Plan 02)**: `FILE_OPEN_REPARSE_POINT` not honored; `LOOKUP_NO_SYMLINKS` is always set; all symlinks return `STATUS_ACCESS_DENIED` even when the client explicitly requests the reparse point itself.
  File: `src/protocol/smb2/smb2_create.c:1519`, `1549`
  Spec: MS-SMB2 §2.2.13 (CreateOptions), §3.3.5.9

- **P2-02 (Plan 02)**: SUPERSEDE does not reset the security descriptor and extended attributes — only file data is truncated; metadata leaks across a supersede.
  File: `src/protocol/smb2/smb2_create.c:2015–2019`, `583–600`
  Spec: MS-SMB2 §3.3.5.9.1

- **P2-03 (Plan 02)**: `FILE_COMPLETE_IF_OPLOCKED` accepted but not enforced; the open should complete immediately with `STATUS_OPLOCK_BREAK_IN_PROGRESS` instead of blocking.
  File: `src/protocol/smb2/smb2_create.c:1344`
  Spec: MS-SMB2 §3.3.5.9, CreateOptions 0x00000100

- **P2-04 (Plan 02)**: `FILE_OPEN_REQUIRING_OPLOCK` (0x00010000) defined but never checked; the create should fail with `STATUS_OPLOCK_NOT_GRANTED` if the oplock cannot be atomically granted.
  File: `src/protocol/smb2/smb2_create.c` (no reference)
  Spec: MS-SMB2 §3.3.5.9

### Read / Write (Plan 03)

- **M1 (Plan 03)**: `SMB2_READFLAG_READ_UNBUFFERED` (0x01) never checked; all reads go through the page cache even when the client explicitly requests direct I/O.
  File: `src/protocol/smb2/smb2_read_write.c` (no reference); constant at `src/include/protocol/smb2pdu.h:1006`
  Spec: MS-SMB2 §3.3.5.12 step 4

- **M2 (Plan 03)**: Per-request `SMB2_READFLAG_READ_COMPRESSED` and `SMB2_WRITEFLAG_REQUEST_COMPRESSED` flags never checked; additionally, `smb2_compress_resp` skips all multi-iov responses (`iov_cnt > 2`), so normal buffered READs are never compressed even when negotiated.
  File: `src/protocol/smb2/smb2_read_write.c`; `src/core/smb2_compress.c:496–503`
  Spec: MS-SMB2 §3.3.5.12.1, §3.3.5.13.1

- **M3 (Plan 03)**: `SMB2_WRITEFLAG_WRITE_UNBUFFERED` (0x02) never checked; clients using `FILE_FLAG_NO_BUFFERING` on Windows expect direct-to-storage writes.
  File: `src/protocol/smb2/smb2_read_write.c:883`
  Spec: MS-SMB2 §3.3.5.13

- **M5 (Plan 03)**: `MinimumCount` short-read semantics only partially implemented; blocking retry-until-mincount is absent for all paths; pipe read ignores `mincount` entirely.
  File: `src/protocol/smb2/smb2_read_write.c:477–481`, `530–535`
  Spec: MS-SMB2 §3.3.5.12

- **M7 (Plan 03)**: Named pipe write has no async support; blocking pipe writes hang indefinitely instead of returning `STATUS_PENDING` and completing later.
  File: `src/protocol/smb2/smb2_read_write.c:622–681`
  Spec: MS-SMB2 §3.3.5.13

### Lock / IOCTL (Plan 04)

- **P2-LOCK-01**: Durable handle reconnect does not restore the byte-range lock state held before disconnect.
  File: `src/fs/vfs_cache.c` (reconnect path)
  Spec: MS-SMB2 §3.3.5.5

- **P2-IOCTL-01**: `FSCTL_PIPE_WAIT` unconditionally returns `STATUS_SUCCESS` without waiting; should block for the pipe instance to become available up to the requested timeout.
  File: `src/fs/ksmbd_fsctl_extra.c:567–569`
  Spec: MS-SMB2 §3.3.5.15.9; MS-FSCC §2.3.30

- **P2-IOCTL-04**: `FSCTL_OFFLOAD_READ`/`FSCTL_OFFLOAD_WRITE` (ODX) token table is server-global; tokens from session A can be consumed in session B — cross-session data copy, a security concern.
  File: `src/fs/ksmbd_fsctl.c:1906–1961`
  Spec: MS-FSCC §2.3.53

- **P2-IOCTL-05**: `FSCTL_SET_COMPRESSION` updates `m_fattr` but does not actually compress underlying file data.
  File: `src/fs/ksmbd_fsctl.c:496–544`
  Spec: MS-FSCC §2.3.61

### QueryDirectory / ChangeNotify (Plan 05)

- **P2-01 (Plan 05)**: `SMB2_WATCH_TREE` flag is stored but never applied to the `fsnotify` mark; only direct children are monitored; subtree events are silently missed.
  File: `src/fs/ksmbd_notify.c:640, 674, 829`
  Spec: MS-SMB2 §3.3.5.18

- **P2-02 (Plan 05)**: CHANGE_NOTIFY responses always contain exactly one `FILE_NOTIFY_INFORMATION` entry; multiple pending events are not batched into a single response.
  File: `src/fs/ksmbd_notify.c` (`ksmbd_notify_build_response()` line 118)
  Spec: MS-SMB2 §2.2.36

- **P2-04 (Plan 05)**: `FILE_NOTIFY_CHANGE_CREATION` is mis-mapped to `FS_CREATE` which is already covered by `FILE_NOTIFY_CHANGE_FILE_NAME`; a pure CREATION-only filter will not trigger.
  File: `src/fs/ksmbd_notify.c:854–855`
  Spec: MS-SMB2 §2.2.36

### QueryInfo / SetInfo (Plan 06)

- **GAP-P2-01 (Plan 06)**: `FileStatInformation` (0x46, SMB 3.1.1) — no handler registered; returns `STATUS_INVALID_INFO_CLASS`.
  File: `src/protocol/smb2/smb2_query_set.c` (no handler)
  Spec: MS-FSCC §2.4.47

- **GAP-P2-02 (Plan 06)**: `FileStatLxInformation` (0x47, WSL/POSIX extension) — no handler registered; breaks WSL2 on Windows.
  File: `src/protocol/smb2/smb2_query_set.c` (no handler)
  Spec: MS-FSCC §2.4.48

- **GAP-P2-06 (Plan 06)**: `FileEaInformation.EASize` always returns 0; applications skip EA queries on files that actually have EAs.
  File: `src/protocol/smb2/smb2_query_set.c:774–782`; also `get_file_all_info()` at line 496
  Spec: MS-FSCC §2.4.13

- **GAP-P2-05 (Plan 06)**: `FilePosixInformation.ReparseTag` only uses `smb2_get_reparse_tag_special_file()`; never reads the `XATTR_NAME_REPARSE_DATA` xattr — files with xattr-backed reparse points show `ReparseTag = 0`.
  File: `src/protocol/smb2/smb2_query_set.c:1085–1086`

### SMB3 Advanced (Plan 07)

- **M2 (Plan 07)**: Chained compression (`SMB2_COMPRESSION_FLAG_CHAINED`) causes a connection abort rather than a graceful protocol rejection.
  File: `src/core/smb2_compress.c:320–323`
  Spec: MS-SMB2 §2.2.42.2

- **M5 (Plan 07)**: No per-channel nonce counter for AES-GCM encryption; two concurrent sends on different multichannel connections sharing the same session key may reuse nonces.
  File: `src/mgmt/user_session.h:27–30`; `src/core/auth.c:1307–1333`
  Spec: MS-SMB2 §3.1.4.3

- **M7 (Plan 07)**: Durable handle timeout/survival mechanism across TCP disconnect requires verification; `fp->durable_timeout` is set but the "keep ksmbd_file alive after session teardown" path is unconfirmed.
  File: `src/mgmt/user_session.c`; `src/fs/vfs_cache.c`
  Spec: MS-SMB2 §3.3.5.9

---

## P3 Partial Implementations

### Plan 01

- **P3-01**: SMB 3.1.1 pre-authentication integrity — the final SESSION_SETUP *response* PDU is not hashed before signing/encryption key derivation; may differ from strict spec-compliant clients.
  File: `src/protocol/smb2/smb2_session.c:720`; `src/core/auth.c:1350–1378`

- **P3-02**: Compression contexts — LZNT1, LZ77, LZ77+Huffman are gracefully declined but chaining (`Flags` bit 0) is never offered; chaining flag hardcoded to 0.
  File: `src/protocol/smb2/smb2_negotiate.c:395–415`, `smb2_negotiate.c:92`

- **P3-03**: TREE_CONNECT `EXTENSION_PRESENT` path: `TreeConnectContextOffset` / `TreeConnectContextCount` never parsed; remoted identity context silently dropped.
  File: `src/protocol/smb2/smb2_tree.c:138–155`
  Spec: MS-SMB2 §2.2.9.1

- **P3-04**: `SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT` and `REDIRECT_TO_OWNER` flags never acted upon; `SMB2_SHARE_CAP_REDIRECT_TO_OWNER` never set in response.
  File: `src/protocol/smb2/smb2_tree.c:244–252`

- **P3-05**: TREE_DISCONNECT does not wait for in-flight async operations on the tree to drain before sending the response.
  File: `src/protocol/smb2/smb2_tree.c:311–363`

- **P3-06**: `SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY` is set without `SMB2_SHARE_CAP_CLUSTER`; MS-SMB2 §2.2.10 expects both bits together for a clustered CA share.
  File: `src/protocol/smb2/smb2_tree.c:246–252`

- **P3-07**: SESSION re-authentication on a `SMB2_SESSION_VALID` session returns 0 without updating signing/encryption keys — security concern if password changed.
  File: `src/protocol/smb2/smb2_session.c:361–367`

### Plan 02

- **P3-01 (Plan 02)**: CLOSE does not validate `PersistentFileId` — only `VolatileFileId` is checked; durable-handle PersistentFileId mismatch goes undetected.
  File: `src/protocol/smb2/smb2_misc_cmds.c:162, 173`

- **P3-03 (Plan 02)**: `FILE_OPEN_FOR_BACKUP_INTENT` accepted but does not grant privilege bypass — backup software gets `STATUS_ACCESS_DENIED` on files it should be able to open.
  File: `src/protocol/smb2/smb2_create.c` (no implementation beyond mask check)

- **P3-04 (Plan 02)**: `FILE_SYNCHRONOUS_IO_ALERT` / `FILE_SYNCHRONOUS_IO_NONALERT` should be rejected with `STATUS_INVALID_PARAMETER` for SMB2; currently silently accepted.
  File: `src/protocol/smb2/smb2_create.c:1344`

### Plan 03

- **P1 (Plan 03)**: RDMA `RDMA_V1_INVALIDATE` only stores and invalidates the first descriptor's token; multi-descriptor RDMA buffers invalidate only the first key.
  File: `src/protocol/smb2/smb2_read_write.c:315–319`

- **P2 (Plan 03)**: READ response compression always skipped because `smb2_compress_resp` bails when `iov_cnt > 2` — normal buffered reads always have 3 iovs.
  File: `src/core/smb2_compress.c:496–503`

- **P6 (Plan 03)**: Named pipe READ: `DataRemaining` always set to 0 even in `STATUS_BUFFER_OVERFLOW` case; client cannot determine how much more data is in the pipe.
  File: `src/protocol/smb2/smb2_read_write.c:280`

### Plan 04

- **P3-LOCK-01**: `smb2_wait_for_posix_lock` does not propagate `-EINTR` from the VFS lock wait; silently retries instead of returning an error.
  File: `src/protocol/smb2/smb2_lock.c:246–267`

- **P3-LOCK-02**: Zero-length lock ranges are skipped at the VFS level; ksmbd-internal conflict check is the only gate — OS-level locks are not involved.
  File: `src/protocol/smb2/smb2_lock.c:830–833`

- **P3-IOCTL-01**: `FSCTL_MARK_HANDLE` ignores the `MARK_HANDLE_INFO` input; `UsnSourceInfo` and `CopyNumber` fields never processed.
  File: `src/fs/ksmbd_fsctl.c:1315–1333`

- **P3-IOCTL-02**: `FSCTL_QUERY_FILE_REGIONS` always returns one region covering the entire range; does not use `llseek(SEEK_DATA/SEEK_HOLE)` for sparse files.
  File: `src/fs/ksmbd_fsctl.c:1736–1797`

- **P3-IOCTL-04**: `FSCTL_OFFLOAD_READ` ignores `TokenTimeToLive`; tokens accumulate indefinitely in kernel memory.
  File: `src/fs/ksmbd_fsctl.c:2009–2088`

- **P3-IOCTL-05**: `FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX` ignores the `ATOMIC` flag; falls back to non-atomic copy without returning `STATUS_NOT_SUPPORTED`.
  File: `src/fs/ksmbd_fsctl.c:1235–1307`

### Plan 05

- **P3-01 (Plan 05)**: DOS wildcard characters `<` (DOS_STAR), `>` (DOS_QM), `"` (DOS_DOT) not implemented in `match_pattern()`; acknowledged via in-source TODO comment.
  File: `src/core/misc.c:21–71`

- **P3-02 (Plan 05)**: `EaSize` in `FileFullDirectoryInformation` / `FileIdFullDirectoryInformation` only reports the reparse tag for reparse-point files; for files with EAs and no reparse point, `EaSize` is always 0.
  File: `src/protocol/smb2/smb2_dir.c:301–304`

- **P3-05 (Plan 05)**: Piggyback CHANGE_NOTIFY completion re-reads `output_buf_len` from the original `work->request_buf` which may be freed after connection reset — potential use-after-free.
  File: `src/fs/ksmbd_notify.c:316–319`

### Plan 06

- **PARTIAL-P3-01 (Plan 06)**: `SACL_SECINFO` query returns empty SACL (0 ACEs); stored NTSD xattr SACL ACEs are not extracted and returned.
  File: `src/fs/smbacl.c:1355–1372`

- **PARTIAL-P3-04 (Plan 06)**: `SL_RETURN_SINGLE_ENTRY` flag logged but not enforced in `FileFullEaInformation`; all EA entries are returned regardless.
  File: `src/protocol/smb2/smb2_query_set.c:215–219`

- **PARTIAL-P3-05 (Plan 06)**: `FileHardLinkInformation` returns only the current file's own path with `EntriesReturned = 1`; does not enumerate all hard links to the inode.
  File: `src/fs/ksmbd_info.c:484–545`

- **PARTIAL-P3-06 (Plan 06)**: `FileCaseSensitiveInformation` SET validates the flag but does not apply `FS_CASEFOLD_FL` to the inode.
  File: `src/fs/ksmbd_info.c:1011–1030`

- **PARTIAL-P3-08 (Plan 06)**: `FileCompressionInformation.CompressedFileSize` uses `stat.blocks << 9` (raw allocation blocks) instead of the actual compressed byte count.
  File: `src/protocol/smb2/smb2_query_set.c:823`

- **PARTIAL-P3-10 (Plan 06)**: `FileFsSizeInformation` reports `SectorsPerAllocationUnit = 1` and `BytesPerSector = f_bsize` (typically 4096); Windows tools expect `BytesPerSector = 512` and a cluster factor — causes incorrect free-space display.
  File: `src/protocol/smb2/smb2_query_set.c:1422–1423`, `1438–1439`

### Plan 07

- **P1 (Plan 07 / Multichannel)**: Session binding is architecturally present; per-channel encryption state (nonce counter) is missing; nonce reuse risk under concurrent sends on different channels.
  File: `src/protocol/smb2/smb2_session.c:572–636`

- **P2 (Plan 07 / Lease v2)**: Directory lease infrastructure present; parent-lease-break trigger completeness unverified.
  File: `src/fs/oplock.c:101–123`

- **P4 (Plan 07 / Encryption)**: Four cipher types negotiated and encrypt/decrypt paths present; per-tree enforcement absent (see P1 B5); nonce derivation fragile under multichannel.
  File: `src/protocol/smb2/smb2_negotiate.c:301–340`

- **P7 (Plan 07 / OplockBreak)**: Oplock and lease break paths present; lease-break acknowledgment LeaseKey match verification needs confirmation.
  File: `src/protocol/smb2/smb2_misc_cmds.c:250–558`

---

## P4 Low Priority

Selected low-priority items across all plans:

- **P4-02 (Plan 01)**: SMB 2.0 does not add `SMB2_GLOBAL_CAP_DFS` even when DFS is enabled. File: `src/protocol/smb2/smb2ops.c:20`
- **P4-03 (Plan 01)**: Compression chaining `Flags` bit always 0. File: `src/protocol/smb2/smb2_negotiate.c:92`
- **P4-03 (Plan 02)**: CREATE response context chain: last context `Next` field may not be explicitly zeroed. File: `src/protocol/smb2/smb2_create.c:2383–2388`
- **P4-IOCTL-01 (Plan 04)**: Legacy `smb2_ioctl.c` `switch(cnt_code)` block is dead code but still compiled — maintenance risk. File: `src/protocol/smb2/smb2_ioctl.c:533–769`
- **P4-IOCTL-02 (Plan 04)**: `FSCTL_PIPE_PEEK` returns `NamedPipeState = 0` which is not a valid state value; must be 1–4. File: `src/fs/ksmbd_fsctl.c:614–632`
- **P4-IOCTL-03 (Plan 04)**: `FSCTL_VALIDATE_NEGOTIATE_INFO` response zeroes the `ServerGuid` field instead of returning the server's GUID. File: `src/fs/ksmbd_fsctl.c:1538`
- **P4-06 (Plan 05)**: Directory scan limit of 100,000 entries emits `STATUS_NO_MORE_FILES` even when matching entries exist beyond that point. File: `src/protocol/smb2/smb2_dir.c:1199–1206`
- **L3 (Plan 03)**: Credit charge vs. payload size not validated; client can charge 1 credit for a 4 MB read, inflating its credit balance. File: `src/protocol/smb2/smb2_pdu_common.c:387–403`
- **L2 (Plan 07)**: LZNT1/LZ77/LZ77+Huffman compression algorithms are stubs; these are the original MS-SMB2 §2.2.3.1.3 mandated algorithms. File: `src/core/smb2_compress.c:234–240`
- **P4-05 (Plan 06)**: `FileRenameInformation.RootDirectory` field is non-zero in the spec but is never read; only absolute share paths are processed. File: `src/protocol/smb2/smb2_query_set.c:1839–1912`

---

## Implementation Roadmap

### Phase 1 — P1 Critical Bugs — **COMPLETE** (Wave 1, 2026-03-02)

All 24 Phase 1 items were implemented in Wave 1 (commit `bc5ef70`). Items included:

- FSCTL_QUERY_NETWORK_INTERFACE_INFO opcode + LinkSpeed unit fix
- SMB2_GLOBAL_CAP_ENCRYPTION for SMB 3.1.1
- Per-tree and per-session encryption enforcement (with connection disconnect)
- FileIdInformation 24-byte struct with VolumeSerialNumber
- FileStreamInformation StreamSize from actual xattr value
- DH2Q persistent-handle STATUS_INVALID_PARAMETER on non-CA share
- SESSION_SETUP encrypt flag enforcement
- ServerGUID persistence (random UUID4 at init)
- ServerStartTime in NEGOTIATE response
- LOGOFF STATUS_USER_SESSION_DELETED fix
- TWrp snapshot path lifetime fix (opens historical snapshot)
- FLUSH on named pipe returns STATUS_NOT_SUPPORTED
- FILE_OPEN_BY_FILE_ID enabled
- Cancelled lock: proper final STATUS_CANCELLED response
- COPYCHUNK off-by-one corrected
- Dead FSCTL_GET_REPARSE_POINT handler removed
- Named pipe write error-path return code fixed
- SMB2_INDEX_SPECIFIED + FileIndex in QUERY_DIRECTORY
- STATUS_NO_SUCH_FILE / STATUS_NO_MORE_FILES gating fixed
- SMB2_REOPEN closes and reopens directory handle
- CHANGE_NOTIFY event coalescing (multi-entry responses)
- VALIDATE_NEGOTIATE_INFO returns real ServerGUID + disconnects on mismatch
- Lock-sequence 5-bug fix (bit extraction, replay, array size, sentinel, ordering)
- Async cancel path fixed for compound CHANGE_NOTIFY work (Wave 2)

---

### Phase 2 — P2 High-Interop Features (estimated 4–6 weeks)

Grouped by subsystem:

**Authentication / session:**
- Check and enforce `SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA` (overlaps Phase 1 above).
- Add NETNAME context validation (P2-01, Plan 01).
- Fix re-authentication to regenerate signing/encryption keys (P3-07, Plan 01).
- Fix PAI final hash: fold response PDU before key derivation (P3-01, Plan 01).

**I/O paths:**
- Implement `SMB2_READFLAG_READ_UNBUFFERED` via O_DIRECT (M1, Plan 03).
- Implement `SMB2_WRITEFLAG_WRITE_UNBUFFERED` (M3, Plan 03).
- Implement per-request compression flags M2 (Plan 03); fix multi-iov compress skip.
- Fix named pipe DataRemaining in READ overflow response (P6, Plan 03).
- Implement async named pipe write (M7, Plan 03).

**Directory / notify:**
- Implement `SMB2_WATCH_TREE` recursive monitoring (P2-01, Plan 05).
- Fix DOS wildcard characters `<`, `>`, `"` in `match_pattern()` (P3-01, Plan 05).
- Fix FileIndex population in directory entries (P1-02, Plan 05).

**QueryInfo / SetInfo:**
- Add `FileStatInformation` (0x46) handler (GAP-P2-01, Plan 06).
- Add `FileStatLxInformation` (0x47) handler for WSL2 (GAP-P2-02, Plan 06).
- Implement real `EaSize` computation (GAP-P2-06, Plan 06).
- Fix `FilePosixInformation.ReparseTag` to read xattr (GAP-P2-05, Plan 06).

**Create:**
- Implement `FILE_OPEN_REPARSE_POINT` (P2-01, Plan 02).
- Implement SUPERSEDE full metadata reset (P2-02, Plan 02).
- Implement `FILE_COMPLETE_IF_OPLOCKED` (P2-03, Plan 02) and `FILE_OPEN_REQUIRING_OPLOCK` (P2-04, Plan 02).
- Compute real `MaximalAccess` from filesystem permissions (P2-03, Plan 01).

**FSCTL / locking:**
- Implement real `FSCTL_PIPE_WAIT` wait semantics (P2-IOCTL-01, Plan 04).
- Scope ODX token table per session (P2-IOCTL-04, Plan 04).
- Restore byte-range locks on durable handle reconnect (P2-LOCK-01, Plan 04).

**SMB3:**
- Fix chained-compression graceful rejection (M2, Plan 07).
- Add per-channel nonce counter for AES-GCM (M5, Plan 07).
- Verify and fix durable handle survival across TCP disconnect (M6, Plan 07).

**Effort estimate:** ~200–280 person-hours.

---

### Phase 3 — P3 Medium-Priority (estimated 3–4 weeks)

- Close PersistentFileId validation gap in CLOSE (P3-01, Plan 02).
- Fix `FILE_OPEN_FOR_BACKUP_INTENT` privilege handling (P3-03, Plan 02).
- Fix RDMA multi-descriptor invalidation (P1, Plan 03).
- Fix READ multi-iov compression block (P2, Plan 03).
- Fix `smb2_wait_for_posix_lock` `-EINTR` propagation (P3-LOCK-01, Plan 04).
- Fix `FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX` ATOMIC flag (P3-IOCTL-05, Plan 04).
- Implement `FSCTL_OFFLOAD_READ` TTL expiry (P3-IOCTL-04, Plan 04).
- Fix `FSCTL_QUERY_FILE_REGIONS` to use `SEEK_DATA`/`SEEK_HOLE` for sparse files (P3-IOCTL-02, Plan 04).
- Enforce `SL_RETURN_SINGLE_ENTRY` in EA query (PARTIAL-P3-04, Plan 06).
- Enumerate all hard links in `FileHardLinkInformation` (PARTIAL-P3-05, Plan 06).
- Implement `FileCaseSensitiveInformation` SET via `FS_IOC_SETFLAGS` (PARTIAL-P3-06, Plan 06).
- Fix piggyback CHANGE_NOTIFY use-after-free risk (P3-05, Plan 05).
- Return `SACL_SECINFO` ACEs from the stored NTSD xattr (PARTIAL-P3-01, Plan 06).
- Fix TREE_CONNECT extension context parsing (P3-03, Plan 01).
- Fix `FileFsSizeInformation` sector/cluster reporting (PARTIAL-P3-10, Plan 06).
- Verify oplock-break lease-key match in acknowledgment (P7, Plan 07).
- Verify durable handle lifetime management end-to-end (P3, Plan 07).

**Effort estimate:** ~80–120 person-hours.

---

### Phase 4 — P4 Low Priority / Aspirational (ongoing, no fixed timeline)

- Implement LZNT1 / LZ77 / LZ77+Huffman compression (L2, Plan 07).
- Implement chained compression (L3, Plan 07).
- Add credit-charge vs. payload-size validation (L3, Plan 03).
- Replace userspace QUIC proxy with native in-kernel QUIC/TLS 1.3 when kernel support arrives (L1, Plan 07).
- Add PRINT share type support (P2-04, Plan 01).
- Remove dead legacy IOCTL switch block (P4-IOCTL-01, Plan 04).
- Fix `FSCTL_PIPE_PEEK` `NamedPipeState` (P4-IOCTL-02, Plan 04).
- Fix `FileRenameInformation.RootDirectory` handling (P4-05, Plan 06).
- Fix 100k directory scan limit status code (P4-06, Plan 05).
- Implement `FileFsDataCopyInformation` (GAP-P2-03, Plan 06) and `FileFsMetadataSizeInformation` (GAP-P2-04).
- Witness protocol (MS-SWN) full integration (L5, Plan 07).
- Advertise `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` for SMB 3.0 (M7, Plan 07).
- Implement non-standard info-class negotiation gate (P4-01, Plan 05).

---

*Generated from a full audit of all seven SMB2 plan files. Bug IDs in this index
use the original IDs from each plan file; where the same ID prefix appears in
multiple plans, the plan number is appended in parentheses for disambiguation.*
