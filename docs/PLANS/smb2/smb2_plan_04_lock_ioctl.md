# SMB2 Plan 04: Lock / IOCTL-FSCTL

**Audit date:** 2026-03-01
**Spec references:** MS-SMB2 §2.2.26/27/31/32, §3.3.5.14/15; MS-FSCC

---

## Current State Summary

### SMB2 LOCK

The LOCK handler (`src/protocol/smb2/smb2_lock.c`) is largely correct. It handles
all four flag combinations, supports the async blocking-lock pattern with
STATUS_PENDING, implements rollback on partial failure, has zero-length lock
range semantics, and correctly clamps high-offset (>2^63) ranges to avoid POSIX
overflow. A lock-sequence idempotency mechanism targeting resilient/durable handles
was added but contains one correctness bug in the bit-field parsing and one
semantic gap for normal (non-durable) handles.

### SMB2 IOCTL/FSCTL

The IOCTL handler (`src/protocol/smb2/smb2_ioctl.c`) routes all calls first through
a pluggable RCU hash-table dispatch (`src/fs/ksmbd_fsctl.c`) and falls through to a
set of inline legacy handlers for a handful of codes. Additional FSCTL codes are
registered by separate subsystems at module init time (DFS, Reparse, VSS, Resilient,
Extra). The architecture is sound. Coverage of the forty-plus FSCTL codes in the
MS-SMB2/MS-FSCC specification is wide but not complete. Errors exist in several
stub implementations.

---

## Complete FSCTL Handler Inventory

### Registered in `builtin_fsctl_handlers[]` (`src/fs/ksmbd_fsctl.c:2354-2641`)

| Code       | FSCTL name                          | Handler                                        | Quality |
|------------|-------------------------------------|------------------------------------------------|---------|
| 0x0009009C | FSCTL_GET_OBJECT_ID                 | `fsctl_get_object_id_handler` (line 318)       | good    |
| 0x00090098 | FSCTL_SET_OBJECT_ID                 | `fsctl_set_object_id_handler` (line 377)       | good    |
| 0x000900A0 | FSCTL_DELETE_OBJECT_ID              | `fsctl_delete_object_id_handler` (line 399)    | good    |
| 0x000900BC | FSCTL_SET_OBJECT_ID_EXTENDED        | `fsctl_set_object_id_extended_handler` (line 388) | stub — accepts first 16 bytes only, ignores BirthId/ExtInfo fields |
| 0x000900C0 | FSCTL_CREATE_OR_GET_OBJECT_ID       | `fsctl_create_or_get_object_id_handler` (line 296) | good |
| 0x0009003C | FSCTL_GET_COMPRESSION               | `fsctl_get_compression_handler` (line 435)     | good    |
| 0x0009C040 | FSCTL_SET_COMPRESSION               | `fsctl_set_compression_handler` (line 496)     | partial — updates m_fattr only, no actual FS compression |
| 0x001401FC | FSCTL_QUERY_NETWORK_INTERFACE_INFO  | `fsctl_query_network_interface_info_handler` (line 819) | good |
| 0x00140078 | FSCTL_REQUEST_RESUME_KEY            | `fsctl_request_resume_key_handler` (line 934)  | good    |
| 0x000900C4 | FSCTL_SET_SPARSE                    | `fsctl_set_sparse_handler` (line 1335)         | good    |
| 0x001440F2 | FSCTL_COPYCHUNK (FSCTL_SRV_COPYCHUNK) | `fsctl_copychunk_handler` (line 1089)        | good    |
| 0x001480F2 | FSCTL_COPYCHUNK_WRITE               | `fsctl_copychunk_write_handler` (line 1119)    | good    |
| 0x00098344 | FSCTL_DUPLICATE_EXTENTS_TO_FILE     | `fsctl_duplicate_extents_handler` (line 1149)  | good    |
| 0x000980C8 | FSCTL_SET_ZERO_DATA                 | `fsctl_set_zero_data_handler` (line 1372)      | good    |
| 0x000940CF | FSCTL_QUERY_ALLOCATED_RANGES        | `fsctl_query_allocated_ranges_handler` (line 1433) | good |
| 0x0009002C | FSCTL_IS_PATHNAME_VALID             | `fsctl_is_pathname_valid_handler` (line 546)   | stub/noop — always returns success |
| 0x00090078 | FSCTL_IS_VOLUME_DIRTY               | `fsctl_is_volume_dirty_handler` (line 557)     | good (always reports clean) |
| 0x00090083 | FSCTL_ALLOW_EXTENDED_DASD_IO        | `fsctl_stub_noop_success_handler`              | stub    |
| 0x000900DB | FSCTL_ENCRYPTION_FSCTL_IO           | `fsctl_stub_noop_success_handler`              | stub    |
| 0x00090060 | FSCTL_FILESYSTEM_GET_STATISTICS     | `fsctl_filesystem_get_stats_handler` (line 1637) | partial — zero counters |
| 0x0009008F | FSCTL_FIND_FILES_BY_SID             | `fsctl_not_supported_handler`                  | not supported (honest) |
| 0x00090064 | FSCTL_GET_NTFS_VOLUME_DATA          | `fsctl_get_ntfs_volume_data_handler` (line 651) | partial |
| 0x00090073 | FSCTL_GET_RETRIEVAL_POINTERS        | `fsctl_get_retrieval_pointers_handler` (line 735) | stub (1 extent) |
| 0x001400E8 | FSCTL_LMR_GET_LINK_TRACK_INF        | `fsctl_not_supported_handler`                  | not supported |
| 0x001400EC | FSCTL_LMR_SET_LINK_TRACK_INF        | `fsctl_stub_noop_success_handler`              | stub    |
| 0x00090018 | FSCTL_LOCK_VOLUME                   | `fsctl_stub_noop_success_handler`              | stub    |
| 0x0011400C | FSCTL_PIPE_PEEK                     | `fsctl_pipe_peek_handler` (line 614)           | stub/zeroed |
| 0x00090058 | FSCTL_QUERY_FAT_BPB                 | `fsctl_not_supported_handler`                  | not supported |
| 0x00090138 | FSCTL_QUERY_SPARING_INFO            | `fsctl_not_supported_handler`                  | not supported |
| 0x000900EB | FSCTL_READ_FILE_USN_DATA            | `fsctl_not_supported_handler`                  | not supported |
| 0x000900E3 | FSCTL_READ_RAW_ENCRYPTED            | `fsctl_not_supported_handler`                  | not supported |
| 0x00090117 | FSCTL_RECALL_FILE                   | `fsctl_not_supported_handler`                  | not supported |
| 0x00090008 | FSCTL_REQUEST_BATCH_OPLOCK          | `fsctl_stub_noop_success_handler`              | stub    |
| 0x0009008C | FSCTL_REQUEST_FILTER_OPLOCK         | `fsctl_stub_noop_success_handler`              | stub    |
| 0x00090000 | FSCTL_REQUEST_OPLOCK_LEVEL_1        | `fsctl_stub_noop_success_handler`              | stub    |
| 0x00090004 | FSCTL_REQUEST_OPLOCK_LEVEL_2        | `fsctl_stub_noop_success_handler`              | stub    |
| 0x00098134 | FSCTL_SET_DEFECT_MANAGEMENT         | `fsctl_not_supported_handler`                  | not supported |
| 0x000900D7 | FSCTL_SET_ENCRYPTION                | `fsctl_set_encryption_handler` (line 1694)     | not supported (honest) |
| 0x000901B4 | FSCTL_SET_SHORT_NAME_BEHAVIOR       | `fsctl_stub_noop_success_handler`              | stub    |
| 0x00090194 | FSCTL_SET_ZERO_ON_DEALLOC           | `fsctl_set_zero_on_dealloc_handler` (line 1668) | stub (validates handle, returns OK) |
| 0x00090100 | FSCTL_SIS_COPYFILE                  | `fsctl_not_supported_handler`                  | not supported |
| 0x0009C104 | FSCTL_SIS_LINK_FILES                | `fsctl_not_supported_handler`                  | not supported |
| 0x0009001C | FSCTL_UNLOCK_VOLUME                 | `fsctl_stub_noop_success_handler`              | stub    |
| 0x000900DF | FSCTL_WRITE_RAW_ENCRYPTED           | `fsctl_not_supported_handler`                  | not supported |
| 0x000900EF | FSCTL_WRITE_USN_CLOSE_RECORD        | `fsctl_not_supported_handler`                  | not supported |
| 0x00140204 | FSCTL_VALIDATE_NEGOTIATE_INFO       | `fsctl_validate_negotiate_info_handler` (line 1496) | good |
| 0x0011C017 | FSCTL_PIPE_TRANSCEIVE               | `fsctl_pipe_transceive_handler` (line 1556)    | good    |
| 0x00090284 | FSCTL_QUERY_FILE_REGIONS            | `fsctl_query_file_regions_handler` (line 1736) | partial (1-region stub) |
| 0x0009027C | FSCTL_GET_INTEGRITY_INFORMATION     | `fsctl_get_integrity_info_handler` (line 1818) | partial (zeroed) |
| 0x0009C280 | FSCTL_SET_INTEGRITY_INFORMATION     | `fsctl_set_integrity_info_handler` (line 1851) | stub/noop |
| 0x00090380 | FSCTL_SET_INTEGRITY_INFORMATION_EX  | `fsctl_set_integrity_info_handler`             | stub/noop |
| 0x000983E8 | FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX  | `fsctl_duplicate_extents_ex_handler` (line 1235) | partial |
| 0x000900FC | FSCTL_MARK_HANDLE                   | `fsctl_mark_handle_handler` (line 1315)        | stub (handle validation only) |
| 0x00094264 | FSCTL_OFFLOAD_READ                  | `fsctl_offload_read_handler` (line 2009)       | partial |
| 0x00098268 | FSCTL_OFFLOAD_WRITE                 | `fsctl_offload_write_handler` (line 2101)      | partial |
| 0x001441BB | FSCTL_SRV_READ_HASH                 | `fsctl_srv_read_hash_handler` (line 2302)      | partial |
| 0x009013C0 | FSCTL_QUERY_ON_DISK_VOLUME_INFO     | `fsctl_not_supported_handler`                  | not supported |

### Registered by separate subsystems (registered at module init)

| Code       | FSCTL name                          | File                           | Handler                       |
|------------|-------------------------------------|--------------------------------|-------------------------------|
| 0x00060194 | FSCTL_DFS_GET_REFERRALS             | `src/fs/ksmbd_dfs.c:453`       | `ksmbd_dfs_get_referrals`     |
| 0x000601B0 | FSCTL_DFS_GET_REFERRALS_EX          | `src/fs/ksmbd_dfs.c:459`       | `ksmbd_dfs_get_referrals_ex`  |
| 0x000900A4 | FSCTL_SET_REPARSE_POINT             | `src/fs/ksmbd_reparse.c:1152`  | `ksmbd_fsctl_set_reparse_point` |
| 0x000900A8 | FSCTL_GET_REPARSE_POINT             | `src/fs/ksmbd_reparse.c:1158`  | `ksmbd_fsctl_get_reparse_point` |
| 0x000900AC | FSCTL_DELETE_REPARSE_POINT          | `src/fs/ksmbd_reparse.c:1164`  | `ksmbd_fsctl_delete_reparse_point` |
| 0x00144064 | FSCTL_SRV_ENUMERATE_SNAPSHOTS       | `src/fs/ksmbd_vss.c:703`       | `ksmbd_vss_enumerate_snapshots` |
| 0x001401D4 | FSCTL_LMR_REQUEST_RESILIENCY        | `src/fs/ksmbd_resilient.c:110` | `ksmbd_fsctl_request_resiliency` |
| 0x00110018 | FSCTL_PIPE_WAIT                     | `src/fs/ksmbd_fsctl_extra.c:610` | `ksmbd_fsctl_pipe_wait`      |
| 0x00098208 | FSCTL_FILE_LEVEL_TRIM               | `src/fs/ksmbd_fsctl_extra.c`   | registered via extra init     |

### Handled in smb2_ioctl.c legacy switch (before ksmbd_fsctl migration, now duplicated as fallback)

`smb2_ioctl.c` lines 533-770 still contain a `switch(cnt_code)` that handles:
`FSCTL_QUERY_NETWORK_INTERFACE_INFO`, `FSCTL_REQUEST_RESUME_KEY`,
`FSCTL_COPYCHUNK`, `FSCTL_COPYCHUNK_WRITE`, `FSCTL_SET_SPARSE`,
`FSCTL_SET_ZERO_DATA`, `FSCTL_QUERY_ALLOCATED_RANGES`, `FSCTL_GET_REPARSE_POINT`
(shadowed legacy), `FSCTL_DUPLICATE_EXTENTS_TO_FILE`. These are only reached when
`ksmbd_dispatch_fsctl` returns `-EOPNOTSUPP`, which should never happen for the
above codes since they are all registered. The legacy paths are dead code.

### FSCTL codes from the audit list not registered anywhere

| Code       | FSCTL name                          | Status                          |
|------------|-------------------------------------|---------------------------------|
| 0x00090035 | FSCTL_REQUEST_OPLOCK (MS-RSVD)      | Not defined; MS-RSVD uses different codes. Not implemented. |
| FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT (0x00090300) | MS-RSVD | Not implemented |
| FSCTL_SVHDX_SYNC_TUNNEL_REQUEST (0x00090304) | MS-RSVD | Not implemented |
| FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST (0x00090364) | MS-RSVD | Not implemented |

---

## Confirmed Bugs (P1)

### P1-LOCK-01: LockSequenceNumber field bit-field comment is wrong — code uses different layout than spec

**File:** `src/include/protocol/smb2pdu.h:1259-1265`, `src/protocol/smb2/smb2_lock.c:406-408`

MS-SMB2 §3.3.5.14 specifies the `LockSequenceNumber` field as:
- Bits 0-3: `LockSequenceNumber` (4-bit sequence value)
- Bits 4-31: `LockSequenceIndex` (28-bit index, valid range 1-64)

The header comment at line 1261-1262 says:
```
* Bits 28-31: LockSequenceNumber (4 bits)
* Bits 24-27: LockSequenceIndex (4 bits)
```
This is wrong (it describes only 4 bits for the index, not 28). However, the code at
`smb2_lock.c:407-408` does the correct extraction:
```c
u8 seq_num = val & 0xF;               /* Low 4 bits */
u32 seq_idx = (val >> 4) & 0xFFFFFFF; /* Upper 28 bits */
```
So the implementation is correct but the struct comment is dangerously misleading.
Additionally, `check_lock_sequence()` only activates for `is_resilient || is_durable
|| is_persistent` handles (`smb2_lock.c:419`). MS-SMB2 §3.3.5.14 states that the
server MUST track the lock sequence for all oplock-capable handles with the sequence
mechanism, not only for durable/resilient. While durable/resilient is the practical
case where retransmits occur, the spec does not limit the tracking to these handle types.

**Impact:** The struct comment is wrong and will mislead future developers. The
gating condition may silently fail to detect replays on plain persistent handles that
are not marked `is_durable`.

---

### P1-LOCK-02: Cancelled blocking lock sends STATUS_CANCELLED then sets send_no_response — client gets no final response

**File:** `src/protocol/smb2/smb2_lock.c:899-905`

```c
if (work->state == KSMBD_WORK_CANCELLED) {
    rsp->hdr.Status = STATUS_CANCELLED;
    kfree(smb_lock);
    smb2_send_interim_resp(work, STATUS_CANCELLED);
    work->send_no_response = 1;
    goto out;
}
```
Per MS-SMB2 §3.3.5.14, when a blocking lock is cancelled the server MUST send a
final error response (not a second interim). Here the code calls
`smb2_send_interim_resp(work, STATUS_CANCELLED)` — using the interim-response path —
then sets `send_no_response = 1` which suppresses the regular final response. This
means the client receives a second interim-style message instead of the required
final SMB2 LOCK response with `STATUS_CANCELLED`. The `smb2_send_interim_resp` path
sets `SMB2_FLAGS_ASYNC_COMMAND` in the response header, which is the wrong flag for
a final error response.

**Impact:** Windows clients may not correctly handle the cancel acknowledgement.

---

### P1-IOCTL-01: FSCTL_QUERY_NETWORK_INTERFACE_INFO code mismatch

**File:** `src/include/protocol/smbfsctl.h:78`

```c
#define FSCTL_QUERY_NETWORK_INTERFACE_INFO 0x001401FC
```

MS-SMB2 §2.2.31.4 defines `FSCTL_QUERY_NETWORK_INTERFACE_INFO` as `0x001400FC`.
The codebase uses `0x001401FC` (byte 2 differs: `01` vs `00`). This means clients
sending the correct code `0x001400FC` will receive `STATUS_INVALID_DEVICE_REQUEST`
instead of a network interface list. Interoperability with Linux kernel SMB3 client
(`cifs.ko`) and Windows is broken for multi-channel negotiation.

**Impact:** Multi-channel SMB3 connections may fail to enumerate network interfaces,
preventing channel aggregation.

---

### P1-IOCTL-02: `FSCTL_GET_REPARSE_POINT` duplicate/shadow in legacy switch

**File:** `src/protocol/smb2/smb2_ioctl.c:670-688`

The legacy switch at line 670 handles `FSCTL_GET_REPARSE_POINT` by returning a
single `reparse_data_buffer` with `ReparseDataLength = 0` and an inferred tag
from the inode mode. Meanwhile, `ksmbd_reparse.c` registers a full implementation
via `ksmbd_fsctl_get_reparse_point` in the hash table. Since the hash-table lookup
happens first (`smb2_ioctl.c:526-529`) and succeeds, the legacy path is dead code.
However, the legacy stub is still visible and might mislead anyone patching or
rebasing. More critically, the old legacy handler at line 670-688 is incorrect
(empty ReparseDataLength) — if somehow reached, it would violate MS-SMB2 §3.3.5.15.

---

### P1-IOCTL-03: FSCTL_COPYCHUNK chunk_count boundary check is off-by-one

**File:** `src/fs/ksmbd_fsctl.c:997`, `src/protocol/smb2/smb2_ioctl.c:96`

```c
if (chunk_count >= ksmbd_server_side_copy_max_chunk_count() ||
```
Both `fsctl_copychunk_common` (line 997) and the legacy `fsctl_copychunk` (line 96)
use `>=` against the max chunk count. This rejects exactly `max_chunk_count` chunks,
which should be valid. MS-FSCC §2.3.12 says the server MUST return
`STATUS_INVALID_PARAMETER` when `ChunkCount` exceeds the server's maximum. The
check should be `> max_chunk_count`. Currently the response when ChunkCount ==
max_chunk_count is `STATUS_INVALID_PARAMETER` where the correct response is to
process the request.

---

## Missing Features (P2)

### P2-LOCK-01: Durable handle reconnect does not restore byte-range lock state

**Files:** `src/fs/vfs_cache.c` (reconnect path)

MS-SMB2 §3.3.5.5 (durable reconnect) requires that byte-range locks held before
the disconnect be preserved or re-acquired after reconnect. The ksmbd durable
reconnect logic preserves the file handle but does not iterate `fp->lock_list` and
re-register held locks with the kernel POSIX lock manager after reconnect. This
means locks silently disappear after a durable reconnect, violating the protocol
guarantee.

---

### P2-LOCK-02: Lock sequence tracking for non-durable, non-resilient handles

**File:** `src/protocol/smb2/smb2_lock.c:418-420`

MS-SMB2 §3.3.5.14 defines the `LockSequenceNumber` check as applying whenever the
lock sequence index is in range (1-64), not only for special handle types. For
oplock-protected handles (standard handles) with a valid lock sequence index, the
server should still honour the idempotency mechanism. The current code silently
skips the check and stores no sequence for plain handles (`check_lock_sequence`
returns 0 immediately). This means a client that sends the same lock request twice
on a plain handle gets a second attempt (possible double-error), not the cached
idempotent success.

---

### P2-IOCTL-01: FSCTL_PIPE_WAIT is a noop

**File:** `src/fs/ksmbd_fsctl_extra.c:567-569`

```c
ksmbd_debug(SMB, "FSCTL_PIPE_WAIT: returning success\n");
*out_len = 0;
return 0;
```
MS-SMB2 §3.3.5.15.9 / MS-FSCC §2.3.30 requires the server to wait until the named
pipe instance is available (up to `Timeout` milliseconds). The ksmbd implementation
unconditionally returns STATUS_SUCCESS without waiting. This is incorrect when no
pipe instance is currently listening; the response should be `STATUS_IO_TIMEOUT`
after the timeout expires.

---

### P2-IOCTL-02: FSCTL_SRV_READ_HASH (BranchCache) is partially implemented but requires SHA-256

**File:** `src/fs/ksmbd_fsctl.c:2302-2346`, `src/fs/ksmbd_branchcache.c`

BranchCache Content Information V1 (MS-PCCRC) requires SHA-256 computation over
file segments. If the implementation falls back to `STATUS_HASH_NOT_PRESENT` on
most paths, clients that rely on BranchCache for WAN acceleration receive no data.
The spec (`MS-SMB2 §3.3.5.15.10`) allows `STATUS_HASH_NOT_PRESENT` as a valid
response only when the hash has not been computed yet, not as a blanket stub.

---

### P2-IOCTL-03: Named-pipe IOCTL (`FSCTL_PIPE_TRANSCEIVE`) does not validate handle is actually a named pipe

**File:** `src/fs/ksmbd_fsctl.c:1556-1607`

`fsctl_pipe_transceive_handler` passes the request straight to `ksmbd_rpc_ioctl`.
It does not verify that the file handle identified by `id` refers to a named pipe.
MS-SMB2 §3.3.5.15.8 requires the server to return `STATUS_INVALID_HANDLE` if the
target is not a named pipe. A regular file handle silently attempts RPC dispatch.

---

### P2-IOCTL-04: FSCTL_OFFLOAD_READ / FSCTL_OFFLOAD_WRITE token scope is server-global, not session-scoped

**File:** `src/fs/ksmbd_fsctl.c:1906-1961` (`odx_token_table`)

The ODX token table is a single global hash table. MS-FSCC §2.3.53 implies tokens
are scoped to the session or connection (the source file must be reachable from the
same session). The current global table allows a token generated in session A to be
consumed in session B, potentially by a different client. This is both a spec
compliance issue and a potential security concern (cross-session data copy).

---

### P2-IOCTL-05: FSCTL_SET_COMPRESSION does not actually compress underlying data

**File:** `src/fs/ksmbd_fsctl.c:496-544`

`fsctl_set_compression_handler` updates `m_fattr | ATTR_COMPRESSED_LE` but does not
call any VFS mechanism to actually compress the file data. MS-FSCC §2.3.61 requires
the file to be compressed on disk when `COMPRESSION_FORMAT_LZNT1` is set, or
decompressed when `COMPRESSION_FORMAT_NONE` is set. The attribute flag is persisted
in a DOS xattr but the data layout is unchanged. Interoperability impact: clients
that set compression and then read the file will not get compressed-on-wire data, and
`FSCTL_GET_COMPRESSION` will report LZNT1 while the data is uncompressed.

---

### P2-IOCTL-06: FSCTL_FILESYSTEM_GET_STATISTICS returns all-zero counters

**File:** `src/fs/ksmbd_fsctl.c:1637-1660`

The implementation returns a `FILESYSTEM_STATISTICS` structure with all counter
fields zeroed. MS-FSCC §2.3.21 and the OS statistics clients use these counters to
measure I/O performance. Returning zero is technically not an error but it prevents
any client-side performance monitoring from functioning.

---

### P2-IOCTL-07: FSCTL_GET_NTFS_VOLUME_DATA uses fabricated NTFS-specific fields

**File:** `src/fs/ksmbd_fsctl.c:651-713`

Fields like `MftValidDataLength`, `MftStartLcn`, `Mft2StartLcn`, `MftZoneStart`,
`MftZoneEnd` are all left zero. These fields are NTFS-internal and have no Linux VFS
equivalent. The spec (MS-FSCC §2.3.26) defines specific meaning for these fields.
While zero may be acceptable, `BytesPerFileRecordSegment` is set to `bytes_per_cluster`
instead of the NTFS standard of 1024 bytes, which can confuse backup software that
relies on this field.

---

## Partial Implementations (P3)

### P3-LOCK-01: `smb2_wait_for_posix_lock` does not propagate `-EINTR`

**File:** `src/protocol/smb2/smb2_lock.c:246-267`

The periodic wakeup loop handles `-ERESTARTSYS` but falls through on other negative
returns (`rc < 0 && rc != -ERESTARTSYS`). The VFS lock wait can return `-EINTR`
under some conditions, which is silently swallowed. The subsequent `retry` path at
line 917 will re-attempt the lock, which may cause an unexpected retry loop.

---

### P3-LOCK-02: Zero-length lock range handling is partial

**File:** `src/protocol/smb2/smb2_lock.c:830-833`

Zero-length lock ranges are silently skipped at the VFS level:
```c
if (smb_lock->zero_len) {
    err = 0;
    goto skip;
}
```
MS-SMB2 §2.2.26 permits zero-length lock ranges (they have defined overlap
semantics). Zero-length locks are tracked in `ksmbd_lock` (`lock->zero_len = 1`,
`smb2_lock_init` at line 356-357) and the conflict checks do handle them. However,
the actual VFS lock call is skipped, so if another client's process holds the range
at the OS level, the zero-length lock will report success even when it should fail.
The ksmbd-internal conflict check is the only gate.

---

### P3-IOCTL-01: FSCTL_MARK_HANDLE ignores input buffer content

**File:** `src/fs/ksmbd_fsctl.c:1315-1333`

`fsctl_mark_handle_handler` validates the file handle but ignores the
`MARK_HANDLE_INFO` input structure entirely. MS-FSCC §2.3.31 defines a
`CopyNumber`, `UsnSourceInfo`, and `VolumeGuid` field. The `UsnSourceInfo` controls
USN journal attribution. The `CopyNumber` field (0x40000000 flag) is important for
clustered environments.

---

### P3-IOCTL-02: FSCTL_QUERY_FILE_REGIONS always returns one region

**File:** `src/fs/ksmbd_fsctl.c:1736-1797`

The handler always returns one region covering the entire requested range with
`FILE_REGION_USAGE_VALID_CACHED_DATA`. MS-FSCC §2.3.39 expects the server to return
actual regions of valid data. For sparse files (which ksmbd supports via
`ATTR_SPARSE_FILE_LE`), this should enumerate non-zero regions. The implementation
does not call `llseek(SEEK_DATA)` / `llseek(SEEK_HOLE)` to find actual data regions.

---

### P3-IOCTL-03: FSCTL_GET_RETRIEVAL_POINTERS reports one fabricated extent

**File:** `src/fs/ksmbd_fsctl.c:735-800`

The handler always returns exactly one extent covering the entire file. Real
defragmentation tools that use this FSCTL expect actual LCN (logical cluster number)
information. The returned `Lcn = starting_vcn` is fabricated and means nothing on a
Linux filesystem.

---

### P3-IOCTL-04: FSCTL_OFFLOAD_READ does not honour `TokenTimeToLive`

**File:** `src/fs/ksmbd_fsctl.c:2009-2088`

The `offload_read_input->TokenTimeToLive` field (milliseconds, 0 = default) is read
but completely ignored. Tokens are stored indefinitely in `odx_token_table` until
consumed. MS-FSCC §2.3.53 requires tokens to expire after the TTL. Stale tokens
accumulate in kernel memory until module unload.

---

### P3-IOCTL-05: FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX ignores the ATOMIC flag

**File:** `src/fs/ksmbd_fsctl.c:1235-1307`

The `DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC` flag (0x00000001) in
`dup_ext->Flags` is never checked. The comment at line 1277-1282 acknowledges that
`vfs_clone_file_range()` is "atomic on filesystems that support reflink." However,
when reflink is not supported and the code falls back to `vfs_copy_file_range()`, the
ATOMIC guarantee is silently dropped without returning an error. MS-FSCC §2.3.8
requires the server to fail with `STATUS_NOT_SUPPORTED` if `ATOMIC` is set and the
operation cannot be completed atomically.

---

### P3-IOCTL-06: FSCTL_SET_ZERO_ON_DEALLOCATION ignores the actual deallocation hint

**File:** `src/fs/ksmbd_fsctl.c:1668-1686`

The handler validates the handle and returns success but performs no action. The
comment says "Linux filesystems already zero deallocated blocks." This is not
universally true (ext2 without `lazytime`, older XFS versions). The spec (MS-FSCC
§2.3.69) requires the server to guarantee zeroing of deallocated regions in
subsequent writes to the same range.

---

## Low Priority (P4)

### P4-LOCK-01: KSMBD_MAX_LOCK_COUNT is 64, MS-SMB2 does not define a minimum upper bound

**File:** `src/include/protocol/smb2pdu_internal.h:18`

`#define KSMBD_MAX_LOCK_COUNT 64` caps lock count at 64 per request. The spec does
not impose a maximum per-request lock count (only memory limits). The cap is
reasonable for anti-DoS but should be advertised in negotiate responses or
documented. Returning `STATUS_INVALID_PARAMETER` for requests with more than 64 lock
elements may confuse strictly-conforming clients.

---

### P4-LOCK-02: No validation that UNLOCK elements all match previously-acquired locks

**File:** `src/protocol/smb2/smb2_lock.c:817-824`

The `nolock = 1` path correctly detects when a lock to be unlocked is not in
`conn->lock_list`. However, on success of the POSIX `vfs_lock_file(F_UNLCK)` call
(line 849), the code does not re-verify that the lock was ksmbd-tracked before
removing it. A Windows-style POSIX unlock without a prior SMB2 lock might succeed
at the VFS level yet `nolock` would still be 1, causing `STATUS_RANGE_NOT_LOCKED`
to be returned on the subsequent check. The logic sequence is slightly fragile.

---

### P4-IOCTL-01: Legacy smb2_ioctl.c handlers are dead code but still compiled

**File:** `src/protocol/smb2/smb2_ioctl.c:533-769`

The entire legacy `switch(cnt_code)` block in `smb2_ioctl()` after the
`ksmbd_dispatch_fsctl()` call is unreachable for all codes that are registered in the
hash table (which includes all the legacy cases). This is dead code that increases
binary size and creates maintenance risk (future patches might update the legacy path
without updating the hash-table handler).

---

### P4-IOCTL-02: FSCTL_PIPE_PEEK returns a zeroed response unconditionally

**File:** `src/fs/ksmbd_fsctl.c:614-632`

`fsctl_pipe_peek_handler` returns a zeroed `fsctl_pipe_peek_rsp` including
`NamedPipeState = 0`. Per MS-FSCC §2.3.32, `FILE_PIPE_PEEK_BUFFER.NamedPipeState`
must be one of: Disconnected(1), Listening(2), Connected(3), Closing(4). Zero is
not a valid state. Clients may mis-handle this.

---

### P4-IOCTL-03: FSCTL_VALIDATE_NEGOTIATE_INFO uses `memset(neg_rsp->Guid, 0, ...)` instead of server GUID

**File:** `src/fs/ksmbd_fsctl.c:1538`

```c
memset(neg_rsp->Guid, 0, SMB2_CLIENT_GUID_SIZE);
```
MS-SMB2 §3.3.5.15.12 requires the server to respond with its own `ServerGuid`.
Zeroing the GUID field is incorrect; it should be `conn->srv_guid` or the server's
negotiated GUID. Windows SMB3 clients verify this field and may reject the validation
response.

---

### P4-IOCTL-04: FSCTL_IS_PATHNAME_VALID always returns success without validating the path

**File:** `src/fs/ksmbd_fsctl.c:546-555`

The handler returns 0 (success) without even looking at the input buffer. MS-FSCC
§2.3.28 requires the server to validate that the path in the input buffer is a
syntactically valid Windows path. Returning success unconditionally means that
clients issuing malformed paths receive no error.

---

### P4-IOCTL-05: `smb2_ioctl` ChannelSequence check re-looks up the fp with `ksmbd_lookup_fd_fast` on a potentially unowned fd

**File:** `src/protocol/smb2/smb2_ioctl.c:479-492`

The channel-sequence check in `smb2_ioctl` looks up the fp, calls
`smb2_check_channel_sequence`, drops the reference, and then the individual FSCTL
handler re-looks up the same fp. This is a TOCTOU window: the file could be closed
between the two lookups. The lookup is safe (returns NULL on closed fd) but the
channel-sequence check result becomes stale.

---

## Compliance Estimate per Command

### SMB2 LOCK (MS-SMB2 §3.3.5.14)

| Requirement                              | Status             | Detail |
|------------------------------------------|--------------------|--------|
| Lock flags: SHARED, EXCLUSIVE, UNLOCK, FAIL_IMMEDIATELY | Implemented | All 4 flags handled correctly |
| Multiple lock elements, rollback on failure | Implemented | Rollback list used |
| FAIL_IMMEDIATELY → STATUS_LOCK_NOT_GRANTED | Implemented | Via `F_SETLK` path |
| Blocking lock → STATUS_PENDING + async   | Implemented | `smb2_send_interim_resp` + work queue |
| CANCEL of pending lock                   | Implemented (with bug P1-LOCK-02) | Cancel handler present |
| Zero-length lock ranges                  | Partial (P3-LOCK-02) | Tracked but VFS skipped |
| Lock ranges > 2^63                       | Implemented | Clamped + ksmbd-internal list |
| LockSequenceNumber/LockSequenceIndex idempotency | Partial (P1-LOCK-01, P2-LOCK-02) | Only for durable handles, struct comment wrong |
| ChannelSequence validation               | Implemented | `smb2_check_channel_sequence` |
| Durable handle reconnect with locks      | Missing (P2-LOCK-01) | Locks not restored |
| Unlock non-locked range → STATUS_RANGE_NOT_LOCKED | Implemented | `nolock` path |

**SMB2 LOCK overall compliance: ~75%**

---

### SMB2 IOCTL/FSCTL (MS-SMB2 §3.3.5.15)

| Requirement                                  | Status             |
|----------------------------------------------|--------------------|
| Flags MUST be SMB2_0_IOCTL_IS_FSCTL          | Implemented (line 472) |
| InputOffset/InputCount bounds validation     | Implemented (line 504-520) |
| MaxOutputResponse cap                        | Implemented (line 495-501) |
| ChannelSequence validation on file handles   | Implemented (line 478-492) |
| FSCTL_DFS_GET_REFERRALS                      | Implemented (stub referral) |
| FSCTL_DFS_GET_REFERRALS_EX                   | Implemented (stub referral) |
| FSCTL_PIPE_PEEK                              | Partial (P4-IOCTL-02) |
| FSCTL_PIPE_WAIT                              | Partial (P2-IOCTL-01) |
| FSCTL_PIPE_TRANSCEIVE                        | Implemented (P2-IOCTL-03 handle check) |
| FSCTL_SET_SPARSE                             | Implemented |
| FSCTL_SET_ZERO_DATA                          | Implemented |
| FSCTL_QUERY_ALLOCATED_RANGES                 | Implemented |
| FSCTL_SET_ZERO_ON_DEALLOCATION               | Partial (P3-IOCTL-06) |
| FSCTL_FIND_FILES_BY_SID                      | Not supported (honest error) |
| FSCTL_CREATE_OR_GET_OBJECT_ID                | Implemented |
| FSCTL_GET_OBJECT_ID                          | Implemented |
| FSCTL_DELETE_OBJECT_ID                       | Implemented |
| FSCTL_SET_OBJECT_ID                          | Partial (P3) |
| FSCTL_SET_OBJECT_ID_EXTENDED                 | Partial (ignores extended fields) |
| FSCTL_GET_COMPRESSION                        | Implemented |
| FSCTL_SET_COMPRESSION                        | Partial (P2-IOCTL-05) |
| FSCTL_SET_REPARSE_POINT                      | Implemented (symlinks, junctions) |
| FSCTL_GET_REPARSE_POINT                      | Implemented |
| FSCTL_DELETE_REPARSE_POINT                   | Implemented |
| FSCTL_FILESYSTEM_GET_STATISTICS              | Partial (P2-IOCTL-06) |
| FSCTL_GET_NTFS_VOLUME_DATA                   | Partial (P2-IOCTL-07) |
| FSCTL_LMR_REQUEST_RESILIENCY                 | Implemented |
| FSCTL_QUERY_NETWORK_INTERFACE_INFO           | Bug (P1-IOCTL-01 — wrong code) |
| FSCTL_VALIDATE_NEGOTIATE_INFO                | Partial (P4-IOCTL-03 — zero GUID) |
| FSCTL_SRV_ENUMERATE_SNAPSHOTS                | Implemented |
| FSCTL_REQUEST_RESUME_KEY                     | Implemented |
| FSCTL_SRV_COPYCHUNK                          | Implemented (P1-IOCTL-03 off-by-one) |
| FSCTL_SRV_COPYCHUNK_WRITE                    | Implemented (same bug) |
| FSCTL_SRV_READ_HASH (BranchCache)            | Partial (P2-IOCTL-02) |
| FSCTL_READ_FILE_USN_DATA                     | Not supported (honest error) |
| FSCTL_WRITE_USN_CLOSE_RECORD                 | Not supported (honest error) |
| FSCTL_REQUEST_OPLOCK (legacy)                | Stub noop |
| FSCTL_OFFLOAD_READ                           | Partial (P2-IOCTL-04, P3-IOCTL-04) |
| FSCTL_OFFLOAD_WRITE                          | Partial (P2-IOCTL-04) |
| FSCTL_SET_INTEGRITY_INFORMATION              | Stub (acceptable for non-ReFS) |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE              | Implemented |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX           | Partial (P3-IOCTL-05) |
| FSCTL_QUERY_ON_DISK_VOLUME_INFO              | Not supported (honest error) |

**SMB2 IOCTL overall compliance: ~68%**

(Core mandatory FSCTLs — VALIDATE_NEGOTIATE, COPYCHUNK, QUERY_NETWORK_INTERFACE,
REPARSE — are either implemented or have narrow bugs. The unimplemented codes are
mostly optional features or Windows-specific features with no Linux equivalent.)

---

## Summary of P1 Action Items

| ID | File:Line | Description |
|----|-----------|-------------|
| P1-LOCK-01 | `src/include/protocol/smb2pdu.h:1261-1262` | Fix struct comment: LockSequenceIndex is 28 bits (bits 4-31), not 4 bits |
| P1-LOCK-02 | `src/protocol/smb2/smb2_lock.c:899-905` | Fix cancelled lock response: send final SMB2 LOCK error response, not a second interim |
| P1-IOCTL-01 | `src/include/protocol/smbfsctl.h:78` | Fix `FSCTL_QUERY_NETWORK_INTERFACE_INFO` code from `0x001401FC` to `0x001400FC` |
| P1-IOCTL-02 | `src/protocol/smb2/smb2_ioctl.c:670-688` | Remove dead legacy `FSCTL_GET_REPARSE_POINT` case |
| P1-IOCTL-03 | `src/fs/ksmbd_fsctl.c:997`, `src/protocol/smb2/smb2_ioctl.c:96` | Fix copychunk `>=` off-by-one to `>` |
