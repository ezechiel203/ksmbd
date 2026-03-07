# SMB3 Plan 07: Server-Side Copy, Snapshots, BranchCache, and Misc FSCTLs

Audit date: 2026-03-01
Audited branch: phase1-security-hardening

Files examined:
- `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_ioctl.c`
- `/home/ezechiel203/ksmbd/src/fs/ksmbd_fsctl.c`
- `/home/ezechiel203/ksmbd/src/fs/ksmbd_fsctl_extra.c`
- `/home/ezechiel203/ksmbd/src/include/protocol/smbfsctl.h`
- `/home/ezechiel203/ksmbd/src/mgmt/ksmbd_witness.c`
- `/home/ezechiel203/ksmbd/src/mgmt/ksmbd_witness.h`
- `/home/ezechiel203/ksmbd/src/fs/ksmbd_vss.c`
- `/home/ezechiel203/ksmbd/src/fs/ksmbd_branchcache.c`
- `/home/ezechiel203/ksmbd/src/fs/ksmbd_resilient.c`
- `/home/ezechiel203/ksmbd/src/core/ksmbd_config.c`
- `/home/ezechiel203/ksmbd/src/include/protocol/smb2pdu.h`

---

## FSCTL_VALIDATE_NEGOTIATE_INFO (0x00140204) — MS-SMB2 §3.3.5.15.12

### Registration
FSCTL_VALIDATE_NEGOTIATE_INFO is registered in `builtin_fsctl_handlers[]` in
`ksmbd_fsctl.c` at line 2581, pointing to `fsctl_validate_negotiate_info_handler`.

### Implementation analysis (ksmbd_fsctl.c lines 1491–1548)

The handler performs the following checks in sequence:

1. Minimum input buffer size (`offsetof(..., Dialects)`, line 1509).
2. DialectCount bounds check against `in_buf_len` (line 1518).
3. `ksmbd_lookup_dialect_by_id()` — verifies client dialect list contains the
   negotiated dialect and matches `conn->dialect` (line 1522–1525).
4. `memcmp(neg_req->Guid, conn->ClientGUID, ...)` — GUID comparison (line 1527).
5. `SecurityMode` comparison against `conn->cli_sec_mode` (line 1530).
6. `Capabilities` comparison against `conn->cli_cap` (line 1533).

On match, the response is filled with:
- `neg_rsp->Capabilities = conn->vals->capabilities`
- `neg_rsp->Guid` — zeroed (see P2 item below)
- `neg_rsp->SecurityMode = conn->srv_sec_mode`
- `neg_rsp->Dialect = conn->dialect`

### Confirmed bugs

**P1-VNI-01: Mismatch returns -EINVAL instead of disconnecting transport**

MS-SMB2 §3.3.5.15.12 states: "If the validation fails, the server MUST
terminate the transport connection."  The current handler returns `-EINVAL`
on any mismatch (lines 1525, 1528, 1531, 1534), which propagates to
`smb2_ioctl()` as `STATUS_INVALID_PARAMETER`. This sends an error response
rather than closing the TCP connection, defeating the downgrade-protection
purpose of the FSCTL.

Location: `ksmbd_fsctl.c:1524-1534`
Spec ref: MS-SMB2 §3.3.5.15.12 ("the server MUST terminate the transport
connection and free the Connection object")
Fix: On validation failure, call `ksmbd_conn_set_exiting(work->conn)` (or
the equivalent transport teardown function) before returning the error,
so the transport is closed rather than a 4xx response being sent.

**P2-VNI-02: ServerGuid field zeroed instead of server GUID**

`neg_rsp->Guid` is set to all zeros via `memset(neg_rsp->Guid, 0, ...)` at
line 1538. MS-SMB2 §2.2.32.6 says this field is the `ServerGuid` as
returned in the NEGOTIATE response. The server GUID is available in
`server_conf.guid`. Sending zeros is technically wrong (a man-in-the-middle
could also zero it); the correct server GUID should be copied.

Location: `ksmbd_fsctl.c:1538`
Spec ref: MS-SMB2 §2.2.32.6 VALIDATE_NEGOTIATE_INFO Response

---

## Server-Side Copy (CopyChunk + ODX)

### FSCTL_SRV_COPYCHUNK (0x001440F2) and FSCTL_SRV_COPYCHUNK_WRITE (0x001480F2)

Both codes are registered in `builtin_fsctl_handlers[]`:
- `FSCTL_COPYCHUNK` → `fsctl_copychunk_handler` (ksmbd_fsctl.c line 2406)
- `FSCTL_COPYCHUNK_WRITE` → `fsctl_copychunk_write_handler` (line 2411)

Both codes are also handled in the legacy `switch` in `smb2_ioctl.c` lines
557–586 and in `ksmbd_fsctl_extra.c` lines 448–466. This creates three
independent implementations of the same logic — a maintenance hazard (see
P2-CC-03 below).

**Structure compliance:**

`copychunk_ioctl_req` (smb2pdu.h line 1150):
```c
struct copychunk_ioctl_req {
    __le64 ResumeKey[3];   // 24 bytes — matches spec
    __le32 ChunkCount;
    __le32 Reserved;
    __u8   Chunks[];
};
```
The ResumeKey is 24 bytes (3 × `__le64`), matching MS-SMB2 §2.2.31.1.
`srv_copychunk` (line 1157) has SourceOffset, TargetOffset (named
TargetOffset, not DestinationOffset as in some spec editions), Length — correct.

**Limits (ksmbd_config.c lines 66–86):**
- Max chunk count default: **256** (configurable, min 1, max 65535).
  MS-SMB2 allows up to 16 per request; default 256 is permissive.
- Max bytes per chunk: **1 MB** (default), up to 16 MB (configurable).
- Max total bytes per request: **16 MB** (default), up to 256 MB (configurable).
  MS-SMB2 §3.3.5.15.6 recommends max 16 chunks, 1 MB/chunk, 16 MB total.
  The server defaults align with the spec but the configurable upper bound
  (65535 chunks, 256 MB total) may permit memory exhaustion or large
  kernel allocations.

**Off-by-one in chunk count validation:**

In `fsctl_copychunk_common()` (ksmbd_fsctl.c line 997) and in
`fsctl_copychunk_handler` (line 1089, via common path) and
`smb2_ioctl.c:96`:
```c
if (chunk_count >= ksmbd_server_side_copy_max_chunk_count() || ...)
```
The boundary check uses `>=` meaning `max_count` is exclusive. If
`max_count` is 16 (spec default), chunk_count of exactly 16 is rejected,
leaving only 15 allowed — one fewer than the spec permits.

Location: `ksmbd_fsctl.c:997`, `smb2_ioctl.c:96`
Spec ref: MS-SMB2 §3.3.5.15.6

**Access check for FSCTL_COPYCHUNK:**

`FSCTL_COPYCHUNK` requires `FILE_READ_DATA` on the destination handle
(MS-SMB2 §3.3.5.15.6: the destination must be opened with read access when
the input is the source token). This is checked at `ksmbd_fsctl.c:1033`:
```c
if (cnt_code == FSCTL_COPYCHUNK &&
    !(dst_fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE)))
```
Correct.

**Actual copy mechanism:**

`ksmbd_vfs_copy_file_ranges()` (vfs.c) is used for the copy, which
ultimately calls `vfs_copy_file_range()` via the VFS. This is correct and
leverages kernel copy offload where available.

**Response fields:** `ChunksWritten`, `ChunkBytesWritten`, `TotalBytesWritten`
are populated from the actual copy results. `TotalBytesWritten` is capped to
`U32_MAX` in the legacy path (smb2_ioctl.c lines 180–184); the handler path
in ksmbd_fsctl.c does not cap at U32_MAX, though the config limit prevents
exceeding 16 MB by default.

**Cross-session source FID:**

`ksmbd_lookup_foreign_fd()` is used to locate the source file. This function
looks up the FID across sessions (not limited to the current session), which
matches the MS-SMB2 §3.3.5.15.6 requirement that the source file opened by
FSCTL_SRV_REQUEST_RESUME_KEY can be cross-session.

### FSCTL_SRV_REQUEST_RESUME_KEY (0x00140078) — §3.3.5.15.5

Registered in `builtin_fsctl_handlers[]` (ksmbd_fsctl.c line 2396) →
`fsctl_request_resume_key_handler` (line 934).

The handler (lines 934–965) returns a 24-byte key:
```c
key_rsp->ResumeKey[0] = cpu_to_le64(fp->volatile_id);
key_rsp->ResumeKey[1] = cpu_to_le64(fp->persistent_id);
// ResumeKey[2] is left zero from memset
```
The `resume_key_ioctl_rsp` structure has `ResumeKey[3]` (24 bytes) — the
third element is zeroed. MS-SMB2 §2.2.32.3 says ResumeKey is 24 bytes opaque.
The current encoding (volatile_id, persistent_id, zero) is valid.

Also present in legacy switch at `smb2_ioctl.c:542–555`. The legacy path
uses the raw request fields (`req->VolatileFileId`, `req->PersistentFileId`)
rather than `ksmbd_lookup_fd_fast` to retrieve the actual `fp` IDs.

**P2-RRK-01: Legacy path does not look up fp**

In `smb2_ioctl.c:548`, `fsctl_request_resume_key()` uses `req->VolatileFileId`
and `req->PersistentFileId` directly but still validates existence via
`ksmbd_lookup_fd_slow()`. The registered handler path (ksmbd_fsctl.c:949) uses
`ksmbd_lookup_fd_fast(work, id)` which uses the potentially rewritten `id`
from compound requests. Because the dispatcher hits the registered handler
first (dispatch returns before reaching the switch), both paths do not
conflict in practice, but the legacy code is redundant dead code.

### ODX: FSCTL_OFFLOAD_READ (0x00094264) and FSCTL_OFFLOAD_WRITE (0x00098268)

Both registered in `builtin_fsctl_handlers[]`:
- `FSCTL_OFFLOAD_READ` → `fsctl_offload_read_handler` (ksmbd_fsctl.c line 2621)
- `FSCTL_OFFLOAD_WRITE` → `fsctl_offload_write_handler` (line 2626)

This is a **functional implementation**, not a stub.

**Token architecture:**

A `ksmbd_odx_token` (512 bytes, matching `STORAGE_OFFLOAD_TOKEN_SIZE`) is
server-local and contains:
- `magic` (4 bytes): `KSMBD_ODX_TOKEN_MAGIC` = "KSMB" (0x4B534D42)
- `file_id` (8 bytes): inode number
- `offset` / `length` / `generation` (8 bytes each)
- `nonce` (16 bytes): random bytes preventing forgery
- padding to exactly 512 bytes (verified by `static_assert` at line 1886)

Tokens are stored in a global hash table (`odx_token_table`) keyed by the
first 4 bytes of the nonce (lines 1906–1936). Tokens are consumed on first
use (one-time tokens, line 1951–1953).

**OFFLOAD_WRITE:**

1. Validates `KSMBD_ODX_TOKEN_MAGIC` (line 2144).
2. Validates token against server registry via nonce + all fields (line 2157).
3. Locates source file by inode number within the session via
   `ksmbd_lookup_fd_inode_sess()` (line 2209).
4. Validates `i_generation` to prevent stale-inode attacks (line 2232).
5. Uses `vfs_copy_file_range()` in a loop for the actual transfer.

**Issues:**

**P1-ODX-01: Token lookup is O(n) due to low-entropy hash key**

`odx_nonce_hash()` at line 1909 returns only the first 4 bytes of the nonce
as the hash key. On a busy server issuing many tokens, hash collisions will
degrade lookup to O(n). This is a minor performance issue but could become
a DoS vector under sustained client load.

Location: `ksmbd_fsctl.c:1909-1916`

**P2-ODX-02: No token expiry / TTL**

MS-FSCC §2.3.53 says the `TokenTimeToLive` field in the OFFLOAD_READ input
specifies the desired token lifetime in milliseconds. The current handler
reads `input->TokenTimeToLive` but ignores it entirely. Tokens persist in
the hash table until consumed or module unload. A client can issue
OFFLOAD_READ without ever issuing OFFLOAD_WRITE, leaking memory permanently.

Location: `ksmbd_fsctl.c:2034` (input structure parsed but TTL not stored)

**P2-ODX-03: ODX is session-local, not cross-session**

`ksmbd_lookup_fd_inode_sess()` restricts source file lookup to the current
session. MS-FSCC does not restrict ODX to the same session. For intra-server
ODX between shares or sessions this may be insufficient, though for the
common use case (single-session offload) it is correct.

---

## Snapshot Enumeration

### FSCTL_SRV_ENUMERATE_SNAPSHOTS (0x00144064) — §3.3.5.15.1

Registered from `ksmbd_vss_init()` (ksmbd_vss.c line 735):
```c
static struct ksmbd_fsctl_handler vss_enumerate_handler = {
    .ctl_code = FSCTL_SRV_ENUMERATE_SNAPSHOTS,
    .handler  = ksmbd_vss_enumerate_snapshots,
};
```

**Implementation (ksmbd_vss.c lines 558–696):**

1. Iterates registered backends (btrfs, zfs, generic) in order.
2. Each backend scans a well-known snapshot directory:
   - btrfs: `<share_path>/.snapshots/`
   - zfs: `<share_path>/.zfs/snapshot/`
   - generic: same as btrfs (`.snapshots/`)
3. Entries are converted to @GMT-YYYY.MM.DD-HH.MM.SS format via
   `ksmbd_vss_dirname_to_gmt()`.
4. Response header (`srv_snapshot_array`) populated with
   `number_of_snapshots`, `number_of_snapshots_returned`,
   `snapshot_array_size` (lines 684–692).
5. @GMT tokens written as UTF-16LE strings, NUL-terminated per entry,
   plus a final array-terminator NUL.

**Structure compliance:**

`srv_snapshot_array` (ksmbd_vss.c line 41) has:
- `number_of_snapshots` (le32)
- `number_of_snapshots_returned` (le32)
- `snapshot_array_size` (le32)
Matches MS-SMB2 §2.2.32.2 SRV_SNAPSHOT_ARRAY.

On buffer-too-small: returns header with total count and required size
but zero returned entries — correct per spec.

On no snapshots: returns success with all-zero counts — correct per spec.

**@GMT path parsing:**

`ksmbd_vss_dirname_to_gmt()` (lines 204–256) supports four formats:
- `@GMT-YYYY.MM.DD-HH.MM.SS` (passthrough)
- `YYYY-MM-DD_HH:MM:SS` (snapper)
- `YYYY-MM-DD-HHMMSS` (simple)
- `YYYY-MM-DD` (date-only)

`ksmbd_vss_resolve_path()` is the API for resolving a @GMT path to a real
filesystem path (used in VFS open path). Backends must implement
`resolve_path` for snapshot access to work.

**P2-VSS-01: @GMT path resolution not wired into VFS open**

`ksmbd_vss_resolve_path()` exists but there is no evidence it is called
during SMB2 CREATE when a path contains an `@GMT-` component. Windows
clients use `@GMT-` prefixes in file paths to open files from VSS snapshots.
Without this hook in the CREATE path, snapshot file access (not just
enumeration) will fail with "file not found".

**P3-VSS-02: btrfs backend assumes snapper layout**

The btrfs backend always looks for `.snapshots/<name>/snapshot/` (the snapper
subvolume layout). Native `btrfs subvolume snapshot` creates snapshots
differently. A configurable snapshot path per share would be more general.

---

## BranchCache (SRV_READ_HASH)

### FSCTL_SRV_READ_HASH (0x001441BB) — §3.3.5.15.4

Registered in `builtin_fsctl_handlers[]` (ksmbd_fsctl.c line 2631) →
`fsctl_srv_read_hash_handler` (line 2302).

This is a **functional implementation** (not a stub), implemented in
`ksmbd_branchcache.c`.

**Request parsing (`ksmbd_branchcache_read_hash`, branchcache.c line 626):**

- `HashType`: validated as `SRV_HASH_TYPE_PEER_DIST` only (line 655).
- `HashVersion`: only V1 (SHA-256) supported (line 662).
- `HashRetrievalType`: only `SRV_HASH_RETRIEVE_FILE_BASED` (line 673).
- `Length` / `Offset`: clamped to file size (line 687–689).

**Hash computation:**

- MS-PCCRC V1: two-level hash. Per-64KB block: `BlockHash = SHA-256(data)`.
  HoD (hash of data) = `SHA-256(BlockHash1 || ... || BlockHashN)`.
  SegmentSecret = `HMAC-SHA256(Ks, HoD)` where Ks is a 32-byte secret
  generated at module load (`ksmbd_branchcache_generate_secret()`).

**Caching:** Hashes are stored/retrieved via extended attribute
`user.ksmbd.pccrc.v1` with mtime/size/offset/length validation for
cache invalidation. `ksmbd_branchcache_invalidate()` removes the xattr on
file write.

**Issues:**

**P3-BC-01: Server secret is never rotated**

A TODO comment in `ksmbd_branchcache.c` lines 39–48 explicitly notes:
"This secret is generated once at module load and never rotated during the
lifetime of the module." The HMAC-SHA256 secret is `pccrc_server_secret`
(line 49). Long-lived secrets increase offline brute-force risk. No rotation
mechanism is implemented.

**P3-BC-02: HASH_BASED retrieval not supported**

`SRV_HASH_RETRIEVE_HASH_BASED` returns `-EOPNOTSUPP` → `STATUS_HASH_NOT_PRESENT`
(ksmbd_fsctl.c line 2329–2332). Clients using hash-based retrieval will fail.
MS-PCCRC defines this as a SHOULD NOT requirement, so returning not-supported
is acceptable but limits functionality.

**P3-BC-03: HashVersion V2 not supported**

Content Information V2 (SHA-512, MS-PCCRC §2.3 v2) is not implemented.
V1 (SHA-256) only. This is acceptable for current Windows clients.

---

## Resilient Handles FSCTL

### FSCTL_LMR_REQUEST_RESILIENCY (0x001401D4) — §3.3.5.15.9

Implemented in `ksmbd_resilient.c`, registered via `ksmbd_resilient_init()`
called from `server.c:905`. Registration:
```c
static struct ksmbd_fsctl_handler resilient_handler = {
    .ctl_code = FSCTL_LMR_REQUEST_RESILIENCY,
    .handler  = ksmbd_fsctl_request_resiliency,
};
```

**Implementation (ksmbd_resilient.c lines 60–105):**

1. Validates `NETWORK_RESILIENCY_REQUEST` structure (16 bytes).
2. Reads `Timeout` field (milliseconds).
3. Caps timeout at `KSMBD_MAX_RESILIENT_TIMEOUT_MS` = 300,000 ms (5 minutes).
4. Sets `fp->is_resilient = true` and `fp->resilient_timeout = timeout_ms`.

**Effect on handle lifecycle (vfs_cache.c lines 1027, 1118, 1242–1244):**

`fp->is_resilient` is checked in:
- `ksmbd_close_fd()` / connection teardown: resilient handles are preserved
  after TCP disconnect for `resilient_timeout` ms.
- Lock sequence validation (smb2_lock.c lines 418–419).

**Issues:**

**P3-RES-01: No reconnection mechanism for resilient handles**

Resilient handle state is set, but the code path for a client to reconnect
and reclaim the resilient handle after a TCP disconnect is not clearly
implemented. MS-SMB2 §3.3.7.1 requires the server to process a re-open
request and match it to the existing resilient handle. Without this path,
the handle is preserved but effectively inaccessible.

**P3-RES-02: Resilient timeout cap may differ from spec suggestion**

MS-SMB2 §3.3.5.15.9 says the server SHOULD honor the timeout but may cap it.
The 5-minute cap is reasonable but not spec-mandated.

---

## FSCTL_QUERY_NETWORK_INTERFACE_INFO (0x001400FC) — §3.3.5.15.11

Registered in `builtin_fsctl_handlers[]` (ksmbd_fsctl.c line 2391) →
`fsctl_query_network_interface_info_handler` (line 819).

Also present in legacy switch (`smb2_ioctl.c:535`). Because the registered
handler is dispatched first, the legacy code is dead but harmless.

**Implementation (ksmbd_fsctl.c lines 819–932):**

Iterates `for_each_netdev(&init_net, ...)` under `rtnl_lock()`.
For each running non-loopback device in the interface list:
1. Sets `IfIndex`, `Capability` (RSS_CAPABLE if `real_num_tx_queues > 1`,
   RDMA_CAPABLE if `ksmbd_rdma_capable_netdev()`).
2. Queries `ethtool_ops->get_link_ksettings` for speed in Mb/s, converts
   to bits/s (`speed * 1000000`).
3. Emits one entry for IPv4 address and one for IPv6 address per device.
4. Each entry is 152 bytes; `Next` field is set to 152 for all but the last.

**Issues:**

**P3-NIC-01: IPv6 iteration under rtnl_lock without rcu_read_lock**

At ksmbd_fsctl.c line 912, `list_for_each_entry` iterates `idev6->addr_list`
without `rcu_read_lock()`. The smb2_ioctl.c legacy version at line 320 uses
`rcu_read_lock()` for the same loop. This is a potential race condition if
an IPv6 address is removed concurrently.

Location: `ksmbd_fsctl.c:912`

**P3-NIC-02: Speed conversion is incorrect for multi-Gb links**

The `speed` variable from `get_link_ksettings` is in Mb/s (e.g., 10000 for
10GbE). Multiplying by 1,000,000 gives bits/s correctly
(10000 * 1000000 = 10^10 = 10 Gb/s). This is correct.

---

## Witness Protocol

### Overview (ksmbd_witness.c, ksmbd_witness.h)

The kernel-side witness infrastructure (MS-SWN) is implemented in
`ksmbd_witness.c`. The design is:
- Kernel tracks resources (IP, share, node) and client registrations.
- Network device UP/DOWN events trigger state-change notifications to
  userspace via `ksmbd_ipc_witness_notify()`.
- Userspace (`ksmbd.mountd`) handles DCE/RPC WitnessrAsyncNotify responses.

**Kernel-side capabilities:**

- `ksmbd_witness_resource_add/del/lookup()`: resource lifecycle.
- `ksmbd_witness_register/unregister/unregister_session()`: per-client
  registration with limits (256 global, 64 per session).
- `ksmbd_witness_notify_state_change()`: snapshot + notify to userspace.
- Netdev notifier monitoring NETDEV_UP / NETDEV_DOWN events (lines 518–573).
- Work queue for deferred (non-atomic) notifications.

**What is NOT in the kernel:**

- No FSCTLs (FSCTL_SWN_*) are defined or registered. The Witness protocol
  uses the DCE/RPC ncacn_ip_tcp binding, not FSCTL. There are no
  `FSCTL_SWN_REGISTER` or similar codes. This is architecturally correct —
  witness registration comes via RPC, not IOCTL.
- Cluster failover logic is absent; this requires platform-specific awareness
  not present.

**Issues:**

**P3-WIT-01: No userspace-to-kernel IPC for witness REGISTER/UNREGISTER**

The header `ksmbd_witness.h` documents that userspace must handle
`KSMBD_EVENT_WITNESS_REGISTER` / `KSMBD_EVENT_WITNESS_UNREGISTER` netlink
events. However, there is no code path that triggers a witness registration
from an incoming SMB2 request (no FSCTL_SWN handler). Registration must be
driven entirely by userspace (ksmbd.mountd) calling kernel functions after
processing the RPC. The netlink event handlers on the kernel side are not
visibly wired to the registration API.

**P3-WIT-02: Witness notification relies on unimplemented userspace**

`ksmbd_ipc_witness_notify()` is called but the implementation of
`ksmbd_rpc_witness_notify` in the IPC path is not confirmed present. If
the IPC handler is not implemented in ksmbd.mountd, notifications are lost
silently.

---

## VSS Integration

`ksmbd_vss.c` provides:
- A pluggable backend registry (`ksmbd_vss_register_backend`).
- Three built-in backends: btrfs (`.snapshots/`), ZFS (`.zfs/snapshot/`),
  generic (same as btrfs).
- `ksmbd_vss_is_gmt_token()` — validates `@GMT-` format (24 chars).
- `ksmbd_vss_parse_gmt_timestamp()` — converts token to Unix timestamp via
  `mktime64()`.
- `ksmbd_vss_dirname_to_gmt()` — converts common snapshot dir naming formats.
- `ksmbd_vss_resolve_path()` — resolves @GMT token to real path via registered
  backends.

The `ksmbd_vss_enumerate_snapshots` FSCTL handler is correct for returning
the snapshot list. The btrfs `resolve_path` implementation
(`ksmbd_vss_btrfs_resolve`) looks for:
```
<share_path>/.snapshots/<gmt_token>/snapshot
```
The ZFS resolve returns:
```
<share_path>/.zfs/snapshot/<gmt_token>
```

**Gap:** The @GMT token path resolution is not integrated into the VFS open
path (see P2-VSS-01 above). Enumeration works; file access from snapshot
does not.

---

## Other SMB3 FSCTLs

### FSCTL_DUPLICATE_EXTENTS_TO_FILE (0x00098344)

Registered in `builtin_fsctl_handlers[]` (ksmbd_fsctl.c line 2416) and in
the legacy switch (`smb2_ioctl.c:691`). Uses `vfs_clone_file_range()` with
fallback to `vfs_copy_file_range()`. Correct per MS-FSCC §2.3.8.

**P2-DUP-01: Missing FILE_READ_DATA access check on source in registered handler**

The registered handler `fsctl_duplicate_extents_handler` (ksmbd_fsctl.c
line 1149) does not check `fp_in->daccess & FILE_READ_DATA_LE`. The legacy
handler in `smb2_ioctl.c:712` has the check:
```c
if (!(fp_in->daccess & FILE_READ_DATA_LE)) {
    ret = -EACCES;
    goto dup_ext_out;
}
```
The `ksmbd_fsctl_extra.c` version at line 493 also has no daccess check.
The registered handler in ksmbd_fsctl.c line 1149 likewise omits it.
Because the dispatcher runs the registered handler first, the access check
is effectively missing for this FSCTL.

Location: `ksmbd_fsctl.c:1149–1213`
Spec ref: MS-FSCC §2.3.7 (source handle opened with FILE_READ_DATA)

### FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX (0x000983E8)

Registered (ksmbd_fsctl.c line 2611) → `fsctl_duplicate_extents_ex_handler`
(line 1235). Handles `DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC` flag
structurally; uses `vfs_clone_file_range()` (atomic on btrfs/xfs). Missing
the same daccess check as the non-EX version (same P2 as above).

### FSCTL_SET_INTEGRITY_INFORMATION (0x0009C280)

Registered (ksmbd_fsctl.c line 2601) → `fsctl_set_integrity_info_handler`.
Returns success silently (line 1858). Per MS-FSCC on non-ReFS volumes this
is acceptable (integrity streams are a ReFS feature). The GET_INTEGRITY
counterpart returns `CHECKSUM_TYPE_NONE` with enforcement-off flag — correct.

### FSCTL_GET_INTEGRITY_INFORMATION (0x0009027C)

Registered (ksmbd_fsctl.c line 2596). Returns 16-byte
`fsctl_get_integrity_info_output` with `ChecksumAlgorithm = NONE`,
`Flags = CHECKSUM_ENFORCEMENT_OFF`. Functionally correct.

---

## Confirmed Bugs (P1)

| ID | File:Line | Symptom | Spec Ref | Fix |
|----|-----------|---------|----------|-----|
| P1-VNI-01 | `ksmbd_fsctl.c:1524–1534` | VALIDATE_NEGOTIATE_INFO mismatch returns STATUS_INVALID_PARAMETER instead of closing TCP connection | MS-SMB2 §3.3.5.15.12 "terminate the transport connection" | Call transport disconnect function before returning error |
| P1-ODX-01 | `ksmbd_fsctl.c:1909–1916` | ODX token hash uses only 4 bytes of 16-byte nonce → degenerate O(n) collision under load | N/A (performance/DoS) | Use `jhash()` or `full_name_hash()` over all 16 nonce bytes |

---

## Missing Features (P2)

| ID | FSCTL | File:Line | Description |
|----|-------|-----------|-------------|
| P2-VNI-02 | VALIDATE_NEGOTIATE_INFO | `ksmbd_fsctl.c:1538` | ServerGuid in response is zeroed; should be `server_conf.guid` |
| P2-CC-03 | FSCTL_COPYCHUNK | `smb2_ioctl.c:557`, `ksmbd_fsctl_extra.c:310`, `ksmbd_fsctl.c:967` | Three independent copychunk implementations; only `ksmbd_fsctl.c` is active (dispatch runs first), the other two are dead code and a maintenance burden |
| P2-VSS-01 | ENUMERATE_SNAPSHOTS | VFS open path | @GMT-token paths not resolved during SMB2 CREATE; snapshot enumeration works but snapshot file access does not |
| P2-ODX-02 | OFFLOAD_READ | `ksmbd_fsctl.c:2034` | `TokenTimeToLive` from client request is read but ignored; tokens never expire, causing unbounded memory growth |
| P2-ODX-03 | OFFLOAD_WRITE | `ksmbd_fsctl.c:2209` | Source file lookup restricted to session; MS-FSCC does not restrict cross-session ODX |
| P2-RRK-01 | REQUEST_RESUME_KEY | `smb2_ioctl.c:542` | Legacy handler is dead code (registered handler wins); should be removed |
| P2-DUP-01 | DUPLICATE_EXTENTS_TO_FILE | `ksmbd_fsctl.c:1149` | Missing FILE_READ_DATA access check on source handle; legacy handler had it but registered handler does not |

---

## Partial Implementation (P3)

| ID | Feature | File:Line | Status |
|----|---------|-----------|--------|
| P3-BC-01 | BranchCache secret | `ksmbd_branchcache.c:49` | Server secret (Ks) never rotated; acknowledged in TODO comment |
| P3-BC-02 | BranchCache HASH_BASED | `ksmbd_fsctl.c:2329` | `SRV_HASH_RETRIEVE_HASH_BASED` returns STATUS_HASH_NOT_PRESENT |
| P3-BC-03 | BranchCache V2 | `ksmbd_branchcache.c:662` | SHA-512 (V2) not implemented; V1 only |
| P3-RES-01 | Resilient handles reconnect | `ksmbd_resilient.c` | Handle is preserved on disconnect but re-open/reclaim path not implemented |
| P3-RES-02 | Resilient timeout cap | `ksmbd_resilient.c:39` | Capped at 5 minutes; spec says SHOULD honor client-requested timeout |
| P3-VSS-02 | Snapshot backend | `ksmbd_vss.c:373` | btrfs backend assumes snapper layout; native btrfs subvolume snapshots not supported |
| P3-WIT-01 | Witness RPC integration | `ksmbd_witness.c` | Kernel side tracks state; no IPC path from userspace RPC register call wired in |
| P3-WIT-02 | Witness notify IPC | `ksmbd_witness.c:486` | `ksmbd_ipc_witness_notify()` called but userspace handler unconfirmed |
| P3-NIC-01 | IPv6 iteration lock | `ksmbd_fsctl.c:912` | `idev6->addr_list` iterated without `rcu_read_lock()` (legacy version has the lock) |

---

## Low Priority (P4)

| ID | File:Line | Description |
|----|-----------|-------------|
| P4-CC-01 | `ksmbd_fsctl.c:997` | Off-by-one in chunk count check (`>=` vs `>`) means max chunk count is one fewer than configured; at the default of 256 this is irrelevant but at the MS-SMB2 recommended 16 it matters |
| P4-CC-02 | `ksmbd_config.c:70` | Max chunk count allows up to 65535; MS-SMB2 §3.3.5.15.6 recommends 16; very large values could trigger large kernel allocations |
| P4-BC-04 | `ksmbd_branchcache.c` | No cache eviction; xattr cache size bounded by filesystem xattr limit, not configurable |
| P4-WIT-03 | `ksmbd_witness.c` | IPv6 addresses not monitored for link-state changes; only IPv4 addresses iterated in `witness_netdev_event()` (line 546) |

---

## SMB3 FSCTL Compliance Matrix

| FSCTL | Code | Status | Notes |
|-------|------|--------|-------|
| FSCTL_VALIDATE_NEGOTIATE_INFO | 0x00140204 | Partial | Registered; validates fields but **must disconnect on mismatch** (P1); ServerGuid zeroed (P2) |
| FSCTL_SRV_COPYCHUNK | 0x001440F2 | Functional | Registered; limits configurable; uses vfs_copy_file_range; off-by-one in count check (P4) |
| FSCTL_SRV_COPYCHUNK_WRITE | 0x001480F2 | Functional | Same as above, no read-access check on dst |
| FSCTL_SRV_REQUEST_RESUME_KEY | 0x00140078 | Functional | Registered; returns 24-byte key correctly |
| FSCTL_OFFLOAD_READ (ODX) | 0x00094264 | Partial | Registered; token issued; no TTL enforcement (P2); poor hash key (P1) |
| FSCTL_OFFLOAD_WRITE (ODX) | 0x00098268 | Partial | Registered; token validated; inode-gen check; session-local only (P2) |
| FSCTL_SRV_ENUMERATE_SNAPSHOTS | 0x00144064 | Partial | Registered; correct response format; @GMT access not wired into CREATE (P2) |
| FSCTL_SRV_READ_HASH (BranchCache) | 0x001441BB | Partial | Registered; V1 SHA-256 functional; HASH_BASED not supported (P3); no secret rotation (P3) |
| FSCTL_LMR_REQUEST_RESILIENCY | 0x001401D4 | Partial | Registered; handle marked resilient; reconnect path incomplete (P3) |
| FSCTL_QUERY_NETWORK_INTERFACE_INFO | 0x001401FC | Functional | Registered; IPv4+IPv6; RDMA flag; speed from ethtool; IPv6 missing rcu_read_lock (P3) |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | 0x00098344 | Partial | Registered; vfs_clone_file_range; missing source daccess check (P2) |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX | 0x000983E8 | Partial | Registered; ATOMIC flag honored via vfs_clone; missing daccess check |
| FSCTL_GET_INTEGRITY_INFORMATION | 0x0009027C | Functional | Registered; returns CHECKSUM_TYPE_NONE |
| FSCTL_SET_INTEGRITY_INFORMATION | 0x0009C280 | Stub | Registered; silently accepts; correct for non-ReFS |
| FSCTL_SET_INTEGRITY_INFORMATION_EX | 0x00090380 | Stub | Same handler as SET; silently accepts |
| FSCTL_QUERY_FILE_REGIONS | 0x00090284 | Partial | Registered; returns single valid-data region; no sparse awareness |
| FSCTL_SET_ZERO_DATA | 0x000980C8 | Functional | Registered (x3); vfs_fallocate ZERO_RANGE |
| FSCTL_QUERY_ALLOCATED_RANGES | 0x000940CF | Functional | Registered; SEEK_DATA/SEEK_HOLE via lseek |
| FSCTL_SET_SPARSE | 0x000900C4 | Functional | Registered; DOS attr updated |
| FSCTL_FILE_LEVEL_TRIM | 0x00098208 | Functional | Registered (extra); FALLOC_FL_PUNCH_HOLE |
| FSCTL_PIPE_WAIT | 0x00110018 | Stub | Returns success; no named pipe semantics |
| FSCTL_PIPE_TRANSCEIVE | 0x0011C017 | Functional | Registered; forwards to userspace RPC |
| FSCTL_PIPE_PEEK | 0x0011400C | Stub | Returns zero-filled response |
| FSCTL_GET_COMPRESSION / SET | 0x0009003C/C040 | Functional | DOS attribute based |
| FSCTL_GET_OBJECT_ID / SET / DELETE | 0x00090098–A0 | Functional | xattr-backed, fallback inode-based |
| FSCTL_CREATE_OR_GET_OBJECT_ID | 0x000900C0 | Functional | Creates on demand |
| FSCTL_GET_NTFS_VOLUME_DATA | 0x00090064 | Stub | Returns vfs_statfs-based approximation |
| FSCTL_GET_RETRIEVAL_POINTERS | 0x00090073 | Stub | Returns single artificial extent |
| FSCTL_FILESYSTEM_GET_STATS | 0x00090060 | Stub | Returns NTFS type, zero counters |
| FSCTL_IS_VOLUME_DIRTY | 0x00090078 | Stub | Returns 0 (not dirty) |
| FSCTL_IS_PATHNAME_VALID | 0x0009002C | Stub | Returns success |
| FSCTL_MARK_HANDLE | 0x000900FC | Stub | Validates handle, returns success |
| FSCTL_FIND_FILES_BY_SID | 0x0009008F | Not supported | STATUS_NOT_SUPPORTED |
| FSCTL_READ_FILE_USN_DATA | 0x000900EB | Not supported | STATUS_NOT_SUPPORTED |
| FSCTL_WRITE_USN_CLOSE_RECORD | 0x000900EF | Not supported | STATUS_NOT_SUPPORTED |
| FSCTL_SIS_COPYFILE | 0x00090100 | Not supported | STATUS_NOT_SUPPORTED |
| FSCTL_RECALL_FILE | 0x00090117 | Not supported | STATUS_NOT_SUPPORTED |
| FSCTL_QUERY_FAT_BPB | 0x00090058 | Not supported | STATUS_NOT_SUPPORTED |
| FSCTL_SET_DEFECT_MANAGEMENT | 0x00098134 | Not supported | STATUS_NOT_SUPPORTED |
| FSCTL_SET_ENCRYPTION | 0x000900D7 | Not supported | STATUS_NOT_SUPPORTED (EFS not applicable) |
| FSCTL_READ_RAW_ENCRYPTED | 0x000900E3 | Not supported | STATUS_NOT_SUPPORTED |
| FSCTL_WRITE_RAW_ENCRYPTED | 0x000900DF | Not supported | STATUS_NOT_SUPPORTED |
| FSCTL_LMR_GET_LINK_TRACK_INF | 0x001400E8 | Not supported | STATUS_NOT_SUPPORTED |
| FSCTL_QUERY_ON_DISK_VOLUME_INFO | 0x009013C0 | Not supported | STATUS_NOT_SUPPORTED (non-NTFS) |
| FSCTL_DFS_GET_REFERRALS | 0x00060194 | Not in table | Handled via ksmbd_dfs.c path, not FSCTL dispatch |
| FSCTL_QUERY_SHARED_VIRTUAL_DISK | 0x00090300 | Not implemented | MS-RSVD; no VHD support |

---

## Summary

The FSCTL infrastructure is well-organized with a pluggable RCU hash-table
dispatch (`ksmbd_dispatch_fsctl`) that is both correct and extensible.
Coverage is broad: nearly all common SMB3 FSCTLs are at minimum stubbed,
and the server-side copy, ODX, BranchCache, snapshot enumeration, resilient
handles, and witness protocol all have substantive (not merely stub)
implementations.

The single highest-priority correctness bug is **P1-VNI-01**: a
VALIDATE_NEGOTIATE_INFO mismatch must cause transport disconnection per
MS-SMB2 §3.3.5.15.12, but currently only returns an error code. This is
the primary downgrade-attack protection gap.

The most significant feature gap is **P2-VSS-01**: snapshot enumeration
works but the @GMT path resolution is not wired into the VFS open path,
so clients cannot actually open files from snapshots despite seeing them
in the "Previous Versions" tab.
