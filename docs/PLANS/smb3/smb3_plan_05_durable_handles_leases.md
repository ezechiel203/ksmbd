# SMB3 Plan 05: Durable Handles, Persistent Handles, and Leases

**Audit date:** 2026-03-01
**Branch:** phase1-security-hardening
**Files audited:**
- `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c`
- `/home/ezechiel203/ksmbd/src/fs/oplock.c`
- `/home/ezechiel203/ksmbd/src/include/fs/oplock.h`
- `/home/ezechiel203/ksmbd/src/fs/vfs_cache.c`
- `/home/ezechiel203/ksmbd/src/include/fs/vfs_cache.h`
- `/home/ezechiel203/ksmbd/src/include/protocol/smb2pdu.h`
- `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_ioctl.c`
- `/home/ezechiel203/ksmbd/src/fs/ksmbd_resilient.c`
- `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2ops.c`
- `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_misc_cmds.c`
- `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_tree.c`

---

## Durable Handle v1 (DHnQ / DHnC)

### DHnQ — Durable Handle Request v1 (MS-SMB2 §2.2.13.2.3, §3.3.5.9.7)

**Parsing and grant gate:**
`smb2_create.c:788` defines the tag array `{"DH2C", "DHnC", "DH2Q", "DHnQ"}` and iterates over it in `parse_durable_handle_context()` (line 778). The `DURABLE_REQ` case (line 939) is reached when context tag "DHnQ" is found. The grant is conditional:

```c
// smb2_create.c:948-952
if ((lc && (lc->req_state & SMB2_LEASE_HANDLE_CACHING_LE)) ||
    req_op_level == SMB2_OPLOCK_LEVEL_BATCH) {
    ksmbd_debug(SMB, "Request for durable open\n");
    dh_info.type = dh_idx;
}
```

This correctly implements the spec requirement that a durable handle requires either a BATCH oplock OR a lease with Handle Caching (`SMB2_LEASE_HANDLE_CACHING`).

**Flag assignment on reconnectable open:**
`smb2_create.c:2208-2214`:
```c
if (dh_info.type == DURABLE_REQ_V2 || dh_info.type == DURABLE_REQ) {
    if (dh_info.type == DURABLE_REQ_V2 && dh_info.persistent && ...)
        fp->is_persistent = true;
    else
        fp->is_durable = true;
    // v1: no timeout is set, fp->durable_timeout stays 0
}
```

**Durable timeout for v1 — MISSING:**
For `DURABLE_REQ` (DHnQ v1), `fp->durable_timeout` is **never assigned**. It remains `0`. The durable scavenger in `vfs_cache.c:1117-1118` skips handles where `!fp->durable_timeout && !(fp->is_resilient && fp->resilient_timeout)`. The session disconnect path at `vfs_cache.c:1239-1241` sets `durable_scavenger_timeout` only when `fp->durable_timeout` is non-zero.

The net effect: **DHnQ durable handles are immortal**. They are preserved across disconnects (`is_reconnectable()` returns `true` at `vfs_cache.c:1029-1033`) but the scavenger never expires them. After a disconnect the handle leaks indefinitely unless the client reconnects and explicitly closes it, or the server restarts.

MS-SMB2 §3.3.5.9.7 requires the server to apply an implementation-defined reconnect timeout (typically the session timeout or a server-configurable window). The spec does not mandate a specific value but explicitly states the server should not keep the handle forever.

**Response context:** `create_durable_rsp_buf()` at `oplock.c:1949-1966` emits a well-formed DHnQ response with `Name[4]="DHnQ"`, `DataLength=8`, and the 8-byte Reserved/Data area zeroed. The NameOffset points to `create_durable_rsp.Name` and the DataOffset to `Data`. This is structurally correct.

### DHnC — Durable Handle Reconnect v1 (MS-SMB2 §2.2.13.2.4, §3.3.5.9.10)

**Parsing:** `smb2_create.c:851-890` handles tag "DHnC" (DURABLE_RECONN case). Reads `PersistentFileId` from `recon->Data.Fid.PersistentFileId`.

**FileId lookup:** `ksmbd_lookup_durable_fd(persistent_id)` at `smb2_create.c:870`. The function at `vfs_cache.c:718-733` searches the global file table and rejects handles that are: scavenger-claimed, still connected (`fp->conn != NULL`), or whose timeout has already expired. This is correct.

**Client GUID check:** `smb2_create.c:878-884` validates `fp->client_guid` against `conn->ClientGUID`. Prevents cross-client reconnect theft. Correct.

**Lease key check — MISSING for DHnC:**
MS-SMB2 §3.3.5.9.10 step 7 requires: "If the create request also includes a DHnC context, the server MUST verify that the LeaseKey in the lease request matches the LeaseKey of the Open." The DHnC path in `DURABLE_RECONN` does **not** require `lc` (lease context) to be present and does not check the lease key against `fp->opinfo->o_lease->lease_key`. The lease key match is only performed in `smb2_check_durable_oplock()` at `oplock.c:2263-2329`, which is called for both reconnect paths. However, for the v1 DHnC path, the spec states that a lease SHOULD be present if the original handle held a lease, and the key MUST match.

**Access/share mode restoration:** `ksmbd_reopen_durable_fd()` (called at `smb2_create.c:1311`) reopens the underlying `struct file` and re-registers the handle. The original `daccess`, `saccess`, `coption`, `cdoption` are preserved on `fp` since they were never erased at disconnect time. This is correct.

**Oplock re-grant:** Not re-granted. The oplock/lease state on `fp->f_opinfo` is preserved in-kernel across the disconnect since only `fp->conn` is set to NULL (not the opinfo). On reconnect the existing opinfo is reused. This matches the spec.

**Timeout window enforcement:** `ksmbd_lookup_durable_fd()` checks `fp->durable_scavenger_timeout < jiffies_to_msecs(jiffies)` but, as noted above, DHnQ sets no timeout, so this check is never triggered for v1 handles.

---

## Durable Handle v2 (DH2Q / DH2C)

### DH2Q — Durable Handle Request v2 (MS-SMB2 §2.2.13.2.11, §3.3.5.9.12)

**Parsing:** `smb2_create.c:892-937` (DURABLE_REQ_V2 case). Reads `durable_v2_blob->Timeout`, `durable_v2_blob->Flags`, `durable_v2_blob->CreateGuid`.

**Timeout clamping:** `smb2_create.c:2219-2224`:
```c
if (dh_info.timeout)
    fp->durable_timeout =
        min_t(unsigned int, dh_info.timeout,
              DURABLE_HANDLE_MAX_TIMEOUT);  // 300000 ms = 5 min
else
    fp->durable_timeout = 60;  // 60 ms (!) — BUG, should be 60000 ms
```
**BUG:** The default timeout when the client sends `Timeout=0` is `60` (sixty milliseconds), not sixty seconds. The `DURABLE_HANDLE_MAX_TIMEOUT` is correctly `300000` ms (smb2pdu.h:712), and client-specified timeouts are clamped to that. But when the client specifies `Timeout=0` (meaning "use server default"), MS-SMB2 §3.3.5.9.12 says the server assigns its own configured default. Sixty milliseconds is essentially zero and will cause the scavenger to immediately expire the handle on the first scavenger tick, defeating the purpose of v2 durable handles.

**Flags/persistent:** `smb2_create.c:2209-2212` correctly checks `dh_info.persistent && test_share_config_flag(...CONTINUOUS_AVAILABILITY)` to set `fp->is_persistent`.

**Flags value check — PARTIAL BUG:** `dh_info.persistent = le32_to_cpu(durable_v2_blob->Flags)` at `smb2_create.c:932`. The spec defines `SMB2_DHANDLE_FLAG_PERSISTENT = 0x00000002`. The raw `Flags` field is used as a boolean, so any non-zero Flags value (including reserved bits) would be treated as "persistent requested". Spec-correct would be `dh_info.persistent = !!(le32_to_cpu(durable_v2_blob->Flags) & SMB2_DHANDLE_FLAG_PERSISTENT)`.

**CreateGuid stored:** `smb2_create.c:2217` copies `CreateGuid` into `fp->create_guid`. Correct.

**DH2Q response:** `create_durable_v2_rsp_buf()` at `oplock.c:1973-1994`:
```c
buf->Timeout = cpu_to_le32(fp->durable_timeout);
if (fp->is_persistent)
    buf->Flags = cpu_to_le32(SMB2_DHANDLE_FLAG_PERSISTENT);
```
Correctly echoes the server-assigned timeout and the persistent flag back to the client.

**Replay detection:** `smb2_create.c:916-924` checks `SMB2_FLAGS_REPLAY_OPERATIONS` before allowing a DH2Q re-use on an existing handle. Correct.

### DH2C — Durable Handle Reconnect v2 (MS-SMB2 §2.2.13.2.12, §3.3.5.9.13)

**Parsing:** `smb2_create.c:802-849` (DURABLE_RECONN_V2 case). Reads both `Fid.PersistentFileId` and `CreateGuid`.

**CreateGuid match:** `smb2_create.c:828-833`:
```c
if (memcmp(dh_info.fp->create_guid, recon_v2->CreateGuid, SMB2_CREATE_GUID_SIZE)) {
    err = -EBADF;
    ksmbd_put_durable_fd(dh_info.fp);
    goto out;
}
```
Correctly validates CreateGuid.

**Client GUID check:** `smb2_create.c:836-843` validates `ClientGUID` against stored `fp->client_guid`. Correct.

**Flags (persistent) check:** The `create_durable_reconn_v2_req.Flags` field is parsed at `smb2_create.c:819` (`recon_v2->Flags`), but `dh_info.persistent` is NOT set for the reconnect path. The spec (§3.3.5.9.13) requires the server to check `Open.IsPersistent` against the reconnect request's persistent flag. There is no explicit Flags validation during DH2C reconnect — the server trusts the stored `fp->is_persistent`. This is acceptable but does not fully validate the client's reconnect intent.

**Lease state restoration:** Handled via `smb2_check_durable_oplock()` at `oplock.c:2263-2329` which enforces lease key match, handle-caching bit, and version consistency.

---

## Persistent Handles

**Capability advertisement:**
- SMB 3.0 (`init_smb3_0_server`): `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` is **NOT advertised** (only LEASING and DIRECTORY_LEASING). `smb2ops.c:272-300`.
- SMB 3.02 (`init_smb3_02_server`): `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` is advertised when `KSMBD_GLOBAL_FLAG_DURABLE_HANDLE` is set. `smb2ops.c:331-332`. Correct.
- SMB 3.11 (`init_smb3_11_server`): `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` is advertised when `KSMBD_GLOBAL_FLAG_DURABLE_HANDLE` is set. `smb2ops.c:364-365`. Correct.

MS-SMB2 §3.3.5.3.1 says persistent handles require dialect 3.0 or higher. Not advertising for SMB 3.0 is technically a compliance gap, but an acceptable conservative choice.

**CA share flag:** `KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY = BIT(16)` defined in `ksmbd_netlink.h:549`. Set via `ksmbd.mountd` configuration. The tree connect response advertises `SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY` when this flag is set and `KSMBD_GLOBAL_FLAG_DURABLE_HANDLE` is active (`smb2_tree.c:247-250`). Correct.

**Persistent handle = server-restart survival — NOT IMPLEMENTED:**
In the actual spec, a persistent handle must survive a server crash and restart. This requires the handle state to be written to **stable storage** (e.g., disk) so it can be recovered after reboot. In KSMBD, `fp->is_persistent = true` sets a flag in memory only. There is no serialization of the open state to disk, no recovery mechanism, and no persistent-handle table that survives a crash. This means KSMBD's "persistent" handles are in practice just durable handles that don't time out — they survive clean session loss but NOT server restarts. This is a fundamental limitation that cannot be fixed without a significant architectural addition.

**Stable storage requirement:** MS-SMB2 §3.3.1.15 defines "GlobalOpenTable" which for persistent handles must be backed by stable storage. KSMBD has no such backing.

---

## Lease v1 (RqLs)

**Parsing:** `parse_lease_state()` at `oplock.c:1839-1886`. Searches for context tag "RqLs" (4 bytes). Distinguishes v1 vs v2 by DataLength: if `sizeof(struct lease_context_v2)` (44 bytes) it is v2, otherwise v1.

**LeaseState bits:** Defined in `smb2pdu.h:887-890`:
```c
#define SMB2_LEASE_READ_CACHING_LE    cpu_to_le32(0x01)  // correct
#define SMB2_LEASE_HANDLE_CACHING_LE  cpu_to_le32(0x02)  // correct
#define SMB2_LEASE_WRITE_CACHING_LE   cpu_to_le32(0x04)  // correct
```
These match MS-SMB2 §2.2.13.2.8.

**LeaseKey:** 16 bytes, copied at `oplock.c:109` and stored in `lease->lease_key`. The key is compared via `compare_guid_key()` at `oplock.c:599-611` against `(ClientGUID, LeaseKey)`. Correct.

**Lease table keyed on ClientGUID:** `add_lease_global_list()` at `oplock.c:1307-1335` uses `opinfo->conn->ClientGUID` to create or find a `lease_table`. The table is a global list of `lease_table` objects, each containing a per-client `lease_list`. This correctly implements the per-client-GUID lease table required by §3.3.1.11.

**Duplicate lease key detection:** `find_same_lease_key()` at `oplock.c:1242-1290` prevents the same lease key from being used on two different files by the same client. Correct.

**Lease break notification:** `smb2_lease_break_noti()` at `oplock.c:1055-1097` sends a lease break notification. The structure at `oplock.c:1022`:
```c
rsp->StructureSize = cpu_to_le16(44);  // correct — 44 bytes for lease break
```
`SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED` is set when `curr_state` contains Write or Handle caching (`oplock.c:1026-1028`). Correct.

**Lease break acknowledgement:** `smb21_lease_break_ack()` at `smb2_misc_cmds.c:404-550` handles the client's ack. The dispatcher at `smb2_misc_cmds.c:567-573` switches on `StructureSize`: 24=oplock break, 36=lease break ack. `OP_BREAK_STRUCT_SIZE_21 = 36` is defined at `smb2pdu.h:1620`. Correct.

**Lease upgrade (none -> state):** `lease_none_upgrade()` at `oplock.c:449-471` handles upgrade from NONE to any state. Called from `same_client_has_lease()` at `oplock.c:673-677`. Correct.

**Lease upgrade (read -> write):** `same_client_has_lease()` at `oplock.c:655-660` upgrades a READ lease to include WRITE if only one open exists and the request includes WRITE. Calls `lease_read_to_write()`. Correct.

---

## Lease v2 (RqL2) and Directory Leases

**Parsing:** `parse_lease_state()` at `oplock.c:1853-1868` reads v2 fields when `DataLength == sizeof(struct lease_context_v2)` (44 bytes). Reads: `LeaseKey`, `LeaseState`, `LeaseFlags`, `Epoch`, `LeaseDuration`, `ParentLeaseKey` (if `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE` set). Sets `lreq->version = 2`.

**ParentLeaseKey:** `oplock.h:39` defines `parent_lease_key[SMB2_LEASE_KEY_SIZE]`. Correctly parsed at `oplock.c:1865-1867` when the flag is set.

**Directory leases:** `smb2_create.c:2031-2034`:
```c
if (S_ISDIR(file_inode(filp)->i_mode)) {
    lc->req_state &= ~SMB2_LEASE_WRITE_CACHING_LE;
    lc->is_dir = true;
}
```
Correctly strips WRITE caching for directories (spec §3.3.5.9.8 step 8: "If the open is a directory, the server MUST clear the SMB2_LEASE_WRITE_CACHING bit"). The `lc->is_dir` flag is propagated into `lease->is_dir` at `oplock.c:114`.

**Directory lease gate in smb_grant_oplock:** `oplock.c:1465-1471`:
```c
if (S_ISDIR(file_inode(fp->filp)->i_mode)) {
    if (!lctx || lctx->version != 2 ||
        (lctx->flags != SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE &&
         !lctx->epoch))
        return 0;
}
```
This only allows leases on directories when the lease is v2. V1 directory leases are silently dropped (returns 0 = no oplock). Correct per spec — directory leases require v2 (§3.3.5.9.11).

**Epoch field:** Stored in `lease->epoch` after increment (`oplock.c:117`: `lease->epoch = le16_to_cpu(lctx->epoch) + 1`). The v2 response echoes the current epoch via `create_lease_buf()` at `oplock.c:1797`:
```c
buf->lcontext.Epoch = cpu_to_le16(lease->epoch);
```

**Epoch in lease break:** `smb2_lease_break_noti()` at `oplock.c:1074-1077`:
```c
if (lease->version == 2)
    br_info->epoch = cpu_to_le16(++lease->epoch);
else
    br_info->epoch = 0;
```
Correctly increments the epoch and sends it in the break notification for v2 leases only.

**Capability advertisement (DIRECTORY_LEASING):**
- SMB 3.0: advertised when `KSMBD_GLOBAL_FLAG_SMB2_LEASES` is set (`smb2ops.c:285-286`).
- SMB 3.02: advertised when `KSMBD_GLOBAL_FLAG_SMB2_LEASES` is set (`smb2ops.c:320-321`).
- SMB 3.11: advertised when `KSMBD_GLOBAL_FLAG_SMB2_LEASES` is set (`smb2ops.c:358-359`).
Correct.

**Parent lease break notification:** `smb_send_parent_lease_break_noti()` at `oplock.c:1358-1395` breaks the parent directory's lease when a child file is opened. Correctly dispatched from `smb2_create.c:2041`. Correct behavior per §3.3.5.9.11 step 6.

**Lazy parent break on close:** `smb_lazy_parent_lease_break_close()` at `oplock.c:1397-1440` breaks the parent directory's lease when a file handle is closed. Called via `fp->reserve_lease_break` at `close_id_del_oplock()` (`oplock.c:481-482`). Correct.

**v1 lease — context name collision — POTENTIAL BUG:**
`parse_lease_state()` searches only for `SMB2_CREATE_REQUEST_LEASE = "RqLs"` (tag length 4). There is no "RqL2" tag. Both v1 and v2 lease contexts use the tag "RqLs"; the distinction is made by DataLength. This is correct per spec — both v1 and v2 contexts use the same 4-character tag "RqLs".

---

## Resilient Handles

**FSCTL code:** Defined as `FSCTL_LMR_REQUEST_RESILIENCY = 0x001401D4` in `smbfsctl.h:81`. The comment in `ksmbd_resilient.c:8` states "(0x001401D4)". Note: some sources cite the code as `0x001D0008` — this is incorrect; the correct Windows FSCTL code is `0x001401D4`. KSMBD uses the correct value.

**FSCTL registration:** `ksmbd_resilient_init()` at `ksmbd_resilient.c:123-136` registers `resilient_handler` with `ctl_code = FSCTL_LMR_REQUEST_RESILIENCY`. Called from `server.c:905`. Correct.

**Timeout parsing:** `ksmbd_fsctl_request_resiliency()` at `ksmbd_resilient.c:60-106` reads `le32_to_cpu(req->timeout)` from a `NETWORK_RESILIENCY_REQUEST` structure. The request structure `{__le32 timeout; __le32 reserved;}` matches §2.2.31.4. Correct.

**Timeout capping:** Server caps at `KSMBD_MAX_RESILIENT_TIMEOUT_MS = 5 * 60 * 1000 = 300000 ms`. The spec allows servers to impose an upper limit. Correct.

**Flag setting:** `fp->is_resilient = true; fp->resilient_timeout = timeout_ms;` at `ksmbd_resilient.c:96-97`. Correct.

**Scavenger integration:** `vfs_cache.c:1027-1028`: `is_reconnectable()` returns true when `fp->is_resilient || fp->is_persistent`. The scavenger at `vfs_cache.c:1117-1118` skips handles that lack either `durable_timeout` or `(is_resilient && resilient_timeout)`. The session disconnect at `vfs_cache.c:1242-1244` sets the scavenger deadline when `is_resilient && resilient_timeout`. Correct.

**Resilient reconnect — PARTIAL:**
The spec §3.3.5.15.9 states that after a resilient FSCTL the server should preserve the handle on disconnect for the specified timeout. KSMBD does preserve the handle. However, the **reconnect path uses DHnC/DH2C** create contexts. A pure resilient-handle reconnect (without durable context, just a new session and a matching volatile-id-aware create) is not explicitly handled. In practice, Windows clients that use FSCTL_LMR_REQUEST_RESILIENCY also tend to use DH2Q/DH2C for reconnect, so this is a low-risk gap.

**Output buffer:** Per spec, the FSCTL response has no output data. `ksmbd_resilient.c:103`: `*out_len = 0`. Correct.

---

## Oplock Break for Leases

### SMB2 OPLOCK_BREAK notification for leases (MS-SMB2 §3.3.4.6)

**StructureSize differentiation:** The spec defines two distinct structures sharing the `SMB2_OPLOCK_BREAK` command:
- Oplock break: `StructureSize = 24` (`smb2pdu.h:1451`, `OP_BREAK_STRUCT_SIZE_20 = 24`)
- Lease break notification: `StructureSize = 44` (`smb2pdu.h:1463`)
- Lease break ack response: `StructureSize = 36` (`smb2pdu.h:1476`, `OP_BREAK_STRUCT_SIZE_21 = 36`)

**Lease break notification sends StructureSize=44:** `oplock.c:1022`:
```c
rsp->StructureSize = cpu_to_le16(44);  // correct
```

**Oplock break notification sends StructureSize=24:** `oplock.c:916`:
```c
rsp->StructureSize = cpu_to_le16(24);  // correct
```

**Lease break notification fields (§2.2.23.2):**
- `Epoch`: `oplock.c:1023`: `rsp->Epoch = br_info->epoch` — correct for v2, 0 for v1
- `Flags` (ACK_REQUIRED): `oplock.c:1026-1028` — set when break is from state with W or H caching
- `LeaseKey`: `oplock.c:1030`: `memcpy(rsp->LeaseKey, br_info->lease_key, SMB2_LEASE_KEY_SIZE)` — correct
- `CurrentLeaseState`: `oplock.c:1031`: `rsp->CurrentLeaseState = br_info->curr_state` — correct
- `NewLeaseState`: `oplock.c:1032`: `rsp->NewLeaseState = br_info->new_state` — correct
- `BreakReason`, `AccessMaskHint`, `ShareMaskHint`: all set to 0 (`oplock.c:1033-1035`) — correct (spec says these SHOULD be 0)

**FileId in lease break — MISSING:**
The `struct smb2_lease_break` at `smb2pdu.h:1461-1472` does **not** include a `PersistentFileId` or `VolatileFileId` field. This is correct per spec — the lease break notification is keyed on `LeaseKey`, not on a FileId. No issue here.

**Lease break acknowledgement (§2.2.24.2):**
`smb21_lease_break_ack()` at `smb2_misc_cmds.c:404-550`. The response:
```c
rsp->StructureSize = cpu_to_le16(36);  // correct
rsp->LeaseState = lease_state;  // echoes the new lease state
```
`lookup_lease_in_table()` is used to find the matching opinfo by `(ClientGUID, LeaseKey)`. Correct.

**Dispatcher:** `smb2_oplock_break()` at `smb2_misc_cmds.c:558-583` dispatches on `StructureSize`:
- `OP_BREAK_STRUCT_SIZE_20 = 24` → oplock ack
- `OP_BREAK_STRUCT_SIZE_21 = 36` → lease ack
Any other value returns `STATUS_INVALID_PARAMETER`. Correct.

**Lease break state machine transitions (§3.3.4.6.4):**
The `oplock_break()` function at `oplock.c:1121-1210` computes `new_state` based on current state:
- RWH → RH (when W break not due to truncate): `new_state = READ | HANDLE` (`oplock.c:1149-1152`)
- RW → R (W break not truncate): `new_state = READ` (`oplock.c:1153-1155`)
- RH → R (H break, not dir): `new_state = READ` (`oplock.c:1157-1160`)
- H → NONE (dir handle break): `new_state = NONE` (`oplock.c:1161-1163`)
- Any truncate: `new_state = NONE` (`oplock.c:1145-1147`)
This matches the spec state machine.

---

## Confirmed Bugs (P1)

### BUG-01: DHnQ (v1) durable handles never expire — handle leak
**File:line:** `smb2_create.c:2208-2225`, `vfs_cache.c:1117-1118`, `vfs_cache.c:1239-1241`
**Symptom:** A client opens a file with DHnQ (batch oplock or handle-caching lease), disconnects, and never reconnects. The handle stays alive indefinitely — the server never reclaims the kernel `struct file`, fd, and associated VFS resources. Under adversarial conditions (multiple disconnected durable handles) this can exhaust the server's file descriptor limits.
**Spec ref:** MS-SMB2 §3.3.5.9.7 — the server SHOULD apply a disconnect timeout (server-configurable reconnect window).
**Fix:** Assign a default `durable_timeout` for DHnQ handles. A reasonable default is 16 seconds (the Windows default for DHnQ). Set `fp->durable_timeout = 16000` (or a server-configurable value) in the `DURABLE_REQ` branch at `smb2_create.c:2208`.

### BUG-02: DH2Q default timeout is 60 ms (should be 60000 ms or server-defined)
**File:line:** `smb2_create.c:2224`
```c
fp->durable_timeout = 60;   // BUG: 60 milliseconds
```
**Symptom:** When a client sends DH2Q with `Timeout=0` (requesting the server's default), the server assigns 60 ms. The scavenger runs every few seconds, and the handle will be expired almost immediately. The client cannot reconnect within 60 ms after a TCP disconnect.
**Spec ref:** MS-SMB2 §3.3.5.9.12 — "If Timeout is 0, the server MUST assign an implementation-specific default timeout."
**Fix:** Change the default to a reasonable value, e.g., `fp->durable_timeout = 60000;` (60 seconds), or expose it as a server configuration parameter.

### BUG-03: DHnC lease key check not enforced for oplock-based durable handles
**File:line:** `smb2_create.c:851-890` (DURABLE_RECONN case)
**Symptom:** If the original DHnQ open was granted based on a BATCH oplock (not a lease), reconnect via DHnC checks only `ClientGUID` and `PersistentFileId`. There is no lease key to match in this case, which is correct. However, if the original open was granted based on `SMB2_LEASE_HANDLE_CACHING_LE`, the client MUST include a lease context ("RqLs") in the DHnC reconnect, and the lease key MUST match. The code calls `smb2_check_durable_oplock()` which does check this (`oplock.c:2297-2309`), so the bug is **partially mitigated**. Still, `smb2_check_durable_oplock()` at line 2272-2273 returns 0 (success) if `opinfo == NULL`, meaning a durable handle that lost its oplock (state was reset to NONE during break) can be reconnected without any lease check.
**Spec ref:** MS-SMB2 §3.3.5.9.10 step 7.
**Fix:** In `smb2_check_durable_oplock()`, if `opinfo == NULL` but `fp->is_durable == true`, fail the reconnect rather than silently succeeding.

---

## Missing Features (P2)

### P2-01: Persistent handles do not survive server restart
**Description:** `fp->is_persistent` is an in-memory flag. No handle state is written to stable storage. After a server crash and restart, all persistent handles are gone. MS-SMB2 §3.3.1.15 requires persistent handles to survive a server failure.
**Impact:** Clients expecting SMB3 CA (Continuously Available) semantics (Hyper-V, clustered environments) will fail to reconnect after a server restart.
**Files:** `vfs_cache.h:143` (`is_persistent`), `smb2_create.c:2209-2212`.

### P2-02: SMB2_GLOBAL_CAP_PERSISTENT_HANDLES not advertised for SMB 3.0
**Description:** `smb2ops.c:272-300` (`init_smb3_0_server`) does not set `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES`. MS-SMB2 §3.3.5.3.1 allows persistent handles on dialect 3.0+.
**Impact:** SMB 3.0 clients cannot use persistent handles even if the server supports them.
**Files:** `smb2ops.c:272-300`.

### P2-03: DH2C Flags not validated against Open.IsPersistent
**Description:** During DH2C reconnect, the `Flags` field from `create_durable_reconn_v2_req` is not validated against `fp->is_persistent`. A non-persistent handle can be reconnected with `Flags=SMB2_DHANDLE_FLAG_PERSISTENT` without rejection.
**Spec ref:** MS-SMB2 §3.3.5.9.13 step 5.
**Files:** `smb2_create.c:802-849`.

### P2-04: No resilient handle reconnect path independent of durable handles
**Description:** FSCTL_LMR_REQUEST_RESILIENCY marks `fp->is_resilient` and the scavenger preserves the handle. However, the reconnect path (`smb2_open()`) only processes DHnC/DH2C create contexts. There is no create context specifically for resilient handle reconnect. In practice, Windows clients combine resilient handles with DH2Q/DH2C, so this is partially mitigated, but it prevents pure resilient-handle reconnect.
**Spec ref:** MS-SMB2 §3.3.5.15.9.
**Files:** `ksmbd_resilient.c`, `smb2_create.c`.

### P2-05: `dh_info.persistent` uses raw Flags value instead of bitmask
**Description:** `smb2_create.c:932`: `dh_info.persistent = le32_to_cpu(durable_v2_blob->Flags)`. Uses integer truth value of the entire Flags field. Reserved bits being set would incorrectly trigger persistent mode.
**Fix:** Use `dh_info.persistent = !!(le32_to_cpu(durable_v2_blob->Flags) & SMB2_DHANDLE_FLAG_PERSISTENT)`.
**Files:** `smb2_create.c:932`.

---

## Partial (P3)

### P3-01: Lease v2 ParentLeaseKey only copied when PARENT_LEASE_KEY_SET flag is present
**Description:** `oplock.c:1865-1867` correctly copies `ParentLeaseKey` only when `lreq->flags == SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE`. The parent lease break logic in `smb_send_parent_lease_break_noti()` also checks this flag (`oplock.c:1377`). However, the equality check (`lctx->flags != SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE`) at `oplock.c:1377` uses `!=` rather than `!(flags & ...)`. If additional flags are set alongside `PARENT_LEASE_KEY_SET`, the parent break notification is skipped.
**Spec ref:** MS-SMB2 §2.2.13.2.10.
**Files:** `oplock.c:1377`.

### P3-02: Lease epoch starts at client_epoch + 1 rather than 1
**Description:** `oplock.c:117`: `lease->epoch = le16_to_cpu(lctx->epoch) + 1`. The client sends an Epoch in the create context; the server increments it by 1. The spec says the server assigns the initial epoch and increments it on each break. Starting from the client's epoch is a valid approach but may cause confusion if the client always sends 0 and the first server epoch is 1.
**Files:** `oplock.c:117`.

### P3-03: Lease break timeout is fixed at OPLOCK_WAIT_TIME = 35 seconds
**Description:** `oplock.h:13`: `#define OPLOCK_WAIT_TIME (35 * HZ)`. This is shared between oplock breaks and lease breaks. The spec allows configurable break timeouts. The 35-second value is reasonable for oplocks but may be too long for some lease scenarios.
**Files:** `oplock.h:13`.

### P3-04: DHnQ durable handle opinfo is preserved even if lease is revoked
**Description:** In `is_reconnectable()` at `vfs_cache.c:1029-1034`, the reconnect check requires the current opinfo to be present with the right state. If a lease is broken to NONE between disconnect and reconnect, `opinfo->is_lease == true` and `opinfo->o_lease->state` no longer contains `SMB2_LEASE_HANDLE_CACHING_LE`, causing `is_reconnectable()` to return false. The handle then gets closed instead of preserved for reconnect. This behavior is correct per spec, but may be surprising in edge cases.
**Files:** `vfs_cache.c:1014-1038`.

---

## Low Priority (P4)

### P4-01: `create_disk_id_rsp_buf` uses wrong NameOffset in ccontext
**Description:** `oplock.c:2033`: `buf->ccontext.NameOffset = cpu_to_le16(offsetof(struct create_mxac_rsp, Name))` — uses `create_mxac_rsp` as offset base instead of `create_disk_id_rsp`. The struct layouts differ and this produces an incorrect NameOffset for the QFid context. While clients may tolerate this (they can skip the context), it is a wire-format bug.
**Files:** `oplock.c:2033`.

### P4-02: DHnQ response uses "DHnQ" as Name rather than spec-defined name
**Description:** `oplock.c:1961-1965`: the response context name is "DHnQ". Per MS-SMB2 §2.2.14.2.3 the response context is `SMB2_CREATE_DURABLE_HANDLE_RESPONSE` which uses the same name "DHnQ". This is correct. No issue.

### P4-03: Lease break ACK response echoes `lease->state` (post-ack) not the requested state
**Description:** `smb2_misc_cmds.c:531`: `lease_state = lease->state` captures the lease state **after** the transition (e.g., after `opinfo_write_to_read()`). The ack response echoes the new state. MS-SMB2 §3.3.5.22.2.2 says the server MUST set `LeaseState` to the state that was granted. This is functionally correct.

### P4-04: Scavenger poll interval starts at 1 ms
**Description:** `vfs_cache.c:1093`: `unsigned int min_timeout = 1`. The scavenger thread initially wakes after 1 ms, then adjusts. The first iteration will always scan immediately and find nothing if no handles have expired, wasting CPU. Should start at a higher initial value (e.g., 1000 ms).
**Files:** `vfs_cache.c:1093`.

---

## Compliance Estimate per Area

| Feature Area | Compliance | Notes |
|---|---|---|
| **DHnQ — Request parsing and grant gate** | 95% | Correct oplock/lease-handle gate; only missing default timeout |
| **DHnQ — Disconnect preservation** | 60% | Handles are preserved but never reclaimed (BUG-01) |
| **DHnC — Reconnect v1** | 80% | ClientGUID check added; lease-key check delegated to `smb2_check_durable_oplock`; edge case if opinfo NULL |
| **DH2Q — Request parsing** | 80% | Good; default timeout is 60 ms (BUG-02); Flags uses raw value (P2-05) |
| **DH2Q — Response (Timeout, Flags)** | 95% | Correct timeout echo and persistent flag |
| **DH2C — Reconnect v2** | 85% | CreateGuid + ClientGUID checked; Flags not validated vs stored persistent state |
| **Persistent Handles (CA shares)** | 20% | In-memory only; no stable storage; does not survive server restart |
| **Lease v1 (RqLs) — Parsing** | 98% | Fully correct |
| **Lease v1 — Grant and break** | 90% | Correct state machine; correct notify structure sizes |
| **Lease v1 — Ack processing** | 90% | Full state machine, correct INVALID_OPLOCK_PROTOCOL handling |
| **Lease v2 (RqL2) — ParentLeaseKey** | 85% | Flags equality vs bitmask check (P3-01) |
| **Directory Leases** | 90% | v1 silently dropped for dirs (correct); v2 supported; parent break implemented |
| **Lease Epoch** | 90% | v2 break increments epoch; response echoes epoch; initial epoch = client+1 |
| **Resilient Handles — FSCTL** | 85% | FSCTL parsed and flag set; no independent reconnect path (P2-04) |
| **Resilient Handles — Scavenger** | 90% | Correctly integrated with durable scavenger |
| **Oplock Break StructureSize** | 100% | 24 for oplock, 44 for lease break notification, 36 for lease ack — all correct |
| **Lease Break State Machine** | 92% | Transitions correct; P3-01 flag check; break-to-none on truncate |
| **Lease Table (ClientGUID keyed)** | 95% | Global lease_table_list with per-client tables; correct |

**Overall durable/lease compliance: approximately 75%**. The implementation is functional for common use cases (Windows 10/11 clients with leases and DH2Q) but has two critical bugs (BUG-01, BUG-02) that cause resource leaks and failed reconnects for default-timeout scenarios, and persistent handles are in-memory only, disqualifying the server from true CA share scenarios.
