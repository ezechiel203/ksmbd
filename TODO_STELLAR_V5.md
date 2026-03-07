# TODO_STELLAR_V5.md — ksmbd Audit Cycle 5

Synthesized from 3 parallel audit agents (security, protocol, quality/stability).
Previous cycles: v1 (66→29), v2 (37→all), v3 (16→6+5OK), v4 (20→18+2deferred).

**Note**: 7 protocol findings were applied directly by the audit agent (marked APPLIED).
Build verified clean: zero errors, zero new warnings after all agent fixes.

---

## ALREADY APPLIED (7 — protocol compliance agent)

### PA-01: SESSION_SETUP BINDING + SessionId=0 not rejected — APPLIED
- **File**: `src/protocol/smb2/smb2_session.c`
- **Fix**: Added guard — BINDING flag with SessionId=0 returns STATUS_INVALID_PARAMETER (MS-SMB2 §3.3.5.5.2).

### PA-02: SESSION binding to IN_PROGRESS returns wrong status — APPLIED
- **File**: `src/protocol/smb2/smb2_session.c`
- **Fix**: Set STATUS_REQUEST_NOT_ACCEPTED explicitly (was STATUS_ACCESS_DENIED).

### PA-03: SESSION binding to guest session wrong status — APPLIED
- **File**: `src/protocol/smb2/smb2_session.c`
- **Fix**: STATUS_REQUEST_NOT_ACCEPTED (was STATUS_NOT_SUPPORTED).

### PA-04: CLOSE POSTQUERY_ATTRIB + stat failure returns STATUS_FILE_CLOSED — APPLIED
- **File**: `src/protocol/smb2/smb2_misc_cmds.c`
- **Fix**: Set STATUS_UNSUCCESSFUL when vfs_getattr fails (file was valid, stat failed).

### PA-05: FileCompressionInformation wrong CompressedFileSize — APPLIED
- **File**: `src/protocol/smb2/smb2_query_set.c`
- **Fix**: Non-compressed files: CompressedFileSize = stat.size (not blocks<<9) per MS-FSCC §2.4.7.

### PA-06: QUERY_DIRECTORY small buffer returns STATUS_INVALID_PARAMETER — APPLIED
- **File**: `src/protocol/smb2/smb2_dir.c`
- **Fix**: STATUS_INFO_LENGTH_MISMATCH (MS-SMB2 §3.3.5.17).

### PA-07: QUERY_INFO security descriptor overflow doesn't return required size — APPLIED
- **File**: `src/protocol/smb2/smb2_query_set.c`
- **Fix**: Response includes OutputBufferLength=secdesclen so client can retry with correct size.

---

## CRITICAL (4 — new, unimplemented)

### C-01: ODX token table unbounded growth — remote kernel OOM DoS
- **File**: `src/fs/ksmbd_fsctl.c:2226-2253` (`odx_token_store`)
- **Issue**: Every `FSCTL_OFFLOAD_READ` call allocates a `ksmbd_odx_token_entry` with no per-session or global cap. Client can loop with max `TokenTimeToLive` (~49 days), exhausting kernel heap. Lazy expiry in `odx_token_validate()` only fires on concurrent validates — never triggered if client never validates.
- **Fix**: Add `atomic_t odx_token_count`; reject when global count > 4096 or per-session count > 64. Add `delayed_work` GC timer in `ksmbd_fsctl_init()` to expire stale tokens.

### C-02: Sleep inside rwsem write lock in `ksmbd_session_rpc_open()`
- **File**: `src/mgmt/user_session.c:121-135`
- **Issue**: `ksmbd_session_rpc_open()` holds `down_write(&sess->rpc_lock)` then calls `ksmbd_rpc_open()` → `ipc_msg_send_request()` → `wait_event_interruptible_timeout()` (sleeps). All concurrent readers of `rpc_lock` (rpc_write, rpc_read, rpc_ioctl) block for the entire IPC round-trip. Same pattern in `ksmbd_session_rpc_clear_list()` via `__session_rpc_close()`.
- **Fix**: Release `rpc_lock` before calling `ksmbd_rpc_open/close`; re-acquire to add/remove the xarray entry. Match the pattern used in `ksmbd_rpc_write/read/ioctl`.

### C-03: `list_for_each_entry_rcu()` used under write-semaphore without RCU read lock
- **File**: `src/fs/vfs_cache.c:1392, 1547`
- **Issue**: `session_fd_check()` and `ksmbd_reopen_durable_fd()` hold `down_write(&ci->m_lock)` and use `list_for_each_entry_rcu()` on `ci->m_op_list`. The list is mutated with plain `list_add()`/`list_del()` (not RCU variants) under `m_lock`. Mixed RCU/non-RCU list operations triggers lockdep splat under `CONFIG_PROVE_RCU`.
- **Fix**: Replace `list_for_each_entry_rcu()` with `list_for_each_entry()` in paths that hold `ci->m_lock` write.

### C-04: Data race in `ksmbd_durable_scavenger_alive()` — `idr_is_empty` without lock
- **File**: `src/fs/vfs_cache.c:1204-1216`
- **Issue**: `idr_is_empty(global_ft.idr)` called without `global_ft.lock`. `idr_alloc_cyclic()`/`idr_remove()` modify it under `write_lock(&global_ft.lock)`. Not atomic — KCSAN data race. Called every loop iteration of the scavenger kthread.
- **Fix**: Either take `read_lock(&global_ft.lock)` around `idr_is_empty()`, or maintain a separate `atomic_t global_ft_count`.

---

## HIGH (6 — new, unimplemented)

### H-01: `fp->node` not removed from `m_fp_list` before `__ksmbd_close_fd` in global teardown
- **File**: `src/fs/vfs_cache.c:1462-1476` (`ksmbd_free_global_file_table`)
- **Issue**: Calls `__ksmbd_close_fd(NULL, fp)` without first removing `fp->node` from `ci->m_fp_list`. If `ksmbd_inode_free(ci)` runs (refcount hits zero), ci is freed while fp->node still points into it. Other fps sharing the ci would then have dangling list pointers.
- **Fix**: Add `down_write(&fp->f_ci->m_lock); list_del_init(&fp->node); up_write(&fp->f_ci->m_lock);` before each `__ksmbd_close_fd` call in `ksmbd_free_global_file_table`.

### H-02: Bare `refcount_dec` should be `opinfo_put` — silent refcount underflow risk
- **File**: `src/fs/oplock.c:186`
- **Issue**: `opinfo_get_list()` calls `refcount_dec(&opinfo->refcount)` on the rejected path. If this was the last reference, the object is not freed — `opinfo_put()` calls `free_opinfo()` on last-dec but bare `refcount_dec` does not.
- **Fix**: Replace `refcount_dec(&opinfo->refcount)` with `opinfo_put(opinfo)`.

### H-03: `__session_lookup()` annotated with wrong lock
- **File**: `src/mgmt/user_session.c:192`
- **Issue**: Annotated `__must_hold(&sessions_table_lock)` but internally asserts `rcu_read_lock_held()`. All callers hold RCU, not the mutex. Misleading annotation causes sparse to miss real locking bugs.
- **Fix**: Change annotation to `__must_hold(RCU)`.

### H-04: `ksmbd_rpc_open/close` rely on caller holding `rpc_lock` for `ksmbd_session_rpc_method`
- **File**: `src/transport/transport_ipc.c:955`, `src/mgmt/user_session.c:128`
- **Issue**: `ksmbd_rpc_open/close` call `ksmbd_session_rpc_method()` which has `lockdep_assert_held(&sess->rpc_lock)`, but don't take `rpc_lock` themselves — they rely on the outer caller. `ksmbd_rpc_write/read/ioctl` correctly take their own `down_read`. Inconsistent contract.
- **Fix**: Take `down_read/up_read(&sess->rpc_lock)` inside `ksmbd_rpc_open/close` themselves, removing the dependency on callers.

### H-05: `dget()` dentry leak when concurrent `ksmbd_inode_get()` write-lock race is lost
- **File**: `src/fs/vfs_cache.c:290-295`
- **Issue**: In `ksmbd_inode_get()`, if the write-lock re-lookup finds a concurrent ci (`tmpci != NULL`), it does `kfree(ci)` but never `dput(ci->m_de)` — the `dget()` taken in `ksmbd_inode_init()` is leaked.
- **Fix**: Add `dput(ci->m_de)` before `kfree(ci)` in the `tmpci != NULL` branch.

### H-06: `FSCTL_PIPE_TRANSCEIVE` routes RPC without validating file handle belongs to caller
- **File**: `src/fs/ksmbd_fsctl.c:1778-1829`
- **Issue**: `fsctl_pipe_transceive_handler()` passes client-controlled `volatile_id` directly to `ksmbd_rpc_ioctl(work->sess, id, ...)` without `ksmbd_lookup_fd_fast()` to verify the handle is open and belongs to the current tree. A client could route RPC to arbitrary IDs.
- **Fix**: Add `fp = ksmbd_lookup_fd_fast(work, id); if (!fp) return -ENOENT;` before the RPC call; verify `fp` is a named-pipe handle; `ksmbd_fd_put(work, fp)` after.

---

## MEDIUM (8 — new, unimplemented)

### M-01: `ksmbd_witness_register()` TOCTOU — per-session count check not atomic with insertion
- **File**: `src/mgmt/ksmbd_witness.c:195-285`
- **Issue**: Per-session count checked under `witness_reg_lock`, then lock released before insert. Two concurrent calls at the limit boundary both pass and both insert, exceeding per-session cap by 1.
- **Fix**: Hold `witness_reg_lock` for both the count check and the insertion.

### M-02: `SESSION_SETUP` buffer extension trusts `SecurityBufferOffset` for forced socket reads
- **File**: `src/core/connection.c:646-692`
- **Issue**: `SecurityBufferOffset + SecurityBufferLength` (both client-controlled) can force up to `MAX_STREAM_PROT_LEN` (~16MB) extra bytes read from socket, blocking a worker thread. No validation that `SecurityBufferOffset >= sizeof(struct smb2_sess_setup_req)`.
- **Fix**: Validate `SecurityBufferOffset >= offsetof(struct smb2_sess_setup_req, Buffer)` before trusting it. Cap `extra` to a reasonable SPNEGO token bound (e.g., 64KB).

### M-03: `FSCTL_QUERY_ALLOCATED_RANGES` — no read-access check on file handle
- **File**: `src/fs/ksmbd_fsctl_extra.c:182-239`
- **Issue**: File layout information returned to handles with no `FILE_READ_DATA` access. Write-only handles shouldn't enumerate allocated ranges.
- **Fix**: Add `if (!(fp->daccess & FILE_READ_DATA_LE))` → STATUS_ACCESS_DENIED after `ksmbd_lookup_fd_fast()`.

### M-04: `opinfo->conn` read-after-`refcount_inc_not_zero` without local snapshot
- **File**: `src/fs/oplock.c:1477-1495`
- **Issue**: In `smb_send_parent_lease_break_noti()` and `smb_lazy_parent_lease_break_close()`, `opinfo->conn` is read for `ksmbd_conn_releasing()` check AFTER `refcount_inc_not_zero`. Between those two points, a concurrent `free_opinfo()` could null `opinfo->conn`, causing NULL deref.
- **Fix**: Copy `opinfo->conn` to a local variable before `refcount_inc_not_zero()`, use only the local for subsequent checks.

### M-05: CopyChunk `chunk_count * sizeof(...)` missing `check_mul_overflow`
- **File**: `src/fs/ksmbd_fsctl.c:1068`, `src/fs/ksmbd_fsctl_extra.c:368`
- **Issue**: Multiplication `chunk_count * sizeof(struct srv_copychunk)` performed without overflow guard. Safe on 64-bit with current limits, but fragile on 32-bit or if limits change. Defensive improvement needed.
- **Fix**: Use `check_mul_overflow(chunk_count, sizeof(struct srv_copychunk), &chunks_sz)` before the bounds comparison.

### M-06: `smb2_notify()` — `argv` freed after `release_async_work()` creates fragile UAF race
- **File**: `src/protocol/smb2/smb2_notify.c:363-372`
- **Issue**: On the error path after `setup_async_work()` succeeds, `release_async_work()` is called (which stores cancel-callback pointer to `argv`), then `kfree(argv)` is called. If a concurrent cancel fires between these two calls, `argv` is double-freed.
- **Fix**: Zero the cancel argument pointer in the work struct before calling `release_async_work()` in error paths.

### M-07: Crypto context pool cap uses `num_online_cpus()` without preemption disable
- **File**: `src/core/crypto_ctx.c:164, 206`
- **Issue**: `num_online_cpus()` called in `ksmbd_find_crypto_ctx()` and `ksmbd_release_crypto_ctx()` can change between calls under CPU hotplug, causing pool size thrashing.
- **Fix**: Cache `num_online_cpus()` at module init time, or use `num_possible_cpus()` (stable).

### M-08: NDR `ndr_encode_dos_attr` — `change_time` error check outside `version==3` block
- **File**: `src/encoding/ndr.c:288-291`
- **Issue**: `if (da->version == 3) ndr_write_int64(da->change_time); if (ret) goto err_free;` — the `if (ret)` is a separate statement, not nested. For version 4, the `change_time` write never runs but the error check fires anyway (harmlessly, since `ret` holds the prior call's value). Misleading structure; will cause silent error masking if code evolves.
- **Fix**: Add braces: `if (da->version == 3) { ret = ndr_write_int64(n, da->change_time); if (ret) goto err_free; }`

---

## LOW (6 — new, unimplemented)

### L-01: Missing `READ_ONCE` on `durable_scavenger_running` bool in scavenger kthread
- **File**: `src/fs/vfs_cache.c:1206`
- **Fix**: `while (READ_ONCE(durable_scavenger_running))` — prevents compiler from hoisting the read out of the loop.

### L-02: Missing `__must_hold` annotations on oplock state transition functions
- **File**: `src/fs/oplock.c:258-433`
- **Issue**: `opinfo_write_to_read()`, `opinfo_write_to_none()`, `opinfo_read_to_none()` etc. mutate shared state without documenting required locks.
- **Fix**: Add `__must_hold(&ci->m_lock)` annotations.

### L-03: RCU + spinlock nesting in `destroy_lease_table()` may miss concurrent `free_opinfo`
- **File**: `src/fs/oplock.c:1313-1325`
- **Issue**: Iterates lease list under `rcu_read_lock()` inside `write_lock(&lease_list_lock)`. `lease_del_list()` takes `lb_lock` spinlock inside. Concurrent `opinfo_put()` → `free_opinfo()` → `free_lease()` can race during teardown.
- **Fix**: Take `opinfo` reference before accessing its lease in the teardown path, or document the teardown ordering guarantee.

### L-04: `ksmbd_tcp_writev()` missing stack-iov fast path (performance)
- **File**: `src/transport/transport_tcp.c:508-550`
- **Issue**: `kmalloc_array()` on every send for `cur_iov`. The read path has a `stack_iov[8]` fast path for small vectors; write path doesn't.
- **Fix**: Apply same `KSMBD_TCP_SMALL_IOV` stack optimization for the common single/dual-vector send case.

### L-05: `ipc_msg_send_request()` missing `__acquires`/`__releases` annotations
- **File**: `src/transport/transport_ipc.c:693-718`
- **Issue**: Non-linear lock acquisition/release flow (two separate `down_write/up_write` pairs with `goto out`) triggers sparse imbalance warnings without annotations.
- **Fix**: Add `__acquires(&ipc_msg_table_lock)` / `__releases(&ipc_msg_table_lock)` at the appropriate points.

### L-06: Test coverage gaps in 7 critical paths
- **Issue**: No KUnit coverage for: `ksmbd_inode_get()` concurrent race, `oplock_break_pending()` timeout, `ksmbd_find_crypto_ctx()` exhaustion, `ksmbd_session_rpc_open()` concurrent close, `ksmbd_purge_disconnected_fp()` concurrent reconnect, `session_fd_check()` duplicate reconnect, `destroy_lease_table()` with in-flight breaks.
- **Fix**: Add targeted KUnit test cases for each path.

---

## Summary

| Source | Priority | Count | Status |
|--------|----------|-------|--------|
| Protocol | APPLIED | 7 | Done (by agent) |
| Security | CRITICAL | 1 | **To fix** |
| Quality | CRITICAL | 3 | **To fix** |
| Security | HIGH | 2 | **To fix** |
| Quality | HIGH | 4 | **To fix** |
| Security | MEDIUM | 5 | **To fix** |
| Quality | MEDIUM | 3 | **To fix** |
| Security | LOW | 2 | **To fix** |
| Quality | LOW | 4 | **To fix** |
| **Total new** | | **24** | |
| **Grand total** | | **31** | 7 already done |

Compared to previous cycles: v1 (66), v2 (37), v3 (16), v4 (20).
The codebase is approaching production-grade stability. Remaining issues are deeper
locking/concurrency problems and a few protocol edge cases.
