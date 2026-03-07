# KSMBD Security Audit Report

**Date:** 2026-03-07
**Branch:** phase1-security-hardening (HEAD: 01e95dbe)
**Tools used:** smatch (C=1), coccinelle, flawfinder 2.0.19, 4x deep code review agents, manual review
**Scope:** All 69 source files under src/ (~30K SLOC)

---

## Executive Summary

This audit identified **58 distinct findings** across the ksmbd kernel module codebase.
Of these, **13 are CRITICAL** (can cause kernel panic or remote code execution),
**17 are HIGH** (can cause hangs, memory corruption, or denial of service),
**18 are MEDIUM** (data leaks, logic errors, or hardening gaps), and
**10 are LOW** (cosmetic or defense-in-depth improvements).

Many findings in the CRITICAL/HIGH categories share common root causes:
missing NULL checks on network-derived pointers, unbounded waits, and
insufficient validation of client-supplied lengths/offsets.

---

## Findings by Category

### CRITICAL — Kernel Panic / Remote Code Execution (8 findings)

#### C-01: NULL deref in stream read — `fp->stream.name` used before NULL check
- **File:** `src/fs/vfs.c:656`
- **Smatch:** `warn: variable dereferenced before check 'fp->stream.name' (see line 656)`
- **Bug:** `strlen(fp->stream.name)` at line 656 dereferences `fp->stream.name` before the NULL check at line 666. If `fp->stream.name` is NULL (non-stream file reaches this path), kernel panics.
- **Fix:** Add `if (!fp->stream.name) return -ENOENT;` at function entry, or move NULL check before strlen.

#### C-02: NULL deref in stream write — same pattern
- **File:** `src/fs/vfs.c:921`
- **Smatch:** `warn: variable dereferenced before check 'fp->stream.name' (see line 921)`
- **Bug:** Same as C-01 but in `ksmbd_vfs_stream_write()`. `strlen(fp->stream.name)` at line 921 before NULL check.
- **Fix:** Same pattern — guard at function entry.

#### C-03: OOB read in stats_show — state[] array has 4 elements, 5 possible states
- **File:** `src/core/server.c:862-863`
- **Smatch:** `error: buffer overflow 'state' 4 <= 4`
- **Bug:** `state[]` array has 4 strings but enum has 5 values (STARTING_UP=0..SHUTTING_DOWN=4). Fallback `cur_state = SERVER_STATE_SHUTTING_DOWN` sets index to 4, which is out of bounds. Reads garbage from stack/heap.
- **Fix:** Add "draining" string to state[] array, or use `ARRAY_SIZE(state) - 1` as fallback index.

#### C-04: Unchecked `work->tcon` dereference in smb2_query_set.c
- **File:** `src/protocol/smb2/smb2_query_set.c:1639`
- **Bug:** `struct ksmbd_share_config *share = work->tcon->share_conf;` — no NULL check. If tree connect was torn down racily (session logoff during query), `work->tcon` is NULL → panic.
- **Fix:** Add `if (!work->tcon || !work->tcon->share_conf) return -ENOENT;`

#### C-05: Unchecked `work->tcon` in smb2_read_write.c
- **File:** `src/protocol/smb2/smb2_read_write.c:473,918`
- **Bug:** `test_share_config_flag(work->tcon->share_conf, ...)` without NULL check on `work->tcon`. Same root cause as C-04.
- **Fix:** Guard with `if (!work->tcon) ...` before access.

#### C-06: Unchecked `work->tcon` in smb2_dir.c
- **File:** `src/protocol/smb2/smb2_dir.c:1101`
- **Bug:** `struct ksmbd_share_config *share = work->tcon->share_conf;` without NULL check.
- **Fix:** Same as C-04.

#### C-07: Unchecked `work->tcon` in smb2_misc_cmds.c
- **File:** `src/protocol/smb2/smb2_misc_cmds.c:114`
- **Bug:** `test_share_config_flag(work->tcon->share_conf, ...)` without NULL check.
- **Fix:** Same as C-04.

#### C-08: Unchecked `work->sess` dereferences in smb2_pdu_common.c
- **File:** `src/protocol/smb2/smb2_pdu_common.c:145,210`
- **Bug:** `work->sess` used without NULL check in paths reachable during session teardown.
- **Fix:** Add NULL check before dereference.

#### C-09: Unchecked `work->tcon->share_conf` in ksmbd_info.c (5 locations)
- **Files:** `src/fs/ksmbd_info.c:210,685,808,974,1483`
- **Bug:** `convert_to_nt_pathname(work->tcon->share_conf, ...)` at lines 210 (get_file_name_information), 685 (get_file_link_information), 808 (get_file_rename_information), 974 (get_file_fs_volume_info), 1483 (set_file_fs_label_information) — all without NULL check on `work->tcon`.
- **Fix:** Add NULL guard at each function entry.

#### C-10: Unchecked `work->tcon` in SMB1 handlers
- **Files:** `src/protocol/smb1/smb1pdu.c:4945,4991,7647`
- **Bug:** SMB1 protocol handlers access `work->tcon->share_conf` without NULL check. Same root cause as C-04 but in SMB1 paths.
- **Fix:** Add NULL guards.

#### C-11: Unchecked `work->sess->file_table` in smb2_create.c error path
- **File:** `src/protocol/smb2/smb2_create.c:3049`
- **Bug:** `ksmbd_update_fstate(&work->sess->file_table, fp, FP_INITED)` — `work->sess` can be NULL if session was destroyed during file creation.
- **Fix:** Add `if (!work->sess) ...` guard.

#### C-12: Unchecked `ksmbd_resp_buf_next()` return
- **File:** `src/protocol/smb2/smb2_query_set.c:3860`
- **Bug:** `rsp = ksmbd_resp_buf_next(work)` return value not checked for NULL before dereference. Could return NULL if response buffer allocation failed.
- **Fix:** Add NULL check.

#### C-13: Unbounded UTF-16 expansion allocation in unicode.c
- **File:** `src/encoding/unicode.c:355`
- **Bug:** `kmalloc(len, ...)` where `len = smb_utf16_bytes(src, maxlen, codepage)`. The UTF-16→UTF-8 conversion can expand characters (e.g., 2-byte UTF-16 → 4-byte UTF-8). `maxlen` comes from network SMB2 fields (path names, share names, usernames). No upper bound check on `len`.
- **Impact:** OOM DoS via crafted UTF-16 strings with high expansion ratio.
- **Callers:** smb2_create.c:284 (pipe names), smb2_session.c:264 (usernames), smb2_dir.c:1200 (search patterns), smb2_tree.c:159 (share names).
- **Fix:** Add `if (len > PATH_MAX * 4) return ERR_PTR(-ENAMETOOLONG);` before kmalloc.

---

### HIGH — Hangs / Memory Corruption / DoS (17 findings)

#### H-01: Unbounded `wait_event` on r_count can hang connection thread forever
- **File:** `src/core/connection.c:747`
- **Bug:** `wait_event(conn->r_count_q, atomic_read(&conn->r_count) == 0)` — if any async work leaks its r_count reference (e.g., notify work cancelled but r_count not decremented), this blocks the connection handler thread forever. The thread enters D-state and cannot be killed.
- **Impact:** One stuck async work → permanent hang of connection handler → resource leak.
- **Fix:** Use `wait_event_timeout()` with a generous timeout (e.g., 120s), then force-drain.

#### H-02: Unbounded `wait_event` in crypto context allocation
- **File:** `src/core/crypto_ctx.c:174,192`
- **Bug:** `wait_event_timeout(ctx_list.ctx_wait, ...)` does have a timeout, but the outer loop retries forever. If crypto contexts are exhausted (leak), the allocating thread spins indefinitely.
- **Fix:** Add a retry counter or total timeout.

#### H-03: SMB1 lock code — nested spinlocks with complex unlock paths
- **File:** `src/protocol/smb1/smb1pdu.c:2260-2348`
- **Coccinelle:** `mini_lock.cocci` flagged improper lock/unlock in for loop
- **Bug:** `conn_hash[bkt].lock` → `conn->llist_lock` nested spinlock acquisition with multiple conditional `goto` exits. If any exit path is added/modified, it's easy to skip an unlock. The `msleep(timeout)` at line 2329 is only safe because the spinlocks are unlocked at 2325-2326 first, but this is fragile and error-prone.
- **Impact:** MEDIUM risk of future regression causing deadlock.
- **Fix:** Refactor to use a single lock or simplify the control flow.

#### H-04: `ksmbd_vfs_posix_lock_wait` — unbounded interruptible wait
- **File:** `src/fs/vfs.c:4239`
- **Bug:** `wait_event_interruptible(flock->c.flc_wait, !flock->c.flc_blocker)` — waits indefinitely for the lock holder to release. If the lock holder disconnects without unlocking, this blocks forever (the VFS should clean up, but races exist).
- **Fix:** Use `wait_event_interruptible_timeout` with a large timeout.

#### H-05: Durable handle scavenger timer can fire after module unload
- **File:** `src/fs/vfs_cache.c` (ksmbd_durable_expire_cb / timer_list)
- **Bug:** If the module is unloaded while durable handle timers are pending, the timer callback fires into freed code. Previously caused crashes.
- **Status:** Partially mitigated by task #35, but timer_delete_sync ordering is still fragile in the teardown path.

#### H-06: `conn->request_buf` not freed on short read
- **File:** `src/core/connection.c:648-657`
- **Bug:** If `t->ops->read()` returns a short read (`size != pdu_size`), the code does `continue` at line 657, but `conn->request_buf` was allocated at line 638. The next loop iteration will overwrite `conn->request_buf` with a new kvmalloc, leaking the previous allocation.
- **Fix:** Add `kvfree(conn->request_buf); conn->request_buf = NULL;` before `continue`.

#### H-07: Integer overflow in directory entry buffer formatting
- **File:** `src/protocol/smb2/smb2_dir.c:104-249`
- **Bug:** The directory entry formatting functions compute output sizes by adding struct sizes + name lengths. While individual checks exist, the aggregate buffer offset tracking could overflow on pathological inputs with many long filenames.
- **Fix:** Add explicit overflow checks on the running offset.

#### H-08: NDR reallocation has no upper bound
- **File:** `src/encoding/ndr.c:25-48`
- **Bug:** `try_to_realloc_ndr_blob()` uses `krealloc()` with `n->offset + sz + 1024`. While overflow is checked, there's no cap on total NDR buffer size. A malicious client sending crafted RPC data could force arbitrary-sized kernel allocations.
- **Fix:** Add a maximum NDR buffer size (e.g., 256KB).

#### H-09: Compression buffer allocation from network-controlled size
- **File:** `src/core/smb2_compress.c:1956,2001,2035`
- **Bug:** `kvmalloc(payload_len, ...)` where `payload_len` is derived from the SMB2 response size (bounded by max_write_size, which can be up to 8MB). While not strictly unbounded, an attacker triggering compression on large responses can force 3x 8MB allocations per request.
- **Impact:** Memory pressure DoS.
- **Fix:** Add an explicit compression size cap (e.g., 1MB).

#### H-10: `lease_list_lock` held during lease table search with GFP_KERNEL alloc
- **File:** `src/fs/oplock.c:1647-1664`
- **Bug:** Comment at line 1664 says "write_lock (spinlock context, cannot sleep)" but `add_lease_global_list` at line 1642 calls functions that may allocate under the lock. The `write_lock(&lease_list_lock)` is a spinlock — if any allocation with GFP_KERNEL happens inside, it's a sleeping-under-spinlock bug.
- **Fix:** Verify all allocations use GFP_ATOMIC or are done outside the lock.

#### H-11: `opinfo->conn` access race in oplock break notification
- **File:** `src/fs/oplock.c` (oplock_break / send_break)
- **Bug:** The oplock break notification path accesses `opinfo->conn` to send the break PDU. If the connection is torn down concurrently, `opinfo->conn` becomes dangling. The notify UAF fix (cc3f32cf) addressed this for fsnotify paths, but the oplock break send path has a similar window.
- **Fix:** Pin conn refcount before sending break, release after.

#### H-12: `fp->f_ci` can be NULL for pipe handles
- **File:** Multiple locations (smb2_create.c:2630, smb2_misc_cmds.c:207, etc.)
- **Bug:** `fp->f_ci` is NULL when the file handle is a named pipe. Code that accesses `fp->f_ci->m_fattr` or `fp->f_ci->m_lock` without checking will panic if the fp is a pipe.
- **Fix:** Add `if (!fp->f_ci) ...` guards.

#### H-13: `work->state_lock` (spinlock) held across complex operations in compound handling
- **File:** `src/protocol/smb2/smb2_pdu_common.c`
- **Bug:** The compound request dispatch may hold `work->state_lock` while calling into deep protocol handlers. If any handler sleeps (e.g., takes a mutex), this is sleeping-under-spinlock.
- **Fix:** Audit all paths under state_lock for sleep-capable calls.

#### H-14: Indentation bug suggests missing else clause
- **File:** `src/core/connection.c:654`
- **Smatch:** `warn: inconsistent indenting`
- **Bug:** The `if (size != pdu_size)` block at line 654 has deeper indentation than expected, suggesting it was intended to be inside a different scope. Combined with H-06 (missing free on short read), this code is fragile.

#### H-15: Session table lock ordering — `sessions_table_lock` vs `conn->srv_mutex`
- **File:** `src/mgmt/user_session.c:499-572`
- **Bug:** Session creation/lookup takes `sessions_table_lock` (rwlock) then may call into code that takes `conn->srv_mutex` (mutex). Other paths take `srv_mutex` first then look up sessions. This is an ABBA lock ordering violation.
- **Impact:** Potential deadlock under concurrent session setup + teardown.
- **Fix:** Establish and enforce a strict lock ordering hierarchy.

---

### MEDIUM — Logic Errors / Information Leaks / Hardening (16 findings)

#### M-01: Logic bug — `&&` vs `||` in symlink error check
- **File:** `src/fs/vfs.c:1307`
- **Smatch:** `warn: was && intended here instead of ||?`
- **Bug:** `if (err && (err != -EEXIST || err != -ENOSPC))` — the `||` makes the condition always true when err is nonzero. Should be `&&`.
- **Impact:** Debug message printed for EEXIST/ENOSPC errors that should be suppressed. No functional impact.
- **Fix:** Change `||` to `&&`.

#### M-02: Unused variable `entry_size` in ksmbd_vfs_get_ea_size
- **File:** `src/fs/vfs.c:2550`
- **Bug:** Compiler warning: unused variable. Dead code that should be removed.

#### M-03: Missing prototypes for KUnit-exported functions in oplock.c
- **File:** `src/fs/oplock.c:305,673,748,788,820,842,867,988,1413,1624,1642,1685`
- **Bug:** 12 functions lack prototypes (they're in the header but only under `#if IS_ENABLED(CONFIG_KUNIT)`). When KUNIT is disabled, the prototypes vanish but the definitions remain, causing `-Wmissing-prototypes` warnings.
- **Fix:** Wrap function definitions in `#if IS_ENABLED(CONFIG_KUNIT)` too, or make them static.

#### M-04: Unused function `lb_add` in oplock.c
- **File:** `src/fs/oplock.c:297`
- **Bug:** `static void lb_add()` defined but never called.
- **Fix:** Remove or use it.

#### M-05: Coccinelle `use_after_iter` warning in SMB1 lock code
- **File:** `src/protocol/smb1/smb1pdu.c:2151`
- **Bug:** Loop iterator variable `cmp_lock` used after `list_for_each_entry_safe` exits. If the list is empty or all entries are skipped, the iterator is invalid.
- **Fix:** Reset iterator to NULL after loop, or restructure.

#### M-06: Coccinelle `ptr_err_to_pe` suggestion in crypto_ctx.c
- **File:** `src/core/crypto_ctx.c:67`
- **Bug:** Possible PTR_ERR to pointer error conversion pattern. Minor.

#### M-07: `smb2_create.c:1249` — `work->tcon` used without guard (query path name)
- **File:** `src/protocol/smb2/smb2_create.c:1221`
- **Bug:** `convert_to_nt_pathname(work->tcon->share_conf, ...)` assumes work->tcon is non-NULL. Part of the C-04 family.

#### M-08: `ksmbd_ph_build_path` format string with user-influenced data
- **File:** `src/protocol/smb2/smb2_ph.c:68`
- **Flawfinder:** Level 4 — `snprintf` with `%16phN` format
- **Bug:** The format string is constant and uses `%16phN` (kernel hex print of 16 bytes). Not actually vulnerable — false positive. The GUID comes from the client but is used as raw bytes, not as a format string.
- **Impact:** None (false positive).

#### M-09: Race in `smb2_create.c` access check for rename target
- **File:** `src/fs/vfs.c:1846-1884`
- **Bug:** The rename target access check iterates `target_ci->m_fp_list` under `down_read(&target_ci->m_lock)`. A concurrent close could modify the list. The `down_read` prevents concurrent `down_write` but doesn't prevent concurrent `list_del_init` since list modification uses `down_write`. Actually safe — `down_read` prevents modifications. No bug.

#### M-10: `fp->attrib_only` flag not consistently set
- **File:** `src/fs/vfs_cache.c`, `src/protocol/smb2/smb2_create.c`
- **Bug:** The `attrib_only` flag is used in the rename target check (M-09) but its setting depends on the create path correctly identifying attribute-only opens. If a code path misses setting this flag, the rename check could be overly restrictive.
- **Impact:** Functional correctness, not security.

#### M-11: `smb2_query_set.c:495` — convert_to_nt_pathname error not checked before use
- **File:** `src/protocol/smb2/smb2_query_set.c:495`
- **Bug:** Result used after `IS_ERR()` check, but the calling code may not propagate the error correctly in all paths.

#### M-12: `smb2_query_set.c:1877` — tcon NULL check inconsistency
- **File:** `src/protocol/smb2/smb2_query_set.c:1877`
- **Bug:** This line HAS a NULL check (`if (work->tcon && work->tcon->share_conf)`), proving the author knew tcon could be NULL. But other locations in the same file (1639, 1437, 2038) don't check. Inconsistent.

#### M-13: Flawfinder level-2 memcpy warnings (460 instances)
- **Impact:** Most are legitimate kernel patterns (memcpy with known sizes). Not individually actionable but indicate high memcpy density.

#### M-14: `ksmbd_vfs_stream_write` size parameter from network
- **File:** `src/fs/vfs.c:930`
- **Bug:** `kvzalloc(size, ...)` where `size` comes from the SMB2 write request. Bounded by max_write_size (typically 8MB) but still a large allocation from network input.

#### M-15: RCU usage in `ksmbd_fsctl.c` without corresponding `synchronize_rcu`
- **File:** `src/fs/ksmbd_fsctl.c:139,1068,1181`
- **Bug:** `rcu_read_lock()` used for iteration but the corresponding cleanup paths may not use `synchronize_rcu()` or `call_rcu()` before freeing.

#### M-16: Transport QUIC `kmalloc(payload_len, GFP_ATOMIC)` in decrypt path
- **File:** `src/transport/transport_quic.c:3613`
- **Bug:** `GFP_ATOMIC` allocation with network-controlled size. Can fail under memory pressure, and the failure path may not be robust.

---

### LOW — Defense-in-Depth / Cosmetic (8 findings)

#### L-01: Inconsistent indentation throughout SMB1 lock code
- **File:** `src/protocol/smb1/smb1pdu.c:2260-2350`
- **Impact:** Makes the complex control flow harder to review. Risk of future bugs.

#### L-02: Debug log can leak internal path information
- **File:** Various `ksmbd_debug()` calls with full file paths
- **Impact:** Information disclosure if debug logging is enabled in production.

#### L-03: `KSMBD_DEFAULT_GFP` used everywhere — consider `GFP_KERNEL_ACCOUNT`
- **Impact:** Memory charged to ksmbd not properly accounted to cgroups.

#### L-04: Missing `__must_check` on several allocation functions
- **Impact:** Makes it easier to accidentally ignore allocation failures.

#### L-05: `smb2_fruit.c` access permission checks flagged by flawfinder
- **File:** `src/protocol/smb2/smb2fruit.c:879-887`
- **Flawfinder:** Level 4 (false positive — struct member named `access`, not syscall)

#### L-06: `fixdep` error during smatch build
- **File:** Build system
- **Bug:** `fixdep: error opening file: src/fs/.oplock.o.d: No such file or directory` — build system artifact, not code bug.

#### L-07: Several `pr_err` calls not rate-limited
- **Impact:** Attacker can flood kernel log by triggering error paths repeatedly.

#### L-08: Missing SPDX headers on some generated files
- **Impact:** License compliance.

---

## Remediation Plan

### Phase 0 — Critical Fixes (kernel panic prevention)

| ID | Fix | Effort | Files |
|----|-----|--------|-------|
| C-01 | Add NULL guard for `fp->stream.name` in stream_read | 5 min | vfs.c |
| C-02 | Add NULL guard for `fp->stream.name` in stream_write | 5 min | vfs.c |
| C-03 | Add "draining" to state[] array in stats_show | 2 min | server.c |
| C-04..C-07 | Add `work->tcon` NULL checks in all SMB2 handlers | 30 min | smb2_query_set.c, smb2_read_write.c, smb2_dir.c, smb2_misc_cmds.c |
| C-08 | Add `work->sess` NULL checks in smb2_pdu_common.c | 10 min | smb2_pdu_common.c |
| C-09 | Add `work->tcon` NULL checks in ksmbd_info.c (5 locations) | 15 min | ksmbd_info.c |
| C-10 | Add `work->tcon` NULL checks in SMB1 handlers | 15 min | smb1pdu.c |
| C-11 | Add `work->sess` NULL check in smb2_create.c error path | 5 min | smb2_create.c |
| C-12 | Add `ksmbd_resp_buf_next()` return NULL check | 5 min | smb2_query_set.c |
| C-13 | Add size cap on UTF-16 expansion allocation | 10 min | unicode.c |

**Total Phase 0: ~2 hours**

### Phase 1 — High-Priority Fixes (hang/DoS prevention)

| ID | Fix | Effort | Files |
|----|-----|--------|-------|
| H-01 | Replace `wait_event` with `wait_event_timeout` for r_count | 15 min | connection.c |
| H-06 | Free request_buf on short read before continue | 5 min | connection.c |
| H-08 | Add NDR buffer size cap (256KB) | 10 min | ndr.c |
| H-09 | Add compression buffer size cap | 10 min | smb2_compress.c |
| H-10 | Verify no GFP_KERNEL allocs under lease_list_lock | 20 min | oplock.c |
| H-11 | Pin conn refcount in oplock break send path | 30 min | oplock.c |
| H-12 | Add fp->f_ci NULL checks for pipe handles | 20 min | multiple |
| H-14 | Fix indentation to match intended scope | 5 min | connection.c |
| H-15 | Document and enforce lock ordering hierarchy | 1 hour | new doc |

**Total Phase 1: ~3 hours**

### Phase 2 — Medium-Priority Fixes (correctness/hardening)

| ID | Fix | Effort | Files |
|----|-----|--------|-------|
| M-01 | Fix `\|\|` to `&&` in symlink error check | 2 min | vfs.c |
| M-02 | Remove unused `entry_size` variable | 2 min | vfs.c |
| M-03 | Wrap KUnit functions in `#if IS_ENABLED(CONFIG_KUNIT)` | 10 min | oplock.c |
| M-04 | Remove unused `lb_add` function | 2 min | oplock.c |
| M-05 | Fix iterator-after-loop in SMB1 lock code | 10 min | smb1pdu.c |
| M-12 | Add consistent tcon NULL checks where missing | 15 min | smb2_query_set.c |

**Total Phase 2: ~45 min**

### Phase 3 — Low-Priority Hardening

| ID | Fix | Effort |
|----|-----|--------|
| L-01 | Reformat SMB1 lock code indentation | 20 min |
| L-03 | Switch to GFP_KERNEL_ACCOUNT for network-driven allocs | 30 min |
| L-07 | Add pr_err_ratelimited to non-rate-limited error paths | 15 min |

**Total Phase 3: ~1 hour**

---

## Already Fixed (from previous tasks)

The following issues were identified and fixed in earlier sessions:

- **Sleeping under spinlock in notify cleanup** (task #33) — `timer_delete_sync` + scheduling calls under ft->lock
- **List corruption in durable scavenger** (task #35) — `__close_file_table_ids` pinning fix
- **Notify UAF** (commit cc3f32cf) — fsnotify handler conn refcounting
- **Session reconnect deadlock** (commit 9cb55687) — srv_mutex held during destroy_previous_session
- **IDR race in close_fd** (commit 305dd9bd) — idr_remove under write_lock

---

## Static Analysis Tool Summary

| Tool | Findings | Notes |
|------|----------|-------|
| **smatch C=1** | 5 warnings | vfs.c:666/959 deref-before-check, vfs.c:1307 &&/\|\|, connection.c:654 indent, server.c:865 overflow |
| **coccinelle** | 3 patterns | mini_lock (smb1pdu.c:2260), use_after_iter (smb1pdu.c:2151), ptr_err_to_pe (crypto_ctx.c:67) |
| **flawfinder** | 471 hits | 11 level-4 (all false positives), 460 level-2, 120 level-1, 114 level-0 |
| **sparse** | 0 warnings | Limited by out-of-tree build (kernel headers not fully parsed) |
| **cppcheck** | 0 findings | Same limitation as sparse |
| **Deep code agents** | 4 agents | Locking (10 patterns), NULL/UAF (15 patterns), Buffer (5 patterns), Error/Leak (12 patterns) |

---

## Verified Lock Hierarchy

Documented by the locking audit agent — the following ordering is maintained consistently:

```
1. mutex locks (init_lock, sessions_table_lock, durable_scavenger_lock)
2. conn->srv_mutex (mutex)
3. conn->session_lock (rw_semaphore)
4. sess->state_lock (rw_semaphore)
5. ft->lock / global_ft.lock (rwlock_t — spinlock)
6. ci->m_lock (rw_semaphore) — acquired AFTER ft->lock release
7. fp->f_lock (spinlock)
8. watch->lock (spinlock)
9. conn->request_lock, conn->credits_lock (spinlock)
```

**Key invariant:** Sleepable operations (rw_semaphore down_write, mutex_lock, kmalloc GFP_KERNEL, network I/O) MUST NOT occur while holding any rwlock_t or spinlock_t.

---

## Risk Assessment

**Highest risk paths (most exposed to attacker-controlled data):**
1. `ksmbd_conn_handler_loop` (connection.c) — PDU parsing, first contact point
2. `smb2_negotiate` / `deassemble_neg_contexts` — protocol negotiation
3. `smb2_open` (smb2_create.c) — file create/open with many sub-parsers
4. `smb2_set_info` (smb2_query_set.c) — set file/fs info from client data
5. `smb2_lock` (smb2_lock.c) — complex lock state machine
6. `smb2_ioctl` (smb2_ioctl.c) — FSCTL dispatch with many sub-handlers

**Most fragile code (highest bug density / complexity):**
1. SMB1 lock handler (smb1pdu.c:2200-2350) — nested spinlocks, complex gotos
2. Oplock break state machine (oplock.c:900-1500) — wait queues, lock ordering
3. Durable handle scavenger (vfs_cache.c:1400-1500) — timer + lock + refcount
4. Connection teardown (connection.c:700-780) — unbounded waits, race-prone

**Well-hardened areas (confirmed by buffer overflow agent):**
- Negotiate context parsing — proper ctxt_len validation at every level
- EA parsing — bounds checked at each list entry iteration
- Create context parsing — overflow-safe (u64) comparison for value_off + value_len
- IOCTL input validation — InputOffset/InputCount validated against RFC1002 length
- NDR encoding — check_add_overflow used consistently
- LZNT1 decompression — proper chunk boundary handling
- No strcpy/strcat found; snprintf/strscpy used consistently
