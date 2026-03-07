# KSMBD Hang / Panic Review

Date: 2026-03-07
Tree: `/home/ezechiel203/ksmbd`
Scope: crash, deadlock, shutdown wedge, and memory-corruption risks in the current tree snapshot.

## Method

Static analysis used:
- `smatch`
- `sparse`
- `scan-build`
- `clang-tidy`
- `cppcheck`
- `flawfinder`
- `spatch`

Supplemental structural review:
- targeted `rg` searches for waits, workqueue teardown, kthread lifecycle, and null-guard/deref patterns
- manual inspection of teardown, notify, oplock, VFS, FSCTL, session, and RDMA paths

Important caveats:
- The tree is dirty; review was done against the current working copy.
- External-module kbuild integration did not yield a normal compile transcript from the top-level `make`, so some analyzers had to be driven from saved `.o.cmd` compile lines or reduced Clang invocations.
- `cppcheck` was low-signal here because kernel macro/config handling was incomplete. Its raw log is still saved.
- `spatch` worked in report/diff mode, but this machine is missing the usual Coccinelle standard macro/iso files and Python embedding support.

Raw outputs are under:
- `GPT_TMP/ksmbd_review_2026-03-07/logs/`

## Confirmed Defects

### 1. Panic-class thread-stop on failed durable scavenger start

Files:
- `src/fs/vfs_cache.c:1567`
- `src/fs/vfs_cache.c:1571`
- `src/fs/vfs_cache.c:1591`

Problem:
- `durable_scavenger_running` is set `true` before `kthread_run()`.
- If `kthread_run()` fails, the code only logs the `ERR_PTR` and leaves both the running flag and `server_conf.dh_task` unchanged.
- `ksmbd_stop_durable_scavenger()` later calls `kthread_stop(server_conf.dh_task)` without `IS_ERR_OR_NULL()` checking.

Impact:
- Reset/unload can dereference an `ERR_PTR` task pointer and crash the kernel.
- Even when it does not crash immediately, subsystem state is inconsistent because the code believes the scavenger is running when it is not.

Required fix:
- Only set `durable_scavenger_running` after successful thread creation.
- Store `NULL` on failure.
- Guard `kthread_stop()` with `IS_ERR_OR_NULL()`.

### 2. Out-of-bounds server-state lookup in sysfs stats path

Files:
- `src/core/server.c:853`
- `src/core/server.c:862`
- `src/core/server.c:865`
- `src/include/core/server.h:47`

Problem:
- The `state[]` string table has 4 elements.
- The enum has 5 states: `STARTING_UP`, `RUNNING`, `RESETTING`, `DRAINING`, `SHUTTING_DOWN`.
- When `cur_state >= ARRAY_SIZE(state)`, the code sets `cur_state = SERVER_STATE_SHUTTING_DOWN`, which is index `4`, then dereferences `state[cur_state]`.

Impact:
- OOB read in a sysfs show path.
- Depending on layout, this can print garbage, read an invalid pointer, or fault in kernel context.

Tool confirmation:
- `smatch`: `buffer overflow 'state' 4 <= 4`
- `scan-build`: `Uninitialized argument value` at the same path
- `clang-tidy`: `Out of bound access to memory after the end of 'state'`

Required fix:
- Make the string table match the enum exactly, or clamp to a valid string index.
- Add a `BUILD_BUG_ON(ARRAY_SIZE(state) != SERVER_STATE_SHUTTING_DOWN + 1)` style invariant.

### 3. Integer-overflow-to-underrun risk in inherited security descriptor allocation

Files:
- `src/fs/smbacl.c:2170`
- `src/fs/smbacl.c:2171`
- `src/fs/smbacl.c:2193`
- `src/fs/smbacl.c:2201`

Problem:
- Allocation sizing uses signed `int` temporaries:
  - `powner_sid_size`
  - `pgroup_sid_size`
  - `pntsd_alloc_size`
- The overflow check is `if (pntsd_alloc_size < nt_size)`, which itself relies on signed overflow semantics that are undefined in C.

Impact:
- Large/hostile ACL composition can wrap the allocation size.
- `kzalloc()` can then allocate too small a buffer, followed by metadata/SID/ACL writes based on the larger logical size.
- That is a real memory-corruption path and can panic the kernel.

Tool confirmation:
- `smatch`: signed-overflow warning in this allocation path.

Required fix:
- Convert all size math to `size_t`/`u32` as appropriate.
- Use `check_add_overflow()` or `struct_size()`-style checked accumulation.
- Reject impossible SID/ACL sizes before allocation.

### 4. Null-deref candidate in async notify response builders

Files:
- `src/fs/ksmbd_notify.c:216`
- `src/fs/ksmbd_notify.c:279`
- `src/fs/ksmbd_notify.c:463`
- `src/fs/ksmbd_notify.c:515`

Problem:
- Both response builders explicitly treat `work->conn` as nullable:
  - `if (work->conn) refcount_inc(...)`
- The same functions later dereference `work->conn->local_nls` unconditionally.

Impact:
- If a queued/pending notify work ever legitimately carries `conn == NULL`, the notification worker can NULL-deref in kernel context.
- The existing guard strongly suggests the author already considered `conn` nullable.

Tool confirmation:
- `smatch`: `we previously assumed 'work->conn' could be null`

Required fix:
- Either make `conn` non-null by construction and assert it, or bail out early before any dereference.
- Encode the invariant once in the notify-work lifecycle instead of half-guarding individual uses.

### 5. Signed-overflow-based offset validation in duplicate-extents handler

Files:
- `src/fs/ksmbd_fsctl.c:1515`
- `src/fs/ksmbd_fsctl.c:1559`
- `src/fs/ksmbd_fsctl.c:1561`
- `src/fs/ksmbd_fsctl.c:1567`

Problem:
- `src_off`, `dst_off`, and `length` are `loff_t`.
- Overflow rejection uses:
  - `src_off + length < src_off`
  - `dst_off + length < dst_off`
- Signed overflow is undefined, so the check is not reliable.

Impact:
- Malformed values can bypass validation on some builds/optimizations.
- Bad ranges then flow into `vfs_clone_file_range()`, pushing the bug into filesystem code.

Tool confirmation:
- `smatch`: signed-overflow warning at this exact check.

Required fix:
- Validate using checked unsigned math plus explicit upper-bound/range checks before converting to `loff_t`.

## Confirmed Hang / Wedge Risks

### 6. Unbounded connection teardown wait

Files:
- `src/core/connection.c:744`
- `src/core/connection.c:747`

Problem:
- Connection teardown blocks in:
  - `wait_event(conn->r_count_q, atomic_read(&conn->r_count) == 0);`
- There is no timeout, abort path, or forced teardown path.

Impact:
- Any leaked `r_count` reference or blocked async path wedges reset/unload forever.
- This is a hang amplifier even if the original leak is elsewhere.

Evidence:
- The tree already contains several comments in notify/oplock paths that special-case `r_count` specifically to avoid shutdown deadlocks. That is a sign the teardown contract is fragile.

Required fix:
- Convert to bounded waiting plus ratelimited diagnostics.
- Add a post-timeout forced-drain path and per-reference provenance counters.

### 7. RDMA transport uses multiple unbounded waits in teardown and send paths

Files:
- `src/transport/transport_rdma.c:407`
- `src/transport/transport_rdma.c:804`
- `src/transport/transport_rdma.c:983`
- `src/transport/transport_rdma.c:1366`
- `src/transport/transport_rdma.c:1989`
- `src/transport/transport_rdma.c:2110`

Problem:
- RDMA code waits indefinitely on:
  - send completions
  - reassembly availability
  - credits
  - disconnect status

Impact:
- Lost completion, stuck CQ, missing disconnect event, or transport error can wedge worker threads or shutdown forever.
- RDMA teardown is especially dangerous because these waits sit in connection destruction paths.

Tool confirmation:
- `spatch` enumerated these unbounded waits directly.

Required fix:
- Replace teardown-critical waits with timeout-bearing forms.
- On timeout, mark the transport poisoned, log state, and continue best-effort teardown.

## Probable Crash Candidates Needing Immediate Triage

These were not validated as deeply as the items above, but they are plausible null-deref or memory-safety bugs and should be reviewed in the first remediation sprint.

### 8. Preauth hash generation dereferences `sess` on binding path without proving it exists

File:
- `src/protocol/smb2/smb2_session.c:95`

Pattern:
- `if (sess && sess->state == SMB2_SESSION_VALID) ...`
- later:
  - `ksmbd_preauth_session_lookup(conn, sess->id);`

Risk:
- If `conn->binding` is reachable before `work->sess` is attached, this is a straight NULL dereference.

### 9. Stream helpers call `strlen(fp->stream.name)` before any explicit null guard

Files:
- `src/fs/vfs.c:654`
- `src/fs/vfs.c:656`
- `src/fs/vfs.c:919`
- `src/fs/vfs.c:921`

Risk:
- If `ksmbd_stream_fd(fp)` is ever true while `fp->stream.name == NULL`, read/write paths can NULL-deref.
- The function later checks `fp->stream.name` in feature-specific branches, which weakens confidence in the invariant.

### 10. SMB2 create path dereferences `sess->user` in ACL inheritance path without the earlier guard

Files:
- `src/protocol/smb2/smb2_create.c:2119`
- `src/protocol/smb2/smb2_create.c:2343`
- `src/protocol/smb2/smb2_create.c:2346`

Risk:
- Earlier code checks `if (sess->user && ...)`.
- Later ACL inheritance path uses `sess->user->uid/gid` directly.
- If guest/incomplete-session handling reaches that branch, it can NULL-deref.

## Other Tool-Driven Crash Candidates

These came from the broader `smatch` sweep and are saved for triage. They are worth reviewing, but I did not promote them to confirmed defects yet.

- `src/protocol/smb1/smb1pdu.c:747` possible nullable `rsp`
- `src/protocol/smb1/smb1pdu.c:3297` possible nullable `fp`
- `src/protocol/smb1/smb1pdu.c:4203` possible nullable `local_acl`
- `src/protocol/smb2/smb2_query_set.c:286` possible nullable `ea_req`
- `src/protocol/smb2/smb2_query_set.c:1877` possible nullable `work->tcon`
- `src/protocol/smb2/smb2_read_write.c:1076` possible nullable `work->tcon` / `work->tcon->share_conf`
- `src/protocol/smb2/smb2_tree.c:369` possible nullable `share`

## Full Remediation Plan

### Phase 0: Stop-Ship Fixes

Do these first, before any wider refactor:
- Fix the durable scavenger thread lifecycle bug.
- Fix the sysfs `state[]` OOB bug and add a compile-time invariant.
- Replace signed allocation math in `smbacl.c` with checked size arithmetic.
- Fix `ksmbd_notify.c` so `work->conn` is either guaranteed non-null or fully guarded.
- Replace duplicate-extents signed-overflow validation with checked math.

### Phase 1: Hang-Proof Teardown

- Audit every teardown/control-path wait and classify it:
  - bounded and safe
  - bounded but missing state dump
  - unbounded and must be fixed
- Convert unbounded waits in:
  - `connection.c`
  - `transport_rdma.c`
  - any control-path notify/oplock teardown helper
- Standardize timeout handling:
  - poison object
  - emit one structured diagnostic
  - continue best-effort teardown

### Phase 2: Encode Nullable / Lifetime Invariants

- For every `struct ksmbd_work`, explicitly document which fields may be `NULL` in:
  - normal request path
  - async notify/oplock path
  - shutdown/cancel path
- Add `WARN_ON_ONCE()` or early returns at invariant boundaries.
- Remove mixed patterns like:
  - “check for null in one spot, dereference later anyway”

### Phase 3: Arithmetic Hardening Pass

- Replace ad hoc size arithmetic with:
  - `check_add_overflow()`
  - `check_mul_overflow()`
  - `struct_size()`
  - `array_size()`
- Prioritize:
  - ACL/security descriptor builders
  - FSCTL copy/clone paths
  - notify buffer construction
  - path/EA/reparse serialization

### Phase 4: Static-Analysis CI That Actually Works

- Fix the external-module analyzer workflow so the tree produces normal compile commands.
- Add scripted targets for:
  - `smatch`
  - `sparse`
  - reduced `scan-build`
  - reduced `clang-tidy`
  - `spatch` structural reports
- Treat these as gating for touched files.
- Preserve raw logs as CI artifacts.

### Phase 5: Dynamic Validation

Build and test with:
- `CONFIG_KASAN`
- `CONFIG_KCSAN`
- `CONFIG_LOCKDEP`
- `CONFIG_PROVE_LOCKING`
- `CONFIG_DEBUG_ATOMIC_SLEEP`
- `CONFIG_UBSAN`
- `CONFIG_KFENCE`

Run:
- targeted notify/oplock cancellation tests
- forced kthread creation failure tests
- reset/unload loops under fault injection
- RDMA disconnect/completion-loss fault tests
- syzkaller and existing fuzzers focused on:
  - SMB2 create/query/set
  - notify
  - FSCTL clone/copychunk
  - session setup / preauth

### Phase 6: Regression Tests to Add Immediately

- KUnit or targeted test for server-state sysfs output while cycling every enum state
- fault-injection test for durable scavenger `kthread_run()` failure
- notify tests where async work has missing/cleared connection state
- FSCTL duplicate-extents boundary tests around `LLONG_MAX`
- ACL inheritance tests with large SID/ACE counts and allocation-failure injection
- teardown tests that assert reset/unload completes under timed waits

## Tool Notes

High-signal outputs:
- `logs/smatch_all.log`
- `logs/clang_tidy_server_min.log`
- `logs/scan_build_server_min/`
- `logs/spatch_risky_waits.log`
- `logs/waits_and_flushes.log`

Lower-signal / environment-limited outputs:
- `logs/cppcheck.log`
- `logs/flawfinder.log`
- `logs/sparse_connection.log`
- `logs/sparse_server.log`
- `logs/sparse_vfs_cache.log`
- `logs/sparse_transport_ipc.log`

## Bottom Line

The current tree has at least two immediately actionable crash bugs and multiple teardown designs that can still wedge shutdown/reset indefinitely. The first remediation sprint should focus on:
- durable scavenger lifecycle
- sysfs state table OOB
- notify nullable-connection handling
- arithmetic hardening in ACL and FSCTL builders
- bounded teardown waits in core connection and RDMA paths
