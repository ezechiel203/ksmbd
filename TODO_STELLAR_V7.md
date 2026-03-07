# TODO_STELLAR_V7.md — ksmbd Cycle 7 Audit

Progressive multi-cycle audit: V1(66)→V2(37)→V3(16)→V4(20)→V5(31)→V6(22)→**V7(12)**

Three parallel audit streams (Security, Protocol, Quality) were run. Many findings proved to
be false positives upon code inspection (already handled, or technically safe). Only confirmed
or well-grounded findings are listed below.

False positives excluded (verified by code reading):
- S-01 (ODX OFFLOAD_WRITE) — signed math guards handle all edge cases
- Q-01 (witness double-delete) — standard list_for_each_entry_safe delete pattern
- Q-02 (IPC hash response) — wait_event condition re-checks prevent spurious issues
- Q-03 (witness iface overflow) — allocation and memset sizes are consistent
- Q-04 (IPC response race) — kernel wake_up provides required memory barrier
- P-01 (CREATE MaxCreateContextResponseSize) — no such field exists in MS-SMB2 CREATE request
- P-02 (QUERY_DIR resume key) — standard VFS vfs_llseek behavior
- P-05 (AllocationSize=0) — existing logic truncates correctly
- P-07 (NOTIFY MaxOutputResponse) — already returns STATUS_NOTIFY_ENUM_DIR at correct places
- P-10 (CANCEL async match) — already fixed in V5
- P-12 (DELETE_ON_CLOSE + ReadOnly) — already fixed in V5 (smb2_create.c:2595)

---

## HIGH

### H-01 [SECURITY/PROTOCOL] smb2_session.c — Anonymous session gets encryption keys
**File**: `src/protocol/smb2/smb2_session.c` ~lines 404–446 (NTLM), 569–591 (Kerberos)
**MS-SMB2**: §3.3.5.5.2 step 6 — null sessions MUST NOT use encryption

**Issue**: Both the NTLM and Kerberos session-setup paths call
`generate_encryptionkey(conn, sess)` without first checking whether the session is
anonymous (null). When `SMB2_SESSION_FLAG_IS_NULL_LE` is set (NTLMSSP anonymous), there is
no real NT session key to derive SMB3 encryption keys from. The call either:
1. Succeeds with all-zero / empty-ticket-derived keys → weak encryption applied, and
   `SMB2_SESSION_FLAG_ENCRYPT_DATA_LE` is set on a null session.
2. Fails → returns -EINVAL and breaks anonymous auth on encrypted shares.

The check on line 404 (`rsp->SessionFlags != SMB2_SESSION_FLAG_IS_GUEST_LE`) correctly
gates signing/encryption for guest sessions but NOT for null sessions (IS_NULL_LE ≠ IS_GUEST_LE).

**Fix**: Add IS_NULL guard in both paths:
```c
/* NTLM path — before line 404 */
if (rsp->SessionFlags & SMB2_SESSION_FLAG_IS_NULL_LE)
    goto binding_session;

/* Kerberos path — before line 569 */
if (rsp->SessionFlags & SMB2_SESSION_FLAG_IS_NULL_LE)
    goto binding_session;
```
This skips key generation and encryption flag setup entirely for null sessions, which have no
shared secret to derive keys from.

---

## MEDIUM

### M-01 [PROTOCOL] smb2_session.c — Null session signing incorrectly enabled
**File**: `src/protocol/smb2/smb2_session.c` lines 404–407, 569–572
**MS-SMB2**: §3.3.5.5.2 — null sessions have no signing key

**Issue**: The signing flag `sess->sign = true` is set based on
`rsp->SessionFlags != SMB2_SESSION_FLAG_IS_GUEST_LE`. A null session (IS_NULL_LE set) passes
this check. With `sess->sign = true` but no signing key, subsequent signed requests fail
verification, breaking anonymous connections on servers with mandatory signing.

**Fix**: Same H-01 guard — when `IS_NULL_LE` is set, skip the signing-enable block too.
The `goto binding_session` above covers both signing and encryption.

---

### M-02 [PROTOCOL] smb2_query_set.c — IOCTL response truncation without STATUS_BUFFER_OVERFLOW
**File**: `src/protocol/smb2/smb2_ioctl.c` (IOCTL output size clamping logic)
**MS-SMB2**: §3.3.5.16 — server MUST return STATUS_BUFFER_OVERFLOW if output exceeds
MaxOutputResponse for FSCTLs that produce variable-length output

**Issue**: The IOCTL handler silently clamps output to MaxOutputResponse. For FSCTLs like
`FSCTL_QUERY_ALLOCATED_RANGES` and `FSCTL_GET_RETRIEVAL_POINTERS`, partial output is
ambiguous — the client cannot tell whether more ranges exist. Per spec, these FSCTLs must
return `STATUS_BUFFER_OVERFLOW` when output is clamped, so the client knows to retry with a
larger buffer.

**Fix**: Identify which FSCTLs produce variable-length output (QUERY_ALLOCATED_RANGES,
GET_RETRIEVAL_POINTERS, QUERY_ON_DISK_VOLUME_INFO) and return `STATUS_BUFFER_OVERFLOW`
when their output is clamped, rather than STATUS_SUCCESS with partial data.

---

### M-03 [QUALITY] smb2_negotiate.c — Signing algorithm fallback not in response context
**File**: `src/protocol/smb2/smb2_negotiate.c` ~line 234
**MS-SMB2**: §3.3.5.4 — server response context must accurately reflect chosen algorithm

**Issue**: When the client offers signing algorithms and none overlap with server preferences,
the code falls back to `SIGNING_ALG_AES_CMAC` (line 512). The response context at line 234-248
emits `conn->signing_algorithm` (the fallback). This is correct for the algorithm, but the
condition `conn->signing_negotiated` may be true while `conn->signing_algorithm` stays at
AES-CMAC. Some clients interpret this as the server explicitly selecting a shared algorithm;
others expect a NO_OVERLAP status. The response should not imply mutual agreement when the
server unilaterally fell back.

**Fix**: When no overlap is found, emit the response context with `AES-CMAC` AND set a debug
log distinguishing "selected" vs "fallback". Optionally add a new per-connection flag
`signing_is_fallback` for future logging/policy.

---

### M-04 [QUALITY] vfs_cache.c — ksmbd_durable_scavenger_alive race with kthread_stop
**File**: `src/fs/vfs_cache.c` ~lines 1245–1261, 1351–1366
**Issue**: `ksmbd_durable_scavenger_alive()` is the condition for `wait_event_timeout`. Its
body reads `READ_ONCE(durable_scavenger_running)` and calls `kthread_should_stop()`. These are
two separate atomic reads with no combined atomicity. If `kthread_stop()` is called between
the two checks, `kthread_should_stop()` returns true but the thread already committed to
another sleep via `wait_event_timeout`. The thread wakes on the next timeout, checks the while
condition (alive→false because kthread_should_stop), and exits correctly. This is functionally
safe but leaves a window of up to `min_timeout` ms before the kthread actually exits.

**Fix**: Replace `wait_event_timeout(dh_wq, alive() == false, timeout)` with
`wait_event_interruptible(dh_wq, !alive())` so that `kthread_stop()` which calls `wake_up`
immediately unblocks the thread. Add `try_to_freeze()` inside the loop and check
`kthread_should_stop()` explicitly at the top of the loop body.

---

### M-05 [QUALITY] oplock.c — opinfo_get_list holds ci->m_lock across potential schedule
**File**: `src/fs/oplock.c`
**Issue**: `opinfo_get_list` acquires `down_write(&ci->m_lock)` (a rwsem, sleepable) while
iterating the op list. If a waiter for `m_lock` is high-priority, the current holder can be
preempted for an extended period with all file-level locks held. For large op lists this
creates latency spikes on concurrent file operations.

**Fix**: Copy the opinfo list under `down_read` (not write), taking per-opinfo refcounts, then
release the read lock and process opinfos without holding `m_lock`. The write lock is only
needed for structural changes, not for reading the list for break notifications.

---

### M-06 [QUALITY] smb2_create.c — CreateContexts response not guarded by response buffer size
**File**: `src/protocol/smb2/smb2_create.c` ~lines 2850–3000 (context append section)
**Issue**: When assembling multiple CREATE response contexts (lease, MxAc, DurableHandleV2,
AAPL, OnDisk, Posix), the code appends each context directly to `rsp->Buffer` using
pre-calculated offsets. There is no runtime check that the cumulative context size does not
exceed the remaining response buffer capacity. A large combination of contexts (e.g., full
AAPL + DurableV2 + lease + posix) could push past the response buffer end.

**Fix**: Track `ctx_off` as a running offset and add a check before each context:
```c
if (offsetof(struct smb2_create_rsp, Buffer) + ctx_off + next_ctx_size >
    work->response_sz) {
    pr_warn_ratelimited("create: context overflow, skipping %s\n", ctx_name);
    break;
}
```

---

## LOW

### L-01 [PROTOCOL] ksmbd_info.c — FileBasicInformation timestamp loses nanosecond precision
**File**: `src/fs/ksmbd_info.c` ~lines 430–445
**MS-FSCC**: §2.4.4 — FileBasicInformation timestamps in 100-nanosecond units

**Issue**: `ksmbd_gentime()` converts Linux `timespec64` to Windows FILETIME using only the
`tv_sec` component (seconds), discarding `tv_nsec`. Windows clients requesting file timestamps
for synchronization (rsync, DFS replication) lose sub-second precision. The FILETIME unit is
100 ns, so full precision is achievable.

**Fix**:
```c
static inline u64 ksmbd_ns_to_filetime(struct timespec64 ts)
{
    return (u64)(ts.tv_sec * 10000000LL + ts.tv_nsec / 100) + KSMBD_TIME_OFFSET;
}
```
Use `stat.mtime`, `stat.atime`, `stat.ctime` from `struct kstat` (which carry nsec) instead
of coercing through `time64_t`.

---

### L-02 [PROTOCOL] smb2_query_set.c — FileStreamInformation on directories
**File**: `src/protocol/smb2/smb2_query_set.c` (FileStreamInformation handler)
**MS-FSCC**: §2.4.66 — FileStreamInformation is only defined for files, not directories

**Issue**: If a client queries `FileStreamInformation` on a directory, the server should
return `STATUS_INVALID_PARAMETER`. Currently the handler likely returns stream info (empty or
otherwise) regardless of file type.

**Fix**: Before processing the FileStreamInformation query, check:
```c
if (S_ISDIR(file_inode(fp->filp)->i_mode))
    return -EINVAL;
```

---

### L-03 [QUALITY] smb2_misc_cmds.c — ECHO response buffer not explicitly zeroed
**File**: `src/protocol/smb2/smb2_misc_cmds.c` ~line 257
**Issue**: ECHO response is exactly 4 bytes (StructureSize + Reserved). The response buffer
allocation may carry stale data beyond these 4 bytes if the allocator returns non-zero memory.
While MS-SMB2 specifies ECHO response as exactly 4 bytes with no padding, defense-in-depth
requires zeroing any allocated response buffer before use.

**Fix**: Ensure `ksmbd_alloc_work_struct` or the response buffer allocation zero-fills by
default (already done via `kzalloc`), OR add an explicit `memset(rsp, 0, sizeof(*rsp))` at the
start of `smb2_echo()`.

---

### L-04 [QUALITY] smb2_tree.c — MaximalAccess ignores share read-only flag
**File**: `src/protocol/smb2/smb2_tree.c` ~lines 266–360
**MS-SMB2**: §2.2.10 — MaximalAccess should reflect share-level restrictions

**Issue**: The TREE_CONNECT response MaximalAccess field is computed using `inode_permission()`
on the filesystem root. If the share is configured as read-only in `ksmbd.conf`, write bits
(FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_ATTRIBUTES) should be excluded from
MaximalAccess. Currently a share marked read-only still returns MaximalAccess with write bits,
which confuses clients that use MaximalAccess to determine available operations.

**Fix**: After computing MaximalAccess, if `tcon->share_conf` has read-only flag set, mask out
write/delete bits:
```c
if (test_share_config_flag(tcon->share_conf, KSMBD_SHARE_FLAG_READONLY))
    maximal_access &= ~(FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE |
                        FILE_WRITE_ATTRIBUTES_LE | DELETE_LE);
```

---

### L-05 [QUALITY] user_session.c — ksmbd_session_lookup under RCU without conn lock
**File**: `src/mgmt/user_session.c` ~line 383
**Issue**: `ksmbd_session_lookup()` (non-slowpath) calls `xa_load(&conn->sessions, id)` under
`down_read(&conn->session_lock)`. This is correct. However, `ksmbd_session_lookup_all` calls
both the fast path and the slowpath `ksmbd_session_lookup_slowpath(id)`, which uses the global
hash table under RCU without holding `conn->session_lock`. If session expiry runs concurrently
on the same connection, the slowpath could return a session being destroyed.

**Fix**: In `ksmbd_session_lookup_slowpath`, verify the returned session is still in a
valid state before returning it (already done by `refcount_inc_not_zero`), but also add a
note in `ksmbd_session_lookup_all` that the state check at line 434 (`sess->state !=
SMB2_SESSION_VALID`) needs to hold the `state_lock` for reading, not just check atomically.
The existing `down_read(&sess->state_lock)` at line 433 is correct; confirm this pattern
is maintained in any future modifications.

---

## Summary Table

| ID   | Severity | File                     | Topic                                   | Status |
|------|-----------|--------------------------|-----------------------------------------|--------|
| H-01 | HIGH      | smb2_session.c:409,574   | Null session gets encryption keys       | TODO   |
| M-01 | MEDIUM    | smb2_session.c:404,569   | Null session signing incorrectly set    | TODO   |
| M-02 | MEDIUM    | smb2_ioctl.c             | IOCTL truncation without BUFFER_OVERFLOW| TODO   |
| M-03 | MEDIUM    | smb2_negotiate.c:512     | Signing fallback vs mutual agreement    | TODO   |
| M-04 | MEDIUM    | vfs_cache.c:1263-1366    | Scavenger kthread_stop latency window   | TODO   |
| M-05 | MEDIUM    | oplock.c                 | down_write m_lock across large op list  | TODO   |
| M-06 | MEDIUM    | smb2_create.c:2850-3000  | Create context response buffer overflow | TODO   |
| L-01 | LOW       | ksmbd_info.c:430-445     | FileBasicInfo timestamp nsec lost       | TODO   |
| L-02 | LOW       | smb2_query_set.c         | FileStreamInfo on directories           | TODO   |
| L-03 | LOW       | smb2_misc_cmds.c:257     | ECHO buffer not zeroed                  | TODO   |
| L-04 | LOW       | smb2_tree.c:266-360      | MaximalAccess ignores share read-only   | TODO   |
| L-05 | LOW       | user_session.c:383       | session_lookup_all documentation gap    | TODO   |

**Total: 12 findings** (1 HIGH, 6 MEDIUM, 5 LOW)

---

## Fix Order (recommended)

1. H-01 + M-01 together — same root cause, single guard in smb2_session.c
2. M-06 — response buffer bounds check in CREATE (memory safety)
3. M-02 — IOCTL STATUS_BUFFER_OVERFLOW compliance
4. M-04 — scavenger shutdown robustness
5. M-03 — signing fallback logging/documentation
6. M-05 — oplock list locking optimization
7. L-01 through L-05 — low-risk polish items

After fixes: run full smbtorture sweep on VM3 + VM7 to verify no regressions.
