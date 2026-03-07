# TODO_STELLAR_V6.md — ksmbd Cycle 6 Audit

Progressive multi-cycle audit: V1(66)→V2(37)→V3(16)→V4(20)→V5(31)→**V6(22)**

Findings from three parallel audit streams: Security (S), Protocol (P), Quality (Q).
False positives excluded: P-02, P-03, P-04, P-11 (already correctly implemented).

---

## CRITICAL (must fix before any deployment)

### C-01 [SECURITY] smbacl.c — ACE size integer overflow (S-01)
**File**: `src/fs/smbacl.c` ~line 1816
**Issue**: `num_subauth * 4` computed as `u16 * int` — if `num_subauth` arrives as 15 from
user-controlled SID data, the product is 60, but the addition to a base size can overflow the
`u16` field used for ACE size in `smb_set_ace()`. No check that `num_subauth <= 15`
(SID_MAX_SUB_AUTHORITIES).

**Fix**:
```c
if (sid->num_subauth > SID_MAX_SUB_AUTHORITIES)
    return -EINVAL;
ace_size = 1 + 1 + 2 + 4 + 4 + sid->num_subauth * 4;
/* check_add_overflow + assign to le16 */
```
Validate `num_subauth` at every point a SID is read from user/network data, not just at ACE
construction time.

---

### C-02 [SECURITY] smbacl.c — pntsd allocation size overflow (S-02)
**File**: `src/fs/smbacl.c` ~lines 1986, 1995, 1998–1999
**Issue**: `pntsd_alloc_size` is built by adding per-ACE sizes derived from SID subauth counts.
No checked arithmetic: `pntsd_alloc_size += offsetof(struct smb_ace, sid) + 8 + sid->num_subauth * 4`
repeated for each ACE without overflow guard. A crafted DACL with many large SIDs causes a
heap OOB write on the allocated buffer.

**Fix**: Replace all additions with `size_add()` / `check_add_overflow()`. Compute total size
first, validate it against a sane maximum (e.g. `KSMBD_ACL_MAX_SIZE`), then allocate once.

---

### C-03 [SECURITY] smb2_query_set.c — allocation shift overflow (S-04)
**File**: `src/protocol/smb2/smb2_query_set.c` ~lines 2794, 2810, 2815, 2821
**Issue**: Expressions of the form `(count << 3)` or `count * sizeof(large_struct)` used as
kmalloc sizes without overflow checking. `count` is derived from the request; a large value
produces a small (wrapped) allocation followed by a heap OOB write.

**Fix**: Replace with `array_size(count, element_size)` or `check_mul_overflow`. Return
`STATUS_INVALID_PARAMETER` if the result would exceed a protocol-defined maximum.

---

### C-04 [QUALITY] user_session.c — xa_store without lock (Q-01)
**File**: `src/mgmt/user_session.c` ~lines 274–280
**Issue**: `xa_store(&conn->sessions, sess->id, sess, GFP_KERNEL)` is called without holding
`sessions_table_lock`. Concurrent session setup on the same connection can produce a duplicate
session ID entry, losing the first session object (reference leak + use-after-free when the
second caller frees it).

**Fix**: Take `spin_lock(&conn->sessions_lock)` (or the XArray's own lock via `xa_lock`)
around the `xa_store` call. Also add `xa_err()` check on the return value.

---

### C-05 [QUALITY] user_session.c — missing synchronize_rcu before session free (Q-10)
**File**: `src/mgmt/user_session.c` ~lines 304–360
**Issue**: After `hash_del_rcu(&sess->hlist)` the session object is freed (or refcount
decremented to zero) without calling `synchronize_rcu()`. Any RCU reader that is mid-traversal
of the session hash table will dereference a freed object.

**Fix**: Add `synchronize_rcu()` after `hash_del_rcu()` and before the `kfree`/`put` path, or
convert to `kfree_rcu(sess, rcu)` if the struct has an embedded `struct rcu_head`.

---

## HIGH

### H-01 [SECURITY] smb2_query_set.c — signed conversion of user offset (S-03)
**File**: `src/protocol/smb2/smb2_query_set.c` ~line 3235
**Issue**: A `__le64` user-supplied offset is read with `le64_to_cpu()` and stored directly in
a signed `loff_t`. If the value exceeds `LLONG_MAX`, the conversion is implementation-defined
(UB in C). Subsequent arithmetic on the `loff_t` (seek, range checks) may bypass validation.

**Fix**:
```c
u64 raw_off = le64_to_cpu(req->CurrentByteOffset);
if (raw_off > (u64)LLONG_MAX)
    return -EINVAL;
pos = (loff_t)raw_off;
```

---

### H-02 [QUALITY] vfs_cache.c — idr iteration without lock (Q-07)
**File**: `src/fs/vfs_cache.c` ~lines 1135–1152
**Issue**: `idr_get_next()` is called in a loop without holding `global_ft.lock` for the
duration. A concurrent `idr_remove()` from another thread (e.g. file close) can invalidate
the iterator and cause a use-after-free or skipped entry.

**Fix**: Hold `read_lock(&global_ft.lock)` for the entire `idr_for_each` / manual iteration,
or use `idr_for_each()` with a callback that takes no sleeping locks, or collect IDs under lock
and process them after unlock.

---

### H-03 [QUALITY] user_session.c — RCU access after rcu_read_unlock (Q-03)
**File**: `src/mgmt/user_session.c` ~lines 492–498 (`destroy_previous_session`)
**Issue**: `rcu_read_unlock()` is called, then the code continues to dereference a pointer that
was obtained under `rcu_read_lock()` (e.g. `prev_sess->id`). This is a classic RCU bug —
the pointer is no longer protected once the read-side critical section ends.

**Fix**: Either extend `rcu_read_lock()` to cover the full dereference window, or take a
reference (refcount) on the session before unlocking RCU.

---

### H-04 [QUALITY] smb2_lock.c — lock range arithmetic overflow (Q-11)
**File**: `src/protocol/smb2/smb2_lock.c` ~lines 633–640
**Issue**: Lock range computed as `lock_start + lock_length` without overflow check. With
crafted values (e.g. start=0xFFFFFFFFFFFF0000, length=0x20000) the sum overflows u64, bypassing
range validation and potentially allowing a lock record to cover an unintended file region.

**Fix**:
```c
u64 lock_end;
if (check_add_overflow(lock_start, lock_length, &lock_end))
    return STATUS_INVALID_PARAMETER;
```

---

### H-05 [QUALITY] ksmbd_notify.c — memory leak on kstrndup failure (Q-09)
**File**: `src/fs/ksmbd_notify.c` ~lines 588–600
**Issue**: When `kstrndup()` fails to allocate `chg->name`, the function returns early but the
`chg` struct (and its embedded data) is not freed. The change notification entry leaks on every
allocation failure in the name copy path.

**Fix**:
```c
chg->name = kstrndup(name, name_len, GFP_KERNEL);
if (!chg->name) {
    kfree(chg);
    return;
}
```

---

### H-06 [QUALITY] connection.c — short write not reported as error (Q-12)
**File**: `src/core/connection.c` ~lines 456–458
**Issue**: When `kernel_sendmsg()` returns fewer bytes than requested (`sent != expected_len`),
the code logs a warning but continues as if the send succeeded. The client receives a truncated
PDU and will likely disconnect with a protocol error, but the server doesn't treat this as an
error, potentially looping or leaving the connection in a broken state.

**Fix**: Treat `sent < expected_len` as a fatal connection error: set connection state to
`KSMBD_SESS_EXITING`, break the send loop, and return an error to the caller.

---

## MEDIUM

### M-01 [PROTOCOL] smb2_query_set.c — EOPNOTSUPP → wrong NTSTATUS (P-12)
**File**: `src/protocol/smb2/smb2_query_set.c`
**Issue**: Several SET_INFO sub-command handlers return `-EOPNOTSUPP` which maps to
`STATUS_NOT_SUPPORTED`. MS-SMB2 §3.3.5.21 specifies `STATUS_INVALID_PARAMETER` for unknown
or unsupported info classes in SET_INFO, not `STATUS_NOT_SUPPORTED`. Windows clients may
react differently to these two statuses.

**Fix**: Return `-EINVAL` (→ `STATUS_INVALID_PARAMETER`) for unsupported info classes.
Reserve `-EOPNOTSUPP` / `STATUS_NOT_SUPPORTED` for explicitly optional features the server
declares as unsupported.

---

### M-02 [PROTOCOL] smb2_tree.c — share name length in UTF-8 bytes not UTF-16 chars (P-07)
**File**: `src/protocol/smb2/smb2_tree.c`
**Issue**: The 80-character share name limit from ME-02 (previous cycle) was applied to the
UTF-8 byte count after conversion, but MS-SMB2 §3.3.5.7 specifies the limit in UTF-16
code units (characters) before conversion. A name with multibyte UTF-8 sequences can
pass the byte-count check while exceeding 80 UTF-16 chars.

**Fix**: Validate `PathLength / 2 <= 80` on the raw UTF-16 input (`TreeConnectReq->PathLength`)
before conversion.

---

### M-03 [PROTOCOL] smb2_negotiate.c — signing fallback (P-01)
**File**: `src/core/smb2_negotiate.c` (or equivalent negotiate handler)
**Issue**: When the client sends a `SIGNING_CAPABILITIES` negotiate context but none of the
offered algorithms overlap with the server's supported set, the current code falls back to
`AES-CMAC` silently. MS-SMB2 §3.3.5.4 requires the server to return `STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP`
or select `AES-128-CMAC` as a mandatory fallback and explicitly document the selection in the
response context — not silently downgrade without a response context.

**Fix**: Always echo a `SIGNING_CAPABILITIES` response context when the client sends one, even
if falling back to AES-CMAC. Populate `SigningAlgorithmCount=1`, `SigningAlgorithms[0]=AES-CMAC`.

---

### M-04 [PROTOCOL] smb2_session.c — session binding NTSTATUS (P-08)
**File**: `src/protocol/smb2/smb2_session.c`
**Issue**: Session binding failure paths return `-EINVAL` which maps to `STATUS_INVALID_PARAMETER`.
MS-SMB2 §3.3.5.5.1 specifies distinct NTSTATUSes for binding violations:
`STATUS_NOT_SUPPORTED` (server doesn't support binding), `STATUS_REQUEST_NOT_ACCEPTED`
(session already bound to this connection), `STATUS_INVALID_PARAMETER` (malformed request).
Using generic `-EINVAL` for all cases loses protocol fidelity.

**Fix**: Add explicit `smb2_set_err_rsp(work, STATUS_NOT_SUPPORTED)` /
`STATUS_REQUEST_NOT_ACCEPTED` where appropriate before returning.

---

### M-05 [QUALITY] vfs_cache.c — waitqueue active check without lock (Q-04)
**File**: `src/fs/vfs_cache.c` ~lines 1363, 1380
**Issue**: `waitqueue_active(&fp->waitq)` is checked outside of the waitqueue's spinlock.
This is a TOCTOU: between the check and the subsequent `wake_up`, a waiter could be added
or removed. While `wake_up` is itself safe to call spuriously, using `waitqueue_active`
as a guard for other state changes is not.

**Fix**: Either call `wake_up()` unconditionally (it's cheap when the queue is empty), or
wrap the check+action under `spin_lock_irq(&fp->waitq.lock)`.

---

### M-06 [QUALITY] vfs_cache.c — durable_scavenger_running unsynchronized (Q-05)
**File**: `src/fs/vfs_cache.c` ~line 1323
**Issue**: `durable_scavenger_running` is written without any synchronization primitive beyond
the existing `READ_ONCE` (added in V5). The writer path doesn't use `WRITE_ONCE`, making
the compiler free to cache-split or tear the write.

**Fix**: Add `WRITE_ONCE(durable_scavenger_running, true/false)` at every write site to match
the `READ_ONCE` on the read side.

---

### M-07 [QUALITY] user_session.c — XArray lookup race (Q-02)
**File**: `src/mgmt/user_session.c` ~lines 424–443 (`ksmbd_session_lookup_all`)
**Issue**: `xa_for_each()` iterates `conn->sessions` without holding a lock. Concurrent session
removal (`xa_erase`) can cause the iterator to skip entries or visit a partially-freed slot.

**Fix**: Use `xa_lock` / `xas_lock` during iteration, or collect session pointers under
`xa_lock` and process them outside (with refcount held).

---

### M-08 [QUALITY] smb2_lock.c — channel_sequence read without lock (Q-08)
**File**: `src/protocol/smb2/smb2_lock.c` ~line 561
**Issue**: `fp->channel_sequence` is read in `smb2_check_channel_sequence()` (called from
lock/write/flush/ioctl handlers) without holding `fp->f_ci->m_lock` or any other lock.
A concurrent `smb2_set_info` on the same FP can update `channel_sequence` mid-check,
causing a false "stale sequence" rejection or a missed staleness detection.

**Fix**: Protect `fp->channel_sequence` reads and writes with `fp->f_ci->m_lock` (or a
dedicated per-file spinlock), or use `READ_ONCE`/`WRITE_ONCE` with a documented rationale
that torn reads are acceptable here.

---

## LOW

### L-01 [PROTOCOL] transport_tcp.c / connection.c — PDU allocation size (S-05)
**File**: `src/core/connection.c` ~lines 622, 665–666
**Issue**: PDU receive buffer allocated as `max_recv_size` without checking whether the
`SmallHeaderSize + SecurityBufferOffset + SecurityBufferLength` from a SESSION_SETUP request
exceeds the allocation. The V5 fix added offset bounds checking, but the allocation itself
still has no upper bound guard against a malformed `MaxReadSize` in NEGOTIATE.

**Fix**: Clamp receive buffer allocation: `alloc_size = min_t(u32, negprot_max, KSMBD_MAX_PDU_SIZE)`.
Return `STATUS_INVALID_PARAMETER` if `MaxReadSize` > `KSMBD_MAX_PDU_SIZE`.

---

### L-02 [PROTOCOL] smb2_negotiate.c — mandatory signing context echo (P-06)
**File**: Negotiate handler
**Issue**: When `SecurityMode` has `SMB2_NEGOTIATE_SIGNING_REQUIRED` but the request contains
no `SIGNING_CAPABILITIES` context (pre-3.1.1 clients), the server accepts without emitting
a signing context in the response. For 3.1.1 clients that do include the context, the echo
path was fixed in V5, but the mandatory-signing enforcement path lacks the echo.

**Fix**: If `conn->signing_negotiated && dialect == SMB311`, always include a
`SIGNING_CAPABILITIES` response context, even when client didn't send one (use AES-CMAC default).

---

### L-03 [QUALITY] Multiple files — sparse/lockdep annotation gaps
**Files**: `src/mgmt/user_session.c`, `src/fs/vfs_cache.c`
**Issue**: Several functions that must be called under specific locks lack `__must_hold()`
annotations or `lockdep_assert_held()` calls:
- `__ksmbd_close_fd()` should assert `down_write(&fp->f_ci->m_lock)` is held
- `ksmbd_session_register()` inner helper should assert `conn->sessions_lock` is held
- `destroy_previous_session()` should assert RCU read lock

**Fix**: Add `lockdep_assert_held_write()` / `lockdep_assert_held_read()` / `RCU_LOCKDEP_WARN`
at the top of each function that has locking preconditions.

---

## Summary Table

| ID   | Severity | File                        | Topic                                 | Status  |
|------|----------|-----------------------------|---------------------------------------|---------|
| C-01 | CRITICAL | smbacl.c:1816               | ACE num_subauth overflow              | TODO    |
| C-02 | CRITICAL | smbacl.c:1986-1999          | pntsd allocation size overflow        | TODO    |
| C-03 | CRITICAL | smb2_query_set.c:2794-2821  | kmalloc shift overflow                | TODO    |
| C-04 | CRITICAL | user_session.c:274-280      | xa_store without lock                 | TODO    |
| C-05 | CRITICAL | user_session.c:304-360      | Missing synchronize_rcu before free   | TODO    |
| H-01 | HIGH     | smb2_query_set.c:3235       | Signed loff_t conversion              | TODO    |
| H-02 | HIGH     | vfs_cache.c:1135-1152       | idr iteration without lock            | TODO    |
| H-03 | HIGH     | user_session.c:492-498      | RCU access after unlock               | TODO    |
| H-04 | HIGH     | smb2_lock.c:633-640         | Lock range u64 overflow               | TODO    |
| H-05 | HIGH     | ksmbd_notify.c:588-600      | Memory leak on kstrndup failure       | TODO    |
| H-06 | HIGH     | connection.c:456-458        | Short write not fatal                 | TODO    |
| M-01 | MEDIUM   | smb2_query_set.c            | EOPNOTSUPP→STATUS_INVALID_PARAMETER   | TODO    |
| M-02 | MEDIUM   | smb2_tree.c                 | Share name UTF-16 char limit          | TODO    |
| M-03 | MEDIUM   | smb2_negotiate.c            | Signing fallback echo in response     | TODO    |
| M-04 | MEDIUM   | smb2_session.c              | Session binding NTSTATUS              | TODO    |
| M-05 | MEDIUM   | vfs_cache.c:1363,1380       | waitqueue check without lock          | TODO    |
| M-06 | MEDIUM   | vfs_cache.c:1323            | WRITE_ONCE for scavenger flag         | TODO    |
| M-07 | MEDIUM   | user_session.c:424-443      | XArray iteration race                 | TODO    |
| M-08 | MEDIUM   | smb2_lock.c:561             | channel_sequence read without lock    | TODO    |
| L-01 | LOW      | connection.c:622,665-666    | PDU alloc size clamp                  | TODO    |
| L-02 | LOW      | smb2_negotiate.c            | Mandatory signing context echo        | TODO    |
| L-03 | LOW      | user_session.c, vfs_cache.c | Sparse/lockdep annotation gaps        | TODO    |

**Total: 22 findings** (5 CRITICAL, 6 HIGH, 8 MEDIUM, 3 LOW)

---

## Fix Order (recommended)

1. C-01, C-02 — smbacl integer overflows (direct heap OOB write, exploitable)
2. C-03 — smb2_query_set shift overflow (same class)
3. C-04, C-05 — session table locking (race conditions on session creation/destruction)
4. H-01 through H-06 — high-severity correctness issues
5. M-01 through M-08 — protocol fidelity and medium concurrency fixes
6. L-01 through L-03 — low-priority hardening

After fixes: run full smbtorture sweep on VM3 to verify no regressions.
