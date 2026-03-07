# TODO_STELLAR_V8.md — ksmbd Cycle 8 Audit

Progressive multi-cycle audit: V1(66)→V2(37)→V3(16)→V4(20)→V5(31)→V6(22)→V7(12)→**V8(0)**

Three parallel audit streams (Security, Protocol, Quality) were run. All findings from
all three streams were verified by reading actual source code. Every finding proved to
be a false positive.

---

## Audit Methodology

Each stream audited a distinct concern:

- **Security stream**: integer overflows, use-after-free, info leaks, auth bypass, NULL derefs,
  format string injection, uninitialized memory in responses.
- **Protocol stream**: MS-SMB2/MS-FSCC compliance — negotiate, session, tree, create, query,
  lock, oplock, IOCTL, directory enumeration.
- **Quality stream**: locking discipline, resource leaks, error propagation, kthread lifecycle,
  IPC path robustness, connection teardown races.

---

## False Positives Excluded (verified by code reading)

### Security stream

- **`%p` in smb2fruit.c:738** — Since Linux 4.15, all `%p` in kernel printk/pr_debug paths
  are automatically hashed via `ptr_to_id()`. They cannot be used to defeat KASLR. Only
  `%px` leaks raw addresses. This is not a vulnerability.
- **Lock range arithmetic (smb2_lock.c:649)** — `check_add_overflow()` at lines 637-644
  correctly validates all overflow cases before the arithmetic is used.
- **Null session crypto** — Fixed in V7 (commit ab2648d8).
- **IOCTL BUFFER_OVERFLOW** — Fixed in V7 (commit ab2648d8).
- **Response buffer init** — All response buffers use `kvzalloc()`.
- **File handle access validation** — All file ops validate session/tree/daccess.
- **Integer overflow protection** — `check_add_overflow`/`check_mul_overflow` guards
  present on all EA, COPYCHUNK, ACL, and lock paths.

### Protocol stream

- **Negotiate fields** — MaxTransactSize/MaxReadSize/MaxWriteSize correctly set; context
  offsets/counts correct for all dialect variants (smb2_negotiate.c:960-977).
- **Tree MaximalAccess** — `inode_permission()` probe plus `KSMBD_TREE_CONN_FLAG_WRITABLE`
  mask at smb2_tree.c:302 is correct.
- **Create FILE_SUPERSEDE** — O_TRUNC handled in disposition table.
- **QueryMaximalAccess context** — Response populated correctly (smb2_create.c:2862-2892).
- **Zero-length locks** — Allowed per MS-SMB2 §3.3.5.14 (smb2_lock.c:903-914).
- **SHARED + FAIL_IMMEDIATELY** — Combined correctly (smb2_lock.c:345-354).
- **FileNormalizedNameInformation (class 48)** — Implemented with 3.1.1+ guard.
- **FilePipeInformation / FilePipeLocalInformation** — Implemented (ksmbd_info.c:305-372).
- **Session re-auth key update** — Both NTLM and Kerberos paths correct.
- **IOCTL Flags check** — Rejects Flags != SMB2_0_IOCTL_IS_FSCTL (smb2_ioctl.c:96-99).

### Quality stream

- **`return atomic_inc()` in void functions (oplock.c:237-250)** — `atomic_inc()` returns
  `void`; `return void_expr;` is valid C and the atomic operation executes correctly.
  Syntactically idiomatic, not a bug.
- **`rcu_read_lock()` inside spinlock (connection.c:292-296)** — The spinlock protects
  `conn_hash[i]` list; `conn->sessions` XArray is protected separately by `conn->session_lock`
  (rwsem). `xa_load()` requires RCU, and the `rcu_read_lock()` inside the spinlock IS
  needed. Correct code.
- **IPC stack allocation in hash table (transport_ipc.c:681-721)** — The `down_write` at
  line 709 serializes with `handle_response()` (which holds `down_read`). The `hash_del`
  at line 718 always executes before the function returns and before the write lock is
  released. Stack frame cannot unwind while any other thread holds a valid pointer to
  the entry. Correct design.
- **`wait_event_interruptible_timeout` return not checked** — Timeout and signal cases both
  fall through to `down_write`→`hash_del`→return NULL. The caller treats NULL as
  "no response". Safe for all return value cases (>0, 0, <0).

---

## Result

**Zero confirmed new findings.**

The ksmbd codebase has reached a state where three independent audit streams covering
security, protocol compliance, and code quality found no new actionable issues. All
potential findings were dismissed after reading actual code.

---

## Audit Coverage Summary (V1–V8 cumulative)

| Area                          | Cycles | Status     |
|-------------------------------|--------|------------|
| Integer overflow guards       | V1–V6  | Complete   |
| Null session handling         | V7     | Complete   |
| IOCTL BUFFER_OVERFLOW         | V7     | Complete   |
| Session state machine         | V5–V7  | Complete   |
| Lock range arithmetic         | V4–V6  | Complete   |
| ACL/SID validation            | V5–V6  | Complete   |
| Compound request handling     | V5     | Complete   |
| Delete-on-close semantics     | V5     | Complete   |
| Credit tracking               | V4–V5  | Complete   |
| IPC response serialization    | V8     | Confirmed safe |
| Oplock locking discipline     | V7–V8  | Confirmed safe |
| Connection teardown races     | V8     | Confirmed safe |
| Protocol negotiate compliance | V1–V8  | Complete   |
| File info class coverage      | V5–V8  | Complete   |
| Response buffer zeroing       | V6–V8  | Complete   |

After fixes: run full smbtorture sweep on VM3 + VM7 to confirm no regressions from V7 commits.
