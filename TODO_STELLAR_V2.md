# KSMBD Stellar-Level TODO v2

Comprehensive prioritized roadmap — post-Phase-1 hardening. Generated from fresh 5-agent
deep audit (2026-03-05) against 88K source lines. Items from v1 that were already fixed
by the 8 parallel worktree agents are NOT included here.

**Legend**: [S] Security | [P] Protocol | [Q] Quality | [T] Testing |
[O] Performance | [U] Upstream | [R] Operations

**Status key**: NEW = first identified in v2 | REMAINING = was in v1, not yet fixed

---

## PRIORITY 1 — CRITICAL (Security)

### S-01: SMB1 FileName memcpy without request-boundary validation (NEW)
- **File**: `src/protocol/smb1/smb1pdu.c:2740-2743`
- `memcpy(src, req->fileName + 1, le16_to_cpu(req->NameLength))` — NameLength read
  from the wire is used as memcpy size without verifying it fits within the received
  PDU buffer boundary
- Buffer is allocated with correct size (kzalloc at :2732), but the source copy reads
  past the request message if NameLength is spoofed
- **Fix**: Add `if (le16_to_cpu(req->NameLength) > smb_buf_length - offsetof(...)) return -EINVAL;`
- **Severity**: CRITICAL — remote OOB read from crafted SMB1 request

### S-02: InputBufferOffset alignment not validated in QUERY/SET_INFO (NEW)
- **File**: `src/protocol/smb2/smb2_query_set.c:214-225`
- `le16_to_cpu(req->InputBufferOffset)` is bounds-checked but not alignment-checked
- Misaligned offset causes unaligned struct pointer access (undefined behavior on strict
  architectures like arm64 without SCTLR_EL1.A)
- **Fix**: Add `if (input_buf_off % 2) return -EINVAL;` (UTF-16LE needs 2-byte alignment)
- **Severity**: HIGH — UB on strict-alignment architectures

### S-03: Pointer format in pr_err leaks kernel addresses (NEW)
- **Files**:
  - `src/fs/vfs_cache.c:1390` — `pr_err("Invalid durable fd [%p:%p]\n", fp->conn, fp->tcon)`
  - `src/fs/smbacl.c:1356` — `pr_err("ACL too small to parse SID %p\n", psid)`
  - `src/transport/transport_rdma.c:2036,2623` — RDMA CM event with `%p`
- Even with kptr_restrict hashing, `%p` is discouraged in kernel security guidelines
- **Fix**: Replace `%p` with `%pK` (privileged-only) or remove pointer from message
- **Severity**: LOW — mitigated by kptr_restrict, but violates hardening standards

---

## PRIORITY 2 — HIGH (Protocol Compliance)

### P-01: Previous Session ID (PreviousSessionId) not implemented (NEW)
- **File**: `src/protocol/smb2/smb2_session.c`
- **MS-SMB2 §3.3.5.5.3**: When client provides PreviousSessionId in SESSION_SETUP,
  server MUST look up the old session and tear it down before creating new one
- Allows clients to reconnect after network interruption without waiting for session
  timeout
- **Fix**: In smb2_sess_setup(), read `req->PreviousSessionId`; if non-zero, call
  `ksmbd_session_destroy(prev_sess)` before proceeding
- **Severity**: HIGH — breaks client reconnection after network glitch

### P-02: Session binding across connections not implemented (NEW)
- **File**: `src/protocol/smb2/smb2_session.c`
- **MS-SMB2 §3.3.5.5.2**: SMB_SESSION_FLAG_BINDING allows a client to bind an existing
  session to a new transport connection (multi-channel)
- Required for SMB3 multi-channel operation
- **Fix**: On SESSION_SETUP with BINDING flag, look up existing SessionId across all
  connections; validate signing key matches; add new connection to session's channel list
- **Severity**: HIGH — multi-channel broken without this

### P-03: Durable handle reconnect timeout not enforced (NEW)
- **File**: `src/protocol/smb2/smb2_create.c:964-1030`
- **MS-SMB2 §3.3.5.9.7-12**: Durable handles have a reconnect window (default 60s for
  DH2Q, configurable via Timeout field). Server must reject reconnect after window expires.
- Currently: handle stays valid indefinitely until scavenger runs
- **Fix**: Store `jiffies + timeout` in durable handle; check in DH2C reconnect path;
  reject with STATUS_OBJECT_NAME_NOT_FOUND if expired
- **Severity**: HIGH — allows stale handle reconnection

### P-04: ImpersonationLevel not validated in CREATE (NEW)
- **File**: `src/protocol/smb2/smb2_create.c`
- **MS-SMB2 §2.2.13.1**: ImpersonationLevel MUST be 0-3 (Anonymous/Identification/
  Impersonation/Delegate)
- Currently: field is completely ignored
- **Fix**: `if (req->ImpersonationLevel > SMB2_IL_DELEGATE) return -EINVAL;`
- **Severity**: MEDIUM

### P-05: SMB2_LOCKFLAG_UNLOCK combined with other flags not rejected (NEW)
- **File**: `src/protocol/smb2/smb2_lock.c`
- **MS-SMB2 §3.3.5.14**: When UNLOCK flag is set, no other flags (EXCLUSIVE_LOCK,
  SHARED_LOCK, FAIL_IMMEDIATELY) may be set
- Currently: combined flags silently accepted, causing unpredictable lock behavior
- **Fix**: `if ((flags & SMB2_LOCKFLAG_UNLOCK) && (flags & ~SMB2_LOCKFLAG_UNLOCK)) return STATUS_INVALID_PARAMETER;`
- **Severity**: MEDIUM

### P-06: NegotiateContextOffset 8-byte alignment not enforced (NEW)
- **File**: `src/protocol/smb2/smb2_negotiate.c:789-800`
- **MS-SMB2 §2.2.3.1**: NegotiateContextOffset must be 8-byte aligned
- Currently: bounds-checked but not alignment-checked
- **Fix**: `if (nego_ctxt_off % 8) return STATUS_INVALID_PARAMETER;`
- **Severity**: LOW

### P-07: Write-through / unbuffered flags ignored (NEW)
- **File**: `src/protocol/smb2/smb2_read_write.c`
- **MS-SMB2 §2.2.22**: SMB2_WRITEFLAG_WRITE_THROUGH (0x01) and
  SMB2_WRITEFLAG_WRITE_UNBUFFERED (0x02) defined but never honored
- Similarly, SMB2_READFLAG_READ_UNBUFFERED (0x01) for reads
- **Fix**: Map WRITE_THROUGH to O_SYNC; map UNBUFFERED to O_DIRECT; document
  any limitations
- **Severity**: MEDIUM — affects data integrity guarantees

### P-08: FileAllInformation response buffer overflow not handled (NEW)
- **File**: `src/protocol/smb2/smb2_query_set.c:1396-1399`
- **MS-SMB2 §2.4.3**: FILE_ALL_INFORMATION combines many sub-fields; if the response
  buffer is too small, server SHOULD return STATUS_BUFFER_OVERFLOW with partial data
- Currently: no check that combined output fits in allocated response buffer
- **Fix**: Calculate total response size before populating; return STATUS_BUFFER_OVERFLOW
  if it exceeds OutputBufferLength
- **Severity**: MEDIUM

### P-09: IOCTL MaxOutputResponse ceiling not enforced by all FSCTL handlers (NEW)
- **File**: `src/protocol/smb2/smb2_ioctl.c:122-128`
- **MS-SMB2 §2.2.31**: MaxOutputResponse is the ceiling; individual FSCTL handlers
  may not all respect the `max_out_len` parameter passed to them
- **Fix**: Audit all FSCTL handlers in ksmbd_fsctl.c and ksmbd_fsctl_extra.c to verify
  they honor max_out_len; add assertion/clamp at the IOCTL dispatch return path
- **Severity**: MEDIUM

### P-10: Kerberos re-authentication incomplete (REMAINING)
- **File**: `src/protocol/smb2/smb2_session.c:871`
- `TODO: need one more negotiation` for Kerberos re-auth
- Multi-round SPNEGO/Kerberos authentication needs completion
- **Severity**: MEDIUM — affects Kerberos-only environments

### P-11: QUIC stream buffer lacks backpressure (REMAINING)
- **File**: `src/transport/transport_quic.c:1753,1923-1926`
- Fixed 128KB QUIC_STREAM_BUF_SIZE; slow-send attack fills buffer
- **Fix**: Implement flow control; timeout incomplete PDUs
- **Severity**: MEDIUM

---

## PRIORITY 3 — MEDIUM (Code Quality)

### Q-01: pr_fmt missing from 38 .c files (REMAINING — partial fix)
- Previous agents added pr_fmt to ~24 files, but 38 still lack it
- **Files needing pr_fmt** (sample): `ksmbd_hooks.c`, `smb2_compress.c`,
  `ksmbd_debugfs.c`, `ksmbd_config.c`, `server.c`, `connection.c`, `ksmbd_md4.c`,
  plus ~31 more identified by code quality agent
- **Fix**: Add `#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt` before first #include
- **Severity**: LOW — cosmetic, but needed for upstream

### Q-02: Lock annotations missing on 34 functions (REMAINING — partial fix)
- Previous agents added annotations to ~10 functions; 34 still lack them
- Key functions:
  - `src/mgmt/user_session.c:221` — `ksmbd_lookup_session_node()` (mutex+down_write)
  - `src/mgmt/user_session.c:482` — `ksmbd_lookup_sign_state()` (mutex+down_write+rcu)
  - `src/mgmt/tree_connect.c:123` — `ksmbd_tree_conn_insert()` (write_lock)
- **Fix**: Add `__must_hold`, `__acquires`, `__releases`, `lockdep_assert_held()`
- **Severity**: LOW — needed for sparse/lockdep static analysis

### Q-03: Magic number 4 for CREATE_CONTEXT_HEADER_LEN (NEW)
- **File**: `src/protocol/smb2/smb2_create.c:777,947,1706,1726,1737`
- Bare `, 4` in `smb2_find_context_vals()` calls — should be a named constant
- Also `+ 4` at lines 275, 1238, 1362 for RFC1002 header (partially fixed in v1)
- **Fix**: `#define CREATE_CONTEXT_NAME_LEN 4` and use throughout
- **Severity**: LOW

### Q-04: Persistent handle save/restore stubs return -EOPNOTSUPP (REMAINING)
- **File**: `src/protocol/smb2/smb2_create.c:891-928`
- Three stub functions exist but are effectively dead code
- **Fix**: Either implement state serialization to userspace daemon, or remove the
  stubs entirely and document the limitation
- **Severity**: LOW — stubs correctly reject; no functional issue

### Q-05: 7 very large files (>2500 lines) without structural decomposition (NEW)
- `smb1pdu.c` (10,081), `vfs.c` (4,159), `smb2_query_set.c` (3,635),
  `ksmbd_fsctl.c` (3,041), `transport_quic.c` (3,208), `smb2_create.c` (3,003),
  `oplock.c` (2,772)
- Not necessarily bugs, but increases review/maintenance burden
- **Fix**: Consider splitting smb1pdu.c (SMB1 command groups), smb2_query_set.c
  (query vs set handlers), ksmbd_fsctl.c (by FSCTL category)
- **Severity**: LOW — maintenance quality

---

## PRIORITY 4 — TESTING GAPS

### T-01: No unit tests for transport layer (NEW)
- Zero test coverage for: `transport_tcp.c`, `transport_rdma.c`, `transport_quic.c`,
  `transport_ipc.c`
- These are the primary kernel attack surface
- **Fix**: Create mock-based KUnit test harness for transport message parsing,
  connection lifecycle, and error injection
- **Severity**: HIGH

### T-02: No unit tests for core infrastructure (REMAINING)
- Missing tests for: `ksmbd_buffer.c`, `ksmbd_work.c`, `ksmbd_config.c`,
  `ksmbd_hooks.c`, `crypto_ctx.c`, `compat.c`
- **Fix**: Write KUnit suites; prioritize buffer pool (allocator security),
  crypto_ctx (key management), ksmbd_work (request lifecycle)
- **Severity**: MEDIUM

### T-03: No authenticated SMB fuzzing paths (NEW)
- 44 fuzzing harnesses exist but all target pre-auth parsing (headers, negotiate)
- Post-authentication handlers (CREATE, READ, WRITE, IOCTL) are completely unfuzzed
- **Fix**: Add libFuzzer harnesses that set up mock authenticated sessions, then
  fuzz individual command handlers
- **Severity**: HIGH — most vulnerabilities are in post-auth paths

### T-04: No multi-client concurrent stress test (REMAINING)
- Concurrency tests exist but don't simulate realistic multi-client load
- **Fix**: Add stress test spawning N kthreads with full session lifecycle:
  negotiate → session_setup → tree_connect → create → read/write → close → logoff
- **Severity**: MEDIUM

### T-05: SMB1 test coverage is minimal (REMAINING)
- 10,081 lines of SMB1 handler code with very few tests
- **Fix**: Add comprehensive SMB1 negotiate/session/tree/trans2 tests OR
  add clear deprecation path with test-only coverage for known-good paths
- **Severity**: MEDIUM

### T-06: No OOM/error-injection testing framework (NEW)
- No use of fault injection (`CONFIG_FAIL_SLAB`, `CONFIG_FAIL_PAGE_ALLOC`)
  to test kmalloc failure paths
- **Fix**: Add CI job with fault injection enabled; verify all error paths
  correctly handle allocation failures without leaks or crashes
- **Severity**: MEDIUM

### T-07: Missing RDMA/QUIC transport error injection tests (REMAINING)
- No test coverage for RDMA buffer deregistration errors, QUIC handshake
  failures, mid-stream disconnections
- **Fix**: Add transport error injection via mock transport layer
- **Severity**: LOW (requires hardware or complex mocking)

---

## PRIORITY 5 — PERFORMANCE

### O-01: Per-lock kzalloc in smb2_lock (NEW)
- **File**: `src/protocol/smb2/smb2_lock.c:372`
- Each lock request allocates `struct ksmbd_lock` via kzalloc (10-100 per request)
- **Fix**: Create `kmem_cache_create("ksmbd_lock_cache", sizeof(struct ksmbd_lock), ...)`
  for hot-path allocation (estimated 5-10% improvement for lock-heavy workloads)
- **Severity**: MEDIUM

### O-02: shares_table_lock could use RCU for read path (NEW)
- Share lookups on every TREE_CONNECT take shares_table_lock
- Read-heavy workload (many tree connects, rare config changes)
- **Fix**: Convert to RCU-protected hash table for lookups; use mutex only for
  insert/delete. Already partially RCU (hash_for_each_possible_rcu) but lock
  still taken for reads.
- **Severity**: LOW (1-5% improvement on high-connection-rate workloads)

### O-03: NUMA awareness for work buffers (REMAINING)
- Work items may bounce between NUMA nodes under load
- **Fix**: Use `alloc_pages_node()` for large work buffers; consider NUMA-local
  allocation in `ksmbd_alloc_work_struct()`
- **Severity**: LOW (only relevant on multi-socket servers)

### O-04: Oplock break notification serialization (REMAINING)
- Break notifications sent synchronously in some paths while holding file locks
- **Fix**: Queue breaks via work_struct; batch-send; release file lock first
- **Severity**: LOW

---

## PRIORITY 6 — UPSTREAM ALIGNMENT

### U-01: Divergence tracking from upstream fs/smb/server/ (REMAINING)
- No systematic mapping between out-of-tree and mainline kernel changes
- Features unique to this fork: QUIC, compression, branchcache, fruit
- **Fix**: Create `UPSTREAM_DELTA.md` documenting each divergence with rationale
- **Severity**: MEDIUM

### U-02: CVE backport tracking (REMAINING)
- No automated process to identify and backport upstream ksmbd CVE fixes
- **Fix**: Create tracking document or script mapping upstream commits; add CI
  check comparing `git log --oneline fs/smb/server/` against local patches
- **Severity**: MEDIUM

### U-03: kernel-doc on exported functions (NEW)
- 16 EXPORT_SYMBOL_GPL functions; most lack proper kernel-doc comments
- Required for upstream submission
- **Fix**: Add `/** ... */` kernel-doc blocks to all exported functions
- **Severity**: LOW

### U-04: W=1/W=2 clean build (REMAINING — CI added, issues may remain)
- CI jobs added by v1 agents; actual warning count not yet verified
- **Fix**: Run `make W=1 W=2 C=2`; fix all warnings that appear
- **Severity**: LOW

---

## PRIORITY 7 — OPERATIONAL READINESS

### R-01: Share config cache flush on daemon reconnect (REMAINING)
- **File**: `src/transport/transport_ipc.c:884`
- Share configs cached in RCU hashtable; daemon restart doesn't flush
- Only `rmmod + insmod` clears stale share flags
- Design documented in TODO comment; needs implementation
- **Fix**: Implement `KSMBD_EVENT_SHARE_CONFIG_FLUSH` netlink command
- **Severity**: HIGH — operational pain point

### R-02: No connection audit logging (REMAINING)
- No structured logging for security events (auth failures, access denied)
- **Fix**: Add audit trail via `audit_log()` for: authentication success/failure,
  share access grants/denials, file deletion, permission changes
- **Severity**: MEDIUM — required for enterprise deployments

### R-03: Live reconfiguration support (REMAINING)
- Share/user changes require daemon restart (design documented in server.h)
- **Fix**: Implement hot-reload per the R-08 design notes already in server.h:
  SIGHUP → netlink event → purge idle share cache entries → next TREE_CONNECT
  picks up new config
- **Severity**: MEDIUM — operational convenience

---

## SUMMARY METRICS

| Category | Items | Critical | High | Medium | Low |
|----------|-------|----------|------|--------|-----|
| Security | 3 | 1 | 1 | 0 | 1 |
| Protocol | 11 | 0 | 3 | 7 | 1 |
| Quality | 5 | 0 | 0 | 0 | 5 |
| Testing | 7 | 0 | 2 | 4 | 1 |
| Performance | 4 | 0 | 0 | 1 | 3 |
| Upstream | 4 | 0 | 0 | 2 | 2 |
| Operations | 3 | 0 | 1 | 2 | 0 |
| **TOTAL** | **37** | **1** | **7** | **16** | **13** |

## ITEMS FIXED IN V1 (by 8 parallel worktree agents, not repeated above)

29 items from v1 are now resolved:
- S-01 through S-13 (all 13 security items — integer overflow, RDMA bounds, symlink,
  IPC NULL, EA underflow, directory memcpy, workqueue flush, etc.)
- P-02 FileStatInfo, P-03 credit algorithm, P-04 signing dup, P-05 SMB1 signing,
  P-06 oplock doc, P-07 shortname, P-08 domain name, P-12 compound error, P-13 IOCTL
  clamp, P-14 lock timeout
- Q-05 magic numbers (RFC1002_HEADER_LEN), Q-06 XXX comment, Q-07 TCP stack iovec,
  Q-08 TCP retry timeout, Q-09 auth buffer size, Q-10 RDMA FIXME, Q-11 BranchCache
  rotation, Q-12 Unicode doc, Q-13 smb2pdu.h FIXME
- T-02 syzkaller harness, T-03 KASAN CI, T-04 sparse CI, U-03 Kconfig URLs,
  U-04 SPDX headers, U-05 W=1/W=2 CI
- R-01 crash recovery, R-03 health sysfs, R-04 graceful drain, R-05 auth rate limit,
  R-07 module params doc, R-08 live reconfig design doc

## RECOMMENDED EXECUTION ORDER

1. **Immediate**: S-01 (SMB1 OOB read — CRITICAL), R-01 (share cache flush — operational)
2. **Week 1**: P-01, P-02, P-03 (session reconnect, multi-channel, durable timeout)
3. **Week 2**: S-02, P-04, P-05, P-07 (validation hardening)
4. **Week 3**: T-01, T-03 (transport tests, authenticated fuzzing)
5. **Week 4**: Q-01, Q-02 (pr_fmt sweep, lock annotations)
6. **Ongoing**: Remaining P-*, T-*, O-*, U-* items

---

*Generated: 2026-03-05 | Audited by: 5 parallel deep-audit agents*
*Previous v1: 66 items → 29 fixed → 37 remaining/new items in v2*
