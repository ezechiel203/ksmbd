# KSMBD Stellar-Level TODO List

Comprehensive prioritized roadmap to bring ksmbd to production-grade, upstream-quality,
stellar-level code. Generated from full codebase audit (74K source lines, 105K test lines).

**Legend**: [S] Security | [P] Protocol Compliance | [Q] Code Quality | [T] Testing |
[O] Performance | [U] Upstream Alignment | [R] Operational Readiness

---

## PRIORITY 1 — CRITICAL (Security / Correctness)

### S-01: Integer overflow in negotiate context assembly
- **File**: `src/protocol/smb2/smb2_negotiate.c:254-256`
- `conn->rdma_transform_count * sizeof(__le16)` has no `check_mul_overflow()`
- Attacker-controlled count can wrap, bypass bounds check, corrupt heap
- Same pattern at lines 350, 441, 501, 572 for other contexts
- **Fix**: Add `check_mul_overflow()` / `size_mul()` before every `next_size` computation

### S-02: RDMA transform array out-of-bounds write
- **File**: `src/protocol/smb2/smb2_negotiate.c:585-589`
- Loop breaks silently at ARRAY_SIZE limit but assignment at line 589 executes AFTER break check
- **Fix**: Move `conn->rdma_transform_ids[count]` assignment inside bounds-checked block; return error

### S-03: Negotiate context pointer advance without bounds check
- **File**: `src/protocol/smb2/smb2_negotiate.c:630-638`
- `offset` from previous iteration advances pointer without checking `offset <= len_of_ctxts`
- Crafted `DataLength` can cause OOB read
- **Fix**: `if (offset > len_of_ctxts) break;` before pointer arithmetic

### S-04: Information leak via uninitialized padding in negotiate contexts
- **File**: `src/protocol/smb2/smb2_negotiate.c` — `assemble_neg_contexts()`
- `round_up(ctxt_size, 8)` alignment padding is not zeroed
- Leaks kernel heap to remote client
- **Fix**: `memset()` padding bytes between contexts, or zero entire output buffer upfront

### S-05: Symlink target traversal bypass
- **File**: `src/fs/vfs.c:1242-1245`
- Only checks `name[0] == '/'` and `strstr(name, "..")` — misses `foo/../../etc/passwd`
- Mitigated by post-open `path_is_under()` check, but pre-open validation should be strict
- **Fix**: Walk each path component; reject any `..` segment (not just substring)

### S-06: Persistent handle state via /tmp — NOT SAFE for kernel module
- **File**: `src/protocol/smb2/smb2_create.c:892-929`
- TODO stubs propose writing to `/tmp/ksmbd_ph/` via `filp_open` + `kernel_write`
- Kernel modules must NOT write to user-visible filesystems
- **Fix**: Use kernel-internal data structures (RCU hashtable + serialization to disk via userspace daemon over netlink)

### S-07: RDMA encryption/signing not enforced (BUG-R01/R02)
- **File**: `src/transport/transport_rdma.c:1783-1820`
- Negotiated encryption/signing not applied to RDMA data path
- Only pr_warn logged; data sent plaintext
- **Fix**: Enforce transform or reject connection when negotiated but not applied

### S-08: QUIC ClientHello silent truncation
- **File**: `src/transport/transport_quic.c:291`
- Fixed 8192-byte `crypto_buf` — larger ClientHellos silently dropped
- **Fix**: Dynamic allocation or reject with CRYPTO_BUFFER_EXCEEDED alert

### S-09: Negotiate context len_of_ctxts underflow
- **File**: `src/protocol/smb2/smb2_negotiate.c:740`
- `len_of_ctxts -= offset` without checking `offset <= len_of_ctxts`
- Unsigned underflow wraps to huge value; subsequent iterations read OOB
- **Fix**: Validate `offset <= len_of_ctxts` before subtraction

### S-10: NULL dereference in IPC response handling
- **File**: `src/transport/transport_ipc.c:605-608`
- `entry->response` cast to `resp` without NULL check before `resp->payload_sz` access
- If allocation failed but entry was added, kernel panics
- **Fix**: Add `if (!resp) return -EINVAL;` after cast

### S-11: EA NextEntryOffset loop underflow
- **File**: `src/protocol/smb2/smb2_query_set.c:442-446`
- `buf_len -= next` without checking remaining space holds a full `struct smb2_ea_info`
- Crafted EA chain can read past buffer end
- **Fix**: Check `buf_len - next >= sizeof(struct smb2_ea_info)` before next iteration

### S-12: Directory info FileName memcpy without remaining-buffer check
- **File**: `src/protocol/smb2/smb2_dir.c:433,456,483,504,531,554`
- Multiple `memcpy(fibdinfo->FileName, conv_name, conv_len)` calls
- `conv_len` not validated against remaining output buffer space
- **Fix**: Add bounds check before each memcpy in directory info formatters

### S-13: Workqueue destroy without explicit flush
- **File**: `src/core/server.c` — `ksmbd_workqueue_destroy()`
- No `flush_workqueue()` before `destroy_workqueue()`
- Pending work items may race with destruction
- **Fix**: Call `flush_workqueue()` before `destroy_workqueue()`

---

## PRIORITY 2 — HIGH (Protocol Compliance / Correctness)

### P-01: Persistent handle recovery not implemented
- **File**: `src/protocol/smb2/smb2_create.c` (multiple TODOs)
- Durable/resilient handles cannot survive server restart
- **Fix**: Implement state serialization via netlink to ksmbd.mountd for persistence

### P-02: FileHardLinkInformation (0x46/0x47) query class stub
- **File**: `src/protocol/smb2/smb2_query_set.c`
- MS-FSCC FileStatInformation classes not fully implemented
- **Fix**: Implement FileStatInfo, FileStatLxInfo query handlers

### P-03: Credit management TODO
- **File**: `src/protocol/smb2/smb2_pdu_common.c:456`
- `TODO: Need to adjuct CreditRequest value according to...`
- Credit granting algorithm is simplistic; should follow MS-SMB2 §3.3.1.2 guidance
- **Fix**: Implement adaptive credit granting based on request type and server load

### P-04: Duplicate SIGNING_CAPABILITIES context not rejected
- **File**: `src/protocol/smb2/smb2_negotiate.c:728-735`
- PREAUTH and ENCRYPT have duplicate detection; SIGNING does not
- **Fix**: Add `signing_seen` flag like `preauth_seen`/`encrypt_seen`

### P-05: SMB1 authentication validation incomplete
- **File**: `src/protocol/smb1/smb1misc.c:27`
- `TODO: properly check client authentication and tree authentication`
- SMB1 paths skip proper auth validation
- **Fix**: Implement full NTLM validation for SMB1 or reject SMB1 when signing required

### P-06: Oplock break not checked in SMB1
- **File**: `src/protocol/smb1/smb1misc.c:42`
- `TODO: check for oplock break`
- **Fix**: Implement oplock break check in SMB1 request validation

### P-07: Short name (8.3) generation incomplete
- **File**: `src/protocol/common/smb_common.c:587`
- `TODO: Though this function conforms the restriction of 8.3 Filename spec...`
- **Fix**: Complete 8.3 name generation per MS-FSCC spec

### P-08: Domain name from configuration
- **File**: `src/core/auth.c:703`
- `TODO: use domain name that imported from configuration file`
- Hardcoded domain affects NTLM domain validation
- **Fix**: Read domain from ksmbd.conf via netlink/IPC

### P-09: QUIC stream buffer DoS vector
- **File**: `src/transport/transport_quic.c:1753,1923-1926`
- Fixed 128KB QUIC_STREAM_BUF_SIZE; slow-send attack fills buffer
- **Fix**: Implement backpressure / flow control; timeout incomplete PDUs

### P-10: Kerberos re-authentication stub
- **File**: `src/protocol/smb2/smb2_session.c:871`
- `TODO: need one more negotiation` for Kerberos re-auth
- **Fix**: Complete multi-round SPNEGO/Kerberos authentication

### P-11: Duplicate NETNAME/POSIX negotiate contexts not rejected
- **File**: `src/protocol/smb2/smb2_negotiate.c:679-709`
- PREAUTH, ENCRYPT, COMPRESS, RDMA all have duplicate detection
- NETNAME and POSIX_EXTENSIONS contexts lack duplicate flags
- **Fix**: Add `netname_seen`/`posix_seen` flags; reject duplicates per MS-SMB2 §3.3.5.2.4

### P-12: Compound error propagation limited to CREATE failures
- Only CREATE failures cascade to subsequent compound commands
- Intermediate FLUSH/WRITE failure in CREATE+FLUSH+WRITE chain doesn't propagate
- **Fix**: Cascade errors from any failing command in compound chain (MS-SMB2 §3.3.5.2.7)

### P-13: IOCTL OutputBufferLength not validated against max response
- **File**: `src/protocol/smb2/smb2_ioctl.c:99-102`
- No check that OutputBufferLength fits in connection's max response buffer
- **Fix**: Clamp or reject when exceeds `conn->vals->max_trans_size`

### P-14: Lock wait timeout hardcoded to 300 seconds
- **File**: `src/protocol/smb2/smb2_lock.c:271`
- `KSMBD_POSIX_LOCK_WAIT_MAX_JIFFIES (300 * HZ)` not configurable
- **Fix**: Make configurable via share/global config

---

## PRIORITY 3 — MEDIUM (Code Quality / Hardening)

### Q-01: Zero `pr_fmt` usage — 573 pr_* calls without module prefix
- All `pr_err`/`pr_warn`/`pr_info`/`pr_debug` lack `pr_fmt` macro
- Messages unattributed in dmesg
- **Fix**: Add `#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt` to every .c file
- Or use existing `ksmbd_debug`/`ksmbd_err` wrappers consistently

### Q-02: Only 7 lock annotations in entire codebase
- No `__must_hold`, `__acquires`, `__releases` annotations
- No `lockdep_assert_held()` calls (only 7 total annotations)
- **Fix**: Add sparse/lockdep annotations to all lock-protected functions

### Q-03: Only 3 sparse annotations (`__user`, `__rcu`, `__force`)
- Network buffer pointers lack `__user`/`__kernel` markers
- RCU-protected structures lack `__rcu` annotation
- **Fix**: Annotate all RCU pointers and user-space buffers for sparse checking

### Q-04: Only 1 `cond_resched()` call
- Long-running loops (directory enumeration, lock list walks) lack preemption points
- **Fix**: Add `cond_resched()` in: oplock break loops, directory scan loops, file close cleanup

### Q-05: Magic numbers without named constants
- Scattered hardcoded values across protocol handlers
- **Fix**: Define named constants in headers (e.g., `SMB2_MAX_NEG_CTXTS 16`)

### Q-06: `XXX` marker without explanation
- **File**: `src/core/misc.c:566`
- Bare `/* XXX */` comment with no explanation
- **Fix**: Document or fix the issue, then remove marker

### Q-07: TCP read/write per-call allocation
- **File**: `src/transport/transport_tcp.c:403-405, 489-491`
- `kmalloc_array()` for iovec on every read/write
- **Fix**: Pre-allocate iovec array per-connection or use stack allocation for small counts

### Q-08: TCP retry loop potential infinite sleep
- **File**: `src/transport/transport_tcp.c:444`
- `usleep_range(1000, 2000)` with potentially unlimited retries
- **Fix**: Add maximum retry count with exponential backoff

### Q-09: auth.h output buffer size TODO
- **File**: `src/include/core/auth.h:50`
- `TODO: callers must be updated to pass the output buffer size as max_blob_sz`
- **Fix**: Thread buffer size through all auth blob generation functions

### Q-10: RDMA RFC1002 header FIXME
- **File**: `src/transport/transport_rdma.c:1597`
- `//FIXME: skip RFC1002 header..`
- **Fix**: Properly handle RFC1002 framing in RDMA path

### Q-11: BranchCache secret rotation TODO
- **File**: `src/fs/ksmbd_branchcache.c:45`
- `TODO: Implement periodic secret rotation`
- **Fix**: Implement timer-based rotation or expose rotation trigger via sysfs

### Q-12: Unicode backslash remapping FIXME
- **File**: `src/encoding/unicode.c:457`
- `FIXME: We can not handle remapping backslash (UNI_SLASH)`
- **Fix**: Handle UNI_SLASH → path separator conversion properly

### Q-13: smb2pdu.h size analysis FIXME
- **File**: `src/include/protocol/smb2pdu.h:112`
- `BB FIXME - analyze following length BB`
- **Fix**: Verify and document the structure size

---

## PRIORITY 4 — TESTING GAPS

### T-01: Missing KUnit tests for critical subsystems
No dedicated test coverage for:
- `crypto_ctx.c` — crypto context management
- `ksmbd_buffer.c` — buffer pool allocator
- `ksmbd_config.c` — configuration handling
- `ksmbd_debugfs.c` — debugfs interface
- `ksmbd_create_ctx.c` — create context dispatch
- `ksmbd_app_instance.c` — APP_INSTANCE_ID handling
- `ksmbd_rsvd.c` — RSVD (shared virtual disk)
- `ksmbd_quota.c` — quota management
- `ksmbd_branchcache.c` — BranchCache
- `smb2fruit.c` — macOS AAPL extensions
- `smb2ops.c` — per-dialect operations table
- `compat.c` — kernel version compatibility
- **Fix**: Write KUnit suites for each; prioritize buffer, crypto_ctx, config

### T-02: No syzkaller harness for netlink interface
- Transport IPC is the primary kernel attack surface
- 56 kernel fuzz harnesses exist but none target netlink message parsing
- **Fix**: Write syzkaller description for ksmbd netlink family (KSMBD_GENL_NAME)

### T-03: No KASAN/KCSAN soak test in CI
- CI builds module but doesn't run under sanitizers
- **Fix**: Add QEMU-based KUnit run with `CONFIG_KASAN=y CONFIG_KCSAN=y` in CI

### T-04: No sparse/smatch/coccinelle in CI
- Build CI doesn't run static analysis
- **Fix**: Add `make C=2 CF="-D__CHECK_ENDIAN__"` and smatch jobs

### T-05: Missing error-path tests for RDMA and QUIC transports
- No test coverage for RDMA buffer deregistration errors
- No test coverage for QUIC handshake failures
- **Fix**: Add transport error injection tests

### T-06: No concurrent multi-session stress test
- Concurrency tests exist but don't simulate realistic multi-client load
- **Fix**: Add stress test spawning N kthreads with full session lifecycle

### T-07: Test-to-source ratio for SMB1 is low
- SMB1 has ~2000 lines of handler code with minimal test coverage
- **Fix**: Add comprehensive SMB1 negotiate/session/tree tests or remove SMB1 entirely

---

## PRIORITY 5 — PERFORMANCE OPTIMIZATION

### O-01: Per-read/write memory allocation in TCP transport
- Every `ksmbd_tcp_readv()`/`ksmbd_tcp_writev()` calls `kmalloc_array()`
- **Fix**: Use `kmem_cache` or per-connection pre-allocated iovec pool

### O-02: Global inode hashtable lock contention under high load
- Per-bucket rwlocks are good, but bucket count may be too small
- **Fix**: Profile under load; consider RCU-based lookup for read path

### O-03: Credit granting algorithm is simplistic
- Fixed credit grants don't adapt to server load or client behavior
- **Fix**: Implement adaptive credit algorithm per MS-SMB2 §3.3.1.2

### O-04: No NUMA awareness in worker thread allocation
- Work items may bounce between NUMA nodes
- **Fix**: Use `alloc_pages_node()` for work buffers; pin workers to NUMA-local CPUs

### O-05: Oplock break notification serialization
- Break notifications sent synchronously in some paths
- **Fix**: Queue breaks and batch-send; avoid holding file locks during network I/O

### O-06: Cache-line layout not optimized for hot structures
- `struct ksmbd_conn`, `struct ksmbd_work` fields not ordered by access frequency
- **Fix**: Profile with `perf c2c`; add `____cacheline_aligned` for contended fields

---

## PRIORITY 6 — UPSTREAM ALIGNMENT

### U-01: Divergence from upstream `fs/smb/server/`
- This out-of-tree build has significant divergence from mainline kernel
- New features (QUIC, compression, branchcache) not in upstream
- **Fix**: Track upstream patches; maintain clear delta documentation

### U-02: Missing upstream security fixes backport tracking
- No systematic process to pull CVE fixes from upstream ksmbd
- **Fix**: Create tracking document mapping upstream commits to local patches

### U-03: Kconfig help text references outdated URLs
- `https://github.com/cifsd-team/ksmbd-tools` may not be current
- **Fix**: Update to current repository URLs

### U-04: SPDX headers inconsistency
- Some files have `GPL-2.0-or-later`, others `GPL-2.0-only`
- **Fix**: Standardize on one license identifier across all files

### U-05: No `W=1 W=2 C=1 C=2` clean build verification
- Upstream submission requires zero warnings at all warning levels
- **Fix**: Add `ccflags-y += -Werror` option; fix all warnings

---

## PRIORITY 7 — OPERATIONAL READINESS

### R-01: Server crash recovery under heavy smbtorture
- `refcount_t` saturation in `ksmbd_conn_transport_destroy` during stop_sessions
- Server enters `SERVER_RESET` state requiring `rmmod + insmod`
- **Fix**: Add graceful recovery path; implement connection drain timeout

### R-02: Kernel share config cache not cleared on daemon restart
- Share configs cached in RCU hashtable; `ksmbdctl restart` doesn't flush
- Only `rmmod + insmod` clears stale share flags
- **Fix**: Add netlink command to flush/invalidate share cache on daemon reconnect

### R-03: No health check / watchdog mechanism
- No sysfs/procfs status to monitor server health
- **Fix**: Expose connection count, active sessions, error rates via sysfs

### R-04: No graceful shutdown with session drain
- `ksmbd.control -s` kills connections without waiting for in-flight requests
- **Fix**: Implement drain phase: reject new requests, wait for outstanding, then shutdown

### R-05: No rate limiting on authentication failures
- Brute-force password attacks not throttled
- **Fix**: Add per-IP auth failure counter with exponential backoff delay

### R-06: No connection audit logging
- No structured logging for security events (auth failures, access denied, etc.)
- **Fix**: Add audit trail via `audit_log()` or structured netlink events

### R-07: Module parameters lack descriptions
- Missing `MODULE_PARM_DESC()` for runtime-tunable parameters
- **Fix**: Add descriptive parameter documentation

### R-08: No live reconfiguration support
- Share/user changes require daemon restart
- **Fix**: Implement hot-reload via netlink notification from daemon to kernel

---

## SUMMARY METRICS

| Category | Items | Critical | High | Medium |
|----------|-------|----------|------|--------|
| Security | 13 | 13 | 0 | 0 |
| Protocol Compliance | 14 | 0 | 14 | 0 |
| Code Quality | 13 | 0 | 0 | 13 |
| Testing | 7 | 0 | 3 | 4 |
| Performance | 6 | 0 | 0 | 6 |
| Upstream | 5 | 0 | 0 | 5 |
| Operations | 8 | 0 | 3 | 5 |
| **TOTAL** | **66** | **13** | **20** | **33** |

## RECOMMENDED EXECUTION ORDER

1. **Week 1-2**: S-01 through S-08 (all critical security fixes)
2. **Week 3-4**: P-01 through P-05 (high-impact protocol compliance)
3. **Week 5-6**: Q-01 through Q-04 (lock annotations, pr_fmt, sparse)
4. **Week 7-8**: T-01 through T-04 (test coverage + CI hardening)
5. **Ongoing**: Performance profiling (O-*), upstream alignment (U-*), ops (R-*)

---

*Generated: 2026-03-05 | Audited by: linux-kernel-dev skill (Linus-level bar)*
*Source: 5 parallel codebase audit agents covering security, VFS, protocol, tests, transport*
