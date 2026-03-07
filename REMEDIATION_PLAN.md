# KSMBD Comprehensive Remediation Plan

**Date**: 2026-02-23
**Branch**: `phase1-security-hardening`
**Source Reviews**: 8 REVIEWFILES, 5 CDXREVIEW files, 5 standalone reviews (FULLREVIEW, FULLREVIEWBIS, EXPERT_REVIEW, SECURITY_CODE_REVIEW, COMPREHENSIVE_MULTI_STANDARD_REVIEW)
**Total Raw Findings**: ~312 across all reviews (with heavy overlap/duplication)
**Deduplicated Unique Issues**: ~185

---

## Executive Summary

Cross-referencing all review findings against the current `phase1-security-hardening` branch reveals that **~70% of critical and high-severity items have already been addressed** through 30+ targeted commits. The remaining work falls into four tiers:

| Tier | Count | Description |
|------|-------|-------------|
| **DONE** | ~130 | Already fixed on this branch |
| **Tier 1 (Critical)** | 12 | Security/safety issues requiring immediate attention |
| **Tier 2 (High)** | 18 | Important correctness, performance, and protocol gaps |
| **Tier 3 (Medium)** | 25 | Quality improvements and feature completions |
| **Tier 4 (Low/Future)** | ~20 | Nice-to-have, long-term architecture work |

---

## Already Completed (No Action Needed)

The following major categories are VERIFIED FIXED on this branch. These items appear across multiple review files but require no further action:

### Security (Fixed)
- [x] CAP_NET_ADMIN check made unconditional (`transport_ipc.c`)
- [x] SecurityBufferOffset/Length bounds validation (`smb2_session.c`)
- [x] CreateOptions `&=` fix (was `=`, now correct bitwise AND) (`smb2_create.c`)
- [x] ssleep(5) replaced with non-blocking mechanism (`smb2_session.c`)
- [x] IOCTL InputOffset bounds checking (`smb2_ioctl.c`)
- [x] EA set loop buffer overflow protection (`smb2_create.c`)
- [x] NDR unaligned access fixed with `put_unaligned_le*()` (`ndr.c`)
- [x] Timing-safe `crypto_memneq()` for auth/signing (`auth.c`, `smb2_pdu_common.c`)
- [x] Passkey zeroed in FS_OBJECT_ID_INFORMATION (`smb2_query_set.c`)
- [x] Session binding UAF fixed with proper locking (`user_session.c`)
- [x] AES-GMAC signing implemented (`auth.c`, `smb2_negotiate.c`)
- [x] GCM nonce monotonic counter (`smb2_pdu_common.c`)
- [x] Session state rw_semaphore protection (`connection.h`)
- [x] Durable handle scavenger race fix (`ksmbd_resilient.c`)

### Performance (Fixed)
- [x] Buffer pool for READ/WRITE (two-tier: 64KB+1MB) (`ksmbd_buffer.c`)
- [x] Zero-copy I/O via splice for SMB2 READ (`smb2_read_write.c`)
- [x] Dedicated slab caches for work, fp, opinfo (`ksmbd_work.c`, `oplock.c`)
- [x] RCU for share_config and session lookups (`mgmt/share_config.c`)

### Protocol Compliance (Fixed)
- [x] CHANGE_NOTIFY via fsnotify (`smb2_notify.c`, `ksmbd_notify.c`)
- [x] Reparse point FSCTLs (SET/GET/DELETE) (`ksmbd_reparse.c`)
- [x] Resilient handles via FSCTL_LMR_REQUEST_RESILIENCY (`ksmbd_resilient.c`)
- [x] Lock sequence validation (`smb2_lock.c`)
- [x] SACL support in security descriptors (`smbacl.c`)
- [x] Quota query support (`ksmbd_quota.c`)
- [x] FILE_VALID_DATA_LENGTH, NORMALIZED_NAME info handlers (`ksmbd_info.c`)
- [x] FSCTL handlers: TRIM, ALLOCATED_RANGES, ZERO_DATA, PIPE_WAIT (`ksmbd_fsctl.c`)
- [x] Apple Fruit module: AFP_AfpInfo, TM quota, ReadDirAttr (`smb2fruit.c`)
- [x] RDMA transform capabilities negotiate context

### Architecture (Fixed)
- [x] smb2pdu.c decomposed into 12 focused compilation units
- [x] Hook system for extensible SMB processing (`ksmbd_hooks.c`)
- [x] CONFIG_KSMBD_FRUIT added to Kconfig

### Testing (Fixed)
- [x] 20 KUnit test modules (`test/ksmbd_test_*.c`)
- [x] 13 fuzz harnesses (`test/fuzz/*_fuzz.c`)
- [x] CI/CD workflows with build verification
- [x] Integration test infrastructure (smbtorture, xfstests)

---

## Tier 1: Critical — Requires Immediate Action

These are security vulnerabilities, crash vectors, or data corruption risks that remain unaddressed. Each item is cross-referenced to the review(s) that identified it.

### T1-01: Validate IPC daemon response contents
**Source**: REVIEWFILES/03-SECURITY.md (CRITICAL-02), REVIEWFILES/TODO.md (#2)
**File**: `transport_ipc.c:284-328`
**Problem**: Kernel completely trusts daemon response contents — UIDs, paths, and security blobs are not validated. A compromised daemon can grant access to any resource.
**Fix**: Add validation of daemon responses: check UIDs exist in system, verify paths are within allowed roots, validate security blob sizes.
**Effort**: M
**Risk**: CVSS 8.4 — privilege escalation via compromised daemon

### T1-02: Per-IP connection rate limiting in kernel
**Source**: REVIEWFILES/03-SECURITY.md (CRITICAL-04, CRITICAL-05), REVIEWFILES/TODO.md (#3)
**File**: `connection.c`, `transport_tcp.c`
**Problem**: No per-IP rate limiting in kernel module. Unauthenticated attacker can exhaust kernel memory via connection flood. Auth failure delay is per-connection, not per-IP.
**Fix**: Add per-IP connection counter with configurable limit. Implement exponential backoff for auth failures keyed by source IP.
**Effort**: M
**Risk**: CVSS 7.5 — pre-authentication DoS

### T1-03: SMB1 attack surface assessment
**Source**: REVIEWFILES/03-SECURITY.md (CRITICAL-03), REVIEWFILES/TODO.md (#7)
**File**: Multiple (31 files with `CONFIG_SMB_INSECURE_SERVER` conditionals)
**Problem**: SMB1 support adds massive attack surface with well-known vulnerability classes. Code scattered across 31 files, not cleanly isolated.
**Fix**: Audit all SMB1 code paths. Either: (a) remove CONFIG_SMB_INSECURE_SERVER entirely, (b) isolate all SMB1 into dedicated files, or (c) add strong input validation to every SMB1 handler. Recommend option (a).
**Effort**: L
**Risk**: CVSS 7.5 — SMB1 has well-known exploits (MS17-010 class)

### T1-04: Path traversal via symlink TOCTOU
**Source**: REVIEWFILES/03-SECURITY.md (HIGH-01), FULLREVIEW.md, TODO.md (#22)
**File**: `vfs.c` (path resolution), `smb2_create.c`
**Problem**: Between `ksmbd_vfs_kern_path()` and `dentry_open()`, symlinks can be swapped by an attacker to escape the share boundary.
**Fix**: Use `O_NOFOLLOW` consistently. Add post-open path verification that the opened file is still within the share root. Consider `LOOKUP_BENEATH` (Linux 5.6+).
**Effort**: M
**Risk**: CVSS 7.1 — share boundary escape

### T1-05: Compound request FID cross-session validation
**Source**: REVIEWFILES/03-SECURITY.md (HIGH-02), FULLREVIEWBIS.md (#10)
**File**: `smb2_pdu_common.c` (compound dispatch), `smb2_read_write.c`
**Problem**: FID propagation in compound requests may allow using FIDs from different sessions/tree connections. COPYCHUNK's `ksmbd_lookup_foreign_fd()` not restricted to current session.
**Fix**: Validate that compound FIDs belong to the same session and tree connection. Restrict `ksmbd_lookup_foreign_fd()` to same-session lookups.
**Effort**: M
**Risk**: CVSS 6.8 — cross-session data access

### T1-06: SetInfo/QueryInfo buffer size validation gaps
**Source**: REVIEWFILES/03-SECURITY.md (HIGH-06), REVIEWFILES/02-SAFETY.md (M-08, M-09), FULLREVIEWBIS.md
**File**: `smb2_query_set.c`
**Problem**: Multiple info-level handlers don't validate available response buffer space before writing. Specifically: `build_sec_desc()` not bounded, FILE_ALL_INFORMATION variable-length filename not bounded.
**Fix**: Pass available buffer size to all info-level handlers. Add explicit size checks before each variable-length field write.
**Effort**: M
**Risk**: CVSS 6.5 — heap buffer overflow

### T1-07: RDMA buffer descriptor validation
**Source**: REVIEWFILES/03-SECURITY.md (HIGH-08), REVIEWFILES/02-SAFETY.md (I-02), TODO.md (#26)
**File**: `transport_rdma.c`, `smb2_read_write.c`
**Problem**: Client-supplied RDMA descriptor array and ChannelInfoLength not fully validated against received buffer boundaries.
**Fix**: Validate complete descriptor array fits within the received message. Check each descriptor's offset and length individually.
**Effort**: M
**Risk**: CVSS 6.5 — OOB read/write via RDMA descriptors

### T1-08: Lock count not bounded against buffer size
**Source**: REVIEWFILES/03-SECURITY.md (HIGH-09), TODO.md (#27)
**File**: `smb2_lock.c`
**Problem**: `LockCount` from wire not bounded against actual received data size. Loop reads past buffer boundary.
**Fix**: Validate `LockCount * sizeof(struct smb2_lock_element) <= available_buf_size` before iterating.
**Effort**: S
**Risk**: CVSS 6.5 — OOB read in lock processing

### T1-09: validate_negotiate_info dialect count check
**Source**: REVIEWFILES/03-SECURITY.md (HIGH-10), TODO.md (#28)
**File**: `smb2_ioctl.c` (validate_negotiate_info handler)
**Problem**: No validation that `DialectCount * sizeof(__le16)` fits in the buffer.
**Fix**: Add `if (neg_info->DialectCount > (in_buf_len - offsetof(...)) / sizeof(__le16)) return -EINVAL;`
**Effort**: S
**Risk**: CVSS 6.0 — OOB read in negotiate validation

### T1-10: POSIX context filename validation bypass
**Source**: REVIEWFILES/03-SECURITY.md (HIGH-11), TODO.md (#29)
**File**: `smb2_create.c`
**Problem**: When POSIX extensions are enabled, `ksmbd_validate_filename()` is skipped, allowing control characters, wildcards, and path separators.
**Fix**: Always validate filenames regardless of POSIX context. Adjust validation rules for POSIX (allow more chars) but still block control chars and path traversal.
**Effort**: S
**Risk**: CVSS 6.5 — filename injection

### T1-11: Crypto context livelock under memory pressure
**Source**: REVIEWFILES/02-SAFETY.md (F-02), TODO.md (#13)
**File**: `crypto_ctx.c:138`
**Problem**: Infinite `wait_event` loop when crypto context allocation fails. Under memory pressure, all worker threads can deadlock here.
**Fix**: Add timeout to `wait_event` (e.g., `wait_event_timeout`). Return NULL on timeout and propagate -ENOMEM to caller.
**Effort**: S
**Risk**: Kernel thread deadlock under memory pressure

### T1-12: NOTIFY watch pending_work UAF
**Source**: CDXREVIEW/FINDINGS.md (KSMBD-CRIT-001)
**File**: `ksmbd_notify.c:132,140,339,398`, `server.c:288-289`, `vfs_cache.c:477`
**Problem**: The notify watch structure keeps raw pointers to `ksmbd_work` objects whose lifetime is managed by the work queue. Work can be freed by completion before the watch is detached, creating a UAF window on file close.
**Fix**: Introduce a refcounted notify context struct decoupled from `ksmbd_work` lifetime. Never store raw work pointers in watch structures. Synchronize watch detach with work completion.
**Effort**: M
**Risk**: Kernel memory corruption / UAF on CHANGE_NOTIFY + close race

---

## Tier 2: High — Important Correctness and Quality

### T2-01: Signing enforcement gap after negotiate
**Source**: REVIEWFILES/03-SECURITY.md (HIGH-05), FULLREVIEW.md (#4 protocol)
**File**: `smb2_pdu_common.c`, `smb2_negotiate.c`
**Problem**: MITM can strip the signing flag during negotiation. Server only verifies signatures when client sets `SMB2_FLAGS_SIGNED`. When `server signing = mandatory`, the server should enforce signing regardless of flags.
**Fix**: When signing is mandatory and session is established, reject unsigned requests even if the flag is not set.
**Effort**: S

### T2-02: Session keys and sensitive data scrubbing
**Source**: FULLREVIEW.md (#3 protocol), FULLREVIEWBIS.md
**File**: `mgmt/user_session.c:157-173`, `mgmt/user_config.c:84-91`
**Problem**: Session signing/encryption keys and password hashes freed with `kfree()` without scrubbing. Sensitive data remains in freed heap pages.
**Fix**: Replace `kfree()` with `kfree_sensitive()` for all key material and password hashes.
**Effort**: S

### T2-03: Durable handle PersistentFileId randomization
**Source**: REVIEWFILES/03-SECURITY.md (HIGH-04), TODO.md (#23)
**File**: `vfs_cache.c` (file handle allocation)
**Problem**: Sequential ID allocation makes persistent handles predictable. Timing side-channel reveals valid handles.
**Fix**: Use `get_random_bytes()` or a hash-based scheme for PersistentFileId generation.
**Effort**: S

### T2-04: write_pipe data offset validation
**Source**: REVIEWFILES/03-SECURITY.md (HIGH-07), TODO.md (#25)
**File**: `smb2_read_write.c` (write_pipe handler)
**Problem**: Off-by-one in offset calculation for pipe write. Boundary check passes but data_buf may point past buffer.
**Fix**: Correct offset calculation and add explicit bounds check.
**Effort**: S

### T2-05: Global inode_hash_lock contention
**Source**: REVIEWFILES/01-SPEED.md (PERF-019), TODO.md (#15)
**File**: `vfs_cache.c:34`
**Problem**: Single rwlock protecting all 16K inode hash buckets. Severe bottleneck under 10K+ concurrent clients.
**Fix**: Convert to per-bucket spinlocks or RCU-protected hash list.
**Effort**: M

### T2-06: Connection list lock contention
**Source**: REVIEWFILES/01-SPEED.md (PERF-020)
**File**: `connection.c`
**Problem**: Global rwsemaphore for the connection list. Becomes bottleneck at high connection rates.
**Fix**: Per-bucket locking for connection hash table.
**Effort**: M

### T2-07: Lease list lock contention
**Source**: REVIEWFILES/01-SPEED.md (PERF-021)
**File**: `oplock.c`
**Problem**: Global rwlock for lease list. Contention under oplock-heavy workloads.
**Fix**: Per-file or per-inode lease locking.
**Effort**: M

### T2-08: Thread-per-connection scalability limit
**Source**: REVIEWFILES/01-SPEED.md (PERF-037, PERF-050)
**File**: `transport_tcp.c`
**Problem**: One kernel thread per connection. At 10K connections = 200MB stack memory alone. Does not scale for large deployments.
**Fix**: Move to io_uring or epoll-based event loop with worker thread pool. This is a major architectural change.
**Effort**: XL (long-term)

### T2-09: DFS referral support
**Source**: REVIEWFILES/05-MISSING-CORE.md, REVIEWFILES/06-MISSING-MODULE.md, TODO.md (#44)
**File**: `smb2_ioctl.c` (FSCTL_DFS_GET_REFERRALS handler)
**Problem**: Returns STATUS_FS_DRIVER_REQUIRED. Enterprise namespace navigation broken.
**Fix**: Implement DFS referral handler with netlink extension for daemon-side DFS configuration. Start with standalone DFS (no domain-based).
**Effort**: L

### T2-10: VSS/Previous Versions support
**Source**: REVIEWFILES/05-MISSING-CORE.md, REVIEWFILES/06-MISSING-MODULE.md, TODO.md (#45, #49)
**File**: `smb2_ioctl.c`, `smb2_create.c` (TIMEWARP context)
**Problem**: FSCTL_SRV_ENUMERATE_SNAPSHOTS not implemented. @GMT token parsing not implemented. Windows "Previous Versions" tab is empty.
**Fix**: Implement snapshot enumeration backend (btrfs subvolume list, ZFS snapshots, LVM). Parse @GMT-YYYY.MM.DD-HH.MM.SS tokens in path resolution.
**Effort**: L

### T2-11: srv_mutex serialization per connection
**Source**: REVIEWFILES/01-SPEED.md (PERF-024)
**File**: `connection.c/h`
**Problem**: `srv_mutex` serializes all response sends on a connection. With compound requests and multi-credit workloads, this is a bottleneck.
**Fix**: Use per-request send ordering or lock-free send queue.
**Effort**: M

### T2-12: Signing enforcement on oplock break acknowledgments
**Source**: FULLREVIEWBIS.md (CRITICAL #2)
**File**: `smb2_pdu_common.c` (signature verification dispatch)
**Problem**: Oplock break acknowledgments (client-to-server) are exempt from signing verification. A MITM can inject forged oplock break acks to corrupt data.
**Note**: Server-to-client oplock breaks being unsigned is correct per spec. But client-to-server acks on signed sessions MUST be verified.
**Fix**: Verify signatures on oplock break ack requests when the session has signing enabled.
**Effort**: S

### T2-13: Connection count check race condition
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM)
**File**: `transport_tcp.c`
**Problem**: Connection count checked and incremented non-atomically. Race window allows exceeding the limit.
**Fix**: Use `atomic_inc_unless_greater()` pattern or hold a lock across check-and-increment.
**Effort**: S

### T2-14: IPC entry leak on timeout
**Source**: REVIEWFILES/02-SAFETY.md (E-07)
**File**: `transport_ipc.c`
**Problem**: When daemon doesn't respond within timeout, the IPC entry is not properly cleaned up.
**Fix**: Add timeout cleanup handler that frees the IPC entry and returns error to kernel.
**Effort**: S

### T2-15: ksmbd-tools rpc_samr.c heap overflow
**Source**: CDXREVIEW/FINDINGS.md (KSMBD-HIGH-003)
**File**: `ksmbd-tools/mountd/rpc_samr.c:446-458`
**Problem**: Profile path buffer allocated one byte short (missing NUL terminator). strcat chain can overflow.
**Fix**: Replace strcat chain with `g_strdup_printf("\\\\%s\\%s\\profile", hostname, user->name)` or use `snprintf()` with proper size calculation.
**Effort**: S

### T2-16: Missing mnt_want_write() in smb2_set_ea
**Source**: REVIEWFILES/02-SAFETY.md (A-01)
**File**: `smb2_create.c` or `smb2_query_set.c` (EA set handler)
**Problem**: Writes to filesystem without calling `mnt_want_write()` first. Can write to read-only mounts.
**Fix**: Add `mnt_want_write_file()` before EA modifications and `mnt_drop_write_file()` after.
**Effort**: S

### T2-17: check_lock_range O(n) scan
**Source**: REVIEWFILES/01-SPEED.md (PERF-003)
**File**: `smb2_lock.c`
**Problem**: Every READ/WRITE does an O(n) scan of all locks to check for conflicts. With many locks, this is a hot-path bottleneck.
**Fix**: Use an interval tree (rbtree-based) for lock ranges. Linux already provides `include/linux/interval_tree.h`.
**Effort**: M

### T2-18: Run_tests.sh initialization fix
**Source**: CDXREVIEW/FINDINGS.md (KSMBD-MED-004)
**File**: `run_tests.sh`
**Problem**: Script fails immediately — logs to uninitialized path, references missing test_framework/ directory.
**Fix**: Move `parse_args` and `setup_environment` before any logging. Update paths to match actual test directory structure.
**Effort**: S

---

## Tier 3: Medium — Quality and Feature Completions

### T3-01: Constant-time comparison in all auth paths
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM), TODO.md (#63)
**File**: `auth.c`
**Problem**: While main NTLM/signing paths use `crypto_memneq()`, there may be residual `memcmp()` calls in edge paths (e.g., signature blob validation at auth.c:583).
**Fix**: Audit all comparison points and use `crypto_memneq()` everywhere security-relevant.
**Effort**: S

### T3-02: SID num_subauth range validation
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM), FULLREVIEWBIS.md
**File**: `smbacl.c`
**Problem**: SID and ACE counts from wire data not fully validated against buffer bounds.
**Fix**: Validate `num_subauth <= SID_MAX_SUB_AUTHORITIES` and verify total SID size fits buffer.
**Effort**: S

### T3-03: Negotiate context parsing buffer overread
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM)
**File**: `smb2_negotiate.c`
**Problem**: Negotiate context parsing may overread if contexts overlap or total length is inconsistent.
**Fix**: Cross-check total negotiate context length against individual context lengths.
**Effort**: S

### T3-04: ipc_timeout multiplication overflow
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM)
**File**: `transport_ipc.c`
**Problem**: IPC timeout value multiplied for kernel timer without overflow check.
**Fix**: Add overflow check on multiplication result.
**Effort**: S

### T3-05: FSCTL_SET_ZERO_DATA signedness issue
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM)
**File**: `smb2_ioctl.c` or `ksmbd_fsctl.c`
**Problem**: Signed/unsigned mismatch in zero data offset handling.
**Fix**: Use consistent unsigned types for offset/length.
**Effort**: S

### T3-06: Stream name length confusion
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM)
**File**: `smb2_create.c` or `vfs.c`
**Problem**: `stream_name_len` used as stream data size in some paths.
**Fix**: Separate stream name length from stream data size variables.
**Effort**: S

### T3-07: Embedded null bytes in filenames
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM)
**File**: `smb2_create.c`, `unicode.c`
**Problem**: Embedded null bytes in UTF-16 filenames not properly detected.
**Fix**: Add explicit null byte check in filename conversion.
**Effort**: S

### T3-08: NDR realloc unbounded growth
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM)
**File**: `ndr.c`
**Problem**: NDR buffer reallocation allows unbounded growth from attacker-controlled counts.
**Fix**: Add maximum NDR buffer size limit (e.g., KSMBD_IPC_MAX_MESSAGE_SIZE).
**Effort**: S

### T3-09: Apple NFS ACE enforcement
**Source**: FULLREVIEW.md (Apple #2), EXPERT_REVIEW.md
**File**: `smbacl.c`, `smb2fruit.c`
**Problem**: `kSupportsSMB2NfsAces` advertised but NFS ACEs not enforced. macOS sets NFS-style ACEs that are silently ignored.
**Fix**: Map NFS ACE well-known SIDs (S-1-5-88-1/2/3) to Unix mode/UID/GID and enforce them.
**Effort**: M

### T3-10: AFP_Resource stream I/O
**Source**: FULLREVIEW.md (Apple #3), EXPERT_REVIEW.md
**File**: `smb2fruit.c`, `vfs.c`
**Problem**: AFP_Resource stream advertised but no actual I/O implementation. Resource fork read/write operations are stubs.
**Fix**: Map AFP_Resource to xattr-backed storage for resource fork data.
**Effort**: M

### T3-11: Unstable Volume UUID
**Source**: FULLREVIEW.md (Apple #6)
**File**: `smb2_query_set.c` (FS_OBJECT_ID)
**Problem**: Volume UUID was derived from user passkey (now zeroed). Needs a stable, per-share UUID for Time Machine.
**Fix**: Derive UUID from server machine-id + share name hash (deterministic, stable across reboots and password changes).
**Effort**: S

### T3-12: Session ID predictability
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM), FULLREVIEWBIS.md (#10)
**File**: `mgmt/ksmbd_ida.c`
**Problem**: Sequential IDA allocation makes session IDs predictable.
**Fix**: XOR IDA-allocated ID with a per-boot random value to make session IDs unpredictable.
**Effort**: S

### T3-13: refcount_t migration
**Source**: REVIEWFILES/04-EXTENSIBILITY.md, TODO.md (#18)
**File**: Multiple files using `atomic_t` for refcounting
**Problem**: `atomic_t` doesn't protect against use-after-free via reference count underflow. `refcount_t` adds saturation and overflow protection.
**Fix**: Replace all `atomic_t` reference counts with `refcount_t` and corresponding API (`refcount_inc`, `refcount_dec_and_test`, etc.).
**Effort**: S (mechanical)

### T3-14: Stack usage in smb2_open
**Source**: REVIEWFILES/02-SAFETY.md (K-04)
**File**: `smb2_create.c`
**Problem**: smb2_open() may use excessive stack (risk on 8KB stack configs). Multiple large local variables and deep call chains.
**Fix**: Move large locals to heap allocation. Consider splitting the function.
**Effort**: M

### T3-15: CI: KUnit actual execution
**Source**: CDXREVIEW/FINDINGS.md (KSMBD-MED-005)
**File**: `.github/workflows/test.yml`
**Problem**: CI counts test files but doesn't actually run KUnit tests or fuzz harnesses.
**Fix**: Add `kunit.py run` step for declared kernel versions. Add kernel build matrix using actual version-specific headers.
**Effort**: M

### T3-16: CI: Make sparse/cppcheck blocking
**Source**: CDXREVIEW/FINDINGS.md (KSMBD-MED-005)
**File**: `.github/workflows/build.yml`
**Problem**: Sparse and cppcheck failures are non-blocking (`continue-on-error: true`).
**Fix**: Remove `continue-on-error` for static analysis steps. Fix all current violations first.
**Effort**: M

### T3-17: Checkpatch compliance
**Source**: CDXREVIEW/FINDINGS.md (KSMBD-MED-007)
**File**: Multiple (110 files, 115 errors, 1225 warnings)
**Problem**: LINUX_VERSION_CODE scattered in 456 locations. Various style issues.
**Fix**: Centralize all version checks into `ksmbd_compat.h`. Run `checkpatch --fix-inplace` for mechanical fixes. Focus on files being actively modified.
**Effort**: L (incremental)

### T3-18: Compression negotiate context
**Source**: REVIEWFILES/05-MISSING-CORE.md, REVIEWFILES/06-MISSING-MODULE.md
**File**: `smb2_negotiate.c`
**Problem**: COMPRESSION_CAPABILITIES context parsed but always responds with SMB3_COMPRESS_NONE.
**Fix**: Implement at least LZ77 compression algorithm with transform header processing. This reduces bandwidth for compressible payloads.
**Effort**: L

### T3-19: Named pipe enhancements (PIPE_PEEK, fragmented RPC)
**Source**: REVIEWFILES/06-MISSING-MODULE.md
**File**: `smb2_ioctl.c`
**Problem**: FSCTL_PIPE_PEEK not implemented. Fragmented RPC not supported.
**Fix**: Implement pipe peek for non-destructive read. Add RPC fragment reassembly.
**Effort**: M

### T3-20: Persistent handle serialization
**Source**: REVIEWFILES/06-MISSING-MODULE.md
**File**: `ksmbd_resilient.c`, `vfs_cache.c`
**Problem**: Persistent handles exist only in memory. They don't survive daemon restart.
**Fix**: Serialize persistent handle state to disk. Restore on daemon startup.
**Effort**: L

### T3-21: Documentation accuracy audit
**Source**: CDXREVIEW/FINDINGS.md (KSMBD-MED-006), EXPERT_REVIEW.md
**File**: `README.md`
**Problem**: README claims exceed implemented behavior (e.g., "Complete Apple Integration", "14x faster directory listings" without evidence).
**Fix**: Audit all README claims. Mark incomplete features. Add actual benchmark methodology and results.
**Effort**: S

### T3-22: Debug message information leakage
**Source**: REVIEWFILES/03-SECURITY.md (LOW)
**File**: Multiple
**Problem**: `pr_err` and debug messages leak internal filesystem paths and user information.
**Fix**: Use `pr_err_ratelimited` consistently. Redact paths in non-debug messages.
**Effort**: S

### T3-23: Benchmark statistical methodology
**Source**: CDXREVIEW/FINDINGS.md (KSMBD-LOW-008)
**File**: `benchmarks/run_benchmarks.sh`
**Problem**: Single-pass execution with no repetitions, confidence intervals, or outlier detection.
**Fix**: Add warm-up run, 5-10 trial repetitions, statistical reporting (mean, median, stdev, percentiles).
**Effort**: S

### T3-24: Socket reference counting on teardown
**Source**: REVIEWFILES/02-SAFETY.md (A-04)
**File**: `transport_tcp.c`
**Problem**: Socket leak on connection init failure paths.
**Fix**: Audit all error paths in `ksmbd_tcp_new_connection()` for proper socket release.
**Effort**: S

### T3-25: Cross-mount share root escape
**Source**: REVIEWFILES/03-SECURITY.md (MEDIUM)
**File**: `vfs.c`
**Problem**: With `crossmnt = yes`, client can traverse mount points to reach unintended filesystems.
**Fix**: Add optional enforcement that paths cannot cross into mount points outside the share root, regardless of crossmnt setting, when security is critical.
**Effort**: M

---

## Tier 4: Low/Future — Architecture and Nice-to-Have

These items are important for long-term health but not urgent:

| ID | Item | Source | Effort |
|----|------|--------|--------|
| T4-01 | Full VFS backend abstraction (`struct ksmbd_vfs_ops`) | 04-EXTENSIBILITY | XL |
| T4-02 | `ksmbd_conn` decomposition into sub-structs | 04-EXTENSIBILITY | XL |
| T4-03 | Protocol version registration API | 04-EXTENSIBILITY | L |
| T4-04 | `ksmbd_work` layered context model | 04-EXTENSIBILITY | L |
| T4-05 | io_uring / epoll event loop (replace thread-per-conn) | 01-SPEED | XL |
| T4-06 | SMB over QUIC | 05-MISSING-CORE | XL |
| T4-07 | Witness Protocol (MS-SWN) for clustering | 06-MISSING-MODULE | XL |
| T4-08 | Spotlight/mdssvc search integration | 06-MISSING-MODULE | XL |
| T4-09 | Print share support | 06-MISSING-MODULE | L |
| T4-10 | ODX (Offloaded Data Transfer) | 06-MISSING-MODULE | XL |
| T4-11 | RDMA encryption and V2 channel | 06-MISSING-MODULE | L |
| T4-12 | inode_hash table dynamic sizing | 01-SPEED | M |
| T4-13 | NUMA-aware memory allocation | 01-SPEED | M |
| T4-14 | TCP_CORK for multi-iov responses | 01-SPEED | S |
| T4-15 | Socket buffer size auto-tuning | 01-SPEED | S |
| T4-16 | Async crypto acceleration | 01-SPEED | M |
| T4-17 | static_key for feature checks | 01-SPEED | S |
| T4-18 | IDR to XArray migration | 01-SPEED | M |
| T4-19 | APP_INSTANCE_ID/VERSION (Hyper-V) | 05-MISSING-CORE | M |
| T4-20 | Coccinelle scripts for automated checks | FULLREVIEW | M |

---

## Implementation Roadmap

### Phase 2A: Critical Security (Tier 1) — Estimated 2-3 weeks
```
Week 1:  T1-08, T1-09, T1-10, T1-11 (all S effort, bounds checks)
         T1-04 (path traversal TOCTOU, M effort)
Week 2:  T1-01 (IPC validation, M effort)
         T1-02 (per-IP rate limiting, M effort)
         T1-05 (compound FID validation, M effort)
Week 3:  T1-06 (SetInfo bounds, M effort)
         T1-07 (RDMA descriptor validation, M effort)
         T1-12 (NOTIFY watch UAF, M effort)
         T1-03 (SMB1 assessment, L effort — start)
```

### Phase 2B: High Priority (Tier 2) — Estimated 3-4 weeks
```
Week 4:  T2-01, T2-02, T2-03, T2-04, T2-12, T2-13, T2-14 (all S effort)
         T2-15 (rpc_samr.c, S effort)
         T2-16, T2-18 (S effort)
Week 5:  T2-05, T2-06, T2-07, T2-11 (lock contention, M effort each)
         T2-17 (interval tree for locks, M effort)
Week 6-7: T2-09 (DFS, L effort)
          T2-10 (VSS, L effort)
```

### Phase 2C: Quality (Tier 3) — Ongoing
```
Continuous: T3-01 through T3-08 (S effort items, 1-2 per week)
Sprints:    T3-09, T3-10 (Apple enhancements, M effort)
            T3-14, T3-15, T3-16 (CI/testing, M effort)
            T3-17 (checkpatch compliance, L effort — incremental)
            T3-18 (compression, L effort)
```

### Phase 3: Architecture (Tier 4) — Long-term
```
Quarter-level efforts for XL items (VFS abstraction, event loop, QUIC)
```

---

## Review Report Conflicts — Resolution

The standalone review reports contain contradictory assessments:

| Report | Verdict | Date |
|--------|---------|------|
| COMPREHENSIVE_MULTI_STANDARD_REVIEW | "PRODUCTION READY, 100% complete" | ~Oct 2025 |
| EXPERT_REVIEW_20251019 | "REJECTED 7/8, only 25% complete" | Oct 19, 2025 |
| SECURITY_CODE_REVIEW_SUMMARY | "All vulnerabilities resolved" | ~2025 |
| FULLREVIEW | 44 issues (4 critical, 17 high) | ~Feb 2026 |
| FULLREVIEWBIS | 209 findings (10 critical, 56 high) | Feb 22, 2026 |

**Resolution**: The COMPREHENSIVE_MULTI_STANDARD_REVIEW appears to be an overly optimistic self-assessment. The EXPERT_REVIEW's "25% complete" referred to Apple/Fruit features specifically (not the whole module), and many of those gaps have since been addressed on this branch. FULLREVIEW and FULLREVIEWBIS are the most detailed and accurate, but many of their findings have been fixed by subsequent commits.

**Current realistic assessment**: The module is substantially more complete and secure than any single review suggests, due to the extensive work on this branch. The Tier 1 items above represent the genuine remaining critical gaps.

---

## Metrics

| Metric | Value |
|--------|-------|
| Total raw review findings | ~312 |
| Deduplicated unique issues | ~185 |
| Already fixed on branch | ~130 (70%) |
| Tier 1 (Critical) remaining | 12 |
| Tier 2 (High) remaining | 18 |
| Tier 3 (Medium) remaining | 25 |
| Tier 4 (Future) remaining | 20 |
| KUnit tests on branch | 20 modules |
| Fuzz harnesses on branch | 13 harnesses |
| Source files decomposed from smb2pdu.c | 12 |
