# ksmbd Code Review - Quick Read
**2026-02-28 | Full codebase review | 170+ files | 10 parallel reviewers**

---

## Bottom Line

The ksmbd kernel module has solid architecture and shows clear security awareness (constant-time crypto, RCU sessions, path traversal defense-in-depth, rate-limited logging). However, **14 critical vulnerabilities** were found that could allow remote attackers to read kernel memory, hijack sessions, or crash the system. Most are fixable with targeted patches.

---

## The 5 Most Urgent Issues

### 1. Session Hijacking via Signing Bypass
An attacker who knows a valid session ID can forge a session binding request because SMB2 SESSION_SETUP is explicitly excluded from signature verification. No credentials needed.
**Fix:** Verify signatures on binding requests before processing.

### 2. Kernel Memory Leak to Remote Clients
The `smb2_get_info_filesystem()` handler doesn't zero response buffers before filling them. Since structs are often partially filled, stale kernel heap data gets sent to clients. Multiple info classes affected.
**Fix:** Add `memset(rsp->Buffer, 0, max_size)` at the top of filesystem info handlers.

### 3. RDMA Out-of-Bounds Read
The RDMA transport validates `data_offset` against struct sizes rather than the actual received buffer length. A crafted SMB-Direct packet can read arbitrary kernel heap memory.
**Fix:** Validate against `recvmsg->sge.length`.

### 4. Decompression Bomb (Remote DoS)
SMB3 compression Pattern_V1 can amplify 8 bytes to 16MB with no rate limiting. A handful of concurrent requests from a single client can OOM the kernel.
**Fix:** Add per-connection rate limiting and reduce max decompressed size.

### 5. Connection Teardown Race Condition
A race between the connection handler thread and worker threads during cleanup can cause double-free or use-after-free on connection objects.
**Fix:** Add proper synchronization barrier before freeing connection.

---

## Findings at a Glance

| Severity | Count | Examples |
|---|---|---|
| Critical | 14 | Session hijack, kernel info leak, RDMA OOB, heap corruption, UAF, DoS |
| High | 30 | Integer overflows, missing bounds checks, signing downgrade, deadlocks |
| Medium | 45 | Race conditions, access control gaps, uninitialized fields |
| Low | 42 | Code quality, minor leaks, performance |
| **Total** | **131** | |

---

## By Component

| Component | Critical | High | Medium | Low |
|---|---|---|---|---|
| Security/Auth | 3 | 5 | 9 | 8 |
| SMB2 Protocol | 4 | 12 | 18 | 13 |
| SMB1 Protocol | 1 | 5 | 6 | 6 |
| VFS/Filesystem | 2 | 5 | 8 | 7 |
| Transport | 1 | 3 | 5 | 6 |
| Core Infra | 3 | 7 | 9 | 8 |
| Management | 2 | 4 | 7 | 8 |
| Tools (userspace) | 0 | 3 | 7 | 8 |

---

## What's Done Well

- 5-layer path traversal defense (share root + ksmbd_vfs_unsafe_symlink + LOOKUP_BENEATH + LOOKUP_NO_SYMLINKS + deny_dot_dot)
- Proper `kfree_sensitive()` / `memzero_explicit()` for credential cleanup
- RCU-protected session lookups with refcount_t lifecycle
- Per-IP connection limits preventing simple connection floods
- Credit-based flow control in both SMB2 and RDMA
- Comprehensive FSCTL input validation

---

## Recommended Fix Order

1. **This week:** Items 1-5 above + all P0s (session signing, response zeroing, RDMA bounds, decompression limits, connection races)
2. **Next 2 weeks:** All P1s (bounds validation, integer fixes, signing enforcement, lock ordering)
3. **Next month:** P2s (race conditions, access control, protocol compliance)
4. **Backlog:** P3s (code quality)

---

## Detailed Reports

All 10 detailed review files are in `review_runs/20260228/`:

```
01_security_auth.md          - Auth, crypto, ACL, sessions
02a_smb2_negotiate_session.md - SMB2 negotiate, session, credits
02b_smb2_create_rw_ioctl.md  - SMB2 file ops, locks, fruit
02c_smb2_dir_query_tree.md   - SMB2 directory, query/set, tree
03_smb1_protocol.md          - SMB1 protocol (legacy)
04_vfs_filesystem.md         - VFS, oplock, ACL, fsctl
05_transport.md              - TCP, RDMA, QUIC, IPC
06_core_infrastructure.md    - Connection, server, buffer, unicode
07_management.md             - Sessions, shares, tree connect
08_ksmbd_tools.md            - Userspace daemon and tools
COMPREHENSIVE_SUMMARY.md     - Full findings table with roadmap
```
