# KSMBD Comprehensive TODO List

**Compiled**: 2026-02-22
**Source**: 7 review files (01-Performance, 02-Safety, 03-Security, 04-Extensibility, 05-Missing Core, 06-Missing Modules, 07-Modular Design)
**Total actionable items**: 200+

---

## How to Read This Document

- **Priority**: P0 (fix immediately) > P1 (fix before production) > P2 (feature completeness) > P3 (future/nice-to-have)
- **Effort**: S (small, <100 LOC) / M (medium, 100-500 LOC) / L (large, 500-1500 LOC) / XL (extra large, 1500+ LOC)
- **Source**: Review file number and finding ID (e.g., `02:M-01` = Safety report, finding M-01)
- **Location**: file:line where the issue exists

---

## P0 — CRITICAL: Fix Immediately

### P0-SEC: Security Critical

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 1 | Make CAP_NET_ADMIN check unconditional | 03:CRITICAL-01 | `transport_ipc.c` (genl policy) | S | Remove `#ifdef CONFIG_SMB_SERVER_CHECK_CAP_NET_ADMIN` guard. Without it, any unprivileged process with netlink access can inject IPC responses. |
| 2 | Validate daemon IPC response contents | 03:CRITICAL-02 | `transport_ipc.c` | M | Add strict schema validation for all netlink response payloads. A compromised daemon can send arbitrary data as valid responses. |
| 3 | Add per-IP connection rate limiting | 03:CRITICAL-04 | `connection.c`, `transport_tcp.c` | M | Enforce hard-coded connection limits. Each connection allocates kernel memory; thousands of pre-auth connections cause OOM. |
| 4 | Replace ssleep(5) with non-blocking delay | 03:CRITICAL-05, HIGH-12 | `auth.c` (auth failure path) | S | `ssleep(5)` blocks a kernel worker thread for 5 seconds per auth failure. Use `schedule_delayed_work()` or connection-level backoff. |
| 5 | Validate IOCTL InputOffset bounds | 03:CRITICAL-06 | `smb2pdu.c:smb2_ioctl()` | S | `le32_to_cpu(req->InputOffset)` used as pointer offset without bounds check. Can read/write out of request buffer. |
| 6 | Fix EA set loop buffer validation | 03:CRITICAL-07 | `smb2pdu.c` (EA set path) | S | EA iteration loop trusts `NextEntryOffset` without validating it stays within the buffer. Heap overflow risk. |
| 7 | Assess/remove SMB1 attack surface | 03:CRITICAL-03 | Multiple files (31 `#ifdef` touchpoints) | L | `CONFIG_SMB_INSECURE_SERVER` adds massive attack surface. Plan removal or strict isolation. |

### P0-SAFETY: Memory/Crash Critical

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 8 | Fix NDR unaligned access | 02:M-01 | `ndr.c` | S | Unaligned memory access in NDR encode/decode can crash on ARM/strict-alignment architectures. Use `get_unaligned_le*()`. |
| 9 | Fix NULL crypto context dereference | 02:M-02 | `crypto_ctx.c` | S | `ksmbd_find_crypto_ctx()` can return NULL if pool exhausted. Callers do not check. |
| 10 | Fix session binding UAF | 02:M-03 | `smb2pdu.c` (session setup) | M | Race between session binding and destruction can cause use-after-free. |
| 11 | Fix EA heap overflow | 02:M-04 | `smb2pdu.c` (EA parsing) | S | EA buffer size not validated against actual data length. Overlaps with CRITICAL-07. |
| 12 | Fix ssleep under spinlock | 02:C-01 | `auth.c` | S | `ssleep()` called while holding a lock. Causes soft lockup. Same root cause as CRITICAL-05. |
| 13 | Fix crypto livelock | 02:F-02 | `crypto_ctx.c` | M | Crypto context allocation retries indefinitely when pool depleted. Add backoff and failure path. |

### P0-PERF: Performance Critical (Hot Path)

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 14 | Eliminate kvzalloc per READ request | 01:PERF-001 | `smb2pdu.c:smb2_read()` | M | Every READ allocates and zeroes a buffer via `kvzalloc(ALIGN(length, 8))`. Use a buffer pool or pre-allocated per-connection buffers. |
| 15 | Replace global inode_hash_lock | 01:PERF-019 | `vfs_cache.c` | M | Single global rwlock for inode hash table creates lock convoy under concurrent access. Use per-bucket locking. |
| 16 | Implement zero-copy I/O | 01:PERF-030 | `smb2pdu.c`, `vfs.c` | L | No splice/sendfile path for READ/WRITE. All data copies through kernel buffers. Use `splice_read` + `kernel_sendpage`. |

### P0-INTEROP: Breaks Basic Interoperability

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 17 | Implement CHANGE_NOTIFY | 05:P0-1 | `smb2pdu.c:9691-9709` | L | Returns `STATUS_NOT_IMPLEMENTED`. Windows Explorer doesn't auto-refresh. IDEs/Office can't detect external changes. Needs inotify/fanotify backend. |

### P0-INFRA: Infrastructure Critical

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 18 | Replace atomic_t refcounting with refcount_t | 04:P0-2 | `ksmbd_conn`, `ksmbd_session`, `ksmbd_share_config`, `oplock_info` | S | `refcount_t` provides saturation-based overflow protection; `atomic_t` silently wraps. Drop-in replacement. |
| 19 | Add CONFIG_KSMBD_FRUIT to Kconfig | 04:P0-1 | `Kconfig` (missing), `Makefile` | S | Currently `Makefile`-only (`?= n`). `menuconfig` can't toggle it. Kernel build systems don't know about it. |
| 20 | Create KUnit test framework | 04:P0-3 | New files: `test/ksmbd_test_*.c` | M | Zero unit tests exist. Start with NDR, ACL, misc, credit management, oplock state machine. |
| 21 | Create fuzzing harnesses | 04:P0-4 | New files | L | SMB2 header parsing, ASN.1/SPNEGO parsing, create context parsing, NDR decode, path parsing. Use syzkaller/kcov. |

---

## P1 — HIGH: Fix Before Production

### P1-SEC: Security High

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 22 | Fix path traversal TOCTOU | 03:HIGH-01 | `vfs.c:ksmbd_vfs_kern_path()` | M | Between `ksmbd_vfs_kern_path` and `dentry_open`, symlinks can be swapped in. Use `LOOKUP_BENEATH` + `O_NOFOLLOW` + post-open path verification. |
| 23 | Randomize durable handle PersistentFileId | 03:HIGH-04 | `vfs_cache.c` | S | Sequential allocation makes IDs predictable and enumerable. Use random IDs. |
| 24 | Validate SetInfo buffer sizes | 03:HIGH-06 | `smb2pdu.c` (set_info handlers) | M | Wire-format buffer offsets used before validation. Check against actual received data length. |
| 25 | Fix write_pipe off-by-one | 03:HIGH-07 | `smb2pdu.c` (pipe write) | S | Off-by-one in pipe write buffer length calculation. |
| 26 | Validate RDMA buffer descriptors | 03:HIGH-08 | `transport_rdma.c` | M | RDMA buffer descriptor from client not validated. Could cause OOB access. |
| 27 | Validate lock count limits | 03:HIGH-09 | `smb2pdu.c:smb2_lock()` | S | `LockCount` from wire not bounded. Large values cause excessive allocation. Cap at 64. |
| 28 | Fix validate_negotiate edge cases | 03:HIGH-10 | `smb2pdu.c:8849-8889` | S | Only validates SMB 3.0+; does not protect SMB 2.0/2.1 connections from downgrade. |
| 29 | Validate POSIX context sizes | 03:HIGH-11 | `smb2pdu.c` (POSIX extensions) | S | POSIX extension context data not validated. Always validate filenames. |
| 30 | Add IPC message integrity checking | 03:12.4 | `transport_ipc.c` | L | No authentication on netlink messages. Add HMAC-based integrity between kernel and daemon. |

### P1-SAFETY: Safety High

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 31 | Fix lock rollback UAF | 02:M-06 | `smb2pdu.c:smb2_lock()` | M | Lock rollback on failure can free locks still referenced by other threads. |
| 32 | Fix security info buffer overflow | 02:M-08 | `smbacl.c` | M | Security descriptor construction doesn't validate total size against output buffer. |
| 33 | Fix file_all_info overflow | 02:M-09 | `smb2pdu.c` (FILE_ALL_INFORMATION) | S | Response buffer size not checked before filling FILE_ALL_INFORMATION (variable-length name field). |
| 34 | Fix lease upgrade locking | 02:C-03 | `oplock.c` | M | Lease upgrade path has race conditions with concurrent break notifications. |
| 35 | Validate RDMA buffer bounds | 02:I-02 | `transport_rdma.c` | M | RDMA read/write operations don't fully validate descriptor offsets. Overlaps with HIGH-08. |
| 36 | Add missing fsids checks | 02:E-05 | `vfs.c` | S | `ksmbd_override_fsids()` return value not checked in some VFS paths. |

### P1-PERF: Performance High

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 37 | Use per-bucket locking for connection hash | 01:PERF-002 | `connection.c` | M | Global connection list lock causes contention under many connections. |
| 38 | Use dedicated slab caches | 01/04:P1-6 | `ksmbd_work.c`, `oplock.c`, `vfs_cache.c` | S | Hot-path objects (`ksmbd_work`, `oplock_info`, `ksmbd_file`) use generic kmalloc. Create `kmem_cache` for each. |
| 39 | Reduce kvzalloc in WRITE path | 01:PERF-003 | `smb2pdu.c:smb2_write()` | M | Similar to READ: per-request allocation on write path. Use buffer pool. |
| 40 | Optimize lease_list_lock contention | 01:PERF-020 | `oplock.c` | M | Global `lease_list_lock` rwlock under oplock storms causes all file ops to stall. Use per-file or per-share locking. |
| 41 | Add RCU for read-heavy data structures | 01/04:9.2 | Multiple files | M | Many data structures (session table, connection list, share config) are read-heavy but use exclusive locks. Add RCU protection. |
| 42 | Optimize short name generation | 01:PERF-015 | `smb_common.c` | S | Short name (8.3) generation called on every directory entry. Cache or skip when not needed. |
| 43 | Batch credit management | 01:PERF-016 | `smb2pdu.c` | S | Credit grant/consume per-request adds overhead. Batch credit operations. |

### P1-INTEROP: Important Missing Features

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 44 | Implement DFS referrals | 05:P1-2 | `smb2pdu.c:9079-9084` | XL | `FSCTL_DFS_GET_REFERRALS` returns `STATUS_FS_DRIVER_REQUIRED`. Enterprise namespace navigation broken. |
| 45 | Implement FSCTL_SRV_ENUMERATE_SNAPSHOTS | 05:P1-3 | `smb2pdu.c` (IOCTL switch) | L | Windows "Previous Versions" tab empty. Needs snapshot enumeration backend. |
| 46 | Implement FSCTL_SET_REPARSE_POINT | 05:P1-4 | `smb2pdu.c` (IOCTL switch) | L | Cannot create Windows symbolic links/junctions. Constant defined but not handled. |
| 47 | Implement FSCTL_DELETE_REPARSE_POINT | 05:P1-5 | `smb2pdu.c` (IOCTL switch) | S | Cannot delete reparse points. Constant defined but not handled. |
| 48 | Implement FILE_NAME_INFORMATION query | 05:P1-6 | `smb2pdu.c` (query info switch) | S | Some applications query file name via this info class. Not in switch statement. |
| 49 | Implement TIMEWARP/VSS create context | 05:P1-7 | `smb2pdu.c:3288-3297` | L | Currently returns `-EBADF`. Point-in-time file access broken. Needs snapshot path mapping. |
| 50 | Complete FSCTL_GET_REPARSE_POINT | 05:P1-8 | `smb2pdu.c:9259-9278` | M | Currently returns tag only, no data buffer content. |

### P1-MODULES: Critical Module Gaps

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 51 | Wire AFP_AfpInfo stream interception | 06:2.3 | `smb2pdu.c:smb2_open()` | M | Most impactful missing piece for macOS compatibility. Finder metadata display broken. |
| 52 | Implement Time Machine quota enforcement | 06:2.3 | `vfs.c` | M | `time_machine_max_size` exists in config but no enforcement. |
| 53 | Fix known lease race | 06:14 | `oplock.c:smb_lazy_parent_lease_break_close()` | M | Known race between lazy parent lease break and file close. |

### P1-ARCH: Architecture High

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 54 | Implement FSCTL handler registration table | 04:P1-1 | New: `ksmbd_fsctl.c/h` | M | Replace hardcoded switch-case with hash table dispatch. Enables modular FSCTL handlers. |
| 55 | Implement create context handler registration | 04:P1-2 | New: `ksmbd_create_ctx.c/h` | L | Extract inline context processing from `smb2_open()` into registerable handlers. |
| 56 | Create unified configuration framework | 04:P1-4 | New: `ksmbd_config.c/h` | M | `struct ksmbd_server_tunables` with all runtime-tunable values, validation, sane defaults. |
| 57 | Add debugfs interface | 04:P1-5 | New: `ksmbd_debugfs.c` | M | Per-connection state dump, session listing, oplock/lease table, credit monitoring. |
| 58 | Set up CI/CD pipeline | 04:P1-7 | New: `.github/workflows/` | L | Multi-kernel build (6.1/6.6/6.8/6.12), KUnit tests, sparse/smatch/coccinelle, smbtorture in QEMU. |
| 59 | Break circular header dependencies | 04:P1-3 | Multiple headers | L | Introduce formal dependency DAG with layered headers. Enables independent compilation/testing. |
| 60 | Three-tier feature negotiation model | 04:7.4 | Multiple files | M | Compile-time -> global enable -> per-connection. Admins can disable features without recompilation. |
| 61 | Create DFS extension framework | 04:P1-9 | New: `ksmbd_dfs.c/h` | L | Even before full DFS: registration API, FSCTL handler, capability advertisement. |

### P1-TESTING: Testing High

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 62 | Integration test harness | 04:8.3 | New: `tests/run_integration.sh` | M | Build module, load with test config, run smbtorture, validate results. |

---

## P2 — MEDIUM: Feature Completeness

### P2-SEC: Security Medium

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 63 | Use constant-time auth comparison | 03:MEDIUM-12 | `auth.c` | S | Authentication token comparison should use `crypto_memneq()`. |
| 64 | Validate SID num_subauth range | 03:MEDIUM-05 | `smbacl.c` | S | `num_subauth` from wire not validated against max. |
| 65 | Add per-session resource limits | 03:DoS-04..07 | Multiple files | M | Limits for per-connection memory, per-session pipe count, per-connection lock count, per-session file count. |
| 66 | Implement GCM nonce tracking | 03:9.3 | `auth.c`, `smb2pdu.c` | M | GCM nonce reuse would break encryption entirely. Track and prevent reuse. |
| 67 | Add memzero_explicit in all key error paths | 03:9.5 | `auth.c`, `smb2pdu.c` | S | Session keys may persist in freed memory if error paths don't clean up. |
| 68 | Validate embedded null bytes in filenames | 03:MEDIUM-15 | `smb2pdu.c` | S | After Unicode conversion, check for embedded null bytes. |
| 69 | Clamp NDR string length | 03:MEDIUM-01 | `ndr.c` | S | NDR decode trusts length fields. Add bounds check. |
| 70 | Rate-limit all network-triggered error messages | 03:LOW-02 | Multiple files | S | Use `pr_err_ratelimited` for all errors triggered by network input. |
| 71 | Reject empty NTLM responses unless guest | 03:LOW-03 | `auth.c` | S | Explicitly deny empty passwords unless guest access configured. |
| 72 | Enforce hard limits on max credit window | 03:LOW-04 | `transport_ipc.c:353-354` | S | A daemon could set `smb2_max_credits` to extreme values. Add hard-coded ceiling. |
| 73 | Fix get_nlink underflow | 03:LOW-05 | `misc.c:210-218` | S | `nlink--` for directories without checking for 0. Return `max(nlink-1, 0)`. |
| 74 | Rate-limit leading backslash error | 03:LOW-06 | `smb2pdu.c:656-659` | S | `pr_err` triggered by client input not rate-limited. Use `pr_err_ratelimited`. |
| 75 | Improve match_pattern worst-case | 03:LOW-07 | `misc.c:31-70` | M | Wildcard matching has quadratic worst-case. Add memoization or NFA-based approach. |
| 76 | Fix session leak on registration failure | 03:LOW-09 | `smb2pdu.c:1780-1788` | S | Session not freed if `ksmbd_session_register` fails after create. |
| 77 | Credit timeout and forced release | 03:DoS-08 | `smb2pdu.c` | M | Consumed credits never expire. Add timeout. |
| 78 | Per-operation credit cost differentiation | 03:13.3 | `smb2pdu.c` | M | Expensive operations (QUERY_DIRECTORY) should cost more credits. |
| 79 | Randomize session/file IDs | 03:INFO-04, 14.18 | Multiple files | M | Sequential allocation is predictable. Use random allocation. |

### P2-SAFETY: Safety Medium

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 80 | Fix TOCTOU in path resolution | 02:Race-01 | `vfs.c` | M | Between `ksmbd_vfs_kern_path` and `dentry_open`, filesystem can change. Same as HIGH-01. |
| 81 | Fix file handle lifecycle vs connection close | 02:Race-02 | `connection.c`, `vfs_cache.c` | M | Outstanding work items may hold references to closed connection's objects. |
| 82 | Fix oplock break vs file close race | 02:Race-03 | `oplock.c`, `vfs_cache.c` | M | Opinfo freed while break handler still references it. |
| 83 | Fix session state machine races | 02:Race-04 | `smb2pdu.c:1918`, `server.c` | M | State transitions not always protected by connection lock. |
| 84 | Fix durable handle scavenger vs reconnect | 02:Race-05 | `vfs_cache.c`, `smb2pdu.c` | M | Scavenger thread can free handle during reconnect lookup. |

### P2-INTEROP: Significant Feature Gaps

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 85 | Implement AES-GMAC signing | 05:P2-9 | `smb2pdu.c`, `auth.c` | M | Constant defined (`smb2pdu.h:336`) but never negotiated. Windows 11 prefers it for performance. |
| 86 | Implement APP_INSTANCE_ID create context | 05:P2-10 | `smb2pdu.c:smb2_open()` | M | Struct defined (`smb2pdu.h:670-675`) but never used. Needed for HA/VM failover. |
| 87 | Implement APP_INSTANCE_VERSION | 05:P2-11 | `smb2pdu.c:smb2_open()` | M | Struct defined (`smb2pdu.h:677-684`) but never used. Needed alongside App Instance ID. |
| 88 | Implement resilient handles | 05:P2-12 | `smb2pdu.c` | L | FSCTL_LMR_REQUEST_RESILIENCY not implemented. Hyper-V/clustered workloads affected. |
| 89 | Implement persistent handle survival | 05:P2-13 | `vfs_cache.c` | XL | `fp->is_persistent` set but handles lost on restart. Needs persistent storage of state. |
| 90 | Implement quota info class | 05:P2-14 | `smb2pdu.c:6332-6335` | L | `SMB2_O_INFO_QUOTA` returns EOPNOTSUPP. Needs Linux quota subsystem integration. |
| 91 | Implement SACL query/set | 05:P2-15 | `smb2pdu.c:6220-6237` | M | Filtered out currently. Windows auditing policies can't be applied. |
| 92 | Implement SMB3 compression | 05:P2-16 | `smb2pdu.c`, `smb_common.c` | XL | `decode_compress_ctxt()` always sets `SMB3_COMPRESS_NONE`. Needs full compression framework. |
| 93 | Implement FSCTL_PIPE_WAIT | 05:P2-17 | `smb2pdu.c` (IOCTL switch) | S | Constant defined in `smbfsctl.h:72` but not handled. |
| 94 | Implement FSCTL_PIPE_PEEK | 05:P2-18 | `smb2pdu.c` (IOCTL switch) | S | Constant defined in `smbfsctl.h:69` but not handled. |
| 95 | Implement FILE_PIPE_INFORMATION query | 05:P2-19 | `smb2pdu.c` (query info switch) | S | Pipe info classes 23/24/25 missing. |
| 96 | Implement FILE_QUOTA_INFORMATION | 05:P2-20 | `smb2pdu.c` (query info switch) | L | Quota queries for management tools. |
| 97 | Implement FILE_VALID_DATA_LENGTH_INFO | 05:P2-21 | `smb2pdu.c` (query/set info) | S | Some backup tools need this. |
| 98 | Implement FILE_NORMALIZED_NAME_INFO | 05:P2-22 | `smb2pdu.c` (query info switch) | S | Path normalization queries. |
| 99 | Complete lock sequence validation | 05:P2-23 | `smb2pdu.c:smb2_lock()` | M | Lock sequence numbers for resilient handles not fully validated. |
| 100 | Implement FS_CONTROL_INFORMATION set | 05:P2-24 | `smb2pdu.c` | S | Query exists (`6151-6170`) but set is missing. |
| 101 | Implement RDMA_TRANSFORM_CAPABILITIES | 05:P2-25 | `smb2pdu.c` (negotiate) | L | Negotiate context missing. Required for RDMA + encryption. |
| 102 | Implement FSCTL_FILE_LEVEL_TRIM | 05:P2-26 | `smb2pdu.c` (IOCTL switch) | S | SSD TRIM passthrough. |
| 103 | Implement FSCTL_OFFLOAD_READ/WRITE | 05:P2-27 | `smb2pdu.c` (IOCTL switch) | L | Offloaded data transfer. |

### P2-MODULES: Module Feature Gaps

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 104 | Wire AFP_Resource stream interception | 06:2.3 | `smb2pdu.c:smb2_open()` | L | Resource fork read/write for legacy macOS apps. |
| 105 | Complete ReadDirAttr enrichment | 06:2.3 | `smb2fruit.c` | M | Resource fork size and max access behind per-share flags. |
| 106 | Wire resolve_fileid into AAPL volume_caps | 06:2.3 | `smb2fruit.c` | M | `ksmbd_vfs_resolve_fileid()` declared but stub. |
| 107 | RDMA credit management refinement | 06:6 | `transport_rdma.c` | M | RDMA credit flow could be more granular. |
| 108 | Complete FSCTL_CREATE_OR_GET_OBJECT_ID | 06:varies | `smb2pdu.c` | S | Currently returns zeroed object ID (dummy). |
| 109 | Implement NETNAME context validation | 05:P3-41 | `smb2pdu.c:1083-1085` | S | Logged but server name not validated or stored. |
| 110 | AFP_AfpInfo synthesis wiring | 06:2.3 | `smb2fruit.c` | M | `fruit_synthesize_afpinfo` exists but not wired into stream open. |

### P2-ARCH: Architecture Medium

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 111 | Decompose smb2pdu.c into sub-files | 04:P2-1, App C | `smb2pdu.c` (~10K lines) | XL | Split into smb2_negotiate.c, smb2_session.c, smb2_create.c, smb2_read_write.c, smb2_query_set.c, smb2_ioctl.c, etc. |
| 112 | Protocol version registration API | 04:P2-2 | New: `ksmbd_protocol.h` | L | `ksmbd_register_protocol_version()` / `ksmbd_unregister_protocol_version()`. Enables new versions without modifying core. |
| 113 | Per-command dispatch overrides & hooks | 04:P2-3 | `smb_common.h`, `connection.h` | M | Per-connection command override array + pre/post hook registration. |
| 114 | Info-level handler registration table | 04:P2-4 | New: `ksmbd_info.c/h` | M | Hash table dispatch for QUERY_INFO/SET_INFO info classes. |
| 115 | Make Fruit a runtime-loadable module | 04:P2-5 | `smb2fruit.c`, `Kconfig` | M | Use create context handler registration + `conn->extension_data` + `module_init/exit`. |
| 116 | Clean RDMA transport abstraction | 04:P2-6 | `ksmbd_transport_ops` | S | Move `rdma_read`/`rdma_write` to secondary ops table. |
| 117 | Clean SMB1 separation | 04:P2-7 | Multiple files (8+ `#ifdef` files) | L | Move ALL SMB1-specific branches into SMB1-specific files. |
| 118 | Authentication provider registration API | 04:P2-8 | New: `ksmbd_auth.h` | L | `ksmbd_register_auth_provider()`. Pluggable NTLM, Kerberos, future mechanisms. |
| 119 | Decompose ksmbd_conn into sub-structs | 04:P2-9 | `connection.h` | XL | `transport_state`, `proto_state`, `sec_state`, `credit_state`, `session_state`, `extension_data`. |
| 120 | Session accessor API for key management | 04:P2-10 | `mgmt/user_session.h` | M | `ksmbd_session_get_signing_key()` etc. Allows moving keys to kernel keyring. |
| 121 | Three-tier VFS abstraction layer | 04:P2-11 | `vfs.c`, `vfs.h` | XL | Split: `ksmbd_vfs_ops.h` (abstract), `ksmbd_vfs_linux.c` (implementation), `ksmbd_vfs_compat.c` (version shims). |
| 122 | Transport factory registration API | 04:P2-12 | New: `ksmbd_transport.h` | M | `ksmbd_register_transport()` / `ksmbd_unregister_transport()`. Future: QUIC plug-in. |

### P2-MODULAR: Modular Design (from 07)

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 123 | Design hook system (netfilter-inspired) | 07:Phase 2 | New: `ksmbd_hooks.c/h` | L | 31 hook points, `static_key` bypass, RCU-protected traversal, priority ordering, verdict-based. |
| 124 | Implement per-connection extension state | 07:Phase 3 | `connection.h` | M | `ext_data[]` array with tagged union for Fruit, DFS, VSS per-connection state. |
| 125 | Define stable public API header | 07:Phase 3 | New: `include/ksmbd/ksmbd_api.h` | M | ~40 `EXPORT_SYMBOL_GPL` functions. Opaque types. Version-stamped. |
| 126 | Module capability negotiation flags | 07:Phase 4 | `ksmbd_netlink.h` | S | Flags to advertise which modules are loaded. |
| 127 | Extract ksmbd-transport-tcp as module | 07:Phase 5, step 1 | `transport_tcp.c` | S | Already behind ops indirection. Straightforward extraction. |
| 128 | Extract ksmbd-transport-rdma as module | 07:Phase 5, step 2 | `transport_rdma.c` | S | Already conditional on CONFIG. |
| 129 | Extract ksmbd-auth-ntlm as module | 07:Phase 5, step 3 | `auth.c` | M | Session setup only. Needs auth provider registration. |
| 130 | Extract ksmbd-fruit as module | 07:Phase 5, step 5 | `smb2fruit.c` | M | Hooks for POST_CREATE, READDIR_ENTRY. |
| 131 | Extract ksmbd-acl as module | 07:Phase 5, step 9 | `smbacl.c`, `ndr.c` | L | CHECK_ACCESS hook. |

---

## P3 — LOW: Future / Nice-to-Have

### P3-INTEROP: Edge Cases & Rare Features

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 132 | Print share support | 05:P3-28 | `smb2pdu.h:438` | L | Constant defined, share type never assigned. Rare for in-kernel server. |
| 133 | Witness protocol (MS-SWN) | 05:P3-29 | N/A | XL | Cluster-only. |
| 134 | SMB over QUIC | 05:P3-30 | N/A | XL | TRANSPORT_CAPABILITIES context needed. |
| 135 | Scale-out cluster support | 05:P3-31 | N/A | XL | Enterprise only. |
| 136 | Various unused FSCTLs | 05:P3-32 | `smb2pdu.c` | S each | LOCK_VOLUME, UNLOCK_VOLUME, IS_PATHNAME_VALID, etc. |
| 137 | FILE_PIPE_LOCAL/REMOTE_INFORMATION | 05:P3-33 | `smb2pdu.c` | S | Diagnostic info classes. |
| 138 | FILE_MAILSLOT_* INFORMATION | 05:P3-34 | `smb2pdu.c` | S | Legacy. |
| 139 | FSCTL_GET/SET_COMPRESSION | 05:P3-35 | `smb2pdu.c` | S | Compression control queries. |
| 140 | FSCTL_SET_ENCRYPTION (per-file) | 05:P3-36 | `smb2pdu.c` | M | Windows EFS. |
| 141 | USN journal FSCTLs | 05:P3-37 | `smb2pdu.c` | M | Change journal. |
| 142 | LABEL_SECINFO (integrity labels) | 05:P3-38 | `smb2pdu.c` | M | Mandatory access control labels. |
| 143 | FS_DRIVER_PATH_INFORMATION | 05:P3-39 | `smb2pdu.c` | S | Diagnostic. |
| 144 | Unbuffered read/write flags | 05:P3-40 | `smb2pdu.c` | S | Direct I/O hints from client. |
| 145 | FSCTL_SET_SHORT_NAME_BEHAVIOR | 05:P3-42 | `smb2pdu.c` | S | Short name control. |
| 146 | Anonymous vs guest session distinction | 05:P3-43 | `smb2pdu.c:1883` | S | Security policy edge case. |

### P3-MODULES: Module Nice-to-Have

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 147 | kAAPL_SUPPORTS_OSX_COPYFILE IOCTL handler | 06:2.3 | `smb2fruit.c` | L | Server-side copyfile with metadata preservation. |
| 148 | Spotlight / mdssvc RPC | 06:2.3 | N/A | XL | macOS search integration. Out of scope for kernel module. |
| 149 | POSIX hardlink detection in dir entries | 06:2.3 | `smb2fruit.c` | S | `fruit_dir_hardlinks` struct defined, not populated. |
| 150 | Savebox/LookerInfo context processing | 06:2.3 | `smb2fruit.c` | S | Currently stubs (log only). |
| 151 | kAAPL_SUPPORTS_TM_LOCK_STEAL | 06:2.3 | `smb2fruit.c` | M | Defined in header but never advertised or handled. |

### P3-ARCH: Architecture Long-term

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 152 | Full VFS backend abstraction | 04:P3-1 | `vfs.c`, `vfs.h` | XL | `ksmbd_vfs_ops` interface. Mock VFS for testing, non-Linux backends. |
| 153 | Layered ksmbd_work context model | 04:P3-2 | `ksmbd_work.h` | L | Split into `req`, `auth`, `io` sub-contexts. |
| 154 | ACL operations interface | 04:P3-3 | `smbacl.c` | M | `ksmbd_acl_ops` for alternative ACL backends (NFSv4, Richacls). |
| 155 | Oplock engine full isolation | 04:P3-4 | `oplock.c` | M | Remove direct `ksmbd_conn`/`ksmbd_session` refs. Opaque identifiers. |
| 156 | Kernel-side RPC caching | 04:P3-5 | `transport_ipc.c` | L | Cache share enum results. Reduce IPC round-trips for frequent RPCs. |
| 157 | io_uring integration investigation | 04:P3-6 | New | L | Replace per-connection kthread with io_uring for zero-copy receive. Premature but worth tracking. |
| 158 | Extract ksmbd-auth-krb5 as module | 07:Phase 5, step 4 | `auth.c`, `asn1.c` | M | SPNEGO forwarding. Isolates security-sensitive ASN.1 parsing. |
| 159 | Extract ksmbd-dfs as module | 07:Phase 5, step 6 | New | L | FSCTL handler + path resolution. |
| 160 | Extract ksmbd-vss as module | 07:Phase 5, step 7 | New | L | FSCTL + snapshot backends. |
| 161 | Extract ksmbd-compress as module | 07:Phase 5, step 8 | New | XL | Transform headers + algorithm registry. |
| 162 | Extract ksmbd-audit as module | 07:Phase 5, step 10 | New | M | AUDIT hook for compliance logging. |

### P3-PERF: Performance Nice-to-Have

| # | Title | Source | Location | Effort | Description |
|---|-------|--------|----------|--------|-------------|
| 163 | CRYPTO_ALG_ASYNC for hardware acceleration | 04:9.2 | `crypto_ctx.c` | M | Current crypto pool uses synchronous API. Hardware crypto engines want async. |
| 164 | Thread pool model for connections | 03:LOW-08 | `transport_tcp.c`, `connection.c` | L | Per-connection kthread wastes resources for idle connections. |
| 165 | Dedicated workqueue for SMB requests | 04:9.2 | `server.c` | M | Currently uses `system_wq`. Dedicated WQ allows tunable parameters. |
| 166 | Static_key for compile-time optional features | 07:Phase 2 | Multiple files | M | Zero-overhead feature checks via `static_key` when modules not loaded. |

---

## Summary Statistics

| Priority | Count | Estimated Effort |
|----------|-------|-----------------|
| **P0 — Critical** | 21 | 8 S, 6 M, 5 L, 2 XL |
| **P1 — High** | 41 | 9 S, 16 M, 12 L, 4 XL |
| **P2 — Medium** | 48 | 17 S, 20 M, 7 L, 4 XL |
| **P3 — Low** | 35 | 11 S, 10 M, 8 L, 6 XL |
| **TOTAL** | **145** | |

---

## Recommended Execution Order

### Phase 1: Hardening (P0 items)
1. Security fixes (#1-7) — prevent exploitation
2. Memory safety (#8-13) — prevent crashes
3. Infrastructure (#18-21) — enable quality gates
4. Hot-path performance (#14-16) — remove worst bottlenecks
5. CHANGE_NOTIFY (#17) — fix basic Windows interop

### Phase 2: Production Readiness (P1 items)
1. Remaining security fixes (#22-30)
2. Safety fixes (#31-36)
3. Core architecture (#54-61) — registration APIs, config framework
4. Critical missing features (#44-50) — DFS, VSS, reparse points
5. Critical module gaps (#51-53)
6. Testing infrastructure (#58, #62)
7. Performance (#37-43)

### Phase 3: Feature Completeness (P2 items)
1. Security hardening (#63-79)
2. Missing protocol features (#85-103)
3. Module completions (#104-110)
4. Architecture improvements (#111-122)
5. Modular design (#123-131)

### Phase 4: Polish (P3 items)
1. Edge-case protocol features (#132-146)
2. Module nice-to-haves (#147-151)
3. Long-term architecture (#152-162)
4. Performance optimizations (#163-166)

---

## Cross-Reference: DoS Attack Vectors

All DoS vectors from the security audit, mapped to their fixes:

| DoS Vector | Fix Item | Priority |
|------------|----------|----------|
| DoS-01: Connection exhaustion (pre-auth) | #3 (per-IP rate limiting) | P0 |
| DoS-02: Auth failure sleep amplification | #4 (non-blocking delay) | P0 |
| DoS-03: Oplock/lease lock storm | #40 (per-file locking) | P1 |
| DoS-04: Large read/write memory exhaustion | #65 (per-connection limits) | P2 |
| DoS-05: Deep directory recursion | #65 (traversal depth limit) | P2 |
| DoS-06: Lock flooding | #65 (per-connection lock limit) | P2 |
| DoS-07: IPC pipe exhaustion | #65 (per-session pipe limit) | P2 |
| DoS-08: Credit starvation | #77 (credit timeout) | P2 |

## Cross-Reference: Race Conditions

| Race | Fix Item | Priority |
|------|----------|----------|
| Race-01: TOCTOU in path resolution | #22 / #80 | P1/P2 |
| Race-02: File handle vs connection close | #81 | P2 |
| Race-03: Oplock break vs file close | #82 | P2 |
| Race-04: Session state machine | #83 | P2 |
| Race-05: Durable handle scavenger vs reconnect | #84 | P2 |
| Race-06: Inode hash table lock granularity | #15 | P0 |

---

*End of Comprehensive TODO List*
*Source: REVIEWFILES/01 through 07*
