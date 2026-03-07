# What's New in ksmbd (Fork vs. Upstream)

**Branch:** `phase1-security-hardening`
**Date range:** 2026-02-22 to 2026-03-02 (9 days of development)
**Commits:** 134 (on branch) + 22 committed / 37 files uncommitted (ksmbd-tools)
**Scope:** 415 files changed, +134,220 / -26,774 lines (kernel module); 68 files, +7,443 / -657 lines (tools)
**Upstream baseline:** cifsd-team/ksmbd 3.5.4 (December 9, 2025) / ksmbd-tools 3.5.6

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architectural Overhaul](#2-architectural-overhaul)
3. [New Protocol Subsystems](#3-new-protocol-subsystems)
4. [Security Hardening](#4-security-hardening)
5. [Performance Improvements](#5-performance-improvements)
6. [Protocol Spec Compliance](#6-protocol-spec-compliance)
7. [SMB1 Enhancements](#7-smb1-enhancements)
8. [SMB2/3 Enhancements](#8-smb23-enhancements)
9. [ksmbd-tools Enhancements](#9-ksmbd-tools-enhancements)
10. [Build System & Infrastructure](#10-build-system--infrastructure)
11. [Testing & Quality](#11-testing--quality)
12. [VM Test Fleet](#12-vm-test-fleet)
13. [Feature Comparison Matrix](#13-feature-comparison-matrix)
14. [Test Results](#14-test-results)
15. [Known Issues](#15-known-issues)

---

## 1. Executive Summary

This fork of ksmbd (the Linux in-kernel CIFS/SMB3 server) significantly expands the
upstream `cifsd-team/ksmbd` 3.5.4 codebase. The kernel module grows from approximately
30,000 lines across 57 files to 85,600+ lines across 125 source files, organized into
a layered directory hierarchy. The userspace tools gain a unified CLI, protocol fixes,
and operational features.

**Headline numbers:**

- 12 entirely new protocol subsystems (compression, QUIC, DFS, VSS, BranchCache, etc.)
- Monolithic `smb2pdu.c` decomposed into 12 focused compilation units
- Source tree reorganized from flat layout into `src/{core,encoding,fs,mgmt,protocol,transport}/`
- 39+ MS-SMB2 spec compliance fixes across sessions, negotiate, create, lock, IOCTL
- 22 KUnit test files + 13 fuzz harnesses
- Kernel-native QUIC transport (RFC 9000/9001) -- no userspace proxy
- SMB3 compression from scratch (LZNT1, LZ77, LZ77+Huffman per MS-XCA)
- smbtorture score: 387 PASS / 170 FAIL / 68 SKIP out of 625 tests (+44% vs baseline)

---

## 2. Architectural Overhaul

### 2.1 Source Tree Reorganization

Upstream stores all `.c` and `.h` files in the repository root with `mgmt/` as the
sole subdirectory. This fork reorganizes everything into a layered structure:

```
src/
  core/             Server core: auth, connection, server, crypto, work queue
  encoding/         ASN.1, NDR, Unicode encoding/decoding
  fs/               VFS, oplock, ACL, and all new filesystem subsystems
  include/
    core/           Core headers
    encoding/       Encoding headers
    fs/             Filesystem headers
    protocol/       Protocol headers (SMB1, SMB2, common)
    transport/      Transport headers (TCP, RDMA, IPC, QUIC)
  mgmt/             User/share/session management, IDA, witness
  protocol/
    common/         Shared protocol code (smb_common, netmisc)
    smb1/           SMB1 protocol (smb1pdu, smb1ops, smb1misc)
    smb2/           SMB2/3 protocol (12 decomposed files)
  transport/        TCP, RDMA, IPC, QUIC transports
```

67 files were renamed/moved from root to their new locations, many with significant
modifications during the move.

### 2.2 SMB2 PDU Decomposition

The upstream monolithic `smb2pdu.c` (~10,063 lines containing ALL SMB2 command handlers)
was deleted and decomposed into 12 focused compilation units:

| File | Lines | Handles |
|------|------:|---------|
| `smb2_query_set.c` | 3,386 | QUERY_INFO, SET_INFO |
| `smb2_create.c` | 2,865 | CREATE / OPEN |
| `smb2_pdu_common.c` | 1,581 | Signing, encryption, credits, compound chaining |
| `smb2_dir.c` | 1,370 | QUERY_DIRECTORY |
| `smb2_read_write.c` | 1,136 | READ, WRITE |
| `smb2_lock.c` | 1,056 | LOCK |
| `smb2_negotiate.c` | 1,009 | NEGOTIATE |
| `smb2_session.c` | 930 | SESSION_SETUP, LOGOFF |
| `smb2_misc_cmds.c` | 668 | ECHO, CANCEL, FLUSH, notification |
| `smb2_tree.c` | 544 | TREE_CONNECT, TREE_DISCONNECT |
| `smb2_notify.c` | 396 | CHANGE_NOTIFY |
| `smb2_ioctl.c` | 212 | IOCTL dispatch |
| **Total** | **15,153** | |

Net increase over the monolith reflects new features added to each handler.

### 2.3 New Architectural Frameworks

| Framework | File | Lines | Purpose |
|-----------|------|------:|---------|
| Unified config | `ksmbd_config.c/h` | 282 | Runtime configuration management |
| Feature negotiation | `ksmbd_feature.c/h` | 154 | Three-tier feature flag framework |
| Hook system | `ksmbd_hooks.c/h` | 394 | Netfilter-inspired extensible SMB processing hooks |
| FSCTL dispatch | `ksmbd_fsctl.c/h` | 3,113 | Registration table for FSCTL handlers |
| Info-level dispatch | `ksmbd_info.c/h` | 2,188 | Registration table for FileInfoClass handlers |
| Create context dispatch | `ksmbd_create_ctx.c/h` | 361 | Registration table for create contexts |
| debugfs interface | `ksmbd_debugfs.c` | 170 | Runtime inspection via debugfs |
| Buffer pool | `ksmbd_buffer.c/h` | 309 | Reusable buffer pool for READ/WRITE |

---

## 3. New Protocol Subsystems

Twelve entirely new subsystems not present in upstream, totaling ~35,000 lines:

### 3.1 SMB3 Compression (`smb2_compress.c` -- 1,969 lines)

Implements SMB 3.1.1 compression per the MS-XCA specification, entirely from scratch
(no Samba code, no third-party libraries):

- **LZNT1**: LZ-based compression used by NTFS
- **LZ77**: Sliding-window dictionary compression
- **LZ77+Huffman**: LZ77 with adaptive Huffman coding
- **Pattern_V1**: Repeated-byte pattern detection
- **LZ4**: Internal fast-path (non-SMB-standard)

Integrates with the request/response pipeline in `server.c` via
`smb2_decompress_req()` / `smb2_compress_resp()`.

### 3.2 QUIC Transport (`transport_quic.c` -- 3,208 lines)

Kernel-native QUIC implementation per RFC 9000 (transport) and RFC 9001 (TLS 1.3):

- UDP socket listener on port 443
- QUIC Initial packet processing with HKDF-SHA-256 key derivation
- AES-128-GCM AEAD packet encryption/decryption
- AES-128-ECB header protection (RFC 9001 Section 5.4)
- TLS 1.3 handshake delegation to userspace via Generic Netlink family ("SMBD_QUIC")
- kTLS integration for hardware-accelerated post-handshake encryption
- Connection state machine: IDLE -> INITIAL -> HANDSHAKE -> CONNECTED
- Requires `CONFIG_SMB_SERVER_QUIC=y` (default for external builds)

No userspace proxy required -- the QUIC stack runs entirely in kernel space.

### 3.3 Change Notification (`ksmbd_notify.c` -- 1,518 lines)

Full SMB2 CHANGE_NOTIFY with Linux fsnotify integration:

- `FILE_NOTIFY_CHANGE_*` flag mapping to `FS_*` fsnotify events
- `WATCH_TREE` recursive directory monitoring
- Async completion with proper cancel handling
- Per-connection watch count limit (memory DoS prevention)
- Piggyback watch support for compound requests

### 3.4 Reparse Points (`ksmbd_reparse.c` -- 1,223 lines)

Reparse point support for symlinks and junctions:

- `FSCTL_SET_REPARSE_POINT` / `FSCTL_GET_REPARSE_POINT` / `FSCTL_DELETE_REPARSE_POINT`
- IO_REPARSE_TAG_SYMLINK with substitute/print name handling
- IO_REPARSE_TAG_MOUNT_POINT (junction) support
- `FILE_OPEN_REPARSE_POINT` create option handling

### 3.5 VSS/Previous Versions (`ksmbd_vss.c` -- 760 lines)

Volume Shadow Copy Service support:

- `FSCTL_SRV_ENUMERATE_SNAPSHOTS` enumeration
- GMT token parsing (`@GMT-YYYY.MM.DD-HH.MM.SS`)
- Pluggable snapshot backend architecture
- Snapshot-routed file access in CREATE handler

### 3.6 BranchCache (`ksmbd_branchcache.c` -- 720 lines)

MS-PCCRC content information for distributed caching:

- Content hash generation (SHA-256/SHA-512)
- Segment/block hash tracking
- `FSCTL_SRV_READ_HASH` implementation

### 3.7 RSVD (`ksmbd_rsvd.c` -- 652 lines)

Remote Shared Virtual Disk FSCTL handlers:

- SCSI tunnel structures per MS-RSVD
- Virtual disk open/close/query operations
- Shared virtual disk metadata

### 3.8 Witness Protocol (`ksmbd_witness.c` -- 742 lines)

MS-SWN (Service Witness Protocol) for cluster failover:

- Witness client registration/unregistration
- Interface list management
- Netlink communication with userspace for failover notifications
- 7 new netlink event types wired through `transport_ipc.c`

### 3.9 DFS Referrals (`ksmbd_dfs.c` -- 520 lines)

Distributed File System namespace support:

- DFS referral request/response handling
- Referral target resolution
- Integration with share configuration

### 3.10 Quota Support (`ksmbd_quota.c` -- 437 lines)

File system quota integration:

- Linux VFS quota subsystem integration
- Per-user/per-group quota queries
- NT_TRANSACT_QUERY_QUOTA support

### 3.11 App Instance ID (`ksmbd_app_instance.c` -- 317 lines)

Application instance tracking for cluster failover:

- App Instance ID create context handling
- App Instance Version tracking
- Handle revocation on failover

### 3.12 Resilient Handles (`ksmbd_resilient.c` -- 146 lines)

Resilient handle support via `FSCTL_LMR_REQUEST_RESILIENCY`:

- Configurable resilient timeout
- Lock sequence replay validation (MS-SMB2 3.3.5.14)

### 3.13 Additional FSCTL Implementations

The `ksmbd_fsctl.c` dispatch table and `ksmbd_fsctl_extra.c` implement 25+ FSCTLs:

| FSCTL | Status |
|-------|--------|
| FSCTL_SRV_COPYCHUNK / _WRITE | Enhanced |
| FSCTL_PIPE_TRANSCEIVE | Enhanced |
| FSCTL_SET_SPARSE | Fixed (MS-FSCC 2.3.64 default) |
| FSCTL_SET_ZERO_DATA | New |
| FSCTL_QUERY_ALLOCATED_RANGES | New |
| FSCTL_SRV_ENUMERATE_SNAPSHOTS | New |
| FSCTL_VALIDATE_NEGOTIATE_INFO | Enhanced |
| FSCTL_FILESYSTEM_GET_STATISTICS | New |
| FSCTL_SET_ZERO_ON_DEALLOCATION | New |
| FSCTL_QUERY_FILE_REGIONS | New |
| FSCTL_GET_INTEGRITY_INFORMATION | New |
| FSCTL_SET_INTEGRITY_INFORMATION | New |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | New |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX | New |
| FSCTL_MARK_HANDLE | New |
| FSCTL_OFFLOAD_READ (ODX) | New |
| FSCTL_OFFLOAD_WRITE (ODX) | New |
| FSCTL_SRV_READ_HASH | New |
| FSCTL_PIPE_WAIT | New |
| FSCTL_PIPE_PEEK | New |
| FSCTL_SET_REPARSE_POINT | New |
| FSCTL_GET_REPARSE_POINT | New |
| FSCTL_DELETE_REPARSE_POINT | New |
| FSCTL_QUERY_ON_DISK_VOLUME_INFO | Stub |
| FSCTL_LMR_REQUEST_RESILIENCY | New |
| NTFS-specific FSCTLs | STATUS_NOT_SUPPORTED |

### 3.14 Additional Info-Level Handlers (`ksmbd_info.c`)

| Info Class | Status |
|------------|--------|
| FileStatInfo (0x46) | New |
| FileStatLxInfo (0x47) | New |
| FilePipeInformation | New |
| FilePipeLocalInformation | New |
| FileValidDataLengthInformation | New |
| FileNormalizedNameInformation | New |
| FileNameInformation | New |
| FsControlInformation | New |
| FileHardLinkInformation | New |
| FileCaseSensitiveInformation | New |

### 3.15 Apple/Fruit Extensions (`smb2fruit.c` -- ~830 lines)

macOS compatibility via `CONFIG_KSMBD_FRUIT`:

- AFP_AfpInfo stream handling
- Time Machine quota support
- Finder metadata enrichment in directory enumeration
- Resource fork handling
- AAPL create context negotiation

### 3.16 Self-Contained MD4 (`ksmbd_md4.c` -- 264 lines)

Fallback MD4 implementation for kernels >= 6.6 where `CRYPTO_MD4` was removed
from the kernel crypto API. Ships unconditionally to ensure NTLM authentication
works on all supported kernel versions.

---

## 4. Security Hardening

### 4.1 Reference Count Overflow Protection

All `atomic_t` reference counts converted to `refcount_t` throughout the codebase:
- Connections (`connection.c`)
- Oplock info (`oplock.c`)
- Share config (`share_config.c`)
- Tree connect (`tree_connect.c`)
- Sessions (`user_session.c`)

`refcount_t` provides kernel-level detection of overflow, underflow, and
use-after-free via `refcount_inc_not_zero()` / `refcount_dec_and_test()`.

### 4.2 Authentication Hardening (`auth.c`)

- **Constant-time comparison reordering**: `crypto_memneq()` runs BEFORE
  `ksmbd_gen_sess_key()` -- prevents session key generation for failed auth
- **Key scrubbing**: `memzero_explicit()` for ntlmv2_hash, IV, signing key,
  construct buffers after use
- **Sensitive free**: `kfree_sensitive()` replaces `kfree()` for all
  credential-derived allocations (uniname, domain, construct)
- **Integer overflow protection**: `check_add_overflow()` in NTLMv2 construct
  allocation and SG table sizing
- **AES-GMAC signing**: New `ksmbd_sign_smb3_pdu_gmac()` for SMB 3.1.1
  (GCM with zero-length plaintext, message as AAD, 12-byte nonce)
- **GCM nonce monitoring**: `atomic64_t gcm_nonce_counter` per session tracks
  nonce usage; CCM path warns at birthday bound (~2^44 messages)
- **Preauth session locking**: `down_read/up_read` around preauth hash lookup
  with local copy
- **SG bounds checking**: Every `sg_set_page()` call guarded by `sg_idx >= total_entries`
- **NULL session tracking**: `SMB2_SESSION_FLAG_IS_NULL_LE` for anonymous auth
- **NTLMv2 blen validation**: Reject blen <= 0 early

### 4.3 Transport & Connection Hardening

- **CAP_NET_ADMIN unconditional**: No longer behind a compile-time option.
  All netlink operations require `CAP_NET_ADMIN`.
- **Session encryption enforcement** (MS-SMB2 3.3.5.2.5): Unencrypted requests
  on encrypted sessions return `STATUS_ACCESS_DENIED` and disconnect the client
- **TOCTOU path resolution**: `LOOKUP_BENEATH` used unconditionally in all
  VFS path resolution to prevent path traversal attacks
- **RDMA disconnect race**: `cmpxchg()` state transition replaces check-then-set
- **IPC integer overflow**: `check_add_overflow()` in all IPC message allocations

### 4.4 SMB1 Protocol Hardening

- **AndX chain protection**: Bounds checking against `buf_end`, loop depth limit
  (max 32), non-forward-progress detection (prevents infinite loops on malformed
  packets)
- **AndX response overflow**: `andx_response_buffer()` validates `buf_size` and
  `min_size` before writing
- **Lock count cap**: Configurable maximum lock count per request prevents
  resource exhaustion

### 4.5 Buffer & Bounds Validation

- Security descriptor `build_sec_desc()` complete rewrite with proper size
  calculations (buffer overflow fix)
- NDR unaligned access fix
- IOCTL InputOffset bounds validation before pointer arithmetic
- EA buffer size validation at all call sites
- Credit exhaustion differentiated from structural PDU failures
- Crypto context livelock fix with NULL handling

---

## 5. Performance Improvements

### 5.1 Lock Granularity

| Resource | Upstream | This Fork | Impact |
|----------|----------|-----------|--------|
| Connection list | Global `rwsem` | Per-bucket `spinlock_t` | Eliminates global contention |
| Inode hash | Global `rwlock` | Per-bucket `rwlock_t` | Parallel inode lookups |
| Session lookup | Hash + global lock | RCU readers (`hash_for_each_possible_rcu`) | Lock-free session lookup |
| Share config lookup | Hash + global lock | RCU readers + `spinlock_t` for writers | Lock-free share lookup |
| Lease table | List + global lock | RCU (`list_add_rcu`, `kfree_rcu`) | Lock-free lease iteration |

### 5.2 Memory Allocation

| Object | Upstream | This Fork |
|--------|----------|-----------|
| oplock_info | `kzalloc()` | Dedicated `kmem_cache` slab |
| ksmbd_work | `kzalloc()` | Dedicated `kmem_cache` slab |
| ksmbd_file (fp) | `kzalloc()` | Dedicated `kmem_cache` slab |
| READ/WRITE buffers | Per-request alloc | Reusable buffer pool (`ksmbd_buffer.c`) |

### 5.3 I/O Path

- **Zero-copy READ**: `ksmbd_vfs_sendfile()` uses splice for direct kernel-to-socket
  data transfer without copying through userspace-visible buffers
- **AllocationSize caching**: Per-inode `m_cached_alloc` avoids repeated VFS stat calls
- **Socket backlog**: Increased from 16 to 64 pending connections
- **TCP keepalive**: TCP_KEEPIDLE=120s, TCP_KEEPINTVL=30s, TCP_KEEPCNT=3

---

## 6. Protocol Spec Compliance

### 6.1 Systematic Compliance Fixes (39+ Fixes)

These fixes were identified through systematic review of the MS-SMB2, MS-SMB,
MS-FSCC, and MS-XCA specifications. Each references the relevant spec section.

#### Negotiate (MS-SMB2 3.3.5.4)

| ID | Issue | Fix |
|----|-------|-----|
| CR-01 | Second NEGOTIATE not rejected | `ksmbd_conn_set_exiting()` + no response (3.3.5.3.1) |
| CR-02 | Duplicate negotiate contexts silently ignored | STATUS_INVALID_PARAMETER for duplicate PREAUTH/ENCRYPT/COMPRESS/RDMA |
| ME-05 | Missing Preauth_HashId after deassemble | STATUS_INVALID_PARAMETER when preauth not negotiated |
| NEG-3 | SigningAlgorithmCount=0 accepted | STATUS_INVALID_PARAMETER |
| NEG-4 | CompressionAlgorithmCount=0 accepted | STATUS_INVALID_PARAMETER |
| NEG-5 | No signing algorithm overlap fatal | Fallback to AES-CMAC (`signing_negotiated=true`) |

#### Session (MS-SMB2 3.3.5.5)

| ID | Issue | Fix |
|----|-------|-----|
| CR-03 | Unencrypted requests on encrypted sessions | STATUS_ACCESS_DENIED + disconnect (3.3.5.2.5) |
| CR-04 | Channel sequence not tracked | Per-file tracking with wrap-around detection (3.3.5.2.10) |
| SESS-1 | Anonymous session flag not set | SMB2_SESSION_FLAG_IS_NULL_LE for NTLMSSP_ANONYMOUS |

#### Create (MS-SMB2 3.3.5.9)

| ID | Issue | Fix |
|----|-------|-----|
| HI-02 | DELETE_ON_CLOSE without delete access | STATUS_ACCESS_DENIED when daccess lacks FILE_DELETE_LE |
| HI-03 | APPEND_DATA writes at non-EOF | Rejected for FILE_APPEND_DATA-only handles |
| HI-05 | Odd NameLength accepted | EINVAL (must be even for UTF-16LE) |
| - | DELETE_ON_CLOSE + READONLY | STATUS_CANNOT_DELETE |
| - | WRITE sentinel 0xFFFFFFFFFFFFFFFF | Recognized as append-to-EOF |

#### Compound (MS-SMB2 3.3.5.2)

| ID | Issue | Fix |
|----|-------|-----|
| - | CREATE failure cascades to all | Only CREATE failures propagate (3.3.5.2.3) |
| - | FID not captured from non-CREATE | Extracts FID from FLUSH/READ/WRITE/CLOSE/etc. (3.3.5.2.7.2) |

#### Lock (MS-SMB2 3.3.5.14)

Five bugs fixed in lock sequence replay:

1. Bit extraction order reversed (index/sequence nibbles swapped)
2. Replay returned STATUS_FILE_NOT_AVAILABLE instead of STATUS_OK
3. Array lock_seq[16] too small -- now lock_seq[65] (valid indices 1-64)
4. No "invalid" sentinel -- now uses 0xFF
5. Sequence stored before lock processed -- now stored after success only

#### IOCTL (MS-SMB2 3.3.5.15)

| ID | Issue | Fix |
|----|-------|-----|
| HI-01 | Flags==0 accepted | STATUS_INVALID_PARAMETER (only SMB2_0_IOCTL_IS_FSCTL valid) |

#### Tree Connect (MS-SMB2 3.3.5.7)

| ID | Issue | Fix |
|----|-------|-----|
| ME-02 | Unbounded share name | Reject names >= 80 chars with STATUS_BAD_NETWORK_NAME |
| R-03 | Extension path parsing | PathOffset relative to Buffer[0] when EXTENSION_PRESENT |

#### Flush (MS-SMB2 3.3.5.11)

| ID | Issue | Fix |
|----|-------|-----|
| FLUSH-1 | No access check | Require FILE_WRITE_DATA or FILE_APPEND_DATA |
| FLUSH-3 | Not-found returns INVALID_HANDLE | STATUS_FILE_CLOSED |

#### Notification

| ID | Issue | Fix |
|----|-------|-----|
| R-01/R-02 | No server-to-client notification | SMB2_SERVER_TO_CLIENT_NOTIFICATION (command 0x0013) implemented |

---

## 7. SMB1 Enhancements

The SMB1 protocol handler (`smb1pdu.c`) grew from ~8,300 to ~10,100 lines with:

### 7.1 NT_TRANSACT Support

Full NT_TRANSACT subcommand dispatcher with handlers for:
- NT_TRANSACT_IOCTL
- NT_TRANSACT_NOTIFY_CHANGE
- NT_TRANSACT_RENAME
- NT_TRANSACT_QUERY_QUOTA
- NT_TRANSACT_CREATE

### 7.2 Dialect Negotiation Fixes

- Added `"\2NT LANMAN 1.0"` alias (smbclient sends this variant instead of
  `"\2NT LM 0.12"`)
- SMB1-to-SMB2 upgrade uses wildcard dialect `0x02FF` (not specific dialect)
- `conn->smb1_conn` flag distinguishes pure SMB1 from upgraded connections
- Memory leak fix: `kfree(conn->vals)` before re-allocation in negotiate paths

### 7.3 Protocol Correctness

- Session disconnect no longer tears down the entire TCP connection; only
  invalidates the specific UID
- Tree disconnect returns `STATUS_SMB_BAD_TID` (was `STATUS_NO_SUCH_USER`)
- `DISCONNECT_TID` flag handling in tree connect for clean reconnection
- `CAP_LOCK_AND_READ` removed from advertised capabilities (opcode 0x13 has no handler)
- POSIX lock `fl_end` calculated correctly as inclusive (`fl_start + length - 1`)
- FORTIFY_SOURCE bypass for intentional variable-length struct writes

---

## 8. SMB2/3 Enhancements

Beyond the decomposition and compliance fixes, significant enhancements to existing handlers:

### 8.1 Connection & Server Core

- **Compression pipeline**: `smb2_decompress_req()` / `smb2_compress_resp()` in main
  request/response path
- **Async work lifecycle**: `__handle_ksmbd_work()` returns `bool` to indicate pending
  async work, preventing use-after-free with concurrent `SMB2_CANCEL`
- **Shutdown ordering**: Transport destruction before workqueue destruction
- **max_async_credits**: Configurable (default 512)

### 8.2 Oplock/Lease Improvements

- Dedicated slab cache for `opinfo` allocation
- Per-inode lease locking via RCU
- `wait_on_bit_timeout()` replaces indefinite `wait_on_bit()` (prevents hangs)
- Breaking count leak fix in timeout error path
- Directory lease granting and breaking (RH->R for directories)
- `smb_break_parent_dir_lease()` for rename/hardlink/delete operations
- Connection refcount safety: check `refcount_inc_not_zero` before opinfo allocation

### 8.3 VFS Layer

- Path traversal protection via unconditional `LOOKUP_BENEATH`
- Zero-copy read via splice
- AllocationSize caching with invalidation on write
- Rename hardening: cross-connection permission checks, recursive child-open detection
- Stream file handling: directories with streams no longer fail directory checks
- Delete-on-close deferred to last closer (not aggressive unlink)
- `ksmbd_inode_pending_delete()` checks only `S_DEL_PENDING` flag

### 8.4 ACL & Security Descriptors

- `build_sec_desc()` rewritten with proper size calculations
- SACL handling in security descriptor parsing and building
- `hide_on_access_denied` support: empty DACL = hidden file, partial DACL = access denied
- `smb_map_generic_desired_access()` expands GENERIC_EXECUTE before DACL check
- Enhanced `mode_to_access_flags()` permission mapping
- `DESIRED_ACCESS_MASK` = `0xF21F01FF` (includes SYNCHRONIZE bit 20)

### 8.5 Session Management

- RCU-based session lookups
- Batched session cleanup (up to 16 per batch with `synchronize_rcu()`)
- Session state transitions protected with `rw_semaphore state_lock`
- Key scrubbing with `memzero_explicit()` for `smb3signingkey` on channel deletion
- Session closed notification sent to other channels on logoff

### 8.6 Share Configuration

- RCU-based share lookups with `spinlock_t` for writers
- Path traversal protection via `ksmbd_path_has_dotdot_component()`
- Share name validation with `strnlen()` bounds checking
- IPC$ auto-detection

### 8.7 Transport

- **TCP**: Keepalive configuration, per-bucket connection hash, sendfile support,
  additional error codes in listen loop
- **RDMA**: Transform capabilities negotiation, send pending timeout (no indefinite
  hang), disconnect race fix via `cmpxchg()`, proper client IP extraction for hash
- **IPC**: Witness protocol events (7 types), integer overflow protection,
  CAP_NET_ADMIN always enforced

---

## 9. ksmbd-tools Enhancements

The userspace tools fork adds 22 commits (+7,443/-657 lines) plus 37 files with
uncommitted changes (+793/-153 lines).

### 9.1 Unified CLI: ksmbdctl

Replaces the multi-binary pattern (`ksmbd.mountd`, `ksmbd.adduser`, `ksmbd.addshare`,
`ksmbd.control`) with a unified CLI using git-style subcommands:

```
ksmbdctl user add|set|delete|list
ksmbdctl share add|update|delete|list
ksmbdctl debug|config|start|stop|reload|status|features|version
```

Old tool names remain as backward-compatible symlinks. systemd service updated to
use `ksmbdctl start/reload/stop`.

### 9.2 Operational Features

- **`ksmbdctl status`**: Server health (module load state, version, mountd PID,
  debug components)
- **`ksmbdctl features`**: Configured feature flags (encryption, multichannel,
  durable handles, fruit, protocol range)
- **Structured JSON logging**: `--json-log` option for log aggregation systems
- **systemd sd_notify**: `READY=1` after IPC initialization for `Type=notify` services

### 9.3 Network Access Control

CIDR notation support in `hosts allow` / `hosts deny`:

```ini
[share]
    hosts allow = 192.168.1.0/24, 10.0.0.0/8, fd00::/8
    hosts deny = 0.0.0.0/0
```

Supports both IPv4 and IPv6. Unit tests included.

### 9.4 macOS/Fruit Configuration

Per-share fruit options:

```ini
[timemachine]
    fruit time machine = yes
    fruit time machine max size = 1T
    fruit finder info = yes
    fruit resource fork size = 0
    fruit max access = 0x1F01FF
```

Global `fruit model` setting. Wired through IPC to kernel share flags.

### 9.5 RPC Protocol Fixes (Critical)

- **Binary handle hashing**: `g_str_hash/g_str_equal` replaced with proper binary
  hash/equal in LSARPC and SAMR. Binary handles containing NUL bytes caused silent
  data corruption with string-based hashing.
- **NDR correctness**: `ndr_read_vstring()` reads actual_count and validates against
  max_count. NDR offset corrected.
- **DCE/RPC bind**: Iterates ALL transfer syntaxes per context (was only checking [0])
- **UUID comparison**: Now compares clock_seq, node, and ver_minor (was incomplete)
- **dssetup disambiguation**: Uses context_id tracking instead of fragile
  `frag_length == 26` heuristic
- **SRVSVC**: Fixed NDR encoding for NetShareInfoCtr level==1
- **Response header**: Writes `reserved` byte per DCE/RPC spec

### 9.6 Security Hardening

- **Password scrubbing**: `explicit_bzero()` before every `g_free()` of password/key
  material: argv optarg, MD4 context, UTF-16LE intermediates, Kerberos session keys,
  SPNEGO blobs, base64 strings
- **Thread-safe functions**: `getpwuid()` -> `getpwuid_r()`, `strtok()` -> `strtok_r()`
- **Signal handler safety**: `ksmbd_health_status` -> `volatile sig_atomic_t`
- **Config file permissions**: 0640 -> 0600
- **SID bounds checking**: Count limited to 256, sub_auth validated
- **Config parser**: `errno` checking, exact key matching (prevents prefix collisions),
  port validation (> 65535 rejected), PID verification via `/proc/PID/comm`
- **IPC**: `select()` -> `poll()` (no FD_SETSIZE limit)
- **Wire struct packing**: `__packed` on all ACL and RPC header structures
- **Symbol renames**: `ACCESS_ALLOWED` -> `SMB_ACCESS_ALLOWED` etc. to avoid
  system header collisions

### 9.7 Stability Fixes

- Session cap race condition: atomic check before add
- Session cap leak: only reclaim when no remaining tree connections
- Tree connect failure: proper error status and cleanup
- Off-by-one in max_connections check
- Memory leaks: `put_ksmbd_user()` on duplicate map entries, handle closures
- Worker pool: `wp_init()` returns error code, checks thread pool creation
- IPC message size validation: forward-compatible minimum size check

### 9.8 Witness Protocol ABI (Uncommitted)

7 new netlink event types for MS-SWN cluster failover:
- WITNESS_REGISTER / UNREGISTER (request + response)
- WITNESS_NOTIFY
- WITNESS_IFACE_LIST (request + response)
- Wire structures, state constants, netlink policy entries

### 9.9 Documentation

- `ksmbd.conf.example` rewritten to 1,247 lines -- comprehensive configuration reference
- `ksmbdctl.8.in` man page expanded to 1,125 lines -- full admin reference with
  architecture overview, security model, performance tuning, debugging guide

---

## 10. Build System & Infrastructure

### 10.1 Makefile

Rewritten from 83 to 259 lines:

- Feature flags default to `y` for external builds: `CONFIG_SMB_INSECURE_SERVER`,
  `CONFIG_KSMBD_FRUIT`, `CONFIG_SMB_SERVER_QUIC`
- `KSMBD_INCLUDE_DIRS` with 7 `-I` paths for the new source hierarchy
- Architecture auto-detection from `uname -m` with ARM64/PPC64 normalization
- New targets: `deploy`, `undeploy`, `remote-deploy-{x86_64,arm64,ppc64}`, `help`
- DKMS: proper add/build/install sequence with error-tolerant uninstall

### 10.2 Kconfig

New options:

- **`CONFIG_SMB_SERVER_QUIC`**: QUIC transport with CRYPTO_AES/GCM/HMAC/SHA256
  selects and TLS dependency
- **`CONFIG_KSMBD_FRUIT`**: Apple SMB extensions (Time Machine, Finder, resource forks)
- **`CONFIG_KSMBD_KUNIT_TEST`**: KUnit test suite (defaults to `KUNIT_ALL_TESTS`)
- **Removed**: `CONFIG_SMB_SERVER_CHECK_CAP_NET_ADMIN` (always enforced now)
- **Enhanced**: `CRYPTO_MD4` conditional select for graceful degradation

### 10.3 Cross-Compilation

- `Makefile.cross` (227 lines): Generic cross-build framework with kernel source
  download, header preparation, module build, and remote deploy via SSH/SCP
- Architecture wrappers: `Makefile.x86_64`, `Makefile.ppc64`, `Makefile.arm64`

### 10.4 CI/CD (GitHub Actions)

- **Build workflow**: Multi-arch matrix (Ubuntu 24.04, Debian Bookworm, Fedora 41)
  across x86_64, arm32, arm64, ppc64le, riscv64
- **Test workflow**: KUnit structure validation, shellcheck, cppcheck, `BUG_ON`
  detection, mixed tabs/spaces
- Scripts: `ci-build-module.sh`, `ci-install-deps.sh`, `ci-target-map.sh`

### 10.5 .gitignore

Ignores build artifacts (`*.o`, `*.ko`, `*.mod*`, `.*.cmd`) and VM disk images.

---

## 11. Testing & Quality

### 11.1 KUnit Tests (22 files, 7,237 lines)

| Test File | Lines | Coverage |
|-----------|------:|----------|
| `ksmbd_test_hooks.c` | 595 | Hook/callback system |
| `ksmbd_test_buffer.c` | 535 | Buffer validation |
| `ksmbd_test_smb1_parser.c` | 482 | SMB1 PDU parsing |
| `ksmbd_test_fsctl_dispatch.c` | 455 | FSCTL dispatch table |
| `ksmbd_test_unicode.c` | 377 | Unicode conversion |
| `ksmbd_test_fruit.c` | 356 | Apple/Fruit extensions |
| `ksmbd_test_create_ctx.c` | 358 | Create context parsing |
| `ksmbd_test_info_dispatch.c` | 339 | Query/Set info dispatch |
| `ksmbd_test_vss.c` | 327 | Volume Shadow Copy |
| `ksmbd_test_conn_hash.c` | 319 | Connection hash table |
| `ksmbd_test_ida.c` | 310 | IDA management |
| `ksmbd_test_misc.c` | 303 | Misc utilities |
| `ksmbd_test_acl.c` | 292 | ACL handling |
| `ksmbd_test_auth.c` | 277 | Authentication |
| `ksmbd_test_pdu_common.c` | 275 | SMB2 PDU common |
| `ksmbd_test_config.c` | 274 | Configuration |
| `ksmbd_test_feature.c` | 271 | Feature flags |
| `ksmbd_test_reparse.c` | 265 | Reparse points |
| `ksmbd_test_smb_common.c` | 252 | SMB common protocol |
| `ksmbd_test_ndr.c` | 216 | NDR encoding |
| `ksmbd_test_oplock.c` | 203 | Oplock/lease |
| `ksmbd_test_credit.c` | 156 | Credit management |

### 11.2 Fuzz Harnesses (13 files, 4,224 lines)

- `smb2_header_fuzz.c` -- SMB2 header parsing
- `negotiate_context_fuzz.c` -- Negotiate context parsing
- `create_context_fuzz.c` -- Create context parsing
- `security_descriptor_fuzz.c` -- Security descriptor parsing
- `asn1_fuzz.c` -- ASN.1 decoding
- `ndr_fuzz.c` -- NDR encoding/decoding
- `path_parse_fuzz.c` -- Path parsing
- `lock_request_fuzz.c` -- Lock request parsing
- `query_set_info_fuzz.c` -- Query/Set info parsing
- `reparse_point_fuzz.c` -- Reparse point parsing
- `quota_request_fuzz.c` -- Quota request parsing
- `dfs_referral_fuzz.c` -- DFS referral parsing
- `transform_header_fuzz.c` -- Transform header parsing

### 11.3 Benchmark Suite (2,948 lines)

- `latency_profile.sh` -- Per-operation latency profiling
- `run_benchmarks.sh` -- Benchmark orchestration
- `compare_servers.sh` -- Server-to-server comparison
- `scalability_test.sh` -- Connection/throughput scalability

### 11.4 ksmbd-tools Tests

- CIDR host ACL unit tests
- Config parser unit tests (751 lines, 20+ test cases)
- Integration test script (214 lines)
- IPC compatibility test

---

## 12. VM Test Fleet

Complete QEMU-based testing infrastructure under `vm/`:

- **5 Arch Linux VMs** (VM0-VM4): Port-isolated, COW overlay disk images
- **Cloud-init bootstrap**: Automated guest preparation
- **Guest scripts**: Module install, daemon startup, share configuration
- **Test runners**: smbtorture (TCP + QUIC), xfstests, smoke tests
- **Regression matrix**: Multi-VM parallel test execution
- **QUIC test infrastructure**: PKI setup, proxy scripts, compatibility matrix
- **Debug workflows**: Host/guest debug setup, serial console logging

Key ports:
- VM3 (Claude's primary): SSH 13022, SMB 13445
- VM4 (Claude's secondary): SSH 14022, SMB 14445

---

## 13. Feature Comparison Matrix

| Feature | Upstream 3.5.4 | This Fork |
|---------|:--------------:|:---------:|
| **Protocols** | | |
| SMB 2.1 / 3.0 / 3.0.2 / 3.1.1 | Yes | Yes |
| SMB1 (CIFS) | Yes | Yes (enhanced) |
| **Authentication** | | |
| NTLM / NTLMv2 / Kerberos | Yes | Yes (hardened) |
| HMAC-SHA256 / AES-CMAC signing | Yes | Yes |
| AES-GMAC signing | No | Yes |
| SMB3 Encryption (CCM/GCM) | Yes | Yes (nonce monitoring) |
| **Core Features** | | |
| Oplocks / Leases v1/v2 | Yes | Yes (per-inode, RCU) |
| Durable Handles v1/v2 | Yes | Yes (enhanced) |
| Compound Requests | Yes | Yes (FID propagation fix) |
| Multi-channel | Partial | Partial (enhanced) |
| **New Protocol Features** | | |
| SMB3 Compression | No | **LZNT1/LZ77/LZ77+Huffman** |
| SMB over QUIC | No | **Kernel-native (RFC 9000)** |
| CHANGE_NOTIFY + WATCH_TREE | Basic | **Full (fsnotify)** |
| DFS Referrals | No | **Yes** |
| VSS / Previous Versions | No | **Yes** |
| BranchCache | No | **Yes** |
| Witness Protocol (MS-SWN) | No | **Yes** |
| Reparse Points | No | **Yes** |
| Quota Support | No | **Yes** |
| Resilient Handles | No | **Yes** |
| RSVD (Virtual Disk) | No | **Yes** |
| Apple/Fruit Extensions | No | **Yes** |
| App Instance ID | No | **Yes** |
| Server-to-Client Notification | No | **Yes** |
| **Performance** | | |
| Per-bucket connection locking | No | **Yes** |
| Per-bucket inode locking | No | **Yes** |
| RCU session/share lookup | No | **Yes** |
| Slab caches (opinfo/work/fp) | No | **Yes** |
| Zero-copy I/O (splice) | No | **Yes** |
| Buffer pool | No | **Yes** |
| **Infrastructure** | | |
| debugfs interface | No | **Yes** |
| Hook system | No | **Yes** |
| Unified CLI (ksmbdctl) | No | **Yes** |
| CIDR host ACLs | No | **Yes** |
| JSON logging | No | **Yes** |
| sd_notify | No | **Yes** |
| KUnit tests | No | **22 test files** |
| Fuzz harnesses | No | **13 harnesses** |
| CI/CD (multi-arch) | No | **Yes** |
| Benchmark suite | No | **Yes** |

---

## 14. Test Results

### smbtorture Sweep (2026-03-02, VM3)

```
PASS  = 387
FAIL  = 170
SKIP  =  68
TOTAL = 625

Improvement: +44% vs. 269-PASS baseline
```

**Perfect suites (0 failures):**
- `smb2.getinfo` (8/8)
- `smb2.dir` (9/9)
- `smb2.lock` (45/45, 4 skip)
- `smb2.read` (4/4, 1 skip)
- `smb2.maxfid` (1/1)
- `smb2.compound` (20/20)

**Top passing categories:**
- `smb2.ioctl`: 54 pass
- `smb2.oplock`: 45 pass
- `smb2.lock`: 45 pass
- `smb2.lease`: 27 pass
- `smb2.durable-open`: 22 pass
- `smb2.compound`: 20 pass

**Smoke tests:**
- TCP: 7/7 PASS, 0 FAIL, 0 SKIP
- QUIC: 7/7 PASS, 0 FAIL, 0 SKIP

---

## 15. Known Issues

### Active

- `ksmbdctl stop` shows cosmetic "Invalid lock entry" messages
- SMB1 session setup triggers `__fortify_memcpy` WARN (non-fatal, pre-existing)
- `session.reauth5`: Known Samba test bug since 2012 (in knownfail on all branches)
- Some `ioctl.dup_extents` and `durable-v2-open` tests crash the daemon
- `ksmbd_netdev_event`: Intermittent NULL deref at boot (non-fatal Oops)
- QUIC Generic Netlink registration fails on kernel 6.18.13 (made non-fatal;
  TCP/RDMA continue working)
- Heavy smbtorture stress can saturate refcounts in `ksmbd_conn_transport_destroy`
  during shutdown (requires module reload to recover)
- `ksmbdctl user set` generates wrong NT hash; workaround: `user delete` + `user add`

### Limitations

- `wait_lease_breaking` has 1-second timeout (pre-existing); causes lease break ACK
  failures when clients delay > 1s
- Server enters `SERVER_RESET` state after crash; requires `rmmod` + `insmod` to recover
- `KillUserProcesses=yes` on VMs: SSH session end kills daemon; must combine
  prepare + test in single session

---

*Generated 2026-03-02 by Claude Code (Opus 4.6)*
*Branch: phase1-security-hardening (134 commits, +134,220/-26,774 lines)*
*Upstream baseline: cifsd-team/ksmbd 3.5.4 / ksmbd-tools 3.5.6*
