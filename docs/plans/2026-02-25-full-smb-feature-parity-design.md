# Design: ksmbd 100% SMB Feature Parity

**Date:** 2026-02-25
**Goal:** Implement every SMB protocol feature — standard and non-standard — across all dialect versions (SMB1, 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1).
**Approach:** Phased by protocol layer, lowest risk first.

---

## Current State

ksmbd is at ~95% feature coverage. All 19 SMB2 commands are implemented. Encryption (AES-128/256-CCM/GCM), signing (HMAC-SHA256, AES-CMAC, AES-GMAC), pre-auth integrity (SHA-512), durable/persistent/resilient handles, directory leases, multi-channel, RDMA, DFS, VSS, Apple AAPL, server-side copy, reparse points, and named pipes are all functional.

### Remaining Gaps

| Gap | Impact | Complexity |
|-----|--------|------------|
| 7 missing QueryDirectory info classes (FileId* variants) | High — Windows clients request these | Low |
| ~15 stub-only FSCTL handlers | Medium — silent wrong behavior | Low-Medium |
| Compression transform (message-level) | Medium — performance feature | Medium |
| POSIX extensions completion | High — Linux/macOS clients | Medium |
| BranchCache (FSCTL_SRV_READ_HASH) | Low — branch office optimization | Medium |
| Witness Protocol (MS-SWN) | High — cluster failover | High |
| QUIC Transport | High — VPN-less secure access | High |
| Shared Virtual Disks (MS-RSVD) | Low — Hyper-V specific | High |
| ODX Offload Copy | Medium — storage optimization | Medium |
| SMB1 edge cases | Low — deprecated protocol | Low |

---

## Phase 1: Missing Directory Info Classes & FSCTL Completion

### 1A. QueryDirectory Info Classes

**Files:** `src/protocol/smb2/smb2_dir.c`, `src/include/protocol/smb2pdu.h`

Currently implemented: FileDirectoryInformation (1), FileFullDirectoryInformation (2), FileBothDirectoryInformation (3), FileNamesInformation (12).

**Add these 7 classes:**

| Level | Class | Key Addition |
|-------|-------|-------------|
| 37 | FileIdBothDirectoryInformation | 8-byte FileId field |
| 38 | FileIdFullDirectoryInformation | 8-byte FileId field |
| 60 | FileIdExtdDirectoryInformation | 16-byte FileId + EA size |
| 78 | FileId64ExtdDirectoryInformation | 64-bit FileId + EA |
| 79 | FileId64ExtdBothDirectoryInformation | 64-bit FileId + short name + EA |
| 80 | FileIdAllExtdDirectoryInformation | All extended fields |
| 81 | FileIdAllExtdBothDirectoryInformation | All extended + short name |

**Implementation approach:**
- Extend the existing `smb2_populate_readdir_entry()` function with new format cases
- FileId is obtained from `stat->ino` (Linux inode number)
- Short names: use 8.3 name generation from VFS or return empty (Linux doesn't natively generate 8.3 names)
- EA size: return extended attribute total size via `vfs_listxattr()` + summing

### 1B. FSCTL Handler Completion

**Files:** `src/fs/ksmbd_fsctl.c`, `src/fs/ksmbd_fsctl_extra.c`, `src/protocol/smb2/smb2_ioctl.c`

**Replace stubs with real implementations where Linux VFS supports it:**

| FSCTL | Current | Action |
|-------|---------|--------|
| FSCTL_FILESYSTEM_GET_STATISTICS | Stub (returns 0) | Implement via `vfs_statfs()` + per-device stats |
| FSCTL_FIND_FILES_BY_SID | Stub (returns 0) | Implement SID-to-UID mapping + directory walk |
| FSCTL_READ_FILE_USN_DATA | Stub (returns 0) | Return STATUS_NOT_SUPPORTED (no USN journal on Linux) |
| FSCTL_WRITE_USN_CLOSE_RECORD | Stub (noop) | Return STATUS_NOT_SUPPORTED |
| FSCTL_QUERY_FAT_BPB | Stub (returns 0) | Return STATUS_NOT_SUPPORTED (not FAT) |
| FSCTL_SET_ENCRYPTION | Stub (noop) | Implement via fscrypt API if available, else STATUS_NOT_SUPPORTED |
| FSCTL_RECALL_FILE | Stub (noop) | Return STATUS_NOT_SUPPORTED (no HSM) |
| FSCTL_SET_ZERO_ON_DEALLOCATION | Stub (noop) | Map to fallocate with FALLOC_FL_ZERO_RANGE semantics |
| FSCTL_SET_SHORT_NAME_BEHAVIOR | Stub (noop) | Keep noop (Linux doesn't use 8.3 names natively) |
| FSCTL_SET_DEFECT_MANAGEMENT | Stub (noop) | Return STATUS_NOT_SUPPORTED |

**Add new FSCTL handlers (currently undefined):**

| FSCTL | Implementation |
|-------|---------------|
| FSCTL_GET_INTEGRITY_INFORMATION | Map to filesystem integrity features (btrfs checksums) |
| FSCTL_SET_INTEGRITY_INFORMATION | Map to filesystem integrity features |
| FSCTL_QUERY_FILE_REGIONS | Map to FIEMAP ioctl for extent info |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX | Extend existing handler with atomic flag |
| FSCTL_OFFLOAD_READ | Phase 8 (ODX) |
| FSCTL_OFFLOAD_WRITE | Phase 8 (ODX) |
| FSCTL_SRV_READ_HASH | Phase 4 (BranchCache) |

---

## Phase 2: Compression Transform

### Overview

Current state: ksmbd negotiates compression capabilities but never actually compresses/decompresses message payloads. This phase adds real message-level compression.

**Files to modify:**
- `src/protocol/smb2/smb2_pdu_common.c` — transform header parsing
- `src/include/protocol/smb2pdu.h` — compression structures
- `src/core/connection.c` — transport-level compression/decompression
- New: `src/core/smb2_compress.c` — compression engine

### Compression Algorithms

| ID | Algorithm | Kernel Support | Priority |
|----|-----------|---------------|----------|
| 0x0001 | LZNT1 | `ntfs3` module has LZNT1 | Must |
| 0x0002 | LZ77 (XPRESS) | Custom implementation needed | Must |
| 0x0003 | LZ77+Huffman (XPRESS Huffman) | Custom implementation needed | Must |
| 0x0004 | Pattern_V1 | Simple repeated-byte detection | Must |
| 0x0005 | LZ4 | `lz4_compress`/`lz4_decompress` in kernel | Should (Win11+) |

### Message Flow

```
Receive: SMB2_COMPRESSION_TRANSFORM_HEADER → detect algorithm → decompress → process normally
Send: process normally → compress payload → prepend SMB2_COMPRESSION_TRANSFORM_HEADER → send
```

### Chained Compression

SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED allows multiple compression algorithms per message. Implementation: chain of `SMB2_COMPRESSION_CHAINED_PAYLOAD_HEADER` structures, each specifying algorithm + compressed size.

### Heuristics

- Only compress messages above a configurable threshold (default: 1024 bytes)
- Skip already-compressed data (encrypted payloads)
- Use Pattern_V1 for zero-filled regions before other algorithms

---

## Phase 3: POSIX Extensions Completion

### Current State

- `SMB2_CREATE_TAG_POSIX` create context: implemented (mode bits on create)
- `FS_POSIX_INFORMATION` (100): implemented for QueryDirectory
- POSIX ACL inheritance: implemented via `ksmbd_vfs_inherit_posix_acl()`

### Missing Pieces

**Files:** `src/protocol/smb2/smb2_dir.c`, `src/protocol/smb2/smb2_create.c`, `src/protocol/smb2/smb2_query_set.c`

| Feature | Implementation |
|---------|---------------|
| SMB2_FIND_POSIX_INFORMATION (level 0x64) | New QueryDirectory info class with UID/GID/mode/nlink/device fields |
| POSIX unlink semantics | Delete-on-close for open files (already partially present) |
| POSIX rename semantics | Atomic rename even when target is open |
| flock support | Map SMB2_LOCK to advisory locks when POSIX context active |
| fallocate mapping | Map allocation info to fallocate() with POSIX mode flags |
| UID/GID SID encoding | Encode POSIX UID/GID using special SID format (S-1-22-1-UID, S-1-22-2-GID) |
| Case sensitivity per-share | Honor case-sensitive flag from POSIX negotiate context |
| Reserved character handling | Allow `:*?"<>|` characters when POSIX context active |
| mkfifo/mknod | Support creating special files via reparse point mechanism |

---

## Phase 4: BranchCache (MS-PCCRC)

### Overview

BranchCache enables peer-to-peer content caching in branch offices. The server provides content hashes; clients in the same branch office share cached content.

**Files:** New `src/fs/ksmbd_branchcache.c`, `src/include/fs/ksmbd_branchcache.h`

### Implementation

| Component | Details |
|-----------|---------|
| FSCTL_SRV_READ_HASH | Return content information for requested file range |
| Content Info V1 | SHA-256 segment hashes, 64KB blocks |
| Content Info V2 | Truncated SHA-512 segment hashes |
| Hash generation | Compute on-demand or cache in xattr (`user.ksmbd.pccrc.v1`, `user.ksmbd.pccrc.v2`) |
| Cache invalidation | Invalidate stored hashes on file write/truncate |

### Kernel crypto usage

Use `crypto_shash_*` API for SHA-256/SHA-512 hashing, same pattern as existing `ksmbd_gen_preauth_integrity_hash()`.

---

## Phase 5: Witness Protocol (MS-SWN)

### Overview

The Witness protocol enables SMB3 clients to receive cluster failover notifications. It runs as a DCE/RPC service over TCP.

**Architecture decision:** The Witness RPC service should run in userspace (ksmbd.mountd or new daemon) since it's a separate TCP service, not part of the SMB transport. The kernel module communicates state changes via the existing netlink interface.

### Components

| Component | Location | Responsibility |
|-----------|----------|---------------|
| Witness RPC server | Userspace (ksmbd.mountd extension) | Handle DCE/RPC calls |
| Cluster state manager | Kernel (new `src/mgmt/ksmbd_witness.c`) | Track node/interface state |
| Netlink extensions | `src/transport/transport_ipc.c` | Kernel↔userspace state sync |

### RPC Operations

| Operation | Description |
|-----------|-------------|
| WitnessrGetInterfaceList | Return available cluster interfaces |
| WitnessrRegister | Client registers for notifications on a resource |
| WitnessrUnRegister | Client unregisters |
| WitnessrAsyncNotify | Async notification delivery (resource state change) |
| WitnessrRegisterEx | Extended registration with share move support |

### Notification Types

- RESOURCE_CHANGE: Node available/unavailable
- CLIENT_MOVE: Client should reconnect to different node
- SHARE_MOVE: Share moved to different node
- IP_CHANGE: Network interface address changed

---

## Phase 6: QUIC Transport

### Overview

SMB over QUIC enables secure file access without VPN, using QUIC (RFC 9000) on port 443 with TLS 1.3 client certificate authentication.

**Architecture:** New transport module using existing kernel infrastructure.

### Kernel Infrastructure

| Component | Kernel Feature | Status |
|-----------|---------------|--------|
| QUIC protocol | `AF_INET6`/`AF_INET` + kernel QUIC (QUIC-LB, in-kernel QUIC) | Evolving; may need `kTLS` + userspace QUIC shim |
| TLS 1.3 | Kernel TLS (kTLS) via `setsockopt(SOL_TLS)` | Available since Linux 4.13 |
| Certificate auth | Kernel keyring + kTLS handshake | Available |

### Implementation Options

**Option A: Full in-kernel QUIC** (preferred if kernel QUIC matures)
- Use kernel QUIC socket API directly
- Lowest latency, consistent with existing transport model

**Option B: Userspace QUIC shim** (pragmatic fallback)
- Userspace process handles QUIC/TLS, forwards decrypted streams to kernel via unix socket
- Similar to how ksmbd.mountd handles RPC
- More portable, easier to update QUIC implementation

**Option C: kTLS + custom QUIC framing** (hybrid)
- Use kTLS for encryption, implement QUIC framing in kernel
- Leverages existing kernel TLS offload

### Files

- New: `src/transport/transport_quic.c` — QUIC transport implementation
- New: `src/include/transport/transport_quic.h` — QUIC transport API
- Modify: `src/core/server.c` — register QUIC transport listener
- Modify: `src/core/connection.c` — QUIC connection handling

### QUIC Stream Mapping

- Each SMB2 connection maps to one QUIC connection
- SMB2 requests/responses map to QUIC streams
- Multi-channel: multiple QUIC connections per session

---

## Phase 7: Shared Virtual Disks (MS-RSVD)

### Overview

Remote Shared Virtual Disk Protocol enables Hyper-V VMs to share VHDX files across cluster nodes.

**Files:** New `src/fs/ksmbd_rsvd.c`, `src/include/fs/ksmbd_rsvd.h`

### FSCTL Operations

| FSCTL | Description |
|-------|-------------|
| FSCTL_SVHDX_SYNC_TUNNEL_REQUEST | Synchronous VHDX metadata operations |
| FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST | Async VHDX metadata operations |
| FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT | Capability query |

### Tunnel Operations

- RSVD_TUNNEL_GET_INITIAL_INFO
- RSVD_TUNNEL_SCSI_REQUEST (SCSI passthrough)
- RSVD_TUNNEL_CHECK_CONNECTION_STATUS
- RSVD_TUNNEL_META_OPERATION_START (resize, snapshot)
- RSVD_TUNNEL_CHANGE_TRACKING_GET_PARAMETERS
- RSVD_TUNNEL_CHANGE_TRACKING_START/STOP

### VHDX Integration

- Parse VHDX file headers for metadata
- Support dynamic and differencing VHDX files
- Coordinate access across multiple opener nodes via app instance IDs

---

## Phase 8: ODX Offload Copy & Remaining Gaps

### ODX (Offload Data Transfer)

**Files:** `src/protocol/smb2/smb2_ioctl.c`, new `src/fs/ksmbd_odx.c`

| FSCTL | Description |
|-------|-------------|
| FSCTL_OFFLOAD_READ | Generate token representing file data range |
| FSCTL_OFFLOAD_WRITE | Write data referenced by token to target file |

**Implementation:**
- Tokens are server-local (opaque 512-byte blobs containing file ID + range + generation)
- Use `copy_file_range()` syscall for actual data transfer
- Token validation: check generation counter against file mtime

### FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX

Extend existing `FSCTL_DUPLICATE_EXTENTS_TO_FILE` handler:
- Add `DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC` flag support
- Atomic semantics: either entire clone succeeds or fails

### SMB1 Remaining Commands

Complete TODO items in `src/protocol/smb1/smb1pdu.c`:
- Process caps properly in negotiate
- Fix signed tree connect
- Handle DOS mode and ACL bits
- Improve time handling compatibility

---

## Testing Strategy

Each phase includes:
1. **Unit tests:** Extend `test/` with targeted tests for new handlers
2. **Protocol conformance:** Use `smbclient`, `smbcacls`, Windows clients for validation
3. **Fuzzing:** Extend `test/fuzz/` with inputs for new FSCTL codes and info classes
4. **Interop testing:** Test against Windows 10/11, macOS, Linux cifs.ko clients
5. **Regression:** Existing test suite must pass after each phase

---

## Specification References

- [MS-SMB2]: Server Message Block Protocol Versions 2 and 3
- [MS-FSCC]: File System Control Codes
- [MS-DFSC]: Distributed File System: Referral Protocol
- [MS-SWN]: Service Witness Protocol
- [MS-RSVD]: Remote Shared Virtual Disk Protocol
- [MS-PCCRC]: Peer Content Caching and Retrieval: Content Identification
- SMB3 POSIX Extensions: Samba Wiki SMB3-Linux + Codeberg spec
- QUIC: RFC 9000, RFC 9001 (QUIC-TLS)
