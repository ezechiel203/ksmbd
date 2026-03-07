# 06 - Missing and Incomplete Optional/Extension Module Features

**Date**: 2026-02-22
**Scope**: ksmbd in-kernel SMB3 server at `/home/ezechiel203/ksmbd/`
**Reviewer**: SMB ecosystem expert review

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Apple/Fruit Extensions (AAPL Create Context)](#2-applefruit-extensions-aapl-create-context)
3. [DFS (Distributed File System)](#3-dfs-distributed-file-system)
4. [VSS/Snapshots (Previous Versions)](#4-vsssnapshots-previous-versions)
5. [Witness Protocol (MS-SWN)](#5-witness-protocol-ms-swn)
6. [RDMA/SMB Direct](#6-rdmasmb-direct)
7. [Compression](#7-compression)
8. [Encryption Enhancements](#8-encryption-enhancements)
9. [Quota Support](#9-quota-support)
10. [Extended Attribute / Stream Support](#10-extended-attribute--stream-support)
11. [Reparse Points / Symlinks](#11-reparse-points--symlinks)
12. [Server-Side Copy](#12-server-side-copy)
13. [Sparse File Support](#13-sparse-file-support)
14. [File Leasing Enhancements](#14-file-leasing-enhancements)
15. [Print Services](#15-print-services)
16. [Named Pipe Enhancements](#16-named-pipe-enhancements)
17. [Change Notification Enhancements](#17-change-notification-enhancements)
18. [Priority Matrix](#18-priority-matrix)
19. [Recommended Implementation Roadmap](#19-recommended-implementation-roadmap)

---

## 1. Executive Summary

This report examines 16 optional protocol extensions and module features for the ksmbd in-kernel SMB3 server, assessing each against the MS-SMB2 specification and comparing with the feature-completeness of Samba and Windows Server implementations.

### Overall Assessment

| Status | Count | Extensions |
|--------|-------|------------|
| **Complete** | 1 | Encryption (with AES-256 support) |
| **Mostly Complete** | 5 | RDMA/SMB Direct, Server-Side Copy, Sparse Files, Named Streams, File Leasing |
| **Partial** | 3 | Apple/Fruit Extensions, Reparse Points, Named Pipes |
| **Stub** | 1 | Change Notification |
| **Missing** | 6 | DFS, VSS/Snapshots, Witness Protocol, Compression, Quota, Print Services |

The server is production-ready for basic file sharing with Windows, Linux, and (partially) macOS clients. The most impactful missing features for enterprise deployment are DFS, VSS/Snapshots, and Change Notification. For macOS environments, completing the Fruit extensions is critical.

---

## 2. Apple/Fruit Extensions (AAPL Create Context)

### 2.1 Overview

- **Name**: Apple SMB Extensions (AAPL/Fruit)
- **Protocol reference**: Apple proprietary AAPL Create Context; analogous to Samba's `vfs_fruit` module
- **Current status**: **Partial**
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smb2fruit.h` -- wire structures, capability defines, function declarations
  - `/home/ezechiel203/ksmbd/smb2fruit.c` -- implementation (gated by `CONFIG_KSMBD_FRUIT`)
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 3806-3863 -- AAPL create context processing in `smb2_open()`
  - `/home/ezechiel203/ksmbd/smb2pdu.h` lines 751-818 -- fruit create context wire structures
  - `/home/ezechiel203/ksmbd/oplock.c` lines 2061-2095 -- `create_fruit_rsp_buf()`
  - `/home/ezechiel203/ksmbd/connection.h` lines 120-124 -- `is_fruit`, `fruit_state`
- **Client demand**: macOS, iOS, iPadOS, tvOS, watchOS
- **Implementation complexity**: L (large -- many sub-features)
- **Performance impact**: Minimal for non-Apple clients (compile-time toggle); moderate per-directory-entry overhead when ReadDirAttr enrichment is enabled
- **Recommended approach**: Compile-time toggle (`CONFIG_KSMBD_FRUIT`) -- already implemented
- **Dependencies**: xattr support on underlying filesystem, POSIX ACL support
- **Priority**: P1

### 2.2 What Is Currently Implemented

| Sub-feature | Status | Details |
|-------------|--------|---------|
| AAPL create context negotiation | **Complete** | Client detection, capability negotiation, server response generation |
| Server capabilities advertisement | **Complete** | `kAAPL_SUPPORTS_READ_DIR_ATTR`, `kAAPL_SUPPORTS_OSX_COPYFILE`, `kAAPL_UNIX_BASED`, `kAAPL_SUPPORTS_NFS_ACE` |
| Volume capabilities | **Partial** | `kAAPL_SUPPORT_RESOLVE_ID`, `kAAPL_CASE_SENSITIVE`, `kAAPL_SUPPORTS_FULL_SYNC` defined but volume_caps response not wired into negotiate |
| ReadDirAttr (UNIX mode in EaSize) | **Complete** | `smb2_read_dir_attr_fill()` packs UNIX mode into EaSize field |
| Fruit model string | **Complete** | Configurable via `fruit_model` in server config, sent in AAPL response |
| Client version detection | **Complete** | Supports FRUIT_VERSION_1_0, 1_1, 2_0; client types macOS/iOS/iPadOS/tvOS/watchOS |
| Connection state management | **Complete** | `fruit_conn_state` struct, init/cleanup/update lifecycle |
| F_FULLFSYNC support | **Complete** | `blkdev_issue_flush()` triggered when `Reserved1 == 0xFFFF` on Fruit connections |
| Zero UniqueId for dirs | **Complete** | Gated by `KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID` |
| Server-side copy on Fruit | **Partial** | xattr copy after copychunk (`ksmbd_vfs_copy_xattrs`) is declared but implementation may be incomplete |

### 2.3 What Is Missing Compared to Samba's vfs_fruit

| Missing Sub-feature | Samba Equivalent | Complexity | Impact |
|---------------------|------------------|------------|--------|
| **AFP_AfpInfo stream interception** | `vfs_fruit:metadata=stream` | M | macOS Finder metadata display |
| **AFP_Resource stream interception** | `vfs_fruit:resource=file/xattr` | L | Resource fork read/write for legacy macOS apps |
| **FinderInfo xattr read/write via stream** | `vfs_fruit` FinderInfo handling | M | Color labels, file types, creator codes in Finder |
| **AFP_AfpInfo synthesis** | Netatalk migration | S | Partially implemented (`fruit_synthesize_afpinfo`) but not wired into stream open |
| **Time Machine backup support** | `vfs_fruit:time machine=yes` | L | `KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE` defined but quota enforcement and bundle validation not implemented |
| **Time Machine disk quota** | `time_machine_max_size` | M | Field exists in `ksmbd_share_config_response` and `share_config`, enforcement missing |
| **Resolve ID (inode-to-path)** | `vfs_fruit` resolve_id | M | `ksmbd_vfs_resolve_fileid()` declared but stub when enabled; not wired to AAPL volume_caps |
| **kAAPL_SUPPORTS_TM_LOCK_STEAL** | Samba TM lock steal | M | Defined in header (0x40) but never advertised or handled |
| **Resource fork size in ReadDirAttr** | `fruit:rfork_size` | M | `KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE` defined, `smb2_read_dir_attr_fill()` does not read resource fork size |
| **MaxAccess in ReadDirAttr** | `fruit:max_access` | S | `KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS` defined but not implemented in `smb2_read_dir_attr_fill()` |
| **Server-side copyfile IOCTL** | macOS copyfile(3) semantics | L | `kAAPL_SUPPORTS_OSX_COPYFILE` advertised but actual IOCTL handler not implemented |
| **Spotlight / mdssvc** | `vfs_fruit` + spotlight | XL | Search integration -- out of scope for kernel module |
| **POSIX hardlink detection in dir entries** | `fruit:dir_hardlinks` | S | `fruit_dir_hardlinks` struct defined, not populated |
| **Savebox/LookerInfo context processing** | Not in Samba | S | `fruit_process_savebox_info` and `fruit_process_looker_info` are stubs (log only) |

### 2.4 Recommendations

1. **P1**: Wire AFP_AfpInfo and AFP_Resource stream interception into the named stream open path in `smb2_open()`. This is the single most impactful missing piece for macOS compatibility.
2. **P1**: Implement Time Machine quota enforcement using `time_machine_max_size` from share config.
3. **P2**: Complete ReadDirAttr enrichment (resource fork size, max access) behind per-share flags.
4. **P2**: Wire `ksmbd_vfs_resolve_fileid()` into AAPL volume capabilities response.
5. **P3**: Implement the kAAPL_SUPPORTS_OSX_COPYFILE IOCTL handler for server-side copyfile with metadata preservation.

---

## 3. DFS (Distributed File System)

### 3.1 Overview

- **Name**: Distributed File System (DFS)
- **Protocol reference**: [MS-DFSC] (DFS Referral Protocol); [MS-SMB2] Section 3.3.5.15.2 (FSCTL_DFS_GET_REFERRALS)
- **Current status**: **Missing** (explicit rejection)
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smbfsctl.h` lines 25-26 -- FSCTL defines present
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 9079-9084 -- explicit `STATUS_FS_DRIVER_REQUIRED` rejection
  - `/home/ezechiel203/ksmbd/smb2pdu.h` lines 225, 449-450, 459 -- `SMB2_GLOBAL_CAP_DFS`, `SHI1005_FLAGS_DFS`, `SMB2_SHARE_CAP_DFS` defined
- **Client demand**: Windows (enterprise environments with multiple file servers), Linux (cifs.ko client)
- **Implementation complexity**: L (standalone DFS) / XL (domain-based DFS)
- **Performance impact**: Negligible on core path -- referral lookups are infrequent
- **Recommended approach**: Runtime module with userspace configuration in ksmbd.mountd
- **Dependencies**: ksmbd.mountd enhancements for DFS namespace configuration; optionally Active Directory integration
- **Priority**: P1 (enterprise)

### 3.2 Current State

The FSCTL codes `FSCTL_DFS_GET_REFERRALS` (0x00060194) and `FSCTL_DFS_GET_REFERRALS_EX` (0x000601B0) are defined in `smbfsctl.h` and handled in the IOCTL dispatcher, but the handler immediately returns `STATUS_FS_DRIVER_REQUIRED`:

```c
case FSCTL_DFS_GET_REFERRALS:
case FSCTL_DFS_GET_REFERRALS_EX:
    /* Not support DFS yet */
    ret = -EOPNOTSUPP;
    rsp->hdr.Status = STATUS_FS_DRIVER_REQUIRED;
    goto out2;
```

The `SMB2_FLAGS_DFS_OPERATIONS` flag (0x10000000) is defined in `smb2pdu.h` but never checked. The `SMB2_GLOBAL_CAP_DFS` capability is defined but never advertised in any protocol version's capabilities.

### 3.3 What Would Be Needed

| Component | Description | Complexity |
|-----------|-------------|------------|
| DFS namespace database | Store DFS root/link targets in ksmbd.mountd config | M |
| FSCTL_DFS_GET_REFERRALS handler | Parse referral request, return referral entries with target paths | M |
| FSCTL_DFS_GET_REFERRALS_EX handler | Extended version with site awareness | S |
| DFS path resolution | Strip DFS prefix from paths before VFS operations | M |
| SMB2_FLAGS_DFS_OPERATIONS handling | Detect DFS-prefixed paths in CREATE, TREE_CONNECT | M |
| Capability advertisement | Set `SMB2_GLOBAL_CAP_DFS` in negotiate response | S |
| Share-level DFS flags | `SHI1005_FLAGS_DFS`, `SHI1005_FLAGS_DFS_ROOT` in tree connect | S |
| Netlink extension | New IPC message type for DFS referral lookup | M |
| ksmbd.mountd DFS config | Parse `msdfs root = yes`, `msdfs proxy` from smb.conf | M |

### 3.4 Recommendations

Standalone DFS (without Active Directory) is achievable as a P1 feature. It requires:
1. A new netlink message type `KSMBD_EVENT_DFS_REFERRAL_REQUEST/RESPONSE`
2. ksmbd.mountd reading DFS link configuration from smb.conf
3. Kernel-side FSCTL handler returning DFS_REFERRAL_V3 responses
4. Path stripping in `smb2_open()` when `SMB2_FLAGS_DFS_OPERATIONS` is set

Domain-based DFS should be deferred to P3 as it requires Active Directory integration.

---

## 4. VSS/Snapshots (Previous Versions)

### 4.1 Overview

- **Name**: Volume Shadow Copy Service / Previous Versions
- **Protocol reference**: [MS-SMB2] Section 3.3.5.15.6 (FSCTL_SRV_ENUMERATE_SNAPSHOTS); [MS-SMB2] Section 2.2.13 (@GMT token in path names)
- **Current status**: **Missing**
- **Current code location**: No implementation found. `STATUS_NOT_SNAPSHOT_VOLUME` is defined in `smbstatus.h` (line 1355) but never used.
- **Client demand**: Windows (Previous Versions tab), third-party backup tools
- **Implementation complexity**: M (for btrfs/ZFS) / L (for LVM)
- **Performance impact**: Negligible -- snapshot enumeration is rare
- **Recommended approach**: Runtime module with filesystem-specific snapshot backends
- **Dependencies**: Underlying filesystem snapshot support (btrfs subvolumes, ZFS snapshots, LVM snapshots)
- **Priority**: P1 (enterprise)

### 4.2 Current State

There is **no implementation** of:
- `FSCTL_SRV_ENUMERATE_SNAPSHOTS` -- not in the IOCTL switch statement
- `@GMT-YYYY.MM.DD-HH.MM.SS` token parsing in path names
- Snapshot directory mapping (e.g., `.snapshots/` for btrfs, `.zfs/snapshot/` for ZFS)

### 4.3 What Would Be Needed

| Component | Description | Complexity |
|-----------|-------------|------------|
| FSCTL_SRV_ENUMERATE_SNAPSHOTS handler | Enumerate available snapshots for a share | M |
| @GMT token parser | Detect and parse @GMT tokens in SMB path names | S |
| Snapshot path resolver | Map @GMT token to filesystem snapshot path | M |
| Filesystem backend: btrfs | Use `BTRFS_IOC_SNAP_CREATE` / list subvolumes | M |
| Filesystem backend: ZFS | Parse `.zfs/snapshot/` directory | S |
| Filesystem backend: LVM | Shell out or use dm-ioctl for snapshot listing | L |
| Per-share snapshot config | Enable/disable, snapshot directory path | S |
| Netlink extension | Snapshot enumeration could be delegated to userspace helper | M |

### 4.4 Recommendations

1. Implement `FSCTL_SRV_ENUMERATE_SNAPSHOTS` with a pluggable backend architecture.
2. Start with btrfs support (most common Linux filesystem with snapshots).
3. @GMT token parsing should be in the VFS path resolution layer, transparent to the rest of the server.
4. Consider delegating snapshot enumeration to ksmbd.mountd via netlink to avoid filesystem-specific code in the kernel module.

---

## 5. Witness Protocol (MS-SWN)

### 5.1 Overview

- **Name**: Service Witness Protocol
- **Protocol reference**: [MS-SWN] (Service Witness Protocol)
- **Current status**: **Missing**
- **Current code location**: The only reference is in documentation (`ksmbd.rst` line 110: "for Witness protocol e.g.").
- **Client demand**: Windows (for cluster failover notification)
- **Implementation complexity**: XL
- **Performance impact**: None on core path (separate RPC endpoint)
- **Recommended approach**: Userspace service (ksmbd-witness daemon)
- **Dependencies**: Cluster infrastructure, persistent handles, multi-channel support
- **Priority**: P3

### 5.2 Current State

There is **no implementation**. The Witness Protocol is a separate RPC service that runs alongside the SMB server to provide cluster failover notifications to clients.

### 5.3 What Would Be Needed

| Component | Description | Complexity |
|-----------|-------------|------------|
| MS-SWN RPC service | Separate RPC endpoint on a well-known pipe | XL |
| Cluster state monitoring | Integration with Linux cluster frameworks (Pacemaker, etc.) | XL |
| Resource move notification | Notify clients when a share moves to a different node | L |
| Client registration database | Track which clients are registered for notifications | M |
| IP address change notification | Notify clients of network interface changes | M |
| Integration with persistent handles | Reconnect using durable/persistent handles after failover | L |

### 5.4 Recommendations

This is an enterprise clustering feature that should be deferred until ksmbd has stable persistent handle support. It would be best implemented as a separate userspace daemon that communicates with ksmbd via netlink, rather than as kernel code.

---

## 6. RDMA/SMB Direct

### 6.1 Overview

- **Name**: SMB Direct (RDMA Transport)
- **Protocol reference**: [MS-SMBD] (SMB2 Remote Direct Memory Access Transport)
- **Current status**: **Mostly Complete**
- **Current code location**:
  - `/home/ezechiel203/ksmbd/transport_rdma.c` -- full implementation (~2400 lines)
  - `/home/ezechiel203/ksmbd/transport_rdma.h` -- wire structures, API declarations
  - `/home/ezechiel203/ksmbd/connection.h` lines 141-148 -- transport ops including `rdma_read`, `rdma_write`
- **Client demand**: Windows (high-performance storage), Hyper-V
- **Implementation complexity**: Already implemented (XL effort was invested)
- **Performance impact**: Significant positive impact for large I/O operations
- **Recommended approach**: Compile-time toggle (`CONFIG_SMB_SERVER_SMBDIRECT`) -- already implemented
- **Dependencies**: RDMA-capable NIC (InfiniBand, iWARP, RoCE), `rdma-core` libraries
- **Priority**: P2

### 6.2 What Is Implemented

| Feature | Status | Details |
|---------|--------|---------|
| SMB Direct negotiation | **Complete** | `smb_direct_negotiate_req/resp` structures, version 1.0 |
| Credit-based flow control | **Complete** | Send/receive credit management with proper synchronization |
| Data transfer framing | **Complete** | `smb_direct_data_transfer` with fragmentation/reassembly |
| RDMA Read channel | **Complete** | `smb_direct_rdma_read()` for client-to-server data |
| RDMA Write channel | **Complete** | `smb_direct_rdma_write()` for server-to-client data |
| Multi-descriptor RDMA | **Complete** | `smb_direct_rdma_xmit()` handles multiple buffer descriptors with credit calculation |
| Connection lifecycle | **Complete** | Connect, disconnect, error handling, work queues |
| Memory registration | **Complete** | Uses `rdma_rw_ctx` API with scatter-gather lists |
| Configurable I/O size | **Complete** | `SMBD_DEFAULT_IOSIZE` (8MB), clamped to 512KB-16MB |
| iWARP + InfiniBand | **Complete** | Dual port support (5445 for iWARP, 445 for InfiniBand) |
| Network interface reporting | **Complete** | `FSCTL_QUERY_NETWORK_INTERFACE_INFO` reports RDMA capability |

### 6.3 What Is Missing

| Missing Feature | MS-SMBD Section | Complexity | Impact |
|-----------------|-----------------|------------|--------|
| **RDMA Channel V2** (`SMB2_CHANNEL_RDMA_V1_INVALIDATE`) | 2.2.3 | M | Performance optimization (remote key invalidation after transfer) -- only V1 descriptors used |
| **SMB Direct negotiate version 2.0** | Future | L | Not yet standardized |
| **Multi-channel RDMA** | [MS-SMB2] 3.2.4.20 | L | Multiple RDMA connections per session; multi-channel framework exists but RDMA-specific multi-channel binding is untested |
| **RDMA-aware zero-copy** | Performance | M | Current implementation copies between kernel buffers and RDMA-registered memory; true zero-copy would use direct page mapping |
| **Encryption over RDMA** | [MS-SMB2] 3.1.4.3 | M | AES-GCM/CCM transform over RDMA transport; may be supported but not explicitly tested |
| **Connection resilience** | [MS-SMBD] 3.1.5.1 | M | Reconnection after transient RDMA failures |

### 6.4 Recommendations

1. **P2**: Test and validate multi-channel with RDMA transport.
2. **P2**: Implement `SMB2_CHANNEL_RDMA_V1_INVALIDATE` for remote key invalidation.
3. **P3**: Investigate zero-copy page mapping for large transfers.

---

## 7. Compression

### 7.1 Overview

- **Name**: SMB 3.1.1 Compression
- **Protocol reference**: [MS-SMB2] Section 2.2.42 (SMB2 COMPRESSION_TRANSFORM_HEADER); [MS-XCA] (compression algorithms)
- **Current status**: **Missing** (negotiate context parsed but compression disabled)
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smb2pdu.h` lines 303-316 -- `smb2_compression_ctx` structure, algorithm defines
  - `/home/ezechiel203/ksmbd/smb2pdu.h` line 113 -- `SMB2_COMPRESSION_TRANSFORM_ID` defined
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 977-980 -- `decode_compress_ctxt()` forces `SMB3_COMPRESS_NONE`
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 872-873 -- `WARN_ON(conn->compress_algorithm != SMB3_COMPRESS_NONE)`
  - `/home/ezechiel203/ksmbd/connection.h` line 113 -- `compress_algorithm` field
- **Client demand**: Windows 10/11, Windows Server 2019+
- **Implementation complexity**: L
- **Performance impact**: CPU overhead for compression/decompression; network bandwidth savings
- **Recommended approach**: Runtime toggle with algorithm selection
- **Dependencies**: Kernel compression libraries (lz77, lznt1)
- **Priority**: P2

### 7.2 Current State

The compression negotiate context is **parsed** during SMB 3.1.1 negotiation but always forces `SMB3_COMPRESS_NONE`:

```c
static void decode_compress_ctxt(struct ksmbd_conn *conn,
                struct smb2_compression_ctx *pneg_ctxt)
{
    conn->compress_algorithm = SMB3_COMPRESS_NONE;
}
```

The algorithm constants are defined:
- `SMB3_COMPRESS_NONE` (0x0000)
- `SMB3_COMPRESS_LZNT1` (0x0001)
- `SMB3_COMPRESS_LZ77` (0x0002)
- `SMB3_COMPRESS_LZ77_HUFF` (0x0003)

`PATTERN_V1` (0x0004) is not defined.

### 7.3 What Would Be Needed

| Component | Description | Complexity |
|-----------|-------------|------------|
| Compression negotiate context response | Advertise supported algorithms | S |
| Compression transform header parsing | Parse `SMB2_COMPRESSION_TRANSFORM_HEADER` on incoming messages | M |
| Compression transform header generation | Generate compressed response messages | M |
| LZ77 compressor/decompressor | Kernel LZ77 implementation or adapter | M |
| LZNT1 compressor/decompressor | Kernel LZNT1 implementation | M |
| LZ77+Huffman compressor/decompressor | Combined algorithm | L |
| PATTERN_V1 | Pattern fill optimization | S |
| Chained compression | Multiple compression payloads per message | M |
| Per-message vs. per-connection policy | Configuration granularity | S |
| Minimum compression threshold | Avoid compressing small or incompressible data | S |

### 7.4 Recommendations

1. Start with LZ77 (simplest algorithm, good compression ratio).
2. Use the kernel's existing compression infrastructure (`crypto_comp`).
3. Implement as a runtime toggle per connection, negotiated during SMB 3.1.1 negotiate.
4. Add a minimum message size threshold to avoid overhead on small messages.

---

## 8. Encryption Enhancements

### 8.1 Overview

- **Name**: SMB3 Encryption
- **Protocol reference**: [MS-SMB2] Section 2.2.41 (SMB2_TRANSFORM_HEADER); Section 3.3.4.1.4
- **Current status**: **Complete** (including AES-256 variants)
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smb2pdu.h` lines 289-292 -- cipher defines (AES-128-CCM, AES-128-GCM, AES-256-CCM, AES-256-GCM)
  - `/home/ezechiel203/ksmbd/auth.c` lines 1086-1087, 1462-1479 -- AES-256 key size handling
  - `/home/ezechiel203/ksmbd/smb2ops.c` lines 292-295, 324-327 -- encryption capability advertisement
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 919-952 -- `decode_encrypt_ctxt()` with AES-256 support
- **Client demand**: All (security requirement)
- **Implementation complexity**: Already implemented
- **Performance impact**: ~5-15% CPU overhead for encrypted connections
- **Recommended approach**: Always-on capability, runtime toggle
- **Dependencies**: Kernel crypto subsystem (aead)
- **Priority**: P0 (already complete)

### 8.2 What Is Implemented

| Feature | Status | Details |
|---------|--------|---------|
| AES-128-CCM | **Complete** | Default for SMB 3.0/3.0.2 |
| AES-128-GCM | **Complete** | Preferred for SMB 3.1.1 |
| AES-256-CCM | **Complete** | Supported in negotiate, key derivation, transform |
| AES-256-GCM | **Complete** | Supported in negotiate, key derivation, transform |
| Per-session encryption | **Complete** | Keys generated per session |
| Encryption key generation | **Complete** | SMB 3.0 and SMB 3.1.1 key derivation |
| Transform header | **Complete** | Nonce generation, encrypt/decrypt |
| Encryption negotiation | **Complete** | SMB2_ENCRYPTION_CAPABILITIES negotiate context |
| Per-server encryption policy | **Complete** | `KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION`, `KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF` |

### 8.3 What Could Be Improved

| Enhancement | Complexity | Impact |
|-------------|------------|--------|
| **Per-share encryption policy** | S | `KSMBD_SHARE_FLAG_ENCRYPT` not defined; encryption is currently per-server only |
| **Hardware acceleration detection** | S | Rely on kernel crypto subsystem (already does this automatically for AES-NI) |
| **Encryption performance metrics** | S | Expose encryption cipher in debug/stats output |
| **Session binding encryption** | M | Ensure bound channels use correct encryption keys |

### 8.4 Recommendations

1. **P2**: Add per-share encryption policy flag to enforce encryption on sensitive shares.
2. No urgent action needed -- encryption support is comprehensive.

---

## 9. Quota Support

### 9.1 Overview

- **Name**: SMB Quota Queries and Management
- **Protocol reference**: [MS-SMB2] Section 2.2.37 (`SMB2_O_INFO_QUOTA`); [MS-FSCC] Section 2.4.33 (`FILE_QUOTA_INFORMATION`)
- **Current status**: **Missing**
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smb2pdu.h` line 1239 -- `SMB2_O_INFO_QUOTA` defined (0x04)
  - No handler in `smb2_query_info()` or `smb2_set_info()` for quota info type
- **Client demand**: Windows (quota management tools), macOS (Time Machine quota)
- **Implementation complexity**: M
- **Performance impact**: Negligible (quota queries are infrequent)
- **Recommended approach**: Runtime always-on (when underlying FS supports quotas)
- **Dependencies**: Linux quota subsystem (`quotactl`, `dquot` interface), filesystem quota support (ext4, XFS, btrfs)
- **Priority**: P2

### 9.2 Current State

`SMB2_O_INFO_QUOTA` (info type 0x04) is defined in the header but there is **no handler** in the `smb2_query_info()` or `smb2_set_info()` functions. Any quota query from a client would result in `STATUS_INVALID_PARAMETER` or `STATUS_NOT_IMPLEMENTED`.

The Time Machine quota field `time_machine_max_size` exists in `ksmbd_share_config` but is not enforced through the SMB quota mechanism.

### 9.3 What Would Be Needed

| Component | Description | Complexity |
|-----------|-------------|------------|
| SMB2_O_INFO_QUOTA query handler | Read user/group quotas via `quotactl()` | M |
| SMB2_O_INFO_QUOTA set handler | Set quotas (admin only) | M |
| FILE_QUOTA_INFORMATION encoding | Encode/decode quota info structures per [MS-FSCC] | M |
| SID-to-UID/GID mapping | Map Windows SIDs to Linux UIDs/GIDs for quota lookup | M |
| Per-share quota limits | Virtual quotas independent of filesystem quotas | L |
| FS_CONTROL_INFORMATION | `DefaultQuotaThreshold`, `DefaultQuotaLimit` in FS control info | S |
| Time Machine integration | Enforce `time_machine_max_size` via quota mechanism | M |

### 9.4 Recommendations

1. **P2**: Implement basic quota query support using Linux `quotactl()` for per-user quotas.
2. **P2**: Wire Time Machine max size into quota enforcement for Apple clients.
3. **P3**: Per-share virtual quotas (independent of filesystem quotas).

---

## 10. Extended Attribute / Stream Support

### 10.1 Overview

- **Name**: Named Streams and Extended Attributes
- **Protocol reference**: [MS-SMB2] Section 2.2.14, 2.2.39; [MS-FSCC] Section 2.1.3 (Stream Info), 2.4.15 (EA Info)
- **Current status**: **Mostly Complete**
- **Current code location**:
  - `/home/ezechiel203/ksmbd/xattr.h` -- DOS attributes, NTACL, stream xattr prefix definitions
  - `/home/ezechiel203/ksmbd/vfs.h` -- xattr VFS operations
  - `/home/ezechiel203/ksmbd/vfs.c` -- xattr get/set/list/remove implementations
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 2553-2600 -- `smb2_set_stream_name_xattr()`
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 3061-3692 -- stream handling in `smb2_open()`
- **Client demand**: Windows (all), macOS (FinderInfo, resource forks)
- **Implementation complexity**: Already largely implemented
- **Performance impact**: xattr operations add I/O per file open
- **Recommended approach**: Always-on with per-share flags
- **Dependencies**: xattr-capable filesystem (ext4, XFS, btrfs)
- **Priority**: P0 (already implemented)

### 10.2 What Is Implemented

| Feature | Status | Details |
|---------|--------|---------|
| DOS attributes via xattr | **Complete** | `XATTR_NAME_DOS_ATTRIBUTE` ("user.DOSATTRIB"), NDR-encoded for Samba compatibility |
| Named streams (DosStream) | **Complete** | `XATTR_NAME_STREAM` ("user.DosStream."), stored as xattrs |
| NTACL via xattr | **Complete** | `XATTR_NAME_SD` ("security.NTACL"), SHA-256 hash validation |
| Stream open/create/read/write | **Complete** | Full stream lifecycle in `smb2_open()` |
| Stream enumeration | **Complete** | `FILE_STREAM_INFORMATION` in query info |
| Per-share stream toggle | **Complete** | `KSMBD_SHARE_FLAG_STREAMS` |
| Per-share store DOS attrs | **Complete** | `KSMBD_SHARE_FLAG_STORE_DOS_ATTRS` |
| Per-share ACL xattr | **Complete** | `KSMBD_SHARE_FLAG_ACL_XATTR` |
| Creation time preservation | **Complete** | Stored in DOS attribute xattr (POSIX has no creation time) |

### 10.3 What Is Missing/Incomplete

| Missing Feature | Complexity | Impact |
|-----------------|------------|--------|
| **NTFS alternate data stream full semantics** | L | Windows apps that expect full NTFS ADS behavior may fail on edge cases (e.g., stream rename, stream delete) |
| **Maximum xattr size handling** | S | No enforcement of filesystem xattr size limits; large streams could fail silently |
| **AFP_AfpInfo stream interception** | M | macOS-specific; covered in Fruit section |
| **AFP_Resource stream interception** | L | macOS-specific; covered in Fruit section |
| **Stream notifications** | M | Change notifications for stream modifications not implemented |

### 10.4 Recommendations

Named stream support is the most complete optional feature in ksmbd. Minor improvements:
1. **P3**: Add maximum xattr size validation to prevent silent failures.
2. **P2**: The AFP stream interception (covered in Fruit section) is the main gap.

---

## 11. Reparse Points / Symlinks

### 11.1 Overview

- **Name**: Reparse Points and Symbolic Links
- **Protocol reference**: [MS-SMB2] Section 2.2.14.2.10 (Create Response for reparse); [MS-FSCC] Section 2.1.2 (Reparse Point)
- **Current status**: **Partial**
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smbfsctl.h` lines 47-49, 81-90 -- reparse point FSCTLs and reparse tags
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 742-757 -- `smb2_get_reparse_tag_special_file()`
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 9259-9277 -- `FSCTL_GET_REPARSE_POINT` handler
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 3305, 3335 -- `LOOKUP_NO_SYMLINKS` in path resolution
  - `/home/ezechiel203/ksmbd/smb2pdu.h` lines 1110-1115 -- `reparse_data_buffer` structure
- **Client demand**: Windows (symlinks, mount points), WSL (special files), macOS
- **Implementation complexity**: M
- **Performance impact**: Negligible
- **Recommended approach**: Always-on with per-share symlink follow toggle
- **Dependencies**: VFS symlink/special file support
- **Priority**: P2

### 11.2 What Is Implemented

| Feature | Status | Details |
|---------|--------|---------|
| Reparse tag for special files | **Complete** | LX_SYMLINK, AF_UNIX, LX_FIFO, LX_CHR, LX_BLK mapped from `i_mode` |
| FSCTL_GET_REPARSE_POINT | **Partial** | Returns reparse tag but empty `ReparseDataLength` (no actual data) |
| ATTR_REPARSE_POINT in dir listings | **Complete** | Set for special files in directory enumeration |
| Symlink path resolution | **Partial** | `LOOKUP_NO_SYMLINKS` prevents following; `KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS` for per-share override |
| SMB2 POSIX symlink info | **Complete** | `POSIX_TYPE_SYMLINK` in POSIX create context responses |

### 11.3 What Is Missing

| Missing Feature | Complexity | Impact |
|-----------------|------------|--------|
| **FSCTL_SET_REPARSE_POINT** | M | Cannot create reparse points/symlinks from Windows clients |
| **FSCTL_DELETE_REPARSE_POINT** | S | Cannot remove reparse points |
| **Reparse data in FSCTL_GET_REPARSE_POINT** | M | `ReparseDataLength` is always 0; Windows clients cannot read symlink targets |
| **IO_REPARSE_TAG_MOUNT_POINT** | L | Windows junction points -- would require kernel-side mount namespace awareness |
| **IO_REPARSE_TAG_SYMLINK** | M | Windows-native symlink format (absolute/relative) |
| **DFS junction handling** | M | `IO_REPARSE_TAG_DFS` for DFS namespace junctions |
| **ERROR_STOPPED_ON_SYMLINK response** | M | Proper symlink error response with substitute path and target |
| **WSL reparse point creation** | L | Allow WSL clients to create special files via reparse points |

### 11.4 Recommendations

1. **P2**: Implement `FSCTL_GET_REPARSE_POINT` with actual symlink target data for `IO_REPARSE_TAG_LX_SYMLINK`.
2. **P2**: Implement `FSCTL_SET_REPARSE_POINT` for symlink creation.
3. **P3**: Windows-native symlink format support.
4. **P3**: DFS junction handling (ties into DFS feature).

---

## 12. Server-Side Copy

### 12.1 Overview

- **Name**: Server-Side Copy (Copychunk / Duplicate Extents)
- **Protocol reference**: [MS-SMB2] Section 3.3.5.15.6 (FSCTL_SRV_COPYCHUNK); Section 3.3.5.15.8 (FSCTL_DUPLICATE_EXTENTS_TO_FILE)
- **Current status**: **Mostly Complete**
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 9142-9184 -- `FSCTL_REQUEST_RESUME_KEY`, `FSCTL_COPYCHUNK`, `FSCTL_COPYCHUNK_WRITE`
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 9279-9342 -- `FSCTL_DUPLICATE_EXTENTS_TO_FILE`
  - `/home/ezechiel203/ksmbd/vfs.c` lines 3579+ -- `ksmbd_vfs_copy_file_ranges()` using `vfs_copy_file_range()`
  - `/home/ezechiel203/ksmbd/smb2pdu.h` lines 1070-1094 -- copychunk structures
- **Client demand**: Windows (Explorer file copy), robocopy, backup tools
- **Implementation complexity**: Already largely implemented
- **Performance impact**: Significant positive (avoids network round-trips for large copies)
- **Recommended approach**: Always-on
- **Dependencies**: `copy_file_range` / `clone_file_range` kernel support
- **Priority**: P0 (already implemented)

### 12.2 What Is Implemented

| Feature | Status | Details |
|---------|--------|---------|
| FSCTL_REQUEST_RESUME_KEY | **Complete** | Returns resume key for source file |
| FSCTL_COPYCHUNK | **Complete** | Multi-chunk server-side copy |
| FSCTL_COPYCHUNK_WRITE | **Complete** | Same as COPYCHUNK but for write-opened files |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | **Complete** | Uses `vfs_clone_file_range()` with fallback to `vfs_copy_file_range()` |
| chunk validation | **Complete** | Validates chunk count, permissions |
| copy_file_range integration | **Complete** | Uses kernel `vfs_copy_file_range()` for efficient copy |

### 12.3 What Is Missing

| Missing Feature | Complexity | Impact |
|-----------------|------------|--------|
| **ODX (Offloaded Data Transfer)** | XL | `FSCTL_OFFLOAD_READ` / `FSCTL_OFFLOAD_WRITE` -- enterprise SAN feature |
| **FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX** | M | Extended version with `DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC` flag |
| **Fruit xattr copy on copychunk** | S | `ksmbd_vfs_copy_xattrs()` declared for Fruit but wiring may be incomplete |
| **Cross-share copy** | L | Currently limited to same-share copies |

### 12.4 Recommendations

1. **P3**: ODX is only relevant for SAN environments and can be deferred.
2. **P2**: Validate that xattr copy on copychunk works correctly for Fruit connections.

---

## 13. Sparse File Support

### 13.1 Overview

- **Name**: Sparse File Operations
- **Protocol reference**: [MS-SMB2] Section 3.3.5.15.14 (FSCTL_SET_SPARSE); [MS-FSCC] Section 2.3.62 (FSCTL_SET_ZERO_DATA), 2.3.33 (FSCTL_QUERY_ALLOCATED_RANGES)
- **Current status**: **Mostly Complete**
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 9186-9257 -- FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA, FSCTL_QUERY_ALLOCATED_RANGES
  - `/home/ezechiel203/ksmbd/vfs.h` lines 274-279 -- `ksmbd_vfs_zero_data()`, `ksmbd_vfs_fqar_lseek()`
  - `/home/ezechiel203/ksmbd/smb2pdu.h` lines 1096-1108 -- wire structures
- **Client demand**: Windows (database files, virtual disk images), backup tools
- **Implementation complexity**: Already implemented
- **Performance impact**: Positive (reduces disk usage for sparse files)
- **Recommended approach**: Always-on
- **Dependencies**: Filesystem support for `fallocate(FALLOC_FL_PUNCH_HOLE)` and `SEEK_HOLE`/`SEEK_DATA`
- **Priority**: P0 (already implemented)

### 13.2 What Is Implemented

| Feature | Status | Details |
|---------|--------|---------|
| FSCTL_SET_SPARSE | **Complete** | Sets/clears sparse attribute on file |
| FSCTL_SET_ZERO_DATA | **Complete** | Uses `ksmbd_vfs_zero_data()` for hole punching via `fallocate()` |
| FSCTL_QUERY_ALLOCATED_RANGES | **Complete** | Uses `SEEK_HOLE`/`SEEK_DATA` via `ksmbd_vfs_fqar_lseek()` |
| ATTR_SPARSE_FILE attribute | **Complete** | Tracked in file attributes |

### 13.3 What Could Be Improved

| Enhancement | Complexity | Impact |
|-------------|------------|--------|
| **Sparse attribute persistence** | S | Sparse flag should be stored in DOS attribute xattr for persistence across remounts |
| **Buffer overflow handling** | S | `FSCTL_QUERY_ALLOCATED_RANGES` returns `STATUS_BUFFER_OVERFLOW` when output buffer is too small -- correctly implemented |

### 13.4 Recommendations

Sparse file support is comprehensive. No urgent action needed.

---

## 14. File Leasing Enhancements

### 14.1 Overview

- **Name**: SMB2/3 File Leasing (Oplocks and Leases)
- **Protocol reference**: [MS-SMB2] Section 2.2.13.2.8 (Lease Create Context); Section 3.3.1.4 (Lease Tables)
- **Current status**: **Mostly Complete**
- **Current code location**:
  - `/home/ezechiel203/ksmbd/oplock.c` -- full lease implementation (~2100 lines)
  - `/home/ezechiel203/ksmbd/oplock.h` -- lease structures, API
  - `/home/ezechiel203/ksmbd/smb2pdu.h` lines 820-858 -- lease context wire structures (v1 and v2)
  - `/home/ezechiel203/ksmbd/smb2ops.c` lines 89, 116, 143 -- `create_lease_size` for v2
- **Client demand**: All (critical for performance)
- **Implementation complexity**: Already largely implemented
- **Performance impact**: Critical positive (client-side caching)
- **Recommended approach**: Always-on (configurable via `KSMBD_GLOBAL_FLAG_SMB2_LEASES`)
- **Dependencies**: None
- **Priority**: P0 (already implemented)

### 14.2 What Is Implemented

| Feature | Status | Details |
|---------|--------|---------|
| Lease V1 | **Complete** | Read/Write/Handle caching |
| Lease V2 | **Complete** | With parent lease key and epoch |
| Directory leasing | **Complete** | `SMB2_GLOBAL_CAP_DIRECTORY_LEASING` advertised for SMB 3.0+ |
| Parent lease break notification | **Complete** | `smb_send_parent_lease_break_noti()` |
| Lease break acknowledgment | **Complete** | Full break flow: Write->Read, ReadHandle->Read, Write->None, Read->None |
| Durable handles | **Complete** | `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` for SMB 3.0.2/3.1.1 |
| Lease tables per client GUID | **Complete** | `lease_table` with per-client lease lists |
| Lease epoch tracking | **Complete** | Epoch incremented on lease state changes |

### 14.3 What Is Missing/Could Be Improved

| Missing Feature | Complexity | Impact |
|-----------------|------------|--------|
| **Handle lease caching validation** | M | Handle (H) caching semantics not fully validated against MS-SMB2 spec |
| **Lease break timeout enforcement** | S | `OPLOCK_WAIT_TIME` (35s) may not match all client expectations |
| **Lazy parent lease break race condition** | M | Known race in `smb_lazy_parent_lease_break_close()` (use-after-free risk documented in prior reviews) |
| **Lease state machine completeness** | M | Some edge cases in lease upgrade/downgrade may not be fully covered |
| **Persistent handle reconnection** | M | Persistent handles across server restart -- requires on-disk state |

### 14.4 Recommendations

1. **P1**: Fix the race condition in `smb_lazy_parent_lease_break_close()` (security issue).
2. **P2**: Validate handle lease caching against the full MS-SMB2 state machine.
3. **P3**: Implement persistent handle state serialization for server restart survival.

---

## 15. Print Services

### 15.1 Overview

- **Name**: SMB Print Share Support
- **Protocol reference**: [MS-SMB2] Section 2.2.10 (`SMB2_SHARE_TYPE_PRINT`); [MS-RPRN] (Print System Remote Protocol)
- **Current status**: **Missing**
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smb2pdu.h` line 438 -- `SMB2_SHARE_TYPE_PRINT` (0x03) defined
  - No implementation of print share handling
- **Client demand**: Legacy Windows environments
- **Implementation complexity**: L
- **Performance impact**: None on core path
- **Recommended approach**: Not recommended for implementation
- **Dependencies**: CUPS or other print spooler, IPP
- **Priority**: P3 (low priority -- CUPS/IPP has largely replaced SMB printing)

### 15.2 Current State

There is **no implementation** of print shares. The share type constant is defined but never used. Modern print workflows use IPP (Internet Printing Protocol) via CUPS, making SMB print shares largely obsolete.

### 15.3 What Would Be Needed

| Component | Description | Complexity |
|-----------|-------------|------------|
| Print share type handling | Recognize `SMB2_SHARE_TYPE_PRINT` in tree connect | S |
| Spool file management | Accept print data, write to spool directory | M |
| Print job lifecycle | Create, queue, cancel, status query | L |
| MS-RPRN RPC service | Print system remote protocol over named pipes | XL |
| CUPS integration | Submit spool files to CUPS | M |

### 15.4 Recommendations

**Do not implement.** SMB print shares are a legacy feature that is being deprecated across the industry. Windows 11 has moved toward IPP everywhere. The effort would be better spent on other features.

---

## 16. Named Pipe Enhancements

### 16.1 Overview

- **Name**: Named Pipe / IPC$ Operations
- **Protocol reference**: [MS-SMB2] Section 3.3.5.15.3 (FSCTL_PIPE_TRANSCEIVE); [MS-CIFS] named pipe operations
- **Current status**: **Partial** (FSCTL_PIPE_TRANSCEIVE only)
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 8923-8966 -- `fsctl_pipe_transceive()`
  - `/home/ezechiel203/ksmbd/smbfsctl.h` lines 69-72 -- FSCTL_PIPE_PEEK, FSCTL_PIPE_TRANSCEIVE, FSCTL_PIPE_WAIT defines
  - `/home/ezechiel203/ksmbd/ksmbd_netlink.h` lines 410-425 -- RPC methods (srvsvc, wkssvc, samr, lsarpc)
  - `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc*.c` -- userspace RPC handlers
- **Client demand**: Windows (RPC services), management tools
- **Implementation complexity**: M
- **Performance impact**: Negligible (infrequent operations)
- **Recommended approach**: Always-on
- **Dependencies**: ksmbd.mountd for RPC processing
- **Priority**: P2

### 16.2 What Is Implemented

| Feature | Status | Details |
|---------|--------|---------|
| FSCTL_PIPE_TRANSCEIVE | **Complete** | Full transceive for RPC over IPC$ |
| IPC$ share type | **Complete** | `KSMBD_SHARE_FLAG_PIPE` |
| srvsvc RPC | **Complete** | NetShareEnum, NetShareGetInfo, etc. via ksmbd.mountd |
| wkssvc RPC | **Complete** | Workstation service queries |
| samr RPC | **Complete** | Security Account Manager queries |
| lsarpc RPC | **Complete** | Local Security Authority queries |
| RPC request/response via netlink | **Complete** | `KSMBD_EVENT_RPC_REQUEST/RESPONSE` |

### 16.3 What Is Missing

| Missing Feature | Complexity | Impact |
|-----------------|------------|--------|
| **FSCTL_PIPE_PEEK** | S | Peek at pipe data without consuming; used by some management tools |
| **FSCTL_PIPE_WAIT** | S | Wait for a named pipe instance to become available |
| **Pipe state management** | M | FILE_PIPE_INFORMATION, FILE_PIPE_LOCAL_INFORMATION query/set |
| **Multiple pipe instances** | M | Support for multiple clients waiting on the same pipe name |
| **Fragmented RPC** | M | Large RPC requests/responses that span multiple transceive calls |
| **Additional RPC services** | Varies | DFS RPC (netdfs), eventlog, svcctl -- each is a significant effort |

### 16.4 Recommendations

1. **P2**: Implement FSCTL_PIPE_PEEK and FSCTL_PIPE_WAIT for broader management tool compatibility.
2. **P3**: Pipe state queries (FILE_PIPE_INFORMATION) for diagnostic tools.
3. **P3**: Additional RPC services should be implemented in ksmbd.mountd userspace, not in the kernel.

---

## 17. Change Notification Enhancements

### 17.1 Overview

- **Name**: SMB2 Change Notification
- **Protocol reference**: [MS-SMB2] Section 2.2.35 (CHANGE_NOTIFY Request); Section 3.3.5.19
- **Current status**: **Stub** (returns `STATUS_NOT_IMPLEMENTED`)
- **Current code location**:
  - `/home/ezechiel203/ksmbd/smb2pdu.c` lines 9691-9709 -- `smb2_notify()` stub
  - `/home/ezechiel203/ksmbd/smb2pdu.h` lines 1117-1163 -- completion filter flags, notify structures, action constants
  - `/home/ezechiel203/ksmbd/smb2ops.c` line 219 -- `smb2_notify` in command table
- **Client demand**: Windows (Explorer auto-refresh), all (directory monitoring applications)
- **Implementation complexity**: L
- **Performance impact**: Potential concern at scale (many watched directories)
- **Recommended approach**: Runtime always-on with per-share toggle
- **Dependencies**: Linux `inotify` or `fsnotify` subsystem
- **Priority**: P1

### 17.2 Current State

The handler exists but returns `STATUS_NOT_IMPLEMENTED`:

```c
int smb2_notify(struct ksmbd_work *work)
{
    ...
    smb2_set_err_rsp(work);
    rsp->hdr.Status = STATUS_NOT_IMPLEMENTED;
    return -EOPNOTSUPP;
}
```

All required wire structures are defined:
- `smb2_notify_req` / `smb2_notify_rsp`
- All 12 `FILE_NOTIFY_CHANGE_*` completion filter flags
- All 9 `FILE_ACTION_*` action codes
- `SMB2_WATCH_TREE` flag for recursive monitoring

### 17.3 What Would Be Needed

| Component | Description | Complexity |
|-----------|-------------|------------|
| inotify/fsnotify integration | Register watches on directory file handles | M |
| Watch table management | Track pending notify requests per file handle | M |
| Completion filter mapping | Map SMB completion filters to inotify event masks | M |
| Recursive monitoring | `SMB2_WATCH_TREE` flag requires recursive inotify watches | L |
| Async response delivery | Notify responses are asynchronous (use existing async framework) | M |
| Buffer management | Accumulate change events until client reads or buffer overflows | M |
| Watch cleanup on close | Remove watches when file handle is closed | S |
| Scalability | Limit total watches per connection/server to prevent resource exhaustion | M |
| inotify watch limit | Respect `fs.inotify.max_user_watches` kernel sysctl | S |

### 17.4 Recommendations

1. **P1**: Implement non-recursive change notification using `inotify` or `fsnotify`.
2. **P1**: This is the most user-visible missing feature -- Windows Explorer does not auto-refresh without it.
3. **P2**: Add recursive monitoring (`SMB2_WATCH_TREE`) using recursive `inotify` watches.
4. **P2**: Implement per-connection watch limits to prevent resource exhaustion.

---

## 18. Priority Matrix

### P0 -- Already Complete / Production Ready

| # | Feature | Status | Code Quality |
|---|---------|--------|--------------|
| 1 | Encryption (AES-128/256, CCM/GCM) | Complete | High |
| 2 | Named Streams / Extended Attributes | Mostly Complete | High |
| 3 | Server-Side Copy (Copychunk) | Mostly Complete | High |
| 4 | Sparse File Operations | Mostly Complete | High |
| 5 | File Leasing (Oplocks V1/V2) | Mostly Complete | Medium (race conditions) |

### P1 -- Critical for Enterprise / User Experience

| # | Feature | Status | Effort | Client Impact |
|---|---------|--------|--------|---------------|
| 1 | **Change Notification** | Stub | L | Windows Explorer auto-refresh |
| 2 | **DFS (Standalone)** | Missing | L | Multi-server namespace |
| 3 | **VSS/Snapshots** | Missing | M | Windows Previous Versions |
| 4 | **Apple/Fruit: AFP stream interception** | Partial | M | macOS file metadata |
| 5 | **Lease race condition fix** | Bug | M | Kernel stability |

### P2 -- Important for Feature Completeness

| # | Feature | Status | Effort | Client Impact |
|---|---------|--------|--------|---------------|
| 1 | **Compression** | Missing | L | Network bandwidth |
| 2 | **Reparse Points (full)** | Partial | M | Symlink interop |
| 3 | **Quota Support** | Missing | M | Storage management |
| 4 | **RDMA enhancements** | Mostly Complete | M | RDMA performance |
| 5 | **Named Pipe enhancements** | Partial | S | Management tools |
| 6 | **Per-share encryption** | Missing | S | Security granularity |
| 7 | **Apple/Fruit: Time Machine** | Partial | M | macOS backups |

### P3 -- Nice to Have / Future

| # | Feature | Status | Effort | Client Impact |
|---|---------|--------|--------|---------------|
| 1 | Witness Protocol (MS-SWN) | Missing | XL | Cluster failover |
| 2 | ODX (Offloaded Data Transfer) | Missing | XL | SAN environments |
| 3 | Print Services | Missing | L | Legacy only |
| 4 | Domain-based DFS | Missing | XL | AD environments |
| 5 | Persistent handle serialization | Missing | L | Server restart survival |
| 6 | Spotlight / mdssvc | Missing | XL | macOS search |

---

## 19. Recommended Implementation Roadmap

### Phase 1: Core Enterprise Features (3-6 months)

**Goal**: Make ksmbd viable for enterprise file server deployment.

1. **Change Notification** (P1)
   - Integrate with `fsnotify` subsystem
   - Non-recursive first, then recursive
   - Critical for Windows Explorer usability

2. **DFS Standalone** (P1)
   - FSCTL_DFS_GET_REFERRALS handler
   - DFS path prefix stripping
   - Netlink extension for referral lookup
   - ksmbd.mountd configuration parsing

3. **VSS/Previous Versions** (P1)
   - FSCTL_SRV_ENUMERATE_SNAPSHOTS handler
   - @GMT token path resolution
   - btrfs snapshot backend (first)

4. **Lease race condition fix** (P1)
   - Fix use-after-free in `smb_lazy_parent_lease_break_close()`
   - Proper reference counting for oplock info

### Phase 2: macOS Compatibility (3-6 months)

**Goal**: Full macOS client support comparable to Samba's vfs_fruit.

1. **AFP stream interception** (P1)
   - AFP_AfpInfo read/write via named stream
   - AFP_Resource read/write via named stream
   - FinderInfo xattr mapping

2. **Time Machine support** (P2)
   - Quota enforcement via `time_machine_max_size`
   - Bundle validation
   - Lock steal support

3. **ReadDirAttr enrichment** (P2)
   - Resource fork size
   - Maximum access rights
   - Per-share flags already defined

### Phase 3: Performance and Security (3-6 months)

**Goal**: Optimize performance and close security gaps.

1. **Compression** (P2)
   - LZ77 algorithm first
   - Negotiate context response
   - Transform header processing

2. **Per-share encryption** (P2)
   - New share flag for mandatory encryption
   - Tree connect enforcement

3. **Quota support** (P2)
   - Linux quotactl integration
   - SMB2_O_INFO_QUOTA handler
   - SID-to-UID mapping

4. **Reparse points** (P2)
   - Full FSCTL_GET_REPARSE_POINT with target data
   - FSCTL_SET_REPARSE_POINT for symlink creation

### Phase 4: Clustering and Advanced Features (6-12 months)

**Goal**: Enterprise clustering and advanced scenarios.

1. **Witness Protocol** (P3)
2. **Persistent handle serialization** (P3)
3. **ODX** (P3)
4. **Domain-based DFS** (P3)

---

## Appendix A: File Reference Index

| File | Module Features |
|------|----------------|
| `/home/ezechiel203/ksmbd/smb2fruit.h` | Apple/Fruit extension structures and declarations |
| `/home/ezechiel203/ksmbd/smb2fruit.c` | Apple/Fruit extension implementation |
| `/home/ezechiel203/ksmbd/smb2pdu.c` | IOCTL handlers (copy, sparse, reparse, pipe), notify stub, Fruit negotiation |
| `/home/ezechiel203/ksmbd/smb2pdu.h` | Wire structures for all features |
| `/home/ezechiel203/ksmbd/smb2ops.c` | Capability advertisement per protocol version |
| `/home/ezechiel203/ksmbd/smbfsctl.h` | FSCTL code definitions |
| `/home/ezechiel203/ksmbd/transport_rdma.c` | RDMA/SMB Direct full implementation |
| `/home/ezechiel203/ksmbd/transport_rdma.h` | RDMA wire structures |
| `/home/ezechiel203/ksmbd/oplock.c` | Lease V1/V2, directory lease, parent lease break |
| `/home/ezechiel203/ksmbd/oplock.h` | Lease structures and API |
| `/home/ezechiel203/ksmbd/vfs.c` | Copy file ranges, zero data, allocated ranges, xattr ops |
| `/home/ezechiel203/ksmbd/vfs.h` | VFS operation declarations |
| `/home/ezechiel203/ksmbd/xattr.h` | DOS attributes, NTACL, stream xattr definitions |
| `/home/ezechiel203/ksmbd/connection.h` | Fruit state, compression algorithm, cipher type fields |
| `/home/ezechiel203/ksmbd/server.h` | Server config including fruit_model |
| `/home/ezechiel203/ksmbd/ksmbd_netlink.h` | Global flags, share flags, startup config |
| `/home/ezechiel203/ksmbd/auth.c` | Encryption key generation (AES-128/256) |
| `/home/ezechiel203/ksmbd/mgmt/share_config.h` | Share configuration with time_machine_max_size |
| `/home/ezechiel203/ksmbd/Makefile` | Compile-time toggles (CONFIG_KSMBD_FRUIT, CONFIG_SMB_SERVER_SMBDIRECT) |

## Appendix B: Compile-Time Feature Toggles

| Toggle | Default | Controls |
|--------|---------|----------|
| `CONFIG_KSMBD_FRUIT` | `n` | Apple/Fruit SMB extensions (smb2fruit.o) |
| `CONFIG_SMB_SERVER_SMBDIRECT` | (kernel config) | RDMA/SMB Direct transport (transport_rdma.o) |
| `CONFIG_SMB_INSECURE_SERVER` | (kernel config) | SMB1 protocol support, legacy SMB2.0 |

## Appendix C: Runtime Feature Toggles (Global Flags)

| Flag | Bit | Controls |
|------|-----|----------|
| `KSMBD_GLOBAL_FLAG_SMB2_LEASES` | BIT(0) | Lease/oplock support |
| `KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION` | BIT(1) | Force encryption on |
| `KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL` | BIT(2) | Multi-channel support |
| `KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF` | BIT(3) | Force encryption off |
| `KSMBD_GLOBAL_FLAG_DURABLE_HANDLE` | BIT(4) | Persistent handles |
| `KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS` | BIT(5) | Enable AAPL create context |
| `KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID` | BIT(6) | Zero UniqueId in dir listings for macOS |
| `KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES` | BIT(7) | NFS ACE support for Apple |
| `KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE` | BIT(8) | Server-side copy with xattr preservation |

## Appendix D: Runtime Feature Toggles (Share Flags)

| Flag | Bit | Controls |
|------|-----|----------|
| `KSMBD_SHARE_FLAG_STREAMS` | BIT(11) | Named stream support |
| `KSMBD_SHARE_FLAG_STORE_DOS_ATTRS` | BIT(6) | DOS attribute xattr storage |
| `KSMBD_SHARE_FLAG_ACL_XATTR` | BIT(13) | NTACL via xattr |
| `KSMBD_SHARE_FLAG_OPLOCKS` | BIT(7) | Oplock support |
| `KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS` | BIT(12) | Follow symlinks in share |
| `KSMBD_SHARE_FLAG_CROSSMNT` | BIT(15) | Cross-mount support |
| `KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY` | BIT(16) | CA share flag |
| `KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE` | BIT(17) | Time Machine backup support |
| `KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO` | BIT(18) | FinderInfo enrichment in ReadDirAttr |
| `KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE` | BIT(19) | Resource fork size in ReadDirAttr |
| `KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS` | BIT(20) | MaxAccess in ReadDirAttr |

---

*End of report.*
