# MS-SMB2 Protocol Compliance Audit: ksmbd

## Executive Summary

This report is an exhaustive protocol compliance audit of the ksmbd in-kernel
SMB3 server against the MS-SMB2 specification and related protocol documents
(MS-FSCC, MS-DTYP, MS-NLMP, MS-SPNG, etc.). Every source file in the
repository has been analyzed to assess implementation completeness.

**Overall assessment**: ksmbd implements a solid foundation covering the most
common SMB2/3 operations needed for basic file sharing with Windows, macOS,
and Linux clients. However, significant gaps exist in advanced features,
several negotiate contexts, many FSCTLs, and multiple information classes.

### Summary Counts

| Category | Complete | Partial | Stub | Missing |
|----------|----------|---------|------|---------|
| SMB2 Commands (19) | 16 | 2 | 1 | 0 |
| Negotiate Contexts (8) | 4 | 2 | 1 | 1 |
| FSCTLs (~40 defined) | 10 | 2 | 2 | ~26 |
| File Info Classes (Query, 38 defined) | 17 | 0 | 0 | 21 |
| File Info Classes (Set, ~12 key) | 9 | 0 | 0 | 3 |
| FS Info Classes (Query, 11 defined) | 8 | 0 | 0 | 3 |
| Security Info Types | 3 | 0 | 0 | 2 |
| Create Contexts (14 spec) | 10 | 1 | 0 | 3 |

---

## 1. Negotiation (MS-SMB2 Section 3.3.5.3)

### 1.1 Dialect Support

| Dialect | Protocol ID | Status | File:Line | Notes |
|---------|------------|--------|-----------|-------|
| SMB 2.0.2 | 0x0202 | **Complete** | `smb_common.c:64-70` | Supported |
| SMB 2.1 | 0x0210 | **Complete** | `smb_common.c:71-76` | Supported |
| SMB 3.0 | 0x0300 | **Complete** | `smb_common.c:77-82` | Supported |
| SMB 3.0.2 | 0x0302 | **Complete** | `smb_common.c:83-88` | Supported |
| SMB 3.1.1 | 0x0311 | **Complete** | `smb_common.c:89-94` | Supported |
| SMB 1.0 (NT LM 0.12) | -- | **Conditional** | `smb_common.c:41-55` | Only with `CONFIG_SMB_INSECURE_SERVER` |

**Assessment**: All current SMB2/3 dialects are supported. SMB 1.0 is correctly
gated behind a compile-time flag. Multi-protocol negotiation (SMB1 -> SMB2 upgrade)
is implemented via `ksmbd_smb_negotiate_common()`.

### 1.2 Negotiate Contexts (SMB 3.1.1)

| Context | Type ID | Status | File:Line | Notes |
|---------|---------|--------|-----------|-------|
| PREAUTH_INTEGRITY_CAPABILITIES | 0x0001 | **Complete** | `smb2pdu.c:789-798, 900-917` | SHA-512 only (correct per spec) |
| ENCRYPTION_CAPABILITIES | 0x0002 | **Complete** | `smb2pdu.c:801-809, 919-955` | All 4 ciphers supported |
| COMPRESSION_CAPABILITIES | 0x0003 | **Stub** | `smb2pdu.c:977-981` | Decoded but always sets `SMB3_COMPRESS_NONE` |
| NETNAME_NEGOTIATE_CONTEXT_ID | 0x0005 | **Partial** | `smb2pdu.c:1083-1085` | Logged but value is not stored or validated |
| SIGNING_CAPABILITIES | 0x0008 | **Partial** | `smb2pdu.c:983-1016, 811-821` | HMAC-SHA256 and AES-CMAC only; AES-GMAC defined (`smb2pdu.h:336`) but NOT negotiated or handled |
| POSIX_EXTENSIONS | 0x0100 | **Complete** | `smb2pdu.c:823-844, 1086-1089` | Linux POSIX extension (non-MS) |
| TRANSPORT_CAPABILITIES | 0x0006 | **Missing** | -- | Not defined or handled at all |
| RDMA_TRANSFORM_CAPABILITIES | 0x0007 | **Missing** | -- | Not defined or handled at all |

**Gaps**:

- **Feature**: SMB2_COMPRESSION_CAPABILITIES (MS-SMB2 2.2.3.1.3)
  - **Status**: Stub
  - **Current code**: `smb2pdu.c:977-981` -- `decode_compress_ctxt()` always sets `SMB3_COMPRESS_NONE`
  - **Impact**: No compression support; clients negotiate but always fall back. No performance benefit from compression.
  - **Effort**: XL (requires full compression/decompression framework, chained compression transforms)
  - **Priority**: P2 (performance optimization, not required for interop)

- **Feature**: SMB2_NETNAME_NEGOTIATE_CONTEXT_ID (MS-SMB2 2.2.3.1.4)
  - **Status**: Partial
  - **Current code**: `smb2pdu.c:1083-1085` -- logged but server name not validated
  - **Impact**: Minor -- spec says server MUST accept but MAY use for connection routing. Low interop risk.
  - **Effort**: S
  - **Priority**: P3

- **Feature**: SIGNING_ALG_AES_GMAC (MS-SMB2 2.2.3.1.7)
  - **Status**: Missing (constant defined but never negotiated)
  - **Current code**: `smb2pdu.h:336` defines the constant; `smb2pdu.c:1005-1007` only accepts HMAC_SHA256 or AES_CMAC
  - **Impact**: Windows 11 prefers AES-GMAC for performance. Clients will fall back to AES-CMAC.
  - **Effort**: M (need GMAC implementation in kernel crypto)
  - **Priority**: P2

- **Feature**: TRANSPORT_CAPABILITIES context (MS-SMB2 2.2.3.1.5)
  - **Status**: Missing
  - **Impact**: Required for SMB over QUIC. Not critical for TCP/RDMA.
  - **Effort**: M
  - **Priority**: P3

- **Feature**: RDMA_TRANSFORM_CAPABILITIES context (MS-SMB2 2.2.3.1.6)
  - **Status**: Missing
  - **Impact**: Required for RDMA transform negotiation (encryption over RDMA). RDMA works without encryption.
  - **Effort**: L
  - **Priority**: P2 (for RDMA + encryption scenarios)

---

## 2. Session Management (MS-SMB2 Section 3.3.5.5)

### 2.1 Authentication Methods

| Method | Status | File:Line | Notes |
|--------|--------|-----------|-------|
| NTLMv2 (NTLMSSP) | **Complete** | `smb2pdu.c:1413-1648`, `auth.c` | Full NTLMSSP NEGOTIATE/CHALLENGE/AUTH |
| Kerberos (SPNEGO) | **Complete** | `smb2pdu.c:1650-1752` | Via ksmbd.mountd userspace helper |
| NTLMv1 | **Missing** | -- | Deliberately not supported (insecure) |
| Guest authentication | **Complete** | `smb2pdu.c:1879-1895` | Guest session flags set correctly |
| Anonymous (null session) | **Partial** | `smb2pdu.c:1883` | `SMB2_SESSION_FLAG_IS_NULL_LE` defined but not clearly distinguished from guest in all paths |

### 2.2 Session Features

| Feature | Status | File:Line | Notes |
|---------|--------|-----------|-------|
| Session binding (multi-channel) | **Complete** | `smb2pdu.c:1791-1838` | SMB2_SESSION_REQ_FLAG_BINDING checked, channel registered |
| Previous session destruction | **Complete** | `smb2pdu.c:1683-1685, 1579-1581` | `destroy_previous_session()` called in both NTLM and Kerberos paths |
| Session key derivation (SMB 3.x) | **Complete** | `smb2ops.c` via `generate_signingkey` / `generate_encryptionkey` ops | Correct for SMB 3.0, 3.0.2, 3.1.1 |
| Reauthentication | **Complete** | `smb2pdu.c:1694-1698` | Checks `SMB2_SESSION_VALID` state |
| Session encryption negotiation | **Complete** | `smb2pdu.c:1593-1613` | Generates encryption key, sets `SMB2_SESSION_FLAG_ENCRYPT_DATA_LE` |

**Gaps**:

- **Feature**: Anonymous vs. Guest distinction (MS-SMB2 3.3.5.5.3)
  - **Status**: Partial
  - **Impact**: Some Windows security policies differentiate between guest and anonymous. Minor interop risk.
  - **Effort**: S
  - **Priority**: P3

---

## 3. Tree Connect (MS-SMB2 Section 3.3.5.7)

### 3.1 Share Types

| Share Type | Status | File:Line | Notes |
|------------|--------|-----------|-------|
| Disk (0x01) | **Complete** | `smb2pdu.c:2091` | Full disk share support |
| Pipe/IPC (0x02) | **Complete** | `smb2pdu.c:2082-2089` | IPC$ share, RPC pipe support |
| Print (0x03) | **Missing** | `smb2pdu.h:438` | Constant defined, never used in tree connect |

### 3.2 Share Capabilities

| Capability | Status | Notes |
|------------|--------|-------|
| SMB2_SHARE_CAP_DFS | **Missing** | DFS not implemented |
| SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY | **Partial** | `smb2pdu.c:2114-2117` -- Set only when durable handles + CA flag enabled |
| SMB2_SHARE_CAP_SCALEOUT | **Missing** | No cluster/scale-out support |
| SMB2_SHARE_CAP_CLUSTER | **Missing** | No cluster support |
| SMB2_SHARE_CAP_ASYMMETRIC | **Missing** | No asymmetric share support |
| SMB2_SHARE_CAP_REDIRECT_TO_OWNER | **Missing** | No redirect support |

**Gaps**:

- **Feature**: Print share type (MS-SMB2 2.2.10)
  - **Status**: Missing
  - **Current code**: `smb2pdu.h:438` -- constant defined but share type never assigned
  - **Impact**: Cannot share printers via SMB
  - **Effort**: L (requires print spooler integration)
  - **Priority**: P3 (rare use case for in-kernel server)

- **Feature**: DFS capability on shares (MS-SMB2 2.2.10)
  - **Status**: Missing
  - **Impact**: Cannot use Distributed File System namespaces
  - **Effort**: XL
  - **Priority**: P1 (important for enterprise deployments)

---

## 4. SMB2 Command Implementation Assessment

### 4.1 NEGOTIATE (0x0000) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c:1112-1318` (`smb2_handle_negotiate`)
- Multi-protocol negotiation: Implemented (SMB1 -> SMB2 upgrade path)
- Negotiate context processing: Implemented for 3.1.1
- Security mode, capabilities, GUID handling: Correct

### 4.2 SESSION_SETUP (0x0001) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c:1754-2027` (`smb2_sess_setup`)
- NTLMSSP and Kerberos/SPNEGO authentication
- Session binding for multi-channel
- Previous session ID handling

### 4.3 LOGOFF (0x0002) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c` (via `smb2_session_logoff`)

### 4.4 TREE_CONNECT (0x0003) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c:2035-2166` (`smb2_tree_connect`)

### 4.5 TREE_DISCONNECT (0x0004) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c` (via `smb2_tree_disconnect`)

### 4.6 CREATE (0x0005) -- Complete (with gaps in create contexts)

- **Status**: **Complete** (core), **Partial** (some create contexts)
- **File**: `smb2pdu.c` (`smb2_open`, ~line 3028 onwards)

#### Create Dispositions

| Disposition | Status |
|-------------|--------|
| FILE_SUPERSEDE | **Complete** |
| FILE_OPEN | **Complete** |
| FILE_CREATE | **Complete** |
| FILE_OPEN_IF | **Complete** |
| FILE_OVERWRITE | **Complete** |
| FILE_OVERWRITE_IF | **Complete** |

All six dispositions are handled in `smb2_create_open_flags()` at line 2178.

#### Create Contexts

| Context | Tag | Status | File:Line | Notes |
|---------|-----|--------|-----------|-------|
| Extended Attributes | ExtA | **Complete** | `smb2pdu.c:3258-3275` | EA buffer parsed and applied |
| Security Descriptor | SecD | **Complete** | `smb2pdu.c:2760` | SD applied at creation |
| Durable Handle Request V1 | DHnQ | **Complete** | `smb2pdu.c:2828,2982-3003` | Via `parse_durable_handle_context` |
| Durable Handle Reconnect V1 | DHnC | **Complete** | `smb2pdu.c:2826,2913-2951` | Client GUID validation included |
| Durable Handle Request V2 | DH2Q | **Complete** | `smb2pdu.c:2827,2954-3003` | Timeout and persistent flag supported |
| Durable Handle Reconnect V2 | DH2C | **Complete** | `smb2pdu.c:2825,2864-2912` | Create GUID and client GUID validated |
| Allocation Size | AlSi | **Complete** | `smb2pdu.c:3768` | Pre-allocation size set |
| Query Maximal Access | MxAc | **Complete** | `smb2pdu.c:3277-3286` | Maximal access returned in response |
| Timewarp (VSS) | TWrp | **Stub** | `smb2pdu.c:3288-3297` | Recognized but returns `-EBADF` (no VSS snapshots) |
| Query on Disk ID | QFid | **Complete** | `smb2pdu.c:3796` | Disk ID returned |
| Request Lease V1/V2 | RqLs | **Complete** | `oplock.c` | Both V1 and V2 lease contexts handled |
| POSIX Create Context | (GUID) | **Complete** | `smb2pdu.c:3087` | POSIX mode setting |
| App Instance ID | (GUID) | **Missing** | -- | Not searched for or handled in `smb2_open` |
| App Instance Version | (GUID) | **Missing** | -- | Not searched for or handled |
| SVHDX Open Device Context | -- | **Missing** | -- | Shared virtual hard disk; enterprise feature |
| Apple AAPL | AAPL | **Complete** | `smb2pdu.c:3808` | Fruit/macOS extension (conditional `CONFIG_KSMBD_FRUIT`) |

**Gaps**:

- **Feature**: SMB2_CREATE_APP_INSTANCE_ID (MS-SMB2 2.2.13.2.13)
  - **Status**: Missing
  - **Current code**: Struct defined in `smb2pdu.h:670-675` but never used in `smb2_open`
  - **Impact**: Clustered/Hyper-V VMs cannot do proper failover of SMB handles
  - **Effort**: M
  - **Priority**: P2 (important for HA/VM scenarios)

- **Feature**: SMB2_CREATE_APP_INSTANCE_VERSION (MS-SMB2 2.2.13.2.14)
  - **Status**: Missing
  - **Current code**: Struct defined in `smb2pdu.h:677-684` but never used
  - **Impact**: Needed alongside App Instance ID for version-aware failover
  - **Effort**: M
  - **Priority**: P2

- **Feature**: TIMEWARP / VSS snapshots (MS-SMB2 2.2.13.2.7)
  - **Status**: Stub (returns error)
  - **Current code**: `smb2pdu.c:3288-3297` -- `rc = -EBADF`
  - **Impact**: Cannot access Previous Versions from Windows Explorer
  - **Effort**: L (needs VFS snapshot integration, e.g., btrfs snapshots, LVM snapshots)
  - **Priority**: P1 (commonly requested enterprise feature)

### 4.7 CLOSE (0x0006) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c` (`smb2_close`)
- SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB: Supported (`smb2pdu.h:861`, `smb2pdu.c` close handler fills timestamps/attrs when flag set)

### 4.8 FLUSH (0x0007) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c` (`smb2_flush`)

### 4.9 READ (0x0008) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c:7523` (`smb2_read`)
- RDMA channel read: Implemented (`smb2_read_rdma_channel` at line 7501)
- Pipe read: Implemented (`smb2_read_pipe` at line 7412)

**Gaps**:
- **Feature**: Unbuffered read (SMB2_READFLAG_READ_UNBUFFERED)
  - **Status**: Missing
  - **Impact**: No direct I/O hint from client
  - **Effort**: S
  - **Priority**: P3

- **Feature**: Compressed read response
  - **Status**: Missing (compression not implemented)
  - **Effort**: XL
  - **Priority**: P2

### 4.10 WRITE (0x0009) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c` (`smb2_write`)
- Write-through flag: `SMB2_WRITEFLAG_WRITE_THROUGH` defined in `smb2pdu.h:939`
- RDMA channel write: Implemented

**Gaps**:
- **Feature**: Unbuffered write (SMB2_WRITEFLAG_WRITE_UNBUFFERED)
  - **Status**: Missing
  - **Impact**: No direct I/O hint from client
  - **Effort**: S
  - **Priority**: P3

### 4.11 LOCK (0x000A) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c` (`smb2_lock`, extensive implementation ~8200-8573)
- Byte-range locks: Shared, exclusive, unlock all implemented
- Lock sequencing: Basic implementation
- Asynchronous lock wait with cancel support: Implemented
- Lock rollback on failure: Implemented

**Gaps**:
- **Feature**: Lock sequence verification (MS-SMB2 3.3.5.14, SMB 3.x)
  - **Status**: Partial
  - **Impact**: Lock sequence numbers for resilient/persistent handles not fully validated
  - **Effort**: M
  - **Priority**: P2

### 4.12 IOCTL/FSCTL (0x000B) -- Partial

- **Status**: **Partial** (see Section 8 for full FSCTL analysis)
- **File**: `smb2pdu.c:9033-9378` (`smb2_ioctl`)
- Only `SMB2_0_IOCTL_IS_FSCTL` flag supported; non-FSCTL IOCTLs return `EOPNOTSUPP`

### 4.13 CANCEL (0x000C) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c` (`smb2_cancel`)
- Cancels async operations (used with LOCK, CHANGE_NOTIFY)

### 4.14 ECHO (0x000D) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c` (`smb2_echo`)

### 4.15 QUERY_DIRECTORY (0x000E) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c` (`smb2_query_dir`)
- See Section 9 for information level completeness

**Query Directory Information Levels**:

| Level | Status | Notes |
|-------|--------|-------|
| FILE_DIRECTORY_INFORMATION (1) | **Complete** | |
| FILE_FULL_DIRECTORY_INFORMATION (2) | **Complete** | |
| FILE_BOTH_DIRECTORY_INFORMATION (3) | **Complete** | |
| FILE_NAMES_INFORMATION (12) | **Complete** | |
| FILEID_BOTH_DIRECTORY_INFORMATION (37) | **Complete** | |
| FILEID_FULL_DIRECTORY_INFORMATION (38) | **Complete** | |
| SMB_FIND_FILE_POSIX_INFO (0x64) | **Complete** | POSIX extension |

### 4.16 CHANGE_NOTIFY (0x000F) -- Stub

- **Status**: **Stub** (returns STATUS_NOT_IMPLEMENTED)
- **File**: `smb2pdu.c:9691-9709` (`smb2_notify`)
- **Current code**: Always returns `STATUS_NOT_IMPLEMENTED`

**Gap**:
- **Feature**: CHANGE_NOTIFY (MS-SMB2 3.3.5.19)
  - **Status**: Stub
  - **Current code**: `smb2pdu.c:9706-9708` -- hardcoded `STATUS_NOT_IMPLEMENTED`
  - **Impact**: **P0 -- Breaks basic interop.** Windows Explorer does not auto-refresh directory listings. Many applications (Office, IDEs) rely on change notifications to detect file modifications. This is arguably the most impactful missing feature.
  - **Effort**: L (requires inotify/fanotify backend, async notification queue, completion filter support)
  - **Priority**: P0

  All completion filter flags are defined in `smb2pdu.h:1118-1131`:
  - FILE_NOTIFY_CHANGE_FILE_NAME (0x01) -- Missing
  - FILE_NOTIFY_CHANGE_DIR_NAME (0x02) -- Missing
  - FILE_NOTIFY_CHANGE_ATTRIBUTES (0x04) -- Missing
  - FILE_NOTIFY_CHANGE_SIZE (0x08) -- Missing
  - FILE_NOTIFY_CHANGE_LAST_WRITE (0x10) -- Missing
  - FILE_NOTIFY_CHANGE_LAST_ACCESS (0x20) -- Missing
  - FILE_NOTIFY_CHANGE_CREATION (0x40) -- Missing
  - FILE_NOTIFY_CHANGE_EA (0x80) -- Missing
  - FILE_NOTIFY_CHANGE_SECURITY (0x100) -- Missing
  - FILE_NOTIFY_CHANGE_STREAM_NAME (0x200) -- Missing
  - FILE_NOTIFY_CHANGE_STREAM_SIZE (0x400) -- Missing
  - FILE_NOTIFY_CHANGE_STREAM_WRITE (0x800) -- Missing

### 4.17 QUERY_INFO (0x0010) -- Complete (with info class gaps)

- **Status**: **Complete** (framework), see Section 9 for info class details
- **File**: `smb2pdu.c:6304-6366` (`smb2_query_info`)
- Supports: `SMB2_O_INFO_FILE`, `SMB2_O_INFO_FILESYSTEM`, `SMB2_O_INFO_SECURITY`
- Missing: `SMB2_O_INFO_QUOTA` (returns EOPNOTSUPP)

### 4.18 SET_INFO (0x0011) -- Complete (with info class gaps)

- **Status**: **Complete** (framework), see Section 9
- **File**: `smb2pdu.c:7304-7404` (`smb2_set_info`)
- Supports: `SMB2_O_INFO_FILE`, `SMB2_O_INFO_SECURITY`
- Missing: `SMB2_O_INFO_FILESYSTEM` (Set), `SMB2_O_INFO_QUOTA`

### 4.19 OPLOCK_BREAK (0x0012) -- Complete

- **Status**: **Complete**
- **File**: `smb2pdu.c:9380` (`smb2_oplock_break`), `oplock.c`
- Oplock break acknowledgment for both oplock and lease modes

---

## 5. Oplock and Lease Model

### 5.1 Oplock Levels

| Level | Status | Notes |
|-------|--------|-------|
| None (0x00) | **Complete** | |
| Level II (0x01) | **Complete** | Read caching |
| Exclusive (0x08) | **Complete** | |
| Batch (0x09) | **Complete** | |
| Lease (0xFF) | **Complete** | Delegates to lease model |

### 5.2 Lease Model

| State | Status | Notes |
|-------|--------|-------|
| Read (R) | **Complete** | |
| Read-Write (RW) | **Complete** | |
| Read-Write-Handle (RWH) | **Complete** | |
| Lease break notification | **Complete** | `oplock.c` sends lease breaks with correct state transitions |
| Lease V1 | **Complete** | `create_lease` struct at `smb2pdu.h:847` |
| Lease V2 (directory leases) | **Complete** | `create_lease_v2` struct at `smb2pdu.h:853`; `lease->is_dir` tracked at `oplock.c:113` |
| Lease break acknowledgment | **Complete** | `smb2_lease_break_ack` handler in `smb2pdu.c` |
| Epoch tracking | **Complete** | `lease_context_v2` includes Epoch field |
| Parent lease key | **Complete** | `ParentLeaseKey` in V2 context |

### 5.3 Durable Handles

| Feature | Status | File:Line | Notes |
|---------|--------|-----------|-------|
| Durable Handle V1 (DHnQ/DHnC) | **Complete** | `smb2pdu.c:2913-2951, 2982-3003` | Create and reconnect |
| Durable Handle V2 (DH2Q/DH2C) | **Complete** | `smb2pdu.c:2864-2912, 2954-2981` | With Create GUID validation |
| Persistent handles | **Partial** | `smb2pdu.c:3890-3893` | `fp->is_persistent` set when CA flag present, but no actual persistence across server restarts |
| Resilient handles | **Missing** | -- | No FSCTL_LMR_REQUEST_RESILIENCY |
| Durable timeout | **Complete** | `DURABLE_HANDLE_MAX_TIMEOUT` = 300000ms |
| Client GUID validation | **Complete** | `smb2pdu.c:2897-2903, 2939-2944` | Prevents durable handle theft |

**Gaps**:

- **Feature**: Persistent handles across server restart (MS-SMB2 3.3.5.9.7)
  - **Status**: Partial (in-memory only)
  - **Impact**: Handles lost on server restart even with persistent flag
  - **Effort**: XL (requires persistent storage of handle state)
  - **Priority**: P2

- **Feature**: Resilient handles (MS-SMB2 3.3.5.15.11)
  - **Status**: Missing
  - **Impact**: Hyper-V and clustered workloads may not reconnect properly
  - **Effort**: L
  - **Priority**: P2

---

## 6. Security Features

### 6.1 Signing

| Algorithm | Status | File:Line | Notes |
|-----------|--------|-----------|-------|
| HMAC-SHA256 (SMB 2.x) | **Complete** | `smb2pdu.c:9740-9776` | `smb2_check_sign_req` / `smb2_set_sign_rsp` |
| AES-128-CMAC (SMB 3.x) | **Complete** | `smb2pdu.c:9810+` | `smb3_check_sign_req` / `smb3_set_sign_rsp` |
| AES-128-GMAC (SMB 3.1.1) | **Missing** | -- | Constant defined at `smb2pdu.h:336` but never negotiated or implemented |

**Gap**:
- **Feature**: AES-GMAC signing (MS-SMB2 3.1.4.1)
  - **Status**: Missing
  - **Impact**: Windows 11 prefers GMAC; falls back to CMAC. Performance penalty.
  - **Effort**: M
  - **Priority**: P2

### 6.2 Encryption

| Cipher | Status | Notes |
|--------|--------|-------|
| AES-128-CCM | **Complete** | Negotiated and used |
| AES-128-GCM | **Complete** | Negotiated and used |
| AES-256-CCM | **Complete** | Negotiated and used |
| AES-256-GCM | **Complete** | Negotiated and used |
| Per-session encryption | **Complete** | `sess->enc` flag |
| Per-share encryption | **Complete** | `SMB2_SESSION_FLAG_ENCRYPT_DATA_LE` |
| Transform header | **Complete** | `smb2_transform_hdr` at `smb2pdu.h:164` |

### 6.3 Pre-authentication Integrity

| Feature | Status | Notes |
|---------|--------|-------|
| SHA-512 hash | **Complete** | `preauth_integrity_info` in `smb2pdu.h:242-247` |
| Hash chain during negotiate | **Complete** | `smb3_preauth_hash_rsp()` at `smb2pdu.h:1761` |
| Hash chain during session setup | **Complete** | Called appropriately |

### 6.4 Secure Negotiation

| Feature | Status | File:Line | Notes |
|---------|--------|-----------|-------|
| FSCTL_VALIDATE_NEGOTIATE_INFO | **Complete** | `smb2pdu.c:8849-8889` | Validates dialect, GUID, SecurityMode, Capabilities |

### 6.5 Access Control

| Feature | Status | Notes |
|---------|--------|-------|
| OWNER_SECINFO | **Complete** | Query and Set |
| GROUP_SECINFO | **Complete** | Query and Set |
| DACL_SECINFO | **Complete** | Query and Set |
| SACL_SECINFO | **Missing** | `smb2pdu.c:6220-6222` -- filtered out if present in AdditionalInformation |
| LABEL_SECINFO | **Missing** | Filtered out |
| ATTRIBUTE_SECINFO | **Missing** | Not handled |
| SCOPE_SECINFO | **Missing** | Not handled |

**Gap**:
- **Feature**: SACL query/set (MS-SMB2 2.2.39)
  - **Status**: Missing
  - **Current code**: `smb2pdu.c:6220-6237` -- returns minimal NTSD with empty offsets for unsupported flags
  - **Impact**: Windows auditing policies cannot be applied. Some security tools fail.
  - **Effort**: M
  - **Priority**: P2

---

## 7. Advanced Features

### 7.1 Multi-Channel

| Feature | Status | File:Line | Notes |
|---------|--------|-----------|-------|
| Session binding | **Complete** | `smb2pdu.c:1791-1838` | SMB2_SESSION_REQ_FLAG_BINDING |
| FSCTL_QUERY_NETWORK_INTERFACE_INFO | **Complete** | `smb2pdu.c:8734-8847` | Returns IPv4/IPv6, RSS/RDMA capabilities, link speed |
| Channel list management | **Complete** | `xa_store(&sess->ksmbd_chann_list, ...)` |
| Channel failover | **Partial** | -- | Basic reconnection via session binding; no witness protocol |

### 7.2 DFS (Distributed File System)

- **Status**: **Missing**
- **Current code**: `smb2pdu.c:9079-9084` -- `FSCTL_DFS_GET_REFERRALS` returns `STATUS_FS_DRIVER_REQUIRED`
- **Impact**: P1 -- Cannot serve DFS referrals; enterprise namespaces broken
- **Effort**: XL
- **Priority**: P1

### 7.3 Witness Protocol (MS-SWN)

- **Status**: **Missing**
- **Impact**: No cluster witness notifications for failover
- **Effort**: XL
- **Priority**: P3 (only for clustered deployments)

### 7.4 RDMA / SMB Direct

| Feature | Status | File:Line | Notes |
|---------|--------|-----------|-------|
| RDMA transport | **Complete** | `transport_rdma.c` | Full SMB Direct implementation |
| RDMA read/write channels | **Complete** | `smb2pdu.c:7471-7515` | `smb2_set_remote_key_for_rdma`, `smb2_read_rdma_channel` |
| SMB2_CHANNEL_RDMA_V1 | **Complete** | `smb2pdu.h:907` | |
| SMB2_CHANNEL_RDMA_V1_INVALIDATE | **Complete** | `smb2pdu.h:908` | |
| RDMA Transform Capabilities | **Missing** | -- | Negotiate context not implemented |

### 7.5 Compression

- **Status**: **Missing**
- **Current code**: `smb_common.c:202-205` -- rejects `SMB2_COMPRESSION_TRANSFORM_ID` with error
- Compression algorithms defined (`smb2pdu.h:303-306`): LZNT1, LZ77, LZ77+Huffman
- `decode_compress_ctxt()` always sets `SMB3_COMPRESS_NONE`
- **Impact**: P2 -- No bandwidth optimization for large transfers
- **Effort**: XL
- **Priority**: P2

### 7.6 Server-Side Copy

| Feature | Status | File:Line | Notes |
|---------|--------|-----------|-------|
| FSCTL_SRV_REQUEST_RESUME_KEY | **Complete** | `smb2pdu.c:9009-9025` | |
| FSCTL_SRV_COPYCHUNK | **Complete** | `smb2pdu.c:8575-8714, 9156-9184` | Full chunk-based copy |
| FSCTL_SRV_COPYCHUNK_WRITE | **Complete** | `smb2pdu.c:9157` | |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | **Complete** | `smb2pdu.c:9279-9342` | Uses `vfs_clone_file_range` with `vfs_copy_file_range` fallback |

### 7.7 Sparse Files

| Feature | Status | File:Line | Notes |
|---------|--------|-----------|-------|
| FSCTL_SET_SPARSE | **Complete** | `smb2pdu.c:8968-9007, 9186-9195` | Sets/clears ATTR_SPARSE_FILE_LE |
| FSCTL_QUERY_ALLOCATED_RANGES | **Complete** | `smb2pdu.c:8891-8921, 9239-9258` | Uses `ksmbd_vfs_fqar_lseek` |
| FSCTL_SET_ZERO_DATA | **Complete** | `smb2pdu.c:9196-9238` | |

### 7.8 Named Pipes

| Feature | Status | File:Line | Notes |
|---------|--------|-----------|-------|
| FSCTL_PIPE_TRANSCEIVE | **Complete** | `smb2pdu.c:8923-8966, 9104-9107` | Via ksmbd.mountd RPC |
| FSCTL_PIPE_WAIT | **Missing** | -- | `smbfsctl.h:72` defines constant; not handled in ioctl |
| FSCTL_PIPE_PEEK | **Missing** | -- | `smbfsctl.h:69` defines constant; not handled |
| Pipe read/write | **Complete** | `smb2pdu.c:7412-7469` (read), write pipe similar | Via RPC subsystem |

### 7.9 Reparse Points

| Feature | Status | File:Line | Notes |
|---------|--------|-----------|-------|
| FSCTL_GET_REPARSE_POINT | **Partial** | `smb2pdu.c:9259-9278` | Returns reparse tag but no data buffer content |
| FSCTL_SET_REPARSE_POINT | **Missing** | -- | Constant defined but not handled |
| FSCTL_DELETE_REPARSE_POINT | **Missing** | -- | Constant defined but not handled |
| WSL reparse tags | **Complete** | `smbfsctl.h:86-90` | LX_SYMLINK, AF_UNIX, LX_FIFO, LX_CHR, LX_BLK |

**Gap**:
- **Feature**: Full reparse point support (MS-FSCC 2.1.2)
  - **Status**: Partial
  - **Impact**: Windows symbolic links, junctions, and dedup reparse points not fully supported
  - **Effort**: L
  - **Priority**: P1

---

## 8. FSCTL Implementation Completeness

### 8.1 Implemented FSCTLs

| FSCTL | Code | Status | Notes |
|-------|------|--------|-------|
| FSCTL_DFS_GET_REFERRALS | 0x00060194 | **Stub** | Returns STATUS_FS_DRIVER_REQUIRED |
| FSCTL_DFS_GET_REFERRALS_EX | 0x000601B0 | **Stub** | Returns STATUS_FS_DRIVER_REQUIRED |
| FSCTL_CREATE_OR_GET_OBJECT_ID | 0x000900C0 | **Partial** | Returns zeroed object ID (dummy) |
| FSCTL_SET_SPARSE | 0x000900C4 | **Complete** | |
| FSCTL_SET_ZERO_DATA | 0x000980C8 | **Complete** | |
| FSCTL_QUERY_ALLOCATED_RANGES | 0x000940CF | **Complete** | |
| FSCTL_GET_REPARSE_POINT | 0x000900A8 | **Partial** | Tag only, no data buffer |
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | 0x00098344 | **Complete** | |
| FSCTL_PIPE_TRANSCEIVE | 0x0011C017 | **Complete** | |
| FSCTL_REQUEST_RESUME_KEY | 0x00140078 | **Complete** | |
| FSCTL_VALIDATE_NEGOTIATE_INFO | 0x00140204 | **Complete** | |
| FSCTL_QUERY_NETWORK_INTERFACE_INFO | 0x001401FC | **Complete** | |
| FSCTL_COPYCHUNK | 0x001440F2 | **Complete** | |
| FSCTL_COPYCHUNK_WRITE | 0x001480F2 | **Complete** | |

### 8.2 Missing FSCTLs

| FSCTL | Code | Priority | Impact |
|-------|------|----------|--------|
| FSCTL_PIPE_WAIT | 0x00110018 | P2 | Named pipe clients cannot wait for pipe availability |
| FSCTL_PIPE_PEEK | 0x0011400C | P2 | Cannot peek at pipe data without consuming it |
| FSCTL_SET_REPARSE_POINT | 0x000900A4 | P1 | Cannot create Windows symlinks/junctions |
| FSCTL_DELETE_REPARSE_POINT | 0x000900AC | P1 | Cannot delete reparse points |
| FSCTL_SRV_ENUMERATE_SNAPSHOTS | 0x00144064 | P1 | Windows "Previous Versions" tab is empty |
| FSCTL_GET_COMPRESSION | 0x0009003C | P3 | Compression query |
| FSCTL_SET_COMPRESSION | 0x0009C040 | P3 | Compression set |
| FSCTL_SET_OBJECT_ID | 0x00090098 | P3 | Object ID management |
| FSCTL_GET_OBJECT_ID | 0x0009009C | P3 | Object ID query |
| FSCTL_DELETE_OBJECT_ID | 0x000900A0 | P3 | Object ID deletion |
| FSCTL_SET_OBJECT_ID_EXTENDED | 0x000900BC | P3 | Extended object ID |
| FSCTL_LOCK_VOLUME | 0x00090018 | P3 | Volume lock |
| FSCTL_UNLOCK_VOLUME | 0x0009001C | P3 | Volume unlock |
| FSCTL_IS_PATHNAME_VALID | 0x0009002C | P3 | Path validation |
| FSCTL_QUERY_FAT_BPB | 0x00090058 | P3 | FAT BPB query |
| FSCTL_FILESYSTEM_GET_STATS | 0x00090060 | P3 | FS statistics |
| FSCTL_GET_NTFS_VOLUME_DATA | 0x00090064 | P3 | NTFS volume data |
| FSCTL_GET_RETRIEVAL_POINTERS | 0x00090073 | P3 | File extent info |
| FSCTL_IS_VOLUME_DIRTY | 0x00090078 | P3 | Volume dirty flag |
| FSCTL_FIND_FILES_BY_SID | 0x0009008F | P3 | SID-based file search |
| FSCTL_SET_ENCRYPTION | 0x000900D7 | P3 | Per-file encryption |
| FSCTL_READ_FILE_USN_DATA | 0x000900EB | P2 | USN journal data |
| FSCTL_WRITE_USN_CLOSE_RECORD | 0x000900EF | P2 | USN close record |
| FSCTL_RECALL_FILE | 0x00090117 | P3 | HSM recall |
| FSCTL_SET_ZERO_ON_DEALLOC | 0x00090194 | P3 | Zero-on-dealloc |
| FSCTL_SET_SHORT_NAME_BEHAVIOR | 0x000901B4 | P3 | Short name control |
| FSCTL_SET_DEFECT_MANAGEMENT | 0x00098134 | P3 | Defect management |
| FSCTL_SIS_LINK_FILES | 0x0009C104 | P3 | SIS link |
| FSCTL_LMR_GET_LINK_TRACK_INF | 0x001400E8 | P3 | Link tracking |
| FSCTL_LMR_SET_LINK_TRACK_INF | 0x001400EC | P3 | Link tracking |
| FSCTL_FILE_LEVEL_TRIM | -- | P2 | SSD TRIM passthrough |
| FSCTL_OFFLOAD_READ | -- | P2 | Offloaded data transfer |
| FSCTL_OFFLOAD_WRITE | -- | P2 | Offloaded data transfer |

---

## 9. Information Level Completeness

### 9.1 QUERY_INFO -- File Information Classes (SMB2_O_INFO_FILE)

| Class | ID | Query | Set | Notes |
|-------|-----|-------|-----|-------|
| FILE_DIRECTORY_INFORMATION | 1 | N/A (dir only) | -- | Used in QUERY_DIRECTORY |
| FILE_FULL_DIRECTORY_INFORMATION | 2 | N/A (dir only) | -- | Used in QUERY_DIRECTORY |
| FILE_BOTH_DIRECTORY_INFORMATION | 3 | N/A (dir only) | -- | Used in QUERY_DIRECTORY |
| FILE_BASIC_INFORMATION | 4 | **Complete** | **Complete** | `smb2pdu.c:5283-5315` / `7203-7209` |
| FILE_STANDARD_INFORMATION | 5 | **Complete** | -- | `smb2pdu.c:5317-5347` |
| FILE_INTERNAL_INFORMATION | 6 | **Complete** | -- | `smb2pdu.c:5623-5641` |
| FILE_EA_INFORMATION | 7 | **Complete** | -- | `smb2pdu.c:5685-5693` |
| FILE_ACCESS_INFORMATION | 8 | **Complete** | -- | `smb2pdu.c:5272-5281` |
| FILE_NAME_INFORMATION | 9 | **Missing** | -- | Not in switch statement |
| FILE_RENAME_INFORMATION | 10 | -- | **Complete** | `smb2pdu.c:7226-7233` |
| FILE_LINK_INFORMATION | 11 | -- | **Complete** | `smb2pdu.c:7235-7243` |
| FILE_NAMES_INFORMATION | 12 | N/A (dir only) | -- | Used in QUERY_DIRECTORY |
| FILE_DISPOSITION_INFORMATION | 13 | -- | **Complete** | `smb2pdu.c:7245-7251` |
| FILE_POSITION_INFORMATION | 14 | **Complete** | **Complete** | `smb2pdu.c:5695-5708` / `7267-7272` |
| FILE_FULL_EA_INFORMATION | 15 | **Complete** | **Complete** | `smb2pdu.c:5105-5270` / `7253-7265` |
| FILE_MODE_INFORMATION | 16 | **Complete** | **Complete** | `smb2pdu.c:5710-5719` / `7274-7279` |
| FILE_ALIGNMENT_INFORMATION | 17 | **Complete** | -- | `smb2pdu.c:5349-5358` |
| FILE_ALL_INFORMATION | 18 | **Complete** | -- | `smb2pdu.c:5360-5432` |
| FILE_ALLOCATION_INFORMATION | 19 | -- | **Complete** | `smb2pdu.c:7210-7216` |
| FILE_END_OF_FILE_INFORMATION | 20 | -- | **Complete** | `smb2pdu.c:7218-7224` |
| FILE_ALTERNATE_NAME_INFORMATION | 21 | **Complete** | -- | `smb2pdu.c:5434-5453` |
| FILE_STREAM_INFORMATION | 22 | **Complete** | -- | `smb2pdu.c:5455-5621` |
| FILE_PIPE_INFORMATION | 23 | **Missing** | **Missing** | |
| FILE_PIPE_LOCAL_INFORMATION | 24 | **Missing** | -- | |
| FILE_PIPE_REMOTE_INFORMATION | 25 | **Missing** | -- | |
| FILE_MAILSLOT_QUERY_INFORMATION | 26 | **Missing** | -- | |
| FILE_MAILSLOT_SET_INFORMATION | 27 | -- | **Missing** | |
| FILE_COMPRESSION_INFORMATION | 28 | **Complete** | -- | `smb2pdu.c:5721-5745` |
| FILE_OBJECT_ID_INFORMATION | 29 | **Missing** | -- | |
| FILE_MOVE_CLUSTER_INFORMATION | 31 | **Missing** | -- | |
| FILE_QUOTA_INFORMATION | 32 | **Missing** | -- | |
| FILE_REPARSE_POINT_INFORMATION | 33 | **Missing** | -- | |
| FILE_NETWORK_OPEN_INFORMATION | 34 | **Complete** | -- | `smb2pdu.c:5643-5683` |
| FILE_ATTRIBUTE_TAG_INFORMATION | 35 | **Complete** | -- | `smb2pdu.c:5747-5764` |
| FILE_TRACKING_INFORMATION | 36 | -- | **Missing** | |
| FILEID_BOTH_DIRECTORY_INFORMATION | 37 | N/A (dir only) | -- | Used in QUERY_DIRECTORY |
| FILEID_FULL_DIRECTORY_INFORMATION | 38 | N/A (dir only) | -- | Used in QUERY_DIRECTORY |
| FILE_VALID_DATA_LENGTH_INFORMATION | 39 | **Missing** | **Missing** | |
| FILE_SHORT_NAME_INFORMATION | 40 | **Missing** | -- | |
| FILE_NORMALIZED_NAME_INFORMATION | 48 | **Missing** | -- | |
| FILE_STANDARD_LINK_INFORMATION | 54 | **Missing** | -- | |
| SMB_FIND_FILE_POSIX_INFO | 0x64 | **Complete** | -- | `smb2pdu.c:5766-5865` |

**Summary**: 17 of ~25 applicable query classes implemented, 9 of ~12 applicable set classes implemented.

**Critical missing**:
- **FILE_NAME_INFORMATION (9)**: P1 -- Some applications query file name
- **FILE_PIPE_INFORMATION (23/24/25)**: P2 -- Pipe info queries from management tools
- **FILE_QUOTA_INFORMATION (32)**: P2 -- Quota management
- **FILE_VALID_DATA_LENGTH_INFORMATION (39)**: P2 -- Some backup tools need this
- **FILE_NORMALIZED_NAME_INFORMATION (48)**: P2 -- Path normalization queries

### 9.2 QUERY_INFO -- FS Information Classes (SMB2_O_INFO_FILESYSTEM)

| Class | ID | Query | Set | Notes |
|-------|-----|-------|-----|-------|
| FS_VOLUME_INFORMATION | 1 | **Complete** | -- | `smb2pdu.c:6057-6082` |
| FS_LABEL_INFORMATION | 2 | -- | **Missing** | Set volume label |
| FS_SIZE_INFORMATION | 3 | **Complete** | -- | `smb2pdu.c:6083-6094` |
| FS_DEVICE_INFORMATION | 4 | **Complete** | -- | `smb2pdu.c:6013-6028` |
| FS_ATTRIBUTE_INFORMATION | 5 | **Complete** | -- | `smb2pdu.c:6029-6056` |
| FS_CONTROL_INFORMATION | 6 | **Complete** | **Missing** | `smb2pdu.c:6151-6170` (query only, hardcoded values) |
| FS_FULL_SIZE_INFORMATION | 7 | **Complete** | -- | `smb2pdu.c:6095-6109` |
| FS_OBJECT_ID_INFORMATION | 8 | **Complete** | **Missing** | `smb2pdu.c:6110-6129` (zeroed OID for security) |
| FS_DRIVER_PATH_INFORMATION | 9 | **Missing** | -- | |
| FS_SECTOR_SIZE_INFORMATION | 11 | **Complete** | -- | `smb2pdu.c:6130-6150` |
| FS_POSIX_INFORMATION | 100 | **Complete** | -- | `smb2pdu.c:6171-6191` (POSIX extension) |

### 9.3 QUERY_INFO -- Quota Information (SMB2_O_INFO_QUOTA)

- **Status**: **Missing entirely**
- **Current code**: `smb2pdu.c:6332-6335` -- falls to default case returning EOPNOTSUPP
- **Impact**: P2 -- Cannot query or set disk quotas via SMB
- **Effort**: L (requires integration with Linux quota subsystem)
- **Priority**: P2

### 9.4 Security Information

| Component | Query | Set | Notes |
|-----------|-------|-----|-------|
| OWNER_SECINFO | **Complete** | **Complete** | |
| GROUP_SECINFO | **Complete** | **Complete** | |
| DACL_SECINFO | **Complete** | **Complete** | ACL via `smbacl.c` |
| SACL_SECINFO | **Missing** | **Missing** | Filtered out in `smb2pdu.c:6220-6222` |
| LABEL_SECINFO | **Missing** | **Missing** | Mandatory integrity labels |

---

## 10. Interoperability Assessment

### 10.1 Windows 10/11 Client Compatibility

| Feature | Status | Notes |
|---------|--------|-------|
| Basic file operations (CRUD) | **Works** | |
| File copy (Explorer) | **Works** | |
| Directory listing | **Works** | But no auto-refresh (CHANGE_NOTIFY missing) |
| Previous Versions tab | **Broken** | FSCTL_SRV_ENUMERATE_SNAPSHOTS missing |
| SMB3 encryption | **Works** | All 4 ciphers |
| SMB3 signing | **Works** | HMAC-SHA256 and AES-CMAC |
| AES-GMAC signing | **Missing** | Falls back to AES-CMAC |
| Multi-channel | **Works** | Session binding + network interface query |
| Offline files / CSC | **Partial** | Manual caching only |
| DFS namespaces | **Broken** | DFS not implemented |
| Print shares | **Broken** | Print share type not implemented |
| Disk quotas | **Missing** | Quota info class not implemented |
| Change notifications | **Broken** | Returns STATUS_NOT_IMPLEMENTED |
| Windows search | **Missing** | No FSCTL_SRV_SEARCH_PATH / indexing |

### 10.2 macOS Finder Compatibility

| Feature | Status | Notes |
|---------|--------|-------|
| Basic file operations | **Works** | |
| Fruit/AAPL extensions | **Complete** | `CONFIG_KSMBD_FRUIT` -- server caps, model string, Time Machine |
| Time Machine backup | **Complete** | `smb2aapl.c`, `smb2fruit.h` |
| Spotlight search | **Missing** | No MDSSVC RPC |
| Resource forks | **Partial** | Via NTFS streams + Fruit COPYFILE xattr copy |
| Finder info | **Partial** | Via xattr |
| POSIX extensions | **Works** | SMB 3.1.1 POSIX context |

### 10.3 Linux smbclient / mount.cifs Compatibility

| Feature | Status | Notes |
|---------|--------|-------|
| Basic mount | **Works** | |
| SMB3 multichannel | **Works** | |
| POSIX extensions | **Works** | Full POSIX mode, UID/GID mapping |
| Directory change notify | **Missing** | inotify not triggered over SMB |
| DFS | **Missing** | |
| smbclient operations | **Works** | All basic operations |

### 10.4 Known Interoperability Issues

1. **Windows Explorer auto-refresh**: Directories do not auto-update because
   CHANGE_NOTIFY returns STATUS_NOT_IMPLEMENTED. Users must manually press F5.

2. **Windows Previous Versions**: The "Previous Versions" tab in file properties
   shows nothing because FSCTL_SRV_ENUMERATE_SNAPSHOTS is not implemented.

3. **DFS referrals**: Clients accessing DFS paths receive STATUS_FS_DRIVER_REQUIRED
   and cannot resolve DFS paths.

4. **Windows Security tab**: Limited -- SACL querying fails, so Auditing tab cannot
   be populated. DACL works correctly.

5. **Quota management**: Windows quota management tools cannot display or set quotas.

6. **Office file locking**: While basic locking works, lock sequence validation
   for resilient handles is incomplete, which may cause issues with Office files
   on unreliable networks.

---

## 11. Priority-Ranked Implementation Roadmap

### P0 -- Breaks Basic Interoperability

| # | Feature | MS-SMB2 Section | Effort | Impact |
|---|---------|-----------------|--------|--------|
| 1 | CHANGE_NOTIFY implementation | 3.3.5.19 | L | Windows Explorer, IDEs, Office auto-refresh all broken |

### P1 -- Important Missing Features

| # | Feature | MS-SMB2 Section | Effort | Impact |
|---|---------|-----------------|--------|--------|
| 2 | DFS referrals (FSCTL_DFS_GET_REFERRALS) | 3.3.5.15.2 | XL | Enterprise namespace navigation |
| 3 | FSCTL_SRV_ENUMERATE_SNAPSHOTS | MS-SMB2 3.3.5.15.3 | L | Windows Previous Versions |
| 4 | FSCTL_SET_REPARSE_POINT | MS-FSCC 2.3.52 | L | Windows symbolic links, junctions |
| 5 | FSCTL_DELETE_REPARSE_POINT | MS-FSCC 2.3.10 | S | Reparse point removal |
| 6 | FILE_NAME_INFORMATION query | MS-FSCC 2.4.12 | S | Some apps query file name |
| 7 | TIMEWARP create context (VSS) | 2.2.13.2.7 | L | Point-in-time file access |
| 8 | Full FSCTL_GET_REPARSE_POINT (with data) | MS-FSCC 2.3.21 | M | Currently returns tag only |

### P2 -- Significant Feature Gaps

| # | Feature | Section | Effort | Impact |
|---|---------|---------|--------|--------|
| 9 | AES-GMAC signing | 2.2.3.1.7 | M | Win11 performance |
| 10 | SMB2_CREATE_APP_INSTANCE_ID | 2.2.13.2.13 | M | HA/VM failover |
| 11 | SMB2_CREATE_APP_INSTANCE_VERSION | 2.2.13.2.14 | M | HA/VM failover |
| 12 | Resilient handles | 3.3.5.15.11 | L | Hyper-V, unreliable networks |
| 13 | Persistent handle survival across restart | 3.3.5.9.7 | XL | True persistent handles |
| 14 | Quota info class (SMB2_O_INFO_QUOTA) | 2.2.37 | L | Disk quota management |
| 15 | SACL_SECINFO query/set | 2.2.39 | M | Windows auditing |
| 16 | SMB3 compression | 2.2.42 | XL | Bandwidth optimization |
| 17 | FSCTL_PIPE_WAIT | MS-FSCC 2.3.38 | S | Pipe availability wait |
| 18 | FSCTL_PIPE_PEEK | MS-FSCC 2.3.36 | S | Pipe peek |
| 19 | FILE_PIPE_INFORMATION query | MS-FSCC 2.4.28 | S | Pipe management tools |
| 20 | FILE_QUOTA_INFORMATION | MS-FSCC 2.4.33 | L | Quota queries |
| 21 | FILE_VALID_DATA_LENGTH_INFORMATION | MS-FSCC 2.4.45 | S | Backup tools |
| 22 | FILE_NORMALIZED_NAME_INFORMATION | MS-FSCC 2.4.48 | S | Path queries |
| 23 | Lock sequence validation | 3.3.5.14 | M | Resilient lock reliability |
| 24 | FS_CONTROL_INFORMATION set | MS-FSCC 2.5.2 | S | Quota control |
| 25 | RDMA_TRANSFORM_CAPABILITIES | 2.2.3.1.6 | L | RDMA + encryption |
| 26 | FSCTL_FILE_LEVEL_TRIM | MS-FSCC | S | SSD optimization |
| 27 | FSCTL_OFFLOAD_READ/WRITE | MS-FSCC | L | Offloaded data transfer |

### P3 -- Nice to Have / Edge Cases

| # | Feature | Effort | Notes |
|---|---------|--------|-------|
| 28 | Print share support | L | Rare for in-kernel server |
| 29 | Witness protocol (MS-SWN) | XL | Cluster only |
| 30 | SMB over QUIC | XL | TRANSPORT_CAPABILITIES context |
| 31 | Scale-out cluster support | XL | Enterprise only |
| 32 | Various unused FSCTLs (LOCK_VOLUME, etc.) | S each | Rarely used |
| 33 | FILE_PIPE_LOCAL/REMOTE_INFORMATION | S | Diagnostic |
| 34 | FILE_MAILSLOT_* INFORMATION | S | Legacy |
| 35 | FSCTL_GET/SET_COMPRESSION | S | Compression control |
| 36 | FSCTL_SET_ENCRYPTION (per-file) | M | Windows EFS |
| 37 | USN journal FSCTLs | M | Change journal |
| 38 | LABEL_SECINFO (integrity labels) | M | Mandatory access control |
| 39 | FS_DRIVER_PATH_INFORMATION | S | Diagnostic |
| 40 | Unbuffered read/write flags | S | I/O hints |
| 41 | NETNAME context validation | S | Server routing |
| 42 | FSCTL_SET_SHORT_NAME_BEHAVIOR | S | Short name control |
| 43 | Anonymous vs guest session distinction | S | Security policy edge case |

---

## 12. Detailed Analysis of Critical Missing Features

### 12.1 CHANGE_NOTIFY (Priority P0)

**Current state**: `smb2pdu.c:9691-9709` -- hardcoded `STATUS_NOT_IMPLEMENTED`.

**What is needed**:
1. Integrate with Linux `inotify` or `fanotify` subsystem for file/directory watches
2. Maintain a per-directory notification queue
3. Support the `SMB2_WATCH_TREE` flag for recursive monitoring
4. Map `inotify` events to SMB2 `FILE_NOTIFY_CHANGE_*` flags
5. Send asynchronous responses when changes occur
6. Handle CANCEL for pending notify requests
7. Support buffer overflow (too many changes) with `STATUS_NOTIFY_ENUM_DIR`

**Complexity**: This is the most impactful single feature gap. The async framework
already exists (used by LOCK), so the infrastructure is partially in place. The main
work is the inotify integration and event mapping.

**Estimated effort**: 800-1200 lines of new code.

### 12.2 DFS Support (Priority P1)

**Current state**: `FSCTL_DFS_GET_REFERRALS` returns `STATUS_FS_DRIVER_REQUIRED`.

**What is needed**:
1. DFS referral table management (in ksmbd.mountd or kernel)
2. `FSCTL_DFS_GET_REFERRALS` / `FSCTL_DFS_GET_REFERRALS_EX` implementation
3. `SMB2_FLAGS_DFS_OPERATIONS` flag handling in request processing
4. DFS path resolution in `smb2_open` and tree connect
5. Share configuration for DFS root vs. DFS link

**Complexity**: DFS is fundamentally a namespace feature that requires significant
design for referral storage and resolution. Most logic could live in ksmbd.mountd.

### 12.3 Previous Versions / VSS (Priority P1)

**Current state**: TWrp create context returns `-EBADF`, no snapshot enumeration.

**What is needed**:
1. `FSCTL_SRV_ENUMERATE_SNAPSHOTS` returning available snapshot timestamps
2. TWrp create context opening files from snapshot paths
3. Backend integration (btrfs snapshots, LVM snapshots, ZFS snapshots)
4. Configuration for snapshot path mapping

**Complexity**: Backend-dependent. Btrfs provides `.snapshot` directories that could
be enumerated. The SMB protocol layer itself is straightforward.

---

## 13. Structural Observations

### 13.1 Code Quality for Protocol Compliance

- Header definitions (`smb2pdu.h`) are comprehensive and match the MS-SMB2 wire format
- Constants for many unimplemented features are already defined (good forward planning)
- The `smb2_ioctl` switch statement has a clear extension pattern for new FSCTLs
- The `smb2_get_info_file` and `smb2_set_info_file` switches are well-structured for adding new info classes

### 13.2 Architecture Strengths

- Clean separation between protocol processing and VFS operations
- Asynchronous work framework already in place (LOCK uses it)
- ksmbd.mountd delegation pattern works well for RPC and authentication
- Multi-dialect support with version-specific ops tables is well designed

### 13.3 Architecture Weaknesses for Protocol Compliance

- CHANGE_NOTIFY requires kernel-level async notification infrastructure that does not exist
- DFS requires coordination between kernel and userspace that current netlink interface does not fully support
- No persistent storage mechanism for durable/persistent handle state
- Compression would require a new transform header processing layer

---

## Appendix A: File Reference Map

| File | Primary Protocol Area |
|------|----------------------|
| `smb2pdu.c` | All SMB2 command handlers, negotiate contexts, IOCTL dispatch |
| `smb2pdu.h` | Wire format structures, constants, function declarations |
| `smb_common.c` | Dialect negotiation, shared mode checking, credential management |
| `smb_common.h` | Protocol version definitions, common interfaces |
| `smbfsctl.h` | FSCTL code definitions |
| `smb2ops.c` | Per-dialect operation tables, command dispatch tables |
| `oplock.c` | Oplock and lease model implementation |
| `auth.c` | NTLMSSP, signing, key derivation |
| `smbacl.c` | Windows ACL / NTSD construction and parsing |
| `vfs.c` | Linux VFS operations (open, read, write, etc.) |
| `vfs_cache.c` | File handle cache, inode info cache |
| `connection.c` | TCP connection management |
| `transport_tcp.c` | TCP transport |
| `transport_rdma.c` | RDMA/SMB Direct transport |
| `transport_ipc.c` | Kernel-userspace netlink interface |
| `server.c` | Server lifecycle, work queue |
| `ksmbd_work.c` | Work item management |
| `smb2aapl.c` | Apple AAPL/Fruit create context handler |
| `mgmt/user_session.c` | Session management |
| `mgmt/share_config.c` | Share configuration |
| `mgmt/tree_connect.c` | Tree connection management |
| `mgmt/user_config.c` | User account management |
| `mgmt/ksmbd_ida.c` | ID allocation |

## Appendix B: Methodology

This audit was conducted by reading every source file in the ksmbd repository and
comparing the implementation against:

- MS-SMB2 (Server Message Block Protocol Versions 2 and 3)
- MS-FSCC (File System Control Codes)
- MS-DTYP (Windows Data Types)
- MS-NLMP (NT LAN Manager Authentication Protocol)
- MS-SPNG (Simple and Protected GSSAPI Negotiation Mechanism)

Each SMB2 command handler was traced through its full code path. Negotiate contexts
were verified by reading both the encode and decode functions. FSCTL support was
verified by examining the switch statement in `smb2_ioctl()`. Information classes
were verified by examining the switch statements in `smb2_get_info_file()`,
`smb2_set_info_file()`, and `smb2_get_info_filesystem()`.
