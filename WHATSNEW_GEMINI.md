# What's New in KSMBD: Comprehensive Enhancements & Security Hardening

**Date:** March 2, 2026  
**Status:** Phase 1 Security Hardening & Apple Extensions Complete  
**Comparison Base:** Official `cifsd-team/ksmbd` & `cifsd-team/ksmbd-tools`

---

## **1. Architectural Revolution**
Unlike the flat, monolithic structure of the upstream repository, our fork has transitioned to a **highly modular, hierarchical architecture**. This ensures better maintainability, faster build times for specific components, and a clearer separation of concerns.

### **New Kernel Layout (`src/`)**
*   **`src/core/`**: Centralized connection management, authentication (Ntlm/Kerberos), and cryptographic contexts.
*   **`src/protocol/`**: Version-specific implementations (`smb1/`, `smb2/`) with shared logic in `common/`.
*   **`src/fs/`**: A robust VFS (Virtual File System) abstraction layer, including advanced ACL and notification logic.
*   **`src/transport/`**: Pluggable transport support for TCP, RDMA, and the new QUIC implementation.

---

## **2. Apple SMB "Fruit" Extensions (AAPL)**
We have delivered the most advanced Apple SMB implementation for the Linux kernel, enabling seamless high-performance integration with macOS clients.

### **Key Features:**
*   **Native AAPL Negotiation**: Supports version 2 negotiation, including client type detection and capability exchange.
*   **ReadDirAttr Optimization**: Implements batch-level enrichment. macOS Finder can now receive UNIX permissions (packed into `EaSize`), resource fork sizes, and FinderInfo in a single round-trip.
*   **Resource Fork Handling**: Optimized stream management for `AFP_Resource`, preventing the "file fragmentation" feel often found in basic SMB implementations.
*   **File ID Resolution**: Native support for `kAAPL_SUPPORT_RESOLVE_ID`, ensuring robust file tracking across moves and renames.
*   **Volume Capabilities**: Full advertisement of Case Sensitivity, Search support, and Full Sync capabilities.

---

## **3. Security Hardening & Remediation**
A dedicated **Security Audit Phase** identified and remediated critical vulnerabilities that were present in the base codebase.

### **Critical Fixes Applied:**
*   **Authentication Bypass**: Removed placeholder "accept-all" logic in the Apple extension paths; replaced with proper signature validation.
*   **Buffer Overflow Protection**: Implemented strict bounds checking for all `DataOffset` and `DataLength` fields in SMB2 Create Contexts.
*   **Use-After-Free (UAF)**: Hardened connection teardown logic. Connection-specific states (like Apple state or compression contexts) are now properly reference-counted.
*   **Integer Overflow Prevention**: Replaced unsafe arithmetic in buffer allocation paths with `size_add()` and `size_mul()` wrappers.

---

## **4. Advanced Protocol Features**

### **SMB3 Compression (LZ77 + Huffman)**
*   Full implementation of **RFC 1951 (Huffman)** and **LZ77** compression.
*   Intelligent dispatch: The server now correctly compresses READ/WRITE responses based on client capabilities and payload entropy.

### **SMB1 Legacy Enhancement**
*   While modernizing, we enhanced SMB1 `NT_TRANSACT` support for legacy industrial systems, including:
    *   `IOCTL` subcommand dispatcher.
    *   `NOTIFY_CHANGE` and `QUOTA` support.
    *   Improved error mapping for NT-style creates.

### **Reliability Improvements**
*   **Multichannel Nonce Tracking**: Fixed race conditions in per-channel nonce increments.
*   **RCU Locking**: Implemented RCU-safe lookups for IPv6 connection tracking.
*   **Persistent Handles**: Hardened the state machine for durable and persistent handles during network jitter.

---

## **5. Next-Gen Transport: QUIC & kTLS**
We have introduced a **kernel-native QUIC transport** (RFC 9000), positioning KSMBD at the forefront of SMB-over-QUIC technology.

*   **Zero-Copy Path**: QUIC data packets are processed directly in the kernel to minimize context switches.
*   **TLS 1.3 Offload**: Leverages the Linux kernel's `kTLS` for symmetric encryption, providing near-line-rate speeds with minimal CPU impact.
*   **IPC Delegation**: Complex TLS handshake logic is delegated to the `ksmbdctl` user-space daemon while maintaining the high-speed data path in the kernel.

---

## **6. Unified User-Space Tooling (`ksmbdctl`)**
We have consolidated the fragmented upstream utilities into a modern, unified CLI.

*   **One Tool to Rule Them All**: `ksmbd.adduser`, `ksmbd.addshare`, and `ksmbd.mountd` are now subcommands of **`ksmbdctl`**.
*   **CIDR-based ACLs**: Support for true network-range matching (e.g., `hosts allow = 192.168.1.0/24`) in `ksmbd.conf`.
*   **Structured Logging**: All tools now support `--json` output for integration with modern monitoring systems.
*   **Reliability**: Added `sd_notify` for systemd readiness, ensuring dependent services only start when KSMBD is truly ready to accept connections.

---

## **7. Quality Assurance & Documentation**
Our project includes a testing and documentation suite far exceeding the upstream project:
*   **Static Assertion Suite**: Validates structure sizes and alignment across x86 and ARM64 to prevent cross-platform bugs.
*   **Comprehensive Reports**:
    *   `APPLE_SMB_COMPILATION_FINAL_REPORT.md`
    *   `COMPREHENSIVE_SECURITY_AUDIT_REPORT.md`
    *   `ARM64_BUILD_INSTRUCTIONS.md`
*   **Performance Profiling**: Built-in support for generating performance flamegraphs to identify latency bottlenecks.

---

## **Comparison Summary**

| Feature | Upstream (cifsd-team) | Our Implementation (ezechiel203) |
| :--- | :--- | :--- |
| **Source Structure** | Monolithic (Flat) | **Modular (`src/` hierarchy)** |
| **Apple Compatibility** | Experimental | **Full AAPL + ReadDirAttr Support** |
| **Security Status** | Community Review | **Audited & Hardened (Remediated UAF/Bypass)** |
| **CLI Experience** | Multiple Binaries | **Unified `ksmbdctl` CLI** |
| **Compression** | Basic | **LZ77 + Huffman (Full Compliance)** |
| **Transport** | TCP / RDMA | **TCP / RDMA / QUIC + kTLS** |
| **Logging** | Plaintext Syslog | **Structured JSON + Extended Debug** |

---

**KSMBD Hardened Fork** - *Bringing Enterprise-Grade SMB to the Linux Kernel.*
