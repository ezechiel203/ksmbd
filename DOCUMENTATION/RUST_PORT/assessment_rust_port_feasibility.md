# Rust Port Feasibility Assessment for ksmbd (Kernel v7.0-rc1)

Date: 2026-02-23

## Executive Summary

Porting the full `ksmbd` C implementation to Rust on kernel `v7.0-rc1` is **high difficulty**: **8.5/10**.

The primary blocker is not Rust language maturity; it is **kernel Rust abstraction coverage** versus the breadth of `ksmbd` subsystem usage (VFS, kernel sockets, generic netlink IPC, crypto, fsnotify, ACL/xattr, and RDMA/IB verbs).

## Upstream Baseline (v7.0-rc1)

- `v7.0-rc1` is present upstream (tagged 2026-02-22).
- Rust is integrated in mainline, but abstraction coverage is still selective.
- Inference from source:
  - `rust/kernel/net.rs` currently exposes only `phy` under config gates.
  - `rust/kernel/fs.rs` currently exports a narrow set (`file`, `kiocb`), and `kiocb` is explicitly documented as incomplete.

## ksmbd Current Implementation Footprint (Local Tree)

- Approx. `115` C/H files in scope.
- Approx. `63,674` LOC in scope.
- Distinct kernel API families detected from the current implementation include:
  - `27` VFS calls (`vfs_create`, `vfs_unlink`, `vfs_rename`, `vfs_getattr`, `vfs_setxattr`, etc.).
  - `10` kernel socket calls (`sock_create_kern`, `kernel_bind`, `kernel_listen`, `kernel_accept`, `kernel_sendmsg`, `kernel_recvmsg`, etc.).
  - `39` RDMA/IB calls (`rdma_*`, `ib_*`).
  - `15` crypto calls (`crypto_shash_*`, `crypto_aead_*`, etc.).
  - fsnotify, POSIX ACL/xattr, and generic netlink usage.

## What Existing Rust Kernel Bindings Can Cover Immediately

Current upstream Rust infrastructure already supports useful base elements:

- Module scaffolding and core Rust-in-kernel patterns (`rust/kernel/lib.rs`).
- Common memory/sync/container patterns.
- Some filesystem and credential/security helper coverage.

This is sufficient to start Rust components, but **not enough** to replace end-to-end `ksmbd` behavior without substantial new subsystem abstractions.

## What Still Needs Development (Bindings + FFI + Rust Abstractions)

To approach full Rust `ksmbd`, the following areas still need significant work:

1. VFS/filesystem abstraction layer
   - Path lookup and parent lookup.
   - Create/unlink/rename/link/symlink.
   - getattr/statfs/fsync/fallocate/truncate.
   - xattr + ACL + lock operation wrappers.

2. Kernel socket server abstraction layer
   - Socket lifecycle and options.
   - `kernel_bind/listen/accept/sendmsg/recvmsg` safe wrappers.
   - Correct ownership/lifetime/thread-safety modeling.

3. Generic netlink control-plane abstraction
   - Family registration/unregistration.
   - Attribute encoding/decoding and policy handling.

4. Crypto abstraction expansion
   - `shash` and `aead` object lifecycle wrappers.
   - Request-buffer and error model normalization.

5. fsnotify integration wrappers
   - Mark/group lifecycle and event routing.

6. RDMA/IB abstraction layer (largest unsafe surface)
   - CM/QP/MR/CQ lifecycle.
   - DMA map/unmap and completion path modeling.
   - Likely phased and partially C-backed for a long period.

7. Helper glue for bindgen gaps
   - `rust/helpers/*.c` wrappers for macros/inline-only C APIs.
   - Add headers to binding helper pipeline as needed.

## Practical Effort Estimate

- Hybrid strategy (Rust protocol/state, most VFS/RDMA still C): **4-8 months**.
- Near-full Rust with RDMA mostly C-backed: **12-18 months**.
- Full Rust including mature RDMA path: **18-30+ months**.

These estimates assume a team already proficient in kernel internals, Rust unsafe/safety contracts, and subsystem upstreaming workflows.

## Recommended Port Strategy

1. Start with a hybrid architecture:
   - Keep high-risk I/O boundaries in C initially.
   - Move protocol parsing/state/control-plane logic to Rust first.
2. Build minimal Rust abstractions where reused across multiple callsites.
3. Gate each migration phase with ABI/protocol compatibility tests.
4. Defer RDMA full-Rust parity until after stable TCP/VFS Rust path.

## Sources

- Linux `v7.0-rc1` commit/tag:
  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?h=v7.0-rc1&id=6de23f81a5e08be8fbf5e8d7e9febc72a5b5f27f
- Rust kernel crate/module surface:
  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/rust/kernel/lib.rs?h=v7.0-rc1
  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/rust/kernel/net.rs?h=v7.0-rc1
  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/rust/kernel/fs.rs?h=v7.0-rc1
  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/rust/kernel/fs/kiocb.rs?h=v7.0-rc1
- Rust kernel general information:
  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/Documentation/rust/general-information.rst?h=v7.0-rc1
