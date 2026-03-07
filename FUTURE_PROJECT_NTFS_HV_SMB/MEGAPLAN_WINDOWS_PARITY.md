# Mega Plan: Windows Server SMB + NTFS + Hyper-V

## Scope
This document turns the future-looking feasibility discussion into an execution plan for two distinct programs:

1. Program A: minimum credible Hyper-V over SMB
2. Program B: maximum Windows Server SMB + NTFS + Hyper-V parity

These must not be managed as one milestone stream. Program A is a product target. Program B is a platform program.

This plan is grounded in the feasibility constraints already recorded in [../GPTREVIEW_060326/README.md](../GPTREVIEW_060326/README.md), especially the NTFS capability matrix, the RSVD/VHDX gap summary, the transport/security TODOs, and the implementation-possibility notes.

## Assumptions
1. `ksmbd` remains the SMB server core.
2. Kerberos remains delegated to userspace unless there is an explicit architectural decision to change that.
3. Linux filesystems remain the backing store unless a dedicated NTFS-aware backend is introduced.
4. Hyper-V support means real Windows interoperability validation, not only protocol self-tests.
5. "Parity" means behavior-level compatibility, not returning success from stubs.

## Program A
Goal: credible Hyper-V over SMB on Linux-backed storage without claiming NTFS parity.

### Program A Product Contract
Supported target:
1. SMB 3.1.1 over TCP
2. Optional QUIC
3. Optional SMB Direct later
4. VHDX files stored as ordinary files on Linux filesystems
5. No RSVD in the initial target
6. No full NTFS metadata parity requirement
7. No cluster-grade continuous-availability promise in the initial target

Out of scope:
1. Full NTFS parity
2. Shared VHDX / VHD Set
3. RSVD SCSI tunnel
4. Witness-driven clustered failover
5. EFS, USN, TxF, full short-name parity

### Program A Workstreams
#### 1. Transport and Crypto
Areas:
- `src/transport/`
- `src/core/`
- `src/protocol/smb2/`

Scope:
1. QUIC Retry integrity tag
2. QUIC proper 1-RTT header protection key derivation
3. RDMA transform security if SMB Direct is in scope
4. Signing, encryption, and preauth integrity validation
5. Removal of insecure interoperability shortcuts

Exit criteria:
1. No insecure fallback path remains in transport bring-up.
2. SMB signing/encryption regressions pass.
3. QUIC interop works with strict clients if QUIC is enabled.
4. RDMA transport is either fully secured or explicitly unsupported.

#### 2. Handle Durability and Reconnect
Areas:
- `src/protocol/smb2/`
- `src/fs/`

Scope:
1. Durable handles
2. Persistent handles
3. Lease/oplock restore
4. Reconnect timeout correctness
5. Crash/restart recovery semantics
6. Lock survival and reconnect correctness under guest I/O

Exit criteria:
1. Disconnect/reconnect during active VM I/O does not corrupt state.
2. Handle restore preserves access rights, lease state, and lock semantics.
3. No stale-ID, restore-path, or scavenger corruption remains.

#### 3. VM-Disk I/O Semantics
Areas:
- `src/fs/`
- `src/protocol/smb2/`
- `src/core/`

Scope:
1. Flush/FUA behavior
2. Sparse file behavior
3. Zero-range and allocation semantics
4. Strict write ordering expectations for guest disks
5. Recovery after forced disconnect and restart

Exit criteria:
1. Hyper-V create/attach/boot/checkpoint/merge flows pass.
2. Forced power-loss and reconnect tests preserve guest disk integrity.
3. No silent metadata or ordering corruption is observed.

#### 4. Authentication and Sessioning
Areas:
- `src/protocol/smb2/`
- `src/core/`
- `ksmbd-tools/`

Scope:
1. Kerberos/SPNEGO reliability
2. Session expiry and rebind behavior
3. Domain-joined Hyper-V host operation
4. Logging and diagnosability for auth/session failures

Exit criteria:
1. Domain auth works repeatedly in long-run tests.
2. Ticket refresh and reconnect behavior is stable.
3. Logs are sufficient for root-cause analysis.

#### 5. Performance and Operations
Areas:
- `src/core/`
- `src/fs/`
- `src/mgmt/`
- `ksmbd-tools/`

Scope:
1. Credit tuning
2. Large I/O stability
3. Operational metrics
4. Production configuration guidance
5. Capacity and failure runbooks

Exit criteria:
1. Boot storm and mixed random/sequential I/O tests remain stable.
2. Metrics exist for sessions, handles, reconnects, errors, and latency.
3. Operational guidance is written and validated.

#### 6. Interoperability Lab
Areas:
- repo tests to be added under a future `tests/` tree
- external Windows/Hyper-V lab automation

Scope:
1. Windows Server matrix
2. Hyper-V host matrix
3. Backing filesystem matrix
4. Crash/restart matrix
5. Upgrade and soak matrix

Exit criteria:
1. A written compatibility matrix exists.
2. Reproducible pass/fail automation exists.
3. Unsupported configurations are explicitly documented.

### Program A Milestones
#### A0: Contract Freeze
Acceptance:
1. Windows and Hyper-V versions are fixed.
2. Backing filesystem is chosen.
3. Supported transports are chosen.
4. Unsupported features are documented.

#### A1: Protocol Hardening
Acceptance:
1. Transport/crypto gaps are closed for in-scope transports.
2. SMB3 security regression suite passes.
3. No review-blocking transport findings remain.

#### A2: Durable VM-Storage Semantics
Acceptance:
1. Persistent handle path is validated under disconnect/reconnect.
2. Long-running guest I/O survives host-side interruption.
3. Filesystem consistency checks pass after crash scenarios.

#### A3: Hyper-V Functional Qualification
Acceptance:
1. Hyper-V can create a VM on the share.
2. Hyper-V can boot from a SMB-backed VHDX.
3. Checkpoint and merge flows work.
4. Long-duration guest workload remains stable.

#### A4: Production Readiness
Acceptance:
1. Runbooks exist.
2. Metrics and logging exist.
3. Upgrade/restart behavior is documented.
4. Support envelope is published.

### Program A Staffing
Recommended minimum team:
1. 1 transport/crypto engineer
2. 1 SMB state/locking engineer
3. 1 storage/filesystem engineer
4. 1 userspace/auth/tooling engineer
5. 1 Windows/Hyper-V validation engineer
6. 1 technical lead

Practical minimum: 5-6 engineers.

### Program A Time Estimate
1. 3-4 months for a serious non-clustered target with a focused, senior team
2. 6-9 months if QUIC, multichannel, and broader validation are included early

### Program A Go/No-Go Gates
1. If persistent-handle and reconnect behavior is still unstable after A2, do not market Hyper-V support.
2. If crash/recovery semantics are not proven, do not proceed.
3. If Kerberos/domain auth is flaky, do not proceed.

## Program B
Goal: Windows Server SMB + NTFS + Hyper-V parity and compatibility.

This includes Program A and extends into Windows-specific filesystem, metadata, cluster, and virtual-disk semantics.

### Program B Product Contract
Supported target:
1. Standalone and clustered Hyper-V scenarios
2. SMB 3.1.1 over TCP
3. QUIC if strategic
4. SMB Direct if strategic
5. Witness and multichannel
6. RSVD / shared virtual disk workflows if claimed
7. NTFS metadata behavior for claimed Windows-visible features

This target is much larger than a normal SMB server product. It is closer to a storage platform.

### Program B Workstreams
#### 1. Full SMB Feature Parity
Owner profile: SMB platform lead

Scope:
1. Multichannel
2. Witness
3. Transparent failover / continuous-availability semantics
4. SMB Direct security completeness
5. FSCTL and info-class completion
6. BranchCache completion
7. Named pipe edge-case coverage

Acceptance:
1. Failover-sensitive client workflows behave like Windows Server for claimed scenarios.
2. Channel rebalance and interface reporting are stable.
3. Transport behavior is deterministic under failure injection.

#### 2. NTFS Compatibility Layer
Owner profile: NTFS semantics lead

Scope:
1. Short names
2. Object IDs
3. Compression get/set
4. Quotas
5. USN-like journal behavior
6. Reparse and metadata semantics
7. DOS/NT namespace quirks required by real clients

Acceptance:
1. Windows admin and management tooling sees expected metadata behavior.
2. Stubs are replaced by working implementations or deliberate compatibility shims.
3. Claimed feature coverage is documented precisely.

#### 3. Native NTFS Backend Decision
Owner profile: filesystem architecture lead

Scope:
1. Evaluate extending `ntfs3`
2. Evaluate a dedicated metadata emulation layer
3. Evaluate a separate NTFS-aware backend
4. Compare performance, crash consistency, and operational complexity

Acceptance:
1. A single architecture is chosen.
2. Rejected architectures are explicitly documented.
3. Failure model and support envelope are documented.

#### 4. RSVD and Virtual Disk Platform
Owner profile: virtual disk / RSVD lead

Scope:
1. SCSI tunnel
2. Reservation semantics
3. VHDX metadata operations
4. Resize and snapshot operations
5. Shared virtual disk behavior
6. Geometry and metadata query correctness

Acceptance:
1. Hyper-V shared-disk workflows pass for claimed scenarios.
2. Reservation conflicts behave as expected by Windows clients.
3. Geometry and metadata are not stubbed in targeted paths.

#### 5. Cluster and Failover Platform
Owner profile: cluster/availability lead

Scope:
1. Witness
2. Node failover semantics
3. Persistent-state replication or shared-state design
4. Connection-group management
5. Failover-safe handle/lock/session state

Acceptance:
1. Planned and unplanned failover tests pass within the target window.
2. Handle, lease, and lock state survives failover as claimed.
3. Client recovery behavior matches support claims.

#### 6. Security Parity
Owner profile: security lead

Scope:
1. Crypto correctness across all transports
2. Kerberos robustness
3. Audit and policy surface
4. Removal of protocol shortcuts

Acceptance:
1. No protocol downgrade shortcuts remain.
2. Policy and audit behavior is deterministic and documented.
3. Security posture is reviewable as a product, not only as code.

#### 7. Compatibility Test Infrastructure
Owner profile: interop lab lead

Scope:
1. Windows Server matrix
2. Hyper-V matrix
3. Cluster matrix
4. Failure-injection matrix
5. Long-haul soak matrix

Acceptance:
1. Repeatable lab automation exists.
2. Bug reproduction time is low.
3. Release gating depends on this lab.

#### 8. Management and Support Surface
Owner profile: productization lead

Scope:
1. Tooling
2. Diagnostics
3. Upgrade and migration behavior
4. Configuration and policy UX
5. Supportability and release engineering

Acceptance:
1. Operators can deploy and debug the platform without source-level intervention.
2. Support playbooks exist.
3. Upgrade and rollback scenarios are validated.

### Program B Milestones
#### B0: Architecture Decision
Acceptance:
1. Decide whether NTFS parity is real scope or explicitly limited.
2. Decide whether RSVD is in scope.
3. Decide whether cluster-grade availability is in scope.
4. Approve multi-year budget and staffing.

#### B1: SMB Platform Parity Foundation
Acceptance:
1. Multichannel, witness, durable state, failover primitives, and transport security foundation are complete.

#### B2: Standalone Hyper-V Parity
Acceptance:
1. All Program A criteria pass at production quality.
2. Broader Windows host matrix passes.

#### B3: RSVD Proof of Capability
Acceptance:
1. Nontrivial RSVD operations work against real Hyper-V scenarios.
2. There are no remaining always-`STATUS_NOT_SUPPORTED` paths in targeted RSVD workflows.

#### B4: NTFS Metadata Parity Foundation
Acceptance:
1. Chosen NTFS architecture produces working short-name, compression, object-id, and quota baselines.
2. Compatibility shims are documented where exact parity is impossible.

#### B5: Cluster-Grade Hyper-V
Acceptance:
1. Failover and clustered storage scenarios pass.
2. Witness and persistent-state semantics are validated.

#### B6: Administrative Parity
Acceptance:
1. Windows admin workflows and server-management expectations are functional or intentionally mapped.

#### B7: Qualification Release
Acceptance:
1. Long-haul soak tests pass.
2. Upgrade tests pass.
3. Restart tests pass.
4. Disaster recovery tests pass.
5. Support matrix is published.

### Program B Staffing
Recommended minimum team:
1. 1 chief architect
2. 2 SMB protocol engineers
3. 2 filesystem/NTFS engineers
4. 2 storage/virtual-disk engineers
5. 2 cluster/availability engineers
6. 1 transport/crypto specialist
7. 1 userspace/tooling engineer
8. 2 validation/lab engineers
9. 1 release/support engineer

Practical minimum: 12-14 engineers.

### Program B Time Estimate
1. 12-18 months for a serious partial-parity platform
2. 24-36 months for something approaching full parity with real confidence
3. Longer if NTFS parity requires substantial new filesystem work

### Program B Hard Truths
1. Short names, compression set, quotas, USN, EFS, and some metadata behaviors are not cleanly available through the current Linux VFS alone.
2. Full parity likely requires one of:
   - deep `ntfs3` expansion
   - a server-side metadata emulation layer
   - a dedicated backend that is effectively a new storage subsystem
3. RSVD/VHDX parity is feasible, but it is specialized storage work, not ordinary SMB work.
4. Full parity should be treated as a strategic product decision, not a backlog extension.

## Recommended Execution Strategy
1. Do Program A first.
2. Gate Program B after Program A milestone A3.
3. Separate NTFS parity from Hyper-V minimum support.
4. Refuse broad support claims until they are proven by the interoperability lab.

## Concrete Support Claims by Stage
### Safe claim after Program A
"Hyper-V over SMB on Linux-backed filesystems" for a bounded matrix.

### Unsafe claim before Program B completion
1. "Windows Server parity"
2. "Full NTFS compatibility"
3. "Cluster-grade Hyper-V storage"

## Acceptance Matrix
### Program A cannot ship unless all are true
1. Hyper-V can create and boot VMs from SMB shares reliably.
2. Network interruption does not corrupt active VM disks.
3. Persistent/durable reconnect is proven under stress.
4. Kerberos/domain auth is stable.
5. Crash/restart scenarios are tested and documented.

### Program B cannot claim parity unless all are true
1. Clustered Hyper-V scenarios are validated.
2. RSVD targeted workflows pass.
3. NTFS metadata behaviors are implemented or accurately emulated for claimed features.
4. Witness, multichannel, and failover behavior are stable.
5. Compatibility matrix is broad and repeatable.

## Next Documents
1. `IMPLEMENTATION_BOARD.md` turns this strategy into repo workstreams, deliverables, dependencies, and acceptance criteria.
2. Future design docs should split into:
   - transport/security
   - durability/state
   - NTFS metadata architecture
   - RSVD/VHDX platform
   - validation lab
