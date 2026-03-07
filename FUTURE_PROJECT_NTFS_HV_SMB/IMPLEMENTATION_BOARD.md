# Implementation Board

## Purpose
This board translates the strategic roadmap in `MEGAPLAN_WINDOWS_PARITY.md` into concrete implementation work packages for this repository and adjacent validation/tooling work.

## Board Rules
1. Program A and Program B must not share milestone definitions.
2. Every work package needs an owner, dependencies, test plan, and claim boundary.
3. No feature is considered complete until Windows interoperability has been tested for the claimed scenario.
4. No support claim should exceed the verified matrix.

## Status Legend
- `backlog`: not started
- `scoping`: design not frozen
- `in_progress`: active engineering
- `blocked`: waiting on dependency or architecture decision
- `done`: code, tests, and documentation complete

## Program A Board
### A-01 Transport Security Hardening
Status: `backlog`

Subsystems:
- `src/transport/transport_quic.c`
- `src/transport/transport_rdma.c`
- `src/core/server.c`

Deliverables:
1. QUIC Retry integrity is fully RFC-correct.
2. QUIC 1-RTT header protection uses correct derived keys.
3. RDMA transform security is implemented for any claimed SMB Direct mode.
4. No insecure transport fallback is reachable in production mode.

Dependencies:
1. TLS 1.3 key schedule design notes
2. transport-specific interop lab access

Validation:
1. protocol regression tests
2. client interop tests
3. negative tests for malformed packets and uninitialized keys

Exit criteria:
1. no review-blocking transport findings remain
2. interoperability is proven for claimed transports

### A-02 Durable and Persistent Handle Reliability
Status: `in_progress`

Subsystems:
- `src/protocol/smb2/smb2_create.c`
- `src/protocol/smb2/smb2_ph.c`
- `src/fs/vfs_cache.c`
- `src/fs/oplock.c`

Deliverables:
1. durable reconnect correctness
2. persistent-handle save/restore correctness
3. lease/oplock restore correctness
4. timeout and scavenger correctness
5. crash/restart recovery semantics defined and tested

Dependencies:
1. transport stability from A-01
2. fault-injection test harness

Validation:
1. disconnect/reconnect under VM I/O
2. process restart / service restart tests
3. handle table consistency checks

Exit criteria:
1. no stale-ID or restore-path corruption
2. reconnect works under active guest load

### A-03 VM-Disk I/O Correctness
Status: `backlog`

Subsystems:
- `src/fs/vfs.c`
- `src/fs/ksmbd_fsctl*.c`
- `src/protocol/smb2/smb2_read_write.c`
- `src/protocol/smb2/smb2_ioctl.c`

Deliverables:
1. flush/FUA semantics validated
2. sparse file and zero-range semantics validated
3. checkpoint/merge-sensitive flows validated
4. crash-ordering behavior characterized

Dependencies:
1. A-02
2. test VHDX workload harness

Validation:
1. Hyper-V create/attach/boot/checkpoint/merge
2. power-loss and reconnect tests
3. filesystem consistency verification after stress

Exit criteria:
1. no disk-integrity regressions in supported matrix

### A-04 Auth and Session Stability
Status: `backlog`

Subsystems:
- `src/protocol/smb2/smb2_session.c`
- `src/core/connection.c`
- `ksmbd-tools/`

Deliverables:
1. stable Kerberos/SPNEGO flow
2. domain-join operational guidance
3. auth/session diagnostics

Dependencies:
1. domain test environment
2. userspace daemon stability

Validation:
1. long-run domain-auth tests
2. reconnect after ticket refresh
3. negative auth-path testing

Exit criteria:
1. auth issues are diagnosable without tracing kernel internals

### A-05 Performance and Operations
Status: `backlog`

Subsystems:
- `src/core/`
- `src/mgmt/`
- `ksmbd-tools/`

Deliverables:
1. metrics for sessions, handles, reconnects, errors, and latency
2. recommended tuning profiles
3. production runbooks

Dependencies:
1. A-02
2. A-03

Validation:
1. soak tests
2. boot storm tests
3. mixed I/O tests

Exit criteria:
1. operator-facing observability exists
2. tuning guidance is reproducible

### A-06 Hyper-V Qualification Lab
Status: `backlog`

Subsystems:
- future `tests/` tree
- external Windows lab automation

Deliverables:
1. compatibility matrix
2. scripted host-side test scenarios
3. crash/reconnect automation

Dependencies:
1. Windows Server and Hyper-V environments
2. image and VM templates

Validation:
1. repeatable pass/fail runs
2. long-haul soak

Exit criteria:
1. support claim is tied to a published matrix

## Program B Board
### B-01 Multichannel and Witness
Status: `backlog`

Subsystems:
- `src/protocol/smb2/`
- `src/core/`
- `src/mgmt/ksmbd_witness.*`

Deliverables:
1. multichannel maturity
2. interface-list accuracy
3. witness correctness
4. failover-aware connection grouping

Dependencies:
1. Program A baseline
2. multi-NIC lab

Validation:
1. multi-NIC failover and rebalance tests
2. witness notification tests

Exit criteria:
1. behavior matches claimed failover model

### B-02 Continuous Availability and Failover State
Status: `backlog`

Subsystems:
- `src/core/`
- `src/fs/`
- `src/protocol/smb2/`

Deliverables:
1. failover-safe durable state model
2. handle/lease/lock state continuity across failover
3. recovery-state coordination between nodes or shared state

Dependencies:
1. B-01
2. state-replication or shared-state architecture

Validation:
1. planned failover
2. unplanned failover
3. split-brain and recovery negative tests

Exit criteria:
1. failover does not violate support claims

### B-03 NTFS Architecture Decision
Status: `scoping`

Subsystems:
- architecture only, potentially extends beyond this repo

Options:
1. extend `ntfs3`
2. metadata emulation layer in/alongside ksmbd
3. dedicated NTFS-aware backend/service

Deliverables:
1. decision memo
2. risk matrix
3. crash-consistency model
4. performance model

Dependencies:
1. proof-of-concept prototypes
2. filesystem expertise

Exit criteria:
1. one architecture is chosen and budgeted

### B-04 NTFS Metadata Compatibility Layer
Status: `blocked`
Blocked by: `B-03`

Subsystems:
- `src/fs/`
- `src/protocol/smb2/`
- potentially adjacent backend code outside this repo

Target features:
1. short names
2. object IDs
3. compression get/set
4. quota semantics
5. reparse metadata fidelity
6. USN-like journal strategy if in scope

Validation:
1. Windows admin-tool compatibility
2. metadata query/set interop
3. crash-recovery correctness

Exit criteria:
1. only claimed features are exposed as supported

### B-05 RSVD and VHDX Platform
Status: `backlog`

Subsystems:
- `src/fs/ksmbd_rsvd.c`
- future VHDX backend code

Deliverables:
1. SCSI tunnel implementation
2. metadata queries
3. resize support
4. snapshot-related support for claimed workflows
5. reservation semantics

Dependencies:
1. VHDX format implementation or backend
2. Hyper-V shared-disk lab

Validation:
1. RSVD command coverage
2. shared-disk scenarios
3. conflict and recovery tests

Exit criteria:
1. targeted RSVD paths no longer return generic not-supported responses

### B-06 SMB Direct Full Security
Status: `backlog`

Subsystems:
- `src/transport/transport_rdma.c`
- `src/protocol/smb2/`

Deliverables:
1. transform-header correctness
2. encryption/signing semantics over RDMA
3. negative-path verification

Dependencies:
1. RDMA hardware lab
2. transport key-management design

Validation:
1. SMB Direct interop
2. failure-injection tests

Exit criteria:
1. no plaintext RDMA path remains in supported mode

### B-07 BranchCache Completion
Status: `backlog`

Subsystems:
- `src/fs/ksmbd_branchcache.c`

Deliverables:
1. content-hash lookup completion
2. metadata and lifecycle handling

Dependencies:
1. hash storage design

Validation:
1. Windows client BranchCache tests

Exit criteria:
1. retrieval path is real, not stubbed

### B-08 FSCTL and Info-Class Completion
Status: `backlog`

Subsystems:
- `src/fs/ksmbd_info.*`
- `src/fs/ksmbd_fsctl*.c`
- `src/protocol/smb2/smb2_query_set.c`
- `src/protocol/smb1/smb1pdu.c`

Deliverables:
1. volume label set/get where meaningful
2. quota query/set where meaningful
3. blocking pipe wait
4. missing SMB1 info levels only if SMB1 remains a supported target
5. compression and metadata behavior mapped accurately to backing FS support

Dependencies:
1. product claim decisions
2. NTFS architecture for NTFS-specific semantics

Validation:
1. Windows admin workflow tests
2. negative tests for unsupported paths

Exit criteria:
1. each unsupported path returns a deliberate, documented result

### B-09 Validation Infrastructure and Release Gating
Status: `backlog`

Subsystems:
- future `tests/`
- CI/lab integration
- release automation

Deliverables:
1. Windows version matrix
2. Hyper-V matrix
3. filesystem matrix
4. transport matrix
5. cluster matrix
6. failure-injection matrix

Dependencies:
1. dedicated lab infrastructure
2. release engineering ownership

Validation:
1. every release candidate gates on matrix results

Exit criteria:
1. parity claims are evidence-backed

## Dependencies Graph
1. Program A is a prerequisite for Program B.
2. `A-02` depends on `A-01` enough to make reconnect paths testable.
3. `A-03` depends on `A-02`.
4. `A-06` spans the entire Program A and must start early.
5. `B-03` is the gate for `B-04`.
6. `B-01` and `B-02` are prerequisites for any credible cluster-grade Hyper-V claim.
7. `B-05` requires dedicated virtual-disk design and lab capacity.

## Proposed Order of Execution
### Program A
1. A-01
2. A-02
3. A-06 starts in parallel as soon as test scaffolding exists
4. A-03
5. A-04
6. A-05
7. A4 milestone signoff

### Program B
1. B-01
2. B-02
3. B-03
4. B-05 and B-04 in parallel after architecture freeze where possible
5. B-06
6. B-08
7. B-09 as permanent release gate

## Claims Control
### Allowed claims after Program A
1. Hyper-V over SMB on Linux-backed filesystems for the verified matrix
2. No NTFS parity claim
3. No RSVD/cluster-grade claim

### Allowed claims after Program B
Only the features validated in the published compatibility matrix.

## Immediate Next Planning Artifacts
1. `A_PROGRAM_MILESTONE_BOARD.md`
2. `B_PROGRAM_FEASIBILITY_DECISION.md`
3. `NTFS_BACKEND_ARCHITECTURE_OPTIONS.md`
4. `RSVD_VHDX_BACKEND_REQUIREMENTS.md`
5. `WINDOWS_INTEROP_LAB_PLAN.md`
