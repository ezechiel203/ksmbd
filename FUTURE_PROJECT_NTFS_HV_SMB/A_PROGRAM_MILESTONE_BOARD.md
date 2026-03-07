# Program A Milestone Board

## Purpose
This document expands Program A from `MEGAPLAN_WINDOWS_PARITY.md` into milestone-level deliverables, acceptance tests, and release gates.

Program A target:
- credible Hyper-V over SMB on Linux-backed filesystems
- no NTFS parity claim
- no RSVD claim
- no cluster-grade continuous-availability claim

## Scope Lock
Supported scope:
1. SMB 3.1.1 over TCP
2. optional QUIC if explicitly enabled
3. optional SMB Direct only after transport-security completion
4. VHDX files handled as ordinary files
5. Kerberos via userspace integration

Explicitly unsupported in Program A:
1. full NTFS parity
2. RSVD / shared VHDX / VHD Set
3. witness-driven cluster failover
4. full multichannel parity
5. EFS, USN, TxF, full 8.3 parity

## Milestone Format
Each milestone contains:
1. objective
2. code areas
3. deliverables
4. test matrix
5. exit criteria
6. block conditions

## A0: Contract Freeze
Status: `backlog`

### Objective
Freeze the exact product claim before engineering expands the scope.

### Deliverables
1. supported Windows Server versions
2. supported Hyper-V host versions
3. chosen backing filesystem set
4. chosen transports in scope
5. unsupported-features list
6. observability minimum set

### Decisions Required
1. Is QUIC in the first release?
2. Is SMB Direct in the first release?
3. Is multichannel in the first release?
4. Which Linux filesystems are supported?
5. Is domain-join mandatory for supported deployments?

### Acceptance
1. A written support matrix exists.
2. Marketing/support claims are frozen.
3. Test lab requirements are derived from that matrix.

### Block Conditions
1. No implementation begins without a frozen support matrix.

## A1: Transport and Crypto Hardening
Status: `backlog`

### Objective
Remove protocol and transport correctness gaps that would make Hyper-V workloads unsafe or non-interoperable.

### Code Areas
1. `src/transport/transport_quic.c`
2. `src/transport/transport_rdma.c`
3. `src/core/server.c`
4. `src/protocol/smb2/`

### Deliverables
1. QUIC Retry integrity fully correct
2. QUIC 1-RTT header protection key derivation fully correct
3. RDMA transform/signing/encryption complete if SMB Direct is in scope
4. no insecure fallback path remains in supported mode
5. transport failure logging is actionable

### Test Matrix
1. malformed packet handling
2. transport reconnect after interruption
3. signed session validation
4. encrypted session validation
5. QUIC interop against strict client stacks if QUIC is enabled
6. RDMA security tests if SMB Direct is enabled

### Acceptance
1. no open transport-security findings remain for supported transports
2. interop succeeds in supported transport matrix
3. packet processing never enters an authenticated state without required keys or handshake completion

### Block Conditions
1. If QUIC remains approximate, QUIC cannot be in the support claim.
2. If RDMA transform security remains incomplete, SMB Direct cannot be in the support claim.

## A2: Durable and Persistent Handle Reliability
Status: `in_progress`

### Objective
Make disconnect, reconnect, and restart behavior safe for active VM-disk workloads.

### Code Areas
1. `src/protocol/smb2/smb2_create.c`
2. `src/protocol/smb2/smb2_ph.c`
3. `src/fs/vfs_cache.c`
4. `src/fs/oplock.c`
5. related `src/protocol/smb2/` reconnect paths

### Deliverables
1. durable handle reconnect correctness
2. persistent handle save/restore correctness
3. lease/oplock reconstruction correctness
4. exact-ID reuse correctness
5. scavenger/timeout correctness
6. share-root confinement on restore
7. recovery-path logging and diagnostics

### Test Matrix
1. transient network disconnect during guest read/write workload
2. process restart and service restart during disconnected handle window
3. reconnect timeout expiration
4. multiple simultaneous durable handles on the same VHDX
5. lock survival and unlock after reconnect
6. crash consistency after restore failure

### Acceptance
1. reconnect under active guest I/O does not corrupt state
2. recovered handle semantics match live handle semantics for supported cases
3. no stale IDR mappings or handle leaks remain
4. restore failures do not delete valid persistent state prematurely

### Block Conditions
1. If reconnect remains unreliable under VM I/O, Program A cannot advance.

## A3: VM-Disk I/O Semantics
Status: `backlog`

### Objective
Validate and, where necessary, fix SMB I/O behavior so VHDX-as-file workloads are safe and stable.

### Code Areas
1. `src/protocol/smb2/smb2_read_write.c`
2. `src/protocol/smb2/smb2_ioctl.c`
3. `src/fs/vfs.c`
4. `src/fs/ksmbd_fsctl.c`
5. `src/fs/ksmbd_fsctl_extra.c`
6. `src/fs/ksmbd_info.c`

### Deliverables
1. flush/FUA behavior validated
2. sparse file and hole-punch semantics validated
3. zeroing semantics validated
4. file-size growth/truncation semantics validated
5. rename/delete/open conflict behavior validated for active VHDX usage
6. backup/checkpoint-sensitive patterns validated

### Test Matrix
1. create VHDX on share
2. attach VHDX to VM
3. boot from SMB-hosted VHDX
4. checkpoint and merge flow
5. heavy random write workload inside guest
6. host-side pause/resume and reconnect during guest I/O
7. filesystem crash/recovery verification after forced interruption

### Acceptance
1. Hyper-V create/attach/boot/checkpoint/merge passes in supported matrix
2. no guest-visible corruption after disconnect/reconnect or restart
3. no host-side metadata corruption on the backing filesystem

### Block Conditions
1. If any guest-disk corruption reproduces, Program A stops until resolved.

## A4: Authentication and Session Stability
Status: `backlog`

### Objective
Make domain-backed deployment stable and diagnosable.

### Code Areas
1. `src/protocol/smb2/smb2_session.c`
2. `src/core/connection.c`
3. `ksmbd-tools/`

### Deliverables
1. stable Kerberos/SPNEGO path
2. session expiry and reconnect behavior validated
3. ticket-refresh behavior validated
4. operational auth diagnostics added

### Test Matrix
1. domain-joined Hyper-V host repeated mount/connect cycles
2. long-lived session under ticket renewal
3. deliberate clock-skew and auth-failure tests
4. fallback behavior when userspace daemon is slow or unavailable

### Acceptance
1. domain auth works reliably in supported matrix
2. failures are diagnosable without source debugging
3. session behavior remains stable through long-running tests

### Block Conditions
1. If auth instability causes host disconnects or mount failures, Program A cannot ship.

## A5: Observability and Operations
Status: `backlog`

### Objective
Make the deployment operable in production.

### Code Areas
1. `src/core/`
2. `src/mgmt/`
3. `ksmbd-tools/`

### Deliverables
1. metrics for sessions, reconnects, handles, lease breaks, auth failures, transport failures, I/O errors
2. runbooks for outage, restart, and upgrade scenarios
3. baseline tuning guidance for VM-storage workloads
4. clear event/log taxonomy

### Test Matrix
1. soak runs with metrics capture
2. operator drill: restart service, rotate logs, inspect failure, recover host connectivity
3. tuning comparisons for supported filesystems and workloads

### Acceptance
1. operator guidance exists and is validated
2. enough metrics exist to triage performance and reliability issues
3. restart and maintenance procedures are documented

### Block Conditions
1. If production debugging still requires ad hoc kernel tracing, Program A is not operationally ready.

## A6: Hyper-V Qualification Lab
Status: `backlog`

### Objective
Make support claims evidence-based.

### Deliverables
1. Windows/Hyper-V version matrix
2. Linux backing-filesystem matrix
3. transport matrix
4. scripted create/boot/checkpoint/merge/reconnect tests
5. soak and crash-injection tests

### Infrastructure Requirements
1. at least two Windows host versions
2. at least one domain-backed environment
3. controlled network fault injection
4. reproducible VM images
5. reproducible share provisioning

### Acceptance
1. every support claim maps to a passing test slice
2. unsupported combinations are explicitly recorded
3. release gating depends on this lab

### Block Conditions
1. No Program A release without a passing lab matrix.

## Release Gate
Program A release is blocked unless all of the following are true:
1. A0 through A6 are complete for the supported matrix
2. no data-integrity bug remains open for VHDX-backed guest workloads
3. no transport-security gap remains open for supported transports
4. reconnect semantics are proven under stress
5. domain-auth deployment is stable if domain auth is in the support claim

## Suggested Parallelization
1. A1 and A2 can overlap partially
2. A6 must start early, not after implementation is "done"
3. A3 should begin as soon as A2 reaches basic reconnect stability
4. A5 should start once metrics insertion points are known, not at the very end

## Suggested Program A Success Statement
A valid Program A release claim looks like this:
"Hyper-V over SMB 3.1.1 on the documented Linux-backed filesystem and Windows/Hyper-V version matrix, with the documented transport and authentication constraints."

A claim that must not be made at Program A completion:
"Windows Server parity"
