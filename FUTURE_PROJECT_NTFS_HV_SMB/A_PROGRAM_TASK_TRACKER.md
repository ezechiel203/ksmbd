# Program A Task Tracker

## Purpose
Translate the Program A milestones into concrete task packages with sequencing and ownership expectations.

## Task Status Legend
- `todo`
- `active`
- `blocked`
- `done`

## A0 Scope Freeze
### A0-T1 Support Matrix Draft
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A0_T1_SUPPORT_MATRIX_DRAFT.md`

Output:
1. Windows Server versions
2. Hyper-V host versions
3. `xfs` and `ext4` backing-filesystem matrix
4. TCP-only transport statement
5. auth modes in scope

Dependencies:
- decision proposals D-001 through D-003

### A0-T2 Unsupported Features Statement
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A0_T2_UNSUPPORTED_FEATURES_STATEMENT.md`

Output:
1. no RSVD
2. no SMB Direct
3. no cluster-grade failover
4. no NTFS parity
5. no QUIC in first support claim

Dependencies:
- D-001, D-002, D-006, D-007

## A1 Transport and Crypto
### A1-T1 QUIC Retry Integrity Review and Completion
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A1_T1_QUIC_RETRY_INTEGRITY_REVIEW_COMPLETION.md`

Primary files:
1. `src/transport/transport_quic.c`

Output:
1. RFC-correct Retry integrity path
2. interop tests for Retry behavior

### A1-T2 QUIC 1-RTT Header Protection Key Separation
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A1_T2_QUIC_1RTT_HEADER_PROTECTION_KEY_SEPARATION.md`

Primary files:
1. `src/transport/transport_quic.c`

Output:
1. separate HP key derivation and storage
2. strict-path validation for packet processing

### A1-T3 TCP Security Regression Sweep
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A1_T3_TCP_SECURITY_REGRESSION_SWEEP.md`

Primary files:
1. `src/core/server.c`
2. `src/protocol/smb2/`

Output:
1. signing/encryption/preauth regression coverage
2. negative-path test list

## A2 Durable and Persistent State
### A2-T1 Persistent Handle Recovery Qualification
Status: `active`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A2_T1_PERSISTENT_HANDLE_RECOVERY_QUALIFICATION.md`

Primary files:
1. `src/protocol/smb2/smb2_ph.c`
2. `src/protocol/smb2/smb2_create.c`
3. `src/fs/vfs_cache.c`
4. `src/fs/oplock.c`

Output:
1. recovery-path test matrix
2. reconnect stress results
3. failure-mode notes

### A2-T2 Lock and Lease Survival Under Reconnect
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A2_T2_LOCK_AND_LEASE_RECONNECT_QUALIFICATION.md`

Primary files:
1. `src/fs/oplock.c`
2. `src/protocol/smb2/smb2_lock.c`
3. `src/fs/vfs_cache.c`

Output:
1. reconnect with outstanding locks
2. reconnect with lease-backed opens
3. known unsupported edge cases documented

### A2-T3 Crash/Restart Semantics Drill
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A2_T3_CRASH_RESTART_SEMANTICS_DRILL.md`

Primary files:
1. `src/core/`
2. `src/fs/`
3. `src/protocol/smb2/`

Output:
1. service restart behavior under disconnected durable window
2. expected and unexpected failure cases

## A3 VM-Disk I/O Semantics
### A3-T1 Flush/FUA Validation
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A3_T1_FLUSH_FUA_VALIDATION.md`

Primary files:
1. `src/protocol/smb2/smb2_read_write.c`
2. `src/protocol/smb2/smb2_ioctl.c`
3. `src/fs/vfs.c`

Output:
1. validated flush semantics under Hyper-V workload
2. known caveats recorded

### A3-T2 Sparse/Zeroing Behavior Qualification
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A3_T2_SPARSE_ZEROING_BEHAVIOR_QUALIFICATION.md`

Primary files:
1. `src/fs/ksmbd_fsctl.c`
2. `src/fs/vfs.c`
3. `src/protocol/smb2/smb2_ioctl.c`

Output:
1. sparse allocation behavior matrix
2. zero-range behavior matrix

### A3-T3 Checkpoint/Merge Flow Validation
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A3_T3_CHECKPOINT_MERGE_FLOW_VALIDATION.md`

Primary files:
1. primarily validation-driven, with fixes likely in `src/fs/` and `src/protocol/smb2/`

Output:
1. Hyper-V checkpoint and merge pass/fail matrix
2. patch list for any discovered issues

## A4 Auth and Session Stability
### A4-T1 Domain Auth Reliability Sweep
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A4_T1_DOMAIN_AUTH_RELIABILITY_SWEEP.md`

Primary files:
1. `src/protocol/smb2/smb2_session.c`
2. `ksmbd-tools/`

Output:
1. repeated domain-auth validation
2. auth failure diagnostics checklist

### A4-T2 Session Rebind and Ticket Refresh Tests
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A4_T2_SESSION_REBIND_TICKET_REFRESH_TESTS.md`

Primary files:
1. `src/protocol/smb2/smb2_session.c`
2. `src/core/connection.c`

Output:
1. long-lived auth/session behavior notes
2. fixes for ticket-refresh instability if found

## A5 Observability and Operations
### A5-T1 Metrics Inventory
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A5_T1_METRICS_INVENTORY.md`

Primary files:
1. `src/core/`
2. `src/mgmt/`
3. `ksmbd-tools/`

Output:
1. metrics list
2. insertion points
3. missing instrumentation list

### A5-T2 Runbook Drafting
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A5_T2_RUNBOOK_DRAFT.md`

Output:
1. outage recovery
2. service restart
3. upgrade/restart guidance
4. debugging checklists

## A6 Interop Lab
### A6-T1 Program A Matrix Definition
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A6_T1_PROGRAM_A_MATRIX_DEFINITION.md`

Output:
1. Windows versions
2. Hyper-V versions
3. filesystems
4. auth modes
5. transport modes

### A6-T2 Automated VM Lifecycle Tests
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A6_T2_AUTOMATED_VM_LIFECYCLE_TESTS.md`

Output:
1. create
2. attach
3. boot
4. checkpoint
5. merge
6. reconnect under load

### A6-T3 Soak and Fault Injection
Status: `todo`

Technical doc:
1. `PROGRAM_A_TECHNICAL/A6_T3_SOAK_AND_FAULT_INJECTION.md`

Output:
1. long-run stress scripts
2. network flap tests
3. service restart tests
4. artifact collection bundle

## Program A Critical Path
1. A0-T1
2. A0-T2
3. A2-T1
4. A2-T2
5. A3-T1
6. A3-T2
7. A3-T3
8. A4-T1
9. A6-T1
10. A6-T2
11. A6-T3
12. A5-T1
13. A5-T2

## Program A Ship Blockers
1. any unresolved guest-disk corruption issue
2. any reconnect path that loses correctness under VM I/O
3. domain-auth instability if domain auth is in scope
4. lack of passing Program A matrix in the interoperability lab
