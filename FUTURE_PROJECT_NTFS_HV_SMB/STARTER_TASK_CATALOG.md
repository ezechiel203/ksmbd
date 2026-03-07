# Starter Task Catalog

## Purpose
List safe first contributions for junior developers, with exact source areas, risk level, expected outcome, and why the task is appropriate.

## Rules
A starter task should:
1. stay inside Program A scope
2. avoid broad architecture changes
3. avoid hidden data-integrity risk
4. have a clear success condition
5. be reviewable in one sitting

## Risk Levels
- `low`: safe for a junior contributor with normal review
- `medium`: acceptable only with close guidance
- `high`: not a starter task

## Category 1: Documentation and Invariants
### T-001 Clarify Durable-Handle Invariants
Risk: `low`

Primary files:
1. [src/protocol/smb2/smb2_ph.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_ph.c)
2. [src/fs/vfs_cache.c](/home/ezechiel203/ksmbd/src/fs/vfs_cache.c)

Task:
1. add or improve short comments that explain critical restore/reconnect invariants
2. document why a given cleanup path must happen in a specific order

Why it is safe:
1. mostly clarifies behavior rather than changing it
2. helps future reviewers understand dangerous state transitions

Success condition:
1. comments are accurate, short, and attached to genuinely tricky logic

### T-002 Document Support Boundaries Near Unsupported Paths
Risk: `low`

Primary files:
1. [src/fs/ksmbd_info.c](/home/ezechiel203/ksmbd/src/fs/ksmbd_info.c)
2. [src/fs/ksmbd_rsvd.c](/home/ezechiel203/ksmbd/src/fs/ksmbd_rsvd.c)
3. [src/fs/ksmbd_fsctl.c](/home/ezechiel203/ksmbd/src/fs/ksmbd_fsctl.c)

Task:
1. improve comments around deliberate `NOT_SUPPORTED` or no-op behavior
2. make the reason explicit where current comments are weak or stale

Why it is safe:
1. does not change semantics
2. reduces future confusion between Program A and Program B work

Success condition:
1. unsupported paths are easier to understand without reading planning docs first

## Category 2: Logging and Diagnostics
### T-003 Improve Reconnect Failure Logging
Risk: `low`

Primary files:
1. [src/protocol/smb2/smb2_create.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c)
2. [src/protocol/smb2/smb2_ph.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_ph.c)

Task:
1. improve logging on reconnect failure branches
2. make logs distinguish common causes such as timeout, GUID mismatch, missing state, or share-root rejection

Why it is safe:
1. improves diagnosability without changing protocol behavior
2. directly helps Program A operations work

Success condition:
1. failure logs are more specific and remain rate-limited where needed

### T-004 Improve Auth Failure Diagnostics
Risk: `low`

Primary files:
1. [src/protocol/smb2/smb2_session.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_session.c)
2. [ksmbd-tools/](/home/ezechiel203/ksmbd/ksmbd-tools)

Task:
1. identify vague auth/session failure logs
2. tighten wording so a future operator can distinguish likely failure classes

Why it is safe:
1. mainly improves operations and debugging
2. stays inside Program A support needs

Success condition:
1. common auth failures become easier to triage from logs alone

## Category 3: Validation and Test Scaffolding
### T-005 Write a Matrix Slice Note for One Program A Workflow
Risk: `low`

Primary docs:
1. [WINDOWS_INTEROP_LAB_PLAN.md](/home/ezechiel203/ksmbd/FUTURE_PROJECT_NTFS_HV_SMB/WINDOWS_INTEROP_LAB_PLAN.md)
2. [A_PROGRAM_TASK_TRACKER.md](/home/ezechiel203/ksmbd/FUTURE_PROJECT_NTFS_HV_SMB/A_PROGRAM_TASK_TRACKER.md)

Task:
1. write one explicit matrix slice for a supported Program A scenario
2. example: one Windows version, one Hyper-V version, one filesystem, TCP, domain auth

Why it is safe:
1. no code changes required
2. teaches the contributor to think in support matrices instead of vague claims

Success condition:
1. the matrix slice is precise enough to be turned into a test case later

### T-006 Write a Plain-English Trace Note for One Request Path
Risk: `low`

Primary files:
1. [src/protocol/smb2/smb2_session.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_session.c)
2. [src/protocol/smb2/smb2_create.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c)
3. [src/fs/vfs_cache.c](/home/ezechiel203/ksmbd/src/fs/vfs_cache.c)

Task:
1. trace one path end to end
2. write a short internal note in plain English explaining how state moves through it

Why it is safe:
1. builds understanding before modification
2. creates useful onboarding material for others

Success condition:
1. another developer can read the note and follow the path more quickly

## Category 4: Small Behavior Cleanups
### T-007 Tighten a Deliberate Unsupported Return Path
Risk: `medium`

Primary files:
1. [src/fs/ksmbd_info.c](/home/ezechiel203/ksmbd/src/fs/ksmbd_info.c)
2. [src/fs/ksmbd_fsctl_extra.c](/home/ezechiel203/ksmbd/src/fs/ksmbd_fsctl_extra.c)
3. [src/protocol/smb2/smb2_query_set.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_query_set.c)

Task:
1. find a path that currently returns a vague error or misleading success
2. tighten it to the correct deliberate unsupported behavior

Why it is only medium risk:
1. even small semantic changes can affect client-visible behavior
2. requires exact understanding of intended support boundary

Success condition:
1. behavior becomes more honest and better documented without breaking supported workflows

### T-008 Improve QUIC TODO Comment Accuracy Without Behavior Change
Risk: `low`

Primary file:
1. [src/transport/transport_quic.c](/home/ezechiel203/ksmbd/src/transport/transport_quic.c)

Task:
1. find stale or misleading TODO/comment text
2. align comments with actual current state of implementation

Why it is safe:
1. does not change transport behavior
2. reduces confusion in a complex file

Success condition:
1. comments match actual code state and open gaps

## Category 5: Metrics and Observability Notes
### T-009 Metrics Insertion-Point Inventory
Risk: `low`

Primary files:
1. [src/core/](/home/ezechiel203/ksmbd/src/core)
2. [src/fs/](/home/ezechiel203/ksmbd/src/fs)
3. [src/protocol/smb2/](/home/ezechiel203/ksmbd/src/protocol/smb2)

Task:
1. identify where counters or timing hooks would logically go for reconnect failures, auth failures, and lease breaks
2. write the inventory as a planning note

Why it is safe:
1. no production behavior changes
2. directly supports Program A operational readiness

Success condition:
1. the team can use the note to implement metrics later with less exploration

## Not Starter Tasks
These should not be assigned as first contributions.

### N-001 Transport Security Logic Changes
Examples:
1. QUIC key derivation changes
2. RDMA transform security changes

Why not:
1. high protocol and interop risk

### N-002 Reconnect State Logic Changes
Examples:
1. handle-restore semantics
2. persistent-ID assignment logic
3. lease reconstruction changes

Why not:
1. high data-integrity and state-consistency risk

### N-003 Flush or Write-Ordering Changes
Examples:
1. write path changes
2. flush semantics changes
3. sparse/zeroing behavior changes

Why not:
1. direct VM-disk integrity risk

### N-004 RSVD, NTFS Parity, or Failover Work
Examples:
1. `ksmbd_rsvd.c` implementation work
2. metadata-emulation experiments
3. cluster-state changes

Why not:
1. this is Program B scope and too large for starter work

## Recommended First Three Starter Tasks
If a junior contributor asked for the safest sequence, assign in this order:
1. `T-006` Write a plain-English trace note for one request path
2. `T-003` Improve reconnect failure logging
3. `T-001` Clarify durable-handle invariants

## Mentor Notes
A mentor should check that the contributor:
1. understands why the task is safe
2. understands what behavior must not change
3. can explain the relevant support boundary before editing anything
