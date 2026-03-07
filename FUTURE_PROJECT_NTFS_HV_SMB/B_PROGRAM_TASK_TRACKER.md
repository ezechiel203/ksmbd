# Program B Task Tracker

## Purpose
Track the concrete work packages that would exist only if Program B is formally approved.

## Important Rule
Program B tasks are planning-level until Program B is explicitly approved. No implementation should start from this file alone.

## Task Status Legend
- `planning`
- `gated`
- `active`
- `blocked`
- `done`

## B0 Approval and Architecture
### B0-T1 Program B Approval Memo
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B0_T1_PROGRAM_B_APPROVAL_MEMO.md`

Output:
1. explicit yes/no approval
2. business justification
3. staffing commitment
4. lab funding commitment

### B0-T2 NTFS Strategy Selection
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B0_T2_NTFS_STRATEGY_SELECTION.md`

Primary design doc:
1. `NTFS_BACKEND_ARCHITECTURE_OPTIONS.md`

Output:
1. chosen architecture
2. rejected architectures
3. crash-consistency model

### B0-T3 RSVD Scope Selection
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B0_T3_RSVD_SCOPE_SELECTION.md`

Primary design doc:
1. `RSVD_VHDX_BACKEND_REQUIREMENTS.md`

Output:
1. exact workflow scope
2. unsupported workflow list
3. backend ownership

### B0-T4 Failover Position Selection
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B0_T4_FAILOVER_POSITION_SELECTION.md`

Primary design doc:
1. `CLUSTER_FAILOVER_STATE_MODEL.md`

Output:
1. no cluster claim, bounded failover, or strategic cluster-grade decision
2. state-sharing model

## B1 SMB Platform Foundation
### B1-T1 Multichannel Maturity
Status: `gated`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B1_T1_MULTICHANNEL_MATURITY.md`

Primary files:
1. `src/protocol/smb2/`
2. `src/core/`

Output:
1. multi-channel behavior model
2. supported interface reporting
3. validation matrix

### B1-T2 Witness Maturity
Status: `gated`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B1_T2_WITNESS_MATURITY.md`

Primary files:
1. `src/mgmt/ksmbd_witness.*`
2. `src/core/`

Output:
1. witness behavior definition
2. failover notification validation

### B1-T3 RDMA Secure Transport Completion
Status: `gated`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B1_T3_RDMA_SECURE_TRANSPORT_COMPLETION.md`

Primary files:
1. `src/transport/transport_rdma.c`

Output:
1. transform-header correctness
2. supported RDMA security modes

## B2 Standalone Hyper-V Plus
### B2-T1 Broader Hyper-V Matrix Expansion
Status: `gated`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B2_T1_BROADER_HYPERV_MATRIX_EXPANSION.md`

Output:
1. more Windows/Hyper-V versions
2. more workload types
3. stronger operations model

### B2-T2 Program A Carry-Forward Hardening
Status: `gated`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B2_T2_PROGRAM_A_CARRY_FORWARD_HARDENING.md`

Output:
1. any Program A residual issues cleared before parity claims grow

## B3 NTFS Compatibility
### B3-T1 Short Name Strategy Prototype
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B3_T1_SHORT_NAME_STRATEGY_PROTOTYPE.md`

Potential code areas:
1. `src/fs/`
2. `src/protocol/smb2/`
3. architecture-dependent metadata layer

Output:
1. exact storage model
2. generation policy
3. rename/update semantics

### B3-T2 Compression Set Semantics Prototype
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B3_T2_COMPRESSION_SET_SEMANTICS_PROTOTYPE.md`

Potential code areas:
1. `src/fs/ksmbd_fsctl.c`
2. filesystem/backend-specific code

Output:
1. whether compression is real, emulated, or unsupported
2. exact claim boundary

### B3-T3 Object ID and Metadata Surface Prototype
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B3_T3_OBJECT_ID_AND_METADATA_SURFACE_PROTOTYPE.md`

Output:
1. metadata storage strategy
2. admin/workflow tests

### B3-T4 Quota Semantics Strategy
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B3_T4_QUOTA_SEMANTICS_STRATEGY.md`

Output:
1. whether quotas are Linux-backed, emulated, or unsupported
2. exact Windows-visible behavior claim

## B4 RSVD and VHDX Platform
### B4-T1 RSVD Command Matrix
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B4_T1_RSVD_COMMAND_MATRIX.md`

Primary files:
1. `src/fs/ksmbd_rsvd.c`

Output:
1. allowed command matrix
2. unsupported command matrix
3. error mapping

### B4-T2 Reservation State Model
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B4_T2_RESERVATION_STATE_MODEL.md`

Output:
1. registration ownership
2. persistence model
3. reconnect/failover semantics

### B4-T3 VHDX Backend Feasibility Prototype
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B4_T3_VHDX_BACKEND_FEASIBILITY_PROTOTYPE.md`

Output:
1. metadata handling approach
2. resize path
3. recovery model

## B5 Cluster and Failover
### B5-T1 Shared-State Architecture
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B5_T1_SHARED_STATE_ARCHITECTURE.md`

Output:
1. shared vs replicated state decision
2. session/handle/lease/lock ownership rules

### B5-T2 Failover Negative-Path Test Design
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B5_T2_FAILOVER_NEGATIVE_PATH_TEST_DESIGN.md`

Output:
1. node death cases
2. split-brain cases
3. partial state-sync cases

### B5-T3 Witness-Driven Recovery Flow
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B5_T3_WITNESS_DRIVEN_RECOVERY_FLOW.md`

Output:
1. claimed recovery path
2. unsupported failover path list

## B6 Qualification and Claims
### B6-T1 Program B Matrix Definition
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B6_T1_PROGRAM_B_MATRIX_DEFINITION.md`

Output:
1. version matrix
2. transport matrix
3. filesystem matrix
4. cluster matrix if claimed
5. RSVD matrix if claimed

### B6-T2 Release Claims Draft
Status: `planning`

Technical doc:
1. `PROGRAM_B_TECHNICAL/B6_T2_RELEASE_CLAIMS_DRAFT.md`

Primary doc:
1. `PROGRAM_B_RELEASE_CLAIMS.md`

Output:
1. allowed wording for the first Program B release
2. forbidden wording list

## Program B Hard Gates
1. No B1+ work without B0 approval.
2. No NTFS compatibility implementation without B0-T2.
3. No RSVD implementation without B0-T3.
4. No cluster-grade claim without B0-T4 and dedicated failover lab.
