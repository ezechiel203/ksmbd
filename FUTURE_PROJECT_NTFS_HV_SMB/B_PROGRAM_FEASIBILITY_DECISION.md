# Program B Feasibility Decision

## Purpose
This document exists to prevent accidental commitment to a multi-year Windows parity program without explicit architectural and budget decisions.

Program B target:
- Windows Server SMB parity
- NTFS-visible metadata and semantic compatibility for claimed features
- Hyper-V advanced workflows
- potentially cluster-grade behavior

That is not an incremental extension of Program A. It is a platform decision.

## Core Question
Should the project commit to Program B at all?

Default answer:
- `No`, unless there is specific product demand strong enough to justify a large dedicated team, a Windows interoperability lab, and likely new backend/filesystem work beyond normal ksmbd feature completion.

## Why Program B Is Different
Program A is mostly about SMB correctness and operational quality.

Program B adds categories that are structurally harder:
1. NTFS-specific metadata behavior not exposed cleanly via Linux VFS
2. Windows-specific storage semantics for Hyper-V shared-disk paths
3. cluster and failover semantics that require infrastructure, not just protocol handlers
4. release qualification that depends on large interoperability matrices

## Decision Framework
Program B should proceed only if all four questions are answered positively.

### 1. Market Need
Questions:
1. Is there a paying requirement for Windows parity, or only for Hyper-V-over-SMB?
2. Are RSVD/shared-disk workflows actually required?
3. Is clustered Hyper-V a requirement, or would standalone Hyper-V satisfy the demand?
4. Are Windows administrative metadata behaviors actually required, or only guest-disk storage semantics?

Decision rule:
- If the market need is only standalone Hyper-V storage, stop at Program A.

### 2. Architecture Tolerance
Questions:
1. Is the project willing to extend `ntfs3` materially?
2. Is it willing to build a metadata emulation layer?
3. Is it willing to build a dedicated VHDX/RSVD backend?
4. Is it willing to carry behavior that diverges from normal Linux filesystem abstractions?

Decision rule:
- If the answer to these is mostly "no", Program B is not feasible.

### 3. Validation Budget
Questions:
1. Is there budget for a Windows/Hyper-V/cluster interoperability lab?
2. Is there budget for long-haul soak testing and failure injection?
3. Is there staffing for release gating based on lab outcomes?

Decision rule:
- If the lab cannot be funded, Program B should not be claimed.

### 4. Team Size and Duration
Questions:
1. Is there a 12-14 engineer team available?
2. Is there executive support for a 12-36 month roadmap?
3. Is there a single architecture owner across SMB, filesystem, and virtual-disk semantics?

Decision rule:
- If not, Program B should not start.

## Feature Classification
### Feasible with High Confidence
These are difficult but normal engineering tasks within the SMB server domain.
1. multichannel maturity
2. witness improvements
3. transport crypto completeness
4. broader FSCTL and info-class coverage
5. stronger reconnect and failover primitives
6. BranchCache completion

### Feasible but Requires Dedicated Storage/Cluster Work
These are possible, but they are not ordinary ksmbd feature tasks.
1. RSVD SCSI tunnel
2. VHDX metadata and geometry operations
3. reservation semantics for Hyper-V shared-disk scenarios
4. failover-safe state management
5. cluster-aware connection management

### Feasible Only with New NTFS Strategy
These are not realistically solved through the current Linux VFS surface alone.
1. short-name parity
2. compression set semantics
3. object IDs
4. quotas with Windows-like semantics
5. USN-like behavior
6. selected Windows metadata and namespace quirks

### Poor ROI or Strategic Risk
These require very strong justification even if technically possible.
1. EFS-equivalent behavior
2. exact Windows parity for deprecated or low-value NTFS features
3. very broad SMB1 parity beyond targeted compatibility needs
4. feature claims that create indefinite compatibility burden with low customer value

## Architecture Decision Gates
These must be frozen before Program B engineering begins in earnest.

### Gate B-ARCH-1: NTFS Strategy
Choose one:
1. extend `ntfs3`
2. metadata emulation layer
3. dedicated NTFS-aware backend/service

Required output:
1. design memo
2. failure model
3. performance model
4. supportability model

### Gate B-ARCH-2: RSVD/VHDX Strategy
Choose one:
1. out of scope
2. minimal targeted implementation for one Hyper-V workflow
3. full strategic RSVD/VHDX platform effort

Required output:
1. command coverage scope
2. VHDX backend ownership
3. validation requirements
4. release claim boundary

### Gate B-ARCH-3: Failover Model
Choose one:
1. no cluster-grade claim
2. bounded failover model
3. strategic cluster-grade availability

Required output:
1. state model
2. recovery semantics
3. witness model
4. split-brain and negative-path plan

## Recommended Program B Staging
### Stage B0: Feasibility Only
Outputs:
1. architecture decision memos
2. staffing and budget approval
3. validation-lab funding decision
4. explicit go/no-go decision

### Stage B1: SMB Platform Foundation
Outputs:
1. multichannel, witness, transport security, and failover primitives
2. no NTFS parity claim yet
3. no RSVD claim yet

### Stage B2: Standalone Hyper-V Plus
Outputs:
1. Program A completed at production quality
2. broader Windows version support
3. stronger operational model

### Stage B3: Chosen Strategic Branch
Possible branches:
1. Branch N: NTFS compatibility layer
2. Branch R: RSVD/VHDX implementation
3. Branch C: cluster-grade availability

Decision rule:
- Do not start all three at once unless team size is clearly sufficient.

### Stage B4: Qualification
Outputs:
1. compatibility matrix
2. long-haul and failure-injection validation
3. support statement

## Risk Register
### Risk 1: VFS Abstraction Ceiling
Description:
- Some NTFS behaviors are not naturally available through Linux VFS.

Impact:
- parity claims become fake or inconsistent unless a new strategy is adopted.

Mitigation:
1. freeze NTFS architecture early
2. refuse unsupported claims

### Risk 2: Hyper-V Scope Explosion
Description:
- Hyper-V standalone storage is much smaller than cluster-grade shared-disk parity.

Impact:
- team starts by chasing RSVD/cluster work and never ships a usable product.

Mitigation:
1. finish Program A first
2. explicitly separate standalone and clustered support claims

### Risk 3: Lab Deficit
Description:
- without a real Windows interoperability lab, regressions are discovered too late.

Impact:
- parity claims cannot be trusted

Mitigation:
1. build the lab before claiming support
2. gate releases on lab results

### Risk 4: Indefinite Compatibility Burden
Description:
- broad parity claims create a long-term support burden beyond engineering capacity.

Impact:
- project becomes a permanent catch-up effort against Windows behavior

Mitigation:
1. keep support claims narrow and matrix-based
2. avoid broad parity language until proven

## Feasibility Verdicts
### Verdict 1: Program B is technically possible
Yes, in the narrow sense that no single feature area is obviously impossible.

### Verdict 2: Program B is operationally feasible only with major commitment
Yes, but only if the project accepts it is building a storage platform, not just finishing ksmbd.

### Verdict 3: Program B should not start by default
Correct. The default decision should be to stop at Program A unless there is strong product pull.

## Minimum Conditions to Approve Program B
All of these must be true:
1. Program A succeeds and proves real Hyper-V value
2. customer demand specifically requires more than Program A
3. architecture decisions for NTFS, RSVD/VHDX, and failover are frozen
4. validation-lab budget is approved
5. staffing of at least 12-14 engineers is available
6. release management accepts multi-year scope

## Explicit Go/No-Go Table
### Go
Approve Program B only if:
1. the target is a strategic Windows compatibility product
2. the team and lab are funded
3. architecture decisions are frozen
4. product management accepts narrow, evidence-based claims through the whole program

### No-Go
Do not approve Program B if any of the following is true:
1. only standalone Hyper-V support is needed
2. there is no dedicated Windows lab
3. there is no NTFS strategy owner
4. RSVD/VHDX is desired but no storage team exists
5. cluster-grade behavior is desired but no availability/state model exists

## Recommended Immediate Outputs If Program B Is Approved
1. `NTFS_BACKEND_ARCHITECTURE_OPTIONS.md`
2. `RSVD_VHDX_BACKEND_REQUIREMENTS.md`
3. `CLUSTER_FAILOVER_STATE_MODEL.md`
4. `WINDOWS_INTEROP_LAB_PLAN.md`
5. `PROGRAM_B_RELEASE_CLAIMS.md`

## Executive Summary
Program B is feasible only if the project explicitly decides to become a Windows-compatible storage platform.

If that is not the strategic goal, the correct decision is:
1. complete Program A
2. publish a narrow Hyper-V-over-SMB support matrix
3. stop there
