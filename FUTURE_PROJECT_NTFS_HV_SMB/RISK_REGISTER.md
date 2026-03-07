# Risk Register

## Purpose
Track strategic and execution risks for the future Windows/NTFS/Hyper-V project.

## Risks
### R1: Scope Explosion
Description:
- Hyper-V support expands into Windows parity and cluster work without explicit approval.

Impact:
- delays, misaligned staffing, and non-shippable breadth

Mitigation:
1. keep Program A and Program B separate
2. use explicit go/no-go gates

### R2: VFS Abstraction Ceiling
Description:
- required NTFS-visible behaviors are not cleanly represented through Linux VFS

Impact:
- fake compatibility or unmaintainable shims

Mitigation:
1. freeze NTFS architecture early
2. narrow claims until architecture exists

### R3: Validation Gap
Description:
- support claims outrun the Windows interoperability lab

Impact:
- regressions discovered by users instead of in the lab

Mitigation:
1. make the lab a release gate
2. forbid unsupported claims

### R4: Storage-Platform Underestimation
Description:
- RSVD/VHDX and failover work is treated like normal SMB feature work

Impact:
- large schedule slip and architectural dead ends

Mitigation:
1. isolate RSVD/VHDX as a storage workstream
2. require dedicated ownership and backend design

### R5: Operational Unsupportability
Description:
- complex metadata or failover logic ships without tooling and diagnostics

Impact:
- production incidents cannot be debugged or recovered cleanly

Mitigation:
1. require observability deliverables per milestone
2. publish runbooks and failure modes
