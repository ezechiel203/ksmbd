# Program B Release Claims Policy

## Purpose
Control what the project is allowed to claim at each stage of Program B.

## Principle
Claims must be narrower than the tested matrix, never broader.

## Forbidden Words Before Full Qualification
Do not use these phrases unless the corresponding matrix is validated:
1. "Windows Server parity"
2. "full NTFS compatibility"
3. "Hyper-V full compatibility"
4. "cluster-grade availability"
5. "drop-in replacement for Windows Server SMB"

## Stage-Based Claim Policy
### After Program A
Allowed:
1. Hyper-V over SMB on the validated Linux-backed matrix
2. specific transport and auth combinations that passed validation

Forbidden:
1. NTFS parity
2. RSVD support
3. clustered Hyper-V support
4. Windows Server parity

### After Program B1/B2
Allowed:
1. broader Windows interoperability for validated standalone scenarios
2. supported multichannel/witness statements only if validated

Still forbidden unless validated:
1. RSVD/shared-disk claims
2. NTFS parity claims
3. cluster-grade claims

### After Program B3/B4/B5
Allowed only if validated:
1. explicitly enumerated RSVD workflows
2. explicitly enumerated NTFS-visible behaviors
3. explicitly enumerated clustered/failover scenarios

## Claim Format Template
Every external claim must specify:
1. Windows version matrix
2. Hyper-V version matrix
3. Linux backing filesystem matrix
4. transport matrix
5. auth matrix
6. unsupported scenarios

## Recommendation
Every release should ship with a support matrix appendix, not marketing shorthand.
