# A0-T1 Support Matrix Draft

Status: `draft`

## Purpose
Define the first-release Program A support envelope tightly enough that test,
code, and marketing scopes stay aligned.

## In-Scope Matrix
1. Windows Server hosts: 2022 and 2025
2. Hyper-V role on those host versions only
3. Backing filesystems: `xfs` and `ext4`
4. Transport: SMB 3.1.1 over TCP only
5. Auth modes: local users and domain auth if the domain path passes gating

## Explicit Exclusions
1. SMB Direct
2. QUIC in the initial support claim
3. RSVD/shared-disk workflows
4. clustered Hyper-V or cluster-grade failover
5. NTFS parity claims

## Validation Requirements
1. Each matrix row must pass create, attach, boot, checkpoint, merge, and
   reconnect-under-load.
2. `xfs` and `ext4` results must be tracked separately.
3. Domain-auth rows cannot be promoted into the public matrix until long-run
   auth tests pass.

## Deliverables
1. Published matrix table for release notes
2. Lab test identifiers for every supported row
3. Unsupported combinations appendix

## Exit Criteria
1. Every supported row has a passing evidence bundle.
2. Every non-supported row has deliberate wording and no accidental claim.
