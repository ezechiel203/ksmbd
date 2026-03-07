# A6-T1 Program A Matrix Definition

Status: `draft`

## Purpose
Turn the scope draft into a lab-owned qualification matrix.

## Required Outputs
1. Windows versions
2. Hyper-V versions
3. Filesystems
4. Auth modes
5. Transport modes

## Baseline Rows
1. Windows Server 2022 Hyper-V + SMB over TCP + `xfs`
2. Windows Server 2022 Hyper-V + SMB over TCP + `ext4`
3. Windows Server 2025 Hyper-V + SMB over TCP + `xfs`
4. Windows Server 2025 Hyper-V + SMB over TCP + `ext4`

## Conditional Rows
1. Domain-auth variants for each baseline row
2. Additional transport rows only after explicit scope approval

## Exit Criteria
1. Every row has test ownership and artifact storage defined.
2. The public support matrix is a strict subset of this qualification matrix.
