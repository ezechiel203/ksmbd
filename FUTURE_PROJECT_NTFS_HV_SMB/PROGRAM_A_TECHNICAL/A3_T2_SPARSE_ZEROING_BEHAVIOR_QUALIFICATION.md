# A3-T2 Sparse/Zeroing Behavior Qualification

Status: `draft`

## Purpose
Qualify sparse allocation, punch/zero behavior, and related FSCTL/IOCTL paths
that Hyper-V can exercise through `VHDX` workflows.

## Primary Code Areas
1. `src/fs/ksmbd_fsctl.c`
2. `src/fs/vfs.c`
3. `src/protocol/smb2/smb2_ioctl.c`

## Required Outputs
1. Sparse allocation behavior matrix
2. Zero-range behavior matrix

## Matrix Axes
1. `xfs` vs `ext4`
2. New `VHDX` vs expanded `VHDX`
3. Zeroing, hole-punch, and allocation-extend flows
4. Guest-visible correctness after merge or restart

## Required Notes
1. Which behaviors are native to the backing FS
2. Which behaviors are translated by `ksmbd`
3. Any mismatch that must be blocked or documented

## Exit Criteria
1. Sparse and zeroing behavior is deterministic for supported rows.
2. Unsupported semantics are not silently advertised as working.
