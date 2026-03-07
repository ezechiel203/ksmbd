# A3-T1 Flush/FUA Validation

Status: `draft`

## Purpose
Validate write ordering and flush semantics for Hyper-V guest-disk workloads on
the supported Linux filesystem matrix.

## Primary Code Areas
1. `src/protocol/smb2/smb2_read_write.c`
2. `src/protocol/smb2/smb2_ioctl.c`
3. `src/fs/vfs.c`

## Required Outputs
1. Validated flush semantics under Hyper-V workload
2. Known caveats recorded

## Validation Matrix
1. `xfs` with ordinary `VHDX` files
2. `ext4` with ordinary `VHDX` files
3. Flush-heavy guest workload
4. Power-loss simulation after acknowledged writes

## Required Evidence
1. Guest integrity checks after crash and restart
2. Host-side trace of flush-triggering SMB operations
3. Filesystem-specific caveats, if any

## Exit Criteria
1. Acknowledged writes survive according to the documented semantics.
2. Any caveat is precise enough to appear in the support matrix.
