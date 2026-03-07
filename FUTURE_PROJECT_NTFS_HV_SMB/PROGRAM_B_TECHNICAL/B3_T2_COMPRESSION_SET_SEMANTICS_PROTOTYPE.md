# B3-T2 Compression Set Semantics Prototype

Status: `planning`

## Purpose
Determine whether compression behavior can be provided as real backend
semantics, an emulation layer, or must remain unsupported.

## Potential Code Areas
1. `src/fs/ksmbd_fsctl.c`
2. Filesystem/backend-specific code

## Required Outputs
1. Whether compression is real, emulated, or unsupported
2. Exact claim boundary

## Focus Areas
1. Set/get semantics
2. Crash consistency
3. Interaction with sparse files and `VHDX`
4. Interaction with failover claims

## Exit Criteria
1. Compression behavior has a written claim boundary and negative-path policy.
