# A3-T3 Checkpoint/Merge Flow Validation

Status: `draft`

## Purpose
Validate Hyper-V checkpoint and merge flows end-to-end and capture any code fix
list required to make the supported matrix reliable.

## Primary Areas
1. Validation-driven; likely fixes in `src/fs/` and `src/protocol/smb2/`

## Required Outputs
1. Hyper-V checkpoint and merge pass/fail matrix
2. Patch list for any discovered issues

## Scenario List
1. Single checkpoint create/delete
2. Multi-checkpoint merge chain
3. Merge under background guest write load
4. Merge after disconnect/reconnect cycle

## Evidence
1. Host event logs
2. `ksmbd` logs and traces
3. Guest filesystem integrity result
4. File-layout observations on the server

## Exit Criteria
1. Supported checkpoint/merge scenarios pass repeatably.
2. Any failing scenario is either fixed or moved to the unsupported appendix.
