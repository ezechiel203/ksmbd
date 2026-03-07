# A2-T2 Lock and Lease Reconnect Qualification

Status: `draft`

## Purpose
Prove that reconnect preserves correctness when locks and lease-backed opens
remain outstanding across interruption.

## Primary Code Areas
1. `src/fs/oplock.c`
2. `src/protocol/smb2/smb2_lock.c`
3. `src/fs/vfs_cache.c`

## Required Outputs
1. Reconnect with outstanding locks
2. Reconnect with lease-backed opens
3. Known unsupported edge cases documented

## Test Cases
1. Byte-range locks held during network flap
2. Concurrent readers/writers while reconnect is pending
3. Lease break racing with reconnect
4. Lock release or downgrade after timeout

## Known Risk Areas
1. Lost lock ownership identity
2. Lease state restored without matching backend state
3. Reconnect succeeding after server-side cleanup

## Exit Criteria
1. Lock and lease semantics are stable under supported reconnect windows.
2. Edge cases that remain unsupported are explicitly tied to status codes or
   support notes.
