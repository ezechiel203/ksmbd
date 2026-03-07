# A2-T1 Persistent Handle Recovery Qualification

Status: `active`

## Purpose
Qualify reconnect and persistent-handle recovery paths before any Program A
Hyper-V claim is considered marketable.

## Primary Code Areas
1. `src/protocol/smb2/smb2_ph.c`
2. `src/protocol/smb2/smb2_create.c`
3. `src/fs/vfs_cache.c`
4. `src/fs/oplock.c`

## Required Outputs
1. Recovery-path test matrix
2. Reconnect stress results
3. Failure-mode notes

## Qualification Focus
1. Disconnect during active VM I/O
2. Reconnect inside and outside the durable window
3. Scavenger interaction with live recovery
4. Access-right, lease, and lock restoration correctness

## Evidence Bundle
1. Packet/log timeline for each recovery scenario
2. Server-side state snapshots before disconnect and after restore
3. Explicit defect list for stale ID, orphaned state, or incorrect restore

## Exit Criteria
1. Recovery does not corrupt guest-visible state.
2. Unsupported cases are enumerated and deliberately blocked or documented.
