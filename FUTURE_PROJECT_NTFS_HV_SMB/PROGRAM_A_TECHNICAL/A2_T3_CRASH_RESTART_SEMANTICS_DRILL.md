# A2-T3 Crash/Restart Semantics Drill

Status: `draft`

## Purpose
Define restart behavior when the service exits or restarts while durable or
persistent state may still matter to the client.

## Primary Code Areas
1. `src/core/`
2. `src/fs/`
3. `src/protocol/smb2/`

## Required Outputs
1. Service restart behavior under disconnected durable window
2. Expected and unexpected failure cases

## Drill Plan
1. Controlled restart with idle open handles
2. Restart during active VM-disk traffic
3. Restart before reconnect timeout expires
4. Restart after cleanup/scavenge has already run

## Required Notes
1. What survives restart and what does not
2. Which errors are acceptable for unsupported recovery cases
3. Required operator actions after restart

## Exit Criteria
1. Restart semantics are documented in a way operators can follow.
2. No support claim depends on behavior that is not actually preserved.
