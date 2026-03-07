# B4-T2 Reservation State Model

Status: `planning`

## Purpose
Define ownership, persistence, and recovery semantics for reservation state.

## Required Outputs
1. Registration ownership
2. Persistence model
3. Reconnect/failover semantics

## Design Questions
1. Where reservation state lives
2. Which node or service owns authoritative state
3. What survives restart, reconnect, and failover
4. How stale ownership is detected and resolved

## Exit Criteria
1. Reservation semantics are coherent enough to test under failure injection.
