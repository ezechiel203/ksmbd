# Cluster and Failover State Model

## Purpose
Describe the state model required for any claim involving cluster-aware behavior, witness-driven failover, or continuous-availability-like semantics.

## Why This Exists
Failover is not a feature bit. It is a state-management problem.

If the project claims cluster-grade or failover-sensitive behavior, it must define how these state classes survive node changes:
1. sessions
2. tree connects
3. durable/persistent handles
4. leases/oplocks
5. byte-range locks
6. reservations if RSVD is in scope

## State Classes
### 1. Reconstructible State
State that can be re-derived from durable backing data or client replay.

Examples:
1. some session metadata
2. ordinary open-file metadata
3. static share configuration

### 2. Durable Shared State
State that must persist across node movement or restart.

Examples:
1. persistent-handle records
2. reservation ownership
3. failover-critical recovery metadata

### 3. Ephemeral Local State
State that exists only on one node and cannot be safely claimed as failover-safe.

Examples:
1. in-memory transient worker state
2. partially processed requests
3. unreplicated local transport state

## Required Design Decisions
### Decision 1: Shared State Location
Options:
1. shared durable storage
2. replicated state service
3. hybrid model

### Decision 2: Session Ownership Model
Options:
1. strict node ownership
2. re-home on failover
3. partial reconstruction only

### Decision 3: Handle Recovery Model
Options:
1. restart-style recovery only
2. node-to-node failover recovery
3. bounded reconnect window with explicit loss modes

### Decision 4: Lease and Lock Recovery Model
Questions:
1. Are locks replicated, reconstructed, or intentionally lost?
2. Are lease epochs preserved?
3. How are break-in-flight cases handled?

## Negative-Path Model
This must be written before any failover claim is made.

Required cases:
1. node dies mid-write
2. node dies during lease break
3. node dies with persistent handle pending reconnect
4. split-brain or duplicate ownership risk
5. witness says fail over but state sync is incomplete

## Acceptable Program B Positions
### Position C1: No Cluster Claim
Allowed claim:
- standalone or bounded reconnect only

### Position C2: Bounded Failover Claim
Allowed claim:
- failover only for documented scenarios with explicit loss model

### Position C3: Strategic Cluster Claim
Allowed claim:
- cluster-grade availability for validated matrix

This requires the strongest architecture and lab support.

## Recommendation
1. Program A should stay at Position C1.
2. Program B should not advance past Position C2 unless there is a real shared-state model and a failover lab.
3. No cluster-grade claim should be made until split-brain and partial-failover negative paths are tested.
