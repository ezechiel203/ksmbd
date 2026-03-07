# B5-T1 Shared-State Architecture

Status: `planning`

## Purpose
Choose how cluster-sensitive state would be shared or replicated across nodes.

## Required Outputs
1. Shared vs replicated state decision
2. Session/handle/lease/lock ownership rules

## State Classes
1. Sessions and auth bindings
2. Durable/persistent handles
3. Leases and oplocks
4. Byte-range locks
5. Reservation state if RSVD is in scope

## Exit Criteria
1. Ownership, fencing, and recovery rules exist for every claimed state class.
