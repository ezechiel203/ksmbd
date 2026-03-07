# A5-T1 Metrics Inventory

Status: `draft`

## Purpose
Define the minimum observability surface required to operate Program A safely.

## Primary Code Areas
1. `src/core/`
2. `src/mgmt/`
3. `ksmbd-tools/`

## Required Outputs
1. Metrics list
2. Insertion points
3. Missing instrumentation list

## Proposed Metrics
1. Reconnect attempts and outcomes
2. Durable/persistent handle restore counts
3. Lease break timing and failures
4. Session auth failures by class
5. Transport disconnect reasons
6. VM-lifecycle test failure counters in lab automation

## Exit Criteria
1. Operators can distinguish auth, transport, and state-recovery failures.
2. Missing instrumentation is mapped to specific source files.
