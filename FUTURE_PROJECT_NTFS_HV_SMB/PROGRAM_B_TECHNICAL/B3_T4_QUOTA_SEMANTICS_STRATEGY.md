# B3-T4 Quota Semantics Strategy

Status: `planning`

## Purpose
Decide whether quota behavior should be Linux-backed, emulated, or unsupported
for Program B claims.

## Required Outputs
1. Whether quotas are Linux-backed, emulated, or unsupported
2. Exact Windows-visible behavior claim

## Decision Questions
1. User vs tree vs volume semantics
2. Reporting accuracy under reconnect and failover
3. Admin tool expectations
4. Error and warning threshold behavior

## Exit Criteria
1. Quota claims are precise enough to test and support.
