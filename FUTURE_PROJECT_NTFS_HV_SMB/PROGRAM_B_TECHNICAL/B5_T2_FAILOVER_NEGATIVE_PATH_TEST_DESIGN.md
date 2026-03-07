# B5-T2 Failover Negative-Path Test Design

Status: `planning`

## Purpose
Define the negative-path suite required before any bounded or strategic failover
claim is allowed.

## Required Outputs
1. Node death cases
2. Split-brain cases
3. Partial state-sync cases

## Test Principles
1. Prefer destructive cases before happy-path demos
2. Capture data-loss and stale-ownership risk explicitly
3. Gate claims on repeatable failure outcomes, not one-off passes

## Exit Criteria
1. Every claimed failover path has a matching negative-path test.
