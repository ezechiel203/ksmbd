# A5-T2 Runbook Draft

Status: `draft`

## Purpose
Provide the first operator runbook for Program A support cases.

## Required Outputs
1. Outage recovery
2. Service restart
3. Upgrade/restart guidance
4. Debugging checklists

## Runbook Sections
1. Preconditions before planned restart
2. Immediate checks after unplanned disconnect storm
3. Safe evidence collection for Hyper-V incidents
4. Domain-auth troubleshooting flow
5. Criteria for removing a node from service

## Operational Constraints
1. No step may imply unsupported cluster-grade recovery.
2. Steps must reflect actual restart/reconnect semantics from A2-T3.
3. Commands and log paths must be repo- and product-specific once tooling lands.

## Exit Criteria
1. Runbook language matches the supported matrix exactly.
2. Support engineers can triage the top Program A failures from this document.
