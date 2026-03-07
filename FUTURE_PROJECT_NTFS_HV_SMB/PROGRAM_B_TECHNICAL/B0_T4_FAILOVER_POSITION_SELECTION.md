# B0-T4 Failover Position Selection

Status: `planning`

## Purpose
Choose whether Program B makes no cluster claim, a bounded failover claim, or a
strategic cluster-grade claim.

## Primary Design Doc
1. `CLUSTER_FAILOVER_STATE_MODEL.md`

## Required Outputs
1. No cluster claim, bounded failover, or strategic cluster-grade decision
2. State-sharing model

## Position Choices
1. No cluster claim
2. Bounded failover model
3. Strategic cluster-grade availability

## Exit Criteria
1. The chosen position has a matching lab plan.
2. Unsupported failover modes are explicitly listed.
