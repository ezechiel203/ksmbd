# B1-T2 Witness Maturity

Status: `gated`

## Purpose
Define what witness support means operationally and what validation is needed
before it can influence any failover story.

## Primary Code Areas
1. `src/mgmt/ksmbd_witness.*`
2. `src/core/`

## Required Outputs
1. Witness behavior definition
2. Failover notification validation

## Focus Areas
1. Notification timing
2. Accuracy of state changes emitted to clients
3. Interaction with bounded failover claims

## Exit Criteria
1. Witness notifications match the documented recovery model exactly.
