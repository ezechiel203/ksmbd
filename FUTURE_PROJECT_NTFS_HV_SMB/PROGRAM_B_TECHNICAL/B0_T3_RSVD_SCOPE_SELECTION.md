# B0-T3 RSVD Scope Selection

Status: `planning`

## Purpose
Define the exact RSVD/shared-disk workflows, if any, that Program B would own.

## Primary Design Doc
1. `RSVD_VHDX_BACKEND_REQUIREMENTS.md`

## Required Outputs
1. Exact workflow scope
2. Unsupported workflow list
3. Backend ownership

## Decision Rule
No RSVD implementation starts until command coverage, storage backend ownership,
and negative-path behavior are specified precisely.

## Exit Criteria
1. Supported workflows are named concretely.
2. Unsupported workflows are explicit enough for sales and engineering to use.
