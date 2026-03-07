# B4-T3 VHDX Backend Feasibility Prototype

Status: `planning`

## Purpose
Prototype whether the project needs a dedicated `VHDX`-aware backend or can
remain file-backed for the targeted RSVD/shared-disk workflows.

## Required Outputs
1. Metadata handling approach
2. Resize path
3. Recovery model

## Prototype Focus
1. `VHDX` metadata correctness
2. Shared-disk reservation interaction
3. Resize and merge behavior under failure

## Exit Criteria
1. Backend ownership and support burden are understood before implementation.
