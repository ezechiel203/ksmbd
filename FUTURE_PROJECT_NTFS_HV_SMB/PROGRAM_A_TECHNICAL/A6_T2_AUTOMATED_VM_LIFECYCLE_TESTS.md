# A6-T2 Automated VM Lifecycle Tests

Status: `draft`

## Purpose
Define the automated lifecycle suite that proves Program A behavior against real
Hyper-V operations.

## Required Outputs
1. Create
2. Attach
3. Boot
4. Checkpoint
5. Merge
6. Reconnect under load

## Proposed Harness Shape
1. Host-side PowerShell orchestration for Hyper-V actions
2. Server-side artifact collection hooks
3. Per-scenario result bundle with logs, timestamps, and pass/fail reason

## Minimum Scenario Set
1. New VM from fresh `VHDX`
2. Existing VM attach and boot
3. Checkpoint create/delete
4. Checkpoint merge after network flap
5. Reconnect during sustained guest I/O

## Exit Criteria
1. The suite runs unattended for every supported matrix row.
2. Results are suitable for release gating, not just exploratory testing.
