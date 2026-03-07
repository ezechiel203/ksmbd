# A6-T3 Soak and Fault Injection

Status: `draft`

## Purpose
Define the long-run and negative-path lab work needed before Program A can ship.

## Required Outputs
1. Long-run stress scripts
2. Network flap tests
3. Service restart tests
4. Artifact collection bundle

## Fault Model
1. Short network flap during guest I/O
2. Longer disconnect inside reconnect window
3. Service restart during active workload
4. Host reboot or forced VM operation interruption

## Artifact Bundle
1. Hyper-V host logs
2. `ksmbd` service logs
3. Packet captures when enabled
4. Guest integrity and filesystem results

## Exit Criteria
1. Soak and fault-injection runs are reproducible and versioned.
2. Release gating can identify regressions in reconnect and disk-integrity
   behavior quickly.
