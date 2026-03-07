# A4-T2 Session Rebind and Ticket Refresh Tests

Status: `draft`

## Purpose
Qualify long-lived session behavior, especially around rebind and ticket-refresh
events that can occur during continuous Hyper-V host operation.

## Primary Code Areas
1. `src/protocol/smb2/smb2_session.c`
2. `src/core/connection.c`

## Required Outputs
1. Long-lived auth/session behavior notes
2. Fixes for ticket-refresh instability if found

## Test Focus
1. Session longevity across ticket renewal
2. Rebind after transient network interruption
3. Session reuse after reconnect
4. Error behavior when refresh fails mid-workload

## Exit Criteria
1. No supported matrix row depends on undefined ticket-refresh behavior.
2. Any instability is either fixed or turned into a scope exclusion.
