# A4-T1 Domain Auth Reliability Sweep

Status: `draft`

## Purpose
Determine whether domain-backed authentication is stable enough to enter the
Program A support matrix.

## Primary Code Areas
1. `src/protocol/smb2/smb2_session.c`
2. `ksmbd-tools/`

## Required Outputs
1. Repeated domain-auth validation
2. Auth failure diagnostics checklist

## Sweep Plan
1. Repeated logon/logoff cycles
2. Ticket expiration and renewal windows
3. Service restart during domain-auth use
4. Negative tests for KDC outage, clock skew, and SPN mismatch

## Diagnostics Checklist
1. Logs needed to root-cause auth failure
2. Counters or tracepoints missing today
3. Minimum operator-visible error information

## Exit Criteria
1. Domain auth is either validated for the published matrix or removed from the
   support claim.
