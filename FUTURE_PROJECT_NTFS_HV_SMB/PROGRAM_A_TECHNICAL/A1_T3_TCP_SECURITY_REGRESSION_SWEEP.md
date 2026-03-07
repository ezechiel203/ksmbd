# A1-T3 TCP Security Regression Sweep

Status: `draft`

## Purpose
Run a focused regression sweep for signing, encryption, and preauth integrity on
the TCP path that Program A actually intends to ship first.

## Primary Code Areas
1. `src/core/server.c`
2. `src/protocol/smb2/`

## Required Outputs
1. Signing/encryption/preauth regression coverage
2. Negative-path test list

## Sweep Areas
1. Downgrade resistance
2. Mixed client capability negotiation
3. Invalid signature and preauth mismatch handling
4. Encryption-required session behavior

## Exit Criteria
1. TCP support claims are backed by explicit negative-path coverage.
2. No insecure fallback remains in the supported path.
