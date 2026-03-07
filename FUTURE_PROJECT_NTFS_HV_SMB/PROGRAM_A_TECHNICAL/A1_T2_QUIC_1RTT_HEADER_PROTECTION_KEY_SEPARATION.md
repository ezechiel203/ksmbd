# A1-T2 QUIC 1-RTT Header Protection Key Separation

Status: `draft`

## Purpose
Separate QUIC header-protection key handling from packet-protection state so the
implementation matches the protocol model and is auditable.

## Primary Code Area
1. `src/transport/transport_quic.c`

## Required Outputs
1. Separate HP key derivation and storage
2. Strict-path validation for packet processing

## Technical Focus
1. Key schedule review
2. State lifetime and rekey boundaries
3. Packet decode path validation with wrong-key and stale-key cases

## Exit Criteria
1. Header protection state is isolated and testable.
2. No mixed-key fast path remains.
