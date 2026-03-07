# A1-T1 QUIC Retry Integrity Review and Completion

Status: `draft`

## Purpose
Close the QUIC Retry integrity gap so Program A can either support QUIC safely
later or reject it from scope on evidence instead of ambiguity.

## Primary Code Area
1. `src/transport/transport_quic.c`

## Required Outputs
1. RFC-correct Retry integrity path
2. Interop tests for Retry behavior

## Technical Focus
1. Retry integrity tag calculation and validation
2. Retry token acceptance rules
3. Negative-path handling for malformed or replayed Retry packets

## Exit Criteria
1. Strict clients interoperate with Retry enabled.
2. Invalid Retry paths fail closed.
