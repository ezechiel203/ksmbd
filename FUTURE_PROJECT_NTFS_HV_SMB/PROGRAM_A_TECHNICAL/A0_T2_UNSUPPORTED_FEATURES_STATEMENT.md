# A0-T2 Unsupported Features Statement

Status: `draft`

## Purpose
Freeze the first-release "no" list so Program A does not silently expand into
Program B.

## Unsupported for the Initial Program A Claim
1. RSVD and shared virtual-disk workflows
2. SMB Direct / RDMA
3. cluster-grade failover or witness-driven recovery claims
4. NTFS parity, including short-name, object ID, USN, and quota parity claims
5. QUIC in the first support statement

## Required User-Facing Wording
1. "Supported for validated standalone Hyper-V over SMB scenarios only."
2. "Backed by Linux filesystems, not by NTFS parity semantics."
3. "Unsupported scenarios fail deliberately or remain undocumented."

## Engineering Implications
1. Unsupported feature paths must return explicit status where possible.
2. Test plans must avoid using unsupported features as hidden prerequisites.
3. Release materials must ship with a support matrix and exclusions list.

## Exit Criteria
1. Release docs, tracker, and milestone board use the same unsupported list.
2. No Program A document contains parity language that contradicts this file.
