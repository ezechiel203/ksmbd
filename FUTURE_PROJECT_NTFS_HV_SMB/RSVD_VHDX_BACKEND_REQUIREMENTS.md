# RSVD and VHDX Backend Requirements

## Purpose
Define what is actually required to support RSVD and Hyper-V shared-disk workflows rather than leaving `ksmbd_rsvd.c` as a stub surface.

## Scope
This document applies only if the project decides to support:
1. RSVD
2. shared virtual disk workflows
3. Hyper-V behaviors that require more than ordinary file I/O on `.vhdx`

This is not required for Program A.

## Core Reality
A server can host ordinary `VHDX` files for Hyper-V without becoming VHDX-aware.

RSVD changes that. Once the server claims RSVD/shared-disk support, it must behave like a virtual-disk-aware platform, not merely a file server.

## Functional Requirements
### 1. SCSI Tunnel Support
The backend must support the command classes needed for claimed Hyper-V workflows.

Required outputs:
1. CDB dispatch model
2. command allowlist/denylist
3. error mapping to SMB/NT status responses
4. timeouts and cancellation behavior

### 2. Persistent Reservation Semantics
The backend must define reservation and conflict behavior for shared-disk access.

Required outputs:
1. registration model
2. reservation ownership model
3. conflict behavior
4. failover and reconnect behavior
5. state durability guarantees

### 3. VHDX Metadata Handling
If the server claims metadata-aware operations, it must correctly process relevant VHDX structures.

Required outputs:
1. metadata region parsing
2. BAT handling
3. geometry reporting
4. sector-size semantics
5. resize behavior
6. metadata update durability model

### 4. Crash Consistency and Recovery
This is non-optional.

Required outputs:
1. recovery after host crash
2. recovery after mid-operation disconnect
3. replay or rollback model
4. logging model
5. corruption-detection strategy

### 5. Snapshot / Checkpoint Semantics
If snapshots or checkpoint-adjacent operations are claimed, they must be specified explicitly.

Required outputs:
1. supported snapshot workflow list
2. unsupported snapshot workflow list
3. merge and chain-handling semantics
4. backup/VSS interaction assumptions

## Non-Functional Requirements
1. deterministic failure behavior
2. observability for reservations, tunnel ops, metadata ops, and conflicts
3. performance characterization under shared-disk workloads
4. no silent corruption under competing access patterns

## Architecture Options
### Option R1: Keep RSVD Out of Scope
Advantages:
1. minimal complexity
2. avoids fake shared-disk claims
3. preserves Program A focus

Recommended when:
1. Hyper-V target is standalone host storage only

### Option R2: Minimal Targeted RSVD Support
Description:
Support only a small, validated subset of RSVD behavior required for one bounded workflow.

Advantages:
1. smaller than full parity
2. product value if a narrow scenario matters

Disadvantages:
1. hard to explain boundary
2. still needs strong validation

### Option R3: Strategic RSVD/VHDX Platform
Description:
Treat RSVD and VHDX handling as a storage subsystem with dedicated backend ownership.

Advantages:
1. strongest long-term compatibility path

Disadvantages:
1. very high cost
2. large validation burden
3. effectively a new platform program

## Required Decision Gates
1. Are shared-disk Hyper-V scenarios truly required?
2. Is VHDX metadata awareness required, or only regular file hosting?
3. Does the product need cluster-grade reservation behavior?
4. Will the project own a VHDX-aware backend?

## Validation Requirements
### Must-Have Lab Coverage
1. shared-disk attach/detach
2. reservation conflict scenarios
3. host reboot and reconnect scenarios
4. cluster-like conflict and recovery cases if claimed
5. corruption-detection checks after forced interruption

### Required Artifacts
1. command coverage matrix
2. supported workflow matrix
3. error-mapping matrix
4. recovery matrix

## Recommendation
1. Keep RSVD out of scope by default.
2. If RSVD becomes required, start with a narrowly defined `Minimal Targeted RSVD Support` decision.
3. Do not claim RSVD compatibility without a dedicated backend design, persistent-reservation model, and Windows interoperability lab coverage.
