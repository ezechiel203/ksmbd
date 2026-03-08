# ksmbd Compliance Matrix Baseline

Date: 2026-03-07

This is the Phase 0 execution baseline for the full compliance program. The authoritative row set is in [COMPLIANCE_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/COMPLIANCE_MATRIX.csv).

The matrix now covers more than the first-pass command inventory. It includes SMB1 `TRANS2` and `NT_TRANSACT` subcommands, SMB1 UNIX/POSIX info levels, SMB2 query-directory classes, SMB2 query/set info classes, Apple AAPL subfeatures, DCE/RPC bind mechanics, and the additional FSCTL registration modules outside the original core tables.

## Status model

- `implemented`: code path exists in-tree
- `partial`: code path exists but protocol correctness is not yet proven end-to-end
- `non-compliant`: current implementation or advertisement is known to violate the protocol contract or project policy
- `test coverage`: `sparse`, `moderate`, or `n/a` based on current local evidence

## Scope captured in the CSV

- SMB1 command surface currently enabled in external builds
- SMB1 `TRANS2`, `NT_TRANSACT`, UNIX, and POSIX subordinate surfaces
- SMB2/SMB3 dialects, core commands, negotiate contexts, session features, create contexts, query/set info classes, POSIX, and Apple extensions
- transports: TCP, RDMA, QUIC
- all currently registered FSCTL handlers across core, DFS, VSS, reparse, resiliency, reserved virtual-disk, and extra modules
- named-pipe RPC interfaces, visible opnums, and DCE/RPC bind/request mechanics

## Immediate red items

These are the `P0` rows that should drive the first engineering sprint:

| Area | Feature | Identifier | Why it is red |
| --- | --- | --- | --- |
| SMB1 | Default enablement | `CONFIG_SMB1_ENABLED_BY_DEFAULT` | Incomplete SMB1 surface is exposed by default for external builds. |
| SMB1 | NT transact | `SMB_COM_NT_TRANSACT` | Known intentionally incomplete SMB1 path while feature remains enabled. |
| SMB1 | NT transact secondary | `SMB_COM_NT_TRANSACT_SECONDARY` | Secondary assembly/completion path is not at full legacy compatibility. |
| SMB2/3 | Negotiate context | `SMB2_COMPRESSION_CAPABILITIES` | Compression negotiation is not spec-correct. |
| SMB2/3 | Negotiate context | `SMB2_TRANSPORT_CAPABILITIES` | Transport security is advertised from the wrong state. |
| SMB2/3 | Negotiate context | `SMB2_RDMA_TRANSFORM_CAPABILITIES` | RDMA transform advertisement is not tied to actual enforcement. |
| SMB2/3 | Session | `SMB3_SESSION_BINDING` | Valid SMB 3.0 and 3.0.2 multichannel binds are rejected. |
| SMB2/3 | Open context | `DH2Q` | Durable-v2 request path still shows failures in local sweep artifacts. |
| SMB2/3 | Open context | `DH2C` | Durable-v2 reconnect path still shows failures in local sweep artifacts. |
| SMB2/3 | Leasing | `DIRLEASE` | Directory lease behavior remains unstable in local sweeps. |
| Transport | RDMA transport | `SMB Direct` | Transport exists but negotiate/signing/encryption truthfulness is not established. |
| Transport | QUIC transport | `SMB over QUIC` | Large code surface exists but has not been driven to compliance-grade interop. |
| FSCTL | Named pipe | `FSCTL_PIPE_PEEK` | Current handler is a compatibility stub. |
| FSCTL | Named pipe | `FSCTL_PIPE_WAIT` | Current handler is a timeout poll, not full pipe-instance wait semantics. |
| RPC | Transport | `IPC$ RPC over SMB` | RPC correctness depends on full named-pipe semantics and wider interface coverage. |

## Execution order

1. Fix protocol truthfulness first.
   Stop advertising capabilities, contexts, or transports whose semantics are not actually enforced.

2. Close session and durable-handle correctness next.
   Multichannel binding, durable-v2, lease, dirlease, replay, and notify are the highest-risk interoperability areas.

3. Replace named-pipe stubs with real semantics.
   That unblocks both FSCTL compatibility and the RPC program surface.

4. Decide the SMB1 policy explicitly.
   Either finish the legacy surface or disable it by default until the command and transaction matrix is green.

5. Turn the CSV into a gated test matrix.
   Every row needs at least one automated proof: `smbtorture`, Windows interop, macOS interop, KUnit, or transport-specific tests.

## Deliverables to add next

- `TEST_MAPPING.csv`: row-to-test linkage for each compliance row
- `SPEC_REFERENCES.md`: normalized spec references per command, context, FSCTL, and RPC interface
- `FAILURE_BACKLOG.md`: one issue per `non-compliant` row with owner, reproducer, and acceptance criteria
