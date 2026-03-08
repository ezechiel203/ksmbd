# ksmbd Protocol Compatibility Audit

Date: 2026-03-07

## Scope

This audit reviewed the active production protocol paths under `src/` line-by-line in the protocol-critical files:

- `src/protocol/smb2/smb2_negotiate.c`
- `src/protocol/smb2/smb2_session.c`
- `src/protocol/smb2/smb2_create.c`
- `src/fs/oplock.c`
- `src/fs/ksmbd_fsctl.c`
- `src/fs/ksmbd_fsctl_extra.c`
- `src/transport/transport_rdma.c`
- `src/protocol/smb1/smb1pdu.c`
- `src/protocol/smb2/smb2ops.c`
- `Makefile`

Cross-check material:

- Official Microsoft Open Specifications: `MS-SMB2`, `MS-FSCC`
- Existing interoperability artifacts in `TESTS/SWEEP/`

This is a static compatibility audit. I did not rerun `smbtorture` in this turn, so interoperability evidence is taken from the existing sweep artifacts in the tree.

## Executive Summary

The current tree is not protocol-clean across SMB2/SMB3 production paths. The biggest compatibility problems are in negotiate-context semantics, multichannel session binding, named-pipe FSCTL behavior, and the legacy SMB1 surface.

Severity summary:

- Critical: 1
- High: 3
- Medium: 3

Broad status by area:

- SMB2/SMB3 negotiate: partial
- SMB3 multichannel/session binding: non-compliant
- SMB Direct/RDMA transforms: partial and internally inconsistent
- Named pipes / IPC FSCTLs: partial
- SMB1: intentionally incomplete, but enabled by default for external builds
- Durable handles / leases: large residual interop risk remains

## Findings

### 1. Critical: SMB3 session binding is incorrectly restricted to SMB 3.1.1

Code:

- `src/protocol/smb2/smb2_session.c:782-872`

Key issue:

- Binding enters the multichannel path for any dialect `>= SMB30`, but then the implementation rejects the bind unless `conn->dialect == SMB311_PROT_ID` and a non-zero preauth hash is present.
- That hard-gates valid SMB 3.0 and 3.0.2 channel binding requests.

Why this is non-compliant:

- `MS-SMB2` defines binding for SMB 3.x multichannel, with additional preauth-integrity processing only when the dialect is 3.1.1.
- The current code treats preauth-integrity as a universal prerequisite instead of a 3.1.1-specific requirement.

Interop evidence:

- `TESTS/SWEEP/logs/smb2.credits.log:36-40` shows `multichannel_ipc_max_async_credits` failing during `smb2_session_setup_spnego`.

Impact:

- SMB 3.0 / 3.0.2 multichannel clients cannot bind additional channels.
- Credit, IPC, and high-availability scenarios that rely on multichannel are blocked.

Required fix:

- Allow binding for SMB 3.0 and 3.0.2 when the normal SMB3 binding rules are satisfied.
- Keep the preauth hash requirement only for SMB 3.1.1.

### 2. High: SMB3 compression negotiate-context handling is not spec-compliant

Code:

- `src/protocol/smb2/smb2_negotiate.c:85-95`
- `src/protocol/smb2/smb2_negotiate.c:206-219`
- `src/protocol/smb2/smb2_negotiate.c:411-468`

Key issue:

- `decode_compress_ctxt()` reduces the client's offered compression list to a single preferred algorithm in `conn->compress_algorithm`.
- `build_compress_ctxt()` always emits exactly one algorithm.
- `assemble_neg_contexts()` omits the compression context entirely when there is no overlap.

Why this is non-compliant:

- `MS-SMB2` requires the server to retain all common compression algorithms, in client order, in `Connection.CompressionIds`.
- If there is no common algorithm, the server should still answer with a compression context containing `NONE`, not silently omit the context.

Impact:

- Clients do not get an accurate negotiated algorithm set.
- Clients that expect `NONE` or a multi-entry response can make incorrect compression decisions.

Required fix:

- Store the full intersected algorithm list, not a single scalar.
- Emit all common algorithms in the response.
- Emit `NONE` when there is no overlap.

### 3. High: Transport security negotiate-context semantics are wrong on plain TCP

Code:

- `src/protocol/smb2/smb2_negotiate.c:132-140`
- `src/protocol/smb2/smb2_negotiate.c:267-275`
- `src/protocol/smb2/smb2_negotiate.c:539-551`
- `src/transport/transport_quic.c:2573-2576`

Key issue:

- `decode_transport_cap_ctxt()` sets `conn->transport_secured = true` when the client says it accepts transport-level security.
- `assemble_neg_contexts()` then uses that same flag to emit `SMB2_TRANSPORT_CAPABILITIES` with `SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY`.
- The same boolean is also used by the QUIC transport to mean the transport is actually secured.

Why this is non-compliant:

- `MS-SMB2` limits this context to transport-secured connections such as SMB over QUIC.
- On plain TCP, a client can provoke ksmbd into echoing a transport-security capability that does not exist on the connection.

Impact:

- False capability advertisement during negotiate.
- Clients can misclassify the transport as transport-secured when it is not.

Required fix:

- Split "client accepts transport security" from "this connection is transport-secured".
- Emit the response context only on actual transport-secured connections.

### 4. High: RDMA transform negotiation advertises more than the implementation can honor

Code:

- `src/protocol/smb2/smb2_negotiate.c:109-129`
- `src/protocol/smb2/smb2_negotiate.c:554-595`
- `src/transport/transport_rdma.c:1781-1794`
- `src/transport/transport_rdma.c:2153-2189`

Key issue:

- `decode_rdma_transform_ctxt()` records `NONE`, `ENCRYPTION`, and `SIGNING` directly from the client request into `conn->rdma_transform_ids[]` without intersecting that list against actual server support.
- `build_rdma_transform_ctxt()` then echoes the stored list back to the client.
- The runtime transform decision in `smb_direct_rdma_transform_needed()` is keyed only off `conn->cipher_type`, so signing-only transform negotiation is not honored.
- The RDMA transmit path still contains explicit warnings that negotiated encryption or signing transforms are not applied.

Why this is non-compliant:

- `MS-SMB2` requires the RDMA transform response to advertise the common supported transforms, not simply mirror the client's offered IDs.
- Unsupported transform IDs must not be returned as negotiated.

Impact:

- Clients can believe RDMA signing support was negotiated when the server does not actually enforce it.
- The negotiate transcript does not accurately describe server behavior.

Required fix:

- Build an explicit server-supported transform set.
- Intersect client and server transform IDs before populating `conn->rdma_transform_ids[]`.
- Do not advertise `SIGNING` until the runtime path really enforces it.

## Medium Findings

### 5. Medium: Named-pipe `FSCTL_PIPE_WAIT` and `FSCTL_PIPE_PEEK` are compatibility stubs

Code:

- `src/fs/ksmbd_fsctl_extra.c:189-259`
- `src/fs/ksmbd_fsctl.c:726-758`

Key issue:

- `FSCTL_PIPE_WAIT` does not resolve by pipe name or wait on pipe-instance availability. It only checks whether a supplied FID is open and then sleeps up to 50 ms before returning `STATUS_IO_TIMEOUT`.
- `FSCTL_PIPE_PEEK` only returns `CONNECTED` or `DISCONNECTED` based on FID existence and does not surface realistic named-pipe state or data availability.

Why this is non-compliant:

- `MS-FSCC` defines these controls in terms of named-pipe object state, instance availability, and timeout behavior, not a shortcut FID existence probe.

Interop evidence:

- `TESTS/SWEEP/logs/smb2.credits.log:34-40` shows IPC-related failures in the credit tests.

Impact:

- Windows and Samba clients probing IPC behavior can get misleading pipe state and timeout behavior.

Required fix:

- Implement wait semantics keyed by pipe name and instance availability.
- Return full `PIPE_PEEK` state/data semantics instead of a binary handle-exists result.

### 6. Medium: SMB1 remains intentionally incomplete, but external builds enable it by default

Code:

- `src/protocol/smb1/smb1pdu.c:9947-10000`
- `src/protocol/smb1/smb1pdu.c:10057-10065`
- `Makefile:144-152`

Key issue:

- `NT_TRANSACT_CREATE` returns `STATUS_NOT_SUPPORTED`.
- SMB1 `NT_TRANSACT_IOCTL`/FSCTL bridging is explicitly not wired up.
- SMB1 `NOTIFY_CHANGE` is parked indefinitely because full SMB1 notify response generation does not exist.
- External module builds set `CONFIG_SMB_INSECURE_SERVER ?= y` and export it as enabled by default.

Why this matters:

- This is not a single isolated missing command. It means the SMB1 protocol surface is compatibility-partial by design.
- Because external builds enable SMB1 automatically, that partial surface is exposed unless the builder explicitly disables it.

Impact:

- Legacy SMB1 clients may connect successfully but encounter unsupported transaction, notify, and FSCTL semantics later in the session.

Required fix:

- Either disable SMB1 by default for external builds or clearly gate it behind an explicit compatibility warning.
- Do not represent the SMB1 surface as broadly interoperable in its current state.

### 7. Medium: Durable-handle v2 and lease interop still show unresolved production failures

Code paths reviewed:

- `src/protocol/smb2/smb2_create.c:862-1088`
- `src/protocol/smb2/smb2_create.c:1595-1650`
- `src/protocol/smb2/smb2_create.c:2828-2857`
- `src/fs/oplock.c` lease-break logic

Interop evidence:

- `TESTS/SWEEP/summary.txt:32-39, 45-56`
- `TESTS/SWEEP/logs/smb2.durable-v2-open.log:25-38`

Observed failures:

- `reopen1a` / `reopen2` return `NT_STATUS_OBJECT_NAME_NOT_FOUND` instead of success.
- `reopen1a-lease` reports the wrong durable-v2 response flag state.
- The sweep summary still shows large failure counts in `durable-open`, `durable-v2-open`, `dirlease`, and `lease`.

Assessment:

- The current durable and lease implementation has substantial logic and many recent fixes, but it is still not interoperability-stable by the torture evidence already present in the tree.
- I am not claiming a single definitive root cause from static review alone; this area needs targeted torture-driven debugging.

Impact:

- Reconnect, replay, and lease/durable interactions remain a production compatibility risk.

Required fix:

- Reproduce the current durable-v2 failures against the present tree and debug the reconnect/replay/lease interaction with packet traces plus `smb2_create.c`/`oplock.c`.

## Areas That Look Correct or Improved

These paths read as materially better aligned with the specs than the areas above:

- Preauth-integrity validation in `smb2_negotiate.c`
- Signing-capability selection order in `smb2_negotiate.c`
- SMB2 session security-buffer bounds checking in `smb2_session.c`
- `FSCTL_QUERY_NETWORK_INTERFACE_INFO` structure building in `ksmbd_fsctl.c`
- Many create-path validations in `smb2_create.c`

Those areas should not be treated as proof of full interoperability, but they are not the primary compatibility blockers in the current tree.

## Priority Order

1. Fix SMB3 multichannel binding for SMB 3.0/3.0.2.
2. Correct negotiate-context semantics for compression, transport security, and RDMA transforms.
3. Decide whether SMB1 should remain enabled by default in external builds.
4. Replace the named-pipe FSCTL stubs with real object-state semantics.
5. Run a focused `smbtorture` pass on durable-v2, lease, dirlease, notify, and credits after the above fixes.

## References

- Microsoft Open Specifications, SMB2/SMB3 Protocol (`MS-SMB2`): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
- Microsoft Open Specifications, File System Control Codes (`MS-FSCC`): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/
- Local interoperability evidence under `TESTS/SWEEP/`
