# ksmbd Compatibility Failure Backlog

Date: 2026-03-07

This backlog is generated from the `P0` and protocol-truthfulness rows in [COMPLIANCE_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/COMPLIANCE_MATRIX.csv). Each item is an implementation issue, not just a documentation note.

## KCOMPAT-001

- Matrix row: `CONFIG_SMB1_ENABLED_BY_DEFAULT`
- Problem: external builds enable SMB1 by default while the SMB1 surface is still intentionally incomplete
- Evidence: [Makefile](/home/ezechiel203/ksmbd/Makefile#L144), [smb1pdu.c](/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c#L9947), [smb1pdu.c](/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c#L10057)
- Required change: either disable SMB1 by default or commit to completing the full SMB1 transaction and RPC legacy surface
- 2026-03-07 progress: external `make all` builds now default `CONFIG_SMB_INSECURE_SERVER=n`; SMB1 stays opt-in instead of being silently enabled in production-default module builds
- Acceptance criteria: default external build does not expose knowingly incomplete SMB1 features, or the SMB1 matrix is fully green with interop proof

## KCOMPAT-002

- Matrix row: `SMB_COM_NT_TRANSACT`
- Problem: NT transact support is incomplete while the command remains enabled
- Evidence: [smb1ops.c](/home/ezechiel203/ksmbd/src/protocol/smb1/smb1ops.c#L77), [smb1pdu.c](/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c#L9947)
- Required change: enumerate each NT transact subcommand, implement missing semantics, and add Windows/Samba SMB1 interop coverage
- Acceptance criteria: all supported NT transact subcommands are documented, tested, and return spec-correct status codes and payloads

## KCOMPAT-003

- Matrix row: `SMB_COM_NT_TRANSACT_SECONDARY`
- Problem: secondary request assembly path is not proven compliant for fragmented legacy requests
- Evidence: [smb1ops.c](/home/ezechiel203/ksmbd/src/protocol/smb1/smb1ops.c#L78), [smb1pdu.c](/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c#L10057)
- Required change: validate fragmented NT transact assembly, bounds checking, and completion semantics against Windows clients and Samba
- Acceptance criteria: fragmented secondary flows pass targeted interop suites without status or payload deviations

## KCOMPAT-004

- Matrix row: `SMB2_COMPRESSION_CAPABILITIES`
- Problem: partially fixed. ksmbd now preserves the negotiated common algorithm set and stops negotiating non-spec `LZ4`, but `NONE` semantics and chained-capability signaling still need spec-level cleanup
- Evidence: [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L85), [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L206), [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L411)
- Progress: [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L85) now assembles the full negotiated compression list; [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L440) retains the full common set in client order; [smb2_compress.c](/home/ezechiel203/ksmbd/src/core/smb2_compress.c#L41) accepts any negotiated algorithm on incoming transform headers instead of only one scalar choice
- Required change: finish `NONE` handling and chained-capability semantics, then validate interop against Windows and Samba raw negotiate/compression traffic
- Acceptance criteria: compression negotiate contexts match MS-SMB2 rules across overlapping, disjoint, and `NONE`-only client offers, and compressed requests using any negotiated algorithm are accepted

## KCOMPAT-005

- Matrix row: `SMB2_TRANSPORT_CAPABILITIES`
- Problem: largely fixed. ksmbd now derives response advertisement from actual transport state instead of letting the client's request context rewrite the secure-transport bit
- Evidence: [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L132), [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L267), [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L539), [transport_quic.c](/home/ezechiel203/ksmbd/src/transport/transport_quic.c#L2573)
- Progress: [transport_quic.c](/home/ezechiel203/ksmbd/src/transport/transport_quic.c#L2573) remains the source of truth for secure transport, and [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L576) now treats the client transport-capability context as informational only
- 2026-03-08 progress: raw TCP negotiate proof is wired and passing for the negative case; full QUIC-side proof is still blocked by guest QUIC bring-up failing with `cannot register handshake genl family: -22`
- Required change: bring QUIC up in the harness, then run the raw negotiate / interop proof that QUIC emits transport security context and plain TCP does not
- Acceptance criteria: QUIC advertises secure transport, plain TCP does not, and negative interop tests fail when the context is misused

## KCOMPAT-006

- Matrix row: `SMB2_RDMA_TRANSFORM_CAPABILITIES`
- Problem: RDMA transform advertisement is not coupled to actually enforced signing or encryption transforms
- Evidence: [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L109), [smb2_negotiate.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c#L554), [transport_rdma.c](/home/ezechiel203/ksmbd/src/transport/transport_rdma.c#L1781), [transport_rdma.c](/home/ezechiel203/ksmbd/src/transport/transport_rdma.c#L2153)
- 2026-03-08 progress: ksmbd continues to suppress RDMA transform negotiation, and SMB2 READ/WRITE now explicitly reject `SMB2_CHANNEL_RDMA_TRANSFORM` instead of silently treating it as a normal channel when transforms were never negotiated
- Required change: implement full negotiated transform enforcement or stop advertising unsupported transform IDs
- Acceptance criteria: each advertised RDMA transform is negotiated, transmitted, received, and verified on the wire in directed tests

## KCOMPAT-007

- Matrix row: `SMB3_SESSION_BINDING`
- Problem: resolved for the known live defect. The remaining gap is broader multichannel failover proof, not the original binding logic bug.
- Evidence: [smb2_session.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_session.c#L782), [smb2.credits.log](/home/ezechiel203/ksmbd/TESTS/SWEEP/logs/smb2.credits.log#L36)
- 2026-03-08 progress: binding admission now distinguishes SMB 3.0/3.0.2 from SMB 3.1.1 preauth requirements, and the final SMB3 bind `SESSION_SETUP` signature mismatch was fixed by restoring request signatures after verification in [smb2_pdu_common.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_pdu_common.c). `smb2.credits.multichannel_max_async_credits`, `smb2.credits.multichannel_ipc_max_async_credits`, and the full `smb2.credits` suite now pass on VM10.
- Required change: run the broader multichannel/failover suites, not just the credit-driven bind coverage
- Acceptance criteria: SMB 3.0 and 3.0.2 multichannel binding passes targeted interop tests while 3.1.1 still enforces preauth rules, and T53-style failover coverage is green

## KCOMPAT-008

- Matrix rows: `DH2Q`, `DH2C`
- Problem: no longer red in the core open path, but the full durable-v2 cluster still lacks refreshed regression closure
- Evidence: [smb2.durable-v2-open.log](/home/ezechiel203/ksmbd/TESTS/SWEEP/logs/smb2.durable-v2-open.log#L25), [summary.txt](/home/ezechiel203/ksmbd/TESTS/SWEEP/summary.txt#L32), [smb2_create.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c#L1546), [smb2_create.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c#L1623)
- 2026-03-08 progress: `smb2.durable-v2-open` is now green on VM10, including `durable-v2-setinfo` and reconnect coverage such as `reconnect-twice`
- Required change: rerun and normalize `smb2.durable-v2-delay` and `smb2.durable-v2-regressions` on the current tree, then close any remaining replay/persistent-handle edge cases
- Acceptance criteria: `smb2.durable-v2-open`, `smb2.durable-v2-delay`, and `smb2.durable-v2-regressions` are green in CI

## KCOMPAT-009

- Matrix row: `DIRLEASE`
- Problem: largely fixed for the current branch; the remaining gap is broader replay/lease-state proof rather than the old dirlease failures
- Evidence: [summary.txt](/home/ezechiel203/ksmbd/TESTS/SWEEP/summary.txt#L45), [smb2_create.c](/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c#L2922)
- 2026-03-07 progress: `smbtorture smb2.notify` is now green end-to-end on VM3 after the notify cleanup, recursive propagation, delete-pending completion, and live-connection async retry fixes in [ksmbd_notify.c](/home/ezechiel203/ksmbd/src/fs/ksmbd_notify.c)
- 2026-03-08 progress: `smb2.dirlease` is now green on VM10
- Required change: keep dirlease coverage in the replay/lease-state regression loop so it does not regress while the remaining lease bugs are fixed
- Acceptance criteria: `smb2.dirlease`, `smb2.notify`, and relevant replay suites are green and stable under timeout stress

## KCOMPAT-010

- Matrix row: `SMB Direct`
- Problem: RDMA transport implementation exists, but compliance-grade truthfulness and interop proof are missing
- Evidence: [transport_rdma.c](/home/ezechiel203/ksmbd/src/transport/transport_rdma.c#L255), [transport_rdma.c](/home/ezechiel203/ksmbd/src/transport/transport_rdma.c#L2162)
- Required change: define supported SMB Direct feature set, enforce negotiated transforms, and build directed RDMA interop tests
- Acceptance criteria: supported SMB Direct feature list is explicit and every advertised feature has passing wire-level tests

## KCOMPAT-011

- Matrix row: `SMB over QUIC`
- Problem: QUIC code surface is large, but compliance-grade interop and transport-parameter validation are not yet in place
- Evidence: [transport_quic.c](/home/ezechiel203/ksmbd/src/transport/transport_quic.c#L5), [transport_quic.c](/home/ezechiel203/ksmbd/src/transport/transport_quic.c#L957)
- 2026-03-08 progress: `ksmbd-tools` now has a real picotls-backed TLS 1.3 handshake delegate, direct `quic-picotls` regression passes, and the kernel listener is gated on delegate registration instead of exposing a dead QUIC surface
- Required change: validate RFC 9000/9001 behavior, SMB-over-QUIC Appendix C constraints, TLS handshake delegation correctness, and transport capability advertisement
- Acceptance criteria: directed QUIC interop suite passes against at least one Windows client and one protocol harness, with transport-capability signaling verified

## KCOMPAT-012

- Matrix row: `FSCTL_PIPE_PEEK`
- Problem: no longer a zeroed stub, but still not full Windows-parity named-pipe semantics
- Evidence: [ksmbd_fsctl.c](/home/ezechiel203/ksmbd/src/fs/ksmbd_fsctl.c#L726), [COMPLIANCE_MATRIX.csv](/home/ezechiel203/ksmbd/GPT_TMP/COMPAT_AUDIT/COMPLIANCE_MATRIX.csv)
- Required change: implement real pipe state inspection, byte counts, message framing semantics, and status code behavior
- 2026-03-07 progress: kernel and `ksmbd-tools` now expose an RPC pipe-state query path; `FSCTL_PIPE_PEEK` reports connected/disconnected state and pending response byte counts from live RPC state instead of a zeroed stub
- Acceptance criteria: pipe peek behavior matches Windows clients across empty, listening, connected, closing, and data-available states

## KCOMPAT-013

- Matrix row: `FSCTL_PIPE_WAIT`
- Problem: wire parsing and status behavior are improved, but real listener-queue blocking semantics are still missing
- Evidence: [ksmbd_fsctl_extra.c](/home/ezechiel203/ksmbd/src/fs/ksmbd_fsctl_extra.c#L180), [ksmbd_fsctl_extra.c](/home/ezechiel203/ksmbd/src/fs/ksmbd_fsctl_extra.c#L190)
- Required change: add listener queue semantics for named pipes and implement timeout handling per the FSCTL contract
- 2026-03-07 progress: `FSCTL_PIPE_WAIT` now validates the requested pipe name on the wire, normalizes `\\PIPE\\` paths, succeeds immediately for the fixed supported RPC surface, and returns `STATUS_OBJECT_NAME_NOT_FOUND` for unsupported pipes instead of fabricating a timeout
- 2026-03-08 progress: indefinite wait semantics are preserved when `TimeoutSpecified == 0`, and pipe availability probing now checks live RPC openability rather than only a static supported-name table
- Acceptance criteria: pipe wait blocks and resolves correctly across available, busy, timeout, and cancellation scenarios

## KCOMPAT-014

- Matrix row: `IPC$ RPC over SMB`
- Problem: transport semantics are improved, but broad DCE/RPC interoperability coverage is still missing
- Evidence: [rpc.c](/home/ezechiel203/ksmbd/ksmbd-tools/mountd/rpc.c), [ksmbd_fsctl.c](/home/ezechiel203/ksmbd/src/fs/ksmbd_fsctl.c#L1927)
- Required change: finish named-pipe transport semantics first, then expand and validate DCE/RPC bind, fragment, auth, and interface behaviors
- 2026-03-07 progress: SMB2 `QUERY_INFO` for `FILE_PIPE_INFORMATION` and `FILE_PIPE_LOCAL_INFORMATION` now uses live RPC pipe state, SMB2 pipe `SET_INFO` for advertised pipe info classes now validates RPC handles in the session pipe table, `FSCTL_PIPE_TRANSCEIVE` validates RPC handles in the correct session namespace, broken pipe reads/transceives return disconnected-pipe status, and SMB1 `TRANS2_QUERY_FILE_INFORMATION` rejects invalid pipe handles instead of answering with synthetic success
- 2026-03-08 progress: SMB2 pipe reads and `FSCTL_PIPE_TRANSCEIVE` now have real async pending completion paths, async connection-teardown cleanup decrements the outstanding async counter correctly, and `rpc_read_request()` no longer regenerates already-consumed bind replies after an IOCTL round-trip
- Acceptance criteria: srvsvc, wkssvc, samr, and lsarpc pass directed client interoperability tests over IPC$ named pipes
