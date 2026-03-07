# Agent Work Packets

## Agent 1: Credit and Connection Safety
- Files:
  - `src/core/server.c`
  - `src/core/connection.c`
  - `src/protocol/smb2/smb2misc.c`
  - `src/protocol/smb2/smb2_pdu_common.c`
  - `src/protocol/common/smb_common.c`
- Tasks:
  - eliminate direct credit counter mutations,
  - implement per-work credit state machine,
  - add invariant checks and negative tests.

## Agent 2: IPC and Userspace Bridge Resilience
- Files:
  - `src/transport/transport_ipc.c`
  - `src/mgmt/*` (interface assumptions)
- Tasks:
  - fix response table locking/state races,
  - remove warning amplification behavior,
  - add duplicate/late response handling tests.

## Agent 3: Notify/Oplock Async Lifetime Safety
- Files:
  - `src/fs/ksmbd_notify.c`
  - `src/fs/oplock.c`
  - `src/fs/vfs_cache.c`
- Tasks:
  - formalize lock ordering,
  - reduce long critical sections,
  - add stress tests for cleanup/teardown races.

## Agent 4: Transport Stress and Failover
- Files:
  - `src/transport/transport_tcp.c`
  - `src/transport/transport_quic.c`
  - `src/transport/transport_rdma.c`
- Tasks:
  - prove graceful behavior under disconnect storms,
  - no deadlocks on transport teardown,
  - gather perf + lock contention telemetry.

## Agent 5: Parser and Protocol Hardening
- Files:
  - `src/protocol/smb2/*`
  - `src/protocol/smb1/*`
- Tasks:
  - malformed/compound parser fuzzing,
  - bounds-validation consistency,
  - enforce “reject safely, never hang”.

## Coordination rules
- Every finding must include: exact file/line, reproducer, expected behavior, proposed patch pattern.
- No cross-agent merge without lockdep + sanitizer pass in at least one VM lane.
