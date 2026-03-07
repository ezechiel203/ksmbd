# Docs to Code Mapping

## Purpose
Map the future-project planning documents to exact source targets in this repository and suggest a practical patch order.

## Rule
This mapping is intentionally repo-specific. It identifies where work most likely lands, not just where concepts live.

## Program A Mapping
### A1 Transport and Crypto
Primary docs:
1. `MEGAPLAN_WINDOWS_PARITY.md`
2. `A_PROGRAM_MILESTONE_BOARD.md`
3. `IMPLEMENTATION_BOARD.md`

Primary code targets:
1. `src/transport/transport_quic.c`
2. `src/transport/transport_rdma.c`
3. `src/core/server.c`
4. `src/protocol/smb2/smb2_negotiate.c`
5. `src/protocol/smb2/smb2misc.c`

Suggested patch order:
1. QUIC Retry integrity correctness
2. QUIC 1-RTT HP key derivation and state storage
3. remove any transport insecure fallback conditions
4. RDMA transform security only if SMB Direct is moved into scope

### A2 Durable and Persistent State
Primary docs:
1. `MEGAPLAN_WINDOWS_PARITY.md`
2. `A_PROGRAM_MILESTONE_BOARD.md`
3. `IMPLEMENTATION_BOARD.md`

Primary code targets:
1. `src/protocol/smb2/smb2_create.c`
2. `src/protocol/smb2/smb2_ph.c`
3. `src/fs/vfs_cache.c`
4. `src/fs/oplock.c`
5. `src/protocol/smb2/smb2_lock.c`
6. `src/protocol/smb2/smb2ops.c`

Suggested patch order:
1. reconnect-path audit and tests
2. lock survival validation and fixes
3. lease/oplock reconnect validation and fixes
4. crash/restart behavior hardening

### A3 VM-Disk I/O Semantics
Primary docs:
1. `MEGAPLAN_WINDOWS_PARITY.md`
2. `A_PROGRAM_MILESTONE_BOARD.md`

Primary code targets:
1. `src/protocol/smb2/smb2_read_write.c`
2. `src/protocol/smb2/smb2_ioctl.c`
3. `src/fs/vfs.c`
4. `src/fs/ksmbd_fsctl.c`
5. `src/fs/ksmbd_fsctl_extra.c`
6. `src/fs/ksmbd_info.c`
7. `src/protocol/smb2/smb2_query_set.c`

Suggested patch order:
1. flush/FUA verification and fixes
2. sparse/zero-range verification and fixes
3. checkpoint/merge failure-path fixes
4. finalize filesystem-specific support notes for `xfs` and `ext4`

### A4 Auth and Session Stability
Primary docs:
1. `MEGAPLAN_WINDOWS_PARITY.md`
2. `A_PROGRAM_MILESTONE_BOARD.md`

Primary code targets:
1. `src/protocol/smb2/smb2_session.c`
2. `src/core/connection.c`
3. `src/core/server.c`
4. `ksmbd-tools/`

Suggested patch order:
1. logging and diagnosability
2. ticket-refresh and reconnect behavior
3. daemon-failure and timeout handling

### A5 Observability and Operations
Primary docs:
1. `MEGAPLAN_WINDOWS_PARITY.md`
2. `A_PROGRAM_MILESTONE_BOARD.md`

Primary code targets:
1. `src/core/`
2. `src/mgmt/`
3. `ksmbd-tools/`

Suggested patch order:
1. metrics inventory and insertion points
2. structured logging improvements
3. operator-facing tooling support

### A6 Interop Lab
Primary docs:
1. `WINDOWS_INTEROP_LAB_PLAN.md`
2. `A_PROGRAM_MILESTONE_BOARD.md`

Repo-adjacent targets:
1. future `tests/` tree
2. helper tooling in `ksmbd-tools/`
3. CI or external lab scripts outside current repo if needed

Suggested patch order:
1. matrix definition
2. automated VM lifecycle scripts
3. soak/fault-injection harness

## Program B Mapping
### B1 Multichannel and Witness
Primary docs:
1. `MEGAPLAN_WINDOWS_PARITY.md`
2. `IMPLEMENTATION_BOARD.md`
3. `B_PROGRAM_FEASIBILITY_DECISION.md`

Primary code targets:
1. `src/core/connection.c`
2. `src/core/server.c`
3. `src/protocol/smb2/smb2_session.c`
4. `src/protocol/smb2/smb2_negotiate.c`
5. `src/mgmt/ksmbd_witness.*`

Suggested patch order:
1. interface list and multichannel state model
2. witness event accuracy
3. bounded failover semantics if approved

### B2 Continuous Availability / Failover
Primary docs:
1. `CLUSTER_FAILOVER_STATE_MODEL.md`
2. `IMPLEMENTATION_BOARD.md`

Primary code targets:
1. `src/core/`
2. `src/fs/`
3. `src/protocol/smb2/`
4. possibly state-sharing code outside current repo

Suggested patch order:
1. shared-state architecture first
2. handle/session recovery model second
3. failover negative-path tests before support claims

### B3 NTFS Compatibility
Primary docs:
1. `NTFS_BACKEND_ARCHITECTURE_OPTIONS.md`
2. `B_PROGRAM_FEASIBILITY_DECISION.md`

Possible code targets depending on chosen architecture:
1. `src/fs/ksmbd_info.c`
2. `src/fs/ksmbd_fsctl.c`
3. `src/protocol/smb2/smb2_query_set.c`
4. `src/protocol/smb1/smb1pdu.c`
5. new metadata-layer code if chosen
6. code outside current repo if `ntfs3` work is chosen

Suggested patch order:
1. architecture freeze
2. one feature prototype, not all at once
3. short names/object IDs/compression/quota only after prototype validation

### B4 RSVD and VHDX
Primary docs:
1. `RSVD_VHDX_BACKEND_REQUIREMENTS.md`
2. `B_PROGRAM_FEASIBILITY_DECISION.md`

Primary code targets:
1. `src/fs/ksmbd_rsvd.c`
2. possibly `src/protocol/smb2/` control paths
3. future backend code likely outside current repo or in a new subsystem

Suggested patch order:
1. exact workflow scope and command matrix
2. reservation state model
3. backend prototype
4. only then mainline `ksmbd_rsvd.c` changes

### B5 FSCTL and Info-Class Completion
Primary docs:
1. `IMPLEMENTATION_BOARD.md`
2. `MEGAPLAN_WINDOWS_PARITY.md`

Primary code targets:
1. `src/fs/ksmbd_info.c`
2. `src/fs/ksmbd_fsctl.c`
3. `src/fs/ksmbd_fsctl_extra.c`
4. `src/protocol/smb2/smb2_query_set.c`
5. `src/protocol/smb1/smb1pdu.c`
6. `src/fs/ksmbd_branchcache.c`

Suggested patch order:
1. best-ROI FSCTL/info completions first
2. explicitly unsupported paths next with deliberate status mapping
3. NTFS-specific paths only after architecture decision

## Recommended Global Patch Order
### Immediate sequence for real engineering
1. Finish Program A scope freeze and decision lock
2. Complete transport hardening only for transports in the support claim
3. Complete durable/persistent handle and reconnect hardening
4. Validate VM-disk I/O semantics on `xfs` and `ext4`
5. Stabilize auth/session behavior
6. Stand up the Program A interoperability lab
7. Publish Program A support matrix

### Deferred sequence for Program B
1. Approve Program B explicitly
2. Freeze NTFS, RSVD, and failover architecture choices
3. Build the expanded lab before broad claims
4. Implement only one strategic branch at a time:
   - NTFS compatibility
   - RSVD/VHDX
   - cluster/failover

## Files Most Likely to Matter First
If implementation started tomorrow, the highest-priority source files are:
1. `src/protocol/smb2/smb2_create.c`
2. `src/protocol/smb2/smb2_ph.c`
3. `src/fs/vfs_cache.c`
4. `src/fs/oplock.c`
5. `src/protocol/smb2/smb2_read_write.c`
6. `src/protocol/smb2/smb2_ioctl.c`
7. `src/fs/vfs.c`
8. `src/protocol/smb2/smb2_session.c`
9. `src/core/connection.c`
10. `src/transport/transport_quic.c`
