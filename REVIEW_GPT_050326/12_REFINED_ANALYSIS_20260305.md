# Refined Deep Review Update (2026-03-05)

## What was refined
This pass deepened the previous analysis with:
- additional stall/hang hardening patches in production code,
- timeout arithmetic hardening,
- regenerated full line-tag corpus,
- generated file-by-file line-level review artifacts.

## New hardening patches in this pass

### R-001 IPC timeout storage/overflow hardening
- Files:
  - `src/include/core/server.h:39`
  - `src/transport/transport_ipc.c:419`
- Change:
  - `server_conf.ipc_timeout` widened from `unsigned short` to `unsigned long`.
  - Added `check_mul_overflow()` for `req->ipc_timeout * HZ` before assignment.
- Risk mitigated:
  - jiffies truncation/wrap leading to broken heartbeat scheduling and unstable daemon liveness behavior.

### R-002 Bounded SMB2 deferred lock waits
- File:
  - `src/protocol/smb2/smb2_lock.c:271`
  - `src/protocol/smb2/smb2_lock.c:945`
- Change:
  - Added bounded wait budget (`KSMBD_POSIX_LOCK_WAIT_MAX_JIFFIES = 300 * HZ`) in deferred lock wait loop.
  - Timeout now returns `-ETIMEDOUT` and is mapped to `STATUS_LOCK_NOT_GRANTED`.
- Risk mitigated:
  - prevents effectively unbounded worker residency on lock contention storms.

## Updated line-by-line corpus
- Tag CSV (all production C/H lines):
  - `LINE_AUDIT/ALL_LINES_TAGGED.csv` (88,096 lines)
- Per-file line-by-line review documents:
  - `DETAILED_REVIEW/` (126 files)
  - total lines: 176,442
- Hotspot summary:
  - `LINE_AUDIT/TOP_WAIT_LOCK_RISK.csv`

## Current top unresolved risks (still open)
1. Full runtime sanitizer verification not completed in this host due missing matching kernel headers (`/lib/modules/6.18.9-arch1-2/build`).
2. Protocol conformance claim to “100% MS-SMB/MS-SMB2” still requires full normative cross-matrix execution against all relevant clauses and smbtorture/fuzz coverage in VM matrix.
3. Highest-complexity code paths still needing deeper manual proof by execution traces:
   - `src/transport/transport_rdma.c`
   - `src/transport/transport_quic.c`
   - `src/fs/oplock.c`
   - `src/fs/vfs.c`
   - `src/protocol/smb1/smb1pdu.c`

## Strict next execution plan
1. Run lockdep/KASAN/KCSAN lanes on VM A-E with current patched tree.
2. Drive targeted stress suites against the five hotspot subsystems above.
3. Promote only findings that are reproducible under sanitizers or protocol conformance tests.
