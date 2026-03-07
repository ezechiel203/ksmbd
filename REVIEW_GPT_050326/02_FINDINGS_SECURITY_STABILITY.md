# Findings: Safety, Security, Stability

## Critical

### F-001 Credit-accounting desynchronization on abort path
- Severity: Critical
- Files:
  - `src/core/server.c:379-394`
  - `src/protocol/smb2/smb2_pdu_common.c:436-443`
- What happens:
  - In `server.c`, the `SERVER_HANDLER_ABORT` path unconditionally calls `set_rsp_credits(work)`.
  - `smb2_set_rsp_credits()` always subtracts `credit_charge` from `total_credits`, and from `outstanding_credits` (or clamps underflow to 0).
  - For abort paths that happen before credit validation/addition in request path, `outstanding_credits` may not have been incremented, causing underflow/desync.
- Why this is dangerous:
  - Repeated desync can trigger credit starvation, erratic flow control, persistent underflow logs, and high contention around `credits_lock`.
  - User-provided soft lockup traces centered at `_raw_spin_lock` -> `smb2_set_rsp_credits` are consistent with a pathological credit-state regime.
- Required fix direction:
  - Make credit settlement stateful per work item (example: `work->credit_validated` / `work->credit_charged`).
  - In response path, decrement only if the request path actually charged credits.
  - Add invariant assertions (non-fatal, ratelimited) to detect impossible transitions.

### F-002 Locking violation on `outstanding_credits`
- Severity: Critical
- File:
  - `src/protocol/common/smb_common.c:178`
  - `src/protocol/common/smb_common.c:189`
- What happens:
  - `work->conn->outstanding_credits++` is performed without `conn->credits_lock`.
- Why this is dangerous:
  - Races with SMB2 credit operations that do use `credits_lock`, breaking counter integrity and enabling false underflow/overflow states.
- Required fix direction:
  - Route all credit mutations through one lock-protected helper API (`ksmbd_credit_charge()`, `ksmbd_credit_settle()`).
  - Ban direct field mutation by convention and CI grep checks.

## High

### F-003 IPC response entry race and response clobber
- Severity: High
- File:
  - `src/transport/transport_ipc.c:366-383`
- What happens:
  - `handle_response()` traverses message table under `down_read(&ipc_msg_table_lock)` but mutates `entry->response` and `entry->msg_sz`.
  - It also sets `entry->response = NULL` before type validation.
- Why this is dangerous:
  - Concurrent replies for same handle can clobber valid response pointer, cause timeout in waiter, or produce stale/wrong wakeups.
- Required fix direction:
  - Protect mutable entry fields with write-side lock or per-entry spin/mutex.
  - Never clear `entry->response` unless consuming under strict ownership.
  - Reject duplicate responses once a response is present.

### F-004 External warning amplification via `WARN_ON(1)`
- Severity: High
- File:
  - `src/transport/transport_ipc.c:529`
- What happens:
  - Unsupported event type triggers `WARN_ON(1)`.
- Why this is dangerous:
  - Warning stack traces are heavyweight and can be abused by privileged local actors (CAP_NET_ADMIN), causing noisy logs and operational instability.
- Required fix direction:
  - Replace with ratelimited `pr_warn_ratelimited` and clean error return.

## Medium

### F-005 Unbounded blocking wait loop for POSIX lock path
- Severity: Medium
- File:
  - `src/protocol/smb2/smb2_lock.c:275-299`
- What happens:
  - `for (;;)` loops with periodic timeout checks; cancellation-aware but no hard upper bound.
- Why this matters:
  - Under adversarial lock contention, worker occupancy can be prolonged and service quality degraded.
- Required fix direction:
  - Add bounded wait policy (`max_wait_jiffies` / retry budget), return graceful timeout status.
  - Add telemetry counters for lock-wait abort/timeouts.

### F-006 Build/test blind spot in host environment
- Severity: Medium
- Evidence:
  - `make all` fails: missing `/lib/modules/6.18.9-arch1-2/build`.
- Why this matters:
  - Safety-critical regressions may pass source review but fail runtime/static instrumentation.
- Required fix direction:
  - Standardize validated build lanes in VMs with matching kernel headers and sanitizers enabled.

## Notes on previously suspected issues
- Several initial snippet-derived suspicions were re-verified and dismissed as non-issues after full-context reads (e.g., list transitions in notify cleanup and repeated variable names across different functions).
- This report only keeps confirmed or strongly evidenced issues.
