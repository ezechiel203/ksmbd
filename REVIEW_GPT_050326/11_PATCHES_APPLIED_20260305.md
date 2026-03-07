# Patches Applied During Deep Review (2026-03-05)

## Scope
Applied hardening patches directly in production code for critical/high issues discovered during review.

## Patch P-001: Credit settlement only debits outstanding credits when request path charged them
- Files:
  - `src/include/core/ksmbd_work.h`
  - `src/core/server.c`
  - `src/protocol/smb2/smb2misc.c`
  - `src/protocol/smb2/smb2_pdu_common.c`
- Summary:
  - Added per-command `work->credit_charge_tracked` state.
  - Reset per command in `__process_request()` before verification.
  - Marked as charged only in request validation paths that actually increase `outstanding_credits`.
  - In `smb2_set_rsp_credits()`, only decrement outstanding credits when tracked.
- Risk addressed:
  - Prevents false underflow and desync on abort/cancel paths that did not charge outstanding credits.

## Patch P-002: Lock protection for SMB1 outstanding credit increments
- File:
  - `src/protocol/common/smb_common.c`
- Summary:
  - Wrapped `outstanding_credits++` in `credits_lock` for SMB1 paths.
- Risk addressed:
  - Removes race between SMB1 increments and SMB2 lock-protected credit accounting.

## Patch P-003: IPC response table race hardening
- File:
  - `src/transport/transport_ipc.c`
- Summary:
  - Switched `handle_response()` from `down_read` to `down_write` because it mutates entry state.
  - Removed unsafe `entry->response = NULL` reset.
  - Added duplicate-response guard with ratelimited warning.
  - Added explicit return codes for bad type/duplicate/missing entry.
- Risk addressed:
  - Prevents clobbered responses/timeouts/racy wakeups.

## Patch P-004: Replace externally triggerable WARN path
- File:
  - `src/transport/transport_ipc.c`
- Summary:
  - Replaced `WARN_ON(1)` for unknown event type with `pr_warn_ratelimited` + `-EINVAL`.
- Risk addressed:
  - Reduces warning-stack amplification vector and log-flood impact.

## Validation
- `git diff --check` clean for touched files.
- Full module compile not possible on host due missing matching kernel headers (`/lib/modules/6.18.9-arch1-2/build`).
