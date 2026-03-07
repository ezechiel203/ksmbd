# Debug Gates Recommendations

## Gate design principles
- Gates must be low-overhead when disabled.
- Gates must never alter protocol-visible behavior in production mode.
- All gate logs must be ratelimited.

## Gate set A: credit invariants
- Add `CONFIG_KSMBD_DEBUG_CREDITS` blocks around charge/settle points.
- Log tuple: `conn_id`, `cmd`, `mid`, `charge`, `total`, `outstanding`, `work_state`.
- Gate action on invariant break:
  - increment violation counter,
  - if threshold exceeded, disconnect connection gracefully.

## Gate set B: IPC state machine
- Add state transition tracepoints for request handle lifecycle.
- Record duplicate/late response events.
- Gate action:
  - discard out-of-state response,
  - no warning stack trace.

## Gate set C: long wait loops
- Add periodic watchdog checkpoints in blocking loops.
- Record wait duration buckets.
- Gate action:
  - convert excessive wait to timeout status and cleanup.

## Gate set D: async list operations
- Wrap list move/delete patterns in helper macros with lock precondition checks.
- Emit one-shot warning when operation called without expected lock state.

## Gate set E: panic avoidance policy
- Replace `WARN_ON(1)` style hard warning paths on external input with controlled error returns.
- Reserve `WARN_ON` for internal impossible states only.
