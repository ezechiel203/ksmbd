# Refactor Roadmap (Fail-Safe Priority)

## Goal
Guarantee graceful failure and prevent kernel panic/hang vectors by making state transitions explicit, bounded, and auditable.

## Track 1: Credit subsystem hardening
1. Introduce central API:
   - `ksmbd_credit_charge(conn, work, charge)`
   - `ksmbd_credit_settle(conn, work, charge, grant)`
   - `ksmbd_credit_abort(conn, work)`
2. Add per-work state:
   - `credit_charge_applied` (bool)
   - `credit_charge_value` (u16)
3. Enforce invariants under lock:
   - `outstanding_credits <= total_credits`
   - `total_credits <= max_credits`
4. Remove all direct mutations of `conn->{total_credits,outstanding_credits}` outside credit module.
5. Add ratelimited violation counter and immediate connection quarantine when repeated invariant breaks occur.

## Track 2: IPC robustness
1. Replace read-lock mutation pattern in `handle_response` with strict ownership model.
2. Add per-entry state machine:
   - `WAITING -> RESPONDED -> CONSUMED/TIMED_OUT`
3. Reject duplicate/late responses deterministically.
4. Replace `WARN_ON(1)` with controlled ratelimited warning.
5. Add timeout metrics and invalid-response counters to debugfs.

## Track 3: Wait-loop and worker starvation controls
1. Any `for (;;)` / `while (1)` in request handling must have at least one hard escape budget.
2. Export debug counters:
   - loop retries,
   - timeout exits,
   - cancel exits,
   - forced connection teardown counts.
3. Introduce kill-switch policy:
   - If a connection causes repeated long waits, mark it degraded and close gracefully.

## Track 4: Defensive isolation around high-complexity async paths
1. `ksmbd_notify` and oplock paths:
   - codify lock ordering in comments and lockdep assertions.
   - wrap list transitions in small helpers with mandatory preconditions.
2. Add internal “must not block under spinlock” annotations and assertions.
3. Add failure-injection hooks for allocation and message-send failures.

## Track 5: CI safety net
1. Mandatory matrix:
   - KASAN + lockdep
   - KCSAN
   - UBSAN
   - PREEMPT and non-PREEMPT kernels
2. Add protocol-fuzz lane against SMB2 parser/compound requests.
3. Gate merges on:
   - no new WARN splats,
   - no lockdep inversions,
   - no sanitizer regressions.
