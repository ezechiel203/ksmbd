# KSMBD Safety/Security/Stability Deep Review (2026-03-05)

## Scope
- Repository: `/home/ezechiel203/ksmbd`
- Branch/commit reviewed: `phase1-security-hardening` @ `83c84bb6`
- Focus: kernel safety, security hardening, stability under malformed traffic, graceful-failure behavior.
- Reviewed code: `src/` full tree plus high-risk deep dives in `core`, `protocol/smb2`, `fs/notify`, `transport/ipc`, `transport/quic`.

## High-level result
- The tree contains substantial defensive work already (timeouts, overflow checks, lock-protected counters, many cleanup guards).
- There are still **critical consistency/race risks** in credit accounting and IPC response handling that can create hangs, desync, request stalls, and unpredictable behavior under adversarial or malformed traffic.
- Prior dmesg evidence provided by user (soft lockups in `smb2_set_rsp_credits`) is consistent with a credit-state desynchronization path observed in current code.

## Confirmed high-priority findings
1. Credit desync risk on server abort path (`src/core/server.c:379-394` + `src/protocol/smb2/smb2_pdu_common.c:436-443`).
2. `outstanding_credits` updated without `credits_lock` in SMB1 paths (`src/protocol/common/smb_common.c:178`, `:189`).
3. IPC response race/clobber in `handle_response` due mutable shared entry under read lock and unconditional response reset (`src/transport/transport_ipc.c:366-383`).
4. `WARN_ON(1)` on unsupported IPC type is externally triggerable by CAP_NET_ADMIN users and can become warning-flood/operational DoS (`src/transport/transport_ipc.c:529`).
5. Indefinite lock-wait loop can be used for worker starvation pressure even though cancellation checks exist (`src/protocol/smb2/smb2_lock.c:275-299`).

## Output artifacts
- Findings and severity: `02_FINDINGS_SECURITY_STABILITY.md`
- Refactor plan and fail-safe architecture: `03_REFACTOR_ROADMAP.md`
- Debug-gate plan: `07_DEBUG_GATES_RECOMMENDATIONS.md`
- Parallel multi-agent split and VM scaling plan: `04_PARALLEL_VM_PLAN.md`, `06_AGENT_WORK_PACKETS.md`
- Full file metrics/coverage: `05_FILE_COVERAGE_MATRIX.csv`

## Tooling constraints encountered
- Kernel headers for active host kernel are missing (`/lib/modules/6.18.9-arch1-2/build`), so full module compile/static toolchain integration could not be executed in this host environment.
- `cppcheck` kernel-aware scan is partially blocked by unresolved kernel macros unless wrapped by a kernel build context.
