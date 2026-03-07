# Parallel VM Plan for Faster Debugging

## Objective
Parallelize safety verification by isolating transport/protocol/features across multiple VMs and kernels.

## Proposed VM lanes
- VM-A (Arch): baseline SMB2/SMB3 regression and credit-stress.
- VM-B (Arch): notify/oplock/fsctl stress with lockdep-enabled kernel.
- VM-C (Arch): QUIC transport and reconnect/failure scenarios.
- VM-D (Arch): RDMA/IPC robustness and malformed netlink response injection.
- VM-E (Debian sid): cross-distro behavior and toolchain variance checks.

## Required instrumentation by lane
- Kernel config variants:
  - `CONFIG_KASAN`, `CONFIG_KCSAN`, `CONFIG_PROVE_LOCKING`, `CONFIG_DEBUG_ATOMIC_SLEEP`.
- Runtime capture:
  - `dmesg -w`, `journalctl -kf`, crash dump collection, lockdep traces.
- Workload:
  - smbtorture suites + targeted fuzzing + long-run soak.

## Execution model
1. Build signed/unsigned module variants with symbols.
2. Deploy same commit hash to all VMs.
3. Run per-lane suite concurrently.
4. Collect normalized artifacts:
   - kernel logs,
   - reproducer command set,
   - pass/fail manifest,
   - perf/latency summary.
5. Triage only findings reproducible in at least one sanitized lane.

## Exit criteria
- No soft lockup / hard lockup / RCU stall under stress suites.
- No infinite wait loops without graceful abort.
- No unbounded warning storms.
- All credit invariants preserved under compound + malformed traffic.
