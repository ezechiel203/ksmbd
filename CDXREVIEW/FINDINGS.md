# Severity-Ordered Findings (Re-Review)

Date: 2026-02-23
Workspace: `/home/ezechiel203/ksmbd`

## Critical

- None in this re-review.

## High

- None in this re-review.

## Medium

### KSMBD-MED-004: `run_tests.sh` still fails in default non-dry mode
- Impact: advertised primary test entrypoint remains unusable without extra flags.
- Evidence:
- `TEST_LOG` default is `/dev/null` (`run_tests.sh:41`).
- Setup path unconditionally touches `TEST_LOG` (`run_tests.sh:288`).
- Full run fails immediately (`raw/ci_run_tests_full.log`): `touch: setting times of '/dev/null': Permission denied`.
- Running with `--log-file` bypasses this specific setup failure (`raw/ci_run_tests_with_logfile.log`).
- Recommended fix:
- If `TEST_LOG=/dev/null`, skip `touch` and file-directory creation; or default to an actual file path under `RESULTS_DIR`.

### KSMBD-MED-012: `test_compilation.sh` is stale and blocks full test flow
- Impact: `run_tests.sh` native path fails build phase even when setup is fixed.
- Evidence:
- Script requires removed files `smb2aapl.h` / `smb2aapl.c` (`test_compilation.sh:11`, `test_compilation.sh:22`).
- Current run fails at header check (`raw/ci_test_compilation.log`): `Missing smb2aapl.h`.
- `run_tests.sh --log-file ...` reaches build stage and fails on this same script (`raw/ci_run_tests_with_logfile.log`).
- Recommended fix:
- Replace this legacy script with checks for current module layout (`smb2fruit.*` and current feature units), or remove it from default run path.

### KSMBD-MED-005: CI still validates structure more than runtime behavior
- Impact: runtime regressions can still pass CI.
- Evidence:
- Workflow checks mostly build, grep, and source-count/syntax checks.
- KUnit and integration suites are not executed as first-class gating runtime jobs in current workflows.
- Recommended fix:
- Add real KUnit execution and at least one privileged integration smoke job in CI.

### KSMBD-MED-007: Core kernel style/process divergence remains high
- Impact: maintainability and upstream-review friction remain elevated.
- Evidence:
- Current core checkpatch totals: `115` errors, `1215` warnings across `110` files (`raw/ci_checkpatch_core.log`).
- Dominant classes remain `LINUX_VERSION_CODE` and constant-comparison warnings.
- Recommended fix:
- Keep cleanup focused on touched files and consolidate version-compat branching into narrow wrappers.

## Low

### KSMBD-LOW-008: Benchmark default is still single-iteration
- Impact: default benchmark confidence remains weak unless users opt into repetitions.
- Evidence:
- Iteration support exists, but default is `ITERATIONS=1` (`benchmarks/run_benchmarks.sh:37`).
- Recommended fix:
- Use multi-iteration defaults for CI/regression profiles and surface variance in reports.

### KSMBD-LOW-014: Shell script lint warnings remain
- Impact: script hygiene issues add maintenance noise.
- Evidence:
- `shellcheck` findings in test and benchmark scripts (`raw/ci_shellcheck_tests.log`, `raw/ci_shellcheck_benchmarks.log`).
- Dominant rule: `SC2034` (unused variables), plus some `SC2174` mkdir-with-`-p` mode warnings.
- Recommended fix:
- Remove dead variables, or annotate intentional unused values; address mkdir mode semantics where relevant.

### KSMBD-LOW-015: Cppcheck currently noisy and non-triaged
- Impact: static-analysis signal quality is low; real defects can be obscured.
- Evidence:
- Current run reports many issues (`raw/ci_cppcheck.log`), including generated-file parse errors (`ksmbd.mod.c`) and multiple uninitialized-variable traces.
- Workflow intent keeps cppcheck non-blocking.
- Recommended fix:
- Exclude generated files, tune suppressions/check-level for kernel code, then triage high-confidence hits.

## Resolved Since Prior CDXREVIEW

### KSMBD-CRIT-001: Original CHANGE_NOTIFY UAF/list-lifetime issue
- Status: **Resolved**.
- Evidence:
- Async-owned work is not freed by worker teardown path (`server.c:288` to `server.c:301`).
- Notify completion/cancel/cleanup paths now own teardown and free correctly (`ksmbd_notify.c:224`, `ksmbd_notify.c:476`, `ksmbd_notify.c:550`).

### KSMBD-HIGH-010: CHANGE_NOTIFY `req_running` leak
- Status: **Resolved**.
- Evidence:
- Async notify completion/cancel/cleanup now call `ksmbd_conn_try_dequeue_request()` before free (`ksmbd_notify.c:224`, `ksmbd_notify.c:476`, `ksmbd_notify.c:550`).

### KSMBD-HIGH-011: CHANGE_NOTIFY mark leak on successful completion
- Status: **Resolved**.
- Evidence:
- Success completion now destroys mark (`ksmbd_notify.c:232`), in addition to cancel/cleanup paths (`ksmbd_notify.c:480`, `ksmbd_notify.c:556`).

### KSMBD-HIGH-002: Build break on `FSNOTIFY_GROUP_NOFS`
- Status: **Resolved**.
- Evidence:
- Compatibility guard present (`ksmbd_notify.c:25` to `ksmbd_notify.c:29`), and `make W=1` passes.

### KSMBD-HIGH-003: `ksmbd-tools` profile path overflow
- Status: **Resolved**.
- Evidence:
- Path construction uses `g_strdup_printf` (`ksmbd-tools/mountd/rpc_samr.c:438`).

### Prior sparse/gcc analyzer actionable items
- Status: **Resolved for previously flagged targets**.
- Evidence:
- Current `C=2` and gcc analyzer passes complete without compiler `error:` diagnostics (`raw/ci_sparse_C2.log`, `raw/ci_gcc_fanalyzer.log`).
