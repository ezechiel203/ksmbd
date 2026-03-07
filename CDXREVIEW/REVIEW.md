# ksmbd Project Review (Re-Validation)

Date: 2026-02-23
Workspace: `/home/ezechiel203/ksmbd`

## Scope
- Kernel module core (`*.c`, `*.h`, excluding `ksmbd-tools/`, `test/`, `tests/`, docs): 110 files
- Full tracked C/H corpus (checkpatch): 144 files
- CHANGE_NOTIFY async lifecycle and prior critical/high issue set
- Local CI-equivalent workflow commands and test launchers

## What I Ran
- `make clean`
- `make -j$(nproc)`
- `make -j$(nproc) W=1`
- `make -k -j$(nproc) C=2`
- `make -k -j$(nproc) W=1 KCFLAGS='-fanalyzer -Wanalyzer-double-free -Wanalyzer-use-after-free -Wanalyzer-null-dereference -Wanalyzer-out-of-bounds -Wanalyzer-malloc-leak'`
- Local workflow emulation checks (BUG_ON scan, source-structure checks, benchmark/help checks)
- `checkpatch.pl` full/core scans
- `cppcheck` and `shellcheck` sweeps
- `./run_tests.sh --dry-run`
- `./run_tests.sh` (full)
- `./run_tests.sh --log-file /tmp/ksmbd_run_tests.log`
- Native test helpers: `./test_compilation.sh`, `./tests/run_integration.sh --skip-smbtorture`, `./tests/run_smbtorture.sh --list`, `./benchmarks/run_benchmarks.sh --help`

## Headline
The previously flagged high-severity CHANGE_NOTIFY lifecycle issues are fixed correctly in the current tree. Core build/static checks pass. The remaining problems are now mostly in test/CI harness quality:

1. `run_tests.sh` still fails by default in non-dry mode (`touch /dev/null`),
2. `test_compilation.sh` is stale and targets removed `smb2aapl.*` files,
3. CI still emphasizes structural checks over true runtime execution.

See [FINDINGS.md](./FINDINGS.md) for severity-ordered details and resolved items.
