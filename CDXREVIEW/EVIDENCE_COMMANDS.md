# Evidence Commands and Results (Re-Validation)

## Build / Static
- `make clean` -> success (`raw/ci_make_clean.log`)
- `make -j$(nproc)` -> success (`raw/ci_make.log`)
- `make -j$(nproc) W=1` -> success (`raw/ci_make_W1.log`)
- `make -k -j$(nproc) C=2` -> success (`raw/ci_sparse_C2.log`)
- `make -k -j$(nproc) W=1 KCFLAGS='-fanalyzer ...'` -> success (`raw/ci_gcc_fanalyzer.log`)

## CI-Equivalent Workflow Sweep
- Local workflow emulation script -> completed (`raw/ci_local_workflows.log`)
- BUG_ON scan -> none found
- KUnit/fuzz/test-makefile structural checks -> pass
- Benchmark script presence/help checks -> pass
- Optional tools now present: `cppcheck`, `shellcheck`

## Lint / Static Extras
- `checkpatch` full scan -> `144` files, `115` errors, `1231` warnings (`raw/ci_checkpatch_full.log`)
- `checkpatch` core scan -> `110` files, `115` errors, `1215` warnings (`raw/ci_checkpatch_core.log`)
- `cppcheck` run -> findings emitted (`raw/ci_cppcheck.log`), including generated-file parse issue and numerous uninit traces
- `shellcheck tests/*.sh` -> warnings (`raw/ci_shellcheck_tests.log`)
- `shellcheck benchmarks/*.sh` -> warnings (`raw/ci_shellcheck_benchmarks.log`)

## Test Entry / Runtime
- `./run_tests.sh --dry-run` -> success (`raw/ci_run_tests_dry.log`)
- `./run_tests.sh` -> fails in setup (`raw/ci_run_tests_full.log`), `/dev/null` touch error
- `./run_tests.sh --log-file /tmp/ksmbd_run_tests.log` -> setup passes, build phase fails in `test_compilation.sh` (`raw/ci_run_tests_with_logfile.log`)
- `./test_compilation.sh` -> fails: missing legacy `smb2aapl.h` (`raw/ci_test_compilation.log`)
- `./tests/run_integration.sh --skip-smbtorture` -> fails: requires root (`raw/ci_run_integration_full.log`)
- `./tests/run_smbtorture.sh --list` -> success (`raw/ci_run_smbtorture_list.log`)
- `./benchmarks/run_benchmarks.sh --help` -> success (`raw/ci_run_benchmarks_help.log`)
