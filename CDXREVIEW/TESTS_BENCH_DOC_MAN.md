# Tests, Benchmarks, Documentation, Manpages (Re-Validation)

## Tests
- `run_tests.sh --dry-run` now works.
- `run_tests.sh` in default non-dry mode still fails in setup due `/dev/null` log handling.
- With explicit `--log-file`, launcher reaches build stage but fails because `test_compilation.sh` is stale (`smb2aapl.*` expectations).
- Native integration runner requires root and cannot run unprivileged in this environment.

## CI / Test Quality
- Local workflow-equivalent checks pass for build/sparse/source-structure guards.
- CI still mostly validates buildability and static structure rather than runtime behavior execution.
- KUnit/integration execution should be promoted to gating jobs.

## Benchmarks
- Benchmark scripts and `--help` flows work.
- Iteration support exists, but default remains single-iteration unless `--iterations` is provided.

## Documentation
- README positioning on Fruit stubs remains improved and aligned with code intent.
- Legacy test script references (`smb2aapl.*`) indicate remaining documentation/test drift in harness tooling.

## Manpages
- Build artifacts contain 7 manpages under `ksmbd-tools/builddir/`.
- Canonical editable source location for manpages is still not clearly first-class in the top-level docs layout.

## Lint / Static Extras
- `shellcheck` reports warnings in `tests/*.sh` and `benchmarks/*.sh`.
- `cppcheck` reports many findings; current output includes generated-file parse noise and requires triage/tuning.
