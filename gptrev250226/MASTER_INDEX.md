# KSMBD Comprehensive Review (Module-by-Module, Line Coverage)

## Scope reviewed

- Files reviewed: 254
- Modules reviewed: 72 module buckets (kernel, userspace tools, tests, build/CI)
- Coverage manifest: `line_coverage.tsv` (every file with reviewed line range `1-N`)

## Method used

- Static scan pass:
  - `cppcheck` over `src`, `ksmbd-tools`, `test`, `tests`
  - `shellcheck` over shell scripts
- Build/test execution pass:
  - `./run_tests.sh`
  - make/build inspection
- Manual source validation pass:
  - verified high-risk tool findings directly in source
  - added protocol/security/concurrency review on session, fsctl, mgmt, and build/test control paths

## Finding summary

- High: 5
- Medium: 5
- Low: 2

See full findings in `findings_catalog.tsv` and `FINDINGS_DETAILED.md`.

## Top risks (priority order)

1. Binary GUID comparisons use `strncmp` in auth/validation paths (`src/protocol/smb2/smb2_session.c:569`, `src/fs/ksmbd_fsctl.c:210`).
2. `krealloc` pointer clobber in session teardown can lead to NULL dereference on OOM (`src/mgmt/user_session.c:290`, `src/mgmt/user_session.c:326`, `src/mgmt/user_session.c:340`).
3. Pipe-share creation can insert a share with `name == NULL` on allocation failure (`src/mgmt/share_config.c:179`, `src/mgmt/share_config.c:232`, `src/mgmt/share_config.c:244`, `src/mgmt/share_config.c:102`).
4. Test harness can mask failing exit codes (`run_tests.sh:406-411`) and does not execute real integration/security/perf tests in native mode (`run_tests.sh:355`).
5. `FSCTL_SET_REPARSE_POINT` currently validates and returns success without applying the change (`src/fs/ksmbd_reparse.c:379-391`).

## Artifact index

- `findings_catalog.tsv`: normalized issue catalog (ID, severity, location, impact, fix guidance)
- `FINDINGS_DETAILED.md`: narrative findings report
- `line_coverage.tsv`: file-by-file, line-range coverage and finding linkage
- `module_stats.tsv`: module file/line totals
- `module_findings.tsv`: module finding counts
- `modules/`: per-module review files (one file per module bucket)
- `raw/`: raw tool outputs (`cppcheck`, `shellcheck`, pattern scans, test run output)

## Per-module reports

All module reports are in `modules/`. Examples:

- `modules/src_core.md`
- `modules/src_fs.md`
- `modules/src_mgmt.md`
- `modules/src_protocol.md`
- `modules/src_transport.md`
- `modules/ksmbd-tools_mountd.md`
- `modules/run_tests_sh.md`
- `modules/build_ksmbd_sh.md`
