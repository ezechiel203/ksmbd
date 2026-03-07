# Sparse + GCC Static Analyzer Report (Re-Validation)

Date: 2026-02-23
Repository: `/home/ezechiel203/ksmbd`

## Toolchain
- `sparse`: 0.6.4
- `gcc`: 15.2.0
- `cppcheck`: 2.17.1

## Commands
- `make -k -j$(nproc) C=2`
- `make -k -j$(nproc) W=1 KCFLAGS='-fanalyzer -Wanalyzer-double-free -Wanalyzer-use-after-free -Wanalyzer-null-dereference -Wanalyzer-out-of-bounds -Wanalyzer-malloc-leak'`
- `cppcheck --enable=warning,performance ...`

## Current Outcome
- Sparse and gcc analyzer build passes complete successfully.
- No compiler `error:` diagnostics are present in sparse/analyzer build logs.
- Analyzer output contains kernel-doc style `Warning:` lines (non-fanalyzer defect traces).

## Cppcheck Outcome
- Cppcheck emits findings (errors/warnings/info), including:
- generated-file parse error on `ksmbd.mod.c`,
- multiple uninitialized-variable traces across kernel code paths.
- Current cppcheck signal is noisy and not yet curated for kernel-specific analysis quality.

## Status of Previously Flagged Sparse/GCC Actionables
- Previously reported target defects remain fixed in current tree:
- wire-endian conversions in `smbacl.c`, `oplock.c`, `smb2_misc_cmds.c`,
- initialization/guard fixes in `ksmbd_work.c`, `smb2_tree.c`, `smb2_query_set.c`, `ksmbd_reparse.c`, `transport_tcp.c`, `ksmbd_vss.c`.

## Evidence
- `CDXREVIEW/raw/ci_sparse_C2.log`
- `CDXREVIEW/raw/ci_gcc_fanalyzer.log`
- `CDXREVIEW/raw/ci_cppcheck.log`
