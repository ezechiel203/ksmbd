# Fixes Applied (2026-02-25)

All issues from `findings_catalog.tsv` (KSMBD-F001 .. KSMBD-F012) were addressed in code.

## Implemented fixes
- KSMBD-F001: `memcmp` for binary ClientGUID compare in `src/protocol/smb2/smb2_session.c`.
- KSMBD-F002: `memcmp` for binary GUID compare in `src/fs/ksmbd_fsctl.c`.
- KSMBD-F003: Early `share->name` allocation failure handling in `src/mgmt/share_config.c`.
- KSMBD-F004: Removed dynamic `krealloc` destroy-array path; switched to hlist-based deferred destroy in `src/mgmt/user_session.c`.
- KSMBD-F005: Correct failure exit-code handling in `run_tests.sh`.
- KSMBD-F006: Replaced help/list placeholders with real native suite execution + explicit skip logic in `run_tests.sh`.
- KSMBD-F007: Reworked `build_ksmbd.sh` to valid bash script with safe command/file handling.
- KSMBD-F008: Replaced string-built make flags with argument arrays in `build_arm64.sh`.
- KSMBD-F009: `FSCTL_SET_REPARSE_POINT` now returns `STATUS_NOT_SUPPORTED` until implementation exists.
- KSMBD-F010: `FSCTL_CREATE_OR_GET_OBJECT_ID` now returns `STATUS_NOT_SUPPORTED` instead of all-zero placeholder IDs.
- KSMBD-F011: Added overflow-safe size checks in `ksmbd-tools/mountd/ipc.c` allocation path.
- KSMBD-F012: Added `check-pkgver` validation gate for DKMS targets in `Makefile`.

## Validation performed
- Kernel module build: `make -j4 all` completed successfully.
- Script syntax: `bash -n run_tests.sh build_arm64.sh build_ksmbd.sh` passed.
- Test harness run: `./run_tests.sh` passed (unit executed; integration/security/performance explicitly skipped due environment prerequisites).
- shellcheck: no remaining findings tied to fixed issues; only low-priority pre-existing warnings remain.

