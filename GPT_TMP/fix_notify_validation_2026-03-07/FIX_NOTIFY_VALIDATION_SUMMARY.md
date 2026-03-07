# Notify Fix Validation Summary

Date: 2026-03-07

## Scope

This pass fixed and revalidated the remaining notify/work lifetime defects that
were implicated in:

- the `ksmbd_notify_cleanup_file()` / `fsnotify_destroy_mark()` Oops
- the `ksmbd_free_work_struct()` KFENCE corruption observed after `T25`

Artifacts for this pass are under `GPT_TMP/fix_notify_validation_2026-03-07/`.

## Code changes

Files changed:

- `src/fs/ksmbd_notify.c`
- `src/include/fs/ksmbd_notify.h`

Implemented changes:

- added explicit terminal ownership for notify work completion / cancel /
  cleanup / delete-pending paths so the same `ksmbd_work` cannot be freed
  twice
- fixed secondary-watch teardown so secondary watches are no longer destroyed
  through `fsnotify_destroy_mark()`
- added secondary-watch references so event dispatch and cancel paths cannot
  race a secondary free
- removed the per-handle limit double-free in `ksmbd_notify_add_watch()`
- kept primary mark owners alive as orphaned primaries when secondaries still
  exist, instead of tearing down the shared mark out from under live
  secondary handles
- switched primary marks to a stable all-events fsnotify mask so secondary
  filters are not silently missed and no unexported fsnotify internals are
  required

## Build validation

- external module rebuild with `EXTERNAL_SMBDIRECT=n` and `CONFIG_SMB_SERVER_QUIC=n`:
  pass
  - log: `logs/build_final.log`
- KUnit external-module compile gate:
  pass
  - command: `./test/run_all_tests.sh --kunit`
  - log is in the console transcript; summary result was `PASS`
- `C=1` build with `CONFIG_SMB_SERVER_SMBDIRECT=n` and `CONFIG_KSMBD_KUNIT_TEST=m`:
  pass
  - log: `logs/c1_build.log`

Notes:

- a plain unconditional module link still fails in this tree on the known
  unrelated RDMA symbol issue (`ksmbd_rdma_capable_netdev`) unless
  `SMB_DIRECT` is disabled for the build, which is the same compile path used
  by the existing validation scripts
- `git diff --check` is not a useful signal in this repository state because
  unrelated tracked VM log files already contain trailing-whitespace diffs

## Runtime validation

### 1. Host `smbtorture smb2.notify` against VM13

Command shape:

- target: `//127.0.0.1/test`
- port: `23445`
- auth: `testuser%testpass`
- suite: `smb2.notify`
- timeout: `240s`

Artifacts:

- `logs/smbtorture_smb2_notify_vm13.log`
- `logs/vm13_dmesg_after_smb2_notify.log`

Result:

- process timed out (`RC=124`)
- the old crash did **not** reproduce
- guest `dmesg` after the run showed only repeated TCP read retry timeouts:
  - `ksmbd: TCP read retry timeout after 60s`
- there was no `Oops`, no `KFENCE`, and no `fsnotify_destroy_mark()` crash

Conclusion:

- the panic-class notify teardown bug is fixed in the targeted runtime repro
- notify protocol behavior is still wrong; the suite now degrades to timeout /
  disconnect instead of crashing

### 2. `ksmbd-torture` `T25` against VM13

Command shape:

- `tests/ksmbd-torture/ksmbd-torture.sh --category T25 --vm 127.0.0.1:23022:23445 --user testuser%testpass`

Artifacts:

- `logs/ksmbd_torture_T25_vm13.log`
- `logs/ksmbd_torture_T25_vm13.stdout`
- `logs/ksmbd_torture_T25_vm13.json`
- `logs/vm13_dmesg_after_T25.log`

Result:

- `RC=0`
- `T25`: `14 pass / 0 fail / 0 skip / health=OK`
- guest `dmesg` after the run showed only the test marker and no crash output

Conclusion:

- the previously observed KFENCE corruption after `T25` no longer reproduced in
  this focused rerun

## Remaining work

The crash-class issues from the previous validation pass are addressed by this
change set, but notify semantics are still not correct:

- `smbtorture smb2.notify` still times out and reports
  `NT_STATUS_CONNECTION_DISCONNECTED` where it expects `NT_STATUS_CANCELLED`
- `valid-req` in that suite still reports `NT_STATUS_OK` instead of
  `NT_STATUS_NOTIFY_ENUM_DIR`

Next engineering target:

1. fix the remaining notify cancel / final-response protocol behavior without
   regressing the lifetime fixes
2. rerun `smbtorture smb2.notify`
3. rerun the broader protocol buckets once notify is stable again
