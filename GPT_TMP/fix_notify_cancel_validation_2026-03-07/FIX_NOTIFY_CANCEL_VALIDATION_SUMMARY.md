# Notify Cancel Fix Validation

Date: 2026-03-07

## Scope

This batch fixed the `SMB2 CANCEL` regression introduced by notify lifetime
hardening. Generic `smb2_cancel()` pre-marks async work as
`KSMBD_WORK_CANCELLED`; the notify cancel path was treating that as a lost race
and skipping the final `STATUS_CANCELLED` response. The fix makes notify cancel
claim work that is already `CANCELLED` by the generic layer, while still
rejecting work already closed by another terminal path.

Files changed:

- `src/fs/ksmbd_notify.c`
- `test/ksmbd_test_notify.c`

## Code changes

- Added `VISIBLE_IF_KUNIT` exports in `ksmbd_notify.c`:
  - `ksmbd_notify_take_work()`
  - `ksmbd_notify_claim_cancel_work()`
- Switched both notify cancel branches to use
  `ksmbd_notify_claim_cancel_work()` instead of requiring an `ACTIVE ->
  CANCELLED` transition.
- Added KUnit coverage for:
  - active-to-closed ownership
  - cancel claiming an already pre-cancelled work item
  - rejection of already-closed work
- Fixed a `-Wmisleading-indentation` issue in the existing secondary-watch
  retry block.

## Validation

Logs:

- `logs/build.log`
- `logs/kunit.log`
- `logs/deploy_vm13.log`
- `logs/vm13_prep.log`
- `logs/smbtorture_smb2_notify_vm13.log`
- `logs/smbtorture_smb2_notify_vm13.rc`
- `logs/vm13_dmesg_after_smb2_notify.log`

### Build

Command:

```sh
make EXTERNAL_SMBDIRECT=n CONFIG_SMB_SERVER_QUIC=n -j$(nproc) all
```

Result: passed

### KUnit compile gate

Command:

```sh
./test/run_all_tests.sh --kunit
```

Result: passed

### Runtime repro

Commands:

```sh
./vm/deploy-all.sh VM13
./vm/vm-exec-instance.sh VM13 'dmesg -C; rm -rf /srv/smb/test/*; echo READY'
timeout 240 smbtorture //127.0.0.1/test -U testuser%testpass -p 23445 smb2.notify
./vm/vm-exec-instance.sh VM13 'dmesg'
```

Result:

- `smb2.notify` completed without timing out
- return code: `1` (suite failures remain, but no timeout / hang)
- guest `dmesg` contained no `BUG`, `Oops`, `panic`, `KFENCE`, or `KASAN`
  signature

## What improved

The cancel regression is fixed. These subtests now pass in the live VM run:

- `tcon`
- `mask`
- `tdis`
- `tdis1`
- `close`
- `logoff`
- `session-reconnect`
- `basedir`
- `double`
- `file`
- `tcp`
- `overflow`
- `rmdir1`
- `rmdir2`
- `rmdir3`
- `rmdir4`
- `handle-permissions`

Most importantly, the prior notify cancel/disconnect failure mode is gone:

- no `STATUS_CONNECTION_DISCONNECTED` on the cancel-focused paths
- no 240-second timeout
- no notify teardown crash

## Remaining failures

Current failing buckets from `smb2.notify`:

- `valid-req`: `NT_STATUS_OK` instead of `NT_STATUS_NOTIFY_ENUM_DIR`
- `dir`: create of `test_notify_DIR\\subdir-name` fails during the scenario
- `mask-change`: `NT_STATUS_SHARING_VIOLATION` instead of `NT_STATUS_OK`
- `invalid-reauth`: `NT_STATUS_OK` instead of `NT_STATUS_LOGON_FAILURE`
- `tree`: `NT_STATUS_OBJECT_NAME_COLLISION` instead of `NT_STATUS_OK`
- `rec`: `NT_STATUS_SHARING_VIOLATION` instead of `NT_STATUS_OK`

## Notes

- `valid-req`, `mask-change`, `invalid-reauth`, `tree`, and `rec` are all
  present in earlier saved notify baselines under
  `/home/ezechiel203/ksmbd-track4-build/debug/tests/` and were not introduced
  by this fix.
- The session/connectivity side improved relative to those older baselines:
  `session-reconnect` and `basedir` now pass in the current run.

## Next targets

Recommended order for the next pass:

1. `dir` / `tree` / `rec` cluster: likely stale directory/watch state or share
   semantics causing `OBJECT_NAME_COLLISION` / `SHARING_VIOLATION`.
2. `invalid-reauth`: likely session-setup error propagation during notify.
3. `valid-req`: persistent `STATUS_NOTIFY_ENUM_DIR` semantics mismatch.
