# VM10 Stop/Lease Validation Summary

Date: 2026-03-07

## Scope

Validated the latest `ksmbd.ko` on `VM10` after fixing:

- `stop_sessions()` hot-rescan of already-tearing-down durable connections
- oplock/lease break notification use of detached `opinfo->conn`
- durable scavenger exit clearing of `server_conf.dh_task`
- per-`opinfo` connection reference release in durable disconnect cleanup

## Artifacts

- Deploy logs:
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/deploy_vm10_r4.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/deploy_vm10_r3.log`
- Targeted successful repro:
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/repro_console_r4.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/durable_v2_open_r4.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/post_restart_status_and_dmesg_r4.log`
- 3-iteration confirmation loop:
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r1/summary.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r1/durable_v2_open_1.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r1/durable_v2_open_2.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r1/durable_v2_open_3.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r1/post_restart_1.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r1/post_restart_2.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r1/post_restart_3.log`
- Post-fix 3-iteration confirmation loop:
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r3/summary.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r3/torture_1.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r3/torture_2.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r3/torture_3.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r3/stop_restart_1.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r3/stop_restart_2.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r3/stop_restart_3.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r3/post_restart_1.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r3/post_restart_2.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/loop_r3/post_restart_3.log`

## Build Validation

- `make -C /usr/lib/modules/6.18.13-arch1-1/build M=/home/ezechiel203/ksmbd C=2 src/core/connection.o`
- `make -C /usr/lib/modules/6.18.13-arch1-1/build M=/home/ezechiel203/ksmbd C=2 src/fs/oplock.o`
- `make -C /usr/lib/modules/6.18.13-arch1-1/build M=/home/ezechiel203/ksmbd C=2 src/fs/vfs_cache.o`
- `make -C /usr/lib/modules/6.18.13-arch1-1/build M=/home/ezechiel203/ksmbd C=2 test/ksmbd_test_connection.o`
- `make -j1 KVER=6.18.13-arch1-1 EXTERNAL_SMBDIRECT=n all`

Touched objects compiled successfully. Full module rebuild succeeded. Pre-existing unrelated warnings remain in other files.

## Runtime Results

- Targeted repro on VM10:
  - `smbtorture smb2.durable-v2-open`: completed
  - `ksmbdctl stop`: completed successfully
  - `ksmbdctl start`: completed successfully

- 3-iteration confirmation loop:
  - iteration 1 stop: `ok`
  - iteration 2 stop: `ok`
  - iteration 3 stop: `ok`

- Post-fix 3-iteration confirmation loop:
  - iteration 1 stop/reload/start: `ok`
  - iteration 2 stop/reload/start: `ok`
  - iteration 3 stop/reload/start: `ok`
  - no `stop_sessions: giving up`
  - no `BUG:`, `Oops`, `WARNING: CPU`, `KASAN`, `KFENCE`, or `hung task`
  - port `445` was listening after every restart

## Important Residual

The teardown leak responsible for the forced orphan cleanup no longer reproduces in the current VM10 loop. The remaining failures in this reproducer are protocol-level:

- `smbtorture smb2.durable-v2-open` still reports multiple expected-vs-actual status mismatches such as `NT_STATUS_OBJECT_NAME_NOT_FOUND` instead of the expected durable-reconnect result
- post-restart dmesg still shows `durable reconnect v2: client GUID mismatch` during the torture run, which matches those semantics failures but does not indicate a shutdown hang or crash

## Conclusion

The panic-class oplock NULL-deref, the durable-scavenger stale-task crash, and the forced-cleanup teardown leak are fixed for this reproducer. On VM10, the original `ksmbdctl stop` wedge no longer reproduces, and repeated `stop -> rmmod -> insmod -> start` cycles now complete cleanly.

What remains here is protocol correctness in `smb2.durable-v2-open`, not teardown safety. The next pass should move back to durable reconnect semantics instead of shutdown recovery.
