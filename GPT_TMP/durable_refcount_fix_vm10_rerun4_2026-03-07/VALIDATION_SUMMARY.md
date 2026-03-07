## VM10 Durable Validation Summary

Date: 2026-03-07
Target VM: `VM10`
SSH port: `20022`
SMB port: `20445`

### Changes validated

- File-table close/unpublish refcount fix in `/home/ezechiel203/ksmbd/src/fs/vfs_cache.c`
- Non-lease `NONE` opener lease downgrade fix in `/home/ezechiel203/ksmbd/src/fs/oplock.c`
- KUnit coverage additions in `/home/ezechiel203/ksmbd/test/ksmbd_test_vfs_cache.c`
- KUnit coverage additions in `/home/ezechiel203/ksmbd/test/ksmbd_test_oplock.c`

### Build validation

- Touched-object compile passed for `src/fs/vfs_cache.o`, `test/ksmbd_test_vfs_cache.o`
- Touched-object compile passed for `src/fs/oplock.o`, `test/ksmbd_test_oplock.o`
- `sparse` passed on the touched `vfs_cache` objects
- Full external-module rebuild completed successfully and produced `ksmbd.ko`

### VM10 runtime validation

- Upgraded guest `ksmbdctl` remained functional (`ksmbd-tools version : 3.5.6`)
- Fresh deploy of rebuilt `ksmbd.ko` to VM10 succeeded
- `smbtorture //127.0.0.1/test -U testuser%testpass -p 20445 smb2.durable-v2-open`
  completed with exit code `0`
- The previously failing `nonstat-and-lease` case now passed
- The earlier refcount warnings (`refcount_warn_saturate` in `ksmbd_close_fd()` /
  `__close_file_table_ids()`) did not reappear in the captured guest `dmesg`
- No panic, Oops, KASAN, KFENCE, or hung-task output was captured in this run

### Residual observations

- Guest `dmesg` still reports repeated `ksmbd: inherit ACL overflow`
- Guest `dmesg` still shows two `durable reconnect v2: client GUID mismatch`
  lines, consistent with negative-path subtests
- `smbtorture` still prints one `Skip acking to 0x0 () in lease handler`
  message during `purge-disconnected-rh-with-write`, but the suite passes

### Artifacts

- Build log: `/home/ezechiel203/ksmbd/GPT_TMP/durable_refcount_fix_vm10_rerun4_2026-03-07/logs/module_build.log`
- Deploy log: `/home/ezechiel203/ksmbd/GPT_TMP/durable_refcount_fix_vm10_rerun4_2026-03-07/logs/module_deploy.log`
- Pre-run status: `/home/ezechiel203/ksmbd/GPT_TMP/durable_refcount_fix_vm10_rerun4_2026-03-07/logs/pre_torture_status.log`
- Torture log: `/home/ezechiel203/ksmbd/GPT_TMP/durable_refcount_fix_vm10_rerun4_2026-03-07/logs/torture.log`
- Torture rc: `/home/ezechiel203/ksmbd/GPT_TMP/durable_refcount_fix_vm10_rerun4_2026-03-07/logs/torture.rc`
- Guest `dmesg` tail: `/home/ezechiel203/ksmbd/GPT_TMP/durable_refcount_fix_vm10_rerun4_2026-03-07/logs/dmesg_tail.log`
