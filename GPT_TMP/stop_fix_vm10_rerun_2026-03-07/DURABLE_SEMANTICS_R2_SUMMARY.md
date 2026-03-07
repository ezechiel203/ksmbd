# VM10 Durable Reconnect Probe R2

Date: 2026-03-07

## Scope

Validated the follow-up durable reconnect fix on `VM10` after narrowing durable disconnect/reconnect `opinfo` ownership:

- disconnect now unbinds only `fp->f_opinfo`
- reconnect now rebinds only `fp->f_opinfo`
- added KUnit regression coverage for target-only unbind/rebind behavior

## Code Changes

- `src/fs/vfs_cache.c`
- `src/include/fs/vfs_cache.h`
- `test/ksmbd_test_vfs_cache.c`

## Validation Artifacts

- deploy:
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/durable_semantics_probe_r2/deploy.log`
- runtime probe:
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/durable_semantics_probe_r2/torture.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/durable_semantics_probe_r2/dmesg_tail.log`
- previous baseline for comparison:
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/durable_semantics_probe/torture.log`
  - `GPT_TMP/stop_fix_vm10_rerun_2026-03-07/logs/durable_semantics_probe/dmesg_tail.log`

## Compile Validation

- `make -C /usr/lib/modules/6.18.13-arch1-1/build M=/home/ezechiel203/ksmbd C=2 src/fs/vfs_cache.o test/ksmbd_test_vfs_cache.o`
- `make -j1 KVER=6.18.13-arch1-1 EXTERNAL_SMBDIRECT=n all`

Both completed successfully. Pre-existing warnings remain outside this fix set.

## Runtime Result

Probe command:

- `smbtorture //127.0.0.1/test -U testuser%testpass -p 20445 smb2.durable-v2-open`

Current result:

- no hang
- no `BUG:`, `Oops`, `KASAN`, `KFENCE`, or hung-task output
- still logs two expected negative-path messages:
  - `ksmbd: durable reconnect v2: client GUID mismatch`

## Failure Comparison

Previous baseline failure count: `13`

- `create-blob`
- `reopen2`
- `reopen2b`
- `reopen2-lease`
- `reopen2-lease-v2`
- `durable-v2-setinfo`
- `lock-oplock`
- `lock-lease`
- `stat-and-lease`
- `nonstat-and-lease`
- `two-same-lease`
- `keep-disconnected-rh-with-rh-open`
- `keep-disconnected-rh-with-rwh-open`

Current failure count: `11`

- `create-blob`
- `reopen2`
- `reopen2-lease`
- `reopen2-lease-v2`
- `durable-v2-setinfo`
- `lock-oplock`
- `nonstat-and-lease`
- `two-same-lease`
- `two-different-lease`
- `keep-disconnected-rh-with-rh-open`
- `keep-disconnected-rh-with-rwh-open`

Resolved relative to the previous probe:

- `reopen2b`
- `lock-lease`
- `stat-and-lease`

Newly failing relative to the previous probe:

- `two-different-lease`

## Assessment

The inode-wide `opinfo` rebinding bug was real and its fix improved the durable reconnect surface, but it did not fully resolve `smb2.durable-v2-open`.

The remaining failures still cluster around durable reconnect plus lease state retention:

- reconnects still returning `STATUS_OBJECT_NAME_NOT_FOUND`
- lease state mismatches on disconnected durable-handle scenarios

The next target should be lease-break handling for disconnected durable handles, especially paths that can drop handle caching or write caching before reconnect.
