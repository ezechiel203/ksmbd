# ksmbd Stop-Path Fix Validation (2026-03-07)

## Scope

Focused fixes for the first items from the saved validation summary:

- `src/transport/transport_tcp.c`
  - bounded listener `kernel_accept()` with a receive timeout
  - taught the listener loop to treat timeout/interrupted accepts as retryable
  - stopped tearing listeners down while holding `iface_list_lock`
  - removed the synchronous listener `kernel_sock_shutdown()` dependency from
    `NETDEV_DOWN` and `ksmbd_tcp_destroy()`
- `src/fs/vfs_cache.c`
  - added a shared cleanup helper for force-closing durable/global handles
  - made durable/global close paths run `set_close_state_blocked_works()` and
    `ksmbd_notify_cleanup_file()` before freeing the file object
  - converted global durable-table teardown to deletion-safe `idr_get_next()`
    iteration instead of deleting while walking `idr_for_each_entry()`

## Validation Performed

- test registration:
  - `./test/check_test_registration.sh`
  - result: passed
- focused object build:
  - `make -C /usr/lib/modules/6.18.13-arch1-1/build M=$PWD ARCH=x86_64 src/fs/vfs_cache.o src/transport/transport_tcp.o`
  - result: passed
- `sparse` on touched files:
  - `make -C /usr/lib/modules/6.18.13-arch1-1/build M=$PWD CHECK=sparse C=2 ARCH=x86_64 src/fs/vfs_cache.o src/transport/transport_tcp.o`
  - result: passed
- `smatch` on touched files:
  - `make -C /usr/lib/modules/6.18.13-arch1-1/build M=$PWD CHECK="smatch -p=kernel" C=2 ARCH=x86_64 src/fs/vfs_cache.o src/transport/transport_tcp.o`
  - result: analyzer completed, but the log contains pre-existing header-level
    `container_of()` static-assert noise from the installed kernel headers
- full module build attempts:
  - `CONFIG_SMB_INSECURE_SERVER=y` build hit a pre-existing unrelated `modpost`
    failure: `ksmbd_lookup_fd_filename` undefined
  - runtime VM deployment was therefore not completed in this batch because a
    freshly linked `ksmbd.ko` was not available from this tree state

## Logs

- `build_objects.log`
- `build_modules.log`
- `build_kunit.log`
- `build_modules_no_smb1.log`
- `check_test_registration.log`
- `sparse.log`
- `smatch.log`

All logs are in this directory.
