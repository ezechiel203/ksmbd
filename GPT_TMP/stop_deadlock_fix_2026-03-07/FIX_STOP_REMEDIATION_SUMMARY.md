# Stop/Reset Deadlock Remediation Summary

Date: 2026-03-07

## Scope

This pass addressed the remaining stop/reset hang identified in the previous
validation summary. The live VM trace pointed to teardown-time notify cleanup
trying to synchronously write `STATUS_NOTIFY_CLEANUP` on a connection whose
send mutex was already occupied during session/file-table teardown.

## Code Changes

- `src/core/connection.c`
  - factored the response write path into an internal helper
  - added `ksmbd_conn_try_write()` for opportunistic, non-blocking writes
  - suppressed expected `-EAGAIN` logging for this intentional skip path
- `src/include/core/connection.h`
  - exported `ksmbd_conn_try_write()`
- `src/fs/ksmbd_notify.c`
  - changed teardown-only notify completions to use `ksmbd_conn_try_write()`
  - applies to both `STATUS_NOTIFY_CLEANUP` and `STATUS_DELETE_PENDING`
  - if the connection is releasing or `srv_mutex` is busy, the response is
    skipped and cleanup proceeds locally instead of blocking teardown

This change preserves the normal blocking write path for ordinary SMB
responses. Only teardown-specific notify completions were made opportunistic.

## Validation

Artifacts are in `GPT_TMP/stop_deadlock_fix_2026-03-07/logs/`.

Local validation:

- `clean.log`: full external-module clean passed
- `modules.log`: full `ksmbd.ko` rebuild passed (`RC:0`)
- `check_test_registration.log`: passed
- touched-object compile:
  - `src/core/connection.o`
  - `src/fs/ksmbd_notify.o`
  - `src/fs/vfs_cache.o`
  - `src/transport/transport_tcp.o`
- touched-file `sparse` check passed
- `kunit_objects.log`: compile-check passed for
  - `ksmbd_test_connection.o`
  - `ksmbd_test_notify.o`
  - `ksmbd_test_tcp_shutdown.o`
  - note: this still reports one pre-existing warning in
    `ksmbd_test_connection.c:321` about ignoring
    `refcount_dec_and_test()`'s return value
- `smatch` on touched files still hits the known installed-header
  `container_of()` static-assert noise and one pre-existing indentation note;
  no new code-local defect was identified from this pass

Runtime validation on `VM13`:

- `vm13_prepare.log`: guest prepare succeeded (`PREPARE_RC:0`)
- `vm13_stop_loop.log`: three consecutive iterations of
  `ksmbdctl stop -> rmmod ksmbd -> insmod ksmbd.ko -> ksmbdctl start`
  completed successfully under an outer timeout
- `vm13_dmesg_tail.log`: shows repeated clean unload/reload cycles and no
  blocked-task report matching the prior deadlock

## Result

The targeted stop/reset hang repro is fixed in this pass on a clean VM.

What is not covered by this validation:

- the broader `ksmbd-torture` protocol failure buckets
- a full `smbtorture` sweep after this change
- the earlier VM3 KFENCE-corrupted environment, which was intentionally not
  reused for the final pass/fail signal
