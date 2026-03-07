# ksmbd Validation Summary (2026-03-07)

## Build / Static Validation

- `ksmbd-tools` Meson test suite: `25/25` passed.
- `test/check_test_registration.sh`: passed after fixing [`test/Makefile`](/home/ezechiel203/ksmbd/test/Makefile).
- External-module compile-check passed with:
  - `CONFIG_SMB_SERVER=m`
  - `CONFIG_SMB_SERVER_SMBDIRECT=n`
  - `CONFIG_SMB_INSECURE_SERVER=y`
  - `CONFIG_KSMBD_FRUIT=y`
  - `CONFIG_SMB_SERVER_QUIC=n`
  - `CONFIG_KSMBD_KUNIT_TEST=m`
- External-module fuzz compile-check passed with the same base config plus `CONFIG_KSMBD_FUZZ_TEST=m`.

## ksmbd-tools

- Full log: [`ksmbd-tools-meson-testlog.txt`](/home/ezechiel203/ksmbd/GPT_TMP/validation_2026-03-07/ksmbd-tools-meson-testlog.txt)
- Result: all tests passed, including:
  - integration CLI
  - IPC compatibility against kernel headers
  - RPC / session / worker IPC / config parser coverage

## ksmbd Torture Quick Run (VM3)

- Log: [`ksmbd_torture_quick_2026-03-07.log`](/home/ezechiel203/ksmbd/GPT_TMP/validation_2026-03-07/ksmbd_torture_quick_2026-03-07.log)
- Result: `214 pass / 69 fail / 7 skip`
- Duration: `1095.489s`
- Notable health signal:
  - post-`T10` / `T11` harness health check reported `ksmbd` not loaded and SMB port not listening before later recovery

Main failure buckets from the completed quick run:

- negotiate/session/auth:
  - `T01`, `T02`
- tree connect / create:
  - `T03`, `T04`
- read / flush / dir query / query-info:
  - `T05`, `T08`, `T09`, `T10`, `T11`
- a small number of set-info / lock / fsctl misc failures:
  - `T12`, `T13`, `T19`, `T25`

Healthy categories in the same run:

- compound: `T17` fully passed
- copychunk / sparse / compression / pipe FSCTL classes: `T21`-`T24` fully passed

## smbtorture Sweep

- Partial sweep logs copied from `/tmp/sweep-20260307-032720/`:
  - [`compound.log`](/home/ezechiel203/ksmbd/GPT_TMP/validation_2026-03-07/compound.log)
  - [`compound_async.log`](/home/ezechiel203/ksmbd/GPT_TMP/validation_2026-03-07/compound_async.log)
  - [`compound_find.log`](/home/ezechiel203/ksmbd/GPT_TMP/validation_2026-03-07/compound_find.log)
  - [`connect.log`](/home/ezechiel203/ksmbd/GPT_TMP/validation_2026-03-07/connect.log)
  - [`create.log`](/home/ezechiel203/ksmbd/GPT_TMP/validation_2026-03-07/create.log)

Observed sweep behavior before the runner wedged:

- `smb2.compound`: `P=0 F=20`
- `smb2.compound_async`: `P=0 F=10`
- `smb2.compound_find`: `P=3 F=0`
- `smb2.connect`: `P=1 F=0`
- `smb2.create`: produced successful subtests, then the sweep stalled in the restart path

The sweep did **not** terminate cleanly. The blocker was the restart helper:

- remote `ksmbdctl stop` wedged on the VM
- the sweep then stalled in its restart/reload sequence
- this is itself a reproducible hang-class finding in the test/deployment path

## Build-System Fixes Made During Validation

- [`test/Makefile`](/home/ezechiel203/ksmbd/test/Makefile)
  - restored missing test object registrations
  - restored include-paths needed by newer tests
- [`test/run_all_tests.sh`](/home/ezechiel203/ksmbd/test/run_all_tests.sh)
  - enabled `pipefail` so `make | tail` no longer masks failures
  - restored kernel build-dir autodetection
  - aligned external-module compile-check configs with the working feature set

## Remaining Work Exposed By Testing

- substantial protocol-conformance failures remain in the quick ksmbd-torture run
- the restart path used by the sweep can hang in `ksmbdctl stop`
- because of that restart-path hang, the full broad sweep could not be completed end-to-end in this session
