# Protocol Validation Summary

Date: 2026-03-07

## Scope

This pass validated the current hardening state after the stop/reset deadlock
fix using:

- `tests/ksmbd-torture/ksmbd-torture.sh --quick`
- host-side SMB2 sweep harness `vm/sweep-smb2.sh`
- host-side `smbtorture` extended TCP matrix against a prepared VM

All artifacts for this pass are under `GPT_TMP/protocol_validation_2026-03-07/`.

## 1. ksmbd-torture quick: complete result set

Artifacts:

- `logs/ksmbd_torture_quick_vm13.log`
- `logs/ksmbd_torture_quick_vm13.stdout`
- `logs/ksmbd_torture_quick_vm13.json`
- `logs/vm13_prepare_before_protocol.log`

Command shape:

- target VM: `VM13`
- host target: `127.0.0.1:23022:23445`
- auth: `testuser%testpass`

Result:

- return code: `1`
- total: `258 pass / 25 fail / 7 skip / 0 crash`
- duration: `766.953s`

Category totals:

- `T01` negotiate: `15 pass / 4 fail`
- `T02` session setup: `15 pass / 3 fail`
- `T03` tree connect: `13 pass / 2 fail / 2 skip`
- `T04` create/open: `42 pass / 7 fail / 2 skip`
- `T05` read: `13 pass / 1 fail / 1 skip`
- `T06` write: `17 pass / 0 fail / 1 skip`
- `T07` close: `6 pass / 0 fail`
- `T08` flush: `10 pass / 0 fail`
- `T09` query directory: `17 pass / 2 fail`
- `T10` query info: `14 pass / 4 fail`
- `T11` fs info: `8 pass / 0 fail`
- `T12` set info: `13 pass / 1 fail`
- `T13` locking: `22 pass / 0 fail`
- `T17` compound: `14 pass / 0 fail`
- `T19` ioctl validate negotiate: `6 pass / 0 fail`
- `T20` interface info: `3 pass / 0 fail / 1 skip`
- `T21` copychunk: `2 pass / 1 fail`
- `T22` sparse/trim: `8 pass / 0 fail`
- `T23` compression/integrity: `5 pass / 0 fail`
- `T24` pipe fsctl: `6 pass / 0 fail`
- `T25` misc fsctl: `9 pass / 0 fail`, but health event below

Important failures still present:

- negotiate: `T01.01`, `T01.02`, `T01.06`, `T01.07`
- session/auth: `T02.02`, `T02.03`, `T02.29`
- tree connect: `T03.03`, `T03.17`
- create/open semantics: `T04.04`, `T04.17`, `T04.19`, `T04.25`, `T04.31`, `T04.32`, `T04.35`
- read/query-dir/query-info/set-info/copychunk: `T05.06`, `T09.16`, `T09.22`, `T10.01`, `T10.03`, `T10.09`, `T10.11`, `T12.16`, `T21.04`

Critical runtime health event:

- during `T25`, VM13 reported `BUG: KFENCE: memory corruption in ksmbd_free_work_struct+0x40/0x140 [ksmbd]`
- this is captured in `logs/ksmbd_torture_quick_vm13.log`

Conclusion from quick suite:

- the stop/reset deadlock fix held; the suite completed instead of wedging
- protocol correctness remains materially incomplete
- there is still a memory-corruption-class bug in work teardown/freeing

## 2. SMB2 sweep harness: executed, but result parser is invalid

Artifacts:

- `logs/vm12_smb2_sweep.log`
- copied raw output dir: `sweep-20260307-110937/`

Command shape:

- target VM: `VM12`
- SSH/SMB ports: `22022 / 22445`

Observed result:

- harness completed
- per-suite counters were all `P=0 F=0 S=0 E=0`
- final totals were `PASS=0 FAIL=0 SKIP=0 ERROR=0`

Conclusion:

- `vm/sweep-smb2.sh` is not currently producing usable counts with this
  `smbtorture` output format
- treat this run as harness evidence only, not protocol conformance evidence

## 3. Guest-side extended TCP smbtorture wrapper: invalid environment

Artifacts:

- `logs/vm12_smbtorture_extended_tcp.log`
- `logs/vm12_prepare_before_extended.log`

Observed result:

- all `38` suites reported `INFRA_FAIL(precheck)`

Root cause:

- the wrapper runs `smbclient` inside the guest
- `VM12` does not have `smbclient` installed (`bash: smbclient: command not found`)

Conclusion:

- this wrapper is unusable on the current guest image without additional
  packages

## 4. Host-side extended smbtorture TCP matrix: valid partial run, then kernel Oops

Artifacts:

- `logs/host_vm12_smbtorture_extended_tcp.log`
- `logs/host_vm12_smbtorture_extended_partial_summary.txt`
- `logs/vm12_dmesg_oops_tail.log`

Command shape:

- host tools: `smbclient`, `smbtorture`
- target VM: `VM12`
- target UNC: `//127.0.0.1/test`
- port: `22445`
- auth: `testuser%testpass`

Usable partial results before stopping the run:

- counted result lines so far: `10 pass / 13 fail / 1 skip / 0 infra`
- last emitted result before termination: `RESULT smb2.notify: SKIP(timeout 180s)`

Observed suite-level outcomes before the crash point:

- pass: `smb2.scan`, `smb2.connect`, `smb2.tcon`, `smb2.getinfo`, `smb2.read`, `smb2.rename`, `smb2.winattr`, `smb2.lock`, `smb2.sharemode`, `smb2.deny`
- fail: `smb2.setinfo`, `smb2.rw`, `smb2.create`, `smb2.dir`, `smb2.mkdir`, `smb2.dosmode`, `smb2.timestamps`, `smb2.ea`, `smb2.streams`, `smb2.delete-on-close-perms`, `smb2.openattr`, `smb2.maximum_allowed`, `smb2.ioctl`
- skip: `smb2.notify` timed out at `180s`

Critical runtime failure on VM12:

- kernel Oops triggered in workqueue context during `handle_ksmbd_work`
- fault path:
  - `ksmbd_notify_cleanup_file()`
  - `fsnotify_destroy_mark()`
  - `fsnotify_detach_mark()`
  - fault in `mutex_is_locked()`
- call chain recorded in `logs/vm12_dmesg_oops_tail.log`
- crash signature:
  - `Oops: 0000 [#1] SMP PTI`
  - `Workqueue: ksmbd-io handle_ksmbd_work [ksmbd]`
  - `RIP: mutex_is_locked+0xe/0x30`

Conclusion:

- the current tree still has a real close/notify cleanup crash path
- this is separate from the earlier stop/reset deadlock and is not fixed by the
  teardown write changes

## Overall status

What is improved:

- the targeted `ksmbdctl stop` / `rmmod` / `insmod` hang is fixed
- `ksmbd-torture --quick` now runs to completion instead of wedging the server

What is still broken:

- `ksmbd-torture --quick` still has `25` protocol failures and `7` skips
- VM13 exposed a `KFENCE` memory corruption in `ksmbd_free_work_struct()`
- VM12 host-side `smbtorture` exposed a kernel Oops in
  `ksmbd_notify_cleanup_file()` / fsnotify mark teardown
- both the host sweep harness and the guest-side extended wrapper need test
  harness fixes before they can be trusted as standalone result sources

## Recommended next engineering order

1. fix the `ksmbd_notify_cleanup_file()` / `fsnotify_destroy_mark()` crash
2. fix the `ksmbd_free_work_struct()` KFENCE corruption
3. re-run `ksmbd-torture --quick`
4. repair `vm/sweep-smb2.sh` result parsing and/or replace it with the
   host-side `smbtorture` matrix harness
