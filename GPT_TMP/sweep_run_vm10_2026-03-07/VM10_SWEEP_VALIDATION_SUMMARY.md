# VM10 Sweep Validation Summary

Date: 2026-03-07
Target VM: `VM10`
Ports: SSH `20022`, SMB `20445`

## Environment refresh

- upgraded `ksmbd-tools` on VM10 from the current workspace tree
- verified with `ksmbdctl version`:
  - `ksmbd-tools version : 3.5.6`
  - `ksmbd version : 3.5.4`
- redeployed the latest `ksmbd.ko` with `./vm/deploy-all.sh VM10`

Logs:

- `GPT_TMP/vm10_refresh_2026-03-07/ksmbd-tools-build-tail.log`
- `GPT_TMP/vm10_refresh_2026-03-07/deploy-all-vm10.log`
- `GPT_TMP/vm10_refresh_2026-03-07/ksmbdctl-version-status.log`

## Sweep harness correction

The first VM10 sweep run was invalid because `vm/sweep-smb2.sh` executed
`smbtorture` inside the guest, and VM10 does not have `smbtorture`
installed. Every suite log contained:

`bash: line 1: smbtorture: command not found`

That invalid run is preserved in:

- `GPT_TMP/sweep_run_vm10_2026-03-07/sweep_vm10.log`
- `GPT_TMP/sweep_run_vm10_2026-03-07/raw/`

The harness was then fixed to:

- require host-side `smbtorture`
- execute `smbtorture` from the host against `//127.0.0.1/test -p 20445`
- align reset-created credentials to `testuser%testpass`

Validation:

- `bash -n vm/sweep-smb2.sh` passed
- `shellcheck vm/sweep-smb2.sh` passed

## Corrected VM10 sweep run

Corrected run log:

- `GPT_TMP/sweep_run_vm10_2026-03-07/host_fixed/sweep_vm10_host.log`

Observed suite results before the run was interrupted for investigation:

- `smb2.compound`: `P=20 F=0 S=0 E=0`
- `smb2.compound_async`: `P=7 F=3 S=0 E=0`
- `smb2.compound_find`: `P=3 F=0 S=0 E=0`
- `smb2.connect`: `P=1 F=0 S=0 E=0`
- `smb2.create`: `P=15 F=2 S=1 E=0`
- `smb2.credits`: `P=5 F=5 S=0 E=0`
- `smb2.delete-on-close-perms`: `P=6 F=3 S=0 E=0`
- `smb2.dir`: `P=7 F=2 S=0 E=0`
- `smb2.dirlease`: `P=18 F=0 S=0 E=0`
- `smb2.dosmode`: `P=0 F=1 S=0 E=0`
- `smb2.durable-open`: `P=16 F=9 S=1 E=0`
- `smb2.durable-v2-open`: `P=20 F=13 S=0 E=0`

The run did not reach a clean total because the harness stopped making
progress before `smb2.getinfo` completed.

## New failure reproduced

The corrected sweep reproduced a lifecycle hang on VM10:

- guest process stuck: `ksmbdctl stop`
- runtime at probe: about 2 minutes 35 seconds
- `ksmbd.mountd` not running
- module still loaded

Probe log:

- `GPT_TMP/sweep_run_vm10_2026-03-07/host_fixed/vm10_stuck_probe.log`

Guest hung-task evidence:

- `INFO: task ksmbd-durable-s:8856 blocked for more than 122 seconds`
- blocked function: `ksmbd_durable_scavenger+0x37b/0x3f0`

Call trace tail from the probe:

```text
ksmbd_durable_scavenger+0x37b/0x3f0 [ksmbd ...]
kthread+0xfc/0x240
ret_from_fork+0x1c2/0x1f0
```

## Kernel-side observations

No guest `panic`, `Oops`, `KASAN`, or `KFENCE` signature was captured before
the run was interrupted.

Repeated runtime warnings/signals seen in the guest during the corrected run:

- `Outstanding credits underflow: charge 1, outstanding 0`
- `inherit ACL overflow`
- `error while processing smb2 query dir rc = -2`
- `durable reconnect: client GUID mismatch`
- `durable reconnect v2: client GUID mismatch`

Live guest dmesg capture:

- `GPT_TMP/sweep_run_vm10_2026-03-07/host_fixed/vm10_dmesg_tail_live.log`

## Conclusion

The VM10 rerun is now valid and useful. The main remaining blocker exposed by
this pass is not the sweep harness anymore; it is a real stop/reset hang tied
to the durable scavenger thread during the per-suite reset path.
