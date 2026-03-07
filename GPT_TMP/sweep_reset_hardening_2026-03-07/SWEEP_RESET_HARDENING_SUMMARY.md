# Sweep Reset Hardening Summary

Date: 2026-03-07

## Scope

Hardened the direct-TCP SMB2 sweep harness so each suite starts from a
guest-side factory reset instead of incremental cleanup.

Changed file:

- `vm/sweep-smb2.sh`

## What changed

- Replaced the ad hoc per-suite `rm -rf /srv/smb/test/*` cleanup with a
  guest-side `guest_factory_reset()` routine.
- Reset now explicitly removes:
  - all `ksmbdctl` / `ksmbd.mountd` / `ksmbd.control` processes
  - guest-side `smbtorture` / `smbclient` leftovers
  - lock files and FIFOs under `/run`, `/var/run`, `/usr/var/run`, and `/tmp`
  - ksmbd config state: `ksmbd.conf`, `ksmbdpwd.db`, `ksmbd.subauth`
  - the full `/srv/smb` share tree
  - common temporary sweep artifacts under `/tmp` and root logs
- Reset now recreates a known-clean minimal server state:
  - `/srv/smb/test`
  - fresh `/etc/ksmbd/ksmbd.conf`
  - fresh `/etc/ksmbd/ksmbdpwd.db` for `testuser%1234`
- The sweep now performs a full `restart_ksmbd()` before every suite, not only
  after selected heavy suites.
- Converted the SSH command to a shell array for safer quoting and cleaner
  shellcheck results.

## Validation

Commands run:

```sh
bash -n vm/sweep-smb2.sh
shellcheck vm/sweep-smb2.sh
```

Results:

- `bash -n`: passed
- `shellcheck`: passed

## Notes

- This reset intentionally preserves unrelated guest assets such as
  `/etc/ksmbd/quic/*`; it only rebuilds the direct-TCP sweep state.
- I did not execute a full sweep in this batch because the change is to harness
  reset behavior, not to protocol logic. The next protocol run should now start
  from a truly clean guest state for every suite.
