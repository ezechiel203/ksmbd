# Validation Commands

## Quick source risk scans
```bash
rg -n "BUG_ON\(|WARN_ON\(|while \(1\)|for \(;;\)" src
rg -n "outstanding_credits|total_credits|credits_lock" src/core src/protocol
rg -n "atomic_|refcount_|spin_lock\(|spin_unlock\(" src/fs/ksmbd_notify.c src/fs/oplock.c
```

## Build (requires matching kernel headers)
```bash
make all W=1 -j$(nproc)
```

## VM runtime capture
```bash
dmesg -w
journalctl -kf
```

## Suggested stress focus
- malformed SMB2 compound requests,
- credit exhaustion / scan traffic,
- rapid connect/disconnect with pending locks,
- notify watch churn and teardown storms,
- IPC duplicate/late response injection.
