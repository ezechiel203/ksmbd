# ksmbd Debug Handoff Summary (2026-02-28)

## Scope completed
This session focused on:
1. Bringing host+VM debug workflow to a reproducible state.
2. Diagnosing and fixing the repeated soft-lockup around `smb2_set_rsp_credits`.
3. Fixing `ksmbdctl status` false negatives caused by lock PID validation.
4. Capturing evidence and preparing next-step instrumentation for remaining SMB disconnects.

## Environment state
- Host repo root: `/home/ezechiel203/ksmbd`
- VM scripts/state: `/home/ezechiel203/ksmbd/vm`
- Active VM launcher: `vm/run-vm.sh --daemonize`
- Active VM helper: `vm/vm-exec.sh`
- Current VM forwarding:
  - SMB: host `10445` -> VM `445`
  - SSH: host `10022` -> VM `22`

## Major fixes implemented

### 1) Credit-path deadlock fix
- File: `src/core/server.c`
- Change: removed outer `spin_lock(&conn->credits_lock)` around `conn->ops->set_rsp_credits(work)`.
- Why: `smb2_set_rsp_credits()` already acquires `credits_lock`; outer lock caused recursive lock acquisition in workqueue path and soft lockups.

### 2) Additional debug gates in contested paths
- File: `src/protocol/smb2/smb2misc.c`
  - Added `ksmbd_debug(SMB, ...)` around credit charge checks + lock enter/exit.
- File: `src/protocol/smb2/smb2_pdu_common.c`
  - Added `ksmbd_debug(SMB, ...)` around response credit lock enter/exit.
- File: `src/core/server.c`
  - Added `ksmbd_debug(SMB, ...)` at `set_rsp_credits` dispatch.

### 3) `ksmbdctl status` lockfile fix
- File: `ksmbd-tools/tools/config_parser.c`
- Change: `verify_mountd_pid()` now accepts both:
  - `ksmbd.mountd`
  - `ksmbdctl`
- Why: unified CLI mode runs mountd through `ksmbdctl start`, so `/proc/<pid>/comm` is `ksmbdctl`.

## Build and deploy checkpoints
- Rebuilt module successfully and validated debug markers present in `ksmbd.ko` strings.
- Loaded module in VM with source version:
  - `79CE76935B714A6DF80583B`
- Rebuilt `ksmbd-tools`, deployed `/usr/bin/ksmbdctl` in VM.

## Runtime outcomes

### Fixed
- Prior recurring watchdog/RCU soft lockup signature centered on `_raw_spin_lock -> smb2_set_rsp_credits` did not reappear in the fresh validation run.
- `ksmbdctl status` now reports mountd correctly as running.

### Still failing
- SMB client flow still disconnects:
  - `smbclient -s /dev/null -N -m SMB3 -p 10445 -L //127.0.0.1`
  - returns `NT_STATUS_CONNECTION_DISCONNECTED`
- Kernel logs during test show:
  - `PDU length(6424065) excceed maximum allowed pdu size(16384)`
  - `cli req too short, len 162 not 252. cmd:1 mid:2`

## Current working hypothesis
Two issues may coexist:
1. Invalid/garbage first RFC1002 frame (or non-SMB probe traffic) triggering oversized PDU path.
2. Session setup packet size validation mismatch (`cmd:1`, `len 162 != clc_len 252`) causing disconnect.

## In-progress local instrumentation
- File: `src/core/connection.c` (currently modified in working tree)
- Added debug gate logs for:
  - Raw 4-byte RFC1002 header bytes before parsing length.
  - First 4 bytes of parsed SMB payload signature after body read.
- Goal: detect framing/desync vs malformed packet origin.

## Important caution for next agent
This repo has many pre-existing local modifications unrelated to this specific bug. Avoid broad rebases/resets. Make only minimal, targeted edits and verify runtime after each.

## Key artifacts
- Main running log: `vm/DEBUG_LOG_2026-02-28.md`
- VM serial log: `vm/qemu-serial.log`
- VM startup output: `/root/ksmbd-start-manual.log` (inside VM)

## Multi-VM tooling implemented
Added:
- `vm/run-vm-instance.sh`
- `vm/vm-exec-instance.sh`
- `vm/stop-vm-instance.sh`

Smoke test performed:
- Launched lane B daemonized.
- Verified SSH command execution via `vm-exec-instance.sh`.
- Stopped lane B via `stop-vm-instance.sh`.
