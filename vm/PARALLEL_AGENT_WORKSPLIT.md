# Parallel Agent Worksplit for ksmbd Debugging

## Objective
Use multiple agents in parallel without conflicting changes while accelerating root-cause analysis.

## Branching and ownership rules
1. One agent per topic branch (no shared branch writes).
2. One agent owns one VM instance + one log file.
3. All agents append findings to their own log, then produce a merge-ready summary.
4. No force-push, no history rewriting.

## Recommended parallel lanes

### Lane A: Transport framing and PDU ingress
Owner focus:
- `src/core/connection.c`
- `src/transport/transport_tcp.c`
Tasks:
1. Capture and classify first packet bytes for failing connections.
2. Determine if oversized RFC1002 length is malformed client input, stream desync, or parser misuse.
3. Propose minimal guard/fallback behavior with compatibility preserved.
Deliverables:
- patch + before/after dmesg excerpts
- packet classification table (good/bad signatures)

### Lane B: SMB2 request length validation path
Owner focus:
- `src/protocol/smb2/smb2misc.c`
- `src/protocol/smb2/smb2_pdu_common.c`
Tasks:
1. Reproduce `cmd:1 len 162 not 252` with precise field dumps.
2. Compare request against MS-SMB2 expectations for session setup framing.
3. Decide whether mismatch is bug in `smb2_calc_size`/offset interpretation or truly invalid client input.
Deliverables:
- validation trace outputs
- RFC/implementation delta notes
- targeted patch or explicit reject rationale

### Lane C: Userspace daemon + netlink + auth path
Owner focus:
- `ksmbd-tools/mountd/*`
- `ksmbd-tools/tools/*`
Tasks:
1. Verify mountd worker lifecycle and netlink response behavior during session setup.
2. Confirm no hidden mountd-side failure that triggers disconnect after parse stage.
3. Extend structured logs around auth/session setup requests.
Deliverables:
- userspace log timeline aligned with kernel timestamps
- patch for missing diagnostics or behavioral fix

### Lane D: Client and reproducibility harness
Owner focus:
- `vm/debug-workflow.sh`
- host-side test invocations
Tasks:
1. Standardize reproducible client probes (`smbclient`, `mount.cifs`, optional smbtorture).
2. Ensure each test records exact command, protocol dialect, and output.
3. Produce pass/fail matrix by feature toggle set.
Deliverables:
- reproducible test harness script updates
- regression checklist

## Minimal merge order
1. Merge infrastructure/logging patches first.
2. Merge framing/validation fixes second.
3. Merge behavioral/auth fixes third.
4. Re-run full matrix and freeze known-good baseline.

## Conflict prevention checklist
- Touch only files in assigned lane unless approved.
- Rebase frequently, resolve conflicts locally, rerun your lane tests.
- Never overwrite another lane’s log files.
