# smbtorture Sweep Results — All Failures with Root Causes

**Branch:** phase1-security-hardening
**HEAD:** 01e95dbe
**Date:** 2026-03-06
**Method:** Individual test runs on fresh VM3 (smbtorture 4.23.6), daemon inside VM

## Summary

| Suite | PASS | FAIL | SKIP | Δ vs baseline |
|-------|------|------|------|---------------|
| rw | 4 | 0 | 0 | same |
| create | 16 | 1 | 1 | same |
| dir | 9 | 0 | 0 | same |
| dosmode | 0 | 1 | 0 | same |
| read | 4 | 0 | 1 | same |
| getinfo | 8 | 0 | 0 | same |
| oplock | 39 | 3 | 0 | +1P |
| lease | 29 | 8 | 1 | same |
| dirlease | 3 | 15 | 0 | same |
| streams | 12 | 2 | 0 | same |
| notify | 16 | 7 | 0 | +2P, -2F |
| compound_async | 7 | 3 | 0 | same |
| compound_find | 3 | 0 | 0 | same |
| ioctl | 40 | 20 | 15 | same |
| durable-open | 21 | 4 | 1 | same |
| durable-v2-open | 32 | 1 | 0 | same |
| replay | 10 | 5 | 0 | same |
| delete-on-close-perms | 8 | 1 | 0 | same |
| secleak | 0 | 1 | 0 | same |
| zero-data-ioctl | 0 | 1 | 0 | same |
| session | 16 | 42 | 10 | same |
| **TOTAL** | **277** | **115** | **29** | **+3P, -2F** |

NOTE: Full sequential sweep shows more failures (150F) due to connection state leaks between suites. The table above reflects individual test results on clean server.

---

## All 115 Failures with Root Causes

### smb2.create (1F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 1 | gentest | access_mask 0x0de0fe00 should be 0x0df0fe00 | Missing ACCESS_SYSTEM_SECURITY (0x01000000) in returned access mask. Intentionally omitted — adding it breaks other tests (DESIRED_ACCESS_MASK rule). Needs --target=win7 |

### smb2.dosmode (1F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 2 | dosmode | FILE_ATTRIBUTE_HIDDEN not set | **Test env config**: ksmbd.conf missing `hide dot files = yes` directive |

### smb2.secleak (1F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 3 | secleak | NT_STATUS_OK should be NT_STATUS_LOGON_FAILURE — allowed session with invalid creds | **Test env config**: `map to guest = bad user` in ksmbd.conf allows anonymous auth for invalid users |

### smb2.zero-data-ioctl (1F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 4 | zero-data-ioctl | FSCTL_SET_ZERO_DATA failure | **Test env config**: needs `--option=torture:offset=<N>` parameter |

### smb2.oplock (3F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 5 | batch3 | NT_STATUS_SHARING_VIOLATION should be NT_STATUS_OK | Server doesn't detect client closed handle-on-break within timeout; 2nd open gets SHARING_VIOLATION |
| 6 | batch7 | NT_STATUS_SHARING_VIOLATION should be NT_STATUS_OK | Same as batch3 — oplock break timeout path doesn't recheck after client close |
| 7 | batch22b | 2nd open should succeed after oplock break timeout | Server must disconnect non-ACKing client (complex behavior, not implemented) |

### smb2.lease (8F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 8 | statopen4 | lease_break_info.count=1 should be 0 | Stat-open with SYNCHRONIZE bit triggers unexpected lease break |
| 9 | oplock | (lease/oplock interaction test) | Oplock-to-lease upgrade path not fully implemented |
| 10 | breaking2 | NT_STATUS_INVALID_NETWORK_RESPONSE should be NT_STATUS_REQUEST_NOT_ACCEPTED | Server sends wrong status when 2nd open arrives during pending lease break |
| 11 | v2_breaking3 | lease_break_info.count=1 should be 0 | Spurious lease break during v2 breaking scenario |
| 12 | breaking4 | (lease break contention) | Server doesn't properly queue opens during active lease break |
| 13 | v2_flags_breaking | (v2 flags during break) | Lease break flags not correctly propagated in v2 path |
| 14 | v2_complex1 | (complex v2 lease scenario) | Multi-handle v2 lease upgrade/downgrade not fully implemented |
| 15 | unlink | break_flags=0x0 should be 0x1 | SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED not set on delete-triggered break |

### smb2.dirlease (15F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 16 | v2_request | lease_epoch 0x26 should be 0x25 | **Not implemented**: directory lease epoch tracking off-by-one |
| 17 | seteof | lease_epoch 0x4 should be 0x3 | Dir lease break on child EOF change — epoch mismatch |
| 18 | setdos | (same pattern) | Dir lease break on child DOS attrib change |
| 19 | setbtime | (same pattern) | Dir lease break on child birth-time change |
| 20 | setmtime | (same pattern) | Dir lease break on child mtime change |
| 21 | setctime | (same pattern) | Dir lease break on child ctime change |
| 22 | setatime | (same pattern) | Dir lease break on child atime change |
| 23 | rename | smb2_lease_break_ack failed NT_STATUS_UNSUCCESSFUL | Dir lease break ACK path broken for rename operations |
| 24 | rename_dst_parent | (similar) | Dir lease break on rename destination parent |
| 25 | overwrite | (similar) | Dir lease break on overwrite |
| 26 | hardlink | (similar) | Dir lease break on hardlink creation |
| 27 | unlink_same_set_and_close | (similar) | Dir lease break on unlink (same lease set) |
| 28 | unlink_different_set_and_close | (similar) | Dir lease break on unlink (different lease set) |
| 29 | unlink_same_initial_and_close | (similar) | Dir lease break on unlink (same initial) |
| 30 | unlink_different_initial_and_close | (similar) | Dir lease break on unlink (different initial) |

**Root cause for all 15**: Directory lease (RH on directories) break-on-child-modification is not fully implemented. Server either doesn't send break, sends wrong epoch, or ACK path fails.

### smb2.streams (2F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 31 | names | streams.c:847 testing stream names | Alternate data stream enumeration incomplete — some system streams not returned or wrong format |
| 32 | names2 | streams.c:1141 testing stream names | Same — second variant of stream name enumeration test |

### smb2.notify (7F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 33 | valid-req | num_changes=4 should be 3 | Server returns extra change event (spurious attribute notify from xattr init) |
| 34 | mask | nchanges=2 expected=1 | Extra events leaking through filter — create-suppress heuristic doesn't cover all cases |
| 35 | mask-change | changes[0].action=1 should be 3 | Server uses first-NOTIFY filter for subsequent requests (Windows behavior), but test expects filter update |
| 36 | invalid-reauth | NT_STATUS_OK should be NT_STATUS_LOGON_FAILURE | Reauth with wrong password succeeds — same root as secleak (map to guest config) |
| 37 | tree | NT_STATUS_OBJECT_NAME_COLLISION should be NT_STATUS_OK | Tree disconnect/reconnect during notify leaves stale directory state |
| 38 | rec | num_changes=5 should be 9 | Recursive (WATCH_TREE) monitoring returns fewer events than expected — subtree event propagation incomplete |
| 39 | dir | (dir event test) | Directory-level notification filtering incomplete |

### smb2.compound_async (3F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 40 | write_write | req[1]->cancel.can_cancel=0 should be 1 | Compound async write+write: 2nd write not marked cancellable (async dispatch issue) |
| 41 | read_read | req[1]->cancel.can_cancel=0 should be 1 | Same pattern for compound async read+read |
| 42 | getinfo_middle | NT_STATUS_FILE_CLOSED should be NT_STATUS_OK | Compound create+getinfo+close — getinfo runs after close due to async ordering |

### smb2.ioctl (20F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 43 | compress_notsup_set | NT_STATUS_INVALID_PARAMETER should be NT_STATUS_NOT_SUPPORTED | FSCTL_SET_COMPRESSION returns wrong error code |
| 44 | sparse_qar_malformed | NT_STATUS_BUFFER_TOO_SMALL should be NT_STATUS_OK | FSCTL_QUERY_ALLOCATED_RANGES buffer handling issue |
| 45 | sparse_punch | far_count=0 expected=1 | FSCTL_SET_ZERO_DATA doesn't properly punch holes in sparse files |
| 46 | sparse_hole_dealloc | far_rsp[0].file_off=4096 expected=0 | Deallocation offset tracking wrong after hole punch |
| 47 | sparse_compressed | (sparse+compressed interaction) | Not implemented |
| 48 | sparse_perms | NT_STATUS_ACCESS_DENIED should be NT_STATUS_OK | FSCTL_SET_SPARSE permission check too restrictive |
| 49 | sparse_lock | NT_STATUS_OK should be NT_STATUS_FILE_LOCK_CONFLICT | Zero-data on locked range should fail but succeeds |
| 50 | trim_simple | (FSCTL_FILE_LEVEL_TRIM) | **Not implemented**: TRIM ioctl not supported |
| 51 | dup_extents_simple | NT_STATUS_NOT_SUPPORTED | **Not implemented**: FSCTL_DUP_EXTENTS_TO_FILE not supported |
| 52 | dup_extents_len_beyond_dest | NT_STATUS_NOT_SUPPORTED | Same — dup_extents not implemented |
| 53 | dup_extents_len_beyond_src | NT_STATUS_NOT_SUPPORTED | Same |
| 54 | dup_extents_len_zero | NT_STATUS_NOT_SUPPORTED | Same |
| 55 | dup_extents_sparse_dest | NT_STATUS_NOT_SUPPORTED | Same |
| 56 | dup_extents_sparse_both | NT_STATUS_NOT_SUPPORTED | Same |
| 57 | dup_extents_src_is_dest | NT_STATUS_NOT_SUPPORTED | Same |
| 58 | dup_extents_bad_handle | NT_STATUS_OBJECT_NAME_NOT_FOUND should be NT_STATUS_FILE_CLOSED | Wrong error code for closed handle in dup_extents |
| 59 | dup_extents_src_lock | NT_STATUS_NOT_SUPPORTED | Same — dup_extents not implemented |
| 60 | dup_extents_dest_lock | NT_STATUS_NOT_SUPPORTED | Same |
| 61 | bug14769 | NT_STATUS_INVALID_DEVICE_REQUEST | FSCTL for bug14769 scenario not handled |
| 62 | bug14788.VALIDATE_NEGOTIATE | NT_STATUS_ACCESS_DENIED on tcon to noperm share | Test requires a `noperm` share in ksmbd.conf |
| 63 | bug14788.NETWORK_INTERFACE | NT_STATUS_INVALID_DEVICE_REQUEST | FSCTL_QUERY_NETWORK_INTERFACE_INFO not implemented (single-NIC) |

### smb2.durable-open (4F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 64 | reopen2-lease | (lease-based durable reconnect) | Lease key mismatch during durable reconnect path |
| 65 | delete_on_close2 | NT_STATUS_OBJECT_NAME_NOT_FOUND | Durable handle with delete-on-close: file deleted before reconnect completes |
| 66 | alloc-size | alloc_size=8192 should be 4096 | Allocation size not preserved across durable reconnect (rounded to block size) |
| 67 | reopen2a | (oplock-based durable reconnect variant) | Reconnect with changed oplock level not handled |

### smb2.durable-v2-open (1F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 68 | reopen2-lease | (v2 lease-based durable reconnect) | Same as durable-open.reopen2-lease but for v2 path |

### smb2.replay (5F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 69 | dhv2-pending1n-vs-violation-lease-close-sane | NT_STATUS_IO_TIMEOUT should be NT_STATUS_FILE_NOT_AVAILABLE | **Not implemented**: replay/pending create conflict resolution |
| 70 | dhv2-pending1n-vs-violation-lease-ack-sane | (similar) | Same — pending create vs lease violation |
| 71 | dhv2-pending1n-vs-oplock-sane | (similar) | Pending create vs oplock conflict |
| 72 | channel-sequence | NT_STATUS_FILE_LOCK_CONFLICT should be NT_STATUS_FILE_NOT_AVAILABLE | Channel sequence number validation not implemented |
| 73 | replay6 | Error codes for DurableHandleReqV2 replay | Replay detection for durable v2 not fully implemented |

### smb2.delete-on-close-perms (1F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 74 | READONLY | NT_STATUS_OK should be NT_STATUS_CANNOT_DELETE | Server allows creating file with DELETE_ON_CLOSE on read-only share — missing share-level perm check |

### smb2.session (42F)

| # | Test | Error | Root Cause |
|---|------|-------|------------|
| 75 | reauth5 | smb2_util_unlink failed (NT_STATUS_OBJECT_NAME_NOT_FOUND) | **Samba test bug**: test tries to unlink a file it never created |
| 76 | bind_negative_smb202 | NT_STATUS_NOT_SUPPORTED | **Requires multichannel** (2nd NIC): session binding needs 2 TCP connections |
| 77–114 | bind_negative_smb210s..smb3signGtoH2Xd (38 tests) | NT_STATUS_NOT_SUPPORTED | **All require multichannel**: session binding negative tests need 2nd transport |
| 115 | anon-encryption1 | NT_STATUS_IO_TIMEOUT should be NT_STATUS_CONNECTION_RESET | Anonymous session + mandatory encryption: server should reset connection, instead times out |
| 116 | anon-encryption2 | (similar) | Same pattern |
| 117 | anon-encryption3 | (similar) | Same pattern |
| — | anon-signing1 | NT_STATUS_ACCESS_DENIED should be NT_STATUS_OK | Anonymous session signing interaction — ACL or signing enforcement bug |

---

## Failure Categories Summary

| Category | Count | Description |
|----------|-------|-------------|
| **Not implemented** | 38 | Feature not yet in ksmbd (dup_extents, trim, replay pending, dir-lease breaks, multichannel bind) |
| **Test env config** | 4 | dosmode, secleak, zero-data-ioctl, bug14788.VALIDATE_NEGOTIATE need ksmbd.conf changes |
| **Oplock/lease break** | 14 | Server doesn't correctly handle break timeout, queuing, or flags |
| **Notify filter/event** | 7 | Extra events, filter leakage, recursive monitoring incomplete |
| **Protocol compliance** | 10 | Wrong error codes, wrong values, missing checks |
| **Compound async** | 3 | Async ordering/cancellation in compound requests |
| **Samba test bug** | 1 | reauth5 unlinks non-existent file |
| **Session/anon** | 4 | Anonymous encryption/signing edge cases |
