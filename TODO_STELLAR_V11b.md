# TODO_STELLAR_V11b — Agent H Follow-up Audit
# Files: smb2_dir.c, ksmbd_notify.c, ksmbd_dfs.c, ksmbd_vss.c
# Date: 2026-03-06 | Branch: phase1-security-hardening
# Findings: 38 total (P0×3, P1×13, P2×16, P3×6)

## TOP 5 CRITICAL (immediate action)

1. NOTIFY-01 (P0): UAF — watch->fp accessed after build_response releases lock; concurrent file close → dangling fp
2. NOTIFY-02/07 (P0): heap overflow — smbConvertToUTF16() writes into response_buf without checking actual allocation size, only client-supplied OutputBufferLength
3. NOTIFY-05 (P1): UAF — piggyback cancel stores raw fp in argv[2] without kref; concurrent close → dangling fp->f_lock
4. DFS-02 (P1): PathConsumed field off-by-2x — computed in UTF-16 codeunits, spec requires BYTES → all DFS redirects broken
5. CROSS-01 (P1): compound CHANGE_NOTIFY memcpy only copies SMB2 header (64B), drops FILE_NOTIFY_INFORMATION body → client gets SUCCESS with empty data

---

## PHASE 0 — P0 CRITICAL

### [P0] NOTIFY-01: UAF — watch->fp accessed without file reference after lock released
**File**: `src/fs/ksmbd_notify.c:883–915`
**Issue**: After ksmbd_notify_build_response() returns, code re-reads watch->fp under watch->lock. But ksmbd_notify_cleanup_file() can free the underlying file between the lock-protected read and spin_lock(&fp->f_lock). TOCTOU UAF window.
**Fix**: After `fp = watch->fp` under watch->lock, call ksmbd_get_file_safe(fp) (or equivalent kref get), drop lock, use fp, then ksmbd_put_file(fp).
**Complexity**: MEDIUM

### [P0] NOTIFY-02: Heap overflow — response_buf write unchecked against actual allocation
**File**: `src/fs/ksmbd_notify.c:223–266`
**Issue**: ksmbd_notify_build_response() writes FILE_NOTIFY_INFORMATION to response_buf, only checking against client-supplied watch->output_buf_len (up to 16MB). Actual response_buf may be much smaller → heap overflow via smbConvertToUTF16().
**Fix**: Add `if (total_rsp_len > work->response_sz) goto overflow_path;` before the memcpy. Cap smbConvertToUTF16() output to actual available bytes.
**Complexity**: LOW

### [P0] NOTIFY-05: UAF — piggyback cancel fp stored without kref
**File**: `src/fs/ksmbd_notify.c:1311–1389`
**Issue**: argv[2] = fp stored without reference. If fp closed between storage and ksmbd_notify_cancel() execution, fp is dangling → UAF on spin_lock(&fp->f_lock).
**Fix**: Hold ksmbd_fd_get() on fp when storing in argv[2]; release in cancel/cleanup.
**Complexity**: MEDIUM

---

## PHASE 1 — P1 HIGH PRIORITY

### smb2_dir.c

### [P1] DIR-01: FILEID_GLOBAL_TX_DIRECTORY_INFORMATION uses wrong struct size (falls through to FILEID_BOTH)
**File**: `src/protocol/smb2/smb2_dir.c:397–434`
**Fix**: Remove FILEID_GLOBAL_TX_DIRECTORY_INFORMATION from verify_info_level() → reject with STATUS_INVALID_INFO_CLASS.
**Complexity**: LOW

### [P1] DIR-02: RESTART_SCANS does not reset readdir_started → STATUS_NO_MORE_FILES instead of STATUS_NO_SUCH_FILE
**File**: `src/protocol/smb2/smb2_dir.c:1214–1218`
**Fix**: Add `dir_fp->readdir_started = false;` in SMB2_RESTART_SCANS branch.
**Complexity**: LOW

### [P1] DIR-09: dentry_name() name_len from wire not bounds-checked → huge name_len to lookup_one
**File**: `src/protocol/smb2/smb2_dir.c:104–250`
**Fix**: Add `if (d_info->name_len > NAME_MAX) return -EINVAL;` after extracting name_len.
**Complexity**: LOW

### ksmbd_notify.c

### [P1] NOTIFY-04: WATCH_TREE flag stored but not honored — recursive monitoring not implemented
**File**: `src/fs/ksmbd_notify.c:1213–1218`
**Issue**: Linux fsnotify mark on single inode doesn't propagate to subdirectories. Clients get only direct-child events, missing all deep events silently.
**Fix**: Either return STATUS_NOT_SUPPORTED for WATCH_TREE requests, or implement recursive marks (complex).
**Complexity**: HIGH

### [P1] NOTIFY-07: Same as NOTIFY-02 (rename response writes before bounds check)
**File**: `src/fs/ksmbd_notify.c:223–266`
**Fix**: See NOTIFY-02.
**Complexity**: LOW

### [P1] NOTIFY-08: File name from fsnotify not validated for max length before UTF-16 encode
**File**: `src/fs/ksmbd_notify.c:208,229`
**Fix**: Add `max_write = work->response_sz - header_overhead;` and limit smbConvertToUTF16() output.
**Complexity**: LOW

### ksmbd_dfs.c

### [P1] DFS-02: PathConsumed off-by-2x — should be bytes, set to codeunits
**File**: `src/fs/ksmbd_dfs.c:330–331`
**Fix**: `dfs_rsp->path_consumed = cpu_to_le16(min_t(u32, req_name_len, U16_MAX));` — remove `/ sizeof(__le16)`.
**Complexity**: LOW

### [P1] DFS-03: RequestFileName not validated to start with backslash → relative path injection
**File**: `src/fs/ksmbd_dfs.c:268–274`
**Fix**: Check `request_path[0] == '\\' || request_path[0] == '/'` after UTF-8 conversion.
**Complexity**: LOW

### ksmbd_vss.c

### [P1] VSS-01: array_size uses KSMBD_VSS_GMT_TOKEN_LEN=32 but actual wire token is 24+1 codeunits
**File**: `src/fs/ksmbd_vss.c:649–651`
**Fix**: Define KSMBD_VSS_GMT_WIRE_LEN 25 and use for stride. The stride mismatch causes clients to see phantom empty entries.
**Complexity**: LOW

### [P1] VSS-02: Snapshot enumeration uses current_cred() (root) — bypasses client permission checks
**File**: `src/fs/ksmbd_vss.c:326–336`
**Fix**: Use ksmbd_override_fsids(work) before kern_path() and ksmbd_revert_fsids(work) after.
**Complexity**: MEDIUM

### Cross-file

### [P1] CROSS-01: Compound CHANGE_NOTIFY only copies 64-byte SMB2 header — drops notification body
**File**: `src/protocol/smb2/smb2_notify.c:258–263`
**Issue**: `memcpy(rsp, msg, __SMB2_HEADER_STRUCTURE_SIZE)` — drops FileNotifyInformation body. Client gets STATUS_SUCCESS with empty data.
**Fix**: Copy full notify response size including the body.
**Complexity**: MEDIUM

### [P1] CROSS-02: ksmbd_notify_cancel piggyback — argv[1] work ptr used without validation after possible free
**File**: `src/protocol/smb2/smb2_notify.c:155–157, src/fs/ksmbd_notify.c:1316`
**Fix**: Verify argv lifetime is tied to work struct; ensure cancel cannot run after release_async_work() on piggyback path.
**Complexity**: MEDIUM

---

## PHASE 2 — P2 MEDIUM

### smb2_dir.c
- DIR-03: INDEX_SPECIFIED silently ignored; add debug log (LOW)
- DIR-04: OutputBufferLength=0 not explicitly rejected with STATUS_INFO_LENGTH_MISMATCH (LOW)
- DIR-05: total_scan limit sends STATUS_NO_MORE_FILES on first request (should be STATUS_NO_SUCH_FILE) (LOW)
- DIR-06: reserve_populate_dentry estimates (name_len+1)*2 — underestimates for supplementary plane chars (LOW)
- DIR-07: verify_info_level() allows non-spec info classes (FILEID_GLOBAL_TX, FILEID_64_*, FILEID_ALL_*) (LOW)
- DIR-08: smb2_resp_buf_len negative returns STATUS_INFO_LENGTH_MISMATCH (should be INSUFFICIENT_RESOURCES) (LOW)
- DIR-10: OutputBufferOffset hardcoded 72 (should be offsetof(smb2_query_directory_rsp, Buffer)) (LOW)

### ksmbd_notify.c
- NOTIFY-03: kfree() called under spin_lock at lines 777, 811 (copy pointer, unlock, then kfree) (LOW)
- NOTIFY-06: KSMBD_NOTIFY_ALL_FILTERS name misleading; rename to KSMBD_NOTIFY_STANDARD_FILTERS (LOW)
- NOTIFY-09: rename response writes before second bounds check — reorder to compute size first (MEDIUM)
- NOTIFY-10: name_len stored as UTF-8 bytes but UTF-16 overflow estimation uses *2 (underestimates for supplementary chars) (LOW)
- NOTIFY-11: ksmbd_notify_complete_delete_pending uses down_read (sleepable); add might_sleep() assertion (LOW)
- NOTIFY-12: ksmbd_notify_build_response uses work->conn without conn reference — may be dangling on TCP drop (MEDIUM)
- NOTIFY-13: notify_watch_count increments/decrements in EEXIST path need audit (LOW)
- NOTIFY-14: FS_DELETE_SELF sends STATUS_DELETE_PENDING; spec requires STATUS_NOTIFY_CLEANUP (LOW)

### ksmbd_dfs.c
- DFS-04: referral_header_flags always sets both REFERRAL_SERVER and STORAGE_SERVER; links should only set STORAGE_SERVER (LOW)
- DFS-05: MaxReferralLevel=1 rejected; should respond with V2 format (LOW)
- DFS-06: FSCTL_DFS_GET_REFERRALS doesn't validate IPC$ tree connection (LOW)
- DFS-07: dfs_build_network_address discards path components after share name (LOW)
- DFS-08: No rate limiting on DFS referral enumeration (LOW)

### ksmbd_vss.c
- VSS-03: btrfs resolve path hardcodes /snapshot suffix (snapper-specific; try without first) (LOW)
- VSS-04: FSCTL_SRV_ENUMERATE_SNAPSHOTS missing FILE_READ_ATTRIBUTES access check on fp (LOW)
- VSS-05: No cap validation on snap_list.count for array_size overflow (add BUILD_BUG_ON) (LOW)
- VSS-06: Snapshot list silently truncated at 256; client not informed; TotalSnapshots should reflect actual count (MEDIUM)

---

## PHASE 3 — P3 POLISH

- DIR-10: Use offsetof() for OutputBufferOffset (LOW)
- NOTIFY-15: handle_event returns 0 unconditionally even on error (LOW)
- NOTIFY-16: qstr.hash uninitialized in ksmbd_notify_flush_one (LOW)
- DFS-07: Network address discards sub-path (LOW)
- VSS-07: ksmbd_vss_generic_backend duplicates btrfs logic — dead code (LOW)
- VSS-08: gmt_token digit validation missing (only checks separator positions) (LOW)
- VSS-09: Third-party VSS backends need module owner field for module safety (MEDIUM)

---

## Wave 3 Implementation Plan

| Agent | Scope | Key fixes |
|-------|-------|-----------|
| W3-NOTIFY-P0 | P0 notify fixes | NOTIFY-01, 02, 05, 07, 08 — UAF/overflow fixes |
| W3-DIR-DFS | P1 dir+DFS fixes | DIR-01, 02, 09; DFS-02, 03, 04; CROSS-01, 02 |
| W3-VSS-NOTIFY-P2 | P2 notify/VSS | NOTIFY-03, 06, 09-14; VSS-01-06 |
| W3-DIR-P2 | P2 dir compliance | DIR-03 through DIR-10 |
| W3-P3 | P3 polish + test sweep | All P3 items + VM test run |
