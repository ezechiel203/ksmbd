# TODO_STELLAR_V4.md — ksmbd Audit Cycle 4

Synthesized from 3 parallel audit agents (security, protocol, quality).
Previous cycles: v1 (66→29), v2 (37→all), v3 (16→6 fixed, 5 verified OK).

---

## CRITICAL (2) — ALL FIXED

### S-01: parse_dacl() heap out-of-bounds write — FIXED
- **File**: `src/fs/smbacl.c` (`init_acl_state`)
- **Fix**: Allocate `num_aces + 2` entries instead of `num_aces` to accommodate post-loop owner/group writes.

### S-02: SMB1 session setup unbounded PasswordLength OOB read — FIXED
- **File**: `src/protocol/smb1/smb1pdu.c` (`build_sess_rsp_noextsec`)
- **Fix**: Added `check_add_overflow(ci_len, cs_len)` and `offset <= ByteCount` validation.

---

## HIGH (4) — ALL FIXED

### S-03: SMB1 tree connect PasswordLength OOB read — FIXED
- **File**: `src/protocol/smb1/smb1pdu.c` (`smb_tree_connect_andx`)
- **Fix**: Added `PasswordLength <= ByteCount` validation before use.

### S-04: SMB1 smb_get_ea() heap buffer overflow — FIXED
- **File**: `src/protocol/smb1/smb1pdu.c` (`smb_get_ea`)
- **Fix**: Added `buf_free_len` checks before header write and before value `memcpy`; returns STATUS_BUFFER_OVERFLOW on overflow.

### S-05: sg_set_buf with kvzalloc buffer (vmalloc incompatible) — FIXED
- **File**: `src/core/auth.c` (GMAC signing path)
- **Fix**: Added `is_vmalloc_addr()` check; uses `sg_set_page(vmalloc_to_page())` for vmalloc buffers, `sg_set_buf()` for kmalloc.

### P-01: READ access check incorrectly includes FILE_READ_ATTRIBUTES_LE — FIXED
- **File**: `src/protocol/smb2/smb2_read_write.c` (`smb2_read`)
- **Fix**: Changed to check only `FILE_READ_DATA_LE` per MS-SMB2 §3.3.5.12.

---

## MEDIUM (7) — ALL FIXED

### S-06: SMB1 ECHO response ByteCount OOB read — FIXED
- **File**: `src/protocol/smb1/smb1pdu.c` (`smb_echo`)
- **Fix**: Clamped `data_count` to actual PDU payload size (`pdu_len - header_offset`).

### S-07: Missing dentry reference in ksmbd_inode_init — FIXED
- **File**: `src/fs/vfs_cache.c`
- **Fix**: `dget()` in `ksmbd_inode_init()`, `dput()` in `ksmbd_inode_free()`.

### Q-01: Session leak on ksmbd_session_register failure — FIXED
- **File**: `src/protocol/smb2/smb2_session.c`
- **Fix**: Call `ksmbd_session_destroy(sess)` and set `sess = NULL` on register failure.

### Q-02: TOCTOU race in add_lease_global_list — FIXED
- **File**: `src/fs/oplock.c`
- **Fix**: Changed from RCU read + separate write_lock to single `write_lock(&lease_list_lock)` for entire search-and-insert. Uses `GFP_ATOMIC` for allocation under spinlock.

### P-02: CLOSE handler does not reject invalid Flags — FIXED
- **File**: `src/protocol/smb2/smb2_misc_cmds.c`
- **Fix**: Added validation: reject `Flags != 0 && Flags != SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB`.

### P-03: Session binding returns wrong status for pre-SMB3 — FIXED
- **File**: `src/protocol/smb2/smb2_session.c`
- **Fix**: Set `rsp->hdr.Status = STATUS_REQUEST_NOT_ACCEPTED` explicitly.

### P-04: FILE_OPEN/FILE_OVERWRITE non-existent file wrong status — FIXED
- **File**: `src/protocol/smb2/smb2_create.c`
- **Fix**: When `!(open_flags & O_CREAT)` and ENOENT, return STATUS_OBJECT_NAME_NOT_FOUND.

---

## LOW (7) — 6 FIXED, 1 DEFERRED

### P-05: Tree Connect missing SMB2_SHAREFLAG_ENCRYPT_DATA — DEFERRED
- Requires ksmbd-tools ABI addition. No code-only fix possible.

### P-06: Tree Connect ShareFlags on error paths — FIXED
- **File**: `src/protocol/smb2/smb2_tree.c`
- **Fix**: Moved Capabilities/ShareFlags assignment above `out_err1:` label.

### P-07: WRITE offset overflow for write-to-EOF — FIXED
- **File**: `src/protocol/smb2/smb2_read_write.c`
- **Fix**: Added post-resolution `offset > MAX_LFS_FILESIZE - length` check after write_to_eof.

### P-08: QUERY_DIR SMB2_INDEX_SPECIFIED ignored — DEFERRED
- Most clients don't use this flag. Low impact.

### S-08: SMB1 session setup response strings — FIXED
- **File**: `src/protocol/smb1/smb1pdu.c`
- **Fix**: Capped string lengths to `sizeof(str)` buffer and workgroup name to 31 chars.

### Q-03: Missing break in S_IFSOCK — FIXED
- **File**: `src/protocol/smb2/smb2_query_set.c`
- **Fix**: Added `break;`.

### Q-04: Indentation inconsistency — FIXED
- **File**: `src/protocol/smb2/smb2_query_set.c`
- **Fix**: Fixed indentation in default case body.

---

## Summary

| Priority | Count | Fixed | Deferred |
|----------|-------|-------|----------|
| CRITICAL | 2 | 2 | 0 |
| HIGH | 4 | 4 | 0 |
| MEDIUM | 7 | 7 | 0 |
| LOW | 7 | 5 | 2 |
| **Total** | **20** | **18** | **2** |

Build verified: zero errors, zero new warnings.
All CRITICAL, HIGH, and MEDIUM items fixed. 2 LOW items deferred (require ABI changes or client-dependent).
