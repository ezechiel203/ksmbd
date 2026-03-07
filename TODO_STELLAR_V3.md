# TODO_STELLAR_V3.md — ksmbd Audit Cycle 3

Synthesized from 3 parallel audit agents (security, protocol, quality/testing).
Previous cycles: v1 (66 items → 29 fixed), v2 (37 items → all fixed).

---

## CRITICAL (1)

### C-01: ChannelSequence tracking incomplete (MS-SMB2 §3.3.5.2.10) — FIXED
- **File**: `src/protocol/smb2/smb2_read_write.c`, `src/protocol/smb2/smb2_dir.c`
- **Fix**: Added `smb2_check_channel_sequence()` calls to `smb2_read()` and `smb2_query_dir()` after fp lookup.

---

## HIGH (3)

### H-01: AvPairs integer overflow in auth.c — FIXED
- **File**: `src/core/auth.c`
- **Fix**: Used `check_add_overflow()` for AvPair offset arithmetic; returns -EINVAL on overflow.

### H-02: APPEND_DATA offset validation gap — FIXED
- **File**: `src/protocol/smb2/smb2_read_write.c`
- **Fix**: Added check: FILE_APPEND_DATA-only handles reject writes at non-EOF offsets with -EACCES.

### H-03: SMB1 andx_response_buffer bounds check — VERIFIED OK
- **File**: `src/protocol/smb1/smb1pdu.c`
- **Status**: Already properly bounds-checked. Callers pass `work->response_sz` (allocated buffer size). No fix needed.

---

## MEDIUM (8)

### M-01: EA null terminator off-by-one — VERIFIED OK (false positive)
- **File**: `src/protocol/smb2/smb2_create.c`
- **Status**: `attr_name` is allocated as `XATTR_NAME_MAX + 1` (fixed buffer), and NUL is written at `[prefix_len + name_len]`. No off-by-one.

### M-02: %px pointer leak in debug output — FIXED
- **File**: `src/fs/vfs_cache.c:1390`
- **Fix**: Changed `%px` to `%pK` (respects kptr_restrict sysctl).

### M-03: CreateContext NameLength validation — VERIFIED OK
- **File**: `src/fs/oplock.c` (`smb2_find_context_vals()`)
- **Status**: Already validates `name_len == tag_len && !memcmp(name, tag, name_len)`. Exact match required.

### M-04: TreeConnect extension path parsing — VERIFIED OK
- **File**: `src/protocol/smb2/smb2_tree.c`
- **Status**: Bounds checks for path_off + path_len already in place. ksmbd doesn't parse tree connect contexts beyond path extraction.

### M-05: Source files missing pr_fmt macro — FIXED (2 files)
- **Files**: `src/core/connection.c`, `src/mgmt/share_config.c`
- **Status**: Originally reported as 17 files, but 15 of those get `pr_fmt` from `glob.h` include. Only 2 truly lacked it. Fixed.

### M-06: 2 bare WARN_ON(1) without context — FIXED
- **Files**: `src/transport/transport_ipc.c`, `src/mgmt/user_session.c`
- **Fix**: Replaced with `WARN(1, "descriptive message")` including relevant context values.

### M-07: Hot-path kzalloc in smb2_pdu_common.c — NO ACTION (non-issue)
- **Status**: The `kzalloc` in `smb3_encrypt_resp()` is per-response (not per-compound-element), allocating ~60 bytes. Not a bottleneck.

### M-08: Durable handle UAF risk window — VERIFIED OK (non-issue)
- **Status**: `ksmbd_lookup_durable_fd()` increments refcount before returning fp. The timeout check happens while holding a reference. No UAF possible.

---

## LOW (4)

### L-01: FSCTL_QUERY_ON_DISK_VOLUME_INFO stub — DEFERRED
- Not required for protocol compliance; STATUS_NOT_SUPPORTED is correct behavior.

### L-02: VFS concurrency test gap — DEFERRED
- Would improve confidence in vfs_cache.c locking but not a code fix.

### L-03: Auth fuzzing gap — DEFERRED
- Would improve security assurance but not a code fix.

### L-04: Upstream delta documentation — DEFERRED
- Maintenance task, not a code fix.

---

## Summary

| Priority | Count | Fixed | Verified OK | Deferred |
|----------|-------|-------|-------------|----------|
| CRITICAL | 1 | 1 | 0 | 0 |
| HIGH | 3 | 2 | 1 | 0 |
| MEDIUM | 8 | 3 | 4 | 1 |
| LOW | 4 | 0 | 0 | 4 |
| **Total** | **16** | **6** | **5** | **5** |

Build verified clean: zero errors, zero warnings.
6 items fixed, 5 verified as already correct (false positives), 5 deferred (non-code items).
