# VFS / Filesystem Layer Security Code Review

**Date:** 2026-02-28
**Reviewer:** Claude Opus 4.6 (automated)
**Scope:** All files under `src/fs/` and `src/include/fs/` in the ksmbd kernel module
**Branch:** phase1-security-hardening

---

## Files Reviewed

| # | File | Lines |
|---|------|-------|
| 1 | `src/fs/vfs.c` | ~3500 |
| 2 | `src/include/fs/vfs.h` | 375 |
| 3 | `src/fs/vfs_cache.c` | 1338 |
| 4 | `src/include/fs/vfs_cache.h` | 225 |
| 5 | `src/fs/oplock.c` | ~2283 |
| 6 | `src/include/fs/oplock.h` | 151 |
| 7 | `src/fs/smbacl.c` | ~1999 |
| 8 | `src/include/fs/smbacl.h` | 309 |
| 9 | `src/fs/ksmbd_fsctl.c` | ~1900 |
| 10 | `src/include/fs/ksmbd_fsctl.h` | 105 |
| 11 | `src/fs/ksmbd_fsctl_extra.c` | 663 |
| 12 | `src/include/fs/ksmbd_fsctl_extra.h` | (header) |
| 13 | `src/fs/ksmbd_notify.c` | 628 |
| 14 | `src/include/fs/ksmbd_notify.h` | (header) |
| 15 | `src/fs/ksmbd_dfs.c` | 521 |
| 16 | `src/include/fs/ksmbd_dfs.h` | (header) |
| 17 | `src/fs/ksmbd_reparse.c` | 1222 |
| 18 | `src/include/fs/ksmbd_reparse.h` | (header) |
| 19 | `src/fs/ksmbd_vss.c` | 761 |
| 20 | `src/include/fs/ksmbd_vss.h` | (header) |
| 21 | `src/fs/ksmbd_branchcache.c` | 721 |
| 22 | `src/include/fs/ksmbd_branchcache.h` | (header) |
| 23 | `src/fs/ksmbd_quota.c` | 438 |
| 24 | `src/include/fs/ksmbd_quota.h` | (header) |
| 25 | `src/fs/ksmbd_info.c` | ~700 |
| 26 | `src/include/fs/ksmbd_info.h` | (header) |
| 27 | `src/fs/ksmbd_app_instance.c` | 318 |
| 28 | `src/include/fs/ksmbd_app_instance.h` | (header) |
| 29 | `src/fs/ksmbd_create_ctx.c` | 247 |
| 30 | `src/include/fs/ksmbd_create_ctx.h` | (header) |
| 31 | `src/fs/ksmbd_resilient.c` | 147 |
| 32 | `src/include/fs/ksmbd_resilient.h` | (header) |
| 33 | `src/fs/ksmbd_rsvd.c` | 653 |
| 34 | `src/include/fs/ksmbd_rsvd.h` | (header) |
| 35 | `src/include/fs/xattr.h` | 137 |

---

## Executive Summary

The VFS/filesystem layer of ksmbd has undergone substantial security hardening in this branch. The codebase demonstrates a strong defensive posture with multiple layers of path traversal prevention (`LOOKUP_BENEATH`, `LOOKUP_NO_SYMLINKS`, post-open `path_is_under()` checks), thorough integer overflow protection in ACL parsing (via `check_add_overflow()`), and careful bounds checking on protocol parsing. The modular FSCTL/info-level dispatch architecture using RCU-protected hash tables is well-designed.

However, several issues remain across the 10 security categories. The most concerning are: (1) a TOCTOU race in `ksmbd_vfs_listxattr()` that can cause kernel heap out-of-bounds reads; (2) potential lock ordering issues in oplock break notification while holding `ci->m_lock`; (3) a weak symlink target validation pattern in legacy SMB1 code; and (4) reference counting operations on `ksmbd_inode` without proper lock protection. The `ksmbd_vfs_get_sd_xattr()` function also has a potential underflow when adjusting NTSD offsets, and the BranchCache server secret is never rotated.

Overall severity distribution:

- **P0 (Critical):** 2 findings
- **P1 (High):** 5 findings
- **P2 (Medium):** 8 findings
- **P3 (Low/Informational):** 7 findings

---

## Critical Findings (P0)

### P0-01: TOCTOU in `ksmbd_vfs_listxattr()` -- Heap Out-of-Bounds Read

**File:** `src/fs/vfs.c`, `ksmbd_vfs_listxattr()`
**Category:** Race Condition / TOCTOU (Category 2)

**Description:**
The function performs two calls to `vfs_listxattr()` -- the first with a NULL buffer to query the size, then a second to actually retrieve the list into an allocated buffer of that size. Between the two calls, another thread or process (including a local attacker with filesystem access) can add xattrs, causing the actual list to exceed the allocated buffer.

```c
// First call: query size
size = vfs_listxattr(dentry, NULL, 0);
// ...
xattr_list = kvmalloc(size, KSMBD_DEFAULT_GFP);
// Second call: fill buffer -- size may have grown
size = vfs_listxattr(dentry, xattr_list, size);
```

If the xattr list grows between the two calls, `vfs_listxattr()` returns `-ERANGE`, which IS handled (the function returns an error). However, the pattern is still fragile because:
1. On some filesystem implementations, the behavior on buffer-too-small may vary.
2. The function is called in a hot path during file close and xattr enumeration.

**Impact:** Potential heap out-of-bounds read if the underlying filesystem does not correctly return `-ERANGE`. In the common case, `vfs_listxattr()` does return `-ERANGE` making the practical impact lower, but the pattern remains a latent risk.

**Recommendation:** Use a retry loop: if `vfs_listxattr()` returns `-ERANGE`, free the buffer, re-query the size, and retry (with a retry limit to prevent infinite loops).

---

### P0-02: `ksmbd_vfs_get_sd_xattr()` NTSD Offset Underflow on Tampered Xattr

**File:** `src/fs/vfs.c`, lines 2768-2773
**Category:** Kernel Memory Corruption (Category 7)

**Description:**
After decoding the cached NTSD from xattr, the function subtracts `NDR_NTSD_OFFSETOF` from three offset fields without checking for underflow:

```c
(*pntsd)->osidoffset = cpu_to_le32(le32_to_cpu((*pntsd)->osidoffset) -
                       NDR_NTSD_OFFSETOF);
(*pntsd)->gsidoffset = cpu_to_le32(le32_to_cpu((*pntsd)->gsidoffset) -
                       NDR_NTSD_OFFSETOF);
(*pntsd)->dacloffset = cpu_to_le32(le32_to_cpu((*pntsd)->dacloffset) -
                       NDR_NTSD_OFFSETOF);
```

If an attacker who controls xattr data (e.g., via a locally mounted filesystem) stores crafted NTSD data in `security.NTACL` with offset values smaller than `NDR_NTSD_OFFSETOF`, the subtraction wraps to a very large value. This corrupted offset is later used by callers to index into the NTSD buffer, leading to out-of-bounds memory access.

**Contrast:** The corresponding `ksmbd_vfs_set_sd_xattr()` (line 2618-2621) correctly validates against overflow BEFORE addition, but the reverse direction lacks underflow checks.

**Impact:** Kernel out-of-bounds read/write when processing tampered xattr data. Requires local filesystem access to exploit (e.g., pre-seeded xattr on the shared volume).

**Recommendation:** Add underflow checks before subtraction:
```c
if (le32_to_cpu((*pntsd)->osidoffset) < NDR_NTSD_OFFSETOF ||
    le32_to_cpu((*pntsd)->gsidoffset) < NDR_NTSD_OFFSETOF ||
    le32_to_cpu((*pntsd)->dacloffset) < NDR_NTSD_OFFSETOF) {
    rc = -EINVAL;
    goto out_free;
}
```

---

## High Findings (P1)

### P1-01: Weak SMB1 Symlink Target Validation

**File:** `src/fs/vfs.c`, `ksmbd_vfs_symlink()` (under `CONFIG_SMB_INSECURE_SERVER`)
**Category:** Symlink Attack / Path Traversal (Categories 1, 5)

**Description:**
The SMB1 symlink creation path uses a simplistic check:

```c
if (name[0] == '/' || strstr(name, ".."))
    return -EACCES;
```

This check has multiple bypass vectors:
1. Encoded path components (e.g., Unicode normalization, alternate encodings passed before this check)
2. Symlink chains where the target itself is a symlink that escapes
3. Paths like `foo/../../etc/shadow` are correctly caught, but the check does not validate the resolved path stays within the share boundary

**Impact:** SMB1 clients could create symlinks that point outside the share root, enabling unauthorized file access. This is gated by `CONFIG_SMB_INSECURE_SERVER` which reduces the exposure.

**Recommendation:** Apply the same `ksmbd_is_safe_reparse_target()` validation used in the SMB2 reparse code path, and add a post-creation `path_is_under()` check as done in `ksmbd_reparse_replace_with_symlink()`.

---

### P1-02: Potential Deadlock in `smb_break_all_levII_oplock()`

**File:** `src/fs/oplock.c`
**Category:** Lock Ordering / Deadlock (Category 8)

**Description:**
`smb_break_all_levII_oplock()` iterates `ci->m_op_list` while holding `ci->m_lock` (read lock) and calls into `oplock_break()` which may:
1. Send a network message (potential blocking I/O)
2. Acquire additional locks in the connection/session path

This creates a potential lock ordering inversion if another thread holds a connection lock and attempts to acquire `ci->m_lock`. The problem is exacerbated because Level II oplock breaks are sent for every file read/write operation on shared files.

**Impact:** Kernel deadlock under concurrent SMB access to the same file from multiple connections.

**Recommendation:** Collect the list of opinfos to break under `m_lock`, drop the lock, then break each one individually. This is the pattern used in similar code in CIFS/SMB client implementations.

---

### P1-03: `ksmbd_lookup_fd_inode()` Decrements `ci->m_count` Without Hash Lock

**File:** `src/fs/vfs_cache.c`
**Category:** Reference Counting Bug (Category 3)

**Description:**
In `ksmbd_lookup_fd_inode()`, the function looks up a `ksmbd_inode` via the hash table, increments `m_count`, accesses `m_fp_list`, then decrements `m_count` -- but the decrement happens after releasing the hash bucket lock. If `m_count` reaches zero between the decrement and any subsequent reference, the inode may be freed while still being referenced by the returned `ksmbd_file`.

Similarly, `ksmbd_query_inode_status()` performs `atomic_dec(&ci->m_count)` without holding the hash lock, which can race with `__ksmbd_inode_close()` that checks `m_count` under the write lock.

**Impact:** Use-after-free of `ksmbd_inode` structures, leading to kernel memory corruption.

**Recommendation:** Either:
1. Use `ksmbd_inode_put()` consistently which handles the free-if-zero semantics safely, or
2. Ensure `m_count` decrements are protected by the hash bucket write lock.

---

### P1-04: VSS Snapshot Path Not Validated Against Share Boundary

**File:** `src/fs/ksmbd_vss.c`, `ksmbd_vss_scan_snap_dir()`
**Category:** Path Traversal (Category 1)

**Description:**
The VSS snapshot scanning uses `kern_path()` with `LOOKUP_FOLLOW | LOOKUP_DIRECTORY` to open snapshot directories. The `LOOKUP_FOLLOW` flag allows symlink traversal, and no `LOOKUP_BENEATH` or share boundary check is applied. If an attacker can create a symlink at `.snapshots/` pointing outside the share, the snapshot enumeration follows it.

```c
ret = kern_path(snap_dir_path,
                LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
                &snap_path);
```

Additionally, the btrfs/zfs resolve functions construct paths via `snprintf()` using the GMT token from the snapshot entry, which is ultimately derived from directory names. A crafted directory name could potentially include path traversal sequences.

**Impact:** Information disclosure or unauthorized file access if an attacker can influence the `.snapshots` directory structure.

**Recommendation:**
1. Replace `LOOKUP_FOLLOW` with `LOOKUP_NO_SYMLINKS` for snapshot directory traversal.
2. Add `path_is_under()` validation after resolving snapshot paths.
3. Validate GMT token entries contain only expected characters.

---

### P1-05: `smb_check_perm_dacl()` Missing `posix_acl_release()` on Error Path

**File:** `src/fs/smbacl.c`, lines 1804-1844
**Category:** Resource Exhaustion / Memory Leak (Category 6)

**Description:**
In the POSIX ACL matching loop within `smb_check_perm_dacl()`, when a matching ACL entry is found, the function calls `posix_acl_release(posix_acls)` and jumps to `check_access_bits`. However, if the loop completes without finding a match (falls through to line 1842), and `posix_acls` is not NULL, `posix_acl_release()` is correctly called. BUT if the function reaches the `found == 0` branch and `others_ace` is also NULL (line 1851), it returns `-EACCES` via `goto err_out` -- at this point `pntsd` is freed but the reference-counted `posix_acls` has already been released. The issue is that in the path through the POSIX ACL check where `id == uid` is matched, the code correctly releases and goes to `check_access_bits`, but the `access_bits` variable is set from the POSIX permissions rather than from the Windows ACE, and the subsequent comparison at `check_access_bits` still references `ace->access_req` which may be an uninitialized or stale pointer if `found == 0`.

**Impact:** Potential use of stale `ace` pointer at `check_access_bits` label when access was determined via POSIX ACL rather than Windows ACE, potentially leaking or misinterpreting access control decisions.

**Recommendation:** At the `check_access_bits` label, only reference `ace->access_req` when `found == 1`. When access was determined by POSIX ACL, use only `access_bits` for the comparison.

---

## Medium Findings (P2)

### P2-01: BranchCache Server Secret Never Rotated

**File:** `src/fs/ksmbd_branchcache.c`
**Category:** Information Disclosure (Category 9)

**Description:**
The BranchCache server secret (`Ks`) is generated once via `get_random_bytes()` during module initialization and is never rotated for the lifetime of the module. The secret is used as the HMAC key for computing segment secrets. If the secret is compromised (e.g., via a memory disclosure vulnerability), all past and future segment secrets can be derived.

Additionally, the server secret is stored in a module-global variable that persists across server restarts (as long as the module remains loaded).

**Impact:** Long-term exposure of the BranchCache keying material. Segment secrets are not security-critical for file access control, but a compromised `Ks` would allow forging content information responses.

**Recommendation:** Implement periodic key rotation (e.g., on each server restart or at a configurable interval). Clear the secret on module unload. Consider using a per-share secret.

---

### P2-02: `ksmbd_vfs_copy_xattrs()` Copies All `user.*` Xattrs Without Filtering

**File:** `src/fs/vfs.c`, `ksmbd_vfs_copy_xattrs()`
**Category:** Permission Bypass (Category 4)

**Description:**
During Apple COPYFILE operations (under `CONFIG_KSMBD_FRUIT`), `ksmbd_vfs_copy_xattrs()` copies ALL `user.*` namespace xattrs from source to destination. This includes potentially sensitive xattrs set by other applications:
- `user.DOSATTRIB` (DOS attributes)
- Any application-specific user xattrs

There is no check whether the SMB client has permission to read the source xattrs or write to the destination xattrs beyond the tree-level write check. This could allow an SMB client to copy security-relevant metadata between files.

**Impact:** Unintended metadata propagation during server-side copy on Fruit-enabled shares.

**Recommendation:** Filter copied xattrs to only include known-safe Fruit-related xattrs (e.g., `com.apple.metadata:*`, `com.apple.FinderInfo`).

---

### P2-03: `ksmbd_vfs_set_fadvise()` Modifies `f_flags` and `f_ra` Without Full Locking

**File:** `src/fs/vfs.c`, lines 2853-2874
**Category:** Race Condition (Category 2)

**Description:**
The function modifies `filp->f_flags` (adding `O_SYNC`) without any lock, and modifies `f_ra.ra_pages` without locking. While `f_mode` modifications are correctly protected by `filp->f_lock`, the `f_flags` and `f_ra` modifications are not. Concurrent access from multiple SMB operations on the same file handle could lead to inconsistent state.

```c
if (option & FILE_WRITE_THROUGH_LE) {
    filp->f_flags |= O_SYNC;  // No lock
} else if (option & FILE_SEQUENTIAL_ONLY_LE) {
    filp->f_ra.ra_pages = inode_to_bdi(mapping->host)->ra_pages * 2;  // No lock
```

**Impact:** Data integrity issues if `O_SYNC` is partially applied, or inconsistent readahead behavior. Low practical severity since these are typically set once per open.

**Recommendation:** Protect `f_flags` modification with `filp->f_lock` as well.

---

### P2-04: `fsctl_copychunk_common()` (in ksmbd_fsctl.c) Missing `if/else if` Chain in Error Mapping

**File:** `src/fs/ksmbd_fsctl.c`, lines 1044-1061
**Category:** Kernel Memory Corruption (Category 7) -- indirect via incorrect error handling

**Description:**
In the original `fsctl_copychunk_common()` (the one in ksmbd_fsctl.c, not the one in ksmbd_fsctl_extra.c), the error mapping after `ksmbd_vfs_copy_file_ranges()` uses `if` for `-EACCES` and then `if` again for `-EAGAIN`, rather than `else if`:

```c
if (ret == -EACCES)
    rsp->hdr.Status = STATUS_ACCESS_DENIED;
if (ret == -EAGAIN)   // Should be "else if"
    rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;
else if (ret == -EBADF)
```

This means if `ret == -EACCES`, the code falls through to `if (ret == -EAGAIN)` which is false, then into `else if (ret == -EBADF)` which is also false, ultimately hitting the final `else` clause that sets `STATUS_UNEXPECTED_IO_ERROR`. The result is that `-EACCES` errors are incorrectly reported as `STATUS_UNEXPECTED_IO_ERROR` to the client.

**Impact:** Incorrect error propagation to SMB clients for access denied scenarios in server-side copy. This could mask the true error and confuse client-side error handling.

**Recommendation:** Change the second `if` to `else if` to create a proper chain.

---

### P2-05: Durable Scavenger Could Race With `ksmbd_reopen_durable_fd()`

**File:** `src/fs/vfs_cache.c`
**Category:** Race Condition (Category 2)

**Description:**
The durable handle scavenger thread checks `fp->durable_scavenger_timeout` and closes expired handles. Concurrently, `ksmbd_reopen_durable_fd()` clears the scavenger timeout to prevent expiry during reclaim. The race window exists between the scavenger reading the timeout value and `ksmbd_reopen_durable_fd()` clearing it. While the code uses `ft->lock` for some synchronization, the timeout check and the close decision span multiple lock acquisitions.

**Impact:** A durable handle could be closed by the scavenger just as a client attempts to reconnect, causing the reconnect to fail unnecessarily.

**Recommendation:** Use an atomic flag or a single lock acquisition that spans both the timeout check and the decision to close, coordinated with `ksmbd_reopen_durable_fd()`.

---

### P2-06: `ksmbd_vss_scan_snap_dir()` Uses `LOOKUP_FOLLOW` for Snapshot Directory

**File:** `src/fs/ksmbd_vss.c`, line 324-326
**Category:** Symlink Attack (Category 5)

**Description:**
The `kern_path()` call in `ksmbd_vss_scan_snap_dir()` uses `LOOKUP_FOLLOW | LOOKUP_DIRECTORY`. The `LOOKUP_FOLLOW` flag means that if `.snapshots/` or `.zfs/snapshot/` is a symlink, it will be followed. An attacker with write access to the share could replace the snapshot directory with a symlink to an arbitrary directory, causing the VSS enumeration to scan and expose files outside the share boundary.

**Impact:** Information disclosure of directory listings outside the share boundary via crafted symlink at the expected snapshot directory location.

**Recommendation:** Use `LOOKUP_NO_SYMLINKS | LOOKUP_DIRECTORY` to prevent symlink following.

---

### P2-07: `ksmbd_quota_query()` SID-to-UID Mapping Only Uses Last Sub-Authority

**File:** `src/fs/ksmbd_quota.c`, `ksmbd_sid_to_uid()`
**Category:** Permission Bypass (Category 4)

**Description:**
The SID-to-UID mapping function extracts only the last sub-authority from the SID to use as the UID. In multi-domain environments, different SIDs can share the same RID (last sub-authority) while referring to different users. This means quota queries could return quota information for the wrong user.

```c
/* Only the RID (last sub_auth) is used as the uid */
```

**Impact:** In multi-domain environments, quota information could be returned for an incorrect user, potentially leaking resource usage data or allowing quota manipulation.

**Recommendation:** Document this as a known limitation for multi-domain deployments. Consider implementing full SID-to-UID resolution via the userspace daemon (ksmbd.mountd) for more accurate mapping.

---

### P2-08: Resilient Handle Timeout Not Validated Against Minimum

**File:** `src/fs/ksmbd_resilient.c`, lines 93-94
**Category:** Resource Exhaustion (Category 6)

**Description:**
The resilient handle timeout is capped at `KSMBD_MAX_RESILIENT_TIMEOUT_MS` (5 minutes) but there is no minimum validation. A client could request a timeout of 0 milliseconds, making the resilient handle effectively non-resilient (immediately eligible for scavenging). More concerning, there is no limit on the total number of resilient handles a single connection can request.

**Impact:** A malicious client could create many resilient handles with the maximum timeout, consuming server-side file descriptor resources that are held open even after the connection drops.

**Recommendation:** Add a per-connection limit on resilient handles and validate a minimum timeout value.

---

## Low / Informational Findings (P3)

### P3-01: `ksmbd_reparse_replace_with_symlink()` Post-Creation Symlink Validation Race

**File:** `src/fs/ksmbd_reparse.c`, lines 351-369
**Category:** Race Condition (Category 2)

**Description:**
After creating a symlink, the code validates the result with `path_is_under()`. If the check fails, it removes the symlink. However, in the brief window between `vfs_symlink()` and the `path_is_under()` check, another SMB request could access the symlink. The parent inode lock IS held during this window, which mitigates the race for most VFS operations, but `readlink()` and `stat()` operations may not require the parent lock.

**Severity:** Low. The parent directory inode lock provides substantial mitigation.

**Recommendation:** Acceptable risk given the defense-in-depth approach. The pre-creation `ksmbd_is_safe_reparse_target()` check is the primary defense.

---

### P3-02: `ksmbd_notify_cleanup_file()` Accesses Work Items After List Removal

**File:** `src/fs/ksmbd_notify.c`, lines 521-591
**Category:** Race Condition (Category 2)

**Description:**
The function collects CHANGE_NOTIFY work items into a local list under `fp->f_lock`, then processes them without any lock. While this is intentional (to avoid doing I/O under spinlock), there is a narrow window where a concurrent cancel operation could also try to process the same work item. The `watch->completed` flag with spinlock protection mitigates this.

**Severity:** Low. The completed flag provides adequate synchronization.

---

### P3-03: `ksmbd_is_safe_reparse_target()` Does Not Check for Encoded Characters

**File:** `src/fs/ksmbd_reparse.c`, `ksmbd_is_safe_reparse_target()`
**Category:** Path Traversal (Category 1)

**Description:**
The function checks for `..`, `.`, `\`, and absolute paths, but does not check for percent-encoded or Unicode-encoded path components that might decode to these values at a later stage. Since the string is already UTF-8 at this point (converted from UTF-16LE), and the Linux VFS does not perform further decoding, this is informational.

**Severity:** Low. The VFS layer treats the string literally.

---

### P3-04: `inode_hash` Uses Dentry Pointer as Hash Input

**File:** `src/fs/vfs_cache.c`
**Category:** VFS API Misuse (Category 10)

**Description:**
The inode hash function uses the dentry pointer value as input to the hash. Since dentries can be released and reallocated (and thus the same dentry pointer could refer to different files over time), this could theoretically lead to hash collisions or stale entries. However, the hash table is only used while active references exist, and the double-check pattern in `ksmbd_inode_get()` prevents stale entries from being used.

**Severity:** Low. The implementation is correct in practice due to the reference counting and double-check pattern.

---

### P3-05: `ksmbd_create_ctx.c` Does Not Validate Tag Uniqueness on Registration

**File:** `src/fs/ksmbd_create_ctx.c`, `ksmbd_register_create_context()`
**Category:** VFS API Misuse (Category 10) -- architectural

**Description:**
The create context registration function does not check for duplicate tag registrations. If two handlers are registered for the same tag, `ksmbd_find_create_context()` will return the first match in list order. This is not a vulnerability per se but could lead to unexpected behavior if modules register conflicting handlers.

**Severity:** Low. All registrations are from trusted kernel code.

---

### P3-06: `ksmbd_vfs_make_xattr_posix_acl()` May Leak `smb_acl` on Unknown ACE Tag

**File:** `src/fs/vfs.c`, lines 2577-2579
**Category:** Resource Exhaustion (Category 6)

**Description:**
When an unknown ACE tag is encountered in the POSIX ACL, the function logs an error and jumps to `out:`. At `out:`, `posix_acl_release()` is called, but `smb_acl` is returned as non-NULL despite being partially filled. However, examining the code more carefully, the jump to `out` does NOT set `smb_acl = NULL`, so a partially-filled `smb_acl` is returned to the caller. The caller (`ksmbd_vfs_set_sd_xattr`) will then encode this partial data into the xattr.

**Severity:** Low. Unknown ACE tags in POSIX ACLs are extremely rare in practice.

**Recommendation:** Set `smb_acl = NULL` (after kfree) in the unknown tag error path, or restructure to return NULL on failure.

---

### P3-07: `ksmbd_rsvd.c` Tunnel Operations Are All Stub Implementations

**File:** `src/fs/ksmbd_rsvd.c`
**Category:** Information Disclosure (Category 9) -- architecture

**Description:**
All RSVD tunnel operations return stub/default responses. The `rsvd_handle_get_disk_info()` returns hardcoded disk geometry (32 MB block size, dynamic VHDX format), and `rsvd_handle_get_initial_info()` advertises RSVD version 2 support. This could mislead Hyper-V clients into attempting operations that will subsequently fail.

**Severity:** Low. The stub nature is documented and appropriate for an initial implementation.

**Recommendation:** Consider returning `STATUS_NOT_SUPPORTED` for the entire RSVD subsystem if full VHDX management is not planned, rather than advertising partial support.

---

## Positive Observations

### Defense-in-Depth Path Traversal Prevention (STRONG)

The codebase implements multiple independent layers of path traversal prevention:

1. **`LOOKUP_BENEATH` flag** on `vfs_path_lookup()` calls (kernel 5.6+, mandatory for 6.4+)
2. **`LOOKUP_NO_SYMLINKS` flag** on file creation paths (`ksmbd_vfs_create`, `ksmbd_vfs_mkdir`)
3. **Post-open `ksmbd_vfs_path_is_within_share()`** using `path_is_under()` as a defense-in-depth check
4. **`ksmbd_is_safe_reparse_target()`** for symlink/reparse point validation
5. **`is_subdir()`** check in `ksmbd_vfs_resolve_fileid()` for file ID resolution

This multi-layer approach means that even if one check is bypassed, subsequent checks provide protection.

### Thorough Integer Overflow Protection in ACL Code (STRONG)

The `smbacl.c` file consistently uses `check_add_overflow()` and `check_mul_overflow()` from `<linux/overflow.h>` for every size computation involving untrusted inputs:
- `ksmbd_ace_size()` validates ACE size computation
- `parse_dacl()` validates ACE count against buffer capacity
- `build_sec_desc()` validates every ACE insertion
- `ksmbd_vfs_make_xattr_posix_acl()` validates allocation size
- `smb_copy_sid()` clamps `num_subauth` to `SID_MAX_SUB_AUTHORITIES`

### Correct RCU Usage in Dispatch Tables (GOOD)

The FSCTL, info-level, and create context dispatch tables all use RCU-protected data structures with correct patterns:
- Registration under spinlock with `list_add_tail_rcu()` / `hash_add_rcu()`
- Lookup under `rcu_read_lock()` with `try_module_get()` for lifetime management
- Unregistration with `synchronize_rcu()` after removal

### Proper Reference Counting in Oplock/Lease Code (GOOD)

The oplock subsystem uses `refcount_t` (not plain `atomic_t`) for opinfo reference counting:
- `opinfo_get()` uses `refcount_inc_not_zero()` to safely take references
- `opinfo_put()` properly decrements and frees when zero
- RCU is used for lease table traversal
- `wait_for_break_ack()` uses uninterruptible wait to avoid signal-related races

### Comprehensive FSCTL Input Validation (GOOD)

Every FSCTL handler validates:
1. Input buffer length against the expected structure size
2. Output buffer capacity before writing responses
3. Tree connection writability for mutation operations
4. File handle existence via `ksmbd_lookup_fd_fast()` with proper `ksmbd_fd_put()` on all paths

### Reparse Point TOCTOU Mitigation (GOOD)

`ksmbd_reparse_replace_with_symlink()` holds the parent directory inode lock (`inode_lock_nested(dir_inode, I_MUTEX_PARENT)`) across both the unlink and symlink creation operations, effectively preventing TOCTOU races where an attacker could place a malicious entry between the two operations.

### Resource Exhaustion Limits (GOOD)

Appropriate limits are in place:
- `KSMBD_MAX_NOTIFY_WATCHES` (512 global) and `KSMBD_MAX_NOTIFY_WATCHES_PER_CONN` (1024)
- `KSMBD_VSS_MAX_SNAPSHOTS` (256)
- `KSMBD_MAX_RESILIENT_TIMEOUT_MS` (5 minutes)
- Server-side copy chunk count/size limits via `ksmbd_server_side_copy_max_*`

### Proper Kernel Version Compatibility (GOOD)

The codebase maintains compatibility across kernel versions 5.x through 6.19+ using well-structured `#if LINUX_VERSION_CODE` conditionals. The idmap/mnt_idmap transitions are handled correctly at each version boundary.
