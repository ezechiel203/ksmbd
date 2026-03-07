# Security Code Review: SMB2 File Operations (Create, Read/Write, IOCTL, Lock, Fruit)

**Date**: 2026-02-28
**Reviewer**: Claude Opus 4.6 (automated security review)
**Branch**: phase1-security-hardening
**Scope**: smb2_create.c, smb2_read_write.c, smb2_ioctl.c, smb2_lock.c, smb2fruit.c

---

## Executive Summary

This review covers the core SMB2 file operation handlers in the ksmbd kernel module: file open/create, read/write, IOCTL dispatch, byte-range locking, and Apple Fruit extensions. These files collectively represent the most attack-surface-dense components of the server, as they directly process untrusted network PDU fields and translate them into kernel VFS operations.

The codebase shows evidence of significant prior security hardening work: bounds checks on PDU offsets and lengths are present in many paths, RDMA channel info validation has been added, lock counts are capped, compound request offsets are handled, TOCTOU path validation is performed after open, and durable handle reconnections validate client GUIDs. Several areas of the code demonstrate careful attention to integer overflow prevention.

However, the review identified several remaining issues ranging from potential out-of-bounds reads in the RDMA write path to integer truncation in IOCTL copychunk responses, lock ordering concerns, and a missing response buffer overflow guard in create context building.

**Critical Findings**: 1
**High Findings**: 5
**Medium Findings**: 9
**Low Findings**: 7

---

## Critical Findings

### Finding 1: Unvalidated WriteChannelInfoOffset in smb2_write_rdma_channel
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_read_write.c:508-511
- **Severity**: Critical
- **Description**: The `smb2_write_rdma_channel()` function computes a pointer using `req->WriteChannelInfoOffset` without performing any bounds validation. While the caller `smb2_write()` validates these offsets in the `is_rdma_channel == true` block (lines 566-583), the `smb2_write_rdma_channel()` function re-reads `req->WriteChannelInfoOffset` directly at line 510, deriving a pointer from it. If `smb2_write_rdma_channel` were ever called from a path that bypasses the earlier validation, or if the request buffer were modified concurrently, the offset would be used unchecked. More critically, the function passes the resulting pointer directly to `ksmbd_conn_rdma_read()` which will dereference the `smb2_buffer_desc_v1` structure at that address, potentially reading token/length values from outside the request buffer. The same pattern exists in `smb2_read_rdma_channel()` at line 172.
- **Impact**: An attacker on an RDMA-capable network could craft an SMB2 WRITE request with a malicious `WriteChannelInfoOffset` that causes out-of-bounds memory reads in kernel space. This could lead to information disclosure (leaking kernel memory contents as RDMA token/length values) or kernel crash if the pointer lands on an unmapped page.
- **Fix**: Move the offset validation into `smb2_write_rdma_channel()` and `smb2_read_rdma_channel()` themselves, or pass pre-validated descriptor pointers rather than having these functions re-derive pointers from raw PDU fields. For defense-in-depth, both functions should validate that the computed pointer falls within the request buffer before dereferencing it.

---

## High Findings

### Finding 2: Response Buffer Overflow in Create Context Building
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c:1984-2107
- **Severity**: High
- **Description**: The `smb2_open()` function builds multiple create context response entries (lease, mxac, disk_id, durable, posix, fruit) by writing them sequentially into `rsp->Buffer`. Each context is written at `rsp->Buffer + le32_to_cpu(rsp->CreateContextsLength)`, and `iov_len` is incremented accordingly. However, there is no check that the accumulated `iov_len` or `CreateContextsLength` remains within the bounds of the response buffer. The response buffer size is fixed (typically 65536 bytes or `work->response_sz`), and the total size of all contexts concatenated could theoretically exceed available space, especially with the variable-length fruit response (which includes a model string converted to UTF-16). If a client negotiates all optional contexts simultaneously (lease + mxac + disk_id + durable_v2 + posix + fruit), the aggregate could approach or exceed the response buffer boundary.
- **Impact**: Kernel heap buffer overflow when writing create context response data past the end of the response buffer. This could lead to heap corruption and potential code execution.
- **Fix**: Before writing each create context, check that `iov_len + context_size <= work->response_sz - sizeof(struct smb2_hdr)`. Add bounds validation on the total accumulated `CreateContextsLength` before each context write.

### Finding 3: Integer Truncation in copychunk TotalBytesWritten
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_ioctl.c:75, 107, 180
- **Severity**: High
- **Description**: In `fsctl_copychunk()`, `total_size_written` is declared as `loff_t` (64-bit signed), but it is truncated to 32 bits when written to the response at line 180 via `cpu_to_le32(total_size_written)`. The maximum total copy size is controlled by `ksmbd_server_side_copy_max_total_size()`, but if this value is configured to be larger than 4GB (UINT32_MAX), the truncation would silently discard the upper 32 bits. Additionally, line 175 casts `total_size_written - preceding` to `unsigned int`, which truncates 64-bit results. While the current maximum defaults likely prevent this, a misconfiguration or future change could trigger it.
- **Impact**: Incorrect response values sent to clients. In certain configurations, this could cause the client to believe more or fewer bytes were copied than actually were, potentially leading to data corruption or inconsistent file state.
- **Fix**: Add an explicit check that `total_size_written <= UINT32_MAX` before writing to the response. Consider using `safe_narrowing` macros or `min_t` to make the truncation explicit.

### Finding 4: Lock Ordering Violation in smb2_lock - Nested Spinlocks Across Connection Hash
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_lock.c:487-576
- **Severity**: High
- **Description**: The `smb2_lock()` function iterates through all connections in `conn_hash[]` while holding nested spinlocks: first `conn_hash[bkt].lock`, then `conn->llist_lock`. The iteration walks all hash buckets sequentially (lines 487-576), acquiring and releasing locks for each bucket. This creates multiple potential issues: (a) If a connection is being torn down concurrently, the `conn` pointer obtained under `conn_hash[bkt].lock` could become stale after the lock is released at line 518-519 (when jumping to `out_check_cl` after an unlock match). (b) The ordering `conn_hash[bkt].lock -> conn->llist_lock` must be consistently maintained everywhere in the codebase, or deadlock will occur. (c) Holding these locks while iterating all connections creates significant lock contention under load, as every lock request from any client blocks all others.
- **Impact**: Potential deadlock under concurrent lock/unlock operations from multiple connections. Under high load, significant performance degradation due to global lock contention. Possible use-after-free if connection teardown races with the lock iteration.
- **Fix**: Consider using RCU for the connection hash iteration to avoid holding spinlocks during the traversal. The `cmp_lock` deletion at lines 516-522 should be deferred or handled with proper reference counting. Alternatively, collect matching locks into a local list under the lock, release the lock, then process the matches.

### Finding 5: Missing Validation of lock_ele Array Bounds Against Request Buffer
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_lock.c:383-384, 393-394
- **Severity**: High
- **Description**: In `smb2_lock()`, `lock_ele` is set to `req->locks` at line 384, and then `lock_ele[i]` is accessed in the loop at line 393 for `i` from 0 to `lock_count - 1`. While `lock_count` is capped at `KSMBD_MAX_LOCK_COUNT` (64), and the PDU validation in `smb2misc.c:175-188` checks that the lock elements fit within the request, this validation happens in a separate phase before `smb2_lock()` is called. If the request buffer size is less than `offsetof(struct smb2_lock_req, locks) + lock_count * sizeof(struct smb2_lock_element)`, accessing `lock_ele[i]` would read past the end of the request buffer. The function relies entirely on the earlier validation in smb2misc.c and does not re-validate locally.
- **Impact**: If the earlier validation is bypassed (e.g., through a code refactoring that changes the validation path, or through compound request handling where offsets are recalculated), out-of-bounds reads from the request buffer could leak kernel memory contents.
- **Fix**: Add a local bounds check in `smb2_lock()` to verify that `lock_count * sizeof(struct smb2_lock_element)` fits within the remaining request buffer after the locks field offset.

### Finding 6: Time Machine Quota Integer Underflow
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2fruit.c:550
- **Severity**: High
- **Description**: In `ksmbd_fruit_check_tm_quota()`, the used bytes calculation is `(u64)(stfs.f_blocks - stfs.f_bfree) * stfs.f_bsize`. If the filesystem reports `f_bfree > f_blocks` (which can happen with certain filesystem implementations, snapshot-aware filesystems, or after filesystem corruption), the subtraction `stfs.f_blocks - stfs.f_bfree` underflows. Since `stfs.f_blocks` and `stfs.f_bfree` are both `u64`, the underflow produces a very large positive value, which is then multiplied by `stfs.f_bsize`, potentially wrapping around. This could cause the quota check to either falsely deny writes (if the result is very large) or falsely allow them (if the multiplication wraps to a small value).
- **Impact**: Incorrect Time Machine quota enforcement. Could either block all writes to a TM share (denial of service) or allow unlimited writes bypassing the configured quota (data integrity risk on the backup volume).
- **Fix**: Add a check `if (stfs.f_bfree > stfs.f_blocks) return 0;` to handle the anomalous case gracefully. Alternatively, use signed arithmetic with overflow checking.

---

## Medium Findings

### Finding 7: FSCTL_COPYCHUNK Return Value Not Checked in smb2_ioctl
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_ioctl.c:554-561
- **Severity**: Medium
- **Description**: In the `smb2_ioctl()` FSCTL_COPYCHUNK/FSCTL_COPYCHUNK_WRITE case, `fsctl_copychunk()` is called at line 554 but its return value is discarded. The function sets `rsp->hdr.Status` internally on error but the caller does not check the return code. This means the ioctl response will be sent with whatever status was set internally, but the `ret` variable in `smb2_ioctl()` remains 0, causing the code to proceed to the `done:` label and send a response that may contain a mix of error status and success-path fields.
- **Impact**: Clients may receive malformed or misleading IOCTL responses after a copychunk failure, potentially causing client-side confusion or data loss if the client believes a partial copy succeeded.
- **Fix**: Capture the return value from `fsctl_copychunk()` and handle it appropriately: `ret = fsctl_copychunk(...); if (ret < 0) goto out;`

### Finding 8: smb2_read RDMA Channel Info Offset Off-by-One Style Check
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_read_write.c:237-238
- **Severity**: Medium
- **Description**: In the RDMA channel validation for `smb2_read()`, `req_len` is computed as `get_rfc1002_len(work->request_buf) + 4`. The check `ch_offset > req_len` at line 240 allows `ch_offset == req_len`, which would point exactly one byte past the end of the request buffer. While `ch_len > req_len - ch_offset` at line 241 would catch a nonzero-length read past the end, a zero-length channel info at the exact boundary is still invalid and could cause issues in downstream processing.
- **Impact**: Edge case where a zero-length RDMA channel descriptor pointing at the buffer boundary passes validation but would fail in `smb2_set_remote_key_for_rdma()` with a different error. Minor robustness issue.
- **Fix**: Change the check to `ch_offset >= req_len` to reject offsets at or past the buffer boundary.

### Finding 9: Fruit Create Context Data Pointer Computed from Unchecked DataOffset
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c:1865-1866
- **Severity**: Medium
- **Description**: In the AAPL/Fruit create context processing in `smb2_open()`, the `context_data` pointer is computed as `(const __u8 *)context + le16_to_cpu(context->DataOffset)`. While `fruit_validate_create_context()` checks that `DataLength` is within expected bounds, it does not validate that `DataOffset` points within the request buffer. The `smb2_find_context_vals()` function validates create contexts at a structural level, but `DataOffset` is a relative offset within the context structure, and a malicious value could point outside the valid request buffer.
- **Impact**: Out-of-bounds read when copying `fruit_client_info` from `context_data`. The `memcpy` at line 1885 copies `copy_len` bytes from `context_data` which could be an invalid pointer, leading to kernel information disclosure or crash.
- **Fix**: Add explicit validation that `context_data` falls within the request buffer bounds, e.g., verify that `(char *)context + le16_to_cpu(context->DataOffset) + copy_len` does not exceed the request buffer end.

### Finding 10: smb2_set_ea Loop Trusts NextEntryOffset Chain Without Cross-Referencing Buffer
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c:243-330
- **Severity**: Medium
- **Description**: The `smb2_set_ea()` function iterates through a chain of `smb2_ea_info` entries using `NextEntryOffset`. While there are checks that `buf_len < next` and that each entry's name+value fits in `buf_len`, the function does not verify that `NextEntryOffset` is properly aligned (EA entries should be aligned to 4-byte boundaries per MS-SMB2). Additionally, a circular chain (where `NextEntryOffset` points back to a previous entry) would cause an infinite loop. The `buf_len -= next` subtraction at line 318 prevents infinite looping in practice since `buf_len` would eventually reach zero, but a large circular offset could still cause many iterations before termination.
- **Impact**: Potential infinite loop or excessive CPU consumption from a crafted EA buffer with circular or near-circular NextEntryOffset values, causing denial of service.
- **Fix**: Add alignment verification for `NextEntryOffset` (must be multiple of 4). Consider tracking the minimum expected position to detect backward references.

### Finding 11: Compound Request Write Data Validation May Underflow
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_read_write.c:649-651
- **Severity**: Medium
- **Description**: In `smb2_write()`, the request buffer length for compound requests is computed as `req_buf_len = get_rfc1002_len(work->request_buf); if (work->next_smb2_rcv_hdr_off) req_buf_len -= work->next_smb2_rcv_hdr_off;`. If `work->next_smb2_rcv_hdr_off` is larger than `req_buf_len` (which could happen with a malformed compound request), the subtraction would underflow the `unsigned int`, producing a very large value that would bypass the subsequent bounds check at line 653.
- **Impact**: Buffer over-read in a compound write request where the compound header offset exceeds the total request length, potentially leading to kernel memory disclosure or crash.
- **Fix**: Add a check: `if (work->next_smb2_rcv_hdr_off > req_buf_len) { err = -EINVAL; goto out; }` before the subtraction.

### Finding 12: smb2_cancel Accesses Work Item Without Reference Count
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_lock.c:86-109
- **Severity**: Medium
- **Description**: In `smb2_cancel()`, the function iterates through `conn->async_requests` under `conn->request_lock`, copies `cancel_fn` and `cancel_argv` from a matched work item, then releases the spinlock and calls `cancel_fn(cancel_argv)` outside the lock. While the work item's state is set to `KSMBD_WORK_CANCELLED` under the lock, there is no reference count increment on the work item itself. The `cancel_argv` pointer is then freed with `kfree(cancel_argv)` at line 109. If the work item completes and frees its own `cancel_argv` between the lock release and the `kfree()` call, this results in a double-free.
- **Impact**: Potential double-free of `cancel_argv` leading to kernel heap corruption, which could be exploitable for code execution.
- **Fix**: Clear `iter->cancel_fn` and `iter->cancel_argv` under the lock (which is already done at lines 102-103), and ensure the work item's completion path checks these fields under the same lock before freeing them. The current code appears to handle this correctly (setting to NULL before release), but add a comment documenting this invariant.

### Finding 13: FSCTL_SET_ZERO_DATA Missing Write Permission Check on File Handle
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_ioctl.c:604-611
- **Severity**: Medium
- **Description**: The `FSCTL_SET_ZERO_DATA` case checks `KSMBD_TREE_CONN_FLAG_WRITABLE` at line 580, but does not verify that the file handle (`fp->daccess`) has `FILE_WRITE_DATA` permission. A file opened with read-only access on a writable share could have zero data operations performed on it, bypassing the file-level access control.
- **Impact**: Unauthorized data modification: a user who opens a file with read-only access could zero out file regions through FSCTL_SET_ZERO_DATA, causing data loss.
- **Fix**: After obtaining `fp` at line 604, add a check: `if (!(fp->daccess & FILE_WRITE_DATA_LE)) { ret = -EACCES; ksmbd_fd_put(work, fp); goto out; }`

### Finding 14: FSCTL_DUPLICATE_EXTENTS_TO_FILE Missing Write Permission Check
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_ioctl.c:660-722
- **Severity**: Medium
- **Description**: The `FSCTL_DUPLICATE_EXTENTS_TO_FILE` handler does not check that the output file (`fp_out`) has write access (`FILE_WRITE_DATA`) or that the input file (`fp_in`) has read access (`FILE_READ_DATA`). It also does not check the tree connection writable flag. A client could use this to clone data between files without proper permissions.
- **Impact**: Unauthorized file data duplication. An attacker could read data from a file they shouldn't have access to by cloning it to a file they control, or write to a file by cloning data into it.
- **Fix**: Add permission checks: verify `fp_in->daccess & FILE_READ_DATA_LE` and `fp_out->daccess & FILE_WRITE_DATA_LE`, and add a `KSMBD_TREE_CONN_FLAG_WRITABLE` check.

### Finding 15: smb2_open Path Not Validated When posix_ctxt is True
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c:1052-1083
- **Severity**: Medium
- **Description**: When `posix_ctxt == true`, the code skips `ksmbd_validate_filename(name)` at line 1080. The POSIX context is set when the connection has POSIX extensions enabled, but this means filenames with potentially dangerous characters (like embedded null bytes or directory traversal sequences that would be caught by `ksmbd_validate_filename`) are allowed through without validation. The later TOCTOU check at line 1558 (`path_is_under`) provides some defense, and `ksmbd_vfs_kern_path` uses `LOOKUP_NO_SYMLINKS`, but the filename validation layer is bypassed entirely.
- **Impact**: Possible path traversal or use of invalid filenames on POSIX-enabled connections. The defense-in-depth layer of filename validation is missing.
- **Fix**: Apply `ksmbd_validate_filename()` regardless of POSIX context, or implement POSIX-specific validation that still prevents dangerous filename patterns.

---

## Low Findings

### Finding 16: create_smb2_pipe NameOffset Bounds Check Inconsistency
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c:148-153
- **Severity**: Low
- **Description**: In `create_smb2_pipe()`, the bounds check compares `(u64)NameOffset + NameLength > rfc1002_len + 4`, which correctly prevents reading past the end of the request. However, it does not validate that `NameOffset >= offsetof(struct smb2_create_req, Buffer)`, so a small `NameOffset` could point into the header fields. The subsequent `smb_strndup_from_utf16` at line 155 reads from `req->Buffer` (which uses the correct offset), not from `NameOffset`, so this is benign in practice.
- **Impact**: Minimal. The actual data read uses `req->Buffer` which is at the correct offset. The bounds check protects against buffer overrun.
- **Fix**: For consistency, verify `NameOffset >= offsetof(struct smb2_create_req, Buffer)` as is done in `smb2_open()`.

### Finding 17: smb2_write_pipe Data Offset Validation Lacks Lower Bound Check
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_read_write.c:449-456
- **Severity**: Low
- **Description**: In `smb2_write_pipe()`, the validation checks that `DataOffset + length <= rfc1002_len` but does not verify that `DataOffset >= offsetof(struct smb2_write_req, Buffer)`. A small `DataOffset` value could cause `data_buf` at line 458 to point into the SMB2 header fields rather than the actual write data. This would cause the wrong data to be written to the pipe.
- **Impact**: Incorrect data written to IPC pipe, which could confuse RPC processing. Exploitation is limited since the data still comes from within the request buffer.
- **Fix**: Add a minimum offset check: `if (le16_to_cpu(req->DataOffset) < offsetof(struct smb2_write_req, Buffer) - 4) { err = -EINVAL; goto out; }`

### Finding 18: smb2_flush Does Not Validate File Handle Before fsync
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_read_write.c:730-756
- **Severity**: Low
- **Description**: `smb2_flush()` passes `req->VolatileFileId` and `req->PersistentFileId` directly to `ksmbd_vfs_fsync()` without first looking up and validating the file handle. While `ksmbd_vfs_fsync()` likely performs its own lookup, the error handling in `smb2_flush()` always returns `STATUS_INVALID_HANDLE` on any error, obscuring the actual failure reason.
- **Impact**: Poor error reporting. If the file handle is invalid, the error is still caught, but the specific error type is lost.
- **Fix**: Look up the file handle explicitly with `ksmbd_lookup_fd_slow()` before calling `ksmbd_vfs_fsync()` to provide accurate error reporting.

### Finding 19: smb2_lock Potential Stale flock After Retry Loop
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_lock.c:589-665
- **Severity**: Low
- **Description**: In the lock processing loop, when a `FILE_LOCK_DEFERRED` result triggers the wait/retry path (lines 609-665), the `flock` pointer is set to `smb_lock->fl` at line 589 and remains the same after the retry at line 665. If the wait is cancelled (line 647) and `work->state != KSMBD_WORK_ACTIVE`, the flock is freed at line 645. However, in the normal retry case (line 665: `goto retry`), the same flock is reused, which is correct. The concern is that `release_async_work(work)` at line 664 might interact with the flock state in unexpected ways.
- **Impact**: Unlikely in current code but represents a fragile state management pattern that could break with future modifications.
- **Fix**: Add a comment documenting the flock lifecycle through the retry path, and assert that `smb_lock->fl` is still valid before `goto retry`.

### Finding 20: Information Disclosure via Debug Log Messages
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c:1050
- **Severity**: Low
- **Description**: At line 1050, `ksmbd_debug(SMB, "converted name = %s\n", name)` logs the full file path being opened. Similar debug messages exist throughout the reviewed files. While these are gated behind debug flags, if debug logging is inadvertently enabled in production, full file paths, file handles, session IDs, and other sensitive information are written to the kernel log, which may be accessible to local unprivileged users via `dmesg`.
- **Impact**: Local information disclosure of file paths and SMB session metadata when debug logging is enabled.
- **Fix**: Consider using rate-limited debug logging for sensitive fields, or hash/redact file paths in debug output. Ensure debug logging is disabled by default and document the security implications of enabling it.

### Finding 21: fruit_synthesize_afpinfo Buffer Layout Assumes Fixed Sizes
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2fruit.c:381-421
- **Severity**: Low
- **Description**: `fruit_synthesize_afpinfo()` reads up to `AFP_FINDER_INFO_SIZE` (32) bytes from the xattr into `buf + 16`, then builds the AfpInfo header around it. The `memset(buf, 0, 16)` at line 400 clears the header, and `memset(buf + 48, 0, 12)` clears the trailer. If `AFP_AFPINFO_SIZE` (60) is ever changed without updating the hardcoded offsets (16, 48, 12), the buffer layout would be incorrect. The function correctly validates `bufsize < AFP_AFPINFO_SIZE` at line 374, but the internal offsets are magic numbers.
- **Impact**: Maintenance risk. No immediate vulnerability, but fragile code that could introduce bugs on modification.
- **Fix**: Define named constants for the internal offsets (e.g., `AFP_HEADER_SIZE = 16`, `AFP_TRAILER_OFFSET = 48`, `AFP_TRAILER_SIZE = 12`) and use static_assert to verify `AFP_HEADER_SIZE + AFP_FINDER_INFO_SIZE + AFP_TRAILER_SIZE == AFP_AFPINFO_SIZE`.

### Finding 22: smb2_read Does Not Check FILE_READ_DATA Specifically
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_read_write.c:260-264
- **Severity**: Low
- **Description**: The read permission check at line 260 allows reading if either `FILE_READ_DATA_LE` or `FILE_READ_ATTRIBUTES_LE` is set. `FILE_READ_ATTRIBUTES_LE` typically grants access only to file metadata (timestamps, size, etc.), not to file content. Allowing a full file read when only `FILE_READ_ATTRIBUTES_LE` was granted expands the access beyond what the client was permitted.
- **Impact**: A file opened with only attribute-read permission could have its full contents read, bypassing intended access restrictions.
- **Fix**: Change the check to require `FILE_READ_DATA_LE` specifically for content reads: `if (!(fp->daccess & FILE_READ_DATA_LE))`. Keep `FILE_READ_ATTRIBUTES_LE` for attribute-only operations.

---

## Positive Observations

1. **RDMA Channel Info Validation**: The `smb2_read()` and `smb2_write()` functions include explicit validation of RDMA channel info offsets and lengths against the request buffer (lines 234-244 and 565-583 respectively). This prevents most out-of-bounds accesses in the RDMA path.

2. **TOCTOU Path Validation**: `smb2_open()` at line 1558 performs a post-open `path_is_under()` check to verify that the opened file is within the share root, mitigating path traversal attacks that might bypass the pre-open filename validation.

3. **Symlink Rejection**: The `LOOKUP_NO_SYMLINKS` flag is used in `ksmbd_vfs_kern_path()` at line 1317, and explicit symlink checking at line 1347 prevents symlink-based path traversal.

4. **Lock Count Cap**: `KSMBD_MAX_LOCK_COUNT` (64) caps the number of lock elements per request, preventing memory exhaustion from a single lock request with millions of entries.

5. **Durable Handle Client GUID Validation**: The `parse_durable_handle_context()` function validates the client GUID on durable reconnections (lines 681-687, 723-729), preventing handle theft by a different client.

6. **Compound Request Awareness**: Both `smb2_read()` and `smb2_write()` properly handle compound request offsets, using `work->next_smb2_rcv_hdr_off` to compute sub-request boundaries.

7. **Input Buffer Validation in IOCTL**: The `smb2_ioctl()` function validates `InputOffset` and `InputCount` against the request buffer at lines 480-496 before using them, preventing out-of-bounds reads from crafted IOCTL requests.

8. **Lock Overflow Prevention**: In `smb2_lock()`, lines 406-411 check for integer overflow on `lock_start + lock_length` using `lock_start > U64_MAX - lock_length`, correctly preventing wrap-around in lock range computation.

9. **Fruit Create Context Size Cap**: The `FRUIT_CREATE_CTX_MAX_DATA_LEN` (4096) constant caps the size of Fruit create context data, preventing excessive memory allocation from crafted client requests.

10. **Error Path Cleanup**: The lock rollback mechanism in `smb2_lock()` (lines 704-734) properly converts acquired locks to unlocks and releases resources on error, preventing lock leaks.
