# Security Code Review: SMB2 Directory, Query/Set Info, Tree Connect, and Miscellaneous Commands

**Date**: 2026-02-28
**Reviewer**: Claude Opus 4.6 (Automated Security Review)
**Scope**: smb2_dir.c, smb2_query_set.c, smb2_tree.c, smb2_notify.c, smb2_misc_cmds.c, smb2pdu.h, smb2pdu_internal.h, smb_common.h, smb2fruit.h
**Branch**: phase1-security-hardening

---

## Executive Summary

This review examines the SMB2 directory enumeration, query/set info, tree connect/disconnect, change-notify, close, echo, and oplock-break handlers across nine source and header files. The codebase demonstrates significant security hardening effort -- buffer length checks, rate-limiting, per-connection resource limits, and input validation are present throughout. However, several issues remain that could lead to information disclosure, denial of service, or logic errors under adversarial conditions.

**Critical findings**: 1
**High findings**: 4
**Medium findings**: 8
**Low findings**: 6

---

## Critical

### Finding 1: FS_POSIX_INFORMATION Missing FileSysIdentifier Initialization -- Information Disclosure
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_query_set.c:1463-1477
- **Severity**: Critical
- **Description**: The `FS_POSIX_INFORMATION` handler in `smb2_get_info_filesystem()` fills `filesystem_posix_info` fields TotalBlocks through FreeFileNodes but never sets the `FileSysIdentifier` field (an 8-byte `__le64`). The struct is written directly into `rsp->Buffer` without any prior zeroing of that specific region. The `smb2_get_info_file()` function does `memset(rsp->Buffer, 0, min_t(unsigned int, max_resp, 1024))` before processing, but `smb2_get_info_filesystem()` does NOT zero the buffer before use. The `filesystem_posix_info` struct is 64 bytes and the hardcoded OutputBufferLength is 56, which excludes the trailing 8-byte `FileSysIdentifier` from being sent on the wire. However, this discrepancy between the struct size (64 bytes) and the declared output (56 bytes) is fragile -- any change to `rsp->OutputBufferLength` would leak 8 bytes of uninitialized kernel heap memory to the client.
- **Impact**: Kernel heap information disclosure. An attacker could receive 8 bytes of stale heap data, potentially leaking kernel pointers, credentials, or other sensitive information. The `FS_POSIX_INFORMATION_SIZE` constant is correctly defined as 56, but the struct itself is 64 bytes, creating a persistent mismatch risk.
- **Fix**: Zero the entire response buffer region before populating filesystem info responses. Add `memset(rsp->Buffer, 0, sizeof(struct filesystem_posix_info))` at the start of the FS_POSIX_INFORMATION case, or explicitly set `info->FileSysIdentifier = 0`. Better yet, add a blanket `memset(rsp->Buffer, 0, ...)` at the top of `smb2_get_info_filesystem()` similar to what `smb2_get_info_file()` does.

---

## High

### Finding 2: FS_OBJECT_ID_INFORMATION Partial version_string Initialization Leaks Heap Data
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_query_set.c:1418
- **Severity**: High
- **Description**: In the `FS_OBJECT_ID_INFORMATION` case, `info->extended_info.version_string` is a 28-byte buffer (`STRING_LENGTH`). The code copies only 5 bytes ("1.1.0") using `memcpy(info->extended_info.version_string, "1.1.0", strlen("1.1.0"))` which is 5 bytes. The remaining 23 bytes of `version_string` are never zeroed, and `rsp->Buffer` in `smb2_get_info_filesystem()` is NOT pre-zeroed. This means 23 bytes of potentially sensitive kernel heap data will be sent to the client.
- **Impact**: Information disclosure of up to 23 bytes of uninitialized kernel heap memory per query. Repeated queries could harvest significant heap layout information useful for exploiting other vulnerabilities.
- **Fix**: Use `strscpy(info->extended_info.version_string, "1.1.0", STRING_LENGTH)` which null-pads the remainder, or add `memset(&info->extended_info, 0, sizeof(info->extended_info))` before populating individual fields.

### Finding 3: notify response buffer lacks bounds check on UTF-16 conversion output
- **File**: /home/ezechiel203/ksmbd/src/fs/ksmbd_notify.c:160-162
- **Severity**: High
- **Description**: In `ksmbd_notify_build_response()`, the initial `name_bytes = file_name->len * 2` is used as a worst-case estimate for the UTF-16 conversion. This estimate is then used for the `info_len > output_buf_len` overflow check. However, the actual `smbConvertToUTF16()` call on line 186 converts into `info->FileName` without any buffer size limit parameter. The `smbConvertToUTF16` function takes a `maxlen` parameter that specifies the maximum input length, not a maximum output buffer size. If a multi-byte UTF-8 filename expands to more UTF-16 code units than expected (e.g., surrogate pairs), the estimate `len * 2` could undercount, though this is unlikely for standard characters. More importantly, the response buffer (`work->response_buf`) has a fixed allocation size and the code writes at offset `sizeof(struct smb2_notify_rsp) - 1 + sizeof(struct file_notify_information) + uni_len` without verifying this fits within the allocated response buffer.
- **Impact**: Potential heap buffer overflow if the UTF-16 conversion produces more bytes than `file_name->len * 2`. While unlikely with standard filenames, malicious filesystem labels or crafted filename entries could trigger this.
- **Fix**: After the `smbConvertToUTF16()` call, recompute `info_len` with the actual `uni_len` and re-check against both `output_buf_len` and the response buffer capacity before proceeding to `ksmbd_iov_pin_rsp`.

### Finding 4: smb2_get_info_filesystem() Does Not Pre-Zero Response Buffer
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_query_set.c:1274-1498
- **Severity**: High
- **Description**: Unlike `smb2_get_info_file()` which zeroes `rsp->Buffer` (line 1147: `memset(rsp->Buffer, 0, min_t(unsigned int, max_resp, 1024))`), the `smb2_get_info_filesystem()` function never zeroes the response buffer before populating it. Multiple filesystem info classes (FS_VOLUME_INFORMATION, FS_ATTRIBUTE_INFORMATION, FS_OBJECT_ID_INFORMATION, FS_POSIX_INFORMATION) write variable-length data and rely on the buffer being clean. For example, `FS_ATTRIBUTE_INFORMATION` writes `FileSystemName` via `smbConvertToUTF16` but the rest of any padding in the allocated buffer remains uninitialized. `FS_OBJECT_ID_INFORMATION` has the version_string leak documented in Finding 2.
- **Impact**: Systematic information disclosure across multiple filesystem info classes. Every FS_OBJECT_ID query leaks 23 bytes; other classes may leak smaller amounts depending on alignment padding.
- **Fix**: Add `memset(rsp->Buffer, 0, min_t(int, smb2_resp_buf_len(work, 8), 1024))` at the beginning of `smb2_get_info_filesystem()`, similar to how `smb2_get_info_file()` handles it.

### Finding 5: tree connect path validation uses potentially incorrect request length calculation
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_tree.c:120-124
- **Severity**: High
- **Description**: The path bounds check in `smb2_tree_connect()` validates: `(u64)le16_to_cpu(req->PathOffset) + le16_to_cpu(req->PathLength) > get_rfc1002_len(work->request_buf) + 4 - ((char *)req - (char *)work->request_buf)`. The subtraction `((char *)req - (char *)work->request_buf)` accounts for compound requests where `req` may point partway into the buffer. However, this subtraction is performed on unsigned values (`get_rfc1002_len` returns `unsigned int`) after the addition of 4. If `req` points far enough into the buffer (which shouldn't happen in normal operation but could in malformed compounds), the subtraction could underflow, making the right-hand side enormous and bypassing the check entirely. Additionally, for non-compound requests, `req` typically points to `work->request_buf + 4` (after the RFC1002 length), making the subtraction equal the SMB2 header offset, which is correct. But for compound requests with `work->next_smb2_rcv_hdr_off`, the `WORK_BUFFERS` macro adjusts `req` but the bounds check doesn't account for next-command chaining boundaries.
- **Impact**: In malformed compound requests, the path bounds check could be bypassed, leading to an out-of-bounds read when `smb_strndup_from_utf16` accesses `(char *)req + PathOffset` with an attacker-controlled PathLength.
- **Fix**: Rewrite the check to use safe arithmetic: compute the absolute end offset and verify it against the total RFC1002 length, not a relative offset from the request pointer. Consider using `check_add_overflow()` for the addition.

---

## Medium

### Finding 6: Inconsistent KSMBD_MAX_NOTIFY_WATCHES vs KSMBD_MAX_NOTIFY_WATCHES_PER_CONN Limits
- **File**: /home/ezechiel203/ksmbd/src/fs/ksmbd_notify.c:35-38
- **Severity**: Medium
- **Description**: The global limit `KSMBD_MAX_NOTIFY_WATCHES` is 512, but the per-connection limit `KSMBD_MAX_NOTIFY_WATCHES_PER_CONN` is 1024. This means the per-connection limit is 2x the global limit and can never actually be reached. A single connection can install at most 512 watches (hitting the global limit first), making the per-connection limit ineffective. Furthermore, with 512 connections each trying to install watches, the global limit ensures at most 512 total, but this means one aggressive client could starve all other clients of notify resources.
- **Impact**: The per-connection limit provides no protection against a single malicious connection consuming all 512 global watch slots. Other legitimate connections would receive ENOSPC errors for change-notify requests.
- **Fix**: Set `KSMBD_MAX_NOTIFY_WATCHES_PER_CONN` to a value significantly lower than `KSMBD_MAX_NOTIFY_WATCHES` (e.g., 32 or 64) to ensure fair distribution of the global watch pool across connections.

### Finding 7: smb2_close Does Not Validate Flags Field Beyond Known Values
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_misc_cmds.c:160
- **Severity**: Medium
- **Description**: In `smb2_close()`, the code checks `if (req->Flags == SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB)` to decide whether to query file attributes before closing. The Flags field is a `__le16` but the comparison is only against the one known flag value. If an attacker sends a Flags value other than 0 or `SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB`, the `else` branch executes and zeroes all response attributes -- which is the correct behavior. However, per MS-SMB2 spec section 3.3.5.9, the server SHOULD return STATUS_INVALID_PARAMETER if any bits other than `SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB` are set. Not rejecting invalid flags could mask protocol conformance issues.
- **Impact**: Low direct security impact, but non-conformance with protocol spec could lead to unexpected behavior with certain SMB clients or security tools that rely on strict protocol validation.
- **Fix**: Add a validation check: `if (req->Flags & ~SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB) { rsp->hdr.Status = STATUS_INVALID_PARAMETER; err = -EINVAL; goto out; }`.

### Finding 8: smb2_query_dir FileNameOffset/FileNameLength Are u16, Preventing Overflow but Missing Validation Against Request Structure
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_dir.c:1100-1104
- **Severity**: Medium
- **Description**: The bounds check validates that `FileNameOffset + FileNameLength` does not exceed the RFC1002 length, which is good. However, the check does not verify that `FileNameOffset` is at least as large as `offsetof(struct smb2_query_directory_req, Buffer)`. If `FileNameOffset` is set to a value less than the size of the fixed request header (e.g., 0 or 32), `smb_strndup_from_utf16` would read from within the request header fields themselves, interpreting header bytes as the search pattern. While the RFC1002 bounds check prevents reading beyond the request buffer, the wrong data would be interpreted as a search pattern.
- **Impact**: A malformed request with a small FileNameOffset could cause the server to interpret arbitrary header bytes as a search pattern, potentially causing unexpected directory enumeration behavior or crashes in the UTF-16 conversion.
- **Fix**: Add a minimum offset check: `if (le16_to_cpu(req->FileNameOffset) < offsetof(struct smb2_query_directory_req, Buffer)) return -EINVAL;`.

### Finding 9: get_file_stream_info Uses Previous `file_info` Pointer for NextEntryOffset = 0 After Loop
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_query_set.c:695
- **Severity**: Medium
- **Description**: After the stream info loop and the `::$DATA` entry addition, `file_info->NextEntryOffset = 0` is set on line 695 to terminate the list. However, if no streams were found and the file is a directory (skipping the `::$DATA` entry), `file_info` still points to `(struct smb2_file_stream_info *)rsp->Buffer` from line 553. In this case, `nbytes` is 0, and setting `file_info->NextEntryOffset = 0` writes into the response buffer at an offset that may overlap with other response data or write into unallocated space. While the `memset(rsp->Buffer, 0, buf_free_len)` on line 562 should have zeroed this area, if `buf_free_len` is 0 (from a negative `smb2_calc_max_out_buf_len` return handled by `goto out`), the write is into unzeroed memory at a valid offset.
- **Impact**: Potential write of 4 bytes into the response buffer when no stream entries exist. This would corrupt whatever data is at `rsp->Buffer[0..3]`, though `rsp->OutputBufferLength` would be 0, so the corrupted data wouldn't normally be sent.
- **Fix**: Guard the final `file_info->NextEntryOffset = 0` assignment with `if (nbytes > 0)`.

### Finding 10: smb2_set_info Buffer Offset/Length Validation for Compound Requests
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_query_set.c:2767-2786
- **Severity**: Medium
- **Description**: The `smb2_set_info()` function performs careful buffer offset/length validation. The check computes `req_len = rfc_len - work->next_smb2_rcv_hdr_off` and then validates `buf_off` and `buf_len` against it. However, `rfc_len` is the total RFC1002 length of the entire compound request, and `work->next_smb2_rcv_hdr_off` is the offset to the current command in the compound chain. The check `buf_off > req_len` verifies the offset against the remaining bytes from the compound start, but `buf_off` is relative to the start of the current SMB2 header (since `buffer = (char *)req + buf_off`). This means the effective offset in the buffer is `work->next_smb2_rcv_hdr_off + buf_off`, and the check should verify this total against `rfc_len + 4`. The current check appears correct for single requests but may allow a carefully crafted compound request to read slightly beyond the current command's boundary into the next command's data.
- **Impact**: Potential cross-command data access in compound requests, which could lead to confused deputy attacks where one command's data is interpreted as another command's set-info buffer.
- **Fix**: For compound requests, also verify that `buf_off + buf_len` does not exceed the current command's boundary (determined by `req->hdr.NextCommand` if non-zero).

### Finding 11: smb2_oplock_break Dispatcher Trusts Client-Supplied StructureSize
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_misc_cmds.c:525-538
- **Severity**: Medium
- **Description**: The `smb2_oplock_break()` function dispatches to either `smb20_oplock_break_ack()` or `smb21_lease_break_ack()` based on `le16_to_cpu(req->StructureSize)`. This uses a client-supplied field to determine which code path to take. While both `OP_BREAK_STRUCT_SIZE_20` (24) and `OP_BREAK_STRUCT_SIZE_21` (36) are defined constants, a malicious client could send `StructureSize = 36` (lease break) but format the body as an oplock break, or vice versa. Each handler then reads different fields from the request body without independently validating the actual request size matches its expected format.
- **Impact**: A client sending a mismatched StructureSize could cause the lease break handler to read uninitialized or incorrect data from what is actually a shorter oplock break request, potentially leading to incorrect oplock state transitions.
- **Fix**: Verify the actual received request length matches the expected size for each handler before processing. Add `if (get_rfc1002_len(work->request_buf) < sizeof(struct smb2_lease_ack)) return -EINVAL;` in the lease break path.

### Finding 12: smb2_get_ea Potential NULL Dereference on prev_eainfo
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_query_set.c:333
- **Severity**: Medium
- **Description**: In `smb2_get_ea()`, `prev_eainfo` is initialized to `eainfo` on line 234. The `while` loop iterates through xattr entries, but if all entries are filtered out (none match the user.* prefix, or all are stream/DOS attributes), the loop body never executes, and `prev_eainfo` still points to the uninitialized `(struct smb2_ea_info *)rsp->Buffer`. Line 333 then sets `prev_eainfo->NextEntryOffset = 0`, which writes 4 bytes at `rsp->Buffer[0]`. While `rsp->Buffer` is a valid location in the response buffer, this write happens even when `rsp_data_cnt == 0`, meaning the OutputBufferLength will be 0, and the 4 bytes are harmless. However, this is a code quality issue that could become a bug if the surrounding logic changes.
- **Impact**: Currently benign, but could become a write to unintended memory if buffer management changes. The 4-byte write at `rsp->Buffer` is always within bounds.
- **Fix**: Move the `prev_eainfo->NextEntryOffset = 0` assignment inside a `if (rsp_data_cnt > 0)` guard.

### Finding 13: smb2_query_dir d_info.wptr Advancement Without Cross-Checking Against Response Buffer End
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_dir.c:620-623
- **Severity**: Medium
- **Description**: In `smb2_populate_readdir_entry()`, after writing the directory entry, the code advances `d_info->wptr += next_entry_offset` and decrements `d_info->out_buf_len -= next_entry_offset`. The check on line 284 (`if (next_entry_offset > d_info->out_buf_len)`) prevents overflow for the current entry. However, `d_info->out_buf_len` is an `int` (signed), and if it somehow goes negative through an arithmetic error, subsequent calls would pass the check (a large positive value compared to a negative int). The `smb2_calc_max_out_buf_len` function does return a signed int and has a `< 0` check, but `d_info->out_buf_len` is decremented in a loop without rechecking for negative values between entries in `reserve_populate_dentry()`.
- **Impact**: If `d_info->out_buf_len` becomes negative through an arithmetic error, subsequent directory entries would be written beyond the allocated response buffer, causing heap corruption.
- **Fix**: Use `unsigned int` for `out_buf_len` or add an explicit `if (d_info->out_buf_len < 0) return -ENOSPC;` check in the populate functions.

---

## Low

### Finding 14: smb2_tree_connect Does Not Validate Reserved Field
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_tree.c:118
- **Severity**: Low
- **Description**: The `smb2_tree_connect_req` structure has a `Reserved` field (which is `Flags` in SMB 3.1.1). The handler does not validate this field, though MS-SMB2 specifies it should be zero for pre-3.1.1 connections. The only flag currently defined for 3.1.1 is `SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT` and `SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER`.
- **Impact**: Minimal. Unknown flag bits would be silently ignored, which is acceptable protocol behavior.
- **Fix**: Optionally log or reject unknown flag bits for defense-in-depth.

### Finding 15: smb2_echo Minimal but Correct Implementation
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_misc_cmds.c:222-234
- **Severity**: Low
- **Description**: The `smb2_echo()` function checks `work->next_smb2_rcv_hdr_off` to handle compound requests, which is correct. However, it does not validate `req->StructureSize == 4` per MS-SMB2. While this is unlikely to cause issues, strict validation would improve protocol conformance.
- **Impact**: None in practice.
- **Fix**: Add `if (le16_to_cpu(req->StructureSize) != 4) return STATUS_INVALID_PARAMETER;` for strict protocol conformance.

### Finding 16: smb2_session_logoff Race Between State Changes
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_tree.c:343-370
- **Severity**: Low
- **Description**: In `smb2_session_logoff()`, the function calls `ksmbd_all_conn_set_status(sess_id, KSMBD_SESS_NEED_RECONNECT)` while holding `conn->lock`, then releases the lock, performs cleanup operations (`ksmbd_close_session_fds`, `ksmbd_conn_wait_idle`), and then acquires `session_lock` and `state_lock` to set the session state to expired. Between releasing `conn->lock` and acquiring `session_lock`, another thread on a different connection could potentially still be using the session. While `ksmbd_conn_wait_idle` should mitigate this, the window between `ksmbd_all_conn_set_status` and `ksmbd_conn_wait_idle` could allow a racing request to proceed.
- **Impact**: Potential use-after-free or double-free if session cleanup races with an in-flight request on another connection. The `ksmbd_conn_wait_idle()` call should prevent this, but the race window exists.
- **Fix**: Consider wrapping the entire logoff sequence in a session-level lock or using more fine-grained state transitions.

### Finding 17: Directory Info Struct ShortName Fields Not Zeroed in All Paths
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_dir.c:321-327
- **Severity**: Low
- **Description**: In `smb2_populate_readdir_entry()`, the `FILE_BOTH_DIRECTORY_INFORMATION` case sets `ShortNameLength = 0` and `Reserved = 0` but does not zero the 24-byte `ShortName` array. Similarly for `FILEID_BOTH_DIRECTORY_INFORMATION` (line 411-412) and the extended both-directory variants. While `ShortNameLength = 0` tells the client to ignore `ShortName`, the 24 bytes could contain stale heap data from the response buffer. This is a minor information disclosure risk as clients should not read past ShortNameLength, but defense-in-depth suggests zeroing these fields.
- **Impact**: Low-severity information disclosure of up to 24 bytes per directory entry if a client reads the ShortName field despite ShortNameLength being 0.
- **Fix**: Add `memset(fbdinfo->ShortName, 0, sizeof(fbdinfo->ShortName))` for all directory info types that contain ShortName fields.

### Finding 18: smb2_query_info Passes work->response_buf as rsp_org to Pipe Handler
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_query_set.c:1152-1153
- **Severity**: Low
- **Description**: When handling pipe (IPC) queries, `smb2_get_info_file()` passes `work->response_buf` as the `rsp_org` argument to `smb2_get_info_file_pipe()`, which in turn passes it to `buffer_check_err()`. The `buffer_check_err()` function writes to `*(__be32 *)rsp_org` on error (line 68). For pipe queries, `rsp_org` is the base response buffer, and this write overwrites the RFC1002 length field. This is intentional (to set the RFC1002 length to just the header size on error), but in compound requests, `work->response_buf` might not be the correct base for the current response. The non-pipe path uses the same `work->response_buf`, which is correct for single requests but may be incorrect for compounds.
- **Impact**: In compound requests, `buffer_check_err` could overwrite the wrong RFC1002 length, potentially corrupting earlier compound responses.
- **Fix**: Use `ksmbd_resp_buf_curr(work)` or equivalent to get the correct response buffer base for compound requests.

### Finding 19: smb2_notify Does Not Cap client output_buf_len
- **File**: /home/ezechiel203/ksmbd/src/protocol/smb2/smb2_notify.c:80-81
- **Severity**: Low
- **Description**: The `smb2_notify()` handler reads `output_buf_len = le32_to_cpu(req->OutputBufferLength)` directly from the client request without capping it against the server's maximum transaction size or the actual response buffer size. This value is stored in the watch structure and later used in `ksmbd_notify_build_response()` to check `info_len > watch->output_buf_len`. Since the actual response is bounded by the allocated response buffer (which has a fixed size), and `ksmbd_iov_pin_rsp` pins only the actual data written, an excessively large `output_buf_len` wouldn't directly cause a buffer overflow. However, it bypasses the intent of the overflow check on line 164 of ksmbd_notify.c.
- **Impact**: The uncapped value means the overflow protection in `ksmbd_notify_build_response()` becomes ineffective -- a client requesting a huge OutputBufferLength would never trigger the STATUS_NOTIFY_ENUM_DIR fallback, even though the actual response buffer cannot hold the data.
- **Fix**: Cap `output_buf_len` to `min(output_buf_len, work->response_sz - sizeof(struct smb2_notify_rsp))` or use `smb2_calc_max_out_buf_len()`.

---

## Positive Observations

1. **Thorough buffer validation in smb2_set_info()**: The BufferOffset/BufferLength validation block (lines 2767-2786) is well-constructed, checking for underflow in compound requests and preventing out-of-bounds reads. This is a significant improvement over many SMB server implementations.

2. **Rate-limiting in directory enumeration**: The `total_scan > 100000` cap in `smb2_query_dir()` (line 1177) is an effective defense against CPU exhaustion attacks via wildcard directory scans on large directories.

3. **Notify watch resource limits**: The dual global (`KSMBD_MAX_NOTIFY_WATCHES = 512`) and per-connection (`KSMBD_MAX_NOTIFY_WATCHES_PER_CONN = 1024`) limits with atomic counters provide good defense against notify-based resource exhaustion, though the per-connection limit should be lower than the global limit.

4. **Access control checks in query handlers**: Virtually all file query handlers check `fp->daccess` against the required access rights (FILE_READ_ATTRIBUTES_LE, FILE_READ_EA_LE, etc.) before returning data. This is consistent and well-implemented.

5. **Pre-zeroing in smb2_get_info_file()**: The `memset(rsp->Buffer, 0, min_t(unsigned int, max_resp, 1024))` call before processing file info requests prevents information disclosure for most file-level queries.

6. **Proper info-level validation**: `verify_info_level()` in smb2_dir.c and the info class size validation in `readdir_info_level_struct_sz()` prevent processing of unsupported information classes, reducing attack surface.

7. **Robust tree connect path validation**: The PathOffset + PathLength bounds check on lines 1100-1104 of smb2_dir.c and lines 120-124 of smb2_tree.c prevent basic out-of-bounds reads.

8. **Object ID information no longer leaks user passkeys**: Line 1412 uses `memset(info->objid, 0, 16)` instead of using user-derived data, which is a deliberate and good security fix (commented as such).

9. **Set-info writable check**: `smb2_set_info()` verifies `KSMBD_TREE_CONN_FLAG_WRITABLE` before allowing any set-info operations, providing a coarse-grained authorization check.

10. **smb2_set_info_file minimum buffer length checks**: Every FileInfoClass handler in `smb2_set_info_file()` validates `buf_len < sizeof(expected_struct)` before casting, preventing underread vulnerabilities.
