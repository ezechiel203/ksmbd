# TODO_STELLAR_V11 — Exhaustive Line-by-Line Parallel Audit

**Date**: 2026-03-05
**Branch**: phase1-security-hardening
**Audit scope**: 10 parallel agents, line-by-line review of all ksmbd source files
**Total findings**: ~233 across 9 completed agents (agent H ran out of quota)
**Agent H scope missed**: smb2_dir.c, ksmbd_notify.c, ksmbd_dfs.c, ksmbd_vss.c

---

## Legend

- **P0**: Kernel crash / use-after-free / memory corruption / security-critical (fix before any deployment)
- **P1**: Protocol security / data corruption / authentication bypass (fix in next commit wave)
- **P2**: Spec compliance / incorrect behavior / wrong return codes (fix in compliance wave)
- **P3**: Polish / minor correctness / documentation (fix opportunistically)
- **Complexity**: LOW = 1-10 lines, MEDIUM = 10-50 lines, HIGH = 50+ lines or new infrastructure

---

## PHASE 0 — P0 CRITICAL (kernel crash / UAF / OOB / security)

Fix ALL of these before any test run. These are kernel stability killers.

### [P0] VFS-18: Sleep under spinlock in ksmbd_file_table_flush
**File**: `src/fs/vfs_cache.c:1573`
**Issue**: `read_lock(&file_table.lock)` is a spinlock. `ksmbd_vfs_fsync()` → `vfs_fsync()` can sleep waiting for I/O writeback. Sleeping under spinlock = BUG/lockup.
**Fix**: Collect volatile_ids under lock into local array, release lock, then fsync outside.
**Complexity**: MEDIUM

### [P0] TC-02: Credits outstanding_credits unsigned wrap (SMB2.0.2)
**File**: `src/protocol/smb2/smb2misc.c:549-559`
**Issue**: `outstanding_credits + 1` on `unsigned int` can wrap to 0 if `outstanding_credits == UINT_MAX`, bypassing the credit limit check entirely.
**Fix**: Change to `if (conn->outstanding_credits >= conn->total_credits)` before increment.
**Complexity**: LOW

### [P0] TC-06: Encryption bypass when work->sess is NULL in compound chain
**File**: `src/core/server.c:394-408`
**Issue**: `if (work->sess && work->sess->enc_forced && !work->encrypted)` skips encryption check when `work->sess == NULL`. Session can become NULL mid-compound on error path. Subsequent compound sub-requests bypass encryption enforcement.
**Fix**: Cache `enc_forced` from outer transform header session before entering compound loop; enforce unconditionally.
**Complexity**: MEDIUM

### [P0] TC-10: Decompression bomb in chained compression path
**File**: `src/core/smb2_compress.c:1505-1531`
**Issue**: `seg_orig_size = *total_out - out_pos` can be the entire remaining budget (2MB) for the first segment. No per-segment size limit. Single compressed segment can expand to full max_allowed budget.
**Fix**: Add per-segment amplification check: reject if `compressed_len * 1024 < seg_orig_size`.
**Complexity**: MEDIUM

### [P0] TC-16: IPC stack-allocated entry UAF on timeout
**File**: `src/transport/transport_ipc.c:355-398`
**Issue**: `ipc_msg_send_request` has `struct ipc_msg_table_entry entry` on **stack**. After timeout, stack frame returns. But concurrent `handle_response` holding `down_read` can still write `entry->response` to the freed stack — classic UAF.
**Fix**: Heap-allocate `ipc_msg_table_entry` via `kmalloc`. Free only after `hash_del` under write lock and all readers have released.
**Complexity**: HIGH

### [P0] VFS-06: UAF — m_count decrement outside hash bucket lock
**File**: `src/fs/vfs_cache.c:442`
**Issue**: `atomic_dec_and_test(&ci->m_count)` is called outside the hash bucket write lock. Between the decrement reaching zero and `ksmbd_inode_free()`, another thread can call `ksmbd_inode_lookup()` which does `atomic_inc_not_zero` and gets a pointer to the being-freed struct.
**Fix**: Perform `atomic_dec_and_test` inside the hash bucket write lock, mirroring the `ksmbd_inode_get` pattern.
**Complexity**: HIGH

### [P0] VFS-11: OOB read in set_posix_acl_entries_dacl — ntace->size=0 infinite loop
**File**: `src/fs/smbacl.c:1121`
**Issue**: Inner loop advances `ntace` by `le16_to_cpu(ntace->size)`. If `ntace->size == 0`: infinite loop. If size advances past buffer end: OOB read of `ntace->sid.sub_auth[...]`.
**Fix**: Add `if (le16_to_cpu(ntace->size) < offsetof(struct smb_ace, sid)) break;` and track remaining buffer bytes.
**Complexity**: LOW

### [P0] VFS-14: Deadlock — d_lock held while calling ksmbd_lookup_fd_inode
**File**: `src/fs/vfs.c:1903-1923`
**Issue**: `ksmbd_validate_entry_in_use` holds `d_lock` (spinlock) while calling `ksmbd_lookup_fd_inode(dst_dent)` which acquires `inode_hashtable[bucket].lock`. Lock ordering violation: `d_lock` → `inode_hashtable.lock`. If any path takes these in reverse order: deadlock.
**Fix**: Drop `d_lock`, `dget(child)`, release spinlock, then call `ksmbd_lookup_fd_inode`.
**Complexity**: MEDIUM

### [P0] VFS-01: UAF on dentry after vfs_unlink in ksmbd_reparse_replace_with_symlink
**File**: `src/fs/ksmbd_reparse.c:305`
**Issue**: After `dget(dentry)` + `vfs_unlink()` + `dput(dentry)`, code accesses `dentry->d_name.name` and `dentry->d_name.len`. If the extra `dput` drops refcount to zero, the dentry memory can be freed.
**Fix**: Save `d_name` fields to local variables before unlink. Remove the extra `dget/dput` pair.
**Complexity**: LOW

### [P0] NEG-03: conn->vals NULL deref + old_vals memory leak on AUT-05 error path
**File**: `src/protocol/smb2/smb2_negotiate.c:892-898`
**Issue**: When Preauth_HashId != SHA512, error path frees `preauth_info` and `goto err_out` but `old_vals` (which holds the original `conn->vals`) is never freed and `conn->vals` remains NULL. Subsequent request handling dereferences NULL `conn->vals`.
**Fix**: Add `conn->vals = old_vals;` before `goto err_out` in the AUT-05 check block.
**Complexity**: LOW

### [P0] SES-02: sess->user race condition — written without state_lock
**File**: `src/protocol/smb2/smb2_session.c:322-344`
**Issue**: `sess->user` is written at lines 335-336 and 343 without holding `sess->state_lock`. Concurrent SESSION_SETUP on another channel reads `sess->user` (e.g., in destroy_previous_session). Race → potential UAF or NULL dereference.
**Fix**: Protect `sess->user` writes with `down_write(&sess->state_lock)` for the entire read-check-write sequence.
**Complexity**: MEDIUM

### [P0] SES-03: destroy_previous_session called BEFORE authentication succeeds
**File**: `src/protocol/smb2/smb2_session.c:317-320`
**Issue**: `destroy_previous_session()` tears down the previous session (closes files, expires session) even if the new authentication subsequently fails. An attacker who knows a victim's session ID can force-tear it down by sending AUTHENTICATE with wrong credentials but victim's PreviousSessionId.
**Fix**: Move `destroy_previous_session()` to AFTER successful `ksmbd_decode_ntlmssp_auth_blob()`. Store `prev_id` and call conditionally on auth success only.
**Complexity**: MEDIUM

### [P0] AUTH-05: vmalloc-backed AES-GMAC scatterlist covers only first page
**File**: `src/core/auth.c:1293-1300`
**Issue**: `sg_set_page(&sg[0], vmalloc_to_page(aad_buf), total_len, ...)` uses only the first page. For `total_len > PAGE_SIZE`, the scatterlist covers only 4KB but claims `total_len` bytes. Crypto layer processes garbage from adjacent pages → kernel BUG or memory corruption for large PDUs.
**Fix**: Allocate `DIV_ROUND_UP(total_len + offset_in_page(aad_buf), PAGE_SIZE)` SG entries and map each vmalloc page separately, mirroring `ksmbd_init_sg()`.
**Complexity**: MEDIUM

### [P0] QSA-09: EA SET off-by-one — value pointer 1 byte past NUL may OOB
**File**: `src/protocol/smb2/smb2_create.c:388-391`
**Issue**: `value = (char *)&eabuf->name + eabuf->EaNameLength + 1`. If `EaNameLength` is exactly at the end of the remaining buffer with no NUL byte, the `+1` causes an out-of-bounds pointer. Subsequent `ksmbd_vfs_setxattr(value, EaValueLength)` reads beyond the allocated buffer.
**Fix**: Add bounds check: `(char *)value + le16_to_cpu(eabuf->EaValueLength) <= (char *)eabuf + buf_remaining`.
**Complexity**: MEDIUM

### [P0] QSA-13: FS_OBJECT_ID version_string — uninitialized kernel heap bytes leaked
**File**: `src/protocol/smb2/smb2_query_set.c:1791`
**Issue**: `info->extended_info.version_string` is a 28-byte field. Only 5 bytes ("1.1.0") are written. The remaining 23 bytes are uninitialized kernel heap memory sent to the client.
**Fix**: `memset(info, 0, sizeof(*info))` before filling fields, OR `memset(info->extended_info.version_string, 0, sizeof(info->extended_info.version_string))` after the memcpy.
**Complexity**: LOW

### [P0] QSA-22: FS_ATTRIBUTE_INFORMATION — smbConvertToUTF16 writes without output buffer cap
**File**: `src/protocol/smb2/smb2_query_set.c:1699`
**Issue**: `smbConvertToUTF16((__le16 *)info->FileSystemName, "NTFS", PATH_MAX, ...)` uses PATH_MAX as max chars but there is no check that `sizeof(response_buffer) - sizeof(filesystem_attribute_info)` accommodates PATH_MAX chars. Client with tiny OutputBufferLength triggers write beyond response buffer.
**Fix**: Cap `smbConvertToUTF16` at `(available_bytes - sizeof(struct filesystem_attribute_info)) / 2` chars, where available_bytes comes from `smb2_calc_max_out_buf_len()`.
**Complexity**: MEDIUM

### [P0] POSIX-01: SMB_FIND_FILE_POSIX_INFO SidBuffer overflows for domain SIDs
**File**: `src/protocol/smb2/smb2_dir.c:638-641`
**Issue**: `SidBuffer[44]` is fixed-size. Domain SIDs can be 28 bytes. Writing owner (28B) + group (28B) = 56B into a 44-byte field causes heap overflow. No bounds check before `id_to_sid()` calls.
**Fix**: Use variable-length SID serialization with explicit length accounting. Check `sizeof_owner_sid + sizeof_group_sid <= sizeof(SidBuffer)` before writing.
**Complexity**: MEDIUM

### [P0] POSIX-02: SMB_FIND_FILE_POSIX_INFO wrong cast — fields written to kstat not output buffer
**File**: `src/protocol/smb2/smb2_dir.c:586`
**Issue**: `posix_info = (struct smb2_posix_info *)kstat` casts the INPUT `kstat` to an output struct. All field assignments (Inode, EaSize, etc.) write into the kstat on the stack, NOT into the wire response buffer. The populate case is architecturally broken.
**Fix**: Use `d_info->wptr` or a properly typed pointer to the actual output buffer in all three SMB_FIND_FILE_POSIX_INFO case blocks.
**Complexity**: HIGH

### [P0] MGMT-01: ksmbd_share_configs_flush() UAF — no RCU grace period
**File**: `src/mgmt/share_config.c:363-381`
**Issue**: Flush path uses `hash_del()` (non-RCU) + immediate `kfree()` under spinlock. RCU readers in `__share_lookup_rcu()` inside RCU read-side critical sections hold valid pointers to the now-freed share struct.
**Fix**: Use `hash_del_rcu()` + `synchronize_rcu()` + `kill_share()` (or `call_rcu()`). Mirror `__ksmbd_share_config_put()` which correctly uses `hash_del_rcu()` + `call_rcu()`.
**Complexity**: MEDIUM

### [P0] IPC-02: handle_generic_event — no size validation for fixed-size response structs
**File**: `src/transport/transport_ipc.c:533-557`
**Issue**: `handle_generic_event()` dispatches responses without minimum-size checks for types not covered by `ipc_validate_msg()` (including `KSMBD_EVENT_LOGIN_RESPONSE`). A truncated login response (4 bytes) causes callers to read `uid`, `gid`, `hash_sz`, `hash` from out-of-bounds memory.
**Fix**: Add minimum size validation for ALL response types in `ipc_validate_msg()`. Change `default: return 0` to `default: return -EINVAL`.
**Complexity**: MEDIUM

### [P0] NETLINK-01: ifc_list_sz no upper bound — kernel reads beyond netlink message
**File**: `src/transport/transport_ipc.c:444`
**Issue**: `ksmbd_tcp_set_interfaces(KSMBD_STARTUP_CONFIG_INTERFACES(req), req->ifc_list_sz)` — `ifc_list_sz` is user-supplied with no kernel-side bound check. Malformed daemon can trigger OOB kernel memory read.
**Fix**: Add `if (req->ifc_list_sz > KSMBD_MAX_IFACE_LIST_SZ || req->ifc_list_sz > nla_len(attr) - sizeof(*req)) return -EINVAL;`
**Complexity**: LOW

### [P0] SMB1-09: SMB1 signing sequence number not validated — replay attack
**File**: `src/protocol/smb1/smb1pdu.c` — `smb1_check_sign_req()`
**Issue**: Signing MAC is verified but the `SequenceNumber` embedded in the MAC computation is never extracted and compared against a session-maintained counter. Any valid signed PDU can be replayed.
**Fix**: Maintain `session->sign_seq_num`. In `smb1_check_sign_req()`, extract expected sequence number, verify it matches the next expected counter, reject (disconnect) on mismatch.
**Complexity**: MEDIUM

### [P0] SMB1-19: smb_trans() LANMAN — no ParameterCount validation (OOB read)
**File**: `src/protocol/smb1/smb1pdu.c:~2500`
**Issue**: LANMAN handler extracts function-specific fields from the parameter buffer without validating `ParameterCount >= minimum_for_function`. A malformed TRANSACTION with `ParameterCount=1` triggers OOB reads parsing function parameters.
**Fix**: Add per-FunctionCode minimum ParameterCount checks. For `NetServerEnum2` (0x68): require `ParameterCount >= 10`. Return `STATUS_INVALID_PARAMETER` if too small.
**Complexity**: LOW

### [P0] SMB1-23: ANDX variable-length response data not bounds-checked
**File**: `src/protocol/smb1/smb1pdu.c` — `smb_session_setup_andx()`, `smb_tree_connect_andx()`
**Issue**: After `andx_response_buffer()` returns sub-buffer pointer, variable-length data (SPNEGO blob, service string, native OS) is written without checking remaining capacity. Heap overflow on crafted short response buffer.
**Fix**: Pass `remaining_size` to each ANDX handler. Check `current_offset + field_len <= buf_end` before writing each variable-length field.
**Complexity**: MEDIUM

### [P0] SMB1-24: UNIX_LINK readlink returns raw kernel absolute path — info leak
**File**: `src/protocol/smb1/smb1pdu.c` — `query_path_info()` level `SMB_QUERY_FILE_UNIX_LINK`
**Issue**: `vfs_readlink()` result is returned verbatim. If the symlink target is `/etc/passwd`, `/proc/kcore`, etc., the full kernel path is disclosed to the client.
**Fix**: After `vfs_readlink()`, check if target is absolute. Map to share-relative path or return `STATUS_ACCESS_DENIED` if target is outside share root.
**Complexity**: MEDIUM

### [P0] SMB1-25: NT_TRANSACT_RENAME name length not validated (OOB heap read)
**File**: `src/protocol/smb1/smb1pdu.c` — `smb_nt_transact_rename()`
**Issue**: `FileNameLength` from setup parameters is used without validating it fits within `TotalParameterCount`. `smb_get_name()` with an unchecked length causes OOB kernel heap read.
**Fix**: Before `smb_get_name()`: validate `name_offset + name_length <= total_parameter_count`.
**Complexity**: LOW

### [P0] AAPL-02: kAAPL_SUPPORTS_READ_DIR_ATTR advertised but ReadDirAttr is a no-op
**File**: `src/protocol/smb2/smb2fruit.c:791-858`
**Issue**: `kAAPL_SUPPORTS_READ_DIR_ATTR` unconditionally set in server caps. `smb2_read_dir_attr_fill()` reads rfork_len/FinderInfo but never packs them into the directory entry wire format. macOS Finder interprets garbage data from the raw unfilled fields.
**Fix**: Write `rfork_len` (4 bytes LE) and FinderInfo (32 bytes) at correct AAPL ReadDirAttr wire offsets. Or remove `kAAPL_SUPPORTS_READ_DIR_ATTR` from advertised caps until implemented.
**Complexity**: MEDIUM

---

## PHASE 1 — P1 HIGH PRIORITY (security / data integrity / protocol correctness)

### Auth / Negotiate

### [P1] NEG-04: ServerGUID lazy init — race on concurrent first-negotiate
**File**: `src/protocol/smb2/smb2_negotiate.c:993-998`
**Issue**: Two simultaneous first-negotiate requests can each see all-zero GUID, generate different GUIDs, last writer wins. ServerGUID becomes non-deterministic under load.
**Fix**: Initialize `server_conf.server_guid` at module/daemon startup (not lazily).
**Complexity**: LOW

### [P1] NEG-05: Preauth hash chain missing negotiate RESPONSE hash
**File**: `src/protocol/smb2/smb2_negotiate.c:909-911`
**Issue**: MS-SMB2 §3.3.5.3.1 requires hashing both the request AND response into the PAI chain. Only the request is hashed. PAI is weakened.
**Fix**: After `ksmbd_iov_pin_rsp()` in both NEGOTIATE and SESSION_SETUP handlers, call `ksmbd_gen_preauth_integrity_hash()` with the response buffer.
**Complexity**: MEDIUM

### [P1] NEG-01: DialectCount multiplication lacks overflow guard on 32-bit
**File**: `src/protocol/smb2/smb2_negotiate.c:824`
**Issue**: `le16_to_cpu(req->DialectCount) * sizeof(__le16)` — no `check_mul_overflow()`. On 32-bit kernels with `DialectCount=0x8000`, can produce incorrect result.
**Fix**: Use `check_mul_overflow()` or `struct_size()` pattern.
**Complexity**: LOW

### [P1] SES-06: Anonymous session can bind to multichannel
**File**: `src/protocol/smb2/smb2_session.c:801-810`
**Issue**: Binding check uses `user_guest(sess->user)` but not the anonymous flag. Anonymous sessions must not be bound to additional channels.
**Fix**: Also check `rsp->SessionFlags & SMB2_SESSION_FLAG_IS_NULL_LE` when rejecting binding.
**Complexity**: LOW

### [P1] SES-07: SecurityBufferOffset not validated against minimum 72
**File**: `src/protocol/smb2/smb2_session.c:870-873`
**Issue**: Check validates `negblob_off >= Buffer field start` but offset of 65-71 passes yet points inside struct padding. Should require `negblob_off >= 72` (per spec §2.2.19 fixed value).
**Fix**: Validate `negblob_off >= 72` and is 8-byte aligned.
**Complexity**: LOW

### [P1] AUTH-01: ntlmv2 blob minimum size check insufficient (20 bytes vs spec 48)
**File**: `src/core/auth.c:646-651`
**Issue**: Check `nt_len < (CIFS_ENCPWD_SIZE + 4)` allows 20-byte blobs. MS-NLMP requires 48 bytes minimum (NTProofStr + CLIENT_CHALLENGE header). Remove dead second check.
**Fix**: Change minimum to `nt_len < (CIFS_ENCPWD_SIZE + 28)` = 44 bytes. Remove redundant second check.
**Complexity**: LOW

### [P1] AUTH-02: In-place RC4 decryption on sess_key — aliased read-write
**File**: `src/core/auth.c:740-770`
**Issue**: `cifs_arc4_crypt(ctx, sess->sess_key, sess->sess_key, len)` reads and writes the same buffer. C aliasing rules make this implementation-defined; compiler may reorder.
**Fix**: Use a separate temp buffer; memcpy to sess_key after; zero the temp.
**Complexity**: LOW

### [P1] AUTH-06: NTLM challenge TargetInfo — all 4 AV_PAIR types use server name
**File**: `src/core/auth.c:904-910`
**Issue**: `MsvAvNbComputerName`, `MsvAvNbDomainName`, `MsvAvDnsComputerName`, `MsvAvDnsDomainName` all set to same server name. Domain-joined Windows clients use `MsvAvNbDomainName` for credential lookup — getting server name causes auth failures.
**Fix**: Populate `MsvAvNbDomainName` with domain/workgroup from `server_conf`. Use actual DNS hostname for DNS-type pairs.
**Complexity**: MEDIUM

### [P1] CRYPTO-01: Crypto context pool — avail_ctx counter race on alloc failure
**File**: `src/core/crypto_ctx.c:183-199`
**Issue**: `avail_ctx++` followed by `spin_unlock` then `kzalloc` — between unlock and alloc, another thread's release can add to idle_ctx but our thread already incremented avail_ctx, leading to premature context frees.
**Fix**: Re-check `idle_ctx` after kzalloc failure before decrementing `avail_ctx`.
**Complexity**: MEDIUM

### [P1] TC-08: SESSION_SETUP extension read — expected_pdu not bounded below
**File**: `src/core/connection.c:659-696`
**Issue**: `expected_pdu = SecurityBufferOffset + SecurityBufferLength` can allocate up to ~16MB from an unauthenticated client before any credit check, with a tiny SecurityBufferOffset.
**Fix**: Cap `expected_pdu` to `pdu_size + SMB2_MAX_BUFFER_SIZE`. Require `expected_pdu >= sizeof(struct smb2_sess_setup_req)`.
**Complexity**: LOW

### [P1] TC-04: Credits lost in compound abort mid-chain
**File**: `src/core/server.c:411-443`
**Issue**: When a compound request hits `SERVER_HANDLER_ABORT`, remaining sub-requests had their `outstanding_credits` incremented but never returned. Credits are permanently lost.
**Fix**: On `SERVER_HANDLER_ABORT`, iterate remaining compound sub-headers and return outstanding credits.
**Complexity**: MEDIUM

### [P1] TC-11: Compression algorithm bypass — chained path skips algorithm mismatch check
**File**: `src/core/smb2_compress.c:1645-1650`
**Issue**: Non-chained path checks `algorithm != conn->compress_algorithm`. Chained path has no such check. Pre-session chained compressed packets are accepted without algorithm validation.
**Fix**: Add the same algorithm mismatch check at the top of the chained path before decompression.
**Complexity**: LOW

### [P1] TC-12: LZNT1 decompressor — copy_len capped at 4096 but uncompressed chunk can be 4098
**File**: `src/core/smb2_compress.c:279-288`
**Issue**: `copy_len = min_t(size_t, 4096, output_len - out_pos)` vs `chunk_data_size` max 4098. Incorrectly rejects valid data with `-ENOSPC`. Copy uses `chunk_data_size` not `copy_len` → potential OOB write if check incorrectly passes.
**Fix**: Use `copy_len = output_len - out_pos` without the artificial 4096 cap.
**Complexity**: LOW

### [P1] TC-13: LZ77+Huffman chain decode — consumes bits without verifying code match
**File**: `src/core/smb2_compress.c:1025-1050`
**Issue**: Chain lookup consumes `LZ77H_FAST_BITS` + `extra` bits from each chain entry without verifying those bits match the expected Huffman code. Wrong bits consumed for all multi-chain long codes → garbled decompression.
**Fix**: Store full codes in chain entries during table build. Peek (not consume) extra bits; compare against stored code; consume only on confirmed match.
**Complexity**: HIGH

### [P1] TC-14: LZ77 extended length formula wrong — missing `- 267` subtraction
**File**: `src/core/smb2_compress.c:613-621`
**Issue**: MS-XCA §2.4: when `length==15` and `more_len==255`, final length = `extra_u16 - 267`. Code sets `length = extra` (raw u16) without subtraction. Incorrect match lengths for longest matches.
**Fix**: Change to `length = extra - (15 + 255) + 3;` per MS-XCA §2.4.
**Complexity**: LOW

### [P1] TC-22: Signing key use-after-free — concurrent session logoff
**File**: `src/protocol/smb2/smb2_pdu_common.c:1244-1320`
**Issue**: `smb3_check_sign_req` calls `lookup_chann_list()` which returns a channel pointer. Concurrent `smb2_session_logoff()` on another channel can free `chann->smb3signingkey` while HMAC is in progress.
**Fix**: Zero `chann->smb3signingkey` under `sess->lock` in free path. Signing path should copy key under lock before HMAC computation.
**Complexity**: MEDIUM

### [P1] TC-17: Connection teardown double-free race in stop_sessions
**File**: `src/core/connection.c:868-882`
**Issue**: `refcount_inc_not_zero` in stop_sessions can race with the normal cleanup path's `refcount_dec_and_test`, both reaching zero simultaneously → double free of `conn`.
**Fix**: Check `ksmbd_conn_releasing` before taking the extra ref in `stop_sessions`. Ensure single-path cleanup.
**Complexity**: HIGH

### [P1] TC-18: QUIC packet replay — no receive window / deduplication
**File**: `src/transport/transport_quic.c`
**Issue**: No replay window tracking. Replayed QUIC packets with same packet number decrypt successfully (same nonce → same AEAD tag). Allows replay of authenticated SMB commands.
**Fix**: Implement 64-bit reception bitmask for the 64 packet numbers below `recv_pkt_num` (RFC 9000 §A.3). Drop replayed packets.
**Complexity**: MEDIUM

### [P1] TC-24: Zero-length decompressed request accepted and passed to SMB2 parser
**File**: `src/core/smb2_compress.c:1710-1743`
**Issue**: If `original_size == 0` and `offset == 0`, a 5-byte buffer is allocated and passed to `ksmbd_smb_request()` → `smb2_check_message()` which will crash on a zero-length SMB2 header.
**Fix**: Add `if (original_size < SMB2_MIN_SUPPORTED_HEADER_SIZE) return -EINVAL;` after offset validation.
**Complexity**: LOW

### VFS / ACL Security

### [P1] VFS-02: stream.size as attr_name_len — zero/negative causes wrong xattr match
**File**: `src/fs/vfs.c:648`
**Issue**: `ksmbd_vfs_getcasexattr(..., fp->stream.size)` passes `ssize_t stream.size` as the name length. If 0: matches first xattr regardless of name. If negative: `strncasecmp` reads huge range.
**Fix**: Use `strlen(fp->stream.name)` as the length parameter.
**Complexity**: LOW

### [P1] VFS-03: kern_path without share root — SMB1 setattr path traversal
**File**: `src/fs/vfs.c:1138`
**Issue**: `kern_path(name, LOOKUP_BENEATH, &path)` — LOOKUP_BENEATH without a starting point does not prevent absolute paths from escaping the share.
**Fix**: Replace with `ksmbd_vfs_kern_path(work, name, LOOKUP_NO_SYMLINKS, &path, false)`.
**Complexity**: LOW

### [P1] VFS-05: Stream fd stream.name not validated for path characters
**File**: `src/fs/vfs.c:74`
**Issue**: `fp->stream.name` containing `/` or `../` could be used with `ksmbd_vfs_getcasexattr` to access unintended xattrs.
**Fix**: Validate `fp->stream.name` contains no `/` when set in the open path.
**Complexity**: LOW

### [P1] VFS-07: Double-refcount drop in purge_disconnected_fp
**File**: `src/fs/vfs_cache.c:958`
**Issue**: Two `refcount_dec` calls: one unconditional, one conditional. Fragile double-drop can lead to UAF under specific refcount scenarios.
**Fix**: Verify refcount semantics — scavenger should only drop the guard ref, relying on connection teardown for base ref.
**Complexity**: HIGH

### [P1] VFS-09: getcasexattr partial-match — strncasecmp prefix match
**File**: `src/fs/vfs.c:611`
**Issue**: `strncasecmp(attr_name, name, attr_name_len)` returns 0 if `name` has `attr_name` as a prefix but is longer. Wrong xattr returned → ACL bypass possible.
**Fix**: Add `strlen(name) != (size_t)attr_name_len` as additional condition.
**Complexity**: LOW

### [P1] VFS-10: parse_dacl heap overflow via ACE accumulation
**File**: `src/fs/smbacl.c:986`
**Issue**: `acl_state.users->n` can reach `num_aces`. Subsequent owner/group writes at `aces[num_aces]` — allocated as `cnt+2`. Verify both `acl_state` and `default_acl_state` counters cannot exceed allocation.
**Fix**: Check `n < allocated_count` before each `aces[n++]` write.
**Complexity**: MEDIUM

### [P1] ACL-02: Object ACE SID sub_auth not validated after smb_ace_get_sid
**File**: `src/fs/smbacl.c:770`
**Issue**: Non-object ACEs have SID validated via `parse_sid()`. Object ACEs skip this validation. OOB read if `num_subauth` is crafted beyond the buffer.
**Fix**: After `smb_ace_get_sid` for object ACEs, call `parse_sid(sid_ptr, end_of_acl)`.
**Complexity**: LOW

### [P1] ACL-03: DJB2 hash for domain-UID mapping — collision allows UID escalation
**File**: `src/fs/smbacl.c:509`
**Issue**: Simple DJB2 hash for domain→UID offset. Attacker controlling a foreign domain SID can craft a hash collision mapping to UID 0 (root).
**Fix**: Use HMAC-SHA256 for the domain hash, or ensure `DOMAIN_UID_OFFSET_MULTIPLIER` is large enough to prevent root collision.
**Complexity**: MEDIUM

### [P1] ACL-04: compare_sids OOB read if num_subauth > SID_MAX_SUB_AUTHORITIES
**File**: `src/fs/smbacl.c:109`
**Issue**: Loop runs `num_subauth` iterations on `sub_auth[]` (max 15 elements). No bound check → OOB read.
**Fix**: Add `if (num_subauth > SID_MAX_SUB_AUTHORITIES) return 1;` before the loop.
**Complexity**: LOW

### [P1] XATTR-01: ReparseData stored in user.* namespace — unprivileged tampering
**File**: `src/include/fs/xattr.h:136`
**Issue**: `XATTR_NAME_REPARSE_DATA = "user.ReparseData"`. Any local user with write access can inject arbitrary reparse data (inject fake junctions/symlinks) visible to Windows clients.
**Fix**: Change to `XATTR_TRUSTED_PREFIX "ReparseData"` (writable only by root).
**Complexity**: LOW

### [P1] VFS-19: is_subdir doesn't prevent mount-crossing share boundary escape
**File**: `src/fs/vfs.c:2201`
**Issue**: `is_subdir(dentry, share_path->dentry)` checks dentry ancestry but ignores mount crossings. `d_find_alias(inode)` can return a dentry on a different mount outside the share.
**Fix**: Use `path_is_under` with full `struct path` (including mount) instead of just dentry.
**Complexity**: MEDIUM

### [P1] MULTI-01: Multi-channel TREE_CONNECT response missing SMB2_SHARE_CAP_SCALEOUT
**File**: `src/protocol/smb2/smb2_tree.c:367-382`
**Issue**: When `KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL` is enabled, TREE_CONNECT response never sets `SMB2_SHARE_CAP_SCALEOUT`. Clients may not use additional channels.
**Fix**: Set `SMB2_SHARE_CAP_SCALEOUT` in response capabilities when multi-channel is enabled.
**Complexity**: LOW

### [P1] MULTI-02: Per-channel binding key derivation — preauth hash validation
**File**: `src/core/auth.c:1431-1470`
**Issue**: Binding channel key must use per-channel preauth hash. If binding connection dialect doesn't support preauth, key derivation may produce same key as primary channel.
**Fix**: Verify binding preauth hash check in `smb2_session.c:852-862` correctly gates on dialect support for preauth. Reject binding with `STATUS_INVALID_PARAMETER` if preauth hash is zero/invalid.
**Complexity**: HIGH

### [P1] MULTI-03: FSCTL_QUERY_NETWORK_INTERFACE_INFO misses IPv6 addresses
**File**: `src/transport/transport_ipc.c:1302-1336`
**Issue**: Only IPv4 addresses enumerated. `KSMBD_WITNESS_IFACE_CAP_IPV6` bit never set. IPv6-only networks cannot use multi-channel.
**Fix**: Add IPv6 enumeration using `in6_dev_get()` / `ipv6_get_ifaddr()`.
**Complexity**: MEDIUM

### [P1] MGMT-02: Session IDs are sequential — remote enumeration/prediction
**File**: `src/mgmt/user_session.c:627-646`
**Issue**: IDA-allocated sequential session IDs enable prediction/brute-force of other active sessions, enabling rogue channel binding attacks.
**Fix**: XOR IDA-allocated ID with a per-boot random 64-bit salt generated at module init.
**Complexity**: MEDIUM

### [P1] MGMT-03: No per-user session limit in kernel — DoS via session accumulation
**File**: `src/mgmt/user_session.c:649-703`
**Issue**: No kernel-side limit on sessions in `SMB2_SESSION_IN_PROGRESS` state. Unauthenticated clients can accumulate unbounded in-progress sessions.
**Fix**: Add configurable limit on in-progress sessions per IP. Return `STATUS_TOO_MANY_SESSIONS` if exceeded.
**Complexity**: MEDIUM

### [P1] IPC-01: IPC_WAIT_TIMEOUT = 2 seconds — false-positive daemon-dead detection
**File**: `src/transport/transport_ipc.c:36`
**Issue**: Loaded daemon (LDAP lookups, etc.) may take > 2s. Timeout causes `STATUS_BAD_NETWORK_NAME` false failures.
**Fix**: Increase to 10+ seconds or make configurable.
**Complexity**: LOW

### [P1] QSA-01: FILE_STAT_LX_INFORMATION (0x47) hash-collides with FILE_CASE_SENSITIVE_INFORMATION (71)
**File**: `src/include/protocol/smb2pdu.h:1638-1639`
**Issue**: Same constant value 71, hash table collision — only one handler gets called. FileStatLx is unreachable for WSL2 clients.
**Fix**: Handle `case 71` with context-based dispatch, or use a separate dispatch mechanism.
**Complexity**: MEDIUM

### [P1] QSA-08: FileStatLxInformation LxFlags always zero — breaks WSL2
**File**: `src/fs/ksmbd_info.c:1730-1731`
**Issue**: `info->LxFlags = 0` for all files. WSL2 uses LxFlags for file type. Regular files/dirs/symlinks all appear as type-unknown.
**Fix**: Populate from `stat.mode`: `S_ISREG→0x2`, `S_ISDIR→0x4`, `S_ISLNK→0x10`, `S_ISCHR→0x20`, `S_ISBLK→0x40`, `S_ISFIFO→0x80`, `S_ISSOCK→0x100`.
**Complexity**: LOW

### [P1] QSA-02: FILE_VALID_DATA_LENGTH SET — early return bypasses actual handler
**File**: `src/protocol/smb2/smb2_query_set.c:3616-3630`
**Issue**: Switch case for FILE_VALID_DATA_LENGTH_INFORMATION returns 0 without calling the actual fallocate handler. The ksmbd_info.c handler is dead code.
**Fix**: Remove the early `return 0` or remove the switch case to allow dispatch table to handle it.
**Complexity**: LOW

### [P1] QSA-16: FILE_ALL_INFORMATION filename silently truncated instead of STATUS_BUFFER_OVERFLOW
**File**: `src/protocol/smb2/smb2_query_set.c:593-601`
**Issue**: When `conv_len > PATH_MAX`, filename silently truncated. `FileNameLength` reports truncated size, not real size. Client never retries with larger buffer.
**Fix**: Store actual `conv_len` in `FileNameLength`. If clamped, return `STATUS_BUFFER_OVERFLOW` via `buffer_check_err()`.
**Complexity**: LOW

### [P1] AAPL-03: kAAPL_RESOLVE_ID advertised but no IOCTL handler
**File**: `src/protocol/smb2/smb2fruit.c:687`
**Issue**: `kAAPL_SUPPORT_RESOLVE_ID` in volume_caps. No `FSCTL_AAPL_RESOLVE_ID` handler. macOS Finder alias resolution silently fails.
**Fix**: Add `FSCTL_AAPL_RESOLVE_ID` case in `smb2_ioctl.c` calling `ksmbd_vfs_resolve_fileid()`. OR remove from advertised caps.
**Complexity**: MEDIUM

### [P1] AAPL-04: AFP_AfpInfo write — DosStream xattr not updated, creating split state
**File**: `src/protocol/smb2/smb2fruit.c:523-540`
**Issue**: Write updates `com.apple.FinderInfo` xattr only. Read reads `XATTR_NAME_AFP_AFPINFO` (DosStream) first. Write and read paths are inconsistent → old value returned after write.
**Fix**: On write, also update `XATTR_NAME_AFP_AFPINFO` with the full 60-byte AFP_AfpInfo structure.
**Complexity**: LOW

### [P1] AAPL-06: AFP_Resource write path completely absent
**File**: `src/protocol/smb2/smb2fruit.c:597-658`
**Issue**: No `ksmbd_fruit_write_resource()`. Resource fork data is stored as ADS or lost — not in the `XATTR_NAME_AFP_RESOURCE` xattr that the read path expects.
**Fix**: Add `ksmbd_fruit_write_resource()` and wire into VFS stream open/read/write path.
**Complexity**: HIGH

### [P1] POSIX-03: SMB_QUERY_POSIX_WHOAMI not implemented
**File**: `src/protocol/smb2/smb2_ioctl.c`
**Issue**: POSIX extensions advertised but `FSCTL_QUERY_POSIX_WHOAMI` (0xC01401BA) has no handler. Linux clients use this for effective UID/GID without per-file round trips.
**Fix**: Add handler returning `current_uid()`, `current_gid()`, supplementary group list.
**Complexity**: MEDIUM

### [P1] POSIX-04: FileStatLxInformation uid/gid/mode fields may not be populated
**File**: `src/fs/ksmbd_info.c:1592`
**Issue**: Verify `LxUid`, `LxGid`, `LxMode`, `LxDeviceIdMajor`, `LxDeviceIdMinor` are all populated. `ls -la` from Linux client shows all files owned by root if not set.
**Fix**: Audit ksmbd_info.c FileStatLx handler and ensure all 5 fields are written from `stat` results.
**Complexity**: LOW

### [P1] SMB1-08: smb_version_ops missing signing callbacks — potential NULL deref
**File**: `src/protocol/smb1/smb1ops.c:37`
**Issue**: `smb1_server_ops.generate_signingkey` is NULL. If any generic code path calls `conn->ops->generate_signingkey()` without a NULL guard: kernel oops.
**Fix**: Either implement `smb1_generate_signingkey()` and assign, or audit ALL call sites for NULL guards.
**Complexity**: MEDIUM

### [P1] SMB1-10: max_write_size = 16MB violates SMB1 MaxBufferSize contract
**File**: `src/protocol/smb1/smb1ops.c:19`
**Issue**: `MaxBufferSize = MAX_STREAM_PROT_LEN = 16MB`. SMB1 MaxBufferSize is typically 65535. Clients may send 16MB WRITE_ANDX requests the SMB1 path cannot handle.
**Fix**: Set `max_write_size = 65535` (or CIFS_DEFAULT_IOSIZE if large WRITE_ANDX tested). Handle `MaxRawSize` separately.
**Complexity**: LOW

### [P1] SMB1-11: LOCKING_ANDX uses msleep() — blocks worker thread for up to UINT_MAX ms
**File**: `src/protocol/smb1/smb1pdu.c` — `smb_locking_andx()`
**Issue**: `msleep(timeout_ms)` in work queue context blocks the connection worker. Client setting `Timeout=0xFFFFFFFF` deadlocks the connection indefinitely.
**Fix**: Convert to async: send `STATUS_PENDING`, use `queue_delayed_work()`. Cap max timeout at 30s.
**Complexity**: HIGH

### [P1] SMB1-13: SESSION_SETUP non-extsec — NTLMv1 response lengths not validated
**File**: `src/protocol/smb1/smb1pdu.c` — `build_sess_rsp_noextsec()`
**Issue**: `CaseSensitivePasswordLength` not validated as exactly 24 bytes for NTLMv1. Variable-length or zero-length values passed to auth subsystem expecting 24 bytes.
**Fix**: Validate lengths == 24 || == 0. Reject non-NTLMv1 lengths with `STATUS_LOGON_FAILURE`.
**Complexity**: LOW

### [P1] SMB1-17: VcNumber=0 doesn't tear down existing sessions — stale sessions linger
**File**: `src/protocol/smb1/smb1pdu.c` — `smb_session_setup_andx()`
**Issue**: Client crash+restart sends VcNumber=0. Old sessions with open files/locks remain. New session cannot re-access files held by stale session.
**Fix**: When `VcNumber == 0`, call `ksmbd_destroy_all_sessions_from_client(conn->peer_addr)` before creating new session.
**Complexity**: MEDIUM

### [P1] F-01: FSCTL_GET_INTEGRITY_INFORMATION — no file handle validation
**File**: `src/fs/ksmbd_fsctl.c:2247`
**Fix**: Add `ksmbd_lookup_fd_fast(work, id)` guard; return STATUS_INVALID_HANDLE if not found.
**Complexity**: LOW

### [P1] F-02: COPYCHUNK total_size_written — signed loff_t vs unsigned int comparison
**File**: `src/fs/ksmbd_fsctl.c:1123`
**Fix**: Use `u64 total_size_written` and `(u64)ksmbd_server_side_copy_max_total_size()` in comparison.
**Complexity**: LOW

### [P1] F-03: COPYCHUNK — cross-filesystem copy not rejected
**File**: `src/fs/ksmbd_fsctl.c:1254`
**Fix**: Compare `file_inode(src_fp->filp)->i_sb != file_inode(dst_fp->filp)->i_sb`; return STATUS_OBJECT_TYPE_MISMATCH.
**Complexity**: LOW

### [P1] F-04: FSCTL_FILE_LEVEL_TRIM — missing FILE_LEVEL_TRIM_OUTPUT response
**File**: `src/fs/ksmbd_fsctl_extra.c:162`
**Fix**: Define 4-byte `file_level_trim_output` struct, populate `NumRangesProcessed`, set `*out_len`.
**Complexity**: LOW

### [P1] F-05: FSCTL_QUERY_FILE_REGIONS — TotalRegionEntryCount equals RegionEntryCount
**File**: `src/fs/ksmbd_fsctl.c:2217`
**Fix**: Track total regions separately; when buffer full, continue counting without writing to get total.
**Complexity**: MEDIUM

### [P1] F-06: FSCTL_PIPE_WAIT — NameLength not validated; potential OOB read
**File**: `src/fs/ksmbd_fsctl_extra.c:207`
**Fix**: Validate `in_buf_len >= sizeof(*req) + le16_to_cpu(req->NameLength)` before accessing Name field.
**Complexity**: LOW

### [P1] F-20: FSCTL_SRV_READ_HASH — -EOPNOTSUPP overrides pre-set STATUS_HASH_NOT_PRESENT
**File**: `src/fs/ksmbd_fsctl.c:2887`
**Fix**: Return 0 (not -EOPNOTSUPP) when setting STATUS_HASH_NOT_PRESENT, so status is preserved.
**Complexity**: LOW

### [P1] F-21: FSCTL_QUERY_ALLOCATED_RANGES — `*out_len` unset on overflow path
**File**: `src/fs/ksmbd_fsctl.c:1796`
**Fix**: Set `*out_len = out_count * sizeof(*out_range)` before returning in the -E2BIG branch.
**Complexity**: LOW

### [P1] F-22: FSCTL_OFFLOAD_WRITE — signed loff_t underflow on copy_len
**File**: `src/fs/ksmbd_fsctl.c:2750`
**Fix**: Decode `token_len`, `xfer_off`, `copy_len` as `u64`. Use `check_sub_overflow` for subtraction.
**Complexity**: MEDIUM

### [P1] F-26: COPYCHUNK — `<=` check rejects valid zero-chunk requests
**File**: `src/fs/ksmbd_fsctl.c:1319`
**Fix**: Change `if (in_buf_len <= sizeof(struct copychunk_ioctl_req))` to `<` (strictly less than).
**Complexity**: LOW

### SMB1 P1

### [P1] SMB1-01: TRANS2_SECONDARY has no reassembly handler
**File**: `src/protocol/smb1/smb1pdu.c` / `smb1ops.c`
**Fix**: Implement per-session fragment buffer. Accumulate on secondary; dispatch when `received >= total`.
**Complexity**: HIGH

### [P1] SMB1-02: NT_TRANSACT_SECONDARY stub — no multi-fragment reassembly
**File**: `src/protocol/smb1/smb1pdu.c` — `smb_nt_transact_secondary()`
**Fix**: Allocate per-connection fragment buffer on primary; accumulate secondary fragments; dispatch when complete.
**Complexity**: HIGH

### [P1] SMB1-03: NT_TRANSACT_IOCTL stub — STATUS_NOT_SUPPORTED
**File**: `src/protocol/smb1/smb1pdu.c` — `smb_nt_transact_ioctl()`
**Fix**: Extract FunctionCode, dispatch to existing ksmbd_vfs_ioctl/ksmbd_fsctl infrastructure.
**Complexity**: HIGH

### [P1] SMB1-04: NT_TRANSACT_NOTIFY_CHANGE — parks requests but delivers no notifications
**File**: `src/protocol/smb1/smb1pdu.c` — `smb_nt_transact_notify_change()`
**Fix**: Integrate with `ksmbd_dnotify`/fsnotify. On directory change: locate parked work items, build FILE_NOTIFY_INFORMATION, send async response.
**Complexity**: HIGH

---

## PHASE 2 — P2 MEDIUM (compliance / correctness / wrong behavior)

### Auth / Negotiate / Session

- **NEG-02**: NegotiateContextOffset not validated as zero for pre-3.1.1 dialects → STATUS_INVALID_PARAMETER
  `smb2_negotiate.c:798-829` | LOW
- **NEG-06**: Compression algorithm selection uses client order not server preference
  `smb2_negotiate.c:448-464` | LOW
- **SES-01**: Channel binding signing key doc comment misleading about which key is used
  `smb2_session.c:859-866` | LOW (documentation)
- **SES-04**: KRB5 path — add NULL check assertion on `sess->user` before `destroy_previous_session`
  `smb2_session.c:564-567` | LOW
- **AUTH-04**: NTLMv2 blob AvPairs minimum size comment and enforcement inconsistent
  `auth.c:680-719` | LOW
- **PROTO-02**: Missing SIGNING_CAPABILITIES duplicate context check (no `sign_ctxt_seen` bool)
  `smb2_negotiate.c:730-738` | LOW
- **PROTO-03**: POSIX_EXTENSIONS_AVAILABLE duplicate context not checked
  `smb2_negotiate.c:708-711` | LOW
- **PROTO-04**: TRANSPORT_CAPABILITIES duplicate context not checked
  `smb2_negotiate.c:712-718` | LOW
- **PROTO-06**: Decryption of requests for EXPIRED sessions — no rate limiting
  `auth.c:1657-1668` | MEDIUM
- **CRYPTO-02**: Keyed algorithm TFMs stateful — add `setkey` assertion before `init`
  `crypto_ctx.c:226-244` | MEDIUM

### Transport / Credits / Crypto

- **TC-01**: active_num_conn leaked on connection failure when max_connections==0
  `transport_tcp.c:341-358` | LOW
- **TC-03**: `smb2_set_rsp_credits` reads `total_credits` outside `credits_lock`
  `smb2_pdu_common.c:427-431` | LOW
- **TC-05**: Credit return codes — use named constants for clarity
  `smb2misc.c:377-401` | LOW
- **TC-07**: Related compound sub-request signing — document that first request gates the whole chain
  `smb2_pdu_common.c:1118-1119` | LOW
- **TC-15**: IPC RPC response payload_sz not bounded before OOB access
  `transport_ipc.c:606-616` | LOW
- **TC-19**: QUIC spinlock held during 128KB memcpy at softirq level
  `transport_quic.c:2250-2260` | MEDIUM
- **TC-23**: Compress response length overflow — add explicit check
  `smb2_compress.c:1926-1929` | LOW
- **TC-25**: IPC share config payload_sz bound check implicit not explicit
  `transport_ipc.c:635-651` | LOW

### VFS / ACL

- **VFS-04**: `ksmbd_vfs_stream_read` sets `count = -EINVAL` on `size_t count` — type confusion
  `vfs.c:683` | LOW
- **VFS-08**: `path_is_under` post-creation check validates location not symlink target
  `ksmbd_reparse.c:357` | LOW (remove misleading check)
- **VFS-12**: Symlink target not bounded to PATH_MAX
  `vfs.c:1252` | LOW
- **VFS-15**: setattr TOCTOU — no re-validation after `inode_lock`
  `vfs.c:1202` | LOW
- **VFS-16**: Double `list_del` of fp->node in `__close_file_table_ids`
  `vfs_cache.c:1229` | LOW
- **VFS-17**: copy_xattrs uses `nop_mnt_idmap`/`init_user_ns` not actual mount idmap
  `vfs.c:2279` | MEDIUM
- **VFS-21**: `path_sz + 1` arithmetic underflow on short `ab_pathname`
  `vfs_cache.c:1599` | LOW
- **ACL-01**: NULL owner/group SID passed to `parse_dacl` silently (permission degradation)
  `smbacl.c:1627` | LOW
- **REPARSE-02**: ucs2_buf allocation size not overflow-checked
  `ksmbd_reparse.c:923` | LOW
- **XATTR-02**: ObjectId in `user.*` namespace — forgeable
  `xattr.h:129` | LOW

### QueryInfo / SetInfo

- **QSA-03**: FILE_NAMES_INFORMATION (class 12) has no handler
  `smb2_query_set.c` | MEDIUM
- **QSA-05**: FILE_QUOTA_INFORMATION GET returns empty response (should be minimal struct)
  `ksmbd_info.c:1475` | LOW
- **QSA-10**: SL_RETURN_SINGLE_ENTRY flag not enforced for multi-EA GET
  `smb2_query_set.c:239` | LOW
- **QSA-11**: FS_SIZE_INFORMATION uses `f_bfree` instead of `f_bavail`
  `smb2_query_set.c:1749` | LOW
- **QSA-12**: FS_LABEL_INFORMATION GET handler missing
  `smb2_query_set.c` | LOW
- **QSA-15**: FileRenameInformationEx FILE_RENAME_POSIX_SEMANTICS flag discarded
  `smb2_query_set.c:3392` | MEDIUM
- **QSA-19**: FileCompressionInfo CompressionUnitShift always 0 for compressed files
  `smb2_query_set.c:1056` | LOW
- **QSA-20**: FileHardLinkInformation — unbounded O(n) dir scan (DoS via large directory)
  `ksmbd_info.c:764` | MEDIUM
- **QSA-23**: FILE_DISPOSITION_ON_CLOSE flag mapped to DeletePending (needs documentation)
  `smb2_query_set.c:3266` | MEDIUM
- **QSA-24**: FileObjectIdInformation — verify sizeof struct == 64 bytes
  `smb2_query_set.c:1299` | LOW
- **QSA-25**: SET_INFO noop handler accepts 0-byte buffer (STATUS_INFO_LENGTH_MISMATCH)
  `ksmbd_info.c:465-476` | LOW

### IOCTL / FSCTL

- **F-07**: FSCTL_SET_COMPRESSION — missing per-handle daccess check
  `ksmbd_fsctl.c:592` | LOW
- **F-08**: FSCTL_SET_COMPRESSION — COMPRESSION_FORMAT_DEFAULT (0x0001) rejected
  `ksmbd_fsctl.c:604` | LOW
- **F-09**: FSCTL_GET_RETRIEVAL_POINTERS — Lcn should be -1 (no mapping), not VCN
  `ksmbd_fsctl.c:923` | LOW
- **F-10**: FSCTL_FILESYSTEM_GET_STATS — NTFS type requires NTFS_STATISTICS tail (208 bytes)
  `ksmbd_fsctl.c:1966` | MEDIUM
- **F-11**: FSCTL_QUERY_NETWORK_INTERFACE_INFO — Next field hardcoded 152 (should be sizeof struct)
  `ksmbd_fsctl.c:994` | LOW
- **F-13**: FSCTL_SET_ZERO_ON_DEALLOCATION — missing FILE_WRITE_DATA access check
  `ksmbd_fsctl.c:2017` | LOW
- **F-14**: FSCTL_MARK_HANDLE — no minimum input buffer size check
  `ksmbd_fsctl.c:1605` | LOW
- **F-16**: REQUEST_OPLOCK_LEVEL_1/2/BATCH stubs return success — should be NOT_GRANTED
  `ksmbd_fsctl.c:3084` | LOW
- **F-25**: FSCTL_PIPE_TRANSCEIVE — ENOTIMPLEMENTED returns success with 0 bytes
  `ksmbd_fsctl.c:1925` | LOW
- **F-27**: FSCTL_OFFLOAD_READ — sector size hardcoded to 512 (should use bdev block size)
  `ksmbd_fsctl.c:2620` | LOW
- **F-30**: FSCTL_VALIDATE_NEGOTIATE_INFO — strict capabilities check breaks some clients
  `ksmbd_fsctl.c:1853` | LOW

### Read / Write / Lock

- **RW-001**: check_lock_range loff_t signed overflow on `*pos + count - 1`
  `vfs.c:801` | LOW
- **RW-002**: Zero-length buffered READ → allocation of 0 bytes returns -ENOMEM not success
  `smb2_read_write.c:604` | LOW
- **RW-003**: RDMA WRITE — bounds checks use pre-overwrite `req->Length` not `RemainingBytes`
  `smb2_read_write.c:894` | LOW
- **CA-001**: CANCEL for not-found sends STATUS_NOT_FOUND; spec requires silent drop
  `smb2_lock.c:251-258` | LOW
- **FL-001**: FLUSH TOCTOU — second fp lookup can fail after access check passed
  `smb2_read_write.c:1199` | LOW
- **LK-003**: Lock rollback double-free of `file_lock` via `locks_free_lock` after `vfs_lock_file(F_UNLCK)`
  `smb2_lock.c:1077-1094` | MEDIUM
- **LK-004**: Cancel argv — possible UAF if cancel_fn has async behavior after kfree
  `smb2_lock.c:140-142` | MEDIUM
- **LK-005**: Blocking lock interim/cancel race — check for cancellation before sending interim
  `smb2_lock.c:984` | MEDIUM
- **LK-006**: Signal/lock-grant race — after signal-interrupted wait, VFS may have granted lock
  `smb2_lock.c:324-328` | HIGH
- **LK-007**: Per-request lock overlap check uses containment, not general overlap
  `smb2_lock.c:696-710` | LOW
- **RW-006**: Sendfile path skips share boundary check (defense-in-depth)
  `smb2_read_write.c:533-588` | LOW
- **RW-008**: check_lock_range — `*pos + count - 1` overflow bypasses lock checking
  `vfs.c:801` | LOW (same as RW-001 but for read path)
- **RW-009**: RDMA channel descriptor count not validated as multiple of 24
  `smb2_read_write.c:437` | LOW
- **SEC-001**: Pipe write error code mapping — -EINVAL → STATUS_INVALID_PARAMETER
  `smb2_read_write.c:758` | LOW
- **RW-010**: stream_read `count = -EINVAL` on `size_t count` → huge nbytes
  `vfs.c:683` | LOW (same root as VFS-04)
- **SEC-002**: WRITE DataOffset compound boundary check needs NextCommand cap
  `smb2_read_write.c:1056-1065` | MEDIUM

### Apple / POSIX / Mgmt

- **AAPL-05**: Time Machine quota reads whole-FS used bytes, not TM directory
  `smb2fruit.c:557-593` | HIGH
- **AAPL-07**: AAPL negotiation state set during CREATE (not atomic with success)
  `smb2_create.c:2709` | MEDIUM
- **POSIX-05**: POSIX unlink xattr cleanup order — audit xattr cleanup vs vfs_unlink ordering
  `vfs.c` | MEDIUM
- **IPC-03**: Witness iface list TOCTOU between count pass and fill pass
  `transport_ipc.c:1275-1336` | LOW
- **IPC-04**: Daemon restart doesn't re-apply server config
  `transport_ipc.c:501-519` | MEDIUM
- **SHARE-02**: share_config_path() — path not validated as NUL-terminated
  `ksmbd_netlink.h:223-234` | LOW
- **NETLINK-02**: spnego_blob_len is __u16 (64KB limit) — Kerberos PAC can exceed
  `ksmbd_netlink.h:297-310` | MEDIUM (ABI change, requires daemon coordination)

### SMB1 P2

- **SMB1-05**: TRANS2_GET_DFS_REFERRAL not implemented (ensure CAP_DFS never set when DFS configured)
  `smb1pdu.c` | HIGH
- **SMB1-06**: TRANS2_OPEN2 not implemented (conflicts with advertised CAP_NT_FIND)
  `smb1pdu.c` | HIGH
- **SMB1-07**: SMB_COM_WRITE 32-bit offset — reject writes to offsets ≥ 4GB
  `smb1pdu.c:~3561` | LOW
- **SMB1-14**: TRANS2_FIND_FIRST RETURN_RESUME_KEYS ignored
  `smb1pdu.c:~6607` | MEDIUM
- **SMB1-15**: set_path_info missing RENAME_INFORMATION and ALLOCATION_INFO
  `smb1pdu.c:~6237` | MEDIUM
- **SMB1-16**: OPEN_ANDX Action field wrong for SUPERSEDE/OVERWRITE
  `smb1pdu.c:~8840` | LOW
- **SMB1-26**: CAP_MPX_MODE advertised without MID multiplexing
  `smb1pdu.h` / `smb1ops.c` | HIGH

---

## PHASE 3 — P3 POLISH (minor / documentation / low-risk)

### Auth / Negotiate
- **AUTH-03**: generate_key() — document constraint: key_size <= 32 bytes. Add WARN_ON
- **PROTO-01**: Binding path signing — add comment confirming Session.SigningKey is correct per spec
- **PROTO-05**: StructureSize not validated in NEGOTIATE/SESSION_SETUP (may already be done by smb2misc)
- **SES-05**: Rate limiting on session setup — TCP delay insufficient for brute force

### Transport
- **TC-09**: kvec_array_init — add WARN_ON(base > new->iov_len) guard
- **TC-20**: QUIC IPC handle sentinel — use bool flag instead of -1 sentinel
- **TC-21**: Connection handler `int size` — declare as `unsigned int` or `size_t`

### VFS
- **VFS-12**: Symlink target NUL termination validation
- **VFS-13**: `ksmbd_vfs_readdir_name` returns -ENOMEM masking real error (return rc)
- **REPARSE-01**: Confirm `smb_strndup_from_utf16` always NUL-terminates

### QueryInfo
- **QSA-04**: FILE_COMPRESSION SET — register handler returning -EOPNOTSUPP
- **QSA-06**: Add #define constants for missing info classes 41-43
- **QSA-14**: Remove dead `< 0` check after u64 guard in FILE_POSITION SET
- **QSA-17**: Move `smb2_file_standard_link_info` struct to smb2pdu.h
- **QSA-18**: Replace `SMB2_NO_FID` with `FILE_QUOTA_NOT_ENFORCED` for FS_CONTROL response

### IOCTL / FSCTL
- **F-12**: FSCTL_PIPE_PEEK — ensure header is correctly populated (ReadDataAvailable=0 explicit)
- **F-15**: FSCTL_CREATE_OR_GET_OBJECT_ID — populate BirthVolumeId from s_dev
- **F-17**: FSCTL_ALLOW_EXTENDED_DASD_IO — validate file handle or return NOT_SUPPORTED
- **F-18**: FSCTL_LOCK/UNLOCK_VOLUME — return NOT_SUPPORTED honestly
- **F-19**: FSCTL_IS_PATHNAME_VALID — validate non-empty UTF-16LE path
- **F-23**: FSCTL_QUERY_SPARING_INFO — return proper 0-value response not NOT_SUPPORTED
- **F-24**: FSCTL_SET_SHORT_NAME_BEHAVIOR — validate FID or map to not_supported
- **F-28**: FSCTL_GET_NTFS_VOLUME_DATA — comment: MFT fields are Linux-approximations
- **F-29**: FSCTL_LMR_SET_LINK_TRACK_INF — change to not_supported_handler for consistency

### Read / Write / Lock
- **FL-002**: WRITE_THROUGH for RDMA — use `vfs_fsync` not `vfs_fsync_range` for metadata durability
- **EC-001**: ECHO bad StructureSize — set explicit STATUS_INVALID_PARAMETER before returning
- **LK-001**: zero_len flag semantics — use explicit `lock_length == 0` check
- **LK-002**: Same-handle shared lock conflict check — document VFS handles upgrade correctly
- **RW-004**: WRITE_THROUGH RDMA — add comment on nbytes accounting correctness

### Apple / SMB1 / Mgmt
- **AAPL-01**: Remove or wire `fruit_build_server_response()` dead code
- **SHARE-01**: Add named defines for SMB2_SHAREFLAG_AUTO/VDO/NO_CACHING
- **TREE-01**: Remove redundant second `t_state = TREE_CONNECTED` in smb2_tree_connect
- **SMB1-12**: smb_trans() — mailslot path: return STATUS_SUCCESS silently for browse traffic
- **SMB1-18**: smb_echo() — remove min-10 cap; add 256 limit with explicit rejection
- **SMB1-20**: ServerTimeZone hardcoded to 0 — populate from `sys_tz.tz_minuteswest`
- **SMB1-21**: SMB_COM_FIND — change STATUS_NOT_IMPLEMENTED to STATUS_NOT_SUPPORTED
- **SMB1-22**: NT_TRANSACT quota stubs — implement via `vfs_get_dqblk`/`vfs_set_dqblk`

---

## AGENT H SCOPE (QueryDir/Notify/DFS/VSS — NOT AUDITED)

Agent H ran out of quota before completing. The following files need a follow-up audit:
- `src/protocol/smb2/smb2_dir.c` — QUERY_DIRECTORY (SMB_FIND_* info levels, wildcards, restart)
- `src/fs/ksmbd_notify.c` — CHANGE_NOTIFY async delivery, filter bits
- `src/fs/ksmbd_dfs.c` — DFS referral correctness, loop detection, domain referrals
- `src/fs/ksmbd_vss.c` — VSS snapshot enumeration, token correctness

Schedule a follow-up V11b audit for these files.

---

## IMPLEMENTATION PLAN

### Wave 1 — P0 Crash/Security (implement in parallel, 3-4 subagents)
**Target**: All ~24 P0 items
**Files**: vfs_cache.c, vfs.c, smbacl.c, auth.c, smb2_session.c, smb2_negotiate.c, smb2_compress.c, transport_ipc.c, share_config.c, smb2_dir.c, smb2_create.c, smb2_query_set.c, smb1pdu.c, smb2fruit.c, ksmbd_netlink.h, smb2pdu.h
**Subagents**:
- Sub-A: VFS/ACL P0s (VFS-01, VFS-06, VFS-11, VFS-14, VFS-18, VFS-20, QSA-09, QSA-13, QSA-22)
- Sub-B: Auth/Negotiate P0s (NEG-03, SES-02, SES-03, AUTH-05, TC-02, TC-06, TC-10, TC-16)
- Sub-C: Infrastructure P0s (MGMT-01, IPC-02, NETLINK-01, POSIX-01/02)
- Sub-D: SMB1/Apple P0s (SMB1-09, SMB1-19, SMB1-23, SMB1-24, SMB1-25, AAPL-02)

### Wave 2 — P1 High (3-4 subagents)
**Target**: P1 auth/crypto/transport items
**Subagents by domain**:
- Sub-A: Auth/Session P1s (NEG-04/05, SES-06/07, AUTH-01/02/06, CRYPTO-01, SES-04/05)
- Sub-B: Transport/Compress P1s (TC-04/08/11/12/13/14/17/18/22/24, TC-01/03/05/07)
- Sub-C: VFS/ACL/IOCTL P1s (VFS-02/03/05/07/09/10, ACL-02/03/04, XATTR-01, VFS-19, F-01/02/03/04/05/06/20/21/22/26)
- Sub-D: Protocol P1s (QSA-01/02/08/16, MULTI-01/02/03, MGMT-02/03, IPC-01, POSIX-03/04, AAPL-03/04/06, SMB1-01/02/03/04/08/10/11/13/17)

### Wave 3 — P2 Compliance (opportunistic, can be parallel)
All P2 items above, grouped by file domain.

### Wave 4 — P3 Polish
All P3 items — low-risk cleanup pass.

### Agent H Follow-up (V11b)
Spawn 1 dedicated audit agent for smb2_dir.c + ksmbd_notify.c + ksmbd_dfs.c + ksmbd_vss.c.

---

## TOTALS BY SEVERITY

| Severity | Count |
|----------|-------|
| P0 Critical | 24 |
| P1 High | ~80 |
| P2 Medium | ~75 |
| P3 Polish | ~35 |
| **Total** | **~214** |

(Plus ~20 additional from Agent H scope, pending V11b audit)
