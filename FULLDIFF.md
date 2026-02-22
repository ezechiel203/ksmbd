# KSMBD Full Diff — All Fixes Applied

> Complete record of every code change made to address the issues identified
> in FULLREVIEW.md. Each entry includes the file, line numbers, previous code,
> new code, and the precise rationale for the change.
>
> **13 files changed, 147 insertions, 53 deletions.**

---

## Table of Contents

1. [Security-Critical Fixes](#security-critical-fixes)
   - [1.1 Timing side-channels (auth.c, smb2pdu.c, user_config.c)](#11-timing-side-channels)
   - [1.2 IOV array OOB write (ksmbd_work.c)](#12-iov-array-oob-write)
   - [1.3 UAF in oplock conn (oplock.c, vfs_cache.c)](#13-uaf-in-oplock-conn-reference)
   - [1.4 Key material zeroing (user_session.c, user_config.c)](#14-key-material-not-zeroed)
   - [1.5 Signing enforcement (smb2pdu.c)](#15-signing-enforcement)
   - [1.6 Tree connect bounds (smb2pdu.c)](#16-tree-connect-path-bounds)
   - [1.7 NegotiateContextCount cap (smb2pdu.c)](#17-negotiatecontextcount-cap)
2. [Correctness Fixes](#correctness-fixes)
   - [2.1 Session refcount leak (user_session.c)](#21-session-refcount-leak)
   - [2.2 NDR return value (ndr.c)](#22-ndr-return-value-ignored)
   - [2.3 NDR memory leak (ndr.c)](#23-ndr-memory-leak-on-error)
   - [2.4 ChunkBytesWritten (smb2pdu.c)](#24-chunkbyteswritten-always-zero)
   - [2.5 Zero file IDs (smb2pdu.c)](#25-zero-file-ids-for-dot-files-only)
   - [2.6 Negotiate error status (smb2pdu.c)](#26-negotiate-error-status-overwrite)
   - [2.7 NextCommand alignment (smb2misc.c)](#27-nextcommand-alignment)
   - [2.8 Lock count bound (smb2misc.c)](#28-lock-count-overflow)
   - [2.9 Durable FD double-free (vfs_cache.c)](#29-durable-fd-double-free)
   - [2.10 smb3_set_sign_rsp (smb2pdu.c)](#210-smb3_set_sign_rsp-silent-failure)
   - [2.11 xattr copy filter (vfs.c)](#211-xattr-copy-filter)
3. [Concurrency Fixes](#concurrency-fixes)
   - [3.1 ksmbd_conn_free ordering (connection.c)](#31-ksmbd_conn_free-ordering)
   - [3.2 stop_sessions UAF (connection.c)](#32-stop_sessions-uaf)
   - [3.3 Tree connect TOCTOU (tree_connect.c)](#33-tree-connect-toctou)
4. [Apple/Fruit Fixes](#applefruit-fixes)
   - [4.1 TM Lock Steal (smb2fruit.h, oplock.c)](#41-tm-lock-steal-capability)
   - [4.2 Remove NFS ACE (oplock.c)](#42-remove-nfs-ace-advertisement)
   - [4.3 Remove RESOLVE_ID (oplock.c)](#43-remove-resolve_id-advertisement)
   - [4.4 AFP_AfpInfo write-back (vfs.c)](#44-afp_afpinfo-write-back)

---

## Security-Critical Fixes

### 1.1 Timing Side-Channels

**Issue:** `memcmp` and `strncmp` short-circuit on the first differing byte,
leaking information about how many leading bytes match via timing measurements.

**Fix:** Replace all cryptographic comparisons with `crypto_memneq()` from
`<crypto/algapi.h>`, which always compares all bytes in constant time.

#### auth.c — NTLMv2 response comparison

**File:** `auth.c:434`

```diff
- if (memcmp(ntlmv2->ntlmv2_hash, ntlmv2_rsp, CIFS_HMAC_MD5_HASH_SIZE) != 0)
+ if (crypto_memneq(ntlmv2->ntlmv2_hash, ntlmv2_rsp, CIFS_HMAC_MD5_HASH_SIZE))
```

**Rationale:** The NTLMv2 HMAC-MD5 hash comparison is the final authentication
gate. A timing oracle here allows a network attacker to progressively narrow
the search space for the correct hash. `crypto_memneq` eliminates this by
always performing a full 16-byte comparison regardless of where differences
occur.

#### auth.c — NTLMv1 response comparison (CONFIG_SMB_INSECURE_SERVER)

**File:** `auth.c:347`

```diff
- if (strncmp(pw_buf, key, CIFS_AUTH_RESP_SIZE) != 0) {
+ if (crypto_memneq(pw_buf, key, CIFS_AUTH_RESP_SIZE)) {
```

**Rationale:** Same timing issue. `strncmp` is even worse than `memcmp` because
it also short-circuits on NUL bytes.

#### auth.c — Added include

**File:** `auth.c:16`

```diff
  #include <crypto/aead.h>
+ #include <crypto/algapi.h>
```

#### smb2pdu.c — SMB2 signature verification

**File:** `smb2pdu.c:9673`

```diff
- if (memcmp(signature, signature_req, SMB2_SIGNATURE_SIZE)) {
+ if (crypto_memneq(signature, signature_req, SMB2_SIGNATURE_SIZE)) {
```

**Rationale:** SMB2 HMAC-SHA256 signature verification. Same timing side-channel.

#### smb2pdu.c — SMB3 signature verification

**File:** `smb2pdu.c:9761`

```diff
- if (memcmp(signature, signature_req, SMB2_SIGNATURE_SIZE)) {
+ if (crypto_memneq(signature, signature_req, SMB2_SIGNATURE_SIZE)) {
```

**Rationale:** SMB3 AES-CMAC signature verification. Same timing side-channel.

#### smb2pdu.c — Added include

**File:** `smb2pdu.c:21`

```diff
+ #include <crypto/algapi.h>
```

#### mgmt/user_config.c — Passkey comparison

**File:** `mgmt/user_config.c:105`

```diff
- if (memcmp(u1->passkey, u2->passkey, u1->passkey_sz))
+ if (crypto_memneq(u1->passkey, u2->passkey, u1->passkey_sz))
```

**Rationale:** `ksmbd_compare_user()` compares NT password hashes. The timing
leak here enables an attacker who can trigger user comparisons (e.g., via
repeated session setup) to distinguish partial hash matches.

#### mgmt/user_config.c — Added include

**File:** `mgmt/user_config.c:8`

```diff
  #include <linux/mm.h>
+ #include <crypto/algapi.h>
```

---

### 1.2 IOV Array OOB Write

**Issue:** `__ksmbd_iov_pin()` pre-increments `iov_idx` before writing to the
array. The caller's bounds check uses `iov_cnt` (which can diverge from
`iov_idx` due to the RFC1001 header slot), allowing a write past the end
of the `iov` array.

#### ksmbd_work.c — Separate increment from array access

**File:** `ksmbd_work.c:108-109`

```diff
  static inline void __ksmbd_iov_pin(struct ksmbd_work *work, void *ib,
                                     unsigned int ib_len)
  {
- 	work->iov[++work->iov_idx].iov_base = ib;
+ 	work->iov_idx++;
+ 	work->iov[work->iov_idx].iov_base = ib;
  	work->iov[work->iov_idx].iov_len = ib_len;
  	work->iov_cnt++;
  }
```

**Rationale:** Separating the increment makes the code clearer and enables
the caller to check bounds accurately before the array write occurs.

#### ksmbd_work.c — Fix bounds check to use iov_idx

**File:** `ksmbd_work.c:127`

```diff
- if (work->iov_alloc_cnt < work->iov_cnt + need_iov_cnt) {
+ if (work->iov_alloc_cnt < work->iov_idx + 1 + need_iov_cnt) {
```

**Rationale:** `iov_cnt` includes the RFC1001 header entry which doesn't
advance `iov_idx`. Using `iov_idx + 1` (the next position that will be
written) ensures the realloc triggers before, not after, the OOB write.

---

### 1.3 UAF in Oplock Conn Reference

**Issue:** `kfree(opinfo->conn)` directly frees the connection object,
bypassing `ksmbd_conn_free()` which handles transport cleanup. Other opinfos
and sessions may still reference the same conn, causing use-after-free.

#### oplock.c — free_opinfo()

**File:** `oplock.c:135-137`

```diff
  	if (opinfo->is_lease)
  		free_lease(opinfo);
- 	if (opinfo->conn && atomic_dec_and_test(&opinfo->conn->refcnt))
- 		kfree(opinfo->conn);
+ 	if (opinfo->conn)
+ 		atomic_dec(&opinfo->conn->refcnt);
+ 	opinfo->conn = NULL;
  	kfree(opinfo);
```

**Rationale:** The connection lifecycle is managed by `ksmbd_conn_free()` which
is called from the handler thread. Decrementing the refcount without freeing
allows the proper teardown path to run when the last reference is dropped.

#### vfs_cache.c — session_fd_check()

**File:** `vfs_cache.c:974-980`

```diff
  	list_for_each_entry_rcu(op, &ci->m_op_list, op_entry) {
  		if (op->conn != conn)
  			continue;
- 		if (op->conn && atomic_dec_and_test(&op->conn->refcnt))
- 			kfree(op->conn);
+ 		if (op->conn)
+ 			atomic_dec(&op->conn->refcnt);
  		op->conn = NULL;
  	}
```

**Rationale:** Same issue. Multiple oplock entries in the list may share the
same `conn` pointer. If the first iteration frees conn, subsequent iterations
accessing the same conn dereference freed memory.

---

### 1.4 Key Material Not Zeroed

**Issue:** Session keys, signing keys, encryption keys, and password hashes
are freed with `kfree()` without being scrubbed. Key material persists in
freed heap pages, recoverable via kernel memory disclosure or speculation.

#### mgmt/user_config.c — ksmbd_free_user()

**File:** `mgmt/user_config.c:90`

```diff
- kfree(user->passkey);
+ kfree_sensitive(user->passkey);
```

**Rationale:** `user->passkey` contains the NT password hash.
`kfree_sensitive()` calls `memzero_explicit()` before freeing.

#### mgmt/user_session.c — free_channel_list()

**File:** `mgmt/user_session.c:38`

```diff
  	xa_for_each(&sess->ksmbd_chann_list, index, chann) {
  		xa_erase(&sess->ksmbd_chann_list, index);
+ 		memzero_explicit(chann->smb3signingkey, sizeof(chann->smb3signingkey));
  		kfree(chann);
  	}
```

**Rationale:** Each channel has its own SMB3 signing key that must be scrubbed.

#### mgmt/user_session.c — ksmbd_session_destroy()

**File:** `mgmt/user_session.c:170-178`

```diff
  	free_channel_list(sess);
- 	kfree(sess->Preauth_HashValue);
+ 	memzero_explicit(sess->sess_key, sizeof(sess->sess_key));
+ 	memzero_explicit(sess->smb3encryptionkey, sizeof(sess->smb3encryptionkey));
+ 	memzero_explicit(sess->smb3decryptionkey, sizeof(sess->smb3decryptionkey));
+ 	memzero_explicit(sess->smb3signingkey, sizeof(sess->smb3signingkey));
+ 	kfree_sensitive(sess->Preauth_HashValue);
  	ksmbd_release_id(&session_ida, sess->id);
- 	kfree(sess);
+ 	kfree_sensitive(sess);
```

**Rationale:** The session struct contains `sess_key` (16 bytes),
`smb3encryptionkey`, `smb3decryptionkey`, `smb3signingkey` (each 32 bytes),
and `Preauth_HashValue`. All are cryptographic material that must be zeroed.
`kfree_sensitive(sess)` ensures the entire struct (including inline key
fields) is zeroed before the page is freed.

#### mgmt/user_session.c — Added include

**File:** `mgmt/user_session.c:10`

```diff
  #include <linux/xarray.h>
+ #include <linux/string.h>
```

---

### 1.5 Signing Enforcement

**Issue:** `smb2_is_sign_req()` only verified signatures when the client set
`SMB2_FLAGS_SIGNED`. A MitM attacker could strip the flag, causing the server
to process unsigned (potentially tampered) requests.

#### smb2pdu.c — smb2_is_sign_req()

**File:** `smb2pdu.c:9622-9635`

```diff
  bool smb2_is_sign_req(struct ksmbd_work *work, unsigned int command)
  {
  	struct smb2_hdr *rcv_hdr2 = smb2_get_msg(work->request_buf);

- 	if ((rcv_hdr2->Flags & SMB2_FLAGS_SIGNED) &&
- 	    command != SMB2_NEGOTIATE_HE &&
- 	    command != SMB2_SESSION_SETUP_HE &&
- 	    command != SMB2_OPLOCK_BREAK_HE)
+ 	if (command == SMB2_NEGOTIATE_HE ||
+ 	    command == SMB2_SESSION_SETUP_HE ||
+ 	    command == SMB2_OPLOCK_BREAK_HE)
+ 		return false;
+
+ 	if ((rcv_hdr2->Flags & SMB2_FLAGS_SIGNED) ||
+ 	    (work->sess && work->sess->sign))
  		return true;

  	return false;
  }
```

**Rationale:** Per MS-SMB2, once signing is negotiated the server MUST reject
unsigned requests (except NEGOTIATE, SESSION_SETUP, OPLOCK_BREAK). The new
logic first excludes exempt commands, then returns true if either the client
flag is set OR the session requires signing (`sess->sign`).

---

### 1.6 Tree Connect Path Bounds

**Issue:** `PathOffset` and `PathLength` from the client are used to index
into the request buffer without validating they fit within the received PDU.

#### smb2pdu.c — smb2_tree_connect()

**File:** `smb2pdu.c:2003-2007`

```diff
  	WORK_BUFFERS(work, req, rsp);

+ 	if (le16_to_cpu(req->PathOffset) + le16_to_cpu(req->PathLength) >
+ 	    get_rfc1002_len(work->request_buf) + 4) {
+ 		rc = -EINVAL;
+ 		goto out_err1;
+ 	}
+
  	treename = smb_strndup_from_utf16(...)
```

**Rationale:** A crafted PDU with inflated `PathOffset` causes `smb_from_utf16`
to read past the end of the request buffer, leaking kernel heap memory or
causing a crash. The check validates the combined offset+length fits within
the actual received data.

---

### 1.7 NegotiateContextCount Cap

**Issue:** `NegotiateContextCount` from the client is used as a loop bound
with no upper limit. A malicious value of 65535 causes excessive iteration.

#### smb2pdu.c — deassemble_neg_contexts()

**File:** `smb2pdu.c:1031-1034`

```diff
  	len_of_ctxts = len_of_smb - offset;

+ 	if (neg_ctxt_cnt > 16) {
+ 		pr_err("Too many negotiate contexts: %d\n", neg_ctxt_cnt);
+ 		return -EINVAL;
+ 	}
+
  	while (i++ < neg_ctxt_cnt) {
```

**Rationale:** SMB3.1.1 defines at most 6 negotiate context types. Capping at
16 allows generous headroom while preventing CPU waste from malicious packets.

---

## Correctness Fixes

### 2.1 Session Refcount Leak

**Issue:** `ksmbd_session_lookup_all()` acquires a session reference via
`ksmbd_session_lookup()` but does not release it when the session state
is not `SMB2_SESSION_VALID`, leaking the reference.

#### mgmt/user_session.c — ksmbd_session_lookup_all()

**File:** `mgmt/user_session.c:349-352`

```diff
- if (sess && sess->state != SMB2_SESSION_VALID)
- 	sess = NULL;
+ if (sess && sess->state != SMB2_SESSION_VALID) {
+ 	ksmbd_user_session_put(sess);
+ 	sess = NULL;
+ }
```

**Rationale:** Without the put, the refcount never reaches zero, preventing
session cleanup. Over time on busy servers, this exhausts kernel memory.

---

### 2.2 NDR Return Value Ignored

**Issue:** `ndr_read_bytes()` return value was silently discarded. On buffer
underflow, `acl->desc` contains uninitialized data.

#### ndr.c — ndr_decode_v4_ntacl()

**File:** `ndr.c:531`

```diff
- ndr_read_bytes(n, acl->desc, 10);
+ ret = ndr_read_bytes(n, acl->desc, 10);
+ if (ret)
+ 	return ret;
```

**Rationale:** If the NDR buffer is shorter than expected, the read fails
silently and the subsequent `strncmp` compares garbage, potentially accepting
a malformed ACL.

---

### 2.3 NDR Memory Leak on Error

**Issue:** In `ndr_encode_dos_attr()`, after `kzalloc` of `n->data`, every
`return ret;` on error leaks the allocation.

#### ndr.c — ndr_encode_dos_attr()

**File:** `ndr.c:188-235`

All `return ret;` after the allocation changed to `goto err_free;`, with
the error label added:

```diff
  	if (ret)
- 		return ret;
+ 		goto err_free;

     ... (same pattern for all 9 error returns) ...

  	if (da->version == 3)
  		ret = ndr_write_int64(n, da->change_time);
- 	return ret;
+ 	if (ret)
+ 		goto err_free;
+
+ 	return 0;
+
+ err_free:
+ 	kfree(n->data);
+ 	n->data = NULL;
+ 	return ret;
  }
```

**Rationale:** Under memory pressure, `ndr_write_*` functions call `krealloc`
which can fail. Each failure previously leaked the original `n->data` buffer.
The cleanup label ensures the buffer is freed and the pointer NULLed on all
error paths.

---

### 2.4 ChunkBytesWritten Always Zero

**Issue:** `chunk_size_written` was initialized to 0 and never updated, so
the FSCTL_SRV_COPYCHUNK response always reported 0 bytes written in the
last chunk.

#### smb2pdu.c — fsctl_copychunk()

**File:** `smb2pdu.c:8583-8596`

```diff
+ 	/*
+ 	 * If chunks were successfully written, compute the last chunk's
+ 	 * written size from total_size_written minus the preceding chunks.
+ 	 */
+ 	if (chunk_count_written > 0) {
+ 		loff_t preceding = 0;
+
+ 		for (i = 0; i + 1 < chunk_count_written; i++)
+ 			preceding += le32_to_cpu(chunks[i].Length);
+ 		chunk_size_written = (unsigned int)(total_size_written - preceding);
+ 	}
+
  	ci_rsp->ChunksWritten = cpu_to_le32(chunk_count_written);
  	ci_rsp->ChunkBytesWritten = cpu_to_le32(chunk_size_written);
```

**Rationale:** Per MS-SMB2, `ChunkBytesWritten` should report the number of
bytes written in the last (potentially partial) chunk. The preceding chunks'
lengths are known from the request; subtracting them from `total_size_written`
yields the last chunk's actual write count.

---

### 2.5 Zero File IDs for Dot Files Only

**Issue:** `KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID` zeroed `UniqueId` for ALL
files, not just dot files. This breaks Finder operations that depend on
unique file IDs.

#### smb2pdu.c — smb2_populate_readdir_entry() (two locations)

**File:** `smb2pdu.c:4264-4266` and `smb2pdu.c:4292-4294`

```diff
  if (conn->is_fruit &&
-     (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID))
+     (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID) &&
+     d_info->name[0] == '.')
  	dinfo->UniqueId = 0;
```

**Rationale:** The feature exists because macOS uses inode numbers as unique
identifiers, and dot files (`.DS_Store`, `.hidden`, `.Spotlight-V100`) may
have inode number collisions across volumes. Only dot files need the zero
treatment.

---

### 2.6 Negotiate Error Status Overwrite

**Issue:** The `err_out` label in `smb2_handle_negotiate()` unconditionally
overwrites `rsp->hdr.Status` with `STATUS_INSUFFICIENT_RESOURCES`, losing
specific error codes set earlier (e.g., `STATUS_INVALID_PARAMETER`).

#### smb2pdu.c — smb2_handle_negotiate()

**File:** `smb2pdu.c:1283`

```diff
  err_out:
  	ksmbd_conn_unlock(conn);
- 	if (rc)
+ 	if (rc && rsp->hdr.Status == 0)
  		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
```

**Rationale:** Only set the fallback status when no more specific status was
already set, preserving diagnostic information.

---

### 2.7 NextCommand Alignment

**Issue:** Per MS-SMB2 section 3.3.5.2.7, compound request `NextCommand`
offsets must be 8-byte aligned. Unaligned offsets cause misaligned header
parsing.

#### smb2misc.c — ksmbd_smb2_check_message()

**File:** `smb2misc.c:389-392`

```diff
+ 	if (next_cmd > 0 && (next_cmd & 7)) {
+ 		pr_err("next command(%u) is not 8-byte aligned\n", next_cmd);
+ 		return 1;
+ 	}
```

**Rationale:** Rejects compound requests with non-aligned offsets before
the server attempts to parse the misaligned header.

---

### 2.8 Lock Count Overflow

**Issue:** `LockCount` is a 16-bit value (max 65535). Multiplied by
`sizeof(struct smb2_lock_element)` (24 bytes), this produces up to 1.5 MB
of claimed data area, far exceeding any real PDU.

#### smb2misc.c — smb2_get_data_area_len()

**File:** `smb2misc.c:175-179`

```diff
  	lock_count = le16_to_cpu(((struct smb2_lock_req *)hdr)->LockCount);
+ 	if (lock_count > 64) {
+ 		ksmbd_debug(SMB, "Too many lock elements: %d\n",
+ 			    lock_count);
+ 		return -EINVAL;
+ 	}
  	if (lock_count > 0) {
```

**Rationale:** No legitimate SMB2 client sends more than 64 lock elements.
Capping prevents out-of-bounds reads when the computed data area exceeds
the actual PDU size.

---

### 2.9 Durable FD Double-Free

**Issue:** `ksmbd_free_global_file_table()` calls `ksmbd_remove_durable_fd(fp)`
then `__ksmbd_close_fd(NULL, fp)`. The close function internally calls
`ksmbd_remove_durable_fd(fp)` again, causing a double `idr_remove` on the
same ID.

#### vfs_cache.c — ksmbd_free_global_file_table()

**File:** `vfs_cache.c:1022-1026`

```diff
  idr_for_each_entry(global_ft.idr, fp, id) {
- 	ksmbd_remove_durable_fd(fp);
+ 	__ksmbd_remove_durable_fd(fp);
+ 	fp->persistent_id = KSMBD_NO_FID;
  	__ksmbd_close_fd(NULL, fp);
  }
```

**Rationale:** Uses the unlocked variant (appropriate during shutdown) and
sets `persistent_id = KSMBD_NO_FID` so the `has_file_id()` guard inside
the second removal (from `__ksmbd_close_fd`) returns early.

---

### 2.10 smb3_set_sign_rsp Silent Failure

**Issue:** When the signing key is NULL, `smb3_set_sign_rsp()` silently
returns without signing. Responses are sent unsigned with no diagnostic.

#### smb2pdu.c — smb3_set_sign_rsp()

**File:** `smb2pdu.c:9796-9800`

```diff
- if (!signing_key)
- 	return;
+ if (!signing_key) {
+ 	pr_warn_once("SMB3 signing key not available for response\n");
+ 	return;
+ }
```

**Rationale:** `pr_warn_once` provides a diagnostic breadcrumb without
flooding logs. The one-time nature prevents noise from repeated hits.

---

### 2.11 xattr Copy Filter

**Issue:** `ksmbd_vfs_copy_xattrs()` copies ALL `user.*` xattrs during
server-side copy, including `user.DOSATTRIB` (DOS attributes) and
`user.DosStream.*` (internal stream wrappers). These are per-file
metadata that should be regenerated, not blindly duplicated.

#### vfs.c — ksmbd_vfs_copy_xattrs()

**File:** `vfs.c:2050-2053`

```diff
  	if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
  		continue;

+ 	/* Skip CIFS-internal xattrs that should not be copied */
+ 	if (!strcmp(name, XATTR_NAME_DOS_ATTRIBUTE) ||
+ 	    !strncmp(name, XATTR_NAME_STREAM, XATTR_NAME_STREAM_LEN))
+ 		continue;
```

**Rationale:** `user.DOSATTRIB` contains the DOS attribute flags and creation
time which are file-specific. `user.DosStream.*` entries are named stream
wrappers that correspond to the source file's alternate data streams and
should not be raw-copied to the destination.

---

## Concurrency Fixes

### 3.1 ksmbd_conn_free Ordering

**Issue:** Resources (`sessions`, `request_buf`, `preauth_info`, fruit state)
were freed unconditionally before the reference count check. If another thread
held a reference, it would access freed memory.

#### connection.c — ksmbd_conn_free()

**File:** `connection.c:40-60`

```diff
  	hash_del(&conn->hlist);
  	up_write(&conn_list_lock);

- 	xa_destroy(&conn->sessions);
- 	kvfree(conn->request_buf);
- 	kfree(conn->preauth_info);
+ 	if (atomic_dec_and_test(&conn->refcnt)) {
+ 		xa_destroy(&conn->sessions);
+ 		kvfree(conn->request_buf);
+ 		kfree(conn->preauth_info);

  #ifdef CONFIG_KSMBD_FRUIT
- 	if (conn->fruit_state) {
- 		fruit_cleanup_connection_state(conn->fruit_state);
- 		kfree(conn->fruit_state);
- 	}
+ 		if (conn->fruit_state) {
+ 			fruit_cleanup_connection_state(conn->fruit_state);
+ 			kfree(conn->fruit_state);
+ 		}
  #endif

- 	if (atomic_dec_and_test(&conn->refcnt)) {
  		conn->transport->ops->free_transport(conn->transport);
  		kfree(conn);
  	}
```

**Rationale:** All resource cleanup now happens inside the refcount-zero block.
The hash table removal remains outside since removing from the lookup table
is always safe and prevents new references from being acquired.

---

### 3.2 stop_sessions UAF

**Issue:** After releasing `conn_list_lock` to call `t->ops->shutdown(t)`,
the connection could be freed by a concurrent `ksmbd_conn_free()`, making
the cached `t` pointer dangling.

#### connection.c — stop_sessions()

**File:** `connection.c:551-556`

```diff
  	if (t->ops->shutdown) {
+ 		atomic_inc(&conn->refcnt);
  		up_read(&conn_list_lock);
  		t->ops->shutdown(t);
+ 		atomic_dec(&conn->refcnt);
  		down_read(&conn_list_lock);
  	}
```

**Rationale:** Taking a reference before releasing the lock prevents the
connection from being freed while `t` is in use. The decrement after
shutdown allows normal teardown to proceed.

---

### 3.3 Tree Connect TOCTOU

**Issue:** `xa_for_each` iteration ran outside the write lock, with the lock
acquired per-iteration. Between lock release and reacquire, another thread
could modify `t_state`, causing double-disconnect.

#### mgmt/tree_connect.c — ksmbd_tree_conn_session_logoff()

**File:** `mgmt/tree_connect.c:150-164`

```diff
+ 	write_lock(&sess->tree_conns_lock);
  	xa_for_each(&sess->tree_conns, id, tc) {
- 		write_lock(&sess->tree_conns_lock);
  		if (tc->t_state == TREE_DISCONNECTED) {
- 			write_unlock(&sess->tree_conns_lock);
  			ret = -ENOENT;
  			continue;
  		}
  		tc->t_state = TREE_DISCONNECTED;
  		write_unlock(&sess->tree_conns_lock);
-
  		ret |= ksmbd_tree_conn_disconnect(sess, tc);
+ 		write_lock(&sess->tree_conns_lock);
  	}
+ 	write_unlock(&sess->tree_conns_lock);
```

**Rationale:** The lock is now held across the state check and state update,
making them atomic. The lock is only released around the disconnect call
(which takes its own locks internally) and reacquired for the next iteration.

---

## Apple/Fruit Fixes

### 4.1 TM Lock Steal Capability

**Issue:** macOS Time Machine needs `kSupportsTMLockSteal` to recover from
stale backup locks when a previous backup was interrupted.

#### smb2fruit.h

**File:** `smb2fruit.h:51`

```diff
  #define kAAPL_SUPPORTS_NFS_ACE			0x08
+ #define kAAPL_SUPPORTS_TM_LOCK_STEAL		0x40
```

#### oplock.c — create_fruit_rsp_buf()

**File:** `oplock.c:2088`

```diff
  caps |= kAAPL_SUPPORTS_READ_DIR_ATTR;
+ caps |= kAAPL_SUPPORTS_TM_LOCK_STEAL;
```

**Rationale:** Without this bit, macOS Time Machine reports "backup disk not
available" after an interrupted backup until the stale lock times out.

---

### 4.2 Remove NFS ACE Advertisement

**Issue:** `kAAPL_SUPPORTS_NFS_ACE` was advertised but never enforced in the
ACL code. macOS would send NFS-style ACEs that ksmbd silently ignored.

#### oplock.c — create_fruit_rsp_buf()

**File:** `oplock.c:2085-2087`

```diff
  caps = kAAPL_UNIX_BASED;
  if (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE)
  	caps |= kAAPL_SUPPORTS_OSX_COPYFILE;
- if (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES)
- 	caps |= kAAPL_SUPPORTS_NFS_ACE;
```

**Rationale:** Advertising an unimplemented capability causes macOS to use a
code path that silently fails. Removing the flag forces macOS to use the
standard POSIX ACL path, which works correctly.

---

### 4.3 Remove RESOLVE_ID Advertisement

**Issue:** `kAAPL_SUPPORT_RESOLVE_ID` was advertised in volume capabilities
but no IOCTL handler exists, causing macOS alias resolution to fail.

#### oplock.c — create_fruit_rsp_buf()

**File:** `oplock.c:2092`

```diff
- vcaps = kAAPL_CASE_SENSITIVE | kAAPL_SUPPORTS_FULL_SYNC |
- 	kAAPL_SUPPORT_RESOLVE_ID;
+ vcaps = kAAPL_CASE_SENSITIVE | kAAPL_SUPPORTS_FULL_SYNC;
```

**Rationale:** macOS sends `FSCTL_AAPL_RESOLVE_ID` IOCTLs when this bit is
set, receiving `STATUS_NOT_SUPPORTED` in response, which breaks alias
resolution. Removing the bit makes macOS fall back to path-based resolution.

---

### 4.4 AFP_AfpInfo Write-Back

**Issue:** macOS writes Finder metadata via the AFP_AfpInfo stream, but ksmbd
only stored it in `user.DosStream.AFP_AfpInfo:$DATA` without writing the
embedded 32-byte FinderInfo back to the native `user.com.apple.FinderInfo`
xattr. This caused divergence between the two xattrs.

#### vfs.c — ksmbd_vfs_stream_write()

**File:** `vfs.c:859-879`

```diff
  	err = ...setxattr(..., stream_buf, size, ...);
  	if (err < 0)
  		goto out;
- 	else
- 		fp->stream.pos = size;
+
+ #ifdef CONFIG_KSMBD_FRUIT
+ 	if (fp->stream.name &&
+ 	    strstr(fp->stream.name, "AFP_AfpInfo") &&
+ 	    size >= 48) {
+ 		int wb_err;
+
+ 		/* Write-back FinderInfo (bytes 16-47) to native xattr */
+ 		wb_err = ksmbd_vfs_setxattr(...,
+ 					    APPLE_FINDER_INFO_XATTR_USER,
+ 					    (void *)(stream_buf + 16), 32,
+ 					    0, true);
+ 		if (wb_err < 0)
+ 			ksmbd_debug(VFS,
+ 				    "Failed to write-back FinderInfo: %d\n",
+ 				    wb_err);
+ 	}
+ #endif
+ 	fp->stream.pos = size;
```

**Rationale:** The AFP_AfpInfo structure is 60 bytes. Bytes 0-15 are header
(magic, version, file ID, backup date). Bytes 16-47 are the 32-byte
FinderInfo (file type, creator code, Finder flags, icon position, etc.).
Since `fruit_synthesize_afpinfo()` reads from `user.com.apple.FinderInfo`,
writing it back ensures round-trip consistency. The write-back failure is
non-fatal (logged at debug level) since the DosStream write already succeeded.

---

## Files Modified

| File | Lines Changed | Issues Addressed |
|------|--------------|------------------|
| `auth.c` | +3/-2 | Timing side-channel (NTLMv1, NTLMv2) |
| `connection.c` | +12/-10 | conn_free ordering, stop_sessions UAF |
| `ksmbd_work.c` | +3/-2 | IOV array OOB write |
| `mgmt/tree_connect.c` | +3/-3 | TOCTOU in session logoff |
| `mgmt/user_config.c` | +3/-2 | Sensitive passkey free, timing side-channel |
| `mgmt/user_session.c` | +11/-3 | Key zeroing, refcount leak |
| `ndr.c` | +20/-10 | Return value check, memory leak |
| `oplock.c` | +5/-6 | UAF fix, TM Lock Steal, NFS ACE, RESOLVE_ID |
| `smb2fruit.h` | +1/-0 | TM Lock Steal define |
| `smb2misc.c` | +10/-0 | NextCommand alignment, lock count bound |
| `smb2pdu.c` | +43/-10 | Signing enforcement, timing, bounds, ChunkBytesWritten, negotiate error, zero fileid, sign_rsp, NegCtxCount, tree connect |
| `vfs.c` | +29/-2 | AFP_AfpInfo write-back, xattr filter |
| `vfs_cache.c` | +4/-3 | UAF fix, durable FD double-free |
