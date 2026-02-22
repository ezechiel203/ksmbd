# KSMBD Security Fixes — Pass 2: Complete Diff Documentation

## Overview

**Date**: 2026-02-22
**Scope**: 209 findings from FULLREVIEWBIS.md second-pass security audit
**Files Modified**: 35 files (541 insertions, 238 deletions)
**Build Status**: Clean compilation with both `CONFIG_KSMBD_FRUIT=n` and `CONFIG_KSMBD_FRUIT=y`

## Summary Statistics

| Category | Count |
|----------|-------|
| CRITICAL fixes | 10 |
| HIGH fixes | 22 |
| MEDIUM fixes | 48 |
| LOW fixes | 15 |
| Total fixes applied | 95 |
| Files modified | 35 |

## Fixes by File

---

### Kconfig

**Fixes in this file:**
- Fix 1: Move CRYPTO_MD4 dependency from base module to insecure-protocol guard (MEDIUM)
- Fix 2: Fix whitespace inconsistency (tabs vs spaces) in Kconfig indentation (LOW)

**Fix 1 — Move CRYPTO_MD4 to SMB_INSECURE_SERVER:**

MD4 is only used by the legacy NTLM (v1) authentication path, which is gated behind `CONFIG_SMB_INSECURE_SERVER`. Having the base `SMB_SERVER` config select CRYPTO_MD4 unnecessarily pulls in an obsolete hash algorithm even when only SMB2/3 protocols are enabled.

**Before:**
```
config SMB_SERVER
	select CRYPTO
	select CRYPTO_MD4
	select CRYPTO_MD5
```

**After:**
```
config SMB_SERVER
	select CRYPTO
	select CRYPTO_MD5
```

And the MD4 dependency is moved under `SMB_INSECURE_SERVER`:

**Before:**
```
config SMB_INSECURE_SERVER
        bool "Support for insecure SMB1/CIFS and SMB2.0 protocols"
        depends on SMB_SERVER && INET
        select NLS
	default n

        help
```

**After:**
```
config SMB_INSECURE_SERVER
	bool "Support for insecure SMB1/CIFS and SMB2.0 protocols"
	depends on SMB_SERVER && INET
	select NLS
	select CRYPTO_MD4
	default n

	help
```

---

### Makefile

**Fixes in this file:**
- Fix 1: Change default `CONFIG_KSMBD_FRUIT` from `y` to `n` (MEDIUM)
- Fix 2: Remove duplicate `PWD` assignment (LOW)

**Fix 1 — Default Fruit extension to disabled:**

Disabling the Apple Fruit SMB extensions by default reduces the attack surface for deployments that do not require macOS compatibility.

**Before:**
```makefile
CONFIG_KSMBD_FRUIT ?= y
```

**After:**
```makefile
CONFIG_KSMBD_FRUIT ?= n
```

**Fix 2 — Remove duplicate PWD line:**

**Before:**
```makefile
PWD	:= $(shell pwd)
PWD	:= $(shell pwd)
```

**After:**
```makefile
PWD	:= $(shell pwd)
```

---

### auth.c

**Fixes in this file:**
- Fix 1: Scrub stack key material in `ksmbd_auth_ntlm` (HIGH)
- Fix 2: Scrub stack key material in `ksmbd_auth_ntlmv2` (HIGH)
- Fix 3: Use constant-time comparison in `__ksmbd_auth_ntlmv2` and scrub stack buffers (HIGH)
- Fix 4: Scrub `prfhash` in `generate_key` (MEDIUM)
- Fix 5: Remove session key and signing/encryption key dumps from debug output (CRITICAL)
- Fix 6: Scrub key material in GCM/CCM encryption path (MEDIUM)

**Fix 1 — Scrub key material in ksmbd_auth_ntlm:**

NTLM v1 authentication leaves the password hash (`p21`) and derived key (`key`) on the stack after returning. An info-leak or stack read vulnerability could expose these credentials.

**Before:**
```c
	rc = ksmbd_enc_p24(p21, cryptkey, key);
	if (rc) {
		pr_err("password processing failed\n");
		return rc;
	}

	ksmbd_enc_md4(sess->sess_key, user_passkey(sess->user),
...

	if (crypto_memneq(pw_buf, key, CIFS_AUTH_RESP_SIZE)) {
		ksmbd_debug(AUTH, "ntlmv1 authentication failed\n");
		return -EINVAL;
	}

	ksmbd_debug(AUTH, "ntlmv1 authentication pass\n");
	return 0;
}
```

**After:**
```c
	rc = ksmbd_enc_p24(p21, cryptkey, key);
	if (rc) {
		pr_err("password processing failed\n");
		goto out;
	}

	ksmbd_enc_md4(sess->sess_key, user_passkey(sess->user),
...

	if (crypto_memneq(pw_buf, key, CIFS_AUTH_RESP_SIZE)) {
		ksmbd_debug(AUTH, "ntlmv1 authentication failed\n");
		rc = -EINVAL;
		goto out;
	}

	ksmbd_debug(AUTH, "ntlmv1 authentication pass\n");
out:
	memzero_explicit(p21, sizeof(p21));
	memzero_explicit(key, sizeof(key));
	return rc;
}
```

**Fix 2 — Scrub key material in ksmbd_auth_ntlmv2:**

**Before:**
```c
	if (ctx)
		ksmbd_release_crypto_ctx(ctx);
	kfree(construct);
	return rc;
}
```

**After:**
```c
	if (ctx)
		ksmbd_release_crypto_ctx(ctx);
	kfree(construct);
	memzero_explicit(ntlmv2_hash, sizeof(ntlmv2_hash));
	memzero_explicit(ntlmv2_rsp, sizeof(ntlmv2_rsp));
	return rc;
}
```

**Fix 3 — Constant-time comparison and scrub in __ksmbd_auth_ntlmv2:**

Using `memcmp` for authentication response comparison leaks timing information. Switching to `crypto_memneq` prevents timing side-channel attacks.

**Before:**
```c
	if (memcmp(ntlm_resp, key, CIFS_AUTH_RESP_SIZE) != 0)
		rc = -EINVAL;
out:
	return rc;
}
```

**After:**
```c
	if (crypto_memneq(ntlm_resp, key, CIFS_AUTH_RESP_SIZE))
		rc = -EINVAL;
out:
	memzero_explicit(sess_key, sizeof(sess_key));
	memzero_explicit(p21, sizeof(p21));
	memzero_explicit(key, sizeof(key));
	return rc;
}
```

**Fix 4 — Scrub prfhash in generate_key:**

**Before:**
```c
smb3signkey_ret:
	ksmbd_release_crypto_ctx(ctx);
	return rc;
}
```

**After:**
```c
smb3signkey_ret:
	ksmbd_release_crypto_ctx(ctx);
	memzero_explicit(prfhash, sizeof(prfhash));
	return rc;
}
```

**Fix 5 — Remove cryptographic key material from debug output:**

Debug logging was dumping raw session keys, signing keys, and encryption keys. If debug logging is enabled in production, this creates a direct credential-disclosure vulnerability.

**Before (signing key generation):**
```c
	ksmbd_debug(AUTH, "dumping generated AES signing keys\n");
	ksmbd_debug(AUTH, "Session Id    %llu\n", sess->id);
	ksmbd_debug(AUTH, "Session Key   %*ph\n",
		    SMB2_NTLMV2_SESSKEY_SIZE, sess->sess_key);
	ksmbd_debug(AUTH, "Signing Key   %*ph\n",
		    SMB3_SIGN_KEY_SIZE, key);
	return 0;
```

**After (signing key generation):**
```c
	ksmbd_debug(AUTH, "generated signing key for session %llu\n", sess->id);
	return 0;
```

**Before (encryption key generation):**
```c
	ksmbd_debug(AUTH, "dumping generated AES encryption keys\n");
	ksmbd_debug(AUTH, "Cipher type   %d\n", conn->cipher_type);
	ksmbd_debug(AUTH, "Session Id    %llu\n", sess->id);
	ksmbd_debug(AUTH, "Session Key   %*ph\n",
		    SMB2_NTLMV2_SESSKEY_SIZE, sess->sess_key);
	if (conn->cipher_type == SMB2_ENCRYPTION_AES256_CCM ||
	    conn->cipher_type == SMB2_ENCRYPTION_AES256_GCM) {
		ksmbd_debug(AUTH, "ServerIn Key  %*ph\n",
			    SMB3_GCM256_CRYPTKEY_SIZE, sess->smb3encryptionkey);
		ksmbd_debug(AUTH, "ServerOut Key %*ph\n",
			    SMB3_GCM256_CRYPTKEY_SIZE, sess->smb3decryptionkey);
	} else {
		ksmbd_debug(AUTH, "ServerIn Key  %*ph\n",
			    SMB3_GCM128_CRYPTKEY_SIZE, sess->smb3encryptionkey);
		ksmbd_debug(AUTH, "ServerOut Key %*ph\n",
			    SMB3_GCM128_CRYPTKEY_SIZE, sess->smb3decryptionkey);
	}
	return 0;
```

**After (encryption key generation):**
```c
	ksmbd_debug(AUTH, "generated encryption keys for session %llu, cipher type %d\n",
		    sess->id, conn->cipher_type);
	return 0;
```

**Fix 6 — Scrub key in GCM/CCM encryption path:**

**Before:**
```c
free_req:
	aead_request_free(req);
free_ctx:
	ksmbd_release_crypto_ctx(ctx);
	return rc;
}
```

**After:**
```c
free_req:
	aead_request_free(req);
free_ctx:
	ksmbd_release_crypto_ctx(ctx);
	memzero_explicit(key, sizeof(key));
	return rc;
}
```

---

### compat.h

**Fixes in this file:**
- Fix 1: Fix non-unique include guard (LOW)

**Before:**
```c
#ifndef COMPAT_H
#define COMPAT_H
```

**After:**
```c
#ifndef __KSMBD_COMPAT_H__
#define __KSMBD_COMPAT_H__
```

---

### connection.c

**Fixes in this file:**
- Fix 1: Split `ksmbd_conn_free` to avoid cleanup-under-lock issues (HIGH)
- Fix 2: Fix integer overflow in PDU size calculation (CRITICAL)
- Fix 3: Fix bare `kfree` in `ksmbd_conn_r_count_dec` (HIGH)
- Fix 4: Fix hash iteration after lock drop in `stop_sessions` (MEDIUM)
- Fix 5: Add `overflow.h` include (LOW)
- Fix 6: Free `conn->vals` in cleanup path (MEDIUM)

**Fix 1 — Refactor ksmbd_conn_free with proper cleanup:**

The original code performed resource cleanup (xa_destroy, kvfree, kfree) inside the `if (atomic_dec_and_test)` block within `ksmbd_conn_free`, but left the reference-count check interleaved with the hash_del under the write lock. The refactored version separates the cleanup into `ksmbd_conn_cleanup()` which is called only after the refcount reaches zero.

**Before:**
```c
void ksmbd_conn_free(struct ksmbd_conn *conn)
{
	down_write(&conn_list_lock);
	hash_del(&conn->hlist);
	up_write(&conn_list_lock);

	if (atomic_dec_and_test(&conn->refcnt)) {
		xa_destroy(&conn->sessions);
		kvfree(conn->request_buf);
		kfree(conn->preauth_info);

#ifdef CONFIG_KSMBD_FRUIT
		/* Clean up Fruit SMB extension resources */
		if (conn->fruit_state) {
			fruit_cleanup_connection_state(conn->fruit_state);
			kfree(conn->fruit_state);
			conn->fruit_state = NULL;
		}
#endif

		conn->transport->ops->free_transport(conn->transport);
		kfree(conn);
	}
}
```

**After:**
```c
static void ksmbd_conn_cleanup(struct ksmbd_conn *conn)
{
	down_write(&conn_list_lock);
	hash_del(&conn->hlist);
	up_write(&conn_list_lock);

	xa_destroy(&conn->sessions);
	kvfree(conn->request_buf);
	kfree(conn->preauth_info);
	kfree(conn->vals);

#ifdef CONFIG_KSMBD_FRUIT
	/* Clean up Fruit SMB extension resources */
	if (conn->fruit_state) {
		fruit_cleanup_connection_state(conn->fruit_state);
		kfree(conn->fruit_state);
		conn->fruit_state = NULL;
	}
#endif

	conn->transport->ops->free_transport(conn->transport);
	kfree(conn);
}

void ksmbd_conn_free(struct ksmbd_conn *conn)
{
	if (!atomic_dec_and_test(&conn->refcnt))
		return;

	ksmbd_conn_cleanup(conn);
}
```

**Fix 2 — Integer overflow in PDU size + 4 + 1 calculation:**

The original code computed `size = pdu_size + 4 + 1` which could overflow on 32-bit systems with a crafted `pdu_size`. Now uses `check_add_overflow` to detect this.

**Before:**
```c
		/* 4 for rfc1002 length field */
		/* 1 for implied bcc[0] */
		size = pdu_size + 4 + 1;
```

**After:**
```c
		/* 4 for rfc1002 length field */
		/* 1 for implied bcc[0] */
		if (check_add_overflow(pdu_size, 5u, (unsigned int *)&size))
			break;
```

**Fix 3 — Fix bare kfree in ksmbd_conn_r_count_dec:**

The `ksmbd_conn_r_count_dec` path had a bare `kfree(conn)` when the refcount hit zero, skipping all cleanup (xa_destroy, kvfree of request_buf, transport free, etc.). Now calls `ksmbd_conn_cleanup` instead.

**Before:**
```c
	if (atomic_dec_and_test(&conn->refcnt))
		kfree(conn);
```

**After:**
```c
	if (atomic_dec_and_test(&conn->refcnt))
		ksmbd_conn_cleanup(conn);
```

**Fix 4 — Fix hash iteration after lock drop in stop_sessions:**

After calling `t->ops->shutdown(t)` and decrementing `conn->refcnt`, the code re-acquired the read lock and continued iterating. Since the hash bucket list may have changed during shutdown, this could cause a use-after-free. Now uses `goto again` to restart the iteration.

**Before:**
```c
			up_read(&conn_list_lock);
			t->ops->shutdown(t);
			atomic_dec(&conn->refcnt);
			down_read(&conn_list_lock);
```

**After:**
```c
			up_read(&conn_list_lock);
			t->ops->shutdown(t);
			atomic_dec(&conn->refcnt);
			goto again;
```

**Fix 5 — Add overflow.h include:**

```c
+#include <linux/overflow.h>
```

---

### connection.h

**Fixes in this file:**
- Fix 1: Move `is_fruit` field inside `CONFIG_KSMBD_FRUIT` guard (LOW)

**Before:**
```c
	atomic_t			refcnt;
	bool				is_fruit;

#ifdef CONFIG_KSMBD_FRUIT
```

**After:**
```c
	atomic_t			refcnt;

#ifdef CONFIG_KSMBD_FRUIT
	bool				is_fruit;
```

---

### crypto_ctx.c

**Fixes in this file:**
- Fix 1: Scrub shash descriptor before freeing (HIGH)

Shash descriptors may contain intermediate cryptographic state (partial hash contexts). Freeing them without zeroing can leave sensitive material in the slab.

**Before:**
```c
static void free_shash(struct shash_desc *shash)
{
	if (shash) {
		crypto_free_shash(shash->tfm);
		kfree(shash);
	}
}
```

**After:**
```c
static void free_shash(struct shash_desc *shash)
{
	if (shash) {
		struct crypto_shash *tfm = shash->tfm;
		size_t shash_size = sizeof(*shash) + crypto_shash_descsize(tfm);

		memzero_explicit(shash, shash_size);
		kfree(shash);
		crypto_free_shash(tfm);
	}
}
```

---

### glob.h

**Fixes in this file:**
- Fix 1: Add parentheses around KSMBD_DEFAULT_GFP macro (MEDIUM)

Without parentheses, the macro can cause operator-precedence bugs when used in expressions like `flags | KSMBD_DEFAULT_GFP`.

**Before:**
```c
#define KSMBD_DEFAULT_GFP	GFP_KERNEL | __GFP_RETRY_MAYFAIL
```

**After:**
```c
#define KSMBD_DEFAULT_GFP	(GFP_KERNEL | __GFP_RETRY_MAYFAIL)
```

---

### mgmt/ksmbd_ida.c

**Fixes in this file:**
- Fix 1: Fix IDA leak for reserved ID 0xFFFE (MEDIUM)

When `ida_alloc_min` returns the reserved value 0xFFFE, the original code called `ida_alloc_min` again with min=1, which would just return 0xFFFE again (since it was never freed). Now properly frees 0xFFFE and allocates from 0xFFFF onward.

**Before:**
```c
	id = ida_alloc_min(ida, 1, KSMBD_DEFAULT_GFP);
	if (id == 0xFFFE)
		id = ida_alloc_min(ida, 1, KSMBD_DEFAULT_GFP);
```

**After:**
```c
	id = ida_alloc_min(ida, 1, KSMBD_DEFAULT_GFP);
	if (id == 0xFFFE) {
		/* 0xFFFE is reserved; free it and allocate the next one */
		ida_free(ida, id);
		id = ida_alloc_min(ida, 0xFFFF, KSMBD_DEFAULT_GFP);
	}
```

---

### mgmt/share_config.c

**Fixes in this file:**
- Fix 1: Validate share path is absolute and has no `..` traversal (CRITICAL)

A malicious userspace daemon (or compromised IPC channel) could supply a share path containing `/../` components, allowing directory traversal outside the intended share boundary.

**Before:**
```c
		share->path = kstrndup(ksmbd_share_config_path(resp), path_len,
				      KSMBD_DEFAULT_GFP);
		if (share->path) {
			share->path_sz = strlen(share->path);
```

**After:**
```c
		share->path = kstrndup(ksmbd_share_config_path(resp), path_len,
				      KSMBD_DEFAULT_GFP);
		if (share->path) {
			/* Validate share path is absolute */
			if (share->path[0] != '/' ||
			    strstr(share->path, "/../") ||
			    !strcmp(share->path, "/..")) {
				pr_err("share path must be absolute without '..' components: %s\n",
				       share->path);
				kill_share(share);
				share = NULL;
				goto out;
			}
			share->path_sz = strlen(share->path);
```

---

### mgmt/tree_connect.c

**Fixes in this file:**
- Fix 1: Fix unlock-during-iteration race in `ksmbd_tree_conn_session_logoff` (CRITICAL)

The original code dropped and re-acquired the write lock during `xa_for_each` iteration to call `ksmbd_tree_conn_disconnect`. This is racy because another thread could modify the xarray while the lock is dropped. The fix collects all tree connections to be disconnected into a temporary list under the lock, then processes them after releasing the lock.

**Before:**
```c
int ksmbd_tree_conn_session_logoff(struct ksmbd_session *sess)
{
	int ret = 0;
	struct ksmbd_tree_connect *tc;
	unsigned long id;

	if (!sess)
		return -EINVAL;

	write_lock(&sess->tree_conns_lock);
	xa_for_each(&sess->tree_conns, id, tc) {
		if (tc->t_state == TREE_DISCONNECTED) {
			...
			continue;
		}
		tc->t_state = TREE_DISCONNECTED;
		write_unlock(&sess->tree_conns_lock);
		ret |= ksmbd_tree_conn_disconnect(sess, tc);
		write_lock(&sess->tree_conns_lock);
	}
	write_unlock(&sess->tree_conns_lock);
	xa_destroy(&sess->tree_conns);
	return ret;
}
```

**After:**
```c
int ksmbd_tree_conn_session_logoff(struct ksmbd_session *sess)
{
	int ret = 0;
	struct ksmbd_tree_connect *tc, *tmp;
	unsigned long id;
	LIST_HEAD(free_list);

	if (!sess)
		return -EINVAL;

	/*
	 * Collect all tree connections under lock and erase them from
	 * the xarray, then process disconnections after releasing the
	 * lock. This avoids dropping/reacquiring the lock during
	 * iteration which is racy.
	 */
	write_lock(&sess->tree_conns_lock);
	xa_for_each(&sess->tree_conns, id, tc) {
		if (tc->t_state == TREE_DISCONNECTED) {
			...
			continue;
		}
		tc->t_state = TREE_DISCONNECTED;
		xa_erase(&sess->tree_conns, tc->id);
		list_add(&tc->list, &free_list);
	}
	write_unlock(&sess->tree_conns_lock);

	list_for_each_entry_safe(tc, tmp, &free_list, list) {
		list_del(&tc->list);
		ret |= ksmbd_ipc_tree_disconnect_request(sess->id, tc->id);
		ksmbd_release_tree_conn_id(sess, tc->id);
		ksmbd_share_config_put(tc->share_conf);
		if (atomic_dec_and_test(&tc->refcount))
			kfree(tc);
	}

	xa_destroy(&sess->tree_conns);
	return ret;
}
```

---

### mgmt/user_config.c

**Fixes in this file:**
- Fix 1: Add passkey size check before `crypto_memneq` in `ksmbd_compare_user` (HIGH)

Without the size check, comparing users with different passkey sizes could read beyond the shorter buffer's bounds.

**Before:**
```c
bool ksmbd_compare_user(struct ksmbd_user *u1, struct ksmbd_user *u2)
{
	if (strcmp(u1->name, u2->name))
		return false;
	if (crypto_memneq(u1->passkey, u2->passkey, u1->passkey_sz))
		return false;
```

**After:**
```c
bool ksmbd_compare_user(struct ksmbd_user *u1, struct ksmbd_user *u2)
{
	if (strcmp(u1->name, u2->name))
		return false;
	if (u1->passkey_sz != u2->passkey_sz)
		return false;
	if (crypto_memneq(u1->passkey, u2->passkey, u1->passkey_sz))
		return false;
```

---

### mgmt/user_session.c

**Fixes in this file:**
- Fix 1: Use constant-time comparison in `destroy_previous_session` (HIGH)
- Fix 2: Add comment about sequential session ID allocation (LOW)
- Fix 3: Add `crypto/algapi.h` include for `crypto_memneq` (LOW)

**Fix 1 — Constant-time passkey comparison:**

**Before:**
```c
	if (!prev_user ||
	    strcmp(user->name, prev_user->name) ||
	    user->passkey_sz != prev_user->passkey_sz ||
	    memcmp(user->passkey, prev_user->passkey, user->passkey_sz))
		goto out;
```

**After:**
```c
	if (!prev_user ||
	    strcmp(user->name, prev_user->name) ||
	    user->passkey_sz != prev_user->passkey_sz ||
	    crypto_memneq(user->passkey, prev_user->passkey, user->passkey_sz))
		goto out;
```

**Fix 2 — Document sequential session ID concern:**

**Before:**
```c
static int __init_smb2_session(struct ksmbd_session *sess)
{
	int id = ksmbd_acquire_smb2_uid(&session_ida);
```

**After:**
```c
static int __init_smb2_session(struct ksmbd_session *sess)
{
	/*
	 * Note: Session IDs are allocated sequentially via IDA, which
	 * could allow enumeration. This is a minor info-leak but
	 * cannot easily use get_random_u64() since the ID is used as
	 * an xarray index throughout the session management code.
	 */
	int id = ksmbd_acquire_smb2_uid(&session_ida);
```

**Fix 3 — Add include:**

```c
+#include <crypto/algapi.h>
```

---

### misc.c

**Fixes in this file:**
- Fix 1: Fix pattern matching to consume trailing wildcards (MEDIUM)
- Fix 2: Fix NULL dereference in `parse_stream_name` (MEDIUM)
- Fix 3: Fix off-by-one in `ksmbd_convert_dir_info_name` allocation (MEDIUM)

**Fix 1 — Consume all trailing wildcards in match_pattern:**

The original code only consumed a single trailing `*`. With patterns like `**`, the function would incorrectly report no match.

**Before:**
```c
	if (*p == '*')
		++p;
	return !*p;
```

**After:**
```c
	while (*p == '*')
		++p;
	return !*p;
```

**Fix 2 — Handle missing stream separator in parse_stream_name:**

When `strsep` finds no `:` separator, `s_name` is NULL, and the subsequent `strchr(s_name, ':')` call would crash.

**Before:**
```c
	s_name = filename;
	filename = strsep(&s_name, ":");
	ksmbd_debug(SMB, "filename : %s, streams : %s\n", filename, s_name);
```

**After:**
```c
	s_name = filename;
	filename = strsep(&s_name, ":");
	if (!s_name) {
		*stream_name = NULL;
		return -ENOENT;
	}
	ksmbd_debug(SMB, "filename : %s, streams : %s\n", filename, s_name);
```

**Fix 3 — Allocate extra bytes for null termination:**

The conversion function may write a 2-byte null terminator. Allocating `sz + 2` prevents a 1-byte heap buffer overflow.

**Before:**
```c
	conv = kmalloc(sz, KSMBD_DEFAULT_GFP);
```

**After:**
```c
	conv = kmalloc(sz + 2, KSMBD_DEFAULT_GFP);
```

---

### ndr.c

**Fixes in this file:**
- Fix 1: Integer overflow protection in `try_to_realloc_ndr_blob` (CRITICAL)
- Fix 2: Align string writes to 2-byte boundary in `ndr_write_string` (MEDIUM)
- Fix 3: Bounds check after alignment in `ndr_read_string` (MEDIUM)
- Fix 4: Fix memory leak on error in `ndr_encode_posix_acl` (MEDIUM)
- Fix 5: Fix memory leak on error in `ndr_encode_v4_ntacl` (MEDIUM)
- Fix 6: Limit `pr_err` format string for untrusted ACL description (LOW)

**Fix 1 — Overflow protection in realloc:**

The original `n->offset + sz + 1024` expression could wrap around on large values, causing an undersized allocation followed by a heap buffer overflow.

**Before:**
```c
static int try_to_realloc_ndr_blob(struct ndr *n, size_t sz)
{
	char *data;

	data = krealloc(n->data, n->offset + sz + 1024, KSMBD_DEFAULT_GFP);
```

**After:**
```c
static int try_to_realloc_ndr_blob(struct ndr *n, size_t sz)
{
	char *data;
	size_t new_sz;

	if (check_add_overflow((size_t)n->offset, sz, &new_sz) ||
	    check_add_overflow(new_sz, (size_t)1024, &new_sz))
		return -EOVERFLOW;

	data = krealloc(n->data, new_sz, KSMBD_DEFAULT_GFP);
```

**Fix 2 — Align string to 2-byte boundary:**

NDR strings must be 2-byte aligned. The original code did not pad, which could cause misaligned writes and protocol errors.

**Before:**
```c
	sz = strlen(value) + 1;
```

**After:**
```c
	sz = ALIGN(strlen(value) + 1, 2);
```

**Fix 3 — Bounds check after alignment in ndr_read_string:**

**Before:**
```c
	n->offset += len;
	n->offset = ALIGN(n->offset, 2);
	return 0;
```

**After:**
```c
	n->offset += len;
	n->offset = ALIGN(n->offset, 2);
	if (n->offset > n->length)
		return -EINVAL;
	return 0;
```

**Fix 4 — Memory leak on error in ndr_encode_posix_acl:**

All early `return ret` paths leaked `n->data`. Now all errors jump to `err_free` which frees the buffer.

**Before (multiple locations):**
```c
	if (ret)
		return ret;
```

**After (all changed to):**
```c
	if (ret)
		goto err_free;
```

With the new error handler:
```c
	return 0;

err_free:
	kfree(n->data);
	n->data = NULL;
	return ret;
```

**Fix 5 — Memory leak on error in ndr_encode_v4_ntacl:**

Same pattern as Fix 4 — all early returns changed to `goto err_free` with a cleanup label.

**Fix 6 — Limit format string for untrusted description:**

**Before:**
```c
		pr_err("Invalid acl description : %s\n", acl->desc);
```

**After:**
```c
		pr_err("Invalid acl description : %.10s\n", acl->desc);
```

---

### ndr.h

**Fixes in this file:**
- Fix 1: Change `offset` and `length` from `int` to `unsigned int` (MEDIUM)

Negative values in offset/length could cause buffer underflows or confuse bounds checks.

**Before:**
```c
struct ndr {
	char	*data;
	int	offset;
	int	length;
};
```

**After:**
```c
struct ndr {
	char		*data;
	unsigned int	offset;
	unsigned int	length;
};
```

---

### ntlmssp.h

**Fixes in this file:**
- Fix 1: Fix endianness annotations in `ntlmv2_resp` (LOW)

Fields that are on-wire little-endian should be annotated with `__le32`/`__le64` rather than `__u32`/`__u64`.

**Before:**
```c
struct ntlmv2_resp {
	char ntlmv2_hash[CIFS_ENCPWD_SIZE];
	__le32 blob_signature;
	__u32  reserved;
	__le64  time;
	__u64  client_chal; /* random */
	__u32  reserved2;
```

**After:**
```c
struct ntlmv2_resp {
	char ntlmv2_hash[CIFS_ENCPWD_SIZE];
	__le32 blob_signature;
	__le32 reserved;
	__le64  time;
	__le64 client_chal; /* random */
	__le32 reserved2;
```

---

### oplock.c

**Fixes in this file:**
- Fix 1: Add NULL check for lease in `opinfo_read_handle_to_read` (MEDIUM)
- Fix 2: Fix double-free replaced with proper reference counting in `close_id_del_oplock` (HIGH)
- Fix 3: Fix RCU dereference without proper reference in `smb_lazy_parent_lease_break_close` (HIGH)
- Fix 4: Fix incorrect `memset` size in `create_durable_v2_rsp_buf` (MEDIUM)

**Fix 1 — Guard against non-lease opinfo:**

**Before:**
```c
int opinfo_read_handle_to_read(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

	lease->state = lease->new_state;
```

**After:**
```c
int opinfo_read_handle_to_read(struct oplock_info *opinfo)
{
	struct lease *lease;

	if (!opinfo->is_lease)
		return -EINVAL;

	lease = opinfo->o_lease;
	lease->state = lease->new_state;
```

**Fix 2 — Fix reference counting in close_id_del_oplock:**

The original code did `atomic_dec` followed by `opinfo_put`. But `opinfo_put` also calls `atomic_dec_and_test`, so this was actually decrementing the refcount by 2 total — which is correct for releasing two references (the "created" reference and the `opinfo_get` reference), but the first `atomic_dec` was not paired with a proper `opinfo_put` check for cleanup. Now both decrements go through `opinfo_put`.

**Before:**
```c
	opinfo_count_dec(fp);
	atomic_dec(&opinfo->refcount);
	opinfo_put(opinfo);
```

**After:**
```c
	opinfo_count_dec(fp);
	opinfo_put(opinfo);  /* release the "created" reference */
	opinfo_put(opinfo);  /* release the opinfo_get() reference */
```

**Fix 3 — Proper reference management in smb_lazy_parent_lease_break_close:**

The original code used `rcu_dereference` without holding the RCU read lock for the duration of the dereference, and did not take a reference before using the opinfo pointer. This is a use-after-free risk.

**Before:**
```c
	rcu_read_lock();
	opinfo = rcu_dereference(fp->f_opinfo);
	rcu_read_unlock();

	if (!opinfo || !opinfo->is_lease || opinfo->o_lease->version != 2)
		return;

	p_ci = ksmbd_inode_lookup_lock(fp->filp->f_path.dentry->d_parent);
	if (!p_ci)
		return;
```

**After:**
```c
	opinfo = opinfo_get(fp);
	if (!opinfo)
		return;

	if (!opinfo->is_lease || opinfo->o_lease->version != 2) {
		opinfo_put(opinfo);
		return;
	}

	p_ci = ksmbd_inode_lookup_lock(fp->filp->f_path.dentry->d_parent);
	if (!p_ci) {
		opinfo_put(opinfo);
		return;
	}

	opinfo_put(opinfo);
```

**Fix 4 — Fix incorrect memset size in create_durable_v2_rsp_buf:**

**Before:**
```c
	buf = (struct create_durable_v2_rsp *)cc;
	memset(buf, 0, sizeof(struct create_durable_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_durable_rsp, Data));
	...
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_durable_rsp, Name));
```

**After:**
```c
	buf = (struct create_durable_v2_rsp *)cc;
	memset(buf, 0, sizeof(struct create_durable_v2_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_durable_v2_rsp, Timeout));
	...
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_durable_v2_rsp, Name));
```

---

### server.c

**Fixes in this file:**
- Fix 1: Bounds-check `server_conf.state` before using as array index (MEDIUM)

A race between state updates and sysfs reads could cause an out-of-bounds array access.

**Before:**
```c
	return sysfs_emit(buf, "%d %s %d %lu\n", stats_version,
			  state[server_conf.state], server_conf.tcp_port,
			  server_conf.ipc_last_active / HZ);
```

**After:**
```c
	unsigned int cur_state = READ_ONCE(server_conf.state);

	if (cur_state >= ARRAY_SIZE(state))
		cur_state = SERVER_STATE_SHUTTING_DOWN;
	return sysfs_emit(buf, "%d %s %d %lu\n", stats_version,
			  state[cur_state], server_conf.tcp_port,
			  server_conf.ipc_last_active / HZ);
```

---

### smb1ops.c

**Fixes in this file:**
- Fix 1: Dynamically allocate `conn->vals` instead of sharing global static (CRITICAL)

All SMB1 connections shared a single global `smb1_server_values` struct. Any per-connection modification (e.g., capability negotiation) would affect all connections.

**Before:**
```c
int init_smb1_server(struct ksmbd_conn *conn)
{
	conn->vals = &smb1_server_values;
```

**After:**
```c
int init_smb1_server(struct ksmbd_conn *conn)
{
	conn->vals = kmemdup(&smb1_server_values,
			     sizeof(smb1_server_values), GFP_KERNEL);
	if (!conn->vals)
		return -ENOMEM;

```

---

### smb2fruit.h

**Fixes in this file:**
- Fix 1: Replace zero-length array with flexible array member (LOW)

Zero-length arrays (`[0]`) are a GCC extension; C99 flexible array members (`[]`) are the standard form.

**Before:**
```c
	__u8			query_data[0];
```

**After:**
```c
	__u8			query_data[];
```

---

### smb2misc.c

**Fixes in this file:**
- Fix 1: Enforce minimum offset for `SecurityBufferOffset` in SESSION_SETUP (HIGH)
- Fix 2: Enforce minimum offset for `ReadChannelInfoOffset` in READ (HIGH)
- Fix 3: Change request length functions from `int` to `u64` return type (CRITICAL)
- Fix 4: Fix integer overflow in credit charge validation (CRITICAL)
- Fix 5: Fix credit accounting race window (MEDIUM)
- Fix 6: Add minimum size check for compound sub-PDU (HIGH)

**Fix 1 — SecurityBufferOffset bounds check:**

A client could supply a `SecurityBufferOffset` that points before the `Buffer` field, causing the server to read from within the header as if it were security data.

**Before:**
```c
	case SMB2_SESSION_SETUP:
		*off = le16_to_cpu(((struct smb2_sess_setup_req *)hdr)->SecurityBufferOffset);
```

**After:**
```c
	case SMB2_SESSION_SETUP:
		*off = max_t(unsigned short int,
			     le16_to_cpu(((struct smb2_sess_setup_req *)hdr)->SecurityBufferOffset),
			     offsetof(struct smb2_sess_setup_req, Buffer));
```

**Fix 2 — ReadChannelInfoOffset bounds check:**

**Before:**
```c
	case SMB2_READ:
		*off = le16_to_cpu(((struct smb2_read_req *)hdr)->ReadChannelInfoOffset);
```

**After:**
```c
	case SMB2_READ:
		*off = max_t(unsigned short int,
			     le16_to_cpu(((struct smb2_read_req *)hdr)->ReadChannelInfoOffset),
			     offsetof(struct smb2_read_req, Buffer));
```

**Fix 3 — Widen request length functions to u64:**

When two `le32_to_cpu` values are added together as `int`, the sum can overflow to negative, bypassing credit charge validation. Using `u64` prevents this.

**Before:**
```c
static inline int smb2_query_info_req_len(struct smb2_query_info_req *h)
{
	return le32_to_cpu(h->InputBufferLength) +
		le32_to_cpu(h->OutputBufferLength);
}

static inline int smb2_set_info_req_len(struct smb2_set_info_req *h)
{
	return le32_to_cpu(h->BufferLength);
}

static inline int smb2_read_req_len(struct smb2_read_req *h)
{
	return le32_to_cpu(h->Length);
}

static inline int smb2_write_req_len(struct smb2_write_req *h)
{
	return le32_to_cpu(h->Length);
}

static inline int smb2_query_dir_req_len(struct smb2_query_directory_req *h)
{
	return le32_to_cpu(h->OutputBufferLength);
}

static inline int smb2_ioctl_req_len(struct smb2_ioctl_req *h)
{
	return le32_to_cpu(h->InputCount) +
		le32_to_cpu(h->OutputCount);
}

static inline int smb2_ioctl_resp_len(struct smb2_ioctl_req *h)
{
	return le32_to_cpu(h->MaxInputResponse) +
		le32_to_cpu(h->MaxOutputResponse);
}
```

**After:**
```c
static inline u64 smb2_query_info_req_len(struct smb2_query_info_req *h)
{
	return (u64)le32_to_cpu(h->InputBufferLength) +
		le32_to_cpu(h->OutputBufferLength);
}

static inline u64 smb2_set_info_req_len(struct smb2_set_info_req *h)
{
	return le32_to_cpu(h->BufferLength);
}

static inline u64 smb2_read_req_len(struct smb2_read_req *h)
{
	return le32_to_cpu(h->Length);
}

static inline u64 smb2_write_req_len(struct smb2_write_req *h)
{
	return le32_to_cpu(h->Length);
}

static inline u64 smb2_query_dir_req_len(struct smb2_query_directory_req *h)
{
	return le32_to_cpu(h->OutputBufferLength);
}

static inline u64 smb2_ioctl_req_len(struct smb2_ioctl_req *h)
{
	return (u64)le32_to_cpu(h->InputCount) +
		le32_to_cpu(h->OutputCount);
}

static inline u64 smb2_ioctl_resp_len(struct smb2_ioctl_req *h)
{
	return (u64)le32_to_cpu(h->MaxInputResponse) +
		le32_to_cpu(h->MaxOutputResponse);
}
```

**Fix 4 — Credit validation with u64 types:**

**Before:**
```c
	unsigned int req_len = 0, expect_resp_len = 0, calc_credit_num, max_len;
	...
	max_len = max_t(unsigned int, req_len, expect_resp_len);
```

**After:**
```c
	u64 req_len = 0, expect_resp_len = 0, max_len;
	unsigned int calc_credit_num;
	...
	max_len = max_t(u64, req_len, expect_resp_len);
```

**Fix 5 — Fix credit accounting race window:**

**Before:**
```c
	if ((u64)conn->outstanding_credits + credit_charge > conn->total_credits) {
		...
		ret = 1;
	} else
		conn->outstanding_credits += credit_charge;

	spin_unlock(&conn->credits_lock);
```

**After:**
```c
	} else if ((u64)conn->outstanding_credits + credit_charge > conn->total_credits) {
		...
		ret = 1;
	} else {
		conn->outstanding_credits += credit_charge;
	}
	spin_unlock(&conn->credits_lock);
```

**Fix 6 — Compound sub-PDU minimum size check:**

**Before:**
```c
	if (next_cmd > 0)
		len = next_cmd;
	else if (work->next_smb2_rcv_hdr_off)
```

**After:**
```c
	if (next_cmd > 0) {
		len = next_cmd;
		if (len < sizeof(struct smb2_hdr) + 2) {
			pr_err("compound sub-PDU too small: %u\n", len);
			return 1;
		}
	} else if (work->next_smb2_rcv_hdr_off)
```

---

### smb2ops.c

**Fixes in this file:**
- Fix 1: Dynamically allocate `conn->vals` for SMB 2.0 (CRITICAL)
- Fix 2: Dynamically allocate `conn->vals` for SMB 2.1, change return type to `int` (CRITICAL)
- Fix 3: Dynamically allocate `conn->vals` for SMB 3.0, change return type to `int` (CRITICAL)
- Fix 4: Dynamically allocate `conn->vals` for SMB 3.0.2, change return type to `int` (CRITICAL)
- Fix 5: Dynamically allocate `conn->vals` for SMB 3.1.1 (CRITICAL)

All SMB version init functions suffered from the same issue: they assigned `conn->vals` to point to a global static struct, meaning all connections of the same protocol version shared the same mutable state. Per-connection capability negotiation could corrupt other connections.

**Fix 1 — SMB 2.0 (already returned int):**

**Before:**
```c
int init_smb2_0_server(struct ksmbd_conn *conn)
{
	conn->vals = &smb20_server_values;
```

**After:**
```c
int init_smb2_0_server(struct ksmbd_conn *conn)
{
	conn->vals = kmemdup(&smb20_server_values,
			     sizeof(smb20_server_values), GFP_KERNEL);
	if (!conn->vals)
		return -ENOMEM;

```

**Fix 2 — SMB 2.1 (signature changed from void to int):**

**Before:**
```c
void init_smb2_1_server(struct ksmbd_conn *conn)
{
	conn->vals = &smb21_server_values;
	...
}
```

**After:**
```c
int init_smb2_1_server(struct ksmbd_conn *conn)
{
	conn->vals = kmemdup(&smb21_server_values,
			     sizeof(smb21_server_values), GFP_KERNEL);
	if (!conn->vals)
		return -ENOMEM;

	...
	return 0;
}
```

**Fix 3 — SMB 3.0 (signature changed from void to int):**

**Before:**
```c
void init_smb3_0_server(struct ksmbd_conn *conn)
{
	conn->vals = &smb30_server_values;
	...
}
```

**After:**
```c
int init_smb3_0_server(struct ksmbd_conn *conn)
{
	conn->vals = kmemdup(&smb30_server_values,
			     sizeof(smb30_server_values), GFP_KERNEL);
	if (!conn->vals)
		return -ENOMEM;

	...
	return 0;
}
```

**Fix 4 — SMB 3.0.2 (signature changed from void to int):**

**Before:**
```c
void init_smb3_02_server(struct ksmbd_conn *conn)
{
	conn->vals = &smb302_server_values;
	...
}
```

**After:**
```c
int init_smb3_02_server(struct ksmbd_conn *conn)
{
	conn->vals = kmemdup(&smb302_server_values,
			     sizeof(smb302_server_values), GFP_KERNEL);
	if (!conn->vals)
		return -ENOMEM;

	...
	return 0;
}
```

**Fix 5 — SMB 3.1.1:**

**Before:**
```c
int init_smb3_11_server(struct ksmbd_conn *conn)
{
	conn->vals = &smb311_server_values;
```

**After:**
```c
int init_smb3_11_server(struct ksmbd_conn *conn)
{
	conn->vals = kmemdup(&smb311_server_values,
			     sizeof(smb311_server_values), GFP_KERNEL);
	if (!conn->vals)
		return -ENOMEM;

```

---

### smb2pdu.c

**Fixes in this file:**
- Fix 1: Rate-limit invalid session ID error message (LOW)
- Fix 2: Fix outstanding credits underflow (MEDIUM)
- Fix 3: Fix return type of `deassemble_neg_contexts` error (MEDIUM)
- Fix 4: Handle init function failures in `smb2_handle_negotiate` (HIGH)
- Fix 5: Add SPNEGO blob buffer overflow check in `ntlm_negotiate` (HIGH)
- Fix 6: Add SPNEGO blob buffer overflow check in `ntlm_authenticate` (HIGH)
- Fix 7: Bounds check in `krb5_authenticate` (HIGH)
- Fix 8: Fix session binding multichannel flag logic (CRITICAL)
- Fix 9: Bounds check for negblob in `smb2_sess_setup` (HIGH)
- Fix 10: Fix tree connect path bounds check (HIGH)
- Fix 11: Clean up tree connection on pin_rsp failure (MEDIUM)
- Fix 12: Client GUID validation for durable handle reconnect v2 (CRITICAL)
- Fix 13: Client GUID validation for durable handle reconnect v1 (CRITICAL)
- Fix 14: Bounds check for CREATE NameOffset/NameLength (HIGH)
- Fix 15: Fix `goto err_out2` should be `err_out1` after durable reconnect (MEDIUM)
- Fix 16: Fix `=~` should be `&=~` for CreateOptions bitwise clear (MEDIUM)
- Fix 17: Use `fp->filp->f_path` instead of local `path` after open (MEDIUM)
- Fix 18: Guard `is_fruit` references with `CONFIG_KSMBD_FRUIT` (MEDIUM)
- Fix 19: QUERY_DIRECTORY filename bounds check (HIGH)
- Fix 20: QUERY_INFO InputBufferOffset bounds check (HIGH)
- Fix 21: Guard Time Machine stream injection with `CONFIG_KSMBD_FRUIT` (MEDIUM)
- Fix 22: Remove passkey leak as FS_OBJECT_ID (CRITICAL)
- Fix 23: Remove unused `sess` variable in `smb2_get_info_filesystem` (LOW)
- Fix 24: Guard flush F_FULLFSYNC with `CONFIG_KSMBD_FRUIT` (MEDIUM)
- Fix 25: Remove unused `conn` variable in `smb2_flush` (LOW)
- Fix 26: Guard copychunk xattr copy with `CONFIG_KSMBD_FRUIT` (MEDIUM)
- Fix 27: Add race comment about `server_conf.enforced_signing` (LOW)

**Fix 1 — Rate-limit invalid session ID:**

**Before:**
```c
	pr_err("Invalid user session id: %llu\n", id);
```

**After:**
```c
	pr_err_ratelimited("Invalid user session id: %llu\n", id);
```

**Fix 2 — Credit underflow protection:**

**Before:**
```c
	conn->total_credits -= credit_charge;
	conn->outstanding_credits -= credit_charge;
```

**After:**
```c
	conn->total_credits -= credit_charge;
	if (credit_charge > conn->outstanding_credits) {
		pr_err("Outstanding credits underflow: charge %u, outstanding %u\n",
		       credit_charge, conn->outstanding_credits);
		conn->outstanding_credits = 0;
	} else {
		conn->outstanding_credits -= credit_charge;
	}
```

**Fix 3 — Return NTSTATUS from deassemble_neg_contexts:**

**Before:**
```c
	if (neg_ctxt_cnt > 16) {
		pr_err("Too many negotiate contexts: %d\n", neg_ctxt_cnt);
		return -EINVAL;
	}
```

**After:**
```c
	if (neg_ctxt_cnt > 16) {
		pr_err("Too many negotiate contexts: %d\n", neg_ctxt_cnt);
		return STATUS_INVALID_PARAMETER;
	}
```

**Fix 4 — Handle init failures in smb2_handle_negotiate:**

**Before:**
```c
	case SMB302_PROT_ID:
		init_smb3_02_server(conn);
		break;
	case SMB30_PROT_ID:
		init_smb3_0_server(conn);
		break;
	case SMB21_PROT_ID:
		init_smb2_1_server(conn);
		break;
```

**After:**
```c
	case SMB302_PROT_ID:
		rc = init_smb3_02_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			goto err_out;
		}
		break;
	case SMB30_PROT_ID:
		rc = init_smb3_0_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			goto err_out;
		}
		break;
	case SMB21_PROT_ID:
		rc = init_smb2_1_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			goto err_out;
		}
		break;
```

**Fix 5 — SPNEGO blob overflow in ntlm_negotiate:**

**Before:**
```c
	memcpy(rsp->Buffer, spnego_blob, spnego_blob_len);
```

**After:**
```c
	if (spnego_blob_len > work->response_sz -
	    ((char *)rsp->Buffer - (char *)work->response_buf)) {
		rc = -ENOMEM;
		kfree(spnego_blob);
		goto out;
	}

	memcpy(rsp->Buffer, spnego_blob, spnego_blob_len);
```

**Fix 6 — SPNEGO blob overflow in ntlm_authenticate:**

**Before:**
```c
		memcpy(rsp->Buffer, spnego_blob, spnego_blob_len);
```

**After:**
```c
		if (spnego_blob_len > work->response_sz -
		    ((char *)rsp->Buffer - (char *)work->response_buf)) {
			kfree(spnego_blob);
			return -ENOMEM;
		}

		memcpy(rsp->Buffer, spnego_blob, spnego_blob_len);
```

**Fix 7 — Bounds check in krb5_authenticate:**

**Before:**
```c
	in_blob = (char *)&req->hdr.ProtocolId +
		le16_to_cpu(req->SecurityBufferOffset);
```

**After:**
```c
	if ((u64)le16_to_cpu(req->SecurityBufferOffset) +
	    le16_to_cpu(req->SecurityBufferLength) >
	    get_rfc1002_len(work->request_buf) + 4)
		return -EINVAL;

	in_blob = (char *)&req->hdr.ProtocolId +
		le16_to_cpu(req->SecurityBufferOffset);
```

**Fix 8 — Multichannel binding check logic inversion:**

The original condition `server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL` was a positive check, meaning "if multichannel IS enabled, reject binding." The intent was the opposite: reject binding if multichannel is NOT enabled.

**Before:**
```c
	} else if ((conn->dialect < SMB30_PROT_ID ||
		    server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL) &&
		   (req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {
```

**After:**
```c
	} else if ((conn->dialect < SMB30_PROT_ID ||
		    !(server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL)) &&
		   (req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {
```

**Fix 9 — Bounds check for negblob in smb2_sess_setup:**

**Before:**
```c
	negblob = (struct negotiate_message *)((char *)&req->hdr.ProtocolId +
			negblob_off);
```

**After:**
```c
	if ((u64)negblob_off + negblob_len > get_rfc1002_len(work->request_buf) + 4) {
		rc = -EINVAL;
		goto out_err;
	}

	negblob = (struct negotiate_message *)((char *)&req->hdr.ProtocolId +
			negblob_off);
```

**Fix 10 — Tree connect path bounds check:**

The original check did not account for compound request offset.

**Before:**
```c
	if (le16_to_cpu(req->PathOffset) + le16_to_cpu(req->PathLength) >
	    get_rfc1002_len(work->request_buf) + 4) {
```

**After:**
```c
	if ((u64)le16_to_cpu(req->PathOffset) + le16_to_cpu(req->PathLength) >
	    get_rfc1002_len(work->request_buf) + 4 -
	    ((char *)req - (char *)work->request_buf)) {
```

**Fix 11 — Clean up tree connection on pin_rsp failure:**

**Before:**
```c
	rc = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_tree_connect_rsp));
	if (rc)
		status.ret = KSMBD_TREE_CONN_STATUS_NOMEM;
```

**After:**
```c
	rc = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_tree_connect_rsp));
	if (rc) {
		if (status.ret == KSMBD_TREE_CONN_STATUS_OK)
			ksmbd_tree_conn_disconnect(sess, status.tree_conn);
		status.ret = KSMBD_TREE_CONN_STATUS_NOMEM;
	}
```

**Fix 12 — Client GUID validation for durable reconnect v2:**

Prevents a different client from stealing another client's durable file handle by validating the client GUID.

**Before:**
```c
			dh_info->type = dh_idx;
			dh_info->reconnected = true;
```

**After:**
```c
			/* Validate client identity to prevent durable handle theft */
			if (memcmp(dh_info->fp->client_guid, conn->ClientGUID,
				   SMB2_CLIENT_GUID_SIZE)) {
				pr_err("durable reconnect v2: client GUID mismatch\n");
				err = -EBADF;
				ksmbd_put_durable_fd(dh_info->fp);
				goto out;
			}

			dh_info->type = dh_idx;
			dh_info->reconnected = true;
```

**Fix 13 — Client GUID validation for durable reconnect v1:**

Same pattern as Fix 12 for the v1 durable handle path.

**Fix 14 — CREATE NameOffset bounds check:**

**Before:**
```c
	if (req->NameLength) {
		name = smb2_get_name((char *)req + le16_to_cpu(req->NameOffset),
```

**After:**
```c
	if (req->NameLength) {
		if ((u64)le16_to_cpu(req->NameOffset) + le16_to_cpu(req->NameLength) >
		    get_rfc1002_len(work->request_buf) + 4) {
			rc = -EINVAL;
			goto err_out2;
		}

		name = smb2_get_name((char *)req + le16_to_cpu(req->NameOffset),
```

**Fix 15 — Fix goto target after durable reconnect stat failure:**

**Before:**
```c
			rc = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);
			if (rc)
				goto err_out2;
```

**After:**
```c
			rc = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);
			if (rc)
				goto err_out1;
```

**Fix 16 — CreateOptions bitwise assignment bug:**

`req->CreateOptions = ~(FILE_SEQUENTIAL_ONLY_LE)` replaces the entire field with the bitwise NOT of the flag, instead of clearing just that bit.

**Before:**
```c
		if (req->CreateOptions & FILE_SEQUENTIAL_ONLY_LE &&
		    req->CreateOptions & FILE_RANDOM_ACCESS_LE)
			req->CreateOptions = ~(FILE_SEQUENTIAL_ONLY_LE);
```

**After:**
```c
		if (req->CreateOptions & FILE_SEQUENTIAL_ONLY_LE &&
		    req->CreateOptions & FILE_RANDOM_ACCESS_LE)
			req->CreateOptions &= ~(FILE_SEQUENTIAL_ONLY_LE);
```

Same fix for `FILE_NO_COMPRESSION_LE`:

**Before:**
```c
			} else if (req->CreateOptions & FILE_NO_COMPRESSION_LE) {
				req->CreateOptions = ~(FILE_NO_COMPRESSION_LE);
			}
```

**After:**
```c
			} else if (req->CreateOptions & FILE_NO_COMPRESSION_LE) {
				req->CreateOptions &= ~(FILE_NO_COMPRESSION_LE);
			}
```

**Fix 17 — Use fp->filp->f_path instead of local path variable:**

After the file is opened, the local `path` variable may be stale (especially after reparse point handling). The file's actual path is `fp->filp->f_path`.

**Before:**
```c
	rc = ksmbd_vfs_getattr(&path, &stat);
	...
						       path.dentry,
```

**After:**
```c
	rc = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);
	...
						       fp->filp->f_path.dentry,
```

**Fix 18 — Guard is_fruit references with CONFIG_KSMBD_FRUIT:**

Multiple places in `smb2_populate_readdir_entry` referenced `conn->is_fruit` without being inside a `CONFIG_KSMBD_FRUIT` guard, causing compilation errors when the feature is disabled.

Added `#ifdef CONFIG_KSMBD_FRUIT` / `#endif` guards around all `conn->is_fruit` accesses in directory entry population.

**Fix 19 — QUERY_DIRECTORY filename bounds check:**

**Before:**
```c
	srch_flag = req->Flags;
	srch_ptr = smb_strndup_from_utf16(...)
```

**After:**
```c
	srch_flag = req->Flags;
	if ((u64)le16_to_cpu(req->FileNameOffset) + le16_to_cpu(req->FileNameLength) >
	    get_rfc1002_len(work->request_buf) + 4) {
		rc = -EINVAL;
		goto err_out2;
	}

	srch_ptr = smb_strndup_from_utf16(...)
```

**Fix 20 — QUERY_INFO InputBufferOffset bounds check:**

**Before:**
```c
		ea_req = (struct smb2_ea_info_req *)((char *)req +
						     le16_to_cpu(req->InputBufferOffset));
```

**After:**
```c
		if ((u64)le16_to_cpu(req->InputBufferOffset) +
		    le32_to_cpu(req->InputBufferLength) >
		    get_rfc1002_len(work->request_buf) + 4)
			return -EINVAL;

		ea_req = (struct smb2_ea_info_req *)((char *)req +
						     le16_to_cpu(req->InputBufferOffset));
```

**Fix 21 — Guard Time Machine stream injection:**

Added `#ifdef CONFIG_KSMBD_FRUIT` / `#endif` around the Time Machine virtual stream injection block in `get_file_stream_info`.

**Fix 22 — Remove passkey leak as FS_OBJECT_ID:**

The original code copied the user's passkey (password hash) into the filesystem object ID response, which is sent to the client in cleartext. This is a direct credential disclosure.

**Before:**
```c
		if (!user_guest(sess->user))
			memcpy(info->objid, user_passkey(sess->user), 16);
		else
			memset(info->objid, 0, 16);
```

**After:**
```c
		/*
		 * Do not leak the user passkey as the object ID.
		 * Use zeroed object ID for all users.
		 */
		memset(info->objid, 0, 16);
```

**Fix 23 — Remove unused sess variable:**

```c
-	struct ksmbd_session *sess = work->sess;
```

**Fix 24 — Guard flush F_FULLFSYNC:**

**Before:**
```c
	if (conn->is_fruit && le16_to_cpu(req->Reserved1) == 0xFFFF)
		fullsync = true;
```

**After:**
```c
#ifdef CONFIG_KSMBD_FRUIT
	if (work->conn->is_fruit && le16_to_cpu(req->Reserved1) == 0xFFFF)
		fullsync = true;
#endif
```

**Fix 25 — Remove unused conn variable:**

```c
-	struct ksmbd_conn *conn = work->conn;
```

**Fix 26 — Guard copychunk xattr copy:**

Added `#ifdef CONFIG_KSMBD_FRUIT` / `#endif` around the Apple COPYFILE xattr copying code in `fsctl_copychunk`.

**Fix 27 — Document race on enforced_signing:**

```c
+		/*
+		 * TODO: server_conf.enforced_signing is a global variable
+		 * written without locking. Concurrent negotiate requests
+		 * can race here. Ideally this should be a per-connection
+		 * flag, but that requires adding a field to ksmbd_conn.
+		 */
		server_conf.enforced_signing = true;
```

---

### smb2pdu.h

**Fixes in this file:**
- Fix 1: Fix endianness annotation for `Reserved1` in transform header (LOW)
- Fix 2: Fix hex constant case for `SMB2_GLOBAL_CAP_LARGE_MTU` (LOW)
- Fix 3: Fix endianness annotation for `Padding` in compression context (LOW)
- Fix 4: Remove duplicate `SMB2_SESSION_REQ_FLAG_*` defines (LOW)
- Fix 5: Replace zero-length arrays with flexible array members (LOW)
- Fix 6: Fix endianness annotations for `Reserved` in create_posix (LOW)
- Fix 7: Fix endianness annotation for `Reserved2` in read/write response (LOW)
- Fix 8: Fix endianness and field name in notify request (LOW)
- Fix 9: Fix endianness annotations for echo req/rsp (LOW)
- Fix 10: Fix endianness annotations for `Pad1`/`Pad2` in file_all_info (LOW)
- Fix 11: Change `init_smb2_1_server`, `init_smb3_0_server`, `init_smb3_02_server` return type from `void` to `int` (HIGH)
- Fix 12: Replace zero-length array in create_fruit_server_query_rsp (LOW)

**Fix 1:**
```c
-	__u16  Reserved1;
+	__le16 Reserved1;
```

**Fix 2:**
```c
-#define SMB2_GLOBAL_CAP_LARGE_MTU	0X00000004
+#define SMB2_GLOBAL_CAP_LARGE_MTU	0x00000004
```

**Fix 3:**
```c
-	__u16	Padding;
+	__le16	Padding;
```

**Fix 4 — Remove duplicate defines:**

The `SMB2_SESSION_REQ_FLAG_BINDING` and `SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA` were defined in two places. Removed the duplicate definitions.

**Fix 5 — Zero-length to flexible arrays:**
```c
-	__u8   Buffer[0];
+	__u8   Buffer[];
```
(Applied to `smb2_create_req` and `create_context`)

**Fix 6:**
```c
-	__u32   Reserved;
+	__le32  Reserved;
```

**Fix 7:**
```c
-	__u32  Reserved2;
+	__le32 Reserved2;
```
(Applied to both `smb2_read_rsp` and `smb2_write_rsp`)

**Fix 8:**
```c
-	__u32 CompletionFileter;
-	__u32 Reserved;
+	__le32 CompletionFilter;
+	__le32 Reserved;
```

**Fix 9:**
```c
-	__u16  Reserved;
+	__le16 Reserved;
```
(Applied to both `smb2_echo_req` and `smb2_echo_rsp`)

**Fix 10:**
```c
-	__u32  Pad1;
+	__le32 Pad1;
...
-	__u16  Pad2;
+	__le16 Pad2;
```

**Fix 11 — Function signatures:**
```c
-void init_smb2_1_server(struct ksmbd_conn *conn);
-void init_smb3_0_server(struct ksmbd_conn *conn);
-void init_smb3_02_server(struct ksmbd_conn *conn);
+int init_smb2_1_server(struct ksmbd_conn *conn);
+int init_smb3_0_server(struct ksmbd_conn *conn);
+int init_smb3_02_server(struct ksmbd_conn *conn);
```

**Fix 12:**
```c
-	__u8   response_data[0];
+	__u8   response_data[];
```

---

### smb_common.c

**Fixes in this file:**
- Fix 1: Replace `strncmp` with `strcmp` in protocol lookup (MEDIUM)
- Fix 2: Validate transform header when connection has no ops (MEDIUM)
- Fix 3: Fix `supported_protocol` logic for SMB2X (MEDIUM)
- Fix 4: Add bounds check in `next_dialect` (MEDIUM)
- Fix 5: Dynamically allocate `conn->vals` for SMB1 in `smb_common.c` (HIGH)
- Fix 6: Handle `init_smb3_11_server` failure in negotiate common path (HIGH)

**Fix 1 — strncmp to strcmp:**

Using `strncmp` with `len = strlen(str)` means a query string "SMB2" would match "SMB2.1" as a prefix. Using `strcmp` requires an exact match.

**Before:**
```c
	int offt = ARRAY_SIZE(smb1_protos) - 1;
	int len = strlen(str);

	while (offt >= 0) {
		if (!strncmp(str, smb1_protos[offt].prot, len)) {
```

**After:**
```c
	int offt = ARRAY_SIZE(smb1_protos) - 1;

	while (offt >= 0) {
		if (!strcmp(str, smb1_protos[offt].prot)) {
```

Same change for `smb2_protos` array.

**Fix 2 — Validate transform header pre-conditions:**

**Before:**
```c
	if (*proto != SMB1_PROTO_NUMBER &&
	    *proto != SMB2_PROTO_NUMBER &&
	    *proto != SMB2_TRANSFORM_PROTO_NUM)
		return false;

	return true;
```

**After:**
```c
	if (*proto != SMB1_PROTO_NUMBER &&
	    *proto != SMB2_PROTO_NUMBER &&
	    *proto != SMB2_TRANSFORM_PROTO_NUM)
		return false;

	if (*proto == SMB2_TRANSFORM_PROTO_NUM &&
	    (!conn->ops || !conn->ops->is_transform_hdr))
		return false;

	return true;
```

**Fix 3 — Fix SMB2X supported_protocol logic:**

The original `||` condition meant SMB2X was supported if EITHER min >= SMB21 OR max <= SMB311, which is always true when only one bound is set. Should be AND.

**Before:**
```c
	if (idx == SMB2X_PROT &&
	    (server_conf.min_protocol >= SMB21_PROT ||
	     server_conf.max_protocol <= SMB311_PROT))
```

**After:**
```c
	if (idx == SMB2X_PROT &&
	    server_conf.min_protocol >= SMB21_PROT &&
	    server_conf.max_protocol <= SMB311_PROT)
```

**Fix 4 — Bounds check in next_dialect:**

**Before:**
```c
static char *next_dialect(char *dialect, int *next_off, int bcount)
{
	dialect = dialect + *next_off;
	*next_off = strnlen(dialect, bcount);
```

**After:**
```c
static char *next_dialect(char *dialect, int *next_off, int bcount)
{
	dialect = dialect + *next_off;
	bcount -= *next_off;
	if (bcount <= 0)
		return NULL;
	*next_off = strnlen(dialect, bcount);
```

**Fix 5 — Dynamic allocation for SMB1 vals:**

**Before:**
```c
static int init_smb1_server(struct ksmbd_conn *conn)
{
	conn->vals = &smb1_server_values;
```

**After:**
```c
static int init_smb1_server(struct ksmbd_conn *conn)
{
	conn->vals = kmemdup(&smb1_server_values,
			     sizeof(smb1_server_values), GFP_KERNEL);
	if (!conn->vals)
		return -ENOMEM;

```

**Fix 6 — Handle init_smb3_11_server failure:**

**Before:**
```c
		if (__smb2_negotiate(conn)) {
			init_smb3_11_server(conn);
			init_smb2_neg_rsp(work);
```

**After:**
```c
		if (__smb2_negotiate(conn)) {
			ret = init_smb3_11_server(conn);
			if (ret)
				return ret;
			init_smb2_neg_rsp(work);
```

---

### smbacl.c

**Fixes in this file:**
- Fix 1: Simplify `compare_sids` to equality-only (no signed ordering) (MEDIUM)
- Fix 2: Bounds check `num_subauth` in `id_to_sid` (HIGH)
- Fix 3: Change `alloc` type from `int` to `size_t` in `init_acl_state` (MEDIUM)
- Fix 4: Bounds check `num_subauth` in `set_mode_dacl` for user SID (HIGH)
- Fix 5: Bounds check `num_subauth` in `set_mode_dacl` for group SID (HIGH)
- Fix 6: Overflow check for ACE count in `smb_inherit_dacl` (MEDIUM)

**Fix 1 — Simplify compare_sids:**

The original function returned -1, 0, or 1 (three-way comparison), but all callers only checked for zero vs non-zero. The ordering was also potentially incorrect due to mixed endianness comparison. Simplified to return 0 for match, 1 for mismatch.

**Before:**
```c
int compare_sids(const struct smb_sid *ctsid, const struct smb_sid *cwsid)
{
	int i;
	int num_subauth, num_sat, num_saw;

	if (!ctsid || !cwsid)
		return 1;

	if (ctsid->revision != cwsid->revision) {
		if (ctsid->revision > cwsid->revision)
			return 1;
		else
			return -1;
	}

	for (i = 0; i < NUM_AUTHS; ++i) {
		if (ctsid->authority[i] != cwsid->authority[i]) {
			if (ctsid->authority[i] > cwsid->authority[i])
				return 1;
			else
				return -1;
		}
	}

	num_sat = ctsid->num_subauth;
	num_saw = cwsid->num_subauth;
	num_subauth = min(num_sat, num_saw);
	if (num_subauth) {
		for (i = 0; i < num_subauth; ++i) {
			if (ctsid->sub_auth[i] != cwsid->sub_auth[i]) {
				if (le32_to_cpu(ctsid->sub_auth[i]) >
				    le32_to_cpu(cwsid->sub_auth[i]))
					return 1;
				else
					return -1;
			}
		}
	}

	return 0;
}
```

**After:**
```c
int compare_sids(const struct smb_sid *ctsid, const struct smb_sid *cwsid)
{
	int i;
	int num_subauth, num_subauth_w;

	if (!ctsid || !cwsid)
		return 1;

	if (ctsid->revision != cwsid->revision)
		return 1;

	num_subauth = ctsid->num_subauth;
	num_subauth_w = cwsid->num_subauth;
	if (num_subauth != num_subauth_w)
		return 1;

	for (i = 0; i < NUM_AUTHS; ++i) {
		if (ctsid->authority[i] != cwsid->authority[i])
			return 1;
	}

	for (i = 0; i < num_subauth; ++i) {
		if (ctsid->sub_auth[i] != cwsid->sub_auth[i])
			return 1;
	}

	return 0;
}
```

**Fix 2 — Bounds check in id_to_sid:**

Without checking `SID_MAX_SUB_AUTHORITIES`, an attacker-controlled SID could overflow the `sub_auth[]` array.

**Before:**
```c
	ssid->sub_auth[ssid->num_subauth] = cpu_to_le32(cid);
	ssid->num_subauth++;
```

**After:**
```c
	if (ssid->num_subauth < SID_MAX_SUB_AUTHORITIES) {
		ssid->sub_auth[ssid->num_subauth] = cpu_to_le32(cid);
		ssid->num_subauth++;
	}
```

**Fix 3 — Size type in init_acl_state:**

**Before:**
```c
	int alloc;
	...
	alloc = sizeof(struct posix_ace_state_array)
		+ cnt * sizeof(struct posix_user_ace_state);
```

**After:**
```c
	size_t alloc;
	...
	alloc = sizeof(struct posix_ace_state_array)
		+ (size_t)cnt * sizeof(struct posix_user_ace_state);
```

**Fix 4 — Bounds check in set_mode_dacl (user SID):**

**Before:**
```c
	pace->sid.sub_auth[pace->sid.num_subauth++] = cpu_to_le32(uid);
```

**After:**
```c
	if (pace->sid.num_subauth < SID_MAX_SUB_AUTHORITIES)
		pace->sid.sub_auth[pace->sid.num_subauth++] = cpu_to_le32(uid);
```

**Fix 5 — Bounds check in set_mode_dacl (group SID):**

**Before:**
```c
	pace->sid.sub_auth[pace->sid.num_subauth++] =
		cpu_to_le32(from_kgid(&init_user_ns, fattr->cf_gid));
```

**After:**
```c
	if (pace->sid.num_subauth < SID_MAX_SUB_AUTHORITIES)
		pace->sid.sub_auth[pace->sid.num_subauth++] =
			cpu_to_le32(from_kgid(&init_user_ns, fattr->cf_gid));
```

**Fix 6 — ACE count overflow check in smb_inherit_dacl:**

**Before:**
```c
	aces_base = kmalloc(sizeof(struct smb_ace) * num_aces * 2,
			    KSMBD_DEFAULT_GFP);
```

**After:**
```c
	if (num_aces > (SIZE_MAX / (sizeof(struct smb_ace) * 2))) {
		rc = -EINVAL;
		goto free_parent_pntsd;
	}

	aces_base = kmalloc(sizeof(struct smb_ace) * num_aces * 2,
			    KSMBD_DEFAULT_GFP);
```

---

### smbstatus.h

**Fixes in this file:**
- Fix 1: Add `__packed` to `ntstatus` struct (LOW)
- Fix 2: Define `STATUS_SUCCESS` as `cpu_to_le32(0)` for consistency (LOW)

**Before:**
```c
};

#define STATUS_SUCCESS 0x00000000
```

**After:**
```c
} __packed;

#define STATUS_SUCCESS cpu_to_le32(0x00000000)
```

---

### transport_ipc.c

**Fixes in this file:**
- Fix 1: Add `GENL_ADMIN_PERM` to all netlink operations (CRITICAL)
- Fix 2: Add max payload size check in `ipc_validate_msg` (HIGH)
- Fix 3: Integer overflow protection in RPC response validation (HIGH)
- Fix 4: Integer overflow protection in SPNEGO response validation (HIGH)
- Fix 5: Integer overflow protection in share config response validation (HIGH)
- Fix 6: Integer overflow protection in login response ext validation (HIGH)
- Fix 7: Add missing `break` in login response ext case (MEDIUM)

**Fix 1 — GENL_ADMIN_PERM on all netlink ops:**

Without `GENL_ADMIN_PERM`, any unprivileged local user could send netlink messages to the ksmbd kernel module, potentially injecting fake authentication responses or share configurations.

**Before (for each operation):**
```c
	{
		.cmd	= KSMBD_EVENT_LOGIN_RESPONSE,
		.doit	= handle_generic_event,
	},
```

**After (for each operation):**
```c
	{
		.cmd	= KSMBD_EVENT_LOGIN_RESPONSE,
		.doit	= handle_generic_event,
		.flags	= GENL_ADMIN_PERM,
	},
```

This change is applied to all 20 netlink operation entries.

**Fix 2 — Max payload size check:**

**Before:**
```c
static int ipc_validate_msg(struct ipc_msg_table_entry *entry)
{
	unsigned int msg_sz = entry->msg_sz;

	switch (entry->type) {
```

**After:**
```c
static int ipc_validate_msg(struct ipc_msg_table_entry *entry)
{
	unsigned int msg_sz = entry->msg_sz;

	if (entry->msg_sz > KSMBD_IPC_MAX_PAYLOAD)
		return -EINVAL;

	switch (entry->type) {
```

**Fix 3 — Overflow-safe RPC response validation:**

**Before:**
```c
		msg_sz = sizeof(struct ksmbd_rpc_command) + resp->payload_sz;
```

**After:**
```c
		if (check_add_overflow(sizeof(struct ksmbd_rpc_command),
				       resp->payload_sz, &msg_sz))
			return -EINVAL;
```

**Fix 4 — Overflow-safe SPNEGO response validation:**

**Before:**
```c
		msg_sz = sizeof(struct ksmbd_spnego_authen_response) +
				resp->session_key_len + resp->spnego_blob_len;
```

**After:**
```c
		unsigned int payload_sz;

		if (check_add_overflow(resp->session_key_len,
				       resp->spnego_blob_len, &payload_sz))
			return -EINVAL;
		if (check_add_overflow(sizeof(struct ksmbd_spnego_authen_response),
				       payload_sz, &msg_sz))
			return -EINVAL;
```

**Fix 5 — Overflow-safe share config response validation:**

**Before:**
```c
			msg_sz = sizeof(struct ksmbd_share_config_response) +
					resp->payload_sz;
```

**After:**
```c
			if (check_add_overflow(sizeof(struct ksmbd_share_config_response),
					       resp->payload_sz, &msg_sz))
				return -EINVAL;
```

**Fix 6 — Overflow-safe login response ext validation:**

**Before:**
```c
		if (resp->ngroups) {
			msg_sz = sizeof(struct ksmbd_login_response_ext) +
					resp->ngroups * sizeof(gid_t);
		}
	}
```

**After:**
```c
		if (resp->ngroups) {
			unsigned int groups_sz;

			if (check_mul_overflow(resp->ngroups,
					       (unsigned int)sizeof(gid_t),
					       &groups_sz))
				return -EINVAL;
			if (check_add_overflow(sizeof(struct ksmbd_login_response_ext),
					       groups_sz, &msg_sz))
				return -EINVAL;
		}
		break;
	}
```

**Fix 7 — Missing break:**

Note the `break;` statement added at the end of the `KSMBD_EVENT_LOGIN_REQUEST_EXT` case above; the original code fell through to the next case.

---

### transport_rdma.c

**Fixes in this file:**
- Fix 1: RDMA RFC1002 length overflow and bounds check (HIGH)

A maliciously crafted RDMA message could supply `data_length + remaining_data_length` values that overflow, resulting in a tiny allocation and heap buffer overflow.

**Before:**
```c
			if (recvmsg->first_segment && size == 4) {
				unsigned int rfc1002_len =
					data_length + remaining_data_length;
				*((__be32 *)buf) = cpu_to_be32(rfc1002_len);
```

**After:**
```c
			if (recvmsg->first_segment && size == 4) {
				unsigned int rfc1002_len =
					data_length + remaining_data_length;
				if (rfc1002_len < data_length ||
				    rfc1002_len > MAX_STREAM_PROT_LEN) {
					pr_err("Invalid rfc1002 length %u\n",
					       rfc1002_len);
					return -EINVAL;
				}
				*((__be32 *)buf) = cpu_to_be32(rfc1002_len);
```

---

### transport_tcp.c

**Fixes in this file:**
- Fix 1: Remove dead code (duplicate `free_transport` call) (LOW)
- Fix 2: Decrement connection counter on `ksmbd_tcp_new_connection` failure (MEDIUM)

**Fix 1 — Remove dead code:**

**Before:**
```c
		free_transport(t);
	}
	return rc;

	free_transport(t);
	return rc;
}
```

**After:**
```c
		free_transport(t);
	}
	return rc;
}
```

**Fix 2 — Connection counter leak:**

When `ksmbd_tcp_new_connection` fails and max_connections is configured, the `active_num_conn` counter is never decremented, causing the server to eventually refuse all new connections.

**Before:**
```c
		ksmbd_tcp_new_connection(client_sk);
```

**After:**
```c
		if (ksmbd_tcp_new_connection(client_sk)) {
			if (server_conf.max_connections)
				atomic_dec(&active_num_conn);
		}
```

---

### unicode.c

**Fixes in this file:**
- Fix 1: Add documentation about buffer size requirements for `smb_strtoUTF16` (LOW)
- Fix 2: Add documentation about buffer size requirements for `smbConvertToUTF16` (LOW)

**Fix 1 — smb_strtoUTF16 buffer size note:**

```c
+ * NOTE: Callers must ensure @to is large enough to hold the converted
+ * output. The buffer should be at least (len * 2 + 2) bytes.
+ *
```

**Fix 2 — smbConvertToUTF16 buffer size note:**

```c
+ * NOTE: This function does not perform output bounds checking on @target.
+ * Callers MUST ensure that @target is allocated with at least
+ * (srclen * 2 + 2) bytes to accommodate the worst-case UTF-16 expansion
+ * plus a null terminator. Surrogate pairs and IVS sequences may produce
+ * up to 3 UTF-16 code units per input character.
+ *
```

---

### vfs.c

**Fixes in this file:**
- Fix 1: Add `LOOKUP_BENEATH` to `kern_path` in `ksmbd_vfs_setattr` (HIGH)
- Fix 2: Validate symlink targets in `ksmbd_vfs_symlink` (HIGH)
- Fix 3: Add `LOOKUP_BENEATH` to `kern_path` in `ksmbd_vfs_link` (HIGH)
- Fix 4: Add share boundary check in `ksmbd_vfs_resolve_fileid` (HIGH)
- Fix 5: Add `LOOKUP_BENEATH` to `kern_path` in `ksmbd_vfs_fsetxattr` (HIGH)

**Fix 1 — LOOKUP_BENEATH in setattr:**

`LOOKUP_BENEATH` prevents path resolution from escaping above the starting point, providing an additional layer of defense against path traversal.

**Before:**
```c
	if (name) {
		err = kern_path(name, 0, &path);
```

**After:**
```c
	if (name) {
		unsigned int lookup_flags = 0;

#ifdef LOOKUP_BENEATH
		lookup_flags |= LOOKUP_BENEATH;
#endif
		err = kern_path(name, lookup_flags, &path);
```

**Fix 2 — Symlink target validation:**

Without validation, a client could create a symlink pointing to `/etc/shadow` or `../../sensitive/data`, escaping the share boundary.

**Before:**
```c
int ksmbd_vfs_symlink(struct ksmbd_work *work, const char *name,
{
	struct dentry *dentry;
	int err;

	if (ksmbd_override_fsids(work))
```

**After:**
```c
int ksmbd_vfs_symlink(struct ksmbd_work *work, const char *name,
{
	struct dentry *dentry;
	int err;

	/* Prevent symlink targets that escape the share boundary */
	if (name[0] == '/' || strstr(name, "..")) {
		pr_err("Symlink target '%s' escapes share boundary\n", name);
		return -EACCES;
	}

	if (ksmbd_override_fsids(work))
```

**Fix 3 — LOOKUP_BENEATH in link:**

**Before:**
```c
	err = kern_path(oldname, LOOKUP_NO_SYMLINKS, &oldpath);
```

**After:**
```c
	{
		unsigned int lookup_flags = LOOKUP_NO_SYMLINKS;
#ifdef LOOKUP_BENEATH
		lookup_flags |= LOOKUP_BENEATH;
#endif
		err = kern_path(oldname, lookup_flags, &oldpath);
	}
```

**Fix 4 — Share boundary check in resolve_fileid:**

An attacker could supply an inode number that resolves to a file outside the share (e.g., via hardlinks or bind mounts). The `is_subdir` check ensures the resolved dentry is within the share root.

**Before:**
```c
	if (!dentry)
		return -ENOENT;

	path_buf = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);
```

**After:**
```c
	if (!dentry)
		return -ENOENT;

	/* Verify resolved file is within the share boundary */
	if (!is_subdir(dentry, share_path->dentry)) {
		pr_err("resolve_fileid: inode %llu is outside share boundary\n",
		       ino);
		dput(dentry);
		return -EACCES;
	}

	path_buf = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);
```

**Fix 5 — LOOKUP_BENEATH in fsetxattr:**

**Before:**
```c
	err = kern_path(filename, 0, &path);
```

**After:**
```c
	{
		unsigned int lookup_flags = 0;
#ifdef LOOKUP_BENEATH
		lookup_flags |= LOOKUP_BENEATH;
#endif
		err = kern_path(filename, lookup_flags, &path);
	}
```

---

### vfs_cache.c

**Fixes in this file:**
- Fix 1: Initialize `ret` to 0 in `ksmbd_file_table_flush` (LOW)

Without initialization, `ret` could be used uninitialized if the IDR is empty (no iterations occur).

**Before:**
```c
	int			ret;
```

**After:**
```c
	int			ret = 0;
```

---

### vfs_cache.h

**Fixes in this file:**
- Fix 1: Fix hex constant format for `FILE_GENERIC_EXECUTE` (LOW)

**Before:**
```c
#define	FILE_GENERIC_EXECUTE	0X1200a0
```

**After:**
```c
#define	FILE_GENERIC_EXECUTE	0x001200a0
```

---

## Cross-Cutting Themes

### 1. Integer Overflow Protection
Files affected: `connection.c`, `ndr.c`, `smb2misc.c`, `transport_ipc.c`, `smbacl.c`

All arithmetic on untrusted sizes now uses `check_add_overflow`, `check_mul_overflow`, or wider types (`u64`) to prevent wrap-around leading to undersized allocations and heap overflows.

### 2. Cryptographic Material Hygiene
Files affected: `auth.c`, `crypto_ctx.c`

All stack-allocated key material (`p21`, `key`, `prfhash`, `ntlmv2_hash`, `ntlmv2_rsp`, `sess_key`) is now scrubbed with `memzero_explicit()` before function return. Debug output no longer dumps raw keys.

### 3. Constant-Time Comparisons
Files affected: `auth.c`, `mgmt/user_config.c`, `mgmt/user_session.c`

All authentication-related comparisons (`memcmp` on passkeys and NTLM responses) replaced with `crypto_memneq` to prevent timing side-channel attacks.

### 4. Bounds Checking on Untrusted Offsets
Files affected: `smb2pdu.c`, `smb2misc.c`

All client-supplied offset+length pairs (`SecurityBufferOffset`, `NameOffset`, `FileNameOffset`, `InputBufferOffset`, `PathOffset`, `ReadChannelInfoOffset`) are validated against the RFC1002 packet length before being used as memory access offsets.

### 5. Per-Connection State Isolation
Files affected: `smb1ops.c`, `smb2ops.c`, `smb_common.c`, `connection.c`

`conn->vals` changed from a pointer to shared global static data to a per-connection `kmemdup` allocation. This prevents one connection's capability negotiation from affecting others.

### 6. Netlink Privilege Enforcement
Files affected: `transport_ipc.c`

All 20 netlink generic operations now require `GENL_ADMIN_PERM` (CAP_NET_ADMIN), preventing unprivileged local users from injecting fake IPC responses.

### 7. Path Traversal Prevention
Files affected: `vfs.c`, `mgmt/share_config.c`

Added `LOOKUP_BENEATH` flags to `kern_path` calls, share path validation against `..` components, symlink target validation, and `is_subdir` checks on inode resolution.

### 8. Conditional Compilation Guards
Files affected: `smb2pdu.c`, `connection.h`

All references to `conn->is_fruit` and Fruit-specific behavior are now properly guarded by `#ifdef CONFIG_KSMBD_FRUIT` to prevent compilation errors and reduce attack surface when the feature is disabled.

### 9. Endianness Annotations
Files affected: `smb2pdu.h`, `ntlmssp.h`

All wire-format structure fields corrected from `__u16`/`__u32`/`__u64` to their `__le16`/`__le32`/`__le64` counterparts, enabling sparse endianness checking to detect byte-order bugs.

### 10. Resource Leak Prevention
Files affected: `ndr.c`, `transport_tcp.c`, `smb2pdu.c`, `connection.c`

Error paths now properly free allocated resources (NDR buffers, tree connections, connection counters) that were previously leaked on failure.
