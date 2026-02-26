// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/xarray.h>
#include <linux/string.h>
#include <linux/random.h>
#include <crypto/algapi.h>

#include "ksmbd_ida.h"
#include "user_session.h"
#include "user_config.h"
#include "tree_connect.h"
#include "ksmbd_witness.h"
#include "transport_ipc.h"
#include "connection.h"
#include "vfs_cache.h"

static DEFINE_IDA(session_ida);

#define SESSION_HASH_BITS		12
static DEFINE_HASHTABLE(sessions_table, SESSION_HASH_BITS);
static DEFINE_MUTEX(sessions_table_lock);

struct ksmbd_session_rpc {
	int			id;
	unsigned int		method;
};

static void free_channel_list(struct ksmbd_session *sess)
{
	struct channel *chann;
	unsigned long index;

	xa_for_each(&sess->ksmbd_chann_list, index, chann) {
		xa_erase(&sess->ksmbd_chann_list, index);
		memzero_explicit(chann->smb3signingkey, sizeof(chann->smb3signingkey));
		kfree(chann);
	}

	xa_destroy(&sess->ksmbd_chann_list);
}

static void __session_rpc_close(struct ksmbd_session *sess,
				struct ksmbd_session_rpc *entry)
{
	struct ksmbd_rpc_command *resp;

	resp = ksmbd_rpc_close(sess, entry->id);
	if (!resp)
		pr_err("Unable to close RPC pipe %d\n", entry->id);

	kvfree(resp);
	ksmbd_rpc_id_free(entry->id);
	kfree(entry);
}

static void ksmbd_session_rpc_clear_list(struct ksmbd_session *sess)
{
	struct ksmbd_session_rpc *entry;
	long index;

	down_write(&sess->rpc_lock);
	xa_for_each(&sess->rpc_handle_list, index, entry) {
		xa_erase(&sess->rpc_handle_list, index);
		__session_rpc_close(sess, entry);
	}
	up_write(&sess->rpc_lock);

	xa_destroy(&sess->rpc_handle_list);
}

static int __rpc_method(char *rpc_name)
{
	if (!strcmp(rpc_name, "\\srvsvc") || !strcmp(rpc_name, "srvsvc"))
		return KSMBD_RPC_SRVSVC_METHOD_INVOKE;

	if (!strcmp(rpc_name, "\\wkssvc") || !strcmp(rpc_name, "wkssvc"))
		return KSMBD_RPC_WKSSVC_METHOD_INVOKE;

	if (!strcmp(rpc_name, "LANMAN") || !strcmp(rpc_name, "lanman"))
		return KSMBD_RPC_RAP_METHOD;

	if (!strcmp(rpc_name, "\\samr") || !strcmp(rpc_name, "samr"))
		return KSMBD_RPC_SAMR_METHOD_INVOKE;

	if (!strcmp(rpc_name, "\\lsarpc") || !strcmp(rpc_name, "lsarpc"))
		return KSMBD_RPC_LSARPC_METHOD_INVOKE;

	pr_err("Unsupported RPC: %s\n", rpc_name);
	return 0;
}

int ksmbd_session_rpc_open(struct ksmbd_session *sess, char *rpc_name)
{
	struct ksmbd_session_rpc *entry, *old;
	struct ksmbd_rpc_command *resp;
	int method, id;

	method = __rpc_method(rpc_name);
	if (!method)
		return -EINVAL;

	entry = kzalloc(sizeof(struct ksmbd_session_rpc), KSMBD_DEFAULT_GFP);
	if (!entry)
		return -ENOMEM;

	entry->method = method;
	entry->id = id = ksmbd_ipc_id_alloc();
	if (id < 0)
		goto free_entry;

	down_write(&sess->rpc_lock);
	old = xa_store(&sess->rpc_handle_list, id, entry, KSMBD_DEFAULT_GFP);
	if (xa_is_err(old)) {
		up_write(&sess->rpc_lock);
		goto free_id;
	}

	resp = ksmbd_rpc_open(sess, id);
	if (!resp) {
		xa_erase(&sess->rpc_handle_list, entry->id);
		up_write(&sess->rpc_lock);
		goto free_id;
	}

	up_write(&sess->rpc_lock);
	kvfree(resp);
	return id;
free_id:
	ksmbd_rpc_id_free(entry->id);
free_entry:
	kfree(entry);
	return -EINVAL;
}

void ksmbd_session_rpc_close(struct ksmbd_session *sess, int id)
{
	struct ksmbd_session_rpc *entry;

	down_write(&sess->rpc_lock);
	entry = xa_erase(&sess->rpc_handle_list, id);
	if (entry)
		__session_rpc_close(sess, entry);
	up_write(&sess->rpc_lock);
}

int ksmbd_session_rpc_method(struct ksmbd_session *sess, int id)
{
	struct ksmbd_session_rpc *entry;

	lockdep_assert_held(&sess->rpc_lock);
	entry = xa_load(&sess->rpc_handle_list, id);

	return entry ? entry->method : 0;
}

void ksmbd_session_destroy(struct ksmbd_session *sess)
{
	if (!sess)
		return;

	/* Clean up any witness registrations owned by this session */
	ksmbd_witness_unregister_session(sess->id);

	if (sess->user)
		ksmbd_free_user(sess->user);

	ksmbd_tree_conn_session_logoff(sess);
	ksmbd_destroy_file_table(&sess->file_table);
	ksmbd_launch_ksmbd_durable_scavenger();
	ksmbd_session_rpc_clear_list(sess);
	free_channel_list(sess);
	memzero_explicit(sess->sess_key, sizeof(sess->sess_key));
	memzero_explicit(sess->smb3encryptionkey, sizeof(sess->smb3encryptionkey));
	memzero_explicit(sess->smb3decryptionkey, sizeof(sess->smb3decryptionkey));
	memzero_explicit(sess->smb3signingkey, sizeof(sess->smb3signingkey));
	kfree_sensitive(sess->Preauth_HashValue);
	ksmbd_release_id(&session_ida, sess->id);
	kfree_sensitive(sess);
}

struct ksmbd_session *__session_lookup(unsigned long long id)
{
	struct ksmbd_session *sess;

	hash_for_each_possible_rcu(sessions_table, sess, hlist, id) {
		if (id == sess->id) {
			sess->last_active = jiffies;
			return sess;
		}
	}
	return NULL;
}

static void ksmbd_expire_session(struct ksmbd_conn *conn)
{
	struct ksmbd_session *expired[16];
	int nr_expired = 0, i;
	unsigned long id;
	struct ksmbd_session *sess;

	mutex_lock(&sessions_table_lock);
	down_write(&conn->session_lock);
	xa_for_each(&conn->sessions, id, sess) {
		int state;

		if (nr_expired >= ARRAY_SIZE(expired))
			break;
		down_read(&sess->state_lock);
		state = sess->state;
		up_read(&sess->state_lock);
		if (refcount_read(&sess->refcnt) <= 1 &&
		    (state != SMB2_SESSION_VALID ||
		     time_after(jiffies,
			       sess->last_active + SMB2_SESSION_TIMEOUT))) {
			xa_erase(&conn->sessions, sess->id);
#ifdef CONFIG_SMB_INSECURE_SERVER
			if (hash_hashed(&sess->hlist))
				hash_del_rcu(&sess->hlist);
#else
			hash_del_rcu(&sess->hlist);
#endif
			expired[nr_expired++] = sess;
			continue;
		}
	}
	up_write(&conn->session_lock);
	mutex_unlock(&sessions_table_lock);

	if (nr_expired) {
		synchronize_rcu();
		for (i = 0; i < nr_expired; i++)
			ksmbd_session_destroy(expired[i]);
	}
}

int ksmbd_session_register(struct ksmbd_conn *conn,
			   struct ksmbd_session *sess)
{
	sess->dialect = conn->dialect;
	memcpy(sess->ClientGUID, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE);
	ksmbd_expire_session(conn);
	return xa_err(xa_store(&conn->sessions, sess->id, sess, KSMBD_DEFAULT_GFP));
}

static int ksmbd_chann_del(struct ksmbd_conn *conn, struct ksmbd_session *sess)
{
	struct channel *chann;

	chann = xa_erase(&sess->ksmbd_chann_list, (long)conn);
	if (!chann)
		return -ENOENT;

	kfree(chann);
	return 0;
}

void ksmbd_sessions_deregister(struct ksmbd_conn *conn)
{
	struct ksmbd_session *sess;
	struct hlist_node *tmp, *n;
	HLIST_HEAD(to_destroy);
	unsigned long id;

	mutex_lock(&sessions_table_lock);
	if (conn->binding) {
		int bkt;

		hash_for_each_safe(sessions_table, bkt, tmp,
				   sess, hlist) {
			if (!ksmbd_chann_del(conn, sess) &&
			    xa_empty(&sess->ksmbd_chann_list)) {
#ifdef CONFIG_SMB_INSECURE_SERVER
				if (hash_hashed(&sess->hlist))
					hash_del_rcu(&sess->hlist);
#else
				hash_del_rcu(&sess->hlist);
#endif
				down_write(&conn->session_lock);
				xa_erase(&conn->sessions, sess->id);
				up_write(&conn->session_lock);
				if (refcount_dec_and_test(&sess->refcnt))
					hlist_add_head(&sess->hlist,
						       &to_destroy);
				continue;
			}
		}
	}

	down_write(&conn->session_lock);
	xa_for_each(&conn->sessions, id, sess) {
		unsigned long chann_id;
		struct channel *chann;

		xa_for_each(&sess->ksmbd_chann_list, chann_id, chann) {
			if (chann->conn != conn)
				ksmbd_conn_set_exiting(chann->conn);
		}

		ksmbd_chann_del(conn, sess);
		if (xa_empty(&sess->ksmbd_chann_list)) {
			xa_erase(&conn->sessions, sess->id);
#ifdef CONFIG_SMB_INSECURE_SERVER
			if (hash_hashed(&sess->hlist))
				hash_del_rcu(&sess->hlist);
#else
			hash_del_rcu(&sess->hlist);
#endif
			if (refcount_dec_and_test(&sess->refcnt))
				hlist_add_head(&sess->hlist, &to_destroy);
		}
	}
	up_write(&conn->session_lock);
	mutex_unlock(&sessions_table_lock);

	if (!hlist_empty(&to_destroy)) {
		synchronize_rcu();
		hlist_for_each_entry_safe(sess, n, &to_destroy, hlist)
			ksmbd_session_destroy(sess);
	}
}

bool is_ksmbd_session_in_connection(struct ksmbd_conn *conn,
				   unsigned long long id)
{
	struct ksmbd_session *sess;

	down_read(&conn->session_lock);
	sess = xa_load(&conn->sessions, id);
	if (sess) {
		up_read(&conn->session_lock);
		return true;
	}
	up_read(&conn->session_lock);

	return false;
}

struct ksmbd_session *ksmbd_session_lookup(struct ksmbd_conn *conn,
					   unsigned long long id)
{
	struct ksmbd_session *sess;

	down_read(&conn->session_lock);
	sess = xa_load(&conn->sessions, id);
	if (sess) {
		sess->last_active = jiffies;
		ksmbd_user_session_get(sess);
	}
	up_read(&conn->session_lock);
	return sess;
}

/**
 * ksmbd_session_lookup_slowpath() - Look up session by ID from
 *                                   global table
 * @id: session ID to look up
 *
 * Uses RCU for lock-free read-side lookup of sessions in the
 * global sessions hash table. Takes a reference on the session
 * if found.
 *
 * Return: session with incremented refcount, or NULL
 */
struct ksmbd_session *ksmbd_session_lookup_slowpath(unsigned long long id)
{
	struct ksmbd_session *sess;

	rcu_read_lock();
	sess = __session_lookup(id);
	if (sess) {
		if (!refcount_inc_not_zero(&sess->refcnt))
			sess = NULL;
	}
	rcu_read_unlock();

	return sess;
}

struct ksmbd_session *ksmbd_session_lookup_all(struct ksmbd_conn *conn,
					       unsigned long long id)
{
	struct ksmbd_session *sess;

	sess = ksmbd_session_lookup(conn, id);
	if (!sess && conn->binding)
		sess = ksmbd_session_lookup_slowpath(id);
	if (sess) {
		down_read(&sess->state_lock);
		if (sess->state != SMB2_SESSION_VALID) {
			up_read(&sess->state_lock);
			ksmbd_user_session_put(sess);
			sess = NULL;
		} else {
			up_read(&sess->state_lock);
		}
	}
	return sess;
}

void ksmbd_user_session_get(struct ksmbd_session *sess)
{
	refcount_inc(&sess->refcnt);
}

void ksmbd_user_session_put(struct ksmbd_session *sess)
{
	if (!sess)
		return;

	if (refcount_read(&sess->refcnt) <= 0)
		WARN_ON(1);
	else if (refcount_dec_and_test(&sess->refcnt))
		ksmbd_session_destroy(sess);
}

struct preauth_session *ksmbd_preauth_session_alloc(struct ksmbd_conn *conn,
						    u64 sess_id)
{
	struct preauth_session *sess;

	sess = kmalloc(sizeof(struct preauth_session), KSMBD_DEFAULT_GFP);
	if (!sess)
		return NULL;

	sess->id = sess_id;
	memcpy(sess->Preauth_HashValue, conn->preauth_info->Preauth_HashValue,
	       PREAUTH_HASHVALUE_SIZE);
	list_add(&sess->preauth_entry, &conn->preauth_sess_table);

	return sess;
}

void destroy_previous_session(struct ksmbd_conn *conn,
			      struct ksmbd_user *user, u64 id)
{
	struct ksmbd_session *prev_sess;
	struct ksmbd_user *prev_user;
	bool needs_setup_status = false;
	int err;

	prev_sess = NULL;
	mutex_lock(&sessions_table_lock);
	down_write(&conn->session_lock);
	rcu_read_lock();
	prev_sess = __session_lookup(id);
	if (prev_sess && !refcount_inc_not_zero(&prev_sess->refcnt))
		prev_sess = NULL;
	rcu_read_unlock();
	if (!prev_sess)
		goto out;

	down_write(&prev_sess->state_lock);
	if (prev_sess->state == SMB2_SESSION_EXPIRED) {
		up_write(&prev_sess->state_lock);
		goto out_put;
	}

	prev_user = prev_sess->user;
	if (!prev_user ||
	    strcmp(user->name, prev_user->name) ||
	    user->passkey_sz != prev_user->passkey_sz ||
	    crypto_memneq(user->passkey, prev_user->passkey,
			  user->passkey_sz)) {
		up_write(&prev_sess->state_lock);
		goto out_put;
	}

	ksmbd_all_conn_set_status(id, KSMBD_SESS_NEED_RECONNECT);
	needs_setup_status = true;
	up_write(&prev_sess->state_lock);
	up_write(&conn->session_lock);
	mutex_unlock(&sessions_table_lock);

	/*
	 * Avoid holding session table/state locks while waiting for
	 * in-flight requests. Keeping these locks held can block request
	 * completion paths and cause reconnect stalls.
	 */
	err = ksmbd_conn_wait_idle_sess_id(conn, id);
	if (err) {
		ksmbd_all_conn_set_status(id, KSMBD_SESS_NEED_SETUP);
		goto out_session_put;
	}

	mutex_lock(&sessions_table_lock);
	down_write(&conn->session_lock);
	down_write(&prev_sess->state_lock);
	if (prev_sess->state != SMB2_SESSION_EXPIRED) {
		ksmbd_destroy_file_table(&prev_sess->file_table);
		prev_sess->state = SMB2_SESSION_EXPIRED;
		ksmbd_launch_ksmbd_durable_scavenger();
	}

	if (needs_setup_status)
		ksmbd_all_conn_set_status(id, KSMBD_SESS_NEED_SETUP);
	up_write(&prev_sess->state_lock);
	up_write(&conn->session_lock);
	mutex_unlock(&sessions_table_lock);

out_session_put:
	ksmbd_user_session_put(prev_sess);
	return;

out_put:
	ksmbd_user_session_put(prev_sess);
out:
	up_write(&conn->session_lock);
	mutex_unlock(&sessions_table_lock);
}

static bool ksmbd_preauth_session_id_match(struct preauth_session *sess,
					   unsigned long long id)
{
	return sess->id == id;
}

struct preauth_session *ksmbd_preauth_session_lookup(struct ksmbd_conn *conn,
						     unsigned long long id)
{
	struct preauth_session *sess = NULL;

	list_for_each_entry(sess, &conn->preauth_sess_table, preauth_entry) {
		if (ksmbd_preauth_session_id_match(sess, id))
			return sess;
	}
	return NULL;
}

#ifdef CONFIG_SMB_INSECURE_SERVER
static int __init_smb1_session(struct ksmbd_session *sess)
{
	int id = ksmbd_acquire_smb1_uid(&session_ida);

	if (id < 0)
		return -EINVAL;
	sess->id = id;
	return 0;
}
#endif

static int __init_smb2_session(struct ksmbd_session *sess)
{
	/*
	 * Note: Session IDs are allocated sequentially via IDA, which
	 * could allow enumeration. This is a minor info-leak but
	 * cannot easily use get_random_u64() since the ID is used as
	 * an xarray index throughout the session management code.
	 */
	int id = ksmbd_acquire_smb2_uid(&session_ida);

	if (id < 0)
		return -EINVAL;
	sess->id = id;
	return 0;
}

static struct ksmbd_session *__session_create(int protocol)
{
	struct ksmbd_session *sess;
	int ret;

	sess = kzalloc(sizeof(struct ksmbd_session), KSMBD_DEFAULT_GFP);
	if (!sess)
		return NULL;

	if (ksmbd_init_file_table(&sess->file_table))
		goto error;

	sess->last_active = jiffies;
	sess->state = SMB2_SESSION_IN_PROGRESS;
	init_rwsem(&sess->state_lock);
	set_session_flag(sess, protocol);
	xa_init(&sess->tree_conns);
	xa_init(&sess->ksmbd_chann_list);
	xa_init(&sess->rpc_handle_list);
	sess->sequence_number = 1;
	rwlock_init(&sess->tree_conns_lock);
	refcount_set(&sess->refcnt, 2);
	init_rwsem(&sess->rpc_lock);
	atomic64_set(&sess->gcm_nonce_counter, 0);
	get_random_bytes(sess->gcm_nonce_prefix,
			 sizeof(sess->gcm_nonce_prefix));

	switch (protocol) {
#ifdef CONFIG_SMB_INSECURE_SERVER
	case CIFDS_SESSION_FLAG_SMB1:
		ret = __init_smb1_session(sess);
		break;
#endif
	case CIFDS_SESSION_FLAG_SMB2:
		ret = __init_smb2_session(sess);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret)
		goto error;

	ida_init(&sess->tree_conn_ida);

	mutex_lock(&sessions_table_lock);
	hash_add_rcu(sessions_table, &sess->hlist, sess->id);
	mutex_unlock(&sessions_table_lock);

	return sess;

error:
	ksmbd_session_destroy(sess);
	return NULL;
}

#ifdef CONFIG_SMB_INSECURE_SERVER
struct ksmbd_session *ksmbd_smb1_session_create(void)
{
	return __session_create(CIFDS_SESSION_FLAG_SMB1);
}
#endif

struct ksmbd_session *ksmbd_smb2_session_create(void)
{
	return __session_create(CIFDS_SESSION_FLAG_SMB2);
}

int ksmbd_acquire_tree_conn_id(struct ksmbd_session *sess)
{
	int id = -EINVAL;

#ifdef CONFIG_SMB_INSECURE_SERVER
	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB1))
		id = ksmbd_acquire_smb1_tid(&sess->tree_conn_ida);
#endif
	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB2))
		id = ksmbd_acquire_smb2_tid(&sess->tree_conn_ida);

	return id;
}

void ksmbd_release_tree_conn_id(struct ksmbd_session *sess, int id)
{
	if (id >= 0)
		ksmbd_release_id(&sess->tree_conn_ida, id);
}
