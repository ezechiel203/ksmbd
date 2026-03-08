/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __USER_SESSION_MANAGEMENT_H__
#define __USER_SESSION_MANAGEMENT_H__

#include <linux/hashtable.h>
#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/xarray.h>
#include <linux/atomic.h>
#include <linux/mutex.h>

#include "smb_common.h"
#include "ntlmssp.h"

#ifdef CONFIG_SMB_INSECURE_SERVER
#define CIFDS_SESSION_FLAG_SMB1		BIT(0)

struct ksmbd_smb1_nttrans_state {
	__u16			mid;
	__u16			tid;
	__u16			pid;
	__u16			uid;
	__u16			function;
	__u8			setup_count;
	size_t			req_hdr_len;
	__u32			total_param_count;
	__u32			total_data_count;
	__u32			param_received;
	__u32			data_received;
	void			*req_hdr;
	char			*params;
	char			*data;
	unsigned long		*param_bitmap;
	unsigned long		*data_bitmap;
};
#endif
#define CIFDS_SESSION_FLAG_SMB2		BIT(1)

#define PREAUTH_HASHVALUE_SIZE		64

struct ksmbd_file_table;

struct channel {
	__u8			smb3signingkey[SMB3_SIGN_KEY_SIZE];
	struct ksmbd_conn	*conn;
	atomic64_t		nonce_counter;  /* per-channel nonce counter for AES-GCM */
};

struct preauth_session {
	__u8			Preauth_HashValue[PREAUTH_HASHVALUE_SIZE];
	__u8			binding_sess_key[SMB2_NTLMV2_SESSKEY_SIZE];
	u64			id;
	bool			binding_sess_key_valid;
	struct list_head	preauth_entry;
};

struct ksmbd_session {
	u64				id;

	__u16				dialect;
	char				ClientGUID[SMB2_CLIENT_GUID_SIZE];

	struct ksmbd_user		*user;
	unsigned int			sequence_number;
	unsigned int			flags;

	bool				sign;
	bool				enc;        /* encryption keys generated */
	bool				enc_forced; /* per-session encryption required */
	bool				is_anonymous;
	bool				in_progress_counted; /* counted in conn->in_progress_sessions */

	__u16				cli_sec_mode; /* negotiate SecurityMode from original connection */
	__u16				srv_sec_mode; /* signing mode from original connection */

	int				state;
	struct rw_semaphore		state_lock; /* Protects state transitions */
	__u8				*Preauth_HashValue;

	char				sess_key[CIFS_KEY_SIZE];

	struct hlist_node		hlist;
	struct xarray			ksmbd_chann_list;
	struct xarray			tree_conns;
	struct ida			tree_conn_ida;
	struct xarray			rpc_handle_list;
#ifdef CONFIG_SMB_INSECURE_SERVER
	struct xarray			smb1_nttrans_list;
	struct mutex			smb1_nttrans_lock;
#endif

	__u8				smb3encryptionkey[SMB3_ENC_DEC_KEY_SIZE];
	__u8				smb3decryptionkey[SMB3_ENC_DEC_KEY_SIZE];
	__u8				smb3signingkey[SMB3_SIGN_KEY_SIZE];

	struct ksmbd_file_table		file_table;
	unsigned long			last_active;
	rwlock_t			tree_conns_lock;

	/* Monotonic GCM nonce counter to prevent nonce reuse */
	atomic64_t			gcm_nonce_counter;
	__u8				gcm_nonce_prefix[4];

	refcount_t			refcnt;
	struct rw_semaphore		rpc_lock;
	struct rcu_head			rcu_head;
};

static inline int test_session_flag(struct ksmbd_session *sess, int bit)
{
	return sess->flags & bit;
}

static inline void set_session_flag(struct ksmbd_session *sess, int bit)
{
	sess->flags |= bit;
}

static inline void clear_session_flag(struct ksmbd_session *sess, int bit)
{
	sess->flags &= ~bit;
}

#ifdef CONFIG_SMB_INSECURE_SERVER
struct ksmbd_session *ksmbd_smb1_session_create(void);
#endif
struct ksmbd_session *ksmbd_smb2_session_create(void);

void ksmbd_session_destroy(struct ksmbd_session *sess);

struct ksmbd_session *ksmbd_session_lookup_slowpath(unsigned long long id);
struct ksmbd_session *ksmbd_session_lookup(struct ksmbd_conn *conn,
					   unsigned long long id);
bool is_ksmbd_session_in_connection(struct ksmbd_conn *conn,
				     unsigned long long id);
int ksmbd_session_register(struct ksmbd_conn *conn,
			   struct ksmbd_session *sess);
void ksmbd_sessions_deregister(struct ksmbd_conn *conn);
struct ksmbd_session *ksmbd_session_lookup_all(struct ksmbd_conn *conn,
					       unsigned long long id);
void ksmbd_user_session_get(struct ksmbd_session *sess);
void ksmbd_user_session_put(struct ksmbd_session *sess);
void destroy_previous_session(struct ksmbd_conn *conn,
			      struct ksmbd_user *user, u64 id);
struct preauth_session *ksmbd_preauth_session_alloc(struct ksmbd_conn *conn,
						    struct ksmbd_session *sess);
struct preauth_session *ksmbd_preauth_session_lookup(struct ksmbd_conn *conn,
						     unsigned long long id);
int ksmbd_preauth_session_store_sess_key(struct ksmbd_conn *conn,
					 unsigned long long id,
					 const __u8 *sess_key,
					 unsigned int sess_key_len);
void ksmbd_preauth_session_free(struct preauth_session *sess);
int ksmbd_preauth_session_remove(struct ksmbd_conn *conn,
				 unsigned long long id);

int ksmbd_acquire_tree_conn_id(struct ksmbd_session *sess);
void ksmbd_release_tree_conn_id(struct ksmbd_session *sess, int id);

int ksmbd_session_rpc_open(struct ksmbd_session *sess, char *rpc_name);
void ksmbd_session_rpc_close(struct ksmbd_session *sess, int id);
int ksmbd_session_rpc_method(struct ksmbd_session *sess, int id);
int ksmbd_session_rpc_method_name(const char *rpc_name);
#endif /* __USER_SESSION_MANAGEMENT_H__ */
