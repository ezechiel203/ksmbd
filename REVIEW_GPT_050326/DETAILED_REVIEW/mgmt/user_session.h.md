# Line-by-line Review: src/mgmt/user_session.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#ifndef __USER_SESSION_MANAGEMENT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __USER_SESSION_MANAGEMENT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/hashtable.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/refcount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/xarray.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/atomic.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "ntlmssp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#define CIFDS_SESSION_FLAG_SMB1		BIT(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define CIFDS_SESSION_FLAG_SMB2		BIT(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#define PREAUTH_HASHVALUE_SIZE		64`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `struct ksmbd_file_table;`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `struct channel {`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	__u8			smb3signingkey[SMB3_SIGN_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	struct ksmbd_conn	*conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	atomic64_t		nonce_counter;  /* per-channel nonce counter for AES-GCM */`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `struct preauth_session {`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	__u8			Preauth_HashValue[PREAUTH_HASHVALUE_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	u64			id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	struct list_head	preauth_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `struct ksmbd_session {`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	u64				id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	__u16				dialect;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [PROTO_GATE|] `	char				ClientGUID[SMB2_CLIENT_GUID_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	struct ksmbd_user		*user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	unsigned int			sequence_number;`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	unsigned int			flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	bool				sign;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	bool				enc;        /* encryption keys generated */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	bool				enc_forced; /* per-session encryption required */`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	bool				is_anonymous;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	int				state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	struct rw_semaphore		state_lock; /* Protects state transitions */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	__u8				*Preauth_HashValue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	char				sess_key[CIFS_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	struct hlist_node		hlist;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	struct xarray			ksmbd_chann_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	struct xarray			tree_conns;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	struct ida			tree_conn_ida;`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	struct xarray			rpc_handle_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	__u8				smb3encryptionkey[SMB3_ENC_DEC_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	__u8				smb3decryptionkey[SMB3_ENC_DEC_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	__u8				smb3signingkey[SMB3_SIGN_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	struct ksmbd_file_table		file_table;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	unsigned long			last_active;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	rwlock_t			tree_conns_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	/* Monotonic GCM nonce counter to prevent nonce reuse */`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	atomic64_t			gcm_nonce_counter;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	__u8				gcm_nonce_prefix[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [LIFETIME|] `	refcount_t			refcnt;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00079 [NONE] `	struct rw_semaphore		rpc_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [LIFETIME|] `	struct rcu_head			rcu_head;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00081 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `static inline int test_session_flag(struct ksmbd_session *sess, int bit)`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	return sess->flags & bit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `static inline void set_session_flag(struct ksmbd_session *sess, int bit)`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	sess->flags |= bit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `static inline void clear_session_flag(struct ksmbd_session *sess, int bit)`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	sess->flags &= ~bit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `struct ksmbd_session *ksmbd_smb1_session_create(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `struct ksmbd_session *ksmbd_smb2_session_create(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `void ksmbd_session_destroy(struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `struct ksmbd_session *ksmbd_session_lookup_slowpath(unsigned long long id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `struct ksmbd_session *ksmbd_session_lookup(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `					   unsigned long long id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `bool is_ksmbd_session_in_connection(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `				     unsigned long long id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `int ksmbd_session_register(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `			   struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `void ksmbd_sessions_deregister(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `struct ksmbd_session *ksmbd_session_lookup_all(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `					       unsigned long long id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `void ksmbd_user_session_get(struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `void ksmbd_user_session_put(struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `void destroy_previous_session(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `			      struct ksmbd_user *user, u64 id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `struct preauth_session *ksmbd_preauth_session_alloc(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `						    u64 sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `struct preauth_session *ksmbd_preauth_session_lookup(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `						     unsigned long long id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `int ksmbd_preauth_session_remove(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `				 unsigned long long id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `int ksmbd_acquire_tree_conn_id(struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `void ksmbd_release_tree_conn_id(struct ksmbd_session *sess, int id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `int ksmbd_session_rpc_open(struct ksmbd_session *sess, char *rpc_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `void ksmbd_session_rpc_close(struct ksmbd_session *sess, int id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `int ksmbd_session_rpc_method(struct ksmbd_session *sess, int id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `#endif /* __USER_SESSION_MANAGEMENT_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
