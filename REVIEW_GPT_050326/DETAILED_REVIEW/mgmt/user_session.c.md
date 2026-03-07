# Line-by-line Review: src/mgmt/user_session.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/rwsem.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/mutex.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/xarray.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/random.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <crypto/algapi.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "ksmbd_ida.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "ksmbd_witness.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `static DEFINE_IDA(session_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define SESSION_HASH_BITS		12`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `static DEFINE_HASHTABLE(sessions_table, SESSION_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `static DEFINE_MUTEX(sessions_table_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `struct ksmbd_session_rpc {`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	int			id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	unsigned int		method;`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `static void free_channel_list(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	struct channel *chann;`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	unsigned long index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	xa_for_each(&sess->ksmbd_chann_list, index, chann) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `		xa_erase(&sess->ksmbd_chann_list, index);`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `		memzero_explicit(chann->smb3signingkey, sizeof(chann->smb3signingkey));`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `		kfree(chann);`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	xa_destroy(&sess->ksmbd_chann_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `static void __session_rpc_close(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `				struct ksmbd_session_rpc *entry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	struct ksmbd_rpc_command *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	resp = ksmbd_rpc_close(sess, entry->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	if (!resp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [ERROR_PATH|] `		pr_err("Unable to close RPC pipe %d\n", entry->id);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	kvfree(resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	ksmbd_rpc_id_free(entry->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	kfree(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `static void ksmbd_session_rpc_clear_list(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	struct ksmbd_session_rpc *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	long index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [LOCK|] `	down_write(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00070 [NONE] `	xa_for_each(&sess->rpc_handle_list, index, entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `		xa_erase(&sess->rpc_handle_list, index);`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `		__session_rpc_close(sess, entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [LOCK|] `	up_write(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	xa_destroy(&sess->rpc_handle_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `static int __rpc_method(char *rpc_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	if (!strcmp(rpc_name, "\\srvsvc") || !strcmp(rpc_name, "srvsvc"))`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `		return KSMBD_RPC_SRVSVC_METHOD_INVOKE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	if (!strcmp(rpc_name, "\\wkssvc") || !strcmp(rpc_name, "wkssvc"))`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `		return KSMBD_RPC_WKSSVC_METHOD_INVOKE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	if (!strcmp(rpc_name, "LANMAN") || !strcmp(rpc_name, "lanman"))`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		return KSMBD_RPC_RAP_METHOD;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	if (!strcmp(rpc_name, "\\samr") || !strcmp(rpc_name, "samr"))`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `		return KSMBD_RPC_SAMR_METHOD_INVOKE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	if (!strcmp(rpc_name, "\\lsarpc") || !strcmp(rpc_name, "lsarpc"))`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `		return KSMBD_RPC_LSARPC_METHOD_INVOKE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [ERROR_PATH|] `	pr_err("Unsupported RPC: %s\n", rpc_name);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00097 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `int ksmbd_session_rpc_open(struct ksmbd_session *sess, char *rpc_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	struct ksmbd_session_rpc *entry, *old;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	struct ksmbd_rpc_command *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	int method, id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	method = __rpc_method(rpc_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	if (!method)`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [MEM_BOUNDS|] `	entry = kzalloc(sizeof(struct ksmbd_session_rpc), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00111 [NONE] `	if (!entry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	entry->method = method;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	entry->id = id = ksmbd_ipc_id_alloc();`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	if (id < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [ERROR_PATH|] `		goto free_entry;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [LOCK|] `	down_write(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00120 [NONE] `	old = xa_store(&sess->rpc_handle_list, id, entry, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	if (xa_is_err(old)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [LOCK|] `		up_write(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00123 [ERROR_PATH|] `		goto free_id;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00124 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	resp = ksmbd_rpc_open(sess, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	if (!resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		xa_erase(&sess->rpc_handle_list, entry->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [LOCK|] `		up_write(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00130 [ERROR_PATH|] `		goto free_id;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00131 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [LOCK|] `	up_write(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00134 [NONE] `	kvfree(resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	return id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `free_id:`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	ksmbd_rpc_id_free(entry->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `free_entry:`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	kfree(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00141 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `void ksmbd_session_rpc_close(struct ksmbd_session *sess, int id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	struct ksmbd_session_rpc *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [LOCK|] `	down_write(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00148 [NONE] `	entry = xa_erase(&sess->rpc_handle_list, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	if (entry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `		__session_rpc_close(sess, entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [LOCK|] `	up_write(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00152 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `int ksmbd_session_rpc_method(struct ksmbd_session *sess, int id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	struct ksmbd_session_rpc *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	lockdep_assert_held(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	entry = xa_load(&sess->rpc_handle_list, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	return entry ? entry->method : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `void ksmbd_session_destroy(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	if (!sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	/* Clean up any witness registrations owned by this session */`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	ksmbd_witness_unregister_session(sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	if (sess->user)`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `		ksmbd_free_user(sess->user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	ksmbd_tree_conn_session_logoff(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	ksmbd_destroy_file_table(&sess->file_table);`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	ksmbd_launch_ksmbd_durable_scavenger();`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	ksmbd_session_rpc_clear_list(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	free_channel_list(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	memzero_explicit(sess->sess_key, sizeof(sess->sess_key));`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	memzero_explicit(sess->smb3encryptionkey, sizeof(sess->smb3encryptionkey));`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	memzero_explicit(sess->smb3decryptionkey, sizeof(sess->smb3decryptionkey));`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	memzero_explicit(sess->smb3signingkey, sizeof(sess->smb3signingkey));`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	kfree_sensitive(sess->Preauth_HashValue);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	ksmbd_release_id(&session_ida, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	kfree_sensitive(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `static struct ksmbd_session *__session_lookup(unsigned long long id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [LIFETIME|] `	lockdep_assert(rcu_read_lock_held());`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	hash_for_each_possible_rcu(sessions_table, sess, hlist, id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		if (id == sess->id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `			return sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ` * ksmbd_expire_session() - expire stale sessions on a connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ` * @conn: connection whose sessions should be checked`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ` * Collects expired sessions in batches to avoid unbounded stack usage.`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ` * Loops until all expired sessions have been cleaned up, ensuring that`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ` * a burst of stale sessions does not accumulate indefinitely.`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `static void ksmbd_expire_session(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	struct ksmbd_session *expired[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	int nr_expired, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `again:`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	nr_expired = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [LOCK|] `	mutex_lock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00219 [LOCK|] `	down_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00220 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		unsigned long id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `		struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		xa_for_each(&conn->sessions, id, sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `			int state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `			if (nr_expired >= ARRAY_SIZE(expired))`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [LOCK|] `			down_read(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00230 [NONE] `			state = sess->state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `			up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [LIFETIME|] `			if (refcount_read(&sess->refcnt) <= 1 &&`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00233 [PROTO_GATE|] `			    (state != SMB2_SESSION_VALID ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00234 [NONE] `			     time_after(jiffies,`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `				       READ_ONCE(sess->last_active) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [PROTO_GATE|] `				       SMB2_SESSION_TIMEOUT))) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00237 [NONE] `				xa_erase(&conn->sessions, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `				if (hash_hashed(&sess->hlist))`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `					hash_del_rcu(&sess->hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `				hash_del_rcu(&sess->hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `				expired[nr_expired++] = sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [LOCK|] `	up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00250 [LOCK|] `	mutex_unlock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	if (nr_expired) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `		synchronize_rcu();`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `		for (i = 0; i < nr_expired; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `			ksmbd_session_destroy(expired[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		/* More expired sessions may remain; loop to drain them all */`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `		if (nr_expired >= ARRAY_SIZE(expired))`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [ERROR_PATH|] `			goto again;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00259 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `int ksmbd_session_register(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `			   struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	sess->dialect = conn->dialect;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [MEM_BOUNDS|PROTO_GATE|] `	memcpy(sess->ClientGUID, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00267 [NONE] `	ksmbd_expire_session(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	return xa_err(xa_store(&conn->sessions, sess->id, sess, KSMBD_DEFAULT_GFP));`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `static int ksmbd_chann_del(struct ksmbd_conn *conn, struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `	struct channel *chann;`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	chann = xa_erase(&sess->ksmbd_chann_list, (long)conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	if (!chann)`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	memzero_explicit(chann->smb3signingkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `			 sizeof(chann->smb3signingkey));`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `	kfree(chann);`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `void ksmbd_sessions_deregister(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	struct hlist_node *tmp, *n;`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	HLIST_HEAD(to_destroy);`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	unsigned long id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [LOCK|] `	mutex_lock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00293 [NONE] `	if (conn->binding) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `		int bkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `		hash_for_each_safe(sessions_table, bkt, tmp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `				   sess, hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `			if (!ksmbd_chann_del(conn, sess) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `			    xa_empty(&sess->ksmbd_chann_list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `				if (hash_hashed(&sess->hlist))`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `					hash_del_rcu(&sess->hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `				hash_del_rcu(&sess->hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [LOCK|] `				down_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00307 [NONE] `				xa_erase(&conn->sessions, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [LOCK|] `				up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00309 [LIFETIME|] `				if (refcount_dec_and_test(&sess->refcnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00310 [NONE] `					hlist_add_head(&sess->hlist,`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `						       &to_destroy);`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [LOCK|] `	down_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00318 [NONE] `	xa_for_each(&conn->sessions, id, sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `		unsigned long chann_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `		struct channel *chann;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `		xa_for_each(&sess->ksmbd_chann_list, chann_id, chann) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `			if (chann->conn != conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `				ksmbd_conn_set_exiting(chann->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `		ksmbd_chann_del(conn, sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `		if (xa_empty(&sess->ksmbd_chann_list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `			xa_erase(&conn->sessions, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `			if (hash_hashed(&sess->hlist))`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `				hash_del_rcu(&sess->hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `			hash_del_rcu(&sess->hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [LIFETIME|] `			if (refcount_dec_and_test(&sess->refcnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00337 [NONE] `				hlist_add_head(&sess->hlist, &to_destroy);`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [LOCK|] `	up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00341 [LOCK|] `	mutex_unlock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	if (!hlist_empty(&to_destroy)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `		synchronize_rcu();`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `		hlist_for_each_entry_safe(sess, n, &to_destroy, hlist)`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `			ksmbd_session_destroy(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `bool is_ksmbd_session_in_connection(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `				   unsigned long long id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	bool found;`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [LOCK|] `	down_read(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00357 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00358 [NONE] `	sess = xa_load(&conn->sessions, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	found = !!sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00361 [NONE] `	up_read(&conn->session_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	return found;`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `struct ksmbd_session *ksmbd_session_lookup(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `					   unsigned long long id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [LOCK|] `	down_read(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00372 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00373 [NONE] `	sess = xa_load(&conn->sessions, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	if (sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `		WRITE_ONCE(sess->last_active, jiffies);`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `		ksmbd_user_session_get(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00379 [NONE] `	up_read(&conn->session_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	return sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] ` * ksmbd_session_lookup_slowpath() - Look up session by ID from`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ` *                                   global table`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] ` * @id: session ID to look up`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [LIFETIME|] ` * Uses RCU for lock-free read-side lookup of sessions in the`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00389 [NONE] ` * global sessions hash table. Takes a reference on the session`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] ` * if found.`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ` * Return: session with incremented refcount, or NULL`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `struct ksmbd_session *ksmbd_session_lookup_slowpath(unsigned long long id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00399 [NONE] `	sess = __session_lookup(id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	if (sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [LIFETIME|] `		if (!refcount_inc_not_zero(&sess->refcnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00402 [NONE] `			sess = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `			WRITE_ONCE(sess->last_active, jiffies);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00407 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	return sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `struct ksmbd_session *ksmbd_session_lookup_all(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `					       unsigned long long id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	sess = ksmbd_session_lookup(conn, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	if (!sess && conn->binding)`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `		sess = ksmbd_session_lookup_slowpath(id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	if (sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [LOCK|] `		down_read(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00421 [PROTO_GATE|] `		if (sess->state != SMB2_SESSION_VALID) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00422 [NONE] `			up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `			ksmbd_user_session_put(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `			sess = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `			up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	return sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `void ksmbd_user_session_get(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [LIFETIME|] `	refcount_inc(&sess->refcnt);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00435 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `void ksmbd_user_session_put(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	if (!sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [LIFETIME|] `	if (refcount_read(&sess->refcnt) <= 0) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00443 [ERROR_PATH|] `		WARN_ON(1);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00444 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [LIFETIME|] `	if (refcount_dec_and_test(&sess->refcnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00447 [NONE] `		ksmbd_session_destroy(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] ` * Caller must hold conn->session_lock for writing.`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `struct preauth_session *ksmbd_preauth_session_alloc(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `						    u64 sess_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	struct preauth_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [MEM_BOUNDS|] `	sess = kmalloc(sizeof(struct preauth_session), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00459 [NONE] `	if (!sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	sess->id = sess_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [MEM_BOUNDS|] `	memcpy(sess->Preauth_HashValue, conn->preauth_info->Preauth_HashValue,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00464 [NONE] `	       PREAUTH_HASHVALUE_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	list_add(&sess->preauth_entry, &conn->preauth_sess_table);`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	return sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `void destroy_previous_session(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `			      struct ksmbd_user *user, u64 id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	struct ksmbd_session *prev_sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	struct ksmbd_user *prev_user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `	bool needs_setup_status = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	prev_sess = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [LOCK|] `	mutex_lock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00480 [LOCK|] `	down_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00481 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00482 [NONE] `	prev_sess = __session_lookup(id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [LIFETIME|] `	if (prev_sess && !refcount_inc_not_zero(&prev_sess->refcnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00484 [NONE] `		prev_sess = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00486 [NONE] `	if (!prev_sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [LOCK|] `	down_write(&prev_sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00490 [PROTO_GATE|] `	if (prev_sess->state == SMB2_SESSION_EXPIRED) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00491 [LOCK|] `		up_write(&prev_sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00492 [ERROR_PATH|] `		goto out_put;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00493 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	prev_user = prev_sess->user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	if (!prev_user ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	    strcmp(user->name, prev_user->name) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	    user->passkey_sz != prev_user->passkey_sz ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	    crypto_memneq(user->passkey, prev_user->passkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `			  user->passkey_sz)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [LOCK|] `		up_write(&prev_sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00502 [ERROR_PATH|] `		goto out_put;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00503 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	ksmbd_all_conn_set_status(id, KSMBD_SESS_NEED_RECONNECT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	needs_setup_status = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [LOCK|] `	up_write(&prev_sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00508 [LOCK|] `	up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00509 [LOCK|] `	mutex_unlock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00510 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	 * Avoid holding session table/state locks while waiting for`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	 * in-flight requests. Keeping these locks held can block request`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	 * completion paths and cause reconnect stalls.`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	err = ksmbd_conn_wait_idle_sess_id(conn, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `		ksmbd_all_conn_set_status(id, KSMBD_SESS_NEED_SETUP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [ERROR_PATH|] `		goto out_session_put;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00520 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [LOCK|] `	mutex_lock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00523 [LOCK|] `	down_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00524 [LOCK|] `	down_write(&prev_sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00525 [PROTO_GATE|] `	if (prev_sess->state != SMB2_SESSION_EXPIRED) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00526 [NONE] `		ksmbd_destroy_file_table(&prev_sess->file_table);`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [PROTO_GATE|] `		prev_sess->state = SMB2_SESSION_EXPIRED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00528 [NONE] `		ksmbd_launch_ksmbd_durable_scavenger();`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	if (needs_setup_status)`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `		ksmbd_all_conn_set_status(id, KSMBD_SESS_NEED_SETUP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [LOCK|] `	up_write(&prev_sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00534 [LOCK|] `	up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00535 [LOCK|] `	mutex_unlock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `out_session_put:`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	ksmbd_user_session_put(prev_sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `out_put:`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	ksmbd_user_session_put(prev_sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [LOCK|] `	up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00545 [LOCK|] `	mutex_unlock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00546 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `static bool ksmbd_preauth_session_id_match(struct preauth_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `					   unsigned long long id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	return sess->id == id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] ` * ksmbd_preauth_session_lookup() - look up a preauth session by ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] ` * @conn: connection to search`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] ` * @id:   session ID to find`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] ` * The caller MUST hold conn->session_lock (read or write) for the`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] ` * lifetime of the returned pointer.  The lock protects the preauth`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ` * session list from concurrent modification by session removal or`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] ` * connection teardown.`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] ` * Return: pointer to the preauth session, or NULL if not found`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `struct preauth_session *ksmbd_preauth_session_lookup(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `						     unsigned long long id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	struct preauth_session *sess = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	lockdep_assert_held(&conn->session_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `	list_for_each_entry(sess, &conn->preauth_sess_table, preauth_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `		if (ksmbd_preauth_session_id_match(sess, id))`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `			return sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `int ksmbd_preauth_session_remove(struct ksmbd_conn *conn, unsigned long long id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	struct preauth_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [LOCK|] `	down_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00584 [NONE] `	list_for_each_entry(sess, &conn->preauth_sess_table, preauth_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `		if (ksmbd_preauth_session_id_match(sess, id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `			list_del(&sess->preauth_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `			kfree(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [LOCK|] `			up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00589 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [LOCK|] `	up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00593 [ERROR_PATH|] `	return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00594 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `static int __init_smb1_session(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	int id = ksmbd_acquire_smb1_uid(&session_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	if (id < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00603 [NONE] `	sess->id = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `static int __init_smb2_session(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `	 * KNOWN ISSUE (P1 security): Session IDs are sequential (IDA-based),`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `	 * which allows remote enumeration and prediction of other active`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `	 * session IDs.  This aids session-targeted attacks during binding`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `	 * operations (ksmbd_session_lookup_all -> slowpath).`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `	 * Proper fix: XOR the IDA-allocated ID with a per-server random key`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `	 * (generated once at module init) so the wire-visible session ID is`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `	 * unpredictable while IDA still manages the ID space internally.`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `	 * This requires coordinated changes across session lookup, register,`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `	 * and destroy paths and is deferred to a dedicated patch.`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `	int id = ksmbd_acquire_smb2_uid(&session_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	if (id < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00626 [NONE] `	sess->id = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `static struct ksmbd_session *__session_create(int protocol)`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [MEM_BOUNDS|] `	sess = kzalloc(sizeof(struct ksmbd_session), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00636 [NONE] `	if (!sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `	if (ksmbd_init_file_table(&sess->file_table))`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [ERROR_PATH|] `		goto error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00641 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `	WRITE_ONCE(sess->last_active, jiffies);`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [PROTO_GATE|] `	sess->state = SMB2_SESSION_IN_PROGRESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00644 [NONE] `	init_rwsem(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `	set_session_flag(sess, protocol);`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	xa_init(&sess->tree_conns);`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `	xa_init(&sess->ksmbd_chann_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	xa_init(&sess->rpc_handle_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	sess->sequence_number = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	rwlock_init(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [LIFETIME|] `	refcount_set(&sess->refcnt, 2);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00652 [NONE] `	init_rwsem(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `	atomic64_set(&sess->gcm_nonce_counter, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `	get_random_bytes(sess->gcm_nonce_prefix,`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `			 sizeof(sess->gcm_nonce_prefix));`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `	switch (protocol) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	case CIFDS_SESSION_FLAG_SMB1:`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `		ret = __init_smb1_session(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `	case CIFDS_SESSION_FLAG_SMB2:`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `		ret = __init_smb2_session(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [ERROR_PATH|] `		goto error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00673 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	ida_init(&sess->tree_conn_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [LOCK|] `	mutex_lock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00677 [NONE] `	hash_add_rcu(sessions_table, &sess->hlist, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [LOCK|] `	mutex_unlock(&sessions_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00679 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `	return sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `error:`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `	ksmbd_session_destroy(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `struct ksmbd_session *ksmbd_smb1_session_create(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `	return __session_create(CIFDS_SESSION_FLAG_SMB1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `struct ksmbd_session *ksmbd_smb2_session_create(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `	return __session_create(CIFDS_SESSION_FLAG_SMB2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `int ksmbd_acquire_tree_conn_id(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `	int id = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB1))`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `		id = ksmbd_acquire_smb1_tid(&sess->tree_conn_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB2))`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `		id = ksmbd_acquire_smb2_tid(&sess->tree_conn_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	return id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `void ksmbd_release_tree_conn_id(struct ksmbd_session *sess, int id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	if (id >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `		ksmbd_release_id(&sess->tree_conn_ida, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
