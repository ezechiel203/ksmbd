# Line-by-line Review: src/core/connection.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/mutex.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/freezer.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/overflow.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "smb1pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "mgmt/ksmbd_ida.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "transport_tcp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "transport_rdma.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "transport_quic.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `static DEFINE_MUTEX(init_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `static struct ksmbd_conn_ops default_conn_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `struct ksmbd_conn_hash_bucket conn_hash[CONN_HASH_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [LIFETIME|] `atomic_t conn_hash_count = ATOMIC_INIT(0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` * ksmbd_conn_hash_init() - initialize per-bucket locks for conn hash`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `void ksmbd_conn_hash_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	for (i = 0; i < CONN_HASH_SIZE; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `		INIT_HLIST_HEAD(&conn_hash[i].head);`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `		spin_lock_init(&conn_hash[i].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [LIFETIME|] `	atomic_set(&conn_hash_count, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00052 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_hash_init);`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ` * ksmbd_conn_hash_add() - add connection to the hash table`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` * @conn:	connection to add`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ` * @key:	hash key (typically conn->inet_hash)`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `void ksmbd_conn_hash_add(struct ksmbd_conn *conn, unsigned int key)`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	unsigned int bkt = hash_min(key, CONN_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [LOCK|] `	spin_lock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00065 [NONE] `	hlist_add_head(&conn->hlist, &conn_hash[bkt].head);`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [LIFETIME|] `	atomic_inc(&conn_hash_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00067 [LOCK|] `	spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00068 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_hash_add);`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` * ksmbd_conn_hash_del() - remove connection from the hash table`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` * @conn:	connection to remove`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `void ksmbd_conn_hash_del(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	unsigned int bkt = hash_min(conn->inet_hash, CONN_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [LOCK|] `	spin_lock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00080 [NONE] `	if (!hlist_unhashed(&conn->hlist)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `		hlist_del_init(&conn->hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [LIFETIME|] `		atomic_dec(&conn_hash_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00083 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [LOCK|] `	spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00085 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_hash_del);`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * ksmbd_conn_hash_empty() - atomically check if the connection hash is empty`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * Uses a global atomic counter to avoid TOCTOU races that could occur`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` * when checking individual buckets non-atomically.`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` * Return:	true if no connections remain`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `bool ksmbd_conn_hash_empty(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [LIFETIME|] `	return atomic_read(&conn_hash_count) == 0;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00099 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_hash_empty);`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ` * ksmbd_conn_free() - free resources of the connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ` * @conn:	connection instance to be cleaned up`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` * During the thread termination, the corresponding conn instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` * resources(sock/memory) are released and finally the conn object is freed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `static void ksmbd_conn_cleanup(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	struct preauth_session *p, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	ksmbd_conn_hash_del(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	xa_destroy(&conn->sessions);`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	list_for_each_entry_safe(p, tmp, &conn->preauth_sess_table,`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `				 preauth_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `		list_del(&p->preauth_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `		kfree(p);`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	kvfree(conn->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	kfree(conn->preauth_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	kfree(conn->vals);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	/* Clean up Fruit SMB extension resources */`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	if (conn->fruit_state) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `		fruit_cleanup_connection_state(conn->fruit_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `		kfree(conn->fruit_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `		conn->fruit_state = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	conn->transport->ops->free_transport(conn->transport);`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	kfree(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `void ksmbd_conn_free(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [LIFETIME|] `	if (!refcount_dec_and_test(&conn->refcnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00144 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	ksmbd_conn_cleanup(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_free);`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ` * ksmbd_conn_alloc() - initialize a new connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ` * Return:	ksmbd_conn struct on success, otherwise NULL`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `struct ksmbd_conn *ksmbd_conn_alloc(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [MEM_BOUNDS|] `	conn = kzalloc(sizeof(struct ksmbd_conn), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00160 [NONE] `	if (!conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	conn->need_neg = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	ksmbd_conn_set_new(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	conn->local_nls = load_nls("utf8");`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	if (!conn->local_nls)`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `		conn->local_nls = load_nls_default();`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	if (IS_ENABLED(CONFIG_UNICODE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `		conn->um = utf8_load(UNICODE_AGE(12, 1, 0));`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `		conn->um = utf8_load("12.1.0");`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `		conn->um = ERR_PTR(-EOPNOTSUPP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	if (IS_ERR(conn->um))`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `		conn->um = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [LIFETIME|] `	atomic_set(&conn->req_running, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00179 [LIFETIME|] `	atomic_set(&conn->r_count, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00180 [LIFETIME|] `	atomic_set(&conn->outstanding_async, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00181 [LIFETIME|] `	refcount_set(&conn->refcnt, 1);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00182 [NONE] `	conn->total_credits = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	conn->outstanding_credits = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	init_waitqueue_head(&conn->req_running_q);`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	init_waitqueue_head(&conn->r_count_q);`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	INIT_LIST_HEAD(&conn->requests);`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	INIT_LIST_HEAD(&conn->async_requests);`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	spin_lock_init(&conn->request_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	spin_lock_init(&conn->credits_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	ida_init(&conn->async_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	xa_init(&conn->sessions);`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	spin_lock_init(&conn->llist_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	INIT_LIST_HEAD(&conn->lock_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `	init_rwsem(&conn->session_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	INIT_LIST_HEAD(&conn->preauth_sess_table);`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	return conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_alloc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `bool ksmbd_conn_lookup_dialect(struct ksmbd_conn *c)`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	struct ksmbd_conn *t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	for (i = 0; i < CONN_HASH_SIZE; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [LOCK|] `		spin_lock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00211 [NONE] `		hlist_for_each_entry(t, &conn_hash[i].head, hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `			if (!memcmp(t->ClientGUID, c->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [PROTO_GATE|] `				    SMB2_CLIENT_GUID_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00214 [LOCK|] `				spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00215 [NONE] `				return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [LOCK|] `		spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00219 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `void ksmbd_conn_enqueue_request(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	struct list_head *requests_queue = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	struct smb2_hdr *hdr = work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [PROTO_GATE|] `	if (hdr->ProtocolId == SMB2_PROTO_NUMBER) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00231 [PROTO_GATE|] `		if (conn->ops->get_cmd_val(work) != SMB2_CANCEL_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00232 [NONE] `			requests_queue = &conn->requests;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [PROTO_GATE|] `		if (conn->ops->get_cmd_val(work) != SMB_COM_NT_CANCEL)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00235 [NONE] `			requests_queue = &conn->requests;`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [PROTO_GATE|] `	if (conn->ops->get_cmd_val(work) != SMB2_CANCEL_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00239 [NONE] `		requests_queue = &conn->requests;`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [LIFETIME|] `	atomic_inc(&conn->req_running);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00243 [NONE] `	if (requests_queue) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [LOCK|] `		spin_lock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00245 [NONE] `		list_add_tail(&work->request_entry, requests_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [LOCK|] `		spin_unlock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00247 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `void ksmbd_conn_try_dequeue_request(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [LIFETIME|] `	atomic_dec(&conn->req_running);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00255 [NONE] `	if (waitqueue_active(&conn->req_running_q))`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		wake_up(&conn->req_running_q);`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [LOCK|] `	spin_lock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00259 [NONE] `	if (list_empty(&work->request_entry) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	    list_empty(&work->async_request_entry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [LOCK|] `		spin_unlock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00262 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	list_del_init(&work->request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [LOCK|] `	spin_unlock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00266 [NONE] `	if (work->asynchronous)`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		release_async_work(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	wake_up_all(&conn->req_running_q);`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `void ksmbd_conn_lock(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [LOCK|] `	mutex_lock(&conn->srv_mutex);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00275 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `void ksmbd_conn_unlock(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [LOCK|] `	mutex_unlock(&conn->srv_mutex);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00280 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `void ksmbd_all_conn_set_status(u64 sess_id, u32 status)`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	for (i = 0; i < CONN_HASH_SIZE; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [LOCK|] `		spin_lock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00289 [NONE] `		hlist_for_each_entry(conn, &conn_hash[i].head, hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [LIFETIME|] `			rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00291 [NONE] `			if (conn->binding ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `			    xa_load(&conn->sessions, sess_id))`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `				WRITE_ONCE(conn->status, status);`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [LIFETIME|] `			rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00295 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [LOCK|] `		spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00297 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `void ksmbd_conn_wait_idle(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [WAIT_LOOP|] `	if (!wait_event_timeout(conn->req_running_q,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00303 [LIFETIME|] `				atomic_read(&conn->req_running) < 2,`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00304 [NONE] `				120 * HZ))`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [ERROR_PATH|] `		pr_err_ratelimited("Timeout waiting for idle conn (req_running=%d, status=%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00306 [LIFETIME|] `				   atomic_read(&conn->req_running),`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00307 [NONE] `				   READ_ONCE(conn->status));`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `int ksmbd_conn_wait_idle_sess_id(struct ksmbd_conn *curr_conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `				 u64 sess_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	int rc, retry_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	int rcount, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	 * Maximum total retries to prevent infinite loops.  Each retry`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	 * waits up to 1 second (HZ), so 120 retries = 120 seconds max.`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `#define WAIT_IDLE_MAX_RETRIES	120`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `retry_idle:`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	if (retry_count >= WAIT_IDLE_MAX_RETRIES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [ERROR_PATH|] `		pr_err_ratelimited("wait_idle_sess_id: timed out after %d retries for session %llu\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00326 [NONE] `				   retry_count, sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00328 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	for (i = 0; i < CONN_HASH_SIZE; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [LOCK|] `		spin_lock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00332 [NONE] `		hlist_for_each_entry(conn, &conn_hash[i].head,`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `				     hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `			bool has_sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [LIFETIME|] `			rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00337 [NONE] `			has_sess = conn->binding ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `				   xa_load(&conn->sessions, sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [LIFETIME|] `			rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00340 [NONE] `			if (!has_sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `			rcount = (conn == curr_conn) ? 2 : 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [LIFETIME|] `			if (atomic_read(&conn->req_running) >=`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00345 [NONE] `			    rcount) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [LOCK|] `				spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00347 [WAIT_LOOP|] `				rc = wait_event_timeout(`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00348 [NONE] `					conn->req_running_q,`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [LIFETIME|] `					atomic_read(`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00350 [NONE] `					    &conn->req_running)`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `					    < rcount,`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `					HZ);`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `				 * Count every restart toward the limit,`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `				 * whether the wait timed out or succeeded,`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `				 * to prevent infinite loops when requests`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `				 * keep arriving between checks.`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `				retry_count++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [ERROR_PATH|] `				goto retry_idle;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00361 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [LOCK|] `		spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00364 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `int ksmbd_conn_write(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	size_t expected_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	int sent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	if (!work->response_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [ERROR_PATH|] `		pr_err("NULL response header\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00377 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00378 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	if (work->send_no_response)`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	if (!work->iov_idx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `		struct kvec iov[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `		int iov_idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `		size_t len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `		if (work->aux_payload_sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `			iov[iov_idx] = (struct kvec) { work->response_buf, work->resp_hdr_sz };`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `			len += iov[iov_idx++].iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `			iov[iov_idx] = (struct kvec) { work->aux_payload_buf, work->aux_payload_sz };`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `			len += iov[iov_idx++].iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `			iov[iov_idx].iov_len = get_rfc1002_len(work->response_buf) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `			iov[iov_idx].iov_base = work->response_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `			len += iov[iov_idx++].iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `		expected_len = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `		ksmbd_conn_lock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `		sent = conn->transport->ops->writev(conn->transport, &iov[0],`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `				iov_idx, len, work->need_invalidate_rkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `				work->remote_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `		ksmbd_conn_unlock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `		size_t len = get_rfc1002_len(work->iov[0].iov_base) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `		if (work->sendfile)`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `			len -= work->sendfile_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `		expected_len = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `		ksmbd_conn_lock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `		sent = conn->transport->ops->writev(conn->transport,`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `						    work->iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `						    work->iov_cnt, len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `						    work->need_invalidate_rkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `						    work->remote_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `		ksmbd_conn_unlock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	if (!work->iov_idx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00425 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `		size_t len = get_rfc1002_len(work->iov[0].iov_base) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `		 * For zero-copy sendfile, the rfc1002 length includes the`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `		 * file data size, but the iov only contains the header.`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `		 * Subtract the sendfile count so writev sends only the`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `		 * header bytes. The file data is sent separately below.`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `		if (work->sendfile)`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `			len -= work->sendfile_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `		expected_len = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `		ksmbd_conn_lock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `		sent = conn->transport->ops->writev(conn->transport,`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `						    work->iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `						    work->iov_cnt, len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `						    work->need_invalidate_rkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `						    work->remote_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `		ksmbd_conn_unlock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	if (sent < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [ERROR_PATH|] `		pr_err("Failed to send message: %d\n", sent);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00451 [NONE] `		return sent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	if (sent != expected_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [ERROR_PATH|] `		pr_warn_ratelimited("Short write: sent %d of %zu bytes\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00456 [NONE] `				    sent, expected_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	/* Send file data via zero-copy after the header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	if (work->sendfile && conn->transport->ops->sendfile) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `		loff_t offset = work->sendfile_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `		ksmbd_conn_lock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `		sent = conn->transport->ops->sendfile(conn->transport,`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `						      work->sendfile_filp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `						      &offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `						      work->sendfile_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `		ksmbd_conn_unlock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `		if (sent < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [ERROR_PATH|] `			pr_err("Failed to sendfile: %d\n", sent);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00470 [NONE] `			return sent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `int ksmbd_conn_rdma_read(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `			 void *buf, unsigned int buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `			 struct smb2_buffer_desc_v1 *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `			 unsigned int desc_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	int ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	if (conn->transport->ops->rdma_read)`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `		ret = conn->transport->ops->rdma_read(conn->transport,`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `						      buf, buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `						      desc, desc_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `int ksmbd_conn_rdma_write(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `			  void *buf, unsigned int buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `			  struct smb2_buffer_desc_v1 *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `			  unsigned int desc_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	int ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	if (conn->transport->ops->rdma_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `		ret = conn->transport->ops->rdma_write(conn->transport,`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `						       buf, buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `						       desc, desc_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `bool ksmbd_conn_alive(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	if (!ksmbd_server_running())`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	if (ksmbd_conn_exiting(conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	if ((current->flags & PF_KTHREAD) && kthread_should_stop())`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [LIFETIME|] `	if (atomic_read(&conn->stats.open_files_count) > 0)`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00517 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	 * Stop current session if the time that get last request from client`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `	 * is bigger than deadtime user configured and opening file count is`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	 * zero.`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	if (READ_ONCE(server_conf.deadtime) > 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	    time_after(jiffies, READ_ONCE(conn->last_active) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `		       READ_ONCE(server_conf.deadtime))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `		ksmbd_debug(CONN, "No response from client in %lu minutes\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `			    READ_ONCE(server_conf.deadtime) / SMB_ECHO_INTERVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `#define SMB1_MIN_SUPPORTED_HEADER_SIZE (sizeof(struct smb_hdr))`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [PROTO_GATE|] `#define SMB2_MIN_SUPPORTED_HEADER_SIZE (sizeof(struct smb2_hdr) + 4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] ` * ksmbd_conn_handler_loop() - session thread to listen on new smb requests`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] ` * @p:		connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] ` * One thread each per connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] ` * Return:	0 on success`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `int ksmbd_conn_handler_loop(void *p)`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	struct ksmbd_conn *conn = (struct ksmbd_conn *)p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	struct ksmbd_transport *t = conn->transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	unsigned int pdu_size, max_allowed_pdu_size, max_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	char hdr_buf[4] = {0,};`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	int size, rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `	mutex_init(&conn->srv_mutex);`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	__module_get(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	if (t->ops->prepare && t->ops->prepare(t))`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00558 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `	max_req = READ_ONCE(server_conf.max_inflight_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	WRITE_ONCE(conn->last_active, jiffies);`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `	set_freezable();`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `	while (ksmbd_conn_alive(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `		if (try_to_freeze())`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `		kvfree(conn->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `		conn->request_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `recheck:`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [LIFETIME|] `		if (atomic_read(&conn->req_running) + 1 > max_req) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00571 [WAIT_LOOP|] `			rc = wait_event_interruptible_timeout(conn->req_running_q,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00572 [LIFETIME|] `							      atomic_read(&conn->req_running) < max_req ||`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00573 [NONE] `							      !ksmbd_conn_alive(conn),`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `							      HZ);`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `			if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `			if (!ksmbd_conn_alive(conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [ERROR_PATH|] `			goto recheck;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00580 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `			size = t->ops->read(t, hdr_buf, sizeof(hdr_buf), -1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `			if (size != sizeof(hdr_buf))`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `			pdu_size = get_rfc1002_len(hdr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `			ksmbd_debug(CONN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `				    "RFC1002 hdr=%02x %02x %02x %02x len=%u status=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `				    (u8)hdr_buf[0], (u8)hdr_buf[1],`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `				    (u8)hdr_buf[2], (u8)hdr_buf[3], pdu_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `				    READ_ONCE(conn->status));`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `		if (ksmbd_conn_good(conn) && conn->vals)`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `			max_allowed_pdu_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `				SMB3_MAX_MSGSIZE + conn->vals->max_write_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `			max_allowed_pdu_size = SMB3_MAX_MSGSIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `		if (pdu_size > max_allowed_pdu_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [ERROR_PATH|] `				pr_err_ratelimited("PDU length(%u) excceed maximum allowed pdu size(%u) on connection(%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00601 [NONE] `						pdu_size, max_allowed_pdu_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `						READ_ONCE(conn->status));`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [ERROR_PATH|] `				pr_err_ratelimited("Invalid RFC1002 hdr bytes: %02x %02x %02x %02x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00604 [NONE] `						   (u8)hdr_buf[0], (u8)hdr_buf[1],`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `						   (u8)hdr_buf[2], (u8)hdr_buf[3]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `		 * Check maximum pdu size(0x00FFFFFF).`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		if (pdu_size > MAX_STREAM_PROT_LEN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `		if (pdu_size < SMB1_MIN_SUPPORTED_HEADER_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `		/* 4 for rfc1002 length field */`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `		/* 1 for implied bcc[0] */`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [MEM_BOUNDS|] `		if (check_add_overflow(pdu_size, 5u, (unsigned int *)&size))`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00621 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [MEM_BOUNDS|] `		conn->request_buf = kvmalloc(size, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00623 [NONE] `		if (!conn->request_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [MEM_BOUNDS|] `		memcpy(conn->request_buf, hdr_buf, sizeof(hdr_buf));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00627 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `		 * We already read 4 bytes to find out PDU size, now`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `		 * read in PDU`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `		size = t->ops->read(t, conn->request_buf + 4, pdu_size, 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `		if (size < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [ERROR_PATH|] `			pr_err("sock_read failed: %d\n", size);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00635 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `			if (size != pdu_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [ERROR_PATH|] `				pr_err("PDU error. Read: %d, Expected: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00640 [NONE] `				       size, pdu_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `			if (pdu_size >= sizeof(struct smb2_sess_setup_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `				struct smb2_sess_setup_req *sess_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `				unsigned int expected_pdu, extra;`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `				sess_req = smb2_get_msg(conn->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [PROTO_GATE|] `				if (sess_req->hdr.ProtocolId == SMB2_PROTO_NUMBER &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00650 [NONE] `				    le16_to_cpu(sess_req->hdr.Command) ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [PROTO_GATE|] `				    SMB2_SESSION_SETUP_HE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00652 [NONE] `					expected_pdu =`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `						le16_to_cpu(sess_req->SecurityBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `						le16_to_cpu(sess_req->SecurityBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `					if (expected_pdu > pdu_size &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `					    expected_pdu <= MAX_STREAM_PROT_LEN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `						char *new_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `						extra = expected_pdu - pdu_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [MEM_BOUNDS|] `						if (check_add_overflow(expected_pdu, 5u,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00662 [NONE] `								       (unsigned int *)&size))`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `							break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [MEM_BOUNDS|] `						new_buf = kvmalloc(size, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00666 [NONE] `						if (!new_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `							break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [MEM_BOUNDS|] `						memcpy(new_buf, conn->request_buf,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00670 [NONE] `						       pdu_size + 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `						kvfree(conn->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `						conn->request_buf = new_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `						size = t->ops->read(t,`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `								   conn->request_buf + 4 + pdu_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `								   extra, 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `						if (size != extra) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [ERROR_PATH|] `							pr_err("SESSION_SETUP extension read failed: %d expected %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00679 [NONE] `							       size, extra);`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `							break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `						}`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `						inc_rfc1001_len(conn->request_buf, extra);`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [ERROR_PATH|] `						pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00685 [NONE] `							"SESSION_SETUP frame length corrected: rfc=%u expected=%u extra=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `							pdu_size, expected_pdu, extra);`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `						pdu_size = expected_pdu;`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `			 * Trace parsed protocol signature after payload read to`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `			 * diagnose framing/stream-desync issues.`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `			if (pdu_size >= 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `				u8 *msg = conn->request_buf + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `				ksmbd_debug(CONN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `					    "PDU sig=%02x %02x %02x %02x pdu=%u req_running=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `					    msg[0], msg[1], msg[2], msg[3],`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [LIFETIME|] `					    pdu_size, atomic_read(&conn->req_running));`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00703 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `		if (!ksmbd_smb_request(conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [PROTO_GATE|] `		if (((struct smb2_hdr *)smb2_get_msg(conn->request_buf))->ProtocolId ==`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00709 [PROTO_GATE|] `		    SMB2_PROTO_NUMBER) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00710 [PROTO_GATE|] `			if (pdu_size < SMB2_MIN_SUPPORTED_HEADER_SIZE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00711 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `		if (!default_conn_ops.process_fn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [ERROR_PATH|] `			pr_err("No connection request callback\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00716 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `		if (default_conn_ops.process_fn(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [ERROR_PATH|] `			pr_err("Cannot handle request\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00721 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `	ksmbd_conn_set_releasing(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `	/* Wait till all reference dropped to the Server object*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [LIFETIME|] `	ksmbd_debug(CONN, "Wait for all pending requests(%d)\n", atomic_read(&conn->r_count));`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00729 [LIFETIME|WAIT_LOOP|] `	wait_event(conn->r_count_q, atomic_read(&conn->r_count) == 0);`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00730 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `	if (IS_ENABLED(CONFIG_UNICODE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `		utf8_unload(conn->um);`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `	unload_nls(conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `	if (default_conn_ops.terminate_fn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `		default_conn_ops.terminate_fn(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `	t->ops->disconnect(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	module_put(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `void ksmbd_conn_init_server_callbacks(struct ksmbd_conn_ops *ops)`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `	default_conn_ops.process_fn = ops->process_fn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `	default_conn_ops.terminate_fn = ops->terminate_fn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `void ksmbd_conn_r_count_inc(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [LIFETIME|] `	atomic_inc(&conn->r_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00750 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `void ksmbd_conn_r_count_dec(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	 * Decrement r_count and wake the connection handler thread if`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	 * it has drained to zero.  The connection handler thread is the`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	 * sole owner responsible for cleanup via ksmbd_conn_free() --`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	 * workers must never call ksmbd_conn_cleanup() directly as that`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `	 * races with the handler's own exit path and causes double-free`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	 * or use-after-free of the transport.`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `	 * waitqueue_active is safe because it uses atomic operation for`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `	 * condition.`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [LIFETIME|] `	if (!atomic_dec_return(&conn->r_count) &&`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00766 [NONE] `	    waitqueue_active(&conn->r_count_q))`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `		wake_up(&conn->r_count_q);`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `int ksmbd_conn_transport_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	ksmbd_conn_hash_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [LOCK|] `	mutex_lock(&init_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00776 [NONE] `	ret = ksmbd_tcp_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [ERROR_PATH|] `		pr_err("Failed to init TCP subsystem: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00779 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00780 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `	ret = ksmbd_rdma_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [ERROR_PATH|] `		pr_warn("RDMA subsystem unavailable (%d), continuing without RDMA\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00785 [NONE] `			ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `		/* RDMA is optional; do not tear down TCP */`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `	ret = ksmbd_quic_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `		/* QUIC is optional: fall back to TCP+RDMA only */`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [ERROR_PATH|] `		pr_warn("QUIC subsystem unavailable (%d), continuing without QUIC\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00793 [NONE] `			ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `		ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [LOCK|] `	mutex_unlock(&init_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00798 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [LOCK|] `	mutex_unlock(&init_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00802 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `/* Maximum retries for stop_sessions: 300 * 100ms = 30 seconds */`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `#define STOP_SESSIONS_MAX_RETRIES	300`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `static void stop_sessions(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `	struct ksmbd_transport *t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `	int retries = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `again:`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `	for (i = 0; i < CONN_HASH_SIZE; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [LOCK|] `		spin_lock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00818 [NONE] `		hlist_for_each_entry(conn, &conn_hash[i].head,`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `				     hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `			t = conn->transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `			ksmbd_conn_set_exiting(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `			if (t->ops->shutdown) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `				 * Take a temporary reference while dropping the`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `				 * hash lock to invoke transport shutdown.`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `				 * The connection can concurrently race to its`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `				 * final put, so only take the ref if still live`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `				 * and release it through ksmbd_conn_free().`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [LIFETIME|] `				if (!refcount_inc_not_zero(&conn->refcnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00831 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [LOCK|] `				spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00833 [NONE] `				t->ops->shutdown(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `				ksmbd_conn_free(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [ERROR_PATH|] `				goto again;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00836 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [LOCK|] `		spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00839 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `	if (!ksmbd_conn_hash_empty()) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `		if (++retries > STOP_SESSIONS_MAX_RETRIES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `			int leaked = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `			 * Force-release remaining connections to avoid`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `			 * leaking resources on module unload.  At this`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `			 * point listeners are already torn down, so no`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `			 * new connections can arrive.`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `			for (i = 0; i < CONN_HASH_SIZE; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [LOCK|] `				spin_lock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00853 [NONE] `				hlist_for_each_entry(conn, &conn_hash[i].head,`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `						     hlist)`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `					leaked++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [LOCK|] `				spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00857 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `			pr_crit("stop_sessions: giving up after %d retries - %d connections leaked, forcing cleanup\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `				retries, leaked);`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `			for (i = 0; i < CONN_HASH_SIZE; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `restart:`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [LOCK|] `				spin_lock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00864 [NONE] `				hlist_for_each_entry(conn, &conn_hash[i].head,`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `						     hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [LIFETIME|] `					if (!refcount_inc_not_zero(&conn->refcnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00867 [NONE] `						continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [LOCK|] `					spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00869 [NONE] `					ksmbd_conn_free(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [ERROR_PATH|] `					goto restart;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00871 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [LOCK|] `				spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00873 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [WAIT_LOOP|] `		msleep(100);`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00877 [ERROR_PATH|] `		goto again;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00878 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `void ksmbd_conn_transport_destroy(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [LOCK|] `	mutex_lock(&init_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00884 [NONE] `	ksmbd_tcp_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `	ksmbd_rdma_stop_listening();`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `	ksmbd_quic_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `	stop_sessions();`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `	ksmbd_rdma_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [LOCK|] `	mutex_unlock(&init_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00890 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
