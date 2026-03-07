# Line-by-line Review: src/mgmt/tree_connect.c

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
- L00008 [NONE] `#include <linux/xarray.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include "share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `struct ksmbd_tree_conn_status`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `ksmbd_tree_conn_connect(struct ksmbd_work *work, const char *share_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `	struct ksmbd_tree_conn_status status = {-ENOENT, NULL};`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	struct ksmbd_tree_connect_response *resp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `	struct ksmbd_share_config *sc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	struct ksmbd_tree_connect *tree_conn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	struct sockaddr *peer_addr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	sc = ksmbd_share_config_get(work, share_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	if (!sc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `		return status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [MEM_BOUNDS|] `	tree_conn = kzalloc(sizeof(struct ksmbd_tree_connect),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00035 [NONE] `			    KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	if (!tree_conn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `		status.ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [ERROR_PATH|] `		goto out_error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00039 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	tree_conn->id = ksmbd_acquire_tree_conn_id(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	if (tree_conn->id < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `		status.ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [ERROR_PATH|] `		goto out_error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00045 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	peer_addr = KSMBD_TCP_PEER_SOCKADDR(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	resp = ksmbd_ipc_tree_connect_request(sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `					      sc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `					      tree_conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `					      peer_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	if (!resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `		status.ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [ERROR_PATH|] `		goto out_error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00055 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	status.ret = resp->status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [PROTO_GATE|] `	if (status.ret != KSMBD_TREE_CONN_STATUS_OK)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [ERROR_PATH|] `		goto out_error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	tree_conn->flags = resp->connection_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	if (test_tree_conn_flag(tree_conn, KSMBD_TREE_CONN_FLAG_UPDATE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `		struct ksmbd_share_config *new_sc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `		ksmbd_share_config_del(sc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `		new_sc = ksmbd_share_config_get(work, share_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `		if (!new_sc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [ERROR_PATH|] `			pr_err("Failed to update stale share config\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00069 [NONE] `			status.ret = -ESTALE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [ERROR_PATH|] `			goto out_error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00071 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `		ksmbd_share_config_put(sc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `		sc = new_sc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	tree_conn->user = sess->user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	tree_conn->share_conf = sc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	status.tree_conn = tree_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	 * Set state to TREE_CONNECTED and take two references (one for the`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	 * xarray, one for the caller) before storing in the xarray.  This`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	 * closes a TOCTOU race where a concurrent session logoff could find`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	 * and free a TREE_NEW entry while the caller still holds a raw`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	 * pointer, causing a use-after-free.`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	tree_conn->t_state = TREE_CONNECTED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [LIFETIME|] `	refcount_set(&tree_conn->refcount, 2);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	ret = xa_err(xa_store(&sess->tree_conns, tree_conn->id, tree_conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `			      KSMBD_DEFAULT_GFP));`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `		status.ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [ERROR_PATH|] `		goto out_error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00095 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	kvfree(resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	return status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `out_error:`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	if (tree_conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `		ksmbd_release_tree_conn_id(sess, tree_conn->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	ksmbd_share_config_put(sc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	kfree(tree_conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	kvfree(resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	return status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `void ksmbd_tree_connect_put(struct ksmbd_tree_connect *tcon)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [LIFETIME|] `	if (refcount_dec_and_test(&tcon->refcount)) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00111 [NONE] `		ksmbd_share_config_put(tcon->share_conf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `		kfree(tcon);`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `int ksmbd_tree_conn_disconnect(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `			       struct ksmbd_tree_connect *tree_conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	write_lock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	xa_erase(&sess->tree_conns, tree_conn->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	write_unlock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	ret = ksmbd_ipc_tree_disconnect_request(sess->id, tree_conn->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	ksmbd_release_tree_conn_id(sess, tree_conn->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	ksmbd_tree_connect_put(tree_conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `struct ksmbd_tree_connect *ksmbd_tree_conn_lookup(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `						  unsigned int id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	struct ksmbd_tree_connect *tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	read_lock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	tcon = xa_load(&sess->tree_conns, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	if (tcon) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `		if (tcon->t_state != TREE_CONNECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `			tcon = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [LIFETIME|] `		else if (!refcount_inc_not_zero(&tcon->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00142 [NONE] `			tcon = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	read_unlock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	return tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `int ksmbd_tree_conn_session_logoff(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	struct ksmbd_tree_connect *tc, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	unsigned long id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	LIST_HEAD(free_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	if (!sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	 * Collect all tree connections under lock and erase them from`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	 * the xarray, then process disconnections after releasing the`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	 * lock. This avoids dropping/reacquiring the lock during`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	 * iteration which is racy.`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	write_lock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	xa_for_each(&sess->tree_conns, id, tc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `		if (tc->t_state == TREE_DISCONNECTED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `			ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `		tc->t_state = TREE_DISCONNECTED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `		xa_erase(&sess->tree_conns, tc->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `		list_add(&tc->list, &free_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	write_unlock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	list_for_each_entry_safe(tc, tmp, &free_list, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `		list_del(&tc->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `		ret |= ksmbd_ipc_tree_disconnect_request(sess->id, tc->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		ksmbd_release_tree_conn_id(sess, tc->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		ksmbd_tree_connect_put(tc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	xa_destroy(&sess->tree_conns);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
