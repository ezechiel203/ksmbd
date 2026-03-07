# Line-by-line Review: src/fs/oplock.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/moduleparam.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#define VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "smb1pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `static LIST_HEAD(lease_table_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `static DEFINE_RWLOCK(lease_list_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `static struct kmem_cache *opinfo_cache;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` * alloc_opinfo() - allocate a new opinfo object for oplock info`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` * @work:	smb work`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` * @id:		fid of open file`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * @Tid:	tree id of connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * Return:      allocated opinfo object on success, otherwise NULL`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `static struct oplock_info *alloc_opinfo(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `					u64 id, __u16 Tid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	opinfo = kmem_cache_zalloc(opinfo_cache, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	if (!opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	opinfo->sess = sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	opinfo->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [PROTO_GATE|] `	opinfo->level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00056 [NONE] `	opinfo->op_state = OPLOCK_STATE_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	opinfo->pending_break = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	opinfo->fid = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	opinfo->Tid = Tid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	opinfo->is_smb2 = IS_SMB2(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	INIT_LIST_HEAD(&opinfo->op_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	init_waitqueue_head(&opinfo->oplock_q);`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	init_waitqueue_head(&opinfo->oplock_brk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [LIFETIME|] `	refcount_set(&opinfo->refcount, 1);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00067 [LIFETIME|] `	atomic_set(&opinfo->breaking_cnt, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00068 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [LIFETIME|] `	 * Use refcount_inc_not_zero() to guard against a race where the`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00070 [NONE] `	 * connection is torn down concurrently and its refcnt has already`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [LIFETIME|] `	 * reached 0.  An unconditional refcount_inc() on a freed object`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00072 [NONE] `	 * would saturate the refcount and corrupt connection state.`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [LIFETIME|] `	if (!refcount_inc_not_zero(&opinfo->conn->refcnt)) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00075 [NONE] `		kmem_cache_free(opinfo_cache, opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	return opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `static void lease_add_list(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	struct lease_table *lb = opinfo->o_lease->l_lb;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [LOCK|] `	spin_lock(&lb->lb_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00087 [NONE] `	list_add_rcu(&opinfo->lease_entry, &lb->lease_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [LOCK|] `	spin_unlock(&lb->lb_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00089 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `static void lease_del_list(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	struct lease_table *lb = opinfo->o_lease->l_lb;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	if (!lb)`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [LOCK|] `	spin_lock(&lb->lb_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00099 [NONE] `	if (list_empty(&opinfo->lease_entry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [LOCK|] `		spin_unlock(&lb->lb_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00101 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	list_del_init(&opinfo->lease_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	opinfo->o_lease->l_lb = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [LOCK|] `	spin_unlock(&lb->lb_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00107 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `static void lb_add(struct lease_table *lb)`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	write_lock(&lease_list_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	list_add_rcu(&lb->l_entry, &lease_table_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	write_unlock(&lease_list_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `int alloc_lease(struct oplock_info *opinfo, struct lease_ctx_info *lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	struct lease *lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [MEM_BOUNDS|] `	lease = kmalloc(sizeof(struct lease), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00122 [NONE] `	if (!lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [MEM_BOUNDS|PROTO_GATE|] `	memcpy(lease->lease_key, lctx->lease_key, SMB2_LEASE_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00126 [NONE] `	lease->state = lctx->req_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	lease->new_state = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	lease->flags = lctx->flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	lease->duration = lctx->duration;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	lease->is_dir = lctx->is_dir;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [MEM_BOUNDS|PROTO_GATE|] `	memcpy(lease->parent_lease_key, lctx->parent_lease_key, SMB2_LEASE_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00132 [NONE] `	lease->version = lctx->version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	lease->epoch = le16_to_cpu(lctx->epoch);`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	lease->l_lb = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	INIT_LIST_HEAD(&opinfo->lease_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	opinfo->o_lease = lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `EXPORT_SYMBOL_IF_KUNIT(alloc_lease);`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `static void free_lease(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	struct lease *lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	kfree(lease);`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `static void free_opinfo(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `		free_lease(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	if (opinfo->conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `		ksmbd_conn_free(opinfo->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	opinfo->conn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	kmem_cache_free(opinfo_cache, opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `struct oplock_info *opinfo_get(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00165 [LIFETIME|] `	opinfo = rcu_dereference(fp->f_opinfo);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00166 [LIFETIME|] `	if (opinfo && !refcount_inc_not_zero(&opinfo->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00167 [NONE] `		opinfo = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00169 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	return opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `static struct oplock_info *opinfo_get_list(struct ksmbd_inode *ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [LOCK|] `	down_read(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00178 [NONE] `	opinfo = list_first_entry_or_null(&ci->m_op_list, struct oplock_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `					  op_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	if (opinfo) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		if (opinfo->conn == NULL ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [LIFETIME|] `		    !refcount_inc_not_zero(&opinfo->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00183 [NONE] `			opinfo = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `		else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `			if (ksmbd_conn_releasing(opinfo->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [LIFETIME|] `				refcount_dec(&opinfo->refcount);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00187 [NONE] `				opinfo = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	return opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `void opinfo_put(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	if (!opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [LIFETIME|] `	if (!refcount_dec_and_test(&opinfo->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00202 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	free_opinfo(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `static void opinfo_add(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	struct ksmbd_inode *ci = opinfo->o_fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [LOCK|] `	down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00212 [NONE] `	list_add(&opinfo->op_entry, &ci->m_op_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [LOCK|] `	up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00214 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `static void opinfo_del(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	struct ksmbd_inode *ci = opinfo->o_fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		lease_del_list(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [LOCK|] `	down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00224 [NONE] `	list_del(&opinfo->op_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [LOCK|] `	up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00226 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `static unsigned long opinfo_count(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	if (ksmbd_stream_fd(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [LIFETIME|] `		return atomic_read(&fp->f_ci->sop_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00232 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [LIFETIME|] `		return atomic_read(&fp->f_ci->op_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00234 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `static void opinfo_count_inc(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	if (ksmbd_stream_fd(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [LIFETIME|] `		return atomic_inc(&fp->f_ci->sop_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00240 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [LIFETIME|] `		return atomic_inc(&fp->f_ci->op_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00242 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `static void opinfo_count_dec(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	if (ksmbd_stream_fd(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [LIFETIME|] `		return atomic_dec(&fp->f_ci->sop_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00248 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [LIFETIME|] `		return atomic_dec(&fp->f_ci->op_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00250 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ` * opinfo_write_to_read() - convert a write oplock to read oplock`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ` * @opinfo:		current oplock info`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] ` * Return:      0 on success, otherwise -EINVAL`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `int opinfo_write_to_read(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	struct lease *lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	if (opinfo->is_smb2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [PROTO_GATE|] `		if (!(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00265 [PROTO_GATE|] `		      opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00266 [ERROR_PATH|] `			pr_err("bad oplock(0x%x)\n", opinfo->level);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00267 [NONE] `			if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [ERROR_PATH|] `				pr_err("lease state(0x%x)\n", lease->state);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00269 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00270 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [PROTO_GATE|] `		opinfo->level = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00272 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `		if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `			lease->state = lease->new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `		if (!(opinfo->level == OPLOCK_EXCLUSIVE ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `		      opinfo->level == OPLOCK_BATCH)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [ERROR_PATH|] `			pr_err("bad oplock(0x%x)\n", opinfo->level);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00279 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00280 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `		opinfo->level = OPLOCK_READ;`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [PROTO_GATE|] `	if (!(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00285 [PROTO_GATE|] `	      opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00286 [ERROR_PATH|] `		pr_err("bad oplock(0x%x)\n", opinfo->level);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00287 [NONE] `		if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [ERROR_PATH|] `			pr_err("lease state(0x%x)\n", lease->state);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00289 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00290 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [PROTO_GATE|] `	opinfo->level = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `		lease->state = lease->new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ` * opinfo_read_handle_to_read() - convert a read/handle oplock to read oplock`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] ` * @opinfo:		current oplock info`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ` * Return:      0 on success, otherwise -EINVAL`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `int opinfo_read_handle_to_read(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `	struct lease *lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	if (!opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00311 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	lease->state = lease->new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [PROTO_GATE|] `	opinfo->level = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00315 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] ` * opinfo_write_handle_to_write() - drop handle caching from a write+handle lease`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ` * @opinfo:		current oplock info`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] ` * Transitions a lease from RWH to RW by dropping Handle caching.`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] ` * The opinfo level stays at BATCH/EXCLUSIVE since Write caching is retained.`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] ` * Return:      0 on success, otherwise -EINVAL`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `int opinfo_write_handle_to_write(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	struct lease *lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	if (!opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [PROTO_GATE|] `	if (!(lease->state & SMB2_LEASE_WRITE_CACHING_LE) ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00336 [PROTO_GATE|] `	    !(lease->state & SMB2_LEASE_HANDLE_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00337 [ERROR_PATH|] `		pr_err("bad lease state(0x%x) for write_handle_to_write\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00338 [NONE] `		       le32_to_cpu(lease->state));`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00340 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	/* Drop Handle caching, keep Read+Write */`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	lease->state = lease->new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `	/* Keep opinfo->level at BATCH/EXCLUSIVE since Write is retained */`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] ` * opinfo_write_to_none() - convert a write oplock to none`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] ` * @opinfo:	current oplock info`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] ` * Return:      0 on success, otherwise -EINVAL`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `int opinfo_write_to_none(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	struct lease *lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	if (opinfo->is_smb2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [PROTO_GATE|] `		if (!(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00361 [PROTO_GATE|] `		      opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00362 [ERROR_PATH|] `			pr_err("bad oplock(0x%x)\n", opinfo->level);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00363 [NONE] `			if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [ERROR_PATH|] `				pr_err("lease state(0x%x)\n", lease->state);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00365 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00366 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [PROTO_GATE|] `		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00368 [NONE] `		if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `			lease->state = lease->new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `		if (!(opinfo->level == OPLOCK_EXCLUSIVE ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `		      opinfo->level == OPLOCK_BATCH)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [ERROR_PATH|] `			pr_err("bad oplock(0x%x)\n", opinfo->level);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00374 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00375 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `		opinfo->level = OPLOCK_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [PROTO_GATE|] `	if (!(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00380 [PROTO_GATE|] `	      opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00381 [ERROR_PATH|] `		pr_err("bad oplock(0x%x)\n", opinfo->level);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00382 [NONE] `		if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [ERROR_PATH|] `			pr_err("lease state(0x%x)\n", lease->state);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00384 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00385 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [PROTO_GATE|] `	opinfo->level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00387 [NONE] `	if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `		lease->state = lease->new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] ` * opinfo_read_to_none() - convert a write read to none`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] ` * @opinfo:	current oplock info`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] ` * Return:      0 on success, otherwise -EINVAL`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `int opinfo_read_to_none(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	struct lease *lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	if (opinfo->is_smb2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [PROTO_GATE|] `		if (opinfo->level != SMB2_OPLOCK_LEVEL_II) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00406 [ERROR_PATH|] `			pr_err("bad oplock(0x%x)\n", opinfo->level);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00407 [NONE] `			if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [ERROR_PATH|] `				pr_err("lease state(0x%x)\n", lease->state);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00409 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00410 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [PROTO_GATE|] `		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00412 [NONE] `		if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `			lease->state = lease->new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `		if (opinfo->level != OPLOCK_READ) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [ERROR_PATH|] `			pr_err("bad oplock(0x%x)\n", opinfo->level);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00417 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00418 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `		opinfo->level = OPLOCK_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [PROTO_GATE|] `	if (opinfo->level != SMB2_OPLOCK_LEVEL_II) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00423 [ERROR_PATH|] `		pr_err("bad oplock(0x%x)\n", opinfo->level);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00424 [NONE] `		if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [ERROR_PATH|] `			pr_err("lease state(0x%x)\n", lease->state);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00426 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00427 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [PROTO_GATE|] `	opinfo->level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00429 [NONE] `	if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `		lease->state = lease->new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ` * lease_read_to_write() - upgrade lease state from read to write`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] ` * @opinfo:	current lease info`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] ` * Return:      0 on success, otherwise -EINVAL`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `int lease_read_to_write(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `	struct lease *lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [PROTO_GATE|] `	if (!(lease->state & SMB2_LEASE_READ_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00446 [NONE] `		ksmbd_debug(OPLOCK, "bad lease state(0x%x)\n", lease->state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00448 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [PROTO_GATE|] `	lease->new_state = SMB2_LEASE_NONE_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00451 [PROTO_GATE|] `	lease->state |= SMB2_LEASE_WRITE_CACHING_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00452 [PROTO_GATE|] `	if (lease->state & SMB2_LEASE_HANDLE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00453 [PROTO_GATE|] `		opinfo->level = SMB2_OPLOCK_LEVEL_BATCH;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00454 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [PROTO_GATE|] `		opinfo->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00456 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] ` * lease_none_upgrade() - upgrade lease state from none`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] ` * @opinfo:	current lease info`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] ` * @new_state:	new lease state`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] ` * Return:	0 on success, otherwise -EINVAL`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `int lease_none_upgrade(struct oplock_info *opinfo, __le32 new_state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	struct lease *lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [PROTO_GATE|] `	if (!(lease->state == SMB2_LEASE_NONE_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00472 [NONE] `		ksmbd_debug(OPLOCK, "bad lease state(0x%x)\n", lease->state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00474 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [PROTO_GATE|] `	lease->new_state = SMB2_LEASE_NONE_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00477 [NONE] `	lease->state = new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [PROTO_GATE|] `	if (lease->state & SMB2_LEASE_HANDLE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00479 [PROTO_GATE|] `		if (lease->state & SMB2_LEASE_WRITE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00480 [PROTO_GATE|] `			opinfo->level = SMB2_OPLOCK_LEVEL_BATCH;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00481 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [PROTO_GATE|] `			opinfo->level = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00483 [PROTO_GATE|] `	else if (lease->state & SMB2_LEASE_WRITE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00484 [PROTO_GATE|] `		opinfo->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00485 [PROTO_GATE|] `	else if (lease->state & SMB2_LEASE_READ_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00486 [PROTO_GATE|] `		opinfo->level = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00487 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [PROTO_GATE|] `	if (new_state != SMB2_LEASE_NONE_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00489 [NONE] `		lease->epoch++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `EXPORT_SYMBOL_IF_KUNIT(lease_none_upgrade);`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] ` * close_id_del_oplock() - release oplock object at file close time`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] ` * @fp:		ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `void close_id_del_oplock(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	if (fp->reserve_lease_break)`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `		smb_lazy_parent_lease_break_close(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	opinfo = opinfo_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	if (!opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	opinfo_del(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [LIFETIME|] `	rcu_assign_pointer(fp->f_opinfo, NULL);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00513 [NONE] `	if (opinfo->op_state == OPLOCK_ACK_WAIT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `		opinfo->op_state = OPLOCK_CLOSING;`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `		wake_up_interruptible_all(&opinfo->oplock_q);`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `		if (opinfo->is_lease) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [LIFETIME|] `			atomic_set(&opinfo->breaking_cnt, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00518 [NONE] `			wake_up_interruptible_all(&opinfo->oplock_brk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	opinfo_count_dec(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	opinfo_put(opinfo);  /* release the "created" reference */`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	opinfo_put(opinfo);  /* release the opinfo_get() reference */`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] ` * grant_write_oplock() - grant exclusive/batch oplock or write lease`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ` * @opinfo_new:	new oplock info object`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ` * @req_oplock: request oplock`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] ` * @lctx:	lease context information`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ` * Return:      0`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `void grant_write_oplock(struct oplock_info *opinfo_new, int req_oplock,`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `			       struct lease_ctx_info *lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	struct lease *lease = opinfo_new->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	if (opinfo_new->is_smb2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [PROTO_GATE|] `		if (req_oplock == SMB2_OPLOCK_LEVEL_BATCH)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00544 [PROTO_GATE|] `			opinfo_new->level = SMB2_OPLOCK_LEVEL_BATCH;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00545 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [PROTO_GATE|] `			opinfo_new->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00547 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `		if (req_oplock == REQ_BATCHOPLOCK)`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `			opinfo_new->level = OPLOCK_BATCH;`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `			opinfo_new->level = OPLOCK_EXCLUSIVE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [PROTO_GATE|] `	if (req_oplock == SMB2_OPLOCK_LEVEL_BATCH)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00555 [PROTO_GATE|] `		opinfo_new->level = SMB2_OPLOCK_LEVEL_BATCH;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00556 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [PROTO_GATE|] `		opinfo_new->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00558 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	if (lctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `		lease->state = lctx->req_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [MEM_BOUNDS|PROTO_GATE|] `		memcpy(lease->lease_key, lctx->lease_key, SMB2_LEASE_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00563 [NONE] `		lease->epoch++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `EXPORT_SYMBOL_IF_KUNIT(grant_write_oplock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] ` * grant_read_oplock() - grant level2 oplock or read lease`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] ` * @opinfo_new:	new oplock info object`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] ` * @lctx:	lease context information`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] ` * Return:      0`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `void grant_read_oplock(struct oplock_info *opinfo_new,`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `			      struct lease_ctx_info *lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `	struct lease *lease = opinfo_new->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	if (opinfo_new->is_smb2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [PROTO_GATE|] `		opinfo_new->level = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00584 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `		opinfo_new->level = OPLOCK_READ;`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [PROTO_GATE|] `	opinfo_new->level = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00588 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	if (lctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [PROTO_GATE|] `		lease->state = SMB2_LEASE_READ_CACHING_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00592 [PROTO_GATE|] `		if (lctx->req_state & SMB2_LEASE_HANDLE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00593 [PROTO_GATE|] `			lease->state |= SMB2_LEASE_HANDLE_CACHING_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00594 [MEM_BOUNDS|PROTO_GATE|] `		memcpy(lease->lease_key, lctx->lease_key, SMB2_LEASE_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00595 [NONE] `		lease->epoch++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `EXPORT_SYMBOL_IF_KUNIT(grant_read_oplock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] ` * grant_none_oplock() - grant none oplock or none lease`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] ` * @opinfo_new:	new oplock info object`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] ` * @lctx:	lease context information`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] ` * Return:      0`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `void grant_none_oplock(struct oplock_info *opinfo_new,`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `			      struct lease_ctx_info *lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `	struct lease *lease = opinfo_new->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `	if (opinfo_new->is_smb2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [PROTO_GATE|] `		opinfo_new->level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00616 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `		opinfo_new->level = OPLOCK_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [PROTO_GATE|] `	opinfo_new->level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00620 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `	if (lctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `		lease->state = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [MEM_BOUNDS|PROTO_GATE|] `		memcpy(lease->lease_key, lctx->lease_key, SMB2_LEASE_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00625 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `EXPORT_SYMBOL_IF_KUNIT(grant_none_oplock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `int compare_guid_key(struct oplock_info *opinfo,`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `				   const char *guid1, const char *key1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	const char *guid2, *key2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `	guid2 = opinfo->conn->ClientGUID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	key2 = opinfo->o_lease->lease_key;`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [PROTO_GATE|] `	if (!memcmp(guid1, guid2, SMB2_CLIENT_GUID_SIZE) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00638 [PROTO_GATE|] `	    !memcmp(key1, key2, SMB2_LEASE_KEY_SIZE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00639 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `EXPORT_SYMBOL_IF_KUNIT(compare_guid_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] ` * same_client_has_lease() - check whether current lease request is`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] ` *		from lease owner of file`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] ` * @ci:		master file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] ` * @client_guid:	Client GUID`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] ` * @lctx:		lease context information`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] ` * Return:      oplock(lease) object on success, otherwise NULL`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `struct oplock_info *same_client_has_lease(struct ksmbd_inode *ci,`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `						 char *client_guid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `						 struct lease_ctx_info *lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	struct lease *lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `	struct oplock_info *m_opinfo = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `	if (!lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	 * Compare lease key and client_guid to know request from same owner`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `	 * of same client`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [LOCK|] `	down_read(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00672 [NONE] `	list_for_each_entry(opinfo, &ci->m_op_list, op_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `		if (!opinfo->is_lease || !opinfo->conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `		lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `		ret = compare_guid_key(opinfo, client_guid, lctx->lease_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `			m_opinfo = opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `			/* skip upgrading lease about breaking lease */`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [LIFETIME|] `			if (atomic_read(&opinfo->breaking_cnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00682 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `			/* upgrading lease */`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [LIFETIME|] `			if ((atomic_read(&ci->op_count) +`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00686 [LIFETIME|] `			     atomic_read(&ci->sop_count)) == 1) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00687 [PROTO_GATE|] `				if (lease->state != SMB2_LEASE_NONE_LE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00688 [NONE] `				    lease->state == (lctx->req_state & lease->state)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `					lease->epoch++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `					lease->state |= lctx->req_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `					if (lctx->req_state &`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [PROTO_GATE|] `						SMB2_LEASE_WRITE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00693 [NONE] `						lease_read_to_write(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [LIFETIME|] `			} else if ((atomic_read(&ci->op_count) +`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00697 [LIFETIME|] `				    atomic_read(&ci->sop_count)) > 1) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00698 [NONE] `				if (lctx->req_state ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [PROTO_GATE|] `				    (SMB2_LEASE_READ_CACHING_LE |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00700 [PROTO_GATE|] `				     SMB2_LEASE_HANDLE_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00701 [NONE] `					lease->epoch++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `					lease->state = lctx->req_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `			if (lctx->req_state && lease->state ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [PROTO_GATE|] `			    SMB2_LEASE_NONE_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00708 [NONE] `				lease->epoch++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `				lease_none_upgrade(opinfo, lctx->req_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `	up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	return m_opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `EXPORT_SYMBOL_IF_KUNIT(same_client_has_lease);`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `static void wait_for_break_ack(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `	 * Must use interruptible wait: the wake-up path on connection close`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `	 * calls wake_up_interruptible_all(&opinfo->oplock_q), which only`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [WAIT_LOOP|] `	 * wakes TASK_INTERRUPTIBLE waiters.  Using wait_event_timeout`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00727 [NONE] `	 * (TASK_UNINTERRUPTIBLE) would cause a full OPLOCK_WAIT_TIME (35s)`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `	 * stall whenever a client disconnects while a break is pending.`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `	 * Kernel worker threads do not receive user signals, so -ERESTARTSYS`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `	 * is not a concern in practice; treat any non-zero rc as "woken".`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [WAIT_LOOP|] `	rc = wait_event_interruptible_timeout(opinfo->oplock_q,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00733 [NONE] `				opinfo->op_state == OPLOCK_STATE_NONE ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `				opinfo->op_state == OPLOCK_CLOSING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `				OPLOCK_WAIT_TIME);`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	/* is this a timeout ? */`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	if (!rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `		if (opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [PROTO_GATE|] `			opinfo->o_lease->state = SMB2_LEASE_NONE_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00741 [PROTO_GATE|] `		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00742 [NONE] `		opinfo->op_state = OPLOCK_STATE_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `static void wake_up_oplock_break(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `	clear_bit_unlock(0, &opinfo->pending_break);`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `	/* memory barrier is needed for wake_up_bit() */`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `	smp_mb__after_atomic();`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `	wake_up_bit(&opinfo->pending_break, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `int oplock_break_pending(struct oplock_info *opinfo, int req_op_level)`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `	while  (test_and_set_bit(0, &opinfo->pending_break)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `		ret = wait_on_bit_timeout(&opinfo->pending_break, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `					  TASK_UNINTERRUPTIBLE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `					  OPLOCK_WAIT_TIME);`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `			if (ret == -EAGAIN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [ERROR_PATH|] `				return -ETIMEDOUT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00766 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `		/* Not immediately break to none. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `		opinfo->open_trunc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `		if (opinfo->op_state == OPLOCK_CLOSING)`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00774 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `		if (opinfo->is_lease) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `			 * For Handle-caching breaks, skip only when the`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `			 * lease has no Handle caching left.  For other`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `			 * break types, skip when the lease has already`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `			 * been broken down to RH (no Write caching).`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `			if (req_op_level == OPLOCK_BREAK_HANDLE_CACHING) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `				if (!(opinfo->o_lease->state &`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [PROTO_GATE|] `				      SMB2_LEASE_HANDLE_CACHING_LE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00785 [NONE] `					return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `			} else if (opinfo->level <= req_op_level &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `				   opinfo->o_lease->state !=`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [PROTO_GATE|] `				   (SMB2_LEASE_HANDLE_CACHING_LE |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00789 [PROTO_GATE|] `				    SMB2_LEASE_READ_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00790 [NONE] `				return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `		} else if (opinfo->level <= req_op_level) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `			return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `	if (opinfo->is_lease) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `		if (req_op_level == OPLOCK_BREAK_HANDLE_CACHING) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `			if (!(opinfo->o_lease->state &`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [PROTO_GATE|] `			      SMB2_LEASE_HANDLE_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00801 [NONE] `				wake_up_oplock_break(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `				return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `		} else if (opinfo->level <= req_op_level &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `			   opinfo->o_lease->state !=`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [PROTO_GATE|] `			   (SMB2_LEASE_HANDLE_CACHING_LE |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00807 [PROTO_GATE|] `			    SMB2_LEASE_READ_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00808 [NONE] `			wake_up_oplock_break(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `			return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `	} else if (opinfo->level <= req_op_level) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `		wake_up_oplock_break(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `EXPORT_SYMBOL_IF_KUNIT(oplock_break_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] ` * smb1_oplock_break_noti() - send smb1 oplock break cmd from conn`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] ` * to client`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] ` * @work:     smb work object`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] ` * There are two ways this function can be called. 1- while file open we break`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] ` * from exclusive/batch lock to levelII oplock and 2- while file write/truncate`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] ` * we break from levelII oplock no oplock.`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] ` * work->request_buf contains oplock_info.`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `static void __smb1_oplock_break_noti(struct work_struct *wk)`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `	struct ksmbd_work *work = container_of(wk, struct ksmbd_work, work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `	struct smb_hdr *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	struct smb_com_lock_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `	struct oplock_info *opinfo = work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `	if (allocate_interim_rsp_buf(work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [ERROR_PATH|] `		pr_err("smb_allocate_rsp_buf failed! ");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00840 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00841 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `	/* Init response header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `	rsp_hdr = work->response_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `	/* wct is 8 for locking andx(18) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `	memset(rsp_hdr, 0, sizeof(struct smb_hdr) + 18);`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `	rsp_hdr->smb_buf_length =`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `		cpu_to_be32(conn->vals->header_size - 4 + 18);`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `	rsp_hdr->Protocol[0] = 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `	rsp_hdr->Protocol[1] = 'S';`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `	rsp_hdr->Protocol[2] = 'M';`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	rsp_hdr->Protocol[3] = 'B';`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [PROTO_GATE|] `	rsp_hdr->Command = SMB_COM_LOCKING_ANDX;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00855 [NONE] `	/* we know unicode, long file name and use nt error codes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `	rsp_hdr->Flags2 = SMBFLG2_UNICODE | SMBFLG2_KNOWS_LONG_NAMES |`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `		SMBFLG2_ERR_STATUS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `	rsp_hdr->Uid = cpu_to_le16(work->sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `	rsp_hdr->Pid = cpu_to_le16(0xFFFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `	rsp_hdr->Mid = cpu_to_le16(0xFFFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `	rsp_hdr->Tid = cpu_to_le16(opinfo->Tid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `	rsp_hdr->WordCount = 8;`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `	/* Init locking request */`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `	req = work->response_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `	req->AndXCommand = 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `	req->AndXReserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `	req->AndXOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `	req->Fid = opinfo->fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `	req->LockType = LOCKING_ANDX_OPLOCK_RELEASE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `	if (!opinfo->open_trunc &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `	    (opinfo->level == OPLOCK_BATCH ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `	     opinfo->level == OPLOCK_EXCLUSIVE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `		req->OplockLevel = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `		req->OplockLevel = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `	req->Timeout = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `	req->NumberOfUnlocks = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `	req->ByteCount = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `	ksmbd_debug(OPLOCK, "sending oplock break for fid %d lock level = %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `		    req->Fid, req->OplockLevel);`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `	ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `	ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `	ksmbd_conn_r_count_dec(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] ` * smb1_oplock_break() - send smb1 exclusive/batch to level2 oplock`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] ` *		break command from server to client`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] ` * @opinfo:		oplock info object`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] ` * @ack_required	if requiring ack`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `static int smb1_oplock_break_noti(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `	struct ksmbd_conn *conn = opinfo->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `	struct ksmbd_work *work = ksmbd_alloc_work_struct();`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `	if (!work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00905 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `	work->request_buf = (char *)opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `	work->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `	ksmbd_conn_r_count_inc(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `	if (opinfo->op_state == OPLOCK_ACK_WAIT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `		INIT_WORK(&work->work, __smb1_oplock_break_noti);`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `		ksmbd_queue_work(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `		wait_for_break_ack(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `		__smb1_oplock_break_noti(&work->work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `		if (opinfo->level == OPLOCK_READ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `			opinfo->level = OPLOCK_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] ` * __smb2_oplock_break_noti() - send smb2 oplock break cmd from conn`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] ` * to client`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] ` * @wk:     smb work object`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] ` * There are two ways this function can be called. 1- while file open we break`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] ` * from exclusive/batch lock to levelII oplock and 2- while file write/truncate`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] ` * we break from levelII oplock no oplock.`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] ` * work->request_buf contains oplock_info.`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `static void __smb2_oplock_break_noti(struct work_struct *wk)`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	struct smb2_oplock_break *rsp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	struct ksmbd_work *work = container_of(wk, struct ksmbd_work, work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `	struct oplock_break_info *br_info = work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `	struct smb2_hdr *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	fp = ksmbd_lookup_global_fd(br_info->fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00946 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `	if (allocate_interim_rsp_buf(work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [ERROR_PATH|] `		pr_err("smb2_allocate_rsp_buf failed! ");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00949 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00951 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `	rsp_hdr = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [PROTO_GATE|] `	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00956 [PROTO_GATE|] `	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00957 [NONE] `	rsp_hdr->CreditRequest = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [PROTO_GATE|] `	rsp_hdr->Command = SMB2_OPLOCK_BREAK;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00959 [PROTO_GATE|] `	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00960 [PROTO_GATE|] `	rsp_hdr->NextCommand = 0;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00961 [NONE] `	rsp_hdr->MessageId = cpu_to_le64(-1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `	rsp_hdr->Id.SyncId.ProcessId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `	rsp_hdr->Id.SyncId.TreeId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `	rsp_hdr->SessionId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	memset(rsp_hdr->Signature, 0, 16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `	rsp->StructureSize = cpu_to_le16(24);`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	if (!br_info->open_trunc &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [PROTO_GATE|] `	    (br_info->level == SMB2_OPLOCK_LEVEL_BATCH ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00972 [PROTO_GATE|] `	     br_info->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00973 [PROTO_GATE|] `		rsp->OplockLevel = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00974 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [PROTO_GATE|] `		rsp->OplockLevel = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00976 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `	rsp->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `	rsp->PersistentFid = cpu_to_le64(fp->persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `	rsp->VolatileFid = cpu_to_le64(fp->volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `	if (ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `			      sizeof(struct smb2_oplock_break)))`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00985 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `	ksmbd_debug(OPLOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `		    "sending oplock break v_id %llu p_id = %llu lock level = %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `		    rsp->VolatileFid, rsp->PersistentFid, rsp->OplockLevel);`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `	ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `	ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	ksmbd_conn_r_count_dec(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] ` * smb2_oplock_break_noti() - send smb2 exclusive/batch to level2 oplock`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] ` *		break command from server to client`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] ` * @opinfo:		oplock info object`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `static int smb2_oplock_break_noti(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `	struct ksmbd_conn *conn = opinfo->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `	struct oplock_break_info *br_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `	struct ksmbd_work *work = ksmbd_alloc_work_struct();`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `	if (!work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [MEM_BOUNDS|] `	br_info = kmalloc(sizeof(struct oplock_break_info), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01015 [NONE] `	if (!br_info) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `		ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01018 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `	br_info->level = opinfo->level;`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `	br_info->fid = opinfo->fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `	br_info->open_trunc = opinfo->open_trunc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `	work->request_buf = (char *)br_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `	work->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `	work->sess = opinfo->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `	ksmbd_conn_r_count_inc(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `	if (opinfo->op_state == OPLOCK_ACK_WAIT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `		INIT_WORK(&work->work, __smb2_oplock_break_noti);`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `		ksmbd_queue_work(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `		wait_for_break_ack(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `		__smb2_oplock_break_noti(&work->work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [PROTO_GATE|] `		if (opinfo->level == SMB2_OPLOCK_LEVEL_II)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01037 [PROTO_GATE|] `			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01038 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] ` * __smb2_lease_break_noti() - send lease break command from server`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] ` * to client`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] ` * @wk:     smb work object`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `static void __smb2_lease_break_noti(struct work_struct *wk)`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `	struct smb2_lease_break *rsp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `	struct ksmbd_work *work = container_of(wk, struct ksmbd_work, work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] `	struct lease_break_info *br_info = work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `	struct smb2_hdr *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `	if (allocate_interim_rsp_buf(work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `		ksmbd_debug(OPLOCK, "smb2_allocate_rsp_buf failed! ");`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01058 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `	rsp_hdr = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [PROTO_GATE|] `	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01063 [PROTO_GATE|] `	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01064 [NONE] `	rsp_hdr->CreditRequest = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [PROTO_GATE|] `	rsp_hdr->Command = SMB2_OPLOCK_BREAK;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01066 [PROTO_GATE|] `	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01067 [PROTO_GATE|] `	rsp_hdr->NextCommand = 0;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01068 [NONE] `	rsp_hdr->MessageId = cpu_to_le64(-1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `	rsp_hdr->Id.SyncId.ProcessId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `	rsp_hdr->Id.SyncId.TreeId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `	rsp_hdr->SessionId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `	memset(rsp_hdr->Signature, 0, 16);`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `	rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `	rsp->StructureSize = cpu_to_le16(44);`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `	rsp->Epoch = br_info->epoch;`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `	rsp->Flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [PROTO_GATE|] `	if (br_info->curr_state & (SMB2_LEASE_WRITE_CACHING_LE |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01080 [PROTO_GATE|] `			SMB2_LEASE_HANDLE_CACHING_LE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01081 [PROTO_GATE|] `		rsp->Flags = SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [MEM_BOUNDS|PROTO_GATE|] `	memcpy(rsp->LeaseKey, br_info->lease_key, SMB2_LEASE_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01084 [NONE] `	rsp->CurrentLeaseState = br_info->curr_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `	rsp->NewLeaseState = br_info->new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `	rsp->BreakReason = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `	rsp->AccessMaskHint = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `	rsp->ShareMaskHint = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `	if (ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `			      sizeof(struct smb2_lease_break)))`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `	ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `	ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `	ksmbd_conn_r_count_dec(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] ` * smb2_lease_break_noti() - break lease when a new client request`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] ` *			write lease`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] ` * @opinfo:		contains lease state information`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `static int smb2_lease_break_noti(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `	struct ksmbd_conn *conn = opinfo->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] `	struct ksmbd_work *work;`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `	struct lease_break_info *br_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `	struct lease *lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `	work = ksmbd_alloc_work_struct();`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `	if (!work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [MEM_BOUNDS|] `	br_info = kmalloc(sizeof(struct lease_break_info), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01120 [NONE] `	if (!br_info) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `		ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01123 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	br_info->curr_state = lease->state;`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `	br_info->new_state = lease->new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `	if (lease->version == 2)`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `		br_info->epoch = cpu_to_le16(++lease->epoch);`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `		br_info->epoch = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [MEM_BOUNDS|PROTO_GATE|] `	memcpy(br_info->lease_key, lease->lease_key, SMB2_LEASE_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `	work->request_buf = (char *)br_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `	work->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `	work->sess = opinfo->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `	ksmbd_conn_r_count_inc(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `	if (opinfo->op_state == OPLOCK_ACK_WAIT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `		INIT_WORK(&work->work, __smb2_lease_break_noti);`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `		ksmbd_queue_work(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `		if (!opinfo->nowait_ack)`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `			wait_for_break_ack(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `		__smb2_lease_break_noti(&work->work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [PROTO_GATE|] `		if (opinfo->o_lease->new_state == SMB2_LEASE_NONE_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01146 [PROTO_GATE|] `			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01147 [PROTO_GATE|] `			opinfo->o_lease->state = SMB2_LEASE_NONE_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01148 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `static void wait_lease_breaking(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `	if (!opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `	wake_up_interruptible_all(&opinfo->oplock_brk);`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [LIFETIME|] `	if (atomic_read(&opinfo->breaking_cnt)) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01160 [NONE] `		int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `		 * Must use interruptible wait: the wake-up path calls`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `		 * wake_up_interruptible_all(&opinfo->oplock_brk).  Using`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [WAIT_LOOP|] `		 * wait_event_timeout (TASK_UNINTERRUPTIBLE) would not be`
  Review: Bounded wait and cancellation path must be guaranteed.
- L01166 [NONE] `		 * woken by that call.`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [WAIT_LOOP|] `		ret = wait_event_interruptible_timeout(opinfo->oplock_brk,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L01169 [LIFETIME|] `					 atomic_read(&opinfo->breaking_cnt) == 0,`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01170 [NONE] `					 HZ);`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `		if (!ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [LIFETIME|] `			atomic_set(&opinfo->breaking_cnt, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01173 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `int oplock_break(struct oplock_info *brk_opinfo, int req_op_level,`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `			struct ksmbd_work *in_work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `	/* Need to break exclusive/batch oplock, write lease or overwrite_if */`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `	ksmbd_debug(OPLOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `		    "request to send oplock(level : 0x%x) break notification\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `		    brk_opinfo->level);`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] `	if (brk_opinfo->is_lease) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `		struct lease *lease = brk_opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `		brk_opinfo->nowait_ack = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [LIFETIME|] `		atomic_inc(&brk_opinfo->breaking_cnt);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01192 [NONE] `		err = oplock_break_pending(brk_opinfo, req_op_level);`
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `		if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [LIFETIME|] `			atomic_dec(&brk_opinfo->breaking_cnt);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01195 [NONE] `			return err < 0 ? err : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `		if (brk_opinfo->open_trunc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `			 * Create overwrite break trigger the lease break to`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `			 * none.`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [PROTO_GATE|] `			lease->new_state = SMB2_LEASE_NONE_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01204 [NONE] `		} else if (req_op_level == OPLOCK_BREAK_HANDLE_CACHING) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `			/* Handle break: strip H bit. RWH->RW, RH->R, H->NONE */`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `			lease->new_state = lease->state &`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [PROTO_GATE|] `					   ~SMB2_LEASE_HANDLE_CACHING_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01208 [NONE] `			if (!lease->new_state)`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [PROTO_GATE|] `				lease->new_state = SMB2_LEASE_NONE_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01210 [PROTO_GATE|] `		} else if (req_op_level == SMB2_OPLOCK_LEVEL_NONE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01211 [PROTO_GATE|] `			lease->new_state = SMB2_LEASE_NONE_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01212 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `			 * One-level-at-a-time break per MS-SMB2 3.3.4.7:`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `			 * Strip Write first, then Handle.`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `			 * RWH->RH, RW->R, RH->R, R->NONE, H->NONE`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [PROTO_GATE|] `			if (lease->state & SMB2_LEASE_WRITE_CACHING_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01219 [NONE] `				lease->new_state = lease->state &`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [PROTO_GATE|] `					~SMB2_LEASE_WRITE_CACHING_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01221 [NONE] `			} else if (lease->state &`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [PROTO_GATE|] `				   SMB2_LEASE_HANDLE_CACHING_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01223 [NONE] `				lease->new_state =`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [PROTO_GATE|] `					SMB2_LEASE_READ_CACHING_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01225 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [PROTO_GATE|] `				lease->new_state = SMB2_LEASE_NONE_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01227 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [PROTO_GATE|] `		if (lease->state & (SMB2_LEASE_WRITE_CACHING_LE |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01231 [PROTO_GATE|] `				SMB2_LEASE_HANDLE_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01232 [NONE] `			if (in_work) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] `				setup_async_work(in_work, NULL, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [PROTO_GATE|] `				smb2_send_interim_resp(in_work, STATUS_PENDING);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01235 [NONE] `				release_async_work(in_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `			brk_opinfo->op_state = OPLOCK_ACK_WAIT;`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `			 * For Handle-caching lease breaks triggered by`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `			 * rename or delete (in_work==NULL), the rename`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `			 * must proceed without waiting for the client's`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `			 * break ack.  The notification is still queued`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `			 * async and ACK_REQUIRED is set, but the calling`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `			 * thread does not block.  The client will ack`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `			 * asynchronously and the ack handler will find`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] `			 * the opinfo in OPLOCK_ACK_WAIT as expected.`
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `			if (!in_work &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `			    req_op_level == OPLOCK_BREAK_HANDLE_CACHING)`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `				brk_opinfo->nowait_ack = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `		} else`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [LIFETIME|] `			atomic_dec(&brk_opinfo->breaking_cnt);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01254 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `		err = oplock_break_pending(brk_opinfo, req_op_level);`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `			return err < 0 ? err : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [PROTO_GATE|] `		if (brk_opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01260 [PROTO_GATE|] `		    brk_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01261 [NONE] `			brk_opinfo->op_state = OPLOCK_ACK_WAIT;`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `	if (brk_opinfo->is_smb2)`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `		if (brk_opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `			err = smb2_lease_break_noti(brk_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `			err = smb2_oplock_break_noti(brk_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `		err = smb1_oplock_break_noti(brk_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `	if (brk_opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `		err = smb2_lease_break_noti(brk_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `		err = smb2_oplock_break_noti(brk_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `	ksmbd_debug(OPLOCK, "oplock granted = %d\n", brk_opinfo->level);`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `	if (brk_opinfo->op_state == OPLOCK_CLOSING)`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `		err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `	wake_up_oplock_break(brk_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `	wait_lease_breaking(brk_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `EXPORT_SYMBOL_IF_KUNIT(oplock_break);`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `void destroy_lease_table(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `	struct lease_table *lb, *lbtmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	write_lock(&lease_list_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `	if (list_empty(&lease_table_list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `		write_unlock(&lease_list_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `	list_for_each_entry_safe(lb, lbtmp, &lease_table_list, l_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `		if (conn && memcmp(lb->client_guid, conn->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [PROTO_GATE|] `				   SMB2_CLIENT_GUID_SIZE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01304 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `again:`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [LIFETIME|] `		rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01307 [NONE] `		list_for_each_entry_rcu(opinfo, &lb->lease_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `					lease_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [LIFETIME|] `			rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01310 [NONE] `			lease_del_list(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [ERROR_PATH|] `			goto again;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01312 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [LIFETIME|] `		rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01314 [NONE] `		list_del_rcu(&lb->l_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [LIFETIME|] `		kfree_rcu(lb, rcu_head);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01316 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `	write_unlock(&lease_list_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `int find_same_lease_key(struct ksmbd_session *sess, struct ksmbd_inode *ci,`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `			struct lease_ctx_info *lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `	struct lease_table *lb;`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `	if (!lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01331 [NONE] `	if (list_empty(&lease_table_list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [LIFETIME|] `		rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01333 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] `	list_for_each_entry_rcu(lb, &lease_table_list, l_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] `		if (!memcmp(lb->client_guid, sess->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [PROTO_GATE|] `			    SMB2_CLIENT_GUID_SIZE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01339 [ERROR_PATH|] `			goto found;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01340 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `found:`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `	list_for_each_entry_rcu(opinfo, &lb->lease_list, lease_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [LIFETIME|] `		if (!refcount_inc_not_zero(&opinfo->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01348 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [LIFETIME|] `		rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01350 [NONE] `		if (opinfo->o_fp->f_ci == ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [ERROR_PATH|] `			goto op_next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01352 [NONE] `		err = compare_guid_key(opinfo, sess->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `				       lctx->lease_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `		if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `			ksmbd_debug(OPLOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `				    "found same lease key is already used in other files\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `			opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `			return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `op_next:`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `		opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [LIFETIME|] `		rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01364 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01366 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] `void copy_lease(struct oplock_info *op1, struct oplock_info *op2)`
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `	struct lease *lease1 = op1->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] `	struct lease *lease2 = op2->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `	op2->level = op1->level;`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `	lease2->state = lease1->state;`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [MEM_BOUNDS|] `	memcpy(lease2->lease_key, lease1->lease_key,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01379 [PROTO_GATE|] `	       SMB2_LEASE_KEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01380 [NONE] `	lease2->duration = lease1->duration;`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `	lease2->flags = lease1->flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `	lease2->epoch = lease1->epoch;`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `	lease2->version = lease1->version;`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `	lease2->is_dir = lease1->is_dir;`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] `EXPORT_SYMBOL_IF_KUNIT(copy_lease);`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] `int add_lease_global_list(struct oplock_info *opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `	struct lease_table *lb;`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01394 [NONE] `	list_for_each_entry_rcu(lb, &lease_table_list, l_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `		if (!memcmp(lb->client_guid, opinfo->conn->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [PROTO_GATE|] `			    SMB2_CLIENT_GUID_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01397 [NONE] `			opinfo->o_lease->l_lb = lb;`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] `			lease_add_list(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [LIFETIME|] `			rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01400 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01404 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [MEM_BOUNDS|] `	lb = kmalloc(sizeof(struct lease_table), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01406 [NONE] `	if (!lb)`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [MEM_BOUNDS|] `	memcpy(lb->client_guid, opinfo->conn->ClientGUID,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01410 [PROTO_GATE|] `	       SMB2_CLIENT_GUID_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01411 [NONE] `	INIT_LIST_HEAD(&lb->lease_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `	spin_lock_init(&lb->lb_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `	opinfo->o_lease->l_lb = lb;`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `	lease_add_list(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] `	lb_add(lb);`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `EXPORT_SYMBOL_IF_KUNIT(add_lease_global_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `void set_oplock_level(struct oplock_info *opinfo, int level,`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] `			     struct lease_ctx_info *lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] `	switch (level) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] `	case REQ_OPLOCK:`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] `	case REQ_BATCHOPLOCK:`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [PROTO_GATE|] `	case SMB2_OPLOCK_LEVEL_BATCH:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01430 [PROTO_GATE|] `	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01431 [NONE] `		grant_write_oplock(opinfo, level, lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [PROTO_GATE|] `	case SMB2_OPLOCK_LEVEL_II:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01434 [NONE] `		grant_read_oplock(opinfo, lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `		grant_none_oplock(opinfo, lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `EXPORT_SYMBOL_IF_KUNIT(set_oplock_level);`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `void smb_send_parent_lease_break_noti(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `				      struct lease_ctx_info *lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `	struct ksmbd_inode *p_ci = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] `	if (lctx->version != 2)`
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `	p_ci = ksmbd_inode_lookup_lock(fp->filp->f_path.dentry->d_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `	if (!p_ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [LOCK|] `	down_read(&p_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01457 [NONE] `	list_for_each_entry(opinfo, &p_ci->m_op_list, op_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `		if (opinfo->conn == NULL || !opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [PROTO_GATE|] `		if (opinfo->o_lease->state != SMB2_OPLOCK_LEVEL_NONE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01462 [PROTO_GATE|] `		    (!(lctx->flags & SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE) ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01463 [NONE] `		     memcmp(opinfo->o_lease->lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] `			    lctx->parent_lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [PROTO_GATE|] `			    SMB2_LEASE_KEY_SIZE))) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01466 [LIFETIME|] `			if (!refcount_inc_not_zero(&opinfo->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01467 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `			if (ksmbd_conn_releasing(opinfo->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `				opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [PROTO_GATE|] `			oplock_break(opinfo, SMB2_OPLOCK_LEVEL_NONE, NULL);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01475 [NONE] `			opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `	up_read(&p_ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] `	ksmbd_inode_put(p_ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `void smb_lazy_parent_lease_break_close(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `	struct oplock_info *child_opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] `	struct ksmbd_inode *p_ci = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `	bool has_parent_key = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [PROTO_GATE|] `	__u8 parent_lease_key[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01490 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `	child_opinfo = opinfo_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `	if (!child_opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `	if (!child_opinfo->is_lease || child_opinfo->o_lease->version != 2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `		opinfo_put(child_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `	 * If the child has a parent lease key set, directory leases`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `	 * held by the same client with a matching key are exempt from`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [NONE] `	 * the break — the client already knows the change happened.`
  Review: Low-risk line; verify in surrounding control flow.
- L01504 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] `	if (child_opinfo->o_lease->flags &`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [PROTO_GATE|] `	    SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01507 [NONE] `		has_parent_key = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [MEM_BOUNDS|] `		memcpy(parent_lease_key,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01509 [NONE] `		       child_opinfo->o_lease->parent_lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [PROTO_GATE|] `		       SMB2_LEASE_KEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01511 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `	p_ci = ksmbd_inode_lookup_lock(fp->filp->f_path.dentry->d_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] `	if (!p_ci) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] `		opinfo_put(child_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `	opinfo_put(child_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [LOCK|] `	down_read(&p_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01522 [NONE] `	list_for_each_entry(opinfo, &p_ci->m_op_list, op_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `		if (opinfo->conn == NULL || !opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [PROTO_GATE|] `		if (opinfo->o_lease->state == SMB2_LEASE_NONE_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01527 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `		 * Skip if the child's parent lease key matches`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `		 * this directory lease's key.`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `		if (has_parent_key &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `		    !memcmp(opinfo->o_lease->lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `			    parent_lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [PROTO_GATE|] `			    SMB2_LEASE_KEY_SIZE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01537 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [LIFETIME|] `		if (!refcount_inc_not_zero(&opinfo->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01540 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `		if (ksmbd_conn_releasing(opinfo->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] `			opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [PROTO_GATE|] `		oplock_break(opinfo, SMB2_OPLOCK_LEVEL_NONE, NULL);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01548 [NONE] `		opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] `	up_read(&p_ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01552 [NONE] `	ksmbd_inode_put(p_ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] ` * smb_break_parent_dir_lease() - break directory leases on parent dir`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [NONE] ` * @fp:		ksmbd file pointer for the child file`
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] ` * Per MS-SMB2 3.3.4.7, when a child file is created, modified, renamed,`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] ` * or deleted inside a directory, any directory lease held on that parent`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] ` * must be broken to NONE.  Clients that supplied a matching parent lease`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [PROTO_GATE|] ` * key (SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET) are exempt because they`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01563 [NONE] ` * already know the directory contents are changing.`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] `void smb_break_parent_dir_lease(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] `	struct oplock_info *child_opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] `	struct ksmbd_inode *p_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] `	bool has_parent_key = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [PROTO_GATE|] `	__u8 parent_lease_key[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] `	if (!fp->filp || !fp->filp->f_path.dentry->d_parent)`
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] `	 * Check if the child file has a v2 lease with parent lease key set.`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `	 * If so, the parent directory lease held by the same client+key is`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] `	 * exempt from the break notification.`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [NONE] `	child_opinfo = opinfo_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] `	if (child_opinfo) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `		if (child_opinfo->is_lease &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `		    child_opinfo->o_lease->version == 2 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] `		    (child_opinfo->o_lease->flags &`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [PROTO_GATE|] `		     SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01587 [NONE] `			has_parent_key = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [MEM_BOUNDS|] `			memcpy(parent_lease_key,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01589 [NONE] `			       child_opinfo->o_lease->parent_lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [PROTO_GATE|] `			       SMB2_LEASE_KEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01591 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] `		opinfo_put(child_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] `	p_ci = ksmbd_inode_lookup_lock(fp->filp->f_path.dentry->d_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] `	if (!p_ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [LOCK|] `	down_read(&p_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01600 [NONE] `	list_for_each_entry(opinfo, &p_ci->m_op_list, op_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] `		if (!opinfo->conn || !opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [PROTO_GATE|] `		if (opinfo->o_lease->state == SMB2_LEASE_NONE_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01605 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `		 * Per MS-SMB2 3.3.4.7, if the child's parent lease key`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `		 * matches this directory lease's key, skip the break.`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `		 * The parent key identifies the directory lease that the`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] `		 * opener is coordinated with, regardless of which client`
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `		 * the opener belongs to.`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] `		if (has_parent_key &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `		    !memcmp(opinfo->o_lease->lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] `			    parent_lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [PROTO_GATE|] `			    SMB2_LEASE_KEY_SIZE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01618 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [LIFETIME|] `		if (!refcount_inc_not_zero(&opinfo->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01621 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `		if (ksmbd_conn_releasing(opinfo->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] `			opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [PROTO_GATE|] `		oplock_break(opinfo, SMB2_OPLOCK_LEVEL_NONE, NULL);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01629 [NONE] `		opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [NONE] `	up_read(&p_ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [NONE] `	ksmbd_inode_put(p_ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L01634 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] ` * smb_break_dir_lease_by_dentry() - break all leases on a directory`
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [NONE] ` * @d:		dentry of the directory to break leases on`
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] ` * @fp:		ksmbd file pointer of the child (may be NULL)`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] ` * Break directory leases on the given directory.  Used for rename`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] ` * operations to break the destination parent directory's lease.`
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] ` * If @fp has a v2 lease with a parent lease key set, directory leases`
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] ` * matching that key are exempt from the break.`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `void smb_break_dir_lease_by_dentry(struct dentry *d, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `	struct oplock_info *child_opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `	struct ksmbd_inode *ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `	bool has_parent_key = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [PROTO_GATE|] `	__u8 parent_lease_key[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01653 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `	if (!d || !d_inode(d))`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [NONE] `	if (fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `		child_opinfo = opinfo_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `		if (child_opinfo) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] `			if (child_opinfo->is_lease &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `			    child_opinfo->o_lease->version == 2 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] `			    (child_opinfo->o_lease->flags &`
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [PROTO_GATE|] `			     SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01664 [NONE] `				has_parent_key = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [MEM_BOUNDS|] `				memcpy(parent_lease_key,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01666 [NONE] `				       child_opinfo->o_lease->parent_lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [PROTO_GATE|] `				       SMB2_LEASE_KEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01668 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] `			opinfo_put(child_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `	ci = ksmbd_inode_lookup_lock(d);`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] `	if (!ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [LOCK|] `	down_read(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01678 [NONE] `	list_for_each_entry(opinfo, &ci->m_op_list, op_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [NONE] `		if (!opinfo->conn || !opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L01680 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01681 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [PROTO_GATE|] `		if (opinfo->o_lease->state == SMB2_LEASE_NONE_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01683 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [NONE] `		if (has_parent_key &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [NONE] `		    !memcmp(opinfo->o_lease->lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] `			    parent_lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [PROTO_GATE|] `			    SMB2_LEASE_KEY_SIZE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01689 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [LIFETIME|] `		if (!refcount_inc_not_zero(&opinfo->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01692 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [NONE] `		if (ksmbd_conn_releasing(opinfo->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] `			opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [PROTO_GATE|] `		oplock_break(opinfo, SMB2_OPLOCK_LEVEL_NONE, NULL);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01700 [NONE] `		opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] `	up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] `	ksmbd_inode_put(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [NONE] ` * smb_grant_oplock() - handle oplock/lease request on file open`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] ` * @work:		smb work`
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] ` * @req_op_level:	oplock level`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] ` * @pid:		id of open file`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] ` * @fp:			ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] ` * @tid:		Tree id of connection`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] ` * @lctx:		lease context information on file open`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] ` * @share_ret:		share mode`
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] `int smb_grant_oplock(struct ksmbd_work *work, int req_op_level, u64 pid,`
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [NONE] `		     struct ksmbd_file *fp, __u16 tid,`
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [NONE] `		     struct lease_ctx_info *lctx, int share_ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] `	struct oplock_info *opinfo = NULL, *prev_opinfo = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [NONE] `	struct ksmbd_inode *ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [NONE] `	bool prev_op_has_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L01728 [NONE] `	__le32 prev_op_state = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] `	/* Only v2 leases handle the directory */`
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] `	if (S_ISDIR(file_inode(fp->filp)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `		if (!lctx || lctx->version != 2)`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [NONE] `	opinfo = alloc_opinfo(work, pid, tid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [NONE] `	if (!opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01739 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `	if (lctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [NONE] `		err = alloc_lease(opinfo, lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01744 [NONE] `		opinfo->is_lease = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] `	/* ci does not have any oplock */`
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `	if (!opinfo_count(fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] `		if (share_ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] `			err = share_ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01752 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [ERROR_PATH|] `		goto set_lev;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01754 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] `	/* grant none-oplock if second open is trunc */`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [NONE] `	if (fp->attrib_only && fp->cdoption != FILE_OVERWRITE_IF_LE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01758 [NONE] `	    fp->cdoption != FILE_OVERWRITE_LE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] `	    fp->cdoption != FILE_SUPERSEDE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [PROTO_GATE|] `		req_op_level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01761 [ERROR_PATH|] `		goto set_lev;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01762 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] `	if (lctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] `		struct oplock_info *m_opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] `		/* is lease already granted ? */`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] `		m_opinfo = same_client_has_lease(ci, sess->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `						 lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] `		if (m_opinfo) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] `			copy_lease(m_opinfo, opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] `			 * MS-SMB2 3.3.5.9.8: The granted lease state`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] `			 * is the intersection of the existing state`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] `			 * and the requested state.  Do not grant more`
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [NONE] `			 * caching than requested.`
  Review: Low-risk line; verify in surrounding control flow.
- L01777 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] `			opinfo->o_lease->state &= lctx->req_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [LIFETIME|] `			if (atomic_read(&m_opinfo->breaking_cnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01780 [NONE] `				opinfo->o_lease->flags =`
  Review: Low-risk line; verify in surrounding control flow.
- L01781 [PROTO_GATE|] `					SMB2_LEASE_FLAG_BREAK_IN_PROGRESS_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01782 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01783 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `	prev_opinfo = opinfo_get_list(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] `	if (!prev_opinfo ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [PROTO_GATE|] `	    (prev_opinfo->level == SMB2_OPLOCK_LEVEL_NONE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01788 [NONE] `	     prev_opinfo->is_lease && lctx)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] `		opinfo_put(prev_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [ERROR_PATH|] `		goto set_lev;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01791 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] `	 * MS-SMB2 3.3.5.9.11: If there is an existing non-lease`
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] `	 * oplock (even NONE level), do not promote a new lease`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] `	 * request.  Grant NONE instead.`
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [PROTO_GATE|] `	if (prev_opinfo->level == SMB2_OPLOCK_LEVEL_NONE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01799 [NONE] `	    !prev_opinfo->is_lease && lctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [NONE] `		opinfo_put(prev_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [PROTO_GATE|] `		req_op_level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01802 [ERROR_PATH|] `		goto set_lev;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01803 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `	prev_op_has_lease = prev_opinfo->is_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] `	if (prev_op_has_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `		prev_op_state = prev_opinfo->o_lease->state;`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] `	if (share_ret < 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [PROTO_GATE|] `	    prev_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01810 [NONE] `		err = share_ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] `		opinfo_put(prev_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01813 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [PROTO_GATE|] `	if (prev_opinfo->level != SMB2_OPLOCK_LEVEL_BATCH &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01816 [PROTO_GATE|] `	    prev_opinfo->level != SMB2_OPLOCK_LEVEL_EXCLUSIVE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01817 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] `		 * Directory leases with Handle caching (RH) need a`
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [NONE] `		 * Handle break (RH -> R) when there is a sharing`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `		 * violation.  The oplock level is LEVEL_II but the`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] `		 * lease state still holds Handle caching that must`
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] `		 * be broken.`
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01824 [NONE] `		if (share_ret < 0 && prev_op_has_lease &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [PROTO_GATE|] `		    (prev_op_state & SMB2_LEASE_HANDLE_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01826 [NONE] `			err = oplock_break(prev_opinfo,`
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `					   OPLOCK_BREAK_HANDLE_CACHING,`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] `					   work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] `			opinfo_put(prev_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `			if (err == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [ERROR_PATH|] `				goto set_lev;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01832 [NONE] `			else if (err < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01834 [ERROR_PATH|] `			goto op_break_not_needed;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01835 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] `		opinfo_put(prev_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [ERROR_PATH|] `		goto op_break_not_needed;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01838 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] `	if (prev_opinfo->is_lease && lctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `		if (share_ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `			 * Sharing violation: break Handle caching only`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] `			 * (RWH->RW).  The open will fail with`
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [PROTO_GATE|] `			 * STATUS_SHARING_VIOLATION after the break.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01846 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [NONE] `			err = oplock_break(prev_opinfo,`
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [NONE] `					   OPLOCK_BREAK_HANDLE_CACHING, work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01849 [NONE] `			opinfo_put(prev_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `			if (err == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [ERROR_PATH|] `				goto set_lev;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01852 [NONE] `			else if (err < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01854 [ERROR_PATH|] `			goto op_break_not_needed;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01855 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01856 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01857 [NONE] `		 * Successful open: break Write caching only (RWH->RH,`
  Review: Low-risk line; verify in surrounding control flow.
- L01858 [NONE] `		 * RW->R).  Handle caching is NOT broken on open; it`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] `		 * is only broken by rename or delete operations.`
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [NONE] `		 * MS-SMB2 3.3.5.9.8`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [NONE] `		err = oplock_break(prev_opinfo,`
  Review: Low-risk line; verify in surrounding control flow.
- L01863 [PROTO_GATE|] `				   SMB2_OPLOCK_LEVEL_II, work);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01864 [NONE] `		opinfo_put(prev_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] `		if (err == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [ERROR_PATH|] `			goto set_lev;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01867 [NONE] `		else if (err < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01868 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01869 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [NONE] `		err = oplock_break(prev_opinfo,`
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [PROTO_GATE|] `				   SMB2_OPLOCK_LEVEL_II, work);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01872 [NONE] `		opinfo_put(prev_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `		if (err == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [ERROR_PATH|] `			goto set_lev;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01875 [NONE] `		else if (err < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01876 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01877 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `op_break_not_needed:`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [NONE] `	if (share_ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [NONE] `		err = share_ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01882 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01883 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [PROTO_GATE|] `	if (req_op_level != SMB2_OPLOCK_LEVEL_NONE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01886 [PROTO_GATE|] `		req_op_level = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01887 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] `	/* grant fixed oplock on stacked locking between lease and oplock */`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] `	if (prev_op_has_lease && !lctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [PROTO_GATE|] `		if (prev_op_state & SMB2_LEASE_HANDLE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01891 [PROTO_GATE|] `			req_op_level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01892 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] `	if (!prev_op_has_lease && lctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [PROTO_GATE|] `		req_op_level = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01895 [PROTO_GATE|] `		lctx->req_state = SMB2_LEASE_READ_CACHING_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01896 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01898 [NONE] `set_lev:`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] `	set_oplock_level(opinfo, req_op_level, lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [LIFETIME|] `	rcu_assign_pointer(fp->f_opinfo, opinfo);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01903 [NONE] `	opinfo->o_fp = fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] `	opinfo_count_inc(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] `	opinfo_add(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] `	if (opinfo->is_lease) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] `		err = add_lease_global_list(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [ERROR_PATH|] `			goto err_out_registered;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01911 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01914 [NONE] `err_out_registered:`
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] `	 * Undo the registration that happened above: remove from the`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] `	 * per-inode oplock list, clear the fp back-pointer, and`
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [NONE] `	 * decrement the opinfo count.  Without this, free_opinfo()`
  Review: Low-risk line; verify in surrounding control flow.
- L01919 [NONE] `	 * would leave dangling references that later cause a`
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [LIFETIME|] `	 * refcount_t underflow ("decrement hit 0; leaking memory")`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01921 [NONE] `	 * when close_id_del_oplock() runs.`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01923 [NONE] `	opinfo_del(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [LIFETIME|] `	rcu_assign_pointer(fp->f_opinfo, NULL);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01925 [NONE] `	opinfo_count_dec(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01926 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01927 [NONE] `	free_opinfo(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01928 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01929 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01930 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] ` * smb_break_all_write_oplock() - break batch/exclusive oplock to level2`
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [NONE] ` * @work:	smb work`
  Review: Low-risk line; verify in surrounding control flow.
- L01934 [NONE] ` * @fp:		ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [NONE] ` * @is_trunc:	truncate on open`
  Review: Low-risk line; verify in surrounding control flow.
- L01936 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] `static void smb_break_all_write_oplock(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] `				       struct ksmbd_file *fp, int is_trunc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01940 [NONE] `	struct oplock_info *brk_opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `	brk_opinfo = opinfo_get_list(fp->f_ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [NONE] `	if (!brk_opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L01944 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [PROTO_GATE|] `	if (brk_opinfo->level != SMB2_OPLOCK_LEVEL_BATCH &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01946 [PROTO_GATE|] `	    brk_opinfo->level != SMB2_OPLOCK_LEVEL_EXCLUSIVE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01947 [NONE] `		opinfo_put(brk_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01948 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01949 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01950 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01951 [NONE] `	brk_opinfo->open_trunc = is_trunc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01952 [PROTO_GATE|] `	oplock_break(brk_opinfo, SMB2_OPLOCK_LEVEL_II, work);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01953 [NONE] `	opinfo_put(brk_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01955 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01956 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] ` * smb_break_all_levII_oplock() - send level2 oplock or read lease break command`
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [NONE] ` *	from server to client`
  Review: Low-risk line; verify in surrounding control flow.
- L01959 [NONE] ` * @work:	smb work`
  Review: Low-risk line; verify in surrounding control flow.
- L01960 [NONE] ` * @fp:		ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L01961 [NONE] ` * @is_trunc:	truncate on open`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01963 [NONE] `void smb_break_all_levII_oplock(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01964 [NONE] `				int is_trunc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01965 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [NONE] `#define LEVII_BRK_BATCH	64`
  Review: Low-risk line; verify in surrounding control flow.
- L01967 [NONE] `	struct oplock_info *op, *brk_op;`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [NONE] `	struct oplock_info *brk_batch[LEVII_BRK_BATCH];`
  Review: Low-risk line; verify in surrounding control flow.
- L01969 [NONE] `	struct ksmbd_inode *ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01971 [NONE] `	int i, brk_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01973 [NONE] `	if (!test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01974 [NONE] `				    KSMBD_SHARE_FLAG_OPLOCKS))`
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [NONE] `	ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L01978 [NONE] `	op = opinfo_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01981 [NONE] `	 * Collect oplocks to break while holding the lock, then release`
  Review: Low-risk line; verify in surrounding control flow.
- L01982 [NONE] `	 * the lock before sending break notifications to avoid deadlock.`
  Review: Low-risk line; verify in surrounding control flow.
- L01983 [LIFETIME|] `	 * Each collected entry holds a reference from refcount_inc_not_zero.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01984 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01985 [NONE] `	brk_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01986 [LOCK|] `	down_read(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01987 [NONE] `	list_for_each_entry(brk_op, &ci->m_op_list, op_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01988 [NONE] `		if (brk_op->conn == NULL)`
  Review: Low-risk line; verify in surrounding control flow.
- L01989 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01990 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01991 [LIFETIME|] `		if (!refcount_inc_not_zero(&brk_op->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01992 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01993 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01994 [NONE] `		if (ksmbd_conn_releasing(brk_op->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01995 [NONE] `			opinfo_put(brk_op);`
  Review: Low-risk line; verify in surrounding control flow.
- L01996 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01997 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01998 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01999 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L02000 [NONE] `		if (brk_op->is_smb2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02001 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02002 [NONE] `			 * C.8: Use LEASE_RH_MASK to check for unexpected`
  Review: Low-risk line; verify in surrounding control flow.
- L02003 [NONE] `			 * caching bits (Write caching etc.) in the lease`
  Review: Low-risk line; verify in surrounding control flow.
- L02004 [NONE] `			 * state, avoiding false positives from extra flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L02005 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02006 [NONE] `			if (brk_op->is_lease &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02007 [NONE] `			    (brk_op->o_lease->state & ~LEASE_RH_MASK)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02008 [NONE] `				ksmbd_debug(OPLOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L02009 [NONE] `					    "unexpected lease state(0x%x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02010 [NONE] `					    brk_op->o_lease->state);`
  Review: Low-risk line; verify in surrounding control flow.
- L02011 [ERROR_PATH|] `				goto next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02012 [NONE] `			} else if (brk_op->level !=`
  Review: Low-risk line; verify in surrounding control flow.
- L02013 [PROTO_GATE|] `					SMB2_OPLOCK_LEVEL_II) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02014 [NONE] `				ksmbd_debug(OPLOCK, "unexpected oplock(0x%x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02015 [NONE] `					    brk_op->level);`
  Review: Low-risk line; verify in surrounding control flow.
- L02016 [ERROR_PATH|] `				goto next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02017 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02019 [NONE] `			/* Skip oplock being break to none */`
  Review: Low-risk line; verify in surrounding control flow.
- L02020 [NONE] `			if (brk_op->is_lease &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02021 [PROTO_GATE|] `			    brk_op->o_lease->new_state == SMB2_LEASE_NONE_LE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02022 [LIFETIME|] `			    atomic_read(&brk_op->breaking_cnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02023 [ERROR_PATH|] `				goto next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02024 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02025 [NONE] `			if (brk_op->level != OPLOCK_READ) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02026 [NONE] `				ksmbd_debug(OPLOCK, "unexpected oplock(0x%x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02027 [NONE] `					    brk_op->level);`
  Review: Low-risk line; verify in surrounding control flow.
- L02028 [ERROR_PATH|] `				goto next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02029 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02030 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02031 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02032 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02033 [NONE] `		 * C.8: Use LEASE_RH_MASK to check for unexpected caching bits`
  Review: Low-risk line; verify in surrounding control flow.
- L02034 [NONE] `		 * in the lease state.  The mask covers Read and Handle caching;`
  Review: Low-risk line; verify in surrounding control flow.
- L02035 [NONE] `		 * any other bits (e.g. Write caching) indicate an unexpected`
  Review: Low-risk line; verify in surrounding control flow.
- L02036 [NONE] `		 * state for a level-II break candidate.`
  Review: Low-risk line; verify in surrounding control flow.
- L02037 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02038 [NONE] `		if (brk_op->is_lease &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02039 [NONE] `		    (brk_op->o_lease->state & ~LEASE_RH_MASK)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02040 [NONE] `			ksmbd_debug(OPLOCK, "unexpected lease state(0x%x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02041 [NONE] `				    brk_op->o_lease->state);`
  Review: Low-risk line; verify in surrounding control flow.
- L02042 [ERROR_PATH|] `			goto next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02043 [PROTO_GATE|] `		} else if (brk_op->level != SMB2_OPLOCK_LEVEL_II) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02044 [NONE] `			ksmbd_debug(OPLOCK, "unexpected oplock(0x%x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02045 [NONE] `				    brk_op->level);`
  Review: Low-risk line; verify in surrounding control flow.
- L02046 [ERROR_PATH|] `			goto next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02047 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02049 [NONE] `		/* Skip oplock being break to none */`
  Review: Low-risk line; verify in surrounding control flow.
- L02050 [NONE] `		if (brk_op->is_lease &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02051 [PROTO_GATE|] `		    brk_op->o_lease->new_state == SMB2_LEASE_NONE_LE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02052 [LIFETIME|] `		    atomic_read(&brk_op->breaking_cnt))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02053 [ERROR_PATH|] `			goto next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02054 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02056 [NONE] `		if (op && op->is_lease && brk_op->is_lease &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02057 [NONE] `		    !memcmp(conn->ClientGUID, brk_op->conn->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L02058 [PROTO_GATE|] `			    SMB2_CLIENT_GUID_SIZE) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02059 [NONE] `		    !memcmp(op->o_lease->lease_key, brk_op->o_lease->lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L02060 [PROTO_GATE|] `			    SMB2_LEASE_KEY_SIZE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02061 [ERROR_PATH|] `			goto next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02062 [NONE] `		brk_op->open_trunc = is_trunc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02063 [NONE] `		if (brk_cnt < LEVII_BRK_BATCH) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02064 [NONE] `			brk_batch[brk_cnt++] = brk_op;`
  Review: Low-risk line; verify in surrounding control flow.
- L02065 [NONE] `			/* keep the reference for use after lock release */`
  Review: Low-risk line; verify in surrounding control flow.
- L02066 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02067 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02068 [NONE] `		/* Overflow: drop this one; will be handled on next call */`
  Review: Low-risk line; verify in surrounding control flow.
- L02069 [NONE] `		opinfo_put(brk_op);`
  Review: Low-risk line; verify in surrounding control flow.
- L02070 [NONE] `		continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02071 [NONE] `next:`
  Review: Low-risk line; verify in surrounding control flow.
- L02072 [NONE] `		opinfo_put(brk_op);`
  Review: Low-risk line; verify in surrounding control flow.
- L02073 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02074 [NONE] `	up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02076 [NONE] `	/* Send break notifications without holding ci->m_lock */`
  Review: Low-risk line; verify in surrounding control flow.
- L02077 [NONE] `	for (i = 0; i < brk_cnt; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02078 [PROTO_GATE|] `		oplock_break(brk_batch[i], SMB2_OPLOCK_LEVEL_NONE, NULL);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02079 [NONE] `		opinfo_put(brk_batch[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L02080 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02082 [NONE] `	if (op)`
  Review: Low-risk line; verify in surrounding control flow.
- L02083 [NONE] `		opinfo_put(op);`
  Review: Low-risk line; verify in surrounding control flow.
- L02084 [NONE] `#undef LEVII_BRK_BATCH`
  Review: Low-risk line; verify in surrounding control flow.
- L02085 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02087 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02088 [NONE] ` * smb_break_all_oplock() - break both batch/exclusive and level2 oplock`
  Review: Low-risk line; verify in surrounding control flow.
- L02089 [NONE] ` * @work:	smb work`
  Review: Low-risk line; verify in surrounding control flow.
- L02090 [NONE] ` * @fp:		ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L02091 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02092 [NONE] `void smb_break_all_oplock(struct ksmbd_work *work, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L02093 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02094 [NONE] `	if (!test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02095 [NONE] `				    KSMBD_SHARE_FLAG_OPLOCKS))`
  Review: Low-risk line; verify in surrounding control flow.
- L02096 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02098 [NONE] `	smb_break_all_write_oplock(work, fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02099 [NONE] `	smb_break_all_levII_oplock(work, fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02100 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02102 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02103 [NONE] ` * smb_break_all_handle_lease() - break Handle caching on all leases for an inode`
  Review: Low-risk line; verify in surrounding control flow.
- L02104 [NONE] ` * @work:	smb work`
  Review: Low-risk line; verify in surrounding control flow.
- L02105 [NONE] ` * @fp:		ksmbd file pointer (caller's own handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L02106 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02107 [NONE] `void smb_break_all_handle_lease(struct ksmbd_work *work, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L02108 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02109 [NONE] `#define HANDLE_BRK_BATCH	64`
  Review: Low-risk line; verify in surrounding control flow.
- L02110 [NONE] `	struct oplock_info *brk_op;`
  Review: Low-risk line; verify in surrounding control flow.
- L02111 [NONE] `	struct oplock_info *brk_batch[HANDLE_BRK_BATCH];`
  Review: Low-risk line; verify in surrounding control flow.
- L02112 [NONE] `	struct ksmbd_inode *ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L02113 [NONE] `	int i, brk_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02115 [NONE] `	if (!test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02116 [NONE] `				    KSMBD_SHARE_FLAG_OPLOCKS))`
  Review: Low-risk line; verify in surrounding control flow.
- L02117 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02119 [NONE] `	ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L02120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02121 [NONE] `	ksmbd_debug(OPLOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L02122 [NONE] `		    "handle lease break: scanning inode %p op_list\n", ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L02123 [NONE] `	brk_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02124 [LOCK|] `	down_read(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02125 [NONE] `	list_for_each_entry(brk_op, &ci->m_op_list, op_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02126 [NONE] `		ksmbd_debug(OPLOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L02127 [NONE] `			    "  op_entry: conn=%p is_lease=%d state=0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02128 [NONE] `			    brk_op->conn, brk_op->is_lease,`
  Review: Low-risk line; verify in surrounding control flow.
- L02129 [NONE] `			    brk_op->is_lease ?`
  Review: Low-risk line; verify in surrounding control flow.
- L02130 [NONE] `			    le32_to_cpu(brk_op->o_lease->state) : 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02131 [NONE] `		if (!brk_op->conn || !brk_op->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L02132 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02133 [PROTO_GATE|] `		if (!(brk_op->o_lease->state & SMB2_LEASE_HANDLE_CACHING_LE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02134 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02135 [LIFETIME|] `		if (!refcount_inc_not_zero(&brk_op->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02136 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02137 [NONE] `		if (ksmbd_conn_releasing(brk_op->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02138 [NONE] `			opinfo_put(brk_op);`
  Review: Low-risk line; verify in surrounding control flow.
- L02139 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02140 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02141 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02142 [NONE] `		 * MS-SMB2 §3.3.5.21.1: Skip the caller's own open.`
  Review: Low-risk line; verify in surrounding control flow.
- L02143 [NONE] `		 * The initiating handle already knows about the rename`
  Review: Low-risk line; verify in surrounding control flow.
- L02144 [NONE] `		 * or delete, so it does not need a break notification.`
  Review: Low-risk line; verify in surrounding control flow.
- L02145 [NONE] `		 * Only OTHER opens on the same file need the Handle`
  Review: Low-risk line; verify in surrounding control flow.
- L02146 [NONE] `		 * caching break.`
  Review: Low-risk line; verify in surrounding control flow.
- L02147 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02148 [NONE] `		if (brk_op->o_fp == fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02149 [NONE] `			opinfo_put(brk_op);`
  Review: Low-risk line; verify in surrounding control flow.
- L02150 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02151 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02152 [NONE] `		if (brk_cnt < HANDLE_BRK_BATCH) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02153 [NONE] `			brk_batch[brk_cnt++] = brk_op;`
  Review: Low-risk line; verify in surrounding control flow.
- L02154 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02155 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02156 [NONE] `		opinfo_put(brk_op);`
  Review: Low-risk line; verify in surrounding control flow.
- L02157 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02158 [NONE] `	up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02160 [NONE] `	ksmbd_debug(OPLOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L02161 [NONE] `		    "handle lease break: found %d leases to break\n", brk_cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02162 [NONE] `	for (i = 0; i < brk_cnt; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02163 [NONE] `		oplock_break(brk_batch[i], OPLOCK_BREAK_HANDLE_CACHING, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02164 [NONE] `		opinfo_put(brk_batch[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L02165 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02166 [NONE] `#undef HANDLE_BRK_BATCH`
  Review: Low-risk line; verify in surrounding control flow.
- L02167 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02169 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02170 [NONE] ` * smb2_map_lease_to_oplock() - map lease state to corresponding oplock type`
  Review: Low-risk line; verify in surrounding control flow.
- L02171 [NONE] ` * @lease_state:     lease type`
  Review: Low-risk line; verify in surrounding control flow.
- L02172 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02173 [NONE] ` * Return:      0 if no mapping, otherwise corresponding oplock type`
  Review: Low-risk line; verify in surrounding control flow.
- L02174 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02175 [NONE] `__u8 smb2_map_lease_to_oplock(__le32 lease_state)`
  Review: Low-risk line; verify in surrounding control flow.
- L02176 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02177 [PROTO_GATE|] `	if (lease_state == (SMB2_LEASE_HANDLE_CACHING_LE |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02178 [PROTO_GATE|] `			    SMB2_LEASE_READ_CACHING_LE |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02179 [PROTO_GATE|] `			    SMB2_LEASE_WRITE_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02180 [PROTO_GATE|] `		return SMB2_OPLOCK_LEVEL_BATCH;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02181 [PROTO_GATE|] `	} else if (lease_state != SMB2_LEASE_WRITE_CACHING_LE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02182 [PROTO_GATE|] `		 lease_state & SMB2_LEASE_WRITE_CACHING_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02183 [PROTO_GATE|] `		if (!(lease_state & SMB2_LEASE_HANDLE_CACHING_LE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02184 [PROTO_GATE|] `			return SMB2_OPLOCK_LEVEL_EXCLUSIVE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02185 [PROTO_GATE|] `	} else if (lease_state & SMB2_LEASE_READ_CACHING_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02186 [PROTO_GATE|] `		return SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02187 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02188 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02189 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02190 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02191 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02192 [NONE] ` * create_lease_buf() - create lease context for open cmd response`
  Review: Low-risk line; verify in surrounding control flow.
- L02193 [NONE] ` * @rbuf:	buffer to create lease context response`
  Review: Low-risk line; verify in surrounding control flow.
- L02194 [NONE] ` * @lease:	buffer to stored parsed lease state information`
  Review: Low-risk line; verify in surrounding control flow.
- L02195 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02196 [NONE] `void create_lease_buf(u8 *rbuf, struct lease *lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L02197 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02198 [NONE] `	if (lease->version == 2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02199 [NONE] `		struct create_lease_v2 *buf = (struct create_lease_v2 *)rbuf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02201 [NONE] `		memset(buf, 0, sizeof(struct create_lease_v2));`
  Review: Low-risk line; verify in surrounding control flow.
- L02202 [MEM_BOUNDS|] `		memcpy(buf->lcontext.LeaseKey, lease->lease_key,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02203 [PROTO_GATE|] `		       SMB2_LEASE_KEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02204 [NONE] `		buf->lcontext.LeaseFlags = lease->flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L02205 [NONE] `		buf->lcontext.Epoch = cpu_to_le16(lease->epoch);`
  Review: Low-risk line; verify in surrounding control flow.
- L02206 [NONE] `		buf->lcontext.LeaseState = lease->state;`
  Review: Low-risk line; verify in surrounding control flow.
- L02207 [PROTO_GATE|] `		if (lease->flags == SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02208 [MEM_BOUNDS|] `			memcpy(buf->lcontext.ParentLeaseKey, lease->parent_lease_key,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02209 [PROTO_GATE|] `			       SMB2_LEASE_KEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02210 [NONE] `		buf->ccontext.DataOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02211 [NONE] `				(struct create_lease_v2, lcontext));`
  Review: Low-risk line; verify in surrounding control flow.
- L02212 [NONE] `		buf->ccontext.DataLength = cpu_to_le32(sizeof(struct lease_context_v2));`
  Review: Low-risk line; verify in surrounding control flow.
- L02213 [NONE] `		buf->ccontext.NameOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02214 [NONE] `				(struct create_lease_v2, Name));`
  Review: Low-risk line; verify in surrounding control flow.
- L02215 [NONE] `		buf->ccontext.NameLength = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L02216 [NONE] `		buf->Name[0] = 'R';`
  Review: Low-risk line; verify in surrounding control flow.
- L02217 [NONE] `		buf->Name[1] = 'q';`
  Review: Low-risk line; verify in surrounding control flow.
- L02218 [NONE] `		buf->Name[2] = 'L';`
  Review: Low-risk line; verify in surrounding control flow.
- L02219 [NONE] `		buf->Name[3] = 's';`
  Review: Low-risk line; verify in surrounding control flow.
- L02220 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02221 [NONE] `		struct create_lease *buf = (struct create_lease *)rbuf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02223 [NONE] `		memset(buf, 0, sizeof(struct create_lease));`
  Review: Low-risk line; verify in surrounding control flow.
- L02224 [MEM_BOUNDS|PROTO_GATE|] `		memcpy(buf->lcontext.LeaseKey, lease->lease_key, SMB2_LEASE_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02225 [NONE] `		buf->lcontext.LeaseFlags = lease->flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L02226 [NONE] `		buf->lcontext.LeaseState = lease->state;`
  Review: Low-risk line; verify in surrounding control flow.
- L02227 [NONE] `		buf->ccontext.DataOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02228 [NONE] `				(struct create_lease, lcontext));`
  Review: Low-risk line; verify in surrounding control flow.
- L02229 [NONE] `		buf->ccontext.DataLength = cpu_to_le32(sizeof(struct lease_context));`
  Review: Low-risk line; verify in surrounding control flow.
- L02230 [NONE] `		buf->ccontext.NameOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02231 [NONE] `				(struct create_lease, Name));`
  Review: Low-risk line; verify in surrounding control flow.
- L02232 [NONE] `		buf->ccontext.NameLength = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L02233 [NONE] `		buf->Name[0] = 'R';`
  Review: Low-risk line; verify in surrounding control flow.
- L02234 [NONE] `		buf->Name[1] = 'q';`
  Review: Low-risk line; verify in surrounding control flow.
- L02235 [NONE] `		buf->Name[2] = 'L';`
  Review: Low-risk line; verify in surrounding control flow.
- L02236 [NONE] `		buf->Name[3] = 's';`
  Review: Low-risk line; verify in surrounding control flow.
- L02237 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02238 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02240 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02241 [NONE] ` * parse_lease_state() - parse lease context contained in file open request`
  Review: Low-risk line; verify in surrounding control flow.
- L02242 [NONE] ` * @open_req:	buffer containing smb2 file open(create) request`
  Review: Low-risk line; verify in surrounding control flow.
- L02243 [NONE] ` * @is_dir:	whether leasing file is directory`
  Review: Low-risk line; verify in surrounding control flow.
- L02244 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02245 [NONE] ` * Return: allocated lease context object on success, otherwise NULL`
  Review: Low-risk line; verify in surrounding control flow.
- L02246 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02247 [NONE] `struct lease_ctx_info *parse_lease_state(void *open_req)`
  Review: Low-risk line; verify in surrounding control flow.
- L02248 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02249 [NONE] `	struct create_context *cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02250 [NONE] `	struct smb2_create_req *req = (struct smb2_create_req *)open_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L02251 [NONE] `	struct lease_ctx_info *lreq;`
  Review: Low-risk line; verify in surrounding control flow.
- L02252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02253 [PROTO_GATE|] `	cc = smb2_find_context_vals(req, SMB2_CREATE_REQUEST_LEASE, 4);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02254 [NONE] `	if (IS_ERR_OR_NULL(cc))`
  Review: Low-risk line; verify in surrounding control flow.
- L02255 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02256 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02257 [MEM_BOUNDS|] `	lreq = kzalloc(sizeof(struct lease_ctx_info), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02258 [NONE] `	if (!lreq)`
  Review: Low-risk line; verify in surrounding control flow.
- L02259 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02260 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02261 [NONE] `	if (sizeof(struct lease_context_v2) == le32_to_cpu(cc->DataLength)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02262 [NONE] `		struct create_lease_v2 *lc = (struct create_lease_v2 *)cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02264 [NONE] `		if (le16_to_cpu(cc->DataOffset) + le32_to_cpu(cc->DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L02265 [NONE] `		    sizeof(struct create_lease_v2) - 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L02266 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02267 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02268 [MEM_BOUNDS|PROTO_GATE|] `		memcpy(lreq->lease_key, lc->lcontext.LeaseKey, SMB2_LEASE_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02269 [NONE] `		lreq->req_state = lc->lcontext.LeaseState;`
  Review: Low-risk line; verify in surrounding control flow.
- L02270 [NONE] `		lreq->flags = lc->lcontext.LeaseFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L02271 [NONE] `		lreq->epoch = lc->lcontext.Epoch;`
  Review: Low-risk line; verify in surrounding control flow.
- L02272 [NONE] `		lreq->duration = lc->lcontext.LeaseDuration;`
  Review: Low-risk line; verify in surrounding control flow.
- L02273 [PROTO_GATE|] `		if (lreq->flags == SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02274 [MEM_BOUNDS|] `			memcpy(lreq->parent_lease_key, lc->lcontext.ParentLeaseKey,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02275 [PROTO_GATE|] `			       SMB2_LEASE_KEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02276 [NONE] `		lreq->version = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L02277 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02278 [NONE] `		struct create_lease *lc = (struct create_lease *)cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02280 [NONE] `		if (le16_to_cpu(cc->DataOffset) + le32_to_cpu(cc->DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L02281 [NONE] `		    sizeof(struct create_lease))`
  Review: Low-risk line; verify in surrounding control flow.
- L02282 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02284 [MEM_BOUNDS|PROTO_GATE|] `		memcpy(lreq->lease_key, lc->lcontext.LeaseKey, SMB2_LEASE_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02285 [NONE] `		lreq->req_state = lc->lcontext.LeaseState;`
  Review: Low-risk line; verify in surrounding control flow.
- L02286 [NONE] `		lreq->flags = lc->lcontext.LeaseFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L02287 [NONE] `		lreq->duration = lc->lcontext.LeaseDuration;`
  Review: Low-risk line; verify in surrounding control flow.
- L02288 [NONE] `		lreq->version = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02289 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02290 [NONE] `	return lreq;`
  Review: Low-risk line; verify in surrounding control flow.
- L02291 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02292 [NONE] `	kfree(lreq);`
  Review: Low-risk line; verify in surrounding control flow.
- L02293 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02294 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02295 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02296 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02297 [NONE] ` * smb2_find_context_vals() - find a particular context info in open request`
  Review: Low-risk line; verify in surrounding control flow.
- L02298 [NONE] ` * @open_req:	buffer containing smb2 file open(create) request`
  Review: Low-risk line; verify in surrounding control flow.
- L02299 [NONE] ` * @tag:	context name to search for`
  Review: Low-risk line; verify in surrounding control flow.
- L02300 [NONE] ` * @tag_len:	the length of tag`
  Review: Low-risk line; verify in surrounding control flow.
- L02301 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02302 [NONE] ` * Return:	pointer to requested context, NULL if @str context not found`
  Review: Low-risk line; verify in surrounding control flow.
- L02303 [NONE] ` *		or error pointer if name length is invalid.`
  Review: Low-risk line; verify in surrounding control flow.
- L02304 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02305 [NONE] `struct create_context *smb2_find_context_vals(void *open_req, const char *tag, int tag_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02306 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02307 [NONE] `	struct create_context *cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02308 [NONE] `	unsigned int next = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02309 [NONE] `	char *name;`
  Review: Low-risk line; verify in surrounding control flow.
- L02310 [NONE] `	struct smb2_create_req *req = (struct smb2_create_req *)open_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L02311 [NONE] `	unsigned int remain_len, name_off, name_len, value_off, value_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02312 [NONE] `		     cc_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02314 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02315 [NONE] `	 * CreateContextsOffset and CreateContextsLength are guaranteed to`
  Review: Low-risk line; verify in surrounding control flow.
- L02316 [NONE] `	 * be valid because of ksmbd_smb2_check_message().`
  Review: Low-risk line; verify in surrounding control flow.
- L02317 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02318 [NONE] `	cc = (struct create_context *)((char *)req +`
  Review: Low-risk line; verify in surrounding control flow.
- L02319 [NONE] `				       le32_to_cpu(req->CreateContextsOffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L02320 [NONE] `	remain_len = le32_to_cpu(req->CreateContextsLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L02321 [NONE] `	do {`
  Review: Low-risk line; verify in surrounding control flow.
- L02322 [NONE] `		cc = (struct create_context *)((char *)cc + next);`
  Review: Low-risk line; verify in surrounding control flow.
- L02323 [NONE] `		if (remain_len < offsetof(struct create_context, Buffer))`
  Review: Low-risk line; verify in surrounding control flow.
- L02324 [NONE] `			return ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02325 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02326 [NONE] `		next = le32_to_cpu(cc->Next);`
  Review: Low-risk line; verify in surrounding control flow.
- L02327 [NONE] `		name_off = le16_to_cpu(cc->NameOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02328 [NONE] `		name_len = le16_to_cpu(cc->NameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L02329 [NONE] `		value_off = le16_to_cpu(cc->DataOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02330 [NONE] `		value_len = le32_to_cpu(cc->DataLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L02331 [NONE] `		cc_len = next ? next : remain_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02333 [NONE] `		if ((next & 0x7) != 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02334 [NONE] `		    next > remain_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02335 [NONE] `		    name_off != offsetof(struct create_context, Buffer) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02336 [NONE] `		    name_len < 4 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02337 [NONE] `		    name_off + name_len > cc_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02338 [NONE] `		    (value_off & 0x7) != 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02339 [NONE] `		    (value_len && value_off < name_off + (name_len < 8 ? 8 : name_len)) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02340 [NONE] `		    ((u64)value_off + value_len > cc_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L02341 [NONE] `			return ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02343 [NONE] `		name = (char *)cc + name_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L02344 [NONE] `		if (name_len == tag_len && !memcmp(name, tag, name_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L02345 [NONE] `			return cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02347 [NONE] `		remain_len -= next;`
  Review: Low-risk line; verify in surrounding control flow.
- L02348 [NONE] `	} while (next != 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02350 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02351 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02353 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02354 [NONE] ` * create_durable_rsp_buf() - create durable handle context`
  Review: Low-risk line; verify in surrounding control flow.
- L02355 [NONE] ` * @cc:	buffer to create durable context response`
  Review: Low-risk line; verify in surrounding control flow.
- L02356 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02357 [NONE] `void create_durable_rsp_buf(char *cc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02358 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02359 [NONE] `	struct create_durable_rsp *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02361 [NONE] `	buf = (struct create_durable_rsp *)cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02362 [NONE] `	memset(buf, 0, sizeof(struct create_durable_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L02363 [NONE] `	buf->ccontext.DataOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02364 [NONE] `			(struct create_durable_rsp, Data));`
  Review: Low-risk line; verify in surrounding control flow.
- L02365 [NONE] `	buf->ccontext.DataLength = cpu_to_le32(8);`
  Review: Low-risk line; verify in surrounding control flow.
- L02366 [NONE] `	buf->ccontext.NameOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02367 [NONE] `			(struct create_durable_rsp, Name));`
  Review: Low-risk line; verify in surrounding control flow.
- L02368 [NONE] `	buf->ccontext.NameLength = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L02369 [PROTO_GATE|] `	/* SMB2_CREATE_DURABLE_HANDLE_RESPONSE is "DHnQ" */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02370 [NONE] `	buf->Name[0] = 'D';`
  Review: Low-risk line; verify in surrounding control flow.
- L02371 [NONE] `	buf->Name[1] = 'H';`
  Review: Low-risk line; verify in surrounding control flow.
- L02372 [NONE] `	buf->Name[2] = 'n';`
  Review: Low-risk line; verify in surrounding control flow.
- L02373 [NONE] `	buf->Name[3] = 'Q';`
  Review: Low-risk line; verify in surrounding control flow.
- L02374 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02375 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02376 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02377 [NONE] ` * create_durable_v2_rsp_buf() - create durable handle v2 context`
  Review: Low-risk line; verify in surrounding control flow.
- L02378 [NONE] ` * @cc:	buffer to create durable context response`
  Review: Low-risk line; verify in surrounding control flow.
- L02379 [NONE] ` * @fp: ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L02380 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02381 [NONE] `void create_durable_v2_rsp_buf(char *cc, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L02382 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02383 [NONE] `	struct create_durable_v2_rsp *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02384 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02385 [NONE] `	buf = (struct create_durable_v2_rsp *)cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02386 [NONE] `	memset(buf, 0, sizeof(struct create_durable_v2_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L02387 [NONE] `	buf->ccontext.DataOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02388 [NONE] `			(struct create_durable_v2_rsp, Timeout));`
  Review: Low-risk line; verify in surrounding control flow.
- L02389 [NONE] `	buf->ccontext.DataLength = cpu_to_le32(8);`
  Review: Low-risk line; verify in surrounding control flow.
- L02390 [NONE] `	buf->ccontext.NameOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02391 [NONE] `			(struct create_durable_v2_rsp, Name));`
  Review: Low-risk line; verify in surrounding control flow.
- L02392 [NONE] `	buf->ccontext.NameLength = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L02393 [PROTO_GATE|] `	/* SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2 is "DH2Q" */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02394 [NONE] `	buf->Name[0] = 'D';`
  Review: Low-risk line; verify in surrounding control flow.
- L02395 [NONE] `	buf->Name[1] = 'H';`
  Review: Low-risk line; verify in surrounding control flow.
- L02396 [NONE] `	buf->Name[2] = '2';`
  Review: Low-risk line; verify in surrounding control flow.
- L02397 [NONE] `	buf->Name[3] = 'Q';`
  Review: Low-risk line; verify in surrounding control flow.
- L02398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02399 [NONE] `	buf->Timeout = cpu_to_le32(fp->durable_timeout);`
  Review: Low-risk line; verify in surrounding control flow.
- L02400 [NONE] `	if (fp->is_persistent)`
  Review: Low-risk line; verify in surrounding control flow.
- L02401 [PROTO_GATE|] `		buf->Flags = cpu_to_le32(SMB2_DHANDLE_FLAG_PERSISTENT);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02402 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02403 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02404 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02405 [NONE] ` * create_mxac_rsp_buf() - create query maximal access context`
  Review: Low-risk line; verify in surrounding control flow.
- L02406 [NONE] ` * @cc:			buffer to create maximal access context response`
  Review: Low-risk line; verify in surrounding control flow.
- L02407 [NONE] ` * @maximal_access:	maximal access`
  Review: Low-risk line; verify in surrounding control flow.
- L02408 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02409 [NONE] `void create_mxac_rsp_buf(char *cc, int maximal_access)`
  Review: Low-risk line; verify in surrounding control flow.
- L02410 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02411 [NONE] `	struct create_mxac_rsp *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02412 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02413 [NONE] `	buf = (struct create_mxac_rsp *)cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02414 [NONE] `	memset(buf, 0, sizeof(struct create_mxac_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L02415 [NONE] `	buf->ccontext.DataOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02416 [NONE] `			(struct create_mxac_rsp, QueryStatus));`
  Review: Low-risk line; verify in surrounding control flow.
- L02417 [NONE] `	buf->ccontext.DataLength = cpu_to_le32(8);`
  Review: Low-risk line; verify in surrounding control flow.
- L02418 [NONE] `	buf->ccontext.NameOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02419 [NONE] `			(struct create_mxac_rsp, Name));`
  Review: Low-risk line; verify in surrounding control flow.
- L02420 [NONE] `	buf->ccontext.NameLength = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L02421 [PROTO_GATE|] `	/* SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE is "MxAc" */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02422 [NONE] `	buf->Name[0] = 'M';`
  Review: Low-risk line; verify in surrounding control flow.
- L02423 [NONE] `	buf->Name[1] = 'x';`
  Review: Low-risk line; verify in surrounding control flow.
- L02424 [NONE] `	buf->Name[2] = 'A';`
  Review: Low-risk line; verify in surrounding control flow.
- L02425 [NONE] `	buf->Name[3] = 'c';`
  Review: Low-risk line; verify in surrounding control flow.
- L02426 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02427 [PROTO_GATE|] `	buf->QueryStatus = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02428 [NONE] `	buf->MaximalAccess = cpu_to_le32(maximal_access);`
  Review: Low-risk line; verify in surrounding control flow.
- L02429 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02430 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02431 [NONE] `void create_disk_id_rsp_buf(char *cc, __u64 file_id, __u64 vol_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L02432 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02433 [NONE] `	struct create_disk_id_rsp *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02434 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02435 [NONE] `	buf = (struct create_disk_id_rsp *)cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02436 [NONE] `	memset(buf, 0, sizeof(struct create_disk_id_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L02437 [NONE] `	buf->ccontext.DataOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02438 [NONE] `			(struct create_disk_id_rsp, DiskFileId));`
  Review: Low-risk line; verify in surrounding control flow.
- L02439 [NONE] `	buf->ccontext.DataLength = cpu_to_le32(32);`
  Review: Low-risk line; verify in surrounding control flow.
- L02440 [NONE] `	buf->ccontext.NameOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02441 [NONE] `			(struct create_mxac_rsp, Name));`
  Review: Low-risk line; verify in surrounding control flow.
- L02442 [NONE] `	buf->ccontext.NameLength = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L02443 [PROTO_GATE|] `	/* SMB2_CREATE_QUERY_ON_DISK_ID_RESPONSE is "QFid" */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02444 [NONE] `	buf->Name[0] = 'Q';`
  Review: Low-risk line; verify in surrounding control flow.
- L02445 [NONE] `	buf->Name[1] = 'F';`
  Review: Low-risk line; verify in surrounding control flow.
- L02446 [NONE] `	buf->Name[2] = 'i';`
  Review: Low-risk line; verify in surrounding control flow.
- L02447 [NONE] `	buf->Name[3] = 'd';`
  Review: Low-risk line; verify in surrounding control flow.
- L02448 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02449 [NONE] `	buf->DiskFileId = cpu_to_le64(file_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02450 [NONE] `	buf->VolumeId = cpu_to_le64(vol_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02451 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02452 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02453 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02454 [NONE] ` * create_posix_rsp_buf() - create posix extension context`
  Review: Low-risk line; verify in surrounding control flow.
- L02455 [NONE] ` * @cc:	buffer to create posix on posix response`
  Review: Low-risk line; verify in surrounding control flow.
- L02456 [NONE] ` * @fp: ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L02457 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02458 [NONE] `void create_posix_rsp_buf(char *cc, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L02459 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02460 [NONE] `	struct create_posix_rsp *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02461 [NONE] `	struct inode *inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02462 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02463 [NONE] `	struct mnt_idmap *idmap = file_mnt_idmap(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02464 [NONE] `	vfsuid_t vfsuid = i_uid_into_vfsuid(idmap, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02465 [NONE] `	vfsgid_t vfsgid = i_gid_into_vfsgid(idmap, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02466 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02467 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02468 [NONE] `	struct user_namespace *user_ns = file_mnt_user_ns(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02469 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02470 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02471 [NONE] `	vfsuid_t vfsuid = i_uid_into_vfsuid(user_ns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02472 [NONE] `	vfsgid_t vfsgid = i_gid_into_vfsgid(user_ns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02473 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02474 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02475 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02476 [NONE] `	buf = (struct create_posix_rsp *)cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02477 [NONE] `	memset(buf, 0, sizeof(struct create_posix_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L02478 [NONE] `	buf->ccontext.DataOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02479 [NONE] `			(struct create_posix_rsp, nlink));`
  Review: Low-risk line; verify in surrounding control flow.
- L02480 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02481 [NONE] `	 * DataLength = nlink(4) + reparse_tag(4) + mode(4) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02482 [NONE] `	 * domain sid(28) + unix group sid(16).`
  Review: Low-risk line; verify in surrounding control flow.
- L02483 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02484 [NONE] `	buf->ccontext.DataLength = cpu_to_le32(56);`
  Review: Low-risk line; verify in surrounding control flow.
- L02485 [NONE] `	buf->ccontext.NameOffset = cpu_to_le16(offsetof`
  Review: Low-risk line; verify in surrounding control flow.
- L02486 [NONE] `			(struct create_posix_rsp, Name));`
  Review: Low-risk line; verify in surrounding control flow.
- L02487 [NONE] `	buf->ccontext.NameLength = cpu_to_le16(POSIX_CTXT_DATA_LEN);`
  Review: Low-risk line; verify in surrounding control flow.
- L02488 [PROTO_GATE|] `	/* SMB2_CREATE_TAG_POSIX is "0x93AD25509CB411E7B42383DE968BCD7C" */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02489 [NONE] `	buf->Name[0] = 0x93;`
  Review: Low-risk line; verify in surrounding control flow.
- L02490 [NONE] `	buf->Name[1] = 0xAD;`
  Review: Low-risk line; verify in surrounding control flow.
- L02491 [NONE] `	buf->Name[2] = 0x25;`
  Review: Low-risk line; verify in surrounding control flow.
- L02492 [NONE] `	buf->Name[3] = 0x50;`
  Review: Low-risk line; verify in surrounding control flow.
- L02493 [NONE] `	buf->Name[4] = 0x9C;`
  Review: Low-risk line; verify in surrounding control flow.
- L02494 [NONE] `	buf->Name[5] = 0xB4;`
  Review: Low-risk line; verify in surrounding control flow.
- L02495 [NONE] `	buf->Name[6] = 0x11;`
  Review: Low-risk line; verify in surrounding control flow.
- L02496 [NONE] `	buf->Name[7] = 0xE7;`
  Review: Low-risk line; verify in surrounding control flow.
- L02497 [NONE] `	buf->Name[8] = 0xB4;`
  Review: Low-risk line; verify in surrounding control flow.
- L02498 [NONE] `	buf->Name[9] = 0x23;`
  Review: Low-risk line; verify in surrounding control flow.
- L02499 [NONE] `	buf->Name[10] = 0x83;`
  Review: Low-risk line; verify in surrounding control flow.
- L02500 [NONE] `	buf->Name[11] = 0xDE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02501 [NONE] `	buf->Name[12] = 0x96;`
  Review: Low-risk line; verify in surrounding control flow.
- L02502 [NONE] `	buf->Name[13] = 0x8B;`
  Review: Low-risk line; verify in surrounding control flow.
- L02503 [NONE] `	buf->Name[14] = 0xCD;`
  Review: Low-risk line; verify in surrounding control flow.
- L02504 [NONE] `	buf->Name[15] = 0x7C;`
  Review: Low-risk line; verify in surrounding control flow.
- L02505 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02506 [NONE] `	buf->nlink = cpu_to_le32(inode->i_nlink);`
  Review: Low-risk line; verify in surrounding control flow.
- L02507 [NONE] `	buf->reparse_tag = cpu_to_le32(fp->volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02508 [NONE] `	buf->mode = cpu_to_le32(inode->i_mode & 0777);`
  Review: Low-risk line; verify in surrounding control flow.
- L02509 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02510 [NONE] `	 * SidBuffer(44) contain two sids(Domain sid(28), UNIX group sid(16)).`
  Review: Low-risk line; verify in surrounding control flow.
- L02511 [NONE] `	 * Domain sid(28) = revision(1) + num_subauth(1) + authority(6) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02512 [NONE] `	 * 		    sub_auth(4 * 4(num_subauth)) + RID(4).`
  Review: Low-risk line; verify in surrounding control flow.
- L02513 [NONE] `	 * UNIX group id(16) = revision(1) + num_subauth(1) + authority(6) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02514 [NONE] `	 * 		       sub_auth(4 * 1(num_subauth)) + RID(4).`
  Review: Low-risk line; verify in surrounding control flow.
- L02515 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02516 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02517 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02518 [NONE] `	id_to_sid(from_kuid_munged(&init_user_ns, vfsuid_into_kuid(vfsuid)),`
  Review: Low-risk line; verify in surrounding control flow.
- L02519 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02520 [NONE] `	id_to_sid(from_kuid_munged(&init_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02521 [NONE] `				   i_uid_into_mnt(user_ns, inode)),`
  Review: Low-risk line; verify in surrounding control flow.
- L02522 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02523 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02524 [NONE] `	id_to_sid(from_kuid_munged(&init_user_ns, inode->i_uid),`
  Review: Low-risk line; verify in surrounding control flow.
- L02525 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02526 [NONE] `		  SIDOWNER, (struct smb_sid *)&buf->SidBuffer[0]);`
  Review: Low-risk line; verify in surrounding control flow.
- L02527 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02528 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02529 [NONE] `	id_to_sid(from_kgid_munged(&init_user_ns, vfsgid_into_kgid(vfsgid)),`
  Review: Low-risk line; verify in surrounding control flow.
- L02530 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02531 [NONE] `	id_to_sid(from_kgid_munged(&init_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02532 [NONE] `				   i_gid_into_mnt(user_ns, inode)),`
  Review: Low-risk line; verify in surrounding control flow.
- L02533 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02534 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02535 [NONE] `	id_to_sid(from_kgid_munged(&init_user_ns, inode->i_gid),`
  Review: Low-risk line; verify in surrounding control flow.
- L02536 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02537 [NONE] `		  SIDUNIX_GROUP, (struct smb_sid *)&buf->SidBuffer[28]);`
  Review: Low-risk line; verify in surrounding control flow.
- L02538 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02539 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02540 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L02541 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02542 [NONE] ` * Compute the total byte size of a Fruit AAPL response`
  Review: Low-risk line; verify in surrounding control flow.
- L02543 [NONE] ` * including the variable-length model string.`
  Review: Low-risk line; verify in surrounding control flow.
- L02544 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02545 [NONE] `static inline size_t fruit_rsp_size(size_t model_utf16_bytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L02546 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02547 [NONE] `	return offsetof(struct create_fruit_rsp, model) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02548 [NONE] `	       model_utf16_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L02549 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02550 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02551 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02552 [NONE] ` * Build the AAPL create context response with all three sections:`
  Review: Low-risk line; verify in surrounding control flow.
- L02553 [NONE] ` *   - server_caps  (computed from global config flags)`
  Review: Low-risk line; verify in surrounding control flow.
- L02554 [NONE] ` *   - volume_caps  (case sensitivity + fullsync support)`
  Review: Low-risk line; verify in surrounding control flow.
- L02555 [NONE] ` *   - model_info   (server model string as UTF-16LE)`
  Review: Low-risk line; verify in surrounding control flow.
- L02556 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02557 [NONE] ` * Returns 0 on success and sets *out_size to the total response size.`
  Review: Low-risk line; verify in surrounding control flow.
- L02558 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02559 [NONE] `int create_fruit_rsp_buf(char *cc, struct ksmbd_conn *conn, size_t *out_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L02560 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02561 [NONE] `	struct create_fruit_rsp *buf = (struct create_fruit_rsp *)cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02562 [NONE] `	const char *model = server_conf.fruit_model;`
  Review: Low-risk line; verify in surrounding control flow.
- L02563 [NONE] `	size_t model_ascii_len, model_utf16_bytes, total;`
  Review: Low-risk line; verify in surrounding control flow.
- L02564 [NONE] `	u64 caps, vcaps;`
  Review: Low-risk line; verify in surrounding control flow.
- L02565 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L02566 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02567 [NONE] `	/* Default model if none configured */`
  Review: Low-risk line; verify in surrounding control flow.
- L02568 [NONE] `	if (!model[0])`
  Review: Low-risk line; verify in surrounding control flow.
- L02569 [NONE] `		model = "MacSamba";`
  Review: Low-risk line; verify in surrounding control flow.
- L02570 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02571 [NONE] `	model_ascii_len = strlen(model);`
  Review: Low-risk line; verify in surrounding control flow.
- L02572 [NONE] `	model_utf16_bytes = model_ascii_len * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L02573 [NONE] `	total = fruit_rsp_size(model_utf16_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L02574 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02575 [NONE] `	memset(buf, 0, total);`
  Review: Low-risk line; verify in surrounding control flow.
- L02576 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02577 [NONE] `	/* create_context header */`
  Review: Low-risk line; verify in surrounding control flow.
- L02578 [NONE] `	buf->ccontext.DataOffset = cpu_to_le16(offsetof(`
  Review: Low-risk line; verify in surrounding control flow.
- L02579 [NONE] `			struct create_fruit_rsp, command_code));`
  Review: Low-risk line; verify in surrounding control flow.
- L02580 [NONE] `	buf->ccontext.DataLength = cpu_to_le32(total -`
  Review: Low-risk line; verify in surrounding control flow.
- L02581 [NONE] `			offsetof(struct create_fruit_rsp, command_code));`
  Review: Low-risk line; verify in surrounding control flow.
- L02582 [NONE] `	buf->ccontext.NameOffset = cpu_to_le16(offsetof(`
  Review: Low-risk line; verify in surrounding control flow.
- L02583 [NONE] `			struct create_fruit_rsp, Name));`
  Review: Low-risk line; verify in surrounding control flow.
- L02584 [NONE] `	buf->ccontext.NameLength = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L02585 [NONE] `	/* Wire protocol name must be "AAPL" */`
  Review: Low-risk line; verify in surrounding control flow.
- L02586 [NONE] `	buf->Name[0] = 'A';`
  Review: Low-risk line; verify in surrounding control flow.
- L02587 [NONE] `	buf->Name[1] = 'A';`
  Review: Low-risk line; verify in surrounding control flow.
- L02588 [NONE] `	buf->Name[2] = 'P';`
  Review: Low-risk line; verify in surrounding control flow.
- L02589 [NONE] `	buf->Name[3] = 'L';`
  Review: Low-risk line; verify in surrounding control flow.
- L02590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02591 [NONE] `	buf->command_code = cpu_to_le32(1); /* kAAPL_SERVER_QUERY */`
  Review: Low-risk line; verify in surrounding control flow.
- L02592 [NONE] `	buf->reply_bitmap = cpu_to_le64(0x07); /* caps + volcaps + model */`
  Review: Low-risk line; verify in surrounding control flow.
- L02593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02594 [NONE] `	/* server_caps: computed from global config flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L02595 [NONE] `	caps = kAAPL_UNIX_BASED; /* always: Linux is UNIX-based */`
  Review: Low-risk line; verify in surrounding control flow.
- L02596 [NONE] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE)`
  Review: Low-risk line; verify in surrounding control flow.
- L02597 [NONE] `		caps |= kAAPL_SUPPORTS_OSX_COPYFILE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02598 [NONE] `	caps |= kAAPL_SUPPORTS_READ_DIR_ATTR;`
  Review: Low-risk line; verify in surrounding control flow.
- L02599 [NONE] `	caps |= kAAPL_SUPPORTS_TM_LOCK_STEAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02600 [NONE] `	buf->server_caps = cpu_to_le64(caps);`
  Review: Low-risk line; verify in surrounding control flow.
- L02601 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02602 [NONE] `	/* volume_caps: use ksmbd_fruit_get_volume_caps() for resolve_fileid */`
  Review: Low-risk line; verify in surrounding control flow.
- L02603 [NONE] `	vcaps = ksmbd_fruit_get_volume_caps(NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02604 [NONE] `	buf->volume_caps = cpu_to_le64(vcaps);`
  Review: Low-risk line; verify in surrounding control flow.
- L02605 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02606 [NONE] `	/* model string: ASCII → UTF-16LE */`
  Review: Low-risk line; verify in surrounding control flow.
- L02607 [NONE] `	buf->model_string_len = cpu_to_le32(model_utf16_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L02608 [NONE] `	for (i = 0; i < (int)model_ascii_len; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L02609 [NONE] `		buf->model[i] = cpu_to_le16((u16)model[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L02610 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02611 [NONE] `	*out_size = total;`
  Review: Low-risk line; verify in surrounding control flow.
- L02612 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02613 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02614 [NONE] `#endif /* CONFIG_KSMBD_FRUIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L02615 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02616 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02617 [NONE] ` * Find lease object(opinfo) for given lease key/fid from lease`
  Review: Low-risk line; verify in surrounding control flow.
- L02618 [NONE] ` * break/file close path.`
  Review: Low-risk line; verify in surrounding control flow.
- L02619 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02620 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02621 [NONE] ` * lookup_lease_in_table() - find a matching lease info object`
  Review: Low-risk line; verify in surrounding control flow.
- L02622 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L02623 [NONE] ` * @lease_key:	lease key to be searched for`
  Review: Low-risk line; verify in surrounding control flow.
- L02624 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02625 [NONE] ` * Return:      opinfo if found matching opinfo, otherwise NULL`
  Review: Low-risk line; verify in surrounding control flow.
- L02626 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02627 [NONE] `struct oplock_info *lookup_lease_in_table(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02628 [NONE] `					  char *lease_key)`
  Review: Low-risk line; verify in surrounding control flow.
- L02629 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02630 [NONE] `	struct oplock_info *opinfo = NULL, *ret_op = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02631 [NONE] `	struct lease_table *lt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02632 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02633 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02634 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02635 [NONE] `	list_for_each_entry_rcu(lt, &lease_table_list, l_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02636 [NONE] `		if (!memcmp(lt->client_guid, conn->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L02637 [PROTO_GATE|] `			    SMB2_CLIENT_GUID_SIZE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02638 [ERROR_PATH|] `			goto found;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02639 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02640 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02641 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02642 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02644 [NONE] `found:`
  Review: Low-risk line; verify in surrounding control flow.
- L02645 [NONE] `	list_for_each_entry_rcu(opinfo, &lt->lease_list, lease_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02646 [LIFETIME|] `		if (!refcount_inc_not_zero(&opinfo->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02647 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02648 [LIFETIME|] `		rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02649 [NONE] `		if (!opinfo->op_state || opinfo->op_state == OPLOCK_CLOSING)`
  Review: Low-risk line; verify in surrounding control flow.
- L02650 [ERROR_PATH|] `			goto op_next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02651 [NONE] `		if (!(opinfo->o_lease->state &`
  Review: Low-risk line; verify in surrounding control flow.
- L02652 [PROTO_GATE|] `		      (SMB2_LEASE_HANDLE_CACHING_LE |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02653 [PROTO_GATE|] `		       SMB2_LEASE_WRITE_CACHING_LE)))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02654 [ERROR_PATH|] `			goto op_next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02655 [NONE] `		ret = compare_guid_key(opinfo, conn->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L02656 [NONE] `				       lease_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L02657 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02658 [NONE] `			ksmbd_debug(OPLOCK, "found opinfo\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02659 [NONE] `			ret_op = opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L02660 [NONE] `			return ret_op;`
  Review: Low-risk line; verify in surrounding control flow.
- L02661 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02662 [NONE] `op_next:`
  Review: Low-risk line; verify in surrounding control flow.
- L02663 [NONE] `		opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L02664 [LIFETIME|] `		rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02665 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02666 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02667 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02668 [NONE] `	return ret_op;`
  Review: Low-risk line; verify in surrounding control flow.
- L02669 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02670 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02671 [NONE] `int smb2_check_durable_oplock(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02672 [NONE] `			      struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L02673 [NONE] `			      struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02674 [NONE] `			      struct lease_ctx_info *lctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L02675 [NONE] `			      char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L02676 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02677 [NONE] `	struct oplock_info *opinfo = opinfo_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02678 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02679 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02680 [NONE] `	if (!opinfo) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02681 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02682 [NONE] `		 * C.9: If there is no opinfo (lease expired / oplock revoked)`
  Review: Low-risk line; verify in surrounding control flow.
- L02683 [NONE] `		 * and this handle was durable, the reconnect MUST fail because`
  Review: Low-risk line; verify in surrounding control flow.
- L02684 [NONE] `		 * there is no oplock/lease state to restore.`
  Review: Low-risk line; verify in surrounding control flow.
- L02685 [NONE] `		 * MS-SMB2 §3.3.5.9.10 / §3.3.5.9.13: durable reconnect`
  Review: Low-risk line; verify in surrounding control flow.
- L02686 [NONE] `		 * requires the handle to still hold the oplock/lease.`
  Review: Low-risk line; verify in surrounding control flow.
- L02687 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02688 [NONE] `		if (fp->is_durable || fp->is_persistent)`
  Review: Low-risk line; verify in surrounding control flow.
- L02689 [ERROR_PATH|] `			return -EBADF;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02690 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02691 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02693 [NONE] `	if (opinfo->is_lease == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02694 [NONE] `		if (lctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02695 [ERROR_PATH|] `			pr_err("create context include lease\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02696 [NONE] `			ret = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L02697 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02698 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02699 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02700 [PROTO_GATE|] `		if (opinfo->level != SMB2_OPLOCK_LEVEL_BATCH) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02701 [ERROR_PATH|PROTO_GATE|] `			pr_err("oplock level is not equal to SMB2_OPLOCK_LEVEL_BATCH\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02702 [NONE] `			ret = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L02703 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02705 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02706 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02708 [NONE] `	if (memcmp(conn->ClientGUID, fp->client_guid,`
  Review: Low-risk line; verify in surrounding control flow.
- L02709 [PROTO_GATE|] `				SMB2_CLIENT_GUID_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02710 [NONE] `		ksmbd_debug(SMB, "Client guid of fp is not equal to the one of connection\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02711 [NONE] `		ret = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L02712 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02713 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02714 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02715 [NONE] `	if (!lctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02716 [NONE] `		ksmbd_debug(SMB, "create context does not include lease\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02717 [NONE] `		ret = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L02718 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02719 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02720 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02721 [NONE] `	if (memcmp(opinfo->o_lease->lease_key, lctx->lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L02722 [PROTO_GATE|] `				SMB2_LEASE_KEY_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02723 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02724 [NONE] `			    "lease key of fp does not match lease key in create context\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02725 [NONE] `		ret = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L02726 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02727 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02728 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02729 [PROTO_GATE|] `	if (!(opinfo->o_lease->state & SMB2_LEASE_HANDLE_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02730 [PROTO_GATE|] `		ksmbd_debug(SMB, "lease state does not contain SMB2_LEASE_HANDLE_CACHING\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02731 [NONE] `		ret = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L02732 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02733 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02734 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02735 [NONE] `	if (opinfo->o_lease->version != lctx->version) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02736 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02737 [NONE] `			    "lease version of fp does not match the one in create context\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02738 [NONE] `		ret = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L02739 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02740 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02741 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02742 [NONE] `	if (!ksmbd_inode_pending_delete(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L02743 [NONE] `		ret = ksmbd_validate_name_reconnect(share, fp, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02744 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02745 [NONE] `	opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L02746 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02747 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02748 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02749 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02750 [NONE] ` * ksmbd_oplock_init() - initialize opinfo slab cache`
  Review: Low-risk line; verify in surrounding control flow.
- L02751 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02752 [NONE] ` * Return:	0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L02753 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02754 [NONE] `int ksmbd_oplock_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L02755 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02756 [NONE] `	opinfo_cache = kmem_cache_create("ksmbd_opinfo_cache",`
  Review: Low-risk line; verify in surrounding control flow.
- L02757 [NONE] `					 sizeof(struct oplock_info), 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L02758 [NONE] `					 SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT,`
  Review: Low-risk line; verify in surrounding control flow.
- L02759 [NONE] `					 NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02760 [NONE] `	if (!opinfo_cache)`
  Review: Low-risk line; verify in surrounding control flow.
- L02761 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02762 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02763 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02764 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02765 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02766 [NONE] ` * ksmbd_oplock_exit() - destroy opinfo slab cache`
  Review: Low-risk line; verify in surrounding control flow.
- L02767 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02768 [NONE] `void ksmbd_oplock_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L02769 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02770 [NONE] `	kmem_cache_destroy(opinfo_cache);`
  Review: Low-risk line; verify in surrounding control flow.
- L02771 [NONE] `	opinfo_cache = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02772 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
