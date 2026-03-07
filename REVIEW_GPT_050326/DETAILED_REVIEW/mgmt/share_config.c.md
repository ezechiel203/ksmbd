# Line-by-line Review: src/mgmt/share_config.c

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
- L00007 [NONE] `#include <linux/jhash.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/rwsem.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/parser.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/sched.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/mm.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#define SHARE_HASH_BITS		12`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `static DEFINE_HASHTABLE(shares_table, SHARE_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `static DEFINE_SPINLOCK(shares_table_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `struct ksmbd_veto_pattern {`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	char			*pattern;`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	struct list_head	list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `static unsigned int share_name_hash(const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	return jhash(name, strlen(name), 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `static void kill_share(struct ksmbd_share_config *share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	while (!list_empty(&share->veto_list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `		struct ksmbd_veto_pattern *p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `		p = list_entry(share->veto_list.next,`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `			       struct ksmbd_veto_pattern,`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `			       list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `		list_del(&p->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `		kfree(p->pattern);`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `		kfree(p);`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	if (share->path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `		path_put(&share->vfs_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	kfree(share->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	kfree(share->path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	kfree(share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [LIFETIME|] ` * kill_share_rcu() - RCU callback to free a share config`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00060 [LIFETIME|] ` * @head: rcu_head embedded in ksmbd_share_config`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00061 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [LIFETIME|] ` * Called after an RCU grace period to safely free a share`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00063 [NONE] ` * config that was removed from the hash table.`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [LIFETIME|] `static void kill_share_rcu(struct rcu_head *head)`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00066 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	struct ksmbd_share_config *share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	share = container_of(head, struct ksmbd_share_config,`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [LIFETIME|] `			     rcu_head);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00071 [NONE] `	kill_share(share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `void ksmbd_share_config_del(struct ksmbd_share_config *share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [LOCK|] `	spin_lock(&shares_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00077 [NONE] `	hash_del_rcu(&share->hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [LOCK|] `	spin_unlock(&shares_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00079 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `void __ksmbd_share_config_put(struct ksmbd_share_config *share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	ksmbd_share_config_del(share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [LIFETIME|] `	call_rcu(&share->rcu_head, kill_share_rcu);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00085 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `static struct ksmbd_share_config *`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `__get_share_config(struct ksmbd_share_config *share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [LIFETIME|] `	if (!refcount_inc_not_zero(&share->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00091 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	return share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `static struct ksmbd_share_config *`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `__share_lookup_rcu(const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	struct ksmbd_share_config *share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	unsigned int key = share_name_hash(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	hash_for_each_possible_rcu(shares_table, share, hlist, key) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `		if (!strcmp(name, share->name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `			return share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `static int parse_veto_list(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `			   char *veto_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `			   int veto_list_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	if (!veto_list_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	while (veto_list_sz > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `		struct ksmbd_veto_pattern *p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `		size_t sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `		sz = strnlen(veto_list, veto_list_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `		if (!sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [ERROR_PATH|] `			goto skip_empty;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00122 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [MEM_BOUNDS|] `		p = kzalloc(sizeof(struct ksmbd_veto_pattern), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00124 [NONE] `		if (!p)`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00126 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `		p->pattern = kstrdup(veto_list, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		if (!p->pattern) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `			kfree(p);`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00131 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `		list_add(&p->list, &share->veto_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `skip_empty:`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `		 * Veto entries are NUL-separated. If no terminator is found`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `		 * in the remaining bytes, this is the final chunk.`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		if (sz == veto_list_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `		veto_list += sz + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `		veto_list_sz -= (sz + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `static bool ksmbd_path_has_dotdot_component(const char *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	const char *p = path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	while (*p) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `		const char *seg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `		while (*p == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `			p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `		if (!*p)`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		seg = p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		while (*p && *p != '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `			p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `		if (p - seg == 2 && seg[0] == '.' && seg[1] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `			return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `static struct ksmbd_share_config *share_config_request(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `						       const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	struct ksmbd_share_config_response *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	struct ksmbd_share_config *share = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	struct ksmbd_share_config *lookup;`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	struct unicode_map *um = work->conn->um;`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	resp = ksmbd_ipc_share_config_request(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	if (!resp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	if (resp->flags == KSMBD_SHARE_FLAG_INVALID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	if (*resp->share_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `		char *cf_resp_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		bool equal;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		size_t share_name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		share_name_len = strnlen(resp->share_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `					 KSMBD_REQ_MAX_SHARE_NAME);`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		if (share_name_len >= KSMBD_REQ_MAX_SHARE_NAME)`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `		cf_resp_name = ksmbd_casefold_sharename(um, resp->share_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `		if (IS_ERR(cf_resp_name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00201 [NONE] `		equal = !strcmp(cf_resp_name, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		kfree(cf_resp_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `		if (!equal)`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00205 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [MEM_BOUNDS|] `	share = kzalloc(sizeof(struct ksmbd_share_config), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00208 [NONE] `	if (!share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	share->flags = resp->flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [LIFETIME|] `	refcount_set(&share->refcount, 1);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00213 [NONE] `	INIT_LIST_HEAD(&share->veto_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	share->name = kstrdup(name, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	if (!share->name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `		kill_share(share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `		share = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00219 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	 * ksmbd-tools should set KSMBD_SHARE_FLAG_PIPE for IPC$.`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	 * If it is missing, force pipe mode for IPC$ so tree-connect`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	 * to IPC can proceed and we don't incorrectly require a path.`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	if (!test_share_config_flag(share, KSMBD_SHARE_FLAG_PIPE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `	    !strncasecmp(share->name, "ipc$", 4) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	    share->name[4] == '\0')`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		share->flags |= KSMBD_SHARE_FLAG_PIPE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	if (!test_share_config_flag(share, KSMBD_SHARE_FLAG_PIPE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		size_t path_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `		if (resp->payload_sz < resp->veto_list_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [ERROR_PATH|] `			goto out_bad_share;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00236 [NONE] `		path_len = resp->payload_sz - resp->veto_list_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `		if (!path_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [ERROR_PATH|] `			goto out_bad_share;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `			char *spath = ksmbd_share_config_path(resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `			if (!spath)`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [ERROR_PATH|] `				goto out_bad_share;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00245 [NONE] `			share->path = kstrndup(spath, path_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `					      KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `		if (!share->path || !share->path[0])`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [ERROR_PATH|] `			goto out_bad_share;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00250 [NONE] `		if (share->path) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `			/* Validate share path is absolute */`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `			if (share->path[0] != '/' ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `			    ksmbd_path_has_dotdot_component(share->path)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [ERROR_PATH|] `				pr_err("share %s path must be absolute without '..' components: %s\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00255 [NONE] `				       share->name, share->path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [ERROR_PATH|] `				goto out_bad_share;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00257 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `			share->path_sz = strlen(share->path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `			while (share->path_sz > 1 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `			       share->path[share->path_sz - 1] == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `				share->path[--share->path_sz] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `		share->create_mask = resp->create_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		share->directory_mask = resp->directory_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		share->force_create_mode = resp->force_create_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `		share->force_directory_mode = resp->force_directory_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		share->force_uid = resp->force_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `		share->force_gid = resp->force_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `		share->time_machine_max_size = resp->time_machine_max_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `		ret = parse_veto_list(share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `				      KSMBD_SHARE_CONFIG_VETO_LIST(resp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `				      resp->veto_list_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `		if (!ret && share->path) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `			if (__ksmbd_override_fsids(work, share)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [ERROR_PATH|] `				goto out_bad_share;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00276 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `			ret = kern_path(share->path, 0, &share->vfs_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `			ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `			if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `				ksmbd_debug(SMB, "failed to access '%s'\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `					    share->path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `				/* Avoid put_path() */`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `				kfree(share->path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `				share->path = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [ERROR_PATH|] `			goto out_bad_share;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00290 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [LOCK|] `	spin_lock(&shares_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00294 [NONE] `	lookup = __share_lookup_rcu(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	if (lookup)`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `		lookup = __get_share_config(lookup);`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	if (!lookup) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `		hash_add_rcu(shares_table, &share->hlist,`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `			     share_name_hash(name));`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `		kill_share(share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `		share = lookup;`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [LOCK|] `	spin_unlock(&shares_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00305 [ERROR_PATH|] `	goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `out_bad_share:`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	if (share) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `		kill_share(share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `		share = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	kvfree(resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	return share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] ` * ksmbd_share_config_get() - Look up a share config by name`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] ` * @work: ksmbd work context`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ` * @name: share name to look up`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [LIFETIME|] ` * Uses RCU for lock-free read-side lookup of share configs.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00323 [NONE] ` * Falls back to IPC request if the share is not cached.`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] ` * Return: share config with incremented refcount, or NULL`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `struct ksmbd_share_config *ksmbd_share_config_get(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `						  const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	struct ksmbd_share_config *share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00333 [NONE] `	share = __share_lookup_rcu(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	if (share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `		share = __get_share_config(share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `	if (share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `		return share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `	return share_config_request(work, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `bool ksmbd_share_veto_filename(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `			       const char *filename)`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `	struct ksmbd_veto_pattern *p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	list_for_each_entry(p, &share->veto_list, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `		if (match_wildcard(p->pattern, filename))`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `			return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
