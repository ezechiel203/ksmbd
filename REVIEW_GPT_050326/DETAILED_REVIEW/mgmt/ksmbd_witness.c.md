# Line-by-line Review: src/mgmt/ksmbd_witness.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2024 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   Witness Protocol (MS-SWN) kernel-side state management.`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   See ksmbd_witness.h for the design overview.`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/rwsem.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/idr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/netdevice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/inetdevice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/inet.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <net/addrconf.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "ksmbd_witness.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `/* Global resource list, protected by witness_lock (read-write semaphore) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `static LIST_HEAD(witness_resources);`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `static DECLARE_RWSEM(witness_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `/* Global registration list for fast lookup by reg_id */`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `static LIST_HEAD(witness_registrations);`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `static DEFINE_SPINLOCK(witness_reg_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `/* IDA for unique registration IDs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `static DEFINE_IDA(witness_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `/* Limit the number of concurrent witness registrations to prevent resource exhaustion */`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#define KSMBD_MAX_WITNESS_REGISTRATIONS		256`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#define KSMBD_MAX_WITNESS_REGS_PER_SESSION	64`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [LIFETIME|] `static atomic_t witness_reg_count = ATOMIC_INIT(0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `/* Network device notifier for link state changes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `static struct notifier_block witness_netdev_nb;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `static struct workqueue_struct *witness_notify_wq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * Work item for deferring netlink notifications out of atomic context.`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * The netdevice notifier callback runs in atomic context, so we queue`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * the actual notification work.`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `struct witness_notify_work {`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	struct work_struct	work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	char			resource_name[KSMBD_WITNESS_NAME_MAX];`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	unsigned int		new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `/* Resource management                                                 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `static struct ksmbd_witness_resource *`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `__witness_resource_lookup_locked(const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	struct ksmbd_witness_resource *res;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	list_for_each_entry(res, &witness_resources, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `		if (!strncmp(res->name, name, KSMBD_WITNESS_NAME_MAX))`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `			return res;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` * ksmbd_witness_resource_add() - add a new monitored resource`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` * @name: resource name (IP address string, share name, or node name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * @type: resource type (KSMBD_WITNESS_RESOURCE_*)`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * Return: pointer to new resource, or ERR_PTR on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` *         Returns -EEXIST if resource already tracked.`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `struct ksmbd_witness_resource *`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `ksmbd_witness_resource_add(const char *name, unsigned int type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	struct ksmbd_witness_resource *res;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	if (!name || !name[0])`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `		return ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [LOCK|] `	down_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00088 [NONE] `	if (__witness_resource_lookup_locked(name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [LOCK|] `		up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00090 [NONE] `		return ERR_PTR(-EEXIST);`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [MEM_BOUNDS|] `	res = kzalloc(sizeof(*res), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00094 [NONE] `	if (!res) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [LOCK|] `		up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00096 [NONE] `		return ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	res->type = type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	res->state = KSMBD_WITNESS_STATE_UNKNOWN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [MEM_BOUNDS|] `	strscpy(res->name, name, KSMBD_WITNESS_NAME_MAX);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00102 [NONE] `	INIT_LIST_HEAD(&res->subscribers);`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	spin_lock_init(&res->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	list_add_tail(&res->list, &witness_resources);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [LOCK|] `	up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	ksmbd_debug(IPC, "witness: resource added: %s type=%u\n", name, type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	return res;`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` * ksmbd_witness_resource_del() - remove a monitored resource`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` * @name: resource name`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ` * Removes the resource and unlinks (but does not free) any`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ` * registrations still attached.  The registrations remain in the`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` * global list so they can be cleaned up by the caller.`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `void ksmbd_witness_resource_del(const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	struct ksmbd_witness_resource *res;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	struct ksmbd_witness_registration *reg, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [LOCK|] `	down_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00125 [NONE] `	res = __witness_resource_lookup_locked(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	if (!res) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [LOCK|] `		up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00128 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	/* Detach all subscriber registrations from this resource */`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [LOCK|] `	spin_lock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00133 [NONE] `	list_for_each_entry_safe(reg, tmp, &res->subscribers, list)`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `		list_del_init(&reg->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [LOCK|] `	spin_unlock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	list_del(&res->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [LOCK|] `	up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00139 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	ksmbd_debug(IPC, "witness: resource removed: %s\n", name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	kfree(res);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ` * ksmbd_witness_resource_lookup() - check whether a resource exists`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ` * @name: resource name`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` * Returns true/false rather than a raw pointer so that callers`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ` * cannot accidentally dereference a stale, unrefcounted pointer.`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ` * The check is serialised under witness_lock (read side) so the`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ` * result is only a point-in-time snapshot.`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ` * Return: true if a resource with @name exists, false otherwise.`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `bool ksmbd_witness_resource_lookup(const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	bool found;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [LOCK|] `	down_read(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00160 [NONE] `	found = __witness_resource_lookup_locked(name) != NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	up_read(&witness_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	return found;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `/* Registration management                                             */`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] ` * ksmbd_witness_register() - register a client for notifications`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ` * @client_name: the client computer name`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ` * @resource_name: the resource being monitored`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ` * @type: resource type (KSMBD_WITNESS_RESOURCE_*)`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ` * @reg_id_out: on success, filled with the unique registration ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ` * If the named resource does not yet exist, it is created`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ` * automatically with UNKNOWN state.`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `int ksmbd_witness_register(const char *client_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `			   const char *resource_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `			   unsigned int type,`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `			   u64 session_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `			   u32 *reg_id_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	struct ksmbd_witness_registration *reg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	struct ksmbd_witness_resource *res;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	int id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	if (!client_name || !resource_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	/* Enforce per-session registration limit to prevent resource exhaustion */`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	if (session_id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		struct ksmbd_witness_registration *r;`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		int sess_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [LOCK|] `		spin_lock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00200 [NONE] `		list_for_each_entry(r, &witness_registrations, global_list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `			if (r->session_id == session_id &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `			    ++sess_count >= KSMBD_MAX_WITNESS_REGS_PER_SESSION) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [LOCK|] `				spin_unlock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00204 [ERROR_PATH|] `				pr_warn_ratelimited("witness: session %llu exceeded max registrations (%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00205 [NONE] `						    session_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `						    KSMBD_MAX_WITNESS_REGS_PER_SESSION);`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [ERROR_PATH|] `				return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00208 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [LOCK|] `		spin_unlock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00211 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [LIFETIME|] `	if (atomic_inc_return(&witness_reg_count) > KSMBD_MAX_WITNESS_REGISTRATIONS) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00214 [LIFETIME|] `		atomic_dec(&witness_reg_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00215 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00216 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [MEM_BOUNDS|] `	reg = kzalloc(sizeof(*reg), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00219 [NONE] `	if (!reg) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [LIFETIME|] `		atomic_dec(&witness_reg_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00221 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00222 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	id = ida_alloc_min(&witness_ida, 1, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	if (id < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `		kfree(reg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [LIFETIME|] `		atomic_dec(&witness_reg_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00228 [NONE] `		return id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	reg->reg_id = (u32)id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	reg->type = type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	reg->session_id = session_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [MEM_BOUNDS|] `	strscpy(reg->client_name, client_name, KSMBD_WITNESS_NAME_MAX);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00235 [MEM_BOUNDS|] `	strscpy(reg->resource_name, resource_name, KSMBD_WITNESS_NAME_MAX);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00236 [NONE] `	INIT_LIST_HEAD(&reg->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	INIT_LIST_HEAD(&reg->global_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	/* Look up or auto-create the resource */`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [LOCK|] `	down_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00241 [NONE] `	res = __witness_resource_lookup_locked(resource_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	if (!res) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [LOCK|] `		up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00244 [NONE] `		res = ksmbd_witness_resource_add(resource_name, type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		if (IS_ERR(res)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `			 * EEXIST means a concurrent add raced with us.`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `			 * Re-lookup under the lock.`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `			if (PTR_ERR(res) != -EEXIST) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `				ida_free(&witness_ida, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `				kfree(reg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [LIFETIME|] `				atomic_dec(&witness_reg_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00254 [NONE] `				return PTR_ERR(res);`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [LOCK|] `			down_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00257 [NONE] `			res = __witness_resource_lookup_locked(resource_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `			if (!res) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [LOCK|] `				up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00260 [NONE] `				ida_free(&witness_ida, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `				kfree(reg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [LIFETIME|] `				atomic_dec(&witness_reg_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00263 [ERROR_PATH|] `				return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00264 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [LOCK|] `			down_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00267 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	/* Attach registration to resource subscriber list */`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [LOCK|] `	spin_lock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00272 [NONE] `	list_add_tail(&reg->list, &res->subscribers);`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [LOCK|] `	spin_unlock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00274 [LOCK|] `	up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00275 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	/* Also add to global registration list */`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [LOCK|] `	spin_lock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00278 [NONE] `	list_add_tail(&reg->global_list, &witness_registrations);`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [LOCK|] `	spin_unlock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00280 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `	*reg_id_out = reg->reg_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	ksmbd_debug(IPC, "witness: registered client=%s resource=%s id=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `		    client_name, resource_name, reg->reg_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] ` * ksmbd_witness_unregister() - unregister a client`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] ` * @reg_id: the registration ID from ksmbd_witness_register()`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ` * Return: 0 on success, -ENOENT if not found.`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `int ksmbd_witness_unregister(u32 reg_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	struct ksmbd_witness_registration *reg, *found = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [LOCK|] `	spin_lock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00298 [NONE] `	list_for_each_entry(reg, &witness_registrations, global_list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `		if (reg->reg_id == reg_id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `			found = reg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `			list_del_init(&found->global_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [LOCK|] `	spin_unlock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `	if (!found)`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	 * Remove from the resource subscriber list.  The list_del_init`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	 * in resource_del may have already detached us, which is fine`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	 * because list_del on an already-initialized empty node is safe.`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [LOCK|] `	down_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00316 [NONE] `	if (!list_empty(&found->list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `		struct ksmbd_witness_resource *res;`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `		res = __witness_resource_lookup_locked(found->resource_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `		if (res) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [LOCK|] `			spin_lock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00322 [NONE] `			list_del_init(&found->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [LOCK|] `			spin_unlock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00324 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [LOCK|] `	up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	ksmbd_debug(IPC, "witness: unregistered id=%u client=%s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `		    reg_id, found->client_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	ida_free(&witness_ida, found->reg_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `	kfree(found);`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [LIFETIME|] `	atomic_dec(&witness_reg_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00334 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ` * ksmbd_witness_unregister_session() - remove all registrations for a session`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ` * @session_id: the session ID whose registrations should be cleaned up`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ` * Called during session teardown to prevent leaked registrations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ` * Iterates the global registration list and removes all entries`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] ` * belonging to the given session.`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `void ksmbd_witness_unregister_session(u64 session_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	struct ksmbd_witness_registration *reg, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	LIST_HEAD(to_free);`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	if (!session_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	/* Collect matching registrations from the global list */`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [LOCK|] `	spin_lock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00355 [NONE] `	list_for_each_entry_safe(reg, tmp, &witness_registrations,`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `				 global_list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		if (reg->session_id == session_id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `			list_del_init(&reg->global_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `			list_add(&reg->global_list, &to_free);`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [LOCK|] `	spin_unlock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00363 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	/* Remove from resource subscriber lists and free */`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	list_for_each_entry_safe(reg, tmp, &to_free, global_list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [LOCK|] `		down_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00367 [NONE] `		if (!list_empty(&reg->list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `			struct ksmbd_witness_resource *res;`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `			res = __witness_resource_lookup_locked(`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `				reg->resource_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `			if (res) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [LOCK|] `				spin_lock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00374 [NONE] `				list_del_init(&reg->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [LOCK|] `				spin_unlock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00376 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [LOCK|] `		up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00379 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `		ksmbd_debug(IPC,`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `			    "witness: session cleanup id=%u client=%s sess=%llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `			    reg->reg_id, reg->client_name, session_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `		list_del(&reg->global_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `		ida_free(&witness_ida, reg->reg_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `		kfree(reg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [LIFETIME|] `		atomic_dec(&witness_reg_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00387 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] ` * ksmbd_witness_registration_count() - count active registrations`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] ` * Return: number of active registrations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `int ksmbd_witness_registration_count(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	struct ksmbd_witness_registration *reg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	int count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [LOCK|] `	spin_lock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00401 [NONE] `	list_for_each_entry(reg, &witness_registrations, global_list)`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `		count++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [LOCK|] `	spin_unlock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00404 [NONE] `	return count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `/* State change notification                                           */`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] ` * ksmbd_witness_notify_state_change() - update resource state and notify`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] ` * @resource_name: the resource whose state changed`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] ` * @new_state: the new state (KSMBD_WITNESS_STATE_*)`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] ` * Updates the resource state and sends a netlink notification to`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ` * userspace for each subscriber registration.  Userspace (ksmbd.mountd)`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] ` * will then relay this via the DCE/RPC WitnessrAsyncNotify response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] ` * The subscriber list is snapshot under spinlock, then notifications`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] ` * are sent without any lock held to avoid sleeping under spinlock`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ` * (kvzalloc with GFP_KERNEL in the IPC path).`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `int ksmbd_witness_notify_state_change(const char *resource_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `				      unsigned int new_state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	struct ksmbd_witness_resource *res;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	struct ksmbd_witness_registration *reg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	u32 *reg_ids = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	int count = 0, capacity = 0, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	/* Acquire write lock because we modify res->state */`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [LOCK|] `	down_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00437 [NONE] `	res = __witness_resource_lookup_locked(resource_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	if (!res) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [LOCK|] `		up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00440 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00441 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `	res->state = new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `	 * Snapshot the subscriber reg_ids under the spinlock so we can`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `	 * drop all locks before doing the allocating IPC sends.`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [LOCK|] `	spin_lock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00450 [NONE] `	list_for_each_entry(reg, &res->subscribers, list)`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `		capacity++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [LOCK|] `	spin_unlock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00453 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [LOCK|] `	up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00455 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	if (!capacity)`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [MEM_BOUNDS|] `	reg_ids = kvzalloc(capacity * sizeof(*reg_ids), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00460 [NONE] `	if (!reg_ids)`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	/* Re-acquire locks to snapshot the actual IDs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [LOCK|] `	down_read(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00465 [NONE] `	res = __witness_resource_lookup_locked(resource_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	if (!res) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `		up_read(&witness_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `		kvfree(reg_ids);`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00470 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [LOCK|] `	spin_lock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00473 [NONE] `	list_for_each_entry(reg, &res->subscribers, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `		if (count >= capacity)`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `		reg_ids[count++] = reg->reg_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [LOCK|] `	spin_unlock(&res->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00479 [NONE] `	up_read(&witness_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	/* Now send notifications without any lock held */`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	for (i = 0; i < count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `		ksmbd_debug(IPC,`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `			    "witness: notifying reg_id=%u resource=%s state=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `			    reg_ids[i], resource_name, new_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `		ret = ksmbd_ipc_witness_notify(reg_ids[i],`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `					       resource_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `					       new_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [ERROR_PATH|] `			pr_err("witness: failed to notify reg_id=%u: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00491 [NONE] `			       reg_ids[i], ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	kvfree(reg_ids);`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `/* Network device notifier                                             */`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `static void witness_notify_work_fn(struct work_struct *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	struct witness_notify_work *nw =`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `		container_of(work, struct witness_notify_work, work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	ksmbd_witness_notify_state_change(nw->resource_name, nw->new_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	kfree(nw);`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] ` * witness_netdev_event() - netdevice notifier callback`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] ` * Monitors NETDEV_UP and NETDEV_DOWN events to detect interface`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] ` * state changes.  The callback runs in atomic context so the actual`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] ` * notification to userspace is deferred via a workqueue.`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `static int witness_netdev_event(struct notifier_block *nb,`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `				unsigned long event, void *ptr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `	struct net_device *dev = netdev_notifier_info_to_dev(ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	struct witness_notify_work *nw;`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	struct in_device *in_dev;`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	const struct in_ifaddr *ifa;`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	unsigned int new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	if (event != NETDEV_UP && event != NETDEV_DOWN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `		return NOTIFY_DONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	new_state = (event == NETDEV_UP) ?`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `		KSMBD_WITNESS_STATE_AVAILABLE :`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `		KSMBD_WITNESS_STATE_UNAVAILABLE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	 * For each IPv4 address on this device, check whether we are`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	 * tracking it as a witness resource and, if so, queue a state`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `	 * change notification.`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00540 [NONE] `	in_dev = __in_dev_get_rcu(dev);`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	if (!in_dev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [LIFETIME|] `		rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00543 [NONE] `		return NOTIFY_DONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	in_dev_for_each_ifa_rcu(ifa, in_dev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `		char addr_str[sizeof("255.255.255.255")];`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [MEM_BOUNDS|] `		snprintf(addr_str, sizeof(addr_str), "%pI4",`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00550 [NONE] `			 &ifa->ifa_address);`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `		/* Quick check without heavy locking */`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `		if (!ksmbd_witness_resource_lookup(addr_str))`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [MEM_BOUNDS|] `		nw = kzalloc(sizeof(*nw), GFP_ATOMIC);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00557 [NONE] `		if (!nw)`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [MEM_BOUNDS|] `		strscpy(nw->resource_name, addr_str,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00561 [NONE] `			KSMBD_WITNESS_NAME_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `		nw->new_state = new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `		INIT_WORK(&nw->work, witness_notify_work_fn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `		queue_work(witness_notify_wq, &nw->work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `		ksmbd_debug(IPC,`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `			    "witness: netdev %s %s -> queued state=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `			    dev->name, addr_str, new_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00571 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `	return NOTIFY_DONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `/* Module init / exit                                                   */`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] ` * ksmbd_witness_init() - initialise the witness subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] ` * Called during ksmbd module load.`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `int ksmbd_witness_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `	witness_notify_wq = alloc_workqueue("ksmbd-witness", WQ_UNBOUND, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `	if (!witness_notify_wq)`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	witness_netdev_nb.notifier_call = witness_netdev_event;`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	register_netdevice_notifier(&witness_netdev_nb);`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `	pr_info("ksmbd: witness protocol support initialised\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] ` * ksmbd_witness_exit() - tear down the witness subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] ` * Called during ksmbd module unload.  Frees all resources and`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] ` * registrations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `void ksmbd_witness_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `	struct ksmbd_witness_registration *reg, *rtmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `	struct ksmbd_witness_resource *res, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `	unregister_netdevice_notifier(&witness_netdev_nb);`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `	if (witness_notify_wq) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		flush_workqueue(witness_notify_wq);`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `		destroy_workqueue(witness_notify_wq);`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `		witness_notify_wq = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `	/* Free all registrations */`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [LOCK|] `	spin_lock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00619 [NONE] `	list_for_each_entry_safe(reg, rtmp, &witness_registrations,`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `				 global_list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `		list_del(&reg->global_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `		ida_free(&witness_ida, reg->reg_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `		kfree(reg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [LOCK|] `	spin_unlock(&witness_reg_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00626 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	/* Free all resources */`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [LOCK|] `	down_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00629 [NONE] `	list_for_each_entry_safe(res, tmp, &witness_resources, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `		list_del(&res->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `		kfree(res);`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [LOCK|] `	up_write(&witness_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `	pr_info("ksmbd: witness protocol support removed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
