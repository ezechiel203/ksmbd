# Line-by-line Review: src/fs/ksmbd_create_ctx.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Create Context handler registration table for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [LIFETIME|] ` *   Provides an RCU-protected linked list for SMB2 Create Context`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00009 [NONE] ` *   handler registration.  Built-in handlers (MxAc, QFid) are`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   registered at module init; additional handlers can be registered`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *   by extension modules.`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *   Dispatch is wired from smb2_create.c. Built-in handlers can perform`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *   per-context validation and request-side processing.`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "ksmbd_create_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `static LIST_HEAD(create_ctx_handlers);`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `static DEFINE_SPINLOCK(create_ctx_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` * ksmbd_register_create_context() - Register a create context handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` * @h: handler descriptor`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [LIFETIME|] ` * Adds the handler to the RCU-protected list under spinlock.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00034 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` * Return: 0 on success`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `int ksmbd_register_create_context(struct ksmbd_create_ctx_handler *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [LOCK|] `	spin_lock(&create_ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00040 [NONE] `	list_add_tail_rcu(&h->list, &create_ctx_handlers);`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [LOCK|] `	spin_unlock(&create_ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00042 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * ksmbd_unregister_create_context() - Unregister a create context handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * @h: handler descriptor previously registered`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [LIFETIME|] ` * Removes the handler under spinlock and waits for an RCU grace period.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00050 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `void ksmbd_unregister_create_context(struct ksmbd_create_ctx_handler *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [LOCK|] `	spin_lock(&create_ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00054 [NONE] `	list_del_rcu(&h->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [LOCK|] `	spin_unlock(&create_ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00056 [NONE] `	synchronize_rcu();`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ` * ksmbd_find_create_context() - Look up a create context handler by tag`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ` * @tag:	Context tag to search for`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` * @tag_len:	Length of the tag`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [LIFETIME|] ` * Performs an RCU-protected list lookup and takes a module reference`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00065 [NONE] ` * on the owning module if a match is found.`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` * Return: Pointer to the handler on success, NULL if not found`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `struct ksmbd_create_ctx_handler *ksmbd_find_create_context(const char *tag,`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `							   size_t tag_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	struct ksmbd_create_ctx_handler *h;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00075 [NONE] `	list_for_each_entry_rcu(h, &create_ctx_handlers, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `		if (h->tag_len == tag_len &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `		    !memcmp(h->tag, tag, tag_len) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `		    try_module_get(h->owner)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [LIFETIME|] `			rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00080 [NONE] `			return h;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00084 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ` * ksmbd_put_create_context() - Release a create context handler reference`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * @h: handler previously returned by ksmbd_find_create_context()`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `void ksmbd_put_create_context(struct ksmbd_create_ctx_handler *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	module_put(h->owner);`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ` * ============================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ` *  Built-in Create Context handler stubs`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ` * ============================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ` *  MxAc (Query Maximal Access) and QFid (Query on Disk ID) are`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ` *  registered here for request-side validation and future response-side`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ` *  modularization.`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` * mxac_on_request() - MxAc request-side stub`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` * The MxAc request context signals that the client wants maximal`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` * access information in the response.  The actual computation`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * remains in smb2_open().`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `static int mxac_on_request(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `			   struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `			   const void *ctx_data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `			   unsigned int ctx_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	 * MxAc request data is either empty or an 8-byte timestamp`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [PROTO_GATE|] `	 * (SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00121 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	if (ctx_len != 0 && ctx_len != sizeof(__le64))`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` * mxac_on_response() - MxAc response-side stub`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ` * Placeholder for building the MxAc response context blob.`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ` * The actual response construction remains in smb2_open().`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `static int mxac_on_response(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `			    struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `			    void *rsp_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `			    unsigned int max_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `			    unsigned int *rsp_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	ksmbd_debug(SMB, "MxAc create context handler (response stub)\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	*rsp_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ` * qfid_on_request() - QFid request-side stub`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` * The QFid request context signals that the client wants the on-disk`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ` * file ID in the response.  The actual computation remains in smb2_open().`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `static int qfid_on_request(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `			   struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `			   const void *ctx_data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `			   unsigned int ctx_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	/* QFid request has no payload data. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	if (ctx_len != 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ` * qfid_on_response() - QFid response-side stub`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ` * Placeholder for building the QFid response context blob.`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ` * The actual response construction remains in smb2_open().`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `static int qfid_on_response(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `			    struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `			    void *rsp_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `			    unsigned int max_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `			    unsigned int *rsp_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	ksmbd_debug(SMB, "QFid create context handler (response stub)\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	*rsp_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ` * ============================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ` *  Built-in handler table`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ` * ============================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `static struct ksmbd_create_ctx_handler builtin_create_ctx_handlers[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `		.tag		= "MxAc",`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `		.tag_len	= 4,`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		.on_request	= mxac_on_request,`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		.on_response	= mxac_on_response,`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `		.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		.tag		= "QFid",`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		.tag_len	= 4,`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		.on_request	= qfid_on_request,`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `		.on_response	= qfid_on_response,`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `		.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ` * ksmbd_create_ctx_init() - Initialize create context dispatch list`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ` * Registers all built-in create context handlers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `int ksmbd_create_ctx_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	int i, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	for (i = 0; i < ARRAY_SIZE(builtin_create_ctx_handlers); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `		ret = ksmbd_register_create_context(`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `				&builtin_create_ctx_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [ERROR_PATH|] `			pr_err("Failed to register create ctx '%.*s': %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00219 [NONE] `			       (int)builtin_create_ctx_handlers[i].tag_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `			       builtin_create_ctx_handlers[i].tag, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [ERROR_PATH|] `			goto err_unregister;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00222 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	ksmbd_debug(SMB, "Registered %zu built-in create context handlers\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `		    ARRAY_SIZE(builtin_create_ctx_handlers));`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `err_unregister:`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	while (--i >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `		ksmbd_unregister_create_context(`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `				&builtin_create_ctx_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ` * ksmbd_create_ctx_exit() - Unregister all create context handlers`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `void ksmbd_create_ctx_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	for (i = 0; i < ARRAY_SIZE(builtin_create_ctx_handlers); i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `		ksmbd_unregister_create_context(`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `				&builtin_create_ctx_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
