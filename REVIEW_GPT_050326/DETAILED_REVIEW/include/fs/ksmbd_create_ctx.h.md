# Line-by-line Review: src/include/fs/ksmbd_create_ctx.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Create Context handler registration API for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#ifndef __KSMBD_CREATE_CTX_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#define __KSMBD_CREATE_CTX_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `struct ksmbd_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * struct ksmbd_create_ctx_handler - Create context dispatch entry`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * @tag:	Context tag string (e.g., "MxAc", "QFid", "AAPL")`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * @tag_len:	Length of tag (typically 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` * @on_request:	Called when the context appears in a CREATE request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` *		Return 0 on success, negative errno on error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` *		May be NULL if only response-side processing is needed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` * @on_response: Called to add context data to the CREATE response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` *		Return 0 on success, negative errno on error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` *		May be NULL if only request-side processing is needed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` * @owner:	Module owning this handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` * @list:	Linked list linkage`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [LIFETIME|] ` * @rcu:	RCU callback for safe removal`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00033 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [LIFETIME|] ` * Each registered handler is stored in an RCU-protected linked list`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00035 [NONE] ` * (there are only ~15 create contexts, so a hash table is overkill).`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [LIFETIME|] ` * The dispatch path looks up handlers under rcu_read_lock and takes`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00037 [NONE] ` * a module reference before invoking the callback.`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `struct ksmbd_create_ctx_handler {`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	const char	*tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	size_t		tag_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	int (*on_request)(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `			  struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `			  const void *ctx_data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `			  unsigned int ctx_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	int (*on_response)(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `			   struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `			   void *rsp_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `			   unsigned int max_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `			   unsigned int *rsp_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	struct module	*owner;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	struct list_head list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [LIFETIME|] `	struct rcu_head	rcu;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00054 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` * ksmbd_register_create_context() - Register a create context handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ` * @h: handler descriptor (caller must keep alive until unregistered)`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [LIFETIME|] ` * Adds the handler to the RCU-protected dispatch list.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00061 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `int ksmbd_register_create_context(struct ksmbd_create_ctx_handler *h);`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` * ksmbd_unregister_create_context() - Unregister a create context handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` * @h: handler descriptor previously passed to ksmbd_register_create_context()`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [LIFETIME|] ` * Removes the handler and waits for an RCU grace period so that`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00071 [NONE] ` * in-flight lookups complete safely.`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `void ksmbd_unregister_create_context(struct ksmbd_create_ctx_handler *h);`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * ksmbd_find_create_context() - Look up a create context handler by tag`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` * @tag:	Context tag to search for`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` * @tag_len:	Length of the tag`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [LIFETIME|] ` * Performs an RCU-protected list lookup and takes a module reference`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00081 [NONE] ` * on the owning module if a match is found.  The caller must call`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` * ksmbd_put_create_context() when done with the handler.`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ` * Return: Pointer to the handler on success, NULL if not found`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `struct ksmbd_create_ctx_handler *ksmbd_find_create_context(const char *tag,`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `							   size_t tag_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` * ksmbd_put_create_context() - Release a create context handler reference`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * @h: handler previously returned by ksmbd_find_create_context()`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * Drops the module reference acquired by ksmbd_find_create_context().`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `void ksmbd_put_create_context(struct ksmbd_create_ctx_handler *h);`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ` * ksmbd_create_ctx_init() - Initialize create context dispatch list`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ` * Registers all built-in create context handlers.  Must be called`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ` * during module initialization.`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `int ksmbd_create_ctx_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` * ksmbd_create_ctx_exit() - Tear down create context dispatch list`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` * Unregisters all handlers and cleans up.  Must be called during`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * module exit.`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `void ksmbd_create_ctx_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `#endif /* __KSMBD_CREATE_CTX_H */`
  Review: Low-risk line; verify in surrounding control flow.
