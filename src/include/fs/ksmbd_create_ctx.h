/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Create Context handler registration API for ksmbd
 */

#ifndef __KSMBD_CREATE_CTX_H
#define __KSMBD_CREATE_CTX_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/rcupdate.h>

struct ksmbd_work;
struct ksmbd_file;

/**
 * struct ksmbd_create_ctx_handler - Create context dispatch entry
 * @tag:	Context tag string (e.g., "MxAc", "QFid", "AAPL")
 * @tag_len:	Length of tag (typically 4)
 * @on_request:	Called when the context appears in a CREATE request.
 *		Return 0 on success, negative errno on error.
 *		May be NULL if only response-side processing is needed.
 * @on_response: Called to add context data to the CREATE response.
 *		Return 0 on success, negative errno on error.
 *		May be NULL if only request-side processing is needed.
 * @owner:	Module owning this handler
 * @list:	Linked list linkage
 * @rcu:	RCU callback for safe removal
 *
 * Each registered handler is stored in an RCU-protected linked list
 * (there are only ~15 create contexts, so a hash table is overkill).
 * The dispatch path looks up handlers under rcu_read_lock and takes
 * a module reference before invoking the callback.
 */
struct ksmbd_create_ctx_handler {
	const char	*tag;
	size_t		tag_len;
	int (*on_request)(struct ksmbd_work *work,
			  struct ksmbd_file *fp,
			  const void *ctx_data,
			  unsigned int ctx_len);
	int (*on_response)(struct ksmbd_work *work,
			   struct ksmbd_file *fp,
			   void *rsp_buf,
			   unsigned int max_len,
			   unsigned int *rsp_len);
	struct module	*owner;
	struct list_head list;
	struct rcu_head	rcu;
};

/**
 * ksmbd_register_create_context() - Register a create context handler
 * @h: handler descriptor (caller must keep alive until unregistered)
 *
 * Adds the handler to the RCU-protected dispatch list.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_register_create_context(struct ksmbd_create_ctx_handler *h);

/**
 * ksmbd_unregister_create_context() - Unregister a create context handler
 * @h: handler descriptor previously passed to ksmbd_register_create_context()
 *
 * Removes the handler and waits for an RCU grace period so that
 * in-flight lookups complete safely.
 */
void ksmbd_unregister_create_context(struct ksmbd_create_ctx_handler *h);

/**
 * ksmbd_find_create_context() - Look up a create context handler by tag
 * @tag:	Context tag to search for
 * @tag_len:	Length of the tag
 *
 * Performs an RCU-protected list lookup and takes a module reference
 * on the owning module if a match is found.  The caller must call
 * ksmbd_put_create_context() when done with the handler.
 *
 * Return: Pointer to the handler on success, NULL if not found
 */
struct ksmbd_create_ctx_handler *ksmbd_find_create_context(const char *tag,
							   size_t tag_len);

/**
 * ksmbd_put_create_context() - Release a create context handler reference
 * @h: handler previously returned by ksmbd_find_create_context()
 *
 * Drops the module reference acquired by ksmbd_find_create_context().
 */
void ksmbd_put_create_context(struct ksmbd_create_ctx_handler *h);

/**
 * ksmbd_create_ctx_init() - Initialize create context dispatch list
 *
 * Registers all built-in create context handlers.  Must be called
 * during module initialization.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_create_ctx_init(void);

/**
 * ksmbd_create_ctx_exit() - Tear down create context dispatch list
 *
 * Unregisters all handlers and cleans up.  Must be called during
 * module exit.
 */
void ksmbd_create_ctx_exit(void);

#endif /* __KSMBD_CREATE_CTX_H */
