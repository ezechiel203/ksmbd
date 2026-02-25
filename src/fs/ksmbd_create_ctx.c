// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Create Context handler registration table for ksmbd
 *
 *   Provides an RCU-protected linked list for SMB2 Create Context
 *   handler registration.  Built-in handlers (MxAc, QFid) are
 *   registered at module init; additional handlers can be registered
 *   by extension modules.
 *
 *   Dispatch is wired from smb2_create.c. Built-in handlers can perform
 *   per-context validation and request-side processing.
 */

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/string.h>

#include "ksmbd_create_ctx.h"
#include "glob.h"

static LIST_HEAD(create_ctx_handlers);
static DEFINE_SPINLOCK(create_ctx_lock);

/**
 * ksmbd_register_create_context() - Register a create context handler
 * @h: handler descriptor
 *
 * Adds the handler to the RCU-protected list under spinlock.
 *
 * Return: 0 on success
 */
int ksmbd_register_create_context(struct ksmbd_create_ctx_handler *h)
{
	spin_lock(&create_ctx_lock);
	list_add_tail_rcu(&h->list, &create_ctx_handlers);
	spin_unlock(&create_ctx_lock);
	return 0;
}

/**
 * ksmbd_unregister_create_context() - Unregister a create context handler
 * @h: handler descriptor previously registered
 *
 * Removes the handler under spinlock and waits for an RCU grace period.
 */
void ksmbd_unregister_create_context(struct ksmbd_create_ctx_handler *h)
{
	spin_lock(&create_ctx_lock);
	list_del_rcu(&h->list);
	spin_unlock(&create_ctx_lock);
	synchronize_rcu();
}

/**
 * ksmbd_find_create_context() - Look up a create context handler by tag
 * @tag:	Context tag to search for
 * @tag_len:	Length of the tag
 *
 * Performs an RCU-protected list lookup and takes a module reference
 * on the owning module if a match is found.
 *
 * Return: Pointer to the handler on success, NULL if not found
 */
struct ksmbd_create_ctx_handler *ksmbd_find_create_context(const char *tag,
							   size_t tag_len)
{
	struct ksmbd_create_ctx_handler *h;

	rcu_read_lock();
	list_for_each_entry_rcu(h, &create_ctx_handlers, list) {
		if (h->tag_len == tag_len &&
		    !memcmp(h->tag, tag, tag_len) &&
		    try_module_get(h->owner)) {
			rcu_read_unlock();
			return h;
		}
	}
	rcu_read_unlock();
	return NULL;
}

/**
 * ksmbd_put_create_context() - Release a create context handler reference
 * @h: handler previously returned by ksmbd_find_create_context()
 */
void ksmbd_put_create_context(struct ksmbd_create_ctx_handler *h)
{
	module_put(h->owner);
}

/*
 * ============================================================
 *  Built-in Create Context handler stubs
 * ============================================================
 *
 *  MxAc (Query Maximal Access) and QFid (Query on Disk ID) are
 *  registered here for request-side validation and future response-side
 *  modularization.
 */

/**
 * mxac_on_request() - MxAc request-side stub
 *
 * The MxAc request context signals that the client wants maximal
 * access information in the response.  The actual computation
 * remains in smb2_open().
 */
static int mxac_on_request(struct ksmbd_work *work,
			   struct ksmbd_file *fp,
			   const void *ctx_data,
			   unsigned int ctx_len)
{
	/*
	 * MxAc request data is either empty or an 8-byte timestamp
	 * (SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST).
	 */
	if (ctx_len != 0 && ctx_len != sizeof(__le64))
		return -EINVAL;

	return 0;
}

/**
 * mxac_on_response() - MxAc response-side stub
 *
 * Placeholder for building the MxAc response context blob.
 * The actual response construction remains in smb2_open().
 */
static int mxac_on_response(struct ksmbd_work *work,
			    struct ksmbd_file *fp,
			    void *rsp_buf,
			    unsigned int max_len,
			    unsigned int *rsp_len)
{
	ksmbd_debug(SMB, "MxAc create context handler (response stub)\n");
	*rsp_len = 0;
	return 0;
}

/**
 * qfid_on_request() - QFid request-side stub
 *
 * The QFid request context signals that the client wants the on-disk
 * file ID in the response.  The actual computation remains in smb2_open().
 */
static int qfid_on_request(struct ksmbd_work *work,
			   struct ksmbd_file *fp,
			   const void *ctx_data,
			   unsigned int ctx_len)
{
	/* QFid request has no payload data. */
	if (ctx_len != 0)
		return -EINVAL;

	return 0;
}

/**
 * qfid_on_response() - QFid response-side stub
 *
 * Placeholder for building the QFid response context blob.
 * The actual response construction remains in smb2_open().
 */
static int qfid_on_response(struct ksmbd_work *work,
			    struct ksmbd_file *fp,
			    void *rsp_buf,
			    unsigned int max_len,
			    unsigned int *rsp_len)
{
	ksmbd_debug(SMB, "QFid create context handler (response stub)\n");
	*rsp_len = 0;
	return 0;
}

/*
 * ============================================================
 *  Built-in handler table
 * ============================================================
 */

static struct ksmbd_create_ctx_handler builtin_create_ctx_handlers[] = {
	{
		.tag		= "MxAc",
		.tag_len	= 4,
		.on_request	= mxac_on_request,
		.on_response	= mxac_on_response,
		.owner		= THIS_MODULE,
	},
	{
		.tag		= "QFid",
		.tag_len	= 4,
		.on_request	= qfid_on_request,
		.on_response	= qfid_on_response,
		.owner		= THIS_MODULE,
	},
};

/**
 * ksmbd_create_ctx_init() - Initialize create context dispatch list
 *
 * Registers all built-in create context handlers.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_create_ctx_init(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(builtin_create_ctx_handlers); i++) {
		ret = ksmbd_register_create_context(
				&builtin_create_ctx_handlers[i]);
		if (ret) {
			pr_err("Failed to register create ctx '%.*s': %d\n",
			       (int)builtin_create_ctx_handlers[i].tag_len,
			       builtin_create_ctx_handlers[i].tag, ret);
			goto err_unregister;
		}
	}

	ksmbd_debug(SMB, "Registered %zu built-in create context handlers\n",
		    ARRAY_SIZE(builtin_create_ctx_handlers));
	return 0;

err_unregister:
	while (--i >= 0)
		ksmbd_unregister_create_context(
				&builtin_create_ctx_handlers[i]);
	return ret;
}

/**
 * ksmbd_create_ctx_exit() - Unregister all create context handlers
 */
void ksmbd_create_ctx_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(builtin_create_ctx_handlers); i++)
		ksmbd_unregister_create_context(
				&builtin_create_ctx_handlers[i]);
}
