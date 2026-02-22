// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Info-level handler registration table for ksmbd
 *
 *   Provides an RCU-protected hash table for dispatching SMB2 QUERY_INFO
 *   and SET_INFO requests, keyed on (info_type, info_class, op).
 *
 *   TODO: Incrementally migrate info-level handlers from the monolithic
 *   switch statements in smb2pdu.c:
 *     - smb2_get_info_file()      (~15 info classes)
 *     - smb2_set_info_file()      (~5 info classes)
 *     - smb2_get_info_filesystem() (~10 info classes)
 *   Each case can be extracted into a standalone handler and registered
 *   here without changing external behavior.
 */

#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/module.h>

#include "ksmbd_info.h"
#include "glob.h"

/* 256 buckets (2^8) -- sufficient for all SMB2 info classes */
#define KSMBD_INFO_HASH_BITS	8

static DEFINE_HASHTABLE(info_handlers, KSMBD_INFO_HASH_BITS);
static DEFINE_SPINLOCK(info_lock);

/**
 * info_hash_key() - compute hash key from info type, class, and operation
 * @info_type:  SMB2 info type (FILE, FILESYSTEM, SECURITY, QUOTA)
 * @info_class: info class within the type
 * @op:         GET or SET operation
 *
 * Return: composite 32-bit hash key
 */
static inline u32 info_hash_key(u8 info_type, u8 info_class,
				enum ksmbd_info_op op)
{
	return (u32)info_type << 16 | (u32)info_class << 8 | (u32)op;
}

/**
 * ksmbd_register_info_handler() - Register an info-level handler
 * @h: handler descriptor (caller must keep alive until unregistered)
 *
 * Adds the handler to the hash table under spinlock using hash_add_rcu.
 * Checks for duplicates before insertion.
 *
 * Return: 0 on success, -EEXIST if (info_type, info_class, op) already
 *         registered
 */
int ksmbd_register_info_handler(struct ksmbd_info_handler *h)
{
	struct ksmbd_info_handler *cur;
	u32 key = info_hash_key(h->info_type, h->info_class, h->op);

	spin_lock(&info_lock);
	hash_for_each_possible_rcu(info_handlers, cur, node, key) {
		if (cur->info_type == h->info_type &&
		    cur->info_class == h->info_class &&
		    cur->op == h->op) {
			spin_unlock(&info_lock);
			pr_err("Info handler (type=%u, class=%u, op=%d) already registered\n",
			       h->info_type, h->info_class, h->op);
			return -EEXIST;
		}
	}
	hash_add_rcu(info_handlers, &h->node, key);
	spin_unlock(&info_lock);
	return 0;
}

/**
 * ksmbd_unregister_info_handler() - Unregister an info-level handler
 * @h: handler descriptor previously registered
 *
 * Removes the handler under spinlock and waits for an RCU grace period
 * so that in-flight lookups complete safely.
 */
void ksmbd_unregister_info_handler(struct ksmbd_info_handler *h)
{
	spin_lock(&info_lock);
	hash_del_rcu(&h->node);
	spin_unlock(&info_lock);
	synchronize_rcu();
}

/**
 * ksmbd_dispatch_info() - Look up and invoke a registered info handler
 * @work:       smb work for this request
 * @fp:         ksmbd file pointer (may be NULL for filesystem-level queries)
 * @info_type:  SMB2 info type
 * @info_class: info class within the type
 * @op:         GET or SET operation
 * @buf:        pointer to data buffer (response buffer for GET, request
 *              buffer for SET)
 * @buf_len:    buffer length
 * @out_len:    [out] number of bytes written (GET) or consumed (SET)
 *
 * Performs an RCU-protected hash lookup, takes a module reference on the
 * owning module, and invokes the handler callback.
 *
 * Return: 0 on success, handler errno on failure, -EOPNOTSUPP if no
 *         handler is registered for the given key.
 */
int ksmbd_dispatch_info(struct ksmbd_work *work,
			struct ksmbd_file *fp,
			u8 info_type, u8 info_class,
			enum ksmbd_info_op op,
			void *buf, unsigned int buf_len,
			unsigned int *out_len)
{
	struct ksmbd_info_handler *h;
	u32 key = info_hash_key(info_type, info_class, op);
	int ret = -EOPNOTSUPP;

	*out_len = 0;

	rcu_read_lock();
	hash_for_each_possible_rcu(info_handlers, h, node, key) {
		if (h->info_type != info_type ||
		    h->info_class != info_class ||
		    h->op != op)
			continue;

		if (!try_module_get(h->owner)) {
			rcu_read_unlock();
			return -ENODEV;
		}
		rcu_read_unlock();

		ret = h->handler(work, fp, buf, buf_len, out_len);
		module_put(h->owner);
		return ret;
	}
	rcu_read_unlock();

	return ret;
}

/**
 * ksmbd_info_init() - Initialize the info-level dispatch table
 *
 * Currently empty -- no handlers are migrated yet.  The hash table is
 * statically initialized via DEFINE_HASHTABLE.  Infrastructure is ready
 * for incremental migration from the monolithic switch statements in
 * smb2pdu.c.
 *
 * TODO: Register built-in handlers here as they are extracted from:
 *   - smb2_get_info_file()       (smb2pdu.c)
 *   - smb2_set_info_file()       (smb2pdu.c)
 *   - smb2_get_info_filesystem() (smb2pdu.c)
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_info_init(void)
{
	hash_init(info_handlers);
	ksmbd_debug(SMB, "Info-level handler table initialized\n");
	return 0;
}

/**
 * ksmbd_info_exit() - Tear down the info-level dispatch table
 *
 * Currently empty -- no handlers registered yet.
 *
 * TODO: Unregister all built-in handlers here once they are migrated.
 */
void ksmbd_info_exit(void)
{
}
