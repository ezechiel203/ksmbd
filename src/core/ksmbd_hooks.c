// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Netfilter-inspired hook system for ksmbd
 *
 *   Provides a zero-cost hook infrastructure for intercepting SMB
 *   operations.  Hook lists are RCU-protected so that the dispatch
 *   path (hot path) never acquires a lock.  A static key ensures
 *   that when no hooks are registered, the overhead is effectively
 *   zero on modern CPUs.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#include "glob.h"
#include "ksmbd_hooks.h"
#include "ksmbd_work.h"

/* Static key: false (off) by default, enabled when first hook registers */
DEFINE_STATIC_KEY_FALSE(ksmbd_hooks_active);

/* Per-hook-point list heads */
static struct list_head hook_chains[__KSMBD_HOOK_MAX];

/* Mutex protecting hook list mutations (register/unregister) */
static DEFINE_MUTEX(hooks_mutex);

/* Total number of registered hooks across all hook points */
static unsigned int hooks_count;

/**
 * ksmbd_hooks_init() - Initialize the hook subsystem
 *
 * Initializes per-hook-point list heads.  Must be called once during
 * module initialization before any hook registration.
 *
 * Return: 0 (always succeeds)
 */
int ksmbd_hooks_init(void)
{
	int i;

	for (i = 0; i < __KSMBD_HOOK_MAX; i++)
		INIT_LIST_HEAD(&hook_chains[i]);

	hooks_count = 0;
	pr_info("ksmbd: hook subsystem initialized (%d hook points)\n",
		__KSMBD_HOOK_MAX);
	return 0;
}

/**
 * ksmbd_hooks_exit() - Tear down the hook subsystem
 *
 * Removes all registered hooks and disables the static key if it
 * was enabled.  Waits for an RCU grace period to ensure no readers
 * reference freed handlers.  Must be called during module exit.
 */
void ksmbd_hooks_exit(void)
{
	struct ksmbd_hook_handler *handler, *tmp;
	int i;

	mutex_lock(&hooks_mutex);
	for (i = 0; i < __KSMBD_HOOK_MAX; i++) {
		list_for_each_entry_safe(handler, tmp, &hook_chains[i],
					 list) {
			list_del_rcu(&handler->list);
			hooks_count--;
		}
	}

	if (static_key_enabled(&ksmbd_hooks_active.key))
		static_branch_disable(&ksmbd_hooks_active);

	mutex_unlock(&hooks_mutex);

	/* Wait for any in-flight RCU readers to finish */
	synchronize_rcu();
}

/**
 * ksmbd_register_hook() - Register a hook handler at a given hook point
 * @handler: Fully initialized hook handler descriptor.  The caller
 *           must set @point, @priority, @hook_fn, @priv, and @owner.
 *
 * The handler is inserted into the per-hook-point list sorted by
 * priority (ascending: lower value = called first).  RCU is used to
 * protect readers so that hook dispatch never blocks.
 *
 * The global static key is enabled when the first handler is registered,
 * ensuring zero overhead when no hooks exist.
 *
 * Return: 0 on success, -EINVAL for bad parameters
 */
int ksmbd_register_hook(struct ksmbd_hook_handler *handler)
{
	struct ksmbd_hook_handler *pos;
	struct list_head *head;

	if (!handler || !handler->hook_fn)
		return -EINVAL;

	if (handler->point < 0 || handler->point >= __KSMBD_HOOK_MAX)
		return -EINVAL;

	mutex_lock(&hooks_mutex);

	head = &hook_chains[handler->point];

	/*
	 * Insert in priority order: walk the list and insert before
	 * the first entry with a higher (numerically larger) priority.
	 */
	list_for_each_entry(pos, head, list) {
		if (pos->priority > handler->priority) {
			list_add_tail_rcu(&handler->list, &pos->list);
			goto inserted;
		}
	}

	/* Highest priority value (or empty list): append at tail */
	list_add_tail_rcu(&handler->list, head);

inserted:
	hooks_count++;

	/* Enable the static key when first hook is registered */
	if (hooks_count == 1)
		static_branch_enable(&ksmbd_hooks_active);

	mutex_unlock(&hooks_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(ksmbd_register_hook);

/**
 * ksmbd_unregister_hook() - Unregister a previously registered hook handler
 * @handler: The hook handler to remove from its hook chain.
 *
 * Removes the handler from the RCU-protected list and waits for an
 * RCU grace period before returning, so the caller can safely free
 * or reuse the handler after this function returns.
 *
 * The global static key is disabled when the last handler is removed.
 */
void ksmbd_unregister_hook(struct ksmbd_hook_handler *handler)
{
	if (!handler)
		return;

	mutex_lock(&hooks_mutex);

	list_del_rcu(&handler->list);

	WARN_ON_ONCE(hooks_count == 0);
	if (hooks_count > 0)
		hooks_count--;

	/* Disable the static key when last hook is removed */
	if (hooks_count == 0 &&
	    static_key_enabled(&ksmbd_hooks_active.key))
		static_branch_disable(&ksmbd_hooks_active);

	mutex_unlock(&hooks_mutex);

	/* Ensure no in-flight RCU readers reference this handler */
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(ksmbd_unregister_hook);

/**
 * __ksmbd_run_hooks() - Iterate and invoke all hooks for a given hook point
 * @point: The hook point to dispatch
 * @work:  The ksmbd_work context for the current SMB request
 *
 * Walks the priority-sorted hook chain under RCU read-side protection.
 * For each registered handler, acquires a module reference (to prevent
 * the owning module from being unloaded mid-callback), invokes the
 * callback, and releases the reference.
 *
 * Processing stops early if a callback returns %KSMBD_HOOK_STOP or
 * %KSMBD_HOOK_DROP.
 *
 * Return: %KSMBD_HOOK_CONTINUE if all handlers allow continuation,
 *         %KSMBD_HOOK_STOP if a handler consumed the request, or
 *         %KSMBD_HOOK_DROP if a handler requests the request be dropped
 */
int __ksmbd_run_hooks(enum ksmbd_hook_point point, struct ksmbd_work *work)
{
	struct ksmbd_hook_handler *handler;
	int ret = KSMBD_HOOK_CONTINUE;

	if (point < 0 || point >= __KSMBD_HOOK_MAX)
		return KSMBD_HOOK_CONTINUE;

	rcu_read_lock();
	list_for_each_entry_rcu(handler, &hook_chains[point], list) {
		if (!try_module_get(handler->owner))
			continue;

		ret = handler->hook_fn(work, handler->priv);

		module_put(handler->owner);

		if (ret != KSMBD_HOOK_CONTINUE)
			break;
	}
	rcu_read_unlock();

	return ret;
}
