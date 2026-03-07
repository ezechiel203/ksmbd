/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Netfilter-inspired hook system for ksmbd
 *
 *   Provides a lightweight, zero-cost hook infrastructure that allows
 *   loadable modules to intercept SMB operations at well-defined
 *   hook points.  When no hooks are registered, the overhead is a
 *   single static-key branch (effectively zero cost on modern CPUs).
 */

#ifndef __KSMBD_HOOKS_H
#define __KSMBD_HOOKS_H

#include <linux/jump_label.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

struct ksmbd_work;

/**
 * enum ksmbd_hook_point - Well-defined interception points for SMB operations
 * @KSMBD_HOOK_PRE_NEGOTIATE:    Before protocol negotiation
 * @KSMBD_HOOK_POST_NEGOTIATE:   After protocol negotiation
 * @KSMBD_HOOK_PRE_SESSION_SETUP:  Before session setup
 * @KSMBD_HOOK_POST_SESSION_SETUP: After session setup
 * @KSMBD_HOOK_PRE_TREE_CONNECT:   Before tree connect
 * @KSMBD_HOOK_POST_TREE_CONNECT:  After tree connect
 * @KSMBD_HOOK_CHECK_ACCESS:       Access control check
 * @KSMBD_HOOK_PRE_CREATE:         Before file create/open
 * @KSMBD_HOOK_POST_CREATE:        After file create/open
 * @KSMBD_HOOK_PRE_READ:           Before file read
 * @KSMBD_HOOK_POST_READ:          After file read
 * @KSMBD_HOOK_PRE_WRITE:          Before file write
 * @KSMBD_HOOK_POST_WRITE:         After file write
 * @KSMBD_HOOK_PRE_CLOSE:          Before file close
 * @KSMBD_HOOK_POST_CLOSE:         After file close
 * @KSMBD_HOOK_PRE_LOCK:           Before file lock
 * @KSMBD_HOOK_POST_LOCK:          After file lock
 * @KSMBD_HOOK_READDIR_ENTRY:      Per-entry during directory enumeration
 * @KSMBD_HOOK_NOTIFY_CHANGE:      Change notification
 * @KSMBD_HOOK_CONN_INIT:          New connection established
 * @KSMBD_HOOK_CONN_CLEANUP:       Connection teardown
 * @KSMBD_HOOK_AUDIT:              Audit/logging event
 * @__KSMBD_HOOK_MAX:              Sentinel, must be last
 */
enum ksmbd_hook_point {
	KSMBD_HOOK_PRE_NEGOTIATE,
	KSMBD_HOOK_POST_NEGOTIATE,
	KSMBD_HOOK_PRE_SESSION_SETUP,
	KSMBD_HOOK_POST_SESSION_SETUP,
	KSMBD_HOOK_PRE_TREE_CONNECT,
	KSMBD_HOOK_POST_TREE_CONNECT,
	KSMBD_HOOK_CHECK_ACCESS,
	KSMBD_HOOK_PRE_CREATE,
	KSMBD_HOOK_POST_CREATE,
	KSMBD_HOOK_PRE_READ,
	KSMBD_HOOK_POST_READ,
	KSMBD_HOOK_PRE_WRITE,
	KSMBD_HOOK_POST_WRITE,
	KSMBD_HOOK_PRE_CLOSE,
	KSMBD_HOOK_POST_CLOSE,
	KSMBD_HOOK_PRE_LOCK,
	KSMBD_HOOK_POST_LOCK,
	KSMBD_HOOK_READDIR_ENTRY,
	KSMBD_HOOK_NOTIFY_CHANGE,
	KSMBD_HOOK_CONN_INIT,
	KSMBD_HOOK_CONN_CLEANUP,
	KSMBD_HOOK_AUDIT,
	__KSMBD_HOOK_MAX,
};

/* Hook callback return values */
#define KSMBD_HOOK_CONTINUE	0	/* Continue processing */
#define KSMBD_HOOK_STOP		1	/* Stop chain, use handler's result */
#define KSMBD_HOOK_DROP		2	/* Drop the request entirely */

/**
 * struct ksmbd_hook_handler - Registered hook callback descriptor
 * @list:     Linkage in per-hook-point list (priority-ordered)
 * @point:    The hook point this handler is attached to
 * @priority: Execution priority; lower value = called first
 * @hook_fn:  Callback function invoked when the hook fires
 * @priv:     Opaque private data passed to @hook_fn
 * @owner:    Module that owns this handler (for refcounting)
 *
 * Security note: The hook system is a design-time extensibility mechanism,
 * not a runtime vulnerability.  Hooks execute in kernel context with full
 * privilege and can intercept any SMB operation.  Therefore, hook handlers
 * must only be registered by trusted, signed kernel modules.  Untrusted
 * code that can register hooks has already achieved kernel-level access,
 * at which point the hook system is not the attack surface.  Module
 * signature verification (CONFIG_MODULE_SIG_FORCE) should be enabled in
 * production to prevent unauthorized module loading.
 */
struct ksmbd_hook_handler {
	struct list_head	list;
	enum ksmbd_hook_point	point;
	int			priority;
	int			(*hook_fn)(struct ksmbd_work *work,
					   void *priv);
	void			*priv;
	struct module		*owner;
};

/* Zero-cost static key: when no hooks are registered, branch is never taken */
DECLARE_STATIC_KEY_FALSE(ksmbd_hooks_active);

int __ksmbd_run_hooks(enum ksmbd_hook_point point, struct ksmbd_work *work);

/**
 * KSMBD_RUN_HOOKS - Dispatch hooks at a given hook point
 * @point:  The &enum ksmbd_hook_point to fire
 * @work:   The &struct ksmbd_work for the current request
 *
 * When no hooks are registered, the static key ensures this compiles
 * to a single NOP on architectures that support jump labels, providing
 * zero overhead in the common (no-hook) case.
 *
 * Return: %KSMBD_HOOK_CONTINUE, %KSMBD_HOOK_STOP, or %KSMBD_HOOK_DROP
 */
#define KSMBD_RUN_HOOKS(point, work) ({					\
	int __ret = KSMBD_HOOK_CONTINUE;				\
	if (static_branch_unlikely(&ksmbd_hooks_active))		\
		__ret = __ksmbd_run_hooks(point, work);			\
	__ret;								\
})

/**
 * ksmbd_hooks_init() - Initialize the hook subsystem
 *
 * Sets up per-hook-point lists and associated locks.  Must be called
 * during module initialization.
 *
 * Return: 0 on success (always succeeds)
 */
int ksmbd_hooks_init(void);

/**
 * ksmbd_hooks_exit() - Tear down the hook subsystem
 *
 * Unregisters all remaining hooks and releases resources.
 * Must be called during module exit.
 */
void ksmbd_hooks_exit(void);

/**
 * ksmbd_register_hook() - Register a hook handler
 * @handler: Pointer to a caller-allocated &struct ksmbd_hook_handler.
 *           The caller must fill in @point, @priority, @hook_fn, @priv,
 *           and @owner before calling.  The handler is inserted into
 *           the per-hook-point list sorted by @priority (ascending).
 *
 * The hook list is protected by RCU; readers (hook dispatch) do not
 * acquire any lock.  The static key is enabled when the first handler
 * is registered.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_register_hook(struct ksmbd_hook_handler *handler);

/**
 * ksmbd_unregister_hook() - Unregister a previously registered hook handler
 * @handler: Pointer to the &struct ksmbd_hook_handler to remove.
 *
 * Removes the handler from the hook chain and waits for an RCU grace
 * period to ensure no concurrent readers reference the handler.  The
 * static key is disabled when the last handler is unregistered.
 */
void ksmbd_unregister_hook(struct ksmbd_hook_handler *handler);

#endif /* __KSMBD_HOOKS_H */
