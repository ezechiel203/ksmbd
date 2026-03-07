# Line-by-line Review: src/include/core/ksmbd_hooks.h

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
- L00006 [NONE] ` *   Netfilter-inspired hook system for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   Provides a lightweight, zero-cost hook infrastructure that allows`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   loadable modules to intercept SMB operations at well-defined`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   hook points.  When no hooks are registered, the overhead is a`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *   single static-key branch (effectively zero cost on modern CPUs).`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#ifndef __KSMBD_HOOKS_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#define __KSMBD_HOOKS_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/jump_label.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` * enum ksmbd_hook_point - Well-defined interception points for SMB operations`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` * @KSMBD_HOOK_PRE_NEGOTIATE:    Before protocol negotiation`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` * @KSMBD_HOOK_POST_NEGOTIATE:   After protocol negotiation`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` * @KSMBD_HOOK_PRE_SESSION_SETUP:  Before session setup`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` * @KSMBD_HOOK_POST_SESSION_SETUP: After session setup`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` * @KSMBD_HOOK_PRE_TREE_CONNECT:   Before tree connect`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` * @KSMBD_HOOK_POST_TREE_CONNECT:  After tree connect`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` * @KSMBD_HOOK_CHECK_ACCESS:       Access control check`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` * @KSMBD_HOOK_PRE_CREATE:         Before file create/open`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` * @KSMBD_HOOK_POST_CREATE:        After file create/open`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` * @KSMBD_HOOK_PRE_READ:           Before file read`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` * @KSMBD_HOOK_POST_READ:          After file read`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * @KSMBD_HOOK_PRE_WRITE:          Before file write`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` * @KSMBD_HOOK_POST_WRITE:         After file write`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * @KSMBD_HOOK_PRE_CLOSE:          Before file close`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` * @KSMBD_HOOK_POST_CLOSE:         After file close`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * @KSMBD_HOOK_PRE_LOCK:           Before file lock`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * @KSMBD_HOOK_POST_LOCK:          After file lock`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * @KSMBD_HOOK_READDIR_ENTRY:      Per-entry during directory enumeration`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * @KSMBD_HOOK_NOTIFY_CHANGE:      Change notification`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * @KSMBD_HOOK_CONN_INIT:          New connection established`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * @KSMBD_HOOK_CONN_CLEANUP:       Connection teardown`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` * @KSMBD_HOOK_AUDIT:              Audit/logging event`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` * @__KSMBD_HOOK_MAX:              Sentinel, must be last`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `enum ksmbd_hook_point {`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	KSMBD_HOOK_PRE_NEGOTIATE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	KSMBD_HOOK_POST_NEGOTIATE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	KSMBD_HOOK_PRE_SESSION_SETUP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	KSMBD_HOOK_POST_SESSION_SETUP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	KSMBD_HOOK_PRE_TREE_CONNECT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	KSMBD_HOOK_POST_TREE_CONNECT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	KSMBD_HOOK_CHECK_ACCESS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	KSMBD_HOOK_PRE_CREATE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	KSMBD_HOOK_POST_CREATE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	KSMBD_HOOK_PRE_READ,`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	KSMBD_HOOK_POST_READ,`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	KSMBD_HOOK_PRE_WRITE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	KSMBD_HOOK_POST_WRITE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	KSMBD_HOOK_PRE_CLOSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	KSMBD_HOOK_POST_CLOSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	KSMBD_HOOK_PRE_LOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	KSMBD_HOOK_POST_LOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	KSMBD_HOOK_READDIR_ENTRY,`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	KSMBD_HOOK_NOTIFY_CHANGE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	KSMBD_HOOK_CONN_INIT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	KSMBD_HOOK_CONN_CLEANUP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	KSMBD_HOOK_AUDIT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	__KSMBD_HOOK_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `/* Hook callback return values */`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `#define KSMBD_HOOK_CONTINUE	0	/* Continue processing */`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `#define KSMBD_HOOK_STOP		1	/* Stop chain, use handler's result */`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `#define KSMBD_HOOK_DROP		2	/* Drop the request entirely */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` * struct ksmbd_hook_handler - Registered hook callback descriptor`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ` * @list:     Linkage in per-hook-point list (priority-ordered)`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ` * @point:    The hook point this handler is attached to`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ` * @priority: Execution priority; lower value = called first`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ` * @hook_fn:  Callback function invoked when the hook fires`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ` * @priv:     Opaque private data passed to @hook_fn`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * @owner:    Module that owns this handler (for refcounting)`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * Security note: The hook system is a design-time extensibility mechanism,`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` * not a runtime vulnerability.  Hooks execute in kernel context with full`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * privilege and can intercept any SMB operation.  Therefore, hook handlers`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` * must only be registered by trusted, signed kernel modules.  Untrusted`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` * code that can register hooks has already achieved kernel-level access,`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ` * at which point the hook system is not the attack surface.  Module`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ` * signature verification (CONFIG_MODULE_SIG_FORCE) should be enabled in`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ` * production to prevent unauthorized module loading.`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `struct ksmbd_hook_handler {`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	struct list_head	list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	enum ksmbd_hook_point	point;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	int			priority;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	int			(*hook_fn)(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `					   void *priv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	void			*priv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	struct module		*owner;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `/* Zero-cost static key: when no hooks are registered, branch is never taken */`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `DECLARE_STATIC_KEY_FALSE(ksmbd_hooks_active);`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `int __ksmbd_run_hooks(enum ksmbd_hook_point point, struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ` * KSMBD_RUN_HOOKS - Dispatch hooks at a given hook point`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` * @point:  The &enum ksmbd_hook_point to fire`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` * @work:   The &struct ksmbd_work for the current request`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` * When no hooks are registered, the static key ensures this compiles`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` * to a single NOP on architectures that support jump labels, providing`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` * zero overhead in the common (no-hook) case.`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ` * Return: %KSMBD_HOOK_CONTINUE, %KSMBD_HOOK_STOP, or %KSMBD_HOOK_DROP`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `#define KSMBD_RUN_HOOKS(point, work) ({					\`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	int __ret = KSMBD_HOOK_CONTINUE;				\`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	if (static_branch_unlikely(&ksmbd_hooks_active))		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `		__ret = __ksmbd_run_hooks(point, work);			\`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	__ret;								\`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `})`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ` * ksmbd_hooks_init() - Initialize the hook subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ` * Sets up per-hook-point lists and associated locks.  Must be called`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ` * during module initialization.`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` * Return: 0 on success (always succeeds)`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `int ksmbd_hooks_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ` * ksmbd_hooks_exit() - Tear down the hook subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ` * Unregisters all remaining hooks and releases resources.`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` * Must be called during module exit.`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `void ksmbd_hooks_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` * ksmbd_register_hook() - Register a hook handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ` * @handler: Pointer to a caller-allocated &struct ksmbd_hook_handler.`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ` *           The caller must fill in @point, @priority, @hook_fn, @priv,`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ` *           and @owner before calling.  The handler is inserted into`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ` *           the per-hook-point list sorted by @priority (ascending).`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [LIFETIME|] ` * The hook list is protected by RCU; readers (hook dispatch) do not`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00159 [NONE] ` * acquire any lock.  The static key is enabled when the first handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] ` * is registered.`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `int ksmbd_register_hook(struct ksmbd_hook_handler *handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ` * ksmbd_unregister_hook() - Unregister a previously registered hook handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ` * @handler: Pointer to the &struct ksmbd_hook_handler to remove.`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [LIFETIME|] ` * Removes the handler from the hook chain and waits for an RCU grace`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00171 [NONE] ` * period to ensure no concurrent readers reference the handler.  The`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ` * static key is disabled when the last handler is unregistered.`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `void ksmbd_unregister_hook(struct ksmbd_hook_handler *handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `#endif /* __KSMBD_HOOKS_H */`
  Review: Low-risk line; verify in surrounding control flow.
