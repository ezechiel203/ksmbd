/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   FSCTL handler registration API for ksmbd
 */

#ifndef __KSMBD_FSCTL_H
#define __KSMBD_FSCTL_H

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/module.h>
#include <linux/rcupdate.h>

struct ksmbd_work;
struct smb2_ioctl_rsp;

/**
 * struct ksmbd_fsctl_handler - FSCTL dispatch entry
 * @ctl_code:	FSCTL control code (host byte order)
 * @handler:	callback function invoked on matching FSCTL
 * @owner:	module owning this handler (for reference counting)
 * @node:	hash table linkage
 * @rcu:	RCU callback head for safe removal
 *
 * Each registered handler is hashed by ctl_code into an RCU-protected
 * hash table.  The dispatch path looks up handlers under rcu_read_lock
 * and invokes the callback.
 *
 * Handler return values:
 *   0         - success, @out_len contains response bytes written
 *   negative  - errno (e.g. -EINVAL, -ENOENT)
 */
struct ksmbd_fsctl_handler {
	u32 ctl_code;
	int (*handler)(struct ksmbd_work *work, u64 id,
		       void *in_buf, unsigned int in_buf_len,
		       unsigned int max_out_len,
		       struct smb2_ioctl_rsp *rsp,
		       unsigned int *out_len);
	struct module *owner;
	struct hlist_node node;
	struct rcu_head rcu;
};

/**
 * ksmbd_register_fsctl() - Register an FSCTL handler
 * @h: handler descriptor (caller must keep alive until unregistered)
 *
 * Adds the handler to the RCU-protected dispatch table.
 *
 * Return: 0 on success, -EEXIST if ctl_code already registered
 */
int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h);

/**
 * ksmbd_unregister_fsctl() - Unregister an FSCTL handler
 * @h: handler descriptor previously passed to ksmbd_register_fsctl()
 *
 * Removes the handler and waits for an RCU grace period so that
 * in-flight lookups complete safely.
 */
void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h);

/**
 * ksmbd_dispatch_fsctl() - Look up and invoke a registered FSCTL handler
 * @work:	    smb work for this request
 * @ctl_code:	    FSCTL control code (host byte order)
 * @id:		    volatile file id
 * @in_buf:	    pointer to input buffer
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Return: 0 on success, handler errno on failure, -EOPNOTSUPP if no
 *         handler is registered for the given ctl_code.
 */
int ksmbd_dispatch_fsctl(struct ksmbd_work *work, u32 ctl_code,
			 u64 id, void *in_buf, unsigned int in_buf_len,
			 unsigned int max_out_len,
			 struct smb2_ioctl_rsp *rsp,
			 unsigned int *out_len);

/**
 * ksmbd_fsctl_init() - Initialize the FSCTL dispatch table
 *
 * Registers all built-in FSCTL handlers.  Must be called during
 * module initialization.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_fsctl_init(void);

/**
 * ksmbd_fsctl_exit() - Tear down the FSCTL dispatch table
 *
 * Unregisters all handlers and cleans up.  Must be called during
 * module exit.
 */
void ksmbd_fsctl_exit(void);

#if IS_ENABLED(CONFIG_KUNIT)
struct ksmbd_file;
struct copychunk_ioctl_req;
struct in_device;
struct ksmbd_odx_token;

/* FSCTL functions exported for KUnit testing (ksmbd_fsctl.c) */
void ksmbd_fsctl_build_fallback_object_id(struct ksmbd_file *fp,
					  u8 *object_id);
int ksmbd_fsctl_fill_object_id_rsp(struct ksmbd_file *fp,
				   bool create_if_missing,
				   unsigned int max_out_len,
				   struct smb2_ioctl_rsp *rsp,
				   unsigned int *out_len);
int fsctl_is_pathname_valid_handler(struct ksmbd_work *work,
				    u64 id, void *in_buf,
				    unsigned int in_buf_len,
				    unsigned int max_out_len,
				    struct smb2_ioctl_rsp *rsp,
				    unsigned int *out_len);
__be32 fsctl_idev_ipv4_address(struct in_device *idev);
int fsctl_copychunk_common(struct ksmbd_work *work,
			   struct copychunk_ioctl_req *ci_req,
			   unsigned int cnt_code,
			   unsigned int input_count,
			   u64 id,
			   struct smb2_ioctl_rsp *rsp);
u32 odx_nonce_hash(const u8 *nonce);
bool odx_token_validate(const struct ksmbd_odx_token *token);
int fsctl_validate_negotiate_info_handler(struct ksmbd_work *work,
					  u64 id, void *in_buf,
					  unsigned int in_buf_len,
					  unsigned int max_out_len,
					  struct smb2_ioctl_rsp *rsp,
					  unsigned int *out_len);
#endif /* CONFIG_KUNIT */

#endif /* __KSMBD_FSCTL_H */
