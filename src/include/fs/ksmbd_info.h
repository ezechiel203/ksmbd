/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Info-level handler registration API for ksmbd
 *
 *   Provides an RCU-protected hash table for SMB2 QUERY_INFO and SET_INFO
 *   handler dispatch, keyed on (info_type, info_class, op).
 */

#ifndef __KSMBD_INFO_H
#define __KSMBD_INFO_H

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/module.h>
#include <linux/rcupdate.h>

struct ksmbd_work;
struct ksmbd_file;

/**
 * enum ksmbd_info_op - info operation type
 * @KSMBD_INFO_GET: query/get information (QUERY_INFO)
 * @KSMBD_INFO_SET: set/modify information (SET_INFO)
 */
enum ksmbd_info_op {
	KSMBD_INFO_GET,
	KSMBD_INFO_SET,
};

/**
 * struct ksmbd_info_handler - Info-level dispatch entry
 * @info_type:  SMB2 info type (FILE, FILESYSTEM, SECURITY, QUOTA)
 * @info_class: File/FS info class (e.g., FileBasicInformation)
 * @op:         GET or SET operation
 * @handler:    callback function
 *              For GET: fills buf, sets *out_len, returns 0 or -errno
 *              For SET: reads buf of buf_len bytes, returns 0 or -errno
 * @owner:      module owning this handler (for reference counting)
 * @node:       hash table linkage
 * @rcu:        RCU callback head for safe removal
 *
 * Each registered handler is hashed by a composite key of
 * (info_type, info_class, op) into an RCU-protected hash table.
 * The dispatch path looks up handlers under rcu_read_lock and
 * invokes the callback.
 */
struct ksmbd_info_handler {
	u8 info_type;
	u8 info_class;
	enum ksmbd_info_op op;
	int (*handler)(struct ksmbd_work *work,
		       struct ksmbd_file *fp,
		       void *buf,
		       unsigned int buf_len,
		       unsigned int *out_len);
	struct module *owner;
	struct hlist_node node;
	struct rcu_head rcu;
};

/**
 * ksmbd_register_info_handler() - Register an info-level handler
 * @h: handler descriptor (caller must keep alive until unregistered)
 *
 * Adds the handler to the RCU-protected dispatch table.
 *
 * Return: 0 on success, -EEXIST if (info_type, info_class, op) already
 *         registered
 */
int ksmbd_register_info_handler(struct ksmbd_info_handler *h);

/**
 * ksmbd_unregister_info_handler() - Unregister an info-level handler
 * @h: handler descriptor previously passed to ksmbd_register_info_handler()
 *
 * Removes the handler and waits for an RCU grace period so that
 * in-flight lookups complete safely.
 */
void ksmbd_unregister_info_handler(struct ksmbd_info_handler *h);

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
 * Return: 0 on success, handler errno on failure, -EOPNOTSUPP if no
 *         handler is registered for the given key.
 */
int ksmbd_dispatch_info(struct ksmbd_work *work,
			struct ksmbd_file *fp,
			u8 info_type, u8 info_class,
			enum ksmbd_info_op op,
			void *buf, unsigned int buf_len,
			unsigned int *out_len);

/**
 * ksmbd_info_get_file_stat_lx() - FileStatLxInformation (class 71) handler
 * @work:    smb work for this request
 * @fp:      ksmbd file pointer
 * @buf:     response buffer to fill
 * @buf_len: available space in @buf
 * @out_len: [out] bytes written to @buf
 *
 * Called directly (not via dispatch) from smb2_get_info_file() case 71
 * because FILE_CASE_SENSITIVE_INFORMATION is also class 71 and occupies
 * the dispatch slot for (SMB2_O_INFO_FILE, 71, KSMBD_INFO_GET).
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_info_get_file_stat_lx(struct ksmbd_work *work,
				struct ksmbd_file *fp,
				void *buf,
				unsigned int buf_len,
				unsigned int *out_len);
int ksmbd_pipe_get_info(struct ksmbd_work *work, u64 id,
			void *buf, unsigned int buf_len,
			unsigned int *out_len);
int ksmbd_pipe_get_local_info(struct ksmbd_work *work, u64 id,
			      void *buf, unsigned int buf_len,
			      unsigned int *out_len);

/**
 * ksmbd_info_init() - Initialize the info-level dispatch table
 *
 * Currently empty — no handlers are migrated yet.  Infrastructure is
 * ready for incremental migration from the monolithic switch statements
 * in smb2pdu.c (smb2_get_info_file, smb2_set_info_file,
 * smb2_get_info_filesystem).
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_info_init(void);

/**
 * ksmbd_info_exit() - Tear down the info-level dispatch table
 *
 * Currently empty — no handlers registered yet.
 */
void ksmbd_info_exit(void);

#endif /* __KSMBD_INFO_H */
