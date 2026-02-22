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
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/nls.h>

#include "ksmbd_info.h"
#include "glob.h"
#include "smb2pdu.h"
#include "connection.h"
#include "misc.h"
#include "mgmt/share_config.h"

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

/*
 * FILE_NAME_INFORMATION (class 9) GET handler
 *
 * Returns the file path relative to the share root encoded as
 * UTF-16LE.  The response layout is:
 *   4 bytes  FileNameLength (in bytes, of the UTF-16LE name)
 *   variable FileName[]     (UTF-16LE, NOT null-terminated)
 */

/**
 * ksmbd_info_get_file_name() - FILE_NAME_INFORMATION query handler
 * @work:    smb work for this request
 * @fp:      ksmbd file pointer
 * @buf:     response buffer to fill
 * @buf_len: available space in @buf
 * @out_len: [out] bytes written to @buf
 *
 * Retrieves the file path relative to the share root, converts it
 * to UTF-16LE, and writes FileNameLength + FileName into @buf.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_info_get_file_name(struct ksmbd_work *work,
				    struct ksmbd_file *fp,
				    void *buf,
				    unsigned int buf_len,
				    unsigned int *out_len)
{
	struct ksmbd_conn *conn = work->conn;
	char *filename;
	int conv_len;
	__le32 *name_len_ptr;
	unsigned int min_len;

	if (!fp)
		return -EINVAL;

	/* Need at least 4 bytes for FileNameLength */
	min_len = sizeof(__le32);
	if (buf_len < min_len)
		return -ENOSPC;

	filename = convert_to_nt_pathname(work->tcon->share_conf,
					  &fp->filp->f_path);
	if (IS_ERR(filename))
		return PTR_ERR(filename);

	ksmbd_debug(SMB,
		    "FILE_NAME_INFORMATION: filename = %s\n",
		    filename);

	name_len_ptr = (__le32 *)buf;

	/*
	 * Convert filename to UTF-16LE after the 4-byte length
	 * field.  smbConvertToUTF16 returns the number of
	 * UTF-16 code units written.
	 */
	conv_len = smbConvertToUTF16(
			(__le16 *)((char *)buf + sizeof(__le32)),
			filename,
			PATH_MAX,
			conn->local_nls,
			0);
	conv_len *= 2; /* code units -> bytes */

	if (sizeof(__le32) + conv_len > buf_len) {
		kfree(filename);
		return -ENOSPC;
	}

	*name_len_ptr = cpu_to_le32(conv_len);
	*out_len = sizeof(__le32) + conv_len;

	kfree(filename);
	return 0;
}

/*
 * FS_CONTROL_INFORMATION (class 6) SET handler
 *
 * Accepts and validates an smb2_fs_control_info structure from the
 * client.  Quota control is not supported by most Linux filesystems
 * so this handler accepts the request and returns success, matching
 * Windows server behavior for non-quota filesystems.
 */

/**
 * ksmbd_info_set_fs_control() - FS_CONTROL_INFORMATION set handler
 * @work:    smb work for this request
 * @fp:      ksmbd file pointer (may be NULL)
 * @buf:     request data buffer containing smb2_fs_control_info
 * @buf_len: length of request data
 * @out_len: [out] bytes consumed from @buf
 *
 * Validates the buffer size and accepts the FS control information.
 * Quota enforcement is not implemented; the handler returns success
 * to match typical Windows server behavior on non-quota volumes.
 *
 * Return: 0 on success, -EMSGSIZE if buffer too small
 */
static int ksmbd_info_set_fs_control(struct ksmbd_work *work,
				     struct ksmbd_file *fp,
				     void *buf,
				     unsigned int buf_len,
				     unsigned int *out_len)
{
	if (buf_len < sizeof(struct smb2_fs_control_info))
		return -EMSGSIZE;

	ksmbd_debug(SMB,
		    "FS_CONTROL_INFORMATION SET: accepted (quota not enforced)\n");

	*out_len = sizeof(struct smb2_fs_control_info);
	return 0;
}

/* Static handler descriptors for built-in info-level handlers */
static struct ksmbd_info_handler ksmbd_file_name_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_NAME_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_file_name,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_fs_control_set_handler = {
	.info_type	= SMB2_O_INFO_FILESYSTEM,
	.info_class	= FS_CONTROL_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_fs_control,
	.owner		= THIS_MODULE,
};

/**
 * ksmbd_info_init() - Initialize the info-level dispatch table
 *
 * Registers built-in info-level handlers for incremental migration
 * from the monolithic switch statements in smb2pdu.c.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_info_init(void)
{
	int ret;

	hash_init(info_handlers);

	ret = ksmbd_register_info_handler(&ksmbd_file_name_get_handler);
	if (ret)
		goto err_out;

	ret = ksmbd_register_info_handler(&ksmbd_fs_control_set_handler);
	if (ret)
		goto err_unreg_file_name;

	ksmbd_debug(SMB, "Info-level handler table initialized\n");
	return 0;

err_unreg_file_name:
	ksmbd_unregister_info_handler(&ksmbd_file_name_get_handler);
err_out:
	pr_err("Failed to register info handlers: %d\n", ret);
	return ret;
}

/**
 * ksmbd_info_exit() - Tear down the info-level dispatch table
 *
 * Unregisters all built-in info-level handlers.
 */
void ksmbd_info_exit(void)
{
	ksmbd_unregister_info_handler(&ksmbd_fs_control_set_handler);
	ksmbd_unregister_info_handler(&ksmbd_file_name_get_handler);
}
