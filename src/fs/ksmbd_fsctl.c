// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   FSCTL handler registration table for ksmbd
 *
 *   Replaces the monolithic switch-case dispatch in smb2_ioctl() with an
 *   RCU-protected hash table.  Built-in handlers are registered at module
 *   init; additional handlers can be registered by extension modules.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/inetdevice.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <net/addrconf.h>
#include <linux/ethtool.h>

#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/visibility.h>
#else
#define VISIBLE_IF_KUNIT static
#define EXPORT_SYMBOL_IF_KUNIT(sym)
#endif

#include "ksmbd_fsctl.h"
#include "ksmbd_branchcache.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "smbstatus.h"
#include "smb_common.h"
#include "glob.h"
#include "compat.h"
#include "connection.h"
#include "transport_ipc.h"
#include "transport_tcp.h"
#include "transport_rdma.h"
#include "ksmbd_netlink.h"
#include "vfs_cache.h"
#include "vfs.h"
#include "ksmbd_work.h"
#include "xattr.h"
#include "oplock.h"
#include "server.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"

/* 256 buckets (2^8) — sufficient for the ~20 built-in FSCTLs */
#define KSMBD_FSCTL_HASH_BITS	8

static DEFINE_HASHTABLE(fsctl_handlers, KSMBD_FSCTL_HASH_BITS);
static DEFINE_SPINLOCK(fsctl_lock);

/**
 * ksmbd_register_fsctl() - Register an FSCTL handler
 * @h: handler descriptor
 *
 * Adds the handler to the hash table under spinlock using hash_add_rcu.
 *
 * Return: 0 on success, -EEXIST if a handler for the same ctl_code
 *         is already registered.
 */
int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h)
{
	struct ksmbd_fsctl_handler *cur;

	spin_lock(&fsctl_lock);
	hash_for_each_possible_rcu(fsctl_handlers, cur, node, h->ctl_code) {
		if (cur->ctl_code == h->ctl_code) {
			spin_unlock(&fsctl_lock);
			pr_err("FSCTL handler 0x%08x already registered\n",
			       h->ctl_code);
			return -EEXIST;
		}
	}
	hash_add_rcu(fsctl_handlers, &h->node, h->ctl_code);
	spin_unlock(&fsctl_lock);
	return 0;
}

/**
 * ksmbd_unregister_fsctl() - Unregister an FSCTL handler
 * @h: handler descriptor previously registered
 *
 * Removes the handler under spinlock and waits for an RCU grace period.
 */
void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h)
{
	spin_lock(&fsctl_lock);
	hash_del_rcu(&h->node);
	spin_unlock(&fsctl_lock);
	synchronize_rcu();
}

/**
 * ksmbd_dispatch_fsctl() - Look up and invoke a registered FSCTL handler
 * @work:	    smb work for this request
 * @ctl_code:	    FSCTL control code (host byte order)
 * @id:		    volatile file id
 * @in_buf:	    pointer to input buffer
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written by the handler
 *
 * Performs an RCU-protected hash lookup, takes a module reference on the
 * owning module, and invokes the handler callback.
 *
 * Return: 0 on success, handler errno on failure, -EOPNOTSUPP if no
 *         handler is registered for the given ctl_code.
 */
int ksmbd_dispatch_fsctl(struct ksmbd_work *work, u32 ctl_code,
			 u64 id, void *in_buf, unsigned int in_buf_len,
			 unsigned int max_out_len,
			 struct smb2_ioctl_rsp *rsp,
			 unsigned int *out_len)
{
	struct ksmbd_fsctl_handler *h;
	int ret = -EOPNOTSUPP;

	*out_len = 0;

	rcu_read_lock();
	hash_for_each_possible_rcu(fsctl_handlers, h, node, ctl_code) {
		if (h->ctl_code != ctl_code)
			continue;

		if (!try_module_get(h->owner)) {
			rcu_read_unlock();
			return -ENODEV;
		}
		rcu_read_unlock();

		ret = h->handler(work, id, in_buf, in_buf_len,
				 max_out_len, rsp, out_len);
		module_put(h->owner);
		return ret;
	}
	rcu_read_unlock();

	return ret;
}

/*
 * ============================================================
 *  Built-in FSCTL handler implementations
 * ============================================================
 *
 * These are extracted from smb2_ioctl() in smb2pdu.c.  Each follows
 * the unified handler signature defined in ksmbd_fsctl.h.
 */

static void ksmbd_fsctl_build_fallback_object_id(struct ksmbd_file *fp,
						 u8 *object_id)
{
	struct inode *inode = file_inode(fp->filp);
	__le64 ino = cpu_to_le64(inode->i_ino);
	__le32 gen = cpu_to_le32(inode->i_generation);
	__le32 dev = cpu_to_le32((u32)new_encode_dev(inode->i_sb->s_dev));

	memset(object_id, 0, 16);
	memcpy(object_id, &ino, sizeof(ino));
	memcpy(object_id + sizeof(ino), &gen, sizeof(gen));
	memcpy(object_id + sizeof(ino) + sizeof(gen), &dev, sizeof(dev));
}

static int ksmbd_fsctl_get_object_id(struct ksmbd_file *fp, u8 *object_id)
{
	char *xattr_buf = NULL;
	ssize_t xattr_len;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),
				       fp->filp->f_path.dentry,
				       XATTR_NAME_OBJECT_ID, &xattr_buf);
#else
	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),
				       fp->filp->f_path.dentry,
				       XATTR_NAME_OBJECT_ID, &xattr_buf);
#endif
	if (xattr_len < 0) {
		if (xattr_len == -EOPNOTSUPP) {
			ksmbd_fsctl_build_fallback_object_id(fp, object_id);
			return 0;
		}
		return (int)xattr_len;
	}

	if (xattr_len != 16) {
		kfree(xattr_buf);
		return -EINVAL;
	}

	memcpy(object_id, xattr_buf, 16);
	kfree(xattr_buf);
	return 0;
}

static int ksmbd_fsctl_set_object_id(struct ksmbd_file *fp, const u8 *object_id)
{
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = ksmbd_vfs_setxattr(file_mnt_idmap(fp->filp),
#else
	ret = ksmbd_vfs_setxattr(file_mnt_user_ns(fp->filp),
#endif
				 &fp->filp->f_path,
				 XATTR_NAME_OBJECT_ID,
				 (void *)object_id,
				 16, 0, true);
	if (ret == -EOPNOTSUPP)
		return 0;
	return ret;
}

static int ksmbd_fsctl_delete_object_id(struct ksmbd_file *fp)
{
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = ksmbd_vfs_remove_xattr(file_mnt_idmap(fp->filp),
#else
	ret = ksmbd_vfs_remove_xattr(file_mnt_user_ns(fp->filp),
#endif
				     &fp->filp->f_path,
				     (char *)XATTR_NAME_OBJECT_ID,
				     true);
	if (ret == -EOPNOTSUPP)
		return 0;
	return ret;
}

static int ksmbd_fsctl_get_or_create_object_id(struct ksmbd_file *fp,
						u8 *object_id)
{
	int ret;

	ret = ksmbd_fsctl_get_object_id(fp, object_id);
	if (!ret)
		return 0;

	if (ret != -ENOENT && ret != -ENODATA && ret != -EINVAL)
		return ret;

	get_random_bytes(object_id, 16);
	return ksmbd_fsctl_set_object_id(fp, object_id);
}

static int ksmbd_fsctl_fill_object_id_rsp(struct ksmbd_file *fp,
					  bool create_if_missing,
					  unsigned int max_out_len,
					  struct smb2_ioctl_rsp *rsp,
					  unsigned int *out_len)
{
	struct file_object_buf_type1_ioctl_rsp *obj_rsp;
	u8 object_id[16];
	int ret;

	if (max_out_len < sizeof(*obj_rsp)) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	if (create_if_missing)
		ret = ksmbd_fsctl_get_or_create_object_id(fp, object_id);
	else
		ret = ksmbd_fsctl_get_object_id(fp, object_id);
	if (ret) {
		if (ret == -EACCES || ret == -EPERM)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (ret == -ENOENT || ret == -ENODATA)
			rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;
		else
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
		*out_len = 0;
		return ret;
	}

	obj_rsp = (struct file_object_buf_type1_ioctl_rsp *)&rsp->Buffer[0];
	memset(obj_rsp, 0, sizeof(*obj_rsp));
	memcpy(obj_rsp->ObjectId, object_id, sizeof(obj_rsp->ObjectId));
	memcpy(obj_rsp->BirthObjectId, object_id,
	       sizeof(obj_rsp->BirthObjectId));
	*out_len = sizeof(*obj_rsp);
	return 0;
}

/**
 * fsctl_create_or_get_object_id_handler() - FSCTL_CREATE_OR_GET_OBJECT_ID
 *
 * Returns a stable 16-byte object ID persisted in xattr, and fills the
 * type-1 FILE_OBJECTID_BUFFER response.
 */
static int fsctl_create_or_get_object_id_handler(struct ksmbd_work *work,
						  u64 id, void *in_buf,
						  unsigned int in_buf_len,
						  unsigned int max_out_len,
						  struct smb2_ioctl_rsp *rsp,
						  unsigned int *out_len)
{
	struct ksmbd_file *fp;
	int ret;

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	ret = ksmbd_fsctl_fill_object_id_rsp(fp, true, max_out_len,
					     rsp, out_len);
	ksmbd_fd_put(work, fp);
	return ret;
}

static int fsctl_get_object_id_handler(struct ksmbd_work *work,
				       u64 id, void *in_buf,
				       unsigned int in_buf_len,
				       unsigned int max_out_len,
				       struct smb2_ioctl_rsp *rsp,
				       unsigned int *out_len)
{
	struct ksmbd_file *fp;
	int ret;

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	ret = ksmbd_fsctl_fill_object_id_rsp(fp, false, max_out_len,
					     rsp, out_len);
	ksmbd_fd_put(work, fp);
	return ret;
}

static int fsctl_set_object_id_common_handler(struct ksmbd_work *work,
					      u64 id, void *in_buf,
					      unsigned int in_buf_len,
					      struct smb2_ioctl_rsp *rsp,
					      unsigned int *out_len)
{
	struct ksmbd_file *fp;
	int ret;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < 16) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	ret = ksmbd_fsctl_set_object_id(fp, (u8 *)in_buf);
	if (ret) {
		if (ret == -EACCES || ret == -EPERM)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
	}
	*out_len = 0;
	ksmbd_fd_put(work, fp);
	return ret;
}

static int fsctl_set_object_id_handler(struct ksmbd_work *work,
				       u64 id, void *in_buf,
				       unsigned int in_buf_len,
				       unsigned int max_out_len,
				       struct smb2_ioctl_rsp *rsp,
				       unsigned int *out_len)
{
	return fsctl_set_object_id_common_handler(work, id, in_buf,
						  in_buf_len, rsp, out_len);
}

static int fsctl_set_object_id_extended_handler(struct ksmbd_work *work,
						u64 id, void *in_buf,
						unsigned int in_buf_len,
						unsigned int max_out_len,
						struct smb2_ioctl_rsp *rsp,
						unsigned int *out_len)
{
	/*
	 * OI-02: MS-FSCC §2.3.67 — FSCTL_SET_OBJECT_ID_EXTENDED input is
	 * 48 bytes (BirthVolumeId[16] + BirthObjectId[16] + DomainId[16]).
	 * We must read the existing full 64-byte FILE_OBJECTID_BUFFER from
	 * xattr, update only the extended 48 bytes (offset 16..63), then
	 * write back all 64 bytes.
	 */
	struct ksmbd_file *fp;
	struct file_object_buf_type1_ioctl_rsp full_buf;
	char *xattr_buf = NULL;
	ssize_t xattr_len;
	int ret;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	/* Extended input must be at least 48 bytes */
	if (in_buf_len < 48) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	/* Read existing ObjectId xattr (may be 16 or 64 bytes) */
	memset(&full_buf, 0, sizeof(full_buf));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),
				       fp->filp->f_path.dentry,
				       XATTR_NAME_OBJECT_ID, &xattr_buf);
#else
	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),
				       fp->filp->f_path.dentry,
				       XATTR_NAME_OBJECT_ID, &xattr_buf);
#endif
	if (xattr_len >= 16)
		memcpy(&full_buf, xattr_buf, min_t(ssize_t, xattr_len, (ssize_t)sizeof(full_buf)));
	else if (xattr_len < 0 && xattr_len != -ENOENT && xattr_len != -ENODATA)
		ksmbd_fsctl_build_fallback_object_id(fp, full_buf.ObjectId);
	kfree(xattr_buf);

	/* Update the extended 48 bytes (bytes 16..63): BirthVolumeId, BirthObjectId, DomainId */
	memcpy(full_buf.BirthVolumeId, (u8 *)in_buf, 16);
	memcpy(full_buf.BirthObjectId, (u8 *)in_buf + 16, 16);
	memcpy(full_buf.DomainId, (u8 *)in_buf + 32, 16);

	/* Write back the full 64-byte buffer */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = ksmbd_vfs_setxattr(file_mnt_idmap(fp->filp),
#else
	ret = ksmbd_vfs_setxattr(file_mnt_user_ns(fp->filp),
#endif
				 &fp->filp->f_path,
				 XATTR_NAME_OBJECT_ID,
				 &full_buf,
				 sizeof(full_buf), 0, true);
	if (ret == -EOPNOTSUPP)
		ret = 0;
	else if (ret) {
		if (ret == -EACCES || ret == -EPERM)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
	}

	*out_len = 0;
	ksmbd_fd_put(work, fp);
	return ret;
}

static int fsctl_delete_object_id_handler(struct ksmbd_work *work,
					  u64 id, void *in_buf,
					  unsigned int in_buf_len,
					  unsigned int max_out_len,
					  struct smb2_ioctl_rsp *rsp,
					  unsigned int *out_len)
{
	struct ksmbd_file *fp;
	int ret;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	ret = ksmbd_fsctl_delete_object_id(fp);
	if (ret == -ENOENT || ret == -ENODATA)
		ret = 0;
	else if (ret) {
		if (ret == -EACCES || ret == -EPERM)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
	}

	*out_len = 0;
	ksmbd_fd_put(work, fp);
	return ret;
}

static int fsctl_get_compression_handler(struct ksmbd_work *work,
					 u64 id, void *in_buf,
					 unsigned int in_buf_len,
					 unsigned int max_out_len,
					 struct smb2_ioctl_rsp *rsp,
					 unsigned int *out_len)
{
	__le16 *compression_state;
	struct ksmbd_file *fp;

	if (max_out_len < sizeof(__le16)) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	compression_state = (__le16 *)&rsp->Buffer[0];
	if (fp->f_ci->m_fattr & ATTR_COMPRESSED_LE)
		*compression_state = cpu_to_le16(COMPRESSION_FORMAT_LZNT1);
	else
		*compression_state = cpu_to_le16(COMPRESSION_FORMAT_NONE);
	*out_len = sizeof(__le16);

	ksmbd_fd_put(work, fp);
	return 0;
}

static int fsctl_persist_dos_attrs(struct ksmbd_work *work,
				   struct ksmbd_file *fp,
				   __le32 old_fattr)
{
	struct xattr_dos_attrib da;
	int ret;

	if (fp->f_ci->m_fattr == old_fattr)
		return 0;

	if (!test_share_config_flag(work->tcon->share_conf,
				    KSMBD_SHARE_FLAG_STORE_DOS_ATTRS))
		return 0;

	ret = compat_ksmbd_vfs_get_dos_attrib_xattr(&fp->filp->f_path,
						    fp->filp->f_path.dentry,
						    &da);
	if (ret <= 0)
		return 0;

	da.attr = le32_to_cpu(fp->f_ci->m_fattr);
	ret = compat_ksmbd_vfs_set_dos_attrib_xattr(&fp->filp->f_path,
						    &da, true);
	if (ret)
		fp->f_ci->m_fattr = old_fattr;

	return ret;
}

static int fsctl_set_compression_handler(struct ksmbd_work *work,
					 u64 id, void *in_buf,
					 unsigned int in_buf_len,
					 unsigned int max_out_len,
					 struct smb2_ioctl_rsp *rsp,
					 unsigned int *out_len)
{
	struct ksmbd_file *fp;
	__le32 old_fattr;
	__le16 compression_state;
	u16 state;
	int ret = 0;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(__le16)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	memcpy(&compression_state, in_buf, sizeof(compression_state));
	state = le16_to_cpu(compression_state);
	if (state != COMPRESSION_FORMAT_NONE &&
	    state != COMPRESSION_FORMAT_DEFAULT &&
	    state != COMPRESSION_FORMAT_LZNT1) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	old_fattr = fp->f_ci->m_fattr;

	/*
	 * MS-FSCC §2.3.67: FSCTL_SET_COMPRESSION enables/disables transparent
	 * data compression on the file/directory.  Linux filesystems (ext4,
	 * xfs, etc.) do not support transparent per-file compression; only
	 * btrfs has this capability via mount-level options.
	 *
	 * Per MS-SMB2 §3.3.5.15.7: if the underlying object store does not
	 * support compression, return STATUS_NOT_SUPPORTED.
	 *
	 * Disabling compression (COMPRESSION_FORMAT_NONE) is always allowed
	 * and silently clears the flag.
	 */
	if (state == COMPRESSION_FORMAT_DEFAULT ||
	    state == COMPRESSION_FORMAT_LZNT1) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_NOT_SUPPORTED;
		return -EOPNOTSUPP;
	}

	/* state == COMPRESSION_FORMAT_NONE: clear the compressed flag */
	fp->f_ci->m_fattr &= ~ATTR_COMPRESSED_LE;

	ret = fsctl_persist_dos_attrs(work, fp, old_fattr);
	ksmbd_fd_put(work, fp);

	*out_len = 0;
	return ret;
}

static int fsctl_is_pathname_valid_handler(struct ksmbd_work *work,
					   u64 id, void *in_buf,
					   unsigned int in_buf_len,
					   unsigned int max_out_len,
					   struct smb2_ioctl_rsp *rsp,
					   unsigned int *out_len)
{
	*out_len = 0;
	return 0;
}

static int fsctl_is_volume_dirty_handler(struct ksmbd_work *work,
					 u64 id, void *in_buf,
					 unsigned int in_buf_len,
					 unsigned int max_out_len,
					 struct smb2_ioctl_rsp *rsp,
					 unsigned int *out_len)
{
	__le32 *volume_dirty;

	if (max_out_len < sizeof(__le32)) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	volume_dirty = (__le32 *)&rsp->Buffer[0];
	*volume_dirty = cpu_to_le32(0);
	*out_len = sizeof(__le32);
	return 0;
}

static int fsctl_stub_noop_success_handler(struct ksmbd_work *work,
					   u64 id, void *in_buf,
					   unsigned int in_buf_len,
					   unsigned int max_out_len,
					   struct smb2_ioctl_rsp *rsp,
					   unsigned int *out_len)
{
	*out_len = 0;
	return 0;
}

/**
 * fsctl_not_supported_handler() - Return STATUS_NOT_SUPPORTED
 *
 * For FSCTLs that reference features with no Linux equivalent (USN journal,
 * FAT BPB, raw encrypted, etc.), return an honest error instead of faking
 * success.
 */
static int fsctl_not_supported_handler(struct ksmbd_work *work,
				       u64 id, void *in_buf,
				       unsigned int in_buf_len,
				       unsigned int max_out_len,
				       struct smb2_ioctl_rsp *rsp,
				       unsigned int *out_len)
{
	rsp->hdr.Status = STATUS_NOT_SUPPORTED;
	*out_len = 0;
	return -EOPNOTSUPP;
}

struct fsctl_pipe_peek_rsp {
	__le32 NamedPipeState;
	__le32 ReadDataAvailable;
	__le32 NumberOfMessages;
	__le32 MessageLength;
} __packed;

/*
 * Named pipe state constants per MS-FSCC §2.3.32:
 *   1 = FILE_PIPE_DISCONNECTED_STATE
 *   2 = FILE_PIPE_LISTENING_STATE
 *   3 = FILE_PIPE_CONNECTED_STATE
 *   4 = FILE_PIPE_CLOSING_STATE
 */
#define FILE_PIPE_DISCONNECTED_STATE	1
#define FILE_PIPE_CONNECTED_STATE	3

struct fsctl_pipe_async_ctx {
	struct delayed_work	dwork;
	struct ksmbd_work	*work;
	u64			id;
	unsigned int		max_out_len;
};

static void fsctl_pipe_async_put_conn_ref(struct ksmbd_work *work)
{
	if (!work || !work->async_conn_ref || !work->conn)
		return;

	work->async_conn_ref = false;
	ksmbd_conn_free(work->conn);
}

static void fsctl_pipe_poll_reschedule(struct fsctl_pipe_async_ctx *ctx)
{
	mod_delayed_work(system_wq, &ctx->dwork, msecs_to_jiffies(25));
}

static void fsctl_pipe_transceive_finish(struct ksmbd_work *work,
					 struct fsctl_pipe_async_ctx *ctx,
					 struct ksmbd_rpc_command *rpc_resp)
{
	struct smb2_ioctl_rsp *rsp = smb2_get_msg(work->response_buf);
	unsigned int nbytes = 0;
	int rc = 0;

	if (!rpc_resp || rpc_resp->flags == KSMBD_RPC_EBAD_FID) {
		rsp->hdr.Status = STATUS_PIPE_DISCONNECTED;
		smb2_set_err_rsp(work);
	} else if (rpc_resp->flags == KSMBD_RPC_OK) {
		nbytes = min_t(unsigned int, rpc_resp->payload_sz,
			       ctx->max_out_len);
		if (rpc_resp->payload_sz > ctx->max_out_len)
			rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
		if (nbytes)
			memcpy((char *)rsp->Buffer, rpc_resp->payload,
			       nbytes);

		rsp->CntCode = cpu_to_le32(FSCTL_PIPE_TRANSCEIVE);
		rsp->InputCount = cpu_to_le32(0);
		rsp->InputOffset = cpu_to_le32(112);
		rsp->OutputOffset = cpu_to_le32(112);
		rsp->OutputCount = cpu_to_le32(nbytes);
		rsp->StructureSize = cpu_to_le16(49);
		rsp->Reserved = cpu_to_le16(0);
		rsp->Flags = cpu_to_le32(0);
		rsp->Reserved2 = cpu_to_le32(0);
		rc = ksmbd_iov_pin_rsp(work, rsp,
				       sizeof(struct smb2_ioctl_rsp) +
				       nbytes);
		if (rc) {
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
			smb2_set_err_rsp(work);
		}
	} else {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		smb2_set_err_rsp(work);
	}

	kvfree(rpc_resp);
	spin_lock(&work->conn->request_lock);
	list_del_init(&work->async_request_entry);
	spin_unlock(&work->conn->request_lock);

	work->pending_async = 0;
	work->send_no_response = 0;
	if (work->sess && work->sess->enc && work->encrypted &&
	    work->conn->ops->encrypt_resp) {
		rc = work->conn->ops->encrypt_resp(work);
		if (rc < 0)
			pr_err_ratelimited("ksmbd: pipe transceive encrypt failed: %d\n",
					   rc);
	}
	ksmbd_conn_write(work);
	ksmbd_conn_try_dequeue_request(work);
	if (READ_ONCE(server_conf.max_async_credits))
		atomic_dec(&work->conn->outstanding_async);
	if (work->sess)
		ksmbd_user_session_put(work->sess);
	fsctl_pipe_async_put_conn_ref(work);
	kfree(ctx);
	ksmbd_free_work_struct(work);
}

static void fsctl_pipe_transceive_poll_work(struct work_struct *wk)
{
	struct delayed_work *dwork = to_delayed_work(wk);
	struct fsctl_pipe_async_ctx *ctx =
		container_of(dwork, struct fsctl_pipe_async_ctx, dwork);
	struct ksmbd_work *work = ctx->work;
	struct ksmbd_rpc_command *rpc_resp;
	struct ksmbd_rpc_command *state_resp;
	struct ksmbd_rpc_pipe_info *pipe_info;

	if (!work || !work->sess || !ksmbd_conn_alive(work->conn) ||
	    ksmbd_conn_exiting(work->conn) || ksmbd_conn_releasing(work->conn)) {
		if (work) {
			spin_lock(&work->conn->request_lock);
			list_del_init(&work->async_request_entry);
			spin_unlock(&work->conn->request_lock);
			ksmbd_conn_try_dequeue_request(work);
			if (READ_ONCE(server_conf.max_async_credits))
				atomic_dec(&work->conn->outstanding_async);
			work->pending_async = 0;
		}
		if (work && work->sess)
			ksmbd_user_session_put(work->sess);
		fsctl_pipe_async_put_conn_ref(work);
		kfree(ctx);
		if (work)
			ksmbd_free_work_struct(work);
		return;
	}

	state_resp = ksmbd_rpc_query(work->sess, ctx->id);
	if (!state_resp) {
		fsctl_pipe_poll_reschedule(ctx);
		return;
	}

	if (state_resp->flags == KSMBD_RPC_EBAD_FID) {
		fsctl_pipe_transceive_finish(work, ctx, state_resp);
		return;
	}

	if (state_resp->flags != KSMBD_RPC_OK ||
	    state_resp->payload_sz < sizeof(*pipe_info)) {
		kvfree(state_resp);
		fsctl_pipe_poll_reschedule(ctx);
		return;
	}

	pipe_info = (struct ksmbd_rpc_pipe_info *)state_resp->payload;
	if (!pipe_info->read_data_available) {
		kvfree(state_resp);
		fsctl_pipe_poll_reschedule(ctx);
		return;
	}
	kvfree(state_resp);

	rpc_resp = ksmbd_rpc_read(work->sess, ctx->id);
	if (!rpc_resp || (rpc_resp->flags == KSMBD_RPC_OK &&
			  rpc_resp->payload_sz == 0)) {
		kvfree(rpc_resp);
		fsctl_pipe_poll_reschedule(ctx);
		return;
	}

	fsctl_pipe_transceive_finish(work, ctx, rpc_resp);
}

/**
 * fsctl_pipe_peek_handler() - Handle FSCTL_PIPE_PEEK
 * @work:	    smb work for this request
 * @id:		    volatile file id (pipe handle)
 * @in_buf:	    input buffer (unused for PEEK)
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed by client
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * MS-FSCC 2.3.18 (FSCTL_PIPE_PEEK output):
 *   Offset  Size  Field
 *   0       4     NamedPipeState
 *   4       4     ReadDataAvailable
 *   8       4     NumberOfMessages
 *   12      4     MessageLength
 *   16      var   Data (preview of first message, non-destructive)
 *
 * The Data field contains a preview of the available pipe data up to
 * min(ReadDataAvailable, max_out_len - sizeof(header)) bytes.  This
 * data is NOT consumed from the pipe (peek semantics).
 *
 * Return: 0 on success, negative errno on failure
 */
static int fsctl_pipe_peek_handler(struct ksmbd_work *work,
				   u64 id, void *in_buf,
				   unsigned int in_buf_len,
				   unsigned int max_out_len,
				   struct smb2_ioctl_rsp *rsp,
				   unsigned int *out_len)
{
	struct fsctl_pipe_peek_rsp *peek_rsp;
	struct ksmbd_rpc_command *rpc_resp = NULL;
	struct ksmbd_rpc_pipe_info *pipe_info;
	u32 data_avail, data_preview_len, extra_data_len;

	if (max_out_len < sizeof(*peek_rsp)) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	peek_rsp = (struct fsctl_pipe_peek_rsp *)&rsp->Buffer[0];
	memset(peek_rsp, 0, sizeof(*peek_rsp));

	rpc_resp = ksmbd_rpc_query(work->sess, id);
	if (!rpc_resp || rpc_resp->flags == KSMBD_RPC_EBAD_FID) {
		peek_rsp->NamedPipeState =
			cpu_to_le32(FILE_PIPE_DISCONNECTED_STATE);
		goto out_no_data;
	}

	if (rpc_resp->flags != KSMBD_RPC_OK ||
	    rpc_resp->payload_sz < sizeof(*pipe_info)) {
		rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
		kvfree(rpc_resp);
		return -EIO;
	}

	pipe_info = (struct ksmbd_rpc_pipe_info *)rpc_resp->payload;
	peek_rsp->NamedPipeState = cpu_to_le32(pipe_info->pipe_state);
	data_avail = pipe_info->read_data_available;
	peek_rsp->ReadDataAvailable = cpu_to_le32(data_avail);
	peek_rsp->NumberOfMessages =
		cpu_to_le32(pipe_info->number_of_messages);
	peek_rsp->MessageLength = cpu_to_le32(pipe_info->message_length);

	/*
	 * MS-FSCC 2.3.18: The Data field contains a non-destructive preview
	 * of the first message.  If the userspace daemon included data beyond
	 * the pipe_info header in its query response, copy it as the preview.
	 *
	 * data_preview_len: how much preview data the daemon sent
	 * We copy min(data_preview_len, space available in output buffer).
	 */
	extra_data_len = rpc_resp->payload_sz - sizeof(*pipe_info);
	if (extra_data_len > 0 && data_avail > 0) {
		u32 space = max_out_len - sizeof(*peek_rsp);

		data_preview_len = min3(extra_data_len, data_avail, space);
		if (data_preview_len > 0) {
			memcpy((u8 *)peek_rsp + sizeof(*peek_rsp),
			       rpc_resp->payload + sizeof(*pipe_info),
			       data_preview_len);
			kvfree(rpc_resp);
			*out_len = sizeof(*peek_rsp) + data_preview_len;
			return 0;
		}
	}

	kvfree(rpc_resp);
out_no_data:
	*out_len = sizeof(*peek_rsp);
	return 0;
}

static void fsctl_pipe_transceive_cancel(void **argv)
{
	struct ksmbd_work *work;
	struct smb2_ioctl_rsp *rsp;
	struct fsctl_pipe_async_ctx *ctx;

	if (!argv || !argv[0])
		return;

	work = argv[0];
	ctx = argv[1];
	rsp = smb2_get_msg(work->response_buf);

	if (ctx)
		cancel_delayed_work_sync(&ctx->dwork);

	rsp->hdr.Flags |= SMB2_FLAGS_ASYNC_COMMAND;
	rsp->hdr.Id.AsyncId = cpu_to_le64(work->async_id);
	rsp->hdr.Status = STATUS_CANCELLED;

	smb2_set_err_rsp(work);
	if (ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_hdr) + 8))
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;

	if (work->sess && work->sess->enc && work->encrypted &&
	    work->conn->ops->encrypt_resp) {
		int rc = work->conn->ops->encrypt_resp(work);

		if (rc < 0)
			pr_err_ratelimited("ksmbd: pipe transceive cancel encrypt failed: %d\n",
					   rc);
	}

	work->send_no_response = 0;
	ksmbd_conn_write(work);

	spin_lock(&work->conn->request_lock);
	list_del_init(&work->async_request_entry);
	spin_unlock(&work->conn->request_lock);

	ksmbd_conn_try_dequeue_request(work);

	if (READ_ONCE(server_conf.max_async_credits))
		atomic_dec(&work->conn->outstanding_async);

	if (work->sess)
		ksmbd_user_session_put(work->sess);
	fsctl_pipe_async_put_conn_ref(work);
	kfree(ctx);
	ksmbd_free_work_struct(work);
}

static int fsctl_pipe_transceive_async(struct ksmbd_work *work,
				       struct smb2_ioctl_rsp *rsp,
				       u64 id, unsigned int max_out_len)
{
	struct fsctl_pipe_async_ctx *ctx;
	void **argv;
	int rc;

	argv = kcalloc(2, sizeof(void *), KSMBD_DEFAULT_GFP);
	if (!argv) {
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		return -ENOMEM;
	}

	ctx = kzalloc(sizeof(*ctx), KSMBD_DEFAULT_GFP);
	if (!ctx) {
		kfree(argv);
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		return -ENOMEM;
	}

	ctx->work = work;
	ctx->id = id;
	ctx->max_out_len = max_out_len;
	INIT_DELAYED_WORK(&ctx->dwork, fsctl_pipe_transceive_poll_work);

	rc = setup_async_work(work, fsctl_pipe_transceive_cancel, argv);
	if (rc) {
		kfree(ctx);
		kfree(argv);
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		return rc;
	}

	argv[0] = work;
	argv[1] = ctx;
	if (work->sess)
		ksmbd_user_session_get(work->sess);
	refcount_inc(&work->conn->refcnt);
	work->async_conn_ref = true;
	work->pending_async = 1;

	if (work->conn->ops->set_rsp_credits)
		work->conn->ops->set_rsp_credits(work);

	smb2_send_interim_resp(work, STATUS_PENDING);
	work->send_no_response = 1;
	fsctl_pipe_poll_reschedule(ctx);
	return 0;
}

struct fsctl_ntfs_volume_data_rsp {
	__le64 VolumeSerialNumber;
	__le64 NumberSectors;
	__le64 TotalClusters;
	__le64 FreeClusters;
	__le64 TotalReserved;
	__le32 BytesPerSector;
	__le32 BytesPerCluster;
	__le32 BytesPerFileRecordSegment;
	__le32 ClustersPerFileRecordSegment;
	__le64 MftValidDataLength;
	__le64 MftStartLcn;
	__le64 Mft2StartLcn;
	__le64 MftZoneStart;
	__le64 MftZoneEnd;
} __packed;

static int fsctl_get_ntfs_volume_data_handler(struct ksmbd_work *work,
					      u64 id, void *in_buf,
					      unsigned int in_buf_len,
					      unsigned int max_out_len,
					      struct smb2_ioctl_rsp *rsp,
					      unsigned int *out_len)
{
	struct fsctl_ntfs_volume_data_rsp *vol_rsp;
	struct ksmbd_share_config *share;
	struct path path;
	struct kstatfs stfs;
	u32 bytes_per_sector = 512;
	u32 bytes_per_cluster;
	u64 total_bytes;
	int ret;

	if (max_out_len < sizeof(*vol_rsp)) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	share = work->tcon ? work->tcon->share_conf : NULL;
	if (!share || !share->path) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	ret = kern_path(share->path, LOOKUP_NO_SYMLINKS, &path);
	if (ret) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return ret;
	}

	ret = vfs_statfs(&path, &stfs);
	if (ret) {
		path_put(&path);
		rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
		return ret;
	}

	vol_rsp = (struct fsctl_ntfs_volume_data_rsp *)&rsp->Buffer[0];
	memset(vol_rsp, 0, sizeof(*vol_rsp));

	bytes_per_cluster = max_t(u32, stfs.f_bsize, 1);
	if (bytes_per_cluster < bytes_per_sector)
		bytes_per_sector = bytes_per_cluster;
	total_bytes = (u64)stfs.f_blocks * stfs.f_bsize;

	vol_rsp->VolumeSerialNumber =
		cpu_to_le64((u64)new_encode_dev(path.mnt->mnt_sb->s_dev));
	vol_rsp->NumberSectors = cpu_to_le64(total_bytes / bytes_per_sector);
	vol_rsp->TotalClusters = cpu_to_le64(stfs.f_blocks);
	vol_rsp->FreeClusters = cpu_to_le64(stfs.f_bfree);
	vol_rsp->TotalReserved = 0;
	vol_rsp->BytesPerSector = cpu_to_le32(bytes_per_sector);
	vol_rsp->BytesPerCluster = cpu_to_le32(bytes_per_cluster);
	vol_rsp->BytesPerFileRecordSegment = cpu_to_le32(bytes_per_cluster);
	vol_rsp->ClustersPerFileRecordSegment = cpu_to_le32(1);

	path_put(&path);
	*out_len = sizeof(*vol_rsp);
	return 0;
}

struct fsctl_starting_vcn_input {
	__le64 StartingVcn;
} __packed;

struct fsctl_retrieval_pointers_hdr {
	__le32 ExtentCount;
	__le32 Reserved;	/* alignment padding per MS-FSCC 2.3.33 */
	__le64 StartingVcn;
} __packed;

struct fsctl_retrieval_pointer_extent {
	__le64 NextVcn;
	__le64 Lcn;
} __packed;

struct fsctl_retrieval_pointers_rsp {
	struct fsctl_retrieval_pointers_hdr hdr;
	struct fsctl_retrieval_pointer_extent extents[1];
} __packed;

static int fsctl_get_retrieval_pointers_handler(struct ksmbd_work *work,
						u64 id, void *in_buf,
						unsigned int in_buf_len,
						unsigned int max_out_len,
						struct smb2_ioctl_rsp *rsp,
						unsigned int *out_len)
{
	struct fsctl_starting_vcn_input *in;
	struct fsctl_retrieval_pointers_hdr *out_hdr;
	struct fsctl_retrieval_pointers_rsp *out_rsp;
	struct ksmbd_file *fp;
	struct inode *inode;
	u64 starting_vcn;
	u64 total_clusters;
	u32 cluster_bytes;

	if (in_buf_len < sizeof(*in)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	in = (struct fsctl_starting_vcn_input *)in_buf;
	starting_vcn = le64_to_cpu(in->StartingVcn);
	inode = file_inode(fp->filp);
	cluster_bytes = max_t(u32, i_blocksize(inode), 1);
	total_clusters = DIV_ROUND_UP_ULL(i_size_read(inode), cluster_bytes);

	if (!total_clusters || starting_vcn >= total_clusters) {
		if (max_out_len < sizeof(*out_hdr)) {
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
			return -ENOSPC;
		}

		out_hdr = (struct fsctl_retrieval_pointers_hdr *)&rsp->Buffer[0];
		out_hdr->ExtentCount = 0;
		out_hdr->Reserved = 0;
		out_hdr->StartingVcn = cpu_to_le64(starting_vcn);
		*out_len = sizeof(*out_hdr);
		ksmbd_fd_put(work, fp);
		return 0;
	}

	if (max_out_len < sizeof(*out_rsp)) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	out_rsp = (struct fsctl_retrieval_pointers_rsp *)&rsp->Buffer[0];
	out_rsp->hdr.ExtentCount = cpu_to_le32(1);
	out_rsp->hdr.Reserved = 0;
	out_rsp->hdr.StartingVcn = cpu_to_le64(starting_vcn);
	out_rsp->extents[0].NextVcn = cpu_to_le64(total_clusters);
	out_rsp->extents[0].Lcn = cpu_to_le64(starting_vcn);
	*out_len = sizeof(*out_rsp);

	ksmbd_fd_put(work, fp);
	return 0;
}

static __be32 fsctl_idev_ipv4_address(struct in_device *idev)
{
	__be32 addr = 0;
	struct in_ifaddr *ifa;

	rcu_read_lock();
	in_dev_for_each_ifa_rcu(ifa, idev) {
		if (ifa->ifa_flags & IFA_F_SECONDARY)
			continue;

		addr = ifa->ifa_address;
		break;
	}
	rcu_read_unlock();
	return addr;
}

static int fsctl_query_network_interface_info_handler(struct ksmbd_work *work,
						      u64 id, void *in_buf,
						      unsigned int in_buf_len,
						      unsigned int max_out_len,
						      struct smb2_ioctl_rsp *rsp,
						      unsigned int *out_len)
{
	struct network_interface_info_ioctl_rsp *nii_rsp = NULL;
	struct sockaddr_storage_rsp *sockaddr_storage;
	struct net_device *netdev;
	unsigned int flags;
	unsigned long long speed;
	unsigned int nbytes = 0;

	rtnl_lock();
	for_each_netdev(&init_net, netdev) {
		bool ipv4_set = false;

		if (netdev->type == ARPHRD_LOOPBACK)
			continue;

		if (!ksmbd_find_netdev_name_iface_list(netdev->name))
			continue;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
		flags = netif_get_flags(netdev);
#else
		flags = dev_get_flags(netdev);
#endif
		if (!(flags & IFF_RUNNING))
			continue;
ipv6_retry:
		if (max_out_len <
		    nbytes + sizeof(struct network_interface_info_ioctl_rsp)) {
			rtnl_unlock();
			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
			return -ENOSPC;
		}

		nii_rsp = (struct network_interface_info_ioctl_rsp *)&rsp->Buffer[nbytes];
		nii_rsp->IfIndex = cpu_to_le32(netdev->ifindex);
		nii_rsp->Capability = 0;
		if ((server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL) &&
		    netdev->real_num_tx_queues > 1)
			nii_rsp->Capability |= cpu_to_le32(RSS_CAPABLE);
		/*
		 * Only advertise RDMA if this interface is RDMA-capable and
		 * ksmbd is actually listening for SMB Direct connections.
		 * Hardware capability alone is not enough for
		 * FSCTL_QUERY_NETWORK_INTERFACE_INFO truthfulness.
		 */
		if (ksmbd_rdma_listener_active() &&
		    ksmbd_rdma_capable_netdev(netdev))
			nii_rsp->Capability |= cpu_to_le32(RDMA_CAPABLE);

		nii_rsp->Next = cpu_to_le32(152);
		nii_rsp->Reserved = 0;

		if (netdev->ethtool_ops->get_link_ksettings) {
			struct ethtool_link_ksettings cmd;

			netdev->ethtool_ops->get_link_ksettings(netdev, &cmd);
			speed = cmd.base.speed;
		} else {
			speed = SPEED_1000;
		}

		speed *= 1000000;
		/* MS-SMB2 §2.2.32.5: LinkSpeed is in bits/second */
		nii_rsp->LinkSpeed = cpu_to_le64(speed);

		sockaddr_storage =
			(struct sockaddr_storage_rsp *)nii_rsp->SockAddr_Storage;
		memset(sockaddr_storage, 0, 128);

		if (!ipv4_set) {
			struct in_device *idev;

			sockaddr_storage->Family = cpu_to_le16(INTERNETWORK);
			sockaddr_storage->addr4.Port = 0;

			idev = __in_dev_get_rtnl(netdev);
			if (!idev)
				continue;
			sockaddr_storage->addr4.IPv4address =
				fsctl_idev_ipv4_address(idev);
			nbytes += sizeof(struct network_interface_info_ioctl_rsp);
			ipv4_set = true;
			goto ipv6_retry;
		} else {
			struct inet6_dev *idev6;
			struct inet6_ifaddr *ifa;
			__u8 *ipv6_addr = sockaddr_storage->addr6.IPv6address;

			sockaddr_storage->Family = cpu_to_le16(INTERNETWORKV6);
			sockaddr_storage->addr6.Port = 0;
			sockaddr_storage->addr6.FlowInfo = 0;

			idev6 = __in6_dev_get(netdev);
			if (!idev6)
				continue;

			/*
			 * F2: Use RCU read lock when iterating IPv6 addresses.
			 * Although we hold rtnl_lock, inet6_ifaddr objects can be
			 * freed via RCU when an IPv6 address is removed concurrently
			 * (e.g., by a netlink message on another CPU).  The RCU lock
			 * ensures we don't dereference a freed inet6_ifaddr.
			 */
			rcu_read_lock();
			list_for_each_entry_rcu(ifa, &idev6->addr_list, if_list) {
				if (ifa->flags & (IFA_F_TENTATIVE |
						  IFA_F_DEPRECATED))
					continue;
				memcpy(ipv6_addr, ifa->addr.s6_addr, 16);
				break;
			}
			rcu_read_unlock();
			sockaddr_storage->addr6.ScopeId = 0;
			nbytes += sizeof(struct network_interface_info_ioctl_rsp);
		}
	}
	rtnl_unlock();

	/* MS-SMB2 §3.3.5.15.14: server MUST return at least one interface */
	if (nbytes == 0) {
		rsp->hdr.Status = STATUS_NOT_FOUND;
		return -ENOENT;
	}

	if (nii_rsp)
		nii_rsp->Next = 0;

	rsp->PersistentFileId = SMB2_NO_FID;
	rsp->VolatileFileId = SMB2_NO_FID;
	*out_len = nbytes;
	return 0;
}

static int fsctl_request_resume_key_handler(struct ksmbd_work *work,
					    u64 id, void *in_buf,
					    unsigned int in_buf_len,
					    unsigned int max_out_len,
					    struct smb2_ioctl_rsp *rsp,
					    unsigned int *out_len)
{
	struct resume_key_ioctl_rsp *key_rsp;
	struct ksmbd_file *fp;

	if (max_out_len < sizeof(*key_rsp)) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	key_rsp = (struct resume_key_ioctl_rsp *)&rsp->Buffer[0];
	memset(key_rsp, 0, sizeof(*key_rsp));
	key_rsp->ResumeKey[0] = cpu_to_le64(fp->volatile_id);
	key_rsp->ResumeKey[1] = cpu_to_le64(fp->persistent_id);
	rsp->VolatileFileId = fp->volatile_id;
	rsp->PersistentFileId = fp->persistent_id;
	*out_len = sizeof(*key_rsp);

	ksmbd_fd_put(work, fp);
	return 0;
}

static int fsctl_copychunk_common(struct ksmbd_work *work,
				  struct copychunk_ioctl_req *ci_req,
				  unsigned int cnt_code,
				  unsigned int input_count,
				  u64 id,
				  struct smb2_ioctl_rsp *rsp)
{
	struct copychunk_ioctl_rsp *ci_rsp;
	struct ksmbd_file *src_fp = NULL, *dst_fp = NULL;
	struct srv_copychunk *chunks;
	unsigned int i, chunk_count, chunk_count_written = 0;
	unsigned int chunk_size_written = 0;
	loff_t total_size_written = 0;
	int ret = 0;

	ci_rsp = (struct copychunk_ioctl_rsp *)&rsp->Buffer[0];
	rsp->VolatileFileId = id;
	rsp->PersistentFileId = SMB2_NO_FID;

	/*
	 * Initialize response to zero.  The server maximum values are
	 * only returned when STATUS_INVALID_PARAMETER is set (MS-FSCC
	 * 2.3.12.1 -- limits exceeded).  For all other errors/successes
	 * the response must carry actual counts.
	 */
	ci_rsp->ChunksWritten = 0;
	ci_rsp->ChunkBytesWritten = 0;
	ci_rsp->TotalBytesWritten = 0;

	chunks = (struct srv_copychunk *)&ci_req->Chunks[0];
	chunk_count = le32_to_cpu(ci_req->ChunkCount);
	if (chunk_count == 0)
		goto out;

	/* MS-FSCC §2.3.12: reject only when ChunkCount EXCEEDS max (> not >=) */
	{
		size_t chunks_sz;

		if (check_mul_overflow(chunk_count,
				       sizeof(struct srv_copychunk),
				       &chunks_sz) ||
		    chunk_count > ksmbd_server_side_copy_max_chunk_count() ||
		    input_count < offsetof(struct copychunk_ioctl_req, Chunks) +
				  chunks_sz) {
			ci_rsp->ChunksWritten =
				cpu_to_le32(ksmbd_server_side_copy_max_chunk_count());
			ci_rsp->ChunkBytesWritten =
				cpu_to_le32(ksmbd_server_side_copy_max_chunk_size());
			ci_rsp->TotalBytesWritten =
				cpu_to_le32(ksmbd_server_side_copy_max_total_size());
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			return -EINVAL;
		}
	}

	for (i = 0; i < chunk_count; i++) {
		u32 chunk_len = le32_to_cpu(chunks[i].Length);
		u64 src_off = le64_to_cpu(chunks[i].SourceOffset);
		u64 dst_off = le64_to_cpu(chunks[i].TargetOffset);
		u64 tmp;

		/* CC-02: zero-length chunk is invalid per MS-FSCC §2.3.12 */
		if (chunk_len == 0) {
			ci_rsp->ChunksWritten =
				cpu_to_le32(ksmbd_server_side_copy_max_chunk_count());
			ci_rsp->ChunkBytesWritten =
				cpu_to_le32(ksmbd_server_side_copy_max_chunk_size());
			ci_rsp->TotalBytesWritten =
				cpu_to_le32(ksmbd_server_side_copy_max_total_size());
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			return -EINVAL;
		}
		/* CC-03: validate source/target offset + length doesn't overflow */
		if (check_add_overflow(src_off, (u64)chunk_len, &tmp) ||
		    check_add_overflow(dst_off, (u64)chunk_len, &tmp)) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			return -EINVAL;
		}
		if (chunk_len > ksmbd_server_side_copy_max_chunk_size())
			break;
		total_size_written += chunk_len;
	}

	/* F-02: cast to u64 to avoid signed/unsigned wrap-around bypass */
	if (i < chunk_count ||
	    (u64)total_size_written > (u64)ksmbd_server_side_copy_max_total_size()) {
		ci_rsp->ChunksWritten =
			cpu_to_le32(ksmbd_server_side_copy_max_chunk_count());
		ci_rsp->ChunkBytesWritten =
			cpu_to_le32(ksmbd_server_side_copy_max_chunk_size());
		ci_rsp->TotalBytesWritten =
			cpu_to_le32(ksmbd_server_side_copy_max_total_size());
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	src_fp = ksmbd_lookup_foreign_fd(work, le64_to_cpu(ci_req->ResumeKey[0]));
	dst_fp = ksmbd_lookup_fd_fast(work, id);
	ret = -EINVAL;
	if (!src_fp ||
	    src_fp->persistent_id != le64_to_cpu(ci_req->ResumeKey[1])) {
		rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}

	if (!dst_fp) {
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		goto out;
	}

	/* F-03: reject cross-filesystem copy chunk (STATUS_OBJECT_TYPE_MISMATCH) */
	if (file_inode(src_fp->filp)->i_sb != file_inode(dst_fp->filp)->i_sb) {
		ret = -EXDEV;
		rsp->hdr.Status = STATUS_OBJECT_TYPE_MISMATCH;
		goto out;
	}

	rsp->PersistentFileId = dst_fp->persistent_id;

	/*
	 * MS-SMB2 §3.3.5.15.6: access check for copy chunk.
	 * Source needs FILE_READ_DATA or FILE_EXECUTE.
	 * FSCTL_COPYCHUNK: destination needs FILE_WRITE_DATA.
	 * FSCTL_COPYCHUNK_WRITE: destination needs FILE_READ_DATA.
	 */
	if (!(src_fp->daccess & (FILE_READ_DATA_LE | FILE_EXECUTE_LE))) {
		ret = -EACCES;
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		goto out;
	}
	/*
	 * Destination write check (both COPYCHUNK and COPYCHUNK_WRITE
	 * need write access on destination).
	 */
	if (!(dst_fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE))) {
		ret = -EACCES;
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		goto out;
	}
	/*
	 * FSCTL_COPYCHUNK additionally requires FILE_READ_DATA on
	 * the destination (MS-SMB2 §3.3.5.15.6.1).
	 * FSCTL_COPYCHUNK_WRITE does not require read access on dest.
	 */
	if (cnt_code == FSCTL_COPYCHUNK &&
	    !(dst_fp->daccess & FILE_READ_DATA_LE)) {
		ret = -EACCES;
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		goto out;
	}

	ret = ksmbd_vfs_copy_file_ranges(work, src_fp, dst_fp,
					 chunks, chunk_count,
					 &chunk_count_written,
					 &chunk_size_written,
					 &total_size_written);
	if (ret < 0) {
		if (ret == -EACCES)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (ret == -EAGAIN)
			rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;
		else if (ret == -EBADF)
			rsp->hdr.Status = STATUS_INVALID_HANDLE;
		else if (ret == -EFBIG || ret == -ENOSPC)
			rsp->hdr.Status = STATUS_DISK_FULL;
		else if (ret == -EINVAL)
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		else if (ret == -EISDIR)
			rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;
		else if (ret == -E2BIG)
			rsp->hdr.Status = STATUS_INVALID_VIEW_SIZE;
		else
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
	}

	ci_rsp->ChunksWritten = cpu_to_le32(chunk_count_written);
	/*
	 * MS-FSCC 2.3.12.1: ChunkBytesWritten MUST be zero when all
	 * requested chunks completed successfully.  It is non-zero only
	 * for a partial write (some chunks succeeded, but one failed),
	 * containing the byte count written for the last chunk attempted.
	 */
	if (chunk_count_written == chunk_count)
		ci_rsp->ChunkBytesWritten = 0;
	else
		ci_rsp->ChunkBytesWritten = cpu_to_le32(chunk_size_written);
	ci_rsp->TotalBytesWritten = cpu_to_le32(total_size_written);

#ifdef CONFIG_KSMBD_FRUIT
	if (!ret && work->conn->is_fruit && src_fp && dst_fp &&
	    (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE)) {
		ksmbd_vfs_copy_xattrs(src_fp->filp->f_path.dentry,
				      dst_fp->filp->f_path.dentry,
				      &dst_fp->filp->f_path);
	}
#endif
out:
	ksmbd_fd_put(work, src_fp);
	ksmbd_fd_put(work, dst_fp);
	return ret;
}

static int fsctl_copychunk_handler(struct ksmbd_work *work,
				   u64 id, void *in_buf,
				   unsigned int in_buf_len,
				   unsigned int max_out_len,
				   struct smb2_ioctl_rsp *rsp,
				   unsigned int *out_len)
{
	int ret;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len <= sizeof(struct copychunk_ioctl_req)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	if (max_out_len < sizeof(struct copychunk_ioctl_rsp)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	ret = fsctl_copychunk_common(work, (struct copychunk_ioctl_req *)in_buf,
				     FSCTL_COPYCHUNK, in_buf_len, id, rsp);
	*out_len = sizeof(struct copychunk_ioctl_rsp);
	return ret;
}

static int fsctl_copychunk_write_handler(struct ksmbd_work *work,
					 u64 id, void *in_buf,
					 unsigned int in_buf_len,
					 unsigned int max_out_len,
					 struct smb2_ioctl_rsp *rsp,
					 unsigned int *out_len)
{
	int ret;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len <= sizeof(struct copychunk_ioctl_req)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	if (max_out_len < sizeof(struct copychunk_ioctl_rsp)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	ret = fsctl_copychunk_common(work, (struct copychunk_ioctl_req *)in_buf,
				     FSCTL_COPYCHUNK_WRITE, in_buf_len, id, rsp);
	*out_len = sizeof(struct copychunk_ioctl_rsp);
	return ret;
}

static int fsctl_duplicate_extents_handler(struct ksmbd_work *work,
					   u64 id, void *in_buf,
					   unsigned int in_buf_len,
					   unsigned int max_out_len,
					   struct smb2_ioctl_rsp *rsp,
					   unsigned int *out_len)
{
	struct ksmbd_file *fp_in = NULL, *fp_out = NULL;
	struct duplicate_extents_to_file *dup_ext;
	loff_t src_off, dst_off, length, cloned;
	int ret = 0;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(*dup_ext)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	dup_ext = (struct duplicate_extents_to_file *)in_buf;
	fp_in = ksmbd_lookup_fd_slow(work, dup_ext->VolatileFileHandle,
				     dup_ext->PersistentFileHandle);
	if (!fp_in) {
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	fp_out = ksmbd_lookup_fd_fast(work, id);
	if (!fp_out) {
		ksmbd_fd_put(work, fp_in);
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	/* MS-SMB2 §3.3.5.15.7: source needs READ, destination needs WRITE */
	if (!(fp_in->daccess & FILE_READ_DATA_LE)) {
		ret = -EACCES;
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		goto out;
	}
	if (!(fp_out->daccess & FILE_WRITE_DATA_LE)) {
		ret = -EACCES;
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		goto out;
	}

	src_off = le64_to_cpu(dup_ext->SourceFileOffset);
	dst_off = le64_to_cpu(dup_ext->TargetFileOffset);
	length = le64_to_cpu(dup_ext->ByteCount);

	/* Validate offset+length doesn't overflow */
	if (length > 0 &&
	    (src_off + length < src_off || dst_off + length < dst_off)) {
		ret = -EINVAL;
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		goto out;
	}

	cloned = vfs_clone_file_range(fp_in->filp, src_off,
				      fp_out->filp, dst_off, length, 0);
	if (cloned != length) {
		/*
		 * Clone may fail on filesystems that don't support
		 * reflink (e.g. ext4).  Fall back to copy_file_range
		 * which does a data copy.
		 */
		cloned = vfs_copy_file_range(fp_in->filp, src_off,
					     fp_out->filp, dst_off,
					     length, 0);
		if (cloned != length) {
			if (cloned < 0)
				ret = cloned;
			else
				ret = -EINVAL;
		}
	}

	if (ret) {
		if (ret == -EINVAL || ret == -EOPNOTSUPP || ret == -EXDEV)
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
		else if (ret == -ENOSPC || ret == -EFBIG)
			rsp->hdr.Status = STATUS_DISK_FULL;
		else
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
	}

	rsp->VolatileFileId = id;
	rsp->PersistentFileId = fp_out->persistent_id;
	*out_len = 0;
out:
	ksmbd_fd_put(work, fp_in);
	ksmbd_fd_put(work, fp_out);
	return ret;
}

/*
 * MS-FSCC 2.3.8 FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX
 *
 * Extended version with Flags field. Key flag:
 * DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC.
 */

#define DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC 0x00000001

struct duplicate_extents_data_ex {
	__le32 StructureSize;
	__le32 Reserved;
	__u64  PersistentFileHandle;  /* opaque endianness */
	__u64  VolatileFileHandle;
	__le64 SourceFileOffset;
	__le64 TargetFileOffset;
	__le64 ByteCount;
	__le32 Flags;
} __packed;

static int fsctl_duplicate_extents_ex_handler(struct ksmbd_work *work,
					      u64 id, void *in_buf,
					      unsigned int in_buf_len,
					      unsigned int max_out_len,
					      struct smb2_ioctl_rsp *rsp,
					      unsigned int *out_len)
{
	struct duplicate_extents_data_ex *dup_ext;
	struct ksmbd_file *fp_in = NULL, *fp_out = NULL;
	loff_t src_off, dst_off, length, cloned;
	int ret = 0;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(*dup_ext)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	dup_ext = (struct duplicate_extents_data_ex *)in_buf;

	/*
	 * F4: MS-FSCC 2.3.8 Flags field — explicit ATOMIC flag handling.
	 *
	 * DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC (0x00000001): client
	 * requests that the extent duplication be performed atomically so
	 * the source range is never observed in a partial state.  The spec
	 * says the server SHOULD support this; it is not MUST.
	 *
	 * vfs_clone_file_range() on reflink-capable filesystems (btrfs, xfs)
	 * is inherently atomic at the VFS level, so this flag is honored
	 * implicitly for those filesystems.  For the vfs_copy_file_range()
	 * fallback path, full atomicity cannot be guaranteed, but we proceed
	 * rather than reject — consistent with the SHOULD requirement.
	 */
	if (le32_to_cpu(dup_ext->Flags) & DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC)
		ksmbd_debug(SMB,
			    "DUPLICATE_EXTENTS_EX: ATOMIC flag set — "
			    "honored via vfs_clone_file_range() where supported\n");

	fp_in = ksmbd_lookup_fd_slow(work, dup_ext->VolatileFileHandle,
				     dup_ext->PersistentFileHandle);
	if (!fp_in) {
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	fp_out = ksmbd_lookup_fd_fast(work, id);
	if (!fp_out) {
		ksmbd_fd_put(work, fp_in);
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		return -ENOENT;
	}

	src_off = le64_to_cpu(dup_ext->SourceFileOffset);
	dst_off = le64_to_cpu(dup_ext->TargetFileOffset);
	length = le64_to_cpu(dup_ext->ByteCount);

	/*
	 * Use vfs_clone_file_range() which is atomic on filesystems
	 * that support reflink (btrfs, xfs). The ATOMIC flag is
	 * honored implicitly. Fall back to vfs_copy_file_range()
	 * if clone is not supported.
	 */
	cloned = vfs_clone_file_range(fp_in->filp, src_off,
				      fp_out->filp, dst_off, length, 0);
	if (cloned == -EXDEV || cloned == -EOPNOTSUPP) {
		ret = -EOPNOTSUPP;
		goto out;
	} else if (cloned != length) {
		cloned = vfs_copy_file_range(fp_in->filp, src_off,
					     fp_out->filp, dst_off,
					     length, 0);
		if (cloned != length) {
			if (cloned < 0)
				ret = cloned;
			else
				ret = -EINVAL;
		}
	}

	rsp->VolatileFileId = id;
	rsp->PersistentFileId = fp_out->persistent_id;
	*out_len = 0;
out:
	ksmbd_fd_put(work, fp_in);
	ksmbd_fd_put(work, fp_out);
	return ret;
}

/*
 * MS-FSCC 2.3.39 MARK_HANDLE_INFO — input buffer for FSCTL_MARK_HANDLE.
 *
 * Fields:
 *   UsnSourceInfo  - advisory hint about the source of the change (USN journal).
 *                    Values: 0x00000001 (DATA_MANAGEMENT),
 *                            0x00000002 (AUXILIARY_DATA),
 *                            0x00000004 (REPLICATION_MANAGEMENT).
 *   VolumeGuid     - GUID of the volume; must be zero for non-ReFS volumes.
 *   HandleInfo     - flags for the handle (e.g., MARK_HANDLE_READ_COPY = 0x80).
 *   CopyNumber     - advisory hint: which storage copy to read from (ReFS/SMB 3.1.1).
 */
struct mark_handle_info {
	__le32 UsnSourceInfo;
	__u8   VolumeGuid[16];
	__le32 HandleInfo;
	__le32 CopyNumber;
} __packed;

/**
 * fsctl_mark_handle_handler() - FSCTL_MARK_HANDLE
 *
 * Marks a file handle for special behavior (USN journal, backup
 * semantics, CopyNumber hint for multi-copy ReFS storage).
 * Accept as advisory hint with file handle validation.
 *
 * MS-SMB2 §3.3.5.15.19: pass-through to object store.  Linux has no
 * equivalent for USN journal marking; log the advisory fields at debug
 * level and succeed.
 */
static int fsctl_mark_handle_handler(struct ksmbd_work *work,
				     u64 id, void *in_buf,
				     unsigned int in_buf_len,
				     unsigned int max_out_len,
				     struct smb2_ioctl_rsp *rsp,
				     unsigned int *out_len)
{
	struct ksmbd_file *fp;

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	/*
	 * F5: Parse and log UsnSourceInfo and CopyNumber advisory fields.
	 * These are hints — no behavior change is required on Linux, but
	 * they should not be silently dropped per spec (MS-FSCC §2.3.39).
	 */
	if (in_buf_len >= sizeof(struct mark_handle_info)) {
		const struct mark_handle_info *mhi =
			(const struct mark_handle_info *)in_buf;

		ksmbd_debug(SMB,
			    "MARK_HANDLE: UsnSourceInfo=0x%08x HandleInfo=0x%08x "
			    "CopyNumber=%u (advisory, no Linux equivalent)\n",
			    le32_to_cpu(mhi->UsnSourceInfo),
			    le32_to_cpu(mhi->HandleInfo),
			    le32_to_cpu(mhi->CopyNumber));
	}

	ksmbd_fd_put(work, fp);
	*out_len = 0;
	return 0;
}

static int fsctl_set_sparse_handler(struct ksmbd_work *work,
				    u64 id, void *in_buf,
				    unsigned int in_buf_len,
				    unsigned int max_out_len,
				    struct smb2_ioctl_rsp *rsp,
				    unsigned int *out_len)
{
	struct file_sparse *sparse;
	struct ksmbd_file *fp;
	__le32 old_fattr;
	int ret = 0;

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	/* MS-FSCC §2.3.64 / MS-SMB2 §3.3.5.15.5: directories cannot be sparse */
	if (S_ISDIR(file_inode(fp->filp)->i_mode)) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	/*
	 * MS-FSCC §2.3.64: handle must have FILE_WRITE_DATA,
	 * FILE_WRITE_ATTRIBUTES, or FILE_APPEND_DATA.
	 */
	if (!(fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE |
			     FILE_WRITE_ATTRIBUTES_LE))) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	old_fattr = fp->f_ci->m_fattr;

	/*
	 * MS-FSCC §2.3.64: If the InputBuffer is not large enough to
	 * contain the FSCTL_SET_SPARSE buffer, the file is set to sparse.
	 */
	if (in_buf_len >= sizeof(struct file_sparse)) {
		sparse = (struct file_sparse *)in_buf;
		if (sparse->SetSparse)
			fp->f_ci->m_fattr |= ATTR_SPARSE_FILE_LE;
		else
			fp->f_ci->m_fattr &= ~ATTR_SPARSE_FILE_LE;
	} else {
		fp->f_ci->m_fattr |= ATTR_SPARSE_FILE_LE;
	}

	ret = fsctl_persist_dos_attrs(work, fp, old_fattr);

	ksmbd_fd_put(work, fp);
	*out_len = 0;
	return ret;
}

static int fsctl_set_zero_data_handler(struct ksmbd_work *work,
				       u64 id, void *in_buf,
				       unsigned int in_buf_len,
				       unsigned int max_out_len,
				       struct smb2_ioctl_rsp *rsp,
				       unsigned int *out_len)
{
	struct file_zero_data_information *zero_data;
	struct ksmbd_file *fp;
	loff_t off, len, bfz;
	int ret = 0;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(*zero_data)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	zero_data = (struct file_zero_data_information *)in_buf;
	off = le64_to_cpu(zero_data->FileOffset);
	bfz = le64_to_cpu(zero_data->BeyondFinalZero);
	if (off < 0 || bfz < 0 || off > bfz) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	len = bfz - off;
	if (len) {
		fp = ksmbd_lookup_fd_fast(work, id);
		if (!fp) {
			rsp->hdr.Status = STATUS_INVALID_HANDLE;
			return -ENOENT;
		}

		/*
		 * Verify the file handle was opened with write access.
		 * The tree-level writable check above guards the share,
		 * but the individual handle must also carry write
		 * permission in its daccess mask.
		 */
		if (!(fp->daccess & FILE_WRITE_DATA_LE)) {
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
			return -EACCES;
		}

		ret = ksmbd_vfs_zero_data(work, fp, off, len);
		ksmbd_fd_put(work, fp);
		if (ret)
			return ret;
	}

	*out_len = 0;
	return 0;
}

static int fsctl_query_allocated_ranges_handler(struct ksmbd_work *work,
						u64 id, void *in_buf,
						unsigned int in_buf_len,
						unsigned int max_out_len,
						struct smb2_ioctl_rsp *rsp,
						unsigned int *out_len)
{
	struct file_allocated_range_buffer *in_range;
	struct file_allocated_range_buffer *out_range;
	struct ksmbd_file *fp;
	unsigned int max_entries, out_count = 0;
	loff_t start, length;
	int ret;

	if (in_buf_len < sizeof(*in_range)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	max_entries = max_out_len / sizeof(*out_range);

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	/* MS-FSCC §2.3.36: handle must have FILE_READ_DATA */
	if (!(fp->daccess & FILE_READ_DATA_LE)) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	in_range = (struct file_allocated_range_buffer *)in_buf;
	start = le64_to_cpu(in_range->file_offset);
	length = le64_to_cpu(in_range->length);
	if (start < 0 || length < 0) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	/*
	 * If no space for output, query with 0 entries.  If there are
	 * no allocated ranges (e.g. zero-length file), return OK with
	 * empty output.  If there are ranges, return BUFFER_TOO_SMALL.
	 */

	/*
	 * Flush dirty data so that SEEK_DATA/SEEK_HOLE reflect the current
	 * allocation state (e.g. after FSCTL_SET_ZERO_DATA punch-holes).
	 */
	vfs_fsync(fp->filp, 1);

	out_range = (struct file_allocated_range_buffer *)&rsp->Buffer[0];
	ret = ksmbd_vfs_fqar_lseek(fp, start, length,
				   out_range, max_entries, &out_count);
	ksmbd_fd_put(work, fp);

	if (ret == -E2BIG) {
		if (!max_entries) {
			/*
			 * Output buffer has zero space but there are
			 * allocated ranges to report.
			 */
			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
			return -ENOSPC;
		}
		rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
		ret = 0;
	} else if (ret) {
		out_count = 0;
		return ret;
	}

	*out_len = out_count * sizeof(*out_range);
	return 0;
}

/**
 * fsctl_validate_negotiate_info_handler() - FSCTL_VALIDATE_NEGOTIATE_INFO
 *
 * Validates that the negotiation parameters match what the server
 * agreed on, preventing downgrade attacks (MS-SMB2 §3.3.5.15.12).
 *
 * On validation mismatch MS-SMB2 §3.3.5.15.12 requires the server to
 * terminate the transport connection WITHOUT sending an error response.
 */
VISIBLE_IF_KUNIT int fsctl_validate_negotiate_info_handler(struct ksmbd_work *work,
						  u64 id, void *in_buf,
						  unsigned int in_buf_len,
						  unsigned int max_out_len,
						  struct smb2_ioctl_rsp *rsp,
						  unsigned int *out_len)
{
	struct ksmbd_conn *conn = work->conn;
	struct validate_negotiate_info_req *neg_req;
	struct validate_negotiate_info_rsp *neg_rsp;
	int dialect;

	if (in_buf_len < offsetof(struct validate_negotiate_info_req,
				  Dialects))
		return -EINVAL;

	if (max_out_len < sizeof(struct validate_negotiate_info_rsp))
		return -EINVAL;

	neg_req = (struct validate_negotiate_info_req *)in_buf;

	if (in_buf_len < offsetof(struct validate_negotiate_info_req, Dialects) +
			le16_to_cpu(neg_req->DialectCount) * sizeof(__le16))
		return -EINVAL;

	dialect = ksmbd_lookup_dialect_by_id(neg_req->Dialects,
					     neg_req->DialectCount);
	if (dialect == BAD_PROT_ID || dialect != conn->dialect)
		goto vni_mismatch;

	if (memcmp(neg_req->Guid, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE))
		goto vni_mismatch;

	if (le16_to_cpu(neg_req->SecurityMode) != conn->cli_sec_mode)
		goto vni_mismatch;

	if (le32_to_cpu(neg_req->Capabilities) != conn->cli_cap)
		goto vni_mismatch;

	neg_rsp = (struct validate_negotiate_info_rsp *)&rsp->Buffer[0];
	neg_rsp->Capabilities = cpu_to_le32(conn->vals->capabilities);
	/*
	 * MS-SMB2 §2.2.32.6: ServerGuid MUST be the server's GUID as
	 * returned in the NEGOTIATE response (F.7).
	 */
	memcpy(neg_rsp->Guid, server_conf.server_guid, SMB2_CLIENT_GUID_SIZE);
	neg_rsp->SecurityMode = cpu_to_le16(conn->srv_sec_mode);
	neg_rsp->Dialect = cpu_to_le16(conn->dialect);

	rsp->PersistentFileId = SMB2_NO_FID;
	rsp->VolatileFileId = SMB2_NO_FID;

	*out_len = sizeof(struct validate_negotiate_info_rsp);
	return 0;

vni_mismatch:
	/*
	 * MS-SMB2 §3.3.5.15.12: "If the validation fails, the server MUST
	 * terminate the transport connection."  Do NOT send an error response.
	 */
	ksmbd_debug(SMB,
		    "VALIDATE_NEGOTIATE_INFO mismatch - terminating connection\n");
	ksmbd_conn_set_exiting(conn);
	work->send_no_response = 1;
	return -EINVAL;
}
EXPORT_SYMBOL_IF_KUNIT(fsctl_validate_negotiate_info_handler);

/**
 * fsctl_pipe_transceive_handler() - FSCTL_PIPE_TRANSCEIVE
 *
 * Forwards an RPC request to the userspace daemon and copies
 * the response into the SMB2 output buffer.
 */
static int fsctl_pipe_transceive_handler(struct ksmbd_work *work,
					  u64 id, void *in_buf,
					  unsigned int in_buf_len,
					  unsigned int max_out_len,
					  struct smb2_ioctl_rsp *rsp,
					  unsigned int *out_len)
{
	struct ksmbd_rpc_command *rpc_resp;
	unsigned int capped_out_len;
	int nbytes = 0;

	/*
	 * Validate the RPC handle against the session's pipe table.
	 * IPC$ pipe FIDs are not VFS file-table entries.
	 */
	down_read(&work->sess->rpc_lock);
	if (!ksmbd_session_rpc_method(work->sess, id)) {
		up_read(&work->sess->rpc_lock);
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}
	up_read(&work->sess->rpc_lock);

	capped_out_len = min_t(u32, KSMBD_IPC_MAX_PAYLOAD, max_out_len);

	rpc_resp = ksmbd_rpc_ioctl(work->sess, id, in_buf, in_buf_len);
	if (rpc_resp) {
		if (rpc_resp->flags == KSMBD_RPC_SOME_NOT_MAPPED) {
			/*
			 * set STATUS_SOME_NOT_MAPPED response
			 * for unknown domain sid.
			 */
			rsp->hdr.Status = STATUS_SOME_NOT_MAPPED;
		} else if (rpc_resp->flags == KSMBD_RPC_ENOTIMPLEMENTED) {
			/*
			 * Gracefully allow clients probing pipe
			 * transceive capability on configurations
			 * without userspace RPC backend support.
			 */
			nbytes = 0;
			goto out;
		} else if (rpc_resp->flags == KSMBD_RPC_EBAD_FID) {
			rsp->hdr.Status = STATUS_PIPE_DISCONNECTED;
			goto out;
		} else if (rpc_resp->flags != KSMBD_RPC_OK) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			goto out;
		}

		nbytes = rpc_resp->payload_sz;
		if (nbytes == 0) {
			kvfree(rpc_resp);
			return fsctl_pipe_transceive_async(work, rsp, id,
							   capped_out_len);
		}
		if (rpc_resp->payload_sz > capped_out_len) {
			rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
			nbytes = capped_out_len;
		}

		/*
		 * A zero-byte RPC response is valid per spec; do not error out.
		 * The STATUS_BUFFER_OVERFLOW check above already handles
		 * the truncation case.
		 */
		if (nbytes > 0)
			memcpy((char *)rsp->Buffer, rpc_resp->payload, nbytes);
	}
out:
	kvfree(rpc_resp);
	*out_len = nbytes;
	return 0;
}

/*
 * MS-FSCC 2.3.22 FSCTL_FILESYSTEM_GET_STATISTICS
 *
 * Return filesystem type + basic statistics. Since Linux doesn't expose
 * per-type stats in the Windows format, we return the base structure with
 * NTFS type identifier and zero-filled counters.
 */

#define FILESYSTEM_STATISTICS_TYPE_NTFS	0x0002

struct filesystem_statistics {
	__le16 FileSystemType;
	__le16 Version;
	__le32 SizeOfCompleteStructure;
	__le32 UserFileReads;
	__le32 UserFileReadBytes;
	__le32 UserDiskReads;
	__le32 UserFileWrites;
	__le32 UserFileWriteBytes;
	__le32 UserDiskWrites;
	__le32 MetaDataReads;
	__le32 MetaDataReadBytes;
	__le32 MetaDataDiskReads;
	__le32 MetaDataWrites;
	__le32 MetaDataWriteBytes;
	__le32 MetaDataDiskWrites;
} __packed;

static int fsctl_filesystem_get_stats_handler(struct ksmbd_work *work,
					      u64 id, void *in_buf,
					      unsigned int in_buf_len,
					      unsigned int max_out_len,
					      struct smb2_ioctl_rsp *rsp,
					      unsigned int *out_len)
{
	struct filesystem_statistics *stats;
	unsigned int struct_sz = sizeof(struct filesystem_statistics);

	if (max_out_len < struct_sz) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	stats = (struct filesystem_statistics *)&rsp->Buffer[0];
	memset(stats, 0, struct_sz);
	stats->FileSystemType = cpu_to_le16(FILESYSTEM_STATISTICS_TYPE_NTFS);
	stats->Version = cpu_to_le16(1);
	stats->SizeOfCompleteStructure = cpu_to_le32(struct_sz);

	*out_len = struct_sz;
	return 0;
}

/**
 * fsctl_set_zero_on_dealloc_handler() - FSCTL_SET_ZERO_ON_DEALLOCATION
 *
 * Hint that deallocated space should be zeroed. Linux filesystems
 * already zero deallocated blocks (ext4/xfs/btrfs), so accept as hint.
 */
static int fsctl_set_zero_on_dealloc_handler(struct ksmbd_work *work,
					     u64 id, void *in_buf,
					     unsigned int in_buf_len,
					     unsigned int max_out_len,
					     struct smb2_ioctl_rsp *rsp,
					     unsigned int *out_len)
{
	struct ksmbd_file *fp;

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	ksmbd_fd_put(work, fp);
	*out_len = 0;
	return 0;
}

/**
 * fsctl_set_encryption_handler() - FSCTL_SET_ENCRYPTION
 *
 * Per-file encryption (EFS). fscrypt key management model doesn't map
 * to the SMB SET_ENCRYPTION request. Return STATUS_NOT_SUPPORTED.
 */
static int fsctl_set_encryption_handler(struct ksmbd_work *work,
					u64 id, void *in_buf,
					unsigned int in_buf_len,
					unsigned int max_out_len,
					struct smb2_ioctl_rsp *rsp,
					unsigned int *out_len)
{
	rsp->hdr.Status = STATUS_NOT_SUPPORTED;
	*out_len = 0;
	return -EOPNOTSUPP;
}

/*
 * MS-FSCC 2.3.39 FSCTL_QUERY_FILE_REGIONS
 *
 * Returns information about file regions.  Uses vfs_llseek(SEEK_DATA) and
 * vfs_llseek(SEEK_HOLE) to enumerate actual data regions in sparse files
 * (F3 — verified: Track F commit 49e3c3f).  Falls back to returning the
 * full requested range as a single valid-data region on filesystems that
 * do not support sparse seeking (returns -ENXIO or -EOPNOTSUPP).
 */

struct file_region_input {
	__le64 FileOffset;
	__le64 Length;
	__le32 DesiredUsage;
	__le32 Reserved;
} __packed;

#define FILE_REGION_USAGE_VALID_CACHED_DATA	0x00000001

struct file_region_output {
	__le32 Flags;
	__le32 TotalRegionEntryCount;
	__le32 RegionEntryCount;
	__le32 Reserved;
} __packed;

struct file_region_info {
	__le64 FileOffset;
	__le64 Length;
	__le32 Usage;
	__le32 Reserved;
} __packed;

static int fsctl_query_file_regions_handler(struct ksmbd_work *work,
					    u64 id, void *in_buf,
					    unsigned int in_buf_len,
					    unsigned int max_out_len,
					    struct smb2_ioctl_rsp *rsp,
					    unsigned int *out_len)
{
	struct ksmbd_file *fp;
	struct file_region_input *input;
	struct file_region_output *output;
	struct file_region_info *region;
	struct inode *inode;
	u64 req_offset, req_length, file_size;
	unsigned int hdr_sz = sizeof(*output);
	unsigned int entry_sz = sizeof(*region);
	unsigned int max_entries;
	unsigned int region_count = 0;
	loff_t data_start, hole_start, cur;
	loff_t end_offset;

	if (max_out_len < hdr_sz + entry_sz) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	inode = file_inode(fp->filp);
	file_size = i_size_read(inode);

	if (in_buf_len >= sizeof(*input)) {
		input = (struct file_region_input *)in_buf;
		req_offset = le64_to_cpu(input->FileOffset);
		req_length = le64_to_cpu(input->Length);
	} else {
		req_offset = 0;
		req_length = file_size;
	}

	/* Clamp to file size */
	if (req_offset >= file_size) {
		req_offset = file_size;
		req_length = 0;
	} else if (req_offset + req_length > file_size) {
		req_length = file_size - req_offset;
	}

	output = (struct file_region_output *)&rsp->Buffer[0];
	memset(output, 0, hdr_sz);
	region = (struct file_region_info *)((char *)output + hdr_sz);

	max_entries = (max_out_len - hdr_sz) / entry_sz;
	if (max_entries == 0) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	end_offset = (loff_t)(req_offset + req_length);
	cur = (loff_t)req_offset;

	/*
	 * F-05: Use SEEK_DATA / SEEK_HOLE to enumerate actual data regions.
	 * If the filesystem does not support sparse seeking (returns -ENXIO
	 * or -EOPNOTSUPP), fall back to returning the full requested range
	 * as a single valid-data region.
	 *
	 * TotalRegionEntryCount must reflect the total number of data regions
	 * regardless of buffer size (MS-FSCC §2.3.39.2). Do a dry-run first
	 * pass to count total regions, then fill limited by max_entries.
	 */
	data_start = vfs_llseek(fp->filp, cur, SEEK_DATA);
	if (data_start < 0) {
		/* Filesystem does not support sparse seek — return full range */
		if (req_length > 0 && region_count < max_entries) {
			memset(&region[0], 0, entry_sz);
			region[0].FileOffset = cpu_to_le64(req_offset);
			region[0].Length = cpu_to_le64(req_length);
			region[0].Usage =
				cpu_to_le32(FILE_REGION_USAGE_VALID_CACHED_DATA);
			region_count = 1;
		}
		/* TotalRegionEntryCount == RegionEntryCount in fallback */
		goto done;
	}

	/*
	 * Dry-run: count total data regions without writing to output buffer.
	 * This gives TotalRegionEntryCount for clients with small buffers.
	 */
	{
		unsigned int total_region_count = 0;
		loff_t dry_cur = (loff_t)req_offset;

		while (dry_cur < end_offset) {
			loff_t d, h;

			d = vfs_llseek(fp->filp, dry_cur, SEEK_DATA);
			if (d < 0 || d >= end_offset)
				break;
			h = vfs_llseek(fp->filp, d, SEEK_HOLE);
			if (h < 0)
				h = end_offset;
			if (h > end_offset)
				h = end_offset;
			if (d < dry_cur)
				d = dry_cur;
			if (d < h)
				total_region_count++;
			dry_cur = h;
		}

		/* Fill pass: write entries up to max_entries into output */
		cur = (loff_t)req_offset;
		while (cur < end_offset && region_count < max_entries) {
			loff_t region_end;

			data_start = vfs_llseek(fp->filp, cur, SEEK_DATA);
			if (data_start < 0 || data_start >= end_offset)
				break;

			hole_start = vfs_llseek(fp->filp, data_start, SEEK_HOLE);
			if (hole_start < 0)
				hole_start = end_offset;
			if (hole_start > end_offset)
				hole_start = end_offset;

			if (data_start < cur)
				data_start = cur;

			region_end = hole_start;

			if (data_start >= region_end) {
				cur = hole_start;
				continue;
			}

			memset(&region[region_count], 0, entry_sz);
			region[region_count].FileOffset = cpu_to_le64((u64)data_start);
			region[region_count].Length =
				cpu_to_le64((u64)(region_end - data_start));
			region[region_count].Usage =
				cpu_to_le32(FILE_REGION_USAGE_VALID_CACHED_DATA);
			region_count++;

			cur = hole_start;
		}

		output->TotalRegionEntryCount = cpu_to_le32(total_region_count);
		output->RegionEntryCount = cpu_to_le32(region_count);
	}
	goto out_put;

done:
	output->TotalRegionEntryCount = cpu_to_le32(region_count);
	output->RegionEntryCount = cpu_to_le32(region_count);
out_put:

	/* Restore file position (it was modified by vfs_llseek) */
	vfs_llseek(fp->filp, 0, SEEK_SET);

	*out_len = hdr_sz + region_count * entry_sz;
	ksmbd_fd_put(work, fp);
	return 0;
}

/*
 * MS-FSCC 2.3.49 / 2.3.65 FSCTL_GET/SET_INTEGRITY_INFORMATION
 *
 * On Windows, used with ReFS for data integrity streams. On Linux,
 * btrfs has checksumming (always on), ext4 has metadata checksums.
 * Return default settings matching non-ReFS behavior.
 */

struct fsctl_get_integrity_info_output {
	__le16 ChecksumAlgorithm;
	__le16 Reserved;
	__le32 Flags;
	__le32 ChecksumChunkSizeInBytes;
	__le32 ClusterSizeInBytes;
} __packed;

#define CHECKSUM_TYPE_NONE		0x0000
#define FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF 0x00000001

static int fsctl_get_integrity_info_handler(struct ksmbd_work *work,
					    u64 id, void *in_buf,
					    unsigned int in_buf_len,
					    unsigned int max_out_len,
					    struct smb2_ioctl_rsp *rsp,
					    unsigned int *out_len)
{
	struct fsctl_get_integrity_info_output *info;
	struct ksmbd_file *fp;
	unsigned int sz = sizeof(*info);

	/* F-01: validate file handle before returning integrity info */
	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -EBADF;
	}
	ksmbd_fd_put(work, fp);

	if (max_out_len < sz) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	info = (struct fsctl_get_integrity_info_output *)&rsp->Buffer[0];
	memset(info, 0, sz);
	info->ChecksumAlgorithm = cpu_to_le16(CHECKSUM_TYPE_NONE);
	info->Flags = cpu_to_le32(FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF);
	info->ChecksumChunkSizeInBytes = cpu_to_le32(0);
	info->ClusterSizeInBytes = cpu_to_le32(4096);

	*out_len = sz;
	return 0;
}

/**
 * fsctl_set_integrity_info_handler() - FSCTL_SET_INTEGRITY_INFORMATION
 *
 * Accept silently. Linux filesystems handle integrity internally
 * (btrfs checksums, ext4 metadata checksums). Matches Windows
 * behavior on non-ReFS volumes.
 */
static int fsctl_set_integrity_info_handler(struct ksmbd_work *work,
					    u64 id, void *in_buf,
					    unsigned int in_buf_len,
					    unsigned int max_out_len,
					    struct smb2_ioctl_rsp *rsp,
					    unsigned int *out_len)
{
	*out_len = 0;
	return 0;
}

/*
 * MS-FSCC 2.3.53 / 2.3.55 FSCTL_OFFLOAD_READ / FSCTL_OFFLOAD_WRITE
 *
 * ODX (Offload Data Transfer) uses opaque tokens.  OFFLOAD_READ generates
 * a server-local token encoding the source inode identity and range.
 * OFFLOAD_WRITE validates the token, locates the source file within the
 * session's open handles, and uses vfs_copy_file_range() to perform the
 * data transfer.
 */

#define STORAGE_OFFLOAD_TOKEN_SIZE	512
#define KSMBD_ODX_TOKEN_MAGIC		0x4B534D42  /* "KSMB" */

struct ksmbd_odx_token {
	__le32 magic;
	__le64 file_id;
	__le64 offset;
	__le64 length;
	__le64 generation;
	u8     nonce[16];
	u8     reserved[STORAGE_OFFLOAD_TOKEN_SIZE -
			sizeof(__le32) - sizeof(__le64) * 4 - 16];
} __packed;

static_assert(sizeof(struct ksmbd_odx_token) == STORAGE_OFFLOAD_TOKEN_SIZE,
	      "ksmbd_odx_token must be exactly STORAGE_OFFLOAD_TOKEN_SIZE bytes");

/*
 * Server-side ODX token registry.  Each token issued by OFFLOAD_READ is
 * recorded here keyed by its random nonce.  OFFLOAD_WRITE validates
 * tokens by looking them up in this table, which prevents forgery --
 * an attacker cannot construct a valid token without the server having
 * issued it.
 */
/* Default ODX token lifetime when client specifies 0: 30 seconds */
#define KSMBD_ODX_DEFAULT_TTL_MS	30000

struct ksmbd_odx_token_entry {
	struct hlist_node	node;
	u8			nonce[16];
	__le64			file_id;
	__le64			offset;
	__le64			length;
	__le64			generation;
	unsigned long		expire_jiffies; /* absolute expiry time */
	__u64			session_id;	/* session that created this token */
};

#define KSMBD_ODX_TOKEN_HASH_BITS	8
static DEFINE_HASHTABLE(odx_token_table, KSMBD_ODX_TOKEN_HASH_BITS);
static DEFINE_SPINLOCK(odx_token_lock);

/* C-01: Bounded ODX token table — prevent remote kernel OOM DoS */
#define KSMBD_ODX_MAX_GLOBAL_TOKENS	4096
#define KSMBD_ODX_MAX_PER_SESSION	64
#define KSMBD_ODX_GC_INTERVAL_MS	30000	/* GC every 30 seconds */

static atomic_t odx_token_count = ATOMIC_INIT(0);
static void odx_gc_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(odx_gc_dwork, odx_gc_work_fn);

static u32 odx_nonce_hash(const u8 *nonce)
{
	/*
	 * Use jhash over all 16 nonce bytes to produce a well-distributed
	 * hash key, avoiding the O(n) collision degradation that occurs
	 * when only the first 4 bytes are used (P1-ODX-01).
	 */
	return jhash(nonce, 16, 0);
}

static void odx_token_store(struct ksmbd_work *work,
			    const struct ksmbd_odx_token *token,
			    u32 ttl_ms)
{
	struct ksmbd_odx_token_entry *entry;
	__u64 caller_session_id = work->sess ? work->sess->id : 0;
	int per_sess_count = 0;

	/* C-01: Enforce global token cap to prevent kernel OOM DoS */
	if (atomic_read(&odx_token_count) >= KSMBD_ODX_MAX_GLOBAL_TOKENS) {
		ksmbd_debug(SMB, "ODX: global token limit (%d) reached, dropping\n",
			    KSMBD_ODX_MAX_GLOBAL_TOKENS);
		return;
	}

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	memcpy(entry->nonce, token->nonce, 16);
	entry->file_id = token->file_id;
	entry->offset = token->offset;
	entry->length = token->length;
	entry->generation = token->generation;

	/* F1: Bind token to the issuing session to prevent cross-session reuse */
	entry->session_id = caller_session_id;

	/* F.9: Respect client-provided TTL; default to 30s if zero */
	if (ttl_ms == 0)
		ttl_ms = KSMBD_ODX_DEFAULT_TTL_MS;
	entry->expire_jiffies = jiffies + msecs_to_jiffies(ttl_ms);

	spin_lock(&odx_token_lock);
	if (caller_session_id) {
		struct ksmbd_odx_token_entry *e;
		struct hlist_node *tmp2;
		int bkt2;

		hash_for_each_safe(odx_token_table, bkt2, tmp2, e, node) {
			if (e->session_id == caller_session_id &&
			    ++per_sess_count >= KSMBD_ODX_MAX_PER_SESSION) {
				spin_unlock(&odx_token_lock);
				ksmbd_debug(SMB,
					    "ODX: per-session limit (%d) reached for sess %llu\n",
					    KSMBD_ODX_MAX_PER_SESSION,
					    caller_session_id);
				kfree(entry);
				return;
			}
		}
	}
	atomic_inc(&odx_token_count);
	hash_add(odx_token_table, &entry->node,
		 odx_nonce_hash(entry->nonce));
	spin_unlock(&odx_token_lock);
}

static bool odx_token_validate(struct ksmbd_work *work,
			       const struct ksmbd_odx_token *token)
{
	struct ksmbd_odx_token_entry *entry;
	struct hlist_node *tmp;
	u32 key = odx_nonce_hash(token->nonce);
	unsigned long now = jiffies;
	__u64 caller_session_id = work->sess ? work->sess->id : 0;
	bool found = false;

	spin_lock(&odx_token_lock);
	/*
	 * F.9: Use hash_for_each_possible_safe so we can lazily expire stale
	 * tokens in the same pass without needing a second lock acquisition.
	 */
	hash_for_each_possible_safe(odx_token_table, entry, tmp, node, key) {
		/* Lazily expire stale tokens we encounter in this bucket */
		if (time_after(now, entry->expire_jiffies)) {
			ksmbd_debug(SMB, "ODX: expiring stale token\n");
			hash_del(&entry->node);
			kfree(entry);
			atomic_dec(&odx_token_count);
			continue;
		}

		if (memcmp(entry->nonce, token->nonce, 16) == 0 &&
		    entry->file_id == token->file_id &&
		    entry->offset == token->offset &&
		    entry->length == token->length &&
		    entry->generation == token->generation) {
			/*
			 * F1: Security check — reject cross-session token use.
			 * A token issued by session A MUST NOT be redeemable by
			 * session B.  This prevents an attacker who has captured
			 * a nonce from impersonating another session's ODX token.
			 */
			if (entry->session_id != caller_session_id) {
				ksmbd_debug(SMB,
					    "ODX: cross-session token rejected "
					    "(token sess %llu, caller sess %llu)\n",
					    entry->session_id,
					    caller_session_id);
				break;
			}
			/* Consume the token: one-time use */
			hash_del(&entry->node);
			kfree(entry);
			atomic_dec(&odx_token_count);
			found = true;
			break;
		}
	}
	spin_unlock(&odx_token_lock);

	return found;
}

static void odx_gc_work_fn(struct work_struct *work)
{
	struct ksmbd_odx_token_entry *entry;
	struct hlist_node *tmp;
	int bkt;
	unsigned long now = jiffies;

	spin_lock(&odx_token_lock);
	hash_for_each_safe(odx_token_table, bkt, tmp, entry, node) {
		if (time_after(now, entry->expire_jiffies)) {
			hash_del(&entry->node);
			kfree(entry);
			atomic_dec(&odx_token_count);
		}
	}
	spin_unlock(&odx_token_lock);

	/* Reschedule unless module is being unloaded */
	schedule_delayed_work(&odx_gc_dwork,
			      msecs_to_jiffies(KSMBD_ODX_GC_INTERVAL_MS));
}

static void odx_token_cleanup(void)
{
	struct ksmbd_odx_token_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	cancel_delayed_work_sync(&odx_gc_dwork);

	spin_lock(&odx_token_lock);
	hash_for_each_safe(odx_token_table, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}
	atomic_set(&odx_token_count, 0);
	spin_unlock(&odx_token_lock);
}

struct offload_read_input {
	__le32 Size;
	__le32 Flags;
	__le32 TokenTimeToLive;
	__le32 Reserved;
	__le64 FileOffset;
	__le64 CopyLength;
} __packed;

struct offload_read_output {
	__le32 Size;
	__le32 Flags;
	__le64 TransferLength;
	u8     Token[STORAGE_OFFLOAD_TOKEN_SIZE];
} __packed;

/* MS-FSCC 2.3.55 FSCTL_OFFLOAD_WRITE input/output */
struct offload_write_input {
	__le32 Size;
	__le32 Flags;
	__le64 FileOffset;
	__le64 CopyLength;
	__le64 TransferOffset;
	u8     Token[STORAGE_OFFLOAD_TOKEN_SIZE];
} __packed;

struct offload_write_output {
	__le32 Size;
	__le32 Flags;
	__le64 LengthWritten;
} __packed;

static int fsctl_offload_read_handler(struct ksmbd_work *work,
				      u64 id, void *in_buf,
				      unsigned int in_buf_len,
				      unsigned int max_out_len,
				      struct smb2_ioctl_rsp *rsp,
				      unsigned int *out_len)
{
	struct offload_read_input *input;
	struct offload_read_output *output;
	struct ksmbd_odx_token *token;
	struct ksmbd_file *fp;
	struct inode *inode;
	u64 offset, length, file_size;
	unsigned int out_sz = sizeof(*output);

	if (in_buf_len < sizeof(*input)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	if (max_out_len < out_sz) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	input = (struct offload_read_input *)in_buf;

	/* Validate the input Size field per MS-FSCC */
	if (le32_to_cpu(input->Size) < sizeof(*input)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	/*
	 * MS-FSCC §2.3.53: TokenTimeToLive is in milliseconds; 0 means
	 * server chooses default TTL (KSMBD_ODX_DEFAULT_TTL_MS = 30s).
	 * The TTL is passed to odx_token_store() and enforced during
	 * OFFLOAD_WRITE validation via lazy expiry (F.9).
	 */
	ksmbd_debug(SMB, "OFFLOAD_READ: TokenTimeToLive=%u ms\n",
		    le32_to_cpu(input->TokenTimeToLive));

	offset = le64_to_cpu(input->FileOffset);
	length = le64_to_cpu(input->CopyLength);

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	/* Verify the handle has read access */
	if (!(fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE))) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	inode = file_inode(fp->filp);
	file_size = i_size_read(inode);

	/* Clamp transfer length to available data */
	if (offset >= file_size)
		length = 0;
	else if (offset + length > file_size)
		length = file_size - offset;

	/*
	 * ODX-01: MS-FSCC §2.3.53 — TransferLength MUST be a multiple of
	 * the logical sector size.  Round down to sector boundary.
	 */
	{
		u32 sector_size = 512; /* default logical sector size */

		length = ALIGN_DOWN(length, sector_size);
	}

	output = (struct offload_read_output *)&rsp->Buffer[0];
	memset(output, 0, out_sz);
	output->Size = cpu_to_le32(out_sz);
	output->TransferLength = cpu_to_le64(length);

	/* Build server-local token */
	token = (struct ksmbd_odx_token *)output->Token;
	memset(token, 0, STORAGE_OFFLOAD_TOKEN_SIZE);
	token->magic = cpu_to_le32(KSMBD_ODX_TOKEN_MAGIC);
	token->file_id = cpu_to_le64(inode->i_ino);
	token->offset = cpu_to_le64(offset);
	token->length = cpu_to_le64(length);
	token->generation = cpu_to_le64(inode->i_generation);
	get_random_bytes(token->nonce, sizeof(token->nonce));

	/* Store the token server-side so OFFLOAD_WRITE can validate it */
	odx_token_store(work, token, le32_to_cpu(input->TokenTimeToLive));

	*out_len = out_sz;
	ksmbd_fd_put(work, fp);
	return 0;
}

/**
 * fsctl_offload_write_handler() - Handle FSCTL_OFFLOAD_WRITE (ODX write)
 *
 * Validates the server-local ODX token produced by a prior OFFLOAD_READ,
 * locates the source file by inode number within the session's open handles,
 * and uses vfs_copy_file_range() to perform the data transfer.
 *
 * MS-FSCC 2.3.55: The token encodes the source file identity and the range
 * to copy.  TransferOffset selects the starting position within the
 * token-described range.
 */
static int fsctl_offload_write_handler(struct ksmbd_work *work,
				       u64 id, void *in_buf,
				       unsigned int in_buf_len,
				       unsigned int max_out_len,
				       struct smb2_ioctl_rsp *rsp,
				       unsigned int *out_len)
{
	struct offload_write_input *input;
	struct offload_write_output *output;
	struct ksmbd_odx_token *token;
	struct ksmbd_file *dst_fp = NULL, *src_fp = NULL;
	struct inode *src_inode;
	loff_t src_off, dst_off, copy_len, token_off, token_len, xfer_off;
	loff_t remaining, copied_total = 0;
	ssize_t copied;
	unsigned int out_sz = sizeof(*output);
	int ret = 0;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(*input)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	if (max_out_len < out_sz) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	input = (struct offload_write_input *)in_buf;
	token = (struct ksmbd_odx_token *)input->Token;

	/* Validate the input Size field per MS-FSCC */
	if (le32_to_cpu(input->Size) < sizeof(*input)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	/* Validate the ODX token magic */
	if (le32_to_cpu(token->magic) != KSMBD_ODX_TOKEN_MAGIC) {
		ksmbd_debug(SMB,
			    "OFFLOAD_WRITE: invalid token magic 0x%08x\n",
			    le32_to_cpu(token->magic));
		rsp->hdr.Status = STATUS_INVALID_TOKEN;
		return -EINVAL;
	}

	/*
	 * Validate the token against the server-side registry.
	 * This prevents forged tokens -- only tokens issued by a prior
	 * OFFLOAD_READ are accepted.  The token is consumed (one-time use).
	 */
	if (!odx_token_validate(work, token)) {
		ksmbd_debug(SMB,
			    "OFFLOAD_WRITE: token validation failed (forged or reused)\n");
		rsp->hdr.Status = STATUS_INVALID_TOKEN;
		return -EINVAL;
	}

	token_off = le64_to_cpu(token->offset);
	token_len = le64_to_cpu(token->length);
	dst_off = le64_to_cpu(input->FileOffset);
	copy_len = le64_to_cpu(input->CopyLength);
	xfer_off = le64_to_cpu(input->TransferOffset);

	/*
	 * TransferOffset is an offset into the token's range.
	 * The actual source offset = token->offset + TransferOffset.
	 * The available length from that point = token->length - TransferOffset.
	 */
	if (token_off < 0 || xfer_off < 0 || xfer_off > token_len) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	/* Guard against signed overflow in token_off + xfer_off */
	if (check_add_overflow(token_off, xfer_off, &src_off)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	/* Clamp copy length to the available token range */
	if (copy_len == 0)
		copy_len = token_len - xfer_off;
	else if (copy_len > token_len - xfer_off)
		copy_len = token_len - xfer_off;

	if (copy_len <= 0) {
		/* Nothing to copy -- return zero bytes written */
		goto out_success;
	}

	/* Look up the destination file */
	dst_fp = ksmbd_lookup_fd_fast(work, id);
	if (!dst_fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	/*
	 * Find the source file by inode number from the token.
	 * The token encodes the inode number and generation from
	 * the OFFLOAD_READ that created it.
	 */
	src_fp = ksmbd_lookup_fd_inode_sess(work, le64_to_cpu(token->file_id));
	if (!src_fp) {
		ksmbd_debug(SMB,
			    "OFFLOAD_WRITE: source inode %llu not found in session\n",
			    le64_to_cpu(token->file_id));
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		ret = -ENOENT;
		goto out;
	}

	/* Verify the source handle has read access */
	if (!(src_fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE))) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		ret = -EACCES;
		goto out;
	}

	/*
	 * Validate the inode generation to ensure the source file
	 * is the same one that was originally read (i.e., the inode
	 * number has not been recycled).
	 */
	src_inode = file_inode(src_fp->filp);
	if (src_inode->i_generation != (u32)le64_to_cpu(token->generation)) {
		ksmbd_debug(SMB,
			    "OFFLOAD_WRITE: generation mismatch (%u vs %llu)\n",
			    src_inode->i_generation,
			    le64_to_cpu(token->generation));
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		ret = -ESTALE;
		goto out;
	}

	/* Break any level-II oplocks on the destination */
	smb_break_all_levII_oplock(work, dst_fp, 1);

	/*
	 * Perform the copy using vfs_copy_file_range().  This handles
	 * reflink, server-side copy, and splice fallback transparently.
	 * Loop to handle partial copies.
	 */
	remaining = copy_len;
	while (remaining > 0) {
		copied = vfs_copy_file_range(src_fp->filp, src_off,
					     dst_fp->filp, dst_off,
					     remaining, 0);
		if (copied <= 0) {
			if (copied == 0)
				break;
			if (copied == -EOPNOTSUPP || copied == -EXDEV) {
				/*
				 * Filesystem does not support copy_file_range
				 * between these files.  Report what we have
				 * copied so far; the client can fall back to
				 * COPYCHUNK for the remainder.
				 */
				break;
			}
			ret = copied;
			if (ret == -ENOSPC || ret == -EFBIG)
				rsp->hdr.Status = STATUS_DISK_FULL;
			else if (ret == -EACCES)
				rsp->hdr.Status = STATUS_ACCESS_DENIED;
			else
				rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
			goto out;
		}
		src_off += copied;
		dst_off += copied;
		remaining -= copied;
		copied_total += copied;
	}

out_success:
	output = (struct offload_write_output *)&rsp->Buffer[0];
	memset(output, 0, out_sz);
	output->Size = cpu_to_le32(out_sz);
	output->LengthWritten = cpu_to_le64(copied_total);
	*out_len = out_sz;

out:
	ksmbd_fd_put(work, src_fp);
	ksmbd_fd_put(work, dst_fp);
	return ret;
}

/**
 * fsctl_srv_read_hash_handler() - FSCTL_SRV_READ_HASH (BranchCache)
 *
 * BranchCache content information retrieval per MS-PCCRC.
 * Computes Content Information V1 (SHA-256) hashes for the requested
 * file range and returns them to the client for peer-to-peer caching.
 */
static int fsctl_srv_read_hash_handler(struct ksmbd_work *work,
				       u64 id, void *in_buf,
				       unsigned int in_buf_len,
				       unsigned int max_out_len,
				       struct smb2_ioctl_rsp *rsp,
				       unsigned int *out_len)
{
	struct ksmbd_file *fp;
	int ret;

	if (in_buf_len < sizeof(struct srv_read_hash_req)) {
		*out_len = 0;
		return -EINVAL;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		*out_len = 0;
		return -ENOENT;
	}

	ret = ksmbd_branchcache_read_hash(work, fp,
					  in_buf, in_buf_len,
					  &rsp->Buffer[0],
					  max_out_len);
	ksmbd_fd_put(work, fp);

	if (ret == -EOPNOTSUPP) {
		rsp->hdr.Status = STATUS_HASH_NOT_PRESENT;
		*out_len = 0;
		return -EOPNOTSUPP;
	}
	if (ret == -E2BIG) {
		rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
		*out_len = 0;
		return -EOPNOTSUPP;
	}
	if (ret < 0) {
		*out_len = 0;
		return ret;
	}

	*out_len = ret;
	return 0;
}

/*
 * POSIX-03: FSCTL_QUERY_POSIX_WHOAMI (0xC01401BA)
 *
 * Returns the effective UID, GID and supplementary group list of the
 * credentials that the server mapped the session to.  Wire format
 * (all native-endian 64/32-bit fields, as defined by samba/POSIX ext):
 *   __u64  mapping_type   (0 = SID-to-UID mapping)
 *   __u64  uid
 *   __u64  gid
 *   __u32  num_groups
 *   __u64  groups[num_groups]
 */
struct ksmbd_posix_whoami_rsp {
	__u64 mapping_type;
	__u64 uid;
	__u64 gid;
	__u32 num_groups;
	__u64 groups[];
} __packed;

static int fsctl_query_posix_whoami_handler(struct ksmbd_work *work,
					    u64 id, void *in_buf,
					    unsigned int in_buf_len,
					    unsigned int max_out_len,
					    struct smb2_ioctl_rsp *rsp,
					    unsigned int *out_len)
{
	const struct cred *cred;
	struct ksmbd_posix_whoami_rsp *resp;
	struct group_info *gi;
	unsigned int ngroups;
	unsigned int resp_size;
	unsigned int i;

	cred = get_current_cred();
	gi = cred->group_info;
	ngroups = gi ? gi->ngroups : 0;

	resp_size = (unsigned int)offsetof(struct ksmbd_posix_whoami_rsp,
					   groups) +
		    ngroups * sizeof(__u64);

	if (max_out_len < resp_size) {
		put_cred(cred);
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	resp = (struct ksmbd_posix_whoami_rsp *)rsp->Buffer;
	memset(resp, 0, resp_size);

	resp->mapping_type = 0; /* SID-to-UID mapping */
	resp->uid = from_kuid(&init_user_ns, cred->uid);
	resp->gid = from_kgid(&init_user_ns, cred->gid);
	resp->num_groups = cpu_to_le32(ngroups);

	for (i = 0; i < ngroups; i++)
		resp->groups[i] = from_kgid(&init_user_ns, gi->gid[i]);

	put_cred(cred);

	rsp->PersistentFileId = SMB2_NO_FID;
	rsp->VolatileFileId = SMB2_NO_FID;
	*out_len = resp_size;
	return 0;
}

/*
 * ============================================================
 *  Built-in handler table
 * ============================================================
 */

static struct ksmbd_fsctl_handler builtin_fsctl_handlers[] = {
	{
		.ctl_code = FSCTL_GET_OBJECT_ID,
		.handler  = fsctl_get_object_id_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SET_OBJECT_ID,
		.handler  = fsctl_set_object_id_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_DELETE_OBJECT_ID,
		.handler  = fsctl_delete_object_id_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SET_OBJECT_ID_EXTENDED,
		.handler  = fsctl_set_object_id_extended_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_CREATE_OR_GET_OBJECT_ID,
		.handler  = fsctl_create_or_get_object_id_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_GET_COMPRESSION,
		.handler  = fsctl_get_compression_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SET_COMPRESSION,
		.handler  = fsctl_set_compression_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_QUERY_NETWORK_INTERFACE_INFO,
		.handler  = fsctl_query_network_interface_info_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_REQUEST_RESUME_KEY,
		.handler  = fsctl_request_resume_key_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SET_SPARSE,
		.handler  = fsctl_set_sparse_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_COPYCHUNK,
		.handler  = fsctl_copychunk_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_COPYCHUNK_WRITE,
		.handler  = fsctl_copychunk_write_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_DUPLICATE_EXTENTS_TO_FILE,
		.handler  = fsctl_duplicate_extents_handler,
		.owner    = THIS_MODULE,
	},
		{
			.ctl_code = FSCTL_SET_ZERO_DATA,
			.handler  = fsctl_set_zero_data_handler,
			.owner    = THIS_MODULE,
		},
		{
			.ctl_code = FSCTL_QUERY_ALLOCATED_RANGES,
			.handler  = fsctl_query_allocated_ranges_handler,
			.owner    = THIS_MODULE,
		},
		{
			.ctl_code = FSCTL_IS_PATHNAME_VALID,
			.handler  = fsctl_is_pathname_valid_handler,
			.owner    = THIS_MODULE,
		},
	{
		.ctl_code = FSCTL_IS_VOLUME_DIRTY,
		.handler  = fsctl_is_volume_dirty_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_ALLOW_EXTENDED_DASD_IO,
		.handler  = fsctl_stub_noop_success_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_ENCRYPTION_FSCTL_IO,
		.handler  = fsctl_stub_noop_success_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_FILESYSTEM_GET_STATS,
		.handler  = fsctl_filesystem_get_stats_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_FIND_FILES_BY_SID,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
		{
			.ctl_code = FSCTL_GET_NTFS_VOLUME_DATA,
			.handler  = fsctl_get_ntfs_volume_data_handler,
			.owner    = THIS_MODULE,
		},
		{
			.ctl_code = FSCTL_GET_RETRIEVAL_POINTERS,
			.handler  = fsctl_get_retrieval_pointers_handler,
			.owner    = THIS_MODULE,
		},
	{
		.ctl_code = FSCTL_LMR_GET_LINK_TRACK_INF,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_LMR_SET_LINK_TRACK_INF,
		.handler  = fsctl_stub_noop_success_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_LOCK_VOLUME,
		.handler  = fsctl_stub_noop_success_handler,
		.owner    = THIS_MODULE,
	},
		{
			.ctl_code = FSCTL_PIPE_PEEK,
			.handler  = fsctl_pipe_peek_handler,
			.owner    = THIS_MODULE,
		},
	{
		.ctl_code = FSCTL_QUERY_FAT_BPB,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_QUERY_SPARING_INFO,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_READ_FILE_USN_DATA,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_READ_RAW_ENCRYPTED,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_RECALL_FILE,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_REQUEST_BATCH_OPLOCK,
		.handler  = fsctl_stub_noop_success_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_REQUEST_FILTER_OPLOCK,
		.handler  = fsctl_stub_noop_success_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_REQUEST_OPLOCK_LEVEL_1,
		.handler  = fsctl_stub_noop_success_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_REQUEST_OPLOCK_LEVEL_2,
		.handler  = fsctl_stub_noop_success_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SET_DEFECT_MANAGEMENT,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SET_ENCRYPTION,
		.handler  = fsctl_set_encryption_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SET_SHORT_NAME_BEHAVIOR,
		.handler  = fsctl_stub_noop_success_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SET_ZERO_ON_DEALLOC,
		.handler  = fsctl_set_zero_on_dealloc_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SIS_COPYFILE,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SIS_LINK_FILES,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_UNLOCK_VOLUME,
		.handler  = fsctl_stub_noop_success_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_WRITE_RAW_ENCRYPTED,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_WRITE_USN_CLOSE_RECORD,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_VALIDATE_NEGOTIATE_INFO,
		.handler  = fsctl_validate_negotiate_info_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_PIPE_TRANSCEIVE,
		.handler  = fsctl_pipe_transceive_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_QUERY_FILE_REGIONS,
		.handler  = fsctl_query_file_regions_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_GET_INTEGRITY_INFORMATION,
		.handler  = fsctl_get_integrity_info_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SET_INTEGRITY_INFORMATION,
		.handler  = fsctl_set_integrity_info_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SET_INTEGRITY_INFORMATION_EX,
		.handler  = fsctl_set_integrity_info_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX,
		.handler  = fsctl_duplicate_extents_ex_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_MARK_HANDLE,
		.handler  = fsctl_mark_handle_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_OFFLOAD_READ,
		.handler  = fsctl_offload_read_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_OFFLOAD_WRITE,
		.handler  = fsctl_offload_write_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SRV_READ_HASH,
		.handler  = fsctl_srv_read_hash_handler,
		.owner    = THIS_MODULE,
	},
	{
		/* MS-SMB2 §2.2.31.1.1.5: not supported on non-NTFS volumes */
		.ctl_code = FSCTL_QUERY_ON_DISK_VOLUME_INFO,
		.handler  = fsctl_not_supported_handler,
		.owner    = THIS_MODULE,
	},
	{
		/* POSIX-03: return server-mapped uid/gid/supplementary groups */
		.ctl_code = FSCTL_QUERY_POSIX_WHOAMI,
		.handler  = fsctl_query_posix_whoami_handler,
		.owner    = THIS_MODULE,
	},
};

/**
 * ksmbd_fsctl_init() - Initialize FSCTL dispatch table with built-in handlers
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_fsctl_init(void)
{
	int i, ret;

	hash_init(fsctl_handlers);
	hash_init(odx_token_table);

	/* C-01: Start periodic GC to expire stale ODX tokens */
	schedule_delayed_work(&odx_gc_dwork,
			      msecs_to_jiffies(KSMBD_ODX_GC_INTERVAL_MS));

	for (i = 0; i < ARRAY_SIZE(builtin_fsctl_handlers); i++) {
		ret = ksmbd_register_fsctl(&builtin_fsctl_handlers[i]);
		if (ret) {
			pr_err("Failed to register FSCTL 0x%08x: %d\n",
			       builtin_fsctl_handlers[i].ctl_code, ret);
			goto err_unregister;
		}
	}

	ksmbd_debug(SMB, "Registered %zu built-in FSCTL handlers\n",
		    ARRAY_SIZE(builtin_fsctl_handlers));
	return 0;

err_unregister:
	while (--i >= 0)
		ksmbd_unregister_fsctl(&builtin_fsctl_handlers[i]);
	return ret;
}

/**
 * ksmbd_fsctl_exit() - Unregister all FSCTL handlers and clean up
 */
void ksmbd_fsctl_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(builtin_fsctl_handlers); i++)
		ksmbd_unregister_fsctl(&builtin_fsctl_handlers[i]);

	/* Free any outstanding ODX tokens */
	odx_token_cleanup();
}
