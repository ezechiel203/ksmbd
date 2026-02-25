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

#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/inetdevice.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <net/addrconf.h>
#include <linux/ethtool.h>

#include "ksmbd_fsctl.h"
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
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
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
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
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
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
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
	return fsctl_set_object_id_common_handler(work, id, in_buf,
						  in_buf_len, rsp, out_len);
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
	if (state == COMPRESSION_FORMAT_LZNT1)
		fp->f_ci->m_fattr |= ATTR_COMPRESSED_LE;
	else
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

static int fsctl_pipe_peek_handler(struct ksmbd_work *work,
				   u64 id, void *in_buf,
				   unsigned int in_buf_len,
				   unsigned int max_out_len,
				   struct smb2_ioctl_rsp *rsp,
				   unsigned int *out_len)
{
	struct fsctl_pipe_peek_rsp *peek_rsp;

	if (max_out_len < sizeof(*peek_rsp)) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	peek_rsp = (struct fsctl_pipe_peek_rsp *)&rsp->Buffer[0];
	memset(peek_rsp, 0, sizeof(*peek_rsp));
	*out_len = sizeof(*peek_rsp);
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
		if (netdev->real_num_tx_queues > 1)
			nii_rsp->Capability |= cpu_to_le32(RSS_CAPABLE);
		if (ksmbd_rdma_capable_netdev(netdev))
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

			list_for_each_entry(ifa, &idev6->addr_list, if_list) {
				if (ifa->flags & (IFA_F_TENTATIVE |
						  IFA_F_DEPRECATED))
					continue;
				memcpy(ipv6_addr, ifa->addr.s6_addr, 16);
				break;
			}
			sockaddr_storage->addr6.ScopeId = 0;
			nbytes += sizeof(struct network_interface_info_ioctl_rsp);
		}
	}
	rtnl_unlock();

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
	ci_rsp->ChunksWritten =
		cpu_to_le32(ksmbd_server_side_copy_max_chunk_count());
	ci_rsp->ChunkBytesWritten =
		cpu_to_le32(ksmbd_server_side_copy_max_chunk_size());
	ci_rsp->TotalBytesWritten =
		cpu_to_le32(ksmbd_server_side_copy_max_total_size());

	chunks = (struct srv_copychunk *)&ci_req->Chunks[0];
	chunk_count = le32_to_cpu(ci_req->ChunkCount);
	if (chunk_count == 0)
		goto out;

	if (chunk_count > ksmbd_server_side_copy_max_chunk_count() ||
	    input_count < offsetof(struct copychunk_ioctl_req, Chunks) +
			 chunk_count * sizeof(struct srv_copychunk)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	for (i = 0; i < chunk_count; i++) {
		if (le32_to_cpu(chunks[i].Length) == 0 ||
		    le32_to_cpu(chunks[i].Length) >
			    ksmbd_server_side_copy_max_chunk_size())
			break;
		total_size_written += le32_to_cpu(chunks[i].Length);
	}

	if (i < chunk_count ||
	    total_size_written > ksmbd_server_side_copy_max_total_size()) {
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

	rsp->PersistentFileId = dst_fp->persistent_id;
	if (cnt_code == FSCTL_COPYCHUNK &&
	    !(dst_fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE))) {
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
		if (ret == -EAGAIN)
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

	if (chunk_count_written > 0) {
		loff_t preceding = 0;

		for (i = 0; i + 1 < chunk_count_written; i++)
			preceding += le32_to_cpu(chunks[i].Length);
		chunk_size_written = (unsigned int)(total_size_written - preceding);
	}

	ci_rsp->ChunksWritten = cpu_to_le32(chunk_count_written);
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
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
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
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
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
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	fp_out = ksmbd_lookup_fd_fast(work, id);
	if (!fp_out) {
		ksmbd_fd_put(work, fp_in);
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	src_off = le64_to_cpu(dup_ext->SourceFileOffset);
	dst_off = le64_to_cpu(dup_ext->TargetFileOffset);
	length = le64_to_cpu(dup_ext->ByteCount);
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

	fp_in = ksmbd_lookup_fd_slow(work, dup_ext->VolatileFileHandle,
				     dup_ext->PersistentFileHandle);
	if (!fp_in) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	fp_out = ksmbd_lookup_fd_fast(work, id);
	if (!fp_out) {
		ksmbd_fd_put(work, fp_in);
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
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

/**
 * fsctl_mark_handle_handler() - FSCTL_MARK_HANDLE
 *
 * Marks a file handle for special behavior (USN journal, backup
 * semantics). Accept as hint with file handle validation.
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

	if (in_buf_len < sizeof(struct file_sparse)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	sparse = (struct file_sparse *)in_buf;
	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	old_fattr = fp->f_ci->m_fattr;
	if (sparse->SetSparse)
		fp->f_ci->m_fattr |= ATTR_SPARSE_FILE_LE;
	else
		fp->f_ci->m_fattr &= ~ATTR_SPARSE_FILE_LE;

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
	if (!max_entries) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	in_range = (struct file_allocated_range_buffer *)in_buf;
	start = le64_to_cpu(in_range->file_offset);
	length = le64_to_cpu(in_range->length);
	if (start < 0 || length < 0) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	out_range = (struct file_allocated_range_buffer *)&rsp->Buffer[0];
	ret = ksmbd_vfs_fqar_lseek(fp, start, length,
				   out_range, max_entries, &out_count);
	ksmbd_fd_put(work, fp);

	if (ret == -E2BIG) {
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
 * agreed on, preventing downgrade attacks (MS-SMB2 3.3.5.15.12).
 */
static int fsctl_validate_negotiate_info_handler(struct ksmbd_work *work,
						  u64 id, void *in_buf,
						  unsigned int in_buf_len,
						  unsigned int max_out_len,
						  struct smb2_ioctl_rsp *rsp,
						  unsigned int *out_len)
{
	struct ksmbd_conn *conn = work->conn;
	struct validate_negotiate_info_req *neg_req;
	struct validate_negotiate_info_rsp *neg_rsp;
	int ret;
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
		return -EINVAL;

	if (memcmp(neg_req->Guid, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE))
		return -EINVAL;

	if (le16_to_cpu(neg_req->SecurityMode) != conn->cli_sec_mode)
		return -EINVAL;

	if (le32_to_cpu(neg_req->Capabilities) != conn->cli_cap)
		return -EINVAL;

	neg_rsp = (struct validate_negotiate_info_rsp *)&rsp->Buffer[0];
	neg_rsp->Capabilities = cpu_to_le32(conn->vals->capabilities);
	memset(neg_rsp->Guid, 0, SMB2_CLIENT_GUID_SIZE);
	neg_rsp->SecurityMode = cpu_to_le16(conn->srv_sec_mode);
	neg_rsp->Dialect = cpu_to_le16(conn->dialect);

	rsp->PersistentFileId = SMB2_NO_FID;
	rsp->VolatileFileId = SMB2_NO_FID;

	*out_len = sizeof(struct validate_negotiate_info_rsp);
	ret = 0;
	return ret;
}

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
		} else if (rpc_resp->flags != KSMBD_RPC_OK) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			goto out;
		}

		nbytes = rpc_resp->payload_sz;
		if (rpc_resp->payload_sz > capped_out_len) {
			rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
			nbytes = capped_out_len;
		}

		if (!rpc_resp->payload_sz) {
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
			goto out;
		}

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
 * Returns information about file regions. Returns the requested range
 * as a single valid-data region.
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
	u64 offset, length, file_size;
	unsigned int hdr_sz = sizeof(*output);
	unsigned int entry_sz = sizeof(*region);

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
		offset = le64_to_cpu(input->FileOffset);
		length = le64_to_cpu(input->Length);
	} else {
		offset = 0;
		length = file_size;
	}

	/* Clamp to file size */
	if (offset >= file_size) {
		offset = file_size;
		length = 0;
	} else if (offset + length > file_size) {
		length = file_size - offset;
	}

	output = (struct file_region_output *)&rsp->Buffer[0];
	memset(output, 0, hdr_sz);
	output->TotalRegionEntryCount = cpu_to_le32(1);
	output->RegionEntryCount = cpu_to_le32(1);

	region = (struct file_region_info *)((char *)output + hdr_sz);
	memset(region, 0, entry_sz);
	region->FileOffset = cpu_to_le64(offset);
	region->Length = cpu_to_le64(length);
	region->Usage = cpu_to_le32(FILE_REGION_USAGE_VALID_CACHED_DATA);

	*out_len = hdr_sz + entry_sz;
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
	unsigned int sz = sizeof(*info);

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
	u8     reserved[512 - 36];
} __packed;

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
	offset = le64_to_cpu(input->FileOffset);
	length = le64_to_cpu(input->CopyLength);

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	inode = file_inode(fp->filp);
	file_size = i_size_read(inode);

	/* Clamp transfer length to available data */
	if (offset >= file_size)
		length = 0;
	else if (offset + length > file_size)
		length = file_size - offset;

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

	/* Validate the ODX token magic */
	if (le32_to_cpu(token->magic) != KSMBD_ODX_TOKEN_MAGIC) {
		ksmbd_debug(SMB,
			    "OFFLOAD_WRITE: invalid token magic 0x%08x\n",
			    le32_to_cpu(token->magic));
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
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
	if (xfer_off < 0 || xfer_off > token_len) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	src_off = token_off + xfer_off;

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
 * BranchCache content information retrieval. Returns
 * STATUS_HASH_NOT_PRESENT until full BranchCache is implemented.
 */
#define STATUS_HASH_NOT_PRESENT		cpu_to_le32(0xC000A100)

static int fsctl_srv_read_hash_handler(struct ksmbd_work *work,
				       u64 id, void *in_buf,
				       unsigned int in_buf_len,
				       unsigned int max_out_len,
				       struct smb2_ioctl_rsp *rsp,
				       unsigned int *out_len)
{
	rsp->hdr.Status = STATUS_HASH_NOT_PRESENT;
	*out_len = 0;
	return -EOPNOTSUPP;
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
}
