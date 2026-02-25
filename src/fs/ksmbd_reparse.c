// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Reparse point FSCTL handlers for ksmbd
 *
 *   Registers FSCTL handlers for FSCTL_SET_REPARSE_POINT,
 *   FSCTL_GET_REPARSE_POINT, and FSCTL_DELETE_REPARSE_POINT.
 *   Supports IO_REPARSE_TAG_SYMLINK and IO_REPARSE_TAG_MOUNT_POINT
 *   for Windows symlink and junction point interoperability.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/version.h>

#include "ksmbd_reparse.h"
#include "ksmbd_fsctl.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "smbstatus.h"
#include "glob.h"
#include "ksmbd_work.h"
#include "vfs.h"
#include "vfs_cache.h"
#include "xattr.h"
#include "connection.h"
#include "mgmt/tree_connect.h"

/*
 * Reparse data buffer structures per MS-FSCC 2.1.2.1
 */

/* Generic reparse data buffer header */
struct reparse_data_buf_hdr {
	__le32	reparse_tag;
	__le16	reparse_data_length;
	__le16	reserved;
	__u8	data_buffer[];
} __packed;

/* Symlink reparse data buffer (IO_REPARSE_TAG_SYMLINK) */
struct reparse_symlink_data_buf {
	__le32	reparse_tag;
	__le16	reparse_data_length;
	__le16	reserved;
	__le16	substitute_name_offset;
	__le16	substitute_name_length;
	__le16	print_name_offset;
	__le16	print_name_length;
	__le32	flags;
	__u8	path_buffer[];
} __packed;

/* Mount point (junction) reparse data buffer */
struct reparse_mount_point_data_buf {
	__le32	reparse_tag;
	__le16	reparse_data_length;
	__le16	reserved;
	__le16	substitute_name_offset;
	__le16	substitute_name_length;
	__le16	print_name_offset;
	__le16	print_name_length;
	__u8	path_buffer[];
} __packed;

#define SYMLINK_FLAG_RELATIVE	0x00000001

/* Maximum symlink target path length we support */
#define REPARSE_MAX_PATH_LEN	4096

static int ksmbd_reparse_store_opaque(struct ksmbd_file *fp,
				      const void *buf, size_t len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return ksmbd_vfs_setxattr(file_mnt_idmap(fp->filp),
#else
	return ksmbd_vfs_setxattr(file_mnt_user_ns(fp->filp),
#endif
				  &fp->filp->f_path,
				  XATTR_NAME_REPARSE_DATA,
				  (void *)buf, len, 0, true);
}

static int ksmbd_reparse_load_opaque(struct ksmbd_file *fp,
				     char **buf, size_t *len)
{
	ssize_t xattr_len;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),
#else
	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),
#endif
				       fp->filp->f_path.dentry,
				       XATTR_NAME_REPARSE_DATA, buf);
	if (xattr_len < 0)
		return xattr_len;

	*len = xattr_len;
	return 0;
}

static int ksmbd_reparse_remove_opaque(struct ksmbd_file *fp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return ksmbd_vfs_remove_xattr(file_mnt_idmap(fp->filp),
#else
	return ksmbd_vfs_remove_xattr(file_mnt_user_ns(fp->filp),
#endif
				      &fp->filp->f_path,
				      (char *)XATTR_NAME_REPARSE_DATA,
				      true);
}

/**
 * ksmbd_convert_slashes() - Convert backslashes to forward slashes
 * @path:	path string to convert in-place
 */
static void ksmbd_convert_slashes(char *path)
{
	char *p;

	for (p = path; *p; p++) {
		if (*p == '\\')
			*p = '/';
	}
}

/**
 * ksmbd_strip_nt_prefix() - Strip NT-style path prefix
 * @path:	path string to strip in-place
 *
 * Removes /??/ or //?/ prefixes from NT-style paths.
 */
static void ksmbd_strip_nt_prefix(char *path)
{
	int len = strlen(path);

	if (len > 4 &&
	    (strncmp(path, "/??/", 4) == 0 ||
	     strncmp(path, "//?/", 4) == 0)) {
		memmove(path, path + 4, len - 4 + 1);
	}
}

static bool ksmbd_is_safe_reparse_target(const char *target)
{
	const char *p;

	if (!target || !*target)
		return false;

	/* Reparse targets must remain share-relative. */
	if (target[0] == '/')
		return false;

	p = target;
	while (*p) {
		const char *seg = p;
		size_t seglen;

		while (*p && *p != '/')
			p++;
		seglen = p - seg;

		if (seglen == 1 && seg[0] == '.')
			return false;
		if (seglen == 2 && seg[0] == '.' && seg[1] == '.')
			return false;

		if (*p == '/')
			p++;
	}

	return true;
}

static int ksmbd_reparse_get_fullpath(struct ksmbd_file *fp, char **fullpath)
{
	char *pathname, *path;

	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);
	if (!pathname)
		return -ENOMEM;

	path = d_path(&fp->filp->f_path, pathname, PATH_MAX);
	if (IS_ERR(path)) {
		kfree(pathname);
		return PTR_ERR(path);
	}

	*fullpath = kstrdup(path, KSMBD_DEFAULT_GFP);
	kfree(pathname);
	if (!*fullpath)
		return -ENOMEM;

	return 0;
}

static int ksmbd_reparse_replace_with_symlink(struct ksmbd_file *fp,
					      const char *target)
{
	struct path create_path;
	struct dentry *create_dentry;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	struct dentry *parent;
#endif
	char *fullpath = NULL;
	int ret;

	ret = ksmbd_reparse_get_fullpath(fp, &fullpath);
	if (ret)
		return ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	ret = ksmbd_vfs_unlink(fp->filp);
#else
	parent = dget_parent(fp->filp->f_path.dentry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = ksmbd_vfs_unlink(file_mnt_idmap(fp->filp), parent,
			       fp->filp->f_path.dentry);
#else
	ret = ksmbd_vfs_unlink(file_mnt_user_ns(fp->filp), parent,
			       fp->filp->f_path.dentry);
#endif
	dput(parent);
#endif
	if (ret)
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	create_dentry = start_creating_path(AT_FDCWD, fullpath,
					    &create_path, 0);
#else
	create_dentry = kern_path_create(AT_FDCWD, fullpath,
					 &create_path, 0);
#endif
	if (IS_ERR(create_dentry)) {
		ret = PTR_ERR(create_dentry);
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	ret = vfs_symlink(mnt_idmap(create_path.mnt),
			  d_inode(create_dentry->d_parent),
			  create_dentry, target, NULL);
#else
	ret = vfs_symlink(mnt_idmap(create_path.mnt),
			  d_inode(create_dentry->d_parent),
			  create_dentry, target);
#endif
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	ret = vfs_symlink(mnt_user_ns(create_path.mnt),
			  d_inode(create_dentry->d_parent),
			  create_dentry, target);
#else
	ret = vfs_symlink(d_inode(create_dentry->d_parent),
			  create_dentry, target);
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	end_creating_path(&create_path, create_dentry);
#else
	done_path_create(&create_path, create_dentry);
#endif

out:
	kfree(fullpath);
	return ret;
}

static int ksmbd_reparse_replace_with_regular_file(struct ksmbd_file *fp)
{
	struct path create_path;
	struct dentry *create_dentry;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	struct dentry *parent;
#endif
	char *fullpath = NULL;
	int ret;

	ret = ksmbd_reparse_get_fullpath(fp, &fullpath);
	if (ret)
		return ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	ret = ksmbd_vfs_unlink(fp->filp);
#else
	parent = dget_parent(fp->filp->f_path.dentry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = ksmbd_vfs_unlink(file_mnt_idmap(fp->filp), parent,
			       fp->filp->f_path.dentry);
#else
	ret = ksmbd_vfs_unlink(file_mnt_user_ns(fp->filp), parent,
			       fp->filp->f_path.dentry);
#endif
	dput(parent);
#endif
	if (ret)
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	create_dentry = start_creating_path(AT_FDCWD, fullpath,
					    &create_path, 0);
#else
	create_dentry = kern_path_create(AT_FDCWD, fullpath,
					 &create_path, 0);
#endif
	if (IS_ERR(create_dentry)) {
		ret = PTR_ERR(create_dentry);
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	ret = vfs_create(mnt_idmap(create_path.mnt), create_dentry,
			 S_IFREG | 0644, NULL);
#else
	ret = vfs_create(mnt_idmap(create_path.mnt),
			 d_inode(create_dentry->d_parent),
			 create_dentry, S_IFREG | 0644, true);
#endif
#else
	ret = vfs_create(mnt_user_ns(create_path.mnt),
			 d_inode(create_dentry->d_parent),
			 create_dentry, S_IFREG | 0644, true);
#endif
#else
	ret = vfs_create(d_inode(create_dentry->d_parent),
			 create_dentry, S_IFREG | 0644, true);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	end_creating_path(&create_path, create_dentry);
#else
	done_path_create(&create_path, create_dentry);
#endif

out:
	kfree(fullpath);
	return ret;
}

/**
 * ksmbd_extract_symlink_target() - Extract UTF-8 target from
 *                                  symlink reparse data
 * @symdata:	symlink reparse data buffer
 * @in_buf_len:	total input buffer length
 * @codepage:	NLS codepage for UTF-16 conversion
 * @target:	[out] allocated UTF-8 target string
 *
 * Validates the reparse data structure and extracts the
 * SubstituteName as a UTF-8 string suitable for VFS operations.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_extract_symlink_target(
		struct reparse_symlink_data_buf *symdata,
		unsigned int in_buf_len,
		const struct nls_table *codepage,
		char **target)
{
	unsigned int sub_off, sub_len;
	char *utf8_target;

	sub_off = le16_to_cpu(symdata->substitute_name_offset);
	sub_len = le16_to_cpu(symdata->substitute_name_length);

	/* Validate against actual input buffer */
	if (offsetof(struct reparse_symlink_data_buf, path_buffer)
	    + sub_off + sub_len > in_buf_len) {
		pr_err_ratelimited(
			"reparse symlink: substitute name overflows buf\n");
		return -EINVAL;
	}

	if (sub_len == 0 || sub_len > REPARSE_MAX_PATH_LEN) {
		pr_err_ratelimited(
			"reparse symlink: invalid sub name len %u\n",
			sub_len);
		return -EINVAL;
	}

	/*
	 * smb_strndup_from_utf16 allocates and converts the
	 * UTF-16LE string to a UTF-8 string.
	 */
	utf8_target = smb_strndup_from_utf16(
			(const char *)(symdata->path_buffer + sub_off),
			sub_len, true, codepage);
	if (IS_ERR(utf8_target)) {
		pr_err_ratelimited(
			"reparse symlink: UTF-16 conversion failed\n");
		return PTR_ERR(utf8_target);
	}

	ksmbd_convert_slashes(utf8_target);
	ksmbd_strip_nt_prefix(utf8_target);

	*target = utf8_target;
	return 0;
}

/**
 * ksmbd_extract_mount_point_target() - Extract UTF-8 target from
 *                                      mount point reparse data
 * @mpdata:	mount point reparse data buffer
 * @in_buf_len:	total input buffer length
 * @codepage:	NLS codepage for UTF-16 conversion
 * @target:	[out] allocated UTF-8 target string
 *
 * Validates the reparse data structure and extracts the
 * SubstituteName as a UTF-8 string suitable for VFS operations.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_extract_mount_point_target(
		struct reparse_mount_point_data_buf *mpdata,
		unsigned int in_buf_len,
		const struct nls_table *codepage,
		char **target)
{
	unsigned int sub_off, sub_len;
	char *utf8_target;

	sub_off = le16_to_cpu(mpdata->substitute_name_offset);
	sub_len = le16_to_cpu(mpdata->substitute_name_length);

	/* Validate against actual input buffer */
	if (offsetof(struct reparse_mount_point_data_buf, path_buffer)
	    + sub_off + sub_len > in_buf_len) {
		pr_err_ratelimited(
			"reparse junction: sub name overflows buf\n");
		return -EINVAL;
	}

	if (sub_len == 0 || sub_len > REPARSE_MAX_PATH_LEN) {
		pr_err_ratelimited(
			"reparse junction: invalid sub name len %u\n",
			sub_len);
		return -EINVAL;
	}

	utf8_target = smb_strndup_from_utf16(
			(const char *)(mpdata->path_buffer + sub_off),
			sub_len, true, codepage);
	if (IS_ERR(utf8_target)) {
		pr_err_ratelimited(
			"reparse junction: UTF-16 conversion failed\n");
		return PTR_ERR(utf8_target);
	}

	ksmbd_convert_slashes(utf8_target);
	ksmbd_strip_nt_prefix(utf8_target);

	*target = utf8_target;
	return 0;
}

/**
 * ksmbd_fsctl_set_reparse_point() - Handle FSCTL_SET_REPARSE_POINT
 * @work:	    smb work for this request
 * @id:		    volatile file id
 * @in_buf:	    input buffer containing reparse data
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Parses the reparse data buffer and validates the symlink or
 * junction point target for IO_REPARSE_TAG_SYMLINK and
 * IO_REPARSE_TAG_MOUNT_POINT tags.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_fsctl_set_reparse_point(struct ksmbd_work *work,
					 u64 id, void *in_buf,
					 unsigned int in_buf_len,
					 unsigned int max_out_len,
					 struct smb2_ioctl_rsp *rsp,
					 unsigned int *out_len)
{
	struct reparse_data_buf_hdr *hdr;
	struct ksmbd_file *fp;
	char *target = NULL;
	const struct nls_table *codepage;
	__le32 tag;
	int ret;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(struct reparse_data_buf_hdr)) {
		pr_err_ratelimited(
			"set reparse: input buffer too short: %u\n",
			in_buf_len);
		rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;
		return -EINVAL;
	}

	hdr = (struct reparse_data_buf_hdr *)in_buf;
	tag = hdr->reparse_tag;
	if (in_buf_len < sizeof(*hdr) + le16_to_cpu(hdr->reparse_data_length)) {
		rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;
		return -EINVAL;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		pr_err_ratelimited("set reparse: file not found\n");
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	codepage = work->conn->local_nls;

	switch (le32_to_cpu(tag)) {
	case IO_REPARSE_TAG_SYMLINK:
	{
		struct reparse_symlink_data_buf *symdata;

		if (in_buf_len <
		    sizeof(struct reparse_symlink_data_buf)) {
			ret = -EINVAL;
			rsp->hdr.Status =
				STATUS_IO_REPARSE_DATA_INVALID;
			goto out;
		}

		symdata = (struct reparse_symlink_data_buf *)in_buf;
		ret = ksmbd_extract_symlink_target(symdata,
						   in_buf_len,
						   codepage,
						   &target);
		if (ret) {
			rsp->hdr.Status =
				STATUS_IO_REPARSE_DATA_INVALID;
			goto out;
		}
		break;
	}
	case IO_REPARSE_TAG_MOUNT_POINT:
	{
		struct reparse_mount_point_data_buf *mpdata;

		if (in_buf_len <
		    sizeof(struct reparse_mount_point_data_buf)) {
			ret = -EINVAL;
			rsp->hdr.Status =
				STATUS_IO_REPARSE_DATA_INVALID;
			goto out;
		}

		mpdata = (struct reparse_mount_point_data_buf *)in_buf;
		ret = ksmbd_extract_mount_point_target(mpdata,
						       in_buf_len,
						       codepage,
						       &target);
		if (ret) {
			rsp->hdr.Status =
				STATUS_IO_REPARSE_DATA_INVALID;
			goto out;
		}
		break;
	}
	default:
		/*
		 * Keep unsupported-name-surrogate tags as opaque reparse
		 * data so clients using custom tags can round-trip
		 * FSCTL_SET/GET/DELETE_REPARSE_POINT.
		 */
		ret = ksmbd_reparse_store_opaque(fp, in_buf, in_buf_len);
		if (ret) {
			if (ret == -EACCES || ret == -EPERM)
				rsp->hdr.Status = STATUS_ACCESS_DENIED;
			else if (ret == -ENOSPC)
				rsp->hdr.Status = STATUS_DISK_FULL;
			else
				rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
			goto out;
		}

		*out_len = 0;
		ret = 0;
		goto out;
	}

	/* Prevent symlink targets that escape share boundary */
	if (!target) {
		ret = -EINVAL;
		rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;
		goto out;
	}

	if (!ksmbd_is_safe_reparse_target(target)) {
		pr_err_ratelimited(
			"set reparse: target '%s' escapes share\n",
			target);
		ret = -EACCES;
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		goto out;
	}

	ksmbd_debug(SMB, "set reparse: tag 0x%x -> %s\n",
		    le32_to_cpu(tag), target);

	ret = ksmbd_reparse_replace_with_symlink(fp, target);
	if (ret) {
		if (ret == -EACCES || ret == -EPERM)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (ret == -ENOSPC)
			rsp->hdr.Status = STATUS_DISK_FULL;
		else if (ret == -ENOTEMPTY)
			rsp->hdr.Status = STATUS_DIRECTORY_NOT_EMPTY;
			else if (ret == -EEXIST)
				rsp->hdr.Status = STATUS_OBJECT_NAME_COLLISION;
			else if (ret == -ENOENT)
				rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;
			else if (ret == -EOPNOTSUPP)
				rsp->hdr.Status = STATUS_INVALID_DEVICE_REQUEST;
			else
				rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
		goto out;
	}

	*out_len = 0;
	ret = 0;

out:
	kfree(target);
	ksmbd_fd_put(work, fp);
	return ret;
}

/**
 * ksmbd_fsctl_get_reparse_point() - Handle FSCTL_GET_REPARSE_POINT
 * @work:	    smb work for this request
 * @id:		    volatile file id
 * @in_buf:	    input buffer (unused)
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Reads the reparse data for the file identified by @id.
 * For symlinks, constructs a SYMLINK reparse data buffer.
 * For other special files, returns the appropriate reparse tag
 * with an empty data buffer.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_fsctl_get_reparse_point(struct ksmbd_work *work,
					 u64 id, void *in_buf,
					 unsigned int in_buf_len,
					 unsigned int max_out_len,
					 struct smb2_ioctl_rsp *rsp,
					 unsigned int *out_len)
{
	struct ksmbd_file *fp;
	struct inode *inode;
	struct reparse_data_buf_hdr *opaque_hdr;
	struct reparse_data_buffer *reparse_ptr;
	struct reparse_symlink_data_buf *symdata;
	const struct nls_table *codepage;
	char *opaque_buf = NULL;
	size_t opaque_len = 0;
	int conv_len;
	unsigned int ucs2_bytes, total_len;
	int ret;

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		pr_err_ratelimited("get reparse: file not found\n");
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	inode = file_inode(fp->filp);
	codepage = work->conn->local_nls;

	ret = ksmbd_reparse_load_opaque(fp, &opaque_buf, &opaque_len);
	if (!ret) {
		if (opaque_len < sizeof(*opaque_hdr)) {
			kfree(opaque_buf);
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;
			return -EINVAL;
		}

		opaque_hdr = (struct reparse_data_buf_hdr *)opaque_buf;
		if (opaque_len < sizeof(*opaque_hdr) +
				 le16_to_cpu(opaque_hdr->reparse_data_length)) {
			kfree(opaque_buf);
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;
			return -EINVAL;
		}

		if (opaque_len > max_out_len) {
			kfree(opaque_buf);
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
			return -ENOSPC;
		}

		memcpy(&rsp->Buffer[0], opaque_buf, opaque_len);
		kfree(opaque_buf);
		*out_len = opaque_len;
		ksmbd_fd_put(work, fp);
		return 0;
	}
	if (ret != -ENODATA && ret != -ENOENT && ret != -EOPNOTSUPP) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
		return ret;
	}

	if (S_ISLNK(inode->i_mode)) {
		const char *link;
		char *link_copy;
		__le16 *ucs2_buf;
		int link_len;
		DEFINE_DELAYED_CALL(done);

		if (max_out_len <
		    sizeof(struct reparse_symlink_data_buf)) {
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
			return -ENOSPC;
		}

		/* Read the symlink target */
		link = vfs_get_link(fp->filp->f_path.dentry, &done);
		if (IS_ERR(link)) {
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_NOT_A_REPARSE_POINT;
			return PTR_ERR(link);
		}

		link_len = strlen(link);

		/* Copy link target so we can release the delayed call */
		link_copy = kzalloc(link_len + 1, KSMBD_DEFAULT_GFP);
		if (!link_copy) {
			do_delayed_call(&done);
			ksmbd_fd_put(work, fp);
			return -ENOMEM;
		}
		memcpy(link_copy, link, link_len);
		do_delayed_call(&done);

		/*
		 * Convert UTF-8 path to UTF-16LE in a temporary
		 * buffer first to calculate the size before writing
		 * into the response buffer.
		 */
		ucs2_buf = kzalloc((link_len + 1) * 2,
				   KSMBD_DEFAULT_GFP);
		if (!ucs2_buf) {
			kfree(link_copy);
			ksmbd_fd_put(work, fp);
			return -ENOMEM;
		}

		conv_len = smbConvertToUTF16(ucs2_buf, link_copy,
					     link_len, codepage, 0);
		kfree(link_copy);

		if (conv_len < 0) {
			kfree(ucs2_buf);
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			return -EINVAL;
		}
		ucs2_bytes = conv_len * 2;

		/*
		 * Total size: fixed header + SubstituteName +
		 * PrintName (both same content).
		 */
		total_len = sizeof(struct reparse_symlink_data_buf)
			    + ucs2_bytes * 2;

		if (total_len > max_out_len) {
			kfree(ucs2_buf);
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
			return -ENOSPC;
		}

		symdata = (struct reparse_symlink_data_buf *)
			  &rsp->Buffer[0];
		memset(symdata, 0,
		       sizeof(struct reparse_symlink_data_buf));

		symdata->reparse_tag =
			cpu_to_le32(IO_REPARSE_TAG_SYMLINK);
		symdata->reparse_data_length = cpu_to_le16(
			total_len -
			offsetof(struct reparse_symlink_data_buf,
				 substitute_name_offset));
		symdata->substitute_name_offset = cpu_to_le16(0);
		symdata->substitute_name_length =
			cpu_to_le16(ucs2_bytes);
		symdata->print_name_offset =
			cpu_to_le16(ucs2_bytes);
		symdata->print_name_length =
			cpu_to_le16(ucs2_bytes);
		symdata->flags =
			cpu_to_le32(SYMLINK_FLAG_RELATIVE);

		/* Copy SubstituteName */
		memcpy(symdata->path_buffer, ucs2_buf, ucs2_bytes);
		/* Copy PrintName (same content, after SubstituteName) */
		memcpy(symdata->path_buffer + ucs2_bytes,
		       ucs2_buf, ucs2_bytes);

		kfree(ucs2_buf);
		*out_len = total_len;
	} else {
		__le32 reparse_tag;

		/*
		 * Non-symlink special files: return the appropriate
		 * reparse tag with empty data, matching the existing
		 * behavior in smb2pdu.c.
		 */
		if (S_ISFIFO(inode->i_mode))
			reparse_tag = IO_REPARSE_TAG_LX_FIFO_LE;
		else if (S_ISSOCK(inode->i_mode))
			reparse_tag = IO_REPARSE_TAG_AF_UNIX_LE;
		else if (S_ISCHR(inode->i_mode))
			reparse_tag = IO_REPARSE_TAG_LX_CHR_LE;
		else if (S_ISBLK(inode->i_mode))
			reparse_tag = IO_REPARSE_TAG_LX_BLK_LE;
		else {
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_NOT_A_REPARSE_POINT;
			*out_len = 0;
			return -EINVAL;
		}

		if (max_out_len <
		    sizeof(struct reparse_data_buffer)) {
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
			return -ENOSPC;
		}

		reparse_ptr = (struct reparse_data_buffer *)
			      &rsp->Buffer[0];
		reparse_ptr->ReparseTag = reparse_tag;
		reparse_ptr->ReparseDataLength = 0;
		*out_len = sizeof(struct reparse_data_buffer);
	}

	ksmbd_fd_put(work, fp);
	return 0;
}

/**
 * ksmbd_fsctl_delete_reparse_point() - Handle FSCTL_DELETE_REPARSE_POINT
 * @work:	    smb work for this request
 * @id:		    volatile file id
 * @in_buf:	    input buffer containing reparse tag
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Validates the reparse tag in the delete request matches the
 * file's actual reparse tag, then removes the reparse data.
 * For symlinks, this removes the symbolic link.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_fsctl_delete_reparse_point(struct ksmbd_work *work,
					    u64 id, void *in_buf,
					    unsigned int in_buf_len,
					    unsigned int max_out_len,
					    struct smb2_ioctl_rsp *rsp,
					    unsigned int *out_len)
{
	struct reparse_data_buf_hdr *hdr;
	struct reparse_data_buf_hdr *opaque_hdr;
	struct ksmbd_file *fp;
	struct inode *inode;
	char *opaque_buf = NULL;
	size_t opaque_len = 0;
	int ret;

	if (in_buf_len < sizeof(struct reparse_data_buf_hdr)) {
		pr_err_ratelimited(
			"delete reparse: buf too short: %u\n",
			in_buf_len);
		rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;
		return -EINVAL;
	}

	hdr = (struct reparse_data_buf_hdr *)in_buf;

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		pr_err_ratelimited("delete reparse: not found\n");
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	ret = ksmbd_reparse_load_opaque(fp, &opaque_buf, &opaque_len);
	if (!ret) {
		if (opaque_len < sizeof(*opaque_hdr)) {
			rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;
			ret = -EINVAL;
			goto out;
		}

		opaque_hdr = (struct reparse_data_buf_hdr *)opaque_buf;
		if (hdr->reparse_tag != opaque_hdr->reparse_tag) {
			rsp->hdr.Status = STATUS_IO_REPARSE_TAG_MISMATCH;
			ret = -EINVAL;
			goto out;
		}

		ret = ksmbd_reparse_remove_opaque(fp);
		if (ret && ret != -ENOENT && ret != -ENODATA) {
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
			goto out;
		}

		*out_len = 0;
		ret = 0;
		goto out;
	}
	if (ret != -ENODATA && ret != -ENOENT && ret != -EOPNOTSUPP) {
		rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
		goto out;
	}

	inode = file_inode(fp->filp);

	/* Verify the file is actually a reparse point */
	if (!S_ISLNK(inode->i_mode) && S_ISREG(inode->i_mode)) {
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_NOT_A_REPARSE_POINT;
		return -EINVAL;
	}

	/* Verify reparse tag matches */
	if (S_ISLNK(inode->i_mode)) {
		__le32 exp_sym =
			cpu_to_le32(IO_REPARSE_TAG_SYMLINK);
		__le32 exp_mp =
			cpu_to_le32(IO_REPARSE_TAG_MOUNT_POINT);

		if (hdr->reparse_tag != exp_sym &&
		    hdr->reparse_tag != exp_mp) {
			ksmbd_fd_put(work, fp);
			rsp->hdr.Status =
				STATUS_IO_REPARSE_TAG_MISMATCH;
			return -EINVAL;
		}
	}

	/*
	 * Convert reparse symlink to a regular file by replacing
	 * the symlink dentry atomically from the same pathname.
	 */
	ksmbd_debug(SMB, "delete reparse: tag 0x%x on ino %lu\n",
		    le32_to_cpu(hdr->reparse_tag), inode->i_ino);

	if (S_ISLNK(inode->i_mode)) {
		ret = ksmbd_reparse_replace_with_regular_file(fp);
		if (ret) {
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
			goto out;
		}
	}

	*out_len = 0;
	ret = 0;
out:
	kfree(opaque_buf);
	ksmbd_fd_put(work, fp);
	return ret;
}

/* FSCTL handler descriptors */
static struct ksmbd_fsctl_handler set_reparse_handler = {
	.ctl_code = FSCTL_SET_REPARSE_POINT,
	.handler  = ksmbd_fsctl_set_reparse_point,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler get_reparse_handler = {
	.ctl_code = FSCTL_GET_REPARSE_POINT,
	.handler  = ksmbd_fsctl_get_reparse_point,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler delete_reparse_handler = {
	.ctl_code = FSCTL_DELETE_REPARSE_POINT,
	.handler  = ksmbd_fsctl_delete_reparse_point,
	.owner    = THIS_MODULE,
};

/**
 * ksmbd_reparse_init() - Initialize reparse point subsystem
 *
 * Registers FSCTL handlers for FSCTL_SET_REPARSE_POINT
 * (0x000900A4), FSCTL_GET_REPARSE_POINT (0x000900A8), and
 * FSCTL_DELETE_REPARSE_POINT (0x000900AC).
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_reparse_init(void)
{
	int ret;

	ret = ksmbd_register_fsctl(&set_reparse_handler);
	if (ret) {
		pr_err("Failed to register FSCTL_SET_REPARSE: %d\n",
		       ret);
		return ret;
	}

	ret = ksmbd_register_fsctl(&get_reparse_handler);
	if (ret) {
		pr_err("Failed to register FSCTL_GET_REPARSE: %d\n",
		       ret);
		goto err_unregister_set;
	}

	ret = ksmbd_register_fsctl(&delete_reparse_handler);
	if (ret) {
		pr_err("Failed to register FSCTL_DELETE_REPARSE: %d\n",
		       ret);
		goto err_unregister_get;
	}

	ksmbd_debug(SMB, "Reparse point subsystem initialized\n");
	return 0;

err_unregister_get:
	ksmbd_unregister_fsctl(&get_reparse_handler);
err_unregister_set:
	ksmbd_unregister_fsctl(&set_reparse_handler);
	return ret;
}

/**
 * ksmbd_reparse_exit() - Tear down reparse point subsystem
 *
 * Unregisters all reparse point FSCTL handlers.
 */
void ksmbd_reparse_exit(void)
{
	ksmbd_unregister_fsctl(&delete_reparse_handler);
	ksmbd_unregister_fsctl(&get_reparse_handler);
	ksmbd_unregister_fsctl(&set_reparse_handler);
}
