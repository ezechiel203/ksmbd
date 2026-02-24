// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_create.c - SMB2_CREATE (open) handler + helpers
 */

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/ethtool.h>
#include <linux/falloc.h>
#include <linux/crc32.h>
#include <linux/mount.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#include <linux/filelock.h>
#endif

#include <crypto/algapi.h>

#include "compat.h"
#include "glob.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "oplock.h"
#include "smbacl.h"

#include "auth.h"
#include "asn1.h"
#include "connection.h"
#include "transport_ipc.h"
#include "transport_rdma.h"
#include "vfs.h"
#include "vfs_cache.h"
#include "misc.h"

#include "server.h"
#include "smb_common.h"
#include "smbstatus.h"
#include "ksmbd_work.h"
#include "mgmt/user_config.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"
#include "mgmt/ksmbd_ida.h"
#include "ndr.h"
#include "transport_tcp.h"
#include "smb2fruit.h"
#include "ksmbd_fsctl.h"
#include "ksmbd_create_ctx.h"
#include "ksmbd_vss.h"
#include "ksmbd_notify.h"
#include "ksmbd_info.h"
#include "ksmbd_buffer.h"
#include "smb2pdu_internal.h"

/**
 * smb2_create_open_flags() - convert smb open flags to unix open flags
 * @file_present:	is file already present
 * @access:		file access flags
 * @disposition:	file disposition flags
 * @may_flags:		set with MAY_ flags
 * @is_dir:		is creating open flags for directory
 *
 * Return:      file open flags
 */
static int smb2_create_open_flags(bool file_present, __le32 access,
				  __le32 disposition,
				  int *may_flags,
				  __le32 coptions,
				  umode_t mode)
{
	int oflags = O_NONBLOCK | O_LARGEFILE;

	if (coptions & FILE_DIRECTORY_FILE_LE || S_ISDIR(mode)) {
		access &= ~FILE_WRITE_DESIRE_ACCESS_LE;
		ksmbd_debug(SMB, "Discard write access to a directory\n");
	}

	if (access & FILE_READ_DESIRED_ACCESS_LE &&
	    access & FILE_WRITE_DESIRE_ACCESS_LE) {
		oflags |= O_RDWR;
		*may_flags = MAY_OPEN | MAY_READ | MAY_WRITE;
	} else if (access & FILE_WRITE_DESIRE_ACCESS_LE) {
		oflags |= O_WRONLY;
		*may_flags = MAY_OPEN | MAY_WRITE;
	} else {
		oflags |= O_RDONLY;
		*may_flags = MAY_OPEN | MAY_READ;
	}

	if (access == FILE_READ_ATTRIBUTES_LE || S_ISBLK(mode) || S_ISCHR(mode))
		oflags |= O_PATH;

	if (file_present) {
		switch (disposition & FILE_CREATE_MASK_LE) {
		case FILE_OPEN_LE:
		case FILE_CREATE_LE:
			break;
		case FILE_SUPERSEDE_LE:
		case FILE_OVERWRITE_LE:
		case FILE_OVERWRITE_IF_LE:
			oflags |= O_TRUNC;
			break;
		default:
			break;
		}
	} else {
		switch (disposition & FILE_CREATE_MASK_LE) {
		case FILE_SUPERSEDE_LE:
		case FILE_CREATE_LE:
		case FILE_OPEN_IF_LE:
		case FILE_OVERWRITE_IF_LE:
			oflags |= O_CREAT;
			break;
		case FILE_OPEN_LE:
		case FILE_OVERWRITE_LE:
			oflags &= ~O_CREAT;
			break;
		default:
			break;
		}
	}

	return oflags;
}

/**
 * create_smb2_pipe() - create IPC pipe
 * @work:	smb work containing request buffer
 *
 * Return:      0 on success, otherwise error
 */
static noinline int create_smb2_pipe(struct ksmbd_work *work)
{
	struct smb2_create_rsp *rsp;
	struct smb2_create_req *req;
	int id;
	int err;
	char *name;

	WORK_BUFFERS(work, req, rsp);

	name = smb_strndup_from_utf16(req->Buffer, le16_to_cpu(req->NameLength),
				      1, work->conn->local_nls);
	if (IS_ERR(name)) {
		rsp->hdr.Status = STATUS_NO_MEMORY;
		err = PTR_ERR(name);
		goto out;
	}

	id = ksmbd_session_rpc_open(work->sess, name);
	if (id < 0) {
		pr_err("Unable to open RPC pipe: %d\n", id);
		err = id;
		goto out;
	}

	rsp->hdr.Status = STATUS_SUCCESS;
	rsp->StructureSize = cpu_to_le16(89);
	rsp->OplockLevel = SMB2_OPLOCK_LEVEL_NONE;
	rsp->Reserved = 0;
	rsp->CreateAction = cpu_to_le32(FILE_OPENED);

	rsp->CreationTime = cpu_to_le64(0);
	rsp->LastAccessTime = cpu_to_le64(0);
	rsp->ChangeTime = cpu_to_le64(0);
	rsp->AllocationSize = cpu_to_le64(0);
	rsp->EndofFile = cpu_to_le64(0);
	rsp->FileAttributes = ATTR_NORMAL_LE;
	rsp->Reserved2 = 0;
	rsp->VolatileFileId = id;
	rsp->PersistentFileId = 0;
	rsp->CreateContextsOffset = 0;
	rsp->CreateContextsLength = 0;

	err = ksmbd_iov_pin_rsp(work, rsp, offsetof(struct smb2_create_rsp, Buffer));
	if (err)
		goto out;

	kfree(name);
	return 0;

out:
	switch (err) {
	case -EINVAL:
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		break;
	case -ENOSPC:
	case -ENOMEM:
		rsp->hdr.Status = STATUS_NO_MEMORY;
		break;
	}

	if (!IS_ERR(name))
		kfree(name);

	smb2_set_err_rsp(work);
	return err;
}

/**
 * smb2_set_ea() - handler for setting extended attributes using set
 *		info command
 * @eabuf:	set info command buffer
 * @buf_len:	set info command buffer length
 * @path:	dentry path for get ea
 * @get_write:	get write access to a mount
 *
 * Return:	0 on success, otherwise error
 */
int smb2_set_ea(struct smb2_ea_info *eabuf, unsigned int buf_len,
		       const struct path *path, bool get_write)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
#else
	struct user_namespace *user_ns = mnt_user_ns(path->mnt);
#endif
	char *attr_name = NULL, *value;
	int rc = 0;
	unsigned int next = 0;

	if (buf_len < sizeof(struct smb2_ea_info) + eabuf->EaNameLength +
			le16_to_cpu(eabuf->EaValueLength))
		return -EINVAL;

	attr_name = kmalloc(XATTR_NAME_MAX + 1, KSMBD_DEFAULT_GFP);
	if (!attr_name)
		return -ENOMEM;

	do {
		if (!eabuf->EaNameLength)
			goto next;

		ksmbd_debug(SMB,
			    "name : <%s>, name_len : %u, value_len : %u, next : %u\n",
			    eabuf->name, eabuf->EaNameLength,
			    le16_to_cpu(eabuf->EaValueLength),
			    le32_to_cpu(eabuf->NextEntryOffset));

		if (eabuf->EaNameLength >
		    (XATTR_NAME_MAX - XATTR_USER_PREFIX_LEN)) {
			rc = -EINVAL;
			break;
		}

		memcpy(attr_name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN);
		memcpy(&attr_name[XATTR_USER_PREFIX_LEN], eabuf->name,
		       eabuf->EaNameLength);
		attr_name[XATTR_USER_PREFIX_LEN + eabuf->EaNameLength] = '\0';
		value = (char *)&eabuf->name + eabuf->EaNameLength + 1;

		if (!eabuf->EaValueLength) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			rc = ksmbd_vfs_casexattr_len(idmap,
#else
			rc = ksmbd_vfs_casexattr_len(user_ns,
#endif
						     path->dentry,
						     attr_name,
						     XATTR_USER_PREFIX_LEN +
						     eabuf->EaNameLength);

			/* delete the EA only when it exits */
			if (rc > 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
				rc = ksmbd_vfs_remove_xattr(idmap,
#else
				rc = ksmbd_vfs_remove_xattr(user_ns,
#endif
							    path,
							    attr_name,
							    get_write);

				if (rc < 0) {
					ksmbd_debug(SMB,
						    "remove xattr failed(%d)\n",
						    rc);
					break;
				}
			}

			/* if the EA doesn't exist, just do nothing. */
			rc = 0;
		} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			rc = ksmbd_vfs_setxattr(idmap,
#else
			rc = ksmbd_vfs_setxattr(user_ns,
#endif
						path, attr_name, value,
						le16_to_cpu(eabuf->EaValueLength),
						0, get_write);
			if (rc < 0) {
				ksmbd_debug(SMB,
					    "ksmbd_vfs_setxattr is failed(%d)\n",
					    rc);
				break;
			}
		}

next:
		next = le32_to_cpu(eabuf->NextEntryOffset);
		if (next == 0 || buf_len < next)
			break;
		buf_len -= next;
		eabuf = (struct smb2_ea_info *)((char *)eabuf + next);
		if (buf_len < sizeof(struct smb2_ea_info)) {
			rc = -EINVAL;
			break;
		}

		if (buf_len < sizeof(struct smb2_ea_info) + eabuf->EaNameLength +
				le16_to_cpu(eabuf->EaValueLength)) {
			rc = -EINVAL;
			break;
		}
	} while (next != 0);

	kfree(attr_name);
	return rc;
}

static noinline int smb2_set_stream_name_xattr(const struct path *path,
					       struct ksmbd_file *fp,
					       char *stream_name, int s_type)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
#else
	struct user_namespace *user_ns = mnt_user_ns(path->mnt);
#endif
	size_t xattr_stream_size;
	char *xattr_stream_name;
	int rc;

	rc = ksmbd_vfs_xattr_stream_name(stream_name,
					 &xattr_stream_name,
					 &xattr_stream_size,
					 s_type);
	if (rc)
		return rc;

	fp->stream.name = xattr_stream_name;
	fp->stream.size = xattr_stream_size;

	/* Check if there is stream prefix in xattr space */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = ksmbd_vfs_casexattr_len(idmap,
#else
	rc = ksmbd_vfs_casexattr_len(user_ns,
#endif
				     path->dentry,
				     xattr_stream_name,
				     xattr_stream_size);
	if (rc >= 0)
		return 0;

	if (fp->cdoption == FILE_OPEN_LE) {
		ksmbd_debug(SMB, "XATTR stream name lookup failed: %d\n", rc);
		return -EBADF;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = ksmbd_vfs_setxattr(idmap, path,
#else
	rc = ksmbd_vfs_setxattr(user_ns, path,
#endif
				xattr_stream_name, NULL, 0, 0, false);
	if (rc < 0)
		pr_err("Failed to store XATTR stream name :%d\n", rc);
	return 0;
}

static int smb2_remove_smb_xattrs(const struct path *path)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
#else
	struct user_namespace *user_ns = mnt_user_ns(path->mnt);
#endif
	char *name, *xattr_list = NULL;
	ssize_t xattr_list_len;
	int err = 0;

	xattr_list_len = ksmbd_vfs_listxattr(path->dentry, &xattr_list);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		ksmbd_debug(SMB, "empty xattr in the file\n");
		goto out;
	}

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		ksmbd_debug(SMB, "%s, len %zd\n", name, strlen(name));

		if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN) &&
		    !strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,
			     STREAM_PREFIX_LEN)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			err = ksmbd_vfs_remove_xattr(idmap, path, name, true);
#else
			err = ksmbd_vfs_remove_xattr(user_ns, path, name, true);
#endif
			if (err)
				ksmbd_debug(SMB, "remove xattr failed : %s\n",
					    name);
		}
	}
out:
	kvfree(xattr_list);
	return err;
}

static int smb2_create_truncate(const struct path *path)
{
	int rc = vfs_truncate(path, 0);

	if (rc) {
		pr_err("vfs_truncate failed, rc %d\n", rc);
		return rc;
	}

	rc = smb2_remove_smb_xattrs(path);
	if (rc == -EOPNOTSUPP)
		rc = 0;
	if (rc)
		ksmbd_debug(SMB,
			    "ksmbd_truncate_stream_name_xattr failed, rc %d\n",
			    rc);
	return rc;
}

static void smb2_new_xattrs(struct ksmbd_tree_connect *tcon, const struct path *path,
			    struct ksmbd_file *fp)
{
	struct xattr_dos_attrib da = {0};
	int rc;

	if (!test_share_config_flag(tcon->share_conf,
				    KSMBD_SHARE_FLAG_STORE_DOS_ATTRS))
		return;

	da.version = 4;
	da.attr = le32_to_cpu(fp->f_ci->m_fattr);
	da.itime = da.create_time = fp->create_time;
	da.flags = XATTR_DOSINFO_ATTRIB | XATTR_DOSINFO_CREATE_TIME |
		XATTR_DOSINFO_ITIME;

	rc = compat_ksmbd_vfs_set_dos_attrib_xattr(path, &da, true);
	if (rc)
		ksmbd_debug(SMB, "failed to store file attribute into xattr\n");
}

static void smb2_update_xattrs(struct ksmbd_tree_connect *tcon,
			       const struct path *path, struct ksmbd_file *fp)
{
	struct xattr_dos_attrib da;
	int rc;

	fp->f_ci->m_fattr &= ~(ATTR_HIDDEN_LE | ATTR_SYSTEM_LE);

	/* get FileAttributes from XATTR_NAME_DOS_ATTRIBUTE */
	if (!test_share_config_flag(tcon->share_conf,
				    KSMBD_SHARE_FLAG_STORE_DOS_ATTRS))
		return;

	rc = compat_ksmbd_vfs_get_dos_attrib_xattr(path, path->dentry, &da);
	if (rc > 0) {
		fp->f_ci->m_fattr = cpu_to_le32(da.attr);
		fp->create_time = da.create_time;
		fp->itime = da.itime;
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static int smb2_creat(struct ksmbd_work *work,
		      struct path *path, char *name, int open_flags,
		      umode_t posix_mode, bool is_dir)
#else
static int smb2_creat(struct ksmbd_work *work, struct path *path, char *name,
		      int open_flags, umode_t posix_mode, bool is_dir)
#endif
{
	struct ksmbd_tree_connect *tcon = work->tcon;
	struct ksmbd_share_config *share = tcon->share_conf;
	umode_t mode;
	int rc;

	if (!(open_flags & O_CREAT))
		return -EBADF;

	ksmbd_debug(SMB, "file does not exist, so creating\n");
	if (is_dir == true) {
		ksmbd_debug(SMB, "creating directory\n");

		mode = share_config_directory_mode(share, posix_mode);
		rc = ksmbd_vfs_mkdir(work, name, mode);
		if (rc)
			return rc;
	} else {
		ksmbd_debug(SMB, "creating regular file\n");

		mode = share_config_create_mode(share, posix_mode);
		rc = ksmbd_vfs_create(work, name, mode);
		if (rc)
			return rc;
	}

	rc = ksmbd_vfs_kern_path(work, name, 0, path, 0);
	if (rc) {
		pr_err("cannot get linux path (%s), err = %d\n",
		       name, rc);
		return rc;
	}
	return 0;
}

static int smb2_create_sd_buffer(struct ksmbd_work *work,
				 struct smb2_create_req *req,
				 const struct path *path)
{
	struct create_context *context;
	struct create_sd_buf_req *sd_buf;

	if (!req->CreateContextsOffset)
		return -ENOENT;

	/* Parse SD BUFFER create contexts */
	context = smb2_find_context_vals(req, SMB2_CREATE_SD_BUFFER, 4);
	if (!context)
		return -ENOENT;
	else if (IS_ERR(context))
		return PTR_ERR(context);

	ksmbd_debug(SMB,
		    "Set ACLs using SMB2_CREATE_SD_BUFFER context\n");
	sd_buf = (struct create_sd_buf_req *)context;
	if (le16_to_cpu(context->DataOffset) +
	    le32_to_cpu(context->DataLength) <
	    sizeof(struct create_sd_buf_req))
		return -EINVAL;
	return set_info_sec(work->conn, work->tcon, path, &sd_buf->ntsd,
			    le32_to_cpu(sd_buf->ccontext.DataLength), true, false);
}

void ksmbd_acls_fattr(struct smb_fattr *fattr,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			     struct mnt_idmap *idmap,
#else
			     struct user_namespace *mnt_userns,
#endif
			     struct inode *inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	vfsuid_t vfsuid = i_uid_into_vfsuid(idmap, inode);
	vfsgid_t vfsgid = i_gid_into_vfsgid(idmap, inode);
#else
	vfsuid_t vfsuid = i_uid_into_vfsuid(mnt_userns, inode);
	vfsgid_t vfsgid = i_gid_into_vfsgid(mnt_userns, inode);
#endif

	fattr->cf_uid = vfsuid_into_kuid(vfsuid);
	fattr->cf_gid = vfsgid_into_kgid(vfsgid);
#else
	fattr->cf_uid = i_uid_into_mnt(mnt_userns, inode);
	fattr->cf_gid = i_gid_into_mnt(mnt_userns, inode);
#endif
#else
	fattr->cf_uid = inode->i_uid;
	fattr->cf_gid = inode->i_gid;
#endif
	fattr->cf_mode = inode->i_mode;
	fattr->cf_acls = NULL;
	fattr->cf_dacls = NULL;

	if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
		fattr->cf_acls = get_inode_acl(inode, ACL_TYPE_ACCESS);
#else
		fattr->cf_acls = get_acl(inode, ACL_TYPE_ACCESS);
#endif
		if (S_ISDIR(inode->i_mode))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
			fattr->cf_dacls = get_inode_acl(inode, ACL_TYPE_DEFAULT);
#else
			fattr->cf_dacls = get_acl(inode, ACL_TYPE_DEFAULT);
#endif
	}
}

enum {
	DURABLE_RECONN_V2 = 1,
	DURABLE_RECONN,
	DURABLE_REQ_V2,
	DURABLE_REQ,
};

struct durable_info {
	struct ksmbd_file *fp;
	unsigned short int type;
	bool persistent;
	bool reconnected;
	unsigned int timeout;
	char *CreateGuid;
};

static int parse_durable_handle_context(struct ksmbd_work *work,
					struct smb2_create_req *req,
					struct lease_ctx_info *lc,
					struct durable_info *dh_info)
{
	struct ksmbd_conn *conn = work->conn;
	struct create_context *context;
	int dh_idx, err = 0;
	u64 persistent_id = 0;
	int req_op_level;
	static const char * const durable_arr[] = {"DH2C", "DHnC", "DH2Q", "DHnQ"};

	req_op_level = req->RequestedOplockLevel;
	for (dh_idx = DURABLE_RECONN_V2; dh_idx <= ARRAY_SIZE(durable_arr);
	     dh_idx++) {
		context = smb2_find_context_vals(req, durable_arr[dh_idx - 1], 4);
		if (IS_ERR(context)) {
			err = PTR_ERR(context);
			goto out;
		}
		if (!context)
			continue;

		switch (dh_idx) {
		case DURABLE_RECONN_V2:
		{
			struct create_durable_reconn_v2_req *recon_v2;

			if (dh_info->type == DURABLE_RECONN ||
			    dh_info->type == DURABLE_REQ_V2) {
				err = -EINVAL;
				goto out;
			}

			if (le16_to_cpu(context->DataOffset) +
				le32_to_cpu(context->DataLength) <
			    sizeof(struct create_durable_reconn_v2_req)) {
				err = -EINVAL;
				goto out;
			}

			recon_v2 = (struct create_durable_reconn_v2_req *)context;
			persistent_id = recon_v2->Fid.PersistentFileId;
			dh_info->fp = ksmbd_lookup_durable_fd(persistent_id);
			if (!dh_info->fp) {
				ksmbd_debug(SMB, "Failed to get durable handle state\n");
				err = -EBADF;
				goto out;
			}

			if (memcmp(dh_info->fp->create_guid, recon_v2->CreateGuid,
				   SMB2_CREATE_GUID_SIZE)) {
				err = -EBADF;
				ksmbd_put_durable_fd(dh_info->fp);
				goto out;
			}

			/* Validate client identity to prevent durable handle theft */
			if (memcmp(dh_info->fp->client_guid, conn->ClientGUID,
				   SMB2_CLIENT_GUID_SIZE)) {
				pr_err_ratelimited("durable reconnect v2: client GUID mismatch\n");
				err = -EBADF;
				ksmbd_put_durable_fd(dh_info->fp);
				goto out;
			}

			dh_info->type = dh_idx;
			dh_info->reconnected = true;
			ksmbd_debug(SMB,
				"reconnect v2 Persistent-id from reconnect = %llu\n",
					persistent_id);
			break;
		}
		case DURABLE_RECONN:
		{
			struct create_durable_reconn_req *recon;

			if (dh_info->type == DURABLE_RECONN_V2 ||
			    dh_info->type == DURABLE_REQ_V2) {
				err = -EINVAL;
				goto out;
			}

			if (le16_to_cpu(context->DataOffset) +
				le32_to_cpu(context->DataLength) <
			    sizeof(struct create_durable_reconn_req)) {
				err = -EINVAL;
				goto out;
			}

			recon = (struct create_durable_reconn_req *)context;
			persistent_id = recon->Data.Fid.PersistentFileId;
			dh_info->fp = ksmbd_lookup_durable_fd(persistent_id);
			if (!dh_info->fp) {
				ksmbd_debug(SMB, "Failed to get durable handle state\n");
				err = -EBADF;
				goto out;
			}

			/* Validate client identity to prevent durable handle theft */
			if (memcmp(dh_info->fp->client_guid, conn->ClientGUID,
				   SMB2_CLIENT_GUID_SIZE)) {
				pr_err_ratelimited("durable reconnect: client GUID mismatch\n");
				err = -EBADF;
				ksmbd_put_durable_fd(dh_info->fp);
				goto out;
			}

			dh_info->type = dh_idx;
			dh_info->reconnected = true;
			ksmbd_debug(SMB, "reconnect Persistent-id from reconnect = %llu\n",
				    persistent_id);
			break;
		}
		case DURABLE_REQ_V2:
		{
			struct create_durable_req_v2 *durable_v2_blob;

			if (dh_info->type == DURABLE_RECONN ||
			    dh_info->type == DURABLE_RECONN_V2) {
				err = -EINVAL;
				goto out;
			}

			if (le16_to_cpu(context->DataOffset) +
				le32_to_cpu(context->DataLength) <
			    sizeof(struct create_durable_req_v2)) {
				err = -EINVAL;
				goto out;
			}

			durable_v2_blob =
				(struct create_durable_req_v2 *)context;
			ksmbd_debug(SMB, "Request for durable v2 open\n");
			dh_info->fp = ksmbd_lookup_fd_cguid(durable_v2_blob->CreateGuid);
			if (dh_info->fp) {
				if (!memcmp(conn->ClientGUID, dh_info->fp->client_guid,
					    SMB2_CLIENT_GUID_SIZE)) {
					if (!(req->hdr.Flags & SMB2_FLAGS_REPLAY_OPERATIONS)) {
						err = -ENOEXEC;
						goto out;
					}

					dh_info->fp->conn = conn;
					dh_info->reconnected = true;
					goto out;
				}
			}

			if ((lc && (lc->req_state & SMB2_LEASE_HANDLE_CACHING_LE)) ||
			    req_op_level == SMB2_OPLOCK_LEVEL_BATCH) {
				dh_info->CreateGuid =
					durable_v2_blob->CreateGuid;
				dh_info->persistent =
					le32_to_cpu(durable_v2_blob->Flags);
				dh_info->timeout =
					le32_to_cpu(durable_v2_blob->Timeout);
				dh_info->type = dh_idx;
			}
			break;
		}
		case DURABLE_REQ:
			if (dh_info->type == DURABLE_RECONN)
				goto out;
			if (dh_info->type == DURABLE_RECONN_V2 ||
			    dh_info->type == DURABLE_REQ_V2) {
				err = -EINVAL;
				goto out;
			}

			if ((lc && (lc->req_state & SMB2_LEASE_HANDLE_CACHING_LE)) ||
			    req_op_level == SMB2_OPLOCK_LEVEL_BATCH) {
				ksmbd_debug(SMB, "Request for durable open\n");
				dh_info->type = dh_idx;
			}
		}
	}

out:
	return err;
}

/**
 * smb2_open() - handler for smb file open request
 * @work:	smb work containing request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_open(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	struct ksmbd_tree_connect *tcon = work->tcon;
	struct smb2_create_req *req;
	struct smb2_create_rsp *rsp;
	struct path path;
	struct ksmbd_share_config *share = tcon->share_conf;
	struct ksmbd_file *fp = NULL;
	struct file *filp = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = NULL;
#else
	struct user_namespace *user_ns = NULL;
#endif
	struct kstat stat;
	struct create_context *context;
	struct lease_ctx_info *lc = NULL;
	struct create_ea_buf_req *ea_buf = NULL;
	struct oplock_info *opinfo;
	struct durable_info dh_info = {0};
	__le32 *next_ptr = NULL;
	int req_op_level = 0, open_flags = 0, may_flags = 0, file_info = 0;
	int rc = 0;
	int contxt_cnt = 0, query_disk_id = 0;
#ifdef CONFIG_KSMBD_FRUIT
	int fruit_ctxt = 0;
#endif
	bool maximal_access_ctxt = false, posix_ctxt = false;
	int s_type = 0;
	int next_off = 0;
	char *name = NULL;
	char *stream_name = NULL;
	bool file_present = false, created = false, already_permitted = false;
	int share_ret, need_truncate = 0;
	u64 time;
	umode_t posix_mode = 0;
	__le32 daccess, maximal_access = 0;
	int iov_len = 0;

	ksmbd_debug(SMB, "Received smb2 create request\n");

	WORK_BUFFERS(work, req, rsp);

	if (req->hdr.NextCommand && !work->next_smb2_rcv_hdr_off &&
	    (req->hdr.Flags & SMB2_FLAGS_RELATED_OPERATIONS)) {
		ksmbd_debug(SMB, "invalid flag in chained command\n");
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		smb2_set_err_rsp(work);
		return -EINVAL;
	}

	if (test_share_config_flag(share, KSMBD_SHARE_FLAG_PIPE)) {
		ksmbd_debug(SMB, "IPC pipe create request\n");
		return create_smb2_pipe(work);
	}

	if (req->CreateContextsOffset && tcon->posix_extensions) {
		context = smb2_find_context_vals(req, SMB2_CREATE_TAG_POSIX, 16);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			goto err_out2;
		} else if (context) {
			struct create_posix *posix = (struct create_posix *)context;

			if (le16_to_cpu(context->DataOffset) +
				le32_to_cpu(context->DataLength) <
			    sizeof(struct create_posix) - 4) {
				rc = -EINVAL;
				goto err_out2;
			}
			ksmbd_debug(SMB, "get posix context\n");

			posix_mode = le32_to_cpu(posix->Mode);
			posix_ctxt = true;
		}
	}

	if (req->NameLength) {
		if ((u64)le16_to_cpu(req->NameOffset) + le16_to_cpu(req->NameLength) >
		    get_rfc1002_len(work->request_buf) + 4) {
			rc = -EINVAL;
			goto err_out2;
		}

		name = smb2_get_name((char *)req + le16_to_cpu(req->NameOffset),
				     le16_to_cpu(req->NameLength),
				     work->conn->local_nls);
		if (IS_ERR(name)) {
			rc = PTR_ERR(name);
			name = NULL;
			goto err_out2;
		}

		ksmbd_debug(SMB, "converted name = %s\n", name);

		if (posix_ctxt == false) {
			if (strchr(name, ':')) {
				if (!test_share_config_flag(work->tcon->share_conf,
							KSMBD_SHARE_FLAG_STREAMS)) {
					rc = -EBADF;
					goto err_out2;
				}
				rc = parse_stream_name(name, &stream_name, &s_type);
				if (rc < 0)
					goto err_out2;
#ifdef CONFIG_KSMBD_FRUIT
				/*
				 * AFP_AfpInfo stream interception: when
				 * a macOS client opens the AFP_AfpInfo
				 * named stream, ksmbd serves AFP metadata
				 * from xattrs rather than requiring a real
				 * alternate data stream.
				 */
				if (stream_name &&
				    conn->is_fruit &&
				    ksmbd_fruit_is_afpinfo_stream(stream_name)) {
					ksmbd_debug(SMB,
						    "Fruit: AFP_AfpInfo stream for %s\n",
						    name);
				}
#endif
			}

			rc = ksmbd_validate_filename(name);
			if (rc < 0)
				goto err_out2;
		}

		if (ksmbd_share_veto_filename(share, name)) {
			rc = -ENOENT;
			ksmbd_debug(SMB, "Reject open(), vetoed file: %s\n",
				    name);
			goto err_out2;
		}
	} else {
		name = kstrdup("", KSMBD_DEFAULT_GFP);
		if (!name) {
			rc = -ENOMEM;
			goto err_out2;
		}
	}

	req_op_level = req->RequestedOplockLevel;

	if (server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE &&
	    req->CreateContextsOffset) {
		lc = parse_lease_state(req);
		rc = parse_durable_handle_context(work, req, lc, &dh_info);
		if (rc) {
			ksmbd_debug(SMB, "error parsing durable handle context\n");
			goto err_out2;
		}

		if (dh_info.reconnected == true) {
			rc = smb2_check_durable_oplock(conn, share, dh_info.fp, lc, name);
			if (rc) {
				ksmbd_put_durable_fd(dh_info.fp);
				goto err_out2;
			}

			rc = ksmbd_reopen_durable_fd(work, dh_info.fp);
			if (rc) {
				ksmbd_put_durable_fd(dh_info.fp);
				goto err_out2;
			}

			if (ksmbd_override_fsids(work)) {
				rc = -ENOMEM;
				ksmbd_put_durable_fd(dh_info.fp);
				goto err_out2;
			}

			fp = dh_info.fp;
			file_info = FILE_OPENED;

			rc = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);
			if (rc)
				goto err_out1;

			ksmbd_put_durable_fd(fp);
			goto reconnected_fp;
		}
	} else if (req_op_level == SMB2_OPLOCK_LEVEL_LEASE)
		lc = parse_lease_state(req);

	if (le32_to_cpu(req->ImpersonationLevel) > le32_to_cpu(IL_DELEGATE_LE)) {
		pr_err_ratelimited("Invalid impersonationlevel : 0x%x\n",
				   le32_to_cpu(req->ImpersonationLevel));
		rc = -EIO;
		rsp->hdr.Status = STATUS_BAD_IMPERSONATION_LEVEL;
		goto err_out2;
	}

	if (req->CreateOptions && !(req->CreateOptions & CREATE_OPTIONS_MASK)) {
		pr_err_ratelimited("Invalid create options : 0x%x\n",
				   le32_to_cpu(req->CreateOptions));
		rc = -EINVAL;
		goto err_out2;
	} else {
		if (req->CreateOptions & FILE_SEQUENTIAL_ONLY_LE &&
		    req->CreateOptions & FILE_RANDOM_ACCESS_LE)
			req->CreateOptions &= ~(FILE_SEQUENTIAL_ONLY_LE);

		if (req->CreateOptions &
		    (FILE_OPEN_BY_FILE_ID_LE | CREATE_TREE_CONNECTION |
		     FILE_RESERVE_OPFILTER_LE)) {
			rc = -EOPNOTSUPP;
			goto err_out2;
		}

		if (req->CreateOptions & FILE_DIRECTORY_FILE_LE) {
			if (req->CreateOptions & FILE_NON_DIRECTORY_FILE_LE) {
				rc = -EINVAL;
				goto err_out2;
			} else if (req->CreateOptions & FILE_NO_COMPRESSION_LE) {
				req->CreateOptions &= ~(FILE_NO_COMPRESSION_LE);
			}
		}
	}

	if (le32_to_cpu(req->CreateDisposition) >
	    le32_to_cpu(FILE_OVERWRITE_IF_LE)) {
		pr_err_ratelimited("Invalid create disposition : 0x%x\n",
				   le32_to_cpu(req->CreateDisposition));
		rc = -EINVAL;
		goto err_out2;
	}

	if (!(req->DesiredAccess & DESIRED_ACCESS_MASK)) {
		pr_err_ratelimited("Invalid desired access : 0x%x\n",
				   le32_to_cpu(req->DesiredAccess));
		rc = -EACCES;
		goto err_out2;
	}

	if (req->FileAttributes && !(req->FileAttributes & ATTR_MASK_LE)) {
		pr_err_ratelimited("Invalid file attribute : 0x%x\n",
				   le32_to_cpu(req->FileAttributes));
		rc = -EINVAL;
		goto err_out2;
	}

	if (req->CreateContextsOffset) {
		/*
		 * TODO: dispatch to registered create context handlers
		 * via ksmbd_find_create_context() instead of inline
		 * processing.  See ksmbd_create_ctx.h for the API.
		 */

		/* Parse non-durable handle create contexts */
		context = smb2_find_context_vals(req, SMB2_CREATE_EA_BUFFER, 4);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			goto err_out2;
		} else if (context) {
			ea_buf = (struct create_ea_buf_req *)context;
			if (le16_to_cpu(context->DataOffset) +
			    le32_to_cpu(context->DataLength) <
			    sizeof(struct create_ea_buf_req)) {
				rc = -EINVAL;
				goto err_out2;
			}
			if (req->CreateOptions & FILE_NO_EA_KNOWLEDGE_LE) {
				rsp->hdr.Status = STATUS_ACCESS_DENIED;
				rc = -EACCES;
				goto err_out2;
			}
		}

		context = smb2_find_context_vals(req,
						 SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST, 4);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			goto err_out2;
		} else if (context) {
			ksmbd_debug(SMB,
				    "get query maximal access context\n");
			maximal_access_ctxt = 1;
		}

		context = smb2_find_context_vals(req,
						 SMB2_CREATE_TIMEWARP_REQUEST, 4);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			goto err_out2;
		} else if (context) {
			__le64 *twrp_ts;
			u64 nts, unix_ts;
			struct tm tm;
			char gmt_token[KSMBD_VSS_GMT_TOKEN_LEN];
			char *snap_path;

			ksmbd_debug(SMB, "get timewarp context\n");

			if (le16_to_cpu(context->DataOffset) +
			    le32_to_cpu(context->DataLength) <
			    sizeof(__le64)) {
				rc = -EINVAL;
				goto err_out2;
			}

			twrp_ts = (__le64 *)((char *)context +
				  le16_to_cpu(context->DataOffset) +
				  4);

			/*
			 * Convert Windows FILETIME (100ns intervals
			 * since 1601-01-01) to Unix timestamp.
			 */
			nts = le64_to_cpu(*twrp_ts);
			unix_ts = (nts / 10000000ULL) - 11644473600ULL;

			time64_to_tm(unix_ts, 0, &tm);
			snprintf(gmt_token, sizeof(gmt_token),
				 "@GMT-%04ld.%02d.%02d-%02d.%02d.%02d",
				 tm.tm_year + 1900,
				 tm.tm_mon + 1, tm.tm_mday,
				 tm.tm_hour, tm.tm_min, tm.tm_sec);

			snap_path = kzalloc(PATH_MAX,
					    KSMBD_DEFAULT_GFP);
			if (!snap_path) {
				rc = -ENOMEM;
				goto err_out2;
			}

			rc = ksmbd_vss_resolve_path(share->path,
						    gmt_token,
						    snap_path,
						    PATH_MAX);
			if (rc) {
				ksmbd_debug(SMB,
					    "timewarp: no snapshot %s\n",
					    gmt_token);
				kfree(snap_path);
				rc = -EBADF;
				goto err_out2;
			}

			ksmbd_debug(SMB,
				    "timewarp: resolved %s\n",
				    gmt_token);
			kfree(snap_path);
		}
	}

	if (ksmbd_override_fsids(work)) {
		rc = -ENOMEM;
		goto err_out2;
	}

	rc = ksmbd_vfs_kern_path(work, name, LOOKUP_NO_SYMLINKS,
				 &path, 1);
	if (!rc) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
		file_present = true;
#endif

		if (req->CreateOptions & FILE_DELETE_ON_CLOSE_LE) {
			/*
			 * If file exists with under flags, return access
			 * denied error.
			 */
			if (req->CreateDisposition == FILE_OVERWRITE_IF_LE ||
			    req->CreateDisposition == FILE_OPEN_IF_LE) {
				rc = -EACCES;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
				path_put(&path);
#endif
				goto err_out;
			}

			if (!test_tree_conn_flag(tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
				ksmbd_debug(SMB,
					    "User does not have write permission\n");
				rc = -EACCES;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
				path_put(&path);
#endif
				goto err_out;
			}
		} else if (d_is_symlink(path.dentry)) {
			rc = -EACCES;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
			path_put(&path);
#endif
			goto err_out;
		}

		file_present = true;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		idmap = mnt_idmap(path.mnt);
#else
		user_ns = mnt_user_ns(path.mnt);
#endif
#else
		user_ns = NULL;
#endif
	} else {
		if (rc != -ENOENT)
			goto err_out;
		ksmbd_debug(SMB, "can not get linux path for %s, rc = %d\n",
			    name, rc);
		rc = 0;
	}

	if (stream_name) {
		if (req->CreateOptions & FILE_DIRECTORY_FILE_LE) {
			if (s_type == DATA_STREAM) {
				rc = -EIO;
				rsp->hdr.Status = STATUS_NOT_A_DIRECTORY;
			}
		} else {
			if (file_present && S_ISDIR(d_inode(path.dentry)->i_mode) &&
			    s_type == DATA_STREAM) {
				rc = -EIO;
				rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;
			}
		}

		if (req->CreateOptions & FILE_DIRECTORY_FILE_LE &&
		    req->FileAttributes & ATTR_NORMAL_LE) {
			rsp->hdr.Status = STATUS_NOT_A_DIRECTORY;
			rc = -EIO;
		}

		if (rc < 0)
			goto err_out;
	}

	if (file_present && req->CreateOptions & FILE_NON_DIRECTORY_FILE_LE &&
	    S_ISDIR(d_inode(path.dentry)->i_mode) &&
	    !(req->CreateOptions & FILE_DELETE_ON_CLOSE_LE)) {
		ksmbd_debug(SMB, "open() argument is a directory: %s, %x\n",
			    name, req->CreateOptions);
		rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;
		rc = -EIO;
		goto err_out;
	}

	if (file_present && (req->CreateOptions & FILE_DIRECTORY_FILE_LE) &&
	    !(req->CreateDisposition == FILE_CREATE_LE) &&
	    !S_ISDIR(d_inode(path.dentry)->i_mode)) {
		rsp->hdr.Status = STATUS_NOT_A_DIRECTORY;
		rc = -EIO;
		goto err_out;
	}

	if (!stream_name && file_present &&
	    req->CreateDisposition == FILE_CREATE_LE) {
		rc = -EEXIST;
		goto err_out;
	}

	daccess = smb_map_generic_desired_access(req->DesiredAccess);

	if (file_present && !(req->CreateOptions & FILE_DELETE_ON_CLOSE_LE)) {
		rc = smb_check_perm_dacl(conn, &path, &daccess,
					 sess->user->uid);
		if (rc)
			goto err_out;
	}

	if (daccess & FILE_MAXIMAL_ACCESS_LE) {
		if (!file_present) {
			daccess = cpu_to_le32(GENERIC_ALL_FLAGS);
		} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			ksmbd_vfs_query_maximal_access(idmap,
						       path.dentry,
						       &daccess);
#else
			rc = ksmbd_vfs_query_maximal_access(user_ns,
							    path.dentry,
							    &daccess);
			if (rc)
				goto err_out;
#endif
			already_permitted = true;
		}
		maximal_access = daccess;
	}

	open_flags = smb2_create_open_flags(file_present, daccess,
					    req->CreateDisposition,
					    &may_flags,
					    req->CreateOptions,
					    file_present ? d_inode(path.dentry)->i_mode : 0);

	if (!test_tree_conn_flag(tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		if (open_flags & (O_CREAT | O_TRUNC)) {
			ksmbd_debug(SMB,
				    "User does not have write permission\n");
			rc = -EACCES;
			goto err_out;
		}
	}

	/*create file if not present */
	if (!file_present) {
		rc = smb2_creat(work, &path, name, open_flags,
				posix_mode,
				req->CreateOptions & FILE_DIRECTORY_FILE_LE);
		if (rc) {
			if (rc == -ENOENT) {
				rc = -EIO;
				rsp->hdr.Status = STATUS_OBJECT_PATH_NOT_FOUND;
			}
			goto err_out;
		}

		created = true;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		idmap = mnt_idmap(path.mnt);
#else
		user_ns = mnt_user_ns(path.mnt);
#endif
		if (ea_buf) {
			if (le32_to_cpu(ea_buf->ccontext.DataLength) <
			    sizeof(struct smb2_ea_info)) {
				rc = -EINVAL;
				goto err_out;
			}

			rc = smb2_set_ea(&ea_buf->ea,
					 le32_to_cpu(ea_buf->ccontext.DataLength),
					 &path, false);
			if (rc == -EOPNOTSUPP)
				rc = 0;
			else if (rc)
				goto err_out;
		}
	} else if (!already_permitted) {
		/* FILE_READ_ATTRIBUTE is allowed without inode_permission,
		 * because execute(search) permission on a parent directory,
		 * is already granted.
		 */
		if (daccess & ~(FILE_READ_ATTRIBUTES_LE | FILE_READ_CONTROL_LE)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			rc = inode_permission(idmap,
#else
			rc = inode_permission(user_ns,
#endif
					      d_inode(path.dentry),
					      may_flags);
#else
			rc = inode_permission(d_inode(path.dentry), may_flags);
#endif
			if (rc)
				goto err_out;

			if ((daccess & FILE_DELETE_LE) ||
			    (req->CreateOptions & FILE_DELETE_ON_CLOSE_LE)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
				rc = inode_permission(idmap,
						      d_inode(path.dentry->d_parent),
						      MAY_EXEC | MAY_WRITE);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
				rc = ksmbd_vfs_may_delete(idmap,
#else
				rc = ksmbd_vfs_may_delete(user_ns,
#endif
							  path.dentry);
#endif
				if (rc)
					goto err_out;
			}
		}
	}

	rc = ksmbd_query_inode_status(path.dentry->d_parent);
	if (rc == KSMBD_INODE_STATUS_PENDING_DELETE) {
		rc = -EBUSY;
		goto err_out;
	}

	rc = 0;
	filp = dentry_open(&path, open_flags, current_cred());
	if (IS_ERR(filp)) {
		rc = PTR_ERR(filp);
		pr_err("dentry open for dir failed, rc %d\n", rc);
		goto err_out;
	}

	/* Post-open TOCTOU check: verify file is within share root */
	if (!path_is_under(&filp->f_path,
			   &work->tcon->share_conf->vfs_path)) {
		pr_err_ratelimited("open path escapes share root\n");
		fput(filp);
		rc = -EACCES;
		goto err_out;
	}

	if (file_present) {
		if (!(open_flags & O_TRUNC))
			file_info = FILE_OPENED;
		else
			file_info = FILE_OVERWRITTEN;

		if ((req->CreateDisposition & FILE_CREATE_MASK_LE) ==
		    FILE_SUPERSEDE_LE)
			file_info = FILE_SUPERSEDED;
	} else if (open_flags & O_CREAT) {
		file_info = FILE_CREATED;
	}

	ksmbd_vfs_set_fadvise(filp, req->CreateOptions);

	/* Obtain Volatile-ID */
	fp = ksmbd_open_fd(work, filp);
	if (IS_ERR(fp)) {
		fput(filp);
		rc = PTR_ERR(fp);
		fp = NULL;
		goto err_out;
	}

	/* Get Persistent-ID */
	ksmbd_open_durable_fd(fp);
	if (!has_file_id(fp->persistent_id)) {
		rc = -ENOMEM;
		goto err_out;
	}

	fp->cdoption = req->CreateDisposition;
	fp->daccess = daccess;
	fp->saccess = req->ShareAccess;
	fp->coption = req->CreateOptions;

	/* Set default windows and posix acls if creating new file */
	if (created) {
		int posix_acl_rc;
		struct inode *inode = d_inode(path.dentry);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		posix_acl_rc = ksmbd_vfs_inherit_posix_acl(idmap,
							   &path,
							   d_inode(path.dentry->d_parent));
#else
		posix_acl_rc = ksmbd_vfs_inherit_posix_acl(user_ns,
							   &path,
							   d_inode(path.dentry->d_parent));
#endif
		if (posix_acl_rc)
			ksmbd_debug(SMB, "inherit posix acl failed : %d\n", posix_acl_rc);

		if (test_share_config_flag(work->tcon->share_conf,
					   KSMBD_SHARE_FLAG_ACL_XATTR)) {
			rc = smb_inherit_dacl(conn, &path, sess->user->uid,
					      sess->user->gid);
		}

		if (rc) {
			rc = smb2_create_sd_buffer(work, req, &path);
			if (rc) {
				if (posix_acl_rc)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
					ksmbd_vfs_set_init_posix_acl(idmap,
								     &path);
#else
					ksmbd_vfs_set_init_posix_acl(user_ns,
								     &path);
#endif

				if (test_share_config_flag(work->tcon->share_conf,
							   KSMBD_SHARE_FLAG_ACL_XATTR)) {
					struct smb_fattr fattr;
					struct smb_ntsd *pntsd;
					int pntsd_size, ace_num = 0;
					unsigned int sd_buf_size;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
					ksmbd_acls_fattr(&fattr, idmap, inode);
#else
					ksmbd_acls_fattr(&fattr, user_ns, inode);
#endif
					if (fattr.cf_acls)
						ace_num = fattr.cf_acls->a_count;
					if (fattr.cf_dacls)
						ace_num += fattr.cf_dacls->a_count;

					sd_buf_size =
						sizeof(struct smb_ntsd) +
						sizeof(struct smb_sid) * 3 +
						sizeof(struct smb_acl) +
						sizeof(struct smb_ace) *
						ace_num * 2;
					pntsd = kmalloc(sd_buf_size,
							KSMBD_DEFAULT_GFP);
					if (!pntsd) {
						posix_acl_release(fattr.cf_acls);
						posix_acl_release(fattr.cf_dacls);
						goto err_out;
					}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
					rc = build_sec_desc(idmap,
#else
					rc = build_sec_desc(user_ns,
#endif
							    pntsd, NULL, 0,
							    OWNER_SECINFO |
							    GROUP_SECINFO |
							    DACL_SECINFO,
							    &pntsd_size,
							    &fattr,
							    sd_buf_size);
					posix_acl_release(fattr.cf_acls);
					posix_acl_release(fattr.cf_dacls);
					if (rc) {
						kfree(pntsd);
						goto err_out;
					}

					rc = ksmbd_vfs_set_sd_xattr(conn,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
								    idmap,
#else
								    user_ns,
#endif
								    &path,
								    pntsd,
								    pntsd_size,
								    false);
					kfree(pntsd);
					if (rc)
						pr_err("failed to store ntacl in xattr : %d\n",
						       rc);
				}
			}
		}
		rc = 0;
	}

	if (stream_name) {
		rc = smb2_set_stream_name_xattr(&path,
						fp,
						stream_name,
						s_type);
		if (rc)
			goto err_out;
		file_info = FILE_CREATED;
	}

	fp->attrib_only = !(req->DesiredAccess & ~(FILE_READ_ATTRIBUTES_LE |
			FILE_WRITE_ATTRIBUTES_LE | FILE_SYNCHRONIZE_LE));

	fp->is_posix_ctxt = posix_ctxt;

	/* fp should be searchable through ksmbd_inode.m_fp_list
	 * after daccess, saccess, attrib_only, and stream are
	 * initialized.
	 */
	down_write(&fp->f_ci->m_lock);
	list_add(&fp->node, &fp->f_ci->m_fp_list);
	up_write(&fp->f_ci->m_lock);

	/* Check delete pending among previous fp before oplock break */
	if (ksmbd_inode_pending_delete(fp)) {
		rc = -EBUSY;
		goto err_out;
	}

	if (file_present || created)
		path_put(&path);

	if (!S_ISDIR(file_inode(filp)->i_mode) && open_flags & O_TRUNC &&
	    !fp->attrib_only && !stream_name) {
		smb_break_all_oplock(work, fp);
		need_truncate = 1;
	}

	share_ret = ksmbd_smb_check_shared_mode(fp->filp, fp);
	if (!test_share_config_flag(work->tcon->share_conf, KSMBD_SHARE_FLAG_OPLOCKS) ||
	    (req_op_level == SMB2_OPLOCK_LEVEL_LEASE &&
	     !(conn->vals->capabilities & SMB2_GLOBAL_CAP_LEASING))) {
		if (share_ret < 0 && !S_ISDIR(file_inode(fp->filp)->i_mode)) {
			rc = share_ret;
			goto err_out1;
		}
	} else {
		if (req_op_level == SMB2_OPLOCK_LEVEL_LEASE && lc) {
			if (S_ISDIR(file_inode(filp)->i_mode)) {
				lc->req_state &= ~SMB2_LEASE_WRITE_CACHING_LE;
				lc->is_dir = true;
			}

			/*
			 * Compare parent lease using parent key. If there is no
			 * a lease that has same parent key, Send lease break
			 * notification.
			 */
			smb_send_parent_lease_break_noti(fp, lc);

			req_op_level = smb2_map_lease_to_oplock(lc->req_state);
			ksmbd_debug(SMB,
				    "lease req for(%s) req oplock state 0x%x, lease state 0x%x\n",
				    name, req_op_level, lc->req_state);
			rc = find_same_lease_key(sess, fp->f_ci, lc);
			if (rc)
				goto err_out1;
		} else if (open_flags == O_RDONLY &&
			   (req_op_level == SMB2_OPLOCK_LEVEL_BATCH ||
			    req_op_level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))
			req_op_level = SMB2_OPLOCK_LEVEL_II;

		rc = smb_grant_oplock(work, req_op_level,
				      fp->persistent_id, fp,
				      le32_to_cpu(req->hdr.Id.SyncId.TreeId),
				      lc, share_ret);
		if (rc < 0)
			goto err_out1;
	}

	if (req->CreateOptions & FILE_DELETE_ON_CLOSE_LE)
		ksmbd_fd_set_delete_on_close(fp, file_info);

	if (need_truncate) {
		rc = smb2_create_truncate(&fp->filp->f_path);
		if (rc)
			goto err_out1;
	}

	if (req->CreateContextsOffset) {
		struct create_alloc_size_req *az_req;

		az_req = (struct create_alloc_size_req *)smb2_find_context_vals(req,
					SMB2_CREATE_ALLOCATION_SIZE, 4);
		if (IS_ERR(az_req)) {
			rc = PTR_ERR(az_req);
			goto err_out1;
		} else if (az_req) {
			loff_t alloc_size;
			int err;

			if (le16_to_cpu(az_req->ccontext.DataOffset) +
			    le32_to_cpu(az_req->ccontext.DataLength) <
			    sizeof(struct create_alloc_size_req)) {
				rc = -EINVAL;
				goto err_out1;
			}
			alloc_size = le64_to_cpu(az_req->AllocationSize);
			ksmbd_debug(SMB,
				    "request smb2 create allocate size : %llu\n",
				    alloc_size);
			smb_break_all_levII_oplock(work, fp, 1);
			err = vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0,
					    alloc_size);
			if (err < 0)
				ksmbd_debug(SMB,
					    "vfs_fallocate is failed : %d\n",
					    err);
		}

		context = smb2_find_context_vals(req, SMB2_CREATE_QUERY_ON_DISK_ID, 4);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			goto err_out1;
		} else if (context) {
			ksmbd_debug(SMB, "get query on disk id context\n");
			query_disk_id = 1;
		}

#ifdef CONFIG_KSMBD_FRUIT
		if ((server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS) &&
		    conn->is_fruit == false) {
			context = smb2_find_context_vals(req, SMB2_CREATE_AAPL, 4);
			if (IS_ERR(context)) {
				rc = PTR_ERR(context);
				goto err_out1;
			} else if (context) {
				const void *context_data;
				size_t data_len;
				struct fruit_client_info *client_info;

				if (le16_to_cpu(context->NameLength) == 4 &&
				    le32_to_cpu(context->DataLength) >= sizeof(struct fruit_client_info)) {

					context_data = (const __u8 *)context +
						le16_to_cpu(context->DataOffset);
					data_len = le32_to_cpu(context->DataLength);

					rc = fruit_validate_create_context(context);
					if (rc) {
						ksmbd_debug(SMB, "Invalid fruit create context: %d\n", rc);
						rc = 0;
						goto continue_create;
					}

					client_info = kzalloc(sizeof(struct fruit_client_info),
							      KSMBD_DEFAULT_GFP);
					if (!client_info) {
						rc = -ENOMEM;
						goto err_out1;
					}

					size_t copy_len = min(data_len,
							     sizeof(struct fruit_client_info));
					memcpy(client_info, context_data, copy_len);

					fruit_debug_client_info(client_info);

					rc = fruit_negotiate_capabilities(conn, client_info);
					if (rc) {
						ksmbd_debug(SMB, "Fruit capability negotiation failed: %d\n", rc);
						kfree(client_info);
						client_info = NULL;
						rc = 0;
						goto continue_create;
					}
					conn->is_fruit = true;
					fruit_ctxt = 1;

					kfree(client_info);
					client_info = NULL;
				} else {
					ksmbd_debug(SMB, "Fruit context too small: name_len=%u, data_len=%u\n",
						    le16_to_cpu(context->NameLength),
						    le32_to_cpu(context->DataLength));
				}
			}
		} else if (conn->is_fruit) {
			fruit_ctxt = 1;
		}
continue_create: ;
#endif /* CONFIG_KSMBD_FRUIT */
	}

	rc = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);
	if (rc)
		goto err_out1;

	if (stat.result_mask & STATX_BTIME)
		fp->create_time = ksmbd_UnixTimeToNT(stat.btime);
	else
		fp->create_time = ksmbd_UnixTimeToNT(stat.ctime);
	if (req->FileAttributes || fp->f_ci->m_fattr == 0)
		fp->f_ci->m_fattr =
			cpu_to_le32(smb2_get_dos_mode(&stat, le32_to_cpu(req->FileAttributes)));

	if (!created)
		smb2_update_xattrs(tcon, &path, fp);
	else
		smb2_new_xattrs(tcon, &path, fp);

	memcpy(fp->client_guid, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE);

	if (dh_info.type == DURABLE_REQ_V2 || dh_info.type == DURABLE_REQ) {
		if (dh_info.type == DURABLE_REQ_V2 && dh_info.persistent &&
		    test_share_config_flag(work->tcon->share_conf,
					   KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY))
			fp->is_persistent = true;
		else
			fp->is_durable = true;

		if (dh_info.type == DURABLE_REQ_V2) {
			memcpy(fp->create_guid, dh_info.CreateGuid,
					SMB2_CREATE_GUID_SIZE);
			if (dh_info.timeout)
				fp->durable_timeout =
					min_t(unsigned int, dh_info.timeout,
					      DURABLE_HANDLE_MAX_TIMEOUT);
			else
				fp->durable_timeout = 60;
		}
	}

reconnected_fp:
	rsp->StructureSize = cpu_to_le16(89);
	rcu_read_lock();
	opinfo = rcu_dereference(fp->f_opinfo);
	rsp->OplockLevel = opinfo != NULL ? opinfo->level : 0;
	rcu_read_unlock();
	rsp->Reserved = 0;
	rsp->CreateAction = cpu_to_le32(file_info);
	rsp->CreationTime = cpu_to_le64(fp->create_time);
	time = ksmbd_UnixTimeToNT(stat.atime);
	rsp->LastAccessTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.mtime);
	rsp->LastWriteTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.ctime);
	rsp->ChangeTime = cpu_to_le64(time);
	rsp->AllocationSize = S_ISDIR(stat.mode) ? 0 :
		cpu_to_le64(stat.blocks << 9);
	rsp->EndofFile = S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);
	rsp->FileAttributes = fp->f_ci->m_fattr;

	rsp->Reserved2 = 0;

	rsp->PersistentFileId = fp->persistent_id;
	rsp->VolatileFileId = fp->volatile_id;

	rsp->CreateContextsOffset = 0;
	rsp->CreateContextsLength = 0;
	iov_len = offsetof(struct smb2_create_rsp, Buffer);

	/* If lease is request send lease context response */
	if (opinfo && opinfo->is_lease) {
		struct create_context *lease_ccontext;

		ksmbd_debug(SMB, "lease granted on(%s) lease state 0x%x\n",
			    name, opinfo->o_lease->state);
		rsp->OplockLevel = SMB2_OPLOCK_LEVEL_LEASE;

		lease_ccontext = (struct create_context *)rsp->Buffer;
		contxt_cnt++;
		create_lease_buf(rsp->Buffer, opinfo->o_lease);
		le32_add_cpu(&rsp->CreateContextsLength,
			     conn->vals->create_lease_size);
		iov_len += conn->vals->create_lease_size;
		next_ptr = &lease_ccontext->Next;
		next_off = conn->vals->create_lease_size;
	}

	if (maximal_access_ctxt) {
		struct create_context *mxac_ccontext;

		if (maximal_access == 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			ksmbd_vfs_query_maximal_access(idmap,
#else
			ksmbd_vfs_query_maximal_access(user_ns,
#endif
						       fp->filp->f_path.dentry,
						       &maximal_access);
		mxac_ccontext = (struct create_context *)(rsp->Buffer +
				le32_to_cpu(rsp->CreateContextsLength));
		contxt_cnt++;
		create_mxac_rsp_buf(rsp->Buffer +
				le32_to_cpu(rsp->CreateContextsLength),
				le32_to_cpu(maximal_access));
		le32_add_cpu(&rsp->CreateContextsLength,
			     conn->vals->create_mxac_size);
		iov_len += conn->vals->create_mxac_size;
		if (next_ptr)
			*next_ptr = cpu_to_le32(next_off);
		next_ptr = &mxac_ccontext->Next;
		next_off = conn->vals->create_mxac_size;
	}

	if (query_disk_id) {
		struct create_context *disk_id_ccontext;

		disk_id_ccontext = (struct create_context *)(rsp->Buffer +
				le32_to_cpu(rsp->CreateContextsLength));
		contxt_cnt++;
		create_disk_id_rsp_buf(rsp->Buffer +
				le32_to_cpu(rsp->CreateContextsLength),
				stat.ino, tcon->id);
		le32_add_cpu(&rsp->CreateContextsLength,
			     conn->vals->create_disk_id_size);
		iov_len += conn->vals->create_disk_id_size;
		if (next_ptr)
			*next_ptr = cpu_to_le32(next_off);
		next_ptr = &disk_id_ccontext->Next;
		next_off = conn->vals->create_disk_id_size;
	}

	if (dh_info.type == DURABLE_REQ || dh_info.type == DURABLE_REQ_V2) {
		struct create_context *durable_ccontext;

		durable_ccontext = (struct create_context *)(rsp->Buffer +
				le32_to_cpu(rsp->CreateContextsLength));
		contxt_cnt++;
		if (dh_info.type == DURABLE_REQ) {
			create_durable_rsp_buf(rsp->Buffer +
					le32_to_cpu(rsp->CreateContextsLength));
			le32_add_cpu(&rsp->CreateContextsLength,
					conn->vals->create_durable_size);
			iov_len += conn->vals->create_durable_size;
		} else {
			create_durable_v2_rsp_buf(rsp->Buffer +
					le32_to_cpu(rsp->CreateContextsLength),
					fp);
			le32_add_cpu(&rsp->CreateContextsLength,
					conn->vals->create_durable_v2_size);
			iov_len += conn->vals->create_durable_v2_size;
		}

		if (next_ptr)
			*next_ptr = cpu_to_le32(next_off);
		next_ptr = &durable_ccontext->Next;
		next_off = conn->vals->create_durable_size;
	}

	if (posix_ctxt) {
		struct create_context *posix_ccontext;

		posix_ccontext = (struct create_context *)(rsp->Buffer +
				le32_to_cpu(rsp->CreateContextsLength));
		contxt_cnt++;
		create_posix_rsp_buf(rsp->Buffer +
				le32_to_cpu(rsp->CreateContextsLength),
				fp);
		le32_add_cpu(&rsp->CreateContextsLength,
			     conn->vals->create_posix_size);
		iov_len += conn->vals->create_posix_size;
		if (next_ptr)
			*next_ptr = cpu_to_le32(next_off);
		next_ptr = &posix_ccontext->Next;
		next_off = conn->vals->create_posix_size;
	}

#ifdef CONFIG_KSMBD_FRUIT
	if (fruit_ctxt) {
		struct create_context *fruit_ccontext;
		size_t fruit_size = 0;

		fruit_ccontext = (struct create_context *)(rsp->Buffer +
				le32_to_cpu(rsp->CreateContextsLength));
		contxt_cnt++;
		create_fruit_rsp_buf(rsp->Buffer +
				le32_to_cpu(rsp->CreateContextsLength),
				conn, &fruit_size);
		le32_add_cpu(&rsp->CreateContextsLength, fruit_size);
		iov_len += fruit_size;
		if (next_ptr)
			*next_ptr = cpu_to_le32(next_off);
	}
#endif

	if (contxt_cnt > 0) {
		rsp->CreateContextsOffset =
			cpu_to_le32(offsetof(struct smb2_create_rsp, Buffer));
	}

err_out:
	if (rc && (file_present || created))
		path_put(&path);
err_out1:
	ksmbd_revert_fsids(work);
err_out2:
	if (!rc) {
		ksmbd_update_fstate(&work->sess->file_table, fp, FP_INITED);
		rc = ksmbd_iov_pin_rsp(work, (void *)rsp, iov_len);
	}
	if (rc) {
		if (rc == -EINVAL)
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		else if (rc == -EOPNOTSUPP)
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
		else if (rc == -EACCES || rc == -ESTALE || rc == -EXDEV)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (rc == -ENOENT)
			rsp->hdr.Status = STATUS_OBJECT_NAME_INVALID;
		else if (rc == -EPERM)
			rsp->hdr.Status = STATUS_SHARING_VIOLATION;
		else if (rc == -EBUSY)
			rsp->hdr.Status = STATUS_DELETE_PENDING;
		else if (rc == -EBADF)
			rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;
		else if (rc == -ENOEXEC)
			rsp->hdr.Status = STATUS_DUPLICATE_OBJECTID;
		else if (rc == -ENXIO)
			rsp->hdr.Status = STATUS_NO_SUCH_DEVICE;
		else if (rc == -EEXIST)
			rsp->hdr.Status = STATUS_OBJECT_NAME_COLLISION;
		else if (rc == -EMFILE)
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		if (!rsp->hdr.Status)
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;

		if (fp)
			ksmbd_fd_put(work, fp);
		smb2_set_err_rsp(work);
		ksmbd_debug(SMB, "Error response: %x\n", rsp->hdr.Status);
	}

	kfree(name);
	kfree(lc);

	return rc;
}
