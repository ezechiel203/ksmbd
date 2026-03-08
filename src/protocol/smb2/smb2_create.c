// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_create.c - SMB2_CREATE (open) handler + helpers
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
#include <kunit/visibility.h>

/* Standard SMB2 create context names are 4 bytes (e.g. "MxAc", "DHnQ"). */
#define SMB2_CREATE_CONTEXT_NAME_SZ	4

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
VISIBLE_IF_KUNIT int smb2_create_open_flags(bool file_present, __le32 access,
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
EXPORT_SYMBOL_IF_KUNIT(smb2_create_open_flags);

/**
 * smb_check_parent_dacl_deny() - Check parent directory DACL for deny ACEs
 * @conn:	SMB connection
 * @parent:	path to the parent directory
 * @uid:	user ID attempting the operation
 * @is_dir:	true if creating a subdirectory, false if creating a file
 *
 * Checks the parent directory's stored Windows ACL for DENY ACEs that
 * would prevent creating files (SEC_DIR_ADD_FILE = 0x02) or subdirectories
 * (SEC_DIR_ADD_SUBDIR = 0x04) within it.
 *
 * This implements Windows-style ACL enforcement for create operations,
 * where DENY ACEs on a parent directory are evaluated before allowing
 * the creation of child entries.
 *
 * Return:	0 if creation is allowed, -EACCES if denied
 */
VISIBLE_IF_KUNIT int smb_check_parent_dacl_deny(struct ksmbd_conn *conn,
						 const struct path *parent,
						 int uid, bool is_dir)
{
	/* S-1-1-0 (Everyone / World) */
	static const struct smb_sid everyone_sid = {
		1, 1, {0, 0, 0, 0, 0, 1}, {0}
	};
	struct smb_ntsd *pntsd = NULL;
	struct smb_acl *pdacl;
	struct smb_ace *ace;
	struct smb_sid user_sid;
	int pntsd_size, acl_size, aces_size;
	unsigned int dacl_offset;
	size_t dacl_struct_end;
	unsigned short ace_size;
	u32 check_mask;
	int i, rc = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = mnt_idmap(parent->mnt);
#else
	struct user_namespace *user_ns = mnt_user_ns(parent->mnt);
#endif

	/* FILE_ADD_FILE = 0x02, FILE_ADD_SUBDIRECTORY = 0x04 */
	check_mask = is_dir ? 0x04 : 0x02;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, idmap,
#else
	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, user_ns,
#endif
					     parent->dentry, &pntsd);
	if (pntsd_size <= 0 || !pntsd)
		return 0;

	dacl_offset = le32_to_cpu(pntsd->dacloffset);
	if (!dacl_offset ||
	    check_add_overflow(dacl_offset, sizeof(struct smb_acl),
			       &dacl_struct_end) ||
	    dacl_struct_end > (size_t)pntsd_size) {
		kfree(pntsd);
		return 0;
	}

	pdacl = (struct smb_acl *)((char *)pntsd + dacl_offset);
	acl_size = pntsd_size - dacl_offset;

	if (le16_to_cpu(pdacl->size) > acl_size ||
	    le16_to_cpu(pdacl->size) < sizeof(struct smb_acl) ||
	    !pdacl->num_aces) {
		kfree(pntsd);
		return 0;
	}

	/* Build user SID for comparison */
	id_to_sid(uid, uid ? SIDOWNER : SIDUNIX_USER, &user_sid);

	/*
	 * Walk all ACEs in order (per Windows ACL evaluation: DENY
	 * ACEs should appear before ALLOW ACEs in a canonical DACL).
	 * If any applicable DENY ACE blocks the requested access,
	 * return -EACCES.
	 */
	ace = (struct smb_ace *)((char *)pdacl + sizeof(struct smb_acl));
	aces_size = acl_size - sizeof(struct smb_acl);
	for (i = 0; i < le16_to_cpu(pdacl->num_aces); i++) {
		bool applies;

		if (offsetof(struct smb_ace, access_req) > aces_size)
			break;
		ace_size = le16_to_cpu(ace->size);
		/*
		 * Minimum ACE size: type(1) + flags(1) + size(2) +
		 * access_req(4) + SID base(8) = 16 bytes.
		 * Note: sizeof(struct smb_ace) includes the max-size
		 * SID array which is much larger than actual ACEs.
		 */
		if (ace_size > aces_size || ace_size < 16)
			break;

		/* Does this ACE apply to our user? */
		applies = (!compare_sids(&user_sid, &ace->sid) ||
			   !compare_sids(&everyone_sid, &ace->sid));

		if (applies &&
		    (ace->type == ACCESS_DENIED_ACE_TYPE ||
		     ace->type == ACCESS_DENIED_CALLBACK_ACE_TYPE) &&
		    (le32_to_cpu(ace->access_req) & check_mask)) {
			ksmbd_debug(SMB,
				    "Parent DACL denies %s creation (ACE type=%d mask=0x%x)\n",
				    is_dir ? "subdir" : "file",
				    ace->type,
				    le32_to_cpu(ace->access_req));
			rc = -EACCES;
			break;
		}

		aces_size -= ace_size;
		ace = (struct smb_ace *)((char *)ace + ace_size);
	}

	kfree(pntsd);
	return rc;
}
EXPORT_SYMBOL_IF_KUNIT(smb_check_parent_dacl_deny);

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
	char *name = ERR_PTR(-EINVAL);

	WORK_BUFFERS(work, req, rsp);

	if ((u64)le16_to_cpu(req->NameOffset) + le16_to_cpu(req->NameLength) >
	    get_rfc1002_len(work->request_buf) + 4) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		err = -EINVAL;
		goto out;
	}

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
	if (rc >= 0) {
		/*
		 * Stream xattr exists on disk.  Replace fp->stream.name
		 * with the on-disk name so that normalized-name queries
		 * return the canonical (creation-time) casing, not the
		 * casing the client used for this particular open.
		 */
		char *xattr_list = NULL, *n;
		ssize_t xattr_list_len;

		xattr_list_len = ksmbd_vfs_listxattr(path->dentry,
						     &xattr_list);
		if (xattr_list_len > 0) {
			for (n = xattr_list;
			     n - xattr_list < xattr_list_len;
			     n += strlen(n) + 1) {
				if (strncasecmp(xattr_stream_name, n,
						xattr_stream_size))
					continue;
				if (strcmp(xattr_stream_name, n)) {
					char *dup = kstrdup(n,
							    KSMBD_DEFAULT_GFP);
					if (dup) {
						kfree(fp->stream.name);
						fp->stream.name = dup;
						fp->stream.size = strlen(dup) + 1;
					}
				}
				break;
			}
		}
		kvfree(xattr_list);
		return 0;
	}

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

/*
 * C.4: Remove user extended attributes (EAs) that are not SMB streams.
 * MS-SMB2 §3.3.5.9: FILE_SUPERSEDE must reset the file to a clean state,
 * including removing all user EAs.  Stream xattrs (user.DosStream.*) are
 * already removed by smb2_remove_smb_xattrs(); this function removes the
 * remaining user.* xattrs (i.e. real SMB EAs).
 * Errors are non-fatal: best-effort removal only.
 */
static void smb2_remove_user_eas(const struct path *path)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
#else
	struct user_namespace *user_ns = mnt_user_ns(path->mnt);
#endif
	char *name, *xattr_list = NULL;
	ssize_t xattr_list_len;
	int err;

	xattr_list_len = ksmbd_vfs_listxattr(path->dentry, &xattr_list);
	if (xattr_list_len <= 0)
		return;

	for (name = xattr_list; name - xattr_list < xattr_list_len;
	     name += strlen(name) + 1) {
		/* Only touch user.* xattrs */
		if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
			continue;
		/* Skip stream xattrs — handled by smb2_remove_smb_xattrs() */
		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,
			     STREAM_PREFIX_LEN))
			continue;
		/* Skip the DOS attribute xattr */
		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], "DOSATTRIB",
			     strlen("DOSATTRIB")))
			continue;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		err = ksmbd_vfs_remove_xattr(idmap, path, name, true);
#else
		err = ksmbd_vfs_remove_xattr(user_ns, path, name, true);
#endif
		if (err)
			ksmbd_debug(SMB,
				    "C.4: remove user EA failed: %s err=%d\n",
				    name, err);
	}
	kvfree(xattr_list);
}

static int smb2_create_truncate(const struct path *path, bool is_supersede)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
#else
	struct user_namespace *user_ns = mnt_user_ns(path->mnt);
#endif
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

	/*
	 * C.4: FILE_SUPERSEDE must reset all file metadata.
	 * Remove the stored security descriptor xattr so the
	 * new create's SD (or the inherited SD) takes effect.
	 * Ignore errors — removal is best-effort on SUPERSEDE.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ksmbd_vfs_remove_sd_xattrs(idmap, path);
#else
	ksmbd_vfs_remove_sd_xattrs(user_ns, path);
#endif

	/*
	 * C.4 (continued): On FILE_SUPERSEDE only, also remove all
	 * user extended attributes (SMB EAs).  FILE_OVERWRITE and
	 * FILE_OVERWRITE_IF preserve EAs; SUPERSEDE must clear them.
	 * MS-SMB2 §3.3.5.9.
	 */
	if (is_supersede)
		smb2_remove_user_eas(path);

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

VISIBLE_IF_KUNIT int smb2_create_sd_buffer(struct ksmbd_work *work,
					   struct smb2_create_req *req,
					   const struct path *path)
{
	struct create_context *context;
	struct create_sd_buf_req *sd_buf;

	if (!req->CreateContextsOffset)
		return -ENOENT;

	/* Parse SD BUFFER create contexts */
	context = smb2_find_context_vals(req, SMB2_CREATE_SD_BUFFER, SMB2_CREATE_CONTEXT_NAME_SZ);
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
EXPORT_SYMBOL_IF_KUNIT(smb2_create_sd_buffer);

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
	bool is_replay;
	unsigned int timeout;
	char *CreateGuid;
};

VISIBLE_IF_KUNIT int parse_durable_handle_context(struct ksmbd_work *work,
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
		context = smb2_find_context_vals(req, durable_arr[dh_idx - 1], SMB2_CREATE_CONTEXT_NAME_SZ);
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
				dh_info->fp = ksmbd_ph_restore(work,
							      persistent_id,
							      recon_v2->CreateGuid);
				if (!dh_info->fp) {
					ksmbd_debug(SMB,
						    "Failed to get durable handle state\n");
					err = -EBADF;
					goto out;
				}
			}

			if (memcmp(dh_info->fp->create_guid, recon_v2->CreateGuid,
				   SMB2_CREATE_GUID_SIZE)) {
				err = -EBADF;
				ksmbd_put_durable_fd(dh_info->fp);
				goto out;
			}

			/*
			 * Validate client identity to prevent durable handle
			 * theft.  Per MS-SMB2 §3.3.5.9.12, the ClientGUID
			 * check only applies when the handle was granted
			 * with a lease.  For oplock-only handles the client
			 * may reconnect with a different ClientGUID.
			 */
			if (dh_info->fp->f_opinfo &&
			    dh_info->fp->f_opinfo->is_lease &&
			    memcmp(dh_info->fp->client_guid, conn->ClientGUID,
				   SMB2_CLIENT_GUID_SIZE)) {
				pr_err_ratelimited("durable reconnect v2: client GUID mismatch\n");
				err = -EBADF;
				ksmbd_put_durable_fd(dh_info->fp);
				goto out;
			}

			/*
			 * P-03: Check durable handle reconnect timeout.
			 * MS-SMB2 §3.3.5.9.7-12: if the durable handle's
			 * reconnect window has expired, reject the reconnect.
			 * durable_scavenger_timeout is set (in jiffies) at
			 * disconnect time in ksmbd_open_durable_fd().
			 */
			if (dh_info->fp->durable_scavenger_timeout &&
			    time_after(jiffies,
				       dh_info->fp->durable_scavenger_timeout)) {
				ksmbd_debug(SMB,
					    "durable reconnect v2: handle expired\n");
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

			/*
			 * Per MS-SMB2, ClientGUID check only applies for
			 * lease-based handles.
			 */
			if (dh_info->fp->f_opinfo &&
			    dh_info->fp->f_opinfo->is_lease &&
			    memcmp(dh_info->fp->client_guid, conn->ClientGUID,
				   SMB2_CLIENT_GUID_SIZE)) {
				pr_err_ratelimited("durable reconnect: client GUID mismatch\n");
				err = -EBADF;
				ksmbd_put_durable_fd(dh_info->fp);
				goto out;
			}

			/*
			 * P-03: Check durable handle reconnect timeout.
			 * MS-SMB2 §3.3.5.9.7: reject if the reconnect
			 * window has expired.
			 */
			if (dh_info->fp->durable_scavenger_timeout &&
			    time_after(jiffies,
				       dh_info->fp->durable_scavenger_timeout)) {
				ksmbd_debug(SMB,
					    "durable reconnect v1: handle expired\n");
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

					/* DHv2 replay (MS-SMB2 3.3.5.9.10) */
					dh_info->is_replay = true;
					dh_info->type = DURABLE_REQ_V2;
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
EXPORT_SYMBOL_IF_KUNIT(parse_durable_handle_context);

static int smb2_dispatch_create_context_handlers_pass(struct ksmbd_work *work,
						      struct smb2_create_req *req,
						      struct ksmbd_file *fp,
						      bool app_instance_id_only)
{
	struct create_context *cc;
	unsigned int next = 0;
	unsigned int remain_len;

	if (!req->CreateContextsOffset || !req->CreateContextsLength)
		return 0;

	cc = (struct create_context *)((char *)req +
				       le32_to_cpu(req->CreateContextsOffset));
	remain_len = le32_to_cpu(req->CreateContextsLength);

	do {
		struct ksmbd_create_ctx_handler *h;
		char *name;
		void *ctx_data;
		unsigned int name_off, name_len, value_off, value_len, cc_len;
		bool is_app_instance_id;
		int rc;

		cc = (struct create_context *)((char *)cc + next);
		if (remain_len < offsetof(struct create_context, Buffer))
			return -EINVAL;

		next = le32_to_cpu(cc->Next);
		name_off = le16_to_cpu(cc->NameOffset);
		name_len = le16_to_cpu(cc->NameLength);
		value_off = le16_to_cpu(cc->DataOffset);
		value_len = le32_to_cpu(cc->DataLength);
		cc_len = next ? next : remain_len;

		if ((next & 0x7) != 0 ||
		    next > remain_len ||
		    name_off != offsetof(struct create_context, Buffer) ||
		    name_len < 4 ||
		    name_off + name_len > cc_len ||
		    (value_off & 0x7) != 0 ||
		    (value_len &&
		     value_off < name_off + (name_len < 8 ? 8 : name_len)) ||
		    (u64)value_off + value_len > cc_len)
			return -EINVAL;

		name = (char *)cc + name_off;
		ctx_data = (char *)cc + value_off;
		is_app_instance_id =
			(name_len == 16 &&
			 !memcmp(name, SMB2_CREATE_APP_INSTANCE_ID, 16));
		if (is_app_instance_id != app_instance_id_only)
			goto next_ctx;

		h = ksmbd_find_create_context(name, name_len);
		if (!h)
			goto next_ctx;

		if (!h->on_request) {
			ksmbd_put_create_context(h);
			goto next_ctx;
		}

		rc = h->on_request(work, fp, ctx_data, value_len);
		ksmbd_put_create_context(h);
		if (rc)
			return rc;

next_ctx:
		remain_len -= next;
	} while (next != 0);

	return 0;
}

static int smb2_dispatch_registered_create_contexts(struct ksmbd_work *work,
						    struct smb2_create_req *req,
						    struct ksmbd_file *fp)
{
	int rc;

	/*
	 * Process APP_INSTANCE_VERSION before APP_INSTANCE_ID to preserve
	 * version-aware close semantics regardless of request context order.
	 */
	rc = smb2_dispatch_create_context_handlers_pass(work, req, fp, false);
	if (rc)
		return rc;

	return smb2_dispatch_create_context_handlers_pass(work, req, fp, true);
}

static int smb2_resolve_open_by_file_id(struct ksmbd_work *work,
						struct smb2_create_req *req,
						char **name)
{
	__le64 file_id_le[2];
	u64 volatile_id;
	u64 persistent_id = KSMBD_NO_FID;
	unsigned int name_len = le16_to_cpu(req->NameLength);
	unsigned int name_off = le16_to_cpu(req->NameOffset);
	struct ksmbd_file *id_fp;
	char *path_name;

	if (name_len != sizeof(__le64) &&
	    name_len != 2 * sizeof(__le64))
		return -EOPNOTSUPP;

	if ((u64)name_off + name_len >
	    get_rfc1002_len(work->request_buf) + 4)
		return -EINVAL;

	memcpy(file_id_le, (char *)req + name_off, name_len);
	volatile_id = le64_to_cpu(file_id_le[0]);
	if (name_len == 2 * sizeof(__le64))
		persistent_id = le64_to_cpu(file_id_le[1]);

	if (persistent_id != KSMBD_NO_FID)
		id_fp = ksmbd_lookup_fd_slow(work, volatile_id, persistent_id);
	else
		id_fp = ksmbd_lookup_fd_fast(work, volatile_id);
	if (!id_fp)
		return -ENOENT;

	path_name = convert_to_nt_pathname(work->tcon->share_conf,
					   &id_fp->filp->f_path);
	ksmbd_fd_put(work, id_fp);
	if (IS_ERR(path_name))
		return PTR_ERR(path_name);

	ksmbd_conv_path_to_unix(path_name);
	if (path_name[0] == '/')
		memmove(path_name, path_name + 1, strlen(path_name));

	*name = path_name;
	return 0;
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
	char *twrp_snap_path = NULL; /* snapshot path from TWrp context */
	bool file_present = false, created = false, already_permitted = false;
	bool is_fake_file = false, is_stream_path = false;
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
		/* MS-SMB2 §2.2.13: NameLength MUST be a multiple of 2 (UTF-16LE) */
		if (le16_to_cpu(req->NameLength) & 1) {
			rc = -EINVAL;
			goto err_out2;
		}

		if ((u64)le16_to_cpu(req->NameOffset) + le16_to_cpu(req->NameLength) >
		    get_rfc1002_len(work->request_buf) + 4) {
			rc = -EINVAL;
			goto err_out2;
		}

		if (req->CreateOptions & FILE_OPEN_BY_FILE_ID_LE) {
			rc = smb2_resolve_open_by_file_id(work, req, &name);
			if (rc) {
				if (rc == -ENOENT)
					rc = -EBADF;
				goto err_out2;
			}
			/* Strip the flag so the rest of the path
			 * proceeds normally with the resolved name.
			 */
			req->CreateOptions &= ~FILE_OPEN_BY_FILE_ID_LE;
		} else {
			unsigned int name_len = le16_to_cpu(req->NameLength);
			const __le16 *utf16_name = (const __le16 *)((char *)req +
					le16_to_cpu(req->NameOffset));

			/*
			 * MS-SMB2 §3.3.5.9: A trailing backslash in the
			 * FileName field (UTF-16LE 0x005C as the last char)
			 * is a path-syntax error.  Return
			 * STATUS_OBJECT_PATH_SYNTAX_BAD.
			 */
			if (name_len >= 2 &&
			    utf16_name[name_len / 2 - 1] == cpu_to_le16('\\')) {
				rsp->hdr.Status = STATUS_OBJECT_PATH_SYNTAX_BAD;
				rc = -EINVAL;
				goto err_out2;
			}

			/*
			 * Validate at the UTF-16LE code-point level BEFORE
			 * conversion.  Post-conversion validation fails for
			 * valid Unicode chars (combining chars, fullwidth
			 * forms, surrogates) because failed conversion
			 * produces '?' which is a Windows-reserved char.
			 */
			rc = ksmbd_validate_utf16_filename(utf16_name, name_len);
			if (rc) {
				rsp->hdr.Status = STATUS_OBJECT_NAME_INVALID;
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
		}

		ksmbd_debug(SMB, "converted name = %s\n", name);

		/*
		 * MS-SMB2 §3.3.5.9: paths containing ".." components
		 * that would traverse above the share root are a syntax
		 * error, not an access error.
		 */
		if (name[0] == '.' && name[1] == '.' &&
		    (name[2] == '/' || name[2] == '\0')) {
			rsp->hdr.Status = STATUS_OBJECT_PATH_SYNTAX_BAD;
			rc = -EINVAL;
			goto err_out2;
		}

		if (strstr(name, "/.") != NULL || !strcmp(name, ".") ||
		    !strcmp(name, "..")) {
			char *normalized;

			normalized = ksmbd_normalize_path(name);
			if (IS_ERR(normalized)) {
				rsp->hdr.Status = STATUS_OBJECT_PATH_SYNTAX_BAD;
				rc = PTR_ERR(normalized);
				goto err_out2;
			}

			kfree(name);
			name = normalized;
			ksmbd_debug(SMB, "normalized create name = %s\n", name);
		}

		/*
		 * Handle NTFS metadata fake files:
		 * $Extend\$Quota:$Q:$INDEX_ALLOCATION is a special
		 * pseudo-file used by Windows clients to open a handle
		 * for quota queries.  Map it to the share root so that
		 * subsequent QUERY_INFO / SET_INFO quota requests have
		 * a valid file handle bound to the correct filesystem.
		 */
		if (strncasecmp(name, "$Extend\\$Quota:", 15) == 0 ||
		    strncasecmp(name, "$Extend/$Quota:", 15) == 0) {
			ksmbd_debug(SMB,
				    "Quota fake file requested: %s, mapping to share root\n",
				    name);
			kfree(name);
			name = kstrdup("", KSMBD_DEFAULT_GFP);
			if (!name) {
				rc = -ENOMEM;
				goto err_out2;
			}
			is_fake_file = true;
		}

		if (posix_ctxt == false) {
			if (strchr(name, ':')) {
				if (!test_share_config_flag(work->tcon->share_conf,
							KSMBD_SHARE_FLAG_STREAMS)) {
					rc = -ENOENT;
					goto err_out2;
				}
				is_stream_path = true;
				/*
				 * Streams cannot be directories.  Reject
				 * FILE_DIRECTORY_FILE before parsing the stream
				 * name so that both named streams (foo:bar) and
				 * the default data stream (foo::$DATA) return
				 * STATUS_NOT_A_DIRECTORY.
				 */
				if (req->CreateOptions & FILE_DIRECTORY_FILE_LE) {
					rc = -ENOTDIR;
					goto err_out2;
				}
				rc = parse_stream_name(name, &stream_name, &s_type);
				if (rc < 0) {
					/*
					 * parse_stream_name returns -ENOENT
					 * with stream_name=NULL for the
					 * default data stream (::$DATA).
					 * Treat this as a normal file open.
					 */
					if (!stream_name) {
						rc = 0;
					} else {
						goto err_out2;
					}
				}
				/*
				 * VFS-05: reject stream names containing '/'
				 * to prevent path traversal via xattr names.
				 * A stream name with '/' could address unintended
				 * xattrs via getcasexattr prefix matching.
				 */
				if (stream_name && strchr(stream_name, '/')) {
					rc = -EINVAL;
					goto err_out2;
				}
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

		if (dh_info.is_replay) {
			/*
			 * DHv2 replay (MS-SMB2 3.3.5.9.10): the handle is
			 * still active on this connection.  Validate that
			 * replay parameters match the original request.
			 */
			bool orig_is_lease = false;
			bool req_is_lease = (req_op_level == SMB2_OPLOCK_LEVEL_LEASE);

			fp = dh_info.fp;
			rcu_read_lock();
			opinfo = rcu_dereference(fp->f_opinfo);
			if (opinfo && opinfo->is_lease)
				orig_is_lease = true;
			rcu_read_unlock();

			/* Reject if oplock type changed or lease key mismatches */
			if (orig_is_lease != req_is_lease) {
				ksmbd_put_durable_fd(fp);
				rc = -EACCES;
				rsp->hdr.Status = STATUS_ACCESS_DENIED;
				goto err_out2;
			}

			if (req_is_lease && lc && opinfo && opinfo->o_lease) {
				if (memcmp(lc->lease_key,
					   opinfo->o_lease->lease_key,
					   SMB2_LEASE_KEY_SIZE)) {
					ksmbd_put_durable_fd(fp);
					rc = -EACCES;
					rsp->hdr.Status = STATUS_ACCESS_DENIED;
					goto err_out2;
				}
			}

			/* Suppress DH2Q if replay has no durable-capable oplock */
			if (req_op_level != SMB2_OPLOCK_LEVEL_BATCH &&
			    req_op_level != SMB2_OPLOCK_LEVEL_LEASE)
				dh_info.type = 0;

			if (ksmbd_override_fsids(work)) {
				rc = -ENOMEM;
				ksmbd_put_durable_fd(fp);
				goto err_out2;
			}

			file_info = fp->create_action ? fp->create_action
						      : FILE_OPENED;

			/*
			 * DHv2 pending replay (MS-SMB2 §3.3.5.9.12):
			 * If the original CREATE is still in-flight (waiting
			 * for an oplock/lease break ACK — OPLOCK_ACK_WAIT),
			 * the replay cache has not been populated yet.  Per
			 * the spec the server MUST return
			 * STATUS_FILE_NOT_AVAILABLE rather than blocking or
			 * succeeding spuriously.
			 */
			if (!fp->replay_cache.valid) {
				struct oplock_info *pending_opinfo;
				bool is_pending = false;

				rcu_read_lock();
				pending_opinfo = rcu_dereference(fp->f_opinfo);
				if (pending_opinfo &&
				    pending_opinfo->op_state == OPLOCK_ACK_WAIT)
					is_pending = true;
				rcu_read_unlock();

				if (is_pending) {
					ksmbd_put_durable_fd(fp);
					rc = -EAGAIN;
					rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;
					goto err_out2;
				}
			}

			if (fp->replay_cache.valid) {
				rsp->StructureSize = cpu_to_le16(89);
				rsp->OplockLevel = req_op_level;
				rsp->Reserved = 0;
				rsp->CreateAction = cpu_to_le32(file_info);
				rsp->CreationTime = cpu_to_le64(fp->create_time);
				rsp->LastAccessTime = cpu_to_le64(fp->replay_cache.last_access);
				rsp->LastWriteTime = cpu_to_le64(fp->replay_cache.last_write);
				rsp->ChangeTime = cpu_to_le64(fp->replay_cache.change);
				rsp->AllocationSize = cpu_to_le64(fp->replay_cache.alloc_size);
				rsp->EndofFile = cpu_to_le64(fp->replay_cache.end_of_file);
				rsp->FileAttributes = fp->replay_cache.file_attrs;
				rsp->Reserved2 = 0;
				rsp->PersistentFileId = fp->persistent_id;
				rsp->VolatileFileId = fp->volatile_id;
				rsp->CreateContextsOffset = 0;
				rsp->CreateContextsLength = 0;
				iov_len = offsetof(struct smb2_create_rsp, Buffer);
				ksmbd_put_durable_fd(fp);
				goto durable_create_ctx;
			}

			rc = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);
			if (rc) {
				ksmbd_put_durable_fd(fp);
				goto err_out1;
			}

			ksmbd_put_durable_fd(fp);
			goto reconnected_fp;
		}

		if (dh_info.reconnected == true) {
			/*
			 * C.7: MS-SMB2 §3.3.5.9.13 step 5 — if the client
			 * reconnects with DH2C and Flags has
			 * SMB2_DHANDLE_FLAG_PERSISTENT set, but the stored
			 * open is NOT persistent, reject the reconnect.
			 */
			if (dh_info.type == DURABLE_RECONN_V2) {
				struct create_context *dh2c_ctx;

				dh2c_ctx = smb2_find_context_vals(req,
								  "DH2C", SMB2_CREATE_CONTEXT_NAME_SZ);
				if (!IS_ERR_OR_NULL(dh2c_ctx)) {
					struct create_durable_reconn_v2_req *rv2 =
						(struct create_durable_reconn_v2_req *)dh2c_ctx;
					bool client_wants_persistent =
						!!(le32_to_cpu(rv2->Flags) &
						   SMB2_DHANDLE_FLAG_PERSISTENT);

					if (client_wants_persistent &&
					    !dh_info.fp->is_persistent) {
						ksmbd_debug(SMB,
							    "DH2C: client requests persistent but handle is not\n");
						rc = -EBADF;
						ksmbd_put_durable_fd(dh_info.fp);
						goto err_out2;
					}
				}
			}

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

			/*
			 * MS-SMB2 §3.3.5.9.7 step 14: if the handle
			 * has DELETE_ON_CLOSE set, clear the durable
			 * flag so the handle is no longer preserved
			 * on disconnect.  Suppress the DHnQ/DH2Q
			 * response context.
			 */
			if (fp->is_delete_on_close) {
				fp->is_durable = false;
				fp->is_persistent = false;
				dh_info.type = 0;
			}

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

			if (req->CreateOptions & CREATE_TREE_CONNECTION) {
				rc = -EOPNOTSUPP;
				goto err_out2;
			}

			if (req->CreateOptions & FILE_RESERVE_OPFILTER_LE) {
				rc = -EOPNOTSUPP;
				goto err_out2;
			}

			if (req->CreateOptions & FILE_OPEN_BY_FILE_ID_LE) {
				if (!name) {
					rc = -EINVAL;
					goto err_out2;
				}
				req->CreateOptions &= ~FILE_OPEN_BY_FILE_ID_LE;
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

	if ((req->CreateOptions & FILE_DIRECTORY_FILE_LE) &&
	    (req->FileAttributes & ATTR_TEMPORARY_LE)) {
		rc = -EINVAL;
		goto err_out2;
	}

	if (req->CreateContextsOffset) {
		/*
		 * Built-in contexts are parsed inline below. Registered
		 * create context handlers are dispatched post-open once
		 * a ksmbd_file exists.
		 */

		/* Parse non-durable handle create contexts */
		context = smb2_find_context_vals(req, SMB2_CREATE_EA_BUFFER, SMB2_CREATE_CONTEXT_NAME_SZ);
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
						 SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST, SMB2_CREATE_CONTEXT_NAME_SZ);
		if (IS_ERR(context)) {
			rc = PTR_ERR(context);
			goto err_out2;
		} else if (context) {
			ksmbd_debug(SMB,
				    "get query maximal access context\n");
			maximal_access_ctxt = 1;
		}

		context = smb2_find_context_vals(req,
						 SMB2_CREATE_TIMEWARP_REQUEST, SMB2_CREATE_CONTEXT_NAME_SZ);
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
				    "timewarp: resolved snapshot path: %s\n",
				    snap_path);
			/*
			 * Save the snapshot path; it will replace @name
			 * when opening the file so we open the snapshot
			 * version rather than the live file.
			 */
			twrp_snap_path = snap_path;
		}
	}

	/*
	 * C.1/C.10: If a TWrp context resolved to a snapshot path,
	 * replace the share-relative filename with the snapshot
	 * filesystem path.  The snap_path already contains the full
	 * absolute path to the snapshot version of the file.
	 * We substitute @name with a relative path derived from
	 * the snapshot directory so ksmbd_vfs_kern_path can locate it.
	 */
	if (twrp_snap_path) {
		kfree(name);
		name = twrp_snap_path;
		twrp_snap_path = NULL;
	}

	if (ksmbd_override_fsids(work)) {
		rc = -ENOMEM;
		goto err_out2;
	}

	{
		/*
		 * FILE_OPEN_REPARSE_POINT: open the reparse point (symlink)
		 * itself rather than following it.  When this flag is set we
		 * must NOT pass LOOKUP_NO_SYMLINKS so the path lookup reaches
		 * the symlink dentry without following it.
		 */
		unsigned int lookup_flags = LOOKUP_NO_SYMLINKS;

		if (req->CreateOptions & FILE_OPEN_REPARSE_POINT_LE)
			lookup_flags = 0;

		rc = ksmbd_vfs_kern_path(work, name, lookup_flags, &path, 1);
	}
	if (!rc) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
		file_present = true;
#endif

		if (req->CreateOptions & FILE_DELETE_ON_CLOSE_LE) {
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
			/*
			 * FILE_OPEN_REPARSE_POINT: client wants the symlink
			 * itself — don't return EACCES; continue with the
			 * open so the dentry is passed to dentry_open().
			 * For all other opens, symlinks are blocked.
			 */
			if (!(req->CreateOptions & FILE_OPEN_REPARSE_POINT_LE)) {
				rc = -EACCES;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
				path_put(&path);
#endif
				goto err_out;
			}
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

	/*
	 * Opening a data stream (including :: default stream) of an
	 * existing directory: Windows returns STATUS_FILE_IS_A_DIRECTORY.
	 */
	if (is_stream_path && !stream_name && file_present &&
	    S_ISDIR(d_inode(path.dentry)->i_mode)) {
		rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;
		rc = -EIO;
		goto err_out;
	}

	if (stream_name) {
		if (req->CreateOptions & FILE_DIRECTORY_FILE_LE) {
			if (s_type == DATA_STREAM) {
				rc = -EIO;
				rsp->hdr.Status = STATUS_NOT_A_DIRECTORY;
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
	    S_ISDIR(d_inode(path.dentry)->i_mode) && !stream_name) {
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
		bool had_maximal = !!(daccess & FILE_MAXIMAL_ACCESS_LE);

		if (!sess->user) {
			rc = -EINVAL;
			goto err_out;
		}
		rc = smb_check_perm_dacl(conn, &path, &daccess,
					 sess->user->uid);
		if (rc == -EACCES) {
			/*
			 * Windows hide-on-access-denied: only hide the file
			 * (return STATUS_OBJECT_NAME_NOT_FOUND) when even
			 * READ_CONTROL is denied.  READ_CONTROL is always
			 * granted to the owner, so 0-ACE DACLs (deny-all)
			 * will still allow READ_CONTROL and the file stays
			 * visible — returning STATUS_ACCESS_DENIED rather than
			 * STATUS_OBJECT_NAME_NOT_FOUND (MS-SMB2 behaviour).
			 */
			__le32 ra = FILE_READ_CONTROL_LE;

			if (smb_check_perm_dacl(conn, &path, &ra,
						 sess->user->uid) == -EACCES)
				rc = -EBADF;
			goto err_out;
		} else if (rc) {
			goto err_out;
		}
		/*
		 * If the original request had MAXIMUM_ALLOWED and
		 * smb_check_perm_dacl resolved it using the Windows DACL
		 * (replacing daccess with the computed grant, stripping the
		 * MAXIMUM_ALLOWED bit), skip the POSIX inode_permission check
		 * below — the DACL has already validated access.
		 */
		if (had_maximal && !(daccess & FILE_MAXIMAL_ACCESS_LE)) {
			already_permitted = true;
			maximal_access = daccess;
		}
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

	/*
	 * MS-SMB2 3.3.5.9: If the file already exists and the disposition
	 * is FILE_OVERWRITE or FILE_OVERWRITE_IF, check for Hidden/System
	 * attribute mismatch.  If the existing file has FILE_ATTRIBUTE_HIDDEN
	 * or FILE_ATTRIBUTE_SYSTEM set, and those bits are NOT present in
	 * the request's FileAttributes, the server MUST fail with
	 * STATUS_ACCESS_DENIED.
	 */
	if (file_present &&
	    (req->CreateDisposition == FILE_OVERWRITE_LE ||
	     req->CreateDisposition == FILE_OVERWRITE_IF_LE) &&
	    !S_ISDIR(d_inode(path.dentry)->i_mode)) {
		struct xattr_dos_attrib da = {0};
		int xattr_rc;

		xattr_rc = compat_ksmbd_vfs_get_dos_attrib_xattr(&path,
								  path.dentry,
								  &da);
		if (xattr_rc >= 0) {
			__le32 existing = cpu_to_le32(da.attr);
			__le32 requested = req->FileAttributes;

			if ((existing & ATTR_HIDDEN_LE) &&
			    !(requested & ATTR_HIDDEN_LE)) {
				rc = -EACCES;
				goto err_out;
			}
			if ((existing & ATTR_SYSTEM_LE) &&
			    !(requested & ATTR_SYSTEM_LE)) {
				rc = -EACCES;
				goto err_out;
			}
		}
	}

	/*
	 * MS-SMB2 §3.3.5.9: Before opening the file, purge any
	 * disconnected durable handles with DELETE_ON_CLOSE.
	 * The disconnected handle's close triggers file deletion,
	 * so the subsequent open creates a fresh file.
	 */
	if (file_present &&
	    ksmbd_purge_disconnected_doc(path.dentry)) {
		/*
		 * At least one DOC handle was purged and the file
		 * may have been deleted.  Re-check file existence.
		 */
		if (d_is_negative(path.dentry) || d_unhashed(path.dentry)) {
			path_put(&path);
			file_present = false;
			/* Recompute open_flags for file creation */
			open_flags = smb2_create_open_flags(false, daccess,
					req->CreateDisposition,
					&may_flags,
					req->CreateOptions, 0);
		}
	}

	/*create file if not present */
	if (!file_present) {
		/*
		 * Check parent directory DACL for DENY ACEs that
		 * would prevent creating files or subdirectories.
		 */
		if (sess->user &&
		    test_share_config_flag(tcon->share_conf,
					  KSMBD_SHARE_FLAG_ACL_XATTR)) {
			struct path parent_path;
			char *parent_name;
			char *last_sep;
			bool is_dir_create;

			is_dir_create = !!(req->CreateOptions &
					   FILE_DIRECTORY_FILE_LE);

			parent_name = kstrdup(name, KSMBD_DEFAULT_GFP);
			if (parent_name) {
				last_sep = strrchr(parent_name, '/');
				if (last_sep)
					*last_sep = '\0';
				else
					parent_name[0] = '\0';

				rc = ksmbd_vfs_kern_path(work,
							 parent_name,
							 LOOKUP_NO_SYMLINKS,
							 &parent_path, 1);
				if (!rc) {
					rc = smb_check_parent_dacl_deny(
						conn, &parent_path,
						sess->user->uid,
						is_dir_create);
					path_put(&parent_path);
				} else {
					/* Parent not found is not a
					 * DACL deny error
					 */
					rc = 0;
				}
				kfree(parent_name);
				if (rc)
					goto err_out;
			}
		}

		rc = smb2_creat(work, &path, name, open_flags,
				posix_mode,
				req->CreateOptions & FILE_DIRECTORY_FILE_LE);
		if (rc) {
			if (rc == -ENOENT) {
				/*
				 * MS-SMB2 §3.3.5.9: distinguish between
				 * "path component missing" (PATH_NOT_FOUND)
				 * and "file missing" (NAME_NOT_FOUND).
				 * When O_CREAT is not set (FILE_OPEN /
				 * FILE_OVERWRITE), the file itself is missing.
				 */
				if (!(open_flags & O_CREAT)) {
					rc = -EBADF;
					rsp->hdr.Status =
						STATUS_OBJECT_NAME_NOT_FOUND;
				} else {
					rc = -EIO;
					rsp->hdr.Status =
						STATUS_OBJECT_PATH_NOT_FOUND;
				}
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

	if (!file_present) {
		rc = ksmbd_query_inode_status(path.dentry->d_parent);
		if (rc == KSMBD_INODE_STATUS_PENDING_DELETE) {
			rc = -EBUSY;
			goto err_out;
		}
	}

	rc = 0;

	ksmbd_lease_breaker_enter();
	filp = dentry_open(&path, open_flags, current_cred());
	ksmbd_lease_breaker_exit();
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

	/*
	 * CN-SUPPRESS: arm the per-work suppress flag so that ksmbd_notify.c
	 * can identify FS_ATTRIB events fired from our own xattr init writes
	 * (POSIX ACL, NT SD, DOS attrs) and suppress them.  These writes are
	 * internal server-side operations and must not trigger CHANGE_NOTIFY
	 * for ATTRIBUTES on the client that issued the CREATE.
	 * The flag is cleared after smb2_new_xattrs() below.
	 */
	if (created)
		work->notify_suppress = true;

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

		/*
		 * Apply security descriptor: client-provided SD takes
		 * precedence over inheritance, which takes precedence
		 * over the default POSIX ACL-based SD.
		 */
		rc = smb2_create_sd_buffer(work, req, &path);
		if (rc) {
			/* No client SD buffer; try Windows DACL inheritance */
			if (test_share_config_flag(work->tcon->share_conf,
						   KSMBD_SHARE_FLAG_ACL_XATTR)) {
				rc = smb_inherit_dacl(conn, &path,
						      sess->user->uid,
						      sess->user->gid);
			}

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

	/*
	 * MS-SMB2 §3.3.5.9: a "stat open" only requests
	 * attribute/synchronize/read-control access — it should not
	 * break existing leases.  Zero access mask is not a stat open.
	 *
	 * Note: READ_CONTROL is included here because lease tests
	 * (lease.statopen4) expect it to be a stat open.  For plain
	 * oplocks (no lease context), the oplock break path in
	 * smb_grant_oplock() applies a stricter check that excludes
	 * READ_CONTROL from the stat-open shortcut.
	 */
	{
		__le32 stat_mask = FILE_READ_ATTRIBUTES_LE |
				   FILE_WRITE_ATTRIBUTES_LE |
				   FILE_READ_CONTROL_LE |
				   FILE_SYNCHRONIZE_LE;

		fp->attrib_only = (req->DesiredAccess & stat_mask) &&
				  !(req->DesiredAccess & ~stat_mask);
	}

	fp->is_posix_ctxt = posix_ctxt;

	/* fp should be searchable through ksmbd_inode.m_fp_list
	 * after daccess, saccess, attrib_only, and stream are
	 * initialized.
	 */
	if (WARN_ON_ONCE(!fp->f_ci)) {
		rc = -EIO;
		goto err_out;
	}
	down_write(&fp->f_ci->m_lock);
	list_add(&fp->node, &fp->f_ci->m_fp_list);
	if (posix_ctxt)
		ksmbd_inode_set_posix(fp->f_ci);
	up_write(&fp->f_ci->m_lock);

	if (req->CreateContextsOffset) {
		rc = smb2_dispatch_registered_create_contexts(work, req, fp);
		if (rc)
			goto err_out1;
	}

	/*
	 * Check delete pending among previous fp before oplock break.
	 * In POSIX mode, allow opens to succeed even when delete is
	 * pending -- the file has already been unlinked from the
	 * directory namespace and data persists until the last handle
	 * closes (POSIX unlink semantics).
	 */
	if (!posix_ctxt && ksmbd_inode_pending_delete(fp)) {
		if (!ksmbd_inode_clear_pending_delete_if_only(fp)) {
			rc = -EBUSY;
			goto err_out;
		}
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
			 * notification.  Only when the directory contents
			 * actually changed (new file created, superseded, or
			 * overwritten) — opening an existing file does not
			 * modify the directory and must not break dir leases.
			 */
			if (file_info != FILE_OPENED)
				smb_send_parent_lease_break_noti(fp, lc);

			req_op_level = smb2_map_lease_to_oplock(lc->req_state);
			ksmbd_debug(SMB,
				    "lease req for(%s) req oplock state 0x%x, lease state 0x%x\n",
				    name, req_op_level, lc->req_state);
			rc = find_same_lease_key(sess, file_inode(fp->filp),
						 lc);
			if (rc)
				goto err_out1;
		} else if (open_flags == O_RDONLY &&
			   (req_op_level == SMB2_OPLOCK_LEVEL_BATCH ||
			    req_op_level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))
			req_op_level = SMB2_OPLOCK_LEVEL_II;

		/*
		 * CR2: FILE_COMPLETE_IF_OPLOCKED (CreateOptions 0x00000100)
		 * MS-SMB2 §3.3.5.9: If this flag is set and there is an
		 * existing oplock on the inode that would require a break
		 * (BATCH or EXCLUSIVE level), return STATUS_OPLOCK_BREAK_IN_PROGRESS
		 * immediately instead of waiting for the oplock break to complete.
		 * This is an informational (success) status — the CREATE still
		 * succeeds, but the client is told a break is pending.
		 */
		if ((req->CreateOptions & FILE_COMPLETE_IF_OPLOCKED_LE) &&
		    (atomic_read(&fp->f_ci->op_count) > 0 ||
		     atomic_read(&fp->f_ci->sop_count) > 0)) {
			struct oplock_info *prev_opinfo;

			prev_opinfo = opinfo_get(fp);
			if (!prev_opinfo) {
				/* Check inode list for a conflicting oplock */
				down_read(&fp->f_ci->m_lock);
				if (!list_empty(&fp->f_ci->m_op_list)) {
					struct oplock_info *tmp;

					tmp = list_first_entry_or_null(
						&fp->f_ci->m_op_list,
						struct oplock_info, op_entry);
					if (tmp &&
					    (tmp->level ==
					     SMB2_OPLOCK_LEVEL_BATCH ||
					     tmp->level ==
					     SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {
						ksmbd_debug(SMB,
							    "FILE_COMPLETE_IF_OPLOCKED: oplock break in progress, skipping wait\n");
						up_read(&fp->f_ci->m_lock);
						rsp->hdr.Status =
							STATUS_OPLOCK_BREAK_IN_PROGRESS;
						goto done_oplock;
					}
				}
				up_read(&fp->f_ci->m_lock);
			} else {
				opinfo_put(prev_opinfo);
			}
		}

		/*
		 * DHv2 pending replay detection (MS-SMB2 §3.3.5.9.10):
		 * Set create_guid and client_guid on fp BEFORE blocking
		 * in smb_grant_oplock().  This allows a replay request
		 * that arrives while the original CREATE is waiting for
		 * an oplock/lease break ACK to find the fp via
		 * ksmbd_lookup_fd_cguid() and detect the pending state.
		 */
		if (dh_info.type == DURABLE_REQ_V2) {
			memcpy(fp->create_guid, dh_info.CreateGuid,
			       SMB2_CREATE_GUID_SIZE);
			memcpy(fp->client_guid, conn->ClientGUID,
			       SMB2_CLIENT_GUID_SIZE);
		}

		rc = smb_grant_oplock(work, req_op_level,
				      fp->persistent_id, fp,
				      le32_to_cpu(req->hdr.Id.SyncId.TreeId),
				      lc, share_ret);
		if (rc < 0)
			goto err_out1;

		/*
		 * CR3: FILE_OPEN_REQUIRING_OPLOCK (CreateOptions 0x00010000)
		 * MS-SMB2 §3.3.5.9: If this flag is set, the open MUST succeed
		 * only if the requested oplock can be granted immediately at the
		 * level requested.  If the oplock was downgraded (granted at a
		 * lower level than requested) or not granted at all, close the
		 * file and return STATUS_OPLOCK_NOT_GRANTED.
		 * Only applies when a non-NONE oplock was requested.
		 */
		if ((req->CreateOptions & FILE_OPEN_REQUIRING_OPLOCK) &&
		    req_op_level != SMB2_OPLOCK_LEVEL_NONE) {
			struct oplock_info *granted_opinfo;
			int granted_level = SMB2_OPLOCK_LEVEL_NONE;

			rcu_read_lock();
			granted_opinfo = rcu_dereference(fp->f_opinfo);
			if (granted_opinfo)
				granted_level = granted_opinfo->level;
			rcu_read_unlock();

			if (granted_level < req_op_level) {
				ksmbd_debug(SMB,
					    "FILE_OPEN_REQUIRING_OPLOCK: oplock not granted at requested level (req=%d granted=%d)\n",
					    req_op_level, granted_level);
				rc = -EPERM;
				rsp->hdr.Status = STATUS_OPLOCK_NOT_GRANTED;
				goto err_out1;
			}
		}
done_oplock:;
	}

	/*
	 * Break parent directory leases when the file is newly created,
	 * overwritten, or superseded — but only for non-lease creates.
	 * Lease-aware creates already called smb_send_parent_lease_break_noti()
	 * above (with parent lease key exemption).  Non-lease creates have
	 * no parent lease key, so smb_break_parent_dir_lease() breaks ALL
	 * directory leases, which is correct.
	 */
	if (file_info != FILE_OPENED && !lc &&
	    !S_ISDIR(file_inode(filp)->i_mode))
		smb_break_parent_dir_lease(fp);

	if (req->CreateOptions & FILE_DELETE_ON_CLOSE_LE) {
		/*
		 * MS-SMB2 §3.3.5.9: If FILE_DELETE_ON_CLOSE is requested but
		 * GrantedAccess does not include DELETE, the server SHOULD fail
		 * with STATUS_ACCESS_DENIED.
		 */
		if (!(daccess & FILE_DELETE_LE)) {
			rc = -EACCES;
			goto err_out1;
		}

		/*
		 * MS-SMB2 §3.3.5.9: If the file has FILE_ATTRIBUTE_READONLY
		 * set, the server MUST fail with STATUS_CANNOT_DELETE.
		 * Also check req->FileAttributes for newly created files
		 * (m_fattr is not yet updated at this point).
		 */
		if ((fp->f_ci->m_fattr & ATTR_READONLY_LE) ||
		    (req->FileAttributes & ATTR_READONLY_LE)) {
			rsp->hdr.Status = STATUS_CANNOT_DELETE;
			rc = -EACCES;
			ksmbd_debug(SMB,
				    "delete-on-close on read-only file\n");
			goto err_out1;
		}
		ksmbd_fd_set_delete_on_close(fp, file_info);

		/*
		 * MS-SMB2 §3.3.5.9: When a file is opened with
		 * FILE_DELETE_ON_CLOSE, break Handle caching leases
		 * on the file so that other clients are notified that
		 * the file name will become invalid when this handle
		 * closes.
		 */
		smb_break_all_handle_lease(work, fp, false);
	}

	if (need_truncate) {
		bool is_supersede = (file_info == FILE_SUPERSEDED);

		rc = smb2_create_truncate(&fp->filp->f_path, is_supersede);
		if (rc)
			goto err_out1;
	}

	if (req->CreateContextsOffset) {
		struct create_alloc_size_req *az_req;

		az_req = (struct create_alloc_size_req *)smb2_find_context_vals(req,
					SMB2_CREATE_ALLOCATION_SIZE, SMB2_CREATE_CONTEXT_NAME_SZ);
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
			else
				fp->f_ci->m_cached_alloc = alloc_size;
		}

		context = smb2_find_context_vals(req, SMB2_CREATE_QUERY_ON_DISK_ID, SMB2_CREATE_CONTEXT_NAME_SZ);
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
			context = smb2_find_context_vals(req, SMB2_CREATE_AAPL, SMB2_CREATE_CONTEXT_NAME_SZ);
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
		smb2_update_xattrs(tcon, &fp->filp->f_path, fp);
	else
		smb2_new_xattrs(tcon, &fp->filp->f_path, fp);

	/*
	 * MS-SMB2: When "hide dot files" is enabled on the share,
	 * files whose name starts with '.' get FILE_ATTRIBUTE_HIDDEN
	 * applied automatically.  This matches Samba behavior and is
	 * tested by smb2.dosmode.
	 */
	if (test_share_config_flag(tcon->share_conf,
				   KSMBD_SHARE_FLAG_HIDE_DOT_FILES)) {
		const char *basename = name ? strrchr(name, '/') : NULL;

		if (basename)
			basename++;
		else
			basename = name;

		if (basename && basename[0] == '.')
			fp->f_ci->m_fattr |= ATTR_HIDDEN_LE;
	}

	/* CN-SUPPRESS: all init xattr writes are done; clear the suppress flag. */
	work->notify_suppress = false;

	memcpy(fp->client_guid, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE);

	if (dh_info.type == DURABLE_REQ_V2 || dh_info.type == DURABLE_REQ) {
		fp->is_durable = true;

		if (dh_info.type == DURABLE_REQ_V2) {
			memcpy(fp->create_guid, dh_info.CreateGuid,
					SMB2_CREATE_GUID_SIZE);
			if ((dh_info.persistent & SMB2_DHANDLE_FLAG_PERSISTENT) &&
			    (conn->vals->capabilities &
			     SMB2_GLOBAL_CAP_PERSISTENT_HANDLES))
				fp->is_persistent = true;
			if (dh_info.timeout)
				fp->durable_timeout =
					min_t(unsigned int, dh_info.timeout,
					      DURABLE_HANDLE_MAX_TIMEOUT);
			else
				/* Default: 60 seconds in milliseconds */
				fp->durable_timeout = 60000;
		} else {
			/*
			 * C.5: DHnQ v1 durable handles previously had no
			 * expiry timeout, causing them to leak indefinitely
			 * after disconnect.  Assign the Windows default
			 * reconnect window of 16 seconds (in ms).
			 * MS-SMB2 §3.3.5.9.7: server SHOULD apply a timeout.
			 */
			fp->durable_timeout = 16000;
		}

		if (fp->is_persistent)
			ksmbd_ph_save(fp);
	}

	/* Save create_action for DHv2 replay (MS-SMB2 3.3.5.9.10) */
	fp->create_action = file_info;

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
	rsp->AllocationSize = cpu_to_le64(ksmbd_alloc_size(fp, &stat));
	rsp->EndofFile = S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);
	rsp->FileAttributes = fp->f_ci->m_fattr;

	/* Cache response for DHv2 replay (MS-SMB2 3.3.5.9.10) */
	if (!fp->replay_cache.valid) {
		fp->replay_cache.last_access = le64_to_cpu(rsp->LastAccessTime);
		fp->replay_cache.last_write = le64_to_cpu(rsp->LastWriteTime);
		fp->replay_cache.change = le64_to_cpu(rsp->ChangeTime);
		fp->replay_cache.alloc_size = le64_to_cpu(rsp->AllocationSize);
		fp->replay_cache.end_of_file = le64_to_cpu(rsp->EndofFile);
		fp->replay_cache.file_attrs = rsp->FileAttributes;
		fp->replay_cache.valid = true;
	}

	/*
	 * NTFS metadata fake files ($Extend\$Quota etc.) are
	 * reported with HIDDEN | SYSTEM | DIRECTORY | ARCHIVE
	 * attributes and zero timestamps, matching Windows Server
	 * behavior.
	 */
	if (is_fake_file) {
		rsp->FileAttributes = cpu_to_le32(ATTR_HIDDEN | ATTR_SYSTEM |
						  ATTR_DIRECTORY | ATTR_ARCHIVE);
		rsp->CreationTime = 0;
		rsp->LastAccessTime = 0;
		rsp->LastWriteTime = 0;
		rsp->ChangeTime = 0;
		rsp->AllocationSize = 0;
		rsp->EndofFile = 0;
	}

	rsp->Reserved2 = 0;

	rsp->PersistentFileId = fp->persistent_id;
	rsp->VolatileFileId = fp->volatile_id;

	rsp->CreateContextsOffset = 0;
	rsp->CreateContextsLength = 0;
	iov_len = offsetof(struct smb2_create_rsp, Buffer);

durable_create_ctx:
	/* If lease is request send lease context response */
	if (opinfo && opinfo->is_lease) {
		struct create_context *lease_ccontext;

		if (iov_len + conn->vals->create_lease_size >
		    work->response_sz - 4) {
			rc = -EINVAL;
			goto err_out;
		}

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

		if (iov_len + conn->vals->create_mxac_size >
		    work->response_sz - 4) {
			rc = -EINVAL;
			goto err_out;
		}

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

		if (iov_len + conn->vals->create_disk_id_size >
		    work->response_sz - 4) {
			rc = -EINVAL;
			goto err_out;
		}

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
		bool is_v2 = (dh_info.type == DURABLE_REQ_V2 ||
			      dh_info.type == DURABLE_RECONN_V2);
		unsigned int durable_ctx_size = is_v2 ?
			conn->vals->create_durable_v2_size :
			conn->vals->create_durable_size;

		if (iov_len + durable_ctx_size > work->response_sz - 4) {
			rc = -EINVAL;
			goto err_out;
		}

		durable_ccontext = (struct create_context *)(rsp->Buffer +
				le32_to_cpu(rsp->CreateContextsLength));
		contxt_cnt++;
		if (!is_v2) {
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
		next_off = is_v2 ?
			conn->vals->create_durable_v2_size :
			conn->vals->create_durable_size;
	}

	if (posix_ctxt) {
		struct create_context *posix_ccontext;

		if (iov_len + conn->vals->create_posix_size >
		    work->response_sz - 4) {
			rc = -EINVAL;
			goto err_out;
		}

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
		size_t max_fruit_size = offsetof(struct create_fruit_rsp, model) +
					sizeof(server_conf.fruit_model) * 2;

		if (iov_len + max_fruit_size > work->response_sz - 4) {
			rc = -EINVAL;
			goto err_out;
		}

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
		/* If status was pre-set (e.g. STATUS_CANNOT_DELETE), keep it */
		if (rsp->hdr.Status == STATUS_SUCCESS) {
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
			else if (rc == -ENOKEY)
				rsp->hdr.Status = STATUS_PRIVILEGE_NOT_HELD;
			else if (rc == -ENOTDIR)
				rsp->hdr.Status = STATUS_NOT_A_DIRECTORY;
			else
				rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
		}


		if (fp)
			ksmbd_fd_put(work, fp);
		smb2_set_err_rsp(work);
		ksmbd_debug(SMB, "Error response: %x\n", rsp->hdr.Status);
	}

	kfree(name);
	kfree(lc);
	kfree(twrp_snap_path);

	return rc;
}
