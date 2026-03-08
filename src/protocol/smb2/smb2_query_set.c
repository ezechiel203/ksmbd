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
#include <linux/overflow.h>
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
#include "xattr.h"
#include "smb2pdu_internal.h"
#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/visibility.h>
#else
#define VISIBLE_IF_KUNIT
#define EXPORT_SYMBOL_IF_KUNIT(sym)
#endif

VISIBLE_IF_KUNIT
int buffer_check_err(int reqOutputBufferLength,
			    struct smb2_query_info_rsp *rsp,
			    void *rsp_org,
			    int min_output_length)
{
	if (reqOutputBufferLength < min_output_length) {
		rsp->hdr.Status = STATUS_INFO_LENGTH_MISMATCH;
		*(__be32 *)rsp_org = cpu_to_be32(sizeof(struct smb2_hdr));
		return -EINVAL;
	}

	if (reqOutputBufferLength < le32_to_cpu(rsp->OutputBufferLength)) {
		rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
		*(__be32 *)rsp_org = cpu_to_be32(sizeof(struct smb2_hdr));
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(buffer_check_err);

VISIBLE_IF_KUNIT
void get_standard_info_pipe(struct smb2_query_info_rsp *rsp,
				   void *rsp_org)
{
	struct smb2_file_standard_info *sinfo;

	sinfo = (struct smb2_file_standard_info *)rsp->Buffer;

	sinfo->AllocationSize = cpu_to_le64(4096);
	sinfo->EndOfFile = cpu_to_le64(0);
	sinfo->NumberOfLinks = cpu_to_le32(1);
	sinfo->DeletePending = 1;
	sinfo->Directory = 0;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_standard_info));
}
EXPORT_SYMBOL_IF_KUNIT(get_standard_info_pipe);

VISIBLE_IF_KUNIT
void get_internal_info_pipe(struct smb2_query_info_rsp *rsp, u64 num,
				   void *rsp_org)
{
	struct smb2_file_internal_info *file_info;

	file_info = (struct smb2_file_internal_info *)rsp->Buffer;

	/* any unique number */
	file_info->IndexNumber = cpu_to_le64(num | (1ULL << 63));
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_internal_info));
}
EXPORT_SYMBOL_IF_KUNIT(get_internal_info_pipe);

static int smb2_get_info_file_pipe(struct ksmbd_work *work,
				   struct ksmbd_session *sess,
				   struct smb2_query_info_req *req,
				   struct smb2_query_info_rsp *rsp,
				   void *rsp_org)
{
	u64 id;
	int rc;
	unsigned int qout_len = 0;

	/*
	 * Windows can sometime send query file info request on
	 * pipe without opening it, checking error condition here
	 */
	id = req->VolatileFileId;

	lockdep_assert_not_held(&sess->rpc_lock);

	down_read(&sess->rpc_lock);
	if (!ksmbd_session_rpc_method(sess, id)) {
		up_read(&sess->rpc_lock);
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -EINVAL;
	}
	up_read(&sess->rpc_lock);

	ksmbd_debug(SMB, "FileInfoClass %u, FileId 0x%llx\n",
		    req->FileInfoClass, req->VolatileFileId);

	switch (req->FileInfoClass) {
	case FILE_STANDARD_INFORMATION:
		get_standard_info_pipe(rsp, rsp_org);
		rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
				      rsp, rsp_org, 4);
		break;
	case FILE_INTERNAL_INFORMATION:
		get_internal_info_pipe(rsp, id, rsp_org);
		rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
				      rsp, rsp_org, 8);
		break;
		case FILE_PIPE_INFORMATION:
			rc = ksmbd_pipe_get_info(work, id, rsp->Buffer,
						 le32_to_cpu(req->OutputBufferLength),
						 &qout_len);
			if (rc == -ENOENT) {
				rsp->hdr.Status = STATUS_INVALID_HANDLE;
				rc = -EINVAL;
			}
			if (!rc) {
				rsp->OutputBufferLength = cpu_to_le32(qout_len);
				rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
					      rsp, rsp_org, 4);
			}
			break;
		case FILE_PIPE_LOCAL_INFORMATION:
			rc = ksmbd_pipe_get_local_info(work, id, rsp->Buffer,
					       le32_to_cpu(req->OutputBufferLength),
					       &qout_len);
			if (rc == -ENOENT) {
				rsp->hdr.Status = STATUS_INVALID_HANDLE;
				rc = -EINVAL;
			}
			if (!rc) {
				rsp->OutputBufferLength = cpu_to_le32(qout_len);
				rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
					      rsp, rsp_org, 4);
			}
		break;
	default:
		rc = ksmbd_dispatch_info(work, NULL,
					 SMB2_O_INFO_FILE,
					 req->FileInfoClass,
					 KSMBD_INFO_GET,
					 rsp->Buffer,
					 le32_to_cpu(req->OutputBufferLength),
					 &qout_len);
		if (!rc) {
			rsp->OutputBufferLength = cpu_to_le32(qout_len);
			rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
					      rsp, rsp_org, 4);
		} else {
			ksmbd_debug(SMB, "smb2_info_file_pipe for %u not supported\n",
				    req->FileInfoClass);
		}
	}
	return rc;
}

static bool smb2_is_pipe_set_info_class(u8 file_info_class)
{
	return file_info_class == FILE_PIPE_INFORMATION ||
	       file_info_class == FILE_PIPE_REMOTE_INFORMATION;
}

static int smb2_set_info_file_pipe(struct ksmbd_work *work,
				   struct smb2_set_info_req *req)
{
	unsigned int id;
	char *set_buf;
	unsigned int set_buf_len;
	unsigned int consumed_len = 0;
	int rc;

	id = req->VolatileFileId;
	set_buf = (char *)req + le16_to_cpu(req->BufferOffset);
	set_buf_len = le32_to_cpu(req->BufferLength);

	down_read(&work->sess->rpc_lock);
	if (!ksmbd_session_rpc_method(work->sess, id)) {
		up_read(&work->sess->rpc_lock);
		return -EBADF;
	}
	up_read(&work->sess->rpc_lock);

	rc = ksmbd_dispatch_info(work, NULL,
				 SMB2_O_INFO_FILE,
				 req->FileInfoClass,
				 KSMBD_INFO_SET,
				 set_buf, set_buf_len,
				 &consumed_len);
	if (!rc && consumed_len > set_buf_len)
		return -EINVAL;

	return rc;
}

/**
 * smb2_get_ea() - handler for smb2 get extended attribute command
 * @work:	smb work containing query info command buffer
 * @fp:		ksmbd_file pointer
 * @req:	get extended attribute request
 * @rsp:	response buffer pointer
 * @rsp_org:	base response buffer pointer in case of chained response
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_get_ea(struct ksmbd_work *work, struct ksmbd_file *fp,
		       struct smb2_query_info_req *req,
		       struct smb2_query_info_rsp *rsp, void *rsp_org)
{
	struct smb2_ea_info *eainfo, *prev_eainfo;
	char *name, *ptr, *xattr_list = NULL, *buf;
	int rc, name_len, value_len, xattr_list_len, idx;
	ssize_t buf_free_len, alignment_bytes, next_offset, rsp_data_cnt = 0;
	struct smb2_ea_info_req *ea_req = NULL;
	const struct path *path;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = file_mnt_idmap(fp->filp);
#else
	struct user_namespace *user_ns = file_mnt_user_ns(fp->filp);
#endif

	if (!(fp->daccess & FILE_READ_EA_LE)) {
		pr_err("Not permitted to read ext attr : 0x%x\n",
		       fp->daccess);
		return -EACCES;
	}

	path = &fp->filp->f_path;
	/* single EA entry is requested with given user.* name */
	if (req->InputBufferLength) {
		if (le32_to_cpu(req->InputBufferLength) <=
		    sizeof(struct smb2_ea_info_req))
			return -EINVAL;

		if ((u64)le16_to_cpu(req->InputBufferOffset) +
		    le32_to_cpu(req->InputBufferLength) >
		    get_rfc1002_len(work->request_buf) + 4)
			return -EINVAL;

		/* UTF-16LE data requires at minimum 2-byte alignment */
		if (le16_to_cpu(req->InputBufferOffset) % 2) {
			pr_err_ratelimited("ksmbd: misaligned InputBufferOffset\n");
			return -EINVAL;
		}

		ea_req = (struct smb2_ea_info_req *)((char *)req +
						     le16_to_cpu(req->InputBufferOffset));
		/* QS-03: bounds-check EaNameLength before use */
		if (ea_req->EaNameLength == 0 ||
		    (u32)ea_req->EaNameLength + sizeof(struct smb2_ea_info_req) >
		    le32_to_cpu(req->InputBufferLength))
			return -EINVAL;
	} else {
		/* need to send all EAs, if no specific EA is requested*/
		if (le32_to_cpu(req->Flags) & SL_RETURN_SINGLE_ENTRY)
			ksmbd_debug(SMB,
				    "All EAs are requested but need to send single EA entry in rsp flags 0x%x\n",
				    le32_to_cpu(req->Flags));
	}

	buf_free_len =
		smb2_calc_max_out_buf_len(work, 8,
					  le32_to_cpu(req->OutputBufferLength));
	if (buf_free_len < 0)
		return -EINVAL;

	rc = ksmbd_vfs_listxattr(path->dentry, &xattr_list);
	if (rc < 0) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		goto out;
	} else if (!rc) { /* there is no EA in the file */
		ksmbd_debug(SMB, "no ea data in the file\n");
		goto done;
	}
	xattr_list_len = rc;

	ptr = (char *)rsp->Buffer;
	eainfo = (struct smb2_ea_info *)ptr;
	prev_eainfo = eainfo;
	idx = 0;

	while (idx < xattr_list_len) {
		name = xattr_list + idx;
		name_len = strlen(name);

		ksmbd_debug(SMB, "%s, len %d\n", name, name_len);
		idx += name_len + 1;

		/*
		 * CIFS does not support EA other than user.* namespace,
		 * still keep the framework generic, to list other attrs
		 * in future.
		 */
		if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
			continue;

		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,
			     STREAM_PREFIX_LEN))
			continue;

		if (req->InputBufferLength && ea_req &&
		    strncmp(&name[XATTR_USER_PREFIX_LEN], ea_req->name,
			    ea_req->EaNameLength))
			continue;

		if (!strncmp(&name[XATTR_USER_PREFIX_LEN],
			     DOS_ATTRIBUTE_PREFIX, DOS_ATTRIBUTE_PREFIX_LEN))
			continue;

		if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
			name_len -= XATTR_USER_PREFIX_LEN;

		buf_free_len -= (offsetof(struct smb2_ea_info, name) +
				name_len + 1);
		/* bailout if xattr can't fit in buf_free_len */
		if (buf_free_len < 0)
			break;

		ptr = eainfo->name + name_len + 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		value_len = ksmbd_vfs_getxattr(idmap, path->dentry,
#else
		value_len = ksmbd_vfs_getxattr(user_ns, path->dentry,
#endif
					       name, &buf);
		if (value_len <= 0) {
			rc = -ENOENT;
			rsp->hdr.Status = STATUS_INVALID_HANDLE;
			goto out;
		}

		buf_free_len -= value_len;
		if (buf_free_len < 0) {
			kfree(buf);
			break;
		}

		memcpy(ptr, buf, value_len);
		kfree(buf);

		ptr += value_len;
		eainfo->Flags = 0;
		eainfo->EaNameLength = name_len;

		if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
			memcpy(eainfo->name, &name[XATTR_USER_PREFIX_LEN],
			       name_len);
		else
			memcpy(eainfo->name, name, name_len);

		eainfo->name[name_len] = '\0';
		eainfo->EaValueLength = cpu_to_le16(value_len);
		next_offset = offsetof(struct smb2_ea_info, name) +
			name_len + 1 + value_len;

		/* align next xattr entry at 4 byte boundary */
		alignment_bytes = ((next_offset + 3) & ~3) - next_offset;
		if (alignment_bytes) {
			if (buf_free_len < alignment_bytes)
				break;
			memset(ptr, '\0', alignment_bytes);
			ptr += alignment_bytes;
			next_offset += alignment_bytes;
			buf_free_len -= alignment_bytes;
		}
		eainfo->NextEntryOffset = cpu_to_le32(next_offset);
		prev_eainfo = eainfo;
		eainfo = (struct smb2_ea_info *)ptr;
		rsp_data_cnt += next_offset;

		if (req->InputBufferLength) {
			ksmbd_debug(SMB, "single entry requested\n");
			break;
		}
	}

	/* no more ea entries */
	prev_eainfo->NextEntryOffset = 0;
done:
	rc = 0;
	if (rsp_data_cnt == 0) {
		/* QS-02: specific EA name was requested but not found */
		if (req->InputBufferLength)
			rsp->hdr.Status = STATUS_NONEXISTENT_EA_ENTRY;
		else
			rsp->hdr.Status = STATUS_NO_EAS_ON_FILE;
	}
	rsp->OutputBufferLength = cpu_to_le32(rsp_data_cnt);
out:
	kvfree(xattr_list);
	return rc;
}

VISIBLE_IF_KUNIT
void get_file_access_info(struct smb2_query_info_rsp *rsp,
				 struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_access_info *file_info;

	file_info = (struct smb2_file_access_info *)rsp->Buffer;
	file_info->AccessFlags = fp->daccess;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_access_info));
}
EXPORT_SYMBOL_IF_KUNIT(get_file_access_info);

VISIBLE_IF_KUNIT
int get_file_basic_info(struct smb2_query_info_rsp *rsp,
			       struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_basic_info *basic_info;
	struct kstat stat;
	u64 time;
	int ret;

	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE)) {
		pr_err("no right to read the attributes : 0x%x\n",
		       fp->daccess);
		return -EACCES;
	}

	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	if (ret)
		return ret;

	basic_info = (struct smb2_file_basic_info *)rsp->Buffer;
	basic_info->CreationTime = cpu_to_le64(fp->create_time);
	time = ksmbd_UnixTimeToNT(stat.atime);
	basic_info->LastAccessTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.mtime);
	basic_info->LastWriteTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.ctime);
	basic_info->ChangeTime = cpu_to_le64(time);
	basic_info->Attributes = fp->f_ci->m_fattr;
	basic_info->Pad1 = 0;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_basic_info));
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(get_file_basic_info);

VISIBLE_IF_KUNIT
int get_file_standard_info(struct smb2_query_info_rsp *rsp,
				  struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_standard_info *sinfo;
	unsigned int delete_pending;
	struct kstat stat;
	int ret;

	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	if (ret)
		return ret;

	sinfo = (struct smb2_file_standard_info *)rsp->Buffer;
	delete_pending = ksmbd_inode_pending_delete(fp);

	if (ksmbd_stream_fd(fp) == false) {
		sinfo->AllocationSize = cpu_to_le64(ksmbd_alloc_size(fp, &stat));
		sinfo->EndOfFile = S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);
	} else {
		sinfo->AllocationSize = cpu_to_le64(fp->stream.size);
		sinfo->EndOfFile = cpu_to_le64(fp->stream.size);
	}
	sinfo->NumberOfLinks = cpu_to_le32(get_nlink(&stat) - delete_pending);
	sinfo->DeletePending = delete_pending;
	sinfo->Directory = S_ISDIR(stat.mode) ? 1 : 0;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_standard_info));

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(get_file_standard_info);

VISIBLE_IF_KUNIT
void get_file_alignment_info(struct smb2_query_info_rsp *rsp,
				    void *rsp_org)
{
	struct smb2_file_alignment_info *file_info;

	file_info = (struct smb2_file_alignment_info *)rsp->Buffer;
	file_info->AlignmentRequirement = 0;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_alignment_info));
}
EXPORT_SYMBOL_IF_KUNIT(get_file_alignment_info);

static int get_file_all_info(struct ksmbd_work *work,
			     struct smb2_query_info_rsp *rsp,
			     struct ksmbd_file *fp,
			     void *rsp_org)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_file_all_info *file_info;
	unsigned int delete_pending;
	struct kstat stat;
	int conv_len;
	char *filename;
	u64 time;
	int ret;

	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE)) {
		ksmbd_debug(SMB, "no right to read the attributes : 0x%x\n",
			    fp->daccess);
		return -EACCES;
	}

	filename = convert_to_nt_pathname(work->tcon->share_conf, &fp->filp->f_path);
	if (IS_ERR(filename))
		return PTR_ERR(filename);

	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	if (ret) {
		kfree(filename);
		return ret;
	}

	ksmbd_debug(SMB, "filename = %s\n", filename);
	delete_pending = ksmbd_inode_pending_delete(fp);
	file_info = (struct smb2_file_all_info *)rsp->Buffer;

	file_info->CreationTime = cpu_to_le64(fp->create_time);
	time = ksmbd_UnixTimeToNT(stat.atime);
	file_info->LastAccessTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.mtime);
	file_info->LastWriteTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.ctime);
	file_info->ChangeTime = cpu_to_le64(time);
	file_info->Attributes = fp->f_ci->m_fattr;
	file_info->Pad1 = 0;
	if (ksmbd_stream_fd(fp) == false) {
		file_info->AllocationSize =
			cpu_to_le64(ksmbd_alloc_size(fp, &stat));
		file_info->EndOfFile = S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);
	} else {
		file_info->AllocationSize = cpu_to_le64(fp->stream.size);
		file_info->EndOfFile = cpu_to_le64(fp->stream.size);
	}
	file_info->NumberOfLinks =
			cpu_to_le32(get_nlink(&stat) - delete_pending);
	file_info->DeletePending = delete_pending;
	file_info->Directory = S_ISDIR(stat.mode) ? 1 : 0;
	file_info->Pad2 = 0;
	file_info->IndexNumber = cpu_to_le64(stat.ino);
	/*
	 * QS-10: compute EASize by iterating user.* xattrs.
	 * EASize on Windows = sum of (8 + name_len + 1 + value_len) per EA.
	 */
	{
		char *allinfo_xlist = NULL;
		ssize_t allinfo_xlen;
		__u32 ea_size = 0;

		allinfo_xlen = ksmbd_vfs_listxattr(
				fp->filp->f_path.dentry, &allinfo_xlist);
		if (allinfo_xlen > 0) {
			int xidx = 0;

			while (xidx < allinfo_xlen) {
				char *xname = allinfo_xlist + xidx;
				int xname_len = strlen(xname);

				xidx += xname_len + 1;
				if (strncmp(xname, XATTR_USER_PREFIX,
					    XATTR_USER_PREFIX_LEN))
					continue;
				if (!strncmp(&xname[XATTR_USER_PREFIX_LEN],
					     STREAM_PREFIX, STREAM_PREFIX_LEN))
					continue;
				if (!strncmp(&xname[XATTR_USER_PREFIX_LEN],
					     DOS_ATTRIBUTE_PREFIX,
					     DOS_ATTRIBUTE_PREFIX_LEN))
					continue;
				{
					int ename_len = xname_len -
						XATTR_USER_PREFIX_LEN;
					char *vbuf = NULL;
					ssize_t vlen;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
					vlen = ksmbd_vfs_getxattr(
						file_mnt_idmap(fp->filp),
#else
					vlen = ksmbd_vfs_getxattr(
						file_mnt_user_ns(fp->filp),
#endif
						fp->filp->f_path.dentry,
						xname, &vbuf);
					kfree(vbuf);
					if (vlen < 0)
						vlen = 0;
					ea_size += 8 + ename_len + 1 +
						   (u32)vlen;
				}
			}
		}
		kvfree(allinfo_xlist);
		file_info->EASize = cpu_to_le32(ea_size);
	}
	file_info->AccessFlags = fp->daccess;
	if (ksmbd_stream_fd(fp) == false)
		file_info->CurrentByteOffset = cpu_to_le64(fp->filp->f_pos);
	else
		file_info->CurrentByteOffset = cpu_to_le64(fp->stream.pos);
	file_info->Mode = fp->coption;
	file_info->AlignmentRequirement = 0;
	/*
	 * QSA-16: Always report the true (un-capped) UTF-16LE byte count in
	 * FileNameLength so the client knows how large a buffer to allocate
	 * on retry.  Set OutputBufferLength to the full size so that
	 * buffer_check_err() returns STATUS_BUFFER_OVERFLOW when the
	 * client-supplied buffer is too small (MS-SMB2 §3.3.5.20.1).
	 */
	conv_len = smbConvertToUTF16((__le16 *)file_info->FileName, filename,
				     PATH_MAX, conn->local_nls, 0);
	conv_len *= 2;
	file_info->FileNameLength = cpu_to_le32(conv_len);
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_all_info) - 1 + conv_len);
	kfree(filename);
	return 0;
}

static void get_file_alternate_info(struct ksmbd_work *work,
				    struct smb2_query_info_rsp *rsp,
				    struct ksmbd_file *fp,
				    void *rsp_org)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_file_alt_name_info *file_info;
	struct dentry *dentry = fp->filp->f_path.dentry;
	int conv_len;

	spin_lock(&dentry->d_lock);
	file_info = (struct smb2_file_alt_name_info *)rsp->Buffer;
	conv_len = ksmbd_extract_shortname(conn,
					   dentry->d_name.name,
					   file_info->FileName);
	spin_unlock(&dentry->d_lock);
	file_info->FileNameLength = cpu_to_le32(conv_len);
	rsp->OutputBufferLength =
		cpu_to_le32(struct_size(file_info, FileName, conv_len));
}

static int get_file_stream_info(struct ksmbd_work *work,
				struct smb2_query_info_rsp *rsp,
				struct ksmbd_file *fp,
				void *rsp_org)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_file_stream_info *file_info;
	char *stream_name, *xattr_list = NULL, *stream_buf;
	struct kstat stat;
	const struct path *path = &fp->filp->f_path;
	ssize_t xattr_list_len;
	int nbytes = 0, streamlen, stream_name_len, next, idx = 0;
	int buf_free_len;
	int ret;

	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	if (ret)
		return ret;

	file_info = (struct smb2_file_stream_info *)rsp->Buffer;

	/*
	 * Use work buffer free space (not client's OutputBufferLength) so we
	 * compute the full response size.  buffer_check_err() will compare
	 * the full size against OutputBufferLength and return
	 * STATUS_BUFFER_OVERFLOW when the client's buffer is too small.
	 */
	buf_free_len = smb2_resp_buf_len(work, 8);
	if (buf_free_len < 0)
		goto out;

	/* Zero the response buffer to prevent leaking stale heap data */
	memset(rsp->Buffer, 0, buf_free_len);

	/*
	 * Only enumerate alternate data streams (stored as xattrs) if the
	 * share has KSMBD_SHARE_FLAG_STREAMS enabled.  When streams are
	 * disabled, skip straight to the default ::$DATA entry.
	 */
	if (!work->tcon || !work->tcon->share_conf ||
	    !test_share_config_flag(work->tcon->share_conf,
				    KSMBD_SHARE_FLAG_STREAMS))
		goto out;

	xattr_list_len = ksmbd_vfs_listxattr(path->dentry, &xattr_list);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		ksmbd_debug(SMB, "empty xattr in the file\n");
		goto out;
	}

	while (idx < xattr_list_len) {
		stream_name = xattr_list + idx;
		streamlen = strlen(stream_name);
		idx += streamlen + 1;

		ksmbd_debug(SMB, "%s, len %d\n", stream_name, streamlen);

		if (strncmp(&stream_name[XATTR_USER_PREFIX_LEN],
			    STREAM_PREFIX, STREAM_PREFIX_LEN))
			continue;

		stream_name_len = streamlen - (XATTR_USER_PREFIX_LEN +
				STREAM_PREFIX_LEN);
		streamlen = stream_name_len;

		/* plus : size */
		streamlen += 1;
		stream_buf = kmalloc(streamlen + 1, KSMBD_DEFAULT_GFP);
		if (!stream_buf)
			break;

		streamlen = snprintf(stream_buf, streamlen + 1,
				     ":%s", &stream_name[XATTR_NAME_STREAM_LEN]);

		next = sizeof(struct smb2_file_stream_info) + streamlen * 2;
		if (next > buf_free_len) {
			kfree(stream_buf);
			break;
		}

		file_info = (struct smb2_file_stream_info *)&rsp->Buffer[nbytes];
		streamlen  = smbConvertToUTF16((__le16 *)file_info->StreamName,
					       stream_buf, streamlen,
					       conn->local_nls, 0);
		streamlen *= 2;
		kfree(stream_buf);
		file_info->StreamNameLength = cpu_to_le32(streamlen);
		/*
		 * G.2: StreamSize must be the actual xattr data size, not the
		 * length of the stream name string. Retrieve via getxattr().
		 */
		{
			char *xattr_val = NULL;
			ssize_t xattr_data_len;
			u64 stream_data_size, stream_alloc_size;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			xattr_data_len = ksmbd_vfs_getxattr(
				file_mnt_idmap(fp->filp),
#else
			xattr_data_len = ksmbd_vfs_getxattr(
				file_mnt_user_ns(fp->filp),
#endif
				path->dentry,
				stream_name,
				&xattr_val);
			kfree(xattr_val);
			if (xattr_data_len < 0)
				xattr_data_len = 0;
			stream_data_size = (u64)xattr_data_len;
			/* Allocation size: round up to 4K */
			stream_alloc_size =
				(stream_data_size + 4095) & ~(u64)4095;
			if (!stream_alloc_size && stream_data_size)
				stream_alloc_size = 4096;
			file_info->StreamSize =
				cpu_to_le64(stream_data_size);
			file_info->StreamAllocationSize =
				cpu_to_le64(stream_alloc_size);
		}

		nbytes += next;
		buf_free_len -= next;
		file_info->NextEntryOffset = cpu_to_le32(next);
	}

out:
#ifdef CONFIG_KSMBD_FRUIT
	/*
	 * Time Machine: inject virtual streams on the share root
	 * when FRUIT_TIME_MACHINE is configured. macOS checks for
	 * these streams to determine if a volume supports Time Machine.
	 */
	if (conn->is_fruit && S_ISDIR(stat.mode) &&
	    work->tcon && work->tcon->share_conf &&
	    test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE) &&
	    path->dentry == work->tcon->share_conf->vfs_path.dentry) {
		const char *tm_supported =
			":com.apple.timemachine.supported:$DATA";
		int tm_len = strlen(tm_supported);

		next = sizeof(struct smb2_file_stream_info) + tm_len * 2;
		if (buf_free_len >= next) {
			file_info = (struct smb2_file_stream_info *)
				&rsp->Buffer[nbytes];
			streamlen = smbConvertToUTF16(
				(__le16 *)file_info->StreamName,
				tm_supported, tm_len,
				conn->local_nls, 0);
			streamlen *= 2;
			file_info->StreamNameLength = cpu_to_le32(streamlen);
			/* Stream value is "1" (supported) */
			file_info->StreamSize = cpu_to_le64(1);
			file_info->StreamAllocationSize = cpu_to_le64(1);
			file_info->NextEntryOffset = cpu_to_le32(next);
			nbytes += next;
			buf_free_len -= next;
		}

		/* Inject MaxSize if configured */
		if (work->tcon->share_conf->time_machine_max_size > 0) {
			const char *tm_maxsize =
				":com.apple.timemachine.MaxSize:$DATA";
			int ms_len = strlen(tm_maxsize);

			next = sizeof(struct smb2_file_stream_info) +
			       ms_len * 2;
			if (buf_free_len >= next) {
				file_info = (struct smb2_file_stream_info *)
					&rsp->Buffer[nbytes];
				streamlen = smbConvertToUTF16(
					(__le16 *)file_info->StreamName,
					tm_maxsize, ms_len,
					conn->local_nls, 0);
				streamlen *= 2;
				file_info->StreamNameLength =
					cpu_to_le32(streamlen);
				file_info->StreamSize = cpu_to_le64(8);
				file_info->StreamAllocationSize =
					cpu_to_le64(8);
				file_info->NextEntryOffset =
					cpu_to_le32(next);
				nbytes += next;
				buf_free_len -= next;
			}
		}
	}
#endif

	if (!S_ISDIR(stat.mode) &&
	    buf_free_len >= sizeof(struct smb2_file_stream_info) + 7 * 2) {
		file_info = (struct smb2_file_stream_info *)
			&rsp->Buffer[nbytes];
		streamlen = smbConvertToUTF16((__le16 *)file_info->StreamName,
					      "::$DATA", 7, conn->local_nls, 0);
		streamlen *= 2;
		file_info->StreamNameLength = cpu_to_le32(streamlen);
		file_info->StreamSize = cpu_to_le64(stat.size);
		file_info->StreamAllocationSize = cpu_to_le64(ksmbd_alloc_size(fp, &stat));
		nbytes += sizeof(struct smb2_file_stream_info) + streamlen;
	}

	/* last entry offset should be 0 */
	file_info->NextEntryOffset = 0;
	kvfree(xattr_list);

	rsp->OutputBufferLength = cpu_to_le32(nbytes);

	return 0;
}

VISIBLE_IF_KUNIT
int get_file_internal_info(struct smb2_query_info_rsp *rsp,
				  struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_internal_info *file_info;
	struct kstat stat;
	int ret;

	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			AT_STATX_SYNC_AS_STAT);
	if (ret)
		return ret;

	file_info = (struct smb2_file_internal_info *)rsp->Buffer;
	file_info->IndexNumber = cpu_to_le64(stat.ino);
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_internal_info));

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(get_file_internal_info);

static int get_file_network_open_info(struct smb2_query_info_rsp *rsp,
				      struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_ntwrk_info *file_info;
	struct kstat stat;
	u64 time;
	int ret;

	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE)) {
		pr_err("no right to read the attributes : 0x%x\n",
		       fp->daccess);
		return -EACCES;
	}

	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	if (ret)
		return ret;

	file_info = (struct smb2_file_ntwrk_info *)rsp->Buffer;

	file_info->CreationTime = cpu_to_le64(fp->create_time);
	time = ksmbd_UnixTimeToNT(stat.atime);
	file_info->LastAccessTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.mtime);
	file_info->LastWriteTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.ctime);
	file_info->ChangeTime = cpu_to_le64(time);
	file_info->Attributes = fp->f_ci->m_fattr;
	if (ksmbd_stream_fd(fp) == false) {
		file_info->AllocationSize = cpu_to_le64(ksmbd_alloc_size(fp, &stat));
		file_info->EndOfFile = S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);
	} else {
		file_info->AllocationSize = cpu_to_le64(fp->stream.size);
		file_info->EndOfFile = cpu_to_le64(fp->stream.size);
	}
	file_info->Reserved = cpu_to_le32(0);
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_ntwrk_info));
	return 0;
}

/*
 * G.5: Compute actual EA size by iterating user.* xattrs (excluding
 * stream and DOS-attribute xattrs).  Per MS-FSCC §2.4.13, EaSize is the
 * sum of all EA entries encoded as FILE_FULL_EA_INFORMATION records.
 * Each record contributes:
 *   sizeof(FILE_FULL_EA_INFORMATION) + EaNameLength + 1 + EaValueLength
 * aligned to 4 bytes.
 */
VISIBLE_IF_KUNIT
void get_file_ea_info(struct smb2_query_info_rsp *rsp,
			     struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_ea_info *file_info;
	u32 ea_size = 0;
	char *xattr_list = NULL;
	ssize_t xattr_list_len;
	int idx = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap;
#else
	struct user_namespace *user_ns;
#endif

	file_info = (struct smb2_file_ea_info *)rsp->Buffer;

	if (!fp)
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	idmap = file_mnt_idmap(fp->filp);
#else
	user_ns = file_mnt_user_ns(fp->filp);
#endif

	xattr_list_len = ksmbd_vfs_listxattr(fp->filp->f_path.dentry,
					     &xattr_list);
	if (xattr_list_len <= 0)
		goto out;

	while (idx < xattr_list_len) {
		char *name = xattr_list + idx;
		int name_len = strlen(name);
		char *xattr_val = NULL;
		ssize_t value_len;
		u32 entry_size;

		idx += name_len + 1;

		/* Only user.* namespace, but not streams or DOS attrs */
		if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
			continue;
		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,
			     STREAM_PREFIX_LEN))
			continue;
		if (!strncmp(&name[XATTR_USER_PREFIX_LEN],
			     DOS_ATTRIBUTE_PREFIX, DOS_ATTRIBUTE_PREFIX_LEN))
			continue;

		/* EA name length = name without "user." prefix */
		name_len -= XATTR_USER_PREFIX_LEN;
		if (name_len <= 0)
			continue;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		value_len = ksmbd_vfs_getxattr(idmap,
#else
		value_len = ksmbd_vfs_getxattr(user_ns,
#endif
					       fp->filp->f_path.dentry,
					       name, &xattr_val);
		kfree(xattr_val);
		if (value_len < 0)
			value_len = 0;

		/*
		 * Each EA entry in FILE_FULL_EA_INFORMATION format:
		 *   NextEntryOffset(4) + Flags(1) + EaNameLength(1) +
		 *   EaValueLength(2) + EaName[EaNameLength+1] + EaValue
		 * = offsetof(smb2_ea_info, name) + name_len + 1 + value_len
		 * aligned up to 4 bytes.
		 */
		entry_size = offsetof(struct smb2_ea_info, name) +
			     name_len + 1 + (u32)value_len;
		entry_size = (entry_size + 3) & ~3U;
		ea_size += entry_size;
	}
	kvfree(xattr_list);

out:
	file_info->EASize = cpu_to_le32(ea_size);
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_ea_info));
}
EXPORT_SYMBOL_IF_KUNIT(get_file_ea_info);

VISIBLE_IF_KUNIT
void get_file_position_info(struct smb2_query_info_rsp *rsp,
				   struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_pos_info *file_info;

	file_info = (struct smb2_file_pos_info *)rsp->Buffer;
	if (ksmbd_stream_fd(fp) == false)
		file_info->CurrentByteOffset = cpu_to_le64(fp->filp->f_pos);
	else
		file_info->CurrentByteOffset = cpu_to_le64(fp->stream.pos);

	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_pos_info));
}
EXPORT_SYMBOL_IF_KUNIT(get_file_position_info);

VISIBLE_IF_KUNIT
void get_file_mode_info(struct smb2_query_info_rsp *rsp,
			       struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_mode_info *file_info;

	file_info = (struct smb2_file_mode_info *)rsp->Buffer;
	file_info->Mode = fp->coption & FILE_MODE_INFO_MASK;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_mode_info));
}
EXPORT_SYMBOL_IF_KUNIT(get_file_mode_info);

VISIBLE_IF_KUNIT
int get_file_compression_info(struct smb2_query_info_rsp *rsp,
				     struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_comp_info *file_info;
	struct kstat stat;
	int ret;

	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	if (ret)
		return ret;

	file_info = (struct smb2_file_comp_info *)rsp->Buffer;
	if (fp->f_ci->m_fattr & ATTR_COMPRESSED_LE) {
		/*
		 * MS-FSCC §2.4.7: for compressed files, CompressedFileSize
		 * is the size of the compressed data on disk (rounded up to
		 * cluster boundary). Use stat.blocks * 512 as an
		 * approximation when the underlying FS doesn't report
		 * separately.
		 */
		file_info->CompressedFileSize = cpu_to_le64(stat.blocks << 9);
		file_info->CompressionFormat =
			cpu_to_le16(COMPRESSION_FORMAT_LZNT1);
	} else {
		/*
		 * MS-FSCC §2.4.7: for non-compressed files,
		 * CompressedFileSize MUST equal the file's EndOfFile
		 * (logical size), not the allocation size.
		 */
		file_info->CompressedFileSize = cpu_to_le64(stat.size);
		file_info->CompressionFormat =
			cpu_to_le16(COMPRESSION_FORMAT_NONE);
	}
	file_info->CompressionUnitShift = 0;
	file_info->ChunkShift = 0;
	file_info->ClusterShift = 0;
	memset(&file_info->Reserved[0], 0, 3);

	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_comp_info));

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(get_file_compression_info);

VISIBLE_IF_KUNIT
int get_file_attribute_tag_info(struct smb2_query_info_rsp *rsp,
				       struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_attr_tag_info *file_info;
	char *reparse_buf = NULL;
	__le32 reparse_tag;
	ssize_t reparse_len;

	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE)) {
		pr_err("no right to read the attributes : 0x%x\n",
		       fp->daccess);
		return -EACCES;
	}

	file_info = (struct smb2_file_attr_tag_info *)rsp->Buffer;
	file_info->FileAttributes = fp->f_ci->m_fattr;
	file_info->ReparseTag =
		smb2_get_reparse_tag_special_file(file_inode(fp->filp)->i_mode);
	if (file_info->ReparseTag) {
		file_info->FileAttributes |= ATTR_REPARSE_POINT_LE;
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	reparse_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),
#else
	reparse_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),
#endif
					 fp->filp->f_path.dentry,
					 XATTR_NAME_REPARSE_DATA,
					 &reparse_buf);
	if (reparse_len >= (ssize_t)sizeof(reparse_tag) && reparse_buf) {
		memcpy(&reparse_tag, reparse_buf, sizeof(reparse_tag));
		file_info->ReparseTag = reparse_tag;
		file_info->FileAttributes |= ATTR_REPARSE_POINT_LE;
	}
	kfree(reparse_buf);

out:
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_attr_tag_info));
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(get_file_attribute_tag_info);

struct smb2_file_reparse_point_info {
	__le64 FileReferenceNumber;
	__le32 Tag;
} __packed;

static int get_file_reparse_point_info(struct smb2_query_info_rsp *rsp,
				       struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_reparse_point_info *info;
	char *reparse_buf = NULL;
	__le32 reparse_tag;
	ssize_t reparse_len;

	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE))
		return -EACCES;

	info = (struct smb2_file_reparse_point_info *)rsp->Buffer;
	info->FileReferenceNumber = cpu_to_le64(file_inode(fp->filp)->i_ino);
	info->Tag = smb2_get_reparse_tag_special_file(file_inode(fp->filp)->i_mode);
	if (info->Tag)
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	reparse_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),
#else
	reparse_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),
#endif
					 fp->filp->f_path.dentry,
					 XATTR_NAME_REPARSE_DATA,
					 &reparse_buf);
	if (reparse_len >= (ssize_t)sizeof(reparse_tag) && reparse_buf) {
		memcpy(&reparse_tag, reparse_buf, sizeof(reparse_tag));
		info->Tag = reparse_tag;
	}
	kfree(reparse_buf);

out:
	rsp->OutputBufferLength = cpu_to_le32(sizeof(*info));
	return 0;
}

struct smb2_file_standard_link_info {
	__le32 NumberOfAccessibleLinks;
	__le32 TotalNumberOfLinks;
	__u8 DeletePending;
	__u8 Directory;
	__le16 Reserved;
} __packed;

static int get_file_standard_link_info(struct smb2_query_info_rsp *rsp,
				       struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_standard_link_info *info;
	unsigned int delete_pending;
	struct kstat stat;
	int ret;

	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE))
		return -EACCES;

	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	if (ret)
		return ret;

	delete_pending = ksmbd_inode_pending_delete(fp);
	info = (struct smb2_file_standard_link_info *)rsp->Buffer;
	info->TotalNumberOfLinks = cpu_to_le32(get_nlink(&stat));
	info->NumberOfAccessibleLinks =
		cpu_to_le32(get_nlink(&stat) - delete_pending);
	info->DeletePending = delete_pending;
	info->Directory = S_ISDIR(stat.mode) ? 1 : 0;
	info->Reserved = 0;
	rsp->OutputBufferLength = cpu_to_le32(sizeof(*info));
	return 0;
}

/*
 * MS-FSCC §2.4.20 FileIdInformation: 24 bytes total
 *   VolumeSerialNumber: 8 bytes (ULONGLONG)
 *   FileId:            16 bytes (128-bit persistent file ID, ULONGLONG[2])
 *
 * We use inode number in the low 64 bits of FileId and zero in the high
 * 64 bits.  VolumeSerialNumber is taken from the superblock device ID.
 */
struct smb2_file_id_info {
	__le64 VolumeSerialNumber; /* 8 bytes */
	__u8   FileId[16];         /* 128-bit FileId */
} __packed; /* 24 bytes total */

VISIBLE_IF_KUNIT
int get_file_id_info(struct smb2_query_info_rsp *rsp,
			    struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_id_info *info;
	struct inode *inode;
	struct kstatfs stfs;
	__le64 ino_le;
	int ret;

	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE))
		return -EACCES;

	if (le32_to_cpu(rsp->OutputBufferLength) != 0 &&
	    le32_to_cpu(rsp->OutputBufferLength) < sizeof(*info))
		return -ENOSPC;

	inode = file_inode(fp->filp);
	info = (struct smb2_file_id_info *)rsp->Buffer;
	memset(info, 0, sizeof(*info));

	/*
	 * G.1: VolumeSerialNumber from statfs.f_fsid per MS-FSCC §2.4.20.
	 * f_fsid.val[0] is the low 32 bits, f_fsid.val[1] is the high 32 bits.
	 * Fall back to the encoded device number if statfs fails.
	 */
	ret = vfs_statfs(&fp->filp->f_path, &stfs);
	if (!ret) {
		info->VolumeSerialNumber = cpu_to_le64(
			(u64)(unsigned int)stfs.f_fsid.val[0] |
			((u64)(unsigned int)stfs.f_fsid.val[1] << 32));
	} else {
		info->VolumeSerialNumber =
			cpu_to_le64((u64)new_encode_dev(inode->i_sb->s_dev));
	}

	/* FileId low 64 bits = inode number, high 64 bits = 0 */
	ino_le = cpu_to_le64(inode->i_ino);
	memcpy(&info->FileId[0], &ino_le, sizeof(ino_le));
	/* FileId[8..15] remain zero */

	rsp->OutputBufferLength = cpu_to_le32(sizeof(*info));
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(get_file_id_info);

VISIBLE_IF_KUNIT
void fill_fallback_object_id(struct ksmbd_file *fp, u8 *object_id)
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
EXPORT_SYMBOL_IF_KUNIT(fill_fallback_object_id);

static int get_file_object_id_info(struct smb2_query_info_rsp *rsp,
				   struct ksmbd_file *fp, void *rsp_org)
{
	char *xattr_buf = NULL;
	u8 object_id[16];
	u8 *out;
	int i;
	ssize_t xattr_len;

	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE))
		return -EACCES;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),
#else
	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),
#endif
				       fp->filp->f_path.dentry,
				       XATTR_NAME_OBJECT_ID,
				       &xattr_buf);
	if (xattr_len == 16) {
		memcpy(object_id, xattr_buf, 16);
		kfree(xattr_buf);
	} else {
		kfree(xattr_buf);
		if (xattr_len < 0 &&
		    xattr_len != -ENOENT &&
		    xattr_len != -ENODATA &&
		    xattr_len != -EOPNOTSUPP)
			return xattr_len;
		fill_fallback_object_id(fp, object_id);
	}

	out = (u8 *)rsp->Buffer;
	for (i = 0; i < sizeof(struct file_object_buf_type1_ioctl_rsp); i++)
		out[i] = 0;
	for (i = 0; i < 16; i++) {
		out[i] = object_id[i];
		out[32 + i] = object_id[i];
	}

	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct file_object_buf_type1_ioctl_rsp));
	return 0;
}

static int find_file_posix_info(struct smb2_query_info_rsp *rsp,
				struct ksmbd_file *fp, void *rsp_org)
{
	struct smb311_posix_qinfo *file_info;
	struct inode *inode = file_inode(fp->filp);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = file_mnt_idmap(fp->filp);
	vfsuid_t vfsuid = i_uid_into_vfsuid(idmap, inode);
	vfsgid_t vfsgid = i_gid_into_vfsgid(idmap, inode);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	struct user_namespace *user_ns = file_mnt_user_ns(fp->filp);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	vfsuid_t vfsuid = i_uid_into_vfsuid(user_ns, inode);
	vfsgid_t vfsgid = i_gid_into_vfsgid(user_ns, inode);
#endif
#endif
	struct kstat stat;
	u64 time;
	int out_buf_len = sizeof(struct smb311_posix_qinfo) + 32;
	int ret;

	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	if (ret)
		return ret;

	file_info = (struct smb311_posix_qinfo *)rsp->Buffer;
	file_info->CreationTime = cpu_to_le64(fp->create_time);
	time = ksmbd_UnixTimeToNT(stat.atime);
	file_info->LastAccessTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.mtime);
	file_info->LastWriteTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.ctime);
	file_info->ChangeTime = cpu_to_le64(time);
	file_info->DosAttributes = fp->f_ci->m_fattr;
	file_info->Inode = cpu_to_le64(stat.ino);
	if (ksmbd_stream_fd(fp) == false) {
		file_info->EndOfFile = cpu_to_le64(stat.size);
		file_info->AllocationSize = cpu_to_le64(ksmbd_alloc_size(fp, &stat));
	} else {
		file_info->EndOfFile = cpu_to_le64(fp->stream.size);
		file_info->AllocationSize = cpu_to_le64(fp->stream.size);
	}
	file_info->HardLinks = cpu_to_le32(stat.nlink);
	file_info->ReparseTag =
		smb2_get_reparse_tag_special_file(stat.mode);
	file_info->Mode = cpu_to_le32(stat.mode & 0777);
	switch (stat.mode & S_IFMT) {
	case S_IFDIR:
		file_info->Mode |= cpu_to_le32(POSIX_TYPE_DIR << POSIX_FILETYPE_SHIFT);
		break;
	case S_IFLNK:
		file_info->Mode |= cpu_to_le32(POSIX_TYPE_SYMLINK << POSIX_FILETYPE_SHIFT);
		break;
	case S_IFCHR:
		file_info->Mode |= cpu_to_le32(POSIX_TYPE_CHARDEV << POSIX_FILETYPE_SHIFT);
		break;
	case S_IFBLK:
		file_info->Mode |= cpu_to_le32(POSIX_TYPE_BLKDEV << POSIX_FILETYPE_SHIFT);
		break;
	case S_IFIFO:
		file_info->Mode |= cpu_to_le32(POSIX_TYPE_FIFO << POSIX_FILETYPE_SHIFT);
		break;
	case S_IFSOCK:
		file_info->Mode |= cpu_to_le32(POSIX_TYPE_SOCKET << POSIX_FILETYPE_SHIFT);
		break;
	}

	file_info->DeviceId = cpu_to_le32(stat.rdev);
	file_info->Zero = 0;
	/*
	 * Sids(32) contain owner sid(16) + group sid(16).
	 * Each UNIX SID(16) = revision(1) + sub_authority_count(1) +
	 *     authority(6) + sub_auth[0](4) + sub_auth[1](4).
	 * (2 sub-authorities; the second is the UID/GID RID)
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	id_to_sid(from_kuid_munged(&init_user_ns, vfsuid_into_kuid(vfsuid)),
#else
	id_to_sid(from_kuid_munged(&init_user_ns,
				   i_uid_into_mnt(user_ns, inode)),
#endif
#else
	id_to_sid(from_kuid_munged(&init_user_ns, inode->i_uid),
#endif
		  SIDUNIX_USER, (struct smb_sid *)&file_info->Sids[0]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	id_to_sid(from_kgid_munged(&init_user_ns, vfsgid_into_kgid(vfsgid)),
#else
	id_to_sid(from_kgid_munged(&init_user_ns,
				   i_gid_into_mnt(user_ns, inode)),
#endif
#else
	id_to_sid(from_kgid_munged(&init_user_ns, inode->i_gid),
#endif
		  SIDUNIX_GROUP, (struct smb_sid *)&file_info->Sids[16]);

	rsp->OutputBufferLength = cpu_to_le32(out_buf_len);

	return 0;
}

static int smb2_get_info_file(struct ksmbd_work *work,
			      struct smb2_query_info_req *req,
			      struct smb2_query_info_rsp *rsp)
{
	struct ksmbd_file *fp;
	int fileinfoclass = 0;
	int rc = 0;
	int min_output_len = 4;
	unsigned int qout_len = 0;
	unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;
	unsigned int max_resp = smb2_calc_max_out_buf_len(work, 8,
					le32_to_cpu(req->OutputBufferLength));
	if (max_resp > 0)
		memset(rsp->Buffer, 0, min_t(unsigned int, max_resp, 1024));

	if (test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_PIPE)) {
		/* smb2 info file called for pipe */
		return smb2_get_info_file_pipe(work, work->sess, req, rsp,
					       work->response_buf);
	}

	if (work->next_smb2_rcv_hdr_off) {
		if (!has_file_id(req->VolatileFileId)) {
			ksmbd_debug(SMB, "Compound request set FID = %llu\n",
				    work->compound_fid);
			id = work->compound_fid;
			pid = work->compound_pfid;
		}
	}

	if (!has_file_id(id)) {
		id = req->VolatileFileId;
		pid = req->PersistentFileId;
	}

	fp = ksmbd_lookup_fd_slow(work, id, pid);
	if (!fp)
		return -ENOENT;

	fileinfoclass = req->FileInfoClass;

	switch (fileinfoclass) {
	case FILE_ACCESS_INFORMATION:
		get_file_access_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_access_info);
		break;

	case FILE_BASIC_INFORMATION:
		rc = get_file_basic_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_basic_info);
		break;

	case FILE_STANDARD_INFORMATION:
		rc = get_file_standard_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_standard_info);
		break;

	case FILE_ALIGNMENT_INFORMATION:
		get_file_alignment_info(rsp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_alignment_info);
		break;

	case FILE_ALL_INFORMATION:
		rc = get_file_all_info(work, rsp, fp, work->response_buf);
		/*
		 * The actual response includes a variable-length FileName
		 * that may exceed OutputBufferLength. buffer_check_err()
		 * called after the switch compares OutputBufferLength
		 * against rsp->OutputBufferLength (set by get_file_all_info)
		 * and returns STATUS_BUFFER_OVERFLOW when the client buffer
		 * is too small, which is the correct MS-SMB2 behavior.
		 */
		min_output_len = FILE_ALL_INFORMATION_SIZE;
		break;

	case FILE_ALTERNATE_NAME_INFORMATION:
		get_file_alternate_info(work, rsp, fp, work->response_buf);
		min_output_len = FILE_ALTERNATE_NAME_INFORMATION_SIZE;
		break;

	case FILE_STREAM_INFORMATION:
		rc = get_file_stream_info(work, rsp, fp, work->response_buf);
		min_output_len = FILE_STREAM_INFORMATION_SIZE;
		break;

	case FILE_INTERNAL_INFORMATION:
		rc = get_file_internal_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_internal_info);
		break;

	case FILE_NETWORK_OPEN_INFORMATION:
		rc = get_file_network_open_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_ntwrk_info);
		break;

	case FILE_EA_INFORMATION:
		get_file_ea_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_ea_info);
		break;

	case FILE_FULL_EA_INFORMATION:
		rc = smb2_get_ea(work, fp, req, rsp, work->response_buf);
		break;

	case FILE_POSITION_INFORMATION:
		get_file_position_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_pos_info);
		break;

	case FILE_MODE_INFORMATION:
		get_file_mode_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_mode_info);
		break;

	case FILE_COMPRESSION_INFORMATION:
		rc = get_file_compression_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_comp_info);
		break;

	case FILE_OBJECT_ID_INFORMATION:
		rc = get_file_object_id_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct file_object_buf_type1_ioctl_rsp);
		break;

	case FILE_REPARSE_POINT_INFORMATION:
		rc = get_file_reparse_point_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_reparse_point_info);
		break;

	case FILE_ATTRIBUTE_TAG_INFORMATION:
		rc = get_file_attribute_tag_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_attr_tag_info);
		break;
	case FILE_STANDARD_LINK_INFORMATION:
		rc = get_file_standard_link_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_standard_link_info);
		break;
	case FILE_ID_INFORMATION:
		rc = get_file_id_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb2_file_id_info);
		break;
	/*
	 * QSA-01: Correct dispatch for class 70 and 71.
	 *
	 * FILE_STAT_LX_INFORMATION = 70 (MS-FSCC §2.4.48, WSL/POSIX extension)
	 *   Called directly (not via dispatch) because the dispatch table
	 *   has no registered handler for class 70 in this slot.
	 *
	 * FILE_CASE_SENSITIVE_INFORMATION = 71 (MS-FSCC §2.4.8)
	 *   Dispatched via the info handler table where
	 *   ksmbd_case_sensitive_get_handler is registered for class 71.
	 *
	 * Previously case 70 dispatched (hitting nothing) and case 71 wrongly
	 * called ksmbd_info_get_file_stat_lx for CASE_SENSITIVE requests.
	 */
	case FILE_STAT_LX_INFORMATION: /* 70 */
	{
		unsigned int stat_lx_out = 0;

		rc = ksmbd_info_get_file_stat_lx(work, fp,
						 rsp->Buffer,
						 le32_to_cpu(req->OutputBufferLength),
						 &stat_lx_out);
		if (!rc) {
			rsp->OutputBufferLength = cpu_to_le32(stat_lx_out);
			min_output_len = stat_lx_out;
		}
		break;
	}
	case FILE_CASE_SENSITIVE_INFORMATION: /* 71 */
	{
		unsigned int case_out = 0;

		rc = ksmbd_dispatch_info(work, fp,
					 SMB2_O_INFO_FILE,
					 fileinfoclass,
					 KSMBD_INFO_GET,
					 rsp->Buffer,
					 le32_to_cpu(req->OutputBufferLength),
					 &case_out);
		if (!rc) {
			rsp->OutputBufferLength = cpu_to_le32(case_out);
			min_output_len = case_out;
		}
		break;
	}
	case SMB_FIND_FILE_POSIX_INFO:
		rc = find_file_posix_info(rsp, fp, work->response_buf);
		min_output_len = sizeof(struct smb311_posix_qinfo);
		break;
	default:
		rc = ksmbd_dispatch_info(work, fp,
					 SMB2_O_INFO_FILE,
					 fileinfoclass,
					 KSMBD_INFO_GET,
					 rsp->Buffer,
					 le32_to_cpu(req->OutputBufferLength),
					 &qout_len);
		if (!rc)
			rsp->OutputBufferLength = cpu_to_le32(qout_len);
		else
			ksmbd_debug(SMB, "fileinfoclass %d unsupported\n",
				    fileinfoclass);
	}
	if (!rc)
		rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
				      rsp, work->response_buf, min_output_len);
	ksmbd_fd_put(work, fp);
	return rc;
}

static int smb2_get_info_filesystem(struct ksmbd_work *work,
				    struct smb2_query_info_req *req,
				    struct smb2_query_info_rsp *rsp)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_share_config *share = work->tcon->share_conf;
	int fsinfoclass = 0;
	struct kstatfs stfs;
	struct path path;
	unsigned int qout_len = 0;
	int rc = 0, len;
	unsigned int max_resp;
	int min_output_len = 4;

	/* Pre-zero the response buffer to prevent kernel heap data leakage */
	max_resp = smb2_calc_max_out_buf_len(work, 8,
				le32_to_cpu(req->OutputBufferLength));
	if (max_resp > 0)
		memset(rsp->Buffer, 0, min_t(unsigned int, max_resp, 1024));

	if (!share->path)
		return -EIO;

	rc = kern_path(share->path, LOOKUP_NO_SYMLINKS, &path);
	if (rc) {
		pr_err("cannot create vfs path\n");
		return -EIO;
	}

	rc = vfs_statfs(&path, &stfs);
	if (rc) {
		pr_err("cannot do stat of path %s\n", share->path);
		path_put(&path);
		return -EIO;
	}

	fsinfoclass = req->FileInfoClass;

	switch (fsinfoclass) {
	case FS_DEVICE_INFORMATION:
	{
		struct filesystem_device_info *info;

		info = (struct filesystem_device_info *)rsp->Buffer;

		info->DeviceType = cpu_to_le32(FILE_DEVICE_DISK);
		info->DeviceCharacteristics =
			cpu_to_le32(FILE_DEVICE_IS_MOUNTED);
		if (!test_tree_conn_flag(work->tcon,
					 KSMBD_TREE_CONN_FLAG_WRITABLE))
			info->DeviceCharacteristics |=
				cpu_to_le32(FILE_READ_ONLY_DEVICE);
		rsp->OutputBufferLength = cpu_to_le32(8);
		min_output_len = 8;
		break;
	}
	case FS_ATTRIBUTE_INFORMATION:
	{
		struct filesystem_attribute_info *info;
		size_t sz;

		info = (struct filesystem_attribute_info *)rsp->Buffer;
		info->Attributes = cpu_to_le32(FILE_SUPPORTS_OBJECT_IDS |
					       FILE_PERSISTENT_ACLS |
					       FILE_UNICODE_ON_DISK |
					       FILE_CASE_PRESERVED_NAMES |
					       FILE_CASE_SENSITIVE_SEARCH |
					       FILE_SUPPORTS_REPARSE_POINTS |
					       FILE_SUPPORTS_BLOCK_REFCOUNTING);

		info->Attributes |= cpu_to_le32(server_conf.share_fake_fscaps);

		if (test_share_config_flag(work->tcon->share_conf,
		    KSMBD_SHARE_FLAG_STREAMS))
			info->Attributes |= cpu_to_le32(FILE_NAMED_STREAMS);

		info->MaxPathNameComponentLength = cpu_to_le32(stfs.f_namelen);
		/*
		 * Always convert the full "NTFS" label so rsp->OutputBufferLength
		 * reflects the complete response size. buffer_check_err() uses
		 * OutputBufferLength to detect when the client's buffer is too
		 * small and must return STATUS_BUFFER_OVERFLOW.  "NTFS" in
		 * UTF-16LE is only 8 bytes so there is no overflow risk.
		 * (Reverts QSA-22 truncation that broke buffer-size detection.)
		 */
		len = smbConvertToUTF16((__le16 *)info->FileSystemName,
					"NTFS", NAME_MAX, conn->local_nls, 0);
		len = len * 2;
		info->FileSystemNameLen = cpu_to_le32(len);
		sz = sizeof(struct filesystem_attribute_info) + len;
		rsp->OutputBufferLength = cpu_to_le32(sz);
		min_output_len = 16;
		break;
	}
	case FS_VOLUME_INFORMATION:
	{
		struct filesystem_vol_info *info;
		size_t sz;
		unsigned int serial_crc = 0;

		info = (struct filesystem_vol_info *)(rsp->Buffer);
		info->VolumeCreationTime = 0;
		serial_crc = crc32_le(serial_crc, share->name,
				      strlen(share->name));
		serial_crc = crc32_le(serial_crc, share->path,
				      strlen(share->path));
		serial_crc = crc32_le(serial_crc, ksmbd_netbios_name(),
				      strlen(ksmbd_netbios_name()));
		/* Taking dummy value of serial number*/
		info->SerialNumber = cpu_to_le32(serial_crc);
		len = smbConvertToUTF16((__le16 *)info->VolumeLabel,
					share->name, PATH_MAX,
					conn->local_nls, 0);
		len = len * 2;
		info->VolumeLabelSize = cpu_to_le32(len);
		info->Reserved = 0;
		sz = sizeof(struct filesystem_vol_info) + len;
		rsp->OutputBufferLength = cpu_to_le32(sz);
		min_output_len = 24;
		break;
	}
	case FS_SIZE_INFORMATION:
	{
		struct filesystem_info *info;
		/*
		 * G.6: Windows expects BytesPerSector=512 and
		 * SectorsPerAllocationUnit = f_bsize / 512 (cluster factor).
		 * This satisfies:
		 *   SectorsPerAllocationUnit * BytesPerSector == f_bsize
		 * and allows Windows Explorer to compute correct free space.
		 */
		unsigned long sectors_per_unit =
			max(1UL, (unsigned long)(stfs.f_bsize / 512));

		info = (struct filesystem_info *)(rsp->Buffer);
		info->TotalAllocationUnits = cpu_to_le64(stfs.f_blocks);
		info->FreeAllocationUnits = cpu_to_le64(stfs.f_bfree);
		info->SectorsPerAllocationUnit = cpu_to_le32(sectors_per_unit);
		info->BytesPerSector = cpu_to_le32(512);
		rsp->OutputBufferLength = cpu_to_le32(24);
		min_output_len = 24;
		break;
	}
	case FS_FULL_SIZE_INFORMATION:
	{
		struct smb2_fs_full_size_info *info;
		unsigned long sectors_per_unit =
			max(1UL, (unsigned long)(stfs.f_bsize / 512));

		info = (struct smb2_fs_full_size_info *)(rsp->Buffer);
		info->TotalAllocationUnits = cpu_to_le64(stfs.f_blocks);
		info->CallerAvailableAllocationUnits =
					cpu_to_le64(stfs.f_bavail);
		info->ActualAvailableAllocationUnits =
					cpu_to_le64(stfs.f_bfree);
		info->SectorsPerAllocationUnit = cpu_to_le32(sectors_per_unit);
		info->BytesPerSector = cpu_to_le32(512);
		rsp->OutputBufferLength = cpu_to_le32(32);
		min_output_len = 32;
		break;
	}
	case FS_OBJECT_ID_INFORMATION:
	{
		struct object_id_info *info;

		info = (struct object_id_info *)(rsp->Buffer);

		/*
		 * Do not leak the user passkey as the object ID.
		 * Use zeroed object ID for all users.
		 */
		memset(info->objid, 0, 16);

		/* QSA-13: Zero the entire extended_info before filling fields
		 * to prevent leaking uninitialized kernel heap data (the
		 * version_string field is 28 bytes but only 5 are filled).
		 */
		memset(&info->extended_info, 0, sizeof(info->extended_info));
		info->extended_info.magic = cpu_to_le32(EXTENDED_INFO_MAGIC);
		info->extended_info.version = cpu_to_le32(1);
		info->extended_info.release = cpu_to_le32(1);
		info->extended_info.rel_date = 0;
		memcpy(info->extended_info.version_string, "1.1.0", strlen("1.1.0"));
		rsp->OutputBufferLength = cpu_to_le32(64);
		min_output_len = 48;
		break;
	}
	case FS_SECTOR_SIZE_INFORMATION:
	{
		struct smb3_fs_ss_info *info;
		unsigned int sector_size =
			min_t(unsigned int, path.mnt->mnt_sb->s_blocksize, 4096);

		info = (struct smb3_fs_ss_info *)(rsp->Buffer);

		info->LogicalBytesPerSector = cpu_to_le32(sector_size);
		info->PhysicalBytesPerSectorForAtomicity =
				cpu_to_le32(sector_size);
		info->PhysicalBytesPerSectorForPerf = cpu_to_le32(sector_size);
		info->FSEffPhysicalBytesPerSectorForAtomicity =
				cpu_to_le32(sector_size);
		info->Flags = cpu_to_le32(SSINFO_FLAGS_ALIGNED_DEVICE |
				    SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE);
		info->ByteOffsetForSectorAlignment = 0;
		info->ByteOffsetForPartitionAlignment = 0;
		rsp->OutputBufferLength = cpu_to_le32(28);
		min_output_len = 28;
		break;
	}
	case FS_CONTROL_INFORMATION:
	{
		/*
		 * FS_CONTROL_INFORMATION: return default quota control
		 * values.  Linux does not expose quota thresholds via
		 * VFS, so use safe defaults matching non-quota volumes.
		 */
		struct smb2_fs_control_info *info;

		info = (struct smb2_fs_control_info *)(rsp->Buffer);
		info->FreeSpaceStartFiltering = 0;
		info->FreeSpaceThreshold = 0;
		info->FreeSpaceStopFiltering = 0;
		info->DefaultQuotaThreshold = cpu_to_le64(SMB2_NO_FID);
		info->DefaultQuotaLimit = cpu_to_le64(SMB2_NO_FID);
		info->Padding = 0;
		rsp->OutputBufferLength = cpu_to_le32(48);
		min_output_len = 48;
		break;
	}
	case FS_POSIX_INFORMATION:
	{
		struct filesystem_posix_info *info;

		info = (struct filesystem_posix_info *)(rsp->Buffer);
		info->OptimalTransferSize = cpu_to_le32(stfs.f_bsize);
		info->BlockSize = cpu_to_le32(stfs.f_bsize);
		info->TotalBlocks = cpu_to_le64(stfs.f_blocks);
		info->BlocksAvail = cpu_to_le64(stfs.f_bfree);
		info->UserBlocksAvail = cpu_to_le64(stfs.f_bavail);
		info->TotalFileNodes = cpu_to_le64(stfs.f_files);
		info->FreeFileNodes = cpu_to_le64(stfs.f_ffree);
		rsp->OutputBufferLength = cpu_to_le32(56);
		min_output_len = 56;
		break;
	}
	default:
		rc = ksmbd_dispatch_info(work, NULL,
					 SMB2_O_INFO_FILESYSTEM,
					 fsinfoclass,
					 KSMBD_INFO_GET,
					 rsp->Buffer,
					 le32_to_cpu(req->OutputBufferLength),
					 &qout_len);
		if (rc) {
			path_put(&path);
			return rc;
		}

		rsp->OutputBufferLength = cpu_to_le32(qout_len);
		break;
	}
	rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
			      rsp, work->response_buf, min_output_len);
	path_put(&path);
	return rc;
}

static int smb2_get_info_sec(struct ksmbd_work *work,
			     struct smb2_query_info_req *req,
			     struct smb2_query_info_rsp *rsp)
{
	struct ksmbd_file *fp;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap;
#else
	struct user_namespace *user_ns;
#endif
	struct smb_ntsd *pntsd = (struct smb_ntsd *)rsp->Buffer, *ppntsd = NULL;
	struct smb_fattr fattr = {{0}};
	struct inode *inode;
	__u32 secdesclen = 0;
	unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;
	int addition_info = le32_to_cpu(req->AdditionalInformation);
	int rc = 0, ppntsd_size = 0;

	if (addition_info & ~(OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO |
			      SACL_SECINFO | LABEL_SECINFO |
			      ATTRIBUTE_SECINFO | SCOPE_SECINFO |
			      BACKUP_SECINFO |
			      PROTECTED_DACL_SECINFO |
			      UNPROTECTED_DACL_SECINFO |
			      PROTECTED_SACL_SECINFO |
			      UNPROTECTED_SACL_SECINFO)) {
		ksmbd_debug(SMB, "Unsupported addition info: 0x%x)\n",
		       addition_info);

		/*
		 * Per MS-SMB2 3.3.5.20.3: when the client requests
		 * security information flags that the server does not
		 * support, return a minimal self-relative security
		 * descriptor with no owner, group, SACL, or DACL.
		 * This is intentional -- it signals to the client that
		 * the requested information is not available without
		 * failing the entire query.
		 */
		pntsd->revision = cpu_to_le16(1);
		pntsd->type = cpu_to_le16(SELF_RELATIVE | DACL_PROTECTED);
		pntsd->osidoffset = 0;
		pntsd->gsidoffset = 0;
		pntsd->sacloffset = 0;
		pntsd->dacloffset = 0;

		secdesclen = sizeof(struct smb_ntsd);
		rsp->OutputBufferLength = cpu_to_le32(secdesclen);

		return 0;
	}

	if (work->next_smb2_rcv_hdr_off) {
		if (!has_file_id(req->VolatileFileId)) {
			ksmbd_debug(SMB, "Compound request set FID = %llu\n",
				    work->compound_fid);
			id = work->compound_fid;
			pid = work->compound_pfid;
		}
	}

	if (!has_file_id(id)) {
		id = req->VolatileFileId;
		pid = req->PersistentFileId;
	}

	fp = ksmbd_lookup_fd_slow(work, id, pid);
	if (!fp)
		return -ENOENT;

	/*
	 * Per MS-SMB2 3.3.5.20.3: querying OWNER, GROUP, or DACL
	 * security info requires READ_CONTROL access.  Querying
	 * SACL requires ACCESS_SYSTEM_SECURITY.
	 */
	if (addition_info & (OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO)) {
		if (!(fp->daccess & FILE_READ_CONTROL_LE)) {
			ksmbd_fd_put(work, fp);
			return -EACCES;
		}
	}
	if (addition_info & SACL_SECINFO) {
		if (!(fp->daccess & FILE_ACCESS_SYSTEM_SECURITY_LE)) {
			ksmbd_fd_put(work, fp);
			return -EACCES;
		}
	}
	/* QS-07: LABEL_SECINFO requires READ_CONTROL access */
	if (addition_info & LABEL_SECINFO) {
		if (!(fp->daccess & FILE_READ_CONTROL_LE)) {
			ksmbd_fd_put(work, fp);
			return -EACCES;
		}
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	idmap = file_mnt_idmap(fp->filp);
#else
	user_ns = file_mnt_user_ns(fp->filp);
#endif
	inode = file_inode(fp->filp);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ksmbd_acls_fattr(&fattr, idmap, inode);
#else
	ksmbd_acls_fattr(&fattr, user_ns, inode);
#endif

	if (test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_ACL_XATTR))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		ppntsd_size = ksmbd_vfs_get_sd_xattr(work->conn, idmap,
#else
		ppntsd_size = ksmbd_vfs_get_sd_xattr(work->conn, user_ns,
#endif
						     fp->filp->f_path.dentry,
						     &ppntsd);

	/* Check if sd buffer size exceeds response buffer size */
	if (smb2_resp_buf_len(work, 8) > ppntsd_size) {
		unsigned int resp_buf_size =
			(unsigned int)smb2_resp_buf_len(work, 8);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		rc = build_sec_desc(idmap, pntsd, ppntsd, ppntsd_size,
#else
		rc = build_sec_desc(user_ns, pntsd, ppntsd, ppntsd_size,
#endif
				    addition_info, &secdesclen,
				    &fattr, resp_buf_size);
	}
	posix_acl_release(fattr.cf_acls);
	posix_acl_release(fattr.cf_dacls);
	kfree(ppntsd);
	if (rc) {
		ksmbd_fd_put(work, fp);
		return rc;
	}

	/*
	 * L-02: MS-SMB2 §3.3.5.20.1 LABEL_SECURITY_INFORMATION (0x10).
	 * If requested, retrieve the stored integrity label SACL from the
	 * dedicated xattr and append it to the security descriptor response.
	 *
	 * ACL-04: Also check the label xattr when SACL_SECINFO is requested
	 * but the stored NTSD has no SACL (sacloffset == 0).  Windows stores
	 * integrity labels in a separate xattr (XATTR_NAME_SD_LABEL) via
	 * set_info_sec(), so a SACL_SECINFO query should also expose them.
	 */
	if ((addition_info & LABEL_SECINFO) ||
	    ((addition_info & SACL_SECINFO) && !pntsd->sacloffset)) {
		char *label_buf = NULL;
		ssize_t label_len;
		struct dentry *dentry = fp->filp->f_path.dentry;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		label_len = ksmbd_vfs_getxattr(idmap, dentry,
#else
		label_len = ksmbd_vfs_getxattr(user_ns, dentry,
#endif
					       XATTR_NAME_SD_LABEL, &label_buf);
		if (label_len > 0 &&
		    label_len >= (ssize_t)sizeof(struct smb_acl)) {
			struct smb_acl *sacl = (struct smb_acl *)label_buf;
			__u16 sacl_size = le16_to_cpu(sacl->size);

			if (sacl_size >= sizeof(struct smb_acl) &&
			    (ssize_t)sacl_size <= label_len) {
				unsigned int resp_len = smb2_resp_buf_len(work, 8);

				if (secdesclen + sacl_size <= resp_len) {
					memcpy((char *)pntsd + secdesclen,
					       label_buf, sacl_size);
					pntsd->sacloffset =
						cpu_to_le32(secdesclen);
					pntsd->type |=
						cpu_to_le16(SACL_PRESENT);
					secdesclen += sacl_size;
				}
			}
		} else if (label_len == -ENODATA || label_len == -ENOENT ||
			   label_len == 0) {
			/*
			 * No label stored: return an empty SACL so the client
			 * knows LABEL_SECINFO is supported but no label is set.
			 */
			unsigned int resp_len = smb2_resp_buf_len(work, 8);

			if (secdesclen + sizeof(struct smb_acl) <= resp_len) {
				struct smb_acl *empty_sacl =
					(struct smb_acl *)((char *)pntsd +
							   secdesclen);

				empty_sacl->revision = cpu_to_le16(2);
				empty_sacl->size =
					cpu_to_le16(sizeof(struct smb_acl));
				empty_sacl->num_aces = 0;
				empty_sacl->reserved = 0;
				pntsd->sacloffset = cpu_to_le32(secdesclen);
				pntsd->type |= cpu_to_le16(SACL_PRESENT);
				secdesclen += sizeof(struct smb_acl);
			}
		}
		kfree(label_buf);
	}

	ksmbd_fd_put(work, fp);
	rsp->OutputBufferLength = cpu_to_le32(secdesclen);

	/*
	 * Per MS-SMB2 3.3.5.20.3: if the security descriptor is
	 * larger than the client's OutputBufferLength, return
	 * STATUS_BUFFER_TOO_SMALL with the required size so the
	 * client can retry with a larger buffer.
	 */
	if (secdesclen > le32_to_cpu(req->OutputBufferLength)) {
		/*
		 * MS-SMB2 §3.3.5.20.3: the server MUST return
		 * STATUS_BUFFER_TOO_SMALL and set OutputBufferLength in
		 * the response to the required size so the client can
		 * retry with a sufficient buffer.
		 *
		 * We encode the required size in OutputBufferLength now.
		 * The caller detects STATUS_BUFFER_TOO_SMALL and pins the
		 * QUERY_INFO response directly rather than calling
		 * smb2_set_err_rsp() (which would erase the size field).
		 */
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		rsp->OutputBufferLength = cpu_to_le32(secdesclen);
		return -EOVERFLOW;
	}

	return 0;
}

/**
 * smb2_query_info() - handler for smb2 query info command
 * @work:	smb work containing query info request buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_query_info(struct ksmbd_work *work)
{
	struct smb2_query_info_req *req;
	struct smb2_query_info_rsp *rsp;
	int rc = 0;
	unsigned int qout_len = 0;

	ksmbd_debug(SMB, "Received request smb2 query info request\n");

	WORK_BUFFERS(work, req, rsp);

	if (ksmbd_override_fsids(work)) {
		rc = -ENOMEM;
		goto err_out;
	}

	switch (req->InfoType) {
	case SMB2_O_INFO_FILE:
		ksmbd_debug(SMB, "GOT SMB2_O_INFO_FILE\n");
		rc = smb2_get_info_file(work, req, rsp);
		break;
	case SMB2_O_INFO_FILESYSTEM:
		ksmbd_debug(SMB, "GOT SMB2_O_INFO_FILESYSTEM\n");
		rc = smb2_get_info_filesystem(work, req, rsp);
		break;
	case SMB2_O_INFO_SECURITY:
		ksmbd_debug(SMB, "GOT SMB2_O_INFO_SECURITY\n");
		rc = smb2_get_info_sec(work, req, rsp);
		break;
	case SMB2_O_INFO_QUOTA:
	{
		struct ksmbd_file *fp;
		unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;
		unsigned int qout_len = 0;

		ksmbd_debug(SMB, "GOT SMB2_O_INFO_QUOTA\n");

		if (work->next_smb2_rcv_hdr_off) {
			if (!has_file_id(req->VolatileFileId)) {
				id = work->compound_fid;
				pid = work->compound_pfid;
			}
		}
		if (!has_file_id(id)) {
			id = req->VolatileFileId;
			pid = req->PersistentFileId;
		}

		fp = ksmbd_lookup_fd_slow(work, id, pid);
		if (!fp) {
			rc = -ENOENT;
			break;
		}

			rc = ksmbd_dispatch_info(work, fp,
						 SMB2_O_INFO_QUOTA,
						 req->FileInfoClass,
						 KSMBD_INFO_GET,
						 rsp->Buffer,
						 le32_to_cpu(req->OutputBufferLength),
						 &qout_len);
		ksmbd_fd_put(work, fp);

			if (rc == -EOPNOTSUPP) {
				/*
				 * If quota handlers are not registered, keep
				 * behavior probe-friendly by returning an empty
				 * response rather than failing the request.
				 */
				rc = 0;
				qout_len = 0;
			}
			if (!rc)
				rsp->OutputBufferLength = cpu_to_le32(qout_len);
			break;
		}
		default:
			/*
			 * Validate InfoType range before dispatching to hook
			 * handlers.  MS-SMB2 defines InfoType values 1..4;
			 * reject anything outside that range to avoid passing
			 * unexpected values to registered hooks.
			 */
			if (req->InfoType < SMB2_O_INFO_FILE ||
			    req->InfoType > SMB2_O_INFO_QUOTA) {
				ksmbd_debug(SMB,
					    "Invalid InfoType %d\n",
					    req->InfoType);
				rc = -EINVAL;
				break;
			}
			rc = ksmbd_dispatch_info(work, NULL,
						 req->InfoType,
						 req->FileInfoClass,
						 KSMBD_INFO_GET,
						 rsp->Buffer,
						 le32_to_cpu(req->OutputBufferLength),
						 &qout_len);
			if (!rc)
				rsp->OutputBufferLength = cpu_to_le32(qout_len);
			else
				ksmbd_debug(SMB, "InfoType %d unsupported\n",
					    req->InfoType);
		}
	ksmbd_revert_fsids(work);

	if (!rc) {
		rsp->StructureSize = cpu_to_le16(9);
		rsp->OutputBufferOffset = cpu_to_le16(72);
		rc = ksmbd_iov_pin_rsp(work, (void *)rsp,
				       offsetof(struct smb2_query_info_rsp, Buffer) +
					le32_to_cpu(rsp->OutputBufferLength));
	}

err_out:
	if (rc < 0) {
		if (rc == -EOVERFLOW) {
			/*
			 * MS-SMB2 §3.3.5.20.3: security descriptor too large.
			 * rsp->hdr.Status is already STATUS_BUFFER_TOO_SMALL
			 * and rsp->OutputBufferLength holds the required size.
			 * Pin a minimal QUERY_INFO response so the client can
			 * read OutputBufferLength and retry with a larger buf.
			 * Do NOT call smb2_set_err_rsp() — it would overwrite
			 * the OutputBufferLength field with an empty error body.
			 */
			rsp->StructureSize = cpu_to_le16(9);
			rsp->OutputBufferOffset = cpu_to_le16(72);
			ksmbd_iov_pin_rsp(work, (void *)rsp,
					  offsetof(struct smb2_query_info_rsp,
						   Buffer));
		} else if (rc == -EACCES)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (rc == -ENOENT)
			rsp->hdr.Status = STATUS_FILE_CLOSED;
		else if (rc == -EIO)
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
		else if (rc == -ENOMEM)
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		else if (rc == -ENOSYS)
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
		else if (rc == -EOPNOTSUPP || rsp->hdr.Status == 0)
			rsp->hdr.Status = STATUS_INVALID_INFO_CLASS;
		if (rc != -EOVERFLOW)
			smb2_set_err_rsp(work);

		ksmbd_debug(SMB, "error while processing smb2 query rc = %d\n",
			    rc);
		return rc;
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static int smb2_rename(struct ksmbd_work *work,
		       struct ksmbd_file *fp,
		       struct smb2_file_rename_info *file_info,
		       struct nls_table *local_nls)
{
	struct ksmbd_share_config *share = fp->tcon->share_conf;
	char *new_name = NULL;
	int rc, flags = 0;

	ksmbd_debug(SMB, "setting FILE_RENAME_INFO\n");
	new_name = smb2_get_name(file_info->FileName,
				 le32_to_cpu(file_info->FileNameLength),
				 local_nls);
	if (IS_ERR(new_name))
		return PTR_ERR(new_name);

	/*
	 * G.7: If RootDirectory is non-zero, it is a volatile FID for
	 * the directory relative to which FileName is resolved.
	 * Prepend the root's share-relative path to new_name.
	 */
	if (file_info->RootDirectory) {
		struct ksmbd_file *root_fp;
		char *root_path, *combined;

		root_fp = ksmbd_lookup_fd_fast(work, file_info->RootDirectory);
		if (!root_fp) {
			kfree(new_name);
			return -ENOENT;
		}
		root_path = convert_to_nt_pathname(share,
						   &root_fp->filp->f_path);
		ksmbd_fd_put(work, root_fp);
		if (IS_ERR(root_path)) {
			kfree(new_name);
			return PTR_ERR(root_path);
		}
		/* Combine root_path + "/" + new_name (strip leading '/') */
		if (new_name[0] == '/' || new_name[0] == '\\')
			combined = kasprintf(KSMBD_DEFAULT_GFP, "%s%s",
					     root_path, new_name);
		else
			combined = kasprintf(KSMBD_DEFAULT_GFP, "%s/%s",
					     root_path, new_name);
		kfree(root_path);
		kfree(new_name);
		if (!combined)
			return -ENOMEM;
		new_name = combined;
		ksmbd_debug(SMB, "RootDirectory resolved new name: %s\n",
			    new_name);
	}

	if (fp->is_posix_ctxt == false && strchr(new_name, ':')) {
		int s_type;
		char *xattr_stream_name, *stream_name = NULL;
		size_t xattr_stream_size;
		int len;

		rc = parse_stream_name(new_name, &stream_name, &s_type);
		if (rc < 0) {
			/*
			 * parse_stream_name returns -ENOENT for "::$DATA"
			 * (the default data stream).  Per MS-FSA 2.1.5.14.11,
			 * renaming a named stream to ::$DATA means removing
			 * the named stream (promoting its data to the default
			 * stream is not supported for xattr-backed streams,
			 * so we just delete the source xattr).
			 */
			if (rc == -ENOENT && !stream_name &&
			    s_type == DATA_STREAM && ksmbd_stream_fd(fp)) {
				rc = ksmbd_vfs_remove_xattr(
					file_mnt_idmap(fp->filp),
					&fp->filp->f_path,
					fp->stream.name, true);
				if (rc)
					pr_err("rename to default stream: remove xattr failed %d\n",
					       rc);
				else
					rc = 0;
			}
			goto out;
		}

		len = strlen(new_name);
		if (len > 0 && new_name[len - 1] != '/') {
			pr_err("not allow base filename in rename\n");
			rc = -ESHARE;
			goto out;
		}

		rc = ksmbd_vfs_xattr_stream_name(stream_name,
						 &xattr_stream_name,
						 &xattr_stream_size,
						 s_type);
		if (rc)
			goto out;

		rc = ksmbd_vfs_setxattr(file_mnt_idmap(fp->filp),
					&fp->filp->f_path,
					xattr_stream_name,
					NULL, 0, 0, true);
		if (rc < 0) {
			pr_err("failed to store stream name in xattr: %d\n",
			       rc);
			rc = -EINVAL;
			goto out;
		}

		goto out;
	}

	ksmbd_debug(SMB, "new name %s\n", new_name);
	if (ksmbd_share_veto_filename(share, new_name)) {
		rc = -ENOENT;
		ksmbd_debug(SMB, "Can't rename vetoed file: %s\n", new_name);
		goto out;
	}

	/*
	 * POSIX rename semantics: always allow atomic replace of the
	 * target, even if it is currently open. This matches the
	 * POSIX rename(2) behavior.
	 */
	if (!file_info->ReplaceIfExists && !fp->is_posix_ctxt)
		flags = RENAME_NOREPLACE;

	smb_break_all_handle_lease(work, fp, true);

	if (!S_ISDIR(file_inode(fp->filp)->i_mode)) {
		struct dentry *src_parent;
		struct path dst_dir_path;
		char *slash;

		/*
		 * Break source parent directory leases BEFORE the rename.
		 */
		src_parent = fp->filp->f_path.dentry->d_parent;
		smb_break_parent_dir_lease(fp);

		/*
		 * Break destination parent directory leases BEFORE
		 * the rename.  If the destination directory has an
		 * open handle with DELETE_ACCESS, use a Handle break
		 * (RH->R) with WAIT so the client can close the
		 * handle; otherwise break to NONE.
		 */
		slash = strrchr(new_name, '/');
		if (slash && slash != new_name) {
			*slash = '\0';
			if (!ksmbd_vfs_kern_path(work, new_name,
						 LOOKUP_NO_SYMLINKS,
						 &dst_dir_path, 1)) {
				if (dst_dir_path.dentry != src_parent) {
					struct ksmbd_file *dst_fp;
					int brk = SMB2_OPLOCK_LEVEL_NONE;

					dst_fp = ksmbd_lookup_fd_inode(
						dst_dir_path.dentry);
					if (dst_fp) {
						if (dst_fp->daccess &
						    FILE_DELETE_LE)
							brk = OPLOCK_BREAK_HANDLE_CACHING_WAIT;
						ksmbd_fd_put(work, dst_fp);
					}
					smb_break_dir_lease_by_dentry_level(
						dst_dir_path.dentry, fp,
						brk);
				}
				path_put(&dst_dir_path);
			}
			*slash = '/';
		} else if (slash == new_name) {
			struct dentry *root =
				fp->filp->f_path.mnt->mnt_root;
			if (root != src_parent) {
				struct ksmbd_file *dst_fp;
				int brk = SMB2_OPLOCK_LEVEL_NONE;

				dst_fp = ksmbd_lookup_fd_inode(root);
				if (dst_fp) {
					if (dst_fp->daccess & FILE_DELETE_LE)
						brk = OPLOCK_BREAK_HANDLE_CACHING_WAIT;
					ksmbd_fd_put(work, dst_fp);
				}
				smb_break_dir_lease_by_dentry_level(root, fp,
								    brk);
			}
		}

		/*
		 * If overwriting (ReplaceIfExists), break Handle lease
		 * on the target and check if it is still open.  Windows
		 * does not allow replacing a file that has open handles.
		 */
		if (file_info->ReplaceIfExists && !fp->is_posix_ctxt) {
			struct path target_path;

			if (!ksmbd_vfs_kern_path(work, new_name,
						 LOOKUP_NO_SYMLINKS,
						 &target_path, 1)) {
				struct ksmbd_inode *target_ci;
				struct ksmbd_file *target_fp;

				target_ci = ksmbd_inode_lookup_lock(
						target_path.dentry);
				if (target_ci) {
					smb_break_target_handle_lease(
						work, target_ci);
					ksmbd_inode_put(target_ci);
				}

				target_fp = ksmbd_lookup_fd_inode(
						target_path.dentry);
				if (target_fp) {
					ksmbd_fd_put(work, target_fp);
					path_put(&target_path);
					rc = -EACCES;
					goto out;
				}
				path_put(&target_path);
			}
		}

		rc = ksmbd_vfs_rename(work, &fp->filp->f_path, new_name,
				      flags);
	} else {
		rc = ksmbd_vfs_rename(work, &fp->filp->f_path, new_name,
				      flags);
	}
out:
	kfree(new_name);
	return rc;
}
#else
static int smb2_rename(struct ksmbd_work *work,
		       struct ksmbd_file *fp,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		       struct mnt_idmap *idmap,
#else
		       struct user_namespace *user_ns,
#endif
		       struct smb2_file_rename_info *file_info,
		       struct nls_table *local_nls)
{
	struct ksmbd_share_config *share = fp->tcon->share_conf;
	char *new_name = NULL, *abs_oldname = NULL, *old_name = NULL;
	char *pathname = NULL;
	struct path path;
	bool file_present = true;
	bool same_name = false;
	int rc;

	ksmbd_debug(SMB, "setting FILE_RENAME_INFO\n");
	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);
	if (!pathname)
		return -ENOMEM;

	abs_oldname = file_path(fp->filp, pathname, PATH_MAX);
	if (IS_ERR(abs_oldname)) {
		rc = -EINVAL;
		goto out;
	}
	old_name = strrchr(abs_oldname, '/');
	if (old_name && old_name[1] != '\0') {
		old_name++;
	} else {
		ksmbd_debug(SMB, "can't get last component in path %s\n",
			    abs_oldname);
		rc = -ENOENT;
		goto out;
	}

	new_name = smb2_get_name(file_info->FileName,
				 le32_to_cpu(file_info->FileNameLength),
				 local_nls);
	if (IS_ERR(new_name)) {
		rc = PTR_ERR(new_name);
		goto out;
	}

	/*
	 * G.7: If RootDirectory is non-zero, look up the root FD and
	 * prepend its share-relative path to new_name.
	 */
	if (file_info->RootDirectory) {
		struct ksmbd_file *root_fp;
		char *root_path, *combined;

		root_fp = ksmbd_lookup_fd_fast(work, file_info->RootDirectory);
		if (!root_fp) {
			rc = -ENOENT;
			goto out;
		}
		root_path = convert_to_nt_pathname(share,
						   &root_fp->filp->f_path);
		ksmbd_fd_put(work, root_fp);
		if (IS_ERR(root_path)) {
			rc = PTR_ERR(root_path);
			goto out;
		}
		if (new_name[0] == '/' || new_name[0] == '\\')
			combined = kasprintf(KSMBD_DEFAULT_GFP, "%s%s",
					     root_path, new_name);
		else
			combined = kasprintf(KSMBD_DEFAULT_GFP, "%s/%s",
					     root_path, new_name);
		kfree(root_path);
		kfree(new_name);
		if (!combined) {
			new_name = NULL;
			rc = -ENOMEM;
			goto out;
		}
		new_name = combined;
		ksmbd_debug(SMB, "RootDirectory resolved new name: %s\n",
			    new_name);
	}

	if (fp->is_posix_ctxt == false && strchr(new_name, ':')) {
		int s_type;
		char *xattr_stream_name, *stream_name = NULL;
		size_t xattr_stream_size;
		int len;

		rc = parse_stream_name(new_name, &stream_name, &s_type);
		if (rc < 0) {
			/*
			 * parse_stream_name returns -ENOENT for "::$DATA"
			 * (the default data stream).  Per MS-FSA 2.1.5.14.11,
			 * renaming a named stream to ::$DATA means removing
			 * the named stream (promoting its data to the default
			 * stream is not supported for xattr-backed streams,
			 * so we just delete the source xattr).
			 */
			if (rc == -ENOENT && !stream_name &&
			    s_type == DATA_STREAM && ksmbd_stream_fd(fp)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
				rc = ksmbd_vfs_remove_xattr(
					idmap,
#else
				rc = ksmbd_vfs_remove_xattr(
					user_ns,
#endif
					&fp->filp->f_path,
					fp->stream.name, true);
				if (rc)
					pr_err("rename to default stream: remove xattr failed %d\n",
					       rc);
				else
					rc = 0;
			}
			goto out;
		}

		len = strlen(new_name);
		if (len > 0 && new_name[len - 1] != '/') {
			pr_err("not allow base filename in rename\n");
			rc = -ESHARE;
			goto out;
		}

		rc = ksmbd_vfs_xattr_stream_name(stream_name,
						 &xattr_stream_name,
						 &xattr_stream_size,
						 s_type);
		if (rc)
			goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		rc = ksmbd_vfs_setxattr(idmap,
#else
		rc = ksmbd_vfs_setxattr(user_ns,
#endif
					&fp->filp->f_path,
					xattr_stream_name,
					NULL, 0, 0, true);
		if (rc < 0) {
			pr_err("failed to store stream name in xattr: %d\n",
			       rc);
			rc = -EINVAL;
			goto out;
		}

		goto out;
	}

	ksmbd_debug(SMB, "new name %s\n", new_name);
	rc = ksmbd_vfs_kern_path(work, new_name, LOOKUP_NO_SYMLINKS, &path, 1);
	if (rc) {
		if (rc != -ENOENT)
			goto out;
		file_present = false;
	} else {
		/*
		 * Save the name comparison result before path_put()
		 * releases the dentry reference.
		 */
		same_name = !strcmp(old_name,
				    path.dentry->d_name.name);
		path_put(&path);
	}

	if (ksmbd_share_veto_filename(share, new_name)) {
		rc = -ENOENT;
		ksmbd_debug(SMB, "Can't rename vetoed file: %s\n", new_name);
		goto out;
	}

	/*
	 * POSIX rename semantics: always allow atomic replace of the
	 * target, even if it is currently open.
	 */
	if (file_info->ReplaceIfExists || fp->is_posix_ctxt) {
		if (file_present) {
			/*
			 * Break Handle lease on the target file before
			 * attempting to remove it, so the holder gets a
			 * chance to close.  If the holder keeps the file
			 * open the rename must fail with ACCESS_DENIED.
			 */
			struct path target_path;

			rc = ksmbd_vfs_kern_path(work, new_name,
						 LOOKUP_NO_SYMLINKS,
						 &target_path, 1);
			if (!rc) {
				struct ksmbd_inode *target_ci;

				target_ci = ksmbd_inode_lookup_lock(
						target_path.dentry);
				if (target_ci) {
					smb_break_target_handle_lease(
						work, target_ci);
					ksmbd_inode_put(target_ci);
				}

				/*
				 * After breaking the lease, check if
				 * the target still has open handles.
				 * If so, the rename must fail — Windows
				 * does not allow replacing an open file.
				 */
				if (!fp->is_posix_ctxt) {
					struct ksmbd_file *target_fp;

					target_fp = ksmbd_lookup_fd_inode(
							target_path.dentry);
					if (target_fp) {
						ksmbd_fd_put(work, target_fp);
						path_put(&target_path);
						rc = -EACCES;
						ksmbd_debug(SMB,
							    "rename target %s is still open\n",
							    new_name);
						goto out;
					}
				}
				path_put(&target_path);
			}

			rc = ksmbd_vfs_remove_file(work, new_name);
			if (rc) {
				if (rc != -ENOTEMPTY)
					rc = -EINVAL;
				ksmbd_debug(SMB, "cannot delete %s, rc %d\n",
					    new_name, rc);
				goto out;
			}
		}
	} else {
		if (file_present && !same_name) {
			rc = -EEXIST;
			ksmbd_debug(SMB,
				    "cannot rename already existing file\n");
			goto out;
		}
	}

	smb_break_all_handle_lease(work, fp, true);
	/*
	 * Break the source parent directory lease before rename.
	 */
	smb_break_parent_dir_lease(fp);
	/*
	 * Break the destination parent directory lease before rename.
	 * If the destination directory has an open with DELETE_ACCESS,
	 * use Handle break with WAIT; otherwise break to NONE.
	 */
	{
		struct path dst_dir_path;
		struct dentry *src_parent;
		char *slash;

		src_parent = fp->filp->f_path.dentry->d_parent;
		slash = strrchr(new_name, '/');
		if (slash && slash != new_name) {
			*slash = '\0';
			if (!ksmbd_vfs_kern_path(work, new_name,
						 LOOKUP_NO_SYMLINKS,
						 &dst_dir_path, 1)) {
				if (dst_dir_path.dentry != src_parent) {
					struct ksmbd_file *dst_fp;
					int brk = SMB2_OPLOCK_LEVEL_NONE;

					dst_fp = ksmbd_lookup_fd_inode(
						dst_dir_path.dentry);
					if (dst_fp) {
						if (dst_fp->daccess &
						    FILE_DELETE_LE)
							brk = OPLOCK_BREAK_HANDLE_CACHING_WAIT;
						ksmbd_fd_put(work, dst_fp);
					}
					smb_break_dir_lease_by_dentry_level(
						dst_dir_path.dentry, fp,
						brk);
				}
				path_put(&dst_dir_path);
			}
			*slash = '/';
		} else if (slash == new_name) {
			/* Destination is in share root */
			struct dentry *root =
				fp->filp->f_path.mnt->mnt_root;
			if (root != src_parent) {
				struct ksmbd_file *dst_fp;
				int brk = SMB2_OPLOCK_LEVEL_NONE;

				dst_fp = ksmbd_lookup_fd_inode(root);
				if (dst_fp) {
					if (dst_fp->daccess & FILE_DELETE_LE)
						brk = OPLOCK_BREAK_HANDLE_CACHING_WAIT;
					ksmbd_fd_put(work, dst_fp);
				}
				smb_break_dir_lease_by_dentry_level(root, fp,
								    brk);
			}
		}
	}
	rc = ksmbd_vfs_fp_rename(work, fp, new_name);
out:
	kfree(pathname);
	if (!IS_ERR(new_name))
		kfree(new_name);
	return rc;
}
#endif

static int smb2_create_link(struct ksmbd_work *work,
			    struct ksmbd_share_config *share,
			    struct smb2_file_link_info *file_info,
			    unsigned int buf_len, struct file *filp,
			    struct nls_table *local_nls,
			    struct ksmbd_file *src_fp)
{
	char *link_name = NULL, *target_name = NULL, *pathname = NULL;
	struct path path;
	int rc;

	if (buf_len < (u64)sizeof(struct smb2_file_link_info) +
			le32_to_cpu(file_info->FileNameLength))
		return -EINVAL;

	ksmbd_debug(SMB, "setting FILE_LINK_INFORMATION\n");
	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);
	if (!pathname)
		return -ENOMEM;

	link_name = smb2_get_name(file_info->FileName,
				  le32_to_cpu(file_info->FileNameLength),
				  local_nls);
	if (IS_ERR(link_name) || S_ISDIR(file_inode(filp)->i_mode)) {
		rc = -EINVAL;
		goto out;
	}

	ksmbd_debug(SMB, "link name is %s\n", link_name);
	target_name = file_path(filp, pathname, PATH_MAX);
	if (IS_ERR(target_name)) {
		rc = -EINVAL;
		goto out;
	}

	ksmbd_debug(SMB, "target name is %s\n", target_name);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	rc = ksmbd_vfs_kern_path_locked(work, link_name, LOOKUP_NO_SYMLINKS,
					&path, 0);
#else
	rc = ksmbd_vfs_kern_path(work, link_name, LOOKUP_NO_SYMLINKS, &path, 0);
#endif
	if (rc) {
		if (rc != -ENOENT)
			goto out;
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
		path_put(&path);
#endif
		if (file_info->ReplaceIfExists) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
			rc = ksmbd_vfs_remove_file(work, &path);
#else
			rc = ksmbd_vfs_remove_file(work, link_name);
#endif
			if (rc) {
				rc = -EINVAL;
				ksmbd_debug(SMB, "cannot delete %s\n",
					    link_name);
				goto out;
			}
		} else {
			rc = -EEXIST;
			ksmbd_debug(SMB, "link already exists\n");
			goto out;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
		ksmbd_vfs_kern_path_unlock(&path);
#endif
	}
	/*
	 * Break the destination parent directory lease before creating
	 * the hard link.  A new directory entry is being added.
	 */
	{
		struct path dst_dir_path;
		char *slash;
		char *link_name_copy;

		link_name_copy = kstrdup(link_name, KSMBD_DEFAULT_GFP);
		if (link_name_copy) {
			slash = strrchr(link_name_copy, '/');
			if (slash && slash != link_name_copy) {
				*slash = '\0';
				if (!ksmbd_vfs_kern_path(work, link_name_copy,
							 LOOKUP_NO_SYMLINKS,
							 &dst_dir_path, 1)) {
					smb_break_dir_lease_by_dentry(
						dst_dir_path.dentry, src_fp);
					path_put(&dst_dir_path);
				}
			}
			kfree(link_name_copy);
		}
	}

	rc = ksmbd_vfs_link(work, target_name, link_name);
	if (rc)
		rc = -EINVAL;
out:

	if (!IS_ERR(link_name))
		kfree(link_name);
	kfree(pathname);
	return rc;
}

static int set_file_basic_info(struct ksmbd_file *fp,
			       struct smb2_file_basic_info *file_info,
			       struct ksmbd_share_config *share)
{
	struct iattr attrs;
	struct file *filp;
	struct inode *inode;
	struct timespec64 saved_ctime;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap;
#else
	struct user_namespace *user_ns;
#endif
	int rc = 0;

	if (!(fp->daccess & FILE_WRITE_ATTRIBUTES_LE))
		return -EACCES;

	attrs.ia_valid = 0;
	filp = fp->filp;
	inode = file_inode(filp);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	idmap = file_mnt_idmap(filp);
#else
	user_ns = file_mnt_user_ns(filp);
#endif

	/*
	 * Save the current ctime before any operations that may
	 * implicitly update it (xattr writes, notify_change, etc.).
	 * SMB semantics: ChangeTime=0 means "don't change", so we
	 * must restore the original ctime if the client didn't
	 * provide an explicit ChangeTime value.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	saved_ctime = inode_get_ctime(inode);
#else
	saved_ctime = inode->i_ctime;
#endif

	/*
	 * MS-FSA §2.1.4.16: CreationTime == 0xFFFFFFFFFFFFFFFF means "no change".
	 * CreationTime == 0 also means "no change" (preserve existing).
	 */
	if (file_info->CreationTime &&
	    file_info->CreationTime != cpu_to_le64(0xFFFFFFFFFFFFFFFFULL))
		fp->create_time = le64_to_cpu(file_info->CreationTime);

	if (file_info->LastAccessTime &&
	    file_info->LastAccessTime != cpu_to_le64(0xFFFFFFFFFFFFFFFFULL)) {
		attrs.ia_atime = ksmbd_NTtimeToUnix(file_info->LastAccessTime);
		attrs.ia_valid |= (ATTR_ATIME | ATTR_ATIME_SET);
	}

	if (file_info->LastWriteTime &&
	    file_info->LastWriteTime != cpu_to_le64(0xFFFFFFFFFFFFFFFFULL)) {
		attrs.ia_mtime = ksmbd_NTtimeToUnix(file_info->LastWriteTime);
		attrs.ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET);
	}

	if (file_info->Attributes) {
		if (!S_ISDIR(inode->i_mode) &&
		    file_info->Attributes & ATTR_DIRECTORY_LE) {
			pr_err("can't change a file to a directory\n");
			return -EINVAL;
		}

		if (S_ISDIR(inode->i_mode) &&
		    file_info->Attributes & ATTR_TEMPORARY_LE) {
			pr_err("can't set temporary attribute on a directory\n");
			return -EINVAL;
		}

		if (!(S_ISDIR(inode->i_mode) && file_info->Attributes == ATTR_NORMAL_LE))
			fp->f_ci->m_fattr = file_info->Attributes |
				(fp->f_ci->m_fattr & ATTR_DIRECTORY_LE);
	}

	if (test_share_config_flag(share, KSMBD_SHARE_FLAG_STORE_DOS_ATTRS) &&
	    (file_info->CreationTime || file_info->Attributes)) {
		struct xattr_dos_attrib da = {0};

		da.version = 4;
		da.itime = fp->itime;
		da.create_time = fp->create_time;
		da.attr = le32_to_cpu(fp->f_ci->m_fattr);
		da.flags = XATTR_DOSINFO_ATTRIB | XATTR_DOSINFO_CREATE_TIME |
			XATTR_DOSINFO_ITIME;

		rc = compat_ksmbd_vfs_set_dos_attrib_xattr(&filp->f_path, &da,
				true);
		if (rc)
			ksmbd_debug(SMB,
				    "failed to restore file attribute in EA\n");
		rc = 0;
	}

	if (attrs.ia_valid) {
		struct dentry *dentry = filp->f_path.dentry;
		struct inode *inode = d_inode(dentry);

		if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
			return -EACCES;

		inode_lock(inode);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		rc = notify_change(idmap, dentry, &attrs, NULL);
#else
		rc = notify_change(user_ns, dentry, &attrs, NULL);
#endif
#else
		rc = notify_change(dentry, &attrs, NULL);
#endif
		inode_unlock(inode);
		if (rc)
			return -EINVAL;
	}

	/*
	 * Apply ChangeTime after all operations that may implicitly
	 * update ctime (notify_change, xattr writes, etc.).
	 * If the client specified an explicit ChangeTime, use it.
	 * If ChangeTime is zero ("don't change"), restore the ctime
	 * we saved before any modifications were made.
	 */
	if (file_info->ChangeTime) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
		inode_set_ctime_to_ts(inode,
				ksmbd_NTtimeToUnix(file_info->ChangeTime));
#else
		inode->i_ctime = ksmbd_NTtimeToUnix(file_info->ChangeTime);
#endif
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
		inode_set_ctime_to_ts(inode, saved_ctime);
#else
		inode->i_ctime = saved_ctime;
#endif
	}

	return rc;
}

static int set_file_allocation_info(struct ksmbd_work *work,
				    struct ksmbd_file *fp,
				    struct smb2_file_alloc_info *file_alloc_info)
{
	/*
	 * Allocation size handling works with both store-dos-attributes
	 * enabled and disabled.  The VFS fallocate/truncate path below
	 * operates on the actual file regardless of DOS attribute storage.
	 */

	loff_t alloc_blks;
	u64 cur_alloc;
	struct inode *inode;
	struct kstat stat;
	int rc;

	if (!(fp->daccess & FILE_WRITE_DATA_LE))
		return -EACCES;

	if (ksmbd_stream_fd(fp) == true)
		return 0;

	rc = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS | STATX_BTIME,
			 AT_STATX_SYNC_AS_STAT);
	if (rc)
		return rc;

	{
		u64 alloc_sz = le64_to_cpu(file_alloc_info->AllocationSize);
		u64 alloc_rounded;

		/* C-03: clamp to MAX_LFS_FILESIZE to avoid loff_t shift overflow */
		if (alloc_sz > MAX_LFS_FILESIZE)
			alloc_sz = MAX_LFS_FILESIZE;
		if (check_add_overflow(alloc_sz, (u64)511, &alloc_rounded)) {
			rc = -EINVAL;
			goto out;
		}
		alloc_blks = alloc_rounded >> 9;
	}
	inode = file_inode(fp->filp);

	/*
	 * Use the cached allocation size (data-only) for comparison
	 * instead of stat.blocks, which on ext4 may include external
	 * xattr blocks (e.g., security.NTACL) that inflate the count.
	 */
	cur_alloc = ksmbd_alloc_size(fp, &stat);

	if ((loff_t)(cur_alloc >> 9) < alloc_blks) {
		smb_break_all_levII_oplock(work, fp, 1);
		rc = vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0,
				   (loff_t)alloc_blks << 9);
		if (rc && rc != -EOPNOTSUPP) {
			pr_err("vfs_fallocate is failed : %d\n", rc);
			return rc;
		}
	} else if ((loff_t)(cur_alloc >> 9) > alloc_blks) {
		loff_t size;

		/*
		 * Allocation size could be smaller than original one
		 * which means allocated blocks in file should be
		 * deallocated. use truncate to cut out it, but inode
		 * size is also updated with truncate offset.
		 * inode size is retained by backup inode size.
		 */
		size = i_size_read(inode);
		rc = ksmbd_vfs_truncate(work, fp, alloc_blks * 512);
		if (rc) {
			pr_err("truncate failed!, err %d\n", rc);
			return rc;
		}
		if (size < alloc_blks * 512)
			i_size_write(inode, size);
	}

	/* Cache the requested allocation size for accurate reporting */
	if (fp->f_ci)
		fp->f_ci->m_cached_alloc = (loff_t)alloc_blks << 9;
	return 0;
out:
	return rc;
}

static int set_end_of_file_info(struct ksmbd_work *work, struct ksmbd_file *fp,
				struct smb2_file_eof_info *file_eof_info)
{
	loff_t newsize;
	struct inode *inode;
	int rc;

	if (!(fp->daccess & FILE_WRITE_DATA_LE))
		return -EACCES;

	newsize = le64_to_cpu(file_eof_info->EndOfFile);
	inode = file_inode(fp->filp);

	/*
	 * If FILE_END_OF_FILE_INFORMATION of set_info_file is called
	 * on FAT32 shared device, truncate execution time is too long
	 * and network error could cause from windows client. because
	 * truncate of some filesystem like FAT32 fill zero data in
	 * truncated range.
	 */
	if (inode->i_sb->s_magic != MSDOS_SUPER_MAGIC &&
	    ksmbd_stream_fd(fp) == false) {
		ksmbd_debug(SMB, "truncated to newsize %lld\n", newsize);
		rc = ksmbd_vfs_truncate(work, fp, newsize);
		if (rc) {
			ksmbd_debug(SMB, "truncate failed!, err %d\n", rc);
			if (rc != -EAGAIN)
				rc = -EBADF;
			return rc;
		}
		/* Invalidate cached allocation; data size changed */
		if (fp->f_ci)
			fp->f_ci->m_cached_alloc = -1;
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static int set_rename_info(struct ksmbd_work *work, struct ksmbd_file *fp,
			   struct smb2_file_rename_info *rename_info,
			   unsigned int buf_len)
{
	struct ksmbd_session *sess = work->sess;
	struct dentry *parent;
	struct path parent_path;
	__le32 daccess;
	int rc;

	if (!sess->user)
		return -EINVAL;
	/*
	 * Do NOT reject guest users here.  On guest-ok shares (guest ok = yes,
	 * read only = no), guests must be able to rename just like any other
	 * user.  The correct access control already happens via:
	 *   1. KSMBD_TREE_CONN_FLAG_WRITABLE check in smb2_set_info()
	 *   2. fp->daccess check below (needs FILE_DELETE_LE)
	 *   3. NTACL DACL check via smb_check_perm_dacl (if an ACL exists)
	 */

	daccess = FILE_DELETE_LE;
	rc = smb_check_perm_dacl(work->conn, &fp->filp->f_path,
				 &daccess, sess->user->uid);
	if (rc)
		return rc;

	parent = dget_parent(fp->filp->f_path.dentry);
	parent_path.mnt = fp->filp->f_path.mnt;
	parent_path.dentry = parent;
	daccess = FILE_DELETE_CHILD_LE;
	rc = smb_check_perm_dacl(work->conn, &parent_path,
				 &daccess, sess->user->uid);
	dput(parent);
	if (rc)
		return rc;

	if (!(fp->daccess & FILE_DELETE_LE)) {
		pr_err("no right to delete : 0x%x\n", fp->daccess);
		return -EACCES;
	}

	if (buf_len < (u64)sizeof(struct smb2_file_rename_info) +
			le32_to_cpu(rename_info->FileNameLength))
		return -EINVAL;

	if (!le32_to_cpu(rename_info->FileNameLength))
		return -EINVAL;

	/*
	 * MS-SMB2 §3.3.5.21.1: Check that all other open handles on the
	 * file being renamed have FILE_SHARE_DELETE in their share access.
	 * If not, the rename must fail with STATUS_SHARING_VIOLATION.
	 */
	if (fp->f_ci) {
		struct ksmbd_file *other_fp;

		down_read(&fp->f_ci->m_lock);
		list_for_each_entry(other_fp, &fp->f_ci->m_fp_list, node) {
			if (other_fp == fp)
				continue;
			if (other_fp->attrib_only)
				continue;
			if (!(other_fp->saccess & FILE_SHARE_DELETE_LE)) {
				up_read(&fp->f_ci->m_lock);
				return -ESHARE;
			}
		}
		up_read(&fp->f_ci->m_lock);
	}

	rc = smb2_rename(work, fp, rename_info, work->conn->local_nls);
	/*
	 * On Windows, renaming a file causes FILE_NOTIFY_CHANGE_ATTRIBUTES
	 * because the file's ctime is updated by the rename.  Replicate this
	 * by re-writing the DOS attribute xattr at the new path; vfs_setxattr
	 * fires fsnotify_xattr() → FS_ATTRIB, which is mapped to MODIFIED
	 * and completes any CHANGE_NOTIFY watching for ATTRIBUTES changes.
	 * Skip this for alternate-data-stream renames (their xattr write is
	 * already done inside smb2_rename).
	 */
	if (!rc && fp->f_ci && !ksmbd_stream_fd(fp) &&
	    test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_STORE_DOS_ATTRS)) {
		struct xattr_dos_attrib da = {0};

		da.version = 4;
		da.attr = le32_to_cpu(fp->f_ci->m_fattr);
		da.itime = da.create_time = fp->create_time;
		da.flags = XATTR_DOSINFO_ATTRIB | XATTR_DOSINFO_CREATE_TIME |
			   XATTR_DOSINFO_ITIME;
		compat_ksmbd_vfs_set_dos_attrib_xattr(&fp->filp->f_path,
						      &da, true);
	}
	return rc;
}
#else
static int set_rename_info(struct ksmbd_work *work, struct ksmbd_file *fp,
			   struct smb2_file_rename_info *rename_info,
			   unsigned int buf_len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap;
#else
	struct user_namespace *user_ns;
#endif
	struct ksmbd_session *sess = work->sess;
	struct ksmbd_file *parent_fp;
	struct dentry *parent;
	struct path parent_path;
	struct dentry *dentry = fp->filp->f_path.dentry;
	__le32 daccess;
	int ret;

	if (!sess->user)
		return -EINVAL;
	/* guest check removed — see comment in >= 6.4.0 variant above */

	daccess = FILE_DELETE_LE;
	ret = smb_check_perm_dacl(work->conn, &fp->filp->f_path,
				  &daccess, sess->user->uid);
	if (ret)
		return ret;

	parent = dget_parent(dentry);
	parent_path.mnt = fp->filp->f_path.mnt;
	parent_path.dentry = parent;
	daccess = FILE_DELETE_CHILD_LE;
	ret = smb_check_perm_dacl(work->conn, &parent_path,
				  &daccess, sess->user->uid);
	dput(parent);
	if (ret)
		return ret;

	if (!(fp->daccess & FILE_DELETE_LE)) {
		pr_err("no right to delete : 0x%x\n", fp->daccess);
		return -EACCES;
	}

	if (buf_len < (u64)sizeof(struct smb2_file_rename_info) +
			le32_to_cpu(rename_info->FileNameLength))
		return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	idmap = file_mnt_idmap(fp->filp);
#else
	user_ns = file_mnt_user_ns(fp->filp);
#endif
	if (ksmbd_stream_fd(fp))
		goto next;

	parent = dget_parent(dentry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = ksmbd_vfs_lock_parent(idmap, parent, dentry);
#else
	ret = ksmbd_vfs_lock_parent(user_ns, parent, dentry);
#endif
	if (ret) {
		dput(parent);
		return ret;
	}

	parent_fp = ksmbd_lookup_fd_inode(parent);
	inode_unlock(d_inode(parent));
	dput(parent);

	if (parent_fp) {
		if (parent_fp->daccess & FILE_DELETE_LE) {
			pr_err("parent dir is opened with delete access\n");
			ksmbd_fd_put(work, parent_fp);
			return -ESHARE;
		}
		ksmbd_fd_put(work, parent_fp);
	}
next:
	/*
	 * MS-SMB2 §3.3.5.21.1: Check that all other open handles on the
	 * file being renamed have FILE_SHARE_DELETE in their share access.
	 * If not, the rename must fail with STATUS_SHARING_VIOLATION.
	 */
	if (fp->f_ci) {
		struct ksmbd_file *other_fp;

		down_read(&fp->f_ci->m_lock);
		list_for_each_entry(other_fp, &fp->f_ci->m_fp_list, node) {
			if (other_fp == fp)
				continue;
			if (other_fp->attrib_only)
				continue;
			if (!(other_fp->saccess & FILE_SHARE_DELETE_LE)) {
				up_read(&fp->f_ci->m_lock);
				return -ESHARE;
			}
		}
		up_read(&fp->f_ci->m_lock);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = smb2_rename(work, fp, idmap, rename_info,
#else
	ret = smb2_rename(work, fp, user_ns, rename_info,
#endif
			  work->conn->local_nls);
	/*
	 * On Windows, renaming a file causes FILE_NOTIFY_CHANGE_ATTRIBUTES
	 * because the file's ctime is updated by the rename.  Replicate this
	 * by re-writing the DOS attribute xattr at the new path; vfs_setxattr
	 * fires fsnotify_xattr() → FS_ATTRIB, which is mapped to MODIFIED
	 * and completes any CHANGE_NOTIFY watching for ATTRIBUTES changes.
	 * Skip this for alternate-data-stream renames (their xattr write is
	 * already done inside smb2_rename).
	 */
	if (!ret && fp->f_ci && !ksmbd_stream_fd(fp) &&
	    test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_STORE_DOS_ATTRS)) {
		struct xattr_dos_attrib da = {0};

		da.version = 4;
		da.attr = le32_to_cpu(fp->f_ci->m_fattr);
		da.itime = da.create_time = fp->create_time;
		da.flags = XATTR_DOSINFO_ATTRIB | XATTR_DOSINFO_CREATE_TIME |
			   XATTR_DOSINFO_ITIME;
		compat_ksmbd_vfs_set_dos_attrib_xattr(&fp->filp->f_path,
						      &da, true);
	}
	return ret;
}
#endif

static int set_file_disposition_info(struct ksmbd_work *work,
				     struct ksmbd_file *fp,
				     struct smb2_file_disposition_info *file_info)
{
	struct inode *inode;

	if (!(fp->daccess & FILE_DELETE_LE)) {
		pr_err("no right to delete : 0x%x\n", fp->daccess);
		return -EACCES;
	}

	inode = file_inode(fp->filp);
	if (file_info->DeletePending) {
		if (fp->f_ci->m_fattr & ATTR_READONLY_LE) {
			ksmbd_debug(SMB,
				    "delete disposition on read-only file\n");
			return -EROFS;
		}
		if (S_ISDIR(inode->i_mode) &&
		    ksmbd_vfs_empty_dir(fp) == -ENOTEMPTY)
			return -EBUSY;
		smb_break_all_handle_lease(work, fp, false);
		ksmbd_set_inode_pending_delete(fp);
		/*
		 * MS-SMB2 §3.3.5.9.6: immediately complete any pending
		 * CHANGE_NOTIFY watches on this directory with
		 * STATUS_DELETE_PENDING now that the delete is requested.
		 */
		ksmbd_notify_complete_delete_pending(fp->f_ci);
	} else {
		ksmbd_clear_inode_pending_delete(fp);
	}
	return 0;
}

#define FILE_DISPOSITION_DELETE			0x00000001
#define FILE_DISPOSITION_POSIX_SEMANTICS	0x00000002
#define FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK 0x00000004
#define FILE_DISPOSITION_ON_CLOSE		0x00000008
#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE 0x00000010

struct smb2_file_disposition_info_ex {
	__le32 Flags;
} __packed;

static int set_file_disposition_info_ex(struct ksmbd_work *work,
					struct ksmbd_file *fp,
					struct smb2_file_disposition_info_ex *file_info)
{
	struct smb2_file_disposition_info legacy = {};
	u32 flags = le32_to_cpu(file_info->Flags);
	u32 valid_flags = FILE_DISPOSITION_DELETE |
			  FILE_DISPOSITION_POSIX_SEMANTICS |
			  FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK |
			  FILE_DISPOSITION_ON_CLOSE |
			  FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
	int rc;

	if (flags & ~valid_flags)
		return -EINVAL;

	if (flags & FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE) {
		if (!(fp->daccess & FILE_WRITE_ATTRIBUTES_LE)) {
			rc = -EACCES;
			goto out;
		}
		fp->f_ci->m_fattr &= ~ATTR_READONLY_LE;
	}

	/*
	 * QS-13: FILE_DISPOSITION_POSIX_SEMANTICS — MS-FSCC §2.4.12.
	 * Immediately unlink the file from the namespace (POSIX delete
	 * semantics) instead of setting delete-on-close.  Access via
	 * existing open handles remains valid until they are all closed.
	 */
	if (flags & FILE_DISPOSITION_POSIX_SEMANTICS) {
		if (!(fp->daccess & FILE_DELETE_LE))
			return -EACCES;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
		rc = ksmbd_vfs_unlink(fp->filp);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		{
			struct dentry *dentry = fp->filp->f_path.dentry;
			struct dentry *parent = dget_parent(dentry);

			rc = ksmbd_vfs_unlink(file_mnt_idmap(fp->filp),
					      parent, dentry);
			dput(parent);
		}
#else
		{
			struct dentry *dentry = fp->filp->f_path.dentry;
			struct dentry *parent = dget_parent(dentry);

			rc = ksmbd_vfs_unlink(file_mnt_user_ns(fp->filp),
					      parent, dentry);
			dput(parent);
		}
#endif
		return rc;
	}

	legacy.DeletePending = !!(flags & FILE_DISPOSITION_DELETE);
	return set_file_disposition_info(work, fp, &legacy);
out:
	return rc;
}

#define FILE_RENAME_REPLACE_IF_EXISTS			0x00000001
#define FILE_RENAME_POSIX_SEMANTICS			0x00000002
#define FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE	0x00000004
#define FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE 0x00000008
#define FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE		0x00000010
#define FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE		0x00000020
#define FILE_RENAME_IGNORE_READONLY_ATTRIBUTE		0x00000040
#define FILE_RENAME_FORCE_RESIZE_TARGET_SR		0x00000080
#define FILE_RENAME_FORCE_RESIZE_SOURCE_SR		0x00000100

struct smb2_file_rename_info_ex {
	__le32 Flags;
	__u32 Reserved;
	__u64 RootDirectory;
	__le32 FileNameLength;
	char FileName[];
} __packed;

static int set_rename_info_ex(struct ksmbd_work *work, struct ksmbd_file *fp,
			      struct smb2_file_rename_info_ex *file_info,
			      unsigned int buf_len)
{
	struct smb2_file_rename_info *legacy;
	unsigned int name_len;
	unsigned int valid_off = offsetof(struct smb2_file_rename_info_ex, FileName);
	u32 flags = le32_to_cpu(file_info->Flags);
	u32 valid_flags = FILE_RENAME_REPLACE_IF_EXISTS |
			  FILE_RENAME_POSIX_SEMANTICS |
			  FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE |
			  FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE |
			  FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE |
			  FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE |
			  FILE_RENAME_IGNORE_READONLY_ATTRIBUTE |
			  FILE_RENAME_FORCE_RESIZE_TARGET_SR |
			  FILE_RENAME_FORCE_RESIZE_SOURCE_SR;
	size_t legacy_len;
	int rc;

	if (flags & ~valid_flags)
		return -EINVAL;

	if (buf_len < valid_off)
		return -EMSGSIZE;

	name_len = le32_to_cpu(file_info->FileNameLength);
	if (name_len > buf_len - valid_off)
		return -EINVAL;

	legacy_len = sizeof(*legacy) + name_len;
	legacy = kzalloc(legacy_len, KSMBD_DEFAULT_GFP);
	if (!legacy)
		return -ENOMEM;

	legacy->ReplaceIfExists = !!(flags & FILE_RENAME_REPLACE_IF_EXISTS);
	legacy->RootDirectory = file_info->RootDirectory;
	legacy->FileNameLength = cpu_to_le32(name_len);
	memcpy(legacy->FileName, file_info->FileName, name_len);

	rc = set_rename_info(work, fp, legacy, legacy_len);
	kfree(legacy);
	return rc;
}

VISIBLE_IF_KUNIT
int set_file_position_info(struct ksmbd_file *fp,
				  struct smb2_file_pos_info *file_info)
{
	loff_t current_byte_offset;
	unsigned long sector_size;
	struct inode *inode;

	inode = file_inode(fp->filp);
	/* H-01: validate u64 fits in loff_t before signed conversion */
	{
		u64 raw_off = le64_to_cpu(file_info->CurrentByteOffset);

		if (raw_off > (u64)LLONG_MAX) {
			pr_err("CurrentByteOffset is not valid : %llu\n", raw_off);
			return -EINVAL;
		}
		current_byte_offset = (loff_t)raw_off;
	}
	sector_size = inode->i_sb->s_blocksize;

	if (current_byte_offset < 0 ||
	    (fp->coption == FILE_NO_INTERMEDIATE_BUFFERING_LE &&
	     current_byte_offset & (sector_size - 1))) {
		pr_err("CurrentByteOffset is not valid : %llu\n",
		       current_byte_offset);
		return -EINVAL;
	}

	if (ksmbd_stream_fd(fp) == false)
		fp->filp->f_pos = current_byte_offset;
	else {
		if (current_byte_offset > XATTR_SIZE_MAX)
			current_byte_offset = XATTR_SIZE_MAX;
		fp->stream.pos = current_byte_offset;
	}
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(set_file_position_info);

VISIBLE_IF_KUNIT
int set_file_mode_info(struct ksmbd_file *fp,
			      struct smb2_file_mode_info *file_info)
{
	__le32 mode;

	mode = file_info->Mode;

	if ((mode & ~FILE_MODE_INFO_MASK) ||
	    (mode & FILE_SYNCHRONOUS_IO_ALERT_LE &&
	     mode & FILE_SYNCHRONOUS_IO_NONALERT_LE)) {
		pr_err("Mode is not valid : 0x%x\n", le32_to_cpu(mode));
		return -EINVAL;
	}

	/*
	 * FILE_SYNCHRONOUS_IO_ALERT / FILE_SYNCHRONOUS_IO_NONALERT:
	 * MS-FSCC §2.4.24 — when either flag is set, the file is in
	 * synchronous I/O mode.  Propagate O_SYNC to the underlying
	 * struct file so that subsequent writes are durable.
	 */
	if (mode & (FILE_SYNCHRONOUS_IO_ALERT_LE | FILE_SYNCHRONOUS_IO_NONALERT_LE))
		fp->filp->f_flags |= O_SYNC;

	ksmbd_vfs_set_fadvise(fp->filp, mode);
	fp->coption = mode;
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(set_file_mode_info);

static int set_file_object_id_info(struct ksmbd_file *fp,
				   const char *buffer, unsigned int buf_len)
{
	int rc;

	if (!(fp->daccess & FILE_WRITE_ATTRIBUTES_LE))
		return -EACCES;

	/*
	 * QS-24: MS-FSCC §2.4.26 — FileObjectIdInformation is 64 bytes
	 * (16-byte ObjectId + 48-byte extended data).
	 * Previous code only checked/stored 16 bytes; now store full 64.
	 */
	if (buf_len < sizeof(struct smb2_file_objectid_info))
		return -EMSGSIZE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = ksmbd_vfs_setxattr(file_mnt_idmap(fp->filp),
#else
	rc = ksmbd_vfs_setxattr(file_mnt_user_ns(fp->filp),
#endif
				&fp->filp->f_path,
				XATTR_NAME_OBJECT_ID,
				(void *)buffer,
				sizeof(struct smb2_file_objectid_info), 0, true);
	if (rc == -EOPNOTSUPP)
		return 0;
	return rc;
}

/**
 * smb2_set_info_file() - handler for smb2 set info command
 * @work:	smb work containing set info command buffer
 * @fp:		ksmbd_file pointer
 * @req:	request buffer pointer
 * @share:	ksmbd_share_config pointer
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_set_info_file(struct ksmbd_work *work, struct ksmbd_file *fp,
			      struct smb2_set_info_req *req,
			      struct ksmbd_share_config *share)
{
	unsigned int buf_len = le32_to_cpu(req->BufferLength);
	char *buffer = (char *)req + le16_to_cpu(req->BufferOffset);
	unsigned int consumed_len = 0;
	int rc;

	switch (req->FileInfoClass) {
	case FILE_BASIC_INFORMATION:
	{
		if (buf_len < sizeof(struct smb2_file_basic_info))
			return -EMSGSIZE;

		return set_file_basic_info(fp, (struct smb2_file_basic_info *)buffer, share);
	}
	case FILE_ALLOCATION_INFORMATION:
	{
		if (buf_len < sizeof(struct smb2_file_alloc_info))
			return -EMSGSIZE;

		return set_file_allocation_info(work, fp,
						(struct smb2_file_alloc_info *)buffer);
	}
	case FILE_END_OF_FILE_INFORMATION:
	{
		if (buf_len < sizeof(struct smb2_file_eof_info))
			return -EMSGSIZE;

		return set_end_of_file_info(work, fp,
					    (struct smb2_file_eof_info *)buffer);
	}
	case FILE_RENAME_INFORMATION:
	case FILE_RENAME_INFORMATION_BYPASS_ACCESS_CHECK:
	{
		if (buf_len < sizeof(struct smb2_file_rename_info))
			return -EMSGSIZE;

		return set_rename_info(work, fp,
				       (struct smb2_file_rename_info *)buffer,
				       buf_len);
	}
	case FILE_RENAME_INFORMATION_EX:
	case FILE_RENAME_INFORMATION_EX_BYPASS_ACCESS_CHECK:
	{
		if (buf_len < offsetof(struct smb2_file_rename_info_ex, FileName))
			return -EMSGSIZE;

		return set_rename_info_ex(work, fp,
					(struct smb2_file_rename_info_ex *)buffer,
					buf_len);
	}
	case FILE_LINK_INFORMATION:
	case FILE_LINK_INFORMATION_BYPASS_ACCESS_CHECK:
	{
		if (buf_len < sizeof(struct smb2_file_link_info))
			return -EMSGSIZE;

		return smb2_create_link(work, work->tcon->share_conf,
					(struct smb2_file_link_info *)buffer,
					buf_len, fp->filp,
					work->conn->local_nls, fp);
	}
	case FILE_DISPOSITION_INFORMATION:
	{
		if (buf_len < sizeof(struct smb2_file_disposition_info))
			return -EMSGSIZE;

		return set_file_disposition_info(work, fp,
						 (struct smb2_file_disposition_info *)buffer);
	}
	case FILE_DISPOSITION_INFORMATION_EX:
	{
		if (buf_len < sizeof(struct smb2_file_disposition_info_ex))
			return -EMSGSIZE;

		return set_file_disposition_info_ex(work, fp,
					(struct smb2_file_disposition_info_ex *)buffer);
	}
	case FILE_FULL_EA_INFORMATION:
	{
		if (!(fp->daccess & FILE_WRITE_EA_LE)) {
			pr_err("Not permitted to write ext  attr: 0x%x\n",
			       fp->daccess);
			return -EACCES;
		}

		if (buf_len < sizeof(struct smb2_ea_info))
			return -EMSGSIZE;

		return smb2_set_ea((struct smb2_ea_info *)buffer,
				   buf_len, &fp->filp->f_path, true);
	}
	case FILE_POSITION_INFORMATION:
	{
		if (buf_len < sizeof(struct smb2_file_pos_info))
			return -EMSGSIZE;

		return set_file_position_info(fp, (struct smb2_file_pos_info *)buffer);
	}
	case FILE_MODE_INFORMATION:
	{
		if (buf_len < sizeof(struct smb2_file_mode_info))
			return -EMSGSIZE;

		return set_file_mode_info(fp, (struct smb2_file_mode_info *)buffer);
	}
	case FILE_OBJECT_ID_INFORMATION:
		return set_file_object_id_info(fp, buffer, buf_len);
	case FILE_VALID_DATA_LENGTH_INFORMATION:
	{
		/* QSA-02: require FILE_WRITE_DATA access */
		if (!(fp->daccess & FILE_WRITE_DATA_LE))
			return -EACCES;

		if (buf_len < sizeof(struct smb2_file_valid_data_length_info))
			return -EMSGSIZE;
		/*
		 * QSA-02: Fall through to the dispatch table handler which
		 * may call fallocate to physically extend the valid data
		 * region.  If no handler is registered, ksmbd_dispatch_info
		 * returns -EOPNOTSUPP and we silently succeed (safe fallback).
		 */
		break;
	}
	}

	rc = ksmbd_dispatch_info(work, fp,
				 SMB2_O_INFO_FILE,
				 req->FileInfoClass,
				 KSMBD_INFO_SET,
				 buffer, buf_len, &consumed_len);
	if (!rc)
		return 0;

	ksmbd_debug(SMB, "FileInfoClass %d unsupported\n", req->FileInfoClass);
	return rc;
}

static int smb2_set_info_sec(struct ksmbd_file *fp, int addition_info,
			     char *buffer, int buf_len)
{
	struct smb_ntsd *pntsd = (struct smb_ntsd *)buffer;
	int rc;

	/*
	 * Enforce SMB access-mask checks on the open handle.
	 * OWNER/GROUP updates require WRITE_OWNER, DACL updates require
	 * WRITE_DAC, and SACL updates require ACCESS_SYSTEM_SECURITY.
	 */
	if (addition_info & (OWNER_SECINFO | GROUP_SECINFO)) {
		if (!(fp->daccess & FILE_WRITE_OWNER_LE))
			return -EACCES;
	}
	if (addition_info & DACL_SECINFO) {
		if (!(fp->daccess & FILE_WRITE_DAC_LE))
			return -EACCES;
	}
	if (addition_info & SACL_SECINFO) {
		if (!(fp->daccess & FILE_ACCESS_SYSTEM_SECURITY_LE))
			return -EACCES;
	}

	/*
	 * Validate addition_info before performing security descriptor
	 * operations.  Only recognised flags should be accepted.
	 */
	if (addition_info & ~(OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO |
			      SACL_SECINFO | LABEL_SECINFO |
			      ATTRIBUTE_SECINFO | SCOPE_SECINFO |
			      BACKUP_SECINFO |
			      PROTECTED_DACL_SECINFO |
			      UNPROTECTED_DACL_SECINFO |
			      PROTECTED_SACL_SECINFO |
			      UNPROTECTED_SACL_SECINFO))
		return -EINVAL;

	rc = set_info_sec(fp->conn, fp->tcon, &fp->filp->f_path, pntsd,
			  buf_len, false, true);
	if (rc)
		return rc;

	/*
	 * QS-08: When LABEL_SECINFO is set, persist the SACL (integrity label)
	 * to a dedicated xattr so it can be retrieved later.
	 */
	if (addition_info & LABEL_SECINFO) {
		__u32 sacl_off = le32_to_cpu(pntsd->sacloffset);

		if (sacl_off && sacl_off < (u32)buf_len) {
			struct smb_acl *sacl = (struct smb_acl *)
					       ((char *)pntsd + sacl_off);
			__u32 sacl_size = le16_to_cpu(sacl->size);

			if (sacl_off + sacl_size <= (u32)buf_len) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
				struct mnt_idmap *idmap =
					file_mnt_idmap(fp->filp);
				ksmbd_vfs_setxattr(idmap,
#else
				struct user_namespace *user_ns =
					file_mnt_user_ns(fp->filp);
				ksmbd_vfs_setxattr(user_ns,
#endif
						  &fp->filp->f_path,
						  XATTR_NAME_SD_LABEL,
						  sacl, sacl_size, 0, false);
			}
		}
	}

	/*
	 * Only grant FILE_SHARE_DELETE when the DACL was actually changed,
	 * to avoid unintended side-effects on share access from other
	 * security descriptor operations (e.g. owner/SACL-only changes).
	 */
	if (addition_info & DACL_SECINFO)
		fp->saccess |= FILE_SHARE_DELETE_LE;
	return 0;
}

/**
 * smb2_set_info() - handler for smb2 set info command handler
 * @work:	smb work containing set info request buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_set_info(struct ksmbd_work *work)
{
	struct smb2_set_info_req *req;
	struct smb2_set_info_rsp *rsp;
	struct ksmbd_file *fp = NULL;
	int rc = 0;
	unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;
	char *set_buf;
	unsigned int set_buf_len;
	unsigned int consumed_len = 0;

	ksmbd_debug(SMB, "Received smb2 set info request\n");

	if (work->next_smb2_rcv_hdr_off) {
		req = ksmbd_req_buf_next(work);
		rsp = ksmbd_resp_buf_next(work);
		if (!has_file_id(req->VolatileFileId)) {
			ksmbd_debug(SMB, "Compound request set FID = %llu\n",
				    work->compound_fid);
			id = work->compound_fid;
			pid = work->compound_pfid;
		}
	} else {
		req = smb2_get_msg(work->request_buf);
		rsp = smb2_get_msg(work->response_buf);
	}

	/*
	 * Validate that BufferOffset + BufferLength from the client
	 * does not exceed the actual request buffer, preventing
	 * out-of-bounds reads from crafted packets.
	 */
	{
		unsigned int buf_off = le16_to_cpu(req->BufferOffset);
		unsigned int buf_len = le32_to_cpu(req->BufferLength);
		unsigned int rfc_len = get_rfc1002_len(work->request_buf);
		unsigned int req_len;

		/* Guard against underflow in compound requests */
		if (rfc_len < work->next_smb2_rcv_hdr_off) {
			rc = -EINVAL;
			goto err_out;
		}
		req_len = rfc_len - work->next_smb2_rcv_hdr_off;

		if (buf_off < offsetof(struct smb2_set_info_req, Buffer) ||
		    buf_off > req_len ||
		    buf_len > req_len - buf_off) {
			rc = -EINVAL;
			goto err_out;
		}
	}

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		ksmbd_debug(SMB, "User does not have write permission\n");
		pr_err("User does not have write permission\n");
		rc = -EACCES;
		goto err_out;
	}

	if (!has_file_id(id)) {
		id = req->VolatileFileId;
		pid = req->PersistentFileId;
	}

	if (test_share_config_flag(work->tcon->share_conf, KSMBD_SHARE_FLAG_PIPE) &&
	    req->InfoType == SMB2_O_INFO_FILE &&
	    smb2_is_pipe_set_info_class(req->FileInfoClass)) {
		rc = smb2_set_info_file_pipe(work, req);
		if (rc < 0)
			goto err_out;

		rsp->StructureSize = cpu_to_le16(2);
		rc = ksmbd_iov_pin_rsp(work, (void *)rsp,
				       sizeof(struct smb2_set_info_rsp));
		if (rc)
			goto err_out;
		return 0;
	}

	fp = ksmbd_lookup_fd_slow(work, id, pid);
	if (!fp) {
		ksmbd_debug(SMB, "Invalid id for close: %u\n", id);
		rc = -ENOENT;
		goto err_out;
	}

	/* MS-SMB2 §3.3.5.2.10: validate ChannelSequence */
	rc = smb2_check_channel_sequence(work, fp);
	if (rc) {
		rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;
		goto err_out;
	}

	set_buf = (char *)req + le16_to_cpu(req->BufferOffset);
	set_buf_len = le32_to_cpu(req->BufferLength);

	switch (req->InfoType) {
	case SMB2_O_INFO_FILE:
		ksmbd_debug(SMB, "GOT SMB2_O_INFO_FILE\n");
		if (ksmbd_override_fsids(work)) {
			rc = -ENOMEM;
			goto err_out;
		}
		rc = smb2_set_info_file(work, fp, req, work->tcon->share_conf);
		ksmbd_revert_fsids(work);
		break;
	case SMB2_O_INFO_FILESYSTEM:
		ksmbd_debug(SMB, "GOT SMB2_O_INFO_FILESYSTEM\n");
		rc = ksmbd_dispatch_info(work, fp,
					 SMB2_O_INFO_FILESYSTEM,
					 req->FileInfoClass,
					 KSMBD_INFO_SET,
					 set_buf, set_buf_len,
					 &consumed_len);
		if (!rc && consumed_len > set_buf_len)
			rc = -EINVAL;
		break;
	case SMB2_O_INFO_SECURITY:
		ksmbd_debug(SMB, "GOT SMB2_O_INFO_SECURITY\n");
		rc = smb2_set_info_sec(fp,
				       le32_to_cpu(req->AdditionalInformation),
				       set_buf, set_buf_len);
		break;
	case SMB2_O_INFO_QUOTA:
		ksmbd_debug(SMB, "GOT SMB2_O_INFO_QUOTA\n");
		rc = ksmbd_dispatch_info(work, fp,
					 SMB2_O_INFO_QUOTA,
					 req->FileInfoClass,
					 KSMBD_INFO_SET,
					 set_buf, set_buf_len,
					 &consumed_len);
		if (!rc && consumed_len > set_buf_len)
			rc = -EINVAL;
		break;
	default:
		/* Validate InfoType range before dispatching to hooks */
		if (req->InfoType < SMB2_O_INFO_FILE ||
		    req->InfoType > SMB2_O_INFO_QUOTA) {
			rc = -EINVAL;
			break;
		}
		rc = ksmbd_dispatch_info(work, fp,
					 req->InfoType,
					 req->FileInfoClass,
					 KSMBD_INFO_SET,
					 set_buf, set_buf_len,
					 &consumed_len);
		if (!rc && consumed_len > set_buf_len)
			rc = -EINVAL;
	}

	if (rc < 0)
		goto err_out;

	/*
	 * After a successful SET_INFO on a child file, break the parent
	 * directory lease.  Per MS-SMB2 3.3.4.7, modifying a child file's
	 * attributes (timestamps, size, rename, etc.) invalidates the
	 * parent directory's cached view.
	 *
	 * Skip for:
	 * - FileDispositionInformation: DOC doesn't modify the directory yet;
	 *   the actual break happens at deletion time (smb_dirlease_break_on_delete).
	 * - FileRenameInformation: the rename handler does its own pre-rename
	 *   source break + post-rename destination break (for cross-dir renames).
	 * - FileLinkInformation: the link handler does its own break.
	 */
	if (req->InfoType == SMB2_O_INFO_FILE &&
	    req->FileInfoClass != FILE_DISPOSITION_INFORMATION &&
	    req->FileInfoClass != FILE_DISPOSITION_INFORMATION_EX &&
	    req->FileInfoClass != FILE_RENAME_INFORMATION &&
	    req->FileInfoClass != FILE_RENAME_INFORMATION_EX &&
	    req->FileInfoClass != FILE_RENAME_INFORMATION_BYPASS_ACCESS_CHECK &&
	    req->FileInfoClass != FILE_RENAME_INFORMATION_EX_BYPASS_ACCESS_CHECK &&
	    req->FileInfoClass != FILE_LINK_INFORMATION &&
	    req->FileInfoClass != FILE_LINK_INFORMATION_BYPASS_ACCESS_CHECK &&
	    !S_ISDIR(file_inode(fp->filp)->i_mode))
		smb_break_parent_dir_lease(fp);

	rsp->StructureSize = cpu_to_le16(2);
	rc = ksmbd_iov_pin_rsp(work, (void *)rsp,
			       sizeof(struct smb2_set_info_rsp));
	if (rc)
		goto err_out;
	ksmbd_fd_put(work, fp);
	return 0;

err_out:
	if (rsp->hdr.Status == 0) {
		if (rc == -EACCES || rc == -EPERM || rc == -EXDEV)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (rc == -EINVAL)
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		else if (rc == -EMSGSIZE)
			rsp->hdr.Status = STATUS_INFO_LENGTH_MISMATCH;
		else if (rc == -ESHARE)
			rsp->hdr.Status = STATUS_SHARING_VIOLATION;
		else if (rc == -ENOENT)
			rsp->hdr.Status = STATUS_OBJECT_NAME_INVALID;
		else if (rc == -EBUSY || rc == -ENOTEMPTY)
			rsp->hdr.Status = STATUS_DIRECTORY_NOT_EMPTY;
		else if (rc == -EAGAIN)
			rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;
		else if (rc == -EBADF || rc == -ESTALE)
			rsp->hdr.Status = STATUS_INVALID_HANDLE;
		else if (rc == -EROFS)
			rsp->hdr.Status = STATUS_CANNOT_DELETE;
		else if (rc == -EEXIST)
			rsp->hdr.Status = STATUS_OBJECT_NAME_COLLISION;
		else if (rc == -EOPNOTSUPP)
			rsp->hdr.Status = STATUS_INVALID_INFO_CLASS;
		else
			rsp->hdr.Status = STATUS_INVALID_INFO_CLASS;
	}
	smb2_set_err_rsp(work);
	if (fp)
		ksmbd_fd_put(work, fp);
	ksmbd_debug(SMB, "error while processing smb2 query rc = %d\n", rc);
	return rc;
}

/**
 * smb2_read_pipe() - handler for smb2 read from IPC pipe
 * @work:	smb work containing read IPC pipe command buffer
 *
 * Return:	0 on success, otherwise error
 */
