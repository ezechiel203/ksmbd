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

static int buffer_check_err(int reqOutputBufferLength,
			    struct smb2_query_info_rsp *rsp,
			    void *rsp_org)
{
	if (reqOutputBufferLength < le32_to_cpu(rsp->OutputBufferLength)) {
		pr_err_ratelimited("Invalid Buffer Size Requested\n");
		rsp->hdr.Status = STATUS_INFO_LENGTH_MISMATCH;
		*(__be32 *)rsp_org = cpu_to_be32(sizeof(struct smb2_hdr));
		return -EINVAL;
	}
	return 0;
}

static void get_standard_info_pipe(struct smb2_query_info_rsp *rsp,
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

static void get_internal_info_pipe(struct smb2_query_info_rsp *rsp, u64 num,
				   void *rsp_org)
{
	struct smb2_file_internal_info *file_info;

	file_info = (struct smb2_file_internal_info *)rsp->Buffer;

	/* any unique number */
	file_info->IndexNumber = cpu_to_le64(num | (1ULL << 63));
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_internal_info));
}

static int smb2_get_info_file_pipe(struct ksmbd_session *sess,
				   struct smb2_query_info_req *req,
				   struct smb2_query_info_rsp *rsp,
				   void *rsp_org)
{
	u64 id;
	int rc;

	/*
	 * Windows can sometime send query file info request on
	 * pipe without opening it, checking error condition here
	 */
	id = req->VolatileFileId;

	lockdep_assert_not_held(&sess->rpc_lock);

	down_read(&sess->rpc_lock);
	if (!ksmbd_session_rpc_method(sess, id)) {
		up_read(&sess->rpc_lock);
		return -ENOENT;
	}
	up_read(&sess->rpc_lock);

	ksmbd_debug(SMB, "FileInfoClass %u, FileId 0x%llx\n",
		    req->FileInfoClass, req->VolatileFileId);

	switch (req->FileInfoClass) {
	case FILE_STANDARD_INFORMATION:
		get_standard_info_pipe(rsp, rsp_org);
		rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
				      rsp, rsp_org);
		break;
	case FILE_INTERNAL_INFORMATION:
		get_internal_info_pipe(rsp, id, rsp_org);
		rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
				      rsp, rsp_org);
		break;
	default:
		ksmbd_debug(SMB, "smb2_info_file_pipe for %u not supported\n",
			    req->FileInfoClass);
		rc = -EOPNOTSUPP;
	}
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

		ea_req = (struct smb2_ea_info_req *)((char *)req +
						     le16_to_cpu(req->InputBufferOffset));
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

		ptr = eainfo->name + name_len + 1;
		buf_free_len -= (offsetof(struct smb2_ea_info, name) +
				name_len + 1);
		/* bailout if xattr can't fit in buf_free_len */
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

		/* align next xattr entry at 4 byte bundary */
		alignment_bytes = ((next_offset + 3) & ~3) - next_offset;
		if (alignment_bytes) {
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
	if (rsp_data_cnt == 0)
		rsp->hdr.Status = STATUS_NO_EAS_ON_FILE;
	rsp->OutputBufferLength = cpu_to_le32(rsp_data_cnt);
out:
	kvfree(xattr_list);
	return rc;
}

static void get_file_access_info(struct smb2_query_info_rsp *rsp,
				 struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_access_info *file_info;

	file_info = (struct smb2_file_access_info *)rsp->Buffer;
	file_info->AccessFlags = fp->daccess;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_access_info));
}

static int get_file_basic_info(struct smb2_query_info_rsp *rsp,
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

static int get_file_standard_info(struct smb2_query_info_rsp *rsp,
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
		sinfo->AllocationSize = cpu_to_le64(stat.blocks << 9);
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

static void get_file_alignment_info(struct smb2_query_info_rsp *rsp,
				    void *rsp_org)
{
	struct smb2_file_alignment_info *file_info;

	file_info = (struct smb2_file_alignment_info *)rsp->Buffer;
	file_info->AlignmentRequirement = 0;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_alignment_info));
}

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
	if (ret)
		return ret;

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
			cpu_to_le64(stat.blocks << 9);
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
	file_info->EASize = 0;
	file_info->AccessFlags = fp->daccess;
	if (ksmbd_stream_fd(fp) == false)
		file_info->CurrentByteOffset = cpu_to_le64(fp->filp->f_pos);
	else
		file_info->CurrentByteOffset = cpu_to_le64(fp->stream.pos);
	file_info->Mode = fp->coption;
	file_info->AlignmentRequirement = 0;
	conv_len = smbConvertToUTF16((__le16 *)file_info->FileName, filename,
				     PATH_MAX, conn->local_nls, 0);
	conv_len *= 2;
	file_info->FileNameLength = cpu_to_le32(conv_len);
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_all_info) + conv_len - 1);
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
	struct smb2_query_info_req *req = ksmbd_req_buf_next(work);
	int ret;

	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
			  AT_STATX_SYNC_AS_STAT);
	if (ret)
		return ret;

	file_info = (struct smb2_file_stream_info *)rsp->Buffer;

	buf_free_len =
		smb2_calc_max_out_buf_len(work, 8,
					  le32_to_cpu(req->OutputBufferLength));
	if (buf_free_len < 0)
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
		file_info->StreamSize = cpu_to_le64(stream_name_len);
		file_info->StreamAllocationSize = cpu_to_le64(stream_name_len);

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
		file_info->StreamAllocationSize = cpu_to_le64(stat.blocks << 9);
		nbytes += sizeof(struct smb2_file_stream_info) + streamlen;
	}

	/* last entry offset should be 0 */
	file_info->NextEntryOffset = 0;
	kvfree(xattr_list);

	rsp->OutputBufferLength = cpu_to_le32(nbytes);

	return 0;
}

static int get_file_internal_info(struct smb2_query_info_rsp *rsp,
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
		file_info->AllocationSize = cpu_to_le64(stat.blocks << 9);
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

static void get_file_ea_info(struct smb2_query_info_rsp *rsp, void *rsp_org)
{
	struct smb2_file_ea_info *file_info;

	file_info = (struct smb2_file_ea_info *)rsp->Buffer;
	file_info->EASize = 0;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_ea_info));
}

static void get_file_position_info(struct smb2_query_info_rsp *rsp,
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

static void get_file_mode_info(struct smb2_query_info_rsp *rsp,
			       struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_mode_info *file_info;

	file_info = (struct smb2_file_mode_info *)rsp->Buffer;
	file_info->Mode = fp->coption & FILE_MODE_INFO_MASK;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_mode_info));
}

static int get_file_compression_info(struct smb2_query_info_rsp *rsp,
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
	file_info->CompressedFileSize = cpu_to_le64(stat.blocks << 9);
	file_info->CompressionFormat = COMPRESSION_FORMAT_NONE;
	file_info->CompressionUnitShift = 0;
	file_info->ChunkShift = 0;
	file_info->ClusterShift = 0;
	memset(&file_info->Reserved[0], 0, 3);

	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_comp_info));

	return 0;
}

static int get_file_attribute_tag_info(struct smb2_query_info_rsp *rsp,
				       struct ksmbd_file *fp, void *rsp_org)
{
	struct smb2_file_attr_tag_info *file_info;

	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE)) {
		pr_err("no right to read the attributes : 0x%x\n",
		       fp->daccess);
		return -EACCES;
	}

	file_info = (struct smb2_file_attr_tag_info *)rsp->Buffer;
	file_info->FileAttributes = fp->f_ci->m_fattr;
	file_info->ReparseTag = 0;
	rsp->OutputBufferLength =
		cpu_to_le32(sizeof(struct smb2_file_attr_tag_info));
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
		file_info->AllocationSize = cpu_to_le64(stat.blocks << 9);
	} else {
		file_info->EndOfFile = cpu_to_le64(fp->stream.size);
		file_info->AllocationSize = cpu_to_le64(fp->stream.size);
	}
	file_info->HardLinks = cpu_to_le32(stat.nlink);
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
	}

	file_info->DeviceId = cpu_to_le32(stat.rdev);
	/*
	 * Sids(32) contain two sids(Domain sid(16), UNIX group sid(16)).
	 * UNIX sid(16) = revision(1) + num_subauth(1) + authority(6) +
	 *		  sub_auth(4 * 1(num_subauth)) + RID(4).
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
	unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;

	if (test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_PIPE)) {
		/* smb2 info file called for pipe */
		return smb2_get_info_file_pipe(work->sess, req, rsp,
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
		break;

	case FILE_BASIC_INFORMATION:
		rc = get_file_basic_info(rsp, fp, work->response_buf);
		break;

	case FILE_STANDARD_INFORMATION:
		rc = get_file_standard_info(rsp, fp, work->response_buf);
		break;

	case FILE_ALIGNMENT_INFORMATION:
		get_file_alignment_info(rsp, work->response_buf);
		break;

	case FILE_ALL_INFORMATION:
		rc = get_file_all_info(work, rsp, fp, work->response_buf);
		break;

	case FILE_ALTERNATE_NAME_INFORMATION:
		get_file_alternate_info(work, rsp, fp, work->response_buf);
		break;

	case FILE_STREAM_INFORMATION:
		rc = get_file_stream_info(work, rsp, fp, work->response_buf);
		break;

	case FILE_INTERNAL_INFORMATION:
		rc = get_file_internal_info(rsp, fp, work->response_buf);
		break;

	case FILE_NETWORK_OPEN_INFORMATION:
		rc = get_file_network_open_info(rsp, fp, work->response_buf);
		break;

	case FILE_EA_INFORMATION:
		get_file_ea_info(rsp, work->response_buf);
		break;

	case FILE_FULL_EA_INFORMATION:
		rc = smb2_get_ea(work, fp, req, rsp, work->response_buf);
		break;

	case FILE_POSITION_INFORMATION:
		get_file_position_info(rsp, fp, work->response_buf);
		break;

	case FILE_MODE_INFORMATION:
		get_file_mode_info(rsp, fp, work->response_buf);
		break;

	case FILE_COMPRESSION_INFORMATION:
		rc = get_file_compression_info(rsp, fp, work->response_buf);
		break;

	case FILE_ATTRIBUTE_TAG_INFORMATION:
		rc = get_file_attribute_tag_info(rsp, fp, work->response_buf);
		break;
	case SMB_FIND_FILE_POSIX_INFO:
		if (!work->tcon->posix_extensions) {
			pr_err("client doesn't negotiate with SMB3.1.1 POSIX Extensions\n");
			rc = -EOPNOTSUPP;
		} else {
			rc = find_file_posix_info(rsp, fp, work->response_buf);
		}
		break;
	default:
		ksmbd_debug(SMB, "fileinfoclass %d not supported yet\n",
			    fileinfoclass);
		rc = -EOPNOTSUPP;
	}
	if (!rc)
		rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
				      rsp, work->response_buf);
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
	int rc = 0, len;

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
					       FILE_SUPPORTS_BLOCK_REFCOUNTING);

		info->Attributes |= cpu_to_le32(server_conf.share_fake_fscaps);

		if (test_share_config_flag(work->tcon->share_conf,
		    KSMBD_SHARE_FLAG_STREAMS))
			info->Attributes |= cpu_to_le32(FILE_NAMED_STREAMS);

		info->MaxPathNameComponentLength = cpu_to_le32(stfs.f_namelen);
		len = smbConvertToUTF16((__le16 *)info->FileSystemName,
					"NTFS", PATH_MAX, conn->local_nls, 0);
		len = len * 2;
		info->FileSystemNameLen = cpu_to_le32(len);
		sz = sizeof(struct filesystem_attribute_info) + len;
		rsp->OutputBufferLength = cpu_to_le32(sz);
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
		break;
	}
	case FS_SIZE_INFORMATION:
	{
		struct filesystem_info *info;

		info = (struct filesystem_info *)(rsp->Buffer);
		info->TotalAllocationUnits = cpu_to_le64(stfs.f_blocks);
		info->FreeAllocationUnits = cpu_to_le64(stfs.f_bfree);
		info->SectorsPerAllocationUnit = cpu_to_le32(1);
		info->BytesPerSector = cpu_to_le32(stfs.f_bsize);
		rsp->OutputBufferLength = cpu_to_le32(24);
		break;
	}
	case FS_FULL_SIZE_INFORMATION:
	{
		struct smb2_fs_full_size_info *info;

		info = (struct smb2_fs_full_size_info *)(rsp->Buffer);
		info->TotalAllocationUnits = cpu_to_le64(stfs.f_blocks);
		info->CallerAvailableAllocationUnits =
					cpu_to_le64(stfs.f_bavail);
		info->ActualAvailableAllocationUnits =
					cpu_to_le64(stfs.f_bfree);
		info->SectorsPerAllocationUnit = cpu_to_le32(1);
		info->BytesPerSector = cpu_to_le32(stfs.f_bsize);
		rsp->OutputBufferLength = cpu_to_le32(32);
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

		info->extended_info.magic = cpu_to_le32(EXTENDED_INFO_MAGIC);
		info->extended_info.version = cpu_to_le32(1);
		info->extended_info.release = cpu_to_le32(1);
		info->extended_info.rel_date = 0;
		memcpy(info->extended_info.version_string, "1.1.0", strlen("1.1.0"));
		rsp->OutputBufferLength = cpu_to_le32(64);
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
		break;
	}
	case FS_CONTROL_INFORMATION:
	{
		/*
		 * TODO : The current implementation is based on
		 * test result with win7(NTFS) server. It's need to
		 * modify this to get valid Quota values
		 * from Linux kernel
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
		break;
	}
	case FS_POSIX_INFORMATION:
	{
		struct filesystem_posix_info *info;

		if (!work->tcon->posix_extensions) {
			pr_err("client doesn't negotiate with SMB3.1.1 POSIX Extensions\n");
			path_put(&path);
			return -EOPNOTSUPP;
		} else {
			info = (struct filesystem_posix_info *)(rsp->Buffer);
			info->OptimalTransferSize = cpu_to_le32(stfs.f_bsize);
			info->BlockSize = cpu_to_le32(stfs.f_bsize);
			info->TotalBlocks = cpu_to_le64(stfs.f_blocks);
			info->BlocksAvail = cpu_to_le64(stfs.f_bfree);
			info->UserBlocksAvail = cpu_to_le64(stfs.f_bavail);
			info->TotalFileNodes = cpu_to_le64(stfs.f_files);
			info->FreeFileNodes = cpu_to_le64(stfs.f_ffree);
			rsp->OutputBufferLength = cpu_to_le32(56);
		}
		break;
	}
	default:
		path_put(&path);
		return -EOPNOTSUPP;
	}
	rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),
			      rsp, work->response_buf);
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
			      SACL_SECINFO | PROTECTED_DACL_SECINFO |
			      UNPROTECTED_DACL_SECINFO |
			      PROTECTED_SACL_SECINFO |
			      UNPROTECTED_SACL_SECINFO)) {
		ksmbd_debug(SMB, "Unsupported addition info: 0x%x)\n",
		       addition_info);

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
	ksmbd_fd_put(work, fp);
	if (rc)
		return rc;

	rsp->OutputBufferLength = cpu_to_le32(secdesclen);
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
					 SMB2_O_INFO_QUOTA, 0,
					 KSMBD_INFO_GET,
					 rsp->Buffer,
					 le32_to_cpu(req->OutputBufferLength),
					 &qout_len);
		ksmbd_fd_put(work, fp);

		if (rc == -EOPNOTSUPP) {
			/* No handler registered — not supported */
			break;
		}
		if (!rc)
			rsp->OutputBufferLength = cpu_to_le32(qout_len);
		break;
	}
	default:
		ksmbd_debug(SMB, "InfoType %d not supported yet\n",
			    req->InfoType);
		rc = -EOPNOTSUPP;
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
		if (rc == -EACCES)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (rc == -ENOENT)
			rsp->hdr.Status = STATUS_FILE_CLOSED;
		else if (rc == -EIO)
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
		else if (rc == -ENOMEM)
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		else if (rc == -EOPNOTSUPP || rsp->hdr.Status == 0)
			rsp->hdr.Status = STATUS_INVALID_INFO_CLASS;
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

	if (fp->is_posix_ctxt == false && strchr(new_name, ':')) {
		int s_type;
		char *xattr_stream_name, *stream_name = NULL;
		size_t xattr_stream_size;
		int len;

		rc = parse_stream_name(new_name, &stream_name, &s_type);
		if (rc < 0)
			goto out;

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

	if (!file_info->ReplaceIfExists)
		flags = RENAME_NOREPLACE;

	rc = ksmbd_vfs_rename(work, &fp->filp->f_path, new_name, flags);
	if (!rc)
		smb_break_all_levII_oplock(work, fp, 0);
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

	if (strchr(new_name, ':')) {
		int s_type;
		char *xattr_stream_name, *stream_name = NULL;
		size_t xattr_stream_size;
		int len;

		rc = parse_stream_name(new_name, &stream_name, &s_type);
		if (rc < 0)
			goto out;

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
		path_put(&path);
	}

	if (ksmbd_share_veto_filename(share, new_name)) {
		rc = -ENOENT;
		ksmbd_debug(SMB, "Can't rename vetoed file: %s\n", new_name);
		goto out;
	}

	if (file_info->ReplaceIfExists) {
		if (file_present) {
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
		if (file_present &&
		    strncmp(old_name, path.dentry->d_name.name, strlen(old_name))) {
			rc = -EEXIST;
			ksmbd_debug(SMB,
				    "cannot rename already existing file\n");
			goto out;
		}
	}

	smb_break_all_levII_oplock(work, fp, 0);
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
			    struct nls_table *local_nls)
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

	if (file_info->CreationTime)
		fp->create_time = le64_to_cpu(file_info->CreationTime);

	if (file_info->LastAccessTime) {
		attrs.ia_atime = ksmbd_NTtimeToUnix(file_info->LastAccessTime);
		attrs.ia_valid |= (ATTR_ATIME | ATTR_ATIME_SET);
	}

	if (file_info->ChangeTime) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
		inode_set_ctime_to_ts(inode,
				ksmbd_NTtimeToUnix(file_info->ChangeTime));
#else
		inode->i_ctime = ksmbd_NTtimeToUnix(file_info->ChangeTime);
#endif
	}

	if (file_info->LastWriteTime) {
		attrs.ia_mtime = ksmbd_NTtimeToUnix(file_info->LastWriteTime);
		attrs.ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET | ATTR_CTIME);
	}

	if (file_info->Attributes) {
		if (!S_ISDIR(inode->i_mode) &&
		    file_info->Attributes & ATTR_DIRECTORY_LE) {
			pr_err("can't change a file to a directory\n");
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
	return rc;
}

static int set_file_allocation_info(struct ksmbd_work *work,
				    struct ksmbd_file *fp,
				    struct smb2_file_alloc_info *file_alloc_info)
{
	/*
	 * TODO : It's working fine only when store dos attributes
	 * is not yes. need to implement a logic which works
	 * properly with any smb.conf option
	 */

	loff_t alloc_blks;
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

	alloc_blks = (le64_to_cpu(file_alloc_info->AllocationSize) + 511) >> 9;
	inode = file_inode(fp->filp);

	if (alloc_blks > stat.blocks) {
		smb_break_all_levII_oplock(work, fp, 1);
		rc = vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0,
				   alloc_blks * 512);
		if (rc && rc != -EOPNOTSUPP) {
			pr_err("vfs_fallocate is failed : %d\n", rc);
			return rc;
		}
	} else if (alloc_blks < stat.blocks) {
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
	return 0;
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
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static int set_rename_info(struct ksmbd_work *work, struct ksmbd_file *fp,
			   struct smb2_file_rename_info *rename_info,
			   unsigned int buf_len)
{
	if (!(fp->daccess & FILE_DELETE_LE)) {
		pr_err("no right to delete : 0x%x\n", fp->daccess);
		return -EACCES;
	}

	if (buf_len < (u64)sizeof(struct smb2_file_rename_info) +
			le32_to_cpu(rename_info->FileNameLength))
		return -EINVAL;

	if (!le32_to_cpu(rename_info->FileNameLength))
		return -EINVAL;

	return smb2_rename(work, fp, rename_info, work->conn->local_nls);
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
	struct ksmbd_file *parent_fp;
	struct dentry *parent;
	struct dentry *dentry = fp->filp->f_path.dentry;
	int ret;

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return smb2_rename(work, fp, idmap, rename_info,
#else
	return smb2_rename(work, fp, user_ns, rename_info,
#endif
			   work->conn->local_nls);
}
#endif

static int set_file_disposition_info(struct ksmbd_file *fp,
				     struct smb2_file_disposition_info *file_info)
{
	struct inode *inode;

	if (!(fp->daccess & FILE_DELETE_LE)) {
		pr_err("no right to delete : 0x%x\n", fp->daccess);
		return -EACCES;
	}

	inode = file_inode(fp->filp);
	if (file_info->DeletePending) {
		if (S_ISDIR(inode->i_mode) &&
		    ksmbd_vfs_empty_dir(fp) == -ENOTEMPTY)
			return -EBUSY;
		ksmbd_set_inode_pending_delete(fp);
	} else {
		ksmbd_clear_inode_pending_delete(fp);
	}
	return 0;
}

static int set_file_position_info(struct ksmbd_file *fp,
				  struct smb2_file_pos_info *file_info)
{
	loff_t current_byte_offset;
	unsigned long sector_size;
	struct inode *inode;

	inode = file_inode(fp->filp);
	current_byte_offset = le64_to_cpu(file_info->CurrentByteOffset);
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

static int set_file_mode_info(struct ksmbd_file *fp,
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
	 * TODO : need to implement consideration for
	 * FILE_SYNCHRONOUS_IO_ALERT and FILE_SYNCHRONOUS_IO_NONALERT
	 */
	ksmbd_vfs_set_fadvise(fp->filp, mode);
	fp->coption = mode;
	return 0;
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
	{
		if (buf_len < sizeof(struct smb2_file_rename_info))
			return -EMSGSIZE;

		return set_rename_info(work, fp,
				       (struct smb2_file_rename_info *)buffer,
				       buf_len);
	}
	case FILE_LINK_INFORMATION:
	{
		if (buf_len < sizeof(struct smb2_file_link_info))
			return -EMSGSIZE;

		return smb2_create_link(work, work->tcon->share_conf,
					(struct smb2_file_link_info *)buffer,
					buf_len, fp->filp,
					work->conn->local_nls);
	}
	case FILE_DISPOSITION_INFORMATION:
	{
		if (buf_len < sizeof(struct smb2_file_disposition_info))
			return -EMSGSIZE;

		return set_file_disposition_info(fp,
						 (struct smb2_file_disposition_info *)buffer);
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
	}

	pr_err_ratelimited("Unimplemented Fileinfoclass :%d\n", req->FileInfoClass);
	return -EOPNOTSUPP;
}

static int smb2_set_info_sec(struct ksmbd_file *fp, int addition_info,
			     char *buffer, int buf_len)
{
	struct smb_ntsd *pntsd = (struct smb_ntsd *)buffer;

	fp->saccess |= FILE_SHARE_DELETE_LE;

	return set_info_sec(fp->conn, fp->tcon, &fp->filp->f_path, pntsd,
			buf_len, false, true);
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
		unsigned int req_len = get_rfc1002_len(work->request_buf)
				       - work->next_smb2_rcv_hdr_off;

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

	fp = ksmbd_lookup_fd_slow(work, id, pid);
	if (!fp) {
		ksmbd_debug(SMB, "Invalid id for close: %u\n", id);
		rc = -ENOENT;
		goto err_out;
	}

	switch (req->InfoType) {
	case SMB2_O_INFO_FILE:
		ksmbd_debug(SMB, "GOT SMB2_O_INFO_FILE\n");
		rc = smb2_set_info_file(work, fp, req, work->tcon->share_conf);
		break;
	case SMB2_O_INFO_SECURITY:
		ksmbd_debug(SMB, "GOT SMB2_O_INFO_SECURITY\n");
		if (ksmbd_override_fsids(work)) {
			rc = -ENOMEM;
			goto err_out;
		}
		rc = smb2_set_info_sec(fp,
				       le32_to_cpu(req->AdditionalInformation),
				       (char *)req + le16_to_cpu(req->BufferOffset),
				       le32_to_cpu(req->BufferLength));
		ksmbd_revert_fsids(work);
		break;
	default:
		rc = -EOPNOTSUPP;
	}

	if (rc < 0)
		goto err_out;

	rsp->StructureSize = cpu_to_le16(2);
	rc = ksmbd_iov_pin_rsp(work, (void *)rsp,
			       sizeof(struct smb2_set_info_rsp));
	if (rc)
		goto err_out;
	ksmbd_fd_put(work, fp);
	return 0;

err_out:
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
	else if (rc == -EEXIST)
		rsp->hdr.Status = STATUS_OBJECT_NAME_COLLISION;
	else if (rsp->hdr.Status == 0 || rc == -EOPNOTSUPP)
		rsp->hdr.Status = STATUS_INVALID_INFO_CLASS;
	smb2_set_err_rsp(work);
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
