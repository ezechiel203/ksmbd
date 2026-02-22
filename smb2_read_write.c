// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_read_write.c - SMB2_READ + SMB2_WRITE + SMB2_FLUSH handlers
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
 * smb2_read_pipe() - handler for smb2 read from IPC pipe
 * @work:	smb work containing read IPC pipe command buffer
 *
 * Return:	0 on success, otherwise error
 */
static noinline int smb2_read_pipe(struct ksmbd_work *work)
{
	int nbytes = 0, err;
	u64 id;
	struct ksmbd_rpc_command *rpc_resp;
	struct smb2_read_req *req;
	struct smb2_read_rsp *rsp;

	WORK_BUFFERS(work, req, rsp);

	id = req->VolatileFileId;

	rpc_resp = ksmbd_rpc_read(work->sess, id);
	if (rpc_resp) {
		void *aux_payload_buf;

		if (rpc_resp->flags != KSMBD_RPC_OK) {
			err = -EINVAL;
			goto out;
		}

		aux_payload_buf =
			kvmalloc(rpc_resp->payload_sz, KSMBD_DEFAULT_GFP);
		if (!aux_payload_buf) {
			err = -ENOMEM;
			goto out;
		}

		memcpy(aux_payload_buf, rpc_resp->payload, rpc_resp->payload_sz);

		nbytes = rpc_resp->payload_sz;
		err = ksmbd_iov_pin_rsp_read(work, (void *)rsp,
					     offsetof(struct smb2_read_rsp, Buffer),
					     aux_payload_buf, nbytes);
		if (err)
			goto out;
		kvfree(rpc_resp);
	} else {
		err = ksmbd_iov_pin_rsp(work, (void *)rsp,
					offsetof(struct smb2_read_rsp, Buffer));
		if (err)
			goto out;
	}

	rsp->StructureSize = cpu_to_le16(17);
	rsp->DataOffset = 80;
	rsp->Reserved = 0;
	rsp->DataLength = cpu_to_le32(nbytes);
	rsp->DataRemaining = 0;
	rsp->Reserved2 = 0;
	return 0;

out:
	rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
	smb2_set_err_rsp(work);
	kvfree(rpc_resp);
	return err;
}

static int smb2_set_remote_key_for_rdma(struct ksmbd_work *work,
					struct smb2_buffer_desc_v1 *desc,
					__le32 Channel,
					__le16 ChannelInfoLength)
{
	unsigned int i, ch_count;

	if (work->conn->dialect == SMB30_PROT_ID &&
	    Channel != SMB2_CHANNEL_RDMA_V1)
		return -EINVAL;

	ch_count = le16_to_cpu(ChannelInfoLength) / sizeof(*desc);
	if (ksmbd_debug_types & KSMBD_DEBUG_RDMA) {
		for (i = 0; i < ch_count; i++) {
			pr_info("RDMA r/w request %#x: token %#x, length %#x\n",
				i,
				le32_to_cpu(desc[i].token),
				le32_to_cpu(desc[i].length));
		}
	}
	if (!ch_count)
		return -EINVAL;

	work->need_invalidate_rkey =
		(Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE);
	if (Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE)
		work->remote_key = le32_to_cpu(desc->token);
	return 0;
}

static ssize_t smb2_read_rdma_channel(struct ksmbd_work *work,
				      struct smb2_read_req *req, void *data_buf,
				      size_t length)
{
	int err;

	err = ksmbd_conn_rdma_write(work->conn, data_buf, length,
				    (struct smb2_buffer_desc_v1 *)
				    ((char *)req + le16_to_cpu(req->ReadChannelInfoOffset)),
				    le16_to_cpu(req->ReadChannelInfoLength));
	if (err)
		return err;

	return length;
}

/**
 * smb2_read() - handler for smb2 read from file
 * @work:	smb work containing read command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_read(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_read_req *req;
	struct smb2_read_rsp *rsp;
	struct ksmbd_file *fp = NULL;
	loff_t offset;
	size_t length, mincount;
	ssize_t nbytes = 0, remain_bytes = 0;
	int err = 0;
	bool is_rdma_channel = false;
	unsigned int max_read_size = conn->vals->max_read_size;
	unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;
	void *aux_payload_buf;

	ksmbd_debug(SMB, "Received smb2 read request\n");

	if (test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_PIPE)) {
		ksmbd_debug(SMB, "IPC pipe read request\n");
		return smb2_read_pipe(work);
	}

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

	if (!has_file_id(id)) {
		id = req->VolatileFileId;
		pid = req->PersistentFileId;
	}

	if (req->Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE ||
	    req->Channel == SMB2_CHANNEL_RDMA_V1) {
		is_rdma_channel = true;
		max_read_size = get_smbd_max_read_write_size();
	}

	if (is_rdma_channel == true) {
		unsigned int ch_offset = le16_to_cpu(req->ReadChannelInfoOffset);

		if (ch_offset < offsetof(struct smb2_read_req, Buffer)) {
			err = -EINVAL;
			goto out;
		}
		err = smb2_set_remote_key_for_rdma(work,
						   (struct smb2_buffer_desc_v1 *)
						   ((char *)req + ch_offset),
						   req->Channel,
						   req->ReadChannelInfoLength);
		if (err)
			goto out;
	}

	fp = ksmbd_lookup_fd_slow(work, id, pid);
	if (!fp) {
		err = -ENOENT;
		goto out;
	}

	if (!(fp->daccess & (FILE_READ_DATA_LE | FILE_READ_ATTRIBUTES_LE))) {
		pr_err("Not permitted to read : 0x%x\n", fp->daccess);
		err = -EACCES;
		goto out;
	}

	offset = le64_to_cpu(req->Offset);
	if (offset < 0) {
		err = -EINVAL;
		goto out;
	}
	length = le32_to_cpu(req->Length);
	mincount = le32_to_cpu(req->MinimumCount);

	if (length > max_read_size) {
		ksmbd_debug(SMB, "limiting read size to max size(%u)\n",
			    max_read_size);
		err = -EINVAL;
		goto out;
	}

	ksmbd_debug(SMB, "filename %pD, offset %lld, len %zu\n",
		    fp->filp, offset, length);

	/*
	 * Try zero-copy path: send file data directly to the socket
	 * without an intermediate buffer copy. This is eligible when:
	 * - Not encrypted (encryption needs to process the data)
	 * - Not signed (signing needs to hash the data payload)
	 * - Not a compound request (need contiguous response)
	 * - Not an RDMA channel (uses different transfer mechanism)
	 * - Not a stream file (streams need special handling)
	 * - Transport supports sendfile
	 */
	if (!work->encrypted &&
	    !(work->sess && work->sess->sign) &&
	    !(req->hdr.Flags & SMB2_FLAGS_SIGNED) &&
	    !work->next_smb2_rcv_hdr_off &&
	    !is_rdma_channel &&
	    !ksmbd_stream_fd(fp) &&
	    conn->transport->ops->sendfile) {
		nbytes = ksmbd_vfs_sendfile(work, fp, offset, length);
		if (nbytes == -EOPNOTSUPP)
			goto buffered_read;

		if (nbytes < 0) {
			err = nbytes;
			goto out;
		}

		if ((nbytes == 0 && length != 0) || nbytes < mincount) {
			rsp->hdr.Status = STATUS_END_OF_FILE;
			smb2_set_err_rsp(work);
			ksmbd_fd_put(work, fp);
			return -ENODATA;
		}

		ksmbd_debug(SMB, "zero-copy nbytes %zu, offset %lld\n",
			    nbytes, offset);

		rsp->StructureSize = cpu_to_le16(17);
		rsp->DataOffset = 80;
		rsp->Reserved = 0;
		rsp->DataLength = cpu_to_le32(nbytes);
		rsp->DataRemaining = cpu_to_le32(0);
		rsp->Reserved2 = 0;

		/*
		 * Pin just the header; file data will be sent by the
		 * transport sendfile op after the header is written.
		 */
		err = ksmbd_iov_pin_rsp(work, (void *)rsp,
					offsetof(struct smb2_read_rsp, Buffer));
		if (err)
			goto out;

		/* Include the file data length in the rfc1002 length */
		inc_rfc1001_len(work->iov[0].iov_base, nbytes);

		/* Set up sendfile state on the work struct */
		work->sendfile = true;
		work->sendfile_filp = get_file(fp->filp);
		work->sendfile_offset = offset;
		work->sendfile_count = nbytes;

		ksmbd_fd_put(work, fp);
		return 0;
	}

buffered_read:
	aux_payload_buf = ksmbd_buffer_pool_get(ALIGN(length, 8));
	if (!aux_payload_buf) {
		err = -ENOMEM;
		goto out;
	}

	nbytes = ksmbd_vfs_read(work, fp, length, &offset, aux_payload_buf);
	if (nbytes < 0) {
		ksmbd_buffer_pool_put(aux_payload_buf);
		err = nbytes;
		goto out;
	}

	if ((nbytes == 0 && length != 0) || nbytes < mincount) {
		ksmbd_buffer_pool_put(aux_payload_buf);
		rsp->hdr.Status = STATUS_END_OF_FILE;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return -ENODATA;
	}

	ksmbd_debug(SMB, "nbytes %zu, offset %lld mincount %zu\n",
		    nbytes, offset, mincount);

	if (is_rdma_channel == true) {
		/* write data to the client using rdma channel */
		remain_bytes = smb2_read_rdma_channel(work, req,
						      aux_payload_buf,
						      nbytes);
		ksmbd_buffer_pool_put(aux_payload_buf);
		aux_payload_buf = NULL;
		nbytes = 0;
		if (remain_bytes < 0) {
			err = (int)remain_bytes;
			goto out;
		}
	}

	rsp->StructureSize = cpu_to_le16(17);
	rsp->DataOffset = 80;
	rsp->Reserved = 0;
	rsp->DataLength = cpu_to_le32(nbytes);
	rsp->DataRemaining = cpu_to_le32(remain_bytes);
	rsp->Reserved2 = 0;
	err = ksmbd_iov_pin_rsp_read(work, (void *)rsp,
				     offsetof(struct smb2_read_rsp, Buffer),
				     aux_payload_buf, nbytes);
	if (err)
		goto out;
	ksmbd_fd_put(work, fp);
	return 0;

out:
	if (err) {
		if (err == -EISDIR)
			rsp->hdr.Status = STATUS_INVALID_DEVICE_REQUEST;
		else if (err == -EAGAIN)
			rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;
		else if (err == -ENOENT)
			rsp->hdr.Status = STATUS_FILE_CLOSED;
		else if (err == -EACCES)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (err == -ESHARE)
			rsp->hdr.Status = STATUS_SHARING_VIOLATION;
		else if (err == -EINVAL)
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		else
			rsp->hdr.Status = STATUS_INVALID_HANDLE;

		smb2_set_err_rsp(work);
	}
	ksmbd_fd_put(work, fp);
	return err;
}

/**
 * smb2_write_pipe() - handler for smb2 write on IPC pipe
 * @work:	smb work containing write IPC pipe command buffer
 *
 * Return:	0 on success, otherwise error
 */
static noinline int smb2_write_pipe(struct ksmbd_work *work)
{
	struct smb2_write_req *req;
	struct smb2_write_rsp *rsp;
	struct ksmbd_rpc_command *rpc_resp;
	u64 id = 0;
	int err = 0, ret = 0;
	char *data_buf;
	size_t length;

	WORK_BUFFERS(work, req, rsp);

	length = le32_to_cpu(req->Length);
	id = req->VolatileFileId;

	if ((u64)le16_to_cpu(req->DataOffset) + length >
	    get_rfc1002_len(work->request_buf)) {
		pr_err_ratelimited("invalid write data offset %u, smb_len %u\n",
				   le16_to_cpu(req->DataOffset),
				   get_rfc1002_len(work->request_buf));
		err = -EINVAL;
		goto out;
	}

	data_buf = (char *)(((char *)&req->hdr.ProtocolId) +
			   le16_to_cpu(req->DataOffset));

	rpc_resp = ksmbd_rpc_write(work->sess, id, data_buf, length);
	if (rpc_resp) {
		if (rpc_resp->flags == KSMBD_RPC_ENOTIMPLEMENTED) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			kvfree(rpc_resp);
			smb2_set_err_rsp(work);
			return -EOPNOTSUPP;
		}
		if (rpc_resp->flags != KSMBD_RPC_OK) {
			rsp->hdr.Status = STATUS_INVALID_HANDLE;
			smb2_set_err_rsp(work);
			kvfree(rpc_resp);
			return ret;
		}
		kvfree(rpc_resp);
	}

	rsp->StructureSize = cpu_to_le16(17);
	rsp->DataOffset = 0;
	rsp->Reserved = 0;
	rsp->DataLength = cpu_to_le32(length);
	rsp->DataRemaining = 0;
	rsp->Reserved2 = 0;
	err = ksmbd_iov_pin_rsp(work, (void *)rsp,
				offsetof(struct smb2_write_rsp, Buffer));
out:
	if (err) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		smb2_set_err_rsp(work);
	}

	return err;
}

static ssize_t smb2_write_rdma_channel(struct ksmbd_work *work,
				       struct smb2_write_req *req,
				       struct ksmbd_file *fp,
				       loff_t offset, size_t length, bool sync)
{
	char *data_buf;
	int ret;
	ssize_t nbytes;

	data_buf = ksmbd_buffer_pool_get(length);
	if (!data_buf)
		return -ENOMEM;

	ret = ksmbd_conn_rdma_read(work->conn, data_buf, length,
				   (struct smb2_buffer_desc_v1 *)
				   ((char *)req + le16_to_cpu(req->WriteChannelInfoOffset)),
				   le16_to_cpu(req->WriteChannelInfoLength));
	if (ret < 0) {
		ksmbd_buffer_pool_put(data_buf);
		return ret;
	}

	ret = ksmbd_vfs_write(work, fp, data_buf, length, &offset, sync, &nbytes);
	ksmbd_buffer_pool_put(data_buf);
	if (ret < 0)
		return ret;

	return nbytes;
}

/**
 * smb2_write() - handler for smb2 write from file
 * @work:	smb work containing write command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_write(struct ksmbd_work *work)
{
	struct smb2_write_req *req;
	struct smb2_write_rsp *rsp;
	struct ksmbd_file *fp = NULL;
	loff_t offset;
	size_t length;
	ssize_t nbytes;
	char *data_buf;
	bool writethrough = false, is_rdma_channel = false;
	int err = 0;
	unsigned int max_write_size = work->conn->vals->max_write_size;

	ksmbd_debug(SMB, "Received smb2 write request\n");

	WORK_BUFFERS(work, req, rsp);

	if (test_share_config_flag(work->tcon->share_conf, KSMBD_SHARE_FLAG_PIPE)) {
		ksmbd_debug(SMB, "IPC pipe write request\n");
		return smb2_write_pipe(work);
	}

	offset = le64_to_cpu(req->Offset);
	if (offset < 0)
		return -EINVAL;
	length = le32_to_cpu(req->Length);

	if (req->Channel == SMB2_CHANNEL_RDMA_V1 ||
	    req->Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE) {
		is_rdma_channel = true;
		max_write_size = get_smbd_max_read_write_size();
		length = le32_to_cpu(req->RemainingBytes);
	}

	if (is_rdma_channel == true) {
		unsigned int ch_offset = le16_to_cpu(req->WriteChannelInfoOffset);

		if (req->Length != 0 || req->DataOffset != 0 ||
		    ch_offset < offsetof(struct smb2_write_req, Buffer)) {
			err = -EINVAL;
			goto out;
		}
		err = smb2_set_remote_key_for_rdma(work,
						   (struct smb2_buffer_desc_v1 *)
						   ((char *)req + ch_offset),
						   req->Channel,
						   req->WriteChannelInfoLength);
		if (err)
			goto out;
	}

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		ksmbd_debug(SMB, "User does not have write permission\n");
		err = -EACCES;
		goto out;
	}

	fp = ksmbd_lookup_fd_slow(work, req->VolatileFileId, req->PersistentFileId);
	if (!fp) {
		err = -ENOENT;
		goto out;
	}

	if (!(fp->daccess & (FILE_WRITE_DATA_LE | FILE_READ_ATTRIBUTES_LE))) {
		pr_err("Not permitted to write : 0x%x\n", fp->daccess);
		err = -EACCES;
		goto out;
	}

	if (length > max_write_size) {
		ksmbd_debug(SMB, "limiting write size to max size(%u)\n",
			    max_write_size);
		err = -EINVAL;
		goto out;
	}

#ifdef CONFIG_KSMBD_FRUIT
	/*
	 * Time Machine quota enforcement: reject writes when the
	 * share's Time Machine max size has been exceeded.
	 */
	if (work->tcon && work->tcon->share_conf &&
	    work->conn->is_fruit) {
		err = ksmbd_fruit_check_tm_quota(
				work->tcon->share_conf,
				&work->tcon->share_conf->vfs_path);
		if (err) {
			ksmbd_debug(SMB,
				    "Fruit TM quota exceeded, rejecting write\n");
			goto out;
		}
	}
#endif

	ksmbd_debug(SMB, "flags %u\n", le32_to_cpu(req->Flags));
	if (le32_to_cpu(req->Flags) & SMB2_WRITEFLAG_WRITE_THROUGH)
		writethrough = true;

	if (is_rdma_channel == false) {
		if (le16_to_cpu(req->DataOffset) <
		    offsetof(struct smb2_write_req, Buffer)) {
			err = -EINVAL;
			goto out;
		}

		data_buf = (char *)(((char *)&req->hdr.ProtocolId) +
				    le16_to_cpu(req->DataOffset));

		ksmbd_debug(SMB, "filename %pD, offset %lld, len %zu\n",
			    fp->filp, offset, length);
		err = ksmbd_vfs_write(work, fp, data_buf, length, &offset,
				      writethrough, &nbytes);
		if (err < 0)
			goto out;
	} else {
		/* read data from the client using rdma channel, and
		 * write the data.
		 */
		nbytes = smb2_write_rdma_channel(work, req, fp, offset, length,
						 writethrough);
		if (nbytes < 0) {
			err = (int)nbytes;
			goto out;
		}
	}

	rsp->StructureSize = cpu_to_le16(17);
	rsp->DataOffset = 0;
	rsp->Reserved = 0;
	rsp->DataLength = cpu_to_le32(nbytes);
	rsp->DataRemaining = 0;
	rsp->Reserved2 = 0;
	err = ksmbd_iov_pin_rsp(work, rsp, offsetof(struct smb2_write_rsp, Buffer));
	if (err)
		goto out;
	ksmbd_fd_put(work, fp);
	return 0;

out:
	if (err == -EAGAIN)
		rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;
	else if (err == -ENOSPC || err == -EFBIG)
		rsp->hdr.Status = STATUS_DISK_FULL;
	else if (err == -ENOENT)
		rsp->hdr.Status = STATUS_FILE_CLOSED;
	else if (err == -EACCES)
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
	else if (err == -ESHARE)
		rsp->hdr.Status = STATUS_SHARING_VIOLATION;
	else if (err == -EINVAL)
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
	else
		rsp->hdr.Status = STATUS_INVALID_HANDLE;

	smb2_set_err_rsp(work);
	ksmbd_fd_put(work, fp);
	return err;
}

/**
 * smb2_flush() - handler for smb2 flush file - fsync
 * @work:	smb work containing flush command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_flush(struct ksmbd_work *work)
{
	struct smb2_flush_req *req;
	struct smb2_flush_rsp *rsp;
	bool fullsync = false;
	int err;

	WORK_BUFFERS(work, req, rsp);

	ksmbd_debug(SMB, "Received smb2 flush request(fid : %llu)\n", req->VolatileFileId);

	/*
	 * Apple F_FULLFSYNC: macOS Time Machine sends
	 * Reserved1=0xFFFF to request a full device flush.
	 */
#ifdef CONFIG_KSMBD_FRUIT
	if (work->conn->is_fruit && le16_to_cpu(req->Reserved1) == 0xFFFF)
		fullsync = true;
#endif

	err = ksmbd_vfs_fsync(work, req->VolatileFileId,
			      req->PersistentFileId, fullsync);
	if (err)
		goto out;

	rsp->StructureSize = cpu_to_le16(4);
	rsp->Reserved = 0;
	return ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_flush_rsp));

out:
	rsp->hdr.Status = STATUS_INVALID_HANDLE;
	smb2_set_err_rsp(work);
	return err;
}
