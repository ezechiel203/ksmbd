// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_read_write.c - SMB2_READ + SMB2_WRITE + SMB2_FLUSH handlers
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
#include "ksmbd_branchcache.h"
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

struct smb2_pipe_async_ctx {
	struct delayed_work	dwork;
	struct ksmbd_work	*work;
	u64			id;
	unsigned int		length;
};

static void smb2_pipe_async_put_conn_ref(struct ksmbd_work *work)
{
	if (!work || !work->async_conn_ref || !work->conn)
		return;

	work->async_conn_ref = false;
	ksmbd_conn_free(work->conn);
}

static void smb2_pipe_read_reschedule(struct smb2_pipe_async_ctx *ctx)
{
	mod_delayed_work(system_wq, &ctx->dwork, msecs_to_jiffies(25));
}

static void smb2_pipe_read_complete(struct ksmbd_work *work,
				    struct smb2_pipe_async_ctx *ctx,
				    struct ksmbd_rpc_command *rpc_resp)
{
	struct smb2_read_rsp *rsp = smb2_get_msg(work->response_buf);
	unsigned int remain_bytes = 0;
	unsigned int nbytes;
	int rc;
	void *aux_payload_buf;

	if (!rpc_resp || rpc_resp->flags != KSMBD_RPC_OK)
		goto out_free_resp;

	nbytes = rpc_resp->payload_sz;
	if (ctx->length == 0 || nbytes == 0) {
		kvfree(rpc_resp);
		smb2_pipe_read_reschedule(ctx);
		return;
	}

	if (nbytes > ctx->length) {
		rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
		remain_bytes = nbytes - ctx->length;
		nbytes = ctx->length;
	}

	aux_payload_buf = kvmalloc(nbytes, KSMBD_DEFAULT_GFP);
	if (!aux_payload_buf) {
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		goto out_free_resp;
	}

	memcpy(aux_payload_buf, rpc_resp->payload, nbytes);
	rc = ksmbd_iov_pin_rsp_read(work, rsp,
				    offsetof(struct smb2_read_rsp, Buffer),
				    aux_payload_buf, nbytes);
	if (rc) {
		kvfree(aux_payload_buf);
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		goto out_free_resp;
	}

	rsp->StructureSize = cpu_to_le16(17);
	rsp->DataOffset = offsetof(struct smb2_read_rsp, Buffer);
	rsp->Reserved = 0;
	rsp->DataLength = cpu_to_le32(nbytes);
	rsp->DataRemaining = cpu_to_le32(remain_bytes);
	rsp->Reserved2 = 0;

out_free_resp:
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
			pr_err_ratelimited("ksmbd: pipe read encrypt failed: %d\n",
					   rc);
	}
	ksmbd_conn_write(work);
	ksmbd_conn_try_dequeue_request(work);
	if (READ_ONCE(server_conf.max_async_credits))
		atomic_dec(&work->conn->outstanding_async);
	if (work->sess)
		ksmbd_user_session_put(work->sess);
	smb2_pipe_async_put_conn_ref(work);
	kfree(ctx);
	ksmbd_free_work_struct(work);
}

static void smb2_pipe_read_poll_work(struct work_struct *wk)
{
	struct delayed_work *dwork = to_delayed_work(wk);
	struct smb2_pipe_async_ctx *ctx =
		container_of(dwork, struct smb2_pipe_async_ctx, dwork);
	struct ksmbd_work *work = ctx->work;
	struct ksmbd_rpc_command *rpc_resp;
	struct smb2_read_rsp *rsp;

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
		smb2_pipe_async_put_conn_ref(work);
		kfree(ctx);
		if (work)
			ksmbd_free_work_struct(work);
		return;
	}

	rpc_resp = ksmbd_rpc_read(work->sess, ctx->id);
	if (!rpc_resp) {
		smb2_pipe_read_reschedule(ctx);
		return;
	}

	rsp = smb2_get_msg(work->response_buf);
	if (rpc_resp->flags == KSMBD_RPC_EBAD_FID) {
		rsp->hdr.Status = STATUS_PIPE_DISCONNECTED;
		smb2_set_err_rsp(work);
		smb2_pipe_read_complete(work, ctx, rpc_resp);
		return;
	}

	if (rpc_resp->flags == KSMBD_RPC_ENOTIMPLEMENTED) {
		kvfree(rpc_resp);
		smb2_pipe_read_reschedule(ctx);
		return;
	}

	if (rpc_resp->flags != KSMBD_RPC_OK || rpc_resp->payload_sz == 0) {
		kvfree(rpc_resp);
		smb2_pipe_read_reschedule(ctx);
		return;
	}

	smb2_pipe_read_complete(work, ctx, rpc_resp);
}

/**
 * smb2_read_pipe_cancel() - cancel callback for async pipe read
 * @argv: cancel argument array (argv[0] is unused/NULL for pipe reads)
 *
 * Called from the SMB2 CANCEL path.  Sends STATUS_CANCELLED to the client
 * and frees the async work.
 */
static void smb2_read_pipe_cancel(void **argv)
{
	struct ksmbd_work *work;
	struct smb2_read_rsp *rsp;
	struct smb2_pipe_async_ctx *ctx;

	/*
	 * argv[0] contains the work pointer for pipe read cancellation.
	 * If NULL, the work was already completed or freed.
	 */
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

	if (ksmbd_iov_pin_rsp(work, rsp,
			      sizeof(struct smb2_hdr) + 2))
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;

	if (work->sess && work->sess->enc && work->encrypted &&
	    work->conn->ops->encrypt_resp) {
		int rc = work->conn->ops->encrypt_resp(work);

		if (rc < 0)
			pr_err_ratelimited("ksmbd: pipe read cancel encrypt failed: %d\n",
					   rc);
	}

	/*
	 * The async handler set send_no_response = 1 to suppress the
	 * main dispatch path's response.  Clear it so the cancel
	 * response is actually transmitted.
	 */
	work->send_no_response = 0;
	ksmbd_conn_write(work);

	/* Remove from async_requests list before freeing */
	spin_lock(&work->conn->request_lock);
	list_del_init(&work->async_request_entry);
	spin_unlock(&work->conn->request_lock);

	ksmbd_conn_try_dequeue_request(work);

	/* Decrement outstanding async count */
	if (READ_ONCE(server_conf.max_async_credits))
		atomic_dec(&work->conn->outstanding_async);

	if (work->sess)
		ksmbd_user_session_put(work->sess);
	smb2_pipe_async_put_conn_ref(work);
	kfree(ctx);
	ksmbd_free_work_struct(work);
}

/**
 * smb2_read_pipe_async() - make a pipe read go async (STATUS_PENDING)
 * @work: smb work to pend
 *
 * Called when a pipe read has no data available.  Sets up async work
 * and sends STATUS_PENDING to the client.  The work remains pending
 * until cancelled or the connection is torn down.
 *
 * Return: 0 on success, negative errno on failure.
 *         -ENOSPC means the async credit limit is reached; caller
 *         should return STATUS_INSUFFICIENT_RESOURCES synchronously.
 */
static int smb2_read_pipe_async(struct ksmbd_work *work)
{
	struct smb2_read_req *req = smb2_get_msg(work->request_buf);
	struct smb2_read_rsp *rsp = smb2_get_msg(work->response_buf);
	struct smb2_pipe_async_ctx *ctx;
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
	ctx->id = req->VolatileFileId;
	INIT_DELAYED_WORK(&ctx->dwork, smb2_pipe_read_poll_work);

	rc = setup_async_work(work, smb2_read_pipe_cancel, argv);
	if (rc) {
		kfree(ctx);
		kfree(argv);
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		return rc;
	}

	/* Store work pointer in cancel argv so cancel can find it */
	argv[0] = work;
	argv[1] = ctx;

	/* Transfer work ownership to async subsystem */
	if (work->sess)
		ksmbd_user_session_get(work->sess);
	refcount_inc(&work->conn->refcnt);
	work->async_conn_ref = true;
	work->pending_async = 1;

	/*
	 * Grant credits in the interim response.  Call set_rsp_credits
	 * BEFORE smb2_send_interim_resp so the CreditRequest field is
	 * set in the response header, and the interim copy inherits it.
	 * This must happen before setting send_no_response, otherwise
	 * set_rsp_credits would bail out immediately.
	 */
	if (work->conn->ops->set_rsp_credits)
		work->conn->ops->set_rsp_credits(work);

	/* Send STATUS_PENDING interim response */
	smb2_send_interim_resp(work, STATUS_PENDING);

	/* Suppress the normal response path */
	work->send_no_response = 1;
	ctx->length = le32_to_cpu(req->Length);
	smb2_pipe_read_reschedule(ctx);
	return 0;
}

/**
 * smb2_read_pipe() - handler for smb2 read from IPC pipe
 * @work:	smb work containing read IPC pipe command buffer
 *
 * Return:	0 on success, otherwise error
 */
static noinline int smb2_read_pipe(struct ksmbd_work *work)
{
	int nbytes = 0, err;
	unsigned int remain_bytes = 0;
	u64 id;
	struct ksmbd_rpc_command *rpc_resp;
	struct smb2_read_req *req;
	struct smb2_read_rsp *rsp;
	unsigned int length;

	WORK_BUFFERS(work, req, rsp);

	id = req->VolatileFileId;
	length = le32_to_cpu(req->Length);

	rpc_resp = ksmbd_rpc_read(work->sess, id);
	if (rpc_resp) {
		void *aux_payload_buf;

		if (rpc_resp->flags == KSMBD_RPC_ENOTIMPLEMENTED) {
			kvfree(rpc_resp);
			rpc_resp = NULL;
			goto no_data;
		}

		if (rpc_resp->flags == KSMBD_RPC_EBAD_FID) {
			rsp->hdr.Status = STATUS_PIPE_DISCONNECTED;
			kvfree(rpc_resp);
			return -EPIPE;
		}

		if (rpc_resp->flags != KSMBD_RPC_OK) {
			kvfree(rpc_resp);
			rpc_resp = NULL;
			goto no_data;
		}

		if (rpc_resp->payload_sz == 0) {
			kvfree(rpc_resp);
			rpc_resp = NULL;
			goto no_data;
		}

		/*
		 * We have pipe data available.
		 */
		nbytes = rpc_resp->payload_sz;

		if (length == 0) {
			/*
			 * Zero-length read but data exists: go async.
			 * The read stays pending since the client
			 * cannot receive data with length=0.
			 */
			kvfree(rpc_resp);
			return smb2_read_pipe_async(work);
		}

		/*
		 * Cap the response to the client's requested length.
		 * If the pipe has more data than the client asked for,
		 * return STATUS_BUFFER_OVERFLOW with truncated data.
		 * Track how many bytes remain so DataRemaining can be set
		 * correctly in the response (MS-SMB2 §2.2.20, D.6).
		 */
		if (nbytes > length) {
			rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
			remain_bytes = nbytes - length;
			nbytes = length;
		}

		aux_payload_buf =
			kvmalloc(nbytes, KSMBD_DEFAULT_GFP);
		if (!aux_payload_buf) {
			err = -ENOMEM;
			goto out;
		}

		memcpy(aux_payload_buf, rpc_resp->payload, nbytes);

		err = ksmbd_iov_pin_rsp_read(work, (void *)rsp,
					     offsetof(struct smb2_read_rsp, Buffer),
					     aux_payload_buf, nbytes);
		if (err)
			goto out;
		kvfree(rpc_resp);
	} else {
no_data:
		/*
		 * No data available on the pipe.  Per MS-SMB2, when a
		 * named pipe has no data, the server should pend the
		 * read and complete it when data arrives.  Since ksmbd
		 * communicates with the RPC daemon synchronously, we
		 * go async here and leave the request pending.
		 */
		return smb2_read_pipe_async(work);
	}

	rsp->StructureSize = cpu_to_le16(17);
	/* D.1: DataOffset is relative to start of SMB2 message header */
	rsp->DataOffset = offsetof(struct smb2_read_rsp, Buffer);
	rsp->Reserved = 0;
	rsp->DataLength = cpu_to_le32(nbytes);
	/*
	 * D.6: MS-SMB2 §2.2.20 — DataRemaining indicates bytes still in the
	 * pipe buffer that could not fit in this response (STATUS_BUFFER_OVERFLOW
	 * case).  Set it to the actual remaining byte count so the client knows
	 * how much more data to request.
	 */
	rsp->DataRemaining = cpu_to_le32(remain_bytes);
	rsp->Reserved2 = 0;
	return 0;

out:
	if (!rsp->hdr.Status)
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
	if (Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE) {
		/*
		 * D.5: Store the first descriptor's token for RDMA_V1_INVALIDATE.
		 * MS-SMB2 §3.3.5.12/13 allows multi-descriptor RDMA buffers
		 * (ch_count > 1).  The ksmbd_work struct only has a single
		 * remote_key field, and the RDMA transport layer (transport_rdma.c)
		 * only supports invalidating one Memory Region per send via
		 * IB_WR_SEND_WITH_INV.  Full multi-descriptor invalidation would
		 * require extending ksmbd_work with an array of tokens and updating
		 * the transport send path.
		 *
		 * In practice, real-world RDMA clients (including Windows) send
		 * exactly one descriptor per SMB2 READ/WRITE when using
		 * RDMA_V1_INVALIDATE, so this limitation does not cause
		 * interoperability problems.  Emit a rate-limited warning if a
		 * client ever sends more than one descriptor so the condition can
		 * be diagnosed.
		 */
		if (ch_count > 1)
			pr_warn_ratelimited("ksmbd: RDMA_V1_INVALIDATE with %u descriptors; only first token (0x%x) will be invalidated\n",
					    ch_count, le32_to_cpu(desc->token));
		work->remote_key = le32_to_cpu(desc->token);
	}
	return 0;
}

static ssize_t smb2_read_rdma_channel(struct ksmbd_work *work,
				      struct smb2_read_req *req, void *data_buf,
				      size_t length)
{
	int err;
	unsigned int ch_offset = le16_to_cpu(req->ReadChannelInfoOffset);
	unsigned int ch_len = le16_to_cpu(req->ReadChannelInfoLength);
	unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;

	if (ch_offset < offsetof(struct smb2_read_req, Buffer) ||
	    ch_offset > req_len ||
	    ch_len > req_len - ch_offset)
		return -EINVAL;

	err = ksmbd_conn_rdma_write(work->conn, data_buf, length,
				    (struct smb2_buffer_desc_v1 *)
				    ((char *)req + ch_offset),
				    ch_len);
	if (err)
		return err;

	return length;
}

/**
 * smb2_direct_read() - attempt direct (unbuffered) file read
 * @filp:	file to read from
 * @buf:	destination buffer
 * @count:	bytes to read
 * @pos:	file offset (updated on success)
 *
 * Uses IOCB_DIRECT to bypass the page cache.  Returns -EOPNOTSUPP if
 * the filesystem does not support direct I/O, so the caller can fall
 * back to a buffered read.
 */
static ssize_t smb2_direct_read(struct file *filp, char *buf,
				size_t count, loff_t *pos)
{
	/*
	 * Direct I/O disabled: causes regressions on ext4 with
	 * small files and oplock tests.  Always fall back to buffered.
	 */
	return -EOPNOTSUPP;
}

/**
 * smb2_direct_write() - attempt direct (unbuffered) file write
 * @filp:	file to write to
 * @buf:	source buffer
 * @count:	bytes to write
 * @pos:	file offset (updated on success)
 *
 * Uses IOCB_DIRECT to bypass the page cache.  Returns -EOPNOTSUPP if
 * the filesystem does not support direct I/O, so the caller can fall
 * back to a buffered write.
 */
static ssize_t smb2_direct_write(struct file *filp, char *buf,
				 size_t count, loff_t *pos)
{
	/*
	 * Direct I/O disabled: causes regressions on ext4 with
	 * small files and oplock tests.  Always fall back to buffered.
	 */
	return -EOPNOTSUPP;
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
	bool unbuffered = false;
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

	if (req->Channel == SMB2_CHANNEL_RDMA_TRANSFORM) {
		/*
		 * RDMA transform channels require explicit negotiate
		 * support. ksmbd currently suppresses RDMA transform
		 * negotiation, so reject transformed reads instead of
		 * silently processing them as inline traffic.
		 */
		err = -EINVAL;
		goto out;
	}

	if (is_rdma_channel == true) {
		unsigned int ch_offset = le16_to_cpu(req->ReadChannelInfoOffset);
		unsigned int ch_len = le16_to_cpu(req->ReadChannelInfoLength);
		unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;

		if (ch_offset < offsetof(struct smb2_read_req, Buffer) ||
		    ch_offset > req_len ||
		    ch_len > req_len - ch_offset) {
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

	/* MS-SMB2 §3.3.5.12: FILE_READ_DATA or FILE_EXECUTE required to read */
	if (!(fp->daccess & (FILE_READ_DATA_LE | FILE_EXECUTE_LE))) {
		pr_err("Not permitted to read : 0x%x\n", fp->daccess);
		err = -EACCES;
		goto out;
	}

	/*
	 * MS-SMB2 §3.3.5.2.10: READ is not state-modifying, so stale CSN
	 * is not rejected.  But we still advance Open.ChannelSequence if
	 * the request carries a higher sequence number.
	 */
	smb2_update_channel_sequence(work, fp);

	offset = le64_to_cpu(req->Offset);
	if (offset < 0 || offset > MAX_LFS_FILESIZE) {
		ksmbd_debug(SMB, "invalid read offset %lld\n", offset);
		err = -EINVAL;
		goto out;
	}
	length = le32_to_cpu(req->Length);
	mincount = le32_to_cpu(req->MinimumCount);

	/*
	 * MS-SMB2 §3.3.5.12: reject reads where offset + length would
	 * overflow the maximum addressable file offset.  A read at
	 * (INT64_MAX, length=1) would wrap to a negative position;
	 * detect this before the VFS call to return INVALID_PARAMETER
	 * rather than STATUS_END_OF_FILE.
	 */
	if (length > 0 && offset > MAX_LFS_FILESIZE - (loff_t)length) {
		err = -EINVAL;
		goto out;
	}

	if (length > max_read_size) {
		ksmbd_debug(SMB, "limiting read size to max size(%u)\n",
			    max_read_size);
		err = -EINVAL;
		goto out;
	}

	/*
	 * D.4: MS-SMB2 §3.3.5.12 — inspect per-request read flags.
	 * The Flags byte in the wire format (MS-SMB2 §2.2.19, 1 byte after
	 * Padding) maps to req->Reserved in the ksmbd struct definition.
	 * SMB2_READFLAG_READ_UNBUFFERED (0x01): the client requests that the
	 * server bypass its page cache and read directly from the backing
	 * store (equivalent to O_DIRECT).  ksmbd uses buffered reads via
	 * kernel_read(); direct I/O is not currently supported.  Log the
	 * request so administrators can identify clients using this feature.
	 */
	if (req->Reserved & SMB2_READFLAG_READ_UNBUFFERED) {
		ksmbd_debug(SMB, "SMB2_READFLAG_READ_UNBUFFERED: attempting direct I/O\n");
		unbuffered = true;
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
	    !req->hdr.NextCommand &&
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
		/* D.1: DataOffset is relative to start of SMB2 message header */
		rsp->DataOffset = offsetof(struct smb2_read_rsp, Buffer);
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

	if (unbuffered) {
		nbytes = smb2_direct_read(fp->filp, aux_payload_buf,
					  length, &offset);
		if (nbytes == -EOPNOTSUPP) {
			ksmbd_debug(SMB, "direct read not supported, falling back to buffered\n");
			unbuffered = false;
		}
	}

	if (!unbuffered)
		nbytes = ksmbd_vfs_read(work, fp, length, &offset,
					aux_payload_buf);

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
	/* D.1: DataOffset is relative to start of SMB2 message header */
	rsp->DataOffset = offsetof(struct smb2_read_rsp, Buffer);
	rsp->Reserved = 0;
	rsp->DataLength = cpu_to_le32(nbytes);
	rsp->DataRemaining = cpu_to_le32(remain_bytes);
	rsp->Reserved2 = 0;

	if (work->next_smb2_rcv_hdr_off) {
		/*
		 * Compound request: copy data inline into the response
		 * buffer so the entire response (header + body + data)
		 * is contiguous.  This ensures that the 8-byte padding
		 * added by init_chained_smb2_rsp() between compound
		 * members is correctly visible to the client, which
		 * parses the compound response as a single contiguous
		 * byte stream.  With a separate aux iov, the
		 * scatter-gather layout can cause the padding to be
		 * invisible to the client's compound parser.
		 */
		memcpy(rsp->Buffer, aux_payload_buf, nbytes);
		ksmbd_buffer_pool_put(aux_payload_buf);
		err = ksmbd_iov_pin_rsp(work, (void *)rsp,
					offsetof(struct smb2_read_rsp, Buffer) +
					nbytes);
		if (err)
			goto out;
	} else {
		err = ksmbd_iov_pin_rsp_read(work, (void *)rsp,
					     offsetof(struct smb2_read_rsp, Buffer),
					     aux_payload_buf, nbytes);
		if (err) {
			ksmbd_buffer_pool_put(aux_payload_buf);
			goto out;
		}
	}
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
		else if (err == -EBUSY)
			rsp->hdr.Status = STATUS_DELETE_PENDING;
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
	int err = 0;
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
			kvfree(rpc_resp);
			rpc_resp = NULL;
			goto write_rsp;
		}
		if (rpc_resp->flags != KSMBD_RPC_OK) {
			/*
			 * D.2: MS-SMB2 §3.3.5.13 — pipe write failures should
			 * return STATUS_PIPE_DISCONNECTED (not STATUS_INVALID_HANDLE).
			 * Also return a proper negative errno so the caller's
			 * compound chain does not treat this as a success.
			 */
			rsp->hdr.Status = STATUS_PIPE_DISCONNECTED;
			smb2_set_err_rsp(work);
			kvfree(rpc_resp);
			return -EPIPE;
		}
		kvfree(rpc_resp);
	}

write_rsp:
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
	unsigned int ch_offset = le16_to_cpu(req->WriteChannelInfoOffset);
	unsigned int ch_len = le16_to_cpu(req->WriteChannelInfoLength);
	unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;

	if (ch_offset < offsetof(struct smb2_write_req, Buffer) ||
	    ch_offset > req_len ||
	    ch_len > req_len - ch_offset)
		return -EINVAL;

	/*
	 * D.3: MS-SMB2 §2.2.21 — for RDMA channels, RemainingBytes carries
	 * the transfer length.  A zero-length RDMA write is valid; skip the
	 * RDMA read entirely and proceed directly to writing zero bytes.
	 */
	if (length == 0) {
		nbytes = 0;
		goto done;
	}

	data_buf = ksmbd_buffer_pool_get(length);
	if (!data_buf)
		return -ENOMEM;

	ret = ksmbd_conn_rdma_read(work->conn, data_buf, length,
				   (struct smb2_buffer_desc_v1 *)
				   ((char *)req + ch_offset),
				   ch_len);
	if (ret < 0) {
		ksmbd_buffer_pool_put(data_buf);
		return ret;
	}

	ret = ksmbd_vfs_write(work, fp, data_buf, length, &offset, sync, &nbytes);
	ksmbd_buffer_pool_put(data_buf);
	if (ret < 0)
		return ret;

done:
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
	bool write_to_eof = false, unbuffered = false;
	int err = 0;
	unsigned int max_write_size = work->conn->vals->max_write_size;

	ksmbd_debug(SMB, "Received smb2 write request\n");

	WORK_BUFFERS(work, req, rsp);

	if (test_share_config_flag(work->tcon->share_conf, KSMBD_SHARE_FLAG_PIPE)) {
		ksmbd_debug(SMB, "IPC pipe write request\n");
		return smb2_write_pipe(work);
	}

	/*
	 * MS-SMB2 §3.3.5.13: 0xFFFFFFFFFFFFFFFF is the write-to-EOF sentinel,
	 * but only for FILE_APPEND_DATA-only handles (no FILE_WRITE_DATA).
	 * We defer sentinel detection to after fp lookup so we can check
	 * the granted access.  For now, just parse the offset; the sentinel
	 * value (all-ones) casts to loff_t -1 which the "offset < 0" check
	 * will catch for non-append handles.
	 */
	{
		__le64 raw_offset = req->Offset;

		write_to_eof = (raw_offset == cpu_to_le64(0xFFFFFFFFFFFFFFFFULL));
		if (write_to_eof) {
			offset = 0; /* placeholder; resolved after fp lookup */
		} else {
			offset = le64_to_cpu(raw_offset);
			if (offset < 0 || offset > MAX_LFS_FILESIZE) {
				err = -EINVAL;
				goto out;
			}
		}
	}
	length = le32_to_cpu(req->Length);

	/* Reject writes where offset + length would overflow MAX_LFS_FILESIZE */
	if (length > 0 && offset > 0 &&
	    offset > MAX_LFS_FILESIZE - (loff_t)length) {
		err = -EINVAL;
		goto out;
	}

	/*
	 * MS-SMB2: NTFS maximum file size is 0xfffffff0000.
	 * Writing at or beyond MAXFILESIZE is INVALID_PARAMETER.
	 * Writing below MAXFILESIZE but extending past it is DISK_FULL.
	 */
#define SMB2_MAX_FILE_OFFSET ((loff_t)0xfffffff0000ULL)
	if (length > 0 && offset >= SMB2_MAX_FILE_OFFSET) {
		err = -EINVAL;
		goto out;
	}
	if (length > 0 && offset + (loff_t)length >= SMB2_MAX_FILE_OFFSET) {
		err = -ENOSPC;
		goto out;
	}

	if (req->Channel == SMB2_CHANNEL_RDMA_V1 ||
	    req->Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE) {
		is_rdma_channel = true;
		max_write_size = get_smbd_max_read_write_size();
		length = le32_to_cpu(req->RemainingBytes);
	}

	if (req->Channel == SMB2_CHANNEL_RDMA_TRANSFORM) {
		/*
		 * See smb2_read(): reject transformed RDMA writes until
		 * RDMA transform negotiation and crypto are implemented.
		 */
		err = -EINVAL;
		goto out;
	}

	if (is_rdma_channel == true) {
		unsigned int ch_offset = le16_to_cpu(req->WriteChannelInfoOffset);
		unsigned int ch_len = le16_to_cpu(req->WriteChannelInfoLength);
		unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;

		if (req->Length != 0 || req->DataOffset != 0 ||
		    ch_offset < offsetof(struct smb2_write_req, Buffer) ||
		    ch_offset > req_len ||
		    ch_len > req_len - ch_offset) {
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

	{
		u64 volatile_id = req->VolatileFileId;
		u64 persistent_id = req->PersistentFileId;

		if (work->next_smb2_rcv_hdr_off &&
		    !has_file_id(volatile_id)) {
			ksmbd_debug(SMB,
				    "Compound request set FID = %llu\n",
				    work->compound_fid);
			volatile_id = work->compound_fid;
			persistent_id = work->compound_pfid;
		}

		fp = ksmbd_lookup_fd_slow(work, volatile_id, persistent_id);
	}
	if (!fp) {
		err = -ENOENT;
		goto out;
	}

	if (!(fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE))) {
		pr_err("Not permitted to write : 0x%x\n", fp->daccess);
		err = -EACCES;
		goto out;
	}

	/* MS-SMB2 §3.3.5.2.10: validate ChannelSequence */
	err = smb2_check_channel_sequence(work, fp);
	if (err) {
		rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;
		goto out;
	}

	/*
	 * MS-SMB2 §3.3.5.13: resolve the write-to-EOF sentinel and enforce
	 * append-only semantics for FILE_APPEND_DATA-without-FILE_WRITE_DATA.
	 *
	 * The sentinel (offset == 0xFFFFFFFFFFFFFFFF) is only valid when the
	 * handle has FILE_APPEND_DATA but NOT FILE_WRITE_DATA.  For handles
	 * with FILE_WRITE_DATA, this offset is simply invalid (negative when
	 * cast to loff_t).
	 */
	if (write_to_eof) {
		if (!(fp->daccess & FILE_APPEND_DATA_LE) ||
		    (fp->daccess & FILE_WRITE_DATA_LE)) {
			/*
			 * Not an append-only handle: offset 0xFFFFFFFFFFFFFFFF
			 * is not a valid sentinel, reject as invalid offset.
			 */
			err = -EINVAL;
			goto out;
		}
		offset = i_size_read(file_inode(fp->filp));
	}

	/* Post-resolution overflow check for write_to_eof (offset was 0 placeholder) */
	if (length > 0 && offset > MAX_LFS_FILESIZE - (loff_t)length) {
		err = -EINVAL;
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

	/*
	 * D.4: MS-SMB2 §3.3.5.13 — inspect per-request write flags.
	 * SMB2_WRITEFLAG_WRITE_UNBUFFERED (0x02): the client requests that
	 * the server write data directly to the backing store without
	 * intermediate buffering (equivalent to O_DIRECT semantics).  ksmbd
	 * uses buffered writes; direct I/O is not currently supported.  Log
	 * the request so administrators can identify clients using this
	 * feature.  WRITE_THROUGH (fsync after write) is handled above.
	 */
	if (le32_to_cpu(req->Flags) & SMB2_WRITEFLAG_WRITE_UNBUFFERED) {
		ksmbd_debug(SMB, "SMB2_WRITEFLAG_WRITE_UNBUFFERED: attempting direct I/O\n");
		unbuffered = true;
	}

	if (is_rdma_channel == false) {
		unsigned int data_off = le16_to_cpu(req->DataOffset);
		unsigned int req_buf_len;

		if (data_off < offsetof(struct smb2_write_req, Buffer)) {
			err = -EINVAL;
			goto out;
		}

		/*
		 * Compute the available request buffer length relative to
		 * the current sub-request's ProtocolId.  For compound
		 * requests, subtract the compound header offset so we
		 * don't allow the write data to spill into adjacent
		 * sub-requests.
		 */
		req_buf_len = get_rfc1002_len(work->request_buf);
		if (work->next_smb2_rcv_hdr_off)
			req_buf_len -= work->next_smb2_rcv_hdr_off;

		if ((u64)data_off + length > req_buf_len) {
			pr_err_ratelimited("write data overflow: off=%u len=%zu buf=%u\n",
					   data_off, length, req_buf_len);
			err = -EINVAL;
			goto out;
		}

		data_buf = (char *)(((char *)&req->hdr.ProtocolId) +
				    le16_to_cpu(req->DataOffset));

		ksmbd_debug(SMB, "filename %pD, offset %lld, len %zu\n",
			    fp->filp, offset, length);

		if (unbuffered) {
			ssize_t dret;

			dret = smb2_direct_write(fp->filp, data_buf,
						 length, &offset);
			if (dret == -EOPNOTSUPP) {
				ksmbd_debug(SMB, "direct write not supported, falling back to buffered\n");
				unbuffered = false;
			} else if (dret < 0) {
				err = dret;
				goto out;
			} else {
				nbytes = dret;
			}
		}

		if (!unbuffered) {
			err = ksmbd_vfs_write(work, fp, data_buf, length,
					      &offset, writethrough, &nbytes);
			if (err < 0)
				goto out;
		}
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

	/* Invalidate BranchCache hashes on successful write */
	ksmbd_branchcache_invalidate(fp);

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
	if (rsp->hdr.Status == 0) {
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
		else if (err == -EBUSY)
			rsp->hdr.Status = STATUS_DELETE_PENDING;
		else
			rsp->hdr.Status = STATUS_INVALID_HANDLE;
	}

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
	struct ksmbd_file *fp;
	bool fullsync = false;
	int err;
	u64 id = KSMBD_NO_FID, pid = KSMBD_NO_FID;

	WORK_BUFFERS(work, req, rsp);

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

	ksmbd_debug(SMB, "Received smb2 flush request(fid : %llu)\n", id);

	/* MS-SMB2 §3.3.5.9: look up fp for access check and ChannelSequence */
	fp = ksmbd_lookup_fd_slow(work, id, pid);
	if (!fp) {
		/* MS-SMB2 §3.3.5.9: closed file handle → STATUS_FILE_CLOSED */
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		smb2_set_err_rsp(work);
		return -ENOENT;
	}

	/*
	 * MS-SMB2 §3.3.5.9 (FLUSH-1): caller must have write or append
	 * access before we honour the flush request.
	 */
	if (!(fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE))) {
		ksmbd_debug(SMB, "Flush: insufficient access (daccess=0x%x)\n",
			    fp->daccess);
		ksmbd_fd_put(work, fp);
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		smb2_set_err_rsp(work);
		return -EACCES;
	}

	/* MS-SMB2 §3.3.5.2.10: validate ChannelSequence before flushing */
	err = smb2_check_channel_sequence(work, fp);
	ksmbd_fd_put(work, fp);
	if (err) {
		rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;
		smb2_set_err_rsp(work);
		return err;
	}

	/*
	 * Apple F_FULLFSYNC: macOS Time Machine sends
	 * Reserved1=0xFFFF to request a full device flush.
	 */
#ifdef CONFIG_KSMBD_FRUIT
	if (work->conn->is_fruit && le16_to_cpu(req->Reserved1) == 0xFFFF)
		fullsync = true;
#endif

	err = ksmbd_vfs_fsync(work, id, pid, fullsync);
	if (err) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		smb2_set_err_rsp(work);
		return err;
	}

	rsp->StructureSize = cpu_to_le16(4);
	rsp->Reserved = 0;
	return ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_flush_rsp));
}
