// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_pdu_common.c - Shared helpers, signing, encryption, credit management
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

void __wbuf(struct ksmbd_work *work, void **req, void **rsp)
{
	if (work->next_smb2_rcv_hdr_off) {
		*req = ksmbd_req_buf_next(work);
		*rsp = ksmbd_resp_buf_next(work);
	} else {
		*req = smb2_get_msg(work->request_buf);
		*rsp = smb2_get_msg(work->response_buf);
	}
}

/**
 * smb2_check_channel_sequence() - validate ChannelSequence for state-modifying requests
 * @work: smb work containing the request
 * @fp:   open file handle
 *
 * MS-SMB2 §3.3.5.2.10: For dialects ≥ 2.1, state-modifying requests
 * (WRITE, LOCK, IOCTL, SET_INFO, FLUSH) carry a ChannelSequence in the
 * low 16 bits of the request header Status field.  If the sequence is
 * behind the last one seen on this open, the request is stale (e.g. a
 * retransmit after channel failover) and must be rejected.
 *
 * Return: 0 on success, -EAGAIN if the request should return
 *         STATUS_FILE_NOT_AVAILABLE to the client.
 */
int smb2_check_channel_sequence(struct ksmbd_work *work, struct ksmbd_file *fp)
{
	struct smb2_hdr *hdr = ksmbd_req_buf_next(work);
	__u16 req_seq;
	s16 diff;

	/* ChannelSequence only defined for dialect ≥ 2.1 */
	if (work->conn->dialect <= SMB20_PROT_ID)
		return 0;

	/*
	 * In request packets, the Status field (32-bit) is overlaid as:
	 *   bits [15:0]  = ChannelSequence
	 *   bits [31:16] = Reserved (MBZ)
	 */
	req_seq = (__u16)le32_to_cpu(hdr->Status);

	spin_lock(&fp->f_lock);
	diff = (s16)(req_seq - fp->channel_sequence);
	if (diff < 0) {
		/* Stale request: ChannelSequence is behind the open's last seen */
		spin_unlock(&fp->f_lock);
		pr_warn_ratelimited("ChannelSequence stale: req=%u open=%u\n",
				    req_seq, fp->channel_sequence);
		return -EAGAIN;
	}
	if (diff > 0)
		fp->channel_sequence = req_seq;
	spin_unlock(&fp->f_lock);
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(smb2_check_channel_sequence);

struct channel *lookup_chann_list(struct ksmbd_session *sess, struct ksmbd_conn *conn)
{
	return xa_load(&sess->ksmbd_chann_list, (long)conn);
}

/**
 * smb2_get_ksmbd_tcon() - get tree connection information using a tree id.
 * @work:	smb work
 *
 * Return:	0 if there is a tree connection matched or these are
 *		skipable commands, otherwise error
 */
int smb2_get_ksmbd_tcon(struct ksmbd_work *work)
{
	struct smb2_hdr *req_hdr = ksmbd_req_buf_next(work);
	unsigned int cmd = le16_to_cpu(req_hdr->Command);
	unsigned int tree_id;

	if (cmd == SMB2_TREE_CONNECT_HE ||
	    cmd ==  SMB2_CANCEL_HE ||
	    cmd ==  SMB2_LOGOFF_HE) {
		ksmbd_debug(SMB, "skip to check tree connect request\n");
		return 0;
	}

	if (xa_empty(&work->sess->tree_conns)) {
		ksmbd_debug(SMB, "NO tree connected\n");
		return -ENOENT;
	}

	tree_id = le32_to_cpu(req_hdr->Id.SyncId.TreeId);

	if (work->next_smb2_rcv_hdr_off) {
		bool is_related = !!(req_hdr->Flags &
				     SMB2_FLAGS_RELATED_OPERATIONS);

		if (is_related) {
			/*
			 * Related request: inherit tree connect from
			 * previous request.  If no tcon was
			 * established, return -EINVAL which maps to
			 * STATUS_INVALID_PARAMETER.
			 */
			if (!work->tcon)
				return -EINVAL;
			return 1;
		}

		/*
		 * Unrelated request in a compound: look up the
		 * tree connect independently by TreeId.
		 * Release the previous tcon reference first.
		 */
		if (work->tcon)
			ksmbd_tree_connect_put(work->tcon);
		work->tcon = ksmbd_tree_conn_lookup(work->sess, tree_id);
		if (!work->tcon) {
			pr_err_ratelimited("Invalid tid %d in compound\n",
					   tree_id);
			return -ENOENT;
		}
		return 1;
	}

	work->tcon = ksmbd_tree_conn_lookup(work->sess, tree_id);
	if (!work->tcon) {
		pr_err_ratelimited("Invalid tid %d\n", tree_id);
		return -ENOENT;
	}

	/*
	 * B.10: Per-session encryption enforcement at tree-connect level.
	 * MS-SMB2 §3.3.5.2.5 and §3.3.5.5.2: when the client established
	 * this session with SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA (resulting in
	 * sess->enc_forced == true and SESSION_FLAG_ENCRYPT_DATA set in the
	 * SESSION_SETUP response), ALL subsequent requests on this session
	 * MUST arrive encrypted.  Unencrypted requests on an
	 * encryption-required session are rejected with STATUS_ACCESS_DENIED
	 * and the connection is terminated.
	 *
	 * This check supplements the global KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION
	 * enforcement in server.c, covering the case where a client explicitly
	 * requested per-session encryption but the global flag is not set.
	 * Commands NEGOTIATE and SESSION_SETUP are exempt because they are used
	 * to establish the encrypted channel.
	 *
	 * Note: sess->enc means encryption keys are available; sess->enc_forced
	 * means encryption was actually negotiated as required (the server set
	 * SMB2_SESSION_FLAG_ENCRYPT_DATA in the SESSION_SETUP response).
	 */
	if (work->sess->enc_forced && !work->encrypted) {
		struct smb2_hdr *rsp_hdr = ksmbd_resp_buf_next(work);

		pr_warn_ratelimited("Unencrypted request (cmd=0x%x) on per-session encrypted session, disconnecting\n",
				    cmd);
		rsp_hdr->Status = STATUS_ACCESS_DENIED;
		smb2_set_err_rsp(work);
		ksmbd_conn_set_exiting(work->conn);
		return -EACCES;
	}

	return 1;
}

/**
 * smb2_set_err_rsp() - set error response code on smb response
 * @work:	smb work containing response buffer
 */
void smb2_set_err_rsp(struct ksmbd_work *work)
{
	struct smb2_err_rsp *err_rsp;

	if (work->next_smb2_rcv_hdr_off)
		err_rsp = ksmbd_resp_buf_next(work);
	else
		err_rsp = smb2_get_msg(work->response_buf);

	if (err_rsp->hdr.Status != STATUS_STOPPED_ON_SYMLINK) {
		int err;

		err_rsp->StructureSize = SMB2_ERROR_STRUCTURE_SIZE2_LE;
		err_rsp->ErrorContextCount = 0;
		err_rsp->Reserved = 0;
		err_rsp->ByteCount = 0;
		err_rsp->ErrorData[0] = 0;
		err = ksmbd_iov_pin_rsp(work, (void *)err_rsp,
					__SMB2_HEADER_STRUCTURE_SIZE +
					SMB2_ERROR_STRUCTURE_SIZE2);
		if (err)
			work->send_no_response = 1;
	}
}

/**
 * is_smb2_neg_cmd() - is it smb2 negotiation command
 * @work:	smb work containing smb header
 *
 * Return:      true if smb2 negotiation command, otherwise false
 */
bool is_smb2_neg_cmd(struct ksmbd_work *work)
{
	struct smb2_hdr *hdr = smb2_get_msg(work->request_buf);

	/* is it SMB2 header ? */
	if (hdr->ProtocolId != SMB2_PROTO_NUMBER)
		return false;

	/* make sure it is request not response message */
	if (hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR)
		return false;

	if (hdr->Command != SMB2_NEGOTIATE)
		return false;

	return true;
}

/**
 * is_smb2_rsp() - is it smb2 response
 * @work:	smb work containing smb response buffer
 *
 * Return:      true if smb2 response, otherwise false
 */
bool is_smb2_rsp(struct ksmbd_work *work)
{
	struct smb2_hdr *hdr = smb2_get_msg(work->response_buf);

	/* is it SMB2 header ? */
	if (hdr->ProtocolId != SMB2_PROTO_NUMBER)
		return false;

	/* make sure it is response not request message */
	if (!(hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR))
		return false;

	return true;
}

/**
 * get_smb2_cmd_val() - get smb command code from smb header
 * @work:	smb work containing smb request buffer
 *
 * Return:      smb2 request command value
 */
u16 get_smb2_cmd_val(struct ksmbd_work *work)
{
	struct smb2_hdr *rcv_hdr;

	if (work->next_smb2_rcv_hdr_off)
		rcv_hdr = ksmbd_req_buf_next(work);
	else
		rcv_hdr = smb2_get_msg(work->request_buf);
	return le16_to_cpu(rcv_hdr->Command);
}

/**
 * set_smb2_rsp_status() - set error response code on smb2 header
 * @work:	smb work containing response buffer
 * @err:	error response code
 */
void set_smb2_rsp_status(struct ksmbd_work *work, __le32 err)
{
	struct smb2_hdr *rsp_hdr;

	rsp_hdr = smb2_get_msg(work->response_buf);
	rsp_hdr->Status = err;

	work->iov_idx = 0;
	work->iov_cnt = 0;
	work->next_smb2_rcv_hdr_off = 0;
	smb2_set_err_rsp(work);
}

/**
 * init_smb2_neg_rsp() - initialize smb2 response for negotiate command
 * @work:	smb work containing smb request buffer
 *
 * smb2 negotiate response is sent in reply of smb1 negotiate command for
 * dialect auto-negotiation.
 */
int init_smb2_neg_rsp(struct ksmbd_work *work)
{
	struct smb2_hdr *rsp_hdr;
	struct smb2_negotiate_rsp *rsp;
	struct ksmbd_conn *conn = work->conn;
	int err;

	rsp_hdr = smb2_get_msg(work->response_buf);
	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);
	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->CreditRequest = cpu_to_le16(2);
	rsp_hdr->Command = SMB2_NEGOTIATE;
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = 0;
	rsp_hdr->Id.SyncId.ProcessId = 0;
	rsp_hdr->Id.SyncId.TreeId = 0;
	rsp_hdr->SessionId = 0;
	memset(rsp_hdr->Signature, 0, 16);

	rsp = smb2_get_msg(work->response_buf);

	WARN_ON(ksmbd_conn_good(conn));

	rsp->StructureSize = cpu_to_le16(65);
	ksmbd_debug(SMB, "conn->dialect 0x%x\n", conn->dialect);
	rsp->DialectRevision = cpu_to_le16(conn->dialect);
	/* Not setting conn guid rsp->ServerGUID, as it
	 * not used by client for identifying connection
	 */
	rsp->Capabilities = cpu_to_le32(conn->vals->capabilities);
	/* Default Max Message Size till SMB2.0, 64K*/
	rsp->MaxTransactSize = cpu_to_le32(conn->vals->max_trans_size);
	rsp->MaxReadSize = cpu_to_le32(conn->vals->max_read_size);
	rsp->MaxWriteSize = cpu_to_le32(conn->vals->max_write_size);

	rsp->SystemTime = cpu_to_le64(ksmbd_systime());
	rsp->ServerStartTime = 0;

	rsp->SecurityBufferOffset = cpu_to_le16(128);
	rsp->SecurityBufferLength = cpu_to_le16(AUTH_GSS_LENGTH);
	ksmbd_copy_gss_neg_header((char *)(&rsp->hdr) +
		le16_to_cpu(rsp->SecurityBufferOffset));
	rsp->SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED_LE;
	if (server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY)
		rsp->SecurityMode |= SMB2_NEGOTIATE_SIGNING_REQUIRED_LE;
	err = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_negotiate_rsp) +
				AUTH_GSS_LENGTH);
	if (err)
		return err;
	conn->use_spnego = true;

	ksmbd_conn_set_need_negotiate(conn);
	return 0;
}

/**
 * smb2_set_rsp_credits() - set number of credits in response buffer
 * @work:	smb work containing smb response buffer
 */
int smb2_set_rsp_credits(struct ksmbd_work *work)
{
	struct smb2_hdr *req_hdr = ksmbd_req_buf_next(work);
	struct smb2_hdr *hdr = ksmbd_resp_buf_next(work);
	struct ksmbd_conn *conn = work->conn;
	unsigned short credits_requested;
	unsigned short credit_charge, credits_granted = 0;

	credit_charge = max_t(unsigned short,
			      le16_to_cpu(req_hdr->CreditCharge), 1);

	/* TC-04: send_no_response means no response is sent, so outstanding_credits
	 * must be decremented here since smb2_set_rsp_credits won't process credits.
	 */
	if (work->send_no_response) {
		spin_lock(&conn->credits_lock);
		if (credit_charge > conn->outstanding_credits)
			conn->outstanding_credits = 0;
		else
			conn->outstanding_credits -= credit_charge;
		spin_unlock(&conn->credits_lock);
		return 0;
	}

	hdr->CreditCharge = req_hdr->CreditCharge;

	if (conn->total_credits > conn->vals->max_credits) {
		hdr->CreditRequest = 0;
		pr_err_ratelimited("Total credits overflow: %d\n", conn->total_credits);
		return -EINVAL;
	}

	ksmbd_debug(SMB,
		    "credit_rsp: lock_enter cmd=%u charge=%u req=%u total=%u out=%u granted_total=%u\n",
		    le16_to_cpu(req_hdr->Command), credit_charge,
		    le16_to_cpu(req_hdr->CreditRequest), conn->total_credits,
		    conn->outstanding_credits, work->credits_granted);
	spin_lock(&conn->credits_lock);
	if (credit_charge > conn->total_credits) {
		spin_unlock(&conn->credits_lock);
		ksmbd_debug(SMB, "Insufficient credits granted, given: %u, granted: %u\n",
			    credit_charge, conn->total_credits);
		return -EINVAL;
	}

	conn->total_credits -= credit_charge;
	if (credit_charge > conn->outstanding_credits) {
		pr_err_ratelimited("Outstanding credits underflow: charge %u, outstanding %u\n",
		       credit_charge, conn->outstanding_credits);
		conn->outstanding_credits = 0;
	} else {
		conn->outstanding_credits -= credit_charge;
	}
	credits_requested = max_t(unsigned short,
				  le16_to_cpu(req_hdr->CreditRequest), 1);

	/* Spec-compliant credit grant per MS-SMB2 §3.3.4.2:
	 *   available = MaxCredits - Connection.CreditBalance + CreditCharge
	 *   grant = min(CreditRequest, max(1, available))
	 *
	 * Note: total_credits has already been decremented by credit_charge
	 * above, so available = max_credits - total_credits.
	 *
	 * Windows Server 2016+ grants up to 8192 credits at once.
	 */
	if (hdr->Command == SMB2_NEGOTIATE) {
		credits_granted = 1;
	} else {
		u16 max_grant = conn->vals->max_credits;
		u16 available;

		available = (max_grant > conn->total_credits) ?
			    max_grant - conn->total_credits : 0;
		credits_granted = min_t(u16, credits_requested,
					max_t(u16, 1, available));
	}

	conn->total_credits += credits_granted;
	work->credits_granted += credits_granted;
	ksmbd_debug(SMB,
		    "credit_rsp: lock_exit cmd=%u charge=%u req=%u granted=%u total=%u out=%u granted_total=%u\n",
		    le16_to_cpu(req_hdr->Command), credit_charge,
		    credits_requested, credits_granted, conn->total_credits,
		    conn->outstanding_credits, work->credits_granted);
	spin_unlock(&conn->credits_lock);

	if (!req_hdr->NextCommand) {
		/* Update CreditRequest in last request */
		hdr->CreditRequest = cpu_to_le16(work->credits_granted);
	}
	ksmbd_debug(SMB,
		    "credits: requested[%d] granted[%d] total_granted[%d]\n",
		    credits_requested, credits_granted,
		    conn->total_credits);
	return 0;
}

/**
 * init_chained_smb2_rsp() - initialize smb2 chained response
 * @work:	smb work containing smb response buffer
 */
VISIBLE_IF_KUNIT void init_chained_smb2_rsp(struct ksmbd_work *work)
{
	struct smb2_hdr *req = ksmbd_req_buf_next(work);
	struct smb2_hdr *rsp = ksmbd_resp_buf_next(work);
	struct smb2_hdr *rsp_hdr;
	struct smb2_hdr *rcv_hdr;
	int next_hdr_offset = 0;
	int len, new_len;

	/* Len of this response = updated RFC len - offset of previous cmd
	 * in the compound rsp
	 */

	/* Storing the current local FID which may be needed by subsequent
	 * command in the compound request
	 */
	if (req->Command == SMB2_CREATE) {
		if (rsp->Status == STATUS_SUCCESS) {
			work->compound_fid = ((struct smb2_create_rsp *)rsp)->VolatileFileId;
			work->compound_pfid = ((struct smb2_create_rsp *)rsp)->PersistentFileId;
			work->compound_sid = le64_to_cpu(rsp->SessionId);
		} else {
			/*
			 * CREATE failed: record the error so that
			 * subsequent related operations propagate it.
			 */
			work->compound_err_status = rsp->Status;
		}
	} else if (rsp->Status == STATUS_SUCCESS &&
		   !has_file_id(work->compound_fid)) {
		/*
		 * MS-SMB2 §3.3.5.2.7.2: For related compound requests,
		 * if the next request has VolatileFileId = 0xFFFFFFFFFFFFFFFF,
		 * the server uses the FID from the previous operation.
		 * Capture the FID from non-CREATE commands that succeeded
		 * so subsequent related operations can reference it.
		 */
		u64 vol = KSMBD_NO_FID, per = KSMBD_NO_FID;

		switch (req->Command) {
		case SMB2_CLOSE:
		{
			struct smb2_close_req *r = (void *)req;

			vol = r->VolatileFileId;
			per = r->PersistentFileId;
			break;
		}
		case SMB2_FLUSH:
		{
			struct smb2_flush_req *r = (void *)req;

			vol = r->VolatileFileId;
			per = r->PersistentFileId;
			break;
		}
		case SMB2_READ:
		{
			struct smb2_read_req *r = (void *)req;

			vol = r->VolatileFileId;
			per = r->PersistentFileId;
			break;
		}
		case SMB2_WRITE:
		{
			struct smb2_write_req *r = (void *)req;

			vol = r->VolatileFileId;
			per = r->PersistentFileId;
			break;
		}
		case SMB2_QUERY_INFO:
		{
			struct smb2_query_info_req *r = (void *)req;

			vol = r->VolatileFileId;
			per = r->PersistentFileId;
			break;
		}
		case SMB2_SET_INFO:
		{
			struct smb2_set_info_req *r = (void *)req;

			vol = r->VolatileFileId;
			per = r->PersistentFileId;
			break;
		}
		case SMB2_LOCK:
		{
			struct smb2_lock_req *r = (void *)req;

			vol = r->VolatileFileId;
			per = r->PersistentFileId;
			break;
		}
		case SMB2_IOCTL:
		{
			struct smb2_ioctl_req *r = (void *)req;

			vol = r->VolatileFileId;
			per = r->PersistentFileId;
			break;
		}
		case SMB2_QUERY_DIRECTORY:
		{
			struct smb2_query_directory_req *r = (void *)req;

			vol = r->VolatileFileId;
			per = r->PersistentFileId;
			break;
		}
		case SMB2_CHANGE_NOTIFY:
		{
			struct smb2_notify_req *r = (void *)req;

			vol = r->VolatileFileId;
			per = r->PersistentFileId;
			break;
		}
		default:
			break;
		}

		if (has_file_id(vol)) {
			work->compound_fid = vol;
			work->compound_pfid = per;
			work->compound_sid = le64_to_cpu(rsp->SessionId);
		}
	} else if (req->Flags & SMB2_FLAGS_RELATED_OPERATIONS &&
		   rsp->Status != STATUS_SUCCESS &&
		   !has_file_id(work->compound_fid) &&
		   work->compound_err_status == STATUS_SUCCESS) {
		/*
		 * Non-CREATE related request failed and no compound
		 * file handle was established.  Propagate this error
		 * to subsequent related requests (e.g. NOTIFY failing
		 * with INVALID_PARAMETER should cascade to CLOSE).
		 *
		 * We only do this when compound_fid is invalid (no
		 * successful CREATE preceded this) and compound_err_status
		 * is not already set, so that a valid compound handle
		 * from a successful CREATE is never overridden.
		 */
		work->compound_err_status = rsp->Status;
	}

	len = get_rfc1002_len(work->response_buf) - work->next_smb2_rsp_hdr_off;
	next_hdr_offset = le32_to_cpu(req->NextCommand);

	new_len = ALIGN(len, 8);
	work->iov[work->iov_idx].iov_len += (new_len - len);
	inc_rfc1001_len(work->response_buf, new_len - len);
	rsp->NextCommand = cpu_to_le32(new_len);

	work->next_smb2_rcv_hdr_off += next_hdr_offset;
	work->curr_smb2_rsp_hdr_off = work->next_smb2_rsp_hdr_off;
	work->next_smb2_rsp_hdr_off += new_len;
	ksmbd_debug(SMB,
		    "Compound req new_len = %d rcv off = %d rsp off = %d\n",
		    new_len, work->next_smb2_rcv_hdr_off,
		    work->next_smb2_rsp_hdr_off);

	rsp_hdr = ksmbd_resp_buf_next(work);
	rcv_hdr = ksmbd_req_buf_next(work);

	if (!(rcv_hdr->Flags & SMB2_FLAGS_RELATED_OPERATIONS)) {
		ksmbd_debug(SMB, "related flag should be set\n");
		work->compound_fid = KSMBD_NO_FID;
		work->compound_pfid = KSMBD_NO_FID;
		/* TC-22: reset compound_sid for unrelated compound requests */
		work->compound_sid = 0;
		work->compound_err_status = STATUS_SUCCESS;
	}
	memset((char *)rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);
	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->Command = rcv_hdr->Command;

	/*
	 * Message is response. We don't grant oplock yet.
	 */
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR |
				SMB2_FLAGS_RELATED_OPERATIONS);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = rcv_hdr->MessageId;
	rsp_hdr->Id.SyncId.ProcessId = rcv_hdr->Id.SyncId.ProcessId;
	rsp_hdr->Id.SyncId.TreeId = rcv_hdr->Id.SyncId.TreeId;
	rsp_hdr->SessionId = rcv_hdr->SessionId;
	/* TC-11: zero Signature in compound response header (MS-SMB2 §3.3.4.1) */
	memset(rsp_hdr->Signature, 0, 16);
}
EXPORT_SYMBOL_IF_KUNIT(init_chained_smb2_rsp);

/**
 * is_chained_smb2_message() - check for chained command
 * @work:	smb work containing smb request buffer
 *
 * Return:      true if chained request, otherwise false
 */
bool is_chained_smb2_message(struct ksmbd_work *work)
{
	struct smb2_hdr *hdr = smb2_get_msg(work->request_buf);
	unsigned int next_cmd;

	if (hdr->ProtocolId != SMB2_PROTO_NUMBER)
		return false;

	hdr = ksmbd_req_buf_next(work);
	next_cmd = le32_to_cpu(hdr->NextCommand);
	if (next_cmd > 0) {
		if ((u64)work->next_smb2_rcv_hdr_off + next_cmd +
			__SMB2_HEADER_STRUCTURE_SIZE >
		    get_rfc1002_len(work->request_buf)) {
			pr_err_ratelimited("next command(%u) offset exceeds smb msg size\n",
					   next_cmd);
			return false;
		}

		if ((u64)get_rfc1002_len(work->response_buf) + MAX_CIFS_SMALL_BUFFER_SIZE >
		    work->response_sz) {
			pr_err_ratelimited("next response offset exceeds response buffer size\n");
			return false;
		}

		ksmbd_debug(SMB, "got SMB2 chained command\n");
		init_chained_smb2_rsp(work);
		return true;
	} else if (work->next_smb2_rcv_hdr_off) {
		/*
		 * This is the last request in a chained command.
		 * Per MS-SMB2 3.3.4.1.3, the last response SHOULD
		 * also be padded to 8-byte alignment.  Windows and
		 * Samba both do this, and smbtorture tests require it.
		 */
		int len, pad;

		len = get_rfc1002_len(work->response_buf);
		pad = ALIGN(len, 8) - len;
		if (pad) {
			work->iov[work->iov_idx].iov_len += pad;
			inc_rfc1001_len(work->response_buf, pad);
		}
		work->curr_smb2_rsp_hdr_off = work->next_smb2_rsp_hdr_off;
	}
	return false;
}

/**
 * init_smb2_rsp_hdr() - initialize smb2 response
 * @work:	smb work containing smb request buffer
 *
 * Return:      0
 */
int init_smb2_rsp_hdr(struct ksmbd_work *work)
{
	struct smb2_hdr *rsp_hdr = smb2_get_msg(work->response_buf);
	struct smb2_hdr *rcv_hdr = smb2_get_msg(work->request_buf);

	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);
	rsp_hdr->ProtocolId = rcv_hdr->ProtocolId;
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->Command = rcv_hdr->Command;

	/*
	 * Message is response. We don't grant oplock yet.
	 */
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = rcv_hdr->MessageId;
	rsp_hdr->Id.SyncId.ProcessId = rcv_hdr->Id.SyncId.ProcessId;
	rsp_hdr->Id.SyncId.TreeId = rcv_hdr->Id.SyncId.TreeId;
	rsp_hdr->SessionId = rcv_hdr->SessionId;
	memcpy(rsp_hdr->Signature, rcv_hdr->Signature, 16);

	return 0;
}

/**
 * smb2_allocate_rsp_buf() - allocate smb2 response buffer
 * @work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_allocate_rsp_buf(struct ksmbd_work *work)
{
	struct smb2_hdr *hdr = smb2_get_msg(work->request_buf);
	size_t small_sz = MAX_CIFS_SMALL_BUFFER_SIZE;
	size_t large_sz = small_sz + work->conn->vals->max_trans_size;
	size_t sz = small_sz;
	int cmd = le16_to_cpu(hdr->Command);

	if (cmd == SMB2_IOCTL_HE || cmd == SMB2_QUERY_DIRECTORY_HE)
		sz = large_sz;

	if (cmd == SMB2_QUERY_INFO_HE) {
		struct smb2_query_info_req *req;

		if (get_rfc1002_len(work->request_buf) <
		    offsetof(struct smb2_query_info_req, OutputBufferLength))
			return -EINVAL;

		req = smb2_get_msg(work->request_buf);
		if ((req->InfoType == SMB2_O_INFO_FILE &&
		     (req->FileInfoClass == FILE_FULL_EA_INFORMATION ||
		     req->FileInfoClass == FILE_ALL_INFORMATION)) ||
		    req->InfoType == SMB2_O_INFO_SECURITY)
			sz = large_sz;
	}

	/* allocate large response buf for chained commands */
	if (le32_to_cpu(hdr->NextCommand) > 0)
		sz = large_sz;

	work->response_buf = kvzalloc(sz, KSMBD_DEFAULT_GFP);
	if (!work->response_buf)
		return -ENOMEM;

	work->response_sz = sz;
	return 0;
}

/**
 * smb2_check_user_session() - check for valid session for a user
 * @work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_check_user_session(struct ksmbd_work *work)
{
	struct smb2_hdr *req_hdr = ksmbd_req_buf_next(work);
	struct ksmbd_conn *conn = work->conn;
	unsigned int cmd = le16_to_cpu(req_hdr->Command);
	unsigned long long sess_id;

	/*
	 * SMB2_ECHO, SMB2_NEGOTIATE, SMB2_SESSION_SETUP command do not
	 * require a session id, so no need to validate user session's for
	 * these commands.
	 */
	if (cmd == SMB2_ECHO_HE || cmd == SMB2_NEGOTIATE_HE ||
	    cmd == SMB2_SESSION_SETUP_HE)
		return 0;

	if (!ksmbd_conn_good(conn))
		return -EIO;

	sess_id = le64_to_cpu(req_hdr->SessionId);

	if (work->next_smb2_rcv_hdr_off) {
		bool is_related = !!(req_hdr->Flags &
				     SMB2_FLAGS_RELATED_OPERATIONS);

		if (is_related) {
			/*
			 * Related request: inherit session from
			 * previous request in the compound chain.
			 * If no session was established (previous
			 * request failed), return -EINVAL which maps
			 * to STATUS_INVALID_PARAMETER per MS-SMB2
			 * 3.3.5.2.3.
			 */
			if (!work->sess)
				return -EINVAL;
			return 1;
		}

		/*
		 * Unrelated request in a compound: look up the
		 * session independently by the SessionId in the
		 * request header, just like a first request.
		 * Release the previous session reference first to
		 * avoid refcount leaks.
		 */
		if (work->sess)
			ksmbd_user_session_put(work->sess);
		work->sess = ksmbd_session_lookup_all(conn, sess_id);
		if (work->sess)
			return 1;
		ksmbd_debug(SMB, "Invalid user session in compound, Uid %llu\n",
			    sess_id);
		return -ENOENT;
	}

	/* Check for validity of user session */
	work->sess = ksmbd_session_lookup_all(conn, sess_id);
	if (work->sess)
		return 1;
	ksmbd_debug(SMB, "Invalid user session, Uid %llu\n", sess_id);
	return -ENOENT;
}

/**
 * smb2_get_name() - get filename string from on the wire smb format
 * @src:	source buffer
 * @maxlen:	maxlen of source string
 * @local_nls:	nls_table pointer
 *
 * Return:      matching converted filename on success, otherwise error ptr
 */
char *
smb2_get_name(const char *src, const int maxlen, struct nls_table *local_nls)
{
	char *name;

	name = smb_strndup_from_utf16(src, maxlen, 1, local_nls);
	if (IS_ERR(name)) {
		pr_err("failed to get name %ld\n", PTR_ERR(name));
		return name;
	}

	if (*name == '\0') {
		kfree(name);
		return ERR_PTR(-EINVAL);
	}

	if (*name == '\\') {
		pr_err("not allow directory name included leading slash\n");
		kfree(name);
		return ERR_PTR(-EINVAL);
	}

	ksmbd_conv_path_to_unix(name);
	ksmbd_strip_last_slash(name);
	return name;
}

int setup_async_work(struct ksmbd_work *work, void (*fn)(void **), void **arg)
{
	struct ksmbd_conn *conn = work->conn;
	int id;
	unsigned int max_async = READ_ONCE(server_conf.max_async_credits);

	/*
	 * Enforce the max async credits limit.  When the number of
	 * outstanding async operations reaches the limit, reject
	 * with -ENOSPC which the caller maps to
	 * STATUS_INSUFFICIENT_RESOURCES.
	 */
	if (max_async &&
	    atomic_inc_return(&conn->outstanding_async) >= max_async) {
		atomic_dec(&conn->outstanding_async);
		return -ENOSPC;
	}

	id = ksmbd_acquire_async_msg_id(&conn->async_ida);
	if (id < 0) {
		pr_err("Failed to alloc async message id\n");
		if (max_async)
			atomic_dec(&conn->outstanding_async);
		return id;
	}
	work->asynchronous = true;
	work->async_id = id;

	ksmbd_debug(SMB,
		    "Send interim Response to inform async request id : %d\n",
		    work->async_id);

	work->cancel_fn = fn;
	work->cancel_argv = arg;

	if (list_empty(&work->async_request_entry)) {
		spin_lock(&conn->request_lock);
		list_add_tail(&work->async_request_entry, &conn->async_requests);
		spin_unlock(&conn->request_lock);
	}

	return 0;
}

void release_async_work(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;

	spin_lock(&conn->request_lock);
	list_del_init(&work->async_request_entry);
	spin_unlock(&conn->request_lock);

	work->asynchronous = 0;
	work->cancel_fn = NULL;
	kfree(work->cancel_argv);
	work->cancel_argv = NULL;
	if (work->async_id) {
		ksmbd_release_id(&conn->async_ida, work->async_id);
		work->async_id = 0;
		/* Decrement outstanding async count */
		if (READ_ONCE(server_conf.max_async_credits))
			atomic_dec(&conn->outstanding_async);
	}
}

void smb2_send_interim_resp(struct ksmbd_work *work, __le32 status)
{
	struct smb2_hdr *rsp_hdr;
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_work *in_work = ksmbd_alloc_work_struct();

	if (!in_work)
		return;

	if (allocate_interim_rsp_buf(in_work)) {
		pr_err("smb_allocate_rsp_buf failed!\n");
		ksmbd_free_work_struct(in_work);
		return;
	}

	in_work->conn = conn;
	in_work->sess = work->sess;
	in_work->encrypted = work->encrypted;
	memcpy(smb2_get_msg(in_work->response_buf), ksmbd_resp_buf_next(work),
	       __SMB2_HEADER_STRUCTURE_SIZE);

	rsp_hdr = smb2_get_msg(in_work->response_buf);
	rsp_hdr->Flags |= SMB2_FLAGS_ASYNC_COMMAND;
	rsp_hdr->Id.AsyncId = cpu_to_le64(work->async_id);
	smb2_set_err_rsp(in_work);
	rsp_hdr->Status = status;

	/* Encrypt the interim response if the session requires encryption */
	if (in_work->sess && in_work->sess->enc && in_work->encrypted &&
	    conn->ops->encrypt_resp) {
		int rc;

		rc = conn->ops->encrypt_resp(in_work);
		if (rc) {
			ksmbd_debug(SMB,
				    "Failed to encrypt interim response: %d\n",
				    rc);
		}
	}

	ksmbd_conn_write(in_work);
	ksmbd_free_work_struct(in_work);
}

__le32 smb2_get_reparse_tag_special_file(umode_t mode)
{
	if (S_ISDIR(mode) || S_ISREG(mode))
		return 0;

	if (S_ISLNK(mode))
		return IO_REPARSE_TAG_LX_SYMLINK_LE;
	else if (S_ISFIFO(mode))
		return IO_REPARSE_TAG_LX_FIFO_LE;
	else if (S_ISSOCK(mode))
		return IO_REPARSE_TAG_AF_UNIX_LE;
	else if (S_ISCHR(mode))
		return IO_REPARSE_TAG_LX_CHR_LE;
	else if (S_ISBLK(mode))
		return IO_REPARSE_TAG_LX_BLK_LE;

	return 0;
}

/**
 * smb2_get_dos_mode() - get file mode in dos format from unix mode
 * @stat:	kstat containing file mode
 * @attribute:	attribute flags
 *
 * Return:      converted dos mode
 */
int smb2_get_dos_mode(struct kstat *stat, int attribute)
{
	int attr = 0;

	if (S_ISDIR(stat->mode)) {
		attr = ATTR_DIRECTORY |
			(attribute & (ATTR_HIDDEN | ATTR_SYSTEM));
	} else {
		attr = (attribute & 0x00005137) | ATTR_ARCHIVE;
		attr &= ~(ATTR_DIRECTORY);

		if (smb2_get_reparse_tag_special_file(stat->mode))
			attr |= ATTR_REPARSE;
	}

	return attr;
}

bool smb2_is_sign_req(struct ksmbd_work *work, unsigned int command)
{
	struct smb2_hdr *rcv_hdr;

	/*
	 * B.11: MS-SMB2 §3.3.5.16 — "The server MUST NOT require the
	 * SMB2 CANCEL Request to be signed."  Exclude CANCEL from signing
	 * enforcement so that legitimate cancel requests on signing-required
	 * sessions are not incorrectly rejected with STATUS_ACCESS_DENIED.
	 *
	 * B.12: SMB2_OPLOCK_BREAK_HE is excluded unconditionally here so
	 * that server-to-client oplock break notifications (which have no
	 * client signature) are not rejected.  Client acknowledgments that
	 * arrive with SMB2_FLAGS_SIGNED set will be verified through the
	 * SMB2_FLAGS_SIGNED branch below.
	 */
	if (command == SMB2_NEGOTIATE_HE ||
	    command == SMB2_CANCEL_HE ||
	    command == SMB2_OPLOCK_BREAK_HE)
		return false;

	/*
	 * For compound sub-requests, use the current request header.
	 * For single requests or the first compound request, use the
	 * first (and only) header.
	 */
	if (work->next_smb2_rcv_hdr_off) {
		rcv_hdr = ksmbd_req_buf_next(work);

		/*
		 * MS-SMB2 §3.3.5.2.3: Related compound sub-requests
		 * inherit the session/signing context of the first
		 * request.  The server MUST NOT verify their signatures.
		 */
		if (rcv_hdr->Flags & SMB2_FLAGS_RELATED_OPERATIONS)
			return false;
	} else {
		rcv_hdr = smb2_get_msg(work->request_buf);
	}

	/*
	 * SESSION_SETUP: skip signing for initial auth (no key yet),
	 * but require it when SMB2_FLAGS_SIGNED is set (binding requests).
	 */
	if (command == SMB2_SESSION_SETUP_HE &&
	    !(rcv_hdr->Flags & SMB2_FLAGS_SIGNED))
		return false;

	if ((rcv_hdr->Flags & SMB2_FLAGS_SIGNED) ||
	    (work->sess && work->sess->sign))
		return true;

	return false;
}

/**
 * smb2_check_sign_req() - handler for req packet sign processing
 * @work:   smb work containing notify command buffer
 *
 * Return:	1 on success, 0 otherwise
 */
int smb2_check_sign_req(struct ksmbd_work *work)
{
	struct smb2_hdr *hdr;
	char signature_req[SMB2_SIGNATURE_SIZE];
	char signature[SMB2_HMACSHA256_SIZE];
	struct kvec iov[1];
	size_t len;

	if (!work->sess)
		return 0;

	hdr = smb2_get_msg(work->request_buf);
	if (work->next_smb2_rcv_hdr_off)
		hdr = ksmbd_req_buf_next(work);

	/*
	 * B.11: MS-SMB2 §3.3.5.16 — CANCEL must NOT be verified even on
	 * signing-required sessions. This is a defence-in-depth guard;
	 * smb2_is_sign_req() already excludes CANCEL from signing
	 * enforcement so check_sign_req() should not normally be called
	 * for CANCEL, but add the check here as an explicit safety net.
	 */
	if (le16_to_cpu(hdr->Command) == SMB2_CANCEL_HE)
		return 1;

	if (!hdr->NextCommand && !work->next_smb2_rcv_hdr_off)
		len = get_rfc1002_len(work->request_buf);
	else if (hdr->NextCommand)
		len = le32_to_cpu(hdr->NextCommand);
	else
		len = get_rfc1002_len(work->request_buf) -
			work->next_smb2_rcv_hdr_off;

	memcpy(signature_req, hdr->Signature, SMB2_SIGNATURE_SIZE);
	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);

	iov[0].iov_base = (char *)&hdr->ProtocolId;
	iov[0].iov_len = len;

	if (ksmbd_sign_smb2_pdu(work->conn, work->sess->sess_key, iov, 1,
				signature))
		return 0;

	if (crypto_memneq(signature, signature_req, SMB2_SIGNATURE_SIZE)) {
		pr_err_ratelimited("bad smb2 signature\n");
		return 0;
	}

	return 1;
}

/**
 * smb2_set_sign_rsp() - handler for rsp packet sign processing
 * @work:   smb work containing notify command buffer
 *
 */
void smb2_set_sign_rsp(struct ksmbd_work *work)
{
	struct smb2_hdr *hdr;
	char signature[SMB2_HMACSHA256_SIZE];
	struct kvec *iov;
	int n_vec = 1;

	hdr = ksmbd_resp_buf_curr(work);
	hdr->Flags |= SMB2_FLAGS_SIGNED;
	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);

	if (hdr->Command == SMB2_READ) {
		if (work->iov_idx == 0)
			return;
		/* Need at least 2 iov entries: header + read data */
		if (work->iov_idx < 1 ||
		    work->iov_idx + 1 > work->iov_cnt) {
			pr_err("invalid iov state for READ signing: idx=%d cnt=%d\n",
			       work->iov_idx, work->iov_cnt);
			return;
		}
		iov = &work->iov[work->iov_idx - 1];
		n_vec++;
	} else {
		if (work->iov_idx >= work->iov_cnt) {
			pr_err("invalid iov index for signing: idx=%d cnt=%d\n",
			       work->iov_idx, work->iov_cnt);
			return;
		}
		iov = &work->iov[work->iov_idx];
	}

	if (!ksmbd_sign_smb2_pdu(work->conn, work->sess->sess_key, iov, n_vec,
				 signature))
		memcpy(hdr->Signature, signature, SMB2_SIGNATURE_SIZE);
}

/**
 * smb3_check_sign_req() - handler for req packet sign processing
 * @work:   smb work containing notify command buffer
 *
 * Return:	1 on success, 0 otherwise
 */
int smb3_check_sign_req(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_hdr *hdr;
	struct channel *chann;
	char signature_req[SMB2_SIGNATURE_SIZE];
	/*
	 * Use SMB2_HMACSHA256_SIZE (32) as the signing buffer size
	 * to accommodate HMAC-SHA-256 which produces 32 bytes.
	 * AES-CMAC and AES-GMAC produce 16 bytes.
	 * Only the first SMB2_SIGNATURE_SIZE (16) bytes are compared.
	 */
	char signature[SMB2_HMACSHA256_SIZE];
	/*
	 * TC-22: Copy the signing key into a local stack buffer under RCU
	 * before performing HMAC.  Without this, a concurrent
	 * smb2_session_logoff() on another channel can free
	 * chann->smb3signingkey (via memzero_explicit + kfree) while our
	 * HMAC crypto operation is still reading it — use-after-free on
	 * key material.  After the copy we hold no reference to chann.
	 */
	char signing_key[SMB3_SIGN_KEY_SIZE];
	struct kvec iov[1];
	size_t len;

	if (!work->sess)
		return 0;

	hdr = smb2_get_msg(work->request_buf);
	if (work->next_smb2_rcv_hdr_off)
		hdr = ksmbd_req_buf_next(work);

	/*
	 * B.11: CANCEL must not be signature-verified (MS-SMB2 §3.3.5.16).
	 * Defence-in-depth: smb2_is_sign_req() already gates this, but
	 * be explicit in both SMB2 and SMB3 check paths.
	 */
	if (le16_to_cpu(hdr->Command) == SMB2_CANCEL_HE)
		return 1;

	if (!hdr->NextCommand && !work->next_smb2_rcv_hdr_off)
		len = get_rfc1002_len(work->request_buf);
	else if (hdr->NextCommand)
		len = le32_to_cpu(hdr->NextCommand);
	else
		len = get_rfc1002_len(work->request_buf) -
			work->next_smb2_rcv_hdr_off;

	if (le16_to_cpu(hdr->Command) == SMB2_SESSION_SETUP_HE) {
		memcpy(signing_key, work->sess->smb3signingkey,
		       SMB3_SIGN_KEY_SIZE);
	} else {
		rcu_read_lock();
		chann = lookup_chann_list(work->sess, conn);
		if (!chann) {
			rcu_read_unlock();
			return 0;
		}
		memcpy(signing_key, chann->smb3signingkey, SMB3_SIGN_KEY_SIZE);
		rcu_read_unlock();
	}

	if (!memchr_inv(signing_key, 0, SMB3_SIGN_KEY_SIZE)) {
		pr_err("SMB3 signing key is not generated\n");
		memzero_explicit(signing_key, SMB3_SIGN_KEY_SIZE);
		return 0;
	}

	memcpy(signature_req, hdr->Signature, SMB2_SIGNATURE_SIZE);
	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);
	iov[0].iov_base = (char *)&hdr->ProtocolId;
	iov[0].iov_len = len;

	if (conn->signing_algorithm == SIGNING_ALG_AES_GMAC) {
		if (ksmbd_sign_smb3_pdu_gmac(conn, signing_key, iov, 1,
					      signature)) {
			memzero_explicit(signing_key, SMB3_SIGN_KEY_SIZE);
			return 0;
		}
	} else if (conn->signing_algorithm == SIGNING_ALG_HMAC_SHA256) {
		if (ksmbd_sign_smb2_pdu(conn, signing_key, iov, 1, signature)) {
			memzero_explicit(signing_key, SMB3_SIGN_KEY_SIZE);
			return 0;
		}
	} else {
		if (ksmbd_sign_smb3_pdu(conn, signing_key, iov, 1, signature)) {
			memzero_explicit(signing_key, SMB3_SIGN_KEY_SIZE);
			return 0;
		}
	}

	memzero_explicit(signing_key, SMB3_SIGN_KEY_SIZE);

	if (crypto_memneq(signature, signature_req, SMB2_SIGNATURE_SIZE)) {
		pr_err_ratelimited("bad smb2 signature\n");
		return 0;
	}

	return 1;
}

/**
 * smb3_set_sign_rsp() - handler for rsp packet sign processing
 * @work:   smb work containing notify command buffer
 *
 */
void smb3_set_sign_rsp(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_hdr *hdr;
	struct channel *chann;
	char signature[SMB2_HMACSHA256_SIZE];
	struct kvec *iov;
	int n_vec = 1;
	char *signing_key;
	int rc;

	hdr = ksmbd_resp_buf_curr(work);

	if (conn->binding == false &&
	    le16_to_cpu(hdr->Command) == SMB2_SESSION_SETUP_HE) {
		signing_key = work->sess->smb3signingkey;
	} else {
		chann = lookup_chann_list(work->sess, work->conn);
		if (!chann) {
			return;
		}
		signing_key = chann->smb3signingkey;
	}

	if (!signing_key) {
		pr_warn_once("SMB3 signing key not available for response\n");
		return;
	}

	hdr->Flags |= SMB2_FLAGS_SIGNED;
	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);

	if (hdr->Command == SMB2_READ) {
		if (work->iov_idx == 0)
			return;
		/* Need at least 2 iov entries: header + read data */
		if (work->iov_idx < 1 ||
		    work->iov_idx + 1 > work->iov_cnt) {
			pr_err("invalid iov state for READ signing: idx=%d cnt=%d\n",
			       work->iov_idx, work->iov_cnt);
			return;
		}
		iov = &work->iov[work->iov_idx - 1];
		n_vec++;
	} else {
		if (work->iov_idx >= work->iov_cnt) {
			pr_err("invalid iov index for signing: idx=%d cnt=%d\n",
			       work->iov_idx, work->iov_cnt);
			return;
		}
		iov = &work->iov[work->iov_idx];
	}

	if (conn->signing_algorithm == SIGNING_ALG_AES_GMAC)
		rc = ksmbd_sign_smb3_pdu_gmac(conn, signing_key, iov, n_vec,
					       signature);
	else if (conn->signing_algorithm == SIGNING_ALG_HMAC_SHA256)
		rc = ksmbd_sign_smb2_pdu(conn, signing_key, iov, n_vec,
					 signature);
	else
		rc = ksmbd_sign_smb3_pdu(conn, signing_key, iov, n_vec,
					 signature);
	if (!rc)
		memcpy(hdr->Signature, signature, SMB2_SIGNATURE_SIZE);
}

/**
 * smb3_preauth_hash_rsp() - handler for computing preauth hash on response
 * @work:   smb work containing response buffer
 *
 */
void smb3_preauth_hash_rsp(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	struct smb2_hdr *req, *rsp;

	if (conn->dialect != SMB311_PROT_ID)
		return;

	WORK_BUFFERS(work, req, rsp);

	if (le16_to_cpu(req->Command) == SMB2_NEGOTIATE_HE &&
	    conn->preauth_info)
		ksmbd_gen_preauth_integrity_hash(conn, work->response_buf,
						 conn->preauth_info->Preauth_HashValue);

	if (le16_to_cpu(rsp->Command) == SMB2_SESSION_SETUP_HE && sess) {
		if (conn->binding) {
			struct preauth_session *preauth_sess;

			down_write(&conn->session_lock);
			preauth_sess = ksmbd_preauth_session_lookup(conn, sess->id);
			if (!preauth_sess) {
				up_write(&conn->session_lock);
				return;
			}
			ksmbd_gen_preauth_integrity_hash(conn, work->response_buf,
							 preauth_sess->Preauth_HashValue);
			up_write(&conn->session_lock);
			return;
		} else {
			if (!sess->Preauth_HashValue)
				return;
			ksmbd_gen_preauth_integrity_hash(conn, work->response_buf,
							 sess->Preauth_HashValue);
		}
	}
}

/**
 * ksmbd_gcm_nonce_limit_reached() - check if GCM nonce counter is exhausted
 * @sess:	session to check
 *
 * For deterministic (counter-based) GCM nonces the theoretical limit
 * is 2^64, but we cap at 2^63 - 1 to stay well within safe bounds.
 *
 * Return: true if the nonce space is exhausted
 */
VISIBLE_IF_KUNIT bool ksmbd_gcm_nonce_limit_reached(struct ksmbd_session *sess)
{
	return atomic64_read(&sess->gcm_nonce_counter) >= S64_MAX;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_gcm_nonce_limit_reached);

VISIBLE_IF_KUNIT int fill_transform_hdr(void *tr_buf, char *old_buf,
					 __le16 cipher_type,
					 struct ksmbd_session *sess)
{
	struct smb2_transform_hdr *tr_hdr = tr_buf + 4;
	struct smb2_hdr *hdr = smb2_get_msg(old_buf);
	unsigned int orig_len = get_rfc1002_len(old_buf);

	memset(tr_buf, 0, sizeof(struct smb2_transform_hdr) + 4);
	tr_hdr->ProtocolId = SMB2_TRANSFORM_PROTO_NUM;
	tr_hdr->OriginalMessageSize = cpu_to_le32(orig_len);
	tr_hdr->Flags = cpu_to_le16(0x01);
	if (cipher_type == SMB2_ENCRYPTION_AES128_GCM ||
	    cipher_type == SMB2_ENCRYPTION_AES256_GCM) {
		__le64 counter_le;

		if (sess && !ksmbd_gcm_nonce_limit_reached(sess)) {
			u64 counter;

			/*
			 * Use deterministic nonce: 4-byte random
			 * session prefix + 8-byte monotonic counter.
			 * This guarantees uniqueness per session key
			 * and avoids the birthday-bound risk of fully
			 * random nonces.
			 */
			counter = atomic64_inc_return(
					&sess->gcm_nonce_counter);
			memcpy(&tr_hdr->Nonce,
			       sess->gcm_nonce_prefix, 4);
			counter_le = cpu_to_le64(counter);
			memcpy(&tr_hdr->Nonce[4],
			       &counter_le, 8);
		} else {
			/*
			 * Fallback: no session or counter exhausted;
			 * use random nonce.  Counter exhaustion means
			 * the key must be rotated — log a warning.
			 */
			if (sess)
				pr_warn_ratelimited(
					"GCM nonce counter exhausted for session %llu, using random nonce\n",
					sess->id);
			get_random_bytes(&tr_hdr->Nonce,
					 SMB3_AES_GCM_NONCE);
		}
	} else {
		get_random_bytes(&tr_hdr->Nonce, SMB3_AES_CCM_NONCE);
	}
	memcpy(&tr_hdr->SessionId, &hdr->SessionId, 8);
	inc_rfc1001_len(tr_buf, sizeof(struct smb2_transform_hdr));
	inc_rfc1001_len(tr_buf, orig_len);
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(fill_transform_hdr);

int smb3_encrypt_resp(struct ksmbd_work *work)
{
	struct kvec *iov = work->iov;
	int rc = -ENOMEM;
	void *tr_buf;

	tr_buf = kzalloc(sizeof(struct smb2_transform_hdr) + 4, KSMBD_DEFAULT_GFP);
	if (!tr_buf)
		return rc;

	/* fill transform header */
	fill_transform_hdr(tr_buf, work->response_buf,
			   work->conn->cipher_type, work->sess);

	iov[0].iov_base = tr_buf;
	iov[0].iov_len = sizeof(struct smb2_transform_hdr) + 4;
	work->tr_buf = tr_buf;

	return ksmbd_crypt_message(work, iov, work->iov_idx + 1, 1);
}

bool smb3_is_transform_hdr(void *buf)
{
	struct smb2_transform_hdr *trhdr = smb2_get_msg(buf);

	return trhdr->ProtocolId == SMB2_TRANSFORM_PROTO_NUM;
}

int smb3_decrypt_req(struct ksmbd_work *work)
{
	struct ksmbd_session *sess;
	char *buf = work->request_buf;
	unsigned int pdu_length = get_rfc1002_len(buf);
	struct kvec iov[2];
	int buf_data_size = pdu_length - sizeof(struct smb2_transform_hdr);
	struct smb2_transform_hdr *tr_hdr = smb2_get_msg(buf);
	int rc = 0;

	if (pdu_length < sizeof(struct smb2_transform_hdr) ||
	    buf_data_size < sizeof(struct smb2_hdr)) {
		pr_err_ratelimited("Transform message is too small (%u)\n",
				   pdu_length);
		return -ECONNABORTED;
	}

	if (buf_data_size < le32_to_cpu(tr_hdr->OriginalMessageSize)) {
		pr_err_ratelimited("Transform message is broken\n");
		return -ECONNABORTED;
	}

	/* TC-05: bounds-check OriginalMessageSize before use */
	if (le32_to_cpu(tr_hdr->OriginalMessageSize) > MAX_STREAM_PROT_LEN)
		return -ECONNABORTED;

	/* TC-19: record session id for encrypted error responses */
	work->tr_sess_id = le64_to_cpu(tr_hdr->SessionId);

	/*
	 * Transform Flags validation: MS-SMB2 §2.2.41 states the Flags
	 * field in the SMB2 TRANSFORM_HEADER MUST be set to 0x0001
	 * (Encrypted bit).  Any other value is malformed and must be
	 * rejected to prevent unexpected behaviour in the decrypt path.
	 */
	if (tr_hdr->Flags != cpu_to_le16(0x0001)) {
		pr_err_ratelimited("Transform header has invalid Flags 0x%04x (expected 0x0001)\n",
				   le16_to_cpu(tr_hdr->Flags));
		return -ECONNABORTED;
	}

	/*
	 * Use ksmbd_session_lookup() (not _all) so that expired sessions
	 * can still be used for decryption.  After logoff, the session
	 * state is SMB2_SESSION_EXPIRED but the decryption key is still
	 * valid.  The session state check happens later in
	 * smb2_check_user_session(), which will properly return
	 * STATUS_USER_SESSION_DELETED.  This prevents the client from
	 * hanging when it sends an encrypted request after logoff.
	 */
	sess = ksmbd_session_lookup(work->conn, le64_to_cpu(tr_hdr->SessionId));
	if (!sess) {
		pr_err_ratelimited("invalid session id(%llx) in transform header\n",
				   le64_to_cpu(tr_hdr->SessionId));
		return -ECONNABORTED;
	}

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(struct smb2_transform_hdr) + 4;
	iov[1].iov_base = buf + sizeof(struct smb2_transform_hdr) + 4;
	iov[1].iov_len = buf_data_size;
	rc = ksmbd_crypt_message(work, iov, 2, 0);
	if (rc) {
		ksmbd_user_session_put(sess);
		return rc;
	}

	/* TC-23: use OriginalMessageSize (excludes AEAD tag) not buf_data_size */
	{
		unsigned int orig_len = le32_to_cpu(tr_hdr->OriginalMessageSize);

		memmove(buf + 4, iov[1].iov_base, orig_len);
		*(__be32 *)buf = cpu_to_be32(orig_len);
	}

	ksmbd_user_session_put(sess);
	return rc;
}

bool smb3_11_final_sess_setup_resp(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	struct smb2_hdr *rsp = smb2_get_msg(work->response_buf);

	if (conn->dialect < SMB30_PROT_ID)
		return false;

	if (work->next_smb2_rcv_hdr_off)
		rsp = ksmbd_resp_buf_next(work);

	if (le16_to_cpu(rsp->Command) == SMB2_SESSION_SETUP_HE &&
	    sess->user && !user_guest(sess->user) &&
	    rsp->Status == STATUS_SUCCESS)
		return true;
	return false;
}
