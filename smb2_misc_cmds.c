// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_misc_cmds.c - Oplock break, close, echo
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
 * smb2_close_pipe() - handler for closing IPC pipe
 * @work:	smb work containing close request buffer
 *
 * Return:	0
 */
static noinline int smb2_close_pipe(struct ksmbd_work *work)
{
	u64 id;
	struct smb2_close_req *req;
	struct smb2_close_rsp *rsp;

	WORK_BUFFERS(work, req, rsp);

	id = req->VolatileFileId;
	ksmbd_session_rpc_close(work->sess, id);

	rsp->StructureSize = cpu_to_le16(60);
	rsp->Flags = 0;
	rsp->Reserved = 0;
	rsp->CreationTime = 0;
	rsp->LastAccessTime = 0;
	rsp->LastWriteTime = 0;
	rsp->ChangeTime = 0;
	rsp->AllocationSize = 0;
	rsp->EndOfFile = 0;
	rsp->Attributes = 0;

	return ksmbd_iov_pin_rsp(work, (void *)rsp,
				 sizeof(struct smb2_close_rsp));
}

/**
 * smb2_close() - handler for smb2 close file command
 * @work:	smb work containing close request buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_close(struct ksmbd_work *work)
{
	u64 volatile_id = KSMBD_NO_FID;
	u64 sess_id;
	struct smb2_close_req *req;
	struct smb2_close_rsp *rsp;
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_file *fp;
	u64 time;
	int err = 0;

	ksmbd_debug(SMB, "Received smb2 close request\n");

	WORK_BUFFERS(work, req, rsp);

	if (test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_PIPE)) {
		ksmbd_debug(SMB, "IPC pipe close request\n");
		return smb2_close_pipe(work);
	}

	sess_id = le64_to_cpu(req->hdr.SessionId);
	if (req->hdr.Flags & SMB2_FLAGS_RELATED_OPERATIONS)
		sess_id = work->compound_sid;

	work->compound_sid = 0;
	if (check_session_id(conn, sess_id)) {
		work->compound_sid = sess_id;
	} else {
		rsp->hdr.Status = STATUS_USER_SESSION_DELETED;
		if (req->hdr.Flags & SMB2_FLAGS_RELATED_OPERATIONS)
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		err = -EBADF;
		goto out;
	}

	if (work->next_smb2_rcv_hdr_off &&
	    !has_file_id(req->VolatileFileId)) {
		if (!has_file_id(work->compound_fid)) {
			/* file already closed, return FILE_CLOSED */
			ksmbd_debug(SMB, "file already closed\n");
			rsp->hdr.Status = STATUS_FILE_CLOSED;
			err = -EBADF;
			goto out;
		} else {
			ksmbd_debug(SMB,
				    "Compound request set FID = %llu:%llu\n",
				    work->compound_fid,
				    work->compound_pfid);
			volatile_id = work->compound_fid;

			/* file closed, stored id is not valid anymore */
			work->compound_fid = KSMBD_NO_FID;
			work->compound_pfid = KSMBD_NO_FID;
		}
	} else {
		volatile_id = req->VolatileFileId;
	}
	ksmbd_debug(SMB, "volatile_id = %llu\n", volatile_id);

	rsp->StructureSize = cpu_to_le16(60);
	rsp->Reserved = 0;

	if (req->Flags == SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB) {
		struct kstat stat;
		int ret;

		fp = ksmbd_lookup_fd_fast(work, volatile_id);
		if (!fp) {
			err = -ENOENT;
			goto out;
		}

		ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,
				  AT_STATX_SYNC_AS_STAT);
		if (ret) {
			ksmbd_fd_put(work, fp);
			goto out;
		}

		rsp->Flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
		rsp->AllocationSize = S_ISDIR(stat.mode) ? 0 :
			cpu_to_le64(stat.blocks << 9);
		rsp->EndOfFile = cpu_to_le64(stat.size);
		rsp->Attributes = fp->f_ci->m_fattr;
		rsp->CreationTime = cpu_to_le64(fp->create_time);
		time = ksmbd_UnixTimeToNT(stat.atime);
		rsp->LastAccessTime = cpu_to_le64(time);
		time = ksmbd_UnixTimeToNT(stat.mtime);
		rsp->LastWriteTime = cpu_to_le64(time);
		time = ksmbd_UnixTimeToNT(stat.ctime);
		rsp->ChangeTime = cpu_to_le64(time);
		ksmbd_fd_put(work, fp);
	} else {
		rsp->Flags = 0;
		rsp->AllocationSize = 0;
		rsp->EndOfFile = 0;
		rsp->Attributes = 0;
		rsp->CreationTime = 0;
		rsp->LastAccessTime = 0;
		rsp->LastWriteTime = 0;
		rsp->ChangeTime = 0;
	}

	err = ksmbd_close_fd(work, volatile_id);
out:
	if (!err)
		err = ksmbd_iov_pin_rsp(work, (void *)rsp,
					sizeof(struct smb2_close_rsp));

	if (err) {
		if (rsp->hdr.Status == 0)
			rsp->hdr.Status = STATUS_FILE_CLOSED;
		smb2_set_err_rsp(work);
	}

	return err;
}

/**
 * smb2_echo() - handler for smb2 echo(ping) command
 * @work:	smb work containing echo request buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_echo(struct ksmbd_work *work)
{
	struct smb2_echo_rsp *rsp = smb2_get_msg(work->response_buf);

	ksmbd_debug(SMB, "Received smb2 echo request\n");

	if (work->next_smb2_rcv_hdr_off)
		rsp = ksmbd_resp_buf_next(work);

	rsp->StructureSize = cpu_to_le16(4);
	rsp->Reserved = 0;
	return ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_echo_rsp));
}

/**
 * smb20_oplock_break_ack() - handler for smb2.0 oplock break command
 * @work:	smb work containing oplock break command buffer
 *
 * Return:	0
 */
static void smb20_oplock_break_ack(struct ksmbd_work *work)
{
	struct smb2_oplock_break *req;
	struct smb2_oplock_break *rsp;
	struct ksmbd_file *fp;
	struct oplock_info *opinfo = NULL;
	__le32 err = 0;
	int ret = 0;
	u64 volatile_id, persistent_id;
	char req_oplevel = 0, rsp_oplevel = 0;
	unsigned int oplock_change_type;

	WORK_BUFFERS(work, req, rsp);

	volatile_id = req->VolatileFid;
	persistent_id = req->PersistentFid;
	req_oplevel = req->OplockLevel;
	ksmbd_debug(OPLOCK, "v_id %llu, p_id %llu request oplock level %d\n",
		    volatile_id, persistent_id, req_oplevel);

	fp = ksmbd_lookup_fd_slow(work, volatile_id, persistent_id);
	if (!fp) {
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		smb2_set_err_rsp(work);
		return;
	}

	opinfo = opinfo_get(fp);
	if (!opinfo) {
		pr_err("unexpected null oplock_info\n");
		rsp->hdr.Status = STATUS_INVALID_OPLOCK_PROTOCOL;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return;
	}

	if (opinfo->level == SMB2_OPLOCK_LEVEL_NONE) {
		rsp->hdr.Status = STATUS_INVALID_OPLOCK_PROTOCOL;
		goto err_out;
	}

	if (opinfo->op_state == OPLOCK_STATE_NONE) {
		ksmbd_debug(SMB, "unexpected oplock state 0x%x\n", opinfo->op_state);
		rsp->hdr.Status = STATUS_UNSUCCESSFUL;
		goto err_out;
	}

	if ((opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
	     opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) &&
	    (req_oplevel != SMB2_OPLOCK_LEVEL_II &&
	     req_oplevel != SMB2_OPLOCK_LEVEL_NONE)) {
		err = STATUS_INVALID_OPLOCK_PROTOCOL;
		oplock_change_type = OPLOCK_WRITE_TO_NONE;
	} else if (opinfo->level == SMB2_OPLOCK_LEVEL_II &&
		   req_oplevel != SMB2_OPLOCK_LEVEL_NONE) {
		err = STATUS_INVALID_OPLOCK_PROTOCOL;
		oplock_change_type = OPLOCK_READ_TO_NONE;
	} else if (req_oplevel == SMB2_OPLOCK_LEVEL_II ||
		   req_oplevel == SMB2_OPLOCK_LEVEL_NONE) {
		err = STATUS_INVALID_DEVICE_STATE;
		if ((opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
		     opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) &&
		    req_oplevel == SMB2_OPLOCK_LEVEL_II) {
			oplock_change_type = OPLOCK_WRITE_TO_READ;
		} else if ((opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
			    opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) &&
			   req_oplevel == SMB2_OPLOCK_LEVEL_NONE) {
			oplock_change_type = OPLOCK_WRITE_TO_NONE;
		} else if (opinfo->level == SMB2_OPLOCK_LEVEL_II &&
			   req_oplevel == SMB2_OPLOCK_LEVEL_NONE) {
			oplock_change_type = OPLOCK_READ_TO_NONE;
		} else {
			oplock_change_type = 0;
		}
	} else {
		oplock_change_type = 0;
	}

	switch (oplock_change_type) {
	case OPLOCK_WRITE_TO_READ:
		ret = opinfo_write_to_read(opinfo);
		rsp_oplevel = SMB2_OPLOCK_LEVEL_II;
		break;
	case OPLOCK_WRITE_TO_NONE:
		ret = opinfo_write_to_none(opinfo);
		rsp_oplevel = SMB2_OPLOCK_LEVEL_NONE;
		break;
	case OPLOCK_READ_TO_NONE:
		ret = opinfo_read_to_none(opinfo);
		rsp_oplevel = SMB2_OPLOCK_LEVEL_NONE;
		break;
	default:
		pr_err_ratelimited("unknown oplock change 0x%x -> 0x%x\n",
				   opinfo->level, rsp_oplevel);
	}

	if (ret < 0) {
		rsp->hdr.Status = err;
		goto err_out;
	}

	rsp->StructureSize = cpu_to_le16(24);
	rsp->OplockLevel = rsp_oplevel;
	rsp->Reserved = 0;
	rsp->Reserved2 = 0;
	rsp->VolatileFid = volatile_id;
	rsp->PersistentFid = persistent_id;
	ret = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_oplock_break));
	if (ret) {
err_out:
		smb2_set_err_rsp(work);
	}

	opinfo->op_state = OPLOCK_STATE_NONE;
	wake_up_interruptible_all(&opinfo->oplock_q);
	opinfo_put(opinfo);
	ksmbd_fd_put(work, fp);
}

static int check_lease_state(struct lease *lease, __le32 req_state)
{
	if ((lease->new_state ==
	     (SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE)) &&
	    !(req_state & SMB2_LEASE_WRITE_CACHING_LE)) {
		lease->new_state = req_state;
		return 0;
	}

	if (lease->new_state == req_state)
		return 0;

	return 1;
}

/**
 * smb21_lease_break_ack() - handler for smb2.1 lease break command
 * @work:	smb work containing lease break command buffer
 *
 * Return:	0
 */
static void smb21_lease_break_ack(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_lease_ack *req;
	struct smb2_lease_ack *rsp;
	struct oplock_info *opinfo;
	__le32 err = 0;
	int ret = 0;
	unsigned int lease_change_type;
	__le32 lease_state;
	struct lease *lease;

	WORK_BUFFERS(work, req, rsp);

	ksmbd_debug(OPLOCK, "smb21 lease break, lease state(0x%x)\n",
		    le32_to_cpu(req->LeaseState));
	opinfo = lookup_lease_in_table(conn, req->LeaseKey);
	if (!opinfo) {
		ksmbd_debug(OPLOCK, "file not opened\n");
		smb2_set_err_rsp(work);
		rsp->hdr.Status = STATUS_UNSUCCESSFUL;
		return;
	}
	lease = opinfo->o_lease;

	if (opinfo->op_state == OPLOCK_STATE_NONE) {
		pr_err_ratelimited("unexpected lease break state 0x%x\n",
				   opinfo->op_state);
		rsp->hdr.Status = STATUS_UNSUCCESSFUL;
		goto err_out;
	}

	if (check_lease_state(lease, req->LeaseState)) {
		rsp->hdr.Status = STATUS_REQUEST_NOT_ACCEPTED;
		ksmbd_debug(OPLOCK,
			    "req lease state: 0x%x, expected state: 0x%x\n",
			    req->LeaseState, lease->new_state);
		goto err_out;
	}

	if (!atomic_read(&opinfo->breaking_cnt)) {
		rsp->hdr.Status = STATUS_UNSUCCESSFUL;
		goto err_out;
	}

	/* check for bad lease state */
	if (req->LeaseState &
	    (~(SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE))) {
		err = STATUS_INVALID_OPLOCK_PROTOCOL;
		if (lease->state & SMB2_LEASE_WRITE_CACHING_LE)
			lease_change_type = OPLOCK_WRITE_TO_NONE;
		else
			lease_change_type = OPLOCK_READ_TO_NONE;
		ksmbd_debug(OPLOCK, "handle bad lease state 0x%x -> 0x%x\n",
			    le32_to_cpu(lease->state),
			    le32_to_cpu(req->LeaseState));
	} else if (lease->state == SMB2_LEASE_READ_CACHING_LE &&
		   req->LeaseState != SMB2_LEASE_NONE_LE) {
		err = STATUS_INVALID_OPLOCK_PROTOCOL;
		lease_change_type = OPLOCK_READ_TO_NONE;
		ksmbd_debug(OPLOCK, "handle bad lease state 0x%x -> 0x%x\n",
			    le32_to_cpu(lease->state),
			    le32_to_cpu(req->LeaseState));
	} else {
		/* valid lease state changes */
		err = STATUS_INVALID_DEVICE_STATE;
		if (req->LeaseState == SMB2_LEASE_NONE_LE) {
			if (lease->state & SMB2_LEASE_WRITE_CACHING_LE)
				lease_change_type = OPLOCK_WRITE_TO_NONE;
			else
				lease_change_type = OPLOCK_READ_TO_NONE;
		} else if (req->LeaseState & SMB2_LEASE_READ_CACHING_LE) {
			if (lease->state & SMB2_LEASE_WRITE_CACHING_LE)
				lease_change_type = OPLOCK_WRITE_TO_READ;
			else
				lease_change_type = OPLOCK_READ_HANDLE_TO_READ;
		} else {
			lease_change_type = 0;
		}
	}

	switch (lease_change_type) {
	case OPLOCK_WRITE_TO_READ:
		ret = opinfo_write_to_read(opinfo);
		break;
	case OPLOCK_READ_HANDLE_TO_READ:
		ret = opinfo_read_handle_to_read(opinfo);
		break;
	case OPLOCK_WRITE_TO_NONE:
		ret = opinfo_write_to_none(opinfo);
		break;
	case OPLOCK_READ_TO_NONE:
		ret = opinfo_read_to_none(opinfo);
		break;
	default:
		ksmbd_debug(OPLOCK, "unknown lease change 0x%x -> 0x%x\n",
			    le32_to_cpu(lease->state),
			    le32_to_cpu(req->LeaseState));
	}

	if (ret < 0) {
		rsp->hdr.Status = err;
		goto err_out;
	}

	lease_state = lease->state;

	rsp->StructureSize = cpu_to_le16(36);
	rsp->Reserved = 0;
	rsp->Flags = 0;
	memcpy(rsp->LeaseKey, req->LeaseKey, 16);
	rsp->LeaseState = lease_state;
	rsp->LeaseDuration = 0;
	ret = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_lease_ack));
	if (ret) {
err_out:
		smb2_set_err_rsp(work);
	}

	opinfo->op_state = OPLOCK_STATE_NONE;
	wake_up_interruptible_all(&opinfo->oplock_q);
	atomic_dec(&opinfo->breaking_cnt);
	wake_up_interruptible_all(&opinfo->oplock_brk);
	opinfo_put(opinfo);
}

/**
 * smb2_oplock_break() - dispatcher for smb2.0 and 2.1 oplock/lease break
 * @work:	smb work containing oplock/lease break command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_oplock_break(struct ksmbd_work *work)
{
	struct smb2_oplock_break *req;
	struct smb2_oplock_break *rsp;

	ksmbd_debug(SMB, "Received smb2 oplock break acknowledgment request\n");

	WORK_BUFFERS(work, req, rsp);

	switch (le16_to_cpu(req->StructureSize)) {
	case OP_BREAK_STRUCT_SIZE_20:
		smb20_oplock_break_ack(work);
		break;
	case OP_BREAK_STRUCT_SIZE_21:
		smb21_lease_break_ack(work);
		break;
	default:
		ksmbd_debug(OPLOCK, "invalid break cmd %d\n",
			    le16_to_cpu(req->StructureSize));
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		smb2_set_err_rsp(work);
		return -EINVAL;
	}

	return 0;
}

/**
 * smb2_notify_cancel() - cancel callback for async notify
 * @argv: cancel arguments (argv[0] = ksmbd_notify_watch *)
 */
