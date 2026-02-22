// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_tree.c - Tree connect/disconnect + session logoff
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
 * smb2_tree_connect() - handler for smb2 tree connect command
 * @work:	smb work containing smb request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_tree_connect(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_tree_connect_req *req;
	struct smb2_tree_connect_rsp *rsp;
	struct ksmbd_session *sess = work->sess;
	char *treename = NULL, *name = NULL;
	struct ksmbd_tree_conn_status status;
	struct ksmbd_share_config *share = NULL;
	int rc = -EINVAL;

	ksmbd_debug(SMB, "Received smb2 tree connect request\n");

	WORK_BUFFERS(work, req, rsp);

	if ((u64)le16_to_cpu(req->PathOffset) + le16_to_cpu(req->PathLength) >
	    get_rfc1002_len(work->request_buf) + 4 -
	    ((char *)req - (char *)work->request_buf)) {
		rc = -EINVAL;
		goto out_err1;
	}

	treename = smb_strndup_from_utf16((char *)req + le16_to_cpu(req->PathOffset),
					  le16_to_cpu(req->PathLength), true,
					  conn->local_nls);
	if (IS_ERR(treename)) {
		pr_err_ratelimited("treename is NULL\n");
		status.ret = KSMBD_TREE_CONN_STATUS_ERROR;
		goto out_err1;
	}

	/*
	 * When SMB2_FLAGS_DFS_OPERATIONS is set, the tree path may
	 * contain a DFS prefix.  Log the DFS operation for debugging.
	 * Full DFS path resolution (stripping the DFS prefix and
	 * redirecting to the correct share) will be implemented when
	 * IPC integration with ksmbd.mountd is available.
	 */
	if (req->hdr.Flags & SMB2_FLAGS_DFS_OPERATIONS)
		ksmbd_debug(SMB,
			    "DFS flag set for tree connect: %s\n",
			    treename);

	name = ksmbd_extract_sharename(conn->um, treename);
	if (IS_ERR(name)) {
		status.ret = KSMBD_TREE_CONN_STATUS_ERROR;
		goto out_err1;
	}

	ksmbd_debug(SMB, "tree connect request for tree %s treename %s\n",
		    name, treename);

	status = ksmbd_tree_conn_connect(work, name);
	if (status.ret == KSMBD_TREE_CONN_STATUS_OK)
		rsp->hdr.Id.SyncId.TreeId = cpu_to_le32(status.tree_conn->id);
	else
		goto out_err1;

	share = status.tree_conn->share_conf;
	if (test_share_config_flag(share, KSMBD_SHARE_FLAG_PIPE)) {
		ksmbd_debug(SMB, "IPC share path request\n");
		rsp->ShareType = SMB2_SHARE_TYPE_PIPE;
		rsp->MaximalAccess = FILE_READ_DATA_LE | FILE_READ_EA_LE |
			FILE_EXECUTE_LE | FILE_READ_ATTRIBUTES_LE |
			FILE_DELETE_LE | FILE_READ_CONTROL_LE |
			FILE_WRITE_DAC_LE | FILE_WRITE_OWNER_LE |
			FILE_SYNCHRONIZE_LE;
	} else {
		rsp->ShareType = SMB2_SHARE_TYPE_DISK;
		rsp->MaximalAccess = FILE_READ_DATA_LE | FILE_READ_EA_LE |
			FILE_EXECUTE_LE | FILE_READ_ATTRIBUTES_LE;
		if (test_tree_conn_flag(status.tree_conn,
					KSMBD_TREE_CONN_FLAG_WRITABLE)) {
			rsp->MaximalAccess |= FILE_WRITE_DATA_LE |
				FILE_APPEND_DATA_LE | FILE_WRITE_EA_LE |
				FILE_DELETE_LE | FILE_WRITE_ATTRIBUTES_LE |
				FILE_DELETE_CHILD_LE | FILE_READ_CONTROL_LE |
				FILE_WRITE_DAC_LE | FILE_WRITE_OWNER_LE |
				FILE_SYNCHRONIZE_LE;
		}
	}

	status.tree_conn->maximal_access = le32_to_cpu(rsp->MaximalAccess);
	if (conn->posix_ext_supported)
		status.tree_conn->posix_extensions = true;

	write_lock(&sess->tree_conns_lock);
	status.tree_conn->t_state = TREE_CONNECTED;
	write_unlock(&sess->tree_conns_lock);
	rsp->StructureSize = cpu_to_le16(16);
out_err1:
	if (server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE && share &&
	    test_share_config_flag(share,
				   KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY))
		rsp->Capabilities = SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY;
	else
		rsp->Capabilities = 0;
	rsp->Reserved = 0;
	/* default manual caching */
	rsp->ShareFlags = SMB2_SHAREFLAG_MANUAL_CACHING;

	rc = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_tree_connect_rsp));
	if (rc) {
		if (status.ret == KSMBD_TREE_CONN_STATUS_OK)
			ksmbd_tree_conn_disconnect(sess, status.tree_conn);
		status.ret = KSMBD_TREE_CONN_STATUS_NOMEM;
	}

	if (!IS_ERR(treename))
		kfree(treename);
	if (!IS_ERR(name))
		kfree(name);

	switch (status.ret) {
	case KSMBD_TREE_CONN_STATUS_OK:
		rsp->hdr.Status = STATUS_SUCCESS;
		rc = 0;
		break;
	case -ESTALE:
	case -ENOENT:
	case KSMBD_TREE_CONN_STATUS_NO_SHARE:
		rsp->hdr.Status = STATUS_BAD_NETWORK_NAME;
		break;
	case -ENOMEM:
	case KSMBD_TREE_CONN_STATUS_NOMEM:
		rsp->hdr.Status = STATUS_NO_MEMORY;
		break;
	case KSMBD_TREE_CONN_STATUS_ERROR:
	case KSMBD_TREE_CONN_STATUS_TOO_MANY_CONNS:
	case KSMBD_TREE_CONN_STATUS_TOO_MANY_SESSIONS:
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		break;
	case -EINVAL:
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		break;
	default:
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
	}

	if (status.ret != KSMBD_TREE_CONN_STATUS_OK)
		smb2_set_err_rsp(work);

	return rc;
}

/**
 * smb2_tree_disconnect() - handler for smb tree connect request
 * @work:	smb work containing request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_tree_disconnect(struct ksmbd_work *work)
{
	struct smb2_tree_disconnect_rsp *rsp;
	struct smb2_tree_disconnect_req *req;
	struct ksmbd_session *sess = work->sess;
	struct ksmbd_tree_connect *tcon = work->tcon;
	int err;

	ksmbd_debug(SMB, "Received smb2 tree disconnect request\n");

	WORK_BUFFERS(work, req, rsp);

	if (!tcon) {
		ksmbd_debug(SMB, "Invalid tid %d\n", req->hdr.Id.SyncId.TreeId);

		rsp->hdr.Status = STATUS_NETWORK_NAME_DELETED;
		err = -ENOENT;
		goto err_out;
	}

	ksmbd_close_tree_conn_fds(work);

	write_lock(&sess->tree_conns_lock);
	if (tcon->t_state == TREE_DISCONNECTED) {
		write_unlock(&sess->tree_conns_lock);
		rsp->hdr.Status = STATUS_NETWORK_NAME_DELETED;
		err = -ENOENT;
		goto err_out;
	}

	tcon->t_state = TREE_DISCONNECTED;
	write_unlock(&sess->tree_conns_lock);

	err = ksmbd_tree_conn_disconnect(sess, tcon);
	if (err) {
		rsp->hdr.Status = STATUS_NETWORK_NAME_DELETED;
		goto err_out;
	}

	rsp->StructureSize = cpu_to_le16(4);
	err = ksmbd_iov_pin_rsp(work, rsp,
				sizeof(struct smb2_tree_disconnect_rsp));
	if (err) {
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		goto err_out;
	}

	return 0;

err_out:
	smb2_set_err_rsp(work);
	return err;

}

/**
 * smb2_session_logoff() - handler for session log off request
 * @work:	smb work containing request buffer
 *
 * Return:      0 on success, otherwise error
 */
int smb2_session_logoff(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	struct smb2_logoff_req *req;
	struct smb2_logoff_rsp *rsp;
	u64 sess_id;
	int err;

	WORK_BUFFERS(work, req, rsp);

	ksmbd_debug(SMB, "Received smb2 session logoff request\n");

	ksmbd_conn_lock(conn);
	if (!ksmbd_conn_good(conn)) {
		ksmbd_conn_unlock(conn);
		rsp->hdr.Status = STATUS_NETWORK_NAME_DELETED;
		smb2_set_err_rsp(work);
		return -ENOENT;
	}
	sess_id = le64_to_cpu(req->hdr.SessionId);
	ksmbd_all_conn_set_status(sess_id, KSMBD_SESS_NEED_RECONNECT);
	ksmbd_conn_unlock(conn);

	ksmbd_close_session_fds(work);
	ksmbd_conn_wait_idle(conn);

	if (ksmbd_tree_conn_session_logoff(sess)) {
		ksmbd_debug(SMB, "Invalid tid %d\n", req->hdr.Id.SyncId.TreeId);
		rsp->hdr.Status = STATUS_NETWORK_NAME_DELETED;
		smb2_set_err_rsp(work);
		return -ENOENT;
	}

	down_write(&conn->session_lock);
	down_write(&sess->state_lock);
	sess->state = SMB2_SESSION_EXPIRED;
	up_write(&sess->state_lock);
	up_write(&conn->session_lock);

	ksmbd_all_conn_set_status(sess_id, KSMBD_SESS_NEED_SETUP);

	rsp->StructureSize = cpu_to_le16(4);
	err = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_logoff_rsp));
	if (err) {
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		return err;
	}
	return 0;
}
