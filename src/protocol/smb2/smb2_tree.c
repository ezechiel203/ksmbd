// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
#include "ksmbd_dfs.h"
#include "smb2pdu_internal.h"

static char *ksmbd_extract_dfs_root_sharename(struct unicode_map *um,
					      const char *treename)
{
	const char *p = treename;
	const char *share_start;
	const char *share_end;
	char *share, *cf_share;

	while (*p == '\\' || *p == '/')
		p++;

	/* server component */
	while (*p && *p != '\\' && *p != '/')
		p++;
	if (!*p)
		return ERR_PTR(-EINVAL);

	while (*p == '\\' || *p == '/')
		p++;
	share_start = p;
	while (*p && *p != '\\' && *p != '/')
		p++;
	share_end = p;
	if (share_end == share_start)
		return ERR_PTR(-EINVAL);

	share = kstrndup(share_start, share_end - share_start, KSMBD_DEFAULT_GFP);
	if (!share)
		return ERR_PTR(-ENOMEM);

	cf_share = ksmbd_casefold_sharename(um, share);
	kfree(share);
	return cf_share;
}

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
	char *treename = NULL, *name = NULL, *dfs_name = ERR_PTR(-EINVAL);
	struct ksmbd_tree_conn_status status = {
		.ret = KSMBD_TREE_CONN_STATUS_ERROR,
		.tree_conn = NULL,
	};
	struct ksmbd_share_config *share = NULL;
	bool dfs_op;
	int rc = -EINVAL;

	ksmbd_debug(SMB, "Received smb2 tree connect request\n");

	WORK_BUFFERS(work, req, rsp);

	{
		unsigned int total_len = get_rfc1002_len(work->request_buf) + 4;
		unsigned int req_off = (char *)req - (char *)work->request_buf;
		unsigned int path_off = le16_to_cpu(req->PathOffset);
		unsigned int path_len = le16_to_cpu(req->PathLength);
		const char *path_ptr;

		if (req_off > total_len) {
			rc = -EINVAL;
			goto out_err1;
		}

		/*
		 * MS-SMB2 §2.2.9, §3.3.5.7: when TREE_CONNECT_FLAG_EXTENSION_PRESENT is
		 * set (SMB 3.1.1+), PathOffset is relative to the start of the
		 * TREE_CONNECT_Request_Extension (which begins at req->Buffer[0]),
		 * not to the SMB2 header.  Adjust accordingly.
		 */
		if (conn->dialect >= SMB311_PROT_ID &&
		    (req->Reserved & SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT)) {
			size_t ext_base = offsetof(struct smb2_tree_connect_req, Buffer);

			ksmbd_debug(SMB, "TREE_CONNECT_FLAG_EXTENSION_PRESENT set\n");
			if (ext_base + path_off > total_len - req_off ||
			    ext_base + path_off + path_len > total_len - req_off) {
				rc = -EINVAL;
				goto out_err1;
			}
			path_ptr = (const char *)req + ext_base + path_off;
		} else {
			if ((u64)path_off + path_len > total_len - req_off) {
				rc = -EINVAL;
				goto out_err1;
			}
			path_ptr = (const char *)req + path_off;
		}

		treename = smb_strndup_from_utf16(path_ptr, path_len, true,
						  conn->local_nls);
	}
	if (IS_ERR(treename)) {
		pr_err_ratelimited("treename is NULL\n");
		status.ret = KSMBD_TREE_CONN_STATUS_ERROR;
		goto out_err1;
	}

	dfs_op = !!(req->hdr.Flags & SMB2_FLAGS_DFS_OPERATIONS);
	if (dfs_op)
		ksmbd_debug(SMB,
			    "DFS flag set for tree connect: %s\n",
			    treename);

	name = ksmbd_extract_sharename(conn->um, treename);
	if (IS_ERR(name)) {
		status.ret = KSMBD_TREE_CONN_STATUS_ERROR;
		goto out_err1;
	}

	/*
	 * M-02: MS-SMB2 §3.3.5.7: share name MUST be fewer than 80 UTF-16
	 * characters.  PathLength is in bytes (UTF-16LE); reject before
	 * conversion to avoid processing oversized names.
	 * Also check the post-conversion UTF-8 length as defence-in-depth.
	 */
	if (le16_to_cpu(req->PathLength) > 80 * sizeof(__le16)) {
		pr_warn_ratelimited("tree connect: PathLength too large (%u bytes)\n",
				    le16_to_cpu(req->PathLength));
		rc = -EINVAL;
		rsp->hdr.Status = STATUS_BAD_NETWORK_NAME;
		goto out_err1;
	}
	if (strlen(name) >= 80) {
		pr_warn_ratelimited("tree connect: share name too long (%zu chars)\n",
				    strlen(name));
		rc = -EINVAL;
		rsp->hdr.Status = STATUS_BAD_NETWORK_NAME;
		goto out_err1;
	}

	ksmbd_debug(SMB, "tree connect request for tree %s treename %s\n",
		    name, treename);

	status = ksmbd_tree_conn_connect(work, name);
	if (status.ret != KSMBD_TREE_CONN_STATUS_OK && dfs_op) {
		dfs_name = ksmbd_extract_dfs_root_sharename(conn->um, treename);
		if (!IS_ERR(dfs_name) && strcmp(name, dfs_name)) {
			ksmbd_debug(SMB,
				    "retry tree connect using DFS root share %s\n",
				    dfs_name);
			status = ksmbd_tree_conn_connect(work, dfs_name);
			if (status.ret == KSMBD_TREE_CONN_STATUS_OK) {
				kfree(name);
				name = dfs_name;
				dfs_name = ERR_PTR(-EINVAL);
			}
		}
	}
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
		/*
		 * B.8: MaximalAccess should reflect actual maximum access for
		 * the authenticated user on this share (MS-SMB2 §2.2.10).
		 *
		 * Compute access from the real POSIX permissions on the share
		 * root directory using inode_permission().  This correctly
		 * accounts for uid/gid/mode of the underlying filesystem path.
		 *
		 * FILE_READ_CONTROL_LE and FILE_SYNCHRONIZE_LE are always
		 * included as they are required for basic file operations.
		 *
		 * B.9: Return SMB2_SHARE_TYPE_PRINT (0x03) for print shares.
		 * KSMBD_SHARE_FLAG_PRINT is not yet defined in ksmbd_netlink.h
		 * (the kernel-userspace ABI), so print share detection is not
		 * currently supported. All non-IPC shares are DISK type.
		 * When KSMBD_SHARE_FLAG_PRINT is added to ksmbd_netlink.h,
		 * add: if (test_share_config_flag(share, KSMBD_SHARE_FLAG_PRINT))
		 *          rsp->ShareType = SMB2_SHARE_TYPE_PRINT;
		 * else
		 */
		rsp->ShareType = SMB2_SHARE_TYPE_DISK;

		/*
		 * Start with the base access bits that are always present:
		 *   FILE_READ_CONTROL_LE - always needed
		 *   FILE_SYNCHRONIZE_LE  - needed for any open with SYNCHRONIZE
		 *   FILE_READ_ATTRIBUTES_LE - reading basic file attributes
		 *   FILE_READ_EA_LE      - reading extended attributes
		 *
		 * Then probe the share root directory with inode_permission()
		 * to determine which access classes the current user holds.
		 */
		rsp->MaximalAccess = FILE_READ_CONTROL_LE | FILE_SYNCHRONIZE_LE;

		if (share->vfs_path.dentry) {
			struct inode *root_inode =
				d_inode(share->vfs_path.dentry);
			struct path *root_path =
				(struct path *)&share->vfs_path;

			if (root_inode) {
				int perm_r, perm_w, perm_x;

				perm_r = compat_inode_permission(root_path,
								 root_inode,
								 MAY_READ);
				perm_w = compat_inode_permission(root_path,
								 root_inode,
								 MAY_WRITE);
				perm_x = compat_inode_permission(root_path,
								 root_inode,
								 MAY_EXEC);

				if (!perm_r) {
					/*
					 * MAY_READ on a directory means the
					 * client can list contents and read
					 * file attributes/EAs.
					 */
					rsp->MaximalAccess |=
						FILE_READ_DATA_LE |
						FILE_LIST_DIRECTORY_LE |
						FILE_READ_ATTRIBUTES_LE |
						FILE_READ_EA_LE;
				}

				if (!perm_w &&
				    test_tree_conn_flag(status.tree_conn,
						KSMBD_TREE_CONN_FLAG_WRITABLE)) {
					/*
					 * MAY_WRITE on directory + share is
					 * writable → full write access.
					 */
					rsp->MaximalAccess |=
						FILE_WRITE_DATA_LE |
						FILE_ADD_FILE_LE |
						FILE_APPEND_DATA_LE |
						FILE_WRITE_EA_LE |
						FILE_DELETE_LE |
						FILE_WRITE_ATTRIBUTES_LE |
						FILE_DELETE_CHILD_LE |
						FILE_WRITE_DAC_LE |
						FILE_WRITE_OWNER_LE;
				}

				if (!perm_x) {
					/*
					 * MAY_EXEC on a directory means the
					 * client can traverse it.
					 */
					rsp->MaximalAccess |= FILE_TRAVERSE_LE |
						FILE_EXECUTE_LE;
				}

				ksmbd_debug(SMB,
					    "MaximalAccess: perm_r=%d perm_w=%d perm_x=%d access=0x%08x\n",
					    perm_r, perm_w, perm_x,
					    le32_to_cpu(rsp->MaximalAccess));
			} else {
				goto share_access_fallback;
			}
		} else {
share_access_fallback:
			/*
			 * vfs_path not available (IPC-like or path lookup
			 * failed at mount time) -- fall back to share-flag
			 * based approach.
			 */
			rsp->MaximalAccess |= FILE_READ_DATA_LE |
				FILE_READ_EA_LE | FILE_EXECUTE_LE |
				FILE_READ_ATTRIBUTES_LE |
				FILE_LIST_DIRECTORY_LE | FILE_TRAVERSE_LE;
			if (test_tree_conn_flag(status.tree_conn,
						KSMBD_TREE_CONN_FLAG_WRITABLE)) {
				rsp->MaximalAccess |= FILE_WRITE_DATA_LE |
					FILE_APPEND_DATA_LE |
					FILE_WRITE_EA_LE |
					FILE_DELETE_LE |
					FILE_WRITE_ATTRIBUTES_LE |
					FILE_DELETE_CHILD_LE |
					FILE_WRITE_DAC_LE |
					FILE_WRITE_OWNER_LE;
			}
		}
	}

	status.tree_conn->maximal_access = le32_to_cpu(rsp->MaximalAccess);
	if (conn->posix_ext_supported)
		status.tree_conn->posix_extensions = true;

	write_lock(&sess->tree_conns_lock);
	status.tree_conn->t_state = TREE_CONNECTED;
	write_unlock(&sess->tree_conns_lock);
	rsp->StructureSize = cpu_to_le16(16);
	rsp->Capabilities = 0;
	if (server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE && share &&
	    test_share_config_flag(share,
				   KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY))
		rsp->Capabilities |= SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY;
	if (ksmbd_dfs_enabled())
		rsp->Capabilities |= SMB2_SHARE_CAP_DFS;
	/*
	 * MULTI-01: Advertise scale-out capability when multichannel is
	 * enabled so that clients attempt to use additional channels
	 * (MS-SMB2 §2.2.10, SMB2_SHARE_CAP_SCALEOUT = 0x00000020).
	 */
	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL)
		rsp->Capabilities |= SMB2_SHARE_CAP_SCALEOUT;
	rsp->Reserved = 0;
	/* M-10: set caching mode from per-share config; default is MANUAL (0) */
	if (share)
		rsp->ShareFlags = cpu_to_le32(share->offline_caching_mode & 0x30);
	else
		rsp->ShareFlags = cpu_to_le32(SMB2_SHAREFLAG_MANUAL_CACHING);
	if (ksmbd_dfs_enabled())
		rsp->ShareFlags |= cpu_to_le32(SHI1005_FLAGS_DFS);

out_err1:
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
	if (!IS_ERR(dfs_name))
		kfree(dfs_name);

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
		/*
		 * B.7: MS-SMB2 §3.3.5.6 — requests on a bad/expired connection
		 * for LOGOFF should return STATUS_USER_SESSION_DELETED.
		 */
		rsp->hdr.Status = STATUS_USER_SESSION_DELETED;
		smb2_set_err_rsp(work);
		return -ENOENT;
	}
	sess_id = le64_to_cpu(req->hdr.SessionId);
	ksmbd_all_conn_set_status(sess_id, KSMBD_SESS_NEED_RECONNECT);
	ksmbd_conn_unlock(conn);

	/*
	 * MS-SMB2 §3.3.4.1.8: on session logoff, notify all other channels
	 * of the session that the session is closing.
	 */
	smb2_send_session_closed_notification(work);

	ksmbd_close_session_fds(work);
	ksmbd_conn_wait_idle(conn);

	if (ksmbd_tree_conn_session_logoff(sess)) {
		ksmbd_debug(SMB, "Invalid tid %d\n", req->hdr.Id.SyncId.TreeId);
		rsp->hdr.Status = STATUS_USER_SESSION_DELETED;
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
