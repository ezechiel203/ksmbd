// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_notify.c - SMB2_CHANGE_NOTIFY handler
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

static void smb2_notify_cancel(void **argv)
{
	ksmbd_notify_cancel(argv);
}

/**
 * smb2_notify() - handler for smb2 notify request
 * @work:   smb work containing notify command buffer
 *
 * Validates the CHANGE_NOTIFY request, installs an fsnotify watch
 * on the target directory, and returns STATUS_PENDING.  The actual
 * response is sent asynchronously when a matching event arrives.
 *
 * Return:      0 on success, otherwise error
 */
int smb2_notify(struct ksmbd_work *work)
{
	struct smb2_notify_req *req;
	struct smb2_notify_rsp *rsp;
	struct ksmbd_file *fp;
	u32 completion_filter;
	u32 output_buf_len;
	bool watch_tree;
	void **argv;
	int rc;

	ksmbd_debug(SMB, "Received smb2 notify\n");

	WORK_BUFFERS(work, req, rsp);

	if (work->next_smb2_rcv_hdr_off && req->hdr.NextCommand) {
		rsp->hdr.Status = STATUS_INTERNAL_ERROR;
		smb2_set_err_rsp(work);
		return -EIO;
	}

	fp = ksmbd_lookup_fd_slow(work,
				  req->VolatileFileId,
				  req->PersistentFileId);
	if (!fp) {
		pr_err_ratelimited("ksmbd: notify invalid FID\n");
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		smb2_set_err_rsp(work);
		return -EBADF;
	}

	/* CHANGE_NOTIFY is only valid on directories */
	if (!S_ISDIR(file_inode(fp->filp)->i_mode)) {
		pr_err_ratelimited(
			"ksmbd: notify on non-directory\n");
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return -EINVAL;
	}

	completion_filter =
		le32_to_cpu(req->CompletionFilter);
	output_buf_len =
		le32_to_cpu(req->OutputBufferLength);
	watch_tree =
		le16_to_cpu(req->Flags) & SMB2_WATCH_TREE;

	/* Set up async work for STATUS_PENDING */
	argv = kmalloc(sizeof(void *), KSMBD_DEFAULT_GFP);
	if (!argv) {
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return -ENOMEM;
	}

	rc = setup_async_work(work, smb2_notify_cancel,
			      argv);
	if (rc) {
		kfree(argv);
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return rc;
	}

	/*
	 * Install the fsnotify watch.  On success argv[0]
	 * is set to the watch pointer for cancel path.
	 */
	rc = ksmbd_notify_add_watch(fp, work,
				    completion_filter,
				    watch_tree,
				    output_buf_len,
				    argv);
	if (rc) {
		release_async_work(work);
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return rc;
	}

	/* Send STATUS_PENDING interim response */
	smb2_send_interim_resp(work, STATUS_PENDING);

	ksmbd_fd_put(work, fp);

	/*
	 * Do NOT send a response from the main handler --
	 * the async completion in fsnotify will send it.
	 */
	work->send_no_response = 1;
	return 0;
}

/**
 * smb2_is_sign_req() - handler for checking packet signing status
 * @work:	smb work containing notify command buffer
 * @command:	SMB2 command id
 *
 * Return:	true if packed is signed, false otherwise
 */
