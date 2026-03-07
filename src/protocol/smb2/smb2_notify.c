// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_notify.c - SMB2_CHANGE_NOTIFY handler
 */

#include <linux/fs.h>
#include <linux/namei.h>

#include "glob.h"
#include "smb2pdu.h"
#include "smbstatus.h"
#include "ksmbd_work.h"
#include "vfs_cache.h"
#include "connection.h"
#include "mgmt/user_session.h"
#include "ksmbd_notify.h"
#include "smb2pdu_internal.h"

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

	/*
	 * Per MS-SMB2 3.3.5.19, CHANGE_NOTIFY may go async and
	 * must be the last request in a compound chain.  If it is
	 * not the last request (NextCommand is set), return
	 * STATUS_INVALID_PARAMETER for the first request or
	 * STATUS_INTERNAL_ERROR for subsequent requests, matching
	 * Windows behavior.
	 */
	if (req->hdr.NextCommand) {
		if (work->next_smb2_rcv_hdr_off)
			rsp->hdr.Status = STATUS_INTERNAL_ERROR;
		else
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		smb2_set_err_rsp(work);
		return -EINVAL;
	}

	{
		u64 volatile_id = req->VolatileFileId;
		u64 persistent_id = req->PersistentFileId;

		if (work->next_smb2_rcv_hdr_off &&
		    !has_file_id(volatile_id)) {
			volatile_id = work->compound_fid;
			persistent_id = work->compound_pfid;
		}

		fp = ksmbd_lookup_fd_slow(work, volatile_id, persistent_id);
	}
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

	/*
	 * Per MS-SMB2 3.3.5.19, the handle must have been opened
	 * with FILE_LIST_DIRECTORY access.  If not, return
	 * STATUS_ACCESS_DENIED.
	 */
	if (!(fp->daccess & FILE_LIST_DIRECTORY_LE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return -EACCES;
	}

	/*
	 * If the CHANGE_NOTIFY subsystem is disabled (e.g.
	 * fsnotify compat issue on kernel 6.18+):
	 *
	 * - Standalone (non-compound) requests: return
	 *   STATUS_NOT_SUPPORTED immediately.
	 *
	 * - Compound-chain requests (last in chain): proceed to
	 *   the async setup path so the compound response includes
	 *   a proper STATUS_PENDING interim.  No fsnotify watch is
	 *   installed; the cancel/cleanup path handles teardown.
	 *   This satisfies the compound.interim1/interim3 tests.
	 */
	if (!ksmbd_notify_enabled() && !work->next_smb2_rcv_hdr_off) {
		rsp->hdr.Status = STATUS_NOT_SUPPORTED;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return -EOPNOTSUPP;
	}

	completion_filter =
		le32_to_cpu(req->CompletionFilter);
	output_buf_len =
		le32_to_cpu(req->OutputBufferLength);
	watch_tree =
		le16_to_cpu(req->Flags) & SMB2_WATCH_TREE;

	/*
	 * MS-SMB2 §3.3.5.19 says CompletionFilter MUST be non-zero, but
	 * Windows accepts 0 and treats it as "monitor all changes".
	 * smbtorture explicitly tests this behaviour (rec test).
	 * Treat 0 as 0xFFFFFFFF (all flags) for compatibility.
	 */
	if (!completion_filter)
		completion_filter = 0xFFFFFFFF;

	/* Set up async work for STATUS_PENDING */
	argv = kmalloc(3 * sizeof(void *), KSMBD_DEFAULT_GFP);
	if (!argv) {
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return -ENOMEM;
	}

	/*
	 * Initialize argv BEFORE setup_async_work, because once
	 * setup_async_work registers the cancel callback, a
	 * concurrent SMB2_CANCEL on another kworker can invoke
	 * ksmbd_notify_cancel which reads argv[0..2].
	 *
	 * NOTIFY-05: argv[2] stores fp for the piggyback cancel path.
	 * We store get_file(fp->filp) separately for lifetime safety —
	 * fp itself is a ksmbd abstraction and may be freed, but the
	 * underlying struct file is reference-counted independently.
	 * We use fp->filp just to pin the inode lifetime; the actual
	 * fp pointer is used only while we hold fp->f_lock.
	 *
	 * Concretely: ksmbd_notify_cleanup_file takes fp->f_lock before
	 * removing blocked_works entries, so the cancel callback racing
	 * cleanup_file will either see the entry in blocked_works (still
	 * valid) or see list_empty (cleanup already ran, no fp access needed).
	 * The fp pointer in argv[2] may be stale after cleanup, so we
	 * guard ALL fp accesses with list_empty check inside fp->f_lock.
	 */
	argv[0] = NULL;	/* watch pointer, set by add_watch */
	argv[1] = work;
	argv[2] = fp;

	/*
	 * Compound CHANGE_NOTIFY handling:
	 *
	 * When NOTIFY is the last request in a compound chain (e.g.
	 * CREATE + NOTIFY), the preceding responses (CREATE) must be
	 * sent immediately.  We allocate a separate async work struct
	 * for the pending NOTIFY, set the NOTIFY response in the
	 * compound to STATUS_PENDING, and let the compound response
	 * flow through the normal send path.  The separate async work
	 * owns the final NOTIFY response and is managed by the
	 * cancel/event/cleanup paths.
	 *
	 * For non-compound NOTIFY, the original work struct is used
	 * directly for the async operation (traditional behavior).
	 */
	if (work->next_smb2_rcv_hdr_off) {
		struct ksmbd_work *async_work;

		/*
		 * Allocate a separate work struct for the async NOTIFY.
		 * This work will be used by the cancel/event paths to
		 * send the final NOTIFY response.
		 */
		async_work = ksmbd_alloc_work_struct();
		if (!async_work) {
			kfree(argv);
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
			smb2_set_err_rsp(work);
			ksmbd_fd_put(work, fp);
			return -ENOMEM;
		}

		if (allocate_interim_rsp_buf(async_work)) {
			ksmbd_free_work_struct(async_work);
			kfree(argv);
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
			smb2_set_err_rsp(work);
			ksmbd_fd_put(work, fp);
			return -ENOMEM;
		}

		/* Copy connection/session state to async work */
		async_work->conn = work->conn;
		async_work->sess = work->sess;
		async_work->tcon = work->tcon;
		async_work->encrypted = work->encrypted;

		/*
		 * Hold a refcnt reference on the connection so the conn struct
		 * is not freed while the async_work is alive.  Using refcnt
		 * (not r_count) is critical: r_count is what the connection
		 * handler waits on at teardown (wait_event r_count_q == 0);
		 * incrementing r_count would deadlock shutdown because terminate_fn
		 * (which drives notify cleanup) is only called AFTER r_count == 0.
		 * refcnt just keeps the struct alive without blocking teardown.
		 * Released via ksmbd_conn_free() in the completion paths
		 * (ksmbd_notify_send_cleanup, ksmbd_notify_cancel, etc.).
		 */
		refcount_inc(&async_work->conn->refcnt);

		/* Take a session reference for the async work */
		if (async_work->sess)
			ksmbd_user_session_get(async_work->sess);

		/* Copy the NOTIFY response header to the async work */
		memcpy(smb2_get_msg(async_work->response_buf), rsp,
		       __SMB2_HEADER_STRUCTURE_SIZE);

		/* Update argv to reference the async work, not the compound work */
		argv[1] = async_work;

		async_work->pending_async = 1;
		async_work->send_no_response = 1;

		rc = setup_async_work(async_work, ksmbd_notify_cancel, argv);
		if (rc) {
			if (async_work->sess)
				ksmbd_user_session_put(async_work->sess);
			ksmbd_conn_free(async_work->conn);
			ksmbd_free_work_struct(async_work);
			kfree(argv);
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
			smb2_set_err_rsp(work);
			ksmbd_fd_put(work, fp);
			return rc;
		}

		/*
		 * When notify is disabled (no fsnotify), skip watch
		 * installation.  The async work sits pending until
		 * cancel/cleanup.  argv[0] stays NULL (no watch).
		 */
		if (!ksmbd_notify_enabled())
			goto compound_set_pending;

		rc = ksmbd_notify_add_watch(fp, async_work,
					    completion_filter,
					    watch_tree,
					    output_buf_len,
					    argv);
		if (rc == -EIOCBQUEUED) {
			/*
			 * Buffered changes available: the response was built
			 * synchronously in async_work.  Copy the response back
			 * to the compound work's NOTIFY slot.
			 */
			release_async_work(async_work);
			async_work->pending_async = 0;
			async_work->send_no_response = 0;
			if (async_work->sess)
				ksmbd_user_session_put(async_work->sess);

			/*
			 * CROSS-01: copy full notify response, not just the 64-byte
			 * SMB2 header.  The response includes StructureSize (2),
			 * OutputBufferOffset (2), OutputBufferLength (4), and the
			 * FILE_NOTIFY_INFORMATION body (OutputBufferLength bytes).
			 * Clamp to the compound work's response buffer size to avoid
			 * overflow.
			 */
			{
				struct smb2_notify_rsp *async_rsp =
					smb2_get_msg(async_work->response_buf);
				size_t fixed_part = __SMB2_HEADER_STRUCTURE_SIZE +
					sizeof(async_rsp->StructureSize) +
					sizeof(async_rsp->OutputBufferOffset) +
					sizeof(async_rsp->OutputBufferLength);
				size_t data_len = le32_to_cpu(async_rsp->OutputBufferLength);
				size_t total_notify_len = fixed_part + data_len;
				size_t copy_len = min(total_notify_len, (size_t)work->response_sz);

				memcpy(rsp, async_rsp, copy_len);
			}

			ksmbd_conn_free(async_work->conn);
			ksmbd_free_work_struct(async_work);
			ksmbd_fd_put(work, fp);
			return 0;
		}
		if (rc) {
			release_async_work(async_work);
			async_work->pending_async = 0;
			async_work->send_no_response = 0;
			if (async_work->sess)
				ksmbd_user_session_put(async_work->sess);
			ksmbd_conn_free(async_work->conn);
			ksmbd_free_work_struct(async_work);
			kfree(argv);
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
			smb2_set_err_rsp(work);
			ksmbd_fd_put(work, fp);
			return rc;
		}

compound_set_pending:
		/*
		 * Set the NOTIFY response in the compound to
		 * STATUS_PENDING with ASYNC_COMMAND flag.  The
		 * compound response will be sent by the main
		 * dispatch loop including this pending status.
		 */
		rsp->hdr.Flags |= SMB2_FLAGS_ASYNC_COMMAND;
		rsp->hdr.Id.AsyncId = cpu_to_le64(async_work->async_id);
		smb2_set_err_rsp(work);
		rsp->hdr.Status = STATUS_PENDING;

		ksmbd_fd_put(work, fp);
		return 0;
	}

	/*
	 * Non-compound path: use the original work directly.
	 *
	 * Take an extra session reference BEFORE registering the
	 * async work.  Once setup_async_work returns, the cancel
	 * path can run concurrently and will use work->sess for
	 * signing/encryption.  __handle_ksmbd_work will drop its
	 * own session reference; the async paths (build_response,
	 * cancel, cleanup_file) drop this extra one.
	 */
	if (work->sess)
		ksmbd_user_session_get(work->sess);

	/*
	 * Set pending_async BEFORE setup_async_work so that
	 * handle_ksmbd_work sees it even if the cancel path
	 * fires immediately and frees the work.  pending_async
	 * is read by handle_ksmbd_work after __handle_ksmbd_work
	 * returns, but the cancel can free the work in between.
	 * To prevent the use-after-free, we move the dequeue
	 * logic to the end of __handle_ksmbd_work (see server.c).
	 *
	 * Also set send_no_response early for the same reason --
	 * the main dispatch loop must not send a response even if
	 * the cancel path completes before we return.
	 */
	work->pending_async = 1;
	work->send_no_response = 1;

	rc = setup_async_work(work, ksmbd_notify_cancel,
			      argv);
	if (rc) {
		work->pending_async = 0;
		work->send_no_response = 0;
		if (work->sess)
			ksmbd_user_session_put(work->sess);
		kfree(argv);
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return rc;
	}

	/*
	 * Install the fsnotify watch.  On success argv[0]
	 * is set to the watch pointer for cancel path,
	 * or NULL for piggyback watches on existing marks.
	 */
	rc = ksmbd_notify_add_watch(fp, work,
				    completion_filter,
				    watch_tree,
				    output_buf_len,
				    argv);
	if (rc == -EIOCBQUEUED) {
		/*
		 * Buffered changes were available and the response
		 * was built synchronously by add_watch.  Undo the
		 * async setup and return the response normally
		 * through the main dispatch loop.
		 * Zero cancel_argv before release_async_work() to prevent
		 * a concurrent cancel from racing with the kfree inside it.
		 */
		work->cancel_argv = NULL;
		work->cancel_fn = NULL;
		release_async_work(work);
		work->pending_async = 0;
		work->send_no_response = 0;
		if (work->sess)
			ksmbd_user_session_put(work->sess);
		kfree(argv);
		ksmbd_fd_put(work, fp);
		return 0;
	}
	if (rc) {
		/*
		 * Zero cancel_argv before release_async_work() frees it.
		 * A concurrent cancel path (e.g., connection teardown) may
		 * still hold a reference to the work and call cancel_fn.
		 * Clearing here prevents use-after-free if release_async_work
		 * races with a concurrent cancel reading cancel_argv.
		 */
		work->cancel_argv = NULL;
		work->cancel_fn = NULL;
		release_async_work(work);
		work->pending_async = 0;
		work->send_no_response = 0;
		if (work->sess)
			ksmbd_user_session_put(work->sess);
		kfree(argv);
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		smb2_set_err_rsp(work);
		ksmbd_fd_put(work, fp);
		return rc;
	}

	/*
	 * Grant credits in the interim response.  Call set_rsp_credits
	 * BEFORE smb2_send_interim_resp so the CreditRequest field is
	 * set in the response header, and the interim copy inherits it.
	 */
	if (work->conn->ops->set_rsp_credits)
		work->conn->ops->set_rsp_credits(work);

	/* Send STATUS_PENDING interim response */
	smb2_send_interim_resp(work, STATUS_PENDING);

	ksmbd_fd_put(work, fp);

	/*
	 * At this point, ownership is transferred to the async
	 * subsystem.  The cancel/event/cleanup paths will send the
	 * final response and free the work.  The main handler must
	 * not touch the work after returning (see handle_ksmbd_work
	 * which checks pending_async to skip freeing).
	 */
	return 0;
}
