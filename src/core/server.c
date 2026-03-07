// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include "glob.h"
#include "oplock.h"
#include "misc.h"
#include <linux/sched/signal.h>
#include <linux/workqueue.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "server.h"
#include "smb2pdu.h"
#include "smb_common.h"
#include "smbstatus.h"
#include "connection.h"
#include "transport_ipc.h"
#include "mgmt/user_session.h"
#include "crypto_ctx.h"
#include "auth.h"
#include "smb2fruit.h"
#include "ksmbd_fsctl.h"
#include "ksmbd_create_ctx.h"
#include "ksmbd_info.h"
#include "ksmbd_dfs.h"
#include "ksmbd_vss.h"
#include "ksmbd_notify.h"
#include "ksmbd_reparse.h"
#include "ksmbd_resilient.h"
#include "ksmbd_quota.h"
#include "ksmbd_app_instance.h"
#include "ksmbd_rsvd.h"
#include "ksmbd_fsctl_extra.h"
#include "ksmbd_hooks.h"
#include "ksmbd_buffer.h"
#include "ksmbd_branchcache.h"
#include "vfs_cache.h"
#include "ksmbd_md4.h"
#include "mgmt/ksmbd_witness.h"

/*
 * ksmbd_debug_types is read from hot paths (ksmbd_debug() macro)
 * and written only from the sysfs debug_store handler.  A torn read
 * is benign -- it may briefly show stale debug flags -- so we
 * deliberately avoid atomic_t / locking overhead here.
 */
int ksmbd_debug_types;

struct ksmbd_server_config server_conf;

enum SERVER_CTRL_TYPE {
	SERVER_CTRL_TYPE_INIT,
	SERVER_CTRL_TYPE_RESET,
};

struct server_ctrl_struct {
	int			type;
	struct work_struct	ctrl_work;
};

static DEFINE_MUTEX(ctrl_lock);

static int ___server_conf_set(int idx, char *val)
{
	if (idx >= ARRAY_SIZE(server_conf.conf))
		return -EINVAL;

	if (!val || val[0] == 0x00)
		return -EINVAL;

	kfree(server_conf.conf[idx]);
	server_conf.conf[idx] = kstrdup(val, KSMBD_DEFAULT_GFP);
	if (!server_conf.conf[idx])
		return -ENOMEM;
	return 0;
}

int ksmbd_set_netbios_name(char *v)
{
	return ___server_conf_set(SERVER_CONF_NETBIOS_NAME, v);
}

int ksmbd_set_server_string(char *v)
{
	return ___server_conf_set(SERVER_CONF_SERVER_STRING, v);
}

int ksmbd_set_work_group(char *v)
{
	return ___server_conf_set(SERVER_CONF_WORK_GROUP, v);
}

char *ksmbd_netbios_name(void)
{
	return server_conf.conf[SERVER_CONF_NETBIOS_NAME];
}

char *ksmbd_server_string(void)
{
	return server_conf.conf[SERVER_CONF_SERVER_STRING];
}

char *ksmbd_work_group(void)
{
	return server_conf.conf[SERVER_CONF_WORK_GROUP];
}

/**
 * check_conn_state() - check state of server thread connection
 * @work:     smb work containing server thread information
 *
 * Return:	0 on valid connection, otherwise 1 to reconnect
 */
static inline int check_conn_state(struct ksmbd_work *work)
{
	struct smb_hdr *rsp_hdr;

	if (ksmbd_conn_exiting(work->conn) ||
	    ksmbd_conn_need_reconnect(work->conn) ||
	    ksmbd_conn_releasing(work->conn)) {
		rsp_hdr = work->response_buf;
		rsp_hdr->Status.CifsError = STATUS_CONNECTION_DISCONNECTED;
		return 1;
	}
	return 0;
}

#define SERVER_HANDLER_CONTINUE		0
#define SERVER_HANDLER_ABORT		1

static int __process_request(struct ksmbd_work *work, struct ksmbd_conn *conn,
			     u16 *cmd)
{
	struct smb_version_cmds *cmds;
	u16 command;
	int ret;

	if (check_conn_state(work))
		return SERVER_HANDLER_CONTINUE;

	ret = ksmbd_verify_smb_message(work);
	if (ret) {
		/*
		 * Return code 2 = credit exhaustion (insufficient credits
		 * to process the request).  Per MS-SMB2, the server SHOULD
		 * return STATUS_INSUFFICIENT_RESOURCES.
		 * Return code 1 = structural validation failure.
		 */
		__le32 err_status = (ret == 2) ?
			STATUS_INSUFFICIENT_RESOURCES :
			STATUS_INVALID_PARAMETER;

		if (work->next_smb2_rcv_hdr_off) {
			/*
			 * In a compound chain, set the error on the
			 * current response position without clobbering
			 * previous responses.  Continue processing so
			 * that credits are granted and the chain
			 * advances properly.
			 */
			struct smb2_hdr *rsp_hdr =
				ksmbd_resp_buf_next(work);

			rsp_hdr->Status = err_status;
			smb2_set_err_rsp(work);
			*cmd = get_smb2_cmd_val(work);
			return SERVER_HANDLER_CONTINUE;
		}
		conn->ops->set_rsp_status(work, err_status);
		return SERVER_HANDLER_ABORT;
	}

	command = conn->ops->get_cmd_val(work);
	*cmd = command;

andx_again:
	if (command >= conn->max_cmds) {
		conn->ops->set_rsp_status(work, STATUS_INVALID_PARAMETER);
		return SERVER_HANDLER_CONTINUE;
	}

	cmds = &conn->cmds[command];
	if (!cmds->proc) {
		ksmbd_debug(SMB, "*** not implemented yet cmd = %x\n", command);
		conn->ops->set_rsp_status(work, STATUS_NOT_IMPLEMENTED);
		return SERVER_HANDLER_CONTINUE;
	}

	if (work->sess && conn->ops->is_sign_req(work, command)) {
		ret = conn->ops->check_sign_req(work);
		if (!ret) {
			conn->ops->set_rsp_status(work, STATUS_ACCESS_DENIED);
			return SERVER_HANDLER_CONTINUE;
		}
	}

	/*
	 * Re-check connection state right before dispatching.
	 * A connection may have entered releasing state while
	 * we were doing signature verification or other pre-dispatch
	 * work above.
	 */
	if (ksmbd_conn_releasing(work->conn)) {
		conn->ops->set_rsp_status(work, STATUS_CONNECTION_DISCONNECTED);
		return SERVER_HANDLER_ABORT;
	}

	{
		unsigned long cmd_start = jiffies;

		ret = cmds->proc(work);

		if (time_after(jiffies, cmd_start + 10 * HZ))
			pr_warn("ksmbd: cmd 0x%x handler took %u ms (pid=%d)\n",
				command,
				jiffies_to_msecs(jiffies - cmd_start),
				current->pid);
	}

	if (ret < 0)
		ksmbd_debug(CONN, "Failed to process %u [%d]\n", command, ret);
	/* AndX commands - chained request can return positive values */
	else if (ret > 0) {
		command = ret;
		*cmd = command;
		goto andx_again;
	}

	if (work->send_no_response)
		return SERVER_HANDLER_ABORT;
	return SERVER_HANDLER_CONTINUE;
}

static bool __handle_ksmbd_work(struct ksmbd_work *work,
				struct ksmbd_conn *conn)
{
	u16 command = 0;
	int rc;
	bool is_chained = false;
	/* TC-06: cache enc_forced so it survives work->sess going NULL mid-compound */
	bool sess_enc_forced = false;

	/*
	 * Handle compressed requests: decompress before any other
	 * processing. After decompression, the request buffer contains
	 * a standard SMB2 message (or an encrypted transform message
	 * that was compressed).
	 */
	if (smb2_is_compression_transform_hdr(work->request_buf)) {
		rc = smb2_decompress_req(work);
		if (rc < 0)
			return false;
	}

	if (conn->ops->is_transform_hdr &&
	    conn->ops->is_transform_hdr(work->request_buf)) {
		rc = conn->ops->decrypt_req(work);
		if (rc < 0) {
			ksmbd_audit("decrypt failure conn=%pIS",
				    KSMBD_TCP_PEER_SOCKADDR(conn));
			return false;
		}
		work->encrypted = true;
	}

	if (conn->ops->allocate_rsp_buf(work))
		return false;

	rc = conn->ops->init_rsp_hdr(work);
	if (rc) {
		/* either uid or tid is not correct */
		conn->ops->set_rsp_status(work, STATUS_INVALID_HANDLE);
		goto send;
	}

	do {
		/*
		 * If the connection is shutting down, break out of
		 * the compound processing loop immediately.  This
		 * handles the case where a kworker entered
		 * __handle_ksmbd_work before the connection was set
		 * to releasing, and releasing was set mid-processing.
		 *
		 * TC-17: Before breaking, ensure the last completed
		 * response has NextCommand=0 (chain terminator).
		 * init_chained_smb2_rsp() sets NextCommand to a non-zero
		 * offset for the sub-request being prepared; if we break
		 * before processing it the response buffer would have a
		 * dangling forward pointer into unwritten memory.
		 */
		if (ksmbd_conn_releasing(conn) || !ksmbd_conn_alive(conn)) {
			if (work->next_smb2_rcv_hdr_off) {
				struct smb2_hdr *last_rsp =
					(struct smb2_hdr *)(work->response_buf +
					work->curr_smb2_rsp_hdr_off + 4);

				last_rsp->NextCommand = 0;
			}
			break;
		}

		/*
		 * Compound error propagation per MS-SMB2 3.3.5.2.3:
		 *
		 * When a CREATE in a related compound chain fails, all
		 * subsequent related operations MUST return the same
		 * error status (the compound handle was never
		 * established, so nothing can operate on it).
		 *
		 * However, if a valid compound file handle exists
		 * (established by a prior successful CREATE),
		 * intermediate operation failures (e.g. WRITE
		 * returning ACCESS_DENIED on a read-only handle) MUST
		 * NOT be propagated -- the handle is still valid and
		 * subsequent operations should execute independently.
		 *
		 * Errors from non-CREATE operations (e.g. READ
		 * returning END_OF_FILE) are also NOT propagated; the
		 * next related request gets its own validation.
		 */
		if (work->next_smb2_rcv_hdr_off) {
			struct smb2_hdr *req_hdr = ksmbd_req_buf_next(work);

			if (req_hdr->Flags & SMB2_FLAGS_RELATED_OPERATIONS) {
				if (work->compound_err_status !=
				    STATUS_SUCCESS) {
					struct smb2_hdr *rsp_hdr =
						ksmbd_resp_buf_next(work);

					rsp_hdr->Status =
						work->compound_err_status;
					smb2_set_err_rsp(work);
					command = get_smb2_cmd_val(work);
					goto compound_continue;
				}
			}
		}

		if (conn->ops->check_user_session) {
			rc = conn->ops->check_user_session(work);
			if (rc < 0) {
				struct smb2_hdr *rsp_hdr =
					ksmbd_resp_buf_next(work);
				__le32 err_status;

				err_status = (rc == -EINVAL) ?
					STATUS_INVALID_PARAMETER :
					STATUS_USER_SESSION_DELETED;
				rsp_hdr->Status = err_status;
				smb2_set_err_rsp(work);
				command = get_smb2_cmd_val(work);

				/*
				 * TC-08: In a related compound chain, session
				 * lookup failure leaves work->sess NULL.
				 * Propagate the error via compound_err_status
				 * so subsequent related sub-requests return
				 * this status directly without touching sess.
				 *
				 * Only propagate when the FAILING request itself
				 * is related.  An unrelated sub-request failure
				 * must not set compound_err_status so that a
				 * subsequent related request can evaluate its
				 * own session state independently
				 * (MS-SMB2 §3.3.5.2.3, smb2.compound.invalid2).
				 */
				if (work->next_smb2_rcv_hdr_off) {
					struct smb2_hdr *fail_hdr =
						ksmbd_req_buf_next(work);
					if (fail_hdr->Flags &
					    SMB2_FLAGS_RELATED_OPERATIONS)
						work->compound_err_status = err_status;
				}

				goto compound_continue;
			} else if (rc > 0) {
				rc = conn->ops->get_ksmbd_tcon(work);
				if (rc < 0) {
					struct smb2_hdr *rsp_hdr =
						ksmbd_resp_buf_next(work);

					rsp_hdr->Status = (rc == -EINVAL) ?
						STATUS_INVALID_PARAMETER :
						STATUS_NETWORK_NAME_DELETED;
					smb2_set_err_rsp(work);
					command = get_smb2_cmd_val(work);
					goto compound_continue;
				}
			}
		}

		/* TC-06: update cached enc_forced each iteration */
		if (work->sess && work->sess->enc_forced)
			sess_enc_forced = true;

		/*
		 * MS-SMB2 §3.3.5.2.5: If Session.EncryptData is TRUE and the
		 * request was not encrypted, the server MUST disconnect the
		 * connection (except for NEGOTIATE and SESSION_SETUP which
		 * establish the encrypted channel).
		 *
		 * Note: sess->enc is set whenever encryption keys are generated
		 * (all SMB3 sessions); sess->enc_forced is set only when the
		 * server actually set SMB2_SESSION_FLAG_ENCRYPT_DATA in the
		 * SESSION_SETUP response (global flag or per-client request).
		 * Only enforce when encryption was actually required.
		 *
		 * TC-06: use sess_enc_forced when work->sess is NULL (session
		 * error mid-compound chain) to prevent encryption bypass.
		 */
		if ((work->sess ? work->sess->enc_forced : sess_enc_forced) &&
		    !work->encrypted) {
			command = get_smb2_cmd_val(work);
			if (command != SMB2_NEGOTIATE_HE &&
			    command != SMB2_SESSION_SETUP_HE) {
				struct smb2_hdr *rsp_hdr =
					ksmbd_resp_buf_next(work);

				pr_warn_ratelimited("Unencrypted request (cmd=0x%x) on encrypted session, disconnecting [off=%d]\n",
						    command, work->next_smb2_rcv_hdr_off);
				rsp_hdr->Status = STATUS_ACCESS_DENIED;
				smb2_set_err_rsp(work);
				ksmbd_conn_set_exiting(conn);
				goto compound_continue;
			}
		}

		rc = __process_request(work, conn, &command);
		if (rc == SERVER_HANDLER_ABORT) {
			/*
			 * Grant credits even on abort so the client does not
			 * deplete its credit budget.  This matters for scan /
			 * probe traffic (e.g. smb2.scan) where unknown opcodes
			 * are rejected before validate_credit is reached; without
			 * this the per-request credit charge is never replenished
			 * and the client stalls with 0 available credits.
			 * smb2_set_rsp_credits() handles send_no_response
			 * internally (early-returns 0), so it is safe to call
			 * unconditionally here.
			 */
			if (conn->ops->set_rsp_credits)
				conn->ops->set_rsp_credits(work);
			break;
		}

		/*
		 * Call smb2_set_rsp_credits() function to set number of credits
		 * granted in hdr of smb2 response.
		 */
		if (conn->ops->set_rsp_credits) {
			ksmbd_debug(SMB,
				    "credit_rsp: dispatch cmd=%u total=%u out=%u granted_total=%u\n",
				    command, conn->total_credits,
				    conn->outstanding_credits,
				    work->credits_granted);
			rc = conn->ops->set_rsp_credits(work);
			if (rc < 0)
				pr_err_ratelimited("Failed to set credits for cmd %u\n",
						   command);
		}

compound_continue:
		is_chained = is_chained_smb2_message(work);

		if (work->sess &&
		    (work->sess->sign || smb3_11_final_sess_setup_resp(work) ||
		     conn->ops->is_sign_req(work, command)))
			conn->ops->set_sign_rsp(work);
	} while (is_chained == true);

send:
	/*
	 * If the connection is shutting down, skip all post-processing
	 * (signing, encryption, compression, write).  The transport and
	 * session state may already be torn down by the connection
	 * handler thread.  Accessing them would be use-after-free.
	 */
	if (ksmbd_conn_releasing(conn)) {
		if (work->sess)
			ksmbd_user_session_put(work->sess);
		if (work->tcon)
			ksmbd_tree_connect_put(work->tcon);
		return false;
	}

	if (work->tcon)
		ksmbd_tree_connect_put(work->tcon);
	smb3_preauth_hash_rsp(work);
	/*
	 * In a compound request, smb2_check_user_session() releases
	 * work->sess when a non-related sub-request carries an invalid
	 * session ID (e.g. smb2.compound.invalid2: CLOSEs with a fake
	 * session in the middle of the chain).  If the original request
	 * was encrypted we still need a valid session to encrypt the
	 * compound response.  Re-fetch from the first SMB2 header's
	 * SessionId, which is always the real session used to decrypt
	 * the Transform packet.
	 */
	if (work->encrypted && !work->sess && conn->ops->encrypt_resp) {
		struct smb2_hdr *hdr = smb2_get_msg(work->request_buf);

		work->sess = ksmbd_session_lookup_all(conn,
						      le64_to_cpu(hdr->SessionId));
		/*
		 * If the inner SMB2 header had an invalid session ID (e.g.
		 * smb2.tcon "invalid VUID" subtest), fall back to the session
		 * that was used to decrypt the TRANSFORM header.  Without this
		 * the server sends an unencrypted error response, causing the
		 * client to disconnect (NT_STATUS_CONNECTION_DISCONNECTED).
		 */
		if (!work->sess && work->tr_sess_id)
			work->sess = ksmbd_session_lookup_all(conn,
							      work->tr_sess_id);
	}
	/*
	 * Skip encrypt/compress for async pending work (send_no_response).
	 * The response buffer is owned by the async subsystem
	 * (e.g. CHANGE_NOTIFY) which will sign/encrypt/send it
	 * when the operation completes or is cancelled.
	 * Running encrypt_resp here would corrupt the IOV state
	 * (allocate tr_buf, overwrite iov[0]) making the async
	 * completion path fail.
	 */
	if (!work->send_no_response) {
		if (work->sess && work->sess->enc && work->encrypted &&
		    conn->ops->encrypt_resp) {
			rc = conn->ops->encrypt_resp(work);
			if (rc < 0)
				conn->ops->set_rsp_status(work,
							  STATUS_DATA_ERROR);
		} else {
			/*
			 * Compress the response if compression was negotiated
			 * and the response is not encrypted.
			 */
			smb2_compress_resp(work);
		}
	}
	if (work->sess)
		ksmbd_user_session_put(work->sess);

	/*
	 * For async pending work (CHANGE_NOTIFY), dequeue from the
	 * synchronous request list NOW, while we still have a valid
	 * reference to the work struct.  After this point, we must
	 * NOT touch the work again -- a concurrent SMB2_CANCEL on
	 * another kworker may have already freed it (or will free
	 * it the instant we release the request_lock).
	 *
	 * We save pending_async in a local before dequeuing because
	 * handle_ksmbd_work needs to know whether to free the work.
	 */
	if (work->pending_async) {
		spin_lock(&conn->request_lock);
		list_del_init(&work->request_entry);
		spin_unlock(&conn->request_lock);
		/*
		 * Do NOT access 'work' after this point.
		 * ksmbd_conn_write is skipped because
		 * send_no_response was already set.
		 */
		return true;
	}

	ksmbd_conn_write(work);
	return false;
}

/**
 * handle_ksmbd_work() - process pending smb work requests
 * @wk:	smb work containing request command buffer
 *
 * called by kworker threads to processing remaining smb work requests
 */
static void handle_ksmbd_work(struct work_struct *wk)
{
	struct ksmbd_work *work = container_of(wk, struct ksmbd_work, work);
	struct ksmbd_conn *conn = work->conn;
	unsigned long start_jiffies = jiffies;
	bool is_async;

	/*
	 * If the connection is already shutting down, skip all
	 * processing.  The transport may be torn down and accessing
	 * it (e.g. via ksmbd_conn_write) would hang or crash.
	 */
	if (ksmbd_conn_releasing(conn) || ksmbd_conn_exiting(conn)) {
		ksmbd_conn_try_dequeue_request(work);
		ksmbd_free_work_struct(work);
		ksmbd_conn_r_count_dec(conn);
		ksmbd_conn_free(conn);
		module_put(THIS_MODULE);
		return;
	}

	atomic64_inc(&conn->stats.request_served);

	is_async = __handle_ksmbd_work(work, conn);

	if (time_after(jiffies, start_jiffies + 30 * HZ))
		pr_warn_ratelimited("ksmbd: handle_ksmbd_work took %u ms\n",
				    jiffies_to_msecs(jiffies - start_jiffies));

	/*
	 * If __handle_ksmbd_work returned true (pending_async path),
	 * it already dequeued the work from conn->requests and the
	 * async subsystem now owns the work lifetime.  A concurrent
	 * SMB2_CANCEL on another kworker may have already freed the
	 * work, so we MUST NOT touch 'work' at all.  Just decrement
	 * the connection reference count using our saved 'conn'.
	 *
	 * For non-async work (returned false), the work is still
	 * valid and we free it normally.
	 */
	if (!is_async) {
		ksmbd_conn_try_dequeue_request(work);
		ksmbd_free_work_struct(work);
	}
	ksmbd_conn_r_count_dec(conn);
	/*
	 * Drop the per-work connection reference taken in
	 * queue_ksmbd_work().  This may be the final reference
	 * (if the handler thread already exited), triggering
	 * connection cleanup.
	 */
	ksmbd_conn_free(conn);
	module_put(THIS_MODULE);
}

/**
 * queue_ksmbd_work() - queue a smb request to worker thread queue
 *		for processing smb command and sending response
 * @conn:	connection instance
 *
 * read remaining data from socket create and submit work.
 */
static int queue_ksmbd_work(struct ksmbd_conn *conn)
{
	struct ksmbd_work *work;
	int err;

	err = ksmbd_init_smb_server(conn);
	if (err)
		return err;

	work = ksmbd_alloc_work_struct();
	if (!work) {
		pr_err("allocation for work failed\n");
		return -ENOMEM;
	}

	work->conn = conn;
	/*
	 * Ownership transfer: the request buffer moves from the
	 * connection to the work struct.  After this assignment,
	 * conn->request_buf is set to NULL to indicate the connection
	 * no longer owns the buffer.  The work struct (and ultimately
	 * ksmbd_free_work_struct()) is now responsible for freeing it.
	 *
	 * This pattern must be maintained: every buffer must have
	 * exactly one owner at any point in time.
	 */
	WARN_ON_ONCE(!conn->request_buf);
	work->request_buf = conn->request_buf;
	conn->request_buf = NULL;

	ksmbd_conn_enqueue_request(work);
	ksmbd_conn_r_count_inc(conn);
	/*
	 * Take a connection reference for the kworker.  This ensures
	 * the connection stays alive until the work item finishes,
	 * even if the handler thread exits and drops its initial
	 * reference in the meantime.  The matching ksmbd_conn_free()
	 * is in handle_ksmbd_work().
	 *
	 * Also take a module reference so rmmod cannot unload the
	 * module while kworkers are still executing.  The matching
	 * module_put() is in handle_ksmbd_work().
	 */
	refcount_inc(&conn->refcnt);
	__module_get(THIS_MODULE);
	/* update activity on connection */
	WRITE_ONCE(conn->last_active, jiffies);
	INIT_WORK(&work->work, handle_ksmbd_work);
	ksmbd_queue_work(work);
	return 0;
}

static int ksmbd_server_process_request(struct ksmbd_conn *conn)
{
	return queue_ksmbd_work(conn);
}

static int ksmbd_server_terminate_conn(struct ksmbd_conn *conn)
{
	ksmbd_sessions_deregister(conn);
	destroy_lease_table(conn);
	return 0;
}

static void ksmbd_server_tcp_callbacks_init(void)
{
	struct ksmbd_conn_ops ops;

	ops.process_fn = ksmbd_server_process_request;
	ops.terminate_fn = ksmbd_server_terminate_conn;

	ksmbd_conn_init_server_callbacks(&ops);
}

static void server_conf_free(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(server_conf.conf); i++) {
		kfree(server_conf.conf[i]);
		server_conf.conf[i] = NULL;
	}
}

static int server_conf_init(void)
{
	WRITE_ONCE(server_conf.state, SERVER_STATE_STARTING_UP);
	server_conf.min_protocol = ksmbd_min_protocol();
	server_conf.max_protocol = ksmbd_max_protocol();
	server_conf.auth_mechs = KSMBD_AUTH_NTLMSSP;
	server_conf.auth_mechs |= KSMBD_AUTH_KRB5 |
				KSMBD_AUTH_MSKRB5;
	server_conf.max_inflight_req = SMB2_MAX_CREDITS;
	server_conf.max_async_credits = 512;
	return 0;
}

static void server_ctrl_handle_init(struct server_ctrl_struct *ctrl)
{
	int ret;

	/*
	 * Re-initialize the global file table after a reset.
	 * server_ctrl_handle_reset() calls ksmbd_free_global_file_table()
	 * which sets global_ft.idr = NULL.  Without this re-init, any
	 * subsequent ksmbd_open_durable_fd() call crashes with a NULL
	 * pointer dereference in idr_alloc_cyclic().
	 * Skip if already initialized (first daemon start after module load).
	 */
	if (!ksmbd_global_file_table_inited()) {
		ret = ksmbd_init_global_file_table();
		if (ret) {
			server_queue_ctrl_reset_work();
			return;
		}
	}

	ret = ksmbd_conn_transport_init();
	if (ret) {
		server_queue_ctrl_reset_work();
		return;
	}

	WRITE_ONCE(server_conf.state, SERVER_STATE_RUNNING);
}

static void server_ctrl_handle_reset(struct server_ctrl_struct *ctrl)
{
	ksmbd_ipc_soft_reset();
	/*
	 * Ask the durable scavenger to exit before transport teardown so a
	 * sleeper on its long timeout does not keep shutdown waiting for the
	 * later synchronous kthread_stop().  The scavenger now checks the stop
	 * request before every scan, so this early wake does not send it back
	 * into m_lock acquisition during reset.
	 */
	ksmbd_request_durable_scavenger_stop();
	/*
	 * Tear down all connections next.  Connection handler kthreads may
	 * hold fp->f_ci->m_lock while processing requests, so the synchronous
	 * stop still waits until transports and workers are drained.
	 */
	ksmbd_conn_transport_destroy();
	/*
	 * Flush the ksmbd workqueue to ensure all pending handle_ksmbd_work()
	 * items have completed and released their module references before we
	 * proceed.  This eliminates spurious rmmod -EBUSY failures.
	 */
	ksmbd_workqueue_flush();
	/*
	 * Now wait for the durable scavenger to exit: transports are gone and
	 * workers are drained, so no remaining m_lock holder can pin it.
	 */
	ksmbd_stop_durable_scavenger();
	ksmbd_free_global_file_table();
	server_conf_free();
	server_conf_init();
	WRITE_ONCE(server_conf.state, SERVER_STATE_STARTING_UP);
}

static void server_ctrl_handle_work(struct work_struct *work)
{
	struct server_ctrl_struct *ctrl;

	ctrl = container_of(work, struct server_ctrl_struct, ctrl_work);

	mutex_lock(&ctrl_lock);
	switch (ctrl->type) {
	case SERVER_CTRL_TYPE_INIT:
		server_ctrl_handle_init(ctrl);
		break;
	case SERVER_CTRL_TYPE_RESET:
		server_ctrl_handle_reset(ctrl);
		break;
	default:
		pr_err("Unknown server work type: %d\n", ctrl->type);
	}
	mutex_unlock(&ctrl_lock);
	kfree(ctrl);
	module_put(THIS_MODULE);
}

static int __queue_ctrl_work(int type)
{
	struct server_ctrl_struct *ctrl;

	ctrl = kmalloc(sizeof(struct server_ctrl_struct), KSMBD_DEFAULT_GFP);
	if (!ctrl)
		return -ENOMEM;

	__module_get(THIS_MODULE);
	ctrl->type = type;
	INIT_WORK(&ctrl->ctrl_work, server_ctrl_handle_work);
	queue_work(system_long_wq, &ctrl->ctrl_work);
	return 0;
}

int server_queue_ctrl_init_work(void)
{
	return __queue_ctrl_work(SERVER_CTRL_TYPE_INIT);
}

int server_queue_ctrl_reset_work(void)
{
	return __queue_ctrl_work(SERVER_CTRL_TYPE_RESET);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static ssize_t stats_show(const struct class *class, const struct class_attribute *attr,
#else
static ssize_t stats_show(struct class *class, struct class_attribute *attr,
#endif
			  char *buf)
{
	/*
	 * Inc this each time you change stats output format,
	 * so user space will know what to do.
	 */
	static int stats_version = 2;
	static const char * const state[] = {
		"startup",
		"running",
		"reset",
		"shutdown"
	};
	unsigned int cur_state = READ_ONCE(server_conf.state);

	if (cur_state >= ARRAY_SIZE(state))
		cur_state = SERVER_STATE_SHUTTING_DOWN;
	return sysfs_emit(buf, "%d %s %d %lu\n", stats_version,
			  state[cur_state],
			  READ_ONCE(server_conf.tcp_port),
			  READ_ONCE(server_conf.ipc_last_active) / HZ);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static ssize_t kill_server_store(const struct class *class,
				 const struct class_attribute *attr, const char *buf,
#else
static ssize_t kill_server_store(struct class *class,
				 struct class_attribute *attr, const char *buf,
#endif
				 size_t len)
{
	if (!sysfs_streq(buf, "hard"))
		return len;

	mutex_lock(&ctrl_lock);
	WRITE_ONCE(server_conf.state, SERVER_STATE_RESETTING);
	__module_get(THIS_MODULE);
	server_ctrl_handle_reset(NULL);
	module_put(THIS_MODULE);
	mutex_unlock(&ctrl_lock);
	return len;
}

static const char * const debug_type_strings[] = {"smb", "auth", "vfs",
						  "oplock", "ipc", "conn",
						  "rdma"};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static ssize_t debug_show(const struct class *class, const struct class_attribute *attr,
#else
static ssize_t debug_show(struct class *class, struct class_attribute *attr,
#endif
			  char *buf)
{
	ssize_t sz = 0;
	int i, pos = 0;

	for (i = 0; i < ARRAY_SIZE(debug_type_strings); i++) {
		if ((ksmbd_debug_types >> i) & 1) {
			pos = sysfs_emit_at(buf, sz, "[%s] ", debug_type_strings[i]);
		} else {
			pos = sysfs_emit_at(buf, sz, "%s ", debug_type_strings[i]);
		}
		sz += pos;
	}
	sz += sysfs_emit_at(buf, sz, "\n");
	return sz;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static ssize_t debug_store(const struct class *class, const struct class_attribute *attr,
#else
static ssize_t debug_store(struct class *class, struct class_attribute *attr,
#endif
			   const char *buf, size_t len)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(debug_type_strings); i++) {
		if (sysfs_streq(buf, "all")) {
			if (ksmbd_debug_types == KSMBD_DEBUG_ALL)
				ksmbd_debug_types = 0;
			else
				ksmbd_debug_types = KSMBD_DEBUG_ALL;
			break;
		}

		if (sysfs_streq(buf, debug_type_strings[i])) {
			if (ksmbd_debug_types & (1 << i))
				ksmbd_debug_types &= ~(1 << i);
			else
				ksmbd_debug_types |= (1 << i);
			break;
		}
	}

	return len;
}

static CLASS_ATTR_RO(stats);
static CLASS_ATTR_WO(kill_server);
static CLASS_ATTR_RW(debug);

static struct attribute *ksmbd_control_class_attrs[] = {
	&class_attr_stats.attr,
	&class_attr_kill_server.attr,
	&class_attr_debug.attr,
	NULL,
};
ATTRIBUTE_GROUPS(ksmbd_control_class);

static struct class ksmbd_control_class = {
	.name		= "ksmbd-control",
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	.owner		= THIS_MODULE,
#endif
	.class_groups	= ksmbd_control_class_groups,
};

static int ksmbd_server_shutdown(void)
{
	WRITE_ONCE(server_conf.state, SERVER_STATE_SHUTTING_DOWN);

	ksmbd_debugfs_exit();
	class_unregister(&ksmbd_control_class);
	/*
	 * Shutdown order:
	 * 1. Request durable scavenger stop and wake it out of timeout sleep
	 * 2. Tear down transports + drain connections (releases m_lock holders)
	 * 3. Stop the durable scavenger synchronously
	 * 3. Destroy workqueue (must outlive all work items)
	 * 4. Release IPC + crypto
	 * 5. Free global file table (all connections dead)
	 */
	ksmbd_branchcache_cleanup();
	ksmbd_request_durable_scavenger_stop();
	ksmbd_conn_transport_destroy();
	ksmbd_stop_durable_scavenger();
	ksmbd_workqueue_destroy();
	ksmbd_ipc_release();
	ksmbd_crypto_destroy();
	ksmbd_free_global_file_table();
	destroy_lease_table(NULL);
	ksmbd_oplock_exit();
	ksmbd_work_pool_destroy();
	ksmbd_buffer_pool_exit();
	ksmbd_exit_file_cache();
	server_conf_free();
	ksmbd_config_exit();
	return 0;
}

static int __init ksmbd_server_init(void)
{
	int ret;

	ret = ksmbd_config_init();
	if (ret) {
		pr_err("Failed to initialize configuration subsystem\n");
		return ret;
	}

	ret = ksmbd_md4_register();
	if (ret)
		goto err_config_exit;

	ret = class_register(&ksmbd_control_class);
	if (ret) {
		pr_err("Unable to register ksmbd-control class\n");
		goto err_md4_unregister;
	}

	ksmbd_server_tcp_callbacks_init();

	ret = server_conf_init();
	if (ret)
		goto err_unregister;

	ret = ksmbd_work_pool_init();
	if (ret)
		goto err_unregister;

	ret = ksmbd_buffer_pool_init();
	if (ret)
		goto err_destroy_work_pools;

	ret = ksmbd_init_file_cache();
	if (ret)
		goto err_destroy_buffer_pool;

	ret = ksmbd_oplock_init();
	if (ret)
		goto err_exit_file_cache;

	ret = ksmbd_ipc_init();
	if (ret)
		goto err_exit_oplock;

	ret = ksmbd_init_global_file_table();
	if (ret)
		goto err_ipc_release;

	ret = ksmbd_inode_hash_init();
	if (ret)
		goto err_destroy_file_table;

	ret = ksmbd_crypto_create();
	if (ret)
		goto err_release_inode_hash;

	ret = ksmbd_workqueue_init();
	if (ret)
		goto err_crypto_destroy;

	/*
	 * NEG-04: Initialize ServerGUID once at module startup to eliminate
	 * the lazy-init race in smb2_handle_negotiate().  Two simultaneous
	 * first-negotiate requests could each see all-zero GUID, generate
	 * different random GUIDs, and the last writer would win.
	 */
	get_random_bytes(server_conf.server_guid, SMB2_CLIENT_GUID_SIZE);

	/* Generate random BranchCache server secret */
	ksmbd_branchcache_generate_secret();

	/* Initialize Fruit SMB extensions */
	ret = fruit_init_module();
	if (ret)
		goto err_workqueue_destroy;

	ret = ksmbd_debugfs_init();
	if (ret)
		goto err_debugfs;

	ret = ksmbd_fsctl_init();
	if (ret)
		goto err_fsctl;

	ret = ksmbd_dfs_init();
	if (ret)
		goto err_dfs;

	ret = ksmbd_vss_init();
	if (ret)
		goto err_vss;

	ret = ksmbd_create_ctx_init();
	if (ret)
		goto err_create_ctx;

	ret = ksmbd_info_init();
	if (ret)
		goto err_info;

	ret = ksmbd_notify_init();
	if (ret)
		goto err_notify;

	ret = ksmbd_reparse_init();
	if (ret)
		goto err_reparse;

	ret = ksmbd_resilient_init();
	if (ret)
		goto err_resilient;

	ret = ksmbd_quota_init();
	if (ret)
		goto err_quota;

	ret = ksmbd_app_instance_init();
	if (ret)
		goto err_app_instance;

	ret = ksmbd_rsvd_init();
	if (ret)
		goto err_rsvd;

	ret = ksmbd_fsctl_extra_init();
	if (ret)
		goto err_fsctl_extra;

	ret = ksmbd_hooks_init();
	if (ret)
		goto err_hooks;

	ret = ksmbd_witness_init();
	if (ret)
		goto err_witness;

	ret = ksmbd_lock_cache_init();
	if (ret)
		goto err_lock_cache;

	return 0;

err_lock_cache:
	ksmbd_witness_exit();
err_witness:
	ksmbd_hooks_exit();
err_hooks:
	ksmbd_fsctl_extra_exit();
err_fsctl_extra:
	ksmbd_rsvd_exit();
err_rsvd:
	ksmbd_app_instance_exit();
err_app_instance:
	ksmbd_quota_exit();
err_quota:
	ksmbd_resilient_exit();
err_resilient:
	ksmbd_reparse_exit();
err_reparse:
	ksmbd_notify_exit();
err_notify:
	ksmbd_info_exit();
err_info:
	ksmbd_create_ctx_exit();
err_create_ctx:
	ksmbd_vss_exit();
err_vss:
	ksmbd_dfs_exit();
err_dfs:
	ksmbd_fsctl_exit();
err_fsctl:
	ksmbd_debugfs_exit();
err_debugfs:
	fruit_cleanup_module();
err_workqueue_destroy:
	ksmbd_workqueue_destroy();
err_crypto_destroy:
	ksmbd_crypto_destroy();
err_release_inode_hash:
	ksmbd_release_inode_hash();
err_destroy_file_table:
	ksmbd_free_global_file_table();
err_ipc_release:
	ksmbd_ipc_release();
err_exit_oplock:
	ksmbd_oplock_exit();
err_exit_file_cache:
	ksmbd_exit_file_cache();
err_destroy_buffer_pool:
	ksmbd_buffer_pool_exit();
err_destroy_work_pools:
	ksmbd_work_pool_destroy();
err_unregister:
	class_unregister(&ksmbd_control_class);
err_md4_unregister:
	ksmbd_md4_unregister();
err_config_exit:
	ksmbd_config_exit();

	return ret;
}

/**
 * ksmbd_server_exit() - shutdown forker thread and free memory at module exit
 */
static void __exit ksmbd_server_exit(void)
{
	ksmbd_lock_cache_destroy();
	ksmbd_witness_exit();
	ksmbd_hooks_exit();
	ksmbd_fsctl_extra_exit();
	ksmbd_rsvd_exit();
	ksmbd_app_instance_exit();
	ksmbd_quota_exit();
	ksmbd_resilient_exit();
	ksmbd_reparse_exit();
	ksmbd_info_exit();
	ksmbd_create_ctx_exit();
	ksmbd_vss_exit();
	ksmbd_dfs_exit();
	ksmbd_fsctl_exit();
	/*
	 * ksmbd_server_shutdown closes all connections and file handles.
	 * ksmbd_notify_exit must come AFTER so that file-handle close
	 * paths can still call ksmbd_notify_cleanup_file() to detach
	 * fsnotify marks properly before the group is destroyed.
	 */
	ksmbd_server_shutdown();
	ksmbd_notify_exit();
	rcu_barrier();
	ksmbd_release_inode_hash();

	/* Cleanup Fruit SMB extensions */
	fruit_cleanup_module();
	ksmbd_md4_unregister();
}

MODULE_AUTHOR("Namjae Jeon <linkinjeon@kernel.org>");
MODULE_VERSION(KSMBD_VERSION);
MODULE_DESCRIPTION("Linux kernel CIFS/SMB SERVER");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: ecb");
MODULE_SOFTDEP("pre: hmac");
MODULE_SOFTDEP("pre: md4");
MODULE_SOFTDEP("pre: md5");
MODULE_SOFTDEP("pre: nls");
MODULE_SOFTDEP("pre: aes");
MODULE_SOFTDEP("pre: cmac");
MODULE_SOFTDEP("pre: sha256");
MODULE_SOFTDEP("pre: sha512");
MODULE_SOFTDEP("pre: aead2");
MODULE_SOFTDEP("pre: ccm");
MODULE_SOFTDEP("pre: gcm");
MODULE_SOFTDEP("pre: crc32");
module_init(ksmbd_server_init)
module_exit(ksmbd_server_exit)
