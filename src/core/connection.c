// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <namjae.jeon@protocolfreedom.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mutex.h>
#include <linux/freezer.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>

#include "server.h"
#include "smb_common.h"
#ifdef CONFIG_SMB_INSECURE_SERVER
#include "smb1pdu.h"
#endif
#include "smb2pdu.h"
#include "mgmt/ksmbd_ida.h"
#include "connection.h"
#include "ksmbd_work.h"
#include "transport_tcp.h"
#include "transport_rdma.h"
#include "transport_quic.h"
#include "smb2fruit.h"
#include "mgmt/user_session.h"

#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/visibility.h>
#else
#define EXPORT_SYMBOL_IF_KUNIT(sym)
#endif

static DEFINE_MUTEX(init_lock);

static struct ksmbd_conn_ops default_conn_ops;

struct ksmbd_conn_hash_bucket conn_hash[CONN_HASH_SIZE];
atomic_t conn_hash_count = ATOMIC_INIT(0);

/**
 * ksmbd_conn_hash_init() - initialize per-bucket locks for conn hash
 */
void ksmbd_conn_hash_init(void)
{
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&conn_hash[i].head);
		spin_lock_init(&conn_hash[i].lock);
	}
	atomic_set(&conn_hash_count, 0);
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_hash_init);

/**
 * ksmbd_conn_hash_add() - add connection to the hash table
 * @conn:	connection to add
 * @key:	hash key (typically conn->inet_hash)
 */
void ksmbd_conn_hash_add(struct ksmbd_conn *conn, unsigned int key)
{
	unsigned int bkt = hash_min(key, CONN_HASH_BITS);

	spin_lock(&conn_hash[bkt].lock);
	hlist_add_head(&conn->hlist, &conn_hash[bkt].head);
	atomic_inc(&conn_hash_count);
	spin_unlock(&conn_hash[bkt].lock);
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_hash_add);

/**
 * ksmbd_conn_hash_del() - remove connection from the hash table
 * @conn:	connection to remove
 */
void ksmbd_conn_hash_del(struct ksmbd_conn *conn)
{
	unsigned int bkt = hash_min(conn->inet_hash, CONN_HASH_BITS);

	spin_lock(&conn_hash[bkt].lock);
	if (!hlist_unhashed(&conn->hlist)) {
		hlist_del_init(&conn->hlist);
		atomic_dec(&conn_hash_count);
	}
	spin_unlock(&conn_hash[bkt].lock);
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_hash_del);

/**
 * ksmbd_conn_hash_empty() - atomically check if the connection hash is empty
 *
 * Uses a global atomic counter to avoid TOCTOU races that could occur
 * when checking individual buckets non-atomically.
 *
 * Return:	true if no connections remain
 */
bool ksmbd_conn_hash_empty(void)
{
	return atomic_read(&conn_hash_count) == 0;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_hash_empty);

/**
 * ksmbd_conn_free() - free resources of the connection instance
 *
 * @conn:	connection instance to be cleaned up
 *
 * During the thread termination, the corresponding conn instance
 * resources(sock/memory) are released and finally the conn object is freed.
 */
static void ksmbd_conn_cleanup(struct ksmbd_conn *conn)
{
	struct preauth_session *p, *tmp;

	ksmbd_conn_hash_del(conn);

	xa_destroy(&conn->sessions);

	list_for_each_entry_safe(p, tmp, &conn->preauth_sess_table,
				 preauth_entry) {
		list_del(&p->preauth_entry);
		kfree(p);
	}

	kvfree(conn->request_buf);
	kfree(conn->preauth_info);
	kfree(conn->vals);

#ifdef CONFIG_KSMBD_FRUIT
	/* Clean up Fruit SMB extension resources */
	if (conn->fruit_state) {
		fruit_cleanup_connection_state(conn->fruit_state);
		kfree(conn->fruit_state);
		conn->fruit_state = NULL;
	}
#endif

	conn->transport->ops->free_transport(conn->transport);
	kfree(conn);
}

void ksmbd_conn_free(struct ksmbd_conn *conn)
{
	if (!refcount_dec_and_test(&conn->refcnt))
		return;

	ksmbd_conn_cleanup(conn);
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_free);

/**
 * ksmbd_conn_alloc() - initialize a new connection instance
 *
 * Return:	ksmbd_conn struct on success, otherwise NULL
 */
struct ksmbd_conn *ksmbd_conn_alloc(void)
{
	struct ksmbd_conn *conn;

	conn = kzalloc(sizeof(struct ksmbd_conn), KSMBD_DEFAULT_GFP);
	if (!conn)
		return NULL;

	conn->need_neg = true;
	ksmbd_conn_set_new(conn);
	conn->local_nls = load_nls("utf8");
	if (!conn->local_nls)
		conn->local_nls = load_nls_default();
	if (IS_ENABLED(CONFIG_UNICODE))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
		conn->um = utf8_load(UNICODE_AGE(12, 1, 0));
#else
		conn->um = utf8_load("12.1.0");
#endif
	else
		conn->um = ERR_PTR(-EOPNOTSUPP);
	if (IS_ERR(conn->um))
		conn->um = NULL;
	atomic_set(&conn->req_running, 0);
	atomic_set(&conn->r_count, 0);
	atomic_set(&conn->outstanding_async, 0);
	atomic_set(&conn->in_progress_sessions, 0);
	refcount_set(&conn->refcnt, 1);
	conn->total_credits = 1;
	conn->outstanding_credits = 0;

	init_waitqueue_head(&conn->req_running_q);
	init_waitqueue_head(&conn->r_count_q);
	INIT_LIST_HEAD(&conn->requests);
	INIT_LIST_HEAD(&conn->async_requests);
	spin_lock_init(&conn->request_lock);
	spin_lock_init(&conn->credits_lock);
	ida_init(&conn->async_ida);
	xa_init(&conn->sessions);

	spin_lock_init(&conn->llist_lock);
	INIT_LIST_HEAD(&conn->lock_list);

	init_rwsem(&conn->session_lock);
	INIT_LIST_HEAD(&conn->preauth_sess_table);

	return conn;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_conn_alloc);

bool ksmbd_conn_lookup_dialect(struct ksmbd_conn *c)
{
	struct ksmbd_conn *t;
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		spin_lock(&conn_hash[i].lock);
		hlist_for_each_entry(t, &conn_hash[i].head, hlist) {
			if (!memcmp(t->ClientGUID, c->ClientGUID,
				    SMB2_CLIENT_GUID_SIZE)) {
				spin_unlock(&conn_hash[i].lock);
				return true;
			}
		}
		spin_unlock(&conn_hash[i].lock);
	}
	return false;
}

void ksmbd_conn_enqueue_request(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct list_head *requests_queue = NULL;
#ifdef CONFIG_SMB_INSECURE_SERVER
	struct smb2_hdr *hdr = work->request_buf;

	if (hdr->ProtocolId == SMB2_PROTO_NUMBER) {
		if (conn->ops->get_cmd_val(work) != SMB2_CANCEL_HE)
			requests_queue = &conn->requests;
	} else {
		if (conn->ops->get_cmd_val(work) != SMB_COM_NT_CANCEL)
			requests_queue = &conn->requests;
	}
#else
	if (conn->ops->get_cmd_val(work) != SMB2_CANCEL_HE)
		requests_queue = &conn->requests;
#endif

	atomic_inc(&conn->req_running);
	if (requests_queue) {
		spin_lock(&conn->request_lock);
		list_add_tail(&work->request_entry, requests_queue);
		spin_unlock(&conn->request_lock);
	}
}

void ksmbd_conn_try_dequeue_request(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;

	atomic_dec(&conn->req_running);
	if (waitqueue_active(&conn->req_running_q))
		wake_up(&conn->req_running_q);

	spin_lock(&conn->request_lock);
	if (list_empty(&work->request_entry) &&
	    list_empty(&work->async_request_entry)) {
		spin_unlock(&conn->request_lock);
		return;
	}
	list_del_init(&work->request_entry);
	spin_unlock(&conn->request_lock);
	if (work->asynchronous)
		release_async_work(work);

	wake_up_all(&conn->req_running_q);
}

void ksmbd_conn_lock(struct ksmbd_conn *conn)
{
	mutex_lock(&conn->srv_mutex);
}

void ksmbd_conn_unlock(struct ksmbd_conn *conn)
{
	mutex_unlock(&conn->srv_mutex);
}

void ksmbd_all_conn_set_status(u64 sess_id, u32 status)
{
	struct ksmbd_conn *conn;
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		spin_lock(&conn_hash[i].lock);
		hlist_for_each_entry(conn, &conn_hash[i].head, hlist) {
			rcu_read_lock();
			if (conn->binding ||
			    xa_load(&conn->sessions, sess_id))
				WRITE_ONCE(conn->status, status);
			rcu_read_unlock();
		}
		spin_unlock(&conn_hash[i].lock);
	}
}

void ksmbd_conn_wait_idle(struct ksmbd_conn *conn)
{
	if (!wait_event_timeout(conn->req_running_q,
				atomic_read(&conn->req_running) < 2,
				120 * HZ))
		pr_err_ratelimited("Timeout waiting for idle conn (req_running=%d, status=%d)\n",
				   atomic_read(&conn->req_running),
				   READ_ONCE(conn->status));
}

int ksmbd_conn_wait_idle_sess_id(struct ksmbd_conn *curr_conn,
				 u64 sess_id)
{
	struct ksmbd_conn *conn;
	int rc, retry_count = 0;
	int rcount, i;

	/*
	 * Maximum total retries to prevent infinite loops.  Each retry
	 * waits up to 1 second (HZ), so 120 retries = 120 seconds max.
	 */
#define WAIT_IDLE_MAX_RETRIES	120

retry_idle:
	if (retry_count >= WAIT_IDLE_MAX_RETRIES) {
		pr_err_ratelimited("wait_idle_sess_id: timed out after %d retries for session %llu\n",
				   retry_count, sess_id);
		return -EIO;
	}

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		spin_lock(&conn_hash[i].lock);
		hlist_for_each_entry(conn, &conn_hash[i].head,
				     hlist) {
			bool has_sess;

			rcu_read_lock();
			has_sess = conn->binding ||
				   xa_load(&conn->sessions, sess_id);
			rcu_read_unlock();
			if (!has_sess)
				continue;

			rcount = (conn == curr_conn) ? 2 : 1;
			if (atomic_read(&conn->req_running) >=
			    rcount) {
				spin_unlock(&conn_hash[i].lock);
				rc = wait_event_timeout(
					conn->req_running_q,
					atomic_read(
					    &conn->req_running)
					    < rcount,
					HZ);
				/*
				 * Count every restart toward the limit,
				 * whether the wait timed out or succeeded,
				 * to prevent infinite loops when requests
				 * keep arriving between checks.
				 */
				retry_count++;
				goto retry_idle;
			}
		}
		spin_unlock(&conn_hash[i].lock);
	}

	return 0;
}

static int __ksmbd_conn_writev(struct ksmbd_work *work, bool try_lock,
			       size_t *expected_len)
{
	struct ksmbd_conn *conn = work->conn;
	int sent;

	if (!work->response_buf) {
		pr_err("NULL response header\n");
		return -EINVAL;
	}

	if (work->send_no_response)
		return 0;

#ifdef CONFIG_SMB_INSECURE_SERVER
	if (!work->iov_idx) {
		struct kvec iov[2];
		int iov_idx = 0;
		size_t len = 0;

		if (work->aux_payload_sz) {
			iov[iov_idx] = (struct kvec) { work->response_buf, work->resp_hdr_sz };
			len += iov[iov_idx++].iov_len;
			iov[iov_idx] = (struct kvec) { work->aux_payload_buf, work->aux_payload_sz };
			len += iov[iov_idx++].iov_len;
		} else {
			iov[iov_idx].iov_len = get_rfc1002_len(work->response_buf) + 4;
			iov[iov_idx].iov_base = work->response_buf;
			len += iov[iov_idx++].iov_len;
		}

		*expected_len = len;
		if (try_lock) {
			if (!mutex_trylock(&conn->srv_mutex))
				return -EAGAIN;
		} else {
			ksmbd_conn_lock(conn);
		}
		sent = conn->transport->ops->writev(conn->transport, &iov[0],
				iov_idx, len, work->need_invalidate_rkey,
				work->remote_key);
		ksmbd_conn_unlock(conn);

	} else {
		size_t len = get_rfc1002_len(work->iov[0].iov_base) + 4;

		if (work->sendfile)
			len -= work->sendfile_count;

		*expected_len = len;
		if (try_lock) {
			if (!mutex_trylock(&conn->srv_mutex))
				return -EAGAIN;
		} else {
			ksmbd_conn_lock(conn);
		}
		sent = conn->transport->ops->writev(conn->transport,
						    work->iov,
						    work->iov_cnt, len,
						    work->need_invalidate_rkey,
						    work->remote_key);
		ksmbd_conn_unlock(conn);
	}
#else
	if (!work->iov_idx)
		return -EINVAL;

	{
		size_t len = get_rfc1002_len(work->iov[0].iov_base) + 4;

		/*
		 * For zero-copy sendfile, the rfc1002 length includes the
		 * file data size, but the iov only contains the header.
		 * Subtract the sendfile count so writev sends only the
		 * header bytes. The file data is sent separately below.
		 */
		if (work->sendfile)
			len -= work->sendfile_count;

		*expected_len = len;
		if (try_lock) {
			if (!mutex_trylock(&conn->srv_mutex))
				return -EAGAIN;
		} else {
			ksmbd_conn_lock(conn);
		}
		sent = conn->transport->ops->writev(conn->transport,
						    work->iov,
						    work->iov_cnt, len,
						    work->need_invalidate_rkey,
						    work->remote_key);
		ksmbd_conn_unlock(conn);
	}
#endif

	return sent;
}

static int __ksmbd_conn_write(struct ksmbd_work *work, bool try_lock)
{
	struct ksmbd_conn *conn = work->conn;
	size_t expected_len = 0;
	int sent;

	/*
	 * Opportunistic writes are used only for teardown-only notify
	 * completions.  Those responses never use sendfile, and allowing
	 * a busy srv_mutex to skip the write is preferable to deadlocking
	 * inside session/reset teardown.
	 */
	if (try_lock && work->sendfile)
		return -EAGAIN;

	sent = __ksmbd_conn_writev(work, try_lock, &expected_len);
	if (sent < 0) {
		if (sent != -EAGAIN)
			pr_err("Failed to send message: %d\n", sent);
		return sent;
	}

	/* H-06: a short write leaves the client with a truncated PDU; treat as fatal */
	if (sent != expected_len) {
		pr_err_ratelimited("Short write: sent %d of %zu bytes, closing connection\n",
				   sent, expected_len);
		return -EPIPE;
	}

	/* Send file data via zero-copy after the header */
	if (work->sendfile && conn->transport->ops->sendfile) {
		loff_t offset = work->sendfile_offset;

		ksmbd_conn_lock(conn);
		sent = conn->transport->ops->sendfile(conn->transport,
						      work->sendfile_filp,
						      &offset,
						      work->sendfile_count);
		ksmbd_conn_unlock(conn);
		if (sent < 0) {
			pr_err("Failed to sendfile: %d\n", sent);
			return sent;
		}
	}

	return 0;
}

int ksmbd_conn_write(struct ksmbd_work *work)
{
	return __ksmbd_conn_write(work, false);
}

int ksmbd_conn_try_write(struct ksmbd_work *work)
{
	return __ksmbd_conn_write(work, true);
}

int ksmbd_conn_rdma_read(struct ksmbd_conn *conn,
			 void *buf, unsigned int buflen,
			 struct smb2_buffer_desc_v1 *desc,
			 unsigned int desc_len)
{
	int ret = -EINVAL;

	if (conn->transport->ops->rdma_read)
		ret = conn->transport->ops->rdma_read(conn->transport,
						      buf, buflen,
						      desc, desc_len);
	return ret;
}

int ksmbd_conn_rdma_write(struct ksmbd_conn *conn,
			  void *buf, unsigned int buflen,
			  struct smb2_buffer_desc_v1 *desc,
			  unsigned int desc_len)
{
	int ret = -EINVAL;

	if (conn->transport->ops->rdma_write)
		ret = conn->transport->ops->rdma_write(conn->transport,
						       buf, buflen,
						       desc, desc_len);
	return ret;
}

bool ksmbd_conn_alive(struct ksmbd_conn *conn)
{
	if (!ksmbd_server_running())
		return false;

	if (ksmbd_conn_exiting(conn))
		return false;

	if ((current->flags & PF_KTHREAD) && kthread_should_stop())
		return false;

	if (atomic_read(&conn->stats.open_files_count) > 0)
		return true;

	/*
	 * Stop current session if the time that get last request from client
	 * is bigger than deadtime user configured and opening file count is
	 * zero.
	 */
	if (READ_ONCE(server_conf.deadtime) > 0 &&
	    time_after(jiffies, READ_ONCE(conn->last_active) +
		       READ_ONCE(server_conf.deadtime))) {
		ksmbd_debug(CONN, "No response from client in %lu minutes\n",
			    READ_ONCE(server_conf.deadtime) / SMB_ECHO_INTERVAL);
		return false;
	}
	return true;
}

#define SMB1_MIN_SUPPORTED_HEADER_SIZE (sizeof(struct smb_hdr))
#define SMB2_MIN_SUPPORTED_HEADER_SIZE (sizeof(struct smb2_hdr) + 4)

/**
 * ksmbd_conn_handler_loop() - session thread to listen on new smb requests
 * @p:		connection instance
 *
 * One thread each per connection
 *
 * Return:	0 on success
 */
int ksmbd_conn_handler_loop(void *p)
{
	struct ksmbd_conn *conn = (struct ksmbd_conn *)p;
	struct ksmbd_transport *t = conn->transport;
	unsigned int pdu_size, max_allowed_pdu_size, max_req;
	char hdr_buf[4] = {0,};
	int size, rc;

	mutex_init(&conn->srv_mutex);
	__module_get(THIS_MODULE);

	if (t->ops->prepare && t->ops->prepare(t))
		goto out;

	max_req = READ_ONCE(server_conf.max_inflight_req);
	WRITE_ONCE(conn->last_active, jiffies);
	set_freezable();
	while (ksmbd_conn_alive(conn)) {
		if (try_to_freeze())
			continue;

		kvfree(conn->request_buf);
		conn->request_buf = NULL;

recheck:
		if (atomic_read(&conn->req_running) + 1 > max_req) {
			rc = wait_event_interruptible_timeout(conn->req_running_q,
							      atomic_read(&conn->req_running) < max_req ||
							      !ksmbd_conn_alive(conn),
							      HZ);
			if (rc < 0)
				break;
			if (!ksmbd_conn_alive(conn))
				break;
			goto recheck;
		}

			size = t->ops->read(t, hdr_buf, sizeof(hdr_buf), -1);
			if (size != sizeof(hdr_buf))
				break;

			pdu_size = get_rfc1002_len(hdr_buf);
			ksmbd_debug(CONN,
				    "RFC1002 hdr=%02x %02x %02x %02x len=%u status=%d\n",
				    (u8)hdr_buf[0], (u8)hdr_buf[1],
				    (u8)hdr_buf[2], (u8)hdr_buf[3], pdu_size,
				    READ_ONCE(conn->status));

		if (ksmbd_conn_good(conn) && conn->vals)
			max_allowed_pdu_size =
				SMB3_MAX_MSGSIZE + conn->vals->max_write_size;
		else
			max_allowed_pdu_size = SMB3_MAX_MSGSIZE;

		if (pdu_size > max_allowed_pdu_size) {
				pr_err_ratelimited("PDU length(%u) excceed maximum allowed pdu size(%u) on connection(%d)\n",
						pdu_size, max_allowed_pdu_size,
						READ_ONCE(conn->status));
				pr_err_ratelimited("Invalid RFC1002 hdr bytes: %02x %02x %02x %02x\n",
						   (u8)hdr_buf[0], (u8)hdr_buf[1],
						   (u8)hdr_buf[2], (u8)hdr_buf[3]);
				break;
			}

		/*
		 * Check maximum pdu size(0x00FFFFFF).
		 */
		if (pdu_size > MAX_STREAM_PROT_LEN)
			break;

		if (pdu_size < SMB1_MIN_SUPPORTED_HEADER_SIZE)
			break;

		/* 4 for rfc1002 length field */
		/* 1 for implied bcc[0] */
		if (check_add_overflow(pdu_size, 5u, (unsigned int *)&size))
			break;
		conn->request_buf = kvmalloc(size, KSMBD_DEFAULT_GFP);
		if (!conn->request_buf)
			break;

		memcpy(conn->request_buf, hdr_buf, sizeof(hdr_buf));

		/*
		 * We already read 4 bytes to find out PDU size, now
		 * read in PDU
		 */
		size = t->ops->read(t, conn->request_buf + 4, pdu_size, 2);
		if (size < 0) {
			pr_err("sock_read failed: %d\n", size);
			break;
		}

			if (size != pdu_size) {
				pr_err("PDU error. Read: %d, Expected: %d\n",
				       size, pdu_size);
				continue;
			}

			if (pdu_size >= sizeof(struct smb2_sess_setup_req)) {
				struct smb2_sess_setup_req *sess_req;
				unsigned int expected_pdu, extra;

				sess_req = smb2_get_msg(conn->request_buf);
				if (sess_req->hdr.ProtocolId == SMB2_PROTO_NUMBER &&
				    le16_to_cpu(sess_req->hdr.Command) ==
				    SMB2_SESSION_SETUP_HE &&
				    le16_to_cpu(sess_req->SecurityBufferOffset) >=
				    offsetof(struct smb2_sess_setup_req, Buffer)) {
					expected_pdu =
						le16_to_cpu(sess_req->SecurityBufferOffset) +
						le16_to_cpu(sess_req->SecurityBufferLength);

					if (expected_pdu > pdu_size &&
					    expected_pdu <= MAX_STREAM_PROT_LEN) {
						char *new_buf;

						extra = expected_pdu - pdu_size;
						if (check_add_overflow(expected_pdu, 5u,
								       (unsigned int *)&size))
							break;

						new_buf = kvmalloc(size, KSMBD_DEFAULT_GFP);
						if (!new_buf)
							break;

						memcpy(new_buf, conn->request_buf,
						       pdu_size + 4);
						kvfree(conn->request_buf);
						conn->request_buf = new_buf;

						size = t->ops->read(t,
								   conn->request_buf + 4 + pdu_size,
								   extra, 2);
						if (size != extra) {
							pr_err("SESSION_SETUP extension read failed: %d expected %u\n",
							       size, extra);
							break;
						}

						inc_rfc1001_len(conn->request_buf, extra);
						pr_warn_ratelimited(
							"SESSION_SETUP frame length corrected: rfc=%u expected=%u extra=%u\n",
							pdu_size, expected_pdu, extra);
						pdu_size = expected_pdu;
					}
				}
			}

			/*
			 * Trace parsed protocol signature after payload read to
			 * diagnose framing/stream-desync issues.
			 */
			if (pdu_size >= 4) {
				u8 *msg = conn->request_buf + 4;

				ksmbd_debug(CONN,
					    "PDU sig=%02x %02x %02x %02x pdu=%u req_running=%d\n",
					    msg[0], msg[1], msg[2], msg[3],
					    pdu_size, atomic_read(&conn->req_running));
			}

		if (!ksmbd_smb_request(conn))
			break;

		if (((struct smb2_hdr *)smb2_get_msg(conn->request_buf))->ProtocolId ==
		    SMB2_PROTO_NUMBER) {
			if (pdu_size < SMB2_MIN_SUPPORTED_HEADER_SIZE)
				break;
		}

		if (!default_conn_ops.process_fn) {
			pr_err("No connection request callback\n");
			break;
		}

		if (default_conn_ops.process_fn(conn)) {
			pr_err("Cannot handle request\n");
			break;
		}
	}

out:
	ksmbd_conn_set_releasing(conn);
	/* Wait till all reference dropped to the Server object*/
	ksmbd_debug(CONN, "Wait for all pending requests(%d)\n", atomic_read(&conn->r_count));
	wait_event(conn->r_count_q, atomic_read(&conn->r_count) == 0);

	if (IS_ENABLED(CONFIG_UNICODE))
		utf8_unload(conn->um);
	unload_nls(conn->local_nls);
	if (default_conn_ops.terminate_fn)
		default_conn_ops.terminate_fn(conn);
	/*
	 * Release the module reference BEFORE calling disconnect().
	 *
	 * disconnect() → free_transport() → ksmbd_conn_free() removes this
	 * connection from the conn hash table.  stop_sessions() in
	 * server_ctrl_handle_reset() uses ksmbd_conn_hash_empty() as its
	 * completion condition, so it returns as soon as disconnect() removes
	 * the last connection from the hash.
	 *
	 * If module_put() were called AFTER disconnect() (old order), there
	 * would be a window between the hash removal and the module_put where
	 * rmmod could fail with -EBUSY even though cleanup is nearly done.
	 * Calling module_put() first ensures the reference is released while
	 * the connection is still in the hash, so when stop_sessions() finally
	 * sees an empty hash it knows all module references from handler
	 * threads have already been dropped.
	 *
	 * Safety: at this point all pending work (r_count == 0) and sessions
	 * have been torn down, so no code paths that depend on the module
	 * staying loaded will execute after this point.
	 */
	module_put(THIS_MODULE);
	t->ops->disconnect(t);
	return 0;
}

void ksmbd_conn_init_server_callbacks(struct ksmbd_conn_ops *ops)
{
	default_conn_ops.process_fn = ops->process_fn;
	default_conn_ops.terminate_fn = ops->terminate_fn;
}

void ksmbd_conn_r_count_inc(struct ksmbd_conn *conn)
{
	atomic_inc(&conn->r_count);
}

void ksmbd_conn_r_count_dec(struct ksmbd_conn *conn)
{
	/*
	 * Decrement r_count and wake the connection handler thread if
	 * it has drained to zero.  The connection handler thread is the
	 * sole owner responsible for cleanup via ksmbd_conn_free() --
	 * workers must never call ksmbd_conn_cleanup() directly as that
	 * races with the handler's own exit path and causes double-free
	 * or use-after-free of the transport.
	 *
	 * waitqueue_active is safe because it uses atomic operation for
	 * condition.
	 */
	if (!atomic_dec_return(&conn->r_count) &&
	    waitqueue_active(&conn->r_count_q))
		wake_up(&conn->r_count_q);
}

int ksmbd_conn_transport_init(void)
{
	int ret;

	ksmbd_conn_hash_init();
	mutex_lock(&init_lock);
	ret = ksmbd_tcp_init();
	if (ret) {
		pr_err("Failed to init TCP subsystem: %d\n", ret);
		goto out;
	}

	ret = ksmbd_rdma_init();
	if (ret) {
		pr_warn("RDMA subsystem unavailable (%d), continuing without RDMA\n",
			ret);
		/* RDMA is optional; do not tear down TCP */
	}

	ret = ksmbd_quic_init();
	if (ret) {
		/* QUIC is optional: fall back to TCP+RDMA only */
		pr_warn("QUIC subsystem unavailable (%d), continuing without QUIC\n",
			ret);
		ret = 0;
	}

	mutex_unlock(&init_lock);
	return 0;

out:
	mutex_unlock(&init_lock);
	return ret;
}

/* Maximum retries for stop_sessions: 300 * 100ms = 30 seconds */
#define STOP_SESSIONS_MAX_RETRIES	300

static void stop_sessions(void)
{
	struct ksmbd_conn *conn;
	struct ksmbd_transport *t;
	int i;
	int retries = 0;
	bool need_retry;
	bool already_shutting_down;
	bool workqueue_flushed = false;

again:
	need_retry = false;
	for (i = 0; i < CONN_HASH_SIZE; i++) {
		spin_lock(&conn_hash[i].lock);
		hlist_for_each_entry(conn, &conn_hash[i].head,
				     hlist) {
			t = conn->transport;
			already_shutting_down = ksmbd_conn_exiting(conn) ||
						ksmbd_conn_releasing(conn);
			ksmbd_conn_set_exiting(conn);
			if (t->ops->shutdown) {
					/*
					 * Always try to grab a temporary reference,
					 * even for RELEASING connections.  Durable
					 * handle teardown can strand those conns in
					 * the hash with zero requests after the first
					 * shutdown pass.  A successful inc_not_zero()
					 * guarantees the object is still live, and
					 * repeated transport shutdown is idempotent.
					 */
					/*
					 * Take a temporary reference while dropping the
					 * hash lock to invoke transport shutdown.
					 * The connection can concurrently race to its
				 * final put, so only take the ref if still live
				 * and release it through ksmbd_conn_free().
				 */
				if (!refcount_inc_not_zero(&conn->refcnt))
					continue;
				spin_unlock(&conn_hash[i].lock);
				t->ops->shutdown(t);
				ksmbd_conn_free(conn);
				/*
				 * We dropped the spinlock, so restart the scan
				 * to catch any connections we may have skipped.
				 * Set need_retry so the outer check knows at
				 * least one non-releasing connection was found
				 * this pass; that guarantees we sleep (msleep)
				 * before the next scan rather than tight-looping
				 * when the handler thread is slow to react.
				 */
				need_retry = true;
				/*
				 * A conn that was already EXITING/RELEASING can
				 * stay in the hash while durable teardown drains
				 * its last refs.  Do not hot-loop on it: go
				 * through the bounded retry path so timeout-based
				 * forced orphaning still triggers.
				 */
				if (already_shutting_down)
					goto check_retry;
				goto again;
			}
		}
		spin_unlock(&conn_hash[i].lock);
	}

check_retry:
	if (!ksmbd_conn_hash_empty() || need_retry) {
		if (!workqueue_flushed) {
			/*
			 * Connection handler threads do not drop their final
			 * hash reference until all queued ksmbd-io work has
			 * drained (r_count == 0).  Flush that workqueue once
			 * after transport shutdown so stop_sessions() waits on
			 * real teardown progress instead of timing out on
			 * connection refs that are still owned by in-flight
			 * workers.
			 */
			ksmbd_workqueue_flush();
			workqueue_flushed = true;
			goto again;
		}
		if (++retries > STOP_SESSIONS_MAX_RETRIES) {
			int leaked = 0;

			/*
			 * Force-release remaining connections to avoid
			 * leaking resources on module unload.  At this
			 * point listeners are already torn down, so no
			 * new connections can arrive.
			 */
			for (i = 0; i < CONN_HASH_SIZE; i++) {
				spin_lock(&conn_hash[i].lock);
				hlist_for_each_entry(conn, &conn_hash[i].head,
						     hlist)
					leaked++;
				spin_unlock(&conn_hash[i].lock);
			}
			pr_crit("stop_sessions: giving up after %d retries - %d connections leaked, forcing cleanup\n",
				retries, leaked);

			for (i = 0; i < CONN_HASH_SIZE; i++) {
restart:
				spin_lock(&conn_hash[i].lock);
				hlist_for_each_entry(conn, &conn_hash[i].head,
						     hlist) {
					if (!refcount_inc_not_zero(&conn->refcnt))
						continue;
					/*
					 * A connection can sit in RELEASING or
					 * EXITING forever when durable-handle
					 * state keeps its final reference alive
					 * after transport shutdown.  At this
					 * point listeners are already gone and
					 * stop_sessions() has timed out, so the
					 * safest last resort is to orphan the
					 * conn from conn_hash to unblock reset.
					 *
					 * The temporary reference taken above
					 * keeps @conn stable after we drop the
					 * bucket lock.  We only drop that guard
					 * ref here; any lingering owner refs may
					 * still free the conn later.
					 */
					if (!hlist_unhashed(&conn->hlist)) {
						hlist_del_init(&conn->hlist);
						atomic_dec(&conn_hash_count);
					}
					spin_unlock(&conn_hash[i].lock);
					ksmbd_conn_free(conn);
					goto restart;
				}
				spin_unlock(&conn_hash[i].lock);
			}
			return;
		}
		msleep(100);
		goto again;
	}
}

void ksmbd_conn_transport_destroy(void)
{
	mutex_lock(&init_lock);
	ksmbd_tcp_destroy();
	ksmbd_rdma_stop_listening();
	ksmbd_quic_destroy();
	stop_sessions();
	ksmbd_rdma_destroy();
	mutex_unlock(&init_lock);
}
