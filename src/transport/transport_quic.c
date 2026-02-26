// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2024 Samsung Electronics Co., Ltd.
 *
 *   QUIC transport for ksmbd — kernel-side unix socket bridge.
 *
 *   This module implements the kernel half of an SMB-over-QUIC transport.
 *   A userspace QUIC proxy (e.g. built on msquic, quiche, or ngtcp2)
 *   terminates the QUIC/TLS 1.3 connection from the SMB client on port 443,
 *   and forwards decrypted SMB2 PDU streams to this module over a unix
 *   domain socket.  From the kernel's perspective each accepted unix socket
 *   is treated like a regular byte-stream transport, reusing the standard
 *   ksmbd connection handler loop and transport ops interface.
 *
 *   Architecture:
 *
 *     SMB Client --(QUIC/TLS 1.3)--> [Userspace Proxy] --(Unix Socket)--> [Kernel ksmbd]
 *
 *   The userspace proxy is responsible for:
 *     - QUIC connection handling and TLS 1.3 termination
 *     - Client certificate authentication (mTLS)
 *     - Sending a ksmbd_quic_conn_info header on each new connection
 *     - Forwarding raw SMB2 PDU bytes bidirectionally
 *
 *   The kernel module is responsible for:
 *     - Listening on a unix domain socket for proxy connections
 *     - Reading the connection info header
 *     - Plugging into the ksmbd transport ops for read/write/disconnect
 */

#define SUBMOD_NAME	"smb_quic"

#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/stddef.h>
#include <linux/un.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <net/sock.h>

#include "glob.h"
#include "connection.h"
#include "smb_common.h"
#include "server.h"
#include "transport_quic.h"

static struct task_struct *quic_listener_kthread;
static struct socket *quic_listener_sock;
static atomic_t quic_active_conns;

/**
 * struct quic_transport - per-connection QUIC transport state
 * @transport:	Embedded ksmbd_transport, must be first for container_of
 * @sock:	Unix domain socket for this connection
 * @iov:	Reusable iovec buffer for reads
 * @nr_iov:	Number of segments allocated in @iov
 * @conn_info:	Connection metadata received from userspace proxy
 * @counted:	Whether this connection was counted in quic_active_conns
 */
struct quic_transport {
	struct ksmbd_transport		transport;
	struct socket			*sock;
	struct kvec			*iov;
	unsigned int			nr_iov;
	struct ksmbd_quic_conn_info	conn_info;
	bool				counted;
};

static const struct ksmbd_transport_ops ksmbd_quic_transport_ops;

#define KSMBD_TRANS(t)	(&(t)->transport)
#define QUIC_TRANS(t)	((struct quic_transport *)container_of(t, \
				struct quic_transport, transport))

/**
 * get_conn_iovec() - get/grow connection iovec for socket reads
 * @t:		QUIC transport instance
 * @nr_segs:	Required number of iovec segments
 *
 * Return:	Pointer to iovec array, or NULL on allocation failure
 */
static struct kvec *get_conn_iovec(struct quic_transport *t,
				   unsigned int nr_segs)
{
	struct kvec *new_iov;

	if (t->iov && nr_segs <= t->nr_iov)
		return t->iov;

	new_iov = kmalloc_array(nr_segs, sizeof(*new_iov), KSMBD_DEFAULT_GFP);
	if (new_iov) {
		kfree(t->iov);
		t->iov = new_iov;
		t->nr_iov = nr_segs;
	}
	return new_iov;
}

/**
 * kvec_array_init() - initialise an IO vector segment after partial read
 * @new:	Destination IO vector
 * @iov:	Source IO vector
 * @nr_segs:	Number of segments in source
 * @bytes:	Bytes already consumed
 *
 * Return:	Remaining number of segments
 */
static unsigned int kvec_array_init(struct kvec *new, struct kvec *iov,
				    unsigned int nr_segs, size_t bytes)
{
	size_t base = 0;

	while (bytes || !iov->iov_len) {
		int copy = min(bytes, iov->iov_len);

		bytes -= copy;
		base += copy;
		if (iov->iov_len == base) {
			iov++;
			nr_segs--;
			base = 0;
		}
	}

	memcpy(new, iov, sizeof(*iov) * nr_segs);
	new->iov_base += base;
	new->iov_len -= base;
	return nr_segs;
}

/**
 * ksmbd_quic_readv() - read data from the unix socket bridge
 * @t:		QUIC transport instance
 * @iov_orig:	IO vector describing the read buffer
 * @nr_segs:	Number of segments in iov_orig
 * @to_read:	Total bytes to read
 * @max_retries: Maximum number of retries (negative = unlimited)
 *
 * Return:	Number of bytes read, or negative error code
 */
static int ksmbd_quic_readv(struct quic_transport *t, struct kvec *iov_orig,
			    unsigned int nr_segs, unsigned int to_read,
			    int max_retries)
{
	int length = 0;
	int total_read;
	unsigned int segs;
	struct msghdr msg;
	struct kvec *iov;
	struct ksmbd_conn *conn = KSMBD_TRANS(t)->conn;

	iov = get_conn_iovec(t, nr_segs);
	if (!iov)
		return -ENOMEM;

	memset(&msg, 0, sizeof(msg));

	for (total_read = 0; to_read; total_read += length, to_read -= length) {
		try_to_freeze();

		if (!ksmbd_conn_alive(conn)) {
			total_read = -ESHUTDOWN;
			break;
		}

		segs = kvec_array_init(iov, iov_orig, nr_segs, total_read);

		length = kernel_recvmsg(t->sock, &msg, iov, segs, to_read, 0);

		if (length == -EINTR) {
			total_read = -ESHUTDOWN;
			break;
		} else if (ksmbd_conn_need_reconnect(conn)) {
			total_read = -EAGAIN;
			break;
		} else if (length == -ERESTARTSYS || length == -EAGAIN) {
			if (max_retries == 0) {
				total_read = length;
				break;
			} else if (max_retries > 0) {
				max_retries--;
			}

			usleep_range(1000, 2000);
			length = 0;
			continue;
		} else if (length <= 0) {
			total_read = length;
			break;
		}
	}
	return total_read;
}

/**
 * ksmbd_quic_read() - transport ops read callback
 * @t:		ksmbd transport instance
 * @buf:	Destination buffer
 * @to_read:	Number of bytes to read
 * @max_retries: Maximum retry count
 *
 * Return:	Number of bytes read, or negative error code
 */
static int ksmbd_quic_read(struct ksmbd_transport *t, char *buf,
			   unsigned int to_read, int max_retries)
{
	struct kvec iov;

	iov.iov_base = buf;
	iov.iov_len = to_read;

	return ksmbd_quic_readv(QUIC_TRANS(t), &iov, 1, to_read, max_retries);
}

/**
 * ksmbd_quic_writev() - transport ops write callback
 * @t:			ksmbd transport instance
 * @iov:		IO vector with data to send
 * @nvecs:		Number of iovec segments
 * @size:		Total bytes to send
 * @need_invalidate:	Unused (RDMA-specific)
 * @remote_key:		Unused (RDMA-specific)
 *
 * Return:	Number of bytes sent, or negative error code
 */
static int ksmbd_quic_writev(struct ksmbd_transport *t, struct kvec *iov,
			     int nvecs, int size, bool need_invalidate,
			     unsigned int remote_key)
{
	struct msghdr msg = {.msg_flags = MSG_NOSIGNAL};

	return kernel_sendmsg(QUIC_TRANS(t)->sock, &msg, iov, nvecs, size);
}

/**
 * ksmbd_quic_free_transport() - free QUIC transport resources
 * @kt:		ksmbd transport instance to free
 *
 * Called from ksmbd_conn_cleanup() to release transport-specific memory.
 */
static void ksmbd_quic_free_transport(struct ksmbd_transport *kt)
{
	struct quic_transport *t = QUIC_TRANS(kt);

	sock_release(t->sock);
	kfree(t->iov);
	kfree(t);
}

/**
 * free_transport() - shut down and free a QUIC connection
 * @t:		QUIC transport instance
 *
 * Shuts down the socket and releases the ksmbd_conn.
 */
static void free_transport(struct quic_transport *t)
{
	kernel_sock_shutdown(t->sock, SHUT_RDWR);
	ksmbd_conn_free(KSMBD_TRANS(t)->conn);
}

/**
 * ksmbd_quic_disconnect() - transport ops disconnect callback
 * @t:		ksmbd transport instance
 *
 * Called when the connection handler loop exits.
 */
static void ksmbd_quic_disconnect(struct ksmbd_transport *t)
{
	struct quic_transport *qt = QUIC_TRANS(t);

	free_transport(qt);
	if (qt->counted) {
		atomic_dec(&quic_active_conns);
		qt->counted = false;
	}
}

/**
 * read_conn_info() - read connection metadata from userspace proxy
 * @t:		QUIC transport with a freshly accepted unix socket
 *
 * The userspace QUIC proxy sends a fixed-size ksmbd_quic_conn_info
 * struct as the very first message on each new connection.  This
 * contains the original client IP/port and TLS verification status.
 *
 * Return:	0 on success, negative error code on failure
 */
static int read_conn_info(struct quic_transport *t)
{
	struct kvec iov;
	struct msghdr msg;
	int ret;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &t->conn_info;
	iov.iov_len = sizeof(t->conn_info);

	ret = kernel_recvmsg(t->sock, &msg, &iov, 1, sizeof(t->conn_info),
			     MSG_WAITALL);
	if (ret != sizeof(t->conn_info)) {
		pr_err("Failed to read QUIC connection info: %d\n", ret);
		return ret < 0 ? ret : -EIO;
	}

	if (t->conn_info.addr_family != AF_INET &&
	    t->conn_info.addr_family != AF_INET6) {
		pr_err("Invalid QUIC client address family: %u\n",
		       t->conn_info.addr_family);
		return -EINVAL;
	}

	if (t->conn_info.addr_family == AF_INET6)
		ksmbd_debug(CONN,
			    "QUIC proxy connection: client %pI6:%u flags=0x%x\n",
			    t->conn_info.client_addr.v6,
			    t->conn_info.client_port,
			    t->conn_info.flags);
	else
		ksmbd_debug(CONN,
			    "QUIC proxy connection: client %pI4:%u flags=0x%x\n",
			    &t->conn_info.client_addr.v4,
			    t->conn_info.client_port,
			    t->conn_info.flags);

	return 0;
}

/**
 * alloc_transport() - allocate and initialise a QUIC transport
 * @client_sk:	Accepted unix domain socket from the proxy
 *
 * Allocates the quic_transport struct, reads connection metadata from
 * the proxy, allocates a ksmbd_conn, and wires everything together.
 *
 * Return:	quic_transport pointer on success, NULL on failure
 */
static struct quic_transport *alloc_transport(struct socket *client_sk)
{
	struct quic_transport *t;
	struct ksmbd_conn *conn;

	t = kzalloc(sizeof(*t), KSMBD_DEFAULT_GFP);
	if (!t)
		return NULL;

	t->sock = client_sk;

	/* Read connection metadata from the userspace QUIC proxy */
	if (read_conn_info(t)) {
		kfree(t);
		return NULL;
	}

	conn = ksmbd_conn_alloc();
	if (!conn) {
		kfree(t);
		return NULL;
	}

	/*
	 * Store the real client address from the proxy info so that
	 * per-IP connection limiting works correctly.
	 * For IPv6, use the lower 32 bits of the address for hashing.
	 */
	if (t->conn_info.addr_family == AF_INET6) {
		memcpy(&conn->inet_addr,
		       &t->conn_info.client_addr.v6[12], 4);
	} else {
		conn->inet_addr = t->conn_info.client_addr.v4;
	}
	conn->inet_hash = ipv4_addr_hash(conn->inet_addr);

	ksmbd_conn_hash_add(conn, conn->inet_hash);

	conn->transport = KSMBD_TRANS(t);
	KSMBD_TRANS(t)->conn = conn;
	KSMBD_TRANS(t)->ops = &ksmbd_quic_transport_ops;
	return t;
}

/**
 * ksmbd_quic_new_connection() - accept a new connection from the proxy
 * @client_sk:	Accepted unix domain socket
 *
 * Allocates transport state and starts a ksmbd connection handler thread.
 *
 * Return:	0 on success, negative error code on failure
 */
static int ksmbd_quic_new_connection(struct socket *client_sk,
				     bool counted)
{
	struct quic_transport *t;
	struct task_struct *handler;

	t = alloc_transport(client_sk);
	if (!t) {
		sock_release(client_sk);
		return -ENOMEM;
	}

	t->counted = counted;

	handler = kthread_run(ksmbd_conn_handler_loop,
			      KSMBD_TRANS(t)->conn,
			      "ksmbd-quic:%pI4",
			      &KSMBD_TRANS(t)->conn->inet_addr);
	if (IS_ERR(handler)) {
		pr_err("Cannot start QUIC connection handler: %ld\n",
		       PTR_ERR(handler));
		free_transport(t);
		return PTR_ERR(handler);
	}
	return 0;
}

/**
 * ksmbd_quic_listener_fn() - listener thread for unix socket connections
 * @p:		Unused
 *
 * Waits for connections from the userspace QUIC proxy on the unix
 * domain socket, applies connection limits, and spawns per-connection
 * handler threads.
 *
 * Return:	0 (thread function)
 */
static int ksmbd_quic_listener_fn(void *p)
{
	struct socket *client_sk;
	bool counted;
	int ret;

	set_freezable();
	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		if (!quic_listener_sock)
			break;

		ret = kernel_accept(quic_listener_sock, &client_sk, 0);
		if (ret == -EINVAL)
			break;
		if (ret)
			continue;

		counted = false;
		if (server_conf.max_connections) {
			if (atomic_inc_return(&quic_active_conns) >=
			    server_conf.max_connections) {
				pr_info_ratelimited("QUIC: max connections reached (%u)\n",
						    atomic_read(&quic_active_conns));
				atomic_dec(&quic_active_conns);
				sock_release(client_sk);
				continue;
			}
			counted = true;
		}

		ksmbd_debug(CONN, "QUIC: accepted new proxy connection\n");
		client_sk->sk->sk_rcvtimeo = KSMBD_QUIC_RECV_TIMEOUT;
		client_sk->sk->sk_sndtimeo = KSMBD_QUIC_SEND_TIMEOUT;

		if (ksmbd_quic_new_connection(client_sk, counted)) {
			if (counted)
				atomic_dec(&quic_active_conns);
		}
	}

	ksmbd_debug(CONN, "QUIC: listener thread exiting\n");
	return 0;
}

/**
 * create_unix_listener() - create and bind the unix domain socket listener
 *
 * Creates a SOCK_STREAM unix domain socket bound to an abstract address
 * (KSMBD_QUIC_SOCK_NAME).  Abstract sockets live in the network namespace
 * rather than on the filesystem, so there is no socket file that could
 * become stale after an unclean shutdown -- eliminating the EADDRINUSE
 * failure that a filesystem-based path would cause on server restart.
 *
 * Return:	0 on success, negative error code on failure
 */
static int create_unix_listener(void)
{
	struct socket *sock;
	struct sockaddr_un addr;
	int addrlen;
	int ret;

	ret = sock_create_kern(current->nsproxy->net_ns, AF_UNIX,
			       SOCK_STREAM, 0, &sock);
	if (ret) {
		pr_err("QUIC: cannot create unix socket: %d\n", ret);
		return ret;
	}

	/*
	 * Use an abstract unix socket: sun_path[0] = '\0' followed by
	 * the name.  The address length includes the family plus the
	 * '\0' byte plus the name (without a trailing NUL).
	 */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = '\0';
	memcpy(addr.sun_path + 1, KSMBD_QUIC_SOCK_NAME,
	       strlen(KSMBD_QUIC_SOCK_NAME));
	addrlen = offsetof(struct sockaddr_un, sun_path) + 1 +
		  strlen(KSMBD_QUIC_SOCK_NAME);

	ret = kernel_bind(sock,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
			  (struct sockaddr_unsized *)&addr,
#else
			  (struct sockaddr *)&addr,
#endif
			  addrlen);
	if (ret) {
		pr_err("QUIC: cannot bind abstract unix socket @%s: %d\n",
		       KSMBD_QUIC_SOCK_NAME, ret);
		sock_release(sock);
		return ret;
	}

	ret = kernel_listen(sock, KSMBD_QUIC_BACKLOG);
	if (ret) {
		pr_err("QUIC: listen() failed: %d\n", ret);
		sock_release(sock);
		return ret;
	}

	quic_listener_sock = sock;
	return 0;
}

/**
 * ksmbd_quic_init() - initialise the QUIC transport subsystem
 *
 * Creates the unix domain socket listener and starts the listener thread
 * that accepts connections from the userspace QUIC proxy.
 *
 * Return:	0 on success, negative error code on failure
 */
int ksmbd_quic_init(void)
{
	int ret;

	ret = create_unix_listener();
	if (ret)
		return ret;

	quic_listener_kthread = kthread_run(ksmbd_quic_listener_fn, NULL,
					    "ksmbd-quic");
	if (IS_ERR(quic_listener_kthread)) {
		ret = PTR_ERR(quic_listener_kthread);
		quic_listener_kthread = NULL;
		pr_err("QUIC: cannot start listener thread: %d\n", ret);
		sock_release(quic_listener_sock);
		quic_listener_sock = NULL;
		return ret;
	}

	pr_info("ksmbd: QUIC transport initialized (abstract socket: @%s)\n",
		KSMBD_QUIC_SOCK_NAME);
	return 0;
}

/**
 * ksmbd_quic_destroy() - tear down the QUIC transport subsystem
 *
 * Stops the listener thread and releases the unix domain socket.
 */
void ksmbd_quic_destroy(void)
{
	if (quic_listener_kthread) {
		kthread_stop(quic_listener_kthread);
		quic_listener_kthread = NULL;
	}

	if (quic_listener_sock) {
		kernel_sock_shutdown(quic_listener_sock, SHUT_RDWR);
		sock_release(quic_listener_sock);
		quic_listener_sock = NULL;
	}

	ksmbd_debug(CONN, "QUIC transport destroyed\n");
}

static const struct ksmbd_transport_ops ksmbd_quic_transport_ops = {
	.read		= ksmbd_quic_read,
	.writev		= ksmbd_quic_writev,
	.disconnect	= ksmbd_quic_disconnect,
	.free_transport	= ksmbd_quic_free_transport,
};
