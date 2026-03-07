# Line-by-line Review: src/transport/transport_tcp.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/freezer.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/uio.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/highmem.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/splice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * ITER_DEST/ITER_SOURCE were introduced in kernel 6.0 replacing`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` * READ/WRITE for iov_iter direction. Provide compat definitions.`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#ifndef ITER_DEST`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#define ITER_DEST	READ`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#ifndef ITER_SOURCE`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define ITER_SOURCE	WRITE`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "transport_tcp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define IFACE_STATE_DOWN		BIT(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define IFACE_STATE_CONFIGURED		BIT(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [LIFETIME|] `static atomic_t active_num_conn;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `struct interface {`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	struct task_struct	*ksmbd_kthread;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	struct socket		*ksmbd_socket;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	struct list_head	entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	char			*name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	int			state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `static LIST_HEAD(iface_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `static DEFINE_MUTEX(iface_list_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `static int bind_additional_ifaces;`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `struct tcp_transport {`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	struct ksmbd_transport		transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	struct socket			*sock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	struct kvec			*iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	unsigned int			nr_iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `static const struct ksmbd_transport_ops ksmbd_tcp_transport_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `static void tcp_stop_kthread(struct task_struct *kthread);`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `static struct interface *alloc_iface(char *ifname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#define KSMBD_TRANS(t)	(&(t)->transport)`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#define TCP_TRANS(t)	((struct tcp_transport *)container_of(t, \`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `				struct tcp_transport, transport))`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `static inline void ksmbd_tcp_nodelay(struct socket *sock)`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	int val = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `			  sizeof(val));`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	tcp_sock_set_nodelay(sock->sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `static inline void ksmbd_tcp_reuseaddr(struct socket *sock)`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	int val = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `			  sizeof(val));`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	sock_set_reuseaddr(sock->sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `static inline void ksmbd_tcp_keepalive(struct socket *sock)`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	int val = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	kernel_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `			  sizeof(val));`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	val = 120;`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	kernel_setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, (char *)&val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `			  sizeof(val));`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	val = 30;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	kernel_setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, (char *)&val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `			  sizeof(val));`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	val = 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	kernel_setsockopt(sock, SOL_TCP, TCP_KEEPCNT, (char *)&val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `			  sizeof(val));`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	tcp_sock_set_keepidle(sock->sk, 120);`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	tcp_sock_set_keepintvl(sock->sk, 30);`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	tcp_sock_set_keepcnt(sock->sk, 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	sock_set_keepalive(sock->sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `static struct tcp_transport *alloc_transport(struct socket *client_sk)`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	struct tcp_transport *t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [MEM_BOUNDS|] `	t = kzalloc(sizeof(*t), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00118 [NONE] `	if (!t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	t->sock = client_sk;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	conn = ksmbd_conn_alloc();`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	if (!conn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `		kfree(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `#if IS_ENABLED(CONFIG_IPV6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	if (client_sk->sk->sk_family == AF_INET6) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [MEM_BOUNDS|] `		memcpy(&conn->inet6_addr, &client_sk->sk->sk_v6_daddr, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00131 [NONE] `		conn->inet_hash = ipv6_addr_hash(&client_sk->sk->sk_v6_daddr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `		conn->inet_addr = inet_sk(client_sk->sk)->inet_daddr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `		conn->inet_hash = ipv4_addr_hash(inet_sk(client_sk->sk)->inet_daddr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	conn->inet_addr = inet_sk(client_sk->sk)->inet_daddr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	ksmbd_conn_hash_add(conn, conn->inet_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	conn->transport = KSMBD_TRANS(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	KSMBD_TRANS(t)->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	KSMBD_TRANS(t)->ops = &ksmbd_tcp_transport_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	return t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `static void ksmbd_tcp_free_transport(struct ksmbd_transport *kt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	struct tcp_transport *t = TCP_TRANS(kt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	sock_release(t->sock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	kfree(t->iov);`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	kfree(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `static void free_transport(struct tcp_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	kernel_sock_shutdown(t->sock, SHUT_RDWR);`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	ksmbd_conn_free(KSMBD_TRANS(t)->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ` * kvec_array_init() - initialize a IO vector segment`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ` * @new:	IO vector to be initialized`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` * @iov:	base IO vector`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ` * @nr_segs:	number of segments in base iov`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ` * @bytes:	total iovec length so far for read`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ` * Return:	Number of IO segments`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `static unsigned int kvec_array_init(struct kvec *new, struct kvec *iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `				    unsigned int nr_segs, size_t bytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	size_t base = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	while (nr_segs && (bytes || !iov->iov_len)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `		size_t copy = min(bytes, iov->iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `		bytes -= copy;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		base += copy;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		if (iov->iov_len == base) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `			iov++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `			nr_segs--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `			base = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	if (!nr_segs)`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [MEM_BOUNDS|] `	memcpy(new, iov, sizeof(*iov) * nr_segs);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00192 [NONE] `	new->iov_base += base;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	new->iov_len -= base;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	return nr_segs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` * ksmbd_tcp_new_connection() - create a new tcp session on mount`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ` * @client_sk:	socket associated with new connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ` * whenever a new connection is requested, create a conn thread`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ` * (session thread) to handle new incoming smb requests from the connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `static int ksmbd_tcp_new_connection(struct socket *client_sk)`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	struct tcp_transport *t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	struct task_struct *handler;`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	t = alloc_transport(client_sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	if (!t) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		sock_release(client_sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00216 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	if (client_sk->sk->sk_family == AF_INET6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `		handler = kthread_run(ksmbd_conn_handler_loop,`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `				KSMBD_TRANS(t)->conn, "ksmbd:%pI6c",`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `				&KSMBD_TRANS(t)->conn->inet6_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `		handler = kthread_run(ksmbd_conn_handler_loop,`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `				KSMBD_TRANS(t)->conn, "ksmbd:%pI4",`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `				&KSMBD_TRANS(t)->conn->inet_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	if (IS_ERR(handler)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [ERROR_PATH|] `		pr_err("cannot start conn thread\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00228 [NONE] `		rc = PTR_ERR(handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		free_transport(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ` * ksmbd_kthread_fn() - listen to new SMB connections and callback server`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ` * @p:		arguments to forker thread`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ` * Return:	0 on success, error number otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `static int ksmbd_kthread_fn(void *p)`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	struct socket *client_sk = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	struct interface *iface = (struct interface *)p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	int ret, inet_hash, bkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	unsigned int max_ip_conns;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	while (!kthread_should_stop()) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `		if (!iface->ksmbd_socket) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `		 * Blocking accept (flags=0) is intentional: the listener`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `		 * thread sleeps in kernel_accept() until a new connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `		 * arrives or the socket is shut down, which is the standard`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		 * pattern for kernel server threads.`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `		ret = kernel_accept(iface->ksmbd_socket, &client_sk, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `		if (ret == -EINVAL || ret == -ESHUTDOWN ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `		    ret == -EBADF || ret == -ENOTSOCK)`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `			cond_resched();`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		if (!server_conf.max_ip_connections)`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [ERROR_PATH|] `			goto skip_max_ip_conns_limit;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00269 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `		 * Limits repeated connections from clients with the same IP.`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `#if IS_ENABLED(CONFIG_IPV6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `		if (client_sk->sk->sk_family == AF_INET6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `			inet_hash = ipv6_addr_hash(&client_sk->sk->sk_v6_daddr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `			inet_hash = ipv4_addr_hash(inet_sk(client_sk->sk)->inet_daddr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `		inet_hash = ipv4_addr_hash(inet_sk(client_sk->sk)->inet_daddr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `		max_ip_conns = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `		bkt = hash_min(inet_hash, CONN_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [LOCK|] `		spin_lock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00285 [NONE] `		hlist_for_each_entry(conn, &conn_hash[bkt].head,`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `				     hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `			if (conn->inet_hash != inet_hash)`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `			 * Connections being torn down are no longer able to`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `			 * serve requests.  Exclude them from the per-IP`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `			 * limit so a burst of short-lived connections (e.g.`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `			 * smbtorture subtests) doesn't prevent legitimate`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `			 * new connections while the old ones are draining.`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `			if (ksmbd_conn_exiting(conn) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `			    ksmbd_conn_releasing(conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `#if IS_ENABLED(CONFIG_IPV6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `			if (client_sk->sk->sk_family == AF_INET6) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `				if (memcmp(&client_sk->sk->sk_v6_daddr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `					   &conn->inet6_addr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `					   16) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `					max_ip_conns++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `			} else if (inet_sk(client_sk->sk)->inet_daddr`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `				   == conn->inet_addr) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `				max_ip_conns++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `			if (inet_sk(client_sk->sk)->inet_daddr ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `			    conn->inet_addr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `				max_ip_conns++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `			if (server_conf.max_ip_connections <=`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `			    max_ip_conns) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `				pr_info_ratelimited("Maximum IP connections exceeded (%u/%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `						    max_ip_conns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `						    server_conf.max_ip_connections);`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `				ret = -EAGAIN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [LOCK|] `		spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00324 [NONE] `		if (ret == -EAGAIN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `			/* Per-IP limit hit: release the just-accepted socket. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `			sock_release(client_sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `skip_max_ip_conns_limit:`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		if (server_conf.max_connections &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [LIFETIME|] `		    atomic_inc_return(&active_num_conn) > server_conf.max_connections) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00333 [NONE] `			pr_info_ratelimited("Limit the maximum number of connections(%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [LIFETIME|] `					    atomic_read(&active_num_conn));`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00335 [LIFETIME|] `			atomic_dec(&active_num_conn);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00336 [NONE] `			sock_release(client_sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `		ksmbd_debug(CONN, "connect success: accepted new connection\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `		client_sk->sk->sk_rcvtimeo = KSMBD_TCP_RECV_TIMEOUT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `		client_sk->sk->sk_sndtimeo = KSMBD_TCP_SEND_TIMEOUT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `		ksmbd_tcp_keepalive(client_sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `		if (ksmbd_tcp_new_connection(client_sk)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `			if (server_conf.max_connections)`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [LIFETIME|] `				atomic_dec(&active_num_conn);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00348 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `	ksmbd_debug(CONN, "releasing socket\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] ` * ksmbd_tcp_run_kthread() - start forker thread`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ` * @iface: pointer to struct interface`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] ` * start forker thread(ksmbd/0) at module init time to listen`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ` * on port 445 for new SMB connection requests. It creates per connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ` * server threads(ksmbd/x)`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] ` * Return:	0 on success or error number`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `static int ksmbd_tcp_run_kthread(struct interface *iface)`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	struct task_struct *kthread;`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	kthread = kthread_run(ksmbd_kthread_fn, (void *)iface, "ksmbd-%s",`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `			      iface->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	if (IS_ERR(kthread)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `		rc = PTR_ERR(kthread);`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `	iface->ksmbd_kthread = kthread;`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ` * ksmbd_tcp_readv() - read data from socket in given iovec`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ` * @t:			TCP transport instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] ` * @iov_orig:		base IO vector`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ` * @nr_segs:		number of segments in base iov`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] ` * @to_read:		number of bytes to read from socket`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ` * @max_retries:	maximum retry count`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] ` * Return:	on success return number of bytes read from socket,`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] ` *		otherwise return error number`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `static int ksmbd_tcp_readv(struct tcp_transport *t, struct kvec *iov_orig,`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `			   unsigned int nr_segs, unsigned int to_read,`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `			   int max_retries)`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	int length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	int total_read;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	unsigned int segs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	struct msghdr ksmbd_msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	struct kvec *iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	struct ksmbd_conn *conn = KSMBD_TRANS(t)->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	iov = kmalloc_array(nr_segs, sizeof(*iov), KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	if (!iov)`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	ksmbd_msg.msg_control = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	ksmbd_msg.msg_controllen = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	for (total_read = 0; to_read; total_read += length, to_read -= length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `		try_to_freeze();`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `		if (!ksmbd_conn_alive(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `			total_read = -ESHUTDOWN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `		segs = kvec_array_init(iov, iov_orig, nr_segs, total_read);`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `		if (!segs) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `			total_read = -EIO;`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `		length = kernel_recvmsg(t->sock, &ksmbd_msg,`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `					iov, segs, to_read, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `		if (length == -EINTR) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `			total_read = -ESHUTDOWN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `		} else if (ksmbd_conn_need_reconnect(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `			total_read = -EAGAIN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `		} else if (length == -ERESTARTSYS || length == -EAGAIN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `			 * If max_retries is negative, Allow unlimited`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `			 * retries to keep connection with inactive sessions.`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `			if (max_retries == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `				total_read = length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `			} else if (max_retries > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `				max_retries--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [WAIT_LOOP|] `			usleep_range(1000, 2000);`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00445 [NONE] `			length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `		} else if (length <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `			total_read = length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	kfree(iov);`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	return total_read;`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] ` * ksmbd_tcp_read() - read data from socket in given buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ` * @t:		TCP transport instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] ` * @buf:	buffer to store read data from socket`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] ` * @to_read:	number of bytes to read from socket`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] ` * @max_retries: number of retries if reading from socket fails`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] ` * Return:	on success return number of bytes read from socket,`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] ` *		otherwise return error number`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `static int ksmbd_tcp_read(struct ksmbd_transport *t, char *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `			  unsigned int to_read, int max_retries)`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	struct kvec iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	iov.iov_base = buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	iov.iov_len = to_read;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	return ksmbd_tcp_readv(TCP_TRANS(t), &iov, 1, to_read, max_retries);`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `static int ksmbd_tcp_writev(struct ksmbd_transport *t, struct kvec *iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `			    int nvecs, int size, bool need_invalidate,`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `			    unsigned int remote_key)`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	struct tcp_transport *tcp_t = TCP_TRANS(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	struct msghdr smb_msg = {.msg_flags = MSG_NOSIGNAL};`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	struct kvec *cur_iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	unsigned int segs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	int total_sent = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	cur_iov = kmalloc_array(nvecs, sizeof(*cur_iov), KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `	if (!cur_iov)`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00492 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	while (total_sent < size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `		if (!ksmbd_conn_alive(KSMBD_TRANS(tcp_t)->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `			ret = -ESHUTDOWN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00497 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `		segs = kvec_array_init(cur_iov, iov, nvecs, total_sent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `		if (!segs) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `			ret = -EIO;`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00503 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `		ret = kernel_sendmsg(tcp_t->sock, &smb_msg, cur_iov, segs,`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `				     size - total_sent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `		if (ret <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `			ret = ret ? ret : -EPIPE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00510 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `		total_sent += ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	ret = total_sent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	kfree(cur_iov);`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] ` * ksmbd_tcp_sendfile() - zero-copy file-to-socket transfer`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ` * @t:		TCP transport instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ` * @filp:	file to read data from`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ` * @pos:	file offset to start reading from (updated on return)`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ` * @count:	number of bytes to send`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] ` * Reads file data into pages using vfs_iter_read() with a bvec`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ` * iterator, then sends the pages directly to the network socket.`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ` * This avoids the intermediate kvzalloc bounce buffer used in the`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] ` * normal read path.`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ` * Return:	number of bytes sent on success, or negative errno`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `#define KSMBD_SENDFILE_MAX_PAGES 16`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `static int ksmbd_tcp_sendfile(struct ksmbd_transport *t, struct file *filp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `			      loff_t *pos, size_t count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	struct tcp_transport *tcp_t = TCP_TRANS(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	struct socket *sock = tcp_t->sock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	ssize_t total_sent = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	while (count > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `		struct bio_vec bvec[KSMBD_SENDFILE_MAX_PAGES];`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `		struct page *pages[KSMBD_SENDFILE_MAX_PAGES];`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `		struct iov_iter iter;`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `		struct msghdr msg = {.msg_flags = MSG_NOSIGNAL};`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `		size_t chunk, read_bytes, remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `		ssize_t ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `		int nr_pages, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `		if (!ksmbd_conn_alive(KSMBD_TRANS(tcp_t)->conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `			return total_sent ? total_sent : -ESHUTDOWN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `		chunk = min_t(size_t, count,`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `			      KSMBD_SENDFILE_MAX_PAGES * PAGE_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `		nr_pages = DIV_ROUND_UP(chunk, PAGE_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `		/* Allocate pages for reading file data */`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `		for (i = 0; i < nr_pages; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `			pages[i] = alloc_page(KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `			if (!pages[i]) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `				while (--i >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `					put_page(pages[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `				return total_sent ? total_sent : -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `		/* Set up bvec entries for the pages */`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `		for (i = 0; i < nr_pages; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `			size_t len = min_t(size_t, chunk - (i * PAGE_SIZE),`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `					   PAGE_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `			bvec[i].bv_page = pages[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `			bvec[i].bv_len = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `			bvec[i].bv_offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `		/* Read file data directly into pages */`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `		iov_iter_bvec(&iter, ITER_DEST, bvec, nr_pages, chunk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `		ret = vfs_iter_read(filp, &iter, pos, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `		if (ret <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `			for (i = 0; i < nr_pages; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `				put_page(pages[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `			return total_sent ? total_sent : (ret ? ret : -EIO);`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `		read_bytes = ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `		/* Adjust last bvec if we read less than requested */`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `		if (read_bytes < chunk) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `			size_t remaining = read_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `			for (i = 0; i < nr_pages; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `				size_t bv_len = min_t(size_t, remaining,`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `						      PAGE_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `				bvec[i].bv_len = bv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `				remaining -= bv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `				if (remaining == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `					/* Free unused pages */`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `					int j;`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `					for (j = i + 1; j < nr_pages; j++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `						put_page(pages[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `					nr_pages = i + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `					break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `		/* Send pages to socket */`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `		iov_iter_bvec(&iter, ITER_SOURCE, bvec, nr_pages, read_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		msg.msg_iter = iter;`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		remaining = read_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `		while (remaining > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `			ret = sock_sendmsg(sock, &msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `			if (ret <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `				for (i = 0; i < nr_pages; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `					put_page(pages[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `				if (total_sent > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `					return total_sent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `				return ret ? ret : -EPIPE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `			remaining -= ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `			total_sent += ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `			count -= ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `		for (i = 0; i < nr_pages; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `			put_page(pages[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	return total_sent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `static void ksmbd_tcp_disconnect(struct ksmbd_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `	free_transport(TCP_TRANS(t));`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `	if (server_conf.max_connections)`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [LIFETIME|] `		atomic_dec(&active_num_conn);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00640 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `static void ksmbd_tcp_shutdown(struct ksmbd_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `	struct socket *sock = TCP_TRANS(t)->sock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	if (!sock)`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	kernel_sock_shutdown(sock, SHUT_RDWR);`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `static void tcp_destroy_socket(struct socket *ksmbd_socket)`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `	if (!ksmbd_socket)`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	ret = kernel_sock_shutdown(ksmbd_socket, SHUT_RDWR);`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [ERROR_PATH|] `		pr_err("Failed to shutdown socket: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00662 [NONE] `	sock_release(ksmbd_socket);`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] ` * create_socket - create socket for ksmbd/0`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] ` * @iface:      interface to bind the created socket to`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] ` * Return:	0 on success, error number otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `static int create_socket(struct interface *iface)`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	struct sockaddr_in6 sin6;`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	struct sockaddr_in sin;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	struct socket *ksmbd_socket;`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `	bool ipv4 = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	ret = sock_create_kern(current->nsproxy->net_ns, PF_INET6, SOCK_STREAM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `			IPPROTO_TCP, &ksmbd_socket);`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `		if (ret != -EAFNOSUPPORT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [ERROR_PATH|] `			pr_err("Can't create socket for ipv6, fallback to ipv4: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00684 [NONE] `		ret = sock_create_kern(current->nsproxy->net_ns, PF_INET,`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `				SOCK_STREAM, IPPROTO_TCP, &ksmbd_socket);`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [ERROR_PATH|] `			pr_err("Can't create socket for ipv4: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00688 [ERROR_PATH|] `			goto out_clear;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00689 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `		sin.sin_family = PF_INET;`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `		sin.sin_addr.s_addr = htonl(INADDR_ANY);`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `		sin.sin_port = htons(server_conf.tcp_port);`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `		ipv4 = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `		sin6.sin6_family = PF_INET6;`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `		sin6.sin6_addr = in6addr_any;`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `		sin6.sin6_port = htons(server_conf.tcp_port);`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `		lock_sock(ksmbd_socket->sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `		ksmbd_socket->sk->sk_ipv6only = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `		release_sock(ksmbd_socket->sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `	ksmbd_tcp_nodelay(ksmbd_socket);`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `	ksmbd_tcp_reuseaddr(ksmbd_socket);`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `	ret = kernel_setsockopt(ksmbd_socket,`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `				SOL_SOCKET,`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `				SO_BINDTODEVICE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `				iface->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `				strlen(iface->name));`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	ret = sock_setsockopt(ksmbd_socket,`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `			      SOL_SOCKET,`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `			      SO_BINDTODEVICE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `			      (char __user *)iface->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `			      KERNEL_SOCKPTR(iface->name),`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `			      strlen(iface->name));`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `	if (ret != -ENODEV && ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [ERROR_PATH|] `		pr_err("Failed to set SO_BINDTODEVICE: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00727 [ERROR_PATH|] `		goto out_error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00728 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `	if (ipv4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `		ret = kernel_bind(ksmbd_socket, (struct sockaddr_unsized *)&sin,`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `		ret = kernel_bind(ksmbd_socket, (struct sockaddr *)&sin,`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `				  sizeof(sin));`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `		ret = kernel_bind(ksmbd_socket, (struct sockaddr_unsized *)&sin6,`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `		ret = kernel_bind(ksmbd_socket, (struct sockaddr *)&sin6,`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `				  sizeof(sin6));`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [ERROR_PATH|] `		pr_err("Failed to bind socket: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00746 [ERROR_PATH|] `		goto out_error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00747 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `	ret = kernel_listen(ksmbd_socket, KSMBD_SOCKET_BACKLOG);`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [ERROR_PATH|] `		pr_err("Port listen() error: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00752 [ERROR_PATH|] `		goto out_error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00753 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	iface->ksmbd_socket = ksmbd_socket;`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	ret = ksmbd_tcp_run_kthread(iface);`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [ERROR_PATH|] `		pr_err("Can't start ksmbd main kthread: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00759 [ERROR_PATH|] `		goto out_error;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00760 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `	iface->state = IFACE_STATE_CONFIGURED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `out_error:`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `	tcp_destroy_socket(ksmbd_socket);`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `out_clear:`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	iface->ksmbd_socket = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `struct interface *ksmbd_find_netdev_name_iface_list(char *netdev_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	struct interface *iface;`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [LOCK|] `	mutex_lock(&iface_list_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00777 [NONE] `	list_for_each_entry(iface, &iface_list, entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `		if (!strcmp(iface->name, netdev_name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [LOCK|] `			mutex_unlock(&iface_list_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00780 [NONE] `			return iface;`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [LOCK|] `	mutex_unlock(&iface_list_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00784 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `static int ksmbd_netdev_event(struct notifier_block *nb, unsigned long event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `			      void *ptr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `	struct interface *iface;`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `	switch (event) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `	case NETDEV_UP:`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `		if (netdev->priv_flags & IFF_BRIDGE_PORT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `			return NOTIFY_OK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `		iface = ksmbd_find_netdev_name_iface_list(netdev->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `		if (iface && iface->state == IFACE_STATE_DOWN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `			ksmbd_debug(CONN, "netdev-up event: netdev(%s) is going up\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `					iface->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `			ret = create_socket(iface);`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `			if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `				return NOTIFY_OK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `		if (!iface && bind_additional_ifaces) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `			iface = alloc_iface(kstrdup(netdev->name, KSMBD_DEFAULT_GFP));`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `			if (!iface)`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `				return NOTIFY_OK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `			ksmbd_debug(CONN, "netdev-up event: netdev(%s) is going up\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `				    iface->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `			ret = create_socket(iface);`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `			if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `	case NETDEV_DOWN:`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `		iface = ksmbd_find_netdev_name_iface_list(netdev->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `		if (iface && iface->state == IFACE_STATE_CONFIGURED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `			ksmbd_debug(CONN, "netdev-down event: netdev(%s) is going down\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `					iface->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `			kernel_sock_shutdown(iface->ksmbd_socket, SHUT_RDWR);`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `			tcp_stop_kthread(iface->ksmbd_kthread);`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `			iface->ksmbd_kthread = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `			sock_release(iface->ksmbd_socket);`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `			iface->ksmbd_socket = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `			iface->state = IFACE_STATE_DOWN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	return NOTIFY_DONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `static struct notifier_block ksmbd_netdev_notifier = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `	.notifier_call = ksmbd_netdev_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `int ksmbd_tcp_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `	register_netdevice_notifier(&ksmbd_netdev_notifier);`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `static void tcp_stop_kthread(struct task_struct *kthread)`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	if (!kthread)`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `	ret = kthread_stop(kthread);`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [ERROR_PATH|] `		pr_err("failed to stop forker thread\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00859 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `void ksmbd_tcp_destroy(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `	struct interface *iface, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `	unregister_netdevice_notifier(&ksmbd_netdev_notifier);`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [LOCK|] `	mutex_lock(&iface_list_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00868 [NONE] `	list_for_each_entry_safe(iface, tmp, &iface_list, entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `		if (iface->ksmbd_socket)`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `			kernel_sock_shutdown(iface->ksmbd_socket, SHUT_RDWR);`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `		tcp_stop_kthread(iface->ksmbd_kthread);`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `		iface->ksmbd_kthread = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `		if (iface->ksmbd_socket) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `			sock_release(iface->ksmbd_socket);`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `			iface->ksmbd_socket = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `		iface->state = IFACE_STATE_DOWN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `		list_del(&iface->entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `		kfree(iface->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `		kfree(iface);`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [LOCK|] `	mutex_unlock(&iface_list_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00883 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `static struct interface *alloc_iface(char *ifname)`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `	struct interface *iface;`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `	if (!ifname)`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [MEM_BOUNDS|] `	iface = kzalloc(sizeof(struct interface), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00893 [NONE] `	if (!iface) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `		kfree(ifname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `	iface->name = ifname;`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `	iface->state = IFACE_STATE_DOWN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [LOCK|] `	mutex_lock(&iface_list_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00901 [NONE] `	list_add(&iface->entry, &iface_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [LOCK|] `	mutex_unlock(&iface_list_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00903 [NONE] `	return iface;`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `int ksmbd_tcp_set_interfaces(char *ifc_list, int ifc_list_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `	struct interface *iface, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `	int sz = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `	if (!ifc_list_sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `		bind_additional_ifaces = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `	while (ifc_list_sz > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `		if (!alloc_iface(kstrdup(ifc_list, KSMBD_DEFAULT_GFP))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [LOCK|] `			mutex_lock(&iface_list_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00919 [NONE] `			list_for_each_entry_safe(iface, tmp, &iface_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `						 entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `				list_del(&iface->entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `				kfree(iface->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `				kfree(iface);`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [LOCK|] `			mutex_unlock(&iface_list_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00926 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00927 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `		sz = strlen(ifc_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `		if (!sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `		ifc_list += sz + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `		ifc_list_sz -= (sz + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	bind_additional_ifaces = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `static const struct ksmbd_transport_ops ksmbd_tcp_transport_ops = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	.read		= ksmbd_tcp_read,`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	.writev		= ksmbd_tcp_writev,`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	.sendfile	= ksmbd_tcp_sendfile,`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	.disconnect	= ksmbd_tcp_disconnect,`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `	.shutdown	= ksmbd_tcp_shutdown,`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	.free_transport = ksmbd_tcp_free_transport,`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
