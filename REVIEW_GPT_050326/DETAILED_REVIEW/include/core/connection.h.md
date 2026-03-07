# Line-by-line Review: src/include/core/connection.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#ifndef __KSMBD_CONNECTION_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __KSMBD_CONNECTION_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/ip.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <net/sock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <net/tcp.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <net/inet_connection_sock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <net/request_sock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/kthread.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/nls.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/refcount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/unicode.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "ksmbd_feature.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` * Listen backlog for the TCP accept queue.  A value of 64 handles`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` * short connection bursts without dropping SYN requests while staying`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` * within reasonable kernel memory limits.`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define KSMBD_SOCKET_BACKLOG		64`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	KSMBD_SESS_NEW = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	KSMBD_SESS_GOOD,`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	KSMBD_SESS_EXITING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	KSMBD_SESS_NEED_RECONNECT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	KSMBD_SESS_NEED_NEGOTIATE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	KSMBD_SESS_NEED_SETUP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	KSMBD_SESS_RELEASING`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `struct ksmbd_stats {`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [LIFETIME|] `	atomic_t			open_files_count;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00044 [NONE] `	atomic64_t			request_served;`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `struct ksmbd_transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `struct ksmbd_conn {`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	struct smb_version_values	*vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	struct smb_version_ops		*ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	struct smb_version_cmds		*cmds;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	unsigned int			max_cmds;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	struct mutex			srv_mutex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	int				status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	unsigned int			cli_cap;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	union {`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `		__be32			inet_addr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#if IS_ENABLED(CONFIG_IPV6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `		u8			inet6_addr[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	};`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	unsigned int			inet_hash;`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	char				*request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	struct ksmbd_transport		*transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	struct nls_table		*local_nls;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	struct unicode_map		*um;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	struct hlist_node		hlist;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	struct rw_semaphore		session_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	/* smb session 1 per user */`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	struct xarray			sessions;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	unsigned long			last_active;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	/* How many request are running currently */`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [LIFETIME|] `	atomic_t			req_running;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00075 [NONE] `	/* References which are made for this Server object*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [LIFETIME|] `	atomic_t			r_count;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00077 [NONE] `	unsigned int			total_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	unsigned int			outstanding_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	spinlock_t			credits_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	wait_queue_head_t		req_running_q;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	wait_queue_head_t		r_count_q;`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	/* Lock to protect requests list*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	spinlock_t			request_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	struct list_head		requests;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	struct list_head		async_requests;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	int				connection_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	struct ksmbd_stats		stats;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [PROTO_GATE|] `	char				ClientGUID[SMB2_CLIENT_GUID_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00089 [NONE] `	struct ntlmssp_auth		ntlmssp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	spinlock_t			llist_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	struct list_head		lock_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	struct preauth_integrity_info	*preauth_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	bool				need_neg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	bool				smb1_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	unsigned int			auth_mechs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	unsigned int			preferred_auth_mech;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	bool				sign;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	bool				use_spnego:1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	__u16				cli_sec_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	__u16				srv_sec_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	/* dialect index that server chose */`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	__u16				dialect;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	char				*mechToken;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	unsigned int			mechTokenLen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	struct ksmbd_conn_ops	*conn_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	/* Preauth Session Table */`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	struct list_head		preauth_sess_table;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	struct sockaddr_storage		peer_addr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	/* Identifier for async message */`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	struct ida			async_ida;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	__le16				cipher_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	__le16				compress_algorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	bool				posix_ext_supported;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	bool				signing_negotiated;`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	__le16				signing_algorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	bool				transport_secured;`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	__le16				rdma_transform_ids[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	unsigned int			rdma_transform_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	bool				binding;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [LIFETIME|] `	refcount_t			refcnt;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00130 [NONE] `	unsigned long			features;  /* per-connection negotiated features */`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	/* Per-connection fsnotify watch count to prevent memory DoS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [LIFETIME|] `	atomic_t			notify_watch_count;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	/* Outstanding async operations for credit exhaustion enforcement */`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [LIFETIME|] `	atomic_t			outstanding_async;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	/* Negotiated CIFS UNIX extension capabilities (SMB1 only) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	__u64				unix_caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	bool				is_fruit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	/* Fruit SMB Extension Support */`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	struct fruit_conn_state	*fruit_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `struct ksmbd_conn_ops {`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	int	(*process_fn)(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	int	(*terminate_fn)(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `struct ksmbd_transport_ops {`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	int (*prepare)(struct ksmbd_transport *t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	void (*disconnect)(struct ksmbd_transport *t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	void (*shutdown)(struct ksmbd_transport *t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	int (*read)(struct ksmbd_transport *t, char *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `		    unsigned int size, int max_retries);`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	int (*writev)(struct ksmbd_transport *t, struct kvec *iovs, int niov,`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		      int size, bool need_invalidate_rkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		      unsigned int remote_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	int (*rdma_read)(struct ksmbd_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `			 void *buf, unsigned int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `			 struct smb2_buffer_desc_v1 *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `			 unsigned int desc_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	int (*rdma_write)(struct ksmbd_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `			  void *buf, unsigned int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `			  struct smb2_buffer_desc_v1 *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `			  unsigned int desc_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	int (*sendfile)(struct ksmbd_transport *t, struct file *filp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `			loff_t *pos, size_t count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	void (*free_transport)(struct ksmbd_transport *kt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `struct ksmbd_transport {`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	struct ksmbd_conn			*conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	const struct ksmbd_transport_ops	*ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `#define KSMBD_TCP_RECV_TIMEOUT	(7 * HZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `#define KSMBD_TCP_SEND_TIMEOUT	(5 * HZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `#define KSMBD_TCP_PEER_SOCKADDR(c)	((struct sockaddr *)&((c)->peer_addr))`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `#define CONN_HASH_BITS	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `#define CONN_HASH_SIZE	(1 << CONN_HASH_BITS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] ` * struct ksmbd_conn_hash_bucket - per-bucket hash entry for connections`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] ` * @head:	hash list head for this bucket`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ` * @lock:	spinlock protecting this bucket`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `struct ksmbd_conn_hash_bucket {`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	struct hlist_head	head;`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	spinlock_t		lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `extern struct ksmbd_conn_hash_bucket conn_hash[CONN_HASH_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [LIFETIME|] `extern atomic_t conn_hash_count;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `void ksmbd_conn_hash_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `void ksmbd_conn_hash_add(struct ksmbd_conn *conn, unsigned int key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `void ksmbd_conn_hash_del(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `bool ksmbd_conn_hash_empty(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `bool ksmbd_conn_alive(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `void ksmbd_conn_wait_idle(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `int ksmbd_conn_wait_idle_sess_id(struct ksmbd_conn *curr_conn, u64 sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `struct ksmbd_conn *ksmbd_conn_alloc(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `void ksmbd_conn_free(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `bool ksmbd_conn_lookup_dialect(struct ksmbd_conn *c);`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `int ksmbd_conn_write(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `int ksmbd_conn_rdma_read(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `			 void *buf, unsigned int buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `			 struct smb2_buffer_desc_v1 *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `			 unsigned int desc_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `int ksmbd_conn_rdma_write(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `			  void *buf, unsigned int buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `			  struct smb2_buffer_desc_v1 *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `			  unsigned int desc_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `void ksmbd_conn_enqueue_request(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `void ksmbd_conn_try_dequeue_request(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `void ksmbd_conn_init_server_callbacks(struct ksmbd_conn_ops *ops);`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `int ksmbd_conn_handler_loop(void *p);`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `int ksmbd_conn_transport_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `void ksmbd_conn_transport_destroy(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `void ksmbd_conn_lock(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `void ksmbd_conn_unlock(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `void ksmbd_conn_r_count_inc(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `void ksmbd_conn_r_count_dec(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] ` * WARNING`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ` * This is a hack. We will move status to a proper place once we land`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ` * a multi-sessions support.`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `static inline bool ksmbd_conn_good(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	return READ_ONCE(conn->status) == KSMBD_SESS_GOOD;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `static inline bool ksmbd_conn_need_negotiate(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	return READ_ONCE(conn->status) == KSMBD_SESS_NEED_NEGOTIATE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `static inline bool ksmbd_conn_need_setup(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	return READ_ONCE(conn->status) == KSMBD_SESS_NEED_SETUP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `static inline bool ksmbd_conn_need_reconnect(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	return READ_ONCE(conn->status) == KSMBD_SESS_NEED_RECONNECT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `static inline bool ksmbd_conn_exiting(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	return READ_ONCE(conn->status) == KSMBD_SESS_EXITING;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `static inline bool ksmbd_conn_releasing(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	return READ_ONCE(conn->status) == KSMBD_SESS_RELEASING;`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `static inline void ksmbd_conn_set_new(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	WRITE_ONCE(conn->status, KSMBD_SESS_NEW);`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `static inline void ksmbd_conn_set_good(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	WRITE_ONCE(conn->status, KSMBD_SESS_GOOD);`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `static inline void ksmbd_conn_set_need_negotiate(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `	WRITE_ONCE(conn->status, KSMBD_SESS_NEED_NEGOTIATE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `static inline void ksmbd_conn_set_need_setup(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	WRITE_ONCE(conn->status, KSMBD_SESS_NEED_SETUP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `static inline void ksmbd_conn_set_need_reconnect(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	WRITE_ONCE(conn->status, KSMBD_SESS_NEED_RECONNECT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `static inline void ksmbd_conn_set_exiting(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	WRITE_ONCE(conn->status, KSMBD_SESS_EXITING);`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `static inline void ksmbd_conn_set_releasing(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	WRITE_ONCE(conn->status, KSMBD_SESS_RELEASING);`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `void ksmbd_all_conn_set_status(u64 sess_id, u32 status);`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `#endif /* __KSMBD_CONNECTION_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
