# Line-by-line Review: src/core/ksmbd_debugfs.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Debugfs interface for ksmbd server runtime inspection`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/debugfs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/seq_file.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/mm.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `static struct dentry *ksmbd_debugfs_dir;`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * ksmbd_conn_status_str() - convert connection status to string`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` * Return:	string representation of the connection status`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `static const char *ksmbd_conn_status_str(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	switch (READ_ONCE(conn->status)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	case KSMBD_SESS_NEW:		return "new";`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	case KSMBD_SESS_GOOD:		return "good";`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	case KSMBD_SESS_EXITING:	return "exiting";`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	case KSMBD_SESS_NEED_RECONNECT:	return "reconnect";`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	case KSMBD_SESS_NEED_NEGOTIATE:	return "negotiate";`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	case KSMBD_SESS_NEED_SETUP:	return "setup";`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	case KSMBD_SESS_RELEASING:	return "releasing";`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	default:			return "unknown";`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `/* Snapshot of connection data collected under spinlock */`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `struct conn_snapshot {`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	char addr_buf[64];`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	unsigned short dialect;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	const char *status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	unsigned int total_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	int req_running;`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `static int ksmbd_debugfs_connections_show(struct seq_file *s, void *v)`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	struct conn_snapshot *snaps = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	int i, count = 0, capacity = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	seq_printf(s, "%-20s %-6s %-10s %-8s %-8s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `		   "peer", "dialect", "status", "credits",`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `		   "requests");`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	seq_puts(s,`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `		 "-----------------------------------------------------------\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `restart_scan:`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	for (i = 0; i < CONN_HASH_SIZE; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [LOCK|] `		spin_lock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00065 [NONE] `		hlist_for_each_entry(conn, &conn_hash[i].head,`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `				     hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `			if (count >= capacity) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `				/* Grow snapshot storage and restart a full scan. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `				int new_capacity;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [LOCK|] `				spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00072 [NONE] `				new_capacity = max(16, capacity * 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `				kvfree(snaps);`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `				snaps = kvmalloc_array(new_capacity,`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `						       sizeof(*snaps),`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `						       KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `				if (!snaps)`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [ERROR_PATH|] `					return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00079 [NONE] `				capacity = new_capacity;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [ERROR_PATH|] `				goto restart_scan;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00081 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [MEM_BOUNDS|] `			snprintf(snaps[count].addr_buf,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00083 [NONE] `				 sizeof(snaps[count].addr_buf),`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `				 "%pIS",`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `				 KSMBD_TCP_PEER_SOCKADDR(conn));`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `			snaps[count].dialect = conn->dialect;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `			snaps[count].status =`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `				ksmbd_conn_status_str(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `			snaps[count].total_credits =`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `				conn->total_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `			snaps[count].req_running =`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [LIFETIME|] `				atomic_read(&conn->req_running);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00093 [NONE] `			count++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [LOCK|] `		spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00096 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	for (i = 0; i < count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `		seq_printf(s,`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `			   "%-20s 0x%04x %-10s %-8u %-8d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `			   snaps[i].addr_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `			   snaps[i].dialect,`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `			   snaps[i].status,`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `			   snaps[i].total_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `			   snaps[i].req_running);`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	kvfree(snaps);`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `DEFINE_SHOW_ATTRIBUTE(ksmbd_debugfs_connections);`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `static int ksmbd_debugfs_stats_show(struct seq_file *s, void *v)`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	int i, num_conns = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	u64 total_requests = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	for (i = 0; i < CONN_HASH_SIZE; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [LOCK|] `		spin_lock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00122 [NONE] `		hlist_for_each_entry(conn, &conn_hash[i].head,`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `				     hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `			num_conns++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `			total_requests +=`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `				atomic64_read(`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `					&conn->stats.request_served);`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [LOCK|] `		spin_unlock(&conn_hash[i].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00130 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	seq_printf(s, "active connections: %d\n", num_conns);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	seq_printf(s, "total requests served: %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `		   total_requests);`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `DEFINE_SHOW_ATTRIBUTE(ksmbd_debugfs_stats);`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` * ksmbd_debugfs_init() - initialize debugfs entries for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ` * Creates /sys/kernel/debug/ksmbd/ directory with entries for`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ` * connections and server statistics.`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ` * Return:	0 on success, negative error code on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `int ksmbd_debugfs_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	ksmbd_debugfs_dir = debugfs_create_dir("ksmbd", NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	if (IS_ERR(ksmbd_debugfs_dir)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [ERROR_PATH|] `		pr_err("Failed to create debugfs directory\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00153 [NONE] `		return PTR_ERR(ksmbd_debugfs_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	/* Root-only: connections file exposes peer IP addresses */`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	debugfs_create_file("connections", 0400, ksmbd_debugfs_dir,`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `			    NULL, &ksmbd_debugfs_connections_fops);`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	debugfs_create_file("stats", 0400, ksmbd_debugfs_dir,`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `			    NULL, &ksmbd_debugfs_stats_fops);`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` * ksmbd_debugfs_exit() - remove all debugfs entries for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `void ksmbd_debugfs_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	debugfs_remove_recursive(ksmbd_debugfs_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
