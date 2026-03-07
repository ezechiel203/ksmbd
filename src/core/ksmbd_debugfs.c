// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Debugfs interface for ksmbd server runtime inspection
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include "glob.h"
#include "server.h"
#include "connection.h"

static struct dentry *ksmbd_debugfs_dir;

/**
 * ksmbd_conn_status_str() - convert connection status to string
 * @conn:	connection instance
 *
 * Return:	string representation of the connection status
 */
static const char *ksmbd_conn_status_str(struct ksmbd_conn *conn)
{
	switch (READ_ONCE(conn->status)) {
	case KSMBD_SESS_NEW:		return "new";
	case KSMBD_SESS_GOOD:		return "good";
	case KSMBD_SESS_EXITING:	return "exiting";
	case KSMBD_SESS_NEED_RECONNECT:	return "reconnect";
	case KSMBD_SESS_NEED_NEGOTIATE:	return "negotiate";
	case KSMBD_SESS_NEED_SETUP:	return "setup";
	case KSMBD_SESS_RELEASING:	return "releasing";
	default:			return "unknown";
	}
}

/* Snapshot of connection data collected under spinlock */
struct conn_snapshot {
	char addr_buf[64];
	unsigned short dialect;
	const char *status;
	unsigned int total_credits;
	int req_running;
};

static int ksmbd_debugfs_connections_show(struct seq_file *s, void *v)
{
	struct ksmbd_conn *conn;
	struct conn_snapshot *snaps = NULL;
	int i, count = 0, capacity = 0;

	seq_printf(s, "%-20s %-6s %-10s %-8s %-8s\n",
		   "peer", "dialect", "status", "credits",
		   "requests");
	seq_puts(s,
		 "-----------------------------------------------------------\n");

restart_scan:
	count = 0;
	for (i = 0; i < CONN_HASH_SIZE; i++) {
		spin_lock(&conn_hash[i].lock);
		hlist_for_each_entry(conn, &conn_hash[i].head,
				     hlist) {
			if (count >= capacity) {
				/* Grow snapshot storage and restart a full scan. */
				int new_capacity;

				spin_unlock(&conn_hash[i].lock);
				new_capacity = max(16, capacity * 2);
				kvfree(snaps);
				snaps = kvmalloc_array(new_capacity,
						       sizeof(*snaps),
						       KSMBD_DEFAULT_GFP);
				if (!snaps)
					return -ENOMEM;
				capacity = new_capacity;
				goto restart_scan;
			}
			snprintf(snaps[count].addr_buf,
				 sizeof(snaps[count].addr_buf),
				 "%pIS",
				 KSMBD_TCP_PEER_SOCKADDR(conn));
			snaps[count].dialect = conn->dialect;
			snaps[count].status =
				ksmbd_conn_status_str(conn);
			snaps[count].total_credits =
				conn->total_credits;
			snaps[count].req_running =
				atomic_read(&conn->req_running);
			count++;
		}
		spin_unlock(&conn_hash[i].lock);
	}

	for (i = 0; i < count; i++) {
		seq_printf(s,
			   "%-20s 0x%04x %-10s %-8u %-8d\n",
			   snaps[i].addr_buf,
			   snaps[i].dialect,
			   snaps[i].status,
			   snaps[i].total_credits,
			   snaps[i].req_running);
	}

	kvfree(snaps);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ksmbd_debugfs_connections);

static int ksmbd_debugfs_stats_show(struct seq_file *s, void *v)
{
	struct ksmbd_conn *conn;
	int i, num_conns = 0;
	u64 total_requests = 0;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		spin_lock(&conn_hash[i].lock);
		hlist_for_each_entry(conn, &conn_hash[i].head,
				     hlist) {
			num_conns++;
			total_requests +=
				atomic64_read(
					&conn->stats.request_served);
		}
		spin_unlock(&conn_hash[i].lock);
	}

	seq_printf(s, "active connections: %d\n", num_conns);
	seq_printf(s, "total requests served: %llu\n",
		   total_requests);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ksmbd_debugfs_stats);

/**
 * ksmbd_debugfs_init() - initialize debugfs entries for ksmbd
 *
 * Creates /sys/kernel/debug/ksmbd/ directory with entries for
 * connections and server statistics.
 *
 * Return:	0 on success, negative error code on failure
 */
int ksmbd_debugfs_init(void)
{
	ksmbd_debugfs_dir = debugfs_create_dir("ksmbd", NULL);
	if (IS_ERR(ksmbd_debugfs_dir)) {
		pr_err("Failed to create debugfs directory\n");
		return PTR_ERR(ksmbd_debugfs_dir);
	}

	/* Root-only: connections file exposes peer IP addresses */
	debugfs_create_file("connections", 0400, ksmbd_debugfs_dir,
			    NULL, &ksmbd_debugfs_connections_fops);
	debugfs_create_file("stats", 0400, ksmbd_debugfs_dir,
			    NULL, &ksmbd_debugfs_stats_fops);
	return 0;
}

/**
 * ksmbd_debugfs_exit() - remove all debugfs entries for ksmbd
 */
void ksmbd_debugfs_exit(void)
{
	debugfs_remove_recursive(ksmbd_debugfs_dir);
}
