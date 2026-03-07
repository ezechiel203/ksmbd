/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __SERVER_H__
#define __SERVER_H__

#include "smbacl.h"
#include "ksmbd_config.h"
#include "ksmbd_feature.h"

/*
 * R-08: Live reconfiguration design notes
 *
 * Currently, ksmbd caches share configurations in an RCU hashtable
 * (shares_table in mgmt/share_config.c).  The cache is populated on
 * the first TREE_CONNECT to a given share name and remains valid
 * until the share_config refcount drops to zero.
 *
 * Hot-reload sequence (future work):
 *   1. Admin signals the daemon (e.g., SIGHUP or "ksmbdctl reload").
 *   2. Daemon sends a new netlink event (e.g., KSMBD_EVENT_RELOAD)
 *      to the kernel module.
 *   3. Kernel handler iterates shares_table under write lock, drops
 *      refcounts of all entries with refcount == 1 (no active tree
 *      connects), and removes them from the hash table.
 *   4. Entries with active tree connects remain valid until the last
 *      tree disconnect, at which point the refcount reaches zero and
 *      the entry is freed via __ksmbd_share_config_put().
 *   5. The next TREE_CONNECT to a purged share re-fetches the config
 *      from the daemon via KSMBD_EVENT_SHARE_CONFIG_REQUEST, picking
 *      up any changes the admin made to ksmbd.conf.
 *
 * For user credential changes, the daemon already re-queries on each
 * SESSION_SETUP via KSMBD_EVENT_LOGIN_REQUEST, so no cache
 * invalidation is needed on the user side.
 *
 * Server-level config (signing, max_credits, etc.) is set once at
 * startup and currently requires a full server reset
 * (SERVER_STATE_RESETTING → STARTING_UP cycle) to change.
 */

/*
 * Server state type
 */
enum {
	SERVER_STATE_STARTING_UP,
	SERVER_STATE_RUNNING,
	SERVER_STATE_RESETTING,
	SERVER_STATE_DRAINING,
	SERVER_STATE_SHUTTING_DOWN,
};

/*
 * Server global config string index
 */
enum {
	SERVER_CONF_NETBIOS_NAME,
	SERVER_CONF_SERVER_STRING,
	SERVER_CONF_WORK_GROUP,
};

struct ksmbd_server_config {
	unsigned int		flags;
	unsigned int		state;
	short			signing;
	short			min_protocol;
	short			max_protocol;
	unsigned short		tcp_port;
	unsigned short		ipc_timeout;
	unsigned long		ipc_last_active;
	unsigned long		deadtime;
	unsigned int		share_fake_fscaps;
	struct smb_sid		domain_sid;
	unsigned int		auth_mechs;
	unsigned int		max_connections;
	unsigned int		max_inflight_req;
	unsigned int		max_async_credits;
	unsigned int		max_ip_connections;

	unsigned long		features;  /* global feature enable bitmask */

	char			*conf[SERVER_CONF_WORK_GROUP + 1];
	char			fruit_model[64];
	struct task_struct	*dh_task;
	bool			bind_interfaces_only;

	/* Stable per-server GUID (MS-SMB2 §2.2.4 ServerGUID) */
	__u8			server_guid[16];
	/* Server start time in 100-ns Windows FILETIME units */
	__u64			server_start_time;

	/* Global health counters for sysfs monitoring (R-06) */
	atomic_t		connections_active;
	atomic_t		sessions_active;
	atomic64_t		requests_served;
	atomic_t		auth_failures;
};

extern struct ksmbd_server_config server_conf;

int ksmbd_set_netbios_name(char *v);
int ksmbd_set_server_string(char *v);
int ksmbd_set_work_group(char *v);

char *ksmbd_netbios_name(void);
char *ksmbd_server_string(void);
char *ksmbd_work_group(void);

static inline int ksmbd_server_running(void)
{
	int state = READ_ONCE(server_conf.state);

	return state == SERVER_STATE_RUNNING ||
	       state == SERVER_STATE_DRAINING;
}

static inline int ksmbd_server_draining(void)
{
	return READ_ONCE(server_conf.state) == SERVER_STATE_DRAINING;
}

static inline int ksmbd_server_configurable(void)
{
	return READ_ONCE(server_conf.state) < SERVER_STATE_RESETTING;
}

int server_queue_ctrl_init_work(void);
int server_queue_ctrl_reset_work(void);

int ksmbd_debugfs_init(void);
void ksmbd_debugfs_exit(void);
#endif /* __SERVER_H__ */
