// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/parser.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/mm.h>

#include "share_config.h"
#include "user_config.h"
#include "user_session.h"
#include "../connection.h"
#include "../transport_ipc.h"
#include "../misc.h"

#define SHARE_HASH_BITS		12
static DEFINE_HASHTABLE(shares_table, SHARE_HASH_BITS);
static DEFINE_SPINLOCK(shares_table_lock);

struct ksmbd_veto_pattern {
	char			*pattern;
	struct list_head	list;
};

static unsigned int share_name_hash(const char *name)
{
	return jhash(name, strlen(name), 0);
}

static void kill_share(struct ksmbd_share_config *share)
{
	while (!list_empty(&share->veto_list)) {
		struct ksmbd_veto_pattern *p;

		p = list_entry(share->veto_list.next,
			       struct ksmbd_veto_pattern,
			       list);
		list_del(&p->list);
		kfree(p->pattern);
		kfree(p);
	}

	if (share->path)
		path_put(&share->vfs_path);
	kfree(share->name);
	kfree(share->path);
	kfree(share);
}

/**
 * kill_share_rcu() - RCU callback to free a share config
 * @head: rcu_head embedded in ksmbd_share_config
 *
 * Called after an RCU grace period to safely free a share
 * config that was removed from the hash table.
 */
static void kill_share_rcu(struct rcu_head *head)
{
	struct ksmbd_share_config *share;

	share = container_of(head, struct ksmbd_share_config,
			     rcu_head);
	kill_share(share);
}

void ksmbd_share_config_del(struct ksmbd_share_config *share)
{
	spin_lock(&shares_table_lock);
	hash_del_rcu(&share->hlist);
	spin_unlock(&shares_table_lock);
}

void __ksmbd_share_config_put(struct ksmbd_share_config *share)
{
	ksmbd_share_config_del(share);
	call_rcu(&share->rcu_head, kill_share_rcu);
}

static struct ksmbd_share_config *
__get_share_config(struct ksmbd_share_config *share)
{
	if (!refcount_inc_not_zero(&share->refcount))
		return NULL;
	return share;
}

static struct ksmbd_share_config *
__share_lookup_rcu(const char *name)
{
	struct ksmbd_share_config *share;
	unsigned int key = share_name_hash(name);

	hash_for_each_possible_rcu(shares_table, share, hlist, key) {
		if (!strcmp(name, share->name))
			return share;
	}
	return NULL;
}

static int parse_veto_list(struct ksmbd_share_config *share,
			   char *veto_list,
			   int veto_list_sz)
{
	int sz = 0;

	if (!veto_list_sz)
		return 0;

	while (veto_list_sz > 0) {
		struct ksmbd_veto_pattern *p;

		sz = strlen(veto_list);
		if (!sz)
			break;

		p = kzalloc(sizeof(struct ksmbd_veto_pattern), KSMBD_DEFAULT_GFP);
		if (!p)
			return -ENOMEM;

		p->pattern = kstrdup(veto_list, KSMBD_DEFAULT_GFP);
		if (!p->pattern) {
			kfree(p);
			return -ENOMEM;
		}

		list_add(&p->list, &share->veto_list);

		veto_list += sz + 1;
		veto_list_sz -= (sz + 1);
	}

	return 0;
}

static struct ksmbd_share_config *share_config_request(struct ksmbd_work *work,
						       const char *name)
{
	struct ksmbd_share_config_response *resp;
	struct ksmbd_share_config *share = NULL;
	struct ksmbd_share_config *lookup;
	struct unicode_map *um = work->conn->um;
	int ret;

	resp = ksmbd_ipc_share_config_request(name);
	if (!resp)
		return NULL;

	if (resp->flags == KSMBD_SHARE_FLAG_INVALID)
		goto out;

	if (*resp->share_name) {
		char *cf_resp_name;
		bool equal;

		cf_resp_name = ksmbd_casefold_sharename(um, resp->share_name);
		if (IS_ERR(cf_resp_name))
			goto out;
		equal = !strcmp(cf_resp_name, name);
		kfree(cf_resp_name);
		if (!equal)
			goto out;
	}

	share = kzalloc(sizeof(struct ksmbd_share_config), KSMBD_DEFAULT_GFP);
	if (!share)
		goto out;

	share->flags = resp->flags;
	refcount_set(&share->refcount, 1);
	INIT_LIST_HEAD(&share->veto_list);
	share->name = kstrdup(name, KSMBD_DEFAULT_GFP);

	if (!test_share_config_flag(share, KSMBD_SHARE_FLAG_PIPE)) {
		int path_len = PATH_MAX;

		if (resp->payload_sz)
			path_len = resp->payload_sz - resp->veto_list_sz;

		share->path = kstrndup(ksmbd_share_config_path(resp), path_len,
				      KSMBD_DEFAULT_GFP);
		if (share->path) {
			/* Validate share path is absolute */
			if (share->path[0] != '/' ||
			    strstr(share->path, "/../") ||
			    !strcmp(share->path, "/..")) {
				pr_err("share path must be absolute without '..' components: %s\n",
				       share->path);
				kill_share(share);
				share = NULL;
				goto out;
			}
			share->path_sz = strlen(share->path);
			while (share->path_sz > 1 &&
			       share->path[share->path_sz - 1] == '/')
				share->path[--share->path_sz] = '\0';
		}
		share->create_mask = resp->create_mask;
		share->directory_mask = resp->directory_mask;
		share->force_create_mode = resp->force_create_mode;
		share->force_directory_mode = resp->force_directory_mode;
		share->force_uid = resp->force_uid;
		share->force_gid = resp->force_gid;
		share->time_machine_max_size = resp->time_machine_max_size;
		ret = parse_veto_list(share,
				      KSMBD_SHARE_CONFIG_VETO_LIST(resp),
				      resp->veto_list_sz);
		if (!ret && share->path) {
			if (__ksmbd_override_fsids(work, share)) {
				kill_share(share);
				share = NULL;
				goto out;
			}

			ret = kern_path(share->path, 0, &share->vfs_path);
			ksmbd_revert_fsids(work);
			if (ret) {
				ksmbd_debug(SMB, "failed to access '%s'\n",
					    share->path);
				/* Avoid put_path() */
				kfree(share->path);
				share->path = NULL;
			}
		}
		if (ret || !share->name) {
			kill_share(share);
			share = NULL;
			goto out;
		}
	}

	spin_lock(&shares_table_lock);
	lookup = __share_lookup_rcu(name);
	if (lookup)
		lookup = __get_share_config(lookup);
	if (!lookup) {
		hash_add_rcu(shares_table, &share->hlist,
			     share_name_hash(name));
	} else {
		kill_share(share);
		share = lookup;
	}
	spin_unlock(&shares_table_lock);

out:
	kvfree(resp);
	return share;
}

/**
 * ksmbd_share_config_get() - Look up a share config by name
 * @work: ksmbd work context
 * @name: share name to look up
 *
 * Uses RCU for lock-free read-side lookup of share configs.
 * Falls back to IPC request if the share is not cached.
 *
 * Return: share config with incremented refcount, or NULL
 */
struct ksmbd_share_config *ksmbd_share_config_get(struct ksmbd_work *work,
						  const char *name)
{
	struct ksmbd_share_config *share;

	rcu_read_lock();
	share = __share_lookup_rcu(name);
	if (share)
		share = __get_share_config(share);
	rcu_read_unlock();

	if (share)
		return share;
	return share_config_request(work, name);
}

bool ksmbd_share_veto_filename(struct ksmbd_share_config *share,
			       const char *filename)
{
	struct ksmbd_veto_pattern *p;

	list_for_each_entry(p, &share->veto_list, list) {
		if (match_wildcard(p->pattern, filename))
			return true;
	}
	return false;
}
