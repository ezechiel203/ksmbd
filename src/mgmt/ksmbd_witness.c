// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2024 Samsung Electronics Co., Ltd.
 *
 *   Witness Protocol (MS-SWN) kernel-side state management.
 *   See ksmbd_witness.h for the design overview.
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/idr.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <net/addrconf.h>

#include "glob.h"
#include "ksmbd_witness.h"
#include "transport_ipc.h"

/* Global resource list, protected by witness_lock (read-write semaphore) */
static LIST_HEAD(witness_resources);
static DECLARE_RWSEM(witness_lock);

/* Global registration list for fast lookup by reg_id */
static LIST_HEAD(witness_registrations);
static DEFINE_SPINLOCK(witness_reg_lock);

/* IDA for unique registration IDs */
static DEFINE_IDA(witness_ida);

/* Limit the number of concurrent witness registrations to prevent resource exhaustion */
#define KSMBD_MAX_WITNESS_REGISTRATIONS		256
#define KSMBD_MAX_WITNESS_REGS_PER_SESSION	64

static atomic_t witness_reg_count = ATOMIC_INIT(0);

/* Network device notifier for link state changes */
static struct notifier_block witness_netdev_nb;
static struct workqueue_struct *witness_notify_wq;

/*
 * Work item for deferring netlink notifications out of atomic context.
 * The netdevice notifier callback runs in atomic context, so we queue
 * the actual notification work.
 */
struct witness_notify_work {
	struct work_struct	work;
	char			resource_name[KSMBD_WITNESS_NAME_MAX];
	unsigned int		new_state;
};

/* ------------------------------------------------------------------ */
/* Resource management                                                 */
/* ------------------------------------------------------------------ */

static struct ksmbd_witness_resource *
__witness_resource_lookup_locked(const char *name)
{
	struct ksmbd_witness_resource *res;

	list_for_each_entry(res, &witness_resources, list) {
		if (!strncmp(res->name, name, KSMBD_WITNESS_NAME_MAX))
			return res;
	}
	return NULL;
}

/**
 * ksmbd_witness_resource_add() - add a new monitored resource
 * @name: resource name (IP address string, share name, or node name)
 * @type: resource type (KSMBD_WITNESS_RESOURCE_*)
 *
 * Return: pointer to new resource, or ERR_PTR on failure.
 *         Returns -EEXIST if resource already tracked.
 */
struct ksmbd_witness_resource *
ksmbd_witness_resource_add(const char *name, unsigned int type)
{
	struct ksmbd_witness_resource *res;

	if (!name || !name[0])
		return ERR_PTR(-EINVAL);

	down_write(&witness_lock);
	if (__witness_resource_lookup_locked(name)) {
		up_write(&witness_lock);
		return ERR_PTR(-EEXIST);
	}

	res = kzalloc(sizeof(*res), KSMBD_DEFAULT_GFP);
	if (!res) {
		up_write(&witness_lock);
		return ERR_PTR(-ENOMEM);
	}

	res->type = type;
	res->state = KSMBD_WITNESS_STATE_UNKNOWN;
	strscpy(res->name, name, KSMBD_WITNESS_NAME_MAX);
	INIT_LIST_HEAD(&res->subscribers);
	spin_lock_init(&res->lock);
	list_add_tail(&res->list, &witness_resources);
	up_write(&witness_lock);

	ksmbd_debug(IPC, "witness: resource added: %s type=%u\n", name, type);
	return res;
}

/**
 * ksmbd_witness_resource_del() - remove a monitored resource
 * @name: resource name
 *
 * Removes the resource and unlinks (but does not free) any
 * registrations still attached.  The registrations remain in the
 * global list so they can be cleaned up by the caller.
 */
void ksmbd_witness_resource_del(const char *name)
{
	struct ksmbd_witness_resource *res;
	struct ksmbd_witness_registration *reg, *tmp;

	down_write(&witness_lock);
	res = __witness_resource_lookup_locked(name);
	if (!res) {
		up_write(&witness_lock);
		return;
	}

	/* Detach all subscriber registrations from this resource */
	spin_lock(&res->lock);
	list_for_each_entry_safe(reg, tmp, &res->subscribers, list)
		list_del_init(&reg->list);
	spin_unlock(&res->lock);

	list_del(&res->list);
	up_write(&witness_lock);

	ksmbd_debug(IPC, "witness: resource removed: %s\n", name);
	kfree(res);
}

/**
 * ksmbd_witness_resource_lookup() - check whether a resource exists
 * @name: resource name
 *
 * Returns true/false rather than a raw pointer so that callers
 * cannot accidentally dereference a stale, unrefcounted pointer.
 * The check is serialised under witness_lock (read side) so the
 * result is only a point-in-time snapshot.
 *
 * Return: true if a resource with @name exists, false otherwise.
 */
bool ksmbd_witness_resource_lookup(const char *name)
{
	bool found;

	down_read(&witness_lock);
	found = __witness_resource_lookup_locked(name) != NULL;
	up_read(&witness_lock);
	return found;
}

/* ------------------------------------------------------------------ */
/* Registration management                                             */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_witness_register() - register a client for notifications
 * @client_name: the client computer name
 * @resource_name: the resource being monitored
 * @type: resource type (KSMBD_WITNESS_RESOURCE_*)
 * @reg_id_out: on success, filled with the unique registration ID
 *
 * If the named resource does not yet exist, it is created
 * automatically with UNKNOWN state.
 *
 * Return: 0 on success, negative errno on failure.
 */
int ksmbd_witness_register(const char *client_name,
			   const char *resource_name,
			   unsigned int type,
			   u64 session_id,
			   u32 *reg_id_out)
{
	struct ksmbd_witness_registration *reg;
	struct ksmbd_witness_resource *res;
	int id;

	if (!client_name || !resource_name)
		return -EINVAL;

	/* Enforce global registration limit */
	if (atomic_inc_return(&witness_reg_count) > KSMBD_MAX_WITNESS_REGISTRATIONS) {
		atomic_dec(&witness_reg_count);
		return -ENOSPC;
	}

	reg = kzalloc(sizeof(*reg), KSMBD_DEFAULT_GFP);
	if (!reg) {
		atomic_dec(&witness_reg_count);
		return -ENOMEM;
	}

	id = ida_alloc_min(&witness_ida, 1, KSMBD_DEFAULT_GFP);
	if (id < 0) {
		kfree(reg);
		atomic_dec(&witness_reg_count);
		return id;
	}

	reg->reg_id = (u32)id;
	reg->type = type;
	reg->session_id = session_id;
	strscpy(reg->client_name, client_name, KSMBD_WITNESS_NAME_MAX);
	strscpy(reg->resource_name, resource_name, KSMBD_WITNESS_NAME_MAX);
	INIT_LIST_HEAD(&reg->list);
	INIT_LIST_HEAD(&reg->global_list);

	/* Look up or auto-create the resource */
	down_write(&witness_lock);
	res = __witness_resource_lookup_locked(resource_name);
	if (!res) {
		up_write(&witness_lock);
		res = ksmbd_witness_resource_add(resource_name, type);
		if (IS_ERR(res)) {
			/*
			 * EEXIST means a concurrent add raced with us.
			 * Re-lookup under the lock.
			 */
			if (PTR_ERR(res) != -EEXIST) {
				ida_free(&witness_ida, id);
				kfree(reg);
				atomic_dec(&witness_reg_count);
				return PTR_ERR(res);
			}
			down_write(&witness_lock);
			res = __witness_resource_lookup_locked(resource_name);
			if (!res) {
				up_write(&witness_lock);
				ida_free(&witness_ida, id);
				kfree(reg);
				atomic_dec(&witness_reg_count);
				return -ENOENT;
			}
		} else {
			down_write(&witness_lock);
		}
	}

	/* Attach registration to resource subscriber list */
	spin_lock(&res->lock);
	list_add_tail(&reg->list, &res->subscribers);
	spin_unlock(&res->lock);
	up_write(&witness_lock);

	/*
	 * M-01: Per-session count check and insertion are atomic under
	 * witness_reg_lock.  This prevents two concurrent calls at the
	 * per-session limit boundary from both passing the check and both
	 * inserting (TOCTOU race).  The check and list_add_tail happen in
	 * the same critical section so no other thread can sneak in between.
	 */
	spin_lock(&witness_reg_lock);
	if (session_id) {
		struct ksmbd_witness_registration *r;
		int sess_count = 0;

		list_for_each_entry(r, &witness_registrations, global_list) {
			if (r->session_id == session_id &&
			    ++sess_count >= KSMBD_MAX_WITNESS_REGS_PER_SESSION) {
				spin_unlock(&witness_reg_lock);
				/*
				 * Undo the resource subscription made above.
				 * witness_lock was already released; re-acquire
				 * it to remove reg from the subscriber list.
				 * res is still valid because reg holds a
				 * subscriber slot keeping res alive.
				 */
				down_write(&witness_lock);
				spin_lock(&res->lock);
				list_del_init(&reg->list);
				spin_unlock(&res->lock);
				up_write(&witness_lock);
				ida_free(&witness_ida, id);
				kfree(reg);
				atomic_dec(&witness_reg_count);
				pr_warn_ratelimited("witness: session %llu exceeded max registrations (%d)\n",
						    session_id,
						    KSMBD_MAX_WITNESS_REGS_PER_SESSION);
				return -ENOSPC;
			}
		}
	}
	list_add_tail(&reg->global_list, &witness_registrations);
	spin_unlock(&witness_reg_lock);

	*reg_id_out = reg->reg_id;
	ksmbd_debug(IPC, "witness: registered client=%s resource=%s id=%u\n",
		    client_name, resource_name, reg->reg_id);
	return 0;
}

/**
 * ksmbd_witness_unregister() - unregister a client
 * @reg_id: the registration ID from ksmbd_witness_register()
 *
 * Return: 0 on success, -ENOENT if not found.
 */
int ksmbd_witness_unregister(u32 reg_id)
{
	struct ksmbd_witness_registration *reg, *found = NULL;

	spin_lock(&witness_reg_lock);
	list_for_each_entry(reg, &witness_registrations, global_list) {
		if (reg->reg_id == reg_id) {
			found = reg;
			list_del_init(&found->global_list);
			break;
		}
	}
	spin_unlock(&witness_reg_lock);

	if (!found)
		return -ENOENT;

	/*
	 * Remove from the resource subscriber list.  The list_del_init
	 * in resource_del may have already detached us, which is fine
	 * because list_del on an already-initialized empty node is safe.
	 */
	down_write(&witness_lock);
	if (!list_empty(&found->list)) {
		struct ksmbd_witness_resource *res;

		res = __witness_resource_lookup_locked(found->resource_name);
		if (res) {
			spin_lock(&res->lock);
			list_del_init(&found->list);
			spin_unlock(&res->lock);
		}
	}
	up_write(&witness_lock);

	ksmbd_debug(IPC, "witness: unregistered id=%u client=%s\n",
		    reg_id, found->client_name);

	ida_free(&witness_ida, found->reg_id);
	kfree(found);
	atomic_dec(&witness_reg_count);
	return 0;
}

/**
 * ksmbd_witness_unregister_session() - remove all registrations for a session
 * @session_id: the session ID whose registrations should be cleaned up
 *
 * Called during session teardown to prevent leaked registrations.
 * Iterates the global registration list and removes all entries
 * belonging to the given session.
 */
void ksmbd_witness_unregister_session(u64 session_id)
{
	struct ksmbd_witness_registration *reg, *tmp;
	LIST_HEAD(to_free);

	if (!session_id)
		return;

	/* Collect matching registrations from the global list */
	spin_lock(&witness_reg_lock);
	list_for_each_entry_safe(reg, tmp, &witness_registrations,
				 global_list) {
		if (reg->session_id == session_id) {
			list_del_init(&reg->global_list);
			list_add(&reg->global_list, &to_free);
		}
	}
	spin_unlock(&witness_reg_lock);

	/* Remove from resource subscriber lists and free */
	list_for_each_entry_safe(reg, tmp, &to_free, global_list) {
		down_write(&witness_lock);
		if (!list_empty(&reg->list)) {
			struct ksmbd_witness_resource *res;

			res = __witness_resource_lookup_locked(
				reg->resource_name);
			if (res) {
				spin_lock(&res->lock);
				list_del_init(&reg->list);
				spin_unlock(&res->lock);
			}
		}
		up_write(&witness_lock);

		ksmbd_debug(IPC,
			    "witness: session cleanup id=%u client=%s sess=%llu\n",
			    reg->reg_id, reg->client_name, session_id);
		list_del(&reg->global_list);
		ida_free(&witness_ida, reg->reg_id);
		kfree(reg);
		atomic_dec(&witness_reg_count);
	}
}

/**
 * ksmbd_witness_registration_count() - count active registrations
 *
 * Return: number of active registrations.
 */
int ksmbd_witness_registration_count(void)
{
	struct ksmbd_witness_registration *reg;
	int count = 0;

	spin_lock(&witness_reg_lock);
	list_for_each_entry(reg, &witness_registrations, global_list)
		count++;
	spin_unlock(&witness_reg_lock);
	return count;
}

/* ------------------------------------------------------------------ */
/* State change notification                                           */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_witness_notify_state_change() - update resource state and notify
 * @resource_name: the resource whose state changed
 * @new_state: the new state (KSMBD_WITNESS_STATE_*)
 *
 * Updates the resource state and sends a netlink notification to
 * userspace for each subscriber registration.  Userspace (ksmbd.mountd)
 * will then relay this via the DCE/RPC WitnessrAsyncNotify response.
 *
 * The subscriber list is snapshot under spinlock, then notifications
 * are sent without any lock held to avoid sleeping under spinlock
 * (kvzalloc with GFP_KERNEL in the IPC path).
 *
 * Return: 0 on success, negative errno on failure.
 */
int ksmbd_witness_notify_state_change(const char *resource_name,
				      unsigned int new_state)
{
	struct ksmbd_witness_resource *res;
	struct ksmbd_witness_registration *reg;
	u32 *reg_ids = NULL;
	int count = 0, capacity = 0, i;
	int ret = 0;

	/* Acquire write lock because we modify res->state */
	down_write(&witness_lock);
	res = __witness_resource_lookup_locked(resource_name);
	if (!res) {
		up_write(&witness_lock);
		return -ENOENT;
	}

	res->state = new_state;

	/*
	 * Snapshot the subscriber reg_ids under the spinlock so we can
	 * drop all locks before doing the allocating IPC sends.
	 */
	spin_lock(&res->lock);
	list_for_each_entry(reg, &res->subscribers, list)
		capacity++;
	spin_unlock(&res->lock);

	up_write(&witness_lock);

	if (!capacity)
		return 0;

	reg_ids = kvzalloc(capacity * sizeof(*reg_ids), KSMBD_DEFAULT_GFP);
	if (!reg_ids)
		return -ENOMEM;

	/* Re-acquire locks to snapshot the actual IDs */
	down_read(&witness_lock);
	res = __witness_resource_lookup_locked(resource_name);
	if (!res) {
		up_read(&witness_lock);
		kvfree(reg_ids);
		return -ENOENT;
	}

	spin_lock(&res->lock);
	list_for_each_entry(reg, &res->subscribers, list) {
		if (count >= capacity)
			break;
		reg_ids[count++] = reg->reg_id;
	}
	spin_unlock(&res->lock);
	up_read(&witness_lock);

	/* Now send notifications without any lock held */
	for (i = 0; i < count; i++) {
		ksmbd_debug(IPC,
			    "witness: notifying reg_id=%u resource=%s state=%u\n",
			    reg_ids[i], resource_name, new_state);
		ret = ksmbd_ipc_witness_notify(reg_ids[i],
					       resource_name,
					       new_state);
		if (ret)
			pr_err("witness: failed to notify reg_id=%u: %d\n",
			       reg_ids[i], ret);
	}

	kvfree(reg_ids);
	return ret;
}

/* ------------------------------------------------------------------ */
/* Network device notifier                                             */
/* ------------------------------------------------------------------ */

static void witness_notify_work_fn(struct work_struct *work)
{
	struct witness_notify_work *nw =
		container_of(work, struct witness_notify_work, work);

	ksmbd_witness_notify_state_change(nw->resource_name, nw->new_state);
	kfree(nw);
}

/**
 * witness_netdev_event() - netdevice notifier callback
 *
 * Monitors NETDEV_UP and NETDEV_DOWN events to detect interface
 * state changes.  The callback runs in atomic context so the actual
 * notification to userspace is deferred via a workqueue.
 */
static int witness_netdev_event(struct notifier_block *nb,
				unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct witness_notify_work *nw;
	struct in_device *in_dev;
	const struct in_ifaddr *ifa;
	unsigned int new_state;

	if (event != NETDEV_UP && event != NETDEV_DOWN)
		return NOTIFY_DONE;

	new_state = (event == NETDEV_UP) ?
		KSMBD_WITNESS_STATE_AVAILABLE :
		KSMBD_WITNESS_STATE_UNAVAILABLE;

	/*
	 * For each IPv4 address on this device, check whether we are
	 * tracking it as a witness resource and, if so, queue a state
	 * change notification.
	 */
	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev) {
		rcu_read_unlock();
		return NOTIFY_DONE;
	}

	in_dev_for_each_ifa_rcu(ifa, in_dev) {
		char addr_str[sizeof("255.255.255.255")];

		snprintf(addr_str, sizeof(addr_str), "%pI4",
			 &ifa->ifa_address);

		/* Quick check without heavy locking */
		if (!ksmbd_witness_resource_lookup(addr_str))
			continue;

		nw = kzalloc(sizeof(*nw), GFP_ATOMIC);
		if (!nw)
			continue;

		strscpy(nw->resource_name, addr_str,
			KSMBD_WITNESS_NAME_MAX);
		nw->new_state = new_state;
		INIT_WORK(&nw->work, witness_notify_work_fn);
		queue_work(witness_notify_wq, &nw->work);

		ksmbd_debug(IPC,
			    "witness: netdev %s %s -> queued state=%u\n",
			    dev->name, addr_str, new_state);
	}
	rcu_read_unlock();

	return NOTIFY_DONE;
}

/* ------------------------------------------------------------------ */
/* Module init / exit                                                   */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_witness_init() - initialise the witness subsystem
 *
 * Called during ksmbd module load.
 * Return: 0 on success, negative errno on failure.
 */
int ksmbd_witness_init(void)
{
	witness_notify_wq = alloc_workqueue("ksmbd-witness", WQ_UNBOUND, 0);
	if (!witness_notify_wq)
		return -ENOMEM;

	witness_netdev_nb.notifier_call = witness_netdev_event;
	register_netdevice_notifier(&witness_netdev_nb);

	pr_info("ksmbd: witness protocol support initialised\n");
	return 0;
}

/**
 * ksmbd_witness_exit() - tear down the witness subsystem
 *
 * Called during ksmbd module unload.  Frees all resources and
 * registrations.
 */
void ksmbd_witness_exit(void)
{
	struct ksmbd_witness_registration *reg, *rtmp;
	struct ksmbd_witness_resource *res, *tmp;

	unregister_netdevice_notifier(&witness_netdev_nb);

	if (witness_notify_wq) {
		flush_workqueue(witness_notify_wq);
		destroy_workqueue(witness_notify_wq);
		witness_notify_wq = NULL;
	}

	/* Free all registrations */
	spin_lock(&witness_reg_lock);
	list_for_each_entry_safe(reg, rtmp, &witness_registrations,
				 global_list) {
		list_del(&reg->global_list);
		ida_free(&witness_ida, reg->reg_id);
		kfree(reg);
	}
	spin_unlock(&witness_reg_lock);

	/* Free all resources */
	down_write(&witness_lock);
	list_for_each_entry_safe(res, tmp, &witness_resources, list) {
		list_del(&res->list);
		kfree(res);
	}
	up_write(&witness_lock);

	pr_info("ksmbd: witness protocol support removed\n");
}
