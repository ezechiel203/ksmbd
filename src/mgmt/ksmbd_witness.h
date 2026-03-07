/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2024 Samsung Electronics Co., Ltd.
 *
 *   Witness Protocol (MS-SWN) kernel-side state management.
 *
 *   The Service Witness Protocol enables SMB3 clients to receive
 *   cluster failover notifications.  The actual DCE/RPC witness
 *   service (ncacn_ip_tcp) runs in userspace (ksmbd.mountd);
 *   the kernel side tracked here provides:
 *     - Cluster/interface resource state tracking
 *     - Network device event monitoring (link up/down)
 *     - Netlink notifications to userspace on state changes
 *
 *   Userspace contract:
 *     ksmbd.mountd must handle the following netlink events:
 *       KSMBD_EVENT_WITNESS_REGISTER   - client registration
 *       KSMBD_EVENT_WITNESS_UNREGISTER - client unregistration
 *       KSMBD_EVENT_WITNESS_NOTIFY     - state change notification
 *       KSMBD_EVENT_WITNESS_IFACE_LIST - interface list query
 *     ksmbd.mountd translates these into the DCE/RPC witness
 *     calls (WitnessrRegister, WitnessrUnRegister,
 *     WitnessrAsyncNotify, WitnessrGetInterfaceList) per MS-SWN.
 */

#ifndef __KSMBD_WITNESS_H__
#define __KSMBD_WITNESS_H__

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/idr.h>
#include <linux/notifier.h>
#include <linux/workqueue.h>

#include "ksmbd_netlink.h"

/* Maximum length for witness resource names (IP, share, node) */
#define KSMBD_WITNESS_NAME_MAX		KSMBD_WITNESS_NAME_MAX_NL

/*
 * Witness resource state and type values are defined in ksmbd_netlink.h
 * as part of the kernel-userspace ABI:
 *   KSMBD_WITNESS_STATE_AVAILABLE     (0)
 *   KSMBD_WITNESS_STATE_UNAVAILABLE   (1)
 *   KSMBD_WITNESS_STATE_UNKNOWN       (0xFF)
 *   KSMBD_WITNESS_RESOURCE_IP         (0)
 *   KSMBD_WITNESS_RESOURCE_SHARE      (1)
 *   KSMBD_WITNESS_RESOURCE_NODE       (2)
 */

/*
 * A monitored resource (network interface, share, or node).
 * Protected by its own spinlock for per-resource subscriber list access.
 */
struct ksmbd_witness_resource {
	unsigned int		type;		/* KSMBD_WITNESS_RESOURCE_* */
	unsigned int		state;		/* KSMBD_WITNESS_STATE_* */
	char			name[KSMBD_WITNESS_NAME_MAX];
	struct list_head	list;		/* global resource list */
	struct list_head	subscribers;	/* registrations watching this */
	spinlock_t		lock;		/* protects subscribers list */
};

/*
 * A client registration for witness notifications.
 * Created by userspace via KSMBD_EVENT_WITNESS_REGISTER,
 * removed via KSMBD_EVENT_WITNESS_UNREGISTER.
 */
struct ksmbd_witness_registration {
	u32			reg_id;		/* unique registration ID */
	u64			session_id;	/* owning session ID, 0 if none */
	char			client_name[KSMBD_WITNESS_NAME_MAX];
	char			resource_name[KSMBD_WITNESS_NAME_MAX];
	unsigned int		type;		/* KSMBD_WITNESS_RESOURCE_* */
	struct list_head	list;		/* link in resource->subscribers */
	struct list_head	global_list;	/* link in global reg list */
};

/* Module-level init/exit */
int ksmbd_witness_init(void);
void ksmbd_witness_exit(void);

/* Resource management */
struct ksmbd_witness_resource *
ksmbd_witness_resource_add(const char *name, unsigned int type);
void ksmbd_witness_resource_del(const char *name);
bool ksmbd_witness_resource_lookup(const char *name);

/* Registration management */
int ksmbd_witness_register(const char *client_name,
			   const char *resource_name,
			   unsigned int type,
			   u64 session_id,
			   u32 *reg_id_out);
int ksmbd_witness_unregister(u32 reg_id);
void ksmbd_witness_unregister_session(u64 session_id);

/* State change notification */
int ksmbd_witness_notify_state_change(const char *resource_name,
				      unsigned int new_state);

/* Number of active registrations (for diagnostics) */
int ksmbd_witness_registration_count(void);

#endif /* __KSMBD_WITNESS_H__ */
