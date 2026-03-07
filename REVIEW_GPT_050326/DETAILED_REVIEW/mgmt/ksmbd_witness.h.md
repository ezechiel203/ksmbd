# Line-by-line Review: src/mgmt/ksmbd_witness.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2024 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   Witness Protocol (MS-SWN) kernel-side state management.`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *   The Service Witness Protocol enables SMB3 clients to receive`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   cluster failover notifications.  The actual DCE/RPC witness`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   service (ncacn_ip_tcp) runs in userspace (ksmbd.mountd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   the kernel side tracked here provides:`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *     - Cluster/interface resource state tracking`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *     - Network device event monitoring (link up/down)`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *     - Netlink notifications to userspace on state changes`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *   Userspace contract:`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` *     ksmbd.mountd must handle the following netlink events:`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` *       KSMBD_EVENT_WITNESS_REGISTER   - client registration`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` *       KSMBD_EVENT_WITNESS_UNREGISTER - client unregistration`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` *       KSMBD_EVENT_WITNESS_NOTIFY     - state change notification`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` *       KSMBD_EVENT_WITNESS_IFACE_LIST - interface list query`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` *     ksmbd.mountd translates these into the DCE/RPC witness`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` *     calls (WitnessrRegister, WitnessrUnRegister,`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` *     WitnessrAsyncNotify, WitnessrGetInterfaceList) per MS-SWN.`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#ifndef __KSMBD_WITNESS_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define __KSMBD_WITNESS_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include <linux/idr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include <linux/notifier.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include <linux/workqueue.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "ksmbd_netlink.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `/* Maximum length for witness resource names (IP, share, node) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define KSMBD_WITNESS_NAME_MAX		KSMBD_WITNESS_NAME_MAX_NL`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * Witness resource state and type values are defined in ksmbd_netlink.h`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * as part of the kernel-userspace ABI:`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` *   KSMBD_WITNESS_STATE_AVAILABLE     (0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` *   KSMBD_WITNESS_STATE_UNAVAILABLE   (1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` *   KSMBD_WITNESS_STATE_UNKNOWN       (0xFF)`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` *   KSMBD_WITNESS_RESOURCE_IP         (0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` *   KSMBD_WITNESS_RESOURCE_SHARE      (1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` *   KSMBD_WITNESS_RESOURCE_NODE       (2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` * A monitored resource (network interface, share, or node).`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` * Protected by its own spinlock for per-resource subscriber list access.`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `struct ksmbd_witness_resource {`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	unsigned int		type;		/* KSMBD_WITNESS_RESOURCE_* */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	unsigned int		state;		/* KSMBD_WITNESS_STATE_* */`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	char			name[KSMBD_WITNESS_NAME_MAX];`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	struct list_head	list;		/* global resource list */`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	struct list_head	subscribers;	/* registrations watching this */`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	spinlock_t		lock;		/* protects subscribers list */`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * A client registration for witness notifications.`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` * Created by userspace via KSMBD_EVENT_WITNESS_REGISTER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` * removed via KSMBD_EVENT_WITNESS_UNREGISTER.`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `struct ksmbd_witness_registration {`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	u32			reg_id;		/* unique registration ID */`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	u64			session_id;	/* owning session ID, 0 if none */`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	char			client_name[KSMBD_WITNESS_NAME_MAX];`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	char			resource_name[KSMBD_WITNESS_NAME_MAX];`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	unsigned int		type;		/* KSMBD_WITNESS_RESOURCE_* */`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	struct list_head	list;		/* link in resource->subscribers */`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	struct list_head	global_list;	/* link in global reg list */`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `/* Module-level init/exit */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `int ksmbd_witness_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `void ksmbd_witness_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `/* Resource management */`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `struct ksmbd_witness_resource *`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `ksmbd_witness_resource_add(const char *name, unsigned int type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `void ksmbd_witness_resource_del(const char *name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `bool ksmbd_witness_resource_lookup(const char *name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `/* Registration management */`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `int ksmbd_witness_register(const char *client_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `			   const char *resource_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `			   unsigned int type,`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `			   u64 session_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `			   u32 *reg_id_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `int ksmbd_witness_unregister(u32 reg_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `void ksmbd_witness_unregister_session(u64 session_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `/* State change notification */`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `int ksmbd_witness_notify_state_change(const char *resource_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `				      unsigned int new_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `/* Number of active registrations (for diagnostics) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `int ksmbd_witness_registration_count(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `#endif /* __KSMBD_WITNESS_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
