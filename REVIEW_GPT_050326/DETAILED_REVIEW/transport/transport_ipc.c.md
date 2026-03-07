# Line-by-line Review: src/transport/transport_ipc.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#include <linux/jhash.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/rwsem.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/mutex.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/wait.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/hashtable.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <net/net_namespace.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <net/genetlink.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/socket.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/workqueue.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/netdevice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/inetdevice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "mgmt/user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "mgmt/ksmbd_ida.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "mgmt/ksmbd_witness.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "transport_tcp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "transport_rdma.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#define IPC_WAIT_TIMEOUT	(2 * HZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#define IPC_MSG_HASH_BITS	3`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `static DEFINE_HASHTABLE(ipc_msg_table, IPC_MSG_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `static DECLARE_RWSEM(ipc_msg_table_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `static DEFINE_MUTEX(startup_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `static DEFINE_IDA(ipc_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `static unsigned int ksmbd_tools_pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `static bool ksmbd_ipc_validate_version(struct genl_info *m)`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	if (m->genlhdr->version != KSMBD_GENL_VERSION) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [ERROR_PATH|] `		pr_err("%s. ksmbd: %d, kernel module: %d. %s.\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00049 [NONE] `		       "Daemon and kernel module version mismatch",`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `		       m->genlhdr->version,`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `		       KSMBD_GENL_VERSION,`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `		       "User-space ksmbd should terminate");`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `struct ksmbd_ipc_msg {`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	unsigned int		type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	unsigned int		sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	unsigned char		payload[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `struct ipc_msg_table_entry {`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	unsigned int		handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	unsigned int		type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	wait_queue_head_t	wait;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	struct hlist_node	ipc_table_hlist;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	void			*response;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	unsigned int		msg_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `static struct delayed_work ipc_timer_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `static int handle_startup_event(struct sk_buff *skb, struct genl_info *info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `static int handle_unsupported_event(struct sk_buff *skb, struct genl_info *info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `static int handle_generic_event(struct sk_buff *skb, struct genl_info *info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `static int handle_witness_register_event(struct sk_buff *skb,`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `					 struct genl_info *info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `static int handle_witness_unregister_event(struct sk_buff *skb,`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `					   struct genl_info *info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `static int handle_witness_iface_list_event(struct sk_buff *skb,`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `					   struct genl_info *info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `static int ksmbd_ipc_heartbeat_request(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `static const struct nla_policy ksmbd_nl_policy[KSMBD_EVENT_MAX + 1] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	[KSMBD_EVENT_UNSPEC] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `		.len = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	[KSMBD_EVENT_HEARTBEAT_REQUEST] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `		.len = sizeof(struct ksmbd_heartbeat),`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	[KSMBD_EVENT_STARTING_UP] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `		.len = sizeof(struct ksmbd_startup_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	[KSMBD_EVENT_SHUTTING_DOWN] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		.len = sizeof(struct ksmbd_shutdown_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	[KSMBD_EVENT_LOGIN_REQUEST] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `		.len = sizeof(struct ksmbd_login_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	[KSMBD_EVENT_LOGIN_RESPONSE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `		.len = sizeof(struct ksmbd_login_response),`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	[KSMBD_EVENT_SHARE_CONFIG_REQUEST] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `		.len = sizeof(struct ksmbd_share_config_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	[KSMBD_EVENT_SHARE_CONFIG_RESPONSE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `		.len = sizeof(struct ksmbd_share_config_response),`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	[KSMBD_EVENT_TREE_CONNECT_REQUEST] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `		.len = sizeof(struct ksmbd_tree_connect_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	[KSMBD_EVENT_TREE_CONNECT_RESPONSE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `		.len = sizeof(struct ksmbd_tree_connect_response),`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	[KSMBD_EVENT_TREE_DISCONNECT_REQUEST] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `		.len = sizeof(struct ksmbd_tree_disconnect_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	[KSMBD_EVENT_LOGOUT_REQUEST] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `		.len = sizeof(struct ksmbd_logout_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	[KSMBD_EVENT_RPC_REQUEST] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	[KSMBD_EVENT_RPC_RESPONSE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	[KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	[KSMBD_EVENT_SPNEGO_AUTHEN_RESPONSE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	[KSMBD_EVENT_LOGIN_REQUEST_EXT] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `		.len = sizeof(struct ksmbd_login_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	[KSMBD_EVENT_LOGIN_RESPONSE_EXT] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `		.len = sizeof(struct ksmbd_login_response_ext),`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	[KSMBD_EVENT_WITNESS_REGISTER] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `		.len = sizeof(struct ksmbd_witness_register_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	[KSMBD_EVENT_WITNESS_REGISTER_RESPONSE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `		.len = sizeof(struct ksmbd_witness_register_response),`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	[KSMBD_EVENT_WITNESS_UNREGISTER] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `		.len = sizeof(struct ksmbd_witness_unregister_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	[KSMBD_EVENT_WITNESS_UNREGISTER_RESPONSE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `		.len = sizeof(struct ksmbd_witness_unregister_response),`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	[KSMBD_EVENT_WITNESS_NOTIFY] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `		.len = sizeof(struct ksmbd_witness_notify_msg),`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	[KSMBD_EVENT_WITNESS_IFACE_LIST] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `		.len = sizeof(struct ksmbd_witness_iface_list_request),`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	[KSMBD_EVENT_WITNESS_IFACE_LIST_RESPONSE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `		.type = NLA_BINARY,`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `		.len = KSMBD_IPC_MAX_PAYLOAD,`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `static struct genl_ops ksmbd_genl_ops[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `		.cmd	= KSMBD_EVENT_UNSPEC,`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `		.cmd	= KSMBD_EVENT_HEARTBEAT_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `		.cmd	= KSMBD_EVENT_STARTING_UP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `		.doit	= handle_startup_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `		.cmd	= KSMBD_EVENT_SHUTTING_DOWN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `		.cmd	= KSMBD_EVENT_LOGIN_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `		.cmd	= KSMBD_EVENT_LOGIN_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		.doit	= handle_generic_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `		.cmd	= KSMBD_EVENT_SHARE_CONFIG_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `		.cmd	= KSMBD_EVENT_SHARE_CONFIG_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `		.doit	= handle_generic_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `		.cmd	= KSMBD_EVENT_TREE_CONNECT_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `		.cmd	= KSMBD_EVENT_TREE_CONNECT_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `		.doit	= handle_generic_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		.cmd	= KSMBD_EVENT_TREE_DISCONNECT_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `		.cmd	= KSMBD_EVENT_LOGOUT_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		.cmd	= KSMBD_EVENT_RPC_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		.cmd	= KSMBD_EVENT_RPC_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `		.doit	= handle_generic_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `		.cmd	= KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `		.cmd	= KSMBD_EVENT_SPNEGO_AUTHEN_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		.doit	= handle_generic_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `		.cmd	= KSMBD_EVENT_LOGIN_REQUEST_EXT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `		.cmd	= KSMBD_EVENT_LOGIN_RESPONSE_EXT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `		.doit	= handle_generic_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `		.cmd	= KSMBD_EVENT_WITNESS_REGISTER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `		.doit	= handle_witness_register_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `		.cmd	= KSMBD_EVENT_WITNESS_REGISTER_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		.cmd	= KSMBD_EVENT_WITNESS_UNREGISTER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		.doit	= handle_witness_unregister_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `		.cmd	= KSMBD_EVENT_WITNESS_UNREGISTER_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `		.cmd	= KSMBD_EVENT_WITNESS_NOTIFY,`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `		.cmd	= KSMBD_EVENT_WITNESS_IFACE_LIST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `		.doit	= handle_witness_iface_list_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `		.cmd	= KSMBD_EVENT_WITNESS_IFACE_LIST_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `		.doit	= handle_unsupported_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `		.flags	= GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `static struct genl_family ksmbd_genl_family = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	.name		= KSMBD_GENL_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	.version	= KSMBD_GENL_VERSION,`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	.hdrsize	= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	.maxattr	= KSMBD_EVENT_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	.netnsok	= true,`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	.module		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	.ops		= ksmbd_genl_ops,`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	.n_ops		= ARRAY_SIZE(ksmbd_genl_ops),`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	.resv_start_op	= KSMBD_EVENT_WITNESS_IFACE_LIST_RESPONSE + 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `static void ksmbd_nl_init_fixup(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	for (i = 0; i < ARRAY_SIZE(ksmbd_genl_ops); i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `		ksmbd_genl_ops[i].validate = GENL_DONT_VALIDATE_STRICT |`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `						GENL_DONT_VALIDATE_DUMP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	ksmbd_genl_family.policy = ksmbd_nl_policy;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `static int rpc_context_flags(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	if (user_guest(sess->user))`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `		return KSMBD_RPC_RESTRICTED_CONTEXT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `static void ipc_update_last_active(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	if (server_conf.ipc_timeout)`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `		server_conf.ipc_last_active = jiffies;`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `static struct ksmbd_ipc_msg *ipc_msg_alloc(size_t sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	size_t msg_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [MEM_BOUNDS|] `	if (check_add_overflow(sz, sizeof(struct ksmbd_ipc_msg), &msg_sz))`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00334 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [MEM_BOUNDS|] `	msg = kvzalloc(msg_sz, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00337 [NONE] `	if (msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `		msg->sz = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	return msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `static void ipc_msg_free(struct ksmbd_ipc_msg *msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `	kvfree(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `static void ipc_msg_handle_free(int handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	if (handle >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		ksmbd_release_id(&ipc_ida, handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `static int handle_response(int type, void *payload, size_t sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	unsigned int handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	struct ipc_msg_table_entry *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	int ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	/* Prevent 4-byte read beyond declared payload size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	if (sz < sizeof(unsigned int))`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00362 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	handle = *(unsigned int *)payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	ipc_update_last_active();`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	 * handle_response mutates table entries (response pointer/size),`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	 * therefore it must run under write lock.`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [LOCK|] `	down_write(&ipc_msg_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00371 [NONE] `	hash_for_each_possible(ipc_msg_table, entry, ipc_table_hlist, handle) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `		if (handle != entry->handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `		 * Response message type value should be equal to`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `		 * request message type + 1.`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `		if (entry->type + 1 != type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [ERROR_PATH|] `			pr_err("Waiting for IPC type %d, got %d. Ignore.\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00381 [NONE] `			       entry->type + 1, type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `			ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `		if (entry->response) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [ERROR_PATH|] `			pr_warn_ratelimited("Duplicate IPC response for handle %u type %d ignored\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00388 [NONE] `					    handle, type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `			ret = -EALREADY;`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [MEM_BOUNDS|] `		entry->response = kvzalloc(sz, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00394 [NONE] `		if (!entry->response) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `			ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [MEM_BOUNDS|] `		memcpy(entry->response, payload, sz);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00400 [NONE] `		entry->msg_sz = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `		wake_up_interruptible(&entry->wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `		ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [LOCK|] `	up_write(&ipc_msg_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `static int ipc_server_config_on_startup(struct ksmbd_startup_request *req)`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	unsigned long ipc_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	ksmbd_set_fd_limit(req->file_max);`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	server_conf.flags = req->flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	server_conf.signing = req->signing;`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	server_conf.tcp_port = req->tcp_port;`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	if (check_mul_overflow((unsigned long)req->ipc_timeout,`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `			       (unsigned long)HZ, &ipc_timeout)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00423 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `	server_conf.ipc_timeout = ipc_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	if (check_mul_overflow(req->deadtime, SMB_ECHO_INTERVAL,`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `					&server_conf.deadtime)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00429 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	server_conf.share_fake_fscaps = req->share_fake_fscaps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	ksmbd_init_domain(req->sub_auth);`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	if (req->smb2_max_read)`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `		init_smb2_max_read_size(req->smb2_max_read);`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	if (req->smb2_max_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `		init_smb2_max_write_size(req->smb2_max_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	if (req->smb2_max_trans)`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `		init_smb2_max_trans_size(req->smb2_max_trans);`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	if (req->smb2_max_credits) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `		init_smb2_max_credits(req->smb2_max_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `		server_conf.max_inflight_req =`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `			req->smb2_max_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `	if (req->smbd_max_io_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `		init_smbd_max_io_size(req->smbd_max_io_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `	if (req->max_connections)`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `		server_conf.max_connections = req->max_connections;`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `	if (req->max_ip_connections)`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `		server_conf.max_ip_connections = req->max_ip_connections;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	ret = ksmbd_set_netbios_name(req->netbios_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	ret |= ksmbd_set_server_string(req->server_string);`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	ret |= ksmbd_set_work_group(req->work_group);`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	server_conf.bind_interfaces_only = req->bind_interfaces_only;`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [MEM_BOUNDS|] `	strscpy(server_conf.fruit_model, req->fruit_model,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00458 [NONE] `		sizeof(server_conf.fruit_model));`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	ret |= ksmbd_tcp_set_interfaces(KSMBD_STARTUP_CONFIG_INTERFACES(req),`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `					req->ifc_list_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [ERROR_PATH|] `		pr_err("Server configuration error: %s %s %s\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00464 [NONE] `		       req->netbios_name, req->server_string,`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `		       req->work_group);`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	if (req->min_prot[0]) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `		ret = ksmbd_lookup_protocol_idx(req->min_prot);`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `		if (ret >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `			server_conf.min_protocol = ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	if (req->max_prot[0]) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `		ret = ksmbd_lookup_protocol_idx(req->max_prot);`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `		if (ret >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `			server_conf.max_protocol = ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `	if (server_conf.ipc_timeout)`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `		schedule_delayed_work(&ipc_timer_work, server_conf.ipc_timeout);`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `static int handle_startup_event(struct sk_buff *skb, struct genl_info *info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	if (!netlink_capable(skb, CAP_NET_ADMIN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [ERROR_PATH|] `		return -EPERM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	if (!ksmbd_ipc_validate_version(info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	if (!info->attrs[KSMBD_EVENT_STARTING_UP])`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [LOCK|] `	mutex_lock(&startup_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00499 [NONE] `	if (!ksmbd_server_configurable()) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [LOCK|] `		mutex_unlock(&startup_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00501 [ERROR_PATH|] `		pr_err("Server reset is in progress, can't start daemon\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00502 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00503 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	if (ksmbd_tools_pid) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `		if (ksmbd_ipc_heartbeat_request() == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `			ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00509 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [ERROR_PATH|] `		pr_err("Reconnect to a new user space daemon\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00512 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `		struct ksmbd_startup_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `		req = nla_data(info->attrs[info->genlhdr->cmd]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `		ret = ipc_server_config_on_startup(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00519 [NONE] `		server_queue_ctrl_init_work();`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	ksmbd_tools_pid = info->snd_portid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	ipc_update_last_active();`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [LOCK|] `	mutex_unlock(&startup_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00527 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `static int handle_unsupported_event(struct sk_buff *skb, struct genl_info *info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [ERROR_PATH|] `	pr_err("Unknown IPC event: %d, ignore.\n", info->genlhdr->cmd);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00533 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00534 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `static int handle_generic_event(struct sk_buff *skb, struct genl_info *info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	void *payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	int sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	int type = info->genlhdr->cmd;`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	if (!netlink_capable(skb, CAP_NET_ADMIN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [ERROR_PATH|] `		return -EPERM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00544 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	if (type > KSMBD_EVENT_MAX) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [ERROR_PATH|] `		pr_warn_ratelimited("Unknown IPC event: %d\n", type);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00547 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00548 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	if (!ksmbd_ipc_validate_version(info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00552 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `	if (!info->attrs[type])`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	payload = nla_data(info->attrs[info->genlhdr->cmd]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	sz = nla_len(info->attrs[info->genlhdr->cmd]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `	return handle_response(type, payload, sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `static int ipc_msg_send(struct ksmbd_ipc_msg *msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `	struct genlmsghdr *nlh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	struct sk_buff *skb;`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `	int ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	if (!ksmbd_tools_pid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	skb = genlmsg_new(msg->sz, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	if (!skb)`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00573 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `	nlh = genlmsg_put(skb, 0, 0, &ksmbd_genl_family, 0, msg->type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	if (!nlh)`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00577 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	ret = nla_put(skb, msg->type, msg->sz, msg->payload);`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `		genlmsg_cancel(skb, nlh);`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00582 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `	genlmsg_end(skb, nlh);`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `	ret = genlmsg_unicast(&init_net, skb, ksmbd_tools_pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `	if (!ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `		ipc_update_last_active();`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	nlmsg_free(skb);`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `static int ipc_validate_msg(struct ipc_msg_table_entry *entry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `	unsigned int msg_sz = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	if (entry->msg_sz > KSMBD_IPC_MAX_PAYLOAD)`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00601 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	switch (entry->type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `	case KSMBD_EVENT_RPC_REQUEST:`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `		struct ksmbd_rpc_command *resp = entry->response;`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `		msg_sz = sizeof(struct ksmbd_rpc_command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [MEM_BOUNDS|] `		if (check_add_overflow(msg_sz, resp->payload_sz, &msg_sz))`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00609 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00610 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `	case KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST:`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `		struct ksmbd_spnego_authen_response *resp = entry->response;`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `		unsigned int payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `		msg_sz = sizeof(struct ksmbd_spnego_authen_response);`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [MEM_BOUNDS|] `		if (check_add_overflow(resp->session_key_len,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00619 [NONE] `				       resp->spnego_blob_len, &payload_sz))`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00621 [MEM_BOUNDS|] `		if (check_add_overflow(msg_sz, payload_sz, &msg_sz))`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00622 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00623 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `	case KSMBD_EVENT_SHARE_CONFIG_REQUEST:`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `		struct ksmbd_share_config_response *resp = entry->response;`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `		msg_sz = sizeof(struct ksmbd_share_config_response);`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `		if (resp->payload_sz < resp->veto_list_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00632 [NONE] `		if (resp->veto_list_sz && resp->payload_sz == resp->veto_list_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [MEM_BOUNDS|] `		if (check_add_overflow(msg_sz, resp->payload_sz, &msg_sz))`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00636 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00637 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `	case KSMBD_EVENT_LOGIN_REQUEST_EXT:`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `		struct ksmbd_login_response_ext *resp = entry->response;`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `		msg_sz = sizeof(struct ksmbd_login_response_ext);`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `		if (resp->ngroups) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `			unsigned int groups_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `			if (check_mul_overflow(resp->ngroups,`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `					       (unsigned int)sizeof(gid_t),`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `					       &groups_sz))`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [ERROR_PATH|] `				return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00651 [MEM_BOUNDS|] `			if (check_add_overflow(msg_sz, groups_sz, &msg_sz))`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00652 [ERROR_PATH|] `				return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00653 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	return entry->msg_sz != msg_sz ? -EINVAL : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `static void *ipc_msg_send_request(struct ksmbd_ipc_msg *msg, unsigned int handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `	struct ipc_msg_table_entry entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	if ((int)handle < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `	entry.type = msg->type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	entry.response = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `	init_waitqueue_head(&entry.wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [LOCK|] `	down_write(&ipc_msg_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00676 [NONE] `	entry.handle = handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `	hash_add(ipc_msg_table, &entry.ipc_table_hlist, entry.handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [LOCK|] `	up_write(&ipc_msg_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00679 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `	ret = ipc_msg_send(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [LOCK|] `		down_write(&ipc_msg_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00683 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00684 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [WAIT_LOOP|] `	ret = wait_event_interruptible_timeout(entry.wait,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00687 [NONE] `					       entry.response != NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `					       IPC_WAIT_TIMEOUT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [LOCK|] `	down_write(&ipc_msg_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00691 [NONE] `	if (entry.response) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `		ret = ipc_validate_msg(&entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `			kvfree(entry.response);`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `			entry.response = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `	hash_del(&entry.ipc_table_hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [LOCK|] `	up_write(&ipc_msg_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00701 [NONE] `	return entry.response;`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `static int ksmbd_ipc_heartbeat_request(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_heartbeat));`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00712 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `	msg->type = KSMBD_EVENT_HEARTBEAT_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	ret = ipc_msg_send(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `struct ksmbd_login_response *ksmbd_ipc_login_request(const char *account)`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `	struct ksmbd_login_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `	struct ksmbd_login_response *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `	if (strlen(account) >= KSMBD_REQ_MAX_ACCOUNT_NAME_SZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_login_request));`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `	msg->type = KSMBD_EVENT_LOGIN_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `	req = (struct ksmbd_login_request *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `	req->handle = ksmbd_acquire_id(&ipc_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [MEM_BOUNDS|] `	strscpy(req->account, account, KSMBD_REQ_MAX_ACCOUNT_NAME_SZ);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00736 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	ipc_msg_handle_free(req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `struct ksmbd_login_response_ext *ksmbd_ipc_login_request_ext(const char *account)`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `	struct ksmbd_login_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `	struct ksmbd_login_response_ext *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `	if (strlen(account) >= KSMBD_REQ_MAX_ACCOUNT_NAME_SZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_login_request));`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	msg->type = KSMBD_EVENT_LOGIN_REQUEST_EXT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	req = (struct ksmbd_login_request *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	req->handle = ksmbd_acquire_id(&ipc_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [MEM_BOUNDS|] `	strscpy(req->account, account, KSMBD_REQ_MAX_ACCOUNT_NAME_SZ);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00759 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	ipc_msg_handle_free(req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `struct ksmbd_spnego_authen_response *`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `ksmbd_ipc_spnego_authen_request(const char *spnego_blob, int blob_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `	struct ksmbd_spnego_authen_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `	struct ksmbd_spnego_authen_response *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `	if (blob_len > KSMBD_IPC_MAX_PAYLOAD)`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_spnego_authen_request) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `			blob_len + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	msg->type = KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `	req = (struct ksmbd_spnego_authen_request *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `	req->handle = ksmbd_acquire_id(&ipc_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `	req->spnego_blob_len = blob_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [MEM_BOUNDS|] `	memcpy(req->spnego_blob, spnego_blob, blob_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00785 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `	ipc_msg_handle_free(req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `struct ksmbd_tree_connect_response *`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `ksmbd_ipc_tree_connect_request(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `			       struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `			       struct ksmbd_tree_connect *tree_conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `			       struct sockaddr *peer_addr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `	struct ksmbd_tree_connect_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `	struct ksmbd_tree_connect_response *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `	if (strlen(user_name(sess->user)) >= KSMBD_REQ_MAX_ACCOUNT_NAME_SZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `	if (strlen(share->name) >= KSMBD_REQ_MAX_SHARE_NAME)`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_tree_connect_request));`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `	msg->type = KSMBD_EVENT_TREE_CONNECT_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `	req = (struct ksmbd_tree_connect_request *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `	req->handle = ksmbd_acquire_id(&ipc_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `	req->account_flags = sess->user->flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `	req->session_id = sess->id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `	req->connect_id = tree_conn->id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [MEM_BOUNDS|] `	strscpy(req->account, user_name(sess->user), KSMBD_REQ_MAX_ACCOUNT_NAME_SZ);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00820 [MEM_BOUNDS|] `	strscpy(req->share, share->name, KSMBD_REQ_MAX_SHARE_NAME);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00821 [MEM_BOUNDS|] `	snprintf(req->peer_addr, sizeof(req->peer_addr), "%pIS", peer_addr);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00822 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `	if (peer_addr->sa_family == AF_INET6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `		req->flags |= KSMBD_TREE_CONN_FLAG_REQUEST_IPV6;`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `	if (test_session_flag(sess, CIFDS_SESSION_FLAG_SMB2))`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `		req->flags |= KSMBD_TREE_CONN_FLAG_REQUEST_SMB2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `	ipc_msg_handle_free(req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `int ksmbd_ipc_tree_disconnect_request(unsigned long long session_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `				      unsigned long long connect_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `	struct ksmbd_tree_disconnect_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_tree_disconnect_request));`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00844 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `	msg->type = KSMBD_EVENT_TREE_DISCONNECT_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `	req = (struct ksmbd_tree_disconnect_request *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `	req->session_id = session_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `	req->connect_id = connect_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `	ret = ipc_msg_send(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `int ksmbd_ipc_logout_request(const char *account, int flags)`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `	struct ksmbd_logout_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `	if (strlen(account) >= KSMBD_REQ_MAX_ACCOUNT_NAME_SZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00863 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_logout_request));`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00867 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `	msg->type = KSMBD_EVENT_LOGOUT_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `	req = (struct ksmbd_logout_request *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `	req->account_flags = flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [MEM_BOUNDS|] `	strscpy(req->account, account, KSMBD_REQ_MAX_ACCOUNT_NAME_SZ);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00872 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `	ret = ipc_msg_send(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `struct ksmbd_share_config_response *`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `ksmbd_ipc_share_config_request(const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `	struct ksmbd_share_config_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `	struct ksmbd_share_config_response *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `	if (strlen(name) >= KSMBD_REQ_MAX_SHARE_NAME)`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_share_config_request));`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `	msg->type = KSMBD_EVENT_SHARE_CONFIG_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `	req = (struct ksmbd_share_config_request *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `	req->handle = ksmbd_acquire_id(&ipc_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [MEM_BOUNDS|] `	strscpy(req->share_name, name, KSMBD_REQ_MAX_SHARE_NAME);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00896 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `	ipc_msg_handle_free(req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_open(struct ksmbd_session *sess, int handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `	struct ksmbd_rpc_command *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `	struct ksmbd_rpc_command *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_rpc_command));`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	msg->type = KSMBD_EVENT_RPC_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `	req = (struct ksmbd_rpc_command *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	req->handle = handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `	req->flags = ksmbd_session_rpc_method(sess, handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `	req->flags |= KSMBD_RPC_OPEN_METHOD;`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `	req->payload_sz = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_close(struct ksmbd_session *sess, int handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `	struct ksmbd_rpc_command *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `	struct ksmbd_rpc_command *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_rpc_command));`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `	msg->type = KSMBD_EVENT_RPC_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	req = (struct ksmbd_rpc_command *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	req->handle = handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	req->flags = ksmbd_session_rpc_method(sess, handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `	req->flags |= KSMBD_RPC_CLOSE_METHOD;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `	req->payload_sz = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_write(struct ksmbd_session *sess, int handle,`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `					  void *payload, size_t payload_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `	struct ksmbd_rpc_command *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `	struct ksmbd_rpc_command *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	if (payload_sz > KSMBD_IPC_MAX_PAYLOAD)`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_rpc_command) + payload_sz + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `	lockdep_assert_not_held(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [LOCK|] `	down_read(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00964 [NONE] `	msg->type = KSMBD_EVENT_RPC_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	req = (struct ksmbd_rpc_command *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `	req->handle = handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	req->flags = ksmbd_session_rpc_method(sess, handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `	req->flags |= rpc_context_flags(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `	req->flags |= KSMBD_RPC_WRITE_METHOD;`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	req->payload_sz = payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [MEM_BOUNDS|] `	memcpy(req->payload, payload, payload_sz);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00972 [NONE] `	up_read(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_read(struct ksmbd_session *sess, int handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `	struct ksmbd_rpc_command *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `	struct ksmbd_rpc_command *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_rpc_command));`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `	lockdep_assert_not_held(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [LOCK|] `	down_read(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00992 [NONE] `	msg->type = KSMBD_EVENT_RPC_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `	req = (struct ksmbd_rpc_command *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	req->handle = handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `	req->flags = ksmbd_session_rpc_method(sess, handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `	req->flags |= rpc_context_flags(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `	req->flags |= KSMBD_RPC_READ_METHOD;`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `	req->payload_sz = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `	up_read(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_ioctl(struct ksmbd_session *sess, int handle,`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `					  void *payload, size_t payload_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `	struct ksmbd_rpc_command *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `	struct ksmbd_rpc_command *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `	if (payload_sz > KSMBD_IPC_MAX_PAYLOAD)`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_rpc_command) + payload_sz + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `	lockdep_assert_not_held(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [LOCK|] `	down_read(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01023 [NONE] `	msg->type = KSMBD_EVENT_RPC_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `	req = (struct ksmbd_rpc_command *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `	req->handle = handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `	req->flags = ksmbd_session_rpc_method(sess, handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `	req->flags |= rpc_context_flags(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `	req->flags |= KSMBD_RPC_IOCTL_METHOD;`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `	req->payload_sz = payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [MEM_BOUNDS|] `	memcpy(req->payload, payload, payload_sz);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01031 [NONE] `	up_read(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_rap(struct ksmbd_session *sess, void *payload,`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `					size_t payload_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `	struct ksmbd_rpc_command *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] `	struct ksmbd_rpc_command *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `	if (payload_sz > KSMBD_IPC_MAX_PAYLOAD)`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_rpc_command) + payload_sz + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] `	msg->type = KSMBD_EVENT_RPC_REQUEST;`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `	req = (struct ksmbd_rpc_command *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `	req->handle = ksmbd_acquire_id(&ipc_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `	req->flags = rpc_context_flags(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `	req->flags |= KSMBD_RPC_RAP_METHOD;`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `	req->payload_sz = payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [MEM_BOUNDS|] `	memcpy(req->payload, payload, payload_sz);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `	resp = ipc_msg_send_request(msg, req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	ipc_msg_handle_free(req->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `	return resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `static int __ipc_heartbeat(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `	unsigned long delta;`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `	if (!ksmbd_server_running())`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `	if (time_after(jiffies, server_conf.ipc_last_active)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `		delta = (jiffies - server_conf.ipc_last_active);`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `		ipc_update_last_active();`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `		schedule_delayed_work(&ipc_timer_work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `				      server_conf.ipc_timeout);`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `	if (delta < server_conf.ipc_timeout) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `		schedule_delayed_work(&ipc_timer_work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `				      server_conf.ipc_timeout - delta);`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `	if (ksmbd_ipc_heartbeat_request() == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `		schedule_delayed_work(&ipc_timer_work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `				      server_conf.ipc_timeout);`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [LOCK|] `	mutex_lock(&startup_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01095 [NONE] `	WRITE_ONCE(server_conf.state, SERVER_STATE_RESETTING);`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `	server_conf.ipc_last_active = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `	ksmbd_tools_pid = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [ERROR_PATH|] `	pr_err("No IPC daemon response for %lus\n", delta / HZ);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01099 [LOCK|] `	mutex_unlock(&startup_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01100 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01101 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `static void ipc_timer_heartbeat(struct work_struct *w)`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `	if (__ipc_heartbeat())`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `		server_queue_ctrl_reset_work();`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `/* Witness Protocol (MS-SWN) handlers and IPC functions                */`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] ` * handle_witness_register_event() - handle a witness registration from userspace`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] ` * Userspace (ksmbd.mountd) sends this when a client calls WitnessrRegister.`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] ` * The kernel creates a registration and replies with the reg_id.`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `static int handle_witness_register_event(struct sk_buff *skb,`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `					 struct genl_info *info)`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `	struct ksmbd_witness_register_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `	struct ksmbd_witness_register_response resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	u32 reg_id = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `	if (!netlink_capable(skb, CAP_NET_ADMIN))`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [ERROR_PATH|] `		return -EPERM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `	if (!ksmbd_ipc_validate_version(info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `	if (!info->attrs[KSMBD_EVENT_WITNESS_REGISTER])`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `	req = nla_data(info->attrs[info->genlhdr->cmd]);`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `	ret = ksmbd_witness_register(req->client_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `				     req->resource_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `				     req->resource_type,`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `				     req->session_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `				     &reg_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `	memset(&resp, 0, sizeof(resp));`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `	resp.handle = req->handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `	resp.reg_id = reg_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `	resp.status = ret ? (__u32)-ret : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `	msg = ipc_msg_alloc(sizeof(resp));`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `	msg->type = KSMBD_EVENT_WITNESS_REGISTER_RESPONSE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [MEM_BOUNDS|] `	memcpy(msg->payload, &resp, sizeof(resp));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01156 [NONE] `	ret = ipc_msg_send(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] ` * handle_witness_unregister_event() - handle a witness unregistration`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `static int handle_witness_unregister_event(struct sk_buff *skb,`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `					   struct genl_info *info)`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `	struct ksmbd_witness_unregister_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `	struct ksmbd_witness_unregister_response resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `	if (!netlink_capable(skb, CAP_NET_ADMIN))`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [ERROR_PATH|] `		return -EPERM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `	if (!ksmbd_ipc_validate_version(info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `	if (!info->attrs[KSMBD_EVENT_WITNESS_UNREGISTER])`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] `	req = nla_data(info->attrs[info->genlhdr->cmd]);`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `	ret = ksmbd_witness_unregister(req->reg_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	memset(&resp, 0, sizeof(resp));`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `	resp.handle = req->handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] `	resp.status = ret ? (__u32)-ret : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `	msg = ipc_msg_alloc(sizeof(resp));`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `	msg->type = KSMBD_EVENT_WITNESS_UNREGISTER_RESPONSE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [MEM_BOUNDS|] `	memcpy(msg->payload, &resp, sizeof(resp));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01195 [NONE] `	ret = ipc_msg_send(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] ` * handle_witness_iface_list_event() - handle interface list query`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] ` * Enumerates network interfaces and returns them to userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] ` * Userspace uses this to respond to WitnessrGetInterfaceList.`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `static int handle_witness_iface_list_event(struct sk_buff *skb,`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `					   struct genl_info *info)`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `	struct ksmbd_witness_iface_list_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `	struct ksmbd_witness_iface_list_response *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `	struct ksmbd_witness_iface_entry *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `	struct net_device *dev;`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `	u32 num_ifaces = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `	size_t payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `	size_t total_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `	if (!netlink_capable(skb, CAP_NET_ADMIN))`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [ERROR_PATH|] `		return -EPERM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] `	if (!ksmbd_ipc_validate_version(info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	if (!info->attrs[KSMBD_EVENT_WITNESS_IFACE_LIST])`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `	req = nla_data(info->attrs[info->genlhdr->cmd]);`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `	/* First pass: count interfaces */`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01232 [NONE] `	for_each_netdev_rcu(&init_net, dev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] `		if (dev->flags & IFF_LOOPBACK)`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `		num_ifaces++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01238 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `	payload_sz = num_ifaces * sizeof(struct ksmbd_witness_iface_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `	total_sz = sizeof(*resp) + payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `	if (total_sz > KSMBD_IPC_MAX_PAYLOAD)`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `		total_sz = KSMBD_IPC_MAX_PAYLOAD;`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `	msg = ipc_msg_alloc(total_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `	msg->type = KSMBD_EVENT_WITNESS_IFACE_LIST_RESPONSE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `	resp = (struct ksmbd_witness_iface_list_response *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `	memset(resp, 0, total_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `	resp->handle = req->handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `	entry = (struct ksmbd_witness_iface_entry *)resp->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `	num_ifaces = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `	/* Second pass: fill interface entries */`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01259 [NONE] `	for_each_netdev_rcu(&init_net, dev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `		struct in_device *in_dev;`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `		const struct in_ifaddr *ifa;`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `		size_t offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `		if (dev->flags & IFF_LOOPBACK)`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `		offset = (char *)entry - (char *)resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `		if (offset + sizeof(*entry) > total_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `		memset(entry, 0, sizeof(*entry));`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `		entry->if_index = dev->ifindex;`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [MEM_BOUNDS|] `		strscpy(entry->if_name, dev->name, sizeof(entry->if_name));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01274 [NONE] `		entry->state = (dev->flags & IFF_UP) ?`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `			KSMBD_WITNESS_STATE_AVAILABLE :`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `			KSMBD_WITNESS_STATE_UNAVAILABLE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] `		in_dev = __in_dev_get_rcu(dev);`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `		if (in_dev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `			in_dev_for_each_ifa_rcu(ifa, in_dev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [MEM_BOUNDS|] `				snprintf(entry->ipv4_addr,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01282 [NONE] `					 sizeof(entry->ipv4_addr),`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] `					 "%pI4", &ifa->ifa_address);`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `				entry->capability |=`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] `					KSMBD_WITNESS_IFACE_CAP_IPV4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `				break; /* first IPv4 address only */`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `		entry++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `		num_ifaces++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	resp->num_interfaces = num_ifaces;`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `	resp->payload_sz = num_ifaces *`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `		sizeof(struct ksmbd_witness_iface_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `	ret = ipc_msg_send(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] ` * ksmbd_ipc_witness_notify() - send witness state change to userspace`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] ` * @reg_id: the registration this notification is for`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] ` * @resource_name: the resource that changed state`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] ` * @new_state: the new state value`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] ` * This is a one-way notification from kernel to userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `int ksmbd_ipc_witness_notify(u32 reg_id, const char *resource_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `			     int new_state)`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `	struct ksmbd_ipc_msg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `	struct ksmbd_witness_notify_msg *notify;`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `	msg = ipc_msg_alloc(sizeof(struct ksmbd_witness_notify_msg));`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `	msg->type = KSMBD_EVENT_WITNESS_NOTIFY;`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `	notify = (struct ksmbd_witness_notify_msg *)msg->payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `	memset(notify, 0, sizeof(*notify));`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `	notify->reg_id = reg_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `	notify->new_state = new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [MEM_BOUNDS|] `	strscpy(notify->resource_name, resource_name,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01330 [NONE] `		KSMBD_WITNESS_NAME_MAX_NL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] `	ret = ipc_msg_send(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `	ipc_msg_free(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] ` * ksmbd_ipc_witness_iface_list_request() - request interface list from kernel`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] ` * This is called from within the kernel; currently not used since`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] ` * the interface list query is handled directly in the netlink handler.`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] ` * Kept as a stub for future use.`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `struct ksmbd_witness_iface_list_response *`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `ksmbd_ipc_witness_iface_list_request(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `int ksmbd_ipc_id_alloc(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] `	return ksmbd_acquire_id(&ipc_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `void ksmbd_rpc_id_free(int handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `	ksmbd_release_id(&ipc_ida, handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `void ksmbd_ipc_release(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	cancel_delayed_work_sync(&ipc_timer_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] `	genl_unregister_family(&ksmbd_genl_family);`
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `void ksmbd_ipc_soft_reset(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [LOCK|] `	mutex_lock(&startup_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01369 [NONE] `	ksmbd_tools_pid = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `	cancel_delayed_work_sync(&ipc_timer_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [LOCK|] `	mutex_unlock(&startup_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01372 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] `int ksmbd_ipc_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `	ksmbd_nl_init_fixup();`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `	INIT_DELAYED_WORK(&ipc_timer_work, ipc_timer_heartbeat);`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `	ret = genl_register_family(&ksmbd_genl_family);`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [ERROR_PATH|] `		pr_err("Failed to register KSMBD netlink interface %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01384 [NONE] `		cancel_delayed_work_sync(&ipc_timer_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
