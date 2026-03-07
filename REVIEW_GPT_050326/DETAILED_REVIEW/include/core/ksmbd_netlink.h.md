# Line-by-line Review: src/include/core/ksmbd_netlink.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   linux-ksmbd-devel@lists.sourceforge.net`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#ifndef _LINUX_KSMBD_SERVER_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#define _LINUX_KSMBD_SERVER_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * This is a userspace ABI to communicate data between ksmbd and user IPC`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` * daemon using netlink. This is added to track and cache user account DB`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` * and share configuration info from userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` *  - KSMBD_EVENT_HEARTBEAT_REQUEST(ksmbd_heartbeat)`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` *    This event is to check whether user IPC daemon is alive. If user IPC`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` *    daemon is dead, ksmbd keep existing connection till disconnecting and`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` *    new connection will be denied.`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` *  - KSMBD_EVENT_STARTING_UP(ksmbd_startup_request)`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` *    This event is to receive the information that initializes the ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` *    server from the user IPC daemon and to start the server. The global`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` *    section parameters are given from smb.conf as initialization`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` *    information.`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` *  - KSMBD_EVENT_SHUTTING_DOWN(ksmbd_shutdown_request)`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` *    This event is to shutdown ksmbd server.`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` *  - KSMBD_EVENT_LOGIN_REQUEST/RESPONSE(ksmbd_login_request/response)`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` *    This event is to get user account info to user IPC daemon.`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` *  - KSMBD_EVENT_SHARE_CONFIG_REQUEST/RESPONSE(ksmbd_share_config_request/response)`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` *    This event is to get net share configuration info.`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` *  - KSMBD_EVENT_TREE_CONNECT_REQUEST/RESPONSE(ksmbd_tree_connect_request/response)`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *    This event is to get session and tree connect info.`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` *  - KSMBD_EVENT_TREE_DISCONNECT_REQUEST(ksmbd_tree_disconnect_request)`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` *    This event is to send tree disconnect info to user IPC daemon.`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` *  - KSMBD_EVENT_LOGOUT_REQUEST(ksmbd_logout_request)`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` *    This event is to send logout request to user IPC daemon.`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` *  - KSMBD_EVENT_RPC_REQUEST/RESPONSE(ksmbd_rpc_command)`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` *    This event is to make DCE/RPC request like srvsvc, wkssvc, lsarpc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` *    samr to be processed in userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` *  - KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST/RESPONSE(ksmbd_spnego_authen_request/response)`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` *    This event is to make kerberos authentication to be processed in`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` *    userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` *  - KSMBD_EVENT_LOGIN_REQUEST_EXT/RESPONSE_EXT(ksmbd_login_request_ext/response_ext)`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ` *    This event is to get user account extension info to user IPC daemon.`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ` *  - KSMBD_EVENT_WITNESS_REGISTER(ksmbd_witness_register_request)`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ` *    Userspace registers a client for witness (MS-SWN) notifications.`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ` *  - KSMBD_EVENT_WITNESS_UNREGISTER(ksmbd_witness_unregister_request)`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` *    Userspace unregisters a client from witness notifications.`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` *  - KSMBD_EVENT_WITNESS_NOTIFY(ksmbd_witness_notify_msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` *    Kernel sends a resource state change notification to userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` *  - KSMBD_EVENT_WITNESS_IFACE_LIST(ksmbd_witness_iface_list_request)`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` *    Userspace queries available network interfaces.`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#define KSMBD_GENL_NAME		"SMBD_GENL"`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `#define KSMBD_GENL_VERSION		0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `#define KSMBD_REQ_MAX_ACCOUNT_NAME_SZ	256`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `#define KSMBD_REQ_MAX_HASH_SZ		18`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `#define KSMBD_REQ_MAX_SHARE_NAME	64`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `#define KSMBD_MAX_SHARE_PAYLOAD_SZ	(64 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `#define KSMBD_MAX_SPNEGO_BLOB_SZ	(64 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `#define KSMBD_MAX_RPC_PAYLOAD_SZ	(256 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` * IPC heartbeat frame to check whether user IPC daemon is alive.`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `struct ksmbd_heartbeat {`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` * Global config flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `#define KSMBD_GLOBAL_FLAG_INVALID		(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [PROTO_GATE|] `#define KSMBD_GLOBAL_FLAG_SMB2_LEASES		BIT(0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00094 [PROTO_GATE|] `#define KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION	BIT(1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00095 [NONE] `#define KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL	BIT(2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [PROTO_GATE|] `#define KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF	BIT(3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00097 [NONE] `#define KSMBD_GLOBAL_FLAG_DURABLE_HANDLE	BIT(4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `#define KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS	BIT(5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `#define KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID	BIT(6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `#define KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES	BIT(7)`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `#define KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE	BIT(8)`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` * IPC request for ksmbd server startup.`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ` * ifc_list_sz: size of interface list in ____payload[]; must not exceed 4KB.`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` * Callers must validate ifc_list_sz before accessing payload data.`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `struct ksmbd_startup_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	__u32	flags;			/* Flags for global config */`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	__s32	signing;		/* Signing enabled */`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	__s8	min_prot[16];		/* The minimum SMB protocol version */`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	__s8	max_prot[16];		/* The maximum SMB protocol version */`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	__s8	netbios_name[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	__s8	work_group[64];		/* Workgroup */`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	__s8	server_string[64];	/* Server string */`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	__u16	tcp_port;		/* tcp port */`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	__u16	ipc_timeout;		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `					 * specifies the number of seconds`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `					 * server will wait for the userspace to`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `					 * reply to heartbeat frames.`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	__u32	deadtime;		/* Number of minutes of inactivity */`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	__u32	file_max;		/* Limits the maximum number of open files */`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	__u32	smb2_max_write;		/* MAX write size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	__u32	smb2_max_read;		/* MAX read size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	__u32	smb2_max_trans;		/* MAX trans size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	__u32	share_fake_fscaps;	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `					 * Support some special application that`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `					 * makes QFSINFO calls to check whether`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `					 * we set the SPARSE_FILES bit (0x40).`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	__u32	sub_auth[3];		/* Subauth value for Security ID */`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	__u32	smb2_max_credits;	/* MAX credits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	__u32	smbd_max_io_size;	/* smbd read write size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	__u32	max_connections;	/* Number of maximum simultaneous connections */`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	__s8	bind_interfaces_only;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	__u32	max_ip_connections;	/* Number of maximum connection per ip address */`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	__s8	fruit_model[64];	/* Fruit model string for AAPL */`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	__s8	reserved[435];		/* Reserved room */`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	__u32	ifc_list_sz;		/* interfaces list size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	__s8	____payload[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `#define KSMBD_STARTUP_CONFIG_INTERFACES(s)	((s)->____payload)`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` * IPC request to shutdown ksmbd server.`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `struct ksmbd_shutdown_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	__s32	reserved[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ` * IPC user login request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `struct ksmbd_login_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	__s8	account[KSMBD_REQ_MAX_ACCOUNT_NAME_SZ]; /* user account name */`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	__u32	reserved[16];				/* Reserved room */`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ` * IPC user login response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `struct ksmbd_login_response {`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	__u32	gid;					/* group id */`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	__u32	uid;					/* user id */`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	__s8	account[KSMBD_REQ_MAX_ACCOUNT_NAME_SZ]; /* user account name */`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	__u16	status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	__u16	hash_sz;			/* hash size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	__s8	hash[KSMBD_REQ_MAX_HASH_SZ];	/* password hash */`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	__u32	reserved[16];			/* Reserved room */`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ` * IPC user login response extension.`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `struct ksmbd_login_response_ext {`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	__s32	ngroups;			/* supplementary group count */`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	__s8	reserved[128];			/* Reserved room */`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	__s8	____payload[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ` * IPC request to fetch net share config.`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `struct ksmbd_share_config_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	__s8	share_name[KSMBD_REQ_MAX_SHARE_NAME]; /* share name */`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	__u32	reserved[16];		/* Reserved room */`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ` * IPC response to the net share config request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ` * payload_sz: total size of ____payload[]; must not exceed`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ` * KSMBD_MAX_SHARE_PAYLOAD_SZ (64KB).`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ` * veto_list_sz: size of veto list within ____payload[]; must be < payload_sz.`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ` * Callers must validate both sizes before accessing payload data.`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `struct ksmbd_share_config_response {`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	__u32	flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	__u16	create_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	__u16	directory_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	__u16	force_create_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	__u16	force_directory_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	__u16	force_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	__u16	force_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	__s8	share_name[KSMBD_REQ_MAX_SHARE_NAME];`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	__u64	time_machine_max_size;	/* Time Machine max size in bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	__u32	reserved[109];		/* Reserved room */`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	__u32	payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	__u32	veto_list_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	__s8	____payload[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `#define KSMBD_SHARE_CONFIG_VETO_LIST(s)	((s)->____payload)`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `static inline char *`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `ksmbd_share_config_path(struct ksmbd_share_config_response *sc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	char *p = sc->____payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	if (sc->veto_list_sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		if (sc->veto_list_sz + 1 > sc->payload_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `			return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `		p += sc->veto_list_sz + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	return p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ` * IPC request for tree connection. This request include session and tree`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ` * connect info from client.`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `struct ksmbd_tree_connect_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	__u16	account_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	__u16	flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	__u64	session_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	__u64	connect_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	__s8	account[KSMBD_REQ_MAX_ACCOUNT_NAME_SZ];`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	__s8	share[KSMBD_REQ_MAX_SHARE_NAME];`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	__s8	peer_addr[64];`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	__u32	reserved[16];		/* Reserved room */`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ` * IPC Response structure for tree connection.`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `struct ksmbd_tree_connect_response {`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	__u16	status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `	__u16	connection_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	__u32	reserved[16];		/* Reserved room */`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ` * IPC Request structure to disconnect tree connection.`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `struct ksmbd_tree_disconnect_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	__u64	session_id;	/* session id */`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	__u64	connect_id;	/* tree connection id */`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	__u32	reserved[16];	/* Reserved room */`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] ` * IPC Response structure to logout user account.`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `struct ksmbd_logout_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	__s8	account[KSMBD_REQ_MAX_ACCOUNT_NAME_SZ]; /* user account name */`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	__u32	account_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	__u32	reserved[16];				/* Reserved room */`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ` * RPC command structure to send rpc request like srvsvc or wkssvc to`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] ` * IPC user daemon.`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] ` * Maximum expected payload_sz: 256KB (KSMBD_MAX_RPC_PAYLOAD_SZ).`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] ` * Callers must validate payload_sz before allocating or copying data.`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `struct ksmbd_rpc_command {`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	__u32	flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	__u32	payload_sz;	/* must not exceed KSMBD_MAX_RPC_PAYLOAD_SZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	__u8	payload[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] ` * IPC Request Kerberos authentication`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `struct ksmbd_spnego_authen_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	__u16	spnego_blob_len;	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `					 * the length of spnego_blob.`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `					 * NOTE: __u16 limits SPNEGO blobs to 64KB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `					 * which may be insufficient for complex`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `					 * Kerberos configurations with many PAC`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `					 * entries or cross-realm trust chains.`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	__u8	spnego_blob[];		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `					 * the GSS token from SecurityBuffer of`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `					 * SMB2 SESSION SETUP request`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ` * Response data which includes the GSS token and the session key generated by`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] ` * user daemon.`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `struct ksmbd_spnego_authen_response {`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	struct ksmbd_login_response login_response; /*`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `						     * the login response with`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `						     * a user identified by the`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `						     * GSS token from a client`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `						     */`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	__u16	session_key_len; /* the length of the session key */`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	__u16	spnego_blob_len; /*`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `				  * the length of the GSS token which will be`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `				  * stored in SecurityBuffer of SMB2 SESSION`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `				  * SETUP response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `				  * NOTE: __u16 limits SPNEGO blobs to 64KB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `				  * which may be insufficient for complex`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `				  * Kerberos configurations with many PAC`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `				  * entries or cross-realm trust chains.`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `				  */`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	__u8	payload[]; /* session key + AP_REP */`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ` * Witness Protocol (MS-SWN) netlink message definitions.`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ` * These are used for kernel <-> userspace witness communication.`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `#define KSMBD_WITNESS_NAME_MAX_NL	256`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] ` * Witness resource states (mirrors MS-SWN WITNESS_STATE).`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] ` * These values are shared between kernel and userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `#define KSMBD_WITNESS_STATE_AVAILABLE		0`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `#define KSMBD_WITNESS_STATE_UNAVAILABLE		1`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `#define KSMBD_WITNESS_STATE_UNKNOWN		0xFF`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] ` * Witness resource types (mirrors MS-SWN).`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `#define KSMBD_WITNESS_RESOURCE_IP		0`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `#define KSMBD_WITNESS_RESOURCE_SHARE		1`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `#define KSMBD_WITNESS_RESOURCE_NODE		2`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] ` * IPC request: userspace registers a client for witness notifications.`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ` * Sent from ksmbd.mountd to kernel when a client calls WitnessrRegister.`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `struct ksmbd_witness_register_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	__u32	handle;				/* IPC handle for response */`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	__u32	resource_type;			/* KSMBD_WITNESS_RESOURCE_* */`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	__s8	client_name[KSMBD_WITNESS_NAME_MAX_NL];`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	__s8	resource_name[KSMBD_WITNESS_NAME_MAX_NL];`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	__u64	session_id;			/* owning session ID */`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	__u32	reserved[6];`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] ` * IPC response: kernel returns reg_id to userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `struct ksmbd_witness_register_response {`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	__u32	handle;				/* IPC handle */`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `	__u32	reg_id;				/* assigned registration ID */`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	__u32	status;				/* 0 on success */`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	__u32	reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ` * IPC request: userspace unregisters a witness client.`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `struct ksmbd_witness_unregister_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	__u32	reg_id;				/* registration ID to remove */`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	__u32	reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] ` * IPC response: kernel acknowledges unregistration.`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `struct ksmbd_witness_unregister_response {`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	__u32	status;				/* 0 on success */`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	__u32	reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ` * IPC notification: kernel sends resource state change to userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] ` * This is a one-way message (kernel -> userspace).  Userspace`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ` * translates this into a WitnessrAsyncNotify response for the client.`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `struct ksmbd_witness_notify_msg {`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	__u32	reg_id;				/* which registration */`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	__u32	new_state;			/* KSMBD_WITNESS_STATE_* */`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	__s8	resource_name[KSMBD_WITNESS_NAME_MAX_NL];`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	__u32	reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] ` * IPC request: userspace queries available network interfaces.`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] ` * Used by WitnessrGetInterfaceList.`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `struct ksmbd_witness_iface_list_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	__u32	reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] ` * IPC response: kernel returns interface list.`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ` * payload[] contains a sequence of ksmbd_witness_iface_entry structs.`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `struct ksmbd_witness_iface_list_response {`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	__u32	num_interfaces;`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	__u32	payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	__u32	reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	__u8	payload[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] ` * Single interface entry in the witness interface list response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `struct ksmbd_witness_iface_entry {`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	__u32	if_index;			/* net_device ifindex */`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	__u32	state;				/* KSMBD_WITNESS_STATE_* */`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	__u32	capability;			/* flags (e.g., IPv4/IPv6) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	__s8	if_name[16];			/* interface name */`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `	__s8	ipv4_addr[16];			/* dotted-decimal IPv4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	__s8	ipv6_addr[48];			/* IPv6 address string */`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	__u32	reserved[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `/* Witness interface capability flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `#define KSMBD_WITNESS_IFACE_CAP_IPV4	BIT(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `#define KSMBD_WITNESS_IFACE_CAP_IPV6	BIT(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] ` * This also used as NETLINK attribute type value.`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ` * NOTE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] ` * Response message type value should be equal to`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] ` * request message type value + 1.`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `enum ksmbd_event {`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `	KSMBD_EVENT_UNSPEC			= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	KSMBD_EVENT_HEARTBEAT_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `	KSMBD_EVENT_STARTING_UP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `	KSMBD_EVENT_SHUTTING_DOWN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	KSMBD_EVENT_LOGIN_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	KSMBD_EVENT_LOGIN_RESPONSE		= 5,`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	KSMBD_EVENT_SHARE_CONFIG_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	KSMBD_EVENT_SHARE_CONFIG_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	KSMBD_EVENT_TREE_CONNECT_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	KSMBD_EVENT_TREE_CONNECT_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	KSMBD_EVENT_TREE_DISCONNECT_REQUEST	= 10,`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	KSMBD_EVENT_LOGOUT_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	KSMBD_EVENT_RPC_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	KSMBD_EVENT_RPC_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `	KSMBD_EVENT_SPNEGO_AUTHEN_RESPONSE	= 15,`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	KSMBD_EVENT_LOGIN_REQUEST_EXT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	KSMBD_EVENT_LOGIN_RESPONSE_EXT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	/* Witness Protocol (MS-SWN) events */`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	KSMBD_EVENT_WITNESS_REGISTER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	KSMBD_EVENT_WITNESS_REGISTER_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	KSMBD_EVENT_WITNESS_UNREGISTER		= 20,`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `	KSMBD_EVENT_WITNESS_UNREGISTER_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	KSMBD_EVENT_WITNESS_NOTIFY,		/* kernel -> userspace only */`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	KSMBD_EVENT_WITNESS_IFACE_LIST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	KSMBD_EVENT_WITNESS_IFACE_LIST_RESPONSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	__KSMBD_EVENT_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	KSMBD_EVENT_MAX = __KSMBD_EVENT_MAX - 1`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] ` * Enumeration for IPC tree connect status.`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `enum KSMBD_TREE_CONN_STATUS {`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [PROTO_GATE|] `	KSMBD_TREE_CONN_STATUS_OK		= 0,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00506 [PROTO_GATE|] `	KSMBD_TREE_CONN_STATUS_NOMEM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00507 [PROTO_GATE|] `	KSMBD_TREE_CONN_STATUS_NO_SHARE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00508 [PROTO_GATE|] `	KSMBD_TREE_CONN_STATUS_NO_USER,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00509 [PROTO_GATE|] `	KSMBD_TREE_CONN_STATUS_INVALID_USER,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00510 [PROTO_GATE|] `	KSMBD_TREE_CONN_STATUS_HOST_DENIED	= 5,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00511 [PROTO_GATE|] `	KSMBD_TREE_CONN_STATUS_CONN_EXIST,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00512 [PROTO_GATE|] `	KSMBD_TREE_CONN_STATUS_TOO_MANY_CONNS,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00513 [PROTO_GATE|] `	KSMBD_TREE_CONN_STATUS_TOO_MANY_SESSIONS,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00514 [PROTO_GATE|] `	KSMBD_TREE_CONN_STATUS_ERROR,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00515 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] ` * User config flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `#define KSMBD_USER_FLAG_INVALID		(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `#define KSMBD_USER_FLAG_OK		BIT(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `#define KSMBD_USER_FLAG_BAD_PASSWORD	BIT(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `#define KSMBD_USER_FLAG_BAD_UID		BIT(2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `#define KSMBD_USER_FLAG_BAD_USER	BIT(3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `#define KSMBD_USER_FLAG_GUEST_ACCOUNT	BIT(4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `#define KSMBD_USER_FLAG_DELAY_SESSION	BIT(5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `#define KSMBD_USER_FLAG_EXTENSION	BIT(6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ` * Share config flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `#define KSMBD_SHARE_FLAG_INVALID			(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `#define KSMBD_SHARE_FLAG_AVAILABLE			BIT(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `#define KSMBD_SHARE_FLAG_BROWSEABLE			BIT(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `#define KSMBD_SHARE_FLAG_WRITEABLE			BIT(2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `#define KSMBD_SHARE_FLAG_READONLY			BIT(3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `#define KSMBD_SHARE_FLAG_GUEST_OK			BIT(4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `#define KSMBD_SHARE_FLAG_GUEST_ONLY			BIT(5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `#define KSMBD_SHARE_FLAG_STORE_DOS_ATTRS		BIT(6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `#define KSMBD_SHARE_FLAG_OPLOCKS			BIT(7)`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `#define KSMBD_SHARE_FLAG_PIPE				BIT(8)`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `#define KSMBD_SHARE_FLAG_HIDE_DOT_FILES			BIT(9)`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `#define KSMBD_SHARE_FLAG_INHERIT_OWNER			BIT(10)`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `#define KSMBD_SHARE_FLAG_STREAMS			BIT(11)`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `#define KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS		BIT(12)`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `#define KSMBD_SHARE_FLAG_ACL_XATTR			BIT(13)`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `#define KSMBD_SHARE_FLAG_UPDATE				BIT(14)`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `#define KSMBD_SHARE_FLAG_CROSSMNT			BIT(15)`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `#define KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY	BIT(16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `#define KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE		BIT(17)`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `#define KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO		BIT(18)`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `#define KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE		BIT(19)`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `#define KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS		BIT(20)`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] ` * Tree connect request flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `#define KSMBD_TREE_CONN_FLAG_REQUEST_SMB1	(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `#define KSMBD_TREE_CONN_FLAG_REQUEST_IPV6	BIT(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `#define KSMBD_TREE_CONN_FLAG_REQUEST_SMB2	BIT(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] ` * Tree connect flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `#define KSMBD_TREE_CONN_FLAG_GUEST_ACCOUNT	BIT(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `#define KSMBD_TREE_CONN_FLAG_READ_ONLY		BIT(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `#define KSMBD_TREE_CONN_FLAG_WRITABLE		BIT(2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `#define KSMBD_TREE_CONN_FLAG_ADMIN_ACCOUNT	BIT(3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `#define KSMBD_TREE_CONN_FLAG_UPDATE		BIT(4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] ` * RPC over IPC.`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `#define KSMBD_RPC_METHOD_RETURN		BIT(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `#define KSMBD_RPC_SRVSVC_METHOD_INVOKE	BIT(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `#define KSMBD_RPC_SRVSVC_METHOD_RETURN	(KSMBD_RPC_SRVSVC_METHOD_INVOKE | KSMBD_RPC_METHOD_RETURN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `#define KSMBD_RPC_WKSSVC_METHOD_INVOKE	BIT(2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `#define KSMBD_RPC_WKSSVC_METHOD_RETURN	(KSMBD_RPC_WKSSVC_METHOD_INVOKE | KSMBD_RPC_METHOD_RETURN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `#define KSMBD_RPC_IOCTL_METHOD		(BIT(3) | KSMBD_RPC_METHOD_RETURN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `#define KSMBD_RPC_OPEN_METHOD		BIT(4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `#define KSMBD_RPC_WRITE_METHOD		BIT(5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `#define KSMBD_RPC_READ_METHOD		(BIT(6) | KSMBD_RPC_METHOD_RETURN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `#define KSMBD_RPC_CLOSE_METHOD		BIT(7)`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `#define KSMBD_RPC_RAP_METHOD		(BIT(8) | KSMBD_RPC_METHOD_RETURN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `#define KSMBD_RPC_RESTRICTED_CONTEXT	BIT(9)`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `#define KSMBD_RPC_SAMR_METHOD_INVOKE	BIT(10)`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `#define KSMBD_RPC_SAMR_METHOD_RETURN	(KSMBD_RPC_SAMR_METHOD_INVOKE | KSMBD_RPC_METHOD_RETURN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `#define KSMBD_RPC_LSARPC_METHOD_INVOKE	BIT(11)`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `#define KSMBD_RPC_LSARPC_METHOD_RETURN	(KSMBD_RPC_LSARPC_METHOD_INVOKE | KSMBD_RPC_METHOD_RETURN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] ` * RPC status definitions.`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `#define KSMBD_RPC_OK			0`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `#define KSMBD_RPC_EBAD_FUNC		0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `#define KSMBD_RPC_EACCESS_DENIED	0x00000005`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `#define KSMBD_RPC_EBAD_FID		0x00000006`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `#define KSMBD_RPC_ENOMEM		0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `#define KSMBD_RPC_EBAD_DATA		0x0000000D`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `#define KSMBD_RPC_ENOTIMPLEMENTED	0x00000040`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `#define KSMBD_RPC_EINVALID_PARAMETER	0x00000057`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `#define KSMBD_RPC_EMORE_DATA		0x000000EA`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `#define KSMBD_RPC_EINVALID_LEVEL	0x0000007C`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `#define KSMBD_RPC_SOME_NOT_MAPPED	0x00000107`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `#define KSMBD_CONFIG_OPT_DISABLED	0`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `#define KSMBD_CONFIG_OPT_ENABLED	1`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `#define KSMBD_CONFIG_OPT_AUTO		2`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `#define KSMBD_CONFIG_OPT_MANDATORY	3`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `#endif /* _LINUX_KSMBD_SERVER_H */`
  Review: Low-risk line; verify in surrounding control flow.
