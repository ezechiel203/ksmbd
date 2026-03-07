# Line-by-line Review: src/include/core/server.h

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
- L00006 [NONE] `#ifndef __SERVER_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __SERVER_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "ksmbd_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "ksmbd_feature.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * Server state type`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `	SERVER_STATE_STARTING_UP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `	SERVER_STATE_RUNNING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `	SERVER_STATE_RESETTING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	SERVER_STATE_SHUTTING_DOWN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` * Server global config string index`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	SERVER_CONF_NETBIOS_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	SERVER_CONF_SERVER_STRING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	SERVER_CONF_WORK_GROUP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `struct ksmbd_server_config {`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	unsigned int		flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	unsigned int		state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	short			signing;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	short			min_protocol;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	short			max_protocol;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	unsigned short		tcp_port;`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	unsigned long		ipc_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	unsigned long		ipc_last_active;`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	unsigned long		deadtime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	unsigned int		share_fake_fscaps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	struct smb_sid		domain_sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	unsigned int		auth_mechs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	unsigned int		max_connections;`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	unsigned int		max_inflight_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	unsigned int		max_async_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	unsigned int		max_ip_connections;`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	unsigned long		features;  /* global feature enable bitmask */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	char			*conf[SERVER_CONF_WORK_GROUP + 1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	char			fruit_model[64];`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	struct task_struct	*dh_task;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	bool			bind_interfaces_only;`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	/* Stable per-server GUID (MS-SMB2 §2.2.4 ServerGUID) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	__u8			server_guid[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	/* Server start time in 100-ns Windows FILETIME units */`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	__u64			server_start_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `extern struct ksmbd_server_config server_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `int ksmbd_set_netbios_name(char *v);`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `int ksmbd_set_server_string(char *v);`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `int ksmbd_set_work_group(char *v);`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `char *ksmbd_netbios_name(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `char *ksmbd_server_string(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `char *ksmbd_work_group(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `static inline int ksmbd_server_running(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	return READ_ONCE(server_conf.state) == SERVER_STATE_RUNNING;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `static inline int ksmbd_server_configurable(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	return READ_ONCE(server_conf.state) < SERVER_STATE_RESETTING;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `int server_queue_ctrl_init_work(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `int server_queue_ctrl_reset_work(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `int ksmbd_debugfs_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `void ksmbd_debugfs_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `#endif /* __SERVER_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
