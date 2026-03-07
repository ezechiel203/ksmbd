# Line-by-line Review: src/mgmt/tree_connect.h

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
- L00006 [NONE] `#ifndef __TREE_CONNECT_MANAGEMENT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __TREE_CONNECT_MANAGEMENT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/hashtable.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/refcount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include "ksmbd_netlink.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `struct ksmbd_share_config;`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `struct ksmbd_user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `struct ksmbd_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	TREE_NEW = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `	TREE_CONNECTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	TREE_DISCONNECTED`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `struct ksmbd_tree_connect {`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	int				id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	unsigned int			flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	struct ksmbd_share_config	*share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	struct ksmbd_user		*user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	struct list_head		list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	int				maximal_access;`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	bool				posix_extensions;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [LIFETIME|] `	refcount_t			refcount;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00037 [NONE] `	unsigned int			t_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `struct ksmbd_tree_conn_status {`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	unsigned int			ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	struct ksmbd_tree_connect	*tree_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `static inline int test_tree_conn_flag(struct ksmbd_tree_connect *tree_conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `				      int flag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	return tree_conn->flags & flag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `struct ksmbd_session;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `struct ksmbd_tree_conn_status`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `ksmbd_tree_conn_connect(struct ksmbd_work *work, const char *share_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `void ksmbd_tree_connect_put(struct ksmbd_tree_connect *tcon);`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `int ksmbd_tree_conn_disconnect(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `			       struct ksmbd_tree_connect *tree_conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `struct ksmbd_tree_connect *ksmbd_tree_conn_lookup(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `						  unsigned int id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `int ksmbd_tree_conn_session_logoff(struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#endif /* __TREE_CONNECT_MANAGEMENT_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
