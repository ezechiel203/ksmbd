# Line-by-line Review: src/mgmt/share_config.h

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
- L00006 [NONE] `#ifndef __SHARE_CONFIG_MANAGEMENT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __SHARE_CONFIG_MANAGEMENT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/workqueue.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/hashtable.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/path.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/refcount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/unicode.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `struct ksmbd_share_config {`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `	char			*name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	char			*path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	unsigned int		path_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `	unsigned int		flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	struct list_head	veto_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	struct path		vfs_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [LIFETIME|] `	refcount_t		refcount;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00029 [NONE] `	struct hlist_node	hlist;`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [LIFETIME|] `	struct rcu_head		rcu_head;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00031 [NONE] `	unsigned short		create_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	unsigned short		directory_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	unsigned short		force_create_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	unsigned short		force_directory_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	unsigned short		force_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	unsigned short		force_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	unsigned long long	time_machine_max_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#define KSMBD_SHARE_INVALID_UID	((__u16)-1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#define KSMBD_SHARE_INVALID_GID	((__u16)-1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `static inline umode_t`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `share_config_create_mode(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `			 umode_t posix_mode)`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	umode_t mode = (posix_mode ?: (umode_t)-1) & share->create_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	return mode | share->force_create_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `static inline umode_t`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `share_config_directory_mode(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `			    umode_t posix_mode)`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	umode_t mode = (posix_mode ?: (umode_t)-1) & share->directory_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	return mode | share->force_directory_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `static inline int test_share_config_flag(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `					 int flag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	return share->flags & flag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `void ksmbd_share_config_del(struct ksmbd_share_config *share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `void __ksmbd_share_config_put(struct ksmbd_share_config *share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `static inline void ksmbd_share_config_put(struct ksmbd_share_config *share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [LIFETIME|] `	if (!refcount_dec_and_test(&share->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00073 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	__ksmbd_share_config_put(share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `struct ksmbd_share_config *ksmbd_share_config_get(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `						  const char *name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `bool ksmbd_share_veto_filename(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `			       const char *filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `#endif /* __SHARE_CONFIG_MANAGEMENT_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
