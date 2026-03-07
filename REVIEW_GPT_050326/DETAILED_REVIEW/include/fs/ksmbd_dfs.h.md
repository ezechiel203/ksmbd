# Line-by-line Review: src/include/fs/ksmbd_dfs.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   DFS referral support for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#ifndef __KSMBD_DFS_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#define __KSMBD_DFS_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `/* DFS referral server types ([MS-DFSC] 2.2.5.3) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#define DFS_SERVER_ROOT		0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#define DFS_SERVER_LINK		0x0000`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `/* DFS referral entry flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define DFS_REFERRAL_FLAG_TARGET_SET	0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `/* DFS referral entry from userspace */`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `struct ksmbd_dfs_referral {`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	char		*path;		/* DFS path */`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	char		*target;	/* Target share path */`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	u16		server_type;	/* Root or link referral */`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	u16		flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	u32		ttl;		/* Time to live in seconds */`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `struct ksmbd_dfs_referral_list {`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	unsigned int			count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	struct ksmbd_dfs_referral	*entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * ksmbd_dfs_init() - Initialize DFS referral subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * Registers FSCTL handlers for FSCTL_DFS_GET_REFERRALS and`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` * FSCTL_DFS_GET_REFERRALS_EX.  Must be called during module`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * initialization after ksmbd_fsctl_init().`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `int ksmbd_dfs_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` * ksmbd_dfs_exit() - Tear down DFS referral subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` * Unregisters FSCTL handlers and releases resources.`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` * Must be called during module exit.`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `void ksmbd_dfs_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` * ksmbd_dfs_enabled() - Check if DFS is globally enabled`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ` * Queries the three-tier feature framework to determine whether`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ` * DFS referral support is available and enabled.`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` * Return: true if DFS is enabled, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `bool ksmbd_dfs_enabled(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#endif /* __KSMBD_DFS_H */`
  Review: Low-risk line; verify in surrounding control flow.
