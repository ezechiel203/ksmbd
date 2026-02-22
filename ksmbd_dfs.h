/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   DFS referral support for ksmbd
 */

#ifndef __KSMBD_DFS_H
#define __KSMBD_DFS_H

#include <linux/types.h>

struct ksmbd_work;

/* DFS referral server types ([MS-DFSC] 2.2.5.3) */
#define DFS_SERVER_ROOT		0x0001
#define DFS_SERVER_LINK		0x0000

/* DFS referral entry flags */
#define DFS_REFERRAL_FLAG_TARGET_SET	0x0001

/* DFS referral entry from userspace */
struct ksmbd_dfs_referral {
	char		*path;		/* DFS path */
	char		*target;	/* Target share path */
	u16		server_type;	/* Root or link referral */
	u16		flags;
	u32		ttl;		/* Time to live in seconds */
};

struct ksmbd_dfs_referral_list {
	unsigned int			count;
	struct ksmbd_dfs_referral	*entries;
};

/**
 * ksmbd_dfs_init() - Initialize DFS referral subsystem
 *
 * Registers FSCTL handlers for FSCTL_DFS_GET_REFERRALS and
 * FSCTL_DFS_GET_REFERRALS_EX.  Must be called during module
 * initialization after ksmbd_fsctl_init().
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_dfs_init(void);

/**
 * ksmbd_dfs_exit() - Tear down DFS referral subsystem
 *
 * Unregisters FSCTL handlers and releases resources.
 * Must be called during module exit.
 */
void ksmbd_dfs_exit(void);

/**
 * ksmbd_dfs_enabled() - Check if DFS is globally enabled
 *
 * Queries the three-tier feature framework to determine whether
 * DFS referral support is available and enabled.
 *
 * Return: true if DFS is enabled, false otherwise
 */
bool ksmbd_dfs_enabled(void);

#endif /* __KSMBD_DFS_H */
