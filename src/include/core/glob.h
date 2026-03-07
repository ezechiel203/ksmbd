/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __KSMBD_GLOB_H
#define __KSMBD_GLOB_H

#include <linux/ctype.h>
#include <linux/limits.h>

#include "unicode.h"
#include "vfs_cache.h"

#define KSMBD_VERSION	"4.2.18"

extern int ksmbd_debug_types;

#define KSMBD_DEBUG_SMB		BIT(0)
#define KSMBD_DEBUG_AUTH	BIT(1)
#define KSMBD_DEBUG_VFS		BIT(2)
#define KSMBD_DEBUG_OPLOCK      BIT(3)
#define KSMBD_DEBUG_IPC         BIT(4)
#define KSMBD_DEBUG_CONN        BIT(5)
#define KSMBD_DEBUG_RDMA        BIT(6)
#define KSMBD_DEBUG_ALL         (KSMBD_DEBUG_SMB | KSMBD_DEBUG_AUTH |	\
				KSMBD_DEBUG_VFS | KSMBD_DEBUG_OPLOCK |	\
				KSMBD_DEBUG_IPC | KSMBD_DEBUG_CONN |	\
				KSMBD_DEBUG_RDMA)

#ifdef pr_fmt
#undef pr_fmt
#endif

#ifdef SUBMOD_NAME
#define pr_fmt(fmt)	"ksmbd: " SUBMOD_NAME ": " fmt
#else
#define pr_fmt(fmt)	"ksmbd: " fmt
#endif

#define ksmbd_debug(type, fmt, ...)				\
	do {							\
		if (ksmbd_debug_types & KSMBD_DEBUG_##type)	\
			pr_info(fmt, ##__VA_ARGS__);		\
	} while (0)

#define ksmbd_audit(fmt, ...) \
	pr_notice("ksmbd[audit]: " fmt "\n", ##__VA_ARGS__)

static inline size_t unicode_byte_len(size_t char_count)
{
	if (char_count > SIZE_MAX / 2)
		return SIZE_MAX;
	return char_count * 2;
}
#define UNICODE_LEN(x)		unicode_byte_len(x)

#ifdef CONFIG_SMB_INSECURE_SERVER
/* ksmbd misc functions */
extern void ntstatus_to_dos(__le32 ntstatus, __u8 *eclass, __le16 *ecode);
#endif

/*
 * WARNING: LOOKUP_NO_SYMLINKS is required to prevent symlink-based path
 * traversal attacks.  On kernels that lack this flag (< 5.10), it falls
 * back to 0, meaning symlink following is NOT blocked.  This is a known
 * security limitation on older kernels; administrators must ensure that
 * exported share paths do not contain attacker-controlled symlinks.
 */
#ifndef LOOKUP_NO_SYMLINKS
#warning "LOOKUP_NO_SYMLINKS not available - symlink protection disabled"
#define LOOKUP_NO_SYMLINKS 0
#endif

#define KSMBD_DEFAULT_GFP	(GFP_KERNEL | __GFP_RETRY_MAYFAIL)

#endif /* __KSMBD_GLOB_H */
