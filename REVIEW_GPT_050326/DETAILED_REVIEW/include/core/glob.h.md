# Line-by-line Review: src/include/core/glob.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#ifndef __KSMBD_GLOB_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define __KSMBD_GLOB_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/ctype.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/limits.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "unicode.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#define KSMBD_VERSION	"3.5.4"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `extern int ksmbd_debug_types;`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#define KSMBD_DEBUG_SMB		BIT(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define KSMBD_DEBUG_AUTH	BIT(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define KSMBD_DEBUG_VFS		BIT(2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#define KSMBD_DEBUG_OPLOCK      BIT(3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#define KSMBD_DEBUG_IPC         BIT(4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#define KSMBD_DEBUG_CONN        BIT(5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#define KSMBD_DEBUG_RDMA        BIT(6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define KSMBD_DEBUG_ALL         (KSMBD_DEBUG_SMB | KSMBD_DEBUG_AUTH |	\`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `				KSMBD_DEBUG_VFS | KSMBD_DEBUG_OPLOCK |	\`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `				KSMBD_DEBUG_IPC | KSMBD_DEBUG_CONN |	\`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `				KSMBD_DEBUG_RDMA)`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#ifdef pr_fmt`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#undef pr_fmt`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#ifdef SUBMOD_NAME`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#define pr_fmt(fmt)	"ksmbd: " SUBMOD_NAME ": " fmt`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define pr_fmt(fmt)	"ksmbd: " fmt`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#define ksmbd_debug(type, fmt, ...)				\`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	do {							\`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `		if (ksmbd_debug_types & KSMBD_DEBUG_##type)	\`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `			pr_info(fmt, ##__VA_ARGS__);		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	} while (0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `static inline size_t unicode_byte_len(size_t char_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	if (char_count > SIZE_MAX / 2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `		return SIZE_MAX;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	return char_count * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#define UNICODE_LEN(x)		unicode_byte_len(x)`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `/* ksmbd misc functions */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `extern void ntstatus_to_dos(__le32 ntstatus, __u8 *eclass, __le16 *ecode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` * WARNING: LOOKUP_NO_SYMLINKS is required to prevent symlink-based path`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * traversal attacks.  On kernels that lack this flag (< 5.10), it falls`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * back to 0, meaning symlink following is NOT blocked.  This is a known`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * security limitation on older kernels; administrators must ensure that`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * exported share paths do not contain attacker-controlled symlinks.`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `#ifndef LOOKUP_NO_SYMLINKS`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `#warning "LOOKUP_NO_SYMLINKS not available - symlink protection disabled"`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#define LOOKUP_NO_SYMLINKS 0`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `#define KSMBD_DEFAULT_GFP	(GFP_KERNEL | __GFP_RETRY_MAYFAIL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `#endif /* __KSMBD_GLOB_H */`
  Review: Low-risk line; verify in surrounding control flow.
