# Line-by-line Review: src/mgmt/user_config.h

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
- L00006 [NONE] `#ifndef __USER_CONFIG_MANAGEMENT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __USER_CONFIG_MANAGEMENT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `struct ksmbd_user {`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `	unsigned short		flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `	unsigned int		uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `	unsigned int		gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `	char			*name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `	size_t			passkey_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	char			*passkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `	int			ngroups;`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	gid_t			*sgid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `static inline bool user_guest(struct ksmbd_user *user)`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	return user->flags & KSMBD_USER_FLAG_GUEST_ACCOUNT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `static inline void set_user_flag(struct ksmbd_user *user, int flag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	user->flags |= flag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `static inline int test_user_flag(struct ksmbd_user *user, int flag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	return user->flags & flag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `static inline void set_user_guest(struct ksmbd_user *user)`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `static inline char *user_passkey(struct ksmbd_user *user)`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	return user->passkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `static inline char *user_name(struct ksmbd_user *user)`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	return user->name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `static inline unsigned int user_uid(struct ksmbd_user *user)`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	return user->uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `static inline unsigned int user_gid(struct ksmbd_user *user)`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	return user->gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `struct ksmbd_user *ksmbd_login_user(const char *account);`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `struct ksmbd_user *ksmbd_alloc_user(struct ksmbd_login_response *resp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `		struct ksmbd_login_response_ext *resp_ext);`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `void ksmbd_free_user(struct ksmbd_user *user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `int ksmbd_anonymous_user(struct ksmbd_user *user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `bool ksmbd_compare_user(struct ksmbd_user *u1, struct ksmbd_user *u2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#endif /* __USER_CONFIG_MANAGEMENT_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
