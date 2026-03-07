# Line-by-line Review: src/mgmt/user_config.c

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
- L00006 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/mm.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <crypto/algapi.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `struct ksmbd_user *ksmbd_login_user(const char *account)`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `	struct ksmbd_login_response *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `	struct ksmbd_login_response_ext *resp_ext = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `	struct ksmbd_user *user = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `	resp = ksmbd_ipc_login_request(account);`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	if (!resp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `	if (!(resp->status & KSMBD_USER_FLAG_OK))`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	if (resp->status & KSMBD_USER_FLAG_EXTENSION)`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `		resp_ext = ksmbd_ipc_login_request_ext(account);`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	user = ksmbd_alloc_user(resp, resp_ext);`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	kvfree(resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	return user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `struct ksmbd_user *ksmbd_alloc_user(struct ksmbd_login_response *resp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `		struct ksmbd_login_response_ext *resp_ext)`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	struct ksmbd_user *user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [MEM_BOUNDS|] `	user = kmalloc(sizeof(struct ksmbd_user), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00041 [NONE] `	if (!user)`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	user->name = kstrdup(resp->account, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	user->flags = resp->status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	user->gid = resp->gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	user->uid = resp->uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	user->passkey_sz = resp->hash_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [MEM_BOUNDS|] `	user->passkey = kmalloc(resp->hash_sz, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00050 [NONE] `	if (user->passkey)`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [MEM_BOUNDS|] `		memcpy(user->passkey, resp->hash, resp->hash_sz);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	user->ngroups = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	user->sgid = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	if (!user->name || !user->passkey)`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	if (resp_ext) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `		if (resp_ext->ngroups > NGROUPS_MAX) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [ERROR_PATH|] `			pr_err("ngroups(%u) from login response exceeds max groups(%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00062 [NONE] `					resp_ext->ngroups, NGROUPS_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [ERROR_PATH|] `			goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00064 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `		user->sgid = kmemdup(resp_ext->____payload,`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `				     resp_ext->ngroups * sizeof(gid_t),`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `				     KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `		if (!user->sgid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [ERROR_PATH|] `			goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `		user->ngroups = resp_ext->ngroups;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `		ksmbd_debug(SMB, "supplementary groups : %d\n", user->ngroups);`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	return user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `err_free:`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	kfree(user->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	kfree(user->passkey);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	kfree(user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `void ksmbd_free_user(struct ksmbd_user *user)`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	ksmbd_ipc_logout_request(user->name, user->flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	kfree(user->sgid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	kfree(user->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	kfree_sensitive(user->passkey);`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	kfree(user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `int ksmbd_anonymous_user(struct ksmbd_user *user)`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	if (user->name[0] == '\0')`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `bool ksmbd_compare_user(struct ksmbd_user *u1, struct ksmbd_user *u2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	if (strcmp(u1->name, u2->name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	if (u1->passkey_sz != u2->passkey_sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	if (crypto_memneq(u1->passkey, u2->passkey, u1->passkey_sz))`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
