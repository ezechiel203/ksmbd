# Line-by-line Review: src/include/core/ksmbd_feature.h

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
- L00007 [NONE] `#ifndef __KSMBD_FEATURE_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define __KSMBD_FEATURE_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/bitops.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * enum ksmbd_feature - Server feature flags`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` * Each feature has a compile-time guard, a global enable,`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` * and a per-connection negotiation state.  Use ksmbd_feat_enabled()`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * to check all three tiers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `enum ksmbd_feature {`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `	KSMBD_FEAT_LEASING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	KSMBD_FEAT_MULTICHANNEL,`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `	KSMBD_FEAT_ENCRYPTION,`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	KSMBD_FEAT_DURABLE_HANDLE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	KSMBD_FEAT_FRUIT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	KSMBD_FEAT_DFS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	KSMBD_FEAT_VSS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	KSMBD_FEAT_COMPRESSION,`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	KSMBD_FEAT_SIGNING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	__KSMBD_FEAT_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` * ksmbd_feature_compiled() - check if a feature is compiled in`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` * @feat:	feature to check`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` * Tier 1 of the three-tier feature negotiation.  Returns true if the`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * feature is available at compile time.`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * Return:	true if compiled in, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `static inline bool ksmbd_feature_compiled(enum ksmbd_feature feat)`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	switch (feat) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	case KSMBD_FEAT_LEASING:`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	case KSMBD_FEAT_MULTICHANNEL:`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	case KSMBD_FEAT_ENCRYPTION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	case KSMBD_FEAT_DURABLE_HANDLE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	case KSMBD_FEAT_DFS:`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	case KSMBD_FEAT_VSS:`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	case KSMBD_FEAT_COMPRESSION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	case KSMBD_FEAT_SIGNING:`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	case KSMBD_FEAT_FRUIT:`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `struct ksmbd_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` * ksmbd_feature_global_enabled() - check if a feature is globally enabled`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` * @feat:	feature to check`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` * Tier 2 of the three-tier feature negotiation.  Returns true if the`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` * feature is enabled server-wide via admin configuration.`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * Return:	true if globally enabled, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `bool ksmbd_feature_global_enabled(enum ksmbd_feature feat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` * ksmbd_feat_enabled() - full three-tier feature check`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` * @conn:	connection to check (may be NULL for global-only check)`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ` * @feat:	feature to check`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` * Checks all three tiers of feature negotiation:`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ` *   Tier 1: Is the feature compiled in?`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ` *   Tier 2: Is the feature enabled server-wide?`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ` *   Tier 3: Was the feature negotiated for this connection?`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ` * If @conn is NULL, only tiers 1 and 2 are checked.`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` * Return:	true if the feature is available, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `bool ksmbd_feat_enabled(struct ksmbd_conn *conn, enum ksmbd_feature feat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `#endif /* __KSMBD_FEATURE_H */`
  Review: Low-risk line; verify in surrounding control flow.
