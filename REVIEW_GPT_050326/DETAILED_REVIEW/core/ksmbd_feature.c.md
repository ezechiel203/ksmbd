# Line-by-line Review: src/core/ksmbd_feature.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Three-tier feature negotiation framework.`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include "ksmbd_feature.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * ksmbd_feature_global_enabled() - check if a feature is globally enabled`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` * @feat:	feature to check`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` * Tier 2 of the three-tier feature negotiation.  Checks whether the`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * given feature is enabled server-wide via the admin configuration`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` * bitmask in server_conf.features.`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * Return:	true if globally enabled, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `bool ksmbd_feature_global_enabled(enum ksmbd_feature feat)`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	if (feat >= __KSMBD_FEAT_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	return test_bit(feat, &server_conf.features);`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` * ksmbd_feat_enabled() - full three-tier feature check`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` * @conn:	connection to check (may be NULL for global-only check)`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` * @feat:	feature to check`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` * Checks all three tiers of feature negotiation:`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` *   Tier 1: Is the feature compiled in?`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` *   Tier 2: Is the feature enabled server-wide?`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *   Tier 3: Was the feature negotiated for this connection?`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` * If @conn is NULL, only tiers 1 and 2 are checked.`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * Return:	true if the feature is available, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `bool ksmbd_feat_enabled(struct ksmbd_conn *conn, enum ksmbd_feature feat)`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	/* Tier 1: compiled in? */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	if (!ksmbd_feature_compiled(feat))`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	/* Tier 2: globally enabled? */`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	if (!ksmbd_feature_global_enabled(feat))`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	/* Tier 3: per-connection negotiated? */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	if (conn && !test_bit(feat, &conn->features))`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
