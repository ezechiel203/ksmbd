/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __KSMBD_FEATURE_H
#define __KSMBD_FEATURE_H

#include <linux/bitops.h>
#include <linux/types.h>

/**
 * enum ksmbd_feature - Server feature flags
 *
 * Each feature has a compile-time guard, a global enable,
 * and a per-connection negotiation state.  Use ksmbd_feat_enabled()
 * to check all three tiers.
 */
enum ksmbd_feature {
	KSMBD_FEAT_LEASING,
	KSMBD_FEAT_MULTICHANNEL,
	KSMBD_FEAT_ENCRYPTION,
	KSMBD_FEAT_DURABLE_HANDLE,
	KSMBD_FEAT_FRUIT,
	KSMBD_FEAT_DFS,
	KSMBD_FEAT_VSS,
	KSMBD_FEAT_COMPRESSION,
	KSMBD_FEAT_SIGNING,
	__KSMBD_FEAT_MAX,
};

/**
 * ksmbd_feature_compiled() - check if a feature is compiled in
 * @feat:	feature to check
 *
 * Tier 1 of the three-tier feature negotiation.  Returns true if the
 * feature is available at compile time.
 *
 * Return:	true if compiled in, false otherwise
 */
static inline bool ksmbd_feature_compiled(enum ksmbd_feature feat)
{
	switch (feat) {
	case KSMBD_FEAT_LEASING:
	case KSMBD_FEAT_MULTICHANNEL:
	case KSMBD_FEAT_ENCRYPTION:
	case KSMBD_FEAT_DURABLE_HANDLE:
	case KSMBD_FEAT_DFS:
	case KSMBD_FEAT_VSS:
	case KSMBD_FEAT_COMPRESSION:
	case KSMBD_FEAT_SIGNING:
		return true;
	case KSMBD_FEAT_FRUIT:
#ifdef CONFIG_KSMBD_FRUIT
		return true;
#else
		return false;
#endif
	default:
		return false;
	}
}

struct ksmbd_conn;

/**
 * ksmbd_feature_global_enabled() - check if a feature is globally enabled
 * @feat:	feature to check
 *
 * Tier 2 of the three-tier feature negotiation.  Returns true if the
 * feature is enabled server-wide via admin configuration.
 *
 * Return:	true if globally enabled, false otherwise
 */
bool ksmbd_feature_global_enabled(enum ksmbd_feature feat);

/**
 * ksmbd_feat_enabled() - full three-tier feature check
 * @conn:	connection to check (may be NULL for global-only check)
 * @feat:	feature to check
 *
 * Checks all three tiers of feature negotiation:
 *   Tier 1: Is the feature compiled in?
 *   Tier 2: Is the feature enabled server-wide?
 *   Tier 3: Was the feature negotiated for this connection?
 *
 * If @conn is NULL, only tiers 1 and 2 are checked.
 *
 * Return:	true if the feature is available, false otherwise
 */
bool ksmbd_feat_enabled(struct ksmbd_conn *conn, enum ksmbd_feature feat);

#endif /* __KSMBD_FEATURE_H */
