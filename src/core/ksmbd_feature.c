// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Three-tier feature negotiation framework.
 */

#include "ksmbd_feature.h"
#include "server.h"
#include "connection.h"

/**
 * ksmbd_feature_global_enabled() - check if a feature is globally enabled
 * @feat:	feature to check
 *
 * Tier 2 of the three-tier feature negotiation.  Checks whether the
 * given feature is enabled server-wide via the admin configuration
 * bitmask in server_conf.features.
 *
 * Return:	true if globally enabled, false otherwise
 */
bool ksmbd_feature_global_enabled(enum ksmbd_feature feat)
{
	if (feat >= __KSMBD_FEAT_MAX)
		return false;

	return test_bit(feat, &server_conf.features);
}

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
bool ksmbd_feat_enabled(struct ksmbd_conn *conn, enum ksmbd_feature feat)
{
	/* Tier 1: compiled in? */
	if (!ksmbd_feature_compiled(feat))
		return false;

	/* Tier 2: globally enabled? */
	if (!ksmbd_feature_global_enabled(feat))
		return false;

	/* Tier 3: per-connection negotiated? */
	if (conn && !test_bit(feat, &conn->features))
		return false;

	return true;
}
