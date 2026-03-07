// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Snapshot path resolution for TWRP (Time-Warp Request).
 *
 *   This module provides the high-level shadow_copy2-compatible path
 *   resolver used by the SMB2 CREATE handler when a client sends a
 *   TimewarpToken create context (MS-SMB2 §3.3.5.9.5).
 *
 *   The actual snapshot enumeration and directory scanning is handled
 *   by the pluggable VSS backend subsystem in ksmbd_vss.c.
 *
 *   Snapshot path resolution for TWRP (Time-Warp Request).
 *
 *   To use snapshots, configure the share with:
 *     shadow copy dir = /path/to/.snapshots
 *   Each snapshot is a directory named by ISO timestamp:
 *     /path/to/.snapshots/2024-01-15T120000Z/
 *   containing a full or partial copy of the share path.
 *
 *   This is compatible with samba's shadow_copy2 module format.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/time64.h>

#include "glob.h"
#include "ksmbd_snapshot.h"
#include "ksmbd_vss.h"
#include "mgmt/share_config.h"

/**
 * ksmbd_snapshot_resolve_path() - Map a share-relative path to snapshot path
 * @share:     share configuration
 * @filename:  share-relative filename to open
 * @timewarp:  requested snapshot timestamp (tv_sec == 0 means no snapshot)
 * @snap_path: output buffer for resolved path (must be PATH_MAX bytes)
 *
 * Converts the timespec64 @timewarp timestamp to an @GMT token string,
 * then delegates resolution to the VSS backend via ksmbd_vss_resolve_path().
 *
 * Returns:
 *   0          - success, @snap_path filled with the resolved filesystem path
 *   -EOPNOTSUPP - no snapshot support available for this share
 *   -ENOENT    - no snapshot matching the requested timestamp
 *   -ENOMEM    - allocation failure
 */
int ksmbd_snapshot_resolve_path(struct ksmbd_share_config *share,
				const char *filename,
				struct timespec64 timewarp,
				char *snap_path)
{
	char gmt_token[KSMBD_VSS_GMT_TOKEN_LEN];
	struct tm tm;
	int ret;

	if (!timewarp.tv_sec)
		return -EOPNOTSUPP;

	if (!share || !share->path)
		return -EOPNOTSUPP;

	/* Convert Unix timestamp to @GMT token */
	time64_to_tm(timewarp.tv_sec, 0, &tm);
	snprintf(gmt_token, sizeof(gmt_token),
		 "@GMT-%04ld.%02d.%02d-%02d.%02d.%02d",
		 tm.tm_year + 1900,
		 tm.tm_mon + 1, tm.tm_mday,
		 tm.tm_hour, tm.tm_min, tm.tm_sec);

	ret = ksmbd_vss_resolve_path(share->path, gmt_token,
				     snap_path, PATH_MAX);
	if (ret == -ENOENT)
		return -ENOENT;
	if (ret)
		return -EOPNOTSUPP;

	ksmbd_debug(VFS, "snapshot: resolved %s@%s -> %s\n",
		    filename ? filename : "(root)", gmt_token, snap_path);
	return 0;
}
