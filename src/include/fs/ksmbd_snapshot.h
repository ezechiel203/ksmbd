/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Snapshot path resolution for TWRP (Time-Warp Request).
 *
 *   This header exposes the shadow_copy2-compatible snapshot path
 *   resolver.  Actual snapshot enumeration and @GMT token resolution
 *   is handled by the pluggable VSS backend subsystem in ksmbd_vss.c.
 *
 *   To use snapshots, configure the share with a .snapshots/ directory
 *   (btrfs/snapper) or .zfs/snapshot/ directory (ZFS).  Each snapshot
 *   sub-directory should be named with an @GMT or ISO timestamp.
 *
 *   This is compatible with samba's shadow_copy2 module format.
 */

#ifndef __KSMBD_SNAPSHOT_H
#define __KSMBD_SNAPSHOT_H

#include <linux/types.h>
#include <linux/time64.h>

struct ksmbd_share_config;

/**
 * ksmbd_snapshot_resolve_path() - Map a share-relative path to snapshot path
 * @share:    share configuration
 * @filename: share-relative filename to open
 * @timewarp: requested snapshot timestamp (tv_sec == 0 means no snapshot)
 * @snap_path: output buffer for resolved path (must be PATH_MAX bytes)
 *
 * Delegates to the VSS backend subsystem (ksmbd_vss_resolve_path) after
 * converting the timespec64 to an @GMT token.
 *
 * Returns 0 on success (snap_path filled), -ENOENT if no matching snapshot,
 * -EOPNOTSUPP if shadow copy not configured on this share.
 */
int ksmbd_snapshot_resolve_path(struct ksmbd_share_config *share,
				const char *filename,
				struct timespec64 timewarp,
				char *snap_path);

#endif /* __KSMBD_SNAPSHOT_H */
