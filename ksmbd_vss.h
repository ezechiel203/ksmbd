/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   VSS/snapshot support for ksmbd -- enables Windows "Previous Versions"
 *   tab.  Provides a pluggable backend API for enumerating filesystem
 *   snapshots (btrfs, ZFS, generic) and resolving @GMT tokens to
 *   snapshot paths.
 */

#ifndef __KSMBD_VSS_H
#define __KSMBD_VSS_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/module.h>

struct ksmbd_work;

/* @GMT-YYYY.MM.DD-HH.MM.SS format: 24 chars + NUL */
#define KSMBD_VSS_GMT_TOKEN_LEN		25

/**
 * struct ksmbd_snapshot_entry - Single snapshot timestamp
 * @gmt_token:	GMT token string (@GMT-YYYY.MM.DD-HH.MM.SS)
 * @timestamp:	Unix timestamp corresponding to the snapshot
 */
struct ksmbd_snapshot_entry {
	char gmt_token[KSMBD_VSS_GMT_TOKEN_LEN];
	u64 timestamp;
};

/**
 * struct ksmbd_snapshot_list - List of snapshots for a share
 * @count:	Number of entries in @entries
 * @entries:	Array of snapshot entries (caller must free with kvfree)
 */
struct ksmbd_snapshot_list {
	unsigned int count;
	struct ksmbd_snapshot_entry *entries;
};

/**
 * struct ksmbd_snapshot_backend - Snapshot filesystem backend
 * @name:		Backend name (e.g., "btrfs", "zfs", "generic")
 * @enumerate:		List available snapshots for a share path
 * @resolve_path:	Resolve a @GMT token to an actual filesystem path
 * @list:		Linkage in the global backend list
 *
 * Each filesystem that supports snapshots registers a backend.
 * The first backend whose enumerate() returns successfully is used.
 */
struct ksmbd_snapshot_backend {
	const char *name;
	int (*enumerate)(const char *share_path,
			 struct ksmbd_snapshot_list *list);
	int (*resolve_path)(const char *share_path,
			    const char *gmt_token,
			    char *resolved, size_t len);
	struct list_head list;
};

/**
 * ksmbd_vss_register_backend() - Register a snapshot backend
 * @be: backend descriptor (caller must keep alive until unregistered)
 *
 * Return: 0 on success, -EEXIST if a backend with the same name
 *         is already registered.
 */
int ksmbd_vss_register_backend(struct ksmbd_snapshot_backend *be);

/**
 * ksmbd_vss_unregister_backend() - Unregister a snapshot backend
 * @be: backend descriptor previously registered
 */
void ksmbd_vss_unregister_backend(struct ksmbd_snapshot_backend *be);

/**
 * ksmbd_vss_resolve_path() - Resolve a @GMT token to a real path
 * @share_path:	Share root path on the filesystem
 * @gmt_token:	GMT token string (@GMT-YYYY.MM.DD-HH.MM.SS)
 * @resolved:	Output buffer for the resolved path
 * @len:	Size of @resolved buffer
 *
 * Iterates registered backends until one successfully resolves.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_vss_resolve_path(const char *share_path,
			   const char *gmt_token,
			   char *resolved, size_t len);

/**
 * ksmbd_vss_init() - Initialize VSS subsystem
 *
 * Registers built-in backends and the FSCTL handler for
 * FSCTL_SRV_ENUMERATE_SNAPSHOTS.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_vss_init(void);

/**
 * ksmbd_vss_exit() - Tear down VSS subsystem
 *
 * Unregisters the FSCTL handler and all built-in backends.
 */
void ksmbd_vss_exit(void);

#endif /* __KSMBD_VSS_H */
