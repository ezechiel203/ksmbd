// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   VSS/snapshot support for ksmbd
 *
 *   Implements FSCTL_SRV_ENUMERATE_SNAPSHOTS and pluggable snapshot
 *   backends (btrfs, ZFS, generic) to enable the Windows "Previous
 *   Versions" tab for files served over SMB.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/version.h>

#include "glob.h"
#include "ksmbd_vss.h"
#include "ksmbd_fsctl.h"
#include "smbfsctl.h"
#include "smb2pdu.h"
#include "vfs_cache.h"
#include "vfs.h"
#include "connection.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "ksmbd_work.h"

/* Maximum number of snapshots to enumerate */
#define KSMBD_VSS_MAX_SNAPSHOTS		256

/*
 * SRV_SNAPSHOT_ARRAY response header (MS-SMB2 2.2.32.2)
 */
struct srv_snapshot_array {
	__le32 number_of_snapshots;
	__le32 number_of_snapshots_returned;
	__le32 snapshot_array_size;
} __packed;

/* ------------------------------------------------------------------ */
/*  Backend registry                                                   */
/* ------------------------------------------------------------------ */

static DEFINE_MUTEX(vss_backend_lock);
static LIST_HEAD(vss_backend_list);

/**
 * ksmbd_vss_register_backend() - Register a snapshot backend
 * @be: backend descriptor
 *
 * Return: 0 on success, -EEXIST if already registered
 */
int ksmbd_vss_register_backend(struct ksmbd_snapshot_backend *be)
{
	struct ksmbd_snapshot_backend *cur;

	if (!be || !be->name || !be->enumerate)
		return -EINVAL;

	mutex_lock(&vss_backend_lock);
	list_for_each_entry(cur, &vss_backend_list, list) {
		if (!strcmp(cur->name, be->name)) {
			mutex_unlock(&vss_backend_lock);
			pr_err("VSS backend '%s' already registered\n",
			       be->name);
			return -EEXIST;
		}
	}
	list_add_tail(&be->list, &vss_backend_list);
	mutex_unlock(&vss_backend_lock);

	ksmbd_debug(VFS, "VSS backend '%s' registered\n", be->name);
	return 0;
}

/**
 * ksmbd_vss_unregister_backend() - Unregister a snapshot backend
 * @be: backend descriptor previously registered
 */
void ksmbd_vss_unregister_backend(struct ksmbd_snapshot_backend *be)
{
	if (!be)
		return;

	mutex_lock(&vss_backend_lock);
	list_del_init(&be->list);
	mutex_unlock(&vss_backend_lock);

	ksmbd_debug(VFS, "VSS backend '%s' unregistered\n", be->name);
}

/**
 * ksmbd_vss_resolve_path() - Resolve a @GMT token to a real path
 * @share_path:	Share root path on the filesystem
 * @gmt_token:	GMT token string
 * @resolved:	Output buffer
 * @len:	Size of output buffer
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_vss_resolve_path(const char *share_path,
			   const char *gmt_token,
			   char *resolved, size_t len)
{
	struct ksmbd_snapshot_backend *be;
	int ret = -ENOENT;

	mutex_lock(&vss_backend_lock);
	list_for_each_entry(be, &vss_backend_list, list) {
		if (!be->resolve_path)
			continue;
		ret = be->resolve_path(share_path, gmt_token,
				       resolved, len);
		if (!ret)
			break;
	}
	mutex_unlock(&vss_backend_lock);

	return ret;
}

/* ------------------------------------------------------------------ */
/*  Snapshot directory scanner                                         */
/* ------------------------------------------------------------------ */

/*
 * Context for iterate_dir callback when scanning snapshot directories.
 */
struct ksmbd_vss_scan_ctx {
	struct dir_context ctx;
	struct ksmbd_snapshot_list *list;
	unsigned int max_entries;
	int error;
};

/**
 * ksmbd_vss_is_gmt_token() - Validate a @GMT token string
 * @name: candidate string
 * @namlen: length of the string
 *
 * Checks the format @GMT-YYYY.MM.DD-HH.MM.SS (exactly 24 chars).
 *
 * Return: true if valid, false otherwise
 */
static bool ksmbd_vss_is_gmt_token(const char *name, int namlen)
{
	if (namlen != KSMBD_VSS_GMT_TOKEN_LEN - 1)
		return false;

	/* @GMT-YYYY.MM.DD-HH.MM.SS */
	return name[0] == '@' &&
	       name[1] == 'G' &&
	       name[2] == 'M' &&
	       name[3] == 'T' &&
	       name[4] == '-' &&
	       name[9] == '.' &&
	       name[12] == '.' &&
	       name[15] == '-' &&
	       name[18] == '.' &&
	       name[21] == '.';
}

/**
 * ksmbd_vss_parse_gmt_timestamp() - Parse @GMT token into Unix timestamp
 * @gmt_token: token string (must pass ksmbd_vss_is_gmt_token())
 *
 * Return: Unix timestamp, or 0 on parse error
 */
static u64 ksmbd_vss_parse_gmt_timestamp(const char *gmt_token)
{
	unsigned int year, month, day, hour, min, sec;
	int ret;

	/* @GMT-YYYY.MM.DD-HH.MM.SS */
	ret = sscanf(gmt_token, "@GMT-%4u.%2u.%2u-%2u.%2u.%2u",
		     &year, &month, &day, &hour, &min, &sec);
	if (ret != 6)
		return 0;

	return (u64)mktime64(year, month, day, hour, min, sec);
}

/**
 * ksmbd_vss_dirname_to_gmt() - Convert snapshot dir name to @GMT token
 * @dirname:	snapshot directory name (various formats supported)
 * @namlen:	length of @dirname
 * @entry:	output snapshot entry
 *
 * Supports the following naming conventions:
 *   - @GMT-YYYY.MM.DD-HH.MM.SS (pass-through)
 *   - YYYY-MM-DD_HH:MM:SS (common btrfs snapper format)
 *   - YYYY-MM-DD-HHMMSS (simple)
 *   - YYYY-MM-DD (date only, time defaults to 00:00:00)
 *
 * Return: 0 on success, -EINVAL if the name cannot be parsed
 */
static int ksmbd_vss_dirname_to_gmt(const char *dirname, int namlen,
				    struct ksmbd_snapshot_entry *entry)
{
	unsigned int year, month, day, hour = 0, min = 0, sec = 0;
	int ret;

	/* Already a @GMT token */
	if (ksmbd_vss_is_gmt_token(dirname, namlen)) {
		memcpy(entry->gmt_token, dirname,
		       KSMBD_VSS_GMT_TOKEN_LEN - 1);
		entry->gmt_token[KSMBD_VSS_GMT_TOKEN_LEN - 1] = '\0';
		entry->timestamp =
			ksmbd_vss_parse_gmt_timestamp(dirname);
		return 0;
	}

	/* Try YYYY-MM-DD_HH:MM:SS (snapper format) */
	ret = sscanf(dirname, "%4u-%2u-%2u_%2u:%2u:%2u",
		     &year, &month, &day, &hour, &min, &sec);
	if (ret == 6)
		goto format;

	/* Try YYYY-MM-DD-HHMMSS */
	ret = sscanf(dirname, "%4u-%2u-%2u-%2u%2u%2u",
		     &year, &month, &day, &hour, &min, &sec);
	if (ret == 6)
		goto format;

	/* Try YYYY-MM-DD (date only) */
	hour = 0;
	min = 0;
	sec = 0;
	ret = sscanf(dirname, "%4u-%2u-%2u",
		     &year, &month, &day);
	if (ret == 3)
		goto format;

	return -EINVAL;

format:
	/* Basic sanity checks */
	if (year < 1970 || year > 9999 || month < 1 || month > 12 ||
	    day < 1 || day > 31 || hour > 23 ||
	    min > 59 || sec > 59)
		return -EINVAL;

	snprintf(entry->gmt_token, KSMBD_VSS_GMT_TOKEN_LEN,
		 "@GMT-%04u.%02u.%02u-%02u.%02u.%02u",
		 year, month, day, hour, min, sec);
	entry->timestamp =
		(u64)mktime64(year, month, day, hour, min, sec);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Btrfs backend (.snapshots/ directory)                              */
/* ------------------------------------------------------------------ */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static bool ksmbd_vss_btrfs_filldir(struct dir_context *ctx,
				    const char *name, int namlen,
#else
static int ksmbd_vss_btrfs_filldir(struct dir_context *ctx,
				   const char *name, int namlen,
#endif
				   loff_t offset, u64 ino,
				   unsigned int d_type)
{
	struct ksmbd_vss_scan_ctx *scan_ctx;
	struct ksmbd_snapshot_entry *entry;

	scan_ctx = container_of(ctx, struct ksmbd_vss_scan_ctx, ctx);

	/* Skip . and .. */
	if (namlen <= 2 && name[0] == '.' &&
	    (namlen == 1 || name[1] == '.'))
		goto cont;

	/* Only interested in directories */
	if (d_type != DT_DIR && d_type != DT_UNKNOWN)
		goto cont;

	if (scan_ctx->list->count >= scan_ctx->max_entries)
		goto stop;

	entry = &scan_ctx->list->entries[scan_ctx->list->count];
	if (ksmbd_vss_dirname_to_gmt(name, namlen, entry))
		goto cont;

	scan_ctx->list->count++;

cont:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	return true;
#else
	return 0;
#endif
stop:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	return false;
#else
	return -ENOSPC;
#endif
}

/**
 * ksmbd_vss_scan_snap_dir() - Scan a snapshot directory for entries
 * @snap_dir_path:	Full path to the snapshot directory
 * @list:		Output snapshot list
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_vss_scan_snap_dir(const char *snap_dir_path,
				   struct ksmbd_snapshot_list *list)
{
	struct path snap_path;
	struct file *filp;
	struct ksmbd_vss_scan_ctx scan_ctx;
	int ret;

	ret = kern_path(snap_dir_path,
			LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&snap_path);
	if (ret)
		return ret;

	filp = dentry_open(&snap_path, O_RDONLY | O_DIRECTORY,
			   current_cred());
	path_put(&snap_path);
	if (IS_ERR(filp))
		return PTR_ERR(filp);

	list->entries = kvcalloc(KSMBD_VSS_MAX_SNAPSHOTS,
				 sizeof(*list->entries),
				 KSMBD_DEFAULT_GFP);
	if (!list->entries) {
		fput(filp);
		return -ENOMEM;
	}

	list->count = 0;

	memset(&scan_ctx, 0, sizeof(scan_ctx));
	scan_ctx.list = list;
	scan_ctx.max_entries = KSMBD_VSS_MAX_SNAPSHOTS;
	set_ctx_actor(&scan_ctx.ctx, ksmbd_vss_btrfs_filldir);

	ret = iterate_dir(filp, &scan_ctx.ctx);
	fput(filp);

	if (ret < 0 && ret != -ENOSPC) {
		kvfree(list->entries);
		list->entries = NULL;
		list->count = 0;
		return ret;
	}

	return 0;
}

/**
 * ksmbd_vss_btrfs_enumerate() - Enumerate btrfs snapshots
 * @share_path:	Share root path
 * @list:	Output snapshot list
 *
 * Looks for snapshots in share_path/.snapshots/ (snapper convention).
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_vss_btrfs_enumerate(const char *share_path,
				     struct ksmbd_snapshot_list *list)
{
	char *snap_dir;
	int ret;

	snap_dir = kasprintf(KSMBD_DEFAULT_GFP, "%s/.snapshots",
			     share_path);
	if (!snap_dir)
		return -ENOMEM;

	ret = ksmbd_vss_scan_snap_dir(snap_dir, list);
	kfree(snap_dir);
	return ret;
}

/**
 * ksmbd_vss_btrfs_resolve() - Resolve @GMT token for btrfs snapshots
 * @share_path:	Share root path
 * @gmt_token:	@GMT token to resolve
 * @resolved:	Output buffer for resolved path
 * @len:	Size of output buffer
 *
 * Return: 0 on success, -ENOENT if no matching snapshot
 */
static int ksmbd_vss_btrfs_resolve(const char *share_path,
				   const char *gmt_token,
				   char *resolved, size_t len)
{
	struct ksmbd_snapshot_list list = {};
	char *snap_dir;
	unsigned int i;
	int ret;

	snap_dir = kasprintf(KSMBD_DEFAULT_GFP, "%s/.snapshots",
			     share_path);
	if (!snap_dir)
		return -ENOMEM;

	ret = ksmbd_vss_scan_snap_dir(snap_dir, &list);
	if (ret) {
		kfree(snap_dir);
		return ret;
	}

	ret = -ENOENT;
	for (i = 0; i < list.count; i++) {
		if (!strncmp(list.entries[i].gmt_token, gmt_token,
			     KSMBD_VSS_GMT_TOKEN_LEN - 1)) {
			snprintf(resolved, len,
				 "%s/.snapshots/%s/snapshot",
				 share_path,
				 list.entries[i].gmt_token);
			ret = 0;
			break;
		}
	}

	kvfree(list.entries);
	kfree(snap_dir);
	return ret;
}

static struct ksmbd_snapshot_backend ksmbd_vss_btrfs_backend = {
	.name		= "btrfs",
	.enumerate	= ksmbd_vss_btrfs_enumerate,
	.resolve_path	= ksmbd_vss_btrfs_resolve,
};

/* ------------------------------------------------------------------ */
/*  ZFS backend (.zfs/snapshot/ directory)                             */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_vss_zfs_enumerate() - Enumerate ZFS snapshots
 * @share_path:	Share root path
 * @list:	Output snapshot list
 *
 * Looks for snapshots in share_path/.zfs/snapshot/.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_vss_zfs_enumerate(const char *share_path,
				   struct ksmbd_snapshot_list *list)
{
	char *snap_dir;
	int ret;

	snap_dir = kasprintf(KSMBD_DEFAULT_GFP,
			     "%s/.zfs/snapshot", share_path);
	if (!snap_dir)
		return -ENOMEM;

	ret = ksmbd_vss_scan_snap_dir(snap_dir, list);
	kfree(snap_dir);
	return ret;
}

/**
 * ksmbd_vss_zfs_resolve() - Resolve @GMT token for ZFS snapshots
 * @share_path:	Share root path
 * @gmt_token:	@GMT token to resolve
 * @resolved:	Output buffer for resolved path
 * @len:	Size of output buffer
 *
 * Return: 0 on success, -ENOENT if no matching snapshot
 */
static int ksmbd_vss_zfs_resolve(const char *share_path,
				 const char *gmt_token,
				 char *resolved, size_t len)
{
	struct ksmbd_snapshot_list list = {};
	char *snap_dir;
	unsigned int i;
	int ret;

	snap_dir = kasprintf(KSMBD_DEFAULT_GFP,
			     "%s/.zfs/snapshot", share_path);
	if (!snap_dir)
		return -ENOMEM;

	ret = ksmbd_vss_scan_snap_dir(snap_dir, &list);
	if (ret) {
		kfree(snap_dir);
		return ret;
	}

	ret = -ENOENT;
	for (i = 0; i < list.count; i++) {
		if (!strncmp(list.entries[i].gmt_token, gmt_token,
			     KSMBD_VSS_GMT_TOKEN_LEN - 1)) {
			snprintf(resolved, len,
				 "%s/.zfs/snapshot/%s",
				 share_path,
				 list.entries[i].gmt_token);
			ret = 0;
			break;
		}
	}

	kvfree(list.entries);
	kfree(snap_dir);
	return ret;
}

static struct ksmbd_snapshot_backend ksmbd_vss_zfs_backend = {
	.name		= "zfs",
	.enumerate	= ksmbd_vss_zfs_enumerate,
	.resolve_path	= ksmbd_vss_zfs_resolve,
};

/* ------------------------------------------------------------------ */
/*  Generic backend (configurable snapshot directory)                   */
/* ------------------------------------------------------------------ */

/*
 * The generic backend scans a .snapshots/ directory as a fallback.
 * It shares the same scan logic as the btrfs backend but can be
 * extended to support a configurable snapshot path in the future.
 */

static struct ksmbd_snapshot_backend ksmbd_vss_generic_backend = {
	.name		= "generic",
	.enumerate	= ksmbd_vss_btrfs_enumerate,
	.resolve_path	= ksmbd_vss_btrfs_resolve,
};

/* ------------------------------------------------------------------ */
/*  FSCTL handler: FSCTL_SRV_ENUMERATE_SNAPSHOTS                       */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_vss_enumerate_snapshots() - FSCTL handler for snapshot enum
 * @work:	    SMB work context
 * @id:		    Volatile file ID
 * @in_buf:	    Input buffer (unused for this FSCTL)
 * @in_buf_len:    Input buffer length
 * @max_out_len:   Maximum output length allowed
 * @rsp:	    Pointer to IOCTL response structure
 * @out_len:	    Output: number of bytes written
 *
 * Builds the SRV_SNAPSHOT_ARRAY response per MS-SMB2 2.2.32.2.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_vss_enumerate_snapshots(struct ksmbd_work *work,
					 u64 id, void *in_buf,
					 unsigned int in_buf_len,
					 unsigned int max_out_len,
					 struct smb2_ioctl_rsp *rsp,
					 unsigned int *out_len)
{
	struct ksmbd_tree_connect *tcon = work->tcon;
	struct ksmbd_share_config *share;
	struct srv_snapshot_array *snap_array;
	struct ksmbd_snapshot_list snap_list = {};
	struct ksmbd_snapshot_backend *be;
	unsigned int array_size = 0;
	unsigned int i, returned = 0;
	__le16 *utf16_ptr;
	int ret = -ENOENT;

	if (!tcon || !tcon->share_conf) {
		pr_err_ratelimited("VSS: no tree connection\n");
		return -EINVAL;
	}

	share = tcon->share_conf;
	if (!share->path) {
		pr_err_ratelimited("VSS: share has no path\n");
		return -EINVAL;
	}

	/* Need at least the header */
	if (max_out_len < sizeof(struct srv_snapshot_array))
		return -ENOSPC;

	/*
	 * VSS-02: Collect all enumerate function pointers under the lock
	 * into a local array, then call them without holding the lock.
	 * This prevents use-after-free if a backend is unregistered
	 * during the unlock window in the original mid-traversal pattern.
	 */
#define KSMBD_VSS_MAX_BACKENDS 8
	{
		int (*enum_fns[KSMBD_VSS_MAX_BACKENDS])(
			const char *, struct ksmbd_snapshot_list *);
		int fn_count = 0, i;

		mutex_lock(&vss_backend_lock);
		list_for_each_entry(be, &vss_backend_list, list) {
			if (fn_count < KSMBD_VSS_MAX_BACKENDS)
				enum_fns[fn_count++] = be->enumerate;
		}
		mutex_unlock(&vss_backend_lock);

		for (i = 0; i < fn_count; i++) {
			ret = enum_fns[i](share->path, &snap_list);
			if (!ret && snap_list.count > 0)
				goto found;
			/* Reset for next backend attempt */
			if (!ret && snap_list.entries) {
				kvfree(snap_list.entries);
				snap_list.entries = NULL;
				snap_list.count = 0;
			}
			ret = -ENOENT;
		}
	}
found:

	/*
	 * Per MS-SMB2: if no snapshots exist, return success
	 * with zero counts rather than an error.
	 */
	snap_array =
		(struct srv_snapshot_array *)&rsp->Buffer[0];

	if (ret || snap_list.count == 0) {
		snap_array->number_of_snapshots =
			cpu_to_le32(0);
		snap_array->number_of_snapshots_returned =
			cpu_to_le32(0);
		snap_array->snapshot_array_size =
			cpu_to_le32(0);
		*out_len = sizeof(struct srv_snapshot_array);
		return 0;
	}

	/*
	 * VSS-01: Calculate the array size needed.
	 * Each @GMT token on the wire is exactly 24 chars + NUL in UTF-16LE
	 * = KSMBD_VSS_GMT_WIRE_LEN * sizeof(__le16) = 50 bytes.
	 * Plus a final NUL terminator (2 bytes).
	 */
	array_size =
		snap_list.count * (KSMBD_VSS_GMT_WIRE_LEN * sizeof(__le16)) +
		sizeof(__le16);

	/*
	 * If the buffer is too small for the data, return just
	 * the header with total count and required size.
	 */
	if (max_out_len <
	    sizeof(struct srv_snapshot_array) + array_size) {
		snap_array->number_of_snapshots =
			cpu_to_le32(snap_list.count);
		snap_array->number_of_snapshots_returned =
			cpu_to_le32(0);
		snap_array->snapshot_array_size =
			cpu_to_le32(array_size);
		*out_len = sizeof(struct srv_snapshot_array);
		kvfree(snap_list.entries);
		return 0;
	}

	/* Write the UTF-16LE snapshot strings */
	utf16_ptr = (__le16 *)(snap_array + 1);

	for (i = 0; i < snap_list.count; i++) {
		const char *gmt = snap_list.entries[i].gmt_token;
		unsigned int j;

		/* Convert ASCII @GMT token to UTF-16LE (24 chars exactly) */
		for (j = 0; j < KSMBD_VSS_GMT_WIRE_CHARS; j++)
			utf16_ptr[j] = cpu_to_le16((u16)gmt[j]);
		/* NUL terminator */
		utf16_ptr[KSMBD_VSS_GMT_WIRE_CHARS] = cpu_to_le16(0);

		/* VSS-01: advance by wire stride (25 UTF-16LE elements) */
		utf16_ptr += KSMBD_VSS_GMT_WIRE_LEN;
		returned++;
	}

	/* Final NUL terminator for the array */
	*utf16_ptr = cpu_to_le16(0);

	snap_array->number_of_snapshots =
		cpu_to_le32(snap_list.count);
	snap_array->number_of_snapshots_returned =
		cpu_to_le32(returned);
	snap_array->snapshot_array_size =
		cpu_to_le32(array_size);

	*out_len =
		sizeof(struct srv_snapshot_array) + array_size;

	kvfree(snap_list.entries);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  FSCTL registration                                                 */
/* ------------------------------------------------------------------ */

static struct ksmbd_fsctl_handler vss_enumerate_handler = {
	.ctl_code = FSCTL_SRV_ENUMERATE_SNAPSHOTS,
	.handler  = ksmbd_vss_enumerate_snapshots,
	.owner    = THIS_MODULE,
};

/* ------------------------------------------------------------------ */
/*  Init / Exit                                                        */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_vss_init() - Initialize VSS subsystem
 *
 * Registers built-in snapshot backends and the FSCTL handler.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_vss_init(void)
{
	int ret;

	ret = ksmbd_vss_register_backend(&ksmbd_vss_btrfs_backend);
	if (ret)
		return ret;

	ret = ksmbd_vss_register_backend(&ksmbd_vss_zfs_backend);
	if (ret)
		goto err_unreg_btrfs;

	ret = ksmbd_vss_register_backend(&ksmbd_vss_generic_backend);
	if (ret)
		goto err_unreg_zfs;

	ret = ksmbd_register_fsctl(&vss_enumerate_handler);
	if (ret)
		goto err_unreg_generic;

	ksmbd_debug(SMB, "VSS subsystem initialized\n");
	return 0;

err_unreg_generic:
	ksmbd_vss_unregister_backend(&ksmbd_vss_generic_backend);
err_unreg_zfs:
	ksmbd_vss_unregister_backend(&ksmbd_vss_zfs_backend);
err_unreg_btrfs:
	ksmbd_vss_unregister_backend(&ksmbd_vss_btrfs_backend);
	return ret;
}

/**
 * ksmbd_vss_exit() - Tear down VSS subsystem
 */
void ksmbd_vss_exit(void)
{
	ksmbd_unregister_fsctl(&vss_enumerate_handler);
	ksmbd_vss_unregister_backend(&ksmbd_vss_generic_backend);
	ksmbd_vss_unregister_backend(&ksmbd_vss_zfs_backend);
	ksmbd_vss_unregister_backend(&ksmbd_vss_btrfs_backend);
}
