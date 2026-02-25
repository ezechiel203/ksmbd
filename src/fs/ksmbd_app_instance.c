// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   APP_INSTANCE_ID / APP_INSTANCE_VERSION create context handlers
 *
 *   APP_INSTANCE_ID (MS-SMB2 2.2.13.2.13) allows a client to associate
 *   an application instance GUID with a file open.  If a new open
 *   arrives with the same APP_INSTANCE_ID on the same file, the server
 *   closes the previous open.  This is critical for failover clustering.
 *
 *   APP_INSTANCE_VERSION (MS-SMB2 2.2.13.2.18) extends this with
 *   version tracking -- the old handle is only closed if the new
 *   version is higher.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/uuid.h>

#include "ksmbd_app_instance.h"
#include "ksmbd_create_ctx.h"
#include "glob.h"
#include "vfs_cache.h"

/*
 * APP_INSTANCE_ID create context structure (MS-SMB2 2.2.13.2.13)
 *
 * StructureSize:  Must be 20
 * Reserved:       Must be 0
 * AppInstanceId:  16-byte application instance GUID
 */
#define APP_INSTANCE_ID_STRUCT_SIZE	20
#define APP_INSTANCE_ID_GUID_OFFSET	4
#define APP_INSTANCE_ID_GUID_LEN	16

/*
 * APP_INSTANCE_VERSION create context structure (MS-SMB2 2.2.13.2.18)
 *
 * StructureSize:  Must be 24
 * Reserved:       Must be 0
 * Padding:        4 bytes padding
 * AppInstanceVersionHigh: 8 bytes
 * AppInstanceVersionLow:  8 bytes
 */
#define APP_INSTANCE_VERSION_STRUCT_SIZE	24
#define APP_INSTANCE_VERSION_HIGH_OFFSET	8
#define APP_INSTANCE_VERSION_LOW_OFFSET		16

/*
 * Binary tag for SMB2_CREATE_APP_INSTANCE_ID
 * GUID: 45BCA66A-EFA7-F74A-9008-FA462E144D74
 */
static const char app_instance_id_tag[] = {
	0x45, 0xBC, 0xA6, 0x6A, 0xEF, 0xA7, 0xF7, 0x4A,
	0x90, 0x08, 0xFA, 0x46, 0x2E, 0x14, 0x4D, 0x74
};

/*
 * Binary tag for SMB2_CREATE_APP_INSTANCE_VERSION
 * GUID: B982D0B7-3B56-074F-A07B-524A8116A010
 */
static const char app_instance_version_tag[] = {
	0xB9, 0x82, 0xD0, 0xB7, 0x3B, 0x56, 0x07, 0x4F,
	0xA0, 0x7B, 0x52, 0x4A, 0x81, 0x16, 0xA0, 0x10
};

/**
 * close_previous_app_instance() - Close prior opens with same app instance
 * @work:	smb work for this request
 * @fp:		the newly opened file (already in the inode fp list)
 * @version_high: app instance version high from the new open
 * @version_low: app instance version low from the new open
 * @has_version: true if APP_INSTANCE_VERSION context was supplied
 *
 * Walk the inode's file list looking for an existing open that has the
 * same app_instance_id on the same inode.  If found, close it only
 * when the new version is strictly higher (or when no version context
 * was supplied, which implies unconditional close).
 */
static void close_previous_app_instance(struct ksmbd_work *work,
					struct ksmbd_file *fp,
					u64 version_high,
					u64 version_low,
					bool has_version)
{
	struct ksmbd_inode *ci = fp->f_ci;
	struct ksmbd_file *prev_fp;
	u64 found_id = KSMBD_NO_FID;

	down_read(&ci->m_lock);
	list_for_each_entry(prev_fp, &ci->m_fp_list, node) {
		if (prev_fp == fp)
			continue;

		if (!prev_fp->has_app_instance_id)
			continue;

		if (memcmp(prev_fp->app_instance_id,
			   fp->app_instance_id,
			   APP_INSTANCE_ID_GUID_LEN))
			continue;

		/*
		 * Same app instance ID on same inode.  If the new open
		 * carries a version, only close if (high, low) is strictly
		 * higher than the previous open's version tuple.
		 */
		if (has_version) {
			if (prev_fp->app_instance_version > version_high)
				continue;
			if (prev_fp->app_instance_version == version_high &&
			    prev_fp->app_instance_version_low >= version_low)
				continue;
		}

		/*
		 * Capture the volatile ID while protected by ci->m_lock.
		 * Do not retain a raw pointer after unlocking.
		 */
		found_id = prev_fp->volatile_id;
		break;
	}
	up_read(&ci->m_lock);

	if (has_file_id(found_id)) {
		ksmbd_debug(SMB,
			    "Closing previous app instance open fid=%llu\n",
			    found_id);
		ksmbd_close_fd(work, found_id);
	}
}

/**
 * app_instance_id_on_request() - Handle APP_INSTANCE_ID create context
 * @work:	smb work for this request
 * @fp:		the file being opened
 * @ctx_data:	raw context data blob (after the tag)
 * @ctx_len:	length of the context data
 *
 * Parses the 16-byte application instance GUID from the context data,
 * stores it on the ksmbd_file, and closes any prior opens with the
 * same app instance ID on the same inode.
 *
 * Return: 0 on success, negative errno on failure
 */
static int app_instance_id_on_request(struct ksmbd_work *work,
				      struct ksmbd_file *fp,
				      const void *ctx_data,
				      unsigned int ctx_len)
{
	const u8 *data = ctx_data;
	static const u8 zero_guid[APP_INSTANCE_ID_GUID_LEN] = {};

	if (ctx_len < APP_INSTANCE_ID_STRUCT_SIZE) {
		ksmbd_debug(SMB,
			    "APP_INSTANCE_ID: context too short (%u)\n",
			    ctx_len);
		return -EINVAL;
	}

	/* Skip StructureSize (2 bytes) and Reserved (2 bytes) */
	memcpy(fp->app_instance_id, data + APP_INSTANCE_ID_GUID_OFFSET,
	       APP_INSTANCE_ID_GUID_LEN);

	/* A zero GUID means "no app instance" -- ignore it */
	if (!memcmp(fp->app_instance_id, zero_guid,
		    APP_INSTANCE_ID_GUID_LEN)) {
		ksmbd_debug(SMB, "APP_INSTANCE_ID: zero GUID, ignoring\n");
		return 0;
	}

	fp->has_app_instance_id = true;

	ksmbd_debug(SMB, "APP_INSTANCE_ID: set on fid=%llu\n",
		    fp->volatile_id);

	close_previous_app_instance(work, fp,
				    fp->app_instance_version,
				    fp->app_instance_version_low,
				    fp->has_app_instance_version);
	return 0;
}

/**
 * app_instance_version_on_request() - Handle APP_INSTANCE_VERSION context
 * @work:	smb work for this request
 * @fp:		the file being opened
 * @ctx_data:	raw context data blob (after the tag)
 * @ctx_len:	length of the context data
 *
 * Parses the version from the context data and stores it on the
 * ksmbd_file.  If an APP_INSTANCE_ID was already set on this file,
 * re-evaluates existing opens with version comparison -- the old
 * handle is closed only when the new version is strictly higher.
 *
 * Return: 0 on success, negative errno on failure
 */
static int app_instance_version_on_request(struct ksmbd_work *work,
					   struct ksmbd_file *fp,
					   const void *ctx_data,
					   unsigned int ctx_len)
{
	const u8 *data = ctx_data;
	u64 ver_high, ver_low;

	if (ctx_len < APP_INSTANCE_VERSION_STRUCT_SIZE) {
		ksmbd_debug(SMB,
			    "APP_INSTANCE_VERSION: context too short (%u)\n",
			    ctx_len);
		return -EINVAL;
	}

	/*
	 * AppInstanceVersionHigh at offset 8,
	 * AppInstanceVersionLow at offset 16.
	 * Per MS-SMB2, compare high first, then low if equal.
	 * We store the high part as the primary version since it
	 * dominates the comparison.
	 */
	ver_high = le64_to_cpu(*(__le64 *)(data +
			       APP_INSTANCE_VERSION_HIGH_OFFSET));
	ver_low = le64_to_cpu(*(__le64 *)(data +
			      APP_INSTANCE_VERSION_LOW_OFFSET));

	fp->has_app_instance_version = true;
	fp->app_instance_version = ver_high;
	fp->app_instance_version_low = ver_low;

	ksmbd_debug(SMB,
		    "APP_INSTANCE_VERSION: high=%llu low=%llu on fid=%llu\n",
		    ver_high, ver_low, fp->volatile_id);

	/*
	 * If this file already has an app instance ID set (the
	 * APP_INSTANCE_ID context is typically processed first),
	 * try to close previous opens with version comparison.
	 */
	if (fp->has_app_instance_id)
		close_previous_app_instance(work, fp, ver_high, ver_low, true);

	return 0;
}

/* Create context handler descriptors */
static struct ksmbd_create_ctx_handler app_instance_id_handler = {
	.tag		= app_instance_id_tag,
	.tag_len	= sizeof(app_instance_id_tag),
	.on_request	= app_instance_id_on_request,
	.on_response	= NULL,
	.owner		= THIS_MODULE,
};

static struct ksmbd_create_ctx_handler app_instance_version_handler = {
	.tag		= app_instance_version_tag,
	.tag_len	= sizeof(app_instance_version_tag),
	.on_request	= app_instance_version_on_request,
	.on_response	= NULL,
	.owner		= THIS_MODULE,
};

/**
 * ksmbd_app_instance_init() - Initialize app instance create contexts
 *
 * Registers the APP_INSTANCE_ID and APP_INSTANCE_VERSION create
 * context handlers.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_app_instance_init(void)
{
	int ret;

	ret = ksmbd_register_create_context(&app_instance_id_handler);
	if (ret) {
		pr_err("Failed to register APP_INSTANCE_ID handler: %d\n",
		       ret);
		return ret;
	}

	ret = ksmbd_register_create_context(&app_instance_version_handler);
	if (ret) {
		pr_err("Failed to register APP_INSTANCE_VERSION handler: %d\n",
		       ret);
		goto err_unregister_id;
	}

	ksmbd_debug(SMB,
		    "APP_INSTANCE_ID/VERSION create contexts initialized\n");
	return 0;

err_unregister_id:
	ksmbd_unregister_create_context(&app_instance_id_handler);
	return ret;
}

/**
 * ksmbd_app_instance_exit() - Tear down app instance create contexts
 *
 * Unregisters the APP_INSTANCE_ID and APP_INSTANCE_VERSION handlers.
 */
void ksmbd_app_instance_exit(void)
{
	ksmbd_unregister_create_context(&app_instance_version_handler);
	ksmbd_unregister_create_context(&app_instance_id_handler);
}
