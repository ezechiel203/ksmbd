// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for IPC/netlink message parsing
 *
 *   This module exercises the netlink response parsing logic used in
 *   ksmbd's transport_ipc.c. The kernel parses responses from the
 *   userspace ksmbd.mountd daemon via Generic Netlink. A compromised
 *   or buggy daemon could send malformed payloads.
 *
 *   Targets:
 *     - Login response: struct ksmbd_login_response fields
 *     - Share config response: struct ksmbd_share_config_response
 *     - SPNEGO authentication response
 *     - Tree connect response
 *
 *   Corpus seed hints:
 *     - Login response: status=0, gid/uid fields, account_name
 *     - Share config: vhost_name, path, flags, share_type
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* Simplified IPC structures (from ksmbd_netlink.h) */
#define KSMBD_REQ_MAX_ACCOUNT_NAME_SZ	48
#define KSMBD_REQ_MAX_HASH_SZ		18
#define KSMBD_REQ_MAX_SHARE_NAME	64

struct fuzz_login_response {
	__u32 status;
	__u32 gid;
	__u32 uid;
	__s8  account;
	__u16 hash_sz;
	__u8  hash[KSMBD_REQ_MAX_HASH_SZ];
} __packed;

struct fuzz_share_config_response {
	__u32 status;
	__u32 flags;
	__u16 share_type;
	__u16 create_mask;
	__u16 directory_mask;
	__u16 force_create_mode;
	__u16 force_directory_mode;
	__u16 force_uid;
	__u16 force_gid;
	__u32 vhost_name_len;
	__u32 path_len;
	/* Followed by vhost_name[vhost_name_len] and path[path_len] */
} __packed;

struct fuzz_spnego_response {
	__u32 status;
	__u32 blob_len;
	/* Followed by blob[blob_len] */
} __packed;

struct fuzz_tree_connect_response {
	__u32 status;
	__u32 share_flags;
	__u16 share_type;
} __packed;

/*
 * fuzz_ipc_login_response - Fuzz login response parsing
 * @data:	raw response buffer
 * @len:	length of buffer
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_ipc_login_response(const u8 *data, size_t len)
{
	const struct fuzz_login_response *resp;

	if (len < sizeof(struct fuzz_login_response)) {
		pr_debug("fuzz_ipc: login response too small (%zu)\n", len);
		return -EINVAL;
	}

	resp = (const struct fuzz_login_response *)data;

	/* Validate hash_sz */
	if (resp->hash_sz > KSMBD_REQ_MAX_HASH_SZ) {
		pr_debug("fuzz_ipc: hash_sz %u > max %u\n",
			 resp->hash_sz, KSMBD_REQ_MAX_HASH_SZ);
		return -EINVAL;
	}

	pr_debug("fuzz_ipc: login status=%u uid=%u gid=%u hash_sz=%u\n",
		 resp->status, resp->uid, resp->gid, resp->hash_sz);

	return 0;
}

/*
 * fuzz_ipc_share_config_response - Fuzz share config response parsing
 * @data:	raw response buffer
 * @len:	length of buffer
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_ipc_share_config_response(const u8 *data, size_t len)
{
	const struct fuzz_share_config_response *resp;
	u32 vhost_len, path_len;
	size_t required;

	if (len < sizeof(struct fuzz_share_config_response)) {
		pr_debug("fuzz_ipc: share config too small (%zu)\n", len);
		return -EINVAL;
	}

	resp = (const struct fuzz_share_config_response *)data;
	vhost_len = resp->vhost_name_len;
	path_len = resp->path_len;

	/* Validate trailing data lengths */
	required = sizeof(struct fuzz_share_config_response) +
		   vhost_len + path_len;
	if (required > len) {
		pr_debug("fuzz_ipc: share config needs %zu, have %zu\n",
			 required, len);
		return -EINVAL;
	}

	/* Sanity limits */
	if (vhost_len > 256) {
		pr_debug("fuzz_ipc: vhost_name_len %u too large\n", vhost_len);
		return -EINVAL;
	}

	if (path_len > PATH_MAX) {
		pr_debug("fuzz_ipc: path_len %u too large\n", path_len);
		return -EINVAL;
	}

	pr_debug("fuzz_ipc: share status=%u flags=0x%08x type=%u vhost=%u path=%u\n",
		 resp->status, resp->flags, resp->share_type,
		 vhost_len, path_len);

	return 0;
}

/*
 * fuzz_ipc_spnego_response - Fuzz SPNEGO auth response parsing
 * @data:	raw response buffer
 * @len:	length of buffer
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_ipc_spnego_response(const u8 *data, size_t len)
{
	const struct fuzz_spnego_response *resp;

	if (len < sizeof(struct fuzz_spnego_response)) {
		pr_debug("fuzz_ipc: spnego response too small (%zu)\n", len);
		return -EINVAL;
	}

	resp = (const struct fuzz_spnego_response *)data;

	/* Validate blob_len */
	if (sizeof(struct fuzz_spnego_response) + resp->blob_len > len) {
		pr_debug("fuzz_ipc: spnego blob_len %u exceeds buffer\n",
			 resp->blob_len);
		return -EINVAL;
	}

	if (resp->blob_len > 65536) {
		pr_debug("fuzz_ipc: spnego blob_len %u too large\n",
			 resp->blob_len);
		return -EINVAL;
	}

	pr_debug("fuzz_ipc: spnego status=%u blob_len=%u\n",
		 resp->status, resp->blob_len);

	return 0;
}

/*
 * fuzz_ipc_tree_connect_response - Fuzz tree connect response parsing
 * @data:	raw response buffer
 * @len:	length of buffer
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_ipc_tree_connect_response(const u8 *data, size_t len)
{
	const struct fuzz_tree_connect_response *resp;

	if (len < sizeof(struct fuzz_tree_connect_response)) {
		pr_debug("fuzz_ipc: tree connect too small (%zu)\n", len);
		return -EINVAL;
	}

	resp = (const struct fuzz_tree_connect_response *)data;

	pr_debug("fuzz_ipc: tree_connect status=%u flags=0x%08x type=%u\n",
		 resp->status, resp->share_flags, resp->share_type);

	return 0;
}

static int __init ipc_message_fuzz_init(void)
{
	u8 *test_buf;
	int ret;

	pr_info("ipc_message_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid login response */
	{
		struct fuzz_login_response *resp =
			(struct fuzz_login_response *)test_buf;

		resp->status = 0;
		resp->uid = 1000;
		resp->gid = 1000;
		resp->hash_sz = 16;
		ret = fuzz_ipc_login_response(test_buf,
					      sizeof(struct fuzz_login_response));
		pr_info("ipc_message_fuzz: valid login returned %d\n", ret);
	}

	/* Self-test 2: oversized hash */
	{
		struct fuzz_login_response *resp =
			(struct fuzz_login_response *)test_buf;

		resp->hash_sz = 255;
		ret = fuzz_ipc_login_response(test_buf,
					      sizeof(struct fuzz_login_response));
		pr_info("ipc_message_fuzz: big hash returned %d\n", ret);
	}

	/* Self-test 3: valid share config */
	{
		struct fuzz_share_config_response *resp =
			(struct fuzz_share_config_response *)test_buf;

		memset(test_buf, 0, 512);
		resp->status = 0;
		resp->flags = 0x1234;
		resp->share_type = 1;
		resp->vhost_name_len = 4;
		resp->path_len = 5;
		memcpy(test_buf + sizeof(*resp), "test", 4);
		memcpy(test_buf + sizeof(*resp) + 4, "/tmp/", 5);
		ret = fuzz_ipc_share_config_response(test_buf,
						     sizeof(*resp) + 9);
		pr_info("ipc_message_fuzz: valid share config returned %d\n", ret);
	}

	/* Self-test 4: share config with huge vhost_name */
	{
		struct fuzz_share_config_response *resp =
			(struct fuzz_share_config_response *)test_buf;

		memset(test_buf, 0, 512);
		resp->vhost_name_len = 0xFFFFFFFF;
		ret = fuzz_ipc_share_config_response(test_buf, sizeof(*resp) + 4);
		pr_info("ipc_message_fuzz: huge vhost returned %d\n", ret);
	}

	/* Self-test 5: spnego response */
	{
		struct fuzz_spnego_response *resp =
			(struct fuzz_spnego_response *)test_buf;

		memset(test_buf, 0, 512);
		resp->status = 0;
		resp->blob_len = 16;
		memset(test_buf + sizeof(*resp), 0xAA, 16);
		ret = fuzz_ipc_spnego_response(test_buf, sizeof(*resp) + 16);
		pr_info("ipc_message_fuzz: spnego returned %d\n", ret);
	}

	/* Self-test 6: garbage */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_ipc_login_response(test_buf, 512);
	pr_info("ipc_message_fuzz: garbage login returned %d\n", ret);
	ret = fuzz_ipc_share_config_response(test_buf, 512);
	pr_info("ipc_message_fuzz: garbage share returned %d\n", ret);
	ret = fuzz_ipc_spnego_response(test_buf, 512);
	pr_info("ipc_message_fuzz: garbage spnego returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit ipc_message_fuzz_exit(void)
{
	pr_info("ipc_message_fuzz: module unloaded\n");
}

module_init(ipc_message_fuzz_init);
module_exit(ipc_message_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for IPC/netlink message parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
