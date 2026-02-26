// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   DFS referral support for ksmbd
 *
 *   Registers FSCTL handlers for FSCTL_DFS_GET_REFERRALS and
 *   FSCTL_DFS_GET_REFERRALS_EX and builds a compatible referral
 *   response for clients probing DFS capability.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/minmax.h>
#include <linux/err.h>

#include "ksmbd_dfs.h"
#include "ksmbd_fsctl.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "smbstatus.h"
#include "glob.h"
#include "ksmbd_feature.h"
#include "ksmbd_work.h"
#include "connection.h"
#include "misc.h"
#include "unicode.h"
#include "server.h"

#define DFS_REFERRAL_V2		2
#define DFS_REFERRAL_V3		3
#define DFS_REFERRAL_V4		4

#define DFSREF_REFERRAL_SERVER	0x00000001
#define DFSREF_STORAGE_SERVER	0x00000002
#define DFSREF_TARGET_FAILBACK	0x00000004

#define DFS_TARGET_SET_BOUNDARY	0x0400
#define DFS_DEFAULT_TTL		300

/*
 * REQ_GET_DFS_REFERRAL request structure ([MS-DFSC] 2.2.2)
 *
 * MaxReferralLevel: Maximum referral version the client understands
 * RequestFileName:  Null-terminated Unicode DFS path
 */
struct req_get_dfs_referral {
	__le16	max_referral_level;
	__u8	request_file_name[];
} __packed;

/*
 * REQ_GET_DFS_REFERRAL_EX request header ([MS-DFSC] 2.2.2.1).
 * RequestData contains a null-terminated UTF-16 request path.
 */
struct req_get_dfs_referral_ex {
	__le16	max_referral_level;
	__le16	request_flags;
	__le32	request_data_length;
	__u8	request_data[];
} __packed;

/*
 * RESP_GET_DFS_REFERRAL response header ([MS-DFSC] 2.2.3)
 */
struct resp_get_dfs_referral {
	__le16	path_consumed;
	__le16	number_of_referrals;
	__le32	referral_header_flags;
} __packed;

/*
 * DFS referral entry versions consumed by SMB clients.
 * Level 3/4 layouts match Linux cifs client parser expectations.
 */
struct dfs_referral_level_2 {
	__le16	version_number;
	__le16	size;
	__le16	server_type;
	__le16	referral_entry_flags;
	__le32	proximity;
	__le32	time_to_live;
	__le16	dfs_path_offset;
	__le16	dfs_alt_path_offset;
	__le16	node_offset;
} __packed;

struct dfs_referral_level_3 {
	__le16	version_number;
	__le16	size;
	__le16	server_type;
	__le16	referral_entry_flags;
	__le32	time_to_live;
	__le16	dfs_path_offset;
	__le16	dfs_alt_path_offset;
	__le16	node_offset;
} __packed;

struct dfs_referral_level_4 {
	__le16	version_number;
	__le16	size;
	__le16	server_type;
	__le16	referral_entry_flags;
	__le32	time_to_live;
	__le16	dfs_path_offset;
	__le16	dfs_alt_path_offset;
	__le16	node_offset;
	__u8	service_site_guid[16];
} __packed;

static unsigned int dfs_referral_fixed_size(u16 version)
{
	switch (version) {
	case DFS_REFERRAL_V4:
		return sizeof(struct dfs_referral_level_4);
	case DFS_REFERRAL_V3:
		return sizeof(struct dfs_referral_level_3);
	case DFS_REFERRAL_V2:
	default:
		return sizeof(struct dfs_referral_level_2);
	}
}

static u16 dfs_select_referral_version(u16 max_level)
{
	if (max_level >= DFS_REFERRAL_V4)
		return DFS_REFERRAL_V4;
	if (max_level >= DFS_REFERRAL_V3)
		return DFS_REFERRAL_V3;
	if (max_level >= DFS_REFERRAL_V2)
		return DFS_REFERRAL_V2;
	return 0;
}

static int dfs_utf16_name_len(const __u8 *name, unsigned int max_len)
{
	unsigned int i;

	if (max_len < sizeof(__le16))
		return -EINVAL;

	for (i = 0; i + 1 < max_len; i += sizeof(__le16)) {
		if (!name[i] && !name[i + 1])
			return i;
	}

	return -EINVAL;
}

static int dfs_utf16_encode(const struct nls_table *nls,
			    const char *name, __u8 **utf16, unsigned int *len)
{
	__le16 *out;
	size_t alloc_units;
	int conv_len;

	alloc_units = strlen(name) * 3 + 1;
	out = kcalloc(alloc_units, sizeof(__le16), KSMBD_DEFAULT_GFP);
	if (!out)
		return -ENOMEM;

	conv_len = smbConvertToUTF16(out, name, strlen(name), nls, 0);
	if (conv_len < 0) {
		kfree(out);
		return -EINVAL;
	}

	*utf16 = (__u8 *)out;
	*len = (conv_len + 1) * sizeof(__le16);
	return 0;
}

static char *dfs_next_component(const char *path, const char **next)
{
	const char *start = path;
	const char *end;

	while (*start == '\\' || *start == '/')
		start++;
	if (!*start)
		return NULL;

	end = start;
	while (*end && *end != '\\' && *end != '/')
		end++;

	if (next) {
		*next = end;
		while (**next == '\\' || **next == '/')
			(*next)++;
	}

	return kstrndup(start, end - start, KSMBD_DEFAULT_GFP);
}

static char *dfs_build_network_address(const char *request_path)
{
	const char *next = request_path;
	const char *netbios = ksmbd_netbios_name();
	char *server = NULL, *share = NULL, *target = NULL;

	server = dfs_next_component(next, &next);
	if (!server)
		goto fallback;

	share = dfs_next_component(next, &next);
	if (!share)
		goto fallback;

	target = kasprintf(KSMBD_DEFAULT_GFP, "\\\\%s\\%s", netbios, share);
	goto out;

fallback:
	target = kasprintf(KSMBD_DEFAULT_GFP, "\\\\%s\\IPC$", netbios);
out:
	kfree(server);
	kfree(share);
	return target;
}

static int dfs_build_referral_response(struct ksmbd_work *work,
				       u16 max_referral_level,
				       const __u8 *request_name,
				       unsigned int request_name_max_len,
				       unsigned int max_out_len,
				       struct smb2_ioctl_rsp *rsp,
				       unsigned int *out_len)
{
	struct resp_get_dfs_referral *dfs_rsp;
	__u8 *entry_ptr;
	__u8 *dfs_path_utf16 = NULL, *target_utf16 = NULL;
	unsigned int dfs_path_len = 0, target_len = 0;
	unsigned int fixed_size, entry_size, total_out;
	unsigned int path_off, alt_path_off, node_off;
	int req_name_len;
	u16 version;
	char *request_path = NULL, *target = NULL;
	int ret;

	version = dfs_select_referral_version(max_referral_level);
	if (!version) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	req_name_len = dfs_utf16_name_len(request_name, request_name_max_len);
	if (req_name_len < 0) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return req_name_len;
	}

	request_path = smb_strndup_from_utf16((const char *)request_name,
					      req_name_len + sizeof(__le16),
					      true, work->conn->local_nls);
	if (IS_ERR(request_path))
		return PTR_ERR(request_path);

	ksmbd_conv_path_to_windows(request_path);
	target = dfs_build_network_address(request_path);
	if (!target) {
		ret = -ENOMEM;
		goto out;
	}

	ret = dfs_utf16_encode(work->conn->local_nls, request_path,
			       &dfs_path_utf16, &dfs_path_len);
	if (ret)
		goto out;

	ret = dfs_utf16_encode(work->conn->local_nls, target,
			       &target_utf16, &target_len);
	if (ret)
		goto out;

	fixed_size = dfs_referral_fixed_size(version);
	entry_size = fixed_size + dfs_path_len + dfs_path_len + target_len;
	total_out = sizeof(struct resp_get_dfs_referral) + entry_size;
	if (max_out_len < total_out) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		ret = -ENOSPC;
		goto out;
	}

	dfs_rsp = (struct resp_get_dfs_referral *)&rsp->Buffer[0];
	dfs_rsp->path_consumed = cpu_to_le16(min_t(unsigned int, req_name_len,
						   U16_MAX));
	dfs_rsp->number_of_referrals = cpu_to_le16(1);
	dfs_rsp->referral_header_flags =
		cpu_to_le32(DFSREF_REFERRAL_SERVER | DFSREF_STORAGE_SERVER |
			    (version == DFS_REFERRAL_V4 ? DFSREF_TARGET_FAILBACK : 0));

	entry_ptr = (__u8 *)dfs_rsp + sizeof(*dfs_rsp);
	path_off = fixed_size;
	alt_path_off = path_off + dfs_path_len;
	node_off = alt_path_off + dfs_path_len;

	if (version == DFS_REFERRAL_V4) {
		struct dfs_referral_level_4 *ref4 =
			(struct dfs_referral_level_4 *)entry_ptr;

		ref4->version_number = cpu_to_le16(DFS_REFERRAL_V4);
		ref4->size = cpu_to_le16(min_t(unsigned int, entry_size, U16_MAX));
		ref4->server_type = cpu_to_le16(DFS_SERVER_ROOT);
		ref4->referral_entry_flags = cpu_to_le16(DFS_TARGET_SET_BOUNDARY);
		ref4->time_to_live = cpu_to_le32(DFS_DEFAULT_TTL);
		ref4->dfs_path_offset = cpu_to_le16(path_off);
		ref4->dfs_alt_path_offset = cpu_to_le16(alt_path_off);
		ref4->node_offset = cpu_to_le16(node_off);
		memset(ref4->service_site_guid, 0, sizeof(ref4->service_site_guid));
	} else if (version == DFS_REFERRAL_V3) {
		struct dfs_referral_level_3 *ref3 =
			(struct dfs_referral_level_3 *)entry_ptr;

		ref3->version_number = cpu_to_le16(DFS_REFERRAL_V3);
		ref3->size = cpu_to_le16(min_t(unsigned int, entry_size, U16_MAX));
		ref3->server_type = cpu_to_le16(DFS_SERVER_ROOT);
		ref3->referral_entry_flags = 0;
		ref3->time_to_live = cpu_to_le32(DFS_DEFAULT_TTL);
		ref3->dfs_path_offset = cpu_to_le16(path_off);
		ref3->dfs_alt_path_offset = cpu_to_le16(alt_path_off);
		ref3->node_offset = cpu_to_le16(node_off);
	} else {
		struct dfs_referral_level_2 *ref2 =
			(struct dfs_referral_level_2 *)entry_ptr;

		ref2->version_number = cpu_to_le16(DFS_REFERRAL_V2);
		ref2->size = cpu_to_le16(min_t(unsigned int, entry_size, U16_MAX));
		ref2->server_type = cpu_to_le16(DFS_SERVER_ROOT);
		ref2->referral_entry_flags = 0;
		ref2->proximity = 0;
		ref2->time_to_live = cpu_to_le32(DFS_DEFAULT_TTL);
		ref2->dfs_path_offset = cpu_to_le16(path_off);
		ref2->dfs_alt_path_offset = cpu_to_le16(alt_path_off);
		ref2->node_offset = cpu_to_le16(node_off);
	}

	memcpy(entry_ptr + path_off, dfs_path_utf16, dfs_path_len);
	memcpy(entry_ptr + alt_path_off, dfs_path_utf16, dfs_path_len);
	memcpy(entry_ptr + node_off, target_utf16, target_len);

	*out_len = total_out;
	ret = 0;
out:
	kfree(request_path);
	kfree(target);
	kfree(dfs_path_utf16);
	kfree(target_utf16);
	return ret;
}

/**
 * ksmbd_dfs_get_referrals() - Handle FSCTL_DFS_GET_REFERRALS
 * @work:           smb work for this request
 * @id:             volatile file id (unused for DFS)
 * @in_buf:         input buffer containing REQ_GET_DFS_REFERRAL
 * @in_buf_len:     input buffer length
 * @max_out_len:    maximum output length allowed
 * @rsp:            pointer to ioctl response structure
 * @out_len:        [out] number of output bytes written
 */
static int ksmbd_dfs_get_referrals(struct ksmbd_work *work, u64 id,
				   void *in_buf, unsigned int in_buf_len,
				   unsigned int max_out_len,
				   struct smb2_ioctl_rsp *rsp,
				   unsigned int *out_len)
{
	struct req_get_dfs_referral *req;
	unsigned int request_name_max_len;

	(void)id;

	if (in_buf_len < sizeof(struct req_get_dfs_referral)) {
		pr_err_ratelimited("DFS referral request too short: %u\n",
				   in_buf_len);
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	req = (struct req_get_dfs_referral *)in_buf;
	request_name_max_len = in_buf_len - sizeof(*req);

	ksmbd_debug(SMB,
		    "DFS GET_REFERRALS: max_level=%u, buf_len=%u\n",
		    le16_to_cpu(req->max_referral_level), in_buf_len);

	return dfs_build_referral_response(work,
				   le16_to_cpu(req->max_referral_level),
				   req->request_file_name,
				   request_name_max_len,
				   max_out_len, rsp, out_len);
}

/**
 * ksmbd_dfs_get_referrals_ex() - Handle FSCTL_DFS_GET_REFERRALS_EX
 * @work:           smb work for this request
 * @id:             volatile file id (unused for DFS)
 * @in_buf:         input buffer containing extended referral request
 * @in_buf_len:     input buffer length
 * @max_out_len:    maximum output length allowed
 * @rsp:            pointer to ioctl response structure
 * @out_len:        [out] number of output bytes written
 */
static int ksmbd_dfs_get_referrals_ex(struct ksmbd_work *work, u64 id,
				      void *in_buf,
				      unsigned int in_buf_len,
				      unsigned int max_out_len,
				      struct smb2_ioctl_rsp *rsp,
				      unsigned int *out_len)
{
	struct req_get_dfs_referral_ex *req;
	unsigned int request_data_len;

	(void)id;

	ksmbd_debug(SMB, "DFS GET_REFERRALS_EX: buf_len=%u\n",
		    in_buf_len);

	if (in_buf_len < sizeof(*req)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	req = (struct req_get_dfs_referral_ex *)in_buf;
	request_data_len = le32_to_cpu(req->request_data_length);
	if (request_data_len == 0 ||
	    request_data_len > in_buf_len - sizeof(*req)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	return dfs_build_referral_response(work,
				   le16_to_cpu(req->max_referral_level),
				   req->request_data,
				   request_data_len,
				   max_out_len, rsp, out_len);
}

/* FSCTL handler descriptors */
static struct ksmbd_fsctl_handler dfs_get_referrals_handler = {
	.ctl_code = FSCTL_DFS_GET_REFERRALS,
	.handler  = ksmbd_dfs_get_referrals,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler dfs_get_referrals_ex_handler = {
	.ctl_code = FSCTL_DFS_GET_REFERRALS_EX,
	.handler  = ksmbd_dfs_get_referrals_ex,
	.owner    = THIS_MODULE,
};

/**
 * ksmbd_dfs_enabled() - Check if DFS is globally enabled
 *
 * Queries the three-tier feature framework to determine whether
 * DFS referral support is compiled in and enabled server-wide.
 *
 * Return: true if DFS is enabled, false otherwise
 */
bool ksmbd_dfs_enabled(void)
{
	return ksmbd_feat_enabled(NULL, KSMBD_FEAT_DFS);
}

/**
 * ksmbd_dfs_init() - Initialize DFS referral subsystem
 *
 * Registers FSCTL handlers for FSCTL_DFS_GET_REFERRALS (0x00060194)
 * and FSCTL_DFS_GET_REFERRALS_EX (0x000601B0).
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_dfs_init(void)
{
	int ret;

	ret = ksmbd_register_fsctl(&dfs_get_referrals_handler);
	if (ret) {
		pr_err("Failed to register FSCTL_DFS_GET_REFERRALS: %d\n",
		       ret);
		return ret;
	}

	ret = ksmbd_register_fsctl(&dfs_get_referrals_ex_handler);
	if (ret) {
		pr_err("Failed to register FSCTL_DFS_GET_REFERRALS_EX: %d\n",
		       ret);
		goto err_unregister;
	}

	ksmbd_debug(SMB, "DFS referral subsystem initialized\n");
	return 0;

err_unregister:
	ksmbd_unregister_fsctl(&dfs_get_referrals_handler);
	return ret;
}

/**
 * ksmbd_dfs_exit() - Tear down DFS referral subsystem
 *
 * Unregisters both DFS FSCTL handlers.
 */
void ksmbd_dfs_exit(void)
{
	ksmbd_unregister_fsctl(&dfs_get_referrals_ex_handler);
	ksmbd_unregister_fsctl(&dfs_get_referrals_handler);
}
