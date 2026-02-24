// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   DFS referral support for ksmbd
 *
 *   Registers FSCTL handlers for FSCTL_DFS_GET_REFERRALS and
 *   FSCTL_DFS_GET_REFERRALS_EX.  Referral resolution is stubbed
 *   for now; full IPC integration with ksmbd.mountd is a future
 *   task.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/string.h>

#include "ksmbd_dfs.h"
#include "ksmbd_fsctl.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "smbstatus.h"
#include "glob.h"
#include "ksmbd_feature.h"
#include "ksmbd_work.h"

/*
 * REQ_GET_DFS_REFERRAL request structure ([MS-DFSC] 2.2.2)
 *
 * MaxReferralLevel: Maximum referral version the client understands
 * RequestFileName:  Null-terminated Unicode DFS path
 */
struct req_get_dfs_referral {
	__le16	max_referral_level;
	__u8	request_file_name[];	/* variable-length UTF-16LE */
} __packed;

/*
 * RESP_GET_DFS_REFERRAL response header ([MS-DFSC] 2.2.3)
 *
 * PathConsumed:    Number of bytes consumed from the request path
 * NumberOfReferrals: Number of referral entries that follow
 * ReferralHeaderFlags: Flags for the response
 */
struct resp_get_dfs_referral {
	__le16	path_consumed;
	__le16	number_of_referrals;
	__le32	referral_header_flags;
	/* Followed by DFS_REFERRAL_V3 entries */
} __packed;

/**
 * ksmbd_dfs_get_referrals() - Handle FSCTL_DFS_GET_REFERRALS
 * @work:	    smb work for this request
 * @id:		    volatile file id (unused for DFS)
 * @in_buf:	    input buffer containing REQ_GET_DFS_REFERRAL
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Parses the DFS referral request and returns STATUS_NOT_FOUND
 * since actual referral resolution requires IPC to ksmbd.mountd,
 * which is not yet implemented.
 *
 * Return: 0 on success (with STATUS_NOT_FOUND in response header),
 *         negative errno on failure
 */
static int ksmbd_dfs_get_referrals(struct ksmbd_work *work, u64 id,
				   void *in_buf, unsigned int in_buf_len,
				   unsigned int max_out_len,
				   struct smb2_ioctl_rsp *rsp,
				   unsigned int *out_len)
{
	struct req_get_dfs_referral *req;
	struct resp_get_dfs_referral *dfs_rsp;

	if (in_buf_len < sizeof(struct req_get_dfs_referral)) {
		pr_err_ratelimited("DFS referral request too short: %u\n",
				   in_buf_len);
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	req = (struct req_get_dfs_referral *)in_buf;

	ksmbd_debug(SMB,
		    "DFS GET_REFERRALS: max_level=%u, buf_len=%u\n",
		    le16_to_cpu(req->max_referral_level), in_buf_len);

	if (max_out_len < sizeof(struct resp_get_dfs_referral)) {
		pr_err_ratelimited("DFS referral output buffer too small: %u\n",
				   max_out_len);
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	/*
	 * Stub: Return an empty referral response with STATUS_NOT_FOUND.
	 *
	 * Full referral resolution requires IPC to ksmbd.mountd where
	 * the DFS namespace configuration lives.  This will be
	 * implemented as a follow-up task.
	 */
	dfs_rsp = (struct resp_get_dfs_referral *)&rsp->Buffer[0];
	dfs_rsp->path_consumed = cpu_to_le16(0);
	dfs_rsp->number_of_referrals = cpu_to_le16(0);
	dfs_rsp->referral_header_flags = cpu_to_le32(0);

	*out_len = sizeof(struct resp_get_dfs_referral);

	rsp->hdr.Status = STATUS_NOT_FOUND;
	return 0;
}

/**
 * ksmbd_dfs_get_referrals_ex() - Handle FSCTL_DFS_GET_REFERRALS_EX
 * @work:	    smb work for this request
 * @id:		    volatile file id (unused for DFS)
 * @in_buf:	    input buffer containing extended referral request
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Extended version of DFS referral with site awareness.
 * Currently delegates to the same stub logic as the base handler.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_dfs_get_referrals_ex(struct ksmbd_work *work, u64 id,
				      void *in_buf,
				      unsigned int in_buf_len,
				      unsigned int max_out_len,
				      struct smb2_ioctl_rsp *rsp,
				      unsigned int *out_len)
{
	/*
	 * FSCTL_DFS_GET_REFERRALS_EX has a slightly different request
	 * format but produces the same response structure.  For now
	 * return the same stub response.
	 */
	ksmbd_debug(SMB, "DFS GET_REFERRALS_EX: buf_len=%u\n",
		    in_buf_len);

	return ksmbd_dfs_get_referrals(work, id, in_buf, in_buf_len,
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
