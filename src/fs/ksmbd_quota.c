// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   SMB2 quota query support for ksmbd
 *
 *   Implements the SMB2_O_INFO_QUOTA info-level handler that maps
 *   Windows SIDs to Linux uids and queries the VFS quota subsystem
 *   via dquot_get_dqblk() when CONFIG_QUOTA is enabled.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/quota.h>
#include <linux/quotaops.h>
#include <linux/module.h>

#include "glob.h"
#include "smb2pdu.h"
#include "smbacl.h"
#include "ksmbd_info.h"
#include "ksmbd_quota.h"
#include "connection.h"
#include "vfs_cache.h"

/*
 * SMB2 QUERY_QUOTA_INFO input buffer — [MS-SMB2] 2.2.37.1
 *
 * Sent in the InputBuffer of an SMB2 QUERY_INFO request when
 * InfoType == SMB2_O_INFO_QUOTA.
 */
struct smb2_query_quota_info {
	__u8	ReturnSingle;
	__u8	RestartScan;
	__le16	Reserved;
	__le32	SidListLength;
	__le32	StartSidLength;
	__le32	StartSidOffset;
} __packed;

/*
 * FILE_GET_QUOTA_INFORMATION — [MS-FSCC] 2.4.33.1
 *
 * Each entry in the SidList of the query request.
 */
struct file_get_quota_info {
	__le32	NextEntryOffset;
	__le32	SidLength;
	__u8	Sid[];
} __packed;

/*
 * FILE_QUOTA_INFORMATION — [MS-FSCC] 2.4.33
 *
 * Each entry in the output buffer of a quota query response.
 */
struct smb2_file_quota_info {
	__le32	NextEntryOffset;
	__le32	SidLength;
	__le64	ChangeTime;
	__le64	QuotaUsed;
	__le64	QuotaThreshold;
	__le64	QuotaLimit;
	__u8	Sid[];
} __packed;

/**
 * ksmbd_sid_byte_len() - compute total byte size of a packed SID
 * @sid: pointer to an smb_sid structure
 *
 * Return: total byte length of the SID (base + sub-authorities)
 */
static inline unsigned int ksmbd_sid_byte_len(const struct smb_sid *sid)
{
	return CIFS_SID_BASE_SIZE +
	       sizeof(__le32) * sid->num_subauth;
}

/**
 * ksmbd_sid_to_uid() - Extract a Linux uid from a Windows SID
 * @sid:     the Windows SID
 * @uid_out: [out] the resulting uid
 *
 * Uses the last sub-authority of the SID as the raw uid, matching
 * the convention used elsewhere in ksmbd (smbacl.c sid_to_id).
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_sid_to_uid(const struct smb_sid *sid, uid_t *uid_out)
{
	if (sid->num_subauth == 0 ||
	    sid->num_subauth > SID_MAX_SUB_AUTHORITIES)
		return -EINVAL;

	*uid_out = le32_to_cpu(sid->sub_auth[sid->num_subauth - 1]);
	return 0;
}

#ifdef CONFIG_QUOTA
/**
 * ksmbd_fill_quota_info() - Fill one FILE_QUOTA_INFORMATION entry
 * @sb:        super_block of the share filesystem
 * @sid:       the Windows SID for this user
 * @sid_len:   byte length of @sid
 * @uid:       Linux uid whose quota to query
 * @out:       output buffer pointer
 * @buf_rem:   remaining bytes in output buffer
 * @out_len:   [out] bytes written to @out
 *
 * Queries the Linux quota subsystem for @uid's quota on @sb and
 * formats a FILE_QUOTA_INFORMATION entry into @out.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_fill_quota_info(struct super_block *sb,
				 const struct smb_sid *sid,
				 unsigned int sid_len,
				 uid_t uid,
				 void *out,
				 unsigned int buf_rem,
				 unsigned int *out_len)
{
	struct smb2_file_quota_info *qi;
	struct qc_dqblk dqblk;
	struct kqid qid;
	unsigned int entry_size;
	int ret;

	entry_size = sizeof(struct smb2_file_quota_info) + sid_len;
	/* Align to 8 bytes for potential chaining */
	entry_size = ALIGN(entry_size, 8);

	if (buf_rem < entry_size) {
		*out_len = 0;
		return -ENOSPC;
	}

	memset(out, 0, entry_size);
	qi = (struct smb2_file_quota_info *)out;

	qid = make_kqid(&init_user_ns, USRQUOTA, uid);
	if (!qid_valid(qid)) {
		*out_len = 0;
		return -EINVAL;
	}

	memset(&dqblk, 0, sizeof(dqblk));
	ret = dquot_get_dqblk(sb, qid, &dqblk);
	if (ret) {
		/*
		 * If quota lookup fails (e.g., quotas not enabled for
		 * this user), return an entry with zeroed quota values.
		 * This is more informative than skipping the entry.
		 */
		ksmbd_debug(SMB,
			    "dquot_get_dqblk failed for uid %u: %d, returning zeros\n",
			    uid, ret);
		memset(&dqblk, 0, sizeof(dqblk));
	}

	qi->NextEntryOffset = 0; /* caller chains entries */
	qi->SidLength = cpu_to_le32(sid_len);
	qi->ChangeTime = 0;
	qi->QuotaUsed = cpu_to_le64(dqblk.d_space);
	qi->QuotaThreshold = cpu_to_le64(dqblk.d_spc_softlimit);
	qi->QuotaLimit = cpu_to_le64(dqblk.d_spc_hardlimit);
	memcpy(qi->Sid, sid, sid_len);

	*out_len = entry_size;
	return 0;
}
#endif /* CONFIG_QUOTA */

/**
 * ksmbd_quota_query() - SMB2_O_INFO_QUOTA GET handler
 * @work:    smb work for this request
 * @fp:      ksmbd file pointer (used to locate the filesystem)
 * @buf:     response buffer to fill with FILE_QUOTA_INFORMATION
 * @buf_len: available space in @buf
 * @out_len: [out] total bytes written to @buf
 *
 * Handles SMB2 QUERY_INFO requests with InfoType == SMB2_O_INFO_QUOTA.
 * Extracts SIDs from the request input buffer, maps each SID to a
 * Linux uid, queries the VFS quota subsystem, and formats the
 * response as FILE_QUOTA_INFORMATION entries.
 *
 * If the filesystem does not support quotas or CONFIG_QUOTA is not
 * enabled, returns an empty response (zero-length output) which
 * signals to the client that no quota data is available.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_quota_query(struct ksmbd_work *work,
			     struct ksmbd_file *fp,
			     void *buf,
			     unsigned int buf_len,
			     unsigned int *out_len)
{
#ifdef CONFIG_QUOTA
	struct smb2_query_info_req *req = ksmbd_req_buf_next(work);
	struct super_block *sb;
	struct smb2_query_quota_info *qqi;
	unsigned int input_buf_len;
	unsigned int total_written = 0;
	void *input_buf;
	void *prev_entry = NULL;

	*out_len = 0;

	if (!fp || !fp->filp) {
		ksmbd_debug(SMB, "Quota query: no file pointer\n");
		return -EINVAL;
	}

	sb = fp->filp->f_path.dentry->d_sb;
	if (!sb) {
		ksmbd_debug(SMB, "Quota query: no super_block\n");
		return -EINVAL;
	}

	/* Check if user quotas are enabled on this filesystem */
	if (!sb_has_quota_active(sb, USRQUOTA)) {
		ksmbd_debug(SMB,
			    "Quota query: quotas not active on filesystem\n");
		*out_len = 0;
		return 0;
	}

	/* Parse the input buffer (SMB2_QUERY_QUOTA_INFO) */
	input_buf_len = le32_to_cpu(req->InputBufferLength);
	if (input_buf_len < sizeof(struct smb2_query_quota_info)) {
		ksmbd_debug(SMB,
			    "Quota query: input buffer too small (%u < %zu)\n",
			    input_buf_len,
			    sizeof(struct smb2_query_quota_info));
		*out_len = 0;
		return 0;
	}

	input_buf = (void *)req + le16_to_cpu(req->InputBufferOffset) -
		    sizeof(struct smb2_hdr);
	qqi = (struct smb2_query_quota_info *)input_buf;

	/*
	 * Process the SID list if present.  Each entry is a
	 * FILE_GET_QUOTA_INFORMATION structure containing a SID
	 * whose quota data the client wants.
	 */
	if (le32_to_cpu(qqi->SidListLength) > 0) {
		unsigned int sid_list_len = le32_to_cpu(qqi->SidListLength);
		void *sid_list = (void *)qqi + sizeof(*qqi);
		unsigned int offset = 0;

		while (offset < sid_list_len) {
			struct file_get_quota_info *gqi;
			struct smb_sid *sid;
			unsigned int sid_len;
			unsigned int entry_len;
			uid_t uid;
			int ret;

			if (offset + sizeof(*gqi) > sid_list_len)
				break;

			gqi = (struct file_get_quota_info *)(sid_list + offset);
			sid_len = le32_to_cpu(gqi->SidLength);

			if (sid_len < CIFS_SID_BASE_SIZE ||
			    offset + sizeof(*gqi) + sid_len > sid_list_len)
				break;

			sid = (struct smb_sid *)gqi->Sid;

			ret = ksmbd_sid_to_uid(sid, &uid);
			if (ret) {
				ksmbd_debug(SMB,
					    "Quota: failed to map SID to uid\n");
				/* Skip this SID */
				if (le32_to_cpu(gqi->NextEntryOffset) == 0)
					break;
				offset += le32_to_cpu(gqi->NextEntryOffset);
				continue;
			}

			ret = ksmbd_fill_quota_info(sb, sid, sid_len, uid,
						    (u8 *)buf + total_written,
						    buf_len - total_written,
						    &entry_len);
			if (ret == -ENOSPC)
				break;
			if (ret)
				break;

			/* Chain previous entry to this one */
			if (prev_entry) {
				struct smb2_file_quota_info *prev =
					(struct smb2_file_quota_info *)
					prev_entry;
				prev->NextEntryOffset = cpu_to_le32(
					(u8 *)buf + total_written -
					(u8 *)prev_entry);
			}

			prev_entry = (u8 *)buf + total_written;
			total_written += entry_len;

			if (qqi->ReturnSingle)
				break;

			if (le32_to_cpu(gqi->NextEntryOffset) == 0)
				break;
			offset += le32_to_cpu(gqi->NextEntryOffset);
		}
	} else if (le32_to_cpu(qqi->StartSidLength) > 0) {
		/*
		 * StartSid-based enumeration: query quota for the
		 * single user identified by the StartSid.
		 */
		unsigned int start_sid_off = le32_to_cpu(qqi->StartSidOffset);
		unsigned int start_sid_len = le32_to_cpu(qqi->StartSidLength);
		struct smb_sid *sid;
		unsigned int entry_len;
		uid_t uid;
		int ret;

		if (start_sid_off + start_sid_len > input_buf_len ||
		    start_sid_len < CIFS_SID_BASE_SIZE)
			goto done;

		sid = (struct smb_sid *)((u8 *)qqi + start_sid_off);

		ret = ksmbd_sid_to_uid(sid, &uid);
		if (ret)
			goto done;

		ret = ksmbd_fill_quota_info(sb, sid, start_sid_len, uid,
					    buf, buf_len, &entry_len);
		if (ret == 0)
			total_written = entry_len;
	}

done:
	*out_len = total_written;
	return 0;
#else
	/* CONFIG_QUOTA not enabled — return empty response */
	*out_len = 0;
	return 0;
#endif /* CONFIG_QUOTA */
}

static struct ksmbd_info_handler ksmbd_quota_get_handler = {
	.info_type	= SMB2_O_INFO_QUOTA,
	.info_class	= 0, /* quota queries do not use info class */
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_quota_query,
	.owner		= THIS_MODULE,
};

/**
 * ksmbd_quota_init() - Initialize quota query handlers
 *
 * Registers the SMB2_O_INFO_QUOTA GET handler in the info-level
 * dispatch table.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_quota_init(void)
{
	int ret;

	ret = ksmbd_register_info_handler(&ksmbd_quota_get_handler);
	if (ret) {
		pr_err("Failed to register quota info handler: %d\n", ret);
		return ret;
	}

	ksmbd_debug(SMB, "Quota query handler registered\n");
	return 0;
}

/**
 * ksmbd_quota_exit() - Tear down quota query handlers
 *
 * Unregisters the quota info-level handler.
 */
void ksmbd_quota_exit(void)
{
	ksmbd_unregister_info_handler(&ksmbd_quota_get_handler);
}
