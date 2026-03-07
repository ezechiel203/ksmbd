// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_ioctl.c - SMB2_IOCTL handler
 */

#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/ethtool.h>
#include <linux/falloc.h>
#include <linux/crc32.h>
#include <linux/mount.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#include <linux/filelock.h>
#endif

#include <crypto/algapi.h>

#include "compat.h"
#include "glob.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "oplock.h"
#include "smbacl.h"

#include "auth.h"
#include "asn1.h"
#include "connection.h"
#include "transport_ipc.h"
#include "transport_rdma.h"
#include "vfs.h"
#include "vfs_cache.h"
#include "misc.h"

#include "server.h"
#include "smb_common.h"
#include "smbstatus.h"
#include "ksmbd_work.h"
#include "mgmt/user_config.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"
#include "mgmt/ksmbd_ida.h"
#include "ndr.h"
#include "transport_tcp.h"
#include "smb2fruit.h"
#include "ksmbd_fsctl.h"
#include "ksmbd_create_ctx.h"
#include "ksmbd_vss.h"
#include "ksmbd_notify.h"
#include "ksmbd_info.h"
#include "ksmbd_buffer.h"
#include "smb2pdu_internal.h"


/**
 * smb2_ioctl() - handler for smb2 ioctl command
 * @work:	smb work containing ioctl command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_ioctl(struct ksmbd_work *work)
{
	struct smb2_ioctl_req *req;
	struct smb2_ioctl_rsp *rsp;
	unsigned int cnt_code, nbytes = 0, out_buf_len, in_buf_len;
	u64 id = KSMBD_NO_FID;
	int ret = 0;
	char *buffer;

	ksmbd_debug(SMB, "Received smb2 ioctl request\n");

	if (work->next_smb2_rcv_hdr_off) {
		req = ksmbd_req_buf_next(work);
		rsp = ksmbd_resp_buf_next(work);
		if (!has_file_id(req->VolatileFileId)) {
			ksmbd_debug(SMB, "Compound request set FID = %llu\n",
				    work->compound_fid);
			id = work->compound_fid;
		}
	} else {
		req = smb2_get_msg(work->request_buf);
		rsp = smb2_get_msg(work->response_buf);
	}

	if (!has_file_id(id))
		id = req->VolatileFileId;

	/*
	 * MS-SMB2 §2.2.31: Flags MUST be SMB2_0_IOCTL_IS_FSCTL (0x00000001).
	 * No other value is defined; reject anything else.
	 */
	if (req->Flags != cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		ret = -EINVAL;
		goto out;
	}

	/* MS-SMB2 §3.3.5.2.10: validate ChannelSequence when a file handle is given */
	if (has_file_id(id)) {
		struct ksmbd_file *fp = ksmbd_lookup_fd_fast(work, id);

		if (!fp) {
			rsp->hdr.Status = STATUS_FILE_CLOSED;
			ret = -ENOENT;
			goto out;
		}
		ret = smb2_check_channel_sequence(work, fp);
		ksmbd_fd_put(work, fp);
		if (ret) {
			rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;
			goto out;
		}
	}

	cnt_code = le32_to_cpu(req->CntCode);
	ret = smb2_calc_max_out_buf_len(work, 48,
					le32_to_cpu(req->MaxOutputResponse));
	if (ret < 0) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		goto out;
	}
	out_buf_len = (unsigned int)ret;
	in_buf_len = le32_to_cpu(req->InputCount);

	/* Validate InputOffset before using it as pointer arithmetic */
	if (in_buf_len > 0) {
		unsigned int input_off = le32_to_cpu(req->InputOffset);
		unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;

		if (work->next_smb2_rcv_hdr_off)
			req_len -= work->next_smb2_rcv_hdr_off;

		if (input_off < sizeof(struct smb2_ioctl_req) ||
		    input_off > req_len ||
		    in_buf_len > req_len - input_off) {
			pr_err_ratelimited("Invalid IOCTL InputOffset %u or InputCount %u (req_len=%u)\n",
					   input_off, in_buf_len, req_len);
			ret = -EINVAL;
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			goto out;
		}
	}

	buffer = (char *)req + le32_to_cpu(req->InputOffset);

	/* Try registered FSCTL handlers first */
	ret = ksmbd_dispatch_fsctl(work, cnt_code, id, buffer,
				   in_buf_len, out_buf_len, rsp, &nbytes);
	if (ret == 0)
		goto done;
	if (ret != -EOPNOTSUPP) {
		/*
		 * MS-FSCC §2.3: some FSCTL handlers (e.g. SRV_COPYCHUNK)
		 * populate the response body even when returning an error
		 * (to convey server limits).  If the handler set nbytes > 0,
		 * go through the normal done path so the body is included.
		 */
		if (nbytes > 0)
			goto done;
		goto out;
	}

	/* No handler found for this FSCTL code */
	ksmbd_debug(SMB, "unknown ioctl command 0x%x\n", cnt_code);
	ret = -EOPNOTSUPP;
	goto out;

done:
	/*
	 * IOCTL-01: MS-SMB2 §2.2.32 — FileId in the response MUST echo the
	 * FileId from the request for file-directed FSCTLs.  Set them here
	 * as a default; individual handlers that use NO_FID (e.g. QNI)
	 * override these fields BEFORE reaching this point, so those
	 * overrides are preserved.
	 */
	if (!has_file_id(rsp->VolatileFileId))
		rsp->VolatileFileId = req->VolatileFileId;
	if (!has_file_id(rsp->PersistentFileId))
		rsp->PersistentFileId = req->PersistentFileId;

	/*
	 * Defense-in-depth: clamp output to MaxOutputResponse in case an
	 * individual FSCTL handler produced more data than the client
	 * requested.  Each handler should respect out_buf_len, but this
	 * catch-all prevents sending an oversized response.
	 */
	if (nbytes > out_buf_len) {
		/*
		 * M-02: MS-SMB2 §3.3.5.16 — when output is clamped to
		 * MaxOutputResponse the client cannot tell whether more data
		 * exists. Return STATUS_BUFFER_OVERFLOW (0x80000005, a warning,
		 * not an error) so the client knows to retry with a larger
		 * buffer. The response body up to out_buf_len bytes is valid.
		 */
		pr_warn_ratelimited("ksmbd: FSCTL handler exceeded MaxOutputResponse (%u > %u), clamping\n",
				    nbytes, out_buf_len);
		nbytes = out_buf_len;
		rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
	}

	rsp->CntCode = cpu_to_le32(cnt_code);
	rsp->InputCount = cpu_to_le32(0);
	rsp->InputOffset = cpu_to_le32(112);
	rsp->OutputOffset = cpu_to_le32(112);
	rsp->OutputCount = cpu_to_le32(nbytes);
	rsp->StructureSize = cpu_to_le16(49);
	rsp->Reserved = cpu_to_le16(0);
	rsp->Flags = cpu_to_le32(0);
	rsp->Reserved2 = cpu_to_le32(0);
	ret = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_ioctl_rsp) + nbytes);
	if (!ret)
		return ret;

out:
	/* If the handler or pre-check already set a specific status, keep it */
	if (rsp->hdr.Status == 0) {
		if (ret == -EACCES)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (ret == -ENOENT)
			rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;
		else if (ret == -EOPNOTSUPP)
			rsp->hdr.Status = STATUS_INVALID_DEVICE_REQUEST;
		else if (ret == -ENOSPC)
			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		else if (ret < 0)
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
	}

	smb2_set_err_rsp(work);
	return ret;
}

/**
 * smb20_oplock_break_ack() - handler for smb2.0 oplock break command
 * @work:	smb work containing oplock break command buffer
 *
 * Return:	0
 */
