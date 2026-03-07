// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Resilient handle support for ksmbd
 *
 *   Implements FSCTL_LMR_REQUEST_RESILIENCY (0x001401D4) which allows
 *   clients to request that the server keep file handles open for a
 *   specified timeout after a network disconnection.  This enables
 *   the client to reconnect and resume operations without data loss.
 */

#include <linux/slab.h>
#include <linux/module.h>

#include "ksmbd_resilient.h"
#include "ksmbd_fsctl.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "smbstatus.h"
#include "glob.h"
#include "ksmbd_work.h"
#include "vfs_cache.h"

/*
 * NETWORK_RESILIENCY_REQUEST structure ([MS-SMB2] 2.2.31.4)
 *
 * Timeout:  Requested timeout in milliseconds that the server should
 *           keep the file handle alive after a network disconnect.
 * Reserved: Must be zero; ignored on receipt.
 */
struct network_resiliency_request {
	__le32	timeout;
	__le32	reserved;
} __packed;

/* Maximum resilient timeout: 5 minutes (in milliseconds) */
#define KSMBD_MAX_RESILIENT_TIMEOUT_MS	(5 * 60 * 1000)

/**
 * ksmbd_fsctl_request_resiliency() - Handle FSCTL_LMR_REQUEST_RESILIENCY
 * @work:	    smb work for this request
 * @id:		    volatile file id
 * @in_buf:	    input buffer containing NETWORK_RESILIENCY_REQUEST
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Parses the NETWORK_RESILIENCY_REQUEST structure from the input
 * buffer, validates the timeout, and marks the file handle as
 * resilient.  The server will keep the handle open for the
 * specified timeout after a network disconnection.
 *
 * Per [MS-SMB2] 3.3.5.15.9, the response has no output data.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_fsctl_request_resiliency(struct ksmbd_work *work,
					  u64 id, void *in_buf,
					  unsigned int in_buf_len,
					  unsigned int max_out_len,
					  struct smb2_ioctl_rsp *rsp,
					  unsigned int *out_len)
{
	struct network_resiliency_request *req;
	struct ksmbd_file *fp;
	unsigned int timeout_ms;

	if (in_buf_len < sizeof(struct network_resiliency_request)) {
		pr_err_ratelimited(
			"resilient handle: input buffer too short: %u\n",
			in_buf_len);
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	req = (struct network_resiliency_request *)in_buf;
	timeout_ms = le32_to_cpu(req->timeout);

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		pr_err_ratelimited("resilient handle: file not found\n");
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	/*
	 * Cap the timeout to a server-defined maximum to prevent
	 * clients from requesting unreasonably long hold times.
	 */
	if (timeout_ms > KSMBD_MAX_RESILIENT_TIMEOUT_MS)
		timeout_ms = KSMBD_MAX_RESILIENT_TIMEOUT_MS;

	fp->is_resilient = true;
	fp->resilient_timeout = timeout_ms;

	ksmbd_debug(SMB,
		    "resilient handle: fid=%llu timeout=%u ms\n",
		    id, timeout_ms);

	*out_len = 0;
	ksmbd_fd_put(work, fp);
	return 0;
}

/* FSCTL handler descriptor */
static struct ksmbd_fsctl_handler resilient_handler = {
	.ctl_code = FSCTL_LMR_REQUEST_RESILIENCY,
	.handler  = ksmbd_fsctl_request_resiliency,
	.owner    = THIS_MODULE,
};

/**
 * ksmbd_resilient_init() - Initialize resilient handle subsystem
 *
 * Registers the FSCTL handler for FSCTL_LMR_REQUEST_RESILIENCY
 * (0x001401D4).
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_resilient_init(void)
{
	int ret;

	ret = ksmbd_register_fsctl(&resilient_handler);
	if (ret) {
		pr_err("Failed to register FSCTL_LMR_REQUEST_RESILIENCY: %d\n",
		       ret);
		return ret;
	}

	ksmbd_debug(SMB, "Resilient handle subsystem initialized\n");
	return 0;
}

/**
 * ksmbd_resilient_exit() - Tear down resilient handle subsystem
 *
 * Unregisters the FSCTL_LMR_REQUEST_RESILIENCY handler.
 */
void ksmbd_resilient_exit(void)
{
	ksmbd_unregister_fsctl(&resilient_handler);
}
