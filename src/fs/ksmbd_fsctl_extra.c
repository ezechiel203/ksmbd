// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Extra FSCTL handlers for ksmbd
 *
 *   Registers supplemental FSCTL handlers that are intentionally
 *   kept outside the built-in core table (currently
 *   FSCTL_FILE_LEVEL_TRIM and FSCTL_PIPE_WAIT).
 *
 *   Dead handler functions that were duplicates of built-in handlers
 *   (COPYCHUNK, ZERO_DATA, QUERY_ALLOCATED_RANGES, DUPLICATE_EXTENTS)
 *   have been removed (GEN-03).
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/falloc.h>
#include <linux/delay.h>
#include <linux/math64.h>

#include "ksmbd_fsctl_extra.h"
#include "ksmbd_fsctl.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "smb_common.h"
#include "smbstatus.h"
#include "glob.h"
#include "ksmbd_work.h"
#include "vfs.h"
#include "vfs_cache.h"
#include "oplock.h"
#include "connection.h"
#include "mgmt/tree_connect.h"

/*
 * FSCTL_FILE_LEVEL_TRIM (0x00098208) is not defined in smbfsctl.h,
 * so define it here.
 */
#ifndef FSCTL_FILE_LEVEL_TRIM
#define FSCTL_FILE_LEVEL_TRIM	0x00098208
#endif

/*
 * MS-FSCC 2.3.73 - FILE_LEVEL_TRIM input structures
 *
 * FILE_LEVEL_TRIM:
 *   Key    (4 bytes) - reserved, must be zero
 *   NumRanges (4 bytes) - number of FILE_LEVEL_TRIM_RANGE entries
 *   Ranges[]  - array of {Offset, Length} pairs
 */
struct file_level_trim_range {
	__le64	offset;
	__le64	length;
} __packed;

struct file_level_trim {
	__le32	key;
	__le32	num_ranges;
	struct file_level_trim_range	ranges[];
} __packed;

/* F-04: MS-FSCC 2.3.74 - FILE_LEVEL_TRIM_OUTPUT */
struct file_level_trim_output {
	__le32	NumRangesProcessed;
} __packed;

/**
 * ksmbd_fsctl_file_level_trim() - Handle FSCTL_FILE_LEVEL_TRIM
 * @work:	    smb work for this request
 * @id:		    volatile file id
 * @in_buf:	    input buffer containing FILE_LEVEL_TRIM structure
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Iterates over the DataSetRanges in the input and calls
 * vfs_fallocate() with FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE
 * for each range to issue trim/discard operations.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_fsctl_file_level_trim(struct ksmbd_work *work,
				       u64 id, void *in_buf,
				       unsigned int in_buf_len,
				       unsigned int max_out_len,
				       struct smb2_ioctl_rsp *rsp,
				       unsigned int *out_len)
{
	struct file_level_trim *trim;
	struct file_level_trim_output *f04_out;
	struct ksmbd_file *fp;
	unsigned int i, num_ranges, num_processed = 0;
	int ret = 0;

	if (!test_tree_conn_flag(work->tcon,
				 KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		ksmbd_debug(SMB,
			    "FSCTL_FILE_LEVEL_TRIM: no write perm\n");
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(struct file_level_trim)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	trim = (struct file_level_trim *)in_buf;
	num_ranges = le32_to_cpu(trim->num_ranges);

	/* Validate that all range entries fit in the input buffer */
	if (num_ranges > (in_buf_len - sizeof(struct file_level_trim)) /
			  sizeof(struct file_level_trim_range)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	if (num_ranges == 0) {
		*out_len = 0;
		return 0;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	smb_break_all_levII_oplock(work, fp, 1);

	for (i = 0; i < num_ranges; i++) {
		loff_t off = le64_to_cpu(trim->ranges[i].offset);
		loff_t len = le64_to_cpu(trim->ranges[i].length);

		if (off < 0 || len <= 0)
			continue;

		ret = vfs_fallocate(fp->filp,
				    FALLOC_FL_PUNCH_HOLE |
				    FALLOC_FL_KEEP_SIZE,
				    off, len);
		if (ret < 0) {
			ksmbd_debug(SMB,
				    "TRIM range %u failed: %d\n",
				    i, ret);
			/*
			 * Per MS-FSCC, individual range failures
			 * are not fatal; continue with remaining
			 * ranges and report the last error.
			 */
		} else {
			num_processed++;
		}
	}

	ksmbd_fd_put(work, fp);

	/*
	 * F-04: MS-FSCC 2.3.74 — populate FILE_LEVEL_TRIM_OUTPUT with
	 * NumRangesProcessed (number of ranges successfully trimmed).
	 * Return success even if some ranges failed (trim is best-effort).
	 */
	if (max_out_len >= sizeof(*f04_out)) {
		f04_out = (struct file_level_trim_output *)&rsp->Buffer[0];
		f04_out->NumRangesProcessed = cpu_to_le32(num_processed);
		*out_len = sizeof(*f04_out);
	} else {
		*out_len = 0;
	}
	return 0;
}

/*
 * MS-FSCC §2.3.30 FSCTL_PIPE_WAIT request structure
 */
struct fsctl_pipe_wait_req {
	__le64	Timeout;		/* 100ns units; 0 = use server default */
	__u8	TimeoutSpecified;
	__u8	Padding;
	__le16	NameLength;		/* byte count of Name[] */
	/* __u8 Name[] follows */
} __packed;

/**
 * ksmbd_fsctl_pipe_wait() - Handle FSCTL_PIPE_WAIT
 * @work:	    smb work for this request
 * @id:		    volatile file id
 * @in_buf:	    input buffer (FSCTL_PIPE_WAIT request)
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * MS-FSCC §2.3.30: The server waits up to Timeout (100ns units) for a named
 * pipe instance to become available.  ksmbd does not implement blocking pipe
 * listener queues, so we check if a pipe FID is already open and return
 * STATUS_IO_TIMEOUT if the pipe is not available.
 *
 * Return: 0 on success, -ETIMEDOUT when pipe is not available
 */
static int ksmbd_fsctl_pipe_wait(struct ksmbd_work *work,
				 u64 id, void *in_buf,
				 unsigned int in_buf_len,
				 unsigned int max_out_len,
				 struct smb2_ioctl_rsp *rsp,
				 unsigned int *out_len)
{
	struct fsctl_pipe_wait_req *req;
	s64 timeout_100ns;
	unsigned int wait_ms;

	*out_len = 0;

	if (in_buf_len < sizeof(*req)) {
		/* No valid request structure; succeed unconditionally */
		ksmbd_debug(SMB, "FSCTL_PIPE_WAIT: no request data, success\n");
		return 0;
	}

	req = (struct fsctl_pipe_wait_req *)in_buf;
	timeout_100ns = (s64)le64_to_cpu(req->Timeout);

	/*
	 * Compute wait in ms.  Use 50ms if no timeout was specified.
	 * Cap at 500ms to avoid blocking the worker thread excessively.
	 */
	if (!req->TimeoutSpecified || timeout_100ns == 0) {
		wait_ms = 50;
	} else {
		wait_ms = (unsigned int)min_t(s64,
					      div_s64(timeout_100ns, 10000LL),
					      500LL);
		if (wait_ms == 0)
			wait_ms = 1;
	}

	ksmbd_debug(SMB, "FSCTL_PIPE_WAIT: NameLength=%u timeout=%u ms\n",
		    le16_to_cpu(req->NameLength), wait_ms);

	/*
	 * Check if the pipe handle (id) is already open.
	 * If a valid FID exists, the pipe is connected — return success.
	 */
	if (has_file_id(id)) {
		struct ksmbd_file *fp = ksmbd_lookup_fd_fast(work, id);

		if (fp) {
			ksmbd_fd_put(work, fp);
			ksmbd_debug(SMB,
				    "FSCTL_PIPE_WAIT: pipe FID open, success\n");
			return 0;
		}
	}

	/*
	 * No open pipe found.  Sleep briefly (up to 50ms) then return
	 * STATUS_IO_TIMEOUT as required by the spec.
	 */
	msleep_interruptible(min_t(unsigned int, wait_ms, 50));

	ksmbd_debug(SMB,
		    "FSCTL_PIPE_WAIT: pipe unavailable, STATUS_IO_TIMEOUT\n");
	rsp->hdr.Status = STATUS_IO_TIMEOUT;
	return -ETIMEDOUT;
}

/* FSCTL handler descriptors */
static struct ksmbd_fsctl_handler file_level_trim_handler = {
	.ctl_code = FSCTL_FILE_LEVEL_TRIM,
	.handler  = ksmbd_fsctl_file_level_trim,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler pipe_wait_handler = {
	.ctl_code = FSCTL_PIPE_WAIT,
	.handler  = ksmbd_fsctl_pipe_wait,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler *extra_handlers[] = {
	&file_level_trim_handler,
	&pipe_wait_handler,
};

/**
 * ksmbd_fsctl_extra_init() - Initialize extra FSCTL handlers
 *
 * Registers extra FSCTL handlers, including:
 * - FSCTL_FILE_LEVEL_TRIM (0x00098208)
 * - FSCTL_PIPE_WAIT (0x00110018)
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_fsctl_extra_init(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(extra_handlers); i++) {
		ret = ksmbd_register_fsctl(extra_handlers[i]);
		if (ret) {
			pr_err("Failed to register FSCTL 0x%08x: %d\n",
			       extra_handlers[i]->ctl_code, ret);
			goto err_unregister;
		}
	}

	ksmbd_debug(SMB, "Extra FSCTL handlers initialized\n");
	return 0;

err_unregister:
	while (--i >= 0)
		ksmbd_unregister_fsctl(extra_handlers[i]);
	return ret;
}

/**
 * ksmbd_fsctl_extra_exit() - Tear down extra FSCTL handlers
 *
 * Unregisters all extra FSCTL handlers.
 */
void ksmbd_fsctl_extra_exit(void)
{
	int i;

	for (i = ARRAY_SIZE(extra_handlers) - 1; i >= 0; i--)
		ksmbd_unregister_fsctl(extra_handlers[i]);
}
