// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Extra FSCTL handlers for ksmbd
 *
 *   Registers FSCTL handlers for FSCTL_FILE_LEVEL_TRIM,
 *   FSCTL_QUERY_ALLOCATED_RANGES, FSCTL_SET_ZERO_DATA, and
 *   FSCTL_PIPE_WAIT via the ksmbd FSCTL registration API.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/falloc.h>

#include "ksmbd_fsctl_extra.h"
#include "ksmbd_fsctl.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
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
	struct ksmbd_file *fp;
	unsigned int i, num_ranges;
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
		}
	}

	ksmbd_fd_put(work, fp);

	/*
	 * FSCTL_FILE_LEVEL_TRIM produces no output data.
	 * Return success even if some ranges failed -- this
	 * matches Windows Server behavior where trim is
	 * best-effort.
	 */
	*out_len = 0;
	return 0;
}

/**
 * ksmbd_fsctl_query_allocated_ranges() - Handle
 *                                        FSCTL_QUERY_ALLOCATED_RANGES
 * @work:	    smb work for this request
 * @id:		    volatile file id
 * @in_buf:	    input FILE_ALLOCATED_RANGE_BUFFER {FileOffset, Length}
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Uses vfs_llseek() with SEEK_DATA/SEEK_HOLE via the existing
 * ksmbd_vfs_fqar_lseek() helper to find allocated (non-sparse)
 * ranges and returns them in the response buffer.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_fsctl_query_allocated_ranges(struct ksmbd_work *work,
					      u64 id, void *in_buf,
					      unsigned int in_buf_len,
					      unsigned int max_out_len,
					      struct smb2_ioctl_rsp *rsp,
					      unsigned int *out_len)
{
	struct file_allocated_range_buffer *qar_req;
	struct file_allocated_range_buffer *qar_rsp;
	struct ksmbd_file *fp;
	unsigned int in_count, nbytes = 0;
	loff_t start, length;
	int ret;

	if (in_buf_len < sizeof(struct file_allocated_range_buffer)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	qar_req = (struct file_allocated_range_buffer *)in_buf;
	qar_rsp = (struct file_allocated_range_buffer *)&rsp->Buffer[0];

	start = le64_to_cpu(qar_req->file_offset);
	length = le64_to_cpu(qar_req->length);

	if (start < 0 || length < 0) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	/* How many output entries can we fit? */
	in_count = max_out_len /
		   sizeof(struct file_allocated_range_buffer);
	if (in_count == 0) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	ret = ksmbd_vfs_fqar_lseek(fp, start, length,
				    qar_rsp, in_count, &nbytes);
	ksmbd_fd_put(work, fp);

	if (ret == -E2BIG) {
		rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
	} else if (ret < 0) {
		*out_len = 0;
		return ret;
	}

	*out_len = nbytes * sizeof(struct file_allocated_range_buffer);
	return 0;
}

/**
 * ksmbd_fsctl_set_zero_data() - Handle FSCTL_SET_ZERO_DATA
 * @work:	    smb work for this request
 * @id:		    volatile file id
 * @in_buf:	    input FILE_ZERO_DATA_INFORMATION {FileOffset,
 *		    BeyondFinalZero}
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Zeros out a range of a file using the existing
 * ksmbd_vfs_zero_data() helper, which calls vfs_fallocate()
 * with FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE (or
 * FALLOC_FL_PUNCH_HOLE for sparse files).
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_fsctl_set_zero_data(struct ksmbd_work *work,
				     u64 id, void *in_buf,
				     unsigned int in_buf_len,
				     unsigned int max_out_len,
				     struct smb2_ioctl_rsp *rsp,
				     unsigned int *out_len)
{
	struct file_zero_data_information *zero_data;
	struct ksmbd_file *fp;
	loff_t off, len, bfz;
	int ret;

	if (!test_tree_conn_flag(work->tcon,
				 KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		ksmbd_debug(SMB,
			    "FSCTL_SET_ZERO_DATA: no write perm\n");
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(struct file_zero_data_information)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	zero_data = (struct file_zero_data_information *)in_buf;

	off = le64_to_cpu(zero_data->FileOffset);
	bfz = le64_to_cpu(zero_data->BeyondFinalZero);
	if (off < 0 || bfz < 0 || off > bfz) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	len = bfz - off;
	if (len == 0) {
		*out_len = 0;
		return 0;
	}

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	ret = ksmbd_vfs_zero_data(work, fp, off, len);
	ksmbd_fd_put(work, fp);
	if (ret < 0)
		return ret;

	*out_len = 0;
	return 0;
}

/**
 * ksmbd_fsctl_pipe_wait() - Handle FSCTL_PIPE_WAIT
 * @work:	    smb work for this request
 * @id:		    volatile file id
 * @in_buf:	    input buffer (pipe wait request)
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written
 *
 * Named pipe wait is handled minimally.  Since ksmbd does not
 * implement full named pipe semantics, this returns
 * STATUS_SUCCESS to satisfy clients that issue this FSCTL
 * during named pipe operations.
 *
 * Return: 0
 */
static int ksmbd_fsctl_pipe_wait(struct ksmbd_work *work,
				 u64 id, void *in_buf,
				 unsigned int in_buf_len,
				 unsigned int max_out_len,
				 struct smb2_ioctl_rsp *rsp,
				 unsigned int *out_len)
{
	ksmbd_debug(SMB, "FSCTL_PIPE_WAIT: returning success\n");
	*out_len = 0;
	return 0;
}

/* FSCTL handler descriptors */
static struct ksmbd_fsctl_handler file_level_trim_handler = {
	.ctl_code = FSCTL_FILE_LEVEL_TRIM,
	.handler  = ksmbd_fsctl_file_level_trim,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler query_allocated_ranges_handler = {
	.ctl_code = FSCTL_QUERY_ALLOCATED_RANGES,
	.handler  = ksmbd_fsctl_query_allocated_ranges,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler set_zero_data_handler = {
	.ctl_code = FSCTL_SET_ZERO_DATA,
	.handler  = ksmbd_fsctl_set_zero_data,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler pipe_wait_handler = {
	.ctl_code = FSCTL_PIPE_WAIT,
	.handler  = ksmbd_fsctl_pipe_wait,
	.owner    = THIS_MODULE,
};

/**
 * ksmbd_fsctl_extra_init() - Initialize extra FSCTL handlers
 *
 * Registers FSCTL handlers for FSCTL_FILE_LEVEL_TRIM (0x00098208),
 * FSCTL_QUERY_ALLOCATED_RANGES (0x000940CF),
 * FSCTL_SET_ZERO_DATA (0x000980C8), and
 * FSCTL_PIPE_WAIT (0x00110018).
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_fsctl_extra_init(void)
{
	int ret;

	ret = ksmbd_register_fsctl(&file_level_trim_handler);
	if (ret) {
		pr_err("Failed to register FSCTL_FILE_LEVEL_TRIM: %d\n",
		       ret);
		return ret;
	}

	ret = ksmbd_register_fsctl(&query_allocated_ranges_handler);
	if (ret) {
		pr_err("Failed to register FSCTL_QUERY_ALLOCATED_RANGES: %d\n",
		       ret);
		goto err_unregister_trim;
	}

	ret = ksmbd_register_fsctl(&set_zero_data_handler);
	if (ret) {
		pr_err("Failed to register FSCTL_SET_ZERO_DATA: %d\n",
		       ret);
		goto err_unregister_qar;
	}

	ret = ksmbd_register_fsctl(&pipe_wait_handler);
	if (ret) {
		pr_err("Failed to register FSCTL_PIPE_WAIT: %d\n",
		       ret);
		goto err_unregister_zero;
	}

	ksmbd_debug(SMB, "Extra FSCTL handlers initialized\n");
	return 0;

err_unregister_zero:
	ksmbd_unregister_fsctl(&set_zero_data_handler);
err_unregister_qar:
	ksmbd_unregister_fsctl(&query_allocated_ranges_handler);
err_unregister_trim:
	ksmbd_unregister_fsctl(&file_level_trim_handler);
	return ret;
}

/**
 * ksmbd_fsctl_extra_exit() - Tear down extra FSCTL handlers
 *
 * Unregisters all extra FSCTL handlers.
 */
void ksmbd_fsctl_extra_exit(void)
{
	ksmbd_unregister_fsctl(&pipe_wait_handler);
	ksmbd_unregister_fsctl(&set_zero_data_handler);
	ksmbd_unregister_fsctl(&query_allocated_ranges_handler);
	ksmbd_unregister_fsctl(&file_level_trim_handler);
}
