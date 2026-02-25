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
 *   Handlers that are now covered by the built-in table remain in
 *   this file for reference but are not registered here.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/falloc.h>

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

static int ksmbd_fsctl_copychunk_common(struct ksmbd_work *work,
					u64 id, void *in_buf,
					unsigned int in_buf_len,
					unsigned int max_out_len,
					struct smb2_ioctl_rsp *rsp,
					unsigned int *out_len,
					bool check_dst_read_access)
{
	struct copychunk_ioctl_req *ci_req;
	struct copychunk_ioctl_rsp *ci_rsp;
	struct ksmbd_file *src_fp = NULL, *dst_fp = NULL;
	struct srv_copychunk *chunks;
	unsigned int i, chunk_count, chunk_count_written = 0;
	unsigned int chunk_size_written = 0;
	loff_t total_size_written = 0;
	int ret = 0;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len <= sizeof(struct copychunk_ioctl_req)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	if (max_out_len < sizeof(struct copychunk_ioctl_rsp)) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	ci_req = (struct copychunk_ioctl_req *)in_buf;
	ci_rsp = (struct copychunk_ioctl_rsp *)&rsp->Buffer[0];
	rsp->VolatileFileId = id;
	rsp->PersistentFileId = SMB2_NO_FID;

	ci_rsp->ChunksWritten =
		cpu_to_le32(ksmbd_server_side_copy_max_chunk_count());
	ci_rsp->ChunkBytesWritten =
		cpu_to_le32(ksmbd_server_side_copy_max_chunk_size());
	ci_rsp->TotalBytesWritten =
		cpu_to_le32(ksmbd_server_side_copy_max_total_size());

	chunks = (struct srv_copychunk *)&ci_req->Chunks[0];
	chunk_count = le32_to_cpu(ci_req->ChunkCount);
	if (!chunk_count) {
		*out_len = sizeof(struct copychunk_ioctl_rsp);
		return 0;
	}

	if (chunk_count > ksmbd_server_side_copy_max_chunk_count() ||
	    in_buf_len < offsetof(struct copychunk_ioctl_req, Chunks) +
			  chunk_count * sizeof(struct srv_copychunk)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	for (i = 0; i < chunk_count; i++) {
		if (!le32_to_cpu(chunks[i].Length) ||
		    le32_to_cpu(chunks[i].Length) >
		    ksmbd_server_side_copy_max_chunk_size())
			break;
		total_size_written += le32_to_cpu(chunks[i].Length);
	}
	if (i < chunk_count ||
	    total_size_written > ksmbd_server_side_copy_max_total_size()) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	src_fp = ksmbd_lookup_foreign_fd(work, le64_to_cpu(ci_req->ResumeKey[0]));
	dst_fp = ksmbd_lookup_fd_fast(work, id);
	if (!src_fp ||
	    src_fp->persistent_id != le64_to_cpu(ci_req->ResumeKey[1])) {
		rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;
		ret = -ENOENT;
		goto out;
	}
	if (!dst_fp) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		ret = -ENOENT;
		goto out;
	}

	rsp->VolatileFileId = dst_fp->volatile_id;
	rsp->PersistentFileId = dst_fp->persistent_id;

	if (check_dst_read_access &&
	    !(dst_fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE))) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		ret = -EACCES;
		goto out;
	}

	ret = ksmbd_vfs_copy_file_ranges(work, src_fp, dst_fp,
					 chunks, chunk_count,
					 &chunk_count_written,
					 &chunk_size_written,
					 &total_size_written);
	if (ret < 0) {
		if (ret == -EACCES)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (ret == -EAGAIN)
			rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;
		else if (ret == -EBADF)
			rsp->hdr.Status = STATUS_INVALID_HANDLE;
		else if (ret == -EFBIG || ret == -ENOSPC)
			rsp->hdr.Status = STATUS_DISK_FULL;
		else if (ret == -EINVAL)
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		else if (ret == -EISDIR)
			rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;
		else if (ret == -E2BIG)
			rsp->hdr.Status = STATUS_INVALID_VIEW_SIZE;
		else
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
	}

	if (chunk_count_written > 0) {
		loff_t preceding = 0;

		for (i = 0; i + 1 < chunk_count_written; i++)
			preceding += le32_to_cpu(chunks[i].Length);
		chunk_size_written = (unsigned int)(total_size_written - preceding);
	}

	ci_rsp->ChunksWritten = cpu_to_le32(chunk_count_written);
	ci_rsp->ChunkBytesWritten = cpu_to_le32(chunk_size_written);
	ci_rsp->TotalBytesWritten = cpu_to_le32(total_size_written);
	*out_len = sizeof(struct copychunk_ioctl_rsp);

out:
	ksmbd_fd_put(work, src_fp);
	ksmbd_fd_put(work, dst_fp);
	return ret;
}

static int ksmbd_fsctl_copychunk(struct ksmbd_work *work, u64 id, void *in_buf,
				 unsigned int in_buf_len,
				 unsigned int max_out_len,
				 struct smb2_ioctl_rsp *rsp,
				 unsigned int *out_len)
{
	return ksmbd_fsctl_copychunk_common(work, id, in_buf, in_buf_len,
					    max_out_len, rsp, out_len, true);
}

static int ksmbd_fsctl_copychunk_write(struct ksmbd_work *work, u64 id,
				       void *in_buf, unsigned int in_buf_len,
				       unsigned int max_out_len,
				       struct smb2_ioctl_rsp *rsp,
				       unsigned int *out_len)
{
	return ksmbd_fsctl_copychunk_common(work, id, in_buf, in_buf_len,
					    max_out_len, rsp, out_len, false);
}

static int ksmbd_fsctl_duplicate_extents_to_file(struct ksmbd_work *work,
						 u64 id, void *in_buf,
						 unsigned int in_buf_len,
						 unsigned int max_out_len,
						 struct smb2_ioctl_rsp *rsp,
						 unsigned int *out_len)
{
	struct duplicate_extents_to_file *dup_ext;
	struct ksmbd_file *fp_in = NULL, *fp_out = NULL;
	loff_t src_off, dst_off, length;
	loff_t copied;
	int ret = 0;

	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(struct duplicate_extents_to_file)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	dup_ext = (struct duplicate_extents_to_file *)in_buf;
	fp_in = ksmbd_lookup_fd_slow(work, dup_ext->VolatileFileHandle,
				     dup_ext->PersistentFileHandle);
	if (!fp_in) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	fp_out = ksmbd_lookup_fd_fast(work, id);
	if (!fp_out) {
		rsp->hdr.Status = STATUS_INVALID_HANDLE;
		ret = -ENOENT;
		goto out;
	}

	rsp->VolatileFileId = fp_out->volatile_id;
	rsp->PersistentFileId = fp_out->persistent_id;

	src_off = le64_to_cpu(dup_ext->SourceFileOffset);
	dst_off = le64_to_cpu(dup_ext->TargetFileOffset);
	length = le64_to_cpu(dup_ext->ByteCount);

	copied = vfs_clone_file_range(fp_in->filp, src_off,
				      fp_out->filp, dst_off, length, 0);
	if (copied != length) {
		copied = vfs_copy_file_range(fp_in->filp, src_off,
					     fp_out->filp, dst_off,
					     length, 0);
		if (copied != length)
			ret = copied < 0 ? copied : -EINVAL;
	}

	if (ret < 0) {
		if (ret == -EACCES || ret == -EPERM)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (ret == -EBADF)
			rsp->hdr.Status = STATUS_INVALID_HANDLE;
		else if (ret == -EFBIG || ret == -ENOSPC)
			rsp->hdr.Status = STATUS_DISK_FULL;
		else if (ret == -EISDIR)
			rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;
		else
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
	}

	*out_len = 0;
out:
	ksmbd_fd_put(work, fp_in);
	ksmbd_fd_put(work, fp_out);
	return ret;
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

static struct ksmbd_fsctl_handler __maybe_unused query_allocated_ranges_handler = {
	.ctl_code = FSCTL_QUERY_ALLOCATED_RANGES,
	.handler  = ksmbd_fsctl_query_allocated_ranges,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler __maybe_unused set_zero_data_handler = {
	.ctl_code = FSCTL_SET_ZERO_DATA,
	.handler  = ksmbd_fsctl_set_zero_data,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler __maybe_unused copychunk_handler = {
	.ctl_code = FSCTL_COPYCHUNK,
	.handler  = ksmbd_fsctl_copychunk,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler __maybe_unused copychunk_write_handler = {
	.ctl_code = FSCTL_COPYCHUNK_WRITE,
	.handler  = ksmbd_fsctl_copychunk_write,
	.owner    = THIS_MODULE,
};

static struct ksmbd_fsctl_handler __maybe_unused duplicate_extents_handler = {
	.ctl_code = FSCTL_DUPLICATE_EXTENTS_TO_FILE,
	.handler  = ksmbd_fsctl_duplicate_extents_to_file,
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
