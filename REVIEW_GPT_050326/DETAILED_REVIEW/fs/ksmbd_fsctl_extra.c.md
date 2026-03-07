# Line-by-line Review: src/fs/ksmbd_fsctl_extra.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Extra FSCTL handlers for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   Registers supplemental FSCTL handlers that are intentionally`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   kept outside the built-in core table (currently`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   FSCTL_FILE_LEVEL_TRIM and FSCTL_PIPE_WAIT).`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *   Handlers that are now covered by the built-in table remain in`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *   this file for reference but are not registered here.`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/falloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/delay.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <linux/math64.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "ksmbd_fsctl_extra.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * FSCTL_FILE_LEVEL_TRIM (0x00098208) is not defined in smbfsctl.h,`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` * so define it here.`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#ifndef FSCTL_FILE_LEVEL_TRIM`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#define FSCTL_FILE_LEVEL_TRIM	0x00098208`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * MS-FSCC 2.3.73 - FILE_LEVEL_TRIM input structures`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` * FILE_LEVEL_TRIM:`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` *   Key    (4 bytes) - reserved, must be zero`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` *   NumRanges (4 bytes) - number of FILE_LEVEL_TRIM_RANGE entries`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` *   Ranges[]  - array of {Offset, Length} pairs`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `struct file_level_trim_range {`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	__le64	offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	__le64	length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `struct file_level_trim {`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	__le32	key;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	__le32	num_ranges;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	struct file_level_trim_range	ranges[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * ksmbd_fsctl_file_level_trim() - Handle FSCTL_FILE_LEVEL_TRIM`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * @work:	    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` * @id:		    volatile file id`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` * @in_buf:	    input buffer containing FILE_LEVEL_TRIM structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` * @in_buf_len:    input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` * @max_out_len:   maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` * @rsp:	    pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` * @out_len:	    [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * Iterates over the DataSetRanges in the input and calls`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` * vfs_fallocate() with FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * for each range to issue trim/discard operations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `static int ksmbd_fsctl_file_level_trim(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `				       u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `				       unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `				       unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `				       struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	struct file_level_trim *trim;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	unsigned int i, num_ranges;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	if (!test_tree_conn_flag(work->tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `				 KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `			    "FSCTL_FILE_LEVEL_TRIM: no write perm\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00097 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00098 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	if (in_buf_len < sizeof(struct file_level_trim)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00102 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00103 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	trim = (struct file_level_trim *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	num_ranges = le32_to_cpu(trim->num_ranges);`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	/* Validate that all range entries fit in the input buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	if (num_ranges > (in_buf_len - sizeof(struct file_level_trim)) /`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `			  sizeof(struct file_level_trim_range)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00112 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00113 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	if (num_ranges == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00123 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00124 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	smb_break_all_levII_oplock(work, fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	for (i = 0; i < num_ranges; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `		loff_t off = le64_to_cpu(trim->ranges[i].offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `		loff_t len = le64_to_cpu(trim->ranges[i].length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `		if (off < 0 || len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `		ret = vfs_fallocate(fp->filp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `				    FALLOC_FL_PUNCH_HOLE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `				    FALLOC_FL_KEEP_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `				    off, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `		if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `				    "TRIM range %u failed: %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `				    i, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `			 * Per MS-FSCC, individual range failures`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `			 * are not fatal; continue with remaining`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `			 * ranges and report the last error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	 * FSCTL_FILE_LEVEL_TRIM produces no output data.`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	 * Return success even if some ranges failed -- this`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	 * matches Windows Server behavior where trim is`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	 * best-effort.`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ` * ksmbd_fsctl_query_allocated_ranges() - Handle`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` *                                        FSCTL_QUERY_ALLOCATED_RANGES`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ` * @work:	    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ` * @id:		    volatile file id`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ` * @in_buf:	    input FILE_ALLOCATED_RANGE_BUFFER {FileOffset, Length}`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ` * @in_buf_len:    input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] ` * @max_out_len:   maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ` * @rsp:	    pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ` * @out_len:	    [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ` * Uses vfs_llseek() with SEEK_DATA/SEEK_HOLE via the existing`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ` * ksmbd_vfs_fqar_lseek() helper to find allocated (non-sparse)`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ` * ranges and returns them in the response buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `static int ksmbd_fsctl_query_allocated_ranges(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `					      u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `					      unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `					      unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `					      struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `					      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	struct file_allocated_range_buffer *qar_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	struct file_allocated_range_buffer *qar_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	unsigned int in_count, nbytes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	loff_t start, length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	if (in_buf_len < sizeof(struct file_allocated_range_buffer)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00196 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00197 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	qar_req = (struct file_allocated_range_buffer *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	qar_rsp = (struct file_allocated_range_buffer *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `	start = le64_to_cpu(qar_req->file_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	length = le64_to_cpu(qar_req->length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	if (start < 0 || length < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00207 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00208 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	/* How many output entries can we fit? */`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	in_count = max_out_len /`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `		   sizeof(struct file_allocated_range_buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	if (in_count == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00215 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00216 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00221 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00222 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	ret = ksmbd_vfs_fqar_lseek(fp, start, length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `				    qar_rsp, in_count, &nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	if (ret == -E2BIG) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00230 [NONE] `	} else if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	*out_len = nbytes * sizeof(struct file_allocated_range_buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ` * ksmbd_fsctl_set_zero_data() - Handle FSCTL_SET_ZERO_DATA`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] ` * @work:	    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] ` * @id:		    volatile file id`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ` * @in_buf:	    input FILE_ZERO_DATA_INFORMATION {FileOffset,`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ` *		    BeyondFinalZero}`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] ` * @in_buf_len:    input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] ` * @max_out_len:   maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ` * @rsp:	    pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ` * @out_len:	    [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ` * Zeros out a range of a file using the existing`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ` * ksmbd_vfs_zero_data() helper, which calls vfs_fallocate()`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ` * with FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE (or`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ` * FALLOC_FL_PUNCH_HOLE for sparse files).`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `static int ksmbd_fsctl_set_zero_data(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `				     u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `				     unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `				     unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `				     struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `				     unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	struct file_zero_data_information *zero_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	loff_t off, len, bfz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	if (!test_tree_conn_flag(work->tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `				 KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `			    "FSCTL_SET_ZERO_DATA: no write perm\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00274 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00275 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	if (in_buf_len < sizeof(struct file_zero_data_information)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00279 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00280 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	zero_data = (struct file_zero_data_information *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	off = le64_to_cpu(zero_data->FileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	bfz = le64_to_cpu(zero_data->BeyondFinalZero);`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	if (off < 0 || bfz < 0 || off > bfz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00288 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00289 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	len = bfz - off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	if (len == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00300 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00301 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	ret = ksmbd_vfs_zero_data(work, fp, off, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	if (ret == -EAGAIN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00307 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `static int ksmbd_fsctl_copychunk_common(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `					u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `					unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `					unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `					struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `					unsigned int *out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `					bool check_dst_read_access)`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	struct copychunk_ioctl_req *ci_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	struct copychunk_ioctl_rsp *ci_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `	struct ksmbd_file *src_fp = NULL, *dst_fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `	struct srv_copychunk *chunks;`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	unsigned int i, chunk_count, chunk_count_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	unsigned int chunk_size_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	loff_t total_size_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00335 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00336 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `	if (in_buf_len <= sizeof(struct copychunk_ioctl_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00340 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00341 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	if (max_out_len < sizeof(struct copychunk_ioctl_rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00345 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00346 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	ci_req = (struct copychunk_ioctl_req *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	ci_rsp = (struct copychunk_ioctl_rsp *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	rsp->VolatileFileId = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [PROTO_GATE|] `	rsp->PersistentFileId = SMB2_NO_FID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	 * Initialize response to zero.  Max values are only returned`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [PROTO_GATE|] `	 * in STATUS_INVALID_PARAMETER responses (MS-FSCC 2.3.12.1).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00356 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	ci_rsp->ChunksWritten = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	ci_rsp->ChunkBytesWritten = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	ci_rsp->TotalBytesWritten = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	chunks = (struct srv_copychunk *)&ci_req->Chunks[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	chunk_count = le32_to_cpu(ci_req->ChunkCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	if (!chunk_count) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `		*out_len = sizeof(struct copychunk_ioctl_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	/* MS-FSCC §2.3.12: reject only when ChunkCount EXCEEDS max (> not >=) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	if (chunk_count > ksmbd_server_side_copy_max_chunk_count() ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	    in_buf_len < offsetof(struct copychunk_ioctl_req, Chunks) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `			  chunk_count * sizeof(struct srv_copychunk)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `		ci_rsp->ChunksWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_chunk_count());`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `		ci_rsp->ChunkBytesWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_chunk_size());`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `		ci_rsp->TotalBytesWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_total_size());`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00379 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00380 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	for (i = 0; i < chunk_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `		if (!le32_to_cpu(chunks[i].Length) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `		    le32_to_cpu(chunks[i].Length) >`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `		    ksmbd_server_side_copy_max_chunk_size())`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `		total_size_written += le32_to_cpu(chunks[i].Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	if (i < chunk_count ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	    total_size_written > ksmbd_server_side_copy_max_total_size()) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `		ci_rsp->ChunksWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_chunk_count());`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `		ci_rsp->ChunkBytesWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_chunk_size());`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `		ci_rsp->TotalBytesWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_total_size());`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00398 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00399 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	src_fp = ksmbd_lookup_foreign_fd(work, le64_to_cpu(ci_req->ResumeKey[0]));`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	dst_fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	if (!src_fp ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	    src_fp->persistent_id != le64_to_cpu(ci_req->ResumeKey[1])) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00406 [NONE] `		ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00408 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	if (!dst_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00411 [NONE] `		ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00413 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	rsp->VolatileFileId = dst_fp->volatile_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	rsp->PersistentFileId = dst_fp->persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	if (check_dst_read_access &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	    !(dst_fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00421 [NONE] `		ret = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00423 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	ret = ksmbd_vfs_copy_file_ranges(work, src_fp, dst_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `					 chunks, chunk_count,`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `					 &chunk_count_written,`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `					 &chunk_size_written,`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `					 &total_size_written);`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `		if (ret == -EACCES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00433 [NONE] `		else if (ret == -EAGAIN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00435 [NONE] `		else if (ret == -EBADF)`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00437 [NONE] `		else if (ret == -EFBIG || ret == -ENOSPC)`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_DISK_FULL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00439 [NONE] `		else if (ret == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00441 [NONE] `		else if (ret == -EISDIR)`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00443 [NONE] `		else if (ret == -E2BIG)`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_VIEW_SIZE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00445 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00447 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	ci_rsp->ChunksWritten = cpu_to_le32(chunk_count_written);`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	 * MS-FSCC 2.3.12.1: ChunkBytesWritten MUST be zero when all`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	 * requested chunks completed successfully.`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	if (chunk_count_written == chunk_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `		ci_rsp->ChunkBytesWritten = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `		ci_rsp->ChunkBytesWritten = cpu_to_le32(chunk_size_written);`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	ci_rsp->TotalBytesWritten = cpu_to_le32(total_size_written);`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	*out_len = sizeof(struct copychunk_ioctl_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	ksmbd_fd_put(work, src_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	ksmbd_fd_put(work, dst_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `static int ksmbd_fsctl_copychunk(struct ksmbd_work *work, u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `				 unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `				 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `				 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `				 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	return ksmbd_fsctl_copychunk_common(work, id, in_buf, in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `					    max_out_len, rsp, out_len, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `static int ksmbd_fsctl_copychunk_write(struct ksmbd_work *work, u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `				       void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `				       unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `				       struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	return ksmbd_fsctl_copychunk_common(work, id, in_buf, in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `					    max_out_len, rsp, out_len, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `static int ksmbd_fsctl_duplicate_extents_to_file(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `						 u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `						 unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `						 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `						 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `						 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	struct duplicate_extents_to_file *dup_ext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	struct ksmbd_file *fp_in = NULL, *fp_out = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	loff_t src_off, dst_off, length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	loff_t copied;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00502 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00503 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	if (in_buf_len < sizeof(struct duplicate_extents_to_file)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00507 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00508 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	dup_ext = (struct duplicate_extents_to_file *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	fp_in = ksmbd_lookup_fd_slow(work, dup_ext->VolatileFileHandle,`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `				     dup_ext->PersistentFileHandle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	if (!fp_in) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00515 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00516 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	fp_out = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	if (!fp_out) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00521 [NONE] `		ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00523 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	rsp->VolatileFileId = fp_out->volatile_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	rsp->PersistentFileId = fp_out->persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	src_off = le64_to_cpu(dup_ext->SourceFileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `	dst_off = le64_to_cpu(dup_ext->TargetFileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	length = le64_to_cpu(dup_ext->ByteCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	copied = vfs_clone_file_range(fp_in->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `				      fp_out->filp, dst_off, length, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	if (copied != length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `		copied = vfs_copy_file_range(fp_in->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `					     fp_out->filp, dst_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `					     length, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `		if (copied != length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `			ret = copied < 0 ? copied : -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `		if (ret == -EACCES || ret == -EPERM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00545 [NONE] `		else if (ret == -EBADF)`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00547 [NONE] `		else if (ret == -EFBIG || ret == -ENOSPC)`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_DISK_FULL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00549 [NONE] `		else if (ret == -EISDIR)`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00551 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00553 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	ksmbd_fd_put(work, fp_in);`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `	ksmbd_fd_put(work, fp_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] ` * MS-FSCC §2.3.30 FSCTL_PIPE_WAIT request structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `struct fsctl_pipe_wait_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	__le64	Timeout;		/* 100ns units; 0 = use server default */`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	__u8	TimeoutSpecified;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	__u8	Padding;`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	__le16	NameLength;		/* byte count of Name[] */`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	/* __u8 Name[] follows */`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] ` * ksmbd_fsctl_pipe_wait() - Handle FSCTL_PIPE_WAIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] ` * @work:	    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] ` * @id:		    volatile file id`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] ` * @in_buf:	    input buffer (FSCTL_PIPE_WAIT request)`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] ` * @in_buf_len:    input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ` * @max_out_len:   maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] ` * @rsp:	    pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ` * @out_len:	    [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] ` * MS-FSCC §2.3.30: The server waits up to Timeout (100ns units) for a named`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ` * pipe instance to become available.  ksmbd does not implement blocking pipe`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] ` * listener queues, so we check if a pipe FID is already open and return`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [PROTO_GATE|] ` * STATUS_IO_TIMEOUT if the pipe is not available.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00587 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] ` * Return: 0 on success, -ETIMEDOUT when pipe is not available`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `static int ksmbd_fsctl_pipe_wait(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `				 u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `				 unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `				 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `				 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `				 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `	struct fsctl_pipe_wait_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	s64 timeout_100ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	unsigned int wait_ms;`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `	if (in_buf_len < sizeof(*req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `		/* No valid request structure; succeed unconditionally */`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `		ksmbd_debug(SMB, "FSCTL_PIPE_WAIT: no request data, success\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `	req = (struct fsctl_pipe_wait_req *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `	timeout_100ns = (s64)le64_to_cpu(req->Timeout);`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `	 * Compute wait in ms.  Use 50ms if no timeout was specified.`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `	 * Cap at 500ms to avoid blocking the worker thread excessively.`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `	if (!req->TimeoutSpecified || timeout_100ns == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `		wait_ms = 50;`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `		wait_ms = (unsigned int)min_t(s64,`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `					      div_s64(timeout_100ns, 10000LL),`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `					      500LL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `		if (wait_ms == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `			wait_ms = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `	ksmbd_debug(SMB, "FSCTL_PIPE_WAIT: NameLength=%u timeout=%u ms\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `		    le16_to_cpu(req->NameLength), wait_ms);`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `	 * Check if the pipe handle (id) is already open.`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `	 * If a valid FID exists, the pipe is connected — return success.`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	if (has_file_id(id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `		struct ksmbd_file *fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `		if (fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `				    "FSCTL_PIPE_WAIT: pipe FID open, success\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `	 * No open pipe found.  Sleep briefly (up to 50ms) then return`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [PROTO_GATE|] `	 * STATUS_IO_TIMEOUT as required by the spec.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00647 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	msleep_interruptible(min_t(unsigned int, wait_ms, 50));`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [PROTO_GATE|] `		    "FSCTL_PIPE_WAIT: pipe unavailable, STATUS_IO_TIMEOUT\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00652 [PROTO_GATE|] `	rsp->hdr.Status = STATUS_IO_TIMEOUT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00653 [ERROR_PATH|] `	return -ETIMEDOUT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00654 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `/* FSCTL handler descriptors */`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `static struct ksmbd_fsctl_handler file_level_trim_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `	.ctl_code = FSCTL_FILE_LEVEL_TRIM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	.handler  = ksmbd_fsctl_file_level_trim,`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `static struct ksmbd_fsctl_handler __maybe_unused query_allocated_ranges_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `	.ctl_code = FSCTL_QUERY_ALLOCATED_RANGES,`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `	.handler  = ksmbd_fsctl_query_allocated_ranges,`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `static struct ksmbd_fsctl_handler __maybe_unused set_zero_data_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `	.ctl_code = FSCTL_SET_ZERO_DATA,`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `	.handler  = ksmbd_fsctl_set_zero_data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `static struct ksmbd_fsctl_handler __maybe_unused copychunk_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	.ctl_code = FSCTL_COPYCHUNK,`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `	.handler  = ksmbd_fsctl_copychunk,`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `static struct ksmbd_fsctl_handler __maybe_unused copychunk_write_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `	.ctl_code = FSCTL_COPYCHUNK_WRITE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `	.handler  = ksmbd_fsctl_copychunk_write,`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `static struct ksmbd_fsctl_handler __maybe_unused duplicate_extents_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `	.ctl_code = FSCTL_DUPLICATE_EXTENTS_TO_FILE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `	.handler  = ksmbd_fsctl_duplicate_extents_to_file,`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `static struct ksmbd_fsctl_handler pipe_wait_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `	.ctl_code = FSCTL_PIPE_WAIT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `	.handler  = ksmbd_fsctl_pipe_wait,`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `static struct ksmbd_fsctl_handler *extra_handlers[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `	&file_level_trim_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `	&pipe_wait_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] ` * ksmbd_fsctl_extra_init() - Initialize extra FSCTL handlers`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] ` * Registers extra FSCTL handlers, including:`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] ` * - FSCTL_FILE_LEVEL_TRIM (0x00098208)`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] ` * - FSCTL_PIPE_WAIT (0x00110018)`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `int ksmbd_fsctl_extra_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	int i, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `	for (i = 0; i < ARRAY_SIZE(extra_handlers); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `		ret = ksmbd_register_fsctl(extra_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [ERROR_PATH|] `			pr_err("Failed to register FSCTL 0x%08x: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00721 [NONE] `			       extra_handlers[i]->ctl_code, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [ERROR_PATH|] `			goto err_unregister;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00723 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `	ksmbd_debug(SMB, "Extra FSCTL handlers initialized\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `err_unregister:`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `	while (--i >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `		ksmbd_unregister_fsctl(extra_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] ` * ksmbd_fsctl_extra_exit() - Tear down extra FSCTL handlers`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] ` * Unregisters all extra FSCTL handlers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `void ksmbd_fsctl_extra_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `	for (i = ARRAY_SIZE(extra_handlers) - 1; i >= 0; i--)`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `		ksmbd_unregister_fsctl(extra_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
