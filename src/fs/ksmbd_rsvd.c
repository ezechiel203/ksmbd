// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   MS-RSVD (Remote Shared Virtual Disk) protocol support for ksmbd
 *
 *   Implements FSCTL handlers for shared virtual disk operations used
 *   by Hyper-V to share VHDX files across cluster nodes via SMB.
 *
 *   Three FSCTLs are tunneled through SMB2 IOCTL:
 *     - FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT  (capability query)
 *     - FSCTL_SVHDX_SYNC_TUNNEL_REQUEST          (synchronous operations)
 *     - FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST          (asynchronous operations)
 *
 *   Reference: [MS-RSVD] Remote Shared Virtual Disk Protocol
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/string.h>

#include "ksmbd_rsvd.h"
#include "ksmbd_fsctl.h"
#include "smbfsctl.h"
#include "smb2pdu.h"
#include "smbstatus.h"
#include "glob.h"
#include "ksmbd_work.h"
#include "vfs_cache.h"

/* ------------------------------------------------------------------ */
/*  Tunnel operation validation helpers                                */
/* ------------------------------------------------------------------ */

/**
 * rsvd_validate_tunnel_header() - Validate tunnel operation header
 * @in_buf:     input buffer containing the tunnel request
 * @in_buf_len: length of input buffer
 * @hdr:        [out] pointer to the parsed header
 *
 * Validates that the input buffer is large enough to contain a tunnel
 * operation header and that the operation code has the correct prefix.
 *
 * Return: 0 on success, negative errno on failure
 */
static int rsvd_validate_tunnel_header(void *in_buf, unsigned int in_buf_len,
				       struct svhdx_tunnel_operation_header **hdr)
{
	if (in_buf_len < SVHDX_TUNNEL_OP_HEADER_SIZE)
		return -EINVAL;

	*hdr = (struct svhdx_tunnel_operation_header *)in_buf;

	/* MS-RSVD 3.2.5.5: upper byte must be 0x02 */
	if ((le32_to_cpu((*hdr)->OperationCode) & RSVD_TUNNEL_OPCODE_PREFIX_MASK)
	     != RSVD_TUNNEL_OPCODE_PREFIX_VAL)
		return -ENODEV;

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Tunnel sub-operation handlers                                      */
/* ------------------------------------------------------------------ */

/**
 * rsvd_handle_get_initial_info() - Handle RSVD_TUNNEL_GET_INITIAL_INFO
 * @work:        smb work for this request
 * @hdr:         tunnel operation header (request)
 * @in_buf:      input buffer (after header)
 * @in_buf_len:  remaining input length
 * @out_buf:     output buffer (after response header)
 * @max_out_len: maximum output bytes available
 * @out_len:     [out] bytes written to output
 *
 * Returns server version and basic virtual disk geometry.
 * Since ksmbd does not directly manage VHDX files, this returns
 * stub values indicating RSVD version 2 support with generic geometry.
 *
 * Return: NTSTATUS value for the tunnel Status field
 */
static __le32 rsvd_handle_get_initial_info(struct ksmbd_work *work,
					   struct svhdx_tunnel_operation_header *hdr,
					   void *in_buf, unsigned int in_buf_len,
					   void *out_buf, unsigned int max_out_len,
					   unsigned int *out_len)
{
	struct svhdx_tunnel_initial_info_rsp *rsp;

	if (max_out_len < sizeof(*rsp)) {
		*out_len = 0;
		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */
	}

	rsp = (struct svhdx_tunnel_initial_info_rsp *)out_buf;
	memset(rsp, 0, sizeof(*rsp));

	rsp->ServerVersion = cpu_to_le32(RSVD_PROTOCOL_VERSION_2);
	rsp->SectorSize = cpu_to_le32(512);
	rsp->PhysicalSectorSize = cpu_to_le32(4096);
	rsp->VirtualSize = cpu_to_le64(0);

	*out_len = sizeof(*rsp);
	return 0; /* STATUS_SUCCESS */
}

/**
 * rsvd_handle_check_connection_status() - Handle RSVD_TUNNEL_CHECK_CONNECTION_STATUS
 * @work:        smb work for this request
 * @hdr:         tunnel operation header
 * @in_buf:      input buffer (after header)
 * @in_buf_len:  remaining input length
 * @out_buf:     output buffer (after response header)
 * @max_out_len: maximum output bytes available
 * @out_len:     [out] bytes written to output
 *
 * Verifies that the shared virtual disk connection is still active.
 * The response is just the tunnel header with a success status.
 *
 * Return: NTSTATUS value for the tunnel Status field
 */
static __le32 rsvd_handle_check_connection_status(struct ksmbd_work *work,
						  struct svhdx_tunnel_operation_header *hdr,
						  void *in_buf, unsigned int in_buf_len,
						  void *out_buf, unsigned int max_out_len,
						  unsigned int *out_len)
{
	/* No additional response data -- just header with success */
	*out_len = 0;
	return 0; /* STATUS_SUCCESS */
}

/**
 * rsvd_handle_get_disk_info() - Handle RSVD_TUNNEL_GET_DISK_INFO
 * @work:        smb work for this request
 * @hdr:         tunnel operation header
 * @in_buf:      input buffer (after header)
 * @in_buf_len:  remaining input length
 * @out_buf:     output buffer (after response header)
 * @max_out_len: maximum output bytes available
 * @out_len:     [out] bytes written to output
 *
 * Returns disk information for the shared virtual disk.
 * Returns stub values since ksmbd does not parse VHDX metadata.
 *
 * Return: NTSTATUS value for the tunnel Status field
 */
static __le32 rsvd_handle_get_disk_info(struct ksmbd_work *work,
					struct svhdx_tunnel_operation_header *hdr,
					void *in_buf, unsigned int in_buf_len,
					void *out_buf, unsigned int max_out_len,
					unsigned int *out_len)
{
	struct svhdx_tunnel_disk_info_rsp *rsp;

	if (max_out_len < sizeof(*rsp)) {
		*out_len = 0;
		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */
	}

	rsp = (struct svhdx_tunnel_disk_info_rsp *)out_buf;
	memset(rsp, 0, sizeof(*rsp));

	rsp->DiskType = cpu_to_le32(SVHD_DISK_TYPE_DYNAMIC);
	rsp->DiskFormat = cpu_to_le32(SVHD_DISK_FORMAT_VHDX);
	rsp->BlockSize = cpu_to_le32(32 * 1024 * 1024); /* 32 MB */
	rsp->IsMounted = 0;
	rsp->Is4kAligned = 1;
	rsp->FileSize = cpu_to_le64(0);

	*out_len = sizeof(*rsp);
	return 0; /* STATUS_SUCCESS */
}

/**
 * rsvd_handle_validate_disk() - Handle RSVD_TUNNEL_VALIDATE_DISK
 * @work:        smb work for this request
 * @hdr:         tunnel operation header
 * @in_buf:      input buffer (after header)
 * @in_buf_len:  remaining input length
 * @out_buf:     output buffer (after response header)
 * @max_out_len: maximum output bytes available
 * @out_len:     [out] bytes written to output
 *
 * Validates whether the virtual disk is accessible.
 *
 * Return: NTSTATUS value for the tunnel Status field
 */
static __le32 rsvd_handle_validate_disk(struct ksmbd_work *work,
					struct svhdx_tunnel_operation_header *hdr,
					void *in_buf, unsigned int in_buf_len,
					void *out_buf, unsigned int max_out_len,
					unsigned int *out_len)
{
	struct svhdx_tunnel_validate_disk_rsp *rsp;

	if (max_out_len < sizeof(*rsp)) {
		*out_len = 0;
		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */
	}

	rsp = (struct svhdx_tunnel_validate_disk_rsp *)out_buf;

	/*
	 * ksmbd does not parse VHDX internals, so we report the disk
	 * as not valid.  A full implementation would inspect the VHDX
	 * header signature.
	 */
	rsp->IsValidDisk = 0;

	*out_len = sizeof(*rsp);
	return 0; /* STATUS_SUCCESS */
}

/**
 * rsvd_handle_srb_status() - Handle RSVD_TUNNEL_SRB_STATUS_OPERATION
 * @work:        smb work for this request
 * @hdr:         tunnel operation header
 * @in_buf:      input buffer (after header)
 * @in_buf_len:  remaining input length
 * @out_buf:     output buffer (after response header)
 * @max_out_len: maximum output bytes available
 * @out_len:     [out] bytes written to output
 *
 * Returns the sense error code from the most recently failed SCSI request.
 * Since ksmbd does not execute real SCSI commands, return all-zero (success).
 *
 * Return: NTSTATUS value for the tunnel Status field
 */
static __le32 rsvd_handle_srb_status(struct ksmbd_work *work,
				     struct svhdx_tunnel_operation_header *hdr,
				     void *in_buf, unsigned int in_buf_len,
				     void *out_buf, unsigned int max_out_len,
				     unsigned int *out_len)
{
	struct svhdx_tunnel_srb_status_rsp *rsp;

	if (max_out_len < sizeof(*rsp)) {
		*out_len = 0;
		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */
	}

	rsp = (struct svhdx_tunnel_srb_status_rsp *)out_buf;
	memset(rsp, 0, sizeof(*rsp));
	rsp->StatusKey = 0;
	rsp->SenseInfoAutoGenerated = 0;
	rsp->SenseInfoExLength = 0;
	rsp->ScsiStatus = 0; /* GOOD */

	*out_len = sizeof(*rsp);
	return 0; /* STATUS_SUCCESS */
}

/**
 * rsvd_handle_meta_op_query_progress() - Handle RSVD_TUNNEL_META_OPERATION_QUERY_PROGRESS
 * @work:        smb work for this request
 * @hdr:         tunnel operation header
 * @in_buf:      input buffer (after header)
 * @in_buf_len:  remaining input length
 * @out_buf:     output buffer (after response header)
 * @max_out_len: maximum output bytes available
 * @out_len:     [out] bytes written to output
 *
 * Reports progress of an ongoing meta-operation.
 * Returns 100% complete since no real meta-operations are in progress.
 *
 * Return: NTSTATUS value for the tunnel Status field
 */
static __le32 rsvd_handle_meta_op_query_progress(struct ksmbd_work *work,
						  struct svhdx_tunnel_operation_header *hdr,
						  void *in_buf, unsigned int in_buf_len,
						  void *out_buf, unsigned int max_out_len,
						  unsigned int *out_len)
{
	struct svhdx_tunnel_meta_op_progress_rsp *rsp;

	if (max_out_len < sizeof(*rsp)) {
		*out_len = 0;
		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */
	}

	rsp = (struct svhdx_tunnel_meta_op_progress_rsp *)out_buf;
	rsp->CurrentProgressValue = cpu_to_le64(100);
	rsp->CompleteValue = cpu_to_le64(100);

	*out_len = sizeof(*rsp);
	return 0; /* STATUS_SUCCESS */
}

/**
 * rsvd_handle_change_tracking_get_params() - Handle RSVD_TUNNEL_CHANGE_TRACKING_GET_PARAMETERS
 * @work:        smb work for this request
 * @hdr:         tunnel operation header
 * @in_buf:      input buffer (after header)
 * @in_buf_len:  remaining input length
 * @out_buf:     output buffer (after response header)
 * @max_out_len: maximum output bytes available
 * @out_len:     [out] bytes written to output
 *
 * Returns change tracking parameters. Reports tracking as not active.
 *
 * Return: NTSTATUS value for the tunnel Status field
 */
static __le32 rsvd_handle_change_tracking_get_params(struct ksmbd_work *work,
						     struct svhdx_tunnel_operation_header *hdr,
						     void *in_buf, unsigned int in_buf_len,
						     void *out_buf, unsigned int max_out_len,
						     unsigned int *out_len)
{
	struct svhdx_tunnel_change_tracking_params_rsp *rsp;

	if (max_out_len < sizeof(*rsp)) {
		*out_len = 0;
		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */
	}

	rsp = (struct svhdx_tunnel_change_tracking_params_rsp *)out_buf;
	memset(rsp, 0, sizeof(*rsp));

	*out_len = sizeof(*rsp);
	return 0; /* STATUS_SUCCESS */
}

/* ------------------------------------------------------------------ */
/*  Tunnel request dispatcher                                          */
/* ------------------------------------------------------------------ */

/**
 * rsvd_dispatch_tunnel_op() - Dispatch a tunnel operation by OperationCode
 * @work:        smb work for this request
 * @in_buf:      input buffer (includes tunnel header)
 * @in_buf_len:  total input buffer length
 * @rsp:         ioctl response structure
 * @max_out_len: maximum output length from client
 * @out_len:     [out] total output bytes written (header + payload)
 *
 * Parses the tunnel operation header, validates the operation code,
 * dispatches to the appropriate sub-handler, and constructs the
 * tunnel response header.
 *
 * Return: 0 on success, negative errno on failure
 */
static int rsvd_dispatch_tunnel_op(struct ksmbd_work *work,
				   void *in_buf, unsigned int in_buf_len,
				   struct smb2_ioctl_rsp *rsp,
				   unsigned int max_out_len,
				   unsigned int *out_len)
{
	struct svhdx_tunnel_operation_header *req_hdr;
	struct svhdx_tunnel_operation_header *rsp_hdr;
	u32 opcode;
	u32 ver_bits;
	void *payload_in;
	void *payload_out;
	unsigned int payload_in_len;
	unsigned int payload_max_out;
	unsigned int payload_out_len = 0;
	__le32 tunnel_status;
	int ret;

	/* Validate and extract the tunnel header */
	ret = rsvd_validate_tunnel_header(in_buf, in_buf_len, &req_hdr);
	if (ret) {
		if (ret == -ENODEV) {
			/* Invalid operation code prefix */
			rsp->hdr.Status = STATUS_INVALID_DEVICE_REQUEST;
			return -EINVAL;
		}
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return ret;
	}

	opcode = le32_to_cpu(req_hdr->OperationCode);

	/*
	 * MS-RSVD 3.2.5.5: validate version bits.
	 * Version 1 operations have 0x001 in bits [23:12].
	 * Version 2 operations have 0x002 in bits [23:12].
	 * We advertise version 2, so accept both.
	 */
	ver_bits = opcode & RSVD_TUNNEL_OPCODE_VER_MASK;
	if (ver_bits != RSVD_TUNNEL_OPCODE_VER1 &&
	    ver_bits != RSVD_TUNNEL_OPCODE_VER2) {
		ksmbd_debug(SMB,
			    "RSVD: unknown version bits 0x%08x in opcode 0x%08x\n",
			    ver_bits, opcode);
		rsp->hdr.Status = cpu_to_le32(STATUS_SVHDX_VERSION_MISMATCH);
		return -EINVAL;
	}

	/* Ensure output buffer can hold at least the response header */
	if (max_out_len < SVHDX_TUNNEL_OP_HEADER_SIZE) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	/* Set up response header in the output buffer */
	rsp_hdr = (struct svhdx_tunnel_operation_header *)&rsp->Buffer[0];
	rsp_hdr->OperationCode = req_hdr->OperationCode;
	rsp_hdr->RequestId = req_hdr->RequestId;

	/* Compute payload pointers */
	payload_in = (u8 *)in_buf + SVHDX_TUNNEL_OP_HEADER_SIZE;
	payload_in_len = in_buf_len - SVHDX_TUNNEL_OP_HEADER_SIZE;
	payload_out = (u8 *)rsp_hdr + SVHDX_TUNNEL_OP_HEADER_SIZE;
	payload_max_out = max_out_len - SVHDX_TUNNEL_OP_HEADER_SIZE;

	/* Dispatch based on operation code */
	switch (opcode) {
	case RSVD_TUNNEL_GET_INITIAL_INFO:
		tunnel_status = rsvd_handle_get_initial_info(
			work, req_hdr, payload_in, payload_in_len,
			payload_out, payload_max_out, &payload_out_len);
		break;

	case RSVD_TUNNEL_CHECK_CONNECTION_STATUS:
		tunnel_status = rsvd_handle_check_connection_status(
			work, req_hdr, payload_in, payload_in_len,
			payload_out, payload_max_out, &payload_out_len);
		break;

	case RSVD_TUNNEL_GET_DISK_INFO:
		tunnel_status = rsvd_handle_get_disk_info(
			work, req_hdr, payload_in, payload_in_len,
			payload_out, payload_max_out, &payload_out_len);
		break;

	case RSVD_TUNNEL_VALIDATE_DISK:
		tunnel_status = rsvd_handle_validate_disk(
			work, req_hdr, payload_in, payload_in_len,
			payload_out, payload_max_out, &payload_out_len);
		break;

	case RSVD_TUNNEL_SRB_STATUS_OPERATION:
		tunnel_status = rsvd_handle_srb_status(
			work, req_hdr, payload_in, payload_in_len,
			payload_out, payload_max_out, &payload_out_len);
		break;

	case RSVD_TUNNEL_META_OPERATION_QUERY_PROGRESS:
		tunnel_status = rsvd_handle_meta_op_query_progress(
			work, req_hdr, payload_in, payload_in_len,
			payload_out, payload_max_out, &payload_out_len);
		break;

	case RSVD_TUNNEL_CHANGE_TRACKING_GET_PARAMETERS:
		tunnel_status = rsvd_handle_change_tracking_get_params(
			work, req_hdr, payload_in, payload_in_len,
			payload_out, payload_max_out, &payload_out_len);
		break;

	case RSVD_TUNNEL_SCSI_OPERATION:
		/*
		 * SCSI passthrough requires actual block device access.
		 * Not implemented -- return STATUS_NOT_SUPPORTED.
		 */
		ksmbd_debug(SMB,
			    "RSVD: SCSI tunnel operation not implemented\n");
		tunnel_status = cpu_to_le32(0xC00000BB); /* STATUS_NOT_SUPPORTED */
		payload_out_len = 0;
		break;

	case RSVD_TUNNEL_META_OPERATION_START:
	case RSVD_TUNNEL_VHDSET_QUERY_INFORMATION:
	case RSVD_TUNNEL_DELETE_SNAPSHOT:
	case RSVD_TUNNEL_CHANGE_TRACKING_START:
	case RSVD_TUNNEL_CHANGE_TRACKING_STOP:
	case RSVD_TUNNEL_QUERY_VIRTUAL_DISK_CHANGES:
	case RSVD_TUNNEL_QUERY_SAFE_SIZE:
		/*
		 * Advanced VHDX management operations.
		 * These require deep VHDX metadata parsing -- stub
		 * them with STATUS_NOT_SUPPORTED.
		 */
		ksmbd_debug(SMB,
			    "RSVD: tunnel operation 0x%08x not implemented\n",
			    opcode);
		tunnel_status = cpu_to_le32(0xC00000BB); /* STATUS_NOT_SUPPORTED */
		payload_out_len = 0;
		break;

	default:
		ksmbd_debug(SMB,
			    "RSVD: unknown tunnel operation 0x%08x\n", opcode);
		tunnel_status = cpu_to_le32(0xC000000D); /* STATUS_INVALID_PARAMETER */
		payload_out_len = 0;
		break;
	}

	/* Fill in the tunnel response status */
	rsp_hdr->Status = tunnel_status;

	/* Total output = tunnel header + payload */
	*out_len = SVHDX_TUNNEL_OP_HEADER_SIZE + payload_out_len;
	return 0;
}

/* ------------------------------------------------------------------ */
/*  FSCTL handler callbacks                                            */
/* ------------------------------------------------------------------ */

/**
 * fsctl_query_shared_virtual_disk_support_handler() -
 *     Handle FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT
 *
 * Returns the server's shared virtual disk capabilities.
 * Indicates basic SVHD support without CDP snapshot support.
 */
static int fsctl_query_shared_virtual_disk_support_handler(
	struct ksmbd_work *work, u64 id,
	void *in_buf, unsigned int in_buf_len,
	unsigned int max_out_len,
	struct smb2_ioctl_rsp *rsp,
	unsigned int *out_len)
{
	struct shared_virtual_disk_support *support;

	if (max_out_len < sizeof(*support)) {
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
		*out_len = 0;
		return -ENOSPC;
	}

	support = (struct shared_virtual_disk_support *)&rsp->Buffer[0];
	support->SharedVirtualDiskSupport = cpu_to_le32(SVHD_SUPPORT_SHARED);
	support->SharedVirtualDiskHandleState =
		cpu_to_le32(SVHD_HANDLE_STATE_NONE);

	*out_len = sizeof(*support);

	ksmbd_debug(SMB, "RSVD: query shared virtual disk support\n");
	return 0;
}

/**
 * fsctl_svhdx_sync_tunnel_handler() -
 *     Handle FSCTL_SVHDX_SYNC_TUNNEL_REQUEST
 *
 * Dispatches synchronous tunnel operations.  The input buffer contains
 * an SVHDX_TUNNEL_OPERATION_HEADER followed by operation-specific data.
 */
static int fsctl_svhdx_sync_tunnel_handler(
	struct ksmbd_work *work, u64 id,
	void *in_buf, unsigned int in_buf_len,
	unsigned int max_out_len,
	struct smb2_ioctl_rsp *rsp,
	unsigned int *out_len)
{
	ksmbd_debug(SMB, "RSVD: sync tunnel request, in_len=%u, max_out=%u\n",
		    in_buf_len, max_out_len);

	return rsvd_dispatch_tunnel_op(work, in_buf, in_buf_len,
				       rsp, max_out_len, out_len);
}

/**
 * fsctl_svhdx_async_tunnel_handler() -
 *     Handle FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST
 *
 * Dispatches asynchronous tunnel operations.  For now, these are
 * handled synchronously using the same dispatcher, since ksmbd does
 * not implement true async RSVD processing.
 */
static int fsctl_svhdx_async_tunnel_handler(
	struct ksmbd_work *work, u64 id,
	void *in_buf, unsigned int in_buf_len,
	unsigned int max_out_len,
	struct smb2_ioctl_rsp *rsp,
	unsigned int *out_len)
{
	ksmbd_debug(SMB, "RSVD: async tunnel request, in_len=%u, max_out=%u\n",
		    in_buf_len, max_out_len);

	/*
	 * For now, dispatch async requests synchronously.
	 * A full implementation would queue work and send
	 * an interim response, then complete asynchronously.
	 */
	return rsvd_dispatch_tunnel_op(work, in_buf, in_buf_len,
				       rsp, max_out_len, out_len);
}

/* ------------------------------------------------------------------ */
/*  FSCTL handler descriptors                                          */
/* ------------------------------------------------------------------ */

static struct ksmbd_fsctl_handler rsvd_handlers[] = {
	{
		.ctl_code = FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT,
		.handler  = fsctl_query_shared_virtual_disk_support_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SVHDX_SYNC_TUNNEL_REQUEST,
		.handler  = fsctl_svhdx_sync_tunnel_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST,
		.handler  = fsctl_svhdx_async_tunnel_handler,
		.owner    = THIS_MODULE,
	},
};

/* ------------------------------------------------------------------ */
/*  Init / Exit                                                        */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_rsvd_init() - Initialize RSVD subsystem
 *
 * Registers all three RSVD FSCTL handlers with the dispatch table.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_rsvd_init(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(rsvd_handlers); i++) {
		ret = ksmbd_register_fsctl(&rsvd_handlers[i]);
		if (ret) {
			pr_err("RSVD: failed to register FSCTL 0x%08x: %d\n",
			       rsvd_handlers[i].ctl_code, ret);
			goto err_unregister;
		}
	}

	ksmbd_debug(SMB, "RSVD subsystem initialized (%zu handlers)\n",
		    ARRAY_SIZE(rsvd_handlers));
	return 0;

err_unregister:
	while (--i >= 0)
		ksmbd_unregister_fsctl(&rsvd_handlers[i]);
	return ret;
}

/**
 * ksmbd_rsvd_exit() - Tear down RSVD subsystem
 *
 * Unregisters all RSVD FSCTL handlers.
 */
void ksmbd_rsvd_exit(void)
{
	int i;

	for (i = ARRAY_SIZE(rsvd_handlers) - 1; i >= 0; i--)
		ksmbd_unregister_fsctl(&rsvd_handlers[i]);
}
