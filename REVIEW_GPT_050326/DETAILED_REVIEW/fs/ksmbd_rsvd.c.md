# Line-by-line Review: src/fs/ksmbd_rsvd.c

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
- L00006 [NONE] ` *   MS-RSVD (Remote Shared Virtual Disk) protocol support for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   Implements FSCTL handlers for shared virtual disk operations used`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   by Hyper-V to share VHDX files across cluster nodes via SMB.`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *   Three FSCTLs are tunneled through SMB2 IOCTL:`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *     - FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT  (capability query)`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *     - FSCTL_SVHDX_SYNC_TUNNEL_REQUEST          (synchronous operations)`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *     - FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST          (asynchronous operations)`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` *   Reference: [MS-RSVD] Remote Shared Virtual Disk Protocol`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "ksmbd_rsvd.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `/*  Tunnel operation validation helpers                                */`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * rsvd_validate_tunnel_header() - Validate tunnel operation header`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` * @in_buf:     input buffer containing the tunnel request`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * @in_buf_len: length of input buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` * @hdr:        [out] pointer to the parsed header`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * Validates that the input buffer is large enough to contain a tunnel`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * operation header and that the operation code has the correct prefix.`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `static int rsvd_validate_tunnel_header(void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `				       struct svhdx_tunnel_operation_header **hdr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	if (in_buf_len < SVHDX_TUNNEL_OP_HEADER_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	*hdr = (struct svhdx_tunnel_operation_header *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	/* MS-RSVD 3.2.5.5: upper byte must be 0x02 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	if ((le32_to_cpu((*hdr)->OperationCode) & RSVD_TUNNEL_OPCODE_PREFIX_MASK)`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	     != RSVD_TUNNEL_OPCODE_PREFIX_VAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [ERROR_PATH|] `		return -ENODEV;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `/*  Tunnel sub-operation handlers                                      */`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` * rsvd_handle_get_initial_info() - Handle RSVD_TUNNEL_GET_INITIAL_INFO`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` * @work:        smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` * @hdr:         tunnel operation header (request)`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` * @in_buf:      input buffer (after header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` * @in_buf_len:  remaining input length`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * @out_buf:     output buffer (after response header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` * @max_out_len: maximum output bytes available`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * @out_len:     [out] bytes written to output`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` * Returns server version and basic virtual disk geometry.`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` * Since ksmbd does not directly manage VHDX files, this returns`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` * stub values indicating RSVD version 2 support with generic geometry.`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` * Return: NTSTATUS value for the tunnel Status field`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `static __le32 rsvd_handle_get_initial_info(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `					   struct svhdx_tunnel_operation_header *hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `					   void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `					   void *out_buf, unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `					   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	struct svhdx_tunnel_initial_info_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	if (max_out_len < sizeof(*rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [PROTO_GATE|] `		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00095 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	rsp = (struct svhdx_tunnel_initial_info_rsp *)out_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	memset(rsp, 0, sizeof(*rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	rsp->ServerVersion = cpu_to_le32(RSVD_PROTOCOL_VERSION_2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	rsp->SectorSize = cpu_to_le32(512);`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	rsp->PhysicalSectorSize = cpu_to_le32(4096);`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	rsp->VirtualSize = cpu_to_le64(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	*out_len = sizeof(*rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [PROTO_GATE|] `	return 0; /* STATUS_SUCCESS */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00107 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` * rsvd_handle_check_connection_status() - Handle RSVD_TUNNEL_CHECK_CONNECTION_STATUS`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * @work:        smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` * @hdr:         tunnel operation header`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` * @in_buf:      input buffer (after header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ` * @in_buf_len:  remaining input length`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ` * @out_buf:     output buffer (after response header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ` * @max_out_len: maximum output bytes available`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` * @out_len:     [out] bytes written to output`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` * Verifies that the shared virtual disk connection is still active.`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` * The response is just the tunnel header with a success status.`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` * Return: NTSTATUS value for the tunnel Status field`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `static __le32 rsvd_handle_check_connection_status(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `						  struct svhdx_tunnel_operation_header *hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `						  void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `						  void *out_buf, unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `						  unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	/* No additional response data -- just header with success */`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [PROTO_GATE|] `	return 0; /* STATUS_SUCCESS */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00133 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ` * rsvd_handle_get_disk_info() - Handle RSVD_TUNNEL_GET_DISK_INFO`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ` * @work:        smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ` * @hdr:         tunnel operation header`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` * @in_buf:      input buffer (after header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` * @in_buf_len:  remaining input length`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` * @out_buf:     output buffer (after response header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` * @max_out_len: maximum output bytes available`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ` * @out_len:     [out] bytes written to output`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ` * Returns disk information for the shared virtual disk.`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ` * Returns stub values since ksmbd does not parse VHDX metadata.`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` * Return: NTSTATUS value for the tunnel Status field`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `static __le32 rsvd_handle_get_disk_info(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `					struct svhdx_tunnel_operation_header *hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `					void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `					void *out_buf, unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `					unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	struct svhdx_tunnel_disk_info_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	if (max_out_len < sizeof(*rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [PROTO_GATE|] `		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00161 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	rsp = (struct svhdx_tunnel_disk_info_rsp *)out_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	memset(rsp, 0, sizeof(*rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	rsp->DiskType = cpu_to_le32(SVHD_DISK_TYPE_DYNAMIC);`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	rsp->DiskFormat = cpu_to_le32(SVHD_DISK_FORMAT_VHDX);`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	rsp->BlockSize = cpu_to_le32(32 * 1024 * 1024); /* 32 MB */`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	rsp->IsMounted = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	rsp->Is4kAligned = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	rsp->FileSize = cpu_to_le64(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	*out_len = sizeof(*rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [PROTO_GATE|] `	return 0; /* STATUS_SUCCESS */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00175 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ` * rsvd_handle_validate_disk() - Handle RSVD_TUNNEL_VALIDATE_DISK`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ` * @work:        smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ` * @hdr:         tunnel operation header`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ` * @in_buf:      input buffer (after header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ` * @in_buf_len:  remaining input length`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ` * @out_buf:     output buffer (after response header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ` * @max_out_len: maximum output bytes available`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ` * @out_len:     [out] bytes written to output`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ` * Validates whether the virtual disk is accessible.`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ` * Return: NTSTATUS value for the tunnel Status field`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `static __le32 rsvd_handle_validate_disk(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `					struct svhdx_tunnel_operation_header *hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `					void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `					void *out_buf, unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `					unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `	struct svhdx_tunnel_validate_disk_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	if (max_out_len < sizeof(*rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [PROTO_GATE|] `		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00202 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	rsp = (struct svhdx_tunnel_validate_disk_rsp *)out_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	 * ksmbd does not parse VHDX internals, so we report the disk`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	 * as not valid.  A full implementation would inspect the VHDX`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	 * header signature.`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	rsp->IsValidDisk = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	*out_len = sizeof(*rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [PROTO_GATE|] `	return 0; /* STATUS_SUCCESS */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00215 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [PROTO_GATE|] ` * rsvd_handle_srb_status() - Handle RSVD_TUNNEL_SRB_STATUS_OPERATION`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00219 [NONE] ` * @work:        smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ` * @hdr:         tunnel operation header`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ` * @in_buf:      input buffer (after header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ` * @in_buf_len:  remaining input length`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ` * @out_buf:     output buffer (after response header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ` * @max_out_len: maximum output bytes available`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ` * @out_len:     [out] bytes written to output`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ` * Returns the sense error code from the most recently failed SCSI request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] ` * Since ksmbd does not execute real SCSI commands, return all-zero (success).`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ` * Return: NTSTATUS value for the tunnel Status field`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `static __le32 rsvd_handle_srb_status(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `				     struct svhdx_tunnel_operation_header *hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `				     void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `				     void *out_buf, unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `				     unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	struct svhdx_tunnel_srb_status_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	if (max_out_len < sizeof(*rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [PROTO_GATE|] `		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00243 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	rsp = (struct svhdx_tunnel_srb_status_rsp *)out_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	memset(rsp, 0, sizeof(*rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	rsp->StatusKey = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	rsp->SenseInfoAutoGenerated = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	rsp->SenseInfoExLength = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	rsp->ScsiStatus = 0; /* GOOD */`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	*out_len = sizeof(*rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [PROTO_GATE|] `	return 0; /* STATUS_SUCCESS */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00254 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ` * rsvd_handle_meta_op_query_progress() - Handle RSVD_TUNNEL_META_OPERATION_QUERY_PROGRESS`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ` * @work:        smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] ` * @hdr:         tunnel operation header`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] ` * @in_buf:      input buffer (after header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ` * @in_buf_len:  remaining input length`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ` * @out_buf:     output buffer (after response header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ` * @max_out_len: maximum output bytes available`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ` * @out_len:     [out] bytes written to output`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ` * Reports progress of an ongoing meta-operation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] ` * Returns 100% complete since no real meta-operations are in progress.`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] ` * Return: NTSTATUS value for the tunnel Status field`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `static __le32 rsvd_handle_meta_op_query_progress(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `						  struct svhdx_tunnel_operation_header *hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `						  void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `						  void *out_buf, unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `						  unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	struct svhdx_tunnel_meta_op_progress_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	if (max_out_len < sizeof(*rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [PROTO_GATE|] `		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00282 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	rsp = (struct svhdx_tunnel_meta_op_progress_rsp *)out_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	rsp->CurrentProgressValue = cpu_to_le64(100);`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	rsp->CompleteValue = cpu_to_le64(100);`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	*out_len = sizeof(*rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [PROTO_GATE|] `	return 0; /* STATUS_SUCCESS */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00290 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] ` * rsvd_handle_change_tracking_get_params() - Handle RSVD_TUNNEL_CHANGE_TRACKING_GET_PARAMETERS`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] ` * @work:        smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] ` * @hdr:         tunnel operation header`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] ` * @in_buf:      input buffer (after header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ` * @in_buf_len:  remaining input length`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ` * @out_buf:     output buffer (after response header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] ` * @max_out_len: maximum output bytes available`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ` * @out_len:     [out] bytes written to output`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ` * Returns change tracking parameters. Reports tracking as not active.`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] ` * Return: NTSTATUS value for the tunnel Status field`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `static __le32 rsvd_handle_change_tracking_get_params(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `						     struct svhdx_tunnel_operation_header *hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `						     void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `						     void *out_buf, unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `						     unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	struct svhdx_tunnel_change_tracking_params_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	if (max_out_len < sizeof(*rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [PROTO_GATE|] `		return cpu_to_le32(0xC0000023); /* STATUS_BUFFER_TOO_SMALL */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00317 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	rsp = (struct svhdx_tunnel_change_tracking_params_rsp *)out_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	memset(rsp, 0, sizeof(*rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	*out_len = sizeof(*rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [PROTO_GATE|] `	return 0; /* STATUS_SUCCESS */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00324 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `/*  Tunnel request dispatcher                                          */`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] ` * rsvd_dispatch_tunnel_op() - Dispatch a tunnel operation by OperationCode`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] ` * @work:        smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] ` * @in_buf:      input buffer (includes tunnel header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] ` * @in_buf_len:  total input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ` * @rsp:         ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] ` * @max_out_len: maximum output length from client`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ` * @out_len:     [out] total output bytes written (header + payload)`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ` * Parses the tunnel operation header, validates the operation code,`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ` * dispatches to the appropriate sub-handler, and constructs the`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ` * tunnel response header.`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `static int rsvd_dispatch_tunnel_op(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `				   void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `				   struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `				   unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `				   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `	struct svhdx_tunnel_operation_header *req_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `	struct svhdx_tunnel_operation_header *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	u32 opcode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	u32 ver_bits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	void *payload_in;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	void *payload_out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	unsigned int payload_in_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	unsigned int payload_max_out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	unsigned int payload_out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	__le32 tunnel_status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	/* Validate and extract the tunnel header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	ret = rsvd_validate_tunnel_header(in_buf, in_buf_len, &req_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `		if (ret == -ENODEV) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `			/* Invalid operation code prefix */`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_DEVICE_REQUEST;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00369 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00370 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00372 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	opcode = le32_to_cpu(req_hdr->OperationCode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	 * MS-RSVD 3.2.5.5: validate version bits.`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	 * Version 1 operations have 0x001 in bits [23:12].`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	 * Version 2 operations have 0x002 in bits [23:12].`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	 * We advertise version 2, so accept both.`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `	ver_bits = opcode & RSVD_TUNNEL_OPCODE_VER_MASK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	if (ver_bits != RSVD_TUNNEL_OPCODE_VER1 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `	    ver_bits != RSVD_TUNNEL_OPCODE_VER2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `			    "RSVD: unknown version bits 0x%08x in opcode 0x%08x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `			    ver_bits, opcode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [PROTO_GATE|] `		rsp->hdr.Status = cpu_to_le32(STATUS_SVHDX_VERSION_MISMATCH);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00390 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00391 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	/* Ensure output buffer can hold at least the response header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	if (max_out_len < SVHDX_TUNNEL_OP_HEADER_SIZE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00396 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00397 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	/* Set up response header in the output buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	rsp_hdr = (struct svhdx_tunnel_operation_header *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	rsp_hdr->OperationCode = req_hdr->OperationCode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	rsp_hdr->RequestId = req_hdr->RequestId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	/* Compute payload pointers */`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	payload_in = (u8 *)in_buf + SVHDX_TUNNEL_OP_HEADER_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	payload_in_len = in_buf_len - SVHDX_TUNNEL_OP_HEADER_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	payload_out = (u8 *)rsp_hdr + SVHDX_TUNNEL_OP_HEADER_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	payload_max_out = max_out_len - SVHDX_TUNNEL_OP_HEADER_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	/* Dispatch based on operation code */`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	switch (opcode) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	case RSVD_TUNNEL_GET_INITIAL_INFO:`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `		tunnel_status = rsvd_handle_get_initial_info(`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `			work, req_hdr, payload_in, payload_in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `			payload_out, payload_max_out, &payload_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	case RSVD_TUNNEL_CHECK_CONNECTION_STATUS:`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `		tunnel_status = rsvd_handle_check_connection_status(`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `			work, req_hdr, payload_in, payload_in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `			payload_out, payload_max_out, &payload_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `	case RSVD_TUNNEL_GET_DISK_INFO:`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `		tunnel_status = rsvd_handle_get_disk_info(`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `			work, req_hdr, payload_in, payload_in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `			payload_out, payload_max_out, &payload_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	case RSVD_TUNNEL_VALIDATE_DISK:`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `		tunnel_status = rsvd_handle_validate_disk(`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `			work, req_hdr, payload_in, payload_in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `			payload_out, payload_max_out, &payload_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [PROTO_GATE|] `	case RSVD_TUNNEL_SRB_STATUS_OPERATION:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00437 [NONE] `		tunnel_status = rsvd_handle_srb_status(`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `			work, req_hdr, payload_in, payload_in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `			payload_out, payload_max_out, &payload_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	case RSVD_TUNNEL_META_OPERATION_QUERY_PROGRESS:`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `		tunnel_status = rsvd_handle_meta_op_query_progress(`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `			work, req_hdr, payload_in, payload_in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `			payload_out, payload_max_out, &payload_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	case RSVD_TUNNEL_CHANGE_TRACKING_GET_PARAMETERS:`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `		tunnel_status = rsvd_handle_change_tracking_get_params(`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `			work, req_hdr, payload_in, payload_in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `			payload_out, payload_max_out, &payload_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	case RSVD_TUNNEL_SCSI_OPERATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `		 * SCSI passthrough requires actual block device access.`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [PROTO_GATE|] `		 * Not implemented -- return STATUS_NOT_SUPPORTED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00458 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `			    "RSVD: SCSI tunnel operation not implemented\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [PROTO_GATE|] `		tunnel_status = cpu_to_le32(0xC00000BB); /* STATUS_NOT_SUPPORTED */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00462 [NONE] `		payload_out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	case RSVD_TUNNEL_META_OPERATION_START:`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	case RSVD_TUNNEL_VHDSET_QUERY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	case RSVD_TUNNEL_DELETE_SNAPSHOT:`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `	case RSVD_TUNNEL_CHANGE_TRACKING_START:`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	case RSVD_TUNNEL_CHANGE_TRACKING_STOP:`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	case RSVD_TUNNEL_QUERY_VIRTUAL_DISK_CHANGES:`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	case RSVD_TUNNEL_QUERY_SAFE_SIZE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `		 * Advanced VHDX management operations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `		 * These require deep VHDX metadata parsing -- stub`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [PROTO_GATE|] `		 * them with STATUS_NOT_SUPPORTED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00476 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `			    "RSVD: tunnel operation 0x%08x not implemented\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `			    opcode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [PROTO_GATE|] `		tunnel_status = cpu_to_le32(0xC00000BB); /* STATUS_NOT_SUPPORTED */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00481 [NONE] `		payload_out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `			    "RSVD: unknown tunnel operation 0x%08x\n", opcode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [PROTO_GATE|] `		tunnel_status = cpu_to_le32(0xC000000D); /* STATUS_INVALID_PARAMETER */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00488 [NONE] `		payload_out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	/* Fill in the tunnel response status */`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	rsp_hdr->Status = tunnel_status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	/* Total output = tunnel header + payload */`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	*out_len = SVHDX_TUNNEL_OP_HEADER_SIZE + payload_out_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `/*  FSCTL handler callbacks                                            */`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] ` * fsctl_query_shared_virtual_disk_support_handler() -`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] ` *     Handle FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] ` * Returns the server's shared virtual disk capabilities.`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] ` * Indicates basic SVHD support without CDP snapshot support.`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `static int fsctl_query_shared_virtual_disk_support_handler(`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	struct ksmbd_work *work, u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	struct shared_virtual_disk_support *support;`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	if (max_out_len < sizeof(*support)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00522 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00524 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	support = (struct shared_virtual_disk_support *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	support->SharedVirtualDiskSupport = cpu_to_le32(SVHD_SUPPORT_SHARED);`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	support->SharedVirtualDiskHandleState =`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `		cpu_to_le32(SVHD_HANDLE_STATE_NONE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	*out_len = sizeof(*support);`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	ksmbd_debug(SMB, "RSVD: query shared virtual disk support\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] ` * fsctl_svhdx_sync_tunnel_handler() -`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] ` *     Handle FSCTL_SVHDX_SYNC_TUNNEL_REQUEST`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] ` * Dispatches synchronous tunnel operations.  The input buffer contains`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] ` * an SVHDX_TUNNEL_OPERATION_HEADER followed by operation-specific data.`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `static int fsctl_svhdx_sync_tunnel_handler(`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	struct ksmbd_work *work, u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	ksmbd_debug(SMB, "RSVD: sync tunnel request, in_len=%u, max_out=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `		    in_buf_len, max_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	return rsvd_dispatch_tunnel_op(work, in_buf, in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `				       rsp, max_out_len, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] ` * fsctl_svhdx_async_tunnel_handler() -`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] ` *     Handle FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] ` * Dispatches asynchronous tunnel operations.  For now, these are`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] ` * handled synchronously using the same dispatcher, since ksmbd does`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] ` * not implement true async RSVD processing.`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `static int fsctl_svhdx_async_tunnel_handler(`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	struct ksmbd_work *work, u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `	ksmbd_debug(SMB, "RSVD: async tunnel request, in_len=%u, max_out=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `		    in_buf_len, max_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	 * For now, dispatch async requests synchronously.`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	 * A full implementation would queue work and send`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `	 * an interim response, then complete asynchronously.`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	return rsvd_dispatch_tunnel_op(work, in_buf, in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `				       rsp, max_out_len, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `/*  FSCTL handler descriptors                                          */`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `static struct ksmbd_fsctl_handler rsvd_handlers[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `		.ctl_code = FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `		.handler  = fsctl_query_shared_virtual_disk_support_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `		.ctl_code = FSCTL_SVHDX_SYNC_TUNNEL_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `		.handler  = fsctl_svhdx_sync_tunnel_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `		.ctl_code = FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST,`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `		.handler  = fsctl_svhdx_async_tunnel_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `/*  Init / Exit                                                        */`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] ` * ksmbd_rsvd_init() - Initialize RSVD subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] ` * Registers all three RSVD FSCTL handlers with the dispatch table.`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `int ksmbd_rsvd_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `	int i, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `	for (i = 0; i < ARRAY_SIZE(rsvd_handlers); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `		ret = ksmbd_register_fsctl(&rsvd_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [ERROR_PATH|] `			pr_err("RSVD: failed to register FSCTL 0x%08x: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00626 [NONE] `			       rsvd_handlers[i].ctl_code, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [ERROR_PATH|] `			goto err_unregister;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00628 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `	ksmbd_debug(SMB, "RSVD subsystem initialized (%zu handlers)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `		    ARRAY_SIZE(rsvd_handlers));`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `err_unregister:`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	while (--i >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `		ksmbd_unregister_fsctl(&rsvd_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] ` * ksmbd_rsvd_exit() - Tear down RSVD subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] ` * Unregisters all RSVD FSCTL handlers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `void ksmbd_rsvd_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	for (i = ARRAY_SIZE(rsvd_handlers) - 1; i >= 0; i--)`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `		ksmbd_unregister_fsctl(&rsvd_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
