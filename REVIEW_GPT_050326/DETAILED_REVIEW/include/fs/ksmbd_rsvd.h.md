# Line-by-line Review: src/include/fs/ksmbd_rsvd.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
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
- L00008 [NONE] ` *   Implements FSCTL handlers for:`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *     - FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *     - FSCTL_SVHDX_SYNC_TUNNEL_REQUEST`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *     - FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *   Reference: [MS-RSVD] Remote Shared Virtual Disk Protocol`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#ifndef __KSMBD_RSVD_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#define __KSMBD_RSVD_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * RSVD protocol versions (section 2.2.1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#define RSVD_PROTOCOL_VERSION_1		0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#define RSVD_PROTOCOL_VERSION_2		0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` * Tunnel operation codes (MS-RSVD section 2.2.2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define RSVD_TUNNEL_GET_INITIAL_INFO                0x02001001`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define RSVD_TUNNEL_SCSI_OPERATION                  0x02001002`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#define RSVD_TUNNEL_CHECK_CONNECTION_STATUS          0x02001003`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [PROTO_GATE|] `#define RSVD_TUNNEL_SRB_STATUS_OPERATION             0x02001004`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00034 [NONE] `#define RSVD_TUNNEL_GET_DISK_INFO                    0x02001005`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#define RSVD_TUNNEL_VALIDATE_DISK                    0x02001006`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#define RSVD_TUNNEL_META_OPERATION_START             0x02002101`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#define RSVD_TUNNEL_META_OPERATION_QUERY_PROGRESS    0x02002002`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#define RSVD_TUNNEL_VHDSET_QUERY_INFORMATION         0x02002005`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define RSVD_TUNNEL_DELETE_SNAPSHOT                   0x02002006`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#define RSVD_TUNNEL_CHANGE_TRACKING_GET_PARAMETERS   0x02002008`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#define RSVD_TUNNEL_CHANGE_TRACKING_START            0x02002009`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#define RSVD_TUNNEL_CHANGE_TRACKING_STOP             0x0200200A`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#define RSVD_TUNNEL_QUERY_VIRTUAL_DISK_CHANGES       0x0200200C`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#define RSVD_TUNNEL_QUERY_SAFE_SIZE                  0x0200200D`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * Tunnel operation code validation masks (MS-RSVD section 3.2.5.5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` * The upper byte must be 0x02.`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` * The middle 12 bits encode the version:`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` *   0x001 = version-1 operations`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` *   0x002 = version-2 operations`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#define RSVD_TUNNEL_OPCODE_PREFIX_MASK	0xFF000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#define RSVD_TUNNEL_OPCODE_PREFIX_VAL	0x02000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#define RSVD_TUNNEL_OPCODE_VER_MASK	0x00FFF000`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#define RSVD_TUNNEL_OPCODE_VER1		0x00001000`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define RSVD_TUNNEL_OPCODE_VER2		0x00002000`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ` * SVHDX_TUNNEL_OPERATION_HEADER (MS-RSVD section 2.2.4.11)`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * Common header for all tunnel operation requests and responses.`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `struct svhdx_tunnel_operation_header {`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	__le32 OperationCode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	__le32 Status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	__le64 RequestId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#define SVHDX_TUNNEL_OP_HEADER_SIZE	sizeof(struct svhdx_tunnel_operation_header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT response (MS-RSVD section 2.2.4.16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `struct shared_virtual_disk_support {`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	__le32 SharedVirtualDiskSupport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	__le32 SharedVirtualDiskHandleState;`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `/* SharedVirtualDiskSupport flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `#define SVHD_SUPPORT_SHARED		0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `#define SVHD_SUPPORT_CDP_SNAPSHOTS	0x00000007`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `/* SharedVirtualDiskHandleState values */`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `#define SVHD_HANDLE_STATE_NONE		0x00000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `#define SVHD_HANDLE_STATE_FILE_SHARED	0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `#define SVHD_HANDLE_STATE_SHARED	0x00000003`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * SVHDX_TUNNEL_INITIAL_INFO_RESPONSE (MS-RSVD section 2.2.4.15)`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * Response to RSVD_TUNNEL_GET_INITIAL_INFO.`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `struct svhdx_tunnel_initial_info_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	__le32 ServerVersion;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	__le32 SectorSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	__le32 PhysicalSectorSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	__le64 VirtualSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` * SVHDX_TUNNEL_DISK_INFO_RESPONSE (MS-RSVD section 2.2.4.4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ` * Response to RSVD_TUNNEL_GET_DISK_INFO.`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `struct svhdx_tunnel_disk_info_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	__le32 DiskType;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	__le32 DiskFormat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	__le32 BlockSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	__u8   LinkageId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	__u8   IsMounted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	__u8   Is4kAligned;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	__le64 FileSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	__u8   VirtualDiskId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `/* DiskType values (MS-RSVD section 2.2.4.4) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `#define SVHD_DISK_TYPE_FIXED		0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `#define SVHD_DISK_TYPE_DYNAMIC		0x00000003`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `#define SVHD_DISK_TYPE_DIFFERENCING	0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `/* DiskFormat values */`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `#define SVHD_DISK_FORMAT_VHDX		0x00000003`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` * SVHDX_TUNNEL_SCSI_REQUEST (MS-RSVD section 2.2.4.7)`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `struct svhdx_tunnel_scsi_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	__le16 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	__le16 Reserved1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	__u8   CDBLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	__u8   SenseInfoExLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	__u8   DataIn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	__u8   Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	__le32 SrbFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	__le32 DataTransferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	__u8   CDB[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	__u8   Reserved3[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	__u8   DataBuffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `/* DataIn values */`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `#define SVHD_SCSI_DATA_WRITE		0x00`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `#define SVHD_SCSI_DATA_READ		0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `#define SVHD_SCSI_DATA_BIDIRECTIONAL	0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ` * SVHDX_TUNNEL_SCSI_RESPONSE (MS-RSVD section 2.2.4.8)`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `struct svhdx_tunnel_scsi_response {`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	__le16 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	__u8   SrbStatus;	/* bit 7: SenseInfoAutoGenerated, bits 6-0: SrbStatus */`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	__u8   ScsiStatus;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	__u8   CDBLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	__u8   SenseInfoExLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	__u8   DataIn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	__le32 SrbFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	__le32 DataTransferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	__u8   SenseDataEx[20];`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	__u8   DataBuffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ` * SVHDX_TUNNEL_VALIDATE_DISK_RESPONSE (MS-RSVD section 2.2.4.5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `struct svhdx_tunnel_validate_disk_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	__u8 IsValidDisk;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [PROTO_GATE|] ` * SVHDX_TUNNEL_SRB_STATUS_RESPONSE (MS-RSVD section 2.2.4.6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00176 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `struct svhdx_tunnel_srb_status_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	__u8   StatusKey;`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	__u8   SenseInfoAutoGenerated;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	__u8   SenseInfoExLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	__u8   ScsiStatus;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	__u8   SenseDataEx[20];`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ` * SVHDX_META_OPERATION_QUERY_PROGRESS_RESPONSE (MS-RSVD section 2.2.4.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `struct svhdx_tunnel_meta_op_progress_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	__le64 CurrentProgressValue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	__le64 CompleteValue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [PROTO_GATE|] ` * SVHDX_TUNNEL_CHECK_CONNECTION_STATUS_RESPONSE`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00195 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ` * This is just the tunnel header with Status set to success/failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ` * No additional fields.`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ` * SVHDX_CHANGE_TRACKING_GET_PARAMETERS_RESPONSE (MS-RSVD section 2.2.4.22)`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `struct svhdx_tunnel_change_tracking_params_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	__le32 ChangeTrackingStatus;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	__le32 MostRecentEntry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	__le32 OldestEntry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	__le32 LogLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `/* SRB status codes (commonly referenced) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [PROTO_GATE|] `#define SRB_STATUS_SUCCESS		0x00`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00212 [PROTO_GATE|] `#define SRB_STATUS_PENDING		0x00`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00213 [PROTO_GATE|] `#define SRB_STATUS_ABORTED		0x02`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00214 [PROTO_GATE|] `#define SRB_STATUS_ERROR		0x04`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00215 [PROTO_GATE|] `#define SRB_STATUS_INVALID_REQUEST	0x06`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `/* NTSTATUS values used in RSVD */`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [PROTO_GATE|] `#define STATUS_SVHDX_ERROR_STORED	0xC05CFF00`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00219 [PROTO_GATE|] `#define STATUS_SVHDX_VERSION_MISMATCH	0xC05CFF0C`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ` * ksmbd_rsvd_init() - Initialize RSVD subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ` * Registers FSCTL handlers for RSVD operations:`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ` *   - FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ` *   - FSCTL_SVHDX_SYNC_TUNNEL_REQUEST`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ` *   - FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `int ksmbd_rsvd_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] ` * ksmbd_rsvd_exit() - Tear down RSVD subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ` * Unregisters all RSVD FSCTL handlers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `void ksmbd_rsvd_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `#endif /* __KSMBD_RSVD_H */`
  Review: Low-risk line; verify in surrounding control flow.
