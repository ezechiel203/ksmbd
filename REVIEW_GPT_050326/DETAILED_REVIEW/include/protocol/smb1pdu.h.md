# Line-by-line Review: src/include/protocol/smb1pdu.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#ifndef __SMB1PDU_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define __SMB1PDU_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#define MAX_CIFS_HDR_SIZE 0x58`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#define SMB1_CLIENT_GUID_SIZE		(16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#define SMB1_MAX_MPX_COUNT		10`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#define SMB1_MAX_VCS			1`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#define SMB1_MAX_RAW_SIZE		65536`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#define MAX_CIFS_LOOKUP_BUFFER_SIZE	(16*1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` * Size of the ntlm client response`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define CIFS_AUTH_RESP_SIZE		24`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define CIFS_SMB1_SIGNATURE_SIZE	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#define CIFS_SMB1_SESSKEY_SIZE		16`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` * SMB1_SERVER_CAPS: advertised server capabilities.`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` * NOTE: CAP_LOCK_AND_READ (0x00000100) is intentionally omitted — opcode`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [PROTO_GATE|] ` * 0x13 (SMB_COM_LOCK_AND_READ) has no handler, so advertising the capability`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00029 [NONE] ` * would be a protocol violation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` * P1.27: Added CAP_MPX_MODE (multiplexing supported, MaxMpxCount=10),`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` *        CAP_RPC_REMOTE_APIS (IPC$/named-pipe DCE/RPC implemented),`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` *        CAP_INFOLEVEL_PASSTHRU (TRANS2 passthrough info levels handled).`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#define SMB1_SERVER_CAPS					\`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	(CAP_UNICODE | CAP_LARGE_FILES | CAP_EXTENDED_SECURITY |\`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	 CAP_NT_SMBS | CAP_STATUS32 |				\`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	 CAP_NT_FIND | CAP_UNIX | CAP_LARGE_READ_X |		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	 CAP_LARGE_WRITE_X | CAP_LEVEL_II_OPLOCKS |		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	 CAP_MPX_MODE | CAP_RPC_REMOTE_APIS | CAP_INFOLEVEL_PASSTHRU)`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#define SMB1_SERVER_SECU  (SECMODE_USER | SECMODE_PW_ENCRYPT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `/* Service Type of TreeConnect*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#define SERVICE_DISK_SHARE	"A:"`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#define SERVICE_IPC_SHARE	"IPC"`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#define SERVICE_PRINTER_SHARE	"LPT1:"`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#define SERVICE_COMM		"COMM"`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#define NATIVE_FILE_SYSTEM	"NTFS"`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#define SMB_NO_MORE_ANDX_COMMAND 0xFF`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#define SMB1_PROTO_NUMBER cpu_to_le32(0x424d53ff)`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [PROTO_GATE|] ` * P1.8: STATUS_SMB_BAD_TID — NTSTATUS for invalid TID in SMB1 tree`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00056 [NONE] ` * disconnect and related operations.  Windows maps ERRSrv/ERRinvnid`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [PROTO_GATE|] ` * to NT status 0xC000004B (STATUS_INVALID_NETWORK_RESPONSE is close;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00058 [PROTO_GATE|] ` * Samba uses STATUS_SMB_BAD_TID = 0xC0000006 is incorrect).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [PROTO_GATE|] ` * Use STATUS_NETWORK_NAME_DELETED (0xC00000C9) per common practice.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00060 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [PROTO_GATE|] `#define STATUS_SMB_BAD_TID cpu_to_le32(0xC00000C9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `/* Transact2 subcommand codes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#define TRANS2_OPEN                   0x00`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#define TRANS2_FIND_FIRST             0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#define TRANS2_FIND_NEXT              0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `#define TRANS2_QUERY_FS_INFORMATION   0x03`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `#define TRANS2_SET_FS_INFORMATION     0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `#define TRANS2_QUERY_PATH_INFORMATION 0x05`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#define TRANS2_SET_PATH_INFORMATION   0x06`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#define TRANS2_QUERY_FILE_INFORMATION 0x07`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `#define TRANS2_SET_FILE_INFORMATION   0x08`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `#define TRANS2_CREATE_DIRECTORY       0x0d`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `#define TRANS2_GET_DFS_REFERRAL       0x10`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `#define TRANS2_REPORT_DFS_INCOSISTENCY 0x11`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `/* SMB Transact (Named Pipe) subcommand codes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `#define TRANS_SET_NMPIPE_STATE      0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `#define TRANS_RAW_READ_NMPIPE       0x0011`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `#define TRANS_QUERY_NMPIPE_STATE    0x0021`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `#define TRANS_QUERY_NMPIPE_INFO     0x0022`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `#define TRANS_PEEK_NMPIPE           0x0023`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `#define TRANS_TRANSACT_NMPIPE       0x0026`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `#define TRANS_RAW_WRITE_NMPIPE      0x0031`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `#define TRANS_READ_NMPIPE           0x0036`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `#define TRANS_WRITE_NMPIPE          0x0037`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `#define TRANS_WAIT_NMPIPE           0x0053`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `#define TRANS_CALL_NMPIPE           0x0054`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `/* NT Transact subcommand codes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `#define NT_TRANSACT_CREATE            0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `#define NT_TRANSACT_IOCTL             0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `#define NT_TRANSACT_SET_SECURITY_DESC 0x03`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `#define NT_TRANSACT_NOTIFY_CHANGE     0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `#define NT_TRANSACT_RENAME            0x05`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `#define NT_TRANSACT_QUERY_SECURITY_DESC 0x06`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `#define NT_TRANSACT_GET_USER_QUOTA    0x07`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `#define NT_TRANSACT_SET_USER_QUOTA    0x08`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `#define NT_TRANSACT_MAX_SUBCOMMAND    0x08`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ` * NT_TRANSACT request (MS-CIFS 2.2.4.62)`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ` * WordCount is variable: 19 + SetupCount`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` * Note: ParameterCount/DataCount are 32-bit (unlike TRANS2's 16-bit).`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `struct smb_com_nt_transact_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	struct smb_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	__u8 MaxSetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	__u16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	__le32 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	__le32 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	__le32 MaxParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	__le32 MaxDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	__le32 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	__le32 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	__le32 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	__le32 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	__le16 Function;	/* NT_TRANSACT subcommand */`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	__u8 Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `struct smb_com_nt_transact_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	struct smb_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	__u8 Reserved[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	__le32 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	__le32 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	__le32 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	__le32 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	__le32 ParameterDisplacement;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	__le32 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	__le32 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	__le32 DataDisplacement;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	__u8 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` * smb1_validate_nt_transact_buffer() - Validate NT_TRANSACT parameter/data`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` * regions within the SMB request buffer. Uses 32-bit counts (unlike TRANS2).`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ` * Return: 0 on valid, -EINVAL if any region overflows.`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `static inline int smb1_validate_nt_transact_buffer(const void *request_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `						   unsigned int buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	const struct smb_com_nt_transact_req *req = request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	unsigned int param_off, param_cnt, data_off, data_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	unsigned int total_param, total_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	param_off = le32_to_cpu(req->ParameterOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	param_cnt = le32_to_cpu(req->ParameterCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	data_off  = le32_to_cpu(req->DataOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	data_cnt  = le32_to_cpu(req->DataCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	total_param = le32_to_cpu(req->TotalParameterCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	total_data  = le32_to_cpu(req->TotalDataCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	/* Integer overflow guards: check individual values first */`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	if (param_off > buf_len || param_cnt > buf_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	    data_off > buf_len || data_cnt > buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	if (param_cnt > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `		if (param_off + 4 > buf_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		    param_off + 4 + param_cnt > buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00168 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	if (data_cnt > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `		if (data_off + 4 > buf_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `		    data_off + 4 + data_cnt > buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00174 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	/* Total must be >= current count */`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	if (total_param < param_cnt || total_data < data_cnt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	/* SetupCount must be within buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	if (req->SetupCount > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `		unsigned int setup_end = offsetof(struct smb_com_nt_transact_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `						  Buffer) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `					 req->SetupCount * sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `		if (setup_end > buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00187 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ` * SMB flag definitions`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `#define SMBFLG_EXTD_LOCK 0x01   /* server supports lock-read write-unlock smb */`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `#define SMBFLG_RCV_POSTED 0x02  /* obsolete */`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `#define SMBFLG_RSVD 0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `#define SMBFLG_CASELESS 0x08    /*`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `				 * all pathnames treated as caseless (off`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `				 * implies case sensitive file handling`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `				 * request)`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `#define SMBFLG_CANONICAL_PATH_FORMAT 0x10       /* obsolete */`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `#define SMBFLG_OLD_OPLOCK 0x20  /* obsolete */`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `#define SMBFLG_OLD_OPLOCK_NOTIFY 0x40   /* obsolete */`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `#define SMBFLG_RESPONSE 0x80    /* this PDU is a response from server */`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ` * SMB flag2 definitions`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `#define SMBFLG2_KNOWS_LONG_NAMES cpu_to_le16(1) /*`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `						 * can send long (non-8.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `						 * path names in response`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `						 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `#define SMBFLG2_KNOWS_EAS cpu_to_le16(2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `#define SMBFLG2_SECURITY_SIGNATURE cpu_to_le16(4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `#define SMBFLG2_COMPRESSED (8)`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `#define SMBFLG2_SECURITY_SIGNATURE_REQUIRED (0x10)`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `#define SMBFLG2_IS_LONG_NAME cpu_to_le16(0x40)`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `#define SMBFLG2_REPARSE_PATH (0x400)`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `#define SMBFLG2_EXT_SEC cpu_to_le16(0x800)`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `#define SMBFLG2_DFS cpu_to_le16(0x1000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `#define SMBFLG2_PAGING_IO cpu_to_le16(0x2000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `#define SMBFLG2_ERR_STATUS cpu_to_le16(0x4000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `#define SMBFLG2_UNICODE cpu_to_le16(0x8000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [PROTO_GATE|] `#define SMB_COM_CREATE_DIRECTORY      0x00 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00228 [PROTO_GATE|] `#define SMB_COM_DELETE_DIRECTORY      0x01 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00229 [PROTO_GATE|] `#define SMB_COM_CLOSE                 0x04 /* triv req/rsp, timestamp ignored */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00230 [PROTO_GATE|] `#define SMB_COM_FLUSH                 0x05 /* triv req/rsp */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00231 [PROTO_GATE|] `#define SMB_COM_DELETE                0x06 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00232 [PROTO_GATE|] `#define SMB_COM_RENAME                0x07 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00233 [PROTO_GATE|] `#define SMB_COM_QUERY_INFORMATION     0x08 /* aka getattr */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00234 [PROTO_GATE|] `#define SMB_COM_SETATTR               0x09 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00235 [PROTO_GATE|] `#define SMB_COM_WRITE                 0x0b`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00236 [NONE] `/* A.2: P2 missing commands */`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [PROTO_GATE|] `#define SMB_COM_SET_INFORMATION2      0x22`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00238 [PROTO_GATE|] `#define SMB_COM_QUERY_INFORMATION2    0x23`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00239 [PROTO_GATE|] `#define SMB_COM_CHECK_DIRECTORY       0x10 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00240 [PROTO_GATE|] `#define SMB_COM_PROCESS_EXIT          0x11 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00241 [PROTO_GATE|] `#define SMB_COM_LOCKING_ANDX          0x24 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00242 [PROTO_GATE|] `#define SMB_COM_TRANSACTION	      0x25`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00243 [PROTO_GATE|] `#define SMB_COM_COPY                  0x29 /* trivial rsp, fail filename ignrd*/`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00244 [PROTO_GATE|] `#define SMB_COM_ECHO                  0x2B /* echo request */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00245 [PROTO_GATE|] `#define SMB_COM_OPEN_ANDX             0x2D /* Legacy open for old servers */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00246 [PROTO_GATE|] `#define SMB_COM_READ_ANDX             0x2E`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00247 [PROTO_GATE|] `#define SMB_COM_WRITE_ANDX            0x2F`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00248 [PROTO_GATE|] `#define SMB_COM_TRANSACTION2          0x32`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00249 [PROTO_GATE|] `#define SMB_COM_TRANSACTION2_SECONDARY 0x33`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00250 [PROTO_GATE|] `#define SMB_COM_FIND_CLOSE2           0x34 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00251 [PROTO_GATE|] `#define SMB_COM_TREE_DISCONNECT       0x71 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00252 [PROTO_GATE|] `#define SMB_COM_NEGOTIATE             0x72`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00253 [PROTO_GATE|] `#define SMB_COM_SESSION_SETUP_ANDX    0x73`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00254 [PROTO_GATE|] `#define SMB_COM_LOGOFF_ANDX           0x74 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00255 [PROTO_GATE|] `#define SMB_COM_TREE_CONNECT_ANDX     0x75`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00256 [PROTO_GATE|] `#define SMB_COM_QUERY_INFORMATION_DISK 0x80`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00257 [PROTO_GATE|] `#define SMB_COM_NT_TRANSACT           0xA0`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00258 [PROTO_GATE|] `#define SMB_COM_NT_TRANSACT_SECONDARY 0xA1`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00259 [PROTO_GATE|] `#define SMB_COM_NT_CREATE_ANDX        0xA2`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00260 [PROTO_GATE|] `#define SMB_COM_NT_CANCEL             0xA4 /* no response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00261 [PROTO_GATE|] `#define SMB_COM_NT_RENAME             0xA5 /* trivial response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `/* Negotiate response Capabilities */`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `#define CAP_RAW_MODE           0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `#define CAP_MPX_MODE           0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `#define CAP_UNICODE            0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `#define CAP_LARGE_FILES        0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `#define CAP_NT_SMBS            0x00000010       /* implies CAP_NT_FIND */`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `#define CAP_RPC_REMOTE_APIS    0x00000020`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `#define CAP_STATUS32           0x00000040`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `#define CAP_LEVEL_II_OPLOCKS   0x00000080`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `#define CAP_LOCK_AND_READ      0x00000100`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `#define CAP_NT_FIND            0x00000200`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `#define CAP_DFS                0x00001000`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `#define CAP_INFOLEVEL_PASSTHRU 0x00002000`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `#define CAP_LARGE_READ_X       0x00004000`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `#define CAP_LARGE_WRITE_X      0x00008000`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `#define CAP_LWIO               0x00010000 /* support fctl_srv_req_resume_key */`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `#define CAP_UNIX               0x00800000`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `#define CAP_COMPRESSED_DATA    0x02000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `#define CAP_DYNAMIC_REAUTH     0x20000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `#define CAP_PERSISTENT_HANDLES 0x40000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `#define CAP_EXTENDED_SECURITY  0x80000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `/* RFC 1002 session packet types */`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `#define RFC1002_SESSION_MESSAGE 0x00`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `#define RFC1002_SESSION_REQUEST  0x81`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `#define RFC1002_POSITIVE_SESSION_RESPONSE 0x82`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `#define RFC1002_NEGATIVE_SESSION_RESPONSE 0x83`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `#define RFC1002_RETARGET_SESSION_RESPONSE 0x84`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `#define RFC1002_SESSION_KEEP_ALIVE 0x85`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `/* Action bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `#define GUEST_LOGIN 1`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `struct smb_negotiate_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	struct smb_hdr hdr;     /* wct = 17 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	__le16 DialectIndex; /* 0xFFFF = no dialect acceptable */`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	__u8 SecurityMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	__le16 MaxMpxCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	__le16 MaxNumberVcs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	__le32 MaxBufferSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	__le32 MaxRawSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	__le32 SessionKey;`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	__le32 Capabilities;    /* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	__le32 SystemTimeLow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `	__le32 SystemTimeHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	__le16 ServerTimeZone;`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	__u8 EncryptionKeyLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	union {`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `		unsigned char EncryptionKey[8]; /* cap extended security off */`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `		/* followed by Domain name - if extended security is off */`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `		/* followed by 16 bytes of server GUID */`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `		/* then security blob if cap_extended_security negotiated */`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `		struct {`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `			unsigned char GUID[SMB1_CLIENT_GUID_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `			unsigned char SecurityBlob[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `		} __packed extended_response;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	} __packed u;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `struct smb_com_read_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	struct smb_hdr hdr;     /* wct = 12 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	__u16 Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	__le32 OffsetLow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	__le16 MaxCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	__le16 MinCount;                /* obsolete */`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `	__le32 MaxCountHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	__le16 Remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	__le32 OffsetHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `struct smb_com_read_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	struct smb_hdr hdr;     /* wct = 12 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	__le16 Remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `	__le16 DataCompactionMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `	__le16 DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	__le16 DataLengthHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	__u64 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `	/* read response data immediately follows */`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `struct smb_com_write_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	struct smb_hdr hdr;	/* wct = 14 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	__u16 Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	__le32 OffsetLow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	__u32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	__le16 WriteMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	__le16 Remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	__le16 DataLengthHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	__le16 DataLengthLow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	__le32 OffsetHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	__u8 Pad;		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `				 * BB check for whether padded to DWORD`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `				 * boundary and optimum performance here`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	char Data[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `struct smb_com_write_req_32bit {`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	struct smb_hdr hdr;	/* wct = 5 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	__u16 Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	__le16 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	__le32 Offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	__u16 Estimate;`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	__le16 ByteCount;	/* must be greater than 2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `	__u8 BufferFormat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	__u16 DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `	char Data[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `struct smb_com_write_rsp_32bit {`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	struct smb_hdr hdr;	/* wct = 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	__le16 Written;`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	__le16 ByteCount;	/* must be 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `struct smb_com_write_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	struct smb_hdr hdr;	/* wct = 6 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	__le16 Count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	__le16 Remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	__le16 CountHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	__u16  Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `struct smb_com_rename_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	struct smb_hdr hdr;     /* wct = 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	__le16 SearchAttributes;        /* target file attributes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	__u8 BufferFormat;      /* 4 = ASCII or Unicode */`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	unsigned char OldFileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	/* followed by __u8 BufferFormat2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	/* followed by NewFileName */`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `struct smb_com_rename_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	struct smb_hdr hdr;     /* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	__le16 ByteCount;        /* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `/* SecurityMode bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `#define SECMODE_USER          0x01      /* off indicates share level security */`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `#define SECMODE_PW_ENCRYPT    0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `#define SECMODE_SIGN_ENABLED  0x04      /* SMB security signatures enabled */`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `#define SECMODE_SIGN_REQUIRED 0x08      /* SMB security signatures required */`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `struct smb_com_session_setup_req {	/* request format */`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	struct smb_hdr hdr;	/* wct = 12 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	__le16 MaxBufferSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	__le16 MaxMpxCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `	__le16 VcNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	__u32 SessionKey;`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	__le16 SecurityBlobLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	__u32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	__le32 Capabilities;	/* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `	unsigned char SecurityBlob[1];	/* followed by */`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	/* STRING NativeOS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	/* STRING NativeLanMan */`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `} __packed;	/* NTLM request format (with extended security) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `struct smb_com_session_setup_req_no_secext {	/* request format */`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `	struct smb_hdr hdr;	/* we will handle this :: wct = 13 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `	__le16 MaxBufferSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	__le16 MaxMpxCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	__le16 VcNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	__u32 SessionKey;`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	__le16 CaseInsensitivePasswordLength;	/* ASCII password len */`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	__le16 CaseSensitivePasswordLength;	/* Unicode password length*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	__u32 Reserved;	/* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `	__le32 Capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	unsigned char CaseInsensitivePassword[0];	/* followed by: */`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `	/* unsigned char * CaseSensitivePassword; */`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `	/* STRING AccountName */`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	/* STRING PrimaryDomain */`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	/* STRING NativeOS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	/* STRING NativeLanMan */`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `} __packed;	/* NTLM request format (without extended security */`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `struct smb_com_session_setup_resp {	/* default (NTLM) response format */`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `	struct smb_hdr hdr;	/* wct = 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	__le16 Action;	/* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	__le16 SecurityBlobLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `	unsigned char SecurityBlob[1];	/* followed by */`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	/*      unsigned char  * NativeOS;      */`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	/*      unsigned char  * NativeLanMan;  */`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	/*      unsigned char  * PrimaryDomain; */`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `} __packed;	/* NTLM response (with or without extended sec) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `struct smb_com_session_setup_old_resp { /* default (NTLM) response format */`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	struct smb_hdr hdr;	/* wct = 3 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	__le16 Action;	/* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	unsigned char NativeOS[1];	/* followed by */`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	/*      unsigned char * NativeLanMan; */`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `	/*      unsigned char * PrimaryDomain; */`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `} __packed;	/* pre-NTLM (LANMAN2.1) response */`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `union smb_com_session_setup_andx {`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	struct smb_com_session_setup_req req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	struct smb_com_session_setup_req_no_secext req_no_secext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	struct smb_com_session_setup_resp resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	struct smb_com_session_setup_old_resp old_resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `struct smb_com_tconx_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	__u8 WordCount;  /* wct = 4, it could be ANDX */`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	__le16 Flags;           /* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	__le16 PasswordLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	unsigned char Password[1];      /* followed by */`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	/* STRING Path    *//* \\server\share name */`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	/* STRING Service */`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `struct smb_com_tconx_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	__u8 WordCount;     /* wct = 3 , not extended response */`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	__le16 OptionalSupport; /* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	unsigned char Service[1];       /* always ASCII, not Unicode */`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `	/* STRING NativeFileSystem */`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `struct smb_com_tconx_rsp_ext {`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	__u8 WordCount;	/* wct = 7, extended response */`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `	__le16 OptionalSupport; /* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	__le32 MaximalShareAccessRights;`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	__le32 GuestMaximalShareAccessRights;`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	unsigned char Service[1];       /* always ASCII, not Unicode */`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	/* STRING NativeFileSystem */`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `struct andx_block {`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	__u8 WordCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `struct locking_andx_range64 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	__le16 Pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	__le16 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	__le32 OffsetHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	__le32 OffsetLow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	__le32 LengthHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	__le32 LengthLow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `struct locking_andx_range32 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	__le16 Pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	__le32 Offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	__le32 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `#define LOCKING_ANDX_SHARED_LOCK     0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `#define LOCKING_ANDX_OPLOCK_RELEASE  0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `#define LOCKING_ANDX_CHANGE_LOCKTYPE 0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `#define LOCKING_ANDX_CANCEL_LOCK     0x08`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `#define LOCKING_ANDX_LARGE_FILES     0x10       /* always on for us */`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `struct smb_com_lock_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	struct smb_hdr hdr;	/* wct = 8 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	__u16 Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	__u8 LockType;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `	__u8 OplockLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `	__le16 NumberOfUnlocks;`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	__le16 NumberOfLocks;`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	char *Locks[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `struct smb_com_lock_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	struct smb_hdr hdr;     /* wct = 2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `struct smb_com_query_information_disk_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `	struct smb_hdr hdr;     /* wct = 5 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	__le16 TotalUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	__le16 BlocksPerUnit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	__le16 BlockSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	__le16 FreeUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `	__le16 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `/* tree connect Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `#define DISCONNECT_TID          0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `#define TCON_EXTENDED_SIGNATURES 0x0004`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `#define TCON_EXTENDED_SECINFO   0x0008`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `/* OptionalSupport bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `#define SMB_SUPPORT_SEARCH_BITS 0x0001  /*`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `					 * "must have" directory search bits`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `					 * (exclusive searches supported)`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `#define SMB_SHARE_IS_IN_DFS     0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `#define SMB_CSC_MASK               0x000C`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `/* CSC flags defined as follows */`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `#define SMB_CSC_CACHE_MANUAL_REINT 0x0000`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `#define SMB_CSC_CACHE_AUTO_REINT   0x0004`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `#define SMB_CSC_CACHE_VDO          0x0008`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `#define SMB_CSC_NO_CACHING         0x000C`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `#define SMB_UNIQUE_FILE_NAME    0x0010`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `#define SMB_EXTENDED_SIGNATURES 0x0020`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `/* OpenFlags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `#define REQ_MORE_INFO      0x00000001  /* legacy (OPEN_AND_X) only */`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `#define REQ_OPLOCK         0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `#define REQ_BATCHOPLOCK    0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `#define REQ_OPENDIRONLY    0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `#define REQ_EXTENDED_INFO  0x00000010`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `/* File type */`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `#define DISK_TYPE               0x0000`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `#define BYTE_PIPE_TYPE          0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `#define MESSAGE_PIPE_TYPE       0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `#define PRINTER_TYPE            0x0003`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `#define COMM_DEV_TYPE           0x0004`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `#define UNKNOWN_TYPE            0xFFFF`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `/* Device Type or File Status Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `#define NO_EAS                  0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `#define NO_SUBSTREAMS           0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `#define NO_REPARSETAG           0x0004`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `/* following flags can apply if pipe */`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `#define ICOUNT_MASK             0x00FF`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `#define PIPE_READ_MODE          0x0100`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `#define NAMED_PIPE_TYPE         0x0400`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `#define PIPE_END_POINT          0x4000`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `#define BLOCKING_NAMED_PIPE     0x8000`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `/* ShareAccess flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `#define FILE_NO_SHARE     0x00000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `#define FILE_SHARE_READ   0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `#define FILE_SHARE_WRITE  0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `#define FILE_SHARE_DELETE 0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `#define FILE_SHARE_ALL    0x00000007`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `/* CreateDisposition flags, similar to CreateAction as well */`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `#define FILE_SUPERSEDE    0x00000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `#define FILE_OPEN         0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `#define FILE_CREATE       0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `#define FILE_OPEN_IF      0x00000003`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `#define FILE_OVERWRITE    0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `#define FILE_OVERWRITE_IF 0x00000005`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `/* ImpersonationLevel flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `#define SECURITY_ANONYMOUS      0`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `#define SECURITY_IDENTIFICATION 1`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `#define SECURITY_IMPERSONATION  2`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `#define SECURITY_DELEGATION     3`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `/* SecurityFlags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `#define SECURITY_CONTEXT_TRACKING 0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `#define SECURITY_EFFECTIVE_ONLY   0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `struct smb_com_open_req {       /* also handles create */`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `	struct smb_hdr hdr;     /* wct = 24 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	__u8 Reserved;          /* Must Be Zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	__le16 NameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	__le32 OpenFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `	__u32  RootDirectoryFid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `	__le32 DesiredAccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `	__le32 FileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	__le32 ShareAccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `	__le32 CreateDisposition;`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `	__le32 CreateOptions;`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `	__le32 ImpersonationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `	__u8 SecurityFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `	char fileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `/* open response for CreateAction shifted left */`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `#define CIFS_CREATE_ACTION 0x20000 /* file created */`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `/* Basic file attributes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `#define SMB_FILE_ATTRIBUTE_NORMAL	0x0000`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `#define SMB_FILE_ATTRIBUTE_READONLY	0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `#define SMB_FILE_ATTRIBUTE_HIDDEN	0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `#define SMB_FILE_ATTRIBUTE_SYSTEM	0x0004`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `#define SMB_FILE_ATTRIBUTE_VOLUME	0x0008`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `#define SMB_FILE_ATTRIBUTE_DIRECTORY	0x0010`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `#define SMB_FILE_ATTRIBUTE_ARCHIVE	0x0020`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `#define SMB_SEARCH_ATTRIBUTE_READONLY	0x0100`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `#define SMB_SEARCH_ATTRIBUTE_HIDDEN	0x0200`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `#define SMB_SEARCH_ATTRIBUTE_SYSTEM	0x0400`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `#define SMB_SEARCH_ATTRIBUTE_DIRECTORY	0x1000`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `#define SMB_SEARCH_ATTRIBUTE_ARCHIVE	0x2000`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `struct smb_com_open_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `	struct smb_hdr hdr;     /* wct = 34 BB */`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	__u8 OplockLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `	__u16 Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	__le32 CreateAction;`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `	__le32 FileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `	__le16 FileType;`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `	__le16 DeviceState;`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `	__u8 DirectoryFlag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `	__le16 ByteCount;        /* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `struct smb_com_open_ext_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `	struct smb_hdr hdr;     /* wct = 42 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `	__u8 OplockLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `	__u16 Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `	__le32 CreateAction;`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `	__le32 FileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `	__le16 FileType;`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `	__le16 DeviceState;`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `	__u8 DirectoryFlag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `	__u8 VolId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `	__u64 fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `	__le32 MaxAccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `	__le32 GuestAccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `	__le16 ByteCount;        /* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `struct smb_com_close_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `	struct smb_hdr hdr;     /* wct = 3 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	__u16 FileID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	__le32 LastWriteTime;    /* should be zero or -1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	__le16  ByteCount;        /* 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `struct smb_com_close_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `	struct smb_hdr hdr;     /* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `	__le16 ByteCount;        /* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `struct smb_com_echo_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `	struct  smb_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `	__le16  EchoCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	__le16  ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `	char    Data[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `struct smb_com_echo_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `	struct  smb_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	__le16  SequenceNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `	__le16  ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `	char    Data[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `struct smb_com_flush_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	struct smb_hdr hdr;     /* wct = 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `	__u16 FileID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `	__le16 ByteCount;        /* 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `struct smb_com_flush_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `	struct smb_hdr hdr;     /* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `	__le16 ByteCount;        /* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [PROTO_GATE|] `/* SMB_COM_TRANSACTION */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00791 [NONE] `struct smb_com_trans_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `	struct smb_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `	__le16 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `	__le16 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `	__le16 MaxParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `	__le16 MaxDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `	__u8 MaxSetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `	__u8 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `	__u16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `	__le16 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `	__le16 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `	__le16 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `	__u8 Reserved3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `	__le16 SubCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `	__u8  Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `	__u8 Data[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `struct smb_com_trans_pipe_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `	struct smb_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `	__le16 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `	__le16 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `	__le16 MaxParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `	__le16 MaxDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `	__u8 MaxSetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `	__u8 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `	__u16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `	__le16 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `	__le16 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `	__le16 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `	__u8 Reserved3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `	__u16 SubCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `	__u16 fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `	__u8  Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `	__u8 Data[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `struct smb_com_trans_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `	struct smb_hdr hdr;     /* wct = 10+ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `	__le16 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `	__le16 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `	__u16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `	__le16 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `	__le16 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `	__le16 ParameterDisplacement;`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `	__le16 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `	__le16 DataDisplacement;`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `	__u8 Reserved1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `	__u8 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [PROTO_GATE|] `/* SMB_COM_TRANSACTION subcommands */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00855 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `#define TRANSACT_DCERPCCMD	0x26`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `/*****************************************************************************`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] ` * TRANS2 command implementation functions`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] ` *****************************************************************************/`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `#define NO_CHANGE_64          0xFFFFFFFFFFFFFFFFULL`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `/* QFSInfo Levels */`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `#define SMB_INFO_ALLOCATION         1`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `#define SMB_INFO_VOLUME             2`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `#define SMB_QUERY_FS_VOLUME_INFO    0x102`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `#define SMB_QUERY_FS_SIZE_INFO      0x103`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `#define SMB_QUERY_FS_DEVICE_INFO    0x104`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `#define SMB_QUERY_FS_ATTRIBUTE_INFO 0x105`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `#define SMB_QUERY_CIFS_UNIX_INFO    0x200`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `#define SMB_QUERY_POSIX_FS_INFO     0x201`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `#define SMB_QUERY_POSIX_WHO_AM_I    0x202`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `#define SMB_REQUEST_TRANSPORT_ENCRYPTION 0x203`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `#define SMB_QUERY_FS_PROXY          0x204 /*`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `					   * WAFS enabled. Returns structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `					   * FILE_SYSTEM__UNIX_INFO to tell`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `					   * whether new NTIOCTL available`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `					   * (0xACE) for WAN friendly SMB`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `					   * operations to be carried`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `					   */`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `#define SMB_QUERY_LABEL_INFO        0x3ea`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `#define SMB_QUERY_FS_QUOTA_INFO     0x3ee`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `#define SMB_QUERY_FS_FULL_SIZE_INFO 0x3ef`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `#define SMB_QUERY_OBJECTID_INFO     0x3f0`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `struct trans2_resp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `	/* struct smb_hdr hdr precedes. Note wct = 10 + setup count */`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `	__le16 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `	__le16 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `	__u16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `	__le16 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `	__le16 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `	__le16 ParameterDisplacement;`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `	__le16 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `	__le16 DataDisplacement;`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `	__u8 Reserved1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `	 * SetupWords[SetupCount];`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `	 * __u16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `	 * __u16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `	/* data area follows */`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `struct smb_com_trans2_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `	struct smb_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `	__le16 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `	__le16 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `	__le16 MaxParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `	__le16 MaxDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	__u8 MaxSetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `	__u8 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `	__u16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `	__le16 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `	__le16 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `	__le16 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `	__u8 Reserved3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `	__le16 SubCommand;      /* one setup word */`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `struct smb_com_trans2_qfsi_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `	struct smb_hdr hdr;     /* wct = 14+ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `	__le16 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `	__le16 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `	__le16 MaxParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `	__le16 MaxDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `	__u8 MaxSetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `	__u8 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	__u16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	__le16 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `	__le16 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `	__le16 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	__u8 Reserved3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	__le16 SubCommand;      /* one setup word */`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	__u8 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `	__le16 InformationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `struct smb_com_trans2_qfsi_req_params {`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `	__le16 InformationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `#define CIFS_SEARCH_CLOSE_ALWAYS	0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `#define CIFS_SEARCH_CLOSE_AT_END	0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `#define CIFS_SEARCH_RETURN_RESUME	0x0004`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `#define CIFS_SEARCH_CONTINUE_FROM_LAST	0x0008`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `#define CIFS_SEARCH_BACKUP_SEARCH	0x0010`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `struct smb_com_trans2_ffirst_req_params {`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `	__le16 SearchAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `	__le16 SearchCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `	__le16 SearchFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `	__le16 InformationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	__le32 SearchStorageType;`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `	char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `struct smb_com_trans2_ffirst_rsp_parms {`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	__u16 SearchHandle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `	__le16 SearchCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `	__le16 EndofSearch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `	__le16 EAErrorOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `	__le16 LastNameOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `struct smb_com_trans2_fnext_req_params {`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `	__u16 SearchHandle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `	__le16 SearchCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `	__le16 InformationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	__u32 ResumeKey;`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `	__le16 SearchFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `	char ResumeFileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `struct smb_com_trans2_fnext_rsp_params {`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `	__le16 SearchCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `	__le16 EndofSearch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `	__le16 EAErrorOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `	__le16 LastNameOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `struct smb_com_trans2_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	struct smb_hdr hdr;     /* wct = 10 + SetupCount */`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `	struct trans2_resp t2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `	__u8 Pad;       /* may be three bytes? *//* followed by data area */`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `	__u8 Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `struct file_internal_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `	__le64  UniqueId; /* inode number */`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `} __packed;      /* level 0x3ee */`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `/* DeviceType Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `#define FILE_DEVICE_CD_ROM              0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `#define FILE_DEVICE_DFS                 0x00000006`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `#define FILE_DEVICE_DISK                0x00000007`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `#define FILE_DEVICE_FILE_SYSTEM         0x00000009`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `#define FILE_DEVICE_NAMED_PIPE          0x00000011`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `#define FILE_DEVICE_NETWORK             0x00000012`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `#define FILE_DEVICE_NULL                0x00000015`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `#define FILE_DEVICE_PARALLEL_PORT       0x00000016`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `#define FILE_DEVICE_PRINTER             0x00000018`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `#define FILE_DEVICE_SERIAL_PORT         0x0000001b`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `#define FILE_DEVICE_STREAMS             0x0000001e`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `#define FILE_DEVICE_TAPE                0x0000001f`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `#define FILE_DEVICE_VIRTUAL_DISK        0x00000024`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `/* Filesystem Attributes. */`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `#define FILE_CASE_SENSITIVE_SEARCH      0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `#define FILE_CASE_PRESERVED_NAMES       0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `#define FILE_UNICODE_ON_DISK            0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `/* According to cifs9f, this is 4, not 8 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `/* Acconding to testing, this actually sets the security attribute! */`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `#define FILE_PERSISTENT_ACLS            0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `#define FILE_FILE_COMPRESSION           0x00000010`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `#define FILE_VOLUME_QUOTAS              0x00000020`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `#define FILE_SUPPORTS_SPARSE_FILES      0x00000040`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `#define FILE_SUPPORTS_REPARSE_POINTS    0x00000080`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `#define FILE_SUPPORTS_REMOTE_STORAGE    0x00000100`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `#define FS_LFN_APIS                     0x00004000`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `#define FILE_VOLUME_IS_COMPRESSED       0x00008000`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `#define FILE_SUPPORTS_OBJECT_IDS        0x00010000`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `#define FILE_SUPPORTS_ENCRYPTION        0x00020000`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `#define FILE_NAMED_STREAMS              0x00040000`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `#define FILE_READ_ONLY_VOLUME           0x00080000`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `/* PathInfo/FileInfo infolevels */`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `#define SMB_INFO_STANDARD                   1`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `#define SMB_SET_FILE_EA                     2`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `#define SMB_QUERY_FILE_EA_SIZE              2`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `#define SMB_INFO_QUERY_EAS_FROM_LIST        3`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `#define SMB_INFO_QUERY_ALL_EAS              4`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `#define SMB_INFO_IS_NAME_VALID              6`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] `#define SMB_QUERY_FILE_BASIC_INFO       0x101`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] `#define SMB_QUERY_FILE_STANDARD_INFO    0x102`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `#define SMB_QUERY_FILE_EA_INFO          0x103`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `#define SMB_QUERY_FILE_NAME_INFO        0x104`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `#define SMB_QUERY_FILE_ALLOCATION_INFO  0x105`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `#define SMB_QUERY_FILE_END_OF_FILEINFO  0x106`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `#define SMB_QUERY_FILE_ALL_INFO         0x107`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `#define SMB_QUERY_ALT_NAME_INFO         0x108`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `#define SMB_QUERY_FILE_STREAM_INFO      0x109`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `#define SMB_QUERY_FILE_COMPRESSION_INFO 0x10B`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `#define SMB_QUERY_FILE_UNIX_BASIC       0x200`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `#define SMB_QUERY_FILE_UNIX_LINK        0x201`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `#define SMB_QUERY_POSIX_ACL             0x204`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `#define SMB_QUERY_XATTR                 0x205  /* e.g. system EA name space */`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `#define SMB_QUERY_ATTR_FLAGS            0x206  /* append,immutable etc. */`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `#define SMB_QUERY_POSIX_PERMISSION      0x207`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `#define SMB_QUERY_POSIX_LOCK            0x208`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `/* #define SMB_POSIX_OPEN               0x209 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `/* #define SMB_POSIX_UNLINK             0x20a */`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `#define SMB_QUERY_FILE__UNIX_INFO2      0x20b`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `#define SMB_QUERY_FILE_INTERNAL_INFO    0x3ee`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `#define SMB_QUERY_FILE_ACCESS_INFO      0x3f0`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `#define SMB_QUERY_FILE_NAME_INFO2       0x3f1 /* 0x30 bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `#define SMB_QUERY_FILE_POSITION_INFO    0x3f6`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `#define SMB_QUERY_FILE_MODE_INFO        0x3f8`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `#define SMB_QUERY_FILE_ALGN_INFO        0x3f9`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `#define SMB_SET_FILE_BASIC_INFO         0x101`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `#define SMB_SET_FILE_DISPOSITION_INFO   0x102`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `#define SMB_SET_FILE_ALLOCATION_INFO    0x103`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `#define SMB_SET_FILE_END_OF_FILE_INFO   0x104`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `#define SMB_SET_FILE_UNIX_BASIC         0x200`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `#define SMB_SET_FILE_UNIX_LINK          0x201`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `#define SMB_SET_FILE_UNIX_HLINK         0x203`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `#define SMB_SET_POSIX_ACL               0x204`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `#define SMB_SET_XATTR                   0x205`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `#define SMB_SET_ATTR_FLAGS              0x206  /* append, immutable etc. */`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `#define SMB_SET_POSIX_LOCK              0x208`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `#define SMB_POSIX_OPEN                  0x209`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `#define SMB_POSIX_UNLINK                0x20a`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `#define SMB_SET_FILE_UNIX_INFO2         0x20b`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `#define SMB_SET_FILE_BASIC_INFO2        0x3ec`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `#define SMB_SET_FILE_RENAME_INFORMATION 0x3f2 /* BB check if qpathinfo too */`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `#define SMB_SET_FILE_DISPOSITION_INFORMATION   0x3f5   /* alias for 0x102 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `#define SMB_FILE_ALL_INFO2              0x3fa`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `#define SMB_SET_FILE_ALLOCATION_INFO2   0x3fb`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `#define SMB_SET_FILE_END_OF_FILE_INFO2  0x3fc`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `#define SMB_FILE_MOVE_CLUSTER_INFO      0x407`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `#define SMB_FILE_QUOTA_INFO             0x408`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `#define SMB_FILE_REPARSEPOINT_INFO      0x409`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `#define SMB_FILE_MAXIMUM_INFO           0x40d`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `/* Find File infolevels */`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `#define SMB_FIND_FILE_INFO_STANDARD       0x001`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `#define SMB_FIND_FILE_QUERY_EA_SIZE       0x002`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `#define SMB_FIND_FILE_QUERY_EAS_FROM_LIST 0x003`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `#define SMB_FIND_FILE_DIRECTORY_INFO      0x101`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `#define SMB_FIND_FILE_FULL_DIRECTORY_INFO 0x102`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `#define SMB_FIND_FILE_NAMES_INFO          0x103`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] `#define SMB_FIND_FILE_BOTH_DIRECTORY_INFO 0x104`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `#define SMB_FIND_FILE_ID_FULL_DIR_INFO    0x105`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `#define SMB_FIND_FILE_ID_BOTH_DIR_INFO    0x106`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `#define SMB_FIND_FILE_UNIX                0x202`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `struct smb_com_trans2_qpi_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `	struct smb_hdr hdr;     /* wct = 14+ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `	__le16 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `	__le16 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `	__le16 MaxParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `	__le16 MaxDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `	__u8 MaxSetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `	__u8 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `	__u16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `	__le16 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `	__le16 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `	__le16 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `	__u8 Reserved3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `	__le16 SubCommand;      /* one setup word */`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `	__u8 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `	__le16 InformationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `	__u32 Reserved4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `	char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `struct trans2_qpi_req_params {`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `	__le16 InformationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `	__u32 Reserved4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `	char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `/******************************************************************************/`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `/* QueryFileInfo/QueryPathinfo (also for SetPath/SetFile) data buffer formats */`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `/******************************************************************************/`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `struct file_basic_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `	__le32 Attributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `	__u32 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `} __packed;      /* size info, level 0x101 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `struct file_standard_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `	__le32 NumberOfLinks;`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `	__u8 DeletePending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `	__u8 Directory;`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `struct file_ea_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `	__le32 EaSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `struct alt_name_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `	char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `struct file_name_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] `	char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `/* data block encoding of response to level 263 QPathInfo */`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `struct file_all_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `	__le32 Attributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `	__u32 Pad1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `	__le64 EndOfFile;       /* size ie offset to first free byte in file */`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] `	__le32 NumberOfLinks;   /* hard links */`
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `	__u8 DeletePending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] `	__u8 Directory;`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] `	__u16 Pad2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] `	__le32 EASize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `	char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `} __packed; /* level 0x107 QPathInfo */`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `/* set path info/open file */`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `/* defines for enumerating possible values of the Unix type field below */`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `#define UNIX_FILE      0`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] `#define UNIX_DIR       1`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `#define UNIX_SYMLINK   2`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `#define UNIX_CHARDEV   3`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `#define UNIX_BLOCKDEV  4`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `#define UNIX_FIFO      5`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `#define UNIX_SOCKET    6`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `#define UNIX_UNKNOWN   0xFFFFFFFF`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `struct file_unix_basic_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `	__le64 NumOfBytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `	__le64 LastStatusChange; /*SNIA specs DCE time for the 3 time fields */`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `	__le64 LastModificationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `	__le64 Uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `	__le64 Gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `	__le32 Type;`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	__le64 DevMajor;`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] `	__le64 DevMinor;`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `	__le64 UniqueId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `	__le64 Permissions;`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	__le64 Nlinks;`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `} __packed; /* level 0x200 QPathInfo */`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `struct smb_com_trans2_spi_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `	struct smb_hdr hdr;     /* wct = 15 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `	__le16 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `	__le16 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `	__le16 MaxParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] `	__le16 MaxDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `	__u8 MaxSetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `	__u8 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `	__u16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `	__le16 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `	__le16 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `	__le16 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `	__u8 Reserved3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `	__le16 SubCommand;      /* one setup word */`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] `	__u8 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `	__u16 Pad1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `	__le16 InformationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `	__u32 Reserved4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `	char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `struct smb_com_trans2_spi_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `	struct smb_hdr hdr;     /* wct = 10 + SetupCount */`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `	struct trans2_resp t2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] `	__u16 Reserved2; /* parameter word is present for infolevels > 100 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `/* POSIX Open Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `#define SMB_O_RDONLY     0x1`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `#define SMB_O_WRONLY    0x2`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `#define SMB_O_RDWR      0x4`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `#define SMB_O_CREAT     0x10`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `#define SMB_O_EXCL      0x20`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `#define SMB_O_TRUNC     0x40`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `#define SMB_O_APPEND    0x80`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `#define SMB_O_SYNC      0x100`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `#define SMB_O_DIRECTORY 0x200`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `#define SMB_O_NOFOLLOW  0x400`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `#define SMB_O_DIRECT    0x800`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `#define SMB_ACCMODE	0x7`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `/* info level response for SMB_POSIX_PATH_OPEN */`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `#define SMB_NO_INFO_LEVEL_RESPONSE 0xFFFF`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] `struct open_psx_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `	__le32 OpenFlags; /* same as NT CreateX */`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `	__le32 PosixOpenFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `	__le64 Permissions;`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `	__le16 Level; /* reply level requested (see QPathInfo levels) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] `} __packed; /* level 0x209 SetPathInfo data */`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] `struct open_psx_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `	__le16 OplockFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `	__u16 Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `	__le32 CreateAction;`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `	__le16 ReturnedLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `	__le16 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `	/* struct following varies based on requested level */`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `} __packed; /* level 0x209 SetPathInfo data */`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `struct unlink_psx_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	__le16 EAErrorOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `} __packed; /* level 0x209 SetPathInfo data*/`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `/* Version numbers for CIFS UNIX major and minor. */`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `#define CIFS_UNIX_MAJOR_VERSION 1`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `#define CIFS_UNIX_MINOR_VERSION 0`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `struct filesystem_unix_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] `	__le16 MajorVersionNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `	__le16 MinorVersionNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `	__le64 Capability;`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `} __packed; /* Unix extension level 0x200*/`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `/* Linux/Unix extensions capability flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] `#define CIFS_UNIX_FCNTL_CAP             0x00000001 /* support for fcntl locks */`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `#define CIFS_UNIX_POSIX_ACL_CAP         0x00000002 /* support getfacl/setfacl */`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `#define CIFS_UNIX_XATTR_CAP             0x00000004 /* support new namespace   */`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `#define CIFS_UNIX_EXTATTR_CAP           0x00000008 /* support chattr/chflag   */`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `#define CIFS_UNIX_POSIX_PATHNAMES_CAP   0x00000010 /* Allow POSIX path chars  */`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `#define CIFS_UNIX_POSIX_PATH_OPS_CAP    0x00000020 /*`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `						    * Allow new POSIX path based`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `						    * calls including posix open`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `						    * and posix unlink`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `						    */`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] `#define CIFS_UNIX_LARGE_READ_CAP        0x00000040 /*`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `						    * support reads >128K (up`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `						    * to 0xFFFF00`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `						    */`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] `#define CIFS_UNIX_LARGE_WRITE_CAP       0x00000080`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `#define CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP 0x00000100 /* can do SPNEGO crypt */`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `#define CIFS_UNIX_TRANSPORT_ENCRYPTION_MANDATORY_CAP  0x00000200 /* must do  */`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `#define CIFS_UNIX_PROXY_CAP             0x00000400 /*`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `						    * Proxy cap: 0xACE ioctl and`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `						    * QFS PROXY call`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `						    */`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `#ifdef CONFIG_CIFS_POSIX`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `/* presumably don't need the 0x20 POSIX_PATH_OPS_CAP since we never send`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] ` * LockingX instead of posix locking call on unix sess (and we do not expect`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] ` * LockingX to use different (ie Windows) semantics than posix locking on`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] ` * the same session (if WINE needs to do this later, we can add this cap`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] ` * back in later`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] `/* #define CIFS_UNIX_CAP_MASK              0x000000fb */`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] `#define CIFS_UNIX_CAP_MASK              0x000003db`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `#define CIFS_UNIX_CAP_MASK              0x00000013`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `#endif /* CONFIG_CIFS_POSIX */`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `#define CIFS_POSIX_EXTENSIONS           0x00000010 /* support for new QFSInfo */`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `/* Our server caps */`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `#define SMB_UNIX_CAPS	(CIFS_UNIX_FCNTL_CAP | CIFS_UNIX_POSIX_ACL_CAP | \`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `		CIFS_UNIX_XATTR_CAP | CIFS_UNIX_POSIX_PATHNAMES_CAP| \`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `		CIFS_UNIX_POSIX_PATH_OPS_CAP | CIFS_UNIX_LARGE_READ_CAP | \`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] `		CIFS_UNIX_LARGE_WRITE_CAP)`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `#define SMB_SET_CIFS_UNIX_INFO    0x200`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `/* Level 0x200 request structure follows */`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `struct smb_com_trans2_setfsi_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `	struct smb_hdr hdr;     /* wct = 15 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `	__le16 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `	__le16 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `	__le16 MaxParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `	__le16 MaxDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	__u8 MaxSetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] `	__u8 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `	__u16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `	__le16 ParameterCount;  /* 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `	__le16 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `	__le16 DataCount;       /* 12 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] `	__u8 SetupCount;        /* one */`
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `	__u8 Reserved3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `	__le16 SubCommand;      /* TRANS2_SET_FS_INFORMATION */`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `	__u8 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `	__u16 FileNum;          /* Parameters start. */`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `	__le16 InformationLevel;/* Parameters end. */`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `	__le16 ClientUnixMajor; /* Data start. */`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `	__le16 ClientUnixMinor;`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] `	__le64 ClientUnixCap;   /* Data end */`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `/* response for setfsinfo levels 0x200 and 0x203 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `struct smb_com_trans2_setfsi_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `	struct smb_hdr hdr;     /* wct = 10 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] `	struct trans2_resp t2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `struct smb_com_trans2_setfsi_req_params {`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `	__u16 FileNum;`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] `	__le16 InformationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] `	__le16 ClientUnixMajor; /* Data start. */`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] `	__le16 ClientUnixMinor;`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `	__le64 ClientUnixCap;   /* Data end */`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] `struct smb_trans2_qfi_req_params {`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] `	__u16   Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `	__le16  InformationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] `/* FIND FIRST2 and FIND NEXT2 INFORMATION Level Codes*/`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] `struct find_info_standard {`
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `	__le16 CreationDate; /* SMB Date see above */`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `	__le16 CreationTime; /* SMB Time */`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] `	__le16 LastAccessDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `	__le16 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] `	__le16 LastWriteDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `	__le16 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `	__le32 DataSize; /* File Size (EOF) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `	__le32 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `	__le16 Attributes; /* verify not u32 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] `	__le16 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `	char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] `struct find_info_query_ea_size {`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] `	__le16 CreationDate; /* SMB Date see above */`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `	__le16 CreationTime; /* SMB Time */`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] `	__le16 LastAccessDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `	__le16 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] `	__le16 LastWriteDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] `	__le16 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] `	__le32 DataSize; /* File Size (EOF) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] `	__le32 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `	__le16 Attributes; /* verify not u32 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] `	__le32 EASize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `	__u8 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] `	char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `struct file_unix_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `	__u32 ResumeKey; /* as with FileIndex - no need to convert */`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `	struct file_unix_basic_info basic;`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `	char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `} __packed; /* level 0x202 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `struct smb_com_trans2_sfi_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] `	struct smb_hdr hdr;     /* wct = 15 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `	__le16 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `	__le16 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `	__le16 MaxParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] `	__le16 MaxDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `	__u8 MaxSetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] `	__u8 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] `	__u16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `	__le16 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `	__le16 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] `	__le16 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] `	__u8 SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] `	__u8 Reserved3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `	__le16 SubCommand;      /* one setup word */`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `	__u8 Pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `	__u16 Pad1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `	__u16 Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] `	__le16 InformationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] `	__u16 Reserved4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] `struct smb_com_trans2_sfi_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] `	struct smb_hdr hdr;     /* wct = 10 + SetupCount */`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `	struct trans2_resp t2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `	__u16 Reserved2;        /*`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] `				 * parameter word reserved -`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] `				 * present for infolevels > 100`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `struct file_end_of_file_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `	__le64 FileSize;                /* offset to end of file */`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] `} __packed; /* size info, level 0x104 for set, 0x106 for query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `struct smb_com_create_directory_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] `	struct smb_hdr hdr;	/* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `	__u8 BufferFormat;	/* 4 = ASCII */`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `	unsigned char DirName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `struct smb_com_create_directory_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `	struct smb_hdr hdr;	/* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] `	__le16 ByteCount;	/* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] `struct smb_com_check_directory_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] `	struct smb_hdr hdr;	/* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `	__u8 BufferFormat;	/* 4 = ASCII */`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] `	unsigned char DirName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `struct smb_com_check_directory_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `	struct smb_hdr hdr;	/* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `	__le16 ByteCount;	/* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] `struct smb_com_process_exit_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] `	struct smb_hdr hdr;	/* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `	__le16 ByteCount;	/* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `struct smb_com_delete_directory_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [NONE] `	struct smb_hdr hdr;     /* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `	__u8 BufferFormat;      /* 4 = ASCII */`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] `	unsigned char DirName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `struct smb_com_delete_directory_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `	struct smb_hdr hdr;     /* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `	__le16 ByteCount;        /* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] `struct smb_com_delete_file_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `	struct smb_hdr hdr;     /* wct = 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `	__le16 SearchAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] `	__u8 BufferFormat;      /* 4 = ASCII */`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] `	unsigned char fileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `struct smb_com_delete_file_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `	struct smb_hdr hdr;     /* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `	__le16 ByteCount;        /* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `#define CREATE_HARD_LINK         0x103`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] `struct smb_com_nt_rename_req {  /* A5 - also used for create hardlink */`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] `	struct smb_hdr hdr;     /* wct = 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `	__le16 SearchAttributes;        /* target file attributes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `	__le16 Flags;           /* spec says Information Level */`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] `	__le32 ClusterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] `	__u8 BufferFormat;      /* 4 = ASCII or Unicode */`
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] `	unsigned char OldFileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `	/* followed by __u8 BufferFormat2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] `	/* followed by NewFileName */`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `struct smb_com_query_information_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] `	struct smb_hdr hdr;     /* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [NONE] `	__le16 ByteCount;       /* 1 + namelen + 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01552 [NONE] `	__u8 BufferFormat;      /* 4 = ASCII */`
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] `	unsigned char FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `struct smb_com_query_information_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [NONE] `	struct smb_hdr hdr;     /* wct = 10 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [NONE] `	__le16 attr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] `	__le32  last_write_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] `	__le32 size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] `	__u16  reserved[5];`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `	__le16 ByteCount;       /* bcc = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] `struct smb_com_findclose_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `	struct smb_hdr hdr; /* wct = 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] `	__u16 FileID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] `	__le16 ByteCount;    /* 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] `#define SMBOPEN_DISPOSITION_NONE        0`
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] `#define SMBOPEN_LOCK_GRANTED            0x8000`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] `#define SMB_DA_ACCESS_READ              0`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] `#define SMB_DA_ACCESS_WRITE             0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] `#define SMB_DA_ACCESS_READ_WRITE        0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] ` * Flags on SMB open`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [NONE] `#define SMBOPEN_WRITE_THROUGH 0x4000`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] `#define SMBOPEN_DENY_ALL      0x0010`
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `#define SMBOPEN_DENY_WRITE    0x0020`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `#define SMBOPEN_DENY_READ     0x0030`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] `#define SMBOPEN_DENY_NONE     0x0040`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] `#define SMBOPEN_SHARING_MODE  (SMBOPEN_DENY_ALL |	\`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] `				SMBOPEN_DENY_WRITE |	\`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] `				SMBOPEN_DENY_READ |	\`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] `				SMBOPEN_DENY_NONE)`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [NONE] `#define SMBOPEN_READ          0x0000`
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `#define SMBOPEN_WRITE         0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] `#define SMBOPEN_READWRITE     0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] `#define SMBOPEN_EXECUTE       0x0003`
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] `#define SMBOPEN_OCREATE       0x0010`
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] `#define SMBOPEN_OTRUNC        0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] `#define SMBOPEN_OAPPEND       0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [NONE] `/* format of legacy open request */`
  Review: Low-risk line; verify in surrounding control flow.
- L01600 [NONE] `struct smb_com_openx_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] `	struct smb_hdr  hdr;    /* wct = 15 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01605 [NONE] `	__le16 OpenFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] `	__le16 Mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `	__le16 Sattr; /* search attributes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `	__le16 FileAttributes;  /* dos attrs */`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `	__le32 CreateTime; /* os2 format */`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `	__le16 OpenFunction;`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] `	__le32 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] `	__le16  ByteCount;  /* file name follows */`
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `	char   fileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01618 [NONE] `struct smb_com_openx_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] `	struct smb_hdr  hdr;    /* wct = 15 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [NONE] `	__u8 AndXCommand;`
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [NONE] `	__u8 AndXReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] `	__le16 AndXOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `	__u16  Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] `	__le16 FileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `	__le32 LastWriteTime; /* os2 format */`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `	__le32 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] `	__le16 Access;`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `	__le16 FileType;`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `	__le16 IPCState;`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] `	__le16 Action;`
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [NONE] `	__u32  FileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [NONE] `	__u16  Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01634 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `struct filesystem_alloc_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] `	__le32 fsid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [NONE] `	__le32 SectorsPerAllocationUnit;`
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] `	__le32 TotalAllocationUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `	__le32 FreeAllocationUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `	__le16  BytesPerSector;`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `struct file_allocation_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] `	__le64 AllocationSize; /* Note old Samba srvr rounds this up too much */`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `} __packed;      /* size used on disk: 0x103 for set, 0x105 for query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `struct file_info_standard {`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `	__le16 CreationDate; /* SMB Date see above */`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `	__le16 CreationTime; /* SMB Time */`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `	__le16 LastAccessDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] `	__le16 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `	__le16 LastWriteDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `	__le16 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `	__le32 DataSize; /* File Size (EOF) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] `	__le32 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [NONE] `	__le16 Attributes; /* verify not u32 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `	__le32 EASize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `} __packed;  /* level 1 SetPath/FileInfo */`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `#define CIFS_MF_SYMLINK_LINK_MAXLEN (1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [NONE] `struct set_file_rename {`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [NONE] `	__le32 overwrite;   /* 1 = overwrite dest */`
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [NONE] `	__u32 root_fid;   /* zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [NONE] `	__le32 target_name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [NONE] `	char  target_name[0];  /* Must be unicode */`
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] `struct fea {`
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `	unsigned char EA_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `	__u8 name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `	__le16 value_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] `	char name[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `	/* optionally followed by value */`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [NONE] `struct fealist {`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [NONE] `	__le32 list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01680 [NONE] `	__u8 list[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01681 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [NONE] `/* POSIX ACL set/query path info structures */`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [NONE] `#define CIFS_ACL_VERSION 1`
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [NONE] `struct cifs_posix_ace { /* access control entry (ACE) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [NONE] `	__u8  cifs_e_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] `	__u8  cifs_e_perm;`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [NONE] `	__le64 cifs_uid; /* or gid */`
  Review: Low-risk line; verify in surrounding control flow.
- L01689 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [NONE] `struct cifs_posix_acl { /* access conrol list  (ACL) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] `	__le16  version;`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] `	__le16  access_entry_count;  /* access ACL - count of entries */`
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [NONE] `	__le16  default_entry_count; /* default ACL - count of entries */`
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] `	struct cifs_posix_ace ace_array[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `	 * followed by`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] `	 * struct cifs_posix_ace default_ace_arraay[]`
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [NONE] `} __packed;  /* level 0x204 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] `struct smb_com_setattr_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] `	struct smb_hdr hdr; /* wct = 8 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] `	__le16 attr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] `	__le32 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] `	__le16 reserved[5]; /* must be zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [NONE] `	__u8   BufferFormat; /* 4 = ASCII */`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] `	unsigned char fileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] `struct smb_com_setattr_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `	struct smb_hdr hdr;     /* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `	__le16 ByteCount;        /* bct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] `/* NT_TRANSACT (0xA0) request/response structures (MS-SMB §2.2.4.62) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] `struct smb_com_ntransact_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] `	struct smb_hdr hdr;		/* wct = 19+SetupCount */`
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [NONE] `	__u8  MaxSetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [NONE] `	__u16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [NONE] `	__le32 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [NONE] `	__le32 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] `	__le32 MaxParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] `	__le32 MaxDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [NONE] `	__le32 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [NONE] `	__le32 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01728 [NONE] `	__le32 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] `	__le32 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] `	__u8  SetupCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] `	__le16 Function;`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `	__le16 SetupWords[1];	/* variable: SetupCount words */`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `	/* followed by ByteCount(__le16) + Pad + Parameters + Data */`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [NONE] `struct smb_com_ntransact_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [NONE] `	struct smb_hdr hdr;		/* wct = 18 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [NONE] `	__u8  Reserved[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L01739 [NONE] `	__le32 TotalParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `	__le32 TotalDataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [NONE] `	__le32 ParameterCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [NONE] `	__le32 ParameterOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [NONE] `	__le32 ParameterDisplacement;`
  Review: Low-risk line; verify in surrounding control flow.
- L01744 [NONE] `	__le32 DataCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `	__le32 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] `	__le32 DataDisplacement;`
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] `	__u8  SetupCount;		/* 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] `extern int init_smb1_server(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01754 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] `/* function prototypes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] `extern int init_smb_rsp_hdr(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [NONE] `extern u16 get_smb_cmd_val(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01758 [NONE] `extern void set_smb_rsp_status(struct ksmbd_work *work, __le32 err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] `extern int smb_allocate_rsp_buf(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] `extern bool smb1_is_sign_req(struct ksmbd_work *work, unsigned int command);`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] `extern int smb1_check_sign_req(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [NONE] `extern void smb1_set_sign_rsp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] `extern int smb_check_user_session(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] `extern int smb_get_ksmbd_tcon(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] `extern int ksmbd_smb1_check_message(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] `/* smb1 command handlers */`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] `extern int smb_rename(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `extern int smb_negotiate_request(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] `extern int smb_handle_negotiate(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] `extern int smb_session_setup_andx(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] `extern int smb_tree_connect_andx(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] `extern int smb_trans2(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [NONE] `extern int smb_nt_transact(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01777 [NONE] `extern int smb_nt_create_andx(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] `extern int smb_trans(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] `extern int smb_locking_andx(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [NONE] `extern int smb_close(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01781 [NONE] `extern int smb_read_andx(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] `extern int smb_tree_disconnect(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] `extern int smb_session_disconnect(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `extern int smb_write_andx(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `extern int smb_echo(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] `extern int smb_flush(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] `extern int smb_mkdir(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [NONE] `extern int smb_rmdir(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] `extern int smb_unlink(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [NONE] `extern int smb_nt_cancel(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01791 [NONE] `extern int smb_nt_rename(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] `extern int smb_query_info(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `extern int smb_closedir(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] `extern int smb_open_andx(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] `extern int smb_write(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] `extern int smb_setattr(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] `extern int smb_query_information_disk(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] `extern int smb_checkdir(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [NONE] `extern int smb_process_exit(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [NONE] `/* A.2: P2 missing commands */`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] `extern int smb_query_information2(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [NONE] `extern int smb_set_information2(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01803 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `/* A.2: Request/Response structures for QUERY_INFORMATION2 (0x23) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] `struct smb_com_query_info2_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `	struct smb_hdr hdr;	/* wct = 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] `	__u16 Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] `	__le16 ByteCount;	/* must be 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] `struct smb_com_query_info2_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [NONE] `	struct smb_hdr hdr;	/* wct = 11 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] `	__le16 CreateDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [NONE] `	__le16 CreateTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [NONE] `	__le16 LastAccessDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01816 [NONE] `	__le16 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [NONE] `	__le16 LastWriteDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] `	__le16 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [NONE] `	__le32 FileDataSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `	__le32 FileAllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] `	__le16 FileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] `	__le16 ByteCount;	/* must be 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01824 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [NONE] `/* A.2: Request/Response structures for SET_INFORMATION2 (0x22) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01826 [NONE] `struct smb_com_set_info2_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `	struct smb_hdr hdr;	/* wct = 7 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] `	__u16 Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] `	__le16 CreateDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `	__le16 CreateTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [NONE] `	__le16 LastAccessDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01832 [NONE] `	__le16 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `	__le16 LastWriteDate;`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] `	__le16 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] `	__le16 ByteCount;	/* must be 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01838 [NONE] `struct smb_com_set_info2_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] `	struct smb_hdr hdr;	/* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] `	__le16 ByteCount;	/* must be 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `int smb_nt_transact(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] `int smb_nt_transact_secondary(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] `#endif /* __SMB1PDU_H */`
  Review: Low-risk line; verify in surrounding control flow.
