# Line-by-line Review: src/include/protocol/smb2pdu.h

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
- L00007 [NONE] `#ifndef _SMB2PDU_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define _SMB2PDU_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "ntlmssp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` * Note that, due to trying to use names similar to the protocol specifications,`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` * there are many mixed case field names in the structures below.  Although`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` * this does not match typical Linux kernel style, it is necessary to be`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * able to match against the protocol specfication.`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` * SMB2 commands`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * Some commands have minimal (wct=0,bcc=0), or uninteresting, responses`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * (ie no useful data other than the SMB error code itself) and are marked such.`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * Knowing this helps avoid response buffer allocations and copy in some cases.`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `/* List of commands in host endian */`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [PROTO_GATE|] `#define SMB2_NEGOTIATE_HE	0x0000`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00028 [PROTO_GATE|] `#define SMB2_SESSION_SETUP_HE	0x0001`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00029 [PROTO_GATE|] `#define SMB2_LOGOFF_HE		0x0002 /* trivial request/resp */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00030 [PROTO_GATE|] `#define SMB2_TREE_CONNECT_HE	0x0003`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00031 [PROTO_GATE|] `#define SMB2_TREE_DISCONNECT_HE	0x0004 /* trivial req/resp */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00032 [PROTO_GATE|] `#define SMB2_CREATE_HE		0x0005`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00033 [PROTO_GATE|] `#define SMB2_CLOSE_HE		0x0006`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00034 [PROTO_GATE|] `#define SMB2_FLUSH_HE		0x0007 /* trivial resp */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00035 [PROTO_GATE|] `#define SMB2_READ_HE		0x0008`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00036 [PROTO_GATE|] `#define SMB2_WRITE_HE		0x0009`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00037 [PROTO_GATE|] `#define SMB2_LOCK_HE		0x000A`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00038 [PROTO_GATE|] `#define SMB2_IOCTL_HE		0x000B`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00039 [PROTO_GATE|] `#define SMB2_CANCEL_HE		0x000C`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00040 [PROTO_GATE|] `#define SMB2_ECHO_HE		0x000D`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00041 [PROTO_GATE|] `#define SMB2_QUERY_DIRECTORY_HE	0x000E`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00042 [PROTO_GATE|] `#define SMB2_CHANGE_NOTIFY_HE	0x000F`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00043 [PROTO_GATE|] `#define SMB2_QUERY_INFO_HE	0x0010`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00044 [PROTO_GATE|] `#define SMB2_SET_INFO_HE	0x0011`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00045 [PROTO_GATE|] `#define SMB2_OPLOCK_BREAK_HE	0x0012`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00046 [NONE] `/* SMB 3.1.1 server-to-client notification (MS-SMB2 §2.2.44) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [PROTO_GATE|] `#define SMB2_SERVER_TO_CLIENT_NOTIFICATION_HE	0x0013`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `/* The same list in little endian */`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [PROTO_GATE|] `#define SMB2_NEGOTIATE		cpu_to_le16(SMB2_NEGOTIATE_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00051 [PROTO_GATE|] `#define SMB2_SESSION_SETUP	cpu_to_le16(SMB2_SESSION_SETUP_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00052 [PROTO_GATE|] `#define SMB2_LOGOFF		cpu_to_le16(SMB2_LOGOFF_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00053 [PROTO_GATE|] `#define SMB2_TREE_CONNECT	cpu_to_le16(SMB2_TREE_CONNECT_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00054 [PROTO_GATE|] `#define SMB2_TREE_DISCONNECT	cpu_to_le16(SMB2_TREE_DISCONNECT_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00055 [PROTO_GATE|] `#define SMB2_CREATE		cpu_to_le16(SMB2_CREATE_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00056 [PROTO_GATE|] `#define SMB2_CLOSE		cpu_to_le16(SMB2_CLOSE_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00057 [PROTO_GATE|] `#define SMB2_FLUSH		cpu_to_le16(SMB2_FLUSH_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00058 [PROTO_GATE|] `#define SMB2_READ		cpu_to_le16(SMB2_READ_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [PROTO_GATE|] `#define SMB2_WRITE		cpu_to_le16(SMB2_WRITE_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00060 [PROTO_GATE|] `#define SMB2_LOCK		cpu_to_le16(SMB2_LOCK_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00061 [PROTO_GATE|] `#define SMB2_IOCTL		cpu_to_le16(SMB2_IOCTL_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00062 [PROTO_GATE|] `#define SMB2_CANCEL		cpu_to_le16(SMB2_CANCEL_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00063 [PROTO_GATE|] `#define SMB2_ECHO		cpu_to_le16(SMB2_ECHO_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00064 [PROTO_GATE|] `#define SMB2_QUERY_DIRECTORY	cpu_to_le16(SMB2_QUERY_DIRECTORY_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00065 [PROTO_GATE|] `#define SMB2_CHANGE_NOTIFY	cpu_to_le16(SMB2_CHANGE_NOTIFY_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00066 [PROTO_GATE|] `#define SMB2_QUERY_INFO		cpu_to_le16(SMB2_QUERY_INFO_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00067 [PROTO_GATE|] `#define SMB2_SET_INFO		cpu_to_le16(SMB2_SET_INFO_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00068 [PROTO_GATE|] `#define SMB2_OPLOCK_BREAK	cpu_to_le16(SMB2_OPLOCK_BREAK_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00069 [PROTO_GATE|] `#define SMB2_SERVER_TO_CLIENT_NOTIFICATION \`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00070 [PROTO_GATE|] `	cpu_to_le16(SMB2_SERVER_TO_CLIENT_NOTIFICATION_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `/*Create Action Flags*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `#define FILE_SUPERSEDED                0x00000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `#define FILE_OPENED            0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `#define FILE_CREATED           0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `#define FILE_OVERWRITTEN       0x00000003`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` * Size of the session key (crypto key encrypted with the password`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [PROTO_GATE|] `#define SMB2_NTLMV2_SESSKEY_SIZE	16`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00082 [PROTO_GATE|] `#define SMB2_SIGNATURE_SIZE		16`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00083 [PROTO_GATE|] `#define SMB2_HMACSHA256_SIZE		32`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00084 [PROTO_GATE|] `#define SMB2_CMACAES_SIZE		16`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00085 [NONE] `#define SMB3_GCM128_CRYPTKEY_SIZE	16`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `#define SMB3_GCM256_CRYPTKEY_SIZE	32`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * Size of the smb3 encryption/decryption keys`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `#define SMB3_ENC_DEC_KEY_SIZE		32`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` * Size of the smb3 signing key`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `#define SMB3_SIGN_KEY_SIZE		16`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `#define CIFS_CLIENT_CHALLENGE_SIZE	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `#define SMB_SERVER_CHALLENGE_SIZE	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `/* SMB2 Max Credits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [PROTO_GATE|] `#define SMB2_MAX_CREDITS		8192`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [PROTO_GATE|] `#define SMB2_CLIENT_GUID_SIZE		16`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00105 [PROTO_GATE|] `#define SMB2_CREATE_GUID_SIZE		16`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `/* Maximum buffer size value we can send with 1 credit */`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [PROTO_GATE|] `#define SMB2_MAX_BUFFER_SIZE 65536`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [PROTO_GATE|] `#define NUMBER_OF_SMB2_COMMANDS	0x0013`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `/* BB FIXME - analyze following length BB */`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [PROTO_GATE|] `#define MAX_SMB2_HDR_SIZE 0x78 /* 4 len + 64 hdr + (2*24 wct) + 2 bct + 2 pad */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [PROTO_GATE|] `#define SMB2_PROTO_NUMBER cpu_to_le32(0x424d53fe) /* 'B''M''S' */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00116 [PROTO_GATE|] `#define SMB2_TRANSFORM_PROTO_NUM cpu_to_le32(0x424d53fd)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00117 [PROTO_GATE|] `#define SMB2_COMPRESSION_TRANSFORM_ID cpu_to_le32(0x424d53fc)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `#define SMB21_DEFAULT_IOSIZE	(1024 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `#define SMB3_DEFAULT_IOSIZE	(4 * 1024 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `#define SMB3_DEFAULT_TRANS_SIZE	(1024 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `#define SMB3_MIN_IOSIZE		(64 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `#define SMB3_MAX_IOSIZE		(8 * 1024 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `#define SMB3_MAX_MSGSIZE	(4 * 4096)`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ` * SMB2 Header Definition`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` * "MBZ" :  Must be Zero`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ` * "BB"  :  BugBug, Something to check/review/analyze later`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ` * "PDU" :  "Protocol Data Unit" (ie a network "frame")`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [PROTO_GATE|] `#define __SMB2_HEADER_STRUCTURE_SIZE	64`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00136 [PROTO_GATE|] `#define SMB2_HEADER_STRUCTURE_SIZE				\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00137 [PROTO_GATE|] `	cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `struct smb2_hdr {`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [PROTO_GATE|] `	__le32 ProtocolId;	/* 0xFE 'S' 'M' 'B' */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00141 [NONE] `	__le16 StructureSize;	/* 64 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [PROTO_GATE|] `	__le16 CreditCharge;	/* MBZ */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00143 [NONE] `	__le32 Status;		/* Error from server */`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	__le16 Command;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	__le16 CreditRequest;	/* CreditResponse */`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [PROTO_GATE|] `	__le32 NextCommand;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00148 [NONE] `	__le64 MessageId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	union {`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `		struct {`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `			__le32 ProcessId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `			__le32  TreeId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `		} __packed SyncId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `		__le64  AsyncId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	} __packed Id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	__le64  SessionId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	__u8   Signature[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `struct smb2_pdu {`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	__le16 StructureSize2; /* size of wct area (varies, request specific) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `#define SMB3_AES_CCM_NONCE 11`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `#define SMB3_AES_GCM_NONCE 12`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `#define SMB3_AES_GMAC_NONCE 12`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `struct smb2_transform_hdr {`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [PROTO_GATE|] `	__le32 ProtocolId;      /* 0xFD 'S' 'M' 'B' */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00171 [NONE] `	__u8   Signature[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	__u8   Nonce[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	__le32 OriginalMessageSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	__le16 Reserved1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	__le16 Flags; /* EncryptionAlgorithm */`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	__le64  SessionId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `/* SMB2 Transform header Flags field (MS-SMB2 §2.2.41) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [PROTO_GATE|] `#define SMB2_TRANSFORM_FLAG_ENCRYPTED		0x0001`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ` *	SMB2 flag definitions`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [PROTO_GATE|] `#define SMB2_FLAGS_SERVER_TO_REDIR	cpu_to_le32(0x00000001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00186 [PROTO_GATE|] `#define SMB2_FLAGS_ASYNC_COMMAND	cpu_to_le32(0x00000002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00187 [PROTO_GATE|] `#define SMB2_FLAGS_RELATED_OPERATIONS	cpu_to_le32(0x00000004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00188 [PROTO_GATE|] `#define SMB2_FLAGS_SIGNED		cpu_to_le32(0x00000008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00189 [PROTO_GATE|] `#define SMB2_FLAGS_DFS_OPERATIONS	cpu_to_le32(0x10000000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00190 [PROTO_GATE|] `#define SMB2_FLAGS_REPLAY_OPERATIONS	cpu_to_le32(0x20000000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00191 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ` *	Definitions for SMB2 Protocol Data Units (network frames)`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ` *  See MS-SMB2.PDF specification for protocol details.`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ` *  The Naming convention is the lower case version of the SMB2`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ` *  command code name for the struct. Note that structures must be packed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [PROTO_GATE|] `#define SMB2_ERROR_STRUCTURE_SIZE2	9`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00202 [PROTO_GATE|] `#define SMB2_ERROR_STRUCTURE_SIZE2_LE	cpu_to_le16(SMB2_ERROR_STRUCTURE_SIZE2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `struct smb2_err_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	__le16 StructureSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	__u8   ErrorContextCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	__le32 ByteCount;  /* even if zero, at least one byte follows */`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	__u8   ErrorData[];  /* variable length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `struct smb2_negotiate_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	__le16 StructureSize; /* Must be 36 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	__le16 DialectCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	__le16 SecurityMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	__le16 Reserved;	/* MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	__le32 Capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [PROTO_GATE|] `	__u8   ClientGUID[SMB2_CLIENT_GUID_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00221 [NONE] `	/* In SMB3.02 and earlier next three were MBZ le64 ClientStartTime */`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	__le32 NegotiateContextOffset; /* SMB3.1.1 only. MBZ earlier */`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	__le16 NegotiateContextCount;  /* SMB3.1.1 only. MBZ earlier */`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	__le16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	__le16 Dialects[]; /* One dialect (vers=) at a time for now */`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `/* SecurityMode flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [PROTO_GATE|] `#define SMB2_NEGOTIATE_SIGNING_ENABLED_LE	cpu_to_le16(0x0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00230 [PROTO_GATE|] `#define SMB2_NEGOTIATE_SIGNING_REQUIRED		0x0002`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00231 [PROTO_GATE|] `#define SMB2_NEGOTIATE_SIGNING_REQUIRED_LE	cpu_to_le16(0x0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00232 [NONE] `/* Capabilities flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [PROTO_GATE|] `#define SMB2_GLOBAL_CAP_DFS		0x00000001`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00234 [PROTO_GATE|] `#define SMB2_GLOBAL_CAP_LEASING		0x00000002 /* Resp only New to SMB2.1 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00235 [PROTO_GATE|] `#define SMB2_GLOBAL_CAP_LARGE_MTU	0x00000004 /* Resp only New to SMB2.1 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00236 [PROTO_GATE|] `#define SMB2_GLOBAL_CAP_MULTI_CHANNEL	0x00000008 /* New to SMB3 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00237 [PROTO_GATE|] `#define SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010 /* New to SMB3 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00238 [PROTO_GATE|] `#define SMB2_GLOBAL_CAP_DIRECTORY_LEASING  0x00000020 /* New to SMB3 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00239 [PROTO_GATE|] `#define SMB2_GLOBAL_CAP_ENCRYPTION	0x00000040 /* New to SMB3 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00240 [PROTO_GATE|] `#define SMB2_GLOBAL_CAP_NOTIFICATIONS	0x00000080 /* New to SMB3.1.1 (MS-SMB2 §2.2.4) */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00241 [NONE] `/* Internal types */`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [PROTO_GATE|] `#define SMB2_NT_FIND			0x00100000`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00243 [PROTO_GATE|] `#define SMB2_LARGE_FILES		0x00200000`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `#define SMB311_SALT_SIZE			32`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `/* Hash Algorithm Types */`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [PROTO_GATE|] `#define SMB2_PREAUTH_INTEGRITY_SHA512	cpu_to_le16(0x0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `#define PREAUTH_HASHVALUE_SIZE		64`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `struct preauth_integrity_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	/* PreAuth integrity Hash ID */`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	__le16			Preauth_HashId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	/* PreAuth integrity Hash Value */`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	__u8			Preauth_HashValue[PREAUTH_HASHVALUE_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `/* offset is sizeof smb2_negotiate_rsp but rounded up to 8 bytes. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `/* sizeof(struct smb2_negotiate_rsp) =`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] ` * header(64) + response(64) + GSS_LENGTH(96) + GSS_PADDING(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `#define OFFSET_OF_NEG_CONTEXT	0xe0`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [PROTO_GATE|] `#define SMB2_PREAUTH_INTEGRITY_CAPABILITIES	cpu_to_le16(1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00265 [PROTO_GATE|] `#define SMB2_ENCRYPTION_CAPABILITIES		cpu_to_le16(2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00266 [PROTO_GATE|] `#define SMB2_COMPRESSION_CAPABILITIES		cpu_to_le16(3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00267 [PROTO_GATE|] `#define SMB2_NETNAME_NEGOTIATE_CONTEXT_ID	cpu_to_le16(5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00268 [PROTO_GATE|] `#define SMB2_TRANSPORT_CAPABILITIES		cpu_to_le16(6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00269 [PROTO_GATE|] `#define SMB2_RDMA_TRANSFORM_CAPABILITIES	cpu_to_le16(7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00270 [PROTO_GATE|] `#define SMB2_SIGNING_CAPABILITIES		cpu_to_le16(8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00271 [PROTO_GATE|] `#define SMB2_POSIX_EXTENSIONS_AVAILABLE		cpu_to_le16(0x100)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00272 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `struct smb2_neg_context {`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	__le16  ContextType;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	__le16  DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	__le32  Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	/* Followed by array of data */`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ` * SaltLength that the server send can be zero, so the only three required`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] ` * fields (all __le16) end up six bytes total, so the minimum context data len`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ` * in the response is six bytes which accounts for`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] ` *      HashAlgorithmCount, SaltLength, and 1 HashAlgorithm.`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `#define MIN_PREAUTH_CTXT_DATA_LEN 6`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `struct smb2_preauth_neg_context {`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	__le16	ContextType; /* 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	__le16	DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	__le32	Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	__le16	HashAlgorithmCount; /* 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	__le16	SaltLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	__le16	HashAlgorithms; /* HashAlgorithms[0] since only one defined */`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	__u8	Salt[SMB311_SALT_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `/* Encryption Algorithms Ciphers */`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [PROTO_GATE|] `#define SMB2_ENCRYPTION_AES128_CCM	cpu_to_le16(0x0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00301 [PROTO_GATE|] `#define SMB2_ENCRYPTION_AES128_GCM	cpu_to_le16(0x0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00302 [PROTO_GATE|] `#define SMB2_ENCRYPTION_AES256_CCM	cpu_to_le16(0x0003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00303 [PROTO_GATE|] `#define SMB2_ENCRYPTION_AES256_GCM	cpu_to_le16(0x0004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00304 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `struct smb2_encryption_neg_context {`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	__le16	ContextType; /* 2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `	__le16	DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	__le32	Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	/* CipherCount usally 2, but can be 3 when AES256-GCM enabled */`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `	__le16	CipherCount; /* AES-128-GCM and AES-128-CCM by default */`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	__le16	Ciphers[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `#define SMB3_COMPRESS_NONE	cpu_to_le16(0x0000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `#define SMB3_COMPRESS_LZNT1	cpu_to_le16(0x0001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `#define SMB3_COMPRESS_LZ77	cpu_to_le16(0x0002)`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `#define SMB3_COMPRESS_LZ77_HUFF	cpu_to_le16(0x0003)`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `#define SMB3_COMPRESS_PATTERN_V1 cpu_to_le16(0x0004)`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ` * WARNING: SMB3_COMPRESS_LZ4 (0x0005) is NOT defined in the MS-SMB2`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ` * specification.  Value 0x0005 is unassigned in all known spec revisions.`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] ` * This constant MUST NOT be advertised to clients in a`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [PROTO_GATE|] ` * SMB2_COMPRESSION_CAPABILITIES negotiate context response, as doing so`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00324 [NONE] ` * would break interoperability with compliant Windows/Samba clients (which`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] ` * will never offer 0x0005).  If a future spec revision assigns 0x0005 to a`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ` * different algorithm, advertising LZ4 as 0x0005 would silently misidentify`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] ` * that algorithm.  Negotiate code (smb2_negotiate.c) MUST NOT include this`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] ` * value in the list of algorithms offered to clients.`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `#define SMB3_COMPRESS_LZ4	cpu_to_le16(0x0005) /* NON-SPEC: not in MS-SMB2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `struct smb2_compression_ctx {`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	__le16	ContextType; /* 3 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	__le16  DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `	__le32	Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `	__le16	CompressionAlgorithmCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `	__le16	Padding;`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `	__le32	Flags; /* MS-SMB2 2.2.3.1.3: 0 = no chaining, 1 = chained */`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	__le16	CompressionAlgorithms[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `/* SMB2 Compression Transform Header (MS-SMB2 2.2.42) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `struct smb2_compression_transform_hdr {`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [PROTO_GATE|] `	__le32 ProtocolId;        /* 0xFC534D42 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00345 [NONE] `	__le32 OriginalCompressedSegmentSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `	__le16 CompressionAlgorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	__le32 Offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `/* Chained compression payload header (MS-SMB2 2.2.42.1) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `struct smb2_compression_chained_payload_hdr {`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	__le16 CompressionAlgorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	__le32 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [PROTO_GATE|] `#define SMB2_COMPRESSION_FLAG_NONE	0x0000`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00359 [PROTO_GATE|] `#define SMB2_COMPRESSION_FLAG_CHAINED	0x0001`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `/* Minimum message size to consider for compression */`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [PROTO_GATE|] `#define SMB2_COMPRESSION_THRESHOLD	1024`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00363 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `#define POSIX_CTXT_DATA_LEN     16`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `struct smb2_posix_neg_context {`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	__le16	ContextType; /* 0x100 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	__le16	DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	__le32	Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	__u8	Name[16]; /* POSIX ctxt GUID 93AD25509CB411E7B42383DE968BCD7C */`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `struct smb2_netname_neg_context {`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	__le16	ContextType; /* 0x100 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	__le16	DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	__le32	Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `	__le16	NetName[]; /* hostname of target converted to UCS-2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `/* Signing algorithms */`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `#define SIGNING_ALG_HMAC_SHA256		cpu_to_le16(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `#define SIGNING_ALG_AES_CMAC		cpu_to_le16(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `#define SIGNING_ALG_AES_GMAC		cpu_to_le16(2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `/* RDMA Transform IDs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [PROTO_GATE|] `#define SMB2_RDMA_TRANSFORM_NONE	cpu_to_le16(0x0000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00386 [PROTO_GATE|] `#define SMB2_RDMA_TRANSFORM_ENCRYPTION	cpu_to_le16(0x0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00387 [PROTO_GATE|] `#define SMB2_RDMA_TRANSFORM_SIGNING	cpu_to_le16(0x0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00388 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `struct smb2_rdma_transform_capabilities {`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	__le16	ContextType; /* 7 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	__le16	DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	__le32	Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	__le16	TransformCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	__le16	Reserved1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	__le32	Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	__le16	RDMATransformIds[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `struct smb2_signing_capabilities {`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	__le16	ContextType; /* 8 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	__le16	DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	__le32	Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	__le16	SigningAlgorithmCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	__le16	SigningAlgorithms[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] ` * Transport Capabilities negotiate context [MS-SMB2] 2.2.3.1.6`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] ` * ContextType 0x0006: indicates transport-level encryption is in use`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] ` * (e.g., SMB over QUIC with TLS 1.3).  When present, the server may`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] ` * skip SMB-level encryption since the transport already provides it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [PROTO_GATE|] `#define SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY	cpu_to_le32(0x00000001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00414 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `struct smb2_transport_capabilities {`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	__le16	ContextType; /* 6 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	__le16	DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	__le32	Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [PROTO_GATE|] `	__le32	Flags;		/* SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00420 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `struct smb2_negotiate_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `	__le16 StructureSize;	/* Must be 65 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	__le16 SecurityMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	__le16 DialectRevision;`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	__le16 NegotiateContextCount; /* Prior to SMB3.1.1 was Reserved & MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	__u8   ServerGUID[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	__le32 Capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	__le32 MaxTransactSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	__le32 MaxReadSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	__le32 MaxWriteSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	__le64 SystemTime;	/* MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `	__le64 ServerStartTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	__le16 SecurityBufferOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	__le16 SecurityBufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	__le32 NegotiateContextOffset;	/* Pre:SMB3.1.1 was reserved/ignored */`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	__u8   Buffer[];	/* variable length GSS security buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `/* Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [PROTO_GATE|] `#define SMB2_SESSION_REQ_FLAG_BINDING		0x01`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00443 [PROTO_GATE|] `#define SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA	0x04`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [PROTO_GATE|] `#define SMB2_SESSION_EXPIRED		(0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00446 [PROTO_GATE|] `#define SMB2_SESSION_IN_PROGRESS	BIT(0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00447 [PROTO_GATE|] `#define SMB2_SESSION_VALID		BIT(1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00448 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [PROTO_GATE|] `#define SMB2_SESSION_TIMEOUT		(10 * HZ)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00450 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `struct smb2_sess_setup_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	__le16 StructureSize; /* Must be 25 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	__u8   Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	__u8   SecurityMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	__le32 Capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `	__le32 Channel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	__le16 SecurityBufferOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	__le16 SecurityBufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `	__le64 PreviousSessionId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `	__u8   Buffer[];	/* variable length GSS security buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `/* Flags/Reserved for SMB3.1.1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [PROTO_GATE|] `#define SMB2_SHAREFLAG_CLUSTER_RECONNECT	0x0001`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00466 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `/* Currently defined SessionFlags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [PROTO_GATE|] `#define SMB2_SESSION_FLAG_IS_GUEST_LE		cpu_to_le16(0x0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00469 [PROTO_GATE|] `#define SMB2_SESSION_FLAG_IS_NULL_LE		cpu_to_le16(0x0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00470 [PROTO_GATE|] `#define SMB2_SESSION_FLAG_ENCRYPT_DATA_LE	cpu_to_le16(0x0004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00471 [NONE] `struct smb2_sess_setup_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	__le16 StructureSize; /* Must be 9 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	__le16 SessionFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `	__le16 SecurityBufferOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	__le16 SecurityBufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	__u8   Buffer[];	/* variable length GSS security buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `struct smb2_logoff_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	__le16 StructureSize;	/* Must be 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `struct smb2_logoff_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	__le16 StructureSize;	/* Must be 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `struct smb2_tree_connect_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	__le16 StructureSize;	/* Must be 9 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	__le16 Reserved;	/* Flags in SMB3.1.1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	__le16 PathOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	__le16 PathLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	__u8   Buffer[];	/* variable length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `struct smb2_tree_connect_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	__le16 StructureSize;	/* Must be 16 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	__u8   ShareType;  /* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	__le32 ShareFlags; /* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	__le32 Capabilities; /* see below */`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	__le32 MaximalAccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `/* SMB 3.1.1 TREE_CONNECT Flags (overloads Reserved field, MS-SMB2 §2.2.9) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [PROTO_GATE|] `#define SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT	cpu_to_le16(0x0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00513 [PROTO_GATE|] `#define SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER	cpu_to_le16(0x0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00514 [PROTO_GATE|] `#define SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT	cpu_to_le16(0x0004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00515 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `/* Possible ShareType values */`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [PROTO_GATE|] `#define SMB2_SHARE_TYPE_DISK	0x01`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00518 [PROTO_GATE|] `#define SMB2_SHARE_TYPE_PIPE	0x02`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00519 [PROTO_GATE|] `#define	SMB2_SHARE_TYPE_PRINT	0x03`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00520 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] ` * Possible ShareFlags - exactly one and only one of the first 4 caching flags`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ` * must be set (any of the remaining, SHI1005, flags may be set individually`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ` * or in combination.`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [PROTO_GATE|] `#define SMB2_SHAREFLAG_MANUAL_CACHING			0x00000000`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00527 [PROTO_GATE|] `#define SMB2_SHAREFLAG_AUTO_CACHING			0x00000010`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00528 [PROTO_GATE|] `#define SMB2_SHAREFLAG_VDO_CACHING			0x00000020`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00529 [PROTO_GATE|] `#define SMB2_SHAREFLAG_NO_CACHING			0x00000030`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00530 [NONE] `#define SHI1005_FLAGS_DFS				0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `#define SHI1005_FLAGS_DFS_ROOT				0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `#define SHI1005_FLAGS_RESTRICT_EXCLUSIVE_OPENS		0x00000100`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `#define SHI1005_FLAGS_FORCE_SHARED_DELETE		0x00000200`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `#define SHI1005_FLAGS_ALLOW_NAMESPACE_CACHING		0x00000400`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `#define SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM	0x00000800`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `#define SHI1005_FLAGS_FORCE_LEVELII_OPLOCK		0x00001000`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `#define SHI1005_FLAGS_ENABLE_HASH			0x00002000`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `/* Possible share capabilities */`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [PROTO_GATE|] `#define SMB2_SHARE_CAP_DFS cpu_to_le32(0x00000008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00541 [PROTO_GATE|] `#define SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY cpu_to_le32(0x00000010) /* 3.0 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00542 [PROTO_GATE|] `#define SMB2_SHARE_CAP_SCALEOUT cpu_to_le32(0x00000020) /* 3.0 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00543 [PROTO_GATE|] `#define SMB2_SHARE_CAP_CLUSTER cpu_to_le32(0x00000040) /* 3.0 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00544 [PROTO_GATE|] `#define SMB2_SHARE_CAP_ASYMMETRIC cpu_to_le32(0x00000080) /* 3.02 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00545 [PROTO_GATE|] `#define SMB2_SHARE_CAP_REDIRECT_TO_OWNER cpu_to_le32(0x00000100) /* 3.1.1 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `struct smb2_tree_disconnect_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	__le16 StructureSize;	/* Must be 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `struct smb2_tree_disconnect_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	__le16 StructureSize;	/* Must be 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `#define ATTR_READONLY_LE	cpu_to_le32(ATTR_READONLY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `#define ATTR_HIDDEN_LE		cpu_to_le32(ATTR_HIDDEN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `#define ATTR_SYSTEM_LE		cpu_to_le32(ATTR_SYSTEM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `#define ATTR_DIRECTORY_LE	cpu_to_le32(ATTR_DIRECTORY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `#define ATTR_ARCHIVE_LE		cpu_to_le32(ATTR_ARCHIVE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `#define ATTR_NORMAL_LE		cpu_to_le32(ATTR_NORMAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `#define ATTR_TEMPORARY_LE	cpu_to_le32(ATTR_TEMPORARY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `#define ATTR_SPARSE_FILE_LE	cpu_to_le32(ATTR_SPARSE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `#define ATTR_REPARSE_POINT_LE	cpu_to_le32(ATTR_REPARSE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `#define ATTR_COMPRESSED_LE	cpu_to_le32(ATTR_COMPRESSED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `#define ATTR_OFFLINE_LE		cpu_to_le32(ATTR_OFFLINE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `#define ATTR_NOT_CONTENT_INDEXED_LE	cpu_to_le32(ATTR_NOT_CONTENT_INDEXED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `#define ATTR_ENCRYPTED_LE	cpu_to_le32(ATTR_ENCRYPTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `#define ATTR_INTEGRITY_STREAML_LE	cpu_to_le32(0x00008000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `#define ATTR_NO_SCRUB_DATA_LE	cpu_to_le32(0x00020000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `#define ATTR_MASK_LE		cpu_to_le32(0x00007FB7)`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `/* Oplock levels */`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [PROTO_GATE|] `#define SMB2_OPLOCK_LEVEL_NONE		0x00`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00578 [PROTO_GATE|] `#define SMB2_OPLOCK_LEVEL_II		0x01`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00579 [PROTO_GATE|] `#define SMB2_OPLOCK_LEVEL_EXCLUSIVE	0x08`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00580 [PROTO_GATE|] `#define SMB2_OPLOCK_LEVEL_BATCH		0x09`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00581 [PROTO_GATE|] `#define SMB2_OPLOCK_LEVEL_LEASE		0xFF`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00582 [NONE] `/* Non-spec internal type */`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [PROTO_GATE|] `#define SMB2_OPLOCK_LEVEL_NOCHANGE	0x99`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00584 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `/* Desired Access Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `#define FILE_READ_DATA_LE		cpu_to_le32(0x00000001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `#define FILE_LIST_DIRECTORY_LE		cpu_to_le32(0x00000001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `#define FILE_WRITE_DATA_LE		cpu_to_le32(0x00000002)`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `#define FILE_ADD_FILE_LE		cpu_to_le32(0x00000002)`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `#define FILE_APPEND_DATA_LE		cpu_to_le32(0x00000004)`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `#define FILE_ADD_SUBDIRECTORY_LE	cpu_to_le32(0x00000004)`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `#define FILE_READ_EA_LE			cpu_to_le32(0x00000008)`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `#define FILE_WRITE_EA_LE		cpu_to_le32(0x00000010)`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `#define FILE_EXECUTE_LE			cpu_to_le32(0x00000020)`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `#define FILE_TRAVERSE_LE		cpu_to_le32(0x00000020)`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `#define FILE_DELETE_CHILD_LE		cpu_to_le32(0x00000040)`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `#define FILE_READ_ATTRIBUTES_LE		cpu_to_le32(0x00000080)`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `#define FILE_WRITE_ATTRIBUTES_LE	cpu_to_le32(0x00000100)`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `#define FILE_DELETE_LE			cpu_to_le32(0x00010000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `#define FILE_READ_CONTROL_LE		cpu_to_le32(0x00020000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `#define FILE_WRITE_DAC_LE		cpu_to_le32(0x00040000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `#define FILE_WRITE_OWNER_LE		cpu_to_le32(0x00080000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `#define FILE_SYNCHRONIZE_LE		cpu_to_le32(0x00100000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `#define FILE_ACCESS_SYSTEM_SECURITY_LE	cpu_to_le32(0x01000000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `#define FILE_MAXIMAL_ACCESS_LE		cpu_to_le32(0x02000000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `#define FILE_GENERIC_ALL_LE		cpu_to_le32(0x10000000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `#define FILE_GENERIC_EXECUTE_LE		cpu_to_le32(0x20000000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `#define FILE_GENERIC_WRITE_LE		cpu_to_le32(0x40000000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `#define FILE_GENERIC_READ_LE		cpu_to_le32(0x80000000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `#define DESIRED_ACCESS_MASK		cpu_to_le32(0xF21F01FF)`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `/* ShareAccess Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `#define FILE_SHARE_READ_LE		cpu_to_le32(0x00000001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `#define FILE_SHARE_WRITE_LE		cpu_to_le32(0x00000002)`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `#define FILE_SHARE_DELETE_LE		cpu_to_le32(0x00000004)`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `#define FILE_SHARE_ALL_LE		cpu_to_le32(0x00000007)`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `/* CreateDisposition Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `#define FILE_SUPERSEDE_LE		cpu_to_le32(0x00000000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `#define FILE_OPEN_LE			cpu_to_le32(0x00000001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `#define FILE_CREATE_LE			cpu_to_le32(0x00000002)`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `#define	FILE_OPEN_IF_LE			cpu_to_le32(0x00000003)`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `#define FILE_OVERWRITE_LE		cpu_to_le32(0x00000004)`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `#define FILE_OVERWRITE_IF_LE		cpu_to_le32(0x00000005)`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `#define FILE_CREATE_MASK_LE		cpu_to_le32(0x00000007)`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `#define FILE_READ_DESIRED_ACCESS_LE	(FILE_READ_DATA_LE |		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `					FILE_READ_EA_LE |		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `					FILE_GENERIC_READ_LE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `#define FILE_WRITE_DESIRE_ACCESS_LE	(FILE_WRITE_DATA_LE |		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `					FILE_APPEND_DATA_LE |		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `					FILE_WRITE_EA_LE |		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `					FILE_WRITE_ATTRIBUTES_LE |	\`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `					FILE_GENERIC_WRITE_LE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `/* Impersonation Levels */`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `#define IL_ANONYMOUS_LE		cpu_to_le32(0x00000000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `#define IL_IDENTIFICATION_LE	cpu_to_le32(0x00000001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `#define IL_IMPERSONATION_LE	cpu_to_le32(0x00000002)`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `#define IL_DELEGATE_LE		cpu_to_le32(0x00000003)`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `/* Create Context Values */`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [PROTO_GATE|] `#define SMB2_CREATE_EA_BUFFER			"ExtA" /* extended attributes */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00644 [PROTO_GATE|] `#define SMB2_CREATE_SD_BUFFER			"SecD" /* security descriptor */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00645 [PROTO_GATE|] `#define SMB2_CREATE_DURABLE_HANDLE_REQUEST	"DHnQ"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00646 [PROTO_GATE|] `#define SMB2_CREATE_DURABLE_HANDLE_RECONNECT	"DHnC"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00647 [PROTO_GATE|] `#define SMB2_CREATE_ALLOCATION_SIZE		"AlSi"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00648 [PROTO_GATE|] `#define SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST "MxAc"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00649 [PROTO_GATE|] `#define SMB2_CREATE_TIMEWARP_REQUEST		"TWrp"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00650 [PROTO_GATE|] `#define SMB2_CREATE_QUERY_ON_DISK_ID		"QFid"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00651 [PROTO_GATE|] `#define SMB2_CREATE_REQUEST_LEASE		"RqLs"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00652 [PROTO_GATE|] `#define SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2   "DH2Q"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00653 [PROTO_GATE|] `#define SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 "DH2C"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00654 [PROTO_GATE|] `#define SMB2_CREATE_APP_INSTANCE_ID     "\x45\xBC\xA6\x6A\xEF\xA7\xF7\x4A\x90\x08\xFA\x46\x2E\x14\x4D\x74"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00655 [PROTO_GATE|] ` #define SMB2_CREATE_APP_INSTANCE_VERSION	"\xB9\x82\xD0\xB7\x3B\x56\x07\x4F\xA0\x7B\x52\x4A\x81\x16\xA0\x10"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00656 [NONE] `#define SVHDX_OPEN_DEVICE_CONTEXT       0x83CE6F1AD851E0986E34401CC9BCFCE9`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [PROTO_GATE|] `#define SMB2_CREATE_TAG_POSIX		"\x93\xAD\x25\x50\x9C\xB4\x11\xE7\xB4\x23\x83\xDE\x96\x8B\xCD\x7C"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00658 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `/* Fruit Defined Contexts - wire value must remain "AAPL" */`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [PROTO_GATE|] `#define	SMB2_CREATE_AAPL			"AAPL"`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00661 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] ` * Note: LookerInfo and Save box are negotiated within the Fruit`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] ` * create context data, not as separate create contexts.`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `struct smb2_create_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	__le16 StructureSize;	/* Must be 57 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `	__u8   SecurityFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `	__u8   RequestedOplockLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `	__le32 ImpersonationLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	__le64 SmbCreateFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `	__le64 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	__le32 DesiredAccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	__le32 FileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	__le32 ShareAccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `	__le32 CreateDisposition;`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `	__le32 CreateOptions;`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	__le16 NameOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `	__le16 NameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	__le32 CreateContextsOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `	__le32 CreateContextsLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `struct smb2_create_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `	__le16 StructureSize;	/* Must be 89 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `	__u8   OplockLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `	__le32 CreateAction;`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `	__le64 EndofFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `	__le32 FileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `	__le32 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `	__le32 CreateContextsOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `	__le32 CreateContextsLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `struct create_context {`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `	__le32 Next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `	__le16 NameOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	__le16 NameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	__le16 DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `	__le32 DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	__u8 Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `struct create_durable_req_v2 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `	__u8 Reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `	__u8 CreateGuid[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `#define DURABLE_HANDLE_MAX_TIMEOUT	300000`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `struct create_durable_reconn_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `	union {`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `		__u8  Reserved[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `		struct {`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `			__u64 PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `			__u64 VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `		} Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	} Data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `struct create_durable_reconn_v2_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `	struct {`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `		__u64 PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `		__u64 VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `	} Fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `	__u8 CreateGuid[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `struct create_app_inst_id {`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `	__u8 Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `	__u8 Reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	__u8 AppInstanceId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `struct create_app_inst_id_vers {`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	__u8 Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `	__u8 Reserved[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `	__u8 Padding[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `	__le64 AppInstanceVersionHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `	__le64 AppInstanceVersionLow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `struct create_mxac_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `	__le64 Timestamp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `struct create_alloc_size_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `struct create_posix {`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `	__u8    Name[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `	__le32  Mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `	__le32  Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `struct create_durable_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `	union {`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `		__u8  Reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `		__u64 data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `	} Data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `/* See MS-SMB2 2.2.13.2.11 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `/* Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [PROTO_GATE|] `#define SMB2_DHANDLE_FLAG_PERSISTENT	0x00000002`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00798 [NONE] `struct create_durable_v2_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `	__le32 Timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `struct create_mxac_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `	__le32 QueryStatus;`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `	__le32 MaximalAccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `struct create_disk_id_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `	__le64 DiskFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `	__le64 VolumeId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `	__u8  Reserved[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `/* equivalent of the contents of SMB3.1.1 POSIX open context response */`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `struct create_posix_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `	__u8    Name[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `	__le32 nlink;`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `	__le32 reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `	__le32 mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `	/* SidBuffer contain two sids(Domain sid(28), UNIX group sid(16)) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `	u8 SidBuffer[44];`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `/* Fruit SMB Extension Create Context Structures */`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `struct create_fruit_server_query_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	__u8   Name[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `	struct fruit_server_query query;`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `struct create_fruit_server_query_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `	__u8   Name[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `	__le32 response_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `	__u8   response_data[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `struct create_fruit_volume_caps_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `	__u8   Name[20];`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `	__le32 reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `struct create_fruit_volume_caps_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `	__u8   Name[20];`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `	struct fruit_volume_capabilities capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `struct create_fruit_file_mode_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `	__u8   Name[12];`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `	struct fruit_file_mode file_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `struct create_fruit_file_mode_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `	__u8   Name[12];`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `	struct fruit_file_mode file_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `struct create_fruit_dir_hardlinks_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `	__u8   Name[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `	__le32 reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `struct create_fruit_dir_hardlinks_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `	__u8   Name[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `	struct fruit_dir_hardlinks hardlinks;`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] ` * Fruit create context response — variable-length.`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] ` * reply_bitmap=0x07 means: server_caps + volume_caps + model_info.`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] ` * The model string is variable-length UTF-16LE, so we use a`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] ` * flexible array member. Total size is computed at runtime via`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] ` * fruit_rsp_size().`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `struct create_fruit_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `	__u8   Name[4];		/* "AAPL" on wire */`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `	__le32 command_code;	/* 1 = kAAPL_SERVER_QUERY */`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `	__le32 reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `	__le64 reply_bitmap;	/* 0x07 = caps + volcaps + model */`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `	__le64 server_caps;	/* kAAPL_* capability bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `	__le64 volume_caps;	/* kAAPL_SUPPORT_* volume bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `	__le32 model_string_len; /* UTF-16LE byte count of model[] */`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `	__le16 model[];		/* UTF-16LE model string, no NUL */`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [PROTO_GATE|] `#define SMB2_LEASE_NONE_LE			cpu_to_le32(0x00)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00902 [PROTO_GATE|] `#define SMB2_LEASE_READ_CACHING_LE		cpu_to_le32(0x01)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00903 [PROTO_GATE|] `#define SMB2_LEASE_HANDLE_CACHING_LE		cpu_to_le32(0x02)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00904 [PROTO_GATE|] `#define SMB2_LEASE_WRITE_CACHING_LE		cpu_to_le32(0x04)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00905 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [PROTO_GATE|] `#define SMB2_LEASE_FLAG_BREAK_IN_PROGRESS_LE	cpu_to_le32(0x02)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00907 [PROTO_GATE|] `#define SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE	cpu_to_le32(0x04)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00908 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [PROTO_GATE|] `#define SMB2_LEASE_KEY_SIZE			16`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00910 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `struct lease_context {`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [PROTO_GATE|] `	__u8 LeaseKey[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00913 [NONE] `	__le32 LeaseState;`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `	__le32 LeaseFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	__le64 LeaseDuration;`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `struct lease_context_v2 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [PROTO_GATE|] `	__u8 LeaseKey[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00920 [NONE] `	__le32 LeaseState;`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `	__le32 LeaseFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `	__le64 LeaseDuration;`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [PROTO_GATE|] `	__u8 ParentLeaseKey[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00924 [NONE] `	__le16 Epoch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `struct create_lease {`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `	struct lease_context lcontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `struct create_lease_v2 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	struct lease_context_v2 lcontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	__u8   Pad[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `/* Currently defined values for close flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [PROTO_GATE|] `#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB	cpu_to_le16(0x0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00943 [NONE] `struct smb2_close_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	__le16 StructureSize;	/* Must be 24 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `struct smb2_close_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	__le16 StructureSize; /* 60 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `	__le64 AllocationSize;	/* Beginning of FILE_STANDARD_INFO equivalent */`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `	__le32 Attributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `struct smb2_flush_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `	__le16 StructureSize;	/* Must be 24 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `	__le16 Reserved1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	__le32 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `struct smb2_flush_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `	__le16 StructureSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `struct smb2_buffer_desc_v1 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `	__le64 offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `	__le32 token;`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `	__le32 length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [PROTO_GATE|] `#define SMB2_CHANNEL_NONE		cpu_to_le32(0x00000000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00988 [PROTO_GATE|] `#define SMB2_CHANNEL_RDMA_V1		cpu_to_le32(0x00000001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00989 [PROTO_GATE|] `#define SMB2_CHANNEL_RDMA_V1_INVALIDATE cpu_to_le32(0x00000002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00990 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `struct smb2_read_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `	__le16 StructureSize; /* Must be 49 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	__u8   Padding; /* offset from start of SMB2 header to place read */`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `	__le32 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `	__le64 Offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `	__le32 MinimumCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `	__le32 Channel; /* Reserved MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `	__le32 RemainingBytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `	__le16 ReadChannelInfoOffset; /* Reserved MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `	__le16 ReadChannelInfoLength; /* Reserved MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `struct smb2_read_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `	__le16 StructureSize; /* Must be 17 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `	__u8   DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `	__le32 DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `	__le32 DataRemaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `	__le32 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `/* SMB2 READ Flags (MS-SMB2 §2.2.19) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [PROTO_GATE|] `#define SMB2_READFLAG_READ_UNBUFFERED              0x00000001`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01021 [PROTO_GATE|] `#define SMB2_READFLAG_READ_COMPRESSED              0x00000002`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01022 [PROTO_GATE|] `#define SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION 0x00000004`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `/* For write request Flags field (MS-SMB2 §2.2.21) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [PROTO_GATE|] `#define SMB2_WRITEFLAG_WRITE_THROUGH               0x00000001`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01026 [PROTO_GATE|] `#define SMB2_WRITEFLAG_WRITE_UNBUFFERED            0x00000002`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01027 [PROTO_GATE|] `#define SMB2_WRITEFLAG_REQUEST_TRANSPORT_ENCRYPTION 0x00000004`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `struct smb2_write_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `	__le16 StructureSize; /* Must be 49 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `	__le16 DataOffset; /* offset from start of SMB2 header to write data */`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `	__le32 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `	__le64 Offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `	__le32 Channel; /* Reserved MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `	__le32 RemainingBytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `	__le16 WriteChannelInfoOffset; /* Reserved MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `	__le16 WriteChannelInfoLength; /* Reserved MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `struct smb2_write_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `	__le16 StructureSize; /* Must be 17 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `	__u8   DataOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `	__le32 DataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] `	__le32 DataRemaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] `	__le32 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [PROTO_GATE|] `#define SMB2_0_IOCTL_IS_FSCTL 0x00000001`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `struct duplicate_extents_to_file {`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `	__u64 PersistentFileHandle; /* source file handle, opaque endianness */`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `	__u64 VolatileFileHandle;`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	__le64 SourceFileOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `	__le64 TargetFileOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `	__le64 ByteCount;  /* Bytes to be copied */`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `struct smb2_ioctl_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `	__le16 StructureSize; /* Must be 57 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `	__le16 Reserved; /* offset from start of SMB2 header to write data */`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `	__le32 CntCode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `	__le32 InputOffset; /* Reserved MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `	__le32 InputCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `	__le32 MaxInputResponse;`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `	__le32 OutputOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `	__le32 OutputCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `	__le32 MaxOutputResponse;`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `	__le32 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `struct smb2_ioctl_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `	__le16 StructureSize; /* Must be 49 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `	__le16 Reserved; /* offset from start of SMB2 header to write data */`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `	__le32 CntCode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `	__le32 InputOffset; /* Reserved MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `	__le32 InputCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `	__le32 OutputOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `	__le32 OutputCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `	__le32 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `struct validate_negotiate_info_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `	__le32 Capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [PROTO_GATE|] `	__u8   Guid[SMB2_CLIENT_GUID_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01103 [NONE] `	__le16 SecurityMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `	__le16 DialectCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `	__le16 Dialects[1]; /* dialect (someday maybe list) client asked for */`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `struct validate_negotiate_info_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `	__le32 Capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [PROTO_GATE|] `	__u8   Guid[SMB2_CLIENT_GUID_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01111 [NONE] `	__le16 SecurityMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `	__le16 Dialect; /* Dialect in use for the connection */`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `struct smb_sockaddr_in {`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `	__be16 Port;`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `	__be32 IPv4address;`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `	__u8 Reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `struct smb_sockaddr_in6 {`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `	__be16 Port;`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `	__be32 FlowInfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `	__u8 IPv6address[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	__be32 ScopeId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `#define INTERNETWORK	0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `#define INTERNETWORKV6	0x0017`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `struct sockaddr_storage_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `	__le16 Family;`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `	union {`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `		struct smb_sockaddr_in addr4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `		struct smb_sockaddr_in6 addr6;`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `	};`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `#define RSS_CAPABLE	0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `#define RDMA_CAPABLE	0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `struct network_interface_info_ioctl_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `	__le32 Next; /* next interface. zero if this is last one */`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `	__le32 IfIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `	__le32 Capability; /* RSS or RDMA Capable */`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `	__le64 LinkSpeed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `	char	SockAddr_Storage[128];`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `struct file_object_buf_type1_ioctl_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `	__u8 ObjectId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `	__u8 BirthVolumeId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `	__u8 BirthObjectId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `	__u8 DomainId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `struct resume_key_ioctl_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `	__le64 ResumeKey[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `	__le32 ContextLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `	__u8 Context[4]; /* ignored, Windows sets to 4 bytes of zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `struct copychunk_ioctl_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `	__le64 ResumeKey[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `	__le32 ChunkCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `	__u8 Chunks[]; /* array of srv_copychunk */`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `struct srv_copychunk {`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `	__le64 SourceOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `	__le64 TargetOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `	__le32 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `struct copychunk_ioctl_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] `	__le32 ChunksWritten;`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `	__le32 ChunkBytesWritten;`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] `	__le32 TotalBytesWritten;`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `struct file_sparse {`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	__u8	SetSparse;`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `struct file_zero_data_information {`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `	__le64	FileOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `	__le64	BeyondFinalZero;`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `struct file_allocated_range_buffer {`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] `	__le64	file_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] `	__le64	length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `struct reparse_data_buffer {`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `	__le32	ReparseTag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `	__le16	ReparseDataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `	__u16	Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `	__u8	DataBuffer[]; /* Variable Length */`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `/* Completion Filter flags for Notify */`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `#define FILE_NOTIFY_CHANGE_FILE_NAME	0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `#define FILE_NOTIFY_CHANGE_DIR_NAME	0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `#define FILE_NOTIFY_CHANGE_NAME		0x00000003`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `#define FILE_NOTIFY_CHANGE_ATTRIBUTES	0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `#define FILE_NOTIFY_CHANGE_SIZE		0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `#define FILE_NOTIFY_CHANGE_LAST_WRITE	0x00000010`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `#define FILE_NOTIFY_CHANGE_LAST_ACCESS	0x00000020`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `#define FILE_NOTIFY_CHANGE_CREATION	0x00000040`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `#define FILE_NOTIFY_CHANGE_EA		0x00000080`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `#define FILE_NOTIFY_CHANGE_SECURITY	0x00000100`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `#define FILE_NOTIFY_CHANGE_STREAM_NAME	0x00000200`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `#define FILE_NOTIFY_CHANGE_STREAM_SIZE	0x00000400`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `#define FILE_NOTIFY_CHANGE_STREAM_WRITE	0x00000800`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `/* Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [PROTO_GATE|] `#define SMB2_WATCH_TREE	0x0001`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `struct smb2_notify_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	__le16 StructureSize; /* Must be 32 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `	__le16 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `	__le32 OutputBufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `	__u64 PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `	__u64 VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `	__le32 CompletionFilter;`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `struct smb2_notify_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `	__le16 StructureSize; /* Must be 9 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] `	__le16 OutputBufferOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `	__le32 OutputBufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `	__u8 Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `/* SMB2 Notify Action Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `#define FILE_ACTION_ADDED		0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `#define FILE_ACTION_REMOVED		0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `#define FILE_ACTION_MODIFIED		0x00000003`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `#define FILE_ACTION_RENAMED_OLD_NAME	0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] `#define FILE_ACTION_RENAMED_NEW_NAME	0x00000005`
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `#define FILE_ACTION_ADDED_STREAM	0x00000006`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `#define FILE_ACTION_REMOVED_STREAM	0x00000007`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `#define FILE_ACTION_MODIFIED_STREAM	0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `#define FILE_ACTION_REMOVED_BY_DELETE	0x00000009`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [PROTO_GATE|] `#define SMB2_LOCKFLAG_SHARED		0x0001`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01254 [PROTO_GATE|] `#define SMB2_LOCKFLAG_EXCLUSIVE		0x0002`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01255 [PROTO_GATE|] `#define SMB2_LOCKFLAG_UNLOCK		0x0004`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01256 [PROTO_GATE|] `#define SMB2_LOCKFLAG_FAIL_IMMEDIATELY	0x0010`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01257 [PROTO_GATE|] `#define SMB2_LOCKFLAG_MASK		(SMB2_LOCKFLAG_SHARED | \`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01258 [PROTO_GATE|] `					 SMB2_LOCKFLAG_EXCLUSIVE | \`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01259 [PROTO_GATE|] `					 SMB2_LOCKFLAG_UNLOCK | \`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01260 [PROTO_GATE|] `					 SMB2_LOCKFLAG_FAIL_IMMEDIATELY)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `struct smb2_lock_element {`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `	__le64 Offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `	__le64 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `struct smb2_lock_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `	__le16 StructureSize; /* Must be 48 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `	__le16 LockCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `	 * Per MS-SMB2 3.3.5.14:`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `	 * Bits 28-31: LockSequenceNumber (4 bits)`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `	 * Bits 24-27: LockSequenceIndex (4 bits)`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `	 * Bits 0-23: Reserved`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `	__le32 LockSequenceNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `	/* Followed by at least one */`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] `	struct smb2_lock_element locks[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `struct smb2_lock_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `	__le16 StructureSize; /* Must be 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `struct smb2_echo_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `	__le16 StructureSize;	/* Must be 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `struct smb2_echo_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `	__le16 StructureSize;	/* Must be 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `/* search (query_directory) Flags field */`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [PROTO_GATE|] `#define SMB2_RESTART_SCANS		0x01`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01306 [PROTO_GATE|] `#define SMB2_RETURN_SINGLE_ENTRY	0x02`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01307 [PROTO_GATE|] `#define SMB2_INDEX_SPECIFIED		0x04`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01308 [PROTO_GATE|] `#define SMB2_REOPEN			0x10`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `struct smb2_query_directory_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `	__le16 StructureSize; /* Must be 33 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `	__u8   FileInformationClass;`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `	__u8   Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `	__le32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `	__le16 FileNameOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] `	__le16 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `	__le32 OutputBufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `struct smb2_query_directory_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `	__le16 StructureSize; /* Must be 9 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `	__le16 OutputBufferOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `	__le32 OutputBufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] `/* Possible InfoType values */`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [PROTO_GATE|] `#define SMB2_O_INFO_FILE	0x01`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01334 [PROTO_GATE|] `#define SMB2_O_INFO_FILESYSTEM	0x02`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01335 [PROTO_GATE|] `#define SMB2_O_INFO_SECURITY	0x03`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01336 [PROTO_GATE|] `#define SMB2_O_INFO_QUOTA	0x04`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] `/* Security info type additionalinfo flags. See MS-SMB2 (2.2.37) or MS-DTYP */`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] `#define OWNER_SECINFO   0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] `#define GROUP_SECINFO   0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `#define DACL_SECINFO   0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `#define SACL_SECINFO   0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `#define LABEL_SECINFO   0x00000010`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `#define ATTRIBUTE_SECINFO   0x00000020`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `#define SCOPE_SECINFO   0x00000040`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `#define BACKUP_SECINFO   0x00010000`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `#define UNPROTECTED_SACL_SECINFO   0x10000000`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `#define UNPROTECTED_DACL_SECINFO   0x20000000`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `#define PROTECTED_SACL_SECINFO   0x40000000`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `#define PROTECTED_DACL_SECINFO   0x80000000`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] `struct smb2_query_info_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `	__le16 StructureSize; /* Must be 41 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `	__u8   InfoType;`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `	__u8   FileInfoClass;`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `	__le32 OutputBufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `	__le16 InputBufferOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `	__u16  Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `	__le32 InputBufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `	__le32 AdditionalInformation;`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `struct smb2_query_info_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `	__le16 StructureSize; /* Must be 9 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] `	__le16 OutputBufferOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `	__le32 OutputBufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `struct smb2_set_info_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `	__le16 StructureSize; /* Must be 33 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `	__u8   InfoType;`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] `	__u8   FileInfoClass;`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `	__le32 BufferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `	__le16 BufferOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `	__u16  Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `	__le32 AdditionalInformation;`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `	__u64  PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] `	__u64  VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `	__u8   Buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `struct smb2_set_info_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] `	__le16 StructureSize; /* Must be 2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `/* FILE Info response size */`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] `#define FILE_DIRECTORY_INFORMATION_SIZE       1`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] `#define FILE_FULL_DIRECTORY_INFORMATION_SIZE  2`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] `#define FILE_BOTH_DIRECTORY_INFORMATION_SIZE  3`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] `#define FILE_BASIC_INFORMATION_SIZE           40`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `#define FILE_STANDARD_INFORMATION_SIZE        24`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `#define FILE_INTERNAL_INFORMATION_SIZE        8`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `#define FILE_EA_INFORMATION_SIZE              4`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] `#define FILE_ACCESS_INFORMATION_SIZE          4`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] `#define FILE_NAME_INFORMATION_SIZE            9`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] `#define FILE_RENAME_INFORMATION_SIZE          10`
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `#define FILE_LINK_INFORMATION_SIZE            11`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `#define FILE_NAMES_INFORMATION_SIZE           12`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] `#define FILE_DISPOSITION_INFORMATION_SIZE     13`
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `#define FILE_POSITION_INFORMATION_SIZE        14`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] `#define FILE_FULL_EA_INFORMATION_SIZE         15`
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `#define FILE_MODE_INFORMATION_SIZE            4`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `#define FILE_ALIGNMENT_INFORMATION_SIZE       4`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `#define FILE_ALL_INFORMATION_SIZE             104`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `#define FILE_ALLOCATION_INFORMATION_SIZE      19`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] `#define FILE_END_OF_FILE_INFORMATION_SIZE     20`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `#define FILE_ALTERNATE_NAME_INFORMATION_SIZE  8`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `#define FILE_STREAM_INFORMATION_SIZE          32`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `#define FILE_PIPE_INFORMATION_SIZE            23`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] `#define FILE_PIPE_LOCAL_INFORMATION_SIZE      24`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] `#define FILE_PIPE_REMOTE_INFORMATION_SIZE     25`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `#define FILE_MAILSLOT_QUERY_INFORMATION_SIZE  26`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] `#define FILE_MAILSLOT_SET_INFORMATION_SIZE    27`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `#define FILE_COMPRESSION_INFORMATION_SIZE     16`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] `#define FILE_OBJECT_ID_INFORMATION_SIZE       29`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] `/* Number 30 not defined in documents */`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] `#define FILE_MOVE_CLUSTER_INFORMATION_SIZE    31`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] `#define FILE_PROCESS_IDS_USING_FILE_INFORMATION_SIZE 8`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `#define FILE_NETWORK_PHYSICAL_NAME_INFORMATION_SIZE  4`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] `#define FILE_IS_REMOTE_DEVICE_INFORMATION_SIZE       4`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `#define FILE_QUOTA_INFORMATION_SIZE           32`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] `#define FILE_REPARSE_POINT_INFORMATION_SIZE   33`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] `#define FILE_NETWORK_OPEN_INFORMATION_SIZE    56`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] `#define FILE_ATTRIBUTE_TAG_INFORMATION_SIZE   8`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `#define FILE_REMOTE_PROTOCOL_INFORMATION_SIZE 116`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `#define FILE_VOLUME_NAME_INFORMATION_SIZE     4`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `#define FILE_DISPOSITION_INFORMATION_EX_SIZE  4`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `#define FILE_CASE_SENSITIVE_INFORMATION_SIZE  4`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `/* FS Info response  size */`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] `#define FS_LABEL_INFORMATION_SIZE      4`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `#define FS_DEVICE_INFORMATION_SIZE     8`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] `#define FS_ATTRIBUTE_INFORMATION_SIZE  16`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `#define FS_VOLUME_INFORMATION_SIZE     24`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `#define FS_SIZE_INFORMATION_SIZE       24`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `#define FS_FULL_SIZE_INFORMATION_SIZE  32`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] `#define FS_DRIVER_PATH_INFORMATION_SIZE 4`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `#define FS_SECTOR_SIZE_INFORMATION_SIZE 28`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] `#define FS_OBJECT_ID_INFORMATION_SIZE 64`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] `#define FS_CONTROL_INFORMATION_SIZE 48`
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `#define FS_POSIX_INFORMATION_SIZE 56`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `/* FS_ATTRIBUTE_File_System_Name */`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `#define FS_TYPE_SUPPORT_SIZE   44`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] ` * fs_type_info is not a wire-format struct, so __packed is not needed.`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] ` * Removing __packed avoids alignment issues from the pointer field.`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `struct fs_type_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `	char		*fs_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `	long		magic_number;`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] `struct smb2_oplock_break {`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `	__le16 StructureSize; /* Must be 24 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] `	__u8   OplockLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] `	__le32 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `	__le64  PersistentFid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `	__le64  VolatileFid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [PROTO_GATE|] `#define SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED cpu_to_le32(0x01)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01474 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `struct smb2_lease_break {`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `	__le16 StructureSize; /* Must be 44 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `	__le16 Epoch;`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] `	__u8   LeaseKey[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `	__le32 CurrentLeaseState;`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] `	__le32 NewLeaseState;`
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `	__le32 BreakReason;`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `	__le32 AccessMaskHint;`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `	__le32 ShareMaskHint;`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `struct smb2_lease_ack {`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] `	__le16 StructureSize; /* Must be 36 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] `	__u8   LeaseKey[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] `	__le32 LeaseState;`
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `	__le64 LeaseDuration;`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] ` * SMB2 SERVER_TO_CLIENT_NOTIFICATION (MS-SMB2 §2.2.44)`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] ` * Server-initiated, unsolicited notification to client (SMB 3.1.1+).`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [PROTO_GATE|] `#define SMB2_NOTIFY_SESSION_CLOSED	cpu_to_le32(0x00000002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01504 [NONE] `struct smb2_server_to_client_notification {`
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] `	struct smb2_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] `	__le16 StructureSize;     /* Must be 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `	__le16 Reserved;          /* MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [PROTO_GATE|] `	__le32 NotificationType;  /* e.g. SMB2_NOTIFY_SESSION_CLOSED */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01509 [NONE] `	/* NotificationData follows (type-specific, variable length) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] ` *	PDU infolevel structure definitions`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] ` *	BB consider moving to a different header`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `/* File System Information Classes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `#define FS_VOLUME_INFORMATION		1 /* Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `#define FS_LABEL_INFORMATION		2 /* Set */`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] `#define FS_SIZE_INFORMATION		3 /* Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] `#define FS_DEVICE_INFORMATION		4 /* Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] `#define FS_ATTRIBUTE_INFORMATION	5 /* Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `#define FS_CONTROL_INFORMATION		6 /* Query, Set */`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `#define FS_FULL_SIZE_INFORMATION	7 /* Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `#define FS_OBJECT_ID_INFORMATION	8 /* Query, Set */`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] `#define FS_DRIVER_PATH_INFORMATION	9 /* Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] `#define FS_SECTOR_SIZE_INFORMATION	11 /* SMB3 or later. Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] `#define FS_POSIX_INFORMATION		100 /* SMB3.1.1 POSIX. Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `struct smb2_fs_full_size_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `	__le64 TotalAllocationUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `	__le64 CallerAvailableAllocationUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `	__le64 ActualAvailableAllocationUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `	__le32 SectorsPerAllocationUnit;`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `	__le32 BytesPerSector;`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] `#define SSINFO_FLAGS_ALIGNED_DEVICE		0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `#define SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE 0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `#define SSINFO_FLAGS_NO_SEEK_PENALTY		0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] `#define SSINFO_FLAGS_TRIM_ENABLED		0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] `/* sector size info struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] `struct smb3_fs_ss_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `	__le32 LogicalBytesPerSector;`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] `	__le32 PhysicalBytesPerSectorForAtomicity;`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `	__le32 PhysicalBytesPerSectorForPerf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] `	__le32 FSEffPhysicalBytesPerSectorForAtomicity;`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] `	__le32 ByteOffsetForSectorAlignment;`
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [NONE] `	__le32 ByteOffsetForPartitionAlignment;`
  Review: Low-risk line; verify in surrounding control flow.
- L01552 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] `/* File System Control Information */`
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] `struct smb2_fs_control_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `	__le64 FreeSpaceStartFiltering;`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [NONE] `	__le64 FreeSpaceThreshold;`
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [NONE] `	__le64 FreeSpaceStopFiltering;`
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] `	__le64 DefaultQuotaThreshold;`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] `	__le64 DefaultQuotaLimit;`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] `	__le32 FileSystemControlFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `	__le32 Padding;`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] `/* partial list of QUERY INFO levels */`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `#define FILE_DIRECTORY_INFORMATION	1`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] `#define FILE_FULL_DIRECTORY_INFORMATION 2`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] `#define FILE_BOTH_DIRECTORY_INFORMATION 3`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] `#define FILE_BASIC_INFORMATION		4`
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] `#define FILE_STANDARD_INFORMATION	5`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] `#define FILE_INTERNAL_INFORMATION	6`
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] `#define FILE_EA_INFORMATION	        7`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] `#define FILE_ACCESS_INFORMATION		8`
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] `#define FILE_NAME_INFORMATION		9`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] `#define FILE_RENAME_INFORMATION		10`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] `#define FILE_LINK_INFORMATION		11`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] `#define FILE_NAMES_INFORMATION		12`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `#define FILE_DISPOSITION_INFORMATION	13`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] `#define FILE_POSITION_INFORMATION	14`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] `#define FILE_FULL_EA_INFORMATION	15`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [NONE] `#define FILE_MODE_INFORMATION		16`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] `#define FILE_ALIGNMENT_INFORMATION	17`
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `#define FILE_ALL_INFORMATION		18`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `#define FILE_ALLOCATION_INFORMATION	19`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] `#define FILE_END_OF_FILE_INFORMATION	20`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] `#define FILE_ALTERNATE_NAME_INFORMATION 21`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] `#define FILE_STREAM_INFORMATION		22`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] `#define FILE_PIPE_INFORMATION		23`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] `#define FILE_PIPE_LOCAL_INFORMATION	24`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [NONE] `#define FILE_PIPE_REMOTE_INFORMATION	25`
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `#define FILE_MAILSLOT_QUERY_INFORMATION 26`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] `#define FILE_MAILSLOT_SET_INFORMATION	27`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] `#define FILE_COMPRESSION_INFORMATION	28`
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] `#define FILE_OBJECT_ID_INFORMATION	29`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] `/* Number 30 not defined in documents */`
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] `#define FILE_MOVE_CLUSTER_INFORMATION	31`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] `#define FILE_QUOTA_INFORMATION		32`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] `#define FILE_REPARSE_POINT_INFORMATION	33`
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [NONE] `#define FILE_NETWORK_OPEN_INFORMATION	34`
  Review: Low-risk line; verify in surrounding control flow.
- L01600 [NONE] `#define FILE_ATTRIBUTE_TAG_INFORMATION	35`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] `#define FILE_TRACKING_INFORMATION	36`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] `#define FILEID_BOTH_DIRECTORY_INFORMATION 37`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] `#define FILEID_FULL_DIRECTORY_INFORMATION 38`
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [NONE] `#define FILE_VALID_DATA_LENGTH_INFORMATION 39`
  Review: Low-risk line; verify in surrounding control flow.
- L01605 [NONE] `#define FILE_SHORT_NAME_INFORMATION	40`
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] `#define FILE_SFIO_RESERVE_INFORMATION	44`
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `#define FILE_SFIO_VOLUME_INFORMATION	45`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `#define FILE_HARD_LINK_INFORMATION	46`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `#define FILE_PROCESS_IDS_USING_FILE_INFORMATION 47`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `#define FILE_NORMALIZED_NAME_INFORMATION 48`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] `#define FILE_NETWORK_PHYSICAL_NAME_INFORMATION 49`
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `#define FILEID_GLOBAL_TX_DIRECTORY_INFORMATION 50`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] `#define FILE_IS_REMOTE_DEVICE_INFORMATION 51`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] `#define FILE_STANDARD_LINK_INFORMATION	54`
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `#define FILE_REMOTE_PROTOCOL_INFORMATION 55`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] `#define FILE_RENAME_INFORMATION_BYPASS_ACCESS_CHECK 56`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [NONE] `#define FILE_LINK_INFORMATION_BYPASS_ACCESS_CHECK 57`
  Review: Low-risk line; verify in surrounding control flow.
- L01618 [NONE] `#define FILE_VOLUME_NAME_INFORMATION	58`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] `#define FILE_ID_INFORMATION		59`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [NONE] `#define FILEID_EXTD_DIRECTORY_INFORMATION 60`
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [NONE] `#define FILEID_EXTD_BOTH_DIRECTORY_INFORMATION 63`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] `#define FILE_DISPOSITION_INFORMATION_EX 64`
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `#define FILE_RENAME_INFORMATION_EX	65`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] `#define FILE_RENAME_INFORMATION_EX_BYPASS_ACCESS_CHECK 66`
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `#define FILE_CASE_SENSITIVE_INFORMATION 71`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `#define FILEID_64_EXTD_DIRECTORY_INFORMATION 78`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] `#define FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION 79`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `#define FILEID_ALL_EXTD_DIRECTORY_INFORMATION 80`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `#define FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION 81`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [NONE] `#define FILE_CS_FLAG_CASE_SENSITIVE_DIR 0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [NONE] `#define OP_BREAK_STRUCT_SIZE_20		24`
  Review: Low-risk line; verify in surrounding control flow.
- L01634 [NONE] `#define OP_BREAK_STRUCT_SIZE_21		36`
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `struct smb2_file_access_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] `	__le32 AccessFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `struct smb2_file_alignment_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `	__le32 AlignmentRequirement;`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `struct smb2_file_internal_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] `	__le64 IndexNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `} __packed; /* level 6 Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `struct smb2_file_rename_info { /* encoding of request for level 10 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `	__u8   ReplaceIfExists; /* 1 = replace existing target with new */`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `				/* 0 = fail if target already exists */`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `	__u8   Reserved[7];`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] `	__u64  RootDirectory;  /* MBZ for network operations (why says spec?) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `	char   FileName[];     /* New name to be assigned */`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `} __packed; /* level 10 Set */`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [NONE] `struct smb2_file_link_info { /* encoding of request for level 11 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `	__u8   ReplaceIfExists; /* 1 = replace existing link with new */`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `				/* 0 = fail if link already exists */`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] `	__u8   Reserved[7];`
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `	__u64  RootDirectory;  /* MBZ for network operations (why says spec?) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [NONE] `	char   FileName[];     /* Name to be assigned to new link */`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [NONE] `} __packed; /* level 11 Set */`
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [NONE] ` * This level 18, although with struct with same name is different from cifs`
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] ` * level 0x107. Level 0x107 has an extra u64 between AccessFlags and`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] ` * CurrentByteOffset.`
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `struct smb2_file_all_info { /* data block encoding of response to level 18 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `	__le64 CreationTime;	/* Beginning of FILE_BASIC_INFO equivalent */`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] `	__le32 Attributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [NONE] `	__le32 Pad1;		/* End of FILE_BASIC_INFO_INFO equivalent */`
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [NONE] `	__le64 AllocationSize;	/* Beginning of FILE_STANDARD_INFO equivalent */`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [NONE] `	__le64 EndOfFile;	/* size ie offset to first free byte in file */`
  Review: Low-risk line; verify in surrounding control flow.
- L01680 [NONE] `	__le32 NumberOfLinks;	/* hard links */`
  Review: Low-risk line; verify in surrounding control flow.
- L01681 [NONE] `	__u8   DeletePending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] `	__u8   Directory;`
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [NONE] `	__le16 Pad2;		/* End of FILE_STANDARD_INFO equivalent */`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [NONE] `	__le64 IndexNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [NONE] `	__le32 EASize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [NONE] `	__le32 AccessFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] `	__le64 CurrentByteOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [NONE] `	__le32 Mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01689 [NONE] `	__le32 AlignmentRequirement;`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [NONE] `	char   FileName[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] `} __packed; /* level 18 Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [NONE] `struct smb2_file_basic_info { /* data block encoding of response to level 18 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] `	__le64 CreationTime;	/* Beginning of FILE_BASIC_INFO equivalent */`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [NONE] `	__le32 Attributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [NONE] `	__u32  Pad1;		/* End of FILE_BASIC_INFO_INFO equivalent */`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] `struct smb2_file_alt_name_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [NONE] `struct smb2_file_stream_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] `	__le32  NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] `	__le32  StreamNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] `	__le64 StreamSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] `	__le64 StreamAllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `	char   StreamName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] `struct smb2_file_eof_info { /* encoding of request for level 10 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] `	__le64 EndOfFile; /* new end of file value */`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] `} __packed; /* level 20 Set */`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [NONE] `struct smb2_file_ntwrk_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [NONE] `	__le32 Attributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01728 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] `struct smb2_file_standard_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] `	__le32 NumberOfLinks;	/* hard links */`
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [NONE] `	__u8   DeletePending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [NONE] `	__u8   Directory;`
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [NONE] `} __packed; /* level 18 Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01739 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `struct smb2_file_ea_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [NONE] `	__le32 EASize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01744 [NONE] `struct smb2_file_alloc_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `struct smb2_file_disposition_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] `	__u8 DeletePending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] `struct smb2_file_pos_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [NONE] `	__le64 CurrentByteOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01754 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] `#define FILE_MODE_INFO_MASK cpu_to_le32(0x0000103e)`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01758 [NONE] `struct smb2_file_mode_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] `	__le32 Mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [NONE] `#define COMPRESSION_FORMAT_NONE 0x0000`
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] `#define COMPRESSION_FORMAT_LZNT1 0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] `struct smb2_file_comp_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] `	__le64 CompressedFileSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] `	__le16 CompressionFormat;`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] `	__u8 CompressionUnitShift;`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `	__u8 ChunkShift;`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] `	__u8 ClusterShift;`
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] `	__u8 Reserved[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] `struct smb2_file_attr_tag_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] `	__le32 FileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [NONE] `	__le32 ReparseTag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01777 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] `/* MS-FSCC 2.4.29 - FilePipeInformation */`
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [NONE] `struct smb2_file_pipe_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01781 [NONE] `	__le32 ReadMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] `	__le32 CompletionMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `/* MS-FSCC 2.4.30 - FilePipeLocalInformation */`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] `struct smb2_file_pipe_local_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] `	__le32 NamedPipeType;`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [NONE] `	__le32 NamedPipeConfiguration;`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] `	__le32 MaximumInstances;`
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [NONE] `	__le32 CurrentInstances;`
  Review: Low-risk line; verify in surrounding control flow.
- L01791 [NONE] `	__le32 InboundQuota;`
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] `	__le32 ReadDataAvailable;`
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `	__le32 OutboundQuota;`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] `	__le32 WriteQuotaAvailable;`
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] `	__le32 NamedPipeState;`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] `	__le32 NamedPipeEnd;`
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [NONE] `/* MS-FSCC 2.4.45 - FileValidDataLengthInformation */`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [NONE] `struct smb2_file_valid_data_length_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] `	__le64 ValidDataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01803 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `#define SL_RESTART_SCAN	0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] `#define SL_RETURN_SINGLE_ENTRY	0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `#define SL_INDEX_SPECIFIED	0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] `struct smb2_ea_info_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [NONE] `	__u8   EaNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] `	char name[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [NONE] `} __packed; /* level 15 Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [NONE] `struct smb2_ea_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01816 [NONE] `	__u8   Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [NONE] `	__u8   EaNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] `	__le16 EaValueLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [NONE] `	char name[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `	/* optionally followed by value */`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] `} __packed; /* level 15 Query */`
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [NONE] `struct create_ea_buf_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01824 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L01826 [NONE] `	struct smb2_ea_info ea;`
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] `struct create_sd_buf_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `	struct create_context ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [NONE] `	__u8   Name[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L01832 [NONE] `	struct smb_ntsd ntsd;`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] `/* Find File infolevels */`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] `#define SMB_FIND_FILE_POSIX_INFO	0x064`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01838 [NONE] `/* Level 100 query info */`
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] `struct smb311_posix_qinfo {`
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [NONE] `	__le32 DosAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [NONE] `	__le64 Inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [NONE] `	__le32 DeviceId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01849 [NONE] `	__le32 Zero;`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `	/* beginning of POSIX Create Context Response */`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [NONE] `	__le32 HardLinks;`
  Review: Low-risk line; verify in surrounding control flow.
- L01852 [NONE] `	__le32 ReparseTag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] `	__le32 Mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] `	u8     Sids[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01856 [NONE] `	 * var sized owner SID`
  Review: Low-risk line; verify in surrounding control flow.
- L01857 [NONE] `	 * var sized group SID`
  Review: Low-risk line; verify in surrounding control flow.
- L01858 [NONE] `	 * le32 filenamelength`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] `	 * u8  filename[]`
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01863 [NONE] `struct smb2_posix_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01864 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] `	__u32 Ignored;`
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01868 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01872 [NONE] `	__le32 DosAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `	__le64 Inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [NONE] `	__le32 DeviceId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01875 [NONE] `	__le32 Zero;`
  Review: Low-risk line; verify in surrounding control flow.
- L01876 [NONE] `	/* beginning of POSIX Create Context Response */`
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [NONE] `	__le32 HardLinks;`
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] `	__le32 ReparseTag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `	__le32 Mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [NONE] `	 * SidBuffer contain two sids(owner sid(up to 28), group sid(16)).`
  Review: Low-risk line; verify in surrounding control flow.
- L01882 [NONE] `	 * Use 44 bytes to match create_posix_rsp and accommodate domain SIDs.`
  Review: Low-risk line; verify in surrounding control flow.
- L01883 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01884 [NONE] `	u8 SidBuffer[44];`
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [NONE] `	__le32 name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01886 [NONE] `	u8 name[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] `	 * var sized owner SID`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] `	 * var sized group SID`
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] `	 * le32 filenamelength`
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] `	 * u8  filename[]`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01895 [NONE] `/* functions */`
  Review: Low-risk line; verify in surrounding control flow.
- L01896 [NONE] `int init_smb2_0_server(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [NONE] `int init_smb2_1_server(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01898 [NONE] `int init_smb3_0_server(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] `int init_smb3_02_server(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] `int init_smb3_11_server(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [NONE] `void init_smb2_max_read_size(unsigned int sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [NONE] `void init_smb2_max_write_size(unsigned int sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] `void init_smb2_max_trans_size(unsigned int sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] `void init_smb2_max_credits(unsigned int sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] `bool is_smb2_neg_cmd(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] `bool is_smb2_rsp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] `u16 get_smb2_cmd_val(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [NONE] `void set_smb2_rsp_status(struct ksmbd_work *work, __le32 err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] `int init_smb2_rsp_hdr(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [NONE] `int smb2_allocate_rsp_buf(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01914 [NONE] `bool is_chained_smb2_message(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [NONE] `int init_smb2_neg_rsp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] `void smb2_set_err_rsp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] `int smb2_check_user_session(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [NONE] `int smb2_get_ksmbd_tcon(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01919 [NONE] `bool smb2_is_sign_req(struct ksmbd_work *work, unsigned int command);`
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [NONE] `int smb2_check_sign_req(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01921 [NONE] `void smb2_set_sign_rsp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [NONE] `int smb3_check_sign_req(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01923 [NONE] `void smb3_set_sign_rsp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [NONE] `int find_matching_smb2_dialect(int start_index, __le16 *cli_dialects,`
  Review: Low-risk line; verify in surrounding control flow.
- L01925 [NONE] `			       __le16 dialects_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L01926 [NONE] `struct file_lock *smb_flock_init(struct file *f);`
  Review: Low-risk line; verify in surrounding control flow.
- L01927 [NONE] `int setup_async_work(struct ksmbd_work *work, void (*fn)(void **),`
  Review: Low-risk line; verify in surrounding control flow.
- L01928 [NONE] `		     void **arg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01929 [NONE] `void release_async_work(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01930 [NONE] `void smb2_send_interim_resp(struct ksmbd_work *work, __le32 status);`
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] `struct channel *lookup_chann_list(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] `				  struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [NONE] `void smb3_preauth_hash_rsp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01934 [NONE] `bool smb3_is_transform_hdr(void *buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [NONE] `int smb3_decrypt_req(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01936 [NONE] `int smb3_encrypt_resp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] `bool smb3_11_final_sess_setup_resp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] `int smb2_set_rsp_credits(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [NONE] `bool smb3_encryption_negotiated(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01940 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] `struct ksmbd_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `int smb2_check_channel_sequence(struct ksmbd_work *work, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01944 [NONE] `/* smb2 compression functions */`
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [NONE] `bool smb2_is_compression_transform_hdr(void *buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01946 [NONE] `int smb2_decompress_req(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01947 [NONE] `int smb2_compress_resp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01948 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01949 [NONE] `/* smb2 misc functions */`
  Review: Low-risk line; verify in surrounding control flow.
- L01950 [NONE] `int ksmbd_smb2_check_message(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01951 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01952 [NONE] `/* smb2 command handlers */`
  Review: Low-risk line; verify in surrounding control flow.
- L01953 [NONE] `int smb2_handle_negotiate(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [NONE] `int smb2_negotiate_request(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01955 [NONE] `int smb2_sess_setup(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01956 [NONE] `int smb2_tree_connect(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] `int smb2_tree_disconnect(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [NONE] `int smb2_session_logoff(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01959 [NONE] `int smb2_open(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01960 [NONE] `int smb2_query_info(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01961 [NONE] `int smb2_query_dir(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [NONE] `int smb2_close(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01963 [NONE] `int smb2_echo(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01964 [NONE] `int smb2_set_info(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01965 [NONE] `int smb2_read(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [NONE] `int smb2_write(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01967 [NONE] `int smb2_flush(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [NONE] `int smb2_cancel(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01969 [NONE] `int smb2_lock(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [NONE] `int smb2_ioctl(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01971 [NONE] `int smb2_oplock_break(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [NONE] `void smb2_send_session_closed_notification(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01973 [NONE] `int smb2_notify(struct ksmbd_work *ksmbd_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01974 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] ` * Get the body of the smb2 message excluding the 4 byte rfc1002 headers`
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [NONE] ` * from request/response buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L01978 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] `static inline void *smb2_get_msg(void *buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01981 [NONE] `	return buf + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01982 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01983 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01984 [NONE] `#define POSIX_TYPE_FILE		0`
  Review: Low-risk line; verify in surrounding control flow.
- L01985 [NONE] `#define POSIX_TYPE_DIR		1`
  Review: Low-risk line; verify in surrounding control flow.
- L01986 [NONE] `#define POSIX_TYPE_SYMLINK	2`
  Review: Low-risk line; verify in surrounding control flow.
- L01987 [NONE] `#define POSIX_TYPE_CHARDEV	3`
  Review: Low-risk line; verify in surrounding control flow.
- L01988 [NONE] `#define POSIX_TYPE_BLKDEV	4`
  Review: Low-risk line; verify in surrounding control flow.
- L01989 [NONE] `#define POSIX_TYPE_FIFO		5`
  Review: Low-risk line; verify in surrounding control flow.
- L01990 [NONE] `#define POSIX_TYPE_SOCKET	6`
  Review: Low-risk line; verify in surrounding control flow.
- L01991 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01992 [NONE] `#define POSIX_FILETYPE_SHIFT	12`
  Review: Low-risk line; verify in surrounding control flow.
- L01993 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01994 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01995 [NONE] `/* Negotiate context decode/assemble (smb2_negotiate.c) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01996 [NONE] `__le32 decode_preauth_ctxt(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01997 [NONE] `			   struct smb2_preauth_neg_context *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L01998 [NONE] `			   int ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01999 [NONE] `void decode_encrypt_ctxt(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02000 [NONE] `			 struct smb2_encryption_neg_context *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L02001 [NONE] `			 int ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02002 [NONE] `__le32 decode_compress_ctxt(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02003 [NONE] `			    struct smb2_compression_ctx *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L02004 [NONE] `			    int ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02005 [NONE] `__le32 decode_sign_cap_ctxt(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02006 [NONE] `			    struct smb2_signing_capabilities *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L02007 [NONE] `			    int ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02008 [NONE] `__le32 deassemble_neg_contexts(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02009 [NONE] `			       struct smb2_negotiate_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L02010 [NONE] `			       unsigned int len_of_smb);`
  Review: Low-risk line; verify in surrounding control flow.
- L02011 [NONE] `int assemble_neg_contexts(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02012 [NONE] `			  struct smb2_negotiate_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02013 [NONE] `			  unsigned int buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02015 [NONE] `/* Session setup helpers (smb2_session.c) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02016 [NONE] `int generate_preauth_hash(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L02017 [NONE] `int decode_negotiation_token(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02018 [NONE] `			     struct negotiate_message *negblob,`
  Review: Low-risk line; verify in surrounding control flow.
- L02019 [NONE] `			     size_t sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L02020 [NONE] `int ntlm_negotiate(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02021 [NONE] `		   struct negotiate_message *negblob,`
  Review: Low-risk line; verify in surrounding control flow.
- L02022 [NONE] `		   size_t negblob_len, struct smb2_sess_setup_rsp *rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02023 [NONE] `struct authenticate_message *user_authblob(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02024 [NONE] `					   struct smb2_sess_setup_req *req);`
  Review: Low-risk line; verify in surrounding control flow.
- L02025 [NONE] `int ntlm_authenticate(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02026 [NONE] `		      struct smb2_sess_setup_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L02027 [NONE] `		      struct smb2_sess_setup_rsp *rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02029 [NONE] `/* Lock helpers (smb2_lock.c) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02030 [NONE] `struct ksmbd_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L02031 [NONE] `int smb2_set_flock_flags(struct file_lock *flock, int flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02032 [NONE] `struct ksmbd_lock *smb2_lock_init(struct file_lock *flock,`
  Review: Low-risk line; verify in surrounding control flow.
- L02033 [NONE] `				  unsigned int cmd, int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L02034 [NONE] `				  unsigned long long smb_start,`
  Review: Low-risk line; verify in surrounding control flow.
- L02035 [NONE] `				  unsigned long long smb_end,`
  Review: Low-risk line; verify in surrounding control flow.
- L02036 [NONE] `				  struct list_head *lock_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02037 [NONE] `int check_lock_sequence(struct ksmbd_file *fp, __le32 lock_seq_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L02038 [NONE] `void store_lock_sequence(struct ksmbd_file *fp, __le32 lock_seq_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L02039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02040 [NONE] `/* Create helpers (smb2_create.c) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02041 [NONE] `int smb2_create_open_flags(bool file_present, __le32 access,`
  Review: Low-risk line; verify in surrounding control flow.
- L02042 [NONE] `			   __le32 disposition, int *may_flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L02043 [NONE] `			   __le32 coptions, umode_t mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02044 [NONE] `int smb_check_parent_dacl_deny(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02045 [NONE] `			       const struct path *parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02046 [NONE] `			       int uid, bool is_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L02047 [NONE] `int smb2_create_sd_buffer(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02048 [NONE] `			  struct smb2_create_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L02049 [NONE] `			  const struct path *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02050 [NONE] `struct lease_ctx_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L02051 [NONE] `struct durable_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L02052 [NONE] `int parse_durable_handle_context(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02053 [NONE] `				 struct smb2_create_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L02054 [NONE] `				 struct lease_ctx_info *lc,`
  Review: Low-risk line; verify in surrounding control flow.
- L02055 [NONE] `				 struct durable_info *dh_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L02056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02057 [NONE] `/* PDU common helpers (smb2_pdu_common.c) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02058 [NONE] `void init_chained_smb2_rsp(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L02059 [NONE] `struct ksmbd_session;`
  Review: Low-risk line; verify in surrounding control flow.
- L02060 [NONE] `struct ksmbd_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L02061 [NONE] `bool ksmbd_gcm_nonce_limit_reached(struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L02062 [NONE] `int smb2_check_channel_sequence(struct ksmbd_work *work, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02063 [NONE] `int fill_transform_hdr(void *tr_buf, char *old_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02064 [NONE] `		       __le16 cipher_type,`
  Review: Low-risk line; verify in surrounding control flow.
- L02065 [NONE] `		       struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L02066 [NONE] `#endif /* CONFIG_KUNIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L02067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02068 [NONE] `#endif	/* _SMB2PDU_H */`
  Review: Low-risk line; verify in surrounding control flow.
