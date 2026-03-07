# Line-by-line Review: src/protocol/smb2/smb2_negotiate.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [PROTO_GATE|] ` *   smb2_negotiate.c - Negotiate contexts + SMB2_NEGOTIATE handler`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/inetdevice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <net/addrconf.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/syscalls.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/statfs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/ethtool.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/falloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/crc32.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/mount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/overflow.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include <linux/filelock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include <crypto/algapi.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "asn1.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "transport_rdma.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#include "mgmt/user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#include "mgmt/ksmbd_ida.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#include "ndr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#include "transport_tcp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#include "ksmbd_create_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#include "ksmbd_vss.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#include "ksmbd_notify.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#include "ksmbd_info.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#include "ksmbd_buffer.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#include "smb2pdu_internal.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `static void build_preauth_ctxt(struct smb2_preauth_neg_context *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `			       __le16 hash_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [PROTO_GATE|] `	pneg_ctxt->ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00067 [NONE] `	pneg_ctxt->DataLength = cpu_to_le16(38);`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	pneg_ctxt->HashAlgorithmCount = cpu_to_le16(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	pneg_ctxt->Reserved = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	pneg_ctxt->SaltLength = cpu_to_le16(SMB311_SALT_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	get_random_bytes(pneg_ctxt->Salt, SMB311_SALT_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	pneg_ctxt->HashAlgorithms = hash_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `static void build_encrypt_ctxt(struct smb2_encryption_neg_context *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `			       __le16 cipher_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [PROTO_GATE|] `	pneg_ctxt->ContextType = SMB2_ENCRYPTION_CAPABILITIES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00079 [NONE] `	pneg_ctxt->DataLength = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	pneg_ctxt->Reserved = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	pneg_ctxt->CipherCount = cpu_to_le16(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	pneg_ctxt->Ciphers[0] = cipher_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `static void build_compress_ctxt(struct smb2_compression_ctx *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `				__le16 alg_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [PROTO_GATE|] `	pneg_ctxt->ContextType = SMB2_COMPRESSION_CAPABILITIES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00089 [NONE] `	pneg_ctxt->DataLength = cpu_to_le16(10);`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	pneg_ctxt->Reserved = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	pneg_ctxt->CompressionAlgorithmCount = cpu_to_le16(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	pneg_ctxt->Padding = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	pneg_ctxt->Flags = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	pneg_ctxt->CompressionAlgorithms[0] = alg_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `static void build_sign_cap_ctxt(struct smb2_signing_capabilities *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `				__le16 sign_algo)`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [PROTO_GATE|] `	pneg_ctxt->ContextType = SMB2_SIGNING_CAPABILITIES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00101 [NONE] `	pneg_ctxt->DataLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `		cpu_to_le16((sizeof(struct smb2_signing_capabilities) + 2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `			- sizeof(struct smb2_neg_context));`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	pneg_ctxt->Reserved = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	pneg_ctxt->SigningAlgorithmCount = cpu_to_le16(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	pneg_ctxt->SigningAlgorithms[0] = sign_algo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `static void build_rdma_transform_ctxt(`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `			struct smb2_rdma_transform_capabilities *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `			struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	unsigned int count = conn->rdma_transform_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	unsigned int data_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [PROTO_GATE|] `	pneg_ctxt->ContextType = SMB2_RDMA_TRANSFORM_CAPABILITIES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00118 [NONE] `	pneg_ctxt->Reserved = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	pneg_ctxt->TransformCount = cpu_to_le16(count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	pneg_ctxt->Reserved1 = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	pneg_ctxt->Reserved2 = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	for (i = 0; i < count; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `		pneg_ctxt->RDMATransformIds[i] = conn->rdma_transform_ids[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	data_len = sizeof(struct smb2_rdma_transform_capabilities)`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `		   - sizeof(struct smb2_neg_context)`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		   + count * sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	pneg_ctxt->DataLength = cpu_to_le16(data_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `static void build_transport_cap_ctxt(`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `				struct smb2_transport_capabilities *pneg_ctxt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [PROTO_GATE|] `	pneg_ctxt->ContextType = SMB2_TRANSPORT_CAPABILITIES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00136 [NONE] `	pneg_ctxt->DataLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `		cpu_to_le16(sizeof(struct smb2_transport_capabilities)`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `			    - sizeof(struct smb2_neg_context));`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	pneg_ctxt->Reserved = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [PROTO_GATE|] `	pneg_ctxt->Flags = SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00141 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `static void build_posix_ctxt(struct smb2_posix_neg_context *pneg_ctxt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [PROTO_GATE|] `	pneg_ctxt->ContextType = SMB2_POSIX_EXTENSIONS_AVAILABLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00146 [NONE] `	pneg_ctxt->DataLength = cpu_to_le16(POSIX_CTXT_DATA_LEN);`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [PROTO_GATE|] `	/* SMB2_CREATE_TAG_POSIX is "0x93AD25509CB411E7B42383DE968BCD7C" */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00148 [NONE] `	pneg_ctxt->Name[0] = 0x93;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	pneg_ctxt->Name[1] = 0xAD;`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	pneg_ctxt->Name[2] = 0x25;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	pneg_ctxt->Name[3] = 0x50;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	pneg_ctxt->Name[4] = 0x9C;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	pneg_ctxt->Name[5] = 0xB4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	pneg_ctxt->Name[6] = 0x11;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	pneg_ctxt->Name[7] = 0xE7;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	pneg_ctxt->Name[8] = 0xB4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	pneg_ctxt->Name[9] = 0x23;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	pneg_ctxt->Name[10] = 0x83;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	pneg_ctxt->Name[11] = 0xDE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	pneg_ctxt->Name[12] = 0x96;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	pneg_ctxt->Name[13] = 0x8B;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	pneg_ctxt->Name[14] = 0xCD;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	pneg_ctxt->Name[15] = 0x7C;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `int assemble_neg_contexts(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `			  struct smb2_negotiate_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `			  unsigned int buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	unsigned int neg_ctxt_off = le32_to_cpu(rsp->NegotiateContextOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	char * const pneg_ctxt = (char *)rsp + neg_ctxt_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	unsigned int buf_remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	int neg_ctxt_cnt = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	int ctxt_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	if (neg_ctxt_off > buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00179 [NONE] `	buf_remaining = buf_len - neg_ctxt_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [PROTO_GATE|] `		    "assemble SMB2_PREAUTH_INTEGRITY_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00183 [NONE] `	if (sizeof(struct smb2_preauth_neg_context) > buf_remaining)`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00185 [NONE] `	build_preauth_ctxt((struct smb2_preauth_neg_context *)pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `			   conn->preauth_info->Preauth_HashId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	ctxt_size = sizeof(struct smb2_preauth_neg_context);`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	if (conn->cipher_type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		unsigned int next_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `		/* Round to 8 byte boundary */`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		ctxt_size = round_up(ctxt_size, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `		next_size = sizeof(struct smb2_encryption_neg_context) + 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		if (ctxt_size + next_size > buf_remaining)`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00197 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [PROTO_GATE|] `			    "assemble SMB2_ENCRYPTION_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00199 [NONE] `		build_encrypt_ctxt((struct smb2_encryption_neg_context *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `				   (pneg_ctxt + ctxt_size),`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `				   conn->cipher_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		neg_ctxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `		ctxt_size += next_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	if (conn->compress_algorithm != SMB3_COMPRESS_NONE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `		unsigned int next_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `		ctxt_size = round_up(ctxt_size, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `		next_size = sizeof(struct smb2_compression_ctx) + sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `		if (ctxt_size + next_size > buf_remaining)`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00213 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [PROTO_GATE|] `			    "assemble SMB2_COMPRESSION_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00215 [NONE] `		build_compress_ctxt((struct smb2_compression_ctx *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `				    (pneg_ctxt + ctxt_size),`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `				    conn->compress_algorithm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `		neg_ctxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `		ctxt_size += next_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	if (conn->posix_ext_supported) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `		ctxt_size = round_up(ctxt_size, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		if (ctxt_size + sizeof(struct smb2_posix_neg_context) > buf_remaining)`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00226 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [PROTO_GATE|] `			    "assemble SMB2_POSIX_EXTENSIONS_AVAILABLE context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00228 [NONE] `		build_posix_ctxt((struct smb2_posix_neg_context *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `				 (pneg_ctxt + ctxt_size));`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `		neg_ctxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `		ctxt_size += sizeof(struct smb2_posix_neg_context);`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	if (conn->signing_negotiated) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `		unsigned int next_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `		ctxt_size = round_up(ctxt_size, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		next_size = sizeof(struct smb2_signing_capabilities) + 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `		if (ctxt_size + next_size > buf_remaining)`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00241 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [PROTO_GATE|] `			    "assemble SMB2_SIGNING_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00243 [NONE] `		build_sign_cap_ctxt((struct smb2_signing_capabilities *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `				    (pneg_ctxt + ctxt_size),`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `				    conn->signing_algorithm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `		neg_ctxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `		ctxt_size += next_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	if (conn->rdma_transform_count) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `		unsigned int next_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `		ctxt_size = round_up(ctxt_size, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `		next_size = sizeof(struct smb2_rdma_transform_capabilities)`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `			    + conn->rdma_transform_count * sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		if (ctxt_size + next_size > buf_remaining)`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00258 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [PROTO_GATE|] `			    "assemble SMB2_RDMA_TRANSFORM_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00260 [NONE] `		build_rdma_transform_ctxt(`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `			(struct smb2_rdma_transform_capabilities *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `			(pneg_ctxt + ctxt_size), conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `		neg_ctxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		ctxt_size += next_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	if (conn->transport_secured) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `		ctxt_size = round_up(ctxt_size, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `		if (ctxt_size + sizeof(struct smb2_transport_capabilities) > buf_remaining)`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00271 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [PROTO_GATE|] `			    "assemble SMB2_TRANSPORT_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00273 [NONE] `		build_transport_cap_ctxt(`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `				(struct smb2_transport_capabilities *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `				(pneg_ctxt + ctxt_size));`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `		neg_ctxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `		ctxt_size += sizeof(struct smb2_transport_capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `	rsp->NegotiateContextCount = cpu_to_le16(neg_ctxt_cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `	return ctxt_size + AUTH_GSS_PADDING;`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `EXPORT_SYMBOL_IF_KUNIT(assemble_neg_contexts);`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `__le32 decode_preauth_ctxt(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `			   struct smb2_preauth_neg_context *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `			   int ctxt_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	int hash_count, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	__le16 *hash_algs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	 * sizeof(smb2_preauth_neg_context) assumes SMB311_SALT_SIZE Salt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	 * which may not be present. Only check for used HashAlgorithms[1].`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	if (ctxt_len <`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	    sizeof(struct smb2_neg_context) + MIN_PREAUTH_CTXT_DATA_LEN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	 * B.4: MS-SMB2 §2.2.3.1.1 — HashAlgorithmCount MUST be >= 1.`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	 * Validate the count before reading any algorithm entries.`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	hash_count = le16_to_cpu(pneg_ctxt->HashAlgorithmCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	if (hash_count == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [ERROR_PATH|PROTO_GATE|] `		pr_warn_ratelimited("SMB2_PREAUTH_INTEGRITY: HashAlgorithmCount=0 is invalid\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00308 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00309 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	/* Ensure we have enough context length for all hash algorithms array */`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	if (ctxt_len < sizeof(struct smb2_neg_context) + MIN_PREAUTH_CTXT_DATA_LEN +`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	    (hash_count - 1) * sizeof(__le16))`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00315 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	hash_algs = &pneg_ctxt->HashAlgorithms;`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	 * Only SHA-512 (0x0001) is currently defined. Iterate through the array`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	 * to find a supported algorithm per MS-SMB2 §3.3.5.4.`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	for (i = 0; i < hash_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [PROTO_GATE|] `		if (hash_algs[i] == SMB2_PREAUTH_INTEGRITY_SHA512) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00324 [NONE] `			conn->preauth_info->Preauth_HashId =`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [PROTO_GATE|] `				SMB2_PREAUTH_INTEGRITY_SHA512;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00326 [PROTO_GATE|] `			return STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00327 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [PROTO_GATE|] `	return STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00331 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `EXPORT_SYMBOL_IF_KUNIT(decode_preauth_ctxt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `void decode_encrypt_ctxt(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `			 struct smb2_encryption_neg_context *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `			 int ctxt_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	int cph_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `	size_t cphs_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	if (sizeof(struct smb2_encryption_neg_context) > ctxt_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [ERROR_PATH|PROTO_GATE|] `		pr_err_ratelimited("Invalid SMB2_ENCRYPTION_CAPABILITIES context size\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00344 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	conn->cipher_type = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	cph_cnt = le16_to_cpu(pneg_ctxt->CipherCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	if (check_mul_overflow((size_t)cph_cnt, sizeof(__le16), &cphs_size)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [ERROR_PATH|] `		pr_err_ratelimited("Cipher count overflow(%d)\n", cph_cnt);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00352 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	if (sizeof(struct smb2_encryption_neg_context) + cphs_size >`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	    (size_t)ctxt_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [ERROR_PATH|] `		pr_err_ratelimited("Invalid cipher count(%d)\n", cph_cnt);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00358 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [PROTO_GATE|] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00362 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	 * B.3: Select cipher by SERVER preference order, not client order.`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	 * MS-SMB2 §3.3.5.2.5.2 step 2: "The server MUST set`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	 * Connection.CipherId to the value in the Ciphers array that is`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	 * preferred by the server."`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	 * Server priority (strongest first):`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `	 *   AES-256-GCM > AES-128-GCM > AES-256-CCM > AES-128-CCM`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `		static const __le16 server_cipher_pref[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [PROTO_GATE|] `			SMB2_ENCRYPTION_AES256_GCM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00376 [PROTO_GATE|] `			SMB2_ENCRYPTION_AES128_GCM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00377 [PROTO_GATE|] `			SMB2_ENCRYPTION_AES256_CCM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00378 [PROTO_GATE|] `			SMB2_ENCRYPTION_AES128_CCM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00379 [NONE] `		};`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `		int p, j;`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `		for (p = 0; p < ARRAY_SIZE(server_cipher_pref); p++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `			for (j = 0; j < cph_cnt; j++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `				if (pneg_ctxt->Ciphers[j] ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `				    server_cipher_pref[p]) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `					ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `						    "Cipher ID = 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `						    le16_to_cpu(pneg_ctxt->Ciphers[j]));`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `					conn->cipher_type =`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `						server_cipher_pref[p];`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `					return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `EXPORT_SYMBOL_IF_KUNIT(decode_encrypt_ctxt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ` * smb3_encryption_negotiated() - checks if server and client agreed on enabling encryption`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] ` * @conn:	smb connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] ` * Return:	true if connection should be encrypted, else false`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `bool smb3_encryption_negotiated(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	if (!conn->ops->generate_encryptionkey)`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [PROTO_GATE|] `	 * SMB 3.0 and 3.0.2 dialects use the SMB2_GLOBAL_CAP_ENCRYPTION flag.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00412 [NONE] `	 * SMB 3.1.1 uses the cipher_type field.`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [PROTO_GATE|] `	return (conn->vals->capabilities & SMB2_GLOBAL_CAP_ENCRYPTION) ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00415 [NONE] `	    conn->cipher_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `__le32 decode_compress_ctxt(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `			    struct smb2_compression_ctx *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `			    int ctxt_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	int algo_cnt, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `	size_t algos_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	conn->compress_algorithm = SMB3_COMPRESS_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	if (sizeof(struct smb2_compression_ctx) > ctxt_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [ERROR_PATH|PROTO_GATE|] `		pr_err("Invalid SMB2_COMPRESSION_CAPABILITIES context length\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00430 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00431 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	algo_cnt = le16_to_cpu(pneg_ctxt->CompressionAlgorithmCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	/* MS-SMB2 §2.2.3.1.3: CompressionAlgorithmCount MUST be > 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	if (algo_cnt == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [ERROR_PATH|PROTO_GATE|] `		pr_warn_ratelimited("SMB2_COMPRESSION_CAPABILITIES: CompressionAlgorithmCount=0 is invalid\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00438 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00439 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	if (check_mul_overflow((size_t)algo_cnt, sizeof(__le16), &algos_size)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [ERROR_PATH|] `		pr_err("Compression algorithm count overflow(%d)\n", algo_cnt);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00443 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00444 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `	if (sizeof(struct smb2_compression_ctx) + algos_size > (size_t)ctxt_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [ERROR_PATH|] `		pr_err("Invalid compression algorithm count(%d)\n", algo_cnt);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00448 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00449 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	 * Select the best compression algorithm supported by both sides.`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	 * Preference order: LZ4 > Pattern_V1 > LZ77+Huffman > LZ77 > LZNT1`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	 * For now, only LZ4 and Pattern_V1 are fully implemented.`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	for (i = 0; i < algo_cnt; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `		if (pneg_ctxt->CompressionAlgorithms[i] == SMB3_COMPRESS_LZ4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `			conn->compress_algorithm = SMB3_COMPRESS_LZ4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `			ksmbd_debug(SMB, "Selected compression algorithm: LZ4\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [PROTO_GATE|] `			return STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00461 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	for (i = 0; i < algo_cnt; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `		if (pneg_ctxt->CompressionAlgorithms[i] ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `		    SMB3_COMPRESS_PATTERN_V1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `			conn->compress_algorithm = SMB3_COMPRESS_PATTERN_V1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `				    "Selected compression algorithm: Pattern_V1\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [PROTO_GATE|] `			return STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00471 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	ksmbd_debug(SMB, "No mutually supported compression algorithm found\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [PROTO_GATE|] `	return STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00476 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `EXPORT_SYMBOL_IF_KUNIT(decode_compress_ctxt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `__le32 decode_sign_cap_ctxt(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `			    struct smb2_signing_capabilities *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `			    int ctxt_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	int sign_algo_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	int i, sign_alos_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	if (sizeof(struct smb2_signing_capabilities) > ctxt_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [ERROR_PATH|PROTO_GATE|] `		pr_err_ratelimited("Invalid SMB2_SIGNING_CAPABILITIES context length\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00489 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00490 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	conn->signing_negotiated = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	sign_algo_cnt = le16_to_cpu(pneg_ctxt->SigningAlgorithmCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	/* MS-SMB2 §2.2.3.1.7: SigningAlgorithmCount MUST be > 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	if (sign_algo_cnt == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [ERROR_PATH|PROTO_GATE|] `		pr_warn_ratelimited("SMB2_SIGNING_CAPABILITIES: SigningAlgorithmCount=0 is invalid\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00498 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00499 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	if (check_mul_overflow((int)sign_algo_cnt, (int)sizeof(__le16), &sign_alos_size))`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	if (sizeof(struct smb2_signing_capabilities) + sign_alos_size >`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	    ctxt_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [ERROR_PATH|] `		pr_err_ratelimited("Invalid signing algorithm count(%d)\n", sign_algo_cnt);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00507 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00508 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	 * MS-SMB2 §3.3.5.4 (Signing Capabilities negotiate context):`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	 * "The server MUST set Connection.SigningAlgorithmId to the first`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	 * entry in the SigningAlgorithms array that the server supports."`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	 * Iterate the CLIENT's list in order and pick the first algorithm`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	 * we support.  AES-CMAC and AES-GMAC are both supported; HMAC-SHA256`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	 * is accepted for compatibility but not preferred.`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	conn->signing_negotiated = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	conn->signing_algorithm = SIGNING_ALG_AES_CMAC; /* fallback */`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `	for (i = 0; i < sign_algo_cnt; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `		__le16 alg = pneg_ctxt->SigningAlgorithms[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `		if (alg == SIGNING_ALG_AES_CMAC ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `		    alg == SIGNING_ALG_AES_GMAC ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `		    alg == SIGNING_ALG_HMAC_SHA256) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `			conn->signing_algorithm = alg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `			ksmbd_debug(SMB, "Signing Algorithm ID = 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `				    le16_to_cpu(alg));`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [PROTO_GATE|] `	return STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00534 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `EXPORT_SYMBOL_IF_KUNIT(decode_sign_cap_ctxt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `static void decode_transport_cap_ctxt(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `				      struct smb2_transport_capabilities *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `				      int ctxt_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	if (sizeof(struct smb2_transport_capabilities) > ctxt_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [ERROR_PATH|PROTO_GATE|] `		pr_err("Invalid SMB2_TRANSPORT_CAPABILITIES context size\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00543 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [PROTO_GATE|] `	if (pneg_ctxt->Flags & SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00547 [NONE] `		ksmbd_debug(SMB, "Client supports transport-level security\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `		conn->transport_secured = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `static void decode_rdma_transform_ctxt(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `					struct smb2_rdma_transform_capabilities *pneg_ctxt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `					int ctxt_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	int xform_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	int i, xforms_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `	if (sizeof(struct smb2_rdma_transform_capabilities) > ctxt_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [ERROR_PATH|PROTO_GATE|] `		pr_err("Invalid SMB2_RDMA_TRANSFORM_CAPABILITIES context size\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00561 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	conn->rdma_transform_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	xform_cnt = le16_to_cpu(pneg_ctxt->TransformCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	if (xform_cnt == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [ERROR_PATH|] `		pr_err("RDMA transform count is zero\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00569 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `	if (check_mul_overflow((int)xform_cnt, (int)sizeof(__le16), &xforms_size))`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	if (sizeof(struct smb2_rdma_transform_capabilities) + xforms_size >`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `	    ctxt_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [ERROR_PATH|] `		pr_err("Invalid RDMA transform count(%d)\n", xform_cnt);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00578 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	for (i = 0; i < xform_cnt; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [PROTO_GATE|] `		if (pneg_ctxt->RDMATransformIds[i] == SMB2_RDMA_TRANSFORM_NONE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00583 [PROTO_GATE|] `		    pneg_ctxt->RDMATransformIds[i] == SMB2_RDMA_TRANSFORM_ENCRYPTION ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00584 [PROTO_GATE|] `		    pneg_ctxt->RDMATransformIds[i] == SMB2_RDMA_TRANSFORM_SIGNING) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00585 [NONE] `			if (conn->rdma_transform_count >= ARRAY_SIZE(conn->rdma_transform_ids))`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `			ksmbd_debug(SMB, "RDMA Transform ID = 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `				    le16_to_cpu(pneg_ctxt->RDMATransformIds[i]));`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `			conn->rdma_transform_ids[conn->rdma_transform_count++] =`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `				pneg_ctxt->RDMATransformIds[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `__le32 deassemble_neg_contexts(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `			       struct smb2_negotiate_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `			       unsigned int len_of_smb)`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	/* +4 is to account for the RFC1001 len field */`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	struct smb2_neg_context *pctx = (struct smb2_neg_context *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	int i = 0, len_of_ctxts;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `	unsigned int offset = le32_to_cpu(req->NegotiateContextOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	unsigned int neg_ctxt_cnt = le16_to_cpu(req->NegotiateContextCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	bool compress_ctxt_seen = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [PROTO_GATE|] `	__le32 status = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `	ksmbd_debug(SMB, "decoding %d negotiate contexts\n", neg_ctxt_cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `	if (len_of_smb <= offset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `		ksmbd_debug(SMB, "Invalid response: negotiate context offset\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		return status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `	len_of_ctxts = len_of_smb - offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `	 * Cap negotiate context count to prevent excessive processing.`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `	 * MS-SMB2 defines a small number of context types; 16 is generous.`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [PROTO_GATE|] `#define SMB2_MAX_NEG_CTXTS	16`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00621 [PROTO_GATE|] `	if (neg_ctxt_cnt > SMB2_MAX_NEG_CTXTS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00622 [ERROR_PATH|] `		pr_warn_ratelimited("Too many negotiate contexts (%d > %d), rejecting\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00623 [PROTO_GATE|] `				    neg_ctxt_cnt, SMB2_MAX_NEG_CTXTS);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00624 [PROTO_GATE|] `		return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00625 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	while (i++ < neg_ctxt_cnt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `		int clen, ctxt_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `		if (len_of_ctxts < (int)sizeof(struct smb2_neg_context))`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `		pctx = (struct smb2_neg_context *)((char *)pctx + offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `		clen = le16_to_cpu(pctx->DataLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `		ctxt_len = clen + sizeof(struct smb2_neg_context);`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `		if (ctxt_len > len_of_ctxts)`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [PROTO_GATE|] `		if (pctx->ContextType == SMB2_PREAUTH_INTEGRITY_CAPABILITIES) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00641 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [PROTO_GATE|] `				    "deassemble SMB2_PREAUTH_INTEGRITY_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00643 [NONE] `			if (conn->preauth_info->Preauth_HashId) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `				/* MS-SMB2 §3.3.5.4: duplicate context MUST be rejected */`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [ERROR_PATH|] `				pr_warn_ratelimited("Duplicate PREAUTH_INTEGRITY context in negotiate\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00646 [PROTO_GATE|] `				return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00647 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `			status = decode_preauth_ctxt(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `						     (struct smb2_preauth_neg_context *)pctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `						     ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [PROTO_GATE|] `			if (status != STATUS_SUCCESS)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00653 [NONE] `				return status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [PROTO_GATE|] `		} else if (pctx->ContextType == SMB2_ENCRYPTION_CAPABILITIES) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00655 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [PROTO_GATE|] `				    "deassemble SMB2_ENCRYPTION_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00657 [NONE] `			if (conn->cipher_type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [ERROR_PATH|] `				pr_warn_ratelimited("Duplicate ENCRYPTION_CAPABILITIES context in negotiate\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00659 [PROTO_GATE|] `				return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00660 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `			decode_encrypt_ctxt(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `					    (struct smb2_encryption_neg_context *)pctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `					    ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [PROTO_GATE|] `		} else if (pctx->ContextType == SMB2_COMPRESSION_CAPABILITIES) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00666 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [PROTO_GATE|] `				    "deassemble SMB2_COMPRESSION_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00668 [NONE] `			if (compress_ctxt_seen) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [ERROR_PATH|] `				pr_warn_ratelimited("Duplicate COMPRESSION_CAPABILITIES context in negotiate\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00670 [PROTO_GATE|] `				return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00671 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `			status = decode_compress_ctxt(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `						     (struct smb2_compression_ctx *)pctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `						     ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [PROTO_GATE|] `			if (status != STATUS_SUCCESS)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00677 [NONE] `				return status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `			compress_ctxt_seen = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [PROTO_GATE|] `		} else if (pctx->ContextType == SMB2_NETNAME_NEGOTIATE_CONTEXT_ID) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00680 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [PROTO_GATE|] `				    "deassemble SMB2_NETNAME_NEGOTIATE_CONTEXT_ID context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00682 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `			 * B.13: MS-SMB2 §3.3.5.2.4 step 2: the server SHOULD`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `			 * validate the NetName against its own server name.`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `			 * Log a debug message if the name doesn't match;`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `			 * do not reject (informational only for compatibility).`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `			if (clen > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `				char *net_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `				struct smb2_netname_neg_context *nc =`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `					(struct smb2_netname_neg_context *)pctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `				net_name = smb_strndup_from_utf16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `						(const char *)nc->NetName, clen, true,`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `						conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `				if (!IS_ERR(net_name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `					char *srv = ksmbd_netbios_name();`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `					if (srv && strcasecmp(net_name, srv) != 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `						ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `							    "NETNAME context name '%s' != server name '%s'\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `							    net_name, srv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `					kfree(net_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [PROTO_GATE|] `		} else if (pctx->ContextType == SMB2_POSIX_EXTENSIONS_AVAILABLE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00707 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [PROTO_GATE|] `				    "deassemble SMB2_POSIX_EXTENSIONS_AVAILABLE context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00709 [NONE] `			conn->posix_ext_supported = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [PROTO_GATE|] `		} else if (pctx->ContextType == SMB2_TRANSPORT_CAPABILITIES) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00711 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [PROTO_GATE|] `				    "deassemble SMB2_TRANSPORT_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00713 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `			decode_transport_cap_ctxt(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `						  (struct smb2_transport_capabilities *)pctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `						  ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [PROTO_GATE|] `		} else if (pctx->ContextType == SMB2_RDMA_TRANSFORM_CAPABILITIES) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00718 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [PROTO_GATE|] `				    "deassemble SMB2_RDMA_TRANSFORM_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00720 [NONE] `			if (conn->rdma_transform_count) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [ERROR_PATH|] `				pr_warn_ratelimited("Duplicate RDMA_TRANSFORM_CAPABILITIES context in negotiate\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00722 [PROTO_GATE|] `				return STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00723 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `			decode_rdma_transform_ctxt(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `						   (struct smb2_rdma_transform_capabilities *)pctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `						   ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [PROTO_GATE|] `		} else if (pctx->ContextType == SMB2_SIGNING_CAPABILITIES) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00729 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [PROTO_GATE|] `				    "deassemble SMB2_SIGNING_CAPABILITIES context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00731 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `			status = decode_sign_cap_ctxt(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `						    (struct smb2_signing_capabilities *)pctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `						    ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [PROTO_GATE|] `			if (status != STATUS_SUCCESS)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00736 [NONE] `				return status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `		/* offsets must be 8 byte aligned */`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `		offset = (ctxt_len + 7) & ~0x7;`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `		len_of_ctxts -= offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `	return status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `EXPORT_SYMBOL_IF_KUNIT(deassemble_neg_contexts);`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] ` * smb2_handle_negotiate() - handler for smb2 negotiate command`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] ` * @work:	smb work containing smb request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] ` * Return:      0`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `int smb2_handle_negotiate(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	struct smb2_negotiate_req *req = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	struct smb2_negotiate_rsp *rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `	unsigned int smb2_buf_len, smb2_neg_size, neg_ctxt_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	__le32 status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `	/* Zero negotiate response body to prevent stale heap data leakage */`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `	memset((char *)rsp + sizeof(struct smb2_hdr), 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `	       sizeof(struct smb2_negotiate_rsp) - sizeof(struct smb2_hdr));`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `	ksmbd_debug(SMB, "Received negotiate request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `	conn->need_neg = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	if (ksmbd_conn_good(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `		 * MS-SMB2 §3.3.5.3.1: "If the server receives a second SMB2`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `		 * NEGOTIATE Request on any established connection, the server`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `		 * MUST disconnect the connection."`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [ERROR_PATH|] `		pr_err_ratelimited("Second NEGOTIATE on established connection, disconnecting\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00775 [NONE] `		ksmbd_conn_set_exiting(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `		work->send_no_response = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00778 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	ksmbd_conn_lock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `	smb2_buf_len = get_rfc1002_len(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `	smb2_neg_size = offsetof(struct smb2_negotiate_req, Dialects);`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `	if (smb2_neg_size > smb2_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00785 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00787 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `	if (req->DialectCount == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [ERROR_PATH|] `		pr_err_ratelimited("malformed packet\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00791 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00792 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00794 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `	if (conn->dialect == SMB311_PROT_ID) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `		unsigned int nego_ctxt_off = le32_to_cpu(req->NegotiateContextOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `		if (smb2_buf_len < nego_ctxt_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00801 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00803 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `		if (smb2_neg_size > nego_ctxt_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00807 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00809 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `		if (smb2_neg_size + le16_to_cpu(req->DialectCount) * sizeof(__le16) >`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `		    nego_ctxt_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00814 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00816 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `		if (smb2_neg_size + le16_to_cpu(req->DialectCount) * sizeof(__le16) >`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `		    smb2_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00821 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00823 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `	conn->cli_cap = le32_to_cpu(req->Capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `	 * Save previous vals so we can free it only after a successful`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `	 * init_smb*_server() call. This prevents conn->vals from being`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `	 * NULL on error paths, which would cause NULL dereferences in`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `	 * subsequent connection handling code.`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	struct smb_version_values *old_vals = conn->vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `	conn->vals = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `	switch (conn->dialect) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `	case SMB311_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `		conn->preauth_info =`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [MEM_BOUNDS|] `			kzalloc(sizeof(struct preauth_integrity_info),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00843 [NONE] `				KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `		if (!conn->preauth_info) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `			rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00847 [NONE] `			conn->vals = old_vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00849 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `		status = deassemble_neg_contexts(conn, req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `						 get_rfc1002_len(work->request_buf));`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [PROTO_GATE|] `		if (status != STATUS_SUCCESS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00854 [ERROR_PATH|] `			pr_err("deassemble_neg_contexts error(0x%x)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00855 [NONE] `			       status);`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `			rsp->hdr.Status = status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `			kfree(conn->preauth_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `			conn->preauth_info = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `			conn->vals = old_vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00862 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `		 * MS-SMB2 §3.3.5.4: SMB 3.1.1 NEGOTIATE MUST contain one`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [PROTO_GATE|] `		 * SMB2_PREAUTH_INTEGRITY_CAPABILITIES context.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00867 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `		if (!conn->preauth_info->Preauth_HashId) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [ERROR_PATH|] `			pr_warn_ratelimited("SMB 3.1.1 negotiate missing mandatory PREAUTH_INTEGRITY context\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00870 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00871 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `			kfree(conn->preauth_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `			conn->preauth_info = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `			conn->vals = old_vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00876 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `		rc = init_smb3_11_server(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `		if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00881 [NONE] `			kfree(conn->preauth_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `			conn->preauth_info = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `			conn->vals = old_vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00885 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `		ksmbd_gen_preauth_integrity_hash(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `						 work->request_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `						 conn->preauth_info->Preauth_HashValue);`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `		rsp->NegotiateContextOffset =`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `				cpu_to_le32(OFFSET_OF_NEG_CONTEXT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `		rc = assemble_neg_contexts(conn, rsp, work->response_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `		if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00895 [NONE] `			kfree(conn->preauth_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `			conn->preauth_info = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `			kfree(old_vals);`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00899 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `		neg_ctxt_len = (unsigned int)rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `		rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `	case SMB302_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `		rc = init_smb3_02_server(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00907 [NONE] `			conn->vals = old_vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00909 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `	case SMB30_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `		rc = init_smb3_0_server(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00915 [NONE] `			conn->vals = old_vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00917 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `	case SMB21_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `		rc = init_smb2_1_server(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00923 [NONE] `			conn->vals = old_vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00925 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `	case SMB20_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `		rc = init_smb2_0_server(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00931 [NONE] `			conn->vals = old_vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00933 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `	case SMB2X_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	case BAD_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `		ksmbd_debug(SMB, "Server dialect :0x%x not supported\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `			    conn->dialect);`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00941 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `		conn->vals = old_vals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00944 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	/* New vals allocated successfully, free the old one */`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	kfree(old_vals);`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	rsp->Capabilities = cpu_to_le32(conn->vals->capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	/* For stats */`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `	conn->connection_type = conn->dialect;`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `	rsp->MaxTransactSize = cpu_to_le32(conn->vals->max_trans_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	rsp->MaxReadSize = cpu_to_le32(conn->vals->max_read_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `	rsp->MaxWriteSize = cpu_to_le32(conn->vals->max_write_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `	if (conn->dialect >= SMB20_PROT_ID) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [MEM_BOUNDS|] `		memcpy(conn->ClientGUID, req->ClientGUID,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00959 [PROTO_GATE|] `		       SMB2_CLIENT_GUID_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00960 [NONE] `		conn->cli_sec_mode = le16_to_cpu(req->SecurityMode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `	rsp->StructureSize = cpu_to_le16(65);`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `	rsp->DialectRevision = cpu_to_le16(conn->dialect);`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `	 * B.1: ServerGUID must be a stable, unique server identity per`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	 * MS-SMB2 §2.2.4.  Generate it lazily on first negotiate and`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `	 * persist it in server_conf so every connection sees the same GUID.`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `	 * This is required for multichannel and durable-handle reconnect.`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [PROTO_GATE|] `	if (!memchr_inv(server_conf.server_guid, 0, SMB2_CLIENT_GUID_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00972 [NONE] `		get_random_bytes(server_conf.server_guid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [PROTO_GATE|] `				 SMB2_CLIENT_GUID_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00974 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [MEM_BOUNDS|] `	memcpy(rsp->ServerGUID, server_conf.server_guid,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00976 [PROTO_GATE|] `	       SMB2_CLIENT_GUID_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00977 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `	 * B.2: ServerStartTime must reflect actual server start time per`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `	 * MS-SMB2 §2.2.4.  Record it lazily on first negotiate.`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `	if (!server_conf.server_start_time)`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `		server_conf.server_start_time = ksmbd_systime();`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `	rsp->SystemTime = cpu_to_le64(ksmbd_systime());`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `	rsp->ServerStartTime = cpu_to_le64(server_conf.server_start_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `	ksmbd_debug(SMB, "negotiate context offset %d, count %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `		    le32_to_cpu(rsp->NegotiateContextOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `		    le16_to_cpu(rsp->NegotiateContextCount));`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `	rsp->SecurityBufferOffset = cpu_to_le16(128);`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `	rsp->SecurityBufferLength = cpu_to_le16(AUTH_GSS_LENGTH);`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `	ksmbd_copy_gss_neg_header((char *)(&rsp->hdr) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `				  le16_to_cpu(rsp->SecurityBufferOffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [PROTO_GATE|] `	rsp->SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00996 [NONE] `	conn->use_spnego = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `	if (server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [PROTO_GATE|] `		rsp->SecurityMode |= SMB2_NEGOTIATE_SIGNING_REQUIRED_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01000 [NONE] `		conn->sign = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `	} else if (server_conf.signing == KSMBD_CONFIG_OPT_AUTO) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `		 * When AUTO, enable signing if the client advertises`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `		 * signing capability. This prevents a MITM from`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `		 * stripping the SIGNING_REQUIRED flag to downgrade`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `		 * the connection to unsigned.`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [PROTO_GATE|] `		if (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_ENABLED_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01009 [NONE] `			conn->sign = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `	} else if (server_conf.signing == KSMBD_CONFIG_OPT_DISABLED &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [PROTO_GATE|] `		   req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01012 [NONE] `		conn->sign = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `	conn->srv_sec_mode = le16_to_cpu(rsp->SecurityMode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `	ksmbd_conn_set_need_setup(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `	ksmbd_conn_unlock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `	if (rc && rsp->hdr.Status == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `	if (!rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `		rc = ksmbd_iov_pin_rsp(work, rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `				       sizeof(struct smb2_negotiate_rsp) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `					AUTH_GSS_LENGTH + neg_ctxt_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `	if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
