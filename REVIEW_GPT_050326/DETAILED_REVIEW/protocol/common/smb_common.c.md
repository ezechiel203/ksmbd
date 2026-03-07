# Line-by-line Review: src/protocol/common/smb_common.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/user_namespace.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "smb1pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "mgmt/user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `/*for shortname implementation */`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `static const char *basechars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-!@#$%";`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define MANGLE_BASE (strlen(basechars) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define MAGIC_CHAR '~'`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#define PERIOD '.'`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#define mangle(V) ((char)(basechars[(V) % MANGLE_BASE]))`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#define KSMBD_MIN_SUPPORTED_HEADER_SIZE	(sizeof(struct smb_hdr))`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#define KSMBD_MIN_SUPPORTED_HEADER_SIZE	(sizeof(struct smb2_hdr))`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `struct smb_protocol {`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	int		index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	char		*name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	char		*prot;`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	__u16		prot_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `static struct smb_protocol smb1_protos[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `		SMB1_PROT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `		"\2NT LM 0.12",`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `		"NT1",`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `		SMB10_PROT_ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [PROTO_GATE|] `		SMB2_PROT,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00058 [NONE] `		"\2SMB 2.002",`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [PROTO_GATE|] `		"SMB2_02",`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00060 [NONE] `		SMB20_PROT_ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `		SMB2X_PROT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `		"\2SMB 2.???",`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [PROTO_GATE|] `		"SMB2_22",`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00067 [NONE] `		SMB2X_PROT_ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `static struct smb_protocol smb2_protos[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [PROTO_GATE|] `		SMB2_PROT,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00074 [NONE] `		"\2SMB 2.002",`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [PROTO_GATE|] `		"SMB2_02",`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00076 [NONE] `		SMB20_PROT_ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `		SMB21_PROT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `		"\2SMB 2.1",`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [PROTO_GATE|] `		"SMB2_10",`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00082 [NONE] `		SMB21_PROT_ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `		SMB30_PROT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `		"\2SMB 3.0",`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `		"SMB3_00",`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		SMB30_PROT_ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `		SMB302_PROT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `		"\2SMB 3.02",`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `		"SMB3_02",`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `		SMB302_PROT_ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `		SMB311_PROT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		"\2SMB 3.1.1",`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `		"SMB3_11",`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `		SMB311_PROT_ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `unsigned int ksmbd_server_side_copy_max_chunk_count(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	return ksmbd_config_get_u32(KSMBD_CFG_COPY_CHUNK_MAX_COUNT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `unsigned int ksmbd_server_side_copy_max_chunk_size(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	return ksmbd_config_get_u32(KSMBD_CFG_COPY_CHUNK_MAX_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `unsigned int ksmbd_server_side_copy_max_total_size(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	return ksmbd_config_get_u32(KSMBD_CFG_COPY_CHUNK_TOTAL_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `inline int ksmbd_min_protocol(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	return SMB1_PROT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [PROTO_GATE|] `	return SMB2_PROT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00125 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `inline int ksmbd_max_protocol(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	return SMB311_PROT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `int ksmbd_lookup_protocol_idx(char *str)`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	int offt = ARRAY_SIZE(smb1_protos) - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	while (offt >= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `		if (!strcmp(str, smb1_protos[offt].prot) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `		    (smb1_protos[offt].index == SMB1_PROT &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		     !strcmp(str, "SMB1"))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `			ksmbd_debug(SMB, "selected %s dialect idx = %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `				    smb1_protos[offt].prot, offt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `			return smb1_protos[offt].index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `		offt--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	offt = ARRAY_SIZE(smb2_protos) - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	while (offt >= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `		if (!strcmp(str, smb2_protos[offt].prot)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `			ksmbd_debug(SMB, "selected %s dialect idx = %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `				    smb2_protos[offt].prot, offt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `			return smb2_protos[offt].index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `		offt--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	return -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ` * ksmbd_verify_smb_message() - check for valid smb2 request header`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ` * @work:	smb work`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ` * check for valid smb signature and packet direction(request/response)`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `int ksmbd_verify_smb_message(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	struct smb2_hdr *smb2_hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [PROTO_GATE|] `	if (smb2_hdr->ProtocolId == SMB2_PROTO_NUMBER) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00174 [NONE] `		ksmbd_debug(SMB, "got SMB2 command\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `		return ksmbd_smb2_check_message(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [LOCK|] `	spin_lock(&work->conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00179 [NONE] `	work->conn->outstanding_credits++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [LOCK|] `	spin_unlock(&work->conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00181 [NONE] `	return ksmbd_smb1_check_message(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	struct smb_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [PROTO_GATE|] `	if (smb2_hdr->ProtocolId == SMB2_PROTO_NUMBER)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00186 [NONE] `		return ksmbd_smb2_check_message(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	hdr = work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	if (*(__le32 *)hdr->Protocol == SMB1_PROTO_NUMBER &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [PROTO_GATE|] `	    hdr->Command == SMB_COM_NEGOTIATE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00191 [LOCK|] `		spin_lock(&work->conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00192 [NONE] `		work->conn->outstanding_credits++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [LOCK|] `		spin_unlock(&work->conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00194 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00198 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ` * ksmbd_smb_request() - check for valid smb request type`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` * Return:      true on success, otherwise false`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `bool ksmbd_smb_request(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	__le32 *proto;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	if (conn->request_buf[0] != 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	proto = (__le32 *)smb2_get_msg(conn->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [PROTO_GATE|] `	if (*proto == SMB2_COMPRESSION_TRANSFORM_ID) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00216 [NONE] `		/* Accept compression transform if compression negotiated */`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `		if (conn->compress_algorithm == SMB3_COMPRESS_NONE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	if (*proto != SMB1_PROTO_NUMBER &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [PROTO_GATE|] `	    *proto != SMB2_PROTO_NUMBER &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00224 [PROTO_GATE|] `	    *proto != SMB2_TRANSFORM_PROTO_NUM)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00225 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [PROTO_GATE|] `	if (*proto == SMB2_TRANSFORM_PROTO_NUM &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00228 [NONE] `	    (!conn->ops || !conn->ops->is_transform_hdr))`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `static bool supported_protocol(int idx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	if (idx == SMB2X_PROT &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	    server_conf.min_protocol >= SMB21_PROT &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	    server_conf.max_protocol <= SMB311_PROT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	return (server_conf.min_protocol <= idx &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `		idx <= server_conf.max_protocol);`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] ` * next_dialect() - advance through a packed SMB1 dialect string list.`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ` * @dialect:  pointer to the start of the dialect buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ` * @next_off: in/out: offset to advance by (updated to the length of current string)`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ` * @bcount:   remaining bytes in the dialect buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ` * SMB1 NEGOTIATE dialects are NUL-terminated ASCII strings packed`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ` * back-to-back, each preceded by a 0x02 byte (MS-SMB §2.2.4.52).`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ` * The caller strips the 0x02 prefix before passing the pointer here.`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ` * Returns NULL when the buffer is exhausted or the string is not NUL-terminated.`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `VISIBLE_IF_KUNIT char *next_dialect(char *dialect, int *next_off, int bcount)`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `	dialect = dialect + *next_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	bcount -= *next_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	if (bcount <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	*next_off = strnlen(dialect, bcount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	if (dialect[*next_off] != '\0')`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	return dialect;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `EXPORT_SYMBOL_IF_KUNIT(next_dialect);`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `static int ksmbd_lookup_dialect_by_name(char *cli_dialects, __le16 byte_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	int i, seq_num, bcount, next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	char *dialect;`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	for (i = ARRAY_SIZE(smb1_protos) - 1; i >= 0; i--) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `		seq_num = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `		next = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `		dialect = cli_dialects;`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `		bcount = le16_to_cpu(byte_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `		do {`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `			dialect = next_dialect(dialect, &next, bcount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `			if (!dialect)`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `			ksmbd_debug(SMB, "client requested dialect %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `				    dialect);`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `			if (!strcmp(dialect, smb1_protos[i].name) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `		    (smb1_protos[i].index == SMB1_PROT &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `		     !strcmp(dialect, "\2NT LANMAN 1.0"))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `				if (supported_protocol(smb1_protos[i].index)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `					ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `						    "selected %s dialect\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `						    smb1_protos[i].name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `					if (smb1_protos[i].index == SMB1_PROT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [ERROR_PATH|] `						pr_warn_ratelimited("ksmbd: negotiated deprecated SMB1 protocol - avoid in production\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00294 [NONE] `						return seq_num;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [PROTO_GATE|] `					if (smb1_protos[i].index == SMB2_PROT)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00297 [ERROR_PATH|] `						pr_warn_ratelimited("ksmbd: negotiated deprecated SMB2.0.2 protocol - avoid in production\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00298 [NONE] `					return smb1_protos[i].prot_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `			seq_num++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `			bcount -= (++next);`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `		} while (bcount > 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	return BAD_PROT_ID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `int ksmbd_lookup_dialect_by_id(__le16 *cli_dialects, __le16 dialects_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	int count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	for (i = ARRAY_SIZE(smb2_protos) - 1; i >= 0; i--) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `		count = le16_to_cpu(dialects_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `		while (--count >= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `			ksmbd_debug(SMB, "client requested dialect 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `				    le16_to_cpu(cli_dialects[count]));`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `			if (le16_to_cpu(cli_dialects[count]) !=`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `					smb2_protos[i].prot_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `			if (supported_protocol(smb2_protos[i].index)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `				ksmbd_debug(SMB, "selected %s dialect\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `					    smb2_protos[i].name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [PROTO_GATE|] `				if (smb2_protos[i].index == SMB2_PROT)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00327 [ERROR_PATH|] `					pr_warn_ratelimited("ksmbd: negotiated deprecated SMB2.0.2 protocol - avoid in production\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00328 [NONE] `				return smb2_protos[i].prot_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	return BAD_PROT_ID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `static int ksmbd_negotiate_smb_dialect(void *buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `	int smb_buf_length = get_rfc1002_len(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [PROTO_GATE|] `	__le32 proto = ((struct smb2_hdr *)smb2_get_msg(buf))->ProtocolId;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00340 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [PROTO_GATE|] `	if (proto == SMB2_PROTO_NUMBER) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00342 [NONE] `		struct smb2_negotiate_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `		int smb2_neg_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `			offsetof(struct smb2_negotiate_req, Dialects);`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `		req = (struct smb2_negotiate_req *)smb2_get_msg(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `		if (smb2_neg_size > smb_buf_length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		if (struct_size(req, Dialects, le16_to_cpu(req->DialectCount)) >`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `		    smb_buf_length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00353 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `		return ksmbd_lookup_dialect_by_id(req->Dialects,`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `						  req->DialectCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	proto = *(__le32 *)((struct smb_hdr *)buf)->Protocol;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	if (proto == SMB1_PROTO_NUMBER) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `		struct smb_negotiate_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `		req = (struct smb_negotiate_req *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `		if (le16_to_cpu(req->ByteCount) < 2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `		if (offsetof(struct smb_negotiate_req, DialectsArray) - 4 +`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `			le16_to_cpu(req->ByteCount) > smb_buf_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00369 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `		return ksmbd_lookup_dialect_by_name(req->DialectsArray,`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `						    req->ByteCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `	return BAD_PROT_ID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `#ifndef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [PROTO_GATE|] `#define SMB_COM_NEGOTIATE_EX	0x0`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00381 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ` * get_smb1_cmd_val() - get smb command value from smb header`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] ` * @work:	smb work containing smb header`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] ` * Return:      smb command value`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `static u16 get_smb1_cmd_val(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [PROTO_GATE|] `	return SMB_COM_NEGOTIATE_EX;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00391 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] ` * init_smb1_rsp_hdr() - initialize smb negotiate response header`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] ` * @work:	smb work containing smb request`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] ` * Return:      0 on success, otherwise -EINVAL`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `static int init_smb1_rsp_hdr(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	struct smb_hdr *rsp_hdr = (struct smb_hdr *)work->response_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	struct smb_hdr *rcv_hdr = (struct smb_hdr *)work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [PROTO_GATE|] `	rsp_hdr->Command = SMB_COM_NEGOTIATE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00405 [NONE] `	*(__le32 *)rsp_hdr->Protocol = SMB1_PROTO_NUMBER;`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	rsp_hdr->Flags = SMBFLG_RESPONSE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	rsp_hdr->Flags2 = SMBFLG2_UNICODE | SMBFLG2_ERR_STATUS |`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `		SMBFLG2_EXT_SEC | SMBFLG2_IS_LONG_NAME;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	rsp_hdr->Pid = rcv_hdr->Pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	rsp_hdr->Mid = rcv_hdr->Mid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] ` * smb1_check_user_session() - check for valid session for a user`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] ` * @work:	smb work containing smb request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `static int smb1_check_user_session(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `	unsigned int cmd = work->conn->ops->get_cmd_val(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [PROTO_GATE|] `	if (cmd == SMB_COM_NEGOTIATE_EX)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00425 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00428 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] ` * smb1_allocate_rsp_buf() - allocate response buffer for a command`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] ` * @work:	smb work containing smb request`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] ` * Return:      0 on success, otherwise -ENOMEM`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `static int smb1_allocate_rsp_buf(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [MEM_BOUNDS|] `	work->response_buf = kzalloc(MAX_CIFS_SMALL_BUFFER_SIZE,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00439 [NONE] `			KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `	work->response_sz = MAX_CIFS_SMALL_BUFFER_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	if (!work->response_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [ERROR_PATH|] `		pr_err("Failed to allocate %u bytes buffer\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00444 [NONE] `				MAX_CIFS_SMALL_BUFFER_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00446 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ` * set_smb1_rsp_status() - set error type in smb response header`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] ` * @work:	smb work containing smb response header`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] ` * @err:	error code to set in response`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `static void set_smb1_rsp_status(struct ksmbd_work *work, __le32 err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	work->send_no_response = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `static struct smb_version_ops smb1_server_ops = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	.get_cmd_val = get_smb1_cmd_val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	.init_rsp_hdr = init_smb1_rsp_hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	.allocate_rsp_buf = smb1_allocate_rsp_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	.check_user_session = smb1_check_user_session,`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	.set_rsp_status = set_smb1_rsp_status,`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `static struct smb_version_values smb1_server_values = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [PROTO_GATE|] `	.max_credits = SMB2_MAX_CREDITS,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00471 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `static int smb1_negotiate(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [PROTO_GATE|] `	return ksmbd_smb_negotiate_common(work, SMB_COM_NEGOTIATE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00476 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `static struct smb_version_cmds smb1_server_cmds[1] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [PROTO_GATE|] `	[SMB_COM_NEGOTIATE_EX]	= { .proc = smb1_negotiate, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00480 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `static int init_smb1_server(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	conn->vals = kmemdup(&smb1_server_values,`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `			     sizeof(smb1_server_values), GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	if (!conn->vals)`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	conn->ops = &smb1_server_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `	conn->cmds = smb1_server_cmds;`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `	conn->max_cmds = ARRAY_SIZE(smb1_server_cmds);`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	conn->smb1_conn = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `int ksmbd_init_smb_server(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	__le32 proto;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	proto = *(__le32 *)((struct smb_hdr *)conn->request_buf)->Protocol;`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	if (conn->need_neg == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `		/* After negotiate, reject SMB1 only on upgraded connections */`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `		if (proto == SMB1_PROTO_NUMBER && !conn->smb1_conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00506 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	conn->need_neg = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	if (proto == SMB1_PROTO_NUMBER)`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `		return init_smb1_server(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	return init_smb3_11_server(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `int ksmbd_populate_dot_dotdot_entries(struct ksmbd_work *work, int info_level,`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `				      struct ksmbd_file *dir,`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `				      struct ksmbd_dir_info *d_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `				      char *search_pattern,`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `				      int (*fn)(struct ksmbd_conn *, int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `						struct ksmbd_dir_info *,`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `						struct ksmbd_kstat *))`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	int i, rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	struct mnt_idmap *idmap = file_mnt_idmap(dir->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `	struct user_namespace *user_ns = file_mnt_user_ns(dir->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	for (i = 0; i < 2; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `		struct kstat kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `		struct ksmbd_kstat ksmbd_kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `		struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `		if (!dir->dot_dotdot[i]) { /* fill dot entry info */`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `			if (i == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `				d_info->name = ".";`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `				d_info->name_len = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `				dentry = dir->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `				d_info->name = "..";`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `				d_info->name_len = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `				dentry = dir->filp->f_path.dentry->d_parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `			if (!match_pattern(d_info->name, d_info->name_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `					   search_pattern)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `				dir->dot_dotdot[i] = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `			ksmbd_kstat.kstat = &kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `			ksmbd_vfs_fill_dentry_attrs(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `						    idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `						    user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `						    dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `						    &ksmbd_kstat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `			rc = fn(conn, info_level, d_info, &ksmbd_kstat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `			if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `			if (d_info->out_buf_len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `			dir->dot_dotdot[i] = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [PROTO_GATE|] `			if (d_info->flags & SMB2_RETURN_SINGLE_ENTRY) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00571 [NONE] `				d_info->out_buf_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ` * ksmbd_extract_shortname() - get shortname from long filename`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] ` * @longname:	source long filename`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ` * @shortname:	destination short filename`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] ` * Return:	shortname length or 0 when source long name is '.' or '..'`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] ` * TODO: Though this function conforms the restriction of 8.3 Filename spec,`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] ` * but the result is different with Windows 7's one. need to check.`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `int ksmbd_extract_shortname(struct ksmbd_conn *conn, const char *longname,`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `			    char *shortname)`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	const char *p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `	char base[9], extension[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `	char out[13] = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `	int baselen = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `	int extlen = 0, len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	unsigned int csum = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	const unsigned char *ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	bool dot_present = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	p = longname;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `	if ((*p == '.') || (!(strcmp(p, "..")))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `		/*no mangling required */`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `	p = strrchr(longname, '.');`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `	if (p == longname) { /*name starts with a dot*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [MEM_BOUNDS|] `		strscpy(extension, "___", sizeof(extension));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00611 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		if (p) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `			p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `			while (*p && extlen < 3) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `				if (*p != '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `					extension[extlen++] = toupper(*p);`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `				p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `			extension[extlen] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `			dot_present = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `	p = longname;`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `	if (*p == '.') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `		p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `		longname++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `	while (*p && (baselen < 5)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `		if (*p != '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `			base[baselen++] = toupper(*p);`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `		p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	base[baselen] = MAGIC_CHAR;`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [MEM_BOUNDS|] `	memcpy(out, base, baselen + 1);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00638 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `	ptr = longname;`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `	len = strlen(longname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `	for (; len > 0; len--, ptr++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `		csum += *ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `	csum = csum % (MANGLE_BASE * MANGLE_BASE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `	out[baselen + 1] = mangle(csum / MANGLE_BASE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	out[baselen + 2] = mangle(csum);`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `	out[baselen + 3] = PERIOD;`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	if (dot_present)`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [MEM_BOUNDS|] `		memcpy(out + baselen + 4, extension, 4);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00651 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `		out[baselen + 4] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `	smbConvertToUTF16((__le16 *)shortname, out, PATH_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `			  conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `	len = strlen(out) * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `	return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `static int __smb2_negotiate(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	return (conn->dialect >= SMB20_PROT_ID &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `		conn->dialect <= SMB311_PROT_ID);`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `#ifndef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `static int smb_handle_negotiate(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	struct smb_negotiate_rsp *neg_rsp = work->response_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `	ksmbd_debug(SMB, "Unsupported SMB1 protocol\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	if (ksmbd_iov_pin_rsp(work, (void *)neg_rsp + 4,`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `			      sizeof(struct smb_negotiate_unsupported_rsp) - 4))`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00675 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [PROTO_GATE|] `	neg_rsp->hdr.Status.CifsError = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00677 [NONE] `	neg_rsp->hdr.WordCount = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `	neg_rsp->DialectIndex = cpu_to_le16(work->conn->dialect);`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	neg_rsp->ByteCount = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `int ksmbd_smb_negotiate_common(struct ksmbd_work *work, unsigned int command)`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `	conn->dialect =`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `		ksmbd_negotiate_smb_dialect(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `	ksmbd_debug(SMB, "conn->dialect 0x%x\n", conn->dialect);`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [PROTO_GATE|] `	if (command == SMB2_NEGOTIATE_HE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00694 [NONE] `		ret = smb2_handle_negotiate(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [PROTO_GATE|] `	if (command == SMB_COM_NEGOTIATE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00699 [NONE] `		if (__smb2_negotiate(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `			 * SMB1 NEGOTIATE with SMB2 dialect(s): upgrade to`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `			 * SMB2. Force wildcard dialect 0x02FF so the client`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `			 * sends a full SMB2 NEGOTIATE for proper dialect`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `			 * selection.`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `			conn->dialect = SMB2X_PROT_ID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `			conn->smb1_conn = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `			kfree(conn->vals);`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `			conn->vals = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `			ret = init_smb3_11_server(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `			if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `				return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `			init_smb2_neg_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `			ksmbd_debug(SMB, "Upgrade to SMB2 negotiation\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `		return smb_handle_negotiate(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [ERROR_PATH|] `	pr_err("Unknown SMB negotiation command: %u\n", command);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00721 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00722 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `enum SHARED_MODE_ERRORS {`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `	SHARE_DELETE_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `	SHARE_READ_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `	SHARE_WRITE_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `	FILE_READ_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `	FILE_WRITE_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `	FILE_DELETE_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `static const char * const shared_mode_errors[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `	"Current access mode does not permit SHARE_DELETE",`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `	"Current access mode does not permit SHARE_READ",`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `	"Current access mode does not permit SHARE_WRITE",`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	"Desired access mode does not permit FILE_READ",`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	"Desired access mode does not permit FILE_WRITE",`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `	"Desired access mode does not permit FILE_DELETE",`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `static void smb_shared_mode_error(int error, struct ksmbd_file *prev_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `				  struct ksmbd_file *curr_fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `	ksmbd_debug(SMB, "%s\n", shared_mode_errors[error]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `	ksmbd_debug(SMB, "Current mode: 0x%x Desired mode: 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `		    prev_fp->saccess, curr_fp->daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `int ksmbd_smb_check_shared_mode(struct file *filp, struct ksmbd_file *curr_fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `	struct ksmbd_file *prev_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `	unsigned int loop_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	 * Lookup fp in master fp list, and check desired access and`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	 * shared mode between previous open and current open.`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [LOCK|] `	down_read(&curr_fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00761 [NONE] `	list_for_each_entry(prev_fp, &curr_fp->f_ci->m_fp_list, node) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `		 * Safety limit: if the list has more entries than is`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `		 * plausible (e.g. corrupted cycle), bail out to avoid`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `		 * spinning forever.  Also check for conn shutdown to`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `		 * allow kworkers to exit promptly during teardown.`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `		if (unlikely(++loop_count > 65536)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [ERROR_PATH|] `			pr_warn_ratelimited("ksmbd: m_fp_list loop limit hit (%u), possible list corruption\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00770 [NONE] `					    loop_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `			rc = -EBUSY;`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `		if (file_inode(filp) != file_inode(prev_fp->filp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `		if (filp == prev_fp->filp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `		if (ksmbd_stream_fd(prev_fp) && ksmbd_stream_fd(curr_fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `			if (strcmp(prev_fp->stream.name, curr_fp->stream.name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `		if (prev_fp->attrib_only != curr_fp->attrib_only)`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `		if (!(prev_fp->saccess & FILE_SHARE_DELETE_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `		    curr_fp->daccess & FILE_DELETE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `			smb_shared_mode_error(SHARE_DELETE_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `					      prev_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `					      curr_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `			rc = -EPERM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `		 * Only check FILE_SHARE_DELETE if stream opened and`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `		 * normal file opened.`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `		if (ksmbd_stream_fd(prev_fp) && !ksmbd_stream_fd(curr_fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `		if (!(prev_fp->saccess & FILE_SHARE_READ_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `		    curr_fp->daccess & (FILE_EXECUTE_LE | FILE_READ_DATA_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `			smb_shared_mode_error(SHARE_READ_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `					      prev_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `					      curr_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `			rc = -EPERM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `		if (!(prev_fp->saccess & FILE_SHARE_WRITE_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `		    curr_fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `			smb_shared_mode_error(SHARE_WRITE_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `					      prev_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `					      curr_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `			rc = -EPERM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `		if (prev_fp->daccess & (FILE_EXECUTE_LE | FILE_READ_DATA_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `		    !(curr_fp->saccess & FILE_SHARE_READ_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `			smb_shared_mode_error(FILE_READ_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `					      prev_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `					      curr_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `			rc = -EPERM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `		if (prev_fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `		    !(curr_fp->saccess & FILE_SHARE_WRITE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `			smb_shared_mode_error(FILE_WRITE_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `					      prev_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `					      curr_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `			rc = -EPERM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `		if (prev_fp->daccess & FILE_DELETE_LE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `		    !(curr_fp->saccess & FILE_SHARE_DELETE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `			smb_shared_mode_error(FILE_DELETE_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `					      prev_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `					      curr_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `			rc = -EPERM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `	up_read(&curr_fp->f_ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `bool is_asterisk(char *p)`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `	return p && p[0] == '*';`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `int __ksmbd_override_fsids(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `		struct ksmbd_share_config *share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `	struct ksmbd_user *user = sess->user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `	struct cred *cred;`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `	struct group_info *gi;`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `	unsigned int uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `	unsigned int gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `	 * If fsids are already overridden (e.g., smb2_set_info already`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `	 * called ksmbd_override_fsids before dispatching to a VFS helper`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `	 * that also calls it), just bump the depth counter and return.`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `	 * The matching ksmbd_revert_fsids will decrement without actually`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `	 * reverting credentials, preventing the BUG at kernel/cred.c:104.`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `	if (work->saved_cred) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `		work->saved_cred_depth++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `	uid = user_uid(user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `	gid = user_gid(user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `	if (share->force_uid != KSMBD_SHARE_INVALID_UID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `		uid = share->force_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `	if (share->force_gid != KSMBD_SHARE_INVALID_GID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `		gid = share->force_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `	cred = prepare_kernel_cred(&init_task);`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `	if (!cred)`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00891 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `	cred->fsuid = make_kuid(&init_user_ns, uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `	cred->fsgid = make_kgid(&init_user_ns, gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `	gi = groups_alloc(user->ngroups);`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `	if (!gi) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `		abort_creds(cred);`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00899 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `	for (i = 0; i < user->ngroups; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `		gi->gid[i] = make_kgid(&init_user_ns, user->sgid[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `	if (user->ngroups)`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		groups_sort(gi);`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `	set_groups(cred, gi);`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `	put_group_info(gi);`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `	if (!uid_eq(cred->fsuid, GLOBAL_ROOT_UID))`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `		cred->cap_effective = cap_drop_fs_set(cred->cap_effective);`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	work->saved_cred = override_creds(cred);`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `	if (!work->saved_cred) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `		abort_creds(cred);`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00917 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `int ksmbd_override_fsids(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `	return __ksmbd_override_fsids(work, work->tcon->share_conf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `void ksmbd_revert_fsids(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `	const struct cred *cred;`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [ERROR_PATH|] `	WARN_ON(!work->saved_cred);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00931 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `	 * If we are in a nested override (depth > 0), just decrement`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `	 * the counter without actually reverting credentials.  The`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `	 * outermost caller will do the real revert.`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	if (work->saved_cred_depth > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `		work->saved_cred_depth--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `	cred = current_cred();`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	revert_creds(work->saved_cred);`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	put_cred(cred);`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	work->saved_cred = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `__le32 smb_map_generic_desired_access(__le32 daccess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	if (daccess & FILE_GENERIC_READ_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `		daccess |= cpu_to_le32(GENERIC_READ_FLAGS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `		daccess &= ~FILE_GENERIC_READ_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `	if (daccess & FILE_GENERIC_WRITE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `		daccess |= cpu_to_le32(GENERIC_WRITE_FLAGS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `		daccess &= ~FILE_GENERIC_WRITE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `	if (daccess & FILE_GENERIC_EXECUTE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `		daccess |= cpu_to_le32(GENERIC_EXECUTE_FLAGS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `		daccess &= ~FILE_GENERIC_EXECUTE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	if (daccess & FILE_GENERIC_ALL_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `		daccess |= cpu_to_le32(GENERIC_ALL_FLAGS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `		daccess &= ~FILE_GENERIC_ALL_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	return daccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
