# Line-by-line Review: src/protocol/smb1/smb1misc.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
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
- L00007 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include "asn1.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include "nterr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include "smb1pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * check_smb_hdr() - check for valid smb request header`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` * @smb:        smb header to be checked`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` * check for valid smb signature and packet direction(request/response)`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` * TODO: properly check client authetication and tree authentication`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` * Return:      0 on success, otherwise 1`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `VISIBLE_IF_KUNIT int check_smb1_hdr(struct smb_hdr *smb)`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	/* does it have the right SMB "signature" ? */`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	if (*(__le32 *) smb->Protocol != SMB1_PROTO_NUMBER) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `		ksmbd_debug(SMB, "Bad protocol string signature header 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `				*(unsigned int *)smb->Protocol);`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	ksmbd_debug(SMB, "got SMB\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	/* if it's not a response then accept */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	/* TODO : check for oplock break */`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	if (!(smb->Flags & SMBFLG_RESPONSE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	ksmbd_debug(SMB, "Server sent request, not response\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `EXPORT_SYMBOL_IF_KUNIT(check_smb1_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `VISIBLE_IF_KUNIT int smb1_req_struct_size(struct smb_hdr *hdr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	int wc = hdr->WordCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	switch (hdr->Command) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [PROTO_GATE|] `	case SMB_COM_CREATE_DIRECTORY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00058 [PROTO_GATE|] `	case SMB_COM_DELETE_DIRECTORY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [PROTO_GATE|] `	case SMB_COM_QUERY_INFORMATION:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00060 [PROTO_GATE|] `	case SMB_COM_TREE_DISCONNECT:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00061 [PROTO_GATE|] `	case SMB_COM_NEGOTIATE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00062 [PROTO_GATE|] `	case SMB_COM_NT_CANCEL:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00063 [PROTO_GATE|] `	case SMB_COM_CHECK_DIRECTORY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00064 [PROTO_GATE|] `	case SMB_COM_PROCESS_EXIT:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00065 [PROTO_GATE|] `	case SMB_COM_QUERY_INFORMATION_DISK:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00066 [NONE] `		if (wc != 0x0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00068 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [PROTO_GATE|] `	case SMB_COM_FLUSH:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00070 [PROTO_GATE|] `	case SMB_COM_DELETE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00071 [PROTO_GATE|] `	case SMB_COM_RENAME:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00072 [PROTO_GATE|] `	case SMB_COM_ECHO:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00073 [PROTO_GATE|] `	case SMB_COM_FIND_CLOSE2:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00074 [PROTO_GATE|] `	case SMB_COM_QUERY_INFORMATION2:	/* A.2: wc = 1 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00075 [NONE] `		if (wc != 0x1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00077 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [PROTO_GATE|] `	case SMB_COM_LOGOFF_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00079 [NONE] `		if (wc != 0x2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00081 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [PROTO_GATE|] `	case SMB_COM_CLOSE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00083 [NONE] `		if (wc != 0x3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00085 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [PROTO_GATE|] `	case SMB_COM_TREE_CONNECT_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00087 [PROTO_GATE|] `	case SMB_COM_NT_RENAME:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00088 [NONE] `		if (wc != 0x4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00090 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [PROTO_GATE|] `	case SMB_COM_WRITE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00092 [NONE] `		if (wc != 0x5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00094 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [PROTO_GATE|] `	case SMB_COM_SETATTR:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00096 [PROTO_GATE|] `	case SMB_COM_LOCKING_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00097 [NONE] `		if (wc != 0x8)`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00099 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [PROTO_GATE|] `	case SMB_COM_SET_INFORMATION2:		/* A.2: wc = 7 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00101 [NONE] `		if (wc != 0x7)`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00103 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [PROTO_GATE|] `	case SMB_COM_TRANSACTION:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00105 [NONE] `		if (wc < 0xe)`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00107 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [PROTO_GATE|] `	case SMB_COM_SESSION_SETUP_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00109 [NONE] `		if (wc != 0xc && wc != 0xd)`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00111 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [PROTO_GATE|] `	case SMB_COM_OPEN_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00113 [PROTO_GATE|] `	case SMB_COM_TRANSACTION2:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00114 [NONE] `		if (wc != 0xf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00116 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [PROTO_GATE|] `	case SMB_COM_NT_TRANSACT:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00118 [NONE] `		/* MS-SMB §2.2.4.62.1: WC >= 19 (SetupWords variable) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `		if (wc < 0x13)`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00121 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [PROTO_GATE|] `	case SMB_COM_NT_TRANSACT_SECONDARY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00123 [NONE] `		/* MS-SMB §2.2.4.63.1: WC >= 18 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `		if (wc < 0x12)`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00126 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [PROTO_GATE|] `	case SMB_COM_NT_CREATE_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00128 [NONE] `		if (wc != 0x18)`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00130 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [PROTO_GATE|] `	case SMB_COM_READ_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00132 [NONE] `		if (wc != 0xa && wc != 0xc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00134 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [PROTO_GATE|] `	case SMB_COM_WRITE_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00136 [NONE] `		if (wc != 0xc && wc != 0xe)`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00138 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00141 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	return wc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb1_req_struct_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `VISIBLE_IF_KUNIT int smb1_get_byte_count(struct smb_hdr *hdr, unsigned int buflen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	int bc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	unsigned int offset = sizeof(struct smb_hdr) + hdr->WordCount * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	if (offset + 2 > buflen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	bc = le16_to_cpu(*(__le16 *)((char *)hdr + offset));`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	switch (hdr->Command) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [PROTO_GATE|] `	case SMB_COM_CLOSE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00159 [PROTO_GATE|] `	case SMB_COM_FLUSH:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00160 [PROTO_GATE|] `	case SMB_COM_READ_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00161 [PROTO_GATE|] `	case SMB_COM_TREE_DISCONNECT:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00162 [PROTO_GATE|] `	case SMB_COM_LOGOFF_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00163 [PROTO_GATE|] `	case SMB_COM_NT_CANCEL:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00164 [PROTO_GATE|] `	case SMB_COM_PROCESS_EXIT:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00165 [PROTO_GATE|] `	case SMB_COM_FIND_CLOSE2:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00166 [PROTO_GATE|] `	case SMB_COM_QUERY_INFORMATION2:	/* A.2: ByteCount must be 0 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00167 [PROTO_GATE|] `	case SMB_COM_SET_INFORMATION2:		/* A.2: ByteCount must be 0 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00168 [NONE] `		if (bc != 0x0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00170 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [PROTO_GATE|] `	case SMB_COM_LOCKING_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00172 [PROTO_GATE|] `	case SMB_COM_TRANSACTION:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00173 [PROTO_GATE|] `	case SMB_COM_TRANSACTION2:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00174 [PROTO_GATE|] `	case SMB_COM_NT_TRANSACT:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00175 [PROTO_GATE|] `	case SMB_COM_NT_TRANSACT_SECONDARY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00176 [PROTO_GATE|] `	case SMB_COM_ECHO:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00177 [PROTO_GATE|] `	case SMB_COM_SESSION_SETUP_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00178 [NONE] `		if (bc < 0x0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00180 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [PROTO_GATE|] `	case SMB_COM_WRITE_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00182 [NONE] `		if (bc < 0x1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00184 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [PROTO_GATE|] `	case SMB_COM_CREATE_DIRECTORY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00186 [PROTO_GATE|] `	case SMB_COM_DELETE_DIRECTORY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00187 [PROTO_GATE|] `	case SMB_COM_DELETE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00188 [PROTO_GATE|] `	case SMB_COM_RENAME:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00189 [PROTO_GATE|] `	case SMB_COM_QUERY_INFORMATION:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00190 [PROTO_GATE|] `	case SMB_COM_SETATTR:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00191 [PROTO_GATE|] `	case SMB_COM_OPEN_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00192 [PROTO_GATE|] `	case SMB_COM_NEGOTIATE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00193 [PROTO_GATE|] `	case SMB_COM_CHECK_DIRECTORY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00194 [NONE] `		if (bc < 0x2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00196 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [PROTO_GATE|] `	case SMB_COM_TREE_CONNECT_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00198 [PROTO_GATE|] `	case SMB_COM_WRITE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00199 [NONE] `		if (bc < 0x3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00201 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [PROTO_GATE|] `	case SMB_COM_NT_RENAME:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00203 [NONE] `		if (bc < 0x4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00205 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [PROTO_GATE|] `	case SMB_COM_NT_CREATE_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00207 [NONE] `		if (hdr->Flags2 & SMBFLG2_UNICODE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `			if (bc < 3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [ERROR_PATH|] `				return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00210 [NONE] `		} else if (bc < 2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00212 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	return bc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb1_get_byte_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ` * smb1_calc_size() - calculate expected SMB1 packet size from header fields`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ` * @hdr:	pointer to SMB1 header`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ` * @buflen:	total buffer length (rfc1002 len + 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ` * Return:	calculated packet size on success, (unsigned int)-1 on error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ` *		Callers must check for (unsigned int)-1 to detect malformed`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ` *		packets (e.g. invalid byte count or word count).`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `static unsigned int smb1_calc_size(struct smb_hdr *hdr, unsigned int buflen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	int len = sizeof(struct smb_hdr) - 4 + 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	int bc, struct_size = hdr->WordCount * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	len += struct_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	bc = smb1_get_byte_count(hdr, buflen);`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	if (bc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `		return (unsigned int)-1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	ksmbd_debug(SMB, "SMB1 byte count %d, struct size : %d\n", bc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		struct_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	len += bc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	ksmbd_debug(SMB, "SMB1 len %d\n", len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `static int smb1_get_data_len(struct smb_hdr *hdr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	int data_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	/* data offset check */`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	switch (hdr->Command) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [PROTO_GATE|] `	case SMB_COM_WRITE_ANDX:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00252 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `		struct smb_com_write_req *req = (struct smb_com_write_req *)hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `		data_len = le16_to_cpu(req->DataLengthLow);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		data_len |= (le16_to_cpu(req->DataLengthHigh) << 16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `		data_len += le16_to_cpu(req->DataOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [PROTO_GATE|] `	case SMB_COM_TRANSACTION:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00261 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		struct smb_com_trans_req *req = (struct smb_com_trans_req *)hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		data_len = le16_to_cpu(req->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `			le16_to_cpu(req->DataCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [PROTO_GATE|] `	case SMB_COM_TRANSACTION2:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00269 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `		struct smb_com_trans2_req *req =`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `				(struct smb_com_trans2_req *)hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `		data_len = le16_to_cpu(req->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `			le16_to_cpu(req->DataCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [PROTO_GATE|] `	case SMB_COM_NT_TRANSACT:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00278 [PROTO_GATE|] `	case SMB_COM_NT_TRANSACT_SECONDARY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00279 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `		struct smb_com_ntransact_req *req =`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `				(struct smb_com_ntransact_req *)hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `		data_len = le32_to_cpu(req->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `			le32_to_cpu(req->DataCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	return data_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `int ksmbd_smb1_check_message(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	struct smb_hdr *hdr = (struct smb_hdr *)work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	char *buf = work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	int command = hdr->Command;`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	__u32 clc_len;  /* calculated length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	__u32 len = get_rfc1002_len(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	int wc, data_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	if (check_smb1_hdr(hdr))`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	wc = smb1_req_struct_size(hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	if (wc == -EOPNOTSUPP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `		ksmbd_debug(SMB, "Not support cmd %x\n", command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	} else if (hdr->WordCount != wc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [ERROR_PATH|] `		pr_err("Invalid word count, %d not %d. cmd %x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00310 [NONE] `		       hdr->WordCount, wc, command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	data_len = smb1_get_data_len(hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	if (len < data_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [ERROR_PATH|] `		pr_err("Invalid data area length %u not %u. cmd : %x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00317 [NONE] `		       len, data_len, command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `	clc_len = smb1_calc_size(hdr, 4 + len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	if (clc_len == (unsigned int)-1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [ERROR_PATH|] `		pr_err("Invalid SMB1 message structure. cmd:%x\n", command);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00324 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `	if (len != clc_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `		 * smbclient may return wrong byte count in smb header.`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `		 * But allow it to avoid write failure with smbclient.`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [PROTO_GATE|] `		if (command == SMB_COM_WRITE_ANDX)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00332 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `		if (len > clc_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `			 * Reject packets significantly longer than expected.`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `			 * A small excess may be caused by padding or client`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `			 * quirks, but large excess suggests a malformed or`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `			 * malicious packet that could cause buffer confusion.`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `			if (len - clc_len > 512) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [ERROR_PATH|] `				pr_err("cli req excessively long, len %d not %d (excess %d). cmd:%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00343 [NONE] `				       len, clc_len, len - clc_len, command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `				return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `				"cli req too long, len %d not %d. cmd:%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `				len, clc_len, command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [ERROR_PATH|] `		pr_err("cli req too short, len %d not %d. cmd:%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00353 [NONE] `		       len, clc_len, command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `int smb_negotiate_request(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [PROTO_GATE|] `	return ksmbd_smb_negotiate_common(work, SMB_COM_NEGOTIATE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00364 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
