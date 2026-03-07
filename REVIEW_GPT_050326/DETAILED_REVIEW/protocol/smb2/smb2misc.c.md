# Line-by-line Review: src/protocol/smb2/smb2misc.c

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
- L00008 [NONE] `#include "nterr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "smb2pdu_internal.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `VISIBLE_IF_KUNIT int check_smb2_hdr(struct smb2_hdr *hdr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	 * Make sure that this really is an SMB, that it is a response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [PROTO_GATE|] `	if (hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00029 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `EXPORT_SYMBOL_IF_KUNIT(check_smb2_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` *  The following table defines the expected "StructureSize" of SMB2 requests`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` *  in order by SMB2 command.  This is similar to "wct" in SMB/CIFS requests.`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` *  Note that commands are defined in smb2pdu.h in le16 but the array below is`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *  indexed by command in host byte order`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [PROTO_GATE|] `static const __le16 smb2_req_struct_sizes[NUMBER_OF_SMB2_COMMANDS] = {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00042 [PROTO_GATE|] `	/* SMB2_NEGOTIATE */ cpu_to_le16(36),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00043 [PROTO_GATE|] `	/* SMB2_SESSION_SETUP */ cpu_to_le16(25),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00044 [PROTO_GATE|] `	/* SMB2_LOGOFF */ cpu_to_le16(4),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00045 [PROTO_GATE|] `	/* SMB2_TREE_CONNECT */ cpu_to_le16(9),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00046 [PROTO_GATE|] `	/* SMB2_TREE_DISCONNECT */ cpu_to_le16(4),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00047 [PROTO_GATE|] `	/* SMB2_CREATE */ cpu_to_le16(57),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00048 [PROTO_GATE|] `	/* SMB2_CLOSE */ cpu_to_le16(24),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00049 [PROTO_GATE|] `	/* SMB2_FLUSH */ cpu_to_le16(24),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00050 [PROTO_GATE|] `	/* SMB2_READ */ cpu_to_le16(49),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00051 [PROTO_GATE|] `	/* SMB2_WRITE */ cpu_to_le16(49),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00052 [PROTO_GATE|] `	/* SMB2_LOCK */ cpu_to_le16(48),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00053 [PROTO_GATE|] `	/* SMB2_IOCTL */ cpu_to_le16(57),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00054 [PROTO_GATE|] `	/* SMB2_CANCEL */ cpu_to_le16(4),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00055 [PROTO_GATE|] `	/* SMB2_ECHO */ cpu_to_le16(4),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00056 [PROTO_GATE|] `	/* SMB2_QUERY_DIRECTORY */ cpu_to_le16(33),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00057 [PROTO_GATE|] `	/* SMB2_CHANGE_NOTIFY */ cpu_to_le16(32),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00058 [PROTO_GATE|] `	/* SMB2_QUERY_INFO */ cpu_to_le16(41),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [PROTO_GATE|] `	/* SMB2_SET_INFO */ cpu_to_le16(33),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00060 [NONE] `	/* use 44 for lease break */`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [PROTO_GATE|] `	/* SMB2_OPLOCK_BREAK */ cpu_to_le16(36)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00062 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * The size of the variable area depends on the offset and length fields`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * located in different fields for various SMB2 requests. SMB2 requests`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` * with no variable length info, show an offset of zero for the offset field.`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [PROTO_GATE|] `static const bool has_smb2_data_area[NUMBER_OF_SMB2_COMMANDS] = {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00070 [PROTO_GATE|] `	/* SMB2_NEGOTIATE */ true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00071 [PROTO_GATE|] `	/* SMB2_SESSION_SETUP */ true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00072 [PROTO_GATE|] `	/* SMB2_LOGOFF */ false,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00073 [PROTO_GATE|] `	/* SMB2_TREE_CONNECT */	true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00074 [PROTO_GATE|] `	/* SMB2_TREE_DISCONNECT */ false,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00075 [PROTO_GATE|] `	/* SMB2_CREATE */ true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00076 [PROTO_GATE|] `	/* SMB2_CLOSE */ false,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00077 [PROTO_GATE|] `	/* SMB2_FLUSH */ false,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00078 [PROTO_GATE|] `	/* SMB2_READ */	true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00079 [PROTO_GATE|] `	/* SMB2_WRITE */ true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00080 [PROTO_GATE|] `	/* SMB2_LOCK */	true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00081 [PROTO_GATE|] `	/* SMB2_IOCTL */ true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00082 [PROTO_GATE|] `	/* SMB2_CANCEL */ false, /* BB CHECK this not listed in documentation */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00083 [PROTO_GATE|] `	/* SMB2_ECHO */ false,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00084 [PROTO_GATE|] `	/* SMB2_QUERY_DIRECTORY */ true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00085 [PROTO_GATE|] `	/* SMB2_CHANGE_NOTIFY */ false,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00086 [PROTO_GATE|] `	/* SMB2_QUERY_INFO */ true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00087 [PROTO_GATE|] `	/* SMB2_SET_INFO */ true,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00088 [PROTO_GATE|] `	/* SMB2_OPLOCK_BREAK */ false`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00089 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` * Set length of the data area and the offset to arguments.`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * if they are invalid, return error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `static int smb2_get_data_area_len(unsigned int *off, unsigned int *len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `				  struct smb2_hdr *hdr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	*off = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	*len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	 * Following commands have data areas so we have to get the location`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	 * of the data buffer offset and data buffer length for the particular`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	 * command.`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	switch (hdr->Command) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [PROTO_GATE|] `	case SMB2_SESSION_SETUP:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00110 [NONE] `		*off = max_t(unsigned short int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `			     le16_to_cpu(((struct smb2_sess_setup_req *)hdr)->SecurityBufferOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `			     offsetof(struct smb2_sess_setup_req, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `		*len = le16_to_cpu(((struct smb2_sess_setup_req *)hdr)->SecurityBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [PROTO_GATE|] `	case SMB2_TREE_CONNECT:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00116 [NONE] `		*off = max_t(unsigned short int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `			     le16_to_cpu(((struct smb2_tree_connect_req *)hdr)->PathOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `			     offsetof(struct smb2_tree_connect_req, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `		*len = le16_to_cpu(((struct smb2_tree_connect_req *)hdr)->PathLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [PROTO_GATE|] `	case SMB2_CREATE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00122 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `		unsigned short int name_off =`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `			max_t(unsigned short int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `			      le16_to_cpu(((struct smb2_create_req *)hdr)->NameOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `			      offsetof(struct smb2_create_req, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `		unsigned short int name_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `			le16_to_cpu(((struct smb2_create_req *)hdr)->NameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `		if (((struct smb2_create_req *)hdr)->CreateContextsLength) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `			*off = le32_to_cpu(((struct smb2_create_req *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `				hdr)->CreateContextsOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `			*len = le32_to_cpu(((struct smb2_create_req *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `				hdr)->CreateContextsLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `			if (!name_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `			if (name_off + name_len < (u64)*off + *len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `		*off = name_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `		*len = name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [PROTO_GATE|] `	case SMB2_QUERY_INFO:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00147 [NONE] `		*off = max_t(unsigned int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `			     le16_to_cpu(((struct smb2_query_info_req *)hdr)->InputBufferOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `			     offsetof(struct smb2_query_info_req, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `		*len = le32_to_cpu(((struct smb2_query_info_req *)hdr)->InputBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [PROTO_GATE|] `	case SMB2_SET_INFO:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00153 [NONE] `		*off = max_t(unsigned int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `			     le16_to_cpu(((struct smb2_set_info_req *)hdr)->BufferOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `			     offsetof(struct smb2_set_info_req, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `		*len = le32_to_cpu(((struct smb2_set_info_req *)hdr)->BufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [PROTO_GATE|] `	case SMB2_READ:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00159 [NONE] `		*off = max_t(unsigned short int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `			     le16_to_cpu(((struct smb2_read_req *)hdr)->ReadChannelInfoOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `			     offsetof(struct smb2_read_req, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		*len = le16_to_cpu(((struct smb2_read_req *)hdr)->ReadChannelInfoLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [PROTO_GATE|] `	case SMB2_WRITE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00165 [NONE] `		if (((struct smb2_write_req *)hdr)->DataOffset ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		    ((struct smb2_write_req *)hdr)->Length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `			*off = max_t(unsigned short int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `				     le16_to_cpu(((struct smb2_write_req *)hdr)->DataOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `				     offsetof(struct smb2_write_req, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `			*len = le32_to_cpu(((struct smb2_write_req *)hdr)->Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `		*off = le16_to_cpu(((struct smb2_write_req *)hdr)->WriteChannelInfoOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `		*len = le16_to_cpu(((struct smb2_write_req *)hdr)->WriteChannelInfoLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [PROTO_GATE|] `	case SMB2_QUERY_DIRECTORY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00178 [NONE] `		*off = max_t(unsigned short int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `			     le16_to_cpu(((struct smb2_query_directory_req *)hdr)->FileNameOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `			     offsetof(struct smb2_query_directory_req, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		*len = le16_to_cpu(((struct smb2_query_directory_req *)hdr)->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [PROTO_GATE|] `	case SMB2_LOCK:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00184 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `		unsigned short lock_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `		lock_count = le16_to_cpu(((struct smb2_lock_req *)hdr)->LockCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `		if (lock_count > KSMBD_MAX_LOCK_COUNT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `			ksmbd_debug(SMB, "Too many lock elements: %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `				    lock_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00192 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		if (lock_count > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `			*off = offsetof(struct smb2_lock_req, locks);`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `			*len = sizeof(struct smb2_lock_element) * lock_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [PROTO_GATE|] `	case SMB2_IOCTL:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00200 [NONE] `		*off = max_t(unsigned short int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `			     le32_to_cpu(((struct smb2_ioctl_req *)hdr)->InputOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `			     offsetof(struct smb2_ioctl_req, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `		*len = le32_to_cpu(((struct smb2_ioctl_req *)hdr)->InputCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `		ksmbd_debug(SMB, "no length check for command\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	if (*off > 4096) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `		ksmbd_debug(SMB, "offset %d too large\n", *off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	} else if ((u64)*off + *len > MAX_STREAM_PROT_LEN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		ksmbd_debug(SMB, "Request is larger than maximum stream protocol length(%u): %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `			    MAX_STREAM_PROT_LEN, (u64)*off + *len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ` * Calculate the size of the SMB message based on the fixed header`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ` * portion, the number of word parameters and the data portion of the message.`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `VISIBLE_IF_KUNIT int smb2_calc_size(void *buf, unsigned int *len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	struct smb2_pdu *pdu = (struct smb2_pdu *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	struct smb2_hdr *hdr = &pdu->hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	unsigned int offset; /* the offset from the beginning of SMB to data area */`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	unsigned int data_length; /* the length of the variable length data area */`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	/* Structure Size has already been checked to make sure it is 64 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	*len = le16_to_cpu(hdr->StructureSize);`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	 * StructureSize2, ie length of fixed parameter area has already`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	 * been checked to make sure it is the correct length.`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	*len += le16_to_cpu(pdu->StructureSize2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	 * StructureSize2 of smb2_lock pdu is set to 48, indicating`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	 * the size of smb2 lock request with single smb2_lock_element`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	 * regardless of number of locks. Subtract single`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	 * smb2_lock_element for correct buffer size check.`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [PROTO_GATE|] `	if (hdr->Command == SMB2_LOCK)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00249 [NONE] `		*len -= sizeof(struct smb2_lock_element);`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	if (has_smb2_data_area[le16_to_cpu(hdr->Command)] == false)`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [ERROR_PATH|] `		goto calc_size_exit;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00253 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	ret = smb2_get_data_area_len(&offset, &data_length, hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	ksmbd_debug(SMB, "SMB2 data length %u offset %u\n", data_length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `		    offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	if (data_length > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		 * Check to make sure that data area begins after fixed area,`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `		 * Note that last byte of the fixed area is part of data area`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		 * for some commands, typically those with odd StructureSize,`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		 * so we must add one to the calculation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		if (offset + 1 < *len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `				    "data area offset %d overlaps SMB2 header %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `				    offset + 1, *len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00272 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `		*len = offset + data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `calc_size_exit:`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	ksmbd_debug(SMB, "SMB2 len %u\n", *len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_calc_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `static inline u64 smb2_query_info_req_len(struct smb2_query_info_req *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	return (u64)le32_to_cpu(h->InputBufferLength) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `		le32_to_cpu(h->OutputBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `static inline u64 smb2_set_info_req_len(struct smb2_set_info_req *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	return le32_to_cpu(h->BufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `static inline u64 smb2_read_req_len(struct smb2_read_req *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	return le32_to_cpu(h->Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `static inline u64 smb2_write_req_len(struct smb2_write_req *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	return le32_to_cpu(h->Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `static inline u64 smb2_query_dir_req_len(struct smb2_query_directory_req *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	return le32_to_cpu(h->OutputBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `static inline u64 smb2_ioctl_req_len(struct smb2_ioctl_req *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	return (u64)le32_to_cpu(h->InputCount) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `		le32_to_cpu(h->OutputCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `static inline u64 smb2_ioctl_resp_len(struct smb2_ioctl_req *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	return (u64)le32_to_cpu(h->MaxInputResponse) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `		le32_to_cpu(h->MaxOutputResponse);`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `VISIBLE_IF_KUNIT int smb2_validate_credit_charge(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `						  struct smb2_hdr *hdr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	u64 req_len = 0, expect_resp_len = 0, max_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	unsigned int calc_credit_num;`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [PROTO_GATE|] `	unsigned short credit_charge = le16_to_cpu(hdr->CreditCharge);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00327 [NONE] `	void *__hdr = hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	switch (hdr->Command) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [PROTO_GATE|] `	case SMB2_QUERY_INFO:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00332 [NONE] `		req_len = smb2_query_info_req_len(__hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [PROTO_GATE|] `	case SMB2_SET_INFO:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00335 [NONE] `		req_len = smb2_set_info_req_len(__hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [PROTO_GATE|] `	case SMB2_READ:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00338 [NONE] `		req_len = smb2_read_req_len(__hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [PROTO_GATE|] `	case SMB2_WRITE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00341 [NONE] `		req_len = smb2_write_req_len(__hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [PROTO_GATE|] `	case SMB2_QUERY_DIRECTORY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00344 [NONE] `		req_len = smb2_query_dir_req_len(__hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [PROTO_GATE|] `	case SMB2_IOCTL:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00347 [NONE] `		req_len = smb2_ioctl_req_len(__hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `		expect_resp_len = smb2_ioctl_resp_len(__hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [PROTO_GATE|] `	case SMB2_CANCEL:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00351 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `		 * For unknown/unhandled commands, default to a credit charge`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `		 * of 1 (the minimum). This is intentional per MS-SMB2:`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		 * commands without large payloads require only a single credit.`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `			    "Unknown command %u in credit charge validation, defaulting to 1\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `			    le16_to_cpu(hdr->Command));`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `		req_len = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	credit_charge = max_t(unsigned short, credit_charge, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	max_len = max_t(u64, req_len, expect_resp_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [PROTO_GATE|] `	calc_credit_num = DIV_ROUND_UP(max_len, SMB2_MAX_BUFFER_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00368 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `		    "credit_check: cmd=%u charge=%u calc=%u req_len=%llu resp_len=%llu total=%u out=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `		    le16_to_cpu(hdr->Command), credit_charge, calc_credit_num,`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `		    req_len, expect_resp_len, conn->total_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `		    conn->outstanding_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	if (credit_charge < calc_credit_num) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `		ksmbd_debug(SMB, "Insufficient credit charge, given: %d, needed: %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `			    credit_charge, calc_credit_num);`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	} else if (credit_charge > conn->vals->max_credits) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `		ksmbd_debug(SMB, "Too large credit charge: %d\n", credit_charge);`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `		    "credit_check: lock_enter cmd=%u charge=%u total=%u out=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `		    le16_to_cpu(hdr->Command), credit_charge, conn->total_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `		    conn->outstanding_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [LOCK|] `	spin_lock(&conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00389 [NONE] `	if (credit_charge > conn->total_credits) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `		ksmbd_debug(SMB, "Insufficient credits granted, given: %u, granted: %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `			    credit_charge, conn->total_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `		ret = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	} else if ((u64)conn->outstanding_credits + credit_charge > conn->total_credits) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `		ksmbd_debug(SMB, "Limits exceeding the maximum allowable outstanding requests, given : %u, pending : %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `			    credit_charge, conn->outstanding_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `		ret = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `		conn->outstanding_credits += credit_charge;`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `		    "credit_check: lock_exit cmd=%u ret=%d total=%u out=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `		    le16_to_cpu(hdr->Command), ret, conn->total_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `		    conn->outstanding_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [LOCK|] `	spin_unlock(&conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_validate_credit_charge);`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `int ksmbd_smb2_check_message(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	struct smb2_pdu *pdu = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	struct smb2_hdr *hdr = &pdu->hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	int command;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	__u32 clc_len;  /* calculated length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	__u32 len = get_rfc1002_len(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [PROTO_GATE|] `	__u32 req_struct_size, next_cmd = le32_to_cpu(hdr->NextCommand);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00418 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	if ((u64)work->next_smb2_rcv_hdr_off + next_cmd > len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [ERROR_PATH|] `		pr_err("next command(%u) offset exceeds smb msg size\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00421 [NONE] `				next_cmd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	if (next_cmd > 0 && (next_cmd & 7)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [ERROR_PATH|] `		pr_err("next command(%u) is not 8-byte aligned\n", next_cmd);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00427 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	if (next_cmd > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `		len = next_cmd;`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `		if (len < sizeof(struct smb2_hdr) + 2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [ERROR_PATH|] `			pr_err("compound sub-PDU too small: %u\n", len);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00434 [NONE] `			return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	} else if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `		len -= work->next_smb2_rcv_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	if (check_smb2_hdr(hdr))`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [PROTO_GATE|] `	if (hdr->StructureSize != SMB2_HEADER_STRUCTURE_SIZE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00443 [NONE] `		ksmbd_debug(SMB, "Illegal structure size %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `			    le16_to_cpu(hdr->StructureSize));`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	command = le16_to_cpu(hdr->Command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [PROTO_GATE|] `	if (command >= NUMBER_OF_SMB2_COMMANDS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00450 [NONE] `		ksmbd_debug(SMB, "Illegal SMB2 command %d\n", command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	if (smb2_req_struct_sizes[command] != pdu->StructureSize2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [PROTO_GATE|] `		if (!(command == SMB2_OPLOCK_BREAK_HE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00456 [NONE] `		    (le16_to_cpu(pdu->StructureSize2) == OP_BREAK_STRUCT_SIZE_20 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `		    le16_to_cpu(pdu->StructureSize2) == OP_BREAK_STRUCT_SIZE_21))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `			/* special case for SMB2.1 lease break message */`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `				"Illegal request size %u for command %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `				le16_to_cpu(pdu->StructureSize2), command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `			return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	req_struct_size = le16_to_cpu(pdu->StructureSize2) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [PROTO_GATE|] `		__SMB2_HEADER_STRUCTURE_SIZE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00468 [PROTO_GATE|] `	if (command == SMB2_LOCK_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00469 [NONE] `		req_struct_size -= sizeof(struct smb2_lock_element);`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	if (req_struct_size > len + 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	if (smb2_calc_size(hdr, &clc_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	if (len != clc_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `		/* client can return one byte more due to implied bcc[0] */`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `		if (clc_len == len + 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [ERROR_PATH|] `			goto validate_credit;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00481 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `		 * Some windows servers (win2016) will pad also the final`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `		 * PDU in a compound to 8 bytes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `		if (ALIGN(clc_len, 8) == len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [ERROR_PATH|] `			goto validate_credit;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `		 * Allow a message that padded to 8byte boundary.`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `		 * Linux 4.19.217 with smb 3.0.2 are sometimes`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `		 * sending messages where the cls_len is exactly`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `		 * 8 bytes less than len.`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `		if (clc_len < len && (len - clc_len) <= 8)`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [ERROR_PATH|] `			goto validate_credit;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `		 * Negotiate request size cannot be precisely calculated`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `		 * because it contains a variable-length Dialects array`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `		 * and optional negotiate contexts (SMB3.1.1).`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [PROTO_GATE|] `		if (command == SMB2_NEGOTIATE_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00504 [ERROR_PATH|] `			goto validate_credit;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00505 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [PROTO_GATE|] `		if (command == SMB2_SESSION_SETUP_HE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00507 [NONE] `			struct smb2_sess_setup_req *req =`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `				(struct smb2_sess_setup_req *)hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [ERROR_PATH|] `			pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00511 [NONE] `				"SESSION_SETUP size mismatch: len=%u calc=%u sec_off=%u sec_len=%u struct2=%u flags=0x%x mid=%llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `				len, clc_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `				le16_to_cpu(req->SecurityBufferOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `				le16_to_cpu(req->SecurityBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `				le16_to_cpu(pdu->StructureSize2),`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `				req->Flags, le64_to_cpu(hdr->MessageId));`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [ERROR_PATH|] `			pr_err_ratelimited("SESSION_SETUP len mismatch tolerated for auth parse\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00518 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `			 * Be tolerant here and let smb2_sess_setup() perform`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `			 * final bounds validation/clamping for the security blob.`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [ERROR_PATH|] `			goto validate_credit;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00524 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00527 [NONE] `			    "cli req too short, len %d not %d. cmd:%d mid:%llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `			    len, clc_len, command,`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `			    le64_to_cpu(hdr->MessageId));`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `validate_credit:`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [PROTO_GATE|] `	if (work->conn->vals->capabilities & SMB2_GLOBAL_CAP_LARGE_MTU) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00536 [NONE] `		int credit_rc = smb2_validate_credit_charge(work->conn, hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `		if (credit_rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `			return credit_rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `		 * smb2_validate_credit_charge() deliberately skips`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [PROTO_GATE|] `		 * outstanding credit charging for SMB2_CANCEL.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00543 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [PROTO_GATE|] `		if (hdr->Command != SMB2_CANCEL)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00545 [NONE] `			work->credit_charge_tracked = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `		 * SMB 2.0.2 doesn't support multi-credit requests`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [PROTO_GATE|] `		 * (CreditCharge is reserved/zero per spec). Charge 1`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00550 [NONE] `		 * credit per request to keep outstanding_credits in`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `		 * sync with smb2_set_rsp_credits().`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [LOCK|] `		spin_lock(&work->conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00554 [NONE] `		if (work->conn->outstanding_credits + 1 >`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `		    work->conn->total_credits) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [LOCK|] `			spin_unlock(&work->conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00557 [ERROR_PATH|] `			pr_err_ratelimited("Outstanding credit overflow, total %u outstanding %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00558 [NONE] `					   work->conn->total_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `					   work->conn->outstanding_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `			return 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `		work->conn->outstanding_credits++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `		work->credit_charge_tracked = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [LOCK|] `		spin_unlock(&work->conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00565 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `int smb2_negotiate_request(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [PROTO_GATE|] `	return ksmbd_smb_negotiate_common(work, SMB2_NEGOTIATE_HE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00573 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
