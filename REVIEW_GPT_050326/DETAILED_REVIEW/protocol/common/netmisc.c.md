# Line-by-line Review: src/protocol/common/netmisc.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (c) International Business Machines  Corp., 2002,2008`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Author(s): Steve French (sfrench@us.ibm.com)`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Error mapping routines from Samba libsmb/errormap.c`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *   Copyright (C) Andrew Tridgell 2001`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "smberr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include "nterr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `/*****************************************************************************`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` * convert a NT status code to a dos class/code`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` *****************************************************************************/`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `/* NT status -> dos error map */`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `static const struct {`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	__u8 dos_class;`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `	__u16 dos_code;`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	__u32 ntstatus;`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `} ntstatus_to_dos_map[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [PROTO_GATE|] `	ERRDOS, ERRgeneral, NT_STATUS_UNSUCCESSFUL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00026 [PROTO_GATE|] `	ERRDOS, ERRbadfunc, NT_STATUS_NOT_IMPLEMENTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00027 [PROTO_GATE|] `	ERRDOS, ERRinvlevel, NT_STATUS_INVALID_INFO_CLASS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00028 [PROTO_GATE|] `	ERRDOS, 24, NT_STATUS_INFO_LENGTH_MISMATCH}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00029 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ACCESS_VIOLATION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00030 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_IN_PAGE_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00031 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PAGEFILE_QUOTA}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00032 [PROTO_GATE|] `	ERRDOS, ERRbadfid, NT_STATUS_INVALID_HANDLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00033 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_INITIAL_STACK}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00034 [PROTO_GATE|] `	ERRDOS, 193, NT_STATUS_BAD_INITIAL_PC}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00035 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_CID}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00036 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_TIMER_NOT_CANCELED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00037 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00038 [PROTO_GATE|] `	ERRDOS, ERRbadfile, NT_STATUS_NO_SUCH_DEVICE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00039 [PROTO_GATE|] `	ERRDOS, ERRbadfile, NT_STATUS_NO_SUCH_FILE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00040 [PROTO_GATE|] `	ERRDOS, ERRbadfunc, NT_STATUS_INVALID_DEVICE_REQUEST}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00041 [PROTO_GATE|] `	ERRDOS, 38, NT_STATUS_END_OF_FILE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00042 [PROTO_GATE|] `	ERRDOS, 34, NT_STATUS_WRONG_VOLUME}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00043 [PROTO_GATE|] `	ERRDOS, 21, NT_STATUS_NO_MEDIA_IN_DEVICE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00044 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNRECOGNIZED_MEDIA}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00045 [PROTO_GATE|] `	ERRDOS, 27, NT_STATUS_NONEXISTENT_SECTOR},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00046 [NONE] `/*	{ This NT error code was 'sqashed'`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [PROTO_GATE|] ` *	 from NT_STATUS_MORE_PROCESSING_REQUIRED to NT_STATUS_OK`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00048 [NONE] ` *	 during the session setup }`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [PROTO_GATE|] `	ERRDOS, ERRnomem, NT_STATUS_NO_MEMORY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00052 [PROTO_GATE|] `	ERRDOS, 487, NT_STATUS_CONFLICTING_ADDRESSES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00053 [PROTO_GATE|] `	ERRDOS, 487, NT_STATUS_NOT_MAPPED_VIEW}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00054 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_UNABLE_TO_FREE_VM}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00055 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_UNABLE_TO_DELETE_SECTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00056 [PROTO_GATE|] `	ERRDOS, 2142, NT_STATUS_INVALID_SYSTEM_SERVICE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00057 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ILLEGAL_INSTRUCTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00058 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_INVALID_LOCK_SEQUENCE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_INVALID_VIEW_SIZE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00060 [PROTO_GATE|] `	ERRDOS, 193, NT_STATUS_INVALID_FILE_FOR_SECTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00061 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_ALREADY_COMMITTED},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00062 [NONE] `/*	{ This NT error code was 'sqashed'`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [PROTO_GATE|] ` *	 from NT_STATUS_ACCESS_DENIED to NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00064 [NONE] ` *	 during the session setup }`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_ACCESS_DENIED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00068 [PROTO_GATE|] `	ERRDOS, 111, NT_STATUS_BUFFER_TOO_SMALL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00069 [PROTO_GATE|] `	ERRDOS, ERRbadfid, NT_STATUS_OBJECT_TYPE_MISMATCH}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00070 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NONCONTINUABLE_EXCEPTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00071 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_DISPOSITION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00072 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNWIND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00073 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_STACK}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00074 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_UNWIND_TARGET}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00075 [PROTO_GATE|] `	ERRDOS, 158, NT_STATUS_NOT_LOCKED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00076 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PARITY_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00077 [PROTO_GATE|] `	ERRDOS, 487, NT_STATUS_UNABLE_TO_DECOMMIT_VM}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00078 [PROTO_GATE|] `	ERRDOS, 487, NT_STATUS_NOT_COMMITTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00079 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_PORT_ATTRIBUTES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00080 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PORT_MESSAGE_TOO_LONG}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00081 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_MIX}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00082 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_QUOTA_LOWER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00083 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DISK_CORRUPT_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00084 [NONE] `	/* mapping changed since shell does lookup on * expects FileNotFound */`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [PROTO_GATE|] `	ERRDOS, ERRbadfile, NT_STATUS_OBJECT_NAME_INVALID}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00086 [PROTO_GATE|] `	ERRDOS, ERRbadfile, NT_STATUS_OBJECT_NAME_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00087 [PROTO_GATE|] `	ERRDOS, ERRalreadyexists, NT_STATUS_OBJECT_NAME_COLLISION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00088 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_HANDLE_NOT_WAITABLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00089 [PROTO_GATE|] `	ERRDOS, ERRbadfid, NT_STATUS_PORT_DISCONNECTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00090 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DEVICE_ALREADY_ATTACHED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00091 [PROTO_GATE|] `	ERRDOS, 161, NT_STATUS_OBJECT_PATH_INVALID}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00092 [PROTO_GATE|] `	ERRDOS, ERRbadpath, NT_STATUS_OBJECT_PATH_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00093 [PROTO_GATE|] `	ERRDOS, 161, NT_STATUS_OBJECT_PATH_SYNTAX_BAD}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00094 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DATA_OVERRUN}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00095 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DATA_LATE_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00096 [PROTO_GATE|] `	ERRDOS, 23, NT_STATUS_DATA_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00097 [PROTO_GATE|] `	ERRDOS, 23, NT_STATUS_CRC_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00098 [PROTO_GATE|] `	ERRDOS, ERRnomem, NT_STATUS_SECTION_TOO_BIG}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00099 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_PORT_CONNECTION_REFUSED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00100 [PROTO_GATE|] `	ERRDOS, ERRbadfid, NT_STATUS_INVALID_PORT_HANDLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00101 [PROTO_GATE|] `	ERRDOS, ERRbadshare, NT_STATUS_SHARING_VIOLATION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00102 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_QUOTA_EXCEEDED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00103 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PAGE_PROTECTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00104 [PROTO_GATE|] `	ERRDOS, 288, NT_STATUS_MUTANT_NOT_OWNED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00105 [PROTO_GATE|] `	ERRDOS, 298, NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00106 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_PORT_ALREADY_SET}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00107 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_SECTION_NOT_IMAGE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00108 [PROTO_GATE|] `	ERRDOS, 156, NT_STATUS_SUSPEND_COUNT_EXCEEDED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00109 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_THREAD_IS_TERMINATING}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00110 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_BAD_WORKING_SET_LIMIT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00111 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INCOMPATIBLE_FILE_MAP}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00112 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_SECTION_PROTECTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00113 [PROTO_GATE|] `	ERRDOS, ERReasnotsupported, NT_STATUS_EAS_NOT_SUPPORTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00114 [PROTO_GATE|] `	ERRDOS, 255, NT_STATUS_EA_TOO_LARGE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00115 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NONEXISTENT_EA_ENTRY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00116 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_EAS_ON_FILE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00117 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_EA_CORRUPT_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00118 [PROTO_GATE|] `	ERRDOS, ERRlock, NT_STATUS_FILE_LOCK_CONFLICT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00119 [PROTO_GATE|] `	ERRDOS, ERRlock, NT_STATUS_LOCK_NOT_GRANTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00120 [PROTO_GATE|] `	ERRDOS, ERRbadfile, NT_STATUS_DELETE_PENDING}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00121 [PROTO_GATE|] `	ERRDOS, ERRunsup, NT_STATUS_CTL_FILE_NOT_SUPPORTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00122 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNKNOWN_REVISION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00123 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_REVISION_MISMATCH}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00124 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_OWNER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00125 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_PRIMARY_GROUP}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00126 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_IMPERSONATION_TOKEN}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00127 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CANT_DISABLE_MANDATORY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00128 [PROTO_GATE|] `	ERRDOS, 2215, NT_STATUS_NO_LOGON_SERVERS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00129 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_SUCH_LOGON_SESSION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00130 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_SUCH_PRIVILEGE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00131 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_PRIVILEGE_NOT_HELD}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00132 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_ACCOUNT_NAME}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00133 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_USER_EXISTS},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00134 [NONE] `/*	{ This NT error code was 'sqashed'`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [PROTO_GATE|] ` *	 from NT_STATUS_NO_SUCH_USER to NT_STATUS_LOGON_FAILURE`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00136 [NONE] ` *	 during the session setup }`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_NO_SUCH_USER}, { /* could map to 2238 */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00140 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_GROUP_EXISTS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00141 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_SUCH_GROUP}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00142 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MEMBER_IN_GROUP}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00143 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MEMBER_NOT_IN_GROUP}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00144 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LAST_ADMIN},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00145 [NONE] `/*	{ This NT error code was 'sqashed'`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [PROTO_GATE|] ` *	 from NT_STATUS_WRONG_PASSWORD to NT_STATUS_LOGON_FAILURE`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00147 [NONE] ` *	 during the session setup }`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [PROTO_GATE|] `	ERRSRV, ERRbadpw, NT_STATUS_WRONG_PASSWORD}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00151 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ILL_FORMED_PASSWORD}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00152 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PASSWORD_RESTRICTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00153 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_LOGON_FAILURE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00154 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ACCOUNT_RESTRICTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00155 [PROTO_GATE|] `	ERRSRV, ERRbadLogonTime, NT_STATUS_INVALID_LOGON_HOURS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00156 [PROTO_GATE|] `	ERRSRV, ERRbadclient, NT_STATUS_INVALID_WORKSTATION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00157 [PROTO_GATE|] `	ERRSRV, ERRpasswordExpired, NT_STATUS_PASSWORD_EXPIRED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00158 [PROTO_GATE|] `	ERRSRV, ERRaccountexpired, NT_STATUS_ACCOUNT_DISABLED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00159 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NONE_MAPPED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00160 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_TOO_MANY_LUIDS_REQUESTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00161 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LUIDS_EXHAUSTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00162 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_SUB_AUTHORITY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00163 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_ACL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00164 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_SID}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00165 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_SECURITY_DESCR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00166 [PROTO_GATE|] `	ERRDOS, 127, NT_STATUS_PROCEDURE_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00167 [PROTO_GATE|] `	ERRDOS, 193, NT_STATUS_INVALID_IMAGE_FORMAT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00168 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_TOKEN}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00169 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_INHERITANCE_ACL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00170 [PROTO_GATE|] `	ERRDOS, 158, NT_STATUS_RANGE_NOT_LOCKED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00171 [PROTO_GATE|] `	ERRDOS, 112, NT_STATUS_DISK_FULL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00172 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_SERVER_DISABLED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00173 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_SERVER_NOT_DISABLED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00174 [PROTO_GATE|] `	ERRDOS, 68, NT_STATUS_TOO_MANY_GUIDS_REQUESTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00175 [PROTO_GATE|] `	ERRDOS, 259, NT_STATUS_GUIDS_EXHAUSTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00176 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_ID_AUTHORITY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00177 [PROTO_GATE|] `	ERRDOS, 259, NT_STATUS_AGENTS_EXHAUSTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00178 [PROTO_GATE|] `	ERRDOS, 154, NT_STATUS_INVALID_VOLUME_LABEL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00179 [PROTO_GATE|] `	ERRDOS, 14, NT_STATUS_SECTION_NOT_EXTENDED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00180 [PROTO_GATE|] `	ERRDOS, 487, NT_STATUS_NOT_MAPPED_DATA}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00181 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_RESOURCE_DATA_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00182 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_RESOURCE_TYPE_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00183 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_RESOURCE_NAME_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00184 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ARRAY_BOUNDS_EXCEEDED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00185 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOAT_DENORMAL_OPERAND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00186 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOAT_DIVIDE_BY_ZERO}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00187 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOAT_INEXACT_RESULT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00188 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOAT_INVALID_OPERATION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00189 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOAT_OVERFLOW}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00190 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOAT_STACK_CHECK}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00191 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOAT_UNDERFLOW}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00192 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INTEGER_DIVIDE_BY_ZERO}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00193 [PROTO_GATE|] `	ERRDOS, 534, NT_STATUS_INTEGER_OVERFLOW}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00194 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PRIVILEGED_INSTRUCTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00195 [PROTO_GATE|] `	ERRDOS, ERRnomem, NT_STATUS_TOO_MANY_PAGING_FILES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00196 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FILE_INVALID}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00197 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ALLOTTED_SPACE_EXCEEDED},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00198 [NONE] `/*	{ This NT error code was 'sqashed'`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [PROTO_GATE|] ` *	 from NT_STATUS_INSUFFICIENT_RESOURCES to`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00200 [PROTO_GATE|] ` *	 NT_STATUS_INSUFF_SERVER_RESOURCES during the session setup }`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00201 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [PROTO_GATE|] `	ERRDOS, ERRnoresource, NT_STATUS_INSUFFICIENT_RESOURCES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00204 [PROTO_GATE|] `	ERRDOS, ERRbadpath, NT_STATUS_DFS_EXIT_PATH_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00205 [PROTO_GATE|] `	ERRDOS, 23, NT_STATUS_DEVICE_DATA_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00206 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DEVICE_NOT_CONNECTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00207 [PROTO_GATE|] `	ERRDOS, 21, NT_STATUS_DEVICE_POWER_FAILURE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00208 [PROTO_GATE|] `	ERRDOS, 487, NT_STATUS_FREE_VM_NOT_AT_BASE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00209 [PROTO_GATE|] `	ERRDOS, 487, NT_STATUS_MEMORY_NOT_ALLOCATED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00210 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_WORKING_SET_QUOTA}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00211 [PROTO_GATE|] `	ERRDOS, 19, NT_STATUS_MEDIA_WRITE_PROTECTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00212 [PROTO_GATE|] `	ERRDOS, 21, NT_STATUS_DEVICE_NOT_READY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00213 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_GROUP_ATTRIBUTES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00214 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_IMPERSONATION_LEVEL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00215 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CANT_OPEN_ANONYMOUS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00216 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_VALIDATION_CLASS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00217 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_TOKEN_TYPE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00218 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_BAD_MASTER_BOOT_RECORD}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00219 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INSTRUCTION_MISALIGNMENT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00220 [PROTO_GATE|] `	ERRDOS, ERRpipebusy, NT_STATUS_INSTANCE_NOT_AVAILABLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00221 [PROTO_GATE|] `	ERRDOS, ERRpipebusy, NT_STATUS_PIPE_NOT_AVAILABLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00222 [PROTO_GATE|] `	ERRDOS, ERRbadpipe, NT_STATUS_INVALID_PIPE_STATE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00223 [PROTO_GATE|] `	ERRDOS, ERRpipebusy, NT_STATUS_PIPE_BUSY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00224 [PROTO_GATE|] `	ERRDOS, ERRbadfunc, NT_STATUS_ILLEGAL_FUNCTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00225 [PROTO_GATE|] `	ERRDOS, ERRnotconnected, NT_STATUS_PIPE_DISCONNECTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00226 [PROTO_GATE|] `	ERRDOS, ERRpipeclosing, NT_STATUS_PIPE_CLOSING}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00227 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PIPE_CONNECTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00228 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PIPE_LISTENING}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00229 [PROTO_GATE|] `	ERRDOS, ERRbadpipe, NT_STATUS_INVALID_READ_MODE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00230 [PROTO_GATE|] `	ERRDOS, 121, NT_STATUS_IO_TIMEOUT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00231 [PROTO_GATE|] `	ERRDOS, 38, NT_STATUS_FILE_FORCED_CLOSED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00232 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PROFILING_NOT_STARTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00233 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PROFILING_NOT_STOPPED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00234 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_COULD_NOT_INTERPRET}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00235 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_FILE_IS_A_DIRECTORY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00236 [PROTO_GATE|] `	ERRDOS, ERRunsup, NT_STATUS_NOT_SUPPORTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00237 [PROTO_GATE|] `	ERRDOS, 51, NT_STATUS_REMOTE_NOT_LISTENING}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00238 [PROTO_GATE|] `	ERRDOS, 52, NT_STATUS_DUPLICATE_NAME}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00239 [PROTO_GATE|] `	ERRDOS, 53, NT_STATUS_BAD_NETWORK_PATH}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00240 [PROTO_GATE|] `	ERRDOS, 54, NT_STATUS_NETWORK_BUSY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00241 [PROTO_GATE|] `	ERRDOS, 55, NT_STATUS_DEVICE_DOES_NOT_EXIST}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00242 [PROTO_GATE|] `	ERRDOS, 56, NT_STATUS_TOO_MANY_COMMANDS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00243 [PROTO_GATE|] `	ERRDOS, 57, NT_STATUS_ADAPTER_HARDWARE_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00244 [PROTO_GATE|] `	ERRDOS, 58, NT_STATUS_INVALID_NETWORK_RESPONSE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00245 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_UNEXPECTED_NETWORK_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00246 [PROTO_GATE|] `	ERRDOS, 60, NT_STATUS_BAD_REMOTE_ADAPTER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00247 [PROTO_GATE|] `	ERRDOS, 61, NT_STATUS_PRINT_QUEUE_FULL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00248 [PROTO_GATE|] `	ERRDOS, 62, NT_STATUS_NO_SPOOL_SPACE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00249 [PROTO_GATE|] `	ERRDOS, 63, NT_STATUS_PRINT_CANCELLED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00250 [PROTO_GATE|] `	ERRDOS, 64, NT_STATUS_NETWORK_NAME_DELETED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00251 [PROTO_GATE|] `	ERRDOS, 65, NT_STATUS_NETWORK_ACCESS_DENIED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00252 [PROTO_GATE|] `	ERRDOS, 66, NT_STATUS_BAD_DEVICE_TYPE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00253 [PROTO_GATE|] `	ERRDOS, ERRnosuchshare, NT_STATUS_BAD_NETWORK_NAME}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00254 [PROTO_GATE|] `	ERRDOS, 68, NT_STATUS_TOO_MANY_NAMES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00255 [PROTO_GATE|] `	ERRDOS, 69, NT_STATUS_TOO_MANY_SESSIONS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00256 [PROTO_GATE|] `	ERRDOS, 70, NT_STATUS_SHARING_PAUSED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00257 [PROTO_GATE|] `	ERRDOS, 71, NT_STATUS_REQUEST_NOT_ACCEPTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00258 [PROTO_GATE|] `	ERRDOS, 72, NT_STATUS_REDIRECTOR_PAUSED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00259 [PROTO_GATE|] `	ERRDOS, 88, NT_STATUS_NET_WRITE_FAULT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00260 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PROFILING_AT_LIMIT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00261 [PROTO_GATE|] `	ERRDOS, ERRdiffdevice, NT_STATUS_NOT_SAME_DEVICE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00262 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_FILE_RENAMED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00263 [LIFETIME|PROTO_GATE|] `	ERRDOS, 240, NT_STATUS_VIRTUAL_CIRCUIT_CLOSED}, {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00264 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_SECURITY_ON_OBJECT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00265 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CANT_WAIT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00266 [PROTO_GATE|] `	ERRDOS, ERRpipeclosing, NT_STATUS_PIPE_EMPTY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00267 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CANT_ACCESS_DOMAIN_INFO}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00268 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CANT_TERMINATE_SELF}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00269 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_SERVER_STATE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00270 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_DOMAIN_STATE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00271 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_DOMAIN_ROLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00272 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_SUCH_DOMAIN}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00273 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DOMAIN_EXISTS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00274 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DOMAIN_LIMIT_EXCEEDED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00275 [PROTO_GATE|] `	ERRDOS, 300, NT_STATUS_OPLOCK_NOT_GRANTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00276 [PROTO_GATE|] `	ERRDOS, 301, NT_STATUS_INVALID_OPLOCK_PROTOCOL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00277 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INTERNAL_DB_CORRUPTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00278 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INTERNAL_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00279 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_GENERIC_NOT_MAPPED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00280 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_DESCRIPTOR_FORMAT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00281 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_USER_BUFFER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00282 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNEXPECTED_IO_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00283 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNEXPECTED_MM_CREATE_ERR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00284 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNEXPECTED_MM_MAP_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00285 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNEXPECTED_MM_EXTEND_ERR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00286 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NOT_LOGON_PROCESS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00287 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LOGON_SESSION_EXISTS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00288 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_1}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00289 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_2}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00290 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_3}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00291 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_4}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00292 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_5}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00293 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_6}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00294 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_7}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00295 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_8}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00296 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_9}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00297 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_10}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00298 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_11}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00299 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_INVALID_PARAMETER_12}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00300 [PROTO_GATE|] `	ERRDOS, ERRbadpath, NT_STATUS_REDIRECTOR_NOT_STARTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00301 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_REDIRECTOR_STARTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00302 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_STACK_OVERFLOW}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00303 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_SUCH_PACKAGE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00304 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_FUNCTION_TABLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00305 [NONE] `	ERRDOS, 203, 0xc0000100}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [PROTO_GATE|] `	ERRDOS, 145, NT_STATUS_DIRECTORY_NOT_EMPTY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00307 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FILE_CORRUPT_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00308 [PROTO_GATE|] `	ERRDOS, 267, NT_STATUS_NOT_A_DIRECTORY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00309 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_LOGON_SESSION_STATE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00310 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LOGON_SESSION_COLLISION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00311 [PROTO_GATE|] `	ERRDOS, 206, NT_STATUS_NAME_TOO_LONG}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00312 [PROTO_GATE|] `	ERRDOS, 2401, NT_STATUS_FILES_OPEN}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00313 [PROTO_GATE|] `	ERRDOS, 2404, NT_STATUS_CONNECTION_IN_USE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00314 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MESSAGE_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00315 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_PROCESS_IS_TERMINATING}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00316 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_LOGON_TYPE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00317 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_GUID_TRANSLATION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00318 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CANNOT_IMPERSONATE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00319 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_IMAGE_ALREADY_LOADED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00320 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ABIOS_NOT_PRESENT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00321 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ABIOS_LID_NOT_EXIST}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00322 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ABIOS_LID_ALREADY_OWNED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00323 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ABIOS_NOT_LID_OWNER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00324 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ABIOS_INVALID_COMMAND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00325 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ABIOS_INVALID_LID}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00326 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00327 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ABIOS_INVALID_SELECTOR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00328 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_LDT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00329 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_LDT_SIZE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00330 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_LDT_OFFSET}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00331 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_LDT_DESCRIPTOR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00332 [PROTO_GATE|] `	ERRDOS, 193, NT_STATUS_INVALID_IMAGE_NE_FORMAT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00333 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_RXACT_INVALID_STATE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00334 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_RXACT_COMMIT_FAILURE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00335 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MAPPED_FILE_SIZE_ZERO}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00336 [PROTO_GATE|] `	ERRDOS, ERRnofids, NT_STATUS_TOO_MANY_OPENED_FILES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00337 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CANCELLED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00338 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_CANNOT_DELETE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00339 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_COMPUTER_NAME}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00340 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_FILE_DELETED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00341 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_SPECIAL_ACCOUNT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00342 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_SPECIAL_GROUP}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00343 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_SPECIAL_USER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00344 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MEMBERS_PRIMARY_GROUP}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00345 [PROTO_GATE|] `	ERRDOS, ERRbadfid, NT_STATUS_FILE_CLOSED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00346 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_TOO_MANY_THREADS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00347 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_THREAD_NOT_IN_PROCESS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00348 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_TOKEN_ALREADY_IN_USE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00349 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PAGEFILE_QUOTA_EXCEEDED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00350 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_COMMITMENT_LIMIT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00351 [PROTO_GATE|] `	ERRDOS, 193, NT_STATUS_INVALID_IMAGE_LE_FORMAT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00352 [PROTO_GATE|] `	ERRDOS, 193, NT_STATUS_INVALID_IMAGE_NOT_MZ}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00353 [PROTO_GATE|] `	ERRDOS, 193, NT_STATUS_INVALID_IMAGE_PROTECT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00354 [PROTO_GATE|] `	ERRDOS, 193, NT_STATUS_INVALID_IMAGE_WIN_16}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00355 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LOGON_SERVER_CONFLICT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00356 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_TIME_DIFFERENCE_AT_DC}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00357 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_SYNCHRONIZATION_REQUIRED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00358 [PROTO_GATE|] `	ERRDOS, 126, NT_STATUS_DLL_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00359 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_OPEN_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00360 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_IO_PRIVILEGE_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00361 [PROTO_GATE|] `	ERRDOS, 182, NT_STATUS_ORDINAL_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00362 [PROTO_GATE|] `	ERRDOS, 127, NT_STATUS_ENTRYPOINT_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00363 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CONTROL_C_EXIT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00364 [PROTO_GATE|] `	ERRDOS, 64, NT_STATUS_LOCAL_DISCONNECT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00365 [PROTO_GATE|] `	ERRDOS, 64, NT_STATUS_REMOTE_DISCONNECT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00366 [PROTO_GATE|] `	ERRDOS, 51, NT_STATUS_REMOTE_RESOURCES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00367 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_LINK_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00368 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_LINK_TIMEOUT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00369 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_INVALID_CONNECTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00370 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_INVALID_ADDRESS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00371 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DLL_INIT_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00372 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MISSING_SYSTEMFILE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00373 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNHANDLED_EXCEPTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00374 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_APP_INIT_FAILURE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00375 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PAGEFILE_CREATE_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00376 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_PAGEFILE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00377 [PROTO_GATE|] `	ERRDOS, 124, NT_STATUS_INVALID_LEVEL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00378 [PROTO_GATE|] `	ERRDOS, 86, NT_STATUS_WRONG_PASSWORD_CORE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00379 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ILLEGAL_FLOAT_CONTEXT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00380 [PROTO_GATE|] `	ERRDOS, 109, NT_STATUS_PIPE_BROKEN}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00381 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_REGISTRY_CORRUPT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00382 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_REGISTRY_IO_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00383 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_EVENT_PAIR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00384 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNRECOGNIZED_VOLUME}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00385 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_SERIAL_NO_DEVICE_INITED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00386 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_SUCH_ALIAS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00387 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MEMBER_NOT_IN_ALIAS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00388 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MEMBER_IN_ALIAS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00389 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ALIAS_EXISTS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00390 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LOGON_NOT_GRANTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00391 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_TOO_MANY_SECRETS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00392 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_SECRET_TOO_LONG}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00393 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INTERNAL_DB_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00394 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FULLSCREEN_MODE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00395 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_TOO_MANY_CONTEXT_IDS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00396 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_LOGON_TYPE_NOT_GRANTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00397 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NOT_REGISTRY_FILE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00398 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00399 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00400 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FT_MISSING_MEMBER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00401 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ILL_FORMED_SERVICE_ENTRY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00402 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ILLEGAL_CHARACTER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00403 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNMAPPABLE_CHARACTER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00404 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNDEFINED_CHARACTER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00405 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOPPY_VOLUME}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00406 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOPPY_ID_MARK_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00407 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOPPY_WRONG_CYLINDER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00408 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOPPY_UNKNOWN_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00409 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FLOPPY_BAD_REGISTERS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00410 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DISK_RECALIBRATE_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00411 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DISK_OPERATION_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00412 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DISK_RESET_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00413 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_SHARED_IRQ_BUSY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00414 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FT_ORPHANING}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00415 [NONE] `	ERRHRD, ERRgeneral, 0xc000016e}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	ERRHRD, ERRgeneral, 0xc000016f}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	ERRHRD, ERRgeneral, 0xc0000170}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	ERRHRD, ERRgeneral, 0xc0000171}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PARTITION_FAILURE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00420 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_BLOCK_LENGTH}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00421 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DEVICE_NOT_PARTITIONED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00422 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNABLE_TO_LOCK_MEDIA}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00423 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNABLE_TO_UNLOAD_MEDIA}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00424 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_EOM_OVERFLOW}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00425 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_MEDIA}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00426 [NONE] `	ERRHRD, ERRgeneral, 0xc0000179}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_SUCH_MEMBER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00428 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_MEMBER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00429 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_KEY_DELETED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00430 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_LOG_SPACE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00431 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_TOO_MANY_SIDS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00432 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00433 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_KEY_HAS_CHILDREN}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00434 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CHILD_MUST_BE_VOLATILE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00435 [PROTO_GATE|] `	ERRDOS, 87, NT_STATUS_DEVICE_CONFIGURATION_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00436 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DRIVER_INTERNAL_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00437 [PROTO_GATE|] `	ERRDOS, 22, NT_STATUS_INVALID_DEVICE_STATE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00438 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_IO_DEVICE_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00439 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DEVICE_PROTOCOL_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00440 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BACKUP_CONTROLLER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00441 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LOG_FILE_FULL}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00442 [PROTO_GATE|] `	ERRDOS, 19, NT_STATUS_TOO_LATE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00443 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_NO_TRUST_LSA_SECRET},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00444 [NONE] `/*	{ This NT error code was 'sqashed'`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [PROTO_GATE|] ` *	 from NT_STATUS_NO_TRUST_SAM_ACCOUNT to`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00446 [PROTO_GATE|] ` *	 NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE during the session setup }`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00447 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_NO_TRUST_SAM_ACCOUNT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00450 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_TRUSTED_DOMAIN_FAILURE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00451 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00452 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_EVENTLOG_FILE_CORRUPT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00453 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_EVENTLOG_CANT_START}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00454 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_TRUST_FAILURE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00455 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MUTANT_LIMIT_EXCEEDED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00456 [PROTO_GATE|] `	ERRDOS, ERRnetlogonNotStarted, NT_STATUS_NETLOGON_NOT_STARTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00457 [PROTO_GATE|] `	ERRSRV, ERRaccountexpired, NT_STATUS_ACCOUNT_EXPIRED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00458 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_POSSIBLE_DEADLOCK}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00459 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NETWORK_CREDENTIAL_CONFLICT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00460 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_REMOTE_SESSION_LIMIT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00461 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_EVENTLOG_FILE_CHANGED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00462 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00463 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00464 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00465 [NONE] `/*	{ This NT error code was 'sqashed'`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [PROTO_GATE|] ` *	 from NT_STATUS_DOMAIN_TRUST_INCONSISTENT to NT_STATUS_LOGON_FAILURE`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00467 [NONE] ` *	 during the session setup }`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_DOMAIN_TRUST_INCONSISTENT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00471 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FS_DRIVER_REQUIRED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00472 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_USER_SESSION_KEY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00473 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_USER_SESSION_DELETED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00474 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_RESOURCE_LANG_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00475 [PROTO_GATE|] `	ERRDOS, ERRnoresource, NT_STATUS_INSUFF_SERVER_RESOURCES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00476 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_BUFFER_SIZE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00477 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_ADDRESS_COMPONENT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00478 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_ADDRESS_WILDCARD}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00479 [PROTO_GATE|] `	ERRDOS, 68, NT_STATUS_TOO_MANY_ADDRESSES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00480 [PROTO_GATE|] `	ERRDOS, 52, NT_STATUS_ADDRESS_ALREADY_EXISTS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00481 [PROTO_GATE|] `	ERRDOS, 64, NT_STATUS_ADDRESS_CLOSED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00482 [PROTO_GATE|] `	ERRDOS, 64, NT_STATUS_CONNECTION_DISCONNECTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00483 [PROTO_GATE|] `	ERRDOS, 64, NT_STATUS_CONNECTION_RESET}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00484 [PROTO_GATE|] `	ERRDOS, 68, NT_STATUS_TOO_MANY_NODES}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00485 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_TRANSACTION_ABORTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00486 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_TRANSACTION_TIMED_OUT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00487 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_TRANSACTION_NO_RELEASE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00488 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_TRANSACTION_NO_MATCH}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00489 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_TRANSACTION_RESPONDED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00490 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_TRANSACTION_INVALID_ID}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00491 [PROTO_GATE|] `	ERRDOS, 59, NT_STATUS_TRANSACTION_INVALID_TYPE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00492 [PROTO_GATE|] `	ERRDOS, ERRunsup, NT_STATUS_NOT_SERVER_SESSION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00493 [PROTO_GATE|] `	ERRDOS, ERRunsup, NT_STATUS_NOT_CLIENT_SESSION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00494 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CANNOT_LOAD_REGISTRY_FILE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00495 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DEBUG_ATTACH_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00496 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_SYSTEM_PROCESS_TERMINATED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00497 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DATA_NOT_ACCEPTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00498 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_BROWSER_SERVERS_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00499 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_VDM_HARD_ERROR}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00500 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DRIVER_CANCEL_TIMEOUT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00501 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_REPLY_MESSAGE_MISMATCH}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00502 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MAPPED_ALIGNMENT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00503 [PROTO_GATE|] `	ERRDOS, 193, NT_STATUS_IMAGE_CHECKSUM_MISMATCH}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00504 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LOST_WRITEBEHIND_DATA}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00505 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00506 [PROTO_GATE|] `	ERRSRV, ERRpasswordExpired, NT_STATUS_PASSWORD_MUST_CHANGE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00507 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00508 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NOT_TINY_STREAM}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00509 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_RECOVERY_FAILURE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00510 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_STACK_OVERFLOW_READ}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00511 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FAIL_CHECK}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00512 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DUPLICATE_OBJECTID}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00513 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_OBJECTID_EXISTS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00514 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CONVERT_TO_LARGE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00515 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_RETRY}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00516 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FOUND_OUT_OF_SCOPE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00517 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ALLOCATE_BUCKET}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00518 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PROPSET_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00519 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_MARSHALL_OVERFLOW}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00520 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_VARIANT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00521 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00522 [PROTO_GATE|] `	ERRDOS, ERRnoaccess, NT_STATUS_ACCOUNT_LOCKED_OUT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00523 [PROTO_GATE|] `	ERRDOS, ERRbadfid, NT_STATUS_HANDLE_NOT_CLOSABLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00524 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CONNECTION_REFUSED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00525 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_GRACEFUL_DISCONNECT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00526 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ADDRESS_ALREADY_ASSOCIATED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00527 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_ADDRESS_NOT_ASSOCIATED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00528 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CONNECTION_INVALID}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00529 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CONNECTION_ACTIVE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00530 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NETWORK_UNREACHABLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00531 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_HOST_UNREACHABLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00532 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PROTOCOL_UNREACHABLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00533 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PORT_UNREACHABLE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00534 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_REQUEST_ABORTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00535 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CONNECTION_ABORTED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00536 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_COMPRESSION_BUFFER}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00537 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_USER_MAPPED_FILE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00538 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_AUDIT_FAILED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00539 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_TIMER_RESOLUTION_NOT_SET}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00540 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_CONNECTION_COUNT_LIMIT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00541 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LOGIN_TIME_RESTRICTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00542 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LOGIN_WKSTA_RESTRICTION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00543 [PROTO_GATE|] `	ERRDOS, 193, NT_STATUS_IMAGE_MP_UP_MISMATCH}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00544 [NONE] `	ERRHRD, ERRgeneral, 0xc000024a}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	ERRHRD, ERRgeneral, 0xc000024b}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	ERRHRD, ERRgeneral, 0xc000024c}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	ERRHRD, ERRgeneral, 0xc000024d}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	ERRHRD, ERRgeneral, 0xc000024e}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	ERRHRD, ERRgeneral, 0xc000024f}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INSUFFICIENT_LOGON_INFO}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00551 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_DLL_ENTRYPOINT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00552 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_BAD_SERVICE_ENTRYPOINT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00553 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LPC_REPLY_LOST}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00554 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_IP_ADDRESS_CONFLICT1}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00555 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_IP_ADDRESS_CONFLICT2}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00556 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_REGISTRY_QUOTA_LIMIT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00557 [PROTO_GATE|] `	ERRSRV, 3, NT_STATUS_PATH_NOT_COVERED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00558 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_NO_CALLBACK_ACTIVE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00559 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_LICENSE_QUOTA_EXCEEDED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00560 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PWD_TOO_SHORT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00561 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PWD_TOO_RECENT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00562 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PWD_HISTORY_CONFLICT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00563 [NONE] `	ERRHRD, ERRgeneral, 0xc000025d}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_PLUGPLAY_NO_DEVICE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00565 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_UNSUPPORTED_COMPRESSION}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00566 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_HW_PROFILE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00567 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00568 [PROTO_GATE|] `	ERRDOS, 182, NT_STATUS_DRIVER_ORDINAL_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00569 [PROTO_GATE|] `	ERRDOS, 127, NT_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00570 [PROTO_GATE|] `	ERRDOS, 288, NT_STATUS_RESOURCE_NOT_OWNED}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00571 [PROTO_GATE|] `	ERRDOS, ErrTooManyLinks, NT_STATUS_TOO_MANY_LINKS}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00572 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_QUOTA_LIST_INCONSISTENT}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00573 [PROTO_GATE|] `	ERRHRD, ERRgeneral, NT_STATUS_FILE_IS_OFFLINE}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00574 [NONE] `	ERRDOS, 21, 0xc000026e}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	ERRDOS, 161, 0xc0000281}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `	ERRDOS, ERRnoaccess, 0xc000028a}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	ERRDOS, ERRnoaccess, 0xc000028b}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	ERRHRD, ERRgeneral, 0xc000028c}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `	ERRDOS, ERRnoaccess, 0xc000028d}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `	ERRDOS, ERRnoaccess, 0xc000028e}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	ERRDOS, ERRnoaccess, 0xc000028f}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	ERRDOS, ERRnoaccess, 0xc0000290}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	ERRDOS, ERRbadfunc, 0xc000029c}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [PROTO_GATE|] `	ERRDOS, ERRsymlink, NT_STATUS_STOPPED_ON_SYMLINK}, {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00585 [NONE] `	ERRDOS, ERRinvlevel, 0x007c0001}, {`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `	0, 0, 0}, };`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `void`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `ntstatus_to_dos(__le32 ntstatus, __u8 *eclass, __le16 *ecode)`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	if (ntstatus == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `		*eclass = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `		*ecode = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	for (i = 0; ntstatus_to_dos_map[i].ntstatus; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `		if (le32_to_cpu(ntstatus) == ntstatus_to_dos_map[i].ntstatus) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `			*eclass = ntstatus_to_dos_map[i].dos_class;`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `			*ecode = cpu_to_le16(ntstatus_to_dos_map[i].dos_code);`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	*eclass = ERRHRD;`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `	*ecode = cpu_to_le16(ERRgeneral);`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
