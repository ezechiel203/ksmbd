# Line-by-line Review: src/include/core/nterr.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` * Unix SMB/Netbios implementation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` * Version 1.9.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` * NT error code constants`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` * Copyright (C) Andrew Tridgell              1992-2000`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` * Copyright (C) John H Terpstra              1996-2000`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` * Copyright (C) Luke Kenneth Casson Leighton 1996-2000`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` * Copyright (C) Paul Ashton                  1998-2000`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#ifndef _NTERR_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#define _NTERR_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `/* Win32 Status codes. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [PROTO_GATE|] `#define NT_STATUS_MORE_ENTRIES         0x0105`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00017 [NONE] `#define NT_ERROR_INVALID_PARAMETER     0x0057`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#define NT_ERROR_INSUFFICIENT_BUFFER   0x007a`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [PROTO_GATE|] `#define NT_STATUS_1804                 0x070c`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00020 [PROTO_GATE|] `#define NT_STATUS_NOTIFY_ENUM_DIR      0x010c`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00021 [PROTO_GATE|] `#define NT_STATUS_INVALID_LOCK_RANGE   (0xC0000000 | 0x01a1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00022 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * Win32 Error codes extracted using a loop in smbclient then printing a netmon`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` * sniff to a file.`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [PROTO_GATE|] `#define NT_STATUS_OK                   0x0000`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00028 [PROTO_GATE|] `#define NT_STATUS_SOME_UNMAPPED        0x0107`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00029 [PROTO_GATE|] `#define NT_STATUS_BUFFER_OVERFLOW  0x80000005`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00030 [PROTO_GATE|] `#define NT_STATUS_NO_MORE_ENTRIES  0x8000001a`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00031 [PROTO_GATE|] `#define NT_STATUS_MEDIA_CHANGED    0x8000001c`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00032 [PROTO_GATE|] `#define NT_STATUS_END_OF_MEDIA     0x8000001e`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00033 [PROTO_GATE|] `#define NT_STATUS_MEDIA_CHECK      0x80000020`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00034 [PROTO_GATE|] `#define NT_STATUS_NO_DATA_DETECTED 0x80000024`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00035 [PROTO_GATE|] `#define NT_STATUS_STOPPED_ON_SYMLINK 0x8000002d`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00036 [PROTO_GATE|] `#define NT_STATUS_DEVICE_REQUIRES_CLEANING 0x80000288`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00037 [PROTO_GATE|] `#define NT_STATUS_DEVICE_DOOR_OPEN 0x80000289`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00038 [PROTO_GATE|] `#define NT_STATUS_UNSUCCESSFUL (0xC0000000 | 0x0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00039 [PROTO_GATE|] `#define NT_STATUS_NOT_IMPLEMENTED (0xC0000000 | 0x0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00040 [PROTO_GATE|] `#define NT_STATUS_INVALID_INFO_CLASS (0xC0000000 | 0x0003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00041 [PROTO_GATE|] `#define NT_STATUS_INFO_LENGTH_MISMATCH (0xC0000000 | 0x0004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00042 [PROTO_GATE|] `#define NT_STATUS_ACCESS_VIOLATION (0xC0000000 | 0x0005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00043 [PROTO_GATE|] `#define NT_STATUS_IN_PAGE_ERROR (0xC0000000 | 0x0006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00044 [PROTO_GATE|] `#define NT_STATUS_PAGEFILE_QUOTA (0xC0000000 | 0x0007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00045 [PROTO_GATE|] `#define NT_STATUS_INVALID_HANDLE (0xC0000000 | 0x0008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00046 [PROTO_GATE|] `#define NT_STATUS_BAD_INITIAL_STACK (0xC0000000 | 0x0009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00047 [PROTO_GATE|] `#define NT_STATUS_BAD_INITIAL_PC (0xC0000000 | 0x000a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00048 [PROTO_GATE|] `#define NT_STATUS_INVALID_CID (0xC0000000 | 0x000b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00049 [PROTO_GATE|] `#define NT_STATUS_TIMER_NOT_CANCELED (0xC0000000 | 0x000c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00050 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER (0xC0000000 | 0x000d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00051 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_DEVICE (0xC0000000 | 0x000e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00052 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_FILE (0xC0000000 | 0x000f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00053 [PROTO_GATE|] `#define NT_STATUS_INVALID_DEVICE_REQUEST (0xC0000000 | 0x0010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00054 [PROTO_GATE|] `#define NT_STATUS_END_OF_FILE (0xC0000000 | 0x0011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00055 [PROTO_GATE|] `#define NT_STATUS_WRONG_VOLUME (0xC0000000 | 0x0012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00056 [PROTO_GATE|] `#define NT_STATUS_NO_MEDIA_IN_DEVICE (0xC0000000 | 0x0013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00057 [PROTO_GATE|] `#define NT_STATUS_UNRECOGNIZED_MEDIA (0xC0000000 | 0x0014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00058 [PROTO_GATE|] `#define NT_STATUS_NONEXISTENT_SECTOR (0xC0000000 | 0x0015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [PROTO_GATE|] `#define NT_STATUS_MORE_PROCESSING_REQUIRED (0xC0000000 | 0x0016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00060 [PROTO_GATE|] `#define NT_STATUS_NO_MEMORY (0xC0000000 | 0x0017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00061 [PROTO_GATE|] `#define NT_STATUS_CONFLICTING_ADDRESSES (0xC0000000 | 0x0018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00062 [PROTO_GATE|] `#define NT_STATUS_NOT_MAPPED_VIEW (0xC0000000 | 0x0019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00063 [PROTO_GATE|] `#define NT_STATUS_UNABLE_TO_FREE_VM (0x80000000 | 0x001a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00064 [PROTO_GATE|] `#define NT_STATUS_UNABLE_TO_DELETE_SECTION (0xC0000000 | 0x001b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00065 [PROTO_GATE|] `#define NT_STATUS_INVALID_SYSTEM_SERVICE (0xC0000000 | 0x001c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00066 [PROTO_GATE|] `#define NT_STATUS_ILLEGAL_INSTRUCTION (0xC0000000 | 0x001d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00067 [PROTO_GATE|] `#define NT_STATUS_INVALID_LOCK_SEQUENCE (0xC0000000 | 0x001e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00068 [PROTO_GATE|] `#define NT_STATUS_INVALID_VIEW_SIZE (0xC0000000 | 0x001f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00069 [PROTO_GATE|] `#define NT_STATUS_INVALID_FILE_FOR_SECTION (0xC0000000 | 0x0020)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00070 [PROTO_GATE|] `#define NT_STATUS_ALREADY_COMMITTED (0xC0000000 | 0x0021)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00071 [PROTO_GATE|] `#define NT_STATUS_ACCESS_DENIED (0xC0000000 | 0x0022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00072 [PROTO_GATE|] `#define NT_STATUS_BUFFER_TOO_SMALL (0xC0000000 | 0x0023)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00073 [PROTO_GATE|] `#define NT_STATUS_OBJECT_TYPE_MISMATCH (0xC0000000 | 0x0024)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00074 [PROTO_GATE|] `#define NT_STATUS_NONCONTINUABLE_EXCEPTION (0xC0000000 | 0x0025)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00075 [PROTO_GATE|] `#define NT_STATUS_INVALID_DISPOSITION (0xC0000000 | 0x0026)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00076 [PROTO_GATE|] `#define NT_STATUS_UNWIND (0xC0000000 | 0x0027)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00077 [PROTO_GATE|] `#define NT_STATUS_BAD_STACK (0xC0000000 | 0x0028)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00078 [PROTO_GATE|] `#define NT_STATUS_INVALID_UNWIND_TARGET (0xC0000000 | 0x0029)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00079 [PROTO_GATE|] `#define NT_STATUS_NOT_LOCKED (0xC0000000 | 0x002a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00080 [PROTO_GATE|] `#define NT_STATUS_PARITY_ERROR (0xC0000000 | 0x002b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00081 [PROTO_GATE|] `#define NT_STATUS_UNABLE_TO_DECOMMIT_VM (0xC0000000 | 0x002c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00082 [PROTO_GATE|] `#define NT_STATUS_NOT_COMMITTED (0xC0000000 | 0x002d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00083 [PROTO_GATE|] `#define NT_STATUS_INVALID_PORT_ATTRIBUTES (0xC0000000 | 0x002e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00084 [PROTO_GATE|] `#define NT_STATUS_PORT_MESSAGE_TOO_LONG (0xC0000000 | 0x002f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00085 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_MIX (0xC0000000 | 0x0030)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00086 [PROTO_GATE|] `#define NT_STATUS_INVALID_QUOTA_LOWER (0xC0000000 | 0x0031)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00087 [PROTO_GATE|] `#define NT_STATUS_DISK_CORRUPT_ERROR (0xC0000000 | 0x0032)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00088 [PROTO_GATE|] `#define NT_STATUS_OBJECT_NAME_INVALID (0xC0000000 | 0x0033)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00089 [PROTO_GATE|] `#define NT_STATUS_OBJECT_NAME_NOT_FOUND (0xC0000000 | 0x0034)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00090 [PROTO_GATE|] `#define NT_STATUS_OBJECT_NAME_COLLISION (0xC0000000 | 0x0035)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00091 [PROTO_GATE|] `#define NT_STATUS_HANDLE_NOT_WAITABLE (0xC0000000 | 0x0036)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00092 [PROTO_GATE|] `#define NT_STATUS_PORT_DISCONNECTED (0xC0000000 | 0x0037)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00093 [PROTO_GATE|] `#define NT_STATUS_DEVICE_ALREADY_ATTACHED (0xC0000000 | 0x0038)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00094 [PROTO_GATE|] `#define NT_STATUS_OBJECT_PATH_INVALID (0xC0000000 | 0x0039)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00095 [PROTO_GATE|] `#define NT_STATUS_OBJECT_PATH_NOT_FOUND (0xC0000000 | 0x003a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00096 [PROTO_GATE|] `#define NT_STATUS_OBJECT_PATH_SYNTAX_BAD (0xC0000000 | 0x003b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00097 [PROTO_GATE|] `#define NT_STATUS_DATA_OVERRUN (0xC0000000 | 0x003c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00098 [PROTO_GATE|] `#define NT_STATUS_DATA_LATE_ERROR (0xC0000000 | 0x003d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00099 [PROTO_GATE|] `#define NT_STATUS_DATA_ERROR (0xC0000000 | 0x003e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00100 [PROTO_GATE|] `#define NT_STATUS_CRC_ERROR (0xC0000000 | 0x003f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00101 [PROTO_GATE|] `#define NT_STATUS_SECTION_TOO_BIG (0xC0000000 | 0x0040)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00102 [PROTO_GATE|] `#define NT_STATUS_PORT_CONNECTION_REFUSED (0xC0000000 | 0x0041)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00103 [PROTO_GATE|] `#define NT_STATUS_INVALID_PORT_HANDLE (0xC0000000 | 0x0042)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00104 [PROTO_GATE|] `#define NT_STATUS_SHARING_VIOLATION (0xC0000000 | 0x0043)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00105 [PROTO_GATE|] `#define NT_STATUS_QUOTA_EXCEEDED (0xC0000000 | 0x0044)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00106 [PROTO_GATE|] `#define NT_STATUS_INVALID_PAGE_PROTECTION (0xC0000000 | 0x0045)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00107 [PROTO_GATE|] `#define NT_STATUS_MUTANT_NOT_OWNED (0xC0000000 | 0x0046)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00108 [PROTO_GATE|] `#define NT_STATUS_SEMAPHORE_LIMIT_EXCEEDED (0xC0000000 | 0x0047)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00109 [PROTO_GATE|] `#define NT_STATUS_PORT_ALREADY_SET (0xC0000000 | 0x0048)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00110 [PROTO_GATE|] `#define NT_STATUS_SECTION_NOT_IMAGE (0xC0000000 | 0x0049)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00111 [PROTO_GATE|] `#define NT_STATUS_SUSPEND_COUNT_EXCEEDED (0xC0000000 | 0x004a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00112 [PROTO_GATE|] `#define NT_STATUS_THREAD_IS_TERMINATING (0xC0000000 | 0x004b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00113 [PROTO_GATE|] `#define NT_STATUS_BAD_WORKING_SET_LIMIT (0xC0000000 | 0x004c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00114 [PROTO_GATE|] `#define NT_STATUS_INCOMPATIBLE_FILE_MAP (0xC0000000 | 0x004d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00115 [PROTO_GATE|] `#define NT_STATUS_SECTION_PROTECTION (0xC0000000 | 0x004e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00116 [PROTO_GATE|] `#define NT_STATUS_EAS_NOT_SUPPORTED (0xC0000000 | 0x004f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00117 [PROTO_GATE|] `#define NT_STATUS_EA_TOO_LARGE (0xC0000000 | 0x0050)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00118 [PROTO_GATE|] `#define NT_STATUS_NONEXISTENT_EA_ENTRY (0xC0000000 | 0x0051)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00119 [PROTO_GATE|] `#define NT_STATUS_NO_EAS_ON_FILE (0xC0000000 | 0x0052)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00120 [PROTO_GATE|] `#define NT_STATUS_EA_CORRUPT_ERROR (0xC0000000 | 0x0053)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00121 [PROTO_GATE|] `#define NT_STATUS_FILE_LOCK_CONFLICT (0xC0000000 | 0x0054)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00122 [PROTO_GATE|] `#define NT_STATUS_LOCK_NOT_GRANTED (0xC0000000 | 0x0055)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00123 [PROTO_GATE|] `#define NT_STATUS_DELETE_PENDING (0xC0000000 | 0x0056)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00124 [PROTO_GATE|] `#define NT_STATUS_CTL_FILE_NOT_SUPPORTED (0xC0000000 | 0x0057)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00125 [PROTO_GATE|] `#define NT_STATUS_UNKNOWN_REVISION (0xC0000000 | 0x0058)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00126 [PROTO_GATE|] `#define NT_STATUS_REVISION_MISMATCH (0xC0000000 | 0x0059)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00127 [PROTO_GATE|] `#define NT_STATUS_INVALID_OWNER (0xC0000000 | 0x005a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00128 [PROTO_GATE|] `#define NT_STATUS_INVALID_PRIMARY_GROUP (0xC0000000 | 0x005b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00129 [PROTO_GATE|] `#define NT_STATUS_NO_IMPERSONATION_TOKEN (0xC0000000 | 0x005c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00130 [PROTO_GATE|] `#define NT_STATUS_CANT_DISABLE_MANDATORY (0xC0000000 | 0x005d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00131 [PROTO_GATE|] `#define NT_STATUS_NO_LOGON_SERVERS (0xC0000000 | 0x005e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00132 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_LOGON_SESSION (0xC0000000 | 0x005f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00133 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_PRIVILEGE (0xC0000000 | 0x0060)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00134 [PROTO_GATE|] `#define NT_STATUS_PRIVILEGE_NOT_HELD (0xC0000000 | 0x0061)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00135 [PROTO_GATE|] `#define NT_STATUS_INVALID_ACCOUNT_NAME (0xC0000000 | 0x0062)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00136 [PROTO_GATE|] `#define NT_STATUS_USER_EXISTS (0xC0000000 | 0x0063)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00137 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_USER (0xC0000000 | 0x0064)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00138 [PROTO_GATE|] `#define NT_STATUS_GROUP_EXISTS (0xC0000000 | 0x0065)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00139 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_GROUP (0xC0000000 | 0x0066)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00140 [PROTO_GATE|] `#define NT_STATUS_MEMBER_IN_GROUP (0xC0000000 | 0x0067)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00141 [PROTO_GATE|] `#define NT_STATUS_MEMBER_NOT_IN_GROUP (0xC0000000 | 0x0068)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00142 [PROTO_GATE|] `#define NT_STATUS_LAST_ADMIN (0xC0000000 | 0x0069)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00143 [PROTO_GATE|] `#define NT_STATUS_WRONG_PASSWORD (0xC0000000 | 0x006a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00144 [PROTO_GATE|] `#define NT_STATUS_ILL_FORMED_PASSWORD (0xC0000000 | 0x006b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00145 [PROTO_GATE|] `#define NT_STATUS_PASSWORD_RESTRICTION (0xC0000000 | 0x006c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00146 [PROTO_GATE|] `#define NT_STATUS_LOGON_FAILURE (0xC0000000 | 0x006d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00147 [PROTO_GATE|] `#define NT_STATUS_ACCOUNT_RESTRICTION (0xC0000000 | 0x006e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00148 [PROTO_GATE|] `#define NT_STATUS_INVALID_LOGON_HOURS (0xC0000000 | 0x006f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00149 [PROTO_GATE|] `#define NT_STATUS_INVALID_WORKSTATION (0xC0000000 | 0x0070)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00150 [PROTO_GATE|] `#define NT_STATUS_PASSWORD_EXPIRED (0xC0000000 | 0x0071)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00151 [PROTO_GATE|] `#define NT_STATUS_ACCOUNT_DISABLED (0xC0000000 | 0x0072)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00152 [PROTO_GATE|] `#define NT_STATUS_NONE_MAPPED (0xC0000000 | 0x0073)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00153 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_LUIDS_REQUESTED (0xC0000000 | 0x0074)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00154 [PROTO_GATE|] `#define NT_STATUS_LUIDS_EXHAUSTED (0xC0000000 | 0x0075)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00155 [PROTO_GATE|] `#define NT_STATUS_INVALID_SUB_AUTHORITY (0xC0000000 | 0x0076)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00156 [PROTO_GATE|] `#define NT_STATUS_INVALID_ACL (0xC0000000 | 0x0077)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00157 [PROTO_GATE|] `#define NT_STATUS_INVALID_SID (0xC0000000 | 0x0078)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00158 [PROTO_GATE|] `#define NT_STATUS_INVALID_SECURITY_DESCR (0xC0000000 | 0x0079)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00159 [PROTO_GATE|] `#define NT_STATUS_PROCEDURE_NOT_FOUND (0xC0000000 | 0x007a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00160 [PROTO_GATE|] `#define NT_STATUS_INVALID_IMAGE_FORMAT (0xC0000000 | 0x007b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00161 [PROTO_GATE|] `#define NT_STATUS_NO_TOKEN (0xC0000000 | 0x007c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00162 [PROTO_GATE|] `#define NT_STATUS_BAD_INHERITANCE_ACL (0xC0000000 | 0x007d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00163 [PROTO_GATE|] `#define NT_STATUS_RANGE_NOT_LOCKED (0xC0000000 | 0x007e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00164 [PROTO_GATE|] `#define NT_STATUS_DISK_FULL (0xC0000000 | 0x007f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00165 [PROTO_GATE|] `#define NT_STATUS_SERVER_DISABLED (0xC0000000 | 0x0080)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00166 [PROTO_GATE|] `#define NT_STATUS_SERVER_NOT_DISABLED (0xC0000000 | 0x0081)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00167 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_GUIDS_REQUESTED (0xC0000000 | 0x0082)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00168 [PROTO_GATE|] `#define NT_STATUS_GUIDS_EXHAUSTED (0xC0000000 | 0x0083)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00169 [PROTO_GATE|] `#define NT_STATUS_INVALID_ID_AUTHORITY (0xC0000000 | 0x0084)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00170 [PROTO_GATE|] `#define NT_STATUS_AGENTS_EXHAUSTED (0xC0000000 | 0x0085)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00171 [PROTO_GATE|] `#define NT_STATUS_INVALID_VOLUME_LABEL (0xC0000000 | 0x0086)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00172 [PROTO_GATE|] `#define NT_STATUS_SECTION_NOT_EXTENDED (0xC0000000 | 0x0087)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00173 [PROTO_GATE|] `#define NT_STATUS_NOT_MAPPED_DATA (0xC0000000 | 0x0088)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00174 [PROTO_GATE|] `#define NT_STATUS_RESOURCE_DATA_NOT_FOUND (0xC0000000 | 0x0089)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00175 [PROTO_GATE|] `#define NT_STATUS_RESOURCE_TYPE_NOT_FOUND (0xC0000000 | 0x008a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00176 [PROTO_GATE|] `#define NT_STATUS_RESOURCE_NAME_NOT_FOUND (0xC0000000 | 0x008b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00177 [PROTO_GATE|] `#define NT_STATUS_ARRAY_BOUNDS_EXCEEDED (0xC0000000 | 0x008c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00178 [PROTO_GATE|] `#define NT_STATUS_FLOAT_DENORMAL_OPERAND (0xC0000000 | 0x008d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00179 [PROTO_GATE|] `#define NT_STATUS_FLOAT_DIVIDE_BY_ZERO (0xC0000000 | 0x008e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00180 [PROTO_GATE|] `#define NT_STATUS_FLOAT_INEXACT_RESULT (0xC0000000 | 0x008f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00181 [PROTO_GATE|] `#define NT_STATUS_FLOAT_INVALID_OPERATION (0xC0000000 | 0x0090)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00182 [PROTO_GATE|] `#define NT_STATUS_FLOAT_OVERFLOW (0xC0000000 | 0x0091)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00183 [PROTO_GATE|] `#define NT_STATUS_FLOAT_STACK_CHECK (0xC0000000 | 0x0092)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00184 [PROTO_GATE|] `#define NT_STATUS_FLOAT_UNDERFLOW (0xC0000000 | 0x0093)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00185 [PROTO_GATE|] `#define NT_STATUS_INTEGER_DIVIDE_BY_ZERO (0xC0000000 | 0x0094)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00186 [PROTO_GATE|] `#define NT_STATUS_INTEGER_OVERFLOW (0xC0000000 | 0x0095)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00187 [PROTO_GATE|] `#define NT_STATUS_PRIVILEGED_INSTRUCTION (0xC0000000 | 0x0096)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00188 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_PAGING_FILES (0xC0000000 | 0x0097)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00189 [PROTO_GATE|] `#define NT_STATUS_FILE_INVALID (0xC0000000 | 0x0098)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00190 [PROTO_GATE|] `#define NT_STATUS_ALLOTTED_SPACE_EXCEEDED (0xC0000000 | 0x0099)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00191 [PROTO_GATE|] `#define NT_STATUS_INSUFFICIENT_RESOURCES (0xC0000000 | 0x009a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00192 [PROTO_GATE|] `#define NT_STATUS_DFS_EXIT_PATH_FOUND (0xC0000000 | 0x009b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00193 [PROTO_GATE|] `#define NT_STATUS_DEVICE_DATA_ERROR (0xC0000000 | 0x009c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00194 [PROTO_GATE|] `#define NT_STATUS_DEVICE_NOT_CONNECTED (0xC0000000 | 0x009d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00195 [PROTO_GATE|] `#define NT_STATUS_DEVICE_POWER_FAILURE (0xC0000000 | 0x009e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00196 [PROTO_GATE|] `#define NT_STATUS_FREE_VM_NOT_AT_BASE (0xC0000000 | 0x009f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00197 [PROTO_GATE|] `#define NT_STATUS_MEMORY_NOT_ALLOCATED (0xC0000000 | 0x00a0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00198 [PROTO_GATE|] `#define NT_STATUS_WORKING_SET_QUOTA (0xC0000000 | 0x00a1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00199 [PROTO_GATE|] `#define NT_STATUS_MEDIA_WRITE_PROTECTED (0xC0000000 | 0x00a2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00200 [PROTO_GATE|] `#define NT_STATUS_DEVICE_NOT_READY (0xC0000000 | 0x00a3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00201 [PROTO_GATE|] `#define NT_STATUS_INVALID_GROUP_ATTRIBUTES (0xC0000000 | 0x00a4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00202 [PROTO_GATE|] `#define NT_STATUS_BAD_IMPERSONATION_LEVEL (0xC0000000 | 0x00a5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00203 [PROTO_GATE|] `#define NT_STATUS_CANT_OPEN_ANONYMOUS (0xC0000000 | 0x00a6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00204 [PROTO_GATE|] `#define NT_STATUS_BAD_VALIDATION_CLASS (0xC0000000 | 0x00a7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00205 [PROTO_GATE|] `#define NT_STATUS_BAD_TOKEN_TYPE (0xC0000000 | 0x00a8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00206 [PROTO_GATE|] `#define NT_STATUS_BAD_MASTER_BOOT_RECORD (0xC0000000 | 0x00a9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00207 [PROTO_GATE|] `#define NT_STATUS_INSTRUCTION_MISALIGNMENT (0xC0000000 | 0x00aa)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00208 [PROTO_GATE|] `#define NT_STATUS_INSTANCE_NOT_AVAILABLE (0xC0000000 | 0x00ab)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00209 [PROTO_GATE|] `#define NT_STATUS_PIPE_NOT_AVAILABLE (0xC0000000 | 0x00ac)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00210 [PROTO_GATE|] `#define NT_STATUS_INVALID_PIPE_STATE (0xC0000000 | 0x00ad)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00211 [PROTO_GATE|] `#define NT_STATUS_PIPE_BUSY (0xC0000000 | 0x00ae)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00212 [PROTO_GATE|] `#define NT_STATUS_ILLEGAL_FUNCTION (0xC0000000 | 0x00af)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00213 [PROTO_GATE|] `#define NT_STATUS_PIPE_DISCONNECTED (0xC0000000 | 0x00b0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00214 [PROTO_GATE|] `#define NT_STATUS_PIPE_CLOSING (0xC0000000 | 0x00b1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00215 [PROTO_GATE|] `#define NT_STATUS_PIPE_CONNECTED (0xC0000000 | 0x00b2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00216 [PROTO_GATE|] `#define NT_STATUS_PIPE_LISTENING (0xC0000000 | 0x00b3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00217 [PROTO_GATE|] `#define NT_STATUS_INVALID_READ_MODE (0xC0000000 | 0x00b4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00218 [PROTO_GATE|] `#define NT_STATUS_IO_TIMEOUT (0xC0000000 | 0x00b5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00219 [PROTO_GATE|] `#define NT_STATUS_FILE_FORCED_CLOSED (0xC0000000 | 0x00b6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00220 [PROTO_GATE|] `#define NT_STATUS_PROFILING_NOT_STARTED (0xC0000000 | 0x00b7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00221 [PROTO_GATE|] `#define NT_STATUS_PROFILING_NOT_STOPPED (0xC0000000 | 0x00b8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00222 [PROTO_GATE|] `#define NT_STATUS_COULD_NOT_INTERPRET (0xC0000000 | 0x00b9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00223 [PROTO_GATE|] `#define NT_STATUS_FILE_IS_A_DIRECTORY (0xC0000000 | 0x00ba)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00224 [PROTO_GATE|] `#define NT_STATUS_NOT_SUPPORTED (0xC0000000 | 0x00bb)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00225 [PROTO_GATE|] `#define NT_STATUS_REMOTE_NOT_LISTENING (0xC0000000 | 0x00bc)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00226 [PROTO_GATE|] `#define NT_STATUS_DUPLICATE_NAME (0xC0000000 | 0x00bd)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00227 [PROTO_GATE|] `#define NT_STATUS_BAD_NETWORK_PATH (0xC0000000 | 0x00be)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00228 [PROTO_GATE|] `#define NT_STATUS_NETWORK_BUSY (0xC0000000 | 0x00bf)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00229 [PROTO_GATE|] `#define NT_STATUS_DEVICE_DOES_NOT_EXIST (0xC0000000 | 0x00c0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00230 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_COMMANDS (0xC0000000 | 0x00c1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00231 [PROTO_GATE|] `#define NT_STATUS_ADAPTER_HARDWARE_ERROR (0xC0000000 | 0x00c2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00232 [PROTO_GATE|] `#define NT_STATUS_INVALID_NETWORK_RESPONSE (0xC0000000 | 0x00c3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00233 [PROTO_GATE|] `#define NT_STATUS_UNEXPECTED_NETWORK_ERROR (0xC0000000 | 0x00c4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00234 [PROTO_GATE|] `#define NT_STATUS_BAD_REMOTE_ADAPTER (0xC0000000 | 0x00c5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00235 [PROTO_GATE|] `#define NT_STATUS_PRINT_QUEUE_FULL (0xC0000000 | 0x00c6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00236 [PROTO_GATE|] `#define NT_STATUS_NO_SPOOL_SPACE (0xC0000000 | 0x00c7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00237 [PROTO_GATE|] `#define NT_STATUS_PRINT_CANCELLED (0xC0000000 | 0x00c8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00238 [PROTO_GATE|] `#define NT_STATUS_NETWORK_NAME_DELETED (0xC0000000 | 0x00c9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00239 [PROTO_GATE|] `#define NT_STATUS_NETWORK_ACCESS_DENIED (0xC0000000 | 0x00ca)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00240 [PROTO_GATE|] `#define NT_STATUS_BAD_DEVICE_TYPE (0xC0000000 | 0x00cb)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00241 [PROTO_GATE|] `#define NT_STATUS_BAD_NETWORK_NAME (0xC0000000 | 0x00cc)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00242 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_NAMES (0xC0000000 | 0x00cd)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00243 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_SESSIONS (0xC0000000 | 0x00ce)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00244 [PROTO_GATE|] `#define NT_STATUS_SHARING_PAUSED (0xC0000000 | 0x00cf)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00245 [PROTO_GATE|] `#define NT_STATUS_REQUEST_NOT_ACCEPTED (0xC0000000 | 0x00d0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00246 [PROTO_GATE|] `#define NT_STATUS_REDIRECTOR_PAUSED (0xC0000000 | 0x00d1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00247 [PROTO_GATE|] `#define NT_STATUS_NET_WRITE_FAULT (0xC0000000 | 0x00d2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00248 [PROTO_GATE|] `#define NT_STATUS_PROFILING_AT_LIMIT (0xC0000000 | 0x00d3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00249 [PROTO_GATE|] `#define NT_STATUS_NOT_SAME_DEVICE (0xC0000000 | 0x00d4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00250 [PROTO_GATE|] `#define NT_STATUS_FILE_RENAMED (0xC0000000 | 0x00d5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00251 [LIFETIME|PROTO_GATE|] `#define NT_STATUS_VIRTUAL_CIRCUIT_CLOSED (0xC0000000 | 0x00d6)`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00252 [PROTO_GATE|] `#define NT_STATUS_NO_SECURITY_ON_OBJECT (0xC0000000 | 0x00d7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00253 [PROTO_GATE|] `#define NT_STATUS_CANT_WAIT (0xC0000000 | 0x00d8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00254 [PROTO_GATE|] `#define NT_STATUS_PIPE_EMPTY (0xC0000000 | 0x00d9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00255 [PROTO_GATE|] `#define NT_STATUS_CANT_ACCESS_DOMAIN_INFO (0xC0000000 | 0x00da)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00256 [PROTO_GATE|] `#define NT_STATUS_CANT_TERMINATE_SELF (0xC0000000 | 0x00db)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00257 [PROTO_GATE|] `#define NT_STATUS_INVALID_SERVER_STATE (0xC0000000 | 0x00dc)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00258 [PROTO_GATE|] `#define NT_STATUS_INVALID_DOMAIN_STATE (0xC0000000 | 0x00dd)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00259 [PROTO_GATE|] `#define NT_STATUS_INVALID_DOMAIN_ROLE (0xC0000000 | 0x00de)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00260 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_DOMAIN (0xC0000000 | 0x00df)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00261 [PROTO_GATE|] `#define NT_STATUS_DOMAIN_EXISTS (0xC0000000 | 0x00e0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00262 [PROTO_GATE|] `#define NT_STATUS_DOMAIN_LIMIT_EXCEEDED (0xC0000000 | 0x00e1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00263 [PROTO_GATE|] `#define NT_STATUS_OPLOCK_NOT_GRANTED (0xC0000000 | 0x00e2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00264 [PROTO_GATE|] `#define NT_STATUS_INVALID_OPLOCK_PROTOCOL (0xC0000000 | 0x00e3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00265 [PROTO_GATE|] `#define NT_STATUS_INTERNAL_DB_CORRUPTION (0xC0000000 | 0x00e4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00266 [PROTO_GATE|] `#define NT_STATUS_INTERNAL_ERROR (0xC0000000 | 0x00e5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00267 [PROTO_GATE|] `#define NT_STATUS_GENERIC_NOT_MAPPED (0xC0000000 | 0x00e6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00268 [PROTO_GATE|] `#define NT_STATUS_BAD_DESCRIPTOR_FORMAT (0xC0000000 | 0x00e7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00269 [PROTO_GATE|] `#define NT_STATUS_INVALID_USER_BUFFER (0xC0000000 | 0x00e8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00270 [PROTO_GATE|] `#define NT_STATUS_UNEXPECTED_IO_ERROR (0xC0000000 | 0x00e9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00271 [PROTO_GATE|] `#define NT_STATUS_UNEXPECTED_MM_CREATE_ERR (0xC0000000 | 0x00ea)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00272 [PROTO_GATE|] `#define NT_STATUS_UNEXPECTED_MM_MAP_ERROR (0xC0000000 | 0x00eb)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00273 [PROTO_GATE|] `#define NT_STATUS_UNEXPECTED_MM_EXTEND_ERR (0xC0000000 | 0x00ec)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00274 [PROTO_GATE|] `#define NT_STATUS_NOT_LOGON_PROCESS (0xC0000000 | 0x00ed)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00275 [PROTO_GATE|] `#define NT_STATUS_LOGON_SESSION_EXISTS (0xC0000000 | 0x00ee)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00276 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_1 (0xC0000000 | 0x00ef)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00277 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_2 (0xC0000000 | 0x00f0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00278 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_3 (0xC0000000 | 0x00f1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00279 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_4 (0xC0000000 | 0x00f2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00280 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_5 (0xC0000000 | 0x00f3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00281 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_6 (0xC0000000 | 0x00f4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00282 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_7 (0xC0000000 | 0x00f5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00283 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_8 (0xC0000000 | 0x00f6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00284 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_9 (0xC0000000 | 0x00f7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00285 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_10 (0xC0000000 | 0x00f8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00286 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_11 (0xC0000000 | 0x00f9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00287 [PROTO_GATE|] `#define NT_STATUS_INVALID_PARAMETER_12 (0xC0000000 | 0x00fa)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00288 [PROTO_GATE|] `#define NT_STATUS_REDIRECTOR_NOT_STARTED (0xC0000000 | 0x00fb)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00289 [PROTO_GATE|] `#define NT_STATUS_REDIRECTOR_STARTED (0xC0000000 | 0x00fc)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00290 [PROTO_GATE|] `#define NT_STATUS_STACK_OVERFLOW (0xC0000000 | 0x00fd)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00291 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_PACKAGE (0xC0000000 | 0x00fe)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00292 [PROTO_GATE|] `#define NT_STATUS_BAD_FUNCTION_TABLE (0xC0000000 | 0x00ff)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00293 [PROTO_GATE|] `#define NT_STATUS_DIRECTORY_NOT_EMPTY (0xC0000000 | 0x0101)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00294 [PROTO_GATE|] `#define NT_STATUS_FILE_CORRUPT_ERROR (0xC0000000 | 0x0102)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00295 [PROTO_GATE|] `#define NT_STATUS_NOT_A_DIRECTORY (0xC0000000 | 0x0103)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00296 [PROTO_GATE|] `#define NT_STATUS_BAD_LOGON_SESSION_STATE (0xC0000000 | 0x0104)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00297 [PROTO_GATE|] `#define NT_STATUS_LOGON_SESSION_COLLISION (0xC0000000 | 0x0105)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00298 [PROTO_GATE|] `#define NT_STATUS_NAME_TOO_LONG (0xC0000000 | 0x0106)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00299 [PROTO_GATE|] `#define NT_STATUS_FILES_OPEN (0xC0000000 | 0x0107)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00300 [PROTO_GATE|] `#define NT_STATUS_CONNECTION_IN_USE (0xC0000000 | 0x0108)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00301 [PROTO_GATE|] `#define NT_STATUS_MESSAGE_NOT_FOUND (0xC0000000 | 0x0109)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00302 [PROTO_GATE|] `#define NT_STATUS_PROCESS_IS_TERMINATING (0xC0000000 | 0x010a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00303 [PROTO_GATE|] `#define NT_STATUS_INVALID_LOGON_TYPE (0xC0000000 | 0x010b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00304 [PROTO_GATE|] `#define NT_STATUS_NO_GUID_TRANSLATION (0xC0000000 | 0x010c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00305 [PROTO_GATE|] `#define NT_STATUS_CANNOT_IMPERSONATE (0xC0000000 | 0x010d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00306 [PROTO_GATE|] `#define NT_STATUS_IMAGE_ALREADY_LOADED (0xC0000000 | 0x010e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00307 [PROTO_GATE|] `#define NT_STATUS_ABIOS_NOT_PRESENT (0xC0000000 | 0x010f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00308 [PROTO_GATE|] `#define NT_STATUS_ABIOS_LID_NOT_EXIST (0xC0000000 | 0x0110)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00309 [PROTO_GATE|] `#define NT_STATUS_ABIOS_LID_ALREADY_OWNED (0xC0000000 | 0x0111)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00310 [PROTO_GATE|] `#define NT_STATUS_ABIOS_NOT_LID_OWNER (0xC0000000 | 0x0112)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00311 [PROTO_GATE|] `#define NT_STATUS_ABIOS_INVALID_COMMAND (0xC0000000 | 0x0113)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00312 [PROTO_GATE|] `#define NT_STATUS_ABIOS_INVALID_LID (0xC0000000 | 0x0114)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00313 [PROTO_GATE|] `#define NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE (0xC0000000 | 0x0115)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00314 [PROTO_GATE|] `#define NT_STATUS_ABIOS_INVALID_SELECTOR (0xC0000000 | 0x0116)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00315 [PROTO_GATE|] `#define NT_STATUS_NO_LDT (0xC0000000 | 0x0117)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00316 [PROTO_GATE|] `#define NT_STATUS_INVALID_LDT_SIZE (0xC0000000 | 0x0118)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00317 [PROTO_GATE|] `#define NT_STATUS_INVALID_LDT_OFFSET (0xC0000000 | 0x0119)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00318 [PROTO_GATE|] `#define NT_STATUS_INVALID_LDT_DESCRIPTOR (0xC0000000 | 0x011a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00319 [PROTO_GATE|] `#define NT_STATUS_INVALID_IMAGE_NE_FORMAT (0xC0000000 | 0x011b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00320 [PROTO_GATE|] `#define NT_STATUS_RXACT_INVALID_STATE (0xC0000000 | 0x011c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00321 [PROTO_GATE|] `#define NT_STATUS_RXACT_COMMIT_FAILURE (0xC0000000 | 0x011d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00322 [PROTO_GATE|] `#define NT_STATUS_MAPPED_FILE_SIZE_ZERO (0xC0000000 | 0x011e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00323 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_OPENED_FILES (0xC0000000 | 0x011f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00324 [PROTO_GATE|] `#define NT_STATUS_CANCELLED (0xC0000000 | 0x0120)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00325 [PROTO_GATE|] `#define NT_STATUS_CANNOT_DELETE (0xC0000000 | 0x0121)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00326 [PROTO_GATE|] `#define NT_STATUS_INVALID_COMPUTER_NAME (0xC0000000 | 0x0122)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00327 [PROTO_GATE|] `#define NT_STATUS_FILE_DELETED (0xC0000000 | 0x0123)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00328 [PROTO_GATE|] `#define NT_STATUS_SPECIAL_ACCOUNT (0xC0000000 | 0x0124)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00329 [PROTO_GATE|] `#define NT_STATUS_SPECIAL_GROUP (0xC0000000 | 0x0125)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00330 [PROTO_GATE|] `#define NT_STATUS_SPECIAL_USER (0xC0000000 | 0x0126)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00331 [PROTO_GATE|] `#define NT_STATUS_MEMBERS_PRIMARY_GROUP (0xC0000000 | 0x0127)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00332 [PROTO_GATE|] `#define NT_STATUS_FILE_CLOSED (0xC0000000 | 0x0128)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00333 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_THREADS (0xC0000000 | 0x0129)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00334 [PROTO_GATE|] `#define NT_STATUS_THREAD_NOT_IN_PROCESS (0xC0000000 | 0x012a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00335 [PROTO_GATE|] `#define NT_STATUS_TOKEN_ALREADY_IN_USE (0xC0000000 | 0x012b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00336 [PROTO_GATE|] `#define NT_STATUS_PAGEFILE_QUOTA_EXCEEDED (0xC0000000 | 0x012c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00337 [PROTO_GATE|] `#define NT_STATUS_COMMITMENT_LIMIT (0xC0000000 | 0x012d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00338 [PROTO_GATE|] `#define NT_STATUS_INVALID_IMAGE_LE_FORMAT (0xC0000000 | 0x012e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00339 [PROTO_GATE|] `#define NT_STATUS_INVALID_IMAGE_NOT_MZ (0xC0000000 | 0x012f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00340 [PROTO_GATE|] `#define NT_STATUS_INVALID_IMAGE_PROTECT (0xC0000000 | 0x0130)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00341 [PROTO_GATE|] `#define NT_STATUS_INVALID_IMAGE_WIN_16 (0xC0000000 | 0x0131)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00342 [PROTO_GATE|] `#define NT_STATUS_LOGON_SERVER_CONFLICT (0xC0000000 | 0x0132)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00343 [PROTO_GATE|] `#define NT_STATUS_TIME_DIFFERENCE_AT_DC (0xC0000000 | 0x0133)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00344 [PROTO_GATE|] `#define NT_STATUS_SYNCHRONIZATION_REQUIRED (0xC0000000 | 0x0134)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00345 [PROTO_GATE|] `#define NT_STATUS_DLL_NOT_FOUND (0xC0000000 | 0x0135)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00346 [PROTO_GATE|] `#define NT_STATUS_OPEN_FAILED (0xC0000000 | 0x0136)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00347 [PROTO_GATE|] `#define NT_STATUS_IO_PRIVILEGE_FAILED (0xC0000000 | 0x0137)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00348 [PROTO_GATE|] `#define NT_STATUS_ORDINAL_NOT_FOUND (0xC0000000 | 0x0138)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00349 [PROTO_GATE|] `#define NT_STATUS_ENTRYPOINT_NOT_FOUND (0xC0000000 | 0x0139)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00350 [PROTO_GATE|] `#define NT_STATUS_CONTROL_C_EXIT (0xC0000000 | 0x013a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00351 [PROTO_GATE|] `#define NT_STATUS_LOCAL_DISCONNECT (0xC0000000 | 0x013b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00352 [PROTO_GATE|] `#define NT_STATUS_REMOTE_DISCONNECT (0xC0000000 | 0x013c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00353 [PROTO_GATE|] `#define NT_STATUS_REMOTE_RESOURCES (0xC0000000 | 0x013d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00354 [PROTO_GATE|] `#define NT_STATUS_LINK_FAILED (0xC0000000 | 0x013e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00355 [PROTO_GATE|] `#define NT_STATUS_LINK_TIMEOUT (0xC0000000 | 0x013f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00356 [PROTO_GATE|] `#define NT_STATUS_INVALID_CONNECTION (0xC0000000 | 0x0140)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00357 [PROTO_GATE|] `#define NT_STATUS_INVALID_ADDRESS (0xC0000000 | 0x0141)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00358 [PROTO_GATE|] `#define NT_STATUS_DLL_INIT_FAILED (0xC0000000 | 0x0142)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00359 [PROTO_GATE|] `#define NT_STATUS_MISSING_SYSTEMFILE (0xC0000000 | 0x0143)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00360 [PROTO_GATE|] `#define NT_STATUS_UNHANDLED_EXCEPTION (0xC0000000 | 0x0144)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00361 [PROTO_GATE|] `#define NT_STATUS_APP_INIT_FAILURE (0xC0000000 | 0x0145)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00362 [PROTO_GATE|] `#define NT_STATUS_PAGEFILE_CREATE_FAILED (0xC0000000 | 0x0146)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00363 [PROTO_GATE|] `#define NT_STATUS_NO_PAGEFILE (0xC0000000 | 0x0147)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00364 [PROTO_GATE|] `#define NT_STATUS_INVALID_LEVEL (0xC0000000 | 0x0148)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00365 [PROTO_GATE|] `#define NT_STATUS_WRONG_PASSWORD_CORE (0xC0000000 | 0x0149)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00366 [PROTO_GATE|] `#define NT_STATUS_ILLEGAL_FLOAT_CONTEXT (0xC0000000 | 0x014a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00367 [PROTO_GATE|] `#define NT_STATUS_PIPE_BROKEN (0xC0000000 | 0x014b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00368 [PROTO_GATE|] `#define NT_STATUS_REGISTRY_CORRUPT (0xC0000000 | 0x014c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00369 [PROTO_GATE|] `#define NT_STATUS_REGISTRY_IO_FAILED (0xC0000000 | 0x014d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00370 [PROTO_GATE|] `#define NT_STATUS_NO_EVENT_PAIR (0xC0000000 | 0x014e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00371 [PROTO_GATE|] `#define NT_STATUS_UNRECOGNIZED_VOLUME (0xC0000000 | 0x014f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00372 [PROTO_GATE|] `#define NT_STATUS_SERIAL_NO_DEVICE_INITED (0xC0000000 | 0x0150)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00373 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_ALIAS (0xC0000000 | 0x0151)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00374 [PROTO_GATE|] `#define NT_STATUS_MEMBER_NOT_IN_ALIAS (0xC0000000 | 0x0152)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00375 [PROTO_GATE|] `#define NT_STATUS_MEMBER_IN_ALIAS (0xC0000000 | 0x0153)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00376 [PROTO_GATE|] `#define NT_STATUS_ALIAS_EXISTS (0xC0000000 | 0x0154)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00377 [PROTO_GATE|] `#define NT_STATUS_LOGON_NOT_GRANTED (0xC0000000 | 0x0155)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00378 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_SECRETS (0xC0000000 | 0x0156)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00379 [PROTO_GATE|] `#define NT_STATUS_SECRET_TOO_LONG (0xC0000000 | 0x0157)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00380 [PROTO_GATE|] `#define NT_STATUS_INTERNAL_DB_ERROR (0xC0000000 | 0x0158)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00381 [PROTO_GATE|] `#define NT_STATUS_FULLSCREEN_MODE (0xC0000000 | 0x0159)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00382 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_CONTEXT_IDS (0xC0000000 | 0x015a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00383 [PROTO_GATE|] `#define NT_STATUS_LOGON_TYPE_NOT_GRANTED (0xC0000000 | 0x015b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00384 [PROTO_GATE|] `#define NT_STATUS_NOT_REGISTRY_FILE (0xC0000000 | 0x015c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00385 [PROTO_GATE|] `#define NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED (0xC0000000 | 0x015d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00386 [PROTO_GATE|] `#define NT_STATUS_DOMAIN_CTRLR_CONFIG_ERROR (0xC0000000 | 0x015e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00387 [PROTO_GATE|] `#define NT_STATUS_FT_MISSING_MEMBER (0xC0000000 | 0x015f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00388 [PROTO_GATE|] `#define NT_STATUS_ILL_FORMED_SERVICE_ENTRY (0xC0000000 | 0x0160)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00389 [PROTO_GATE|] `#define NT_STATUS_ILLEGAL_CHARACTER (0xC0000000 | 0x0161)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00390 [PROTO_GATE|] `#define NT_STATUS_UNMAPPABLE_CHARACTER (0xC0000000 | 0x0162)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00391 [PROTO_GATE|] `#define NT_STATUS_UNDEFINED_CHARACTER (0xC0000000 | 0x0163)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00392 [PROTO_GATE|] `#define NT_STATUS_FLOPPY_VOLUME (0xC0000000 | 0x0164)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00393 [PROTO_GATE|] `#define NT_STATUS_FLOPPY_ID_MARK_NOT_FOUND (0xC0000000 | 0x0165)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00394 [PROTO_GATE|] `#define NT_STATUS_FLOPPY_WRONG_CYLINDER (0xC0000000 | 0x0166)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00395 [PROTO_GATE|] `#define NT_STATUS_FLOPPY_UNKNOWN_ERROR (0xC0000000 | 0x0167)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00396 [PROTO_GATE|] `#define NT_STATUS_FLOPPY_BAD_REGISTERS (0xC0000000 | 0x0168)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00397 [PROTO_GATE|] `#define NT_STATUS_DISK_RECALIBRATE_FAILED (0xC0000000 | 0x0169)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00398 [PROTO_GATE|] `#define NT_STATUS_DISK_OPERATION_FAILED (0xC0000000 | 0x016a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00399 [PROTO_GATE|] `#define NT_STATUS_DISK_RESET_FAILED (0xC0000000 | 0x016b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00400 [PROTO_GATE|] `#define NT_STATUS_SHARED_IRQ_BUSY (0xC0000000 | 0x016c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00401 [PROTO_GATE|] `#define NT_STATUS_FT_ORPHANING (0xC0000000 | 0x016d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00402 [PROTO_GATE|] `#define NT_STATUS_PARTITION_FAILURE (0xC0000000 | 0x0172)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00403 [PROTO_GATE|] `#define NT_STATUS_INVALID_BLOCK_LENGTH (0xC0000000 | 0x0173)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00404 [PROTO_GATE|] `#define NT_STATUS_DEVICE_NOT_PARTITIONED (0xC0000000 | 0x0174)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00405 [PROTO_GATE|] `#define NT_STATUS_UNABLE_TO_LOCK_MEDIA (0xC0000000 | 0x0175)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00406 [PROTO_GATE|] `#define NT_STATUS_UNABLE_TO_UNLOAD_MEDIA (0xC0000000 | 0x0176)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00407 [PROTO_GATE|] `#define NT_STATUS_EOM_OVERFLOW (0xC0000000 | 0x0177)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00408 [PROTO_GATE|] `#define NT_STATUS_NO_MEDIA (0xC0000000 | 0x0178)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00409 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_MEMBER (0xC0000000 | 0x017a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00410 [PROTO_GATE|] `#define NT_STATUS_INVALID_MEMBER (0xC0000000 | 0x017b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00411 [PROTO_GATE|] `#define NT_STATUS_KEY_DELETED (0xC0000000 | 0x017c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00412 [PROTO_GATE|] `#define NT_STATUS_NO_LOG_SPACE (0xC0000000 | 0x017d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00413 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_SIDS (0xC0000000 | 0x017e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00414 [PROTO_GATE|] `#define NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED (0xC0000000 | 0x017f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00415 [PROTO_GATE|] `#define NT_STATUS_KEY_HAS_CHILDREN (0xC0000000 | 0x0180)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00416 [PROTO_GATE|] `#define NT_STATUS_CHILD_MUST_BE_VOLATILE (0xC0000000 | 0x0181)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00417 [PROTO_GATE|] `#define NT_STATUS_DEVICE_CONFIGURATION_ERROR (0xC0000000 | 0x0182)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00418 [PROTO_GATE|] `#define NT_STATUS_DRIVER_INTERNAL_ERROR (0xC0000000 | 0x0183)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00419 [PROTO_GATE|] `#define NT_STATUS_INVALID_DEVICE_STATE (0xC0000000 | 0x0184)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00420 [PROTO_GATE|] `#define NT_STATUS_IO_DEVICE_ERROR (0xC0000000 | 0x0185)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00421 [PROTO_GATE|] `#define NT_STATUS_DEVICE_PROTOCOL_ERROR (0xC0000000 | 0x0186)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00422 [PROTO_GATE|] `#define NT_STATUS_BACKUP_CONTROLLER (0xC0000000 | 0x0187)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00423 [PROTO_GATE|] `#define NT_STATUS_LOG_FILE_FULL (0xC0000000 | 0x0188)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00424 [PROTO_GATE|] `#define NT_STATUS_TOO_LATE (0xC0000000 | 0x0189)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00425 [PROTO_GATE|] `#define NT_STATUS_NO_TRUST_LSA_SECRET (0xC0000000 | 0x018a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00426 [PROTO_GATE|] `#define NT_STATUS_NO_TRUST_SAM_ACCOUNT (0xC0000000 | 0x018b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00427 [PROTO_GATE|] `#define NT_STATUS_TRUSTED_DOMAIN_FAILURE (0xC0000000 | 0x018c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00428 [PROTO_GATE|] `#define NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE (0xC0000000 | 0x018d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00429 [PROTO_GATE|] `#define NT_STATUS_EVENTLOG_FILE_CORRUPT (0xC0000000 | 0x018e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00430 [PROTO_GATE|] `#define NT_STATUS_EVENTLOG_CANT_START (0xC0000000 | 0x018f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00431 [PROTO_GATE|] `#define NT_STATUS_TRUST_FAILURE (0xC0000000 | 0x0190)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00432 [PROTO_GATE|] `#define NT_STATUS_MUTANT_LIMIT_EXCEEDED (0xC0000000 | 0x0191)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00433 [PROTO_GATE|] `#define NT_STATUS_NETLOGON_NOT_STARTED (0xC0000000 | 0x0192)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00434 [PROTO_GATE|] `#define NT_STATUS_ACCOUNT_EXPIRED (0xC0000000 | 0x0193)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00435 [PROTO_GATE|] `#define NT_STATUS_POSSIBLE_DEADLOCK (0xC0000000 | 0x0194)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00436 [PROTO_GATE|] `#define NT_STATUS_NETWORK_CREDENTIAL_CONFLICT (0xC0000000 | 0x0195)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00437 [PROTO_GATE|] `#define NT_STATUS_REMOTE_SESSION_LIMIT (0xC0000000 | 0x0196)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00438 [PROTO_GATE|] `#define NT_STATUS_EVENTLOG_FILE_CHANGED (0xC0000000 | 0x0197)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00439 [PROTO_GATE|] `#define NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT (0xC0000000 | 0x0198)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00440 [PROTO_GATE|] `#define NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT (0xC0000000 | 0x0199)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00441 [PROTO_GATE|] `#define NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT (0xC0000000 | 0x019a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00442 [PROTO_GATE|] `#define NT_STATUS_DOMAIN_TRUST_INCONSISTENT (0xC0000000 | 0x019b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00443 [PROTO_GATE|] `#define NT_STATUS_FS_DRIVER_REQUIRED (0xC0000000 | 0x019c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00444 [PROTO_GATE|] `#define NT_STATUS_NO_USER_SESSION_KEY (0xC0000000 | 0x0202)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00445 [PROTO_GATE|] `#define NT_STATUS_USER_SESSION_DELETED (0xC0000000 | 0x0203)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00446 [PROTO_GATE|] `#define NT_STATUS_RESOURCE_LANG_NOT_FOUND (0xC0000000 | 0x0204)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00447 [PROTO_GATE|] `#define NT_STATUS_INSUFF_SERVER_RESOURCES (0xC0000000 | 0x0205)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00448 [PROTO_GATE|] `#define NT_STATUS_INVALID_BUFFER_SIZE (0xC0000000 | 0x0206)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00449 [PROTO_GATE|] `#define NT_STATUS_INVALID_ADDRESS_COMPONENT (0xC0000000 | 0x0207)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00450 [PROTO_GATE|] `#define NT_STATUS_INVALID_ADDRESS_WILDCARD (0xC0000000 | 0x0208)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00451 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_ADDRESSES (0xC0000000 | 0x0209)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00452 [PROTO_GATE|] `#define NT_STATUS_ADDRESS_ALREADY_EXISTS (0xC0000000 | 0x020a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00453 [PROTO_GATE|] `#define NT_STATUS_ADDRESS_CLOSED (0xC0000000 | 0x020b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00454 [PROTO_GATE|] `#define NT_STATUS_CONNECTION_DISCONNECTED (0xC0000000 | 0x020c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00455 [PROTO_GATE|] `#define NT_STATUS_CONNECTION_RESET (0xC0000000 | 0x020d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00456 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_NODES (0xC0000000 | 0x020e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00457 [PROTO_GATE|] `#define NT_STATUS_TRANSACTION_ABORTED (0xC0000000 | 0x020f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00458 [PROTO_GATE|] `#define NT_STATUS_TRANSACTION_TIMED_OUT (0xC0000000 | 0x0210)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00459 [PROTO_GATE|] `#define NT_STATUS_TRANSACTION_NO_RELEASE (0xC0000000 | 0x0211)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00460 [PROTO_GATE|] `#define NT_STATUS_TRANSACTION_NO_MATCH (0xC0000000 | 0x0212)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00461 [PROTO_GATE|] `#define NT_STATUS_TRANSACTION_RESPONDED (0xC0000000 | 0x0213)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00462 [PROTO_GATE|] `#define NT_STATUS_TRANSACTION_INVALID_ID (0xC0000000 | 0x0214)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00463 [PROTO_GATE|] `#define NT_STATUS_TRANSACTION_INVALID_TYPE (0xC0000000 | 0x0215)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00464 [PROTO_GATE|] `#define NT_STATUS_NOT_SERVER_SESSION (0xC0000000 | 0x0216)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00465 [PROTO_GATE|] `#define NT_STATUS_NOT_CLIENT_SESSION (0xC0000000 | 0x0217)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00466 [PROTO_GATE|] `#define NT_STATUS_CANNOT_LOAD_REGISTRY_FILE (0xC0000000 | 0x0218)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00467 [PROTO_GATE|] `#define NT_STATUS_DEBUG_ATTACH_FAILED (0xC0000000 | 0x0219)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00468 [PROTO_GATE|] `#define NT_STATUS_SYSTEM_PROCESS_TERMINATED (0xC0000000 | 0x021a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00469 [PROTO_GATE|] `#define NT_STATUS_DATA_NOT_ACCEPTED (0xC0000000 | 0x021b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00470 [PROTO_GATE|] `#define NT_STATUS_NO_BROWSER_SERVERS_FOUND (0xC0000000 | 0x021c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00471 [PROTO_GATE|] `#define NT_STATUS_VDM_HARD_ERROR (0xC0000000 | 0x021d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00472 [PROTO_GATE|] `#define NT_STATUS_DRIVER_CANCEL_TIMEOUT (0xC0000000 | 0x021e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00473 [PROTO_GATE|] `#define NT_STATUS_REPLY_MESSAGE_MISMATCH (0xC0000000 | 0x021f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00474 [PROTO_GATE|] `#define NT_STATUS_MAPPED_ALIGNMENT (0xC0000000 | 0x0220)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00475 [PROTO_GATE|] `#define NT_STATUS_IMAGE_CHECKSUM_MISMATCH (0xC0000000 | 0x0221)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00476 [PROTO_GATE|] `#define NT_STATUS_LOST_WRITEBEHIND_DATA (0xC0000000 | 0x0222)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00477 [PROTO_GATE|] `#define NT_STATUS_CLIENT_SERVER_PARAMETERS_INVALID (0xC0000000 | 0x0223)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00478 [PROTO_GATE|] `#define NT_STATUS_PASSWORD_MUST_CHANGE (0xC0000000 | 0x0224)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00479 [PROTO_GATE|] `#define NT_STATUS_NOT_FOUND (0xC0000000 | 0x0225)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00480 [PROTO_GATE|] `#define NT_STATUS_NOT_TINY_STREAM (0xC0000000 | 0x0226)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00481 [PROTO_GATE|] `#define NT_STATUS_RECOVERY_FAILURE (0xC0000000 | 0x0227)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00482 [PROTO_GATE|] `#define NT_STATUS_STACK_OVERFLOW_READ (0xC0000000 | 0x0228)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00483 [PROTO_GATE|] `#define NT_STATUS_FAIL_CHECK (0xC0000000 | 0x0229)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00484 [PROTO_GATE|] `#define NT_STATUS_DUPLICATE_OBJECTID (0xC0000000 | 0x022a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00485 [PROTO_GATE|] `#define NT_STATUS_OBJECTID_EXISTS (0xC0000000 | 0x022b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00486 [PROTO_GATE|] `#define NT_STATUS_CONVERT_TO_LARGE (0xC0000000 | 0x022c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00487 [PROTO_GATE|] `#define NT_STATUS_RETRY (0xC0000000 | 0x022d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00488 [PROTO_GATE|] `#define NT_STATUS_FOUND_OUT_OF_SCOPE (0xC0000000 | 0x022e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00489 [PROTO_GATE|] `#define NT_STATUS_ALLOCATE_BUCKET (0xC0000000 | 0x022f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00490 [PROTO_GATE|] `#define NT_STATUS_PROPSET_NOT_FOUND (0xC0000000 | 0x0230)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00491 [PROTO_GATE|] `#define NT_STATUS_MARSHALL_OVERFLOW (0xC0000000 | 0x0231)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00492 [PROTO_GATE|] `#define NT_STATUS_INVALID_VARIANT (0xC0000000 | 0x0232)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00493 [PROTO_GATE|] `#define NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND (0xC0000000 | 0x0233)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00494 [PROTO_GATE|] `#define NT_STATUS_ACCOUNT_LOCKED_OUT (0xC0000000 | 0x0234)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00495 [PROTO_GATE|] `#define NT_STATUS_HANDLE_NOT_CLOSABLE (0xC0000000 | 0x0235)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00496 [PROTO_GATE|] `#define NT_STATUS_CONNECTION_REFUSED (0xC0000000 | 0x0236)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00497 [PROTO_GATE|] `#define NT_STATUS_GRACEFUL_DISCONNECT (0xC0000000 | 0x0237)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00498 [PROTO_GATE|] `#define NT_STATUS_ADDRESS_ALREADY_ASSOCIATED (0xC0000000 | 0x0238)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00499 [PROTO_GATE|] `#define NT_STATUS_ADDRESS_NOT_ASSOCIATED (0xC0000000 | 0x0239)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00500 [PROTO_GATE|] `#define NT_STATUS_CONNECTION_INVALID (0xC0000000 | 0x023a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00501 [PROTO_GATE|] `#define NT_STATUS_CONNECTION_ACTIVE (0xC0000000 | 0x023b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00502 [PROTO_GATE|] `#define NT_STATUS_NETWORK_UNREACHABLE (0xC0000000 | 0x023c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00503 [PROTO_GATE|] `#define NT_STATUS_HOST_UNREACHABLE (0xC0000000 | 0x023d)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00504 [PROTO_GATE|] `#define NT_STATUS_PROTOCOL_UNREACHABLE (0xC0000000 | 0x023e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00505 [PROTO_GATE|] `#define NT_STATUS_PORT_UNREACHABLE (0xC0000000 | 0x023f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00506 [PROTO_GATE|] `#define NT_STATUS_REQUEST_ABORTED (0xC0000000 | 0x0240)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00507 [PROTO_GATE|] `#define NT_STATUS_CONNECTION_ABORTED (0xC0000000 | 0x0241)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00508 [PROTO_GATE|] `#define NT_STATUS_BAD_COMPRESSION_BUFFER (0xC0000000 | 0x0242)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00509 [PROTO_GATE|] `#define NT_STATUS_USER_MAPPED_FILE (0xC0000000 | 0x0243)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00510 [PROTO_GATE|] `#define NT_STATUS_AUDIT_FAILED (0xC0000000 | 0x0244)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00511 [PROTO_GATE|] `#define NT_STATUS_TIMER_RESOLUTION_NOT_SET (0xC0000000 | 0x0245)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00512 [PROTO_GATE|] `#define NT_STATUS_CONNECTION_COUNT_LIMIT (0xC0000000 | 0x0246)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00513 [PROTO_GATE|] `#define NT_STATUS_LOGIN_TIME_RESTRICTION (0xC0000000 | 0x0247)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00514 [PROTO_GATE|] `#define NT_STATUS_LOGIN_WKSTA_RESTRICTION (0xC0000000 | 0x0248)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00515 [PROTO_GATE|] `#define NT_STATUS_IMAGE_MP_UP_MISMATCH (0xC0000000 | 0x0249)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00516 [PROTO_GATE|] `#define NT_STATUS_INSUFFICIENT_LOGON_INFO (0xC0000000 | 0x0250)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00517 [PROTO_GATE|] `#define NT_STATUS_BAD_DLL_ENTRYPOINT (0xC0000000 | 0x0251)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00518 [PROTO_GATE|] `#define NT_STATUS_BAD_SERVICE_ENTRYPOINT (0xC0000000 | 0x0252)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00519 [PROTO_GATE|] `#define NT_STATUS_LPC_REPLY_LOST (0xC0000000 | 0x0253)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00520 [PROTO_GATE|] `#define NT_STATUS_IP_ADDRESS_CONFLICT1 (0xC0000000 | 0x0254)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00521 [PROTO_GATE|] `#define NT_STATUS_IP_ADDRESS_CONFLICT2 (0xC0000000 | 0x0255)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00522 [PROTO_GATE|] `#define NT_STATUS_REGISTRY_QUOTA_LIMIT (0xC0000000 | 0x0256)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00523 [PROTO_GATE|] `#define NT_STATUS_PATH_NOT_COVERED (0xC0000000 | 0x0257)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00524 [PROTO_GATE|] `#define NT_STATUS_NO_CALLBACK_ACTIVE (0xC0000000 | 0x0258)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00525 [PROTO_GATE|] `#define NT_STATUS_LICENSE_QUOTA_EXCEEDED (0xC0000000 | 0x0259)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00526 [PROTO_GATE|] `#define NT_STATUS_PWD_TOO_SHORT (0xC0000000 | 0x025a)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00527 [PROTO_GATE|] `#define NT_STATUS_PWD_TOO_RECENT (0xC0000000 | 0x025b)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00528 [PROTO_GATE|] `#define NT_STATUS_PWD_HISTORY_CONFLICT (0xC0000000 | 0x025c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00529 [PROTO_GATE|] `#define NT_STATUS_PLUGPLAY_NO_DEVICE (0xC0000000 | 0x025e)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00530 [PROTO_GATE|] `#define NT_STATUS_UNSUPPORTED_COMPRESSION (0xC0000000 | 0x025f)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00531 [PROTO_GATE|] `#define NT_STATUS_INVALID_HW_PROFILE (0xC0000000 | 0x0260)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00532 [PROTO_GATE|] `#define NT_STATUS_INVALID_PLUGPLAY_DEVICE_PATH (0xC0000000 | 0x0261)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00533 [PROTO_GATE|] `#define NT_STATUS_DRIVER_ORDINAL_NOT_FOUND (0xC0000000 | 0x0262)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00534 [PROTO_GATE|] `#define NT_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND (0xC0000000 | 0x0263)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00535 [PROTO_GATE|] `#define NT_STATUS_RESOURCE_NOT_OWNED (0xC0000000 | 0x0264)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00536 [PROTO_GATE|] `#define NT_STATUS_TOO_MANY_LINKS (0xC0000000 | 0x0265)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00537 [PROTO_GATE|] `#define NT_STATUS_QUOTA_LIST_INCONSISTENT (0xC0000000 | 0x0266)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00538 [PROTO_GATE|] `#define NT_STATUS_FILE_IS_OFFLINE (0xC0000000 | 0x0267)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00539 [PROTO_GATE|] `#define NT_STATUS_NETWORK_SESSION_EXPIRED  (0xC0000000 | 0x035c)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00540 [PROTO_GATE|] `#define NT_STATUS_NO_SUCH_JOB (0xC0000000 | 0xEDE)     /* scheduler */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00541 [PROTO_GATE|] `#define NT_STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP (0xC0000000 | 0x5D0000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00542 [PROTO_GATE|] `#define NT_STATUS_PENDING 0x00000103`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00543 [NONE] `#endif				/* _NTERR_H */`
  Review: Low-risk line; verify in surrounding control flow.
