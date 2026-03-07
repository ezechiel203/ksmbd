# Line-by-line Review: src/include/protocol/smbstatus.h

- L00001 [NONE] `/* SPDX-License-Identifier: LGPL-2.1+ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   fs/cifs/smb2status.h`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   SMB2 Status code (network error) definitions`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Definitions are from MS-ERREF`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   Copyright (c) International Business Machines  Corp., 2009,2011`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   Author(s): Steve French (sfrench@us.ibm.com)`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *  0 1 2 3 4 5 6 7 8 9 0 A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *  SEV C N <-------Facility--------> <------Error Status Code------>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` *  C is set if "customer defined" error, N bit is reserved and MBZ`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [PROTO_GATE|] `#define STATUS_SEVERITY_SUCCESS cpu_to_le32(0x0000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00020 [PROTO_GATE|] `#define STATUS_SEVERITY_INFORMATIONAL cpu_to_le32(0x0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00021 [PROTO_GATE|] `#define STATUS_SEVERITY_WARNING cpu_to_le32(0x0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00022 [PROTO_GATE|] `#define STATUS_SEVERITY_ERROR cpu_to_le32(0x0003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `struct ntstatus {`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	/* Facility is the high 12 bits of the following field */`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	__le32 Facility; /* low 2 bits Severity, next is Customer, then rsrvd */`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	__le32 Code;`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [PROTO_GATE|] `#define STATUS_SUCCESS cpu_to_le32(0x00000000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00031 [PROTO_GATE|] `#define STATUS_WAIT_0 cpu_to_le32(0x00000000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00032 [PROTO_GATE|] `#define STATUS_WAIT_1 cpu_to_le32(0x00000001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00033 [PROTO_GATE|] `#define STATUS_WAIT_2 cpu_to_le32(0x00000002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00034 [PROTO_GATE|] `#define STATUS_WAIT_3 cpu_to_le32(0x00000003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00035 [PROTO_GATE|] `#define STATUS_WAIT_63 cpu_to_le32(0x0000003F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00036 [PROTO_GATE|] `#define STATUS_ABANDONED cpu_to_le32(0x00000080)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00037 [PROTO_GATE|] `#define STATUS_ABANDONED_WAIT_0 cpu_to_le32(0x00000080)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00038 [PROTO_GATE|] `#define STATUS_ABANDONED_WAIT_63 cpu_to_le32(0x000000BF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00039 [PROTO_GATE|] `#define STATUS_USER_APC cpu_to_le32(0x000000C0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00040 [PROTO_GATE|] `#define STATUS_KERNEL_APC cpu_to_le32(0x00000100)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00041 [PROTO_GATE|] `#define STATUS_ALERTED cpu_to_le32(0x00000101)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00042 [PROTO_GATE|] `#define STATUS_TIMEOUT cpu_to_le32(0x00000102)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00043 [PROTO_GATE|] `#define STATUS_PENDING cpu_to_le32(0x00000103)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00044 [PROTO_GATE|] `#define STATUS_REPARSE cpu_to_le32(0x00000104)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00045 [PROTO_GATE|] `#define STATUS_MORE_ENTRIES cpu_to_le32(0x00000105)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00046 [PROTO_GATE|] `#define STATUS_NOT_ALL_ASSIGNED cpu_to_le32(0x00000106)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00047 [PROTO_GATE|] `#define STATUS_SOME_NOT_MAPPED cpu_to_le32(0x00000107)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00048 [PROTO_GATE|] `#define STATUS_OPLOCK_BREAK_IN_PROGRESS cpu_to_le32(0x00000108)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00049 [PROTO_GATE|] `#define STATUS_VOLUME_MOUNTED cpu_to_le32(0x00000109)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00050 [PROTO_GATE|] `#define STATUS_RXACT_COMMITTED cpu_to_le32(0x0000010A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00051 [PROTO_GATE|] `#define STATUS_NOTIFY_CLEANUP cpu_to_le32(0x0000010B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00052 [PROTO_GATE|] `#define STATUS_NOTIFY_ENUM_DIR cpu_to_le32(0x0000010C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00053 [PROTO_GATE|] `#define STATUS_NO_QUOTAS_FOR_ACCOUNT cpu_to_le32(0x0000010D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00054 [PROTO_GATE|] `#define STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED cpu_to_le32(0x0000010E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00055 [PROTO_GATE|] `#define STATUS_PAGE_FAULT_TRANSITION cpu_to_le32(0x00000110)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00056 [PROTO_GATE|] `#define STATUS_PAGE_FAULT_DEMAND_ZERO cpu_to_le32(0x00000111)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00057 [PROTO_GATE|] `#define STATUS_PAGE_FAULT_COPY_ON_WRITE cpu_to_le32(0x00000112)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00058 [PROTO_GATE|] `#define STATUS_PAGE_FAULT_GUARD_PAGE cpu_to_le32(0x00000113)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [PROTO_GATE|] `#define STATUS_PAGE_FAULT_PAGING_FILE cpu_to_le32(0x00000114)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00060 [PROTO_GATE|] `#define STATUS_CACHE_PAGE_LOCKED cpu_to_le32(0x00000115)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00061 [PROTO_GATE|] `#define STATUS_CRASH_DUMP cpu_to_le32(0x00000116)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00062 [PROTO_GATE|] `#define STATUS_BUFFER_ALL_ZEROS cpu_to_le32(0x00000117)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00063 [PROTO_GATE|] `#define STATUS_REPARSE_OBJECT cpu_to_le32(0x00000118)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00064 [PROTO_GATE|] `#define STATUS_RESOURCE_REQUIREMENTS_CHANGED cpu_to_le32(0x00000119)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00065 [PROTO_GATE|] `#define STATUS_TRANSLATION_COMPLETE cpu_to_le32(0x00000120)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00066 [PROTO_GATE|] `#define STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY cpu_to_le32(0x00000121)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00067 [PROTO_GATE|] `#define STATUS_NOTHING_TO_TERMINATE cpu_to_le32(0x00000122)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00068 [PROTO_GATE|] `#define STATUS_PROCESS_NOT_IN_JOB cpu_to_le32(0x00000123)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00069 [PROTO_GATE|] `#define STATUS_PROCESS_IN_JOB cpu_to_le32(0x00000124)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00070 [PROTO_GATE|] `#define STATUS_VOLSNAP_HIBERNATE_READY cpu_to_le32(0x00000125)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00071 [PROTO_GATE|] `#define STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY cpu_to_le32(0x00000126)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00072 [PROTO_GATE|] `#define STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED cpu_to_le32(0x00000127)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00073 [PROTO_GATE|] `#define STATUS_INTERRUPT_STILL_CONNECTED cpu_to_le32(0x00000128)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00074 [PROTO_GATE|] `#define STATUS_PROCESS_CLONED cpu_to_le32(0x00000129)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00075 [PROTO_GATE|] `#define STATUS_FILE_LOCKED_WITH_ONLY_READERS cpu_to_le32(0x0000012A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00076 [PROTO_GATE|] `#define STATUS_FILE_LOCKED_WITH_WRITERS cpu_to_le32(0x0000012B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00077 [PROTO_GATE|] `#define STATUS_RESOURCEMANAGER_READ_ONLY cpu_to_le32(0x00000202)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00078 [PROTO_GATE|] `#define STATUS_WAIT_FOR_OPLOCK cpu_to_le32(0x00000367)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00079 [NONE] `#define DBG_EXCEPTION_HANDLED cpu_to_le32(0x00010001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `#define DBG_CONTINUE cpu_to_le32(0x00010002)`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [PROTO_GATE|] `#define STATUS_FLT_IO_COMPLETE cpu_to_le32(0x001C0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00082 [PROTO_GATE|] `#define STATUS_OBJECT_NAME_EXISTS cpu_to_le32(0x40000000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00083 [PROTO_GATE|] `#define STATUS_THREAD_WAS_SUSPENDED cpu_to_le32(0x40000001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00084 [PROTO_GATE|] `#define STATUS_WORKING_SET_LIMIT_RANGE cpu_to_le32(0x40000002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00085 [PROTO_GATE|] `#define STATUS_IMAGE_NOT_AT_BASE cpu_to_le32(0x40000003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00086 [PROTO_GATE|] `#define STATUS_RXACT_STATE_CREATED cpu_to_le32(0x40000004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00087 [PROTO_GATE|] `#define STATUS_SEGMENT_NOTIFICATION cpu_to_le32(0x40000005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00088 [PROTO_GATE|] `#define STATUS_LOCAL_USER_SESSION_KEY cpu_to_le32(0x40000006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00089 [PROTO_GATE|] `#define STATUS_BAD_CURRENT_DIRECTORY cpu_to_le32(0x40000007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00090 [PROTO_GATE|] `#define STATUS_SERIAL_MORE_WRITES cpu_to_le32(0x40000008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00091 [PROTO_GATE|] `#define STATUS_REGISTRY_RECOVERED cpu_to_le32(0x40000009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00092 [PROTO_GATE|] `#define STATUS_FT_READ_RECOVERY_FROM_BACKUP cpu_to_le32(0x4000000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00093 [PROTO_GATE|] `#define STATUS_FT_WRITE_RECOVERY cpu_to_le32(0x4000000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00094 [PROTO_GATE|] `#define STATUS_SERIAL_COUNTER_TIMEOUT cpu_to_le32(0x4000000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00095 [PROTO_GATE|] `#define STATUS_NULL_LM_PASSWORD cpu_to_le32(0x4000000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00096 [PROTO_GATE|] `#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH cpu_to_le32(0x4000000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00097 [PROTO_GATE|] `#define STATUS_RECEIVE_PARTIAL cpu_to_le32(0x4000000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00098 [PROTO_GATE|] `#define STATUS_RECEIVE_EXPEDITED cpu_to_le32(0x40000010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00099 [PROTO_GATE|] `#define STATUS_RECEIVE_PARTIAL_EXPEDITED cpu_to_le32(0x40000011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00100 [PROTO_GATE|] `#define STATUS_EVENT_DONE cpu_to_le32(0x40000012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00101 [PROTO_GATE|] `#define STATUS_EVENT_PENDING cpu_to_le32(0x40000013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00102 [PROTO_GATE|] `#define STATUS_CHECKING_FILE_SYSTEM cpu_to_le32(0x40000014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00103 [PROTO_GATE|] `#define STATUS_FATAL_APP_EXIT cpu_to_le32(0x40000015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00104 [PROTO_GATE|] `#define STATUS_PREDEFINED_HANDLE cpu_to_le32(0x40000016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00105 [PROTO_GATE|] `#define STATUS_WAS_UNLOCKED cpu_to_le32(0x40000017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00106 [PROTO_GATE|] `#define STATUS_SERVICE_NOTIFICATION cpu_to_le32(0x40000018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00107 [PROTO_GATE|] `#define STATUS_WAS_LOCKED cpu_to_le32(0x40000019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00108 [PROTO_GATE|] `#define STATUS_LOG_HARD_ERROR cpu_to_le32(0x4000001A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00109 [PROTO_GATE|] `#define STATUS_ALREADY_WIN32 cpu_to_le32(0x4000001B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00110 [PROTO_GATE|] `#define STATUS_WX86_UNSIMULATE cpu_to_le32(0x4000001C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00111 [PROTO_GATE|] `#define STATUS_WX86_CONTINUE cpu_to_le32(0x4000001D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00112 [PROTO_GATE|] `#define STATUS_WX86_SINGLE_STEP cpu_to_le32(0x4000001E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00113 [PROTO_GATE|] `#define STATUS_WX86_BREAKPOINT cpu_to_le32(0x4000001F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00114 [PROTO_GATE|] `#define STATUS_WX86_EXCEPTION_CONTINUE cpu_to_le32(0x40000020)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00115 [PROTO_GATE|] `#define STATUS_WX86_EXCEPTION_LASTCHANCE cpu_to_le32(0x40000021)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00116 [PROTO_GATE|] `#define STATUS_WX86_EXCEPTION_CHAIN cpu_to_le32(0x40000022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00117 [PROTO_GATE|] `#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE cpu_to_le32(0x40000023)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00118 [PROTO_GATE|] `#define STATUS_NO_YIELD_PERFORMED cpu_to_le32(0x40000024)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00119 [PROTO_GATE|] `#define STATUS_TIMER_RESUME_IGNORED cpu_to_le32(0x40000025)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00120 [PROTO_GATE|] `#define STATUS_ARBITRATION_UNHANDLED cpu_to_le32(0x40000026)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00121 [PROTO_GATE|] `#define STATUS_CARDBUS_NOT_SUPPORTED cpu_to_le32(0x40000027)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00122 [PROTO_GATE|] `#define STATUS_WX86_CREATEWX86TIB cpu_to_le32(0x40000028)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00123 [PROTO_GATE|] `#define STATUS_MP_PROCESSOR_MISMATCH cpu_to_le32(0x40000029)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00124 [PROTO_GATE|] `#define STATUS_HIBERNATED cpu_to_le32(0x4000002A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00125 [PROTO_GATE|] `#define STATUS_RESUME_HIBERNATION cpu_to_le32(0x4000002B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00126 [PROTO_GATE|] `#define STATUS_FIRMWARE_UPDATED cpu_to_le32(0x4000002C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00127 [PROTO_GATE|] `#define STATUS_DRIVERS_LEAKING_LOCKED_PAGES cpu_to_le32(0x4000002D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00128 [PROTO_GATE|] `#define STATUS_MESSAGE_RETRIEVED cpu_to_le32(0x4000002E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00129 [PROTO_GATE|] `#define STATUS_SYSTEM_POWERSTATE_TRANSITION cpu_to_le32(0x4000002F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00130 [PROTO_GATE|] `#define STATUS_ALPC_CHECK_COMPLETION_LIST cpu_to_le32(0x40000030)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00131 [PROTO_GATE|] `#define STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION cpu_to_le32(0x40000031)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00132 [PROTO_GATE|] `#define STATUS_ACCESS_AUDIT_BY_POLICY cpu_to_le32(0x40000032)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00133 [PROTO_GATE|] `#define STATUS_ABANDON_HIBERFILE cpu_to_le32(0x40000033)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00134 [PROTO_GATE|] `#define STATUS_BIZRULES_NOT_ENABLED cpu_to_le32(0x40000034)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00135 [PROTO_GATE|] `#define STATUS_WAKE_SYSTEM cpu_to_le32(0x40000294)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00136 [PROTO_GATE|] `#define STATUS_DS_SHUTTING_DOWN cpu_to_le32(0x40000370)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00137 [NONE] `#define DBG_REPLY_LATER cpu_to_le32(0x40010001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `#define DBG_UNABLE_TO_PROVIDE_HANDLE cpu_to_le32(0x40010002)`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `#define DBG_TERMINATE_THREAD cpu_to_le32(0x40010003)`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `#define DBG_TERMINATE_PROCESS cpu_to_le32(0x40010004)`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `#define DBG_CONTROL_C cpu_to_le32(0x40010005)`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `#define DBG_PRINTEXCEPTION_C cpu_to_le32(0x40010006)`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `#define DBG_RIPEXCEPTION cpu_to_le32(0x40010007)`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `#define DBG_CONTROL_BREAK cpu_to_le32(0x40010008)`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `#define DBG_COMMAND_EXCEPTION cpu_to_le32(0x40010009)`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `#define RPC_NT_UUID_LOCAL_ONLY cpu_to_le32(0x40020056)`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `#define RPC_NT_SEND_INCOMPLETE cpu_to_le32(0x400200AF)`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [PROTO_GATE|] `#define STATUS_CTX_CDM_CONNECT cpu_to_le32(0x400A0004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00149 [PROTO_GATE|] `#define STATUS_CTX_CDM_DISCONNECT cpu_to_le32(0x400A0005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00150 [PROTO_GATE|] `#define STATUS_SXS_RELEASE_ACTIVATION_CONTEXT cpu_to_le32(0x4015000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00151 [PROTO_GATE|] `#define STATUS_RECOVERY_NOT_NEEDED cpu_to_le32(0x40190034)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00152 [PROTO_GATE|] `#define STATUS_RM_ALREADY_STARTED cpu_to_le32(0x40190035)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00153 [PROTO_GATE|] `#define STATUS_LOG_NO_RESTART cpu_to_le32(0x401A000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00154 [PROTO_GATE|] `#define STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST cpu_to_le32(0x401B00EC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00155 [PROTO_GATE|] `#define STATUS_GRAPHICS_PARTIAL_DATA_POPULATED cpu_to_le32(0x401E000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00156 [PROTO_GATE|] `#define STATUS_GRAPHICS_DRIVER_MISMATCH cpu_to_le32(0x401E0117)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00157 [PROTO_GATE|] `#define STATUS_GRAPHICS_MODE_NOT_PINNED cpu_to_le32(0x401E0307)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00158 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_PREFERRED_MODE cpu_to_le32(0x401E031E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00159 [PROTO_GATE|] `#define STATUS_GRAPHICS_DATASET_IS_EMPTY cpu_to_le32(0x401E034B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00160 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET cpu_to_le32(0x401E034C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00161 [PROTO_GATE|] `#define STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00162 [NONE] `	cpu_to_le32(0x401E0351)`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [PROTO_GATE|] `#define STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS cpu_to_le32(0x401E042F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00164 [PROTO_GATE|] `#define STATUS_GRAPHICS_LEADLINK_START_DEFERRED cpu_to_le32(0x401E0437)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00165 [PROTO_GATE|] `#define STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY cpu_to_le32(0x401E0439)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00166 [PROTO_GATE|] `#define STATUS_GRAPHICS_START_DEFERRED cpu_to_le32(0x401E043A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00167 [PROTO_GATE|] `#define STATUS_NDIS_INDICATION_REQUIRED cpu_to_le32(0x40230001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00168 [PROTO_GATE|] `#define STATUS_GUARD_PAGE_VIOLATION cpu_to_le32(0x80000001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00169 [PROTO_GATE|] `#define STATUS_DATATYPE_MISALIGNMENT cpu_to_le32(0x80000002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00170 [PROTO_GATE|] `#define STATUS_BREAKPOINT cpu_to_le32(0x80000003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00171 [PROTO_GATE|] `#define STATUS_SINGLE_STEP cpu_to_le32(0x80000004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00172 [PROTO_GATE|] `#define STATUS_BUFFER_OVERFLOW cpu_to_le32(0x80000005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00173 [PROTO_GATE|] `#define STATUS_NO_MORE_FILES cpu_to_le32(0x80000006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00174 [PROTO_GATE|] `#define STATUS_WAKE_SYSTEM_DEBUGGER cpu_to_le32(0x80000007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00175 [PROTO_GATE|] `#define STATUS_HANDLES_CLOSED cpu_to_le32(0x8000000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00176 [PROTO_GATE|] `#define STATUS_NO_INHERITANCE cpu_to_le32(0x8000000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00177 [PROTO_GATE|] `#define STATUS_GUID_SUBSTITUTION_MADE cpu_to_le32(0x8000000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00178 [PROTO_GATE|] `#define STATUS_PARTIAL_COPY cpu_to_le32(0x8000000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00179 [PROTO_GATE|] `#define STATUS_DEVICE_PAPER_EMPTY cpu_to_le32(0x8000000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00180 [PROTO_GATE|] `#define STATUS_DEVICE_POWERED_OFF cpu_to_le32(0x8000000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00181 [PROTO_GATE|] `#define STATUS_DEVICE_OFF_LINE cpu_to_le32(0x80000010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00182 [PROTO_GATE|] `#define STATUS_DEVICE_BUSY cpu_to_le32(0x80000011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00183 [PROTO_GATE|] `#define STATUS_NO_MORE_EAS cpu_to_le32(0x80000012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00184 [PROTO_GATE|] `#define STATUS_INVALID_EA_NAME cpu_to_le32(0x80000013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00185 [PROTO_GATE|] `#define STATUS_EA_LIST_INCONSISTENT cpu_to_le32(0x80000014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00186 [PROTO_GATE|] `#define STATUS_INVALID_EA_FLAG cpu_to_le32(0x80000015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00187 [PROTO_GATE|] `#define STATUS_VERIFY_REQUIRED cpu_to_le32(0x80000016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00188 [PROTO_GATE|] `#define STATUS_EXTRANEOUS_INFORMATION cpu_to_le32(0x80000017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00189 [PROTO_GATE|] `#define STATUS_RXACT_COMMIT_NECESSARY cpu_to_le32(0x80000018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00190 [PROTO_GATE|] `#define STATUS_NO_MORE_ENTRIES cpu_to_le32(0x8000001A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00191 [PROTO_GATE|] `#define STATUS_FILEMARK_DETECTED cpu_to_le32(0x8000001B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00192 [PROTO_GATE|] `#define STATUS_MEDIA_CHANGED cpu_to_le32(0x8000001C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00193 [PROTO_GATE|] `#define STATUS_BUS_RESET cpu_to_le32(0x8000001D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00194 [PROTO_GATE|] `#define STATUS_END_OF_MEDIA cpu_to_le32(0x8000001E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00195 [PROTO_GATE|] `#define STATUS_BEGINNING_OF_MEDIA cpu_to_le32(0x8000001F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00196 [PROTO_GATE|] `#define STATUS_MEDIA_CHECK cpu_to_le32(0x80000020)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00197 [PROTO_GATE|] `#define STATUS_SETMARK_DETECTED cpu_to_le32(0x80000021)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00198 [PROTO_GATE|] `#define STATUS_NO_DATA_DETECTED cpu_to_le32(0x80000022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00199 [PROTO_GATE|] `#define STATUS_REDIRECTOR_HAS_OPEN_HANDLES cpu_to_le32(0x80000023)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00200 [PROTO_GATE|] `#define STATUS_SERVER_HAS_OPEN_HANDLES cpu_to_le32(0x80000024)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00201 [PROTO_GATE|] `#define STATUS_ALREADY_DISCONNECTED cpu_to_le32(0x80000025)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00202 [PROTO_GATE|] `#define STATUS_LONGJUMP cpu_to_le32(0x80000026)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00203 [PROTO_GATE|] `#define STATUS_CLEANER_CARTRIDGE_INSTALLED cpu_to_le32(0x80000027)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00204 [PROTO_GATE|] `#define STATUS_PLUGPLAY_QUERY_VETOED cpu_to_le32(0x80000028)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00205 [PROTO_GATE|] `#define STATUS_UNWIND_CONSOLIDATE cpu_to_le32(0x80000029)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00206 [PROTO_GATE|] `#define STATUS_REGISTRY_HIVE_RECOVERED cpu_to_le32(0x8000002A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00207 [PROTO_GATE|] `#define STATUS_DLL_MIGHT_BE_INSECURE cpu_to_le32(0x8000002B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00208 [PROTO_GATE|] `#define STATUS_DLL_MIGHT_BE_INCOMPATIBLE cpu_to_le32(0x8000002C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00209 [PROTO_GATE|] `#define STATUS_STOPPED_ON_SYMLINK cpu_to_le32(0x8000002D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00210 [PROTO_GATE|] `#define STATUS_DEVICE_REQUIRES_CLEANING cpu_to_le32(0x80000288)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00211 [PROTO_GATE|] `#define STATUS_DEVICE_DOOR_OPEN cpu_to_le32(0x80000289)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00212 [PROTO_GATE|] `#define STATUS_DATA_LOST_REPAIR cpu_to_le32(0x80000803)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00213 [NONE] `#define DBG_EXCEPTION_NOT_HANDLED cpu_to_le32(0x80010001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_ALREADY_UP cpu_to_le32(0x80130001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00215 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_ALREADY_DOWN cpu_to_le32(0x80130002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00216 [PROTO_GATE|] `#define STATUS_CLUSTER_NETWORK_ALREADY_ONLINE cpu_to_le32(0x80130003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00217 [PROTO_GATE|] `#define STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE cpu_to_le32(0x80130004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00218 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_ALREADY_MEMBER cpu_to_le32(0x80130005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00219 [PROTO_GATE|] `#define STATUS_COULD_NOT_RESIZE_LOG cpu_to_le32(0x80190009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00220 [PROTO_GATE|] `#define STATUS_NO_TXF_METADATA cpu_to_le32(0x80190029)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00221 [PROTO_GATE|] `#define STATUS_CANT_RECOVER_WITH_HANDLE_OPEN cpu_to_le32(0x80190031)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00222 [PROTO_GATE|] `#define STATUS_TXF_METADATA_ALREADY_PRESENT cpu_to_le32(0x80190041)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00223 [PROTO_GATE|] `#define STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET cpu_to_le32(0x80190042)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00224 [PROTO_GATE|] `#define STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00225 [NONE] `	cpu_to_le32(0x801B00EB)`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [PROTO_GATE|] `#define STATUS_FLT_BUFFER_TOO_SMALL cpu_to_le32(0x801C0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00227 [PROTO_GATE|] `#define STATUS_FVE_PARTIAL_METADATA cpu_to_le32(0x80210001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00228 [PROTO_GATE|] `#define STATUS_UNSUCCESSFUL cpu_to_le32(0xC0000001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00229 [PROTO_GATE|] `#define STATUS_NOT_IMPLEMENTED cpu_to_le32(0xC0000002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00230 [PROTO_GATE|] `#define STATUS_INVALID_INFO_CLASS cpu_to_le32(0xC0000003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00231 [PROTO_GATE|] `#define STATUS_INFO_LENGTH_MISMATCH cpu_to_le32(0xC0000004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00232 [PROTO_GATE|] `#define STATUS_ACCESS_VIOLATION cpu_to_le32(0xC0000005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00233 [PROTO_GATE|] `#define STATUS_IN_PAGE_ERROR cpu_to_le32(0xC0000006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00234 [PROTO_GATE|] `#define STATUS_PAGEFILE_QUOTA cpu_to_le32(0xC0000007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00235 [PROTO_GATE|] `#define STATUS_INVALID_HANDLE cpu_to_le32(0xC0000008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00236 [PROTO_GATE|] `#define STATUS_BAD_INITIAL_STACK cpu_to_le32(0xC0000009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00237 [PROTO_GATE|] `#define STATUS_BAD_INITIAL_PC cpu_to_le32(0xC000000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00238 [PROTO_GATE|] `#define STATUS_INVALID_CID cpu_to_le32(0xC000000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00239 [PROTO_GATE|] `#define STATUS_TIMER_NOT_CANCELED cpu_to_le32(0xC000000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00240 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER cpu_to_le32(0xC000000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00241 [PROTO_GATE|] `#define STATUS_NO_SUCH_DEVICE cpu_to_le32(0xC000000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00242 [PROTO_GATE|] `#define STATUS_NO_SUCH_FILE cpu_to_le32(0xC000000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00243 [PROTO_GATE|] `#define STATUS_INVALID_DEVICE_REQUEST cpu_to_le32(0xC0000010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00244 [PROTO_GATE|] `#define STATUS_END_OF_FILE cpu_to_le32(0xC0000011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00245 [PROTO_GATE|] `#define STATUS_WRONG_VOLUME cpu_to_le32(0xC0000012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00246 [PROTO_GATE|] `#define STATUS_NO_MEDIA_IN_DEVICE cpu_to_le32(0xC0000013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00247 [PROTO_GATE|] `#define STATUS_UNRECOGNIZED_MEDIA cpu_to_le32(0xC0000014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00248 [PROTO_GATE|] `#define STATUS_NONEXISTENT_SECTOR cpu_to_le32(0xC0000015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00249 [PROTO_GATE|] `#define STATUS_MORE_PROCESSING_REQUIRED cpu_to_le32(0xC0000016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00250 [PROTO_GATE|] `#define STATUS_NO_MEMORY cpu_to_le32(0xC0000017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00251 [PROTO_GATE|] `#define STATUS_CONFLICTING_ADDRESSES cpu_to_le32(0xC0000018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00252 [PROTO_GATE|] `#define STATUS_NOT_MAPPED_VIEW cpu_to_le32(0xC0000019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00253 [PROTO_GATE|] `#define STATUS_UNABLE_TO_FREE_VM cpu_to_le32(0xC000001A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00254 [PROTO_GATE|] `#define STATUS_UNABLE_TO_DELETE_SECTION cpu_to_le32(0xC000001B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00255 [PROTO_GATE|] `#define STATUS_INVALID_SYSTEM_SERVICE cpu_to_le32(0xC000001C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00256 [PROTO_GATE|] `#define STATUS_ILLEGAL_INSTRUCTION cpu_to_le32(0xC000001D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00257 [PROTO_GATE|] `#define STATUS_INVALID_LOCK_SEQUENCE cpu_to_le32(0xC000001E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00258 [PROTO_GATE|] `#define STATUS_INVALID_VIEW_SIZE cpu_to_le32(0xC000001F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00259 [PROTO_GATE|] `#define STATUS_INVALID_FILE_FOR_SECTION cpu_to_le32(0xC0000020)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00260 [PROTO_GATE|] `#define STATUS_ALREADY_COMMITTED cpu_to_le32(0xC0000021)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00261 [PROTO_GATE|] `#define STATUS_ACCESS_DENIED cpu_to_le32(0xC0000022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00262 [PROTO_GATE|] `#define STATUS_BUFFER_TOO_SMALL cpu_to_le32(0xC0000023)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00263 [PROTO_GATE|] `#define STATUS_OBJECT_TYPE_MISMATCH cpu_to_le32(0xC0000024)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00264 [PROTO_GATE|] `#define STATUS_NONCONTINUABLE_EXCEPTION cpu_to_le32(0xC0000025)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00265 [PROTO_GATE|] `#define STATUS_INVALID_DISPOSITION cpu_to_le32(0xC0000026)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00266 [PROTO_GATE|] `#define STATUS_UNWIND cpu_to_le32(0xC0000027)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00267 [PROTO_GATE|] `#define STATUS_BAD_STACK cpu_to_le32(0xC0000028)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00268 [PROTO_GATE|] `#define STATUS_INVALID_UNWIND_TARGET cpu_to_le32(0xC0000029)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00269 [PROTO_GATE|] `#define STATUS_NOT_LOCKED cpu_to_le32(0xC000002A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00270 [PROTO_GATE|] `#define STATUS_PARITY_ERROR cpu_to_le32(0xC000002B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00271 [PROTO_GATE|] `#define STATUS_UNABLE_TO_DECOMMIT_VM cpu_to_le32(0xC000002C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00272 [PROTO_GATE|] `#define STATUS_NOT_COMMITTED cpu_to_le32(0xC000002D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00273 [PROTO_GATE|] `#define STATUS_INVALID_PORT_ATTRIBUTES cpu_to_le32(0xC000002E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00274 [PROTO_GATE|] `#define STATUS_PORT_MESSAGE_TOO_LONG cpu_to_le32(0xC000002F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00275 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_MIX cpu_to_le32(0xC0000030)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00276 [PROTO_GATE|] `#define STATUS_INVALID_QUOTA_LOWER cpu_to_le32(0xC0000031)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00277 [PROTO_GATE|] `#define STATUS_DISK_CORRUPT_ERROR cpu_to_le32(0xC0000032)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00278 [PROTO_GATE|] `#define STATUS_OBJECT_NAME_INVALID cpu_to_le32(0xC0000033)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00279 [PROTO_GATE|] `#define STATUS_OBJECT_NAME_NOT_FOUND cpu_to_le32(0xC0000034)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00280 [PROTO_GATE|] `#define STATUS_OBJECT_NAME_COLLISION cpu_to_le32(0xC0000035)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00281 [PROTO_GATE|] `#define STATUS_PORT_DISCONNECTED cpu_to_le32(0xC0000037)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00282 [PROTO_GATE|] `#define STATUS_DEVICE_ALREADY_ATTACHED cpu_to_le32(0xC0000038)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00283 [PROTO_GATE|] `#define STATUS_OBJECT_PATH_INVALID cpu_to_le32(0xC0000039)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00284 [PROTO_GATE|] `#define STATUS_OBJECT_PATH_NOT_FOUND cpu_to_le32(0xC000003A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00285 [PROTO_GATE|] `#define STATUS_OBJECT_PATH_SYNTAX_BAD cpu_to_le32(0xC000003B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00286 [PROTO_GATE|] `#define STATUS_DATA_OVERRUN cpu_to_le32(0xC000003C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00287 [PROTO_GATE|] `#define STATUS_DATA_LATE_ERROR cpu_to_le32(0xC000003D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00288 [PROTO_GATE|] `#define STATUS_DATA_ERROR cpu_to_le32(0xC000003E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00289 [PROTO_GATE|] `#define STATUS_CRC_ERROR cpu_to_le32(0xC000003F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00290 [PROTO_GATE|] `#define STATUS_SECTION_TOO_BIG cpu_to_le32(0xC0000040)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00291 [PROTO_GATE|] `#define STATUS_PORT_CONNECTION_REFUSED cpu_to_le32(0xC0000041)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00292 [PROTO_GATE|] `#define STATUS_INVALID_PORT_HANDLE cpu_to_le32(0xC0000042)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00293 [PROTO_GATE|] `#define STATUS_SHARING_VIOLATION cpu_to_le32(0xC0000043)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00294 [PROTO_GATE|] `#define STATUS_QUOTA_EXCEEDED cpu_to_le32(0xC0000044)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00295 [PROTO_GATE|] `#define STATUS_INVALID_PAGE_PROTECTION cpu_to_le32(0xC0000045)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00296 [PROTO_GATE|] `#define STATUS_MUTANT_NOT_OWNED cpu_to_le32(0xC0000046)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00297 [PROTO_GATE|] `#define STATUS_SEMAPHORE_LIMIT_EXCEEDED cpu_to_le32(0xC0000047)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00298 [PROTO_GATE|] `#define STATUS_PORT_ALREADY_SET cpu_to_le32(0xC0000048)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00299 [PROTO_GATE|] `#define STATUS_SECTION_NOT_IMAGE cpu_to_le32(0xC0000049)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00300 [PROTO_GATE|] `#define STATUS_SUSPEND_COUNT_EXCEEDED cpu_to_le32(0xC000004A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00301 [PROTO_GATE|] `#define STATUS_THREAD_IS_TERMINATING cpu_to_le32(0xC000004B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00302 [PROTO_GATE|] `#define STATUS_BAD_WORKING_SET_LIMIT cpu_to_le32(0xC000004C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00303 [PROTO_GATE|] `#define STATUS_INCOMPATIBLE_FILE_MAP cpu_to_le32(0xC000004D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00304 [PROTO_GATE|] `#define STATUS_SECTION_PROTECTION cpu_to_le32(0xC000004E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00305 [PROTO_GATE|] `#define STATUS_EAS_NOT_SUPPORTED cpu_to_le32(0xC000004F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00306 [PROTO_GATE|] `#define STATUS_EA_TOO_LARGE cpu_to_le32(0xC0000050)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00307 [PROTO_GATE|] `#define STATUS_NONEXISTENT_EA_ENTRY cpu_to_le32(0xC0000051)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00308 [PROTO_GATE|] `#define STATUS_NO_EAS_ON_FILE cpu_to_le32(0xC0000052)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00309 [PROTO_GATE|] `#define STATUS_EA_CORRUPT_ERROR cpu_to_le32(0xC0000053)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00310 [PROTO_GATE|] `#define STATUS_FILE_LOCK_CONFLICT cpu_to_le32(0xC0000054)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00311 [PROTO_GATE|] `#define STATUS_LOCK_NOT_GRANTED cpu_to_le32(0xC0000055)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00312 [PROTO_GATE|] `#define STATUS_DELETE_PENDING cpu_to_le32(0xC0000056)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00313 [PROTO_GATE|] `#define STATUS_CTL_FILE_NOT_SUPPORTED cpu_to_le32(0xC0000057)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00314 [PROTO_GATE|] `#define STATUS_UNKNOWN_REVISION cpu_to_le32(0xC0000058)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00315 [PROTO_GATE|] `#define STATUS_REVISION_MISMATCH cpu_to_le32(0xC0000059)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00316 [PROTO_GATE|] `#define STATUS_INVALID_OWNER cpu_to_le32(0xC000005A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00317 [PROTO_GATE|] `#define STATUS_INVALID_PRIMARY_GROUP cpu_to_le32(0xC000005B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00318 [PROTO_GATE|] `#define STATUS_NO_IMPERSONATION_TOKEN cpu_to_le32(0xC000005C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00319 [PROTO_GATE|] `#define STATUS_CANT_DISABLE_MANDATORY cpu_to_le32(0xC000005D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00320 [PROTO_GATE|] `#define STATUS_NO_LOGON_SERVERS cpu_to_le32(0xC000005E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00321 [PROTO_GATE|] `#define STATUS_NO_SUCH_LOGON_SESSION cpu_to_le32(0xC000005F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00322 [PROTO_GATE|] `#define STATUS_NO_SUCH_PRIVILEGE cpu_to_le32(0xC0000060)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00323 [PROTO_GATE|] `#define STATUS_PRIVILEGE_NOT_HELD cpu_to_le32(0xC0000061)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00324 [PROTO_GATE|] `#define STATUS_INVALID_ACCOUNT_NAME cpu_to_le32(0xC0000062)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00325 [PROTO_GATE|] `#define STATUS_USER_EXISTS cpu_to_le32(0xC0000063)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00326 [PROTO_GATE|] `#define STATUS_NO_SUCH_USER cpu_to_le32(0xC0000064)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00327 [PROTO_GATE|] `#define STATUS_GROUP_EXISTS cpu_to_le32(0xC0000065)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00328 [PROTO_GATE|] `#define STATUS_NO_SUCH_GROUP cpu_to_le32(0xC0000066)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00329 [PROTO_GATE|] `#define STATUS_MEMBER_IN_GROUP cpu_to_le32(0xC0000067)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00330 [PROTO_GATE|] `#define STATUS_MEMBER_NOT_IN_GROUP cpu_to_le32(0xC0000068)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00331 [PROTO_GATE|] `#define STATUS_LAST_ADMIN cpu_to_le32(0xC0000069)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00332 [PROTO_GATE|] `#define STATUS_WRONG_PASSWORD cpu_to_le32(0xC000006A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00333 [PROTO_GATE|] `#define STATUS_ILL_FORMED_PASSWORD cpu_to_le32(0xC000006B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00334 [PROTO_GATE|] `#define STATUS_PASSWORD_RESTRICTION cpu_to_le32(0xC000006C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00335 [PROTO_GATE|] `#define STATUS_LOGON_FAILURE cpu_to_le32(0xC000006D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00336 [PROTO_GATE|] `#define STATUS_ACCOUNT_RESTRICTION cpu_to_le32(0xC000006E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00337 [PROTO_GATE|] `#define STATUS_INVALID_LOGON_HOURS cpu_to_le32(0xC000006F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00338 [PROTO_GATE|] `#define STATUS_INVALID_WORKSTATION cpu_to_le32(0xC0000070)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00339 [PROTO_GATE|] `#define STATUS_PASSWORD_EXPIRED cpu_to_le32(0xC0000071)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00340 [PROTO_GATE|] `#define STATUS_ACCOUNT_DISABLED cpu_to_le32(0xC0000072)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00341 [PROTO_GATE|] `#define STATUS_NONE_MAPPED cpu_to_le32(0xC0000073)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00342 [PROTO_GATE|] `#define STATUS_TOO_MANY_LUIDS_REQUESTED cpu_to_le32(0xC0000074)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00343 [PROTO_GATE|] `#define STATUS_LUIDS_EXHAUSTED cpu_to_le32(0xC0000075)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00344 [PROTO_GATE|] `#define STATUS_INVALID_SUB_AUTHORITY cpu_to_le32(0xC0000076)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00345 [PROTO_GATE|] `#define STATUS_INVALID_ACL cpu_to_le32(0xC0000077)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00346 [PROTO_GATE|] `#define STATUS_INVALID_SID cpu_to_le32(0xC0000078)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00347 [PROTO_GATE|] `#define STATUS_INVALID_SECURITY_DESCR cpu_to_le32(0xC0000079)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00348 [PROTO_GATE|] `#define STATUS_PROCEDURE_NOT_FOUND cpu_to_le32(0xC000007A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00349 [PROTO_GATE|] `#define STATUS_INVALID_IMAGE_FORMAT cpu_to_le32(0xC000007B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00350 [PROTO_GATE|] `#define STATUS_NO_TOKEN cpu_to_le32(0xC000007C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00351 [PROTO_GATE|] `#define STATUS_BAD_INHERITANCE_ACL cpu_to_le32(0xC000007D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00352 [PROTO_GATE|] `#define STATUS_RANGE_NOT_LOCKED cpu_to_le32(0xC000007E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00353 [PROTO_GATE|] `#define STATUS_DISK_FULL cpu_to_le32(0xC000007F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00354 [PROTO_GATE|] `#define STATUS_SERVER_DISABLED cpu_to_le32(0xC0000080)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00355 [PROTO_GATE|] `#define STATUS_SERVER_NOT_DISABLED cpu_to_le32(0xC0000081)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00356 [PROTO_GATE|] `#define STATUS_TOO_MANY_GUIDS_REQUESTED cpu_to_le32(0xC0000082)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00357 [PROTO_GATE|] `#define STATUS_GUIDS_EXHAUSTED cpu_to_le32(0xC0000083)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00358 [PROTO_GATE|] `#define STATUS_INVALID_ID_AUTHORITY cpu_to_le32(0xC0000084)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00359 [PROTO_GATE|] `#define STATUS_AGENTS_EXHAUSTED cpu_to_le32(0xC0000085)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00360 [PROTO_GATE|] `#define STATUS_INVALID_VOLUME_LABEL cpu_to_le32(0xC0000086)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00361 [PROTO_GATE|] `#define STATUS_SECTION_NOT_EXTENDED cpu_to_le32(0xC0000087)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00362 [PROTO_GATE|] `#define STATUS_NOT_MAPPED_DATA cpu_to_le32(0xC0000088)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00363 [PROTO_GATE|] `#define STATUS_RESOURCE_DATA_NOT_FOUND cpu_to_le32(0xC0000089)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00364 [PROTO_GATE|] `#define STATUS_RESOURCE_TYPE_NOT_FOUND cpu_to_le32(0xC000008A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00365 [PROTO_GATE|] `#define STATUS_RESOURCE_NAME_NOT_FOUND cpu_to_le32(0xC000008B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00366 [PROTO_GATE|] `#define STATUS_ARRAY_BOUNDS_EXCEEDED cpu_to_le32(0xC000008C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00367 [PROTO_GATE|] `#define STATUS_FLOAT_DENORMAL_OPERAND cpu_to_le32(0xC000008D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00368 [PROTO_GATE|] `#define STATUS_FLOAT_DIVIDE_BY_ZERO cpu_to_le32(0xC000008E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00369 [PROTO_GATE|] `#define STATUS_FLOAT_INEXACT_RESULT cpu_to_le32(0xC000008F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00370 [PROTO_GATE|] `#define STATUS_FLOAT_INVALID_OPERATION cpu_to_le32(0xC0000090)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00371 [PROTO_GATE|] `#define STATUS_FLOAT_OVERFLOW cpu_to_le32(0xC0000091)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00372 [PROTO_GATE|] `#define STATUS_FLOAT_STACK_CHECK cpu_to_le32(0xC0000092)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00373 [PROTO_GATE|] `#define STATUS_FLOAT_UNDERFLOW cpu_to_le32(0xC0000093)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00374 [PROTO_GATE|] `#define STATUS_INTEGER_DIVIDE_BY_ZERO cpu_to_le32(0xC0000094)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00375 [PROTO_GATE|] `#define STATUS_INTEGER_OVERFLOW cpu_to_le32(0xC0000095)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00376 [PROTO_GATE|] `#define STATUS_PRIVILEGED_INSTRUCTION cpu_to_le32(0xC0000096)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00377 [PROTO_GATE|] `#define STATUS_TOO_MANY_PAGING_FILES cpu_to_le32(0xC0000097)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00378 [PROTO_GATE|] `#define STATUS_FILE_INVALID cpu_to_le32(0xC0000098)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00379 [PROTO_GATE|] `#define STATUS_ALLOTTED_SPACE_EXCEEDED cpu_to_le32(0xC0000099)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00380 [PROTO_GATE|] `#define STATUS_INSUFFICIENT_RESOURCES cpu_to_le32(0xC000009A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00381 [PROTO_GATE|] `#define STATUS_DFS_EXIT_PATH_FOUND cpu_to_le32(0xC000009B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00382 [PROTO_GATE|] `#define STATUS_DEVICE_DATA_ERROR cpu_to_le32(0xC000009C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00383 [PROTO_GATE|] `#define STATUS_DEVICE_NOT_CONNECTED cpu_to_le32(0xC000009D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00384 [PROTO_GATE|] `#define STATUS_DEVICE_POWER_FAILURE cpu_to_le32(0xC000009E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00385 [PROTO_GATE|] `#define STATUS_FREE_VM_NOT_AT_BASE cpu_to_le32(0xC000009F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00386 [PROTO_GATE|] `#define STATUS_MEMORY_NOT_ALLOCATED cpu_to_le32(0xC00000A0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00387 [PROTO_GATE|] `#define STATUS_WORKING_SET_QUOTA cpu_to_le32(0xC00000A1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00388 [PROTO_GATE|] `#define STATUS_MEDIA_WRITE_PROTECTED cpu_to_le32(0xC00000A2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00389 [PROTO_GATE|] `#define STATUS_DEVICE_NOT_READY cpu_to_le32(0xC00000A3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00390 [PROTO_GATE|] `#define STATUS_INVALID_GROUP_ATTRIBUTES cpu_to_le32(0xC00000A4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00391 [PROTO_GATE|] `#define STATUS_BAD_IMPERSONATION_LEVEL cpu_to_le32(0xC00000A5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00392 [PROTO_GATE|] `#define STATUS_CANT_OPEN_ANONYMOUS cpu_to_le32(0xC00000A6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00393 [PROTO_GATE|] `#define STATUS_BAD_VALIDATION_CLASS cpu_to_le32(0xC00000A7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00394 [PROTO_GATE|] `#define STATUS_BAD_TOKEN_TYPE cpu_to_le32(0xC00000A8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00395 [PROTO_GATE|] `#define STATUS_BAD_MASTER_BOOT_RECORD cpu_to_le32(0xC00000A9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00396 [PROTO_GATE|] `#define STATUS_INSTRUCTION_MISALIGNMENT cpu_to_le32(0xC00000AA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00397 [PROTO_GATE|] `#define STATUS_INSTANCE_NOT_AVAILABLE cpu_to_le32(0xC00000AB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00398 [PROTO_GATE|] `#define STATUS_PIPE_NOT_AVAILABLE cpu_to_le32(0xC00000AC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00399 [PROTO_GATE|] `#define STATUS_INVALID_PIPE_STATE cpu_to_le32(0xC00000AD)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00400 [PROTO_GATE|] `#define STATUS_PIPE_BUSY cpu_to_le32(0xC00000AE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00401 [PROTO_GATE|] `#define STATUS_ILLEGAL_FUNCTION cpu_to_le32(0xC00000AF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00402 [PROTO_GATE|] `#define STATUS_PIPE_DISCONNECTED cpu_to_le32(0xC00000B0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00403 [PROTO_GATE|] `#define STATUS_PIPE_CLOSING cpu_to_le32(0xC00000B1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00404 [PROTO_GATE|] `#define STATUS_PIPE_CONNECTED cpu_to_le32(0xC00000B2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00405 [PROTO_GATE|] `#define STATUS_PIPE_LISTENING cpu_to_le32(0xC00000B3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00406 [PROTO_GATE|] `#define STATUS_INVALID_READ_MODE cpu_to_le32(0xC00000B4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00407 [PROTO_GATE|] `#define STATUS_IO_TIMEOUT cpu_to_le32(0xC00000B5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00408 [PROTO_GATE|] `#define STATUS_FILE_FORCED_CLOSED cpu_to_le32(0xC00000B6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00409 [PROTO_GATE|] `#define STATUS_PROFILING_NOT_STARTED cpu_to_le32(0xC00000B7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00410 [PROTO_GATE|] `#define STATUS_PROFILING_NOT_STOPPED cpu_to_le32(0xC00000B8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00411 [PROTO_GATE|] `#define STATUS_COULD_NOT_INTERPRET cpu_to_le32(0xC00000B9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00412 [PROTO_GATE|] `#define STATUS_FILE_IS_A_DIRECTORY cpu_to_le32(0xC00000BA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00413 [PROTO_GATE|] `#define STATUS_NOT_SUPPORTED cpu_to_le32(0xC00000BB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00414 [PROTO_GATE|] `#define STATUS_REMOTE_NOT_LISTENING cpu_to_le32(0xC00000BC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00415 [PROTO_GATE|] `#define STATUS_DUPLICATE_NAME cpu_to_le32(0xC00000BD)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00416 [PROTO_GATE|] `#define STATUS_BAD_NETWORK_PATH cpu_to_le32(0xC00000BE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00417 [PROTO_GATE|] `#define STATUS_NETWORK_BUSY cpu_to_le32(0xC00000BF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00418 [PROTO_GATE|] `#define STATUS_DEVICE_DOES_NOT_EXIST cpu_to_le32(0xC00000C0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00419 [PROTO_GATE|] `#define STATUS_TOO_MANY_COMMANDS cpu_to_le32(0xC00000C1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00420 [PROTO_GATE|] `#define STATUS_ADAPTER_HARDWARE_ERROR cpu_to_le32(0xC00000C2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00421 [PROTO_GATE|] `#define STATUS_INVALID_NETWORK_RESPONSE cpu_to_le32(0xC00000C3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00422 [PROTO_GATE|] `#define STATUS_UNEXPECTED_NETWORK_ERROR cpu_to_le32(0xC00000C4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00423 [PROTO_GATE|] `#define STATUS_BAD_REMOTE_ADAPTER cpu_to_le32(0xC00000C5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00424 [PROTO_GATE|] `#define STATUS_PRINT_QUEUE_FULL cpu_to_le32(0xC00000C6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00425 [PROTO_GATE|] `#define STATUS_NO_SPOOL_SPACE cpu_to_le32(0xC00000C7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00426 [PROTO_GATE|] `#define STATUS_PRINT_CANCELLED cpu_to_le32(0xC00000C8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00427 [PROTO_GATE|] `#define STATUS_NETWORK_NAME_DELETED cpu_to_le32(0xC00000C9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00428 [PROTO_GATE|] `#define STATUS_NETWORK_ACCESS_DENIED cpu_to_le32(0xC00000CA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00429 [PROTO_GATE|] `#define STATUS_BAD_DEVICE_TYPE cpu_to_le32(0xC00000CB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00430 [PROTO_GATE|] `#define STATUS_BAD_NETWORK_NAME cpu_to_le32(0xC00000CC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00431 [PROTO_GATE|] `#define STATUS_TOO_MANY_NAMES cpu_to_le32(0xC00000CD)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00432 [PROTO_GATE|] `#define STATUS_TOO_MANY_SESSIONS cpu_to_le32(0xC00000CE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00433 [PROTO_GATE|] `#define STATUS_SHARING_PAUSED cpu_to_le32(0xC00000CF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00434 [PROTO_GATE|] `#define STATUS_REQUEST_NOT_ACCEPTED cpu_to_le32(0xC00000D0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00435 [PROTO_GATE|] `#define STATUS_REDIRECTOR_PAUSED cpu_to_le32(0xC00000D1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00436 [PROTO_GATE|] `#define STATUS_NET_WRITE_FAULT cpu_to_le32(0xC00000D2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00437 [PROTO_GATE|] `#define STATUS_PROFILING_AT_LIMIT cpu_to_le32(0xC00000D3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00438 [PROTO_GATE|] `#define STATUS_NOT_SAME_DEVICE cpu_to_le32(0xC00000D4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00439 [PROTO_GATE|] `#define STATUS_FILE_RENAMED cpu_to_le32(0xC00000D5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00440 [LIFETIME|PROTO_GATE|] `#define STATUS_VIRTUAL_CIRCUIT_CLOSED cpu_to_le32(0xC00000D6)`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00441 [PROTO_GATE|] `#define STATUS_NO_SECURITY_ON_OBJECT cpu_to_le32(0xC00000D7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00442 [PROTO_GATE|] `#define STATUS_CANT_WAIT cpu_to_le32(0xC00000D8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00443 [PROTO_GATE|] `#define STATUS_PIPE_EMPTY cpu_to_le32(0xC00000D9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00444 [PROTO_GATE|] `#define STATUS_CANT_ACCESS_DOMAIN_INFO cpu_to_le32(0xC00000DA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00445 [PROTO_GATE|] `#define STATUS_CANT_TERMINATE_SELF cpu_to_le32(0xC00000DB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00446 [PROTO_GATE|] `#define STATUS_INVALID_SERVER_STATE cpu_to_le32(0xC00000DC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00447 [PROTO_GATE|] `#define STATUS_INVALID_DOMAIN_STATE cpu_to_le32(0xC00000DD)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00448 [PROTO_GATE|] `#define STATUS_INVALID_DOMAIN_ROLE cpu_to_le32(0xC00000DE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00449 [PROTO_GATE|] `#define STATUS_NO_SUCH_DOMAIN cpu_to_le32(0xC00000DF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00450 [PROTO_GATE|] `#define STATUS_DOMAIN_EXISTS cpu_to_le32(0xC00000E0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00451 [PROTO_GATE|] `#define STATUS_DOMAIN_LIMIT_EXCEEDED cpu_to_le32(0xC00000E1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00452 [PROTO_GATE|] `#define STATUS_OPLOCK_NOT_GRANTED cpu_to_le32(0xC00000E2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00453 [PROTO_GATE|] `#define STATUS_INVALID_OPLOCK_PROTOCOL cpu_to_le32(0xC00000E3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00454 [PROTO_GATE|] `#define STATUS_INTERNAL_DB_CORRUPTION cpu_to_le32(0xC00000E4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00455 [PROTO_GATE|] `#define STATUS_INTERNAL_ERROR cpu_to_le32(0xC00000E5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00456 [PROTO_GATE|] `#define STATUS_GENERIC_NOT_MAPPED cpu_to_le32(0xC00000E6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00457 [PROTO_GATE|] `#define STATUS_BAD_DESCRIPTOR_FORMAT cpu_to_le32(0xC00000E7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00458 [PROTO_GATE|] `#define STATUS_INVALID_USER_BUFFER cpu_to_le32(0xC00000E8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00459 [PROTO_GATE|] `#define STATUS_UNEXPECTED_IO_ERROR cpu_to_le32(0xC00000E9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00460 [PROTO_GATE|] `#define STATUS_UNEXPECTED_MM_CREATE_ERR cpu_to_le32(0xC00000EA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00461 [PROTO_GATE|] `#define STATUS_UNEXPECTED_MM_MAP_ERROR cpu_to_le32(0xC00000EB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00462 [PROTO_GATE|] `#define STATUS_UNEXPECTED_MM_EXTEND_ERR cpu_to_le32(0xC00000EC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00463 [PROTO_GATE|] `#define STATUS_NOT_LOGON_PROCESS cpu_to_le32(0xC00000ED)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00464 [PROTO_GATE|] `#define STATUS_LOGON_SESSION_EXISTS cpu_to_le32(0xC00000EE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00465 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_1 cpu_to_le32(0xC00000EF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00466 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_2 cpu_to_le32(0xC00000F0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00467 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_3 cpu_to_le32(0xC00000F1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00468 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_4 cpu_to_le32(0xC00000F2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00469 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_5 cpu_to_le32(0xC00000F3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00470 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_6 cpu_to_le32(0xC00000F4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00471 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_7 cpu_to_le32(0xC00000F5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00472 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_8 cpu_to_le32(0xC00000F6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00473 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_9 cpu_to_le32(0xC00000F7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00474 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_10 cpu_to_le32(0xC00000F8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00475 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_11 cpu_to_le32(0xC00000F9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00476 [PROTO_GATE|] `#define STATUS_INVALID_PARAMETER_12 cpu_to_le32(0xC00000FA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00477 [PROTO_GATE|] `#define STATUS_REDIRECTOR_NOT_STARTED cpu_to_le32(0xC00000FB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00478 [PROTO_GATE|] `#define STATUS_REDIRECTOR_STARTED cpu_to_le32(0xC00000FC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00479 [PROTO_GATE|] `#define STATUS_STACK_OVERFLOW cpu_to_le32(0xC00000FD)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00480 [PROTO_GATE|] `#define STATUS_NO_SUCH_PACKAGE cpu_to_le32(0xC00000FE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00481 [PROTO_GATE|] `#define STATUS_BAD_FUNCTION_TABLE cpu_to_le32(0xC00000FF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00482 [PROTO_GATE|] `#define STATUS_VARIABLE_NOT_FOUND cpu_to_le32(0xC0000100)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00483 [PROTO_GATE|] `#define STATUS_DIRECTORY_NOT_EMPTY cpu_to_le32(0xC0000101)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00484 [PROTO_GATE|] `#define STATUS_FILE_CORRUPT_ERROR cpu_to_le32(0xC0000102)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00485 [PROTO_GATE|] `#define STATUS_NOT_A_DIRECTORY cpu_to_le32(0xC0000103)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00486 [PROTO_GATE|] `#define STATUS_BAD_LOGON_SESSION_STATE cpu_to_le32(0xC0000104)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00487 [PROTO_GATE|] `#define STATUS_LOGON_SESSION_COLLISION cpu_to_le32(0xC0000105)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00488 [PROTO_GATE|] `#define STATUS_NAME_TOO_LONG cpu_to_le32(0xC0000106)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00489 [PROTO_GATE|] `#define STATUS_FILES_OPEN cpu_to_le32(0xC0000107)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00490 [PROTO_GATE|] `#define STATUS_CONNECTION_IN_USE cpu_to_le32(0xC0000108)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00491 [PROTO_GATE|] `#define STATUS_MESSAGE_NOT_FOUND cpu_to_le32(0xC0000109)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00492 [PROTO_GATE|] `#define STATUS_PROCESS_IS_TERMINATING cpu_to_le32(0xC000010A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00493 [PROTO_GATE|] `#define STATUS_INVALID_LOGON_TYPE cpu_to_le32(0xC000010B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00494 [PROTO_GATE|] `#define STATUS_NO_GUID_TRANSLATION cpu_to_le32(0xC000010C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00495 [PROTO_GATE|] `#define STATUS_CANNOT_IMPERSONATE cpu_to_le32(0xC000010D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00496 [PROTO_GATE|] `#define STATUS_IMAGE_ALREADY_LOADED cpu_to_le32(0xC000010E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00497 [PROTO_GATE|] `#define STATUS_ABIOS_NOT_PRESENT cpu_to_le32(0xC000010F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00498 [PROTO_GATE|] `#define STATUS_ABIOS_LID_NOT_EXIST cpu_to_le32(0xC0000110)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00499 [PROTO_GATE|] `#define STATUS_ABIOS_LID_ALREADY_OWNED cpu_to_le32(0xC0000111)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00500 [PROTO_GATE|] `#define STATUS_ABIOS_NOT_LID_OWNER cpu_to_le32(0xC0000112)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00501 [PROTO_GATE|] `#define STATUS_ABIOS_INVALID_COMMAND cpu_to_le32(0xC0000113)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00502 [PROTO_GATE|] `#define STATUS_ABIOS_INVALID_LID cpu_to_le32(0xC0000114)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00503 [PROTO_GATE|] `#define STATUS_ABIOS_SELECTOR_NOT_AVAILABLE cpu_to_le32(0xC0000115)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00504 [PROTO_GATE|] `#define STATUS_ABIOS_INVALID_SELECTOR cpu_to_le32(0xC0000116)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00505 [PROTO_GATE|] `#define STATUS_NO_LDT cpu_to_le32(0xC0000117)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00506 [PROTO_GATE|] `#define STATUS_INVALID_LDT_SIZE cpu_to_le32(0xC0000118)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00507 [PROTO_GATE|] `#define STATUS_INVALID_LDT_OFFSET cpu_to_le32(0xC0000119)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00508 [PROTO_GATE|] `#define STATUS_INVALID_LDT_DESCRIPTOR cpu_to_le32(0xC000011A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00509 [PROTO_GATE|] `#define STATUS_INVALID_IMAGE_NE_FORMAT cpu_to_le32(0xC000011B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00510 [PROTO_GATE|] `#define STATUS_RXACT_INVALID_STATE cpu_to_le32(0xC000011C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00511 [PROTO_GATE|] `#define STATUS_RXACT_COMMIT_FAILURE cpu_to_le32(0xC000011D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00512 [PROTO_GATE|] `#define STATUS_MAPPED_FILE_SIZE_ZERO cpu_to_le32(0xC000011E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00513 [PROTO_GATE|] `#define STATUS_TOO_MANY_OPENED_FILES cpu_to_le32(0xC000011F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00514 [PROTO_GATE|] `#define STATUS_CANCELLED cpu_to_le32(0xC0000120)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00515 [PROTO_GATE|] `#define STATUS_CANNOT_DELETE cpu_to_le32(0xC0000121)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00516 [PROTO_GATE|] `#define STATUS_INVALID_COMPUTER_NAME cpu_to_le32(0xC0000122)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00517 [PROTO_GATE|] `#define STATUS_FILE_DELETED cpu_to_le32(0xC0000123)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00518 [PROTO_GATE|] `#define STATUS_SPECIAL_ACCOUNT cpu_to_le32(0xC0000124)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00519 [PROTO_GATE|] `#define STATUS_SPECIAL_GROUP cpu_to_le32(0xC0000125)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00520 [PROTO_GATE|] `#define STATUS_SPECIAL_USER cpu_to_le32(0xC0000126)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00521 [PROTO_GATE|] `#define STATUS_MEMBERS_PRIMARY_GROUP cpu_to_le32(0xC0000127)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00522 [PROTO_GATE|] `#define STATUS_FILE_CLOSED cpu_to_le32(0xC0000128)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00523 [PROTO_GATE|] `#define STATUS_TOO_MANY_THREADS cpu_to_le32(0xC0000129)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00524 [PROTO_GATE|] `#define STATUS_THREAD_NOT_IN_PROCESS cpu_to_le32(0xC000012A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00525 [PROTO_GATE|] `#define STATUS_TOKEN_ALREADY_IN_USE cpu_to_le32(0xC000012B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00526 [PROTO_GATE|] `#define STATUS_PAGEFILE_QUOTA_EXCEEDED cpu_to_le32(0xC000012C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00527 [PROTO_GATE|] `#define STATUS_COMMITMENT_LIMIT cpu_to_le32(0xC000012D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00528 [PROTO_GATE|] `#define STATUS_INVALID_IMAGE_LE_FORMAT cpu_to_le32(0xC000012E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00529 [PROTO_GATE|] `#define STATUS_INVALID_IMAGE_NOT_MZ cpu_to_le32(0xC000012F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00530 [PROTO_GATE|] `#define STATUS_INVALID_IMAGE_PROTECT cpu_to_le32(0xC0000130)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00531 [PROTO_GATE|] `#define STATUS_INVALID_IMAGE_WIN_16 cpu_to_le32(0xC0000131)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00532 [PROTO_GATE|] `#define STATUS_LOGON_SERVER_CONFLICT cpu_to_le32(0xC0000132)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00533 [PROTO_GATE|] `#define STATUS_TIME_DIFFERENCE_AT_DC cpu_to_le32(0xC0000133)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00534 [PROTO_GATE|] `#define STATUS_SYNCHRONIZATION_REQUIRED cpu_to_le32(0xC0000134)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00535 [PROTO_GATE|] `#define STATUS_DLL_NOT_FOUND cpu_to_le32(0xC0000135)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00536 [PROTO_GATE|] `#define STATUS_OPEN_FAILED cpu_to_le32(0xC0000136)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00537 [PROTO_GATE|] `#define STATUS_IO_PRIVILEGE_FAILED cpu_to_le32(0xC0000137)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00538 [PROTO_GATE|] `#define STATUS_ORDINAL_NOT_FOUND cpu_to_le32(0xC0000138)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00539 [PROTO_GATE|] `#define STATUS_ENTRYPOINT_NOT_FOUND cpu_to_le32(0xC0000139)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00540 [PROTO_GATE|] `#define STATUS_CONTROL_C_EXIT cpu_to_le32(0xC000013A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00541 [PROTO_GATE|] `#define STATUS_LOCAL_DISCONNECT cpu_to_le32(0xC000013B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00542 [PROTO_GATE|] `#define STATUS_REMOTE_DISCONNECT cpu_to_le32(0xC000013C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00543 [PROTO_GATE|] `#define STATUS_REMOTE_RESOURCES cpu_to_le32(0xC000013D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00544 [PROTO_GATE|] `#define STATUS_LINK_FAILED cpu_to_le32(0xC000013E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00545 [PROTO_GATE|] `#define STATUS_LINK_TIMEOUT cpu_to_le32(0xC000013F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00546 [PROTO_GATE|] `#define STATUS_INVALID_CONNECTION cpu_to_le32(0xC0000140)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00547 [PROTO_GATE|] `#define STATUS_INVALID_ADDRESS cpu_to_le32(0xC0000141)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00548 [PROTO_GATE|] `#define STATUS_DLL_INIT_FAILED cpu_to_le32(0xC0000142)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00549 [PROTO_GATE|] `#define STATUS_MISSING_SYSTEMFILE cpu_to_le32(0xC0000143)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00550 [PROTO_GATE|] `#define STATUS_UNHANDLED_EXCEPTION cpu_to_le32(0xC0000144)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00551 [PROTO_GATE|] `#define STATUS_APP_INIT_FAILURE cpu_to_le32(0xC0000145)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00552 [PROTO_GATE|] `#define STATUS_PAGEFILE_CREATE_FAILED cpu_to_le32(0xC0000146)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00553 [PROTO_GATE|] `#define STATUS_NO_PAGEFILE cpu_to_le32(0xC0000147)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00554 [PROTO_GATE|] `#define STATUS_INVALID_LEVEL cpu_to_le32(0xC0000148)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00555 [PROTO_GATE|] `#define STATUS_WRONG_PASSWORD_CORE cpu_to_le32(0xC0000149)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00556 [PROTO_GATE|] `#define STATUS_ILLEGAL_FLOAT_CONTEXT cpu_to_le32(0xC000014A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00557 [PROTO_GATE|] `#define STATUS_PIPE_BROKEN cpu_to_le32(0xC000014B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00558 [PROTO_GATE|] `#define STATUS_REGISTRY_CORRUPT cpu_to_le32(0xC000014C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00559 [PROTO_GATE|] `#define STATUS_REGISTRY_IO_FAILED cpu_to_le32(0xC000014D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00560 [PROTO_GATE|] `#define STATUS_NO_EVENT_PAIR cpu_to_le32(0xC000014E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00561 [PROTO_GATE|] `#define STATUS_UNRECOGNIZED_VOLUME cpu_to_le32(0xC000014F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00562 [PROTO_GATE|] `#define STATUS_SERIAL_NO_DEVICE_INITED cpu_to_le32(0xC0000150)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00563 [PROTO_GATE|] `#define STATUS_NO_SUCH_ALIAS cpu_to_le32(0xC0000151)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00564 [PROTO_GATE|] `#define STATUS_MEMBER_NOT_IN_ALIAS cpu_to_le32(0xC0000152)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00565 [PROTO_GATE|] `#define STATUS_MEMBER_IN_ALIAS cpu_to_le32(0xC0000153)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00566 [PROTO_GATE|] `#define STATUS_ALIAS_EXISTS cpu_to_le32(0xC0000154)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00567 [PROTO_GATE|] `#define STATUS_LOGON_NOT_GRANTED cpu_to_le32(0xC0000155)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00568 [PROTO_GATE|] `#define STATUS_TOO_MANY_SECRETS cpu_to_le32(0xC0000156)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00569 [PROTO_GATE|] `#define STATUS_SECRET_TOO_LONG cpu_to_le32(0xC0000157)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00570 [PROTO_GATE|] `#define STATUS_INTERNAL_DB_ERROR cpu_to_le32(0xC0000158)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00571 [PROTO_GATE|] `#define STATUS_FULLSCREEN_MODE cpu_to_le32(0xC0000159)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00572 [PROTO_GATE|] `#define STATUS_TOO_MANY_CONTEXT_IDS cpu_to_le32(0xC000015A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00573 [PROTO_GATE|] `#define STATUS_LOGON_TYPE_NOT_GRANTED cpu_to_le32(0xC000015B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00574 [PROTO_GATE|] `#define STATUS_NOT_REGISTRY_FILE cpu_to_le32(0xC000015C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00575 [PROTO_GATE|] `#define STATUS_NT_CROSS_ENCRYPTION_REQUIRED cpu_to_le32(0xC000015D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00576 [PROTO_GATE|] `#define STATUS_DOMAIN_CTRLR_CONFIG_ERROR cpu_to_le32(0xC000015E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00577 [PROTO_GATE|] `#define STATUS_FT_MISSING_MEMBER cpu_to_le32(0xC000015F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00578 [PROTO_GATE|] `#define STATUS_ILL_FORMED_SERVICE_ENTRY cpu_to_le32(0xC0000160)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00579 [PROTO_GATE|] `#define STATUS_ILLEGAL_CHARACTER cpu_to_le32(0xC0000161)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00580 [PROTO_GATE|] `#define STATUS_UNMAPPABLE_CHARACTER cpu_to_le32(0xC0000162)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00581 [PROTO_GATE|] `#define STATUS_UNDEFINED_CHARACTER cpu_to_le32(0xC0000163)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00582 [PROTO_GATE|] `#define STATUS_FLOPPY_VOLUME cpu_to_le32(0xC0000164)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00583 [PROTO_GATE|] `#define STATUS_FLOPPY_ID_MARK_NOT_FOUND cpu_to_le32(0xC0000165)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00584 [PROTO_GATE|] `#define STATUS_FLOPPY_WRONG_CYLINDER cpu_to_le32(0xC0000166)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00585 [PROTO_GATE|] `#define STATUS_FLOPPY_UNKNOWN_ERROR cpu_to_le32(0xC0000167)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00586 [PROTO_GATE|] `#define STATUS_FLOPPY_BAD_REGISTERS cpu_to_le32(0xC0000168)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00587 [PROTO_GATE|] `#define STATUS_DISK_RECALIBRATE_FAILED cpu_to_le32(0xC0000169)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00588 [PROTO_GATE|] `#define STATUS_DISK_OPERATION_FAILED cpu_to_le32(0xC000016A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00589 [PROTO_GATE|] `#define STATUS_DISK_RESET_FAILED cpu_to_le32(0xC000016B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00590 [PROTO_GATE|] `#define STATUS_SHARED_IRQ_BUSY cpu_to_le32(0xC000016C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00591 [PROTO_GATE|] `#define STATUS_FT_ORPHANING cpu_to_le32(0xC000016D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00592 [PROTO_GATE|] `#define STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT cpu_to_le32(0xC000016E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00593 [PROTO_GATE|] `#define STATUS_PARTITION_FAILURE cpu_to_le32(0xC0000172)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00594 [PROTO_GATE|] `#define STATUS_INVALID_BLOCK_LENGTH cpu_to_le32(0xC0000173)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00595 [PROTO_GATE|] `#define STATUS_DEVICE_NOT_PARTITIONED cpu_to_le32(0xC0000174)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00596 [PROTO_GATE|] `#define STATUS_UNABLE_TO_LOCK_MEDIA cpu_to_le32(0xC0000175)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00597 [PROTO_GATE|] `#define STATUS_UNABLE_TO_UNLOAD_MEDIA cpu_to_le32(0xC0000176)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00598 [PROTO_GATE|] `#define STATUS_EOM_OVERFLOW cpu_to_le32(0xC0000177)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00599 [PROTO_GATE|] `#define STATUS_NO_MEDIA cpu_to_le32(0xC0000178)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00600 [PROTO_GATE|] `#define STATUS_NO_SUCH_MEMBER cpu_to_le32(0xC000017A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00601 [PROTO_GATE|] `#define STATUS_INVALID_MEMBER cpu_to_le32(0xC000017B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00602 [PROTO_GATE|] `#define STATUS_KEY_DELETED cpu_to_le32(0xC000017C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00603 [PROTO_GATE|] `#define STATUS_NO_LOG_SPACE cpu_to_le32(0xC000017D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00604 [PROTO_GATE|] `#define STATUS_TOO_MANY_SIDS cpu_to_le32(0xC000017E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00605 [PROTO_GATE|] `#define STATUS_LM_CROSS_ENCRYPTION_REQUIRED cpu_to_le32(0xC000017F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00606 [PROTO_GATE|] `#define STATUS_KEY_HAS_CHILDREN cpu_to_le32(0xC0000180)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00607 [PROTO_GATE|] `#define STATUS_CHILD_MUST_BE_VOLATILE cpu_to_le32(0xC0000181)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00608 [PROTO_GATE|] `#define STATUS_DEVICE_CONFIGURATION_ERROR cpu_to_le32(0xC0000182)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00609 [PROTO_GATE|] `#define STATUS_DRIVER_INTERNAL_ERROR cpu_to_le32(0xC0000183)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00610 [PROTO_GATE|] `#define STATUS_INVALID_DEVICE_STATE cpu_to_le32(0xC0000184)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00611 [PROTO_GATE|] `#define STATUS_IO_DEVICE_ERROR cpu_to_le32(0xC0000185)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00612 [PROTO_GATE|] `#define STATUS_DEVICE_PROTOCOL_ERROR cpu_to_le32(0xC0000186)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00613 [PROTO_GATE|] `#define STATUS_BACKUP_CONTROLLER cpu_to_le32(0xC0000187)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00614 [PROTO_GATE|] `#define STATUS_LOG_FILE_FULL cpu_to_le32(0xC0000188)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00615 [PROTO_GATE|] `#define STATUS_TOO_LATE cpu_to_le32(0xC0000189)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00616 [PROTO_GATE|] `#define STATUS_NO_TRUST_LSA_SECRET cpu_to_le32(0xC000018A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00617 [PROTO_GATE|] `#define STATUS_NO_TRUST_SAM_ACCOUNT cpu_to_le32(0xC000018B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00618 [PROTO_GATE|] `#define STATUS_TRUSTED_DOMAIN_FAILURE cpu_to_le32(0xC000018C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00619 [PROTO_GATE|] `#define STATUS_TRUSTED_RELATIONSHIP_FAILURE cpu_to_le32(0xC000018D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00620 [PROTO_GATE|] `#define STATUS_EVENTLOG_FILE_CORRUPT cpu_to_le32(0xC000018E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00621 [PROTO_GATE|] `#define STATUS_EVENTLOG_CANT_START cpu_to_le32(0xC000018F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00622 [PROTO_GATE|] `#define STATUS_TRUST_FAILURE cpu_to_le32(0xC0000190)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00623 [PROTO_GATE|] `#define STATUS_MUTANT_LIMIT_EXCEEDED cpu_to_le32(0xC0000191)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00624 [PROTO_GATE|] `#define STATUS_NETLOGON_NOT_STARTED cpu_to_le32(0xC0000192)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00625 [PROTO_GATE|] `#define STATUS_ACCOUNT_EXPIRED cpu_to_le32(0xC0000193)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00626 [PROTO_GATE|] `#define STATUS_POSSIBLE_DEADLOCK cpu_to_le32(0xC0000194)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00627 [PROTO_GATE|] `#define STATUS_NETWORK_CREDENTIAL_CONFLICT cpu_to_le32(0xC0000195)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00628 [PROTO_GATE|] `#define STATUS_REMOTE_SESSION_LIMIT cpu_to_le32(0xC0000196)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00629 [PROTO_GATE|] `#define STATUS_EVENTLOG_FILE_CHANGED cpu_to_le32(0xC0000197)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00630 [PROTO_GATE|] `#define STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT cpu_to_le32(0xC0000198)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00631 [PROTO_GATE|] `#define STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT cpu_to_le32(0xC0000199)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00632 [PROTO_GATE|] `#define STATUS_NOLOGON_SERVER_TRUST_ACCOUNT cpu_to_le32(0xC000019A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00633 [PROTO_GATE|] `#define STATUS_DOMAIN_TRUST_INCONSISTENT cpu_to_le32(0xC000019B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00634 [PROTO_GATE|] `#define STATUS_FS_DRIVER_REQUIRED cpu_to_le32(0xC000019C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00635 [PROTO_GATE|] `#define STATUS_IMAGE_ALREADY_LOADED_AS_DLL cpu_to_le32(0xC000019D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00636 [PROTO_GATE|] `#define STATUS_NETWORK_OPEN_RESTRICTION cpu_to_le32(0xC0000201)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00637 [PROTO_GATE|] `#define STATUS_NO_USER_SESSION_KEY cpu_to_le32(0xC0000202)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00638 [PROTO_GATE|] `#define STATUS_USER_SESSION_DELETED cpu_to_le32(0xC0000203)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00639 [PROTO_GATE|] `#define STATUS_RESOURCE_LANG_NOT_FOUND cpu_to_le32(0xC0000204)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00640 [PROTO_GATE|] `#define STATUS_INSUFF_SERVER_RESOURCES cpu_to_le32(0xC0000205)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00641 [PROTO_GATE|] `#define STATUS_INVALID_BUFFER_SIZE cpu_to_le32(0xC0000206)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00642 [PROTO_GATE|] `#define STATUS_INVALID_ADDRESS_COMPONENT cpu_to_le32(0xC0000207)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00643 [PROTO_GATE|] `#define STATUS_INVALID_ADDRESS_WILDCARD cpu_to_le32(0xC0000208)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00644 [PROTO_GATE|] `#define STATUS_TOO_MANY_ADDRESSES cpu_to_le32(0xC0000209)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00645 [PROTO_GATE|] `#define STATUS_ADDRESS_ALREADY_EXISTS cpu_to_le32(0xC000020A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00646 [PROTO_GATE|] `#define STATUS_ADDRESS_CLOSED cpu_to_le32(0xC000020B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00647 [PROTO_GATE|] `#define STATUS_CONNECTION_DISCONNECTED cpu_to_le32(0xC000020C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00648 [PROTO_GATE|] `#define STATUS_CONNECTION_RESET cpu_to_le32(0xC000020D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00649 [PROTO_GATE|] `#define STATUS_TOO_MANY_NODES cpu_to_le32(0xC000020E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00650 [PROTO_GATE|] `#define STATUS_TRANSACTION_ABORTED cpu_to_le32(0xC000020F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00651 [PROTO_GATE|] `#define STATUS_TRANSACTION_TIMED_OUT cpu_to_le32(0xC0000210)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00652 [PROTO_GATE|] `#define STATUS_TRANSACTION_NO_RELEASE cpu_to_le32(0xC0000211)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00653 [PROTO_GATE|] `#define STATUS_TRANSACTION_NO_MATCH cpu_to_le32(0xC0000212)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00654 [PROTO_GATE|] `#define STATUS_TRANSACTION_RESPONDED cpu_to_le32(0xC0000213)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00655 [PROTO_GATE|] `#define STATUS_TRANSACTION_INVALID_ID cpu_to_le32(0xC0000214)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00656 [PROTO_GATE|] `#define STATUS_TRANSACTION_INVALID_TYPE cpu_to_le32(0xC0000215)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00657 [PROTO_GATE|] `#define STATUS_NOT_SERVER_SESSION cpu_to_le32(0xC0000216)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00658 [PROTO_GATE|] `#define STATUS_NOT_CLIENT_SESSION cpu_to_le32(0xC0000217)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00659 [PROTO_GATE|] `#define STATUS_CANNOT_LOAD_REGISTRY_FILE cpu_to_le32(0xC0000218)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00660 [PROTO_GATE|] `#define STATUS_DEBUG_ATTACH_FAILED cpu_to_le32(0xC0000219)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00661 [PROTO_GATE|] `#define STATUS_SYSTEM_PROCESS_TERMINATED cpu_to_le32(0xC000021A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00662 [PROTO_GATE|] `#define STATUS_DATA_NOT_ACCEPTED cpu_to_le32(0xC000021B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00663 [PROTO_GATE|] `#define STATUS_NO_BROWSER_SERVERS_FOUND cpu_to_le32(0xC000021C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00664 [PROTO_GATE|] `#define STATUS_VDM_HARD_ERROR cpu_to_le32(0xC000021D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00665 [PROTO_GATE|] `#define STATUS_DRIVER_CANCEL_TIMEOUT cpu_to_le32(0xC000021E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00666 [PROTO_GATE|] `#define STATUS_REPLY_MESSAGE_MISMATCH cpu_to_le32(0xC000021F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00667 [PROTO_GATE|] `#define STATUS_MAPPED_ALIGNMENT cpu_to_le32(0xC0000220)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00668 [PROTO_GATE|] `#define STATUS_IMAGE_CHECKSUM_MISMATCH cpu_to_le32(0xC0000221)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00669 [PROTO_GATE|] `#define STATUS_LOST_WRITEBEHIND_DATA cpu_to_le32(0xC0000222)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00670 [PROTO_GATE|] `#define STATUS_CLIENT_SERVER_PARAMETERS_INVALID cpu_to_le32(0xC0000223)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00671 [PROTO_GATE|] `#define STATUS_PASSWORD_MUST_CHANGE cpu_to_le32(0xC0000224)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00672 [PROTO_GATE|] `#define STATUS_NOT_FOUND cpu_to_le32(0xC0000225)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00673 [PROTO_GATE|] `#define STATUS_NOT_TINY_STREAM cpu_to_le32(0xC0000226)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00674 [PROTO_GATE|] `#define STATUS_RECOVERY_FAILURE cpu_to_le32(0xC0000227)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00675 [PROTO_GATE|] `#define STATUS_STACK_OVERFLOW_READ cpu_to_le32(0xC0000228)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00676 [PROTO_GATE|] `#define STATUS_FAIL_CHECK cpu_to_le32(0xC0000229)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00677 [PROTO_GATE|] `#define STATUS_DUPLICATE_OBJECTID cpu_to_le32(0xC000022A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00678 [PROTO_GATE|] `#define STATUS_OBJECTID_EXISTS cpu_to_le32(0xC000022B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00679 [PROTO_GATE|] `#define STATUS_CONVERT_TO_LARGE cpu_to_le32(0xC000022C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00680 [PROTO_GATE|] `#define STATUS_RETRY cpu_to_le32(0xC000022D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00681 [PROTO_GATE|] `#define STATUS_FOUND_OUT_OF_SCOPE cpu_to_le32(0xC000022E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00682 [PROTO_GATE|] `#define STATUS_ALLOCATE_BUCKET cpu_to_le32(0xC000022F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00683 [PROTO_GATE|] `#define STATUS_PROPSET_NOT_FOUND cpu_to_le32(0xC0000230)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00684 [PROTO_GATE|] `#define STATUS_MARSHALL_OVERFLOW cpu_to_le32(0xC0000231)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00685 [PROTO_GATE|] `#define STATUS_INVALID_VARIANT cpu_to_le32(0xC0000232)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00686 [PROTO_GATE|] `#define STATUS_DOMAIN_CONTROLLER_NOT_FOUND cpu_to_le32(0xC0000233)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00687 [PROTO_GATE|] `#define STATUS_ACCOUNT_LOCKED_OUT cpu_to_le32(0xC0000234)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00688 [PROTO_GATE|] `#define STATUS_HANDLE_NOT_CLOSABLE cpu_to_le32(0xC0000235)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00689 [PROTO_GATE|] `#define STATUS_CONNECTION_REFUSED cpu_to_le32(0xC0000236)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00690 [PROTO_GATE|] `#define STATUS_GRACEFUL_DISCONNECT cpu_to_le32(0xC0000237)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00691 [PROTO_GATE|] `#define STATUS_ADDRESS_ALREADY_ASSOCIATED cpu_to_le32(0xC0000238)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00692 [PROTO_GATE|] `#define STATUS_ADDRESS_NOT_ASSOCIATED cpu_to_le32(0xC0000239)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00693 [PROTO_GATE|] `#define STATUS_CONNECTION_INVALID cpu_to_le32(0xC000023A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00694 [PROTO_GATE|] `#define STATUS_CONNECTION_ACTIVE cpu_to_le32(0xC000023B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00695 [PROTO_GATE|] `#define STATUS_NETWORK_UNREACHABLE cpu_to_le32(0xC000023C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00696 [PROTO_GATE|] `#define STATUS_HOST_UNREACHABLE cpu_to_le32(0xC000023D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00697 [PROTO_GATE|] `#define STATUS_PROTOCOL_UNREACHABLE cpu_to_le32(0xC000023E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00698 [PROTO_GATE|] `#define STATUS_PORT_UNREACHABLE cpu_to_le32(0xC000023F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00699 [PROTO_GATE|] `#define STATUS_REQUEST_ABORTED cpu_to_le32(0xC0000240)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00700 [PROTO_GATE|] `#define STATUS_CONNECTION_ABORTED cpu_to_le32(0xC0000241)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00701 [PROTO_GATE|] `#define STATUS_BAD_COMPRESSION_BUFFER cpu_to_le32(0xC0000242)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00702 [PROTO_GATE|] `#define STATUS_USER_MAPPED_FILE cpu_to_le32(0xC0000243)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00703 [PROTO_GATE|] `#define STATUS_AUDIT_FAILED cpu_to_le32(0xC0000244)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00704 [PROTO_GATE|] `#define STATUS_TIMER_RESOLUTION_NOT_SET cpu_to_le32(0xC0000245)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00705 [PROTO_GATE|] `#define STATUS_CONNECTION_COUNT_LIMIT cpu_to_le32(0xC0000246)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00706 [PROTO_GATE|] `#define STATUS_LOGIN_TIME_RESTRICTION cpu_to_le32(0xC0000247)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00707 [PROTO_GATE|] `#define STATUS_LOGIN_WKSTA_RESTRICTION cpu_to_le32(0xC0000248)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00708 [PROTO_GATE|] `#define STATUS_IMAGE_MP_UP_MISMATCH cpu_to_le32(0xC0000249)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00709 [PROTO_GATE|] `#define STATUS_INSUFFICIENT_LOGON_INFO cpu_to_le32(0xC0000250)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00710 [PROTO_GATE|] `#define STATUS_BAD_DLL_ENTRYPOINT cpu_to_le32(0xC0000251)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00711 [PROTO_GATE|] `#define STATUS_BAD_SERVICE_ENTRYPOINT cpu_to_le32(0xC0000252)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00712 [PROTO_GATE|] `#define STATUS_LPC_REPLY_LOST cpu_to_le32(0xC0000253)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00713 [PROTO_GATE|] `#define STATUS_IP_ADDRESS_CONFLICT1 cpu_to_le32(0xC0000254)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00714 [PROTO_GATE|] `#define STATUS_IP_ADDRESS_CONFLICT2 cpu_to_le32(0xC0000255)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00715 [PROTO_GATE|] `#define STATUS_REGISTRY_QUOTA_LIMIT cpu_to_le32(0xC0000256)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00716 [PROTO_GATE|] `#define STATUS_PATH_NOT_COVERED cpu_to_le32(0xC0000257)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00717 [PROTO_GATE|] `#define STATUS_NO_CALLBACK_ACTIVE cpu_to_le32(0xC0000258)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00718 [PROTO_GATE|] `#define STATUS_LICENSE_QUOTA_EXCEEDED cpu_to_le32(0xC0000259)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00719 [PROTO_GATE|] `#define STATUS_PWD_TOO_SHORT cpu_to_le32(0xC000025A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00720 [PROTO_GATE|] `#define STATUS_PWD_TOO_RECENT cpu_to_le32(0xC000025B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00721 [PROTO_GATE|] `#define STATUS_PWD_HISTORY_CONFLICT cpu_to_le32(0xC000025C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00722 [PROTO_GATE|] `#define STATUS_PLUGPLAY_NO_DEVICE cpu_to_le32(0xC000025E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00723 [PROTO_GATE|] `#define STATUS_UNSUPPORTED_COMPRESSION cpu_to_le32(0xC000025F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00724 [PROTO_GATE|] `#define STATUS_INVALID_HW_PROFILE cpu_to_le32(0xC0000260)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00725 [PROTO_GATE|] `#define STATUS_INVALID_PLUGPLAY_DEVICE_PATH cpu_to_le32(0xC0000261)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00726 [PROTO_GATE|] `#define STATUS_DRIVER_ORDINAL_NOT_FOUND cpu_to_le32(0xC0000262)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00727 [PROTO_GATE|] `#define STATUS_DRIVER_ENTRYPOINT_NOT_FOUND cpu_to_le32(0xC0000263)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00728 [PROTO_GATE|] `#define STATUS_RESOURCE_NOT_OWNED cpu_to_le32(0xC0000264)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00729 [PROTO_GATE|] `#define STATUS_TOO_MANY_LINKS cpu_to_le32(0xC0000265)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00730 [PROTO_GATE|] `#define STATUS_QUOTA_LIST_INCONSISTENT cpu_to_le32(0xC0000266)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00731 [PROTO_GATE|] `#define STATUS_FILE_IS_OFFLINE cpu_to_le32(0xC0000267)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00732 [PROTO_GATE|] `#define STATUS_EVALUATION_EXPIRATION cpu_to_le32(0xC0000268)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00733 [PROTO_GATE|] `#define STATUS_ILLEGAL_DLL_RELOCATION cpu_to_le32(0xC0000269)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00734 [PROTO_GATE|] `#define STATUS_LICENSE_VIOLATION cpu_to_le32(0xC000026A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00735 [PROTO_GATE|] `#define STATUS_DLL_INIT_FAILED_LOGOFF cpu_to_le32(0xC000026B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00736 [PROTO_GATE|] `#define STATUS_DRIVER_UNABLE_TO_LOAD cpu_to_le32(0xC000026C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00737 [PROTO_GATE|] `#define STATUS_DFS_UNAVAILABLE cpu_to_le32(0xC000026D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00738 [PROTO_GATE|] `#define STATUS_VOLUME_DISMOUNTED cpu_to_le32(0xC000026E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00739 [PROTO_GATE|] `#define STATUS_WX86_INTERNAL_ERROR cpu_to_le32(0xC000026F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00740 [PROTO_GATE|] `#define STATUS_WX86_FLOAT_STACK_CHECK cpu_to_le32(0xC0000270)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00741 [PROTO_GATE|] `#define STATUS_VALIDATE_CONTINUE cpu_to_le32(0xC0000271)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00742 [PROTO_GATE|] `#define STATUS_NO_MATCH cpu_to_le32(0xC0000272)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00743 [PROTO_GATE|] `#define STATUS_NO_MORE_MATCHES cpu_to_le32(0xC0000273)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00744 [PROTO_GATE|] `#define STATUS_NOT_A_REPARSE_POINT cpu_to_le32(0xC0000275)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00745 [PROTO_GATE|] `#define STATUS_IO_REPARSE_TAG_INVALID cpu_to_le32(0xC0000276)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00746 [PROTO_GATE|] `#define STATUS_IO_REPARSE_TAG_MISMATCH cpu_to_le32(0xC0000277)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00747 [PROTO_GATE|] `#define STATUS_IO_REPARSE_DATA_INVALID cpu_to_le32(0xC0000278)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00748 [PROTO_GATE|] `#define STATUS_IO_REPARSE_TAG_NOT_HANDLED cpu_to_le32(0xC0000279)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00749 [PROTO_GATE|] `#define STATUS_REPARSE_POINT_NOT_RESOLVED cpu_to_le32(0xC0000280)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00750 [PROTO_GATE|] `#define STATUS_DIRECTORY_IS_A_REPARSE_POINT cpu_to_le32(0xC0000281)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00751 [PROTO_GATE|] `#define STATUS_RANGE_LIST_CONFLICT cpu_to_le32(0xC0000282)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00752 [PROTO_GATE|] `#define STATUS_SOURCE_ELEMENT_EMPTY cpu_to_le32(0xC0000283)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00753 [PROTO_GATE|] `#define STATUS_DESTINATION_ELEMENT_FULL cpu_to_le32(0xC0000284)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00754 [PROTO_GATE|] `#define STATUS_ILLEGAL_ELEMENT_ADDRESS cpu_to_le32(0xC0000285)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00755 [PROTO_GATE|] `#define STATUS_MAGAZINE_NOT_PRESENT cpu_to_le32(0xC0000286)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00756 [PROTO_GATE|] `#define STATUS_REINITIALIZATION_NEEDED cpu_to_le32(0xC0000287)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00757 [PROTO_GATE|] `#define STATUS_ENCRYPTION_FAILED cpu_to_le32(0xC000028A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00758 [PROTO_GATE|] `#define STATUS_DECRYPTION_FAILED cpu_to_le32(0xC000028B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00759 [PROTO_GATE|] `#define STATUS_RANGE_NOT_FOUND cpu_to_le32(0xC000028C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00760 [PROTO_GATE|] `#define STATUS_NO_RECOVERY_POLICY cpu_to_le32(0xC000028D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00761 [PROTO_GATE|] `#define STATUS_NO_EFS cpu_to_le32(0xC000028E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00762 [PROTO_GATE|] `#define STATUS_WRONG_EFS cpu_to_le32(0xC000028F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00763 [PROTO_GATE|] `#define STATUS_NO_USER_KEYS cpu_to_le32(0xC0000290)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00764 [PROTO_GATE|] `#define STATUS_FILE_NOT_ENCRYPTED cpu_to_le32(0xC0000291)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00765 [PROTO_GATE|] `#define STATUS_NOT_EXPORT_FORMAT cpu_to_le32(0xC0000292)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00766 [PROTO_GATE|] `#define STATUS_FILE_ENCRYPTED cpu_to_le32(0xC0000293)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00767 [PROTO_GATE|] `#define STATUS_WMI_GUID_NOT_FOUND cpu_to_le32(0xC0000295)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00768 [PROTO_GATE|] `#define STATUS_WMI_INSTANCE_NOT_FOUND cpu_to_le32(0xC0000296)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00769 [PROTO_GATE|] `#define STATUS_WMI_ITEMID_NOT_FOUND cpu_to_le32(0xC0000297)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00770 [PROTO_GATE|] `#define STATUS_WMI_TRY_AGAIN cpu_to_le32(0xC0000298)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00771 [PROTO_GATE|] `#define STATUS_SHARED_POLICY cpu_to_le32(0xC0000299)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00772 [PROTO_GATE|] `#define STATUS_POLICY_OBJECT_NOT_FOUND cpu_to_le32(0xC000029A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00773 [PROTO_GATE|] `#define STATUS_POLICY_ONLY_IN_DS cpu_to_le32(0xC000029B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00774 [PROTO_GATE|] `#define STATUS_VOLUME_NOT_UPGRADED cpu_to_le32(0xC000029C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00775 [PROTO_GATE|] `#define STATUS_REMOTE_STORAGE_NOT_ACTIVE cpu_to_le32(0xC000029D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00776 [PROTO_GATE|] `#define STATUS_REMOTE_STORAGE_MEDIA_ERROR cpu_to_le32(0xC000029E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00777 [PROTO_GATE|] `#define STATUS_NO_TRACKING_SERVICE cpu_to_le32(0xC000029F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00778 [PROTO_GATE|] `#define STATUS_SERVER_SID_MISMATCH cpu_to_le32(0xC00002A0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00779 [PROTO_GATE|] `#define STATUS_DS_NO_ATTRIBUTE_OR_VALUE cpu_to_le32(0xC00002A1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00780 [PROTO_GATE|] `#define STATUS_DS_INVALID_ATTRIBUTE_SYNTAX cpu_to_le32(0xC00002A2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00781 [PROTO_GATE|] `#define STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED cpu_to_le32(0xC00002A3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00782 [PROTO_GATE|] `#define STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS cpu_to_le32(0xC00002A4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00783 [PROTO_GATE|] `#define STATUS_DS_BUSY cpu_to_le32(0xC00002A5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00784 [PROTO_GATE|] `#define STATUS_DS_UNAVAILABLE cpu_to_le32(0xC00002A6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00785 [PROTO_GATE|] `#define STATUS_DS_NO_RIDS_ALLOCATED cpu_to_le32(0xC00002A7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00786 [PROTO_GATE|] `#define STATUS_DS_NO_MORE_RIDS cpu_to_le32(0xC00002A8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00787 [PROTO_GATE|] `#define STATUS_DS_INCORRECT_ROLE_OWNER cpu_to_le32(0xC00002A9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00788 [PROTO_GATE|] `#define STATUS_DS_RIDMGR_INIT_ERROR cpu_to_le32(0xC00002AA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00789 [PROTO_GATE|] `#define STATUS_DS_OBJ_CLASS_VIOLATION cpu_to_le32(0xC00002AB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00790 [PROTO_GATE|] `#define STATUS_DS_CANT_ON_NON_LEAF cpu_to_le32(0xC00002AC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00791 [PROTO_GATE|] `#define STATUS_DS_CANT_ON_RDN cpu_to_le32(0xC00002AD)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00792 [PROTO_GATE|] `#define STATUS_DS_CANT_MOD_OBJ_CLASS cpu_to_le32(0xC00002AE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00793 [PROTO_GATE|] `#define STATUS_DS_CROSS_DOM_MOVE_FAILED cpu_to_le32(0xC00002AF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00794 [PROTO_GATE|] `#define STATUS_DS_GC_NOT_AVAILABLE cpu_to_le32(0xC00002B0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00795 [PROTO_GATE|] `#define STATUS_DIRECTORY_SERVICE_REQUIRED cpu_to_le32(0xC00002B1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00796 [PROTO_GATE|] `#define STATUS_REPARSE_ATTRIBUTE_CONFLICT cpu_to_le32(0xC00002B2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00797 [PROTO_GATE|] `#define STATUS_CANT_ENABLE_DENY_ONLY cpu_to_le32(0xC00002B3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00798 [PROTO_GATE|] `#define STATUS_FLOAT_MULTIPLE_FAULTS cpu_to_le32(0xC00002B4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00799 [PROTO_GATE|] `#define STATUS_FLOAT_MULTIPLE_TRAPS cpu_to_le32(0xC00002B5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00800 [PROTO_GATE|] `#define STATUS_DEVICE_REMOVED cpu_to_le32(0xC00002B6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00801 [PROTO_GATE|] `#define STATUS_JOURNAL_DELETE_IN_PROGRESS cpu_to_le32(0xC00002B7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00802 [PROTO_GATE|] `#define STATUS_JOURNAL_NOT_ACTIVE cpu_to_le32(0xC00002B8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00803 [PROTO_GATE|] `#define STATUS_NOINTERFACE cpu_to_le32(0xC00002B9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00804 [PROTO_GATE|] `#define STATUS_DS_ADMIN_LIMIT_EXCEEDED cpu_to_le32(0xC00002C1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00805 [PROTO_GATE|] `#define STATUS_DRIVER_FAILED_SLEEP cpu_to_le32(0xC00002C2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00806 [PROTO_GATE|] `#define STATUS_MUTUAL_AUTHENTICATION_FAILED cpu_to_le32(0xC00002C3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00807 [PROTO_GATE|] `#define STATUS_CORRUPT_SYSTEM_FILE cpu_to_le32(0xC00002C4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00808 [PROTO_GATE|] `#define STATUS_DATATYPE_MISALIGNMENT_ERROR cpu_to_le32(0xC00002C5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00809 [PROTO_GATE|] `#define STATUS_WMI_READ_ONLY cpu_to_le32(0xC00002C6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00810 [PROTO_GATE|] `#define STATUS_WMI_SET_FAILURE cpu_to_le32(0xC00002C7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00811 [PROTO_GATE|] `#define STATUS_COMMITMENT_MINIMUM cpu_to_le32(0xC00002C8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00812 [PROTO_GATE|] `#define STATUS_REG_NAT_CONSUMPTION cpu_to_le32(0xC00002C9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00813 [PROTO_GATE|] `#define STATUS_TRANSPORT_FULL cpu_to_le32(0xC00002CA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00814 [PROTO_GATE|] `#define STATUS_DS_SAM_INIT_FAILURE cpu_to_le32(0xC00002CB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00815 [PROTO_GATE|] `#define STATUS_ONLY_IF_CONNECTED cpu_to_le32(0xC00002CC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00816 [PROTO_GATE|] `#define STATUS_DS_SENSITIVE_GROUP_VIOLATION cpu_to_le32(0xC00002CD)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00817 [PROTO_GATE|] `#define STATUS_PNP_RESTART_ENUMERATION cpu_to_le32(0xC00002CE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00818 [PROTO_GATE|] `#define STATUS_JOURNAL_ENTRY_DELETED cpu_to_le32(0xC00002CF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00819 [PROTO_GATE|] `#define STATUS_DS_CANT_MOD_PRIMARYGROUPID cpu_to_le32(0xC00002D0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00820 [PROTO_GATE|] `#define STATUS_SYSTEM_IMAGE_BAD_SIGNATURE cpu_to_le32(0xC00002D1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00821 [PROTO_GATE|] `#define STATUS_PNP_REBOOT_REQUIRED cpu_to_le32(0xC00002D2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00822 [PROTO_GATE|] `#define STATUS_POWER_STATE_INVALID cpu_to_le32(0xC00002D3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00823 [PROTO_GATE|] `#define STATUS_DS_INVALID_GROUP_TYPE cpu_to_le32(0xC00002D4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00824 [PROTO_GATE|] `#define STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN cpu_to_le32(0xC00002D5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00825 [PROTO_GATE|] `#define STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN cpu_to_le32(0xC00002D6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00826 [PROTO_GATE|] `#define STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER cpu_to_le32(0xC00002D7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00827 [PROTO_GATE|] `#define STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER cpu_to_le32(0xC00002D8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00828 [PROTO_GATE|] `#define STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER cpu_to_le32(0xC00002D9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00829 [PROTO_GATE|] `#define STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER cpu_to_le32(0xC00002DA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00830 [PROTO_GATE|] `#define STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00831 [NONE] `	cpu_to_le32(0xC00002DB)`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [PROTO_GATE|] `#define STATUS_DS_HAVE_PRIMARY_MEMBERS cpu_to_le32(0xC00002DC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00833 [PROTO_GATE|] `#define STATUS_WMI_NOT_SUPPORTED cpu_to_le32(0xC00002DD)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00834 [PROTO_GATE|] `#define STATUS_INSUFFICIENT_POWER cpu_to_le32(0xC00002DE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00835 [PROTO_GATE|] `#define STATUS_SAM_NEED_BOOTKEY_PASSWORD cpu_to_le32(0xC00002DF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00836 [PROTO_GATE|] `#define STATUS_SAM_NEED_BOOTKEY_FLOPPY cpu_to_le32(0xC00002E0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00837 [PROTO_GATE|] `#define STATUS_DS_CANT_START cpu_to_le32(0xC00002E1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00838 [PROTO_GATE|] `#define STATUS_DS_INIT_FAILURE cpu_to_le32(0xC00002E2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00839 [PROTO_GATE|] `#define STATUS_SAM_INIT_FAILURE cpu_to_le32(0xC00002E3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00840 [PROTO_GATE|] `#define STATUS_DS_GC_REQUIRED cpu_to_le32(0xC00002E4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00841 [PROTO_GATE|] `#define STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY cpu_to_le32(0xC00002E5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00842 [PROTO_GATE|] `#define STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS cpu_to_le32(0xC00002E6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00843 [PROTO_GATE|] `#define STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED cpu_to_le32(0xC00002E7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00844 [PROTO_GATE|] `#define STATUS_MULTIPLE_FAULT_VIOLATION cpu_to_le32(0xC00002E8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00845 [PROTO_GATE|] `#define STATUS_CURRENT_DOMAIN_NOT_ALLOWED cpu_to_le32(0xC00002E9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00846 [PROTO_GATE|] `#define STATUS_CANNOT_MAKE cpu_to_le32(0xC00002EA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00847 [PROTO_GATE|] `#define STATUS_SYSTEM_SHUTDOWN cpu_to_le32(0xC00002EB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00848 [PROTO_GATE|] `#define STATUS_DS_INIT_FAILURE_CONSOLE cpu_to_le32(0xC00002EC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00849 [PROTO_GATE|] `#define STATUS_DS_SAM_INIT_FAILURE_CONSOLE cpu_to_le32(0xC00002ED)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00850 [PROTO_GATE|] `#define STATUS_UNFINISHED_CONTEXT_DELETED cpu_to_le32(0xC00002EE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00851 [PROTO_GATE|] `#define STATUS_NO_TGT_REPLY cpu_to_le32(0xC00002EF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00852 [PROTO_GATE|] `#define STATUS_OBJECTID_NOT_FOUND cpu_to_le32(0xC00002F0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00853 [PROTO_GATE|] `#define STATUS_NO_IP_ADDRESSES cpu_to_le32(0xC00002F1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00854 [PROTO_GATE|] `#define STATUS_WRONG_CREDENTIAL_HANDLE cpu_to_le32(0xC00002F2)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00855 [PROTO_GATE|] `#define STATUS_CRYPTO_SYSTEM_INVALID cpu_to_le32(0xC00002F3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00856 [PROTO_GATE|] `#define STATUS_MAX_REFERRALS_EXCEEDED cpu_to_le32(0xC00002F4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00857 [PROTO_GATE|] `#define STATUS_MUST_BE_KDC cpu_to_le32(0xC00002F5)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00858 [PROTO_GATE|] `#define STATUS_STRONG_CRYPTO_NOT_SUPPORTED cpu_to_le32(0xC00002F6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00859 [PROTO_GATE|] `#define STATUS_TOO_MANY_PRINCIPALS cpu_to_le32(0xC00002F7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00860 [PROTO_GATE|] `#define STATUS_NO_PA_DATA cpu_to_le32(0xC00002F8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00861 [PROTO_GATE|] `#define STATUS_PKINIT_NAME_MISMATCH cpu_to_le32(0xC00002F9)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00862 [PROTO_GATE|] `#define STATUS_SMARTCARD_LOGON_REQUIRED cpu_to_le32(0xC00002FA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00863 [PROTO_GATE|] `#define STATUS_KDC_INVALID_REQUEST cpu_to_le32(0xC00002FB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00864 [PROTO_GATE|] `#define STATUS_KDC_UNABLE_TO_REFER cpu_to_le32(0xC00002FC)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00865 [PROTO_GATE|] `#define STATUS_KDC_UNKNOWN_ETYPE cpu_to_le32(0xC00002FD)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00866 [PROTO_GATE|] `#define STATUS_SHUTDOWN_IN_PROGRESS cpu_to_le32(0xC00002FE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00867 [PROTO_GATE|] `#define STATUS_SERVER_SHUTDOWN_IN_PROGRESS cpu_to_le32(0xC00002FF)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00868 [PROTO_GATE|] `#define STATUS_NOT_SUPPORTED_ON_SBS cpu_to_le32(0xC0000300)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00869 [PROTO_GATE|] `#define STATUS_WMI_GUID_DISCONNECTED cpu_to_le32(0xC0000301)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00870 [PROTO_GATE|] `#define STATUS_WMI_ALREADY_DISABLED cpu_to_le32(0xC0000302)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00871 [PROTO_GATE|] `#define STATUS_WMI_ALREADY_ENABLED cpu_to_le32(0xC0000303)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00872 [PROTO_GATE|] `#define STATUS_MFT_TOO_FRAGMENTED cpu_to_le32(0xC0000304)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00873 [PROTO_GATE|] `#define STATUS_COPY_PROTECTION_FAILURE cpu_to_le32(0xC0000305)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00874 [PROTO_GATE|] `#define STATUS_CSS_AUTHENTICATION_FAILURE cpu_to_le32(0xC0000306)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00875 [PROTO_GATE|] `#define STATUS_CSS_KEY_NOT_PRESENT cpu_to_le32(0xC0000307)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00876 [PROTO_GATE|] `#define STATUS_CSS_KEY_NOT_ESTABLISHED cpu_to_le32(0xC0000308)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00877 [PROTO_GATE|] `#define STATUS_CSS_SCRAMBLED_SECTOR cpu_to_le32(0xC0000309)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00878 [PROTO_GATE|] `#define STATUS_CSS_REGION_MISMATCH cpu_to_le32(0xC000030A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00879 [PROTO_GATE|] `#define STATUS_CSS_RESETS_EXHAUSTED cpu_to_le32(0xC000030B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00880 [PROTO_GATE|] `#define STATUS_PKINIT_FAILURE cpu_to_le32(0xC0000320)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00881 [PROTO_GATE|] `#define STATUS_SMARTCARD_SUBSYSTEM_FAILURE cpu_to_le32(0xC0000321)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00882 [PROTO_GATE|] `#define STATUS_NO_KERB_KEY cpu_to_le32(0xC0000322)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00883 [PROTO_GATE|] `#define STATUS_HOST_DOWN cpu_to_le32(0xC0000350)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00884 [PROTO_GATE|] `#define STATUS_UNSUPPORTED_PREAUTH cpu_to_le32(0xC0000351)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00885 [PROTO_GATE|] `#define STATUS_EFS_ALG_BLOB_TOO_BIG cpu_to_le32(0xC0000352)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00886 [PROTO_GATE|] `#define STATUS_PORT_NOT_SET cpu_to_le32(0xC0000353)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00887 [PROTO_GATE|] `#define STATUS_DEBUGGER_INACTIVE cpu_to_le32(0xC0000354)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00888 [PROTO_GATE|] `#define STATUS_DS_VERSION_CHECK_FAILURE cpu_to_le32(0xC0000355)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00889 [PROTO_GATE|] `#define STATUS_AUDITING_DISABLED cpu_to_le32(0xC0000356)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00890 [PROTO_GATE|] `#define STATUS_PRENT4_MACHINE_ACCOUNT cpu_to_le32(0xC0000357)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00891 [PROTO_GATE|] `#define STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER cpu_to_le32(0xC0000358)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00892 [PROTO_GATE|] `#define STATUS_INVALID_IMAGE_WIN_32 cpu_to_le32(0xC0000359)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00893 [PROTO_GATE|] `#define STATUS_INVALID_IMAGE_WIN_64 cpu_to_le32(0xC000035A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00894 [PROTO_GATE|] `#define STATUS_BAD_BINDINGS cpu_to_le32(0xC000035B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00895 [PROTO_GATE|] `#define STATUS_NETWORK_SESSION_EXPIRED cpu_to_le32(0xC000035C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00896 [PROTO_GATE|] `#define STATUS_APPHELP_BLOCK cpu_to_le32(0xC000035D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00897 [PROTO_GATE|] `#define STATUS_ALL_SIDS_FILTERED cpu_to_le32(0xC000035E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00898 [PROTO_GATE|] `#define STATUS_NOT_SAFE_MODE_DRIVER cpu_to_le32(0xC000035F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00899 [PROTO_GATE|] `#define STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT cpu_to_le32(0xC0000361)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00900 [PROTO_GATE|] `#define STATUS_ACCESS_DISABLED_BY_POLICY_PATH cpu_to_le32(0xC0000362)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00901 [PROTO_GATE|] `#define STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER cpu_to_le32(0xC0000363)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00902 [PROTO_GATE|] `#define STATUS_ACCESS_DISABLED_BY_POLICY_OTHER cpu_to_le32(0xC0000364)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00903 [PROTO_GATE|] `#define STATUS_FAILED_DRIVER_ENTRY cpu_to_le32(0xC0000365)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00904 [PROTO_GATE|] `#define STATUS_DEVICE_ENUMERATION_ERROR cpu_to_le32(0xC0000366)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00905 [PROTO_GATE|] `#define STATUS_MOUNT_POINT_NOT_RESOLVED cpu_to_le32(0xC0000368)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00906 [PROTO_GATE|] `#define STATUS_INVALID_DEVICE_OBJECT_PARAMETER cpu_to_le32(0xC0000369)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00907 [PROTO_GATE|] `#define STATUS_MCA_OCCURRED cpu_to_le32(0xC000036A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00908 [PROTO_GATE|] `#define STATUS_DRIVER_BLOCKED_CRITICAL cpu_to_le32(0xC000036B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00909 [PROTO_GATE|] `#define STATUS_DRIVER_BLOCKED cpu_to_le32(0xC000036C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00910 [PROTO_GATE|] `#define STATUS_DRIVER_DATABASE_ERROR cpu_to_le32(0xC000036D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00911 [PROTO_GATE|] `#define STATUS_SYSTEM_HIVE_TOO_LARGE cpu_to_le32(0xC000036E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00912 [PROTO_GATE|] `#define STATUS_INVALID_IMPORT_OF_NON_DLL cpu_to_le32(0xC000036F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00913 [PROTO_GATE|] `#define STATUS_NO_SECRETS cpu_to_le32(0xC0000371)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00914 [PROTO_GATE|] `#define STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY cpu_to_le32(0xC0000372)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00915 [PROTO_GATE|] `#define STATUS_FAILED_STACK_SWITCH cpu_to_le32(0xC0000373)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00916 [PROTO_GATE|] `#define STATUS_HEAP_CORRUPTION cpu_to_le32(0xC0000374)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00917 [PROTO_GATE|] `#define STATUS_SMARTCARD_WRONG_PIN cpu_to_le32(0xC0000380)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00918 [PROTO_GATE|] `#define STATUS_SMARTCARD_CARD_BLOCKED cpu_to_le32(0xC0000381)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00919 [PROTO_GATE|] `#define STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED cpu_to_le32(0xC0000382)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00920 [PROTO_GATE|] `#define STATUS_SMARTCARD_NO_CARD cpu_to_le32(0xC0000383)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00921 [PROTO_GATE|] `#define STATUS_SMARTCARD_NO_KEY_CONTAINER cpu_to_le32(0xC0000384)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00922 [PROTO_GATE|] `#define STATUS_SMARTCARD_NO_CERTIFICATE cpu_to_le32(0xC0000385)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00923 [PROTO_GATE|] `#define STATUS_SMARTCARD_NO_KEYSET cpu_to_le32(0xC0000386)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00924 [PROTO_GATE|] `#define STATUS_SMARTCARD_IO_ERROR cpu_to_le32(0xC0000387)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00925 [PROTO_GATE|] `#define STATUS_DOWNGRADE_DETECTED cpu_to_le32(0xC0000388)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00926 [PROTO_GATE|] `#define STATUS_SMARTCARD_CERT_REVOKED cpu_to_le32(0xC0000389)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00927 [PROTO_GATE|] `#define STATUS_ISSUING_CA_UNTRUSTED cpu_to_le32(0xC000038A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00928 [PROTO_GATE|] `#define STATUS_REVOCATION_OFFLINE_C cpu_to_le32(0xC000038B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00929 [PROTO_GATE|] `#define STATUS_PKINIT_CLIENT_FAILURE cpu_to_le32(0xC000038C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00930 [PROTO_GATE|] `#define STATUS_SMARTCARD_CERT_EXPIRED cpu_to_le32(0xC000038D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00931 [PROTO_GATE|] `#define STATUS_DRIVER_FAILED_PRIOR_UNLOAD cpu_to_le32(0xC000038E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00932 [PROTO_GATE|] `#define STATUS_SMARTCARD_SILENT_CONTEXT cpu_to_le32(0xC000038F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00933 [PROTO_GATE|] `#define STATUS_PER_USER_TRUST_QUOTA_EXCEEDED cpu_to_le32(0xC0000401)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00934 [PROTO_GATE|] `#define STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED cpu_to_le32(0xC0000402)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00935 [PROTO_GATE|] `#define STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED cpu_to_le32(0xC0000403)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00936 [PROTO_GATE|] `#define STATUS_DS_NAME_NOT_UNIQUE cpu_to_le32(0xC0000404)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00937 [PROTO_GATE|] `#define STATUS_DS_DUPLICATE_ID_FOUND cpu_to_le32(0xC0000405)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00938 [PROTO_GATE|] `#define STATUS_DS_GROUP_CONVERSION_ERROR cpu_to_le32(0xC0000406)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00939 [PROTO_GATE|] `#define STATUS_VOLSNAP_PREPARE_HIBERNATE cpu_to_le32(0xC0000407)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00940 [PROTO_GATE|] `#define STATUS_USER2USER_REQUIRED cpu_to_le32(0xC0000408)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00941 [PROTO_GATE|] `#define STATUS_STACK_BUFFER_OVERRUN cpu_to_le32(0xC0000409)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00942 [PROTO_GATE|] `#define STATUS_NO_S4U_PROT_SUPPORT cpu_to_le32(0xC000040A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00943 [PROTO_GATE|] `#define STATUS_CROSSREALM_DELEGATION_FAILURE cpu_to_le32(0xC000040B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00944 [PROTO_GATE|] `#define STATUS_REVOCATION_OFFLINE_KDC cpu_to_le32(0xC000040C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00945 [PROTO_GATE|] `#define STATUS_ISSUING_CA_UNTRUSTED_KDC cpu_to_le32(0xC000040D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00946 [PROTO_GATE|] `#define STATUS_KDC_CERT_EXPIRED cpu_to_le32(0xC000040E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00947 [PROTO_GATE|] `#define STATUS_KDC_CERT_REVOKED cpu_to_le32(0xC000040F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00948 [PROTO_GATE|] `#define STATUS_PARAMETER_QUOTA_EXCEEDED cpu_to_le32(0xC0000410)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00949 [PROTO_GATE|] `#define STATUS_HIBERNATION_FAILURE cpu_to_le32(0xC0000411)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00950 [PROTO_GATE|] `#define STATUS_DELAY_LOAD_FAILED cpu_to_le32(0xC0000412)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00951 [PROTO_GATE|] `#define STATUS_AUTHENTICATION_FIREWALL_FAILED cpu_to_le32(0xC0000413)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00952 [PROTO_GATE|] `#define STATUS_VDM_DISALLOWED cpu_to_le32(0xC0000414)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00953 [PROTO_GATE|] `#define STATUS_HUNG_DISPLAY_DRIVER_THREAD cpu_to_le32(0xC0000415)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00954 [PROTO_GATE|] `#define STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00955 [NONE] `	cpu_to_le32(0xC0000416)`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [PROTO_GATE|] `#define STATUS_INVALID_CRUNTIME_PARAMETER cpu_to_le32(0xC0000417)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00957 [PROTO_GATE|] `#define STATUS_NTLM_BLOCKED cpu_to_le32(0xC0000418)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00958 [PROTO_GATE|] `#define STATUS_ASSERTION_FAILURE cpu_to_le32(0xC0000420)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00959 [PROTO_GATE|] `#define STATUS_VERIFIER_STOP cpu_to_le32(0xC0000421)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00960 [PROTO_GATE|] `#define STATUS_CALLBACK_POP_STACK cpu_to_le32(0xC0000423)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00961 [PROTO_GATE|] `#define STATUS_INCOMPATIBLE_DRIVER_BLOCKED cpu_to_le32(0xC0000424)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00962 [PROTO_GATE|] `#define STATUS_HIVE_UNLOADED cpu_to_le32(0xC0000425)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00963 [PROTO_GATE|] `#define STATUS_COMPRESSION_DISABLED cpu_to_le32(0xC0000426)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00964 [PROTO_GATE|] `#define STATUS_FILE_SYSTEM_LIMITATION cpu_to_le32(0xC0000427)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00965 [PROTO_GATE|] `#define STATUS_INVALID_IMAGE_HASH cpu_to_le32(0xC0000428)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00966 [PROTO_GATE|] `#define STATUS_NOT_CAPABLE cpu_to_le32(0xC0000429)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00967 [PROTO_GATE|] `#define STATUS_REQUEST_OUT_OF_SEQUENCE cpu_to_le32(0xC000042A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00968 [PROTO_GATE|] `#define STATUS_IMPLEMENTATION_LIMIT cpu_to_le32(0xC000042B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00969 [PROTO_GATE|] `#define STATUS_ELEVATION_REQUIRED cpu_to_le32(0xC000042C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00970 [PROTO_GATE|] `#define STATUS_BEYOND_VDL cpu_to_le32(0xC0000432)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00971 [PROTO_GATE|] `#define STATUS_ENCOUNTERED_WRITE_IN_PROGRESS cpu_to_le32(0xC0000433)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00972 [PROTO_GATE|] `#define STATUS_PTE_CHANGED cpu_to_le32(0xC0000434)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00973 [PROTO_GATE|] `#define STATUS_PURGE_FAILED cpu_to_le32(0xC0000435)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00974 [PROTO_GATE|] `#define STATUS_CRED_REQUIRES_CONFIRMATION cpu_to_le32(0xC0000440)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00975 [PROTO_GATE|] `#define STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE cpu_to_le32(0xC0000441)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00976 [PROTO_GATE|] `#define STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER cpu_to_le32(0xC0000442)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00977 [PROTO_GATE|] `#define STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE cpu_to_le32(0xC0000443)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00978 [PROTO_GATE|] `#define STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE cpu_to_le32(0xC0000444)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00979 [PROTO_GATE|] `#define STATUS_CS_ENCRYPTION_FILE_NOT_CSE cpu_to_le32(0xC0000445)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00980 [PROTO_GATE|] `#define STATUS_INVALID_LABEL cpu_to_le32(0xC0000446)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00981 [PROTO_GATE|] `#define STATUS_DRIVER_PROCESS_TERMINATED cpu_to_le32(0xC0000450)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00982 [PROTO_GATE|] `#define STATUS_AMBIGUOUS_SYSTEM_DEVICE cpu_to_le32(0xC0000451)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00983 [PROTO_GATE|] `#define STATUS_SYSTEM_DEVICE_NOT_FOUND cpu_to_le32(0xC0000452)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00984 [PROTO_GATE|] `#define STATUS_RESTART_BOOT_APPLICATION cpu_to_le32(0xC0000453)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00985 [PROTO_GATE|] `#define STATUS_FILE_NOT_AVAILABLE cpu_to_le32(0xC0000467)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00986 [PROTO_GATE|] `#define STATUS_INVALID_TASK_NAME cpu_to_le32(0xC0000500)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00987 [PROTO_GATE|] `#define STATUS_INVALID_TASK_INDEX cpu_to_le32(0xC0000501)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00988 [PROTO_GATE|] `#define STATUS_THREAD_ALREADY_IN_TASK cpu_to_le32(0xC0000502)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00989 [PROTO_GATE|] `#define STATUS_CALLBACK_BYPASS cpu_to_le32(0xC0000503)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00990 [PROTO_GATE|] `#define STATUS_PORT_CLOSED cpu_to_le32(0xC0000700)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00991 [PROTO_GATE|] `#define STATUS_MESSAGE_LOST cpu_to_le32(0xC0000701)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00992 [PROTO_GATE|] `#define STATUS_INVALID_MESSAGE cpu_to_le32(0xC0000702)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00993 [PROTO_GATE|] `#define STATUS_REQUEST_CANCELED cpu_to_le32(0xC0000703)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00994 [PROTO_GATE|] `#define STATUS_RECURSIVE_DISPATCH cpu_to_le32(0xC0000704)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00995 [PROTO_GATE|] `#define STATUS_LPC_RECEIVE_BUFFER_EXPECTED cpu_to_le32(0xC0000705)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00996 [PROTO_GATE|] `#define STATUS_LPC_INVALID_CONNECTION_USAGE cpu_to_le32(0xC0000706)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00997 [PROTO_GATE|] `#define STATUS_LPC_REQUESTS_NOT_ALLOWED cpu_to_le32(0xC0000707)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00998 [PROTO_GATE|] `#define STATUS_RESOURCE_IN_USE cpu_to_le32(0xC0000708)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00999 [PROTO_GATE|] `#define STATUS_HARDWARE_MEMORY_ERROR cpu_to_le32(0xC0000709)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01000 [PROTO_GATE|] `#define STATUS_THREADPOOL_HANDLE_EXCEPTION cpu_to_le32(0xC000070A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01001 [PROTO_GATE|] `#define STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED cpu_to_le32(0xC000070B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01002 [PROTO_GATE|] `#define STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01003 [NONE] `	cpu_to_le32(0xC000070C)`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [PROTO_GATE|] `#define STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01005 [NONE] `	cpu_to_le32(0xC000070D)`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [PROTO_GATE|] `#define STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01007 [NONE] `	cpu_to_le32(0xC000070E)`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [PROTO_GATE|] `#define STATUS_THREADPOOL_RELEASED_DURING_OPERATION cpu_to_le32(0xC000070F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01009 [PROTO_GATE|] `#define STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING cpu_to_le32(0xC0000710)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01010 [PROTO_GATE|] `#define STATUS_APC_RETURNED_WHILE_IMPERSONATING cpu_to_le32(0xC0000711)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01011 [PROTO_GATE|] `#define STATUS_PROCESS_IS_PROTECTED cpu_to_le32(0xC0000712)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01012 [PROTO_GATE|] `#define STATUS_MCA_EXCEPTION cpu_to_le32(0xC0000713)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01013 [PROTO_GATE|] `#define STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE cpu_to_le32(0xC0000714)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01014 [PROTO_GATE|] `#define STATUS_SYMLINK_CLASS_DISABLED cpu_to_le32(0xC0000715)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01015 [PROTO_GATE|] `#define STATUS_INVALID_IDN_NORMALIZATION cpu_to_le32(0xC0000716)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01016 [PROTO_GATE|] `#define STATUS_NO_UNICODE_TRANSLATION cpu_to_le32(0xC0000717)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01017 [PROTO_GATE|] `#define STATUS_ALREADY_REGISTERED cpu_to_le32(0xC0000718)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01018 [PROTO_GATE|] `#define STATUS_CONTEXT_MISMATCH cpu_to_le32(0xC0000719)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01019 [PROTO_GATE|] `#define STATUS_PORT_ALREADY_HAS_COMPLETION_LIST cpu_to_le32(0xC000071A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01020 [PROTO_GATE|] `#define STATUS_CALLBACK_RETURNED_THREAD_PRIORITY cpu_to_le32(0xC000071B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01021 [PROTO_GATE|] `#define STATUS_INVALID_THREAD cpu_to_le32(0xC000071C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01022 [PROTO_GATE|] `#define STATUS_CALLBACK_RETURNED_TRANSACTION cpu_to_le32(0xC000071D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01023 [PROTO_GATE|] `#define STATUS_CALLBACK_RETURNED_LDR_LOCK cpu_to_le32(0xC000071E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01024 [PROTO_GATE|] `#define STATUS_CALLBACK_RETURNED_LANG cpu_to_le32(0xC000071F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01025 [PROTO_GATE|] `#define STATUS_CALLBACK_RETURNED_PRI_BACK cpu_to_le32(0xC0000720)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01026 [PROTO_GATE|] `#define STATUS_CALLBACK_RETURNED_THREAD_AFFINITY cpu_to_le32(0xC0000721)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01027 [PROTO_GATE|] `#define STATUS_DISK_REPAIR_DISABLED cpu_to_le32(0xC0000800)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01028 [PROTO_GATE|] `#define STATUS_DS_DOMAIN_RENAME_IN_PROGRESS cpu_to_le32(0xC0000801)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01029 [PROTO_GATE|] `#define STATUS_DISK_QUOTA_EXCEEDED cpu_to_le32(0xC0000802)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01030 [PROTO_GATE|] `#define STATUS_CONTENT_BLOCKED cpu_to_le32(0xC0000804)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01031 [PROTO_GATE|] `#define STATUS_BAD_CLUSTERS cpu_to_le32(0xC0000805)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01032 [PROTO_GATE|] `#define STATUS_VOLUME_DIRTY cpu_to_le32(0xC0000806)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01033 [PROTO_GATE|] `#define STATUS_FILE_CHECKED_OUT cpu_to_le32(0xC0000901)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01034 [PROTO_GATE|] `#define STATUS_CHECKOUT_REQUIRED cpu_to_le32(0xC0000902)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01035 [PROTO_GATE|] `#define STATUS_BAD_FILE_TYPE cpu_to_le32(0xC0000903)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01036 [PROTO_GATE|] `#define STATUS_FILE_TOO_LARGE cpu_to_le32(0xC0000904)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01037 [PROTO_GATE|] `#define STATUS_FORMS_AUTH_REQUIRED cpu_to_le32(0xC0000905)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01038 [PROTO_GATE|] `#define STATUS_VIRUS_INFECTED cpu_to_le32(0xC0000906)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01039 [PROTO_GATE|] `#define STATUS_VIRUS_DELETED cpu_to_le32(0xC0000907)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01040 [PROTO_GATE|] `#define STATUS_BAD_MCFG_TABLE cpu_to_le32(0xC0000908)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01041 [PROTO_GATE|] `#define STATUS_WOW_ASSERTION cpu_to_le32(0xC0009898)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01042 [PROTO_GATE|] `#define STATUS_INVALID_SIGNATURE cpu_to_le32(0xC000A000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01043 [PROTO_GATE|] `#define STATUS_HMAC_NOT_SUPPORTED cpu_to_le32(0xC000A001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01044 [PROTO_GATE|] `#define STATUS_IPSEC_QUEUE_OVERFLOW cpu_to_le32(0xC000A010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01045 [PROTO_GATE|] `#define STATUS_ND_QUEUE_OVERFLOW cpu_to_le32(0xC000A011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01046 [PROTO_GATE|] `#define STATUS_HOPLIMIT_EXCEEDED cpu_to_le32(0xC000A012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01047 [PROTO_GATE|] `#define STATUS_PROTOCOL_NOT_SUPPORTED cpu_to_le32(0xC000A013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01048 [PROTO_GATE|] `#define STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01049 [NONE] `	cpu_to_le32(0xC000A080)`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [PROTO_GATE|] `#define STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01051 [NONE] `	cpu_to_le32(0xC000A081)`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [PROTO_GATE|] `#define STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR cpu_to_le32(0xC000A082)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01053 [PROTO_GATE|] `#define STATUS_XML_PARSE_ERROR cpu_to_le32(0xC000A083)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01054 [PROTO_GATE|] `#define STATUS_XMLDSIG_ERROR cpu_to_le32(0xC000A084)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01055 [PROTO_GATE|] `#define STATUS_WRONG_COMPARTMENT cpu_to_le32(0xC000A085)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01056 [PROTO_GATE|] `#define STATUS_AUTHIP_FAILURE cpu_to_le32(0xC000A086)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01057 [PROTO_GATE|] `#define STATUS_HASH_NOT_SUPPORTED cpu_to_le32(0xC000A100)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01058 [PROTO_GATE|] `#define STATUS_HASH_NOT_PRESENT cpu_to_le32(0xC000A101)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01059 [PROTO_GATE|] `#define STATUS_INVALID_TOKEN cpu_to_le32(0xC0000148)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01060 [NONE] `#define DBG_NO_STATE_CHANGE cpu_to_le32(0xC0010001)`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `#define DBG_APP_NOT_IDLE cpu_to_le32(0xC0010002)`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `#define RPC_NT_INVALID_STRING_BINDING cpu_to_le32(0xC0020001)`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `#define RPC_NT_WRONG_KIND_OF_BINDING cpu_to_le32(0xC0020002)`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `#define RPC_NT_INVALID_BINDING cpu_to_le32(0xC0020003)`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `#define RPC_NT_PROTSEQ_NOT_SUPPORTED cpu_to_le32(0xC0020004)`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `#define RPC_NT_INVALID_RPC_PROTSEQ cpu_to_le32(0xC0020005)`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `#define RPC_NT_INVALID_STRING_UUID cpu_to_le32(0xC0020006)`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `#define RPC_NT_INVALID_ENDPOINT_FORMAT cpu_to_le32(0xC0020007)`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `#define RPC_NT_INVALID_NET_ADDR cpu_to_le32(0xC0020008)`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `#define RPC_NT_NO_ENDPOINT_FOUND cpu_to_le32(0xC0020009)`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `#define RPC_NT_INVALID_TIMEOUT cpu_to_le32(0xC002000A)`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `#define RPC_NT_OBJECT_NOT_FOUND cpu_to_le32(0xC002000B)`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `#define RPC_NT_ALREADY_REGISTERED cpu_to_le32(0xC002000C)`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `#define RPC_NT_TYPE_ALREADY_REGISTERED cpu_to_le32(0xC002000D)`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `#define RPC_NT_ALREADY_LISTENING cpu_to_le32(0xC002000E)`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `#define RPC_NT_NO_PROTSEQS_REGISTERED cpu_to_le32(0xC002000F)`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `#define RPC_NT_NOT_LISTENING cpu_to_le32(0xC0020010)`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `#define RPC_NT_UNKNOWN_MGR_TYPE cpu_to_le32(0xC0020011)`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `#define RPC_NT_UNKNOWN_IF cpu_to_le32(0xC0020012)`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `#define RPC_NT_NO_BINDINGS cpu_to_le32(0xC0020013)`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `#define RPC_NT_NO_PROTSEQS cpu_to_le32(0xC0020014)`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `#define RPC_NT_CANT_CREATE_ENDPOINT cpu_to_le32(0xC0020015)`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `#define RPC_NT_OUT_OF_RESOURCES cpu_to_le32(0xC0020016)`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `#define RPC_NT_SERVER_UNAVAILABLE cpu_to_le32(0xC0020017)`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `#define RPC_NT_SERVER_TOO_BUSY cpu_to_le32(0xC0020018)`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `#define RPC_NT_INVALID_NETWORK_OPTIONS cpu_to_le32(0xC0020019)`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `#define RPC_NT_NO_CALL_ACTIVE cpu_to_le32(0xC002001A)`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `#define RPC_NT_CALL_FAILED cpu_to_le32(0xC002001B)`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `#define RPC_NT_CALL_FAILED_DNE cpu_to_le32(0xC002001C)`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `#define RPC_NT_PROTOCOL_ERROR cpu_to_le32(0xC002001D)`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `#define RPC_NT_UNSUPPORTED_TRANS_SYN cpu_to_le32(0xC002001F)`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `#define RPC_NT_UNSUPPORTED_TYPE cpu_to_le32(0xC0020021)`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `#define RPC_NT_INVALID_TAG cpu_to_le32(0xC0020022)`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `#define RPC_NT_INVALID_BOUND cpu_to_le32(0xC0020023)`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `#define RPC_NT_NO_ENTRY_NAME cpu_to_le32(0xC0020024)`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `#define RPC_NT_INVALID_NAME_SYNTAX cpu_to_le32(0xC0020025)`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `#define RPC_NT_UNSUPPORTED_NAME_SYNTAX cpu_to_le32(0xC0020026)`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `#define RPC_NT_UUID_NO_ADDRESS cpu_to_le32(0xC0020028)`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `#define RPC_NT_DUPLICATE_ENDPOINT cpu_to_le32(0xC0020029)`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `#define RPC_NT_UNKNOWN_AUTHN_TYPE cpu_to_le32(0xC002002A)`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `#define RPC_NT_MAX_CALLS_TOO_SMALL cpu_to_le32(0xC002002B)`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `#define RPC_NT_STRING_TOO_LONG cpu_to_le32(0xC002002C)`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `#define RPC_NT_PROTSEQ_NOT_FOUND cpu_to_le32(0xC002002D)`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `#define RPC_NT_PROCNUM_OUT_OF_RANGE cpu_to_le32(0xC002002E)`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `#define RPC_NT_BINDING_HAS_NO_AUTH cpu_to_le32(0xC002002F)`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `#define RPC_NT_UNKNOWN_AUTHN_SERVICE cpu_to_le32(0xC0020030)`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `#define RPC_NT_UNKNOWN_AUTHN_LEVEL cpu_to_le32(0xC0020031)`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `#define RPC_NT_INVALID_AUTH_IDENTITY cpu_to_le32(0xC0020032)`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `#define RPC_NT_UNKNOWN_AUTHZ_SERVICE cpu_to_le32(0xC0020033)`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `#define EPT_NT_INVALID_ENTRY cpu_to_le32(0xC0020034)`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] `#define EPT_NT_CANT_PERFORM_OP cpu_to_le32(0xC0020035)`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `#define EPT_NT_NOT_REGISTERED cpu_to_le32(0xC0020036)`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `#define RPC_NT_NOTHING_TO_EXPORT cpu_to_le32(0xC0020037)`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `#define RPC_NT_INCOMPLETE_NAME cpu_to_le32(0xC0020038)`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `#define RPC_NT_INVALID_VERS_OPTION cpu_to_le32(0xC0020039)`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `#define RPC_NT_NO_MORE_MEMBERS cpu_to_le32(0xC002003A)`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `#define RPC_NT_NOT_ALL_OBJS_UNEXPORTED cpu_to_le32(0xC002003B)`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `#define RPC_NT_INTERFACE_NOT_FOUND cpu_to_le32(0xC002003C)`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `#define RPC_NT_ENTRY_ALREADY_EXISTS cpu_to_le32(0xC002003D)`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `#define RPC_NT_ENTRY_NOT_FOUND cpu_to_le32(0xC002003E)`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `#define RPC_NT_NAME_SERVICE_UNAVAILABLE cpu_to_le32(0xC002003F)`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `#define RPC_NT_INVALID_NAF_ID cpu_to_le32(0xC0020040)`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `#define RPC_NT_CANNOT_SUPPORT cpu_to_le32(0xC0020041)`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `#define RPC_NT_NO_CONTEXT_AVAILABLE cpu_to_le32(0xC0020042)`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `#define RPC_NT_INTERNAL_ERROR cpu_to_le32(0xC0020043)`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `#define RPC_NT_ZERO_DIVIDE cpu_to_le32(0xC0020044)`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `#define RPC_NT_ADDRESS_ERROR cpu_to_le32(0xC0020045)`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `#define RPC_NT_FP_DIV_ZERO cpu_to_le32(0xC0020046)`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `#define RPC_NT_FP_UNDERFLOW cpu_to_le32(0xC0020047)`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `#define RPC_NT_FP_OVERFLOW cpu_to_le32(0xC0020048)`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `#define RPC_NT_CALL_IN_PROGRESS cpu_to_le32(0xC0020049)`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `#define RPC_NT_NO_MORE_BINDINGS cpu_to_le32(0xC002004A)`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `#define RPC_NT_GROUP_MEMBER_NOT_FOUND cpu_to_le32(0xC002004B)`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `#define EPT_NT_CANT_CREATE cpu_to_le32(0xC002004C)`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `#define RPC_NT_INVALID_OBJECT cpu_to_le32(0xC002004D)`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `#define RPC_NT_NO_INTERFACES cpu_to_le32(0xC002004F)`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `#define RPC_NT_CALL_CANCELLED cpu_to_le32(0xC0020050)`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `#define RPC_NT_BINDING_INCOMPLETE cpu_to_le32(0xC0020051)`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `#define RPC_NT_COMM_FAILURE cpu_to_le32(0xC0020052)`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `#define RPC_NT_UNSUPPORTED_AUTHN_LEVEL cpu_to_le32(0xC0020053)`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `#define RPC_NT_NO_PRINC_NAME cpu_to_le32(0xC0020054)`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `#define RPC_NT_NOT_RPC_ERROR cpu_to_le32(0xC0020055)`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `#define RPC_NT_SEC_PKG_ERROR cpu_to_le32(0xC0020057)`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `#define RPC_NT_NOT_CANCELLED cpu_to_le32(0xC0020058)`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `#define RPC_NT_INVALID_ASYNC_HANDLE cpu_to_le32(0xC0020062)`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `#define RPC_NT_INVALID_ASYNC_CALL cpu_to_le32(0xC0020063)`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `#define RPC_NT_PROXY_ACCESS_DENIED cpu_to_le32(0xC0020064)`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `#define RPC_NT_NO_MORE_ENTRIES cpu_to_le32(0xC0030001)`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `#define RPC_NT_SS_CHAR_TRANS_OPEN_FAIL cpu_to_le32(0xC0030002)`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `#define RPC_NT_SS_CHAR_TRANS_SHORT_FILE cpu_to_le32(0xC0030003)`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `#define RPC_NT_SS_IN_NULL_CONTEXT cpu_to_le32(0xC0030004)`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `#define RPC_NT_SS_CONTEXT_MISMATCH cpu_to_le32(0xC0030005)`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `#define RPC_NT_SS_CONTEXT_DAMAGED cpu_to_le32(0xC0030006)`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `#define RPC_NT_SS_HANDLES_MISMATCH cpu_to_le32(0xC0030007)`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `#define RPC_NT_SS_CANNOT_GET_CALL_HANDLE cpu_to_le32(0xC0030008)`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `#define RPC_NT_NULL_REF_POINTER cpu_to_le32(0xC0030009)`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `#define RPC_NT_ENUM_VALUE_OUT_OF_RANGE cpu_to_le32(0xC003000A)`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `#define RPC_NT_BYTE_COUNT_TOO_SMALL cpu_to_le32(0xC003000B)`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `#define RPC_NT_BAD_STUB_DATA cpu_to_le32(0xC003000C)`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `#define RPC_NT_INVALID_ES_ACTION cpu_to_le32(0xC0030059)`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `#define RPC_NT_WRONG_ES_VERSION cpu_to_le32(0xC003005A)`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `#define RPC_NT_WRONG_STUB_VERSION cpu_to_le32(0xC003005B)`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `#define RPC_NT_INVALID_PIPE_OBJECT cpu_to_le32(0xC003005C)`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `#define RPC_NT_INVALID_PIPE_OPERATION cpu_to_le32(0xC003005D)`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `#define RPC_NT_WRONG_PIPE_VERSION cpu_to_le32(0xC003005E)`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `#define RPC_NT_PIPE_CLOSED cpu_to_le32(0xC003005F)`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `#define RPC_NT_PIPE_DISCIPLINE_ERROR cpu_to_le32(0xC0030060)`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `#define RPC_NT_PIPE_EMPTY cpu_to_le32(0xC0030061)`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [PROTO_GATE|] `#define STATUS_PNP_BAD_MPS_TABLE cpu_to_le32(0xC0040035)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01170 [PROTO_GATE|] `#define STATUS_PNP_TRANSLATION_FAILED cpu_to_le32(0xC0040036)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01171 [PROTO_GATE|] `#define STATUS_PNP_IRQ_TRANSLATION_FAILED cpu_to_le32(0xC0040037)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01172 [PROTO_GATE|] `#define STATUS_PNP_INVALID_ID cpu_to_le32(0xC0040038)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01173 [PROTO_GATE|] `#define STATUS_IO_REISSUE_AS_CACHED cpu_to_le32(0xC0040039)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01174 [PROTO_GATE|] `#define STATUS_CTX_WINSTATION_NAME_INVALID cpu_to_le32(0xC00A0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01175 [PROTO_GATE|] `#define STATUS_CTX_INVALID_PD cpu_to_le32(0xC00A0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01176 [PROTO_GATE|] `#define STATUS_CTX_PD_NOT_FOUND cpu_to_le32(0xC00A0003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01177 [PROTO_GATE|] `#define STATUS_CTX_CLOSE_PENDING cpu_to_le32(0xC00A0006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01178 [PROTO_GATE|] `#define STATUS_CTX_NO_OUTBUF cpu_to_le32(0xC00A0007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01179 [PROTO_GATE|] `#define STATUS_CTX_MODEM_INF_NOT_FOUND cpu_to_le32(0xC00A0008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01180 [PROTO_GATE|] `#define STATUS_CTX_INVALID_MODEMNAME cpu_to_le32(0xC00A0009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01181 [PROTO_GATE|] `#define STATUS_CTX_RESPONSE_ERROR cpu_to_le32(0xC00A000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01182 [PROTO_GATE|] `#define STATUS_CTX_MODEM_RESPONSE_TIMEOUT cpu_to_le32(0xC00A000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01183 [PROTO_GATE|] `#define STATUS_CTX_MODEM_RESPONSE_NO_CARRIER cpu_to_le32(0xC00A000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01184 [PROTO_GATE|] `#define STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE cpu_to_le32(0xC00A000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01185 [PROTO_GATE|] `#define STATUS_CTX_MODEM_RESPONSE_BUSY cpu_to_le32(0xC00A000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01186 [PROTO_GATE|] `#define STATUS_CTX_MODEM_RESPONSE_VOICE cpu_to_le32(0xC00A000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01187 [PROTO_GATE|] `#define STATUS_CTX_TD_ERROR cpu_to_le32(0xC00A0010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01188 [PROTO_GATE|] `#define STATUS_CTX_LICENSE_CLIENT_INVALID cpu_to_le32(0xC00A0012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01189 [PROTO_GATE|] `#define STATUS_CTX_LICENSE_NOT_AVAILABLE cpu_to_le32(0xC00A0013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01190 [PROTO_GATE|] `#define STATUS_CTX_LICENSE_EXPIRED cpu_to_le32(0xC00A0014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01191 [PROTO_GATE|] `#define STATUS_CTX_WINSTATION_NOT_FOUND cpu_to_le32(0xC00A0015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01192 [PROTO_GATE|] `#define STATUS_CTX_WINSTATION_NAME_COLLISION cpu_to_le32(0xC00A0016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01193 [PROTO_GATE|] `#define STATUS_CTX_WINSTATION_BUSY cpu_to_le32(0xC00A0017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01194 [PROTO_GATE|] `#define STATUS_CTX_BAD_VIDEO_MODE cpu_to_le32(0xC00A0018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01195 [PROTO_GATE|] `#define STATUS_CTX_GRAPHICS_INVALID cpu_to_le32(0xC00A0022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01196 [PROTO_GATE|] `#define STATUS_CTX_NOT_CONSOLE cpu_to_le32(0xC00A0024)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01197 [PROTO_GATE|] `#define STATUS_CTX_CLIENT_QUERY_TIMEOUT cpu_to_le32(0xC00A0026)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01198 [PROTO_GATE|] `#define STATUS_CTX_CONSOLE_DISCONNECT cpu_to_le32(0xC00A0027)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01199 [PROTO_GATE|] `#define STATUS_CTX_CONSOLE_CONNECT cpu_to_le32(0xC00A0028)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01200 [PROTO_GATE|] `#define STATUS_CTX_SHADOW_DENIED cpu_to_le32(0xC00A002A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01201 [PROTO_GATE|] `#define STATUS_CTX_WINSTATION_ACCESS_DENIED cpu_to_le32(0xC00A002B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01202 [PROTO_GATE|] `#define STATUS_CTX_INVALID_WD cpu_to_le32(0xC00A002E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01203 [PROTO_GATE|] `#define STATUS_CTX_WD_NOT_FOUND cpu_to_le32(0xC00A002F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01204 [PROTO_GATE|] `#define STATUS_CTX_SHADOW_INVALID cpu_to_le32(0xC00A0030)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01205 [PROTO_GATE|] `#define STATUS_CTX_SHADOW_DISABLED cpu_to_le32(0xC00A0031)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01206 [PROTO_GATE|] `#define STATUS_RDP_PROTOCOL_ERROR cpu_to_le32(0xC00A0032)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01207 [PROTO_GATE|] `#define STATUS_CTX_CLIENT_LICENSE_NOT_SET cpu_to_le32(0xC00A0033)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01208 [PROTO_GATE|] `#define STATUS_CTX_CLIENT_LICENSE_IN_USE cpu_to_le32(0xC00A0034)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01209 [PROTO_GATE|] `#define STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE cpu_to_le32(0xC00A0035)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01210 [PROTO_GATE|] `#define STATUS_CTX_SHADOW_NOT_RUNNING cpu_to_le32(0xC00A0036)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01211 [PROTO_GATE|] `#define STATUS_CTX_LOGON_DISABLED cpu_to_le32(0xC00A0037)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01212 [PROTO_GATE|] `#define STATUS_CTX_SECURITY_LAYER_ERROR cpu_to_le32(0xC00A0038)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01213 [PROTO_GATE|] `#define STATUS_TS_INCOMPATIBLE_SESSIONS cpu_to_le32(0xC00A0039)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01214 [PROTO_GATE|] `#define STATUS_MUI_FILE_NOT_FOUND cpu_to_le32(0xC00B0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01215 [PROTO_GATE|] `#define STATUS_MUI_INVALID_FILE cpu_to_le32(0xC00B0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01216 [PROTO_GATE|] `#define STATUS_MUI_INVALID_RC_CONFIG cpu_to_le32(0xC00B0003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01217 [PROTO_GATE|] `#define STATUS_MUI_INVALID_LOCALE_NAME cpu_to_le32(0xC00B0004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01218 [PROTO_GATE|] `#define STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME cpu_to_le32(0xC00B0005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01219 [PROTO_GATE|] `#define STATUS_MUI_FILE_NOT_LOADED cpu_to_le32(0xC00B0006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01220 [PROTO_GATE|] `#define STATUS_RESOURCE_ENUM_USER_STOP cpu_to_le32(0xC00B0007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01221 [PROTO_GATE|] `#define STATUS_CLUSTER_INVALID_NODE cpu_to_le32(0xC0130001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01222 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_EXISTS cpu_to_le32(0xC0130002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01223 [PROTO_GATE|] `#define STATUS_CLUSTER_JOIN_IN_PROGRESS cpu_to_le32(0xC0130003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01224 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_NOT_FOUND cpu_to_le32(0xC0130004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01225 [PROTO_GATE|] `#define STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND cpu_to_le32(0xC0130005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01226 [PROTO_GATE|] `#define STATUS_CLUSTER_NETWORK_EXISTS cpu_to_le32(0xC0130006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01227 [PROTO_GATE|] `#define STATUS_CLUSTER_NETWORK_NOT_FOUND cpu_to_le32(0xC0130007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01228 [PROTO_GATE|] `#define STATUS_CLUSTER_NETINTERFACE_EXISTS cpu_to_le32(0xC0130008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01229 [PROTO_GATE|] `#define STATUS_CLUSTER_NETINTERFACE_NOT_FOUND cpu_to_le32(0xC0130009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01230 [PROTO_GATE|] `#define STATUS_CLUSTER_INVALID_REQUEST cpu_to_le32(0xC013000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01231 [PROTO_GATE|] `#define STATUS_CLUSTER_INVALID_NETWORK_PROVIDER cpu_to_le32(0xC013000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01232 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_DOWN cpu_to_le32(0xC013000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01233 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_UNREACHABLE cpu_to_le32(0xC013000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01234 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_NOT_MEMBER cpu_to_le32(0xC013000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01235 [PROTO_GATE|] `#define STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS cpu_to_le32(0xC013000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01236 [PROTO_GATE|] `#define STATUS_CLUSTER_INVALID_NETWORK cpu_to_le32(0xC0130010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01237 [PROTO_GATE|] `#define STATUS_CLUSTER_NO_NET_ADAPTERS cpu_to_le32(0xC0130011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01238 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_UP cpu_to_le32(0xC0130012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01239 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_PAUSED cpu_to_le32(0xC0130013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01240 [PROTO_GATE|] `#define STATUS_CLUSTER_NODE_NOT_PAUSED cpu_to_le32(0xC0130014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01241 [PROTO_GATE|] `#define STATUS_CLUSTER_NO_SECURITY_CONTEXT cpu_to_le32(0xC0130015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01242 [PROTO_GATE|] `#define STATUS_CLUSTER_NETWORK_NOT_INTERNAL cpu_to_le32(0xC0130016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01243 [PROTO_GATE|] `#define STATUS_CLUSTER_POISONED cpu_to_le32(0xC0130017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01244 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_OPCODE cpu_to_le32(0xC0140001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01245 [PROTO_GATE|] `#define STATUS_ACPI_STACK_OVERFLOW cpu_to_le32(0xC0140002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01246 [PROTO_GATE|] `#define STATUS_ACPI_ASSERT_FAILED cpu_to_le32(0xC0140003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01247 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_INDEX cpu_to_le32(0xC0140004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01248 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_ARGUMENT cpu_to_le32(0xC0140005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01249 [PROTO_GATE|] `#define STATUS_ACPI_FATAL cpu_to_le32(0xC0140006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01250 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_SUPERNAME cpu_to_le32(0xC0140007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01251 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_ARGTYPE cpu_to_le32(0xC0140008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01252 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_OBJTYPE cpu_to_le32(0xC0140009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01253 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_TARGETTYPE cpu_to_le32(0xC014000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01254 [PROTO_GATE|] `#define STATUS_ACPI_INCORRECT_ARGUMENT_COUNT cpu_to_le32(0xC014000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01255 [PROTO_GATE|] `#define STATUS_ACPI_ADDRESS_NOT_MAPPED cpu_to_le32(0xC014000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01256 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_EVENTTYPE cpu_to_le32(0xC014000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01257 [PROTO_GATE|] `#define STATUS_ACPI_HANDLER_COLLISION cpu_to_le32(0xC014000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01258 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_DATA cpu_to_le32(0xC014000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01259 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_REGION cpu_to_le32(0xC0140010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01260 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_ACCESS_SIZE cpu_to_le32(0xC0140011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01261 [PROTO_GATE|] `#define STATUS_ACPI_ACQUIRE_GLOBAL_LOCK cpu_to_le32(0xC0140012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01262 [PROTO_GATE|] `#define STATUS_ACPI_ALREADY_INITIALIZED cpu_to_le32(0xC0140013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01263 [PROTO_GATE|] `#define STATUS_ACPI_NOT_INITIALIZED cpu_to_le32(0xC0140014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01264 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_MUTEX_LEVEL cpu_to_le32(0xC0140015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01265 [PROTO_GATE|] `#define STATUS_ACPI_MUTEX_NOT_OWNED cpu_to_le32(0xC0140016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01266 [PROTO_GATE|] `#define STATUS_ACPI_MUTEX_NOT_OWNER cpu_to_le32(0xC0140017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01267 [PROTO_GATE|] `#define STATUS_ACPI_RS_ACCESS cpu_to_le32(0xC0140018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01268 [PROTO_GATE|] `#define STATUS_ACPI_INVALID_TABLE cpu_to_le32(0xC0140019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01269 [PROTO_GATE|] `#define STATUS_ACPI_REG_HANDLER_FAILED cpu_to_le32(0xC0140020)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01270 [PROTO_GATE|] `#define STATUS_ACPI_POWER_REQUEST_FAILED cpu_to_le32(0xC0140021)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01271 [PROTO_GATE|] `#define STATUS_SXS_SECTION_NOT_FOUND cpu_to_le32(0xC0150001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01272 [PROTO_GATE|] `#define STATUS_SXS_CANT_GEN_ACTCTX cpu_to_le32(0xC0150002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01273 [PROTO_GATE|] `#define STATUS_SXS_INVALID_ACTCTXDATA_FORMAT cpu_to_le32(0xC0150003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01274 [PROTO_GATE|] `#define STATUS_SXS_ASSEMBLY_NOT_FOUND cpu_to_le32(0xC0150004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01275 [PROTO_GATE|] `#define STATUS_SXS_MANIFEST_FORMAT_ERROR cpu_to_le32(0xC0150005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01276 [PROTO_GATE|] `#define STATUS_SXS_MANIFEST_PARSE_ERROR cpu_to_le32(0xC0150006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01277 [PROTO_GATE|] `#define STATUS_SXS_ACTIVATION_CONTEXT_DISABLED cpu_to_le32(0xC0150007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01278 [PROTO_GATE|] `#define STATUS_SXS_KEY_NOT_FOUND cpu_to_le32(0xC0150008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01279 [PROTO_GATE|] `#define STATUS_SXS_VERSION_CONFLICT cpu_to_le32(0xC0150009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01280 [PROTO_GATE|] `#define STATUS_SXS_WRONG_SECTION_TYPE cpu_to_le32(0xC015000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01281 [PROTO_GATE|] `#define STATUS_SXS_THREAD_QUERIES_DISABLED cpu_to_le32(0xC015000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01282 [PROTO_GATE|] `#define STATUS_SXS_ASSEMBLY_MISSING cpu_to_le32(0xC015000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01283 [PROTO_GATE|] `#define STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET cpu_to_le32(0xC015000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01284 [PROTO_GATE|] `#define STATUS_SXS_EARLY_DEACTIVATION cpu_to_le32(0xC015000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01285 [PROTO_GATE|] `#define STATUS_SXS_INVALID_DEACTIVATION cpu_to_le32(0xC0150010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01286 [PROTO_GATE|] `#define STATUS_SXS_MULTIPLE_DEACTIVATION cpu_to_le32(0xC0150011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01287 [PROTO_GATE|] `#define STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01288 [NONE] `	cpu_to_le32(0xC0150012)`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [PROTO_GATE|] `#define STATUS_SXS_PROCESS_TERMINATION_REQUESTED cpu_to_le32(0xC0150013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01290 [PROTO_GATE|] `#define STATUS_SXS_CORRUPT_ACTIVATION_STACK cpu_to_le32(0xC0150014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01291 [PROTO_GATE|] `#define STATUS_SXS_CORRUPTION cpu_to_le32(0xC0150015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01292 [PROTO_GATE|] `#define STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE cpu_to_le32(0xC0150016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01293 [PROTO_GATE|] `#define STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME cpu_to_le32(0xC0150017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01294 [PROTO_GATE|] `#define STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE cpu_to_le32(0xC0150018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01295 [PROTO_GATE|] `#define STATUS_SXS_IDENTITY_PARSE_ERROR cpu_to_le32(0xC0150019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01296 [PROTO_GATE|] `#define STATUS_SXS_COMPONENT_STORE_CORRUPT cpu_to_le32(0xC015001A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01297 [PROTO_GATE|] `#define STATUS_SXS_FILE_HASH_MISMATCH cpu_to_le32(0xC015001B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01298 [PROTO_GATE|] `#define STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01299 [NONE] `	cpu_to_le32(0xC015001C)`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [PROTO_GATE|] `#define STATUS_SXS_IDENTITIES_DIFFERENT cpu_to_le32(0xC015001D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01301 [PROTO_GATE|] `#define STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT cpu_to_le32(0xC015001E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01302 [PROTO_GATE|] `#define STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY cpu_to_le32(0xC015001F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01303 [PROTO_GATE|] `#define STATUS_ADVANCED_INSTALLER_FAILED cpu_to_le32(0xC0150020)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01304 [PROTO_GATE|] `#define STATUS_XML_ENCODING_MISMATCH cpu_to_le32(0xC0150021)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01305 [PROTO_GATE|] `#define STATUS_SXS_MANIFEST_TOO_BIG cpu_to_le32(0xC0150022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01306 [PROTO_GATE|] `#define STATUS_SXS_SETTING_NOT_REGISTERED cpu_to_le32(0xC0150023)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01307 [PROTO_GATE|] `#define STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE cpu_to_le32(0xC0150024)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01308 [PROTO_GATE|] `#define STATUS_SMI_PRIMITIVE_INSTALLER_FAILED cpu_to_le32(0xC0150025)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01309 [PROTO_GATE|] `#define STATUS_GENERIC_COMMAND_FAILED cpu_to_le32(0xC0150026)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01310 [PROTO_GATE|] `#define STATUS_SXS_FILE_HASH_MISSING cpu_to_le32(0xC0150027)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01311 [PROTO_GATE|] `#define STATUS_TRANSACTIONAL_CONFLICT cpu_to_le32(0xC0190001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01312 [PROTO_GATE|] `#define STATUS_INVALID_TRANSACTION cpu_to_le32(0xC0190002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01313 [PROTO_GATE|] `#define STATUS_TRANSACTION_NOT_ACTIVE cpu_to_le32(0xC0190003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01314 [PROTO_GATE|] `#define STATUS_TM_INITIALIZATION_FAILED cpu_to_le32(0xC0190004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01315 [PROTO_GATE|] `#define STATUS_RM_NOT_ACTIVE cpu_to_le32(0xC0190005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01316 [PROTO_GATE|] `#define STATUS_RM_METADATA_CORRUPT cpu_to_le32(0xC0190006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01317 [PROTO_GATE|] `#define STATUS_TRANSACTION_NOT_JOINED cpu_to_le32(0xC0190007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01318 [PROTO_GATE|] `#define STATUS_DIRECTORY_NOT_RM cpu_to_le32(0xC0190008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01319 [PROTO_GATE|] `#define STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE cpu_to_le32(0xC019000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01320 [PROTO_GATE|] `#define STATUS_LOG_RESIZE_INVALID_SIZE cpu_to_le32(0xC019000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01321 [PROTO_GATE|] `#define STATUS_REMOTE_FILE_VERSION_MISMATCH cpu_to_le32(0xC019000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01322 [PROTO_GATE|] `#define STATUS_CRM_PROTOCOL_ALREADY_EXISTS cpu_to_le32(0xC019000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01323 [PROTO_GATE|] `#define STATUS_TRANSACTION_PROPAGATION_FAILED cpu_to_le32(0xC0190010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01324 [PROTO_GATE|] `#define STATUS_CRM_PROTOCOL_NOT_FOUND cpu_to_le32(0xC0190011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01325 [PROTO_GATE|] `#define STATUS_TRANSACTION_SUPERIOR_EXISTS cpu_to_le32(0xC0190012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01326 [PROTO_GATE|] `#define STATUS_TRANSACTION_REQUEST_NOT_VALID cpu_to_le32(0xC0190013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01327 [PROTO_GATE|] `#define STATUS_TRANSACTION_NOT_REQUESTED cpu_to_le32(0xC0190014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01328 [PROTO_GATE|] `#define STATUS_TRANSACTION_ALREADY_ABORTED cpu_to_le32(0xC0190015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01329 [PROTO_GATE|] `#define STATUS_TRANSACTION_ALREADY_COMMITTED cpu_to_le32(0xC0190016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01330 [PROTO_GATE|] `#define STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER cpu_to_le32(0xC0190017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01331 [PROTO_GATE|] `#define STATUS_CURRENT_TRANSACTION_NOT_VALID cpu_to_le32(0xC0190018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01332 [PROTO_GATE|] `#define STATUS_LOG_GROWTH_FAILED cpu_to_le32(0xC0190019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01333 [PROTO_GATE|] `#define STATUS_OBJECT_NO_LONGER_EXISTS cpu_to_le32(0xC0190021)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01334 [PROTO_GATE|] `#define STATUS_STREAM_MINIVERSION_NOT_FOUND cpu_to_le32(0xC0190022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01335 [PROTO_GATE|] `#define STATUS_STREAM_MINIVERSION_NOT_VALID cpu_to_le32(0xC0190023)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01336 [PROTO_GATE|] `#define STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01337 [NONE] `	cpu_to_le32(0xC0190024)`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [PROTO_GATE|] `#define STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT cpu_to_le32(0xC0190025)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01339 [PROTO_GATE|] `#define STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS cpu_to_le32(0xC0190026)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01340 [PROTO_GATE|] `#define STATUS_HANDLE_NO_LONGER_VALID cpu_to_le32(0xC0190028)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01341 [PROTO_GATE|] `#define STATUS_LOG_CORRUPTION_DETECTED cpu_to_le32(0xC0190030)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01342 [PROTO_GATE|] `#define STATUS_RM_DISCONNECTED cpu_to_le32(0xC0190032)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01343 [PROTO_GATE|] `#define STATUS_ENLISTMENT_NOT_SUPERIOR cpu_to_le32(0xC0190033)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01344 [PROTO_GATE|] `#define STATUS_FILE_IDENTITY_NOT_PERSISTENT cpu_to_le32(0xC0190036)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01345 [PROTO_GATE|] `#define STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY cpu_to_le32(0xC0190037)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01346 [PROTO_GATE|] `#define STATUS_CANT_CROSS_RM_BOUNDARY cpu_to_le32(0xC0190038)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01347 [PROTO_GATE|] `#define STATUS_TXF_DIR_NOT_EMPTY cpu_to_le32(0xC0190039)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01348 [PROTO_GATE|] `#define STATUS_INDOUBT_TRANSACTIONS_EXIST cpu_to_le32(0xC019003A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01349 [PROTO_GATE|] `#define STATUS_TM_VOLATILE cpu_to_le32(0xC019003B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01350 [PROTO_GATE|] `#define STATUS_ROLLBACK_TIMER_EXPIRED cpu_to_le32(0xC019003C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01351 [PROTO_GATE|] `#define STATUS_TXF_ATTRIBUTE_CORRUPT cpu_to_le32(0xC019003D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01352 [PROTO_GATE|] `#define STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION cpu_to_le32(0xC019003E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01353 [PROTO_GATE|] `#define STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED cpu_to_le32(0xC019003F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01354 [PROTO_GATE|] `#define STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE cpu_to_le32(0xC0190040)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01355 [PROTO_GATE|] `#define STATUS_TRANSACTION_REQUIRED_PROMOTION cpu_to_le32(0xC0190043)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01356 [PROTO_GATE|] `#define STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION cpu_to_le32(0xC0190044)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01357 [PROTO_GATE|] `#define STATUS_TRANSACTIONS_NOT_FROZEN cpu_to_le32(0xC0190045)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01358 [PROTO_GATE|] `#define STATUS_TRANSACTION_FREEZE_IN_PROGRESS cpu_to_le32(0xC0190046)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01359 [PROTO_GATE|] `#define STATUS_NOT_SNAPSHOT_VOLUME cpu_to_le32(0xC0190047)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01360 [PROTO_GATE|] `#define STATUS_NO_SAVEPOINT_WITH_OPEN_FILES cpu_to_le32(0xC0190048)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01361 [PROTO_GATE|] `#define STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION cpu_to_le32(0xC0190049)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01362 [PROTO_GATE|] `#define STATUS_TM_IDENTITY_MISMATCH cpu_to_le32(0xC019004A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01363 [PROTO_GATE|] `#define STATUS_FLOATED_SECTION cpu_to_le32(0xC019004B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01364 [PROTO_GATE|] `#define STATUS_CANNOT_ACCEPT_TRANSACTED_WORK cpu_to_le32(0xC019004C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01365 [PROTO_GATE|] `#define STATUS_CANNOT_ABORT_TRANSACTIONS cpu_to_le32(0xC019004D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01366 [PROTO_GATE|] `#define STATUS_TRANSACTION_NOT_FOUND cpu_to_le32(0xC019004E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01367 [PROTO_GATE|] `#define STATUS_RESOURCEMANAGER_NOT_FOUND cpu_to_le32(0xC019004F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01368 [PROTO_GATE|] `#define STATUS_ENLISTMENT_NOT_FOUND cpu_to_le32(0xC0190050)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01369 [PROTO_GATE|] `#define STATUS_TRANSACTIONMANAGER_NOT_FOUND cpu_to_le32(0xC0190051)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01370 [PROTO_GATE|] `#define STATUS_TRANSACTIONMANAGER_NOT_ONLINE cpu_to_le32(0xC0190052)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01371 [PROTO_GATE|] `#define STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01372 [NONE] `	cpu_to_le32(0xC0190053)`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [PROTO_GATE|] `#define STATUS_TRANSACTION_NOT_ROOT cpu_to_le32(0xC0190054)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01374 [PROTO_GATE|] `#define STATUS_TRANSACTION_OBJECT_EXPIRED cpu_to_le32(0xC0190055)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01375 [PROTO_GATE|] `#define STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION cpu_to_le32(0xC0190056)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01376 [PROTO_GATE|] `#define STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED cpu_to_le32(0xC0190057)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01377 [PROTO_GATE|] `#define STATUS_TRANSACTION_RECORD_TOO_LONG cpu_to_le32(0xC0190058)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01378 [PROTO_GATE|] `#define STATUS_NO_LINK_TRACKING_IN_TRANSACTION cpu_to_le32(0xC0190059)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01379 [PROTO_GATE|] `#define STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION cpu_to_le32(0xC019005A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01380 [PROTO_GATE|] `#define STATUS_TRANSACTION_INTEGRITY_VIOLATED cpu_to_le32(0xC019005B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01381 [PROTO_GATE|] `#define STATUS_LOG_SECTOR_INVALID cpu_to_le32(0xC01A0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01382 [PROTO_GATE|] `#define STATUS_LOG_SECTOR_PARITY_INVALID cpu_to_le32(0xC01A0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01383 [PROTO_GATE|] `#define STATUS_LOG_SECTOR_REMAPPED cpu_to_le32(0xC01A0003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01384 [PROTO_GATE|] `#define STATUS_LOG_BLOCK_INCOMPLETE cpu_to_le32(0xC01A0004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01385 [PROTO_GATE|] `#define STATUS_LOG_INVALID_RANGE cpu_to_le32(0xC01A0005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01386 [PROTO_GATE|] `#define STATUS_LOG_BLOCKS_EXHAUSTED cpu_to_le32(0xC01A0006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01387 [PROTO_GATE|] `#define STATUS_LOG_READ_CONTEXT_INVALID cpu_to_le32(0xC01A0007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01388 [PROTO_GATE|] `#define STATUS_LOG_RESTART_INVALID cpu_to_le32(0xC01A0008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01389 [PROTO_GATE|] `#define STATUS_LOG_BLOCK_VERSION cpu_to_le32(0xC01A0009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01390 [PROTO_GATE|] `#define STATUS_LOG_BLOCK_INVALID cpu_to_le32(0xC01A000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01391 [PROTO_GATE|] `#define STATUS_LOG_READ_MODE_INVALID cpu_to_le32(0xC01A000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01392 [PROTO_GATE|] `#define STATUS_LOG_METADATA_CORRUPT cpu_to_le32(0xC01A000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01393 [PROTO_GATE|] `#define STATUS_LOG_METADATA_INVALID cpu_to_le32(0xC01A000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01394 [PROTO_GATE|] `#define STATUS_LOG_METADATA_INCONSISTENT cpu_to_le32(0xC01A000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01395 [PROTO_GATE|] `#define STATUS_LOG_RESERVATION_INVALID cpu_to_le32(0xC01A0010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01396 [PROTO_GATE|] `#define STATUS_LOG_CANT_DELETE cpu_to_le32(0xC01A0011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01397 [PROTO_GATE|] `#define STATUS_LOG_CONTAINER_LIMIT_EXCEEDED cpu_to_le32(0xC01A0012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01398 [PROTO_GATE|] `#define STATUS_LOG_START_OF_LOG cpu_to_le32(0xC01A0013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01399 [PROTO_GATE|] `#define STATUS_LOG_POLICY_ALREADY_INSTALLED cpu_to_le32(0xC01A0014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01400 [PROTO_GATE|] `#define STATUS_LOG_POLICY_NOT_INSTALLED cpu_to_le32(0xC01A0015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01401 [PROTO_GATE|] `#define STATUS_LOG_POLICY_INVALID cpu_to_le32(0xC01A0016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01402 [PROTO_GATE|] `#define STATUS_LOG_POLICY_CONFLICT cpu_to_le32(0xC01A0017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01403 [PROTO_GATE|] `#define STATUS_LOG_PINNED_ARCHIVE_TAIL cpu_to_le32(0xC01A0018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01404 [PROTO_GATE|] `#define STATUS_LOG_RECORD_NONEXISTENT cpu_to_le32(0xC01A0019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01405 [PROTO_GATE|] `#define STATUS_LOG_RECORDS_RESERVED_INVALID cpu_to_le32(0xC01A001A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01406 [PROTO_GATE|] `#define STATUS_LOG_SPACE_RESERVED_INVALID cpu_to_le32(0xC01A001B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01407 [PROTO_GATE|] `#define STATUS_LOG_TAIL_INVALID cpu_to_le32(0xC01A001C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01408 [PROTO_GATE|] `#define STATUS_LOG_FULL cpu_to_le32(0xC01A001D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01409 [PROTO_GATE|] `#define STATUS_LOG_MULTIPLEXED cpu_to_le32(0xC01A001E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01410 [PROTO_GATE|] `#define STATUS_LOG_DEDICATED cpu_to_le32(0xC01A001F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01411 [PROTO_GATE|] `#define STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS cpu_to_le32(0xC01A0020)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01412 [PROTO_GATE|] `#define STATUS_LOG_ARCHIVE_IN_PROGRESS cpu_to_le32(0xC01A0021)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01413 [PROTO_GATE|] `#define STATUS_LOG_EPHEMERAL cpu_to_le32(0xC01A0022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01414 [PROTO_GATE|] `#define STATUS_LOG_NOT_ENOUGH_CONTAINERS cpu_to_le32(0xC01A0023)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01415 [PROTO_GATE|] `#define STATUS_LOG_CLIENT_ALREADY_REGISTERED cpu_to_le32(0xC01A0024)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01416 [PROTO_GATE|] `#define STATUS_LOG_CLIENT_NOT_REGISTERED cpu_to_le32(0xC01A0025)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01417 [PROTO_GATE|] `#define STATUS_LOG_FULL_HANDLER_IN_PROGRESS cpu_to_le32(0xC01A0026)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01418 [PROTO_GATE|] `#define STATUS_LOG_CONTAINER_READ_FAILED cpu_to_le32(0xC01A0027)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01419 [PROTO_GATE|] `#define STATUS_LOG_CONTAINER_WRITE_FAILED cpu_to_le32(0xC01A0028)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01420 [PROTO_GATE|] `#define STATUS_LOG_CONTAINER_OPEN_FAILED cpu_to_le32(0xC01A0029)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01421 [PROTO_GATE|] `#define STATUS_LOG_CONTAINER_STATE_INVALID cpu_to_le32(0xC01A002A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01422 [PROTO_GATE|] `#define STATUS_LOG_STATE_INVALID cpu_to_le32(0xC01A002B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01423 [PROTO_GATE|] `#define STATUS_LOG_PINNED cpu_to_le32(0xC01A002C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01424 [PROTO_GATE|] `#define STATUS_LOG_METADATA_FLUSH_FAILED cpu_to_le32(0xC01A002D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01425 [PROTO_GATE|] `#define STATUS_LOG_INCONSISTENT_SECURITY cpu_to_le32(0xC01A002E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01426 [PROTO_GATE|] `#define STATUS_LOG_APPENDED_FLUSH_FAILED cpu_to_le32(0xC01A002F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01427 [PROTO_GATE|] `#define STATUS_LOG_PINNED_RESERVATION cpu_to_le32(0xC01A0030)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01428 [PROTO_GATE|] `#define STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD cpu_to_le32(0xC01B00EA)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01429 [PROTO_GATE|] `#define STATUS_FLT_NO_HANDLER_DEFINED cpu_to_le32(0xC01C0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01430 [PROTO_GATE|] `#define STATUS_FLT_CONTEXT_ALREADY_DEFINED cpu_to_le32(0xC01C0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01431 [PROTO_GATE|] `#define STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST cpu_to_le32(0xC01C0003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01432 [PROTO_GATE|] `#define STATUS_FLT_DISALLOW_FAST_IO cpu_to_le32(0xC01C0004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01433 [PROTO_GATE|] `#define STATUS_FLT_INVALID_NAME_REQUEST cpu_to_le32(0xC01C0005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01434 [PROTO_GATE|] `#define STATUS_FLT_NOT_SAFE_TO_POST_OPERATION cpu_to_le32(0xC01C0006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01435 [PROTO_GATE|] `#define STATUS_FLT_NOT_INITIALIZED cpu_to_le32(0xC01C0007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01436 [PROTO_GATE|] `#define STATUS_FLT_FILTER_NOT_READY cpu_to_le32(0xC01C0008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01437 [PROTO_GATE|] `#define STATUS_FLT_POST_OPERATION_CLEANUP cpu_to_le32(0xC01C0009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01438 [PROTO_GATE|] `#define STATUS_FLT_INTERNAL_ERROR cpu_to_le32(0xC01C000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01439 [PROTO_GATE|] `#define STATUS_FLT_DELETING_OBJECT cpu_to_le32(0xC01C000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01440 [PROTO_GATE|] `#define STATUS_FLT_MUST_BE_NONPAGED_POOL cpu_to_le32(0xC01C000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01441 [PROTO_GATE|] `#define STATUS_FLT_DUPLICATE_ENTRY cpu_to_le32(0xC01C000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01442 [PROTO_GATE|] `#define STATUS_FLT_CBDQ_DISABLED cpu_to_le32(0xC01C000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01443 [PROTO_GATE|] `#define STATUS_FLT_DO_NOT_ATTACH cpu_to_le32(0xC01C000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01444 [PROTO_GATE|] `#define STATUS_FLT_DO_NOT_DETACH cpu_to_le32(0xC01C0010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01445 [PROTO_GATE|] `#define STATUS_FLT_INSTANCE_ALTITUDE_COLLISION cpu_to_le32(0xC01C0011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01446 [PROTO_GATE|] `#define STATUS_FLT_INSTANCE_NAME_COLLISION cpu_to_le32(0xC01C0012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01447 [PROTO_GATE|] `#define STATUS_FLT_FILTER_NOT_FOUND cpu_to_le32(0xC01C0013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01448 [PROTO_GATE|] `#define STATUS_FLT_VOLUME_NOT_FOUND cpu_to_le32(0xC01C0014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01449 [PROTO_GATE|] `#define STATUS_FLT_INSTANCE_NOT_FOUND cpu_to_le32(0xC01C0015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01450 [PROTO_GATE|] `#define STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND cpu_to_le32(0xC01C0016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01451 [PROTO_GATE|] `#define STATUS_FLT_INVALID_CONTEXT_REGISTRATION cpu_to_le32(0xC01C0017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01452 [PROTO_GATE|] `#define STATUS_FLT_NAME_CACHE_MISS cpu_to_le32(0xC01C0018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01453 [PROTO_GATE|] `#define STATUS_FLT_NO_DEVICE_OBJECT cpu_to_le32(0xC01C0019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01454 [PROTO_GATE|] `#define STATUS_FLT_VOLUME_ALREADY_MOUNTED cpu_to_le32(0xC01C001A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01455 [PROTO_GATE|] `#define STATUS_FLT_ALREADY_ENLISTED cpu_to_le32(0xC01C001B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01456 [PROTO_GATE|] `#define STATUS_FLT_CONTEXT_ALREADY_LINKED cpu_to_le32(0xC01C001C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01457 [PROTO_GATE|] `#define STATUS_FLT_NO_WAITER_FOR_REPLY cpu_to_le32(0xC01C0020)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01458 [PROTO_GATE|] `#define STATUS_MONITOR_NO_DESCRIPTOR cpu_to_le32(0xC01D0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01459 [PROTO_GATE|] `#define STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT cpu_to_le32(0xC01D0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01460 [PROTO_GATE|] `#define STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM cpu_to_le32(0xC01D0003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01461 [PROTO_GATE|] `#define STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK cpu_to_le32(0xC01D0004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01462 [PROTO_GATE|] `#define STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED cpu_to_le32(0xC01D0005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01463 [PROTO_GATE|] `#define STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01464 [NONE] `	cpu_to_le32(0xC01D0006)`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [PROTO_GATE|] `#define STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01466 [NONE] `	cpu_to_le32(0xC01D0007)`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [PROTO_GATE|] `#define STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA cpu_to_le32(0xC01D0008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01468 [PROTO_GATE|] `#define STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK cpu_to_le32(0xC01D0009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01469 [PROTO_GATE|] `#define STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER cpu_to_le32(0xC01E0000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01470 [PROTO_GATE|] `#define STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER cpu_to_le32(0xC01E0001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01471 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER cpu_to_le32(0xC01E0002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01472 [PROTO_GATE|] `#define STATUS_GRAPHICS_ADAPTER_WAS_RESET cpu_to_le32(0xC01E0003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01473 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_DRIVER_MODEL cpu_to_le32(0xC01E0004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01474 [PROTO_GATE|] `#define STATUS_GRAPHICS_PRESENT_MODE_CHANGED cpu_to_le32(0xC01E0005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01475 [PROTO_GATE|] `#define STATUS_GRAPHICS_PRESENT_OCCLUDED cpu_to_le32(0xC01E0006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01476 [PROTO_GATE|] `#define STATUS_GRAPHICS_PRESENT_DENIED cpu_to_le32(0xC01E0007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01477 [PROTO_GATE|] `#define STATUS_GRAPHICS_CANNOTCOLORCONVERT cpu_to_le32(0xC01E0008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01478 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_VIDEO_MEMORY cpu_to_le32(0xC01E0100)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01479 [PROTO_GATE|] `#define STATUS_GRAPHICS_CANT_LOCK_MEMORY cpu_to_le32(0xC01E0101)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01480 [PROTO_GATE|] `#define STATUS_GRAPHICS_ALLOCATION_BUSY cpu_to_le32(0xC01E0102)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01481 [PROTO_GATE|] `#define STATUS_GRAPHICS_TOO_MANY_REFERENCES cpu_to_le32(0xC01E0103)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01482 [PROTO_GATE|] `#define STATUS_GRAPHICS_TRY_AGAIN_LATER cpu_to_le32(0xC01E0104)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01483 [PROTO_GATE|] `#define STATUS_GRAPHICS_TRY_AGAIN_NOW cpu_to_le32(0xC01E0105)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01484 [PROTO_GATE|] `#define STATUS_GRAPHICS_ALLOCATION_INVALID cpu_to_le32(0xC01E0106)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01485 [PROTO_GATE|] `#define STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE cpu_to_le32(0xC01E0107)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01486 [PROTO_GATE|] `#define STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED cpu_to_le32(0xC01E0108)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01487 [PROTO_GATE|] `#define STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION cpu_to_le32(0xC01E0109)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01488 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE cpu_to_le32(0xC01E0110)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01489 [PROTO_GATE|] `#define STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION cpu_to_le32(0xC01E0111)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01490 [PROTO_GATE|] `#define STATUS_GRAPHICS_ALLOCATION_CLOSED cpu_to_le32(0xC01E0112)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01491 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE cpu_to_le32(0xC01E0113)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01492 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE cpu_to_le32(0xC01E0114)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01493 [PROTO_GATE|] `#define STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE cpu_to_le32(0xC01E0115)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01494 [PROTO_GATE|] `#define STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST cpu_to_le32(0xC01E0116)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01495 [PROTO_GATE|] `#define STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE cpu_to_le32(0xC01E0200)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01496 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY cpu_to_le32(0xC01E0300)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01497 [PROTO_GATE|] `#define STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED cpu_to_le32(0xC01E0301)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01498 [PROTO_GATE|] `#define STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01499 [NONE] `	cpu_to_le32(0xC01E0302)`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDPN cpu_to_le32(0xC01E0303)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01501 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE cpu_to_le32(0xC01E0304)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01502 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET cpu_to_le32(0xC01E0305)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01503 [PROTO_GATE|] `#define STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED cpu_to_le32(0xC01E0306)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01504 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET cpu_to_le32(0xC01E0308)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01505 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET cpu_to_le32(0xC01E0309)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01506 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_FREQUENCY cpu_to_le32(0xC01E030A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01507 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_ACTIVE_REGION cpu_to_le32(0xC01E030B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01508 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_TOTAL_REGION cpu_to_le32(0xC01E030C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01509 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01510 [NONE] `	cpu_to_le32(0xC01E0310)`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01512 [NONE] `	cpu_to_le32(0xC01E0311)`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [PROTO_GATE|] `#define STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET cpu_to_le32(0xC01E0312)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01514 [PROTO_GATE|] `#define STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY cpu_to_le32(0xC01E0313)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01515 [PROTO_GATE|] `#define STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET cpu_to_le32(0xC01E0314)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01516 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET cpu_to_le32(0xC01E0315)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01517 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET cpu_to_le32(0xC01E0316)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01518 [PROTO_GATE|] `#define STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET cpu_to_le32(0xC01E0317)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01519 [PROTO_GATE|] `#define STATUS_GRAPHICS_TARGET_ALREADY_IN_SET cpu_to_le32(0xC01E0318)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01520 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH cpu_to_le32(0xC01E0319)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01521 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY cpu_to_le32(0xC01E031A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01522 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01523 [NONE] `	cpu_to_le32(0xC01E031B)`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE cpu_to_le32(0xC01E031C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01525 [PROTO_GATE|] `#define STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET cpu_to_le32(0xC01E031D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01526 [PROTO_GATE|] `#define STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET cpu_to_le32(0xC01E031F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01527 [PROTO_GATE|] `#define STATUS_GRAPHICS_STALE_MODESET cpu_to_le32(0xC01E0320)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01528 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET cpu_to_le32(0xC01E0321)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01529 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE cpu_to_le32(0xC01E0322)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01530 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN cpu_to_le32(0xC01E0323)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01531 [PROTO_GATE|] `#define STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE cpu_to_le32(0xC01E0324)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01532 [PROTO_GATE|] `#define STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01533 [NONE] `	cpu_to_le32(0xC01E0325)`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [PROTO_GATE|] `#define STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01535 [NONE] `	cpu_to_le32(0xC01E0326)`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [PROTO_GATE|] `#define STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY cpu_to_le32(0xC01E0327)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01537 [PROTO_GATE|] `#define STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01538 [NONE] `	cpu_to_le32(0xC01E0328)`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [PROTO_GATE|] `#define STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01540 [NONE] `	cpu_to_le32(0xC01E0329)`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET cpu_to_le32(0xC01E032A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01542 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR cpu_to_le32(0xC01E032B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01543 [PROTO_GATE|] `#define STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET cpu_to_le32(0xC01E032C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01544 [PROTO_GATE|] `#define STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET cpu_to_le32(0xC01E032D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01545 [PROTO_GATE|] `#define STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01546 [NONE] `	cpu_to_le32(0xC01E032E)`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE cpu_to_le32(0xC01E032F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01548 [PROTO_GATE|] `#define STATUS_GRAPHICS_RESOURCES_NOT_RELATED cpu_to_le32(0xC01E0330)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01549 [PROTO_GATE|] `#define STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE cpu_to_le32(0xC01E0331)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01550 [PROTO_GATE|] `#define STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE cpu_to_le32(0xC01E0332)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01551 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET cpu_to_le32(0xC01E0333)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01552 [PROTO_GATE|] `#define STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01553 [NONE] `	cpu_to_le32(0xC01E0334)`
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_VIDPNMGR cpu_to_le32(0xC01E0335)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01555 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_ACTIVE_VIDPN cpu_to_le32(0xC01E0336)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01556 [PROTO_GATE|] `#define STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY cpu_to_le32(0xC01E0337)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01557 [PROTO_GATE|] `#define STATUS_GRAPHICS_MONITOR_NOT_CONNECTED cpu_to_le32(0xC01E0338)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01558 [PROTO_GATE|] `#define STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY cpu_to_le32(0xC01E0339)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01559 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE cpu_to_le32(0xC01E033A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01560 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE cpu_to_le32(0xC01E033B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01561 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_STRIDE cpu_to_le32(0xC01E033C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01562 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_PIXELFORMAT cpu_to_le32(0xC01E033D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01563 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_COLORBASIS cpu_to_le32(0xC01E033E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01564 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE cpu_to_le32(0xC01E033F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01565 [PROTO_GATE|] `#define STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY cpu_to_le32(0xC01E0340)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01566 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01567 [NONE] `	cpu_to_le32(0xC01E0341)`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [PROTO_GATE|] `#define STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE cpu_to_le32(0xC01E0342)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01569 [PROTO_GATE|] `#define STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN cpu_to_le32(0xC01E0343)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01570 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL cpu_to_le32(0xC01E0344)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01571 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01572 [NONE] `	cpu_to_le32(0xC01E0345)`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [PROTO_GATE|] `#define STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED \`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01574 [NONE] `	cpu_to_le32(0xC01E0346)`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_GAMMA_RAMP cpu_to_le32(0xC01E0347)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01576 [PROTO_GATE|] `#define STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED cpu_to_le32(0xC01E0348)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01577 [PROTO_GATE|] `#define STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED cpu_to_le32(0xC01E0349)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01578 [PROTO_GATE|] `#define STATUS_GRAPHICS_MODE_NOT_IN_MODESET cpu_to_le32(0xC01E034A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01579 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01580 [NONE] `	cpu_to_le32(0xC01E034D)`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE cpu_to_le32(0xC01E034E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01582 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE cpu_to_le32(0xC01E034F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01583 [PROTO_GATE|] `#define STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01584 [NONE] `	cpu_to_le32(0xC01E0350)`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING cpu_to_le32(0xC01E0352)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01586 [PROTO_GATE|] `#define STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED cpu_to_le32(0xC01E0353)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01587 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS cpu_to_le32(0xC01E0354)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01588 [PROTO_GATE|] `#define STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT cpu_to_le32(0xC01E0355)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01589 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM cpu_to_le32(0xC01E0356)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01590 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01591 [NONE] `	cpu_to_le32(0xC01E0357)`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01593 [NONE] `	cpu_to_le32(0xC01E0358)`
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [PROTO_GATE|] `#define STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED cpu_to_le32(0xC01E0359)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01595 [PROTO_GATE|] `#define STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01596 [NONE] `	cpu_to_le32(0xC01E035A)`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_CLIENT_TYPE cpu_to_le32(0xC01E035B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01598 [PROTO_GATE|] `#define STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET cpu_to_le32(0xC01E035C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01599 [PROTO_GATE|] `#define STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01600 [NONE] `	cpu_to_le32(0xC01E0400)`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [PROTO_GATE|] `#define STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED cpu_to_le32(0xC01E0401)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01602 [PROTO_GATE|] `#define STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER cpu_to_le32(0xC01E0430)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01603 [PROTO_GATE|] `#define STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED cpu_to_le32(0xC01E0431)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01604 [PROTO_GATE|] `#define STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED cpu_to_le32(0xC01E0432)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01605 [PROTO_GATE|] `#define STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY cpu_to_le32(0xC01E0433)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01606 [PROTO_GATE|] `#define STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED cpu_to_le32(0xC01E0434)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01607 [PROTO_GATE|] `#define STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON cpu_to_le32(0xC01E0435)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01608 [PROTO_GATE|] `#define STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE cpu_to_le32(0xC01E0436)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01609 [PROTO_GATE|] `#define STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER cpu_to_le32(0xC01E0438)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01610 [PROTO_GATE|] `#define STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED cpu_to_le32(0xC01E043B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01611 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS \`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01612 [NONE] `	cpu_to_le32(0xC01E051C)`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST cpu_to_le32(0xC01E051D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01614 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR cpu_to_le32(0xC01E051E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01615 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS \`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01616 [NONE] `	cpu_to_le32(0xC01E051F)`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED cpu_to_le32(0xC01E0520)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01618 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01619 [NONE] `	cpu_to_le32(0xC01E0521)`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_NOT_SUPPORTED cpu_to_le32(0xC01E0500)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01621 [PROTO_GATE|] `#define STATUS_GRAPHICS_COPP_NOT_SUPPORTED cpu_to_le32(0xC01E0501)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01622 [PROTO_GATE|] `#define STATUS_GRAPHICS_UAB_NOT_SUPPORTED cpu_to_le32(0xC01E0502)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01623 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS cpu_to_le32(0xC01E0503)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01624 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_PARAMETER_ARRAY_TOO_SMALL cpu_to_le32(0xC01E0504)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01625 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST cpu_to_le32(0xC01E0505)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01626 [PROTO_GATE|] `#define STATUS_GRAPHICS_PVP_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01627 [NONE] `	cpu_to_le32(0xC01E0506)`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [PROTO_GATE|] `#define STATUS_GRAPHICS_PVP_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01629 [NONE] `	cpu_to_le32(0xC01E0507)`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [PROTO_GATE|] `#define STATUS_GRAPHICS_PVP_MIRRORING_DEVICES_NOT_SUPPORTED	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01631 [NONE] `	cpu_to_le32(0xC01E0508)`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_INVALID_POINTER cpu_to_le32(0xC01E050A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01633 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_INTERNAL_ERROR cpu_to_le32(0xC01E050B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01634 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_INVALID_HANDLE cpu_to_le32(0xC01E050C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01635 [PROTO_GATE|] `#define STATUS_GRAPHICS_PVP_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01636 [NONE] `	cpu_to_le32(0xC01E050D)`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [PROTO_GATE|] `#define STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH cpu_to_le32(0xC01E050E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01638 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED cpu_to_le32(0xC01E050F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01639 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED cpu_to_le32(0xC01E0510)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01640 [PROTO_GATE|] `#define STATUS_GRAPHICS_PVP_HFS_FAILED cpu_to_le32(0xC01E0511)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01641 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_INVALID_SRM cpu_to_le32(0xC01E0512)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01642 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP cpu_to_le32(0xC01E0513)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01643 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP cpu_to_le32(0xC01E0514)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01644 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01645 [NONE] `	cpu_to_le32(0xC01E0515)`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET cpu_to_le32(0xC01E0516)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01647 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH cpu_to_le32(0xC01E0517)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01648 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01649 [NONE] `	cpu_to_le32(0xC01E0518)`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01651 [NONE] `	cpu_to_le32(0xC01E051A)`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [PROTO_GATE|] `#define STATUS_GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01653 [NONE] `	cpu_to_le32(0xC01E051B)`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [PROTO_GATE|] `#define STATUS_GRAPHICS_I2C_NOT_SUPPORTED cpu_to_le32(0xC01E0580)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01655 [PROTO_GATE|] `#define STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST cpu_to_le32(0xC01E0581)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01656 [PROTO_GATE|] `#define STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA cpu_to_le32(0xC01E0582)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01657 [PROTO_GATE|] `#define STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA cpu_to_le32(0xC01E0583)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01658 [PROTO_GATE|] `#define STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED cpu_to_le32(0xC01E0584)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01659 [PROTO_GATE|] `#define STATUS_GRAPHICS_DDCCI_INVALID_DATA cpu_to_le32(0xC01E0585)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01660 [PROTO_GATE|] `#define STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE \`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01661 [NONE] `	cpu_to_le32(0xC01E0586)`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [PROTO_GATE|] `#define STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01663 [NONE] `	cpu_to_le32(0xC01E0587)`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [PROTO_GATE|] `#define STATUS_GRAPHICS_MCA_INTERNAL_ERROR cpu_to_le32(0xC01E0588)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01665 [PROTO_GATE|] `#define STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND cpu_to_le32(0xC01E0589)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01666 [PROTO_GATE|] `#define STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH cpu_to_le32(0xC01E058A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01667 [PROTO_GATE|] `#define STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM cpu_to_le32(0xC01E058B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01668 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE cpu_to_le32(0xC01E058C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01669 [PROTO_GATE|] `#define STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS cpu_to_le32(0xC01E058D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01670 [PROTO_GATE|] `#define STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED cpu_to_le32(0xC01E05E0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01671 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01672 [NONE] `	cpu_to_le32(0xC01E05E1)`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [PROTO_GATE|] `#define STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01674 [NONE] `	cpu_to_le32(0xC01E05E2)`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [PROTO_GATE|] `#define STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED cpu_to_le32(0xC01E05E3)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01676 [PROTO_GATE|] `#define STATUS_GRAPHICS_INVALID_POINTER cpu_to_le32(0xC01E05E4)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01677 [PROTO_GATE|] `#define STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE	\`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01678 [NONE] `	cpu_to_le32(0xC01E05E5)`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [PROTO_GATE|] `#define STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL cpu_to_le32(0xC01E05E6)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01680 [PROTO_GATE|] `#define STATUS_GRAPHICS_INTERNAL_ERROR cpu_to_le32(0xC01E05E7)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01681 [PROTO_GATE|] `#define STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS cpu_to_le32(0xC01E05E8)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01682 [PROTO_GATE|] `#define STATUS_FVE_LOCKED_VOLUME cpu_to_le32(0xC0210000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01683 [PROTO_GATE|] `#define STATUS_FVE_NOT_ENCRYPTED cpu_to_le32(0xC0210001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01684 [PROTO_GATE|] `#define STATUS_FVE_BAD_INFORMATION cpu_to_le32(0xC0210002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01685 [PROTO_GATE|] `#define STATUS_FVE_TOO_SMALL cpu_to_le32(0xC0210003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01686 [PROTO_GATE|] `#define STATUS_FVE_FAILED_WRONG_FS cpu_to_le32(0xC0210004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01687 [PROTO_GATE|] `#define STATUS_FVE_FAILED_BAD_FS cpu_to_le32(0xC0210005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01688 [PROTO_GATE|] `#define STATUS_FVE_FS_NOT_EXTENDED cpu_to_le32(0xC0210006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01689 [PROTO_GATE|] `#define STATUS_FVE_FS_MOUNTED cpu_to_le32(0xC0210007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01690 [PROTO_GATE|] `#define STATUS_FVE_NO_LICENSE cpu_to_le32(0xC0210008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01691 [PROTO_GATE|] `#define STATUS_FVE_ACTION_NOT_ALLOWED cpu_to_le32(0xC0210009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01692 [PROTO_GATE|] `#define STATUS_FVE_BAD_DATA cpu_to_le32(0xC021000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01693 [PROTO_GATE|] `#define STATUS_FVE_VOLUME_NOT_BOUND cpu_to_le32(0xC021000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01694 [PROTO_GATE|] `#define STATUS_FVE_NOT_DATA_VOLUME cpu_to_le32(0xC021000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01695 [PROTO_GATE|] `#define STATUS_FVE_CONV_READ_ERROR cpu_to_le32(0xC021000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01696 [PROTO_GATE|] `#define STATUS_FVE_CONV_WRITE_ERROR cpu_to_le32(0xC021000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01697 [PROTO_GATE|] `#define STATUS_FVE_OVERLAPPED_UPDATE cpu_to_le32(0xC021000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01698 [PROTO_GATE|] `#define STATUS_FVE_FAILED_SECTOR_SIZE cpu_to_le32(0xC0210010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01699 [PROTO_GATE|] `#define STATUS_FVE_FAILED_AUTHENTICATION cpu_to_le32(0xC0210011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01700 [PROTO_GATE|] `#define STATUS_FVE_NOT_OS_VOLUME cpu_to_le32(0xC0210012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01701 [PROTO_GATE|] `#define STATUS_FVE_KEYFILE_NOT_FOUND cpu_to_le32(0xC0210013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01702 [PROTO_GATE|] `#define STATUS_FVE_KEYFILE_INVALID cpu_to_le32(0xC0210014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01703 [PROTO_GATE|] `#define STATUS_FVE_KEYFILE_NO_VMK cpu_to_le32(0xC0210015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01704 [PROTO_GATE|] `#define STATUS_FVE_TPM_DISABLED cpu_to_le32(0xC0210016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01705 [PROTO_GATE|] `#define STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO cpu_to_le32(0xC0210017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01706 [PROTO_GATE|] `#define STATUS_FVE_TPM_INVALID_PCR cpu_to_le32(0xC0210018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01707 [PROTO_GATE|] `#define STATUS_FVE_TPM_NO_VMK cpu_to_le32(0xC0210019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01708 [PROTO_GATE|] `#define STATUS_FVE_PIN_INVALID cpu_to_le32(0xC021001A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01709 [PROTO_GATE|] `#define STATUS_FVE_AUTH_INVALID_APPLICATION cpu_to_le32(0xC021001B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01710 [PROTO_GATE|] `#define STATUS_FVE_AUTH_INVALID_CONFIG cpu_to_le32(0xC021001C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01711 [PROTO_GATE|] `#define STATUS_FVE_DEBUGGER_ENABLED cpu_to_le32(0xC021001D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01712 [PROTO_GATE|] `#define STATUS_FVE_DRY_RUN_FAILED cpu_to_le32(0xC021001E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01713 [PROTO_GATE|] `#define STATUS_FVE_BAD_METADATA_POINTER cpu_to_le32(0xC021001F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01714 [PROTO_GATE|] `#define STATUS_FVE_OLD_METADATA_COPY cpu_to_le32(0xC0210020)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01715 [PROTO_GATE|] `#define STATUS_FVE_REBOOT_REQUIRED cpu_to_le32(0xC0210021)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01716 [PROTO_GATE|] `#define STATUS_FVE_RAW_ACCESS cpu_to_le32(0xC0210022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01717 [PROTO_GATE|] `#define STATUS_FVE_RAW_BLOCKED cpu_to_le32(0xC0210023)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01718 [PROTO_GATE|] `#define STATUS_FWP_CALLOUT_NOT_FOUND cpu_to_le32(0xC0220001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01719 [PROTO_GATE|] `#define STATUS_FWP_CONDITION_NOT_FOUND cpu_to_le32(0xC0220002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01720 [PROTO_GATE|] `#define STATUS_FWP_FILTER_NOT_FOUND cpu_to_le32(0xC0220003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01721 [PROTO_GATE|] `#define STATUS_FWP_LAYER_NOT_FOUND cpu_to_le32(0xC0220004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01722 [PROTO_GATE|] `#define STATUS_FWP_PROVIDER_NOT_FOUND cpu_to_le32(0xC0220005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01723 [PROTO_GATE|] `#define STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND cpu_to_le32(0xC0220006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01724 [PROTO_GATE|] `#define STATUS_FWP_SUBLAYER_NOT_FOUND cpu_to_le32(0xC0220007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01725 [PROTO_GATE|] `#define STATUS_FWP_NOT_FOUND cpu_to_le32(0xC0220008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01726 [PROTO_GATE|] `#define STATUS_FWP_ALREADY_EXISTS cpu_to_le32(0xC0220009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01727 [PROTO_GATE|] `#define STATUS_FWP_IN_USE cpu_to_le32(0xC022000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01728 [PROTO_GATE|] `#define STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS cpu_to_le32(0xC022000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01729 [PROTO_GATE|] `#define STATUS_FWP_WRONG_SESSION cpu_to_le32(0xC022000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01730 [PROTO_GATE|] `#define STATUS_FWP_NO_TXN_IN_PROGRESS cpu_to_le32(0xC022000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01731 [PROTO_GATE|] `#define STATUS_FWP_TXN_IN_PROGRESS cpu_to_le32(0xC022000E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01732 [PROTO_GATE|] `#define STATUS_FWP_TXN_ABORTED cpu_to_le32(0xC022000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01733 [PROTO_GATE|] `#define STATUS_FWP_SESSION_ABORTED cpu_to_le32(0xC0220010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01734 [PROTO_GATE|] `#define STATUS_FWP_INCOMPATIBLE_TXN cpu_to_le32(0xC0220011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01735 [PROTO_GATE|] `#define STATUS_FWP_TIMEOUT cpu_to_le32(0xC0220012)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01736 [PROTO_GATE|] `#define STATUS_FWP_NET_EVENTS_DISABLED cpu_to_le32(0xC0220013)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01737 [PROTO_GATE|] `#define STATUS_FWP_INCOMPATIBLE_LAYER cpu_to_le32(0xC0220014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01738 [PROTO_GATE|] `#define STATUS_FWP_KM_CLIENTS_ONLY cpu_to_le32(0xC0220015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01739 [PROTO_GATE|] `#define STATUS_FWP_LIFETIME_MISMATCH cpu_to_le32(0xC0220016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01740 [PROTO_GATE|] `#define STATUS_FWP_BUILTIN_OBJECT cpu_to_le32(0xC0220017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01741 [PROTO_GATE|] `#define STATUS_FWP_TOO_MANY_BOOTTIME_FILTERS cpu_to_le32(0xC0220018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01742 [PROTO_GATE|] `#define STATUS_FWP_TOO_MANY_CALLOUTS cpu_to_le32(0xC0220018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01743 [PROTO_GATE|] `#define STATUS_FWP_NOTIFICATION_DROPPED cpu_to_le32(0xC0220019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01744 [PROTO_GATE|] `#define STATUS_FWP_TRAFFIC_MISMATCH cpu_to_le32(0xC022001A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01745 [PROTO_GATE|] `#define STATUS_FWP_INCOMPATIBLE_SA_STATE cpu_to_le32(0xC022001B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01746 [PROTO_GATE|] `#define STATUS_FWP_NULL_POINTER cpu_to_le32(0xC022001C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01747 [PROTO_GATE|] `#define STATUS_FWP_INVALID_ENUMERATOR cpu_to_le32(0xC022001D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01748 [PROTO_GATE|] `#define STATUS_FWP_INVALID_FLAGS cpu_to_le32(0xC022001E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01749 [PROTO_GATE|] `#define STATUS_FWP_INVALID_NET_MASK cpu_to_le32(0xC022001F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01750 [PROTO_GATE|] `#define STATUS_FWP_INVALID_RANGE cpu_to_le32(0xC0220020)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01751 [PROTO_GATE|] `#define STATUS_FWP_INVALID_INTERVAL cpu_to_le32(0xC0220021)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01752 [PROTO_GATE|] `#define STATUS_FWP_ZERO_LENGTH_ARRAY cpu_to_le32(0xC0220022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01753 [PROTO_GATE|] `#define STATUS_FWP_NULL_DISPLAY_NAME cpu_to_le32(0xC0220023)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01754 [PROTO_GATE|] `#define STATUS_FWP_INVALID_ACTION_TYPE cpu_to_le32(0xC0220024)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01755 [PROTO_GATE|] `#define STATUS_FWP_INVALID_WEIGHT cpu_to_le32(0xC0220025)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01756 [PROTO_GATE|] `#define STATUS_FWP_MATCH_TYPE_MISMATCH cpu_to_le32(0xC0220026)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01757 [PROTO_GATE|] `#define STATUS_FWP_TYPE_MISMATCH cpu_to_le32(0xC0220027)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01758 [PROTO_GATE|] `#define STATUS_FWP_OUT_OF_BOUNDS cpu_to_le32(0xC0220028)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01759 [PROTO_GATE|] `#define STATUS_FWP_RESERVED cpu_to_le32(0xC0220029)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01760 [PROTO_GATE|] `#define STATUS_FWP_DUPLICATE_CONDITION cpu_to_le32(0xC022002A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01761 [PROTO_GATE|] `#define STATUS_FWP_DUPLICATE_KEYMOD cpu_to_le32(0xC022002B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01762 [PROTO_GATE|] `#define STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER cpu_to_le32(0xC022002C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01763 [PROTO_GATE|] `#define STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER cpu_to_le32(0xC022002D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01764 [PROTO_GATE|] `#define STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER cpu_to_le32(0xC022002E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01765 [PROTO_GATE|] `#define STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT cpu_to_le32(0xC022002F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01766 [PROTO_GATE|] `#define STATUS_FWP_INCOMPATIBLE_AUTH_METHOD cpu_to_le32(0xC0220030)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01767 [PROTO_GATE|] `#define STATUS_FWP_INCOMPATIBLE_DH_GROUP cpu_to_le32(0xC0220031)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01768 [PROTO_GATE|] `#define STATUS_FWP_EM_NOT_SUPPORTED cpu_to_le32(0xC0220032)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01769 [PROTO_GATE|] `#define STATUS_FWP_NEVER_MATCH cpu_to_le32(0xC0220033)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01770 [PROTO_GATE|] `#define STATUS_FWP_PROVIDER_CONTEXT_MISMATCH cpu_to_le32(0xC0220034)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01771 [PROTO_GATE|] `#define STATUS_FWP_INVALID_PARAMETER cpu_to_le32(0xC0220035)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01772 [PROTO_GATE|] `#define STATUS_FWP_TOO_MANY_SUBLAYERS cpu_to_le32(0xC0220036)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01773 [PROTO_GATE|] `#define STATUS_FWP_CALLOUT_NOTIFICATION_FAILED cpu_to_le32(0xC0220037)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01774 [PROTO_GATE|] `#define STATUS_FWP_INCOMPATIBLE_AUTH_CONFIG cpu_to_le32(0xC0220038)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01775 [PROTO_GATE|] `#define STATUS_FWP_INCOMPATIBLE_CIPHER_CONFIG cpu_to_le32(0xC0220039)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01776 [PROTO_GATE|] `#define STATUS_FWP_TCPIP_NOT_READY cpu_to_le32(0xC0220100)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01777 [PROTO_GATE|] `#define STATUS_FWP_INJECT_HANDLE_CLOSING cpu_to_le32(0xC0220101)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01778 [PROTO_GATE|] `#define STATUS_FWP_INJECT_HANDLE_STALE cpu_to_le32(0xC0220102)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01779 [PROTO_GATE|] `#define STATUS_FWP_CANNOT_PEND cpu_to_le32(0xC0220103)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01780 [PROTO_GATE|] `#define STATUS_NDIS_CLOSING cpu_to_le32(0xC0230002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01781 [PROTO_GATE|] `#define STATUS_NDIS_BAD_VERSION cpu_to_le32(0xC0230004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01782 [PROTO_GATE|] `#define STATUS_NDIS_BAD_CHARACTERISTICS cpu_to_le32(0xC0230005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01783 [PROTO_GATE|] `#define STATUS_NDIS_ADAPTER_NOT_FOUND cpu_to_le32(0xC0230006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01784 [PROTO_GATE|] `#define STATUS_NDIS_OPEN_FAILED cpu_to_le32(0xC0230007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01785 [PROTO_GATE|] `#define STATUS_NDIS_DEVICE_FAILED cpu_to_le32(0xC0230008)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01786 [PROTO_GATE|] `#define STATUS_NDIS_MULTICAST_FULL cpu_to_le32(0xC0230009)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01787 [PROTO_GATE|] `#define STATUS_NDIS_MULTICAST_EXISTS cpu_to_le32(0xC023000A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01788 [PROTO_GATE|] `#define STATUS_NDIS_MULTICAST_NOT_FOUND cpu_to_le32(0xC023000B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01789 [PROTO_GATE|] `#define STATUS_NDIS_REQUEST_ABORTED cpu_to_le32(0xC023000C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01790 [PROTO_GATE|] `#define STATUS_NDIS_RESET_IN_PROGRESS cpu_to_le32(0xC023000D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01791 [PROTO_GATE|] `#define STATUS_NDIS_INVALID_PACKET cpu_to_le32(0xC023000F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01792 [PROTO_GATE|] `#define STATUS_NDIS_INVALID_DEVICE_REQUEST cpu_to_le32(0xC0230010)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01793 [PROTO_GATE|] `#define STATUS_NDIS_ADAPTER_NOT_READY cpu_to_le32(0xC0230011)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01794 [PROTO_GATE|] `#define STATUS_NDIS_INVALID_LENGTH cpu_to_le32(0xC0230014)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01795 [PROTO_GATE|] `#define STATUS_NDIS_INVALID_DATA cpu_to_le32(0xC0230015)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01796 [PROTO_GATE|] `#define STATUS_NDIS_BUFFER_TOO_SHORT cpu_to_le32(0xC0230016)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01797 [PROTO_GATE|] `#define STATUS_NDIS_INVALID_OID cpu_to_le32(0xC0230017)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01798 [PROTO_GATE|] `#define STATUS_NDIS_ADAPTER_REMOVED cpu_to_le32(0xC0230018)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01799 [PROTO_GATE|] `#define STATUS_NDIS_UNSUPPORTED_MEDIA cpu_to_le32(0xC0230019)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01800 [PROTO_GATE|] `#define STATUS_NDIS_GROUP_ADDRESS_IN_USE cpu_to_le32(0xC023001A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01801 [PROTO_GATE|] `#define STATUS_NDIS_FILE_NOT_FOUND cpu_to_le32(0xC023001B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01802 [PROTO_GATE|] `#define STATUS_NDIS_ERROR_READING_FILE cpu_to_le32(0xC023001C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01803 [PROTO_GATE|] `#define STATUS_NDIS_ALREADY_MAPPED cpu_to_le32(0xC023001D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01804 [PROTO_GATE|] `#define STATUS_NDIS_RESOURCE_CONFLICT cpu_to_le32(0xC023001E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01805 [PROTO_GATE|] `#define STATUS_NDIS_MEDIA_DISCONNECTED cpu_to_le32(0xC023001F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01806 [PROTO_GATE|] `#define STATUS_NDIS_INVALID_ADDRESS cpu_to_le32(0xC0230022)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01807 [PROTO_GATE|] `#define STATUS_NDIS_PAUSED cpu_to_le32(0xC023002A)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01808 [PROTO_GATE|] `#define STATUS_NDIS_INTERFACE_NOT_FOUND cpu_to_le32(0xC023002B)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01809 [PROTO_GATE|] `#define STATUS_NDIS_UNSUPPORTED_REVISION cpu_to_le32(0xC023002C)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01810 [PROTO_GATE|] `#define STATUS_NDIS_INVALID_PORT cpu_to_le32(0xC023002D)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01811 [PROTO_GATE|] `#define STATUS_NDIS_INVALID_PORT_STATE cpu_to_le32(0xC023002E)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01812 [PROTO_GATE|] `#define STATUS_NDIS_LOW_POWER_STATE cpu_to_le32(0xC023002F)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01813 [PROTO_GATE|] `#define STATUS_NDIS_NOT_SUPPORTED cpu_to_le32(0xC02300BB)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01814 [PROTO_GATE|] `#define STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED cpu_to_le32(0xC0232000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01815 [PROTO_GATE|] `#define STATUS_NDIS_DOT11_MEDIA_IN_USE cpu_to_le32(0xC0232001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01816 [PROTO_GATE|] `#define STATUS_NDIS_DOT11_POWER_STATE_INVALID cpu_to_le32(0xC0232002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01817 [PROTO_GATE|] `#define STATUS_IPSEC_BAD_SPI cpu_to_le32(0xC0360001)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01818 [PROTO_GATE|] `#define STATUS_IPSEC_SA_LIFETIME_EXPIRED cpu_to_le32(0xC0360002)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01819 [PROTO_GATE|] `#define STATUS_IPSEC_WRONG_SA cpu_to_le32(0xC0360003)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01820 [PROTO_GATE|] `#define STATUS_IPSEC_REPLAY_CHECK_FAILED cpu_to_le32(0xC0360004)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01821 [PROTO_GATE|] `#define STATUS_IPSEC_INVALID_PACKET cpu_to_le32(0xC0360005)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01822 [PROTO_GATE|] `#define STATUS_IPSEC_INTEGRITY_CHECK_FAILED cpu_to_le32(0xC0360006)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01823 [PROTO_GATE|] `#define STATUS_IPSEC_CLEAR_TEXT_DROP cpu_to_le32(0xC0360007)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01824 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [PROTO_GATE|] `#define STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP cpu_to_le32(0xC05D0000)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01826 [PROTO_GATE|] `#define STATUS_INVALID_LOCK_RANGE cpu_to_le32(0xC00001a1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
