# Line-by-line Review: src/include/protocol/smb_common.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#ifndef __SMB_COMMON_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __SMB_COMMON_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/unaligned.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <asm/unaligned.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "nterr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * ksmbd-internal error code for share access violations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * Value 50000 is intentionally far above the kernel errno range (< 4096)`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` * to avoid conflicts. This must never be exposed to userspace or returned`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [PROTO_GATE|] ` * as a syscall error — it is translated to NT_STATUS_SHARING_VIOLATION`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00026 [NONE] ` * before being sent on the wire.`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#define ESHARE			50000`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define SMB1_PROT		0`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [PROTO_GATE|] `#define SMB2_PROT		1`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00032 [NONE] `#define SMB21_PROT		2`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `/* multi-protocol negotiate request */`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#define SMB2X_PROT		3`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#define SMB30_PROT		4`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#define SMB302_PROT		5`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#define SMB311_PROT		6`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#define BAD_PROT		0xFFFF`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#define SMB1_VERSION_STRING	"1.0"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#define SMB20_VERSION_STRING	"2.0"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#define SMB21_VERSION_STRING	"2.1"`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#define SMB30_VERSION_STRING	"3.0"`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#define SMB302_VERSION_STRING	"3.02"`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#define SMB311_VERSION_STRING	"3.1.1"`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `/* Dialects */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#define SMB10_PROT_ID		0x00`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#define SMB20_PROT_ID		0x0202`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#define SMB21_PROT_ID		0x0210`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `/* multi-protocol negotiate request */`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#define SMB2X_PROT_ID		0x02FF`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#define SMB30_PROT_ID		0x0300`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#define SMB302_PROT_ID		0x0302`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#define SMB311_PROT_ID		0x0311`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#define BAD_PROT_ID		0xFFFF`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define SMB_ECHO_INTERVAL	(60 * HZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#define CIFS_DEFAULT_IOSIZE	(64 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#define MAX_CIFS_SMALL_BUFFER_SIZE 448 /* big enough for most */`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `#define MAX_STREAM_PROT_LEN	0x00FFFFFF`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#define IS_SMB2(x)		((x)->vals->protocol_id != SMB10_PROT_ID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#define MAX_HEADER_SIZE(conn)		((conn)->vals->max_header_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `/* Responses when opening a file. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `#define F_SUPERSEDED	0`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#define F_OPENED	1`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#define F_CREATED	2`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `#define F_OVERWRITTEN	3`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` * File Attribute flags`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `#define ATTR_READONLY			0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `#define ATTR_HIDDEN			0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `#define ATTR_SYSTEM			0x0004`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `#define ATTR_VOLUME			0x0008`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `#define ATTR_DIRECTORY			0x0010`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `#define ATTR_ARCHIVE			0x0020`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `#define ATTR_DEVICE			0x0040`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `#define ATTR_NORMAL			0x0080`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `#define ATTR_TEMPORARY			0x0100`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `#define ATTR_SPARSE			0x0200`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `#define ATTR_REPARSE			0x0400`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `#define ATTR_COMPRESSED			0x0800`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `#define ATTR_OFFLINE			0x1000`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `#define ATTR_NOT_CONTENT_INDEXED	0x2000`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `#define ATTR_ENCRYPTED			0x4000`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `#define ATTR_POSIX_SEMANTICS		0x01000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `#define ATTR_BACKUP_SEMANTICS		0x02000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `#define ATTR_DELETE_ON_CLOSE		0x04000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `#define ATTR_SEQUENTIAL_SCAN		0x08000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `#define ATTR_RANDOM_ACCESS		0x10000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `#define ATTR_NO_BUFFERING		0x20000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `#define ATTR_WRITE_THROUGH		0x80000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `#ifndef ATTR_READONLY_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `#define ATTR_READONLY_LE		cpu_to_le32(ATTR_READONLY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `#ifndef ATTR_HIDDEN_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `#define ATTR_HIDDEN_LE			cpu_to_le32(ATTR_HIDDEN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `#ifndef ATTR_SYSTEM_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `#define ATTR_SYSTEM_LE			cpu_to_le32(ATTR_SYSTEM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `#ifndef ATTR_DIRECTORY_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `#define ATTR_DIRECTORY_LE		cpu_to_le32(ATTR_DIRECTORY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `#ifndef ATTR_ARCHIVE_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `#define ATTR_ARCHIVE_LE			cpu_to_le32(ATTR_ARCHIVE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `#ifndef ATTR_NORMAL_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `#define ATTR_NORMAL_LE			cpu_to_le32(ATTR_NORMAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `#ifndef ATTR_TEMPORARY_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `#define ATTR_TEMPORARY_LE		cpu_to_le32(ATTR_TEMPORARY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `#ifndef ATTR_SPARSE_FILE_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `#define ATTR_SPARSE_FILE_LE		cpu_to_le32(ATTR_SPARSE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `#ifndef ATTR_REPARSE_POINT_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `#define ATTR_REPARSE_POINT_LE		cpu_to_le32(ATTR_REPARSE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `#ifndef ATTR_COMPRESSED_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `#define ATTR_COMPRESSED_LE		cpu_to_le32(ATTR_COMPRESSED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `#ifndef ATTR_OFFLINE_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `#define ATTR_OFFLINE_LE			cpu_to_le32(ATTR_OFFLINE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `#ifndef ATTR_NOT_CONTENT_INDEXED_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `#define ATTR_NOT_CONTENT_INDEXED_LE	cpu_to_le32(ATTR_NOT_CONTENT_INDEXED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `#ifndef ATTR_ENCRYPTED_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `#define ATTR_ENCRYPTED_LE		cpu_to_le32(ATTR_ENCRYPTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `#ifndef ATTR_INTEGRITY_STREAML_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `#define ATTR_INTEGRITY_STREAML_LE	cpu_to_le32(0x00008000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `#ifndef ATTR_NO_SCRUB_DATA_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `#define ATTR_NO_SCRUB_DATA_LE		cpu_to_le32(0x00020000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `#ifndef ATTR_MASK_LE`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `#define ATTR_MASK_LE			cpu_to_le32(0x00007FB7)`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `/* List of FileSystemAttributes - see 2.5.1 of MS-FSCC */`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `#define FILE_SUPPORTS_SPARSE_VDL	0x10000000 /* faster nonsparse extend */`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `#define FILE_SUPPORTS_BLOCK_REFCOUNTING	0x08000000 /* allow ioctl dup extents */`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `#define FILE_SUPPORT_INTEGRITY_STREAMS	0x04000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `#define FILE_SUPPORTS_USN_JOURNAL	0x02000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `#define FILE_SUPPORTS_OPEN_BY_FILE_ID	0x01000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `#define FILE_SUPPORTS_EXTENDED_ATTRIBUTES 0x00800000`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `#define FILE_SUPPORTS_HARD_LINKS	0x00400000`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `#define FILE_SUPPORTS_TRANSACTIONS	0x00200000`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `#define FILE_SEQUENTIAL_WRITE_ONCE	0x00100000`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `#define FILE_READ_ONLY_VOLUME		0x00080000`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `#define FILE_NAMED_STREAMS		0x00040000`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `#define FILE_SUPPORTS_ENCRYPTION	0x00020000`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `#define FILE_SUPPORTS_OBJECT_IDS	0x00010000`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `#define FILE_VOLUME_IS_COMPRESSED	0x00008000`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `#define FILE_SUPPORTS_REMOTE_STORAGE	0x00000100`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `#define FILE_SUPPORTS_REPARSE_POINTS	0x00000080`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `#define FILE_SUPPORTS_SPARSE_FILES	0x00000040`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `#define FILE_VOLUME_QUOTAS		0x00000020`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `#define FILE_FILE_COMPRESSION		0x00000010`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `#define FILE_PERSISTENT_ACLS		0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `#define FILE_UNICODE_ON_DISK		0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `#define FILE_CASE_PRESERVED_NAMES	0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `#define FILE_CASE_SENSITIVE_SEARCH	0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `#define FILE_READ_DATA        0x00000001  /* Data can be read from the file   */`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `#define FILE_WRITE_DATA       0x00000002  /* Data can be written to the file  */`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `#define FILE_APPEND_DATA      0x00000004  /* Data can be appended to the file */`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `#define FILE_READ_EA          0x00000008  /* Extended attributes associated   */`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `/* with the file can be read        */`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `#define FILE_WRITE_EA         0x00000010  /* Extended attributes associated   */`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `/* with the file can be written     */`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `#define FILE_EXECUTE          0x00000020  /*Data can be read into memory from */`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `/* the file using system paging I/O */`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `#define FILE_DELETE_CHILD     0x00000040`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `#define FILE_READ_ATTRIBUTES  0x00000080  /* Attributes associated with the   */`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `/* file can be read                 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `#define FILE_WRITE_ATTRIBUTES 0x00000100  /* Attributes associated with the   */`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `/* file can be written              */`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `#define DELETE                0x00010000  /* The file can be deleted          */`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `#define READ_CONTROL          0x00020000  /* The access control list and      */`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `/* ownership associated with the    */`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `/* file can be read                 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `#define WRITE_DAC             0x00040000  /* The access control list and      */`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `/* ownership associated with the    */`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `/* file can be written.             */`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `#define WRITE_OWNER           0x00080000  /* Ownership information associated */`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `/* with the file can be written     */`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `#define SYNCHRONIZE           0x00100000  /* The file handle can waited on to */`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `/* synchronize with the completion  */`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `/* of an input/output request       */`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `#define GENERIC_ALL           0x10000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `#define GENERIC_EXECUTE       0x20000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `#define GENERIC_WRITE         0x40000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `#define GENERIC_READ          0x80000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `/* In summary - Relevant file       */`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `/* access flags from CIFS are       */`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `/* file_read_data, file_write_data  */`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `/* file_execute, file_read_attributes*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `/* write_dac, and delete.           */`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `#define FILE_READ_RIGHTS (FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `#define FILE_WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA \`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `		| FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `#define FILE_EXEC_RIGHTS (FILE_EXECUTE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `#define SET_FILE_READ_RIGHTS (FILE_READ_DATA | FILE_READ_EA \`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `		| FILE_READ_ATTRIBUTES \`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `		| DELETE | READ_CONTROL | WRITE_DAC \`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `		| WRITE_OWNER | SYNCHRONIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `#define SET_FILE_WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA \`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `		| FILE_WRITE_EA \`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		| FILE_DELETE_CHILD \`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `		| FILE_WRITE_ATTRIBUTES \`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `		| DELETE | READ_CONTROL | WRITE_DAC \`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		| WRITE_OWNER | SYNCHRONIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `#define SET_FILE_EXEC_RIGHTS (FILE_READ_EA | FILE_WRITE_EA | FILE_EXECUTE \`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `		| FILE_READ_ATTRIBUTES \`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `		| FILE_WRITE_ATTRIBUTES \`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `		| DELETE | READ_CONTROL | WRITE_DAC \`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		| WRITE_OWNER | SYNCHRONIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `#define SET_MINIMUM_RIGHTS (FILE_READ_EA | FILE_READ_ATTRIBUTES \`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		| READ_CONTROL | SYNCHRONIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `/* generic flags for file open */`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `#define GENERIC_READ_FLAGS	(READ_CONTROL | FILE_READ_DATA | \`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `		FILE_READ_ATTRIBUTES | \`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `		FILE_READ_EA | SYNCHRONIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `#define GENERIC_WRITE_FLAGS	(READ_CONTROL | FILE_WRITE_DATA | \`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | \`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		FILE_APPEND_DATA | SYNCHRONIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `#define GENERIC_EXECUTE_FLAGS	(READ_CONTROL | FILE_EXECUTE | \`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `		FILE_READ_ATTRIBUTES | SYNCHRONIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `#define GENERIC_ALL_FLAGS	(DELETE | READ_CONTROL | WRITE_DAC | \`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `		WRITE_OWNER | SYNCHRONIZE | FILE_READ_DATA | \`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `		FILE_WRITE_DATA | FILE_APPEND_DATA | \`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `		FILE_READ_EA | FILE_WRITE_EA | \`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `		FILE_EXECUTE | FILE_DELETE_CHILD | \`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `		FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `/* DeviceType Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `#define FILE_DEVICE_CD_ROM              0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `#define FILE_DEVICE_DFS                 0x00000006`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `#define FILE_DEVICE_DISK                0x00000007`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `#define FILE_DEVICE_FILE_SYSTEM         0x00000009`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `#define FILE_DEVICE_NAMED_PIPE          0x00000011`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `#define FILE_DEVICE_NETWORK             0x00000012`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `#define FILE_DEVICE_NULL                0x00000015`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `#define FILE_DEVICE_PARALLEL_PORT       0x00000016`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `#define FILE_DEVICE_PRINTER             0x00000018`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `#define FILE_DEVICE_SERIAL_PORT         0x0000001b`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `#define FILE_DEVICE_STREAMS             0x0000001e`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `#define FILE_DEVICE_TAPE                0x0000001f`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `#define FILE_DEVICE_VIRTUAL_DISK        0x00000024`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `/* Device Characteristics */`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `#define FILE_REMOVABLE_MEDIA			0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `#define FILE_READ_ONLY_DEVICE			0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `#define FILE_FLOPPY_DISKETTE			0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `#define FILE_WRITE_ONCE_MEDIA			0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `#define FILE_REMOTE_DEVICE			0x00000010`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `#define FILE_DEVICE_IS_MOUNTED			0x00000020`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `#define FILE_VIRTUAL_VOLUME			0x00000040`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `#define FILE_DEVICE_SECURE_OPEN			0x00000100`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `#define FILE_CHARACTERISTIC_TS_DEVICE		0x00001000`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `#define FILE_CHARACTERISTIC_WEBDAV_DEVICE	0x00002000`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `#define FILE_PORTABLE_DEVICE			0x00004000`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `#define FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL 0x00020000`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `#define SMB1_PROTO_NUMBER		cpu_to_le32(0x424d53ff)`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [PROTO_GATE|] `#define SMB_COM_NEGOTIATE		0x72`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00289 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `#define SMB1_CLIENT_GUID_SIZE		(16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `struct smb_hdr {`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	__be32 smb_buf_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	__u8 Protocol[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	__u8 Command;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	union {`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `		struct {`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `			__u8 ErrorClass;`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `			__u8 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `			__le16 Error;`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `		} __packed DosError;`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `		__le32 CifsError;`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	} __packed Status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	__u8 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	__le16 Flags2;          /* note: le */`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	__le16 PidHigh;`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	union {`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `		struct {`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `			__le32 SequenceNumber;  /* le */`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `			__u32 Reserved; /* zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `		} __packed Sequence;`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `		__u8 SecuritySignature[8];      /* le */`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	} __packed Signature;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	__u8 pad[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	__le16 Tid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	__le16 Pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	__le16 Uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	__le16 Mid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	__u8 WordCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `struct smb_negotiate_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	struct smb_hdr hdr;     /* wct = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	unsigned char DialectsArray[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `struct smb_negotiate_unsupported_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	struct smb_hdr hdr;     /* wct = 17 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	__le16 DialectIndex; /* 0xFFFF = no dialect acceptable */`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	__le16 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `struct filesystem_attribute_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	__le32 Attributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `	__le32 MaxPathNameComponentLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `	__le32 FileSystemNameLen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `	__le16 FileSystemName[]; /* do not have to save this - get subset? */`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `struct filesystem_device_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `	__le32 DeviceType;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	__le32 DeviceCharacteristics;`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `} __packed; /* device info level 0x104 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `struct filesystem_vol_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `	__le64 VolumeCreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	__le32 SerialNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	__le32 VolumeLabelSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	__le16 VolumeLabel[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `struct filesystem_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	__le64 TotalAllocationUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	__le64 FreeAllocationUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	__le32 SectorsPerAllocationUnit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	__le32 BytesPerSector;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `} __packed;     /* size info, level 0x103 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `struct filesystem_full_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	__le64 TotalAllocationUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	__le64 FreeAllocationUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	__le64 ActualAvailableUnits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	__le32 SectorsPerAllocationUnit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	__le32 BytesPerSector;`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `} __packed;     /* size info, level 0x3ef */`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `#define EXTENDED_INFO_MAGIC 0x43667364	/* Cfsd */`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `#define STRING_LENGTH 28`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `struct fs_extended_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	__le32 magic;`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	__le32 version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	__le32 release;`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	__le64 rel_date;`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `	char    version_string[STRING_LENGTH];`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `struct object_id_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	char objid[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	struct fs_extended_info extended_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `struct file_directory_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `} __packed;   /* level 0x101 FF resp data */`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `struct file_names_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `} __packed;   /* level 0xc FF resp data */`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `struct file_full_directory_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	__le32 EaSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `} __packed; /* level 0x102 FF resp */`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `struct file_both_directory_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	__le32 EaSize; /* length of the xattrs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	__u8   ShortNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `	__u8   ShortName[24];`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `} __packed; /* level 0x104 FFrsp data */`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `struct file_id_both_directory_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	__le32 EaSize; /* length of the xattrs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `	__u8   ShortNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	__u8   ShortName[24];`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	__le16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	__le64 UniqueId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `struct file_id_full_dir_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	__le32 EaSize; /* EA size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	__le64 UniqueId; /* inode num - le since Samba puts ino in low 32 bit*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `} __packed; /* level 0x105 FF rsp data */`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `struct file_id_extd_dir_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	__le32 EaSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	__le32 ReparsePointTag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	__u8   FileId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `struct file_id_extd_both_dir_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	__le32 EaSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	__le32 ReparsePointTag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	__u8   FileId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	__u8   ShortNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	__u8   ShortName[24];`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `struct file_id_64_extd_dir_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	__le32 EaSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	__le32 ReparsePointTag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	__le64 FileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `struct file_id_64_extd_both_dir_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	__le32 EaSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	__le32 ReparsePointTag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	__le64 FileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	__u8   ShortNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	__u8   ShortName[24];`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `struct file_id_all_extd_dir_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	__le32 EaSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `	__le32 ReparsePointTag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `	__le64 FileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `	__u8   FileId128[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `struct file_id_all_extd_both_dir_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	__u32 FileIndex;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `	__le32 ExtFileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	__le32 EaSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `	__le32 ReparsePointTag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `	__le64 FileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	__u8   FileId128[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	__u8   ShortNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	__u8   Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `	__u8   ShortName[24];`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `struct smb_version_values {`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `	char		*version_string;`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	__u16		protocol_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	__le16		lock_cmd;`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	__u32		capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	__u32		max_read_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `	__u32		max_write_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `	__u32		max_trans_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `	__u32		max_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `	__u32		large_lock_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	__u32		exclusive_lock_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	__u32		shared_lock_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	__u32		unlock_lock_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	size_t		header_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	size_t		max_header_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `	size_t		read_rsp_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	unsigned int	cap_unix;`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	unsigned int	cap_nt_find;`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `	unsigned int	cap_large_files;`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `	__u16		signing_enabled;`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `	__u16		signing_required;`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `	size_t		create_lease_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `	size_t		create_durable_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `	size_t		create_durable_v2_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `	size_t		create_mxac_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `	size_t		create_disk_id_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `	size_t		create_posix_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `struct filesystem_posix_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `	/* For undefined recommended transfer size return -1 in that field */`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `	__le32 OptimalTransferSize;  /* bsize on some os, iosize on other os */`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `	__le32 BlockSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `	/* The next three fields are in terms of the block size.`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `	 * (above). If block size is unknown, 4096 would be a`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `	 * reasonable block size for a server to report.`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	 * Note that returning the blocks/blocksavail removes need`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `	 * to make a second call (to QFSInfo level 0x103 to get this info.`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `	 * UserBlockAvail is typically less than or equal to BlocksAvail,`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	 * if no distinction is made return the same value in each`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `	__le64 TotalBlocks;`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `	__le64 BlocksAvail;       /* bfree */`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `	__le64 UserBlocksAvail;   /* bavail */`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	/* For undefined Node fields or FSID return -1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	__le64 TotalFileNodes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `	__le64 FreeFileNodes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `	__le64 FileSysIdentifier;   /* fsid */`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	/* NB Namelen comes from FILE_SYSTEM_ATTRIBUTE_INFO call */`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `	/* NB flags can come from FILE_SYSTEM_DEVICE_INFO call   */`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `struct smb_version_ops {`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `	u16 (*get_cmd_val)(struct ksmbd_work *swork);`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `	int (*init_rsp_hdr)(struct ksmbd_work *swork);`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `	void (*set_rsp_status)(struct ksmbd_work *swork, __le32 err);`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `	int (*allocate_rsp_buf)(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `	int (*set_rsp_credits)(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	int (*check_user_session)(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `	int (*get_ksmbd_tcon)(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	bool (*is_sign_req)(struct ksmbd_work *work, unsigned int command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	int (*check_sign_req)(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	void (*set_sign_rsp)(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `	int (*generate_signingkey)(struct ksmbd_session *sess, struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `	int (*generate_encryptionkey)(struct ksmbd_conn *conn, struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `	bool (*is_transform_hdr)(void *buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `	int (*decrypt_req)(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `	int (*encrypt_resp)(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `struct smb_version_cmds {`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	int (*proc)(struct ksmbd_work *swork);`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `int ksmbd_min_protocol(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `int ksmbd_max_protocol(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `int ksmbd_lookup_protocol_idx(char *str);`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `int ksmbd_verify_smb_message(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `bool ksmbd_smb_request(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `int ksmbd_lookup_dialect_by_id(__le16 *cli_dialects, __le16 dialects_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `int ksmbd_init_smb_server(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `bool ksmbd_pdu_size_has_room(unsigned int pdu);`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `struct ksmbd_kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `int ksmbd_populate_dot_dotdot_entries(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `				      int info_level,`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `				      struct ksmbd_file *dir,`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `				      struct ksmbd_dir_info *d_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `				      char *search_pattern,`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `				      int (*fn)(struct ksmbd_conn *,`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `						int,`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `						struct ksmbd_dir_info *,`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `						struct ksmbd_kstat *));`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `int ksmbd_extract_shortname(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `			    const char *longname,`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `			    char *shortname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `int ksmbd_smb_negotiate_common(struct ksmbd_work *work, unsigned int command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `int ksmbd_smb_check_shared_mode(struct file *filp, struct ksmbd_file *curr_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `int __ksmbd_override_fsids(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `			   struct ksmbd_share_config *share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `int ksmbd_override_fsids(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `void ksmbd_revert_fsids(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `unsigned int ksmbd_server_side_copy_max_chunk_count(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `unsigned int ksmbd_server_side_copy_max_chunk_size(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `unsigned int ksmbd_server_side_copy_max_total_size(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `bool is_asterisk(char *p);`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `__le32 smb_map_generic_desired_access(__le32 daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `static inline unsigned int get_rfc1002_len(void *buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `	return get_unaligned_be32(buf) & 0xffffff;`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `static inline void inc_rfc1001_len(void *buf, int count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	unsigned int cur = get_rfc1002_len(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	if (WARN_ON_ONCE((unsigned int)(cur + count) > MAX_STREAM_PROT_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	be32_add_cpu((__be32 *)buf, count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `#endif /* __SMB_COMMON_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
