# Line-by-line Review: src/include/protocol/smbfsctl.h

- L00001 [NONE] `/* SPDX-License-Identifier: LGPL-2.1+ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   fs/cifs/smbfsctl.h: SMB, CIFS, SMB2 FSCTL definitions`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   Copyright (c) International Business Machines  Corp., 2002,2009`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Author(s): Steve French (sfrench@us.ibm.com)`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `/* IOCTL information */`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` * List of ioctl/fsctl function codes that are or could be useful in the`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` * future to remote clients like cifs or SMB2 client.  There is probably`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` * a slightly larger set of fsctls that NTFS local filesystem could handle,`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * including the seven below that we do not have struct definitions for.`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` * Even with protocol definitions for most of these now available, we still`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` * need to do some experimentation to identify which are practical to do`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` * remotely.  Some of the following, such as the encryption/compression ones`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * could be invoked from tools via a specialized hook into the VFS rather`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` * than via the standard vfs entry points`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#ifndef __KSMBD_SMBFSCTL_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#define __KSMBD_SMBFSCTL_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#define FSCTL_DFS_GET_REFERRALS      0x00060194`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#define FSCTL_DFS_GET_REFERRALS_EX   0x000601B0`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define FSCTL_REQUEST_OPLOCK_LEVEL_1 0x00090000`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#define FSCTL_REQUEST_OPLOCK_LEVEL_2 0x00090004`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#define FSCTL_REQUEST_BATCH_OPLOCK   0x00090008`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define FSCTL_LOCK_VOLUME            0x00090018`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define FSCTL_UNLOCK_VOLUME          0x0009001C`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#define FSCTL_IS_PATHNAME_VALID      0x0009002C /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#define FSCTL_GET_COMPRESSION        0x0009003C /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#define FSCTL_SET_COMPRESSION        0x0009C040 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#define FSCTL_QUERY_FAT_BPB          0x00090058 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `/* Verify the next FSCTL number, we had it as 0x00090090 before */`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#define FSCTL_FILESYSTEM_GET_STATS   0x00090060 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#define FSCTL_GET_NTFS_VOLUME_DATA   0x00090064 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define FSCTL_GET_RETRIEVAL_POINTERS 0x00090073 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#define FSCTL_IS_VOLUME_DIRTY        0x00090078 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#define FSCTL_ALLOW_EXTENDED_DASD_IO 0x00090083 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#define FSCTL_REQUEST_FILTER_OPLOCK  0x0009008C`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#define FSCTL_FIND_FILES_BY_SID      0x0009008F /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#define FSCTL_SET_OBJECT_ID          0x00090098 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#define FSCTL_GET_OBJECT_ID          0x0009009C /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#define FSCTL_DELETE_OBJECT_ID       0x000900A0 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#define FSCTL_SET_REPARSE_POINT      0x000900A4 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#define FSCTL_GET_REPARSE_POINT      0x000900A8 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#define FSCTL_DELETE_REPARSE_POINT   0x000900AC /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#define FSCTL_SET_OBJECT_ID_EXTENDED 0x000900BC /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#define FSCTL_CREATE_OR_GET_OBJECT_ID 0x000900C0 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#define FSCTL_SET_SPARSE             0x000900C4 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#define FSCTL_SET_ZERO_DATA          0x000980C8 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#define FSCTL_SET_ENCRYPTION         0x000900D7 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#define FSCTL_ENCRYPTION_FSCTL_IO    0x000900DB /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#define FSCTL_WRITE_RAW_ENCRYPTED    0x000900DF /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#define FSCTL_READ_RAW_ENCRYPTED     0x000900E3 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define FSCTL_READ_FILE_USN_DATA     0x000900EB /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#define FSCTL_WRITE_USN_CLOSE_RECORD 0x000900EF /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#define FSCTL_SIS_COPYFILE           0x00090100 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#define FSCTL_RECALL_FILE            0x00090117 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#define FSCTL_QUERY_SPARING_INFO     0x00090138 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `#define FSCTL_SET_ZERO_ON_DEALLOC    0x00090194 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#define FSCTL_SET_SHORT_NAME_BEHAVIOR 0x000901B4 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#define FSCTL_QUERY_ALLOCATED_RANGES 0x000940CF /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#define FSCTL_FILE_LEVEL_TRIM        0x00098208`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `#define FSCTL_SET_DEFECT_MANAGEMENT  0x00098134 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `#define FSCTL_DUPLICATE_EXTENTS_TO_FILE 0x00098344`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `#define FSCTL_SIS_LINK_FILES         0x0009C104`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#define FSCTL_PIPE_PEEK              0x0011400C /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#define FSCTL_PIPE_TRANSCEIVE        0x0011C017 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `/* strange that the number for this op is not sequential with previous op */`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `#define FSCTL_PIPE_WAIT              0x00110018 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `#define FSCTL_REQUEST_RESUME_KEY     0x00140078`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `#define FSCTL_LMR_GET_LINK_TRACK_INF 0x001400E8 /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `#define FSCTL_LMR_SET_LINK_TRACK_INF 0x001400EC /* BB add struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `#define FSCTL_VALIDATE_NEGOTIATE_INFO 0x00140204`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `#define FSCTL_QUERY_NETWORK_INTERFACE_INFO 0x001400FC`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `#define FSCTL_SRV_ENUMERATE_SNAPSHOTS 0x00144064`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `#define FSCTL_COPYCHUNK              0x001440F2`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `#define FSCTL_LMR_REQUEST_RESILIENCY 0x001401D4`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `#define FSCTL_COPYCHUNK_WRITE        0x001480F2`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `/* Phase 1: Missing FSCTL codes from MS-FSCC / MS-SMB2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `#define FSCTL_GET_INTEGRITY_INFORMATION    0x0009027C`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `#define FSCTL_SET_INTEGRITY_INFORMATION    0x0009C280`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `#define FSCTL_QUERY_FILE_REGIONS           0x00090284`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `#define FSCTL_OFFLOAD_READ                 0x00094264`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `#define FSCTL_OFFLOAD_WRITE               0x00098268`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `#define FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX 0x000983E8`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `#define FSCTL_SRV_READ_HASH               0x001441BB`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `#define FSCTL_SET_INTEGRITY_INFORMATION_EX 0x00090380`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `#define FSCTL_MARK_HANDLE                  0x000900FC`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `/* Phase 7: MS-RSVD (Remote Shared Virtual Disk) FSCTL codes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `#define FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT 0x00090300`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `#define FSCTL_SVHDX_SYNC_TUNNEL_REQUEST         0x00090304`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `#define FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST        0x00090364`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `#define FSCTL_QUERY_ON_DISK_VOLUME_INFO         0x009013C0`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `#define IO_REPARSE_TAG_MOUNT_POINT   0xA0000003`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `#define IO_REPARSE_TAG_HSM           0xC0000004`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `#define IO_REPARSE_TAG_SIS           0x80000007`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `#define IO_REPARSE_TAG_SYMLINK       0xA000000C`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `/* WSL reparse tags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `#define IO_REPARSE_TAG_LX_SYMLINK_LE	cpu_to_le32(0xA000001D)`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `#define IO_REPARSE_TAG_AF_UNIX_LE	cpu_to_le32(0x80000023)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `#define IO_REPARSE_TAG_LX_FIFO_LE	cpu_to_le32(0x80000024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `#define IO_REPARSE_TAG_LX_CHR_LE	cpu_to_le32(0x80000025)`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `#define IO_REPARSE_TAG_LX_BLK_LE	cpu_to_le32(0x80000026)`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `#endif /* __KSMBD_SMBFSCTL_H */`
  Review: Low-risk line; verify in surrounding control flow.
