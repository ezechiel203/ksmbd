# Line-by-line Review: src/include/fs/xattr.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2021 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#ifndef __XATTR_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __XATTR_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` * These are on-disk structures to store additional metadata into xattr to`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` * reproduce windows filesystem semantics. And they are encoded with NDR to`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` * compatible with samba's xattr meta format. The compatibility with samba`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` * is important because it can lose the information(file attribute,`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * creation time, acls) about the existing files when switching between`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` * ksmbd and samba.`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` * Dos attribute flags used for what variable is valid.`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	XATTR_DOSINFO_ATTRIB		= 0x00000001,`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `	XATTR_DOSINFO_EA_SIZE		= 0x00000002,`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	XATTR_DOSINFO_SIZE		= 0x00000004,`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	XATTR_DOSINFO_ALLOC_SIZE	= 0x00000008,`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	XATTR_DOSINFO_CREATE_TIME	= 0x00000010,`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	XATTR_DOSINFO_CHANGE_TIME	= 0x00000020,`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	XATTR_DOSINFO_ITIME		= 0x00000040`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` * Dos attribute structure which is compatible with samba's one.`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` * Storing it into the xattr named "DOSATTRIB" separately from inode`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` * allows ksmbd to faithfully reproduce windows filesystem semantics`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` * on top of a POSIX filesystem.`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `struct xattr_dos_attrib {`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	__u16	version;	/* version 3 or version 4 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	__u32	flags;		/* valid flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	__u32	attr;		/* Dos attribute */`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	__u32	ea_size;	/* EA size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	__u64	size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	__u64	alloc_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	__u64	create_time;	/* File creation time */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	__u64	change_time;	/* File change time */`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	__u64	itime;		/* Invented/Initial time */`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` * Enumeration is used for computing posix acl hash.`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	SMB_ACL_TAG_INVALID = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	SMB_ACL_USER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	SMB_ACL_USER_OBJ,`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	SMB_ACL_GROUP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	SMB_ACL_GROUP_OBJ,`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	SMB_ACL_OTHER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	SMB_ACL_MASK`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#define SMB_ACL_READ			4`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `#define SMB_ACL_WRITE			2`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#define SMB_ACL_EXECUTE			1`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `struct xattr_acl_entry {`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	__u32 type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	__u32 uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	__u32 gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	__u32 perm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * xattr_smb_acl structure is used for computing posix acl hash.`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `struct xattr_smb_acl {`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	__u32 count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	__u32 next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	struct xattr_acl_entry entries[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `/* 64bytes hash in xattr_ntacl is computed with sha256 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `#define XATTR_SD_HASH_TYPE_SHA256	0x1`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `#define XATTR_SD_HASH_SIZE		64`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ` * xattr_ntacl is used for storing ntacl and hashes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ` * Hash is used for checking valid posix acl and ntacl in xattr.`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `struct xattr_ntacl {`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	__u16	version; /* version 4*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	void	*sd_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	__u32	sd_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	__u16	hash_type; /* hash type */`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	__u8	desc[10]; /* posix_acl description */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	__u16	desc_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	__u64	current_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	__u8	hash[XATTR_SD_HASH_SIZE]; /* 64bytes hash for ntacl */`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	__u8	posix_acl_hash[XATTR_SD_HASH_SIZE]; /* 64bytes hash for posix acl */`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `/* DOS ATTRIBUTE XATTR PREFIX */`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `#define DOS_ATTRIBUTE_PREFIX		"DOSATTRIB"`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `#define DOS_ATTRIBUTE_PREFIX_LEN	(sizeof(DOS_ATTRIBUTE_PREFIX) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `#define XATTR_NAME_DOS_ATTRIBUTE	(XATTR_USER_PREFIX DOS_ATTRIBUTE_PREFIX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `#define XATTR_NAME_DOS_ATTRIBUTE_LEN	\`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `		(sizeof(XATTR_USER_PREFIX DOS_ATTRIBUTE_PREFIX) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `/* STREAM XATTR PREFIX */`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `#define STREAM_PREFIX			"DosStream."`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `#define STREAM_PREFIX_LEN		(sizeof(STREAM_PREFIX) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `#define XATTR_NAME_STREAM		(XATTR_USER_PREFIX STREAM_PREFIX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `#define XATTR_NAME_STREAM_LEN		(sizeof(XATTR_NAME_STREAM) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `/* SECURITY DESCRIPTOR(NTACL) XATTR PREFIX */`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `#define SD_PREFIX			"NTACL"`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `#define SD_PREFIX_LEN	(sizeof(SD_PREFIX) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `#define XATTR_NAME_SD	(XATTR_SECURITY_PREFIX SD_PREFIX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `#define XATTR_NAME_SD_LEN	\`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `		(sizeof(XATTR_SECURITY_PREFIX SD_PREFIX) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `/* OBJECT ID XATTR PREFIX - stores 16-byte object identifier per file */`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `#define OBJECT_ID_PREFIX		"ObjectId"`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `#define OBJECT_ID_PREFIX_LEN		(sizeof(OBJECT_ID_PREFIX) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `#define XATTR_NAME_OBJECT_ID		(XATTR_USER_PREFIX OBJECT_ID_PREFIX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `#define XATTR_NAME_OBJECT_ID_LEN	\`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `		(sizeof(XATTR_USER_PREFIX OBJECT_ID_PREFIX) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `/* REPARSE DATA XATTR PREFIX */`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `#define REPARSE_DATA_PREFIX		"ReparseData"`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `#define REPARSE_DATA_PREFIX_LEN		(sizeof(REPARSE_DATA_PREFIX) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `#define XATTR_NAME_REPARSE_DATA		(XATTR_USER_PREFIX REPARSE_DATA_PREFIX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `#define XATTR_NAME_REPARSE_DATA_LEN	\`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `		(sizeof(XATTR_USER_PREFIX REPARSE_DATA_PREFIX) - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `#endif /* __XATTR_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
