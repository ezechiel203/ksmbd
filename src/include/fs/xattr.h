/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 */

#ifndef __XATTR_H__
#define __XATTR_H__

/*
 * These are on-disk structures to store additional metadata into xattr to
 * reproduce windows filesystem semantics. And they are encoded with NDR to
 * compatible with samba's xattr meta format. The compatibility with samba
 * is important because it can lose the information(file attribute,
 * creation time, acls) about the existing files when switching between
 * ksmbd and samba.
 */

/*
 * Dos attribute flags used for what variable is valid.
 */
enum {
	XATTR_DOSINFO_ATTRIB		= 0x00000001,
	XATTR_DOSINFO_EA_SIZE		= 0x00000002,
	XATTR_DOSINFO_SIZE		= 0x00000004,
	XATTR_DOSINFO_ALLOC_SIZE	= 0x00000008,
	XATTR_DOSINFO_CREATE_TIME	= 0x00000010,
	XATTR_DOSINFO_CHANGE_TIME	= 0x00000020,
	XATTR_DOSINFO_ITIME		= 0x00000040
};

/*
 * Dos attribute structure which is compatible with samba's one.
 * Storing it into the xattr named "DOSATTRIB" separately from inode
 * allows ksmbd to faithfully reproduce windows filesystem semantics
 * on top of a POSIX filesystem.
 */
struct xattr_dos_attrib {
	__u16	version;	/* version 3 or version 4 */
	__u32	flags;		/* valid flags */
	__u32	attr;		/* Dos attribute */
	__u32	ea_size;	/* EA size */
	__u64	size;
	__u64	alloc_size;
	__u64	create_time;	/* File creation time */
	__u64	change_time;	/* File change time */
	__u64	itime;		/* Invented/Initial time */
} __packed;

/*
 * Enumeration is used for computing posix acl hash.
 */
enum {
	SMB_ACL_TAG_INVALID = 0,
	SMB_ACL_USER,
	SMB_ACL_USER_OBJ,
	SMB_ACL_GROUP,
	SMB_ACL_GROUP_OBJ,
	SMB_ACL_OTHER,
	SMB_ACL_MASK
};

#define SMB_ACL_READ			4
#define SMB_ACL_WRITE			2
#define SMB_ACL_EXECUTE			1

struct xattr_acl_entry {
	__u32 type;
	__u32 uid;
	__u32 gid;
	__u32 perm;
} __packed;

/*
 * xattr_smb_acl structure is used for computing posix acl hash.
 */
struct xattr_smb_acl {
	__u32 count;
	__u32 next;
	struct xattr_acl_entry entries[];
} __packed;

/* 64bytes hash in xattr_ntacl is computed with sha256 */
#define XATTR_SD_HASH_TYPE_SHA256	0x1
#define XATTR_SD_HASH_SIZE		64

/*
 * xattr_ntacl is used for storing ntacl and hashes.
 * Hash is used for checking valid posix acl and ntacl in xattr.
 */
struct xattr_ntacl {
	__u16	version; /* version 4*/
	void	*sd_buf;
	__u32	sd_size;
	__u16	hash_type; /* hash type */
	__u8	desc[10]; /* posix_acl description */
	__u16	desc_len;
	__u64	current_time;
	__u8	hash[XATTR_SD_HASH_SIZE]; /* 64bytes hash for ntacl */
	__u8	posix_acl_hash[XATTR_SD_HASH_SIZE]; /* 64bytes hash for posix acl */
};

/* DOS ATTRIBUTE XATTR PREFIX */
#define DOS_ATTRIBUTE_PREFIX		"DOSATTRIB"
#define DOS_ATTRIBUTE_PREFIX_LEN	(sizeof(DOS_ATTRIBUTE_PREFIX) - 1)
#define XATTR_NAME_DOS_ATTRIBUTE	(XATTR_USER_PREFIX DOS_ATTRIBUTE_PREFIX)
#define XATTR_NAME_DOS_ATTRIBUTE_LEN	\
		(sizeof(XATTR_USER_PREFIX DOS_ATTRIBUTE_PREFIX) - 1)

/* STREAM XATTR PREFIX */
#define STREAM_PREFIX			"DosStream."
#define STREAM_PREFIX_LEN		(sizeof(STREAM_PREFIX) - 1)
#define XATTR_NAME_STREAM		(XATTR_USER_PREFIX STREAM_PREFIX)
#define XATTR_NAME_STREAM_LEN		(sizeof(XATTR_NAME_STREAM) - 1)

/* SECURITY DESCRIPTOR(NTACL) XATTR PREFIX */
#define SD_PREFIX			"NTACL"
#define SD_PREFIX_LEN	(sizeof(SD_PREFIX) - 1)
#define XATTR_NAME_SD	(XATTR_SECURITY_PREFIX SD_PREFIX)
#define XATTR_NAME_SD_LEN	\
		(sizeof(XATTR_SECURITY_PREFIX SD_PREFIX) - 1)

/* L-02: INTEGRITY LABEL (SACL) XATTR — stores raw SACL bytes for LABEL_SECINFO */
#define SD_LABEL_PREFIX		"ksmbd_label"
#define XATTR_NAME_SD_LABEL	(XATTR_SECURITY_PREFIX SD_LABEL_PREFIX)

/* OBJECT ID XATTR PREFIX - stores 16-byte object identifier per file */
#define OBJECT_ID_PREFIX		"ObjectId"
#define OBJECT_ID_PREFIX_LEN		(sizeof(OBJECT_ID_PREFIX) - 1)
#define XATTR_NAME_OBJECT_ID		(XATTR_USER_PREFIX OBJECT_ID_PREFIX)
#define XATTR_NAME_OBJECT_ID_LEN	\
		(sizeof(XATTR_USER_PREFIX OBJECT_ID_PREFIX) - 1)

/*
 * REPARSE DATA XATTR PREFIX
 *
 * XATTR-01 security hardening: moved from user.* to trusted.* namespace.
 * In the user.* namespace any local user with write access to a file could
 * inject fake junction/symlink reparse data visible to Windows clients.
 * The trusted.* namespace is writable only by root/CAP_SYS_ADMIN, preventing
 * unprivileged tampering.
 *
 * NOTE: This is an incompatible on-disk change.  Existing deployments that
 * stored reparse data under "user.ReparseData" must migrate the xattr to
 * "trusted.ReparseData" (e.g. using getfattr/setfattr).  ksmbd will no
 * longer read or write the old user.* name.
 */
#define REPARSE_DATA_PREFIX		"ReparseData"
#define REPARSE_DATA_PREFIX_LEN		(sizeof(REPARSE_DATA_PREFIX) - 1)
#define XATTR_NAME_REPARSE_DATA		(XATTR_TRUSTED_PREFIX REPARSE_DATA_PREFIX)
#define XATTR_NAME_REPARSE_DATA_LEN	\
		(sizeof(XATTR_TRUSTED_PREFIX REPARSE_DATA_PREFIX) - 1)


#endif /* __XATTR_H__ */
