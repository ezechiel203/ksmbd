# Line-by-line Review: src/include/fs/smbacl.h

- L00001 [NONE] `/* SPDX-License-Identifier: LGPL-2.1+ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (c) International Business Machines  Corp., 2007`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Author(s): Steve French (sfrench@us.ibm.com)`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   Modified by Namjae Jeon (linkinjeon@kernel.org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#ifndef _SMBACL_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#define _SMBACL_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/posix_acl.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/mnt_idmapping.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define NUM_AUTHS (6)	/* number of authority fields */`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define SID_MAX_SUB_AUTHORITIES (15) /* max number of sub authority fields */`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` * ACE types - see MS-DTYP 2.4.4.1`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	ACCESS_ALLOWED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	ACCESS_DENIED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` * Security ID types`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	SIDOWNER = 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	SIDGROUP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	SIDCREATOR_OWNER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	SIDCREATOR_GROUP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	SIDUNIX_USER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	SIDUNIX_GROUP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	SIDNFS_USER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	SIDNFS_GROUP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	SIDNFS_MODE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `/* Revision for ACLs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#define SD_REVISION	1`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `/* Control flags for Security Descriptor */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#define OWNER_DEFAULTED		0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#define GROUP_DEFAULTED		0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#define DACL_PRESENT		0x0004`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#define DACL_DEFAULTED		0x0008`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#define SACL_PRESENT		0x0010`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#define SACL_DEFAULTED		0x0020`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#define DACL_TRUSTED		0x0040`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define SERVER_SECURITY		0x0080`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#define DACL_AUTO_INHERIT_REQ	0x0100`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#define SACL_AUTO_INHERIT_REQ	0x0200`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#define DACL_AUTO_INHERITED	0x0400`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#define SACL_AUTO_INHERITED	0x0800`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `#define DACL_PROTECTED		0x1000`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#define SACL_PROTECTED		0x2000`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#define RM_CONTROL_VALID	0x4000`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#define SELF_RELATIVE		0x8000`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `/* ACE types - see MS-DTYP 2.4.4.1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `#define ACCESS_ALLOWED_ACE_TYPE 0x00`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#define ACCESS_DENIED_ACE_TYPE  0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#define SYSTEM_AUDIT_ACE_TYPE   0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `#define SYSTEM_ALARM_ACE_TYPE   0x03`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `#define ACCESS_ALLOWED_COMPOUND_ACE_TYPE 0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `#define ACCESS_ALLOWED_OBJECT_ACE_TYPE  0x05`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `#define ACCESS_DENIED_OBJECT_ACE_TYPE   0x06`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `#define SYSTEM_AUDIT_OBJECT_ACE_TYPE    0x07`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `#define SYSTEM_ALARM_OBJECT_ACE_TYPE    0x08`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `#define ACCESS_ALLOWED_CALLBACK_ACE_TYPE 0x09`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `#define ACCESS_DENIED_CALLBACK_ACE_TYPE 0x0A`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `#define ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE 0x0B`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `#define ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  0x0C`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `#define SYSTEM_AUDIT_CALLBACK_ACE_TYPE  0x0D`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `#define SYSTEM_ALARM_CALLBACK_ACE_TYPE  0x0E /* Reserved */`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `#define SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE 0x0F`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `#define SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE 0x10 /* reserved */`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `#define SYSTEM_MANDATORY_LABEL_ACE_TYPE 0x11`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `#define SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE 0x12`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `#define SYSTEM_SCOPED_POLICY_ID_ACE_TYPE 0x13`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `/* ACE flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `#define OBJECT_INHERIT_ACE		0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `#define CONTAINER_INHERIT_ACE		0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `#define NO_PROPAGATE_INHERIT_ACE	0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `#define INHERIT_ONLY_ACE		0x08`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `#define INHERITED_ACE			0x10`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `#define SUCCESSFUL_ACCESS_ACE_FLAG	0x40`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `#define FAILED_ACCESS_ACE_FLAG		0x80`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ` * Maximum size of a string representation of a SID:`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ` * The fields are unsigned values in decimal. So:`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` * u8:  max 3 bytes in decimal`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ` * u32: max 10 bytes in decimal`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` * "S-" + 3 bytes for version field + 15 for authority field + NULL terminator`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` * For authority field, max is when all 6 values are non-zero and it must be`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` * represented in hex. So "-0x" + 12 hex digits.`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` * Add 11 bytes for each subauthority field (10 bytes each + 1 for '-')`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `#define SID_STRING_BASE_SIZE (2 + 3 + 15 + 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `#define SID_STRING_SUBAUTH_SIZE (11) /* size of a single subauth string */`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `#define DOMAIN_USER_RID_LE	cpu_to_le32(513)`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` * Domain-aware SID-to-UID mapping constants.`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` * SECURITY: Without domain validation, two different AD domains that`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ` * assign the same RID to different users would silently map to the`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ` * same Linux UID, causing ACL mis-application and quota bypass.`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ` * When a SID's domain prefix does not match the server's configured`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ` * domain SID, we apply a hash-based offset to the RID so that`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ` * different domains produce different UIDs for the same RID.`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ` * The multiplier is chosen to be large enough to separate domains`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ` * while small enough to stay within uid_t range for typical RID values.`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `#define DOMAIN_UID_OFFSET_MULTIPLIER	100000U`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `#define DOMAIN_UID_MAX_OFFSET		(U32_MAX - DOMAIN_UID_OFFSET_MULTIPLIER)`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [PROTO_GATE|] `/* Return value when a SID cannot be mapped (NT_STATUS_NONE_MAPPED) */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00137 [PROTO_GATE|] `#define KSMBD_STATUS_NONE_MAPPED	(-ENOENT)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `struct ksmbd_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `struct smb_ntsd {`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	__le16 revision; /* revision level */`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	__le16 type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	__le32 osidoffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	__le32 gsidoffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	__le32 sacloffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	__le32 dacloffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `struct smb_sid {`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	__u8 revision; /* revision level */`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	__u8 num_subauth;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	__u8 authority[NUM_AUTHS];`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	__le32 sub_auth[SID_MAX_SUB_AUTHORITIES]; /* sub_auth[num_subauth] */`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `/* size of a struct cifs_sid, sans sub_auth array */`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `#define CIFS_SID_BASE_SIZE (1 + 1 + NUM_AUTHS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `struct smb_acl {`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	__le16 revision; /* revision level */`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	__le16 size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	__le16 num_aces;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	__le16 reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `struct smb_ace {`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	__u8 type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	__u8 flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	__le16 size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	__le32 access_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	struct smb_sid sid; /* ie UUID of user or group who gets these perms */`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `struct smb_fattr {`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	kuid_t	cf_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	kgid_t	cf_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	umode_t	cf_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	__le32 daccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	struct posix_acl *cf_acls;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	struct posix_acl *cf_dacls;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `struct posix_ace_state {`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	u32 allow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	u32 deny;`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `struct posix_user_ace_state {`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	union {`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		kuid_t uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `		kgid_t gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	};`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	struct posix_ace_state perms;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `struct posix_ace_state_array {`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	int n;`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	struct posix_user_ace_state aces[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ` * while processing the nfsv4 ace, this maintains the partial permissions`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ` * calculated so far:`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `struct posix_acl_state {`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	struct posix_ace_state owner;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	struct posix_ace_state group;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	struct posix_ace_state other;`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	struct posix_ace_state everyone;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	struct posix_ace_state mask; /* deny unused in this case */`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	struct posix_ace_state_array *users;`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	struct posix_ace_state_array *groups;`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `int parse_sec_desc(struct mnt_idmap *idmap, struct smb_ntsd *pntsd,`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `int parse_sec_desc(struct user_namespace *user_ns, struct smb_ntsd *pntsd,`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `		   int acl_len, struct smb_fattr *fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `int build_sec_desc(struct mnt_idmap *idmap, struct smb_ntsd *pntsd,`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `int build_sec_desc(struct user_namespace *user_ns, struct smb_ntsd *pntsd,`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `		   struct smb_ntsd *ppntsd, int ppntsd_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		   int addition_info, __u32 *secdesclen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `		   struct smb_fattr *fattr, unsigned int buf_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `int init_acl_state(struct posix_acl_state *state, u16 cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `void free_acl_state(struct posix_acl_state *state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `void posix_state_to_acl(struct posix_acl_state *state,`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `			struct posix_acl_entry *pace);`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `int compare_sids(const struct smb_sid *ctsid, const struct smb_sid *cwsid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `bool smb_inherit_flags(int flags, bool is_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `int smb_inherit_dacl(struct ksmbd_conn *conn, const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		     unsigned int uid, unsigned int gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `int smb_check_perm_dacl(struct ksmbd_conn *conn, const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `			__le32 *pdaccess, int uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `int set_info_sec(struct ksmbd_conn *conn, struct ksmbd_tree_connect *tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `		 const struct path *path, struct smb_ntsd *pntsd, int ntsd_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `		 bool type_check, bool get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `void id_to_sid(unsigned int cid, uint sidtype, struct smb_sid *ssid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `void ksmbd_init_domain(u32 *sub_auth);`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `int ksmbd_validate_sid_to_uid(struct smb_sid *psid, uid_t *uid_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `bool ksmbd_sid_domain_match(const struct smb_sid *sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `u32 ksmbd_domain_sid_hash(const struct smb_sid *sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `int ksmbd_extract_domain_prefix(const struct smb_sid *sid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `				struct smb_sid *domain_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `static inline uid_t posix_acl_uid_translate(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `static inline uid_t posix_acl_uid_translate(struct user_namespace *mnt_userns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `					    struct posix_acl_entry *pace)`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	vfsuid_t vfsuid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	kuid_t kuid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	/* If this is an idmapped mount, apply the idmapping. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) || \`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 52) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0))`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	vfsuid = make_vfsuid(idmap, &init_user_ns, pace->e_uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `	vfsuid = make_vfsuid(mnt_userns, &init_user_ns, pace->e_uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	kuid = mapped_kuid_fs(mnt_userns, &init_user_ns, pace->e_uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	kuid = kuid_into_mnt(mnt_userns, pace->e_uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	/* Translate the kuid into a userspace id ksmbd would see. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	return from_kuid(&init_user_ns, vfsuid_into_kuid(vfsuid));`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	return from_kuid(&init_user_ns, kuid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	return from_kuid(&init_user_ns, pace->e_uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `static inline gid_t posix_acl_gid_translate(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `static inline gid_t posix_acl_gid_translate(struct user_namespace *mnt_userns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `					    struct posix_acl_entry *pace)`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	vfsgid_t vfsgid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	kgid_t kgid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `	/* If this is an idmapped mount, apply the idmapping. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) || \`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 52) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0))`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	vfsgid = make_vfsgid(idmap, &init_user_ns, pace->e_gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	vfsgid = make_vfsgid(mnt_userns, &init_user_ns, pace->e_gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	kgid = mapped_kgid_fs(mnt_userns, &init_user_ns, pace->e_gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	kgid = kgid_into_mnt(mnt_userns, pace->e_gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	/* Translate the kgid into a userspace id ksmbd would see. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	return from_kgid(&init_user_ns, vfsgid_into_kgid(vfsgid));`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `	return from_kgid(&init_user_ns, kgid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	return from_kgid(&init_user_ns, pace->e_gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `void smb_copy_sid(struct smb_sid *dst, const struct smb_sid *src);`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `umode_t access_flags_to_mode(struct smb_fattr *fattr, __le32 ace_flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `			     int type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `void mode_to_access_flags(umode_t mode, umode_t bits_to_use,`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `			  __u32 *pace_flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `__u16 fill_ace_for_sid(struct smb_ace *pntace, const struct smb_sid *psid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `		       int type, int flags, umode_t mode, umode_t bits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `void parse_dacl(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `void parse_dacl(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `		struct smb_acl *pdacl, char *end_of_acl,`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `		struct smb_sid *pownersid, struct smb_sid *pgrpsid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		struct smb_fattr *fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `int parse_sid(struct smb_sid *psid, char *end_of_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `void smb_set_ace(struct smb_ace *ace, const struct smb_sid *sid, u8 type,`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `		 u8 flags, __le32 access_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `int ksmbd_sid_to_id_domain_aware(struct smb_sid *psid, uid_t *id_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `#endif /* CONFIG_KUNIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `#endif /* _SMBACL_H */`
  Review: Low-risk line; verify in surrounding control flow.
