# Line-by-line Review: src/fs/smbacl.c

- L00001 [NONE] `// SPDX-License-Identifier: LGPL-2.1+`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) International Business Machines  Corp., 2007,2008`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Author(s): Steve French (sfrench@us.ibm.com)`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   Copyright (C) 2020 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Author(s): Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/overflow.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/mnt_idmapping.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#define VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `static const struct smb_sid domain = {1, 4, {0, 0, 0, 0, 0, 5},`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	{cpu_to_le32(21), cpu_to_le32(1), cpu_to_le32(2), cpu_to_le32(3),`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `/* security id for everyone/world system group */`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `static const struct smb_sid creator_owner = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	1, 1, {0, 0, 0, 0, 0, 3}, {0} };`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `/* security id for everyone/world system group */`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `static const struct smb_sid creator_group = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	1, 1, {0, 0, 0, 0, 0, 3}, {cpu_to_le32(1)} };`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `/* security id for everyone/world system group */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `static const struct smb_sid sid_everyone = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	1, 1, {0, 0, 0, 0, 0, 1}, {0} };`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `/* security id for Authenticated Users system group */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `static const struct smb_sid sid_authusers = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	1, 1, {0, 0, 0, 0, 0, 5}, {cpu_to_le32(11)} };`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `/* S-1-22-1 Unmapped Unix users */`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `static const struct smb_sid sid_unix_users = {1, 1, {0, 0, 0, 0, 0, 22},`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `		{cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `/* S-1-22-2 Unmapped Unix groups */`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `static const struct smb_sid sid_unix_groups = { 1, 1, {0, 0, 0, 0, 0, 22},`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `		{cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` * See http://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `/* S-1-5-88 MS NFS and Fruit style UID/GID/mode */`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `/* S-1-5-88-1 Unix uid */`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `static const struct smb_sid sid_unix_NFS_users = { 1, 2, {0, 0, 0, 0, 0, 5},`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	{cpu_to_le32(88),`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	 cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `/* S-1-5-88-2 Unix gid */`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `static const struct smb_sid sid_unix_NFS_groups = { 1, 2, {0, 0, 0, 0, 0, 5},`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	{cpu_to_le32(88),`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	 cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `/* S-1-5-88-3 Unix mode */`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `static const struct smb_sid sid_unix_NFS_mode = { 1, 2, {0, 0, 0, 0, 0, 5},`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	{cpu_to_le32(88),`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	 cpu_to_le32(3), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` * if the two SIDs (roughly equivalent to a UUID for a user or group) are`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` * the same returns zero, if they do not match returns non-zero.`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `int compare_sids(const struct smb_sid *ctsid, const struct smb_sid *cwsid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	int num_subauth, num_subauth_w;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	if (!ctsid || !cwsid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	/* compare the revision */`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	if (ctsid->revision != cwsid->revision)`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	/* compare the num_subauth */`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	num_subauth = ctsid->num_subauth;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	num_subauth_w = cwsid->num_subauth;`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	if (num_subauth != num_subauth_w)`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	/* compare all of the six auth_id bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	for (i = 0; i < NUM_AUTHS; ++i) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `		if (ctsid->authority[i] != cwsid->authority[i])`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `			return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	for (i = 0; i < num_subauth; ++i) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `		if (ctsid->sub_auth[i] != cwsid->sub_auth[i])`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `			return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	return 0; /* sids compare/match */`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `void smb_copy_sid(struct smb_sid *dst, const struct smb_sid *src)`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	dst->revision = src->revision;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	dst->num_subauth = min_t(u8, src->num_subauth, SID_MAX_SUB_AUTHORITIES);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	for (i = 0; i < NUM_AUTHS; ++i)`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `		dst->authority[i] = src->authority[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	for (i = 0; i < dst->num_subauth; ++i)`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `		dst->sub_auth[i] = src->sub_auth[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb_copy_sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ` * change posix mode to reflect permissions`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` * pmode is the existing mode (we only want to overwrite part of this`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ` * bits to set can be: S_IRWXU, S_IRWXG or S_IRWXO ie 00700 or 00070 or 00007`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `umode_t access_flags_to_mode(struct smb_fattr *fattr, __le32 ace_flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `				    int type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	__u32 flags = le32_to_cpu(ace_flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	umode_t mode = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	if (flags & GENERIC_ALL) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		mode = 0777;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `		ksmbd_debug(SMB, "all perms\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `		return mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	if ((flags & GENERIC_READ) || (flags & FILE_READ_RIGHTS))`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `		mode = 0444;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	if ((flags & GENERIC_WRITE) || (flags & FILE_WRITE_RIGHTS)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `		mode |= 0222;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `		if (S_ISDIR(fattr->cf_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `			mode |= 0111;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	if ((flags & GENERIC_EXECUTE) || (flags & FILE_EXEC_RIGHTS))`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `		mode |= 0111;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	if (type == ACCESS_DENIED_ACE_TYPE || type == ACCESS_DENIED_OBJECT_ACE_TYPE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `		mode = ~mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	ksmbd_debug(SMB, "access flags 0x%x mode now %04o\n", flags, mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	return mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `EXPORT_SYMBOL_IF_KUNIT(access_flags_to_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` * Generate access flags to reflect permissions mode is the existing mode.`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ` * This function is called for every ACE in the DACL whose SID matches`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ` * with either owner or group or everyone.`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `void mode_to_access_flags(umode_t mode, umode_t bits_to_use,`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `				 __u32 *pace_flags)`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	/* reset access mask */`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	*pace_flags = 0x0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	/* bits to use are either S_IRWXU or S_IRWXG or S_IRWXO */`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	mode &= bits_to_use;`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	 * check for R/W/X UGO since we do not know whose flags`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	 * is this but we have cleared all the bits sans RWX for`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	 * either user or group or other as per bits_to_use`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	if (mode & 0444)`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `		*pace_flags |= SET_FILE_READ_RIGHTS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	if (mode & 0222)`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `		*pace_flags |= FILE_WRITE_RIGHTS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	if (mode & 0111)`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `		*pace_flags |= SET_FILE_EXEC_RIGHTS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	ksmbd_debug(SMB, "mode: %o, access flags now 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `		    mode, *pace_flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `EXPORT_SYMBOL_IF_KUNIT(mode_to_access_flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ` * ksmbd_ace_size() - calculate ACE size for a given SID`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` * @psid:	pointer to the SID`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ` * Return:	size of the ACE in bytes, or 0 on overflow`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `static __u16 ksmbd_ace_size(const struct smb_sid *psid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	unsigned int size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [MEM_BOUNDS|] `	if (check_add_overflow(1u + 1u + 2u + 4u + 1u + 1u + 6u,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00207 [NONE] `			       (unsigned int)psid->num_subauth * 4u,`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `			       &size))`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	if (size > U16_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	return (__u16)size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `__u16 fill_ace_for_sid(struct smb_ace *pntace,`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `			      const struct smb_sid *psid, int type,`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `			      int flags, umode_t mode, umode_t bits)`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	__u16 size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	__u32 access_req = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	size = ksmbd_ace_size(psid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	if (!size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	pntace->type = type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	pntace->flags = flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	mode_to_access_flags(mode, bits, &access_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	if (!access_req)`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		access_req = SET_MINIMUM_RIGHTS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	pntace->access_req = cpu_to_le32(access_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	pntace->sid.revision = psid->revision;`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	pntace->sid.num_subauth = psid->num_subauth;`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	for (i = 0; i < NUM_AUTHS; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		pntace->sid.authority[i] = psid->authority[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	for (i = 0; i < psid->num_subauth; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		pntace->sid.sub_auth[i] = psid->sub_auth[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	pntace->size = cpu_to_le16(size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	return size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `EXPORT_SYMBOL_IF_KUNIT(fill_ace_for_sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `void id_to_sid(unsigned int cid, uint sidtype, struct smb_sid *ssid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	switch (sidtype) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	case SIDOWNER:`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `		smb_copy_sid(ssid, &server_conf.domain_sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	case SIDUNIX_USER:`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `		smb_copy_sid(ssid, &sid_unix_users);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	case SIDUNIX_GROUP:`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `		smb_copy_sid(ssid, &sid_unix_groups);`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	case SIDCREATOR_OWNER:`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `		smb_copy_sid(ssid, &creator_owner);`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	case SIDCREATOR_GROUP:`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		smb_copy_sid(ssid, &creator_group);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	case SIDNFS_USER:`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		smb_copy_sid(ssid, &sid_unix_NFS_users);`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	case SIDNFS_GROUP:`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `		smb_copy_sid(ssid, &sid_unix_NFS_groups);`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	case SIDNFS_MODE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `		smb_copy_sid(ssid, &sid_unix_NFS_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	/* RID */`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `	if (ssid->num_subauth < SID_MAX_SUB_AUTHORITIES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `		ssid->sub_auth[ssid->num_subauth] = cpu_to_le32(cid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `		ssid->num_subauth++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] ` * Domain-aware SID-to-UID mapping helpers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] ` * SECURITY FIX: Previously, sid_to_id() extracted only the last`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] ` * sub-authority (RID) from a Windows SID and used it directly as the`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ` * Linux UID.  This meant that DOMAIN1\alice (S-1-5-21-X-Y-Z-500) and`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ` * DOMAIN2\alice (S-1-5-21-A-B-C-500) would both map to UID 500,`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] ` * causing incorrect ACL application and quota bypass in multi-domain`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] ` * Active Directory environments.`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] ` * The fix adds domain SID validation:`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ` *   - Well-known SIDs (S-1-22-*, S-1-5-88-*) pass through unchanged.`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ` *   - SIDs whose domain prefix matches server_conf.domain_sid use the`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] ` *     RID directly (preserving backward compatibility).`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ` *   - SIDs from foreign domains get a hash-based offset applied to`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] ` *     their RID to prevent UID collisions across domains.`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ` *   - Bounds checking rejects RIDs that would overflow uid_t after`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ` *     the offset is applied.`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] ` * ksmbd_extract_domain_prefix() - extract the domain portion of a SID`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] ` * @sid:        input SID (must have num_subauth >= 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] ` * @domain_out: output SID containing all sub-authorities except the last (RID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] ` * For a SID like S-1-5-21-A-B-C-500, this extracts S-1-5-21-A-B-C`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] ` * (everything except the final RID sub-authority).`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] ` * Return: 0 on success, -EINVAL on invalid input`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `int ksmbd_extract_domain_prefix(const struct smb_sid *sid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `				struct smb_sid *domain_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `	if (!sid || !domain_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	if (sid->num_subauth == 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	    sid->num_subauth > SID_MAX_SUB_AUTHORITIES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	domain_out->revision = sid->revision;`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	domain_out->num_subauth = sid->num_subauth - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	for (i = 0; i < NUM_AUTHS; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		domain_out->authority[i] = sid->authority[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `	for (i = 0; i < domain_out->num_subauth; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `		domain_out->sub_auth[i] = sid->sub_auth[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_extract_domain_prefix);`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ` * ksmbd_domain_sid_hash() - compute a hash of a SID's domain prefix`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ` * @sid: input SID`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] ` * Hashes the authority and all sub-authorities except the last (which`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] ` * is the RID).  Uses a simple DJB2-style hash for speed and adequate`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] ` * distribution.`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] ` * Return: 32-bit hash value (0 if SID is NULL or has no domain portion)`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `u32 ksmbd_domain_sid_hash(const struct smb_sid *sid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `	u32 hash = 5381;`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	int domain_subauth_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	if (!sid || sid->num_subauth <= 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	domain_subauth_count = sid->num_subauth - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	/* Hash the authority bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	for (i = 0; i < NUM_AUTHS; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `		hash = hash * 33 + sid->authority[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	/* Hash the domain sub-authorities (everything except the RID) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	for (i = 0; i < domain_subauth_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `		u32 sa = le32_to_cpu(sid->sub_auth[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `		hash = hash * 33 + (sa & 0xFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `		hash = hash * 33 + ((sa >> 8) & 0xFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `		hash = hash * 33 + ((sa >> 16) & 0xFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `		hash = hash * 33 + ((sa >> 24) & 0xFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	return hash;`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_domain_sid_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ` * ksmbd_sid_domain_match() - check if a SID belongs to the server's domain`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ` * @sid: the SID to check`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ` * Compares the domain portion of @sid (all sub-authorities except the`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ` * last) against server_conf.domain_sid.  Well-known SIDs from the`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] ` * Unix user/group namespaces (S-1-22-*) and NFS namespaces (S-1-5-88-*)`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ` * are always treated as matching (local).`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ` * Return: true if the SID is from the server's domain or a well-known`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] ` *         local namespace, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `bool ksmbd_sid_domain_match(const struct smb_sid *sid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	const struct smb_sid *dom = &server_conf.domain_sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	int domain_subauth_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	if (!sid || sid->num_subauth == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	 * Well-known local SIDs always match:`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	 * S-1-22-1-* (Unix users), S-1-22-2-* (Unix groups)`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	if (sid->authority[5] == 22 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	    (sid->authority[0] | sid->authority[1] | sid->authority[2] |`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	     sid->authority[3] | sid->authority[4]) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	 * NFS-style SIDs: S-1-5-88-{1,2,3}-*`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	if (sid->authority[5] == 5 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	    (sid->authority[0] | sid->authority[1] | sid->authority[2] |`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	     sid->authority[3] | sid->authority[4]) == 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	    sid->num_subauth >= 2 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	    le32_to_cpu(sid->sub_auth[0]) == 88)`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	 * Compare the domain prefix: the server's domain_sid has`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	 * num_subauth sub-authorities (typically 4 for S-1-5-21-X-Y-Z).`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	 * The incoming SID must have at least one more (the RID).`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `	 * We compare all of the domain_sid's sub-authorities against`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	 * the corresponding leading sub-authorities of the incoming SID.`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	domain_subauth_count = dom->num_subauth;`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	if (sid->num_subauth <= domain_subauth_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	/* Compare revision and authority */`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	if (sid->revision != dom->revision)`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	for (i = 0; i < NUM_AUTHS; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `		if (sid->authority[i] != dom->authority[i])`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	/* Compare domain sub-authorities */`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	for (i = 0; i < domain_subauth_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `		if (sid->sub_auth[i] != dom->sub_auth[i])`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_sid_domain_match);`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] ` * ksmbd_validate_sid_to_uid() - domain-aware SID to UID conversion`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] ` * @psid:    the input SID to convert`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] ` * @uid_out: [out] the resulting UID`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ` * Converts a Windows SID to a Linux UID with domain awareness:`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] ` *   - Rejects NULL SIDs, SIDs with 0 or >15 sub-authorities`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] ` *   - Rejects the well-known Everyone SID (S-1-1-0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] ` *   - For SIDs matching the server's domain, uses the RID directly`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] ` *   - For foreign-domain SIDs, applies a hash-based offset to prevent`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] ` *     UID collisions: uid = rid + (hash(domain) % MULTIPLIER) * MULTIPLIER`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ` *   - Rejects if the resulting UID would overflow uid_t`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] ` * This function is also exported for KUnit testing.`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] ` * Return: 0 on success with *uid_out set, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `int ksmbd_sid_to_id_domain_aware(struct smb_sid *psid, uid_t *id_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	uid_t rid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `	u32 hash_val, offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	if (!psid || !id_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00472 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	if (psid->num_subauth == 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	    psid->num_subauth > SID_MAX_SUB_AUTHORITIES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00476 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	/* Reject the Everyone SID (S-1-1-0) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	if (!compare_sids(psid, &sid_everyone))`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	rid = le32_to_cpu(psid->sub_auth[psid->num_subauth - 1]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	 * If the SID belongs to the server's configured domain or is`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	 * a well-known local SID, use the RID directly (backward compat).`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	if (ksmbd_sid_domain_match(psid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `		*id_out = rid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	 * Foreign domain SID: apply a domain-hash offset so that the`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	 * same RID from different domains maps to different UIDs.`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	 * offset = (hash(domain_prefix) % MULTIPLIER + 1) * MULTIPLIER`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	 * This ensures:`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	 *   - offset is always > 0 (so foreign UIDs never collide with local)`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	 *   - offset is always a multiple of MULTIPLIER (predictable ranges)`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	 *   - different domain hashes produce different offsets with high`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	 *     probability`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	hash_val = ksmbd_domain_sid_hash(psid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	offset = ((hash_val % DOMAIN_UID_OFFSET_MULTIPLIER) + 1) *`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `		 DOMAIN_UID_OFFSET_MULTIPLIER;`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	/* Bounds check: reject if RID + offset would overflow uid_t */`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	if (rid > U32_MAX - offset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [ERROR_PATH|] `		pr_err("SID RID %u + domain offset %u would overflow uid_t\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00511 [NONE] `		       rid, offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [PROTO_GATE|] `		return KSMBD_STATUS_NONE_MAPPED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00513 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	*id_out = rid + offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_sid_to_id_domain_aware);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ` * ksmbd_validate_sid_to_uid() - public API for domain-aware SID-to-UID mapping`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] ` * @psid:    the input SID`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ` * @uid_out: [out] the resulting UID`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ` * Wrapper around ksmbd_sid_to_id_domain_aware() for callers outside smbacl.c.`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `int ksmbd_validate_sid_to_uid(struct smb_sid *psid, uid_t *uid_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	return ksmbd_sid_to_id_domain_aware(psid, uid_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `static int sid_to_id(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `static int sid_to_id(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `		     struct smb_sid *psid, uint sidtype,`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `		     struct smb_fattr *fattr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	int rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	 * If we have too many subauthorities, then something is really wrong.`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	 * Just return an error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	if (unlikely(psid->num_subauth > SID_MAX_SUB_AUTHORITIES)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [ERROR_PATH|] `		pr_err("%s: %u subauthorities is too many!\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00550 [NONE] `		       __func__, psid->num_subauth);`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00552 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	if (!compare_sids(psid, &sid_everyone))`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00556 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	if (psid->num_subauth == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [ERROR_PATH|] `		pr_err("%s: zero subauthorities!\n", __func__);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00559 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00560 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `	if (sidtype == SIDOWNER) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `		kuid_t uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `		uid_t id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `		 * SECURITY: Use domain-aware mapping to prevent SID`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `		 * collision across domains.  ksmbd_sid_to_id_domain_aware()`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `		 * applies a hash-based offset for foreign-domain SIDs.`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `		rc = ksmbd_sid_to_id_domain_aware(psid, &id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [ERROR_PATH|] `			pr_err("%s: domain-aware SID-to-UID mapping failed: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00574 [NONE] `			       __func__, rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) || \`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 52) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0))`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `		uid = KUIDT_INIT(id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `		uid = from_vfsuid(idmap, &init_user_ns, VFSUIDT_INIT(uid));`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `		uid = from_vfsuid(user_ns, &init_user_ns, VFSUIDT_INIT(uid));`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `		uid = mapped_kuid_user(user_ns, &init_user_ns, KUIDT_INIT(id));`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `		 * Translate raw sid into kuid in the server's user`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `		 * namespace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `		uid = make_kuid(&init_user_ns, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `		/* If this is an idmapped mount, apply the idmapping. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `		uid = kuid_from_mnt(user_ns, uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `		if (uid_valid(uid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `			fattr->cf_uid = uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `			rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `		kgid_t gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `		gid_t id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `		uid_t raw_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		 * SECURITY: Use domain-aware mapping for GIDs too,`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		 * preventing GID collisions across domains.`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `		rc = ksmbd_sid_to_id_domain_aware(psid, &raw_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [ERROR_PATH|] `			pr_err("%s: domain-aware SID-to-GID mapping failed: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00617 [NONE] `			       __func__, rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `		id = (gid_t)raw_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) || \`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 52) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0))`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `		gid = KGIDT_INIT(id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `		gid = from_vfsgid(idmap, &init_user_ns, VFSGIDT_INIT(gid));`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `		gid = from_vfsgid(user_ns, &init_user_ns, VFSGIDT_INIT(gid));`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `		gid = mapped_kgid_user(user_ns, &init_user_ns, KGIDT_INIT(id));`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `		 * Translate raw sid into kgid in the server's user`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `		 * namespace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `		gid = make_kgid(&init_user_ns, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `		/* If this is an idmapped mount, apply the idmapping. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `		gid = kgid_from_mnt(user_ns, gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `		if (gid_valid(gid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `			fattr->cf_gid = gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `			rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `void posix_state_to_acl(struct posix_acl_state *state,`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `			struct posix_acl_entry *pace)`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	pace->e_tag = ACL_USER_OBJ;`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	pace->e_perm = state->owner.allow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	for (i = 0; i < state->users->n; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `		pace++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `		pace->e_tag = ACL_USER;`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `		pace->e_uid = state->users->aces[i].uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `		pace->e_perm = state->users->aces[i].perms.allow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	pace++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `	pace->e_tag = ACL_GROUP_OBJ;`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `	pace->e_perm = state->group.allow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	for (i = 0; i < state->groups->n; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `		pace++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `		pace->e_tag = ACL_GROUP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `		pace->e_gid = state->groups->aces[i].gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `		pace->e_perm = state->groups->aces[i].perms.allow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	if (state->users->n || state->groups->n) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `		pace++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `		pace->e_tag = ACL_MASK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `		pace->e_perm = state->mask.allow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `	pace++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `	pace->e_tag = ACL_OTHER;`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `	pace->e_perm = state->other.allow;`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `int init_acl_state(struct posix_acl_state *state, u16 cnt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `	size_t alloc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `	memset(state, 0, sizeof(struct posix_acl_state));`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `	 * In the worst case, each individual acl could be for a distinct`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `	 * named user or group, but we don't know which, so we allocate`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `	 * enough space for either:`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `	alloc = sizeof(struct posix_ace_state_array)`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `		+ (size_t)cnt * sizeof(struct posix_user_ace_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [MEM_BOUNDS|] `	state->users = kzalloc(alloc, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00703 [NONE] `	if (!state->users)`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00705 [MEM_BOUNDS|] `	state->groups = kzalloc(alloc, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00706 [NONE] `	if (!state->groups) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `		kfree(state->users);`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00709 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `void free_acl_state(struct posix_acl_state *state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	kfree(state->users);`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	kfree(state->groups);`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `void parse_dacl(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `void parse_dacl(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `		       struct smb_acl *pdacl, char *end_of_acl,`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `		       struct smb_sid *pownersid, struct smb_sid *pgrpsid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `		       struct smb_fattr *fattr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `	int i, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `	u16 num_aces = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `	unsigned int acl_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `	char *acl_base;`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `	struct smb_ace **ppace;`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `	struct posix_acl_entry *cf_pace, *cf_pdace;`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `	struct posix_acl_state acl_state, default_acl_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	umode_t mode = 0, acl_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	bool owner_found = false, group_found = false, others_found = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `	if (!pdacl)`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `	/* validate that we do not go past end of acl */`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `	if (end_of_acl < (char *)pdacl + sizeof(struct smb_acl) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `	    end_of_acl < (char *)pdacl + le16_to_cpu(pdacl->size)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [ERROR_PATH|] `		pr_err("ACL too small to parse DACL\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00747 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `	ksmbd_debug(SMB, "DACL revision %d size %d num aces %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `		    le16_to_cpu(pdacl->revision), le16_to_cpu(pdacl->size),`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `		    le16_to_cpu(pdacl->num_aces));`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `	acl_base = (char *)pdacl;`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	acl_size = sizeof(struct smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	num_aces = le16_to_cpu(pdacl->num_aces);`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	if (num_aces <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `	/* Validate ACE count against available buffer space */`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `	if (num_aces > (le16_to_cpu(pdacl->size) -`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `			sizeof(struct smb_acl)) /`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `			(offsetof(struct smb_ace, sid) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `			 offsetof(struct smb_sid, sub_auth) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `			 sizeof(__le16))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [ERROR_PATH|] `		pr_err_ratelimited("ACE count %u exceeds buffer capacity\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00768 [NONE] `				   num_aces);`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `	ret = init_acl_state(&acl_state, num_aces);`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `	ret = init_acl_state(&default_acl_state, num_aces);`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `		free_acl_state(&acl_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `	ppace = kmalloc_array(num_aces, sizeof(struct smb_ace *), KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `	if (!ppace) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `		free_acl_state(&default_acl_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `		free_acl_state(&acl_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `	 * reset rwx permissions for user/group/other.`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `	 * Also, if num_aces is 0 i.e. DACL has no ACEs,`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `	 * user/group/other have no permissions`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `	for (i = 0; i < num_aces; ++i) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `		if (end_of_acl - acl_base < acl_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `		ppace[i] = (struct smb_ace *)(acl_base + acl_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `		acl_base = (char *)ppace[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `		acl_size = offsetof(struct smb_ace, sid) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `			offsetof(struct smb_sid, sub_auth);`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `		if (end_of_acl - acl_base < acl_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `		    ppace[i]->sid.num_subauth == 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `		    ppace[i]->sid.num_subauth > SID_MAX_SUB_AUTHORITIES ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `		    (end_of_acl - acl_base <`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `		     acl_size + sizeof(__le32) * ppace[i]->sid.num_subauth) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `		    (le16_to_cpu(ppace[i]->size) <`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `		     acl_size + sizeof(__le32) * ppace[i]->sid.num_subauth))`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `		acl_size = le16_to_cpu(ppace[i]->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `		ppace[i]->access_req =`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `			smb_map_generic_desired_access(ppace[i]->access_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `		if (!(compare_sids(&ppace[i]->sid, &sid_unix_NFS_mode))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `			fattr->cf_mode =`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `				le32_to_cpu(ppace[i]->sid.sub_auth[2]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `		} else if (!compare_sids(&ppace[i]->sid, pownersid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `			acl_mode = access_flags_to_mode(fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `							ppace[i]->access_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `							ppace[i]->type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `			acl_mode &= 0700;`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `			if (!owner_found) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `				mode &= ~(0700);`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `				mode |= acl_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `			owner_found = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `		} else if (!compare_sids(&ppace[i]->sid, pgrpsid) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `			   ppace[i]->sid.sub_auth[ppace[i]->sid.num_subauth - 1] ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `			    DOMAIN_USER_RID_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `			acl_mode = access_flags_to_mode(fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `							ppace[i]->access_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `							ppace[i]->type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `			acl_mode &= 0070;`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `			if (!group_found) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `				mode &= ~(0070);`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `				mode |= acl_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `			group_found = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `		} else if (!compare_sids(&ppace[i]->sid, &sid_everyone)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `			acl_mode = access_flags_to_mode(fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `							ppace[i]->access_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `							ppace[i]->type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `			acl_mode &= 0007;`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `			if (!others_found) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `				mode &= ~(0007);`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `				mode |= acl_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `			others_found = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `		} else if (!compare_sids(&ppace[i]->sid, &creator_owner)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `		} else if (!compare_sids(&ppace[i]->sid, &creator_group)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `		} else if (!compare_sids(&ppace[i]->sid, &sid_authusers)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `			struct smb_fattr temp_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `			acl_mode = access_flags_to_mode(fattr, ppace[i]->access_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `							ppace[i]->type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `			temp_fattr.cf_uid = INVALID_UID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `			ret = sid_to_id(idmap, &ppace[i]->sid, SIDOWNER, &temp_fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `			ret = sid_to_id(user_ns, &ppace[i]->sid, SIDOWNER, &temp_fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `			if (ret || uid_eq(temp_fattr.cf_uid, INVALID_UID)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [ERROR_PATH|] `				pr_err("%s: Error %d mapping Owner SID to uid\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00871 [NONE] `				       __func__, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `			acl_state.owner.allow = ((acl_mode & 0700) >> 6) | 0004;`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `			acl_state.users->aces[acl_state.users->n].uid =`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `				temp_fattr.cf_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `			acl_state.users->aces[acl_state.users->n++].perms.allow =`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `				((acl_mode & 0700) >> 6) | 0004;`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `			default_acl_state.owner.allow = ((acl_mode & 0700) >> 6) | 0004;`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `			default_acl_state.users->aces[default_acl_state.users->n].uid =`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `				temp_fattr.cf_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `			default_acl_state.users->aces[default_acl_state.users->n++].perms.allow =`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `				((acl_mode & 0700) >> 6) | 0004;`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `	kfree(ppace);`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `	if (owner_found) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `		/* The owner must be set to at least read-only. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `		acl_state.owner.allow = ((mode & 0700) >> 6) | 0004;`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `		acl_state.users->aces[acl_state.users->n].uid = fattr->cf_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `		acl_state.users->aces[acl_state.users->n++].perms.allow =`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `			((mode & 0700) >> 6) | 0004;`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `		default_acl_state.owner.allow = ((mode & 0700) >> 6) | 0004;`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `		default_acl_state.users->aces[default_acl_state.users->n].uid =`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `			fattr->cf_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `		default_acl_state.users->aces[default_acl_state.users->n++].perms.allow =`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `			((mode & 0700) >> 6) | 0004;`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `	if (group_found) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `		acl_state.group.allow = (mode & 0070) >> 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `		acl_state.groups->aces[acl_state.groups->n].gid =`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `			fattr->cf_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `		acl_state.groups->aces[acl_state.groups->n++].perms.allow =`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `			(mode & 0070) >> 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `		default_acl_state.group.allow = (mode & 0070) >> 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `		default_acl_state.groups->aces[default_acl_state.groups->n].gid =`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `			fattr->cf_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `		default_acl_state.groups->aces[default_acl_state.groups->n++].perms.allow =`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `			(mode & 0070) >> 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	if (others_found) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `		fattr->cf_mode &= ~(0007);`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `		fattr->cf_mode |= mode & 0007;`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `		acl_state.other.allow = mode & 0007;`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `		default_acl_state.other.allow = mode & 0007;`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `	if (acl_state.users->n || acl_state.groups->n) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `		acl_state.mask.allow = 0x07;`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `		if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `			fattr->cf_acls =`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `				posix_acl_alloc(acl_state.users->n +`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `					acl_state.groups->n + 4, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `			if (fattr->cf_acls) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `				cf_pace = fattr->cf_acls->a_entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `				posix_state_to_acl(&acl_state, cf_pace);`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	if (default_acl_state.users->n || default_acl_state.groups->n) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `		default_acl_state.mask.allow = 0x07;`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `		if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `			fattr->cf_dacls =`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `				posix_acl_alloc(default_acl_state.users->n +`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `				default_acl_state.groups->n + 4, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `			if (fattr->cf_dacls) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `				cf_pdace = fattr->cf_dacls->a_entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `				posix_state_to_acl(&default_acl_state, cf_pdace);`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	free_acl_state(&acl_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `	free_acl_state(&default_acl_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `EXPORT_SYMBOL_IF_KUNIT(parse_dacl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `static int set_posix_acl_entries_dacl(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `static int set_posix_acl_entries_dacl(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `				      struct smb_ace *pndace,`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `				      struct smb_fattr *fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `				      u16 *num_aces, u16 *size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `				      u32 nt_aces_num,`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `				      unsigned int buf_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `	struct posix_acl_entry *pace;`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	struct smb_sid *sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `	struct smb_ace *ntace;`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `	int i, j;`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	unsigned int new_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `	__u16 ace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `	if (!fattr->cf_acls)`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [ERROR_PATH|] `		goto posix_default_acl;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00975 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `	pace = fattr->cf_acls->a_entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `	for (i = 0; i < fattr->cf_acls->a_count; i++, pace++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `		int flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [MEM_BOUNDS|] `		sid = kmalloc(sizeof(struct smb_sid), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00981 [NONE] `		if (!sid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `		if (pace->e_tag == ACL_USER) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `			uid_t uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `			unsigned int sid_type = SIDOWNER;`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `			uid = posix_acl_uid_translate(idmap, pace);`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `			uid = posix_acl_uid_translate(user_ns, pace);`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `			if (!uid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `				sid_type = SIDUNIX_USER;`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `			id_to_sid(uid, sid_type, sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `		} else if (pace->e_tag == ACL_GROUP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `			gid_t gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `			gid = posix_acl_gid_translate(idmap, pace);`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `			gid = posix_acl_gid_translate(user_ns, pace);`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `			id_to_sid(gid, SIDUNIX_GROUP, sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `		} else if (pace->e_tag == ACL_OTHER && !nt_aces_num) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `			smb_copy_sid(sid, &sid_everyone);`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `			kfree(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `		ntace = pndace;`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `		for (j = 0; j < nt_aces_num; j++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `			if (ntace->sid.sub_auth[ntace->sid.num_subauth - 1] ==`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `					sid->sub_auth[sid->num_subauth - 1])`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [ERROR_PATH|] `				goto pass_same_sid;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01016 [NONE] `			ntace = (struct smb_ace *)((char *)ntace +`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `					le16_to_cpu(ntace->size));`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `		if (S_ISDIR(fattr->cf_mode) && pace->e_tag == ACL_OTHER)`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `			flags = 0x03;`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `		ace_size = ksmbd_ace_size(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `		if (!ace_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [MEM_BOUNDS|] `		    check_add_overflow((unsigned int)*size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01026 [NONE] `				       (unsigned int)ace_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `				       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `		    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `			kfree(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [ERROR_PATH|] `			pr_err_ratelimited("ACL buffer overflow in posix ACE\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01031 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01032 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `		ntace = (struct smb_ace *)((char *)pndace + *size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `		*size += fill_ace_for_sid(ntace, sid, ACCESS_ALLOWED,`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `				flags, pace->e_perm, 0777);`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `		(*num_aces)++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `		if (pace->e_tag == ACL_USER)`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `			ntace->access_req |=`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `				FILE_DELETE_LE | FILE_DELETE_CHILD_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `		if (S_ISDIR(fattr->cf_mode) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] `		    (pace->e_tag == ACL_USER ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `		     pace->e_tag == ACL_GROUP)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `			ace_size = ksmbd_ace_size(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `			if (!ace_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [MEM_BOUNDS|] `			    check_add_overflow((unsigned int)*size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01048 [NONE] `					       (unsigned int)ace_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `					       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `			    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] `				kfree(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [ERROR_PATH|] `				pr_err_ratelimited("ACL buffer overflow in posix dir ACE\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01053 [ERROR_PATH|] `				return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01054 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `			ntace = (struct smb_ace *)((char *)pndace +`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `					*size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `			*size += fill_ace_for_sid(ntace, sid,`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `					ACCESS_ALLOWED, 0x03,`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `					pace->e_perm, 0777);`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `			(*num_aces)++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `			if (pace->e_tag == ACL_USER)`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `				ntace->access_req |=`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `					FILE_DELETE_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `					FILE_DELETE_CHILD_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `pass_same_sid:`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `		kfree(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `	if (nt_aces_num)`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `posix_default_acl:`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `	if (!fattr->cf_dacls)`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `	pace = fattr->cf_dacls->a_entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `	for (i = 0; i < fattr->cf_dacls->a_count; i++, pace++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [MEM_BOUNDS|] `		sid = kmalloc(sizeof(struct smb_sid), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01082 [NONE] `		if (!sid)`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `		if (pace->e_tag == ACL_USER) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `			uid_t uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `			uid = posix_acl_uid_translate(idmap, pace);`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `			uid = posix_acl_uid_translate(user_ns, pace);`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `			id_to_sid(uid, SIDCREATOR_OWNER, sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `		} else if (pace->e_tag == ACL_GROUP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `			gid_t gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `			gid = posix_acl_gid_translate(idmap, pace);`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `			gid = posix_acl_gid_translate(user_ns, pace);`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `			id_to_sid(gid, SIDCREATOR_GROUP, sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `			kfree(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `		ace_size = ksmbd_ace_size(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `		if (!ace_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [MEM_BOUNDS|] `		    check_add_overflow((unsigned int)*size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01111 [NONE] `				       (unsigned int)ace_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `				       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `		    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `			kfree(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [ERROR_PATH|] `			pr_err_ratelimited("ACL buffer overflow in default ACE\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01116 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01117 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `		ntace = (struct smb_ace *)((char *)pndace + *size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `		*size += fill_ace_for_sid(ntace, sid, ACCESS_ALLOWED,`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `				0x0b, pace->e_perm, 0777);`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `		(*num_aces)++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `		if (pace->e_tag == ACL_USER)`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `			ntace->access_req |=`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `				FILE_DELETE_LE | FILE_DELETE_CHILD_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `		kfree(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `static int set_ntacl_dacl(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `static int set_ntacl_dacl(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `			  struct smb_acl *pndacl,`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `			  struct smb_acl *nt_dacl,`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `			  unsigned int aces_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `			  const struct smb_sid *pownersid,`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `			  const struct smb_sid *pgrpsid,`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `			  struct smb_fattr *fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `			  unsigned int buf_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `	struct smb_ace *ntace, *pndace;`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `	u16 nt_num_aces = le16_to_cpu(nt_dacl->num_aces);`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `	u16 num_aces = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `	unsigned short size = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `	unsigned int new_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `	int i, rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `	pndace = (struct smb_ace *)((char *)pndacl +`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `			sizeof(struct smb_acl));`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `	if (nt_num_aces) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `		ntace = (struct smb_ace *)((char *)nt_dacl +`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `				sizeof(struct smb_acl));`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `		for (i = 0; i < nt_num_aces; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `			unsigned short nt_ace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `			if (offsetof(struct smb_ace, access_req) >`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `			    aces_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `			nt_ace_size = le16_to_cpu(ntace->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `			if (nt_ace_size > aces_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [MEM_BOUNDS|] `			if (check_add_overflow((unsigned int)size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01168 [NONE] `					       (unsigned int)nt_ace_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `					       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `			    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [ERROR_PATH|] `				pr_err_ratelimited("ACL buffer overflow copying NT ACEs\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01172 [ERROR_PATH|] `				return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01173 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [MEM_BOUNDS|] `			memcpy((char *)pndace + size, ntace,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01176 [NONE] `			       nt_ace_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `			size += nt_ace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `			aces_size -= nt_ace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] `			ntace = (struct smb_ace *)((char *)ntace +`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `					nt_ace_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] `			num_aces++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `	 * Only add POSIX ACL-derived ACEs when the stored NTACL has`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] `	 * no ACEs of its own.  When a client-provided SD was stored`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [PROTO_GATE|] `	 * (e.g. via SMB2_CREATE_SD_BUFFER), the NTACL is authoritative`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01189 [NONE] `	 * and must not be augmented with POSIX-derived entries.`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `	if (!nt_num_aces) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `		rc = set_posix_acl_entries_dacl(idmap, pndace, fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] `		rc = set_posix_acl_entries_dacl(user_ns, pndace, fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] `						&num_aces, &size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `						nt_num_aces, buf_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `	pndacl->num_aces = cpu_to_le16(num_aces);`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] `	pndacl->size = cpu_to_le16(le16_to_cpu(pndacl->size) + size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `static int set_mode_dacl(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `static int set_mode_dacl(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `			 struct smb_acl *pndacl,`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `			 struct smb_fattr *fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `			 unsigned int buf_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `	struct smb_ace *pace, *pndace;`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `	u16 num_aces = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `	u16 size = 0, ace_size = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `	unsigned int new_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	uid_t uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] `	const struct smb_sid *sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	pace = pndace = (struct smb_ace *)((char *)pndacl +`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `			sizeof(struct smb_acl));`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `	if (fattr->cf_acls) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `		rc = set_posix_acl_entries_dacl(idmap, pndace, fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `		rc = set_posix_acl_entries_dacl(user_ns, pndace, fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `						&num_aces, &size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `						num_aces, buf_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01239 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `	/* owner RID - account for extra sub_auth (+4) appended */`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `	uid = from_kuid(&init_user_ns, fattr->cf_uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `	if (uid)`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `		sid = &server_conf.domain_sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `		sid = &sid_unix_users;`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `	ace_size = ksmbd_ace_size(sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `	if (!ace_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [MEM_BOUNDS|] `	    check_add_overflow((unsigned int)ace_size, 4u,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01251 [NONE] `			       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [MEM_BOUNDS|] `	    check_add_overflow((unsigned int)size, new_off,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01253 [NONE] `			       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `	    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [ERROR_PATH|] `		pr_err_ratelimited("ACL buffer overflow: owner ACE\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01256 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01257 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] `	ace_size = fill_ace_for_sid(pace, sid, ACCESS_ALLOWED, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `				    fattr->cf_mode, 0700);`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `	if (pace->sid.num_subauth < SID_MAX_SUB_AUTHORITIES)`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `		pace->sid.sub_auth[pace->sid.num_subauth++] =`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `			cpu_to_le32(uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `	pace->size = cpu_to_le16(ace_size + 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `	size += le16_to_cpu(pace->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `	pace = (struct smb_ace *)((char *)pndace + size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `	/* Group RID */`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `	ace_size = ksmbd_ace_size(&sid_unix_groups);`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `	if (!ace_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [MEM_BOUNDS|] `	    check_add_overflow((unsigned int)ace_size, 4u,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01272 [NONE] `			       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [MEM_BOUNDS|] `	    check_add_overflow((unsigned int)size, new_off,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01274 [NONE] `			       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `	    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [ERROR_PATH|] `		pr_err_ratelimited("ACL buffer overflow: group ACE\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01277 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01278 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `	ace_size = fill_ace_for_sid(pace, &sid_unix_groups,`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `				    ACCESS_ALLOWED, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `				    fattr->cf_mode, 0070);`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] `	if (pace->sid.num_subauth < SID_MAX_SUB_AUTHORITIES)`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `		pace->sid.sub_auth[pace->sid.num_subauth++] =`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] `			cpu_to_le32(from_kgid(&init_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `					      fattr->cf_gid));`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `	pace->size = cpu_to_le16(ace_size + 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `	size += le16_to_cpu(pace->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `	pace = (struct smb_ace *)((char *)pndace + size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `	num_aces = 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `	if (S_ISDIR(fattr->cf_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] `		pace = (struct smb_ace *)((char *)pndace + size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `		/* creator owner */`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `		ace_size = ksmbd_ace_size(&creator_owner);`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `		if (!ace_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [MEM_BOUNDS|] `		    check_add_overflow((unsigned int)size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01299 [NONE] `				       (unsigned int)ace_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `				       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `		    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [ERROR_PATH|] `			pr_err_ratelimited("ACL buffer overflow: creator owner\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01303 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01304 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `		size += fill_ace_for_sid(pace, &creator_owner,`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `					ACCESS_ALLOWED, 0x0b,`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `					fattr->cf_mode, 0700);`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `		pace = (struct smb_ace *)((char *)pndace + size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `		/* creator group */`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `		ace_size = ksmbd_ace_size(&creator_group);`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `		if (!ace_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [MEM_BOUNDS|] `		    check_add_overflow((unsigned int)size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01314 [NONE] `				       (unsigned int)ace_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `				       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `		    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [ERROR_PATH|] `			pr_err_ratelimited("ACL buffer overflow: creator group\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01318 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01319 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `		size += fill_ace_for_sid(pace, &creator_group,`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `					ACCESS_ALLOWED, 0x0b,`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `					fattr->cf_mode, 0070);`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] `		pace = (struct smb_ace *)((char *)pndace + size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `		num_aces = 5;`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `	/* other */`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `	ace_size = ksmbd_ace_size(&sid_everyone);`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `	if (!ace_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [MEM_BOUNDS|] `	    check_add_overflow((unsigned int)size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01331 [NONE] `			       (unsigned int)ace_size, &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] `	    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [ERROR_PATH|] `		pr_err_ratelimited("ACL buffer overflow: everyone ACE\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01334 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01335 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] `	size += fill_ace_for_sid(pace, &sid_everyone,`
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] `				ACCESS_ALLOWED, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] `				fattr->cf_mode, 0007);`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `	pndacl->num_aces = cpu_to_le16(num_aces);`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `	pndacl->size = cpu_to_le16(le16_to_cpu(pndacl->size) + size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `int parse_sid(struct smb_sid *psid, char *end_of_acl)`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `	 * validate that we do not go past end of ACL - sid must be at least 8`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `	 * bytes long (assuming no sub-auths - e.g. the null SID`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `	if (end_of_acl < (char *)psid + 8) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [ERROR_PATH|] `		pr_err("ACL too small to parse SID %p\n", psid);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01355 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01356 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `	if (!psid->num_subauth)`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `	if (psid->num_subauth > SID_MAX_SUB_AUTHORITIES ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	    end_of_acl < (char *)psid + 8 + sizeof(__le32) * psid->num_subauth)`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `EXPORT_SYMBOL_IF_KUNIT(parse_sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `/* Convert CIFS ACL to POSIX form */`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] `int parse_sec_desc(struct mnt_idmap *idmap, struct smb_ntsd *pntsd,`
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `int parse_sec_desc(struct user_namespace *user_ns, struct smb_ntsd *pntsd,`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `		   int acl_len, struct smb_fattr *fattr)`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `	struct smb_sid *owner_sid_ptr, *group_sid_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `	struct smb_acl *dacl_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] `	char *end_of_acl = ((char *)pntsd) + acl_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `	__u32 dacloffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `	int pntsd_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `	if (!pntsd)`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01386 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `	if (acl_len < sizeof(struct smb_ntsd))`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `	 * Validate that SID and DACL offsets fall within the buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [MEM_BOUNDS|] `	 * before computing pointers.  Use check_add_overflow() to`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01393 [NONE] `	 * guard against crafted offsets that could wrap around.`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] `		__u32 osidoff = le32_to_cpu(pntsd->osidoffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] `		__u32 gsidoff = le32_to_cpu(pntsd->gsidoffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] `		unsigned int end;`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `		dacloffset = le32_to_cpu(pntsd->dacloffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `		if (osidoff &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [MEM_BOUNDS|] `		    (check_add_overflow(osidoff,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01404 [NONE] `				       (unsigned int)CIFS_SID_BASE_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] `				       &end) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `		     end > (unsigned int)acl_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `		if (gsidoff &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [MEM_BOUNDS|] `		    (check_add_overflow(gsidoff,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01411 [NONE] `				       (unsigned int)CIFS_SID_BASE_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `				       &end) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `		     end > (unsigned int)acl_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `		if (dacloffset &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [MEM_BOUNDS|] `		    (check_add_overflow(dacloffset,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01418 [NONE] `				       (unsigned int)sizeof(struct smb_acl),`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] `				       &end) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] `		     end > (unsigned int)acl_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `		owner_sid_ptr = (struct smb_sid *)((char *)pntsd + osidoff);`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] `		group_sid_ptr = (struct smb_sid *)((char *)pntsd + gsidoff);`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] `		dacl_ptr = (struct smb_acl *)((char *)pntsd + dacloffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `		    "revision %d type 0x%x ooffset 0x%x goffset 0x%x sacloffset 0x%x dacloffset 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] `		    pntsd->revision, pntsd->type, le32_to_cpu(pntsd->osidoffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `		    le32_to_cpu(pntsd->gsidoffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] `		    le32_to_cpu(pntsd->sacloffset), dacloffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] `	pntsd_type = le16_to_cpu(pntsd->type);`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `	if (!(pntsd_type & DACL_PRESENT)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `		ksmbd_debug(SMB, "DACL_PRESENT in DACL type is not set\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `	pntsd->type = cpu_to_le16(DACL_PRESENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `	/* Preserve SACL flags if present in the incoming descriptor */`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] `	if (pntsd_type & SACL_PRESENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `		pntsd->type |= cpu_to_le16(SACL_PRESENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `	if (pntsd_type & SACL_DEFAULTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `		pntsd->type |= cpu_to_le16(SACL_DEFAULTED);`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] `	if (pntsd_type & SACL_AUTO_INHERITED)`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `		pntsd->type |= cpu_to_le16(SACL_AUTO_INHERITED);`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] `	if (pntsd_type & SACL_PROTECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] `		pntsd->type |= cpu_to_le16(SACL_PROTECTED);`
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] `	if (pntsd->osidoffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `		if (le32_to_cpu(pntsd->osidoffset) < sizeof(struct smb_ntsd))`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] `		rc = parse_sid(owner_sid_ptr, end_of_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [ERROR_PATH|] `			pr_err("%s: Error %d parsing Owner SID\n", __func__, rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01458 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `		rc = sid_to_id(idmap, owner_sid_ptr, SIDOWNER, fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] `		rc = sid_to_id(user_ns, owner_sid_ptr, SIDOWNER, fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [ERROR_PATH|] `			pr_err("%s: Error %d mapping Owner SID to uid\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01468 [NONE] `			       __func__, rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `			owner_sid_ptr = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] `	if (pntsd->gsidoffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `		if (le32_to_cpu(pntsd->gsidoffset) < sizeof(struct smb_ntsd))`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01476 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `		rc = parse_sid(group_sid_ptr, end_of_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [ERROR_PATH|] `			pr_err("%s: Error %d mapping Owner SID to gid\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01480 [NONE] `			       __func__, rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `		rc = sid_to_id(idmap, group_sid_ptr, SIDUNIX_GROUP, fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `		rc = sid_to_id(user_ns, group_sid_ptr, SIDUNIX_GROUP, fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [ERROR_PATH|] `			pr_err("%s: Error %d mapping Group SID to gid\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01490 [NONE] `			       __func__, rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `			group_sid_ptr = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `	if ((pntsd_type & (DACL_AUTO_INHERITED | DACL_AUTO_INHERIT_REQ)) ==`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `	    (DACL_AUTO_INHERITED | DACL_AUTO_INHERIT_REQ))`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] `		pntsd->type |= cpu_to_le16(DACL_AUTO_INHERITED);`
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] `	if (pntsd_type & DACL_PROTECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] `		pntsd->type |= cpu_to_le16(DACL_PROTECTED);`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `	if (dacloffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `		if (dacloffset < sizeof(struct smb_ntsd))`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] `		parse_dacl(idmap, dacl_ptr, end_of_acl,`
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] `		parse_dacl(user_ns, dacl_ptr, end_of_acl,`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `			   owner_sid_ptr, group_sid_ptr, fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] `EXPORT_SYMBOL_IF_KUNIT(parse_sec_desc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] ` * build_sec_desc() - convert permission bits to equivalent CIFS ACL`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] ` * @idmap:	idmap of the relevant mount (user_ns on older kernels)`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] ` * @pntsd:	output NT security descriptor buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] ` * @ppntsd:	optional parent NT security descriptor`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] ` * @ppntsd_size:	size of parent security descriptor`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] ` * @addition_info:	which security info sections to include`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] ` * @secdesclen:	output total security descriptor length`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] ` * @fattr:	file attributes with uid/gid/mode/ACLs`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] ` * @buf_size:	total size of the output buffer pntsd`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] ` * Return:	0 on success, negative errno on error`
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `int build_sec_desc(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `int build_sec_desc(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `		   struct smb_ntsd *pntsd, struct smb_ntsd *ppntsd,`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [NONE] `		   int ppntsd_size, int addition_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] `		   __u32 *secdesclen, struct smb_fattr *fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] `		   unsigned int buf_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] `	__u32 offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `	unsigned int sid_size, new_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] `	struct smb_sid *owner_sid_ptr, *group_sid_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] `	struct smb_sid *nowner_sid_ptr, *ngroup_sid_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `	struct smb_acl *dacl_ptr = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] `	struct smb_acl *sacl_ptr = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `	uid_t uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] `	gid_t gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `	unsigned int sid_type = SIDOWNER;`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [NONE] `	if (buf_size < sizeof(struct smb_ntsd))`
  Review: Low-risk line; verify in surrounding control flow.
- L01552 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [MEM_BOUNDS|] `	nowner_sid_ptr = kmalloc(sizeof(struct smb_sid),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01555 [NONE] `				 KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `	if (!nowner_sid_ptr)`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01558 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] `	uid = from_kuid(&init_user_ns, fattr->cf_uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] `	if (!uid)`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] `		sid_type = SIDUNIX_USER;`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `	id_to_sid(uid, sid_type, nowner_sid_ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [MEM_BOUNDS|] `	ngroup_sid_ptr = kmalloc(sizeof(struct smb_sid),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01565 [NONE] `				 KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `	if (!ngroup_sid_ptr) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] `		kfree(nowner_sid_ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01569 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] `	gid = from_kgid(&init_user_ns, fattr->cf_gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] `	id_to_sid(gid, SIDUNIX_GROUP, ngroup_sid_ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] `	offset = sizeof(struct smb_ntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] `	pntsd->sacloffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] `	pntsd->dacloffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] `	pntsd->revision = cpu_to_le16(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `	pntsd->type = cpu_to_le16(SELF_RELATIVE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] `	if (ppntsd)`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] `		pntsd->type |= ppntsd->type;`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `	 * If a stored NTSD has explicit owner/group SIDs, use them`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `	 * instead of the POSIX uid/gid-derived SIDs.  This preserves`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [PROTO_GATE|] `	 * client-supplied ownership from SMB2_CREATE_SD_BUFFER or`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01586 [NONE] `	 * SET_INFO operations.`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] `	if (ppntsd && ppntsd->osidoffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] `		unsigned int osid_off = le32_to_cpu(ppntsd->osidoffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `		if (osid_off + offsetof(struct smb_sid, sub_auth) <=`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] `		    (unsigned int)ppntsd_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] `			struct smb_sid *stored_owner =`
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] `				(struct smb_sid *)((char *)ppntsd + osid_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] `			smb_copy_sid(nowner_sid_ptr, stored_owner);`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01600 [NONE] `	if (ppntsd && ppntsd->gsidoffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] `		unsigned int gsid_off = le32_to_cpu(ppntsd->gsidoffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] `		if (gsid_off + offsetof(struct smb_sid, sub_auth) <=`
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [NONE] `		    (unsigned int)ppntsd_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01605 [NONE] `			struct smb_sid *stored_group =`
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] `				(struct smb_sid *)((char *)ppntsd + gsid_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `			smb_copy_sid(ngroup_sid_ptr, stored_group);`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `	if (addition_info & OWNER_SECINFO) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] `		sid_size = 1 + 1 + 6 +`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] `			(unsigned int)nowner_sid_ptr->num_subauth * 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [MEM_BOUNDS|] `		if (check_add_overflow(offset, sid_size, &new_off) ||`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01616 [NONE] `		    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [ERROR_PATH|] `			pr_err_ratelimited("SD buffer overflow: owner SID\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01618 [NONE] `			rc = -ENOSPC;`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01620 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [NONE] `		pntsd->osidoffset = cpu_to_le32(offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] `		owner_sid_ptr = (struct smb_sid *)((char *)pntsd +`
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `				offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] `		smb_copy_sid(owner_sid_ptr, nowner_sid_ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `		offset = new_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `	if (addition_info & GROUP_SECINFO) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `		sid_size = 1 + 1 + 6 +`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] `			(unsigned int)ngroup_sid_ptr->num_subauth * 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [MEM_BOUNDS|] `		if (check_add_overflow(offset, sid_size, &new_off) ||`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01632 [NONE] `		    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [ERROR_PATH|] `			pr_err_ratelimited("SD buffer overflow: group SID\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01634 [NONE] `			rc = -ENOSPC;`
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01636 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] `		pntsd->gsidoffset = cpu_to_le32(offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [NONE] `		group_sid_ptr = (struct smb_sid *)((char *)pntsd +`
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] `				offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `		smb_copy_sid(group_sid_ptr, ngroup_sid_ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `		offset = new_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `	if (addition_info & SACL_SECINFO) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `		 * G.8: Try to copy stored SACL ACEs from ppntsd.  If the`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] `		 * stored SD contains a SACL (sacloffset != 0), replicate it`
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `		 * verbatim.  If there is no stored SACL, return an empty SACL`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [PROTO_GATE|] `		 * with 0 ACEs and STATUS_SUCCESS (not an error) so that Windows`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01650 [NONE] `		 * does not interpret the response as "access denied to SACL".`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] `		if (ppntsd && le32_to_cpu(ppntsd->sacloffset)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `			unsigned int sacl_off = le32_to_cpu(ppntsd->sacloffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `			struct smb_acl *pp_sacl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `			unsigned int pp_sacl_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [NONE] `			if (sacl_off + sizeof(struct smb_acl) <=`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `			    (unsigned int)ppntsd_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `				pp_sacl = (struct smb_acl *)`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] `					((char *)ppntsd + sacl_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `				pp_sacl_size = le16_to_cpu(pp_sacl->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [NONE] `				if (pp_sacl_size >= sizeof(struct smb_acl) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [NONE] `				    sacl_off + pp_sacl_size <=`
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [NONE] `				    (unsigned int)ppntsd_size &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [MEM_BOUNDS|] `				    !check_add_overflow(offset, pp_sacl_size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01667 [NONE] `						       &new_off) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] `				    new_off <= buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] `					/* Copy stored SACL verbatim */`
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] `					pntsd->type |=`
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `						cpu_to_le16(SACL_PRESENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `					pntsd->sacloffset =`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `						cpu_to_le32(offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] `					sacl_ptr = (struct smb_acl *)`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `						((char *)pntsd + offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [MEM_BOUNDS|] `					memcpy(sacl_ptr, pp_sacl,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01677 [NONE] `					       pp_sacl_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [NONE] `					offset = new_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [ERROR_PATH|] `					goto sacl_done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01680 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01681 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [PROTO_GATE|] `		/* No stored SACL: return empty SACL (0 ACEs, STATUS_SUCCESS) */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01685 [MEM_BOUNDS|] `		if (check_add_overflow(offset,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01686 [NONE] `				       (unsigned int)sizeof(struct smb_acl),`
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] `				       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [NONE] `		    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01689 [ERROR_PATH|] `			pr_err_ratelimited("SD buffer overflow: SACL hdr\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01690 [NONE] `			rc = -ENOSPC;`
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01692 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [NONE] `		pntsd->type |= cpu_to_le16(SACL_PRESENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] `		pntsd->sacloffset = cpu_to_le32(offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `		sacl_ptr = (struct smb_acl *)((char *)pntsd + offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `		sacl_ptr->revision = cpu_to_le16(2);`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] `		sacl_ptr->size = cpu_to_le16(sizeof(struct smb_acl));`
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [NONE] `		sacl_ptr->num_aces = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [NONE] `		sacl_ptr->reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [NONE] `		offset = new_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] `sacl_done:;`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] `	if (addition_info & DACL_SECINFO) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] `		unsigned int dacl_buf_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [NONE] `		pntsd->type |= cpu_to_le16(DACL_PRESENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] `		 * If the stored SD has DACL_PRESENT but no DACL data`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] `		 * (dacloffset == 0), this is a NULL DACL meaning`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `		 * everyone has full access.  Preserve it as-is:`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `		 * set DACL_PRESENT but leave dacloffset = 0.`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] `		if (ppntsd &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] `		    (le16_to_cpu(ppntsd->type) & DACL_PRESENT) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] `		    !ppntsd->dacloffset)`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [ERROR_PATH|] `			goto dacl_done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01720 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [MEM_BOUNDS|] `		if (check_add_overflow(offset,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01722 [NONE] `				       (unsigned int)sizeof(struct smb_acl),`
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [NONE] `				       &new_off) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] `		    new_off > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [ERROR_PATH|] `			pr_err_ratelimited("SD buffer overflow: DACL hdr\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01726 [NONE] `			rc = -ENOSPC;`
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01728 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] `		dacl_ptr = (struct smb_acl *)((char *)pntsd + offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] `		dacl_ptr->revision = cpu_to_le16(2);`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `		dacl_ptr->size = cpu_to_le16(sizeof(struct smb_acl));`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `		dacl_ptr->num_aces = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [NONE] `		/* Space remaining for ACEs after DACL header */`
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [NONE] `		dacl_buf_size = buf_size - new_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [NONE] `		if (!ppntsd) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01739 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `			rc = set_mode_dacl(idmap, dacl_ptr, fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [NONE] `			rc = set_mode_dacl(user_ns, dacl_ptr, fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01744 [NONE] `					   dacl_buf_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `			if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01747 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `			struct smb_acl *ppdacl_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] `			unsigned int dacl_offset =`
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] `				le32_to_cpu(ppntsd->dacloffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [NONE] `			int ppdacl_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] `			int ntacl_size = ppntsd_size - dacl_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01754 [NONE] `			if (!dacl_offset ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] `			    (dacl_offset + sizeof(struct smb_acl) >`
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] `			     (unsigned int)ppntsd_size))`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [ERROR_PATH|] `				goto dacl_done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01758 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] `			ppdacl_ptr = (struct smb_acl *)((char *)ppntsd +`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] `					dacl_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] `			ppdacl_size = le16_to_cpu(ppdacl_ptr->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [NONE] `			if (ppdacl_size > ntacl_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] `			    ppdacl_size < sizeof(struct smb_acl))`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [ERROR_PATH|] `				goto dacl_done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01765 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] `			rc = set_ntacl_dacl(idmap, dacl_ptr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `			rc = set_ntacl_dacl(user_ns, dacl_ptr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] `					    ppdacl_ptr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] `					    ntacl_size -`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] `					    sizeof(struct smb_acl),`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] `					    nowner_sid_ptr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] `					    ngroup_sid_ptr, fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [NONE] `					    dacl_buf_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01777 [NONE] `			if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01779 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [NONE] `		pntsd->dacloffset = cpu_to_le32(offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01781 [NONE] `		offset += le16_to_cpu(dacl_ptr->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] `		/* Final validation */`
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `		if (offset > buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [ERROR_PATH|] `			pr_err_ratelimited("SD exceeds buffer: %u > %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01786 [NONE] `					   offset, buf_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] `			rc = -ENOSPC;`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01789 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01791 [NONE] `dacl_done:`
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] `	kfree(nowner_sid_ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] `	kfree(ngroup_sid_ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] `	*secdesclen = offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [NONE] `EXPORT_SYMBOL_IF_KUNIT(build_sec_desc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [NONE] `void smb_set_ace(struct smb_ace *ace, const struct smb_sid *sid, u8 type,`
  Review: Low-risk line; verify in surrounding control flow.
- L01803 [NONE] `			u8 flags, __le32 access_req)`
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] `	ace->type = type;`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `	ace->flags = flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] `	ace->access_req = access_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] `	smb_copy_sid(&ace->sid, sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] `	ace->size = cpu_to_le16(1 + 1 + 2 + 4 + 1 + 1 + 6 + (sid->num_subauth * 4));`
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb_set_ace);`
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] `int smb_inherit_dacl(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [NONE] `		     const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [NONE] `		     unsigned int uid, unsigned int gid)`
  Review: Low-risk line; verify in surrounding control flow.
- L01816 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [NONE] `	const struct smb_sid *psid, *creator = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] `	struct smb_ace *parent_aces, *aces;`
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [NONE] `	struct smb_acl *parent_pdacl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `	struct smb_ntsd *parent_pntsd = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] `	struct smb_sid owner_sid, group_sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] `	struct dentry *parent = path->dentry->d_parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01824 [NONE] `	struct mnt_idmap *idmap = mnt_idmap(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01826 [NONE] `	struct user_namespace *user_ns = mnt_user_ns(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] `	int inherited_flags = 0, flags = 0, i, nt_size = 0, pdacl_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] `	int rc = 0, pntsd_type, pntsd_size, acl_len, aces_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `	unsigned int dacloffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [NONE] `	size_t dacl_struct_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L01832 [NONE] `	size_t aces_buf_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `	u16 num_aces, ace_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] `	char *aces_base;`
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] `	bool is_dir = S_ISDIR(d_inode(path->dentry)->i_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01838 [NONE] `	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] `	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] `					    parent, &parent_pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `	if (pntsd_size <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01845 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [NONE] `	dacloffset = le32_to_cpu(parent_pntsd->dacloffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [NONE] `	if (!dacloffset ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [MEM_BOUNDS|] `	    check_add_overflow(dacloffset, sizeof(struct smb_acl), &dacl_struct_end) ||`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01849 [NONE] `	    dacl_struct_end > (size_t)pntsd_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [ERROR_PATH|] `		goto free_parent_pntsd;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01852 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] `	parent_pdacl = (struct smb_acl *)((char *)parent_pntsd + dacloffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [NONE] `	acl_len = pntsd_size - dacloffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01856 [NONE] `	num_aces = le16_to_cpu(parent_pdacl->num_aces);`
  Review: Low-risk line; verify in surrounding control flow.
- L01857 [NONE] `	pntsd_type = le16_to_cpu(parent_pntsd->type);`
  Review: Low-risk line; verify in surrounding control flow.
- L01858 [NONE] `	pdacl_size = le16_to_cpu(parent_pdacl->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [NONE] `	if (pdacl_size > acl_len || pdacl_size < sizeof(struct smb_acl)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [ERROR_PATH|] `		goto free_parent_pntsd;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01863 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01864 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] `	if (num_aces > (SIZE_MAX / (sizeof(struct smb_ace) * 2))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [ERROR_PATH|] `		goto free_parent_pntsd;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01868 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [NONE] `	aces_buf_size = sizeof(struct smb_ace) * num_aces * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [MEM_BOUNDS|] `	aces_base = kmalloc(aces_buf_size, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01872 [NONE] `	if (!aces_base) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [ERROR_PATH|] `		goto free_parent_pntsd;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01875 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01876 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [NONE] `	aces = (struct smb_ace *)aces_base;`
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] `	parent_aces = (struct smb_ace *)((char *)parent_pdacl +`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `			sizeof(struct smb_acl));`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [NONE] `	aces_size = acl_len - sizeof(struct smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01882 [NONE] `	if (pntsd_type & DACL_AUTO_INHERITED)`
  Review: Low-risk line; verify in surrounding control flow.
- L01883 [NONE] `		inherited_flags = INHERITED_ACE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [NONE] `	for (i = 0; i < num_aces; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01886 [NONE] `		int pace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] `		if (offsetof(struct smb_ace, access_req) > aces_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] `		pace_size = le16_to_cpu(parent_aces->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] `		if (pace_size > aces_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01895 [NONE] `		aces_size -= pace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01896 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [NONE] `		flags = parent_aces->flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01898 [NONE] `		if (!smb_inherit_flags(flags, is_dir))`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [ERROR_PATH|] `			goto pass;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01900 [NONE] `		if (is_dir) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] `			flags &= ~(INHERIT_ONLY_ACE | INHERITED_ACE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [NONE] `			if (!(flags & CONTAINER_INHERIT_ACE))`
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [NONE] `				flags |= INHERIT_ONLY_ACE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] `			if (flags & NO_PROPAGATE_INHERIT_ACE)`
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] `				flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] `			flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] `		if (!compare_sids(&creator_owner, &parent_aces->sid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [NONE] `			creator = &creator_owner;`
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] `			id_to_sid(uid, SIDOWNER, &owner_sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [NONE] `			psid = &owner_sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01914 [NONE] `		} else if (!compare_sids(&creator_group, &parent_aces->sid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [NONE] `			creator = &creator_group;`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] `			id_to_sid(gid, SIDUNIX_GROUP, &group_sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] `			psid = &group_sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01919 [NONE] `			creator = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [NONE] `			psid = &parent_aces->sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01921 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01923 [NONE] `		if (is_dir && creator && flags & CONTAINER_INHERIT_ACE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [NONE] `			__u16 asize = ksmbd_ace_size(psid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01925 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01926 [NONE] `			if (!asize ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01927 [NONE] `			    (unsigned int)nt_size + asize > aces_buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01928 [ERROR_PATH|] `				pr_err_ratelimited("inherit ACL overflow\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01929 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01930 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] `			smb_set_ace(aces, psid, parent_aces->type,`
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] `				    inherited_flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [NONE] `				    parent_aces->access_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01934 [NONE] `			nt_size += le16_to_cpu(aces->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [NONE] `			ace_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01936 [NONE] `			aces = (struct smb_ace *)((char *)aces +`
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] `					le16_to_cpu(aces->size));`
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] `			flags |= INHERIT_ONLY_ACE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [NONE] `			psid = creator;`
  Review: Low-risk line; verify in surrounding control flow.
- L01940 [NONE] `		} else if (is_dir && !(parent_aces->flags &`
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] `				       NO_PROPAGATE_INHERIT_ACE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `			psid = &parent_aces->sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01944 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L01946 [NONE] `			__u16 asize = ksmbd_ace_size(psid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01947 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01948 [NONE] `			if (!asize ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01949 [NONE] `			    (unsigned int)nt_size + asize > aces_buf_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01950 [ERROR_PATH|] `				pr_err_ratelimited("inherit ACL overflow\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01951 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01952 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01953 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [NONE] `		smb_set_ace(aces, psid, parent_aces->type,`
  Review: Low-risk line; verify in surrounding control flow.
- L01955 [NONE] `			    flags | inherited_flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L01956 [NONE] `			    parent_aces->access_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] `		nt_size += le16_to_cpu(aces->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [NONE] `		aces = (struct smb_ace *)((char *)aces +`
  Review: Low-risk line; verify in surrounding control flow.
- L01959 [NONE] `				le16_to_cpu(aces->size));`
  Review: Low-risk line; verify in surrounding control flow.
- L01960 [NONE] `		ace_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01961 [NONE] `pass:`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [NONE] `		parent_aces = (struct smb_ace *)((char *)parent_aces + pace_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01963 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01964 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01965 [NONE] `	if (nt_size > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [NONE] `		struct smb_ntsd *pntsd;`
  Review: Low-risk line; verify in surrounding control flow.
- L01967 [NONE] `		struct smb_acl *pdacl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [NONE] `		struct smb_sid *powner_sid = NULL, *pgroup_sid = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01969 [NONE] `		int powner_sid_size = 0, pgroup_sid_size = 0, pntsd_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [NONE] `		int pntsd_alloc_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01971 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [NONE] `		if (parent_pntsd->osidoffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01973 [NONE] `			powner_sid = (struct smb_sid *)((char *)parent_pntsd +`
  Review: Low-risk line; verify in surrounding control flow.
- L01974 [NONE] `					le32_to_cpu(parent_pntsd->osidoffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `			if (powner_sid->num_subauth > SID_MAX_SUB_AUTHORITIES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [ERROR_PATH|] `				goto free_aces_base;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01978 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] `			powner_sid_size = 1 + 1 + 6 + (powner_sid->num_subauth * 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01981 [NONE] `		if (parent_pntsd->gsidoffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01982 [NONE] `			pgroup_sid = (struct smb_sid *)((char *)parent_pntsd +`
  Review: Low-risk line; verify in surrounding control flow.
- L01983 [NONE] `					le32_to_cpu(parent_pntsd->gsidoffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L01984 [NONE] `			if (pgroup_sid->num_subauth > SID_MAX_SUB_AUTHORITIES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01985 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01986 [ERROR_PATH|] `				goto free_aces_base;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01987 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01988 [NONE] `			pgroup_sid_size = 1 + 1 + 6 + (pgroup_sid->num_subauth * 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01989 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01990 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01991 [NONE] `		pntsd_alloc_size = sizeof(struct smb_ntsd) + powner_sid_size +`
  Review: Low-risk line; verify in surrounding control flow.
- L01992 [NONE] `			pgroup_sid_size + sizeof(struct smb_acl) + nt_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01993 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01994 [MEM_BOUNDS|] `		pntsd = kzalloc(pntsd_alloc_size, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01995 [NONE] `		if (!pntsd) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01996 [NONE] `			rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01997 [ERROR_PATH|] `			goto free_aces_base;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01998 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01999 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02000 [NONE] `		pntsd->revision = cpu_to_le16(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02001 [NONE] `		pntsd->type = cpu_to_le16(SELF_RELATIVE | DACL_PRESENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L02002 [NONE] `		if (le16_to_cpu(parent_pntsd->type) & DACL_AUTO_INHERITED)`
  Review: Low-risk line; verify in surrounding control flow.
- L02003 [NONE] `			pntsd->type |= cpu_to_le16(DACL_AUTO_INHERITED);`
  Review: Low-risk line; verify in surrounding control flow.
- L02004 [NONE] `		pntsd_size = sizeof(struct smb_ntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02005 [NONE] `		pntsd->osidoffset = parent_pntsd->osidoffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02006 [NONE] `		pntsd->gsidoffset = parent_pntsd->gsidoffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02007 [NONE] `		pntsd->dacloffset = parent_pntsd->dacloffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02009 [NONE] `		if ((u64)le32_to_cpu(pntsd->osidoffset) + powner_sid_size >`
  Review: Low-risk line; verify in surrounding control flow.
- L02010 [NONE] `		    pntsd_alloc_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02011 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02012 [NONE] `			kfree(pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02013 [ERROR_PATH|] `			goto free_aces_base;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02014 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02016 [NONE] `		if ((u64)le32_to_cpu(pntsd->gsidoffset) + pgroup_sid_size >`
  Review: Low-risk line; verify in surrounding control flow.
- L02017 [NONE] `		    pntsd_alloc_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02018 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02019 [NONE] `			kfree(pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02020 [ERROR_PATH|] `			goto free_aces_base;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02021 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02023 [NONE] `		if ((u64)le32_to_cpu(pntsd->dacloffset) + sizeof(struct smb_acl) + nt_size >`
  Review: Low-risk line; verify in surrounding control flow.
- L02024 [NONE] `		    pntsd_alloc_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02025 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02026 [NONE] `			kfree(pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02027 [ERROR_PATH|] `			goto free_aces_base;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02028 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02030 [NONE] `		if (pntsd->osidoffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02031 [NONE] `			struct smb_sid *owner_sid = (struct smb_sid *)((char *)pntsd +`
  Review: Low-risk line; verify in surrounding control flow.
- L02032 [NONE] `					le32_to_cpu(pntsd->osidoffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L02033 [MEM_BOUNDS|] `			memcpy(owner_sid, powner_sid, powner_sid_size);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02034 [NONE] `			pntsd_size += powner_sid_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02035 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02037 [NONE] `		if (pntsd->gsidoffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02038 [NONE] `			struct smb_sid *group_sid = (struct smb_sid *)((char *)pntsd +`
  Review: Low-risk line; verify in surrounding control flow.
- L02039 [NONE] `					le32_to_cpu(pntsd->gsidoffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L02040 [MEM_BOUNDS|] `			memcpy(group_sid, pgroup_sid, pgroup_sid_size);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02041 [NONE] `			pntsd_size += pgroup_sid_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02042 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02044 [NONE] `		if (pntsd->dacloffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02045 [NONE] `			struct smb_ace *pace;`
  Review: Low-risk line; verify in surrounding control flow.
- L02046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02047 [NONE] `			pdacl = (struct smb_acl *)((char *)pntsd + le32_to_cpu(pntsd->dacloffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L02048 [NONE] `			pdacl->revision = cpu_to_le16(2);`
  Review: Low-risk line; verify in surrounding control flow.
- L02049 [NONE] `			pdacl->size = cpu_to_le16(sizeof(struct smb_acl) + nt_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02050 [NONE] `			pdacl->num_aces = cpu_to_le16(ace_cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02051 [NONE] `			pace = (struct smb_ace *)((char *)pdacl + sizeof(struct smb_acl));`
  Review: Low-risk line; verify in surrounding control flow.
- L02052 [MEM_BOUNDS|] `			memcpy(pace, aces_base, nt_size);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02053 [NONE] `			pntsd_size += sizeof(struct smb_acl) + nt_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02054 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02056 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02057 [NONE] `		ksmbd_vfs_set_sd_xattr(conn, idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02058 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02059 [NONE] `		ksmbd_vfs_set_sd_xattr(conn, user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02060 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02061 [NONE] `				       path, pntsd, pntsd_size, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L02062 [NONE] `		kfree(pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02063 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02065 [NONE] `free_aces_base:`
  Review: Low-risk line; verify in surrounding control flow.
- L02066 [NONE] `	kfree(aces_base);`
  Review: Low-risk line; verify in surrounding control flow.
- L02067 [NONE] `free_parent_pntsd:`
  Review: Low-risk line; verify in surrounding control flow.
- L02068 [NONE] `	kfree(parent_pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02069 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02070 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02072 [NONE] `bool smb_inherit_flags(int flags, bool is_dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L02073 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02074 [NONE] `	if (!is_dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L02075 [NONE] `		return (flags & OBJECT_INHERIT_ACE) != 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02077 [NONE] `	if (flags & OBJECT_INHERIT_ACE && !(flags & NO_PROPAGATE_INHERIT_ACE))`
  Review: Low-risk line; verify in surrounding control flow.
- L02078 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02080 [NONE] `	if (flags & CONTAINER_INHERIT_ACE)`
  Review: Low-risk line; verify in surrounding control flow.
- L02081 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02082 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L02083 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02085 [NONE] `int smb_check_perm_dacl(struct ksmbd_conn *conn, const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02086 [NONE] `			__le32 *pdaccess, int uid)`
  Review: Low-risk line; verify in surrounding control flow.
- L02087 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02088 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02089 [NONE] `	struct mnt_idmap *idmap = mnt_idmap(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02090 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02091 [NONE] `	struct user_namespace *user_ns = mnt_user_ns(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02092 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02093 [NONE] `	struct smb_ntsd *pntsd = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02094 [NONE] `	struct smb_acl *pdacl;`
  Review: Low-risk line; verify in surrounding control flow.
- L02095 [NONE] `	struct posix_acl *posix_acls;`
  Review: Low-risk line; verify in surrounding control flow.
- L02096 [NONE] `	int rc = 0, pntsd_size, acl_size, aces_size, pdacl_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02097 [NONE] `	unsigned int dacl_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02098 [NONE] `	size_t dacl_struct_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L02099 [NONE] `	struct smb_sid sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L02100 [NONE] `	int granted = le32_to_cpu(*pdaccess & ~FILE_MAXIMAL_ACCESS_LE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02101 [NONE] `	struct smb_ace *ace;`
  Review: Low-risk line; verify in surrounding control flow.
- L02102 [NONE] `	int i, found = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02103 [NONE] `	unsigned int access_bits = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02104 [NONE] `	struct smb_ace *others_ace = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02105 [NONE] `	struct posix_acl_entry *pa_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02106 [NONE] `	unsigned int sid_type = SIDOWNER;`
  Review: Low-risk line; verify in surrounding control flow.
- L02107 [NONE] `	unsigned short ace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02109 [NONE] `	ksmbd_debug(SMB, "check permission using windows acl\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02110 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02111 [NONE] `	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02112 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02113 [NONE] `	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02114 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02115 [NONE] `					    path->dentry, &pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02116 [NONE] `	if (pntsd_size <= 0 || !pntsd)`
  Review: Low-risk line; verify in surrounding control flow.
- L02117 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02119 [NONE] `	dacl_offset = le32_to_cpu(pntsd->dacloffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02120 [NONE] `	if (!dacl_offset ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02121 [MEM_BOUNDS|] `	    check_add_overflow(dacl_offset, sizeof(struct smb_acl), &dacl_struct_end) ||`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02122 [NONE] `	    dacl_struct_end > (size_t)pntsd_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L02123 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02125 [NONE] `	pdacl = (struct smb_acl *)((char *)pntsd + le32_to_cpu(pntsd->dacloffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L02126 [NONE] `	acl_size = pntsd_size - dacl_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02127 [NONE] `	pdacl_size = le16_to_cpu(pdacl->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02129 [NONE] `	if (pdacl_size > acl_size || pdacl_size < sizeof(struct smb_acl))`
  Review: Low-risk line; verify in surrounding control flow.
- L02130 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02132 [NONE] `	if (!pdacl->num_aces) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02133 [NONE] `		if (!(pdacl_size - sizeof(struct smb_acl)) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02134 [NONE] `		    *pdaccess & ~(FILE_READ_CONTROL_LE | FILE_WRITE_DAC_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02135 [NONE] `			rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02136 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02137 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02138 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02139 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02141 [NONE] `	if (*pdaccess & FILE_MAXIMAL_ACCESS_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02142 [NONE] `		granted = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES |`
  Review: Low-risk line; verify in surrounding control flow.
- L02143 [NONE] `			DELETE | SYNCHRONIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02145 [NONE] `		ace = (struct smb_ace *)((char *)pdacl + sizeof(struct smb_acl));`
  Review: Low-risk line; verify in surrounding control flow.
- L02146 [NONE] `		aces_size = acl_size - sizeof(struct smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02147 [NONE] `		for (i = 0; i < le16_to_cpu(pdacl->num_aces); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02148 [NONE] `			if (offsetof(struct smb_ace, access_req) > aces_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L02149 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02150 [NONE] `			ace_size = le16_to_cpu(ace->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02151 [NONE] `			if (ace_size > aces_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L02152 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02153 [NONE] `			aces_size -= ace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02154 [NONE] `			granted |= le32_to_cpu(ace->access_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L02155 [NONE] `			ace = (struct smb_ace *)((char *)ace + le16_to_cpu(ace->size));`
  Review: Low-risk line; verify in surrounding control flow.
- L02156 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02158 [NONE] `		if (!pdacl->num_aces)`
  Review: Low-risk line; verify in surrounding control flow.
- L02159 [NONE] `			granted = GENERIC_ALL_FLAGS;`
  Review: Low-risk line; verify in surrounding control flow.
- L02160 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02161 [NONE] `		/* MS-SMB2: extra bits requested alongside MAXIMUM_ALLOWED must`
  Review: Low-risk line; verify in surrounding control flow.
- L02162 [NONE] `		 * also be within the computed maximum grant; deny if not.`
  Review: Low-risk line; verify in surrounding control flow.
- L02163 [NONE] `		 * ACCESS_SYSTEM_SECURITY (0x01000000) requires SeSecurityPrivilege`
  Review: Low-risk line; verify in surrounding control flow.
- L02164 [ERROR_PATH|] `		 * which we don't implement; return -ENOKEY so the caller maps it`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02165 [PROTO_GATE|] `		 * to STATUS_PRIVILEGE_NOT_HELD.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02166 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L02167 [NONE] `		 * Generic rights are expanded to their file-specific equivalents`
  Review: Low-risk line; verify in surrounding control flow.
- L02168 [NONE] `		 * before checking.  GENERIC_EXECUTE is mapped without FILE_EXECUTE`
  Review: Low-risk line; verify in surrounding control flow.
- L02169 [NONE] `		 * because Windows treats it as satisfied whenever the other`
  Review: Low-risk line; verify in surrounding control flow.
- L02170 [NONE] `		 * READ_CONTROL / SYNCHRONIZE / FILE_READ_ATTRIBUTES overlap is`
  Review: Low-risk line; verify in surrounding control flow.
- L02171 [NONE] `		 * present (the Samba torture comment: "SEC_GENERIC_EXECUTE is a`
  Review: Low-risk line; verify in surrounding control flow.
- L02172 [NONE] `		 * complete subset of SEC_GENERIC_READ when mapped to specific`
  Review: Low-risk line; verify in surrounding control flow.
- L02173 [NONE] `		 * bits"). */`
  Review: Low-risk line; verify in surrounding control flow.
- L02174 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L02175 [NONE] `			unsigned int extra = le32_to_cpu(*pdaccess) &`
  Review: Low-risk line; verify in surrounding control flow.
- L02176 [NONE] `					     ~(unsigned int)0x02000000;`
  Review: Low-risk line; verify in surrounding control flow.
- L02177 [NONE] `			/* Expand generic bits to file-specific equivalents.`
  Review: Low-risk line; verify in surrounding control flow.
- L02178 [NONE] `			 * Bits 26-27 (0x04000000 / 0x08000000) are reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L02179 [NONE] `			 * propagate them directly into expanded so they are`
  Review: Low-risk line; verify in surrounding control flow.
- L02180 [NONE] `			 * denied (they are never in any DACL grant). */`
  Review: Low-risk line; verify in surrounding control flow.
- L02181 [NONE] `			unsigned int expanded = extra & 0x0CFFFFFFu;`
  Review: Low-risk line; verify in surrounding control flow.
- L02182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02183 [NONE] `			if (extra & 0x80000000u) /* GENERIC_READ */`
  Review: Low-risk line; verify in surrounding control flow.
- L02184 [NONE] `				expanded |= 0x00120089u; /* READ_CONTROL|SYNC|FILE_READ_DATA|FILE_READ_ATTR|FILE_READ_EA */`
  Review: Low-risk line; verify in surrounding control flow.
- L02185 [NONE] `			if (extra & 0x40000000u) /* GENERIC_WRITE */`
  Review: Low-risk line; verify in surrounding control flow.
- L02186 [NONE] `				expanded |= 0x00120116u; /* READ_CONTROL|SYNC|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_ATTR|FILE_WRITE_EA */`
  Review: Low-risk line; verify in surrounding control flow.
- L02187 [NONE] `			if (extra & 0x20000000u) /* GENERIC_EXECUTE */`
  Review: Low-risk line; verify in surrounding control flow.
- L02188 [NONE] `				expanded |= 0x00120080u; /* READ_CONTROL|SYNC|FILE_READ_ATTR (no FILE_EXECUTE) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02189 [NONE] `			if (extra & 0x10000000u) /* GENERIC_ALL */`
  Review: Low-risk line; verify in surrounding control flow.
- L02190 [NONE] `				expanded |= 0x001F01FFu; /* FILE_ALL_ACCESS */`
  Review: Low-risk line; verify in surrounding control flow.
- L02191 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02192 [NONE] `			/* SYSTEM_SECURITY is never in the DACL grant */`
  Review: Low-risk line; verify in surrounding control flow.
- L02193 [NONE] `			if (extra & 0x01000000u) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02194 [NONE] `				rc = -ENOKEY;`
  Review: Low-risk line; verify in surrounding control flow.
- L02195 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02196 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02197 [NONE] `			expanded &= ~0x01000000u;`
  Review: Low-risk line; verify in surrounding control flow.
- L02198 [NONE] `			if (expanded & ~(unsigned int)granted) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02199 [NONE] `				rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02200 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02201 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02202 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02203 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02205 [NONE] `	if (!uid)`
  Review: Low-risk line; verify in surrounding control flow.
- L02206 [NONE] `		sid_type = SIDUNIX_USER;`
  Review: Low-risk line; verify in surrounding control flow.
- L02207 [NONE] `	id_to_sid(uid, sid_type, &sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L02208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02209 [NONE] `	ace = (struct smb_ace *)((char *)pdacl + sizeof(struct smb_acl));`
  Review: Low-risk line; verify in surrounding control flow.
- L02210 [NONE] `	aces_size = acl_size - sizeof(struct smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02211 [NONE] `	for (i = 0; i < le16_to_cpu(pdacl->num_aces); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02212 [NONE] `		if (offsetof(struct smb_ace, access_req) > aces_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L02213 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02214 [NONE] `		ace_size = le16_to_cpu(ace->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02215 [NONE] `		if (ace_size > aces_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L02216 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02217 [NONE] `		aces_size -= ace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02219 [NONE] `		if (!compare_sids(&sid, &ace->sid) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02220 [NONE] `		    !compare_sids(&sid_unix_NFS_mode, &ace->sid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02221 [NONE] `			found = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02222 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02223 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02224 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02225 [NONE] `		 * CREATOR_OWNER (S-1-3-0): substitute the file's actual owner.`
  Review: Low-risk line; verify in surrounding control flow.
- L02226 [NONE] `		 * Per MS-DTYP §2.5.2.1, CREATOR_OWNER in a DACL applies to the`
  Review: Low-risk line; verify in surrounding control flow.
- L02227 [NONE] `		 * object's owner at access-check time.`
  Review: Low-risk line; verify in surrounding control flow.
- L02228 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02229 [NONE] `		if (!compare_sids(&creator_owner, &ace->sid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02230 [NONE] `			struct smb_sid owner_sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L02231 [NONE] `			unsigned int owner_uid = i_uid_read(d_inode(path->dentry));`
  Review: Low-risk line; verify in surrounding control flow.
- L02232 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02233 [NONE] `			id_to_sid(owner_uid,`
  Review: Low-risk line; verify in surrounding control flow.
- L02234 [NONE] `				  owner_uid ? SIDOWNER : SIDUNIX_USER,`
  Review: Low-risk line; verify in surrounding control flow.
- L02235 [NONE] `				  &owner_sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L02236 [NONE] `			if (!compare_sids(&sid, &owner_sid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02237 [NONE] `				found = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02238 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02239 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02240 [NONE] `			/* Not the owner: CREATOR_OWNER ACE doesn't apply */`
  Review: Low-risk line; verify in surrounding control flow.
- L02241 [NONE] `		} else if (!compare_sids(&sid_everyone, &ace->sid) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02242 [NONE] `			   !compare_sids(&sid_authusers, &ace->sid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02243 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02244 [NONE] `			 * S-1-1-0 (Everyone) and S-1-5-11 (Authenticated Users)`
  Review: Low-risk line; verify in surrounding control flow.
- L02245 [NONE] `			 * are group SIDs that apply to all authenticated users.`
  Review: Low-risk line; verify in surrounding control flow.
- L02246 [NONE] `			 * Treat them as catch-all ACEs (others_ace) so that files`
  Review: Low-risk line; verify in surrounding control flow.
- L02247 [NONE] `			 * protected only by Authenticated Users ACEs are`
  Review: Low-risk line; verify in surrounding control flow.
- L02248 [NONE] `			 * accessible to normal domain/local users.`
  Review: Low-risk line; verify in surrounding control flow.
- L02249 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02250 [NONE] `			others_ace = ace;`
  Review: Low-risk line; verify in surrounding control flow.
- L02251 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02253 [NONE] `		ace = (struct smb_ace *)((char *)ace + le16_to_cpu(ace->size));`
  Review: Low-risk line; verify in surrounding control flow.
- L02254 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02255 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02256 [NONE] `	if (*pdaccess & FILE_MAXIMAL_ACCESS_LE && found) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02257 [NONE] `		granted = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES |`
  Review: Low-risk line; verify in surrounding control flow.
- L02258 [NONE] `			DELETE | SYNCHRONIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02259 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02260 [NONE] `		granted |= le32_to_cpu(ace->access_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L02261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02262 [NONE] `		if (!pdacl->num_aces)`
  Review: Low-risk line; verify in surrounding control flow.
- L02263 [NONE] `			granted = GENERIC_ALL_FLAGS;`
  Review: Low-risk line; verify in surrounding control flow.
- L02264 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02266 [NONE] `	if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02267 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02268 [NONE] `		posix_acls = get_inode_acl(d_inode(path->dentry), ACL_TYPE_ACCESS);`
  Review: Low-risk line; verify in surrounding control flow.
- L02269 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02270 [NONE] `		posix_acls = get_acl(d_inode(path->dentry), ACL_TYPE_ACCESS);`
  Review: Low-risk line; verify in surrounding control flow.
- L02271 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02272 [NONE] `		if (!IS_ERR_OR_NULL(posix_acls) && !found) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02273 [NONE] `			unsigned int id = -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02274 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02275 [NONE] `			pa_entry = posix_acls->a_entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L02276 [NONE] `			for (i = 0; i < posix_acls->a_count; i++, pa_entry++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02277 [NONE] `				if (pa_entry->e_tag == ACL_USER)`
  Review: Low-risk line; verify in surrounding control flow.
- L02278 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02279 [NONE] `					id = posix_acl_uid_translate(idmap, pa_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02280 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02281 [NONE] `					id = posix_acl_uid_translate(user_ns, pa_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02282 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02283 [NONE] `				else if (pa_entry->e_tag == ACL_GROUP)`
  Review: Low-risk line; verify in surrounding control flow.
- L02284 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02285 [NONE] `					id = posix_acl_gid_translate(idmap, pa_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02286 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02287 [NONE] `					id = posix_acl_gid_translate(user_ns, pa_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02288 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02289 [NONE] `				else`
  Review: Low-risk line; verify in surrounding control flow.
- L02290 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02292 [NONE] `				if (id == uid) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02293 [NONE] `					mode_to_access_flags(pa_entry->e_perm,`
  Review: Low-risk line; verify in surrounding control flow.
- L02294 [NONE] `							     0777,`
  Review: Low-risk line; verify in surrounding control flow.
- L02295 [NONE] `							     &access_bits);`
  Review: Low-risk line; verify in surrounding control flow.
- L02296 [NONE] `					if (!access_bits)`
  Review: Low-risk line; verify in surrounding control flow.
- L02297 [NONE] `						access_bits =`
  Review: Low-risk line; verify in surrounding control flow.
- L02298 [NONE] `							SET_MINIMUM_RIGHTS;`
  Review: Low-risk line; verify in surrounding control flow.
- L02299 [NONE] `					posix_acl_release(posix_acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02300 [ERROR_PATH|] `					goto check_access_bits;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02301 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L02302 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02303 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02304 [NONE] `		if (!IS_ERR_OR_NULL(posix_acls))`
  Review: Low-risk line; verify in surrounding control flow.
- L02305 [NONE] `			posix_acl_release(posix_acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02306 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02308 [NONE] `	if (!found) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02309 [NONE] `		if (others_ace) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02310 [NONE] `			ace = others_ace;`
  Review: Low-risk line; verify in surrounding control flow.
- L02311 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02312 [NONE] `			ksmbd_debug(SMB, "Can't find corresponding sid\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02313 [NONE] `			rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02314 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02315 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02316 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02318 [NONE] `	switch (ace->type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02319 [NONE] `	case ACCESS_ALLOWED_ACE_TYPE:`
  Review: Low-risk line; verify in surrounding control flow.
- L02320 [NONE] `		access_bits = le32_to_cpu(ace->access_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L02321 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02322 [NONE] `	case ACCESS_DENIED_ACE_TYPE:`
  Review: Low-risk line; verify in surrounding control flow.
- L02323 [NONE] `	case ACCESS_DENIED_CALLBACK_ACE_TYPE:`
  Review: Low-risk line; verify in surrounding control flow.
- L02324 [NONE] `		access_bits = le32_to_cpu(~ace->access_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L02325 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02326 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02328 [NONE] `check_access_bits:`
  Review: Low-risk line; verify in surrounding control flow.
- L02329 [NONE] `	if (granted &`
  Review: Low-risk line; verify in surrounding control flow.
- L02330 [NONE] `	    ~(access_bits | FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | DELETE | SYNCHRONIZE | FILE_EXECUTE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02331 [NONE] `		ksmbd_debug(SMB, "Access denied with winACL, granted : %x, access_req : %x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02332 [NONE] `			    granted, le32_to_cpu(ace->access_req));`
  Review: Low-risk line; verify in surrounding control flow.
- L02333 [NONE] `		rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02334 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02335 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02336 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02337 [NONE] `	*pdaccess = cpu_to_le32(granted);`
  Review: Low-risk line; verify in surrounding control flow.
- L02338 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02339 [NONE] `	kfree(pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02340 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02341 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02343 [NONE] `int set_info_sec(struct ksmbd_conn *conn, struct ksmbd_tree_connect *tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L02344 [NONE] `		 const struct path *path, struct smb_ntsd *pntsd, int ntsd_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02345 [NONE] `		 bool type_check, bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L02346 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02347 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02348 [NONE] `	struct smb_fattr fattr = {{0}};`
  Review: Low-risk line; verify in surrounding control flow.
- L02349 [NONE] `	struct inode *inode = d_inode(path->dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02350 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02351 [NONE] `	struct mnt_idmap *idmap = mnt_idmap(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02352 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02353 [NONE] `	struct user_namespace *user_ns = mnt_user_ns(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02354 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02355 [NONE] `	struct iattr newattrs;`
  Review: Low-risk line; verify in surrounding control flow.
- L02356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02357 [NONE] `	fattr.cf_uid = INVALID_UID;`
  Review: Low-risk line; verify in surrounding control flow.
- L02358 [NONE] `	fattr.cf_gid = INVALID_GID;`
  Review: Low-risk line; verify in surrounding control flow.
- L02359 [NONE] `	fattr.cf_mode = inode->i_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L02360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02361 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02362 [NONE] `	rc = parse_sec_desc(idmap, pntsd, ntsd_len, &fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02363 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02364 [NONE] `	rc = parse_sec_desc(user_ns, pntsd, ntsd_len, &fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02365 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02366 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02367 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02368 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02369 [NONE] `	newattrs.ia_valid = ATTR_CTIME;`
  Review: Low-risk line; verify in surrounding control flow.
- L02370 [NONE] `	if (!uid_eq(fattr.cf_uid, INVALID_UID)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02371 [NONE] `		newattrs.ia_valid |= ATTR_UID;`
  Review: Low-risk line; verify in surrounding control flow.
- L02372 [NONE] `		newattrs.ia_uid = fattr.cf_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L02373 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02374 [NONE] `	if (!gid_eq(fattr.cf_gid, INVALID_GID)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02375 [NONE] `		inode->i_gid = fattr.cf_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L02376 [NONE] `		newattrs.ia_valid |= ATTR_GID;`
  Review: Low-risk line; verify in surrounding control flow.
- L02377 [NONE] `		newattrs.ia_gid = fattr.cf_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L02378 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02379 [NONE] `	newattrs.ia_valid |= ATTR_MODE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02380 [NONE] `	newattrs.ia_mode = (inode->i_mode & ~0777) | (fattr.cf_mode & 0777);`
  Review: Low-risk line; verify in surrounding control flow.
- L02381 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02382 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02383 [NONE] `	ksmbd_vfs_remove_acl_xattrs(idmap, path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02384 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02385 [NONE] `	ksmbd_vfs_remove_acl_xattrs(user_ns, path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02386 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02387 [NONE] `	/* Update posix acls */`
  Review: Low-risk line; verify in surrounding control flow.
- L02388 [NONE] `	if (IS_ENABLED(CONFIG_FS_POSIX_ACL) && fattr.cf_dacls) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02389 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02390 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02391 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02392 [NONE] `		rc = set_posix_acl(idmap, path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02393 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02394 [NONE] `		rc = set_posix_acl(user_ns, path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02395 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02396 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02397 [NONE] `		rc = set_posix_acl(user_ns, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02398 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02399 [NONE] `				   ACL_TYPE_ACCESS,`
  Review: Low-risk line; verify in surrounding control flow.
- L02400 [NONE] `				   fattr.cf_acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02401 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02402 [NONE] `		rc = set_posix_acl(inode, ACL_TYPE_ACCESS, fattr.cf_acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02403 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02404 [NONE] `		if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02405 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02406 [NONE] `				    "Set posix acl(ACL_TYPE_ACCESS) failed, rc : %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02407 [NONE] `				    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02408 [NONE] `		if (S_ISDIR(inode->i_mode) && fattr.cf_dacls) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02409 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02410 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02411 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02412 [NONE] `			rc = set_posix_acl(idmap, path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02413 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02414 [NONE] `			rc = set_posix_acl(user_ns, path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02415 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02416 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02417 [NONE] `			rc = set_posix_acl(user_ns, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02418 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02419 [NONE] `					   ACL_TYPE_DEFAULT, fattr.cf_dacls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02420 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02421 [NONE] `			rc = set_posix_acl(inode, ACL_TYPE_DEFAULT,`
  Review: Low-risk line; verify in surrounding control flow.
- L02422 [NONE] `					   fattr.cf_dacls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02423 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02424 [NONE] `			if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02425 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02426 [NONE] `					    "Set posix acl(ACL_TYPE_DEFAULT) failed, rc : %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02427 [NONE] `					    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02428 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02429 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02430 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02431 [NONE] `	inode_lock(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02432 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02433 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02434 [NONE] `	rc = notify_change(idmap, path->dentry, &newattrs, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02435 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02436 [NONE] `	rc = notify_change(user_ns, path->dentry, &newattrs, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02437 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02438 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02439 [NONE] `	rc = notify_change(path->dentry, &newattrs, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02440 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02441 [NONE] `	inode_unlock(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02442 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02443 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02445 [NONE] `	/* Check it only calling from SD BUFFER context */`
  Review: Low-risk line; verify in surrounding control flow.
- L02446 [NONE] `	if (type_check && !(le16_to_cpu(pntsd->type) & DACL_PRESENT))`
  Review: Low-risk line; verify in surrounding control flow.
- L02447 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02448 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02449 [NONE] `	if (test_share_config_flag(tcon->share_conf, KSMBD_SHARE_FLAG_ACL_XATTR)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02450 [NONE] `		/* Update WinACL in xattr */`
  Review: Low-risk line; verify in surrounding control flow.
- L02451 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02452 [NONE] `		ksmbd_vfs_remove_sd_xattrs(idmap, path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02453 [NONE] `		ksmbd_vfs_set_sd_xattr(conn, idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02454 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02455 [NONE] `		ksmbd_vfs_remove_sd_xattrs(user_ns, path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02456 [NONE] `		ksmbd_vfs_set_sd_xattr(conn, user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02457 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02458 [NONE] `				       path, pntsd, ntsd_len, get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L02459 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02460 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02461 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02462 [NONE] `	posix_acl_release(fattr.cf_acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02463 [NONE] `	posix_acl_release(fattr.cf_dacls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02464 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02465 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02466 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02467 [NONE] `void ksmbd_init_domain(u32 *sub_auth)`
  Review: Low-risk line; verify in surrounding control flow.
- L02468 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02469 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L02470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02471 [MEM_BOUNDS|] `	memcpy(&server_conf.domain_sid, &domain, sizeof(struct smb_sid));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02472 [NONE] `	for (i = 0; i < 3; ++i)`
  Review: Low-risk line; verify in surrounding control flow.
- L02473 [NONE] `		server_conf.domain_sid.sub_auth[i + 1] = cpu_to_le32(sub_auth[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L02474 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
