// SPDX-License-Identifier: LGPL-2.1+
/*
 *   Copyright (C) International Business Machines  Corp., 2007,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Copyright (C) 2020 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/fs.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
#include <linux/mnt_idmapping.h>
#endif

#include "smbacl.h"
#include "smb_common.h"
#include "server.h"
#include "misc.h"
#include "mgmt/share_config.h"
#include "vfs.h"
#include "xattr.h"
#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/visibility.h>
#else
#define VISIBLE_IF_KUNIT
#define EXPORT_SYMBOL_IF_KUNIT(sym)
#endif

static const struct smb_sid domain = {1, 4, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(21), cpu_to_le32(1), cpu_to_le32(2), cpu_to_le32(3),
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* security id for everyone/world system group */
static const struct smb_sid creator_owner = {
	1, 1, {0, 0, 0, 0, 0, 3}, {0} };
/* security id for everyone/world system group */
static const struct smb_sid creator_group = {
	1, 1, {0, 0, 0, 0, 0, 3}, {cpu_to_le32(1)} };

/* security id for everyone/world system group */
static const struct smb_sid sid_everyone = {
	1, 1, {0, 0, 0, 0, 0, 1}, {0} };
/* security id for Authenticated Users system group */
static const struct smb_sid sid_authusers = {
	1, 1, {0, 0, 0, 0, 0, 5}, {cpu_to_le32(11)} };

/* S-1-22-1 Unmapped Unix users */
static const struct smb_sid sid_unix_users = {1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-22-2 Unmapped Unix groups */
static const struct smb_sid sid_unix_groups = { 1, 1, {0, 0, 0, 0, 0, 22},
		{cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/*
 * See http://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx
 */

/* S-1-5-88 MS NFS and Fruit style UID/GID/mode */

/* S-1-5-88-1 Unix uid */
static const struct smb_sid sid_unix_NFS_users = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-2 Unix gid */
static const struct smb_sid sid_unix_NFS_groups = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(2), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/* S-1-5-88-3 Unix mode */
static const struct smb_sid sid_unix_NFS_mode = { 1, 2, {0, 0, 0, 0, 0, 5},
	{cpu_to_le32(88),
	 cpu_to_le32(3), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };

/*
 * if the two SIDs (roughly equivalent to a UUID for a user or group) are
 * the same returns zero, if they do not match returns non-zero.
 */
int compare_sids(const struct smb_sid *ctsid, const struct smb_sid *cwsid)
{
	int i;
	int num_subauth, num_subauth_w;

	if (!ctsid || !cwsid)
		return 1;

	/* compare the revision */
	if (ctsid->revision != cwsid->revision)
		return 1;

	/* compare the num_subauth */
	num_subauth = ctsid->num_subauth;
	num_subauth_w = cwsid->num_subauth;
	if (num_subauth != num_subauth_w)
		return 1;

	/*
	 * ACL-04: cap loop count to SID_MAX_SUB_AUTHORITIES to prevent OOB
	 * read if a crafted SID has num_subauth > 15 (the sub_auth[] maximum).
	 * Reject SIDs with excessive sub-authorities rather than iterating
	 * past the end of the fixed-size sub_auth array.
	 */
	if ((u8)num_subauth > SID_MAX_SUB_AUTHORITIES)
		return 1;

	/* compare all of the six auth_id bytes */
	for (i = 0; i < NUM_AUTHS; ++i) {
		if (ctsid->authority[i] != cwsid->authority[i])
			return 1;
	}

	for (i = 0; i < num_subauth; ++i) {
		if (ctsid->sub_auth[i] != cwsid->sub_auth[i])
			return 1;
	}

	return 0; /* sids compare/match */
}

VISIBLE_IF_KUNIT
void smb_copy_sid(struct smb_sid *dst, const struct smb_sid *src)
{
	int i;

	dst->revision = src->revision;
	dst->num_subauth = min_t(u8, src->num_subauth, SID_MAX_SUB_AUTHORITIES);
	for (i = 0; i < NUM_AUTHS; ++i)
		dst->authority[i] = src->authority[i];
	for (i = 0; i < dst->num_subauth; ++i)
		dst->sub_auth[i] = src->sub_auth[i];
}
EXPORT_SYMBOL_IF_KUNIT(smb_copy_sid);

/*
 * change posix mode to reflect permissions
 * pmode is the existing mode (we only want to overwrite part of this
 * bits to set can be: S_IRWXU, S_IRWXG or S_IRWXO ie 00700 or 00070 or 00007
 */
VISIBLE_IF_KUNIT
umode_t access_flags_to_mode(struct smb_fattr *fattr, __le32 ace_flags,
				    int type)
{
	__u32 flags = le32_to_cpu(ace_flags);
	umode_t mode = 0;

	if (flags & GENERIC_ALL) {
		mode = 0777;
		ksmbd_debug(SMB, "all perms\n");
		return mode;
	}

	if ((flags & GENERIC_READ) || (flags & FILE_READ_RIGHTS))
		mode = 0444;
	if ((flags & GENERIC_WRITE) || (flags & FILE_WRITE_RIGHTS)) {
		mode |= 0222;
		if (S_ISDIR(fattr->cf_mode))
			mode |= 0111;
	}
	if ((flags & GENERIC_EXECUTE) || (flags & FILE_EXEC_RIGHTS))
		mode |= 0111;

	if (type == ACCESS_DENIED_ACE_TYPE || type == ACCESS_DENIED_OBJECT_ACE_TYPE)
		mode = ~mode;

	ksmbd_debug(SMB, "access flags 0x%x mode now %04o\n", flags, mode);

	return mode;
}
EXPORT_SYMBOL_IF_KUNIT(access_flags_to_mode);

/*
 * Generate access flags to reflect permissions mode is the existing mode.
 * This function is called for every ACE in the DACL whose SID matches
 * with either owner or group or everyone.
 */
VISIBLE_IF_KUNIT
void mode_to_access_flags(umode_t mode, umode_t bits_to_use,
				 __u32 *pace_flags)
{
	/* reset access mask */
	*pace_flags = 0x0;

	/* bits to use are either S_IRWXU or S_IRWXG or S_IRWXO */
	mode &= bits_to_use;

	/*
	 * check for R/W/X UGO since we do not know whose flags
	 * is this but we have cleared all the bits sans RWX for
	 * either user or group or other as per bits_to_use
	 */
	if (mode & 0444)
		*pace_flags |= SET_FILE_READ_RIGHTS;
	if (mode & 0222)
		*pace_flags |= FILE_WRITE_RIGHTS;
	if (mode & 0111)
		*pace_flags |= SET_FILE_EXEC_RIGHTS;

	ksmbd_debug(SMB, "mode: %o, access flags now 0x%x\n",
		    mode, *pace_flags);
}
EXPORT_SYMBOL_IF_KUNIT(mode_to_access_flags);

/**
 * ksmbd_ace_size() - calculate ACE size for a given SID
 * @psid:	pointer to the SID
 *
 * Return:	size of the ACE in bytes, or 0 on overflow
 */
static __u16 ksmbd_ace_size(const struct smb_sid *psid)
{
	unsigned int size;

	if (check_add_overflow(1u + 1u + 2u + 4u + 1u + 1u + 6u,
			       (unsigned int)psid->num_subauth * 4u,
			       &size))
		return 0;
	if (size > U16_MAX)
		return 0;
	return (__u16)size;
}

VISIBLE_IF_KUNIT
size_t ksmbd_inherited_ace_size(const struct smb_ace *parent_ace,
				bool is_dir,
				const struct smb_sid *owner_sid,
				const struct smb_sid *group_sid)
{
	const struct smb_sid *psid;
	const struct smb_sid *creator;
	size_t total = 0;
	int flags;
	__u16 asize;

	if (!parent_ace)
		return 0;

	flags = parent_ace->flags;
	if (!smb_inherit_flags(flags, is_dir))
		return 0;

	if (is_dir) {
		flags &= ~(INHERIT_ONLY_ACE | INHERITED_ACE);
		if (!(flags & CONTAINER_INHERIT_ACE))
			flags |= INHERIT_ONLY_ACE;
		if (flags & NO_PROPAGATE_INHERIT_ACE)
			flags = 0;
	} else {
		flags = 0;
	}

	if (!compare_sids(&creator_owner, &parent_ace->sid)) {
		creator = &creator_owner;
		psid = owner_sid;
	} else if (!compare_sids(&creator_group, &parent_ace->sid)) {
		creator = &creator_group;
		psid = group_sid;
	} else {
		creator = NULL;
		psid = &parent_ace->sid;
	}

	if (is_dir && creator && flags & CONTAINER_INHERIT_ACE) {
		asize = ksmbd_ace_size(psid);
		if (!asize)
			return 0;
		total += asize;
		flags |= INHERIT_ONLY_ACE;
		psid = creator;
	} else if (is_dir &&
		   !(parent_ace->flags & NO_PROPAGATE_INHERIT_ACE)) {
		psid = &parent_ace->sid;
	}

	asize = ksmbd_ace_size(psid);
	if (!asize)
		return 0;
	total += asize;
	return total;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_inherited_ace_size);

VISIBLE_IF_KUNIT
__u16 fill_ace_for_sid(struct smb_ace *pntace,
			      const struct smb_sid *psid, int type,
			      int flags, umode_t mode, umode_t bits)
{
	int i;
	__u16 size;
	__u32 access_req = 0;

	size = ksmbd_ace_size(psid);
	if (!size)
		return 0;

	pntace->type = type;
	pntace->flags = flags;
	mode_to_access_flags(mode, bits, &access_req);
	if (!access_req)
		access_req = SET_MINIMUM_RIGHTS;
	pntace->access_req = cpu_to_le32(access_req);

	pntace->sid.revision = psid->revision;
	pntace->sid.num_subauth = psid->num_subauth;
	for (i = 0; i < NUM_AUTHS; i++)
		pntace->sid.authority[i] = psid->authority[i];
	for (i = 0; i < psid->num_subauth; i++)
		pntace->sid.sub_auth[i] = psid->sub_auth[i];

	pntace->size = cpu_to_le16(size);

	return size;
}
EXPORT_SYMBOL_IF_KUNIT(fill_ace_for_sid);

void id_to_sid(unsigned int cid, uint sidtype, struct smb_sid *ssid)
{
	switch (sidtype) {
	case SIDOWNER:
		smb_copy_sid(ssid, &server_conf.domain_sid);
		break;
	case SIDUNIX_USER:
		smb_copy_sid(ssid, &sid_unix_users);
		break;
	case SIDUNIX_GROUP:
		smb_copy_sid(ssid, &sid_unix_groups);
		break;
	case SIDCREATOR_OWNER:
		smb_copy_sid(ssid, &creator_owner);
		return;
	case SIDCREATOR_GROUP:
		smb_copy_sid(ssid, &creator_group);
		return;
	case SIDNFS_USER:
		smb_copy_sid(ssid, &sid_unix_NFS_users);
		break;
	case SIDNFS_GROUP:
		smb_copy_sid(ssid, &sid_unix_NFS_groups);
		break;
	case SIDNFS_MODE:
		smb_copy_sid(ssid, &sid_unix_NFS_mode);
		break;
	default:
		return;
	}

	/* RID */
	if (ssid->num_subauth < SID_MAX_SUB_AUTHORITIES) {
		ssid->sub_auth[ssid->num_subauth] = cpu_to_le32(cid);
		ssid->num_subauth++;
	}
}

/*
 * Domain-aware SID-to-UID mapping helpers.
 *
 * SECURITY FIX: Previously, sid_to_id() extracted only the last
 * sub-authority (RID) from a Windows SID and used it directly as the
 * Linux UID.  This meant that DOMAIN1\alice (S-1-5-21-X-Y-Z-500) and
 * DOMAIN2\alice (S-1-5-21-A-B-C-500) would both map to UID 500,
 * causing incorrect ACL application and quota bypass in multi-domain
 * Active Directory environments.
 *
 * The fix adds domain SID validation:
 *   - Well-known SIDs (S-1-22-*, S-1-5-88-*) pass through unchanged.
 *   - SIDs whose domain prefix matches server_conf.domain_sid use the
 *     RID directly (preserving backward compatibility).
 *   - SIDs from foreign domains get a hash-based offset applied to
 *     their RID to prevent UID collisions across domains.
 *   - Bounds checking rejects RIDs that would overflow uid_t after
 *     the offset is applied.
 */

/**
 * ksmbd_extract_domain_prefix() - extract the domain portion of a SID
 * @sid:        input SID (must have num_subauth >= 1)
 * @domain_out: output SID containing all sub-authorities except the last (RID)
 *
 * For a SID like S-1-5-21-A-B-C-500, this extracts S-1-5-21-A-B-C
 * (everything except the final RID sub-authority).
 *
 * Return: 0 on success, -EINVAL on invalid input
 */
int ksmbd_extract_domain_prefix(const struct smb_sid *sid,
				struct smb_sid *domain_out)
{
	int i;

	if (!sid || !domain_out)
		return -EINVAL;

	if (sid->num_subauth == 0 ||
	    sid->num_subauth > SID_MAX_SUB_AUTHORITIES)
		return -EINVAL;

	domain_out->revision = sid->revision;
	domain_out->num_subauth = sid->num_subauth - 1;
	for (i = 0; i < NUM_AUTHS; i++)
		domain_out->authority[i] = sid->authority[i];
	for (i = 0; i < domain_out->num_subauth; i++)
		domain_out->sub_auth[i] = sid->sub_auth[i];

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_extract_domain_prefix);

/**
 * ksmbd_domain_sid_hash() - compute a hash of a SID's domain prefix
 * @sid: input SID
 *
 * Hashes the authority and all sub-authorities except the last (which
 * is the RID).  Uses a simple DJB2-style hash for speed and adequate
 * distribution.
 *
 * Return: 32-bit hash value (0 if SID is NULL or has no domain portion)
 */
u32 ksmbd_domain_sid_hash(const struct smb_sid *sid)
{
	u32 hash = 5381;
	int i;
	int domain_subauth_count;

	if (!sid || sid->num_subauth <= 1)
		return 0;

	domain_subauth_count = sid->num_subauth - 1;

	/* Hash the authority bytes */
	for (i = 0; i < NUM_AUTHS; i++)
		hash = hash * 33 + sid->authority[i];

	/* Hash the domain sub-authorities (everything except the RID) */
	for (i = 0; i < domain_subauth_count; i++) {
		u32 sa = le32_to_cpu(sid->sub_auth[i]);

		hash = hash * 33 + (sa & 0xFF);
		hash = hash * 33 + ((sa >> 8) & 0xFF);
		hash = hash * 33 + ((sa >> 16) & 0xFF);
		hash = hash * 33 + ((sa >> 24) & 0xFF);
	}

	return hash;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_domain_sid_hash);

/**
 * ksmbd_sid_domain_match() - check if a SID belongs to the server's domain
 * @sid: the SID to check
 *
 * Compares the domain portion of @sid (all sub-authorities except the
 * last) against server_conf.domain_sid.  Well-known SIDs from the
 * Unix user/group namespaces (S-1-22-*) and NFS namespaces (S-1-5-88-*)
 * are always treated as matching (local).
 *
 * Return: true if the SID is from the server's domain or a well-known
 *         local namespace, false otherwise
 */
bool ksmbd_sid_domain_match(const struct smb_sid *sid)
{
	int i;
	const struct smb_sid *dom = &server_conf.domain_sid;
	int domain_subauth_count;

	if (!sid || sid->num_subauth == 0)
		return false;

	/*
	 * Well-known local SIDs always match:
	 * S-1-22-1-* (Unix users), S-1-22-2-* (Unix groups)
	 */
	if (sid->authority[5] == 22 &&
	    (sid->authority[0] | sid->authority[1] | sid->authority[2] |
	     sid->authority[3] | sid->authority[4]) == 0)
		return true;

	/*
	 * NFS-style SIDs: S-1-5-88-{1,2,3}-*
	 */
	if (sid->authority[5] == 5 &&
	    (sid->authority[0] | sid->authority[1] | sid->authority[2] |
	     sid->authority[3] | sid->authority[4]) == 0 &&
	    sid->num_subauth >= 2 &&
	    le32_to_cpu(sid->sub_auth[0]) == 88)
		return true;

	/*
	 * Compare the domain prefix: the server's domain_sid has
	 * num_subauth sub-authorities (typically 4 for S-1-5-21-X-Y-Z).
	 * The incoming SID must have at least one more (the RID).
	 * We compare all of the domain_sid's sub-authorities against
	 * the corresponding leading sub-authorities of the incoming SID.
	 */
	domain_subauth_count = dom->num_subauth;
	if (sid->num_subauth <= domain_subauth_count)
		return false;

	/* Compare revision and authority */
	if (sid->revision != dom->revision)
		return false;
	for (i = 0; i < NUM_AUTHS; i++) {
		if (sid->authority[i] != dom->authority[i])
			return false;
	}

	/* Compare domain sub-authorities */
	for (i = 0; i < domain_subauth_count; i++) {
		if (sid->sub_auth[i] != dom->sub_auth[i])
			return false;
	}

	return true;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_sid_domain_match);

/**
 * ksmbd_validate_sid_to_uid() - domain-aware SID to UID conversion
 * @psid:    the input SID to convert
 * @uid_out: [out] the resulting UID
 *
 * Converts a Windows SID to a Linux UID with domain awareness:
 *   - Rejects NULL SIDs, SIDs with 0 or >15 sub-authorities
 *   - Rejects the well-known Everyone SID (S-1-1-0)
 *   - For SIDs matching the server's domain, uses the RID directly
 *   - For foreign-domain SIDs, applies a hash-based offset to prevent
 *     UID collisions: uid = rid + (hash(domain) % MULTIPLIER) * MULTIPLIER
 *   - Rejects if the resulting UID would overflow uid_t
 *
 * This function is also exported for KUnit testing.
 *
 * Return: 0 on success with *uid_out set, negative errno on failure
 */
VISIBLE_IF_KUNIT
int ksmbd_sid_to_id_domain_aware(struct smb_sid *psid, uid_t *id_out)
{
	uid_t rid;
	u32 hash_val, offset;

	if (!psid || !id_out)
		return -EINVAL;

	if (psid->num_subauth == 0 ||
	    psid->num_subauth > SID_MAX_SUB_AUTHORITIES)
		return -EINVAL;

	/* Reject the Everyone SID (S-1-1-0) */
	if (!compare_sids(psid, &sid_everyone))
		return -EIO;

	rid = le32_to_cpu(psid->sub_auth[psid->num_subauth - 1]);

	/*
	 * If the SID belongs to the server's configured domain or is
	 * a well-known local SID, use the RID directly (backward compat).
	 */
	if (ksmbd_sid_domain_match(psid)) {
		*id_out = rid;
		return 0;
	}

	/*
	 * Foreign domain SID: apply a domain-hash offset so that the
	 * same RID from different domains maps to different UIDs.
	 *
	 * offset = (hash(domain_prefix) % MULTIPLIER + 1) * MULTIPLIER
	 *
	 * This ensures:
	 *   - offset is always > 0 (so foreign UIDs never collide with local)
	 *   - offset is always a multiple of MULTIPLIER (predictable ranges)
	 *   - different domain hashes produce different offsets with high
	 *     probability
	 */
	hash_val = ksmbd_domain_sid_hash(psid);
	offset = ((hash_val % DOMAIN_UID_OFFSET_MULTIPLIER) + 1) *
		 DOMAIN_UID_OFFSET_MULTIPLIER;

	/* Bounds check: reject if RID + offset would overflow uid_t */
	if (rid > U32_MAX - offset) {
		pr_err("SID RID %u + domain offset %u would overflow uid_t\n",
		       rid, offset);
		return KSMBD_STATUS_NONE_MAPPED;
	}

	*id_out = rid + offset;

	/*
	 * ACL-03: hardening against DJB2 hash collisions that could map a
	 * crafted foreign-domain SID to UID 0 (root).  The offset formula
	 * ensures offset > 0, so the only way to reach uid 0 would be via
	 * a hash collision producing offset = 0 — which cannot happen because
	 * the formula adds 1 before multiplying.  As a belt-and-suspenders
	 * defence, explicitly reject any mapping to UID 0.
	 */
	if (*id_out == 0) {
		pr_warn_ratelimited("SID-to-UID mapping would produce uid 0 — rejected for security\n");
		return -EACCES;
	}

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_sid_to_id_domain_aware);

/**
 * ksmbd_validate_sid_to_uid() - public API for domain-aware SID-to-UID mapping
 * @psid:    the input SID
 * @uid_out: [out] the resulting UID
 *
 * Wrapper around ksmbd_sid_to_id_domain_aware() for callers outside smbacl.c.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_validate_sid_to_uid(struct smb_sid *psid, uid_t *uid_out)
{
	return ksmbd_sid_to_id_domain_aware(psid, uid_out);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int sid_to_id(struct mnt_idmap *idmap,
#else
static int sid_to_id(struct user_namespace *user_ns,
#endif
		     struct smb_sid *psid, uint sidtype,
		     struct smb_fattr *fattr)
{
	int rc = -EINVAL;

	/*
	 * If we have too many subauthorities, then something is really wrong.
	 * Just return an error.
	 */
	if (unlikely(psid->num_subauth > SID_MAX_SUB_AUTHORITIES)) {
		pr_err("%s: %u subauthorities is too many!\n",
		       __func__, psid->num_subauth);
		return -EIO;
	}

	if (!compare_sids(psid, &sid_everyone))
		return -EIO;

	if (psid->num_subauth == 0) {
		pr_err("%s: zero subauthorities!\n", __func__);
		return -EIO;
	}

	if (sidtype == SIDOWNER) {
		kuid_t uid;
		uid_t id;

		/*
		 * SECURITY: Use domain-aware mapping to prevent SID
		 * collision across domains.  ksmbd_sid_to_id_domain_aware()
		 * applies a hash-based offset for foreign-domain SIDs.
		 */
		rc = ksmbd_sid_to_id_domain_aware(psid, &id);
		if (rc) {
			pr_err("%s: domain-aware SID-to-UID mapping failed: %d\n",
			       __func__, rc);
			return rc;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 52) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
		uid = KUIDT_INIT(id);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		uid = from_vfsuid(idmap, &init_user_ns, VFSUIDT_INIT(uid));
#else
		uid = from_vfsuid(user_ns, &init_user_ns, VFSUIDT_INIT(uid));
#endif
#else
		uid = mapped_kuid_user(user_ns, &init_user_ns, KUIDT_INIT(id));
#endif
#else
		/*
		 * Translate raw sid into kuid in the server's user
		 * namespace.
		 */
		uid = make_kuid(&init_user_ns, id);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		/* If this is an idmapped mount, apply the idmapping. */
		uid = kuid_from_mnt(user_ns, uid);
#endif
#endif
		if (uid_valid(uid)) {
			fattr->cf_uid = uid;
			rc = 0;
		}
	} else {
		kgid_t gid;
		gid_t id;
		uid_t raw_id;

		/*
		 * SECURITY: Use domain-aware mapping for GIDs too,
		 * preventing GID collisions across domains.
		 */
		rc = ksmbd_sid_to_id_domain_aware(psid, &raw_id);
		if (rc) {
			pr_err("%s: domain-aware SID-to-GID mapping failed: %d\n",
			       __func__, rc);
			return rc;
		}
		id = (gid_t)raw_id;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) || \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 52) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
		gid = KGIDT_INIT(id);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		gid = from_vfsgid(idmap, &init_user_ns, VFSGIDT_INIT(gid));
#else
		gid = from_vfsgid(user_ns, &init_user_ns, VFSGIDT_INIT(gid));
#endif
#else
		gid = mapped_kgid_user(user_ns, &init_user_ns, KGIDT_INIT(id));
#endif
#else
		/*
		 * Translate raw sid into kgid in the server's user
		 * namespace.
		 */
		gid = make_kgid(&init_user_ns, id);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		/* If this is an idmapped mount, apply the idmapping. */
		gid = kgid_from_mnt(user_ns, gid);
#endif
#endif
		if (gid_valid(gid)) {
			fattr->cf_gid = gid;
			rc = 0;
		}
	}

	return rc;
}

void posix_state_to_acl(struct posix_acl_state *state,
			struct posix_acl_entry *pace)
{
	int i;

	pace->e_tag = ACL_USER_OBJ;
	pace->e_perm = state->owner.allow;
	for (i = 0; i < state->users->n; i++) {
		pace++;
		pace->e_tag = ACL_USER;
		pace->e_uid = state->users->aces[i].uid;
		pace->e_perm = state->users->aces[i].perms.allow;
	}

	pace++;
	pace->e_tag = ACL_GROUP_OBJ;
	pace->e_perm = state->group.allow;

	for (i = 0; i < state->groups->n; i++) {
		pace++;
		pace->e_tag = ACL_GROUP;
		pace->e_gid = state->groups->aces[i].gid;
		pace->e_perm = state->groups->aces[i].perms.allow;
	}

	if (state->users->n || state->groups->n) {
		pace++;
		pace->e_tag = ACL_MASK;
		pace->e_perm = state->mask.allow;
	}

	pace++;
	pace->e_tag = ACL_OTHER;
	pace->e_perm = state->other.allow;
}

int init_acl_state(struct posix_acl_state *state, u16 cnt)
{
	size_t alloc;

	memset(state, 0, sizeof(struct posix_acl_state));
	/*
	 * In the worst case, each individual acl could be for a distinct
	 * named user or group, but we don't know which, so we allocate
	 * enough space for either:
	 */
	/*
	 * Allocate cnt + 2 entries: the loop may use up to cnt slots for
	 * foreign SIDs, and the post-loop owner_found / group_found blocks
	 * each write one additional entry.
	 */
	alloc = sizeof(struct posix_ace_state_array)
		+ ((size_t)cnt + 2) * sizeof(struct posix_user_ace_state);
	state->users = kzalloc(alloc, KSMBD_DEFAULT_GFP);
	if (!state->users)
		return -ENOMEM;
	state->groups = kzalloc(alloc, KSMBD_DEFAULT_GFP);
	if (!state->groups) {
		kfree(state->users);
		return -ENOMEM;
	}
	return 0;
}

void free_acl_state(struct posix_acl_state *state)
{
	kfree(state->users);
	kfree(state->groups);
}

/*
 * ACL-03: MS-DTYP §2.4.4.3 — Object ACE types (0x05-0x08, 0x0B-0x10) have
 * optional GUID fields between access_req and the SID.  ObjectFlags (first
 * 4 bytes after access_req) controls which GUIDs are present:
 *   bit 0x01: ObjectType GUID (16 bytes)
 *   bit 0x02: InheritedObjectType GUID (16 bytes)
 *
 * Returns the actual SID pointer inside the ACE, or NULL if the ACE is
 * too short to contain a valid SID.
 */
static struct smb_sid *smb_ace_get_sid(const struct smb_ace *ace,
				       const char *end_of_acl)
{
	const u8 *ptr = (const u8 *)ace;
	u32 obj_flags;
	size_t offset;

	switch (ace->type) {
	case ACCESS_ALLOWED_OBJECT_ACE_TYPE:      /* 0x05 */
	case ACCESS_DENIED_OBJECT_ACE_TYPE:       /* 0x06 */
	case SYSTEM_AUDIT_OBJECT_ACE_TYPE:        /* 0x07 */
	case SYSTEM_ALARM_OBJECT_ACE_TYPE:        /* 0x08 */
	case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: /* 0x0B */
	case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:  /* 0x0C */
	case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:   /* 0x0F */
	case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:   /* 0x10 */
		/* base offset: past type+flags+size+access_req */
		offset = offsetof(struct smb_ace, sid);
		/* check enough room for ObjectFlags field */
		if ((const char *)(ptr + offset + 4) > end_of_acl)
			return NULL;
		obj_flags = le32_to_cpu(*((__le32 *)(ptr + offset)));
		offset += 4; /* skip ObjectFlags */
		if (obj_flags & 0x01) {
			/* skip ObjectType GUID (16 bytes) */
			offset += 16;
		}
		if (obj_flags & 0x02) {
			/* skip InheritedObjectType GUID (16 bytes) */
			offset += 16;
		}
		/* validate SID fits within ACE */
		if ((const char *)(ptr + offset +
				   offsetof(struct smb_sid, sub_auth)) > end_of_acl)
			return NULL;
		return (struct smb_sid *)(ptr + offset);
	default:
		return &((struct smb_ace *)ace)->sid;
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
VISIBLE_IF_KUNIT
void parse_dacl(struct mnt_idmap *idmap,
#else
VISIBLE_IF_KUNIT
void parse_dacl(struct user_namespace *user_ns,
#endif
		       struct smb_acl *pdacl, char *end_of_acl,
		       struct smb_sid *pownersid, struct smb_sid *pgrpsid,
		       struct smb_fattr *fattr)
{
	int i, ret;
	u16 num_aces = 0;
	unsigned int acl_size;
	char *acl_base;
	struct smb_ace **ppace;
	struct posix_acl_entry *cf_pace, *cf_pdace;
	struct posix_acl_state acl_state, default_acl_state;
	umode_t mode = 0, acl_mode;
	bool owner_found = false, group_found = false, others_found = false;

	if (!pdacl)
		return;

	/* validate that we do not go past end of acl */
	if (end_of_acl < (char *)pdacl + sizeof(struct smb_acl) ||
	    end_of_acl < (char *)pdacl + le16_to_cpu(pdacl->size)) {
		pr_err("ACL too small to parse DACL\n");
		return;
	}

	ksmbd_debug(SMB, "DACL revision %d size %d num aces %d\n",
		    le16_to_cpu(pdacl->revision), le16_to_cpu(pdacl->size),
		    le16_to_cpu(pdacl->num_aces));

	/* ACL-05: Validate ACL revision (MS-DTYP §2.4.5) */
	{
		__u16 acl_rev = le16_to_cpu(pdacl->revision);

		if (acl_rev != 0x02 && acl_rev != 0x04) {
			pr_err("Invalid DACL revision: 0x%x\n", acl_rev);
			return;
		}
	}

	acl_base = (char *)pdacl;
	acl_size = sizeof(struct smb_acl);

	num_aces = le16_to_cpu(pdacl->num_aces);
	if (num_aces <= 0)
		return;

	/* Validate ACE count against available buffer space */
	if (num_aces > (le16_to_cpu(pdacl->size) -
			sizeof(struct smb_acl)) /
			(offsetof(struct smb_ace, sid) +
			 offsetof(struct smb_sid, sub_auth) +
			 sizeof(__le16))) {
		pr_err_ratelimited("ACE count %u exceeds buffer capacity\n",
				   num_aces);
		return;
	}

	ret = init_acl_state(&acl_state, num_aces);
	if (ret)
		return;
	ret = init_acl_state(&default_acl_state, num_aces);
	if (ret) {
		free_acl_state(&acl_state);
		return;
	}

	ppace = kmalloc_array(num_aces, sizeof(struct smb_ace *), KSMBD_DEFAULT_GFP);
	if (!ppace) {
		free_acl_state(&default_acl_state);
		free_acl_state(&acl_state);
		return;
	}

	/*
	 * reset rwx permissions for user/group/other.
	 * Also, if num_aces is 0 i.e. DACL has no ACEs,
	 * user/group/other have no permissions
	 */
	for (i = 0; i < num_aces; ++i) {
		struct smb_sid *sid_ptr;

		if (end_of_acl - acl_base < acl_size)
			break;

		ppace[i] = (struct smb_ace *)(acl_base + acl_size);
		acl_base = (char *)ppace[i];
		acl_size = offsetof(struct smb_ace, sid) +
			offsetof(struct smb_sid, sub_auth);

		/*
		 * ACL-03: Determine if this ACE type has optional GUID fields
		 * before the SID (MS-DTYP §2.4.4.3 — Object ACE types).
		 * For non-object ACEs, validate num_subauth as before.
		 */
		{
			bool is_object_ace;

			switch (ppace[i]->type) {
			case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
			case ACCESS_DENIED_OBJECT_ACE_TYPE:
			case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
			case SYSTEM_ALARM_OBJECT_ACE_TYPE:
			case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
			case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
			case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
			case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
				is_object_ace = true;
				break;
			default:
				is_object_ace = false;
				break;
			}

			if (!is_object_ace) {
				if (end_of_acl - acl_base < acl_size ||
				    ppace[i]->sid.num_subauth == 0 ||
				    ppace[i]->sid.num_subauth > SID_MAX_SUB_AUTHORITIES ||
				    (end_of_acl - acl_base <
				     acl_size + sizeof(__le32) * ppace[i]->sid.num_subauth) ||
				    (le16_to_cpu(ppace[i]->size) <
				     acl_size + sizeof(__le32) * ppace[i]->sid.num_subauth))
					break;
			}
			/* else: object ACE — smb_ace_get_sid() handles bounds */
		}

		acl_size = le16_to_cpu(ppace[i]->size);
		ppace[i]->access_req =
			smb_map_generic_desired_access(ppace[i]->access_req);

		/*
		 * ACL-03: Compute actual SID pointer, accounting for optional
		 * GUID fields in Object ACE types (MS-DTYP §2.4.4.3).
		 */
		sid_ptr = smb_ace_get_sid(ppace[i], end_of_acl);
		if (!sid_ptr)
			continue;

		/*
		 * ACL-02: validate SID bounds for both non-object and object
		 * ACEs.  Non-object ACEs are validated above (before calling
		 * smb_ace_get_sid).  Object ACEs compute the SID via
		 * smb_ace_get_sid() which only does a coarse end_of_acl check;
		 * call parse_sid() to fully validate num_subauth and bounds.
		 */
		if (parse_sid(sid_ptr, end_of_acl))
			continue;

		if (!(compare_sids(sid_ptr, &sid_unix_NFS_mode))) {
			fattr->cf_mode =
				le32_to_cpu(sid_ptr->sub_auth[2]);
			break;
		} else if (!compare_sids(sid_ptr, pownersid)) {
			acl_mode = access_flags_to_mode(fattr,
							ppace[i]->access_req,
							ppace[i]->type);
			acl_mode &= 0700;

			if (!owner_found) {
				mode &= ~(0700);
				mode |= acl_mode;
			}
			owner_found = true;
		} else if (!compare_sids(sid_ptr, pgrpsid) ||
			   sid_ptr->sub_auth[sid_ptr->num_subauth - 1] ==
			    DOMAIN_USER_RID_LE) {
			acl_mode = access_flags_to_mode(fattr,
							ppace[i]->access_req,
							ppace[i]->type);
			acl_mode &= 0070;
			if (!group_found) {
				mode &= ~(0070);
				mode |= acl_mode;
			}
			group_found = true;
		} else if (!compare_sids(sid_ptr, &sid_everyone)) {
			acl_mode = access_flags_to_mode(fattr,
							ppace[i]->access_req,
							ppace[i]->type);
			acl_mode &= 0007;
			if (!others_found) {
				mode &= ~(0007);
				mode |= acl_mode;
			}
			others_found = true;
		} else if (!compare_sids(sid_ptr, &creator_owner)) {
			continue;
		} else if (!compare_sids(sid_ptr, &creator_group)) {
			continue;
		} else if (!compare_sids(sid_ptr, &sid_authusers)) {
			continue;
		} else {
			struct smb_fattr temp_fattr;

			acl_mode = access_flags_to_mode(fattr, ppace[i]->access_req,
							ppace[i]->type);
			temp_fattr.cf_uid = INVALID_UID;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			ret = sid_to_id(idmap, sid_ptr, SIDOWNER, &temp_fattr);
#else
			ret = sid_to_id(user_ns, sid_ptr, SIDOWNER, &temp_fattr);
#endif
			if (ret || uid_eq(temp_fattr.cf_uid, INVALID_UID)) {
				pr_err("%s: Error %d mapping Owner SID to uid\n",
				       __func__, ret);
				continue;
			}

			/*
			 * VFS-10: bounds check before writing into aces[].
			 * init_acl_state allocates num_aces+2 slots; the loop
			 * may write up to num_aces foreign-SID entries, leaving
			 * 2 slots for the post-loop owner_found/group_found writes.
			 */
			if (acl_state.users->n >= num_aces ||
			    default_acl_state.users->n >= num_aces)
				break;

			acl_state.owner.allow = ((acl_mode & 0700) >> 6) | 0004;
			acl_state.users->aces[acl_state.users->n].uid =
				temp_fattr.cf_uid;
			acl_state.users->aces[acl_state.users->n++].perms.allow =
				((acl_mode & 0700) >> 6) | 0004;
			default_acl_state.owner.allow = ((acl_mode & 0700) >> 6) | 0004;
			default_acl_state.users->aces[default_acl_state.users->n].uid =
				temp_fattr.cf_uid;
			default_acl_state.users->aces[default_acl_state.users->n++].perms.allow =
				((acl_mode & 0700) >> 6) | 0004;
		}
	}
	kfree(ppace);

	if (owner_found) {
		/* The owner must be set to at least read-only. */
		acl_state.owner.allow = ((mode & 0700) >> 6) | 0004;
		acl_state.users->aces[acl_state.users->n].uid = fattr->cf_uid;
		acl_state.users->aces[acl_state.users->n++].perms.allow =
			((mode & 0700) >> 6) | 0004;
		default_acl_state.owner.allow = ((mode & 0700) >> 6) | 0004;
		default_acl_state.users->aces[default_acl_state.users->n].uid =
			fattr->cf_uid;
		default_acl_state.users->aces[default_acl_state.users->n++].perms.allow =
			((mode & 0700) >> 6) | 0004;
	}

	if (group_found) {
		acl_state.group.allow = (mode & 0070) >> 3;
		acl_state.groups->aces[acl_state.groups->n].gid =
			fattr->cf_gid;
		acl_state.groups->aces[acl_state.groups->n++].perms.allow =
			(mode & 0070) >> 3;
		default_acl_state.group.allow = (mode & 0070) >> 3;
		default_acl_state.groups->aces[default_acl_state.groups->n].gid =
			fattr->cf_gid;
		default_acl_state.groups->aces[default_acl_state.groups->n++].perms.allow =
			(mode & 0070) >> 3;
	}

	if (others_found) {
		fattr->cf_mode &= ~(0007);
		fattr->cf_mode |= mode & 0007;

		acl_state.other.allow = mode & 0007;
		default_acl_state.other.allow = mode & 0007;
	}

	if (acl_state.users->n || acl_state.groups->n) {
		acl_state.mask.allow = 0x07;

		if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {
			fattr->cf_acls =
				posix_acl_alloc(acl_state.users->n +
					acl_state.groups->n + 4, KSMBD_DEFAULT_GFP);
			if (fattr->cf_acls) {
				cf_pace = fattr->cf_acls->a_entries;
				posix_state_to_acl(&acl_state, cf_pace);
			}
		}
	}

	if (default_acl_state.users->n || default_acl_state.groups->n) {
		default_acl_state.mask.allow = 0x07;

		if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {
			fattr->cf_dacls =
				posix_acl_alloc(default_acl_state.users->n +
				default_acl_state.groups->n + 4, KSMBD_DEFAULT_GFP);
			if (fattr->cf_dacls) {
				cf_pdace = fattr->cf_dacls->a_entries;
				posix_state_to_acl(&default_acl_state, cf_pdace);
			}
		}
	}
	free_acl_state(&acl_state);
	free_acl_state(&default_acl_state);
}
EXPORT_SYMBOL_IF_KUNIT(parse_dacl);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int set_posix_acl_entries_dacl(struct mnt_idmap *idmap,
#else
static int set_posix_acl_entries_dacl(struct user_namespace *user_ns,
#endif
				      struct smb_ace *pndace,
				      struct smb_fattr *fattr,
				      u16 *num_aces, u16 *size,
				      u32 nt_aces_num,
				      unsigned int buf_size)
{
	struct posix_acl_entry *pace;
	struct smb_sid *sid;
	struct smb_ace *ntace;
	int i, j;
	unsigned int new_off;
	__u16 ace_size;

	if (!fattr->cf_acls)
		goto posix_default_acl;

	pace = fattr->cf_acls->a_entries;
	for (i = 0; i < fattr->cf_acls->a_count; i++, pace++) {
		int flags = 0;

		sid = kmalloc(sizeof(struct smb_sid), KSMBD_DEFAULT_GFP);
		if (!sid)
			break;

		if (pace->e_tag == ACL_USER) {
			uid_t uid;
			unsigned int sid_type = SIDOWNER;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			uid = posix_acl_uid_translate(idmap, pace);
#else
			uid = posix_acl_uid_translate(user_ns, pace);
#endif
			if (!uid)
				sid_type = SIDUNIX_USER;
			id_to_sid(uid, sid_type, sid);
		} else if (pace->e_tag == ACL_GROUP) {
			gid_t gid;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			gid = posix_acl_gid_translate(idmap, pace);
#else
			gid = posix_acl_gid_translate(user_ns, pace);
#endif
			id_to_sid(gid, SIDUNIX_GROUP, sid);
		} else if (pace->e_tag == ACL_OTHER && !nt_aces_num) {
			smb_copy_sid(sid, &sid_everyone);
		} else {
			kfree(sid);
			continue;
		}
		ntace = pndace;
		for (j = 0; j < nt_aces_num; j++) {
			__u16 ntace_sz = le16_to_cpu(ntace->size);

			/* VFS-11: reject zero/undersized ACE to prevent infinite
			 * loop and OOB reads.
			 */
			if (ntace_sz < offsetof(struct smb_ace, sid))
				break;
			if (ntace->sid.sub_auth[ntace->sid.num_subauth - 1] ==
					sid->sub_auth[sid->num_subauth - 1])
				goto pass_same_sid;
			ntace = (struct smb_ace *)((char *)ntace + ntace_sz);
		}

		if (S_ISDIR(fattr->cf_mode) && pace->e_tag == ACL_OTHER)
			flags = 0x03;

		ace_size = ksmbd_ace_size(sid);
		if (!ace_size ||
		    check_add_overflow((unsigned int)*size,
				       (unsigned int)ace_size,
				       &new_off) ||
		    new_off > buf_size) {
			kfree(sid);
			pr_err_ratelimited("ACL buffer overflow in posix ACE\n");
			return -ENOSPC;
		}

		ntace = (struct smb_ace *)((char *)pndace + *size);
		*size += fill_ace_for_sid(ntace, sid, ACCESS_ALLOWED,
				flags, pace->e_perm, 0777);
		(*num_aces)++;
		if (pace->e_tag == ACL_USER)
			ntace->access_req |=
				FILE_DELETE_LE | FILE_DELETE_CHILD_LE;

		if (S_ISDIR(fattr->cf_mode) &&
		    (pace->e_tag == ACL_USER ||
		     pace->e_tag == ACL_GROUP)) {
			ace_size = ksmbd_ace_size(sid);
			if (!ace_size ||
			    check_add_overflow((unsigned int)*size,
					       (unsigned int)ace_size,
					       &new_off) ||
			    new_off > buf_size) {
				kfree(sid);
				pr_err_ratelimited("ACL buffer overflow in posix dir ACE\n");
				return -ENOSPC;
			}

			ntace = (struct smb_ace *)((char *)pndace +
					*size);
			*size += fill_ace_for_sid(ntace, sid,
					ACCESS_ALLOWED, 0x03,
					pace->e_perm, 0777);
			(*num_aces)++;
			if (pace->e_tag == ACL_USER)
				ntace->access_req |=
					FILE_DELETE_LE |
					FILE_DELETE_CHILD_LE;
		}

pass_same_sid:
		kfree(sid);
	}

	if (nt_aces_num)
		return 0;

posix_default_acl:
	if (!fattr->cf_dacls)
		return 0;

	pace = fattr->cf_dacls->a_entries;
	for (i = 0; i < fattr->cf_dacls->a_count; i++, pace++) {
		sid = kmalloc(sizeof(struct smb_sid), KSMBD_DEFAULT_GFP);
		if (!sid)
			break;

		if (pace->e_tag == ACL_USER) {
			uid_t uid;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			uid = posix_acl_uid_translate(idmap, pace);
#else
			uid = posix_acl_uid_translate(user_ns, pace);
#endif
			id_to_sid(uid, SIDCREATOR_OWNER, sid);
		} else if (pace->e_tag == ACL_GROUP) {
			gid_t gid;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			gid = posix_acl_gid_translate(idmap, pace);
#else
			gid = posix_acl_gid_translate(user_ns, pace);
#endif
			id_to_sid(gid, SIDCREATOR_GROUP, sid);
		} else {
			kfree(sid);
			continue;
		}

		ace_size = ksmbd_ace_size(sid);
		if (!ace_size ||
		    check_add_overflow((unsigned int)*size,
				       (unsigned int)ace_size,
				       &new_off) ||
		    new_off > buf_size) {
			kfree(sid);
			pr_err_ratelimited("ACL buffer overflow in default ACE\n");
			return -ENOSPC;
		}

		ntace = (struct smb_ace *)((char *)pndace + *size);
		*size += fill_ace_for_sid(ntace, sid, ACCESS_ALLOWED,
				0x0b, pace->e_perm, 0777);
		(*num_aces)++;
		if (pace->e_tag == ACL_USER)
			ntace->access_req |=
				FILE_DELETE_LE | FILE_DELETE_CHILD_LE;
		kfree(sid);
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int set_ntacl_dacl(struct mnt_idmap *idmap,
#else
static int set_ntacl_dacl(struct user_namespace *user_ns,
#endif
			  struct smb_acl *pndacl,
			  struct smb_acl *nt_dacl,
			  unsigned int aces_size,
			  const struct smb_sid *pownersid,
			  const struct smb_sid *pgrpsid,
			  struct smb_fattr *fattr,
			  unsigned int buf_size)
{
	struct smb_ace *ntace, *pndace;
	u16 nt_num_aces = le16_to_cpu(nt_dacl->num_aces);
	u16 num_aces = 0;
	unsigned short size = 0;
	unsigned int new_off;
	int i, rc;

	pndace = (struct smb_ace *)((char *)pndacl +
			sizeof(struct smb_acl));
	if (nt_num_aces) {
		ntace = (struct smb_ace *)((char *)nt_dacl +
				sizeof(struct smb_acl));
		for (i = 0; i < nt_num_aces; i++) {
			unsigned short nt_ace_size;

			if (offsetof(struct smb_ace, access_req) >
			    aces_size)
				break;

			nt_ace_size = le16_to_cpu(ntace->size);
			if (nt_ace_size > aces_size)
				break;

			if (check_add_overflow((unsigned int)size,
					       (unsigned int)nt_ace_size,
					       &new_off) ||
			    new_off > buf_size) {
				pr_err_ratelimited("ACL buffer overflow copying NT ACEs\n");
				return -ENOSPC;
			}

			memcpy((char *)pndace + size, ntace,
			       nt_ace_size);
			size += nt_ace_size;
			aces_size -= nt_ace_size;
			ntace = (struct smb_ace *)((char *)ntace +
					nt_ace_size);
			num_aces++;
		}
	}

	/*
	 * Only add POSIX ACL-derived ACEs when the stored NTACL has
	 * no ACEs of its own.  When a client-provided SD was stored
	 * (e.g. via SMB2_CREATE_SD_BUFFER), the NTACL is authoritative
	 * and must not be augmented with POSIX-derived entries.
	 */
	if (!nt_num_aces) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		rc = set_posix_acl_entries_dacl(idmap, pndace, fattr,
#else
		rc = set_posix_acl_entries_dacl(user_ns, pndace, fattr,
#endif
						&num_aces, &size,
						nt_num_aces, buf_size);
		if (rc)
			return rc;
	}

	pndacl->num_aces = cpu_to_le16(num_aces);
	pndacl->size = cpu_to_le16(le16_to_cpu(pndacl->size) + size);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int set_mode_dacl(struct mnt_idmap *idmap,
#else
static int set_mode_dacl(struct user_namespace *user_ns,
#endif
			 struct smb_acl *pndacl,
			 struct smb_fattr *fattr,
			 unsigned int buf_size)
{
	struct smb_ace *pace, *pndace;
	u16 num_aces = 0;
	u16 size = 0, ace_size = 0;
	unsigned int new_off;
	uid_t uid;
	const struct smb_sid *sid;
	int rc;

	pace = pndace = (struct smb_ace *)((char *)pndacl +
			sizeof(struct smb_acl));

	if (fattr->cf_acls) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		rc = set_posix_acl_entries_dacl(idmap, pndace, fattr,
#else
		rc = set_posix_acl_entries_dacl(user_ns, pndace, fattr,
#endif
						&num_aces, &size,
						num_aces, buf_size);
		if (rc)
			return rc;
		goto out;
	}

	/* owner RID - account for extra sub_auth (+4) appended */
	uid = from_kuid(&init_user_ns, fattr->cf_uid);
	if (uid)
		sid = &server_conf.domain_sid;
	else
		sid = &sid_unix_users;

	ace_size = ksmbd_ace_size(sid);
	if (!ace_size ||
	    check_add_overflow((unsigned int)ace_size, 4u,
			       &new_off) ||
	    check_add_overflow((unsigned int)size, new_off,
			       &new_off) ||
	    new_off > buf_size) {
		pr_err_ratelimited("ACL buffer overflow: owner ACE\n");
		return -ENOSPC;
	}

	ace_size = fill_ace_for_sid(pace, sid, ACCESS_ALLOWED, 0,
				    fattr->cf_mode, 0700);
	if (pace->sid.num_subauth < SID_MAX_SUB_AUTHORITIES)
		pace->sid.sub_auth[pace->sid.num_subauth++] =
			cpu_to_le32(uid);
	pace->size = cpu_to_le16(ace_size + 4);
	size += le16_to_cpu(pace->size);
	pace = (struct smb_ace *)((char *)pndace + size);

	/* Group RID */
	ace_size = ksmbd_ace_size(&sid_unix_groups);
	if (!ace_size ||
	    check_add_overflow((unsigned int)ace_size, 4u,
			       &new_off) ||
	    check_add_overflow((unsigned int)size, new_off,
			       &new_off) ||
	    new_off > buf_size) {
		pr_err_ratelimited("ACL buffer overflow: group ACE\n");
		return -ENOSPC;
	}

	ace_size = fill_ace_for_sid(pace, &sid_unix_groups,
				    ACCESS_ALLOWED, 0,
				    fattr->cf_mode, 0070);
	if (pace->sid.num_subauth < SID_MAX_SUB_AUTHORITIES)
		pace->sid.sub_auth[pace->sid.num_subauth++] =
			cpu_to_le32(from_kgid(&init_user_ns,
					      fattr->cf_gid));
	pace->size = cpu_to_le16(ace_size + 4);
	size += le16_to_cpu(pace->size);
	pace = (struct smb_ace *)((char *)pndace + size);
	num_aces = 3;

	if (S_ISDIR(fattr->cf_mode)) {
		pace = (struct smb_ace *)((char *)pndace + size);

		/* creator owner */
		ace_size = ksmbd_ace_size(&creator_owner);
		if (!ace_size ||
		    check_add_overflow((unsigned int)size,
				       (unsigned int)ace_size,
				       &new_off) ||
		    new_off > buf_size) {
			pr_err_ratelimited("ACL buffer overflow: creator owner\n");
			return -ENOSPC;
		}
		size += fill_ace_for_sid(pace, &creator_owner,
					ACCESS_ALLOWED, 0x0b,
					fattr->cf_mode, 0700);
		pace = (struct smb_ace *)((char *)pndace + size);

		/* creator group */
		ace_size = ksmbd_ace_size(&creator_group);
		if (!ace_size ||
		    check_add_overflow((unsigned int)size,
				       (unsigned int)ace_size,
				       &new_off) ||
		    new_off > buf_size) {
			pr_err_ratelimited("ACL buffer overflow: creator group\n");
			return -ENOSPC;
		}
		size += fill_ace_for_sid(pace, &creator_group,
					ACCESS_ALLOWED, 0x0b,
					fattr->cf_mode, 0070);
		pace = (struct smb_ace *)((char *)pndace + size);
		num_aces = 5;
	}

	/* other */
	ace_size = ksmbd_ace_size(&sid_everyone);
	if (!ace_size ||
	    check_add_overflow((unsigned int)size,
			       (unsigned int)ace_size, &new_off) ||
	    new_off > buf_size) {
		pr_err_ratelimited("ACL buffer overflow: everyone ACE\n");
		return -ENOSPC;
	}
	size += fill_ace_for_sid(pace, &sid_everyone,
				ACCESS_ALLOWED, 0,
				fattr->cf_mode, 0007);

out:
	pndacl->num_aces = cpu_to_le16(num_aces);
	pndacl->size = cpu_to_le16(le16_to_cpu(pndacl->size) + size);
	return 0;
}

VISIBLE_IF_KUNIT
int parse_sid(struct smb_sid *psid, char *end_of_acl)
{
	/*
	 * validate that we do not go past end of ACL - sid must be at least 8
	 * bytes long (assuming no sub-auths - e.g. the null SID
	 */
	if (end_of_acl < (char *)psid + 8) {
		pr_err("ACL too small to parse SID\n");
		return -EINVAL;
	}

	if (!psid->num_subauth)
		return 0;

	if (psid->num_subauth > SID_MAX_SUB_AUTHORITIES ||
	    end_of_acl < (char *)psid + 8 + sizeof(__le32) * psid->num_subauth)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(parse_sid);

/* Convert CIFS ACL to POSIX form */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
int parse_sec_desc(struct mnt_idmap *idmap, struct smb_ntsd *pntsd,
#else
int parse_sec_desc(struct user_namespace *user_ns, struct smb_ntsd *pntsd,
#endif
		   int acl_len, struct smb_fattr *fattr)
{
	int rc = 0;
	struct smb_sid *owner_sid_ptr, *group_sid_ptr;
	struct smb_acl *dacl_ptr;
	char *end_of_acl = ((char *)pntsd) + acl_len;
	__u32 dacloffset;
	int pntsd_type;

	if (!pntsd)
		return -EIO;

	if (acl_len < sizeof(struct smb_ntsd))
		return -EINVAL;

	/*
	 * Validate that SID and DACL offsets fall within the buffer
	 * before computing pointers.  Use check_add_overflow() to
	 * guard against crafted offsets that could wrap around.
	 */
	{
		__u32 osidoff = le32_to_cpu(pntsd->osidoffset);
		__u32 gsidoff = le32_to_cpu(pntsd->gsidoffset);
		unsigned int end;

		dacloffset = le32_to_cpu(pntsd->dacloffset);

		if (osidoff &&
		    (check_add_overflow(osidoff,
				       (unsigned int)CIFS_SID_BASE_SIZE,
				       &end) ||
		     end > (unsigned int)acl_len))
			return -EINVAL;

		if (gsidoff &&
		    (check_add_overflow(gsidoff,
				       (unsigned int)CIFS_SID_BASE_SIZE,
				       &end) ||
		     end > (unsigned int)acl_len))
			return -EINVAL;

		if (dacloffset &&
		    (check_add_overflow(dacloffset,
				       (unsigned int)sizeof(struct smb_acl),
				       &end) ||
		     end > (unsigned int)acl_len))
			return -EINVAL;

		owner_sid_ptr = (struct smb_sid *)((char *)pntsd + osidoff);
		group_sid_ptr = (struct smb_sid *)((char *)pntsd + gsidoff);
		dacl_ptr = (struct smb_acl *)((char *)pntsd + dacloffset);
	}
	ksmbd_debug(SMB,
		    "revision %d type 0x%x ooffset 0x%x goffset 0x%x sacloffset 0x%x dacloffset 0x%x\n",
		    pntsd->revision, pntsd->type, le32_to_cpu(pntsd->osidoffset),
		    le32_to_cpu(pntsd->gsidoffset),
		    le32_to_cpu(pntsd->sacloffset), dacloffset);

	/* ACL-01: Validate SD revision (MS-DTYP §2.4.6) */
	if (le16_to_cpu(pntsd->revision) != SD_REVISION) {
		pr_err("%s: Invalid SD revision: %d\n", __func__,
		       le16_to_cpu(pntsd->revision));
		return -EINVAL;
	}

	/* ACL-08: Validate SELF_RELATIVE flag (MS-DTYP §2.4.6) */
	if (!(le16_to_cpu(pntsd->type) & SELF_RELATIVE)) {
		pr_err("%s: SD missing SELF_RELATIVE flag\n", __func__);
		return -EINVAL;
	}

	pntsd_type = le16_to_cpu(pntsd->type);
	if (!(pntsd_type & DACL_PRESENT)) {
		ksmbd_debug(SMB, "DACL_PRESENT in DACL type is not set\n");
		return rc;
	}

	pntsd->type = cpu_to_le16(DACL_PRESENT);

	/* Preserve SACL flags if present in the incoming descriptor */
	if (pntsd_type & SACL_PRESENT)
		pntsd->type |= cpu_to_le16(SACL_PRESENT);
	if (pntsd_type & SACL_DEFAULTED)
		pntsd->type |= cpu_to_le16(SACL_DEFAULTED);
	if (pntsd_type & SACL_AUTO_INHERITED)
		pntsd->type |= cpu_to_le16(SACL_AUTO_INHERITED);
	if (pntsd_type & SACL_PROTECTED)
		pntsd->type |= cpu_to_le16(SACL_PROTECTED);

	if (pntsd->osidoffset) {
		if (le32_to_cpu(pntsd->osidoffset) < sizeof(struct smb_ntsd))
			return -EINVAL;

		rc = parse_sid(owner_sid_ptr, end_of_acl);
		if (rc) {
			pr_err("%s: Error %d parsing Owner SID\n", __func__, rc);
			return rc;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		rc = sid_to_id(idmap, owner_sid_ptr, SIDOWNER, fattr);
#else
		rc = sid_to_id(user_ns, owner_sid_ptr, SIDOWNER, fattr);
#endif
		if (rc) {
			pr_err("%s: Error %d mapping Owner SID to uid\n",
			       __func__, rc);
			owner_sid_ptr = NULL;
		}
	}

	if (pntsd->gsidoffset) {
		if (le32_to_cpu(pntsd->gsidoffset) < sizeof(struct smb_ntsd))
			return -EINVAL;

		rc = parse_sid(group_sid_ptr, end_of_acl);
		if (rc) {
			pr_err("%s: Error %d mapping Owner SID to gid\n",
			       __func__, rc);
			return rc;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		rc = sid_to_id(idmap, group_sid_ptr, SIDUNIX_GROUP, fattr);
#else
		rc = sid_to_id(user_ns, group_sid_ptr, SIDUNIX_GROUP, fattr);
#endif
		if (rc) {
			pr_err("%s: Error %d mapping Group SID to gid\n",
			       __func__, rc);
			group_sid_ptr = NULL;
		}
	}

	if ((pntsd_type & (DACL_AUTO_INHERITED | DACL_AUTO_INHERIT_REQ)) ==
	    (DACL_AUTO_INHERITED | DACL_AUTO_INHERIT_REQ))
		pntsd->type |= cpu_to_le16(DACL_AUTO_INHERITED);
	if (pntsd_type & DACL_PROTECTED)
		pntsd->type |= cpu_to_le16(DACL_PROTECTED);

	if (dacloffset) {
		if (dacloffset < sizeof(struct smb_ntsd))
			return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		parse_dacl(idmap, dacl_ptr, end_of_acl,
#else
		parse_dacl(user_ns, dacl_ptr, end_of_acl,
#endif
			   owner_sid_ptr, group_sid_ptr, fattr);
	}

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(parse_sec_desc);

/**
 * build_sec_desc() - convert permission bits to equivalent CIFS ACL
 * @idmap:	idmap of the relevant mount (user_ns on older kernels)
 * @pntsd:	output NT security descriptor buffer
 * @ppntsd:	optional parent NT security descriptor
 * @ppntsd_size:	size of parent security descriptor
 * @addition_info:	which security info sections to include
 * @secdesclen:	output total security descriptor length
 * @fattr:	file attributes with uid/gid/mode/ACLs
 * @buf_size:	total size of the output buffer pntsd
 *
 * Return:	0 on success, negative errno on error
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
int build_sec_desc(struct mnt_idmap *idmap,
#else
int build_sec_desc(struct user_namespace *user_ns,
#endif
		   struct smb_ntsd *pntsd, struct smb_ntsd *ppntsd,
		   int ppntsd_size, int addition_info,
		   __u32 *secdesclen, struct smb_fattr *fattr,
		   unsigned int buf_size)
{
	int rc = 0;
	__u32 offset;
	unsigned int sid_size, new_off;
	struct smb_sid *owner_sid_ptr, *group_sid_ptr;
	struct smb_sid *nowner_sid_ptr, *ngroup_sid_ptr;
	struct smb_acl *dacl_ptr = NULL;
	struct smb_acl *sacl_ptr = NULL;
	uid_t uid;
	gid_t gid;
	unsigned int sid_type = SIDOWNER;

	if (buf_size < sizeof(struct smb_ntsd))
		return -ENOSPC;

	nowner_sid_ptr = kmalloc(sizeof(struct smb_sid),
				 KSMBD_DEFAULT_GFP);
	if (!nowner_sid_ptr)
		return -ENOMEM;

	uid = from_kuid(&init_user_ns, fattr->cf_uid);
	if (!uid)
		sid_type = SIDUNIX_USER;
	id_to_sid(uid, sid_type, nowner_sid_ptr);

	ngroup_sid_ptr = kmalloc(sizeof(struct smb_sid),
				 KSMBD_DEFAULT_GFP);
	if (!ngroup_sid_ptr) {
		kfree(nowner_sid_ptr);
		return -ENOMEM;
	}

	gid = from_kgid(&init_user_ns, fattr->cf_gid);
	id_to_sid(gid, SIDUNIX_GROUP, ngroup_sid_ptr);

	offset = sizeof(struct smb_ntsd);
	pntsd->sacloffset = 0;
	pntsd->dacloffset = 0;
	pntsd->revision = cpu_to_le16(1);
	pntsd->type = cpu_to_le16(SELF_RELATIVE);
	if (ppntsd)
		pntsd->type |= ppntsd->type;

	/*
	 * If a stored NTSD has explicit owner/group SIDs, use them
	 * instead of the POSIX uid/gid-derived SIDs.  This preserves
	 * client-supplied ownership from SMB2_CREATE_SD_BUFFER or
	 * SET_INFO operations.
	 */
	if (ppntsd && ppntsd->osidoffset) {
		unsigned int osid_off = le32_to_cpu(ppntsd->osidoffset);

		if (osid_off + offsetof(struct smb_sid, sub_auth) <=
		    (unsigned int)ppntsd_size) {
			struct smb_sid *stored_owner =
				(struct smb_sid *)((char *)ppntsd + osid_off);

			smb_copy_sid(nowner_sid_ptr, stored_owner);
		}
	}

	if (ppntsd && ppntsd->gsidoffset) {
		unsigned int gsid_off = le32_to_cpu(ppntsd->gsidoffset);

		if (gsid_off + offsetof(struct smb_sid, sub_auth) <=
		    (unsigned int)ppntsd_size) {
			struct smb_sid *stored_group =
				(struct smb_sid *)((char *)ppntsd + gsid_off);

			smb_copy_sid(ngroup_sid_ptr, stored_group);
		}
	}

	if (addition_info & OWNER_SECINFO) {
		sid_size = 1 + 1 + 6 +
			(unsigned int)nowner_sid_ptr->num_subauth * 4;
		if (check_add_overflow(offset, sid_size, &new_off) ||
		    new_off > buf_size) {
			pr_err_ratelimited("SD buffer overflow: owner SID\n");
			rc = -ENOSPC;
			goto out;
		}
		pntsd->osidoffset = cpu_to_le32(offset);
		owner_sid_ptr = (struct smb_sid *)((char *)pntsd +
				offset);
		smb_copy_sid(owner_sid_ptr, nowner_sid_ptr);
		offset = new_off;
	}

	if (addition_info & GROUP_SECINFO) {
		sid_size = 1 + 1 + 6 +
			(unsigned int)ngroup_sid_ptr->num_subauth * 4;
		if (check_add_overflow(offset, sid_size, &new_off) ||
		    new_off > buf_size) {
			pr_err_ratelimited("SD buffer overflow: group SID\n");
			rc = -ENOSPC;
			goto out;
		}
		pntsd->gsidoffset = cpu_to_le32(offset);
		group_sid_ptr = (struct smb_sid *)((char *)pntsd +
				offset);
		smb_copy_sid(group_sid_ptr, ngroup_sid_ptr);
		offset = new_off;
	}

	if (addition_info & SACL_SECINFO) {
		/*
		 * G.8: Try to copy stored SACL ACEs from ppntsd.  If the
		 * stored SD contains a SACL (sacloffset != 0), replicate it
		 * verbatim.  If there is no stored SACL, return an empty SACL
		 * with 0 ACEs and STATUS_SUCCESS (not an error) so that Windows
		 * does not interpret the response as "access denied to SACL".
		 */
		if (ppntsd && le32_to_cpu(ppntsd->sacloffset)) {
			unsigned int sacl_off = le32_to_cpu(ppntsd->sacloffset);
			struct smb_acl *pp_sacl;
			unsigned int pp_sacl_size;

			if (sacl_off + sizeof(struct smb_acl) <=
			    (unsigned int)ppntsd_size) {
				pp_sacl = (struct smb_acl *)
					((char *)ppntsd + sacl_off);
				pp_sacl_size = le16_to_cpu(pp_sacl->size);

				if (pp_sacl_size >= sizeof(struct smb_acl) &&
				    sacl_off + pp_sacl_size <=
				    (unsigned int)ppntsd_size &&
				    !check_add_overflow(offset, pp_sacl_size,
						       &new_off) &&
				    new_off <= buf_size) {
					/* Copy stored SACL verbatim */
					pntsd->type |=
						cpu_to_le16(SACL_PRESENT);
					pntsd->sacloffset =
						cpu_to_le32(offset);
					sacl_ptr = (struct smb_acl *)
						((char *)pntsd + offset);
					memcpy(sacl_ptr, pp_sacl,
					       pp_sacl_size);
					offset = new_off;
					goto sacl_done;
				}
			}
		}

		/* No stored SACL: return empty SACL (0 ACEs, STATUS_SUCCESS) */
		if (check_add_overflow(offset,
				       (unsigned int)sizeof(struct smb_acl),
				       &new_off) ||
		    new_off > buf_size) {
			pr_err_ratelimited("SD buffer overflow: SACL hdr\n");
			rc = -ENOSPC;
			goto out;
		}

		pntsd->type |= cpu_to_le16(SACL_PRESENT);
		pntsd->sacloffset = cpu_to_le32(offset);
		sacl_ptr = (struct smb_acl *)((char *)pntsd + offset);
		sacl_ptr->revision = cpu_to_le16(2);
		sacl_ptr->size = cpu_to_le16(sizeof(struct smb_acl));
		sacl_ptr->num_aces = 0;
		sacl_ptr->reserved = 0;
		offset = new_off;
sacl_done:;
	}

	if (addition_info & DACL_SECINFO) {
		unsigned int dacl_buf_size;

		pntsd->type |= cpu_to_le16(DACL_PRESENT);

		/*
		 * If the stored SD has DACL_PRESENT but no DACL data
		 * (dacloffset == 0), this is a NULL DACL meaning
		 * everyone has full access.  Preserve it as-is:
		 * set DACL_PRESENT but leave dacloffset = 0.
		 */
		if (ppntsd &&
		    (le16_to_cpu(ppntsd->type) & DACL_PRESENT) &&
		    !ppntsd->dacloffset)
			goto dacl_done;

		if (check_add_overflow(offset,
				       (unsigned int)sizeof(struct smb_acl),
				       &new_off) ||
		    new_off > buf_size) {
			pr_err_ratelimited("SD buffer overflow: DACL hdr\n");
			rc = -ENOSPC;
			goto out;
		}

		dacl_ptr = (struct smb_acl *)((char *)pntsd + offset);
		dacl_ptr->revision = cpu_to_le16(2);
		dacl_ptr->size = cpu_to_le16(sizeof(struct smb_acl));
		dacl_ptr->num_aces = 0;

		/* Space remaining for ACEs after DACL header */
		dacl_buf_size = buf_size - new_off;

		if (!ppntsd) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			rc = set_mode_dacl(idmap, dacl_ptr, fattr,
#else
			rc = set_mode_dacl(user_ns, dacl_ptr, fattr,
#endif
					   dacl_buf_size);
			if (rc)
				goto out;
		} else {
			struct smb_acl *ppdacl_ptr;
			unsigned int dacl_offset =
				le32_to_cpu(ppntsd->dacloffset);
			int ppdacl_size;
			int ntacl_size = ppntsd_size - dacl_offset;

			if (!dacl_offset ||
			    (dacl_offset + sizeof(struct smb_acl) >
			     (unsigned int)ppntsd_size))
				goto dacl_done;

			ppdacl_ptr = (struct smb_acl *)((char *)ppntsd +
					dacl_offset);
			ppdacl_size = le16_to_cpu(ppdacl_ptr->size);
			if (ppdacl_size > ntacl_size ||
			    ppdacl_size < sizeof(struct smb_acl))
				goto dacl_done;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			rc = set_ntacl_dacl(idmap, dacl_ptr,
#else
			rc = set_ntacl_dacl(user_ns, dacl_ptr,
#endif
					    ppdacl_ptr,
					    ntacl_size -
					    sizeof(struct smb_acl),
					    nowner_sid_ptr,
					    ngroup_sid_ptr, fattr,
					    dacl_buf_size);
			if (rc)
				goto out;
		}
		pntsd->dacloffset = cpu_to_le32(offset);
		offset += le16_to_cpu(dacl_ptr->size);

		/* Final validation */
		if (offset > buf_size) {
			pr_err_ratelimited("SD exceeds buffer: %u > %u\n",
					   offset, buf_size);
			rc = -ENOSPC;
			goto out;
		}
	}
dacl_done:

out:
	kfree(nowner_sid_ptr);
	kfree(ngroup_sid_ptr);
	*secdesclen = offset;
	return rc;
}
EXPORT_SYMBOL_IF_KUNIT(build_sec_desc);

VISIBLE_IF_KUNIT
void smb_set_ace(struct smb_ace *ace, const struct smb_sid *sid, u8 type,
			u8 flags, __le32 access_req)
{
	/* C-01: guard against SIDs with invalid subauthority counts */
	if (WARN_ON_ONCE(sid->num_subauth > SID_MAX_SUB_AUTHORITIES))
		return;

	ace->type = type;
	ace->flags = flags;
	ace->access_req = access_req;
	smb_copy_sid(&ace->sid, sid);
	ace->size = cpu_to_le16(1 + 1 + 2 + 4 + 1 + 1 + 6 + (sid->num_subauth * 4));
}
EXPORT_SYMBOL_IF_KUNIT(smb_set_ace);

int smb_inherit_dacl(struct ksmbd_conn *conn,
		     const struct path *path,
		     unsigned int uid, unsigned int gid)
{
	const struct smb_sid *psid, *creator = NULL;
	struct smb_ace *parent_aces, *aces;
	struct smb_acl *parent_pdacl;
	struct smb_ntsd *parent_pntsd = NULL;
	struct smb_sid owner_sid, group_sid;
	struct dentry *parent = path->dentry->d_parent;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
#else
	struct user_namespace *user_ns = mnt_user_ns(path->mnt);
#endif
	int inherited_flags = 0, flags = 0, i, nt_size = 0, pdacl_size;
	int rc = 0, pntsd_type, pntsd_size, acl_len, aces_size;
	unsigned int dacloffset;
	size_t dacl_struct_end;
	size_t aces_buf_size;
	u16 num_aces, ace_cnt = 0;
	char *aces_base;
	bool is_dir = S_ISDIR(d_inode(path->dentry)->i_mode);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, idmap,
#else
	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, user_ns,
#endif
					    parent, &parent_pntsd);
	if (pntsd_size <= 0)
		return -ENOENT;

	dacloffset = le32_to_cpu(parent_pntsd->dacloffset);
	if (!dacloffset ||
	    check_add_overflow(dacloffset, sizeof(struct smb_acl), &dacl_struct_end) ||
	    dacl_struct_end > (size_t)pntsd_size) {
		rc = -EINVAL;
		goto free_parent_pntsd;
	}

	parent_pdacl = (struct smb_acl *)((char *)parent_pntsd + dacloffset);
	acl_len = pntsd_size - dacloffset;
	num_aces = le16_to_cpu(parent_pdacl->num_aces);
	pntsd_type = le16_to_cpu(parent_pntsd->type);
	pdacl_size = le16_to_cpu(parent_pdacl->size);

	if (pdacl_size > acl_len || pdacl_size < sizeof(struct smb_acl)) {
		rc = -EINVAL;
		goto free_parent_pntsd;
	}

	/*
	 * INHERIT-01: Compute actual buffer size by summing real ACE sizes.
	 * ACEs with large SIDs can be up to 72 bytes vs sizeof(struct smb_ace)
	 * (~20 bytes), so using the base struct size would underallocate.
	 * Multiply by 2 to account for the possible creator-owner duplication.
	 */
	{
		struct smb_ace *scan_ace;
		struct smb_sid owner_sid, group_sid;
		int scan_size;
		size_t total_ace_bytes = 0;
		int i;

		id_to_sid(uid, SIDOWNER, &owner_sid);
		id_to_sid(gid, SIDUNIX_GROUP, &group_sid);

		scan_ace = (struct smb_ace *)((char *)parent_pdacl +
				sizeof(struct smb_acl));
		scan_size = acl_len - sizeof(struct smb_acl);
		for (i = 0; i < num_aces; i++) {
			int pace_sz;

			if (offsetof(struct smb_ace, access_req) > scan_size)
				break;
			pace_sz = le16_to_cpu(scan_ace->size);
			if (pace_sz > scan_size || pace_sz < sizeof(struct smb_ace))
				break;
			{
				size_t inherited_sz;

				inherited_sz = ksmbd_inherited_ace_size(scan_ace,
								is_dir,
								&owner_sid,
								&group_sid);
				if (check_add_overflow(total_ace_bytes,
						       inherited_sz,
						       &total_ace_bytes)) {
					rc = -EINVAL;
					goto free_parent_pntsd;
				}
			}
			scan_size -= pace_sz;
			scan_ace = (struct smb_ace *)((char *)scan_ace + pace_sz);
		}
		aces_buf_size = total_ace_bytes;
	}
	aces_base = kmalloc(aces_buf_size, KSMBD_DEFAULT_GFP);
	if (!aces_base) {
		rc = -ENOMEM;
		goto free_parent_pntsd;
	}

	aces = (struct smb_ace *)aces_base;
	parent_aces = (struct smb_ace *)((char *)parent_pdacl +
			sizeof(struct smb_acl));
	aces_size = acl_len - sizeof(struct smb_acl);

	if (pntsd_type & DACL_AUTO_INHERITED)
		inherited_flags = INHERITED_ACE;

	for (i = 0; i < num_aces; i++) {
		int pace_size;

		if (offsetof(struct smb_ace, access_req) > aces_size)
			break;

		pace_size = le16_to_cpu(parent_aces->size);
		if (pace_size > aces_size)
			break;

		aces_size -= pace_size;

		flags = parent_aces->flags;
		if (!smb_inherit_flags(flags, is_dir))
			goto pass;
		if (is_dir) {
			flags &= ~(INHERIT_ONLY_ACE | INHERITED_ACE);
			if (!(flags & CONTAINER_INHERIT_ACE))
				flags |= INHERIT_ONLY_ACE;
			if (flags & NO_PROPAGATE_INHERIT_ACE)
				flags = 0;
		} else {
			flags = 0;
		}

		if (!compare_sids(&creator_owner, &parent_aces->sid)) {
			creator = &creator_owner;
			id_to_sid(uid, SIDOWNER, &owner_sid);
			psid = &owner_sid;
		} else if (!compare_sids(&creator_group, &parent_aces->sid)) {
			creator = &creator_group;
			id_to_sid(gid, SIDUNIX_GROUP, &group_sid);
			psid = &group_sid;
		} else {
			creator = NULL;
			psid = &parent_aces->sid;
		}

		if (is_dir && creator && flags & CONTAINER_INHERIT_ACE) {
			__u16 asize = ksmbd_ace_size(psid);

			if (!asize ||
			    (unsigned int)nt_size + asize > aces_buf_size) {
				pr_err_ratelimited("inherit ACL overflow\n");
				break;
			}
			smb_set_ace(aces, psid, parent_aces->type,
				    inherited_flags,
				    parent_aces->access_req);
			nt_size += le16_to_cpu(aces->size);
			ace_cnt++;
			aces = (struct smb_ace *)((char *)aces +
					le16_to_cpu(aces->size));
			flags |= INHERIT_ONLY_ACE;
			psid = creator;
		} else if (is_dir && !(parent_aces->flags &
				       NO_PROPAGATE_INHERIT_ACE)) {
			psid = &parent_aces->sid;
		}

		{
			__u16 asize = ksmbd_ace_size(psid);

			if (!asize ||
			    (unsigned int)nt_size + asize > aces_buf_size) {
				pr_err_ratelimited("inherit ACL overflow\n");
				break;
			}
		}
		smb_set_ace(aces, psid, parent_aces->type,
			    flags | inherited_flags,
			    parent_aces->access_req);
		nt_size += le16_to_cpu(aces->size);
		aces = (struct smb_ace *)((char *)aces +
				le16_to_cpu(aces->size));
		ace_cnt++;
pass:
		parent_aces = (struct smb_ace *)((char *)parent_aces + pace_size);
	}

	if (nt_size > 0) {
		struct smb_ntsd *pntsd;
		struct smb_acl *pdacl;
		struct smb_sid *powner_sid = NULL, *pgroup_sid = NULL;
		int powner_sid_size = 0, pgroup_sid_size = 0, pntsd_size;
		int pntsd_alloc_size;

		if (parent_pntsd->osidoffset) {
			powner_sid = (struct smb_sid *)((char *)parent_pntsd +
					le32_to_cpu(parent_pntsd->osidoffset));
			if (powner_sid->num_subauth > SID_MAX_SUB_AUTHORITIES) {
				rc = -EINVAL;
				goto free_aces_base;
			}
			powner_sid_size = 1 + 1 + 6 + (powner_sid->num_subauth * 4);
		}
		if (parent_pntsd->gsidoffset) {
			pgroup_sid = (struct smb_sid *)((char *)parent_pntsd +
					le32_to_cpu(parent_pntsd->gsidoffset));
			if (pgroup_sid->num_subauth > SID_MAX_SUB_AUTHORITIES) {
				rc = -EINVAL;
				goto free_aces_base;
			}
			pgroup_sid_size = 1 + 1 + 6 + (pgroup_sid->num_subauth * 4);
		}

		/* C-02: use checked arithmetic to prevent pntsd_alloc_size overflow */
		pntsd_alloc_size = sizeof(struct smb_ntsd) + powner_sid_size +
			pgroup_sid_size + sizeof(struct smb_acl) + nt_size;
		if (pntsd_alloc_size < nt_size) {
			/* overflow */
			rc = -EINVAL;
			goto free_aces_base;
		}

		pntsd = kzalloc(pntsd_alloc_size, KSMBD_DEFAULT_GFP);
		if (!pntsd) {
			rc = -ENOMEM;
			goto free_aces_base;
		}

		pntsd->revision = cpu_to_le16(1);
		pntsd->type = cpu_to_le16(SELF_RELATIVE | DACL_PRESENT);
		/*
		 * MS-DTYP §2.4.6: DACL_AUTO_INHERITED must be set whenever the
		 * DACL contains auto-inherited ACEs (i.e., when we performed
		 * inheritance).  Set it unconditionally here since ace_cnt > 0
		 * means we inherited at least one ACE.
		 */
		if (ace_cnt > 0)
			pntsd->type |= cpu_to_le16(DACL_AUTO_INHERITED);
		else if (le16_to_cpu(parent_pntsd->type) & DACL_AUTO_INHERITED)
			pntsd->type |= cpu_to_le16(DACL_AUTO_INHERITED);
		/* ACL-06: Propagate DACL_AUTO_INHERIT_REQ flag (MS-DTYP §2.4.6) */
		if (le16_to_cpu(parent_pntsd->type) & DACL_AUTO_INHERIT_REQ)
			pntsd->type |= cpu_to_le16(DACL_AUTO_INHERIT_REQ);
		pntsd_size = sizeof(struct smb_ntsd);
		pntsd->osidoffset = parent_pntsd->osidoffset;
		pntsd->gsidoffset = parent_pntsd->gsidoffset;
		pntsd->dacloffset = parent_pntsd->dacloffset;

		if ((u64)le32_to_cpu(pntsd->osidoffset) + powner_sid_size >
		    pntsd_alloc_size) {
			rc = -EINVAL;
			kfree(pntsd);
			goto free_aces_base;
		}

		if ((u64)le32_to_cpu(pntsd->gsidoffset) + pgroup_sid_size >
		    pntsd_alloc_size) {
			rc = -EINVAL;
			kfree(pntsd);
			goto free_aces_base;
		}

		if ((u64)le32_to_cpu(pntsd->dacloffset) + sizeof(struct smb_acl) + nt_size >
		    pntsd_alloc_size) {
			rc = -EINVAL;
			kfree(pntsd);
			goto free_aces_base;
		}

		if (pntsd->osidoffset) {
			struct smb_sid *owner_sid = (struct smb_sid *)((char *)pntsd +
					le32_to_cpu(pntsd->osidoffset));
			memcpy(owner_sid, powner_sid, powner_sid_size);
			pntsd_size += powner_sid_size;
		}

		if (pntsd->gsidoffset) {
			struct smb_sid *group_sid = (struct smb_sid *)((char *)pntsd +
					le32_to_cpu(pntsd->gsidoffset));
			memcpy(group_sid, pgroup_sid, pgroup_sid_size);
			pntsd_size += pgroup_sid_size;
		}

		if (pntsd->dacloffset) {
			struct smb_ace *pace;

			pdacl = (struct smb_acl *)((char *)pntsd + le32_to_cpu(pntsd->dacloffset));
			pdacl->revision = cpu_to_le16(2);
			pdacl->size = cpu_to_le16(sizeof(struct smb_acl) + nt_size);
			pdacl->num_aces = cpu_to_le16(ace_cnt);
			pace = (struct smb_ace *)((char *)pdacl + sizeof(struct smb_acl));
			memcpy(pace, aces_base, nt_size);
			pntsd_size += sizeof(struct smb_acl) + nt_size;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		ksmbd_vfs_set_sd_xattr(conn, idmap,
#else
		ksmbd_vfs_set_sd_xattr(conn, user_ns,
#endif
				       path, pntsd, pntsd_size, false);
		kfree(pntsd);
	}

free_aces_base:
	kfree(aces_base);
free_parent_pntsd:
	kfree(parent_pntsd);
	return rc;
}

bool smb_inherit_flags(int flags, bool is_dir)
{
	if (!is_dir)
		return (flags & OBJECT_INHERIT_ACE) != 0;

	if (flags & OBJECT_INHERIT_ACE && !(flags & NO_PROPAGATE_INHERIT_ACE))
		return true;

	if (flags & CONTAINER_INHERIT_ACE)
		return true;
	return false;
}

int smb_check_perm_dacl(struct ksmbd_conn *conn, const struct path *path,
			__le32 *pdaccess, int uid)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
#else
	struct user_namespace *user_ns = mnt_user_ns(path->mnt);
#endif
	struct smb_ntsd *pntsd = NULL;
	struct smb_acl *pdacl;
	struct posix_acl *posix_acls;
	int rc = 0, pntsd_size, acl_size, aces_size, pdacl_size;
	unsigned int dacl_offset;
	size_t dacl_struct_end;
	struct smb_sid sid;
	int granted = le32_to_cpu(*pdaccess & ~FILE_MAXIMAL_ACCESS_LE);
	struct smb_ace *ace;
	int i, found = 0;
	unsigned int access_bits = 0;
	struct smb_ace *others_ace = NULL;
	struct posix_acl_entry *pa_entry;
	unsigned int sid_type = SIDOWNER;
	unsigned short ace_size;

	ksmbd_debug(SMB, "check permission using windows acl\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, idmap,
#else
	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, user_ns,
#endif
					    path->dentry, &pntsd);
	if (pntsd_size <= 0 || !pntsd)
		goto err_out;

	dacl_offset = le32_to_cpu(pntsd->dacloffset);
	if (!dacl_offset ||
	    check_add_overflow(dacl_offset, sizeof(struct smb_acl), &dacl_struct_end) ||
	    dacl_struct_end > (size_t)pntsd_size)
		goto err_out;

	pdacl = (struct smb_acl *)((char *)pntsd + le32_to_cpu(pntsd->dacloffset));
	acl_size = pntsd_size - dacl_offset;
	pdacl_size = le16_to_cpu(pdacl->size);

	if (pdacl_size > acl_size || pdacl_size < sizeof(struct smb_acl))
		goto err_out;

	if (!pdacl->num_aces) {
		if (!(pdacl_size - sizeof(struct smb_acl)) &&
		    *pdaccess & ~(FILE_READ_CONTROL_LE | FILE_WRITE_DAC_LE)) {
			rc = -EACCES;
			goto err_out;
		}
		goto err_out;
	}

	if (*pdaccess & FILE_MAXIMAL_ACCESS_LE) {
		granted = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES |
			DELETE | SYNCHRONIZE;

		ace = (struct smb_ace *)((char *)pdacl + sizeof(struct smb_acl));
		aces_size = acl_size - sizeof(struct smb_acl);
		for (i = 0; i < le16_to_cpu(pdacl->num_aces); i++) {
			if (offsetof(struct smb_ace, access_req) > aces_size)
				break;
			ace_size = le16_to_cpu(ace->size);
			if (ace_size > aces_size)
				break;
			aces_size -= ace_size;
			granted |= le32_to_cpu(ace->access_req);
			ace = (struct smb_ace *)((char *)ace + le16_to_cpu(ace->size));
		}

		if (!pdacl->num_aces)
			granted = GENERIC_ALL_FLAGS;

		/* MS-SMB2: extra bits requested alongside MAXIMUM_ALLOWED must
		 * also be within the computed maximum grant; deny if not.
		 * ACCESS_SYSTEM_SECURITY (0x01000000) requires SeSecurityPrivilege
		 * which we don't implement; return -ENOKEY so the caller maps it
		 * to STATUS_PRIVILEGE_NOT_HELD.
		 *
		 * Generic rights are expanded to their file-specific equivalents
		 * before checking.  GENERIC_EXECUTE is mapped without FILE_EXECUTE
		 * because Windows treats it as satisfied whenever the other
		 * READ_CONTROL / SYNCHRONIZE / FILE_READ_ATTRIBUTES overlap is
		 * present (the Samba torture comment: "SEC_GENERIC_EXECUTE is a
		 * complete subset of SEC_GENERIC_READ when mapped to specific
		 * bits"). */
		{
			unsigned int extra = le32_to_cpu(*pdaccess) &
					     ~(unsigned int)0x02000000;
			/* Expand generic bits to file-specific equivalents.
			 * Bits 26-27 (0x04000000 / 0x08000000) are reserved;
			 * propagate them directly into expanded so they are
			 * denied (they are never in any DACL grant). */
			unsigned int expanded = extra & 0x0CFFFFFFu;

			if (extra & 0x80000000u) /* GENERIC_READ */
				expanded |= 0x00120089u; /* READ_CONTROL|SYNC|FILE_READ_DATA|FILE_READ_ATTR|FILE_READ_EA */
			if (extra & 0x40000000u) /* GENERIC_WRITE */
				expanded |= 0x00120116u; /* READ_CONTROL|SYNC|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_ATTR|FILE_WRITE_EA */
			if (extra & 0x20000000u) /* GENERIC_EXECUTE */
				expanded |= 0x00120080u; /* READ_CONTROL|SYNC|FILE_READ_ATTR (no FILE_EXECUTE) */
			if (extra & 0x10000000u) /* GENERIC_ALL */
				expanded |= 0x001F01FFu; /* FILE_ALL_ACCESS */

			/* SYSTEM_SECURITY is never in the DACL grant */
			if (extra & 0x01000000u) {
				rc = -ENOKEY;
				goto err_out;
			}
			expanded &= ~0x01000000u;
			if (expanded & ~(unsigned int)granted) {
				rc = -EACCES;
				goto err_out;
			}
		}
	}

	if (!uid)
		sid_type = SIDUNIX_USER;
	id_to_sid(uid, sid_type, &sid);

	ace = (struct smb_ace *)((char *)pdacl + sizeof(struct smb_acl));
	aces_size = acl_size - sizeof(struct smb_acl);
	for (i = 0; i < le16_to_cpu(pdacl->num_aces); i++) {
		if (offsetof(struct smb_ace, access_req) > aces_size)
			break;
		ace_size = le16_to_cpu(ace->size);
		if (ace_size > aces_size)
			break;
		aces_size -= ace_size;

		/* ACL-07: Skip INHERIT_ONLY ACEs during access checks (MS-DTYP §2.4.4.1) */
		if (ace->flags & INHERIT_ONLY_ACE)
			goto next_ace;

		if (!compare_sids(&sid, &ace->sid) ||
		    !compare_sids(&sid_unix_NFS_mode, &ace->sid)) {
			found = 1;
			break;
		}
		/*
		 * CREATOR_OWNER (S-1-3-0): substitute the file's actual owner.
		 * Per MS-DTYP §2.5.2.1, CREATOR_OWNER in a DACL applies to the
		 * object's owner at access-check time.
		 */
		if (!compare_sids(&creator_owner, &ace->sid)) {
			struct smb_sid owner_sid;
			unsigned int owner_uid = i_uid_read(d_inode(path->dentry));

			id_to_sid(owner_uid,
				  owner_uid ? SIDOWNER : SIDUNIX_USER,
				  &owner_sid);
			if (!compare_sids(&sid, &owner_sid)) {
				found = 1;
				break;
			}
			/* Not the owner: CREATOR_OWNER ACE doesn't apply */
		} else if (!compare_sids(&sid_everyone, &ace->sid) ||
			   !compare_sids(&sid_authusers, &ace->sid)) {
			/*
			 * S-1-1-0 (Everyone) and S-1-5-11 (Authenticated Users)
			 * are group SIDs that apply to all authenticated users.
			 * Treat them as catch-all ACEs (others_ace) so that files
			 * protected only by Authenticated Users ACEs are
			 * accessible to normal domain/local users.
			 */
			others_ace = ace;
		}


next_ace:
		ace = (struct smb_ace *)((char *)ace + le16_to_cpu(ace->size));
	}

	if (*pdaccess & FILE_MAXIMAL_ACCESS_LE && found) {
		granted = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES |
			DELETE | SYNCHRONIZE;

		if (ace->type == ACCESS_ALLOWED_ACE_TYPE ||
		    ace->type == ACCESS_ALLOWED_CALLBACK_ACE_TYPE ||
		    ace->type == ACCESS_ALLOWED_OBJECT_ACE_TYPE)
			granted |= le32_to_cpu(ace->access_req);
		else if (ace->type == ACCESS_DENIED_ACE_TYPE ||
			 ace->type == ACCESS_DENIED_CALLBACK_ACE_TYPE ||
			 ace->type == ACCESS_DENIED_OBJECT_ACE_TYPE)
			granted &= ~le32_to_cpu(ace->access_req);

		if (!pdacl->num_aces)
			granted = GENERIC_ALL_FLAGS;
	}

	if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
		posix_acls = get_inode_acl(d_inode(path->dentry), ACL_TYPE_ACCESS);
#else
		posix_acls = get_acl(d_inode(path->dentry), ACL_TYPE_ACCESS);
#endif
		if (!IS_ERR_OR_NULL(posix_acls) && !found) {
			unsigned int id = -1;

			pa_entry = posix_acls->a_entries;
			for (i = 0; i < posix_acls->a_count; i++, pa_entry++) {
				if (pa_entry->e_tag == ACL_USER)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
					id = posix_acl_uid_translate(idmap, pa_entry);
#else
					id = posix_acl_uid_translate(user_ns, pa_entry);
#endif
				else if (pa_entry->e_tag == ACL_GROUP)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
					id = posix_acl_gid_translate(idmap, pa_entry);
#else
					id = posix_acl_gid_translate(user_ns, pa_entry);
#endif
				else
					continue;

				if (id == uid) {
					mode_to_access_flags(pa_entry->e_perm,
							     0777,
							     &access_bits);
					if (!access_bits)
						access_bits =
							SET_MINIMUM_RIGHTS;
					posix_acl_release(posix_acls);
					goto check_access_bits;
				}
			}
		}
		if (!IS_ERR_OR_NULL(posix_acls))
			posix_acl_release(posix_acls);
	}

	if (!found) {
		if (others_ace) {
			ace = others_ace;
		} else {
			ksmbd_debug(SMB, "Can't find corresponding sid\n");
			rc = -EACCES;
			goto err_out;
		}
	}

	switch (ace->type) {
	case ACCESS_ALLOWED_ACE_TYPE:
	case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:  /* ACL-02: MS-DTYP §2.4.4.2 */
	case ACCESS_ALLOWED_OBJECT_ACE_TYPE:    /* ACL-02: MS-DTYP §2.4.4.2 */
		access_bits = le32_to_cpu(ace->access_req);
		break;
	case ACCESS_DENIED_ACE_TYPE:
	case ACCESS_DENIED_CALLBACK_ACE_TYPE:
	case ACCESS_DENIED_OBJECT_ACE_TYPE:     /* ACL-02: MS-DTYP §2.4.4.2 */
		access_bits = le32_to_cpu(~ace->access_req);
		break;
	}

check_access_bits:
	/*
	 * For MAXIMUM_ALLOWED, the granted mask was already computed above
	 * using the ACL — skip the explicit access_bits check and just
	 * return the computed maximum grant.
	 */
	if (*pdaccess & FILE_MAXIMAL_ACCESS_LE) {
		*pdaccess = cpu_to_le32(granted);
		goto err_out;
	}

	if (granted &
	    ~(access_bits | FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | DELETE | SYNCHRONIZE | FILE_EXECUTE)) {
		ksmbd_debug(SMB, "Access denied with winACL, granted : %x, access_req : %x\n",
			    granted, le32_to_cpu(ace->access_req));
		rc = -EACCES;
		goto err_out;
	}

	*pdaccess = cpu_to_le32(granted);
err_out:
	kfree(pntsd);
	return rc;
}

int set_info_sec(struct ksmbd_conn *conn, struct ksmbd_tree_connect *tcon,
		 const struct path *path, struct smb_ntsd *pntsd, int ntsd_len,
		 bool type_check, bool get_write)
{
	int rc;
	struct smb_fattr fattr = {{0}};
	struct inode *inode = d_inode(path->dentry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = mnt_idmap(path->mnt);
#else
	struct user_namespace *user_ns = mnt_user_ns(path->mnt);
#endif
	struct iattr newattrs;

	fattr.cf_uid = INVALID_UID;
	fattr.cf_gid = INVALID_GID;
	fattr.cf_mode = inode->i_mode;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = parse_sec_desc(idmap, pntsd, ntsd_len, &fattr);
#else
	rc = parse_sec_desc(user_ns, pntsd, ntsd_len, &fattr);
#endif
	if (rc)
		goto out;

	newattrs.ia_valid = ATTR_CTIME;
	if (!uid_eq(fattr.cf_uid, INVALID_UID)) {
		newattrs.ia_valid |= ATTR_UID;
		newattrs.ia_uid = fattr.cf_uid;
	}
	if (!gid_eq(fattr.cf_gid, INVALID_GID)) {
		inode->i_gid = fattr.cf_gid;
		newattrs.ia_valid |= ATTR_GID;
		newattrs.ia_gid = fattr.cf_gid;
	}
	newattrs.ia_valid |= ATTR_MODE;
	newattrs.ia_mode = (inode->i_mode & ~0777) | (fattr.cf_mode & 0777);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ksmbd_vfs_remove_acl_xattrs(idmap, path);
#else
	ksmbd_vfs_remove_acl_xattrs(user_ns, path);
#endif
	/* Update posix acls */
	if (IS_ENABLED(CONFIG_FS_POSIX_ACL) && fattr.cf_dacls) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		rc = set_posix_acl(idmap, path->dentry,
#else
		rc = set_posix_acl(user_ns, path->dentry,
#endif
#else
		rc = set_posix_acl(user_ns, inode,
#endif
				   ACL_TYPE_ACCESS,
				   fattr.cf_acls);
#else
		rc = set_posix_acl(inode, ACL_TYPE_ACCESS, fattr.cf_acls);
#endif
		if (rc < 0)
			ksmbd_debug(SMB,
				    "Set posix acl(ACL_TYPE_ACCESS) failed, rc : %d\n",
				    rc);
		if (S_ISDIR(inode->i_mode) && fattr.cf_dacls) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			rc = set_posix_acl(idmap, path->dentry,
#else
			rc = set_posix_acl(user_ns, path->dentry,
#endif
#else
			rc = set_posix_acl(user_ns, inode,
#endif
					   ACL_TYPE_DEFAULT, fattr.cf_dacls);
#else
			rc = set_posix_acl(inode, ACL_TYPE_DEFAULT,
					   fattr.cf_dacls);
#endif
			if (rc)
				ksmbd_debug(SMB,
					    "Set posix acl(ACL_TYPE_DEFAULT) failed, rc : %d\n",
					    rc);
		}
	}

	inode_lock(inode);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = notify_change(idmap, path->dentry, &newattrs, NULL);
#else
	rc = notify_change(user_ns, path->dentry, &newattrs, NULL);
#endif
#else
	rc = notify_change(path->dentry, &newattrs, NULL);
#endif
	inode_unlock(inode);
	if (rc)
		goto out;

	/* Check it only calling from SD BUFFER context */
	if (type_check && !(le16_to_cpu(pntsd->type) & DACL_PRESENT))
		goto out;

	if (test_share_config_flag(tcon->share_conf, KSMBD_SHARE_FLAG_ACL_XATTR)) {
		/* Update WinACL in xattr */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		ksmbd_vfs_remove_sd_xattrs(idmap, path);
		ksmbd_vfs_set_sd_xattr(conn, idmap,
#else
		ksmbd_vfs_remove_sd_xattrs(user_ns, path);
		ksmbd_vfs_set_sd_xattr(conn, user_ns,
#endif
				       path, pntsd, ntsd_len, get_write);
	}

	/*
	 * L-02: MS-SMB2 §3.3.5.20.3 LABEL_SECURITY_INFORMATION (0x10).
	 * If the incoming SD carries a non-zero SACL (sacloffset != 0),
	 * persist the raw SACL bytes as an integrity label xattr so that
	 * subsequent GET_SECURITY with LABEL_SECINFO can retrieve them.
	 */
	{
		__u32 sacloffset = le32_to_cpu(pntsd->sacloffset);

		if (sacloffset &&
		    sacloffset + sizeof(struct smb_acl) <= (unsigned int)ntsd_len) {
			struct smb_acl *sacl =
				(struct smb_acl *)((char *)pntsd + sacloffset);
			__u16 sacl_size = le16_to_cpu(sacl->size);

			if (sacl_size >= sizeof(struct smb_acl) &&
			    sacloffset + sacl_size <= (unsigned int)ntsd_len) {
				int label_rc;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
				label_rc = ksmbd_vfs_setxattr(idmap,
							      path,
#else
				label_rc = ksmbd_vfs_setxattr(user_ns,
							      path,
#endif
						XATTR_NAME_SD_LABEL,
						sacl, sacl_size, 0, get_write);
				if (label_rc < 0 &&
				    label_rc != -EOPNOTSUPP &&
				    label_rc != -ENOTSUPP)
					ksmbd_debug(SMB,
						    "label xattr write failed: %d\n",
						    label_rc);
			}
		}
	}

out:
	posix_acl_release(fattr.cf_acls);
	posix_acl_release(fattr.cf_dacls);
	return rc;
}

void ksmbd_init_domain(u32 *sub_auth)
{
	int i;

	memcpy(&server_conf.domain_sid, &domain, sizeof(struct smb_sid));
	for (i = 0; i < 3; ++i)
		server_conf.domain_sid.sub_auth[i + 1] = cpu_to_le32(sub_auth[i]);
}
