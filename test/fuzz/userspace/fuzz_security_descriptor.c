// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Userspace libFuzzer target for NT security descriptor parsing.
 *
 * Exercises the critical parsing paths that ksmbd uses when processing
 * SET_INFO requests with security information:
 *   - SECURITY_DESCRIPTOR_RELATIVE offset validation
 *   - SID revision and num_subauth bounds checking
 *   - ACL size vs ACE count consistency
 *   - ACE size and embedded SID validation
 *   - SID comparison (compare_sids)
 *
 * Build: clang -fsanitize=fuzzer,address,undefined -g -O1 \
 *        -I. fuzz_security_descriptor.c -o fuzz_security_descriptor
 */

#include "ksmbd_compat.h"

/* --- Inline structures (match smbacl.h) --- */

#define SID_MAX_SUB_AUTHORITIES	15
#define NUM_AUTHS		6
#define CIFS_SID_BASE_SIZE	(1 + 1 + NUM_AUTHS)

/* SD control flags */
#define DACL_PRESENT	0x0004
#define SACL_PRESENT	0x0010
#define SELF_RELATIVE	0x8000

struct smb_sid {
	__u8   revision;
	__u8   num_subauth;
	__u8   authority[NUM_AUTHS];
	__le32 sub_auth[];
} __packed;

struct smb_acl {
	__le16 revision;
	__le16 size;
	__le16 num_aces;
	__le16 reserved;
} __packed;

struct smb_ace {
	__u8   type;
	__u8   flags;
	__le16 size;
	__le32 access_req;
	struct smb_sid sid;
} __packed;

struct smb_ntsd {
	__le16 revision;
	__le16 type;
	__le32 osidoffset;
	__le32 gsidoffset;
	__le32 sacloffset;
	__le32 dacloffset;
} __packed;

/* --- SID comparison (mirrors smbacl.c compare_sids) --- */

static int fuzz_compare_sids(const struct smb_sid *a, const struct smb_sid *b)
{
	int i;
	int n;

	if (a->revision != b->revision)
		return a->revision < b->revision ? -1 : 1;

	if (a->num_subauth != b->num_subauth)
		return a->num_subauth < b->num_subauth ? -1 : 1;

	for (i = 0; i < NUM_AUTHS; i++) {
		if (a->authority[i] != b->authority[i])
			return a->authority[i] < b->authority[i] ? -1 : 1;
	}

	n = min_t(int, a->num_subauth, SID_MAX_SUB_AUTHORITIES);
	for (i = 0; i < n; i++) {
		__u32 sa = le32_to_cpu(a->sub_auth[i]);
		__u32 sb = le32_to_cpu(b->sub_auth[i]);

		if (sa != sb)
			return sa < sb ? -1 : 1;
	}

	return 0;
}

/* --- Validation helpers --- */

static int validate_sid(const u8 *data, size_t len, u32 offset)
{
	const struct smb_sid *sid;
	size_t sid_size;

	if (offset + sizeof(struct smb_sid) > len)
		return -EINVAL;

	sid = (const struct smb_sid *)(data + offset);

	if (sid->revision != 1)
		return -EINVAL;

	if (sid->num_subauth > SID_MAX_SUB_AUTHORITIES)
		return -EINVAL;

	sid_size = CIFS_SID_BASE_SIZE +
		   sid->num_subauth * sizeof(__le32);
	if (offset + sid_size > len)
		return -EINVAL;

	return 0;
}

static int validate_acl(const u8 *data, size_t len, u32 offset)
{
	const struct smb_acl *acl;
	const struct smb_ace *ace;
	u16 acl_size;
	u16 num_aces;
	u32 ace_offset;
	u16 i;
	u16 ace_size;

	if (offset + sizeof(struct smb_acl) > len)
		return -EINVAL;

	acl = (const struct smb_acl *)(data + offset);
	acl_size = le16_to_cpu(acl->size);
	num_aces = le16_to_cpu(acl->num_aces);

	if (offset + acl_size > len)
		return -EINVAL;

	if (acl_size < sizeof(struct smb_acl))
		return -EINVAL;

	/* Cap to prevent excessive processing */
	if (num_aces > 1024)
		return -EINVAL;

	ace_offset = offset + sizeof(struct smb_acl);
	for (i = 0; i < num_aces; i++) {
		if (ace_offset + sizeof(struct smb_ace) > len ||
		    ace_offset + sizeof(struct smb_ace) > offset + acl_size)
			return -EINVAL;

		ace = (const struct smb_ace *)(data + ace_offset);
		ace_size = le16_to_cpu(ace->size);

		if (ace_size < sizeof(struct smb_ace))
			return -EINVAL;

		if (ace_offset + ace_size > offset + acl_size)
			return -EINVAL;

		/* Validate embedded SID sub-authority count */
		if (ace->sid.num_subauth > SID_MAX_SUB_AUTHORITIES)
			return -EINVAL;

		/* Validate that ACE size accommodates the SID */
		{
			size_t min_ace_size = offsetof(struct smb_ace, sid) +
				CIFS_SID_BASE_SIZE +
				ace->sid.num_subauth * sizeof(__le32);
			if (ace_size < min_ace_size)
				return -EINVAL;
		}

		ace_offset += ace_size;
	}

	return 0;
}

static void parse_security_descriptor(const u8 *data, size_t len)
{
	const struct smb_ntsd *ntsd;
	u32 osidoffset, gsidoffset, sacloffset, dacloffset;
	u16 type;
	int ret;

	if (len < sizeof(struct smb_ntsd))
		return;

	/* Cap input to prevent excessive processing */
	if (len > 65536)
		len = 65536;

	ntsd = (const struct smb_ntsd *)data;

	osidoffset = le32_to_cpu(ntsd->osidoffset);
	gsidoffset = le32_to_cpu(ntsd->gsidoffset);
	sacloffset = le32_to_cpu(ntsd->sacloffset);
	dacloffset = le32_to_cpu(ntsd->dacloffset);
	type = le16_to_cpu(ntsd->type);

	/* Validate owner SID */
	if (osidoffset != 0) {
		if (osidoffset < sizeof(struct smb_ntsd))
			return;
		ret = validate_sid(data, len, osidoffset);
		if (ret < 0)
			return;
	}

	/* Validate group SID */
	if (gsidoffset != 0) {
		if (gsidoffset < sizeof(struct smb_ntsd))
			return;
		ret = validate_sid(data, len, gsidoffset);
		if (ret < 0)
			return;
	}

	/* Validate SACL */
	if (sacloffset != 0 && (type & SACL_PRESENT)) {
		if (sacloffset < sizeof(struct smb_ntsd))
			return;
		ret = validate_acl(data, len, sacloffset);
		if (ret < 0)
			return;
	}

	/* Validate DACL */
	if (dacloffset != 0 && (type & DACL_PRESENT)) {
		if (dacloffset < sizeof(struct smb_ntsd))
			return;
		ret = validate_acl(data, len, dacloffset);
		if (ret < 0)
			return;
	}

	/* If both owner and group SIDs are valid, compare them */
	if (osidoffset != 0 && gsidoffset != 0 &&
	    osidoffset >= sizeof(struct smb_ntsd) &&
	    gsidoffset >= sizeof(struct smb_ntsd)) {
		const struct smb_sid *osid, *gsid;
		size_t osid_size, gsid_size;

		if (osidoffset + sizeof(struct smb_sid) <= len &&
		    gsidoffset + sizeof(struct smb_sid) <= len) {
			osid = (const struct smb_sid *)(data + osidoffset);
			gsid = (const struct smb_sid *)(data + gsidoffset);

			if (osid->revision == 1 &&
			    osid->num_subauth <= SID_MAX_SUB_AUTHORITIES &&
			    gsid->revision == 1 &&
			    gsid->num_subauth <= SID_MAX_SUB_AUTHORITIES) {
				osid_size = CIFS_SID_BASE_SIZE +
					osid->num_subauth * sizeof(__le32);
				gsid_size = CIFS_SID_BASE_SIZE +
					gsid->num_subauth * sizeof(__le32);

				if (osidoffset + osid_size <= len &&
				    gsidoffset + gsid_size <= len) {
					/* Exercise SID comparison */
					volatile int cmp =
						fuzz_compare_sids(osid, gsid);
					(void)cmp;
				}
			}
		}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	parse_security_descriptor(data, size);
	return 0;
}
