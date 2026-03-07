// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for advanced ACL operations (smbacl.c)
 *
 *   Tests for parse_dacl() and build_sec_desc() — functions that operate
 *   on wire-format buffers and do not require VFS or connection state.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#include <linux/mnt_idmapping.h>
#endif

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smbacl.h"
#include "smb2pdu.h"

/*
 * Wire-format ACE helper: build a minimal ACCESS_ALLOWED or ACCESS_DENIED
 * ACE into a buffer.  Returns the total ACE size written.
 *
 * The on-wire layout is:
 *   type(1) + flags(1) + size(2) + access_req(4) + SID(variable)
 * where SID = revision(1) + num_subauth(1) + authority(6) + sub_auth(4*n)
 */
static u16 build_wire_ace(void *buf, u8 type, u8 flags, __le32 access,
			  const struct smb_sid *sid)
{
	struct smb_ace *ace = buf;
	u16 sid_size = 1 + 1 + 6 + sid->num_subauth * 4;
	u16 ace_size = offsetof(struct smb_ace, sid) + sid_size;

	ace->type = type;
	ace->flags = flags;
	ace->size = cpu_to_le16(ace_size);
	ace->access_req = access;
	memcpy(&ace->sid, sid, sid_size);
	return ace_size;
}

/* ================================================================
 * parse_dacl tests
 * ================================================================ */

/*
 * test_parse_dacl_owner_allow - parse DACL with a single ALLOW ACE for owner
 *
 * Constructs a wire-format DACL with one ACCESS_ALLOWED ACE whose SID
 * matches pownersid.  After parse_dacl(), fattr->cf_mode should have
 * owner bits set based on the access mask (GENERIC_ALL -> 0700 owner).
 */
static void test_parse_dacl_owner_allow(struct kunit *test)
{
	/* Owner SID: S-1-22-1-1000 (Unix user 1000) */
	struct smb_sid owner_sid = {
		.revision = 1,
		.num_subauth = 2,
		.authority = {0, 0, 0, 0, 0, 22},
		.sub_auth = {cpu_to_le32(1), cpu_to_le32(1000)},
	};
	struct smb_sid group_sid = {
		.revision = 1,
		.num_subauth = 2,
		.authority = {0, 0, 0, 0, 0, 22},
		.sub_auth = {cpu_to_le32(2), cpu_to_le32(1000)},
	};
	struct smb_fattr fattr = {};
	/*
	 * Buffer layout: smb_acl header + 1 ACE
	 * Max ACE size with 2 sub_auths: 8 + 4 + 1+1+6+8 = 28 bytes
	 */
	char buf[256] = {};
	struct smb_acl *dacl = (struct smb_acl *)buf;
	void *ace_start = buf + sizeof(struct smb_acl);
	u16 ace_size;
	char *end;

	fattr.cf_uid = KUIDT_INIT(1000);
	fattr.cf_gid = KGIDT_INIT(1000);
	fattr.cf_mode = S_IFREG;

	/* Build DACL header */
	dacl->revision = cpu_to_le16(0x02);
	dacl->num_aces = cpu_to_le16(1);
	dacl->reserved = 0;

	/* Build one ALLOW ACE with GENERIC_ALL */
	ace_size = build_wire_ace(ace_start, ACCESS_ALLOWED_ACE_TYPE, 0,
				  cpu_to_le32(GENERIC_ALL), &owner_sid);

	dacl->size = cpu_to_le16(sizeof(struct smb_acl) + ace_size);
	end = buf + sizeof(struct smb_acl) + ace_size;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	parse_dacl(&nop_mnt_idmap, dacl, end, &owner_sid, &group_sid, &fattr);
#else
	parse_dacl(&init_user_ns, dacl, end, &owner_sid, &group_sid, &fattr);
#endif

	/* Owner bits from GENERIC_ALL should produce 0700 */
	KUNIT_EXPECT_EQ(test, (int)(fattr.cf_mode & 0700), 0700);
}

/*
 * test_parse_dacl_null_dacl - parse_dacl with NULL pdacl returns immediately
 */
static void test_parse_dacl_null_dacl(struct kunit *test)
{
	struct smb_sid owner_sid = {
		.revision = 1, .num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21)},
	};
	struct smb_fattr fattr = {};

	fattr.cf_mode = S_IFREG | 0644;

	/* Should not crash, mode should remain unchanged */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	parse_dacl(&nop_mnt_idmap, NULL, NULL, &owner_sid, &owner_sid, &fattr);
#else
	parse_dacl(&init_user_ns, NULL, NULL, &owner_sid, &owner_sid, &fattr);
#endif

	KUNIT_EXPECT_EQ(test, (int)(fattr.cf_mode & 0777), 0644);
}

/*
 * test_parse_dacl_zero_aces - DACL with num_aces=0 returns early
 */
static void test_parse_dacl_zero_aces(struct kunit *test)
{
	char buf[32] = {};
	struct smb_acl *dacl = (struct smb_acl *)buf;
	struct smb_sid sid = {
		.revision = 1, .num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21)},
	};
	struct smb_fattr fattr = {};

	fattr.cf_mode = S_IFREG | 0755;

	dacl->revision = cpu_to_le16(0x02);
	dacl->size = cpu_to_le16(sizeof(struct smb_acl));
	dacl->num_aces = cpu_to_le16(0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	parse_dacl(&nop_mnt_idmap, dacl, buf + sizeof(struct smb_acl),
		   &sid, &sid, &fattr);
#else
	parse_dacl(&init_user_ns, dacl, buf + sizeof(struct smb_acl),
		   &sid, &sid, &fattr);
#endif

	/* Mode should remain unchanged (no ACEs processed) */
	KUNIT_EXPECT_EQ(test, (int)(fattr.cf_mode & 0777), 0755);
}

/*
 * test_parse_dacl_invalid_revision - DACL with bad revision returns early
 */
static void test_parse_dacl_invalid_revision(struct kunit *test)
{
	char buf[64] = {};
	struct smb_acl *dacl = (struct smb_acl *)buf;
	struct smb_sid sid = {
		.revision = 1, .num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21)},
	};
	struct smb_fattr fattr = {};

	fattr.cf_mode = S_IFREG | 0644;

	/* Set invalid revision 0x07 */
	dacl->revision = cpu_to_le16(0x07);
	dacl->size = cpu_to_le16(sizeof(struct smb_acl));
	dacl->num_aces = cpu_to_le16(1);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	parse_dacl(&nop_mnt_idmap, dacl, buf + sizeof(*dacl),
		   &sid, &sid, &fattr);
#else
	parse_dacl(&init_user_ns, dacl, buf + sizeof(*dacl),
		   &sid, &sid, &fattr);
#endif

	/* Mode should remain unchanged due to invalid revision */
	KUNIT_EXPECT_EQ(test, (int)(fattr.cf_mode & 0777), 0644);
}

/*
 * test_parse_dacl_truncated_buffer - DACL size exceeds end_of_acl
 */
static void test_parse_dacl_truncated_buffer(struct kunit *test)
{
	char buf[16] = {};
	struct smb_acl *dacl = (struct smb_acl *)buf;
	struct smb_sid sid = {
		.revision = 1, .num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21)},
	};
	struct smb_fattr fattr = {};

	fattr.cf_mode = S_IFREG | 0644;

	dacl->revision = cpu_to_le16(0x02);
	/* Claim size 200 but only have 16 bytes */
	dacl->size = cpu_to_le16(200);
	dacl->num_aces = cpu_to_le16(1);

	/* end_of_acl is only buf+16, much smaller than declared size */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	parse_dacl(&nop_mnt_idmap, dacl, buf + 16,
		   &sid, &sid, &fattr);
#else
	parse_dacl(&init_user_ns, dacl, buf + 16,
		   &sid, &sid, &fattr);
#endif

	/* Should return early, mode unchanged */
	KUNIT_EXPECT_EQ(test, (int)(fattr.cf_mode & 0777), 0644);
}

/*
 * test_parse_dacl_everyone_allow - parse DACL with Everyone SID ALLOW
 *
 * The "Everyone" SID (S-1-1-0) should set the "others" bits.
 */
static void test_parse_dacl_everyone_allow(struct kunit *test)
{
	/* Everyone SID: S-1-1-0 */
	struct smb_sid everyone_sid = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 1},
		.sub_auth = {0},
	};
	/* Owner SID different from Everyone */
	struct smb_sid owner_sid = {
		.revision = 1,
		.num_subauth = 2,
		.authority = {0, 0, 0, 0, 0, 22},
		.sub_auth = {cpu_to_le32(1), cpu_to_le32(1000)},
	};
	struct smb_sid group_sid = {
		.revision = 1,
		.num_subauth = 2,
		.authority = {0, 0, 0, 0, 0, 22},
		.sub_auth = {cpu_to_le32(2), cpu_to_le32(1000)},
	};
	struct smb_fattr fattr = {};
	char buf[256] = {};
	struct smb_acl *dacl = (struct smb_acl *)buf;
	void *ace_start = buf + sizeof(struct smb_acl);
	u16 ace_size;
	char *end;

	fattr.cf_uid = KUIDT_INIT(1000);
	fattr.cf_gid = KGIDT_INIT(1000);
	fattr.cf_mode = S_IFREG;

	dacl->revision = cpu_to_le16(0x02);
	dacl->num_aces = cpu_to_le16(1);

	/* ALLOW ACE with GENERIC_READ for Everyone */
	ace_size = build_wire_ace(ace_start, ACCESS_ALLOWED_ACE_TYPE, 0,
				  cpu_to_le32(GENERIC_READ), &everyone_sid);

	dacl->size = cpu_to_le16(sizeof(struct smb_acl) + ace_size);
	end = buf + sizeof(struct smb_acl) + ace_size;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	parse_dacl(&nop_mnt_idmap, dacl, end, &owner_sid, &group_sid, &fattr);
#else
	parse_dacl(&init_user_ns, dacl, end, &owner_sid, &group_sid, &fattr);
#endif

	/* Others bits from GENERIC_READ: should have read bit (0004) */
	KUNIT_EXPECT_TRUE(test, (fattr.cf_mode & 0004) != 0);
}

/* ================================================================
 * build_sec_desc tests
 * ================================================================ */

/*
 * test_build_sec_desc_basic - build SD with OWNER+GROUP+DACL, no parent
 *
 * Verifies the SD header is properly constructed and the output
 * security descriptor length is reasonable.
 */
static void test_build_sec_desc_basic(struct kunit *test)
{
	struct smb_ntsd *pntsd;
	struct smb_fattr fattr = {};
	__u32 secdesclen = 0;
	int rc;
	unsigned int buf_size = 2048;

	pntsd = kunit_kzalloc(test, buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pntsd);

	fattr.cf_uid = KUIDT_INIT(1000);
	fattr.cf_gid = KGIDT_INIT(1000);
	fattr.cf_mode = S_IFREG | 0755;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = build_sec_desc(&nop_mnt_idmap, pntsd, NULL, 0,
			    OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO,
			    &secdesclen, &fattr, buf_size);
#else
	rc = build_sec_desc(&init_user_ns, pntsd, NULL, 0,
			    OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO,
			    &secdesclen, &fattr, buf_size);
#endif

	KUNIT_EXPECT_EQ(test, rc, 0);
	/* SD should have a valid revision */
	KUNIT_EXPECT_EQ(test, le16_to_cpu(pntsd->revision), 1);
	/* Should have SELF_RELATIVE flag */
	KUNIT_EXPECT_TRUE(test, le16_to_cpu(pntsd->type) & SELF_RELATIVE);
	/* Owner and group offsets should be set */
	KUNIT_EXPECT_NE(test, le32_to_cpu(pntsd->osidoffset), (__u32)0);
	KUNIT_EXPECT_NE(test, le32_to_cpu(pntsd->gsidoffset), (__u32)0);
	/* secdesclen should be > sizeof(smb_ntsd) */
	KUNIT_EXPECT_GT(test, secdesclen, (__u32)sizeof(struct smb_ntsd));
	/* secdesclen must not exceed buffer */
	KUNIT_EXPECT_LE(test, secdesclen, (__u32)buf_size);
}

/*
 * test_build_sec_desc_owner_only - build SD with only OWNER_SECINFO
 */
static void test_build_sec_desc_owner_only(struct kunit *test)
{
	struct smb_ntsd *pntsd;
	struct smb_fattr fattr = {};
	__u32 secdesclen = 0;
	int rc;
	unsigned int buf_size = 512;

	pntsd = kunit_kzalloc(test, buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pntsd);

	fattr.cf_uid = KUIDT_INIT(0);
	fattr.cf_gid = KGIDT_INIT(0);
	fattr.cf_mode = S_IFREG | 0644;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = build_sec_desc(&nop_mnt_idmap, pntsd, NULL, 0,
			    OWNER_SECINFO,
			    &secdesclen, &fattr, buf_size);
#else
	rc = build_sec_desc(&init_user_ns, pntsd, NULL, 0,
			    OWNER_SECINFO,
			    &secdesclen, &fattr, buf_size);
#endif

	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_NE(test, le32_to_cpu(pntsd->osidoffset), (__u32)0);
	/* Group/DACL/SACL offsets should be 0 */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(pntsd->gsidoffset), (__u32)0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(pntsd->dacloffset), (__u32)0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(pntsd->sacloffset), (__u32)0);
}

/*
 * test_build_sec_desc_too_small - buffer too small should return -ENOSPC
 */
static void test_build_sec_desc_too_small(struct kunit *test)
{
	struct smb_ntsd *pntsd;
	struct smb_fattr fattr = {};
	__u32 secdesclen = 0;
	int rc;
	/* Buffer too small for even the NTSD header */
	unsigned int buf_size = 4;

	pntsd = kunit_kzalloc(test, buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pntsd);

	fattr.cf_uid = KUIDT_INIT(1000);
	fattr.cf_gid = KGIDT_INIT(1000);
	fattr.cf_mode = S_IFREG | 0644;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = build_sec_desc(&nop_mnt_idmap, pntsd, NULL, 0,
			    OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO,
			    &secdesclen, &fattr, buf_size);
#else
	rc = build_sec_desc(&init_user_ns, pntsd, NULL, 0,
			    OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO,
			    &secdesclen, &fattr, buf_size);
#endif

	KUNIT_EXPECT_EQ(test, rc, -ENOSPC);
}

/*
 * test_build_sec_desc_dacl_present - SD with DACL should have DACL_PRESENT
 */
static void test_build_sec_desc_dacl_present(struct kunit *test)
{
	struct smb_ntsd *pntsd;
	struct smb_fattr fattr = {};
	__u32 secdesclen = 0;
	int rc;
	unsigned int buf_size = 2048;

	pntsd = kunit_kzalloc(test, buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pntsd);

	fattr.cf_uid = KUIDT_INIT(1000);
	fattr.cf_gid = KGIDT_INIT(1000);
	fattr.cf_mode = S_IFREG | 0755;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = build_sec_desc(&nop_mnt_idmap, pntsd, NULL, 0,
			    DACL_SECINFO,
			    &secdesclen, &fattr, buf_size);
#else
	rc = build_sec_desc(&init_user_ns, pntsd, NULL, 0,
			    DACL_SECINFO,
			    &secdesclen, &fattr, buf_size);
#endif

	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_TRUE(test,
			  le16_to_cpu(pntsd->type) & DACL_PRESENT);
	KUNIT_EXPECT_NE(test, le32_to_cpu(pntsd->dacloffset), (__u32)0);
}

/*
 * test_build_sec_desc_sacl_empty - SD with SACL and no parent has empty SACL
 */
static void test_build_sec_desc_sacl_empty(struct kunit *test)
{
	struct smb_ntsd *pntsd;
	struct smb_fattr fattr = {};
	__u32 secdesclen = 0;
	struct smb_acl *sacl;
	int rc;
	unsigned int buf_size = 2048;

	pntsd = kunit_kzalloc(test, buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pntsd);

	fattr.cf_uid = KUIDT_INIT(1000);
	fattr.cf_gid = KGIDT_INIT(1000);
	fattr.cf_mode = S_IFREG | 0644;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = build_sec_desc(&nop_mnt_idmap, pntsd, NULL, 0,
			    SACL_SECINFO,
			    &secdesclen, &fattr, buf_size);
#else
	rc = build_sec_desc(&init_user_ns, pntsd, NULL, 0,
			    SACL_SECINFO,
			    &secdesclen, &fattr, buf_size);
#endif

	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_TRUE(test,
			  le16_to_cpu(pntsd->type) & SACL_PRESENT);
	KUNIT_EXPECT_NE(test, le32_to_cpu(pntsd->sacloffset), (__u32)0);

	/* The empty SACL should have 0 ACEs */
	sacl = (struct smb_acl *)((char *)pntsd +
				  le32_to_cpu(pntsd->sacloffset));
	KUNIT_EXPECT_EQ(test, le16_to_cpu(sacl->num_aces), (__u16)0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(sacl->revision), (__u16)2);
}

/*
 * test_build_sec_desc_owner_sid_correct - verify owner SID in built SD
 */
static void test_build_sec_desc_owner_sid_correct(struct kunit *test)
{
	struct smb_ntsd *pntsd;
	struct smb_fattr fattr = {};
	struct smb_sid *owner;
	__u32 secdesclen = 0;
	int rc;
	unsigned int buf_size = 2048;

	pntsd = kunit_kzalloc(test, buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, pntsd);

	fattr.cf_uid = KUIDT_INIT(1000);
	fattr.cf_gid = KGIDT_INIT(1000);
	fattr.cf_mode = S_IFREG | 0644;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = build_sec_desc(&nop_mnt_idmap, pntsd, NULL, 0,
			    OWNER_SECINFO,
			    &secdesclen, &fattr, buf_size);
#else
	rc = build_sec_desc(&init_user_ns, pntsd, NULL, 0,
			    OWNER_SECINFO,
			    &secdesclen, &fattr, buf_size);
#endif

	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_NE(test, le32_to_cpu(pntsd->osidoffset), (__u32)0);

	owner = (struct smb_sid *)((char *)pntsd +
				   le32_to_cpu(pntsd->osidoffset));
	KUNIT_EXPECT_EQ(test, owner->revision, (__u8)1);
	/* uid 1000 with SIDOWNER -> domain SID with 5 sub_auths */
	KUNIT_EXPECT_EQ(test, owner->num_subauth, (__u8)5);
	/* Last sub_auth should be the uid RID (1000) */
	KUNIT_EXPECT_EQ(test, owner->sub_auth[owner->num_subauth - 1],
			cpu_to_le32(1000));
}

/* ================================================================
 * Test case array and suite definition
 * ================================================================ */

static struct kunit_case ksmbd_acl_advanced_test_cases[] = {
	/* parse_dacl tests */
	KUNIT_CASE(test_parse_dacl_owner_allow),
	KUNIT_CASE(test_parse_dacl_null_dacl),
	KUNIT_CASE(test_parse_dacl_zero_aces),
	KUNIT_CASE(test_parse_dacl_invalid_revision),
	KUNIT_CASE(test_parse_dacl_truncated_buffer),
	KUNIT_CASE(test_parse_dacl_everyone_allow),
	/* build_sec_desc tests */
	KUNIT_CASE(test_build_sec_desc_basic),
	KUNIT_CASE(test_build_sec_desc_owner_only),
	KUNIT_CASE(test_build_sec_desc_too_small),
	KUNIT_CASE(test_build_sec_desc_dacl_present),
	KUNIT_CASE(test_build_sec_desc_sacl_empty),
	KUNIT_CASE(test_build_sec_desc_owner_sid_correct),
	{}
};

static struct kunit_suite ksmbd_acl_advanced_test_suite = {
	.name = "ksmbd_acl_advanced",
	.test_cases = ksmbd_acl_advanced_test_cases,
};

kunit_test_suite(ksmbd_acl_advanced_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd parse_dacl and build_sec_desc");
