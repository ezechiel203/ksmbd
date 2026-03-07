// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for ACL operations (smbacl.c)
 *
 *   This file exercises both the publicly-exported ACL helpers and
 *   the formerly-static functions that are now conditionally visible
 *   via VISIBLE_IF_KUNIT / EXPORT_SYMBOL_IF_KUNIT.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smbacl.h"
#include "smb_common.h"

/* VISIBLE_IF_KUNIT helpers from smbacl.c */
void smb_copy_sid(struct smb_sid *dst, const struct smb_sid *src);
umode_t access_flags_to_mode(struct smb_fattr *fattr, __le32 ace_flags,
			     int type);
void mode_to_access_flags(umode_t mode, umode_t bits_to_use,
			  __u32 *pace_flags);
__u16 fill_ace_for_sid(struct smb_ace *pntace, const struct smb_sid *psid,
		       int type, int flags, umode_t mode, umode_t bits);
void smb_set_ace(struct smb_ace *ace, const struct smb_sid *sid, u8 type,
		 u8 flags, __le32 access_req);
size_t ksmbd_inherited_ace_size(const struct smb_ace *parent_ace,
				bool is_dir,
				const struct smb_sid *owner_sid,
				const struct smb_sid *group_sid);

static __u16 test_ace_size(const struct smb_sid *sid)
{
	return 1 + 1 + 2 + 4 + 1 + 1 + 6 + sid->num_subauth * 4;
}

/* ================================================================
 * Section 1: Original compare_sids tests (14 tests)
 * ================================================================ */

/*
 * test_compare_sids_equal - identical SIDs should compare as equal (return 0)
 */
static void test_compare_sids_equal(struct kunit *test)
{
	struct smb_sid sid1 = {
		.revision = 1,
		.num_subauth = 2,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21), cpu_to_le32(100)},
	};
	struct smb_sid sid2 = sid1;

	KUNIT_EXPECT_EQ(test, compare_sids(&sid1, &sid2), 0);
}

/*
 * test_compare_sids_different_revision - different revisions should not match
 */
static void test_compare_sids_different_revision(struct kunit *test)
{
	struct smb_sid sid1 = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21)},
	};
	struct smb_sid sid2 = sid1;

	sid2.revision = 2;
	KUNIT_EXPECT_NE(test, compare_sids(&sid1, &sid2), 0);
}

/*
 * test_compare_sids_different_subauth_count - different num_subauth
 */
static void test_compare_sids_different_subauth_count(struct kunit *test)
{
	struct smb_sid sid1 = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21)},
	};
	struct smb_sid sid2 = {
		.revision = 1,
		.num_subauth = 2,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21), cpu_to_le32(100)},
	};

	KUNIT_EXPECT_NE(test, compare_sids(&sid1, &sid2), 0);
}

/*
 * test_compare_sids_different_authority - different authority bytes
 */
static void test_compare_sids_different_authority(struct kunit *test)
{
	struct smb_sid sid1 = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21)},
	};
	struct smb_sid sid2 = sid1;

	sid2.authority[5] = 22;
	KUNIT_EXPECT_NE(test, compare_sids(&sid1, &sid2), 0);
}

/*
 * test_compare_sids_different_subauth - same structure, different sub_auth
 */
static void test_compare_sids_different_subauth(struct kunit *test)
{
	struct smb_sid sid1 = {
		.revision = 1,
		.num_subauth = 2,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21), cpu_to_le32(100)},
	};
	struct smb_sid sid2 = sid1;

	sid2.sub_auth[1] = cpu_to_le32(200);
	KUNIT_EXPECT_NE(test, compare_sids(&sid1, &sid2), 0);
}

/*
 * test_compare_sids_null - NULL arguments should return non-zero
 */
static void test_compare_sids_null(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 0,
		.authority = {0, 0, 0, 0, 0, 1},
	};

	KUNIT_EXPECT_NE(test, compare_sids(NULL, &sid), 0);
	KUNIT_EXPECT_NE(test, compare_sids(&sid, NULL), 0);
	KUNIT_EXPECT_NE(test, compare_sids(NULL, NULL), 0);
}

/*
 * test_compare_sids_everyone - verify the well-known S-1-1-0 SID
 */
static void test_compare_sids_everyone(struct kunit *test)
{
	struct smb_sid everyone = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 1},
		.sub_auth = {0},
	};
	struct smb_sid not_everyone = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(11)},
	};

	/* Everyone SID should match itself */
	KUNIT_EXPECT_EQ(test, compare_sids(&everyone, &everyone), 0);
	/* Everyone SID should not match authenticated users */
	KUNIT_EXPECT_NE(test, compare_sids(&everyone, &not_everyone), 0);
}

/*
 * test_smb_inherit_flags_file - file inheritance requires OBJECT_INHERIT_ACE
 */
static void test_smb_inherit_flags_file(struct kunit *test)
{
	/* File: only OBJECT_INHERIT_ACE triggers inheritance */
	KUNIT_EXPECT_TRUE(test, smb_inherit_flags(OBJECT_INHERIT_ACE, false));
	KUNIT_EXPECT_FALSE(test, smb_inherit_flags(CONTAINER_INHERIT_ACE, false));
	KUNIT_EXPECT_FALSE(test, smb_inherit_flags(0, false));
	KUNIT_EXPECT_TRUE(test,
		smb_inherit_flags(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
				  false));
}

/*
 * test_smb_inherit_flags_dir - directory inheritance rules
 */
static void test_smb_inherit_flags_dir(struct kunit *test)
{
	/* Directory: CONTAINER_INHERIT_ACE always triggers */
	KUNIT_EXPECT_TRUE(test, smb_inherit_flags(CONTAINER_INHERIT_ACE, true));

	/* OBJECT_INHERIT_ACE without NO_PROPAGATE triggers */
	KUNIT_EXPECT_TRUE(test, smb_inherit_flags(OBJECT_INHERIT_ACE, true));

	/* OBJECT_INHERIT_ACE with NO_PROPAGATE does NOT trigger */
	KUNIT_EXPECT_FALSE(test,
		smb_inherit_flags(OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
				  true));

	/* No flags: no inheritance */
	KUNIT_EXPECT_FALSE(test, smb_inherit_flags(0, true));

	/* Both CONTAINER and OBJECT triggers */
	KUNIT_EXPECT_TRUE(test,
		smb_inherit_flags(CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
				  true));
}

/*
 * test_init_free_acl_state - basic alloc/free of posix_acl_state
 */
static void test_init_free_acl_state(struct kunit *test)
{
	struct posix_acl_state state;
	int ret;

	ret = init_acl_state(&state, 4);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_NOT_NULL(test, state.users);
	KUNIT_ASSERT_NOT_NULL(test, state.groups);

	/* Verify zero-initialization */
	KUNIT_EXPECT_EQ(test, state.users->n, 0);
	KUNIT_EXPECT_EQ(test, state.groups->n, 0);
	KUNIT_EXPECT_EQ(test, state.owner.allow, (u32)0);
	KUNIT_EXPECT_EQ(test, state.group.allow, (u32)0);
	KUNIT_EXPECT_EQ(test, state.other.allow, (u32)0);

	free_acl_state(&state);
}

/*
 * test_id_to_sid_owner - id_to_sid with SIDOWNER type
 */
static void test_id_to_sid_owner(struct kunit *test)
{
	struct smb_sid sid = {};

	id_to_sid(1000, SIDOWNER, &sid);
	KUNIT_EXPECT_EQ(test, sid.revision, (__u8)1);
	/* Domain SID has 4 base sub_auth + 1 RID appended = 5 */
	KUNIT_EXPECT_EQ(test, sid.num_subauth, (__u8)5);
	KUNIT_EXPECT_EQ(test, sid.sub_auth[sid.num_subauth - 1],
			cpu_to_le32(1000));
}

/*
 * test_id_to_sid_unix_user - id_to_sid with SIDUNIX_USER type
 */
static void test_id_to_sid_unix_user(struct kunit *test)
{
	struct smb_sid sid = {};

	id_to_sid(500, SIDUNIX_USER, &sid);
	KUNIT_EXPECT_EQ(test, sid.revision, (__u8)1);
	/* Unix users SID: S-1-22-1-<uid>, so 1 base + 1 RID = 2 */
	KUNIT_EXPECT_EQ(test, sid.num_subauth, (__u8)2);
	KUNIT_EXPECT_EQ(test, sid.authority[5], (__u8)22);
	KUNIT_EXPECT_EQ(test, sid.sub_auth[0], cpu_to_le32(1));
	KUNIT_EXPECT_EQ(test, sid.sub_auth[1], cpu_to_le32(500));
}

/*
 * test_id_to_sid_unix_group - id_to_sid with SIDUNIX_GROUP type
 */
static void test_id_to_sid_unix_group(struct kunit *test)
{
	struct smb_sid sid = {};

	id_to_sid(1000, SIDUNIX_GROUP, &sid);
	KUNIT_EXPECT_EQ(test, sid.revision, (__u8)1);
	/* Unix groups SID: S-1-22-2-<gid>, so 1 base + 1 RID = 2 */
	KUNIT_EXPECT_EQ(test, sid.num_subauth, (__u8)2);
	KUNIT_EXPECT_EQ(test, sid.authority[5], (__u8)22);
	KUNIT_EXPECT_EQ(test, sid.sub_auth[0], cpu_to_le32(2));
	KUNIT_EXPECT_EQ(test, sid.sub_auth[1], cpu_to_le32(1000));
}

/*
 * test_id_to_sid_creator_owner - SIDCREATOR_OWNER should not append RID
 */
static void test_id_to_sid_creator_owner(struct kunit *test)
{
	struct smb_sid sid = {};

	id_to_sid(0, SIDCREATOR_OWNER, &sid);
	KUNIT_EXPECT_EQ(test, sid.revision, (__u8)1);
	/* Creator owner: S-1-3-0, num_subauth=1, no RID appended */
	KUNIT_EXPECT_EQ(test, sid.num_subauth, (__u8)1);
	KUNIT_EXPECT_EQ(test, sid.authority[5], (__u8)3);
}

/* ================================================================
 * Section 2: Tests for exported functions (14 tests)
 * ================================================================ */

/*
 * test_smb_copy_sid - smb_copy_sid should faithfully copy all SID fields
 */
static void test_smb_copy_sid(struct kunit *test)
{
	struct smb_sid src = {
		.revision = 1,
		.num_subauth = 3,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21), cpu_to_le32(100), cpu_to_le32(200)},
	};
	struct smb_sid dst = {};

	smb_copy_sid(&dst, &src);

	KUNIT_EXPECT_EQ(test, dst.revision, (__u8)1);
	KUNIT_EXPECT_EQ(test, dst.num_subauth, (__u8)3);
	KUNIT_EXPECT_EQ(test, memcmp(dst.authority, src.authority, NUM_AUTHS), 0);
	KUNIT_EXPECT_EQ(test, dst.sub_auth[0], cpu_to_le32(21));
	KUNIT_EXPECT_EQ(test, dst.sub_auth[1], cpu_to_le32(100));
	KUNIT_EXPECT_EQ(test, dst.sub_auth[2], cpu_to_le32(200));
}

/*
 * test_smb_copy_sid_zero_subauth - copy SID with zero sub-authorities
 */
static void test_smb_copy_sid_zero_subauth(struct kunit *test)
{
	struct smb_sid src = {
		.revision = 1,
		.num_subauth = 0,
		.authority = {0, 0, 0, 0, 0, 1},
	};
	struct smb_sid dst = {};

	smb_copy_sid(&dst, &src);

	KUNIT_EXPECT_EQ(test, dst.revision, (__u8)1);
	KUNIT_EXPECT_EQ(test, dst.num_subauth, (__u8)0);
	KUNIT_EXPECT_EQ(test, dst.authority[5], (__u8)1);
}

/*
 * test_access_flags_to_mode_read - GENERIC_READ should produce 0444
 */
static void test_access_flags_to_mode_read(struct kunit *test)
{
	struct smb_fattr fattr = {};
	umode_t mode;

	fattr.cf_mode = S_IFREG;
	mode = access_flags_to_mode(&fattr, cpu_to_le32(GENERIC_READ),
				    ACCESS_ALLOWED_ACE_TYPE);
	KUNIT_EXPECT_EQ(test, mode, (umode_t)0444);
}

/*
 * test_access_flags_to_mode_write - GENERIC_WRITE on file should produce 0222
 */
static void test_access_flags_to_mode_write(struct kunit *test)
{
	struct smb_fattr fattr = {};
	umode_t mode;

	fattr.cf_mode = S_IFREG; /* regular file */
	mode = access_flags_to_mode(&fattr, cpu_to_le32(GENERIC_WRITE),
				    ACCESS_ALLOWED_ACE_TYPE);
	/* GENERIC_WRITE on a regular file: 0222 (no execute for files) */
	KUNIT_EXPECT_EQ(test, mode, (umode_t)0222);
}

/*
 * test_access_flags_to_mode_write_dir - GENERIC_WRITE on dir should produce 0333
 */
static void test_access_flags_to_mode_write_dir(struct kunit *test)
{
	struct smb_fattr fattr = {};
	umode_t mode;

	fattr.cf_mode = S_IFDIR; /* directory */
	mode = access_flags_to_mode(&fattr, cpu_to_le32(GENERIC_WRITE),
				    ACCESS_ALLOWED_ACE_TYPE);
	/* GENERIC_WRITE on directory: 0222 | 0111 = 0333 */
	KUNIT_EXPECT_EQ(test, mode, (umode_t)0333);
}

/*
 * test_access_flags_to_mode_exec - GENERIC_EXECUTE should produce 0111
 */
static void test_access_flags_to_mode_exec(struct kunit *test)
{
	struct smb_fattr fattr = {};
	umode_t mode;

	fattr.cf_mode = S_IFREG;
	mode = access_flags_to_mode(&fattr, cpu_to_le32(GENERIC_EXECUTE),
				    ACCESS_ALLOWED_ACE_TYPE);
	KUNIT_EXPECT_EQ(test, mode, (umode_t)0111);
}

/*
 * test_access_flags_to_mode_all - GENERIC_ALL should produce 0777
 */
static void test_access_flags_to_mode_all(struct kunit *test)
{
	struct smb_fattr fattr = {};
	umode_t mode;

	fattr.cf_mode = S_IFREG;
	mode = access_flags_to_mode(&fattr, cpu_to_le32(GENERIC_ALL),
				    ACCESS_ALLOWED_ACE_TYPE);
	KUNIT_EXPECT_EQ(test, mode, (umode_t)0777);
}

/*
 * test_mode_to_access_flags_rwx - mode 0777 should set read+write+exec flags
 */
static void test_mode_to_access_flags_rwx(struct kunit *test)
{
	__u32 flags = 0;

	mode_to_access_flags(0777, S_IRWXU, &flags);

	KUNIT_EXPECT_TRUE(test, (flags & SET_FILE_READ_RIGHTS) != 0);
	KUNIT_EXPECT_TRUE(test, (flags & FILE_WRITE_RIGHTS) != 0);
	KUNIT_EXPECT_TRUE(test, (flags & SET_FILE_EXEC_RIGHTS) != 0);
}

/*
 * test_mode_to_access_flags_none - mode 0000 should produce no flags
 */
static void test_mode_to_access_flags_none(struct kunit *test)
{
	__u32 flags = 0xDEADBEEF;  /* start dirty to verify reset */

	mode_to_access_flags(0000, S_IRWXU, &flags);

	KUNIT_EXPECT_EQ(test, flags, (__u32)0);
}

/*
 * test_fill_ace_for_sid_basic - fill_ace_for_sid with valid SID and rwx mode
 */
static void test_fill_ace_for_sid_basic(struct kunit *test)
{
	struct smb_ace *ace;
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21)},
	};
	__u16 size;

	ace = kunit_kzalloc(test, sizeof(*ace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ace);

	size = fill_ace_for_sid(ace, &sid, ACCESS_ALLOWED_ACE_TYPE, 0,
				0755, S_IRWXU);
	KUNIT_EXPECT_GT(test, size, (__u16)0);
	KUNIT_EXPECT_EQ(test, ace->type, (__u8)ACCESS_ALLOWED_ACE_TYPE);
	KUNIT_EXPECT_EQ(test, ace->flags, (__u8)0);
	KUNIT_EXPECT_EQ(test, ace->sid.revision, (__u8)1);
	KUNIT_EXPECT_EQ(test, ace->sid.num_subauth, (__u8)1);
	/* access_req should be non-zero for mode 0755 with S_IRWXU mask */
	KUNIT_EXPECT_NE(test, ace->access_req, cpu_to_le32(0));
}

/*
 * test_smb_set_ace - smb_set_ace should fill all fields correctly
 */
static void test_smb_set_ace(struct kunit *test)
{
	struct smb_ace *ace;
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 2,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21), cpu_to_le32(500)},
	};

	ace = kunit_kzalloc(test, sizeof(*ace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ace);

	smb_set_ace(ace, &sid, ACCESS_ALLOWED_ACE_TYPE, 0,
		    cpu_to_le32(FILE_WRITE_RIGHTS));

	KUNIT_EXPECT_EQ(test, ace->type, (__u8)ACCESS_ALLOWED_ACE_TYPE);
	KUNIT_EXPECT_EQ(test, ace->flags, (__u8)0);
	KUNIT_EXPECT_EQ(test, ace->access_req, cpu_to_le32(FILE_WRITE_RIGHTS));
	KUNIT_EXPECT_EQ(test, ace->sid.revision, (__u8)1);
	KUNIT_EXPECT_EQ(test, ace->sid.num_subauth, (__u8)2);
	KUNIT_EXPECT_EQ(test, ace->sid.sub_auth[0], cpu_to_le32(21));
	KUNIT_EXPECT_EQ(test, ace->sid.sub_auth[1], cpu_to_le32(500));
	/* Size: 1+1+2+4+1+1+6+(2*4) = 24 */
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ace->size), (__u16)24);
}

/*
 * test_smb_set_ace_with_flags - smb_set_ace with inheritance flags
 */
static void test_smb_set_ace_with_flags(struct kunit *test)
{
	struct smb_ace *ace;
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 1},
		.sub_auth = {0},
	};

	ace = kunit_kzalloc(test, sizeof(*ace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ace);

	smb_set_ace(ace, &sid, ACCESS_DENIED_ACE_TYPE,
		    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
		    cpu_to_le32(GENERIC_ALL));

	KUNIT_EXPECT_EQ(test, ace->type, (__u8)ACCESS_DENIED_ACE_TYPE);
	KUNIT_EXPECT_EQ(test, ace->flags,
			(__u8)(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE));
	KUNIT_EXPECT_EQ(test, ace->access_req, cpu_to_le32(GENERIC_ALL));
}

/*
 * test_parse_sid_valid - parse_sid with a valid SID should succeed
 */
static void test_parse_sid_valid(struct kunit *test)
{
	/* Construct a minimal SID buffer: revision(1) + num_subauth(1) +
	 * authority(6) + 1 sub_auth(4) = 12 bytes
	 */
	char buf[16] = {};
	struct smb_sid *psid = (struct smb_sid *)buf;
	char *end;

	psid->revision = 1;
	psid->num_subauth = 1;
	psid->authority[5] = 5;
	psid->sub_auth[0] = cpu_to_le32(21);
	end = buf + 12;  /* exactly covers the SID */

	KUNIT_EXPECT_EQ(test, parse_sid(psid, end), 0);
}

/*
 * test_parse_sid_truncated - parse_sid with buffer too small for header
 */
static void test_parse_sid_truncated(struct kunit *test)
{
	char buf[4] = {};
	struct smb_sid *psid = (struct smb_sid *)buf;
	char *end = buf + 4;  /* too small: need at least 8 bytes for header */

	KUNIT_EXPECT_EQ(test, parse_sid(psid, end), -EINVAL);
}

/* ================================================================
 * Section 3: Error path / edge case tests (7 tests)
 * ================================================================ */

/*
 * test_access_flags_to_mode_denied - ACCESS_DENIED_ACE_TYPE inverts the mode
 */
static void test_access_flags_to_mode_denied(struct kunit *test)
{
	struct smb_fattr fattr = {};
	umode_t mode;

	fattr.cf_mode = S_IFREG;
	mode = access_flags_to_mode(&fattr, cpu_to_le32(GENERIC_ALL),
				    ACCESS_DENIED_ACE_TYPE);
	/* GENERIC_ALL produces 0777, then ACCESS_DENIED inverts to ~0777 */
	KUNIT_EXPECT_EQ(test, mode, (umode_t)~0777);
}

/*
 * test_mode_to_access_flags_read_only - read-only mode sets only read flags
 */
static void test_mode_to_access_flags_read_only(struct kunit *test)
{
	__u32 flags = 0;

	mode_to_access_flags(0444, S_IRWXU, &flags);

	KUNIT_EXPECT_TRUE(test, (flags & SET_FILE_READ_RIGHTS) != 0);
	/* Write and execute bits should NOT be set */
	KUNIT_EXPECT_EQ(test, flags & FILE_WRITE_RIGHTS, (__u32)0);
	KUNIT_EXPECT_EQ(test, flags & SET_FILE_EXEC_RIGHTS, (__u32)0);
}

/*
 * test_fill_ace_for_sid_zero_mode - zero mode triggers SET_MINIMUM_RIGHTS
 */
static void test_fill_ace_for_sid_zero_mode(struct kunit *test)
{
	struct smb_ace *ace;
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21)},
	};
	__u16 size;

	ace = kunit_kzalloc(test, sizeof(*ace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ace);

	/* mode=0, bits=S_IRWXU: mode_to_access_flags returns 0,
	 * so fill_ace_for_sid falls back to SET_MINIMUM_RIGHTS
	 */
	size = fill_ace_for_sid(ace, &sid, ACCESS_ALLOWED_ACE_TYPE, 0,
				0, S_IRWXU);
	KUNIT_EXPECT_GT(test, size, (__u16)0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ace->access_req),
			(__u32)SET_MINIMUM_RIGHTS);
}

/*
 * test_smb_copy_sid_max_subauth - copy SID with SID_MAX_SUB_AUTHORITIES
 */
static void test_smb_copy_sid_max_subauth(struct kunit *test)
{
	struct smb_sid src = {
		.revision = 1,
		.num_subauth = SID_MAX_SUB_AUTHORITIES,
		.authority = {0, 0, 0, 0, 0, 5},
	};
	struct smb_sid dst = {};
	int i;

	for (i = 0; i < SID_MAX_SUB_AUTHORITIES; i++)
		src.sub_auth[i] = cpu_to_le32(i + 1);

	smb_copy_sid(&dst, &src);

	KUNIT_EXPECT_EQ(test, dst.num_subauth, (__u8)SID_MAX_SUB_AUTHORITIES);
	for (i = 0; i < SID_MAX_SUB_AUTHORITIES; i++)
		KUNIT_EXPECT_EQ(test, dst.sub_auth[i], cpu_to_le32(i + 1));
}

/*
 * test_init_acl_state_zero_count - init_acl_state with zero entry count
 */
static void test_init_acl_state_zero_count(struct kunit *test)
{
	struct posix_acl_state state;
	int ret;

	ret = init_acl_state(&state, 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_NOT_NULL(test, state.users);
	KUNIT_ASSERT_NOT_NULL(test, state.groups);
	KUNIT_EXPECT_EQ(test, state.users->n, 0);
	KUNIT_EXPECT_EQ(test, state.groups->n, 0);

	free_acl_state(&state);
}

/*
 * test_id_to_sid_group - SIDCREATOR_GROUP maps to S-1-3-1
 */
static void test_id_to_sid_creator_group(struct kunit *test)
{
	struct smb_sid sid = {};

	id_to_sid(0, SIDCREATOR_GROUP, &sid);
	KUNIT_EXPECT_EQ(test, sid.revision, (__u8)1);
	/* Creator group: S-1-3-1, num_subauth=1, no RID appended */
	KUNIT_EXPECT_EQ(test, sid.num_subauth, (__u8)1);
	KUNIT_EXPECT_EQ(test, sid.authority[5], (__u8)3);
	KUNIT_EXPECT_EQ(test, sid.sub_auth[0], cpu_to_le32(1));
}

/*
 * test_parse_sid_max_subauth - parse_sid at the boundary of max sub-authorities
 */
static void test_parse_sid_max_subauth(struct kunit *test)
{
	/* Buffer large enough for SID_MAX_SUB_AUTHORITIES sub-auths:
	 * 8 (header) + 15*4 (sub_auths) = 68 bytes
	 */
	char buf[68] = {};
	struct smb_sid *psid = (struct smb_sid *)buf;
	char *end = buf + sizeof(buf);

	psid->revision = 1;
	psid->num_subauth = SID_MAX_SUB_AUTHORITIES;
	psid->authority[5] = 5;

	KUNIT_EXPECT_EQ(test, parse_sid(psid, end), 0);
}

static void test_inherited_ace_size_creator_owner_dir(struct kunit *test)
{
	struct smb_ace ace = {};
	struct smb_sid owner_sid;
	struct smb_sid group_sid;
	size_t expected;

	id_to_sid(1234, SIDCREATOR_OWNER, &ace.sid);
	id_to_sid(1234, SIDOWNER, &owner_sid);
	id_to_sid(4321, SIDUNIX_GROUP, &group_sid);
	ace.flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;

	expected = test_ace_size(&owner_sid) + test_ace_size(&ace.sid);
	KUNIT_EXPECT_EQ(test,
			(unsigned long long)ksmbd_inherited_ace_size(&ace, true,
								     &owner_sid,
								     &group_sid),
			(unsigned long long)expected);
}

static void test_inherited_ace_size_noninherit_zero(struct kunit *test)
{
	struct smb_ace ace = {};
	struct smb_sid owner_sid;
	struct smb_sid group_sid;

	id_to_sid(1234, SIDOWNER, &owner_sid);
	id_to_sid(4321, SIDUNIX_GROUP, &group_sid);
	ace.flags = 0;

	KUNIT_EXPECT_EQ(test,
			(unsigned long long)ksmbd_inherited_ace_size(&ace, true,
								     &owner_sid,
								     &group_sid),
			0ULL);
}

/* ================================================================
 * Test case array and suite definition
 * ================================================================ */

static struct kunit_case ksmbd_acl_test_cases[] = {
	/* Section 1: Original compare_sids tests */
	KUNIT_CASE(test_compare_sids_equal),
	KUNIT_CASE(test_compare_sids_different_revision),
	KUNIT_CASE(test_compare_sids_different_subauth_count),
	KUNIT_CASE(test_compare_sids_different_authority),
	KUNIT_CASE(test_compare_sids_different_subauth),
	KUNIT_CASE(test_compare_sids_null),
	KUNIT_CASE(test_compare_sids_everyone),
	KUNIT_CASE(test_smb_inherit_flags_file),
	KUNIT_CASE(test_smb_inherit_flags_dir),
	KUNIT_CASE(test_init_free_acl_state),
	KUNIT_CASE(test_id_to_sid_owner),
	KUNIT_CASE(test_id_to_sid_unix_user),
	KUNIT_CASE(test_id_to_sid_unix_group),
	KUNIT_CASE(test_id_to_sid_creator_owner),
	/* Section 2: Tests for exported functions */
	KUNIT_CASE(test_smb_copy_sid),
	KUNIT_CASE(test_smb_copy_sid_zero_subauth),
	KUNIT_CASE(test_access_flags_to_mode_read),
	KUNIT_CASE(test_access_flags_to_mode_write),
	KUNIT_CASE(test_access_flags_to_mode_write_dir),
	KUNIT_CASE(test_access_flags_to_mode_exec),
	KUNIT_CASE(test_access_flags_to_mode_all),
	KUNIT_CASE(test_mode_to_access_flags_rwx),
	KUNIT_CASE(test_mode_to_access_flags_none),
	KUNIT_CASE(test_fill_ace_for_sid_basic),
	KUNIT_CASE(test_smb_set_ace),
	KUNIT_CASE(test_smb_set_ace_with_flags),
	KUNIT_CASE(test_inherited_ace_size_creator_owner_dir),
	KUNIT_CASE(test_inherited_ace_size_noninherit_zero),
	KUNIT_CASE(test_parse_sid_valid),
	KUNIT_CASE(test_parse_sid_truncated),
	/* Section 3: Error path / edge case tests */
	KUNIT_CASE(test_access_flags_to_mode_denied),
	KUNIT_CASE(test_mode_to_access_flags_read_only),
	KUNIT_CASE(test_fill_ace_for_sid_zero_mode),
	KUNIT_CASE(test_smb_copy_sid_max_subauth),
	KUNIT_CASE(test_init_acl_state_zero_count),
	KUNIT_CASE(test_id_to_sid_creator_group),
	KUNIT_CASE(test_parse_sid_max_subauth),
	{}
};

static struct kunit_suite ksmbd_acl_test_suite = {
	.name = "ksmbd_acl",
	.test_cases = ksmbd_acl_test_cases,
};

kunit_test_suite(ksmbd_acl_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd ACL operations");
