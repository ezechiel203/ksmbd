// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for ACL operations (smbacl.c)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "smbacl.h"

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

static struct kunit_case ksmbd_acl_test_cases[] = {
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
	{}
};

static struct kunit_suite ksmbd_acl_test_suite = {
	.name = "ksmbd_acl",
	.test_cases = ksmbd_acl_test_cases,
};

kunit_test_suite(ksmbd_acl_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd ACL operations");
