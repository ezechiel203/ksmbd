// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for domain-aware SID-to-UID mapping (smbacl.c)
 *
 *   Tests the security fix for SID-to-UID mapping collisions in
 *   multi-domain environments.  Previously, only the RID (last
 *   sub-authority) was used, so DOMAIN1\user (S-1-5-21-X-Y-Z-500)
 *   and DOMAIN2\user (S-1-5-21-A-B-C-500) both mapped to UID 500.
 *
 *   The fix adds domain-aware validation: local domain SIDs use the
 *   RID directly, while foreign domain SIDs get a hash-based offset.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smbacl.h"
#include "server.h"

/*
 * Helper: Build a domain SID S-1-5-21-<a>-<b>-<c>-<rid>
 */
static void build_domain_sid(struct smb_sid *sid, u32 a, u32 b, u32 c, u32 rid)
{
	memset(sid, 0, sizeof(*sid));
	sid->revision = 1;
	sid->num_subauth = 5;
	sid->authority[5] = 5;
	sid->sub_auth[0] = cpu_to_le32(21);
	sid->sub_auth[1] = cpu_to_le32(a);
	sid->sub_auth[2] = cpu_to_le32(b);
	sid->sub_auth[3] = cpu_to_le32(c);
	sid->sub_auth[4] = cpu_to_le32(rid);
}

/*
 * Helper: Build a Unix user SID S-1-22-1-<uid>
 */
static void build_unix_user_sid(struct smb_sid *sid, u32 uid)
{
	memset(sid, 0, sizeof(*sid));
	sid->revision = 1;
	sid->num_subauth = 2;
	sid->authority[5] = 22;
	sid->sub_auth[0] = cpu_to_le32(1);
	sid->sub_auth[1] = cpu_to_le32(uid);
}

/*
 * Helper: Build a Unix group SID S-1-22-2-<gid>
 */
static void build_unix_group_sid(struct smb_sid *sid, u32 gid)
{
	memset(sid, 0, sizeof(*sid));
	sid->revision = 1;
	sid->num_subauth = 2;
	sid->authority[5] = 22;
	sid->sub_auth[0] = cpu_to_le32(2);
	sid->sub_auth[1] = cpu_to_le32(gid);
}

/*
 * Helper: Build an NFS user SID S-1-5-88-1-<uid>
 */
static void build_nfs_user_sid(struct smb_sid *sid, u32 uid)
{
	memset(sid, 0, sizeof(*sid));
	sid->revision = 1;
	sid->num_subauth = 3;
	sid->authority[5] = 5;
	sid->sub_auth[0] = cpu_to_le32(88);
	sid->sub_auth[1] = cpu_to_le32(1);
	sid->sub_auth[2] = cpu_to_le32(uid);
}

/* ================================================================
 * Test suite init: configure server_conf.domain_sid
 * ================================================================ */

/*
 * Set the server's domain SID to S-1-5-21-1000-2000-3000
 * (a typical AD domain SID with 4 sub-authorities).
 */
static int sid_mapping_suite_init(struct kunit_suite *suite)
{
	u32 sub_auth[3] = {1000, 2000, 3000};

	ksmbd_init_domain(sub_auth);
	return 0;
}

/* ================================================================
 * Section 1: Same RID from different domains (core collision test)
 * ================================================================ */

/*
 * test_same_rid_different_domains - The critical security test.
 * Same RID (500) from two different domains must map to different UIDs.
 */
static void test_same_rid_different_domains(struct kunit *test)
{
	struct smb_sid sid_local, sid_foreign;
	uid_t uid_local, uid_foreign;
	int rc;

	/* Local domain: S-1-5-21-1000-2000-3000-500 */
	build_domain_sid(&sid_local, 1000, 2000, 3000, 500);
	/* Foreign domain: S-1-5-21-9999-8888-7777-500 */
	build_domain_sid(&sid_foreign, 9999, 8888, 7777, 500);

	rc = ksmbd_sid_to_id_domain_aware(&sid_local, &uid_local);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = ksmbd_sid_to_id_domain_aware(&sid_foreign, &uid_foreign);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* The whole point: same RID, different domains -> different UIDs */
	KUNIT_EXPECT_NE(test, uid_local, uid_foreign);
}

/*
 * test_local_domain_uses_rid_directly - SIDs from the server's domain
 * should use the RID directly (backward compatibility).
 */
static void test_local_domain_uses_rid_directly(struct kunit *test)
{
	struct smb_sid sid;
	uid_t uid;
	int rc;

	build_domain_sid(&sid, 1000, 2000, 3000, 1234);
	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);

	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, uid, (uid_t)1234);
}

/*
 * test_foreign_domain_gets_offset - Foreign domain SIDs must get a
 * non-zero offset applied.
 */
static void test_foreign_domain_gets_offset(struct kunit *test)
{
	struct smb_sid sid;
	uid_t uid;
	int rc;

	build_domain_sid(&sid, 5555, 6666, 7777, 1234);
	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);

	KUNIT_ASSERT_EQ(test, rc, 0);
	/* Foreign UID must be >= DOMAIN_UID_OFFSET_MULTIPLIER */
	KUNIT_EXPECT_GE(test, uid, (uid_t)DOMAIN_UID_OFFSET_MULTIPLIER);
	/* But the lower portion should still contain the RID */
	KUNIT_EXPECT_EQ(test, uid % DOMAIN_UID_OFFSET_MULTIPLIER, (uid_t)1234);
}

/*
 * test_two_foreign_domains_differ - Two different foreign domains
 * with the same RID should (with very high probability) map to different UIDs.
 */
static void test_two_foreign_domains_differ(struct kunit *test)
{
	struct smb_sid sid1, sid2;
	uid_t uid1, uid2;
	int rc;

	build_domain_sid(&sid1, 111, 222, 333, 42);
	build_domain_sid(&sid2, 444, 555, 666, 42);

	rc = ksmbd_sid_to_id_domain_aware(&sid1, &uid1);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = ksmbd_sid_to_id_domain_aware(&sid2, &uid2);
	KUNIT_ASSERT_EQ(test, rc, 0);

	KUNIT_EXPECT_NE(test, uid1, uid2);
}

/* ================================================================
 * Section 2: Well-known SID handling
 * ================================================================ */

/*
 * test_wellknown_unix_user_sid - S-1-22-1-<uid> should pass through
 * (treated as local).
 */
static void test_wellknown_unix_user_sid(struct kunit *test)
{
	struct smb_sid sid;
	uid_t uid;
	int rc;

	build_unix_user_sid(&sid, 1000);
	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);

	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, uid, (uid_t)1000);
}

/*
 * test_wellknown_unix_group_sid - S-1-22-2-<gid> should pass through.
 */
static void test_wellknown_unix_group_sid(struct kunit *test)
{
	struct smb_sid sid;
	uid_t uid;
	int rc;

	build_unix_group_sid(&sid, 500);
	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);

	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, uid, (uid_t)500);
}

/*
 * test_wellknown_nfs_user_sid - S-1-5-88-1-<uid> should pass through.
 */
static void test_wellknown_nfs_user_sid(struct kunit *test)
{
	struct smb_sid sid;
	uid_t uid;
	int rc;

	build_nfs_user_sid(&sid, 65534);
	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);

	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, uid, (uid_t)65534);
}

/*
 * test_wellknown_local_system - S-1-5-18 (LocalSystem) should be
 * handled (one sub-authority, domain doesn't apply).
 */
static void test_wellknown_local_system(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(18)},
	};
	uid_t uid;
	int rc;

	/*
	 * S-1-5-18 has only 1 sub-authority, which is also the RID.
	 * It should not be treated as having a domain prefix, so
	 * domain_match should fail and it gets a foreign offset.
	 * That's fine -- LocalSystem is not a user account on Linux.
	 * The important thing is no crash.
	 */
	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);
	KUNIT_ASSERT_EQ(test, rc, 0);
}

/*
 * test_wellknown_builtin_admins - S-1-5-32-544 (BUILTIN\Administrators)
 * has authority=5 but sub_auth[0]=32, not 21 or 88, so it's a foreign
 * SID relative to any domain.
 */
static void test_wellknown_builtin_admins(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 2,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(32), cpu_to_le32(544)},
	};
	uid_t uid;
	int rc;

	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);
	KUNIT_ASSERT_EQ(test, rc, 0);
	/* Should get an offset since it's not our domain */
}

/* ================================================================
 * Section 3: Edge cases and error handling
 * ================================================================ */

/*
 * test_sid_zero_subauth_rejected - SID with 0 sub-authorities must fail.
 */
static void test_sid_zero_subauth_rejected(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 0,
		.authority = {0, 0, 0, 0, 0, 5},
	};
	uid_t uid;
	int rc;

	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);
	KUNIT_EXPECT_NE(test, rc, 0);
}

/*
 * test_sid_max_subauth_handled - SID with SID_MAX_SUB_AUTHORITIES (15)
 * sub-authorities should be accepted.
 */
static void test_sid_max_subauth_handled(struct kunit *test)
{
	struct smb_sid sid;
	uid_t uid;
	int rc, i;

	memset(&sid, 0, sizeof(sid));
	sid.revision = 1;
	sid.num_subauth = SID_MAX_SUB_AUTHORITIES;
	sid.authority[5] = 5;
	sid.sub_auth[0] = cpu_to_le32(21);
	for (i = 1; i < SID_MAX_SUB_AUTHORITIES; i++)
		sid.sub_auth[i] = cpu_to_le32(i * 100);

	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);
	KUNIT_ASSERT_EQ(test, rc, 0);
}

/*
 * test_sid_over_max_subauth_rejected - SID with > SID_MAX_SUB_AUTHORITIES
 * must be rejected.
 */
static void test_sid_over_max_subauth_rejected(struct kunit *test)
{
	struct smb_sid sid;
	uid_t uid;
	int rc;

	memset(&sid, 0, sizeof(sid));
	sid.revision = 1;
	sid.num_subauth = SID_MAX_SUB_AUTHORITIES + 1;
	sid.authority[5] = 5;

	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);
	KUNIT_EXPECT_NE(test, rc, 0);
}

/*
 * test_null_sid_rejected - NULL SID pointer must fail gracefully.
 */
static void test_null_sid_rejected(struct kunit *test)
{
	uid_t uid;
	int rc;

	rc = ksmbd_sid_to_id_domain_aware(NULL, &uid);
	KUNIT_EXPECT_NE(test, rc, 0);
}

/*
 * test_null_output_rejected - NULL output pointer must fail.
 */
static void test_null_output_rejected(struct kunit *test)
{
	struct smb_sid sid;
	int rc;

	build_domain_sid(&sid, 1000, 2000, 3000, 100);
	rc = ksmbd_sid_to_id_domain_aware(&sid, NULL);
	KUNIT_EXPECT_NE(test, rc, 0);
}

/*
 * test_everyone_sid_rejected - The Everyone SID (S-1-1-0) should be
 * rejected by the mapping function.
 */
static void test_everyone_sid_rejected(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 1},
		.sub_auth = {0},
	};
	uid_t uid;
	int rc;

	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);
	KUNIT_EXPECT_NE(test, rc, 0);
}

/*
 * test_rid_overflow_protection - RID near U32_MAX with foreign domain
 * offset should be rejected to prevent overflow.
 */
static void test_rid_overflow_protection(struct kunit *test)
{
	struct smb_sid sid;
	uid_t uid;
	int rc;

	/* Foreign domain with a very large RID close to U32_MAX */
	build_domain_sid(&sid, 5555, 6666, 7777, U32_MAX - 1);
	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);

	/*
	 * The foreign domain offset is at least DOMAIN_UID_OFFSET_MULTIPLIER,
	 * so adding it to (U32_MAX - 1) would overflow.  Must be rejected.
	 */
	KUNIT_EXPECT_NE(test, rc, 0);
}

/*
 * test_rid_zero_local_domain - RID 0 from local domain should map to UID 0.
 */
static void test_rid_zero_local_domain(struct kunit *test)
{
	struct smb_sid sid;
	uid_t uid;
	int rc;

	build_domain_sid(&sid, 1000, 2000, 3000, 0);
	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid);

	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, uid, (uid_t)0);
}

/* ================================================================
 * Section 4: Domain prefix extraction and hash tests
 * ================================================================ */

/*
 * test_extract_domain_prefix_basic - extract domain prefix from a 5-subauth SID
 */
static void test_extract_domain_prefix_basic(struct kunit *test)
{
	struct smb_sid sid, dom;
	int rc;

	build_domain_sid(&sid, 1000, 2000, 3000, 500);
	rc = ksmbd_extract_domain_prefix(&sid, &dom);

	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, dom.revision, (__u8)1);
	KUNIT_EXPECT_EQ(test, dom.num_subauth, (__u8)4);
	KUNIT_EXPECT_EQ(test, dom.authority[5], (__u8)5);
	KUNIT_EXPECT_EQ(test, dom.sub_auth[0], cpu_to_le32(21));
	KUNIT_EXPECT_EQ(test, dom.sub_auth[1], cpu_to_le32(1000));
	KUNIT_EXPECT_EQ(test, dom.sub_auth[2], cpu_to_le32(2000));
	KUNIT_EXPECT_EQ(test, dom.sub_auth[3], cpu_to_le32(3000));
}

/*
 * test_extract_domain_prefix_null_input - NULL input should fail.
 */
static void test_extract_domain_prefix_null_input(struct kunit *test)
{
	struct smb_sid dom;

	KUNIT_EXPECT_NE(test, ksmbd_extract_domain_prefix(NULL, &dom), 0);
}

/*
 * test_extract_domain_prefix_null_output - NULL output should fail.
 */
static void test_extract_domain_prefix_null_output(struct kunit *test)
{
	struct smb_sid sid;

	build_domain_sid(&sid, 1, 2, 3, 4);
	KUNIT_EXPECT_NE(test, ksmbd_extract_domain_prefix(&sid, NULL), 0);
}

/*
 * test_extract_domain_prefix_zero_subauth - 0 sub-auths should fail.
 */
static void test_extract_domain_prefix_zero_subauth(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 0,
		.authority = {0, 0, 0, 0, 0, 5},
	};
	struct smb_sid dom;

	KUNIT_EXPECT_NE(test, ksmbd_extract_domain_prefix(&sid, &dom), 0);
}

/*
 * test_domain_hash_deterministic - Same domain should always produce the
 * same hash.
 */
static void test_domain_hash_deterministic(struct kunit *test)
{
	struct smb_sid sid;
	u32 h1, h2;

	build_domain_sid(&sid, 100, 200, 300, 42);
	h1 = ksmbd_domain_sid_hash(&sid);
	h2 = ksmbd_domain_sid_hash(&sid);

	KUNIT_EXPECT_EQ(test, h1, h2);
}

/*
 * test_domain_hash_different_domains - Different domains should produce
 * different hashes (with very high probability).
 */
static void test_domain_hash_different_domains(struct kunit *test)
{
	struct smb_sid sid1, sid2;
	u32 h1, h2;

	build_domain_sid(&sid1, 100, 200, 300, 42);
	build_domain_sid(&sid2, 400, 500, 600, 42);
	h1 = ksmbd_domain_sid_hash(&sid1);
	h2 = ksmbd_domain_sid_hash(&sid2);

	KUNIT_EXPECT_NE(test, h1, h2);
}

/*
 * test_domain_hash_null - NULL SID should return hash 0.
 */
static void test_domain_hash_null(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_domain_sid_hash(NULL), (u32)0);
}

/*
 * test_domain_hash_single_subauth - SID with only 1 sub-authority has
 * no domain prefix, should return 0.
 */
static void test_domain_hash_single_subauth(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(18)},
	};

	KUNIT_EXPECT_EQ(test, ksmbd_domain_sid_hash(&sid), (u32)0);
}

/* ================================================================
 * Section 5: Domain match tests
 * ================================================================ */

/*
 * test_domain_match_local - SID from local domain should match.
 */
static void test_domain_match_local(struct kunit *test)
{
	struct smb_sid sid;

	build_domain_sid(&sid, 1000, 2000, 3000, 500);
	KUNIT_EXPECT_TRUE(test, ksmbd_sid_domain_match(&sid));
}

/*
 * test_domain_match_foreign - SID from foreign domain should not match.
 */
static void test_domain_match_foreign(struct kunit *test)
{
	struct smb_sid sid;

	build_domain_sid(&sid, 9999, 8888, 7777, 500);
	KUNIT_EXPECT_FALSE(test, ksmbd_sid_domain_match(&sid));
}

/*
 * test_domain_match_unix_users - S-1-22-1-* should always match (well-known).
 */
static void test_domain_match_unix_users(struct kunit *test)
{
	struct smb_sid sid;

	build_unix_user_sid(&sid, 1000);
	KUNIT_EXPECT_TRUE(test, ksmbd_sid_domain_match(&sid));
}

/*
 * test_domain_match_unix_groups - S-1-22-2-* should always match (well-known).
 */
static void test_domain_match_unix_groups(struct kunit *test)
{
	struct smb_sid sid;

	build_unix_group_sid(&sid, 500);
	KUNIT_EXPECT_TRUE(test, ksmbd_sid_domain_match(&sid));
}

/*
 * test_domain_match_nfs_user - S-1-5-88-1-* should always match (well-known).
 */
static void test_domain_match_nfs_user(struct kunit *test)
{
	struct smb_sid sid;

	build_nfs_user_sid(&sid, 65534);
	KUNIT_EXPECT_TRUE(test, ksmbd_sid_domain_match(&sid));
}

/*
 * test_domain_match_null - NULL SID should not match.
 */
static void test_domain_match_null(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, ksmbd_sid_domain_match(NULL));
}

/*
 * test_domain_match_zero_subauth - SID with 0 sub-authorities should not match.
 */
static void test_domain_match_zero_subauth(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 0,
		.authority = {0, 0, 0, 0, 0, 5},
	};

	KUNIT_EXPECT_FALSE(test, ksmbd_sid_domain_match(&sid));
}

/* ================================================================
 * Section 6: Consistency and idempotency tests
 * ================================================================ */

/*
 * test_mapping_idempotent - Calling the mapping twice with the same SID
 * should yield the same result.
 */
static void test_mapping_idempotent(struct kunit *test)
{
	struct smb_sid sid;
	uid_t uid1, uid2;
	int rc;

	build_domain_sid(&sid, 5555, 6666, 7777, 42);
	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid1);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = ksmbd_sid_to_id_domain_aware(&sid, &uid2);
	KUNIT_ASSERT_EQ(test, rc, 0);

	KUNIT_EXPECT_EQ(test, uid1, uid2);
}

/*
 * test_same_rid_same_domain_same_uid - Same domain + same RID = same UID.
 */
static void test_same_rid_same_domain_same_uid(struct kunit *test)
{
	struct smb_sid sid1, sid2;
	uid_t uid1, uid2;
	int rc;

	build_domain_sid(&sid1, 1000, 2000, 3000, 999);
	build_domain_sid(&sid2, 1000, 2000, 3000, 999);

	rc = ksmbd_sid_to_id_domain_aware(&sid1, &uid1);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = ksmbd_sid_to_id_domain_aware(&sid2, &uid2);
	KUNIT_ASSERT_EQ(test, rc, 0);

	KUNIT_EXPECT_EQ(test, uid1, uid2);
}

/* ================================================================
 * Test case array and suite definition
 * ================================================================ */

static struct kunit_case ksmbd_sid_mapping_test_cases[] = {
	/* Section 1: Cross-domain collision prevention */
	KUNIT_CASE(test_same_rid_different_domains),
	KUNIT_CASE(test_local_domain_uses_rid_directly),
	KUNIT_CASE(test_foreign_domain_gets_offset),
	KUNIT_CASE(test_two_foreign_domains_differ),
	/* Section 2: Well-known SID handling */
	KUNIT_CASE(test_wellknown_unix_user_sid),
	KUNIT_CASE(test_wellknown_unix_group_sid),
	KUNIT_CASE(test_wellknown_nfs_user_sid),
	KUNIT_CASE(test_wellknown_local_system),
	KUNIT_CASE(test_wellknown_builtin_admins),
	/* Section 3: Edge cases and error handling */
	KUNIT_CASE(test_sid_zero_subauth_rejected),
	KUNIT_CASE(test_sid_max_subauth_handled),
	KUNIT_CASE(test_sid_over_max_subauth_rejected),
	KUNIT_CASE(test_null_sid_rejected),
	KUNIT_CASE(test_null_output_rejected),
	KUNIT_CASE(test_everyone_sid_rejected),
	KUNIT_CASE(test_rid_overflow_protection),
	KUNIT_CASE(test_rid_zero_local_domain),
	/* Section 4: Domain prefix extraction and hash tests */
	KUNIT_CASE(test_extract_domain_prefix_basic),
	KUNIT_CASE(test_extract_domain_prefix_null_input),
	KUNIT_CASE(test_extract_domain_prefix_null_output),
	KUNIT_CASE(test_extract_domain_prefix_zero_subauth),
	KUNIT_CASE(test_domain_hash_deterministic),
	KUNIT_CASE(test_domain_hash_different_domains),
	KUNIT_CASE(test_domain_hash_null),
	KUNIT_CASE(test_domain_hash_single_subauth),
	/* Section 5: Domain match tests */
	KUNIT_CASE(test_domain_match_local),
	KUNIT_CASE(test_domain_match_foreign),
	KUNIT_CASE(test_domain_match_unix_users),
	KUNIT_CASE(test_domain_match_unix_groups),
	KUNIT_CASE(test_domain_match_nfs_user),
	KUNIT_CASE(test_domain_match_null),
	KUNIT_CASE(test_domain_match_zero_subauth),
	/* Section 6: Consistency and idempotency */
	KUNIT_CASE(test_mapping_idempotent),
	KUNIT_CASE(test_same_rid_same_domain_same_uid),
	{}
};

static struct kunit_suite ksmbd_sid_mapping_test_suite = {
	.name = "ksmbd_sid_mapping",
	.suite_init = sid_mapping_suite_init,
	.test_cases = ksmbd_sid_mapping_test_cases,
};

kunit_test_suite(ksmbd_sid_mapping_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for domain-aware SID-to-UID mapping");
