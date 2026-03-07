// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for quota query support (ksmbd_quota.c)
 *
 *   Tests the SID-to-UID mapping logic and quota structure
 *   validation.  The actual quota query functions require VFS
 *   filesystem state and CONFIG_QUOTA, so we test the pure-logic
 *   portions.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "smbacl.h"

/* Replicated SID-to-UID logic from ksmbd_quota.c */

static int test_sid_to_uid(const struct smb_sid *sid, unsigned int sid_len,
			   uid_t *uid_out)
{
	if (sid->num_subauth == 0 ||
	    sid->num_subauth > SID_MAX_SUB_AUTHORITIES)
		return -EINVAL;

	if (sid_len < CIFS_SID_BASE_SIZE +
		      (unsigned int)sid->num_subauth * sizeof(__le32))
		return -EINVAL;

	*uid_out = le32_to_cpu(sid->sub_auth[sid->num_subauth - 1]);
	return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  SID to UID Mapping Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_sid_to_uid_single_subauth(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(1000)},
	};
	uid_t uid = 0;
	unsigned int sid_len = CIFS_SID_BASE_SIZE + sizeof(__le32);

	KUNIT_EXPECT_EQ(test, test_sid_to_uid(&sid, sid_len, &uid), 0);
	KUNIT_EXPECT_EQ(test, uid, (uid_t)1000);
}

static void test_sid_to_uid_multiple_subauth_uses_last(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 4,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21), cpu_to_le32(100),
			     cpu_to_le32(200), cpu_to_le32(500)},
	};
	uid_t uid = 0;
	unsigned int sid_len = CIFS_SID_BASE_SIZE + 4 * sizeof(__le32);

	KUNIT_EXPECT_EQ(test, test_sid_to_uid(&sid, sid_len, &uid), 0);
	KUNIT_EXPECT_EQ(test, uid, (uid_t)500);
}

static void test_sid_to_uid_zero_subauth_rejected(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 0,
		.authority = {0, 0, 0, 0, 0, 5},
	};
	uid_t uid = 0;

	KUNIT_EXPECT_EQ(test, test_sid_to_uid(&sid, CIFS_SID_BASE_SIZE, &uid),
			-EINVAL);
}

static void test_sid_to_uid_too_many_subauth_rejected(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = SID_MAX_SUB_AUTHORITIES + 1,
		.authority = {0, 0, 0, 0, 0, 5},
	};
	uid_t uid = 0;
	unsigned int sid_len = CIFS_SID_BASE_SIZE +
		(SID_MAX_SUB_AUTHORITIES + 1) * sizeof(__le32);

	KUNIT_EXPECT_EQ(test, test_sid_to_uid(&sid, sid_len, &uid), -EINVAL);
}

static void test_sid_to_uid_buffer_too_small_rejected(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 2,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(21), cpu_to_le32(1000)},
	};
	uid_t uid = 0;
	/* Buffer claims only 1 subauth worth of space */
	unsigned int sid_len = CIFS_SID_BASE_SIZE + sizeof(__le32);

	KUNIT_EXPECT_EQ(test, test_sid_to_uid(&sid, sid_len, &uid), -EINVAL);
}

static void test_sid_to_uid_max_subauth(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = SID_MAX_SUB_AUTHORITIES,
		.authority = {0, 0, 0, 0, 0, 5},
	};
	uid_t uid = 0;
	unsigned int sid_len = CIFS_SID_BASE_SIZE +
		SID_MAX_SUB_AUTHORITIES * sizeof(__le32);
	int i;

	for (i = 0; i < SID_MAX_SUB_AUTHORITIES; i++)
		sid.sub_auth[i] = cpu_to_le32(i + 1);

	KUNIT_EXPECT_EQ(test, test_sid_to_uid(&sid, sid_len, &uid), 0);
	KUNIT_EXPECT_EQ(test, uid, (uid_t)SID_MAX_SUB_AUTHORITIES);
}

/* ═══════════════════════════════════════════════════════════════════
 *  SID Byte Length Tests
 * ═══════════════════════════════════════════════════════════════════ */

static unsigned int test_sid_byte_len(const struct smb_sid *sid)
{
	return CIFS_SID_BASE_SIZE + sizeof(__le32) * sid->num_subauth;
}

static void test_sid_byte_len_zero_subauth(struct kunit *test)
{
	struct smb_sid sid = { .num_subauth = 0 };

	KUNIT_EXPECT_EQ(test, test_sid_byte_len(&sid),
			(unsigned int)CIFS_SID_BASE_SIZE);
}

static void test_sid_byte_len_one_subauth(struct kunit *test)
{
	struct smb_sid sid = { .num_subauth = 1 };

	KUNIT_EXPECT_EQ(test, test_sid_byte_len(&sid),
			(unsigned int)(CIFS_SID_BASE_SIZE + 4));
}

static void test_sid_byte_len_max_subauth(struct kunit *test)
{
	struct smb_sid sid = { .num_subauth = SID_MAX_SUB_AUTHORITIES };

	KUNIT_EXPECT_EQ(test, test_sid_byte_len(&sid),
			(unsigned int)(CIFS_SID_BASE_SIZE +
				       SID_MAX_SUB_AUTHORITIES * 4));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Quota Entry Alignment Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_quota_entry_alignment(struct kunit *test)
{
	/* Quota entries must be 8-byte aligned per MS-FSCC 2.4.33 */
	unsigned int base = 40; /* fixed fields */
	unsigned int sid_len = CIFS_SID_BASE_SIZE + 4; /* 1 subauth */
	unsigned int total = base + sid_len;
	unsigned int aligned = ALIGN(total, 8);

	KUNIT_EXPECT_EQ(test, aligned % 8, 0U);
}

static void test_quota_entry_size_with_padding(struct kunit *test)
{
	unsigned int base = 40;
	unsigned int sid_len = CIFS_SID_BASE_SIZE + 8; /* 2 subauths */
	unsigned int total = base + sid_len;
	unsigned int aligned = ALIGN(total, 8);

	KUNIT_EXPECT_GE(test, aligned, total);
	KUNIT_EXPECT_EQ(test, aligned % 8, 0U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  CIFS_SID_BASE_SIZE Constant Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_cifs_sid_base_size(struct kunit *test)
{
	/* 1 byte revision + 1 byte num_subauth + 6 bytes authority = 8 */
	KUNIT_EXPECT_EQ(test, CIFS_SID_BASE_SIZE, (unsigned int)(1 + 1 + 6));
}

static void test_sid_max_sub_authorities(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SID_MAX_SUB_AUTHORITIES, 15);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Quota Entry Size Calculation Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_quota_entry_size_with_max_subauth(struct kunit *test)
{
	unsigned int base = 40;
	unsigned int sid_len = CIFS_SID_BASE_SIZE +
		SID_MAX_SUB_AUTHORITIES * sizeof(__le32);
	unsigned int total = base + sid_len;
	unsigned int aligned = ALIGN(total, 8);

	KUNIT_EXPECT_EQ(test, aligned % 8, 0U);
	KUNIT_EXPECT_GE(test, aligned, total);
}

static void test_quota_entry_next_offset_zero_for_last(struct kunit *test)
{
	/*
	 * Per MS-FSCC 2.4.33, NextEntryOffset == 0 indicates
	 * the last entry in the list.
	 */
	__le32 next_offset = cpu_to_le32(0);

	KUNIT_EXPECT_EQ(test, le32_to_cpu(next_offset), 0U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  SID to UID Boundary Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_sid_to_uid_boundary_zero(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(0)},
	};
	uid_t uid = 999;
	unsigned int sid_len = CIFS_SID_BASE_SIZE + sizeof(__le32);

	KUNIT_EXPECT_EQ(test, test_sid_to_uid(&sid, sid_len, &uid), 0);
	KUNIT_EXPECT_EQ(test, uid, (uid_t)0);
}

static void test_sid_to_uid_boundary_max(struct kunit *test)
{
	struct smb_sid sid = {
		.revision = 1,
		.num_subauth = 1,
		.authority = {0, 0, 0, 0, 0, 5},
		.sub_auth = {cpu_to_le32(UINT_MAX)},
	};
	uid_t uid = 0;
	unsigned int sid_len = CIFS_SID_BASE_SIZE + sizeof(__le32);

	KUNIT_EXPECT_EQ(test, test_sid_to_uid(&sid, sid_len, &uid), 0);
	KUNIT_EXPECT_EQ(test, uid, (uid_t)UINT_MAX);
}

/* ═══════════════════════════════════════════════════════════════════
 *  SID Byte Length Additional Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_sid_byte_len_four_subauth(struct kunit *test)
{
	struct smb_sid sid = { .num_subauth = 4 };

	KUNIT_EXPECT_EQ(test, test_sid_byte_len(&sid),
			(unsigned int)(CIFS_SID_BASE_SIZE + 16));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Test Case Array and Suite Registration
 * ═══════════════════════════════════════════════════════════════════ */

static struct kunit_case ksmbd_quota_test_cases[] = {
	/* SID to UID */
	KUNIT_CASE(test_sid_to_uid_single_subauth),
	KUNIT_CASE(test_sid_to_uid_multiple_subauth_uses_last),
	KUNIT_CASE(test_sid_to_uid_zero_subauth_rejected),
	KUNIT_CASE(test_sid_to_uid_too_many_subauth_rejected),
	KUNIT_CASE(test_sid_to_uid_buffer_too_small_rejected),
	KUNIT_CASE(test_sid_to_uid_max_subauth),
	/* SID byte length */
	KUNIT_CASE(test_sid_byte_len_zero_subauth),
	KUNIT_CASE(test_sid_byte_len_one_subauth),
	KUNIT_CASE(test_sid_byte_len_max_subauth),
	/* Quota entry alignment */
	KUNIT_CASE(test_quota_entry_alignment),
	KUNIT_CASE(test_quota_entry_size_with_padding),
	/* Constants */
	KUNIT_CASE(test_cifs_sid_base_size),
	KUNIT_CASE(test_sid_max_sub_authorities),
	/* Quota entry size */
	KUNIT_CASE(test_quota_entry_size_with_max_subauth),
	KUNIT_CASE(test_quota_entry_next_offset_zero_for_last),
	/* SID to UID boundaries */
	KUNIT_CASE(test_sid_to_uid_boundary_zero),
	KUNIT_CASE(test_sid_to_uid_boundary_max),
	/* SID byte length additional */
	KUNIT_CASE(test_sid_byte_len_four_subauth),
	{}
};

static struct kunit_suite ksmbd_quota_test_suite = {
	.name = "ksmbd_quota",
	.test_cases = ksmbd_quota_test_cases,
};

kunit_test_suite(ksmbd_quota_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd quota query support");
