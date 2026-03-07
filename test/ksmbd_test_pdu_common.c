// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for PDU common helpers (smb2_pdu_common.c)
 *
 *   These tests call the real init_chained_smb2_rsp(),
 *   ksmbd_gcm_nonce_limit_reached(), and fill_transform_hdr()
 *   production functions via VISIBLE_IF_KUNIT exports.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/types.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "smbfsctl.h"
#include "ksmbd_work.h"
#include "mgmt/user_session.h"

/* Replicate reparse tag constants from smbfsctl.h */
#define TEST_IO_REPARSE_TAG_LX_SYMLINK	cpu_to_le32(0xA000001D)
#define TEST_IO_REPARSE_TAG_AF_UNIX	cpu_to_le32(0x80000023)
#define TEST_IO_REPARSE_TAG_LX_FIFO	cpu_to_le32(0x80000024)
#define TEST_IO_REPARSE_TAG_LX_CHR	cpu_to_le32(0x80000025)
#define TEST_IO_REPARSE_TAG_LX_BLK	cpu_to_le32(0x80000026)

/* Replicate file attribute constants from smb_common.h */
#define TEST_ATTR_READONLY	0x0001
#define TEST_ATTR_HIDDEN	0x0002
#define TEST_ATTR_SYSTEM	0x0004
#define TEST_ATTR_DIRECTORY	0x0010
#define TEST_ATTR_ARCHIVE	0x0020
#define TEST_ATTR_SPARSE	0x0200
#define TEST_ATTR_REPARSE	0x0400

/* --- GCM nonce limit tests using real ksmbd_gcm_nonce_limit_reached() --- */

/*
 * test_gcm_nonce_zero_not_exhausted - fresh session has room
 */
static void test_gcm_nonce_zero_not_exhausted(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));
	atomic64_set(&sess.gcm_nonce_counter, 0);

	KUNIT_EXPECT_FALSE(test, ksmbd_gcm_nonce_limit_reached(&sess));
}

/*
 * test_gcm_nonce_at_limit - counter at S64_MAX is exhausted
 */
static void test_gcm_nonce_at_limit(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));
	atomic64_set(&sess.gcm_nonce_counter, S64_MAX);

	KUNIT_EXPECT_TRUE(test, ksmbd_gcm_nonce_limit_reached(&sess));
}

/*
 * test_gcm_nonce_below_limit - counter just below limit
 */
static void test_gcm_nonce_below_limit(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));
	atomic64_set(&sess.gcm_nonce_counter, S64_MAX - 1);

	KUNIT_EXPECT_FALSE(test, ksmbd_gcm_nonce_limit_reached(&sess));
}

/* --- fill_transform_hdr() tests --- */

/*
 * test_fill_transform_hdr_ccm - CCM cipher sets proper header fields
 */
static void test_fill_transform_hdr_ccm(struct kunit *test)
{
	char *old_buf;
	void *tr_buf;
	struct smb2_transform_hdr *tr_hdr;
	struct smb2_hdr *hdr;
	int rc;

	old_buf = kzalloc(256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_buf);

	tr_buf = kzalloc(sizeof(struct smb2_transform_hdr) + 4, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, tr_buf);

	/* Set up a minimal SMB2 buffer: RFC1001 len + SMB2 header */
	hdr = (struct smb2_hdr *)(old_buf + 4);
	hdr->ProtocolId = SMB2_PROTO_NUMBER;
	hdr->SessionId = cpu_to_le64(0x1234);
	/* RFC1001 length = 64 (header size) */
	*((__be32 *)old_buf) = cpu_to_be32(64);

	rc = fill_transform_hdr(tr_buf, old_buf,
				SMB2_ENCRYPTION_AES128_CCM, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);

	tr_hdr = (struct smb2_transform_hdr *)(tr_buf + 4);
	KUNIT_EXPECT_EQ(test, tr_hdr->ProtocolId, SMB2_TRANSFORM_PROTO_NUM);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(tr_hdr->OriginalMessageSize), 64U);
	KUNIT_EXPECT_EQ(test, tr_hdr->SessionId, cpu_to_le64(0x1234));

	kfree(tr_buf);
	kfree(old_buf);
}

static struct kunit_case ksmbd_pdu_common_test_cases[] = {
	KUNIT_CASE(test_gcm_nonce_zero_not_exhausted),
	KUNIT_CASE(test_gcm_nonce_at_limit),
	KUNIT_CASE(test_gcm_nonce_below_limit),
	KUNIT_CASE(test_fill_transform_hdr_ccm),
	{}
};

static struct kunit_suite ksmbd_pdu_common_test_suite = {
	.name = "ksmbd_pdu_common",
	.test_cases = ksmbd_pdu_common_test_cases,
};

kunit_test_suite(ksmbd_pdu_common_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd PDU common helpers");
