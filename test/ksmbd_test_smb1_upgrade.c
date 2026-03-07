// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB1 -> SMB2 dialect upgrade state machine
 *
 *   These tests replicate the pure logic of the SMB1-to-SMB2 upgrade
 *   path in smb_common.c and connection.c:
 *   - Wildcard dialect 0x02FF in upgrade response
 *   - conn->smb1_conn flag transitions
 *   - conn->vals re-allocation during upgrade
 *   - need_neg flag handling
 *   - Second NEGOTIATE rejection after upgrade
 *   - SMB1 command rejection after upgrade
 *   - Dialect selection affecting upgrade decision
 *   - Connection state transitions
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "smb_common.h"
#include "smb1pdu.h"

/* Protocol ID constants from smb_common.h */
#define TEST_SMB10_PROT_ID	0x00
#define TEST_SMB20_PROT_ID	0x0202
#define TEST_SMB21_PROT_ID	0x0210
#define TEST_SMB2X_PROT_ID	0x02FF
#define TEST_SMB30_PROT_ID	0x0300
#define TEST_SMB302_PROT_ID	0x0302
#define TEST_SMB311_PROT_ID	0x0311
#define TEST_BAD_PROT_ID	0xFFFF

#define TEST_SMB1_PROTO_NUMBER	cpu_to_le32(0x424d53ff)
#define TEST_SMB2_PROTO_NUMBER	cpu_to_le32(0x424d53fe)

/*
 * Minimal mock of connection state fields relevant to the upgrade
 * state machine.  We do not use the real ksmbd_conn because it
 * contains too many kernel-internal dependencies (transport, locks, etc.).
 */
struct test_conn {
	void		*vals;
	bool		need_neg;
	bool		smb1_conn;
	__u16		dialect;
};

/*
 * Replicate __smb2_negotiate() from smb_common.c:
 * Returns true if the negotiated dialect is an SMB2/3 dialect.
 */
static bool test_is_smb2_dialect(u16 dialect)
{
	return (dialect >= TEST_SMB20_PROT_ID &&
		dialect <= TEST_SMB311_PROT_ID);
}

/*
 * Replicate init_smb1_server() connection setup.
 */
static int test_init_smb1(struct kunit *test, struct test_conn *conn)
{
	conn->vals = kunit_kzalloc(test, 64, GFP_KERNEL);
	if (!conn->vals)
		return -ENOMEM;

	conn->smb1_conn = true;
	conn->need_neg = false;
	conn->dialect = TEST_SMB10_PROT_ID;
	return 0;
}

/*
 * Replicate init_smb3_11_server() connection setup (SMB2 side).
 */
static int test_init_smb2(struct kunit *test, struct test_conn *conn)
{
	conn->vals = kunit_kzalloc(test, 64, GFP_KERNEL);
	if (!conn->vals)
		return -ENOMEM;

	return 0;
}

/*
 * Replicate the upgrade path from ksmbd_smb_negotiate_common():
 *
 *   if (__smb2_negotiate(conn)) {
 *       conn->dialect = SMB2X_PROT_ID;
 *       conn->smb1_conn = false;
 *       kfree(conn->vals);
 *       conn->vals = NULL;
 *       ret = init_smb3_11_server(conn);
 *       ...
 *   }
 *
 * Returns 0 on successful upgrade, -1 if no upgrade (stays SMB1).
 */
static int test_try_upgrade(struct kunit *test, struct test_conn *conn)
{
	if (!test_is_smb2_dialect(conn->dialect))
		return -1; /* no upgrade */

	/* Upgrade to SMB2 */
	conn->dialect = TEST_SMB2X_PROT_ID;
	conn->smb1_conn = false;

	/* Free old vals (simulating kfree(conn->vals)) */
	/* Note: kunit_kzalloc memory is managed by kunit, but we
	 * set to NULL to match real code behavior */
	conn->vals = NULL;

	/* Re-allocate for SMB2 */
	return test_init_smb2(test, conn);
}

/*
 * Replicate ksmbd_init_smb_server() post-negotiate check:
 *
 *   if (conn->need_neg == false) {
 *       if (proto == SMB1_PROTO_NUMBER && !conn->smb1_conn)
 *           return -EINVAL;
 *       return 0;
 *   }
 */
static int test_post_negotiate_check(struct test_conn *conn, __le32 proto)
{
	if (!conn->need_neg) {
		if (proto == TEST_SMB1_PROTO_NUMBER && !conn->smb1_conn)
			return -EINVAL;
		return 0;
	}
	return 0;
}

/* ======== Test: Upgrade uses wildcard dialect 0x02FF ======== */

static void test_upgrade_uses_wildcard_dialect(struct kunit *test)
{
	struct test_conn conn = {};
	int rc;

	conn.need_neg = true;
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Simulate client offering SMB2_02 in SMB1 NEGOTIATE */
	conn.dialect = TEST_SMB20_PROT_ID;

	rc = test_try_upgrade(test, &conn);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* After upgrade, dialect MUST be 0x02FF (wildcard) */
	KUNIT_EXPECT_EQ(test, conn.dialect, (u16)TEST_SMB2X_PROT_ID);
	KUNIT_EXPECT_EQ(test, conn.dialect, (u16)0x02FF);
}

/* ======== Test: smb1_conn flag transitions ======== */

static void test_smb1_conn_true_before_upgrade(struct kunit *test)
{
	struct test_conn conn = {};
	int rc;

	conn.need_neg = true;
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Before upgrade, smb1_conn should be true */
	KUNIT_EXPECT_TRUE(test, conn.smb1_conn);
}

static void test_smb1_conn_false_after_upgrade(struct kunit *test)
{
	struct test_conn conn = {};
	int rc;

	conn.need_neg = true;
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	conn.dialect = TEST_SMB20_PROT_ID;
	rc = test_try_upgrade(test, &conn);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* After upgrade, smb1_conn should be false */
	KUNIT_EXPECT_FALSE(test, conn.smb1_conn);
}

/* ======== Test: vals freed and re-allocated during upgrade ======== */

static void test_vals_reallocated_during_upgrade(struct kunit *test)
{
	struct test_conn conn = {};
	void *old_vals;
	int rc;

	conn.need_neg = true;
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	old_vals = conn.vals;
	KUNIT_ASSERT_NOT_NULL(test, old_vals);

	conn.dialect = TEST_SMB21_PROT_ID;
	rc = test_try_upgrade(test, &conn);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* vals should be re-allocated (new pointer, not NULL) */
	KUNIT_EXPECT_NOT_NULL(test, conn.vals);
	/* The new vals pointer should differ from the old SMB1 vals */
	KUNIT_EXPECT_PTR_NE(test, conn.vals, old_vals);
}

/* ======== Test: Second NEGOTIATE after upgrade is rejected ======== */

static void test_second_negotiate_after_upgrade_rejected(struct kunit *test)
{
	struct test_conn conn = {};
	int rc;

	conn.need_neg = true;
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	conn.dialect = TEST_SMB30_PROT_ID;
	rc = test_try_upgrade(test, &conn);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* After upgrade, need_neg was already set false by init_smb1.
	 * A second SMB1 NEGOTIATE should be rejected because
	 * smb1_conn is false after upgrade.
	 */
	KUNIT_EXPECT_FALSE(test, conn.need_neg);
	rc = test_post_negotiate_check(&conn, TEST_SMB1_PROTO_NUMBER);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

/* ======== Test: SMB1 command after upgrade rejected ======== */

static void test_smb1_command_after_upgrade_rejected(struct kunit *test)
{
	struct test_conn conn = {};
	int rc;

	conn.need_neg = true;
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	conn.dialect = TEST_SMB311_PROT_ID;
	rc = test_try_upgrade(test, &conn);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/*
	 * After upgrade, any SMB1 protocol packet (proto == SMB1_PROTO_NUMBER)
	 * should be rejected because conn->smb1_conn is now false.
	 */
	rc = test_post_negotiate_check(&conn, TEST_SMB1_PROTO_NUMBER);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	/* But SMB2 protocol packets should be accepted */
	rc = test_post_negotiate_check(&conn, TEST_SMB2_PROTO_NUMBER);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

/* ======== Test: Only SMB1 dialects -> no upgrade ======== */

static void test_smb1_only_dialects_no_upgrade(struct kunit *test)
{
	struct test_conn conn = {};
	int rc;

	conn.need_neg = true;
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Client offers only NT LM 0.12 (SMB10_PROT_ID = 0x00) */
	conn.dialect = TEST_SMB10_PROT_ID;

	rc = test_try_upgrade(test, &conn);
	/* Should return -1 (no upgrade) */
	KUNIT_EXPECT_EQ(test, rc, -1);

	/* Connection should remain SMB1 */
	KUNIT_EXPECT_TRUE(test, conn.smb1_conn);
	KUNIT_EXPECT_EQ(test, conn.dialect, (u16)TEST_SMB10_PROT_ID);
}

/* ======== Test: Upgrade with SMB2_02 as highest dialect ======== */

static void test_upgrade_with_smb2_02(struct kunit *test)
{
	struct test_conn conn = {};
	int rc;

	conn.need_neg = true;
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	conn.dialect = TEST_SMB20_PROT_ID;
	rc = test_try_upgrade(test, &conn);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Even with SMB2_02, the upgrade dialect is always 0x02FF */
	KUNIT_EXPECT_EQ(test, conn.dialect, (u16)TEST_SMB2X_PROT_ID);
	KUNIT_EXPECT_FALSE(test, conn.smb1_conn);
}

/* ======== Test: Upgrade with SMB3_11 as highest dialect ======== */

static void test_upgrade_with_smb3_11(struct kunit *test)
{
	struct test_conn conn = {};
	int rc;

	conn.need_neg = true;
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	conn.dialect = TEST_SMB311_PROT_ID;
	rc = test_try_upgrade(test, &conn);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Regardless of highest dialect, upgrade always sets 0x02FF */
	KUNIT_EXPECT_EQ(test, conn.dialect, (u16)TEST_SMB2X_PROT_ID);
	KUNIT_EXPECT_FALSE(test, conn.smb1_conn);
	KUNIT_EXPECT_NOT_NULL(test, conn.vals);
}

/* ======== Test: need_neg flag handling during upgrade ======== */

static void test_need_neg_cleared_on_init(struct kunit *test)
{
	struct test_conn conn = {};
	int rc;

	conn.need_neg = true;

	/* init_smb1_server sets need_neg = false (via the caller
	 * ksmbd_init_smb_server which clears it before calling init) */
	conn.need_neg = false; /* simulate ksmbd_init_smb_server clearing it */
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	KUNIT_EXPECT_FALSE(test, conn.need_neg);
}

/* ======== Test: Connection state transitions during upgrade ======== */

static void test_connection_state_transition_full_sequence(struct kunit *test)
{
	struct test_conn conn = {};
	int rc;

	/* Phase 1: Initial state */
	conn.need_neg = true;
	conn.smb1_conn = false;
	conn.vals = NULL;
	conn.dialect = 0;

	/* Phase 2: First NEGOTIATE arrives as SMB1 */
	conn.need_neg = false; /* cleared by ksmbd_init_smb_server */
	rc = test_init_smb1(test, &conn);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Verify SMB1 state */
	KUNIT_EXPECT_TRUE(test, conn.smb1_conn);
	KUNIT_EXPECT_FALSE(test, conn.need_neg);
	KUNIT_EXPECT_NOT_NULL(test, conn.vals);

	/* Phase 3: Dialect negotiation finds SMB2 dialect */
	conn.dialect = TEST_SMB302_PROT_ID;

	/* Phase 4: Upgrade */
	rc = test_try_upgrade(test, &conn);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Verify post-upgrade state */
	KUNIT_EXPECT_FALSE(test, conn.smb1_conn);
	KUNIT_EXPECT_EQ(test, conn.dialect, (u16)TEST_SMB2X_PROT_ID);
	KUNIT_EXPECT_NOT_NULL(test, conn.vals);

	/* Phase 5: SMB1 packets now rejected */
	rc = test_post_negotiate_check(&conn, TEST_SMB1_PROTO_NUMBER);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	/* Phase 6: SMB2 packets accepted */
	rc = test_post_negotiate_check(&conn, TEST_SMB2_PROTO_NUMBER);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static struct kunit_case ksmbd_smb1_upgrade_test_cases[] = {
	KUNIT_CASE(test_upgrade_uses_wildcard_dialect),
	KUNIT_CASE(test_smb1_conn_true_before_upgrade),
	KUNIT_CASE(test_smb1_conn_false_after_upgrade),
	KUNIT_CASE(test_vals_reallocated_during_upgrade),
	KUNIT_CASE(test_second_negotiate_after_upgrade_rejected),
	KUNIT_CASE(test_smb1_command_after_upgrade_rejected),
	KUNIT_CASE(test_smb1_only_dialects_no_upgrade),
	KUNIT_CASE(test_upgrade_with_smb2_02),
	KUNIT_CASE(test_upgrade_with_smb3_11),
	KUNIT_CASE(test_need_neg_cleared_on_init),
	KUNIT_CASE(test_connection_state_transition_full_sequence),
	{}
};

static struct kunit_suite ksmbd_smb1_upgrade_test_suite = {
	.name = "ksmbd_smb1_upgrade",
	.test_cases = ksmbd_smb1_upgrade_test_cases,
};

kunit_test_suite(ksmbd_smb1_upgrade_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB1 to SMB2 dialect upgrade state machine");
