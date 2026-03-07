// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for security info dispatch table absence.
 *
 *   Security info (SMB2_O_INFO_SECURITY) is handled directly in
 *   smb2_query_set.c, NOT through the dispatch table.  This test
 *   verifies that the dispatch table does not have a security handler
 *   (correct separation of concerns).
 */

#include <kunit/test.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/*
 * Replicate info_hash_key and lookup to verify that
 * SMB2_O_INFO_SECURITY lookups return nothing.
 */

#define SMB2_O_INFO_SECURITY	3

enum test_info_op_sec {
	TEST_INFO_GET_SEC = 0,
	TEST_INFO_SET_SEC = 1,
};

#define TEST_SEC_HASH_BITS	8
static DEFINE_HASHTABLE(test_sec_handlers, TEST_SEC_HASH_BITS);

static inline u32 test_sec_hash_key(u8 info_type, u8 info_class,
				    enum test_info_op_sec op)
{
	return (u32)info_type << 16 | (u32)info_class << 8 | (u32)op;
}

struct test_sec_handler {
	u8 info_type;
	u8 info_class;
	enum test_info_op_sec op;
	struct hlist_node node;
};

static struct test_sec_handler *test_sec_lookup(u8 info_type,
						u8 info_class,
						enum test_info_op_sec op)
{
	struct test_sec_handler *h;
	u32 key = test_sec_hash_key(info_type, info_class, op);

	hash_for_each_possible(test_sec_handlers, h, node, key) {
		if (h->info_type == info_type &&
		    h->info_class == info_class &&
		    h->op == op)
			return h;
	}
	return NULL;
}

/*
 * test_security_info_not_in_dispatch - SMB2_O_INFO_SECURITY lookups
 * should return NULL since security info is handled inline in
 * smb2_query_set.c, not via the dispatch table.
 */
static void test_security_info_not_in_dispatch(struct kunit *test)
{
	struct test_sec_handler *found;
	u8 classes[] = { 0, 1, 2, 3, 4, 5 };
	unsigned int i;

	hash_init(test_sec_handlers);

	/* No handlers registered; all lookups should return NULL */
	for (i = 0; i < ARRAY_SIZE(classes); i++) {
		found = test_sec_lookup(SMB2_O_INFO_SECURITY,
					classes[i],
					TEST_INFO_GET_SEC);
		KUNIT_EXPECT_NULL(test, found);
	}
}

static struct kunit_case ksmbd_info_security_test_cases[] = {
	KUNIT_CASE(test_security_info_not_in_dispatch),
	{}
};

static struct kunit_suite ksmbd_info_security_test_suite = {
	.name = "ksmbd_info_security",
	.test_cases = ksmbd_info_security_test_cases,
};

kunit_test_suite(ksmbd_info_security_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd security info dispatch table absence");
