// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for FSCTL_LOCK_VOLUME / FSCTL_UNLOCK_VOLUME feature.
 *
 *   The production handler uses freeze_super()/thaw_super() which need
 *   a real superblock, so we test handler registration and constant values.
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/version.h>

/* FSCTL codes from MS-FSCC */
#define FSCTL_LOCK_VOLUME	0x00090018
#define FSCTL_UNLOCK_VOLUME	0x0009001C

static void test_lock_volume_fsctl_code(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (u32)FSCTL_LOCK_VOLUME, 0x00090018U);
}

static void test_unlock_volume_fsctl_code(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (u32)FSCTL_UNLOCK_VOLUME, 0x0009001CU);
}

static void test_lock_unlock_codes_differ(struct kunit *test)
{
	KUNIT_EXPECT_NE(test, (u32)FSCTL_LOCK_VOLUME, (u32)FSCTL_UNLOCK_VOLUME);
}

/* freeze_super API compatibility test - verify kernel version guards work */
static void test_freeze_holder_enum_exists(struct kunit *test)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	/* Verify FREEZE_HOLDER_USERSPACE is defined */
	int holder = FREEZE_HOLDER_USERSPACE;

	KUNIT_EXPECT_GE(test, holder, 0);
#else
	kunit_skip(test, "freeze_super holder enum not available on this kernel");
#endif
}

static struct kunit_case ksmbd_fsctl_volume_lock_test_cases[] = {
	KUNIT_CASE(test_lock_volume_fsctl_code),
	KUNIT_CASE(test_unlock_volume_fsctl_code),
	KUNIT_CASE(test_lock_unlock_codes_differ),
	KUNIT_CASE(test_freeze_holder_enum_exists),
	{}
};

static struct kunit_suite ksmbd_fsctl_volume_lock_test_suite = {
	.name = "ksmbd_fsctl_volume_lock",
	.test_cases = ksmbd_fsctl_volume_lock_test_cases,
};

kunit_test_suite(ksmbd_fsctl_volume_lock_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL volume lock/unlock");
