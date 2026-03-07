// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for VFS operations (vfs.c)
 *
 *   Many VFS functions require full kernel filesystem state that cannot
 *   be mocked in KUnit.  We test the pure-logic helpers and structural
 *   validation functions that can operate on stack-allocated data.
 *   For functions needing real filesystem context, we replicate
 *   the validation logic inline and test boundary conditions.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>

#include "vfs.h"
#include "vfs_cache.h"
#include "smb2pdu.h"

/* ═══════════════════════════════════════════════════════════════════
 *  Stream Name Tests (ksmbd_vfs_xattr_stream_name)
 * ═══════════════════════════════════════════════════════════════════ */

static void test_vfs_xattr_stream_name_formats_correctly(struct kunit *test)
{
	char *xattr_name = NULL;
	size_t xattr_name_size = 0;
	int ret;

	ret = ksmbd_vfs_xattr_stream_name("Stream1", &xattr_name,
					   &xattr_name_size, DATA_STREAM);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_NOT_NULL(test, xattr_name);
	KUNIT_EXPECT_GT(test, xattr_name_size, (size_t)0);
	/* The xattr name should contain the stream name */
	KUNIT_EXPECT_NOT_NULL(test, strstr(xattr_name, "Stream1"));

	kfree(xattr_name);
}

static void test_vfs_xattr_stream_name_special_chars(struct kunit *test)
{
	char *xattr_name = NULL;
	size_t xattr_name_size = 0;
	int ret;

	ret = ksmbd_vfs_xattr_stream_name("my stream.txt", &xattr_name,
					   &xattr_name_size, DATA_STREAM);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_NOT_NULL(test, xattr_name);

	kfree(xattr_name);
}

/* ═══════════════════════════════════════════════════════════════════
 *  fadvise Tests (ksmbd_vfs_set_fadvise)
 *
 *  These test the replicated logic since the actual function
 *  requires a real struct file.
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Replicate the fadvise logic from vfs.c for testing without a real file.
 * The actual function calls fadvise() on the kernel file, but we test
 * the option-to-advice mapping.
 */
static int test_fadvise_map(__le32 option)
{
	if (option & FILE_SEQUENTIAL_ONLY_LE)
		return POSIX_FADV_SEQUENTIAL;
	else if (option & FILE_RANDOM_ACCESS_LE)
		return POSIX_FADV_RANDOM;
	return POSIX_FADV_NORMAL;
}

static void test_vfs_set_fadvise_sequential(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_fadvise_map(FILE_SEQUENTIAL_ONLY_LE),
			POSIX_FADV_SEQUENTIAL);
}

static void test_vfs_set_fadvise_random(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_fadvise_map(FILE_RANDOM_ACCESS_LE),
			POSIX_FADV_RANDOM);
}

static void test_vfs_set_fadvise_none(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_fadvise_map(cpu_to_le32(0)),
			POSIX_FADV_NORMAL);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Path Traversal Security Tests (replicated logic)
 *
 *  These test the safety checks that prevent directory traversal
 *  attacks through SMB path components.
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Replicate the path safety check from ksmbd.
 * A path component of ".." or starting with "/" is rejected.
 */
static bool test_path_component_safe(const char *path)
{
	const char *p = path;

	if (!path || !*path)
		return true;

	/* Absolute paths are rejected */
	if (*path == '/')
		return false;

	while (*p) {
		const char *seg = p;
		size_t seglen;

		while (*p && *p != '/' && *p != '\\')
			p++;
		seglen = p - seg;

		if (seglen == 2 && seg[0] == '.' && seg[1] == '.')
			return false;

		if (*p)
			p++;
	}

	return true;
}

static void test_path_traversal_dotdot_in_middle(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_path_component_safe("a/../b"));
}

static void test_path_traversal_dotdot_at_start(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_path_component_safe("../escape"));
}

static void test_path_traversal_backslash_dotdot(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_path_component_safe("a\\..\\b"));
}

static void test_path_traversal_absolute_rejected(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_path_component_safe("/etc/passwd"));
}

static void test_path_traversal_normal_path_ok(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_path_component_safe("dir/subdir/file.txt"));
}

static void test_path_traversal_double_slash_ok(struct kunit *test)
{
	/* Double slash is not a traversal, just redundant */
	KUNIT_EXPECT_TRUE(test, test_path_component_safe("dir//file.txt"));
}

static void test_path_traversal_single_dot_ok(struct kunit *test)
{
	/* Single dot is current directory, not a traversal */
	KUNIT_EXPECT_TRUE(test, test_path_component_safe("dir/./file.txt"));
}

static void test_path_traversal_null_byte(struct kunit *test)
{
	/*
	 * Path with embedded NUL - the C string stops at the NUL,
	 * so "dir\0../escape" is just "dir"
	 */
	char path[] = "dir\0../escape";

	KUNIT_EXPECT_TRUE(test, test_path_component_safe(path));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Allocation Size Helper Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_ksmbd_alloc_size_cached(struct kunit *test)
{
	struct ksmbd_file fp = {};
	struct ksmbd_inode ci = {};
	struct kstat stat = {};

	fp.f_ci = &ci;
	ci.m_cached_alloc = 8192;
	stat.blocks = 16; /* 8KB */

	KUNIT_EXPECT_EQ(test, ksmbd_alloc_size(&fp, &stat), (u64)8192);
}

static void test_ksmbd_alloc_size_from_stat(struct kunit *test)
{
	struct ksmbd_file fp = {};
	struct ksmbd_inode ci = {};
	struct kstat stat = {};

	fp.f_ci = &ci;
	ci.m_cached_alloc = -1; /* Not explicitly set */
	stat.blocks = 8; /* 4KB */

	KUNIT_EXPECT_EQ(test, ksmbd_alloc_size(&fp, &stat),
			(u64)(8ULL << 9));
}

static void test_ksmbd_alloc_size_null_fp(struct kunit *test)
{
	struct kstat stat = {};

	stat.blocks = 16;
	KUNIT_EXPECT_EQ(test, ksmbd_alloc_size(NULL, &stat),
			(u64)(16ULL << 9));
}

/* ═══════════════════════════════════════════════════════════════════
 *  has_file_id() Helper Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_has_file_id_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, has_file_id(0));
	KUNIT_EXPECT_TRUE(test, has_file_id(1));
	KUNIT_EXPECT_TRUE(test, has_file_id(KSMBD_NO_FID - 1));
}

static void test_has_file_id_invalid(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, has_file_id(KSMBD_NO_FID));
	KUNIT_EXPECT_FALSE(test, has_file_id((u64)KSMBD_NO_FID + 1));
}

/* ═══════════════════════════════════════════════════════════════════
 *  ksmbd_stream_fd() Helper Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_ksmbd_stream_fd_with_stream(struct kunit *test)
{
	struct ksmbd_file fp = {};

	fp.stream.name = "test_stream";
	KUNIT_EXPECT_TRUE(test, ksmbd_stream_fd(&fp));
}

static void test_ksmbd_stream_fd_without_stream(struct kunit *test)
{
	struct ksmbd_file fp = {};

	fp.stream.name = NULL;
	KUNIT_EXPECT_FALSE(test, ksmbd_stream_fd(&fp));
}

/* ═══════════════════════════════════════════════════════════════════
 *  CreateOptions Flag Constant Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_create_options_directory_flag(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, FILE_DIRECTORY_FILE_LE, cpu_to_le32(0x00000001));
}

static void test_create_options_non_directory_flag(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, FILE_NON_DIRECTORY_FILE_LE,
			cpu_to_le32(0x00000040));
}

static void test_create_options_delete_on_close_flag(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, FILE_DELETE_ON_CLOSE_LE,
			cpu_to_le32(0x00001000));
}

static void test_create_options_mask(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, CREATE_OPTIONS_MASK,
			cpu_to_le32(0x00FFFFFF));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Lock Range Validation Tests (replicated logic)
 *
 *  check_lock_range() validates that lock parameters won't overflow.
 *  OFFSET_MAX is the kernel limit for file offsets.
 * ═══════════════════════════════════════════════════════════════════ */

static bool test_lock_range_valid(loff_t start, loff_t length)
{
	loff_t end;

	if (start < 0)
		return false;
	if (length == 0)
		return true;
	if (length < 0)
		return false;

	/* Check overflow */
	end = start + length - 1;
	if (end < start)
		return false;

	return true;
}

static void test_check_lock_range_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_lock_range_valid(0, 100));
	KUNIT_EXPECT_TRUE(test, test_lock_range_valid(1000, 500));
}

static void test_check_lock_range_zero_length(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_lock_range_valid(0, 0));
	KUNIT_EXPECT_TRUE(test, test_lock_range_valid(100, 0));
}

static void test_check_lock_range_negative_start(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_lock_range_valid(-1, 100));
}

static void test_check_lock_range_overflow(struct kunit *test)
{
	/* Large start + length overflows */
	KUNIT_EXPECT_FALSE(test, test_lock_range_valid(LLONG_MAX, 2));
}

static void test_check_lock_range_max_valid(struct kunit *test)
{
	/* Exactly at max: start=0, length=LLONG_MAX is valid */
	KUNIT_EXPECT_TRUE(test, test_lock_range_valid(0, LLONG_MAX));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Path Traversal Additional Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_path_traversal_very_long_path(struct kunit *test)
{
	char long_path[300];
	int i;

	/* Build a long but safe path */
	for (i = 0; i < 290; i++)
		long_path[i] = (i % 10 == 9) ? '/' : 'a';
	long_path[290] = '\0';

	KUNIT_EXPECT_TRUE(test, test_path_component_safe(long_path));
}

static void test_path_traversal_encoded_dotdot_safe(struct kunit *test)
{
	/*
	 * "%2e%2e" is NOT ".." in the raw string sense.
	 * The path checker sees literal characters, not URL encoding.
	 */
	KUNIT_EXPECT_TRUE(test, test_path_component_safe("dir/%2e%2e/file"));
}

static void test_path_traversal_dotdot_at_end(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_path_component_safe("dir/.."));
}

static void test_path_traversal_empty_path_safe(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_path_component_safe(""));
}

static void test_path_traversal_null_path_safe(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_path_component_safe(NULL));
}

/* ═══════════════════════════════════════════════════════════════════
 *  fadvise Additional Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_vfs_set_fadvise_sequential_and_random(struct kunit *test)
{
	/*
	 * If both flags are set, sequential takes priority
	 * (checked first in the if/else chain).
	 */
	__le32 both = FILE_SEQUENTIAL_ONLY_LE | FILE_RANDOM_ACCESS_LE;

	KUNIT_EXPECT_EQ(test, test_fadvise_map(both), POSIX_FADV_SEQUENTIAL);
}

/* ═══════════════════════════════════════════════════════════════════
 *  CreateOptions Additional Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_create_options_write_through(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, FILE_WRITE_THROUGH_LE,
			cpu_to_le32(0x00000002));
}

static void test_create_options_sequential_only(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, FILE_SEQUENTIAL_ONLY_LE,
			cpu_to_le32(0x00000004));
}

static void test_create_options_synchronous_io(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, FILE_SYNCHRONOUS_IO_NONALERT_LE,
			cpu_to_le32(0x00000020));
}

static void test_create_options_open_reparse(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, FILE_OPEN_REPARSE_POINT_LE,
			cpu_to_le32(0x00200000));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Test Case Array and Suite Registration
 * ═══════════════════════════════════════════════════════════════════ */

static struct kunit_case ksmbd_vfs_test_cases[] = {
	/* Stream name */
	KUNIT_CASE(test_vfs_xattr_stream_name_formats_correctly),
	KUNIT_CASE(test_vfs_xattr_stream_name_special_chars),
	/* fadvise mapping */
	KUNIT_CASE(test_vfs_set_fadvise_sequential),
	KUNIT_CASE(test_vfs_set_fadvise_random),
	KUNIT_CASE(test_vfs_set_fadvise_none),
	/* Path traversal */
	KUNIT_CASE(test_path_traversal_dotdot_in_middle),
	KUNIT_CASE(test_path_traversal_dotdot_at_start),
	KUNIT_CASE(test_path_traversal_backslash_dotdot),
	KUNIT_CASE(test_path_traversal_absolute_rejected),
	KUNIT_CASE(test_path_traversal_normal_path_ok),
	KUNIT_CASE(test_path_traversal_double_slash_ok),
	KUNIT_CASE(test_path_traversal_single_dot_ok),
	KUNIT_CASE(test_path_traversal_null_byte),
	/* Allocation size */
	KUNIT_CASE(test_ksmbd_alloc_size_cached),
	KUNIT_CASE(test_ksmbd_alloc_size_from_stat),
	KUNIT_CASE(test_ksmbd_alloc_size_null_fp),
	/* has_file_id */
	KUNIT_CASE(test_has_file_id_valid),
	KUNIT_CASE(test_has_file_id_invalid),
	/* ksmbd_stream_fd */
	KUNIT_CASE(test_ksmbd_stream_fd_with_stream),
	KUNIT_CASE(test_ksmbd_stream_fd_without_stream),
	/* Lock range */
	KUNIT_CASE(test_check_lock_range_valid),
	KUNIT_CASE(test_check_lock_range_zero_length),
	KUNIT_CASE(test_check_lock_range_negative_start),
	KUNIT_CASE(test_check_lock_range_overflow),
	KUNIT_CASE(test_check_lock_range_max_valid),
	/* Path traversal additional */
	KUNIT_CASE(test_path_traversal_very_long_path),
	KUNIT_CASE(test_path_traversal_encoded_dotdot_safe),
	KUNIT_CASE(test_path_traversal_dotdot_at_end),
	KUNIT_CASE(test_path_traversal_empty_path_safe),
	KUNIT_CASE(test_path_traversal_null_path_safe),
	/* fadvise additional */
	KUNIT_CASE(test_vfs_set_fadvise_sequential_and_random),
	/* CreateOptions flags */
	KUNIT_CASE(test_create_options_directory_flag),
	KUNIT_CASE(test_create_options_non_directory_flag),
	KUNIT_CASE(test_create_options_delete_on_close_flag),
	KUNIT_CASE(test_create_options_mask),
	KUNIT_CASE(test_create_options_write_through),
	KUNIT_CASE(test_create_options_sequential_only),
	KUNIT_CASE(test_create_options_synchronous_io),
	KUNIT_CASE(test_create_options_open_reparse),
	{}
};

static struct kunit_suite ksmbd_vfs_test_suite = {
	.name = "ksmbd_vfs",
	.test_cases = ksmbd_vfs_test_cases,
};

kunit_test_suite(ksmbd_vfs_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd VFS operations");
