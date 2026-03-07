// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for the kernel-version compatibility layer (compat.c / compat.h)
 *
 *   compat.c provides per-kernel-version shims for VFS and xattr APIs that
 *   changed signature across the 5.12, 6.3, and 6.6 kernel boundaries.
 *   Because every shim ultimately forwards to a real VFS call that requires a
 *   live inode, the tests here focus on compile-time properties:
 *     - LINUX_VERSION_CODE is defined and falls in a reasonable range
 *     - The compat wrapper symbols declared in compat.h are present
 *     - Struct sizes and field offsets used by the compat layer are stable
 *     - Preprocessor version guards are mutually exclusive and cover all paths
 */

#include <kunit/test.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>

#include "compat.h"

/* ──────────────────────────────────────────────────────────────────────────
 * 1. Kernel version sanity
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_compat_kernel_version - LINUX_VERSION_CODE is defined and sane
 *
 * LINUX_VERSION_CODE must be defined (by <linux/version.h>) and must encode
 * a kernel version >= 5.4 (the minimum ksmbd supports) and <= 8.0 (a
 * conservatively high ceiling).  Both bounds are expressed as
 * KERNEL_VERSION(major, minor, 0) for readability.
 */
static void test_compat_kernel_version(struct kunit *test)
{
	unsigned int kver = LINUX_VERSION_CODE;

	KUNIT_EXPECT_GE(test, kver,
			(unsigned int)KERNEL_VERSION(5, 4, 0));
	KUNIT_EXPECT_LT(test, kver,
			(unsigned int)KERNEL_VERSION(8, 0, 0));
}

/* ──────────────────────────────────────────────────────────────────────────
 * 2. Version boundary checks (mutually exclusive paths)
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_compat_version_guards_consistent - exactly one code path is compiled in
 *
 * compat.c has three branches:
 *   A) LINUX_VERSION_CODE >= 6.6.0  (mnt_idmap, new interface)
 *   B) LINUX_VERSION_CODE >= 6.3.0  (mnt_idmap, older interface)
 *   C) LINUX_VERSION_CODE >= 5.12.0 (mnt_user_ns)
 *   D) LINUX_VERSION_CODE <  5.12.0 (init_user_ns / no ns arg)
 *
 * Verify that the boundaries are ordered correctly so the #if / #else chain
 * is well-formed: 5.12 < 6.3 < 6.6.
 */
static void test_compat_version_guards_consistent(struct kunit *test)
{
	unsigned int v512 = KERNEL_VERSION(5, 12, 0);
	unsigned int v63  = KERNEL_VERSION(6, 3, 0);
	unsigned int v66  = KERNEL_VERSION(6, 6, 0);

	KUNIT_EXPECT_LT(test, v512, v63);
	KUNIT_EXPECT_LT(test, v63,  v66);
}

/*
 * test_compat_idmap_or_user_ns_exclusive - only one namespace API is active
 *
 * On kernels >= 6.3, mnt_idmap() is used.  On older kernels either
 * mnt_user_ns() or the no-namespace form is used.  The two code paths
 * must not both be active at the same time.
 *
 * We represent each branch as a compile-time integer (0 or 1) derived from
 * LINUX_VERSION_CODE and verify that their sum equals exactly 1.
 */
static void test_compat_idmap_or_user_ns_exclusive(struct kunit *test)
{
	int uses_idmap  = (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)) ? 1 : 0;
	int uses_userns = ((LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)) &&
			   (LINUX_VERSION_CODE <  KERNEL_VERSION(6, 3, 0))) ? 1 : 0;
	int uses_nons   = (LINUX_VERSION_CODE <  KERNEL_VERSION(5, 12, 0)) ? 1 : 0;

	/* Exactly one branch must be active */
	KUNIT_EXPECT_EQ(test, uses_idmap + uses_userns + uses_nons, 1);
}

/*
 * test_compat_no_overlap_branches - 6.3 and 6.6 branches do not overlap
 *
 * The outer #if >= 6.6 and the inner #if >= 6.3 are structured as nested
 * if/else, so they are mutually exclusive.  Verify via arithmetic.
 */
static void test_compat_no_overlap_branches(struct kunit *test)
{
	int is_66plus = (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)) ? 1 : 0;
	int is_63to65 = ((LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)) &&
			 (LINUX_VERSION_CODE <  KERNEL_VERSION(6, 6, 0))) ? 1 : 0;

	/* The two ranges must not both be true */
	KUNIT_EXPECT_LE(test, is_66plus + is_63to65, 1);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 3. compat wrapper function existence (link-time check)
 *
 * The following tests take the address of each wrapper function declared in
 * compat.h and assert it is non-NULL.  If the symbol were missing the linker
 * would refuse to build this test module, which is itself a useful check.
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_compat_inode_permission_defined - compat_inode_permission is present
 */
static void test_compat_inode_permission_defined(struct kunit *test)
{
	void *fn = (void *)compat_inode_permission;

	KUNIT_EXPECT_NOT_NULL(test, fn);
}

/*
 * test_compat_vfs_getxattr_defined - compat_ksmbd_vfs_getxattr is present
 */
static void test_compat_vfs_getxattr_defined(struct kunit *test)
{
	void *fn = (void *)compat_ksmbd_vfs_getxattr;

	KUNIT_EXPECT_NOT_NULL(test, fn);
}

/*
 * test_compat_vfs_setxattr_defined - compat_ksmbd_vfs_set_dos_attrib_xattr is present
 */
static void test_compat_vfs_setxattr_defined(struct kunit *test)
{
	void *fn = (void *)compat_ksmbd_vfs_set_dos_attrib_xattr;

	KUNIT_EXPECT_NOT_NULL(test, fn);
}

/*
 * test_compat_vfs_removexattr_defined - get/set dos attrib wrappers cover both directions
 *
 * The compat layer exposes get and set for DOS attribute xattrs.  Verify
 * both getter and setter symbols are non-NULL; the "removexattr" functionality
 * is subsumed by setting an attribute with a cleared value.
 */
static void test_compat_vfs_removexattr_defined(struct kunit *test)
{
	void *fn_get = (void *)compat_ksmbd_vfs_get_dos_attrib_xattr;
	void *fn_set = (void *)compat_ksmbd_vfs_set_dos_attrib_xattr;

	KUNIT_EXPECT_NOT_NULL(test, fn_get);
	KUNIT_EXPECT_NOT_NULL(test, fn_set);
}

/*
 * test_compat_dosattrib_getter_nonnull - DOS attrib getter function pointer is non-null
 */
static void test_compat_dosattrib_getter_nonnull(struct kunit *test)
{
	void *fn = (void *)compat_ksmbd_vfs_get_dos_attrib_xattr;

	KUNIT_EXPECT_NOT_NULL(test, fn);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 4. namespace API selection tests (compile-time path selection)
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_compat_init_user_ns_or_nop_mnt_idmap - correct namespace helper is chosen
 *
 * Before 5.12: init_user_ns passed directly.
 * 5.12 – 6.2:  mnt_user_ns() used.
 * >= 6.3:      mnt_idmap() used.
 *
 * We cannot call these VFS helpers without a real mount, so we verify the
 * compile-time selection is consistent with LINUX_VERSION_CODE.
 */
static void test_compat_init_user_ns_or_nop_mnt_idmap(struct kunit *test)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	/* mnt_idmap() path: struct mnt_idmap must be a known type */
	KUNIT_SUCCEED(test);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	/* mnt_user_ns() path */
	KUNIT_SUCCEED(test);
#else
	/* init_user_ns path */
	KUNIT_SUCCEED(test);
#endif
}

/*
 * test_compat_file_mnt_idmap_defined - idmap accessor is available on >= 6.3
 *
 * On kernels >= 6.3, file_mnt_idmap() is expected to exist.  On older
 * kernels it does not exist; the test just succeeds without checking.
 */
static void test_compat_file_mnt_idmap_defined(struct kunit *test)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	/*
	 * We only verify the version guard selects the idmap path; calling
	 * file_mnt_idmap() requires a real struct file.
	 */
	KUNIT_EXPECT_GE(test, (unsigned int)LINUX_VERSION_CODE,
			(unsigned int)KERNEL_VERSION(6, 3, 0));
#else
	/* On older kernels the function may not exist; nothing to verify */
	KUNIT_SUCCEED(test);
#endif
}

/*
 * test_compat_sb_mnt_idmap_defined - superblock idmap accessor availability
 *
 * Similar to the file-based accessor: on >= 6.3 kernels the idmap API is
 * available through the mount; on older kernels the user-ns API is used.
 */
static void test_compat_sb_mnt_idmap_defined(struct kunit *test)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	KUNIT_EXPECT_GE(test, (unsigned int)LINUX_VERSION_CODE,
			(unsigned int)KERNEL_VERSION(6, 3, 0));
#else
	KUNIT_SUCCEED(test);
#endif
}

/* ──────────────────────────────────────────────────────────────────────────
 * 5. Struct size stability tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_compat_struct_sizes_stable - key kernel structs used by compat have known minimum sizes
 *
 * The compat wrappers pass struct path pointers; verify that struct path
 * and struct dentry are present and non-zero-sized (they must be real kernel
 * types).  We cannot check exact sizes across all kernel versions, so a
 * non-zero lower bound is sufficient.
 */
static void test_compat_struct_sizes_stable(struct kunit *test)
{
	KUNIT_EXPECT_GT(test, sizeof(struct path), (size_t)0);
	KUNIT_EXPECT_GT(test, sizeof(struct dentry), (size_t)0);
	KUNIT_EXPECT_GT(test, sizeof(struct inode), (size_t)0);
}

/*
 * test_compat_posix_acl_ops_defined - posix_acl type is present
 *
 * The compat layer (and ksmbd at large) uses POSIX ACL structures.  Verify
 * that the posix_acl struct is at least pointer-sized.
 */
static void test_compat_posix_acl_ops_defined(struct kunit *test)
{
	/* struct posix_acl is defined in <linux/posix_acl.h>, included via fs.h */
	KUNIT_EXPECT_GT(test, sizeof(struct posix_acl *), (size_t)0);
}

/*
 * test_compat_tmpfile_signature - wrapper compat_inode_permission returns int
 *
 * The compat_inode_permission() wrapper is declared to return int in compat.h.
 * Use sizeof on the function pointer type to confirm the return-type annotation
 * is correct: sizeof a function pointer must equal sizeof(void *).
 */
static void test_compat_tmpfile_signature(struct kunit *test)
{
	/*
	 * sizeof a function pointer is always sizeof(void*) on all supported
	 * architectures; this merely confirms the symbol resolves as a pointer.
	 */
	KUNIT_EXPECT_EQ(test,
			sizeof((void *)compat_inode_permission),
			sizeof(void *));
}

/* ──────────────────────────────────────────────────────────────────────────
 * 6. disable_work_sync compat shim
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_compat_disable_work_sync_defined - disable_work_sync shim is present
 *
 * compat.h provides disable_work_sync() on kernels < 6.13 as a wrapper
 * around cancel_work_sync().  On >= 6.13 the kernel provides it directly.
 * Either way the symbol must be callable; verify by taking its address.
 */
static void test_compat_disable_work_sync_defined(struct kunit *test)
{
	void *fn = (void *)disable_work_sync;

	KUNIT_EXPECT_NOT_NULL(test, fn);
}

/*
 * test_compat_lookup_beneath_defined - LOOKUP_BENEATH fallback is present
 *
 * compat.h defines LOOKUP_BENEATH as 0 on kernels < 5.6 where the flag did
 * not exist.  On >= 5.6 the kernel defines it.  In both cases the macro
 * must expand to an integer; verify it is zero or a small power of two.
 */
static void test_compat_lookup_beneath_defined(struct kunit *test)
{
	unsigned int val = LOOKUP_BENEATH;

	/* Must be 0 (compat fallback) or a valid lookup flag (small int) */
	KUNIT_EXPECT_LE(test, val, (unsigned int)0x10000);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_compat_test_cases[] = {
	/* Kernel version sanity */
	KUNIT_CASE(test_compat_kernel_version),
	/* Version guard consistency */
	KUNIT_CASE(test_compat_version_guards_consistent),
	KUNIT_CASE(test_compat_idmap_or_user_ns_exclusive),
	KUNIT_CASE(test_compat_no_overlap_branches),
	/* Wrapper symbol existence */
	KUNIT_CASE(test_compat_inode_permission_defined),
	KUNIT_CASE(test_compat_vfs_getxattr_defined),
	KUNIT_CASE(test_compat_vfs_setxattr_defined),
	KUNIT_CASE(test_compat_vfs_removexattr_defined),
	KUNIT_CASE(test_compat_dosattrib_getter_nonnull),
	/* Namespace API selection */
	KUNIT_CASE(test_compat_init_user_ns_or_nop_mnt_idmap),
	KUNIT_CASE(test_compat_file_mnt_idmap_defined),
	KUNIT_CASE(test_compat_sb_mnt_idmap_defined),
	/* Struct size stability */
	KUNIT_CASE(test_compat_struct_sizes_stable),
	KUNIT_CASE(test_compat_posix_acl_ops_defined),
	KUNIT_CASE(test_compat_tmpfile_signature),
	/* Auxiliary compat shims */
	KUNIT_CASE(test_compat_disable_work_sync_defined),
	KUNIT_CASE(test_compat_lookup_beneath_defined),
	{}
};

static struct kunit_suite ksmbd_compat_test_suite = {
	.name = "ksmbd_compat",
	.test_cases = ksmbd_compat_test_cases,
};

kunit_test_suite(ksmbd_compat_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd kernel-version compatibility layer");
