// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for ntstatus_to_dos() mapping (netmisc.c)
 *
 *   Calls the production ntstatus_to_dos() directly via exported symbol.
 *   Only built when CONFIG_SMB_INSECURE_SERVER=y (netmisc.c is conditional).
 */

#include <kunit/test.h>
#include <linux/types.h>

#include "glob.h"
#include "smberr.h"
#include "nterr.h"

#ifdef CONFIG_SMB_INSECURE_SERVER

static void test_success_maps_to_zero(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(0, &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, 0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), 0);
}

static void test_access_denied(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_ACCESS_DENIED),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRnoaccess);
}

static void test_no_such_file(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_NO_SUCH_FILE),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRbadfile);
}

static void test_sharing_violation(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_SHARING_VIOLATION),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRbadshare);
}

static void test_invalid_parameter(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_INVALID_PARAMETER),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), 87);
}

static void test_invalid_handle(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_INVALID_HANDLE),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRbadfid);
}

static void test_object_name_collision(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_OBJECT_NAME_COLLISION),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRalreadyexists);
}

static void test_disk_full(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_DISK_FULL),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), 112);
}

static void test_directory_not_empty(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_DIRECTORY_NOT_EMPTY),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), 145);
}

static void test_lock_not_granted(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_LOCK_NOT_GRANTED),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRlock);
}

static void test_file_lock_conflict(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_FILE_LOCK_CONFLICT),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRlock);
}

static void test_not_a_directory(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_NOT_A_DIRECTORY),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), 267);
}

static void test_password_expired(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_PASSWORD_EXPIRED),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRSRV);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRpasswordExpired);
}

static void test_unknown_status_fallback(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(0xDEADBEEF), &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRHRD);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRgeneral);
}

static void test_object_name_not_found(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_OBJECT_NAME_NOT_FOUND),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRbadfile);
}

static void test_object_path_not_found(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	ntstatus_to_dos(cpu_to_le32(NT_STATUS_OBJECT_PATH_NOT_FOUND),
			&eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRbadpath);
}

static struct kunit_case ksmbd_netmisc_mapping_cases[] = {
	KUNIT_CASE(test_success_maps_to_zero),
	KUNIT_CASE(test_access_denied),
	KUNIT_CASE(test_no_such_file),
	KUNIT_CASE(test_sharing_violation),
	KUNIT_CASE(test_invalid_parameter),
	KUNIT_CASE(test_invalid_handle),
	KUNIT_CASE(test_object_name_collision),
	KUNIT_CASE(test_disk_full),
	KUNIT_CASE(test_directory_not_empty),
	KUNIT_CASE(test_lock_not_granted),
	KUNIT_CASE(test_file_lock_conflict),
	KUNIT_CASE(test_not_a_directory),
	KUNIT_CASE(test_password_expired),
	KUNIT_CASE(test_unknown_status_fallback),
	KUNIT_CASE(test_object_name_not_found),
	KUNIT_CASE(test_object_path_not_found),
	{}
};

static struct kunit_suite ksmbd_netmisc_mapping_suite = {
	.name = "ksmbd_netmisc_mapping",
	.test_cases = ksmbd_netmisc_mapping_cases,
};

kunit_test_suite(ksmbd_netmisc_mapping_suite);

#endif /* CONFIG_SMB_INSECURE_SERVER */

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd NT status to DOS error mapping (calls production code)");
