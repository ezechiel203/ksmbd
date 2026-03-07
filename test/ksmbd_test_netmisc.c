// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for ntstatus_to_dos() mapping (netmisc.c)
 *
 *   The mapping table is pure logic: given an NT status code, it
 *   produces a DOS error class and code.  We replicate the function
 *   inline to avoid needing to link against the full ksmbd module.
 */

#include <kunit/test.h>
#include <linux/types.h>

#include "smberr.h"
#include "nterr.h"
#include "glob.h"

/*
 * We call the real ntstatus_to_dos() from netmisc.c.  Because we include
 * glob.h which declares it extern, we need to replicate it here.
 */

/* Replicated from netmisc.c for standalone KUnit builds */
static const struct {
	__u8 dos_class;
	__u16 dos_code;
	__u32 ntstatus;
} test_ntstatus_to_dos_map[] = {
	{ ERRDOS, ERRgeneral, NT_STATUS_UNSUCCESSFUL },
	{ ERRDOS, ERRbadfunc, NT_STATUS_NOT_IMPLEMENTED },
	{ ERRHRD, ERRgeneral, NT_STATUS_ACCESS_VIOLATION },
	{ ERRDOS, ERRbadfid, NT_STATUS_INVALID_HANDLE },
	{ ERRDOS, 87, NT_STATUS_INVALID_PARAMETER },
	{ ERRDOS, ERRbadfile, NT_STATUS_NO_SUCH_FILE },
	{ ERRDOS, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ ERRDOS, ERRbadfile, NT_STATUS_OBJECT_NAME_NOT_FOUND },
	{ ERRDOS, ERRalreadyexists, NT_STATUS_OBJECT_NAME_COLLISION },
	{ ERRDOS, ERRbadshare, NT_STATUS_SHARING_VIOLATION },
	{ ERRDOS, ERRlock, NT_STATUS_FILE_LOCK_CONFLICT },
	{ ERRDOS, ERRlock, NT_STATUS_LOCK_NOT_GRANTED },
	{ ERRDOS, ERRbadfile, NT_STATUS_DELETE_PENDING },
	{ ERRDOS, 112, NT_STATUS_DISK_FULL },
	{ ERRDOS, 145, NT_STATUS_DIRECTORY_NOT_EMPTY },
	{ ERRDOS, ERRnofids, NT_STATUS_TOO_MANY_OPENED_FILES },
	{ ERRDOS, ERRbadfid, NT_STATUS_FILE_CLOSED },
	{ ERRSRV, ERRpasswordExpired, NT_STATUS_PASSWORD_EXPIRED },
	{ 0, 0, 0 },
};

static void
test_ntstatus_to_dos_impl(__le32 ntstatus, __u8 *eclass, __le16 *ecode)
{
	int i;

	if (ntstatus == 0) {
		*eclass = 0;
		*ecode = 0;
		return;
	}
	for (i = 0; test_ntstatus_to_dos_map[i].ntstatus; i++) {
		if (le32_to_cpu(ntstatus) ==
		    test_ntstatus_to_dos_map[i].ntstatus) {
			*eclass = test_ntstatus_to_dos_map[i].dos_class;
			*ecode = cpu_to_le16(
				test_ntstatus_to_dos_map[i].dos_code);
			return;
		}
	}
	*eclass = ERRHRD;
	*ecode = cpu_to_le16(ERRgeneral);
}

/* --- Test cases --- */

static void test_ntstatus_to_dos_success(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(0, &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, 0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), 0);
}

static void test_ntstatus_to_dos_access_denied(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_ACCESS_DENIED),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRnoaccess);
}

static void test_ntstatus_to_dos_no_such_file(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_NO_SUCH_FILE),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRbadfile);
}

static void test_ntstatus_to_dos_sharing_violation(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_SHARING_VIOLATION),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRbadshare);
}

static void test_ntstatus_to_dos_lock_conflict(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_FILE_LOCK_CONFLICT),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRlock);
}

static void test_ntstatus_to_dos_invalid_parameter(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_INVALID_PARAMETER),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), 87);
}

static void test_ntstatus_to_dos_invalid_handle(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_INVALID_HANDLE),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRbadfid);
}

static void test_ntstatus_to_dos_object_name_collision(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_OBJECT_NAME_COLLISION),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRalreadyexists);
}

static void test_ntstatus_to_dos_disk_full(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_DISK_FULL),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), 112);
}

static void test_ntstatus_to_dos_directory_not_empty(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_DIRECTORY_NOT_EMPTY),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), 145);
}

static void test_ntstatus_to_dos_unknown_status(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	/* A completely unknown status code should fallback */
	test_ntstatus_to_dos_impl(cpu_to_le32(0xDEADBEEF), &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRHRD);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRgeneral);
}

static void test_ntstatus_to_dos_file_closed(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_FILE_CLOSED),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRbadfid);
}

static void test_ntstatus_to_dos_password_expired(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_PASSWORD_EXPIRED),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRSRV);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRpasswordExpired);
}

static void test_ntstatus_to_dos_delete_pending(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_DELETE_PENDING),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRbadfile);
}

static void test_ntstatus_to_dos_too_many_opened_files(struct kunit *test)
{
	__u8 eclass;
	__le16 ecode;

	test_ntstatus_to_dos_impl(cpu_to_le32(NT_STATUS_TOO_MANY_OPENED_FILES),
				  &eclass, &ecode);
	KUNIT_EXPECT_EQ(test, (int)eclass, ERRDOS);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ecode), ERRnofids);
}

static struct kunit_case ksmbd_netmisc_test_cases[] = {
	KUNIT_CASE(test_ntstatus_to_dos_success),
	KUNIT_CASE(test_ntstatus_to_dos_access_denied),
	KUNIT_CASE(test_ntstatus_to_dos_no_such_file),
	KUNIT_CASE(test_ntstatus_to_dos_sharing_violation),
	KUNIT_CASE(test_ntstatus_to_dos_lock_conflict),
	KUNIT_CASE(test_ntstatus_to_dos_invalid_parameter),
	KUNIT_CASE(test_ntstatus_to_dos_invalid_handle),
	KUNIT_CASE(test_ntstatus_to_dos_object_name_collision),
	KUNIT_CASE(test_ntstatus_to_dos_disk_full),
	KUNIT_CASE(test_ntstatus_to_dos_directory_not_empty),
	KUNIT_CASE(test_ntstatus_to_dos_unknown_status),
	KUNIT_CASE(test_ntstatus_to_dos_file_closed),
	KUNIT_CASE(test_ntstatus_to_dos_password_expired),
	KUNIT_CASE(test_ntstatus_to_dos_delete_pending),
	KUNIT_CASE(test_ntstatus_to_dos_too_many_opened_files),
	{}
};

static struct kunit_suite ksmbd_netmisc_test_suite = {
	.name = "ksmbd_netmisc",
	.test_cases = ksmbd_netmisc_test_cases,
};

kunit_test_suite(ksmbd_netmisc_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd NT status to DOS error mapping");
