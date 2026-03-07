// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for filesystem info-level handlers:
 *   FS_CONTROL SET, FS_DRIVER_PATH GET, FS_LABEL SET, FS_OBJECT_ID SET.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ---- Replicated structures ---- */

struct test_fs_control_info {
	__le64 FreeSpaceStartFiltering;
	__le64 FreeSpaceThreshold;
	__le64 FreeSpaceStopFiltering;
	__le64 DefaultQuotaThreshold;
	__le64 DefaultQuotaLimit;
	__le32 FileSystemControlFlags;
	__le32 Padding;
} __packed;

struct test_fs_driver_path_info {
	__u8 DriverInPath;
	__u8 Reserved[3];
} __packed;

struct test_fs_label_info {
	__le32 VolumeLabelLength;
	__le16 VolumeLabel[];
} __packed;

struct test_object_id_info {
	__u8 ObjectId[16];
	__u8 BirthObjectId[16];
	__u8 DomainId[16];
} __packed;

/* ---- Replicated handlers ---- */

static int test_set_fs_control(void *buf, unsigned int buf_len,
			       unsigned int *out_len)
{
	if (buf_len < sizeof(struct test_fs_control_info))
		return -EMSGSIZE;

	*out_len = sizeof(struct test_fs_control_info);
	return 0;
}

static int test_get_fs_driver_path(void *buf, unsigned int buf_len,
				   unsigned int *out_len)
{
	struct test_fs_driver_path_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_fs_driver_path_info *)buf;
	memset(info, 0, sizeof(*info));
	*out_len = sizeof(*info);
	return 0;
}

static int test_set_fs_label(void *buf, unsigned int buf_len,
			     unsigned int *out_len)
{
	struct test_fs_label_info *info;
	unsigned int consumed;
	u32 label_len;

	if (buf_len < sizeof(*info))
		return -EMSGSIZE;

	info = (struct test_fs_label_info *)buf;
	label_len = le32_to_cpu(info->VolumeLabelLength);
	if (label_len & 1)
		return -EINVAL;

	consumed = offsetof(struct test_fs_label_info, VolumeLabel) + label_len;
	if (consumed > buf_len)
		return -EINVAL;

	*out_len = consumed;
	return 0;
}

static int test_set_fs_object_id(void *buf, unsigned int buf_len,
				 unsigned int *out_len)
{
	if (buf_len < sizeof(struct test_object_id_info))
		return -EMSGSIZE;

	*out_len = sizeof(struct test_object_id_info);
	return 0;
}

/* ---- Test cases: FS_CONTROL SET ---- */

static void test_fs_control_set_normal(struct kunit *test)
{
	struct test_fs_control_info buf;
	unsigned int out_len;
	int ret;

	memset(&buf, 0, sizeof(buf));
	ret = test_set_fs_control(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_fs_control_set_buffer_too_small(struct kunit *test)
{
	struct test_fs_control_info buf;
	unsigned int out_len;
	int ret;

	ret = test_set_fs_control(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EMSGSIZE);
}

/* ---- Test cases: FS_DRIVER_PATH GET ---- */

static void test_fs_driver_path_get_normal(struct kunit *test)
{
	struct test_fs_driver_path_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_fs_driver_path(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, buf.DriverInPath, (u8)0);
}

static void test_fs_driver_path_get_buffer_too_small(struct kunit *test)
{
	struct test_fs_driver_path_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_fs_driver_path(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: FS_LABEL SET ---- */

static void test_fs_label_set_normal(struct kunit *test)
{
	/* 4 bytes header + 4 bytes label (2 UTF-16 chars) */
	u8 raw[8];
	struct test_fs_label_info *info = (struct test_fs_label_info *)raw;
	unsigned int out_len;
	int ret;

	memset(raw, 0, sizeof(raw));
	info->VolumeLabelLength = cpu_to_le32(4);
	info->VolumeLabel[0] = cpu_to_le16('A');
	info->VolumeLabel[1] = cpu_to_le16('B');

	ret = test_set_fs_label(raw, sizeof(raw), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)8);
}

static void test_fs_label_set_buffer_too_small(struct kunit *test)
{
	u8 raw[3]; /* Too small for header */
	unsigned int out_len;
	int ret;

	memset(raw, 0, sizeof(raw));
	ret = test_set_fs_label(raw, sizeof(raw), &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EMSGSIZE);
}

static void test_fs_label_set_odd_label_length(struct kunit *test)
{
	u8 raw[8];
	struct test_fs_label_info *info = (struct test_fs_label_info *)raw;
	unsigned int out_len;
	int ret;

	memset(raw, 0, sizeof(raw));
	info->VolumeLabelLength = cpu_to_le32(3); /* Odd: invalid for UTF-16 */

	ret = test_set_fs_label(raw, sizeof(raw), &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_fs_label_set_length_exceeds_buffer(struct kunit *test)
{
	u8 raw[8];
	struct test_fs_label_info *info = (struct test_fs_label_info *)raw;
	unsigned int out_len;
	int ret;

	memset(raw, 0, sizeof(raw));
	info->VolumeLabelLength = cpu_to_le32(100); /* Way beyond buffer */

	ret = test_set_fs_label(raw, sizeof(raw), &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* ---- Test cases: FS_OBJECT_ID SET ---- */

static void test_fs_object_id_set_normal(struct kunit *test)
{
	struct test_object_id_info buf;
	unsigned int out_len;
	int ret;

	memset(&buf, 0x42, sizeof(buf));
	ret = test_set_fs_object_id(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_fs_object_id_set_buffer_too_small(struct kunit *test)
{
	struct test_object_id_info buf;
	unsigned int out_len;
	int ret;

	ret = test_set_fs_object_id(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EMSGSIZE);
}

static struct kunit_case ksmbd_info_fs_test_cases[] = {
	KUNIT_CASE(test_fs_control_set_normal),
	KUNIT_CASE(test_fs_control_set_buffer_too_small),
	KUNIT_CASE(test_fs_driver_path_get_normal),
	KUNIT_CASE(test_fs_driver_path_get_buffer_too_small),
	KUNIT_CASE(test_fs_label_set_normal),
	KUNIT_CASE(test_fs_label_set_buffer_too_small),
	KUNIT_CASE(test_fs_label_set_odd_label_length),
	KUNIT_CASE(test_fs_label_set_length_exceeds_buffer),
	KUNIT_CASE(test_fs_object_id_set_normal),
	KUNIT_CASE(test_fs_object_id_set_buffer_too_small),
	{}
};

/* MOCK-ONLY: tests replicated logic, not production ksmbd code */
static struct kunit_suite ksmbd_info_fs_test_suite = {
	.name = "ksmbd_info_fs",
	.test_cases = ksmbd_info_fs_test_cases,
};

kunit_test_suite(ksmbd_info_fs_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd filesystem info-level handlers");
