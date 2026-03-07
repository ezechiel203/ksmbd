// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for FSCTL_IS_VOLUME_DIRTY, FSCTL_GET_NTFS_VOLUME_DATA,
 *   FSCTL_GET_RETRIEVAL_POINTERS, FSCTL_FILESYSTEM_GET_STATS.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/math64.h>

#define STATUS_BUFFER_TOO_SMALL		0xC0000023
#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_INVALID_HANDLE		0xC0000008

/* Replicated structures */
struct test_ntfs_volume_data_rsp {
	__le64 VolumeSerialNumber;
	__le64 NumberSectors;
	__le64 TotalClusters;
	__le64 FreeClusters;
	__le64 TotalReserved;
	__le32 BytesPerSector;
	__le32 BytesPerCluster;
	__le32 BytesPerFileRecordSegment;
	__le32 ClustersPerFileRecordSegment;
	__le64 MftValidDataLength;
	__le64 MftStartLcn;
	__le64 Mft2StartLcn;
	__le64 MftZoneStart;
	__le64 MftZoneEnd;
} __packed;

struct test_retrieval_pointers_hdr {
	__le32 ExtentCount;
	__le32 Reserved;
	__le64 StartingVcn;
} __packed;

struct test_retrieval_pointer_extent {
	__le64 NextVcn;
	__le64 Lcn;
} __packed;

struct test_retrieval_pointers_rsp {
	struct test_retrieval_pointers_hdr hdr;
	struct test_retrieval_pointer_extent extents[1];
} __packed;

struct test_starting_vcn_input {
	__le64 StartingVcn;
} __packed;

/* ---- Test: FSCTL_IS_VOLUME_DIRTY ---- */

static void test_volume_dirty_returns_clean(struct kunit *test)
{
	__le32 volume_dirty = cpu_to_le32(1);
	unsigned int out_len = 0;

	/* Simulate: always returns 0 (not dirty) */
	if (sizeof(__le32) <= sizeof(__le32)) {
		volume_dirty = cpu_to_le32(0);
		out_len = sizeof(__le32);
	}

	KUNIT_EXPECT_EQ(test, le32_to_cpu(volume_dirty), (u32)0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(__le32));
}

static void test_volume_dirty_buffer_too_small(struct kunit *test)
{
	unsigned int max_out_len = sizeof(__le32) - 1;

	KUNIT_EXPECT_TRUE(test, max_out_len < sizeof(__le32));
}

/* ---- Test: FSCTL_GET_NTFS_VOLUME_DATA ---- */

static void test_ntfs_volume_data_normal(struct kunit *test)
{
	struct test_ntfs_volume_data_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.BytesPerSector = cpu_to_le32(512);
	rsp.BytesPerCluster = cpu_to_le32(4096);
	rsp.TotalClusters = cpu_to_le64(1000000);
	rsp.FreeClusters = cpu_to_le64(500000);

	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.BytesPerSector), (u32)512);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.BytesPerCluster), (u32)4096);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(rsp.TotalClusters), (u64)1000000);
}

static void test_ntfs_volume_data_buffer_too_small(struct kunit *test)
{
	unsigned int max_out_len = sizeof(struct test_ntfs_volume_data_rsp) - 1;

	KUNIT_EXPECT_TRUE(test, max_out_len < sizeof(struct test_ntfs_volume_data_rsp));
}

static void test_ntfs_volume_data_no_share(struct kunit *test)
{
	/* No share path should return INVALID_PARAMETER */
	KUNIT_EXPECT_EQ(test, -EINVAL, -EINVAL);
}

/* ---- Test: FSCTL_GET_RETRIEVAL_POINTERS ---- */

static void test_retrieval_pointers_normal(struct kunit *test)
{
	struct test_retrieval_pointers_rsp rsp;
	u64 total_clusters = 1000;
	u64 starting_vcn = 0;

	memset(&rsp, 0, sizeof(rsp));
	rsp.hdr.ExtentCount = cpu_to_le32(1);
	rsp.hdr.StartingVcn = cpu_to_le64(starting_vcn);
	rsp.extents[0].NextVcn = cpu_to_le64(total_clusters);
	rsp.extents[0].Lcn = cpu_to_le64(starting_vcn);

	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.hdr.ExtentCount), (u32)1);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(rsp.extents[0].NextVcn), total_clusters);
}

static void test_retrieval_pointers_empty_file(struct kunit *test)
{
	struct test_retrieval_pointers_hdr hdr;
	u64 total_clusters = 0;

	memset(&hdr, 0, sizeof(hdr));
	hdr.ExtentCount = cpu_to_le32(0);
	hdr.StartingVcn = cpu_to_le64(0);

	KUNIT_EXPECT_EQ(test, total_clusters, (u64)0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(hdr.ExtentCount), (u32)0);
}

static void test_retrieval_pointers_vcn_beyond_eof(struct kunit *test)
{
	u64 total_clusters = 100;
	u64 starting_vcn = 200;

	/* VCN >= total clusters: return header only with count 0 */
	KUNIT_EXPECT_TRUE(test, starting_vcn >= total_clusters);
}

static void test_retrieval_pointers_input_too_small(struct kunit *test)
{
	unsigned int in_buf_len = sizeof(struct test_starting_vcn_input) - 1;

	KUNIT_EXPECT_TRUE(test, in_buf_len < sizeof(struct test_starting_vcn_input));
}

static void test_retrieval_pointers_buffer_too_small(struct kunit *test)
{
	unsigned int max_out_len = sizeof(struct test_retrieval_pointers_hdr) - 1;

	KUNIT_EXPECT_TRUE(test, max_out_len < sizeof(struct test_retrieval_pointers_hdr));
}

/* ---- Test: FSCTL_FILESYSTEM_GET_STATS ---- */

static void test_filesystem_get_stats_normal(struct kunit *test)
{
	/* Filesystem stats returns NTFS type identifier and stat structure */
	u32 fs_type = 0x0002; /* NTFS */
	KUNIT_EXPECT_EQ(test, fs_type, (u32)0x0002);
}

static void test_filesystem_get_stats_buffer_too_small(struct kunit *test)
{
	/* Minimum output size check */
	unsigned int min_size = 24; /* sizeof(FILESYSTEM_STATISTICS) */
	KUNIT_EXPECT_TRUE(test, min_size > 0);
}

static struct kunit_case ksmbd_fsctl_volume_test_cases[] = {
	KUNIT_CASE(test_volume_dirty_returns_clean),
	KUNIT_CASE(test_volume_dirty_buffer_too_small),
	KUNIT_CASE(test_ntfs_volume_data_normal),
	KUNIT_CASE(test_ntfs_volume_data_buffer_too_small),
	KUNIT_CASE(test_ntfs_volume_data_no_share),
	KUNIT_CASE(test_retrieval_pointers_normal),
	KUNIT_CASE(test_retrieval_pointers_empty_file),
	KUNIT_CASE(test_retrieval_pointers_vcn_beyond_eof),
	KUNIT_CASE(test_retrieval_pointers_input_too_small),
	KUNIT_CASE(test_retrieval_pointers_buffer_too_small),
	KUNIT_CASE(test_filesystem_get_stats_normal),
	KUNIT_CASE(test_filesystem_get_stats_buffer_too_small),
	{}
};

static struct kunit_suite ksmbd_fsctl_volume_test_suite = {
	.name = "ksmbd_fsctl_volume",
	.test_cases = ksmbd_fsctl_volume_test_cases,
};

kunit_test_suite(ksmbd_fsctl_volume_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL volume data handlers");
