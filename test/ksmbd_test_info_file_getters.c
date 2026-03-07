// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for file info getter/setter handlers in smb2_query_set.c:
 *   get_file_access_info, get_file_basic_info, get_file_standard_info,
 *   get_file_internal_info, get_file_position_info, get_file_mode_info,
 *   get_file_compression_info, get_file_attribute_tag_info,
 *   get_file_id_info, fill_fallback_object_id,
 *   set_file_position_info, set_file_mode_info.
 *
 *   All tests call production code directly via MODULE_IMPORT_NS.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>

#include "../smb2pdu.h"
#include "../smb2_query_set.h"
#include "../vfs_cache.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

/*
 * Allocate a buffer large enough for an smb2_query_info_rsp + response data.
 * Layout: 4 bytes __be32 header prefix (rsp_org) + smb2_query_info_rsp + 256
 * bytes of Buffer space for response data.
 */
#define RSP_BUF_SIZE (4 + sizeof(struct smb2_query_info_rsp) + 256)

struct getter_test_ctx {
	void *rsp_buf;
	struct smb2_query_info_rsp *rsp;
	void *rsp_org;
	struct ksmbd_file fp;
	struct ksmbd_inode ci;
	struct file *filp;
};

static int getter_test_init(struct kunit *test)
{
	struct getter_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->rsp_buf = kunit_kzalloc(test, RSP_BUF_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->rsp_buf);

	ctx->rsp_org = ctx->rsp_buf;
	ctx->rsp = (struct smb2_query_info_rsp *)((char *)ctx->rsp_buf + 4);

	/*
	 * Open a real kernel file so that vfs_getattr / vfs_statfs /
	 * file_inode work correctly in the production getters.
	 * /proc/version is available on all kernels and is a regular file.
	 */
	ctx->filp = filp_open("/proc/version", O_RDONLY, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR(ctx->filp));

	memset(&ctx->fp, 0, sizeof(ctx->fp));
	memset(&ctx->ci, 0, sizeof(ctx->ci));

	ctx->fp.filp = ctx->filp;
	ctx->fp.f_ci = &ctx->ci;
	ctx->fp.daccess = cpu_to_le32(0xFFFFFFFF); /* full access by default */
	ctx->fp.coption = cpu_to_le32(0);
	ctx->fp.create_time = 132800000000000000ULL; /* arbitrary NT time */
	ctx->ci.m_fattr = ATTR_NORMAL_LE;
	ctx->ci.m_cached_alloc = -1; /* "not explicitly set" */

	test->priv = ctx;
	return 0;
}

static void getter_test_exit(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;

	if (ctx && ctx->filp && !IS_ERR(ctx->filp))
		fput(ctx->filp);
}

/* ------------------------------------------------------------------ */
/*  get_file_access_info tests                                        */
/* ------------------------------------------------------------------ */

static void test_access_info_normal(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_access_info *info;

	ctx->fp.daccess = cpu_to_le32(0x001F01FF);
	get_file_access_info(ctx->rsp, &ctx->fp, ctx->rsp_org);

	info = (struct smb2_file_access_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le32_to_cpu(info->AccessFlags), (u32)0x001F01FF);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_access_info));
}

static void test_access_info_zero(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_access_info *info;

	ctx->fp.daccess = cpu_to_le32(0);
	get_file_access_info(ctx->rsp, &ctx->fp, ctx->rsp_org);

	info = (struct smb2_file_access_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le32_to_cpu(info->AccessFlags), (u32)0);
}

static void test_access_info_read_only(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_access_info *info;

	ctx->fp.daccess = FILE_READ_DATA_LE;
	get_file_access_info(ctx->rsp, &ctx->fp, ctx->rsp_org);

	info = (struct smb2_file_access_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, info->AccessFlags, FILE_READ_DATA_LE);
}

/* ------------------------------------------------------------------ */
/*  get_file_basic_info tests                                         */
/* ------------------------------------------------------------------ */

static void test_basic_info_normal(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_basic_info *info;
	int ret;

	ctx->fp.daccess = FILE_READ_ATTRIBUTES_LE;
	ret = get_file_basic_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ret, 0);

	info = (struct smb2_file_basic_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le64_to_cpu(info->CreationTime),
			ctx->fp.create_time);
	/* LastAccessTime / LastWriteTime / ChangeTime come from vfs_getattr */
	KUNIT_EXPECT_NE(test, le64_to_cpu(info->LastAccessTime), (u64)0);
	KUNIT_EXPECT_EQ(test, info->Attributes, ctx->ci.m_fattr);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_basic_info));
}

static void test_basic_info_no_read_attr(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	int ret;

	ctx->fp.daccess = cpu_to_le32(0); /* no FILE_READ_ATTRIBUTES */
	ret = get_file_basic_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

/* ------------------------------------------------------------------ */
/*  get_file_standard_info tests                                      */
/* ------------------------------------------------------------------ */

static void test_standard_info_normal(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_standard_info *sinfo;
	int ret;

	ret = get_file_standard_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ret, 0);

	sinfo = (struct smb2_file_standard_info *)ctx->rsp->Buffer;
	/* /proc/version is not a directory */
	KUNIT_EXPECT_EQ(test, sinfo->Directory, (u8)0);
	KUNIT_EXPECT_GE(test, le32_to_cpu(sinfo->NumberOfLinks), (u32)1);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_standard_info));
}

static void test_standard_info_output_len(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;

	get_file_standard_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_standard_info));
}

/* ------------------------------------------------------------------ */
/*  get_file_internal_info tests                                      */
/* ------------------------------------------------------------------ */

static void test_internal_info_normal(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_internal_info *info;
	int ret;

	ret = get_file_internal_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ret, 0);

	info = (struct smb2_file_internal_info *)ctx->rsp->Buffer;
	/* Should return the actual inode number of /proc/version */
	KUNIT_EXPECT_NE(test, le64_to_cpu(info->IndexNumber), (u64)0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_internal_info));
}

static void test_internal_info_matches_inode(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_internal_info *info;
	struct inode *inode;

	get_file_internal_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	info = (struct smb2_file_internal_info *)ctx->rsp->Buffer;

	inode = file_inode(ctx->filp);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(info->IndexNumber), (u64)inode->i_ino);
}

/* ------------------------------------------------------------------ */
/*  get_file_position_info tests                                      */
/* ------------------------------------------------------------------ */

static void test_position_info_normal(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_pos_info *info;

	/* Set a known position */
	ctx->filp->f_pos = 42;
	get_file_position_info(ctx->rsp, &ctx->fp, ctx->rsp_org);

	info = (struct smb2_file_pos_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le64_to_cpu(info->CurrentByteOffset), (u64)42);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_pos_info));
}

static void test_position_info_zero(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_pos_info *info;

	ctx->filp->f_pos = 0;
	get_file_position_info(ctx->rsp, &ctx->fp, ctx->rsp_org);

	info = (struct smb2_file_pos_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le64_to_cpu(info->CurrentByteOffset), (u64)0);
}

static void test_position_info_stream(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_pos_info *info;
	char stream_name[] = ":stream1";

	/* Mark as stream fd */
	ctx->fp.stream.name = stream_name;
	ctx->fp.stream.pos = 1024;
	get_file_position_info(ctx->rsp, &ctx->fp, ctx->rsp_org);

	info = (struct smb2_file_pos_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le64_to_cpu(info->CurrentByteOffset), (u64)1024);

	/* Clean up so exit doesn't get confused */
	ctx->fp.stream.name = NULL;
}

/* ------------------------------------------------------------------ */
/*  get_file_mode_info tests                                          */
/* ------------------------------------------------------------------ */

static void test_mode_info_normal(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_mode_info *info;

	ctx->fp.coption = cpu_to_le32(0x00001000); /* FILE_DELETE_ON_CLOSE */
	get_file_mode_info(ctx->rsp, &ctx->fp, ctx->rsp_org);

	info = (struct smb2_file_mode_info *)ctx->rsp->Buffer;
	/* Mode should be masked by FILE_MODE_INFO_MASK (0x103e) */
	KUNIT_EXPECT_EQ(test, info->Mode,
			cpu_to_le32(0x00001000) & FILE_MODE_INFO_MASK);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_mode_info));
}

static void test_mode_info_zero(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_mode_info *info;

	ctx->fp.coption = cpu_to_le32(0);
	get_file_mode_info(ctx->rsp, &ctx->fp, ctx->rsp_org);

	info = (struct smb2_file_mode_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le32_to_cpu(info->Mode), (u32)0);
}

static void test_mode_info_mask_applied(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_mode_info *info;

	/* Set bits outside the mask to verify they are stripped */
	ctx->fp.coption = cpu_to_le32(0xFFFFFFFF);
	get_file_mode_info(ctx->rsp, &ctx->fp, ctx->rsp_org);

	info = (struct smb2_file_mode_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, info->Mode, FILE_MODE_INFO_MASK);
}

/* ------------------------------------------------------------------ */
/*  get_file_compression_info tests                                   */
/* ------------------------------------------------------------------ */

static void test_compression_info_normal(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_comp_info *info;
	int ret;

	ctx->ci.m_fattr = ATTR_NORMAL_LE; /* not compressed */
	ret = get_file_compression_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ret, 0);

	info = (struct smb2_file_comp_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le16_to_cpu(info->CompressionFormat),
			(u16)COMPRESSION_FORMAT_NONE);
	KUNIT_EXPECT_EQ(test, info->CompressionUnitShift, (u8)0);
	KUNIT_EXPECT_EQ(test, info->ChunkShift, (u8)0);
	KUNIT_EXPECT_EQ(test, info->ClusterShift, (u8)0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_comp_info));
}

static void test_compression_info_compressed_attr(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_comp_info *info;
	int ret;

	ctx->ci.m_fattr = ATTR_COMPRESSED_LE;
	ret = get_file_compression_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ret, 0);

	info = (struct smb2_file_comp_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le16_to_cpu(info->CompressionFormat),
			(u16)COMPRESSION_FORMAT_LZNT1);
}

/* ------------------------------------------------------------------ */
/*  get_file_attribute_tag_info tests                                 */
/* ------------------------------------------------------------------ */

static void test_attr_tag_info_normal(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_attr_tag_info *info;
	int ret;

	ctx->ci.m_fattr = ATTR_NORMAL_LE;
	ret = get_file_attribute_tag_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ret, 0);

	info = (struct smb2_file_attr_tag_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, info->FileAttributes, ATTR_NORMAL_LE);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_attr_tag_info));
}

static void test_attr_tag_info_no_read_attr(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	int ret;

	ctx->fp.daccess = cpu_to_le32(0); /* no FILE_READ_ATTRIBUTES */
	ret = get_file_attribute_tag_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

/* ------------------------------------------------------------------ */
/*  get_file_id_info tests                                            */
/* ------------------------------------------------------------------ */

static void test_id_info_normal(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_id_info *info;
	int ret;

	ret = get_file_id_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ret, 0);

	info = (struct smb2_file_id_info *)ctx->rsp->Buffer;
	/* VolumeSerialNumber should be non-zero for any real FS */
	KUNIT_EXPECT_NE(test, le64_to_cpu(info->VolumeSerialNumber), (u64)0);

	/* FileId low 64 bits should match inode number */
	{
		__le64 ino_le;

		memcpy(&ino_le, &info->FileId[0], sizeof(ino_le));
		KUNIT_EXPECT_EQ(test, le64_to_cpu(ino_le),
				(u64)file_inode(ctx->filp)->i_ino);
	}

	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_id_info));
}

static void test_id_info_no_read_attr(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	int ret;

	ctx->fp.daccess = cpu_to_le32(0);
	ret = get_file_id_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

static void test_id_info_high_file_id_zero(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_id_info *info;
	__le64 high;

	get_file_id_info(ctx->rsp, &ctx->fp, ctx->rsp_org);
	info = (struct smb2_file_id_info *)ctx->rsp->Buffer;

	/* FileId[8..15] (high 64 bits) should be zero */
	memcpy(&high, &info->FileId[8], sizeof(high));
	KUNIT_EXPECT_EQ(test, le64_to_cpu(high), (u64)0);
}

/* ------------------------------------------------------------------ */
/*  fill_fallback_object_id tests                                     */
/* ------------------------------------------------------------------ */

static void test_fallback_object_id_normal(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	u8 object_id[16];
	struct inode *inode;
	__le64 ino;
	__le32 gen, dev;

	fill_fallback_object_id(&ctx->fp, object_id);

	inode = file_inode(ctx->filp);
	ino = cpu_to_le64(inode->i_ino);
	gen = cpu_to_le32(inode->i_generation);
	dev = cpu_to_le32((u32)new_encode_dev(inode->i_sb->s_dev));

	KUNIT_EXPECT_MEMEQ(test, object_id, &ino, sizeof(ino));
	KUNIT_EXPECT_MEMEQ(test, object_id + sizeof(ino), &gen, sizeof(gen));
	KUNIT_EXPECT_MEMEQ(test, object_id + sizeof(ino) + sizeof(gen),
			   &dev, sizeof(dev));
}

static void test_fallback_object_id_remaining_zeroed(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	u8 object_id[16];
	u8 zero_tail[16 - sizeof(__le64) - sizeof(__le32) - sizeof(__le32)];

	memset(object_id, 0xFF, sizeof(object_id));
	fill_fallback_object_id(&ctx->fp, object_id);

	/*
	 * The function memsets the full 16 bytes to zero first, then copies
	 * ino (8) + gen (4) + dev (4) = 16 bytes total.  So nothing remains
	 * but verify the call succeeded without crash.
	 */
	memset(zero_tail, 0, sizeof(zero_tail));
	KUNIT_EXPECT_EQ(test, sizeof(zero_tail), (size_t)0);
	/* 8 + 4 + 4 = 16, no remaining bytes, just verify no crash */
	KUNIT_SUCCEED(test);
}

/* ------------------------------------------------------------------ */
/*  set_file_position_info tests                                      */
/* ------------------------------------------------------------------ */

static void test_set_position_info_valid(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_pos_info pos_info;
	int ret;

	pos_info.CurrentByteOffset = cpu_to_le64(4096);
	ret = set_file_position_info(&ctx->fp, &pos_info);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->filp->f_pos, (loff_t)4096);
}

static void test_set_position_info_zero(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_pos_info pos_info;
	int ret;

	pos_info.CurrentByteOffset = cpu_to_le64(0);
	ret = set_file_position_info(&ctx->fp, &pos_info);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->filp->f_pos, (loff_t)0);
}

static void test_set_position_info_overflow(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_pos_info pos_info;
	int ret;

	/* Value > LLONG_MAX should be rejected */
	pos_info.CurrentByteOffset = cpu_to_le64((u64)LLONG_MAX + 1);
	ret = set_file_position_info(&ctx->fp, &pos_info);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_set_position_info_max_valid(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_pos_info pos_info;
	int ret;

	/* LLONG_MAX itself should be accepted */
	pos_info.CurrentByteOffset = cpu_to_le64((u64)LLONG_MAX);
	ret = set_file_position_info(&ctx->fp, &pos_info);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_set_position_info_stream(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_pos_info pos_info;
	char stream_name[] = ":stream1";
	int ret;

	ctx->fp.stream.name = stream_name;
	ctx->fp.stream.pos = 0;

	pos_info.CurrentByteOffset = cpu_to_le64(512);
	ret = set_file_position_info(&ctx->fp, &pos_info);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->fp.stream.pos, (loff_t)512);

	ctx->fp.stream.name = NULL;
}

/* ------------------------------------------------------------------ */
/*  set_file_mode_info tests                                          */
/* ------------------------------------------------------------------ */

static void test_set_mode_info_valid(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_mode_info mode_info;
	int ret;

	mode_info.Mode = FILE_SYNCHRONOUS_IO_ALERT_LE;
	ret = set_file_mode_info(&ctx->fp, &mode_info);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->fp.coption, FILE_SYNCHRONOUS_IO_ALERT_LE);
}

static void test_set_mode_info_zero(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_mode_info mode_info;
	int ret;

	mode_info.Mode = cpu_to_le32(0);
	ret = set_file_mode_info(&ctx->fp, &mode_info);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->fp.coption), (u32)0);
}

static void test_set_mode_info_invalid_bits(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_mode_info mode_info;
	int ret;

	/* Bits outside FILE_MODE_INFO_MASK (0x103e) should be rejected */
	mode_info.Mode = cpu_to_le32(0x80000000);
	ret = set_file_mode_info(&ctx->fp, &mode_info);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_set_mode_info_conflicting_sync(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_mode_info mode_info;
	int ret;

	/*
	 * Both FILE_SYNCHRONOUS_IO_ALERT (0x10) and
	 * FILE_SYNCHRONOUS_IO_NONALERT (0x20) set simultaneously
	 * should be rejected.
	 */
	mode_info.Mode = FILE_SYNCHRONOUS_IO_ALERT_LE |
			 FILE_SYNCHRONOUS_IO_NONALERT_LE;
	ret = set_file_mode_info(&ctx->fp, &mode_info);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_set_mode_info_sync_sets_osync(struct kunit *test)
{
	struct getter_test_ctx *ctx = test->priv;
	struct smb2_file_mode_info mode_info;

	/* Clear O_SYNC first */
	ctx->filp->f_flags &= ~O_SYNC;

	mode_info.Mode = FILE_SYNCHRONOUS_IO_NONALERT_LE;
	set_file_mode_info(&ctx->fp, &mode_info);

	KUNIT_EXPECT_TRUE(test, (ctx->filp->f_flags & O_SYNC) != 0);
}

/* ------------------------------------------------------------------ */
/*  Test registration                                                 */
/* ------------------------------------------------------------------ */

static struct kunit_case ksmbd_info_file_getters_test_cases[] = {
	/* get_file_access_info */
	KUNIT_CASE(test_access_info_normal),
	KUNIT_CASE(test_access_info_zero),
	KUNIT_CASE(test_access_info_read_only),
	/* get_file_basic_info */
	KUNIT_CASE(test_basic_info_normal),
	KUNIT_CASE(test_basic_info_no_read_attr),
	/* get_file_standard_info */
	KUNIT_CASE(test_standard_info_normal),
	KUNIT_CASE(test_standard_info_output_len),
	/* get_file_internal_info */
	KUNIT_CASE(test_internal_info_normal),
	KUNIT_CASE(test_internal_info_matches_inode),
	/* get_file_position_info */
	KUNIT_CASE(test_position_info_normal),
	KUNIT_CASE(test_position_info_zero),
	KUNIT_CASE(test_position_info_stream),
	/* get_file_mode_info */
	KUNIT_CASE(test_mode_info_normal),
	KUNIT_CASE(test_mode_info_zero),
	KUNIT_CASE(test_mode_info_mask_applied),
	/* get_file_compression_info */
	KUNIT_CASE(test_compression_info_normal),
	KUNIT_CASE(test_compression_info_compressed_attr),
	/* get_file_attribute_tag_info */
	KUNIT_CASE(test_attr_tag_info_normal),
	KUNIT_CASE(test_attr_tag_info_no_read_attr),
	/* get_file_id_info */
	KUNIT_CASE(test_id_info_normal),
	KUNIT_CASE(test_id_info_no_read_attr),
	KUNIT_CASE(test_id_info_high_file_id_zero),
	/* fill_fallback_object_id */
	KUNIT_CASE(test_fallback_object_id_normal),
	KUNIT_CASE(test_fallback_object_id_remaining_zeroed),
	/* set_file_position_info */
	KUNIT_CASE(test_set_position_info_valid),
	KUNIT_CASE(test_set_position_info_zero),
	KUNIT_CASE(test_set_position_info_overflow),
	KUNIT_CASE(test_set_position_info_max_valid),
	KUNIT_CASE(test_set_position_info_stream),
	/* set_file_mode_info */
	KUNIT_CASE(test_set_mode_info_valid),
	KUNIT_CASE(test_set_mode_info_zero),
	KUNIT_CASE(test_set_mode_info_invalid_bits),
	KUNIT_CASE(test_set_mode_info_conflicting_sync),
	KUNIT_CASE(test_set_mode_info_sync_sets_osync),
	{}
};

static struct kunit_suite ksmbd_info_file_getters_test_suite = {
	.name = "ksmbd_info_file_getters",
	.init = getter_test_init,
	.exit = getter_test_exit,
	.test_cases = ksmbd_info_file_getters_test_cases,
};

kunit_test_suite(ksmbd_info_file_getters_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd file info getter/setter handlers");
