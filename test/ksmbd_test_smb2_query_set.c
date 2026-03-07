// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 QUERY_INFO / SET_INFO handler logic.
 *   Calls real production functions via MODULE_IMPORT_NS.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

#include "../smb2pdu.h"
#include "../smb2_query_set.h"
#include "../vfs_cache.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

/*
 * Allocate a buffer large enough for an smb2_query_info_rsp + response data.
 * We need:
 *   - 4 bytes for the __be32 header prefix (rsp_org)
 *   - struct smb2_query_info_rsp
 *   - 256 bytes of Buffer space for response data
 */
#define RSP_BUF_SIZE (4 + sizeof(struct smb2_query_info_rsp) + 256)

struct query_set_test_ctx {
	void *rsp_buf;
	struct smb2_query_info_rsp *rsp;
	void *rsp_org;
};

static int query_set_test_init(struct kunit *test)
{
	struct query_set_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->rsp_buf = kunit_kzalloc(test, RSP_BUF_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->rsp_buf);

	ctx->rsp_org = ctx->rsp_buf;
	ctx->rsp = (struct smb2_query_info_rsp *)((char *)ctx->rsp_buf + 4);

	test->priv = ctx;
	return 0;
}

/* ---- buffer_check_err tests ---- */

static void test_buffer_check_err_sufficient(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(40);
	KUNIT_EXPECT_EQ(test, buffer_check_err(100, ctx->rsp, ctx->rsp_org), 0);
}

static void test_buffer_check_err_exact(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(40);
	KUNIT_EXPECT_EQ(test, buffer_check_err(40, ctx->rsp, ctx->rsp_org), 0);
}

static void test_buffer_check_err_insufficient(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(100);
	KUNIT_EXPECT_EQ(test, buffer_check_err(10, ctx->rsp, ctx->rsp_org), -EINVAL);
}

static void test_buffer_check_err_status_set(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(100);
	buffer_check_err(10, ctx->rsp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, ctx->rsp->hdr.Status,
			STATUS_INFO_LENGTH_MISMATCH);
}

static void test_buffer_check_err_zero_output(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(0);
	KUNIT_EXPECT_EQ(test, buffer_check_err(0, ctx->rsp, ctx->rsp_org), 0);
}

/* ---- get_standard_info_pipe tests ---- */

static void test_standard_info_pipe_alloc(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;
	struct smb2_file_standard_info *sinfo;

	get_standard_info_pipe(ctx->rsp, ctx->rsp_org);
	sinfo = (struct smb2_file_standard_info *)ctx->rsp->Buffer;

	KUNIT_EXPECT_EQ(test, le64_to_cpu(sinfo->AllocationSize), (u64)4096);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(sinfo->EndOfFile), (u64)0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(sinfo->NumberOfLinks), (u32)1);
	KUNIT_EXPECT_EQ(test, sinfo->DeletePending, (u8)1);
	KUNIT_EXPECT_EQ(test, sinfo->Directory, (u8)0);
}

static void test_standard_info_pipe_output_len(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;

	get_standard_info_pipe(ctx->rsp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_standard_info));
}

/* ---- get_internal_info_pipe tests ---- */

static void test_internal_info_pipe_index(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;
	struct smb2_file_internal_info *info;
	u64 num = 42;

	get_internal_info_pipe(ctx->rsp, num, ctx->rsp_org);
	info = (struct smb2_file_internal_info *)ctx->rsp->Buffer;

	/* Index should have bit 63 set */
	KUNIT_EXPECT_EQ(test, le64_to_cpu(info->IndexNumber),
			num | (1ULL << 63));
}

static void test_internal_info_pipe_zero(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;
	struct smb2_file_internal_info *info;

	get_internal_info_pipe(ctx->rsp, 0, ctx->rsp_org);
	info = (struct smb2_file_internal_info *)ctx->rsp->Buffer;

	KUNIT_EXPECT_EQ(test, le64_to_cpu(info->IndexNumber), (1ULL << 63));
}

static void test_internal_info_pipe_output_len(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;

	get_internal_info_pipe(ctx->rsp, 1, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_internal_info));
}

/* ---- get_file_alignment_info tests ---- */

static void test_alignment_info_zero(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;
	struct smb2_file_alignment_info *info;

	get_file_alignment_info(ctx->rsp, ctx->rsp_org);
	info = (struct smb2_file_alignment_info *)ctx->rsp->Buffer;

	KUNIT_EXPECT_EQ(test, le32_to_cpu(info->AlignmentRequirement), (u32)0);
}

static void test_alignment_info_output_len(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;

	get_file_alignment_info(ctx->rsp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_alignment_info));
}

/* ---- get_file_ea_info tests ---- */

static void test_ea_info_no_fp(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;
	struct smb2_file_ea_info *info;

	/* In the old codebase, get_file_ea_info doesn't take fp, just sets EASize=0 */
	get_file_ea_info(ctx->rsp, ctx->rsp_org);
	info = (struct smb2_file_ea_info *)ctx->rsp->Buffer;

	KUNIT_EXPECT_EQ(test, le32_to_cpu(info->EASize), (u32)0);
}

static void test_ea_info_output_len(struct kunit *test)
{
	struct query_set_test_ctx *ctx = test->priv;

	get_file_ea_info(ctx->rsp, ctx->rsp_org);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ctx->rsp->OutputBufferLength),
			(u32)sizeof(struct smb2_file_ea_info));
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_smb2_query_set_test_cases[] = {
	/* buffer_check_err */
	KUNIT_CASE(test_buffer_check_err_sufficient),
	KUNIT_CASE(test_buffer_check_err_exact),
	KUNIT_CASE(test_buffer_check_err_insufficient),
	KUNIT_CASE(test_buffer_check_err_status_set),
	KUNIT_CASE(test_buffer_check_err_zero_output),
	/* Pipe info */
	KUNIT_CASE(test_standard_info_pipe_alloc),
	KUNIT_CASE(test_standard_info_pipe_output_len),
	KUNIT_CASE(test_internal_info_pipe_index),
	KUNIT_CASE(test_internal_info_pipe_zero),
	KUNIT_CASE(test_internal_info_pipe_output_len),
	/* Alignment info */
	KUNIT_CASE(test_alignment_info_zero),
	KUNIT_CASE(test_alignment_info_output_len),
	/* EA info */
	KUNIT_CASE(test_ea_info_no_fp),
	KUNIT_CASE(test_ea_info_output_len),
	{}
};

static struct kunit_suite ksmbd_smb2_query_set_test_suite = {
	.name = "ksmbd_smb2_query_set",
	.init = query_set_test_init,
	.test_cases = ksmbd_smb2_query_set_test_cases,
};

kunit_test_suite(ksmbd_smb2_query_set_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 QUERY_INFO/SET_INFO handlers");
