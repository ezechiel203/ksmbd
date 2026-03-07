// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit error path tests for SMB2 QUERY_INFO / SET_INFO handlers.
 *   Calls real production functions via MODULE_IMPORT_NS.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "../smb2pdu.h"
#include "../smb2_query_set.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#define RSP_BUF_SIZE (4 + sizeof(struct smb2_query_info_rsp) + 256)

struct error_test_ctx {
	void *rsp_buf;
	struct smb2_query_info_rsp *rsp;
	void *rsp_org;
};

static int error_test_init(struct kunit *test)
{
	struct error_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->rsp_buf = kunit_kzalloc(test, RSP_BUF_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->rsp_buf);

	ctx->rsp_org = ctx->rsp_buf;
	ctx->rsp = (struct smb2_query_info_rsp *)((char *)ctx->rsp_buf + 4);

	test->priv = ctx;
	return 0;
}

/* ---- buffer_check_err error paths ---- */

static void test_err_buffer_check_zero_req_nonzero_output(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(50);
	KUNIT_EXPECT_EQ(test, buffer_check_err(0, ctx->rsp, ctx->rsp_org),
			-EINVAL);
}

static void test_err_buffer_check_sets_status(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;

	ctx->rsp->hdr.Status = 0;
	ctx->rsp->OutputBufferLength = cpu_to_le32(100);
	buffer_check_err(10, ctx->rsp, ctx->rsp_org);

	KUNIT_EXPECT_EQ(test, ctx->rsp->hdr.Status,
			STATUS_INFO_LENGTH_MISMATCH);
}

static void test_err_buffer_check_sets_rsp_org(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(100);
	buffer_check_err(10, ctx->rsp, ctx->rsp_org);

	/* rsp_org should have sizeof(smb2_hdr) in big-endian */
	KUNIT_EXPECT_EQ(test, *(__be32 *)ctx->rsp_org,
			cpu_to_be32(sizeof(struct smb2_hdr)));
}

static void test_err_buffer_check_negative_req(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(10);
	/* Negative reqOutputBufferLength should fail comparison */
	KUNIT_EXPECT_EQ(test, buffer_check_err(-1, ctx->rsp, ctx->rsp_org),
			-EINVAL);
}

static void test_err_buffer_check_max_output(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(0xFFFFFFFF);
	KUNIT_EXPECT_EQ(test, buffer_check_err(100, ctx->rsp, ctx->rsp_org),
			-EINVAL);
}

/* ---- get_standard_info_pipe idempotency ---- */

static void test_err_pipe_info_double_call(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;
	struct smb2_file_standard_info *sinfo;

	/* Calling twice should produce identical results */
	get_standard_info_pipe(ctx->rsp, ctx->rsp_org);
	get_standard_info_pipe(ctx->rsp, ctx->rsp_org);

	sinfo = (struct smb2_file_standard_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le64_to_cpu(sinfo->AllocationSize), (u64)4096);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(sinfo->NumberOfLinks), (u32)1);
}

/* ---- get_internal_info_pipe edge cases ---- */

static void test_err_internal_pipe_max_num(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;
	struct smb2_file_internal_info *info;

	get_internal_info_pipe(ctx->rsp, U64_MAX, ctx->rsp_org);
	info = (struct smb2_file_internal_info *)ctx->rsp->Buffer;

	/* U64_MAX | (1<<63) == U64_MAX */
	KUNIT_EXPECT_EQ(test, le64_to_cpu(info->IndexNumber), U64_MAX);
}

static void test_err_internal_pipe_bit63_already_set(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;
	struct smb2_file_internal_info *info;
	u64 num = (1ULL << 63) | 0x42;

	get_internal_info_pipe(ctx->rsp, num, ctx->rsp_org);
	info = (struct smb2_file_internal_info *)ctx->rsp->Buffer;

	KUNIT_EXPECT_EQ(test, le64_to_cpu(info->IndexNumber), num);
}

/* ---- get_file_ea_info edge case ---- */

static void test_err_ea_info_always_zero(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;
	struct smb2_file_ea_info *info;

	/* Without fp, EASize is always 0 */
	get_file_ea_info(ctx->rsp, ctx->rsp_org);
	info = (struct smb2_file_ea_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le32_to_cpu(info->EASize), (u32)0);
}

/* ---- get_file_alignment_info consistency ---- */

static void test_err_alignment_always_zero(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;
	struct smb2_file_alignment_info *info;

	get_file_alignment_info(ctx->rsp, ctx->rsp_org);
	info = (struct smb2_file_alignment_info *)ctx->rsp->Buffer;
	KUNIT_EXPECT_EQ(test, le32_to_cpu(info->AlignmentRequirement), (u32)0);
}

/* ---- buffer_check_err boundary ---- */

static void test_err_buffer_check_one_byte_short(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(41);
	KUNIT_EXPECT_EQ(test, buffer_check_err(40, ctx->rsp, ctx->rsp_org),
			-EINVAL);
}

static void test_err_buffer_check_one_byte_over(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(40);
	KUNIT_EXPECT_EQ(test, buffer_check_err(41, ctx->rsp, ctx->rsp_org), 0);
}

/* ---- buffer_check_err with zero output but nonzero request ---- */

static void test_err_buffer_zero_output_nonzero_req(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(0);
	KUNIT_EXPECT_EQ(test, buffer_check_err(100, ctx->rsp, ctx->rsp_org), 0);
}

static void test_err_buffer_both_zero(struct kunit *test)
{
	struct error_test_ctx *ctx = test->priv;

	ctx->rsp->OutputBufferLength = cpu_to_le32(0);
	KUNIT_EXPECT_EQ(test, buffer_check_err(0, ctx->rsp, ctx->rsp_org), 0);
}

static struct kunit_case ksmbd_error_query_set_test_cases[] = {
	KUNIT_CASE(test_err_buffer_check_zero_req_nonzero_output),
	KUNIT_CASE(test_err_buffer_check_sets_status),
	KUNIT_CASE(test_err_buffer_check_sets_rsp_org),
	KUNIT_CASE(test_err_buffer_check_negative_req),
	KUNIT_CASE(test_err_buffer_check_max_output),
	KUNIT_CASE(test_err_pipe_info_double_call),
	KUNIT_CASE(test_err_internal_pipe_max_num),
	KUNIT_CASE(test_err_internal_pipe_bit63_already_set),
	KUNIT_CASE(test_err_ea_info_always_zero),
	KUNIT_CASE(test_err_alignment_always_zero),
	KUNIT_CASE(test_err_buffer_check_one_byte_short),
	KUNIT_CASE(test_err_buffer_check_one_byte_over),
	KUNIT_CASE(test_err_buffer_zero_output_nonzero_req),
	KUNIT_CASE(test_err_buffer_both_zero),
	{}
};

static struct kunit_suite ksmbd_error_query_set_test_suite = {
	.name = "ksmbd_error_query_set",
	.init = error_test_init,
	.test_cases = ksmbd_error_query_set_test_cases,
};

kunit_test_suite(ksmbd_error_query_set_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit error path tests for ksmbd SMB2 QUERY_INFO/SET_INFO");
