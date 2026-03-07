// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for FSCTL_VALIDATE_NEGOTIATE_INFO validation logic.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_BUFFER_TOO_SMALL		0xC0000023
#define STATUS_ACCESS_DENIED		0xC0000022

struct test_validate_negotiate_req {
	__le32 Capabilities;
	__u8   Guid[16];
	__le16 SecurityMode;
	__le16 DialectCount;
	__le16 Dialects[];
} __packed;

struct test_validate_negotiate_rsp {
	__le32 Capabilities;
	__u8   Guid[16];
	__le16 SecurityMode;
	__le16 Dialect;
} __packed;

struct test_vneg_ctx {
	__le32 server_caps;
	u8     server_guid[16];
	__le16 server_sec_mode;
	__le16 server_dialect;
};

static int test_validate_negotiate(struct test_vneg_ctx *ctx,
				   void *in_buf, unsigned int in_buf_len,
				   unsigned int max_out_len,
				   struct test_validate_negotiate_rsp *rsp,
				   unsigned int *out_len, __le32 *status,
				   bool *terminate)
{
	struct test_validate_negotiate_req *req;
	unsigned int min_size;
	unsigned int i;
	bool dialect_found = false;

	*status = 0;
	*out_len = 0;
	*terminate = false;

	min_size = offsetof(struct test_validate_negotiate_req, Dialects);
	if (in_buf_len < min_size) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	if (max_out_len < sizeof(*rsp)) {
		*status = cpu_to_le32(STATUS_BUFFER_TOO_SMALL);
		return -ENOSPC;
	}

	req = (struct test_validate_negotiate_req *)in_buf;

	/* Check DialectCount does not overflow buffer */
	if (in_buf_len < min_size + le16_to_cpu(req->DialectCount) * sizeof(__le16)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	/* Validate GUID match */
	if (memcmp(req->Guid, ctx->server_guid, 16) != 0) {
		*terminate = true;
		return -EINVAL;
	}

	/* Validate SecurityMode match */
	if (req->SecurityMode != ctx->server_sec_mode) {
		*terminate = true;
		return -EINVAL;
	}

	/* Validate Capabilities match */
	if (req->Capabilities != ctx->server_caps) {
		*terminate = true;
		return -EINVAL;
	}

	/* Validate that negotiated dialect is in the list */
	for (i = 0; i < le16_to_cpu(req->DialectCount); i++) {
		if (req->Dialects[i] == ctx->server_dialect) {
			dialect_found = true;
			break;
		}
	}
	if (!dialect_found) {
		*terminate = true;
		return -EINVAL;
	}

	/* Build response */
	rsp->Capabilities = ctx->server_caps;
	memcpy(rsp->Guid, ctx->server_guid, 16);
	rsp->SecurityMode = ctx->server_sec_mode;
	rsp->Dialect = ctx->server_dialect;
	*out_len = sizeof(*rsp);
	return 0;
}

static struct test_vneg_ctx default_vneg_ctx(void)
{
	struct test_vneg_ctx ctx = {
		.server_caps = cpu_to_le32(0x0000007F),
		.server_sec_mode = cpu_to_le16(0x0001),
		.server_dialect = cpu_to_le16(0x0300),
	};
	memset(ctx.server_guid, 0xAB, 16);
	return ctx;
}

static void *build_vneg_req(struct kunit *test, struct test_vneg_ctx *ctx,
			    unsigned int dialect_count, unsigned int *req_len)
{
	unsigned int total = offsetof(struct test_validate_negotiate_req, Dialects) +
			     dialect_count * sizeof(__le16);
	struct test_validate_negotiate_req *req;

	req = kunit_kzalloc(test, total, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	req->Capabilities = ctx->server_caps;
	memcpy(req->Guid, ctx->server_guid, 16);
	req->SecurityMode = ctx->server_sec_mode;
	req->DialectCount = cpu_to_le16(dialect_count);
	if (dialect_count > 0)
		req->Dialects[0] = ctx->server_dialect;

	*req_len = total;
	return req;
}

static void test_validate_negotiate_success(struct kunit *test)
{
	struct test_vneg_ctx ctx = default_vneg_ctx();
	struct test_validate_negotiate_rsp rsp;
	unsigned int out_len, req_len;
	__le32 status;
	bool term;
	void *buf;
	int ret;

	buf = build_vneg_req(test, &ctx, 1, &req_len);
	ret = test_validate_negotiate(&ctx, buf, req_len, sizeof(rsp),
				      &rsp, &out_len, &status, &term);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, term);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(rsp));
}

static void test_validate_negotiate_dialect_mismatch(struct kunit *test)
{
	struct test_vneg_ctx ctx = default_vneg_ctx();
	struct test_validate_negotiate_rsp rsp;
	unsigned int out_len, req_len;
	__le32 status;
	bool term;
	void *buf;
	struct test_validate_negotiate_req *req;
	int ret;

	buf = build_vneg_req(test, &ctx, 1, &req_len);
	req = (struct test_validate_negotiate_req *)buf;
	req->Dialects[0] = cpu_to_le16(0x0210); /* Wrong dialect */

	ret = test_validate_negotiate(&ctx, buf, req_len, sizeof(rsp),
				      &rsp, &out_len, &status, &term);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_TRUE(test, term);
}

static void test_validate_negotiate_guid_mismatch(struct kunit *test)
{
	struct test_vneg_ctx ctx = default_vneg_ctx();
	struct test_validate_negotiate_rsp rsp;
	unsigned int out_len, req_len;
	__le32 status;
	bool term;
	void *buf;
	struct test_validate_negotiate_req *req;
	int ret;

	buf = build_vneg_req(test, &ctx, 1, &req_len);
	req = (struct test_validate_negotiate_req *)buf;
	memset(req->Guid, 0xFF, 16); /* Wrong GUID */

	ret = test_validate_negotiate(&ctx, buf, req_len, sizeof(rsp),
				      &rsp, &out_len, &status, &term);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_TRUE(test, term);
}

static void test_validate_negotiate_security_mode_mismatch(struct kunit *test)
{
	struct test_vneg_ctx ctx = default_vneg_ctx();
	struct test_validate_negotiate_rsp rsp;
	unsigned int out_len, req_len;
	__le32 status;
	bool term;
	void *buf;
	struct test_validate_negotiate_req *req;
	int ret;

	buf = build_vneg_req(test, &ctx, 1, &req_len);
	req = (struct test_validate_negotiate_req *)buf;
	req->SecurityMode = cpu_to_le16(0x0002); /* Wrong mode */

	ret = test_validate_negotiate(&ctx, buf, req_len, sizeof(rsp),
				      &rsp, &out_len, &status, &term);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_TRUE(test, term);
}

static void test_validate_negotiate_capabilities_mismatch(struct kunit *test)
{
	struct test_vneg_ctx ctx = default_vneg_ctx();
	struct test_validate_negotiate_rsp rsp;
	unsigned int out_len, req_len;
	__le32 status;
	bool term;
	void *buf;
	struct test_validate_negotiate_req *req;
	int ret;

	buf = build_vneg_req(test, &ctx, 1, &req_len);
	req = (struct test_validate_negotiate_req *)buf;
	req->Capabilities = cpu_to_le32(0xDEADBEEF); /* Wrong caps */

	ret = test_validate_negotiate(&ctx, buf, req_len, sizeof(rsp),
				      &rsp, &out_len, &status, &term);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_TRUE(test, term);
}

static void test_validate_negotiate_input_too_small(struct kunit *test)
{
	struct test_vneg_ctx ctx = default_vneg_ctx();
	struct test_validate_negotiate_rsp rsp;
	unsigned int out_len;
	__le32 status;
	bool term;
	u8 small[3];
	int ret;

	memset(small, 0, sizeof(small));
	ret = test_validate_negotiate(&ctx, small, sizeof(small), sizeof(rsp),
				      &rsp, &out_len, &status, &term);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_validate_negotiate_output_too_small(struct kunit *test)
{
	struct test_vneg_ctx ctx = default_vneg_ctx();
	struct test_validate_negotiate_rsp rsp;
	unsigned int out_len, req_len;
	__le32 status;
	bool term;
	void *buf;
	int ret;

	buf = build_vneg_req(test, &ctx, 1, &req_len);
	ret = test_validate_negotiate(&ctx, buf, req_len, sizeof(rsp) - 1,
				      &rsp, &out_len, &status, &term);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_BUFFER_TOO_SMALL);
}

static void test_validate_negotiate_dialect_count_overflow(struct kunit *test)
{
	struct test_vneg_ctx ctx = default_vneg_ctx();
	struct test_validate_negotiate_rsp rsp;
	unsigned int out_len, req_len;
	__le32 status;
	bool term;
	void *buf;
	struct test_validate_negotiate_req *req;
	int ret;

	/* Build with 1 dialect but claim 100 */
	buf = build_vneg_req(test, &ctx, 1, &req_len);
	req = (struct test_validate_negotiate_req *)buf;
	req->DialectCount = cpu_to_le16(100);

	ret = test_validate_negotiate(&ctx, buf, req_len, sizeof(rsp),
				      &rsp, &out_len, &status, &term);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_validate_negotiate_response_fields(struct kunit *test)
{
	struct test_vneg_ctx ctx = default_vneg_ctx();
	struct test_validate_negotiate_rsp rsp;
	unsigned int out_len, req_len;
	__le32 status;
	bool term;
	void *buf;
	int ret;

	buf = build_vneg_req(test, &ctx, 1, &req_len);
	ret = test_validate_negotiate(&ctx, buf, req_len, sizeof(rsp),
				      &rsp, &out_len, &status, &term);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, rsp.Capabilities, ctx.server_caps);
	KUNIT_EXPECT_EQ(test, rsp.SecurityMode, ctx.server_sec_mode);
	KUNIT_EXPECT_EQ(test, rsp.Dialect, ctx.server_dialect);
	KUNIT_EXPECT_EQ(test, memcmp(rsp.Guid, ctx.server_guid, 16), 0);
}

static struct kunit_case ksmbd_fsctl_vneg_test_cases[] = {
	KUNIT_CASE(test_validate_negotiate_success),
	KUNIT_CASE(test_validate_negotiate_dialect_mismatch),
	KUNIT_CASE(test_validate_negotiate_guid_mismatch),
	KUNIT_CASE(test_validate_negotiate_security_mode_mismatch),
	KUNIT_CASE(test_validate_negotiate_capabilities_mismatch),
	KUNIT_CASE(test_validate_negotiate_input_too_small),
	KUNIT_CASE(test_validate_negotiate_output_too_small),
	KUNIT_CASE(test_validate_negotiate_dialect_count_overflow),
	KUNIT_CASE(test_validate_negotiate_response_fields),
	{}
};

static struct kunit_suite ksmbd_fsctl_vneg_test_suite = {
	.name = "ksmbd_fsctl_validate_negotiate",
	.test_cases = ksmbd_fsctl_vneg_test_cases,
};

kunit_test_suite(ksmbd_fsctl_vneg_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL validate negotiate info");
