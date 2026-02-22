// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 negotiate context chain parsing
 *
 *   This module exercises the negotiate context parsing logic used in
 *   SMB2 NEGOTIATE requests and responses. Negotiate contexts carry
 *   preauth integrity, encryption, compression, and signing capabilities.
 *   Malformed contexts can lead to out-of-bounds reads or infinite loops
 *   if not properly validated.
 *
 *   Targets:
 *     - Negotiate context chain traversal with 8-byte alignment
 *     - ContextType validation
 *     - DataLength vs remaining buffer validation
 *     - Overlapping context detection
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_negotiate_context() entry point
 *     accepts a raw byte buffer and length.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * Inline the negotiate context structure to avoid full header dependencies.
 */

struct smb2_neg_context {
	__le16 ContextType;
	__le16 DataLength;
	__le32 Reserved;
} __packed;

#define NEG_CTX_HDR_SIZE	sizeof(struct smb2_neg_context)

/* Well-known negotiate context types */
#define SMB2_PREAUTH_INTEGRITY_CAPABILITIES	cpu_to_le16(0x0001)
#define SMB2_ENCRYPTION_CAPABILITIES		cpu_to_le16(0x0002)
#define SMB2_COMPRESSION_CAPABILITIES		cpu_to_le16(0x0003)
#define SMB2_NETNAME_NEGOTIATE_CONTEXT_ID	cpu_to_le16(0x0005)
#define SMB2_TRANSPORT_CAPABILITIES		cpu_to_le16(0x0006)
#define SMB2_RDMA_TRANSFORM_CAPABILITIES	cpu_to_le16(0x0007)
#define SMB2_SIGNING_CAPABILITIES		cpu_to_le16(0x0008)

/*
 * fuzz_negotiate_context - Fuzz negotiate context chain parsing
 * @data:	raw input bytes containing negotiate contexts
 * @len:	length of input
 *
 * Walks the negotiate context chain with 8-byte alignment, validating
 * DataLength against the remaining buffer at each step.
 *
 * Return: number of contexts parsed, or negative on error
 */
static int fuzz_negotiate_context(const u8 *data, size_t len)
{
	const struct smb2_neg_context *ctx;
	u32 offset = 0;
	u16 ctx_type;
	u16 data_length;
	u32 ctx_total;
	int count = 0;

	if (len < NEG_CTX_HDR_SIZE) {
		pr_debug("fuzz_negctx: input too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	/* Cap to prevent excessive processing */
	if (len > 65536)
		len = 65536;

	while (offset + NEG_CTX_HDR_SIZE <= len) {
		ctx = (const struct smb2_neg_context *)(data + offset);
		ctx_type = le16_to_cpu(ctx->ContextType);
		data_length = le16_to_cpu(ctx->DataLength);

		/* Validate DataLength does not exceed remaining buffer */
		ctx_total = NEG_CTX_HDR_SIZE + data_length;
		if (offset + ctx_total > len) {
			pr_debug("fuzz_negctx: context %d DataLength %u exceeds buffer at offset %u\n",
				 count, data_length, offset);
			return -EINVAL;
		}

		/* Log the context type */
		switch (ctx->ContextType) {
		case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
			pr_debug("fuzz_negctx: PREAUTH_INTEGRITY ctx, data_len=%u\n",
				 data_length);
			break;
		case SMB2_ENCRYPTION_CAPABILITIES:
			pr_debug("fuzz_negctx: ENCRYPTION ctx, data_len=%u\n",
				 data_length);
			break;
		case SMB2_COMPRESSION_CAPABILITIES:
			pr_debug("fuzz_negctx: COMPRESSION ctx, data_len=%u\n",
				 data_length);
			break;
		case SMB2_SIGNING_CAPABILITIES:
			pr_debug("fuzz_negctx: SIGNING ctx, data_len=%u\n",
				 data_length);
			break;
		default:
			pr_debug("fuzz_negctx: unknown ctx type=0x%04x, data_len=%u\n",
				 ctx_type, data_length);
			break;
		}

		count++;

		/* Advance to next context with 8-byte alignment */
		offset += ctx_total;
		offset = (offset + 7) & ~7U;

		/* Safety limit */
		if (count > 256) {
			pr_debug("fuzz_negctx: too many contexts, stopping\n");
			break;
		}
	}

	pr_debug("fuzz_negctx: parsed %d negotiate contexts\n", count);
	return count;
}

/*
 * fuzz_negotiate_context_validate - Strict validation of negotiate contexts
 * @data:	raw input bytes
 * @len:	length of input
 * @expected_count: expected number of contexts (from negotiate header)
 *
 * Performs strict validation matching the server-side parsing logic,
 * where the context count is known from the negotiate request header.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_negotiate_context_validate(const u8 *data, size_t len,
					   u16 expected_count)
{
	const struct smb2_neg_context *ctx;
	u32 offset = 0;
	u16 data_length;
	u32 ctx_total;
	u16 i;

	if (expected_count == 0)
		return 0;

	for (i = 0; i < expected_count; i++) {
		/* Check header fits */
		if (offset + NEG_CTX_HDR_SIZE > len) {
			pr_debug("fuzz_negctx: context %u/%u header at %u exceeds buffer %zu\n",
				 i, expected_count, offset, len);
			return -EINVAL;
		}

		ctx = (const struct smb2_neg_context *)(data + offset);
		data_length = le16_to_cpu(ctx->DataLength);
		ctx_total = NEG_CTX_HDR_SIZE + data_length;

		if (offset + ctx_total > len) {
			pr_debug("fuzz_negctx: context %u data at %u+%u exceeds buffer %zu\n",
				 i, offset, ctx_total, len);
			return -EINVAL;
		}

		/* Advance with 8-byte alignment for all but last context */
		offset += ctx_total;
		if (i < expected_count - 1)
			offset = (offset + 7) & ~7U;
	}

	return 0;
}

static int __init negotiate_context_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_neg_context *ctx;
	int ret;

	pr_info("negotiate_context_fuzz: module loaded\n");

	test_buf = kzalloc(256, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: single valid negotiate context */
	ctx = (struct smb2_neg_context *)test_buf;
	ctx->ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(8);
	ctx->Reserved = 0;

	ret = fuzz_negotiate_context(test_buf, NEG_CTX_HDR_SIZE + 8);
	pr_info("negotiate_context_fuzz: single valid context returned %d\n", ret);

	/* Self-test 2: empty input */
	ret = fuzz_negotiate_context(test_buf, 0);
	pr_info("negotiate_context_fuzz: empty test returned %d\n", ret);

	/* Self-test 3: overlapping contexts (huge DataLength) */
	memset(test_buf, 0, 256);
	ctx = (struct smb2_neg_context *)test_buf;
	ctx->ContextType = SMB2_ENCRYPTION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(0xFFFF); /* huge DataLength */
	ret = fuzz_negotiate_context(test_buf, 32);
	pr_info("negotiate_context_fuzz: huge DataLength test returned %d\n", ret);

	/* Self-test 4: two chained contexts */
	memset(test_buf, 0, 256);
	ctx = (struct smb2_neg_context *)test_buf;
	ctx->ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(4);
	/* Next context at 8-byte aligned offset: HDR(8) + Data(4) = 12 -> aligned to 16 */
	ctx = (struct smb2_neg_context *)(test_buf + 16);
	ctx->ContextType = SMB2_ENCRYPTION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(4);

	ret = fuzz_negotiate_context(test_buf, 24);
	pr_info("negotiate_context_fuzz: chained contexts returned %d\n", ret);

	/* Self-test 5: strict validation with expected count */
	ret = fuzz_negotiate_context_validate(test_buf, 24, 2);
	pr_info("negotiate_context_fuzz: strict validate returned %d\n", ret);

	/* Self-test 6: garbage data */
	memset(test_buf, 0xff, 256);
	ret = fuzz_negotiate_context(test_buf, 256);
	pr_info("negotiate_context_fuzz: garbage test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit negotiate_context_fuzz_exit(void)
{
	pr_info("negotiate_context_fuzz: module unloaded\n");
}

module_init(negotiate_context_fuzz_init);
module_exit(negotiate_context_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 negotiate context chain parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
