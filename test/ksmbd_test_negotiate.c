// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 negotiate functions (smb2_negotiate.c)
 *
 *   Tests the exported smb3_encryption_negotiated() by calling the
 *   actual production function. For static helpers (decode_preauth_ctxt,
 *   decode_encrypt_ctxt, decode_compress_ctxt, decode_sign_cap_ctxt,
 *   decode_transport_cap_ctxt, decode_rdma_transform_ctxt,
 *   deassemble_neg_contexts), we replicate their logic here since they
 *   cannot be called directly. The replicated logic must stay in sync
 *   with smb2_negotiate.c.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/overflow.h>

#include "smb2pdu.h"
#include "smbstatus.h"
#include "smb_common.h"
#include "connection.h"
#include "server.h"
#include "ksmbd_netlink.h"

/* ===== Replicated static helpers from smb2_negotiate.c ===== */

/*
 * Replicate decode_preauth_ctxt() from smb2_negotiate.c.
 * Must stay in sync with production code.
 */
static __le32 test_decode_preauth_ctxt(struct ksmbd_conn *conn,
				       struct smb2_preauth_neg_context *pneg_ctxt,
				       int ctxt_len)
{
	int hash_count;

	if (ctxt_len <
	    (int)(sizeof(struct smb2_neg_context) + MIN_PREAUTH_CTXT_DATA_LEN))
		return STATUS_INVALID_PARAMETER;

	hash_count = le16_to_cpu(pneg_ctxt->HashAlgorithmCount);
	if (hash_count == 0)
		return STATUS_INVALID_PARAMETER;

	if (pneg_ctxt->HashAlgorithms == SMB2_PREAUTH_INTEGRITY_SHA512) {
		conn->preauth_info->Preauth_HashId =
			SMB2_PREAUTH_INTEGRITY_SHA512;
		return STATUS_SUCCESS;
	}

	return STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP;
}

/*
 * Replicate decode_encrypt_ctxt() from smb2_negotiate.c.
 */
static void test_decode_encrypt_ctxt(struct ksmbd_conn *conn,
				     struct smb2_encryption_neg_context *pneg_ctxt,
				     int ctxt_len)
{
	int cph_cnt;
	size_t cphs_size;

	if (sizeof(struct smb2_encryption_neg_context) > (size_t)ctxt_len)
		return;

	conn->cipher_type = 0;

	cph_cnt = le16_to_cpu(pneg_ctxt->CipherCount);
	if (check_mul_overflow((size_t)cph_cnt, sizeof(__le16), &cphs_size))
		return;

	if (sizeof(struct smb2_encryption_neg_context) + cphs_size >
	    (size_t)ctxt_len)
		return;

	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF)
		return;

	/* Server preference: AES-256-GCM > AES-128-GCM > AES-256-CCM > AES-128-CCM */
	{
		static const __le16 server_cipher_pref[] = {
			SMB2_ENCRYPTION_AES256_GCM,
			SMB2_ENCRYPTION_AES128_GCM,
			SMB2_ENCRYPTION_AES256_CCM,
			SMB2_ENCRYPTION_AES128_CCM,
		};
		int p, j;

		for (p = 0; p < (int)ARRAY_SIZE(server_cipher_pref); p++) {
			for (j = 0; j < cph_cnt; j++) {
				if (pneg_ctxt->Ciphers[j] ==
				    server_cipher_pref[p]) {
					conn->cipher_type =
						server_cipher_pref[p];
					return;
				}
			}
		}
	}
}

/*
 * Replicate decode_compress_ctxt() from smb2_negotiate.c.
 */
static __le32 test_decode_compress_ctxt(struct ksmbd_conn *conn,
					struct smb2_compression_ctx *pneg_ctxt,
					int ctxt_len)
{
	int algo_cnt, i;
	size_t algos_size;

	conn->compress_algorithm = SMB3_COMPRESS_NONE;

	if (sizeof(struct smb2_compression_ctx) > (size_t)ctxt_len)
		return STATUS_INVALID_PARAMETER;

	algo_cnt = le16_to_cpu(pneg_ctxt->CompressionAlgorithmCount);

	if (algo_cnt == 0)
		return STATUS_INVALID_PARAMETER;

	if (check_mul_overflow((size_t)algo_cnt, sizeof(__le16), &algos_size))
		return STATUS_INVALID_PARAMETER;

	if (sizeof(struct smb2_compression_ctx) + algos_size > (size_t)ctxt_len)
		return STATUS_INVALID_PARAMETER;

	for (i = 0; i < algo_cnt; i++) {
		if (pneg_ctxt->CompressionAlgorithms[i] == SMB3_COMPRESS_LZ4) {
			conn->compress_algorithm = SMB3_COMPRESS_LZ4;
			return STATUS_SUCCESS;
		}
	}

	for (i = 0; i < algo_cnt; i++) {
		if (pneg_ctxt->CompressionAlgorithms[i] ==
		    SMB3_COMPRESS_PATTERN_V1) {
			conn->compress_algorithm = SMB3_COMPRESS_PATTERN_V1;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_SUCCESS;
}

/*
 * Replicate decode_sign_cap_ctxt() from smb2_negotiate.c.
 */
static __le32 test_decode_sign_cap_ctxt(struct ksmbd_conn *conn,
					struct smb2_signing_capabilities *pneg_ctxt,
					int ctxt_len)
{
	int sign_algo_cnt;
	int i, sign_alos_size;

	if (sizeof(struct smb2_signing_capabilities) > (size_t)ctxt_len)
		return STATUS_INVALID_PARAMETER;

	conn->signing_negotiated = false;
	sign_algo_cnt = le16_to_cpu(pneg_ctxt->SigningAlgorithmCount);

	if (sign_algo_cnt == 0)
		return STATUS_INVALID_PARAMETER;

	if (check_mul_overflow((int)sign_algo_cnt, (int)sizeof(__le16),
			       &sign_alos_size))
		return STATUS_INVALID_PARAMETER;

	if ((int)sizeof(struct smb2_signing_capabilities) + sign_alos_size >
	    ctxt_len)
		return STATUS_INVALID_PARAMETER;

	conn->signing_negotiated = true;
	conn->signing_algorithm = SIGNING_ALG_AES_CMAC; /* fallback */
	for (i = 0; i < sign_algo_cnt; i++) {
		__le16 alg = pneg_ctxt->SigningAlgorithms[i];

		if (alg == SIGNING_ALG_AES_CMAC ||
		    alg == SIGNING_ALG_HMAC_SHA256) {
			conn->signing_algorithm = alg;
			break;
		}
	}
	return STATUS_SUCCESS;
}

/*
 * Replicate decode_transport_cap_ctxt() from smb2_negotiate.c.
 */
static void test_decode_transport_cap_ctxt(struct ksmbd_conn *conn,
					   struct smb2_transport_capabilities *pneg_ctxt,
					   int ctxt_len)
{
	if (sizeof(struct smb2_transport_capabilities) > (size_t)ctxt_len)
		return;

	if (pneg_ctxt->Flags & SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY)
		conn->transport_secured = true;
}

/*
 * Replicate decode_rdma_transform_ctxt() from smb2_negotiate.c.
 */
static void test_decode_rdma_transform_ctxt(struct ksmbd_conn *conn,
					    struct smb2_rdma_transform_capabilities *pneg_ctxt,
					    int ctxt_len)
{
	int xform_cnt;
	int i, xforms_size;

	if (sizeof(struct smb2_rdma_transform_capabilities) > (size_t)ctxt_len)
		return;

	conn->rdma_transform_count = 0;

	xform_cnt = le16_to_cpu(pneg_ctxt->TransformCount);
	if (xform_cnt == 0)
		return;

	if (check_mul_overflow((int)xform_cnt, (int)sizeof(__le16),
			       &xforms_size))
		return;

	if ((int)sizeof(struct smb2_rdma_transform_capabilities) +
	    xforms_size > ctxt_len)
		return;

	for (i = 0; i < xform_cnt; i++) {
		if (pneg_ctxt->RDMATransformIds[i] == SMB2_RDMA_TRANSFORM_NONE ||
		    pneg_ctxt->RDMATransformIds[i] == SMB2_RDMA_TRANSFORM_ENCRYPTION ||
		    pneg_ctxt->RDMATransformIds[i] == SMB2_RDMA_TRANSFORM_SIGNING) {
			if (conn->rdma_transform_count >=
			    ARRAY_SIZE(conn->rdma_transform_ids))
				break;
			conn->rdma_transform_ids[conn->rdma_transform_count++] =
				pneg_ctxt->RDMATransformIds[i];
		}
	}
}

/* ===== Helper to create a minimal mock connection ===== */

static struct ksmbd_conn *create_mock_conn(void)
{
	struct ksmbd_conn *conn;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return NULL;

	xa_init(&conn->sessions);
	init_rwsem(&conn->session_lock);
	INIT_LIST_HEAD(&conn->preauth_sess_table);

	return conn;
}

static void destroy_mock_conn(struct ksmbd_conn *conn)
{
	if (!conn)
		return;
	kfree(conn->preauth_info);
	kfree(conn->vals);
	xa_destroy(&conn->sessions);
	kfree(conn);
}

/* ===== smb3_encryption_negotiated() tests ===== */

/*
 * test_smb3_encryption_negotiated_no_ops - NULL generate_encryptionkey
 * returns false
 */
static void test_smb3_encryption_negotiated_no_ops(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct smb_version_ops ops;
	struct smb_version_values vals;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(&ops, 0, sizeof(ops));
	memset(&vals, 0, sizeof(vals));
	conn->ops = &ops;
	conn->vals = &vals;
	conn->cipher_type = 0;

	/* No generate_encryptionkey => false */
	KUNIT_EXPECT_FALSE(test, smb3_encryption_negotiated(conn));

	conn->vals = NULL; /* don't double-free */
	destroy_mock_conn(conn);
}

/*
 * test_smb3_encryption_negotiated_cap_flag - CAP_ENCRYPTION set returns true
 */
static void test_smb3_encryption_negotiated_cap_flag(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct smb_version_ops ops;
	struct smb_version_values vals;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(&ops, 0, sizeof(ops));
	memset(&vals, 0, sizeof(vals));
	/* Must have a non-NULL generate_encryptionkey to pass the first check */
	ops.generate_encryptionkey = (void *)1UL; /* dummy non-NULL */
	vals.capabilities = SMB2_GLOBAL_CAP_ENCRYPTION;
	conn->ops = &ops;
	conn->vals = &vals;
	conn->cipher_type = 0;

	KUNIT_EXPECT_TRUE(test, smb3_encryption_negotiated(conn));

	conn->vals = NULL;
	destroy_mock_conn(conn);
}

/*
 * test_smb3_encryption_negotiated_cipher_type - cipher_type set returns true
 */
static void test_smb3_encryption_negotiated_cipher_type(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct smb_version_ops ops;
	struct smb_version_values vals;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(&ops, 0, sizeof(ops));
	memset(&vals, 0, sizeof(vals));
	ops.generate_encryptionkey = (void *)1UL;
	vals.capabilities = 0;
	conn->ops = &ops;
	conn->vals = &vals;
	conn->cipher_type = SMB2_ENCRYPTION_AES128_GCM;

	KUNIT_EXPECT_TRUE(test, smb3_encryption_negotiated(conn));

	conn->vals = NULL;
	destroy_mock_conn(conn);
}

/* ===== decode_preauth_ctxt() tests ===== */

/*
 * test_decode_preauth_ctxt_valid - valid SHA-512 context
 */
static void test_decode_preauth_ctxt_valid(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct smb2_preauth_neg_context ctx;
	struct preauth_integrity_info preauth_info;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(&preauth_info, 0, sizeof(preauth_info));
	conn->preauth_info = &preauth_info;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctx.DataLength = cpu_to_le16(38);
	ctx.HashAlgorithmCount = cpu_to_le16(1);
	ctx.HashAlgorithms = SMB2_PREAUTH_INTEGRITY_SHA512;

	status = test_decode_preauth_ctxt(conn, &ctx, sizeof(ctx));

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_SUCCESS, status);
	KUNIT_EXPECT_EQ(test, conn->preauth_info->Preauth_HashId,
			(__le16)SMB2_PREAUTH_INTEGRITY_SHA512);

	conn->preauth_info = NULL; /* stack-allocated, don't free */
	destroy_mock_conn(conn);
}

/*
 * test_decode_preauth_ctxt_too_short - truncated context
 */
static void test_decode_preauth_ctxt_too_short(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct smb2_preauth_neg_context ctx;
	struct preauth_integrity_info preauth_info;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(&preauth_info, 0, sizeof(preauth_info));
	conn->preauth_info = &preauth_info;
	memset(&ctx, 0, sizeof(ctx));

	/* Pass ctxt_len smaller than minimum */
	status = test_decode_preauth_ctxt(conn, &ctx, 4);

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_INVALID_PARAMETER, status);

	conn->preauth_info = NULL;
	destroy_mock_conn(conn);
}

/*
 * test_decode_preauth_ctxt_zero_hash_count - HashAlgorithmCount = 0
 */
static void test_decode_preauth_ctxt_zero_hash_count(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct smb2_preauth_neg_context ctx;
	struct preauth_integrity_info preauth_info;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(&preauth_info, 0, sizeof(preauth_info));
	conn->preauth_info = &preauth_info;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctx.DataLength = cpu_to_le16(38);
	ctx.HashAlgorithmCount = cpu_to_le16(0);

	status = test_decode_preauth_ctxt(conn, &ctx, sizeof(ctx));

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_INVALID_PARAMETER, status);

	conn->preauth_info = NULL;
	destroy_mock_conn(conn);
}

/*
 * test_decode_preauth_ctxt_unknown_hash - unsupported hash algorithm
 */
static void test_decode_preauth_ctxt_unknown_hash(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct smb2_preauth_neg_context ctx;
	struct preauth_integrity_info preauth_info;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(&preauth_info, 0, sizeof(preauth_info));
	conn->preauth_info = &preauth_info;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctx.DataLength = cpu_to_le16(38);
	ctx.HashAlgorithmCount = cpu_to_le16(1);
	ctx.HashAlgorithms = cpu_to_le16(0xFFFF); /* unsupported */

	status = test_decode_preauth_ctxt(conn, &ctx, sizeof(ctx));

	KUNIT_EXPECT_EQ(test,
			(__le32)STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP,
			status);

	conn->preauth_info = NULL;
	destroy_mock_conn(conn);
}

/* ===== decode_encrypt_ctxt() tests ===== */

/*
 * test_decode_encrypt_ctxt_aes128_gcm - client offers AES-128-GCM only
 */
static void test_decode_encrypt_ctxt_aes128_gcm(struct kunit *test)
{
	struct ksmbd_conn *conn;
	/* Allocate context with room for 1 cipher */
	char buf[sizeof(struct smb2_encryption_neg_context) + sizeof(__le16)];
	struct smb2_encryption_neg_context *ctx =
		(struct smb2_encryption_neg_context *)buf;
	unsigned int saved_flags;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	/* Ensure encryption is not disabled */
	saved_flags = server_conf.flags;
	server_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF;

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_ENCRYPTION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(4);
	ctx->CipherCount = cpu_to_le16(1);
	ctx->Ciphers[0] = SMB2_ENCRYPTION_AES128_GCM;

	test_decode_encrypt_ctxt(conn, ctx, sizeof(buf));

	KUNIT_EXPECT_EQ(test, conn->cipher_type,
			(__le16)SMB2_ENCRYPTION_AES128_GCM);

	server_conf.flags = saved_flags;
	destroy_mock_conn(conn);
}

/*
 * test_decode_encrypt_ctxt_server_preference - server prefers GCM over CCM
 */
static void test_decode_encrypt_ctxt_server_preference(struct kunit *test)
{
	struct ksmbd_conn *conn;
	/* Allocate context with room for 2 ciphers */
	char buf[sizeof(struct smb2_encryption_neg_context) + 2 * sizeof(__le16)];
	struct smb2_encryption_neg_context *ctx =
		(struct smb2_encryption_neg_context *)buf;
	unsigned int saved_flags;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	saved_flags = server_conf.flags;
	server_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF;

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_ENCRYPTION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(6); /* 2 + 2*2 */
	ctx->CipherCount = cpu_to_le16(2);
	/* Client sends CCM first, then GCM */
	ctx->Ciphers[0] = SMB2_ENCRYPTION_AES128_CCM;
	ctx->Ciphers[1] = SMB2_ENCRYPTION_AES128_GCM;

	test_decode_encrypt_ctxt(conn, ctx, sizeof(buf));

	/*
	 * Server prefers AES-256-GCM > AES-128-GCM > AES-256-CCM > AES-128-CCM
	 * Since AES-128-GCM is offered, it should be selected over AES-128-CCM
	 */
	KUNIT_EXPECT_EQ(test, conn->cipher_type,
			(__le16)SMB2_ENCRYPTION_AES128_GCM);

	server_conf.flags = saved_flags;
	destroy_mock_conn(conn);
}

/*
 * test_decode_encrypt_ctxt_cipher_count_overflow - CipherCount causes overflow
 */
static void test_decode_encrypt_ctxt_cipher_count_overflow(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_encryption_neg_context) + sizeof(__le16)];
	struct smb2_encryption_neg_context *ctx =
		(struct smb2_encryption_neg_context *)buf;
	unsigned int saved_flags;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	saved_flags = server_conf.flags;
	server_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF;

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_ENCRYPTION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(4);
	/* Claim huge cipher count but actual buffer is tiny */
	ctx->CipherCount = cpu_to_le16(0x7FFF);
	ctx->Ciphers[0] = SMB2_ENCRYPTION_AES128_GCM;

	test_decode_encrypt_ctxt(conn, ctx, sizeof(buf));

	/* cipher_type should remain 0 (no cipher selected) */
	KUNIT_EXPECT_EQ(test, conn->cipher_type, (__le16)0);

	server_conf.flags = saved_flags;
	destroy_mock_conn(conn);
}

/*
 * test_decode_encrypt_ctxt_encryption_disabled - ENCRYPTION_OFF flag
 */
static void test_decode_encrypt_ctxt_encryption_disabled(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_encryption_neg_context) + sizeof(__le16)];
	struct smb2_encryption_neg_context *ctx =
		(struct smb2_encryption_neg_context *)buf;
	unsigned int saved_flags;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	saved_flags = server_conf.flags;
	server_conf.flags |= KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF;

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_ENCRYPTION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(4);
	ctx->CipherCount = cpu_to_le16(1);
	ctx->Ciphers[0] = SMB2_ENCRYPTION_AES128_GCM;

	test_decode_encrypt_ctxt(conn, ctx, sizeof(buf));

	/* cipher_type should remain 0 when encryption is admin-disabled */
	KUNIT_EXPECT_EQ(test, conn->cipher_type, (__le16)0);

	server_conf.flags = saved_flags;
	destroy_mock_conn(conn);
}

/* ===== decode_compress_ctxt() tests ===== */

/*
 * test_decode_compress_ctxt_zero_count - CompressionAlgorithmCount = 0
 */
static void test_decode_compress_ctxt_zero_count(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_compression_ctx) + sizeof(__le16)];
	struct smb2_compression_ctx *ctx =
		(struct smb2_compression_ctx *)buf;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_COMPRESSION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(10);
	ctx->CompressionAlgorithmCount = cpu_to_le16(0);

	status = test_decode_compress_ctxt(conn, ctx, sizeof(buf));

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_INVALID_PARAMETER, status);

	destroy_mock_conn(conn);
}

/*
 * test_decode_compress_ctxt_lz4 - client offers LZ4
 */
static void test_decode_compress_ctxt_lz4(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_compression_ctx) + sizeof(__le16)];
	struct smb2_compression_ctx *ctx =
		(struct smb2_compression_ctx *)buf;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_COMPRESSION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(10);
	ctx->CompressionAlgorithmCount = cpu_to_le16(1);
	ctx->CompressionAlgorithms[0] = SMB3_COMPRESS_LZ4;

	status = test_decode_compress_ctxt(conn, ctx, sizeof(buf));

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_SUCCESS, status);
	KUNIT_EXPECT_EQ(test, conn->compress_algorithm,
			(__le16)SMB3_COMPRESS_LZ4);

	destroy_mock_conn(conn);
}

/*
 * test_decode_compress_ctxt_pattern_v1 - client offers Pattern_V1
 */
static void test_decode_compress_ctxt_pattern_v1(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_compression_ctx) + sizeof(__le16)];
	struct smb2_compression_ctx *ctx =
		(struct smb2_compression_ctx *)buf;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_COMPRESSION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(10);
	ctx->CompressionAlgorithmCount = cpu_to_le16(1);
	ctx->CompressionAlgorithms[0] = SMB3_COMPRESS_PATTERN_V1;

	status = test_decode_compress_ctxt(conn, ctx, sizeof(buf));

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_SUCCESS, status);
	KUNIT_EXPECT_EQ(test, conn->compress_algorithm,
			(__le16)SMB3_COMPRESS_PATTERN_V1);

	destroy_mock_conn(conn);
}

/*
 * test_decode_compress_ctxt_no_supported - unsupported algorithms only
 */
static void test_decode_compress_ctxt_no_supported(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_compression_ctx) + sizeof(__le16)];
	struct smb2_compression_ctx *ctx =
		(struct smb2_compression_ctx *)buf;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_COMPRESSION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(10);
	ctx->CompressionAlgorithmCount = cpu_to_le16(1);
	ctx->CompressionAlgorithms[0] = SMB3_COMPRESS_LZNT1; /* Not fully supported */

	status = test_decode_compress_ctxt(conn, ctx, sizeof(buf));

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_SUCCESS, status);
	KUNIT_EXPECT_EQ(test, conn->compress_algorithm,
			(__le16)SMB3_COMPRESS_NONE);

	destroy_mock_conn(conn);
}

/* ===== decode_sign_cap_ctxt() tests ===== */

/*
 * test_decode_sign_cap_ctxt_zero_count - SigningAlgorithmCount = 0
 */
static void test_decode_sign_cap_ctxt_zero_count(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_signing_capabilities) + sizeof(__le16)];
	struct smb2_signing_capabilities *ctx =
		(struct smb2_signing_capabilities *)buf;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_SIGNING_CAPABILITIES;
	ctx->SigningAlgorithmCount = cpu_to_le16(0);

	status = test_decode_sign_cap_ctxt(conn, ctx, sizeof(buf));

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_INVALID_PARAMETER, status);

	destroy_mock_conn(conn);
}

/*
 * test_decode_sign_cap_ctxt_aes_cmac - AES-CMAC offered
 */
static void test_decode_sign_cap_ctxt_aes_cmac(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_signing_capabilities) + sizeof(__le16)];
	struct smb2_signing_capabilities *ctx =
		(struct smb2_signing_capabilities *)buf;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_SIGNING_CAPABILITIES;
	ctx->SigningAlgorithmCount = cpu_to_le16(1);
	ctx->SigningAlgorithms[0] = SIGNING_ALG_AES_CMAC;

	status = test_decode_sign_cap_ctxt(conn, ctx, sizeof(buf));

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_SUCCESS, status);
	KUNIT_EXPECT_TRUE(test, conn->signing_negotiated);
	KUNIT_EXPECT_EQ(test, conn->signing_algorithm,
			(__le16)SIGNING_ALG_AES_CMAC);

	destroy_mock_conn(conn);
}

/*
 * test_decode_sign_cap_ctxt_hmac_sha256 - HMAC-SHA256 offered
 */
static void test_decode_sign_cap_ctxt_hmac_sha256(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_signing_capabilities) + sizeof(__le16)];
	struct smb2_signing_capabilities *ctx =
		(struct smb2_signing_capabilities *)buf;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_SIGNING_CAPABILITIES;
	ctx->SigningAlgorithmCount = cpu_to_le16(1);
	ctx->SigningAlgorithms[0] = SIGNING_ALG_HMAC_SHA256;

	status = test_decode_sign_cap_ctxt(conn, ctx, sizeof(buf));

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_SUCCESS, status);
	KUNIT_EXPECT_TRUE(test, conn->signing_negotiated);
	KUNIT_EXPECT_EQ(test, conn->signing_algorithm,
			(__le16)SIGNING_ALG_HMAC_SHA256);

	destroy_mock_conn(conn);
}

/*
 * test_decode_sign_cap_ctxt_no_overlap_fallback - only GMAC offered (no overlap)
 * Must fall back to AES-CMAC
 */
static void test_decode_sign_cap_ctxt_no_overlap_fallback(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_signing_capabilities) + sizeof(__le16)];
	struct smb2_signing_capabilities *ctx =
		(struct smb2_signing_capabilities *)buf;
	__le32 status;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_SIGNING_CAPABILITIES;
	ctx->SigningAlgorithmCount = cpu_to_le16(1);
	ctx->SigningAlgorithms[0] = SIGNING_ALG_AES_GMAC; /* Not accepted */

	status = test_decode_sign_cap_ctxt(conn, ctx, sizeof(buf));

	KUNIT_EXPECT_EQ(test, (__le32)STATUS_SUCCESS, status);
	KUNIT_EXPECT_TRUE(test, conn->signing_negotiated);
	/* Falls back to AES-CMAC when no overlap found */
	KUNIT_EXPECT_EQ(test, conn->signing_algorithm,
			(__le16)SIGNING_ALG_AES_CMAC);

	destroy_mock_conn(conn);
}

/* ===== decode_transport_cap_ctxt() tests ===== */

/*
 * test_decode_transport_cap_ctxt_supported - transport security accepted
 */
static void test_decode_transport_cap_ctxt_supported(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct smb2_transport_capabilities ctx;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	conn->transport_secured = false;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextType = SMB2_TRANSPORT_CAPABILITIES;
	ctx.Flags = SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY;

	test_decode_transport_cap_ctxt(conn, &ctx, sizeof(ctx));

	KUNIT_EXPECT_TRUE(test, conn->transport_secured);

	destroy_mock_conn(conn);
}

/*
 * test_decode_transport_cap_ctxt_too_short - truncated context ignored
 */
static void test_decode_transport_cap_ctxt_too_short(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct smb2_transport_capabilities ctx;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	conn->transport_secured = false;

	memset(&ctx, 0, sizeof(ctx));
	ctx.Flags = SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY;

	/* Pass too small length */
	test_decode_transport_cap_ctxt(conn, &ctx, 4);

	/* Should not have been set */
	KUNIT_EXPECT_FALSE(test, conn->transport_secured);

	destroy_mock_conn(conn);
}

/* ===== decode_rdma_transform_ctxt() tests ===== */

/*
 * test_decode_rdma_transform_ctxt_valid - accepts known transforms
 */
static void test_decode_rdma_transform_ctxt_valid(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_rdma_transform_capabilities) +
		 3 * sizeof(__le16)];
	struct smb2_rdma_transform_capabilities *ctx =
		(struct smb2_rdma_transform_capabilities *)buf;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_RDMA_TRANSFORM_CAPABILITIES;
	ctx->TransformCount = cpu_to_le16(3);
	ctx->RDMATransformIds[0] = SMB2_RDMA_TRANSFORM_NONE;
	ctx->RDMATransformIds[1] = SMB2_RDMA_TRANSFORM_ENCRYPTION;
	ctx->RDMATransformIds[2] = SMB2_RDMA_TRANSFORM_SIGNING;

	test_decode_rdma_transform_ctxt(conn, ctx, sizeof(buf));

	KUNIT_EXPECT_EQ(test, conn->rdma_transform_count, 3U);
	KUNIT_EXPECT_EQ(test, conn->rdma_transform_ids[0],
			(__le16)SMB2_RDMA_TRANSFORM_NONE);
	KUNIT_EXPECT_EQ(test, conn->rdma_transform_ids[1],
			(__le16)SMB2_RDMA_TRANSFORM_ENCRYPTION);
	KUNIT_EXPECT_EQ(test, conn->rdma_transform_ids[2],
			(__le16)SMB2_RDMA_TRANSFORM_SIGNING);

	destroy_mock_conn(conn);
}

/*
 * test_decode_rdma_transform_ctxt_zero_count - TransformCount = 0
 */
static void test_decode_rdma_transform_ctxt_zero_count(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct smb2_rdma_transform_capabilities ctx;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextType = SMB2_RDMA_TRANSFORM_CAPABILITIES;
	ctx.TransformCount = cpu_to_le16(0);

	test_decode_rdma_transform_ctxt(conn, &ctx, sizeof(ctx));

	KUNIT_EXPECT_EQ(test, conn->rdma_transform_count, 0U);

	destroy_mock_conn(conn);
}

/* ===== Cipher server preference order test ===== */

/*
 * test_cipher_preference_aes256_gcm_first - AES-256-GCM has highest priority
 */
static void test_cipher_preference_aes256_gcm_first(struct kunit *test)
{
	struct ksmbd_conn *conn;
	char buf[sizeof(struct smb2_encryption_neg_context) + 4 * sizeof(__le16)];
	struct smb2_encryption_neg_context *ctx =
		(struct smb2_encryption_neg_context *)buf;
	unsigned int saved_flags;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	saved_flags = server_conf.flags;
	server_conf.flags &= ~KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF;

	memset(buf, 0, sizeof(buf));
	ctx->ContextType = SMB2_ENCRYPTION_CAPABILITIES;
	ctx->DataLength = cpu_to_le16(2 + 4 * 2); /* CipherCount + 4 ciphers */
	ctx->CipherCount = cpu_to_le16(4);
	/* Client offers all 4 ciphers in reverse preference order */
	ctx->Ciphers[0] = SMB2_ENCRYPTION_AES128_CCM;
	ctx->Ciphers[1] = SMB2_ENCRYPTION_AES256_CCM;
	ctx->Ciphers[2] = SMB2_ENCRYPTION_AES128_GCM;
	ctx->Ciphers[3] = SMB2_ENCRYPTION_AES256_GCM;

	test_decode_encrypt_ctxt(conn, ctx, sizeof(buf));

	/* Server picks AES-256-GCM (highest preference) */
	KUNIT_EXPECT_EQ(test, conn->cipher_type,
			(__le16)SMB2_ENCRYPTION_AES256_GCM);

	server_conf.flags = saved_flags;
	destroy_mock_conn(conn);
}

/* ===== Constants and structural tests ===== */

/*
 * test_negotiate_context_type_values - verify context type constants
 */
static void test_negotiate_context_type_values(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_PREAUTH_INTEGRITY_CAPABILITIES),
			1);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_ENCRYPTION_CAPABILITIES), 2);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_COMPRESSION_CAPABILITIES), 3);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_NETNAME_NEGOTIATE_CONTEXT_ID),
			5);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_TRANSPORT_CAPABILITIES), 6);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_RDMA_TRANSFORM_CAPABILITIES),
			7);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_SIGNING_CAPABILITIES), 8);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_POSIX_EXTENSIONS_AVAILABLE),
			0x100);
}

/*
 * test_signing_algorithm_constants - verify signing algorithm IDs
 */
static void test_signing_algorithm_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SIGNING_ALG_HMAC_SHA256), 0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SIGNING_ALG_AES_CMAC), 1);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SIGNING_ALG_AES_GMAC), 2);
}

/*
 * test_cipher_type_constants - verify cipher type IDs
 */
static void test_cipher_type_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_ENCRYPTION_AES128_CCM), 0x0001);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_ENCRYPTION_AES128_GCM), 0x0002);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_ENCRYPTION_AES256_CCM), 0x0003);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_ENCRYPTION_AES256_GCM), 0x0004);
}

/*
 * test_compression_algorithm_constants - verify compression algorithm IDs
 */
static void test_compression_algorithm_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB3_COMPRESS_NONE), 0x0000);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB3_COMPRESS_LZNT1), 0x0001);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB3_COMPRESS_LZ77), 0x0002);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB3_COMPRESS_LZ77_HUFF), 0x0003);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB3_COMPRESS_PATTERN_V1), 0x0004);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB3_COMPRESS_LZ4), 0x0005);
}

static struct kunit_case ksmbd_negotiate_test_cases[] = {
	/* smb3_encryption_negotiated() */
	KUNIT_CASE(test_smb3_encryption_negotiated_no_ops),
	KUNIT_CASE(test_smb3_encryption_negotiated_cap_flag),
	KUNIT_CASE(test_smb3_encryption_negotiated_cipher_type),
	/* decode_preauth_ctxt() */
	KUNIT_CASE(test_decode_preauth_ctxt_valid),
	KUNIT_CASE(test_decode_preauth_ctxt_too_short),
	KUNIT_CASE(test_decode_preauth_ctxt_zero_hash_count),
	KUNIT_CASE(test_decode_preauth_ctxt_unknown_hash),
	/* decode_encrypt_ctxt() */
	KUNIT_CASE(test_decode_encrypt_ctxt_aes128_gcm),
	KUNIT_CASE(test_decode_encrypt_ctxt_server_preference),
	KUNIT_CASE(test_decode_encrypt_ctxt_cipher_count_overflow),
	KUNIT_CASE(test_decode_encrypt_ctxt_encryption_disabled),
	/* decode_compress_ctxt() */
	KUNIT_CASE(test_decode_compress_ctxt_zero_count),
	KUNIT_CASE(test_decode_compress_ctxt_lz4),
	KUNIT_CASE(test_decode_compress_ctxt_pattern_v1),
	KUNIT_CASE(test_decode_compress_ctxt_no_supported),
	/* decode_sign_cap_ctxt() */
	KUNIT_CASE(test_decode_sign_cap_ctxt_zero_count),
	KUNIT_CASE(test_decode_sign_cap_ctxt_aes_cmac),
	KUNIT_CASE(test_decode_sign_cap_ctxt_hmac_sha256),
	KUNIT_CASE(test_decode_sign_cap_ctxt_no_overlap_fallback),
	/* decode_transport_cap_ctxt() */
	KUNIT_CASE(test_decode_transport_cap_ctxt_supported),
	KUNIT_CASE(test_decode_transport_cap_ctxt_too_short),
	/* decode_rdma_transform_ctxt() */
	KUNIT_CASE(test_decode_rdma_transform_ctxt_valid),
	KUNIT_CASE(test_decode_rdma_transform_ctxt_zero_count),
	/* Cipher preference order */
	KUNIT_CASE(test_cipher_preference_aes256_gcm_first),
	/* Constants validation */
	KUNIT_CASE(test_negotiate_context_type_values),
	KUNIT_CASE(test_signing_algorithm_constants),
	KUNIT_CASE(test_cipher_type_constants),
	KUNIT_CASE(test_compression_algorithm_constants),
	{}
};

static struct kunit_suite ksmbd_negotiate_test_suite = {
	.name = "ksmbd_negotiate",
	.test_cases = ksmbd_negotiate_test_cases,
};

kunit_test_suite(ksmbd_negotiate_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 negotiate protocol");
