// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB2 negotiate context helpers (smb2_negotiate.c)
 *
 *   Tests call real decode_preauth_ctxt(), decode_encrypt_ctxt(),
 *   decode_compress_ctxt(), decode_sign_cap_ctxt() via VISIBLE_IF_KUNIT.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "smbstatus.h"
#include "connection.h"
#include "server.h"
#include "auth.h"

/* Exported under VISIBLE_IF_KUNIT from smb2_negotiate.c. */
__le32 decode_preauth_ctxt(struct ksmbd_conn *conn,
			   struct smb2_preauth_neg_context *pneg_ctxt,
			   int ctxt_len);
void decode_encrypt_ctxt(struct ksmbd_conn *conn,
			 struct smb2_encryption_neg_context *pneg_ctxt,
			 int ctxt_len);
__le32 decode_compress_ctxt(struct ksmbd_conn *conn,
			    struct smb2_compression_ctx *pneg_ctxt,
			    int ctxt_len);
__le32 decode_sign_cap_ctxt(struct ksmbd_conn *conn,
			    struct smb2_signing_capabilities *pneg_ctxt,
			    int ctxt_len);
int assemble_neg_contexts(struct ksmbd_conn *conn,
			  struct smb2_negotiate_rsp *rsp,
			  unsigned int buf_len);

/* --- decode_preauth_ctxt() tests --- */

/*
 * test_preauth_sha512 - SHA-512 is accepted
 */
static void test_preauth_sha512(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct preauth_integrity_info preauth;
	struct smb2_preauth_neg_context ctxt;
	__le32 status;
	int ctxt_len;

	memset(&conn, 0, sizeof(conn));
	memset(&preauth, 0, sizeof(preauth));
	conn.preauth_info = &preauth;

	memset(&ctxt, 0, sizeof(ctxt));
	ctxt.ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctxt.DataLength = cpu_to_le16(sizeof(ctxt) - sizeof(struct smb2_neg_context));
	ctxt.HashAlgorithmCount = cpu_to_le16(1);
	ctxt.HashAlgorithms = SMB2_PREAUTH_INTEGRITY_SHA512;
	ctxt_len = sizeof(ctxt);

	status = decode_preauth_ctxt(&conn, &ctxt, ctxt_len);
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, conn.preauth_info->Preauth_HashId,
			SMB2_PREAUTH_INTEGRITY_SHA512);
}

/*
 * test_preauth_hash_count_zero - HashAlgorithmCount=0 is rejected
 */
static void test_preauth_hash_count_zero(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct preauth_integrity_info preauth;
	struct smb2_preauth_neg_context ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&preauth, 0, sizeof(preauth));
	conn.preauth_info = &preauth;

	memset(&ctxt, 0, sizeof(ctxt));
	ctxt.ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctxt.DataLength = cpu_to_le16(sizeof(ctxt) - sizeof(struct smb2_neg_context));
	ctxt.HashAlgorithmCount = cpu_to_le16(0);
	ctxt.HashAlgorithms = SMB2_PREAUTH_INTEGRITY_SHA512;

	status = decode_preauth_ctxt(&conn, &ctxt, sizeof(ctxt));
	KUNIT_EXPECT_EQ(test, status, STATUS_INVALID_PARAMETER);
}

/*
 * test_preauth_unknown_hash - unknown hash algorithm has no overlap
 */
static void test_preauth_unknown_hash(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct preauth_integrity_info preauth;
	struct smb2_preauth_neg_context ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&preauth, 0, sizeof(preauth));
	conn.preauth_info = &preauth;

	memset(&ctxt, 0, sizeof(ctxt));
	ctxt.ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctxt.DataLength = cpu_to_le16(sizeof(ctxt) - sizeof(struct smb2_neg_context));
	ctxt.HashAlgorithmCount = cpu_to_le16(1);
	ctxt.HashAlgorithms = cpu_to_le16(0xFFFF); /* unknown */

	status = decode_preauth_ctxt(&conn, &ctxt, sizeof(ctxt));
	KUNIT_EXPECT_EQ(test, status, STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP);
}

/*
 * test_preauth_truncated - short context rejected
 */
static void test_preauth_truncated(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct preauth_integrity_info preauth;
	struct smb2_preauth_neg_context ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&preauth, 0, sizeof(preauth));
	conn.preauth_info = &preauth;

	memset(&ctxt, 0, sizeof(ctxt));
	/* Provide a very short context length */
	status = decode_preauth_ctxt(&conn, &ctxt, 4);
	KUNIT_EXPECT_EQ(test, status, STATUS_INVALID_PARAMETER);
}

/* --- decode_sign_cap_ctxt() tests --- */

/*
 * test_sign_cap_aes_cmac - AES-CMAC is selected
 */
static void test_sign_cap_aes_cmac(struct kunit *test)
{
	struct ksmbd_conn conn;
	/* Need room for 1 algorithm entry after the struct */
	struct {
		struct smb2_signing_capabilities cap;
		__le16 alg;
	} __packed ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&ctxt, 0, sizeof(ctxt));

	ctxt.cap.ContextType = SMB2_SIGNING_CAPABILITIES;
	ctxt.cap.DataLength = cpu_to_le16(sizeof(__le16) + sizeof(__le16));
	ctxt.cap.SigningAlgorithmCount = cpu_to_le16(1);
	ctxt.cap.SigningAlgorithms[0] = SIGNING_ALG_AES_CMAC;

	status = decode_sign_cap_ctxt(&conn, &ctxt.cap, sizeof(ctxt));
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);
	KUNIT_EXPECT_TRUE(test, conn.signing_negotiated);
	KUNIT_EXPECT_EQ(test, conn.signing_algorithm, SIGNING_ALG_AES_CMAC);
}

/*
 * test_sign_cap_count_zero - SigningAlgorithmCount=0 is rejected
 */
static void test_sign_cap_count_zero(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_signing_capabilities cap;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&cap, 0, sizeof(cap));

	cap.ContextType = SMB2_SIGNING_CAPABILITIES;
	cap.DataLength = cpu_to_le16(sizeof(__le16));
	cap.SigningAlgorithmCount = cpu_to_le16(0);

	status = decode_sign_cap_ctxt(&conn, &cap, sizeof(cap));
	KUNIT_EXPECT_EQ(test, status, STATUS_INVALID_PARAMETER);
}

/*
 * test_sign_cap_no_overlap_fallback - no overlap falls back to AES-CMAC
 */
static void test_sign_cap_no_overlap_fallback(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct {
		struct smb2_signing_capabilities cap;
		__le16 alg;
	} __packed ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&ctxt, 0, sizeof(ctxt));

	ctxt.cap.ContextType = SMB2_SIGNING_CAPABILITIES;
	ctxt.cap.DataLength = cpu_to_le16(sizeof(__le16) + sizeof(__le16));
	ctxt.cap.SigningAlgorithmCount = cpu_to_le16(1);
	ctxt.cap.SigningAlgorithms[0] = cpu_to_le16(0xFFFF); /* unknown */

	status = decode_sign_cap_ctxt(&conn, &ctxt.cap, sizeof(ctxt));
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);
	KUNIT_EXPECT_TRUE(test, conn.signing_negotiated);
	/* Falls back to AES-CMAC */
	KUNIT_EXPECT_EQ(test, conn.signing_algorithm, SIGNING_ALG_AES_CMAC);
}

/* --- decode_compress_ctxt() tests --- */

/*
 * test_compress_count_zero - CompressionAlgorithmCount=0 is rejected
 */
static void test_compress_count_zero(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_compression_ctx ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&ctxt, 0, sizeof(ctxt));

	ctxt.ContextType = SMB2_COMPRESSION_CAPABILITIES;
	ctxt.DataLength = cpu_to_le16(sizeof(ctxt) - sizeof(struct smb2_neg_context));
	ctxt.CompressionAlgorithmCount = cpu_to_le16(0);

	status = decode_compress_ctxt(&conn, &ctxt, sizeof(ctxt));
	KUNIT_EXPECT_EQ(test, status, STATUS_INVALID_PARAMETER);
}

/*
 * test_compress_truncated - truncated context is rejected
 */
static void test_compress_truncated(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_compression_ctx ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&ctxt, 0, sizeof(ctxt));

	/* Too small context */
	status = decode_compress_ctxt(&conn, &ctxt, 2);
	KUNIT_EXPECT_EQ(test, status, STATUS_INVALID_PARAMETER);
}

static void test_compress_lz4_not_negotiated(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct {
		struct smb2_compression_ctx ctxt;
		__le16 algorithm;
	} __packed buf;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&buf, 0, sizeof(buf));

	buf.ctxt.ContextType = SMB2_COMPRESSION_CAPABILITIES;
	buf.ctxt.DataLength = cpu_to_le16(10);
	buf.ctxt.CompressionAlgorithmCount = cpu_to_le16(1);
	buf.ctxt.CompressionAlgorithms[0] = SMB3_COMPRESS_LZ4;

	status = decode_compress_ctxt(&conn, &buf.ctxt, sizeof(buf));
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, conn.compress_algorithm, SMB3_COMPRESS_NONE);
	KUNIT_EXPECT_EQ(test, conn.compress_algorithm_count, 0U);
}

static void test_compress_common_algorithms_preserve_client_order(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct {
		struct smb2_compression_ctx ctxt;
		__le16 algorithms[4];
	} __packed buf;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&buf, 0, sizeof(buf));

	buf.ctxt.ContextType = SMB2_COMPRESSION_CAPABILITIES;
	buf.ctxt.DataLength = cpu_to_le16(16);
	buf.ctxt.CompressionAlgorithmCount = cpu_to_le16(4);
	buf.ctxt.CompressionAlgorithms[0] = SMB3_COMPRESS_LZNT1;
	buf.ctxt.CompressionAlgorithms[1] = SMB3_COMPRESS_LZ4;
	buf.ctxt.CompressionAlgorithms[2] = SMB3_COMPRESS_LZ77_HUFF;
	buf.ctxt.CompressionAlgorithms[3] = SMB3_COMPRESS_PATTERN_V1;

	status = decode_compress_ctxt(&conn, &buf.ctxt, sizeof(buf));
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, conn.compress_algorithm, SMB3_COMPRESS_LZNT1);
	KUNIT_EXPECT_EQ(test, conn.compress_algorithm_count, 3U);
	KUNIT_EXPECT_EQ(test, conn.compress_algorithms[0], SMB3_COMPRESS_LZNT1);
	KUNIT_EXPECT_EQ(test, conn.compress_algorithms[1], SMB3_COMPRESS_LZ77_HUFF);
	KUNIT_EXPECT_EQ(test, conn.compress_algorithms[2], SMB3_COMPRESS_PATTERN_V1);
}

static struct smb2_neg_context *find_neg_context(void *base, unsigned int len,
						 __le16 type)
{
	char *pos = base;
	unsigned int off = 0;

	while (off + sizeof(struct smb2_neg_context) <= len) {
		struct smb2_neg_context *ctx =
			(struct smb2_neg_context *)(pos + off);
		unsigned int ctx_len;

		ctx_len = sizeof(*ctx) + le16_to_cpu(ctx->DataLength);
		if (ctx->ContextType == type)
			return ctx;
		off += round_up(ctx_len, 8);
	}

	return NULL;
}

static void test_assemble_transport_context_only_for_secure_transport(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct preauth_integrity_info preauth;
	u8 rsp_buf[512];
	struct smb2_negotiate_rsp *rsp = (struct smb2_negotiate_rsp *)rsp_buf;
	unsigned int ctx_bytes;
	int rc;

	memset(&conn, 0, sizeof(conn));
	memset(&preauth, 0, sizeof(preauth));
	memset(rsp_buf, 0, sizeof(rsp_buf));

	conn.preauth_info = &preauth;
	conn.preauth_info->Preauth_HashId = SMB2_PREAUTH_INTEGRITY_SHA512;
	rsp->NegotiateContextOffset = cpu_to_le32(OFFSET_OF_NEG_CONTEXT);

	rc = assemble_neg_contexts(&conn, rsp, sizeof(rsp_buf));
	KUNIT_ASSERT_GT(test, rc, AUTH_GSS_PADDING);
	ctx_bytes = rc - AUTH_GSS_PADDING;
	KUNIT_EXPECT_NULL(test, find_neg_context(rsp_buf + OFFSET_OF_NEG_CONTEXT,
						 ctx_bytes,
						 SMB2_TRANSPORT_CAPABILITIES));

	memset(rsp_buf, 0, sizeof(rsp_buf));
	rsp = (struct smb2_negotiate_rsp *)rsp_buf;
	rsp->NegotiateContextOffset = cpu_to_le32(OFFSET_OF_NEG_CONTEXT);
	conn.transport_secured = true;

	rc = assemble_neg_contexts(&conn, rsp, sizeof(rsp_buf));
	KUNIT_ASSERT_GT(test, rc, AUTH_GSS_PADDING);
	ctx_bytes = rc - AUTH_GSS_PADDING;
	KUNIT_EXPECT_NOT_NULL(test,
			      find_neg_context(rsp_buf + OFFSET_OF_NEG_CONTEXT,
					       ctx_bytes,
					       SMB2_TRANSPORT_CAPABILITIES));
}

static void test_assemble_compress_context_advertises_all_negotiated_ids(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct preauth_integrity_info preauth;
	u8 rsp_buf[512];
	struct smb2_negotiate_rsp *rsp = (struct smb2_negotiate_rsp *)rsp_buf;
	struct smb2_compression_ctx *comp;
	int rc;
	unsigned int ctx_bytes;

	memset(&conn, 0, sizeof(conn));
	memset(&preauth, 0, sizeof(preauth));
	memset(rsp_buf, 0, sizeof(rsp_buf));

	conn.preauth_info = &preauth;
	conn.preauth_info->Preauth_HashId = SMB2_PREAUTH_INTEGRITY_SHA512;
	conn.compress_algorithm = SMB3_COMPRESS_LZNT1;
	conn.compress_algorithms[0] = SMB3_COMPRESS_LZNT1;
	conn.compress_algorithms[1] = SMB3_COMPRESS_LZ77;
	conn.compress_algorithms[2] = SMB3_COMPRESS_PATTERN_V1;
	conn.compress_algorithm_count = 3;
	rsp->NegotiateContextOffset = cpu_to_le32(OFFSET_OF_NEG_CONTEXT);

	rc = assemble_neg_contexts(&conn, rsp, sizeof(rsp_buf));
	KUNIT_ASSERT_GT(test, rc, AUTH_GSS_PADDING);

	ctx_bytes = rc - AUTH_GSS_PADDING;
	comp = (struct smb2_compression_ctx *)find_neg_context(
		rsp_buf + OFFSET_OF_NEG_CONTEXT, ctx_bytes,
		SMB2_COMPRESSION_CAPABILITIES);
	KUNIT_ASSERT_NOT_NULL(test, comp);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(comp->CompressionAlgorithmCount), 3);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(comp->DataLength), 14);
	KUNIT_EXPECT_EQ(test, comp->CompressionAlgorithms[0], SMB3_COMPRESS_LZNT1);
	KUNIT_EXPECT_EQ(test, comp->CompressionAlgorithms[1], SMB3_COMPRESS_LZ77);
	KUNIT_EXPECT_EQ(test, comp->CompressionAlgorithms[2], SMB3_COMPRESS_PATTERN_V1);
}

/* --- decode_encrypt_ctxt() tests --- */

/*
 * test_encrypt_truncated - truncated context handled gracefully
 */
static void test_encrypt_truncated(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_encryption_neg_context ctxt;

	memset(&conn, 0, sizeof(conn));
	conn.cipher_type = 0x1234; /* Set to detect if cleared */
	memset(&ctxt, 0, sizeof(ctxt));

	/* Too-short context: function should return without setting cipher */
	decode_encrypt_ctxt(&conn, &ctxt, 2);
	/* cipher_type was not set to any valid cipher (function returns early) */
	KUNIT_EXPECT_EQ(test, conn.cipher_type, (__le16)0x1234);
}

static struct kunit_case ksmbd_smb2_negotiate_test_cases[] = {
	KUNIT_CASE(test_preauth_sha512),
	KUNIT_CASE(test_preauth_hash_count_zero),
	KUNIT_CASE(test_preauth_unknown_hash),
	KUNIT_CASE(test_preauth_truncated),
	KUNIT_CASE(test_sign_cap_aes_cmac),
	KUNIT_CASE(test_sign_cap_count_zero),
	KUNIT_CASE(test_sign_cap_no_overlap_fallback),
	KUNIT_CASE(test_compress_count_zero),
	KUNIT_CASE(test_compress_truncated),
	KUNIT_CASE(test_compress_lz4_not_negotiated),
	KUNIT_CASE(test_compress_common_algorithms_preserve_client_order),
	KUNIT_CASE(test_assemble_transport_context_only_for_secure_transport),
	KUNIT_CASE(test_assemble_compress_context_advertises_all_negotiated_ids),
	KUNIT_CASE(test_encrypt_truncated),
	{}
};

static struct kunit_suite ksmbd_smb2_negotiate_test_suite = {
	.name = "ksmbd_smb2_negotiate",
	.test_cases = ksmbd_smb2_negotiate_test_cases,
};

kunit_test_suite(ksmbd_smb2_negotiate_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 negotiate context helpers");
