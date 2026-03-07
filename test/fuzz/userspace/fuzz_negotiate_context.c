// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Userspace libFuzzer target for SMB2 negotiate context parsing.
 *
 * Exercises the negotiate context chain traversal that ksmbd performs
 * during SMB2 NEGOTIATE request processing (MS-SMB2 2.2.3.1):
 *   - Context chain walking with 8-byte alignment
 *   - ContextType dispatch (preauth, encrypt, compress, sign, RDMA)
 *   - DataLength vs remaining buffer bounds checking
 *   - Preauth integrity hash algorithm/salt validation
 *   - Encryption/compression capability count validation
 *   - Signing algorithm count validation
 *
 * Build: clang -fsanitize=fuzzer,address,undefined -g -O1 \
 *        -I. fuzz_negotiate_context.c -o fuzz_negotiate_context
 */

#include "ksmbd_compat.h"

/* --- Negotiate context structures (match smb2pdu.h) --- */

struct smb2_neg_context {
	__le16 ContextType;
	__le16 DataLength;
	__le32 Reserved;
} __packed;

#define NEG_CTX_HDR_SIZE sizeof(struct smb2_neg_context)

/* Preauth integrity context (MS-SMB2 2.2.3.1.1) */
struct smb2_preauth_neg_context {
	__le16 ContextType;  /* 0x0001 */
	__le16 DataLength;
	__le32 Reserved;
	__le16 HashAlgorithmCount;
	__le16 SaltLength;
	__le16 HashAlgorithms[];
	/* followed by Salt[SaltLength] */
} __packed;

/* Encryption context (MS-SMB2 2.2.3.1.2) */
struct smb2_encryption_neg_context {
	__le16 ContextType;  /* 0x0002 */
	__le16 DataLength;
	__le32 Reserved;
	__le16 CipherCount;
	__le16 Ciphers[];
} __packed;

/* Compression context (MS-SMB2 2.2.3.1.3) */
struct smb2_compression_neg_context {
	__le16 ContextType;  /* 0x0003 */
	__le16 DataLength;
	__le32 Reserved;
	__le16 CompressionAlgorithmCount;
	__le16 Padding;
	__le32 Flags;
	__le16 CompressionAlgorithms[];
} __packed;

/* Signing context (MS-SMB2 2.2.3.1.7) */
struct smb2_signing_neg_context {
	__le16 ContextType;  /* 0x0008 */
	__le16 DataLength;
	__le32 Reserved;
	__le16 SigningAlgorithmCount;
	__le16 SigningAlgorithms[];
} __packed;

/* Context type constants */
#define SMB2_PREAUTH_INTEGRITY_CAPABILITIES_LE	cpu_to_le16(0x0001)
#define SMB2_ENCRYPTION_CAPABILITIES_LE		cpu_to_le16(0x0002)
#define SMB2_COMPRESSION_CAPABILITIES_LE	cpu_to_le16(0x0003)
#define SMB2_NETNAME_NEGOTIATE_CONTEXT_ID_LE	cpu_to_le16(0x0005)
#define SMB2_TRANSPORT_CAPABILITIES_LE		cpu_to_le16(0x0006)
#define SMB2_RDMA_TRANSFORM_CAPABILITIES_LE	cpu_to_le16(0x0007)
#define SMB2_SIGNING_CAPABILITIES_LE		cpu_to_le16(0x0008)

/* Hash algorithms */
#define SMB2_PREAUTH_INTEGRITY_SHA512	cpu_to_le16(0x0001)

/* Cipher algorithms */
#define SMB2_ENCRYPTION_AES128_CCM	cpu_to_le16(0x0001)
#define SMB2_ENCRYPTION_AES128_GCM	cpu_to_le16(0x0002)
#define SMB2_ENCRYPTION_AES256_CCM	cpu_to_le16(0x0003)
#define SMB2_ENCRYPTION_AES256_GCM	cpu_to_le16(0x0004)

/* Compression algorithms */
#define SMB2_COMPRESSION_NONE		cpu_to_le16(0x0000)
#define SMB2_COMPRESSION_LZNT1		cpu_to_le16(0x0001)
#define SMB2_COMPRESSION_LZ77		cpu_to_le16(0x0002)
#define SMB2_COMPRESSION_LZ77_HUFFMAN	cpu_to_le16(0x0003)
#define SMB2_COMPRESSION_PATTERN_V1	cpu_to_le16(0x0004)

/* Signing algorithms */
#define SMB2_SIGNING_AES_CMAC		cpu_to_le16(0x0001)
#define SMB2_SIGNING_AES_GMAC		cpu_to_le16(0x0002)

/* --- Context-specific parsing --- */

static void parse_preauth_context(const u8 *ctx_data, u16 data_len)
{
	const struct smb2_preauth_neg_context *pneg;
	u16 hash_count, salt_len;
	u16 i;
	size_t expected;

	if (data_len < sizeof(__le16) * 2)
		return;

	pneg = (const struct smb2_preauth_neg_context *)(ctx_data - NEG_CTX_HDR_SIZE);
	hash_count = le16_to_cpu(pneg->HashAlgorithmCount);
	salt_len = le16_to_cpu(pneg->SaltLength);

	if (hash_count == 0)
		return; /* MS-SMB2: reject if zero */

	expected = sizeof(__le16) * 2 + hash_count * sizeof(__le16) + salt_len;
	if (expected > data_len)
		return;

	/* Validate each hash algorithm */
	for (i = 0; i < hash_count; i++) {
		volatile __le16 algo = pneg->HashAlgorithms[i];
		(void)algo;
	}
}

static void parse_encryption_context(const u8 *ctx_data, u16 data_len)
{
	const struct smb2_encryption_neg_context *ectx;
	u16 cipher_count;
	u16 i;

	if (data_len < sizeof(__le16))
		return;

	ectx = (const struct smb2_encryption_neg_context *)(ctx_data - NEG_CTX_HDR_SIZE);
	cipher_count = le16_to_cpu(ectx->CipherCount);

	if (cipher_count == 0)
		return;

	if (sizeof(__le16) + cipher_count * sizeof(__le16) > data_len)
		return;

	for (i = 0; i < cipher_count; i++) {
		volatile __le16 cipher = ectx->Ciphers[i];
		(void)cipher;
	}
}

static void parse_compression_context(const u8 *ctx_data, u16 data_len)
{
	const struct smb2_compression_neg_context *cctx;
	u16 algo_count;
	u16 i;

	/* Minimum: AlgorithmCount(2) + Padding(2) + Flags(4) */
	if (data_len < 8)
		return;

	cctx = (const struct smb2_compression_neg_context *)(ctx_data - NEG_CTX_HDR_SIZE);
	algo_count = le16_to_cpu(cctx->CompressionAlgorithmCount);

	if (algo_count == 0)
		return;

	if (8 + algo_count * sizeof(__le16) > data_len)
		return;

	for (i = 0; i < algo_count; i++) {
		volatile __le16 algo = cctx->CompressionAlgorithms[i];
		(void)algo;
	}
}

static void parse_signing_context(const u8 *ctx_data, u16 data_len)
{
	const struct smb2_signing_neg_context *sctx;
	u16 sign_count;
	u16 i;

	if (data_len < sizeof(__le16))
		return;

	sctx = (const struct smb2_signing_neg_context *)(ctx_data - NEG_CTX_HDR_SIZE);
	sign_count = le16_to_cpu(sctx->SigningAlgorithmCount);

	if (sign_count == 0)
		return;

	if (sizeof(__le16) + sign_count * sizeof(__le16) > data_len)
		return;

	for (i = 0; i < sign_count; i++) {
		volatile __le16 algo = sctx->SigningAlgorithms[i];
		(void)algo;
	}
}

static void parse_netname_context(const u8 *ctx_data, u16 data_len)
{
	/*
	 * Netname context is a Unicode string. Just ensure it is
	 * an even number of bytes (UTF-16LE) and validate bounds.
	 */
	if (data_len == 0)
		return;

	/* Read bytes to trigger ASAN on OOB */
	volatile u8 last = ctx_data[data_len - 1];
	(void)last;
}

/* --- Main context chain walker --- */

static void parse_negotiate_contexts(const u8 *data, size_t len)
{
	const struct smb2_neg_context *ctx;
	u32 offset = 0;
	u16 data_length;
	u32 ctx_total;
	int count = 0;
	bool seen_preauth = false;
	bool seen_encrypt = false;
	bool seen_compress = false;
	bool seen_signing = false;

	if (len < NEG_CTX_HDR_SIZE)
		return;

	/* Cap to prevent excessive processing */
	if (len > 65536)
		len = 65536;

	/*
	 * First 2 bytes are used as expected context count (from
	 * the negotiate request header NegotiateContextCount field).
	 * Remaining bytes are the context chain itself.
	 */
	if (len < 2 + NEG_CTX_HDR_SIZE)
		return;

	u16 expected_count = le16_to_cpu(*(const __le16 *)data);
	data += 2;
	len -= 2;

	/* Cap expected count */
	if (expected_count > 64)
		expected_count = 64;

	while (offset + NEG_CTX_HDR_SIZE <= len && count < expected_count) {
		ctx = (const struct smb2_neg_context *)(data + offset);
		data_length = le16_to_cpu(ctx->DataLength);

		ctx_total = NEG_CTX_HDR_SIZE + data_length;
		if (offset + ctx_total > len)
			break;

		/* Dispatch to context-specific parser */
		const u8 *ctx_payload = data + offset + NEG_CTX_HDR_SIZE;

		switch (ctx->ContextType) {
		case SMB2_PREAUTH_INTEGRITY_CAPABILITIES_LE:
			if (seen_preauth)
				return; /* Duplicate - reject */
			seen_preauth = true;
			parse_preauth_context(ctx_payload, data_length);
			break;
		case SMB2_ENCRYPTION_CAPABILITIES_LE:
			if (seen_encrypt)
				return;
			seen_encrypt = true;
			parse_encryption_context(ctx_payload, data_length);
			break;
		case SMB2_COMPRESSION_CAPABILITIES_LE:
			if (seen_compress)
				return;
			seen_compress = true;
			parse_compression_context(ctx_payload, data_length);
			break;
		case SMB2_SIGNING_CAPABILITIES_LE:
			if (seen_signing)
				return;
			seen_signing = true;
			parse_signing_context(ctx_payload, data_length);
			break;
		case SMB2_NETNAME_NEGOTIATE_CONTEXT_ID_LE:
			parse_netname_context(ctx_payload, data_length);
			break;
		default:
			/* Unknown context type - skip */
			break;
		}

		count++;

		/* Advance to next context with 8-byte alignment */
		offset += ctx_total;
		if (count < expected_count)
			offset = (offset + 7) & ~7U;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	parse_negotiate_contexts(data, size);
	return 0;
}
