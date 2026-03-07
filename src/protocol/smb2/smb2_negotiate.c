// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_negotiate.c - Negotiate contexts + SMB2_NEGOTIATE handler
 */

#include <kunit/visibility.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/ethtool.h>
#include <linux/falloc.h>
#include <linux/crc32.h>
#include <linux/mount.h>
#include <linux/overflow.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#include <linux/filelock.h>
#endif

#include <crypto/algapi.h>

#include "compat.h"
#include "glob.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "oplock.h"
#include "smbacl.h"

#include "auth.h"
#include "asn1.h"
#include "connection.h"
#include "transport_ipc.h"
#include "transport_rdma.h"
#include "vfs.h"
#include "vfs_cache.h"
#include "misc.h"

#include "server.h"
#include "smb_common.h"
#include "smbstatus.h"
#include "ksmbd_work.h"
#include "mgmt/user_config.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"
#include "mgmt/ksmbd_ida.h"
#include "ndr.h"
#include "transport_tcp.h"
#include "smb2fruit.h"
#include "ksmbd_fsctl.h"
#include "ksmbd_create_ctx.h"
#include "ksmbd_vss.h"
#include "ksmbd_notify.h"
#include "ksmbd_info.h"
#include "ksmbd_buffer.h"
#include "smb2pdu_internal.h"

static void build_preauth_ctxt(struct smb2_preauth_neg_context *pneg_ctxt,
			       __le16 hash_id)
{
	pneg_ctxt->ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	pneg_ctxt->DataLength = cpu_to_le16(38);
	pneg_ctxt->HashAlgorithmCount = cpu_to_le16(1);
	pneg_ctxt->Reserved = cpu_to_le32(0);
	pneg_ctxt->SaltLength = cpu_to_le16(SMB311_SALT_SIZE);
	get_random_bytes(pneg_ctxt->Salt, SMB311_SALT_SIZE);
	pneg_ctxt->HashAlgorithms = hash_id;
}

static void build_encrypt_ctxt(struct smb2_encryption_neg_context *pneg_ctxt,
			       __le16 cipher_type)
{
	pneg_ctxt->ContextType = SMB2_ENCRYPTION_CAPABILITIES;
	pneg_ctxt->DataLength = cpu_to_le16(4);
	pneg_ctxt->Reserved = cpu_to_le32(0);
	pneg_ctxt->CipherCount = cpu_to_le16(1);
	pneg_ctxt->Ciphers[0] = cipher_type;
}

static void build_compress_ctxt(struct smb2_compression_ctx *pneg_ctxt,
				__le16 alg_type)
{
	pneg_ctxt->ContextType = SMB2_COMPRESSION_CAPABILITIES;
	pneg_ctxt->DataLength = cpu_to_le16(10);
	pneg_ctxt->Reserved = cpu_to_le32(0);
	pneg_ctxt->CompressionAlgorithmCount = cpu_to_le16(1);
	pneg_ctxt->Padding = cpu_to_le16(0);
	pneg_ctxt->Flags = cpu_to_le32(0);
	pneg_ctxt->CompressionAlgorithms[0] = alg_type;
}

static void build_sign_cap_ctxt(struct smb2_signing_capabilities *pneg_ctxt,
				__le16 sign_algo)
{
	pneg_ctxt->ContextType = SMB2_SIGNING_CAPABILITIES;
	pneg_ctxt->DataLength =
		cpu_to_le16((sizeof(struct smb2_signing_capabilities) + 2)
			- sizeof(struct smb2_neg_context));
	pneg_ctxt->Reserved = cpu_to_le32(0);
	pneg_ctxt->SigningAlgorithmCount = cpu_to_le16(1);
	pneg_ctxt->SigningAlgorithms[0] = sign_algo;
}

static void build_rdma_transform_ctxt(
			struct smb2_rdma_transform_capabilities *pneg_ctxt,
			struct ksmbd_conn *conn)
{
	unsigned int count = conn->rdma_transform_count;
	unsigned int data_len;
	unsigned int i;

	pneg_ctxt->ContextType = SMB2_RDMA_TRANSFORM_CAPABILITIES;
	pneg_ctxt->Reserved = cpu_to_le32(0);
	pneg_ctxt->TransformCount = cpu_to_le16(count);
	pneg_ctxt->Reserved1 = cpu_to_le16(0);
	pneg_ctxt->Reserved2 = cpu_to_le32(0);

	for (i = 0; i < count; i++)
		pneg_ctxt->RDMATransformIds[i] = conn->rdma_transform_ids[i];

	data_len = sizeof(struct smb2_rdma_transform_capabilities)
		   - sizeof(struct smb2_neg_context)
		   + count * sizeof(__le16);
	pneg_ctxt->DataLength = cpu_to_le16(data_len);
}

static void build_transport_cap_ctxt(
				struct smb2_transport_capabilities *pneg_ctxt)
{
	pneg_ctxt->ContextType = SMB2_TRANSPORT_CAPABILITIES;
	pneg_ctxt->DataLength =
		cpu_to_le16(sizeof(struct smb2_transport_capabilities)
			    - sizeof(struct smb2_neg_context));
	pneg_ctxt->Reserved = cpu_to_le32(0);
	pneg_ctxt->Flags = SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY;
}

static void build_posix_ctxt(struct smb2_posix_neg_context *pneg_ctxt)
{
	pneg_ctxt->ContextType = SMB2_POSIX_EXTENSIONS_AVAILABLE;
	pneg_ctxt->DataLength = cpu_to_le16(POSIX_CTXT_DATA_LEN);
	/* SMB2_CREATE_TAG_POSIX is "0x93AD25509CB411E7B42383DE968BCD7C" */
	pneg_ctxt->Name[0] = 0x93;
	pneg_ctxt->Name[1] = 0xAD;
	pneg_ctxt->Name[2] = 0x25;
	pneg_ctxt->Name[3] = 0x50;
	pneg_ctxt->Name[4] = 0x9C;
	pneg_ctxt->Name[5] = 0xB4;
	pneg_ctxt->Name[6] = 0x11;
	pneg_ctxt->Name[7] = 0xE7;
	pneg_ctxt->Name[8] = 0xB4;
	pneg_ctxt->Name[9] = 0x23;
	pneg_ctxt->Name[10] = 0x83;
	pneg_ctxt->Name[11] = 0xDE;
	pneg_ctxt->Name[12] = 0x96;
	pneg_ctxt->Name[13] = 0x8B;
	pneg_ctxt->Name[14] = 0xCD;
	pneg_ctxt->Name[15] = 0x7C;
}

VISIBLE_IF_KUNIT
int assemble_neg_contexts(struct ksmbd_conn *conn,
			  struct smb2_negotiate_rsp *rsp,
			  unsigned int buf_len)
{
	unsigned int neg_ctxt_off = le32_to_cpu(rsp->NegotiateContextOffset);
	char * const pneg_ctxt = (char *)rsp + neg_ctxt_off;
	unsigned int buf_remaining;
	int neg_ctxt_cnt = 1;
	int ctxt_size;

	if (neg_ctxt_off > buf_len)
		return -EINVAL;
	buf_remaining = buf_len - neg_ctxt_off;

	ksmbd_debug(SMB,
		    "assemble SMB2_PREAUTH_INTEGRITY_CAPABILITIES context\n");
	if (sizeof(struct smb2_preauth_neg_context) > buf_remaining)
		return -EINVAL;
	build_preauth_ctxt((struct smb2_preauth_neg_context *)pneg_ctxt,
			   conn->preauth_info->Preauth_HashId);
	ctxt_size = sizeof(struct smb2_preauth_neg_context);

	if (conn->cipher_type) {
		unsigned int next_size;

		/* Round to 8 byte boundary */
		ctxt_size = round_up(ctxt_size, 8);
		next_size = sizeof(struct smb2_encryption_neg_context) + 2;
		if (ctxt_size + next_size > buf_remaining)
			return -EINVAL;
		ksmbd_debug(SMB,
			    "assemble SMB2_ENCRYPTION_CAPABILITIES context\n");
		build_encrypt_ctxt((struct smb2_encryption_neg_context *)
				   (pneg_ctxt + ctxt_size),
				   conn->cipher_type);
		neg_ctxt_cnt++;
		ctxt_size += next_size;
	}

	if (conn->compress_algorithm != SMB3_COMPRESS_NONE) {
		unsigned int next_size;

		ctxt_size = round_up(ctxt_size, 8);
		next_size = sizeof(struct smb2_compression_ctx) + sizeof(__le16);
		if (ctxt_size + next_size > buf_remaining)
			return -EINVAL;
		ksmbd_debug(SMB,
			    "assemble SMB2_COMPRESSION_CAPABILITIES context\n");
		build_compress_ctxt((struct smb2_compression_ctx *)
				    (pneg_ctxt + ctxt_size),
				    conn->compress_algorithm);
		neg_ctxt_cnt++;
		ctxt_size += next_size;
	}

	if (conn->posix_ext_supported) {
		ctxt_size = round_up(ctxt_size, 8);
		if (ctxt_size + sizeof(struct smb2_posix_neg_context) > buf_remaining)
			return -EINVAL;
		ksmbd_debug(SMB,
			    "assemble SMB2_POSIX_EXTENSIONS_AVAILABLE context\n");
		build_posix_ctxt((struct smb2_posix_neg_context *)
				 (pneg_ctxt + ctxt_size));
		neg_ctxt_cnt++;
		ctxt_size += sizeof(struct smb2_posix_neg_context);
	}

	if (conn->signing_negotiated) {
		unsigned int next_size;

		ctxt_size = round_up(ctxt_size, 8);
		next_size = sizeof(struct smb2_signing_capabilities) + 2;
		if (ctxt_size + next_size > buf_remaining)
			return -EINVAL;
		ksmbd_debug(SMB,
			    "assemble SMB2_SIGNING_CAPABILITIES context\n");
		build_sign_cap_ctxt((struct smb2_signing_capabilities *)
				    (pneg_ctxt + ctxt_size),
				    conn->signing_algorithm);
		neg_ctxt_cnt++;
		ctxt_size += next_size;
	}

	if (conn->rdma_transform_count) {
		unsigned int next_size;

		ctxt_size = round_up(ctxt_size, 8);
		next_size = sizeof(struct smb2_rdma_transform_capabilities)
			    + conn->rdma_transform_count * sizeof(__le16);
		if (ctxt_size + next_size > buf_remaining)
			return -EINVAL;
		ksmbd_debug(SMB,
			    "assemble SMB2_RDMA_TRANSFORM_CAPABILITIES context\n");
		build_rdma_transform_ctxt(
			(struct smb2_rdma_transform_capabilities *)
			(pneg_ctxt + ctxt_size), conn);
		neg_ctxt_cnt++;
		ctxt_size += next_size;
	}

	if (conn->transport_secured) {
		ctxt_size = round_up(ctxt_size, 8);
		if (ctxt_size + sizeof(struct smb2_transport_capabilities) > buf_remaining)
			return -EINVAL;
		ksmbd_debug(SMB,
			    "assemble SMB2_TRANSPORT_CAPABILITIES context\n");
		build_transport_cap_ctxt(
				(struct smb2_transport_capabilities *)
				(pneg_ctxt + ctxt_size));
		neg_ctxt_cnt++;
		ctxt_size += sizeof(struct smb2_transport_capabilities);
	}

	rsp->NegotiateContextCount = cpu_to_le16(neg_ctxt_cnt);
	return ctxt_size + AUTH_GSS_PADDING;
}
EXPORT_SYMBOL_IF_KUNIT(assemble_neg_contexts);

VISIBLE_IF_KUNIT
__le32 decode_preauth_ctxt(struct ksmbd_conn *conn,
			   struct smb2_preauth_neg_context *pneg_ctxt,
			   int ctxt_len)
{
	int hash_count;

	/*
	 * sizeof(smb2_preauth_neg_context) assumes SMB311_SALT_SIZE Salt,
	 * which may not be present. Only check for used HashAlgorithms[1].
	 */
	if (ctxt_len <
	    sizeof(struct smb2_neg_context) + MIN_PREAUTH_CTXT_DATA_LEN)
		return STATUS_INVALID_PARAMETER;

	/*
	 * B.4: MS-SMB2 §2.2.3.1.1 — HashAlgorithmCount MUST be >= 1.
	 * Validate the count before reading any algorithm entries.
	 */
	hash_count = le16_to_cpu(pneg_ctxt->HashAlgorithmCount);
	if (hash_count == 0) {
		pr_warn_ratelimited("SMB2_PREAUTH_INTEGRITY: HashAlgorithmCount=0 is invalid\n");
		return STATUS_INVALID_PARAMETER;
	}

	/*
	 * Only SHA-512 (0x0001) is currently defined. The HashAlgorithms
	 * field holds the first (and typically only) algorithm. If SHA-512
	 * is present, accept it; otherwise report no overlap.
	 * Unknown algorithm IDs are ignored per spec.
	 */
	if (pneg_ctxt->HashAlgorithms == SMB2_PREAUTH_INTEGRITY_SHA512) {
		conn->preauth_info->Preauth_HashId =
			SMB2_PREAUTH_INTEGRITY_SHA512;
		return STATUS_SUCCESS;
	}

	return STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP;
}
EXPORT_SYMBOL_IF_KUNIT(decode_preauth_ctxt);

VISIBLE_IF_KUNIT
void decode_encrypt_ctxt(struct ksmbd_conn *conn,
			 struct smb2_encryption_neg_context *pneg_ctxt,
			 int ctxt_len)
{
	int cph_cnt;
	size_t cphs_size;

	if (sizeof(struct smb2_encryption_neg_context) > ctxt_len) {
		pr_err_ratelimited("Invalid SMB2_ENCRYPTION_CAPABILITIES context size\n");
		return;
	}

	conn->cipher_type = 0;

	cph_cnt = le16_to_cpu(pneg_ctxt->CipherCount);
	if (check_mul_overflow((size_t)cph_cnt, sizeof(__le16), &cphs_size)) {
		pr_err_ratelimited("Cipher count overflow(%d)\n", cph_cnt);
		return;
	}

	if (sizeof(struct smb2_encryption_neg_context) + cphs_size >
	    (size_t)ctxt_len) {
		pr_err_ratelimited("Invalid cipher count(%d)\n", cph_cnt);
		return;
	}

	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF)
		return;

	/*
	 * B.3: Select cipher by SERVER preference order, not client order.
	 * MS-SMB2 §3.3.5.2.5.2 step 2: "The server MUST set
	 * Connection.CipherId to the value in the Ciphers array that is
	 * preferred by the server."
	 *
	 * Server priority (strongest first):
	 *   AES-256-GCM > AES-128-GCM > AES-256-CCM > AES-128-CCM
	 */
	{
		static const __le16 server_cipher_pref[] = {
			SMB2_ENCRYPTION_AES256_GCM,
			SMB2_ENCRYPTION_AES128_GCM,
			SMB2_ENCRYPTION_AES256_CCM,
			SMB2_ENCRYPTION_AES128_CCM,
		};
		int p, j;

		for (p = 0; p < ARRAY_SIZE(server_cipher_pref); p++) {
			for (j = 0; j < cph_cnt; j++) {
				if (pneg_ctxt->Ciphers[j] ==
				    server_cipher_pref[p]) {
					ksmbd_debug(SMB,
						    "Cipher ID = 0x%x\n",
						    le16_to_cpu(pneg_ctxt->Ciphers[j]));
					conn->cipher_type =
						server_cipher_pref[p];
					return;
				}
			}
		}
	}
}
EXPORT_SYMBOL_IF_KUNIT(decode_encrypt_ctxt);

/**
 * smb3_encryption_negotiated() - checks if server and client agreed on enabling encryption
 * @conn:	smb connection
 *
 * Return:	true if connection should be encrypted, else false
 */
bool smb3_encryption_negotiated(struct ksmbd_conn *conn)
{
	if (!conn->ops->generate_encryptionkey)
		return false;

	/*
	 * SMB 3.0 and 3.0.2 dialects use the SMB2_GLOBAL_CAP_ENCRYPTION flag.
	 * SMB 3.1.1 uses the cipher_type field.
	 */
	return (conn->vals->capabilities & SMB2_GLOBAL_CAP_ENCRYPTION) ||
	    conn->cipher_type;
}

VISIBLE_IF_KUNIT
__le32 decode_compress_ctxt(struct ksmbd_conn *conn,
			    struct smb2_compression_ctx *pneg_ctxt,
			    int ctxt_len)
{
	int algo_cnt, i;
	size_t algos_size;

	conn->compress_algorithm = SMB3_COMPRESS_NONE;

	if (sizeof(struct smb2_compression_ctx) > ctxt_len) {
		pr_err("Invalid SMB2_COMPRESSION_CAPABILITIES context length\n");
		return STATUS_INVALID_PARAMETER;
	}

	algo_cnt = le16_to_cpu(pneg_ctxt->CompressionAlgorithmCount);

	/* MS-SMB2 §2.2.3.1.3: CompressionAlgorithmCount MUST be > 0 */
	if (algo_cnt == 0) {
		pr_warn_ratelimited("SMB2_COMPRESSION_CAPABILITIES: CompressionAlgorithmCount=0 is invalid\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (check_mul_overflow((size_t)algo_cnt, sizeof(__le16), &algos_size)) {
		pr_err("Compression algorithm count overflow(%d)\n", algo_cnt);
		return STATUS_INVALID_PARAMETER;
	}

	if (sizeof(struct smb2_compression_ctx) + algos_size > (size_t)ctxt_len) {
		pr_err("Invalid compression algorithm count(%d)\n", algo_cnt);
		return STATUS_INVALID_PARAMETER;
	}

	/*
	 * Select the best compression algorithm supported by both sides.
	 * Preference order: LZ4 > Pattern_V1 > LZ77+Huffman > LZ77 > LZNT1
	 * For now, only LZ4 and Pattern_V1 are fully implemented.
	 */
	for (i = 0; i < algo_cnt; i++) {
		if (pneg_ctxt->CompressionAlgorithms[i] == SMB3_COMPRESS_LZ4) {
			conn->compress_algorithm = SMB3_COMPRESS_LZ4;
			ksmbd_debug(SMB, "Selected compression algorithm: LZ4\n");
			return STATUS_SUCCESS;
		}
	}

	for (i = 0; i < algo_cnt; i++) {
		if (pneg_ctxt->CompressionAlgorithms[i] ==
		    SMB3_COMPRESS_PATTERN_V1) {
			conn->compress_algorithm = SMB3_COMPRESS_PATTERN_V1;
			ksmbd_debug(SMB,
				    "Selected compression algorithm: Pattern_V1\n");
			return STATUS_SUCCESS;
		}
	}

	ksmbd_debug(SMB, "No mutually supported compression algorithm found\n");
	return STATUS_SUCCESS;
}
EXPORT_SYMBOL_IF_KUNIT(decode_compress_ctxt);

VISIBLE_IF_KUNIT
__le32 decode_sign_cap_ctxt(struct ksmbd_conn *conn,
			    struct smb2_signing_capabilities *pneg_ctxt,
			    int ctxt_len)
{
	int sign_algo_cnt;
	int i, sign_alos_size;

	if (sizeof(struct smb2_signing_capabilities) > ctxt_len) {
		pr_err_ratelimited("Invalid SMB2_SIGNING_CAPABILITIES context length\n");
		return STATUS_INVALID_PARAMETER;
	}

	conn->signing_negotiated = false;
	sign_algo_cnt = le16_to_cpu(pneg_ctxt->SigningAlgorithmCount);

	/* MS-SMB2 §2.2.3.1.7: SigningAlgorithmCount MUST be > 0 */
	if (sign_algo_cnt == 0) {
		pr_warn_ratelimited("SMB2_SIGNING_CAPABILITIES: SigningAlgorithmCount=0 is invalid\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (check_mul_overflow((int)sign_algo_cnt, (int)sizeof(__le16), &sign_alos_size))
		return STATUS_INVALID_PARAMETER;

	if (sizeof(struct smb2_signing_capabilities) + sign_alos_size >
	    ctxt_len) {
		pr_err_ratelimited("Invalid signing algorithm count(%d)\n", sign_algo_cnt);
		return STATUS_INVALID_PARAMETER;
	}

	/*
	 * MS-SMB2 §3.3.5.4 (Signing Capabilities negotiate context):
	 * "The server MUST set Connection.SigningAlgorithmId to the first
	 * entry in the SigningAlgorithms array that the server supports."
	 *
	 * Iterate the CLIENT's list in order and pick the first algorithm
	 * we support.  AES-CMAC and AES-GMAC are both supported; HMAC-SHA256
	 * is accepted for compatibility but not preferred.
	 */
	conn->signing_negotiated = true;
	conn->signing_algorithm = SIGNING_ALG_AES_CMAC; /* fallback */
	for (i = 0; i < sign_algo_cnt; i++) {
		__le16 alg = pneg_ctxt->SigningAlgorithms[i];

		if (alg == SIGNING_ALG_AES_CMAC ||
		    alg == SIGNING_ALG_AES_GMAC ||
		    alg == SIGNING_ALG_HMAC_SHA256) {
			conn->signing_algorithm = alg;
			ksmbd_debug(SMB, "Signing Algorithm ID = 0x%x (mutually agreed)\n",
				    le16_to_cpu(alg));
			break;
		}
	}
	/*
	 * M-03: If no overlap was found between client's offered algorithms
	 * and those the server supports, we unilaterally fall back to
	 * AES-CMAC (the mandatory baseline per MS-SMB2 §3.3.5.4).
	 * Log a distinct message so operators can distinguish "negotiated"
	 * from "unilateral fallback" when diagnosing signing mismatches.
	 */
	if (i == sign_algo_cnt)
		ksmbd_debug(SMB,
			    "No signing algorithm overlap with client — falling back to AES-CMAC\n");
	return STATUS_SUCCESS;
}
EXPORT_SYMBOL_IF_KUNIT(decode_sign_cap_ctxt);

static void decode_transport_cap_ctxt(struct ksmbd_conn *conn,
				      struct smb2_transport_capabilities *pneg_ctxt,
				      int ctxt_len)
{
	if (sizeof(struct smb2_transport_capabilities) > ctxt_len) {
		pr_err("Invalid SMB2_TRANSPORT_CAPABILITIES context size\n");
		return;
	}

	if (pneg_ctxt->Flags & SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY) {
		ksmbd_debug(SMB, "Client supports transport-level security\n");
		conn->transport_secured = true;
	}
}

static void decode_rdma_transform_ctxt(struct ksmbd_conn *conn,
					struct smb2_rdma_transform_capabilities *pneg_ctxt,
					int ctxt_len)
{
	int xform_cnt;
	int i, xforms_size;

	if (sizeof(struct smb2_rdma_transform_capabilities) > ctxt_len) {
		pr_err("Invalid SMB2_RDMA_TRANSFORM_CAPABILITIES context size\n");
		return;
	}

	conn->rdma_transform_count = 0;

	xform_cnt = le16_to_cpu(pneg_ctxt->TransformCount);
	if (xform_cnt == 0) {
		pr_err("RDMA transform count is zero\n");
		return;
	}

	if (check_mul_overflow((int)xform_cnt, (int)sizeof(__le16), &xforms_size))
		return;

	if (sizeof(struct smb2_rdma_transform_capabilities) + xforms_size >
	    ctxt_len) {
		pr_err("Invalid RDMA transform count(%d)\n", xform_cnt);
		return;
	}

	for (i = 0; i < xform_cnt; i++) {
		if (pneg_ctxt->RDMATransformIds[i] == SMB2_RDMA_TRANSFORM_NONE ||
		    pneg_ctxt->RDMATransformIds[i] == SMB2_RDMA_TRANSFORM_ENCRYPTION ||
		    pneg_ctxt->RDMATransformIds[i] == SMB2_RDMA_TRANSFORM_SIGNING) {
			if (conn->rdma_transform_count >= ARRAY_SIZE(conn->rdma_transform_ids))
				break;
			ksmbd_debug(SMB, "RDMA Transform ID = 0x%x\n",
				    le16_to_cpu(pneg_ctxt->RDMATransformIds[i]));
			conn->rdma_transform_ids[conn->rdma_transform_count++] =
				pneg_ctxt->RDMATransformIds[i];
		}
	}
}

VISIBLE_IF_KUNIT
__le32 deassemble_neg_contexts(struct ksmbd_conn *conn,
			       struct smb2_negotiate_req *req,
			       unsigned int len_of_smb)
{
	/* +4 is to account for the RFC1001 len field */
	struct smb2_neg_context *pctx = (struct smb2_neg_context *)req;
	int i = 0, len_of_ctxts;
	unsigned int offset = le32_to_cpu(req->NegotiateContextOffset);
	unsigned int neg_ctxt_cnt = le16_to_cpu(req->NegotiateContextCount);
	bool compress_ctxt_seen = false;
	__le32 status = STATUS_SUCCESS;

	ksmbd_debug(SMB, "decoding %d negotiate contexts\n", neg_ctxt_cnt);
	if (len_of_smb <= offset) {
		ksmbd_debug(SMB, "Invalid response: negotiate context offset\n");
		return status;
	}

	len_of_ctxts = len_of_smb - offset;

	/*
	 * Cap negotiate context count to prevent excessive processing.
	 * MS-SMB2 defines a small number of context types; 16 is generous.
	 */
#define SMB2_MAX_NEG_CTXTS	16
	if (neg_ctxt_cnt > SMB2_MAX_NEG_CTXTS) {
		pr_warn_ratelimited("Too many negotiate contexts (%d > %d), rejecting\n",
				    neg_ctxt_cnt, SMB2_MAX_NEG_CTXTS);
		return STATUS_INVALID_PARAMETER;
	}

	while (i++ < neg_ctxt_cnt) {
		int clen, ctxt_len;

		if (len_of_ctxts < (int)sizeof(struct smb2_neg_context))
			break;

		pctx = (struct smb2_neg_context *)((char *)pctx + offset);
		clen = le16_to_cpu(pctx->DataLength);
		ctxt_len = clen + sizeof(struct smb2_neg_context);

		if (ctxt_len > len_of_ctxts)
			break;

		if (pctx->ContextType == SMB2_PREAUTH_INTEGRITY_CAPABILITIES) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_PREAUTH_INTEGRITY_CAPABILITIES context\n");
			if (conn->preauth_info->Preauth_HashId) {
				/* MS-SMB2 §3.3.5.4: duplicate context MUST be rejected */
				pr_warn_ratelimited("Duplicate PREAUTH_INTEGRITY context in negotiate\n");
				return STATUS_INVALID_PARAMETER;
			}

			status = decode_preauth_ctxt(conn,
						     (struct smb2_preauth_neg_context *)pctx,
						     ctxt_len);
			if (status != STATUS_SUCCESS)
				return status;
		} else if (pctx->ContextType == SMB2_ENCRYPTION_CAPABILITIES) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_ENCRYPTION_CAPABILITIES context\n");
			if (conn->cipher_type) {
				pr_warn_ratelimited("Duplicate ENCRYPTION_CAPABILITIES context in negotiate\n");
				return STATUS_INVALID_PARAMETER;
			}

			decode_encrypt_ctxt(conn,
					    (struct smb2_encryption_neg_context *)pctx,
					    ctxt_len);
		} else if (pctx->ContextType == SMB2_COMPRESSION_CAPABILITIES) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_COMPRESSION_CAPABILITIES context\n");
			if (compress_ctxt_seen) {
				pr_warn_ratelimited("Duplicate COMPRESSION_CAPABILITIES context in negotiate\n");
				return STATUS_INVALID_PARAMETER;
			}

			status = decode_compress_ctxt(conn,
						     (struct smb2_compression_ctx *)pctx,
						     ctxt_len);
			if (status != STATUS_SUCCESS)
				return status;
			compress_ctxt_seen = true;
		} else if (pctx->ContextType == SMB2_NETNAME_NEGOTIATE_CONTEXT_ID) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_NETNAME_NEGOTIATE_CONTEXT_ID context\n");
			/*
			 * B.13: MS-SMB2 §3.3.5.2.4 step 2: the server SHOULD
			 * validate the NetName against its own server name.
			 * Log a debug message if the name doesn't match;
			 * do not reject (informational only for compatibility).
			 */
			if (clen > 0) {
				char *net_name;
				struct smb2_netname_neg_context *nc =
					(struct smb2_netname_neg_context *)pctx;

				net_name = smb_strndup_from_utf16(
						(const char *)nc->NetName, clen, true,
						conn->local_nls);
				if (!IS_ERR(net_name)) {
					char *srv = ksmbd_netbios_name();

					if (srv && strcasecmp(net_name, srv) != 0)
						ksmbd_debug(SMB,
							    "NETNAME context name '%s' != server name '%s'\n",
							    net_name, srv);
					kfree(net_name);
				}
			}
		} else if (pctx->ContextType == SMB2_POSIX_EXTENSIONS_AVAILABLE) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_POSIX_EXTENSIONS_AVAILABLE context\n");
			conn->posix_ext_supported = true;
		} else if (pctx->ContextType == SMB2_TRANSPORT_CAPABILITIES) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_TRANSPORT_CAPABILITIES context\n");

			decode_transport_cap_ctxt(conn,
						  (struct smb2_transport_capabilities *)pctx,
						  ctxt_len);
		} else if (pctx->ContextType == SMB2_RDMA_TRANSFORM_CAPABILITIES) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_RDMA_TRANSFORM_CAPABILITIES context\n");
			if (conn->rdma_transform_count) {
				pr_warn_ratelimited("Duplicate RDMA_TRANSFORM_CAPABILITIES context in negotiate\n");
				return STATUS_INVALID_PARAMETER;
			}

			decode_rdma_transform_ctxt(conn,
						   (struct smb2_rdma_transform_capabilities *)pctx,
						   ctxt_len);
		} else if (pctx->ContextType == SMB2_SIGNING_CAPABILITIES) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_SIGNING_CAPABILITIES context\n");

			status = decode_sign_cap_ctxt(conn,
						    (struct smb2_signing_capabilities *)pctx,
						    ctxt_len);
			if (status != STATUS_SUCCESS)
				return status;
		}

		/* offsets must be 8 byte aligned */
		offset = (ctxt_len + 7) & ~0x7;
		len_of_ctxts -= offset;
	}
	return status;
}
EXPORT_SYMBOL_IF_KUNIT(deassemble_neg_contexts);

/**
 * smb2_handle_negotiate() - handler for smb2 negotiate command
 * @work:	smb work containing smb request buffer
 *
 * Return:      0
 */
int smb2_handle_negotiate(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_negotiate_req *req = smb2_get_msg(work->request_buf);
	struct smb2_negotiate_rsp *rsp = smb2_get_msg(work->response_buf);
	int rc = 0;
	unsigned int smb2_buf_len, smb2_neg_size, neg_ctxt_len = 0;
	__le32 status;

	/* Zero negotiate response body to prevent stale heap data leakage */
	memset((char *)rsp + sizeof(struct smb2_hdr), 0,
	       sizeof(struct smb2_negotiate_rsp) - sizeof(struct smb2_hdr));

	ksmbd_debug(SMB, "Received negotiate request\n");
	conn->need_neg = false;
	if (ksmbd_conn_good(conn)) {
		/*
		 * MS-SMB2 §3.3.5.3.1: "If the server receives a second SMB2
		 * NEGOTIATE Request on any established connection, the server
		 * MUST disconnect the connection."
		 */
		pr_err_ratelimited("Second NEGOTIATE on established connection, disconnecting\n");
		ksmbd_conn_set_exiting(conn);
		work->send_no_response = 1;
		return -EINVAL;
	}

	ksmbd_conn_lock(conn);
	smb2_buf_len = get_rfc1002_len(work->request_buf);
	smb2_neg_size = offsetof(struct smb2_negotiate_req, Dialects);
	if (smb2_neg_size > smb2_buf_len) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		rc = -EINVAL;
		goto err_out;
	}

	if (req->DialectCount == 0) {
		pr_err_ratelimited("malformed packet\n");
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		rc = -EINVAL;
		goto err_out;
	}

	/*
	 * NEG-01: Guard against DialectCount multiplication overflow.
	 * On 32-bit kernels, DialectCount=0x8000 causes
	 * le16_to_cpu(req->DialectCount) * sizeof(__le16) to silently
	 * overflow to 0, bypassing the bounds check below.
	 * Cap to SMB2_MAX_DIALECTS (8 known SMB dialects).
	 */
#define SMB2_MAX_DIALECTS	8
	if (le16_to_cpu(req->DialectCount) > SMB2_MAX_DIALECTS) {
		pr_err_ratelimited("DialectCount %u exceeds maximum %u\n",
				   le16_to_cpu(req->DialectCount),
				   SMB2_MAX_DIALECTS);
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		rc = -EINVAL;
		goto err_out;
	}

	if (conn->dialect == SMB311_PROT_ID) {
		unsigned int nego_ctxt_off = le32_to_cpu(req->NegotiateContextOffset);

		/*
		 * MS-SMB2 §2.2.3.1: NegotiateContextOffset MUST be
		 * 8-byte aligned from the beginning of the header.
		 */
		if (nego_ctxt_off % 8) {
			pr_err_ratelimited("ksmbd: negotiate context offset not 8-byte aligned\n");
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			rc = -EINVAL;
			goto err_out;
		}

		if (smb2_buf_len < nego_ctxt_off) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			rc = -EINVAL;
			goto err_out;
		}

		if (smb2_neg_size > nego_ctxt_off) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			rc = -EINVAL;
			goto err_out;
		}

		if (smb2_neg_size + le16_to_cpu(req->DialectCount) * sizeof(__le16) >
		    nego_ctxt_off) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			rc = -EINVAL;
			goto err_out;
		}
	} else {
		if (smb2_neg_size + le16_to_cpu(req->DialectCount) * sizeof(__le16) >
		    smb2_buf_len) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			rc = -EINVAL;
			goto err_out;
		}
	}

	conn->cli_cap = le32_to_cpu(req->Capabilities);

	{
	/*
	 * Save previous vals so we can free it only after a successful
	 * init_smb*_server() call. This prevents conn->vals from being
	 * NULL on error paths, which would cause NULL dereferences in
	 * subsequent connection handling code.
	 */
	struct smb_version_values *old_vals = conn->vals;

	conn->vals = NULL;

	switch (conn->dialect) {
	case SMB311_PROT_ID:
		conn->preauth_info =
			kzalloc(sizeof(struct preauth_integrity_info),
				KSMBD_DEFAULT_GFP);
		if (!conn->preauth_info) {
			rc = -ENOMEM;
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			conn->vals = old_vals;
			goto err_out;
		}

		status = deassemble_neg_contexts(conn, req,
						 get_rfc1002_len(work->request_buf));
		if (status != STATUS_SUCCESS) {
			pr_err("deassemble_neg_contexts error(0x%x)\n",
			       status);
			rsp->hdr.Status = status;
			rc = -EINVAL;
			kfree(conn->preauth_info);
			conn->preauth_info = NULL;
			conn->vals = old_vals;
			goto err_out;
		}

		/*
		 * MS-SMB2 §3.3.5.4: SMB 3.1.1 NEGOTIATE MUST contain one
		 * SMB2_PREAUTH_INTEGRITY_CAPABILITIES context.
		 */
		if (!conn->preauth_info->Preauth_HashId) {
			pr_warn_ratelimited("SMB 3.1.1 negotiate missing mandatory PREAUTH_INTEGRITY context\n");
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			rc = -EINVAL;
			kfree(conn->preauth_info);
			conn->preauth_info = NULL;
			conn->vals = old_vals;
			goto err_out;
		}

		/* AUT-05: Preauth HashId must specifically be SHA512 (MS-SMB2 §3.3.5.4) */
		if (conn->preauth_info->Preauth_HashId != SMB2_PREAUTH_INTEGRITY_SHA512) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			rc = -EINVAL;
			kfree(conn->preauth_info);
			conn->preauth_info = NULL;
			goto err_out;
		}

		rc = init_smb3_11_server(conn);
		if (rc < 0) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			kfree(conn->preauth_info);
			conn->preauth_info = NULL;
			conn->vals = old_vals;
			goto err_out;
		}

		ksmbd_gen_preauth_integrity_hash(conn,
						 work->request_buf,
						 conn->preauth_info->Preauth_HashValue);
		rsp->NegotiateContextOffset =
				cpu_to_le32(OFFSET_OF_NEG_CONTEXT);
		rc = assemble_neg_contexts(conn, rsp, work->response_sz);
		if (rc < 0) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			kfree(conn->preauth_info);
			conn->preauth_info = NULL;
			kfree(old_vals);
			goto err_out;
		}
		neg_ctxt_len = (unsigned int)rc;
		rc = 0;
		break;
	case SMB302_PROT_ID:
		rc = init_smb3_02_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			conn->vals = old_vals;
			goto err_out;
		}
		break;
	case SMB30_PROT_ID:
		rc = init_smb3_0_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			conn->vals = old_vals;
			goto err_out;
		}
		break;
	case SMB21_PROT_ID:
		rc = init_smb2_1_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			conn->vals = old_vals;
			goto err_out;
		}
		break;
	case SMB20_PROT_ID:
		rc = init_smb2_0_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			conn->vals = old_vals;
			goto err_out;
		}
		break;
	case SMB2X_PROT_ID:
	case BAD_PROT_ID:
	default:
		ksmbd_debug(SMB, "Server dialect :0x%x not supported\n",
			    conn->dialect);
		rsp->hdr.Status = STATUS_NOT_SUPPORTED;
		rc = -EINVAL;
		conn->vals = old_vals;
		goto err_out;
	}
	/* New vals allocated successfully, free the old one */
	kfree(old_vals);
	}
	rsp->Capabilities = cpu_to_le32(conn->vals->capabilities);

	/* For stats */
	conn->connection_type = conn->dialect;

	rsp->MaxTransactSize = cpu_to_le32(conn->vals->max_trans_size);
	rsp->MaxReadSize = cpu_to_le32(conn->vals->max_read_size);
	rsp->MaxWriteSize = cpu_to_le32(conn->vals->max_write_size);

	if (conn->dialect >= SMB20_PROT_ID) {
		memcpy(conn->ClientGUID, req->ClientGUID,
		       SMB2_CLIENT_GUID_SIZE);
		conn->cli_sec_mode = le16_to_cpu(req->SecurityMode);
	}

	rsp->StructureSize = cpu_to_le16(65);
	rsp->DialectRevision = cpu_to_le16(conn->dialect);
	/*
	 * NEG-04: ServerGUID is initialized once at module startup
	 * (ksmbd_server_init) via get_random_bytes() to eliminate the lazy-
	 * init race where two simultaneous first-negotiate requests could each
	 * see all-zero GUID, generate different values, and the last writer
	 * wins — breaking multichannel and durable-handle reconnect.
	 */
	memcpy(rsp->ServerGUID, server_conf.server_guid,
	       SMB2_CLIENT_GUID_SIZE);

	/*
	 * B.2: ServerStartTime must reflect actual server start time per
	 * MS-SMB2 §2.2.4.  Record it lazily on first negotiate.
	 */
	if (!server_conf.server_start_time)
		server_conf.server_start_time = ksmbd_systime();

	rsp->SystemTime = cpu_to_le64(ksmbd_systime());
	rsp->ServerStartTime = cpu_to_le64(server_conf.server_start_time);
	ksmbd_debug(SMB, "negotiate context offset %d, count %d\n",
		    le32_to_cpu(rsp->NegotiateContextOffset),
		    le16_to_cpu(rsp->NegotiateContextCount));

	rsp->SecurityBufferOffset = cpu_to_le16(128);
	rsp->SecurityBufferLength = cpu_to_le16(AUTH_GSS_LENGTH);
	ksmbd_copy_gss_neg_header((char *)(&rsp->hdr) +
				  le16_to_cpu(rsp->SecurityBufferOffset));
	rsp->SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED_LE;
	conn->use_spnego = true;

	if (server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY) {
		rsp->SecurityMode |= SMB2_NEGOTIATE_SIGNING_REQUIRED_LE;
		conn->sign = true;
	} else if (server_conf.signing == KSMBD_CONFIG_OPT_AUTO) {
		/*
		 * When AUTO, enable signing if the client advertises
		 * signing capability. This prevents a MITM from
		 * stripping the SIGNING_REQUIRED flag to downgrade
		 * the connection to unsigned.
		 */
		if (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_ENABLED_LE)
			conn->sign = true;
	} else if (server_conf.signing == KSMBD_CONFIG_OPT_DISABLED &&
		   req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED_LE) {
		conn->sign = true;
	}

	/*
	 * MS-SMB2 §3.3.5.3.1: If the client sets SIGNING_REQUIRED in its
	 * SecurityMode, the server MUST also set SIGNING_REQUIRED in the
	 * negotiate response.  This prevents a MITM from stripping the flag.
	 */
	if (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED_LE) {
		rsp->SecurityMode |= SMB2_NEGOTIATE_SIGNING_REQUIRED_LE;
		conn->sign = true;
	}

	conn->srv_sec_mode = le16_to_cpu(rsp->SecurityMode);
	ksmbd_conn_set_need_setup(conn);

err_out:
	ksmbd_conn_unlock(conn);
	if (rc && rsp->hdr.Status == 0)
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;

	if (!rc)
		rc = ksmbd_iov_pin_rsp(work, rsp,
				       sizeof(struct smb2_negotiate_rsp) +
					AUTH_GSS_LENGTH + neg_ctxt_len);
	if (rc < 0)
		smb2_set_err_rsp(work);
	return rc;
}
