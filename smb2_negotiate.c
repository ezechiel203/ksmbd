// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_negotiate.c - Negotiate contexts + SMB2_NEGOTIATE handler
 */

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/ethtool.h>
#include <linux/falloc.h>
#include <linux/crc32.h>
#include <linux/mount.h>
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

static unsigned int assemble_neg_contexts(struct ksmbd_conn *conn,
				  struct smb2_negotiate_rsp *rsp)
{
	char * const pneg_ctxt = (char *)rsp +
			le32_to_cpu(rsp->NegotiateContextOffset);
	int neg_ctxt_cnt = 1;
	int ctxt_size;

	ksmbd_debug(SMB,
		    "assemble SMB2_PREAUTH_INTEGRITY_CAPABILITIES context\n");
	build_preauth_ctxt((struct smb2_preauth_neg_context *)pneg_ctxt,
			   conn->preauth_info->Preauth_HashId);
	ctxt_size = sizeof(struct smb2_preauth_neg_context);

	if (conn->cipher_type) {
		/* Round to 8 byte boundary */
		ctxt_size = round_up(ctxt_size, 8);
		ksmbd_debug(SMB,
			    "assemble SMB2_ENCRYPTION_CAPABILITIES context\n");
		build_encrypt_ctxt((struct smb2_encryption_neg_context *)
				   (pneg_ctxt + ctxt_size),
				   conn->cipher_type);
		neg_ctxt_cnt++;
		ctxt_size += sizeof(struct smb2_encryption_neg_context) + 2;
	}

	/* compression context not yet supported */
	WARN_ON(conn->compress_algorithm != SMB3_COMPRESS_NONE);

	if (conn->posix_ext_supported) {
		ctxt_size = round_up(ctxt_size, 8);
		ksmbd_debug(SMB,
			    "assemble SMB2_POSIX_EXTENSIONS_AVAILABLE context\n");
		build_posix_ctxt((struct smb2_posix_neg_context *)
				 (pneg_ctxt + ctxt_size));
		neg_ctxt_cnt++;
		ctxt_size += sizeof(struct smb2_posix_neg_context);
	}

	if (conn->signing_negotiated) {
		ctxt_size = round_up(ctxt_size, 8);
		ksmbd_debug(SMB,
			    "assemble SMB2_SIGNING_CAPABILITIES context\n");
		build_sign_cap_ctxt((struct smb2_signing_capabilities *)
				    (pneg_ctxt + ctxt_size),
				    conn->signing_algorithm);
		neg_ctxt_cnt++;
		ctxt_size += sizeof(struct smb2_signing_capabilities) + 2;
	}

	if (conn->rdma_transform_count) {
		ctxt_size = round_up(ctxt_size, 8);
		ksmbd_debug(SMB,
			    "assemble SMB2_RDMA_TRANSFORM_CAPABILITIES context\n");
		build_rdma_transform_ctxt(
			(struct smb2_rdma_transform_capabilities *)
			(pneg_ctxt + ctxt_size), conn);
		neg_ctxt_cnt++;
		ctxt_size += sizeof(struct smb2_rdma_transform_capabilities)
			     + conn->rdma_transform_count * sizeof(__le16);
	}

	rsp->NegotiateContextCount = cpu_to_le16(neg_ctxt_cnt);
	return ctxt_size + AUTH_GSS_PADDING;
}

static __le32 decode_preauth_ctxt(struct ksmbd_conn *conn,
				  struct smb2_preauth_neg_context *pneg_ctxt,
				  int ctxt_len)
{
	/*
	 * sizeof(smb2_preauth_neg_context) assumes SMB311_SALT_SIZE Salt,
	 * which may not be present. Only check for used HashAlgorithms[1].
	 */
	if (ctxt_len <
	    sizeof(struct smb2_neg_context) + MIN_PREAUTH_CTXT_DATA_LEN)
		return STATUS_INVALID_PARAMETER;

	if (pneg_ctxt->HashAlgorithms != SMB2_PREAUTH_INTEGRITY_SHA512)
		return STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP;

	conn->preauth_info->Preauth_HashId = SMB2_PREAUTH_INTEGRITY_SHA512;
	return STATUS_SUCCESS;
}

static void decode_encrypt_ctxt(struct ksmbd_conn *conn,
				struct smb2_encryption_neg_context *pneg_ctxt,
				int ctxt_len)
{
	int cph_cnt;
	int i, cphs_size;

	if (sizeof(struct smb2_encryption_neg_context) > ctxt_len) {
		pr_err_ratelimited("Invalid SMB2_ENCRYPTION_CAPABILITIES context size\n");
		return;
	}

	conn->cipher_type = 0;

	cph_cnt = le16_to_cpu(pneg_ctxt->CipherCount);
	cphs_size = cph_cnt * sizeof(__le16);

	if (sizeof(struct smb2_encryption_neg_context) + cphs_size >
	    ctxt_len) {
		pr_err_ratelimited("Invalid cipher count(%d)\n", cph_cnt);
		return;
	}

	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF)
		return;

	for (i = 0; i < cph_cnt; i++) {
		if (pneg_ctxt->Ciphers[i] == SMB2_ENCRYPTION_AES128_GCM ||
		    pneg_ctxt->Ciphers[i] == SMB2_ENCRYPTION_AES128_CCM ||
		    pneg_ctxt->Ciphers[i] == SMB2_ENCRYPTION_AES256_CCM ||
		    pneg_ctxt->Ciphers[i] == SMB2_ENCRYPTION_AES256_GCM) {
			ksmbd_debug(SMB, "Cipher ID = 0x%x\n",
				    pneg_ctxt->Ciphers[i]);
			conn->cipher_type = pneg_ctxt->Ciphers[i];
			break;
		}
	}
}

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

static void decode_compress_ctxt(struct ksmbd_conn *conn,
				 struct smb2_compression_ctx *pneg_ctxt)
{
	conn->compress_algorithm = SMB3_COMPRESS_NONE;
}

static void decode_sign_cap_ctxt(struct ksmbd_conn *conn,
				 struct smb2_signing_capabilities *pneg_ctxt,
				 int ctxt_len)
{
	int sign_algo_cnt;
	int i, sign_alos_size;
	int best_priority = -1;
	__le16 best_algo = 0;

	if (sizeof(struct smb2_signing_capabilities) > ctxt_len) {
		pr_err_ratelimited("Invalid SMB2_SIGNING_CAPABILITIES context length\n");
		return;
	}

	conn->signing_negotiated = false;
	sign_algo_cnt = le16_to_cpu(pneg_ctxt->SigningAlgorithmCount);
	sign_alos_size = sign_algo_cnt * sizeof(__le16);

	if (sizeof(struct smb2_signing_capabilities) + sign_alos_size >
	    ctxt_len) {
		pr_err_ratelimited("Invalid signing algorithm count(%d)\n", sign_algo_cnt);
		return;
	}

	/*
	 * Select the best mutually supported signing algorithm.
	 * Priority order: AES-GMAC (highest) > AES-CMAC > HMAC-SHA256.
	 */
	for (i = 0; i < sign_algo_cnt; i++) {
		int priority = -1;

		if (pneg_ctxt->SigningAlgorithms[i] == SIGNING_ALG_HMAC_SHA256)
			priority = 0;
		else if (pneg_ctxt->SigningAlgorithms[i] == SIGNING_ALG_AES_CMAC)
			priority = 1;
		else if (pneg_ctxt->SigningAlgorithms[i] == SIGNING_ALG_AES_GMAC)
			priority = 2;

		if (priority > best_priority) {
			best_priority = priority;
			best_algo = pneg_ctxt->SigningAlgorithms[i];
		}
	}

	if (best_priority >= 0) {
		ksmbd_debug(SMB, "Signing Algorithm ID = 0x%x\n",
			    le16_to_cpu(best_algo));
		conn->signing_negotiated = true;
		conn->signing_algorithm = best_algo;
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

	xforms_size = xform_cnt * sizeof(__le16);

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

static __le32 deassemble_neg_contexts(struct ksmbd_conn *conn,
				      struct smb2_negotiate_req *req,
				      unsigned int len_of_smb)
{
	/* +4 is to account for the RFC1001 len field */
	struct smb2_neg_context *pctx = (struct smb2_neg_context *)req;
	int i = 0, len_of_ctxts;
	unsigned int offset = le32_to_cpu(req->NegotiateContextOffset);
	unsigned int neg_ctxt_cnt = le16_to_cpu(req->NegotiateContextCount);
	__le32 status = STATUS_INVALID_PARAMETER;

	ksmbd_debug(SMB, "decoding %d negotiate contexts\n", neg_ctxt_cnt);
	if (len_of_smb <= offset) {
		ksmbd_debug(SMB, "Invalid response: negotiate context offset\n");
		return status;
	}

	len_of_ctxts = len_of_smb - offset;

	if (neg_ctxt_cnt > 16) {
		pr_err_ratelimited("Too many negotiate contexts: %d\n", neg_ctxt_cnt);
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
			if (conn->preauth_info->Preauth_HashId)
				break;

			status = decode_preauth_ctxt(conn,
						     (struct smb2_preauth_neg_context *)pctx,
						     ctxt_len);
			if (status != STATUS_SUCCESS)
				break;
		} else if (pctx->ContextType == SMB2_ENCRYPTION_CAPABILITIES) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_ENCRYPTION_CAPABILITIES context\n");
			if (conn->cipher_type)
				break;

			decode_encrypt_ctxt(conn,
					    (struct smb2_encryption_neg_context *)pctx,
					    ctxt_len);
		} else if (pctx->ContextType == SMB2_COMPRESSION_CAPABILITIES) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_COMPRESSION_CAPABILITIES context\n");
			if (conn->compress_algorithm)
				break;

			decode_compress_ctxt(conn,
					     (struct smb2_compression_ctx *)pctx);
		} else if (pctx->ContextType == SMB2_NETNAME_NEGOTIATE_CONTEXT_ID) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_NETNAME_NEGOTIATE_CONTEXT_ID context\n");
		} else if (pctx->ContextType == SMB2_POSIX_EXTENSIONS_AVAILABLE) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_POSIX_EXTENSIONS_AVAILABLE context\n");
			conn->posix_ext_supported = true;
		} else if (pctx->ContextType == SMB2_RDMA_TRANSFORM_CAPABILITIES) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_RDMA_TRANSFORM_CAPABILITIES context\n");
			if (conn->rdma_transform_count)
				break;

			decode_rdma_transform_ctxt(conn,
						   (struct smb2_rdma_transform_capabilities *)pctx,
						   ctxt_len);
		} else if (pctx->ContextType == SMB2_SIGNING_CAPABILITIES) {
			ksmbd_debug(SMB,
				    "deassemble SMB2_SIGNING_CAPABILITIES context\n");

			decode_sign_cap_ctxt(conn,
					     (struct smb2_signing_capabilities *)pctx,
					     ctxt_len);
		}

		/* offsets must be 8 byte aligned */
		offset = (ctxt_len + 7) & ~0x7;
		len_of_ctxts -= offset;
	}
	return status;
}

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

	ksmbd_debug(SMB, "Received negotiate request\n");
	conn->need_neg = false;
	if (ksmbd_conn_good(conn)) {
		pr_err_ratelimited("conn->tcp_status is already in CifsGood State\n");
		work->send_no_response = 1;
		return rc;
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

	if (conn->dialect == SMB311_PROT_ID) {
		unsigned int nego_ctxt_off = le32_to_cpu(req->NegotiateContextOffset);

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
	switch (conn->dialect) {
	case SMB311_PROT_ID:
		conn->preauth_info =
			kzalloc(sizeof(struct preauth_integrity_info),
				KSMBD_DEFAULT_GFP);
		if (!conn->preauth_info) {
			rc = -ENOMEM;
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
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
			goto err_out;
		}

		rc = init_smb3_11_server(conn);
		if (rc < 0) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			kfree(conn->preauth_info);
			conn->preauth_info = NULL;
			goto err_out;
		}

		ksmbd_gen_preauth_integrity_hash(conn,
						 work->request_buf,
						 conn->preauth_info->Preauth_HashValue);
		rsp->NegotiateContextOffset =
				cpu_to_le32(OFFSET_OF_NEG_CONTEXT);
		neg_ctxt_len = assemble_neg_contexts(conn, rsp);
		break;
	case SMB302_PROT_ID:
		rc = init_smb3_02_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			goto err_out;
		}
		break;
	case SMB30_PROT_ID:
		rc = init_smb3_0_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			goto err_out;
		}
		break;
	case SMB21_PROT_ID:
		rc = init_smb2_1_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			goto err_out;
		}
		break;
	case SMB20_PROT_ID:
		rc = init_smb2_0_server(conn);
		if (rc) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
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
		goto err_out;
	}
	rsp->Capabilities = cpu_to_le32(conn->vals->capabilities);

	/* For stats */
	conn->connection_type = conn->dialect;

	rsp->MaxTransactSize = cpu_to_le32(conn->vals->max_trans_size);
	rsp->MaxReadSize = cpu_to_le32(conn->vals->max_read_size);
	rsp->MaxWriteSize = cpu_to_le32(conn->vals->max_write_size);

	if (conn->dialect > SMB20_PROT_ID) {
		memcpy(conn->ClientGUID, req->ClientGUID,
		       SMB2_CLIENT_GUID_SIZE);
		conn->cli_sec_mode = le16_to_cpu(req->SecurityMode);
	}

	rsp->StructureSize = cpu_to_le16(65);
	rsp->DialectRevision = cpu_to_le16(conn->dialect);
	/* Not setting conn guid rsp->ServerGUID, as it
	 * not used by client for identifying server
	 */
	memset(rsp->ServerGUID, 0, SMB2_CLIENT_GUID_SIZE);

	rsp->SystemTime = cpu_to_le64(ksmbd_systime());
	rsp->ServerStartTime = 0;
	ksmbd_debug(SMB, "negotiate context offset %d, count %d\n",
		    le32_to_cpu(rsp->NegotiateContextOffset),
		    le16_to_cpu(rsp->NegotiateContextCount));

	rsp->SecurityBufferOffset = cpu_to_le16(128);
	rsp->SecurityBufferLength = cpu_to_le16(AUTH_GSS_LENGTH);
	ksmbd_copy_gss_neg_header((char *)(&rsp->hdr) +
				  le16_to_cpu(rsp->SecurityBufferOffset));
	rsp->SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED_LE;
	conn->use_spnego = true;

	if ((server_conf.signing == KSMBD_CONFIG_OPT_AUTO ||
	     server_conf.signing == KSMBD_CONFIG_OPT_DISABLED) &&
	    req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED_LE)
		conn->sign = true;
	else if (server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY) {
		/*
		 * TODO: server_conf.enforced_signing is a global variable
		 * written without locking. Concurrent negotiate requests
		 * can race here. Ideally this should be a per-connection
		 * flag, but that requires adding a field to ksmbd_conn.
		 */
		server_conf.enforced_signing = true;
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
