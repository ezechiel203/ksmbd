// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_session.c - Session setup + authentication
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

static int alloc_preauth_hash(struct ksmbd_session *sess,
			      struct ksmbd_conn *conn)
{
	if (sess->Preauth_HashValue)
		return 0;

	if (!conn->preauth_info)
		return -ENOMEM;

	sess->Preauth_HashValue = kmemdup(conn->preauth_info->Preauth_HashValue,
					  PREAUTH_HASHVALUE_SIZE, KSMBD_DEFAULT_GFP);
	if (!sess->Preauth_HashValue)
		return -ENOMEM;

	return 0;
}

static int generate_preauth_hash(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	u8 *preauth_hash;

	if (conn->dialect != SMB311_PROT_ID)
		return 0;

	if (conn->binding) {
		struct preauth_session *preauth_sess;

		preauth_sess = ksmbd_preauth_session_lookup(conn, sess->id);
		if (!preauth_sess) {
			preauth_sess = ksmbd_preauth_session_alloc(conn, sess->id);
			if (!preauth_sess)
				return -ENOMEM;
		}

		preauth_hash = preauth_sess->Preauth_HashValue;
	} else {
		if (!sess->Preauth_HashValue)
			if (alloc_preauth_hash(sess, conn))
				return -ENOMEM;
		preauth_hash = sess->Preauth_HashValue;
	}

	ksmbd_gen_preauth_integrity_hash(conn, work->request_buf, preauth_hash);
	return 0;
}

static int decode_negotiation_token(struct ksmbd_conn *conn,
				    struct negotiate_message *negblob,
				    size_t sz)
{
	if (!conn->use_spnego)
		return -EINVAL;

	if (ksmbd_decode_negTokenInit((char *)negblob, sz, conn)) {
		if (ksmbd_decode_negTokenTarg((char *)negblob, sz, conn)) {
			conn->auth_mechs |= KSMBD_AUTH_NTLMSSP;
			conn->preferred_auth_mech = KSMBD_AUTH_NTLMSSP;
			conn->use_spnego = false;
		}
	}
	return 0;
}

static int ntlm_negotiate(struct ksmbd_work *work,
			  struct negotiate_message *negblob,
			  size_t negblob_len, struct smb2_sess_setup_rsp *rsp)
{
	struct challenge_message *chgblob;
	unsigned char *spnego_blob = NULL;
	u16 spnego_blob_len;
	char *neg_blob;
	int sz, rc;

	ksmbd_debug(SMB, "negotiate phase\n");
	rc = ksmbd_decode_ntlmssp_neg_blob(negblob, negblob_len, work->conn);
	if (rc)
		return rc;

	sz = le16_to_cpu(rsp->SecurityBufferOffset);
	chgblob = (struct challenge_message *)rsp->Buffer;
	memset(chgblob, 0, sizeof(struct challenge_message));

	if (!work->conn->use_spnego) {
		sz = ksmbd_build_ntlmssp_challenge_blob(chgblob, work->conn);
		if (sz < 0)
			return -ENOMEM;

		rsp->SecurityBufferLength = cpu_to_le16(sz);
		return 0;
	}

	sz = sizeof(struct challenge_message);
	sz += (strlen(ksmbd_netbios_name()) * 2 + 1 + 4) * 6;

	neg_blob = kzalloc(sz, KSMBD_DEFAULT_GFP);
	if (!neg_blob)
		return -ENOMEM;

	chgblob = (struct challenge_message *)neg_blob;
	sz = ksmbd_build_ntlmssp_challenge_blob(chgblob, work->conn);
	if (sz < 0) {
		rc = -ENOMEM;
		goto out;
	}

	rc = build_spnego_ntlmssp_neg_blob(&spnego_blob, &spnego_blob_len,
					   neg_blob, sz);
	if (rc) {
		rc = -ENOMEM;
		goto out;
	}

	if (spnego_blob_len > work->response_sz -
	    ((char *)rsp->Buffer - (char *)work->response_buf)) {
		rc = -ENOMEM;
		kfree(spnego_blob);
		goto out;
	}

	memcpy(rsp->Buffer, spnego_blob, spnego_blob_len);
	rsp->SecurityBufferLength = cpu_to_le16(spnego_blob_len);

out:
	kfree(spnego_blob);
	kfree(neg_blob);
	return rc;
}

static struct authenticate_message *user_authblob(struct ksmbd_conn *conn,
						  struct smb2_sess_setup_req *req)
{
	int sz;

	if (conn->use_spnego && conn->mechToken)
		return (struct authenticate_message *)conn->mechToken;

	sz = le16_to_cpu(req->SecurityBufferOffset);
	return (struct authenticate_message *)((char *)&req->hdr.ProtocolId
					       + sz);
}

static struct ksmbd_user *session_user(struct ksmbd_conn *conn,
				       struct smb2_sess_setup_req *req)
{
	struct authenticate_message *authblob;
	struct ksmbd_user *user;
	char *name;
	unsigned int name_off, name_len, secbuf_len;

	if (conn->use_spnego && conn->mechToken)
		secbuf_len = conn->mechTokenLen;
	else
		secbuf_len = le16_to_cpu(req->SecurityBufferLength);
	if (secbuf_len < sizeof(struct authenticate_message)) {
		ksmbd_debug(SMB, "blob len %d too small\n", secbuf_len);
		return NULL;
	}
	authblob = user_authblob(conn, req);
	name_off = le32_to_cpu(authblob->UserName.BufferOffset);
	name_len = le16_to_cpu(authblob->UserName.Length);

	if (secbuf_len < (u64)name_off + name_len)
		return NULL;

	name = smb_strndup_from_utf16((const char *)authblob + name_off,
				      name_len,
				      true,
				      conn->local_nls);
	if (IS_ERR(name)) {
		pr_err("cannot allocate memory\n");
		return NULL;
	}

	ksmbd_debug(SMB, "session setup request for user %s\n", name);
	user = ksmbd_login_user(name);
	kfree(name);
	return user;
}

static int ntlm_authenticate(struct ksmbd_work *work,
			     struct smb2_sess_setup_req *req,
			     struct smb2_sess_setup_rsp *rsp)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	struct channel *chann = NULL, *old;
	struct ksmbd_user *user;
	u64 prev_id;
	int sz, rc;

	ksmbd_debug(SMB, "authenticate phase\n");
	if (conn->use_spnego) {
		unsigned char *spnego_blob;
		u16 spnego_blob_len;

		rc = build_spnego_ntlmssp_auth_blob(&spnego_blob,
						    &spnego_blob_len,
						    0);
		if (rc)
			return -ENOMEM;

		if (spnego_blob_len > work->response_sz -
		    ((char *)rsp->Buffer - (char *)work->response_buf)) {
			kfree(spnego_blob);
			return -ENOMEM;
		}

		memcpy(rsp->Buffer, spnego_blob, spnego_blob_len);
		rsp->SecurityBufferLength = cpu_to_le16(spnego_blob_len);
		kfree(spnego_blob);
	}

	user = session_user(conn, req);
	if (!user) {
		ksmbd_debug(SMB, "Unknown user name or an error\n");
		return -EPERM;
	}

	/* Check for previous session */
	prev_id = le64_to_cpu(req->PreviousSessionId);
	if (prev_id && prev_id != sess->id)
		destroy_previous_session(conn, user, prev_id);

	down_read(&sess->state_lock);
	if (sess->state == SMB2_SESSION_VALID) {
		up_read(&sess->state_lock);
		/*
		 * Reuse session if anonymous try to connect
		 * on reauthetication.
		 */
		if (conn->binding == false && ksmbd_anonymous_user(user)) {
			ksmbd_free_user(user);
			return 0;
		}

		if (!ksmbd_compare_user(sess->user, user)) {
			ksmbd_free_user(user);
			return -EPERM;
		}
		ksmbd_free_user(user);
	} else {
		up_read(&sess->state_lock);
		sess->user = user;
	}

	if (conn->binding == false && user_guest(sess->user)) {
		rsp->SessionFlags = SMB2_SESSION_FLAG_IS_GUEST_LE;
	} else {
		struct authenticate_message *authblob;

		authblob = user_authblob(conn, req);
		if (conn->use_spnego && conn->mechToken)
			sz = conn->mechTokenLen;
		else
			sz = le16_to_cpu(req->SecurityBufferLength);
		rc = ksmbd_decode_ntlmssp_auth_blob(authblob, sz, conn, sess);
		if (rc) {
			set_user_flag(sess->user, KSMBD_USER_FLAG_BAD_PASSWORD);
			ksmbd_debug(SMB, "authentication failed\n");
			return -EPERM;
		}
	}

	/*
	 * If session state is SMB2_SESSION_VALID, We can assume
	 * that it is reauthentication. And the user/password
	 * has been verified, so return it here.
	 */
	down_read(&sess->state_lock);
	if (sess->state == SMB2_SESSION_VALID) {
		up_read(&sess->state_lock);
		if (conn->binding)
			goto binding_session;
		return 0;
	}
	up_read(&sess->state_lock);

	if ((rsp->SessionFlags != SMB2_SESSION_FLAG_IS_GUEST_LE &&
	     (conn->sign || server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY)) ||
	    (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED))
		sess->sign = true;

	if (smb3_encryption_negotiated(conn) &&
			!(req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {
		rc = conn->ops->generate_encryptionkey(conn, sess);
		if (rc) {
			ksmbd_debug(SMB,
					"SMB3 encryption key generation failed\n");
			return -EINVAL;
		}
		sess->enc = true;
		if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION)
			rsp->SessionFlags = SMB2_SESSION_FLAG_ENCRYPT_DATA_LE;
		/*
		 * signing is disable if encryption is enable
		 * on this session
		 */
		sess->sign = false;
	}

binding_session:
	if (conn->dialect >= SMB30_PROT_ID) {
		chann = lookup_chann_list(sess, conn);
		if (!chann) {
			chann = kmalloc(sizeof(struct channel), KSMBD_DEFAULT_GFP);
			if (!chann)
				return -ENOMEM;

			chann->conn = conn;
			old = xa_store(&sess->ksmbd_chann_list, (long)conn, chann,
					KSMBD_DEFAULT_GFP);
			if (xa_is_err(old)) {
				kfree(chann);
				return xa_err(old);
			}
		}
	}

	if (conn->ops->generate_signingkey) {
		rc = conn->ops->generate_signingkey(sess, conn);
		if (rc) {
			ksmbd_debug(SMB, "SMB3 signing key generation failed\n");
			return -EINVAL;
		}
	}

	if (conn->dialect > SMB20_PROT_ID) {
		if (!ksmbd_conn_lookup_dialect(conn)) {
			pr_err_ratelimited("fail to verify the dialect\n");
			return -ENOENT;
		}
	}
	return 0;
}

static int krb5_authenticate(struct ksmbd_work *work,
			     struct smb2_sess_setup_req *req,
			     struct smb2_sess_setup_rsp *rsp)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	char *in_blob, *out_blob;
	struct channel *chann = NULL, *old;
	u64 prev_sess_id;
	int in_len, out_len;
	int retval;

	if ((u64)le16_to_cpu(req->SecurityBufferOffset) +
	    le16_to_cpu(req->SecurityBufferLength) >
	    get_rfc1002_len(work->request_buf) + 4)
		return -EINVAL;

	in_blob = (char *)&req->hdr.ProtocolId +
		le16_to_cpu(req->SecurityBufferOffset);
	in_len = le16_to_cpu(req->SecurityBufferLength);
	out_blob = (char *)&rsp->hdr.ProtocolId +
		le16_to_cpu(rsp->SecurityBufferOffset);
	out_len = work->response_sz -
		(le16_to_cpu(rsp->SecurityBufferOffset) + 4);

	retval = ksmbd_krb5_authenticate(sess, in_blob, in_len,
					 out_blob, &out_len);
	if (retval) {
		ksmbd_debug(SMB, "krb5 authentication failed\n");
		return -EINVAL;
	}

	/* Check previous session */
	prev_sess_id = le64_to_cpu(req->PreviousSessionId);
	if (prev_sess_id && prev_sess_id != sess->id)
		destroy_previous_session(conn, sess->user, prev_sess_id);

	rsp->SecurityBufferLength = cpu_to_le16(out_len);

	/*
	 * If session state is SMB2_SESSION_VALID, We can assume
	 * that it is reauthentication. And the user/password
	 * has been verified, so return it here.
	 */
	down_read(&sess->state_lock);
	if (sess->state == SMB2_SESSION_VALID) {
		up_read(&sess->state_lock);
		if (conn->binding)
			goto binding_session;
		return 0;
	}
	up_read(&sess->state_lock);

	if ((rsp->SessionFlags != SMB2_SESSION_FLAG_IS_GUEST_LE &&
	    (conn->sign || server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY)) ||
	    (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED))
		sess->sign = true;

	if (smb3_encryption_negotiated(conn) &&
	    !(req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {
		retval = conn->ops->generate_encryptionkey(conn, sess);
		if (retval) {
			ksmbd_debug(SMB,
				    "SMB3 encryption key generation failed\n");
			return -EINVAL;
		}
		sess->enc = true;
		if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION)
			rsp->SessionFlags = SMB2_SESSION_FLAG_ENCRYPT_DATA_LE;
		sess->sign = false;
	}

binding_session:
	if (conn->dialect >= SMB30_PROT_ID) {
		chann = lookup_chann_list(sess, conn);
		if (!chann) {
			chann = kmalloc(sizeof(struct channel), KSMBD_DEFAULT_GFP);
			if (!chann)
				return -ENOMEM;

			chann->conn = conn;
			old = xa_store(&sess->ksmbd_chann_list, (long)conn,
					chann, KSMBD_DEFAULT_GFP);
			if (xa_is_err(old)) {
				kfree(chann);
				return xa_err(old);
			}
		}
	}

	if (conn->ops->generate_signingkey) {
		retval = conn->ops->generate_signingkey(sess, conn);
		if (retval) {
			ksmbd_debug(SMB, "SMB3 signing key generation failed\n");
			return -EINVAL;
		}
	}

	if (conn->dialect > SMB20_PROT_ID) {
		if (!ksmbd_conn_lookup_dialect(conn)) {
			pr_err_ratelimited("fail to verify the dialect\n");
			return -ENOENT;
		}
	}
	return 0;
}

int smb2_sess_setup(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_sess_setup_req *req;
	struct smb2_sess_setup_rsp *rsp;
	struct ksmbd_session *sess;
	struct negotiate_message *negblob;
	unsigned int negblob_len, negblob_off;
	int rc = 0;

	ksmbd_debug(SMB, "Received smb2 session setup request\n");

	if (!ksmbd_conn_need_setup(conn) && !ksmbd_conn_good(conn)) {
		work->send_no_response = 1;
		return rc;
	}

	WORK_BUFFERS(work, req, rsp);

	rsp->StructureSize = cpu_to_le16(9);
	rsp->SessionFlags = 0;
	rsp->SecurityBufferOffset = cpu_to_le16(72);
	rsp->SecurityBufferLength = 0;

	ksmbd_conn_lock(conn);
	if (!req->hdr.SessionId) {
		sess = ksmbd_smb2_session_create();
		if (!sess) {
			rc = -ENOMEM;
			goto out_err;
		}
		rsp->hdr.SessionId = cpu_to_le64(sess->id);
		rc = ksmbd_session_register(conn, sess);
		if (rc)
			goto out_err;

		conn->binding = false;
	} else if (conn->dialect >= SMB30_PROT_ID &&
		   (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL) &&
		   req->Flags & SMB2_SESSION_REQ_FLAG_BINDING) {
		u64 sess_id = le64_to_cpu(req->hdr.SessionId);

		sess = ksmbd_session_lookup_slowpath(sess_id);
		if (!sess) {
			rc = -ENOENT;
			goto out_err;
		}

		if (conn->dialect != sess->dialect) {
			rc = -EINVAL;
			goto out_err;
		}

		if (!(req->hdr.Flags & SMB2_FLAGS_SIGNED)) {
			rc = -EINVAL;
			goto out_err;
		}

		if (memcmp(conn->ClientGUID, sess->ClientGUID,
			   SMB2_CLIENT_GUID_SIZE)) {
			rc = -ENOENT;
			goto out_err;
		}

		down_read(&sess->state_lock);
		if (sess->state == SMB2_SESSION_IN_PROGRESS) {
			up_read(&sess->state_lock);
			rc = -EACCES;
			goto out_err;
		}

		if (sess->state == SMB2_SESSION_EXPIRED) {
			up_read(&sess->state_lock);
			rc = -EFAULT;
			goto out_err;
		}
		up_read(&sess->state_lock);

		if (ksmbd_conn_need_reconnect(conn)) {
			rc = -EFAULT;
			ksmbd_user_session_put(sess);
			sess = NULL;
			goto out_err;
		}

		if (is_ksmbd_session_in_connection(conn, sess_id)) {
			rc = -EACCES;
			goto out_err;
		}

			conn->binding = true;
		} else if ((conn->dialect < SMB30_PROT_ID ||
			    !(server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL)) &&
		   (req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {
		sess = NULL;
		rc = -EACCES;
		goto out_err;
	} else {
		sess = ksmbd_session_lookup(conn,
					    le64_to_cpu(req->hdr.SessionId));
		if (!sess) {
			rc = -ENOENT;
			goto out_err;
		}

		down_read(&sess->state_lock);
		if (sess->state == SMB2_SESSION_EXPIRED) {
			up_read(&sess->state_lock);
			rc = -EFAULT;
			goto out_err;
		}
		up_read(&sess->state_lock);

		if (ksmbd_conn_need_reconnect(conn)) {
			rc = -EFAULT;
			ksmbd_user_session_put(sess);
			sess = NULL;
			goto out_err;
		}

		conn->binding = false;
	}
	work->sess = sess;

	negblob_off = le16_to_cpu(req->SecurityBufferOffset);
	negblob_len = le16_to_cpu(req->SecurityBufferLength);
	if (negblob_off < offsetof(struct smb2_sess_setup_req, Buffer)) {
		rc = -EINVAL;
		goto out_err;
	}

	if ((u64)negblob_off + negblob_len > get_rfc1002_len(work->request_buf) + 4) {
		rc = -EINVAL;
		goto out_err;
	}

	negblob = (struct negotiate_message *)((char *)&req->hdr.ProtocolId +
			negblob_off);

	if (decode_negotiation_token(conn, negblob, negblob_len) == 0) {
		if (conn->mechToken) {
			negblob = (struct negotiate_message *)conn->mechToken;
			negblob_len = conn->mechTokenLen;
		}
	}

	if (negblob_len < offsetof(struct negotiate_message, NegotiateFlags)) {
		rc = -EINVAL;
		goto out_err;
	}

	if (server_conf.auth_mechs & conn->auth_mechs) {
		rc = generate_preauth_hash(work);
		if (rc)
			goto out_err;

		if (conn->preferred_auth_mech &
				(KSMBD_AUTH_KRB5 | KSMBD_AUTH_MSKRB5)) {
			rc = krb5_authenticate(work, req, rsp);
			if (rc) {
				rc = -EINVAL;
				goto out_err;
			}

			if (!ksmbd_conn_need_reconnect(conn)) {
				ksmbd_conn_set_good(conn);
				down_write(&sess->state_lock);
				sess->state = SMB2_SESSION_VALID;
				up_write(&sess->state_lock);
			}
		} else if (conn->preferred_auth_mech == KSMBD_AUTH_NTLMSSP) {
			if (negblob->MessageType == NtLmNegotiate) {
				rc = ntlm_negotiate(work, negblob, negblob_len, rsp);
				if (rc)
					goto out_err;
				rsp->hdr.Status =
					STATUS_MORE_PROCESSING_REQUIRED;
			} else if (negblob->MessageType == NtLmAuthenticate) {
				rc = ntlm_authenticate(work, req, rsp);
				if (rc)
					goto out_err;

				if (!ksmbd_conn_need_reconnect(conn)) {
					ksmbd_conn_set_good(conn);
					down_write(&sess->state_lock);
					sess->state = SMB2_SESSION_VALID;
					up_write(&sess->state_lock);
				}
				if (conn->binding) {
					struct preauth_session *preauth_sess;

					preauth_sess =
						ksmbd_preauth_session_lookup(conn, sess->id);
					if (preauth_sess) {
						list_del(&preauth_sess->preauth_entry);
						kfree(preauth_sess);
					}
				}
			} else {
				pr_info_ratelimited("Unknown NTLMSSP message type : 0x%x\n",
						le32_to_cpu(negblob->MessageType));
				rc = -EINVAL;
			}
		} else {
			/* TODO: need one more negotiation */
			pr_err_ratelimited("Not support the preferred authentication\n");
			rc = -EINVAL;
		}
	} else {
		pr_err_ratelimited("Not support authentication\n");
		rc = -EINVAL;
	}

out_err:
	if (rc == -EINVAL)
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
	else if (rc == -ENOENT)
		rsp->hdr.Status = STATUS_USER_SESSION_DELETED;
	else if (rc == -EACCES)
		rsp->hdr.Status = STATUS_REQUEST_NOT_ACCEPTED;
	else if (rc == -EFAULT)
		rsp->hdr.Status = STATUS_NETWORK_SESSION_EXPIRED;
	else if (rc == -ENOMEM)
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
	else if (rc)
		rsp->hdr.Status = STATUS_LOGON_FAILURE;

	if (conn->use_spnego && conn->mechToken) {
		kfree(conn->mechToken);
		conn->mechToken = NULL;
	}

	if (rc < 0) {
		/*
		 * SecurityBufferOffset should be set to zero
		 * in session setup error response.
		 */
		rsp->SecurityBufferOffset = 0;

		if (sess) {
			bool try_delay = false;

			/*
			 * To mitigate dictionary attacks, force the client to
			 * reconnect on auth failure. The TCP handshake provides
			 * natural rate limiting (~100-300ms per attempt).
			 */
			if (sess->user && sess->user->flags & KSMBD_USER_FLAG_DELAY_SESSION)
				try_delay = true;

			sess->last_active = jiffies;
			down_write(&sess->state_lock);
			sess->state = SMB2_SESSION_EXPIRED;
			up_write(&sess->state_lock);
			ksmbd_user_session_put(sess);
			work->sess = NULL;
			if (try_delay) {
				pr_info_ratelimited("Auth failure from %pIS, forcing reconnect\n",
						    KSMBD_TCP_PEER_SOCKADDR(conn));
				ksmbd_conn_set_need_reconnect(conn);
			}
		}
		smb2_set_err_rsp(work);
	} else {
		unsigned int iov_len;

		if (rsp->SecurityBufferLength)
			iov_len = offsetof(struct smb2_sess_setup_rsp, Buffer) +
				le16_to_cpu(rsp->SecurityBufferLength);
		else
			iov_len = sizeof(struct smb2_sess_setup_rsp);
		rc = ksmbd_iov_pin_rsp(work, rsp, iov_len);
		if (rc)
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
	}

	ksmbd_conn_unlock(conn);
	return rc;
}
