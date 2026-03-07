// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_session.c - Session setup + authentication
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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

VISIBLE_IF_KUNIT
int generate_preauth_hash(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	u8 *preauth_hash;

	if (conn->dialect != SMB311_PROT_ID)
		return 0;

	/* TC-07: do not update preauth hash after session is fully authenticated */
	if (sess && sess->state == SMB2_SESSION_VALID)
		return 0;

	if (conn->binding) {
		struct preauth_session *preauth_sess;

		down_write(&conn->session_lock);
		preauth_sess = ksmbd_preauth_session_lookup(conn, sess->id);
		if (!preauth_sess) {
			preauth_sess = ksmbd_preauth_session_alloc(conn, sess->id);
			if (!preauth_sess) {
				up_write(&conn->session_lock);
				return -ENOMEM;
			}
		}

		preauth_hash = preauth_sess->Preauth_HashValue;
		ksmbd_gen_preauth_integrity_hash(conn, work->request_buf,
						 preauth_hash);
		up_write(&conn->session_lock);
		return 0;
	} else {
		if (!sess->Preauth_HashValue)
			if (alloc_preauth_hash(sess, conn))
				return -ENOMEM;
		preauth_hash = sess->Preauth_HashValue;
	}

	ksmbd_gen_preauth_integrity_hash(conn, work->request_buf, preauth_hash);
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(generate_preauth_hash);

VISIBLE_IF_KUNIT
int decode_negotiation_token(struct ksmbd_conn *conn,
				    struct negotiate_message *negblob,
				    size_t sz)
{
	if (!conn->use_spnego)
		return -EINVAL;

	if (ksmbd_decode_negTokenInit((char *)negblob, sz, conn)) {
		if (ksmbd_decode_negTokenTarg((char *)negblob, sz, conn)) {
			kfree(conn->mechToken);
			conn->mechToken = NULL;
			conn->mechTokenLen = 0;
			ksmbd_debug(AUTH,
				    "SPNEGO decode failed, falling back to raw NTLMSSP\n");
			conn->auth_mechs = KSMBD_AUTH_NTLMSSP;
			conn->preferred_auth_mech = KSMBD_AUTH_NTLMSSP;
			conn->use_spnego = false;
		}
	}
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(decode_negotiation_token);

VISIBLE_IF_KUNIT
int ntlm_negotiate(struct ksmbd_work *work,
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
		unsigned int max_blob_sz = work->response_sz -
					   ((char *)rsp->Buffer - (char *)work->response_buf);
		sz = ksmbd_build_ntlmssp_challenge_blob(chgblob, max_blob_sz, work->conn);
		if (sz < 0)
			return -ENOMEM;

		rsp->SecurityBufferLength = cpu_to_le16(sz);
		return 0;
	}

	/* AUTH-06: account for workgroup name which may be longer than server name */
	{
		size_t nb_len = strlen(ksmbd_netbios_name());
		const char *wg = ksmbd_work_group();
		size_t wg_len = wg ? strlen(wg) : 0;
		size_t max_name_len = max(nb_len, wg_len);

		sz = sizeof(struct challenge_message);
		sz += (max_name_len * 2 + 1 + 4) * 6;
	}

	neg_blob = kzalloc(sz, KSMBD_DEFAULT_GFP);
	if (!neg_blob)
		return -ENOMEM;

	chgblob = (struct challenge_message *)neg_blob;
	sz = ksmbd_build_ntlmssp_challenge_blob(chgblob, sz, work->conn);
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
EXPORT_SYMBOL_IF_KUNIT(ntlm_negotiate);

VISIBLE_IF_KUNIT
struct authenticate_message *user_authblob(struct ksmbd_conn *conn,
					   struct smb2_sess_setup_req *req)
{
	int sz;

	if (conn->use_spnego && conn->mechToken)
		return (struct authenticate_message *)conn->mechToken;

	sz = le16_to_cpu(req->SecurityBufferOffset);
	return (struct authenticate_message *)((char *)&req->hdr.ProtocolId
					       + sz);
}
EXPORT_SYMBOL_IF_KUNIT(user_authblob);

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

VISIBLE_IF_KUNIT
int ntlm_authenticate(struct ksmbd_work *work,
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

	/*
	 * SES-03: Save PreviousSessionId now, but defer destroy_previous_session()
	 * until AFTER authentication succeeds (MS-SMB2 §3.3.5.5.3).
	 * Tearing down the previous session before verifying credentials
	 * would expunge a valid session if auth then fails.
	 */
	prev_id = le64_to_cpu(req->PreviousSessionId);

	/*
	 * SES-02: sess->user must be written under state_lock to prevent
	 * a race with concurrent SESSION_SETUP on another channel reading
	 * sess->user. Use down_write so the check-and-write is atomic.
	 */
	down_write(&sess->state_lock);
	if (sess->state == SMB2_SESSION_VALID) {
		up_write(&sess->state_lock);
		/*
		 * Re-authentication (MS-SMB2 3.3.5.2.5): accept the new
		 * credentials and update the session user.  MS-SMB2 allows
		 * re-authentication with different credentials (including
		 * anonymous) on a valid session.
		 */
		if (conn->binding == false) {
			if (ksmbd_compare_user(sess->user, user)) {
				ksmbd_free_user(user);
			} else {
				ksmbd_free_user(sess->user);
				sess->user = user;
			}
		} else {
			ksmbd_free_user(user);
		}
	} else {
		sess->user = user;
		up_write(&sess->state_lock);
	}

	if (conn->binding == false && user_guest(sess->user)) {
		if (server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY) {
			pr_err_ratelimited("Guest login rejected: server requires signing\n");
			return -EACCES;
		}
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
			/*
			 * Preserve -EINVAL for malformed NTLMSSP blobs
			 * so it maps to STATUS_INVALID_PARAMETER.
			 * Other errors map to STATUS_LOGON_FAILURE.
			 */
			if (rc == -EINVAL)
				return -EINVAL;
			return -EPERM;
		}

		/*
		 * SES-03: Authentication succeeded — now safe to tear down the
		 * previous session. Only applies to SMB 3.0+ dialects per spec
		 * (MS-SMB2 §3.3.5.5.3).
		 *
		 * IMPORTANT: release conn->srv_mutex before calling
		 * destroy_previous_session.  That function may call
		 * ksmbd_notify_send_cleanup → ksmbd_conn_write which also
		 * tries to acquire conn->srv_mutex (to serialize TCP writes),
		 * causing a self-deadlock.  Re-acquire after returning.
		 */
		if (prev_id && prev_id != sess->id &&
		    conn->dialect >= SMB30_PROT_ID) {
			ksmbd_conn_unlock(conn);
			destroy_previous_session(conn, user, prev_id);
			ksmbd_conn_lock(conn);
		}

		/*
		 * MS-SMB2 §3.3.5.5.3: set SESSION_FLAG_IS_NULL for
		 * anonymous (null) sessions (NTLMSSP_ANONYMOUS flag set and
		 * NtChallengeResponse length == 0).
		 */
		if (authblob &&
		    le16_to_cpu(authblob->NtChallengeResponse.Length) == 0 &&
		    (le32_to_cpu(authblob->NegotiateFlags) & NTLMSSP_ANONYMOUS)) {
			rsp->SessionFlags |= SMB2_SESSION_FLAG_IS_NULL_LE;
			/* SES-06: Mark session as anonymous to block multichannel binding */
			sess->is_anonymous = true;
		}
	}

	/*
	 * MS-SMB2 §3.3.5.5.2: Re-authentication.
	 *
	 * When the session state is SMB2_SESSION_VALID and conn->binding is
	 * false, the client is performing re-authentication on an already
	 * established session.  The server MUST NOT regenerate the signing
	 * or encryption keys -- the Samba client (and Windows) do not update
	 * their keys during re-auth, so regenerating keys server-side would
	 * cause a signing key mismatch on the response.
	 *
	 * For channel binding requests, fall through to binding_session so
	 * the new channel gets its own signing key.
	 */
	down_read(&sess->state_lock);
	if (sess->state == SMB2_SESSION_VALID) {
		up_read(&sess->state_lock);
		if (conn->binding)
			goto binding_session;
		return 0;
	} else {
		up_read(&sess->state_lock);
	}

	/*
	 * H-01/M-01: Anonymous (null) sessions have no shared secret —
	 * skip signing and encryption setup entirely.  Enabling either on
	 * a null session would use zero/empty-derived keys, which is
	 * weaker than no protection at all and violates MS-SMB2 §3.3.5.5.2.
	 */
	if (rsp->SessionFlags & SMB2_SESSION_FLAG_IS_NULL_LE)
		goto binding_session;

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
		/*
		 * When SMB3 encryption keys are available, signing is
		 * superseded by encryption and MUST be disabled so that
		 * subsequent requests are not required to carry SMB2_FLAGS_SIGNED
		 * (they are authenticated by the Transform header instead).
		 * This restores the original behaviour where sess->sign was
		 * unconditionally cleared whenever sess->enc was set.
		 */
		sess->sign = false;

		/*
		 * B.6: MS-SMB2 §3.3.5.5.2 — if the client sets
		 * SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA (0x04) in the SESSION_SETUP
		 * request Flags field, the server MUST set
		 * SMB2_SESSION_FLAG_ENCRYPT_DATA in the response and encrypt all
		 * subsequent traffic on this session, regardless of the global
		 * encryption setting.
		 *
		 * Note: the global "smb2 encryption = yes" flag enables the
		 * capability (keys are generated above), but does not force
		 * per-session encryption.  Only client request or per-share
		 * settings force encryption.
		 */
		if ((server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION) ||
		    (req->Flags & SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA)) {
			sess->enc_forced = true;
			rsp->SessionFlags |= SMB2_SESSION_FLAG_ENCRYPT_DATA_LE;
		}
	}

binding_session:
	if (conn->dialect >= SMB30_PROT_ID) {
		chann = lookup_chann_list(sess, conn);
		if (!chann) {
			chann = kmalloc(sizeof(struct channel), KSMBD_DEFAULT_GFP);
			if (!chann)
				return -ENOMEM;

			chann->conn = conn;
			atomic64_set(&chann->nonce_counter, 0);

			/*
			 * S3: Insert the channel into the session list before
			 * deriving the signing key (generate_signingkey uses
			 * lookup_chann_list to find the channel).  If key
			 * derivation fails we remove it again, eliminating the
			 * window where the channel is visible without a valid key.
			 */
			old = xa_store(&sess->ksmbd_chann_list, (long)conn, chann,
					KSMBD_DEFAULT_GFP);
			if (xa_is_err(old)) {
				kfree(chann);
				return xa_err(old);
			}

			if (conn->ops->generate_signingkey) {
				rc = conn->ops->generate_signingkey(sess, conn);
				if (rc) {
					ksmbd_debug(SMB, "SMB3 signing key generation failed\n");
					xa_erase(&sess->ksmbd_chann_list, (long)conn);
					kfree(chann);
					return -EINVAL;
				}
			}

			goto ntlm_skip_signingkey;
		}
	}

	/*
	 * MC-01: Per-channel signing key not derived (MS-SMB2 §3.3.5.5.3).
	 * Each channel MUST derive its own Channel.SigningKey using the
	 * channel pre-auth hash as context. Currently all channels share
	 * the session signing key. Full per-channel key derivation requires
	 * storing the channel pre-auth hash and calling generate_key() per
	 * channel — deferred for safety.
	 */
	if (conn->ops->generate_signingkey) {
		rc = conn->ops->generate_signingkey(sess, conn);
		if (rc) {
			ksmbd_debug(SMB, "SMB3 signing key generation failed\n");
			return -EINVAL;
		}
	}

ntlm_skip_signingkey:
	if (conn->dialect > SMB20_PROT_ID) {
		if (!ksmbd_conn_lookup_dialect(conn)) {
			pr_err_ratelimited("fail to verify the dialect\n");
			return -ENOENT;
		}
	}
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(ntlm_authenticate);

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

	/*
	 * Check previous session (MS-SMB2 §3.3.5.5.3).
	 * Tear down old session if it belongs to the same user.
	 * Only applies to SMB 3.0+ dialects per spec.
	 *
	 * Release conn->srv_mutex before calling destroy_previous_session
	 * to avoid a deadlock: destroy_previous_session may call
	 * ksmbd_conn_write (via ksmbd_notify_send_cleanup) which tries to
	 * acquire the same mutex.
	 */
	prev_sess_id = le64_to_cpu(req->PreviousSessionId);
	if (prev_sess_id && prev_sess_id != sess->id &&
	    conn->dialect >= SMB30_PROT_ID) {
		ksmbd_conn_unlock(conn);
		destroy_previous_session(conn, sess->user, prev_sess_id);
		ksmbd_conn_lock(conn);
	}

	rsp->SecurityBufferLength = cpu_to_le16(out_len);

	/*
	 * B.14 (krb5 path): MS-SMB2 §3.3.5.5.2 — re-authentication key update.
	 *
	 * When the session is already valid and conn->binding is false, the
	 * client is re-authenticating (e.g. after Kerberos ticket renewal).
	 * Regenerate signing and encryption keys rather than returning early
	 * with stale cryptographic material.  For binding requests, fall
	 * through to binding_session for channel key generation.
	 */
	down_read(&sess->state_lock);
	if (sess->state == SMB2_SESSION_VALID) {
		up_read(&sess->state_lock);
		if (conn->binding)
			goto binding_session;
		/* Re-auth: fall through to regenerate signing/encryption keys */
	} else {
		up_read(&sess->state_lock);
	}

	/*
	 * H-01/M-01 (krb5 path): Anonymous (null) sessions have no shared
	 * secret — skip signing and encryption setup entirely.
	 * MS-SMB2 §3.3.5.5.2 step 6.
	 */
	if (rsp->SessionFlags & SMB2_SESSION_FLAG_IS_NULL_LE)
		goto binding_session;

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
		/* Encryption supersedes signing; clear sign as in ntlm path */
		sess->sign = false;

		if ((server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION) ||
		    (req->Flags & SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA)) {
			sess->enc_forced = true;
			rsp->SessionFlags |= SMB2_SESSION_FLAG_ENCRYPT_DATA_LE;
		}
	}

binding_session:
	if (conn->dialect >= SMB30_PROT_ID) {
		chann = lookup_chann_list(sess, conn);
		if (!chann) {
			chann = kmalloc(sizeof(struct channel), KSMBD_DEFAULT_GFP);
			if (!chann)
				return -ENOMEM;

			chann->conn = conn;
			atomic64_set(&chann->nonce_counter, 0);

			/* S3: insert channel before signingkey derivation */
			old = xa_store(&sess->ksmbd_chann_list, (long)conn,
					chann, KSMBD_DEFAULT_GFP);
			if (xa_is_err(old)) {
				kfree(chann);
				return xa_err(old);
			}

			if (conn->ops->generate_signingkey) {
				retval = conn->ops->generate_signingkey(sess, conn);
				if (retval) {
					ksmbd_debug(SMB, "SMB3 signing key generation failed\n");
					xa_erase(&sess->ksmbd_chann_list, (long)conn);
					kfree(chann);
					return -EINVAL;
				}
			}

			goto krb5_skip_signingkey;
		}
	}

	if (conn->ops->generate_signingkey) {
		retval = conn->ops->generate_signingkey(sess, conn);
		if (retval) {
			ksmbd_debug(SMB, "SMB3 signing key generation failed\n");
			return -EINVAL;
		}
	}

krb5_skip_signingkey:
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
	bool new_session = false;
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
	if (!req->hdr.SessionId &&
	    (req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {
		/*
		 * MS-SMB2 §3.3.5.5.2: If the BINDING flag is set and
		 * SessionId is zero the server MUST fail with
		 * STATUS_INVALID_PARAMETER.
		 */
		rc = -EINVAL;
		goto out_err;
	} else if (!req->hdr.SessionId) {
		/*
		 * MGMT-03: Enforce per-connection in-progress session limit.
		 * Unauthenticated clients can otherwise accumulate unbounded
		 * in-progress sessions, consuming kernel memory with no cost.
		 */
#define KSMBD_MAX_INPROGRESS_SESSIONS	8
		if (atomic_read(&conn->in_progress_sessions) >=
		    KSMBD_MAX_INPROGRESS_SESSIONS) {
			rsp->hdr.Status = STATUS_TOO_MANY_SESSIONS;
			rc = -EACCES;
			goto out_err;
		}

		sess = ksmbd_smb2_session_create();
		if (!sess) {
			rc = -ENOMEM;
			goto out_err;
		}
		atomic_inc(&conn->in_progress_sessions);
		new_session = true;
		sess->in_progress_counted = true;
		rsp->hdr.SessionId = cpu_to_le64(sess->id);
		rc = ksmbd_session_register(conn, sess);
		if (rc) {
			/* Registration failed: destroy the session to avoid
			 * orphaning it in the global sessions_table.
			 */
			atomic_dec(&conn->in_progress_sessions);
			ksmbd_session_destroy(sess);
			sess = NULL;
			goto out_err;
		}

		conn->binding = false;
	} else if (conn->dialect >= SMB30_PROT_ID &&
		   (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL) &&
		   req->Flags & SMB2_SESSION_REQ_FLAG_BINDING) {
		/*
		 * Session binding (MS-SMB2 §3.3.5.5.2):
		 * The client wants to bind an existing session to a new
		 * transport connection for multi-channel operation.
		 */
		u64 sess_id = le64_to_cpu(req->hdr.SessionId);

		sess = ksmbd_session_lookup_slowpath(sess_id);
		if (!sess) {
			rc = -ENOENT;
			goto out_err;
		}

		if (conn->dialect != sess->dialect) {
			/*
			 * MS-SMB2 §3.3.5.5.2 step 4: If Connection.Dialect does
			 * not equal Session.Connection.Dialect, the server MUST
			 * fail the request with STATUS_REQUEST_NOT_ACCEPTED.
			 */
			rsp->hdr.Status = STATUS_REQUEST_NOT_ACCEPTED;
			rc = -EACCES;
			ksmbd_user_session_put(sess);
			sess = NULL;
			goto out_err;
		}

		/*
		 * MS-SMB2 §3.3.5.5.2 step 5: Connection.ClientSecurityMode
		 * (the binding connection's negotiate SecurityMode) MUST match
		 * Session.Connection.ClientSecurityMode (the original session
		 * connection's negotiate SecurityMode).  We compare the
		 * SIGNING_REQUIRED bit of the binding connection's negotiate
		 * against the session's stored server security mode, which
		 * reflects the signing requirement negotiated originally.
		 */
		{
			__u16 bind_sign = conn->cli_sec_mode &
					  SMB2_NEGOTIATE_SIGNING_REQUIRED;
			__u16 sess_sign = sess->srv_sec_mode &
					  SMB2_NEGOTIATE_SIGNING_REQUIRED;

			if (bind_sign != sess_sign) {
				rc = -EINVAL;
				ksmbd_user_session_put(sess);
				sess = NULL;
				goto out_err;
			}
		}

		/*
		 * MS-SMB2 §3.3.5.5.2 step 5: If the binding connection
		 * advertises capabilities not in the original session's
		 * connection (conn->vals->capabilities), reject with
		 * STATUS_INVALID_PARAMETER.
		 */
		if (le32_to_cpu(req->Capabilities) &
		    ~conn->vals->capabilities) {
			rc = -EINVAL;
			ksmbd_user_session_put(sess);
			sess = NULL;
			goto out_err;
		}

		/*
		 * MULTI-02: Per-channel binding key derivation requires the
		 * binding connection to support SMB 3.1.1 pre-authentication
		 * integrity (PAI).  On dialects < 3.1.1 there is no per-
		 * connection preauth hash, so the derived binding key would
		 * be identical to the primary session key — defeating the
		 * security purpose of per-channel key binding.
		 *
		 * Reject the binding if:
		 *  1. The binding connection's dialect is not SMB 3.1.1, OR
		 *  2. No preauth_info was allocated (PAI not negotiated), OR
		 *  3. The preauth hash value is all-zeros (never updated).
		 */
		if (conn->dialect != SMB311_PROT_ID ||
		    !conn->preauth_info ||
		    !memchr_inv(conn->preauth_info->Preauth_HashValue,
				0, PREAUTH_HASHVALUE_SIZE)) {
			pr_warn_ratelimited(
				"Session binding rejected: require SMB 3.1.1 with valid preauth hash\n");
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			rc = -EINVAL;
			ksmbd_user_session_put(sess);
			sess = NULL;
			goto out_err;
		}

		/*
		 * MS-SMB2 3.3.5.2.7: Session binding requests MUST be
		 * signed.  Verify the flag here; actual cryptographic
		 * signature verification is performed below after
		 * work->sess is set.
		 */
		if (!(req->hdr.Flags & SMB2_FLAGS_SIGNED)) {
			rc = -EINVAL;
			goto out_err;
		}

		/* AUT-13: Reject sessions where ClientGUID is all-zeros (uninitialized) */
		if (!memchr_inv(conn->ClientGUID, 0, SMB2_CLIENT_GUID_SIZE)) {
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
			/*
			 * MS-SMB2 §3.3.5.5.2 step 6: binding to a session
			 * that is still in the authentication phase MUST be
			 * rejected with STATUS_REQUEST_NOT_ACCEPTED.
			 */
			rsp->hdr.Status = STATUS_REQUEST_NOT_ACCEPTED;
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

		if (user_guest(sess->user) || sess->is_anonymous) {
			/*
			 * SES-06/MS-SMB2 §3.3.5.5.2: guest and anonymous sessions
			 * cannot be bound to additional transport connections.
			 */
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			rc = -EACCES;
			goto out_err;
		}

		conn->binding = true;
	} else if ((conn->dialect < SMB30_PROT_ID ||
		    !(server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL)) &&
		   (req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {
		/*
		 * Session binding requested but multi-channel is not
		 * supported or dialect is pre-SMB3.0. Return
		 * STATUS_REQUEST_NOT_ACCEPTED (MS-SMB2 §3.3.5.5.2).
		 */
		sess = NULL;
		rsp->hdr.Status = STATUS_REQUEST_NOT_ACCEPTED;
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

	/*
	 * MS-SMB2 3.3.5.2.7: Verify the signature on binding requests
	 * using the session's signing key. This must happen after
	 * work->sess is set so that check_sign_req can locate the key.
	 * Note: __process_request() cannot do this because work->sess
	 * is NULL at that point (smb2_check_user_session skips
	 * SESSION_SETUP).
	 */
	if (conn->binding) {
		if (!conn->ops->check_sign_req ||
		    !conn->ops->check_sign_req(work)) {
			pr_err_ratelimited("Session binding signature verification failed\n");
			rc = -EACCES;
			goto out_err;
		}
	}

	negblob_off = le16_to_cpu(req->SecurityBufferOffset);
	negblob_len = le16_to_cpu(req->SecurityBufferLength);
	/* SES-07: MS-SMB2 §2.2.5 requires SecurityBufferOffset >= 72 and 8-byte aligned */
	if (negblob_off < offsetof(struct smb2_sess_setup_req, Buffer) ||
	    negblob_off % 8 != 0) {
		pr_err_ratelimited("SESSION_SETUP SecurityBufferOffset invalid: %u\n",
				   negblob_off);
		rc = -EINVAL;
		goto out_err;
	}

	if ((u64)negblob_off + negblob_len > get_rfc1002_len(work->request_buf) + 4) {
		pr_err_ratelimited(
			"SESSION_SETUP security blob out of bounds: off=%u len=%u msg_len=%u mid=%llu\n",
			negblob_off, negblob_len,
			get_rfc1002_len(work->request_buf) + 4,
			le64_to_cpu(req->hdr.MessageId));
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
				if (!conn->binding && sess->in_progress_counted) {
					atomic_dec(&conn->in_progress_sessions);
					sess->in_progress_counted = false;
				}
			}
			/* S4: Clean up preauth session after Kerberos binding */
			if (conn->binding) {
				struct preauth_session *preauth_sess;

				preauth_sess =
					ksmbd_preauth_session_lookup(conn, sess->id);
				if (preauth_sess) {
					list_del(&preauth_sess->preauth_entry);
					kfree(preauth_sess);
				}
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
					if (!conn->binding &&
					    sess->in_progress_counted) {
						atomic_dec(&conn->in_progress_sessions);
						sess->in_progress_counted = false;
					}
				}
				if (conn->binding)
					ksmbd_preauth_session_remove(conn, sess->id);
			} else {
				pr_info_ratelimited("Unknown NTLMSSP message type : 0x%x\n",
						le32_to_cpu(negblob->MessageType));
				rc = -EINVAL;
			}
		} else {
			/*
			 * Unsupported authentication mechanism. SPNEGO
			 * selected a mechanism other than NTLMSSP or
			 * Kerberos, which ksmbd does not implement.
			 */
			pr_info_ratelimited("Unsupported auth mechanism selected by client\n");
			rc = -EPERM;
		}
	} else {
		pr_err_ratelimited("Not support authentication\n");
		rc = -EINVAL;
	}

out_err:
	/*
	 * Only set the response status if it has not already been set by
	 * the specific error path (e.g. STATUS_TOO_MANY_SESSIONS,
	 * STATUS_REQUEST_NOT_ACCEPTED).  This prevents generic codes like
	 * STATUS_ACCESS_DENIED from overriding more informative pre-set values.
	 */
	if (!rsp->hdr.Status) {
		if (rc == -EINVAL)
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		else if (rc == -ENOENT)
			rsp->hdr.Status = STATUS_USER_SESSION_DELETED;
		else if (rc == -EACCES)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		else if (rc == -EFAULT)
			rsp->hdr.Status = STATUS_NETWORK_SESSION_EXPIRED;
		else if (rc == -ENOMEM)
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		else if (rc == -EOPNOTSUPP)
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
		else if (rc)
			rsp->hdr.Status = STATUS_LOGON_FAILURE;
	}

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

		/*
		 * If in_progress_sessions was incremented for this session
		 * (tracked via sess->in_progress_counted), decrement it now
		 * so failed authentication attempts do not accumulate the
		 * counter.  This covers both single-step authentication
		 * (NtLmAuthenticate as the first SESSION_SETUP with
		 * SessionId==0) and two-step authentication (NtLmNegotiate
		 * created the session, NtLmAuthenticate is the second
		 * SESSION_SETUP and fails — at that point new_session==false
		 * but the session was still counted).
		 */
		if (sess && sess->in_progress_counted && !conn->binding) {
			atomic_dec(&conn->in_progress_sessions);
			sess->in_progress_counted = false;
		}

		if (sess) {
			bool try_delay = false;

			/*
			 * To mitigate dictionary attacks, force the client to
			 * reconnect on auth failure. The TCP handshake provides
			 * natural rate limiting (~100-300ms per attempt).
			 */
			if (sess->user && sess->user->flags & KSMBD_USER_FLAG_DELAY_SESSION)
				try_delay = true;

			WRITE_ONCE(sess->last_active, jiffies);
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
