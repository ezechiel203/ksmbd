/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __AUTH_H__
#define __AUTH_H__

#include "ntlmssp.h"

#define AUTH_GSS_LENGTH		96
#define AUTH_GSS_PADDING	0

#define CIFS_HMAC_MD5_HASH_SIZE	(16)
#define CIFS_NTHASH_SIZE	(16)

/*
 * Size of the ntlm client response
 */
#define CIFS_AUTH_RESP_SIZE		24
#define CIFS_SMB1_SIGNATURE_SIZE	8
#define CIFS_SMB1_SESSKEY_SIZE		16

#define KSMBD_AUTH_NTLMSSP	0x0001
#define KSMBD_AUTH_KRB5		0x0002
#define KSMBD_AUTH_MSKRB5	0x0004
#define KSMBD_AUTH_KRB5U2U	0x0008

struct ksmbd_session;
struct ksmbd_conn;
struct ksmbd_work;
struct kvec;

int ksmbd_crypt_message(struct ksmbd_work *work, struct kvec *iov,
			unsigned int nvec, int enc);
void ksmbd_copy_gss_neg_header(void *buf);
int ksmbd_auth_ntlm(struct ksmbd_session *sess, char *pw_buf, char *cryptkey);
int ksmbd_auth_ntlmv2(struct ksmbd_conn *conn, struct ksmbd_session *sess,
		      struct ntlmv2_resp *ntlmv2, int blen, char *domain_name,
		      char *cryptkey);
int ksmbd_decode_ntlmssp_auth_blob(struct authenticate_message *authblob,
				   int blob_len, struct ksmbd_conn *conn,
				   struct ksmbd_session *sess);
int ksmbd_decode_ntlmssp_neg_blob(struct negotiate_message *negblob,
				  int blob_len, struct ksmbd_conn *conn);
int
ksmbd_build_ntlmssp_challenge_blob(struct challenge_message *chgblob,
				   unsigned int max_blob_sz,
				   struct ksmbd_conn *conn);
int ksmbd_krb5_authenticate(struct ksmbd_session *sess, char *in_blob,
			    int in_len, char *out_blob, int *out_len);
#ifdef CONFIG_SMB_INSECURE_SERVER
int ksmbd_sign_smb1_pdu(struct ksmbd_session *sess, struct kvec *iov, int n_vec,
			char *sig);
#endif
int ksmbd_sign_smb2_pdu(struct ksmbd_conn *conn, char *key, struct kvec *iov,
			int n_vec, char *sig);
int ksmbd_sign_smb3_pdu(struct ksmbd_conn *conn, char *key, struct kvec *iov,
			int n_vec, char *sig);
int ksmbd_sign_smb3_pdu_gmac(struct ksmbd_conn *conn, char *key,
			      struct kvec *iov, int n_vec, char *sig);
int ksmbd_gen_smb30_signingkey(struct ksmbd_session *sess,
			       struct ksmbd_conn *conn);
int ksmbd_gen_smb311_signingkey(struct ksmbd_session *sess,
				struct ksmbd_conn *conn);
int ksmbd_gen_smb30_encryptionkey(struct ksmbd_conn *conn,
				  struct ksmbd_session *sess);
int ksmbd_gen_smb311_encryptionkey(struct ksmbd_conn *conn,
				   struct ksmbd_session *sess);
int ksmbd_gen_preauth_integrity_hash(struct ksmbd_conn *conn, char *buf,
				     __u8 *pi_hash);
int ksmbd_gen_sd_hash(struct ksmbd_conn *conn, char *sd_buf, int len,
		      __u8 *pi_hash);

/*
 * Encrypt a work's response if the session requires encryption.
 * Used by async/interim response paths that bypass the main
 * __handle_ksmbd_work() encryption gate.
 */
int smb2_encrypt_resp_if_needed(struct ksmbd_work *work);

#define ARC4_MIN_KEY_SIZE	1
#define ARC4_MAX_KEY_SIZE	256
#define ARC4_BLOCK_SIZE		1

struct arc4_ctx {
	u32 S[256];
	u32 x, y;
};

#if IS_ENABLED(CONFIG_KUNIT)
/*
 * Functions exported for KUnit testing -- see kunit/visibility.h.
 * These are normally static in auth.c but become visible when
 * CONFIG_KUNIT is enabled.
 */
struct scatterlist;
struct derivation;
struct derivation_twin;

#ifdef CONFIG_SMB_INSECURE_SERVER
int ksmbd_enc_p24(unsigned char *p21, const unsigned char *c8,
		  unsigned char *p24);
int ksmbd_enc_md4(unsigned char *md4_hash, unsigned char *link_str,
		  int link_len);
int ksmbd_enc_update_sess_key(unsigned char *md5_hash, char *nonce,
			      char *server_challenge, int len);
int __ksmbd_auth_ntlmv2(struct ksmbd_session *sess, char *client_nonce,
			 char *ntlm_resp, char *cryptkey);
#endif /* CONFIG_SMB_INSECURE_SERVER */

int cifs_arc4_setkey(struct arc4_ctx *ctx, const u8 *in_key,
		     unsigned int key_len);
void cifs_arc4_crypt(struct arc4_ctx *ctx, u8 *out, const u8 *in,
		     unsigned int len);
int ksmbd_gen_sess_key(struct ksmbd_session *sess, char *hash, char *hmac);
int calc_ntlmv2_hash(struct ksmbd_conn *conn, struct ksmbd_session *sess,
		     char *ntlmv2_hash, char *dname);
int generate_key(struct ksmbd_conn *conn, struct ksmbd_session *sess,
		 struct kvec label, struct kvec context, __u8 *key,
		 unsigned int key_size);
int generate_smb3signingkey(struct ksmbd_session *sess,
			    struct ksmbd_conn *conn,
			    const struct derivation *signing);
int generate_smb3encryptionkey(struct ksmbd_conn *conn,
			       struct ksmbd_session *sess,
			       const struct derivation_twin *ptwin);
struct scatterlist *ksmbd_init_sg(struct kvec *iov, unsigned int nvec,
				  u8 *sign);

#endif /* IS_ENABLED(CONFIG_KUNIT) */

#endif /* __AUTH_H__ */
