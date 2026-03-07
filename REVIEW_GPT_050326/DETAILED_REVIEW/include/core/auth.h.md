# Line-by-line Review: src/include/core/auth.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#ifndef __AUTH_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __AUTH_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include "ntlmssp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#define AUTH_GSS_LENGTH		96`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#define AUTH_GSS_PADDING	0`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#define CIFS_HMAC_MD5_HASH_SIZE	(16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#define CIFS_NTHASH_SIZE	(16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * Size of the ntlm client response`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#define CIFS_AUTH_RESP_SIZE		24`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define CIFS_SMB1_SIGNATURE_SIZE	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define CIFS_SMB1_SESSKEY_SIZE		16`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#define KSMBD_AUTH_NTLMSSP	0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#define KSMBD_AUTH_KRB5		0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#define KSMBD_AUTH_MSKRB5	0x0004`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define KSMBD_AUTH_KRB5U2U	0x0008`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `struct ksmbd_session;`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `struct ksmbd_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `struct kvec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `int ksmbd_crypt_message(struct ksmbd_work *work, struct kvec *iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `			unsigned int nvec, int enc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `void ksmbd_copy_gss_neg_header(void *buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `int ksmbd_auth_ntlm(struct ksmbd_session *sess, char *pw_buf, char *cryptkey);`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `int ksmbd_auth_ntlmv2(struct ksmbd_conn *conn, struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `		      struct ntlmv2_resp *ntlmv2, int blen, char *domain_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `		      char *cryptkey);`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `int ksmbd_decode_ntlmssp_auth_blob(struct authenticate_message *authblob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `				   int blob_len, struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `				   struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `int ksmbd_decode_ntlmssp_neg_blob(struct negotiate_message *negblob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `				  int blob_len, struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `int`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `ksmbd_build_ntlmssp_challenge_blob(struct challenge_message *chgblob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `				   unsigned int max_blob_sz,`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `				   struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `/* TODO: callers must be updated to pass the output buffer size as max_blob_sz */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `int ksmbd_krb5_authenticate(struct ksmbd_session *sess, char *in_blob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `			    int in_len, char *out_blob, int *out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `int ksmbd_sign_smb1_pdu(struct ksmbd_session *sess, struct kvec *iov, int n_vec,`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `			char *sig);`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `int ksmbd_sign_smb2_pdu(struct ksmbd_conn *conn, char *key, struct kvec *iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `			int n_vec, char *sig);`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `int ksmbd_sign_smb3_pdu(struct ksmbd_conn *conn, char *key, struct kvec *iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `			int n_vec, char *sig);`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `int ksmbd_sign_smb3_pdu_gmac(struct ksmbd_conn *conn, char *key,`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `			      struct kvec *iov, int n_vec, char *sig);`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `int ksmbd_gen_smb30_signingkey(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `			       struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `int ksmbd_gen_smb311_signingkey(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `				struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `int ksmbd_gen_smb30_encryptionkey(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `				  struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `int ksmbd_gen_smb311_encryptionkey(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `				   struct ksmbd_session *sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `int ksmbd_gen_preauth_integrity_hash(struct ksmbd_conn *conn, char *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `				     __u8 *pi_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `int ksmbd_gen_sd_hash(struct ksmbd_conn *conn, char *sd_buf, int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `		      __u8 *pi_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` * Encrypt a work's response if the session requires encryption.`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` * Used by async/interim response paths that bypass the main`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` * __handle_ksmbd_work() encryption gate.`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `int smb2_encrypt_resp_if_needed(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `#define ARC4_MIN_KEY_SIZE	1`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `#define ARC4_MAX_KEY_SIZE	256`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `#define ARC4_BLOCK_SIZE		1`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `struct arc4_ctx {`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	u32 S[256];`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	u32 x, y;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` * Functions exported for KUnit testing -- see kunit/visibility.h.`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` * These are normally static in auth.c but become visible when`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ` * CONFIG_KUNIT is enabled.`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `struct scatterlist;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `struct derivation;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `struct derivation_twin;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `int ksmbd_enc_p24(unsigned char *p21, const unsigned char *c8,`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `		  unsigned char *p24);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `int ksmbd_enc_md4(unsigned char *md4_hash, unsigned char *link_str,`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `		  int link_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `int ksmbd_enc_update_sess_key(unsigned char *md5_hash, char *nonce,`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `			      char *server_challenge, int len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `int __ksmbd_auth_ntlmv2(struct ksmbd_session *sess, char *client_nonce,`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `			 char *ntlm_resp, char *cryptkey);`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `#endif /* CONFIG_SMB_INSECURE_SERVER */`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `int cifs_arc4_setkey(struct arc4_ctx *ctx, const u8 *in_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		     unsigned int key_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `void cifs_arc4_crypt(struct arc4_ctx *ctx, u8 *out, const u8 *in,`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `		     unsigned int len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `int ksmbd_gen_sess_key(struct ksmbd_session *sess, char *hash, char *hmac);`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `int calc_ntlmv2_hash(struct ksmbd_conn *conn, struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `		     char *ntlmv2_hash, char *dname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `int generate_key(struct ksmbd_conn *conn, struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `		 struct kvec label, struct kvec context, __u8 *key,`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `		 unsigned int key_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `int generate_smb3signingkey(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `			    struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `			    const struct derivation *signing);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `int generate_smb3encryptionkey(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `			       struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `			       const struct derivation_twin *ptwin);`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `struct scatterlist *ksmbd_init_sg(struct kvec *iov, unsigned int nvec,`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `				  u8 *sign);`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `#endif /* IS_ENABLED(CONFIG_KUNIT) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `#endif /* __AUTH_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
