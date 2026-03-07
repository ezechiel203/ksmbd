# Line-by-line Review: src/include/encoding/asn1.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` * The ASB.1/BER parsing code is derived from ip_nat_snmp_basic.c which was in`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` * turn derived from the gxsnmp package by Gregory McLean & Jochen Friedrich`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` * Copyright (c) 2000 RP Internet (www.rpi.net.au).`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` * Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#ifndef __ASN1_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#define __ASN1_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `int ksmbd_decode_negTokenInit(unsigned char *security_blob, int length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `			      struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `int ksmbd_decode_negTokenTarg(unsigned char *security_blob, int length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `			      struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `int build_spnego_ntlmssp_neg_blob(unsigned char **pbuffer, u16 *buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `				  char *ntlm_blob, int ntlm_blob_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `int build_spnego_ntlmssp_auth_blob(unsigned char **pbuffer, u16 *buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `				   int neg_result);`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#endif /* __ASN1_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
