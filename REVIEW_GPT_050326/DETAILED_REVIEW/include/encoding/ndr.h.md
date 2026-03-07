# Line-by-line Review: src/include/encoding/ndr.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2020 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Author(s): Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `struct ndr {`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `	char		*data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `	unsigned int	offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `	unsigned int	length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#define NDR_NTSD_OFFSETOF	0xA0`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `int ndr_encode_dos_attr(struct ndr *n, struct xattr_dos_attrib *da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `int ndr_decode_dos_attr(struct ndr *n, struct xattr_dos_attrib *da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `int ndr_encode_posix_acl(struct ndr *n, struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `int ndr_encode_posix_acl(struct ndr *n, struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `			 struct inode *inode, struct xattr_smb_acl *acl,`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `			 struct xattr_smb_acl *def_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `int ndr_encode_v4_ntacl(struct ndr *n, struct xattr_ntacl *acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `int ndr_encode_v3_ntacl(struct ndr *n, struct xattr_ntacl *acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `int ndr_decode_v4_ntacl(struct ndr *n, struct xattr_ntacl *acl);`
  Review: Low-risk line; verify in surrounding control flow.
