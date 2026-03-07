# Line-by-line Review: src/include/core/smb2_compress.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [PROTO_GATE|] `#ifndef __KSMBD_SMB2_COMPRESS_H__`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00003 [PROTO_GATE|] `#define __KSMBD_SMB2_COMPRESS_H__`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00004 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `int smb2_pattern_v1_compress(const void *src, unsigned int src_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `			     void *dst, unsigned int dst_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `int smb2_pattern_v1_decompress(const void *src, unsigned int src_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `			       void *dst, unsigned int dst_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `			       unsigned int original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `int smb2_lz4_decompress(const void *src, unsigned int src_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `			void *dst, unsigned int dst_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `			unsigned int original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `int smb2_compress_data(__le16 algorithm, const void *src,`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `		       unsigned int src_len, void *dst,`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `		       unsigned int dst_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `int smb2_decompress_data(__le16 algorithm, const void *src,`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `			 unsigned int src_len, void *dst,`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `			 unsigned int dst_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `			 unsigned int original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#endif /* IS_ENABLED(CONFIG_KUNIT) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [PROTO_GATE|] `#endif /* __KSMBD_SMB2_COMPRESS_H__ */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
