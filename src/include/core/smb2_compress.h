/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KSMBD_SMB2_COMPRESS_H__
#define __KSMBD_SMB2_COMPRESS_H__

#if IS_ENABLED(CONFIG_KUNIT)

int smb2_pattern_v1_compress(const void *src, unsigned int src_len,
			     void *dst, unsigned int dst_len);
int smb2_pattern_v1_decompress(const void *src, unsigned int src_len,
			       void *dst, unsigned int dst_len,
			       unsigned int original_size);
int smb2_lz4_decompress(const void *src, unsigned int src_len,
			void *dst, unsigned int dst_len,
			unsigned int original_size);
int smb2_compress_data(__le16 algorithm, const void *src,
		       unsigned int src_len, void *dst,
		       unsigned int dst_len);
int smb2_decompress_data(__le16 algorithm, const void *src,
			 unsigned int src_len, void *dst,
			 unsigned int dst_len,
			 unsigned int original_size);

#endif /* IS_ENABLED(CONFIG_KUNIT) */

#endif /* __KSMBD_SMB2_COMPRESS_H__ */
