# Line-by-line Review: src/core/smb2_compress.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   SMB2/3 Compression Transform Support`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   Copyright (C) 2026 ksmbd contributors`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *   Implements message-level compression and decompression for SMB 3.1.1`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   per MS-SMB2 section 2.2.42 and MS-XCA.`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   Supported algorithms:`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *     - Pattern_V1 (0x0004): Repeated-byte pattern detection`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *     - LZ4 (0x0005): LZ4 block compression via kernel API (internal only,`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *                     NOT advertised to clients — see I.2 below)`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *     - LZNT1 (0x0001): MS-XCA §2.3 implementation`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *     - LZ77 plain (0x0002): MS-XCA §2.4 implementation`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` *     - LZ77+Huffman (0x0003): MS-XCA §2.5 (LZXPRESS Huffman) full impl`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * I.2 NOTE: LZ4 (0x0005) is not in the MS-SMB2 specification and MUST NOT`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [PROTO_GATE|] ` * be advertised in the SMB2_COMPRESSION_CAPABILITIES negotiate context.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00020 [NONE] ` * The negotiate code (smb2_negotiate.c) is responsible for filtering LZ4`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * from the advertised list.  If a client somehow negotiates LZ4, this file`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * supports decompression for backward compatibility, but the server will`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * not actively compress responses using LZ4 (smb2_compress_data declines).`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include <linux/lz4.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include <linux/overflow.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#define VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * Pattern_V1 compression (MS-XCA 2.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * Pattern_V1 is the simplest compression algorithm in the SMB3 spec.`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` * It detects repeated byte patterns. The compressed format is:`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` *   - 1 byte: the repeated byte value`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` *   - The rest of the original data (or nothing if entire buffer is a pattern)`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` * For Pattern_V1, the compressed payload consists of:`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` *   Byte 0: The pattern byte`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` *   Bytes 1..N: Reserved (zero)`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ` * Per MS-SMB2, Pattern_V1 is only used in chained compression mode as`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` * a pre-scan. For our non-chained implementation we implement it as a`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ` * simple run-length check: if the entire buffer is a single repeated byte,`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ` * we compress it down to 8 bytes (1 byte pattern + 3 bytes reserved +`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ` * 4 bytes repetition count).`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `/* Pattern_V1 compressed payload */`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `struct pattern_v1_payload {`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	__u8  Pattern;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	__u8  Reserved1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	__le16 Reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	__le32 Repetitions;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#define PATTERN_V1_COMPRESSED_SIZE sizeof(struct pattern_v1_payload)`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * smb2_pattern_v1_compress - Compress data using Pattern_V1 algorithm`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` * @src:      Source data buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * @src_len:  Length of source data`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` * @dst:      Destination buffer (must be at least PATTERN_V1_COMPRESSED_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` * @dst_len:  Available space in destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` * Returns compressed size on success, 0 if data is not compressible`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ` * with Pattern_V1 (i.e., not a single repeated byte), or negative`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` * errno on error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `VISIBLE_IF_KUNIT int smb2_pattern_v1_compress(const void *src, unsigned int src_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `				    void *dst, unsigned int dst_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	const unsigned char *data = src;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	struct pattern_v1_payload *payload = dst;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	unsigned char pattern;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	if (src_len == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	if (dst_len < PATTERN_V1_COMPRESSED_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	/* Check if entire buffer is a single repeated byte */`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	pattern = data[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	for (i = 1; i < src_len; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `		if (data[i] != pattern)`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `			return 0; /* Not a pattern - cannot compress */`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	/* Only compress if we actually save space */`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	if (PATTERN_V1_COMPRESSED_SIZE >= src_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	payload->Pattern = pattern;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	payload->Reserved1 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	payload->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	payload->Repetitions = cpu_to_le32(src_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	return PATTERN_V1_COMPRESSED_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_pattern_v1_compress);`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` * smb2_pattern_v1_decompress - Decompress Pattern_V1 compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` * @src:          Compressed data buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` * @src_len:      Length of compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` * @dst:          Destination buffer for decompressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ` * @dst_len:      Size of destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ` * @original_size: Expected original (decompressed) size`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ` * Returns 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `VISIBLE_IF_KUNIT int smb2_pattern_v1_decompress(const void *src, unsigned int src_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `				      void *dst, unsigned int dst_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `				      unsigned int original_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	const struct pattern_v1_payload *payload = src;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	unsigned int repetitions;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	if (src_len < PATTERN_V1_COMPRESSED_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	repetitions = le32_to_cpu(payload->Repetitions);`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	if (repetitions != original_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	if (original_size > dst_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	memset(dst, payload->Pattern, original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_pattern_v1_decompress);`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ` * LZ4 compression using the kernel's built-in LZ4 API.`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ` * The kernel provides lz4_compress() and lz4_decompress_unknownoutputsize()`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ` * from <linux/lz4.h>.`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ` * smb2_lz4_decompress - Decompress LZ4 compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ` * @src:          Compressed data buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] ` * @src_len:      Length of compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ` * @dst:          Destination buffer for decompressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ` * @dst_len:      Size of destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ` * @original_size: Expected original (decompressed) size`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` * Returns 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `VISIBLE_IF_KUNIT int smb2_lz4_decompress(const void *src, unsigned int src_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `			       void *dst, unsigned int dst_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `			       unsigned int original_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	if (original_size > dst_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	ret = LZ4_decompress_safe(src, dst, src_len, original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [ERROR_PATH|] `		pr_err("LZ4 decompression failed: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00179 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00180 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	if ((unsigned int)ret != original_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [ERROR_PATH|] `		pr_err("LZ4 decompression size mismatch: got %d, expected %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00184 [NONE] `		       ret, original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00186 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_lz4_decompress);`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ` * LZNT1 compression/decompression (MS-XCA §2.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ` * LZNT1 is a chunk-based LZ77 variant. The compressed stream consists of`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ` * 4096-byte chunks, each preceded by a 2-byte chunk header:`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ` *   - Bit 15 set:   uncompressed chunk (copy 4096 bytes as-is)`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` *   - Bit 15 clear: compressed chunk; bits 12:0 = (compressed_size - 3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ` * Within a compressed chunk, data is encoded as:`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ` *   - A flag byte (8 bits), each bit indicates literal (0) or back-ref (1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ` *   - Literals: 1 byte copied as-is`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ` *   - Back-references: 2 bytes encoding offset+length, where the split`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ` *     between offset and length bits varies based on position in the output`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` *     (more offset bits as output fills up, per MS-XCA §2.3.1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ` * The decompressor is the critical path (server receives compressed client`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ` * data).  The compressor produces valid LZNT1 output but is not highly`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ` * optimised.`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `#define LZNT1_CHUNK_SIZE	4096`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] ` * lznt1_get_offset - Extract offset field from LZNT1 back-reference token`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `static inline unsigned int lznt1_get_offset(unsigned int word,`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `					    unsigned int pos_bits)`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	/* offset uses the high (16 - pos_bits) bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	return (word >> pos_bits) + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ` * lznt1_get_length - Extract length field from LZNT1 back-reference token`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `static inline unsigned int lznt1_get_length(unsigned int word,`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `					    unsigned int pos_bits)`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	/* length uses the low pos_bits bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	unsigned int mask = (1u << pos_bits) - 1u;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	return (word & mask) + 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ` * ksmbd_lznt1_decompress - Decompress LZNT1 data (MS-XCA §2.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ` * @input:      Compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ` * @input_len:  Length of compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ` * @output:     Output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] ` * @output_len: Size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ` * Returns number of decompressed bytes on success, negative errno on error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `static ssize_t ksmbd_lznt1_decompress(const void *input, size_t input_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `				      void *output, size_t output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	const unsigned char *in = input;`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	unsigned char *out = output;`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	size_t in_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	size_t out_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	while (in_pos + 2 <= input_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `		unsigned int chunk_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `		size_t chunk_start_out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		bool is_compressed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `		size_t chunk_data_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `		size_t chunk_end_in;`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `		chunk_hdr = (unsigned int)in[in_pos] |`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `			    ((unsigned int)in[in_pos + 1] << 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		in_pos += 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		is_compressed = !(chunk_hdr & 0x8000);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		chunk_data_size = (chunk_hdr & 0x0FFF) + 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		if (in_pos + chunk_data_size > input_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `			/* Truncated chunk — treat as end of stream */`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `		chunk_end_in = in_pos + chunk_data_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `		chunk_start_out = out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `		if (!is_compressed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `			/* Uncompressed chunk: 4096 bytes verbatim */`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `			size_t copy_len = min_t(size_t, 4096,`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `						output_len - out_pos);`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `			if (copy_len < chunk_data_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [ERROR_PATH|] `				return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00282 [MEM_BOUNDS|] `			memcpy(out + out_pos, in + in_pos, chunk_data_size);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00283 [NONE] `			out_pos += chunk_data_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `			in_pos = chunk_end_in;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `		/* Compressed chunk: parse LZ77 tokens */`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `		while (in_pos < chunk_end_in && out_pos < output_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `			unsigned int flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `			int bit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `			if (in_pos >= chunk_end_in)`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `			flags = in[in_pos++];`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `			for (bit = 0; bit < 8 && in_pos < chunk_end_in &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `			     out_pos < output_len; bit++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `				if (!(flags & (1u << bit))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `					/* Literal byte */`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `					out[out_pos++] = in[in_pos++];`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `				} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `					/* Back-reference */`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `					unsigned int token;`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `					unsigned int offset, length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `					unsigned int filled;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `					unsigned int pos_bits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `					unsigned int copy_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `					if (in_pos + 2 > chunk_end_in)`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [ERROR_PATH|] `						return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `					token = (unsigned int)in[in_pos] |`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `						((unsigned int)in[in_pos + 1] << 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `					in_pos += 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `					/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `					 * Number of bits for length field depends`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `					 * on how much output we've produced in`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `					 * this chunk so far.  Per MS-XCA §2.3.1:`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `					 * pos_bits starts at 4 (for 0-16 bytes),`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `					 * grows by 1 for each doubling of chunk`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `					 * position, up to max 12.`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `					filled = out_pos - chunk_start_out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `					pos_bits = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `					{`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `						unsigned int tmp = filled;`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `						while (tmp >= (1u << pos_bits) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `						       pos_bits < 12)`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `							pos_bits++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `					offset = lznt1_get_offset(token,`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `								  pos_bits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `					length = lznt1_get_length(token,`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `								  pos_bits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `					if (offset > out_pos)`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [ERROR_PATH|] `						return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00343 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `					copy_offset = out_pos - offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `					if (out_pos + length > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [ERROR_PATH|] `						return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `					/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `					 * Copy byte by byte to handle overlapping`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `					 * back-references (run-length expansion).`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `					while (length-- > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `						out[out_pos++] =`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `							out[copy_offset++];`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `		in_pos = chunk_end_in;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	return (ssize_t)out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] ` * ksmbd_lznt1_compress - Compress data using LZNT1 (MS-XCA §2.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] ` * @input:      Input data`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] ` * @input_len:  Length of input data`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] ` * @output:     Output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] ` * @output_len: Size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] ` * Returns number of compressed bytes on success, negative errno on error,`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] ` * or 0 if compression did not reduce the data size.`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `static ssize_t ksmbd_lznt1_compress(const void *input, size_t input_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `				    void *output, size_t output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	const unsigned char *in = input;`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	unsigned char *out = output;`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	size_t in_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	size_t out_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `	while (in_pos < input_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `		/* Position where this chunk header will be written */`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `		size_t chunk_hdr_pos = out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `		size_t chunk_start_in = in_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `		size_t chunk_end_in = min_t(size_t, in_pos + LZNT1_CHUNK_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `					    input_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `		size_t chunk_out_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `		unsigned char *flags_byte;`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `		int flag_bit = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `		bool any_match = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `		/* Reserve space for chunk header (2 bytes) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `		if (out_pos + 2 > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `			return 0; /* No space */`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `		out_pos += 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `		chunk_out_start = out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `		/* Reserve space for flag byte */`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `		if (out_pos >= output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `		flags_byte = &out[out_pos++];`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `		*flags_byte = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `		while (in_pos < chunk_end_in) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `			size_t best_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `			size_t best_off = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `			size_t search_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `			unsigned int filled;`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `			unsigned int pos_bits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `			/* Search backwards for longest match */`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `			search_start = (in_pos > chunk_start_in + 4096) ?`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `					in_pos - 4096 : chunk_start_in;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `			filled = in_pos - chunk_start_in;`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `			pos_bits = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `			{`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `				unsigned int tmp = filled;`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `				while (tmp >= (1u << pos_bits) && pos_bits < 12)`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `					pos_bits++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `			{`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `				size_t max_off = (1u << (16 - pos_bits));`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `				size_t max_len = (1u << pos_bits) + 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `				size_t s;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `				for (s = in_pos - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `				     s >= search_start && in_pos > search_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `				     s--) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `					size_t match_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `					size_t off = in_pos - s;`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `					if (off > max_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `						break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `					while (match_len < max_len &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `					       in_pos + match_len < chunk_end_in &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `					       in[s + match_len] ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `					       in[in_pos + match_len])`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `						match_len++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `					if (match_len >= 3 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `					    match_len > best_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `						best_len = match_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `						best_off = off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `					if (s == chunk_start_in)`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `						break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `			if (best_len >= 3) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `				/* Emit back-reference */`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `				unsigned int token;`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `				unsigned int off_field = best_off - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `				unsigned int len_field = best_len - 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `				unsigned int len_mask = (1u << pos_bits) - 1u;`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `				token = (off_field << pos_bits) | (len_field & len_mask);`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `				if (out_pos + 2 > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `					return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `				out[out_pos++] = token & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `				out[out_pos++] = (token >> 8) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `				*flags_byte |= (1u << flag_bit);`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `				in_pos += best_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `				any_match = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `				/* Emit literal */`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `				if (out_pos >= output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `					return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `				out[out_pos++] = in[in_pos++];`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `			flag_bit++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `			if (flag_bit == 8 && in_pos < chunk_end_in) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `				/* Start new flag byte */`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `				if (out_pos >= output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `					return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `				flags_byte = &out[out_pos++];`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `				*flags_byte = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `				flag_bit = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `		 * Write chunk header.`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `		 * If chunk compresses well, write compressed header;`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `		 * otherwise write uncompressed (if space allows).`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `			size_t compressed_chunk_size = out_pos - chunk_out_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `			size_t orig_chunk_size = chunk_end_in - chunk_start_in;`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `			if (!any_match || compressed_chunk_size >= orig_chunk_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `				/* Write uncompressed chunk */`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `				if (chunk_hdr_pos + 2 + orig_chunk_size > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `					return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `				out_pos = chunk_hdr_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `				/* Uncompressed: bit 15 set, size = orig_chunk_size - 3 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `				{`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `					unsigned int hdr = 0x8000 |`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `						((orig_chunk_size - 3) & 0x0FFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `					out[out_pos++] = hdr & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `					out[out_pos++] = (hdr >> 8) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [MEM_BOUNDS|] `				memcpy(out + out_pos, in + chunk_start_in,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00513 [NONE] `				       orig_chunk_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `				out_pos += orig_chunk_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `				/* Write compressed chunk header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `				unsigned int hdr = (compressed_chunk_size - 3) & 0x0FFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `				/* bit 15 clear = compressed */`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `				out[chunk_hdr_pos] = hdr & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `				out[chunk_hdr_pos + 1] = (hdr >> 8) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `		in_pos = chunk_end_in;`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	/* Return 0 if we didn't compress at all */`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	if (out_pos >= input_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	return (ssize_t)out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] ` * LZ77 plain compression/decompression (MS-XCA §2.4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] ` * LZ77 plain (not LZ77+Huffman) uses a simple binary format:`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] ` *   - 4-byte flag word: each bit (LSB first) indicates whether the`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] ` *     corresponding item is a literal (0) or back-reference (1).`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] ` *   - Literal: 1 byte copied as-is.`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] ` *   - Back-reference: 2 bytes little-endian:`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] ` *       bits 15:4 = offset - 1 (12 bits, so max offset 4096)`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] ` *       bits  3:0 = extra_length (4 bits)`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] ` *     If extra_length == 15: read 1 more byte for more_len.`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] ` *       If more_len == 255: read 2-byte additional length, then subtract`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] ` *       (15 + 255) to get final_length.`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] ` *       Otherwise final_length = extra_length + more_len + 3.`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] ` *     Otherwise final_length = extra_length + 3.`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] ` * The format operates on the entire message (no chunk boundary).`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] ` * This is the LZ77 "plain" algorithm as used in SMB3 (algorithm 0x0002).`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] ` * ksmbd_lz77_decompress - Decompress LZ77 plain data (MS-XCA §2.4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] ` * @input:      Compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] ` * @input_len:  Length of compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] ` * @output:     Output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] ` * @output_len: Size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ` * Returns number of decompressed bytes on success, negative errno on error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `static ssize_t ksmbd_lz77_decompress(const void *input, size_t input_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `				     void *output, size_t output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	const unsigned char *in = input;`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	unsigned char *out = output;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	size_t in_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	size_t out_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	while (in_pos < input_len && out_pos < output_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `		unsigned int flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `		int bit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `		/* Read 4-byte flag word */`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		if (in_pos + 4 > input_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `		flags = (unsigned int)in[in_pos] |`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `			((unsigned int)in[in_pos + 1] << 8) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `			((unsigned int)in[in_pos + 2] << 16) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `			((unsigned int)in[in_pos + 3] << 24);`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `		in_pos += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `		for (bit = 0; bit < 32 && in_pos < input_len &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `		     out_pos < output_len; bit++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `			if (!(flags & (1u << bit))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `				/* Literal */`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `				out[out_pos++] = in[in_pos++];`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `				/* Back-reference */`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `				unsigned int token;`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `				unsigned int offset, length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `				if (in_pos + 2 > input_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [ERROR_PATH|] `					return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00597 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `				token = (unsigned int)in[in_pos] |`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `					((unsigned int)in[in_pos + 1] << 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `				in_pos += 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `				offset = (token >> 4) + 1;  /* 12-bit offset + 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `				length = token & 0xF;        /* 4-bit extra length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `				if (length == 15) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `					unsigned int more;`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `					if (in_pos >= input_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [ERROR_PATH|] `						return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00610 [NONE] `					more = in[in_pos++];`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `					if (more == 255) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `						unsigned int extra;`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `						if (in_pos + 2 > input_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [ERROR_PATH|] `							return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00616 [NONE] `						extra = (unsigned int)in[in_pos] |`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `							((unsigned int)in[in_pos + 1] << 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `						in_pos += 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `						length = extra;`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `					} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `						length = length + more + 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `				} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `					length += 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `				if (offset > out_pos)`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [ERROR_PATH|] `					return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00629 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `				if (out_pos + length > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [ERROR_PATH|] `					return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00632 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `				{`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `					size_t src = out_pos - offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `					while (length-- > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `						out[out_pos++] = out[src++];`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `	return (ssize_t)out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] ` * ksmbd_lz77_compress - Compress data using LZ77 plain (MS-XCA §2.4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] ` * @input:      Input data`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] ` * @input_len:  Length of input data`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] ` * @output:     Output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] ` * @output_len: Size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] ` * Returns number of compressed bytes on success, 0 if not compressible,`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] ` * negative errno on error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `static ssize_t ksmbd_lz77_compress(const void *input, size_t input_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `				   void *output, size_t output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	const unsigned char *in = input;`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	unsigned char *out = output;`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	size_t in_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `	size_t out_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `	while (in_pos < input_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `		/* Reserve 4 bytes for flag word */`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `		size_t flags_pos = out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `		unsigned int flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `		int bit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `		if (out_pos + 4 > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `		out_pos += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `		for (bit = 0; bit < 32 && in_pos < input_len; bit++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `			size_t best_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `			size_t best_off = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `			size_t search_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `			size_t max_match;`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `			size_t s;`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `			/* Search back up to 4096 bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `			search_start = (in_pos > 4096) ? in_pos - 4096 : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `			max_match = min_t(size_t, input_len - in_pos, (1u << 16) + 17);`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `			for (s = search_start; s < in_pos; s++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `				size_t match_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `				size_t off = in_pos - s;`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `				while (match_len < max_match &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `				       in_pos + match_len < input_len &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `				       in[s + match_len] == in[in_pos + match_len])`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `					match_len++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `				if (match_len >= 3 && match_len > best_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `					best_len = match_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `					best_off = off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `			if (best_len >= 3) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `				/* Emit back-reference */`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `				unsigned int token_base;`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `				flags |= (1u << bit);`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `				token_base = ((best_off - 1) << 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `				if (best_len - 3 < 15) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `					/* Fits in 4 bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `					unsigned int token =`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `						token_base | (best_len - 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `					if (out_pos + 2 > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `						return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `					out[out_pos++] = token & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `					out[out_pos++] = (token >> 8) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `				} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `					/* Need extra length byte(s) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `					unsigned int token = token_base | 0xF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `					unsigned int extra_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `					if (out_pos + 2 > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `						return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `					out[out_pos++] = token & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `					out[out_pos++] = (token >> 8) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `					extra_len = best_len - 3 - 15;`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `					if (extra_len < 255) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `						if (out_pos >= output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `							return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `						out[out_pos++] = (unsigned char)extra_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `					} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `						if (out_pos + 3 > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `							return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `						out[out_pos++] = 255;`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `						{`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `							unsigned int total =`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `								best_len - 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `							out[out_pos++] = total & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `							out[out_pos++] = (total >> 8) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `						}`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `				in_pos += best_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `				/* Emit literal */`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `				if (out_pos >= output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `					return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `				out[out_pos++] = in[in_pos++];`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `		/* Write flag word */`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `		out[flags_pos]     = flags & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `		out[flags_pos + 1] = (flags >> 8) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `		out[flags_pos + 2] = (flags >> 16) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `		out[flags_pos + 3] = (flags >> 24) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	if (out_pos >= input_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `	return (ssize_t)out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] ` * LZ77+Huffman compression/decompression (MS-XCA §2.5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] ` * SMB3 compression algorithm 0x0003 (SMB3_COMPRESS_LZ77_HUFF).`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] ` * This is the LZXPRESS Huffman algorithm.  The wire format is:`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] ` * For each 65536-byte (uncompressed) block:`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] ` *   [256 bytes: Huffman symbol length table, 512 4-bit lengths packed]`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] ` *   [variable: Huffman-coded LZ77 token stream]`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] ` * The Huffman alphabet has 512 symbols:`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] ` *   Symbols   0-255: literal bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] ` *   Symbols 256-511: LZ77 match tokens`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] ` *     symbol = 256 + ((match_length - 3) << 4) + distance_log2`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] ` *       match_length: decoded_length = len_slot + 3  (len_slot = high nibble)`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] ` *       distance_log2: low nibble; read that many more bits for exact offset`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] ` *         offset = (1 << distance_log2) + read_bits(distance_log2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] ` *         special case: distance_log2 == 0 => offset = 1, no extra bits`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] ` * Bit-stream: 32-bit LE words, bits extracted LSB-first.`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] ` * Huffman codes: canonical, lengths up to 15 bits, read MSB-first within`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] ` * the 32-bit window (i.e., the bit-reversal is baked into the decode table).`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] ` * Compressor: we implement a literal-only encoder (all 256 symbols at`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] ` * length 8), which is spec-valid but does not compress data.  The caller`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] ` * (smb2_compress_data) will detect that compressed >= original and fall`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] ` * back to sending uncompressed data.`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `/* Maximum number of Huffman symbols */`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `#define LZ77H_NSYM		512`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `/* Maximum Huffman code length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `#define LZ77H_MAX_BITS		15`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `/* Bits in the fast decode table index */`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `#define LZ77H_FAST_BITS		11`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `#define LZ77H_FAST_SIZE		(1 << LZ77H_FAST_BITS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `/* Uncompressed block size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `#define LZ77H_BLOCK_SIZE	65536`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] ` * Huffman decode entry.`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] ` * For codes <= LZ77H_FAST_BITS, stored directly in fast[].`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] ` * For longer codes, fast[] entry has is_chain=1 and sym=chain index.`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `struct lz77h_entry {`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `	__u16 sym;      /* decoded symbol */`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `	__u8  len;      /* code length in bits, 0 = empty slot */`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `	__u8  is_chain; /* 1 = sym is index into chain[], not a symbol */`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `/* Per-block decoder state */`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `struct lz77h_decoder {`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `	struct lz77h_entry fast[LZ77H_FAST_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `	/* Overflow entries for codes > LZ77H_FAST_BITS bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `	struct lz77h_entry chain[LZ77H_NSYM];`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `	int chain_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] ` * Build canonical Huffman decode tables.`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] ` * lengths[i] = code length for symbol i (0 = symbol not present).`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] ` * Returns 0 on success, -EINVAL on bad table.`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] ` * The bit-stream reads bits LSB-first from 32-bit LE words.  Canonical`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] ` * Huffman codes are assigned MSB-first (standard).  To look up a code`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] ` * in the fast table we use the bit-reversed code as the table index.`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `static int lz77h_build_table(struct lz77h_decoder *dec,`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `			     const __u8 *lengths, int nsym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `	int cnt[LZ77H_MAX_BITS + 1] = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `	int next_code[LZ77H_MAX_BITS + 2] = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `	int i, bits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `	unsigned int code;`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `	memset(dec->fast, 0, sizeof(dec->fast));`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `	dec->chain_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `	/* Count codes per length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `	for (i = 0; i < nsym; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `		if (lengths[i] > LZ77H_MAX_BITS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00848 [NONE] `		if (lengths[i])`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `			cnt[lengths[i]]++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	/* Canonical code start values */`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	code = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `	next_code[0] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `	for (bits = 1; bits <= LZ77H_MAX_BITS; bits++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `		code = (code + cnt[bits - 1]) << 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `		next_code[bits] = (int)code;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `	/* Assign codes and populate decode table */`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `	for (i = 0; i < nsym; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `		int len = lengths[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `		unsigned int c, rev;`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `		int b;`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `		if (!len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `		c = (unsigned int)next_code[len]++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `		 * Bit-reverse the canonical code so it can be used as an`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `		 * index into the fast table (which is indexed by bits read`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `		 * LSB-first from the stream).`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `		rev = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `		for (b = 0; b < len; b++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `			rev = (rev << 1) | ((c >> b) & 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `		if (len <= LZ77H_FAST_BITS) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `			 * Short code: fill all fast[] entries whose index`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `			 * has \047rev\047 as a prefix (the remaining bits are`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `			 * don't-cares).`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `			int pad = LZ77H_FAST_BITS - len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `			unsigned int base = rev << pad; /* no — wrong */`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `			 * Correct: rev is the LSB-first code of length \047len\047.`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `			 * We want all indices idx in [0, LZ77H_FAST_SIZE) such`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `			 * that (idx & ((1<<len)-1)) == rev.`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `			 * These are: rev + k*(1<<len) for k = 0..2^pad-1.`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `			base = rev;`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `			{`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `				unsigned int stride = 1u << len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `				unsigned int idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `				for (idx = base; idx < LZ77H_FAST_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `				     idx += stride) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `					if (dec->fast[idx].len == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `						dec->fast[idx].sym = (u16)i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `						dec->fast[idx].len = (u8)len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `						dec->fast[idx].is_chain = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `			 * Long code: add to chain table.`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `			 * The fast[] entry for the lower LZ77H_FAST_BITS bits`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `			 * of rev acts as a chain anchor.`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `			unsigned int fast_idx = rev & (LZ77H_FAST_SIZE - 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `			if (dec->chain_cnt < LZ77H_NSYM) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `				int ci = dec->chain_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `				dec->chain[ci].sym = (u16)i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `				dec->chain[ci].len = (u8)len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `				dec->chain[ci].is_chain = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `				 * Point the fast entry to the first chain`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `				 * entry (if not already set).  If already a`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `				 * chain pointer, that's fine — linear scan`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `				 * will find this entry too.`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `				if (dec->fast[fast_idx].len == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `					dec->fast[fast_idx].sym = (u16)ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `					dec->fast[fast_idx].len = LZ77H_FAST_BITS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `					dec->fast[fast_idx].is_chain = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `/* Bit-reader for LZ77+Huffman */`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `struct lz77h_br {`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	const unsigned char *data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	size_t              data_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	size_t              pos;   /* next byte to read */`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `	unsigned int        buf;   /* bit buffer, LSB = next bit */`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	int                 avail; /* valid bits in buf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `static inline void lz77h_br_init(struct lz77h_br *br,`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `				 const unsigned char *data, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	br->data     = data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `	br->data_len = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `	br->pos      = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `	br->buf      = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `	br->avail    = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `/* Refill bit buffer from input stream (read up to 16 bits at a time) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `static inline void lz77h_br_refill(struct lz77h_br *br)`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `	while (br->avail <= 24 && br->pos + 1 < br->data_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `		unsigned int word = (unsigned int)br->data[br->pos] |`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `				    ((unsigned int)br->data[br->pos + 1] << 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `		br->buf  |= word << br->avail;`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `		br->avail += 16;`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `		br->pos  += 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `	/* Handle trailing odd byte */`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `	if (br->avail <= 24 && br->pos < br->data_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `		br->buf  |= (unsigned int)br->data[br->pos] << br->avail;`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `		br->avail += 8;`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `		br->pos++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `static inline unsigned int lz77h_br_read(struct lz77h_br *br, int n)`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	unsigned int v;`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `	if (n == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `	lz77h_br_refill(br);`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `	v        = br->buf & ((1u << n) - 1u);`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `	br->buf  >>= n;`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `	br->avail -= n;`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `	return v;`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] ` * Decode one Huffman symbol from the bit-stream.`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] ` * Returns symbol (0..511) on success, -1 on error/end-of-stream.`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `static int lz77h_decode_sym(struct lz77h_decoder *dec, struct lz77h_br *br)`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `	unsigned int peek;`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `	struct lz77h_entry *e;`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `	lz77h_br_refill(br);`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `	if (br->avail < 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `		return -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `	/* Peek LZ77H_FAST_BITS bits (LSB first) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `	peek = br->buf & (LZ77H_FAST_SIZE - 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `	e = &dec->fast[peek];`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `	if (e->len == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `		return -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `	if (!e->is_chain) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `		/* Direct hit */`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `		br->buf   >>= e->len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `		br->avail  -= e->len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `		return e->sym;`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `	 * Chain lookup: consume the fast bits first, then check each`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `	 * chain entry for a match using its full code length.`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `		int ci_start = e->sym;`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `		int ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `		/* Consume the LZ77H_FAST_BITS bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `		br->buf   >>= LZ77H_FAST_BITS;`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `		br->avail  -= LZ77H_FAST_BITS;`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `		lz77h_br_refill(br);`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `		for (ci = ci_start; ci < dec->chain_cnt; ci++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `			struct lz77h_entry *ce = &dec->chain[ci];`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `			int extra = ce->len - LZ77H_FAST_BITS;`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `			if (extra <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `			if (br->avail < extra)`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `				return -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `			br->buf   >>= extra;`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] `			br->avail  -= extra;`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `			return ce->sym;`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `	return -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] ` * ksmbd_lz77huff_decompress - Decompress LZ77+Huffman data (MS-XCA §2.5)`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] ` * @input:      Compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] ` * @input_len:  Length of compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] ` * @output:     Output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] ` * @output_len: Size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] ` * Returns number of decompressed bytes on success, negative errno on error.`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `static ssize_t ksmbd_lz77huff_decompress(const void *input, size_t input_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `					 void *output, size_t output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `	const unsigned char *in = input;`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `	unsigned char *out = output;`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `	size_t in_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `	size_t out_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `	while (out_pos < output_len && in_pos < input_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `		__u8 lengths[LZ77H_NSYM];`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `		struct lz77h_decoder *dec;`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `		struct lz77h_br br;`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `		size_t block_out_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `		int i, rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `		/* Each block decompresses to at most LZ77H_BLOCK_SIZE bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `		block_out_end = min_t(size_t, out_pos + LZ77H_BLOCK_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `				      output_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `		/* Read 256-byte Huffman table: 512 symbols, 4 bits each */`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `		if (in_pos + 256 > input_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `		for (i = 0; i < 256; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `			unsigned char b = in[in_pos + i];`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `			lengths[2 * i]     = b & 0x0F;`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `			lengths[2 * i + 1] = (b >> 4) & 0x0F;`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `		in_pos += 256;`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [MEM_BOUNDS|] `		dec = kvmalloc(sizeof(*dec), GFP_KERNEL);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01092 [NONE] `		if (!dec)`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `		rc = lz77h_build_table(dec, lengths, LZ77H_NSYM);`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `			kvfree(dec);`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `		/* Initialize bit reader starting right after the table */`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `		lz77h_br_init(&br, in + in_pos, input_len - in_pos);`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `		/* Decode symbols for this block */`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `		while (out_pos < block_out_end) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `			int sym = lz77h_decode_sym(dec, &br);`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `			if (sym < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] `			if (sym < 256) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `				/* Literal byte */`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `				out[out_pos++] = (unsigned char)sym;`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `				 * LZ77 match token.`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `				 * sym = 256 + (len_slot << 4) + dist_log2`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `				unsigned int token     = (unsigned int)sym - 256;`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `				unsigned int len_slot  = token >> 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `				unsigned int dist_log2 = token & 0xF;`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `				unsigned int match_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `				unsigned int offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `				unsigned int copy_src;`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `				/* Base match length */`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `				match_len = len_slot + 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `				 * Extended length: if len_slot == 15, read`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `				 * additional length bytes per MS-XCA §2.5.1.`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `				if (len_slot == 15) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `					unsigned int extra;`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `					lz77h_br_refill(&br);`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `					extra = lz77h_br_read(&br, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `					match_len = extra + 3 + 15;`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `					if (extra == 255) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `						unsigned int lo, hi;`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `						lo = lz77h_br_read(&br, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `						hi = lz77h_br_read(&br, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `						match_len = lo | (hi << 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `				/* Decode offset */`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `				if (dist_log2 == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `					offset = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `				} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `					unsigned int extra_bits =`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `						lz77h_br_read(&br, dist_log2);`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `					offset = (1u << dist_log2) + extra_bits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `				if (offset > out_pos) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `					kvfree(dec);`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [ERROR_PATH|] `					return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01161 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `				/* Clamp match to available output */`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `				if (out_pos + match_len > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `					match_len = output_len - out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `				/* Byte-by-byte copy for overlapping matches */`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `				copy_src = out_pos - offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `				while (match_len-- > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `					out[out_pos++] = out[copy_src++];`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `		/* Advance input by bytes consumed by bit reader */`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `		in_pos += br.pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `		/* Account for bits buffered but not consumed */`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `		if (br.avail > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `			in_pos -= (br.avail / 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `		kvfree(dec);`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `	return (ssize_t)out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] ` * ksmbd_lz77huff_compress - Compress data using LZ77+Huffman (MS-XCA §2.5)`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] ` * @input:      Input data`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] ` * @input_len:  Length of input data`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] ` * @output:     Output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] ` * @output_len: Size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] ` * This implements a literal-only encoder: all 256 literal symbols are`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] ` * assigned 8-bit codes (balanced table), and no LZ77 back-references`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] ` * are emitted.  The output is spec-valid LZ77+Huffman and can be`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] ` * decompressed by any compliant implementation.`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] ` * Because a literal-only encoding expands data (Huffman table overhead),`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] ` * this function will return 0 (decline) when output >= input, causing`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] ` * the caller to fall back to uncompressed transmission.`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] ` * Returns number of compressed bytes, 0 if not beneficial, negative on error.`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] `static ssize_t ksmbd_lz77huff_compress(const void *input, size_t input_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `					void *output, size_t output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `	const unsigned char *in = input;`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `	unsigned char *out = output;`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `	size_t in_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `	size_t out_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `	while (in_pos < input_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `		size_t block_size = min_t(size_t, input_len - in_pos,`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `					  LZ77H_BLOCK_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `		size_t i;`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `		 * Huffman table: 512 symbols, 4 bits each, 256 bytes total.`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `		 * Symbols 0-255 (literals): length = 8 (fits in 4 bits as 0x8).`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `		 * Symbols 256-511 (matches): length = 0 (not used).`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `		 * Layout: byte[k] = len[2k] | (len[2k+1] << 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] `		 *   bytes 0-127:  both nibbles = 8  => 0x88`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `		 *   bytes 128-255: both nibbles = 0  => 0x00`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `		if (out_pos + 256 > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `		for (i = 0; i < 128; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `			out[out_pos++] = 0x88;`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `		for (i = 128; i < 256; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `			out[out_pos++] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `		 * Encode literals.  With all symbols at length 8, the`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `		 * canonical code for symbol i is simply i (8-bit MSB-first).`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `		 * In our LSB-first bit stream, symbol i is emitted as`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] `		 * bit-reverse(i, 8).`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `		 * We pack symbols into 32-bit LE words (4 symbols per word).`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `		for (i = 0; i < block_size; ) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `			unsigned int word = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `			int j;`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `			if (out_pos + 4 > output_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `				return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `			for (j = 0; j < 4 && i < block_size; j++, i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `				unsigned int v = in[in_pos + i];`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `				unsigned int rev = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `				int b;`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `				/* Bit-reverse 8 bits for LSB-first stream */`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `				for (b = 0; b < 8; b++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `					rev = (rev << 1) | (v & 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `					v >>= 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] `				word |= rev << (j * 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `			out[out_pos++] = (unsigned char)(word);`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `			out[out_pos++] = (unsigned char)(word >> 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `			out[out_pos++] = (unsigned char)(word >> 16);`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `			out[out_pos++] = (unsigned char)(word >> 24);`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `		in_pos += block_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `	/* Literal-only encoding always expands; decline compression */`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `	if (out_pos >= input_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `	return (ssize_t)out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] ` * smb2_compress_data - Compress data using the specified algorithm`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] ` * @algorithm:  Compression algorithm to use (le16 wire value)`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] ` * @src:        Source data buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] ` * @src_len:    Length of source data`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] ` * @dst:        Destination buffer for compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] ` * @dst_len:    Available space in destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] ` * Returns compressed size on success, 0 if data is not compressible`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] ` * or algorithm is not supported, or negative errno on error.`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] ` * I.2: LZ4 (0x0005) is NOT in the MS-SMB2 spec and MUST NOT be`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] ` * advertised.  Although LZ4 decompression is still supported for`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] ` * backward compatibility, the server never actively *compresses* with`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] ` * LZ4 — smb2_compress_data() returns 0 (decline) for LZ4.`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] `VISIBLE_IF_KUNIT int smb2_compress_data(__le16 algorithm, const void *src,`
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `			      unsigned int src_len, void *dst,`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `			      unsigned int dst_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `	if (algorithm == SMB3_COMPRESS_PATTERN_V1)`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `		return smb2_pattern_v1_compress(src, src_len, dst, dst_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `	 * I.2: Do NOT actively compress with LZ4 — it is non-spec.`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `	 * Return 0 (decline) so callers send uncompressed data.`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] `	 * LZ4 decompression is still supported in smb2_decompress_data().`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `	if (algorithm == SMB3_COMPRESS_LZ4)`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `	if (algorithm == SMB3_COMPRESS_LZNT1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] `		ssize_t ret = ksmbd_lznt1_compress(src, src_len, dst, dst_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `		if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `			return (int)ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `		return (int)ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `	if (algorithm == SMB3_COMPRESS_LZ77) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `		ssize_t ret = ksmbd_lz77_compress(src, src_len, dst, dst_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] `		if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `			return (int)ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `		return (int)ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `	if (algorithm == SMB3_COMPRESS_LZ77_HUFF) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `		ssize_t ret = ksmbd_lz77huff_compress(src, src_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `						       dst, dst_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `		if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `			return (int)ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `		return (int)ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `	return 0; /* Unknown algorithm */`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_compress_data);`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] ` * smb2_decompress_data - Decompress data using the specified algorithm`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] ` * @algorithm:      Compression algorithm used (le16 wire value)`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] ` * @src:            Compressed data buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] ` * @src_len:        Length of compressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] ` * @dst:            Destination buffer for decompressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] ` * @dst_len:        Size of destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] ` * @original_size:  Expected original (decompressed) size`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] ` * Returns 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `VISIBLE_IF_KUNIT int smb2_decompress_data(__le16 algorithm, const void *src,`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `				unsigned int src_len, void *dst,`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `				unsigned int dst_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `				unsigned int original_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `	if (algorithm == SMB3_COMPRESS_PATTERN_V1)`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `		return smb2_pattern_v1_decompress(src, src_len, dst, dst_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `						  original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `	if (algorithm == SMB3_COMPRESS_LZ4)`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `		return smb2_lz4_decompress(src, src_len, dst, dst_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `					   original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `	if (algorithm == SMB3_COMPRESS_LZNT1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `		ssize_t ret = ksmbd_lznt1_decompress(src, src_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] `						     dst, dst_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `		if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `			return (int)ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `		if ((unsigned int)ret != original_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [ERROR_PATH|] `			pr_err("LZNT1 decompression size mismatch: got %zd, expected %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01369 [NONE] `			       ret, original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [ERROR_PATH|] `			return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01371 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `	if (algorithm == SMB3_COMPRESS_LZ77) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `		ssize_t ret = ksmbd_lz77_decompress(src, src_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `						    dst, dst_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `		if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] `			return (int)ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `		if ((unsigned int)ret != original_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [ERROR_PATH|] `			pr_err("LZ77 decompression size mismatch: got %zd, expected %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01383 [NONE] `			       ret, original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [ERROR_PATH|] `			return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01385 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] `	if (algorithm == SMB3_COMPRESS_LZ77_HUFF) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `		ssize_t ret = ksmbd_lz77huff_decompress(src, src_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `							 dst, dst_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] `		if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] `			return (int)ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `		if ((unsigned int)ret != original_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [ERROR_PATH|] `			pr_err("LZ77+Huffman decompression size mismatch: got %zd, expected %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01397 [NONE] `			       ret, original_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [ERROR_PATH|] `			return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01399 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [ERROR_PATH|] `	pr_err("Unsupported compression algorithm: 0x%04x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01404 [NONE] `	       le16_to_cpu(algorithm));`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [ERROR_PATH|] `	return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01406 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_decompress_data);`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] ` * smb2_is_compression_transform_hdr - Check if buffer starts with a`
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] ` *                                     compression transform header`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] ` * @buf:  Buffer to check (raw request including RFC1002 4-byte length)`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [PROTO_GATE|] ` * Returns true if the protocol ID matches SMB2_COMPRESSION_TRANSFORM_ID.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01415 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `bool smb2_is_compression_transform_hdr(void *buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `	struct smb2_compression_transform_hdr *hdr = smb2_get_msg(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [PROTO_GATE|] `	return hdr->ProtocolId == SMB2_COMPRESSION_TRANSFORM_ID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01421 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] ` * smb2_decompress_chained - Decompress a chained compression message`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] ` * @buf:        Raw buffer starting at RFC1002 prefix`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] ` * @pdu_length: PDU length (from RFC1002 header, bytes after the 4-byte prefix)`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] ` * @out_buf:    Pre-allocated output buffer for decompressed data`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] ` * @out_size:   Size of out_buf`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] ` * @total_out:  Receives total bytes written to out_buf on success`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] ` * Handles chained compression as defined in MS-SMB2 §2.2.42.1.`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] ` * After the initial smb2_compression_transform_hdr with Flags=CHAINED,`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] ` * the data consists of a series of smb2_compression_chained_payload_hdr`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] ` * segments, each followed by compressed (or uncompressed) data.`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] ` * Returns 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `static int smb2_decompress_chained(const char *buf, unsigned int pdu_length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `				   char *out_buf, unsigned int out_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] `				   unsigned int *total_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] `	const struct smb2_compression_transform_hdr *first_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `	const unsigned char *msg;  /* points to first byte after RFC1002 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `	unsigned int msg_off;      /* current offset within msg[] */`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `	unsigned int out_pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `	msg = (const unsigned char *)(buf + 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] `	first_hdr = (const struct smb2_compression_transform_hdr *)msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] `	 * OriginalCompressedSegmentSize: total uncompressed size of all`
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `	 * chained segments combined.`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] `	*total_out = le32_to_cpu(first_hdr->OriginalCompressedSegmentSize);`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] `	if (*total_out > out_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [ERROR_PATH|] `		pr_err("Chained: total original size %u exceeds buffer %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01457 [NONE] `		       *total_out, out_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01459 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `	 * Skip past the initial transform header to reach the first`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] `	 * chained payload header.`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `	msg_off = sizeof(struct smb2_compression_transform_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] `	while (msg_off < pdu_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] `		const struct smb2_compression_chained_payload_hdr *seg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `		__le16 seg_algo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `		unsigned int seg_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `		unsigned int seg_comp_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] `		const unsigned char *seg_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] `		unsigned int seg_orig_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `		int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] `		if (msg_off + sizeof(*seg) > pdu_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [ERROR_PATH|] `			pr_err("Chained: truncated segment header at offset %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01478 [NONE] `			       msg_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01480 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] `		seg = (const struct smb2_compression_chained_payload_hdr *)`
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `		      (msg + msg_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `		seg_algo     = seg->CompressionAlgorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `		seg_flags    = le16_to_cpu(seg->Flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] `		seg_comp_len = le32_to_cpu(seg->Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `		msg_off += sizeof(*seg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `		if (msg_off + seg_comp_len > pdu_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [ERROR_PATH|] `			pr_err("Chained: segment data overruns PDU (off=%u len=%u pdusz=%u)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01493 [NONE] `			       msg_off, seg_comp_len, pdu_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01495 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] `		seg_data = msg + msg_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `		 * Segment original size: we don't know it explicitly here`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `		 * (it's not in the minimal chained payload header).  Use`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `		 * the remaining output budget as an upper bound.  The`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [NONE] `		 * decompressor will stop at the actual decompressed size.`
  Review: Low-risk line; verify in surrounding control flow.
- L01504 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] `		seg_orig_size = *total_out - out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `		if (seg_algo == SMB3_COMPRESS_NONE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] `			/* Uncompressed segment: copy verbatim */`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] `			if (out_pos + seg_comp_len > out_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [ERROR_PATH|] `				return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01511 [MEM_BOUNDS|] `			memcpy(out_buf + out_pos, seg_data, seg_comp_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01512 [NONE] `			out_pos += seg_comp_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] `			rc = smb2_decompress_data(seg_algo,`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] `						  seg_data, seg_comp_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] `						  out_buf + out_pos,`
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `						  out_size - out_pos,`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `						  seg_orig_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [ERROR_PATH|] `				pr_err("Chained: segment decompress failed: %d (algo=0x%04x)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01521 [NONE] `				       rc, le16_to_cpu(seg_algo));`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] `				return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `			 * smb2_decompress_data verifies exact size only when`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] `			 * it knows seg_orig_size.  Advance by what was written,`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] `			 * which smb2_decompress_data confirmed == seg_orig_size.`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] `			out_pos += seg_orig_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `		msg_off += seg_comp_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `		/* Last segment has Flags without CHAINED bit set */`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [PROTO_GATE|] `		if (!(seg_flags & SMB2_COMPRESSION_FLAG_CHAINED))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01536 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `	*total_out = out_pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] ` * smb2_decompress_req - Decompress a compressed SMB2 request in place`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] ` * @work:  ksmbd_work containing the request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] ` * If the incoming request has a compression transform header, decompress`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] ` * the payload and replace the request buffer with the decompressed version.`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] ` * The decompressed buffer will have standard RFC1002 framing with the`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] ` * original SMB2 header.`
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01552 [NONE] ` * Supports both non-chained and chained compression (MS-SMB2 §2.2.42,`
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] ` * §2.2.42.1).`
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] ` * Returns 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [NONE] `int smb2_decompress_req(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] `	char *buf = work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] `	unsigned int pdu_length = get_rfc1002_len(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] `	struct smb2_compression_transform_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `	unsigned int original_size, offset, compressed_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] `	unsigned int compressed_len, total_decompressed_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] `	__le16 algorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] `	char *decompressed_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `	char *uncompressed_part;`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] `	char *compressed_part;`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] `	if (pdu_length < sizeof(struct smb2_compression_transform_hdr)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [ERROR_PATH|] `		pr_err("Compression transform message too small (%u)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01572 [NONE] `		       pdu_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [ERROR_PATH|] `		return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01574 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] `	hdr = (struct smb2_compression_transform_hdr *)smb2_get_msg(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] `	 * Handle chained compression (MS-SMB2 §2.2.42.1).`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [PROTO_GATE|] `	 * When Flags has SMB2_COMPRESSION_FLAG_CHAINED set, the payload`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01581 [NONE] `	 * consists of a series of smb2_compression_chained_payload_hdr`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] `	 * segments rather than a single compressed region.`
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [PROTO_GATE|] `	if (le16_to_cpu(hdr->Flags) & SMB2_COMPRESSION_FLAG_CHAINED) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01585 [NONE] `		unsigned int max_allowed = 2 * 1024 * 1024;`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] `		unsigned int chain_total;`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] `		if (work->conn && work->conn->vals &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] `		    work->conn->vals->max_trans_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [NONE] `			max_allowed = min_t(unsigned int, max_allowed,`
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `					    work->conn->vals->max_trans_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] `		original_size = le32_to_cpu(hdr->OriginalCompressedSegmentSize);`
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] `		if (original_size > max_allowed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [ERROR_PATH|] `			pr_err("Chained: decompressed size too large: %u (max %u)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01596 [NONE] `			       original_size, max_allowed);`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [ERROR_PATH|] `			return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01598 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01600 [NONE] `		/* Allocate: 4 bytes RFC1002 + decompressed payload */`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [MEM_BOUNDS|] `		decompressed_buf = kvmalloc(original_size + 5,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01602 [NONE] `					    KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] `		if (!decompressed_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01605 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] `		rc = smb2_decompress_chained(buf, pdu_length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `					     decompressed_buf + 4,`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `					     original_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `					     &chain_total);`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] `			kvfree(decompressed_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `		*(__be32 *)decompressed_buf = cpu_to_be32(chain_total);`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [NONE] `		kvfree(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01618 [NONE] `		work->request_buf = decompressed_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [NONE] `			    "Chained decompressed request: %u bytes\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] `			    chain_total);`
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `	/* Non-chained decompression path */`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] `	algorithm = hdr->CompressionAlgorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `	original_size = le32_to_cpu(hdr->OriginalCompressedSegmentSize);`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `	offset = le32_to_cpu(hdr->Offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [NONE] `	 * Security fix (BUG-C02): Validate that the CompressionAlgorithm in the`
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [NONE] `	 * transform header matches the algorithm that was negotiated for this`
  Review: Low-risk line; verify in surrounding control flow.
- L01634 [NONE] `	 * connection.  Without this check a client that negotiated Pattern_V1`
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] `	 * could send a transform header claiming LZ4 (or any other algorithm)`
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `	 * and force the server to invoke an arbitrary decompressor on attacker-`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] `	 * controlled data — a classic algorithm-confusion attack.`
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] `	 * MS-SMB2 §3.3.5.2.3 requires the server to use the negotiated`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `	 * compression algorithm.  If the PDU specifies a different algorithm,`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `	 * drop the packet.`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] `	if (algorithm != work->conn->compress_algorithm) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [ERROR_PATH|] `		pr_err("ksmbd: compression algorithm mismatch: got %d, expected %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01645 [NONE] `		       le16_to_cpu(algorithm),`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `		       le16_to_cpu(work->conn->compress_algorithm));`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01648 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `	 * Decompression bomb cap (BUG-C03): cap original_size at`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] `	 * min(2MB, max_trans_size).`
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `	 * MS-SMB2 §2.2.42 requires OriginalCompressedSegmentSize MUST NOT`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `	 * exceed MaxTransactSize negotiated in the NEGOTIATE response.`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `		unsigned int max_allowed = 2 * 1024 * 1024;`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `		struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `		if (conn && conn->vals && conn->vals->max_trans_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] `			max_allowed = min_t(unsigned int, max_allowed,`
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [NONE] `					    conn->vals->max_trans_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [NONE] `		if (original_size > max_allowed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [ERROR_PATH|] `			pr_err("Decompressed size too large: %u (max %u)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01666 [NONE] `			       original_size, max_allowed);`
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [ERROR_PATH|] `			return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01668 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `	 * Layout (non-chained):`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `	 *   [RFC1002 4B][CompressionTransformHdr]`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] `	 *   [Uncompressed prefix: 'offset' bytes]`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `	 *   [Compressed region]`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [MEM_BOUNDS|] `	if (check_add_overflow(`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01678 [NONE] `		    (unsigned int)sizeof(struct smb2_compression_transform_hdr),`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [NONE] `		    offset, &compressed_offset)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01680 [ERROR_PATH|] `		pr_err("Compression offset overflow: sizeof(hdr) + %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01681 [NONE] `		       offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [ERROR_PATH|] `		return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01683 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [NONE] `	if (compressed_offset > pdu_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [ERROR_PATH|] `		pr_err("Invalid compression offset: %u > PDU length %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01687 [NONE] `		       compressed_offset, pdu_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [ERROR_PATH|] `		return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01689 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [NONE] `	compressed_len = pdu_length - compressed_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [NONE] `	 * Reject excessive amplification ratios (decompression bomb guard).`
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] `	 * Cap at 1024:1 which is generous for legitimate traffic.`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `	if (compressed_len > 0 && original_size > offset &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] `	    (original_size - offset) / 1024 > compressed_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [ERROR_PATH|] `		pr_err("Decompression ratio too high: %u -> %u (compressed %u)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01700 [NONE] `		       compressed_len, original_size - offset, compressed_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [ERROR_PATH|] `		return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01702 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] `	uncompressed_part = (char *)hdr +`
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] `			    sizeof(struct smb2_compression_transform_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] `	compressed_part = (char *)hdr + compressed_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [NONE] `	if (original_size < offset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [ERROR_PATH|] `		pr_err("Invalid: original size %u < offset %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01710 [NONE] `		       original_size, offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [ERROR_PATH|] `		return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01712 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `	total_decompressed_len = original_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] `	/* Allocate buffer: 4 bytes RFC1002 + decompressed payload */`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [MEM_BOUNDS|] `	decompressed_buf = kvmalloc(total_decompressed_len + 5,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01718 [NONE] `				    KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] `	if (!decompressed_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01721 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [NONE] `	/* Set RFC1002 length header */`
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [NONE] `	*(__be32 *)decompressed_buf = cpu_to_be32(total_decompressed_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] `	/* Copy uncompressed prefix */`
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [NONE] `	if (offset > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [MEM_BOUNDS|] `		memcpy(decompressed_buf + 4, uncompressed_part, offset);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01728 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] `	/* Decompress the compressed region */`
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] `	if (compressed_len > 0 && (original_size - offset) > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] `		rc = smb2_decompress_data(algorithm, compressed_part,`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `					  compressed_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `					  decompressed_buf + 4 + offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] `					  total_decompressed_len - offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [NONE] `					  original_size - offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [ERROR_PATH|] `			pr_err("Decompression failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01738 [NONE] `			kvfree(decompressed_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01739 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [NONE] `	/* Replace the request buffer with the decompressed version */`
  Review: Low-risk line; verify in surrounding control flow.
- L01744 [NONE] `	kvfree(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `	work->request_buf = decompressed_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] `	ksmbd_debug(SMB, "Decompressed request: %u -> %u bytes (algo=0x%04x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `		    pdu_length, total_decompressed_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] `		    le16_to_cpu(algorithm));`
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01754 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] ` * smb2_compress_resp - Compress an SMB2 response if beneficial`
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] ` * @work:  ksmbd_work containing the response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01758 [NONE] ` * Attempts to compress the SMB2 response payload. If compression`
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] ` * is negotiated and the message exceeds the compression threshold,`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] ` * the response is replaced with a compression transform header`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] ` * followed by the compressed payload.`
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] ` * Compression is skipped if:`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] ` *   - No compression algorithm was negotiated`
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] ` *   - The message is already encrypted`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] ` *   - The message is too small (below threshold)`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] ` *   - Compression does not reduce the message size`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] ` * Multi-iov responses (e.g., SMB2 READ with iov[0]=RFC1002 4-byte header,`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] ` * iov[1]=SMB2 response struct, iov[2]=file data) are handled by`
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] ` * linearizing all payload iovs (iov[1..n]) into a contiguous buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] ` * before compression.`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] ` * Returns 0 on success (including when compression is skipped),`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] ` * negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01777 [NONE] `int smb2_compress_resp(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [NONE] `	struct kvec *iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L01781 [NONE] `	struct smb2_hdr *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] `	struct smb2_compression_transform_hdr *comp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] `	void *payload_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `	unsigned int payload_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `	bool payload_allocated = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] `	void *compressed_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] `	void *comp_transform_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [NONE] `	int compressed_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] `	unsigned int comp_transform_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [NONE] `	__le16 algorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L01791 [NONE] `	unsigned int total_rsp_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] `	unsigned int smb2_hdr_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] `	/* Skip if no compression negotiated */`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] `	if (conn->compress_algorithm == SMB3_COMPRESS_NONE)`
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [NONE] `	/* Skip if the response is encrypted */`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [NONE] `	if (work->encrypted)`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01803 [NONE] `	/* We need at least iov[0] (RFC1002) and iov[1] (SMB2 header) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `	if (!work->iov_idx || !work->iov || work->iov_cnt < 2)`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] `	iov = work->iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] `	algorithm = conn->compress_algorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] `	 * iov[0].iov_base = work->response_buf, iov[0].iov_len = 4`
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [NONE] `	 *   Contains RFC1002 4-byte length prefix.`
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] `	 * iov[1].iov_base = SMB2 response header + command response`
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [NONE] `	 * iov[2].iov_base = auxiliary data (file data for READ, etc.)`
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01816 [NONE] `	 * total_rsp_len = bytes after the RFC1002 prefix`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [NONE] `	 *               = sum of iov[1..n].iov_len`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [NONE] `	total_rsp_len = get_rfc1002_len(iov[0].iov_base);`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] `	/* Check minimum size threshold */`
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [PROTO_GATE|] `	if (total_rsp_len < SMB2_COMPRESSION_THRESHOLD)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01823 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01824 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [NONE] `	/* iov[1] must hold at least the SMB2 header */`
  Review: Low-risk line; verify in surrounding control flow.
- L01826 [NONE] `	smb2_hdr_size = sizeof(struct smb2_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `	if (iov[1].iov_len < smb2_hdr_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `	rsp_hdr = iov[1].iov_base;`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01832 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `	 * payload_len = everything after the SMB2 header (what we compress).`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] `	 * The SMB2 header itself becomes the uncompressed Offset prefix.`
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] `	if (total_rsp_len <= smb2_hdr_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01838 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] `	payload_len = total_rsp_len - smb2_hdr_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `	if (work->iov_cnt == 2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `		 * Simple case: all data is in iov[1].`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] `		 * The payload starts immediately after the SMB2 header.`
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [NONE] `		payload_buf = (char *)iov[1].iov_base + smb2_hdr_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [NONE] `		payload_allocated = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01849 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `		 * Multi-iov case (e.g., READ response with iov[2] = file data).`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [NONE] `		 * Linearize the body of iov[1] plus iov[2..n] into one buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L01852 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] `		unsigned int linear_off = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] `		char *linear;`
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01856 [MEM_BOUNDS|] `		linear = kvmalloc(payload_len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01857 [NONE] `		if (!linear)`
  Review: Low-risk line; verify in surrounding control flow.
- L01858 [NONE] `			return 0; /* Fail silently — send uncompressed */`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [NONE] `		/* Tail portion of iov[1] (after the SMB2 header) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [NONE] `			unsigned int iov1_body =`
  Review: Low-risk line; verify in surrounding control flow.
- L01863 [NONE] `				(iov[1].iov_len > smb2_hdr_size) ?`
  Review: Low-risk line; verify in surrounding control flow.
- L01864 [NONE] `				(iov[1].iov_len - smb2_hdr_size) : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `			if (iov1_body > payload_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [NONE] `				iov1_body = payload_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01868 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [NONE] `			if (iov1_body > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [MEM_BOUNDS|] `				memcpy(linear,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01871 [NONE] `				       (char *)iov[1].iov_base + smb2_hdr_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01872 [NONE] `				       iov1_body);`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `				linear_off += iov1_body;`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01875 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01876 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [NONE] `		/* Remaining iovs (iov[2], iov[3], ...) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] `		for (i = 2; i < work->iov_cnt && linear_off < payload_len; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `			unsigned int copy_len = min_t(unsigned int,`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [NONE] `						      iov[i].iov_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [NONE] `						      payload_len - linear_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L01882 [NONE] `			if (iov[i].iov_base && copy_len > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01883 [MEM_BOUNDS|] `				memcpy(linear + linear_off,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01884 [NONE] `				       iov[i].iov_base, copy_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [NONE] `				linear_off += copy_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01886 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] `		payload_buf = linear;`
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] `		payload_len = linear_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] `		payload_allocated = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [NONE] `	if (payload_len == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01895 [NONE] `		if (payload_allocated)`
  Review: Low-risk line; verify in surrounding control flow.
- L01896 [NONE] `			kvfree(payload_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01898 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] `	/* Try to compress the payload */`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [MEM_BOUNDS|] `	compressed_buf = kvmalloc(payload_len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01902 [NONE] `	if (!compressed_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [NONE] `		if (payload_allocated)`
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] `			kvfree(payload_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] `	compressed_size = smb2_compress_data(algorithm,`
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] `					     payload_buf, payload_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] `					     compressed_buf, payload_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] `	if (payload_allocated)`
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [NONE] `		kvfree(payload_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01914 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [NONE] `	if (compressed_size <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] `		kvfree(compressed_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] `		return 0; /* Not compressible — send uncompressed */`
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01919 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01921 [NONE] `	 * Build the output:`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [NONE] `	 *   [RFC1002 4B][CompTransformHdr][SMB2Hdr (uncompressed)][Compressed body]`
  Review: Low-risk line; verify in surrounding control flow.
- L01923 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [NONE] `	comp_transform_len = 4 +`
  Review: Low-risk line; verify in surrounding control flow.
- L01925 [NONE] `			     sizeof(struct smb2_compression_transform_hdr) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01926 [NONE] `			     smb2_hdr_size +`
  Review: Low-risk line; verify in surrounding control flow.
- L01927 [NONE] `			     (unsigned int)compressed_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01928 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01929 [NONE] `	/* Only use compression if it actually reduces the message size */`
  Review: Low-risk line; verify in surrounding control flow.
- L01930 [NONE] `	if (comp_transform_len >= total_rsp_len + 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] `		kvfree(compressed_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01934 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [MEM_BOUNDS|] `	comp_transform_buf = kvmalloc(comp_transform_len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01936 [NONE] `	if (!comp_transform_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] `		kvfree(compressed_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01940 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] `	/* RFC1002 length field */`
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `	*(__be32 *)comp_transform_buf = cpu_to_be32(comp_transform_len - 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01944 [NONE] `	/* Compression transform header */`
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [NONE] `	comp_hdr = (struct smb2_compression_transform_hdr *)`
  Review: Low-risk line; verify in surrounding control flow.
- L01946 [NONE] `		   (comp_transform_buf + 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01947 [PROTO_GATE|] `	comp_hdr->ProtocolId = SMB2_COMPRESSION_TRANSFORM_ID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01948 [NONE] `	comp_hdr->OriginalCompressedSegmentSize = cpu_to_le32(total_rsp_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01949 [NONE] `	comp_hdr->CompressionAlgorithm = algorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L01950 [PROTO_GATE|] `	comp_hdr->Flags = cpu_to_le16(SMB2_COMPRESSION_FLAG_NONE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01951 [NONE] `	comp_hdr->Offset = cpu_to_le32(smb2_hdr_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01952 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01953 [NONE] `	/* Uncompressed SMB2 header (Offset bytes) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [MEM_BOUNDS|] `	memcpy(comp_transform_buf + 4 +`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01955 [NONE] `	       sizeof(struct smb2_compression_transform_hdr),`
  Review: Low-risk line; verify in surrounding control flow.
- L01956 [NONE] `	       rsp_hdr, smb2_hdr_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [NONE] `	/* Compressed body */`
  Review: Low-risk line; verify in surrounding control flow.
- L01959 [MEM_BOUNDS|] `	memcpy(comp_transform_buf + 4 +`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01960 [NONE] `	       sizeof(struct smb2_compression_transform_hdr) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01961 [NONE] `	       smb2_hdr_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [NONE] `	       compressed_buf, compressed_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01963 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01964 [NONE] `	kvfree(compressed_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01965 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [NONE] `	/* Collapse the iov array: replace with single compressed buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L01967 [NONE] `	iov[0].iov_base = comp_transform_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [NONE] `	iov[0].iov_len  = comp_transform_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01969 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [NONE] `	work->tr_buf  = comp_transform_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01971 [NONE] `	work->iov_cnt = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [NONE] `	work->iov_idx = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01973 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01974 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `		    "Compressed response: %u -> %u bytes (algo=0x%04x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] `		    total_rsp_len, comp_transform_len - 4,`
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [NONE] `		    le16_to_cpu(algorithm));`
  Review: Low-risk line; verify in surrounding control flow.
- L01978 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
