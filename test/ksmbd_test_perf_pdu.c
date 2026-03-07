// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2026 ksmbd contributors
 *
 *   KUnit micro-benchmark tests for ksmbd PDU processing operations.
 *
 *   SMB2 header validation and calc_size use real production exports:
 *     check_smb2_hdr(), smb2_calc_size() (from smb2misc.c).
 *   Credit charge validation is kept as a local mirror because the
 *   production smb2_validate_credit_charge() requires struct ksmbd_conn *.
 *   Compound parsing, create context parsing, security descriptor parsing,
 *   NDR encoding, and unicode conversion are kept as local mirrors because
 *   the production functions use different struct types or internal state.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/byteorder/generic.h>

/* Production SMB2 types and exports */
#include "smb2pdu.h"

/* ========================================================================
 * Configurable iteration counts
 * ======================================================================== */

#define PDU_ITERS		10000
#define PDU_ITERS_HEAVY		5000

/* ========================================================================
 * Benchmark reporting macros
 * ======================================================================== */

#define BENCH_REPORT(test, name, iters, total_ns, extra)		\
	kunit_info(test,						\
		   "BENCHMARK: %s iters=%u total_ns=%llu "		\
		   "per_iter_ns=%llu %s\n",				\
		   (name), (unsigned int)(iters),			\
		   (unsigned long long)(total_ns),			\
		   (unsigned long long)((total_ns) / (iters)),		\
		   (extra))

#define BENCH_REPORT_THROUGHPUT(test, name, iters, total_ns, bytes)	\
	do {								\
		u64 __mbps = 0;						\
		if ((total_ns) > 0)					\
			__mbps = ((u64)(bytes) * (u64)(iters) * 1000ULL) / \
				 (total_ns);				\
		kunit_info(test,					\
			   "BENCHMARK: %s iters=%u total_ns=%llu "	\
			   "per_iter_ns=%llu throughput_MBps=%llu\n",	\
			   (name), (unsigned int)(iters),		\
			   (unsigned long long)(total_ns),		\
			   (unsigned long long)((total_ns) / (iters)),	\
			   (unsigned long long)__mbps);			\
	} while (0)

/* ========================================================================
 * Credit charge validation -- mirror from smb2misc.c
 *
 * Kept as a local mirror because the production smb2_validate_credit_charge()
 * requires struct ksmbd_conn * which cannot be instantiated in KUnit.
 * ======================================================================== */

#define PERF_SMB2_MAX_CREDITS	8192
#define PERF_SMB2_MAX_BUFFER	65536

static int perf_validate_credit_charge(struct smb2_hdr *hdr,
				       unsigned int payload_sz)
{
	unsigned int credit_charge = le16_to_cpu(hdr->CreditCharge);
	unsigned int expected;

	if (payload_sz == 0)
		expected = 1;
	else
		expected = (payload_sz - 1) / PERF_SMB2_MAX_BUFFER + 1;

	if (credit_charge == 0)
		credit_charge = 1;

	if (credit_charge < expected)
		return -1;

	if (credit_charge > PERF_SMB2_MAX_CREDITS)
		return -1;

	return 0;
}

/* ========================================================================
 * Compound request parsing -- mirror from server.c
 *
 * Kept as a local mirror: the production compound parser is integrated
 * into the request processing pipeline (ksmbd_smb2_check_message) and
 * cannot be called in isolation.
 * ======================================================================== */

struct perf_compound_chain {
	struct smb2_hdr hdrs[8]; /* up to 8 chained requests */
	unsigned int count;
};

static int perf_parse_compound(const u8 *buf, unsigned int buf_len,
			       struct perf_compound_chain *chain)
{
	unsigned int off = 0;

	chain->count = 0;

	while (off + sizeof(struct smb2_hdr) <= buf_len &&
	       chain->count < 8) {
		struct smb2_hdr *hdr;
		__le32 next_cmd;

		hdr = (struct smb2_hdr *)(buf + off);

		if (hdr->ProtocolId != SMB2_PROTO_NUMBER)
			return -1;

		memcpy(&chain->hdrs[chain->count], hdr,
		       sizeof(struct smb2_hdr));
		chain->count++;

		next_cmd = hdr->NextCommand;
		if (next_cmd == 0)
			break;

		off += le32_to_cpu(next_cmd);
		if (off >= buf_len)
			return -1;
	}

	return (int)chain->count;
}

/* ========================================================================
 * Create context parsing -- mirror from smb2pdu.c
 *
 * Kept as a local mirror: the production smb2_find_context_vals() uses
 * request buffer offsets relative to struct ksmbd_work.
 * ======================================================================== */

struct perf_create_context {
	__le32 next;
	__le16 name_offset;
	__le16 name_length;
	__le16 reserved;
	__le16 data_offset;
	__le32 data_length;
	u8     buffer[]; /* name + data follow */
} __packed;

static int perf_parse_create_contexts(const u8 *buf, unsigned int len)
{
	unsigned int off = 0;
	int count = 0;

	while (off < len) {
		struct perf_create_context *ctx;
		__le32 next;

		if (off + sizeof(struct perf_create_context) > len)
			return -1;

		ctx = (struct perf_create_context *)(buf + off);
		count++;

		next = ctx->next;
		if (next == 0)
			break;

		off += le32_to_cpu(next);
		if (off >= len)
			return -1;
	}

	return count;
}

/* ========================================================================
 * Security descriptor parsing -- mirror from smbacl.c
 *
 * Kept as a local mirror because the production parse_sec_desc() requires
 * struct mnt_idmap * and struct smb_fattr * which need VFS context.
 * ======================================================================== */

#define PERF_NUM_AUTHS			6
#define PERF_SID_MAX_SUB_AUTHORITIES	15

struct perf_smb_sid {
	__u8   revision;
	__u8   num_subauth;
	__u8   authority[PERF_NUM_AUTHS];
	__le32 sub_auth[PERF_SID_MAX_SUB_AUTHORITIES];
} __packed;

#define PERF_SID_BASE_SIZE (1 + 1 + PERF_NUM_AUTHS)

struct perf_smb_ace {
	__u8   type;
	__u8   flags;
	__le16 size;
	__le32 access_req;
	struct perf_smb_sid sid;
} __packed;

struct perf_smb_acl {
	__le16 revision;
	__le16 size;
	__le16 num_aces;
	__le16 reserved;
} __packed;

struct perf_smb_ntsd {
	__le16 revision;
	__le16 type;
	__le32 osidoffset;
	__le32 gsidoffset;
	__le32 sacloffset;
	__le32 dacloffset;
} __packed;

static int perf_parse_sec_desc(const u8 *buf, unsigned int len)
{
	struct perf_smb_ntsd *ntsd;
	struct perf_smb_acl *dacl;
	unsigned int dacl_off;
	__le16 num_aces;
	unsigned int ace_off;
	int i;

	if (len < sizeof(struct perf_smb_ntsd))
		return -1;

	ntsd = (struct perf_smb_ntsd *)buf;

	/* Validate revision */
	if (le16_to_cpu(ntsd->revision) != 1)
		return -1;

	dacl_off = le32_to_cpu(ntsd->dacloffset);
	if (dacl_off == 0 || dacl_off + sizeof(struct perf_smb_acl) > len)
		return -1;

	dacl = (struct perf_smb_acl *)(buf + dacl_off);
	num_aces = dacl->num_aces;

	/* Walk ACE list */
	ace_off = dacl_off + sizeof(struct perf_smb_acl);
	for (i = 0; i < le16_to_cpu(num_aces); i++) {
		struct perf_smb_ace *ace;

		if (ace_off + sizeof(struct perf_smb_ace) > len)
			return -1;

		ace = (struct perf_smb_ace *)(buf + ace_off);
		ace_off += le16_to_cpu(ace->size);
	}

	return le16_to_cpu(num_aces);
}

/* ========================================================================
 * NDR encoding -- mirror from ndr.c
 *
 * Kept as a local mirror because the production ndr_encode_dos_attr()
 * and ndr_decode_dos_attr() use struct ndr and struct xattr_dos_attrib
 * which are tightly coupled to the xattr subsystem.
 * ======================================================================== */

struct perf_ndr {
	u8		*data;
	unsigned int	offset;
	unsigned int	length;
};

static int perf_ndr_write_int32(struct perf_ndr *n, u32 value)
{
	if (n->offset + 4 > n->length)
		return -1;

	*(__le32 *)(n->data + n->offset) = cpu_to_le32(value);
	n->offset += 4;
	return 0;
}

static int perf_ndr_read_int32(struct perf_ndr *n, u32 *value)
{
	if (n->offset + 4 > n->length)
		return -1;

	*value = le32_to_cpu(*(__le32 *)(n->data + n->offset));
	n->offset += 4;
	return 0;
}

/* Encode a simplified DOS attribute structure */
static int perf_ndr_encode_dos_attr(struct perf_ndr *n, u32 attrs,
				    u64 create_time, u64 change_time)
{
	int ret;

	ret = perf_ndr_write_int32(n, 0x0002);  /* version */
	if (ret) return ret;
	ret = perf_ndr_write_int32(n, attrs);
	if (ret) return ret;
	ret = perf_ndr_write_int32(n, (u32)create_time);
	if (ret) return ret;
	ret = perf_ndr_write_int32(n, (u32)(create_time >> 32));
	if (ret) return ret;
	ret = perf_ndr_write_int32(n, (u32)change_time);
	if (ret) return ret;
	ret = perf_ndr_write_int32(n, (u32)(change_time >> 32));
	if (ret) return ret;

	return 0;
}

static int perf_ndr_decode_dos_attr(struct perf_ndr *n, u32 *attrs,
				    u64 *create_time)
{
	u32 version, lo, hi;
	int ret;

	ret = perf_ndr_read_int32(n, &version);
	if (ret) return ret;
	ret = perf_ndr_read_int32(n, attrs);
	if (ret) return ret;
	ret = perf_ndr_read_int32(n, &lo);
	if (ret) return ret;
	ret = perf_ndr_read_int32(n, &hi);
	if (ret) return ret;

	*create_time = ((u64)hi << 32) | lo;
	return 0;
}

/* ========================================================================
 * Unicode conversion -- mirror from unicode.c
 *
 * Kept as a local mirror because the production smb_from_utf16() and
 * smb_strtoUTF16() use struct nls_table * and internal codepage tables.
 * ======================================================================== */

static int perf_utf8_to_utf16le(const char *src, unsigned int src_len,
				__le16 *dst, unsigned int dst_max_chars)
{
	unsigned int si = 0, di = 0;

	while (si < src_len && di < dst_max_chars) {
		u8 c = (u8)src[si];

		if (c < 0x80) {
			/* ASCII: direct mapping */
			dst[di++] = cpu_to_le16((u16)c);
			si++;
		} else if ((c & 0xE0) == 0xC0 && si + 1 < src_len) {
			/* 2-byte UTF-8 */
			u16 uc = ((u16)(c & 0x1F) << 6) |
				 ((u16)(src[si + 1] & 0x3F));
			dst[di++] = cpu_to_le16(uc);
			si += 2;
		} else if ((c & 0xF0) == 0xE0 && si + 2 < src_len) {
			/* 3-byte UTF-8 */
			u16 uc = ((u16)(c & 0x0F) << 12) |
				 ((u16)(src[si + 1] & 0x3F) << 6) |
				 ((u16)(src[si + 2] & 0x3F));
			dst[di++] = cpu_to_le16(uc);
			si += 3;
		} else {
			/* Skip invalid/4-byte sequences */
			si++;
		}
	}

	return (int)di;
}

static int perf_utf16le_to_utf8(const __le16 *src, unsigned int src_chars,
				char *dst, unsigned int dst_max_bytes)
{
	unsigned int si = 0, di = 0;

	while (si < src_chars && di < dst_max_bytes) {
		u16 uc = le16_to_cpu(src[si]);

		if (uc < 0x80) {
			dst[di++] = (char)uc;
		} else if (uc < 0x800 && di + 1 < dst_max_bytes) {
			dst[di++] = (char)(0xC0 | (uc >> 6));
			dst[di++] = (char)(0x80 | (uc & 0x3F));
		} else if (di + 2 < dst_max_bytes) {
			dst[di++] = (char)(0xE0 | (uc >> 12));
			dst[di++] = (char)(0x80 | ((uc >> 6) & 0x3F));
			dst[di++] = (char)(0x80 | (uc & 0x3F));
		} else {
			break;
		}
		si++;
	}

	if (di < dst_max_bytes)
		dst[di] = '\0';

	return (int)di;
}

/* ========================================================================
 * Helper: build a valid SMB2 PDU buffer for benchmarking
 * ======================================================================== */

static void build_smb2_hdr(struct smb2_hdr *hdr, u16 command,
			   u64 message_id)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->ProtocolId = SMB2_PROTO_NUMBER;
	hdr->StructureSize = cpu_to_le16(64);
	hdr->Command = cpu_to_le16(command);
	hdr->MessageId = cpu_to_le64(message_id);
	hdr->CreditCharge = cpu_to_le16(1);
	hdr->CreditRequest = cpu_to_le16(31);
	hdr->Id.SyncId.ProcessId = cpu_to_le32(0x1234);
	hdr->Id.SyncId.TreeId = cpu_to_le32(1);
	hdr->SessionId = cpu_to_le64(0x100000001ULL);
}

/* ========================================================================
 * Benchmark 1: SMB2 header validation throughput
 *
 * Uses production check_smb2_hdr() export from smb2misc.c.
 * ======================================================================== */

static void test_perf_hdr_validate(struct kunit *test)
{
	struct smb2_hdr *hdrs;
	u64 start, elapsed;
	int i, valid_count = 0;

	hdrs = vmalloc(PDU_ITERS * sizeof(struct smb2_hdr));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, hdrs);

	/* Pre-build valid headers */
	for (i = 0; i < PDU_ITERS; i++)
		build_smb2_hdr(&hdrs[i], i % NUMBER_OF_SMB2_COMMANDS, i);

	/* Verify correctness on one header */
	KUNIT_ASSERT_EQ(test, check_smb2_hdr(&hdrs[0]), 0);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < PDU_ITERS; i++) {
		if (check_smb2_hdr(&hdrs[i]) == 0)
			valid_count++;
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_EQ(test, valid_count, PDU_ITERS);

	BENCH_REPORT(test, "smb2_hdr_validate", PDU_ITERS, elapsed,
		     "ops/sec");

	vfree(hdrs);
}

/* ========================================================================
 * Benchmark 2: smb2_calc_size throughput
 *
 * Uses production smb2_calc_size() export from smb2misc.c.
 * ======================================================================== */

/* Expected request StructureSize values per command (from smb2misc.c) */
static const __le16 perf_req_struct_sizes[NUMBER_OF_SMB2_COMMANDS] = {
	/* NEGOTIATE    */ cpu_to_le16(36),
	/* SESSION_SETUP */ cpu_to_le16(25),
	/* LOGOFF       */ cpu_to_le16(4),
	/* TREE_CONNECT */ cpu_to_le16(9),
	/* TREE_DISC    */ cpu_to_le16(4),
	/* CREATE       */ cpu_to_le16(57),
	/* CLOSE        */ cpu_to_le16(24),
	/* FLUSH        */ cpu_to_le16(24),
	/* READ         */ cpu_to_le16(49),
	/* WRITE        */ cpu_to_le16(49),
	/* LOCK         */ cpu_to_le16(48),
	/* IOCTL        */ cpu_to_le16(57),
	/* CANCEL       */ cpu_to_le16(4),
	/* ECHO         */ cpu_to_le16(4),
	/* QUERY_DIR    */ cpu_to_le16(33),
	/* CHANGE_NOTIFY */ cpu_to_le16(32),
	/* QUERY_INFO   */ cpu_to_le16(41),
	/* SET_INFO     */ cpu_to_le16(33),
	/* OPLOCK_BREAK */ cpu_to_le16(36),
};

static void test_perf_calc_size(struct kunit *test)
{
	struct smb2_pdu *pdus;
	u64 start, elapsed;
	int i;
	unsigned int total_len = 0;

	pdus = vmalloc(PDU_ITERS * sizeof(struct smb2_pdu));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, pdus);

	/* Build varied PDUs */
	for (i = 0; i < PDU_ITERS; i++) {
		u16 cmd = i % NUMBER_OF_SMB2_COMMANDS;

		build_smb2_hdr(&pdus[i].hdr, cmd, i);
		pdus[i].StructureSize2 = perf_req_struct_sizes[cmd];
	}

	/* Verify */
	{
		unsigned int len = 0;

		KUNIT_ASSERT_EQ(test, smb2_calc_size(&pdus[0], &len), 0);
		KUNIT_ASSERT_GT(test, len, 0U);
	}

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < PDU_ITERS; i++) {
		unsigned int len = 0;

		smb2_calc_size(&pdus[i], &len);
		total_len += len;
	}
	elapsed = ktime_get_ns() - start;

	/* Use total_len to prevent optimization */
	KUNIT_EXPECT_GT(test, total_len, 0U);

	BENCH_REPORT(test, "smb2_calc_size", PDU_ITERS, elapsed, "ops/sec");

	vfree(pdus);
}

/* ========================================================================
 * Benchmark 3: Credit charge validation throughput (local mirror)
 * ======================================================================== */

static void test_perf_credit_validate(struct kunit *test)
{
	struct smb2_hdr *hdrs;
	u64 start, elapsed;
	int i, valid_count = 0;

	hdrs = vmalloc(PDU_ITERS * sizeof(struct smb2_hdr));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, hdrs);

	/* Build headers with varying credit charges */
	for (i = 0; i < PDU_ITERS; i++) {
		build_smb2_hdr(&hdrs[i], SMB2_READ_HE, i);
		/* Vary credit charge from 1 to 4 */
		hdrs[i].CreditCharge = cpu_to_le16((i % 4) + 1);
	}

	/* Verify */
	KUNIT_ASSERT_EQ(test, perf_validate_credit_charge(&hdrs[0], 1024), 0);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < PDU_ITERS; i++) {
		/* Payload sizes: 1K, 4K, 64K, 128K cycling */
		static const unsigned int payload_sizes[] = {
			1024, 4096, 65536, 131072
		};
		unsigned int payload = payload_sizes[i & 3];

		if (perf_validate_credit_charge(&hdrs[i], payload) == 0)
			valid_count++;
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_GT(test, valid_count, 0);

	BENCH_REPORT(test, "credit_charge_validate", PDU_ITERS, elapsed,
		     "ops/sec");

	vfree(hdrs);
}

/* ========================================================================
 * Benchmark 4: Compound request parsing throughput (3-element chain)
 * ======================================================================== */

static void test_perf_compound_parse(struct kunit *test)
{
	u8 *compound_buf;
	struct perf_compound_chain chain;
	unsigned int compound_size;
	u64 start, elapsed;
	int i;

	/*
	 * Build a 3-element compound: CREATE + READ + CLOSE
	 * Each request is 128 bytes (aligned to 8 bytes)
	 */
	compound_size = 3 * 128;
	compound_buf = kzalloc(compound_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compound_buf);

	/* Request 1: CREATE */
	{
		struct smb2_hdr *hdr = (struct smb2_hdr *)compound_buf;

		build_smb2_hdr(hdr, SMB2_CREATE_HE, 1);
		hdr->NextCommand = cpu_to_le32(128);
	}
	/* Request 2: READ (related) */
	{
		struct smb2_hdr *hdr =
			(struct smb2_hdr *)(compound_buf + 128);

		build_smb2_hdr(hdr, SMB2_READ_HE, 2);
		hdr->Flags |= SMB2_FLAGS_RELATED_OPERATIONS;
		hdr->NextCommand = cpu_to_le32(128);
	}
	/* Request 3: CLOSE (related, last) */
	{
		struct smb2_hdr *hdr =
			(struct smb2_hdr *)(compound_buf + 256);

		build_smb2_hdr(hdr, SMB2_CLOSE_HE, 3);
		hdr->Flags |= SMB2_FLAGS_RELATED_OPERATIONS;
		hdr->NextCommand = 0; /* last in chain */
	}

	/* Verify */
	KUNIT_ASSERT_EQ(test,
			perf_parse_compound(compound_buf, compound_size, &chain),
			3);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < PDU_ITERS; i++)
		perf_parse_compound(compound_buf, compound_size, &chain);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT(test, "compound_parse_3_element", PDU_ITERS, elapsed,
		     "ops/sec");

	kfree(compound_buf);
}

/* ========================================================================
 * Benchmark 5: Create context parsing throughput (5-context chain)
 * ======================================================================== */

static void test_perf_create_context_parse(struct kunit *test)
{
	u8 *ctx_buf;
	unsigned int ctx_size;
	int count;
	u64 start, elapsed;
	int i;

	/*
	 * Build a chain of 5 create contexts.
	 * Each context: 32 bytes (header + 4-byte name + 8-byte data + pad)
	 */
	ctx_size = 5 * 32;
	ctx_buf = kzalloc(ctx_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx_buf);

	for (i = 0; i < 5; i++) {
		struct perf_create_context *cc;

		cc = (struct perf_create_context *)(ctx_buf + i * 32);
		cc->next = (i < 4) ? cpu_to_le32(32) : 0;
		cc->name_offset = cpu_to_le16(16); /* offset into buffer */
		cc->name_length = cpu_to_le16(4);
		cc->data_offset = cpu_to_le16(24);
		cc->data_length = cpu_to_le32(8);
	}

	/* Verify */
	count = perf_parse_create_contexts(ctx_buf, ctx_size);
	KUNIT_ASSERT_EQ(test, count, 5);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < PDU_ITERS; i++)
		perf_parse_create_contexts(ctx_buf, ctx_size);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT(test, "create_context_parse_5", PDU_ITERS, elapsed,
		     "ops/sec");

	kfree(ctx_buf);
}

/* ========================================================================
 * Benchmark 6: Security descriptor parsing throughput (DACL with 10 ACEs)
 * ======================================================================== */

static void test_perf_sec_desc_parse(struct kunit *test)
{
	u8 *sd_buf;
	unsigned int sd_size;
	unsigned int ace_total_size;
	int ace_count;
	u64 start, elapsed;
	int i;

	/*
	 * Build a security descriptor with:
	 * - NTSD header (20 bytes)
	 * - Owner SID at offset 20 (28 bytes: base + 2 sub_auth)
	 * - Group SID at offset 48 (28 bytes)
	 * - DACL at offset 76 (8 bytes header + 10 ACEs)
	 * - Each ACE: 36 bytes (header + access_req + SID with 2 sub_auth)
	 */
	ace_total_size = 10 * 36;
	sd_size = 76 + 8 + ace_total_size;
	sd_buf = kzalloc(sd_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sd_buf);

	/* NTSD header */
	{
		struct perf_smb_ntsd *ntsd = (struct perf_smb_ntsd *)sd_buf;

		ntsd->revision = cpu_to_le16(1);
		ntsd->type = cpu_to_le16(0x8004); /* DACL_PRESENT | SELF_RELATIVE */
		ntsd->osidoffset = cpu_to_le32(20);
		ntsd->gsidoffset = cpu_to_le32(48);
		ntsd->sacloffset = 0;
		ntsd->dacloffset = cpu_to_le32(76);
	}

	/* Owner SID (S-1-5-21-x-y-z-1000) */
	{
		struct perf_smb_sid *sid = (struct perf_smb_sid *)(sd_buf + 20);

		sid->revision = 1;
		sid->num_subauth = 2;
		sid->authority[5] = 5;
		sid->sub_auth[0] = cpu_to_le32(21);
		sid->sub_auth[1] = cpu_to_le32(1000);
	}

	/* Group SID */
	{
		struct perf_smb_sid *sid = (struct perf_smb_sid *)(sd_buf + 48);

		sid->revision = 1;
		sid->num_subauth = 2;
		sid->authority[5] = 5;
		sid->sub_auth[0] = cpu_to_le32(21);
		sid->sub_auth[1] = cpu_to_le32(513);
	}

	/* DACL header */
	{
		struct perf_smb_acl *dacl = (struct perf_smb_acl *)(sd_buf + 76);

		dacl->revision = cpu_to_le16(2);
		dacl->size = cpu_to_le16(8 + ace_total_size);
		dacl->num_aces = cpu_to_le16(10);
	}

	/* 10 ACEs */
	for (i = 0; i < 10; i++) {
		struct perf_smb_ace *ace;

		ace = (struct perf_smb_ace *)(sd_buf + 84 + i * 36);
		ace->type = (i % 2 == 0) ? 0x00 : 0x01; /* ALLOWED/DENIED */
		ace->flags = 0;
		ace->size = cpu_to_le16(36);
		ace->access_req = cpu_to_le32(0x1F01FF); /* FILE_GENERIC_ALL */
		ace->sid.revision = 1;
		ace->sid.num_subauth = 2;
		ace->sid.authority[5] = 5;
		ace->sid.sub_auth[0] = cpu_to_le32(21);
		ace->sid.sub_auth[1] = cpu_to_le32(1000 + i);
	}

	/* Verify */
	ace_count = perf_parse_sec_desc(sd_buf, sd_size);
	KUNIT_ASSERT_EQ(test, ace_count, 10);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < PDU_ITERS; i++)
		perf_parse_sec_desc(sd_buf, sd_size);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT(test, "sec_desc_parse_10_aces", PDU_ITERS, elapsed,
		     "ops/sec");

	kfree(sd_buf);
}

/* ========================================================================
 * Benchmark 7: NDR encoding/decoding throughput (local mirror)
 * ======================================================================== */

static void test_perf_ndr_encode_decode(struct kunit *test)
{
	struct perf_ndr n;
	u8 *buf;
	u64 start, elapsed;
	int i;

	buf = kzalloc(4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);

	/* Verify roundtrip */
	n.data = buf;
	n.offset = 0;
	n.length = 4096;
	KUNIT_ASSERT_EQ(test,
			perf_ndr_encode_dos_attr(&n, 0x20, 132456789ULL,
						 987654321ULL),
			0);
	{
		u32 attrs = 0;
		u64 create_time = 0;

		n.offset = 0;
		KUNIT_ASSERT_EQ(test,
				perf_ndr_decode_dos_attr(&n, &attrs,
							 &create_time),
				0);
		KUNIT_ASSERT_EQ(test, attrs, 0x20U);
	}

	/* Benchmark: encode + decode cycle */
	start = ktime_get_ns();
	for (i = 0; i < PDU_ITERS; i++) {
		u32 attrs;
		u64 ct;

		n.offset = 0;
		perf_ndr_encode_dos_attr(&n, 0x20 + (i & 0xFF),
					 (u64)i * 1000, (u64)i * 2000);

		n.offset = 0;
		perf_ndr_decode_dos_attr(&n, &attrs, &ct);
	}
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT(test, "ndr_encode_decode_cycle", PDU_ITERS, elapsed,
		     "ops/sec");

	kfree(buf);
}

/* ========================================================================
 * Benchmark 8: Unicode conversion throughput (local mirror)
 * ======================================================================== */

static void test_perf_unicode_convert(struct kunit *test)
{
	char utf8_path[512];
	__le16 *utf16_buf;
	char *roundtrip_buf;
	int utf16_len, utf8_len;
	u64 start, elapsed;
	int i;

	/* Build a typical 256-char SMB path (ASCII range) */
	for (i = 0; i < 256; i++) {
		if (i % 32 == 0 && i > 0)
			utf8_path[i] = '\\';
		else
			utf8_path[i] = 'a' + (i % 26);
	}
	utf8_path[256] = '\0';

	utf16_buf = kzalloc(512 * sizeof(__le16), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, utf16_buf);
	roundtrip_buf = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, roundtrip_buf);

	/* Verify roundtrip */
	utf16_len = perf_utf8_to_utf16le(utf8_path, 256, utf16_buf, 512);
	KUNIT_ASSERT_EQ(test, utf16_len, 256);
	utf8_len = perf_utf16le_to_utf8(utf16_buf, utf16_len,
					roundtrip_buf, 1024);
	KUNIT_ASSERT_EQ(test, utf8_len, 256);
	KUNIT_ASSERT_EQ(test, memcmp(utf8_path, roundtrip_buf, 256), 0);

	/* Benchmark: UTF-8 -> UTF-16LE -> UTF-8 roundtrip */
	start = ktime_get_ns();
	for (i = 0; i < PDU_ITERS; i++) {
		utf16_len = perf_utf8_to_utf16le(utf8_path, 256,
						  utf16_buf, 512);
		utf8_len = perf_utf16le_to_utf8(utf16_buf, utf16_len,
						 roundtrip_buf, 1024);
	}
	elapsed = ktime_get_ns() - start;

	/* Use utf8_len to prevent optimization */
	KUNIT_EXPECT_EQ(test, utf8_len, 256);

	BENCH_REPORT_THROUGHPUT(test, "unicode_utf8_utf16_roundtrip_256",
				PDU_ITERS, elapsed, 256 * 2);

	kfree(roundtrip_buf);
	kfree(utf16_buf);
}

/* ========================================================================
 * Test suite registration
 * ======================================================================== */

static struct kunit_case ksmbd_perf_pdu_cases[] = {
	KUNIT_CASE(test_perf_hdr_validate),
	KUNIT_CASE(test_perf_calc_size),
	KUNIT_CASE(test_perf_credit_validate),
	KUNIT_CASE(test_perf_compound_parse),
	KUNIT_CASE(test_perf_create_context_parse),
	KUNIT_CASE(test_perf_sec_desc_parse),
	KUNIT_CASE(test_perf_ndr_encode_decode),
	KUNIT_CASE(test_perf_unicode_convert),
	{}
};

static struct kunit_suite ksmbd_perf_pdu_suite = {
	.name = "ksmbd_perf_pdu",
	.test_cases = ksmbd_perf_pdu_cases,
};

kunit_test_suite(ksmbd_perf_pdu_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit micro-benchmarks for ksmbd PDU processing operations");
