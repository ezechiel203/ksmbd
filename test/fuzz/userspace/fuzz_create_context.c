// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Userspace libFuzzer target for SMB2 CREATE context list parsing.
 *
 * Exercises the create context chain traversal that ksmbd performs
 * during SMB2 CREATE request processing (MS-SMB2 2.2.13.2):
 *   - Chained create context list walking via Next field
 *   - NameOffset/NameLength bounds validation
 *   - DataOffset/DataLength bounds validation
 *   - 8-byte alignment of Next and DataOffset fields
 *   - Context name lookup (MxAc, DHnQ, DH2Q, QFid, RqLs, AAPL, etc.)
 *   - Durable handle context data extraction
 *   - Lease context data extraction
 *
 * Build: clang -fsanitize=fuzzer,address,undefined -g -O1 \
 *        -I. fuzz_create_context.c -o fuzz_create_context
 */

#include "ksmbd_compat.h"

/* --- Create context structure (matches smb2pdu.h) --- */

struct create_context {
	__le32 Next;
	__le16 NameOffset;
	__le16 NameLength;
	__le16 Reserved;
	__le16 DataOffset;
	__le32 DataLength;
	__u8   Buffer[];
} __packed;

#define CC_HDR_SIZE offsetof(struct create_context, Buffer)

/* Well-known create context tags */
static const char *const CC_TAGS[] = {
	"DH2Q",  /* Durable Handle V2 Request */
	"DH2C",  /* Durable Handle V2 Reconnect */
	"DHnQ",  /* Durable Handle Request */
	"DHnC",  /* Durable Handle Reconnect */
	"MxAc",  /* Maximum Access */
	"QFid",  /* Query on Disk ID */
	"RqLs",  /* Request Lease */
	"AAPL",  /* Apple Extensions */
	"TWrp",  /* Timewarp (snapshot) */
	"SMB2_CREATE_APP_INSTANCE_ID",
	"SMB2_CREATE_APP_INSTANCE_VERSION",
};
#define NUM_CC_TAGS ARRAY_SIZE(CC_TAGS)

/* --- Lease context data --- */

struct lease_context_v1 {
	__u8   LeaseKey[16];
	__le32 LeaseState;
	__le32 LeaseFlags;
	__le64 LeaseDuration;
} __packed;

struct lease_context_v2 {
	__u8   LeaseKey[16];
	__le32 LeaseState;
	__le32 LeaseFlags;
	__le64 LeaseDuration;
	__u8   ParentLeaseKey[16];
	__le16 Epoch;
	__le16 Reserved;
} __packed;

/* --- Durable handle V2 context data --- */

struct durable_v2_context {
	__le32 Timeout;
	__le32 Flags;
	__u8   Reserved[8];
	__u8   CreateGuid[16];
} __packed;

/* --- Context chain walker --- */

/*
 * find_context_by_tag - Search for a specific create context by name tag.
 *
 * Mirrors smb2_find_context_vals() from ksmbd oplock.c.
 * Returns pointer to matching context, NULL if not found,
 * or (void*)-1 on malformed input.
 */
static const struct create_context *
find_context_by_tag(const u8 *data, size_t data_len,
		    const char *tag, size_t tag_len)
{
	const struct create_context *cc;
	unsigned int next = 0;
	unsigned int remain_len;
	unsigned int name_off, name_len, value_off, value_len, cc_len;
	const char *name;

	if (data_len < CC_HDR_SIZE)
		return (const struct create_context *)(intptr_t)-1;

	remain_len = data_len;
	cc = (const struct create_context *)data;

	do {
		cc = (const struct create_context *)((const char *)cc + next);
		if (remain_len < CC_HDR_SIZE)
			return (const struct create_context *)(intptr_t)-1;

		next = le32_to_cpu(cc->Next);
		name_off = le16_to_cpu(cc->NameOffset);
		name_len = le16_to_cpu(cc->NameLength);
		value_off = le16_to_cpu(cc->DataOffset);
		value_len = le32_to_cpu(cc->DataLength);
		cc_len = next ? next : remain_len;

		/* Bounds and alignment validation */
		if ((next & 0x7) != 0 ||
		    next > remain_len ||
		    name_off != CC_HDR_SIZE ||
		    name_len < tag_len ||
		    name_off + name_len > cc_len ||
		    (value_off & 0x7) != 0 ||
		    (value_len && (value_off < name_off + name_len ||
				   value_off + value_len > cc_len))) {
			return (const struct create_context *)(intptr_t)-1;
		}

		name = (const char *)cc + name_off;
		if (name_len >= tag_len && memcmp(name, tag, tag_len) == 0)
			return cc;

		remain_len -= next;
	} while (next != 0);

	return NULL;
}

/* --- Chain enumeration --- */

static int walk_context_chain(const u8 *data, size_t data_len)
{
	unsigned int offset = 0;
	unsigned int next;
	int count = 0;

	if (data_len < CC_HDR_SIZE)
		return -EINVAL;

	do {
		const struct create_context *cc;
		unsigned int cc_len;
		unsigned int name_off, name_len, value_off, value_len;

		if (offset + CC_HDR_SIZE > data_len)
			break;

		cc = (const struct create_context *)(data + offset);
		next = le32_to_cpu(cc->Next);
		name_off = le16_to_cpu(cc->NameOffset);
		name_len = le16_to_cpu(cc->NameLength);
		value_off = le16_to_cpu(cc->DataOffset);
		value_len = le32_to_cpu(cc->DataLength);

		/* Prevent infinite loops and excessive chains */
		if (next != 0 && (next & 0x7) != 0)
			break;
		if (next != 0 && next > data_len - offset)
			break;

		cc_len = next ? next : (data_len - offset);

		/* Validate NameOffset at minimum */
		if (name_off < CC_HDR_SIZE && name_len > 0)
			break;

		/* Read the name bytes if accessible (absolute bounds, overflow-safe) */
		if (name_len > 0 && name_off <= cc_len &&
		    name_len <= cc_len - name_off) {
			const u8 *name_ptr = data + offset + name_off;
			volatile u8 first = name_ptr[0];
			volatile u8 last = name_ptr[name_len - 1];
			(void)first;
			(void)last;
		}

		/* Read the data bytes if accessible (absolute bounds, overflow-safe) */
		if (value_len > 0 && value_off > 0 &&
		    value_off <= cc_len &&
		    value_len <= cc_len - value_off) {
			const u8 *data_ptr = data + offset + value_off;
			volatile u8 first = data_ptr[0];
			volatile u8 last = data_ptr[value_len - 1];
			(void)first;
			(void)last;
		}

		count++;
		if (next == 0)
			break;

		offset += next;

		if (count > 256)
			break;
	} while (1);

	return count;
}

/* --- Context-specific data extraction --- */

static void extract_lease_data(const struct create_context *cc,
			       const u8 *buf_start, size_t buf_len)
{
	u32 data_len = le32_to_cpu(cc->DataLength);
	u16 data_off = le16_to_cpu(cc->DataOffset);
	const u8 *cc_base = (const u8 *)cc;
	size_t cc_offset_in_buf;

	if (data_len == 0 || data_off == 0)
		return;

	/* Ensure cc + data_off + data_len stays within the original buffer */
	if (cc_base < buf_start || cc_base >= buf_start + buf_len)
		return;
	cc_offset_in_buf = cc_base - buf_start;
	if ((size_t)data_off > buf_len - cc_offset_in_buf)
		return;
	if (data_len > buf_len - cc_offset_in_buf - data_off)
		return;

	const u8 *data = cc_base + data_off;

	/* Try V2 first, fall back to V1 */
	if (data_len >= sizeof(struct lease_context_v2)) {
		const struct lease_context_v2 *lc =
			(const struct lease_context_v2 *)data;
		volatile u32 state = le32_to_cpu(lc->LeaseState);
		volatile u32 flags = le32_to_cpu(lc->LeaseFlags);
		volatile u16 epoch = le16_to_cpu(lc->Epoch);
		(void)state;
		(void)flags;
		(void)epoch;
	} else if (data_len >= sizeof(struct lease_context_v1)) {
		const struct lease_context_v1 *lc =
			(const struct lease_context_v1 *)data;
		volatile u32 state = le32_to_cpu(lc->LeaseState);
		volatile u32 flags = le32_to_cpu(lc->LeaseFlags);
		(void)state;
		(void)flags;
	}
}

static void extract_durable_v2_data(const struct create_context *cc,
				    const u8 *buf_start, size_t buf_len)
{
	u32 data_len = le32_to_cpu(cc->DataLength);
	u16 data_off = le16_to_cpu(cc->DataOffset);
	const u8 *cc_base = (const u8 *)cc;
	size_t cc_offset_in_buf;

	if (data_len < sizeof(struct durable_v2_context) || data_off == 0)
		return;

	/* Ensure cc + data_off + data_len stays within the original buffer */
	if (cc_base < buf_start || cc_base >= buf_start + buf_len)
		return;
	cc_offset_in_buf = cc_base - buf_start;
	if ((size_t)data_off > buf_len - cc_offset_in_buf)
		return;
	if (data_len > buf_len - cc_offset_in_buf - data_off)
		return;

	const u8 *data = cc_base + data_off;
	const struct durable_v2_context *dctx =
		(const struct durable_v2_context *)data;

	volatile u32 timeout = le32_to_cpu(dctx->Timeout);
	volatile u32 flags = le32_to_cpu(dctx->Flags);
	(void)timeout;
	(void)flags;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const struct create_context *result;
	size_t i;

	if (size < CC_HDR_SIZE)
		return 0;

	/* Cap to prevent excessive processing */
	if (size > 65536)
		size = 65536;

	/* Walk the entire chain */
	walk_context_chain(data, size);

	/* Search for each well-known tag */
	for (i = 0; i < NUM_CC_TAGS; i++) {
		size_t tag_len = strlen(CC_TAGS[i]);
		/* Use min of tag_len and 4 for the standard 4-byte tags */
		size_t search_len = tag_len > 4 ? tag_len : 4;

		if (search_len > tag_len)
			search_len = tag_len;

		result = find_context_by_tag(data, size,
					     CC_TAGS[i], search_len);

		if (result && result != (const struct create_context *)(intptr_t)-1) {
			/* Found - extract data for specific context types */
			if (memcmp(CC_TAGS[i], "RqLs", 4) == 0)
				extract_lease_data(result, data, size);
			else if (memcmp(CC_TAGS[i], "DH2Q", 4) == 0)
				extract_durable_v2_data(result, data, size);
		}
	}

	return 0;
}
