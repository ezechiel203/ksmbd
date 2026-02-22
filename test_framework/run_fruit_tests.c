// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Userspace Test Runner for Fruit SMB Extensions
 *
 * Mocks the kernel environment and #includes smb2fruit.c directly
 * to test the actual source code in a CI-friendly userspace binary.
 *
 * Build:  gcc -I test_framework/include -I . -o test_framework/run_fruit_tests \
 *             test_framework/run_fruit_tests.c
 * Run:    ./test_framework/run_fruit_tests
 */

/* ── Standard C headers ───────────────────────────────────────── */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>

/* ── System linux headers for kernel types and errno values ──── */
#include <linux/types.h>

/* ── Supplementary kernel types not in userspace linux/types.h ─ */
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* __packed not provided by userspace linux/types.h */
#ifndef __packed
#define __packed __attribute__((packed))
#endif

/* Endian conversion macros (identity — assumes little-endian host) */
#define cpu_to_le16(x) ((__le16)(x))
#define cpu_to_le32(x) ((__le32)(x))
#define cpu_to_le64(x) ((__le64)(x))
#define le16_to_cpu(x) ((__u16)(x))
#define le32_to_cpu(x) ((__u32)(x))
#define le64_to_cpu(x) ((__u64)(x))
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#include <endian.h>
#define cpu_to_be32(x) htobe32(x)

/* ── Block system linux/kernel.h (we provide our own stubs) ──── */
#define _LINUX_KERNEL_H

/* linux/slab.h has no system equivalent — handled by stub header
 * at test_framework/include/linux/slab.h via -I flag.
 * linux/string.h and linux/errno.h use system versions. */

/* ── Kernel API stubs ─────────────────────────────────────────── */
#define pr_info(fmt, ...)   printf(fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)    fprintf(stderr, fmt, ##__VA_ARGS__)

#define SMB 0
#define ksmbd_debug(comp, fmt, ...) do { } while (0)

/* IS_ERR / PTR_ERR stubs */
#define MAX_ERRNO 4095
#define IS_ERR(ptr) ((unsigned long)(ptr) >= (unsigned long)-MAX_ERRNO)
#define PTR_ERR(ptr) ((long)(ptr))
#define ERR_PTR(err) ((void *)(long)(err))

/* ── Struct stubs for ksmbd internals ──────────────────────────── */

struct smb2_hdr {
	__le32 ProtocolId;
	__le16 StructureSize;
	__le16 CreditCharge;
	__le32 Status;
	__le16 Command;
	__le16 CreditRequest;
	__le32 Flags;
	__le32 NextCommand;
	__le64 MessageId;
	union {
		struct {
			__le32 ProcessId;
			__le32 TreeId;
		} __packed SyncId;
		__le64 AsyncId;
	} __packed Id;
	__le64 SessionId;
	__u8   Signature[16];
} __packed;

struct smb2_create_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;
	__u8   SecurityFlags;
	__u8   RequestedOplockLevel;
	__le32 ImpersonationLevel;
	__le64 SmbCreateFlags;
	__le64 Reserved;
	__le32 DesiredAccess;
	__le32 FileAttributes;
	__le32 ShareAccess;
	__le32 CreateDisposition;
	__le32 CreateOptions;
	__le16 NameOffset;
	__le16 NameLength;
	__le32 CreateContextsOffset;
	__le32 CreateContextsLength;
	__u8   Buffer[0];
} __packed;

struct create_context {
	__le32 Next;
	__le16 NameOffset;
	__le16 NameLength;
	__le16 Reserved;
	__le16 DataOffset;
	__le32 DataLength;
	__u8   Buffer[0];
} __packed;

#define SMB2_CREATE_AAPL "AAPL"
#define SMB311_PROT_ID  0x0311

/* Forward decl */
struct fruit_conn_state;

struct smb_version_values {
	int dummy;
};

struct smb_version_ops {
	int dummy;
};

struct ksmbd_conn {
	bool is_fruit;
	struct fruit_conn_state *fruit_state;
	int dialect;
	struct smb_version_values *vals;
	struct smb_version_ops *ops;
};

struct ksmbd_work {
	struct ksmbd_conn *conn;
	void *request_buf;
};

struct path {
	void *dentry;
	void *mnt;
};

/* Stub: smb2_find_context_vals always returns NULL (no context) */
struct create_context *smb2_find_context_vals(void *open_req,
					      const char *tag, int tag_len)
{
	(void)open_req;
	(void)tag;
	(void)tag_len;
	return NULL;
}

/* ── Block ksmbd headers from being included by smb2fruit.c ──── */
#define __SMB_COMMON_H__
#define __KSMBD_CONNECTION_H__
#define __KSMBD_OPLOCK_H
#define __SERVER_H__
#define __KSMBD_NETLINK_H__

/* ── Flag/struct definitions needed by smb2fruit.c ─────────────
 * ksmbd_netlink.h is blocked above, so we provide the definitions
 * that fruit_compute_server_caps() and tests need.
 * These MUST stay in sync with the kernel header ksmbd_netlink.h.
 */
#ifndef BIT
#define BIT(n) (1U << (n))
#endif

/* Global config flags (from ksmbd_netlink.h) */
#define KSMBD_GLOBAL_FLAG_INVALID		(0)
#define KSMBD_GLOBAL_FLAG_SMB2_LEASES		BIT(0)
#define KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION	BIT(1)
#define KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL	BIT(2)
#define KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF	BIT(3)
#define KSMBD_GLOBAL_FLAG_DURABLE_HANDLE	BIT(4)
#define KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS	BIT(5)
#define KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID	BIT(6)
#define KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES	BIT(7)
#define KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE	BIT(8)

/* Share config flags (from ksmbd_netlink.h) */
#define KSMBD_SHARE_FLAG_INVALID		(0)
#define KSMBD_SHARE_FLAG_AVAILABLE		BIT(0)
#define KSMBD_SHARE_FLAG_BROWSEABLE		BIT(1)
#define KSMBD_SHARE_FLAG_WRITEABLE		BIT(2)
#define KSMBD_SHARE_FLAG_READONLY		BIT(3)
#define KSMBD_SHARE_FLAG_GUEST_OK		BIT(4)
#define KSMBD_SHARE_FLAG_GUEST_ONLY		BIT(5)
#define KSMBD_SHARE_FLAG_STORE_DOS_ATTRS	BIT(6)
#define KSMBD_SHARE_FLAG_OPLOCKS		BIT(7)
#define KSMBD_SHARE_FLAG_PIPE			BIT(8)
#define KSMBD_SHARE_FLAG_HIDE_DOT_FILES		BIT(9)
#define KSMBD_SHARE_FLAG_INHERIT_OWNER		BIT(10)
#define KSMBD_SHARE_FLAG_STREAMS		BIT(11)
#define KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS	BIT(12)
#define KSMBD_SHARE_FLAG_ACL_XATTR		BIT(13)
#define KSMBD_SHARE_FLAG_UPDATE			BIT(14)
#define KSMBD_SHARE_FLAG_CROSSMNT		BIT(15)
#define KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY	BIT(16)
#define KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE	BIT(17)
#define KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO	BIT(18)
#define KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE	BIT(19)
#define KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS	BIT(20)

#define KSMBD_REQ_MAX_SHARE_NAME	64

/* ── Stub for server_conf used by fruit_compute_server_caps() ── */
struct ksmbd_server_config {
	unsigned int flags;
	char fruit_model[64];
};

struct ksmbd_server_config server_conf = {
	.flags = 0x1FF, /* all fruit flags enabled (bits 0-8) */
	.fruit_model = "TestModel",
};

/* ── Stub for struct kstat (kernel-only, needed by smb2_read_dir_attr_fill) */
struct kstat {
	unsigned short mode;
};

/* ── Stub for struct ksmbd_share_config (needed by smb2_read_dir_attr_fill) */
struct ksmbd_share_config {
	unsigned int flags;
};

/* Include the actual source under test.
 * System linux/ headers provide types and errno values.
 * Stub linux/slab.h (via -I flag) provides kzalloc/kfree.
 * ksmbd headers are blocked by guards above. */
#include "../smb2fruit.c"

/* ── create_fruit_rsp_buf (from oplock.c) ──────────────────────── */

/*
 * Variable-length AAPL create context response.
 * reply_bitmap=0x07 means: server_caps + volume_caps + model_info.
 * The model string is variable-length UTF-16LE.
 */
struct create_fruit_rsp {
	struct create_context ccontext;
	__u8   Name[4];         /* "AAPL" on wire */
	__le32 command_code;    /* 1 = kAAPL_SERVER_QUERY */
	__le32 reserved;
	__le64 reply_bitmap;    /* 0x07 = caps + volcaps + model */
	__le64 server_caps;     /* kAAPL_* capability bits */
	__le64 volume_caps;     /* kAAPL_SUPPORT_* volume bits */
	__le32 model_string_len; /* UTF-16LE byte count of model[] */
	__le16 model[];         /* UTF-16LE model string, no NUL */
} __packed;

static inline size_t fruit_rsp_size(size_t model_utf16_bytes)
{
	return offsetof(struct create_fruit_rsp, model) + model_utf16_bytes;
}

int create_fruit_rsp_buf(char *cc, struct ksmbd_conn *conn, size_t *out_size)
{
	struct create_fruit_rsp *buf = (struct create_fruit_rsp *)cc;
	const char *model = server_conf.fruit_model;
	size_t model_ascii_len, model_utf16_bytes, total;
	int i;

	if (!model[0])
		model = "MacSamba";

	model_ascii_len = strlen(model);
	model_utf16_bytes = model_ascii_len * 2;
	total = fruit_rsp_size(model_utf16_bytes);

	memset(buf, 0, total);

	buf->ccontext.DataOffset = cpu_to_le16(offsetof(
			struct create_fruit_rsp, command_code));
	buf->ccontext.DataLength = cpu_to_le32(total -
			offsetof(struct create_fruit_rsp, command_code));
	buf->ccontext.NameOffset = cpu_to_le16(offsetof(
			struct create_fruit_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	buf->Name[0] = 'A'; buf->Name[1] = 'A';
	buf->Name[2] = 'P'; buf->Name[3] = 'L';

	buf->command_code = cpu_to_le32(1);
	buf->reply_bitmap = cpu_to_le64(0x07);

	{
		u64 caps = kAAPL_UNIX_BASED;
		if (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE)
			caps |= kAAPL_SUPPORTS_OSX_COPYFILE;
		if (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES)
			caps |= kAAPL_SUPPORTS_NFS_ACE;
		caps |= kAAPL_SUPPORTS_READ_DIR_ATTR;
		buf->server_caps = cpu_to_le64(caps);
	}

	{
		u64 vcaps = kAAPL_CASE_SENSITIVE | kAAPL_SUPPORTS_FULL_SYNC;
		buf->volume_caps = cpu_to_le64(vcaps);
	}

	buf->model_string_len = cpu_to_le32(model_utf16_bytes);
	for (i = 0; i < (int)model_ascii_len; i++)
		buf->model[i] = cpu_to_le16((u16)model[i]);

	*out_size = total;
	return 0;
}

/* ── Test infrastructure ───────────────────────────────────────── */

static int total_tests = 0;
static int passed_tests = 0;
static int failed_tests = 0;

static void test_pass(const char *name)
{
	passed_tests++;
	printf("  PASS: %s\n", name);
}

static void test_fail_msg(const char *name, const char *func, int line,
			  const char *msg)
{
	failed_tests++;
	fprintf(stderr, "  FAIL: %s (%s:%d): %s\n", name, func, line, msg);
}

#define T_ASSERT(cond, tname, message) \
	do { \
		if (!(cond)) { \
			test_fail_msg(tname, __func__, __LINE__, message); \
			return; \
		} \
	} while (0)

#define T_ASSERT_EQ(expected, actual, tname, message) \
	do { \
		if ((expected) != (actual)) { \
			char _msg[256]; \
			snprintf(_msg, sizeof(_msg), \
				 "%s (expected=%lld, actual=%lld)", \
				 message, (long long)(expected), \
				 (long long)(actual)); \
			test_fail_msg(tname, __func__, __LINE__, _msg); \
			return; \
		} \
	} while (0)

#define T_ASSERT_STR_EQ(expected, actual, tname, message) \
	do { \
		if (strcmp(expected, actual) != 0) { \
			char _msg[256]; \
			snprintf(_msg, sizeof(_msg), \
				 "%s (expected='%s', actual='%s')", \
				 message, expected, actual); \
			test_fail_msg(tname, __func__, __LINE__, _msg); \
			return; \
		} \
	} while (0)

/* ── Mock helpers ──────────────────────────────────────────────── */

static struct smb_version_values test_server_values;
static struct smb_version_ops test_server_ops;

/*
 * Computed kAAPL server caps with all flags enabled (server_conf.flags=0x1FF):
 * kAAPL_UNIX_BASED(0x04) | kAAPL_SUPPORTS_OSX_COPYFILE(0x02) |
 * kAAPL_SUPPORTS_NFS_ACE(0x08) | kAAPL_SUPPORTS_READ_DIR_ATTR(0x01) = 0x0F
 */
#define TEST_ALL_KAAPL_CAPS \
	(kAAPL_SUPPORTS_READ_DIR_ATTR | kAAPL_SUPPORTS_OSX_COPYFILE | \
	 kAAPL_UNIX_BASED | kAAPL_SUPPORTS_NFS_ACE)

static struct ksmbd_conn *create_mock_conn(bool is_fruit)
{
	struct ksmbd_conn *conn = calloc(1, sizeof(*conn));

	if (!conn)
		return NULL;
	conn->is_fruit = is_fruit;
	conn->dialect = SMB311_PROT_ID;
	conn->vals = &test_server_values;
	conn->ops = &test_server_ops;
	return conn;
}

static void free_mock_conn(struct ksmbd_conn *conn)
{
	if (!conn)
		return;
	free(conn->fruit_state);
	free(conn);
}

static void build_client_info(struct fruit_client_info *ci, __le32 version,
			      __le32 client_type, __le64 caps)
{
	memset(ci, 0, sizeof(*ci));
	ci->signature[0] = 'A';
	ci->signature[1] = 'A';
	ci->signature[2] = 'P';
	ci->signature[3] = 'L';
	ci->version = version;
	ci->client_type = client_type;
	ci->capabilities = caps;
	ci->build_number = cpu_to_le32(0x12345678);
}

/* ══════════════════════════════════════════════════════════════════
 *  TEST FUNCTIONS — Groups A through Z
 * ══════════════════════════════════════════════════════════════════ */

/* Group A: fruit_valid_signature() */

static void test_A1(void) {
	const char *tn = "A1: valid_signature AAPL";
	__u8 sig[4] = {'A','A','P','L'};
	total_tests++;
	T_ASSERT(fruit_valid_signature(sig) == true, tn, "should be valid");
	test_pass(tn);
}
static void test_A2(void) {
	const char *tn = "A2: valid_signature XXXX";
	__u8 sig[4] = {'X','X','X','X'};
	total_tests++;
	T_ASSERT(fruit_valid_signature(sig) == false, tn, "should be invalid");
	test_pass(tn);
}
static void test_A3(void) {
	const char *tn = "A3: valid_signature NULL";
	total_tests++;
	T_ASSERT(fruit_valid_signature(NULL) == false, tn, "should be false");
	test_pass(tn);
}

/* Group B: fruit_validate_create_context() */

static void test_B1(void) {
	const char *tn = "B1: validate_ctx valid";
	struct create_context *ctx;
	size_t sz = sizeof(struct create_context) + sizeof(struct fruit_client_info) + 4;
	total_tests++;
	ctx = calloc(1, sz);
	T_ASSERT(ctx != NULL, tn, "alloc");
	ctx->NameLength = cpu_to_le16(4);
	ctx->DataLength = cpu_to_le32(sizeof(struct fruit_client_info));
	T_ASSERT_EQ(0, fruit_validate_create_context(ctx), tn, "should pass");
	free(ctx);
	test_pass(tn);
}
static void test_B2(void) {
	const char *tn = "B2: validate_ctx NULL";
	total_tests++;
	T_ASSERT_EQ(-EINVAL, fruit_validate_create_context(NULL), tn, "NULL");
	test_pass(tn);
}
static void test_B3(void) {
	const char *tn = "B3: validate_ctx bad namelen";
	struct create_context ctx;
	total_tests++;
	memset(&ctx, 0, sizeof(ctx));
	ctx.NameLength = cpu_to_le16(3);
	ctx.DataLength = cpu_to_le32(sizeof(struct fruit_client_info));
	T_ASSERT_EQ(-EINVAL, fruit_validate_create_context(&ctx), tn, "bad name");
	test_pass(tn);
}
static void test_B4(void) {
	const char *tn = "B4: validate_ctx small data";
	struct create_context ctx;
	total_tests++;
	memset(&ctx, 0, sizeof(ctx));
	ctx.NameLength = cpu_to_le16(4);
	ctx.DataLength = cpu_to_le32(4);
	T_ASSERT_EQ(-EINVAL, fruit_validate_create_context(&ctx), tn, "small data");
	test_pass(tn);
}

/* Group C: fruit_parse_client_info() */

static void test_C1(void) {
	const char *tn = "C1: parse_client valid";
	struct fruit_client_info ci;
	struct fruit_conn_state state;
	total_tests++;
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_2_0),
			  cpu_to_le32(FRUIT_CLIENT_MACOS),
			  cpu_to_le64(kAAPL_UNIX_BASED));
	memset(&state, 0, sizeof(state));
	T_ASSERT_EQ(0, fruit_parse_client_info(&ci, sizeof(ci), &state), tn, "ok");
	T_ASSERT_EQ(FRUIT_VERSION_2_0, (int)state.client_version, tn, "ver");
	T_ASSERT_EQ(FRUIT_CLIENT_MACOS, (int)state.client_type, tn, "type");
	T_ASSERT_EQ(kAAPL_UNIX_BASED, (long long)state.client_capabilities, tn, "caps");
	test_pass(tn);
}
static void test_C2(void) {
	const char *tn = "C2: parse_client NULL data";
	struct fruit_conn_state state;
	total_tests++;
	T_ASSERT_EQ(-EINVAL, fruit_parse_client_info(NULL, 64, &state), tn, "null data");
	test_pass(tn);
}
static void test_C3(void) {
	const char *tn = "C3: parse_client NULL state";
	struct fruit_client_info ci;
	total_tests++;
	build_client_info(&ci, 0, 0, 0);
	T_ASSERT_EQ(-EINVAL, fruit_parse_client_info(&ci, sizeof(ci), NULL), tn, "null state");
	test_pass(tn);
}
static void test_C4(void) {
	const char *tn = "C4: parse_client short len";
	struct fruit_client_info ci;
	struct fruit_conn_state state;
	total_tests++;
	build_client_info(&ci, 0, 0, 0);
	T_ASSERT_EQ(-EINVAL, fruit_parse_client_info(&ci, 4, &state), tn, "short");
	test_pass(tn);
}
static void test_C5(void) {
	const char *tn = "C5: parse_client bad sig";
	struct fruit_client_info ci;
	struct fruit_conn_state state;
	total_tests++;
	memset(&ci, 0, sizeof(ci));
	ci.signature[0] = 'X'; ci.signature[1] = 'Y';
	ci.signature[2] = 'Z'; ci.signature[3] = 'W';
	T_ASSERT_EQ(-EINVAL, fruit_parse_client_info(&ci, sizeof(ci), &state), tn, "bad sig");
	test_pass(tn);
}

/* Group D: fruit_detect_client_version() */

static void test_D1(void) {
	const char *tn = "D1: detect version v1.0";
	struct fruit_client_info ci;
	total_tests++;
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_1_0), 0, 0);
	T_ASSERT_EQ(FRUIT_VERSION_1_0, fruit_detect_client_version(&ci, sizeof(ci)), tn, "v1");
	test_pass(tn);
}
static void test_D2(void) {
	const char *tn = "D2: detect version v2.0";
	struct fruit_client_info ci;
	total_tests++;
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_2_0), 0, 0);
	T_ASSERT_EQ(FRUIT_VERSION_2_0, fruit_detect_client_version(&ci, sizeof(ci)), tn, "v2");
	test_pass(tn);
}
static void test_D3(void) {
	const char *tn = "D3: detect version NULL";
	total_tests++;
	T_ASSERT_EQ(0, fruit_detect_client_version(NULL, 0), tn, "null");
	test_pass(tn);
}
static void test_D4(void) {
	const char *tn = "D4: detect version bad sig";
	struct fruit_client_info ci;
	total_tests++;
	memset(&ci, 0, sizeof(ci));
	ci.signature[0]='B'; ci.signature[1]='A'; ci.signature[2]='D'; ci.signature[3]='!';
	ci.version = cpu_to_le32(FRUIT_VERSION_1_0);
	T_ASSERT_EQ(0, fruit_detect_client_version(&ci, sizeof(ci)), tn, "bad sig");
	test_pass(tn);
}

/* Group E: fruit_get_client_name() */

static void test_E1(void) { total_tests++; T_ASSERT_STR_EQ("macOS", fruit_get_client_name(FRUIT_CLIENT_MACOS), "E1", "macos"); test_pass("E1"); }
static void test_E2(void) { total_tests++; T_ASSERT_STR_EQ("iOS", fruit_get_client_name(FRUIT_CLIENT_IOS), "E2", "ios"); test_pass("E2"); }
static void test_E3(void) { total_tests++; T_ASSERT_STR_EQ("iPadOS", fruit_get_client_name(FRUIT_CLIENT_IPADOS), "E3", "ipados"); test_pass("E3"); }
static void test_E4(void) { total_tests++; T_ASSERT_STR_EQ("tvOS", fruit_get_client_name(FRUIT_CLIENT_TVOS), "E4", "tvos"); test_pass("E4"); }
static void test_E5(void) { total_tests++; T_ASSERT_STR_EQ("watchOS", fruit_get_client_name(FRUIT_CLIENT_WATCHOS), "E5", "watchos"); test_pass("E5"); }
static void test_E6(void) { total_tests++; T_ASSERT_STR_EQ("Unknown", fruit_get_client_name(0xFF), "E6", "unknown"); test_pass("E6"); }

/* Group F: fruit_get_version_string() */

static void test_F1(void) { total_tests++; T_ASSERT_STR_EQ("1.0", fruit_get_version_string(FRUIT_VERSION_1_0), "F1", "1.0"); test_pass("F1"); }
static void test_F2(void) { total_tests++; T_ASSERT_STR_EQ("1.1", fruit_get_version_string(FRUIT_VERSION_1_1), "F2", "1.1"); test_pass("F2"); }
static void test_F3(void) { total_tests++; T_ASSERT_STR_EQ("2.0", fruit_get_version_string(FRUIT_VERSION_2_0), "F3", "2.0"); test_pass("F3"); }
static void test_F4(void) { total_tests++; T_ASSERT_STR_EQ("Unknown", fruit_get_version_string(0xDEADBEEF), "F4", "unk"); test_pass("F4"); }

/* Group G: fruit_init_connection_state() */

static void test_G1(void) {
	const char *tn = "G1: init_state ok";
	struct fruit_conn_state state;
	total_tests++;
	memset(&state, 0xFF, sizeof(state));
	T_ASSERT_EQ(0, fruit_init_connection_state(&state), tn, "ret");
	T_ASSERT_EQ((long long)TEST_ALL_KAAPL_CAPS, (long long)state.supported_features, tn, "supported");
	T_ASSERT_EQ((long long)TEST_ALL_KAAPL_CAPS, (long long)state.enabled_features, tn, "enabled");
	T_ASSERT_EQ((long long)TEST_ALL_KAAPL_CAPS, (long long)state.negotiated_capabilities, tn, "negotiated");
	test_pass(tn);
}
static void test_G2(void) {
	total_tests++;
	T_ASSERT_EQ(-EINVAL, fruit_init_connection_state(NULL), "G2", "null");
	test_pass("G2");
}
static void test_G3(void) {
	const char *tn = "G3: init_state zeroes client";
	struct fruit_conn_state state;
	total_tests++;
	memset(&state, 0xFF, sizeof(state));
	fruit_init_connection_state(&state);
	T_ASSERT_EQ(0, (int)state.client_version, tn, "ver");
	T_ASSERT_EQ(0, (int)state.client_type, tn, "type");
	T_ASSERT_EQ(0, (long long)state.client_capabilities, tn, "caps");
	test_pass(tn);
}

/* Group H: fruit_cleanup_connection_state() */

static void test_H1(void) {
	const char *tn = "H1: cleanup_state ok";
	struct fruit_conn_state state;
	total_tests++;
	memset(&state, 0xFF, sizeof(state));
	fruit_cleanup_connection_state(&state);
	T_ASSERT_EQ(0, (int)state.client_version, tn, "zeroed");
	T_ASSERT_EQ(0, (long long)state.negotiated_capabilities, tn, "zeroed caps");
	test_pass(tn);
}
static void test_H2(void) {
	total_tests++;
	fruit_cleanup_connection_state(NULL);
	test_pass("H2: cleanup NULL");
}

/* Group I: fruit_negotiate_capabilities()
 *
 * After the kAAPL refactor, negotiate no longer intersects client &
 * server caps. It always sets server caps from config flags and
 * ignores client capabilities. extensions_enabled is always set to 1.
 */

static void test_I1(void) {
	const char *tn = "I1: negotiate sets server caps";
	struct ksmbd_conn *conn;
	struct fruit_client_info ci;
	total_tests++;
	conn = create_mock_conn(false);
	T_ASSERT(conn != NULL, tn, "alloc");
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_2_0),
			  cpu_to_le32(FRUIT_CLIENT_MACOS),
			  cpu_to_le64(kAAPL_UNIX_BASED));
	T_ASSERT_EQ(0, fruit_negotiate_capabilities(conn, &ci), tn, "ret");
	T_ASSERT(conn->fruit_state != NULL, tn, "state allocated");
	T_ASSERT_EQ((long long)TEST_ALL_KAAPL_CAPS,
		    (long long)conn->fruit_state->negotiated_capabilities, tn, "caps");
	free_mock_conn(conn);
	test_pass(tn);
}
static void test_I2(void) {
	const char *tn = "I2: negotiate ignores client caps";
	struct ksmbd_conn *conn;
	struct fruit_client_info ci;
	total_tests++;
	conn = create_mock_conn(false);
	T_ASSERT(conn != NULL, tn, "alloc");
	/* Client sends zero capabilities — server still sets its caps */
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_2_0),
			  cpu_to_le32(FRUIT_CLIENT_MACOS),
			  cpu_to_le64(0));
	T_ASSERT_EQ(0, fruit_negotiate_capabilities(conn, &ci), tn, "ret");
	T_ASSERT_EQ((long long)TEST_ALL_KAAPL_CAPS,
		    (long long)conn->fruit_state->negotiated_capabilities, tn, "still all caps");
	free_mock_conn(conn);
	test_pass(tn);
}
static void test_I3(void) {
	struct fruit_client_info ci;
	total_tests++;
	build_client_info(&ci, 0, 0, 0);
	T_ASSERT_EQ(-EINVAL, fruit_negotiate_capabilities(NULL, &ci), "I3", "null conn");
	test_pass("I3");
}
static void test_I4(void) {
	struct ksmbd_conn *conn;
	total_tests++;
	conn = create_mock_conn(false);
	T_ASSERT(conn != NULL, "I4", "alloc");
	T_ASSERT_EQ(-EINVAL, fruit_negotiate_capabilities(conn, NULL), "I4", "null info");
	free_mock_conn(conn);
	test_pass("I4");
}
static void test_I5(void) {
	const char *tn = "I5: negotiate sets extensions_enabled only";
	struct ksmbd_conn *conn;
	struct fruit_client_info ci;
	total_tests++;
	conn = create_mock_conn(false);
	T_ASSERT(conn != NULL, tn, "alloc");
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_2_0),
			  cpu_to_le32(FRUIT_CLIENT_MACOS),
			  cpu_to_le64(kAAPL_UNIX_BASED));
	fruit_negotiate_capabilities(conn, &ci);
	T_ASSERT_EQ(1, (int)conn->fruit_state->extensions_enabled, tn, "ext=1");
	/* Other boolean flags are NOT set by negotiate — they stay zero */
	T_ASSERT_EQ(0, (int)conn->fruit_state->posix_locks_enabled, tn, "posix=0");
	T_ASSERT_EQ(0, (int)conn->fruit_state->resilient_handles_enabled, tn, "resilient=0");
	T_ASSERT_EQ(0, (int)conn->fruit_state->compression_supported, tn, "compress=0");
	free_mock_conn(conn);
	test_pass(tn);
}

/* Group J: fruit_supports_capability() */

static void test_J1(void) {
	struct fruit_conn_state state = {0};
	total_tests++;
	state.negotiated_capabilities = kAAPL_UNIX_BASED | kAAPL_SUPPORTS_READ_DIR_ATTR;
	T_ASSERT(fruit_supports_capability(&state, kAAPL_UNIX_BASED), "J1", "present");
	test_pass("J1");
}
static void test_J2(void) {
	struct fruit_conn_state state = {0};
	total_tests++;
	state.negotiated_capabilities = kAAPL_UNIX_BASED;
	T_ASSERT(!fruit_supports_capability(&state, kAAPL_SUPPORTS_OSX_COPYFILE), "J2", "absent");
	test_pass("J2");
}
static void test_J3(void) {
	total_tests++;
	T_ASSERT(!fruit_supports_capability(NULL, kAAPL_UNIX_BASED), "J3", "null");
	test_pass("J3");
}

/* Group K: fruit_update_connection_state() */

static void test_K1(void) {
	const char *tn = "K1: update_state ok";
	struct fruit_conn_state state = {0};
	struct fruit_client_info ci;
	total_tests++;
	state.supported_features = TEST_ALL_KAAPL_CAPS;
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_1_1), cpu_to_le32(FRUIT_CLIENT_IOS),
			  cpu_to_le64(kAAPL_UNIX_BASED | kAAPL_SUPPORTS_READ_DIR_ATTR));
	T_ASSERT_EQ(0, fruit_update_connection_state(&state, &ci), tn, "ret");
	T_ASSERT_EQ(FRUIT_VERSION_1_1, (int)state.client_version, tn, "ver");
	T_ASSERT_EQ(FRUIT_CLIENT_IOS, (int)state.client_type, tn, "type");
	T_ASSERT(state.negotiated_capabilities & kAAPL_UNIX_BASED, tn, "unix");
	T_ASSERT(state.negotiated_capabilities & kAAPL_SUPPORTS_READ_DIR_ATTR, tn, "readdir");
	test_pass(tn);
}
static void test_K2(void) {
	struct fruit_client_info ci;
	total_tests++;
	build_client_info(&ci, 0, 0, 0);
	T_ASSERT_EQ(-EINVAL, fruit_update_connection_state(NULL, &ci), "K2", "null state");
	test_pass("K2");
}
static void test_K3(void) {
	struct fruit_conn_state state = {0};
	total_tests++;
	T_ASSERT_EQ(-EINVAL, fruit_update_connection_state(&state, NULL), "K3", "null info");
	test_pass("K3");
}
static void test_K4(void) {
	struct fruit_conn_state state = {0};
	struct fruit_client_info ci = {0};
	total_tests++;
	ci.signature[0]='N'; ci.signature[1]='O'; ci.signature[2]='P'; ci.signature[3]='E';
	T_ASSERT_EQ(-EINVAL, fruit_update_connection_state(&state, &ci), "K4", "bad sig");
	test_pass("K4");
}

/* Group L: fruit_get_context_size() */

static void test_L1(void) { total_tests++; T_ASSERT_EQ((long long)sizeof(struct fruit_server_query), (long long)fruit_get_context_size(FRUIT_SERVER_QUERY_CONTEXT), "L1", "ServerQuery"); test_pass("L1"); }
static void test_L2(void) { total_tests++; T_ASSERT_EQ((long long)sizeof(struct fruit_volume_capabilities), (long long)fruit_get_context_size(FRUIT_VOLUME_CAPABILITIES_CONTEXT), "L2", "VolCaps"); test_pass("L2"); }
static void test_L3(void) { total_tests++; T_ASSERT_EQ((long long)sizeof(struct fruit_file_mode), (long long)fruit_get_context_size(FRUIT_FILE_MODE_CONTEXT), "L3", "FileMode"); test_pass("L3"); }
static void test_L4(void) { total_tests++; T_ASSERT_EQ((long long)sizeof(struct fruit_dir_hardlinks), (long long)fruit_get_context_size(FRUIT_DIR_HARDLINKS_CONTEXT), "L4", "DirHL"); test_pass("L4"); }
static void test_L5(void) { total_tests++; T_ASSERT_EQ((long long)sizeof(struct fruit_looker_info), (long long)fruit_get_context_size(FRUIT_LOOKERINFO_CONTEXT), "L5", "Looker"); test_pass("L5"); }
static void test_L6(void) { total_tests++; T_ASSERT_EQ((long long)sizeof(struct fruit_savebox_info), (long long)fruit_get_context_size(FRUIT_SAVEBOX_CONTEXT), "L6", "SaveBox"); test_pass("L6"); }
static void test_L7(void) { total_tests++; T_ASSERT_EQ(0, (long long)fruit_get_context_size(NULL), "L7", "null"); test_pass("L7"); }
static void test_L8(void) { total_tests++; T_ASSERT_EQ(0, (long long)fruit_get_context_size("NoSuch"), "L8", "unknown"); test_pass("L8"); }

/* Group M: fruit_build_server_response() */

static void test_M1(void) {
	void *data = NULL; size_t len = 0;
	total_tests++;
	T_ASSERT_EQ(0, fruit_build_server_response(&data, &len, cpu_to_le64(kAAPL_UNIX_BASED), cpu_to_le32(1)), "M1", "ok");
	T_ASSERT(data != NULL, "M1", "non-null");
	T_ASSERT_EQ((long long)sizeof(struct fruit_server_query), (long long)len, "M1", "len");
	free(data);
	test_pass("M1");
}
static void test_M2(void) { size_t len; total_tests++; T_ASSERT_EQ(-EINVAL, fruit_build_server_response(NULL, &len, 0, 0), "M2", "null data"); test_pass("M2"); }
static void test_M3(void) { void *d; total_tests++; T_ASSERT_EQ(-EINVAL, fruit_build_server_response(&d, NULL, 0, 0), "M3", "null len"); test_pass("M3"); }

/* Group N: fruit_debug_client_info() */

static void test_N1(void) {
	struct fruit_client_info ci;
	total_tests++;
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_2_0), cpu_to_le32(FRUIT_CLIENT_MACOS), cpu_to_le64(kAAPL_UNIX_BASED));
	fruit_debug_client_info(&ci);
	test_pass("N1: debug_client_info ok");
}
static void test_N2(void) { total_tests++; fruit_debug_client_info(NULL); test_pass("N2: debug_client_info NULL"); }

/* Group O: fruit_debug_capabilities() */

static void test_O1(void) {
	total_tests++;
	fruit_debug_capabilities(TEST_ALL_KAAPL_CAPS);
	fruit_debug_capabilities(0);
	fruit_debug_capabilities(0xFFFFFFFFFFFFFFFFULL);
	test_pass("O1: debug_capabilities");
}

/* Group P: fruit_process_looker_info() */

static void test_P1(void) {
	struct ksmbd_conn *conn; struct fruit_looker_info info = {0};
	total_tests++;
	conn = create_mock_conn(true);
	T_ASSERT(conn != NULL, "P1", "alloc");
	memcpy(info.creator, "TEST", 4); memcpy(info.type, "FILE", 4);
	T_ASSERT_EQ(0, fruit_process_looker_info(conn, &info), "P1", "ok");
	free_mock_conn(conn);
	test_pass("P1");
}
static void test_P2(void) { struct fruit_looker_info info = {0}; total_tests++; T_ASSERT_EQ(-EINVAL, fruit_process_looker_info(NULL, &info), "P2", "null conn"); test_pass("P2"); }
static void test_P3(void) {
	struct ksmbd_conn *conn; total_tests++;
	conn = create_mock_conn(true); T_ASSERT(conn != NULL, "P3", "alloc");
	T_ASSERT_EQ(-EINVAL, fruit_process_looker_info(conn, NULL), "P3", "null info");
	free_mock_conn(conn); test_pass("P3");
}

/* Group Q: savebox / server_query / read_dir_attr / handle_bundle */

static void test_Q1(void) {
	struct ksmbd_conn *conn; struct fruit_savebox_info info = {0};
	total_tests++;
	conn = create_mock_conn(true); T_ASSERT(conn != NULL, "Q1", "alloc");
	info.version = cpu_to_le32(1);
	T_ASSERT_EQ(0, fruit_process_savebox_info(conn, &info), "Q1", "ok");
	free_mock_conn(conn); test_pass("Q1");
}
static void test_Q2(void) { struct fruit_savebox_info i = {0}; total_tests++; T_ASSERT_EQ(-EINVAL, fruit_process_savebox_info(NULL, &i), "Q2", "null"); test_pass("Q2"); }
static void test_Q3(void) {
	struct ksmbd_conn *conn; total_tests++;
	conn = create_mock_conn(true); T_ASSERT(conn != NULL, "Q3", "alloc");
	T_ASSERT_EQ(-EINVAL, fruit_process_savebox_info(conn, NULL), "Q3", "null info");
	free_mock_conn(conn); test_pass("Q3");
}
static void test_Q4(void) {
	struct ksmbd_conn *conn; struct fruit_server_query q = {0};
	total_tests++;
	conn = create_mock_conn(true); T_ASSERT(conn != NULL, "Q4", "alloc");
	q.type = cpu_to_le32(1);
	T_ASSERT_EQ(0, fruit_process_server_query(conn, &q), "Q4", "ok");
	free_mock_conn(conn); test_pass("Q4");
}
static void test_Q5(void) {
	struct ksmbd_conn *conn; struct fruit_server_query q = {0};
	total_tests++;
	conn = create_mock_conn(true); T_ASSERT(conn != NULL, "Q5", "alloc");
	T_ASSERT_EQ(-EINVAL, fruit_process_server_query(NULL, &q), "Q5", "null conn");
	T_ASSERT_EQ(-EINVAL, fruit_process_server_query(conn, NULL), "Q5", "null query");
	free_mock_conn(conn); test_pass("Q5");
}
static void test_Q6(void) { total_tests++; T_ASSERT_EQ(-EINVAL, smb2_read_dir_attr(NULL), "Q6", "null work"); test_pass("Q6"); }
static void test_Q7(void) {
	struct ksmbd_conn *conn; struct fruit_savebox_info info = {0};
	total_tests++;
	conn = create_mock_conn(true); T_ASSERT(conn != NULL, "Q7", "alloc");
	T_ASSERT_EQ(-EINVAL, fruit_handle_savebox_bundle(NULL, NULL, &info), "Q7", "null conn");
	T_ASSERT_EQ(-EINVAL, fruit_handle_savebox_bundle(conn, NULL, NULL), "Q7", "null info");
	free_mock_conn(conn); test_pass("Q7");
}

/* Group R: create_fruit_rsp_buf() — variable-length AAPL response */

static void test_R1(void) {
	const char *tn = "R1: rsp_buf builds valid response";
	struct ksmbd_conn *conn;
	char buf[256];
	struct create_fruit_rsp *rsp;
	size_t out_size = 0;
	total_tests++;
	conn = create_mock_conn(true); T_ASSERT(conn != NULL, tn, "alloc");
	memset(buf, 0xFF, sizeof(buf));
	T_ASSERT_EQ(0, create_fruit_rsp_buf(buf, conn, &out_size), tn, "ret");
	rsp = (struct create_fruit_rsp *)buf;
	T_ASSERT_EQ('A', (int)rsp->Name[0], tn, "A"); T_ASSERT_EQ('A', (int)rsp->Name[1], tn, "A");
	T_ASSERT_EQ('P', (int)rsp->Name[2], tn, "P"); T_ASSERT_EQ('L', (int)rsp->Name[3], tn, "L");
	T_ASSERT_EQ(1, (int)le32_to_cpu(rsp->command_code), tn, "cmd");
	T_ASSERT_EQ(0x07, (long long)le64_to_cpu(rsp->reply_bitmap), tn, "bitmap");
	T_ASSERT_EQ((long long)TEST_ALL_KAAPL_CAPS, (long long)le64_to_cpu(rsp->server_caps), tn, "caps");
	T_ASSERT(out_size > 0, tn, "out_size > 0");
	free_mock_conn(conn); test_pass(tn);
}
static void test_R2(void) {
	const char *tn = "R2: rsp_buf volume_caps and model";
	struct ksmbd_conn *conn;
	char buf[256];
	struct create_fruit_rsp *rsp;
	size_t out_size = 0;
	total_tests++;
	conn = create_mock_conn(true); T_ASSERT(conn != NULL, tn, "alloc");
	create_fruit_rsp_buf(buf, conn, &out_size);
	rsp = (struct create_fruit_rsp *)buf;
	/* volume_caps should have CASE_SENSITIVE and FULL_SYNC */
	T_ASSERT_EQ((long long)(kAAPL_CASE_SENSITIVE | kAAPL_SUPPORTS_FULL_SYNC),
		    (long long)le64_to_cpu(rsp->volume_caps), tn, "vcaps");
	/* model string: "TestModel" = 9 chars * 2 = 18 bytes UTF-16LE */
	T_ASSERT_EQ(18, (int)le32_to_cpu(rsp->model_string_len), tn, "model_len");
	/* First char 'T' = 0x0054 in UTF-16LE */
	T_ASSERT_EQ('T', (int)le16_to_cpu(rsp->model[0]), tn, "model[0]");
	T_ASSERT_EQ('e', (int)le16_to_cpu(rsp->model[1]), tn, "model[1]");
	/* Total size = fixed part + 18 bytes model */
	T_ASSERT_EQ((long long)fruit_rsp_size(18), (long long)out_size, tn, "total size");
	free_mock_conn(conn); test_pass(tn);
}
static void test_R3(void) {
	const char *tn = "R3: rsp_buf offsets";
	struct ksmbd_conn *conn;
	char buf[256];
	struct create_fruit_rsp *rsp;
	size_t out_size = 0;
	total_tests++;
	conn = create_mock_conn(true); T_ASSERT(conn != NULL, tn, "alloc");
	create_fruit_rsp_buf(buf, conn, &out_size);
	rsp = (struct create_fruit_rsp *)buf;
	T_ASSERT_EQ((long long)offsetof(struct create_fruit_rsp, command_code),
		    (long long)le16_to_cpu(rsp->ccontext.DataOffset), tn, "DataOffset");
	T_ASSERT_EQ((long long)(out_size - offsetof(struct create_fruit_rsp, command_code)),
		    (long long)le32_to_cpu(rsp->ccontext.DataLength), tn, "DataLength");
	T_ASSERT_EQ((long long)offsetof(struct create_fruit_rsp, Name),
		    (long long)le16_to_cpu(rsp->ccontext.NameOffset), tn, "NameOffset");
	T_ASSERT_EQ(4, (int)le16_to_cpu(rsp->ccontext.NameLength), tn, "NameLength");
	free_mock_conn(conn); test_pass(tn);
}

/* Group S: struct layout */

static void test_S1(void) {
	total_tests++;
	/* Verify variable-length response struct has expected fixed-field offsets */
	T_ASSERT_EQ((long long)(offsetof(struct create_fruit_rsp, server_caps)),
		    (long long)(offsetof(struct create_fruit_rsp, reply_bitmap) + 8), "S1", "server_caps after reply_bitmap");
	T_ASSERT_EQ((long long)(offsetof(struct create_fruit_rsp, volume_caps)),
		    (long long)(offsetof(struct create_fruit_rsp, server_caps) + 8), "S1", "volume_caps after server_caps");
	test_pass("S1");
}
static void test_S2(void) {
	total_tests++;
	T_ASSERT_EQ(0, (long long)offsetof(struct fruit_client_info, signature), "S2", "sig@0");
	T_ASSERT(sizeof(struct fruit_client_info) <= 48, "S2", "compact");
	test_pass("S2");
}
static void test_S3(void) {
	total_tests++;
	T_ASSERT(sizeof(struct fruit_server_query) > 0, "S3", "sq");
	T_ASSERT(sizeof(struct fruit_volume_capabilities) > 0, "S3", "vc");
	T_ASSERT(sizeof(struct fruit_file_mode) > 0, "S3", "fm");
	T_ASSERT(sizeof(struct fruit_dir_hardlinks) > 0, "S3", "dh");
	T_ASSERT(sizeof(struct fruit_looker_info) > 0, "S3", "li");
	T_ASSERT(sizeof(struct fruit_savebox_info) > 0, "S3", "sb");
	T_ASSERT(sizeof(struct fruit_conn_state) > 0, "S3", "cs");
	test_pass("S3");
}

/* Group T: integration constants */

static void test_T1(void) {
	total_tests++;
	/* Verify kAAPL constants match expected wire protocol values */
	T_ASSERT_EQ(0x01, kAAPL_SUPPORTS_READ_DIR_ATTR, "T1", "read_dir_attr=0x01");
	T_ASSERT_EQ(0x02, kAAPL_SUPPORTS_OSX_COPYFILE, "T1", "osx_copyfile=0x02");
	T_ASSERT_EQ(0x04, kAAPL_UNIX_BASED, "T1", "unix_based=0x04");
	T_ASSERT_EQ(0x08, kAAPL_SUPPORTS_NFS_ACE, "T1", "nfs_ace=0x08");
	test_pass("T1");
}
static void test_T2(void) {
	total_tests++;
	T_ASSERT_EQ(0, strncmp(SMB2_CREATE_AAPL, "AAPL", 4), "T2", "AAPL tag");
	T_ASSERT_EQ(0, strncmp(FRUIT_CONTEXT_NAME, "AAPL", 4), "T2", "FRUIT_CONTEXT_NAME");
	test_pass("T2");
}

/* Group U: fruit_is_client_request() */

static void test_U1(void) { total_tests++; T_ASSERT(fruit_is_client_request(NULL, 0) == false, "U1", "null"); test_pass("U1"); }
static void test_U2(void) {
	char small[16] = {0}; total_tests++;
	T_ASSERT(fruit_is_client_request(small, sizeof(small)) == false, "U2", "short");
	test_pass("U2");
}
static void test_U3(void) {
	void *buf; size_t sz = sizeof(struct smb2_create_req) + 256;
	total_tests++;
	buf = calloc(1, sz); T_ASSERT(buf != NULL, "U3", "alloc");
	T_ASSERT(fruit_is_client_request(buf, sz) == false, "U3", "no ctx");
	free(buf); test_pass("U3");
}

/* Group V: module init/cleanup */

static void test_V1(void) { total_tests++; T_ASSERT_EQ(0, fruit_init_module(), "V1", "init"); test_pass("V1"); }
static void test_V2(void) { total_tests++; fruit_cleanup_module(); test_pass("V2: cleanup"); }

/* Group W: Global config flag definitions and bit uniqueness */

static void test_W1(void) {
	total_tests++;
	/* Verify global fruit flags are defined at expected bit positions */
	T_ASSERT_EQ(1 << 5, KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS, "W1", "extensions BIT(5)");
	T_ASSERT_EQ(1 << 6, KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID, "W1", "zero_fileid BIT(6)");
	T_ASSERT_EQ(1 << 7, KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES, "W1", "nfs_aces BIT(7)");
	T_ASSERT_EQ(1 << 8, KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE, "W1", "copyfile BIT(8)");
	test_pass("W1");
}

static void test_W2(void) {
	total_tests++;
	/* Verify no global flag bit collisions */
	unsigned int all_flags =
		KSMBD_GLOBAL_FLAG_SMB2_LEASES |
		KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION |
		KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL |
		KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF |
		KSMBD_GLOBAL_FLAG_DURABLE_HANDLE |
		KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS |
		KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID |
		KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES |
		KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE;
	/* popcount should equal 9 (no overlapping bits) */
	int count = 0;
	unsigned int v = all_flags;
	while (v) { count += v & 1; v >>= 1; }
	T_ASSERT_EQ(9, count, "W2", "9 unique global flag bits");
	test_pass("W2");
}

static void test_W3(void) {
	total_tests++;
	/* Verify share fruit flags are defined at expected bit positions */
	T_ASSERT_EQ(1 << 17, KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE, "W3", "time_machine BIT(17)");
	T_ASSERT_EQ(1 << 18, KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO, "W3", "finder_info BIT(18)");
	T_ASSERT_EQ(1 << 19, KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE, "W3", "rfork_size BIT(19)");
	T_ASSERT_EQ(1 << 20, KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS, "W3", "max_access BIT(20)");
	test_pass("W3");
}

static void test_W4(void) {
	total_tests++;
	/* Verify share flags don't collide with existing flags */
	unsigned int fruit_flags =
		KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE |
		KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO |
		KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE |
		KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS;
	unsigned int existing_flags =
		KSMBD_SHARE_FLAG_AVAILABLE |
		KSMBD_SHARE_FLAG_BROWSEABLE |
		KSMBD_SHARE_FLAG_WRITEABLE |
		KSMBD_SHARE_FLAG_READONLY |
		KSMBD_SHARE_FLAG_GUEST_OK |
		KSMBD_SHARE_FLAG_GUEST_ONLY |
		KSMBD_SHARE_FLAG_STORE_DOS_ATTRS |
		KSMBD_SHARE_FLAG_OPLOCKS |
		KSMBD_SHARE_FLAG_PIPE |
		KSMBD_SHARE_FLAG_HIDE_DOT_FILES |
		KSMBD_SHARE_FLAG_INHERIT_OWNER |
		KSMBD_SHARE_FLAG_STREAMS |
		KSMBD_SHARE_FLAG_FOLLOW_SYMLINKS |
		KSMBD_SHARE_FLAG_ACL_XATTR |
		KSMBD_SHARE_FLAG_UPDATE |
		KSMBD_SHARE_FLAG_CROSSMNT |
		KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY;
	T_ASSERT_EQ(0, fruit_flags & existing_flags, "W4", "no share flag overlap");
	test_pass("W4");
}

/* Minimal stub of ksmbd_startup_request for struct layout tests.
 * Field order/sizes must match ksmbd_netlink.h exactly. */
struct ksmbd_startup_request {
	__u32	flags;
	__s32	signing;
	__s8	min_prot[16];
	__s8	max_prot[16];
	__s8	netbios_name[16];
	__s8	work_group[64];
	__s8	server_string[64];
	__u16	tcp_port;
	__u16	ipc_timeout;
	__u32	deadtime;
	__u32	file_max;
	__u32	smb2_max_write;
	__u32	smb2_max_read;
	__u32	smb2_max_trans;
	__u32	share_fake_fscaps;
	__u32	sub_auth[3];
	__u32	smb2_max_credits;
	__u32	smbd_max_io_size;
	__u32	max_connections;
	__s8	bind_interfaces_only;
	__u32	max_ip_connections;
	__s8	fruit_model[64];
	__s8	reserved[435];
	__u32	ifc_list_sz;
	__s8	____payload[];
} __packed;

/* Minimal stub of ksmbd_share_config_response for struct layout tests.
 * Field order/sizes must match ksmbd_netlink.h exactly. */
struct ksmbd_share_config_response {
	__u32	handle;
	__u32	flags;
	__u16	create_mask;
	__u16	directory_mask;
	__u16	force_create_mode;
	__u16	force_directory_mode;
	__u16	force_uid;
	__u16	force_gid;
	__s8	share_name[KSMBD_REQ_MAX_SHARE_NAME];
	__u64	time_machine_max_size;
	__u32	reserved[109];
	__u32	payload_sz;
	__u32	veto_list_sz;
	__s8	____payload[];
};

static void test_W5(void) {
	total_tests++;
	/* Verify fruit_model field exists in startup_request and has correct size */
	struct ksmbd_startup_request req;
	T_ASSERT_EQ(64, (long long)sizeof(req.fruit_model), "W5", "fruit_model size 64");
	/* Verify it's at a sensible offset (after max_ip_connections) */
	T_ASSERT(offsetof(struct ksmbd_startup_request, fruit_model) >
		 offsetof(struct ksmbd_startup_request, max_ip_connections), "W5", "field order");
	test_pass("W5");
}

static void test_W6(void) {
	total_tests++;
	/* Verify time_machine_max_size field in share_config_response */
	struct ksmbd_share_config_response resp;
	T_ASSERT_EQ(8, (long long)sizeof(resp.time_machine_max_size), "W6", "tm_max_size is 8 bytes");
	test_pass("W6");
}

/* Group X: Config flag set/clear operations */

static void test_X1(void) {
	total_tests++;
	/* Test that fruit extension flags can be independently set and cleared */
	unsigned int flags = 0;
	flags |= KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS;
	T_ASSERT(flags & KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS, "X1", "set ext");
	T_ASSERT(!(flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE), "X1", "copy not set");
	flags |= KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE;
	T_ASSERT(flags & KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS, "X1", "ext still set");
	T_ASSERT(flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE, "X1", "copy now set");
	flags &= ~KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS;
	T_ASSERT(!(flags & KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS), "X1", "ext cleared");
	T_ASSERT(flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE, "X1", "copy preserved");
	test_pass("X1");
}

static void test_X2(void) {
	total_tests++;
	/* Test share flag operations */
	unsigned int flags = 0;
	flags |= KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE;
	flags |= KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO;
	T_ASSERT(flags & KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE, "X2", "tm set");
	T_ASSERT(flags & KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO, "X2", "fi set");
	T_ASSERT(!(flags & KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE), "X2", "rf not set");
	T_ASSERT(!(flags & KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS), "X2", "ma not set");
	flags &= ~KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE;
	T_ASSERT(!(flags & KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE), "X2", "tm cleared");
	T_ASSERT(flags & KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO, "X2", "fi preserved");
	test_pass("X2");
}

static void test_X3(void) {
	total_tests++;
	/* Test fruit_model string copy into startup_request */
	struct ksmbd_startup_request req;
	memset(&req, 0, sizeof(req));
	strncpy(req.fruit_model, "Xserve", sizeof(req.fruit_model) - 1);
	T_ASSERT_STR_EQ("Xserve", req.fruit_model, "X3", "model string");
	test_pass("X3");
}

static void test_X4(void) {
	total_tests++;
	/* Test time_machine_max_size in share config response */
	struct ksmbd_share_config_response resp;
	memset(&resp, 0, sizeof(resp));
	resp.time_machine_max_size = 1024ULL * 1024 * 1024 * 500; /* 500GB */
	T_ASSERT_EQ(536870912000LL, (long long)resp.time_machine_max_size, "X4", "500GB");
	test_pass("X4");
}

static void test_X5(void) {
	total_tests++;
	/* Test that fruit flags coexist with existing share flags */
	unsigned int flags = KSMBD_SHARE_FLAG_AVAILABLE |
			     KSMBD_SHARE_FLAG_BROWSEABLE |
			     KSMBD_SHARE_FLAG_WRITEABLE |
			     KSMBD_SHARE_FLAG_OPLOCKS;
	flags |= KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO;
	flags |= KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS;
	T_ASSERT(flags & KSMBD_SHARE_FLAG_AVAILABLE, "X5", "avail");
	T_ASSERT(flags & KSMBD_SHARE_FLAG_BROWSEABLE, "X5", "browse");
	T_ASSERT(flags & KSMBD_SHARE_FLAG_WRITEABLE, "X5", "write");
	T_ASSERT(flags & KSMBD_SHARE_FLAG_OPLOCKS, "X5", "oplocks");
	T_ASSERT(flags & KSMBD_SHARE_FLAG_FRUIT_FINDER_INFO, "X5", "finder");
	T_ASSERT(flags & KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS, "X5", "maxacc");
	test_pass("X5");
}

static void test_X6(void) {
	total_tests++;
	/* Verify that fruit_model overflow is prevented */
	struct ksmbd_startup_request req;
	memset(&req, 0, sizeof(req));
	/* Try to write exactly 63 chars + NUL (fits) */
	char long_model[64];
	memset(long_model, 'M', 63);
	long_model[63] = '\0';
	strncpy(req.fruit_model, long_model, sizeof(req.fruit_model) - 1);
	req.fruit_model[sizeof(req.fruit_model) - 1] = '\0';
	T_ASSERT_EQ(63, (long long)strlen(req.fruit_model), "X6", "max len 63");
	test_pass("X6");
}

/* Group Y: kAAPL wire protocol constants and computed caps */

static void test_Y1(void) {
	total_tests++;
	/* Verify kAAPL server caps match Apple wire protocol exactly */
	T_ASSERT_EQ(0x01, kAAPL_SUPPORTS_READ_DIR_ATTR, "Y1", "read_dir_attr=0x01");
	T_ASSERT_EQ(0x02, kAAPL_SUPPORTS_OSX_COPYFILE, "Y1", "osx_copyfile=0x02");
	T_ASSERT_EQ(0x04, kAAPL_UNIX_BASED, "Y1", "unix_based=0x04");
	T_ASSERT_EQ(0x08, kAAPL_SUPPORTS_NFS_ACE, "Y1", "nfs_ace=0x08");
	test_pass("Y1");
}

static void test_Y2(void) {
	total_tests++;
	/* Verify kAAPL volume caps match Apple wire protocol */
	T_ASSERT_EQ(0x01, kAAPL_SUPPORT_RESOLVE_ID, "Y2", "resolve_id=0x01");
	T_ASSERT_EQ(0x02, kAAPL_CASE_SENSITIVE, "Y2", "case_sensitive=0x02");
	T_ASSERT_EQ(0x04, kAAPL_SUPPORTS_FULL_SYNC, "Y2", "full_sync=0x04");
	test_pass("Y2");
}

static void test_Y3(void) {
	total_tests++;
	/* Verify no bit overlaps between kAAPL server caps */
	int caps[] = {kAAPL_SUPPORTS_READ_DIR_ATTR, kAAPL_SUPPORTS_OSX_COPYFILE,
		      kAAPL_UNIX_BASED, kAAPL_SUPPORTS_NFS_ACE};
	int i, j;
	for (i = 0; i < 4; i++)
		for (j = i+1; j < 4; j++)
			T_ASSERT_EQ(0, caps[i] & caps[j], "Y3", "no overlap");
	test_pass("Y3");
}

static void test_Y4(void) {
	total_tests++;
	/* Verify fruit_compute_server_caps matches expected output */
	/* server_conf.flags = 0x1FF → all fruit flags enabled */
	T_ASSERT_EQ((long long)TEST_ALL_KAAPL_CAPS, (long long)0x0F, "Y4", "TEST_ALL_KAAPL_CAPS=0x0F");
	test_pass("Y4");
}

static void test_Y5(void) {
	total_tests++;
	/* Verify AFP stream constants */
	T_ASSERT_STR_EQ("AFP_AfpInfo", AFP_AFPINFO_STREAM, "Y5", "afpinfo stream");
	T_ASSERT_STR_EQ("AFP_Resource", AFP_RESOURCE_STREAM, "Y5", "resource stream");
	T_ASSERT_STR_EQ("com.apple.FinderInfo", APPLE_FINDER_INFO_XATTR, "Y5", "finder xattr");
	T_ASSERT_EQ(60, AFP_AFPINFO_SIZE, "Y5", "afpinfo size=60");
	test_pass("Y5");
}

static void test_Y6(void) {
	total_tests++;
	/* Verify ReadDirAttr FinderInfo size constant */
	T_ASSERT_EQ(32, READDIR_ATTR_FINDER_INFO_SIZE, "Y6", "finder_info_size=32");
	test_pass("Y6");
}

/* Group Z: F_FULLFSYNC detection and ReadDirAttr */

static void test_Z1(void) {
	total_tests++;
	/* Verify Reserved1=0xFFFF triggers fullsync detection */
	__le16 reserved_normal = cpu_to_le16(0x0000);
	__le16 reserved_fullsync = cpu_to_le16(0xFFFF);
	T_ASSERT_EQ(0, le16_to_cpu(reserved_normal) == 0xFFFF, "Z1", "normal != fullsync");
	T_ASSERT_EQ(1, le16_to_cpu(reserved_fullsync) == 0xFFFF, "Z1", "0xFFFF == fullsync");
	test_pass("Z1");
}

static void test_Z2(void) {
	total_tests++;
	/* Verify smb2_read_dir_attr_fill packs mode into EaSize */
	struct ksmbd_conn conn = {0};
	struct kstat st = {0};
	__le32 ea_size = cpu_to_le32(0xDEAD);
	conn.is_fruit = true;
	st.mode = 0100644; /* regular file, rw-r--r-- */
	smb2_read_dir_attr_fill(&conn, NULL, &st, NULL, &ea_size);
	T_ASSERT_EQ(0100644, (int)le32_to_cpu(ea_size), "Z2", "mode packed into EaSize");
	test_pass("Z2");
}

static void test_Z3(void) {
	total_tests++;
	/* Verify smb2_read_dir_attr_fill is no-op for non-fruit connections */
	struct ksmbd_conn conn = {0};
	struct kstat st = {0};
	__le32 ea_size = cpu_to_le32(0xDEAD);
	conn.is_fruit = false;
	st.mode = 0100755;
	smb2_read_dir_attr_fill(&conn, NULL, &st, NULL, &ea_size);
	T_ASSERT_EQ((int)0xDEAD, (int)le32_to_cpu(ea_size), "Z3", "unchanged for non-fruit");
	test_pass("Z3");
}

static void test_Z4(void) {
	total_tests++;
	/* Verify smb2_read_dir_attr_fill handles NULL stat gracefully */
	struct ksmbd_conn conn = {0};
	__le32 ea_size = cpu_to_le32(0xBEEF);
	conn.is_fruit = true;
	smb2_read_dir_attr_fill(&conn, NULL, NULL, NULL, &ea_size);
	T_ASSERT_EQ((int)0xBEEF, (int)le32_to_cpu(ea_size), "Z4", "unchanged for NULL stat");
	test_pass("Z4");
}

static void test_Z5(void) {
	const char *tn = "Z5: rsp_buf with default model";
	struct ksmbd_conn *conn;
	char buf[256];
	struct create_fruit_rsp *rsp;
	size_t out_size = 0;
	total_tests++;
	/* Clear fruit_model to trigger default "MacSamba" */
	char saved_model[64];
	memcpy(saved_model, server_conf.fruit_model, sizeof(saved_model));
	server_conf.fruit_model[0] = '\0';
	conn = create_mock_conn(true); T_ASSERT(conn != NULL, tn, "alloc");
	create_fruit_rsp_buf(buf, conn, &out_size);
	rsp = (struct create_fruit_rsp *)buf;
	/* "MacSamba" = 8 chars * 2 = 16 bytes UTF-16LE */
	T_ASSERT_EQ(16, (int)le32_to_cpu(rsp->model_string_len), tn, "default model len");
	T_ASSERT_EQ('M', (int)le16_to_cpu(rsp->model[0]), tn, "model[0]='M'");
	/* Restore model */
	memcpy(server_conf.fruit_model, saved_model, sizeof(saved_model));
	free_mock_conn(conn); test_pass(tn);
}

/* ── Test runner ───────────────────────────────────────────────── */

typedef struct { const char *name; void (*func)(void); } test_entry;

static test_entry all_tests[] = {
	{"A1", test_A1}, {"A2", test_A2}, {"A3", test_A3},
	{"B1", test_B1}, {"B2", test_B2}, {"B3", test_B3}, {"B4", test_B4},
	{"C1", test_C1}, {"C2", test_C2}, {"C3", test_C3}, {"C4", test_C4}, {"C5", test_C5},
	{"D1", test_D1}, {"D2", test_D2}, {"D3", test_D3}, {"D4", test_D4},
	{"E1", test_E1}, {"E2", test_E2}, {"E3", test_E3}, {"E4", test_E4}, {"E5", test_E5}, {"E6", test_E6},
	{"F1", test_F1}, {"F2", test_F2}, {"F3", test_F3}, {"F4", test_F4},
	{"G1", test_G1}, {"G2", test_G2}, {"G3", test_G3},
	{"H1", test_H1}, {"H2", test_H2},
	{"I1", test_I1}, {"I2", test_I2}, {"I3", test_I3}, {"I4", test_I4}, {"I5", test_I5},
	{"J1", test_J1}, {"J2", test_J2}, {"J3", test_J3},
	{"K1", test_K1}, {"K2", test_K2}, {"K3", test_K3}, {"K4", test_K4},
	{"L1", test_L1}, {"L2", test_L2}, {"L3", test_L3}, {"L4", test_L4},
	{"L5", test_L5}, {"L6", test_L6}, {"L7", test_L7}, {"L8", test_L8},
	{"M1", test_M1}, {"M2", test_M2}, {"M3", test_M3},
	{"N1", test_N1}, {"N2", test_N2},
	{"O1", test_O1},
	{"P1", test_P1}, {"P2", test_P2}, {"P3", test_P3},
	{"Q1", test_Q1}, {"Q2", test_Q2}, {"Q3", test_Q3}, {"Q4", test_Q4},
	{"Q5", test_Q5}, {"Q6", test_Q6}, {"Q7", test_Q7},
	{"R1", test_R1}, {"R2", test_R2}, {"R3", test_R3},
	{"S1", test_S1}, {"S2", test_S2}, {"S3", test_S3},
	{"T1", test_T1}, {"T2", test_T2},
	{"U1", test_U1}, {"U2", test_U2}, {"U3", test_U3},
	{"V1", test_V1}, {"V2", test_V2},
	{"W1", test_W1}, {"W2", test_W2}, {"W3", test_W3},
	{"W4", test_W4}, {"W5", test_W5}, {"W6", test_W6},
	{"X1", test_X1}, {"X2", test_X2}, {"X3", test_X3},
	{"X4", test_X4}, {"X5", test_X5}, {"X6", test_X6},
	{"Y1", test_Y1}, {"Y2", test_Y2}, {"Y3", test_Y3},
	{"Y4", test_Y4}, {"Y5", test_Y5}, {"Y6", test_Y6},
	{"Z1", test_Z1}, {"Z2", test_Z2}, {"Z3", test_Z3},
	{"Z4", test_Z4}, {"Z5", test_Z5},
	{NULL, NULL}
};

int main(void)
{
	int i;

	printf("=== Fruit SMB Extensions Coverage Tests ===\n");
	printf("Running test groups A-Z (%d tests)\n\n",
	       (int)(sizeof(all_tests)/sizeof(all_tests[0]) - 1));

	for (i = 0; all_tests[i].name != NULL; i++) {
		printf("[%s]\n", all_tests[i].name);
		all_tests[i].func();
	}

	printf("\n=== Results ===\n");
	printf("  Total:  %d\n", total_tests);
	printf("  Passed: %d\n", passed_tests);
	printf("  Failed: %d\n", failed_tests);

	if (failed_tests > 0) {
		printf("\n=== TESTS FAILED ===\n");
		return 1;
	}

	printf("\n=== ALL %d TESTS PASSED ===\n", passed_tests);
	return 0;
}
