// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2025 Alexandre BETRY
 *
 *   Comprehensive Coverage Tests for Fruit SMB Extensions
 *
 *   Tests every function and code path added/modified by the Fruit
 *   SMB extensions vs upstream ksmbd, organized by function group.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "smb2pdu.h"
#include "connection.h"
#include "smb2fruit.h"
#include "oplock.h"

#define TEST_MODULE_NAME "ksmbd_fruit_coverage_test"

/* Test statistics */
static struct {
	atomic_t total;
	atomic_t passed;
	atomic_t failed;
	atomic_t skipped;
} stats;

static void test_pass(const char *name)
{
	atomic_inc(&stats.passed);
	pr_info("  PASS: %s\n", name);
}

static void test_fail(const char *name, const char *func, int line,
		      const char *msg)
{
	atomic_inc(&stats.failed);
	pr_err("  FAIL: %s (%s:%d): %s\n", name, func, line, msg);
}

#define TEST_ASSERT(cond, tname, message) \
	do { \
		if (!(cond)) { \
			test_fail(tname, __func__, __LINE__, message); \
			return; \
		} \
	} while (0)

#define TEST_ASSERT_EQ(expected, actual, tname, message) \
	do { \
		if ((expected) != (actual)) { \
			char _msg[256]; \
			snprintf(_msg, sizeof(_msg), \
				 "%s (expected=%lld, actual=%lld)", \
				 message, (long long)(expected), \
				 (long long)(actual)); \
			test_fail(tname, __func__, __LINE__, _msg); \
			return; \
		} \
	} while (0)

#define TEST_ASSERT_STR_EQ(expected, actual, tname, message) \
	do { \
		if (strcmp(expected, actual) != 0) { \
			char _msg[256]; \
			snprintf(_msg, sizeof(_msg), \
				 "%s (expected='%s', actual='%s')", \
				 message, expected, actual); \
			test_fail(tname, __func__, __LINE__, _msg); \
			return; \
		} \
	} while (0)

/* ── Mock helpers ──────────────────────────────────────────────── */

static struct ksmbd_conn *create_mock_conn(bool is_fruit)
{
	struct ksmbd_conn *conn = kzalloc(sizeof(*conn), GFP_KERNEL);

	if (!conn)
		return NULL;
	conn->is_fruit = is_fruit;
	conn->dialect = SMB311_PROT_ID;
	conn->vals = &smb311_server_values;
	conn->ops = &smb311_server_ops;
	mutex_init(&conn->srv_mutex);
	atomic_set(&conn->req_running, 0);
	atomic_set(&conn->r_count, 1);
	return conn;
}

static void free_mock_conn(struct ksmbd_conn *conn)
{
	if (!conn)
		return;
	kfree(conn->fruit_state);
	kfree(conn);
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

/* ── Group A: fruit_valid_signature() ──────────────────────────── */

static void test_valid_signature_ok(void)
{
	const char *tn = "A1: valid_signature with AAPL";
	__u8 sig[4] = {'A', 'A', 'P', 'L'};

	atomic_inc(&stats.total);
	TEST_ASSERT(fruit_valid_signature(sig) == true, tn,
		    "AAPL signature should be valid");
	test_pass(tn);
}

static void test_valid_signature_bad(void)
{
	const char *tn = "A2: valid_signature with XXXX";
	__u8 sig[4] = {'X', 'X', 'X', 'X'};

	atomic_inc(&stats.total);
	TEST_ASSERT(fruit_valid_signature(sig) == false, tn,
		    "XXXX signature should be invalid");
	test_pass(tn);
}

static void test_valid_signature_null(void)
{
	const char *tn = "A3: valid_signature with NULL";

	atomic_inc(&stats.total);
	TEST_ASSERT(fruit_valid_signature(NULL) == false, tn,
		    "NULL signature should be invalid");
	test_pass(tn);
}

/* ── Group B: fruit_validate_create_context() ──────────────────── */

static void test_validate_ctx_valid(void)
{
	const char *tn = "B1: validate_create_context valid";
	struct create_context *ctx;
	size_t total = sizeof(struct create_context) +
		       sizeof(struct fruit_client_info) + 4;
	int rc;

	atomic_inc(&stats.total);
	ctx = kzalloc(total, GFP_KERNEL);
	TEST_ASSERT(ctx != NULL, tn, "alloc failed");

	ctx->NameLength = cpu_to_le16(4);
	ctx->DataLength = cpu_to_le32(sizeof(struct fruit_client_info));

	rc = fruit_validate_create_context(ctx);
	TEST_ASSERT_EQ(0, rc, tn, "should return 0 for valid context");

	kfree(ctx);
	test_pass(tn);
}

static void test_validate_ctx_null(void)
{
	const char *tn = "B2: validate_create_context NULL";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ(-EINVAL, fruit_validate_create_context(NULL), tn,
		       "should return -EINVAL for NULL");
	test_pass(tn);
}

static void test_validate_ctx_bad_namelen(void)
{
	const char *tn = "B3: validate_create_context wrong NameLength";
	struct create_context ctx;

	atomic_inc(&stats.total);
	memset(&ctx, 0, sizeof(ctx));
	ctx.NameLength = cpu_to_le16(3);
	ctx.DataLength = cpu_to_le32(sizeof(struct fruit_client_info));

	TEST_ASSERT_EQ(-EINVAL, fruit_validate_create_context(&ctx), tn,
		       "should reject NameLength!=4");
	test_pass(tn);
}

static void test_validate_ctx_small_data(void)
{
	const char *tn = "B4: validate_create_context DataLength too small";
	struct create_context ctx;

	atomic_inc(&stats.total);
	memset(&ctx, 0, sizeof(ctx));
	ctx.NameLength = cpu_to_le16(4);
	ctx.DataLength = cpu_to_le32(4); /* too small */

	TEST_ASSERT_EQ(-EINVAL, fruit_validate_create_context(&ctx), tn,
		       "should reject DataLength < sizeof(fruit_client_info)");
	test_pass(tn);
}

/* ── Group C: fruit_parse_client_info() ────────────────────────── */

static void test_parse_client_valid(void)
{
	const char *tn = "C1: parse_client_info valid";
	struct fruit_client_info ci;
	struct fruit_conn_state state;
	int rc;

	atomic_inc(&stats.total);
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_2_0),
			  cpu_to_le32(FRUIT_CLIENT_MACOS),
			  cpu_to_le64(FRUIT_CAP_UNIX_EXTENSIONS));

	memset(&state, 0, sizeof(state));
	rc = fruit_parse_client_info(&ci, sizeof(ci), &state);
	TEST_ASSERT_EQ(0, rc, tn, "should succeed");
	TEST_ASSERT_EQ(FRUIT_VERSION_2_0, (int)state.client_version, tn,
		       "version should match");
	TEST_ASSERT_EQ(FRUIT_CLIENT_MACOS, (int)state.client_type, tn,
		       "client_type should match");
	TEST_ASSERT_EQ(FRUIT_CAP_UNIX_EXTENSIONS,
		       (long long)state.client_capabilities, tn,
		       "capabilities should match");
	test_pass(tn);
}

static void test_parse_client_null_data(void)
{
	const char *tn = "C2: parse_client_info NULL data";
	struct fruit_conn_state state;

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ(-EINVAL, fruit_parse_client_info(NULL, 64, &state), tn,
		       "should reject NULL data");
	test_pass(tn);
}

static void test_parse_client_null_state(void)
{
	const char *tn = "C3: parse_client_info NULL state";
	struct fruit_client_info ci;

	atomic_inc(&stats.total);
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_1_0),
			  cpu_to_le32(FRUIT_CLIENT_MACOS), 0);
	TEST_ASSERT_EQ(-EINVAL,
		       fruit_parse_client_info(&ci, sizeof(ci), NULL), tn,
		       "should reject NULL state");
	test_pass(tn);
}

static void test_parse_client_short_len(void)
{
	const char *tn = "C4: parse_client_info data_len too small";
	struct fruit_client_info ci;
	struct fruit_conn_state state;

	atomic_inc(&stats.total);
	build_client_info(&ci, 0, 0, 0);
	TEST_ASSERT_EQ(-EINVAL, fruit_parse_client_info(&ci, 4, &state), tn,
		       "should reject short data_len");
	test_pass(tn);
}

static void test_parse_client_bad_sig(void)
{
	const char *tn = "C5: parse_client_info wrong signature";
	struct fruit_client_info ci;
	struct fruit_conn_state state;

	atomic_inc(&stats.total);
	memset(&ci, 0, sizeof(ci));
	ci.signature[0] = 'X';
	ci.signature[1] = 'Y';
	ci.signature[2] = 'Z';
	ci.signature[3] = 'W';

	TEST_ASSERT_EQ(-EINVAL,
		       fruit_parse_client_info(&ci, sizeof(ci), &state), tn,
		       "should reject bad signature");
	test_pass(tn);
}

/* ── Group D: fruit_detect_client_version() ────────────────────── */

static void test_detect_version_v1(void)
{
	const char *tn = "D1: detect_client_version v1.0";
	struct fruit_client_info ci;

	atomic_inc(&stats.total);
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_1_0), 0, 0);
	TEST_ASSERT_EQ(FRUIT_VERSION_1_0,
		       fruit_detect_client_version(&ci, sizeof(ci)), tn,
		       "should detect v1.0");
	test_pass(tn);
}

static void test_detect_version_v2(void)
{
	const char *tn = "D2: detect_client_version v2.0";
	struct fruit_client_info ci;

	atomic_inc(&stats.total);
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_2_0), 0, 0);
	TEST_ASSERT_EQ(FRUIT_VERSION_2_0,
		       fruit_detect_client_version(&ci, sizeof(ci)), tn,
		       "should detect v2.0");
	test_pass(tn);
}

static void test_detect_version_null(void)
{
	const char *tn = "D3: detect_client_version NULL";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ(0, fruit_detect_client_version(NULL, 0), tn,
		       "should return 0 for NULL");
	test_pass(tn);
}

static void test_detect_version_bad_sig(void)
{
	const char *tn = "D4: detect_client_version bad signature";
	struct fruit_client_info ci;

	atomic_inc(&stats.total);
	memset(&ci, 0, sizeof(ci));
	ci.signature[0] = 'B';
	ci.signature[1] = 'A';
	ci.signature[2] = 'D';
	ci.signature[3] = '!';
	ci.version = cpu_to_le32(FRUIT_VERSION_1_0);

	TEST_ASSERT_EQ(0, fruit_detect_client_version(&ci, sizeof(ci)), tn,
		       "should return 0 for bad signature");
	test_pass(tn);
}

/* ── Group E: fruit_get_client_name() ──────────────────────────── */

static void test_client_name_macos(void)
{
	const char *tn = "E1: get_client_name macOS";

	atomic_inc(&stats.total);
	TEST_ASSERT_STR_EQ("macOS",
			   fruit_get_client_name(FRUIT_CLIENT_MACOS), tn,
			   "MACOS should map to macOS");
	test_pass(tn);
}

static void test_client_name_ios(void)
{
	const char *tn = "E2: get_client_name iOS";

	atomic_inc(&stats.total);
	TEST_ASSERT_STR_EQ("iOS",
			   fruit_get_client_name(FRUIT_CLIENT_IOS), tn,
			   "IOS should map to iOS");
	test_pass(tn);
}

static void test_client_name_ipados(void)
{
	const char *tn = "E3: get_client_name iPadOS";

	atomic_inc(&stats.total);
	TEST_ASSERT_STR_EQ("iPadOS",
			   fruit_get_client_name(FRUIT_CLIENT_IPADOS), tn,
			   "IPADOS should map to iPadOS");
	test_pass(tn);
}

static void test_client_name_tvos(void)
{
	const char *tn = "E4: get_client_name tvOS";

	atomic_inc(&stats.total);
	TEST_ASSERT_STR_EQ("tvOS",
			   fruit_get_client_name(FRUIT_CLIENT_TVOS), tn,
			   "TVOS should map to tvOS");
	test_pass(tn);
}

static void test_client_name_watchos(void)
{
	const char *tn = "E5: get_client_name watchOS";

	atomic_inc(&stats.total);
	TEST_ASSERT_STR_EQ("watchOS",
			   fruit_get_client_name(FRUIT_CLIENT_WATCHOS), tn,
			   "WATCHOS should map to watchOS");
	test_pass(tn);
}

static void test_client_name_unknown(void)
{
	const char *tn = "E6: get_client_name unknown";

	atomic_inc(&stats.total);
	TEST_ASSERT_STR_EQ("Unknown",
			   fruit_get_client_name(0xFF), tn,
			   "0xFF should map to Unknown");
	test_pass(tn);
}

/* ── Group F: fruit_get_version_string() ───────────────────────── */

static void test_version_string_10(void)
{
	const char *tn = "F1: get_version_string 1.0";

	atomic_inc(&stats.total);
	TEST_ASSERT_STR_EQ("1.0",
			   fruit_get_version_string(FRUIT_VERSION_1_0), tn,
			   "VERSION_1_0 should map to 1.0");
	test_pass(tn);
}

static void test_version_string_11(void)
{
	const char *tn = "F2: get_version_string 1.1";

	atomic_inc(&stats.total);
	TEST_ASSERT_STR_EQ("1.1",
			   fruit_get_version_string(FRUIT_VERSION_1_1), tn,
			   "VERSION_1_1 should map to 1.1");
	test_pass(tn);
}

static void test_version_string_20(void)
{
	const char *tn = "F3: get_version_string 2.0";

	atomic_inc(&stats.total);
	TEST_ASSERT_STR_EQ("2.0",
			   fruit_get_version_string(FRUIT_VERSION_2_0), tn,
			   "VERSION_2_0 should map to 2.0");
	test_pass(tn);
}

static void test_version_string_unknown(void)
{
	const char *tn = "F4: get_version_string unknown";

	atomic_inc(&stats.total);
	TEST_ASSERT_STR_EQ("Unknown",
			   fruit_get_version_string(0xDEADBEEF), tn,
			   "unknown version should map to Unknown");
	test_pass(tn);
}

/* ── Group G: fruit_init_connection_state() ────────────────────── */

static void test_init_state_ok(void)
{
	const char *tn = "G1: init_connection_state valid";
	struct fruit_conn_state state;
	int rc;

	atomic_inc(&stats.total);
	memset(&state, 0xFF, sizeof(state));

	rc = fruit_init_connection_state(&state);
	TEST_ASSERT_EQ(0, rc, tn, "should return 0");
	TEST_ASSERT_EQ((long long)FRUIT_DEFAULT_CAPABILITIES,
		       (long long)state.supported_features, tn,
		       "supported_features should be FRUIT_DEFAULT_CAPABILITIES");
	TEST_ASSERT_EQ((long long)FRUIT_DEFAULT_CAPABILITIES,
		       (long long)state.enabled_features, tn,
		       "enabled_features should be FRUIT_DEFAULT_CAPABILITIES");
	TEST_ASSERT_EQ((long long)FRUIT_DEFAULT_CAPABILITIES,
		       (long long)state.negotiated_capabilities, tn,
		       "negotiated_capabilities should be FRUIT_DEFAULT_CAPABILITIES");
	test_pass(tn);
}

static void test_init_state_null(void)
{
	const char *tn = "G2: init_connection_state NULL";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ(-EINVAL, fruit_init_connection_state(NULL), tn,
		       "should return -EINVAL for NULL");
	test_pass(tn);
}

static void test_init_state_zeroes_fields(void)
{
	const char *tn = "G3: init_connection_state zeroes client fields";
	struct fruit_conn_state state;

	atomic_inc(&stats.total);
	memset(&state, 0xFF, sizeof(state));
	fruit_init_connection_state(&state);

	TEST_ASSERT_EQ(0, (int)state.client_version, tn,
		       "client_version should be 0");
	TEST_ASSERT_EQ(0, (int)state.client_type, tn,
		       "client_type should be 0");
	TEST_ASSERT_EQ(0, (long long)state.client_capabilities, tn,
		       "client_capabilities should be 0");
	test_pass(tn);
}

/* ── Group H: fruit_cleanup_connection_state() ─────────────────── */

static void test_cleanup_state_ok(void)
{
	const char *tn = "H1: cleanup_connection_state valid";
	struct fruit_conn_state state;

	atomic_inc(&stats.total);
	memset(&state, 0xFF, sizeof(state));
	fruit_cleanup_connection_state(&state);

	TEST_ASSERT_EQ(0, (int)state.client_version, tn,
		       "should be zeroed after cleanup");
	TEST_ASSERT_EQ(0, (long long)state.negotiated_capabilities, tn,
		       "negotiated_caps should be zeroed after cleanup");
	test_pass(tn);
}

static void test_cleanup_state_null(void)
{
	const char *tn = "H2: cleanup_connection_state NULL";

	atomic_inc(&stats.total);
	/* should not crash */
	fruit_cleanup_connection_state(NULL);
	test_pass(tn);
}

/* ── Group I: fruit_negotiate_capabilities() ───────────────────── */

static void test_negotiate_full_caps(void)
{
	const char *tn = "I1: negotiate_capabilities full caps";
	struct ksmbd_conn *conn;
	struct fruit_client_info ci;
	u64 all_caps = FRUIT_DEFAULT_CAPABILITIES;
	int rc;

	atomic_inc(&stats.total);
	conn = create_mock_conn(false);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_2_0),
			  cpu_to_le32(FRUIT_CLIENT_MACOS),
			  cpu_to_le64(all_caps));
	rc = fruit_negotiate_capabilities(conn, &ci);
	TEST_ASSERT_EQ(0, rc, tn, "should succeed");
	TEST_ASSERT(conn->fruit_state != NULL, tn,
		    "fruit_state should be allocated");
	TEST_ASSERT_EQ((long long)all_caps,
		       (long long)conn->fruit_state->negotiated_capabilities,
		       tn, "negotiated caps should equal client & server");
	free_mock_conn(conn);
	test_pass(tn);
}

static void test_negotiate_partial_caps(void)
{
	const char *tn = "I2: negotiate_capabilities partial caps";
	struct ksmbd_conn *conn;
	struct fruit_client_info ci;
	u64 client_caps = FRUIT_CAP_UNIX_EXTENSIONS |
			  FRUIT_CAP_POSIX_LOCKS |
			  FRUIT_CAP_DEDUPLICATION; /* dedup not in default */
	u64 expected;
	int rc;

	atomic_inc(&stats.total);
	conn = create_mock_conn(false);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	build_client_info(&ci, 0, 0, cpu_to_le64(client_caps));
	rc = fruit_negotiate_capabilities(conn, &ci);
	TEST_ASSERT_EQ(0, rc, tn, "should succeed");

	expected = client_caps & FRUIT_DEFAULT_CAPABILITIES;
	TEST_ASSERT_EQ((long long)expected,
		       (long long)conn->fruit_state->negotiated_capabilities,
		       tn, "negotiated should be intersection");

	/* DEDUPLICATION is not in FRUIT_DEFAULT_CAPABILITIES */
	TEST_ASSERT(!(conn->fruit_state->negotiated_capabilities &
		      FRUIT_CAP_DEDUPLICATION), tn,
		    "dedup should not be negotiated");

	free_mock_conn(conn);
	test_pass(tn);
}

static void test_negotiate_null_conn(void)
{
	const char *tn = "I3: negotiate_capabilities NULL conn";
	struct fruit_client_info ci;

	atomic_inc(&stats.total);
	build_client_info(&ci, 0, 0, 0);
	TEST_ASSERT_EQ(-EINVAL, fruit_negotiate_capabilities(NULL, &ci), tn,
		       "should reject NULL conn");
	test_pass(tn);
}

static void test_negotiate_null_info(void)
{
	const char *tn = "I4: negotiate_capabilities NULL client_info";
	struct ksmbd_conn *conn;

	atomic_inc(&stats.total);
	conn = create_mock_conn(false);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	TEST_ASSERT_EQ(-EINVAL, fruit_negotiate_capabilities(conn, NULL), tn,
		       "should reject NULL client_info");
	free_mock_conn(conn);
	test_pass(tn);
}

static void test_negotiate_boolean_flags(void)
{
	const char *tn = "I5: negotiate_capabilities boolean flags";
	struct ksmbd_conn *conn;
	struct fruit_client_info ci;
	u64 caps = FRUIT_CAP_EXTENDED_ATTRIBUTES |
		   FRUIT_CAP_POSIX_LOCKS |
		   FRUIT_CAP_RESILIENT_HANDLES |
		   FRUIT_COMPRESSION_ZLIB;

	atomic_inc(&stats.total);
	conn = create_mock_conn(false);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	build_client_info(&ci, 0, 0, cpu_to_le64(caps));
	fruit_negotiate_capabilities(conn, &ci);

	TEST_ASSERT_EQ(1, (int)conn->fruit_state->extensions_enabled, tn,
		       "extensions_enabled should be set");
	TEST_ASSERT_EQ(1, (int)conn->fruit_state->posix_locks_enabled, tn,
		       "posix_locks_enabled should be set");
	TEST_ASSERT_EQ(1, (int)conn->fruit_state->resilient_handles_enabled,
		       tn, "resilient_handles_enabled should be set");
	TEST_ASSERT_EQ(1, (int)conn->fruit_state->compression_supported, tn,
		       "compression_supported should be set");

	free_mock_conn(conn);
	test_pass(tn);
}

/* ── Group J: fruit_supports_capability() ──────────────────────── */

static void test_supports_cap_present(void)
{
	const char *tn = "J1: supports_capability present";
	struct fruit_conn_state state;

	atomic_inc(&stats.total);
	memset(&state, 0, sizeof(state));
	state.negotiated_capabilities = FRUIT_CAP_UNIX_EXTENSIONS |
					FRUIT_CAP_FILE_IDS;

	TEST_ASSERT(fruit_supports_capability(&state,
					      FRUIT_CAP_UNIX_EXTENSIONS), tn,
		    "should return true for present cap");
	test_pass(tn);
}

static void test_supports_cap_absent(void)
{
	const char *tn = "J2: supports_capability absent";
	struct fruit_conn_state state;

	atomic_inc(&stats.total);
	memset(&state, 0, sizeof(state));
	state.negotiated_capabilities = FRUIT_CAP_UNIX_EXTENSIONS;

	TEST_ASSERT(!fruit_supports_capability(&state,
					       FRUIT_CAP_SAVEBOX), tn,
		    "should return false for absent cap");
	test_pass(tn);
}

static void test_supports_cap_null(void)
{
	const char *tn = "J3: supports_capability NULL state";

	atomic_inc(&stats.total);
	TEST_ASSERT(!fruit_supports_capability(NULL,
					       FRUIT_CAP_UNIX_EXTENSIONS), tn,
		    "should return false for NULL state");
	test_pass(tn);
}

/* ── Group K: fruit_update_connection_state() ──────────────────── */

static void test_update_state_ok(void)
{
	const char *tn = "K1: update_connection_state valid";
	struct fruit_conn_state state;
	struct fruit_client_info ci;
	int rc;

	atomic_inc(&stats.total);
	memset(&state, 0, sizeof(state));
	state.supported_features = FRUIT_DEFAULT_CAPABILITIES;

	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_1_1),
			  cpu_to_le32(FRUIT_CLIENT_IOS),
			  cpu_to_le64(FRUIT_CAP_UNIX_EXTENSIONS |
				      FRUIT_CAP_FILE_IDS));

	rc = fruit_update_connection_state(&state, &ci);
	TEST_ASSERT_EQ(0, rc, tn, "should succeed");
	TEST_ASSERT_EQ(FRUIT_VERSION_1_1, (int)state.client_version, tn,
		       "version should be updated");
	TEST_ASSERT_EQ(FRUIT_CLIENT_IOS, (int)state.client_type, tn,
		       "type should be updated");
	/* Verify renegotiation: intersection of client caps & supported */
	TEST_ASSERT(state.negotiated_capabilities &
		    FRUIT_CAP_UNIX_EXTENSIONS, tn,
		    "unix_ext should be negotiated");
	TEST_ASSERT(state.negotiated_capabilities &
		    FRUIT_CAP_FILE_IDS, tn,
		    "file_ids should be negotiated");
	test_pass(tn);
}

static void test_update_state_null_state(void)
{
	const char *tn = "K2: update_connection_state NULL state";
	struct fruit_client_info ci;

	atomic_inc(&stats.total);
	build_client_info(&ci, 0, 0, 0);
	TEST_ASSERT_EQ(-EINVAL, fruit_update_connection_state(NULL, &ci), tn,
		       "should reject NULL state");
	test_pass(tn);
}

static void test_update_state_null_info(void)
{
	const char *tn = "K3: update_connection_state NULL info";
	struct fruit_conn_state state;

	atomic_inc(&stats.total);
	memset(&state, 0, sizeof(state));
	TEST_ASSERT_EQ(-EINVAL, fruit_update_connection_state(&state, NULL),
		       tn, "should reject NULL info");
	test_pass(tn);
}

static void test_update_state_bad_sig(void)
{
	const char *tn = "K4: update_connection_state bad signature";
	struct fruit_conn_state state;
	struct fruit_client_info ci;

	atomic_inc(&stats.total);
	memset(&state, 0, sizeof(state));
	memset(&ci, 0, sizeof(ci));
	ci.signature[0] = 'N';
	ci.signature[1] = 'O';
	ci.signature[2] = 'P';
	ci.signature[3] = 'E';

	TEST_ASSERT_EQ(-EINVAL, fruit_update_connection_state(&state, &ci),
		       tn, "should reject bad signature");
	test_pass(tn);
}

/* ── Group L: fruit_get_context_size() ─────────────────────────── */

static void test_ctx_size_server_query(void)
{
	const char *tn = "L1: get_context_size ServerQuery";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ((long long)sizeof(struct fruit_server_query),
		       (long long)fruit_get_context_size(
				FRUIT_SERVER_QUERY_CONTEXT),
		       tn, "size should match struct");
	test_pass(tn);
}

static void test_ctx_size_volume_caps(void)
{
	const char *tn = "L2: get_context_size VolumeCapabilities";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ((long long)sizeof(struct fruit_volume_capabilities),
		       (long long)fruit_get_context_size(
				FRUIT_VOLUME_CAPABILITIES_CONTEXT),
		       tn, "size should match struct");
	test_pass(tn);
}

static void test_ctx_size_file_mode(void)
{
	const char *tn = "L3: get_context_size FileMode";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ((long long)sizeof(struct fruit_file_mode),
		       (long long)fruit_get_context_size(
				FRUIT_FILE_MODE_CONTEXT),
		       tn, "size should match struct");
	test_pass(tn);
}

static void test_ctx_size_dir_hardlinks(void)
{
	const char *tn = "L4: get_context_size DirHardLinks";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ((long long)sizeof(struct fruit_dir_hardlinks),
		       (long long)fruit_get_context_size(
				FRUIT_DIR_HARDLINKS_CONTEXT),
		       tn, "size should match struct");
	test_pass(tn);
}

static void test_ctx_size_lookerinfo(void)
{
	const char *tn = "L5: get_context_size LookerInfo";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ((long long)sizeof(struct fruit_looker_info),
		       (long long)fruit_get_context_size(
				FRUIT_LOOKERINFO_CONTEXT),
		       tn, "size should match struct");
	test_pass(tn);
}

static void test_ctx_size_savebox(void)
{
	const char *tn = "L6: get_context_size SaveBox";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ((long long)sizeof(struct fruit_savebox_info),
		       (long long)fruit_get_context_size(
				FRUIT_SAVEBOX_CONTEXT),
		       tn, "size should match struct");
	test_pass(tn);
}

static void test_ctx_size_null(void)
{
	const char *tn = "L7: get_context_size NULL";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ(0, (long long)fruit_get_context_size(NULL), tn,
		       "NULL should return 0");
	test_pass(tn);
}

static void test_ctx_size_unknown(void)
{
	const char *tn = "L8: get_context_size unknown name";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ(0, (long long)fruit_get_context_size("NoSuchContext"),
		       tn, "unknown name should return 0");
	test_pass(tn);
}

/* ── Group M: fruit_build_server_response() ────────────────────── */

static void test_build_response_ok(void)
{
	const char *tn = "M1: build_server_response valid";
	void *data = NULL;
	size_t len = 0;
	int rc;

	atomic_inc(&stats.total);
	rc = fruit_build_server_response(&data, &len,
					 cpu_to_le64(FRUIT_CAP_UNIX_EXTENSIONS),
					 cpu_to_le32(1));
	TEST_ASSERT_EQ(0, rc, tn, "should succeed");
	TEST_ASSERT(data != NULL, tn, "data should be non-NULL");
	TEST_ASSERT_EQ((long long)sizeof(struct fruit_server_query),
		       (long long)len, tn, "len should match struct size");

	kfree(data);
	test_pass(tn);
}

static void test_build_response_null_data(void)
{
	const char *tn = "M2: build_server_response NULL data";
	size_t len;

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ(-EINVAL,
		       fruit_build_server_response(NULL, &len, 0, 0), tn,
		       "should reject NULL data ptr");
	test_pass(tn);
}

static void test_build_response_null_len(void)
{
	const char *tn = "M3: build_server_response NULL len";
	void *data;

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ(-EINVAL,
		       fruit_build_server_response(&data, NULL, 0, 0), tn,
		       "should reject NULL len ptr");
	test_pass(tn);
}

/* ── Group N: fruit_debug_client_info() ────────────────────────── */

static void test_debug_client_info_ok(void)
{
	const char *tn = "N1: debug_client_info valid";
	struct fruit_client_info ci;

	atomic_inc(&stats.total);
	build_client_info(&ci, cpu_to_le32(FRUIT_VERSION_2_0),
			  cpu_to_le32(FRUIT_CLIENT_MACOS),
			  cpu_to_le64(FRUIT_CAP_UNIX_EXTENSIONS));
	/* should not crash; output goes to ksmbd_debug */
	fruit_debug_client_info(&ci);
	test_pass(tn);
}

static void test_debug_client_info_null(void)
{
	const char *tn = "N2: debug_client_info NULL";

	atomic_inc(&stats.total);
	fruit_debug_client_info(NULL);
	test_pass(tn);
}

/* ── Group O: fruit_debug_capabilities() ───────────────────────── */

static void test_debug_capabilities(void)
{
	const char *tn = "O1: debug_capabilities";

	atomic_inc(&stats.total);
	/* should not crash; exercises every capability bit printout */
	fruit_debug_capabilities(FRUIT_DEFAULT_CAPABILITIES);
	fruit_debug_capabilities(0);
	fruit_debug_capabilities(0xFFFFFFFFFFFFFFFFULL);
	test_pass(tn);
}

/* ── Group P: fruit_process_looker_info() ──────────────────────── */

static void test_process_looker_ok(void)
{
	const char *tn = "P1: process_looker_info valid";
	struct ksmbd_conn *conn;
	struct fruit_looker_info info;

	atomic_inc(&stats.total);
	conn = create_mock_conn(true);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	memset(&info, 0, sizeof(info));
	memcpy(info.creator, "TEST", 4);
	memcpy(info.type, "FILE", 4);

	TEST_ASSERT_EQ(0, fruit_process_looker_info(conn, &info), tn,
		       "should succeed");
	free_mock_conn(conn);
	test_pass(tn);
}

static void test_process_looker_null_conn(void)
{
	const char *tn = "P2: process_looker_info NULL conn";
	struct fruit_looker_info info;

	atomic_inc(&stats.total);
	memset(&info, 0, sizeof(info));
	TEST_ASSERT_EQ(-EINVAL, fruit_process_looker_info(NULL, &info), tn,
		       "should reject NULL conn");
	test_pass(tn);
}

static void test_process_looker_null_info(void)
{
	const char *tn = "P3: process_looker_info NULL info";
	struct ksmbd_conn *conn;

	atomic_inc(&stats.total);
	conn = create_mock_conn(true);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	TEST_ASSERT_EQ(-EINVAL, fruit_process_looker_info(conn, NULL), tn,
		       "should reject NULL info");
	free_mock_conn(conn);
	test_pass(tn);
}

/* ── Group Q: savebox / server_query / read_dir_attr ───────────── */

static void test_process_savebox_ok(void)
{
	const char *tn = "Q1: process_savebox_info valid";
	struct ksmbd_conn *conn;
	struct fruit_savebox_info info;

	atomic_inc(&stats.total);
	conn = create_mock_conn(true);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	memset(&info, 0, sizeof(info));
	info.version = cpu_to_le32(1);
	TEST_ASSERT_EQ(0, fruit_process_savebox_info(conn, &info), tn,
		       "should succeed");
	free_mock_conn(conn);
	test_pass(tn);
}

static void test_process_savebox_null_conn(void)
{
	const char *tn = "Q2: process_savebox_info NULL conn";
	struct fruit_savebox_info info;

	atomic_inc(&stats.total);
	memset(&info, 0, sizeof(info));
	TEST_ASSERT_EQ(-EINVAL, fruit_process_savebox_info(NULL, &info), tn,
		       "should reject NULL conn");
	test_pass(tn);
}

static void test_process_savebox_null_info(void)
{
	const char *tn = "Q3: process_savebox_info NULL info";
	struct ksmbd_conn *conn;

	atomic_inc(&stats.total);
	conn = create_mock_conn(true);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	TEST_ASSERT_EQ(-EINVAL, fruit_process_savebox_info(conn, NULL), tn,
		       "should reject NULL info");
	free_mock_conn(conn);
	test_pass(tn);
}

static void test_process_server_query_ok(void)
{
	const char *tn = "Q4: process_server_query valid";
	struct ksmbd_conn *conn;
	struct fruit_server_query query;

	atomic_inc(&stats.total);
	conn = create_mock_conn(true);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	memset(&query, 0, sizeof(query));
	query.type = cpu_to_le32(1);
	TEST_ASSERT_EQ(0, fruit_process_server_query(conn, &query), tn,
		       "should succeed");
	free_mock_conn(conn);
	test_pass(tn);
}

static void test_process_server_query_null(void)
{
	const char *tn = "Q5: process_server_query NULL args";
	struct ksmbd_conn *conn;
	struct fruit_server_query query;

	atomic_inc(&stats.total);
	conn = create_mock_conn(true);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	memset(&query, 0, sizeof(query));
	TEST_ASSERT_EQ(-EINVAL, fruit_process_server_query(NULL, &query), tn,
		       "should reject NULL conn");
	TEST_ASSERT_EQ(-EINVAL, fruit_process_server_query(conn, NULL), tn,
		       "should reject NULL query");
	free_mock_conn(conn);
	test_pass(tn);
}

static void test_read_dir_attr_null(void)
{
	const char *tn = "Q6: smb2_read_dir_attr NULL work";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ(-EINVAL, smb2_read_dir_attr(NULL), tn,
		       "should reject NULL work");
	test_pass(tn);
}

static void test_handle_savebox_bundle_null(void)
{
	const char *tn = "Q7: handle_savebox_bundle NULL args";
	struct ksmbd_conn *conn;
	struct fruit_savebox_info info;

	atomic_inc(&stats.total);
	conn = create_mock_conn(true);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");
	memset(&info, 0, sizeof(info));

	TEST_ASSERT_EQ(-EINVAL,
		       fruit_handle_savebox_bundle(NULL, NULL, &info), tn,
		       "should reject NULL conn");
	TEST_ASSERT_EQ(-EINVAL,
		       fruit_handle_savebox_bundle(conn, NULL, NULL), tn,
		       "should reject NULL info");
	free_mock_conn(conn);
	test_pass(tn);
}

/* ── Group R: create_fruit_rsp_buf() (oplock.c) ───────────────── */

static void test_rsp_buf_with_state(void)
{
	const char *tn = "R1: create_fruit_rsp_buf with fruit_state";
	struct ksmbd_conn *conn;
	char buf[sizeof(struct create_fruit_rsp)];
	struct create_fruit_rsp *rsp;
	u64 test_caps = FRUIT_CAP_UNIX_EXTENSIONS | FRUIT_CAP_FILE_IDS;

	atomic_inc(&stats.total);
	conn = create_mock_conn(true);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");

	conn->fruit_state = kzalloc(sizeof(struct fruit_conn_state),
				    GFP_KERNEL);
	TEST_ASSERT(conn->fruit_state != NULL, tn, "state alloc failed");
	conn->fruit_state->negotiated_capabilities = test_caps;

	memset(buf, 0xFF, sizeof(buf));
	create_fruit_rsp_buf(buf, conn);

	rsp = (struct create_fruit_rsp *)buf;
	TEST_ASSERT_EQ('A', (int)rsp->Name[0], tn, "Name[0] should be A");
	TEST_ASSERT_EQ('A', (int)rsp->Name[1], tn, "Name[1] should be A");
	TEST_ASSERT_EQ('P', (int)rsp->Name[2], tn, "Name[2] should be P");
	TEST_ASSERT_EQ('L', (int)rsp->Name[3], tn, "Name[3] should be L");
	TEST_ASSERT_EQ(1, (int)le32_to_cpu(rsp->command_code), tn,
		       "command_code should be 1");
	TEST_ASSERT_EQ(0x07, (long long)le64_to_cpu(rsp->reply_bitmap), tn,
		       "reply_bitmap should be 0x07");
	TEST_ASSERT_EQ((long long)test_caps,
		       (long long)le64_to_cpu(rsp->server_caps), tn,
		       "server_caps should match negotiated");

	free_mock_conn(conn);
	test_pass(tn);
}

static void test_rsp_buf_no_state(void)
{
	const char *tn = "R2: create_fruit_rsp_buf without fruit_state";
	struct ksmbd_conn *conn;
	char buf[sizeof(struct create_fruit_rsp)];
	struct create_fruit_rsp *rsp;

	atomic_inc(&stats.total);
	conn = create_mock_conn(true);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");
	conn->fruit_state = NULL;

	create_fruit_rsp_buf(buf, conn);
	rsp = (struct create_fruit_rsp *)buf;

	TEST_ASSERT_EQ(0, (long long)le64_to_cpu(rsp->server_caps), tn,
		       "server_caps should be 0 when no state");
	TEST_ASSERT_EQ(1, (int)le32_to_cpu(rsp->command_code), tn,
		       "command_code should still be 1");

	free_mock_conn(conn);
	test_pass(tn);
}

static void test_rsp_buf_offsets(void)
{
	const char *tn = "R3: create_fruit_rsp_buf field offsets";
	struct ksmbd_conn *conn;
	char buf[sizeof(struct create_fruit_rsp)];
	struct create_fruit_rsp *rsp;

	atomic_inc(&stats.total);
	conn = create_mock_conn(true);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");
	conn->fruit_state = NULL;

	create_fruit_rsp_buf(buf, conn);
	rsp = (struct create_fruit_rsp *)buf;

	TEST_ASSERT_EQ((long long)offsetof(struct create_fruit_rsp,
					   command_code),
		       (long long)le16_to_cpu(rsp->ccontext.DataOffset), tn,
		       "DataOffset should point to command_code");

	TEST_ASSERT_EQ((long long)(sizeof(struct create_fruit_rsp) -
		       offsetof(struct create_fruit_rsp, command_code)),
		       (long long)le32_to_cpu(rsp->ccontext.DataLength), tn,
		       "DataLength should cover data fields");

	TEST_ASSERT_EQ((long long)offsetof(struct create_fruit_rsp, Name),
		       (long long)le16_to_cpu(rsp->ccontext.NameOffset), tn,
		       "NameOffset should point to Name");

	TEST_ASSERT_EQ(4, (int)le16_to_cpu(rsp->ccontext.NameLength), tn,
		       "NameLength should be 4");

	free_mock_conn(conn);
	test_pass(tn);
}

/* ── Group S: struct layout validation ─────────────────────────── */

static void test_struct_fruit_rsp_size(void)
{
	const char *tn = "S1: create_fruit_rsp size matches smb_version_values";
	struct ksmbd_conn *conn;

	atomic_inc(&stats.total);
	conn = create_mock_conn(false);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");
	TEST_ASSERT_EQ((long long)sizeof(struct create_fruit_rsp),
		       (long long)conn->vals->create_fruit_size, tn,
		       "size should match version struct value");
	free_mock_conn(conn);
	test_pass(tn);
}

static void test_struct_client_info_packed(void)
{
	const char *tn = "S2: fruit_client_info signature at offset 0";
	struct fruit_client_info ci;

	atomic_inc(&stats.total);
	/* Verify signature is at the start of the struct */
	TEST_ASSERT_EQ(0, (long long)offsetof(struct fruit_client_info,
					      signature), tn,
		       "signature should be at offset 0");
	/* Verify struct is reasonable size (packed, no excessive padding) */
	TEST_ASSERT(sizeof(ci) <= 48, tn,
		    "fruit_client_info should be compact (<=48 bytes)");
	test_pass(tn);
}

static void test_struct_wire_sizes(void)
{
	const char *tn = "S3: wire-format struct sizes";

	atomic_inc(&stats.total);
	/* These packed structs should have deterministic sizes */
	TEST_ASSERT(sizeof(struct fruit_server_query) > 0, tn,
		    "server_query should have nonzero size");
	TEST_ASSERT(sizeof(struct fruit_volume_capabilities) > 0, tn,
		    "volume_capabilities should have nonzero size");
	TEST_ASSERT(sizeof(struct fruit_file_mode) > 0, tn,
		    "file_mode should have nonzero size");
	TEST_ASSERT(sizeof(struct fruit_dir_hardlinks) > 0, tn,
		    "dir_hardlinks should have nonzero size");
	TEST_ASSERT(sizeof(struct fruit_looker_info) > 0, tn,
		    "looker_info should have nonzero size");
	TEST_ASSERT(sizeof(struct fruit_savebox_info) > 0, tn,
		    "savebox_info should have nonzero size");
	TEST_ASSERT(sizeof(struct fruit_conn_state) > 0, tn,
		    "conn_state should have nonzero size");
	test_pass(tn);
}

/* ── Group T: integration constants ────────────────────────────── */

static void test_version_values_fruit_size(void)
{
	const char *tn = "T1: create_fruit_size matches sizeof(create_fruit_rsp)";
	struct ksmbd_conn *conn;
	size_t expected = sizeof(struct create_fruit_rsp);

	atomic_inc(&stats.total);

	/*
	 * Verify via conn->vals pointer (set to smb311_server_values by
	 * the mock). The other version structs are static in smb2ops.c
	 * and initialized identically; we verify the one accessible here.
	 */
	conn = create_mock_conn(false);
	TEST_ASSERT(conn != NULL, tn, "alloc failed");
	TEST_ASSERT(conn->vals != NULL, tn, "vals should be set by mock");
	TEST_ASSERT_EQ((long long)expected,
		       (long long)conn->vals->create_fruit_size, tn,
		       "create_fruit_size mismatch in smb311_server_values");
	free_mock_conn(conn);
	test_pass(tn);
}

static void test_wire_protocol_tag(void)
{
	const char *tn = "T2: SMB2_CREATE_AAPL wire tag";

	atomic_inc(&stats.total);
	TEST_ASSERT_EQ(0, strncmp(SMB2_CREATE_AAPL, "AAPL", 4), tn,
		       "SMB2_CREATE_AAPL should be AAPL");
	TEST_ASSERT_EQ(0, strncmp(FRUIT_CONTEXT_NAME, "AAPL", 4), tn,
		       "FRUIT_CONTEXT_NAME should be AAPL");
	test_pass(tn);
}

/* ── Group U: fruit_is_client_request() ────────────────────────── */

static void test_is_client_req_null(void)
{
	const char *tn = "U1: is_client_request NULL buffer";

	atomic_inc(&stats.total);
	TEST_ASSERT(fruit_is_client_request(NULL, 0) == false, tn,
		    "NULL buffer should return false");
	test_pass(tn);
}

static void test_is_client_req_short(void)
{
	const char *tn = "U2: is_client_request short buffer";
	char small[16];

	atomic_inc(&stats.total);
	memset(small, 0, sizeof(small));
	TEST_ASSERT(fruit_is_client_request(small, sizeof(small)) == false, tn,
		    "buffer shorter than smb2_create_req should return false");
	test_pass(tn);
}

static void test_is_client_req_no_context(void)
{
	const char *tn = "U3: is_client_request zeroed buffer (no context)";
	void *buf;
	size_t sz = sizeof(struct smb2_create_req) + 256;

	atomic_inc(&stats.total);
	buf = kzalloc(sz, GFP_KERNEL);
	TEST_ASSERT(buf != NULL, tn, "alloc failed");

	/* Zeroed CREATE request has no AAPL create context */
	TEST_ASSERT(fruit_is_client_request(buf, sz) == false, tn,
		    "zeroed buffer without AAPL context should return false");
	kfree(buf);
	test_pass(tn);
}

/* ── Group V: fruit_init_module() / fruit_cleanup_module() ─────── */

static void test_init_module(void)
{
	const char *tn = "V1: fruit_init_module returns 0";
	int rc;

	atomic_inc(&stats.total);
	rc = fruit_init_module();
	TEST_ASSERT_EQ(0, rc, tn, "init_module should return 0");
	test_pass(tn);
}

static void test_cleanup_module(void)
{
	const char *tn = "V2: fruit_cleanup_module no crash";

	atomic_inc(&stats.total);
	fruit_cleanup_module();
	test_pass(tn);
}

/* ── Test registration and runner ──────────────────────────────── */

static struct {
	const char *name;
	void (*func)(void);
} test_cases[] = {
	/* Group A: fruit_valid_signature */
	{"A1_valid_signature_ok",         test_valid_signature_ok},
	{"A2_valid_signature_bad",        test_valid_signature_bad},
	{"A3_valid_signature_null",       test_valid_signature_null},
	/* Group B: fruit_validate_create_context */
	{"B1_validate_ctx_valid",         test_validate_ctx_valid},
	{"B2_validate_ctx_null",          test_validate_ctx_null},
	{"B3_validate_ctx_bad_namelen",   test_validate_ctx_bad_namelen},
	{"B4_validate_ctx_small_data",    test_validate_ctx_small_data},
	/* Group C: fruit_parse_client_info */
	{"C1_parse_client_valid",         test_parse_client_valid},
	{"C2_parse_client_null_data",     test_parse_client_null_data},
	{"C3_parse_client_null_state",    test_parse_client_null_state},
	{"C4_parse_client_short_len",     test_parse_client_short_len},
	{"C5_parse_client_bad_sig",       test_parse_client_bad_sig},
	/* Group D: fruit_detect_client_version */
	{"D1_detect_version_v1",          test_detect_version_v1},
	{"D2_detect_version_v2",          test_detect_version_v2},
	{"D3_detect_version_null",        test_detect_version_null},
	{"D4_detect_version_bad_sig",     test_detect_version_bad_sig},
	/* Group E: fruit_get_client_name */
	{"E1_client_name_macos",          test_client_name_macos},
	{"E2_client_name_ios",            test_client_name_ios},
	{"E3_client_name_ipados",         test_client_name_ipados},
	{"E4_client_name_tvos",           test_client_name_tvos},
	{"E5_client_name_watchos",        test_client_name_watchos},
	{"E6_client_name_unknown",        test_client_name_unknown},
	/* Group F: fruit_get_version_string */
	{"F1_version_string_10",          test_version_string_10},
	{"F2_version_string_11",          test_version_string_11},
	{"F3_version_string_20",          test_version_string_20},
	{"F4_version_string_unknown",     test_version_string_unknown},
	/* Group G: fruit_init_connection_state */
	{"G1_init_state_ok",              test_init_state_ok},
	{"G2_init_state_null",            test_init_state_null},
	{"G3_init_state_zeroes",          test_init_state_zeroes_fields},
	/* Group H: fruit_cleanup_connection_state */
	{"H1_cleanup_state_ok",           test_cleanup_state_ok},
	{"H2_cleanup_state_null",         test_cleanup_state_null},
	/* Group I: fruit_negotiate_capabilities */
	{"I1_negotiate_full_caps",        test_negotiate_full_caps},
	{"I2_negotiate_partial_caps",     test_negotiate_partial_caps},
	{"I3_negotiate_null_conn",        test_negotiate_null_conn},
	{"I4_negotiate_null_info",        test_negotiate_null_info},
	{"I5_negotiate_boolean_flags",    test_negotiate_boolean_flags},
	/* Group J: fruit_supports_capability */
	{"J1_supports_cap_present",       test_supports_cap_present},
	{"J2_supports_cap_absent",        test_supports_cap_absent},
	{"J3_supports_cap_null",          test_supports_cap_null},
	/* Group K: fruit_update_connection_state */
	{"K1_update_state_ok",            test_update_state_ok},
	{"K2_update_state_null_state",    test_update_state_null_state},
	{"K3_update_state_null_info",     test_update_state_null_info},
	{"K4_update_state_bad_sig",       test_update_state_bad_sig},
	/* Group L: fruit_get_context_size */
	{"L1_ctx_size_server_query",      test_ctx_size_server_query},
	{"L2_ctx_size_volume_caps",       test_ctx_size_volume_caps},
	{"L3_ctx_size_file_mode",         test_ctx_size_file_mode},
	{"L4_ctx_size_dir_hardlinks",     test_ctx_size_dir_hardlinks},
	{"L5_ctx_size_lookerinfo",        test_ctx_size_lookerinfo},
	{"L6_ctx_size_savebox",           test_ctx_size_savebox},
	{"L7_ctx_size_null",              test_ctx_size_null},
	{"L8_ctx_size_unknown",           test_ctx_size_unknown},
	/* Group M: fruit_build_server_response */
	{"M1_build_response_ok",          test_build_response_ok},
	{"M2_build_response_null_data",   test_build_response_null_data},
	{"M3_build_response_null_len",    test_build_response_null_len},
	/* Group N: fruit_debug_client_info */
	{"N1_debug_client_info_ok",       test_debug_client_info_ok},
	{"N2_debug_client_info_null",     test_debug_client_info_null},
	/* Group O: fruit_debug_capabilities */
	{"O1_debug_capabilities",         test_debug_capabilities},
	/* Group P: fruit_process_looker_info */
	{"P1_process_looker_ok",          test_process_looker_ok},
	{"P2_process_looker_null_conn",   test_process_looker_null_conn},
	{"P3_process_looker_null_info",   test_process_looker_null_info},
	/* Group Q: savebox / server_query / read_dir_attr */
	{"Q1_process_savebox_ok",         test_process_savebox_ok},
	{"Q2_process_savebox_null_conn",  test_process_savebox_null_conn},
	{"Q3_process_savebox_null_info",  test_process_savebox_null_info},
	{"Q4_process_server_query_ok",    test_process_server_query_ok},
	{"Q5_process_server_query_null",  test_process_server_query_null},
	{"Q6_read_dir_attr_null",         test_read_dir_attr_null},
	{"Q7_handle_savebox_bundle_null", test_handle_savebox_bundle_null},
	/* Group R: create_fruit_rsp_buf */
	{"R1_rsp_buf_with_state",         test_rsp_buf_with_state},
	{"R2_rsp_buf_no_state",           test_rsp_buf_no_state},
	{"R3_rsp_buf_offsets",            test_rsp_buf_offsets},
	/* Group S: struct layout validation */
	{"S1_struct_fruit_rsp_size",      test_struct_fruit_rsp_size},
	{"S2_struct_client_info_packed",  test_struct_client_info_packed},
	{"S3_struct_wire_sizes",          test_struct_wire_sizes},
	/* Group T: integration constants */
	{"T1_version_values_fruit_size",  test_version_values_fruit_size},
	{"T2_wire_protocol_tag",          test_wire_protocol_tag},
	/* Group U: fruit_is_client_request */
	{"U1_is_client_req_null",         test_is_client_req_null},
	{"U2_is_client_req_short",        test_is_client_req_short},
	{"U3_is_client_req_no_context",   test_is_client_req_no_context},
	/* Group V: fruit_init_module / fruit_cleanup_module */
	{"V1_init_module",                test_init_module},
	{"V2_cleanup_module",             test_cleanup_module},
	{NULL, NULL}
};

static int run_all_tests(void)
{
	int i;
	unsigned long long start, duration;

	pr_info("=== %s: Fruit SMB Coverage Tests ===\n", TEST_MODULE_NAME);
	pr_info("Running %d test groups (A-V)\n", 22);

	atomic_set(&stats.total, 0);
	atomic_set(&stats.passed, 0);
	atomic_set(&stats.failed, 0);
	atomic_set(&stats.skipped, 0);

	start = ktime_get_ns();

	for (i = 0; test_cases[i].name != NULL; i++) {
		pr_info("[%s]\n", test_cases[i].name);
		test_cases[i].func();
	}

	duration = ktime_get_ns() - start;

	pr_info("=== Results ===\n");
	pr_info("  Total:   %d\n", atomic_read(&stats.total));
	pr_info("  Passed:  %d\n", atomic_read(&stats.passed));
	pr_info("  Failed:  %d\n", atomic_read(&stats.failed));
	pr_info("  Skipped: %d\n", atomic_read(&stats.skipped));
	pr_info("  Time:    %llu ns\n", duration);

	if (atomic_read(&stats.failed) > 0) {
		pr_err("=== TESTS FAILED ===\n");
		return -1;
	}

	pr_info("=== ALL TESTS PASSED ===\n");
	return 0;
}

static int __init fruit_coverage_test_init(void)
{
	int ret;

	pr_info("Loading %s\n", TEST_MODULE_NAME);
	ret = run_all_tests();
	if (ret)
		return ret;
	return 0;
}

static void __exit fruit_coverage_test_exit(void)
{
	pr_info("Unloading %s\n", TEST_MODULE_NAME);
}

module_init(fruit_coverage_test_init);
module_exit(fruit_coverage_test_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexandre BETRY");
MODULE_DESCRIPTION("Comprehensive Coverage Tests for Fruit SMB Extensions");
MODULE_VERSION("1.0");
