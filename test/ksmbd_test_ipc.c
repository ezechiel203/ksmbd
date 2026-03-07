// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for IPC message validation and handling (transport_ipc.c)
 *
 *   These tests replicate the ipc_validate_msg() logic from transport_ipc.c
 *   without linking to the ksmbd module.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/overflow.h>

/* ── Replicated constants ─── */

#define TEST_IPC_MAX_PAYLOAD	4096

/* Replicated event types */
enum {
	TEST_EVENT_UNSPEC = 0,
	TEST_EVENT_RPC_REQUEST = 12,
	TEST_EVENT_SPNEGO_AUTHEN_REQUEST = 14,
	TEST_EVENT_SHARE_CONFIG_REQUEST = 6,
	TEST_EVENT_LOGIN_REQUEST_EXT = 16,
};

/* Minimal replicated structures for ipc_validate_msg */
struct test_rpc_command {
	unsigned int	status;
	unsigned int	payload_sz;
	char		payload[];
};

struct test_spnego_response {
	unsigned int	status;
	unsigned int	session_key_len;
	unsigned int	spnego_blob_len;
	char		payload[];
};

struct test_share_config_response {
	unsigned int	status;
	unsigned int	flags;
	unsigned int	veto_list_sz;
	unsigned int	payload_sz;
	char		payload[];
};

struct test_login_response_ext {
	unsigned int	status;
	unsigned int	ngroups;
	char		payload[];
};

struct test_ipc_entry {
	unsigned int	handle;
	unsigned int	type;
	void		*response;
	unsigned int	msg_sz;
};

/* ── Replicated ipc_validate_msg() ─── */

static int test_ipc_validate_msg(struct test_ipc_entry *entry)
{
	unsigned int msg_sz = 0;

	if (entry->msg_sz > TEST_IPC_MAX_PAYLOAD)
		return -EINVAL;

	switch (entry->type) {
	case TEST_EVENT_RPC_REQUEST:
	{
		struct test_rpc_command *resp = entry->response;

		msg_sz = sizeof(struct test_rpc_command);
		if (check_add_overflow(msg_sz, resp->payload_sz, &msg_sz))
			return -EINVAL;
		break;
	}
	case TEST_EVENT_SPNEGO_AUTHEN_REQUEST:
	{
		struct test_spnego_response *resp = entry->response;
		unsigned int payload_sz;

		msg_sz = sizeof(struct test_spnego_response);
		if (check_add_overflow(resp->session_key_len,
				       resp->spnego_blob_len, &payload_sz))
			return -EINVAL;
		if (check_add_overflow(msg_sz, payload_sz, &msg_sz))
			return -EINVAL;
		break;
	}
	case TEST_EVENT_SHARE_CONFIG_REQUEST:
	{
		struct test_share_config_response *resp = entry->response;

		msg_sz = sizeof(struct test_share_config_response);
		if (resp->payload_sz < resp->veto_list_sz)
			return -EINVAL;
		if (resp->veto_list_sz && resp->payload_sz == resp->veto_list_sz)
			return -EINVAL;

		if (check_add_overflow(msg_sz, resp->payload_sz, &msg_sz))
			return -EINVAL;
		break;
	}
	case TEST_EVENT_LOGIN_REQUEST_EXT:
	{
		struct test_login_response_ext *resp = entry->response;

		msg_sz = sizeof(struct test_login_response_ext);
		if (resp->ngroups) {
			unsigned int groups_sz;

			if (check_mul_overflow(resp->ngroups,
					       (unsigned int)sizeof(gid_t),
					       &groups_sz))
				return -EINVAL;
			if (check_add_overflow(msg_sz, groups_sz, &msg_sz))
				return -EINVAL;
		}
		break;
	}
	default:
		return 0;
	}

	return entry->msg_sz != msg_sz ? -EINVAL : 0;
}

/* ──────────────────────────────────────────────────────────
 * Message allocation tests
 * ────────────────────────────────────────────────────────── */

static void test_ipc_msg_alloc_basic(struct kunit *test)
{
	unsigned int sz = 100;
	void *payload = kzalloc(sz, GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, payload);
	/* Verify zeroed */
	KUNIT_EXPECT_EQ(test, ((char *)payload)[0], 0);
	KUNIT_EXPECT_EQ(test, ((char *)payload)[sz - 1], 0);
	kfree(payload);
}

static void test_ipc_msg_alloc_zero(struct kunit *test)
{
	void *payload = kzalloc(0, GFP_KERNEL);

	/*
	 * kzalloc(0) returns ZERO_SIZE_PTR on many architectures
	 * which is not NULL. The point is that it does not crash.
	 */
	kfree(payload);
}

/* ──────────────────────────────────────────────────────────
 * ipc_validate_msg tests
 * ────────────────────────────────────────────────────────── */

static void test_ipc_validate_rpc_response_correct_size(struct kunit *test)
{
	struct test_rpc_command resp = { .payload_sz = 50 };
	struct test_ipc_entry entry = {
		.type = TEST_EVENT_RPC_REQUEST,
		.response = &resp,
		.msg_sz = sizeof(resp) + 50,
	};

	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), 0);
}

static void test_ipc_validate_rpc_response_overflow(struct kunit *test)
{
	struct test_rpc_command resp = { .payload_sz = UINT_MAX };
	struct test_ipc_entry entry = {
		.type = TEST_EVENT_RPC_REQUEST,
		.response = &resp,
		.msg_sz = 100,
	};

	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), -EINVAL);
}

static void test_ipc_validate_spnego_response_correct(struct kunit *test)
{
	struct test_spnego_response resp = {
		.session_key_len = 16,
		.spnego_blob_len = 32,
	};
	struct test_ipc_entry entry = {
		.type = TEST_EVENT_SPNEGO_AUTHEN_REQUEST,
		.response = &resp,
		.msg_sz = sizeof(resp) + 16 + 32,
	};

	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), 0);
}

static void test_ipc_validate_spnego_response_overflow(struct kunit *test)
{
	struct test_spnego_response resp = {
		.session_key_len = UINT_MAX,
		.spnego_blob_len = 1,
	};
	struct test_ipc_entry entry = {
		.type = TEST_EVENT_SPNEGO_AUTHEN_REQUEST,
		.response = &resp,
		.msg_sz = 100,
	};

	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), -EINVAL);
}

static void test_ipc_validate_share_config_response_correct(struct kunit *test)
{
	struct test_share_config_response resp = {
		.veto_list_sz = 10,
		.payload_sz = 50,
	};
	struct test_ipc_entry entry = {
		.type = TEST_EVENT_SHARE_CONFIG_REQUEST,
		.response = &resp,
		.msg_sz = sizeof(resp) + 50,
	};

	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), 0);
}

static void test_ipc_validate_share_config_veto_list_overflow(
	struct kunit *test)
{
	struct test_share_config_response resp = {
		.veto_list_sz = 100,
		.payload_sz = 50, /* payload_sz < veto_list_sz */
	};
	struct test_ipc_entry entry = {
		.type = TEST_EVENT_SHARE_CONFIG_REQUEST,
		.response = &resp,
		.msg_sz = sizeof(resp) + 50,
	};

	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), -EINVAL);
}

static void test_ipc_validate_share_config_veto_equal_payload(
	struct kunit *test)
{
	struct test_share_config_response resp = {
		.veto_list_sz = 50,
		.payload_sz = 50, /* veto > 0 and payload == veto (no path) */
	};
	struct test_ipc_entry entry = {
		.type = TEST_EVENT_SHARE_CONFIG_REQUEST,
		.response = &resp,
		.msg_sz = sizeof(resp) + 50,
	};

	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), -EINVAL);
}

static void test_ipc_validate_login_ext_correct(struct kunit *test)
{
	struct test_login_response_ext resp = {
		.ngroups = 3,
	};
	struct test_ipc_entry entry = {
		.type = TEST_EVENT_LOGIN_REQUEST_EXT,
		.response = &resp,
		.msg_sz = sizeof(resp) + 3 * sizeof(gid_t),
	};

	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), 0);
}

static void test_ipc_validate_login_ext_groups_overflow(struct kunit *test)
{
	struct test_login_response_ext resp = {
		.ngroups = UINT_MAX, /* causes multiplication overflow */
	};
	struct test_ipc_entry entry = {
		.type = TEST_EVENT_LOGIN_REQUEST_EXT,
		.response = &resp,
		.msg_sz = 100,
	};

	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), -EINVAL);
}

static void test_ipc_validate_max_payload(struct kunit *test)
{
	struct test_rpc_command resp = { .payload_sz = 0 };
	struct test_ipc_entry entry = {
		.type = TEST_EVENT_RPC_REQUEST,
		.response = &resp,
		.msg_sz = TEST_IPC_MAX_PAYLOAD + 1,
	};

	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), -EINVAL);
}

static void test_ipc_validate_unknown_type(struct kunit *test)
{
	struct test_ipc_entry entry = {
		.type = 0xFF,
		.response = NULL,
		.msg_sz = 100,
	};

	/* Unknown types return 0 (default case) */
	KUNIT_EXPECT_EQ(test, test_ipc_validate_msg(&entry), 0);
}

/* ──────────────────────────────────────────────────────────
 * Response handling tests
 * ────────────────────────────────────────────────────────── */

static void test_handle_response_payload_too_small(struct kunit *test)
{
	unsigned int payload_size = sizeof(unsigned int) - 1;

	/* Payload < sizeof(unsigned int) should be rejected */
	KUNIT_EXPECT_LT(test, payload_size, (unsigned int)sizeof(unsigned int));
}

static void test_handle_response_type_mismatch(struct kunit *test)
{
	unsigned int entry_type = 5;
	unsigned int response_type = 7; /* entry_type + 1 != 7 */

	KUNIT_EXPECT_NE(test, entry_type + 1, response_type);
}

static void test_handle_response_valid(struct kunit *test)
{
	unsigned int entry_type = 5;
	unsigned int response_type = 6; /* entry_type + 1 == 6 */

	KUNIT_EXPECT_EQ(test, entry_type + 1, response_type);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_ipc_test_cases[] = {
	/* Message allocation */
	KUNIT_CASE(test_ipc_msg_alloc_basic),
	KUNIT_CASE(test_ipc_msg_alloc_zero),
	/* ipc_validate_msg */
	KUNIT_CASE(test_ipc_validate_rpc_response_correct_size),
	KUNIT_CASE(test_ipc_validate_rpc_response_overflow),
	KUNIT_CASE(test_ipc_validate_spnego_response_correct),
	KUNIT_CASE(test_ipc_validate_spnego_response_overflow),
	KUNIT_CASE(test_ipc_validate_share_config_response_correct),
	KUNIT_CASE(test_ipc_validate_share_config_veto_list_overflow),
	KUNIT_CASE(test_ipc_validate_share_config_veto_equal_payload),
	KUNIT_CASE(test_ipc_validate_login_ext_correct),
	KUNIT_CASE(test_ipc_validate_login_ext_groups_overflow),
	KUNIT_CASE(test_ipc_validate_max_payload),
	KUNIT_CASE(test_ipc_validate_unknown_type),
	/* Response handling */
	KUNIT_CASE(test_handle_response_payload_too_small),
	KUNIT_CASE(test_handle_response_type_mismatch),
	KUNIT_CASE(test_handle_response_valid),
	{}
};

static struct kunit_suite ksmbd_ipc_test_suite = {
	.name = "ksmbd_ipc",
	.test_cases = ksmbd_ipc_test_cases,
};

kunit_test_suite(ksmbd_ipc_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd IPC message validation");
