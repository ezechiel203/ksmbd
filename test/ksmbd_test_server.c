// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for server configuration and state management (server.c)
 *
 *   These tests replicate the configuration set/get logic and state machine
 *   from server.c without linking to the ksmbd module.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ── Replicated server state constants ─── */
enum {
	TEST_SERVER_STATE_STARTING_UP,
	TEST_SERVER_STATE_RUNNING,
	TEST_SERVER_STATE_RESETTING,
	TEST_SERVER_STATE_SHUTTING_DOWN,
};

enum {
	TEST_SERVER_CONF_NETBIOS_NAME,
	TEST_SERVER_CONF_SERVER_STRING,
	TEST_SERVER_CONF_WORK_GROUP,
};

struct test_server_config {
	unsigned int	state;
	char		*conf[TEST_SERVER_CONF_WORK_GROUP + 1];
};

/* ── Replicated conf set/get logic ─── */

static int test_server_conf_set(struct test_server_config *cfg, int idx,
				char *val)
{
	if (idx > TEST_SERVER_CONF_WORK_GROUP)
		return -EINVAL;
	if (!val || val[0] == 0x00)
		return -EINVAL;

	kfree(cfg->conf[idx]);
	cfg->conf[idx] = kstrdup(val, GFP_KERNEL);
	if (!cfg->conf[idx])
		return -ENOMEM;
	return 0;
}

static int test_set_netbios_name(struct test_server_config *cfg, char *v)
{
	return test_server_conf_set(cfg, TEST_SERVER_CONF_NETBIOS_NAME, v);
}

static int test_set_server_string(struct test_server_config *cfg, char *v)
{
	return test_server_conf_set(cfg, TEST_SERVER_CONF_SERVER_STRING, v);
}

static int test_set_work_group(struct test_server_config *cfg, char *v)
{
	return test_server_conf_set(cfg, TEST_SERVER_CONF_WORK_GROUP, v);
}

static char *test_netbios_name(struct test_server_config *cfg)
{
	return cfg->conf[TEST_SERVER_CONF_NETBIOS_NAME];
}

static char *test_server_string(struct test_server_config *cfg)
{
	return cfg->conf[TEST_SERVER_CONF_SERVER_STRING];
}

static char *test_work_group(struct test_server_config *cfg)
{
	return cfg->conf[TEST_SERVER_CONF_WORK_GROUP];
}

static inline int test_server_running(struct test_server_config *cfg)
{
	return READ_ONCE(cfg->state) == TEST_SERVER_STATE_RUNNING;
}

static inline int test_server_configurable(struct test_server_config *cfg)
{
	return READ_ONCE(cfg->state) < TEST_SERVER_STATE_RESETTING;
}

static void test_server_conf_free(struct test_server_config *cfg)
{
	int i;

	for (i = 0; i <= TEST_SERVER_CONF_WORK_GROUP; i++) {
		kfree(cfg->conf[i]);
		cfg->conf[i] = NULL;
	}
}

/* ── Test init/exit ─── */

static int server_test_init(struct kunit *test)
{
	struct test_server_config *cfg;

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cfg);
	WRITE_ONCE(cfg->state, TEST_SERVER_STATE_STARTING_UP);
	test->priv = cfg;
	return 0;
}

static void server_test_exit(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;

	test_server_conf_free(cfg);
	kfree(cfg);
}

/* ──────────────────────────────────────────────────────────
 * Server configuration tests
 * ────────────────────────────────────────────────────────── */

static void test_server_conf_set_netbios_name(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;
	int ret;

	ret = test_set_netbios_name(cfg, "TESTSERVER");
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, test_netbios_name(cfg), "TESTSERVER");
}

static void test_server_conf_set_server_string(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;
	int ret;

	ret = test_set_server_string(cfg, "Test Server");
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, test_server_string(cfg), "Test Server");
}

static void test_server_conf_set_work_group(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;
	int ret;

	ret = test_set_work_group(cfg, "TESTWORKGROUP");
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, test_work_group(cfg), "TESTWORKGROUP");
}

static void test_server_conf_set_null_value(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;
	int ret;

	ret = test_set_netbios_name(cfg, NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_server_conf_set_empty_value(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;
	int ret;

	ret = test_set_netbios_name(cfg, "");
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_server_conf_set_replaces_previous(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;
	int ret;

	ret = test_set_netbios_name(cfg, "A");
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, test_netbios_name(cfg), "A");

	ret = test_set_netbios_name(cfg, "B");
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, test_netbios_name(cfg), "B");
}

/* ──────────────────────────────────────────────────────────
 * Server state machine tests
 * ────────────────────────────────────────────────────────── */

static void test_server_state_startup(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;

	KUNIT_EXPECT_EQ(test, READ_ONCE(cfg->state),
			(unsigned int)TEST_SERVER_STATE_STARTING_UP);
}

static void test_server_state_running(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;

	WRITE_ONCE(cfg->state, TEST_SERVER_STATE_RUNNING);
	KUNIT_EXPECT_EQ(test, READ_ONCE(cfg->state),
			(unsigned int)TEST_SERVER_STATE_RUNNING);
}

static void test_server_configurable(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;

	/* STARTING_UP is configurable */
	KUNIT_EXPECT_TRUE(test, test_server_configurable(cfg));
}

static void test_server_configurable_false_when_resetting(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;

	WRITE_ONCE(cfg->state, TEST_SERVER_STATE_RESETTING);
	KUNIT_EXPECT_FALSE(test, test_server_configurable(cfg));
}

static void test_server_running_check(struct kunit *test)
{
	struct test_server_config *cfg = test->priv;

	KUNIT_EXPECT_FALSE(test, test_server_running(cfg));
	WRITE_ONCE(cfg->state, TEST_SERVER_STATE_RUNNING);
	KUNIT_EXPECT_TRUE(test, test_server_running(cfg));
}

/* ──────────────────────────────────────────────────────────
 * Request dispatch tests (replicated logic)
 * ────────────────────────────────────────────────────────── */

#define TEST_SERVER_HANDLER_CONTINUE	0
#define TEST_SERVER_HANDLER_ABORT	1

static int test_process_request_dispatch(u16 command, unsigned int max_cmds,
					 bool has_proc)
{
	if (command >= max_cmds)
		return -1; /* STATUS_INVALID_PARAMETER */
	if (!has_proc)
		return -2; /* STATUS_NOT_IMPLEMENTED */
	return 0;
}

static void test_process_request_invalid_command(struct kunit *test)
{
	int ret;

	ret = test_process_request_dispatch(0xFF, 0x20, true);
	KUNIT_EXPECT_EQ(test, ret, -1);
}

static void test_process_request_unimplemented(struct kunit *test)
{
	int ret;

	ret = test_process_request_dispatch(0x05, 0x20, false);
	KUNIT_EXPECT_EQ(test, ret, -2);
}

static void test_process_request_valid(struct kunit *test)
{
	int ret;

	ret = test_process_request_dispatch(0x05, 0x20, true);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* ──────────────────────────────────────────────────────────
 * Encryption enforcement tests
 * ────────────────────────────────────────────────────────── */

#define TEST_SMB2_NEGOTIATE_HE		0x0000
#define TEST_SMB2_SESSION_SETUP_HE	0x0001

static bool test_encryption_check(bool enc_forced, bool encrypted, u16 command)
{
	if (enc_forced && !encrypted) {
		if (command != TEST_SMB2_NEGOTIATE_HE &&
		    command != TEST_SMB2_SESSION_SETUP_HE)
			return true; /* rejected */
	}
	return false; /* allowed */
}

static void test_encrypted_session_unencrypted_request_rejected(
	struct kunit *test)
{
	/* WRITE command (0x0009) should be rejected */
	KUNIT_EXPECT_TRUE(test, test_encryption_check(true, false, 0x0009));
}

static void test_encrypted_session_negotiate_allowed(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test,
		test_encryption_check(true, false, TEST_SMB2_NEGOTIATE_HE));
}

static void test_encrypted_session_session_setup_allowed(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test,
		test_encryption_check(true, false, TEST_SMB2_SESSION_SETUP_HE));
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_server_test_cases[] = {
	/* Configuration */
	KUNIT_CASE(test_server_conf_set_netbios_name),
	KUNIT_CASE(test_server_conf_set_server_string),
	KUNIT_CASE(test_server_conf_set_work_group),
	KUNIT_CASE(test_server_conf_set_null_value),
	KUNIT_CASE(test_server_conf_set_empty_value),
	KUNIT_CASE(test_server_conf_set_replaces_previous),
	/* State machine */
	KUNIT_CASE(test_server_state_startup),
	KUNIT_CASE(test_server_state_running),
	KUNIT_CASE(test_server_configurable),
	KUNIT_CASE(test_server_configurable_false_when_resetting),
	KUNIT_CASE(test_server_running_check),
	/* Request dispatch */
	KUNIT_CASE(test_process_request_invalid_command),
	KUNIT_CASE(test_process_request_unimplemented),
	KUNIT_CASE(test_process_request_valid),
	/* Encryption enforcement */
	KUNIT_CASE(test_encrypted_session_unencrypted_request_rejected),
	KUNIT_CASE(test_encrypted_session_negotiate_allowed),
	KUNIT_CASE(test_encrypted_session_session_setup_allowed),
	{}
};

static struct kunit_suite ksmbd_server_test_suite = {
	.name = "ksmbd_server",
	.init = server_test_init,
	.exit = server_test_exit,
	.test_cases = ksmbd_server_test_cases,
};

kunit_test_suite(ksmbd_server_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd server configuration and state machine");
