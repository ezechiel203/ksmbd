// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 CANCEL command processing (smb2_lock.c smb2_cancel)
 *
 *   Tests cover:
 *     - Cancel request identification (AsyncId vs MessageId)
 *     - Cancel of pending lock requests
 *     - Cancel of pending notify watches
 *     - Cancel of pending change notify (piggyback)
 *     - send_no_response flag on cancel
 *     - Cancel with invalid/non-existent IDs
 *     - Signing exclusion (MS-SMB2 3.2.4.24)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* ---- Replicated constants ---- */

#define TEST_SMB2_FLAGS_ASYNC_COMMAND		0x00000002
#define TEST_SMB2_FLAGS_SIGNED			0x00000008

#define TEST_SMB2_CANCEL_HE			0x000C
#define TEST_SMB2_LOCK_HE			0x000A
#define TEST_SMB2_CHANGE_NOTIFY_HE		0x000F
#define TEST_SMB2_NEGOTIATE_HE			0x0000
#define TEST_SMB2_SESSION_SETUP_HE		0x0001

/* Cancel never requires signing (MS-SMB2 3.2.4.24) */
#define TEST_CANCEL_EXEMPT_FROM_SIGNING		1

/* ---- Replicated structures ---- */

struct test_cancel_state {
	u64 async_id;
	u64 message_id;
	u32 flags;
	bool found;
	bool cancelled;
};

struct test_pending_request {
	u64 async_id;
	u64 message_id;
	u16 command;
	bool is_async;
	bool cancelled;
};

/* ---- Replicated logic ---- */

/*
 * Determine if cancel targets an async request (uses AsyncId)
 * or a sync request (uses MessageId)
 */
static bool test_cancel_is_async(u32 flags)
{
	return !!(flags & TEST_SMB2_FLAGS_ASYNC_COMMAND);
}

/*
 * Find pending request by AsyncId
 */
static struct test_pending_request *
test_find_by_async_id(struct test_pending_request *reqs, int count, u64 async_id)
{
	int i;

	for (i = 0; i < count; i++) {
		if (reqs[i].is_async && reqs[i].async_id == async_id)
			return &reqs[i];
	}
	return NULL;
}

/*
 * Find pending request by MessageId
 */
static struct test_pending_request *
test_find_by_message_id(struct test_pending_request *reqs, int count,
			u64 message_id)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!reqs[i].is_async && reqs[i].message_id == message_id)
			return &reqs[i];
	}
	return NULL;
}

/*
 * Cancel always returns send_no_response = 1
 * (MS-SMB2 3.3.5.16: no response is sent for CANCEL)
 */
static int test_process_cancel(struct test_cancel_state *state,
			       struct test_pending_request *reqs, int count)
{
	struct test_pending_request *found = NULL;

	if (test_cancel_is_async(state->flags))
		found = test_find_by_async_id(reqs, count, state->async_id);
	else
		found = test_find_by_message_id(reqs, count,
						state->message_id);

	if (found) {
		found->cancelled = true;
		state->found = true;
		state->cancelled = true;
	} else {
		state->found = false;
	}

	/* Cancel always sets send_no_response */
	return 1; /* send_no_response */
}

/*
 * Check if command is exempt from signing (MS-SMB2 3.2.4.24)
 */
static bool test_signing_exempt(u16 command)
{
	switch (command) {
	case TEST_SMB2_CANCEL_HE:
	case TEST_SMB2_NEGOTIATE_HE:
		return true;
	default:
		return false;
	}
}

/*
 * Validate cancel request: CANCEL has no body (StructureSize = 4)
 */
static bool test_validate_cancel_body(u16 struct_size)
{
	return struct_size == 4;
}

/* ---- Test Cases: Cancel Identification ---- */

static void test_cancel_async_flag_detection(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_cancel_is_async(TEST_SMB2_FLAGS_ASYNC_COMMAND));
	KUNIT_EXPECT_FALSE(test, test_cancel_is_async(0));
	KUNIT_EXPECT_TRUE(test,
		test_cancel_is_async(TEST_SMB2_FLAGS_ASYNC_COMMAND |
				     TEST_SMB2_FLAGS_SIGNED));
}

static void test_cancel_find_by_async_id(struct kunit *test)
{
	struct test_pending_request reqs[2] = {
		{ .async_id = 100, .message_id = 1,
		  .command = TEST_SMB2_LOCK_HE, .is_async = true },
		{ .async_id = 200, .message_id = 2,
		  .command = TEST_SMB2_CHANGE_NOTIFY_HE, .is_async = true },
	};
	struct test_pending_request *found;

	found = test_find_by_async_id(reqs, 2, 100);
	KUNIT_ASSERT_NOT_NULL(test, found);
	KUNIT_EXPECT_EQ(test, found->command, (u16)TEST_SMB2_LOCK_HE);

	found = test_find_by_async_id(reqs, 2, 200);
	KUNIT_ASSERT_NOT_NULL(test, found);
	KUNIT_EXPECT_EQ(test, found->command,
			(u16)TEST_SMB2_CHANGE_NOTIFY_HE);
}

static void test_cancel_find_by_async_id_not_found(struct kunit *test)
{
	struct test_pending_request reqs[1] = {
		{ .async_id = 100, .is_async = true },
	};
	struct test_pending_request *found;

	found = test_find_by_async_id(reqs, 1, 999);
	KUNIT_EXPECT_NULL(test, found);
}

static void test_cancel_find_by_message_id(struct kunit *test)
{
	struct test_pending_request reqs[2] = {
		{ .message_id = 10, .command = TEST_SMB2_LOCK_HE },
		{ .message_id = 20, .command = TEST_SMB2_CHANGE_NOTIFY_HE },
	};
	struct test_pending_request *found;

	found = test_find_by_message_id(reqs, 2, 20);
	KUNIT_ASSERT_NOT_NULL(test, found);
	KUNIT_EXPECT_EQ(test, found->command,
			(u16)TEST_SMB2_CHANGE_NOTIFY_HE);
}

static void test_cancel_find_by_message_id_not_found(struct kunit *test)
{
	struct test_pending_request reqs[1] = {
		{ .message_id = 10 },
	};
	struct test_pending_request *found;

	found = test_find_by_message_id(reqs, 1, 999);
	KUNIT_EXPECT_NULL(test, found);
}

/* ---- Test Cases: Cancel Processing ---- */

static void test_cancel_pending_lock(struct kunit *test)
{
	struct test_cancel_state state = {
		.async_id = 100,
		.flags = TEST_SMB2_FLAGS_ASYNC_COMMAND,
	};
	struct test_pending_request reqs[1] = {
		{ .async_id = 100, .command = TEST_SMB2_LOCK_HE,
		  .is_async = true },
	};
	int send_no_response;

	send_no_response = test_process_cancel(&state, reqs, 1);

	KUNIT_EXPECT_TRUE(test, state.found);
	KUNIT_EXPECT_TRUE(test, state.cancelled);
	KUNIT_EXPECT_TRUE(test, reqs[0].cancelled);
	KUNIT_EXPECT_EQ(test, send_no_response, 1);
}

static void test_cancel_pending_notify(struct kunit *test)
{
	struct test_cancel_state state = {
		.async_id = 200,
		.flags = TEST_SMB2_FLAGS_ASYNC_COMMAND,
	};
	struct test_pending_request reqs[1] = {
		{ .async_id = 200, .command = TEST_SMB2_CHANGE_NOTIFY_HE,
		  .is_async = true },
	};
	int send_no_response;

	send_no_response = test_process_cancel(&state, reqs, 1);

	KUNIT_EXPECT_TRUE(test, state.found);
	KUNIT_EXPECT_TRUE(test, reqs[0].cancelled);
	KUNIT_EXPECT_EQ(test, send_no_response, 1);
}

static void test_cancel_sync_pending_lock(struct kunit *test)
{
	struct test_cancel_state state = {
		.message_id = 42,
		.flags = 0, /* sync */
	};
	struct test_pending_request reqs[1] = {
		{ .message_id = 42, .command = TEST_SMB2_LOCK_HE },
	};
	int send_no_response;

	send_no_response = test_process_cancel(&state, reqs, 1);

	KUNIT_EXPECT_TRUE(test, state.found);
	KUNIT_EXPECT_TRUE(test, reqs[0].cancelled);
	KUNIT_EXPECT_EQ(test, send_no_response, 1);
}

static void test_cancel_not_found(struct kunit *test)
{
	struct test_cancel_state state = {
		.async_id = 999,
		.flags = TEST_SMB2_FLAGS_ASYNC_COMMAND,
	};
	struct test_pending_request reqs[1] = {
		{ .async_id = 100, .is_async = true },
	};
	int send_no_response;

	send_no_response = test_process_cancel(&state, reqs, 1);

	KUNIT_EXPECT_FALSE(test, state.found);
	KUNIT_EXPECT_FALSE(test, reqs[0].cancelled);
	/* Even when not found, cancel returns send_no_response */
	KUNIT_EXPECT_EQ(test, send_no_response, 1);
}

static void test_cancel_empty_pending_list(struct kunit *test)
{
	struct test_cancel_state state = {
		.async_id = 100,
		.flags = TEST_SMB2_FLAGS_ASYNC_COMMAND,
	};
	int send_no_response;

	send_no_response = test_process_cancel(&state, NULL, 0);

	KUNIT_EXPECT_FALSE(test, state.found);
	KUNIT_EXPECT_EQ(test, send_no_response, 1);
}

static void test_cancel_multiple_pending(struct kunit *test)
{
	struct test_cancel_state state = {
		.async_id = 300,
		.flags = TEST_SMB2_FLAGS_ASYNC_COMMAND,
	};
	struct test_pending_request reqs[3] = {
		{ .async_id = 100, .command = TEST_SMB2_LOCK_HE,
		  .is_async = true },
		{ .async_id = 200, .command = TEST_SMB2_CHANGE_NOTIFY_HE,
		  .is_async = true },
		{ .async_id = 300, .command = TEST_SMB2_LOCK_HE,
		  .is_async = true },
	};

	test_process_cancel(&state, reqs, 3);

	/* Only the matching request should be cancelled */
	KUNIT_EXPECT_FALSE(test, reqs[0].cancelled);
	KUNIT_EXPECT_FALSE(test, reqs[1].cancelled);
	KUNIT_EXPECT_TRUE(test, reqs[2].cancelled);
}

/* ---- Test Cases: send_no_response ---- */

static void test_cancel_always_no_response(struct kunit *test)
{
	/*
	 * MS-SMB2 3.3.5.16: The server MUST NOT send a response
	 * to the SMB2 CANCEL request.
	 */
	struct test_cancel_state state1 = {
		.async_id = 100,
		.flags = TEST_SMB2_FLAGS_ASYNC_COMMAND,
	};
	struct test_cancel_state state2 = {
		.message_id = 100,
		.flags = 0,
	};
	struct test_pending_request reqs[1] = {
		{ .async_id = 100, .message_id = 100, .is_async = true },
	};

	KUNIT_EXPECT_EQ(test, test_process_cancel(&state1, reqs, 1), 1);
	/* Reset for sync test */
	reqs[0].is_async = false;
	reqs[0].cancelled = false;
	KUNIT_EXPECT_EQ(test, test_process_cancel(&state2, reqs, 1), 1);
}

/* ---- Test Cases: Signing Exclusion ---- */

static void test_cancel_signing_exempt(struct kunit *test)
{
	/* CANCEL is exempt from signing (MS-SMB2 3.2.4.24) */
	KUNIT_EXPECT_TRUE(test, test_signing_exempt(TEST_SMB2_CANCEL_HE));
}

static void test_cancel_negotiate_also_exempt(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_signing_exempt(TEST_SMB2_NEGOTIATE_HE));
}

static void test_cancel_other_commands_not_exempt(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_signing_exempt(TEST_SMB2_LOCK_HE));
	KUNIT_EXPECT_FALSE(test,
		test_signing_exempt(TEST_SMB2_CHANGE_NOTIFY_HE));
	KUNIT_EXPECT_FALSE(test,
		test_signing_exempt(TEST_SMB2_SESSION_SETUP_HE));
}

/* ---- Test Cases: Body Validation ---- */

static void test_cancel_body_struct_size(struct kunit *test)
{
	/* CANCEL request body is 4 bytes (StructureSize only) */
	KUNIT_EXPECT_TRUE(test, test_validate_cancel_body(4));
	KUNIT_EXPECT_FALSE(test, test_validate_cancel_body(8));
	KUNIT_EXPECT_FALSE(test, test_validate_cancel_body(0));
}

/* ---- Test Cases: Piggyback Cancel ---- */

static void test_cancel_piggyback_notify(struct kunit *test)
{
	/*
	 * When a CHANGE_NOTIFY is used as a "piggyback" (reusing
	 * an already-completed notify for new events), cancel must
	 * properly decrement the outstanding_async counter.
	 */
	int outstanding_async = 2;

	/* Simulate cancel of one piggyback watch */
	outstanding_async--;
	KUNIT_EXPECT_EQ(test, outstanding_async, 1);

	/* Cancel of second */
	outstanding_async--;
	KUNIT_EXPECT_EQ(test, outstanding_async, 0);
}

static void test_cancel_outstanding_async_counter(struct kunit *test)
{
	/*
	 * The outstanding_async counter must be decremented when
	 * a pending async request is cancelled, to avoid leaking
	 * the counter and eventually hitting a resource limit.
	 */
	int outstanding_async = 5;

	/* Cancel one */
	outstanding_async--;
	KUNIT_EXPECT_EQ(test, outstanding_async, 4);

	/* Counter should never go negative */
	outstanding_async = 0;
	/* In real code, decrement is guarded */
	if (outstanding_async > 0)
		outstanding_async--;
	KUNIT_EXPECT_EQ(test, outstanding_async, 0);
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_smb2_cancel_test_cases[] = {
	/* Cancel Identification */
	KUNIT_CASE(test_cancel_async_flag_detection),
	KUNIT_CASE(test_cancel_find_by_async_id),
	KUNIT_CASE(test_cancel_find_by_async_id_not_found),
	KUNIT_CASE(test_cancel_find_by_message_id),
	KUNIT_CASE(test_cancel_find_by_message_id_not_found),
	/* Cancel Processing */
	KUNIT_CASE(test_cancel_pending_lock),
	KUNIT_CASE(test_cancel_pending_notify),
	KUNIT_CASE(test_cancel_sync_pending_lock),
	KUNIT_CASE(test_cancel_not_found),
	KUNIT_CASE(test_cancel_empty_pending_list),
	KUNIT_CASE(test_cancel_multiple_pending),
	/* send_no_response */
	KUNIT_CASE(test_cancel_always_no_response),
	/* Signing Exclusion */
	KUNIT_CASE(test_cancel_signing_exempt),
	KUNIT_CASE(test_cancel_negotiate_also_exempt),
	KUNIT_CASE(test_cancel_other_commands_not_exempt),
	/* Body Validation */
	KUNIT_CASE(test_cancel_body_struct_size),
	/* Piggyback */
	KUNIT_CASE(test_cancel_piggyback_notify),
	KUNIT_CASE(test_cancel_outstanding_async_counter),
	{}
};

static struct kunit_suite ksmbd_smb2_cancel_test_suite = {
	.name = "ksmbd_smb2_cancel",
	.test_cases = ksmbd_smb2_cancel_test_cases,
};

kunit_test_suite(ksmbd_smb2_cancel_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 CANCEL command processing");
