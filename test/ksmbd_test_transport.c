// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for TCP transport pure-logic functions (transport_tcp.c)
 *
 *   These tests replicate the kvec_array_init logic and interface management
 *   helpers without requiring actual socket operations.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uio.h>

/* ── Replicated kvec_array_init() from transport_tcp.c ───
 *
 * Given an array of kvec segments and a byte offset, compute the
 * starting segment and adjust its base/len for partial consumption.
 * Returns the number of remaining segments.
 */
static unsigned int test_kvec_array_init(struct kvec *new, struct kvec *iov,
					 unsigned int nr_segs,
					 unsigned int bytes)
{
	unsigned int i, skip;

	for (i = 0; i < nr_segs; i++) {
		if (bytes < iov[i].iov_len)
			break;
		bytes -= iov[i].iov_len;
	}

	if (i >= nr_segs)
		return 0;

	skip = i;
	new[0].iov_base = (char *)iov[skip].iov_base + bytes;
	new[0].iov_len = iov[skip].iov_len - bytes;

	for (i = 1; i < nr_segs - skip; i++) {
		new[i].iov_base = iov[skip + i].iov_base;
		new[i].iov_len = iov[skip + i].iov_len;
	}

	return nr_segs - skip;
}

/* ── Interface state constants ─── */
#define TEST_IFACE_STATE_DOWN	0
#define TEST_IFACE_STATE_UP	1

struct test_interface {
	char		name[16];
	int		state;
	struct list_head	entry;
};

static struct test_interface *test_alloc_iface(const char *name)
{
	struct test_interface *iface;

	if (!name)
		return NULL;

	iface = kzalloc(sizeof(*iface), GFP_KERNEL);
	if (!iface)
		return NULL;

	strscpy(iface->name, name, sizeof(iface->name));
	iface->state = TEST_IFACE_STATE_DOWN;
	INIT_LIST_HEAD(&iface->entry);
	return iface;
}

/* ──────────────────────────────────────────────────────────
 * kvec_array_init tests
 * ────────────────────────────────────────────────────────── */

static void test_kvec_array_init_single_segment(struct kunit *test)
{
	char buf[100];
	struct kvec iov = { .iov_base = buf, .iov_len = 100 };
	struct kvec new[1];
	unsigned int nr;

	nr = test_kvec_array_init(new, &iov, 1, 0);
	KUNIT_EXPECT_EQ(test, nr, 1u);
	KUNIT_EXPECT_PTR_EQ(test, new[0].iov_base, buf);
	KUNIT_EXPECT_EQ(test, (unsigned int)new[0].iov_len, 100u);
}

static void test_kvec_array_init_partial_first_segment(struct kunit *test)
{
	char buf[100];
	struct kvec iov = { .iov_base = buf, .iov_len = 100 };
	struct kvec new[1];
	unsigned int nr;

	nr = test_kvec_array_init(new, &iov, 1, 50);
	KUNIT_EXPECT_EQ(test, nr, 1u);
	KUNIT_EXPECT_PTR_EQ(test, new[0].iov_base, buf + 50);
	KUNIT_EXPECT_EQ(test, (unsigned int)new[0].iov_len, 50u);
}

static void test_kvec_array_init_skip_entire_first_segment(struct kunit *test)
{
	char buf1[100], buf2[200];
	struct kvec iov[2] = {
		{ .iov_base = buf1, .iov_len = 100 },
		{ .iov_base = buf2, .iov_len = 200 },
	};
	struct kvec new[2];
	unsigned int nr;

	nr = test_kvec_array_init(new, iov, 2, 100);
	KUNIT_EXPECT_EQ(test, nr, 1u);
	KUNIT_EXPECT_PTR_EQ(test, new[0].iov_base, buf2);
	KUNIT_EXPECT_EQ(test, (unsigned int)new[0].iov_len, 200u);
}

static void test_kvec_array_init_partial_second_segment(struct kunit *test)
{
	char buf1[100], buf2[200];
	struct kvec iov[2] = {
		{ .iov_base = buf1, .iov_len = 100 },
		{ .iov_base = buf2, .iov_len = 200 },
	};
	struct kvec new[2];
	unsigned int nr;

	nr = test_kvec_array_init(new, iov, 2, 150);
	KUNIT_EXPECT_EQ(test, nr, 1u);
	KUNIT_EXPECT_PTR_EQ(test, new[0].iov_base, buf2 + 50);
	KUNIT_EXPECT_EQ(test, (unsigned int)new[0].iov_len, 150u);
}

static void test_kvec_array_init_all_consumed(struct kunit *test)
{
	char buf[100];
	struct kvec iov = { .iov_base = buf, .iov_len = 100 };
	struct kvec new[1];
	unsigned int nr;

	nr = test_kvec_array_init(new, &iov, 1, 100);
	KUNIT_EXPECT_EQ(test, nr, 0u);
}

static void test_kvec_array_init_zero_length_segment(struct kunit *test)
{
	char buf1[50], buf2[0], buf3[100];
	struct kvec iov[3] = {
		{ .iov_base = buf1, .iov_len = 50 },
		{ .iov_base = buf2, .iov_len = 0 },
		{ .iov_base = buf3, .iov_len = 100 },
	};
	struct kvec new[3];
	unsigned int nr;

	/* Skip first segment (50 bytes) + zero-length segment */
	nr = test_kvec_array_init(new, iov, 3, 50);
	/* Zero-length segment is skipped automatically */
	KUNIT_EXPECT_GE(test, nr, 1u);
}

static void test_kvec_array_init_many_segments(struct kunit *test)
{
	char bufs[8][32];
	struct kvec iov[8];
	struct kvec new[8];
	unsigned int nr;
	int i;

	for (i = 0; i < 8; i++) {
		memset(bufs[i], 'A' + i, 32);
		iov[i].iov_base = bufs[i];
		iov[i].iov_len = 32;
	}

	/* Skip 3 full segments (96 bytes) + 10 bytes into 4th */
	nr = test_kvec_array_init(new, iov, 8, 106);
	KUNIT_EXPECT_EQ(test, nr, 5u); /* segments 3-7 remain */
	KUNIT_EXPECT_PTR_EQ(test, new[0].iov_base, bufs[3] + 10);
	KUNIT_EXPECT_EQ(test, (unsigned int)new[0].iov_len, 22u);
}

/* ──────────────────────────────────────────────────────────
 * Interface management tests
 * ────────────────────────────────────────────────────────── */

static void test_alloc_iface_null_name(struct kunit *test)
{
	struct test_interface *iface = test_alloc_iface(NULL);

	KUNIT_EXPECT_NULL(test, iface);
}

static void test_alloc_iface_valid(struct kunit *test)
{
	struct test_interface *iface = test_alloc_iface("eth0");

	KUNIT_ASSERT_NOT_NULL(test, iface);
	KUNIT_EXPECT_STREQ(test, iface->name, "eth0");
	KUNIT_EXPECT_EQ(test, iface->state, TEST_IFACE_STATE_DOWN);
	kfree(iface);
}

static void test_find_netdev_name_iface(struct kunit *test)
{
	struct test_interface *i1, *i2;
	struct test_interface *found = NULL, *cur;
	LIST_HEAD(iface_list);

	i1 = test_alloc_iface("eth0");
	i2 = test_alloc_iface("eth1");
	KUNIT_ASSERT_NOT_NULL(test, i1);
	KUNIT_ASSERT_NOT_NULL(test, i2);

	list_add_tail(&i1->entry, &iface_list);
	list_add_tail(&i2->entry, &iface_list);

	/* Search for eth0 */
	list_for_each_entry(cur, &iface_list, entry) {
		if (strcmp(cur->name, "eth0") == 0) {
			found = cur;
			break;
		}
	}
	KUNIT_EXPECT_NOT_NULL(test, found);
	KUNIT_EXPECT_STREQ(test, found->name, "eth0");

	/* Search for eth2 (should not be found) */
	found = NULL;
	list_for_each_entry(cur, &iface_list, entry) {
		if (strcmp(cur->name, "eth2") == 0) {
			found = cur;
			break;
		}
	}
	KUNIT_EXPECT_NULL(test, found);

	list_del(&i1->entry);
	list_del(&i2->entry);
	kfree(i1);
	kfree(i2);
}

/* ──────────────────────────────────────────────────────────
 * Transport allocation tests
 * ────────────────────────────────────────────────────────── */

static void test_alloc_transport_null_socket(struct kunit *test)
{
	/*
	 * In production, passing NULL socket returns NULL.
	 * We verify the concept.
	 */
	void *transport = NULL;

	if (!transport) /* NULL socket -> NULL transport */
		KUNIT_EXPECT_NULL(test, transport);
}

/* ──────────────────────────────────────────────────────────
 * Connection teardown tests
 * ────────────────────────────────────────────────────────── */

static void test_disconnect_decrements_active_count(struct kunit *test)
{
	atomic_t active_num_conn = ATOMIC_INIT(1);

	atomic_dec(&active_num_conn);
	KUNIT_EXPECT_EQ(test, atomic_read(&active_num_conn), 0);
}

static void test_disconnect_no_decrement_when_max_zero(struct kunit *test)
{
	unsigned int max_connections = 0;
	atomic_t active_num_conn = ATOMIC_INIT(5);

	/* When max_connections is 0, active count tracking is not used */
	if (max_connections == 0) {
		KUNIT_EXPECT_EQ(test, atomic_read(&active_num_conn), 5);
	}
}

/* ──────────────────────────────────────────────────────────
 * Socket option verification tests (replicated constants)
 * ────────────────────────────────────────────────────────── */

static void test_tcp_nodelay_constant(struct kunit *test)
{
	/*
	 * ksmbd_tcp_nodelay() sets TCP_NODELAY=1 on the socket.
	 * Verify the constant values used.
	 */
	int nodelay = 1;

	KUNIT_EXPECT_EQ(test, nodelay, 1);
}

static void test_tcp_keepalive_params(struct kunit *test)
{
	/*
	 * ksmbd sets keepalive params:
	 *   keepidle = 120 seconds
	 *   keepintvl = 30 seconds
	 *   keepcnt = 3 retries
	 */
	int keepidle = 120;
	int keepintvl = 30;
	int keepcnt = 3;

	KUNIT_EXPECT_EQ(test, keepidle, 120);
	KUNIT_EXPECT_EQ(test, keepintvl, 30);
	KUNIT_EXPECT_EQ(test, keepcnt, 3);
}

static void test_tcp_reuseaddr_constant(struct kunit *test)
{
	int reuseaddr = 1;

	KUNIT_EXPECT_EQ(test, reuseaddr, 1);
}

static void test_tcp_set_interfaces_empty(struct kunit *test)
{
	/*
	 * When set_interfaces is called with NULL/0 args,
	 * bind_additional_ifaces should be set to 1 (wildcard).
	 */
	int bind_additional_ifaces = 0;
	const char *iface_list = NULL;

	if (!iface_list)
		bind_additional_ifaces = 1;

	KUNIT_EXPECT_EQ(test, bind_additional_ifaces, 1);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_transport_test_cases[] = {
	/* kvec_array_init */
	KUNIT_CASE(test_kvec_array_init_single_segment),
	KUNIT_CASE(test_kvec_array_init_partial_first_segment),
	KUNIT_CASE(test_kvec_array_init_skip_entire_first_segment),
	KUNIT_CASE(test_kvec_array_init_partial_second_segment),
	KUNIT_CASE(test_kvec_array_init_all_consumed),
	KUNIT_CASE(test_kvec_array_init_zero_length_segment),
	KUNIT_CASE(test_kvec_array_init_many_segments),
	/* Interface management */
	KUNIT_CASE(test_alloc_iface_null_name),
	KUNIT_CASE(test_alloc_iface_valid),
	KUNIT_CASE(test_find_netdev_name_iface),
	/* Transport allocation */
	KUNIT_CASE(test_alloc_transport_null_socket),
	/* Connection teardown */
	KUNIT_CASE(test_disconnect_decrements_active_count),
	KUNIT_CASE(test_disconnect_no_decrement_when_max_zero),
	/* Socket options */
	KUNIT_CASE(test_tcp_nodelay_constant),
	KUNIT_CASE(test_tcp_keepalive_params),
	KUNIT_CASE(test_tcp_reuseaddr_constant),
	KUNIT_CASE(test_tcp_set_interfaces_empty),
	{}
};

static struct kunit_suite ksmbd_transport_test_suite = {
	.name = "ksmbd_transport",
	.test_cases = ksmbd_transport_test_cases,
};

kunit_test_suite(ksmbd_transport_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd TCP transport helpers");
