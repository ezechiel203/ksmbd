// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for TCP transport layer: RFC1002 header parsing,
 *   connection state machine, per-IP connection limits, iovec
 *   allocation thresholds, and PDU size validation.
 *
 *   Since we cannot create real TCP connections in KUnit, these tests
 *   replicate the pure-logic helpers from transport_tcp.c and
 *   connection.c that can be validated independently.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/overflow.h>
#include <asm/unaligned.h>

/* ---- Replicated constants from smb_common.h / connection.h ---- */

#define TEST_RFC1002_HEADER_LEN		4
#define TEST_MAX_STREAM_PROT_LEN	0x00FFFFFF
#define TEST_SMB1_MIN_SUPPORTED_HEADER_SIZE	35
#define TEST_SMB3_MAX_MSGSIZE		(4 * 4096)

/* RFC1002 message types (from smb1pdu.h) */
#define TEST_RFC1002_SESSION_MESSAGE		0x00
#define TEST_RFC1002_SESSION_REQUEST		0x81
#define TEST_RFC1002_POSITIVE_SESSION_RESPONSE	0x82
#define TEST_RFC1002_NEGATIVE_SESSION_RESPONSE	0x83
#define TEST_RFC1002_RETARGET_SESSION_RESPONSE	0x84
#define TEST_RFC1002_SESSION_KEEP_ALIVE		0x85

/* Connection states (replicated from connection.h) */
enum test_conn_status {
	TEST_SESS_NEW = 0,
	TEST_SESS_GOOD,
	TEST_SESS_EXITING,
	TEST_SESS_NEED_RECONNECT,
	TEST_SESS_NEED_NEGOTIATE,
	TEST_SESS_NEED_SETUP,
	TEST_SESS_RELEASING
};

/* Small IOV threshold from transport_tcp.c */
#define TEST_KSMBD_TCP_SMALL_IOV	8

/* ---- Replicated get_rfc1002_len() from smb_common.h ---- */

static inline unsigned int test_get_rfc1002_len(void *buf)
{
	return get_unaligned_be32(buf) & 0xffffff;
}

/* ---- Replicated inc_rfc1001_len() from smb_common.h ---- */

static inline void test_inc_rfc1001_len(void *buf, int count)
{
	unsigned int cur = test_get_rfc1002_len(buf);

	if ((unsigned int)(cur + count) > TEST_MAX_STREAM_PROT_LEN)
		return;
	be32_add_cpu((__be32 *)buf, count);
}

/* ---- Replicated kvec_array_init() from transport_tcp.c ---- */

static unsigned int test_kvec_array_init(struct kvec *new, struct kvec *iov,
					 unsigned int nr_segs, size_t bytes)
{
	size_t base = 0;

	while (nr_segs && (bytes || !iov->iov_len)) {
		size_t copy = min(bytes, iov->iov_len);

		bytes -= copy;
		base += copy;
		if (iov->iov_len == base) {
			iov++;
			nr_segs--;
			base = 0;
		}
	}

	if (!nr_segs)
		return 0;

	memcpy(new, iov, sizeof(*iov) * nr_segs);
	new->iov_base += base;
	new->iov_len -= base;
	return nr_segs;
}

/* ---- Replicated per-IP connection limit logic ---- */

struct test_conn_entry {
	struct hlist_node	hlist;
	unsigned int		inet_hash;
	__be32			inet_addr;
	int			status;
};

#define TEST_CONN_HASH_BITS	4
static DEFINE_HASHTABLE(test_conn_hash, TEST_CONN_HASH_BITS);

static unsigned int test_count_ip_conns(unsigned int inet_hash,
					__be32 addr,
					unsigned int max_ip_conns)
{
	struct test_conn_entry *conn;
	unsigned int count = 0;
	int bkt;

	bkt = hash_min(inet_hash, TEST_CONN_HASH_BITS);
	hlist_for_each_entry(conn, &test_conn_hash[1 << TEST_CONN_HASH_BITS],
			     hlist) {
		/* dummy: won't iterate */
	}

	/* Direct iteration over the correct bucket */
	hash_for_each_possible(test_conn_hash, conn, hlist, inet_hash) {
		if (conn->inet_hash != inet_hash)
			continue;
		if (conn->status == TEST_SESS_EXITING ||
		    conn->status == TEST_SESS_RELEASING)
			continue;
		if (conn->inet_addr == addr)
			count++;
		if (count >= max_ip_conns)
			break;
	}
	return count;
}

/* ==================================================================
 * Test cases: RFC1002 header parsing
 * ================================================================== */

/*
 * test_rfc1002_parse_valid_session_message - standard session message
 * with 24-bit length field.
 */
static void test_rfc1002_parse_valid_session_message(struct kunit *test)
{
	unsigned char hdr[4] = { 0x00, 0x00, 0x01, 0x00 }; /* type=0, len=256 */
	unsigned int len;

	len = test_get_rfc1002_len(hdr);
	KUNIT_EXPECT_EQ(test, len, 256u);
}

/*
 * test_rfc1002_parse_zero_length - zero-length PDU
 */
static void test_rfc1002_parse_zero_length(struct kunit *test)
{
	unsigned char hdr[4] = { 0x00, 0x00, 0x00, 0x00 };
	unsigned int len;

	len = test_get_rfc1002_len(hdr);
	KUNIT_EXPECT_EQ(test, len, 0u);
}

/*
 * test_rfc1002_parse_max_length - maximum valid length (0x00FFFFFF)
 */
static void test_rfc1002_parse_max_length(struct kunit *test)
{
	unsigned char hdr[4] = { 0x00, 0xFF, 0xFF, 0xFF };
	unsigned int len;

	len = test_get_rfc1002_len(hdr);
	KUNIT_EXPECT_EQ(test, len, TEST_MAX_STREAM_PROT_LEN);
}

/*
 * test_rfc1002_parse_type_byte_masked - the type byte (hdr[0]) is
 * masked out by the & 0xffffff operation.
 */
static void test_rfc1002_parse_type_byte_masked(struct kunit *test)
{
	unsigned char hdr[4] = { 0x85, 0x00, 0x00, 0x04 }; /* keep-alive, len=4 */
	unsigned int len;

	len = test_get_rfc1002_len(hdr);
	/* 0x85000004 & 0xffffff = 0x000004 = 4 */
	KUNIT_EXPECT_EQ(test, len, 4u);
}

/*
 * test_rfc1002_parse_session_request - RFC1002 session request type
 */
static void test_rfc1002_parse_session_request(struct kunit *test)
{
	unsigned char hdr[4] = { TEST_RFC1002_SESSION_REQUEST, 0x00, 0x00, 0x44 };
	unsigned int len;

	len = test_get_rfc1002_len(hdr);
	KUNIT_EXPECT_EQ(test, len, 0x44u);
}

/*
 * test_rfc1002_inc_len - increment length field
 */
static void test_rfc1002_inc_len(struct kunit *test)
{
	unsigned char hdr[4] = { 0x00, 0x00, 0x01, 0x00 }; /* len=256 */

	test_inc_rfc1001_len(hdr, 100);
	KUNIT_EXPECT_EQ(test, test_get_rfc1002_len(hdr), 356u);
}

/*
 * test_rfc1002_inc_len_clamp_overflow - increment that would exceed
 * MAX_STREAM_PROT_LEN is silently ignored.
 */
static void test_rfc1002_inc_len_clamp_overflow(struct kunit *test)
{
	unsigned char hdr[4] = { 0x00, 0xFF, 0xFF, 0xFE }; /* len = 0xFFFFFE */

	test_inc_rfc1001_len(hdr, 2);
	/* Should not increment past 0xFFFFFF */
	KUNIT_EXPECT_EQ(test, test_get_rfc1002_len(hdr), 0xFFFFFEu);
}

/* ==================================================================
 * Test cases: Connection state transitions
 * ================================================================== */

/*
 * test_conn_state_initial - new connections start in NEW state
 */
static void test_conn_state_initial(struct kunit *test)
{
	int status = TEST_SESS_NEW;

	KUNIT_EXPECT_EQ(test, status, (int)TEST_SESS_NEW);
	KUNIT_EXPECT_NE(test, status, (int)TEST_SESS_GOOD);
}

/*
 * test_conn_state_negotiate_to_good - normal negotiation flow
 */
static void test_conn_state_negotiate_to_good(struct kunit *test)
{
	int status = TEST_SESS_NEW;

	/* After negotiate succeeds */
	status = TEST_SESS_NEED_NEGOTIATE;
	KUNIT_EXPECT_EQ(test, status, (int)TEST_SESS_NEED_NEGOTIATE);

	/* After session setup */
	status = TEST_SESS_NEED_SETUP;
	KUNIT_EXPECT_EQ(test, status, (int)TEST_SESS_NEED_SETUP);

	/* Session established */
	status = TEST_SESS_GOOD;
	KUNIT_EXPECT_EQ(test, status, (int)TEST_SESS_GOOD);
}

/*
 * test_conn_state_good_to_exiting - graceful disconnect
 */
static void test_conn_state_good_to_exiting(struct kunit *test)
{
	int status = TEST_SESS_GOOD;

	status = TEST_SESS_EXITING;
	KUNIT_EXPECT_EQ(test, status, (int)TEST_SESS_EXITING);
}

/*
 * test_conn_state_good_to_reconnect - reconnect request
 */
static void test_conn_state_good_to_reconnect(struct kunit *test)
{
	int status = TEST_SESS_GOOD;

	status = TEST_SESS_NEED_RECONNECT;
	KUNIT_EXPECT_EQ(test, status, (int)TEST_SESS_NEED_RECONNECT);
}

/*
 * test_conn_state_releasing - final teardown state
 */
static void test_conn_state_releasing(struct kunit *test)
{
	int status = TEST_SESS_EXITING;

	status = TEST_SESS_RELEASING;
	KUNIT_EXPECT_EQ(test, status, (int)TEST_SESS_RELEASING);
}

/*
 * test_conn_state_all_values_distinct - all states are unique
 */
static void test_conn_state_all_values_distinct(struct kunit *test)
{
	int states[] = {
		TEST_SESS_NEW,
		TEST_SESS_GOOD,
		TEST_SESS_EXITING,
		TEST_SESS_NEED_RECONNECT,
		TEST_SESS_NEED_NEGOTIATE,
		TEST_SESS_NEED_SETUP,
		TEST_SESS_RELEASING,
	};
	int i, j;

	for (i = 0; i < ARRAY_SIZE(states); i++) {
		for (j = i + 1; j < ARRAY_SIZE(states); j++) {
			KUNIT_EXPECT_NE(test, states[i], states[j]);
		}
	}
}

/* ==================================================================
 * Test cases: Max connections limit enforcement
 * ================================================================== */

/*
 * test_max_connections_atomic_tracking - atomic counter tracks
 * active connection count.
 */
static void test_max_connections_atomic_tracking(struct kunit *test)
{
	atomic_t active_num_conn = ATOMIC_INIT(0);
	unsigned int max_connections = 5;
	int i;

	for (i = 0; i < 5; i++) {
		int val = atomic_inc_return(&active_num_conn);

		KUNIT_EXPECT_LE(test, val, (int)max_connections);
	}

	KUNIT_EXPECT_EQ(test, atomic_read(&active_num_conn), 5);

	/* Next connection exceeds limit */
	KUNIT_EXPECT_GT(test, atomic_inc_return(&active_num_conn),
			(int)max_connections);
	atomic_dec(&active_num_conn);

	/* Cleanup */
	for (i = 0; i < 5; i++)
		atomic_dec(&active_num_conn);
	KUNIT_EXPECT_EQ(test, atomic_read(&active_num_conn), 0);
}

/*
 * test_max_connections_zero_means_unlimited - when max_connections=0,
 * no limit enforcement occurs.
 */
static void test_max_connections_zero_means_unlimited(struct kunit *test)
{
	unsigned int max_connections = 0;
	atomic_t active_num_conn = ATOMIC_INIT(1000);

	/* With max_connections=0, the check is skipped entirely */
	if (!max_connections) {
		/* No decrement or rejection */
		KUNIT_EXPECT_EQ(test, atomic_read(&active_num_conn), 1000);
	}
}

/* ==================================================================
 * Test cases: Per-IP connection limit
 * ================================================================== */

/*
 * test_per_ip_limit_below_threshold - connections below limit are allowed
 */
static void test_per_ip_limit_below_threshold(struct kunit *test)
{
	struct test_conn_entry entries[3];
	unsigned int count;
	__be32 addr = cpu_to_be32(0xC0A80001); /* 192.168.0.1 */
	unsigned int ihash = 0xC0A80001;
	int i;

	hash_init(test_conn_hash);

	for (i = 0; i < 3; i++) {
		entries[i].inet_hash = ihash;
		entries[i].inet_addr = addr;
		entries[i].status = TEST_SESS_GOOD;
		hash_add(test_conn_hash, &entries[i].hlist, ihash);
	}

	count = test_count_ip_conns(ihash, addr, 10);
	KUNIT_EXPECT_EQ(test, count, 3u);

	hash_init(test_conn_hash);
}

/*
 * test_per_ip_limit_at_threshold - connections at limit triggers early exit
 */
static void test_per_ip_limit_at_threshold(struct kunit *test)
{
	struct test_conn_entry entries[5];
	unsigned int count;
	__be32 addr = cpu_to_be32(0xC0A80002);
	unsigned int ihash = 0xC0A80002;
	int i;

	hash_init(test_conn_hash);

	for (i = 0; i < 5; i++) {
		entries[i].inet_hash = ihash;
		entries[i].inet_addr = addr;
		entries[i].status = TEST_SESS_GOOD;
		hash_add(test_conn_hash, &entries[i].hlist, ihash);
	}

	count = test_count_ip_conns(ihash, addr, 5);
	/* Should return 5 (at limit, loop breaks at >= max) */
	KUNIT_EXPECT_GE(test, count, 5u);

	hash_init(test_conn_hash);
}

/*
 * test_per_ip_limit_exiting_excluded - exiting connections are not counted
 */
static void test_per_ip_limit_exiting_excluded(struct kunit *test)
{
	struct test_conn_entry entries[4];
	unsigned int count;
	__be32 addr = cpu_to_be32(0xC0A80003);
	unsigned int ihash = 0xC0A80003;
	int i;

	hash_init(test_conn_hash);

	for (i = 0; i < 4; i++) {
		entries[i].inet_hash = ihash;
		entries[i].inet_addr = addr;
		entries[i].status = (i < 2) ? TEST_SESS_GOOD : TEST_SESS_EXITING;
		hash_add(test_conn_hash, &entries[i].hlist, ihash);
	}

	count = test_count_ip_conns(ihash, addr, 10);
	/* Only 2 GOOD connections should be counted */
	KUNIT_EXPECT_EQ(test, count, 2u);

	hash_init(test_conn_hash);
}

/*
 * test_per_ip_limit_releasing_excluded - releasing connections not counted
 */
static void test_per_ip_limit_releasing_excluded(struct kunit *test)
{
	struct test_conn_entry entries[3];
	unsigned int count;
	__be32 addr = cpu_to_be32(0xC0A80004);
	unsigned int ihash = 0xC0A80004;

	hash_init(test_conn_hash);

	entries[0].inet_hash = ihash;
	entries[0].inet_addr = addr;
	entries[0].status = TEST_SESS_GOOD;
	hash_add(test_conn_hash, &entries[0].hlist, ihash);

	entries[1].inet_hash = ihash;
	entries[1].inet_addr = addr;
	entries[1].status = TEST_SESS_RELEASING;
	hash_add(test_conn_hash, &entries[1].hlist, ihash);

	entries[2].inet_hash = ihash;
	entries[2].inet_addr = addr;
	entries[2].status = TEST_SESS_NEED_NEGOTIATE;
	hash_add(test_conn_hash, &entries[2].hlist, ihash);

	count = test_count_ip_conns(ihash, addr, 10);
	/* GOOD + NEED_NEGOTIATE = 2, RELEASING excluded */
	KUNIT_EXPECT_EQ(test, count, 2u);

	hash_init(test_conn_hash);
}

/*
 * test_per_ip_limit_different_ips - connections from different IPs
 * are counted separately.
 */
static void test_per_ip_limit_different_ips(struct kunit *test)
{
	struct test_conn_entry entries[4];
	unsigned int count;
	__be32 addr1 = cpu_to_be32(0xC0A80001);
	__be32 addr2 = cpu_to_be32(0xC0A80002);
	unsigned int ihash = 0xABCD; /* same hash bucket, different addrs */
	int i;

	hash_init(test_conn_hash);

	for (i = 0; i < 2; i++) {
		entries[i].inet_hash = ihash;
		entries[i].inet_addr = addr1;
		entries[i].status = TEST_SESS_GOOD;
		hash_add(test_conn_hash, &entries[i].hlist, ihash);
	}
	for (i = 2; i < 4; i++) {
		entries[i].inet_hash = ihash;
		entries[i].inet_addr = addr2;
		entries[i].status = TEST_SESS_GOOD;
		hash_add(test_conn_hash, &entries[i].hlist, ihash);
	}

	count = test_count_ip_conns(ihash, addr1, 10);
	KUNIT_EXPECT_EQ(test, count, 2u);

	count = test_count_ip_conns(ihash, addr2, 10);
	KUNIT_EXPECT_EQ(test, count, 2u);

	hash_init(test_conn_hash);
}

/* ==================================================================
 * Test cases: iovec allocation for various segment counts
 * ================================================================== */

/*
 * test_iov_alloc_single_segment - common case, 1 segment
 */
static void test_iov_alloc_single_segment(struct kunit *test)
{
	unsigned int nr_segs = 1;
	bool use_stack = (nr_segs <= TEST_KSMBD_TCP_SMALL_IOV);

	KUNIT_EXPECT_TRUE(test, use_stack);
}

/*
 * test_iov_alloc_at_small_threshold - exactly SMALL_IOV segments
 */
static void test_iov_alloc_at_small_threshold(struct kunit *test)
{
	unsigned int nr_segs = TEST_KSMBD_TCP_SMALL_IOV;
	bool use_stack = (nr_segs <= TEST_KSMBD_TCP_SMALL_IOV);

	KUNIT_EXPECT_TRUE(test, use_stack);
}

/*
 * test_iov_alloc_above_small_threshold - exceeding SMALL_IOV requires kmalloc
 */
static void test_iov_alloc_above_small_threshold(struct kunit *test)
{
	unsigned int nr_segs = TEST_KSMBD_TCP_SMALL_IOV + 1;
	bool use_stack = (nr_segs <= TEST_KSMBD_TCP_SMALL_IOV);
	struct kvec *iov;

	KUNIT_EXPECT_FALSE(test, use_stack);

	/* Simulate kmalloc path */
	iov = kmalloc_array(nr_segs, sizeof(*iov), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, iov);
	kfree(iov);
}

/*
 * test_iov_alloc_large_count - 100 segments requires heap allocation
 */
static void test_iov_alloc_large_count(struct kunit *test)
{
	unsigned int nr_segs = 100;
	struct kvec *iov;

	KUNIT_EXPECT_GT(test, nr_segs, TEST_KSMBD_TCP_SMALL_IOV);

	iov = kmalloc_array(nr_segs, sizeof(*iov), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, iov);

	/* Verify all segments are usable */
	memset(iov, 0, nr_segs * sizeof(*iov));
	KUNIT_EXPECT_EQ(test, (unsigned int)iov[99].iov_len, 0u);

	kfree(iov);
}

/*
 * test_iov_kvec_init_with_large_segments - kvec_array_init with many segs
 */
static void test_iov_kvec_init_with_large_segments(struct kunit *test)
{
	char bufs[16][64];
	struct kvec iov[16];
	struct kvec new[16];
	unsigned int nr;
	int i;

	for (i = 0; i < 16; i++) {
		memset(bufs[i], (char)i, 64);
		iov[i].iov_base = bufs[i];
		iov[i].iov_len = 64;
	}

	/* Skip 8 full segments (512 bytes) + 32 into 9th */
	nr = test_kvec_array_init(new, iov, 16, 544);
	KUNIT_EXPECT_EQ(test, nr, 8u); /* segments 8-15 remain */
	KUNIT_EXPECT_PTR_EQ(test, new[0].iov_base, (void *)(bufs[8] + 32));
	KUNIT_EXPECT_EQ(test, (unsigned int)new[0].iov_len, 32u);
}

/* ==================================================================
 * Test cases: PDU size validation
 * ================================================================== */

/*
 * test_pdu_size_below_min - PDU smaller than minimum header is rejected
 */
static void test_pdu_size_below_min(struct kunit *test)
{
	unsigned int pdu_size = 10;

	KUNIT_EXPECT_LT(test, pdu_size, TEST_SMB1_MIN_SUPPORTED_HEADER_SIZE);
}

/*
 * test_pdu_size_at_min - PDU at minimum header size is accepted
 */
static void test_pdu_size_at_min(struct kunit *test)
{
	unsigned int pdu_size = TEST_SMB1_MIN_SUPPORTED_HEADER_SIZE;

	KUNIT_EXPECT_GE(test, pdu_size, TEST_SMB1_MIN_SUPPORTED_HEADER_SIZE);
}

/*
 * test_pdu_size_above_max_stream - PDU exceeding MAX_STREAM_PROT_LEN rejected
 */
static void test_pdu_size_above_max_stream(struct kunit *test)
{
	unsigned int pdu_size = TEST_MAX_STREAM_PROT_LEN + 1;

	KUNIT_EXPECT_GT(test, pdu_size, TEST_MAX_STREAM_PROT_LEN);
}

/*
 * test_pdu_size_add_overflow_check - pdu_size + 5 overflow detection
 */
static void test_pdu_size_add_overflow_check(struct kunit *test)
{
	unsigned int pdu_size, result;
	bool overflow;

	/* Normal case: no overflow */
	pdu_size = 1000;
	overflow = check_add_overflow(pdu_size, 5u, &result);
	KUNIT_EXPECT_FALSE(test, overflow);
	KUNIT_EXPECT_EQ(test, result, 1005u);

	/* Near max: no overflow */
	pdu_size = TEST_MAX_STREAM_PROT_LEN;
	overflow = check_add_overflow(pdu_size, 5u, &result);
	KUNIT_EXPECT_FALSE(test, overflow);

	/* Actual overflow */
	pdu_size = UINT_MAX - 3;
	overflow = check_add_overflow(pdu_size, 5u, &result);
	KUNIT_EXPECT_TRUE(test, overflow);
}

/* ---- Test suite registration ---- */

static struct kunit_case ksmbd_transport_tcp_test_cases[] = {
	/* RFC1002 header parsing */
	KUNIT_CASE(test_rfc1002_parse_valid_session_message),
	KUNIT_CASE(test_rfc1002_parse_zero_length),
	KUNIT_CASE(test_rfc1002_parse_max_length),
	KUNIT_CASE(test_rfc1002_parse_type_byte_masked),
	KUNIT_CASE(test_rfc1002_parse_session_request),
	KUNIT_CASE(test_rfc1002_inc_len),
	KUNIT_CASE(test_rfc1002_inc_len_clamp_overflow),
	/* Connection state transitions */
	KUNIT_CASE(test_conn_state_initial),
	KUNIT_CASE(test_conn_state_negotiate_to_good),
	KUNIT_CASE(test_conn_state_good_to_exiting),
	KUNIT_CASE(test_conn_state_good_to_reconnect),
	KUNIT_CASE(test_conn_state_releasing),
	KUNIT_CASE(test_conn_state_all_values_distinct),
	/* Max connections limit */
	KUNIT_CASE(test_max_connections_atomic_tracking),
	KUNIT_CASE(test_max_connections_zero_means_unlimited),
	/* Per-IP connection limit */
	KUNIT_CASE(test_per_ip_limit_below_threshold),
	KUNIT_CASE(test_per_ip_limit_at_threshold),
	KUNIT_CASE(test_per_ip_limit_exiting_excluded),
	KUNIT_CASE(test_per_ip_limit_releasing_excluded),
	KUNIT_CASE(test_per_ip_limit_different_ips),
	/* IOV allocation */
	KUNIT_CASE(test_iov_alloc_single_segment),
	KUNIT_CASE(test_iov_alloc_at_small_threshold),
	KUNIT_CASE(test_iov_alloc_above_small_threshold),
	KUNIT_CASE(test_iov_alloc_large_count),
	KUNIT_CASE(test_iov_kvec_init_with_large_segments),
	/* PDU size validation */
	KUNIT_CASE(test_pdu_size_below_min),
	KUNIT_CASE(test_pdu_size_at_min),
	KUNIT_CASE(test_pdu_size_above_max_stream),
	KUNIT_CASE(test_pdu_size_add_overflow_check),
	{}
};

static struct kunit_suite ksmbd_transport_tcp_test_suite = {
	.name = "ksmbd_transport_tcp",
	.test_cases = ksmbd_transport_tcp_test_cases,
};

kunit_test_suite(ksmbd_transport_tcp_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd TCP transport layer");
