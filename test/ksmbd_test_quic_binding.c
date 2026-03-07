// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for QUIC peer identity binding (transport_quic.c)
 *
 *   These tests verify the session hijack prevention logic that binds
 *   a client identity (IP + port) at QUIC connection establishment
 *   and validates it on every subsequent request.
 *
 *   No real QUIC/network stack is needed -- the tests exercise the
 *   pure-logic quic_bind_peer_identity() and quic_validate_peer_identity()
 *   functions using synthetic ksmbd_quic_conn_info structs.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/in6.h>

#include "transport_quic.h"

/* ──────────────────────────────────────────────────────────
 * Helper: build a ksmbd_quic_conn_info with IPv4 address
 * ────────────────────────────────────────────────────────── */
static struct ksmbd_quic_conn_info make_ipv4_conn_info(__be32 addr, __u16 port)
{
	struct ksmbd_quic_conn_info info;

	memset(&info, 0, sizeof(info));
	info.addr_family = AF_INET;
	info.client_port = port;
	info.flags = KSMBD_QUIC_F_TLS_VERIFIED;
	info.client_addr.v4 = addr;
	return info;
}

/* ──────────────────────────────────────────────────────────
 * Helper: build a ksmbd_quic_conn_info with IPv6 address
 * ────────────────────────────────────────────────────────── */
static struct ksmbd_quic_conn_info make_ipv6_conn_info(const __u8 *v6addr,
						       __u16 port)
{
	struct ksmbd_quic_conn_info info;

	memset(&info, 0, sizeof(info));
	info.addr_family = AF_INET6;
	info.client_port = port;
	info.flags = KSMBD_QUIC_F_TLS_VERIFIED;
	memcpy(info.client_addr.v6, v6addr, 16);
	return info;
}

/* ──────────────────────────────────────────────────────────
 * Test 1: peer identity struct is zeroed on init
 * ────────────────────────────────────────────────────────── */
static void test_peer_identity_init_zeroed(struct kunit *test)
{
	struct quic_peer_identity id;

	memset(&id, 0, sizeof(id));

	KUNIT_EXPECT_EQ(test, id.addr_family, (__u16)0);
	KUNIT_EXPECT_EQ(test, id.client_port, (__u16)0);
	KUNIT_EXPECT_FALSE(test, id.bound);
	KUNIT_EXPECT_FALSE(test, id.has_cert_hash);
}

/* ──────────────────────────────────────────────────────────
 * Test 2: bind stores IPv4 address correctly
 * ────────────────────────────────────────────────────────── */
static void test_bind_stores_ipv4_address(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;
	__be32 addr = cpu_to_be32(0xC0A80164); /* 192.168.1.100 */

	info = make_ipv4_conn_info(addr, 12345);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_TRUE(test, id.bound);
	KUNIT_EXPECT_EQ(test, id.addr_family, (__u16)AF_INET);
	KUNIT_EXPECT_EQ(test, id.client_port, (__u16)12345);
	KUNIT_EXPECT_EQ(test, id.client_addr.v4, addr);
}

/* ──────────────────────────────────────────────────────────
 * Test 3: bind stores IPv6 address correctly
 * ────────────────────────────────────────────────────────── */
static void test_bind_stores_ipv6_address(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;
	__u8 v6[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
	};

	info = make_ipv6_conn_info(v6, 443);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_TRUE(test, id.bound);
	KUNIT_EXPECT_EQ(test, id.addr_family, (__u16)AF_INET6);
	KUNIT_EXPECT_EQ(test, id.client_port, (__u16)443);
	KUNIT_EXPECT_EQ(test, memcmp(id.client_addr.v6, v6, 16), 0);
}

/* ──────────────────────────────────────────────────────────
 * Test 4: same IPv4 address validates successfully
 * ────────────────────────────────────────────────────────── */
static void test_validate_same_ipv4_succeeds(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;
	__be32 addr = cpu_to_be32(0x0A000001); /* 10.0.0.1 */

	info = make_ipv4_conn_info(addr, 8080);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info), 0);
}

/* ──────────────────────────────────────────────────────────
 * Test 5: same IPv6 address validates successfully
 * ────────────────────────────────────────────────────────── */
static void test_validate_same_ipv6_succeeds(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;
	__u8 v6[16] = {
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x1a, 0x2b, 0xff, 0xfe, 0x3c, 0x4d, 0x5e
	};

	info = make_ipv6_conn_info(v6, 9090);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info), 0);
}

/* ──────────────────────────────────────────────────────────
 * Test 6: different IPv4 address returns EACCES
 * ────────────────────────────────────────────────────────── */
static void test_validate_different_ipv4_fails(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info, spoofed;
	__be32 real_addr = cpu_to_be32(0x0A000001);
	__be32 fake_addr = cpu_to_be32(0x0A000002);

	info = make_ipv4_conn_info(real_addr, 8080);
	quic_bind_peer_identity(&id, &info);

	spoofed = make_ipv4_conn_info(fake_addr, 8080);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &spoofed),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 7: different IPv6 address returns EACCES
 * ────────────────────────────────────────────────────────── */
static void test_validate_different_ipv6_fails(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info, spoofed;
	__u8 real_v6[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
	};
	__u8 fake_v6[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
	};

	info = make_ipv6_conn_info(real_v6, 443);
	quic_bind_peer_identity(&id, &info);

	spoofed = make_ipv6_conn_info(fake_v6, 443);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &spoofed),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 8: different port returns EACCES
 * ────────────────────────────────────────────────────────── */
static void test_validate_different_port_fails(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info, spoofed;
	__be32 addr = cpu_to_be32(0x0A000001);

	info = make_ipv4_conn_info(addr, 8080);
	quic_bind_peer_identity(&id, &info);

	spoofed = make_ipv4_conn_info(addr, 9090);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &spoofed),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 9: NULL stored identity returns EACCES
 * ────────────────────────────────────────────────────────── */
static void test_validate_null_stored_fails(struct kunit *test)
{
	struct ksmbd_quic_conn_info info;

	info = make_ipv4_conn_info(cpu_to_be32(0x0A000001), 8080);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(NULL, &info),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 10: NULL current_info returns EACCES
 * ────────────────────────────────────────────────────────── */
static void test_validate_null_current_fails(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;

	info = make_ipv4_conn_info(cpu_to_be32(0x0A000001), 8080);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, NULL),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 11: unbound identity (not yet initialized) returns EACCES
 * ────────────────────────────────────────────────────────── */
static void test_validate_unbound_identity_fails(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;

	memset(&id, 0, sizeof(id));
	/* id.bound is false */

	info = make_ipv4_conn_info(cpu_to_be32(0x0A000001), 8080);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 12: address family mismatch (IPv4 stored, IPv6 presented)
 * ────────────────────────────────────────────────────────── */
static void test_validate_family_mismatch_fails(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info4, info6;
	__u8 v6[16] = { 0 };

	info4 = make_ipv4_conn_info(cpu_to_be32(0x0A000001), 8080);
	quic_bind_peer_identity(&id, &info4);

	info6 = make_ipv6_conn_info(v6, 8080);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info6),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 13: multiple sequential validations with same address all pass
 * ────────────────────────────────────────────────────────── */
static void test_validate_multiple_same_address_pass(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;
	__be32 addr = cpu_to_be32(0xC0A80101);
	int i;

	info = make_ipv4_conn_info(addr, 5555);
	quic_bind_peer_identity(&id, &info);

	for (i = 0; i < 100; i++)
		KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info),
				0);
}

/* ──────────────────────────────────────────────────────────
 * Test 14: address spoof after N successful requests is detected
 * ────────────────────────────────────────────────────────── */
static void test_validate_spoof_after_n_requests(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info, spoofed;
	__be32 real = cpu_to_be32(0xC0A80101);
	__be32 fake = cpu_to_be32(0xC0A80199);
	int i;

	info = make_ipv4_conn_info(real, 5555);
	quic_bind_peer_identity(&id, &info);

	/* 50 successful validations */
	for (i = 0; i < 50; i++)
		KUNIT_ASSERT_EQ(test, quic_validate_peer_identity(&id, &info),
				0);

	/* Then attacker spoofs address */
	spoofed = make_ipv4_conn_info(fake, 5555);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &spoofed),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 15: bind clears previous state (rebind scenario)
 * ────────────────────────────────────────────────────────── */
static void test_bind_clears_previous_state(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info1, info2;
	__be32 addr1 = cpu_to_be32(0x0A000001);
	__be32 addr2 = cpu_to_be32(0x0A000002);

	info1 = make_ipv4_conn_info(addr1, 1111);
	quic_bind_peer_identity(&id, &info1);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info1), 0);

	/* Rebind to different address (simulates new connection) */
	info2 = make_ipv4_conn_info(addr2, 2222);
	quic_bind_peer_identity(&id, &info2);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info2), 0);

	/* Old address should now fail */
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info1),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 16: IPv4 zero address (0.0.0.0) is a valid binding
 * ────────────────────────────────────────────────────────── */
static void test_validate_ipv4_zero_address(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;

	info = make_ipv4_conn_info(0, 8080);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info), 0);
}

/* ──────────────────────────────────────────────────────────
 * Test 17: IPv6 all-zeros (::) is a valid binding
 * ────────────────────────────────────────────────────────── */
static void test_validate_ipv6_zero_address(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;
	__u8 zero_v6[16] = { 0 };

	info = make_ipv6_conn_info(zero_v6, 443);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info), 0);
}

/* ──────────────────────────────────────────────────────────
 * Test 18: port zero is a valid binding (ephemeral port)
 * ────────────────────────────────────────────────────────── */
static void test_validate_port_zero(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;

	info = make_ipv4_conn_info(cpu_to_be32(0x0A000001), 0);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info), 0);
}

/* ──────────────────────────────────────────────────────────
 * Test 19: IPv4 loopback address binding and validation
 * ────────────────────────────────────────────────────────── */
static void test_validate_ipv4_loopback(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info, spoofed;
	__be32 loopback = cpu_to_be32(INADDR_LOOPBACK);

	info = make_ipv4_conn_info(loopback, 12345);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info), 0);

	/* Different loopback variant should fail */
	spoofed = make_ipv4_conn_info(cpu_to_be32(0x7F000002), 12345);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &spoofed),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 20: IPv6 loopback (::1) binding and validation
 * ────────────────────────────────────────────────────────── */
static void test_validate_ipv6_loopback(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info, spoofed;
	__u8 lo6[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
			 0, 0, 0, 0, 0, 0, 0, 1 };
	__u8 lo6_diff[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
			      0, 0, 0, 0, 0, 0, 0, 2 };

	info = make_ipv6_conn_info(lo6, 443);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info), 0);

	spoofed = make_ipv6_conn_info(lo6_diff, 443);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &spoofed),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 21: cert_hash field starts zeroed after bind
 * ────────────────────────────────────────────────────────── */
static void test_bind_cert_hash_zeroed(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;
	__u8 zero_hash[KSMBD_QUIC_CERT_HASH_SIZE] = { 0 };

	info = make_ipv4_conn_info(cpu_to_be32(0x0A000001), 8080);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_FALSE(test, id.has_cert_hash);
	KUNIT_EXPECT_EQ(test, memcmp(id.cert_hash, zero_hash,
				     KSMBD_QUIC_CERT_HASH_SIZE), 0);
}

/* ──────────────────────────────────────────────────────────
 * Test 22: proxy consistency - same info validates throughout session
 * ────────────────────────────────────────────────────────── */
static void test_proxy_consistency_same_info(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;
	__be32 addr = cpu_to_be32(0xAC100164); /* 172.16.1.100 */
	int i;

	info = make_ipv4_conn_info(addr, 49152);
	quic_bind_peer_identity(&id, &info);

	/* Simulate a long-lived connection: 1000 request validations */
	for (i = 0; i < 1000; i++)
		KUNIT_ASSERT_EQ(test, quic_validate_peer_identity(&id, &info),
				0);
}

/* ──────────────────────────────────────────────────────────
 * Test 23: IPv6 address differs only in high bits - detected
 * ────────────────────────────────────────────────────────── */
static void test_validate_ipv6_high_bits_differ(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info, spoofed;
	__u8 v6_real[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
	};
	/* Same lower 32 bits but different upper 96 bits */
	__u8 v6_fake[16] = {
		0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
	};

	info = make_ipv6_conn_info(v6_real, 443);
	quic_bind_peer_identity(&id, &info);

	spoofed = make_ipv6_conn_info(v6_fake, 443);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &spoofed),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 24: both NULL pointers returns EACCES
 * ────────────────────────────────────────────────────────── */
static void test_validate_both_null_fails(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(NULL, NULL),
			-EACCES);
}

/* ──────────────────────────────────────────────────────────
 * Test 25: bind sets bound=true, validate succeeds
 * ────────────────────────────────────────────────────────── */
static void test_bind_sets_bound_flag(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info;

	memset(&id, 0xFF, sizeof(id)); /* garbage fill */
	info = make_ipv4_conn_info(cpu_to_be32(0xC0A80001), 1234);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_TRUE(test, id.bound);
	/* Validate works after bind even if struct was garbage before */
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info), 0);
}

/* ──────────────────────────────────────────────────────────
 * Test 26: max port number (65535)
 * ────────────────────────────────────────────────────────── */
static void test_validate_max_port(struct kunit *test)
{
	struct quic_peer_identity id;
	struct ksmbd_quic_conn_info info, diff_port;

	info = make_ipv4_conn_info(cpu_to_be32(0x0A000001), 65535);
	quic_bind_peer_identity(&id, &info);

	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &info), 0);

	diff_port = make_ipv4_conn_info(cpu_to_be32(0x0A000001), 65534);
	KUNIT_EXPECT_EQ(test, quic_validate_peer_identity(&id, &diff_port),
			-EACCES);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_quic_binding_test_cases[] = {
	KUNIT_CASE(test_peer_identity_init_zeroed),
	KUNIT_CASE(test_bind_stores_ipv4_address),
	KUNIT_CASE(test_bind_stores_ipv6_address),
	KUNIT_CASE(test_validate_same_ipv4_succeeds),
	KUNIT_CASE(test_validate_same_ipv6_succeeds),
	KUNIT_CASE(test_validate_different_ipv4_fails),
	KUNIT_CASE(test_validate_different_ipv6_fails),
	KUNIT_CASE(test_validate_different_port_fails),
	KUNIT_CASE(test_validate_null_stored_fails),
	KUNIT_CASE(test_validate_null_current_fails),
	KUNIT_CASE(test_validate_unbound_identity_fails),
	KUNIT_CASE(test_validate_family_mismatch_fails),
	KUNIT_CASE(test_validate_multiple_same_address_pass),
	KUNIT_CASE(test_validate_spoof_after_n_requests),
	KUNIT_CASE(test_bind_clears_previous_state),
	KUNIT_CASE(test_validate_ipv4_zero_address),
	KUNIT_CASE(test_validate_ipv6_zero_address),
	KUNIT_CASE(test_validate_port_zero),
	KUNIT_CASE(test_validate_ipv4_loopback),
	KUNIT_CASE(test_validate_ipv6_loopback),
	KUNIT_CASE(test_bind_cert_hash_zeroed),
	KUNIT_CASE(test_proxy_consistency_same_info),
	KUNIT_CASE(test_validate_ipv6_high_bits_differ),
	KUNIT_CASE(test_validate_both_null_fails),
	KUNIT_CASE(test_bind_sets_bound_flag),
	KUNIT_CASE(test_validate_max_port),
	{}
};

static struct kunit_suite ksmbd_quic_binding_test_suite = {
	.name = "ksmbd_quic_binding",
	.test_cases = ksmbd_quic_binding_test_cases,
};

kunit_test_suite(ksmbd_quic_binding_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd QUIC peer identity binding");
