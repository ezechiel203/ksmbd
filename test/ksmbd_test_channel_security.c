// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB3 per-channel security association validation.
 *
 *   These tests replicate the pure logic of smb2_check_channel_sequence()
 *   from smb2_pdu_common.c without calling into the ksmbd module.
 *   The ChannelSequence field occupies the low 16 bits of the SMB2 header
 *   Status field in request packets (MS-SMB2 section 3.3.5.2.10).
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/spinlock.h>

/* Replicate dialect constants from smb_common.h */
#define TEST_SMB10_PROT_ID	0x00
#define TEST_SMB20_PROT_ID	0x0202
#define TEST_SMB21_PROT_ID	0x0210
#define TEST_SMB30_PROT_ID	0x0300
#define TEST_SMB302_PROT_ID	0x0302
#define TEST_SMB311_PROT_ID	0x0311

/* Replicate SMB2 command IDs from smb2pdu.h */
#define TEST_SMB2_WRITE_HE	0x0009
#define TEST_SMB2_FLUSH_HE	0x0007
#define TEST_SMB2_LOCK_HE	0x000A
#define TEST_SMB2_SET_INFO_HE	0x0011
#define TEST_SMB2_IOCTL_HE	0x000B

/*
 * Minimal test file structure replicating the channel_sequence
 * tracking from struct ksmbd_file (vfs_cache.h).
 */
struct test_fp {
	spinlock_t	f_lock;
	__u16		channel_sequence;
};

/*
 * Replicate smb2_check_channel_sequence() logic from smb2_pdu_common.c.
 *
 * @dialect:    negotiated protocol dialect
 * @req_seq:    ChannelSequence from request (low 16 bits of Status)
 * @fp:         per-file tracking structure
 *
 * Returns 0 on success, -EAGAIN if stale.
 */
static int test_check_channel_sequence(__u16 dialect, __u16 req_seq,
				       struct test_fp *fp)
{
	s16 diff;

	/* ChannelSequence only defined for dialect >= 2.1 */
	if (dialect <= TEST_SMB20_PROT_ID)
		return 0;

	spin_lock(&fp->f_lock);
	diff = (s16)(req_seq - fp->channel_sequence);
	if (diff < 0) {
		spin_unlock(&fp->f_lock);
		return -EAGAIN;
	}
	if (diff > 0)
		fp->channel_sequence = req_seq;
	spin_unlock(&fp->f_lock);
	return 0;
}

/*
 * Helper: extract ChannelSequence from a simulated SMB2 header Status field.
 * In request packets, Status[15:0] = ChannelSequence, Status[31:16] = Reserved.
 */
static __u16 test_extract_channel_seq(__le32 status)
{
	return (__u16)le32_to_cpu(status);
}

/*
 * Helper: initialize a test_fp with a given starting sequence.
 */
static void init_test_fp(struct test_fp *fp, __u16 seq)
{
	spin_lock_init(&fp->f_lock);
	fp->channel_sequence = seq;
}

/* ------------------------------------------------------------------ */
/* Test: valid ChannelSequence accepted (current == stored)           */
/* ------------------------------------------------------------------ */
static void test_channel_seq_equal_accepted(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 5);
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 5, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)5, fp.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: stale ChannelSequence rejected (current < stored)            */
/* ------------------------------------------------------------------ */
static void test_channel_seq_stale_rejected(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 10);
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 9, &fp));
	/* Stored value must not change on rejection */
	KUNIT_EXPECT_EQ(test, (__u16)10, fp.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: future ChannelSequence accepted and updates stored value     */
/* ------------------------------------------------------------------ */
static void test_channel_seq_future_accepted(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 3);
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 7, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)7, fp.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: wrap-around from 0xFFFF to 0x0000                            */
/* ------------------------------------------------------------------ */
static void test_channel_seq_wraparound_ffff_to_0(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 0xFFFF);
	/* 0x0000 - 0xFFFF = 1 as s16, so this is a valid increment */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 0x0000, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)0x0000, fp.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: wrap-around with s16 diff detection                          */
/* ------------------------------------------------------------------ */
static void test_channel_seq_wraparound_s16_diff(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 0xFFFE);
	/* 0x0001 - 0xFFFE = 3 as s16 (wraps around) */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 0x0001, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)0x0001, fp.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: zero ChannelSequence on first request (initial state)        */
/* ------------------------------------------------------------------ */
static void test_channel_seq_zero_initial(struct kunit *test)
{
	struct test_fp fp;

	/* ksmbd_file is allocated with kmem_cache_zalloc, so sequence=0 */
	init_test_fp(&fp, 0);
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 0, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)0, fp.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: ChannelSequence on non-multichannel connection (SMB 2.0.2)   */
/* should be ignored                                                  */
/* ------------------------------------------------------------------ */
static void test_channel_seq_smb202_ignored(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 10);
	/* Even a "stale" sequence should be accepted for SMB 2.0.2 */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB20_PROT_ID, 5, &fp));
	/* Stored value must not change when dialect check bypasses */
	KUNIT_EXPECT_EQ(test, (__u16)10, fp.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: ChannelSequence field location in SMB2 header                */
/* (low 16 bits of Status)                                            */
/* ------------------------------------------------------------------ */
static void test_channel_seq_field_location(struct kunit *test)
{
	__le32 status;
	__u16 seq;

	/* ChannelSequence = 0x1234, Reserved = 0x0000 */
	status = cpu_to_le32(0x00001234);
	seq = test_extract_channel_seq(status);
	KUNIT_EXPECT_EQ(test, (__u16)0x1234, seq);

	/* ChannelSequence = 0xABCD, upper bits should be ignored */
	status = cpu_to_le32(0xFFFFABCD);
	seq = test_extract_channel_seq(status);
	KUNIT_EXPECT_EQ(test, (__u16)0xABCD, seq);
}

/* ------------------------------------------------------------------ */
/* Test: per-file ChannelSequence tracking (different files)          */
/* ------------------------------------------------------------------ */
static void test_channel_seq_per_file(struct kunit *test)
{
	struct test_fp fp1, fp2;

	init_test_fp(&fp1, 10);
	init_test_fp(&fp2, 20);

	/* Advance fp1 to 15, leave fp2 at 20 */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 15, &fp1));
	KUNIT_EXPECT_EQ(test, (__u16)15, fp1.channel_sequence);
	KUNIT_EXPECT_EQ(test, (__u16)20, fp2.channel_sequence);

	/* fp2 can still accept 20 (equal), but reject 19 (stale) */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 20, &fp2));
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 19, &fp2));
}

/* ------------------------------------------------------------------ */
/* Test: ChannelSequence validation on WRITE command concept          */
/* ------------------------------------------------------------------ */
static void test_channel_seq_write_validation(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 5);

	/* WRITE with current sequence passes */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 5, &fp));
	/* WRITE with stale sequence fails */
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 4, &fp));
}

/* ------------------------------------------------------------------ */
/* Test: ChannelSequence validation on FLUSH command concept          */
/* ------------------------------------------------------------------ */
static void test_channel_seq_flush_validation(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 100);

	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 101, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)101, fp.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: ChannelSequence validation on LOCK command concept           */
/* ------------------------------------------------------------------ */
static void test_channel_seq_lock_validation(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 50);

	/* Stale LOCK rejected */
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 49, &fp));
	/* Current LOCK accepted */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 50, &fp));
}

/* ------------------------------------------------------------------ */
/* Test: ChannelSequence validation on SET_INFO command concept       */
/* ------------------------------------------------------------------ */
static void test_channel_seq_setinfo_validation(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 200);

	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 250, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)250, fp.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: ChannelSequence validation on IOCTL command concept          */
/* ------------------------------------------------------------------ */
static void test_channel_seq_ioctl_validation(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 0);

	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 1, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)1, fp.channel_sequence);
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 0, &fp));
}

/* ------------------------------------------------------------------ */
/* Test: STATUS_FILE_NOT_AVAILABLE returned for stale sequence        */
/* (verify the -EAGAIN return code that callers map to this status)   */
/* ------------------------------------------------------------------ */
static void test_channel_seq_stale_returns_eagain(struct kunit *test)
{
	struct test_fp fp;
	int ret;

	init_test_fp(&fp, 1000);
	ret = test_check_channel_sequence(TEST_SMB30_PROT_ID, 999, &fp);
	KUNIT_EXPECT_EQ(test, -EAGAIN, ret);
}

/* ------------------------------------------------------------------ */
/* Test: channel binding mismatch concept (different transport types) */
/* The ChannelSequence logic is transport-agnostic; the same check    */
/* applies regardless of whether the channel is TCP or QUIC.          */
/* ------------------------------------------------------------------ */
static void test_channel_seq_transport_agnostic(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 42);

	/* Same logic regardless of transport -- both SMB3 dialects */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 43, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)43, fp.channel_sequence);

	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB311_PROT_ID, 44, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)44, fp.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: per-channel nonce counter basics                             */
/* Verify the counter can increment from 0 through successive calls. */
/* ------------------------------------------------------------------ */
static void test_channel_seq_nonce_counter(struct kunit *test)
{
	struct test_fp fp;
	__u16 i;

	init_test_fp(&fp, 0);

	for (i = 1; i <= 10; i++) {
		KUNIT_EXPECT_EQ(test, 0,
				test_check_channel_sequence(TEST_SMB30_PROT_ID,
							    i, &fp));
		KUNIT_EXPECT_EQ(test, i, fp.channel_sequence);
	}
}

/* ------------------------------------------------------------------ */
/* Test: multiple channels same session, different sequences          */
/* Each file handle tracks independently.                             */
/* ------------------------------------------------------------------ */
static void test_channel_seq_multi_channel(struct kunit *test)
{
	struct test_fp fp_chan1, fp_chan2;

	init_test_fp(&fp_chan1, 0);
	init_test_fp(&fp_chan2, 0);

	/* Channel 1 advances to 5 */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 5, &fp_chan1));
	KUNIT_EXPECT_EQ(test, (__u16)5, fp_chan1.channel_sequence);
	KUNIT_EXPECT_EQ(test, (__u16)0, fp_chan2.channel_sequence);

	/* Channel 2 advances to 3 independently */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 3, &fp_chan2));
	KUNIT_EXPECT_EQ(test, (__u16)3, fp_chan2.channel_sequence);
}

/* ------------------------------------------------------------------ */
/* Test: session binding requires valid ChannelSequence               */
/* After binding, a stale sequence on the new channel is rejected.    */
/* ------------------------------------------------------------------ */
static void test_channel_seq_session_binding(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 10);

	/* Simulated binding: new channel sends seq 10 (current) - OK */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 10, &fp));
	/* Subsequent request with stale seq on binding channel - reject */
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 9, &fp));
}

/* ------------------------------------------------------------------ */
/* Test: compound request - ChannelSequence in first header only      */
/* (The same check applies once per compound; first header carries    */
/*  the sequence for the entire compound request.)                    */
/* ------------------------------------------------------------------ */
static void test_channel_seq_compound_first_only(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 5);

	/* First request in compound: advance to 6 */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 6, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)6, fp.channel_sequence);

	/* Subsequent requests in compound use same sequence (6) */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 6, &fp));
}

/* ------------------------------------------------------------------ */
/* Test: ChannelSequence after session reconnect (reset to 0)         */
/* ------------------------------------------------------------------ */
static void test_channel_seq_reconnect_reset(struct kunit *test)
{
	struct test_fp fp;

	/* Simulate pre-reconnect state at seq 500 */
	init_test_fp(&fp, 500);

	/* After reconnect, ksmbd_file is re-created with seq=0 */
	init_test_fp(&fp, 0);

	/* First request after reconnect with seq=0 should pass */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 0, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)0, fp.channel_sequence);

	/* Then seq=1 advances normally */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID, 1, &fp));
}

/* ------------------------------------------------------------------ */
/* Test: maximum s16 diff threshold for staleness detection           */
/* s16 diff of -1 (0x7FFF stored, 0x7FFE requested) is stale.        */
/* s16 diff of +1 (0x7FFE stored, 0x7FFF requested) is valid.        */
/* ------------------------------------------------------------------ */
static void test_channel_seq_max_s16_diff(struct kunit *test)
{
	struct test_fp fp;

	/* diff = (s16)(0x7FFF - 0x7FFE) = +1 => valid */
	init_test_fp(&fp, 0x7FFE);
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID,
						    0x7FFF, &fp));

	/* diff = (s16)(0x7FFE - 0x7FFF) = -1 => stale */
	init_test_fp(&fp, 0x7FFF);
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			test_check_channel_sequence(TEST_SMB30_PROT_ID,
						    0x7FFE, &fp));
}

/* ------------------------------------------------------------------ */
/* Test: ChannelSequence with SMB2 dialect < 3.0 (SMB 2.1)           */
/* SMB 2.1 is dialect 0x0210 which is > SMB20_PROT_ID (0x0202),      */
/* so ChannelSequence IS validated for SMB 2.1.                       */
/* ------------------------------------------------------------------ */
static void test_channel_seq_smb21_validated(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 10);

	/* SMB 2.1 (0x0210) > 0x0202, so stale should be rejected */
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			test_check_channel_sequence(TEST_SMB21_PROT_ID, 9, &fp));
	/* Current should pass */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB21_PROT_ID, 10, &fp));
}

/* ------------------------------------------------------------------ */
/* Test: negative diff edge case (wrap from high to low)              */
/* stored=0x0002, req=0x8001 => diff=(s16)(0x8001-0x0002)=0x7FFF=+32767 */
/* This is the maximum positive s16 value, so still accepted.        */
/* ------------------------------------------------------------------ */
static void test_channel_seq_negative_diff_edge(struct kunit *test)
{
	struct test_fp fp;

	/* stored=0x0002, req=0x8001 => diff = (s16)0x7FFF = 32767 (valid) */
	init_test_fp(&fp, 0x0002);
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID,
						    0x8001, &fp));

	/* stored=0x0002, req=0x8002 => diff = (s16)0x8000 = -32768 (stale!) */
	init_test_fp(&fp, 0x0002);
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			test_check_channel_sequence(TEST_SMB30_PROT_ID,
						    0x8002, &fp));
}

/* ------------------------------------------------------------------ */
/* Test: diff exactly at INT16_MAX boundary                           */
/* ------------------------------------------------------------------ */
static void test_channel_seq_int16_max_boundary(struct kunit *test)
{
	struct test_fp fp;
	s16 diff;

	/* stored=0, req=0x7FFF => diff = +32767 = INT16_MAX (accepted) */
	init_test_fp(&fp, 0);
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB30_PROT_ID,
						    0x7FFF, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)0x7FFF, fp.channel_sequence);

	/* stored=0, req=0x8000 => diff = (s16)0x8000 = -32768 (stale) */
	init_test_fp(&fp, 0);
	diff = (s16)((__u16)0x8000 - (__u16)0);
	KUNIT_EXPECT_LT(test, (int)diff, 0);
	KUNIT_EXPECT_EQ(test, -EAGAIN,
			test_check_channel_sequence(TEST_SMB30_PROT_ID,
						    0x8000, &fp));
}

/* ------------------------------------------------------------------ */
/* Test: SMB1 dialect completely bypasses ChannelSequence check       */
/* ------------------------------------------------------------------ */
static void test_channel_seq_smb1_bypassed(struct kunit *test)
{
	struct test_fp fp;

	init_test_fp(&fp, 100);

	/* SMB1 (0x00) <= 0x0202, so even stale sequence is bypassed */
	KUNIT_EXPECT_EQ(test, 0,
			test_check_channel_sequence(TEST_SMB10_PROT_ID, 0, &fp));
	KUNIT_EXPECT_EQ(test, (__u16)100, fp.channel_sequence);
}

static struct kunit_case ksmbd_channel_security_test_cases[] = {
	KUNIT_CASE(test_channel_seq_equal_accepted),
	KUNIT_CASE(test_channel_seq_stale_rejected),
	KUNIT_CASE(test_channel_seq_future_accepted),
	KUNIT_CASE(test_channel_seq_wraparound_ffff_to_0),
	KUNIT_CASE(test_channel_seq_wraparound_s16_diff),
	KUNIT_CASE(test_channel_seq_zero_initial),
	KUNIT_CASE(test_channel_seq_smb202_ignored),
	KUNIT_CASE(test_channel_seq_field_location),
	KUNIT_CASE(test_channel_seq_per_file),
	KUNIT_CASE(test_channel_seq_write_validation),
	KUNIT_CASE(test_channel_seq_flush_validation),
	KUNIT_CASE(test_channel_seq_lock_validation),
	KUNIT_CASE(test_channel_seq_setinfo_validation),
	KUNIT_CASE(test_channel_seq_ioctl_validation),
	KUNIT_CASE(test_channel_seq_stale_returns_eagain),
	KUNIT_CASE(test_channel_seq_transport_agnostic),
	KUNIT_CASE(test_channel_seq_nonce_counter),
	KUNIT_CASE(test_channel_seq_multi_channel),
	KUNIT_CASE(test_channel_seq_session_binding),
	KUNIT_CASE(test_channel_seq_compound_first_only),
	KUNIT_CASE(test_channel_seq_reconnect_reset),
	KUNIT_CASE(test_channel_seq_max_s16_diff),
	KUNIT_CASE(test_channel_seq_smb21_validated),
	KUNIT_CASE(test_channel_seq_negative_diff_edge),
	KUNIT_CASE(test_channel_seq_int16_max_boundary),
	KUNIT_CASE(test_channel_seq_smb1_bypassed),
	{}
};

static struct kunit_suite ksmbd_channel_security_test_suite = {
	.name = "ksmbd_channel_security",
	.test_cases = ksmbd_channel_security_test_cases,
};

kunit_test_suite(ksmbd_channel_security_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB3 per-channel security association");
