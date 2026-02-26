// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB1 parser hardening paths (smb1pdu.c)
 *
 *   These tests replicate the pure validation logic for:
 *   - andx_request_buffer() bounds and loop checks
 *   - smb_trans() request offset/count pre-validation
 */

#include <kunit/test.h>
#include <linux/string.h>

#include "smb_common.h"
#include "smb1pdu.h"

static inline void test_set_rfc1002_len(void *buf, unsigned int len)
{
	*(__be32 *)buf = cpu_to_be32(len & 0x00ffffff);
}

static inline u32 test_prng_next(u32 *state)
{
	*state = *state * 1664525u + 1013904223u;
	return *state;
}

static char *test_andx_request_buffer(char *buf, int command)
{
	struct andx_block *andx_ptr;
	char *andx_start;
	char *buf_end;
	unsigned int depth = 0;

	andx_start = buf + sizeof(struct smb_hdr) - 1;
	buf_end = buf + 4 + get_rfc1002_len(buf);
	andx_ptr = (struct andx_block *)andx_start;

	while (1) {
		unsigned int andx_off;
		char *next_ptr;

		if ((char *)andx_ptr < andx_start ||
		    (char *)andx_ptr + sizeof(*andx_ptr) > buf_end)
			return NULL;

		if (andx_ptr->AndXCommand == SMB_NO_MORE_ANDX_COMMAND)
			break;

		andx_off = le16_to_cpu(andx_ptr->AndXOffset);
		next_ptr = buf + 4 + andx_off;
		if (next_ptr < andx_start ||
		    next_ptr + sizeof(struct andx_block) > buf_end)
			return NULL;

		if (andx_ptr->AndXCommand == command)
			return next_ptr;

		if (next_ptr <= (char *)andx_ptr || ++depth > 32)
			return NULL;

		andx_ptr = (struct andx_block *)next_ptr;
	}

	return NULL;
}

static int test_smb_trans_precheck(struct smb_com_trans_req *req,
				   unsigned int req_buf_len,
				   unsigned int response_sz,
				   unsigned int decoded_name_len)
{
	unsigned int setup_bytes_count = 0;
	unsigned int trans_data_off;
	unsigned int name_maxlen;
	unsigned int param_off, param_cnt;
	unsigned int data_off, data_cnt;
	unsigned int str_len_uni;
	unsigned int min_param_data_off;

	trans_data_off = offsetof(struct smb_com_trans_req, Data) - 4;
	if (trans_data_off > req_buf_len)
		return -EINVAL;

	if (response_sz < sizeof(struct smb_com_trans_rsp))
		return -EINVAL;

	if (req->SetupCount)
		setup_bytes_count = req->SetupCount * sizeof(__le16);
	if (setup_bytes_count > req_buf_len - trans_data_off)
		return -EINVAL;

	name_maxlen = req_buf_len - trans_data_off - setup_bytes_count;
	if (!name_maxlen)
		return -EINVAL;

	param_off = le16_to_cpu(req->ParameterOffset);
	param_cnt = le16_to_cpu(req->ParameterCount);
	data_off = le16_to_cpu(req->DataOffset);
	data_cnt = le16_to_cpu(req->DataCount);
	if (param_off > req_buf_len || param_cnt > req_buf_len - param_off ||
	    data_off > req_buf_len || data_cnt > req_buf_len - data_off)
		return -EINVAL;

	str_len_uni = 2 * (decoded_name_len + 1);
	if (str_len_uni > req_buf_len - trans_data_off - setup_bytes_count)
		return -EINVAL;

	min_param_data_off = trans_data_off + setup_bytes_count + str_len_uni;
	if (param_off < min_param_data_off)
		return -EINVAL;

	return 0;
}

/* --- AndX parser tests --- */

static void test_andx_valid_chain_returns_target(struct kunit *test)
{
	char buf[128] = {};
	char *andx_start = buf + sizeof(struct smb_hdr) - 1;
	struct andx_block *first = (struct andx_block *)andx_start;
	struct andx_block *second =
		(struct andx_block *)(andx_start + sizeof(struct andx_block));
	unsigned int smb_len;
	char *ret;

	first->AndXCommand = SMB_COM_TREE_CONNECT_ANDX;
	first->AndXOffset = cpu_to_le16((char *)second - (buf + 4));
	second->AndXCommand = SMB_NO_MORE_ANDX_COMMAND;

	smb_len = (char *)second + sizeof(*second) - (buf + 4);
	test_set_rfc1002_len(buf, smb_len);

	ret = test_andx_request_buffer(buf, SMB_COM_TREE_CONNECT_ANDX);
	KUNIT_EXPECT_PTR_EQ(test, ret, (char *)second);
}

static void test_andx_rejects_offset_before_andx_start(struct kunit *test)
{
	char buf[128] = {};
	char *andx_start = buf + sizeof(struct smb_hdr) - 1;
	struct andx_block *first = (struct andx_block *)andx_start;
	unsigned int smb_len;

	first->AndXCommand = SMB_COM_TREE_CONNECT_ANDX;
	first->AndXOffset = cpu_to_le16(0);
	smb_len = (char *)first + sizeof(*first) - (buf + 4);
	test_set_rfc1002_len(buf, smb_len);

	KUNIT_EXPECT_PTR_EQ(test,
			    test_andx_request_buffer(buf,
						     SMB_COM_TREE_CONNECT_ANDX),
			    NULL);
}

static void test_andx_rejects_offset_past_packet_end(struct kunit *test)
{
	char buf[128] = {};
	char *andx_start = buf + sizeof(struct smb_hdr) - 1;
	struct andx_block *first = (struct andx_block *)andx_start;
	unsigned int smb_len;

	first->AndXCommand = SMB_COM_TREE_CONNECT_ANDX;
	first->AndXOffset = cpu_to_le16(100);
	smb_len = (char *)first + sizeof(*first) - (buf + 4);
	test_set_rfc1002_len(buf, smb_len);

	KUNIT_EXPECT_PTR_EQ(test,
			    test_andx_request_buffer(buf,
						     SMB_COM_TREE_CONNECT_ANDX),
			    NULL);
}

static void test_andx_rejects_non_forward_progress(struct kunit *test)
{
	char buf[128] = {};
	char *andx_start = buf + sizeof(struct smb_hdr) - 1;
	struct andx_block *first = (struct andx_block *)andx_start;
	unsigned int smb_len;

	first->AndXCommand = SMB_COM_ECHO;
	first->AndXOffset = cpu_to_le16((char *)first - (buf + 4));
	smb_len = (char *)first + sizeof(*first) - (buf + 4);
	test_set_rfc1002_len(buf, smb_len);

	KUNIT_EXPECT_PTR_EQ(test,
			    test_andx_request_buffer(buf, SMB_COM_TREE_CONNECT_ANDX),
			    NULL);
}

static void test_andx_rejects_excessive_chain_depth(struct kunit *test)
{
	char buf[512] = {};
	char *andx_start = buf + sizeof(struct smb_hdr) - 1;
	struct andx_block *cur = (struct andx_block *)andx_start;
	int i;
	unsigned int smb_len;

	for (i = 0; i < 33; i++) {
		struct andx_block *next =
			(struct andx_block *)((char *)cur + sizeof(*cur));

		cur->AndXCommand = SMB_COM_ECHO;
		cur->AndXOffset = cpu_to_le16((char *)next - (buf + 4));
		cur = next;
	}
	cur->AndXCommand = SMB_NO_MORE_ANDX_COMMAND;

	smb_len = (char *)cur + sizeof(*cur) - (buf + 4);
	test_set_rfc1002_len(buf, smb_len);

	KUNIT_EXPECT_PTR_EQ(test,
			    test_andx_request_buffer(buf, SMB_COM_TREE_CONNECT_ANDX),
			    NULL);
}

static void test_andx_fuzz_invalid_offsets_rejected(struct kunit *test)
{
	char buf[256] = {};
	char *andx_start = buf + sizeof(struct smb_hdr) - 1;
	struct andx_block *first = (struct andx_block *)andx_start;
	unsigned int smb_len = 96;
	unsigned int min_off = andx_start - (buf + 4);
	u32 seed = 0x1234abcd;
	int i;

	KUNIT_ASSERT_GT(test, min_off, 0u);

	test_set_rfc1002_len(buf, smb_len);
	first->AndXCommand = SMB_COM_ECHO;

	for (i = 0; i < 128; i++) {
		unsigned int off;
		u32 r = test_prng_next(&seed);

		switch (i % 3) {
		case 0:
			/* Offset points before AndX chain start. */
			off = r % min_off;
			break;
		case 1:
			/* Offset points beyond packet boundary. */
			off = smb_len + 1 + (r % 32);
			break;
		default:
			/* Offset makes no forward progress (self/backward). */
			off = (unsigned int)((char *)first - (buf + 4));
			if (off > 0)
				off -= (r % min_t(unsigned int, off + 1, 8));
			break;
		}

		first->AndXOffset = cpu_to_le16(off);
		KUNIT_EXPECT_PTR_EQ(test,
				    test_andx_request_buffer(buf,
							     SMB_COM_TREE_CONNECT_ANDX),
				    NULL);
	}
}

/* --- SMB_TRANS pre-validation tests --- */

static void test_smb_trans_precheck_valid_offsets(struct kunit *test)
{
	struct smb_com_trans_req req = {};
	unsigned int trans_data_off = offsetof(struct smb_com_trans_req, Data) - 4;
	unsigned int name_len = 5;
	unsigned int setup_bytes = sizeof(__le16);
	unsigned int str_len_uni = 2 * (name_len + 1);
	unsigned int param_off = trans_data_off + setup_bytes + str_len_uni;
	unsigned int req_len = param_off + 16;
	int ret;

	req.SetupCount = 1;
	req.ParameterOffset = cpu_to_le16(param_off);
	req.ParameterCount = cpu_to_le16(8);
	req.DataOffset = cpu_to_le16(param_off + 8);
	req.DataCount = cpu_to_le16(4);

	ret = test_smb_trans_precheck(&req, req_len,
				      sizeof(struct smb_com_trans_rsp) + 64,
				      name_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_smb_trans_precheck_rejects_short_response_buf(struct kunit *test)
{
	struct smb_com_trans_req req = {};
	unsigned int trans_data_off = offsetof(struct smb_com_trans_req, Data) - 4;
	int ret;

	ret = test_smb_trans_precheck(&req, trans_data_off + 8,
				      sizeof(struct smb_com_trans_rsp) - 1, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_smb_trans_precheck_rejects_setup_overflow(struct kunit *test)
{
	struct smb_com_trans_req req = {};
	unsigned int trans_data_off = offsetof(struct smb_com_trans_req, Data) - 4;
	int ret;

	req.SetupCount = 1;
	ret = test_smb_trans_precheck(&req, trans_data_off + 1,
				      sizeof(struct smb_com_trans_rsp) + 32, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_smb_trans_precheck_rejects_param_offset_out_of_bounds(struct kunit *test)
{
	struct smb_com_trans_req req = {};
	unsigned int trans_data_off = offsetof(struct smb_com_trans_req, Data) - 4;
	unsigned int req_len = trans_data_off + 32;
	int ret;

	req.ParameterOffset = cpu_to_le16(req_len + 1);
	ret = test_smb_trans_precheck(&req, req_len,
				      sizeof(struct smb_com_trans_rsp) + 32, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_smb_trans_precheck_rejects_param_count_overflow(struct kunit *test)
{
	struct smb_com_trans_req req = {};
	unsigned int trans_data_off = offsetof(struct smb_com_trans_req, Data) - 4;
	unsigned int req_len = trans_data_off + 32;
	int ret;

	req.ParameterOffset = cpu_to_le16(req_len - 2);
	req.ParameterCount = cpu_to_le16(4);
	ret = test_smb_trans_precheck(&req, req_len,
				      sizeof(struct smb_com_trans_rsp) + 32, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_smb_trans_precheck_rejects_data_count_overflow(struct kunit *test)
{
	struct smb_com_trans_req req = {};
	unsigned int trans_data_off = offsetof(struct smb_com_trans_req, Data) - 4;
	unsigned int req_len = trans_data_off + 32;
	int ret;

	req.DataOffset = cpu_to_le16(req_len - 1);
	req.DataCount = cpu_to_le16(2);
	ret = test_smb_trans_precheck(&req, req_len,
				      sizeof(struct smb_com_trans_rsp) + 32, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_smb_trans_precheck_rejects_param_before_pipe_data(struct kunit *test)
{
	struct smb_com_trans_req req = {};
	unsigned int trans_data_off = offsetof(struct smb_com_trans_req, Data) - 4;
	unsigned int name_len = 5;
	unsigned int setup_bytes = sizeof(__le16);
	unsigned int str_len_uni = 2 * (name_len + 1);
	unsigned int min_param = trans_data_off + setup_bytes + str_len_uni;
	unsigned int req_len = min_param + 16;
	int ret;

	req.SetupCount = 1;
	req.ParameterOffset = cpu_to_le16(min_param - 1);
	req.ParameterCount = cpu_to_le16(4);
	req.DataOffset = cpu_to_le16(min_param + 4);
	req.DataCount = cpu_to_le16(2);

	ret = test_smb_trans_precheck(&req, req_len,
				      sizeof(struct smb_com_trans_rsp) + 32,
				      name_len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_smb_trans_precheck_rejects_oversized_name_span(struct kunit *test)
{
	struct smb_com_trans_req req = {};
	unsigned int trans_data_off = offsetof(struct smb_com_trans_req, Data) - 4;
	unsigned int req_len = trans_data_off + 12;
	int ret;

	req.ParameterOffset = cpu_to_le16(req_len);
	ret = test_smb_trans_precheck(&req, req_len,
				      sizeof(struct smb_com_trans_rsp) + 32, 10);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_smb_trans_precheck_fuzz_invalid_offsets_rejected(struct kunit *test)
{
	struct smb_com_trans_req req;
	unsigned int trans_data_off = offsetof(struct smb_com_trans_req, Data) - 4;
	unsigned int req_len = trans_data_off + 80;
	u32 seed = 0x9e3779b9;
	int i;

	for (i = 0; i < 160; i++) {
		unsigned int param_off, param_cnt;
		unsigned int data_off, data_cnt;
		unsigned int name_len, min_param;
		u32 r = test_prng_next(&seed);
		int ret;

		memset(&req, 0, sizeof(req));
		param_off = trans_data_off + 16;
		param_cnt = 4;
		data_off = trans_data_off + 24;
		data_cnt = 4;
		name_len = 4;

		switch (i % 6) {
		case 0:
			/* ParameterOffset beyond request length. */
			param_off = req_len + 1 + (r % 64);
			break;
		case 1:
			/* ParameterCount overflows request boundary. */
			param_off = req_len - 1;
			param_cnt = 8;
			break;
		case 2:
			/* DataOffset beyond request length. */
			data_off = req_len + 1 + (r % 64);
			break;
		case 3:
			/* DataCount overflows request boundary. */
			data_off = req_len - 2;
			data_cnt = 8;
			break;
		case 4:
			/* SetupCount consumes beyond available setup bytes. */
			req.SetupCount = ((req_len - trans_data_off) / 2) + 1;
			break;
		default:
			/* ParameterOffset before minimum pipe data region. */
			req.SetupCount = 1;
			name_len = 1 + (r % 8);
			min_param = trans_data_off +
				    req.SetupCount * sizeof(__le16) +
				    2 * (name_len + 1);
			if (min_param > 0)
				param_off = min_param - 1;
			break;
		}

		req.ParameterOffset = cpu_to_le16(param_off);
		req.ParameterCount = cpu_to_le16(param_cnt);
		req.DataOffset = cpu_to_le16(data_off);
		req.DataCount = cpu_to_le16(data_cnt);

		ret = test_smb_trans_precheck(&req, req_len,
					      sizeof(struct smb_com_trans_rsp) + 64,
					      name_len);
		KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	}
}

static struct kunit_case ksmbd_smb1_parser_test_cases[] = {
	KUNIT_CASE(test_andx_valid_chain_returns_target),
	KUNIT_CASE(test_andx_rejects_offset_before_andx_start),
	KUNIT_CASE(test_andx_rejects_offset_past_packet_end),
	KUNIT_CASE(test_andx_rejects_non_forward_progress),
	KUNIT_CASE(test_andx_rejects_excessive_chain_depth),
	KUNIT_CASE(test_andx_fuzz_invalid_offsets_rejected),
	KUNIT_CASE(test_smb_trans_precheck_valid_offsets),
	KUNIT_CASE(test_smb_trans_precheck_rejects_short_response_buf),
	KUNIT_CASE(test_smb_trans_precheck_rejects_setup_overflow),
	KUNIT_CASE(test_smb_trans_precheck_rejects_param_offset_out_of_bounds),
	KUNIT_CASE(test_smb_trans_precheck_rejects_param_count_overflow),
	KUNIT_CASE(test_smb_trans_precheck_rejects_data_count_overflow),
	KUNIT_CASE(test_smb_trans_precheck_rejects_param_before_pipe_data),
	KUNIT_CASE(test_smb_trans_precheck_rejects_oversized_name_span),
	KUNIT_CASE(test_smb_trans_precheck_fuzz_invalid_offsets_rejected),
	{}
};

static struct kunit_suite ksmbd_smb1_parser_test_suite = {
	.name = "ksmbd_smb1_parser",
	.test_cases = ksmbd_smb1_parser_test_cases,
};

kunit_test_suite(ksmbd_smb1_parser_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB1 parser offset hardening");
