// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit regression tests for compound request handling
 *
 *   Tests known-fixed bugs in init_chained_smb2_rsp() to prevent
 *   regressions. All tests call the real production function via
 *   VISIBLE_IF_KUNIT.
 *
 *   REG-015: Compound error propagation (only CREATE failures cascade)
 *   REG-016: Compound FID from non-CREATE commands
 *   REG-017: Compound FID for FLUSH/READ/WRITE/CLOSE
 *
 *   Note: init_chained_smb2_rsp() requires a fully wired ksmbd_work
 *   structure with valid request/response buffers. Minimal stubs
 *   are created to exercise the FID propagation and error cascading
 *   logic paths.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "ksmbd_work.h"
#include "connection.h"

/*
 * Helper to build a minimal compound request+response buffer pair.
 * The buffers are laid out as:
 *   [4-byte RFC1001 len] [SMB2 header] [body padding]
 */
#define COMPOUND_BUF_SIZE	4096

static struct ksmbd_work *alloc_compound_work(struct kunit *test)
{
	struct ksmbd_work *work;

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work);

	work->request_buf = kzalloc(COMPOUND_BUF_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->request_buf);

	work->response_buf = kzalloc(COMPOUND_BUF_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);

	work->response_sz = COMPOUND_BUF_SIZE;

	/* Initialize compound state */
	work->compound_fid = KSMBD_NO_FID;
	work->compound_pfid = KSMBD_NO_FID;
	work->compound_sid = 0;
	work->compound_err_status = STATUS_SUCCESS;
	work->next_smb2_rcv_hdr_off = 0;
	work->next_smb2_rsp_hdr_off = 0;
	work->curr_smb2_rsp_hdr_off = 0;
	work->iov_idx = 0;

	/* Set up initial iov */
	work->iov[0].iov_base = work->response_buf;
	work->iov[0].iov_len = 0;

	return work;
}

static void free_compound_work(struct ksmbd_work *work)
{
	kfree(work->request_buf);
	kfree(work->response_buf);
	kfree(work);
}

/*
 * Set up a compound request/response pair at the current offset.
 * req_cmd: the SMB2 command code for the request
 * rsp_status: the status code for the response
 * next_cmd_offset: NextCommand offset in the request (0 = last)
 */
static void setup_compound_msg(struct ksmbd_work *work,
			       __le16 req_cmd, __le32 rsp_status,
			       u32 next_cmd_offset)
{
	struct smb2_hdr *req_hdr;
	struct smb2_hdr *rsp_hdr;
	int rfc_len;

	/* Request header at current offset */
	req_hdr = (struct smb2_hdr *)(work->request_buf + 4 +
				      work->next_smb2_rcv_hdr_off);
	memset(req_hdr, 0, sizeof(*req_hdr));
	req_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	req_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	req_hdr->Command = req_cmd;
	req_hdr->NextCommand = cpu_to_le32(next_cmd_offset);
	req_hdr->Flags = SMB2_FLAGS_RELATED_OPERATIONS;

	/* Response header at current offset */
	rsp_hdr = (struct smb2_hdr *)(work->response_buf + 4 +
				      work->next_smb2_rsp_hdr_off);
	memset(rsp_hdr, 0, sizeof(*rsp_hdr));
	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->Command = req_cmd;
	rsp_hdr->Status = rsp_status;
	rsp_hdr->Flags = SMB2_FLAGS_SERVER_TO_REDIR;

	/* Set RFC1001 length to include current response */
	rfc_len = work->next_smb2_rsp_hdr_off + sizeof(struct smb2_hdr) + 64;
	*((__be32 *)work->response_buf) = cpu_to_be32(rfc_len);

	/* Set iov_len to cover the response */
	work->iov[work->iov_idx].iov_len = rfc_len + 4;

	/* Set RFC1001 length for request too */
	rfc_len = work->next_smb2_rcv_hdr_off + sizeof(struct smb2_hdr) + 64;
	if (next_cmd_offset)
		rfc_len = work->next_smb2_rcv_hdr_off + next_cmd_offset + sizeof(struct smb2_hdr) + 64;
	*((__be32 *)work->request_buf) = cpu_to_be32(rfc_len);
}

/*
 * REG-015: Compound error propagation - only CREATE failures cascade
 *
 * When a CREATE command in a compound chain fails, the error status
 * should be recorded in compound_err_status so subsequent related
 * requests can propagate the failure.
 */
static void test_reg015_create_failure_cascades(struct kunit *test)
{
	struct ksmbd_work *work = alloc_compound_work(test);
	struct smb2_hdr *req_hdr;
	struct smb2_hdr *rsp_hdr;

	/* Set up a failed CREATE as first command */
	req_hdr = (struct smb2_hdr *)(work->request_buf + 4);
	memset(req_hdr, 0, sizeof(*req_hdr));
	req_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	req_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	req_hdr->Command = SMB2_CREATE;
	req_hdr->NextCommand = cpu_to_le32(ALIGN(sizeof(struct smb2_hdr) + 64, 8));

	rsp_hdr = (struct smb2_hdr *)(work->response_buf + 4);
	memset(rsp_hdr, 0, sizeof(*rsp_hdr));
	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->Command = SMB2_CREATE;
	rsp_hdr->Status = STATUS_OBJECT_NAME_NOT_FOUND;
	rsp_hdr->Flags = SMB2_FLAGS_SERVER_TO_REDIR;

	/* Set RFC1001 length */
	{
		int rfc_len = sizeof(struct smb2_hdr) + 64 +
			      ALIGN(sizeof(struct smb2_hdr) + 64, 8);
		*((__be32 *)work->request_buf) = cpu_to_be32(rfc_len);
		*((__be32 *)work->response_buf) = cpu_to_be32(
			sizeof(struct smb2_hdr) + 64);
		work->iov[0].iov_len = sizeof(struct smb2_hdr) + 64 + 4;
	}

	/* Set up the next command in request to be RELATED CLOSE */
	{
		struct smb2_hdr *next_req;
		int next_off = ALIGN(sizeof(struct smb2_hdr) + 64, 8);

		next_req = (struct smb2_hdr *)(work->request_buf + 4 + next_off);
		memset(next_req, 0, sizeof(*next_req));
		next_req->ProtocolId = SMB2_PROTO_NUMBER;
		next_req->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
		next_req->Command = SMB2_CLOSE;
		next_req->Flags = SMB2_FLAGS_RELATED_OPERATIONS;
	}

	/* Call init_chained_smb2_rsp */
	init_chained_smb2_rsp(work);

	/* CREATE failed: compound_err_status should record the error */
	KUNIT_EXPECT_EQ(test, work->compound_err_status,
			STATUS_OBJECT_NAME_NOT_FOUND);
	/* compound_fid should remain invalid (CREATE didn't succeed) */
	KUNIT_EXPECT_EQ(test, work->compound_fid, (u64)KSMBD_NO_FID);

	free_compound_work(work);
}

/*
 * REG-016: Compound FID from non-CREATE commands
 *
 * After a successful CREATE, the FID is captured. We verify that
 * init_chained_smb2_rsp correctly captures the FID from CREATE.
 */
static void test_reg016_create_success_captures_fid(struct kunit *test)
{
	struct ksmbd_work *work = alloc_compound_work(test);
	struct smb2_hdr *req_hdr;
	struct smb2_create_rsp *rsp;

	/* Set up a successful CREATE */
	req_hdr = (struct smb2_hdr *)(work->request_buf + 4);
	memset(req_hdr, 0, sizeof(*req_hdr));
	req_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	req_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	req_hdr->Command = SMB2_CREATE;
	req_hdr->NextCommand = cpu_to_le32(ALIGN(sizeof(struct smb2_create_rsp) + 64, 8));

	rsp = (struct smb2_create_rsp *)(work->response_buf + 4);
	memset(rsp, 0, sizeof(*rsp));
	rsp->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	rsp->hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp->hdr.Command = SMB2_CREATE;
	rsp->hdr.Status = STATUS_SUCCESS;
	rsp->hdr.Flags = SMB2_FLAGS_SERVER_TO_REDIR;
	rsp->hdr.SessionId = cpu_to_le64(42);
	rsp->VolatileFileId = 0x1234;
	rsp->PersistentFileId = 0x5678;

	{
		int rfc_len = ALIGN(sizeof(struct smb2_create_rsp) + 64, 8) +
			      sizeof(struct smb2_hdr) + 64;
		*((__be32 *)work->request_buf) = cpu_to_be32(rfc_len);
		*((__be32 *)work->response_buf) = cpu_to_be32(
			sizeof(struct smb2_create_rsp) + 64);
		work->iov[0].iov_len = sizeof(struct smb2_create_rsp) + 64 + 4;
	}

	/* Next command */
	{
		struct smb2_hdr *next_req;
		int next_off = ALIGN(sizeof(struct smb2_create_rsp) + 64, 8);

		next_req = (struct smb2_hdr *)(work->request_buf + 4 + next_off);
		memset(next_req, 0, sizeof(*next_req));
		next_req->ProtocolId = SMB2_PROTO_NUMBER;
		next_req->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
		next_req->Command = SMB2_CLOSE;
		next_req->Flags = SMB2_FLAGS_RELATED_OPERATIONS;
	}

	init_chained_smb2_rsp(work);

	KUNIT_EXPECT_EQ(test, work->compound_fid, (u64)0x1234);
	KUNIT_EXPECT_EQ(test, work->compound_pfid, (u64)0x5678);
	KUNIT_EXPECT_EQ(test, work->compound_sid, (u64)42);

	free_compound_work(work);
}

/*
 * REG-017: Compound FID for FLUSH/READ/WRITE/CLOSE
 *
 * Non-CREATE successful commands should also capture their FID
 * when compound_fid is not yet set. This was a fix for
 * flush_close, flush_flush, rename_last, rename_middle subtests.
 *
 * Here we test with a FLUSH request that has a valid FID.
 */
static void test_reg017_flush_captures_fid(struct kunit *test)
{
	struct ksmbd_work *work = alloc_compound_work(test);
	struct smb2_hdr *req_hdr;
	struct smb2_flush_req *flush_req;
	struct smb2_hdr *rsp_hdr;

	/* Set up a successful FLUSH as the current command */
	flush_req = (struct smb2_flush_req *)(work->request_buf + 4);
	memset(flush_req, 0, sizeof(*flush_req));
	flush_req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
	flush_req->hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	flush_req->hdr.Command = SMB2_FLUSH;
	flush_req->hdr.NextCommand = cpu_to_le32(ALIGN(sizeof(struct smb2_flush_req) + 32, 8));
	flush_req->hdr.Flags = SMB2_FLAGS_RELATED_OPERATIONS;
	flush_req->VolatileFileId = 0xAAAA;
	flush_req->PersistentFileId = 0xBBBB;

	rsp_hdr = (struct smb2_hdr *)(work->response_buf + 4);
	memset(rsp_hdr, 0, sizeof(*rsp_hdr));
	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->Command = SMB2_FLUSH;
	rsp_hdr->Status = STATUS_SUCCESS;
	rsp_hdr->Flags = SMB2_FLAGS_SERVER_TO_REDIR;

	{
		int rfc_len = ALIGN(sizeof(struct smb2_flush_req) + 32, 8) +
			      sizeof(struct smb2_hdr) + 64;
		*((__be32 *)work->request_buf) = cpu_to_be32(rfc_len);
		*((__be32 *)work->response_buf) = cpu_to_be32(
			sizeof(struct smb2_hdr) + 64);
		work->iov[0].iov_len = sizeof(struct smb2_hdr) + 64 + 4;
	}

	/* Next command */
	{
		int next_off = ALIGN(sizeof(struct smb2_flush_req) + 32, 8);
		struct smb2_hdr *next_req;

		next_req = (struct smb2_hdr *)(work->request_buf + 4 + next_off);
		memset(next_req, 0, sizeof(*next_req));
		next_req->ProtocolId = SMB2_PROTO_NUMBER;
		next_req->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
		next_req->Command = SMB2_CLOSE;
		next_req->Flags = SMB2_FLAGS_RELATED_OPERATIONS;
	}

	/* compound_fid is NOT set (no CREATE preceded this) */
	KUNIT_EXPECT_EQ(test, work->compound_fid, (u64)KSMBD_NO_FID);

	init_chained_smb2_rsp(work);

	/* FLUSH succeeded: FID should be captured from the request */
	KUNIT_EXPECT_EQ(test, work->compound_fid, (u64)0xAAAA);
	KUNIT_EXPECT_EQ(test, work->compound_pfid, (u64)0xBBBB);

	free_compound_work(work);
}

static struct kunit_case ksmbd_regression_compound_test_cases[] = {
	KUNIT_CASE(test_reg015_create_failure_cascades),
	KUNIT_CASE(test_reg016_create_success_captures_fid),
	KUNIT_CASE(test_reg017_flush_captures_fid),
	{}
};

static struct kunit_suite ksmbd_regression_compound_test_suite = {
	.name = "ksmbd_regression_compound",
	.test_cases = ksmbd_regression_compound_test_cases,
};

kunit_test_suite(ksmbd_regression_compound_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit regression tests for ksmbd compound request fixes");
