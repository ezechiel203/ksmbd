// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB1 protocol constants, structures, and helpers
 *   (smb1pdu.c, smb1pdu.h, smb1ops.c, smb1misc.c)
 *
 *   Tests cover:
 *   - Protocol constants (MPX count, raw size, capabilities)
 *   - SMB1 header structure layout and magic bytes
 *   - Command opcode values
 *   - Negotiate, session setup, tree connect structures
 *   - Read/write/close/find request/response layouts
 *   - DOS error class codes
 *   - Service type strings
 *   - Security mode flags
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>

#include "smb_common.h"
#include "smb1pdu.h"
#include "smberr.h"

/* ──────────────────────────────────────────────────────────
 * Protocol constants
 * ────────────────────────────────────────────────────────── */

static void test_smb1_max_mpx_count(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB1_MAX_MPX_COUNT, 10);
}

static void test_smb1_max_raw_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB1_MAX_RAW_SIZE, 65536);
}

static void test_smb1_max_vcs(struct kunit *test)
{
	/* MaxNumberVcs: only 1 VC supported */
	KUNIT_EXPECT_EQ(test, SMB1_MAX_VCS, 1);
}

static void test_smb1_protocol_string(struct kunit *test)
{
	/*
	 * SMB1 dialect string identifiers.
	 * "NT LM 0.12" is the canonical NT1 dialect.
	 */
	KUNIT_EXPECT_STREQ(test, SMB1_VERSION_STRING, "1.0");
	KUNIT_EXPECT_EQ(test, SMB10_PROT_ID, 0x00);
}

static void test_smb1_capabilities_no_lock_and_read(struct kunit *test)
{
	/*
	 * CAP_LOCK_AND_READ (0x00000100) must NOT be in SMB1_SERVER_CAPS
	 * because opcode 0x13 (SMB_COM_LOCK_AND_READ) has no handler.
	 */
	KUNIT_EXPECT_EQ(test, (unsigned int)(SMB1_SERVER_CAPS & CAP_LOCK_AND_READ),
			0u);
}

static void test_smb1_capabilities_required_flags(struct kunit *test)
{
	/*
	 * Verify key capabilities are present in SMB1_SERVER_CAPS.
	 */
	unsigned int caps = SMB1_SERVER_CAPS;

	KUNIT_EXPECT_NE(test, caps & CAP_UNICODE, 0u);
	KUNIT_EXPECT_NE(test, caps & CAP_LARGE_FILES, 0u);
	KUNIT_EXPECT_NE(test, caps & CAP_NT_SMBS, 0u);
	KUNIT_EXPECT_NE(test, caps & CAP_STATUS32, 0u);
	KUNIT_EXPECT_NE(test, caps & CAP_EXTENDED_SECURITY, 0u);
	KUNIT_EXPECT_NE(test, caps & CAP_LARGE_READ_X, 0u);
	KUNIT_EXPECT_NE(test, caps & CAP_LARGE_WRITE_X, 0u);
	KUNIT_EXPECT_NE(test, caps & CAP_LEVEL_II_OPLOCKS, 0u);
	KUNIT_EXPECT_NE(test, caps & CAP_UNIX, 0u);
	KUNIT_EXPECT_NE(test, caps & CAP_NT_FIND, 0u);
}

/* ──────────────────────────────────────────────────────────
 * SMB1 header structure
 * ────────────────────────────────────────────────────────── */

static void test_smb1_header_size(struct kunit *test)
{
	/*
	 * struct smb_hdr: 4 (smb_buf_length) + 4 (Protocol) + 1 (Command)
	 *   + 4 (Status) + 1 (Flags) + 2 (Flags2) + 2 (PidHigh)
	 *   + 8 (Signature) + 2 (pad) + 2 (Tid) + 2 (Pid) + 2 (Uid)
	 *   + 2 (Mid) + 1 (WordCount) = 37 bytes
	 * But the struct is __packed, so verify against the actual size.
	 */
	KUNIT_EXPECT_EQ(test, (unsigned int)sizeof(struct smb_hdr), 37u);
}

static void test_smb1_protocol_magic(struct kunit *test)
{
	/*
	 * SMB1 magic: 0xFF 'S' 'M' 'B' => little-endian 0x424d53ff
	 */
	__le32 magic = SMB1_PROTO_NUMBER;
	unsigned char *bytes = (unsigned char *)&magic;

	KUNIT_EXPECT_EQ(test, bytes[0], 0xFFu);
	KUNIT_EXPECT_EQ(test, bytes[1], (unsigned char)'S');
	KUNIT_EXPECT_EQ(test, bytes[2], (unsigned char)'M');
	KUNIT_EXPECT_EQ(test, bytes[3], (unsigned char)'B');
}

static void test_smb1_header_field_offsets(struct kunit *test)
{
	/* Verify critical header field offsets for wire compatibility */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_hdr, Protocol), 4u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_hdr, Command), 8u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_hdr, Status), 9u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_hdr, Flags), 13u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_hdr, Flags2), 14u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_hdr, Tid), 28u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_hdr, Pid), 30u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_hdr, Uid), 32u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_hdr, Mid), 34u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_hdr, WordCount), 36u);
}

/* ──────────────────────────────────────────────────────────
 * SMB1 command codes
 * ────────────────────────────────────────────────────────── */

static void test_smb1_command_codes(struct kunit *test)
{
	/* Verify key SMB1 command opcode values per MS-SMB */
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_CREATE_DIRECTORY, 0x00u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_DELETE_DIRECTORY, 0x01u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_CLOSE, 0x04u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_FLUSH, 0x05u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_DELETE, 0x06u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_RENAME, 0x07u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_QUERY_INFORMATION, 0x08u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_WRITE, 0x0Bu);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_LOCKING_ANDX, 0x24u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_TRANSACTION, 0x25u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_ECHO, 0x2Bu);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_OPEN_ANDX, 0x2Du);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_READ_ANDX, 0x2Eu);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_WRITE_ANDX, 0x2Fu);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_NEGOTIATE, 0x72u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_SESSION_SETUP_ANDX, 0x73u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_LOGOFF_ANDX, 0x74u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_TREE_CONNECT_ANDX, 0x75u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_NT_CREATE_ANDX, 0xA2u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_COM_NT_CANCEL, 0xA4u);
}

/* ──────────────────────────────────────────────────────────
 * Negotiate structure
 * ────────────────────────────────────────────────────────── */

static void test_smb1_negotiate_rsp_structure(struct kunit *test)
{
	/*
	 * Verify negotiate response structure has correct size.
	 * smb_negotiate_rsp: smb_hdr + 17 words + ByteCount + union
	 */
	KUNIT_EXPECT_GT(test,
		(unsigned int)sizeof(struct smb_negotiate_rsp),
		(unsigned int)sizeof(struct smb_hdr));

	/* DialectIndex field immediately follows hdr */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_negotiate_rsp, DialectIndex),
		(unsigned int)sizeof(struct smb_hdr));
}

static void test_smb1_negotiate_capabilities_field(struct kunit *test)
{
	/*
	 * Capabilities field offset in negotiate response.
	 * After hdr: DialectIndex(2) + SecurityMode(1) + MaxMpxCount(2)
	 *   + MaxNumberVcs(2) + MaxBufferSize(4) + MaxRawSize(4)
	 *   + SessionKey(4) = 19 bytes from end of hdr.
	 */
	unsigned int expected = sizeof(struct smb_hdr) + 2 + 1 + 2 + 2 + 4 + 4 + 4;

	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_negotiate_rsp, Capabilities),
		expected);
}

static void test_smb1_negotiate_security_mode(struct kunit *test)
{
	/*
	 * SMB1_SERVER_SECU = SECMODE_USER | SECMODE_PW_ENCRYPT
	 * Verify the security mode constants.
	 */
	KUNIT_EXPECT_EQ(test, SECMODE_USER, 0x01);
	KUNIT_EXPECT_EQ(test, SECMODE_PW_ENCRYPT, 0x02);
	KUNIT_EXPECT_EQ(test, SECMODE_SIGN_ENABLED, 0x04);
	KUNIT_EXPECT_EQ(test, SECMODE_SIGN_REQUIRED, 0x08);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB1_SERVER_SECU,
			(unsigned int)(SECMODE_USER | SECMODE_PW_ENCRYPT));
}

static void test_smb1_negotiate_max_buffer_size(struct kunit *test)
{
	/* MaxBufferSize is a __le32 field at known offset */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_negotiate_rsp, MaxBufferSize),
		(unsigned int)(sizeof(struct smb_hdr) + 2 + 1 + 2 + 2));
}

/* ──────────────────────────────────────────────────────────
 * Session setup structure
 * ────────────────────────────────────────────────────────── */

static void test_smb1_session_setup_andx(struct kunit *test)
{
	/*
	 * Session setup request (extended security) includes
	 * hdr + AndXCommand(1) + AndXReserved(1) + AndXOffset(2)
	 * + MaxBufferSize(2) + MaxMpxCount(2) + VcNumber(2)
	 * + SessionKey(4) + SecurityBlobLength(2) + Reserved(4)
	 * + Capabilities(4) + ByteCount(2) + SecurityBlob[1]
	 */
	KUNIT_EXPECT_GT(test,
		(unsigned int)sizeof(struct smb_com_session_setup_req),
		(unsigned int)sizeof(struct smb_hdr));

	/* AndXCommand is the first field after hdr */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_com_session_setup_req, AndXCommand),
		(unsigned int)sizeof(struct smb_hdr));
}

static void test_smb1_session_flags(struct kunit *test)
{
	/* GUEST_LOGIN action flag */
	KUNIT_EXPECT_EQ(test, GUEST_LOGIN, 1);
}

static void test_smb1_session_no_more_andx(struct kunit *test)
{
	/* Terminal AndX command marker */
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_NO_MORE_ANDX_COMMAND, 0xFFu);
}

/* ──────────────────────────────────────────────────────────
 * Tree connect structure
 * ────────────────────────────────────────────────────────── */

static void test_smb1_tree_connect_andx(struct kunit *test)
{
	/*
	 * Tree connect request: WordCount(1) + AndXCommand(1)
	 * + AndXReserved(1) + AndXOffset(2) + Flags(2)
	 * + PasswordLength(2) + ByteCount(2) + Password[1]
	 */
	KUNIT_EXPECT_GT(test,
		(unsigned int)sizeof(struct smb_com_tconx_req), 10u);

	/* Flags field offset */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_com_tconx_req, Flags),
		5u);
}

static void test_smb1_service_types(struct kunit *test)
{
	/* Service type strings for tree connect */
	KUNIT_EXPECT_STREQ(test, SERVICE_DISK_SHARE, "A:");
	KUNIT_EXPECT_STREQ(test, SERVICE_IPC_SHARE, "IPC");
	KUNIT_EXPECT_STREQ(test, SERVICE_PRINTER_SHARE, "LPT1:");
	KUNIT_EXPECT_STREQ(test, SERVICE_COMM, "COMM");
}

static void test_smb1_native_fs(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, NATIVE_FILE_SYSTEM, "NTFS");
}

static void test_smb1_tcon_flags(struct kunit *test)
{
	/* Tree connect flag constants */
	KUNIT_EXPECT_EQ(test, (unsigned int)DISCONNECT_TID, 0x0001u);
	KUNIT_EXPECT_EQ(test, (unsigned int)TCON_EXTENDED_SIGNATURES, 0x0004u);
	KUNIT_EXPECT_EQ(test, (unsigned int)TCON_EXTENDED_SECINFO, 0x0008u);
}

/* ──────────────────────────────────────────────────────────
 * Command structure layouts
 * ────────────────────────────────────────────────────────── */

static void test_smb1_read_andx_structure(struct kunit *test)
{
	/*
	 * Read request: hdr + AndXCommand(1) + AndXReserved(1) + AndXOffset(2)
	 * + Fid(2) + OffsetLow(4) + MaxCount(2) + MinCount(2)
	 * + MaxCountHigh(4) + Remaining(2) + OffsetHigh(4) + ByteCount(2)
	 */
	unsigned int expected_size = sizeof(struct smb_hdr) +
		1 + 1 + 2 + 2 + 4 + 2 + 2 + 4 + 2 + 4 + 2;

	KUNIT_EXPECT_EQ(test, (unsigned int)sizeof(struct smb_com_read_req),
			expected_size);

	/* Fid offset: hdr + AndXCommand(1) + AndXReserved(1) + AndXOffset(2) */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_com_read_req, Fid),
		(unsigned int)(sizeof(struct smb_hdr) + 1 + 1 + 2));
}

static void test_smb1_write_andx_structure(struct kunit *test)
{
	/*
	 * Write request: hdr + AndXCommand(1) + AndXReserved(1) + AndXOffset(2)
	 * + Fid(2) + OffsetLow(4) + Reserved(4) + WriteMode(2) + Remaining(2)
	 * + DataLengthHigh(2) + DataLengthLow(2) + DataOffset(2)
	 * + OffsetHigh(4) + ByteCount(2) + Pad(1) + Data[0]
	 */
	KUNIT_EXPECT_GT(test,
		(unsigned int)sizeof(struct smb_com_write_req),
		(unsigned int)sizeof(struct smb_hdr));

	/* Fid at known offset after hdr */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_com_write_req, Fid),
		(unsigned int)(sizeof(struct smb_hdr) + 1 + 1 + 2));
}

static void test_smb1_close_structure(struct kunit *test)
{
	/*
	 * Close request: hdr + FileID(2) + LastWriteTime(4) + ByteCount(2)
	 */
	unsigned int expected = sizeof(struct smb_hdr) + 2 + 4 + 2;

	KUNIT_EXPECT_EQ(test, (unsigned int)sizeof(struct smb_com_close_req),
			expected);

	/* FileID follows hdr directly */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_com_close_req, FileID),
		(unsigned int)sizeof(struct smb_hdr));
}

static void test_smb1_close_rsp_structure(struct kunit *test)
{
	/*
	 * Close response: hdr + ByteCount(2)
	 */
	unsigned int expected = sizeof(struct smb_hdr) + 2;

	KUNIT_EXPECT_EQ(test, (unsigned int)sizeof(struct smb_com_close_rsp),
			expected);
}

static void test_smb1_find_first2(struct kunit *test)
{
	/*
	 * TRANS2_FIND_FIRST request parameters structure:
	 * SearchAttributes(2) + SearchCount(2) + SearchFlags(2)
	 * + InformationLevel(2) + SearchStorageType(4) + FileName[1]
	 */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)sizeof(struct smb_com_trans2_ffirst_req_params),
		2u + 2u + 2u + 2u + 4u + 1u);

	/* Verify TRANS2_FIND_FIRST subcommand code */
	KUNIT_EXPECT_EQ(test, TRANS2_FIND_FIRST, 0x01);
	KUNIT_EXPECT_EQ(test, TRANS2_FIND_NEXT, 0x02);
}

static void test_smb1_find_response_params(struct kunit *test)
{
	/*
	 * TRANS2_FIND_FIRST response parameters:
	 * SearchHandle(2) + SearchCount(2) + EndofSearch(2)
	 * + EAErrorOffset(2) + LastNameOffset(2)
	 */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)sizeof(struct smb_com_trans2_ffirst_rsp_parms),
		10u);
}

/* ──────────────────────────────────────────────────────────
 * Error mapping and error class codes
 * ────────────────────────────────────────────────────────── */

static void test_smb1_error_class_codes(struct kunit *test)
{
	/* DOS error classes (MS-SMB 2.2.1.4) */
	KUNIT_EXPECT_EQ(test, SUCCESS, 0x00);
	KUNIT_EXPECT_EQ(test, ERRDOS, 0x01);
	KUNIT_EXPECT_EQ(test, ERRSRV, 0x02);
	KUNIT_EXPECT_EQ(test, ERRHRD, 0x03);
	KUNIT_EXPECT_EQ(test, ERRCMD, 0xFF);
}

static void test_smb1_dos_error_codes(struct kunit *test)
{
	/* Common ERRDOS error codes */
	KUNIT_EXPECT_EQ(test, ERRbadfunc, 1);
	KUNIT_EXPECT_EQ(test, ERRbadfile, 2);
	KUNIT_EXPECT_EQ(test, ERRbadpath, 3);
	KUNIT_EXPECT_EQ(test, ERRnofids, 4);
	KUNIT_EXPECT_EQ(test, ERRnoaccess, 5);
	KUNIT_EXPECT_EQ(test, ERRbadfid, 6);
	KUNIT_EXPECT_EQ(test, ERRnomem, 8);
	KUNIT_EXPECT_EQ(test, ERRbadshare, 32);
	KUNIT_EXPECT_EQ(test, ERRlock, 33);
	KUNIT_EXPECT_EQ(test, ERRfilexists, 80);
	KUNIT_EXPECT_EQ(test, ERRdiskfull, 112);
	KUNIT_EXPECT_EQ(test, ERRmoredata, 234);
}

static void test_smb1_srv_error_codes(struct kunit *test)
{
	/* Common ERRSRV error codes */
	KUNIT_EXPECT_EQ(test, ERRerror, 1);
	KUNIT_EXPECT_EQ(test, ERRbadpw, 2);
	KUNIT_EXPECT_EQ(test, ERRaccess, 4);
	KUNIT_EXPECT_EQ(test, ERRinvtid, 5);
	KUNIT_EXPECT_EQ(test, ERRinvnetname, 6);
	KUNIT_EXPECT_EQ(test, ERRinvdevice, 7);
	KUNIT_EXPECT_EQ(test, ERRsmbcmd, 64);
	KUNIT_EXPECT_EQ(test, ERRsrverror, 65);
	KUNIT_EXPECT_EQ(test, ERRbaduid, 91);
	KUNIT_EXPECT_EQ(test, ERRnosupport, 0xFFFF);
}

/* ──────────────────────────────────────────────────────────
 * SMB1 flag definitions
 * ────────────────────────────────────────────────────────── */

static void test_smb1_flags(struct kunit *test)
{
	/* SMB Flags byte (MS-SMB 2.2.3.1) */
	KUNIT_EXPECT_EQ(test, (unsigned int)SMBFLG_EXTD_LOCK, 0x01u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMBFLG_CASELESS, 0x08u);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMBFLG_RESPONSE, 0x80u);
}

static void test_smb1_flags2(struct kunit *test)
{
	/* SMB Flags2 word (MS-SMB 2.2.3.1) */
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(SMBFLG2_UNICODE), 0x8000);
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(SMBFLG2_ERR_STATUS), 0x4000);
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(SMBFLG2_EXT_SEC), 0x0800);
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(SMBFLG2_KNOWS_LONG_NAMES), 0x0001);
}

/* ──────────────────────────────────────────────────────────
 * Transact subcommand codes
 * ────────────────────────────────────────────────────────── */

static void test_smb1_trans2_subcmds(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TRANS2_OPEN, 0x00);
	KUNIT_EXPECT_EQ(test, TRANS2_FIND_FIRST, 0x01);
	KUNIT_EXPECT_EQ(test, TRANS2_FIND_NEXT, 0x02);
	KUNIT_EXPECT_EQ(test, TRANS2_QUERY_FS_INFORMATION, 0x03);
	KUNIT_EXPECT_EQ(test, TRANS2_SET_FS_INFORMATION, 0x04);
	KUNIT_EXPECT_EQ(test, TRANS2_QUERY_PATH_INFORMATION, 0x05);
	KUNIT_EXPECT_EQ(test, TRANS2_SET_PATH_INFORMATION, 0x06);
	KUNIT_EXPECT_EQ(test, TRANS2_QUERY_FILE_INFORMATION, 0x07);
	KUNIT_EXPECT_EQ(test, TRANS2_SET_FILE_INFORMATION, 0x08);
	KUNIT_EXPECT_EQ(test, TRANS2_CREATE_DIRECTORY, 0x0d);
	KUNIT_EXPECT_EQ(test, TRANS2_GET_DFS_REFERRAL, 0x10);
}

static void test_smb1_nt_transact_subcmds(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, NT_TRANSACT_CREATE, 0x01);
	KUNIT_EXPECT_EQ(test, NT_TRANSACT_IOCTL, 0x02);
	KUNIT_EXPECT_EQ(test, NT_TRANSACT_SET_SECURITY_DESC, 0x03);
	KUNIT_EXPECT_EQ(test, NT_TRANSACT_NOTIFY_CHANGE, 0x04);
	KUNIT_EXPECT_EQ(test, NT_TRANSACT_RENAME, 0x05);
	KUNIT_EXPECT_EQ(test, NT_TRANSACT_QUERY_SECURITY_DESC, 0x06);
	KUNIT_EXPECT_EQ(test, NT_TRANSACT_GET_USER_QUOTA, 0x07);
	KUNIT_EXPECT_EQ(test, NT_TRANSACT_SET_USER_QUOTA, 0x08);
}

/* ──────────────────────────────────────────────────────────
 * Open/Create structures
 * ────────────────────────────────────────────────────────── */

static void test_smb1_open_andx_structure(struct kunit *test)
{
	/* NT_CREATE_ANDX request structure */
	KUNIT_EXPECT_GT(test,
		(unsigned int)sizeof(struct smb_com_open_req),
		(unsigned int)sizeof(struct smb_hdr));

	/* NameLength field offset */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_com_open_req, NameLength),
		(unsigned int)(sizeof(struct smb_hdr) + 1 + 1 + 2 + 1));
}

static void test_smb1_open_rsp_structure(struct kunit *test)
{
	/* Open response has OplockLevel, Fid, CreateAction, timestamps */
	KUNIT_EXPECT_GT(test,
		(unsigned int)sizeof(struct smb_com_open_rsp),
		(unsigned int)sizeof(struct smb_hdr) + 20u);

	/* OplockLevel follows hdr + AndX block */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_com_open_rsp, OplockLevel),
		(unsigned int)(sizeof(struct smb_hdr) + 1 + 1 + 2));
}

/* ──────────────────────────────────────────────────────────
 * Locking structure
 * ────────────────────────────────────────────────────────── */

static void test_smb1_locking_andx_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned int)LOCKING_ANDX_SHARED_LOCK, 0x01u);
	KUNIT_EXPECT_EQ(test, (unsigned int)LOCKING_ANDX_OPLOCK_RELEASE, 0x02u);
	KUNIT_EXPECT_EQ(test, (unsigned int)LOCKING_ANDX_CHANGE_LOCKTYPE, 0x04u);
	KUNIT_EXPECT_EQ(test, (unsigned int)LOCKING_ANDX_CANCEL_LOCK, 0x08u);
	KUNIT_EXPECT_EQ(test, (unsigned int)LOCKING_ANDX_LARGE_FILES, 0x10u);
}

static void test_smb1_locking_range64_size(struct kunit *test)
{
	/*
	 * 64-bit lock range: Pid(2) + Pad(2) + OffsetHigh(4) + OffsetLow(4)
	 *   + LengthHigh(4) + LengthLow(4) = 20 bytes
	 */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)sizeof(struct locking_andx_range64), 20u);
}

static void test_smb1_locking_range32_size(struct kunit *test)
{
	/*
	 * 32-bit lock range: Pid(2) + Offset(4) + Length(4) = 10 bytes
	 */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)sizeof(struct locking_andx_range32), 10u);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_smb1_pdu_test_cases[] = {
	/* Protocol constants */
	KUNIT_CASE(test_smb1_max_mpx_count),
	KUNIT_CASE(test_smb1_max_raw_size),
	KUNIT_CASE(test_smb1_max_vcs),
	KUNIT_CASE(test_smb1_protocol_string),
	KUNIT_CASE(test_smb1_capabilities_no_lock_and_read),
	KUNIT_CASE(test_smb1_capabilities_required_flags),
	/* SMB1 header structure */
	KUNIT_CASE(test_smb1_header_size),
	KUNIT_CASE(test_smb1_protocol_magic),
	KUNIT_CASE(test_smb1_header_field_offsets),
	/* Command codes */
	KUNIT_CASE(test_smb1_command_codes),
	/* Negotiate */
	KUNIT_CASE(test_smb1_negotiate_rsp_structure),
	KUNIT_CASE(test_smb1_negotiate_capabilities_field),
	KUNIT_CASE(test_smb1_negotiate_security_mode),
	KUNIT_CASE(test_smb1_negotiate_max_buffer_size),
	/* Session setup */
	KUNIT_CASE(test_smb1_session_setup_andx),
	KUNIT_CASE(test_smb1_session_flags),
	KUNIT_CASE(test_smb1_session_no_more_andx),
	/* Tree connect */
	KUNIT_CASE(test_smb1_tree_connect_andx),
	KUNIT_CASE(test_smb1_service_types),
	KUNIT_CASE(test_smb1_native_fs),
	KUNIT_CASE(test_smb1_tcon_flags),
	/* Command structures */
	KUNIT_CASE(test_smb1_read_andx_structure),
	KUNIT_CASE(test_smb1_write_andx_structure),
	KUNIT_CASE(test_smb1_close_structure),
	KUNIT_CASE(test_smb1_close_rsp_structure),
	KUNIT_CASE(test_smb1_find_first2),
	KUNIT_CASE(test_smb1_find_response_params),
	/* Error mapping */
	KUNIT_CASE(test_smb1_error_class_codes),
	KUNIT_CASE(test_smb1_dos_error_codes),
	KUNIT_CASE(test_smb1_srv_error_codes),
	/* Flags */
	KUNIT_CASE(test_smb1_flags),
	KUNIT_CASE(test_smb1_flags2),
	/* Transact subcommands */
	KUNIT_CASE(test_smb1_trans2_subcmds),
	KUNIT_CASE(test_smb1_nt_transact_subcmds),
	/* Open/Create */
	KUNIT_CASE(test_smb1_open_andx_structure),
	KUNIT_CASE(test_smb1_open_rsp_structure),
	/* Locking */
	KUNIT_CASE(test_smb1_locking_andx_constants),
	KUNIT_CASE(test_smb1_locking_range64_size),
	KUNIT_CASE(test_smb1_locking_range32_size),
	{}
};

static struct kunit_suite ksmbd_smb1_pdu_test_suite = {
	.name = "ksmbd_smb1_pdu",
	.test_cases = ksmbd_smb1_pdu_test_cases,
};

kunit_test_suite(ksmbd_smb1_pdu_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB1 protocol constants, structures, and helpers");
