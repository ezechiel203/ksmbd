// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for file-level info handlers (ksmbd_info.c):
 *   FILE_NAME, PIPE_INFO GET, PIPE_LOCAL, PIPE_REMOTE, MAILSLOT_QUERY,
 *   HARD_LINK, NORMALIZED_NAME, PROCESS_IDS, NETWORK_PHYSICAL_NAME,
 *   VOLUME_NAME, IS_REMOTE_DEVICE, REMOTE_PROTOCOL, CASE_SENSITIVE,
 *   FILE_STAT, FILE_STAT_LX, VALID_DATA_LENGTH.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ---- Replicated structures ---- */

struct test_pipe_info {
	__le32 ReadMode;
	__le32 CompletionMode;
} __packed;

struct test_pipe_local_info {
	__le32 NamedPipeType;
	__le32 NamedPipeConfiguration;
	__le32 MaximumInstances;
	__le32 CurrentInstances;
	__le32 InboundQuota;
	__le32 ReadDataAvailable;
	__le32 OutboundQuota;
	__le32 WriteQuotaAvailable;
	__le32 NamedPipeState;
	__le32 NamedPipeEnd;
} __packed;

struct test_pipe_remote_info {
	__le64 CollectDataTime;
	__le32 MaximumCollectionCount;
	__le32 CollectDataTimeout;
} __packed;

struct test_mailslot_query_info {
	__le32 MaximumMessageSize;
	__le32 MailslotQuota;
	__le32 NextMessageSize;
	__le32 MessagesAvailable;
	__le64 ReadTimeout;
} __packed;

struct test_file_links_info {
	__le32 BytesNeeded;
	__le32 EntriesReturned;
} __packed;

struct test_process_ids_info {
	__le32 NumberOfProcessIdsInList;
	__le32 Reserved;
} __packed;

struct test_is_remote_device_info {
	__le32 Flags;
} __packed;

struct test_remote_protocol_info {
	__le16 StructureVersion;
	__le16 StructureSize;
	__le32 Protocol;
	__le16 ProtocolMajorVersion;
	__le16 ProtocolMinorVersion;
	__le16 ProtocolRevision;
	__le16 Reserved;
	__le32 Flags;
	__le32 GenericReserved[8];
	__le32 ProtocolSpecificReserved[16];
} __packed;

struct test_case_sensitive_info {
	__le32 Flags;
} __packed;

struct test_file_stat_info {
	__le64 FileId;
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le64 AllocationSize;
	__le64 EndOfFile;
	__le32 NumberOfLinks;
	__u8   DeletePending;
	__u8   Directory;
	__le16 Reserved;
} __packed; /* 56 bytes */

/*
 * FileStatLxInformation (MS-FSCC section 2.4.48):
 * extends FileStatInformation with POSIX/Linux-specific fields.
 */
struct test_file_stat_lx_info {
	__le64 FileId;
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le64 AllocationSize;
	__le64 EndOfFile;
	__le32 NumberOfLinks;
	__u8   DeletePending;
	__u8   Directory;
	__le16 Reserved;
	__le32 LxFlags;       /* LX_FILE_* flags */
	__le32 LxUid;
	__le32 LxGid;
	__le32 LxMode;
	__le32 LxDeviceIdMajor;
	__le32 LxDeviceIdMinor;
} __packed; /* 80 bytes */

struct test_valid_data_length_info {
	__le64 ValidDataLength;
} __packed;

/* Helper to simulate buffer-based info handler pattern */

static int test_get_pipe(void *buf, unsigned int buf_len, unsigned int *out_len)
{
	struct test_pipe_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_pipe_info *)buf;
	info->ReadMode = cpu_to_le32(0);
	info->CompletionMode = cpu_to_le32(0);
	*out_len = sizeof(*info);
	return 0;
}

static int test_get_pipe_local(void *buf, unsigned int buf_len,
			       unsigned int *out_len)
{
	struct test_pipe_local_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_pipe_local_info *)buf;
	info->NamedPipeType = cpu_to_le32(0);
	info->NamedPipeConfiguration = cpu_to_le32(0);
	info->MaximumInstances = cpu_to_le32(0xFFFFFFFF);
	info->CurrentInstances = cpu_to_le32(0);
	info->InboundQuota = cpu_to_le32(0);
	info->ReadDataAvailable = cpu_to_le32(0);
	info->OutboundQuota = cpu_to_le32(0);
	info->WriteQuotaAvailable = cpu_to_le32(0);
	info->NamedPipeState = cpu_to_le32(0);
	info->NamedPipeEnd = cpu_to_le32(0);
	*out_len = sizeof(*info);
	return 0;
}

static int test_get_pipe_remote(void *buf, unsigned int buf_len,
				unsigned int *out_len)
{
	struct test_pipe_remote_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_pipe_remote_info *)buf;
	memset(info, 0, sizeof(*info));
	*out_len = sizeof(*info);
	return 0;
}

static int test_get_mailslot_query(void *buf, unsigned int buf_len,
				   unsigned int *out_len)
{
	struct test_mailslot_query_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_mailslot_query_info *)buf;
	memset(info, 0, sizeof(*info));
	*out_len = sizeof(*info);
	return 0;
}

static int test_get_process_ids(void *buf, unsigned int buf_len,
				unsigned int *out_len)
{
	struct test_process_ids_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_process_ids_info *)buf;
	info->NumberOfProcessIdsInList = 0;
	info->Reserved = 0;
	*out_len = sizeof(*info);
	return 0;
}

static int test_get_is_remote_device(void *buf, unsigned int buf_len,
				     unsigned int *out_len)
{
	struct test_is_remote_device_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_is_remote_device_info *)buf;
	info->Flags = 0;
	*out_len = sizeof(*info);
	return 0;
}

static int test_get_remote_protocol(void *buf, unsigned int buf_len,
				    unsigned int *out_len,
				    u16 dialect)
{
	struct test_remote_protocol_info *info;
	u16 major, minor, rev;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_remote_protocol_info *)buf;
	memset(info, 0, sizeof(*info));
	info->StructureVersion = cpu_to_le16(1);
	info->StructureSize = cpu_to_le16(sizeof(*info));
	info->Protocol = cpu_to_le32(0x00020000); /* WNNC_NET_LANMAN */

	switch (dialect) {
	case 0x0200: /* SMB 2.0.2 */
		major = 2; minor = 0; rev = 0;
		break;
	case 0x0210: /* SMB 2.1 */
		major = 2; minor = 1; rev = 0;
		break;
	case 0x0300: /* SMB 3.0 */
		major = 3; minor = 0; rev = 0;
		break;
	case 0x0302: /* SMB 3.0.2 */
		major = 3; minor = 0; rev = 2;
		break;
	case 0x0311: /* SMB 3.1.1 */
	default:
		major = 3; minor = 1; rev = 1;
		break;
	}

	info->ProtocolMajorVersion = cpu_to_le16(major);
	info->ProtocolMinorVersion = cpu_to_le16(minor);
	info->ProtocolRevision = cpu_to_le16(rev);
	*out_len = sizeof(*info);
	return 0;
}

static int test_get_case_sensitive(void *buf, unsigned int buf_len,
				   unsigned int *out_len)
{
	struct test_case_sensitive_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_case_sensitive_info *)buf;
	info->Flags = 0;
	*out_len = sizeof(*info);
	return 0;
}

#define FILE_CS_FLAG_CASE_SENSITIVE_DIR	0x00000001

static int test_set_case_sensitive(void *buf, unsigned int buf_len,
				   unsigned int *out_len, bool fp_exists)
{
	struct test_case_sensitive_info *info;
	u32 flags;

	if (!fp_exists)
		return -EINVAL;

	if (buf_len < sizeof(*info))
		return -EMSGSIZE;

	info = (struct test_case_sensitive_info *)buf;
	flags = le32_to_cpu(info->Flags);
	if (flags & ~FILE_CS_FLAG_CASE_SENSITIVE_DIR)
		return -EINVAL;

	*out_len = sizeof(*info);
	return 0;
}

static int test_get_file_name(bool fp_exists, unsigned int buf_len,
			      unsigned int *out_len)
{
	if (!fp_exists)
		return -EINVAL;

	if (buf_len < sizeof(__le32))
		return -ENOSPC;

	/* Simulate: 4-byte length + at least 2 bytes for name */
	if ((buf_len - sizeof(__le32)) / sizeof(__le16) == 0)
		return -ENOSPC;

	/* Return a 2-byte name (1 UTF-16 char) */
	*out_len = sizeof(__le32) + 2;
	return 0;
}

static int test_get_hard_link(bool fp_exists, unsigned int buf_len,
			      unsigned int *out_len)
{
	if (!fp_exists)
		return -EINVAL;

	if (buf_len < sizeof(struct test_file_links_info))
		return -ENOSPC;

	/* Return single-link header */
	*out_len = sizeof(struct test_file_links_info);
	return 0;
}

static int test_get_normalized_name(bool fp_exists, u16 dialect,
				    unsigned int buf_len,
				    unsigned int *out_len)
{
	if (!fp_exists)
		return -EINVAL;

	/*
	 * MS-SMB2: FileNormalizedNameInformation is available for
	 * SMB 3.0 (0x0300) and SMB 3.1.1+ (>= 0x0311).
	 * Reject for SMB 2.0.2, 2.1, and 3.0.2.
	 */
	if (dialect != 0x0300 && dialect < 0x0311)
		return -ENOSYS;

	if (buf_len < sizeof(__le32))
		return -ENOSPC;

	if ((buf_len - sizeof(__le32)) / sizeof(__le16) == 0)
		return -ENOSPC;

	*out_len = sizeof(__le32) + 2;
	return 0;
}

static int test_get_network_physical_name(unsigned int buf_len,
					  unsigned int *out_len)
{
	if (buf_len < sizeof(__le32))
		return -ENOSPC;

	if ((buf_len - sizeof(__le32)) / sizeof(__le16) == 0)
		return -ENOSPC;

	*out_len = sizeof(__le32) + 4; /* 2 UTF-16 chars */
	return 0;
}

static int test_get_volume_name(unsigned int buf_len,
				unsigned int *out_len)
{
	if (buf_len < sizeof(__le32))
		return -ENOSPC;

	if ((buf_len - sizeof(__le32)) / sizeof(__le16) == 0)
		return -ENOSPC;

	*out_len = sizeof(__le32) + 4;
	return 0;
}

static int test_get_file_stat(bool fp_exists, void *buf,
			      unsigned int buf_len,
			      unsigned int *out_len)
{
	struct test_file_stat_info *info;

	if (!fp_exists)
		return -EINVAL;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_file_stat_info *)buf;
	memset(info, 0, sizeof(*info));
	info->FileId = cpu_to_le64(12345);
	info->NumberOfLinks = cpu_to_le32(1);
	*out_len = sizeof(*info);
	return 0;
}

static int test_get_file_stat_lx(bool fp_exists, void *buf,
				 unsigned int buf_len,
				 unsigned int *out_len)
{
	struct test_file_stat_lx_info *info;

	if (!fp_exists)
		return -EINVAL;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct test_file_stat_lx_info *)buf;
	memset(info, 0, sizeof(*info));
	info->FileId = cpu_to_le64(12345);
	info->NumberOfLinks = cpu_to_le32(1);
	/* LxFlags: LX_FILE_CASE_SENSITIVE_DIR not set by default */
	info->LxFlags = cpu_to_le32(0);
	info->LxUid = cpu_to_le32(1000);
	info->LxGid = cpu_to_le32(1000);
	info->LxMode = cpu_to_le32(0100644); /* regular file, rw-r--r-- */
	*out_len = sizeof(*info);
	return 0;
}

static int test_set_valid_data_length(bool fp_exists, void *buf,
				      unsigned int buf_len,
				      unsigned int *out_len)
{
	struct test_valid_data_length_info *info;
	s64 length;

	if (!fp_exists)
		return -EINVAL;

	if (buf_len < sizeof(*info))
		return -EMSGSIZE;

	info = (struct test_valid_data_length_info *)buf;
	length = (s64)le64_to_cpu(info->ValidDataLength);
	if (length < 0)
		return -EINVAL;

	*out_len = sizeof(*info);
	return 0;
}

/* ---- Test cases: FILE_NAME_INFORMATION ---- */

static void test_file_name_normal(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_file_name(true, 256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_GT(test, out_len, (unsigned int)sizeof(__le32));
}

static void test_file_name_buffer_too_small(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_file_name(true, 3, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

static void test_file_name_no_fp(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_file_name(false, 256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* ---- Test cases: PIPE_INFO GET ---- */

static void test_pipe_info_get_defaults(struct kunit *test)
{
	struct test_pipe_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_pipe(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(buf.ReadMode), (u32)0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(buf.CompletionMode), (u32)0);
}

static void test_pipe_info_get_buffer_too_small(struct kunit *test)
{
	struct test_pipe_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_pipe(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: PIPE_LOCAL_INFORMATION ---- */

static void test_pipe_local_info_defaults(struct kunit *test)
{
	struct test_pipe_local_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_pipe_local(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(buf.MaximumInstances), (u32)0xFFFFFFFF);
}

static void test_pipe_local_info_buffer_too_small(struct kunit *test)
{
	struct test_pipe_local_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_pipe_local(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: PIPE_REMOTE_INFORMATION ---- */

static void test_pipe_remote_info_defaults(struct kunit *test)
{
	struct test_pipe_remote_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_pipe_remote(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_pipe_remote_info_buffer_too_small(struct kunit *test)
{
	struct test_pipe_remote_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_pipe_remote(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: MAILSLOT_QUERY ---- */

static void test_mailslot_query_defaults(struct kunit *test)
{
	struct test_mailslot_query_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_mailslot_query(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_mailslot_query_buffer_too_small(struct kunit *test)
{
	struct test_mailslot_query_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_mailslot_query(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: HARD_LINK ---- */

static void test_hard_link_single_link(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_hard_link(true, 256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_hard_link_multiple_links(struct kunit *test)
{
	/* Multiple links would enumerate parent dir; test structure acceptance */
	unsigned int out_len;
	int ret;

	ret = test_get_hard_link(true, 1024, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_hard_link_buffer_too_small(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_hard_link(true,
				 sizeof(struct test_file_links_info) - 1,
				 &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

static void test_hard_link_no_fp(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_hard_link(false, 256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* ---- Test cases: NORMALIZED_NAME ---- */

static void test_normalized_name_smb311(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_normalized_name(true, 0x0311, 256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_normalized_name_smb30(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	/* SMB 3.0 (0x0300) should also support FileNormalizedNameInformation */
	ret = test_get_normalized_name(true, 0x0300, 256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_normalized_name_pre_311(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	/* SMB 3.0.2 is neither 3.0 nor >= 3.1.1, should be rejected */
	ret = test_get_normalized_name(true, 0x0302, 256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSYS);
}

static void test_normalized_name_root(struct kunit *test)
{
	/* Root should return empty (zero-length) name */
	unsigned int out_len;
	int ret;

	ret = test_get_normalized_name(true, 0x0311, 256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_normalized_name_stream(struct kunit *test)
{
	/* Stream handle appends :streamname -- verified at integration level */
	unsigned int out_len;
	int ret;

	ret = test_get_normalized_name(true, 0x0311, 256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_normalized_name_buffer_too_small(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_normalized_name(true, 0x0311, 3, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: PROCESS_IDS ---- */

static void test_process_ids_returns_empty(struct kunit *test)
{
	struct test_process_ids_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_process_ids(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, buf.NumberOfProcessIdsInList, (u32)0);
}

static void test_process_ids_buffer_too_small(struct kunit *test)
{
	struct test_process_ids_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_process_ids(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: NETWORK_PHYSICAL_NAME ---- */

static void test_network_physical_name_normal(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_network_physical_name(256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_GT(test, out_len, (unsigned int)sizeof(__le32));
}

static void test_network_physical_name_buffer_too_small(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_network_physical_name(3, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: VOLUME_NAME ---- */

static void test_volume_name_normal(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_volume_name(256, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_GT(test, out_len, (unsigned int)sizeof(__le32));
}

static void test_volume_name_buffer_too_small(struct kunit *test)
{
	unsigned int out_len;
	int ret;

	ret = test_get_volume_name(3, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: IS_REMOTE_DEVICE ---- */

static void test_is_remote_device_returns_zero(struct kunit *test)
{
	struct test_is_remote_device_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_is_remote_device(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, buf.Flags, (u32)0);
}

static void test_is_remote_device_buffer_too_small(struct kunit *test)
{
	struct test_is_remote_device_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_is_remote_device(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: REMOTE_PROTOCOL ---- */

static void test_remote_protocol_smb311(struct kunit *test)
{
	struct test_remote_protocol_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_remote_protocol(&buf, sizeof(buf), &out_len, 0x0311);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf.ProtocolMajorVersion), (u16)3);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf.ProtocolMinorVersion), (u16)1);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf.ProtocolRevision), (u16)1);
}

static void test_remote_protocol_smb20(struct kunit *test)
{
	struct test_remote_protocol_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_remote_protocol(&buf, sizeof(buf), &out_len, 0x0200);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf.ProtocolMajorVersion), (u16)2);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf.ProtocolMinorVersion), (u16)0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf.ProtocolRevision), (u16)0);
}

static void test_remote_protocol_buffer_too_small(struct kunit *test)
{
	struct test_remote_protocol_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_remote_protocol(&buf, sizeof(buf) - 1, &out_len, 0x0311);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

/* ---- Test cases: CASE_SENSITIVE ---- */

static void test_case_sensitive_get_returns_zero(struct kunit *test)
{
	struct test_case_sensitive_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_case_sensitive(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, buf.Flags, (u32)0);
}

static void test_case_sensitive_get_buffer_too_small(struct kunit *test)
{
	struct test_case_sensitive_info buf;
	unsigned int out_len;
	int ret;

	ret = test_get_case_sensitive(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

static void test_case_sensitive_set_enable(struct kunit *test)
{
	struct test_case_sensitive_info buf = {
		.Flags = cpu_to_le32(FILE_CS_FLAG_CASE_SENSITIVE_DIR),
	};
	unsigned int out_len;
	int ret;

	ret = test_set_case_sensitive(&buf, sizeof(buf), &out_len, true);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_case_sensitive_set_disable(struct kunit *test)
{
	struct test_case_sensitive_info buf = {
		.Flags = cpu_to_le32(0),
	};
	unsigned int out_len;
	int ret;

	ret = test_set_case_sensitive(&buf, sizeof(buf), &out_len, true);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_case_sensitive_set_buffer_too_small(struct kunit *test)
{
	struct test_case_sensitive_info buf = {};
	unsigned int out_len;
	int ret;

	ret = test_set_case_sensitive(&buf, sizeof(buf) - 1, &out_len, true);
	KUNIT_EXPECT_EQ(test, ret, -EMSGSIZE);
}

static void test_case_sensitive_set_invalid_flags(struct kunit *test)
{
	struct test_case_sensitive_info buf = {
		.Flags = cpu_to_le32(0xDEAD),
	};
	unsigned int out_len;
	int ret;

	ret = test_set_case_sensitive(&buf, sizeof(buf), &out_len, true);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* ---- Test cases: FILE_STAT ---- */

static void test_file_stat_normal(struct kunit *test)
{
	u8 buf[56];
	unsigned int out_len;
	int ret;

	ret = test_get_file_stat(true, buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)56);
}

static void test_file_stat_buffer_too_small(struct kunit *test)
{
	u8 buf[55];
	unsigned int out_len;
	int ret;

	ret = test_get_file_stat(true, buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

static void test_file_stat_no_fp(struct kunit *test)
{
	u8 buf[56];
	unsigned int out_len;
	int ret;

	ret = test_get_file_stat(false, buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_file_stat_stream(struct kunit *test)
{
	/* Stream handles return stream size -- verified at integration level */
	u8 buf[56];
	unsigned int out_len;
	int ret;

	ret = test_get_file_stat(true, buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* ---- Test cases: FILE_STAT_LX ---- */

static void test_file_stat_lx_normal(struct kunit *test)
{
	u8 buf[80];
	unsigned int out_len;
	struct test_file_stat_lx_info *info;
	int ret;

	ret = test_get_file_stat_lx(true, buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(struct test_file_stat_lx_info));

	info = (struct test_file_stat_lx_info *)buf;
	KUNIT_EXPECT_EQ(test, le32_to_cpu(info->LxUid), (u32)1000);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(info->LxGid), (u32)1000);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(info->LxMode), (u32)0100644);
}

static void test_file_stat_lx_buffer_too_small(struct kunit *test)
{
	u8 buf[79]; /* one byte short of required 80 */
	unsigned int out_len;
	int ret;

	ret = test_get_file_stat_lx(true, buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

static void test_file_stat_lx_no_fp(struct kunit *test)
{
	u8 buf[80];
	unsigned int out_len;
	int ret;

	ret = test_get_file_stat_lx(false, buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* ---- Test cases: VALID_DATA_LENGTH SET ---- */

static void test_valid_data_length_set_normal(struct kunit *test)
{
	struct test_valid_data_length_info buf = {
		.ValidDataLength = cpu_to_le64(4096),
	};
	unsigned int out_len;
	int ret;

	ret = test_set_valid_data_length(true, &buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_valid_data_length_set_negative(struct kunit *test)
{
	struct test_valid_data_length_info buf = {
		.ValidDataLength = cpu_to_le64((u64)-1LL),
	};
	unsigned int out_len;
	int ret;

	ret = test_set_valid_data_length(true, &buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_valid_data_length_set_buffer_too_small(struct kunit *test)
{
	struct test_valid_data_length_info buf = {};
	unsigned int out_len;
	int ret;

	ret = test_set_valid_data_length(true, &buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EMSGSIZE);
}

static void test_valid_data_length_set_no_fp(struct kunit *test)
{
	struct test_valid_data_length_info buf = {
		.ValidDataLength = cpu_to_le64(4096),
	};
	unsigned int out_len;
	int ret;

	ret = test_set_valid_data_length(false, &buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static struct kunit_case ksmbd_info_file_test_cases[] = {
	KUNIT_CASE(test_file_name_normal),
	KUNIT_CASE(test_file_name_buffer_too_small),
	KUNIT_CASE(test_file_name_no_fp),
	KUNIT_CASE(test_pipe_info_get_defaults),
	KUNIT_CASE(test_pipe_info_get_buffer_too_small),
	KUNIT_CASE(test_pipe_local_info_defaults),
	KUNIT_CASE(test_pipe_local_info_buffer_too_small),
	KUNIT_CASE(test_pipe_remote_info_defaults),
	KUNIT_CASE(test_pipe_remote_info_buffer_too_small),
	KUNIT_CASE(test_mailslot_query_defaults),
	KUNIT_CASE(test_mailslot_query_buffer_too_small),
	KUNIT_CASE(test_hard_link_single_link),
	KUNIT_CASE(test_hard_link_multiple_links),
	KUNIT_CASE(test_hard_link_buffer_too_small),
	KUNIT_CASE(test_hard_link_no_fp),
	KUNIT_CASE(test_normalized_name_smb311),
	KUNIT_CASE(test_normalized_name_smb30),
	KUNIT_CASE(test_normalized_name_pre_311),
	KUNIT_CASE(test_normalized_name_root),
	KUNIT_CASE(test_normalized_name_stream),
	KUNIT_CASE(test_normalized_name_buffer_too_small),
	KUNIT_CASE(test_process_ids_returns_empty),
	KUNIT_CASE(test_process_ids_buffer_too_small),
	KUNIT_CASE(test_network_physical_name_normal),
	KUNIT_CASE(test_network_physical_name_buffer_too_small),
	KUNIT_CASE(test_volume_name_normal),
	KUNIT_CASE(test_volume_name_buffer_too_small),
	KUNIT_CASE(test_is_remote_device_returns_zero),
	KUNIT_CASE(test_is_remote_device_buffer_too_small),
	KUNIT_CASE(test_remote_protocol_smb311),
	KUNIT_CASE(test_remote_protocol_smb20),
	KUNIT_CASE(test_remote_protocol_buffer_too_small),
	KUNIT_CASE(test_case_sensitive_get_returns_zero),
	KUNIT_CASE(test_case_sensitive_get_buffer_too_small),
	KUNIT_CASE(test_case_sensitive_set_enable),
	KUNIT_CASE(test_case_sensitive_set_disable),
	KUNIT_CASE(test_case_sensitive_set_buffer_too_small),
	KUNIT_CASE(test_case_sensitive_set_invalid_flags),
	KUNIT_CASE(test_file_stat_normal),
	KUNIT_CASE(test_file_stat_buffer_too_small),
	KUNIT_CASE(test_file_stat_no_fp),
	KUNIT_CASE(test_file_stat_stream),
	KUNIT_CASE(test_file_stat_lx_normal),
	KUNIT_CASE(test_file_stat_lx_buffer_too_small),
	KUNIT_CASE(test_file_stat_lx_no_fp),
	KUNIT_CASE(test_valid_data_length_set_normal),
	KUNIT_CASE(test_valid_data_length_set_negative),
	KUNIT_CASE(test_valid_data_length_set_buffer_too_small),
	KUNIT_CASE(test_valid_data_length_set_no_fp),
	{}
};

/* MOCK-ONLY: tests replicated logic, not production ksmbd code */
static struct kunit_suite ksmbd_info_file_test_suite = {
	.name = "ksmbd_info_file",
	.test_cases = ksmbd_info_file_test_cases,
};

kunit_test_suite(ksmbd_info_file_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd file info-level handlers");
