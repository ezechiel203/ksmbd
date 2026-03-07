# Audit Read Write Tests

Agent ID: a7e831148797e1eef

Now let me look at the spec to understand whether DATA_OFFSET for write request has a DataOffset > 0x100 check.

I already have the spec text from section 3.3.5.13:
> "If Channel is equal to SMB2_CHANNEL_NONE and DataOffset is greater than 0x100, the server MUST fail the request with STATUS_INVALID_PARAMETER."

Now I have all the information for a comprehensive audit. Let me compile the full report.

---

# AUDIT REPORT: SMB2 READ/WRITE KUnit Test Files vs. MS-SMB2 Specification

## File 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_read_write.c`

This test file calls `VISIBLE_IF_KUNIT`-exported helper functions from `smb2_read_write.c`. **Critical note**: These helper functions (`smb2_validate_read_offset`, `smb2_validate_read_range`, etc.) do not currently exist in the source tree. They are not yet extracted from the production code. The tests reference functions that have not been implemented, making this entire test file **non-compilable**. The audit below evaluates the assertions against the spec assuming the functions would implement what the test names suggest.

### smb2_validate_read_offset tests

**test_read_offset_zero** (line 24-27): Expects `smb2_validate_read_offset(0) == 0`.
- **CORRECT**. Offset 0 is valid per MS-SMB2 section 2.2.19 (no constraint on offset value in the wire format; the server processes it against the underlying file).

**test_read_offset_normal** (line 29-32): Expects `smb2_validate_read_offset(4096) == 0`.
- **CORRECT**. Normal offset within file range.

**test_read_offset_max_lfs** (line 34-38): Expects `smb2_validate_read_offset(MAX_LFS_FILESIZE) == 0`.
- **QUESTIONABLE**. The MS-SMB2 spec does not define a maximum read offset. The Offset field is an unsigned 64-bit value (8 bytes). `MAX_LFS_FILESIZE` is a Linux VFS internal limit, not an SMB2 protocol limit. The spec says the offset is "in bytes, into the file from which the data MUST be read" -- the server is expected to perform the read and return an error from the underlying file system (like STATUS_END_OF_FILE) if the offset exceeds the file size. Rejecting at `MAX_LFS_FILESIZE + 1` (test below) is a VFS safety guard, not a protocol requirement. This is acceptable as an implementation detail but does not directly correspond to a spec requirement.

**test_read_offset_negative** (line 40-46): Expects `smb2_validate_read_offset(neg) == -EINVAL` where neg = LLONG_MAX+1 (i.e., loff_t bit 63 set).
- **CORRECT** as an implementation guard. The SMB2 offset field is unsigned 64-bit on the wire, but Linux's `loff_t` is signed 64-bit. Values with bit 63 set would be negative in `loff_t`, which is invalid for VFS operations.

**test_read_offset_beyond_max_lfs** (line 48-52): Expects `smb2_validate_read_offset(MAX_LFS_FILESIZE + 1) == -EINVAL`.
- **CORRECT** as implementation guard. Same reasoning as above -- VFS safety limit.

**test_read_offset_minus_one** (line 54-60): Expects offset `0xFFFFFFFFFFFFFFFF` cast to `loff_t` == -1, rejected as `-EINVAL`.
- **CORRECT**. For READ, the spec has no "append-to-EOF" sentinel like WRITE does. The value 0xFFFFFFFFFFFFFFFF is simply a very large offset that becomes -1 in signed representation, which should be rejected.

### smb2_validate_read_range tests

**test_read_range_normal** (line 64-67): `smb2_validate_read_range(0, 4096) == 0`.
- **CORRECT**.

**test_read_range_zero_length** (line 69-73): `smb2_validate_read_range(MAX_LFS_FILESIZE, 0) == 0`.
- **CORRECT**. MS-SMB2 section 2.2.19: "The length of the data being read can be zero bytes."

**test_read_range_at_boundary** (line 75-79): `smb2_validate_read_range(MAX_LFS_FILESIZE - 1, 1) == 0`.
- **CORRECT**. Offset + length == MAX_LFS_FILESIZE, no overflow.

**test_read_range_overflow** (line 81-86): `smb2_validate_read_range(MAX_LFS_FILESIZE - 5, 10) == -EINVAL`.
- **CORRECT**. Offset + length > MAX_LFS_FILESIZE would overflow. Production code at line 480 of `smb2_read_write.c` checks: `if (length > 0 && offset > MAX_LFS_FILESIZE - (loff_t)length)`.

**test_read_range_large_offset_small_len** (line 88-92): `smb2_validate_read_range(MAX_LFS_FILESIZE, 1) == -EINVAL`.
- **CORRECT**. MAX_LFS_FILESIZE + 1 exceeds the limit.

**test_read_range_offset_zero_large_len** (line 94-100): `smb2_validate_read_range(0, (size_t)MAX_LFS_FILESIZE + 1) == -EINVAL`.
- **CORRECT**. Length > MAX_LFS_FILESIZE from offset 0 exceeds the limit.

### smb2_validate_read_access tests

**test_read_access_read_data** (line 104-107): `smb2_validate_read_access(FILE_READ_DATA_LE) == 0`.
- **CORRECT**. MS-SMB2 section 3.3.5.12: "If Open.GrantedAccess does not allow for FILE_READ_DATA, the request MUST be failed with STATUS_ACCESS_DENIED."

**test_read_access_read_attributes** (line 109-112): `smb2_validate_read_access(FILE_READ_ATTRIBUTES_LE) == 0`.
- **WRONG**. MS-SMB2 section 3.3.5.12 only requires `FILE_READ_DATA` for read access. `FILE_READ_ATTRIBUTES` alone should NOT be sufficient to perform a read operation. The spec says "If Open.GrantedAccess does not allow for FILE_READ_DATA" -- so only FILE_READ_DATA matters. The production code at line 458 does check `FILE_READ_DATA_LE | FILE_READ_ATTRIBUTES_LE`, which is a ksmbd extension (perhaps for compatibility), but per the spec, `FILE_READ_ATTRIBUTES_LE` alone should result in STATUS_ACCESS_DENIED. **Spec ref: MS-SMB2 section 3.3.5.12.**

**test_read_access_both** (line 114-118): `smb2_validate_read_access(FILE_READ_DATA_LE | FILE_READ_ATTRIBUTES_LE) == 0`.
- **CORRECT** (because FILE_READ_DATA is present).

**test_read_access_write_only** (line 120-124): `smb2_validate_read_access(FILE_WRITE_DATA_LE) == -EACCES`.
- **CORRECT**. No FILE_READ_DATA.

**test_read_access_none** (line 126-129): `smb2_validate_read_access(0) == -EACCES`.
- **CORRECT**. No access at all.

### smb2_validate_write_offset tests

**test_write_offset_zero** (line 133-136): `smb2_validate_write_offset(0) == 0`.
- **CORRECT**.

**test_write_offset_normal** (line 138-141): `smb2_validate_write_offset(1024) == 0`.
- **CORRECT**.

**test_write_offset_max_lfs** (line 143-146): `smb2_validate_write_offset(MAX_LFS_FILESIZE) == 0`.
- **QUESTIONABLE** (same as read -- VFS limit, not protocol limit).

**test_write_offset_negative** (line 148-153): `smb2_validate_write_offset(neg) == -EINVAL`.
- **CORRECT** as VFS guard.

**test_write_offset_beyond_max_lfs** (line 155-159): `smb2_validate_write_offset(MAX_LFS_FILESIZE + 1) == -EINVAL`.
- **CORRECT** as VFS guard.

### smb2_validate_write_range tests

**test_write_range_normal** (line 163-166): `smb2_validate_write_range(0, 4096) == 0`.
- **CORRECT**.

**test_write_range_zero_length** (line 168-171): `smb2_validate_write_range(MAX_LFS_FILESIZE, 0) == 0`.
- **CORRECT**. MS-SMB2 section 2.2.21: "The length of the data being written can be zero bytes."

**test_write_range_zero_offset** (line 173-179): `smb2_validate_write_range(0, (size_t)MAX_LFS_FILESIZE + 10) == 0`.
- **QUESTIONABLE**. The test expects that when offset==0 and length is huge (MAX_LFS_FILESIZE+10), the result is success. The comment says "offset==0: the special case (offset > 0 check) means no overflow." Looking at the production code at line 855: `if (length > 0 && offset > 0 && offset > MAX_LFS_FILESIZE - (loff_t)length)`, the check only fires when `offset > 0`. So offset==0 skips the overflow check entirely. While this is consistent with the production code, it means the test validates a quirk: writing from offset 0 with a length exceeding MAX_LFS_FILESIZE is accepted at the validation stage (the VFS write call would handle truncation). This is **implementation-consistent but spec-neutral** -- the spec does not constrain the Length field to MAX_LFS_FILESIZE.

**test_write_range_overflow** (line 181-185): `smb2_validate_write_range(MAX_LFS_FILESIZE - 5, 10) == -EINVAL`.
- **CORRECT**.

**test_write_range_at_boundary** (line 187-191): `smb2_validate_write_range(MAX_LFS_FILESIZE - 1, 1) == 0`.
- **CORRECT**.

### smb2_validate_write_ntfs_limit tests

**test_ntfs_limit_normal** (line 195-198): `smb2_validate_write_ntfs_limit(0, 4096) == 0`.
- **CORRECT**.

**test_ntfs_limit_zero_length** (line 200-205): `smb2_validate_write_ntfs_limit(0xfffffff0000, 0) == 0`.
- **CORRECT**. Zero-length write is always valid.

**test_ntfs_limit_at_boundary** (line 207-212): `smb2_validate_write_ntfs_limit(0xfffffff0000, 1) == -EINVAL`.
- **CORRECT**. At or beyond 0xfffffff0000 should return INVALID_PARAMETER. Production code line 867: `if (length > 0 && offset >= SMB2_MAX_FILE_OFFSET)`.

**test_ntfs_limit_beyond_boundary** (line 214-218): `smb2_validate_write_ntfs_limit(0xfffffff0001, 1) == -EINVAL`.
- **CORRECT**.

**test_ntfs_limit_extend_past** (line 220-225): `smb2_validate_write_ntfs_limit(0xfffffff0000 - 1, 2) == -ENOSPC`.
- **WRONG**. The test expects `-ENOSPC` (STATUS_DISK_FULL) but the production code at line 871 checks `if (length > 0 && offset + (loff_t)length >= SMB2_MAX_FILE_OFFSET)` which returns `-ENOSPC`. However, the offset here is `0xfffffff0000 - 1 = 0xfffffffefff`, and `offset + length = 0xfffffffefff + 2 = 0xfffffff0001`. This IS >= SMB2_MAX_FILE_OFFSET (0xfffffff0000), so `-ENOSPC` is returned. This is **CORRECT** -- the write starts below the limit but would extend past it, producing STATUS_DISK_FULL.

**test_ntfs_limit_just_under** (line 227-232): `smb2_validate_write_ntfs_limit(0xfffffff0000 - 1, 1) == -ENOSPC`.
- **WRONG**. Offset = `0xfffffffefff`, length = 1, so offset + length = `0xfffffff0000` which is exactly SMB2_MAX_FILE_OFFSET. The production code checks `>= SMB2_MAX_FILE_OFFSET`, so it returns `-ENOSPC`. But this means a write that ends exactly AT the NTFS limit is rejected. Consider: offset 0xfffffffefff is the last valid byte position. Writing 1 byte there would write TO that position (the byte at offset 0xfffffffefff). The resulting file size would be 0xfffffff0000 bytes. The NTFS max file size is 0xfffffff0000 (256 TB - 64 KB). Writing 1 byte at the position just before that limit should be valid since it doesn't exceed the limit. The production code's `>=` should arguably be `>`. **QUESTIONABLE** -- depends on whether SMB2_MAX_FILE_OFFSET represents the maximum valid file size (exclusive) or the maximum valid byte offset (inclusive). If it's the max file size, then a write at offset (max-1) with length 1 produces exactly that size, which should be valid. The test and production code may have an off-by-one error here, but the MS-SMB2 spec does not clearly define this NTFS limit.

**test_ntfs_limit_well_under** (line 234-239): `smb2_validate_write_ntfs_limit(0xfffffff, 4096) == 0`.
- **CORRECT**.

### smb2_validate_write_data_bounds tests

**test_data_bounds_valid** (line 243-247): `smb2_validate_write_data_bounds(70, 100, 256) == 0`.
- **CORRECT**. DataOffset=70 is above the minimum (offsetof Buffer), and 70+100 <= 256. Per MS-SMB2 section 3.3.5.13: "If Channel is equal to SMB2_CHANNEL_NONE and the number of bytes received in Buffer is less than (DataOffset + Length), the server MUST fail."

**test_data_bounds_offset_too_small** (line 249-254): `smb2_validate_write_data_bounds(10, 100, 256) == -EINVAL`.
- **CORRECT**. DataOffset=10 is before the Buffer field, which is invalid. Production code line 1011: `if (data_off < offsetof(struct smb2_write_req, Buffer))`.

**test_data_bounds_overflow** (line 256-261): `smb2_validate_write_data_bounds(200, 100, 256) == -EINVAL`.
- **CORRECT**. 200+100=300 > 256, data extends beyond buffer. Per MS-SMB2 section 3.3.5.13.

**test_data_bounds_exact_fit** (line 263-269): `smb2_validate_write_data_bounds(off, 256-off, 256) == 0` where `off = offsetof(struct smb2_write_req, Buffer)`.
- **CORRECT**. Exact fit, DataOffset + Length == buf_len.

**test_data_bounds_zero_length** (line 271-276): `smb2_validate_write_data_bounds(off, 0, 256) == 0`.
- **CORRECT**. Zero-length write is valid.

### smb2_is_write_to_eof tests

**test_is_write_to_eof_true** (line 280-284): `smb2_is_write_to_eof(cpu_to_le64(0xFFFFFFFFFFFFFFFF)) == true`.
- **CORRECT**. The MEMORY.md documents that 0xFFFFFFFFFFFFFFFF is the append-to-EOF sentinel. This is consistent with standard SMB2 behavior (the spec does not explicitly document this sentinel in section 2.2.21, but it is a well-known convention for WRITE operations where the client wants to append).

**test_is_write_to_eof_false_zero** (line 286-289): `smb2_is_write_to_eof(cpu_to_le64(0)) == false`.
- **CORRECT**.

**test_is_write_to_eof_false_normal** (line 291-294): `smb2_is_write_to_eof(cpu_to_le64(100)) == false`.
- **CORRECT**.

**test_is_write_to_eof_false_near_max** (line 296-300): `smb2_is_write_to_eof(cpu_to_le64(0xFFFFFFFFFFFFFFFE)) == false`.
- **CORRECT**. Only exact 0xFFFFFFFFFFFFFFFF is the sentinel.

### smb2_validate_write_to_eof_access tests

**test_eof_access_append_only** (line 304-309): `smb2_validate_write_to_eof_access(FILE_APPEND_DATA_LE) == 0`.
- **CORRECT**. MS-SMB2 section 3.3.5.13: the write-to-EOF sentinel is valid when the handle has FILE_APPEND_DATA without FILE_WRITE_DATA (append-only). Production code line 953: `if (!(fp->daccess & FILE_APPEND_DATA_LE) || (fp->daccess & FILE_WRITE_DATA_LE))`.

**test_eof_access_both** (line 311-316): `smb2_validate_write_to_eof_access(FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE) == -EINVAL`.
- **QUESTIONABLE**. The test says that having both FILE_WRITE_DATA and FILE_APPEND_DATA should reject the EOF sentinel. The production code at line 954 rejects when `fp->daccess & FILE_WRITE_DATA_LE`. This is a ksmbd design choice: for handles with FILE_WRITE_DATA, the client should specify an actual offset rather than the EOF sentinel. However, the MS-SMB2 spec in section 3.3.5.13 says: "if the range being written to extends the file size and Open.GrantedAccess does not include FILE_APPEND_DATA, the server SHOULD fail." The spec does NOT prohibit using the EOF sentinel with FILE_WRITE_DATA present. This is **debatable** but the ksmbd approach is more restrictive than necessary.

**test_eof_access_write_only** (line 318-323): `smb2_validate_write_to_eof_access(FILE_WRITE_DATA_LE) == -EINVAL`.
- **QUESTIONABLE**. Same reasoning as above. The spec does not explicitly prohibit the EOF sentinel for FILE_WRITE_DATA handles.

**test_eof_access_none** (line 325-329): `smb2_validate_write_to_eof_access(0) == -EINVAL`.
- **CORRECT**. No write access at all.

**test_eof_access_read_data** (line 331-336): `smb2_validate_write_to_eof_access(FILE_READ_DATA_LE) == -EINVAL`.
- **CORRECT**. Read-only access cannot write.

### smb2_validate_flush_access tests

**test_flush_access_write_data** (line 340-343): `smb2_validate_flush_access(FILE_WRITE_DATA_LE) == 0`.
- **CORRECT**. MS-SMB2 section 3.3.5.11: "If the Open is on a file and Open.GrantedAccess includes neither FILE_WRITE_DATA nor FILE_APPEND_DATA, the server MUST fail the request with STATUS_ACCESS_DENIED."

**test_flush_access_append_data** (line 345-348): `smb2_validate_flush_access(FILE_APPEND_DATA_LE) == 0`.
- **CORRECT**. Per section 3.3.5.11.

**test_flush_access_both** (line 350-354): `smb2_validate_flush_access(FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE) == 0`.
- **CORRECT**.

**test_flush_access_read_only** (line 356-360): `smb2_validate_flush_access(FILE_READ_DATA_LE) == -EACCES`.
- **CORRECT**. Per section 3.3.5.11.

**test_flush_access_none** (line 362-365): `smb2_validate_flush_access(0) == -EACCES`.
- **CORRECT**. Per section 3.3.5.11.

### smb2_validate_write_access tests

**test_write_access_write_data** (line 369-372): `smb2_validate_write_access(FILE_WRITE_DATA_LE) == 0`.
- **CORRECT**. MS-SMB2 section 3.3.5.13: checks Open.GrantedAccess for FILE_WRITE_DATA or FILE_APPEND_DATA.

**test_write_access_append_data** (line 374-377): `smb2_validate_write_access(FILE_APPEND_DATA_LE) == 0`.
- **CORRECT**. Per section 3.3.5.13.

**test_write_access_read_only** (line 379-383): `smb2_validate_write_access(FILE_READ_DATA_LE) == -EACCES`.
- **CORRECT**. Per section 3.3.5.13.

**test_write_access_none** (line 385-388): `smb2_validate_write_access(0) == -EACCES`.
- **CORRECT**.

---

## File 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_error_readwrite.c`

This file is a self-contained test that does NOT call any exported functions -- it simply tests basic arithmetic and type properties. It does not use `MODULE_IMPORT_NS` and includes `"../smb2pdu.h"` for struct definitions only. These are trivial sanity tests.

### test_read_offset_zero (line 24-30)
Tests that `loff_t offset = 0; KUNIT_EXPECT_GE(test, offset, (loff_t)0)`.
- **CORRECT** but trivial. Tests a basic property, not production logic.

### test_read_offset_max (line 32-38)
Tests that `loff_t offset = LLONG_MAX; KUNIT_EXPECT_GT(test, offset, (loff_t)0)`.
- **CORRECT** but trivial.

### test_read_offset_negative (line 40-46)
Tests that `loff_t offset = -1; KUNIT_EXPECT_LT(test, offset, (loff_t)0)`.
- **CORRECT** but trivial.

### test_read_offset_overflow_check (line 48-58)
Tests that `u64(0xFFFFFFFFFFFFFFFF)` cast to `loff_t` equals -1.
- **CORRECT**. This verifies the sentinel value cast behavior, which is important for the write-to-EOF sentinel path.

### test_write_length_zero (line 62-68)
Tests that `u32 length = 0; KUNIT_EXPECT_EQ(test, length, (u32)0)`.
- **CORRECT** but trivial. Does not test any production logic.

### test_write_length_max_credits (line 70-82)
Tests that 256 * 65536 = 16MB.
- **QUESTIONABLE**. The comment says "max credits for a single request is typically 256" and "max data per credit is 65536." Per MS-SMB2 section 3.3.5.2.5, credit charge is computed as `(PayloadSize - 1) / 65536 + 1`. The maximum number of credits granted per request is implementation-dependent. This test just verifies arithmetic, not spec compliance.

### test_data_offset_valid (line 86-95)
Tests that `sizeof(struct smb2_hdr) + 48` is >= `sizeof(struct smb2_hdr)`.
- **CORRECT** but trivial. Always true by definition.

### test_data_offset_zero (line 97-103)
Tests that DataOffset=0 is less than `sizeof(struct smb2_hdr)`.
- **CORRECT** but trivial.

### test_data_offset_too_small (line 105-111)
Tests that DataOffset=10 is less than `sizeof(struct smb2_hdr)`.
- **CORRECT** but trivial. In practice, DataOffset must be >= the offset of the Buffer field (which is header + fixed body fields), not just >= header size. The actual minimum DataOffset is `offsetof(struct smb2_write_req, Buffer)` which is larger than just the header. This test uses the header size as the threshold, which is technically too lenient. **QUESTIONABLE** -- the comparison is `sizeof(struct smb2_hdr)` which is only 64 bytes, but the real minimum DataOffset for a WRITE request is `offsetof(struct smb2_write_req, Buffer)` = 64 + 48 = 112 bytes.

### test_offset_length_overflow (line 115-124)
Tests `check_add_overflow(U64_MAX - 10, 100)` is true.
- **CORRECT**. Verifies overflow detection in the offset+length calculation.

### test_offset_length_no_overflow (line 126-136)
Tests `check_add_overflow(1000, 4096)` is false and result is 5096.
- **CORRECT**.

**Overall assessment of this file**: The tests are all trivially correct but test no production code paths. They verify basic arithmetic, type properties, and `check_add_overflow` behavior. They provide zero protocol compliance coverage. This file is essentially testing the C language and Linux kernel helpers, not SMB2 protocol behavior.

---

## File 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_write_through.c`

This file inlines its own struct definitions and tests layout, flag values, and structure sizes.

### test_write_through_flag_value (line 120-124)
Tests `SMB2_WRITEFLAG_WRITE_THROUGH == 0x00000001`.
- **CORRECT**. MS-SMB2 section 2.2.21: "SMB2_WRITEFLAG_WRITE_THROUGH 0x00000001".

### test_write_unbuffered_flag_value (line 129-133)
Tests `SMB2_WRITEFLAG_WRITE_UNBUFFERED == 0x00000002`.
- **CORRECT**. MS-SMB2 section 2.2.21: "SMB2_WRITEFLAG_WRITE_UNBUFFERED 0x00000002".

### test_write_req_structure_size (line 141-149)
Tests that StructureSize for WRITE request is 49.
- **CORRECT**. MS-SMB2 section 2.2.21: "The client MUST set this field to 49."

### test_read_req_structure_size (line 156-164)
Tests that StructureSize for READ request is 49.
- **CORRECT**. MS-SMB2 section 2.2.19: "The client MUST set this field to 49."

### test_write_rsp_structure_size (line 171-179)
Tests that StructureSize for WRITE response is 17.
- **CORRECT**. MS-SMB2 section 2.2.22: "The server MUST set this field to 17."

### test_read_rsp_structure_size (line 186-194)
Tests that StructureSize for READ response is 17.
- **CORRECT**. MS-SMB2 section 2.2.20: "The server MUST set this field to 17."

### test_write_flags_field_offset (line 208-222)
Tests that the Flags field is at offset 44 from the start of the write request body (after the header).
- Let me verify: StructureSize(2) + DataOffset(2) + Length(4) + Offset(8) + PersistentFileId(8) + VolatileFileId(8) + Channel(4) + RemainingBytes(4) + WriteChannelInfoOffset(2) + WriteChannelInfoLength(2) = 44. Then Flags(4) starts at body+44.
- **CORRECT**. This matches MS-SMB2 section 2.2.21 field layout.

### test_write_channel_values (line 229-237)
Tests SMB2_CHANNEL_NONE=0, SMB2_CHANNEL_RDMA_V1=1, SMB2_CHANNEL_RDMA_V1_INVALIDATE=2.
- **CORRECT**. Per MS-SMB2 section 2.2.21.
- **Note**: The test does not include `SMB2_CHANNEL_RDMA_TRANSFORM = 0x00000003` which is defined for SMB 3.1.1. This is not wrong (the test only defines what it tests), but it is incomplete.

### test_write_req_field_layout (line 248-281)
Tests field offsets relative to header:
- StructureSize at body+0: **CORRECT**
- DataOffset at body+2: **CORRECT**
- Length at body+4: **CORRECT**
- Offset at body+8: **CORRECT**
- Channel at body+32: Let's verify: body+0(StructureSize,2)+2(DataOffset,2)+4(Length,4)+8(Offset,8)+16(PersistentFileId,8)+24(VolatileFileId,8) = 32. **CORRECT**.
- Flags at body+44: Already verified above. **CORRECT**.

### test_combined_write_flags (line 288-306)
Tests that WRITE_THROUGH | WRITE_UNBUFFERED = 0x3, and individual bits are testable.
- **CORRECT**. Basic bitmask arithmetic.

### WRITE Response structure issue

**WRONG**: The test file's `struct test_smb2_write_rsp` (lines 104-113) defines the WRITE response with these fields:
```
__le16 StructureSize;  /* 17 */
__u8   DataOffset;
__u8   Reserved;
__le32 DataLength;
__le32 DataRemaining;
__le32 Reserved2;
__u8   Buffer[];
```

But per MS-SMB2 section 2.2.22, the WRITE response has:
```
StructureSize (2 bytes)   -- MUST be 17
Reserved (2 bytes)        -- NOT split into DataOffset(1) + Reserved(1)
Count (4 bytes)           -- named "Count", not "DataLength"
Remaining (4 bytes)       -- named "Remaining", not "DataRemaining"
WriteChannelInfoOffset (2 bytes)
WriteChannelInfoLength (2 bytes)
```

The test struct has:
1. `__u8 DataOffset` + `__u8 Reserved` (2 bytes total) where the spec has `__le16 Reserved` (2 bytes) -- the bit-level layout is the same size (2 bytes), but the spec uses a single 2-byte Reserved field, not split into DataOffset+Reserved. **The field name "DataOffset" is wrong** -- the WRITE response has NO DataOffset field. The 2-byte field after StructureSize is simply Reserved.

2. `DataLength` vs spec's `Count`, `DataRemaining` vs spec's `Remaining` -- these are name differences only; the sizes match.

3. `Reserved2` (4 bytes) vs spec's `WriteChannelInfoOffset(2) + WriteChannelInfoLength(2)` = 4 bytes -- size matches but field semantics differ.

4. `Buffer[]` -- the spec does NOT include a Buffer field in the WRITE response. The WRITE response is a fixed-size structure with no variable-length data.

**The test struct for smb2_write_rsp is modeled after the READ response, not the WRITE response.** This is a structural copy-paste error. However, since the total body size is the same (16 bytes, with StructureSize=17), the StructureSize test still passes. The field-level tests are not affected because no test accesses the individual write-response fields. **Spec ref: MS-SMB2 section 2.2.22.**

---

## SUMMARY TABLE

| Test File | Test Case | Verdict | Notes |
|-----------|-----------|---------|-------|
| **smb2_read_write.c** | test_read_offset_zero | CORRECT | |
| | test_read_offset_normal | CORRECT | |
| | test_read_offset_max_lfs | CORRECT | VFS guard, not spec requirement |
| | test_read_offset_negative | CORRECT | VFS guard |
| | test_read_offset_beyond_max_lfs | CORRECT | VFS guard |
| | test_read_offset_minus_one | CORRECT | |
| | test_read_range_normal | CORRECT | |
| | test_read_range_zero_length | CORRECT | Spec allows zero-length reads |
| | test_read_range_at_boundary | CORRECT | |
| | test_read_range_overflow | CORRECT | |
| | test_read_range_large_offset_small_len | CORRECT | |
| | test_read_range_offset_zero_large_len | CORRECT | |
| | test_read_access_read_data | CORRECT | |
| | **test_read_access_read_attributes** | **WRONG** | Spec section 3.3.5.12 requires FILE_READ_DATA only; FILE_READ_ATTRIBUTES alone should fail |
| | test_read_access_both | CORRECT | |
| | test_read_access_write_only | CORRECT | |
| | test_read_access_none | CORRECT | |
| | test_write_offset_zero | CORRECT | |
| | test_write_offset_normal | CORRECT | |
| | test_write_offset_max_lfs | CORRECT | VFS guard |
| | test_write_offset_negative | CORRECT | VFS guard |
| | test_write_offset_beyond_max_lfs | CORRECT | VFS guard |
| | test_write_range_normal | CORRECT | |
| | test_write_range_zero_length | CORRECT | |
| | test_write_range_zero_offset | QUESTIONABLE | Offset==0 skips overflow check; valid per impl, not spec-derived |
| | test_write_range_overflow | CORRECT | |
| | test_write_range_at_boundary | CORRECT | |
| | test_ntfs_limit_normal | CORRECT | |
| | test_ntfs_limit_zero_length | CORRECT | |
| | test_ntfs_limit_at_boundary | CORRECT | |
| | test_ntfs_limit_beyond_boundary | CORRECT | |
| | test_ntfs_limit_extend_past | CORRECT | |
| | **test_ntfs_limit_just_under** | **QUESTIONABLE** | offset+length == max is rejected with ENOSPC; may be off-by-one |
| | test_ntfs_limit_well_under | CORRECT | |
| | test_data_bounds_valid | CORRECT | |
| | test_data_bounds_offset_too_small | CORRECT | |
| | test_data_bounds_overflow | CORRECT | |
| | test_data_bounds_exact_fit | CORRECT | |
| | test_data_bounds_zero_length | CORRECT | |
| | test_is_write_to_eof_true | CORRECT | |
| | test_is_write_to_eof_false_zero | CORRECT | |
| | test_is_write_to_eof_false_normal | CORRECT | |
| | test_is_write_to_eof_false_near_max | CORRECT | |
| | test_eof_access_append_only | CORRECT | |
| | **test_eof_access_both** | **QUESTIONABLE** | Spec does not prohibit EOF sentinel with FILE_WRITE_DATA present |
| | **test_eof_access_write_only** | **QUESTIONABLE** | Same as above |
| | test_eof_access_none | CORRECT | |
| | test_eof_access_read_data | CORRECT | |
| | test_flush_access_write_data | CORRECT | |
| | test_flush_access_append_data | CORRECT | |
| | test_flush_access_both | CORRECT | |
| | test_flush_access_read_only | CORRECT | |
| | test_flush_access_none | CORRECT | |
| | test_write_access_write_data | CORRECT | |
| | test_write_access_append_data | CORRECT | |
| | test_write_access_read_only | CORRECT | |
| | test_write_access_none | CORRECT | |
| **error_readwrite.c** | test_read_offset_zero | CORRECT | Trivial; tests C language, not SMB2 |
| | test_read_offset_max | CORRECT | Trivial |
| | test_read_offset_negative | CORRECT | Trivial |
| | test_read_offset_overflow_check | CORRECT | Sentinel cast verification |
| | test_write_length_zero | CORRECT | Trivial |
| | test_write_length_max_credits | QUESTIONABLE | Tests arithmetic, not protocol compliance |
| | test_data_offset_valid | CORRECT | Trivial |
| | test_data_offset_zero | CORRECT | Trivial |
| | **test_data_offset_too_small** | **QUESTIONABLE** | Uses sizeof(smb2_hdr) as threshold, but real minimum is offsetof(Buffer) |
| | test_offset_length_overflow | CORRECT | Tests check_add_overflow |
| | test_offset_length_no_overflow | CORRECT | Tests check_add_overflow |
| **write_through.c** | test_write_through_flag_value | CORRECT | Matches section 2.2.21 |
| | test_write_unbuffered_flag_value | CORRECT | Matches section 2.2.21 |
| | test_write_req_structure_size | CORRECT | StructureSize=49 per section 2.2.21 |
| | test_read_req_structure_size | CORRECT | StructureSize=49 per section 2.2.19 |
| | test_write_rsp_structure_size | CORRECT | StructureSize=17 per section 2.2.22 |
| | test_read_rsp_structure_size | CORRECT | StructureSize=17 per section 2.2.20 |
| | test_write_flags_field_offset | CORRECT | Offset 44 from body start verified |
| | test_write_req_field_layout | CORRECT | All field offsets match section 2.2.21 |
| | test_write_channel_values | CORRECT | Missing RDMA_TRANSFORM but not wrong |
| | test_combined_write_flags | CORRECT | Basic bitmask test |

## CRITICAL FINDINGS

1. **NON-COMPILABLE TEST**: `ksmbd_test_smb2_read_write.c` references functions (`smb2_validate_read_offset`, `smb2_validate_read_range`, etc.) that do not exist anywhere in the source tree. These functions were never extracted from the production code as VISIBLE_IF_KUNIT exports. This file will fail to compile.

2. **WRONG: test_read_access_read_attributes** (`ksmbd_test_smb2_read_write.c` line 109-112): Expects `FILE_READ_ATTRIBUTES_LE` alone is sufficient for a read. MS-SMB2 section 3.3.5.12 only requires `FILE_READ_DATA`. The production code (line 458 of `smb2_read_write.c`) checks `FILE_READ_DATA_LE | FILE_READ_ATTRIBUTES_LE`, which is more permissive than the spec. **Fix**: Either update the test to expect `-EACCES` for FILE_READ_ATTRIBUTES_LE alone, or document this as a deliberate ksmbd extension. The production code should also be fixed to match the spec.

3. **WRONG: test_smb2_write_rsp struct** (`ksmbd_test_write_through.c` lines 104-113): The inlined WRITE response structure uses READ-response-style field names (`DataOffset`, `Reserved`, `DataLength`, `DataRemaining`, `Reserved2`, `Buffer[]`). Per MS-SMB2 section 2.2.22, the WRITE response has `Reserved(2)`, `Count(4)`, `Remaining(4)`, `WriteChannelInfoOffset(2)`, `WriteChannelInfoLength(2)`, and no Buffer field. The struct layout is correct in terms of byte sizes but the field semantics and names are wrong. No tests currently depend on the individual fields, so this does not cause test failures. **Fix**: Rename fields to match the spec.

4. **QUESTIONABLE: test_eof_access_both and test_eof_access_write_only** (`ksmbd_test_smb2_read_write.c` lines 311-323): The tests assert that the EOF sentinel (0xFFFFFFFFFFFFFFFF offset) is invalid when FILE_WRITE_DATA is present. The MS-SMB2 spec does not explicitly prohibit this combination. This is a ksmbd design decision that is more restrictive than the spec requires.

5. **QUESTIONABLE: test_ntfs_limit_just_under** (`ksmbd_test_smb2_read_write.c` line 227-232): A write at offset `0xfffffffefff` with length 1 (ending exactly at the NTFS limit) is rejected with ENOSPC. This may be an off-by-one: the last valid byte offset should be `0xfffffffefff`, and writing 1 byte there produces a file of exactly `0xfffffff0000` bytes, which should be valid.

6. **READ flag constant**: `TEST_SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION = 0x00000004` in `ksmbd_test_write_through.c` (line 50) and `SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION` in `smb2pdu.h` (line 1022). The MS-SMB2 spec (section 2.2.19, January 2026 edition) defines only two read flags: READ_UNBUFFERED (0x01) and REQUEST_COMPRESSED (0x02). There is no READ_REQUEST_TRANSPORT_ENCRYPTION flag in the spec. This constant appears to be fabricated. **QUESTIONABLE** -- it may be a vendor extension or from a newer spec revision, but it is not in the January 2026 edition being audited.

7. **WRITE flag constant**: `TEST_SMB2_WRITEFLAG_REQUEST_TRANSPORT_ENCRYPTION = 0x00000004` in `ksmbd_test_write_through.c` (line 44) and potentially in `smb2pdu.h`. The MS-SMB2 spec (section 2.2.21) defines only WRITE_THROUGH (0x01) and WRITE_UNBUFFERED (0x02). There is no WRITE_REQUEST_TRANSPORT_ENCRYPTION flag. Same issue as above.

8. **Trivial test file**: `ksmbd_test_error_readwrite.c` provides zero protocol compliance testing. All 11 tests verify basic arithmetic, type casting, and `check_add_overflow` behavior. None call production code. This file should be reconsidered for value.