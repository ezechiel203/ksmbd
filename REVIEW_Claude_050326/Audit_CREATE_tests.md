# Audit Create Tests

Agent ID: a1127b1fb8d1cc8ed

So FILE_GENERIC_READ_LE = 0x80000000 (bit 31). FILE_READ_ATTRIBUTES_LE = 0x00000080 (bit 7). These are entirely different bits. FILE_READ_ATTRIBUTES is NOT in FILE_READ_DESIRED_ACCESS_LE. So the test that expects O_PATH for FILE_READ_ATTRIBUTES_LE makes sense as an implementation detail (ksmbd opens with O_PATH when only attributes are needed).

Now I have enough information for a comprehensive audit. Let me compile the full report.

---

# AUDIT REPORT: KUnit Test Files vs MS-SMB2 Specification

## File 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_create.c`

This file tests `smb2_create_open_flags()`, which maps SMB2 CREATE dispositions and access masks to Linux `open()` flags. There are 33 KUNIT_CASE entries.

### Create Disposition Values (MS-SMB2 section 2.2.13, CreateDisposition field)

Per the spec:
- FILE_SUPERSEDE = 0x00000000
- FILE_OPEN = 0x00000001
- FILE_CREATE = 0x00000002
- FILE_OPEN_IF = 0x00000003
- FILE_OVERWRITE = 0x00000004
- FILE_OVERWRITE_IF = 0x00000005

The ksmbd code defines: `FILE_SUPERSEDE_LE = cpu_to_le32(0x00000000)`, `FILE_OPEN_LE = cpu_to_le32(0x00000001)`, `FILE_CREATE_LE = cpu_to_le32(0x00000002)`, `FILE_OPEN_IF_LE = cpu_to_le32(0x00000003)`, `FILE_OVERWRITE_LE = cpu_to_le32(0x00000004)`, `FILE_OVERWRITE_IF_LE = cpu_to_le32(0x00000005)`. All match the spec.

### Individual Test Cases

**1. test_open_flags_read_existing** -- CORRECT
FILE_OPEN (existing=true, read): no O_CREAT, no O_TRUNC, O_RDONLY. Per spec: "If the file already exists, return success." No create/truncate expected.

**2. test_open_flags_write_existing** -- CORRECT
FILE_OPEN (existing=true, write): O_WRONLY. FILE_WRITE_DATA_LE is in FILE_WRITE_DESIRE_ACCESS_LE, so write path is correct.

**3. test_open_flags_readwrite** -- CORRECT
Both FILE_READ_DATA and FILE_WRITE_DATA: O_RDWR with MAY_READ | MAY_WRITE.

**4. test_open_flags_create_new** -- CORRECT
FILE_CREATE (existing=false): O_CREAT. Per spec: "If the file already exists, fail the operation; otherwise, create the file."

**5. test_open_flags_overwrite** -- CORRECT
FILE_OVERWRITE (existing=true): O_TRUNC. Per spec: "Overwrite the file if it already exists."

**6. test_open_flags_supersede** -- CORRECT
FILE_SUPERSEDE (existing=true): O_TRUNC. Per spec: "If the file already exists, supersede it." Truncation is the ksmbd implementation of supersede on existing files.

**7. test_open_flags_open_if_new** -- CORRECT
FILE_OPEN_IF (existing=false): O_CREAT. Per spec: "Open the file if it already exists; otherwise, create the file."

**8. test_open_flags_directory_discards_write** -- CORRECT
Directory with FILE_WRITE_DATA + FILE_DIRECTORY_FILE: write stripped, falls to O_RDONLY. This is an implementation detail (Linux directories cannot be opened for write), not directly from spec, but consistent with MS-SMB2 section 2.2.13 which says FILE_DIRECTORY_FILE limits valid CreateOptions.

**9. test_open_flags_read_attributes_opath** -- CORRECT
FILE_READ_ATTRIBUTES only: O_PATH. This is a ksmbd implementation detail; FILE_READ_ATTRIBUTES (0x80) is not in FILE_READ_DESIRED_ACCESS_LE, so it uses O_PATH for metadata-only access.

**10. test_open_flags_nonblock_largefile** -- CORRECT
Always sets O_NONBLOCK | O_LARGEFILE. Implementation detail of ksmbd, not spec-mandated, but valid behavior.

**11. test_open_flags_open_nonexistent** -- CORRECT
FILE_OPEN (existing=false): no O_CREAT. Per spec: "fail the operation" when file doesn't exist with FILE_OPEN.

**12. test_create_sd_buffer_no_contexts** -- CORRECT
No CreateContextsOffset (0): returns -ENOENT. Tests that smb2_create_sd_buffer returns error when no contexts are present.

**13. test_open_flags_overwrite_if** -- CORRECT
FILE_OVERWRITE_IF: new file -> O_CREAT, existing file -> O_TRUNC. Per spec: "Overwrite the file if it already exists; otherwise, create the file."

**14. test_open_flags_append_only** -- CORRECT
FILE_APPEND_DATA (0x04) is in FILE_WRITE_DESIRE_ACCESS_LE, so write path -> O_WRONLY, MAY_WRITE.

**15. test_open_flags_delete_access** -- CORRECT
FILE_DELETE_LE (0x10000) is not in FILE_READ_DESIRED_ACCESS_LE or FILE_WRITE_DESIRE_ACCESS_LE, so falls to O_RDONLY, MAY_READ. This is ksmbd implementation logic.

**16. test_open_flags_execute_access** -- CORRECT
FILE_EXECUTE (0x20) is not in FILE_READ_DESIRED_ACCESS_LE or FILE_WRITE_DESIRE_ACCESS_LE, so falls to O_RDONLY. This is ksmbd implementation behavior.

**17. test_open_flags_write_attributes_only** -- CORRECT
FILE_WRITE_ATTRIBUTES (0x100) is explicitly included in FILE_WRITE_DESIRE_ACCESS_LE, so O_WRONLY, MAY_WRITE.

**18. test_open_flags_create_always_existing** -- CORRECT
FILE_OPEN_IF (existing=true): no O_CREAT, no O_TRUNC. Per spec: "Open the file if it already exists" -- just open it.

**19. test_open_flags_all_access** -- CORRECT
Combined read+write+append+execute+delete: has both read and write bits -> O_RDWR.

**20. test_open_flags_directory_create** -- CORRECT
Directory + FILE_CREATE (existing=false): O_CREAT, O_RDONLY (write stripped for dirs).

**21. test_open_flags_supersede_new** -- CORRECT
FILE_SUPERSEDE (existing=false): O_CREAT. Per spec: "Otherwise, create the file."

**22. test_open_flags_create_existing_fails** -- CORRECT
FILE_CREATE (existing=true): no O_CREAT. Per spec: "If the file already exists, fail the operation." The caller handles the error; open_flags just doesn't set O_CREAT.

**23. test_open_flags_overwrite_new_no_trunc** -- CORRECT
FILE_OVERWRITE (existing=false): no O_TRUNC. Per spec: "otherwise, fail the operation." Non-existent file with FILE_OVERWRITE is an error path; no truncation.

**24. test_open_flags_open_existing_no_create** -- CORRECT
FILE_OPEN (existing=true): no O_CREAT, no O_TRUNC.

**25. test_open_flags_directory_open_if_new** -- CORRECT
FILE_OPEN_IF + DIR (existing=false): O_CREAT, O_RDONLY (write stripped).

**26. test_open_flags_generic_read_write** -- CORRECT
Combined read+write+append: O_RDWR, MAY_READ | MAY_WRITE.

**27. test_open_flags_block_device** -- CORRECT
Block device (S_IFBLK): O_PATH. Implementation detail of ksmbd (prevents direct block device access).

**28. test_open_flags_char_device** -- CORRECT
Char device (S_IFCHR): O_PATH. Same rationale as block device.

**29. test_open_flags_overwrite_nonexistent_clears_creat** -- CORRECT
FILE_OVERWRITE (existing=false): no O_CREAT, no O_TRUNC. Error path per spec.

**30. test_open_flags_dir_mode_strips_write** -- CORRECT
S_ISDIR(mode) alone (without FILE_DIRECTORY_FILE in coptions): write still stripped. Implementation detail.

**31. test_open_flags_supersede_existing_truncates** -- CORRECT
FILE_SUPERSEDE (existing=true): O_TRUNC, O_RDWR (both read+write requested).

**32. test_open_flags_create_nonexistent_creates** -- CORRECT
FILE_CREATE (existing=false): O_CREAT, MAY_READ.

**33. test_open_flags_read_ea_access_is_read** -- CORRECT
FILE_READ_EA (0x08) is in FILE_READ_DESIRED_ACCESS_LE, so MAY_READ.

**34. test_open_flags_open_if_existing_no_flags** -- CORRECT
FILE_OPEN_IF (existing=true): no O_CREAT, no O_TRUNC.

**35. test_open_flags_overwrite_if_existing_truncates** -- CORRECT
FILE_OVERWRITE_IF (existing=true): O_TRUNC.

**36. test_open_flags_write_ea_access_is_write** -- CORRECT
FILE_WRITE_EA (0x10) is in FILE_WRITE_DESIRE_ACCESS_LE, so O_WRONLY, MAY_WRITE.

**37. test_open_flags_dir_rw_becomes_ro** -- CORRECT
Directory with read+write: write stripped, MAY_READ remains.

---

## File 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_create_ctx.c`

This file tests an inlined create context dispatch list (register, find, unregister). There are 11 KUNIT_CASE entries.

**1. test_register_and_find** -- CORRECT
Registers "MxAc" (4 bytes), finds it. Tag name "MxAc" matches MS-SMB2 section 2.2.13.2 (0x4d784163 = "MxAc").

**2. test_find_empty_list** -- CORRECT
Find on empty list returns NULL.

**3. test_unregister_then_find** -- CORRECT
"QFid" tag (SMB2_CREATE_QUERY_ON_DISK_ID per MS-SMB2 section 2.2.13.2, 0x51466964 = "QFid"). Correct.

**4. test_multiple_tags_found** -- CORRECT
"MxAc", "QFid", "AAPL" all found. "AAPL" is Apple's extension, not in MS-SMB2 spec, but is a valid real-world create context tag.

**5. test_tag_exact_memcmp** -- CORRECT
Exact memcmp matching.

**6. test_tag_same_prefix_different_suffix** -- CORRECT
Tests distinct tags with same prefix.

**7. test_tag_not_found** -- CORRECT
Non-existent "ZZZZ" returns NULL.

**8. test_case_sensitive** -- CORRECT
Per MS-SMB2 section 2.2.13.2: create context names are defined as specific byte values in network byte order. The matching must be exact (binary), which is case-sensitive. "mxac" and "MXAC" must not match "MxAc".

**9. test_unregister_one_leaves_others** -- CORRECT

**10. test_zero_length_tag** -- CORRECT
Edge case test.

**11. test_register_returns_zero** -- CORRECT

---

## File 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_create_ctx_tags.c`

This file tests that specific tags are or are not in a dispatch list. 9 KUNIT_CASE entries.

**1. test_find_mxac_tag** -- CORRECT
"MxAc" is a registered built-in. Matches MS-SMB2 section 2.2.13.2: SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST = "MxAc".

**2. test_find_qfid_tag** -- CORRECT
"QFid" is a registered built-in. Matches MS-SMB2 section 2.2.13.2: SMB2_CREATE_QUERY_ON_DISK_ID = "QFid".

**3. test_find_unknown_tag** -- CORRECT
"XXXX" not found.

**4. test_find_secd_not_in_list** -- CORRECT
"SecD" (SMB2_CREATE_SD_BUFFER, 0x53656344) is handled inline, not in dispatch list. The tag name matches spec.

**5. test_find_dhq_not_in_list** -- CORRECT
"DHnQ" (SMB2_CREATE_DURABLE_HANDLE_REQUEST, 0x44486e51) is handled inline. Tag name matches spec.

**6. test_find_rqls_not_in_list** -- CORRECT
"RqLs" (SMB2_CREATE_REQUEST_LEASE, 0x52714c73) is handled inline. Tag name matches spec.

**7. test_find_posix_tag_not_in_list** -- CORRECT
POSIX create context uses a 16-byte tag (a GUID), not in the dispatch list. Correct.

**8. test_register_custom_tag** -- CORRECT

**9. test_unregister_custom_tag** -- CORRECT

---

## File 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_create_maximal_access.c`

This file tests the MxAc create context structures and access mask constants. 17 KUNIT_CASE entries.

**1. test_mxac_context_tag_name** -- CORRECT
"MxAc" = 0x4D, 0x78, 0x41, 0x63. Per MS-SMB2 section 2.2.13.2: SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST = 0x4d784163 = "MxAc". The hex values 0x4D='M', 0x78='x', 0x41='A', 0x63='c' are correct.

**2. test_mxac_tag_length** -- CORRECT
Tag length = 4 bytes. Per MS-SMB2 section 2.2.13.2, the name is a 4-byte value.

**3. test_mxac_response_struct_size** -- CORRECT
`sizeof(struct create_mxac_rsp)` expected to be 32 bytes. Layout: create_context(16) + Name[8](8) + QueryStatus(4) + MaximalAccess(4) = 32. Per MS-SMB2 section 2.2.14.2.5, the response data is QueryStatus(4) + MaximalAccess(4) = 8 bytes of data, plus the create_context header and Name padding.

**4. test_mxac_request_struct_has_timestamp** -- CORRECT
`sizeof(struct create_mxac_req)` = 32 bytes. Layout: create_context(16) + Name[8](8) + Timestamp(8) = 32. Per MS-SMB2 section 2.2.13.2.5, the data is either empty or an 8-byte Timestamp.

**5. test_mxac_query_status_field_offset** -- QUESTIONABLE
The test computes expected offset as: `offsetof(struct create_context, Next) + sizeof(struct create_context) + 8`. Since `offsetof(struct create_context, Next) = 0`, this equals `0 + 16 + 8 = 24`. The actual field QueryStatus is at offset 24 in the struct (after ccontext[16] + Name[8]). This is correct in terms of C struct layout. However, the expression `offsetof(struct create_context, Next)` is redundant (it's always 0 since Next is the first field), making the code confusing but technically correct.

**6. test_mxac_maximal_access_field_offset** -- CORRECT
MaximalAccess follows QueryStatus by sizeof(__le32) = 4 bytes. At offset 28.

**7. test_mxac_maximal_access_mask_bits** -- CORRECT
DESIRED_ACCESS_MASK = 0xF21F01FF. Verified against MS-SMB2 section 2.2.13.1.1. This includes all standard file rights (0x01FF), all standard access rights (DELETE through SYNCHRONIZE = 0x001F0000), MAXIMUM_ALLOWED (0x02000000), and all four generic rights (GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ = 0xF0000000). Notably excludes ACCESS_SYSTEM_SECURITY (0x01000000).

**8. test_mxac_read_access_includes_read_data** -- CORRECT
FILE_READ_DATA = 0x00000001, which is set in 0xF21F01FF.

**9. test_mxac_write_access_includes_write_data** -- CORRECT
FILE_WRITE_DATA = 0x00000002, which is set in 0xF21F01FF.

**10. test_mxac_delete_access_includes_delete** -- CORRECT
FILE_DELETE_LE = 0x00010000 (DELETE), which is set in 0xF21F01FF.

**11. test_mxac_synchronize_bit_included** -- CORRECT
FILE_SYNCHRONIZE = 0x00100000, which is set in 0xF21F01FF (bit 20). The comment references MS-SMB2 section 2.2.13.2.8 which is not entirely accurate (that section doesn't specifically mandate SYNCHRONIZE in the mask), but the assertion itself is correct.

**12. test_mxac_generic_all_includes_specific** -- CORRECT
FILE_GENERIC_ALL_LE = 0x10000000, which is set in 0xF21F01FF. Per MS-SMB2 section 2.2.13.1.1: GENERIC_ALL = 0x10000000.

**13. test_mxac_context_name_offset** -- CORRECT
`offsetof(struct create_context, NameOffset)` expected at byte 4. Layout: Next(4) then NameOffset(2). So NameOffset is at offset 4. Per MS-SMB2 section 2.2.13.2: Next(4 bytes) followed by NameOffset(2 bytes).

**14. test_mxac_context_name_length_offset** -- CORRECT
NameLength follows NameOffset by sizeof(__le16) = 2. NameLength at offset 6. Per spec: NameOffset(2) then NameLength(2).

**15. test_mxac_context_header_size** -- CORRECT
`sizeof(struct create_context)` = 16. Per MS-SMB2 section 2.2.13.2: Next(4) + NameOffset(2) + NameLength(2) + Reserved(2) + DataOffset(2) + DataLength(4) = 16 bytes.

**16. test_mxac_query_status_success** -- CORRECT
STATUS_SUCCESS = 0x00000000. Per MS-ERREF.

**17. test_mxac_timestamp_field_optional** -- CORRECT
Timestamp field size = sizeof(__le64) = 8 bytes. Per MS-SMB2 section 2.2.13.2.5: "either empty (0 bytes) or an 8-byte FILETIME."

---

## File 5: `/home/ezechiel203/ksmbd/test/ksmbd_test_error_create.c`

This file tests smb2_create_open_flags error paths. 20 KUNIT_CASE entries. Most of these overlap with the tests in ksmbd_test_smb2_create.c.

**1. err_create_open_existing_file** -- CORRECT
FILE_OPEN (existing=true): no O_CREAT, no O_TRUNC.

**2. err_create_open_nonexistent** -- CORRECT
FILE_OPEN (existing=false): no O_CREAT.

**3. err_create_create_existing** -- CORRECT
FILE_CREATE (existing=true): no O_TRUNC.

**4. err_create_create_nonexistent** -- CORRECT
FILE_CREATE (existing=false): O_CREAT.

**5. err_create_supersede_existing** -- CORRECT
FILE_SUPERSEDE (existing=true): O_TRUNC.

**6. err_create_supersede_nonexistent** -- CORRECT
FILE_SUPERSEDE (existing=false): O_CREAT.

**7. err_create_overwrite_existing** -- CORRECT
FILE_OVERWRITE (existing=true): O_TRUNC.

**8. err_create_overwrite_nonexistent** -- CORRECT
FILE_OVERWRITE (existing=false): no O_CREAT.

**9. err_create_overwrite_if_existing** -- CORRECT
FILE_OVERWRITE_IF (existing=true): O_TRUNC.

**10. err_create_overwrite_if_nonexistent** -- CORRECT
FILE_OVERWRITE_IF (existing=false): O_CREAT.

**11. err_create_open_if_nonexistent** -- CORRECT
FILE_OPEN_IF (existing=false): O_CREAT.

**12. err_create_read_only_access** -- CORRECT
FILE_READ_DATA only: no O_WRONLY, no O_RDWR, MAY_READ.

**13. err_create_write_only_access** -- CORRECT
FILE_WRITE_DATA only: O_WRONLY, MAY_WRITE.

**14. err_create_rdwr_access** -- CORRECT
FILE_READ_DATA | FILE_WRITE_DATA: O_RDWR, MAY_READ | MAY_WRITE.

**15. err_create_directory_strips_write** -- CORRECT
FILE_DIRECTORY_FILE + FILE_WRITE_DATA: write stripped, no O_WRONLY.

**16. err_create_read_attributes_opath** -- CORRECT
FILE_READ_ATTRIBUTES: O_PATH.

**17. err_create_block_device_opath** -- CORRECT
S_IFBLK: O_PATH.

**18. err_create_char_device_opath** -- CORRECT
S_IFCHR: O_PATH.

**19. err_create_always_nonblock_largefile** -- CORRECT
Always O_NONBLOCK | O_LARGEFILE.

**20. err_create_invalid_disposition_existing** -- CORRECT
Disposition 0x06 (invalid, beyond FILE_OVERWRITE_IF=0x05): falls through switch default, no O_CREAT/O_TRUNC. The comment about FILE_CREATE_MASK_LE (0x07) masking to 0x06 is correct per ksmbd implementation. The spec does not define disposition value 0x06.

---

## File 6: `/home/ezechiel203/ksmbd/test/ksmbd_test_app_instance.c`

This file tests APP_INSTANCE_ID and APP_INSTANCE_VERSION create context parsing and version comparison logic. 25 KUNIT_CASE entries.

### APP_INSTANCE_ID Structure Constants

The test defines:
- `APP_INSTANCE_ID_STRUCT_SIZE = 20`
- `APP_INSTANCE_ID_GUID_OFFSET = 4`
- `APP_INSTANCE_ID_GUID_LEN = 16`

Per MS-SMB2 section 2.2.13.2.13: StructureSize(2) + Reserved(2) + AppInstanceId(16) = 20 bytes. StructureSize MUST be 20. GUID starts at offset 4. Length is 16. **All CORRECT**.

### APP_INSTANCE_VERSION Structure Constants

The test defines:
- `APP_INSTANCE_VERSION_STRUCT_SIZE = 24`
- `APP_INSTANCE_VERSION_HIGH_OFFSET = 8`
- `APP_INSTANCE_VERSION_LOW_OFFSET = 16`

Per MS-SMB2 section 2.2.13.2.15: StructureSize(2) + Reserved(2) + Padding(4) + AppInstanceVersionHigh(8) + AppInstanceVersionLow(8) = 24. StructureSize MUST be 24. VersionHigh at offset 8, VersionLow at offset 16. **All CORRECT**.

### Version Comparison Logic

Per MS-SMB2 section 3.3.5.9.13, the server fails the CREATE with STATUS_FILE_FORCED_CLOSED when:
- Old.VersionHigh > New.VersionHigh, OR
- Old.VersionHigh == New.VersionHigh AND Old.VersionLow >= New.VersionLow

This means the server REJECTS the new open when the old version is higher or equal. Equivalently, the old handle should be closed (and the new open allowed) only when the new version is strictly higher.

The test's `should_close_previous()` function implements:
```c
if (!has_version)
    return true; /* Unconditional close */
if (old_high > new_high)
    return false;
if (old_high == new_high && old_low >= new_low)
    return false;
return true;
```

This says: close the old handle when `new_high > old_high`, or `new_high == old_high && new_low > old_low`. Equal versions: do NOT close. This is **the inverse perspective** from the spec -- the spec describes when to REJECT the new request, while the test describes when to CLOSE the old handle. Let me verify they are consistent.

Spec says REJECT when: `old.high > new.high` OR (`old.high == new.high` AND `old.low >= new.low`)
So ACCEPT (close old) when: NOT(reject) = NOT(old.high > new.high) AND NOT(old.high == new.high AND old.low >= new.low)
= (old.high <= new.high) AND (old.high != new.high OR old.low < new.low)
= (old.high < new.high) OR (old.high == new.high AND old.low < new.low)
= new.high > old.high OR (new.high == old.high AND new.low > old.low)

The test function returns true (close) when:
- `!(old_high > new_high)` AND `!(old_high == new_high && old_low >= new_low)` = `old_high <= new_high` AND `(old_high != new_high OR old_low < new_low)`
Which simplifies to: `new_high > old_high` OR `(new_high == old_high AND new_low > old_low)`.

This **matches** the spec exactly.

### Individual Test Cases

**1. test_app_instance_id_valid** -- CORRECT
Parses 16 bytes from offset 4, sets flag. Matches spec layout.

**2. test_app_instance_id_too_short_rejected** -- CORRECT
ctx_len < APP_INSTANCE_ID_STRUCT_SIZE (19 < 20). Trivially true.

**3. test_app_instance_id_zero_guid_ignored** -- CORRECT
Zero GUID should not set has_app_instance_id. The spec doesn't explicitly mandate this behavior but ksmbd treats zero GUID as "no app instance". This is implementation-specific but reasonable.

**4. test_app_instance_id_sets_flag_and_guid** -- CORRECT

**5. test_app_instance_version_valid** -- CORRECT
Parses VersionHigh at offset 8 and VersionLow at offset 16. Matches MS-SMB2 section 2.2.13.2.15 layout.

**6. test_app_instance_version_too_short_rejected** -- CORRECT
23 < 24.

**7. test_app_instance_version_sets_high_and_low** -- CORRECT

**8. test_app_instance_version_sets_flag** -- CORRECT

**9. test_version_high_dominates** -- CORRECT
new_high(2) > old_high(1): close. Matches spec.

**10. test_version_low_breaks_tie** -- CORRECT
Same high(5), new_low(11) > old_low(10): close. Matches spec.

**11. test_version_both_equal_no_close** -- CORRECT
Equal versions (5,10): do NOT close. Per spec: equal triggers `old.low >= new.low` -> reject.

**12. test_version_high_greater_low_less_closes** -- CORRECT
new_high(2) > old_high(1), regardless of low: close.

**13. test_close_previous_no_version_unconditional** -- CORRECT
No version context: unconditional close. Per MS-SMB2 section 3.3.5.9.13: if no APP_INSTANCE_VERSION context and old version is not empty, reject. But if old version IS empty, proceed to close. The test models the "no version context, old has no version" case, which is unconditional close. This matches the spec's description at the end: "If an Open is found, the server MUST calculate the maximal access..." and proceed to close.

**14. test_close_previous_version_lower_no_close** -- CORRECT
old_high(10) > new_high(5): do NOT close. Per spec: reject.

**15. test_close_previous_version_equal_high_lower_low** -- CORRECT
old_high == new_high(5), old_low(20) > new_low(10): do NOT close. Per spec: reject.

**16. test_guid_same_match** -- CORRECT

**17. test_guid_different_no_match** -- CORRECT

**18. test_guid_zero_is_special** -- CORRECT

**19. test_close_previous_same_instance_id** -- CORRECT
No version, unconditional close.

**20. test_close_previous_version_much_higher** -- CORRECT
new_high(100) >> old_high(1): close.

**21. test_close_previous_version_much_lower** -- CORRECT
old_high(100) >> new_high(1): do NOT close.

**22. test_close_previous_high_zero_low_matters** -- CORRECT
Both high=0: low comparison determines outcome.

**23. test_close_previous_max_u64_versions** -- CORRECT
Both at ULLONG_MAX: equal, do NOT close.

**24. test_app_instance_id_struct_size** -- CORRECT
20 = 4 + 16. Matches MS-SMB2 section 2.2.13.2.13.

**25. test_app_instance_version_struct_size** -- CORRECT
24 bytes. 16 + 8 = 24. Matches MS-SMB2 section 2.2.13.2.15.

---

## Summary

| File | Test Cases | CORRECT | WRONG | QUESTIONABLE |
|------|-----------|---------|-------|--------------|
| ksmbd_test_smb2_create.c | 37 | 37 | 0 | 0 |
| ksmbd_test_create_ctx.c | 11 | 11 | 0 | 0 |
| ksmbd_test_create_ctx_tags.c | 9 | 9 | 0 | 0 |
| ksmbd_test_create_maximal_access.c | 17 | 16 | 0 | 1 |
| ksmbd_test_error_create.c | 20 | 20 | 0 | 0 |
| ksmbd_test_app_instance.c | 25 | 25 | 0 | 0 |
| **Total** | **119** | **118** | **0** | **1** |

### WRONG Findings

None.

### QUESTIONABLE Findings

1. **test_mxac_query_status_field_offset** in `/home/ezechiel203/ksmbd/test/ksmbd_test_create_maximal_access.c` (line 107-116): The expression `offsetof(struct create_context, Next) + sizeof(struct create_context) + 8` is unnecessarily convoluted because `offsetof(struct create_context, Next)` is always 0 (Next is the first field). The code works correctly but the expression is misleading -- it appears to suggest that `Next` might not be at offset 0. A clearer expression would be `sizeof(struct create_context) + 8`. This is purely a readability issue; the assertion is correct.

### Key Verification Points Confirmed

- **StructureSize values**: CREATE Request = 57 (not tested in these files, but the tests focus on open flags and create contexts, which is appropriate), CREATE Response = 89 (not tested directly, also appropriate since these are unit tests of helper functions, not PDU construction).
- **Create disposition values**: FILE_SUPERSEDE=0, FILE_OPEN=1, FILE_CREATE=2, FILE_OPEN_IF=3, FILE_OVERWRITE=4, FILE_OVERWRITE_IF=5 -- all correct.
- **Create context tag names**: "MxAc" (0x4D784163), "QFid" (0x51466964), "SecD" (0x53656344), "DHnQ" (0x44486e51), "RqLs" (0x52714c73) -- all match MS-SMB2 section 2.2.13.2.
- **Access mask constants**: FILE_READ_DATA=0x01, FILE_WRITE_DATA=0x02, FILE_APPEND_DATA=0x04, FILE_READ_EA=0x08, FILE_WRITE_EA=0x10, FILE_EXECUTE=0x20, FILE_READ_ATTRIBUTES=0x80, FILE_WRITE_ATTRIBUTES=0x100, FILE_DELETE=0x10000, FILE_SYNCHRONIZE=0x100000, GENERIC_ALL=0x10000000 -- all match MS-SMB2 section 2.2.13.1.1.
- **DESIRED_ACCESS_MASK = 0xF21F01FF** -- correctly includes all standard file-specific bits, standard access rights, generic rights, and MAXIMUM_ALLOWED, while excluding ACCESS_SYSTEM_SECURITY.
- **APP_INSTANCE_ID**: StructureSize=20, GUID at offset 4, length 16 -- matches MS-SMB2 section 2.2.13.2.13.
- **APP_INSTANCE_VERSION**: StructureSize=24, VersionHigh at offset 8, VersionLow at offset 16 -- matches MS-SMB2 section 2.2.13.2.15.
- **Version comparison semantics**: Close old handle when new_version > old_version (lexicographic on high,low) -- correctly implements the inverse of the spec's rejection condition from MS-SMB2 section 3.3.5.9.13.
- **create_context header**: 16 bytes (Next=4 + NameOffset=2 + NameLength=2 + Reserved=2 + DataOffset=2 + DataLength=4) -- matches MS-SMB2 section 2.2.13.2.

### Coverage Gaps (not errors, but noted)

The test suite does not cover:
- StructureSize assertion for CREATE Request (57) or Response (89), though this is outside the scope of open_flags helper tests.
- Error code testing (STATUS_OBJECT_NAME_COLLISION for FILE_CREATE when file exists, STATUS_OBJECT_NAME_NOT_FOUND for FILE_OPEN when file doesn't exist, etc.).
- The APP_INSTANCE_ID 16-byte GUID tag name (0x45BCA66AEFA7F74A9008FA462E144D74) is not verified in any test.
- Durable handle context tags (DH2Q, DH2C, DHnC) are not tested for correctness.
- The `create_app_inst_id` C struct layout is not tested (it has Reserved[8] which seems to pack NameOffset alignment padding differently from other create contexts that use Reserved[2] + Padding).