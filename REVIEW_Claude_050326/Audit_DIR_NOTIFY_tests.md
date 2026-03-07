# Audit Dir Notify Tests

Agent ID: a3b52f4288ccd87df

Good. The test expectations for `ksmbd_fsnotify_to_smb2_filter` and `ksmbd_fsnotify_to_action` match the actual implementation. Let me verify the specific test expectations:

- `test_real_filter_create`: FS_CREATE -> 0xFFF. Code: `filter |= KSMBD_NOTIFY_ALL_FILTERS` (0xFFF). **CORRECT**.
- `test_real_filter_delete`: FS_DELETE -> 0xFFF. Same pattern. **CORRECT**.
- `test_real_filter_modify`: FS_MODIFY -> LAST_WRITE | SIZE = 0x10 | 0x08 = 0x18. **CORRECT**.
- `test_real_filter_attrib`: FS_ATTRIB -> ATTRIBUTES | SECURITY | EA = 0x04 | 0x100 | 0x80 = 0x184. **CORRECT**.
- `test_real_filter_moved_from`: FS_MOVED_FROM -> 0xFFF. **CORRECT**.
- `test_real_filter_moved_to`: FS_MOVED_TO -> 0xFFF. **CORRECT**.
- `test_real_filter_access`: FS_ACCESS -> LAST_ACCESS = 0x20. **CORRECT**.
- `test_real_filter_zero`: 0 -> 0. **CORRECT**.
- `test_real_action_create`: FS_CREATE -> FILE_ACTION_ADDED (1). **CORRECT**.
- `test_real_action_delete`: FS_DELETE -> FILE_ACTION_REMOVED (2). **CORRECT**.
- `test_real_action_moved_from`: FS_MOVED_FROM -> FILE_ACTION_RENAMED_OLD_NAME (4). **CORRECT**.
- `test_real_action_moved_to`: FS_MOVED_TO -> FILE_ACTION_RENAMED_NEW_NAME (5). **CORRECT**.
- `test_real_action_modify_default`: FS_MODIFY -> FILE_ACTION_MODIFIED (3). Falls through to default. **CORRECT**.
- `test_real_action_zero_default`: 0 -> FILE_ACTION_MODIFIED (3). Falls through. **CORRECT**.

Now let me compile the complete audit report.

---

Here is the complete audit report for all four test files against the MS-SMB2 specification.

---

## AUDIT REPORT: Directory and Notify KUnit Tests vs MS-SMB2 Specification

---

### FILE 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_dir.c`

**Suite: `ksmbd_smb2_dir`** (45 KUNIT_CASEs)

#### Group: readdir_info_level_struct_sz tests (14 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 1 | `test_readdir_struct_sz_file_directory` | **CORRECT** | FILE_DIRECTORY_INFORMATION (1) maps to `struct file_directory_info`. Value matches MS-SMB2 section 2.2.33, MS-FSCC section 2.4. |
| 2 | `test_readdir_struct_sz_file_full_directory` | **CORRECT** | FILE_FULL_DIRECTORY_INFORMATION (2) maps to `struct file_full_directory_info`. |
| 3 | `test_readdir_struct_sz_file_both_directory` | **CORRECT** | FILE_BOTH_DIRECTORY_INFORMATION (3) maps to `struct file_both_directory_info`. |
| 4 | `test_readdir_struct_sz_file_names` | **CORRECT** | FILE_NAMES_INFORMATION (12 = 0x0C) maps to `struct file_names_info`. |
| 5 | `test_readdir_struct_sz_fileid_full_dir` | **CORRECT** | FILEID_FULL_DIRECTORY_INFORMATION (38 = 0x26) maps correctly per MS-SMB2 section 2.2.33. |
| 6 | `test_readdir_struct_sz_fileid_both_dir` | **CORRECT** | FILEID_BOTH_DIRECTORY_INFORMATION (37 = 0x25) maps correctly per MS-SMB2 section 2.2.33. |
| 7 | `test_readdir_struct_sz_fileid_global_tx` | **CORRECT** | FILEID_GLOBAL_TX_DIRECTORY_INFORMATION (50) -- not in MS-SMB2 table but from MS-FSCC. Internal implementation maps to same struct as FILEID_BOTH. |
| 8 | `test_readdir_struct_sz_fileid_extd_dir` | **CORRECT** | FILEID_EXTD_DIRECTORY_INFORMATION (60 = 0x3C) per MS-SMB2 section 2.2.33. |
| 9 | `test_readdir_struct_sz_fileid_extd_both_dir` | **CORRECT** | FILEID_EXTD_BOTH_DIRECTORY_INFORMATION (63) -- not explicitly in MS-SMB2 table but from MS-FSCC. |
| 10 | `test_readdir_struct_sz_fileid_64_extd_dir` | **CORRECT** | FILEID_64_EXTD_DIRECTORY_INFORMATION (78 = 0x4E) per MS-SMB2 section 2.2.33. |
| 11 | `test_readdir_struct_sz_fileid_64_extd_both_dir` | **CORRECT** | FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION (79 = 0x4F) per MS-SMB2 section 2.2.33. |
| 12 | `test_readdir_struct_sz_fileid_all_extd_dir` | **CORRECT** | FILEID_ALL_EXTD_DIRECTORY_INFORMATION (80 = 0x50) per MS-SMB2 section 2.2.33. |
| 13 | `test_readdir_struct_sz_fileid_all_extd_both_dir` | **CORRECT** | FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION (81 = 0x51) per MS-SMB2 section 2.2.33. |
| 14 | `test_readdir_struct_sz_smb_find_posix` | **CORRECT** | SMB_FIND_FILE_POSIX_INFO (0x064 = 100). Linux POSIX extension reusing reserved MS-SMB2 value 0x64 (MS-SMB2 section 2.2.33 says "FileInformationClass_Reserved 0x64"). This is intentional. |

#### Group: invalid level tests (3 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 15 | `test_readdir_struct_sz_invalid_zero` | **CORRECT** | Level 0 is not a valid FileInformationClass. Returns -EOPNOTSUPP. |
| 16 | `test_readdir_struct_sz_invalid_0xff` | **CORRECT** | Level 0xFF is not valid. Returns -EOPNOTSUPP. |
| 17 | `test_readdir_struct_sz_invalid_negative` | **CORRECT** | Level -1 is not valid. Returns -EOPNOTSUPP. |

#### Group: aggregate tests (2 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 18 | `test_readdir_struct_sz_all_positive` | **CORRECT** | Verifies all valid levels return positive struct sizes. |
| 19 | `test_readdir_struct_sz_names_is_smallest` | **CORRECT** | FILE_NAMES_INFORMATION has only NextEntryOffset + FileIndex + FileNameLength = 12 bytes, correctly the smallest. |
| 20 | `test_readdir_struct_sz_both_larger_than_full` | **CORRECT** | FILE_BOTH adds ShortNameLength(1) + Reserved(1) + ShortName[24](24) = 26 bytes over FILE_FULL. |

#### Group: verify_info_level tests (18 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 21-34 | `test_verify_info_level_*` (14 valid levels) | **CORRECT** | All 14 valid levels return 0. Levels match MS-SMB2 section 3.3.5.18 supported list plus ksmbd extensions (GLOBAL_TX, EXTD_BOTH, POSIX). |
| 35-38 | `test_verify_info_level_invalid_*` (4 invalid levels) | **CORRECT** | Levels 0, 0xFF, 0x10 (16), and -1 all return -EOPNOTSUPP. |

#### Group: cross-validation tests (2 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 39 | `test_verify_and_struct_sz_consistent` | **CORRECT** | Good consistency check -- every valid level has a positive struct size. |
| 40 | `test_invalid_levels_rejected_by_both` | **WRONG** | **BUG: The invalid levels array includes 0x50 (= 80 decimal = FILEID_ALL_EXTD_DIRECTORY_INFORMATION), which is a VALID level.** This directly contradicts `test_verify_info_level_all_extd_dir` (case #33) and `test_readdir_struct_sz_fileid_all_extd_dir` (case #12), both of which assert level 80 is valid. **Spec ref: MS-SMB2 section 2.2.33 lists FileIdAllExtdDirectoryInformation (0x50) as a valid FileInformationClass; section 3.3.5.18 lists it as supported.** **Fix: Remove 0x50 from the invalid_levels array.** The other hex values in the array are genuinely invalid (0x20=32, 0x30=48, 0x40=64, 0x63=99, 0x65=101, 0x80=128, 0xFF=255). |

#### Group: struct layout tests (11 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 41 | `test_struct_sz_file_directory_info` | **CORRECT** | sizeof = 64 bytes. Manual count: 4+4+(6x8)+4+4 = 64. |
| 42 | `test_struct_sz_file_full_directory_info` | **CORRECT** | sizeof = 68 bytes. Adds EaSize(4) to file_directory_info. |
| 43 | `test_struct_sz_file_both_directory_info` | **CORRECT** | sizeof = 94 bytes. Adds ShortNameLength(1) + Reserved(1) + ShortName[24](24) to file_full. |
| 44 | `test_struct_sz_file_names_info` | **CORRECT** | sizeof = 12 bytes. NextEntryOffset(4) + FileIndex(4) + FileNameLength(4). |
| 45 | `test_struct_sz_fileid_full_dir_info` | **CORRECT** | sizeof = 80 bytes. file_full(68) + Reserved(4) + UniqueId(8). |
| 46 | `test_struct_sz_fileid_both_dir_info` | **CORRECT** | sizeof = 104 bytes. file_both(94) + Reserved2(2) + UniqueId(8). |
| 47 | `test_struct_sz_fileid_extd_dir_info` | **WRONG** | **Expected sizeof = 96, but actual sizeof of `struct file_id_extd_dir_info` is 88 bytes.** Manual count: file_full(68) + ReparsePointTag(4) + FileId[16](16) = 88 bytes. The struct is `__packed` so no padding is added. The test comment says "adds ReparsePointTag + FileId[16] = 96" which is arithmetically wrong. **Fix: Change expected size from 96 to 88.** |
| 48 | `test_struct_sz_fileid_extd_both_dir_info` | **WRONG** | **Expected sizeof = 122, but actual sizeof is 114 bytes.** Manual count: file_id_extd_dir(88) + ShortNameLength(1) + Reserved(1) + ShortName[24](24) = 114 bytes. **Fix: Change expected size from 122 to 114.** |
| 49 | `test_struct_sz_fileid_64_extd_dir_info` | **CORRECT** | sizeof = 80 bytes. file_full(68) + ReparsePointTag(4) + FileId(__le64=8). |
| 50 | `test_struct_sz_fileid_64_extd_both_dir_info` | **CORRECT** | sizeof = 106 bytes. file_id_64_extd(80) + ShortNameLength(1) + Reserved(1) + ShortName[24](24). |
| 51 | `test_struct_sz_fileid_all_extd_dir_info` | **CORRECT** | sizeof = 96 bytes. file_id_64_extd(80) + FileId128[16](16). |

#### Group: alignment tests (5 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 52 | `test_dir_info_alignment_value` | **CORRECT** | KSMBD_DIR_INFO_ALIGNMENT = 8. MS-FSCC specifies 8-byte alignment for directory entry NextEntryOffset. |
| 53 | `test_dir_info_alignment_round_up` | **CORRECT** | ALIGN(65, 8) = 72. |
| 54 | `test_dir_info_alignment_exact` | **CORRECT** | ALIGN(64, 8) = 64. |
| 55 | `test_dir_info_alignment_from_one` | **CORRECT** | ALIGN(1, 8) = 8. |
| 56 | `test_dir_info_alignment_zero` | **CORRECT** | ALIGN(0, 8) = 0. |

#### Group: constant value tests (1 case)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 57 | `test_info_class_constants` | **CORRECT** | All FileInformationClass constant values verified against MS-SMB2 section 2.2.33: FileDirectoryInformation=1 (0x01), FileFullDirectoryInformation=2 (0x02), FileBothDirectoryInformation=3 (0x03), FileNamesInformation=12 (0x0C), FileIdBothDirectoryInformation=37 (0x25), FileIdFullDirectoryInformation=38 (0x26), FileIdGlobalTxDirectoryInformation=50, FileIdExtdDirectoryInformation=60 (0x3C), FileIdExtdBothDirectoryInformation=63, FileId64ExtdDirectoryInformation=78 (0x4E), FileId64ExtdBothDirectoryInformation=79 (0x4F), FileIdAllExtdDirectoryInformation=80 (0x50), FileIdAllExtdBothDirectoryInformation=81 (0x51), SMB_FIND_FILE_POSIX_INFO=0x064. All match. |

---

### FILE 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_notify.c`

**Suite: `ksmbd_smb2_notify`** (25 KUNIT_CASEs)

#### Group: Request Validation (7 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 1 | `test_notify_basic_setup` | **CORRECT** | Validates that a directory with FILE_LIST_DIRECTORY access succeeds. Per MS-SMB2 section 3.3.5.19: must be directory + must have FILE_LIST_DIRECTORY. |
| 2 | `test_notify_invalid_fid` | **CORRECT** | Trivially tests NULL fp. Per MS-SMB2 section 3.3.5.19: "If no open is found... MUST fail with STATUS_FILE_CLOSED." |
| 3 | `test_notify_non_directory` | **CORRECT** | Non-directory returns -EINVAL (STATUS_INVALID_PARAMETER). Per MS-SMB2 section 3.3.5.19 line 25328-25329. |
| 4 | `test_notify_no_list_directory` | **CORRECT** | Missing FILE_LIST_DIRECTORY returns -EACCES (STATUS_ACCESS_DENIED). Per MS-SMB2 section 3.3.5.19 line 25331-25332. |
| 5 | `test_notify_compound_not_last` | **QUESTIONABLE** | Tests that CHANGE_NOTIFY not as last in compound returns -EINVAL. **The test comment cites "MS-SMB2 3.3.5.19" but this requirement is not stated in the spec.** MS-SMB2 section 3.3.5.19 does not mention compound restrictions for CHANGE_NOTIFY. This appears to be a ksmbd implementation constraint (since NOTIFY goes async), not a spec requirement. The behavior is sensible but the spec reference is inaccurate. |
| 6 | `test_notify_compound_last_ok` | **QUESTIONABLE** | Companion to case #5. Same spec reference concern. |
| 7 | `test_notify_compound_fid_propagation` | **CORRECT** | Tests that compound FID (0xFFFFFFFFFFFFFFFF sentinel) resolves to the compound's persisted FID. Per MS-SMB2 section 3.3.5.2.7.2. |

#### Group: Flags (2 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 8 | `test_notify_watch_tree` | **CORRECT** | SMB2_WATCH_TREE = 0x0001. Per MS-SMB2 section 2.2.35 line 9130-9131. |
| 9 | `test_notify_no_watch_tree` | **CORRECT** | Flags=0 means no subtree monitoring. Per MS-SMB2 section 2.2.35 line 9127-9128. |

#### Group: Completion Filter (8 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 10 | `test_notify_filter_file_name` | **CORRECT** | FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001. Per MS-SMB2 section 2.2.35 line 9146-9147. |
| 11 | `test_notify_filter_dir_name` | **CORRECT** | FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002. Per line 9149-9150. |
| 12 | `test_notify_filter_attributes` | **CORRECT** | 0x00000004. Per line 9152-9153. |
| 13 | `test_notify_filter_size` | **CORRECT** | 0x00000008. Per line 9155-9156. |
| 14 | `test_notify_filter_last_write` | **CORRECT** | 0x00000010. Per line 9158-9159. |
| 15 | `test_notify_filter_security` | **CORRECT** | 0x00000100. Per line 9170-9171. |
| 16 | `test_notify_filter_combined` | **CORRECT** | Tests combined filter matching logic. Correctly verifies that CHANGE_SECURITY does not match a filter of FILE_NAME|SIZE|LAST_WRITE. |
| 17 | `test_notify_filter_zero` | **CORRECT** | Zero completion filter has no valid bits. Per MS-SMB2 section 3.3.5.19 lines 25347-25350: "If there are no valid bits in the CompletionFilter, the request will remain pending until the change notification is canceled or the directory handle is closed." The test correctly identifies zero as having no valid filter bits. |

#### Group: Async / Cancel (4 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 18 | `test_notify_returns_status_pending` | **CORRECT** | STATUS_PENDING = 0x00000103 per MS-ERREF. CHANGE_NOTIFY is handled asynchronously per MS-SMB2 section 3.3.5.19. |
| 19 | `test_notify_cancel` | **CORRECT** | STATUS_CANCELLED = 0xC0000120 per MS-ERREF. Cancel behavior per MS-SMB2 section 3.3.5.16. |
| 20 | `test_notify_cancel_piggyback` | **CORRECT** | Tests async counter decrement on piggyback cancel. Implementation-level test, no protocol issue. |
| 21 | `test_notify_outstanding_async_counter` | **CORRECT** | Tests increment/decrement of outstanding async count. Implementation-level. |

#### Group: Output (4 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 22 | `test_notify_response_format` | **CORRECT** | FILE_NOTIFY_INFORMATION structure fields: NextEntryOffset(4), Action(4), FileNameLength(4). Per MS-FSCC section 2.7.1 (referenced from MS-SMB2 section 2.2.36 line 9224). |
| 23 | `test_notify_multiple_events` | **CORRECT** | Tests 4-byte alignment of NextEntryOffset for non-last entries and no alignment for last entry. Alignment is per MS-FSCC 2.7.1. |
| 24 | `test_notify_output_buffer_overflow` | **CORRECT** | Tests that entry larger than OutputBufferLength is detected. Per MS-SMB2 section 3.3.5.19 lines 25360-25362: "If the server is unable to copy the results into the buffer... set the Status to STATUS_NOTIFY_ENUM_DIR." |
| 25 | `test_notify_output_buffer_exact_fit` | **CORRECT** | Tests boundary condition where entry exactly fits buffer. |

#### Group: Action Values (1 case)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 26 | `test_notify_action_values` | **CORRECT** | All FILE_ACTION values match MS-FSCC section 2.7.1: ADDED=1, REMOVED=2, MODIFIED=3, RENAMED_OLD_NAME=4, RENAMED_NEW_NAME=5, ADDED_STREAM=6, REMOVED_STREAM=7, MODIFIED_STREAM=8. |

#### Additional Notes

- The `TEST_SMB2_CHANGE_NOTIFY_REQ_STRUCT_SIZE = 32` constant is **CORRECT** per MS-SMB2 section 2.2.35 line 9111.
- The `TEST_SMB2_HEADER_SIZE = 64` constant is **CORRECT** per MS-SMB2 section 2.2.1.
- The test file uses replicated logic (not calling production functions), which limits the test's ability to catch production bugs but makes the constants/logic self-consistent.

---

### FILE 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_notify.c`

**Suite: `ksmbd_notify`** (42 KUNIT_CASEs)

#### Group: Data Structure Tests (2 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 1 | `test_notify_change_struct_init` | **CORRECT** | Tests `struct ksmbd_notify_change` initialization. FILE_ACTION_ADDED = 0x00000001 per MS-FSCC. |
| 2 | `test_notify_watch_struct_init` | **CORRECT** | Tests `struct ksmbd_notify_watch` initialization. Completion filter 0x17 = FILE_NAME|DIR_NAME|ATTRIBUTES|SIZE|LAST_WRITE, all valid per MS-SMB2 section 2.2.35. |

#### Group: Filter Flag Tests (9 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 3-9 | `test_notify_filter_{file_name,dir_name,attributes,size,last_write,security,creation}_change` | **CORRECT** | All filter bit values match MS-SMB2 section 2.2.35. |
| 10 | `test_notify_filter_combined_flags` | **CORRECT** | Tests combined filter bitmask matching. |
| 11 | `test_notify_filter_no_match_no_delivery` | **CORRECT** | Correctly tests that non-matching events are not delivered. |

#### Group: File Action Constants (1 case)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 12 | `test_notify_file_action_constants` | **CORRECT** | FILE_ACTION_ADDED=1, REMOVED=2, MODIFIED=3, RENAMED_OLD_NAME=4, RENAMED_NEW_NAME=5. All per MS-FSCC section 2.7.1. **Note:** This test does not cover stream actions (ADDED_STREAM=6, REMOVED_STREAM=7, MODIFIED_STREAM=8) unlike the smb2_notify test file. This is not wrong, just incomplete coverage. |

#### Group: Buffer Validation Tests (5 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 13 | `test_notify_response_single_entry_fits` | **CORRECT** | NOTIFY_INFO_HEADER_SIZE = 12 bytes (NextEntryOffset(4) + Action(4) + FileNameLength(4)), per MS-FSCC 2.7.1. Entry with 20-byte name fits in 4096-byte buffer. |
| 14 | `test_notify_response_truncated_at_max` | **CORRECT** | Tests that a large name exceeds a small buffer. |
| 15 | `test_notify_response_overflow_set_flag` | **CORRECT** | Tests completed flag set on overflow. Per MS-SMB2 section 3.3.5.19: STATUS_NOTIFY_ENUM_DIR when buffer too small. |
| 16 | `test_notify_response_buffer_exactly_fits` | **CORRECT** | Boundary test. |
| 17 | `test_notify_response_buffer_one_byte_short` | **CORRECT** | Off-by-one boundary test. |

#### Group: Watch Tree Semantics (2 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 18 | `test_notify_add_watch_tree_flag_set` | **CORRECT** | SMB2_WATCH_TREE semantics per MS-SMB2 section 2.2.35. |
| 19 | `test_notify_watch_non_tree_default` | **CORRECT** | Default is no subtree monitoring. |

#### Group: Buffered Changes Management (2 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 20 | `test_notify_buffered_count_increments` | **CORRECT** | Implementation-level test, no protocol issue. |
| 21 | `test_notify_completed_flag` | **CORRECT** | Implementation-level test. |

#### Group: Stream Notification Filter Tests (5 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 22 | `test_notify_filter_stream_name_change` | **CORRECT** | 0x00000200 per MS-SMB2 section 2.2.35 line 9173-9174. |
| 23 | `test_notify_filter_stream_size_change` | **CORRECT** | 0x00000400 per line 9176-9177. |
| 24 | `test_notify_filter_stream_write_change` | **CORRECT** | 0x00000800 per line 9179-9180. |
| 25 | `test_notify_filter_ea_change` | **CORRECT** | 0x00000080 per line 9167-9168. |
| 26 | `test_notify_filter_last_access_change` | **CORRECT** | 0x00000020 per line 9161-9162. |

#### Group: Entry Alignment Tests (3 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 27 | `test_notify_entry_alignment_short_name` | **CORRECT** | 4-byte alignment per MS-FSCC 2.7.1 for FILE_NOTIFY_INFORMATION entries. |
| 28 | `test_notify_entry_alignment_long_name` | **CORRECT** | Same alignment. |
| 29 | `test_notify_entry_alignment_odd_name` | **CORRECT** | 12+13=25 -> aligned to 28. |

#### Group: Multiple Buffered Changes (2 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 30 | `test_notify_multiple_changes_accumulate` | **CORRECT** | Implementation test. |
| 31 | `test_notify_completed_overrides` | **CORRECT** | Implementation test. |

#### Group: All Filters Combined (1 case)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 32 | `test_notify_all_filters_combined` | **CORRECT** | All 12 filter bits OR'd = 0x00000FFF. Matches sum of all values in MS-SMB2 section 2.2.35 CompletionFilter table. |

#### Group: Real Production Function Tests (14 cases)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 33 | `test_real_filter_create` | **CORRECT** | FS_CREATE -> 0xFFF (all filters). Matches implementation in `ksmbd_notify.c`. |
| 34 | `test_real_filter_delete` | **CORRECT** | FS_DELETE -> 0xFFF. Same logic. |
| 35 | `test_real_filter_modify` | **CORRECT** | FS_MODIFY -> LAST_WRITE(0x10) | SIZE(0x08) = 0x18. |
| 36 | `test_real_filter_attrib` | **CORRECT** | FS_ATTRIB -> ATTRIBUTES(0x04) | SECURITY(0x100) | EA(0x80) = 0x184. |
| 37 | `test_real_filter_moved_from` | **CORRECT** | FS_MOVED_FROM -> 0xFFF. |
| 38 | `test_real_filter_moved_to` | **CORRECT** | FS_MOVED_TO -> 0xFFF. |
| 39 | `test_real_filter_access` | **CORRECT** | FS_ACCESS -> LAST_ACCESS(0x20). |
| 40 | `test_real_filter_zero` | **CORRECT** | 0 -> 0. |
| 41 | `test_real_action_create` | **CORRECT** | FS_CREATE -> FILE_ACTION_ADDED (1). |
| 42 | `test_real_action_delete` | **CORRECT** | FS_DELETE -> FILE_ACTION_REMOVED (2). |
| 43 | `test_real_action_moved_from` | **CORRECT** | FS_MOVED_FROM -> FILE_ACTION_RENAMED_OLD_NAME (4). |
| 44 | `test_real_action_moved_to` | **CORRECT** | FS_MOVED_TO -> FILE_ACTION_RENAMED_NEW_NAME (5). |
| 45 | `test_real_action_modify_default` | **CORRECT** | FS_MODIFY -> FILE_ACTION_MODIFIED (3), via default path. |
| 46 | `test_real_action_zero_default` | **CORRECT** | 0 -> FILE_ACTION_MODIFIED (3), via default path. |

---

### FILE 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_concurrency_notify.c`

**Suite: `ksmbd_concurrency_notify`** (5 KUNIT_CASEs)

| # | Test | Verdict | Notes |
|---|------|---------|-------|
| 1 | `test_notify_parallel_register` | **CORRECT** | Pure concurrency test -- 4 threads registering watchers in parallel. Tests spinlock correctness. No protocol-level assertions. |
| 2 | `test_notify_register_fire_race` | **CORRECT** | Tests race between registering watchers and firing events. No protocol-level assertions. |
| 3 | `test_notify_register_cancel_race` | **CORRECT** | Tests race between registering and canceling. No protocol-level assertions. |
| 4 | `test_notify_fire_cancel_race` | **CORRECT** | Tests three-way race: register + fire + cancel. No protocol-level assertions. |
| 5 | `test_notify_empty_fire` | **CORRECT** | Tests firing on empty watcher list. No protocol-level assertions. |

**Overall verdict for this file:** All 5 tests are implementation-level concurrency safety tests. They do not make any protocol-level assertions and are therefore not subject to MS-SMB2 spec compliance verification. All appear correctly designed.

---

## SUMMARY OF FINDINGS

### WRONG (3 issues)

1. **`test_invalid_levels_rejected_by_both` in `ksmbd_test_smb2_dir.c` (line 334):** The invalid_levels array includes `0x50` (= 80 decimal = `FILEID_ALL_EXTD_DIRECTORY_INFORMATION`), which is a valid FileInformationClass per MS-SMB2 section 2.2.33 and section 3.3.5.18. This contradicts other tests in the same file that assert level 80 is valid. **Fix:** Remove `0x50` from the invalid_levels array.

2. **`test_struct_sz_fileid_extd_dir_info` in `ksmbd_test_smb2_dir.c` (line 393):** Expects `sizeof(struct file_id_extd_dir_info) == 96` but the actual packed struct size is 88 bytes (NextEntryOffset(4) + FileIndex(4) + CreationTime(8) + LastAccessTime(8) + LastWriteTime(8) + ChangeTime(8) + EndOfFile(8) + AllocationSize(8) + ExtFileAttributes(4) + FileNameLength(4) + EaSize(4) + ReparsePointTag(4) + FileId[16](16) = 88). **Fix:** Change expected size from `(size_t)96` to `(size_t)88`.

3. **`test_struct_sz_fileid_extd_both_dir_info` in `ksmbd_test_smb2_dir.c` (line 399):** Expects `sizeof(struct file_id_extd_both_dir_info) == 122` but the actual packed struct size is 114 bytes (88 + ShortNameLength(1) + Reserved(1) + ShortName[24](24) = 114). **Fix:** Change expected size from `(size_t)122` to `(size_t)114`.

### QUESTIONABLE (2 issues)

1. **`test_notify_compound_not_last` in `ksmbd_test_smb2_notify.c` (line 177):** The test comment cites "MS-SMB2 3.3.5.19" for the requirement that CHANGE_NOTIFY must be the last request in a compound. However, MS-SMB2 section 3.3.5.19 does not state this requirement. The behavior is a reasonable implementation choice (since CHANGE_NOTIFY goes async) but the spec citation is incorrect.

2. **`test_notify_compound_last_ok` in `ksmbd_test_smb2_notify.c` (line 185):** Same spec citation concern as above.

### CORRECT (all remaining)

All other test cases across all four files (112 total excluding the 5 above) are **CORRECT** with respect to the MS-SMB2 specification. Protocol constants, StructureSize values, flag values, completion filter bitmasks, FILE_ACTION values, alignment rules, and error code semantics all match the specification.