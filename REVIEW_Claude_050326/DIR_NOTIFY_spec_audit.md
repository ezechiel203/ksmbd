# Dir Notify Spec Audit

Agent ID: a0392a7c2dd7ac18a

Now let me finalize the audit.

---

## Audit Summary

### Files Audited

| # | Requested File | Status |
|---|---------------|--------|
| 1 | `test/ksmbd_test_smb2_dir.c` | EXISTS -- 57 tests audited |
| 2 | `test/ksmbd_test_error_dir.c` | DOES NOT EXIST |
| 3 | `test/ksmbd_test_smb2_notify.c` | EXISTS -- 26 tests audited |
| 4 | `test/ksmbd_test_error_notify.c` | DOES NOT EXIST |

Additionally audited `test/ksmbd_test_notify.c` (46 tests) as the closest substitute for the missing `error_notify` file.

### Overall Totals

- **Total tests audited**: 129 (57 + 26 + 46)
- **CORRECT**: 119
- **WRONG**: 3
- **QUESTIONABLE**: 7

---

### WRONG Findings

#### WRONG-1: `test_invalid_levels_rejected_by_both` includes valid level 0x50 (FILEID_ALL_EXTD_DIRECTORY_INFORMATION)

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_dir.c`, line 333

**Test code**:
```c
static const int invalid_levels[] = {
    0, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16,
    0x20, 0x30, 0x40, 0x50, 0x63, 0x65, 0x80, 0xFF,
};
```

**Problem**: The value `0x50` (80 decimal) is `FILEID_ALL_EXTD_DIRECTORY_INFORMATION`, which is explicitly listed as a valid FileInformationClass in both MS-SMB2 section 2.2.33 (value 0x50, "FileIdAllExtdDirectoryInformation") and section 3.3.5.18 (supported class list). The test expects this level to be rejected with `-EOPNOTSUPP`, which contradicts the spec. This also contradicts the `test_readdir_struct_sz_fileid_all_extd_dir` and `test_verify_info_level_all_extd_dir` tests in the same file, which correctly treat 0x50 as valid.

**Spec reference**: MS-SMB2 section 2.2.33 "FileIdAllExtdDirectoryInformation 0x50" and section 3.3.5.18 "FileIdAllExtdDirectoryInformation" in the supported classes list.

#### WRONG-2: `test_notify_filter_zero` treats zero CompletionFilter as invalid

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_notify.c`, line 278-281

**Test code**:
```c
static void test_notify_filter_zero(struct kunit *test)
{
    KUNIT_EXPECT_FALSE(test, test_validate_completion_filter(0));
}
```

**Problem**: The test asserts that a zero CompletionFilter is invalid. However, MS-SMB2 section 3.3.5.19 explicitly states: "A Change notification request processed by the server with invalid bits in the CompletionFilter field MUST ignore the invalid bits and process the valid bits. If there are no valid bits in the CompletionFilter, the request will remain pending until the change notification is canceled or the directory handle is closed." This means a zero CompletionFilter is allowed by the spec -- it simply results in a perpetually pending watch. The server MUST NOT reject it.

**Spec reference**: MS-SMB2 section 3.3.5.19, paragraph beginning "A Change notification request processed by the server with invalid bits..."

#### WRONG-3: `test_struct_sz_fileid_extd_dir_info` expects sizeof = 96 (should be 88)

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_dir.c`, line 391-393

**Test code**:
```c
static void test_struct_sz_fileid_extd_dir_info(struct kunit *test)
{
    KUNIT_EXPECT_EQ(test, sizeof(struct file_id_extd_dir_info), (size_t)96);
}
```

**Problem**: Per MS-FSCC (referenced by MS-SMB2 section 2.2.33 at value 0x3C), `FileIdExtdDirectoryInformation` has the following wire layout: NextEntryOffset(4) + FileIndex(4) + CreationTime(8) + LastAccessTime(8) + LastWriteTime(8) + ChangeTime(8) + EndOfFile(8) + AllocationSize(8) + FileAttributes(4) + FileNameLength(4) + EaSize(4) + ReparsePointTag(4) + FileId(16) = 88 bytes. The actual `__packed` struct in `/home/ezechiel203/ksmbd/src/include/protocol/smb_common.h` (lines 475-490) also computes to 88 bytes. The test expects 96, which is 8 bytes too large.

**Spec reference**: MS-SMB2 section 2.2.33 referencing MS-FSCC section 2.4, FileIdExtdDirectoryInformation.

---

### QUESTIONABLE Findings

#### Q-1: `test_readdir_struct_sz_fileid_global_tx` -- FILEID_GLOBAL_TX_DIRECTORY_INFORMATION not in MS-SMB2

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_dir.c`, lines 70-76

The test validates `FILEID_GLOBAL_TX_DIRECTORY_INFORMATION` (value 50 = 0x32) as a valid directory info level. This FileInformationClass is NOT listed in MS-SMB2 section 2.2.33 or 3.3.5.18. It exists in MS-FSCC as a Windows-internal level but is not part of the SMB2 protocol specification. The test expects the same struct size as `FILEID_BOTH_DIRECTORY_INFORMATION`, which is also not specified. Whether to support it is implementation-specific.

**Same issue applies to**: `test_verify_info_level_global_tx` (line 234), `test_info_class_constants` (line 469 asserting value 50), and the valid_levels arrays at lines 158 and 307.

#### Q-2: `test_readdir_struct_sz_fileid_extd_both_dir` -- FILEID_EXTD_BOTH_DIRECTORY_INFORMATION not in MS-SMB2

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_dir.c`, lines 85-90

`FILEID_EXTD_BOTH_DIRECTORY_INFORMATION` (value 63 = 0x3F) is NOT listed in MS-SMB2 section 2.2.33 or section 3.3.5.18. It does not appear in the spec at all. Whether to support it is implementation-specific.

**Same issue applies to**: `test_verify_info_level_extd_both_dir` (line 244), `test_struct_sz_fileid_extd_both_dir_info` (line 396), `test_info_class_constants` (line 471 asserting value 63), and the valid_levels arrays.

#### Q-3: `test_readdir_struct_sz_smb_find_posix` -- SMB_FIND_FILE_POSIX_INFO uses reserved value 0x64

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_dir.c`, lines 120-125

`SMB_FIND_FILE_POSIX_INFO` (0x064 = 100) reuses the `FileInformationClass_Reserved` value (0x64) which MS-SMB2 section 2.2.33 states "MUST be reserved and MUST be ignored on receipt." This is a non-standard POSIX extension used by Linux/Samba for POSIX semantics. It is not part of the MS-SMB2 specification.

**Same issue applies to**: `test_verify_info_level_posix` (line 269), `test_info_class_constants` (line 476).

#### Q-4: `test_struct_sz_fileid_extd_both_dir_info` expects sizeof = 122 (likely should be 114)

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_dir.c`, lines 396-399

If the struct wire format is computed from the `__packed` struct definition (NextEntryOffset through ShortName[24]), the result is 114 bytes, not 122. However, since this info class (0x3F) is not defined in MS-SMB2, there is no spec reference to validate against. Marked QUESTIONABLE rather than WRONG because the info class itself is non-standard.

#### Q-5: `test_notify_compound_not_last` -- No normative spec requirement

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_notify.c`, lines 176-181

The test asserts that CHANGE_NOTIFY in a compound chain (not as last request) returns -EINVAL (STATUS_INVALID_PARAMETER). The comment claims "MS-SMB2 3.3.5.19" as the source. However, section 3.3.5.19 does not mention compound requests at all. The behavior is described in an implementation note (<266>) at section 3.3.5.2.7 which says Windows fails such operations with STATUS_INTERNAL_ERROR (not STATUS_INVALID_PARAMETER). This is a reasonable implementation choice but does not precisely match either the normative spec or the Windows behavior note.

#### Q-6: `test_notify_action_values` -- Stream action values not in MS-SMB2

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_notify.c`, lines 385-395

The test validates `FILE_ACTION_ADDED_STREAM` (0x06), `FILE_ACTION_REMOVED_STREAM` (0x07), and `FILE_ACTION_MODIFIED_STREAM` (0x08). These values are defined in MS-FSCC section 2.7.1, not in MS-SMB2 directly. MS-SMB2 only references the FILE_NOTIFY_INFORMATION structure by cross-reference. The values are correct per MS-FSCC but are not independently verifiable against MS-SMB2 alone.

#### Q-7: `test_real_action_zero_default` -- Zero fsnotify mask defaults to FILE_ACTION_MODIFIED

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_notify.c`, lines 546-550

The test asserts that `ksmbd_fsnotify_to_action(0)` returns `FILE_ACTION_MODIFIED`. There is no spec guidance on what action to use for an unmapped fsnotify event. This is purely an implementation decision with no spec basis to validate against.

---

### Detailed Breakdown by File

#### `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_dir.c` (57 tests)

| Category | Count |
|----------|-------|
| CORRECT | 47 |
| WRONG | 2 (WRONG-1, WRONG-3) |
| QUESTIONABLE | 8 (Q-1 x4, Q-2 x3, Q-3 x3 -- some tests touch multiple issues, counted per distinct test) |

Note: Some tests touch multiple questionable issues simultaneously (e.g., `test_info_class_constants` validates multiple values, some correct and some questionable). The 8 QUESTIONABLE count represents individual tests that contain at least one questionable assertion.

#### `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_notify.c` (26 tests)

| Category | Count |
|----------|-------|
| CORRECT | 22 |
| WRONG | 1 (WRONG-2) |
| QUESTIONABLE | 3 (Q-5, Q-6, partially overlapping with Q-6 for stream actions) |

Note: `test_notify_action_values` (Q-6) validates 8 values; 5 are standard MS-FSCC values and 3 are stream-specific MS-FSCC values. The entire test is QUESTIONABLE because the stream values, while correct per MS-FSCC, are not verifiable against MS-SMB2 alone.

#### `/home/ezechiel203/ksmbd/test/ksmbd_test_notify.c` (46 tests)

| Category | Count |
|----------|-------|
| CORRECT | 45 |
| WRONG | 0 |
| QUESTIONABLE | 1 (Q-7) |