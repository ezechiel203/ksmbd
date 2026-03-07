# Vfs Acl Vss Spec Audit

Agent ID: a0001b22b4059ddf5

So 82 total, with 7 conditional. That means 75 unconditional + 7 conditional = 82.

Now I have all the information needed for the audit. Here is my comprehensive analysis:

---

## Test Audit Report: Cross-referencing KUnit Tests Against MS-SMB2 Specification

### Files Audited

Note: Three of the six requested files do not exist in the repository:
- `/home/ezechiel203/ksmbd/test/ksmbd_test_smbacl.c` -- does not exist (closest: `ksmbd_test_acl.c`)
- `/home/ezechiel203/ksmbd/test/ksmbd_test_acl_xattr.c` -- does not exist
- `/home/ezechiel203/ksmbd/test/ksmbd_test_xattr.c` -- does not exist

The audit covers the four files that exist:

| File | Path | Test Count |
|------|------|-----------|
| ksmbd_test_vfs.c | `/home/ezechiel203/ksmbd/test/ksmbd_test_vfs.c` | 82 (75 + 7 conditional) |
| ksmbd_test_vfs_cache.c | `/home/ezechiel203/ksmbd/test/ksmbd_test_vfs_cache.c` | 66 |
| ksmbd_test_acl.c | `/home/ezechiel203/ksmbd/test/ksmbd_test_acl.c` | 89 |
| ksmbd_test_vss.c | `/home/ezechiel203/ksmbd/test/ksmbd_test_vss.c` | 32 |

**Total tests audited: 269**

---

### Summary

| Classification | Count |
|---------------|-------|
| CORRECT | 265 |
| WRONG | 1 |
| QUESTIONABLE | 3 |

---

### WRONG Findings

#### W-1: `test_vfs_set_fadvise_sequential_and_random` -- WRONG

**File:** `/home/ezechiel203/ksmbd/test/ksmbd_test_vfs.c`, lines 395-403

**Test code:**
```c
static void test_vfs_set_fadvise_sequential_and_random(struct kunit *test)
{
    /*
     * If both flags are set, sequential takes priority
     * (checked first in the if/else chain).
     */
    __le32 both = FILE_SEQUENTIAL_ONLY_LE | FILE_RANDOM_ACCESS_LE;
    KUNIT_EXPECT_EQ(test, test_fadvise_map(both), POSIX_FADV_SEQUENTIAL);
}
```

**Spec reference:** MS-SMB2 section 2.2.13, CreateOptions, FILE_RANDOM_ACCESS (0x00000800), lines 4879-4881 of `ms-smb2.txt`:

> "This flag value is incompatible with the FILE_SEQUENTIAL_ONLY value. If both FILE_RANDOM_ACCESS and FILE_SEQUENTIAL_ONLY are set, then FILE_SEQUENTIAL_ONLY is ignored."

**Problem:** The spec explicitly states that when both flags are set, FILE_SEQUENTIAL_ONLY is ignored, meaning FILE_RANDOM_ACCESS should take effect. The test expects `POSIX_FADV_SEQUENTIAL`, but per the spec the correct result should be `POSIX_FADV_RANDOM`. The test comment ("sequential takes priority") directly contradicts the spec.

**Note:** The production code at `/home/ezechiel203/ksmbd/src/fs/vfs.c` lines 2959-2964 has the same bug -- it checks `FILE_SEQUENTIAL_ONLY_LE` before `FILE_RANDOM_ACCESS_LE` in an if/else-if chain, so when both are set, sequential incorrectly wins. Both the test and the production code are wrong relative to the spec.

---

### QUESTIONABLE Findings

#### Q-1: `test_real_is_gmt_token_24chars` -- Tests a Production Bug

**File:** `/home/ezechiel203/ksmbd/test/ksmbd_test_vss.c`, lines 323-329

**Test code:**
```c
static void test_real_is_gmt_token_24chars(struct kunit *test)
{
    const char *token = "@GMT-2024.01.15-10.30.00";
    /* 24 chars: production code expects 31, so this returns false */
    KUNIT_EXPECT_FALSE(test, ksmbd_vss_is_gmt_token(token, 24));
}
```

**Spec reference:** MS-SMB2 Glossary, `@GMT token`, lines 866-869 of `ms-smb2.txt`:

> "@GMT token: A special token that can be present as part of a file path to indicate a request to see a previous version of the file or directory. The format is '@GMT-YYYY.MM.DD-HH.MM.SS'."

**Issue:** The @GMT token is exactly 24 characters per the spec. The production function `ksmbd_vss_is_gmt_token()` in `/home/ezechiel203/ksmbd/src/fs/ksmbd_vss.c` line 162 checks `namlen != KSMBD_VSS_GMT_TOKEN_LEN - 1` where `KSMBD_VSS_GMT_TOKEN_LEN = 32`, so it requires `namlen == 31`. A valid 24-character @GMT token will always be rejected. The test correctly documents this production behavior, but the production code violates the spec. The test is classified as QUESTIONABLE because it tests against buggy behavior rather than spec-compliant behavior. The test comment is accurate about what the code does, but the underlying behavior it validates is spec-non-compliant.

#### Q-2: `ksmbd_vss_is_gmt_token` Length Mismatch in Production GMT Passthrough

**File:** `/home/ezechiel203/ksmbd/test/ksmbd_test_vss.c`, lines 410-419

**Test:** `test_real_dirname_to_gmt_snapper`, `test_real_dirname_to_gmt_simple`, `test_real_dirname_to_gmt_date_only`

**Issue:** These tests correctly pass by using non-@GMT formats (snapper, simple, date-only). However, there is no test for `ksmbd_vss_dirname_to_gmt()` with a standard 24-character @GMT token. Such a test would fail because `ksmbd_vss_is_gmt_token()` requires `namlen == 31`, and the fallback `sscanf` patterns do not match @GMT format. The test suite has a coverage gap here -- the @GMT passthrough path is untested for the production function precisely because it's broken. This is QUESTIONABLE because the existing tests are correct for what they test, but they obscure a spec compliance gap by avoiding the broken path.

#### Q-3: `CREATE_OPTIONS_MASK = 0x00FFFFFF` -- Implementation-Specific

**File:** `/home/ezechiel203/ksmbd/test/ksmbd_test_vfs.c`, lines 289-293

**Test code:**
```c
static void test_create_options_mask(struct kunit *test)
{
    KUNIT_EXPECT_EQ(test, CREATE_OPTIONS_MASK, cpu_to_le32(0x00FFFFFF));
}
```

**Issue:** MS-SMB2 section 2.2.13 does not define a `CREATE_OPTIONS_MASK` value. The highest defined CreateOptions bit is `FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000`. The mask `0x00FFFFFF` covers bits 0-23, which includes all defined values but also includes undefined bits in the range (e.g., 0x00040000, 0x00080000, etc.). This is an implementation choice, not something the spec mandates. The test is not wrong per se, but the mask value is implementation-specific and cannot be verified against the spec.

---

### Detailed Correct Test Breakdown

#### ksmbd_test_vfs.c (82 tests)

- **Stream name tests** (8 tests): Test internal xattr naming for NTFS alternate data streams. These test ksmbd-internal implementation (XATTR_NAME_STREAM prefix, :$DATA/:$INDEX_ALLOCATION suffixes). No spec contradiction -- streams are an implementation detail of how ksmbd maps NTFS ADS to Linux xattrs.

- **fadvise mapping tests** (3 correct, 1 WRONG): `FILE_SEQUENTIAL_ONLY -> POSIX_FADV_SEQUENTIAL`, `FILE_RANDOM_ACCESS -> POSIX_FADV_RANDOM`, `no flags -> POSIX_FADV_NORMAL` all match spec. The combined-flags test is WRONG (see W-1).

- **Path traversal tests** (18 tests): These test a replicated path safety checker for preventing directory traversal attacks. These are internal security hardening tests, not protocol-level tests. All expectations are reasonable from a security standpoint.

- **Allocation size helper tests** (6 tests): Test the `ksmbd_alloc_size()` helper which computes allocation sizes from stat blocks or cached values. Implementation-internal, no direct spec mapping.

- **has_file_id tests** (4 tests): Test the `KSMBD_NO_FID` sentinel check. `KSMBD_NO_FID = INT_MAX` is an internal implementation detail for the ksmbd file handle table, distinct from `SMB2_NO_FID = 0xFFFFFFFFFFFFFFFF` which is the wire protocol value. Both are correctly tested.

- **ksmbd_stream_fd tests** (3 tests): Test stream-vs-normal file detection via NULL name check. Implementation-internal.

- **CreateOptions flag constant tests** (10 tests, 1 QUESTIONABLE): All individual flag values match MS-SMB2 section 2.2.13 exactly:
  - `FILE_DIRECTORY_FILE = 0x00000001` (spec line 4814)
  - `FILE_WRITE_THROUGH = 0x00000002` (spec line 4838)
  - `FILE_SEQUENTIAL_ONLY = 0x00000004` (spec line 4842)
  - `FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008` (spec line 4848)
  - `FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020` (spec line 4855)
  - `FILE_NON_DIRECTORY_FILE = 0x00000040` (spec line 4858)
  - `FILE_RANDOM_ACCESS = 0x00000800` (spec line 4875)
  - `FILE_DELETE_ON_CLOSE = 0x00001000` (spec line 4883)
  - `FILE_OPEN_REPARSE_POINT = 0x00200000` (spec line 4924)
  - `CREATE_OPTIONS_MASK = 0x00FFFFFF` (QUESTIONABLE, see Q-3)

- **Lock range validation tests** (11 tests): These test overflow detection for byte-range lock parameters. The validation logic is implementation-specific (using `loff_t`/`LLONG_MAX` kernel constraints). The spec (MS-SMB2 section 2.2.26) defines Offset and Length as 64-bit values; the kernel must map these to `loff_t` safely. All test expectations are reasonable.

- **ksmbd_is_dot_dotdot tests** (10 tests): Test dot/dotdot entry identification for directory enumeration. These are implementation helpers for SMB2 QUERY_DIRECTORY, not directly spec-constrained.

- **smb_check_attrs tests** (7 tests, conditional on CONFIG_SMB_INSECURE_SERVER): Test POSIX attribute sanitization for SMB1 setattr. These implement Linux VFS conventions (ATTR_KILL_SUID/SGID on chown), not SMB protocol rules.

#### ksmbd_test_vfs_cache.c (66 tests)

All 66 tests are CORRECT. They test internal data structure management:

- **Pending delete state** (4 tests): Test `S_DEL_PENDING` flag manipulation. Implementation-internal.
- **POSIX flag** (1 test): Test `S_POSIX` flag. Implementation-internal.
- **Lock sequence tracking** (7 tests): Test the `lock_seq[65]` array. The array size (65 entries, indices 0-64) correctly matches the spec requirement (MS-SMB2 section 3.3.1.10, line 18062: "An array of 64 entries... Each entry MUST be assigned an index from the range of 1 to 64"). The 0xFF sentinel initialization matches the spec's "Set Valid to FALSE" (line 22105).
- **File state transitions** (2 tests): Test FP_NEW/FP_INITED/FP_CLOSED state machine. Implementation-internal.
- **Delete-on-close** (2 tests): Test `is_delete_on_close` flag. Implementation-internal.
- **Allocation size** (2 tests): Test cached-vs-stat allocation size computation. Implementation-internal.
- **Durable handle fields** (2 tests): Test durable/resilient/persistent handle tracking fields. The `durable_timeout` and `resilient_timeout` fields correspond to MS-SMB2 section 3.3.1.10 Open.DurableOpenTimeout and Open.ResilientOpenTimeout.
- **Channel sequence tracking** (2 tests): Test `channel_sequence` field. Corresponds to MS-SMB2 section 3.3.1.10 Open.ChannelSequence (line 18078): "A 16-bit identifier indicating the client's Channel change." The zero-initialization and u16 type match spec.
- **App instance fields** (2 tests): Test app instance ID/version tracking. Corresponds to MS-SMB2 section 3.3.1.10 Open.AppInstanceId.
- **FID constants** (3 tests): `SMB2_NO_FID = 0xFFFFFFFFFFFFFFFF` matches spec (MS-SMB2 uses `{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}` for FileId in multiple places). `KSMBD_NO_FID = INT_MAX` and `KSMBD_START_FID = 0` are implementation-internal.
- **Remaining tests** (37 tests): Cover dot_dotdot tracking, inode refcounting, oplock/stream counts, file state constants, pending-delete clear-if-only, inode flags, fd_limit helpers, inode_hash, __sanity_check, __open_id_set, ksmbd_fp_get, tree_conn_fd_check, fd_limit_close. All are implementation-internal helpers with no direct spec constraints.

#### ksmbd_test_acl.c (89 tests)

All 89 tests are CORRECT. ACL/SID operations are defined in MS-DTYP (not MS-SMB2), and the tests correctly implement:

- **compare_sids** (9 tests): SID comparison is a byte-level operation on the SID structure (revision, num_subauth, authority, sub_auth[]). All expectations match MS-DTYP SID structure definition.
- **smb_inherit_flags** (3 tests): ACE inheritance rules follow MS-DTYP ACE inheritance semantics (OBJECT_INHERIT_ACE, CONTAINER_INHERIT_ACE, NO_PROPAGATE_INHERIT_ACE).
- **id_to_sid** (10 tests): Maps Unix UIDs/GIDs to SIDs. Uses well-known SID prefixes: S-1-22-1 (Unix users), S-1-22-2 (Unix groups), S-1-3-0 (Creator Owner), S-1-3-1 (Creator Group), S-1-5-88-{1,2,3} (NFS uid/gid/mode). These are Samba/CIFS conventions, not MS-SMB2.
- **smb_copy_sid** (5 tests): SID copy including boundary clamping at SID_MAX_SUB_AUTHORITIES.
- **access_flags_to_mode** (10 tests): Maps Windows ACE access flags (GENERIC_READ/WRITE/EXECUTE/ALL) to Unix mode bits. Implementation-specific mapping, not defined in MS-SMB2.
- **mode_to_access_flags** (6 tests): Reverse mapping from Unix mode to Windows access flags.
- **fill_ace_for_sid / smb_set_ace** (7 tests): ACE construction with correct size calculation (header: type+flags+size+access = 8 bytes, SID: revision+num_subauth+authority = 8 bytes, sub_auth: 4*n bytes).
- **parse_sid** (4 tests): SID buffer validation with boundary checks.
- **Domain-aware SID mapping** (18 tests): Domain prefix extraction, hash computation, domain matching for Unix/NFS SIDs. Implementation-specific.
- **ksmbd_ace_size** (4 tests): ACE size calculation: 8 (ACE header) + 8 (SID base) + 4*n (sub_auth). Calculations verified: 1 subauth=20, 0 subauth=16, 15 subauth=76, 2 subauth=24. All correct.

#### ksmbd_test_vss.c (32 tests)

30 tests are CORRECT, 2 are QUESTIONABLE (see Q-1 and Q-2).

- **Replicated GMT token validation** (6 tests): The replicated `test_is_gmt_token()` correctly validates 24-character @GMT tokens matching the spec format.
- **Timestamp parsing** (3 tests): Correctly converts @GMT tokens to Unix timestamps via `mktime64`.
- **dirname_to_gmt conversion** (9 tests): Tests snapper format, simple format, date-only format, GMT passthrough, leap year, invalid inputs. All replicated logic tests are correct.
- **Production function tests** (14 tests): 12 tests are CORRECT (they test non-@GMT formats and error paths). 2 are QUESTIONABLE (Q-1: `test_real_is_gmt_token_24chars` tests broken production behavior; Q-2: missing @GMT passthrough test for production function).

---

### Final Summary

| Metric | Value |
|--------|-------|
| Total tests audited | 269 |
| CORRECT | 265 |
| WRONG | 1 |
| QUESTIONABLE | 3 |

The single WRONG finding (W-1) is a direct spec violation in both the test and the production code: MS-SMB2 section 2.2.13 mandates that FILE_SEQUENTIAL_ONLY is ignored when both FILE_SEQUENTIAL_ONLY and FILE_RANDOM_ACCESS are set, but both the production code and the test give priority to FILE_SEQUENTIAL_ONLY. The three QUESTIONABLE findings involve an implementation-specific mask constant (Q-3) and tests that correctly document production behavior that itself violates the spec regarding @GMT token length (Q-1, Q-2).