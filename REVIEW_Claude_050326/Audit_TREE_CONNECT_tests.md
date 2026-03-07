# Audit Tree Connect Tests

Agent ID: a393e843f46ba7325

Now I see a discrepancy. The spec at line 3983 says "MUST be less than or equal to 80 characters" but the code comment at line 187 says "MUST be less than 80 characters" and then rejects at `>= 80` (line 190). The production code is WRONG compared to the spec -- it should allow exactly 80 characters. But this audit is about the test files vs spec, not the production code.

Now I have all the information I need. Let me compile the comprehensive audit report.

---

# KUNIT Test Audit Report: Tree Connect / DFS Tests vs. MS-SMB2 Specification

## File 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_tree.c`

### Section 1: DFS Root Share Extraction (11 tests)

**1. `test_dfs_root_basic`** -- Tests `ksmbd_extract_dfs_root_sharename()` with `\\server\share`.
- **Verdict: CORRECT.** This tests internal helper logic for parsing UNC paths. The expected result "share" is correct for the second path component extraction. Not directly a protocol wire-format assertion.

**2. `test_dfs_root_with_subfolder`** -- Tests `\\domain\dfsroot\folder` extracts "dfsroot".
- **Verdict: CORRECT.** The DFS root is the first share-level component in the UNC path, not deeper subfolders. Consistent with MS-DFSC path semantics.

**3. `test_dfs_root_with_deep_path`** -- Tests `\\dc01\root\sub1\sub2\file` extracts "root".
- **Verdict: CORRECT.** Same rationale as above.

**4. `test_dfs_root_casefold`** -- Tests `\\SERVER\SHARE` yields "share" (lowercased).
- **Verdict: CORRECT.** Share names are case-insensitive in SMB; casefolding to lowercase is a valid implementation approach.

**5. `test_dfs_root_forward_slashes`** -- Tests `//server/myshare/sub` extracts "myshare".
- **Verdict: CORRECT.** The function handles both `/` and `\` separators, which is a reasonable implementation choice for internal path handling.

**6. `test_dfs_root_mixed_slashes`** -- Tests `\\server/data\sub` extracts "data".
- **Verdict: CORRECT.**

**7. `test_dfs_root_no_share`** -- Tests `\\server` returns an error.
- **Verdict: CORRECT.** A UNC path with only a server component has no share to extract.

**8. `test_dfs_root_no_share_trailing_slash`** -- Tests `\\server\` returns an error.
- **Verdict: CORRECT.** Trailing separator with no share name after it.

**9. `test_dfs_root_ip_address`** -- Tests `\\192.168.1.100\data` extracts "data".
- **Verdict: CORRECT.** MS-SMB2 section 2.2.9 explicitly allows "textual IPv4 or IPv6 address" as the server component.

**10. `test_dfs_root_ipc_dollar`** -- Tests `\\server\IPC$` extracts "ipc$" (lowercased).
- **Verdict: CORRECT.** IPC$ is a valid share name; casefolding is acceptable.

**11. `test_dfs_root_multiple_leading_slashes`** -- Tests `\\\\server\share` with extra leading backslashes.
- **Verdict: QUESTIONABLE.** The test expects "share" from `\\\\\\\\server\\share` (4 pairs of backslashes before "server"). Per MS-SMB2 section 2.2.9, the path is in the form `\\server\share`. Extra leading backslashes are not part of the spec format. The test verifies the function's robustness to malformed input, which is fine from a defense-in-depth perspective, but the expected result depends entirely on the implementation's behavior when given non-conforming input. The test documents rather than validates protocol behavior.

### Section 2: Share Name Extraction (6 tests)

**12. `test_extract_sharename_basic`** -- Tests `\\server\testshare` extracts "testshare".
- **Verdict: CORRECT.**

**13. `test_extract_sharename_ipc`** -- Tests `\\server\IPC$` extracts "ipc$" (lowercased).
- **Verdict: CORRECT.**

**14. `test_extract_sharename_ip_address`** -- Tests `\\192.168.1.1\data` extracts "data".
- **Verdict: CORRECT.**

**15. `test_extract_sharename_with_subfolder`** -- Tests `\\server\share\sub` extracts "sub" (last component).
- **Verdict: QUESTIONABLE.** The test comment states `ksmbd_extract_sharename` uses `strrchr('\\')` and extracts the last component "sub". However, for TREE_CONNECT, the share name is the component immediately after the server name. Extracting "sub" rather than "share" from `\\server\share\sub` is not the share name per MS-SMB2 section 2.2.9. The test correctly documents the function's behavior (last component via `strrchr`), but this function's semantics do not match what MS-SMB2 would consider the "share name" in a TREE_CONNECT context. Whether this is a bug in the helper function or just a different use case depends on calling context.

**16. `test_extract_sharename_casefold`** -- Tests casefolding.
- **Verdict: CORRECT.**

**17. `test_extract_sharename_no_separator`** -- Tests "justashare" (no backslash) returns "justashare".
- **Verdict: QUESTIONABLE.** A path without `\\` prefix is not a valid UNC path per MS-SMB2 section 2.2.9. The test documents the function's behavior on invalid input rather than validating protocol correctness.

### Section 3: Share Name Length Validation (4 tests)

**18. `test_share_name_len_valid`** -- 79 chars is valid (< 80).
- **Verdict: WRONG.** The test defines `MAX_SHARE_NAME_LEN` as 80 and tests that 79 chars is `< 80`. Per MS-SMB2 section 2.2.9 (line 3983): "The share component of the path MUST be less than or equal to 80 characters in length." This means 80 characters is VALID. The test's threshold is correct that 79 < 80, but the overall validation framework using `>= 80` as the rejection threshold (see test 19) is off by one: 80-character share names should be accepted, not rejected. **Spec ref: MS-SMB2 section 2.2.9, PathOffset description. Fix: Change `MAX_SHARE_NAME_LEN` to 81 so that `>= 81` rejects correctly, or change the comparison to `> 80`.**

**19. `test_share_name_len_at_limit`** -- 80 chars is rejected (`>= 80`).
- **Verdict: WRONG.** As noted above, per MS-SMB2 section 2.2.9, 80 characters MUST be allowed ("less than or equal to 80"). The test rejects at 80, which contradicts the spec. **Spec ref: MS-SMB2 section 2.2.9. Fix: 80 characters should pass; rejection should be at > 80 (i.e., 81+ characters).**

**20. `test_share_name_len_way_too_long`** -- 199 chars rejected.
- **Verdict: CORRECT.** 199 is clearly above 80.

**21. `test_share_name_empty`** -- Empty string length 0 < 80.
- **Verdict: CORRECT** as a length check, though the spec does not explicitly mandate a minimum share name length in section 2.2.9.

### Section 4: IPC$ Share Detection (1 test)

**22. `test_is_ipc_share`** -- Tests `strcasecmp("IPC$", "ipc$") == 0`.
- **Verdict: CORRECT.** IPC$ is a well-known pipe share. Case-insensitive comparison is correct for SMB.

### Section 5: Tree Connect Flags (4 tests)

**23. `test_tree_connect_flags_extension_present`** -- Tests `TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0004`.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.9 (line 3970): `SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT 0x0004`.

**24. `test_tree_connect_flags_cluster_reconnect`** -- Tests `0x0001`.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.9 (line 3960): `SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT 0x0001`.

**25. `test_tree_connect_flags_redirect_to_owner`** -- Tests `0x0002`.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.9 (line 3965): `SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER 0x0002`.

**26. `test_tree_connect_flags_combined`** -- Tests OR of CLUSTER_RECONNECT | EXTENSION_PRESENT = 0x0005 with correct bit checks.
- **Verdict: CORRECT.**

### Section 6: Share Type Constants (3 tests)

**27. `test_share_type_disk`** -- Tests `SMB2_SHARE_TYPE_DISK == 0x01`.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.10 (line 4424): `SMB2_SHARE_TYPE_DISK 0x01`.

**28. `test_share_type_pipe`** -- Tests `SMB2_SHARE_TYPE_PIPE == 0x02`.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.10 (line 4427): `SMB2_SHARE_TYPE_PIPE 0x02`.

**29. `test_share_type_print`** -- Tests `SMB2_SHARE_TYPE_PRINT == 0x03`.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.10 (line 4430): `SMB2_SHARE_TYPE_PRINT 0x03`.

### Section 7: Tree Disconnect Validation (3 tests)

**30. `test_tree_disconnect_valid_tid`** -- Tests `tree_id = 1` is non-zero.
- **Verdict: CORRECT** but trivial. MS-SMB2 section 3.3.5.7 reserves -1 (0xFFFFFFFF) as invalid TreeId; any non-zero, non-reserved value is valid.

**31. `test_tree_disconnect_invalid_tid`** -- Tests `tree_id = 0` equals 0.
- **Verdict: QUESTIONABLE.** The test just asserts `tree_id == 0`. Per MS-SMB2, the spec reserves 0xFFFFFFFF as invalid TreeId, not 0. A TreeId of 0 in the header typically means "no tree connect" but is not explicitly stated as "invalid" the same way -1 is. The test is more of a tautology (`0 == 0`) than a spec validation.

**32. `test_tree_state_transitions`** -- Tests `TREE_NEW != TREE_CONNECTED != TREE_DISCONNECTED`.
- **Verdict: CORRECT.** These are internal implementation states. The test simply verifies they are distinct values. Not a direct protocol assertion but validates implementation invariants.

### Section 8: Session Logoff Validation (2 tests)

**33. `test_session_logoff_valid_session`** -- Tests `session_id = 0x1234` is non-zero.
- **Verdict: CORRECT** but trivial. Session IDs must be non-zero for valid sessions.

**34. `test_session_logoff_notification_count`** -- Tests 3 channels - 1 = 2 notifications.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.44 / section 4.11 (line 29844): Session closed notifications are sent to all other channels of the same session (excluding the current connection). The arithmetic `total_channels - 1` is consistent with the spec.

### Section 9: DFS and Tree Connect Response (3 tests)

**35. `test_tree_connect_dfs_capabilities`** -- Tests `SMB2_SHARE_CAP_DFS != 0`.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.10 (line 4532): `SMB2_SHARE_CAP_DFS = 0x00000008`. Non-zero is confirmed.

**36. `test_tree_connect_continuous_availability`** -- Tests `SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY != 0`.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.10 (line 4535): `SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x00000010`. Non-zero confirmed.

**37. `test_tree_connect_rsp_structure_size`** -- Tests response StructureSize = 16.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.10 (line 4416): "The server MUST set this field to 16, indicating the size of the response structure, not including the header."

---

## File 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_tree_connect.c`

This file tests tree connect management internals (refcounting, xarray lookup, disconnect, session logoff) using replicated data structures rather than protocol wire formats.

**38. `test_tree_connect_put_frees_on_last_ref`** -- Tests refcount drop to 0 sets `freed = true`.
- **Verdict: CORRECT.** Internal lifecycle management; not directly a protocol assertion.

**39. `test_tree_connect_put_decrements_ref`** -- Tests refcount goes from 2 to 1 without freeing.
- **Verdict: CORRECT.** Standard refcounting behavior.

**40. `test_tree_conn_lookup_returns_null_for_nonexistent`** -- Lookup of non-existent ID returns NULL.
- **Verdict: CORRECT.** Consistent with MS-SMB2 section 3.3.5.7 which requires looking up the tree connect and failing if not found.

**41. `test_tree_conn_lookup_rejects_disconnected`** -- Lookup of disconnected tree returns NULL.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.2.11, operations on disconnected tree connects should fail. The test's approach of returning NULL for disconnected trees is appropriate.

**42. `test_tree_conn_session_logoff_null_session`** -- NULL session returns -EINVAL.
- **Verdict: CORRECT.** Defensive coding check.

**43. `test_tree_conn_disconnect_removes_from_xarray`** -- Disconnect removes entry from lookup table.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.8, tree disconnect removes the tree connect from Session.TreeConnectTable.

**44. `test_tree_conn_session_logoff_marks_disconnected`** -- Session logoff marks all tree connects as disconnected.
- **Verdict: CORRECT.** Per MS-SMB2 section 3.3.5.6 (Session Logoff), the server must close all tree connects associated with the session.

---

## File 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_error_tree.c`

**45. `test_tree_share_name_valid`** -- "TestShare" (9 chars) < 80.
- **Verdict: CORRECT.**

**46. `test_tree_share_name_max_len`** -- 79 chars < 80.
- **Verdict: WRONG (same off-by-one as file 1).** Per MS-SMB2 section 2.2.9: share name MUST be "less than or equal to 80 characters." Using `KSMBD_MAX_SHARE_NAME_LEN = 80` with a `< 80` comparison means 80-character names are rejected, contradicting the spec. **Fix: Use `<= 80` or set the limit constant to 81.**

**47. `test_tree_share_name_too_long`** -- 80 chars >= 80 triggers rejection.
- **Verdict: WRONG.** Same off-by-one. Per the spec, 80 characters is valid. Rejection should start at 81. **Spec ref: MS-SMB2 section 2.2.9.**

**48. `test_tree_share_name_empty`** -- Empty string length == 0.
- **Verdict: CORRECT** as a length measurement.

**49. `test_tree_unc_path_valid`** -- `\\server\share` starts with `\\` and share component is "share".
- **Verdict: CORRECT.** Consistent with MS-SMB2 section 2.2.9 path format `\\server\share`.

**50. `test_tree_unc_path_no_share`** -- `\\server` has no backslash after server name.
- **Verdict: CORRECT.** A UNC path without a share component is invalid per MS-SMB2 section 2.2.9.

**51. `test_tree_unc_path_not_unc`** -- `/mnt/share` does not start with `\`.
- **Verdict: CORRECT.** MS-SMB2 section 2.2.9 requires `\\server\share` format with Unicode path.

**52. `test_tree_share_name_with_special_chars`** -- `Share$Admin` with `$` is valid.
- **Verdict: CORRECT.** `$` is commonly used in admin shares (e.g., `C$`, `IPC$`, `ADMIN$`). The character is not listed as invalid in [MS-FSCC] section 2.1.6.

---

## File 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_dfs.c`

These tests focus on DFS referral logic, which is primarily defined in MS-DFSC (not MS-SMB2). The DFS referral request/response is carried via FSCTL_DFS_GET_REFERRALS in SMB2 IOCTL. I will audit against MS-DFSC structures as referenced by MS-SMB2.

### Referral Version Selection (5 tests)

**53. `test_dfs_select_referral_version_v4`** -- max_level >= 4 returns V4.
- **Verdict: CORRECT.** V4 is the highest supported version; clamping to V4 for max_level >= 4 is correct.

**54. `test_dfs_select_referral_version_v3`** -- max_level == 3 returns V3.
- **Verdict: CORRECT.**

**55. `test_dfs_select_referral_version_v2`** -- max_level == 2 returns V2.
- **Verdict: CORRECT.**

**56. `test_dfs_select_referral_version_v1_returns_zero`** -- max_level == 1 returns 0.
- **Verdict: QUESTIONABLE.** MS-DFSC defines referral versions 1-4. Version 1 is a valid (though very old) referral version. Returning 0 (unsupported) for V1 requests is an implementation choice by ksmbd to not support V1 referrals. The test correctly documents this implementation decision, but it is worth noting that V1 is a valid referral version per MS-DFSC.

**57. `test_dfs_select_referral_version_zero_returns_zero`** -- max_level == 0 returns 0.
- **Verdict: CORRECT.** 0 is not a valid referral version.

### Referral Fixed Size (3 tests)

**58. `test_dfs_referral_fixed_size_v2`** -- V2 size == sizeof(test_dfs_referral_v2).
- **Verdict: CORRECT.** The replicated V2 structure has: version_number(2) + size(2) + server_type(2) + referral_entry_flags(2) + proximity(4) + time_to_live(4) + dfs_path_offset(2) + dfs_alt_path_offset(2) + node_offset(2) = 22 bytes. This matches MS-DFSC section 2.2.5.3 DFS_REFERRAL_V2.

**59. `test_dfs_referral_fixed_size_v3`** -- V3 size == sizeof(test_dfs_referral_v3).
- **Verdict: QUESTIONABLE.** The replicated V3 structure has: version_number(2) + size(2) + server_type(2) + referral_entry_flags(2) + time_to_live(4) + dfs_path_offset(2) + dfs_alt_path_offset(2) + node_offset(2) = 18 bytes. Per MS-DFSC section 2.2.5.4, the V3 referral entry fixed part includes a ServiceSiteGuid field (16 bytes) at the end, making the total 34 bytes. However, MS-DFSC also states that the ServiceSiteGuid field is only present if the NameListReferral bit is set in ReferralEntryFlags (which uses a different union layout). The ksmbd implementation appears to only consider the non-NameList variant (without GUID), giving 18 bytes. **This is an implementation-specific choice; the test matches the ksmbd implementation but does not account for the full V3 structure when NameListReferral is set.**

**60. `test_dfs_referral_fixed_size_v4`** -- V4 > V3, with 16-byte GUID difference.
- **Verdict: QUESTIONABLE.** The test's V4 structure adds a 16-byte `service_site_guid` to V3, giving 34 bytes. Per MS-DFSC, V4 referral entries are identical in format to V3 entries; the difference is that V4 allows target set boundaries (the T flag in ReferralEntryFlags). The V4 structure in the test with an explicit GUID field diverges from the spec, where V3 and V4 have the same layout. **The assertion `v4 - v3 == 16` may be based on incorrect structure definitions rather than the actual spec.**

### UTF-16 Name Length (4 tests)

**61. `test_dfs_utf16_name_len_normal`** -- "AB" in UTF-16LE is 4 bytes.
- **Verdict: CORRECT.**

**62. `test_dfs_utf16_name_len_empty`** -- Just NUL terminator is 0 bytes.
- **Verdict: CORRECT.**

**63. `test_dfs_utf16_name_len_no_null_terminator`** -- Missing NUL returns -EINVAL.
- **Verdict: CORRECT.**

**64. `test_dfs_utf16_name_len_max_len_too_small`** -- max_len=1 returns -EINVAL.
- **Verdict: CORRECT.** UTF-16 requires at least 2 bytes for any character.

### Path Component Extraction (6 tests)

**65-70. `test_dfs_next_component_*` tests** -- All test path component parsing with various separators and edge cases.
- **Verdict: CORRECT.** These test internal path parsing logic. The behavior is consistent with UNC path semantics.

### Default/Fallback (1 test)

**71. `test_dfs_referral_default_falls_to_v2`** -- Unknown versions (0, 99) fall through to V2 size.
- **Verdict: CORRECT** as an implementation design decision (safe fallback).

### Network Address Building (5 tests)

**72-76. `test_dfs_build_network_address_*` tests** -- Tests building `\\server\share` strings.
- **Verdict: CORRECT.** The UNC path format `\\server\share` matches MS-SMB2 section 2.2.9.

### UTF-16 Edge Cases (2 tests)

**77. `test_dfs_utf16_name_len_single_char`** -- "A" is 2 bytes.
- **Verdict: CORRECT.**

**78. `test_dfs_utf16_name_len_max_len_zero`** -- max_len=0 returns -EINVAL.
- **Verdict: CORRECT.**

### Referral Structure Sizes (2 tests)

**79. `test_dfs_referral_v3_v4_relationship`** -- V4 - V3 == 16.
- **Verdict: QUESTIONABLE (same issue as test 60).** The test's V4 structure definition with an explicit GUID field that V3 lacks is non-standard. Per MS-DFSC, V3 and V4 have identical wire format.

**80. `test_dfs_referral_v2_has_proximity`** -- V2 size > 0.
- **Verdict: CORRECT** (trivially true).

### Real Production Function Tests (13 tests)

**81-93. `test_real_dfs_*` tests** -- These call actual exported functions from ksmbd_dfs.c with the same inputs as the replicated tests above.
- **Verdict: Same as their replicated counterparts.** The tests that call real functions with the same inputs and expected outputs have the same correctness status as the replicated versions above.

---

## File 5: `/home/ezechiel203/ksmbd/test/ksmbd_test_dfs_behavior.c`

**94. `test_dfs_request_structure_layout`** -- `sizeof(req_get_dfs_referral) == 2`, offset of `request_file_name` is 2.
- **Verdict: CORRECT.** Per MS-DFSC section 2.2.2, REQ_GET_DFS_REFERRAL has MaxReferralLevel (2 bytes) followed by variable-length RequestFileName. The fixed part is 2 bytes.

**95. `test_dfs_response_structure_layout`** -- `sizeof(resp_get_dfs_referral) == 8`, offsets: path_consumed=0, number_of_referrals=2, referral_header_flags=4.
- **Verdict: CORRECT.** Per MS-DFSC section 2.2.4, RESP_GET_DFS_REFERRAL has PathConsumed(2) + NumberOfReferrals(2) + ReferralHeaderFlags(4) = 8 bytes.

**96. `test_referral_entry_flags`** -- DFSREF_REFERRAL_SERVER=0x1, DFSREF_STORAGE_SERVER=0x2, DFSREF_TARGET_FAILBACK=0x4.
- **Verdict: QUESTIONABLE.** The flag constants for `DFSREF_REFERRAL_SERVER` (0x1), `DFSREF_STORAGE_SERVER` (0x2) are defined in MS-DFSC section 2.2.4 for the ReferralHeaderFlags field. However, `DFSREF_TARGET_FAILBACK` (0x4) is not a standard flag in the ReferralHeaderFlags -- it is a flag in the individual referral entry's ReferralEntryFlags field (MS-DFSC section 2.2.5.4, T flag = 0x0004 for TargetFailback in V3/V4). The test mixes header-level and entry-level flags as if they were all in the same field. The combined test `REFERRAL_SERVER | STORAGE_SERVER | TARGET_FAILBACK == 0x7` is misleading because these flags belong to different fields.

**97. `test_path_normalization`** -- Converts `/` to `\` in paths.
- **Verdict: CORRECT.** Internal normalization; paths on the wire are `\`-separated in SMB.

**98. `test_long_path_component_rejected`** -- Components > 255 chars rejected with ENAMETOOLONG.
- **Verdict: CORRECT.** This is consistent with filesystem path component limits (NAME_MAX = 255 in Linux). MS-SMB2 section 2.2.9 also states the server component must be < 256 characters.

**99. `test_empty_path_in_referral_request`** -- Empty/too-small buffers handled correctly.
- **Verdict: CORRECT.**

**100. `test_root_vs_link_referral`** -- DFS_SERVER_ROOT=0x0001, DFS_SERVER_LINK=0x0000.
- **Verdict: CORRECT.** Per MS-DFSC section 2.2.5, ServerType field: 0x0001 = root targets, 0x0000 = non-root (link) targets.

**101. `test_referral_entry_version_fields`** -- V2=22 bytes, V3=18 bytes, V4=34 bytes.
- **Verdict: QUESTIONABLE.** V2 at 22 bytes matches MS-DFSC section 2.2.5.3. V3 at 18 bytes represents only the name-based (non-NameList) variant. V4 at 34 bytes with an explicit 16-byte GUID field is **non-standard** -- per MS-DFSC, V4 uses the same structure as V3 (the difference is semantic: the T flag for target set boundaries). The V4 structure in this test file artificially adds a `service_site_guid[16]` field. **The test's V4 structure does not match MS-DFSC section 2.2.5.6.**

**102. `test_dfs_header_flag_referral_svr`** -- Sets DFSREF_REFERRAL_SERVER in response header.
- **Verdict: CORRECT.**

**103. `test_dfs_header_flag_storage_svr`** -- Sets REFERRAL_SERVER | STORAGE_SERVER in response header.
- **Verdict: CORRECT.** Per MS-DFSC section 2.2.4, these can be combined in ReferralHeaderFlags.

**104. `test_max_referral_level_validation`** -- Version clamping logic.
- **Verdict: CORRECT** (same analysis as tests 53-57).

**105. `test_referral_response_zero_entries`** -- Response with 0 referrals.
- **Verdict: CORRECT.** A response with `NumberOfReferrals = 0` is valid (e.g., when no referral targets exist).

**106. `test_referral_response_multiple_entries`** -- Response with 3 V3 referral entries; verifies layout.
- **Verdict: CORRECT.** The test constructs a response header followed by 3 contiguous V3 referral entries and verifies each entry's version, TTL, and server_type. The layout is consistent with MS-DFSC section 2.2.4 (header followed by referral entries).

**107. `test_path_consumed_nested_shares`** -- PathConsumed = `strlen("\\\\server\\share") * 2 = 28` bytes.
- **Verdict: CORRECT.** PathConsumed is in bytes of UTF-16LE. `\\server\share` is 14 characters, each 2 bytes in UTF-16LE = 28 bytes. Per MS-DFSC section 2.2.4, PathConsumed is the number of bytes consumed from the request path.

**108. `test_request_filename_utf16_encoding`** -- `\\A` in UTF-16LE is 6 bytes (3 code units).
- **Verdict: CORRECT.** `\` = 0x005C, `\` = 0x005C, `A` = 0x0041, each 2 bytes = 6 bytes total.

---

## Summary Table

| # | Test Name | File | Verdict | Issue |
|---|-----------|------|---------|-------|
| 1-10 | test_dfs_root_* | smb2_tree | CORRECT | Internal helper tests |
| 11 | test_dfs_root_multiple_leading_slashes | smb2_tree | QUESTIONABLE | Non-standard input |
| 12-16 | test_extract_sharename_* | smb2_tree | CORRECT | |
| 15 | test_extract_sharename_with_subfolder | smb2_tree | QUESTIONABLE | Extracts last component, not share name |
| 17 | test_extract_sharename_no_separator | smb2_tree | QUESTIONABLE | Invalid UNC path |
| 18 | test_share_name_len_valid | smb2_tree | WRONG | Off-by-one: 80 chars should be valid |
| 19 | test_share_name_len_at_limit | smb2_tree | WRONG | Off-by-one: 80 chars should be valid |
| 20-21 | test_share_name_len_* | smb2_tree | CORRECT | |
| 22 | test_is_ipc_share | smb2_tree | CORRECT | |
| 23-26 | test_tree_connect_flags_* | smb2_tree | CORRECT | Flag values match spec |
| 27-29 | test_share_type_* | smb2_tree | CORRECT | Values match MS-SMB2 section 2.2.10 |
| 30 | test_tree_disconnect_valid_tid | smb2_tree | CORRECT | Trivial |
| 31 | test_tree_disconnect_invalid_tid | smb2_tree | QUESTIONABLE | Spec reserves 0xFFFFFFFF, not 0 |
| 32 | test_tree_state_transitions | smb2_tree | CORRECT | Internal states |
| 33 | test_session_logoff_valid_session | smb2_tree | CORRECT | Trivial |
| 34 | test_session_logoff_notification_count | smb2_tree | CORRECT | Matches spec section 2.2.44 |
| 35-37 | test_tree_connect_dfs/ca/rsp | smb2_tree | CORRECT | |
| 38-44 | test_tree_connect/conn_* | tree_connect | CORRECT | Internal lifecycle |
| 45 | test_tree_share_name_valid | error_tree | CORRECT | |
| 46 | test_tree_share_name_max_len | error_tree | WRONG | Off-by-one (same as #18) |
| 47 | test_tree_share_name_too_long | error_tree | WRONG | Off-by-one (same as #19) |
| 48-52 | test_tree_* | error_tree | CORRECT | |
| 53-57 | test_dfs_select_referral_version_* | dfs | CORRECT | |
| 58 | test_dfs_referral_fixed_size_v2 | dfs | CORRECT | |
| 59 | test_dfs_referral_fixed_size_v3 | dfs | QUESTIONABLE | V3 fixed size may not account for NameList variant |
| 60 | test_dfs_referral_fixed_size_v4 | dfs | QUESTIONABLE | V4 structure adds non-standard GUID field |
| 61-78 | Various dfs helper tests | dfs | CORRECT | |
| 79 | test_dfs_referral_v3_v4_relationship | dfs | QUESTIONABLE | V4-V3=16 based on non-standard V4 struct |
| 94-95 | test_dfs_request/response_structure_layout | dfs_behavior | CORRECT | |
| 96 | test_referral_entry_flags | dfs_behavior | QUESTIONABLE | Mixes header and entry flags |
| 97-100 | test_path/root_vs_link_* | dfs_behavior | CORRECT | |
| 101 | test_referral_entry_version_fields | dfs_behavior | QUESTIONABLE | V4 struct is non-standard |
| 102-108 | Various dfs behavior tests | dfs_behavior | CORRECT | |

## Critical Findings

### WRONG (4 instances, 1 root cause)

**Off-by-one in share name length validation** -- Tests 18, 19 (in `ksmbd_test_smb2_tree.c`) and tests 46, 47 (in `ksmbd_test_error_tree.c`) all reject share names of exactly 80 characters. Per MS-SMB2 section 2.2.9: "The share component of the path MUST be less than or equal to 80 characters in length." This means 80 characters is valid. The test constant `MAX_SHARE_NAME_LEN = 80` combined with `>= 80` rejection rejects a valid length.

Note: The production code at `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_tree.c` line 190 has the same bug (`if (strlen(name) >= 80)`), and its comment at line 187 incorrectly says "less than 80 characters" instead of "less than or equal to 80 characters."

**Fix for all 4 test assertions and the production code:** Either change `MAX_SHARE_NAME_LEN` to 81 (so `>= 81` rejects at 81+), or change comparisons from `>= 80` to `> 80`.

### QUESTIONABLE (9 instances)

1. **test_dfs_root_multiple_leading_slashes** -- Tests non-conforming input; documents implementation rather than spec.
2. **test_extract_sharename_with_subfolder** -- `ksmbd_extract_sharename` extracts last component, not the share name per MS-SMB2 UNC path format.
3. **test_extract_sharename_no_separator** -- Tests behavior on invalid (non-UNC) input.
4. **test_tree_disconnect_invalid_tid** -- Uses TreeId=0 as "invalid"; spec reserves 0xFFFFFFFF.
5. **DFS referral V3 fixed size** -- Only accounts for non-NameList variant.
6. **DFS referral V4 structure** (3 instances: tests 60, 79, 101) -- Adds a 16-byte `service_site_guid` field to V4 that does not exist in the MS-DFSC V4 specification. Per MS-DFSC, V4 entries have the same wire format as V3 entries.
7. **test_referral_entry_flags** -- Mixes `DFSREF_TARGET_FAILBACK` (an entry-level flag) with header-level flags `DFSREF_REFERRAL_SERVER` and `DFSREF_STORAGE_SERVER`.