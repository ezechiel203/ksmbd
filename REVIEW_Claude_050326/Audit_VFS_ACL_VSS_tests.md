# Audit Vfs Acl Vss Tests

Agent ID: a0f8410ec96ce5e8f

Now I have all the information needed. Let me compile the comprehensive audit report.

---

# Comprehensive KUnit Test Audit Against MS-SMB2 Specification

## File 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_vfs.c`

### Stream Name Tests

| Test | Verdict | Details |
|------|---------|---------|
| `test_vfs_xattr_stream_name_formats_correctly` | **CORRECT** | Tests that DATA_STREAM produces a valid xattr name containing the stream name. MS-SMB2 does not define the xattr storage format; this is an implementation detail. |
| `test_vfs_xattr_stream_name_special_chars` | **CORRECT** | Verifies special characters in stream names are handled. |
| `test_vfs_xattr_stream_name_dir_stream` | **CORRECT** | DIR_STREAM using `:$INDEX_ALLOCATION` suffix is consistent with NTFS stream naming conventions per MS-FSCC. |
| `test_vfs_xattr_stream_name_empty` | **CORRECT** | Empty stream name producing `:$DATA` suffix is correct -- the default data stream is named `::$DATA`. |
| `test_vfs_xattr_stream_name_prefix` | **CORRECT** | Verifies XATTR_NAME_STREAM prefix presence. Implementation detail, correctly tested. |
| `test_vfs_xattr_stream_name_long_name` | **CORRECT** | Boundary test for long stream names. |
| `test_vfs_xattr_stream_name_data_suffix` | **CORRECT** | DATA_STREAM should have `:$DATA` suffix. |

### fadvise Mapping Tests

| Test | Verdict | Details |
|------|---------|---------|
| `test_vfs_set_fadvise_sequential` | **CORRECT** | FILE_SEQUENTIAL_ONLY (0x00000004 per MS-SMB2 section 2.2.13) maps to POSIX_FADV_SEQUENTIAL. Correct mapping. |
| `test_vfs_set_fadvise_random` | **CORRECT** | FILE_RANDOM_ACCESS (0x00000800 per MS-SMB2 section 2.2.13) maps to POSIX_FADV_RANDOM. Correct mapping. |
| `test_vfs_set_fadvise_none` | **CORRECT** | No flags maps to POSIX_FADV_NORMAL. |
| `test_vfs_set_fadvise_sequential_and_random` | **CORRECT** | Per MS-SMB2 section 2.2.13: "If both FILE_RANDOM_ACCESS and FILE_SEQUENTIAL_ONLY are set, then FILE_SEQUENTIAL_ONLY is ignored." However, the test asserts sequential takes priority. This is **QUESTIONABLE** -- the spec says sequential should be IGNORED when both are set, meaning random should win. But this tests a replicated local function, not the production code. The test is internally consistent with its own replicated logic (sequential checked first in if/else), but **differs from spec intent**. |

**Correction for `test_vfs_set_fadvise_sequential_and_random`:** Per MS-SMB2 section 2.2.13 line 4879-4881: "If both FILE_RANDOM_ACCESS and FILE_SEQUENTIAL_ONLY are set, then FILE_SEQUENTIAL_ONLY is ignored." The spec says when both are set, FILE_SEQUENTIAL_ONLY should be ignored and FILE_RANDOM_ACCESS should prevail. The test asserts the opposite. **WRONG** -- spec ref: MS-SMB2 section 2.2.13 CreateOptions. Fix: the replicated `test_fadvise_map()` should check FILE_RANDOM_ACCESS first, and the test should expect `POSIX_FADV_RANDOM` when both flags are set.

### Path Traversal Tests

| Test | Verdict | Details |
|------|---------|---------|
| `test_path_traversal_dotdot_in_middle` | **CORRECT** | Path traversal via ".." must be rejected (MS-SMB2 section 3.3.5.9 path validation). |
| `test_path_traversal_dotdot_at_start` | **CORRECT** | |
| `test_path_traversal_backslash_dotdot` | **CORRECT** | Handles backslash as path separator per SMB convention. |
| `test_path_traversal_absolute_rejected` | **CORRECT** | Absolute paths must be rejected. |
| `test_path_traversal_normal_path_ok` | **CORRECT** | |
| `test_path_traversal_double_slash_ok` | **CORRECT** | |
| `test_path_traversal_single_dot_ok` | **CORRECT** | |
| `test_path_traversal_null_byte` | **CORRECT** | Embedded NUL terminates the C string. |
| `test_path_traversal_very_long_path` | **CORRECT** | |
| `test_path_traversal_encoded_dotdot_safe` | **CORRECT** | URL-encoded ".." is not interpreted at the raw path level. |
| `test_path_traversal_dotdot_at_end` | **CORRECT** | |
| `test_path_traversal_empty_path_safe` | **CORRECT** | |
| `test_path_traversal_null_path_safe` | **CORRECT** | |
| `test_path_traversal_triple_dot` | **CORRECT** | "..." is not "..", safe. |
| `test_path_traversal_dot_space` | **CORRECT** | ". " is not "..", safe. |
| `test_path_traversal_mixed_separators` | **CORRECT** | |
| `test_path_traversal_only_dots` | **CORRECT** | |
| `test_path_traversal_trailing_separator` | **CORRECT** | |
| `test_path_traversal_dot_filename` | **CORRECT** | ".hidden" and "..hidden" are valid filenames. |

### Allocation Size Tests

| Test | Verdict | Details |
|------|---------|---------|
| `test_ksmbd_alloc_size_cached` | **CORRECT** | Cached allocation size takes precedence. |
| `test_ksmbd_alloc_size_from_stat` | **CORRECT** | `blocks << 9` converts 512-byte blocks to bytes. |
| `test_ksmbd_alloc_size_null_fp` | **CORRECT** | NULL fp falls back to stat.blocks. |
| `test_ksmbd_alloc_size_zero_blocks` | **CORRECT** | |
| `test_ksmbd_alloc_size_large_blocks` | **CORRECT** | |
| `test_ksmbd_alloc_size_cached_overrides_stat` | **CORRECT** | |

### has_file_id Tests

| Test | Verdict | Details |
|------|---------|---------|
| `test_has_file_id_valid` | **CORRECT** | Valid file IDs are 0 through KSMBD_NO_FID-1. |
| `test_has_file_id_invalid` | **CORRECT** | KSMBD_NO_FID and above are invalid. |
| `test_has_file_id_boundary` | **CORRECT** | |
| `test_has_file_id_zero` | **CORRECT** | |

### ksmbd_stream_fd Tests

| Test | Verdict | Details |
|------|---------|---------|
| `test_ksmbd_stream_fd_with_stream` | **CORRECT** | Non-NULL stream.name indicates a stream FD. |
| `test_ksmbd_stream_fd_without_stream` | **CORRECT** | |
| `test_ksmbd_stream_fd_empty_name` | **CORRECT** | Empty string is still non-NULL. |

### CreateOptions Flag Constant Tests

| Test | Verdict | Details |
|------|---------|---------|
| `test_create_options_directory_flag` | **CORRECT** | FILE_DIRECTORY_FILE = 0x00000001 per MS-SMB2 section 2.2.13. |
| `test_create_options_non_directory_flag` | **CORRECT** | FILE_NON_DIRECTORY_FILE = 0x00000040 per MS-SMB2 section 2.2.13. |
| `test_create_options_delete_on_close_flag` | **CORRECT** | FILE_DELETE_ON_CLOSE = 0x00001000 per MS-SMB2 section 2.2.13. |
| `test_create_options_mask` | **QUESTIONABLE** | CREATE_OPTIONS_MASK = 0x00FFFFFF. The spec does not define this exact mask value. This is an implementation-defined validation mask. Looking at the defined values, the highest CreateOptions bit is FILE_OPEN_REPARSE_POINT at 0x00200000 and FILE_RESERVE_OPFILTER at 0x00100000, so 0x00FFFFFF covers all defined bits plus some undefined ones. Reasonable but not directly from the spec. |
| `test_create_options_write_through` | **CORRECT** | FILE_WRITE_THROUGH = 0x00000002 per MS-SMB2 section 2.2.13. |
| `test_create_options_sequential_only` | **CORRECT** | FILE_SEQUENTIAL_ONLY = 0x00000004 per MS-SMB2 section 2.2.13. |
| `test_create_options_synchronous_io` | **CORRECT** | FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020 per MS-SMB2 section 2.2.13. |
| `test_create_options_open_reparse` | **CORRECT** | FILE_OPEN_REPARSE_POINT = 0x00200000 per MS-SMB2 section 2.2.13. |
| `test_create_options_no_intermediate_buffering` | **CORRECT** | FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008 per MS-SMB2 section 2.2.13. |
| `test_create_options_random_access` | **CORRECT** | FILE_RANDOM_ACCESS = 0x00000800 per MS-SMB2 section 2.2.13. |

### Lock Range Tests

| Test | Verdict | Details |
|------|---------|---------|
| `test_check_lock_range_valid` | **CORRECT** | |
| `test_check_lock_range_zero_length` | **CORRECT** | Zero-length locks are valid per MS-SMB2 section 2.2.26. |
| `test_check_lock_range_negative_start` | **CORRECT** | Negative start rejected (kernel-space constraint). |
| `test_check_lock_range_overflow` | **CORRECT** | |
| `test_check_lock_range_max_valid` | **CORRECT** | |
| `test_check_lock_range_llong_max` | **CORRECT** | |
| `test_check_lock_range_full_range` | **CORRECT** | |
| `test_check_lock_range_one_byte` | **CORRECT** | |
| `test_check_lock_range_negative_length` | **CORRECT** | |
| `test_check_lock_range_large_start_small_length` | **CORRECT** | |
| `test_check_lock_range_large_start_large_length` | **CORRECT** | |
| `test_check_lock_range_both_zero` | **CORRECT** | |

### ksmbd_is_dot_dotdot Tests

| Test | Verdict | Details |
|------|---------|---------|
| `test_is_dot_dotdot_single_dot` | **CORRECT** | |
| `test_is_dot_dotdot_double_dot` | **CORRECT** | |
| `test_is_dot_dotdot_regular_name` | **CORRECT** | |
| `test_is_dot_dotdot_dotfile` | **CORRECT** | |
| `test_is_dot_dotdot_dotdotfile` | **CORRECT** | |
| `test_is_dot_dotdot_empty_name` | **CORRECT** | |
| `test_is_dot_dotdot_single_char_not_dot` | **CORRECT** | |
| `test_is_dot_dotdot_two_char_not_dotdot` | **CORRECT** | |
| `test_is_dot_dotdot_three_dots` | **CORRECT** | |
| `test_is_dot_dotdot_len_mismatch` | **CORRECT** | Passes ".." buffer with len=1, treated as ".". |

### smb_check_attrs Tests (CONFIG_SMB_INSECURE_SERVER only)

| Test | Verdict | Details |
|------|---------|---------|
| `test_smb_check_attrs_mode_sanitize` | **CORRECT** | SMB1 attribute sanitization. |
| `test_smb_check_attrs_no_mode_no_chown` | **CORRECT** | |
| `test_smb_check_attrs_chown_revokes_suid_sgid` | **CORRECT** | Standard Linux security: chown revokes setuid/setgid. |
| `test_smb_check_attrs_chown_with_mode_clears_suid` | **CORRECT** | |
| `test_smb_check_attrs_chown_same_uid_no_revoke` | **CORRECT** | |
| `test_smb_check_attrs_dir_no_revoke` | **CORRECT** | Directories skip setuid/setgid revocation. |
| `test_smb_check_attrs_gid_change` | **CORRECT** | |

---

## File 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_vfs_cache.c`

All 57 KUNIT_CASEs in this file test VFS cache internal data structures: pending delete flags, POSIX flags, lock sequence arrays, file state transitions, delete-on-close, allocation size, durable/resilient handle fields, channel sequence, app instance ID, inode status constants, FID constants, dot_dotdot tracking, refcounting, oplock/stream counts, fd_limit, inode_hash, sanity_check, open_id_set, fp_get, tree_conn_fd_check, and fd_limit_close.

| Test Category | Count | Verdict |
|---------------|-------|---------|
| Pending delete state | 4 | **CORRECT** -- S_DEL_PENDING (0x0001), S_DEL_ON_CLS (0x0002) are implementation-internal flags, correctly tested. |
| POSIX flag | 1 | **CORRECT** |
| Lock sequence tracking | 5 | **CORRECT** -- Array size 65 (indices 0-64), initialized to 0xFF sentinel. Per MS-SMB2 section 3.3.5.14, lock sequence indices are 1-64, and 0xFF is used as "not valid." |
| File state transitions | 1 | **CORRECT** -- FP_NEW -> FP_INITED -> FP_CLOSED lifecycle. |
| Delete-on-close | 2 | **CORRECT** |
| Allocation size | 2 | **CORRECT** |
| Durable/resilient handle fields | 2 | **CORRECT** -- Per MS-SMB2 section 3.3.5.9.7 (durable handles). |
| Channel sequence | 2 | **CORRECT** -- Per MS-SMB2 section 3.3.5.2.10, ChannelSequence is a 16-bit value. Initial 0 is correct. |
| App instance ID | 2 | **CORRECT** -- Per MS-SMB2 section 2.2.13.2.13 (app instance ID create context). |
| Inode status constants | 1 | **CORRECT** |
| FID constants | 3 | **CORRECT** -- SMB2_NO_FID = 0xFFFFFFFFFFFFFFFF per MS-SMB2 section 2.2.14. KSMBD_NO_FID = INT_MAX and KSMBD_START_FID = 0 are implementation constants. |
| dot_dotdot tracking | 2 | **CORRECT** -- Reset on RESTART_SCANS per MS-SMB2 section 3.3.5.17 (QUERY_DIRECTORY). |
| Inode refcount | 4 | **CORRECT** |
| Oplock/stream counts | 3 | **CORRECT** |
| Lock sequence resilient/persistent | 2 | **CORRECT** -- Lock sequence applies to resilient and persistent handles per MS-SMB2 section 3.3.5.14. |
| File state constants | 1 | **CORRECT** |
| Pending delete clear_if_only | 2 | **CORRECT** -- Only clears when single handle remaining. |
| Inode flags independence | 2 | **CORRECT** |
| fd_limit (VISIBLE_IF_KUNIT) | 2 | **CORRECT** |
| inode_hash (VISIBLE_IF_KUNIT) | 5 | **CORRECT** |
| __sanity_check (VISIBLE_IF_KUNIT) | 4 | **CORRECT** |
| __open_id_set (VISIBLE_IF_KUNIT) | 5 | **CORRECT** |
| ksmbd_fp_get (VISIBLE_IF_KUNIT) | 4 | **CORRECT** -- Only FP_INITED state allows get. |
| tree_conn_fd_check (VISIBLE_IF_KUNIT) | 4 | **CORRECT** |
| fd_limit_close (VISIBLE_IF_KUNIT) | 1 | **CORRECT** |

---

## File 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_error_vfs.c`

| Test | Verdict | Details |
|------|---------|---------|
| `test_fd_limit_at_zero` | **CORRECT** | |
| `test_fd_limit_at_one` | **CORRECT** | |
| `test_inode_hash_zero_hashval` | **CORRECT** | |
| `test_inode_hash_max_hashval` | **CORRECT** | |
| `test_inode_hash_same_sb_different_vals` | **CORRECT** | |
| `test_sanity_check_both_null` | **CORRECT** | NULL fp always returns false. |
| `test_sanity_check_null_tcon_in_fp` | **CORRECT** | fp->tcon=NULL vs non-NULL tcon returns false. |
| `test_sanity_check_same_pointer` | **CORRECT** | |
| `test_sanity_check_different_tcons_same_content` | **CORRECT** | Pointer comparison, not content comparison. |
| `test_sanity_check_null_tcon_arg` | **CORRECT** | Both NULL matches. |

---

## File 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_acl.c`

### SID Format Verification

Per MS-DTYP section 2.4.2 (referenced by MS-SMB2), a SID has:
- Revision (1 byte) -- always 1
- SubAuthorityCount (1 byte) -- 0 to 15
- IdentifierAuthority (6 bytes)
- SubAuthority array (4 bytes each)

| Test | Verdict | Details |
|------|---------|---------|
| `test_compare_sids_equal` | **CORRECT** | SID S-1-5-21-100 with revision=1, authority={0,0,0,0,0,5}, sub_auth[0]=21, sub_auth[1]=100. Correct SID format. |
| `test_compare_sids_different_revision` | **CORRECT** | Revision 2 is technically invalid per MS-DTYP (only revision 1 is defined), but the test correctly validates that different revisions don't match. |
| `test_compare_sids_different_subauth_count` | **CORRECT** | |
| `test_compare_sids_different_authority` | **CORRECT** | |
| `test_compare_sids_different_subauth` | **CORRECT** | |
| `test_compare_sids_null` | **CORRECT** | |
| `test_compare_sids_everyone` | **CORRECT** | Everyone SID = S-1-1-0: revision=1, authority={0,0,0,0,0,1}, sub_auth[0]=0. This is the correct well-known SID per MS-DTYP section 2.4.2.4. |
| `test_compare_sids_self_equal` | **CORRECT** | |
| `test_compare_sids_max_subauth_equal` | **CORRECT** | SID_MAX_SUB_AUTHORITIES=15 per MS-DTYP. |
| `test_compare_sids_zero_subauth` | **CORRECT** | |

### ACE Inheritance Flags

Per MS-DTYP section 2.4.4.1:
- OBJECT_INHERIT_ACE (0x01): ACE propagated to non-container objects
- CONTAINER_INHERIT_ACE (0x02): ACE propagated to container objects
- NO_PROPAGATE_INHERIT_ACE (0x04): ACE not propagated beyond one level

| Test | Verdict | Details |
|------|---------|---------|
| `test_smb_inherit_flags_file` | **CORRECT** | Files inherit only from OBJECT_INHERIT_ACE. Per MS-DTYP, OI applies to non-container (file) objects. |
| `test_smb_inherit_flags_dir` | **CORRECT** | Directories inherit from CONTAINER_INHERIT_ACE. OBJECT_INHERIT_ACE also inherits to directories unless NO_PROPAGATE_INHERIT_ACE blocks it. |
| `test_smb_inherit_flags_no_propagate_container` | **CORRECT** | CONTAINER_INHERIT_ACE with NO_PROPAGATE_INHERIT_ACE still inherits to the immediate child directory. NO_PROPAGATE prevents further propagation, but doesn't prevent initial inheritance. |

### ACE Type and Structure

Per MS-DTYP section 2.4.4.2:
- ACCESS_ALLOWED_ACE_TYPE (0x00)
- ACCESS_DENIED_ACE_TYPE (0x01)
- ACE structure: type(1) + flags(1) + size(2) + access_mask(4) + SID

| Test | Verdict | Details |
|------|---------|---------|
| `test_smb_set_ace` | **CORRECT** | ACE size = 1+1+2+4 (header) + 1+1+6+n*4 (SID) = 8+8+n*4. For 2 sub-auths: 8+8+8=24. Correct. |
| `test_smb_set_ace_with_flags` | **CORRECT** | ACCESS_DENIED with OI+CI flags. |
| `test_smb_set_ace_size_calculation` | **CORRECT** | For 3 sub-auths: 8+8+12=28. Correct. |
| `test_fill_ace_for_sid_basic` | **CORRECT** | |
| `test_fill_ace_for_sid_zero_mode` | **CORRECT** | Falls back to SET_MINIMUM_RIGHTS. |
| `test_fill_ace_for_sid_denied_type` | **CORRECT** | |

### SID Type Mapping (id_to_sid)

| Test | Verdict | Details |
|------|---------|---------|
| `test_id_to_sid_owner` | **CORRECT** | SIDOWNER produces domain SID with 5 sub-authorities (4 domain + 1 RID). |
| `test_id_to_sid_unix_user` | **CORRECT** | S-1-22-1-uid: Samba's Unix user SID. authority[5]=22, sub_auth[0]=1, sub_auth[1]=uid. Not in MS-SMB2 spec but a well-known Samba convention. |
| `test_id_to_sid_unix_group` | **CORRECT** | S-1-22-2-gid: Samba's Unix group SID. Correct. |
| `test_id_to_sid_creator_owner` | **CORRECT** | S-1-3-0: CREATOR OWNER per MS-DTYP. authority[5]=3, sub_auth[0]=0. Correct. |
| `test_id_to_sid_creator_group` | **CORRECT** | S-1-3-1: CREATOR GROUP per MS-DTYP. authority[5]=3, sub_auth[0]=1. Correct. |
| `test_id_to_sid_group_owner` | **CORRECT** | |
| `test_id_to_sid_zero_uid` | **CORRECT** | |
| `test_id_to_sid_max_uid` | **CORRECT** | |

### Access Flags to Mode Mapping

| Test | Verdict | Details |
|------|---------|---------|
| `test_access_flags_to_mode_read` | **CORRECT** | GENERIC_READ -> 0444 (read for owner/group/other). |
| `test_access_flags_to_mode_write` | **CORRECT** | GENERIC_WRITE on file -> 0222. |
| `test_access_flags_to_mode_write_dir` | **CORRECT** | GENERIC_WRITE on directory -> 0333 (write+execute needed for directory traversal). |
| `test_access_flags_to_mode_exec` | **CORRECT** | GENERIC_EXECUTE -> 0111. |
| `test_access_flags_to_mode_all` | **CORRECT** | GENERIC_ALL -> 0777. |
| `test_access_flags_to_mode_denied` | **CORRECT** | ACCESS_DENIED inverts the mode. |
| `test_access_flags_to_mode_no_flags` | **CORRECT** | Zero flags -> zero mode. |
| `test_mode_to_access_flags_rwx` | **CORRECT** | |
| `test_mode_to_access_flags_none` | **CORRECT** | |
| `test_mode_to_access_flags_read_only` | **CORRECT** | |
| `test_mode_to_access_flags_exec_only` | **CORRECT** | |

### SID Parsing

| Test | Verdict | Details |
|------|---------|---------|
| `test_parse_sid_valid` | **CORRECT** | 12 bytes = 8 (header) + 4 (1 sub-auth). |
| `test_parse_sid_truncated` | **CORRECT** | 4 bytes < 8 bytes minimum for SID header. |
| `test_parse_sid_max_subauth` | **CORRECT** | 68 = 8 + 15*4. Correct for SID_MAX_SUB_AUTHORITIES=15. |
| `test_parse_sid_too_many_subauth` | **CORRECT** | num_subauth=16 exceeds SID_MAX_SUB_AUTHORITIES=15. |
| `test_parse_sid_subauth_overflow` | **CORRECT** | Claims 2 sub-auths (16 bytes needed) but only 12 available. |

### Domain-Aware SID Mapping (VISIBLE_IF_KUNIT)

| Test | Verdict | Details |
|------|---------|---------|
| `test_extract_domain_prefix_basic` | **CORRECT** | Extracts 4 sub-auths from 5-subauth SID. |
| `test_extract_domain_prefix_null` | **CORRECT** | |
| `test_extract_domain_prefix_zero_subauth` | **CORRECT** | |
| `test_extract_domain_prefix_too_many_subauth` | **CORRECT** | |
| `test_extract_domain_prefix_single_subauth` | **CORRECT** | Single sub-auth produces empty domain (num_subauth=0). |
| `test_domain_sid_hash_null` | **CORRECT** | |
| `test_domain_sid_hash_single_subauth` | **CORRECT** | |
| `test_domain_sid_hash_deterministic` | **CORRECT** | |
| `test_domain_sid_hash_different_domains` | **CORRECT** | |
| `test_domain_sid_hash_same_rid_different_domain` | **CORRECT** | |
| `test_sid_domain_match_unix_user` | **CORRECT** | S-1-22-1-* always matches (well-known). |
| `test_sid_domain_match_unix_group` | **CORRECT** | S-1-22-2-* always matches. |
| `test_sid_domain_match_nfs` | **CORRECT** | S-1-5-88-* always matches. |
| `test_sid_domain_match_null` | **CORRECT** | |
| `test_sid_domain_match_zero_subauth` | **CORRECT** | |
| `test_sid_to_id_null` | **CORRECT** | |
| `test_sid_to_id_zero_subauth` | **CORRECT** | |
| `test_sid_to_id_too_many_subauth` | **CORRECT** | |
| `test_sid_to_id_everyone_rejected` | **CORRECT** | S-1-1-0 (Everyone) cannot map to a single UID. Returns -EIO. |
| `test_sid_to_id_unix_user` | **CORRECT** | |
| `test_sid_to_id_nfs_uid` | **CORRECT** | |
| `test_smb_copy_sid` | **CORRECT** | |
| `test_smb_copy_sid_zero_subauth` | **CORRECT** | |
| `test_smb_copy_sid_max_subauth` | **CORRECT** | |
| `test_smb_copy_sid_preserves_authority` | **CORRECT** | |
| `test_init_free_acl_state` | **CORRECT** | |
| `test_init_acl_state_zero_count` | **CORRECT** | |
| `test_init_acl_state_large_count` | **CORRECT** | |
| `test_ace_size_basic` (from remaining tests) | **CORRECT** | |

---

## File 5: `/home/ezechiel203/ksmbd/test/ksmbd_test_sid_mapping.c`

| Test | Verdict | Details |
|------|---------|---------|
| `test_same_rid_different_domains` | **CORRECT** | Critical security test: same RID from different domains must map to different UIDs. |
| `test_local_domain_uses_rid_directly` | **CORRECT** | Local domain SIDs use RID directly for backward compatibility. |
| `test_foreign_domain_gets_offset` | **CORRECT** | Foreign domain SIDs get offset >= DOMAIN_UID_OFFSET_MULTIPLIER. |
| `test_two_foreign_domains_differ` | **CORRECT** | |
| `test_wellknown_unix_user_sid` | **CORRECT** | S-1-22-1-1000 -> UID 1000. |
| `test_wellknown_unix_group_sid` | **CORRECT** | S-1-22-2-500 -> GID 500. |
| `test_wellknown_nfs_user_sid` | **CORRECT** | S-1-5-88-1-65534 -> UID 65534 (nobody). |
| `test_wellknown_local_system` | **CORRECT** | S-1-5-18 (LocalSystem) -- no crash. |
| `test_wellknown_builtin_admins` | **CORRECT** | S-1-5-32-544 (BUILTIN\Administrators). |
| `test_sid_zero_subauth_rejected` | **CORRECT** | |
| `test_sid_max_subauth_handled` | **CORRECT** | SID_MAX_SUB_AUTHORITIES=15, accepted. |
| `test_sid_over_max_subauth_rejected` | **CORRECT** | 16 > 15, rejected. |
| `test_null_sid_rejected` | **CORRECT** | |
| `test_null_output_rejected` | **CORRECT** | |
| `test_everyone_sid_rejected` | **CORRECT** | S-1-1-0 (Everyone) cannot map to a UID. |
| `test_rid_overflow_protection` | **CORRECT** | U32_MAX-1 + offset would overflow. |
| `test_rid_zero_local_domain` | **CORRECT** | RID 0 from local domain -> UID 0. |
| `test_extract_domain_prefix_basic` | **CORRECT** | |
| `test_extract_domain_prefix_null_input` | **CORRECT** | |
| `test_extract_domain_prefix_null_output` | **CORRECT** | |
| `test_extract_domain_prefix_zero_subauth` | **CORRECT** | |
| `test_domain_hash_deterministic` | **CORRECT** | |
| `test_domain_hash_different_domains` | **CORRECT** | |
| `test_domain_hash_null` | **CORRECT** | |
| `test_domain_hash_single_subauth` | **CORRECT** | |
| `test_domain_match_local` | **CORRECT** | |
| `test_domain_match_foreign` | **CORRECT** | |
| `test_domain_match_unix_users` | **CORRECT** | |
| `test_domain_match_unix_groups` | **CORRECT** | |
| `test_domain_match_nfs_user` | **CORRECT** | |
| `test_domain_match_null` | **CORRECT** | |
| `test_domain_match_zero_subauth` | **CORRECT** | |
| `test_mapping_idempotent` | **CORRECT** | |
| `test_same_rid_same_domain_same_uid` | **CORRECT** | |

---

## File 6: `/home/ezechiel203/ksmbd/test/ksmbd_test_vss.c`

### GMT Token Format

Per MS-SMB2 glossary (line 867): The format is "@GMT-YYYY.MM.DD-HH.MM.SS". This is a 24-character string (plus NUL = 25 bytes).

| Test | Verdict | Details |
|------|---------|---------|
| `test_gmt_token_valid` | **CORRECT** | "@GMT-2024.01.15-10.30.00" = 24 chars. Format matches MS-SMB2 definition. |
| `test_gmt_token_wrong_prefix` | **CORRECT** | "@XMT-..." is not valid. |
| `test_gmt_token_wrong_length_short` | **CORRECT** | 15 chars != 24 chars. |
| `test_gmt_token_wrong_length_long` | **CORRECT** | 25 chars != 24 chars. |
| `test_gmt_token_missing_separator` | **CORRECT** | Separator validation. |
| `test_gmt_token_empty` | **CORRECT** | 0 chars != 24 chars. |

### Timestamp Parsing

| Test | Verdict | Details |
|------|---------|---------|
| `test_parse_timestamp_known_date` | **CORRECT** | |
| `test_parse_timestamp_epoch` | **CORRECT** | 1970-01-01 00:00:00 = timestamp 0. |
| `test_parse_timestamp_invalid_format` | **CORRECT** | |

### dirname_to_gmt Conversion

| Test | Verdict | Details |
|------|---------|---------|
| `test_dirname_gmt_passthrough` | **CORRECT** | GMT token passed through unchanged. |
| `test_dirname_snapper_format` | **CORRECT** | Snapper format "YYYY-MM-DD_HH:MM:SS" converted correctly. |
| `test_dirname_simple_format` | **CORRECT** | "YYYY-MM-DD-HHMMSS" converted correctly. |
| `test_dirname_date_only` | **CORRECT** | "YYYY-MM-DD" with time defaulting to 00:00:00. |
| `test_dirname_leap_year` | **CORRECT** | Feb 29 on leap year 2024. |
| `test_dirname_invalid_garbage` | **CORRECT** | Returns -EINVAL. |
| `test_dirname_year_before_epoch` | **CORRECT** | Year < 1970 rejected. |
| `test_dirname_invalid_month` | **CORRECT** | Month > 12 rejected. |

### Production Function Tests

| Test | Verdict | Details |
|------|---------|---------|
| `test_real_is_gmt_token_24chars` | **QUESTIONABLE** | The test expects that a 24-char GMT token returns false because production `KSMBD_VSS_GMT_TOKEN_LEN=32` and `ksmbd_vss_is_gmt_token()` checks `namlen != 31`. However, per MS-SMB2, the @GMT token is exactly 24 characters. The production code expecting 31 characters is **WRONG** relative to the MS-SMB2 spec. The test correctly documents the production behavior but the production code has a **spec deviation**: the comment in `ksmbd_vss.h` says "24 chars + NUL = 25. Use 32 to silence gcc" but then `ksmbd_vss_is_gmt_token()` checks for `namlen == KSMBD_VSS_GMT_TOKEN_LEN - 1` = 31, which would reject the spec-compliant 24-char token. |

**WRONG (production code spec deviation documented in test):** `ksmbd_vss_is_gmt_token()` rejects 24-char @GMT tokens because it checks `namlen == 31` instead of `namlen == 24`. Per MS-SMB2 glossary line 867 and section 3.3.5.15.1 line 8417: "@GMT-YYYY.MM.DD-HH.MM.SS" is exactly 24 characters. The test correctly identifies this behavior but the underlying production code is non-compliant. Fix: `KSMBD_VSS_GMT_TOKEN_LEN` should be 25 (24 chars + NUL), and `ksmbd_vss_is_gmt_token()` should check `namlen == 24`.

| Test | Verdict | Details |
|------|---------|---------|
| `test_real_is_gmt_token_wrong_prefix` | **CORRECT** | |
| `test_real_is_gmt_token_empty` | **CORRECT** | |
| `test_real_is_gmt_token_too_short` | **CORRECT** | |
| `test_real_parse_gmt_timestamp_valid` | **CORRECT** | Parse works on the @GMT format regardless of length check. |
| `test_real_parse_gmt_timestamp_epoch` | **CORRECT** | |
| `test_real_parse_gmt_timestamp_invalid` | **CORRECT** | |
| `test_real_parse_gmt_timestamp_y2k38` | **CORRECT** | u64 timestamp handles dates past 2038. |
| `test_real_dirname_to_gmt_snapper` | **CORRECT** | |
| `test_real_dirname_to_gmt_simple` | **CORRECT** | |
| `test_real_dirname_to_gmt_date_only` | **CORRECT** | |
| `test_real_dirname_to_gmt_invalid` | **CORRECT** | |
| `test_real_dirname_to_gmt_pre_epoch` | **CORRECT** | |
| `test_real_dirname_to_gmt_invalid_month` | **CORRECT** | |
| `test_real_dirname_to_gmt_timestamp_value` | **CORRECT** | |

---

## File 7: `/home/ezechiel203/ksmbd/test/ksmbd_test_access_edge.c`

### Access Mask Bit Positions (per MS-SMB2 section 2.2.13.1.1)

| Test | Verdict | Details |
|------|---------|---------|
| `test_file_read_attributes_bit_position` | **CORRECT** | FILE_READ_ATTRIBUTES = 0x00000080. Verified against MS-SMB2 section 2.2.13.1.1 line 5012-5013. |
| `test_file_read_data_bit_position` | **CORRECT** | FILE_READ_DATA = 0x00000001. Line 4991-4992. |
| `test_file_write_data_bit_position` | **CORRECT** | FILE_WRITE_DATA = 0x00000002. Line 4994-4995. |
| `test_file_execute_bit_position` | **CORRECT** | FILE_EXECUTE = 0x00000020. Line 5009-5010. |
| `test_file_delete_bit_position` | **CORRECT** | DELETE = 0x00010000. Line 5018-5019. |
| `test_desired_access_mask_value` | **CORRECT** | 0xF21F01FF includes all file-specific bits (0x000001FF), standard rights (0x001F0000), SYNCHRONIZE (0x00100000), MAXIMUM_ALLOWED (0x02000000), and generic bits (0xF0000000). ACCESS_SYSTEM_SECURITY (0x01000000) correctly excluded. |
| `test_read_attributes_excludes_read_data` | **CORRECT** | 0x0080 & 0x0001 = 0. Critical for hide_on_access_denied logic. |
| `test_generic_read_includes_read_attributes` | **CORRECT** | GENERIC_READ (0x80000000) expands to include FILE_READ_ATTRIBUTES. Both are valid in DESIRED_ACCESS_MASK. FILE_READ_ATTRIBUTES alone is correctly NOT in FILE_READ_DESIRED_ACCESS_LE. |
| `test_delete_on_close_requires_delete_access` | **CORRECT** | Per MS-SMB2 section 2.2.13 line 4884-4886: "When this option is set, the DesiredAccess field MUST include the DELETE flag." The test verifies CreateOptions DELETE_ON_CLOSE (0x00001000) and access mask DELETE (0x00010000) are different bits. |
| `test_synchronize_bit_in_desired_access_mask` | **CORRECT** | SYNCHRONIZE = 0x00100000 (bit 20). Per MS-SMB2 section 2.2.13.1.1 line 5031: "SMB2 clients set this flag to any value." Must be accepted in the mask. |

---

## File 8: `/home/ezechiel203/ksmbd/test/ksmbd_test_regression_access.c`

| Test | Verdict | Details |
|------|---------|---------|
| `reg_desired_access_mask_synchronize` | **CORRECT** | DESIRED_ACCESS_MASK = 0xF21F01FF, includes bit 20 (SYNCHRONIZE). |
| `reg_delete_on_close_needs_delete_access` | **CORRECT** | Tests smb2_create_open_flags with DELETE access. FILE_DELETE_LE = 0x00010000, FILE_DELETE_ON_CLOSE_LE = 0x00001000. Both correct per MS-SMB2. |
| `reg_append_only_rejects_non_eof_write` | **CORRECT** | FILE_APPEND_DATA = 0x00000004 per MS-SMB2 section 2.2.13.1.1. Produces O_WRONLY for append-only access. Per MS-SMB2 section 3.3.5.21 line 23271: write with only FILE_APPEND_DATA at non-EOF offset is rejected. |
| `reg_doc_readonly_status_cannot_delete` | **CORRECT** | ATTR_READONLY = 0x01 per MS-FSCC. FILE_DELETE_ON_CLOSE + readonly = STATUS_CANNOT_DELETE per MS-SMB2 section 3.3.5.9. |
| `reg_generic_execute_pre_expansion` | **CORRECT** | GENERIC_EXECUTE = 0x20000000 per MS-SMB2. Maps to read-only file access. |
| `reg_odd_name_length_rejected` | **CORRECT** | SMB2 names are UTF-16LE, so NameLength must be even. |
| `reg_dotdot_path_traversal` | **CORRECT** | Simple string check for ".." in path. |
| `reg_tree_connect_share_name_80chars` | **CORRECT** | Share names >= 80 chars rejected. This is an implementation limit. |

---

## File 9: `/home/ezechiel203/ksmbd/test/ksmbd_test_regression_vfs.c`

| Test | Verdict | Details |
|------|---------|---------|
| `test_reg033_fd_limit_depleted_atomic` | **CORRECT** | Tests atomic fd_limit with limit=2. |
| `test_reg034_inode_hash_stability` | **CORRECT** | Hash determinism. |
| `test_reg034_inode_hash_distribution` | **CORRECT** | Statistical collision check. |
| `test_reg036_sanity_check_null_fp` | **CORRECT** | |
| `test_reg036_sanity_check_match` | **CORRECT** | |
| `test_reg036_sanity_check_mismatch` | **CORRECT** | |

---

## Summary

**Total KUNIT_CASEs audited:** ~210 across 9 files

### Issues Found

| # | File | Test | Severity | Verdict | Spec Reference | Description |
|---|------|------|----------|---------|----------------|-------------|
| 1 | `ksmbd_test_vfs.c` | `test_vfs_set_fadvise_sequential_and_random` | **WRONG** | WRONG | MS-SMB2 section 2.2.13, lines 4879-4881 | When both FILE_RANDOM_ACCESS and FILE_SEQUENTIAL_ONLY are set, the spec says "FILE_SEQUENTIAL_ONLY is ignored." The test asserts sequential takes priority (the replicated logic checks sequential first). The test should expect `POSIX_FADV_RANDOM`. Fix: swap the if/else order in `test_fadvise_map()` to check FILE_RANDOM_ACCESS first, and change the assertion to `KUNIT_EXPECT_EQ(test, test_fadvise_map(both), POSIX_FADV_RANDOM)`. Note: this is in the test's replicated logic; the production code in `vfs.c` should also be checked for the same bug. |
| 2 | `ksmbd_test_vss.c` | `test_real_is_gmt_token_24chars` | **WRONG (production code)** | WRONG | MS-SMB2 glossary line 867, section 3.3.5.15.1 line 8417 | Production `ksmbd_vss_is_gmt_token()` rejects spec-compliant 24-char @GMT tokens because `KSMBD_VSS_GMT_TOKEN_LEN=32` causes it to check for `namlen==31`. The test correctly documents this behavior but the production code deviates from the spec. The @GMT token format is exactly "@GMT-YYYY.MM.DD-HH.MM.SS" = 24 characters. Fix: `KSMBD_VSS_GMT_TOKEN_LEN` should be 25 (24+NUL), or the check should use a separate constant for the expected string length. |

### Questionable Items

| # | File | Test | Details |
|---|------|------|---------|
| 1 | `ksmbd_test_vfs.c` | `test_create_options_mask` | CREATE_OPTIONS_MASK = 0x00FFFFFF is not directly specified in MS-SMB2. It is an implementation-defined validation mask that covers all defined CreateOptions bits. Reasonable but not directly from the spec. |

### Overall Assessment

The vast majority of tests (208 out of ~210) are **CORRECT** against the MS-SMB2 specification. The SID format, well-known SID values, ACE types and flags, security descriptor structure, access mask bit positions, CreateOptions constants, lock range validation, and VFS cache lifecycle assertions are all correctly implemented and tested.

The two **WRONG** findings are:

1. **fadvise priority when both FILE_SEQUENTIAL_ONLY and FILE_RANDOM_ACCESS are set** -- the test's replicated logic gives sequential priority, but MS-SMB2 section 2.2.13 explicitly says FILE_SEQUENTIAL_ONLY is ignored when both are set. This should also be checked in the production `ksmbd_vfs_set_fadvise()` function.

2. **GMT token length check in production code** -- `ksmbd_vss_is_gmt_token()` expects 31-character tokens due to `KSMBD_VSS_GMT_TOKEN_LEN=32`, but MS-SMB2 defines the @GMT token as exactly 24 characters. The test accurately documents this deviation but the production code itself is non-compliant with the spec.