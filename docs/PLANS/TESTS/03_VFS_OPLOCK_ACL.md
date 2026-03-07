# Test Plan: VFS, Oplock/Lease & ACL

## Current Coverage Summary

### ksmbd_test_oplock.c (11 tests)
Tests ONLY `smb2_map_lease_to_oplock()` and constant validation:
- Lease-to-oplock mapping: RWH, RW, R, RH, None, W-only, WH (7 tests)
- Oplock level constant ordering and values (2 tests)
- Lease state constant values and combinations (2 tests)

**Coverage: 1 of ~30 exported functions tested (3%)**

### ksmbd_test_acl.c (14 tests)
Tests `compare_sids()`, `smb_inherit_flags()`, `init_acl_state()`/`free_acl_state()`, and `id_to_sid()`:
- SID comparison: equal, different revision/subauth/authority, NULL, well-known (7 tests)
- Inheritance flags: file and directory rules (2 tests)
- ACL state allocation/deallocation (1 test)
- ID-to-SID: SIDOWNER, SIDUNIX_USER, SIDUNIX_GROUP, SIDCREATOR_OWNER (4 tests)

**Coverage: 4 of ~12 exported functions tested (33%)**

### ksmbd_test_vss.c (17 tests)
Tests replicated VSS pure-logic functions (GMT token validation, timestamp parsing, dirname-to-GMT conversion):
- GMT token validation: valid, wrong prefix, wrong lengths, missing separator, empty (6 tests)
- Timestamp parsing: known date, epoch, invalid format (3 tests)
- dirname_to_gmt: passthrough, snapper, simple, date-only, leap year, garbage, pre-epoch, invalid month (8 tests)

**Note: Tests replicate logic inline rather than testing actual ksmbd_vss.c functions.**
**Coverage: 0 exported functions tested directly (0% of module API)**

### ksmbd_test_reparse.c (17 tests)
Tests replicated reparse point pure-logic functions (slash conversion, NT prefix stripping, target safety):
- Slash conversion: basic, no-op, empty, mixed, all-backslash, leading/trailing, single (7 tests)
- NT prefix stripping: /??/, //?/, no prefix, too short, just-prefix+1 (5 tests)
- Full workflow: convert + strip pipeline (1 test)
- Reparse target safety: relative ok, reject absolute, reject dotdot, reject dot-component (4 tests)

**Note: Tests replicate logic inline rather than testing actual ksmbd_reparse.c functions.**
**Coverage: 0 exported functions tested directly (0% of module API)**

---

## Gap Analysis

### Completely Untested Source Files

| Source File | Exported Functions | Test File | Status |
|---|---|---|---|
| `src/fs/vfs.c` | ~50+ functions | None | **NO TESTS** |
| `src/fs/vfs_cache.c` | ~30+ functions | None | **NO TESTS** |
| `src/fs/ksmbd_notify.c` | 6 exported functions | None | **NO TESTS** |
| `src/fs/ksmbd_quota.c` | 2 exported functions | None | **NO TESTS** |
| `src/fs/ksmbd_dfs.c` | 3 exported functions | None | **NO TESTS** |
| `src/fs/ksmbd_branchcache.c` | 3 exported functions | None | **NO TESTS** |
| `src/fs/ksmbd_resilient.c` | 2 exported functions | None | **NO TESTS** |
| `src/fs/ksmbd_app_instance.c` | 2 exported functions | None | **NO TESTS** |

### Completely Untested Functions (oplock.c)

| Function | Category | Testability |
|---|---|---|
| `opinfo_get(fp)` | opinfo lifecycle | Needs mock fp with f_opinfo |
| `opinfo_put(opinfo)` | opinfo lifecycle | Needs opinfo with refcount |
| `opinfo_write_to_read(opinfo)` | state transition | Needs pre-set opinfo->level |
| `opinfo_read_handle_to_read(opinfo)` | state transition | Needs lease state |
| `opinfo_write_handle_to_write(opinfo)` | state transition | Needs W+H lease state |
| `opinfo_write_to_none(opinfo)` | state transition | Needs pre-set opinfo->level |
| `opinfo_read_to_none(opinfo)` | state transition | Needs pre-set opinfo->level |
| `lease_read_to_write(opinfo)` | lease upgrade | Needs R lease state |
| `close_id_del_oplock(fp)` | opinfo lifecycle | Needs full fp + opinfo chain |
| `destroy_lease_table(conn)` | lease table | Needs conn with lease tables |
| `find_same_lease_key(sess, ci, lctx)` | lease lookup | Needs session + inode + lease |
| `smb_send_parent_lease_break_noti(fp, ...)` | lease break | Needs fp with parent |
| `smb_break_parent_dir_lease(d)` | lease break | Needs dentry with lease |
| `smb_lazy_parent_lease_break_close(fp)` | lease break | Needs fp with reserve |
| `smb_grant_oplock(work, ...)` | oplock grant | Needs full work context |
| `smb_break_all_levII_oplock(work, fp, ...)` | oplock break | Needs multi-handle |
| `smb_break_all_oplock(work, fp)` | oplock break | Needs multi-handle |
| `create_lease_buf(rbuf, lease)` | response buf | Needs lease struct |
| `create_durable_rsp_buf(cc)` | response buf | Pure buffer fill |
| `create_durable_v2_rsp_buf(cc, fp)` | response buf | Needs fp |
| `create_mxac_rsp_buf(cc, maximal_access)` | response buf | Pure buffer fill |
| `create_disk_id_rsp_buf(cc, file_id, vol_id)` | response buf | Pure buffer fill |
| `create_posix_rsp_buf(cc, fp)` | response buf | Needs fp |
| `create_fruit_rsp_buf(cc, conn, out_size)` | response buf | Needs conn |
| `smb2_check_durable_oplock(conn, ...)` | durable check | Needs conn + share |

### Completely Untested Functions (smbacl.c)

| Function | Category | Testability |
|---|---|---|
| `posix_state_to_acl(state, pace)` | POSIX ACL | Needs populated state + pace array |
| `parse_sec_desc(idmap, pntsd, ...)` | SD parsing | Needs wire-format SD buffer |
| `build_sec_desc(idmap, pntsd, ...)` | SD building | Needs idmap + fattr |
| `smb_inherit_dacl(conn, path, ...)` | DACL inherit | Needs filesystem context |
| `smb_check_perm_dacl(conn, path, ...)` | Permission check | Needs filesystem context |
| `set_info_sec(conn, tcon, ...)` | SD set | Needs tcon + file |
| `ksmbd_init_domain(sub_auth)` | Domain init | Pure function |

### Completely Untested Functions (vfs.c)

| Function | Priority | Category |
|---|---|---|
| `ksmbd_vfs_create(work, name, mode)` | HIGH | File creation |
| `ksmbd_vfs_mkdir(work, name, mode)` | HIGH | Directory creation |
| `ksmbd_vfs_read(work, fp, count, pos)` | HIGH | Read I/O |
| `ksmbd_vfs_write(work, fp, buf, count, pos)` | HIGH | Write I/O |
| `ksmbd_vfs_sendfile(work, fp, ...)` | HIGH | Zero-copy send |
| `ksmbd_vfs_getattr(path, stat)` | MEDIUM | Attribute query |
| `ksmbd_vfs_setattr(work, name, fid, ...)` | MEDIUM | Attribute set |
| `ksmbd_vfs_symlink(work, name, target)` | MEDIUM | Symlink creation |
| `ksmbd_vfs_readlink(path, buf, len)` | MEDIUM | Symlink read |
| `ksmbd_vfs_link(work, oldname, newname)` | MEDIUM | Hard link |
| `ksmbd_vfs_rename(work, old_path, ...)` | HIGH | Rename |
| `ksmbd_vfs_fp_rename(work, fp, ...)` | HIGH | FP-based rename |
| `ksmbd_vfs_truncate(work, fp, size)` | MEDIUM | Truncation |
| `ksmbd_vfs_remove_file(work, path)` | HIGH | File removal |
| `ksmbd_vfs_fsync(work, fid, pid, full)` | MEDIUM | Sync |
| `ksmbd_vfs_lock_parent(parent, child)` | MEDIUM | Parent lock |
| `ksmbd_vfs_query_maximal_access(idmap, de, ...)` | MEDIUM | Access query |
| `ksmbd_vfs_kern_path(work, filepath, ...)` | HIGH | Path resolution |
| `ksmbd_vfs_kern_path_locked(work, filepath, ...)` | HIGH | Locked path resolution |
| `check_lock_range(filp, start, end, ...)` | HIGH | Lock range validation |
| `ksmbd_vfs_getxattr(idmap, de, name, ...)` | MEDIUM | Xattr get |
| `ksmbd_vfs_setxattr(idmap, path, name, ...)` | MEDIUM | Xattr set |
| `ksmbd_vfs_fsetxattr(work, name, ...)` | MEDIUM | Xattr set (by name) |
| `ksmbd_vfs_remove_xattr(idmap, path, ...)` | MEDIUM | Xattr remove |
| `ksmbd_vfs_listxattr(dentry, list)` | MEDIUM | Xattr list |
| `ksmbd_vfs_remove_acl_xattrs(idmap, path)` | MEDIUM | ACL xattr remove |
| `ksmbd_vfs_remove_sd_xattrs(idmap, path)` | MEDIUM | SD xattr remove |
| `ksmbd_vfs_set_sd_xattr(conn, ...)` | HIGH | SD xattr set |
| `ksmbd_vfs_get_sd_xattr(conn, ...)` | HIGH | SD xattr get |
| `ksmbd_vfs_set_dos_attrib_xattr(idmap, ...)` | MEDIUM | DOS attr xattr set |
| `ksmbd_vfs_get_dos_attrib_xattr(idmap, ...)` | MEDIUM | DOS attr xattr get |
| `ksmbd_vfs_set_fadvise(filp, option)` | LOW | fadvise |
| `ksmbd_vfs_zero_data(work, fp, off, len)` | MEDIUM | Zero data |
| `ksmbd_vfs_fqar_lseek(fp, start, len, ...)` | MEDIUM | Allocated ranges |
| `ksmbd_vfs_unlink(filp)` | HIGH | Unlink |
| `ksmbd_vfs_empty_dir(fp)` | MEDIUM | Empty dir check |
| `ksmbd_vfs_copy_xattrs(src, dst)` | MEDIUM | Xattr copy |
| `ksmbd_vfs_copy_file_ranges(work, ...)` | HIGH | File range copy |
| `ksmbd_vfs_posix_lock_wait(flock)` | MEDIUM | Lock wait |
| `ksmbd_vfs_posix_lock_wait_timeout(flock, t)` | MEDIUM | Lock wait + timeout |
| `ksmbd_vfs_posix_lock_unblock(flock)` | MEDIUM | Lock unblock |
| `ksmbd_vfs_set_init_posix_acl(idmap, ...)` | MEDIUM | Initial ACL |
| `ksmbd_vfs_inherit_posix_acl(idmap, ...)` | MEDIUM | ACL inheritance |
| `ksmbd_vfs_fill_dentry_attrs(work, ...)` | MEDIUM | Dentry attr fill |
| `ksmbd_vfs_casexattr_len(idmap, ...)` | LOW | Case xattr length |
| `ksmbd_vfs_xattr_stream_name(stream, ...)` | MEDIUM | Stream name xattr |
| `ksmbd_vfs_resolve_fileid(share_path, ...)` | MEDIUM | File ID resolution |
| `ksmbd_vfs_readdir_name(work, ...)` | MEDIUM | Directory read |

### Completely Untested Functions (vfs_cache.c)

| Function | Priority | Category |
|---|---|---|
| `ksmbd_set_fd_limit(limit)` | MEDIUM | FD limit control |
| `ksmbd_query_inode_status(dentry)` | HIGH | Inode status query |
| `ksmbd_inode_pending_delete(fp)` | HIGH | Delete-pending check |
| `ksmbd_inode_clear_pending_delete_if_only(fp)` | HIGH | Conditional clear |
| `ksmbd_set_inode_pending_delete(fp)` | HIGH | Set pending delete |
| `ksmbd_clear_inode_pending_delete(fp)` | HIGH | Clear pending delete |
| `ksmbd_fd_set_delete_on_close(fp, info)` | HIGH | DOC set |
| `ksmbd_inode_set_posix(ci)` | LOW | POSIX flag set |
| `ksmbd_inode_put(ci)` | MEDIUM | Inode refcount |
| `ksmbd_inode_hash_init()` | LOW | Hash init |
| `ksmbd_release_inode_hash()` | LOW | Hash release |
| `ksmbd_close_fd(work, id)` | HIGH | FD close |
| `ksmbd_fd_put(work, fp)` | MEDIUM | FD refcount |
| `ksmbd_put_durable_fd(fp)` | MEDIUM | Durable FD release |
| `ksmbd_update_fstate(ft, fp, state)` | MEDIUM | State update |
| `ksmbd_launch_ksmbd_durable_scavenger()` | LOW | Scavenger start |
| `ksmbd_stop_durable_scavenger()` | LOW | Scavenger stop |
| `ksmbd_close_tree_conn_fds(work)` | MEDIUM | Tree conn cleanup |
| `ksmbd_close_session_fds(work)` | MEDIUM | Session cleanup |
| `ksmbd_init_global_file_table()` | LOW | Global FT init |
| `ksmbd_free_global_file_table()` | LOW | Global FT free |
| `ksmbd_file_table_flush(work)` | MEDIUM | FT flush |
| `ksmbd_validate_name_reconnect(share, fp)` | HIGH | Durable reconnect |
| `ksmbd_reopen_durable_fd(work, fp)` | HIGH | Durable reopen |
| `ksmbd_init_file_table(ft)` | LOW | FT init |
| `ksmbd_destroy_file_table(ft)` | LOW | FT destroy |
| `ksmbd_init_file_cache()` | LOW | Cache init |
| `ksmbd_exit_file_cache()` | LOW | Cache exit |
| `ksmbd_inode_lookup_lock(d)` | MEDIUM | Inode lookup |

### Insufficiently Tested Functions

| Function | Current Tests | Missing Coverage |
|---|---|---|
| `smb2_map_lease_to_oplock()` | All 8 states | Edge: `__le32` overflow, endian handling |
| `compare_sids()` | 7 scenarios | Edge: max subauth (15), zero-length authority |
| `id_to_sid()` | 4 types | Missing: SIDCREATOR_GROUP, SIDNFS_USER, SIDNFS_GROUP, SIDNFS_MODE, default case, boundary uid (0, UINT_MAX), SID_MAX_SUB_AUTHORITIES overflow |
| `smb_inherit_flags()` | File + dir | Missing: INHERIT_ONLY_ACE interaction, all combinations with NO_PROPAGATE |
| `init_acl_state()` | Basic alloc | Missing: cnt=0, cnt=UINT16_MAX, allocation failure paths |

---

## New Tests Required

### ksmbd_test_oplock.c Enhancements

#### Oplock State Transition Tests
```
test_opinfo_write_to_read_from_batch
test_opinfo_write_to_read_from_exclusive
test_opinfo_write_to_read_from_level2_fails
test_opinfo_write_to_read_from_none_fails
test_opinfo_write_to_read_lease_state_update

test_opinfo_read_handle_to_read_valid
test_opinfo_read_handle_to_read_non_lease_fails

test_opinfo_write_handle_to_write_rwh_to_rw
test_opinfo_write_handle_to_write_no_write_fails
test_opinfo_write_handle_to_write_no_handle_fails
test_opinfo_write_handle_to_write_non_lease_fails

test_opinfo_write_to_none_from_batch
test_opinfo_write_to_none_from_exclusive
test_opinfo_write_to_none_from_level2_fails
test_opinfo_write_to_none_lease_state_update

test_opinfo_read_to_none_from_level2
test_opinfo_read_to_none_from_batch_fails
test_opinfo_read_to_none_from_none_fails
test_opinfo_read_to_none_lease_state_update
```

#### Lease Upgrade/Downgrade Tests
```
test_lease_read_to_write_r_to_rw
test_lease_read_to_write_rh_to_rwh
test_lease_read_to_write_no_read_fails
test_lease_read_to_write_opinfo_level_exclusive
test_lease_read_to_write_opinfo_level_batch_with_handle

test_lease_none_upgrade_to_r
test_lease_none_upgrade_to_rw
test_lease_none_upgrade_to_rwh
test_lease_none_upgrade_to_rh
test_lease_none_upgrade_from_non_none_fails
```

#### Response Buffer Construction Tests
```
test_create_lease_buf_v1_rwh
test_create_lease_buf_v1_r
test_create_lease_buf_v2_rwh
test_create_lease_buf_v2_with_parent_key
test_create_lease_buf_v2_epoch_increment

test_create_durable_rsp_buf_layout
test_create_durable_v2_rsp_buf_layout
test_create_mxac_rsp_buf_max_access
test_create_mxac_rsp_buf_zero_access
test_create_disk_id_rsp_buf_values
```

#### Oplock Break Timing and Sequencing
```
test_oplock_break_pending_no_contention
test_oplock_break_pending_level_already_lower
test_oplock_break_pending_timeout_behavior
test_oplock_break_ack_wait_timeout_clears_state
test_oplock_break_ack_wait_closing_state

test_smb2_oplock_break_noti_batch_to_level2
test_smb2_oplock_break_noti_level2_to_none
test_smb2_oplock_break_noti_truncate_breaks_to_none
```

#### Lease Break Acknowledgment
```
test_lease_break_ack_rwh_to_rw
test_lease_break_ack_rwh_to_r
test_lease_break_ack_rwh_to_none
test_lease_break_ack_rh_to_r
test_lease_break_ack_rh_to_none
test_lease_break_ack_rw_to_r
test_lease_break_ack_r_to_none
test_lease_break_ack_invalid_state_rejected
```

#### Parent Lease Breaking
```
test_smb_break_parent_dir_lease_triggers_break
test_smb_break_parent_dir_lease_no_lease_noop
test_smb_lazy_parent_lease_break_close_deferred
test_smb_send_parent_lease_break_noti_structure
```

#### Opinfo Lifecycle
```
test_opinfo_get_increments_refcount
test_opinfo_get_null_on_freed
test_opinfo_put_frees_at_zero
test_opinfo_put_null_safe
test_opinfo_count_stream_vs_regular
test_close_id_del_oplock_ack_wait_state
test_close_id_del_oplock_no_opinfo_noop
```

#### Connection Dying During Break
```
test_oplock_break_conn_releasing_skips
test_opinfo_get_list_conn_null_returns_null
test_opinfo_get_list_conn_releasing_returns_null
```

### ksmbd_test_acl.c Enhancements

#### Every SID Type Coverage
```
test_id_to_sid_creator_group
test_id_to_sid_nfs_user
test_id_to_sid_nfs_group
test_id_to_sid_nfs_mode
test_id_to_sid_unknown_type_noop
test_id_to_sid_boundary_uid_zero
test_id_to_sid_boundary_uid_max
test_id_to_sid_subauth_overflow_at_max
```

#### DACL/SACL Combinations
```
test_parse_sec_desc_null_dacl_full_access
test_parse_sec_desc_empty_dacl_no_access
test_parse_sec_desc_single_allow_ace
test_parse_sec_desc_single_deny_ace
test_parse_sec_desc_deny_before_allow
test_parse_sec_desc_allow_before_deny
test_parse_sec_desc_owner_sid_match
test_parse_sec_desc_group_sid_match
test_parse_sec_desc_everyone_sid_match
test_parse_sec_desc_unknown_sid_mapped_to_user
test_parse_sec_desc_sacl_ignored (audit ACEs should not affect mode)
```

#### Empty and NULL DACL
```
test_parse_dacl_null_pointer_full_access
test_parse_dacl_zero_aces_no_access
test_parse_dacl_single_ace_owner_only
test_build_sec_desc_null_dacl_roundtrip
test_build_sec_desc_empty_dacl_roundtrip
```

#### Generic Access Mapping
```
test_access_flags_to_mode_generic_all
test_access_flags_to_mode_generic_read
test_access_flags_to_mode_generic_write
test_access_flags_to_mode_generic_execute
test_access_flags_to_mode_file_read_rights
test_access_flags_to_mode_file_write_rights_dir
test_access_flags_to_mode_denied_inverts
test_mode_to_access_flags_rwx
test_mode_to_access_flags_readonly
test_mode_to_access_flags_writeonly
test_mode_to_access_flags_execonly
test_mode_to_access_flags_zero
```

#### mode_to_access_flags / access_flags_to_mode Round-Trip
```
test_mode_roundtrip_0755
test_mode_roundtrip_0644
test_mode_roundtrip_0700
test_mode_roundtrip_0777
test_mode_roundtrip_0000
```

#### Owner/Group SID Handling
```
test_build_sec_desc_owner_sid_matches_uid
test_build_sec_desc_group_sid_matches_gid
test_parse_sec_desc_owner_sid_sets_uid
test_parse_sec_desc_group_sid_sets_gid
test_sid_to_id_owner_valid
test_sid_to_id_group_valid
test_sid_to_id_too_many_subauth_rejected
test_sid_to_id_zero_subauth_rejected
test_sid_to_id_everyone_sid_rejected
```

#### Inherited ACEs
```
test_smb_inherit_dacl_object_inherit_to_file
test_smb_inherit_dacl_container_inherit_to_dir
test_smb_inherit_dacl_both_inherit_flags
test_smb_inherit_dacl_no_propagate_stops_at_child
test_smb_inherit_dacl_inherit_only_not_applied_to_parent
test_smb_inherit_dacl_creator_owner_replaced
test_smb_inherit_dacl_creator_group_replaced
```

#### ACL State Management
```
test_init_acl_state_count_zero
test_init_acl_state_count_one
test_init_acl_state_count_large
test_posix_state_to_acl_owner_only
test_posix_state_to_acl_owner_group_other
test_posix_state_to_acl_with_users_and_mask
test_posix_state_to_acl_with_groups_and_mask
test_free_acl_state_double_free_safe
```

#### Domain SID Initialization
```
test_ksmbd_init_domain_sets_subauth
test_ksmbd_init_domain_preserves_base
```

#### Permission Check
```
test_smb_check_perm_dacl_read_allowed
test_smb_check_perm_dacl_write_allowed
test_smb_check_perm_dacl_delete_allowed
test_smb_check_perm_dacl_read_denied
test_smb_check_perm_dacl_empty_dacl_denied
test_smb_check_perm_dacl_no_matching_sid
```

#### ACE Size Overflow
```
test_ksmbd_ace_size_normal
test_ksmbd_ace_size_max_subauth
test_ksmbd_ace_size_overflow_returns_zero
```

### ksmbd_test_vfs.c (NEW)

#### Path Resolution
```
test_kern_path_empty_resolves_share_root
test_kern_path_simple_file
test_kern_path_nested_directory
test_kern_path_nonexistent_returns_enoent
test_kern_path_locked_acquires_lock
test_kern_path_locked_releases_on_error
```

#### LOOKUP_BENEATH Enforcement
```
test_path_lookup_dotdot_rejected
test_path_lookup_absolute_rejected
test_path_lookup_symlink_escape_rejected
test_path_lookup_within_share_ok
test_path_lookup_crossmnt_followed
test_path_lookup_crossmnt_not_followed_when_disabled
```

#### File Creation
```
test_vfs_create_regular_file
test_vfs_create_inherits_owner
test_vfs_create_mode_bits
test_vfs_create_existing_fails
test_vfs_mkdir_creates_directory
test_vfs_mkdir_mode_bits
test_vfs_mkdir_nested_path
```

#### Read/Write Operations
```
test_vfs_read_entire_file
test_vfs_read_partial_at_offset
test_vfs_read_beyond_eof_returns_zero
test_vfs_write_creates_data
test_vfs_write_at_offset
test_vfs_write_append_mode
test_vfs_write_extends_file
```

#### Sendfile (Zero-Copy)
```
test_vfs_sendfile_entire_file
test_vfs_sendfile_partial_range
test_vfs_sendfile_zero_length
```

#### Rename Operations
```
test_vfs_rename_simple
test_vfs_rename_cross_directory
test_vfs_rename_overwrite_existing
test_vfs_rename_to_same_name_noop
test_vfs_fp_rename_via_file_pointer
test_vfs_fp_rename_stream_name
```

#### Hard Link
```
test_vfs_link_creates_hard_link
test_vfs_link_same_inode
test_vfs_link_cross_device_fails
```

#### Symlink
```
test_vfs_symlink_creates_link
test_vfs_readlink_returns_target
test_vfs_readlink_nonlink_fails
```

#### Stream Operations
```
test_vfs_xattr_stream_name_formats_correctly
test_vfs_xattr_stream_name_special_chars
test_vfs_casexattr_len_case_insensitive_match
test_vfs_casexattr_len_no_match
```

#### File Attributes
```
test_vfs_getattr_returns_correct_size
test_vfs_getattr_returns_correct_mode
test_vfs_setattr_changes_mode
test_vfs_setattr_changes_size
test_vfs_fill_dentry_attrs_populates_struct
```

#### Timestamps
```
test_vfs_setattr_changes_mtime
test_vfs_setattr_changes_atime
test_vfs_setattr_changes_ctime
test_vfs_setattr_preserves_unset_times
```

#### Allocation Size and Truncation
```
test_vfs_truncate_shrinks_file
test_vfs_truncate_extends_file
test_vfs_truncate_zero_length
test_vfs_zero_data_punches_hole
test_vfs_fqar_lseek_finds_allocated
test_vfs_fqar_lseek_finds_holes
```

#### Xattr Operations
```
test_vfs_setxattr_creates_xattr
test_vfs_getxattr_retrieves_xattr
test_vfs_getxattr_nonexistent_returns_error
test_vfs_remove_xattr_deletes_xattr
test_vfs_listxattr_enumerates_all
test_vfs_copy_xattrs_copies_all
test_vfs_remove_acl_xattrs_cleans_acls
test_vfs_remove_sd_xattrs_cleans_sds
```

#### SD Xattr Round-Trip
```
test_vfs_set_sd_xattr_stores_ntsd
test_vfs_get_sd_xattr_retrieves_ntsd
test_vfs_set_sd_xattr_overwrites
test_vfs_get_sd_xattr_nonexistent
```

#### DOS Attribute Xattr
```
test_vfs_set_dos_attrib_xattr_stores
test_vfs_get_dos_attrib_xattr_retrieves
test_vfs_get_dos_attrib_xattr_nonexistent
```

#### fadvise
```
test_vfs_set_fadvise_sequential
test_vfs_set_fadvise_random
test_vfs_set_fadvise_none
```

#### File Lock Operations
```
test_check_lock_range_valid
test_check_lock_range_beyond_offset_max
test_check_lock_range_overlap_detected
test_vfs_posix_lock_wait_completes
test_vfs_posix_lock_wait_timeout_expires
test_vfs_posix_lock_unblock_wakes_waiter
```

#### File Copy
```
test_vfs_copy_file_ranges_same_file
test_vfs_copy_file_ranges_cross_file
test_vfs_copy_file_ranges_multiple_chunks
test_vfs_copy_file_ranges_src_beyond_eof
test_vfs_copy_file_ranges_zero_length
```

#### File Removal
```
test_vfs_remove_file_regular
test_vfs_remove_file_nonexistent
test_vfs_unlink_file
test_vfs_empty_dir_empty
test_vfs_empty_dir_nonempty
```

#### Maximal Access
```
test_vfs_query_maximal_access_root
test_vfs_query_maximal_access_readonly
test_vfs_query_maximal_access_no_delete_parent
```

#### Post-Open Share Containment
```
test_vfs_path_is_within_share_valid
test_vfs_path_is_within_share_escape
```

#### POSIX ACL Initialization
```
test_vfs_set_init_posix_acl_file
test_vfs_set_init_posix_acl_dir
test_vfs_inherit_posix_acl_from_parent
```

### ksmbd_test_vfs_cache.c (NEW)

#### Inode Hash Operations
```
test_inode_hash_init_creates_buckets
test_inode_hash_mask_is_power_of_two_minus_one
test_inode_lookup_lock_found
test_inode_lookup_lock_not_found
test_inode_lookup_lock_concurrent_insert
test_inode_get_creates_new
test_inode_get_returns_existing
test_inode_get_race_uses_existing
```

#### Delete-On-Close Lifecycle
```
test_fd_set_delete_on_close_file
test_fd_set_delete_on_close_stream
test_inode_close_delete_on_close_last_handle
test_inode_close_delete_on_close_not_last_handle
test_inode_close_delete_on_close_unlink_fails_restores_flag
test_inode_close_delete_pending_last_handle
test_inode_close_stream_delete_on_close_removes_xattr
```

#### Pending Delete States
```
test_set_inode_pending_delete
test_clear_inode_pending_delete
test_inode_pending_delete_only_checks_del_pending
test_inode_pending_delete_ignores_del_on_cls
test_clear_pending_delete_if_only_single_handle
test_clear_pending_delete_if_only_multiple_handles
test_query_inode_status_unknown_for_no_ci
test_query_inode_status_ok_for_normal
test_query_inode_status_pending_delete
```

#### POSIX Flag
```
test_ksmbd_inode_set_posix_sets_flag
```

#### Durable Handle Scavenging
```
test_durable_scavenger_launches
test_durable_scavenger_stops
test_durable_scavenger_timeout_expires_handle
test_durable_scavenger_handle_reopened_before_timeout
```

#### File Descriptor Lifecycle
```
test_ksmbd_close_fd_valid_id
test_ksmbd_close_fd_invalid_id
test_ksmbd_fd_put_decrements_refcount
test_ksmbd_fd_put_null_safe
test_ksmbd_update_fstate_transitions
```

#### Lock Sequence Tracking
```
test_lock_sequence_initial_sentinel_0xff
test_lock_sequence_store_on_success
test_lock_sequence_replay_returns_ok
test_lock_sequence_stale_sequence_rejected
test_lock_sequence_index_boundary_0
test_lock_sequence_index_boundary_64
test_lock_sequence_resilient_handle
test_lock_sequence_persistent_handle
```

#### FD Limit Management
```
test_ksmbd_set_fd_limit_below_max
test_ksmbd_set_fd_limit_above_max_clamped
test_fd_limit_depleted_returns_true
test_fd_limit_close_increments
```

#### File Table Operations
```
test_init_file_table_creates_idr
test_destroy_file_table_cleans_up
test_init_global_file_table
test_free_global_file_table
test_file_table_flush_syncs_all
```

#### Durable Reconnect
```
test_validate_name_reconnect_matching
test_validate_name_reconnect_mismatch
test_reopen_durable_fd_success
test_reopen_durable_fd_expired
```

#### Session/Tree Cleanup
```
test_close_tree_conn_fds_closes_all
test_close_session_fds_closes_all
```

#### Inode Refcount
```
test_ksmbd_inode_put_frees_at_zero
test_ksmbd_inode_put_not_freed_above_zero
```

### ksmbd_test_notify.c (NEW)

#### fsnotify Integration
```
test_notify_init_creates_group
test_notify_exit_destroys_group
test_notify_enabled_returns_true_after_init
test_notify_enabled_returns_false_before_init
```

#### Watch Management
```
test_notify_add_watch_single
test_notify_add_watch_multiple_same_dir
test_notify_add_watch_different_dirs
test_notify_add_watch_piggyback_on_existing_mark
```

#### WATCH_TREE Recursive
```
test_notify_add_watch_tree_flag_set
test_notify_watch_tree_receives_subdir_events
test_notify_watch_non_tree_ignores_subdir_events
```

#### Filter Flags
```
test_notify_filter_file_name_change
test_notify_filter_dir_name_change
test_notify_filter_attributes_change
test_notify_filter_size_change
test_notify_filter_last_write_change
test_notify_filter_security_change
test_notify_filter_creation_change
test_notify_filter_combined_flags
test_notify_filter_no_match_no_delivery
```

#### Completion
```
test_notify_completion_fills_response
test_notify_completion_multiple_changes
test_notify_completion_buffer_size_respected
```

#### Cancel Race
```
test_notify_cancel_pending_watch
test_notify_cancel_already_completed_noop
test_notify_cancel_concurrent_with_event
```

#### Buffer Overflow
```
test_notify_response_truncated_at_max_output_len
test_notify_response_single_entry_fits
test_notify_response_overflow_set_flag
```

#### Max Watch Count
```
test_notify_max_watches_per_connection
test_notify_cleanup_file_removes_all_watches
test_notify_complete_delete_pending_notifies_watchers
```

#### Flush and Cleanup
```
test_notify_cleanup_file_no_watches_noop
test_notify_cleanup_file_with_pending_watches
test_notify_complete_delete_pending_sends_notification
test_notify_exit_cleans_all_watches
```

### ksmbd_test_dfs.c (NEW)

#### DFS Enabled Check
```
test_ksmbd_dfs_enabled_when_feature_on
test_ksmbd_dfs_enabled_when_feature_off
```

#### Referral Version Selection
```
test_dfs_select_referral_version_v4
test_dfs_select_referral_version_v3
test_dfs_select_referral_version_v2
test_dfs_select_referral_version_v1_returns_zero
test_dfs_select_referral_version_zero_returns_zero
```

#### Referral Fixed Sizes
```
test_dfs_referral_fixed_size_v2
test_dfs_referral_fixed_size_v3
test_dfs_referral_fixed_size_v4
```

#### UTF-16 Name Length
```
test_dfs_utf16_name_len_normal
test_dfs_utf16_name_len_empty
test_dfs_utf16_name_len_no_null_terminator
test_dfs_utf16_name_len_max_len_too_small
```

#### Path Component Extraction
```
test_dfs_next_component_single
test_dfs_next_component_multiple
test_dfs_next_component_leading_separators
test_dfs_next_component_empty
test_dfs_next_component_mixed_separators
```

#### Network Address Building
```
test_dfs_build_network_address_server_share
test_dfs_build_network_address_server_only_fallback
test_dfs_build_network_address_empty_fallback
```

#### GET_REFERRALS FSCTL
```
test_dfs_get_referrals_too_short_rejected
test_dfs_get_referrals_valid_v3
test_dfs_get_referrals_valid_v4
test_dfs_get_referrals_output_too_small
```

#### GET_REFERRALS_EX FSCTL
```
test_dfs_get_referrals_ex_too_short_rejected
test_dfs_get_referrals_ex_zero_data_length_rejected
test_dfs_get_referrals_ex_valid
```

### ksmbd_test_branchcache.c (NEW)

#### Secret Generation
```
test_branchcache_generate_secret_nonzero
test_branchcache_generate_secret_changes_on_regen
test_branchcache_generate_secret_records_timestamp
```

#### Read Hash Validation
```
test_branchcache_read_hash_input_too_small
test_branchcache_read_hash_invalid_hash_type
test_branchcache_read_hash_invalid_hash_version
test_branchcache_read_hash_invalid_retrieval_type
test_branchcache_read_hash_offset_beyond_eof
test_branchcache_read_hash_zero_length
test_branchcache_read_hash_clamps_to_file_size
```

#### Content Info V1 Structure
```
test_branchcache_content_info_v1_header
test_branchcache_content_info_v1_single_segment
test_branchcache_content_info_v1_multiple_segments
test_branchcache_content_info_v1_partial_last_segment
test_branchcache_content_info_v1_output_too_small
```

#### Segment Hash Computation
```
test_branchcache_segment_hash_deterministic
test_branchcache_segment_hash_different_data
test_branchcache_segment_secret_uses_server_key
```

#### Xattr Cache
```
test_branchcache_cache_stores_hashes
test_branchcache_cache_hit_on_second_request
test_branchcache_cache_miss_on_mtime_change
test_branchcache_cache_miss_on_size_change
test_branchcache_cache_miss_on_offset_change
test_branchcache_invalidate_removes_cache
test_branchcache_invalidate_null_fp_safe
```

### ksmbd_test_quota.c (NEW)

#### SID to UID Mapping
```
test_sid_to_uid_single_subauth
test_sid_to_uid_multiple_subauth_uses_last
test_sid_to_uid_zero_subauth_rejected
test_sid_to_uid_too_many_subauth_rejected
test_sid_to_uid_buffer_too_small_rejected
```

#### Quota Query (requires CONFIG_QUOTA)
```
test_quota_query_no_file_pointer_rejected
test_quota_query_quotas_not_active_empty
test_quota_query_input_too_small_empty
test_quota_query_sid_list_single_entry
test_quota_query_sid_list_multiple_entries
test_quota_query_sid_list_unmappable_sid_skipped
test_quota_query_return_single_flag
test_quota_query_start_sid_based
test_quota_query_overflow_input_buffer
test_quota_query_output_buffer_overflow
```

#### Quota Fill Entry
```
test_fill_quota_info_normal
test_fill_quota_info_buffer_too_small
test_fill_quota_info_invalid_qid
test_fill_quota_info_dquot_failure_returns_zeros
test_fill_quota_info_entry_alignment
```

### ksmbd_test_resilient.c (NEW)

#### FSCTL Request Resiliency
```
test_resilient_input_too_short_rejected
test_resilient_file_not_found_rejected
test_resilient_normal_timeout
test_resilient_timeout_capped_to_max
test_resilient_zero_timeout
test_resilient_sets_is_resilient_flag
test_resilient_sets_timeout_value
test_resilient_no_output_data
```

#### Init/Exit
```
test_resilient_init_registers_handler
test_resilient_exit_unregisters_handler
```

### ksmbd_test_app_instance.c (NEW)

#### APP_INSTANCE_ID Parsing
```
test_app_instance_id_valid
test_app_instance_id_too_short_rejected
test_app_instance_id_zero_guid_ignored
test_app_instance_id_sets_flag_and_guid
```

#### APP_INSTANCE_VERSION Parsing
```
test_app_instance_version_valid
test_app_instance_version_too_short_rejected
test_app_instance_version_sets_high_and_low
test_app_instance_version_sets_flag
```

#### Previous Instance Closure
```
test_close_previous_same_instance_id
test_close_previous_different_instance_id_no_close
test_close_previous_version_higher_closes
test_close_previous_version_lower_does_not_close
test_close_previous_version_equal_does_not_close
test_close_previous_no_version_context_unconditional
test_close_previous_no_matching_handle_noop
```

#### Version Comparison Semantics
```
test_version_high_dominates
test_version_low_breaks_tie
test_version_both_equal_no_close
test_version_high_greater_low_less_closes
```

---

## Edge Cases & Security Tests

### Path Traversal
```
test_path_traversal_dotdot_in_middle
test_path_traversal_dotdot_at_start
test_path_traversal_encoded_dotdot
test_path_traversal_backslash_dotdot
test_path_traversal_double_slash_collapse
test_path_traversal_null_byte_in_path
test_path_traversal_very_long_path
test_path_traversal_unicode_normalization
```

### Symlink Attacks
```
test_symlink_escape_share_boundary
test_symlink_race_create_replace
test_symlink_to_proc_rejected
test_symlink_to_dev_rejected
test_symlink_circular_rejected
test_reparse_symlink_target_escape
test_reparse_mount_point_target_escape
test_reparse_symlink_target_with_backslash
```

### Race Conditions
```
test_concurrent_open_same_file
test_concurrent_close_same_file
test_concurrent_delete_on_close_two_handles
test_concurrent_rename_same_file
test_concurrent_oplock_break_and_close
test_concurrent_lease_break_and_ack
test_concurrent_delete_pending_and_new_open
test_concurrent_inode_get_same_dentry
test_concurrent_fd_limit_depletion
test_concurrent_notify_add_and_cancel
test_concurrent_durable_scavenge_and_reconnect
```

### Concurrent Open/Close/Delete
```
test_open_during_delete_pending_returns_status
test_open_during_delete_on_close_allowed
test_close_last_handle_triggers_delete
test_close_not_last_handle_no_delete
test_delete_on_close_readonly_file_rejected
test_delete_on_close_nonempty_dir_deferred
test_multiple_handles_delete_on_close_last_wins
```

### Buffer Overflow / Underflow
```
test_acl_buffer_overflow_capped
test_ace_count_exceeds_buffer_rejected
test_ace_size_larger_than_buffer
test_parse_sec_desc_truncated_buffer
test_build_sec_desc_insufficient_buffer
test_notify_response_buffer_exactly_fits
test_notify_response_buffer_one_byte_short
test_reparse_data_length_exceeds_buffer
test_dfs_referral_output_buffer_boundary
```

### Integer Overflow
```
test_ace_size_overflow_check_returns_zero
test_init_acl_state_alloc_overflow
test_lock_range_start_plus_length_overflows
test_vfs_fqar_offset_plus_length_overflows
test_copy_file_ranges_chunk_count_overflow
test_branchcache_segment_count_overflow
test_quota_entry_size_alignment_overflow
```

### Refcount Saturation
```
test_opinfo_refcount_saturated_returns_null
test_conn_refcount_saturated_alloc_opinfo_fails
test_inode_refcount_saturated_lookup_fails
```

---

## Fuzz Targets

### ACL Fuzzing
```
fuzz_parse_sec_desc
  - Input: arbitrary byte buffer as smb_ntsd
  - Goal: no kernel panics, no OOB reads, correct error returns
  - Bounds: vary total buffer length from 0 to 64KB
  - Mutations: corrupt revision, offset fields, ACE counts, SID sub_auth counts

fuzz_build_sec_desc
  - Input: random smb_fattr with varied uid/gid/mode
  - Goal: produced buffer is parseable by parse_sec_desc

fuzz_compare_sids
  - Input: two random smb_sid structures
  - Goal: no crashes, consistent results (commutative for equality)
```

### Oplock/Lease Fuzzing
```
fuzz_smb2_map_lease_to_oplock
  - Input: all 32-bit __le32 values
  - Goal: no crashes, return value in valid oplock level set

fuzz_create_lease_buf
  - Input: random lease struct with varied state/flags/epoch
  - Goal: well-formed output buffer, no OOB writes

fuzz_lease_break_ack
  - Input: random lease state transitions
  - Goal: all transitions either succeed or return -EINVAL
```

### VFS Path Fuzzing
```
fuzz_ksmbd_vfs_kern_path
  - Input: random UTF-8 strings as filepath
  - Goal: no path escapes, proper EINVAL/ENOENT, no OOPS

fuzz_ksmbd_vfs_kern_path_locked
  - Input: random paths with lock/unlock sequences
  - Goal: lock always balanced, no deadlocks
```

### Reparse Point Fuzzing
```
fuzz_fsctl_set_reparse_point
  - Input: random reparse data buffers
  - Goal: no crashes, proper STATUS codes, no symlink escapes

fuzz_fsctl_get_reparse_point
  - Input: files with random xattr contents
  - Goal: no OOB reads from corrupted xattr data

fuzz_reparse_target_safety
  - Input: random path strings
  - Goal: all unsafe paths rejected, no false positives for safe relative paths
```

### Notify Fuzzing
```
fuzz_notify_add_watch
  - Input: random filter flags, random watch_tree combinations
  - Goal: no null derefs, marks properly cleaned up

fuzz_notify_event_delivery
  - Input: rapid file creation/deletion while watches active
  - Goal: no use-after-free, no double-complete
```

### DFS Referral Fuzzing
```
fuzz_dfs_get_referrals
  - Input: random UTF-16 request path, random max_referral_level
  - Goal: well-formed response or proper error, no buffer overruns

fuzz_dfs_utf16_name_len
  - Input: random byte buffers as UTF-16 names
  - Goal: never reads past max_len boundary
```

### Quota Fuzzing
```
fuzz_quota_query
  - Input: random smb2_query_quota_info with random SID lists
  - Goal: no OOB reads, proper bounds checking on SID parsing

fuzz_sid_to_uid
  - Input: random SIDs with varied sub_auth counts and buffer sizes
  - Goal: consistent rejection of malformed SIDs
```

### BranchCache Fuzzing
```
fuzz_branchcache_read_hash
  - Input: random srv_read_hash_req with varied offsets/lengths
  - Goal: no reads past file boundary, no allocation overflows

fuzz_branchcache_cache_xattr
  - Input: corrupt xattr contents for pccrc cache
  - Goal: cache miss returned, no crashes on corrupted headers
```

---

## Implementation Priority

### Phase 1: Pure-Logic Unit Tests (no kernel state required)
1. **ksmbd_test_oplock.c enhancements** -- oplock state transitions (can test with mock opinfo structs)
2. **ksmbd_test_acl.c enhancements** -- access_flags_to_mode, mode_to_access_flags, round-trips, ACE size, all SID types
3. **ksmbd_test_dfs.c** -- referral version selection, fixed sizes, UTF-16 name length, path components

### Phase 2: State-Machine Tests (need mock infrastructure)
4. **ksmbd_test_vfs_cache.c** -- delete-on-close lifecycle, pending delete, FD limit, inode hash
5. **ksmbd_test_notify.c** -- watch management, filter flags, cancel race
6. **ksmbd_test_app_instance.c** -- GUID parsing, version comparison, closure logic

### Phase 3: Integration Tests (need filesystem + kernel infrastructure)
7. **ksmbd_test_vfs.c** -- path resolution, LOOKUP_BENEATH, file operations
8. **ksmbd_test_branchcache.c** -- hash computation, xattr caching
9. **ksmbd_test_quota.c** -- SID-to-UID mapping, quota fill
10. **ksmbd_test_resilient.c** -- timeout, flag management

### Phase 4: Fuzz Targets
11. ACL fuzz targets (parse_sec_desc, build_sec_desc)
12. VFS path fuzz targets
13. Reparse point fuzz targets
14. DFS referral fuzz targets
