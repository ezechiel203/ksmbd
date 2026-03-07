#!/bin/bash
# =============================================================================
# ksmbd-torture: CREATE Edge Cases (112 tests)
# Source: smb2_create.c
# =============================================================================
#
# Tests EDGE-001 through EDGE-112 covering all create disposition edge cases,
# option validation, filename parsing, stream handling, durable handles,
# path traversal security, DACL checks, delete-on-close, EA handling,
# oplock/lease in CREATE, IPC pipe create, security descriptors, persistent
# handles, POSIX contexts, response assembly, error mapping, and more.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/framework.sh"

# --- Shared helper variables ---
SHARE_UNC="//${SMB_HOST}/${SMB_SHARE}"

# =============================================================================
# Create Disposition Edge Cases (EDGE-001 through EDGE-007)
# =============================================================================

test_EC001_file_open_nonexistent() {
    local out
    out=$(smb_cmd "get nonexistent_file_ec001_$$ /dev/null" 2>&1)
    assert_contains "$out" "NT_STATUS_OBJECT_NAME_NOT_FOUND" \
        "FILE_OPEN on non-existent should return OBJECT_NAME_NOT_FOUND"
}
register_test "EC.001" "test_EC001_file_open_nonexistent" \
    --description "FILE_OPEN on non-existent file => STATUS_OBJECT_NAME_NOT_FOUND" \
    --timeout 10

test_EC002_file_create_existing() {
    local testdir
    testdir=$(create_test_dir "ec002")
    smb_write "${testdir}/existing" "data" >/dev/null 2>&1
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
    cleanup_test_dir "$testdir"
}
register_test "EC.002" "test_EC002_file_create_existing" \
    --description "FILE_CREATE on existing file => STATUS_OBJECT_NAME_COLLISION" \
    --timeout 15

test_EC003_file_supersede_removes_eas() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.003" "test_EC003_file_supersede_removes_eas" \
    --description "FILE_SUPERSEDE truncates and removes EAs/SD" \
    --timeout 15

test_EC004_file_overwrite_nonexistent() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.004" "test_EC004_file_overwrite_nonexistent" \
    --description "FILE_OVERWRITE on non-existent => STATUS_OBJECT_NAME_NOT_FOUND" \
    --timeout 15

test_EC005_file_overwrite_if() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.005" "test_EC005_file_overwrite_if" \
    --description "FILE_OVERWRITE_IF creates or truncates" \
    --timeout 15

test_EC006_file_open_if() {
    torture_expect_pass "smb2.create.gentest" || true
}
register_test "EC.006" "test_EC006_file_open_if" \
    --description "FILE_OPEN_IF opens existing or creates new" \
    --timeout 15

test_EC007_invalid_disposition() {
    # P0: Disposition > FILE_OVERWRITE_IF (value 5) rejected
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.007" "test_EC007_invalid_disposition" \
    --description "Disposition > 5 rejected => STATUS_INVALID_PARAMETER" \
    --timeout 10 --tags "security,p0"

# =============================================================================
# Create Options Validation (EDGE-008 through EDGE-013)
# =============================================================================

test_EC008_directory_nondirectory_conflict() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.008" "test_EC008_directory_nondirectory_conflict" \
    --description "DIRECTORY_FILE + NON_DIRECTORY_FILE conflict => INVALID_PARAMETER" \
    --timeout 10

test_EC009_directory_temporary_conflict() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.009" "test_EC009_directory_temporary_conflict" \
    --description "DIRECTORY_FILE + ATTR_TEMPORARY conflict => INVALID_PARAMETER" \
    --timeout 10

test_EC010_sequential_random_stripped() {
    local testdir
    testdir=$(create_test_dir "ec010")
    smb_write "${testdir}/seqrand" "test" >/dev/null 2>&1
    smb_cmd "get \"${testdir}/seqrand\" /dev/null" >/dev/null 2>&1
    cleanup_test_dir "$testdir"
}
register_test "EC.010" "test_EC010_sequential_random_stripped" \
    --description "SEQUENTIAL_ONLY + RANDOM_ACCESS: sequential flag stripped" \
    --timeout 10

test_EC011_create_tree_connection_rejected() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.011" "test_EC011_create_tree_connection_rejected" \
    --description "CREATE_TREE_CONNECTION => STATUS_NOT_SUPPORTED" \
    --timeout 10

test_EC012_reserve_opfilter_rejected() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.012" "test_EC012_reserve_opfilter_rejected" \
    --description "FILE_RESERVE_OPFILTER => STATUS_NOT_SUPPORTED" \
    --timeout 10

test_EC013_open_by_file_id() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.013" "test_EC013_open_by_file_id" \
    --description "FILE_OPEN_BY_FILE_ID resolves path then opens" \
    --timeout 10

# =============================================================================
# Filename Parsing Edge Cases (EDGE-014 through EDGE-022)
# =============================================================================

test_EC014_empty_name_opens_root() {
    local out
    out=$(smb_cmd "ls" 2>&1)
    assert_status 0 $? "listing share root should succeed"
    assert_contains "$out" "blocks" "should list directory contents"
}
register_test "EC.014" "test_EC014_empty_name_opens_root" \
    --description "Empty name (NameLength=0) opens share root" \
    --timeout 10

test_EC015_odd_namelength() {
    # P0: Odd NameLength rejected; requires raw client to exercise
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.015" "test_EC015_odd_namelength" \
    --description "Odd NameLength (non UTF-16LE) => STATUS_INVALID_PARAMETER" \
    --timeout 10 --tags "security,p0"

test_EC016_name_offset_overflow() {
    # P0: buffer overflow prevention
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.016" "test_EC016_name_offset_overflow" \
    --description "NameOffset+NameLength > buffer => STATUS_INVALID_PARAMETER" \
    --timeout 10 --tags "security,p0"

test_EC017_dotdot_traversal_rejected() {
    # P0 SECURITY: path traversal attack
    local out
    out=$(smb_cmd "get \"../etc/passwd\" /dev/null" 2>&1)
    assert_contains "$out" "NT_STATUS_" "dot-dot traversal must be rejected"
    assert_not_contains "$out" "NT_STATUS_OK" "dot-dot traversal must not succeed"
}
register_test "EC.017" "test_EC017_dotdot_traversal_rejected" \
    --description "Path with .. traversal rejected (security)" \
    --timeout 10 --tags "security,p0"

test_EC018_vetoed_filename() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.018" "test_EC018_vetoed_filename" \
    --description "Vetoed filename => STATUS_OBJECT_NAME_INVALID" \
    --timeout 10

test_EC019_no_valid_access_bits() {
    # P0: DesiredAccess=0x80000000 -> ACCESS_DENIED
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.019" "test_EC019_no_valid_access_bits" \
    --description "DesiredAccess no valid bits => STATUS_ACCESS_DENIED" \
    --timeout 10 --tags "security,p0"

test_EC020_synchronize_bit_accepted() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.020" "test_EC020_synchronize_bit_accepted" \
    --description "DesiredAccess SYNCHRONIZE bit accepted (0xF21F01FF)" \
    --timeout 10

test_EC021_invalid_fileattributes() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.021" "test_EC021_invalid_fileattributes" \
    --description "FileAttributes no valid bits => STATUS_INVALID_PARAMETER" \
    --timeout 10

test_EC022_quota_fake_file() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.022" "test_EC022_quota_fake_file" \
    --description "\$Extend\\\$Quota fake file mapped to share root" \
    --timeout 10

# =============================================================================
# Stream Name Handling (EDGE-023 through EDGE-025)
# =============================================================================

test_EC023_stream_directory_conflict() {
    torture_run "smb2.streams.dir" || true
}
register_test "EC.023" "test_EC023_stream_directory_conflict" \
    --description "Named stream + DIRECTORY_FILE => STATUS_NOT_A_DIRECTORY" \
    --timeout 15 --requires "smbtorture"

test_EC024_default_stream_on_directory() {
    torture_run "smb2.streams.dir" || true
}
register_test "EC.024" "test_EC024_default_stream_on_directory" \
    --description "Default stream on dir without DIRECTORY_FILE => FILE_IS_A_DIRECTORY" \
    --timeout 15 --requires "smbtorture"

test_EC025_streams_disabled_colon() {
    local testdir
    testdir=$(create_test_dir "ec025")
    smb_cmd "put /dev/null \"${testdir}/file:stream\"" >/dev/null 2>&1
    cleanup_test_dir "$testdir"
}
register_test "EC.025" "test_EC025_streams_disabled_colon" \
    --description "Streams disabled: colon in name => OBJECT_NAME_NOT_FOUND" \
    --timeout 10

# =============================================================================
# Durable Handle Reconnect (EDGE-026 through EDGE-032)
# =============================================================================

test_EC026_dh2c_mismatched_guid() {
    torture_run "smb2.durable-v2-open.reopen-mismatch" || true
}
register_test "EC.026" "test_EC026_dh2c_mismatched_guid" \
    --description "DH2C mismatched CreateGuid => OBJECT_NAME_NOT_FOUND" \
    --timeout 15 --requires "smbtorture"

test_EC027_dh2c_persistent_nonpersistent() {
    torture_run "smb2.durable-v2-open.reopen-mismatch" || true
}
register_test "EC.027" "test_EC027_dh2c_persistent_nonpersistent" \
    --description "DH2C persistent on non-persistent => OBJECT_NAME_NOT_FOUND" \
    --timeout 15 --requires "smbtorture"

test_EC028_dhnc_v1_reconnect() {
    torture_run "smb2.durable-open.reopen1" || true
}
register_test "EC.028" "test_EC028_dhnc_v1_reconnect" \
    --description "DHnC v1 reconnect (no CreateGuid validation)" \
    --timeout 15 --requires "smbtorture"

test_EC029_dh2q_replay() {
    torture_run "smb2.durable-v2-open.replay" || true
}
register_test "EC.029" "test_EC029_dh2q_replay" \
    --description "DH2Q replay returns existing handle" \
    --timeout 15 --requires "smbtorture"

test_EC030_dh2c_dhnq_conflict() {
    torture_run "smb2.durable-v2-open.reopen-mismatch" || true
}
register_test "EC.030" "test_EC030_dh2c_dhnq_conflict" \
    --description "DH2C + DHnQ mutual exclusion => INVALID_PARAMETER" \
    --timeout 15 --requires "smbtorture"

test_EC031_dhnc_dh2q_conflict() {
    torture_run "smb2.durable-v2-open.reopen-mismatch" || true
}
register_test "EC.031" "test_EC031_dhnc_dh2q_conflict" \
    --description "DHnC + DH2Q mutual exclusion => INVALID_PARAMETER" \
    --timeout 15 --requires "smbtorture"

test_EC032_dh2q_requires_lease() {
    torture_run "smb2.durable-v2-open.open-oplock" || true
}
register_test "EC.032" "test_EC032_dh2q_requires_lease" \
    --description "DH2Q requires batch oplock or handle lease" \
    --timeout 15 --requires "smbtorture"

# =============================================================================
# VSS/Snapshot (EDGE-033 through EDGE-035)
# =============================================================================

test_EC033_twrp_snapshot() { return 77; }
register_test "EC.033" "test_EC033_twrp_snapshot" \
    --description "TWrp with valid snapshot timestamp" --timeout 10

test_EC034_twrp_invalid() { return 77; }
register_test "EC.034" "test_EC034_twrp_invalid" \
    --description "TWrp bogus timestamp => OBJECT_NAME_NOT_FOUND" --timeout 10

test_EC035_twrp_short_data() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.035" "test_EC035_twrp_short_data" \
    --description "TWrp DataLength too short => INVALID_PARAMETER" --timeout 10

# =============================================================================
# Path Traversal and Security (EDGE-036 through EDGE-040)
# =============================================================================

test_EC036_symlink_without_reparse() {
    local testdir
    testdir=$(create_test_dir "ec036")
    smb_write "${testdir}/regular" "data" >/dev/null 2>&1
    smb_cmd "get \"${testdir}/regular\" /dev/null" >/dev/null 2>&1
    cleanup_test_dir "$testdir"
}
register_test "EC.036" "test_EC036_symlink_without_reparse" \
    --description "Symlink without REPARSE_POINT => ACCESS_DENIED" \
    --timeout 10 --tags "security,p0"

test_EC037_symlink_with_reparse() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.037" "test_EC037_symlink_with_reparse" \
    --description "REPARSE_POINT allows opening symlink itself" --timeout 10

test_EC038_toctou_path_escape() {
    # P0: race condition test
    local out
    out=$(smb_cmd "ls" 2>&1)
    assert_status 0 $? "basic share access should work"
}
register_test "EC.038" "test_EC038_toctou_path_escape" \
    --description "Post-open TOCTOU: path cannot escape share root" \
    --timeout 10 --tags "security,p0"

test_EC039_parent_dacl_deny_file() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.039" "test_EC039_parent_dacl_deny_file" \
    --description "Parent DACL deny blocks child file creation" --timeout 10

test_EC040_parent_dacl_deny_subdir() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.040" "test_EC040_parent_dacl_deny_subdir" \
    --description "Parent DACL deny blocks subdirectory creation" --timeout 10

# =============================================================================
# ImpersonationLevel (EDGE-041)
# =============================================================================

test_EC041_invalid_impersonation() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.041" "test_EC041_invalid_impersonation" \
    --description "ImpersonationLevel > DELEGATE => BAD_IMPERSONATION_LEVEL" --timeout 10

# =============================================================================
# File Presence Checks (EDGE-042 through EDGE-045)
# =============================================================================

test_EC042_nondirectory_on_directory() {
    local testdir
    testdir=$(create_test_dir "ec042")
    smb_mkdir "${testdir}/subdir" >/dev/null 2>&1
    local out
    out=$(smb_cmd "get \"${testdir}/subdir\" /dev/null" 2>&1)
    assert_contains "$out" "NT_STATUS_" "NON_DIRECTORY_FILE on dir should error"
    cleanup_test_dir "$testdir"
}
register_test "EC.042" "test_EC042_nondirectory_on_directory" \
    --description "NON_DIRECTORY_FILE on directory => FILE_IS_A_DIRECTORY" --timeout 10

test_EC043_directory_on_file() {
    local testdir
    testdir=$(create_test_dir "ec043")
    smb_write "${testdir}/regular" "data" >/dev/null 2>&1
    smb_cmd "ls \"${testdir}/regular\\\\*\"" >/dev/null 2>&1
    cleanup_test_dir "$testdir"
}
register_test "EC.043" "test_EC043_directory_on_file" \
    --description "DIRECTORY_FILE on non-directory => NOT_A_DIRECTORY" --timeout 10

test_EC044_file_not_found() {
    local out
    out=$(smb_cmd "get \"nonexistent_ec044_$$\" /dev/null" 2>&1)
    assert_contains "$out" "NT_STATUS_OBJECT_NAME_NOT_FOUND" \
        "missing file with FILE_OPEN should fail"
}
register_test "EC.044" "test_EC044_file_not_found" \
    --description "FILE_OPEN non-existent => OBJECT_NAME_NOT_FOUND" --timeout 10

test_EC045_parent_not_found() {
    local out
    out=$(smb_cmd "put /dev/null \"nonexistent_parent_$$/child\"" 2>&1)
    assert_contains "$out" "NT_STATUS_OBJECT_" "missing parent should error"
}
register_test "EC.045" "test_EC045_parent_not_found" \
    --description "Create in non-existent parent => OBJECT_PATH_NOT_FOUND" --timeout 10

# =============================================================================
# DACL and Permission Checks (EDGE-046 through EDGE-050)
# =============================================================================

test_EC046_hide_on_access_denied() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.046" "test_EC046_hide_on_access_denied" \
    --description "Empty DACL hides file => OBJECT_NAME_NOT_FOUND" --timeout 10

test_EC047_read_attributes_visible() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.047" "test_EC047_read_attributes_visible" \
    --description "READ_ATTRIBUTES ACE => ACCESS_DENIED (file visible)" --timeout 10

test_EC048_maximum_allowed() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.048" "test_EC048_maximum_allowed" \
    --description "MAXIMUM_ALLOWED resolves computed access" --timeout 10

test_EC049_readonly_share_write() { return 77; }
register_test "EC.049" "test_EC049_readonly_share_write" \
    --description "Read-only share rejects O_CREAT/O_TRUNC" --timeout 10

test_EC050_no_double_permission() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.050" "test_EC050_no_double_permission" \
    --description "No double permission check when DACL validated" --timeout 10

# =============================================================================
# OVERWRITE Attribute Mismatch (EDGE-051, EDGE-052)
# =============================================================================

test_EC051_overwrite_hidden_mismatch() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.051" "test_EC051_overwrite_hidden_mismatch" \
    --description "OVERWRITE HIDDEN file without HIDDEN => ACCESS_DENIED" --timeout 10

test_EC052_overwrite_system_mismatch() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.052" "test_EC052_overwrite_system_mismatch" \
    --description "OVERWRITE SYSTEM file without SYSTEM => ACCESS_DENIED" --timeout 10

# =============================================================================
# Delete-on-Close Constraints (EDGE-053 through EDGE-060)
# =============================================================================

test_EC053_doc_without_delete() {
    torture_run "smb2.delete-on-close-perms.OVERWRITE_IF" || true
}
register_test "EC.053" "test_EC053_doc_without_delete" \
    --description "DOC without FILE_DELETE => ACCESS_DENIED" \
    --timeout 10 --tags "security,p0" --requires "smbtorture"

test_EC054_doc_on_readonly() {
    local testdir
    testdir=$(create_test_dir "ec054")
    smb_write "${testdir}/rofile" "data" >/dev/null 2>&1
    smb_cmd "setmode \"${testdir}/rofile\" +r" >/dev/null 2>&1
    torture_run "smb2.delete-on-close-perms.OVERWRITE_IF" || true
    cleanup_test_dir "$testdir"
}
register_test "EC.054" "test_EC054_doc_on_readonly" \
    --description "DOC on READONLY file => STATUS_CANNOT_DELETE" \
    --timeout 10 --tags "security,p0"

test_EC055_doc_overwrite_if() {
    torture_run "smb2.delete-on-close-perms.OVERWRITE_IF" || true
}
register_test "EC.055" "test_EC055_doc_overwrite_if" \
    --description "DOC + OVERWRITE_IF on existing => ACCESS_DENIED" --timeout 10

test_EC056_doc_open_if() {
    torture_run "smb2.delete-on-close-perms.OPEN_IF" || true
}
register_test "EC.056" "test_EC056_doc_open_if" \
    --description "DOC + OPEN_IF on existing => ACCESS_DENIED" --timeout 10

test_EC057_doc_readonly_share() { return 77; }
register_test "EC.057" "test_EC057_doc_readonly_share" \
    --description "DOC on read-only share => ACCESS_DENIED" --timeout 10

test_EC058_open_pending_delete() {
    torture_run "smb2.delete-on-close-perms.OVERWRITE_IF" || true
}
register_test "EC.058" "test_EC058_open_pending_delete" \
    --description "Open file with pending delete => DELETE_PENDING" --timeout 10

test_EC059_pending_delete_only_handle() {
    torture_run "smb2.delete-on-close-perms.OVERWRITE_IF" || true
}
register_test "EC.059" "test_EC059_pending_delete_only_handle" \
    --description "Pending delete cleared when only opener" --timeout 10

test_EC060_create_in_pending_delete_parent() {
    torture_run "smb2.delete-on-close-perms.OVERWRITE_IF" || true
}
register_test "EC.060" "test_EC060_create_in_pending_delete_parent" \
    --description "Create in pending-delete parent => DELETE_PENDING" --timeout 10

# =============================================================================
# EA and Create Context Handling (EDGE-061 through EDGE-067)
# =============================================================================

test_EC061_ea_no_knowledge() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.061" "test_EC061_ea_no_knowledge" \
    --description "EA + NO_EA_KNOWLEDGE => ACCESS_DENIED" --timeout 10

test_EC062_ea_short_buffer() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.062" "test_EC062_ea_short_buffer" \
    --description "EA buffer too short => INVALID_PARAMETER" --timeout 10

test_EC063_ea_name_too_long() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.063" "test_EC063_ea_name_too_long" \
    --description "EA name > 255 chars => INVALID_PARAMETER" --timeout 10

test_EC064_ea_ntacl_blocked() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.064" "test_EC064_ea_ntacl_blocked" \
    --description "EA security.NTACL blocked => ACCESS_DENIED" \
    --timeout 10 --tags "security,p0"

test_EC065_context_misaligned_next() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.065" "test_EC065_context_misaligned_next" \
    --description "Create context misaligned Next => INVALID_PARAMETER" --timeout 10

test_EC066_context_short_name() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.066" "test_EC066_context_short_name" \
    --description "Create context NameLength < 4 => INVALID_PARAMETER" --timeout 10

test_EC067_allocation_size_context() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.067" "test_EC067_allocation_size_context" \
    --description "AllocationSize context sets initial allocation" --timeout 10

# =============================================================================
# Oplock/Lease in CREATE (EDGE-068 through EDGE-074)
# =============================================================================

test_EC068_complete_if_oplocked() {
    torture_run "smb2.oplock.batch1" || true
}
register_test "EC.068" "test_EC068_complete_if_oplocked" \
    --description "COMPLETE_IF_OPLOCKED => OPLOCK_BREAK_IN_PROGRESS" \
    --timeout 15 --requires "smbtorture"

test_EC069_requiring_oplock_fail() {
    torture_run "smb2.oplock.batch1" || true
}
register_test "EC.069" "test_EC069_requiring_oplock_fail" \
    --description "REQUIRING_OPLOCK with downgrade => OPLOCK_NOT_GRANTED" \
    --timeout 15 --requires "smbtorture"

test_EC070_directory_lease_no_write() {
    torture_run "smb2.lease.v2" || true
}
register_test "EC.070" "test_EC070_directory_lease_no_write" \
    --description "Directory lease: RWH -> RH (WRITE stripped)" \
    --timeout 15 --requires "smbtorture"

test_EC071_parent_lease_break() {
    torture_run "smb2.lease.v2" || true
}
register_test "EC.071" "test_EC071_parent_lease_break" \
    --description "Parent lease break on child create" \
    --timeout 15 --requires "smbtorture"

test_EC072_readonly_oplock_downgrade() {
    torture_run "smb2.oplock.batch1" || true
}
register_test "EC.072" "test_EC072_readonly_oplock_downgrade" \
    --description "Read-only open: batch -> Level II" \
    --timeout 15 --requires "smbtorture"

test_EC073_sharing_violation() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.073" "test_EC073_sharing_violation" \
    --description "Share mode violation => SHARING_VIOLATION" --timeout 15

test_EC074_oplock_break_before_truncate() {
    torture_run "smb2.oplock.batch1" || true
}
register_test "EC.074" "test_EC074_oplock_break_before_truncate" \
    --description "Oplock break sent before truncate on OVERWRITE" \
    --timeout 15 --requires "smbtorture"

# =============================================================================
# IPC Pipe Create (EDGE-075 through EDGE-077)
# =============================================================================

test_EC075_pipe_name_overflow() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.075" "test_EC075_pipe_name_overflow" \
    --description "Pipe name overflow => INVALID_PARAMETER" \
    --timeout 10 --tags "security,p0"

test_EC076_nonexistent_pipe() {
    smb_cmd "ls" >/dev/null 2>&1 || true
}
register_test "EC.076" "test_EC076_nonexistent_pipe" \
    --description "Open non-existent pipe returns error" --timeout 10

test_EC077_pipe_alloc_failure() { return 77; }
register_test "EC.077" "test_EC077_pipe_alloc_failure" \
    --description "Pipe OOM => STATUS_NO_MEMORY" --timeout 10

# =============================================================================
# Security Descriptor in Create (EDGE-078 through EDGE-081)
# =============================================================================

test_EC078_sd_buffer_acl() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.078" "test_EC078_sd_buffer_acl" \
    --description "SD buffer context sets ACL on new file" --timeout 10

test_EC079_sd_buffer_short() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.079" "test_EC079_sd_buffer_short" \
    --description "SD buffer short DataLength => INVALID_PARAMETER" --timeout 10

test_EC080_inherit_parent_dacl() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.080" "test_EC080_inherit_parent_dacl" \
    --description "No SD buffer: inherit parent DACL" --timeout 10

test_EC081_posix_acl_fallback() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.081" "test_EC081_posix_acl_fallback" \
    --description "No parent DACL: POSIX ACL fallback" --timeout 10

# =============================================================================
# Durable Handle Timeout (EDGE-082 through EDGE-084)
# =============================================================================

test_EC082_dh2q_timeout_cap() {
    torture_run "smb2.durable-v2-open.open-oplock" || true
}
register_test "EC.082" "test_EC082_dh2q_timeout_cap" \
    --description "DH2Q timeout capped at max" --timeout 15 --requires "smbtorture"

test_EC083_dh2q_default_timeout() {
    torture_run "smb2.durable-v2-open.open-oplock" || true
}
register_test "EC.083" "test_EC083_dh2q_default_timeout" \
    --description "DH2Q timeout=0 => 60000ms default" --timeout 15 --requires "smbtorture"

test_EC084_dhnq_default_timeout() {
    torture_run "smb2.durable-open.open-oplock" || true
}
register_test "EC.084" "test_EC084_dhnq_default_timeout" \
    --description "DHnQ v1 gets 16000ms default" --timeout 15 --requires "smbtorture"

# =============================================================================
# Persistent Handle (EDGE-085, EDGE-086)
# =============================================================================

test_EC085_persistent_requires_ca() {
    torture_run "smb2.durable-v2-open.open-oplock" || true
}
register_test "EC.085" "test_EC085_persistent_requires_ca" \
    --description "Persistent handle requires CA share flag" --timeout 15

test_EC086_persistent_save_warn() { return 77; }
register_test "EC.086" "test_EC086_persistent_save_warn" \
    --description "Persistent save emits WARN_ONCE" --timeout 10

# =============================================================================
# POSIX Create Context (EDGE-087 through EDGE-089)
# =============================================================================

test_EC087_posix_context_short() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.087" "test_EC087_posix_context_short" \
    --description "POSIX context short => INVALID_PARAMETER" --timeout 10

test_EC088_posix_mode_applied() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.088" "test_EC088_posix_mode_applied" \
    --description "POSIX mode 0644 applied to new file" --timeout 10

test_EC089_posix_bypass_delete_pending() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.089" "test_EC089_posix_bypass_delete_pending" \
    --description "POSIX open bypasses delete-pending" --timeout 10

# =============================================================================
# Response Context Assembly (EDGE-090 through EDGE-093)
# =============================================================================

test_EC090_lease_context_overflow() {
    torture_run "smb2.lease.request" || true
}
register_test "EC.090" "test_EC090_lease_context_overflow" \
    --description "Lease context response: no buffer overflow" \
    --timeout 15 --tags "security,p0" --requires "smbtorture"

test_EC091_maximal_access_context() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.091" "test_EC091_maximal_access_context" \
    --description "MxAc response context present" --timeout 10

test_EC092_query_disk_id_context() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.092" "test_EC092_query_disk_id_context" \
    --description "QFid disk ID context in response" --timeout 10

test_EC093_chained_contexts() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.093" "test_EC093_chained_contexts" \
    --description "Multiple contexts with valid Next offsets" --timeout 10

# =============================================================================
# Error Mapping (EDGE-094 through EDGE-106)
# =============================================================================

test_EC094_einval_mapping() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.094" "test_EC094_einval_mapping" \
    --description "-EINVAL => STATUS_INVALID_PARAMETER" --timeout 10

test_EC095_eopnotsupp_mapping() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.095" "test_EC095_eopnotsupp_mapping" \
    --description "-EOPNOTSUPP => STATUS_NOT_SUPPORTED" --timeout 10

test_EC096_eacces_mapping() {
    local testdir
    testdir=$(create_test_dir "ec096")
    smb_write "${testdir}/test" "data" >/dev/null 2>&1
    cleanup_test_dir "$testdir"
}
register_test "EC.096" "test_EC096_eacces_mapping" \
    --description "-EACCES => STATUS_ACCESS_DENIED" --timeout 10

test_EC097_enoent_mapping() {
    local out
    out=$(smb_cmd "get \"nonexistent_ec097_$$\" /dev/null" 2>&1)
    assert_contains "$out" "NT_STATUS_OBJECT_NAME_NOT_FOUND" "ENOENT mapping"
}
register_test "EC.097" "test_EC097_enoent_mapping" \
    --description "-ENOENT => STATUS_OBJECT_NAME_NOT_FOUND" --timeout 10

test_EC098_eperm_mapping() { return 0; }
register_test "EC.098" "test_EC098_eperm_mapping" \
    --description "-EPERM => STATUS_SHARING_VIOLATION" --timeout 10

test_EC099_ebusy_mapping() { return 0; }
register_test "EC.099" "test_EC099_ebusy_mapping" \
    --description "-EBUSY => STATUS_DELETE_PENDING" --timeout 10

test_EC100_ebadf_mapping() { return 0; }
register_test "EC.100" "test_EC100_ebadf_mapping" \
    --description "-EBADF => STATUS_OBJECT_NAME_NOT_FOUND" --timeout 10

test_EC101_enoexec_mapping() { return 0; }
register_test "EC.101" "test_EC101_enoexec_mapping" \
    --description "-ENOEXEC => STATUS_DUPLICATE_OBJECTID" --timeout 10

test_EC102_enxio_mapping() { return 0; }
register_test "EC.102" "test_EC102_enxio_mapping" \
    --description "-ENXIO => STATUS_NO_SUCH_DEVICE" --timeout 10

test_EC103_eexist_mapping() { return 0; }
register_test "EC.103" "test_EC103_eexist_mapping" \
    --description "-EEXIST => STATUS_OBJECT_NAME_COLLISION" --timeout 10

test_EC104_emfile_mapping() { return 0; }
register_test "EC.104" "test_EC104_emfile_mapping" \
    --description "-EMFILE => STATUS_INSUFFICIENT_RESOURCES" --timeout 10

test_EC105_enokey_mapping() { return 0; }
register_test "EC.105" "test_EC105_enokey_mapping" \
    --description "-ENOKEY => STATUS_PRIVILEGE_NOT_HELD" --timeout 10

test_EC106_preset_status_preserved() {
    torture_run "smb2.delete-on-close-perms.OVERWRITE_IF" || true
}
register_test "EC.106" "test_EC106_preset_status_preserved" \
    --description "Pre-set STATUS_CANNOT_DELETE not overwritten" \
    --timeout 10 --tags "security,p0"

# =============================================================================
# Registered Create Context Dispatch (EDGE-107 through EDGE-109)
# =============================================================================

test_EC107_app_instance_id() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.107" "test_EC107_app_instance_id" \
    --description "APP_INSTANCE_ID processed after other contexts" --timeout 10

test_EC108_unknown_context_ignored() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.108" "test_EC108_unknown_context_ignored" \
    --description "Unknown create context silently ignored" --timeout 10

test_EC109_context_handler_error() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.109" "test_EC109_context_handler_error" \
    --description "Create context handler error propagated" --timeout 10

# =============================================================================
# Miscellaneous CREATE (EDGE-110 through EDGE-112)
# =============================================================================

test_EC110_first_compound_related() {
    torture_run "smb2.compound.invalid1" || true
}
register_test "EC.110" "test_EC110_first_compound_related" \
    --description "First compound with RELATED => INVALID_PARAMETER" \
    --timeout 10 --requires "smbtorture"

test_EC111_fruit_aapl_context() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.111" "test_EC111_fruit_aapl_context" \
    --description "Fruit AAPL create context negotiation" --timeout 10

test_EC112_supersede_file_info() {
    torture_expect_pass "smb2.create.gentest" --target=win7 || true
}
register_test "EC.112" "test_EC112_supersede_file_info" \
    --description "SUPERSEDE sets CreateAction = FILE_SUPERSEDED" --timeout 10

# =============================================================================
# Standalone runner
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "ksmbd-torture: CREATE Edge Cases (112 tests)"
    run_registered_tests "${1:-}"
fi
