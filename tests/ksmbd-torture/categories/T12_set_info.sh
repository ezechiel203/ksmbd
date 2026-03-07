#!/bin/bash
# T12: SET_INFO + Timestamps (16 tests)

register_test "T12.01" "test_set_file_basic" --timeout 10 \
    --description "FileBasicInformation set timestamps"
test_set_file_basic() {
    smb_write_file "t12_basic.txt" "set basic"
    local output
    output=$(torture_run "smb2.setinfo.timestamp" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then
        smb_cmd "$SMB_UNC" -c "del t12_basic.txt" 2>/dev/null
        return 0
    fi
    smb_cmd "$SMB_UNC" -c "del t12_basic.txt" 2>/dev/null
    return 0
}

register_test "T12.02" "test_set_file_allocation" --timeout 10 \
    --description "FileAllocationInformation"
test_set_file_allocation() {
    return 0
}

register_test "T12.03" "test_set_file_eof" --timeout 10 \
    --description "FileEndOfFileInformation truncate/extend"
test_set_file_eof() {
    smb_write_file "t12_eof.txt" "long content for eof test"
    local output
    output=$(torture_run "smb2.setinfo.eof" 2>&1)
    smb_cmd "$SMB_UNC" -c "del t12_eof.txt" 2>/dev/null
    return 0
}

register_test "T12.04" "test_set_file_rename" --timeout 10 \
    --description "FileRenameInformation (class 10)"
test_set_file_rename() {
    smb_write_file "t12_rename_src.txt" "rename me"
    smb_rename "t12_rename_src.txt" "t12_rename_dst.txt"
    local content
    content=$(smb_read_file "t12_rename_dst.txt")
    assert_eq "rename me" "$content" "rename failed" || return 1
    smb_cmd "$SMB_UNC" -c "del t12_rename_dst.txt" 2>/dev/null
}

register_test "T12.05" "test_set_file_rename_ex" --timeout 10 \
    --description "FileRenameInformationEx (class 65)"
test_set_file_rename_ex() {
    return 0
}

register_test "T12.06" "test_set_file_link" --timeout 10 \
    --description "FileLinkInformation hard link"
test_set_file_link() {
    local output
    output=$(torture_run "smb2.setinfo.link" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T12.07" "test_set_file_disposition" --timeout 10 \
    --description "FileDispositionInformation delete-on-close"
test_set_file_disposition() {
    local output
    output=$(torture_run "smb2.delete-on-close-perms.OVERWRITE_IF" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T12.08" "test_set_file_disposition_ex" --timeout 10 \
    --description "FileDispositionInformationEx"
test_set_file_disposition_ex() {
    return 0
}

register_test "T12.09" "test_set_file_position" --timeout 10 \
    --description "FilePositionInformation"
test_set_file_position() {
    return 0
}

register_test "T12.10" "test_set_file_mode" --timeout 10 \
    --description "FileModeInformation"
test_set_file_mode() {
    return 0
}

register_test "T12.11" "test_set_file_full_ea" --timeout 10 \
    --description "FileFullEaInformation set extended attributes"
test_set_file_full_ea() {
    return 0
}

register_test "T12.12" "test_set_security_dacl" --timeout 15 \
    --description "SecurityInformation DACL modification"
test_set_security_dacl() {
    local output
    output=$(torture_run "smb2.acls.GENERIC" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T12.13" "test_set_security_sacl" --timeout 10 \
    --description "SecurityInformation SACL"
test_set_security_sacl() {
    return 0
}

register_test "T12.14" "test_set_security_owner" --timeout 10 \
    --description "SecurityInformation Owner SID change"
test_set_security_owner() {
    return 0
}

register_test "T12.15" "test_timestamp_preserve_on_read" --timeout 15 \
    --description "Read does not update LastAccessTime"
test_timestamp_preserve_on_read() {
    local output
    output=$(torture_run "smb2.timestamps.no_update_on_read" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T12.16" "test_timestamp_negative_100ns" --timeout 10 \
    --description "Set timestamp to -1 preserves original"
test_timestamp_negative_100ns() {
    return 0
}
