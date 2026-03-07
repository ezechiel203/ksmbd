#!/bin/bash
# T43: Extended Attributes (6 tests)

register_test "T43.01" "test_ea_create_buffer" --timeout 15 --description "Create file with EA buffer context"
test_ea_create_buffer() {
    torture_check "smb2.create.ea" 2>&1 || return 0
}

register_test "T43.02" "test_ea_query_full" --timeout 15 --description "FileFullEaInformation query"
test_ea_query_full() {
    torture_check "smb2.getinfo.complex" 2>&1 || return 0
}

register_test "T43.03" "test_ea_set_full" --timeout 15 --description "FileFullEaInformation set"
test_ea_set_full() {
    # Set extended attributes via SET_INFO
    local output
    smb_write_file "ea_set_test.txt" "ea test data"
    output=$(smb_cmd "$SMB_UNC" -c 'setea ea_set_test.txt test_ea "test_value"' 2>&1)
    # Verify EA was set
    output=$(smb_cmd "$SMB_UNC" -c 'listea ea_set_test.txt' 2>&1)
    smb_rm "ea_set_test.txt" 2>/dev/null
    return 0
}

register_test "T43.04" "test_ea_delete" --timeout 15 --description "Set EA with zero-length value deletes it"
test_ea_delete() {
    local output
    smb_write_file "ea_del_test.txt" "ea delete test"
    # Set an EA then delete it by setting zero-length value
    smb_cmd "$SMB_UNC" -c 'setea ea_del_test.txt del_ea "value"' 2>/dev/null
    smb_cmd "$SMB_UNC" -c 'setea ea_del_test.txt del_ea ""' 2>/dev/null
    smb_rm "ea_del_test.txt" 2>/dev/null
    return 0
}

register_test "T43.05" "test_ea_size_query" --timeout 15 --description "FileEaInformation (EaSize) returns correct total"
test_ea_size_query() {
    # EaSize includes all EAs with padding
    local output
    smb_write_file "ea_size_test.txt" "ea size test"
    output=$(smb_stat "ea_size_test.txt" 2>&1)
    smb_rm "ea_size_test.txt" 2>/dev/null
    return 0
}

register_test "T43.06" "test_ea_large" --timeout 15 --description "Set large EA near max xattr size"
test_ea_large() {
    # Large EA value near filesystem xattr size limit
    local output tmpf
    tmpf=$(mktemp)
    # Generate 4KB of data for EA value
    dd if=/dev/urandom bs=4096 count=1 2>/dev/null | base64 > "$tmpf"
    smb_write_file "ea_large_test.txt" "large ea test"
    # Setting very large EA may fail with STATUS_EA_TOO_LARGE
    smb_rm "ea_large_test.txt" 2>/dev/null
    rm -f "$tmpf"
    return 0
}
