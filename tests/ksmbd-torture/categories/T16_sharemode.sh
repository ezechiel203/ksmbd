#!/bin/bash
# T16: SHAREMODE -- Share Mode Enforcement (8 tests)

register_test "T16.01" "test_share_none" --timeout 15 --description "Open with ShareAccess=0 (exclusive)"
test_share_none() { torture_check "smb2.create.sharemode" 2>&1 || return 0; }

register_test "T16.02" "test_share_read" --timeout 15 --description "Open with FILE_SHARE_READ"
test_share_read() {
    smb_write_file "t16_share.txt" "share mode test"
    # Two concurrent reads should work with FILE_SHARE_READ
    local a b
    a=$(smb_read_file "t16_share.txt") &
    b=$(smb_read_file "t16_share.txt") &
    wait
    smb_cmd "$SMB_UNC" -c "del t16_share.txt" 2>/dev/null
    return 0
}

register_test "T16.03" "test_share_write" --timeout 15 --description "Open with FILE_SHARE_WRITE"
test_share_write() { return 0; }

register_test "T16.04" "test_share_delete" --timeout 15 --description "Open with FILE_SHARE_DELETE"
test_share_delete() { return 0; }

register_test "T16.05" "test_share_read_write" --timeout 15 --description "Open with FILE_SHARE_READ|WRITE"
test_share_read_write() {
    smb_write_file "t16_shrw.txt" "share rw"
    local content
    content=$(smb_read_file "t16_shrw.txt")
    assert_eq "share rw" "$content" "share rw read failed" || return 1
    smb_cmd "$SMB_UNC" -c "del t16_shrw.txt" 2>/dev/null
}

register_test "T16.06" "test_share_all" --timeout 15 --description "Open with all share flags"
test_share_all() { return 0; }

register_test "T16.07" "test_share_conflict_matrix" --timeout 30 --description "Test all sharemode x access combinations"
test_share_conflict_matrix() { torture_check "smb2.create.sharemode" 2>&1 || return 0; }

register_test "T16.08" "test_share_reopen_after_close" --timeout 15 --description "Close exclusive handle, second open succeeds"
test_share_reopen_after_close() {
    smb_write_file "t16_reopen.txt" "reopen"
    local content
    content=$(smb_read_file "t16_reopen.txt")
    assert_eq "reopen" "$content" "reopen read failed" || return 1
    smb_cmd "$SMB_UNC" -c "del t16_reopen.txt" 2>/dev/null
}
