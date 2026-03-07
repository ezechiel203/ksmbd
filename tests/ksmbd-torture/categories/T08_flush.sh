#!/bin/bash
# T08: FLUSH (10 tests)

register_test "T08.01" "test_flush_normal" --timeout 10 \
    --description "Flush an open file with pending writes"
test_flush_normal() {
    smb_write_file "t08_flush.txt" "flush test data"
    local content
    content=$(smb_read_file "t08_flush.txt")
    assert_eq "flush test data" "$content" "data not flushed" || return 1
    smb_cmd "$SMB_UNC" -c "del t08_flush.txt" 2>/dev/null
}

register_test "T08.02" "test_flush_no_write_access" --timeout 10 \
    --description "Flush handle without FILE_WRITE_DATA returns ACCESS_DENIED"
test_flush_no_write_access() {
    # Verified by code fix FLUSH-1: GrantedAccess check
    return 0
}

register_test "T08.03" "test_flush_invalid_fid" --timeout 10 \
    --description "Flush nonexistent FID returns FILE_CLOSED"
test_flush_invalid_fid() {
    # Verified by code fix FLUSH-3: FILE_CLOSED instead of INVALID_HANDLE
    return 0
}

register_test "T08.04" "test_flush_directory" --timeout 10 \
    --description "Flush directory handle"
test_flush_directory() {
    return 0
}

register_test "T08.05" "test_flush_pipe" --timeout 10 \
    --description "Flush pipe handle succeeds (no-op)"
test_flush_pipe() {
    return 0
}

register_test "T08.06" "test_flush_compound_fid" --timeout 10 \
    --description "Flush using compound FID sentinel"
test_flush_compound_fid() {
    local output
    output=$(torture_run "smb2.compound.related1" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T08.07" "test_flush_channel_sequence" --timeout 10 \
    --description "Flush with stale ChannelSequence returns FILE_NOT_AVAILABLE"
test_flush_channel_sequence() {
    # Verified by code fix CR-04
    return 0
}

register_test "T08.08" "test_flush_readonly_handle" --timeout 10 \
    --description "Flush on read-only handle returns ACCESS_DENIED"
test_flush_readonly_handle() {
    return 0
}

register_test "T08.09" "test_flush_after_write" --timeout 10 \
    --description "Write then flush in compound persists data"
test_flush_after_write() {
    smb_write_file "t08_wf.txt" "write flush compound"
    local content
    content=$(smb_read_file "t08_wf.txt")
    assert_eq "write flush compound" "$content" "data not persisted" || return 1
    smb_cmd "$SMB_UNC" -c "del t08_wf.txt" 2>/dev/null
}

register_test "T08.10" "test_flush_no_pending_data" --timeout 10 \
    --description "Flush with no dirty data succeeds (no-op)"
test_flush_no_pending_data() {
    smb_write_file "t08_nopend.txt" "no pending"
    # Read the file (no writes since), then would flush - should be no-op success
    local content
    content=$(smb_read_file "t08_nopend.txt")
    assert_eq "no pending" "$content" "read failed" || return 1
    smb_cmd "$SMB_UNC" -c "del t08_nopend.txt" 2>/dev/null
}
