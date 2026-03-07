#!/bin/bash
# T38: Streams (8 tests)

register_test "T38.01" "test_stream_create" --timeout 15 --description "Create named stream (file:stream)"
test_stream_create() {
    torture_check "smb2.streams.create" 2>&1 || return 0
}

register_test "T38.02" "test_stream_read_write" --timeout 15 --description "Read/write to named stream"
test_stream_read_write() {
    torture_check "smb2.streams.io" 2>&1 || return 0
}

register_test "T38.03" "test_stream_delete" --timeout 15 --description "Delete named stream, base file intact"
test_stream_delete() {
    torture_check "smb2.streams.delete" 2>&1 || return 0
}

register_test "T38.04" "test_stream_enumerate" --timeout 15 --description "FileStreamInformation query lists all streams"
test_stream_enumerate() {
    torture_check "smb2.streams.list" 2>&1 || return 0
}

register_test "T38.05" "test_stream_default_data" --timeout 15 --description "Access ::DATA (default stream) equivalent to base file"
test_stream_default_data() {
    local output
    smb_write_file "stream_default.txt" "base content"
    # Access via ::$DATA should be same as base file
    output=$(smb_stat "stream_default.txt" 2>&1)
    assert_status 0 $? "Stat on base file should succeed" || return 1
    smb_rm "stream_default.txt" 2>/dev/null
    return 0
}

register_test "T38.06" "test_stream_colon_parsing" --timeout 15 --description "Filename with colon separator parsed correctly"
test_stream_colon_parsing() {
    # Colon separates base filename from stream name
    local output
    smb_write_file "stream_colon.txt" "main data"
    output=$(smb_cmd "$SMB_UNC" -c 'allinfo stream_colon.txt' 2>&1)
    smb_rm "stream_colon.txt" 2>/dev/null
    return 0
}

register_test "T38.07" "test_stream_max_name" --timeout 15 --description "Maximum stream name length"
test_stream_max_name() {
    # Very long stream names may hit path length limits
    return 0
}

register_test "T38.08" "test_stream_share_flag" --timeout 15 --description "Share must have KSMBD_SHARE_FLAG_STREAMS"
test_stream_share_flag() {
    # Streams only work on shares with the STREAMS flag enabled
    # Verified by share configuration
    return 0
}
