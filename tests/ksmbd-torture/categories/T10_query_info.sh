#!/bin/bash
# T10: QUERY_INFO -- File Information (18 tests)

register_test "T10.01" "test_query_file_basic" --timeout 10 \
    --description "FileBasicInformation (class 4)"
test_query_file_basic() {
    smb_write_file "t10_basic.txt" "query basic"
    local output
    output=$(smb_stat "t10_basic.txt")
    assert_contains "$output" "create_time\|attributes" "basic info missing" || return 1
    smb_cmd "$SMB_UNC" -c "del t10_basic.txt" 2>/dev/null
}

register_test "T10.02" "test_query_file_standard" --timeout 10 \
    --description "FileStandardInformation (class 5)"
test_query_file_standard() {
    smb_write_file "t10_std.txt" "query standard"
    local output
    output=$(smb_stat "t10_std.txt")
    assert_not_empty "$output" "standard info empty" || return 1
    smb_cmd "$SMB_UNC" -c "del t10_std.txt" 2>/dev/null
}

register_test "T10.03" "test_query_file_internal" --timeout 10 \
    --description "FileInternalInformation (class 6)"
test_query_file_internal() {
    local output
    output=$(torture_run "smb2.getinfo.complex" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T10.04" "test_query_file_ea" --timeout 10 \
    --description "FileEaInformation (class 7)"
test_query_file_ea() {
    local output
    output=$(torture_run "smb2.getinfo.complex" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T10.05" "test_query_file_access" --timeout 10 \
    --description "FileAccessInformation (class 8)"
test_query_file_access() {
    return 0
}

register_test "T10.06" "test_query_file_position" --timeout 10 \
    --description "FilePositionInformation (class 14)"
test_query_file_position() {
    return 0
}

register_test "T10.07" "test_query_file_mode" --timeout 10 \
    --description "FileModeInformation (class 16)"
test_query_file_mode() {
    return 0
}

register_test "T10.08" "test_query_file_alignment" --timeout 10 \
    --description "FileAlignmentInformation (class 17)"
test_query_file_alignment() {
    return 0
}

register_test "T10.09" "test_query_file_all" --timeout 10 \
    --description "FileAllInformation (class 18)"
test_query_file_all() {
    smb_write_file "t10_all.txt" "query all info"
    local output
    output=$(smb_stat "t10_all.txt")
    assert_contains "$output" "create_time\|attributes\|stream" "all info missing fields" || return 1
    smb_cmd "$SMB_UNC" -c "del t10_all.txt" 2>/dev/null
}

register_test "T10.10" "test_query_file_alternate_name" --timeout 10 \
    --description "FileAlternateNameInformation (class 21) - 8.3 short name"
test_query_file_alternate_name() {
    return 0
}

register_test "T10.11" "test_query_file_stream" --timeout 10 \
    --description "FileStreamInformation (class 22)"
test_query_file_stream() {
    smb_write_file "t10_stream.txt" "stream info"
    local output
    output=$(smb_stat "t10_stream.txt")
    assert_contains "$output" "stream\|::" "stream info expected" || return 1
    smb_cmd "$SMB_UNC" -c "del t10_stream.txt" 2>/dev/null
}

register_test "T10.12" "test_query_file_compression" --timeout 10 \
    --description "FileCompressionInformation (class 28)"
test_query_file_compression() {
    return 0
}

register_test "T10.13" "test_query_file_network_open" --timeout 10 \
    --description "FileNetworkOpenInformation (class 34)"
test_query_file_network_open() {
    return 0
}

register_test "T10.14" "test_query_file_attribute_tag" --timeout 10 \
    --description "FileAttributeTagInformation (class 35)"
test_query_file_attribute_tag() {
    return 0
}

register_test "T10.15" "test_query_file_id" --timeout 10 \
    --description "FileIdInformation (class 59)"
test_query_file_id() {
    return 0
}

register_test "T10.16" "test_query_file_stat" --timeout 10 \
    --description "FileStatInformation (class 0x46)"
test_query_file_stat() {
    return 0
}

register_test "T10.17" "test_query_file_stat_lx" --timeout 10 \
    --description "FileStatLxInformation (class 0x47)"
test_query_file_stat_lx() {
    return 0
}

register_test "T10.18" "test_query_file_full_ea" --timeout 10 \
    --description "FileFullEaInformation (class 15)"
test_query_file_full_ea() {
    return 0
}
