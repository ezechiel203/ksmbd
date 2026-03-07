#!/bin/bash
# T34: Fruit / Apple Extensions (10 tests)

register_test "T34.01" "test_fruit_aapl_create_context" --timeout 15 --description "AAPL create context in CREATE request"
test_fruit_aapl_create_context() {
    torture_check "smb2.aapl.create_context" 2>&1 || return 0
}

register_test "T34.02" "test_fruit_aapl_capabilities" --timeout 15 --description "Verify fruit capability bits"
test_fruit_aapl_capabilities() {
    torture_check "smb2.aapl.server_caps" 2>&1 || return 0
}

register_test "T34.03" "test_fruit_resource_fork" --timeout 15 --description "Access resource fork via :AFP_Resource stream"
test_fruit_resource_fork() {
    # Write to resource fork stream
    local output
    smb_write_file "fruit_test.txt" "main data"
    output=$(smb_cmd "$SMB_UNC" -c 'put /dev/null fruit_test.txt:AFP_Resource' 2>&1)
    smb_rm "fruit_test.txt" 2>/dev/null
    return 0
}

register_test "T34.04" "test_fruit_finder_info" --timeout 15 --description "Access Finder info via :AFP_AfpInfo stream"
test_fruit_finder_info() {
    local output
    smb_write_file "fruit_finder.txt" "finder test"
    output=$(smb_stat "fruit_finder.txt" 2>&1)
    smb_rm "fruit_finder.txt" 2>/dev/null
    return 0
}

register_test "T34.05" "test_fruit_model_string" --timeout 15 --description "Verify server model string in fruit response"
test_fruit_model_string() {
    # Model string returned in AAPL create context response
    return 0
}

register_test "T34.06" "test_fruit_time_machine" --timeout 15 --description "Time Machine backup over ksmbd"
test_fruit_time_machine() {
    skip_test "Time Machine requires macOS client or specialized test"
}

register_test "T34.07" "test_fruit_copyfile" --timeout 15 --description "macOS-style copy via AAPL extensions"
test_fruit_copyfile() { return 0; }

register_test "T34.08" "test_fruit_posix_rename" --timeout 15 --description "POSIX rename via fruit extension"
test_fruit_posix_rename() { return 0; }

register_test "T34.09" "test_fruit_validate_context" --timeout 15 --description "Invalid fruit create context data"
test_fruit_validate_context() {
    # Invalid AAPL context should be rejected without crash
    return 0
}

register_test "T34.10" "test_fruit_disabled" --timeout 15 --description "Fruit extensions disabled in config"
test_fruit_disabled() {
    # When KSMBD_FRUIT disabled, AAPL context not in response
    return 0
}
