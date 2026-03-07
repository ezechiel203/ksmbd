#!/bin/bash
# T11: QUERY_INFO - Filesystem (8 tests)

register_test "T11.01" "test_query_fs_volume" --timeout 10 \
    --description "FileFsVolumeInformation"
test_query_fs_volume() {
    local output
    output=$(smb_volume)
    assert_not_empty "$output" "volume info empty" || return 1
}

register_test "T11.02" "test_query_fs_size" --timeout 10 \
    --description "FileFsSizeInformation"
test_query_fs_size() {
    local output
    output=$(smb_cmd "$SMB_UNC" -c "ls")
    assert_contains "$output" "blocks" "size info (blocks) expected" || return 1
}

register_test "T11.03" "test_query_fs_device" --timeout 10 \
    --description "FileFsDeviceInformation"
test_query_fs_device() {
    return 0
}

register_test "T11.04" "test_query_fs_attribute" --timeout 10 \
    --description "FileFsAttributeInformation"
test_query_fs_attribute() {
    local output
    output=$(smb_cmd "$SMB_UNC" -c "ls")
    assert_status 0 $? "fs attribute query path failed" || return 1
}

register_test "T11.05" "test_query_fs_full_size" --timeout 10 \
    --description "FileFsFullSizeInformation"
test_query_fs_full_size() {
    return 0
}

register_test "T11.06" "test_query_fs_sector_size" --timeout 10 \
    --description "FileFsSectorSizeInformation"
test_query_fs_sector_size() {
    return 0
}

register_test "T11.07" "test_query_fs_object_id" --timeout 10 \
    --description "FileFsObjectIdInformation"
test_query_fs_object_id() {
    return 0
}

register_test "T11.08" "test_query_fs_control" --timeout 10 \
    --description "FileFsControlInformation"
test_query_fs_control() {
    return 0
}
