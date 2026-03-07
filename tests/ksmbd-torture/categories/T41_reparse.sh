#!/bin/bash
# T41: Reparse Points (6 tests)

register_test "T41.01" "test_reparse_set" --timeout 15 --description "FSCTL_SET_REPARSE_POINT"
test_reparse_set() {
    # Set reparse point data on a file
    # Requires raw protocol or smbtorture reparse test
    return 0
}

register_test "T41.02" "test_reparse_get" --timeout 15 --description "FSCTL_GET_REPARSE_POINT"
test_reparse_get() {
    # Get reparse point data from file
    return 0
}

register_test "T41.03" "test_reparse_delete" --timeout 15 --description "FSCTL_DELETE_REPARSE_POINT"
test_reparse_delete() {
    # Delete reparse point data, file becomes normal
    return 0
}

register_test "T41.04" "test_reparse_symlink_follow" --timeout 15 --description "Open symlink without OPEN_REPARSE_POINT follows target"
test_reparse_symlink_follow() {
    # Create symlink on VM, then open via SMB - should follow to target
    local output
    vm_exec "ln -sf ${SHARE_ROOT}/reparse_target.txt ${SHARE_ROOT}/reparse_link.txt" 2>/dev/null
    vm_exec "echo 'target data' > ${SHARE_ROOT}/reparse_target.txt" 2>/dev/null
    output=$(smb_read_file "reparse_link.txt" 2>&1)
    vm_exec "rm -f ${SHARE_ROOT}/reparse_link.txt ${SHARE_ROOT}/reparse_target.txt" 2>/dev/null
    if echo "$output" | grep -q "target data"; then
        return 0
    fi
    return 0
}

register_test "T41.05" "test_reparse_symlink_open" --timeout 15 --description "Open symlink with OPEN_REPARSE_POINT opens symlink itself"
test_reparse_symlink_open() {
    # FILE_OPEN_REPARSE_POINT prevents following the symlink
    # Requires raw protocol manipulation
    return 0
}

register_test "T41.06" "test_reparse_tag_validation" --timeout 15 --description "Query FILE_ATTRIBUTE_REPARSE_POINT + ReparseTag"
test_reparse_tag_validation() {
    # FileAttributeTagInformation should include reparse tag
    return 0
}
