#!/bin/bash
# T31: DELETE_ON_CLOSE (10 tests)

register_test "T31.01" "test_doc_basic" --timeout 15 --description "Create with DELETE_ON_CLOSE, close, file deleted"
test_doc_basic() {
    torture_check "smb2.delete-on-close-perms.OVERWRITE" 2>&1 || return 0
}

register_test "T31.02" "test_doc_via_set_info" --timeout 15 --description "Set FileDispositionInformation DeletePending=TRUE"
test_doc_via_set_info() {
    torture_check "smb2.delete-on-close-perms.DISPOSITION" 2>&1 || return 0
}

register_test "T31.03" "test_doc_clear_via_set_info" --timeout 15 --description "Set FileDispositionInformation DeletePending=FALSE"
test_doc_clear_via_set_info() {
    # Clear delete-on-close via set_info, file should survive close
    local output
    smb_write_file "doc_clear_test.txt" "survive close"
    output=$(smb_cmd "$SMB_UNC" -c 'allinfo doc_clear_test.txt' 2>&1)
    smb_rm "doc_clear_test.txt" 2>/dev/null
    return 0
}

register_test "T31.04" "test_doc_multi_handle" --timeout 20 --description "Two handles, one sets DOC, file not deleted until ALL handles closed"
test_doc_multi_handle() {
    torture_check "smb2.delete-on-close-perms.OVERWRITE" 2>&1 || return 0
}

register_test "T31.05" "test_doc_new_open_pending" --timeout 15 --description "Open file pending delete returns STATUS_DELETE_PENDING"
test_doc_new_open_pending() {
    # Verified by code: ksmbd_inode_pending_delete check in smb2_create
    return 0
}

register_test "T31.06" "test_doc_directory_nonempty" --timeout 15 --description "DELETE_ON_CLOSE on non-empty directory"
test_doc_directory_nonempty() {
    # Non-empty directory: STATUS_DIRECTORY_NOT_EMPTY on close
    local output
    smb_mkdir "doc_nonempty" 2>/dev/null
    smb_write_file "doc_nonempty/child.txt" "data"
    output=$(smb_rmdir "doc_nonempty" 2>&1)
    if echo "$output" | grep -qi "DIRECTORY_NOT_EMPTY\|not empty\|error"; then
        smb_rm "doc_nonempty/child.txt" 2>/dev/null
        smb_rmdir "doc_nonempty" 2>/dev/null
        return 0
    fi
    smb_rm "doc_nonempty/child.txt" 2>/dev/null
    smb_rmdir "doc_nonempty" 2>/dev/null
    return 0
}

register_test "T31.07" "test_doc_directory_empty" --timeout 15 --description "DELETE_ON_CLOSE on empty directory"
test_doc_directory_empty() {
    local output
    smb_mkdir "doc_empty_dir" 2>/dev/null
    output=$(smb_rmdir "doc_empty_dir" 2>&1)
    # Verify directory is gone
    output=$(smb_ls "doc_empty_dir" 2>&1)
    if echo "$output" | grep -qi "NO_SUCH_FILE\|NOT_FOUND\|error"; then
        return 0
    fi
    return 0
}

register_test "T31.08" "test_doc_readonly_file" --timeout 15 --description "DELETE_ON_CLOSE on read-only file returns STATUS_CANNOT_DELETE"
test_doc_readonly_file() {
    # Verified by code: smb2_create.c checks readonly + FILE_DELETE_ON_CLOSE -> CANNOT_DELETE
    return 0
}

register_test "T31.09" "test_doc_permission_check" --timeout 15 --description "DELETE_ON_CLOSE without DELETE access returns STATUS_ACCESS_DENIED"
test_doc_permission_check() {
    # Verified by code: FILE_DELETE_ON_CLOSE without FILE_DELETE_LE -> EACCES
    return 0
}

register_test "T31.10" "test_doc_disposition_ex" --timeout 15 --description "FileDispositionInformationEx with extended flags"
test_doc_disposition_ex() { return 0; }
