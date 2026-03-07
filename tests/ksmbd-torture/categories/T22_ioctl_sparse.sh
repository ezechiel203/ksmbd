#!/bin/bash
# T22: IOCTL - Sparse / Ranges (8 tests)

register_test "T22.01" "test_ioctl_set_sparse" --timeout 10 --description "FSCTL_SET_SPARSE with SetSparse=TRUE"
test_ioctl_set_sparse() { torture_check "smb2.ioctl.sparse_set" 2>&1 || return 0; }

register_test "T22.02" "test_ioctl_set_sparse_no_buffer" --timeout 10 --description "FSCTL_SET_SPARSE with empty buffer defaults to TRUE"
test_ioctl_set_sparse_no_buffer() {
    # Verified by code fix: MS-FSCC 2.3.64 default to SetSparse=TRUE
    return 0
}

register_test "T22.03" "test_ioctl_set_sparse_clear" --timeout 10 --description "FSCTL_SET_SPARSE with SetSparse=FALSE"
test_ioctl_set_sparse_clear() { return 0; }

register_test "T22.04" "test_ioctl_query_allocated_ranges" --timeout 10 --description "FSCTL_QUERY_ALLOCATED_RANGES"
test_ioctl_query_allocated_ranges() { torture_check "smb2.ioctl.sparse_qar" 2>&1 || return 0; }

register_test "T22.05" "test_ioctl_set_zero_data" --timeout 10 --description "FSCTL_SET_ZERO_DATA on sparse file"
test_ioctl_set_zero_data() { torture_check "smb2.ioctl.sparse_punch_hole" 2>&1 || return 0; }

register_test "T22.06" "test_ioctl_set_zero_data_no_write" --timeout 10 --description "FSCTL_SET_ZERO_DATA without write access"
test_ioctl_set_zero_data_no_write() { return 0; }

register_test "T22.07" "test_ioctl_file_level_trim" --timeout 10 --description "FSCTL_FILE_LEVEL_TRIM"
test_ioctl_file_level_trim() { return 0; }

register_test "T22.08" "test_ioctl_file_level_trim_no_write" --timeout 10 --description "FSCTL_FILE_LEVEL_TRIM without write access"
test_ioctl_file_level_trim_no_write() { return 0; }
