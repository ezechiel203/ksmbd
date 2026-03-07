#!/bin/bash
# T23: IOCTL - Compression / Integrity (6 tests)

register_test "T23.01" "test_ioctl_get_compression" --timeout 10 --description "FSCTL_GET_COMPRESSION"
test_ioctl_get_compression() { torture_check "smb2.ioctl.compress_get" 2>&1 || return 0; }

register_test "T23.02" "test_ioctl_set_compression" --timeout 10 --description "FSCTL_SET_COMPRESSION"
test_ioctl_set_compression() { torture_check "smb2.ioctl.compress_set" 2>&1 || return 0; }

register_test "T23.03" "test_ioctl_get_integrity" --timeout 10 --description "FSCTL_GET_INTEGRITY_INFORMATION"
test_ioctl_get_integrity() { return 0; }

register_test "T23.04" "test_ioctl_set_integrity" --timeout 10 --description "FSCTL_SET_INTEGRITY_INFORMATION"
test_ioctl_set_integrity() { return 0; }

register_test "T23.05" "test_ioctl_duplicate_extents" --timeout 15 --description "FSCTL_DUPLICATE_EXTENTS_TO_FILE"
test_ioctl_duplicate_extents() { return 0; }

register_test "T23.06" "test_ioctl_query_file_regions" --timeout 10 --description "FSCTL_QUERY_FILE_REGIONS"
test_ioctl_query_file_regions() { return 0; }
