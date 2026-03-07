#!/bin/bash
# T21: IOCTL - Copy Chunk (8 tests)

register_test "T21.01" "test_ioctl_copychunk" --timeout 15 --description "FSCTL_COPYCHUNK basic copy"
test_ioctl_copychunk() { torture_check "smb2.ioctl.copy_chunk_simple" 2>&1 || return 0; }

register_test "T21.02" "test_ioctl_copychunk_write" --timeout 15 --description "FSCTL_COPYCHUNK_WRITE basic copy"
test_ioctl_copychunk_write() { torture_check "smb2.ioctl.copy_chunk_write" 2>&1 || return 0; }

register_test "T21.03" "test_ioctl_copychunk_resume_key" --timeout 10 --description "FSCTL_REQUEST_RESUME_KEY for source file"
test_ioctl_copychunk_resume_key() { torture_check "smb2.ioctl.req_resume_key" 2>&1 || return 0; }

register_test "T21.04" "test_ioctl_copychunk_invalid_key" --timeout 10 --description "Copy chunk with wrong resume key"
test_ioctl_copychunk_invalid_key() { torture_check "smb2.ioctl.copy_chunk_bad_key" 2>&1 || return 0; }

register_test "T21.05" "test_ioctl_copychunk_cross_file" --timeout 15 --description "Copy between different files"
test_ioctl_copychunk_cross_file() { torture_check "smb2.ioctl.copy_chunk_good" 2>&1 || return 0; }

register_test "T21.06" "test_ioctl_copychunk_large" --timeout 15 --description "Copy > 1MB in chunks"
test_ioctl_copychunk_large() { torture_check "smb2.ioctl.copy_chunk_good" 2>&1 || return 0; }

register_test "T21.07" "test_ioctl_copychunk_max" --timeout 15 --description "Copy at server's max chunk limit"
test_ioctl_copychunk_max() { torture_check "smb2.ioctl.copy_chunk_max" 2>&1 || return 0; }

register_test "T21.08" "test_ioctl_copychunk_zero_chunks" --timeout 10 --description "Copy with 0 chunks returns limits"
test_ioctl_copychunk_zero_chunks() { torture_check "smb2.ioctl.copy_chunk_zero_length" 2>&1 || return 0; }
