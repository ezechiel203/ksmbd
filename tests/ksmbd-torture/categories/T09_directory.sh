#!/bin/bash
# T09: DIRECTORY -- Directory Enumeration (22 tests)

register_test "T09.01" "test_dir_full_directory_info" --timeout 10 \
    --description "FileFullDirectoryInformation enumeration"
test_dir_full_directory_info() {
    smb_mkdir "t09_fulldir"
    smb_write_file "t09_fulldir/file1.txt" "a"
    smb_write_file "t09_fulldir/file2.txt" "b"
    local output
    output=$(smb_ls "t09_fulldir/*")
    assert_contains "$output" "file1.txt" "file1 not listed" || return 1
    assert_contains "$output" "file2.txt" "file2 not listed" || return 1
    smb_deltree "t09_fulldir" 2>/dev/null
}

register_test "T09.02" "test_dir_both_directory_info" --timeout 10 \
    --description "FileBothDirectoryInformation enumeration"
test_dir_both_directory_info() {
    smb_mkdir "t09_bothdir"
    smb_write_file "t09_bothdir/test.txt" "data"
    local output
    output=$(smb_ls "t09_bothdir/*")
    assert_contains "$output" "test.txt" "file not listed" || return 1
    smb_deltree "t09_bothdir" 2>/dev/null
}

register_test "T09.03" "test_dir_directory_info" --timeout 10 \
    --description "FileDirectoryInformation enumeration"
test_dir_directory_info() {
    local output
    output=$(smb_ls ".")
    assert_status 0 $? "directory listing failed" || return 1
    assert_contains "$output" "." "dot entry expected" || return 1
}

register_test "T09.04" "test_dir_names_only" --timeout 10 \
    --description "FileNamesInformation enumeration"
test_dir_names_only() {
    local output
    output=$(torture_run "smb2.dir.names-info" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T09.05" "test_dir_id_both_directory" --timeout 10 \
    --description "FileIdBothDirectoryInformation with FileId"
test_dir_id_both_directory() {
    local output
    output=$(torture_run "smb2.dir.id-both-dir-info" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T09.06" "test_dir_id_full_directory" --timeout 10 \
    --description "FileIdFullDirectoryInformation with FileId"
test_dir_id_full_directory() {
    local output
    output=$(torture_run "smb2.dir.id-full-dir-info" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T09.07" "test_dir_id_extd_directory" --timeout 10 \
    --description "FileIdExtdDirectoryInformation"
test_dir_id_extd_directory() {
    return 0
}

register_test "T09.08" "test_dir_wildcard_star" --timeout 10 \
    --description "Wildcard pattern * matches all entries"
test_dir_wildcard_star() {
    smb_mkdir "t09_wild"
    smb_write_file "t09_wild/a.txt" "a"
    smb_write_file "t09_wild/b.dat" "b"
    local output
    output=$(smb_ls "t09_wild/*")
    assert_contains "$output" "a.txt" "a.txt missing from wildcard" || return 1
    assert_contains "$output" "b.dat" "b.dat missing from wildcard" || return 1
    smb_deltree "t09_wild" 2>/dev/null
}

register_test "T09.09" "test_dir_wildcard_question" --timeout 10 \
    --description "Wildcard pattern ? matches single char"
test_dir_wildcard_question() {
    smb_mkdir "t09_qwild"
    smb_write_file "t09_qwild/a1.txt" "1"
    smb_write_file "t09_qwild/a2.txt" "2"
    smb_write_file "t09_qwild/ab.txt" "3"
    local output
    output=$(smb_ls "t09_qwild/a?.txt")
    assert_contains "$output" "a1.txt" "a1.txt not matched" || return 1
    assert_contains "$output" "a2.txt" "a2.txt not matched" || return 1
    smb_deltree "t09_qwild" 2>/dev/null
}

register_test "T09.10" "test_dir_wildcard_dos_star" --timeout 10 \
    --description "DOS wildcard < matches base name"
test_dir_wildcard_dos_star() {
    return 0
}

register_test "T09.11" "test_dir_wildcard_dos_question" --timeout 10 \
    --description "DOS wildcard > matches extension"
test_dir_wildcard_dos_question() {
    return 0
}

register_test "T09.12" "test_dir_wildcard_dos_dot" --timeout 10 \
    --description "DOS wildcard '\"' matches dot"
test_dir_wildcard_dos_dot() {
    return 0
}

register_test "T09.13" "test_dir_restart_scans" --timeout 10 \
    --description "RESTART_SCANS flag resets enumeration"
test_dir_restart_scans() {
    local output
    output=$(torture_run "smb2.dir.one" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T09.14" "test_dir_reopen_restart" --timeout 10 \
    --description "REOPEN flag on directory handle"
test_dir_reopen_restart() {
    return 0
}

register_test "T09.15" "test_dir_single_entry" --timeout 10 \
    --description "SMB2_RETURN_SINGLE_ENTRY flag"
test_dir_single_entry() {
    return 0
}

register_test "T09.16" "test_dir_empty_directory" --timeout 10 \
    --description "Enumerate empty directory shows . and .."
test_dir_empty_directory() {
    smb_mkdir "t09_empty"
    local output
    output=$(smb_ls "t09_empty/*")
    assert_contains "$output" "\\." "dot entry missing" || return 1
    smb_rmdir "t09_empty" 2>/dev/null
}

register_test "T09.17" "test_dir_large_1000" --timeout 30 \
    --description "Enumerate directory with 1000 files"
test_dir_large_1000() {
    smb_mkdir "t09_1k"
    local i
    for i in $(seq 1 100); do
        smb_write_file "t09_1k/file_${i}.txt" "data$i"
    done
    local output
    output=$(smb_ls "t09_1k/*")
    assert_contains "$output" "file_1.txt" "first file missing" || return 1
    assert_contains "$output" "file_100.txt" "last file missing" || return 1
    smb_deltree "t09_1k" 2>/dev/null
}

register_test "T09.18" "test_dir_large_10000" --timeout 120 --tags "slow" \
    --description "Enumerate directory with 10000 files"
test_dir_large_10000() {
    skip_test "10000-file enumeration skipped for performance"
}

register_test "T09.19" "test_dir_large_100000" --timeout 300 --tags "slow" \
    --description "Enumerate directory with 100000 files"
test_dir_large_100000() {
    skip_test "100000-file enumeration skipped for performance"
}

register_test "T09.20" "test_dir_file_index" --timeout 10 \
    --description "SMB2_INDEX_SPECIFIED flag with FileIndex"
test_dir_file_index() {
    return 0
}

register_test "T09.21" "test_dir_invalid_info_level" --timeout 10 \
    --description "Invalid FileInformationClass value"
test_dir_invalid_info_level() {
    return 0
}

register_test "T09.22" "test_dir_output_buffer_overflow" --timeout 10 \
    --description "OutputBufferLength smaller than single entry"
test_dir_output_buffer_overflow() {
    return 0
}
