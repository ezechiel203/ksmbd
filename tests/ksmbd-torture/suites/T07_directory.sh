#!/bin/bash
# T07_directory.sh -- Directory operation tests
#
# Tests nested directory creation, large directory listing, wildcard
# search, non-empty directory deletion, and recursive operations.

DIR_PREFIX="torture_dir_$$"

_dir_cleanup() {
    # Clean up in reverse order (inner files first)
    _smbclient_cmd "deltree \"${DIR_PREFIX}\"" 2>/dev/null
    _smbclient_cmd "del \"${DIR_PREFIX}_*\"" 2>/dev/null
    smb_rmdir "${DIR_PREFIX}" 2>/dev/null
    return 0
}

# ============================================================================
# Test 1: Create nested directories
# ============================================================================
test_dir_nested_create() {
    local desc="Create nested directories"
    _dir_cleanup 2>/dev/null

    # Create parent
    smb_mkdir "${DIR_PREFIX}" >/dev/null 2>&1
    # Create child
    smb_mkdir "${DIR_PREFIX}/level1" >/dev/null 2>&1
    # Create grandchild
    smb_mkdir "${DIR_PREFIX}/level1/level2" >/dev/null 2>&1

    # Verify each level exists
    local output
    output=$(smb_ls "${DIR_PREFIX}/*")
    assert_contains "$output" "level1" "level1 directory should exist" || {
        _dir_cleanup
        return 1
    }

    output=$(smb_ls "${DIR_PREFIX}/level1/*")
    assert_contains "$output" "level2" "level2 directory should exist" || {
        _dir_cleanup
        return 1
    }

    _dir_cleanup
}

# ============================================================================
# Test 2: List large directory (1000 entries)
# ============================================================================
test_dir_large_listing() {
    local desc="List directory with 1000 entries"
    _dir_cleanup 2>/dev/null

    smb_mkdir "${DIR_PREFIX}" >/dev/null 2>&1

    # Create 1000 small files using batched smbclient commands
    # Build a single command string for efficiency
    local batch_size=50
    local total=1000
    local created=0
    local tmpfile="${_HELPERS_TMPDIR}/dir_large_$$"
    echo "x" > "$tmpfile"

    while [[ $created -lt $total ]]; do
        local cmds=""
        local i
        for ((i = 0; i < batch_size && created < total; i++, created++)); do
            cmds="${cmds}put \"$tmpfile\" \"${DIR_PREFIX}/file_$(printf '%04d' "$created")\"; "
        done
        _smbclient_cmd "$cmds" >/dev/null 2>&1
    done
    rm -f "$tmpfile"

    # List the directory and count entries
    local output
    output=$(smb_ls "${DIR_PREFIX}/*")
    local count
    count=$(echo "$output" | grep -c "file_" || true)

    if [[ $count -lt 900 ]]; then
        echo "Expected ~1000 files, found $count" >&2
        _dir_cleanup
        return 1
    fi

    _dir_cleanup
}

# ============================================================================
# Test 3: Wildcard search
# ============================================================================
test_dir_wildcard_search() {
    local desc="Wildcard search matches correct files"
    _dir_cleanup 2>/dev/null

    smb_mkdir "${DIR_PREFIX}" >/dev/null 2>&1

    # Create files with different extensions
    local tmpfile="${_HELPERS_TMPDIR}/dir_wild_$$"
    echo "data" > "$tmpfile"

    _smbclient_cmd "
        put \"$tmpfile\" \"${DIR_PREFIX}/report.txt\";
        put \"$tmpfile\" \"${DIR_PREFIX}/data.txt\";
        put \"$tmpfile\" \"${DIR_PREFIX}/image.png\";
        put \"$tmpfile\" \"${DIR_PREFIX}/notes.txt\";
        put \"$tmpfile\" \"${DIR_PREFIX}/photo.png\"
    " >/dev/null 2>&1
    rm -f "$tmpfile"

    # Search for *.txt files
    local output
    output=$(smb_ls "${DIR_PREFIX}/*.txt")
    local txt_count
    txt_count=$(echo "$output" | grep -c "\.txt" || true)

    if [[ $txt_count -lt 3 ]]; then
        echo "Wildcard *.txt should find 3 files, found $txt_count" >&2
        echo "Output: $output" >&2
        _dir_cleanup
        return 1
    fi

    # Search for *.png files
    output=$(smb_ls "${DIR_PREFIX}/*.png")
    local png_count
    png_count=$(echo "$output" | grep -c "\.png" || true)

    if [[ $png_count -lt 2 ]]; then
        echo "Wildcard *.png should find 2 files, found $png_count" >&2
        _dir_cleanup
        return 1
    fi

    _dir_cleanup
}

# ============================================================================
# Test 4: Delete non-empty directory should fail
# ============================================================================
test_dir_delete_nonempty_fails() {
    local desc="Delete non-empty directory should fail"
    _dir_cleanup 2>/dev/null

    smb_mkdir "${DIR_PREFIX}" >/dev/null 2>&1

    # Put a file inside
    local tmpfile="${_HELPERS_TMPDIR}/dir_nonempty_$$"
    echo "blocker" > "$tmpfile"
    smb_put_file "$tmpfile" "${DIR_PREFIX}/blocker.txt" >/dev/null 2>&1
    rm -f "$tmpfile"

    # Try to remove directory (should fail because it is not empty)
    local output
    output=$(smb_rmdir "${DIR_PREFIX}" 2>&1)

    # The directory should still exist
    local listing
    listing=$(smb_ls "${DIR_PREFIX}/*" 2>&1)
    if echo "$listing" | grep -q "blocker.txt"; then
        # Good -- directory still exists with its contents
        _dir_cleanup
        return 0
    fi

    # If smbclient somehow removed it, check for error
    if echo "$output" | grep -qE "NT_STATUS_DIRECTORY_NOT_EMPTY|DIRECTORY_NOT_EMPTY|not empty"; then
        _dir_cleanup
        return 0
    fi

    echo "Expected non-empty directory deletion to fail" >&2
    _dir_cleanup
    return 1
}

# ============================================================================
# Test 5: Recursive delete
# ============================================================================
test_dir_recursive_delete() {
    local desc="Recursive delete removes all contents"
    _dir_cleanup 2>/dev/null

    # Create nested structure
    smb_mkdir "${DIR_PREFIX}" >/dev/null 2>&1
    smb_mkdir "${DIR_PREFIX}/sub1" >/dev/null 2>&1
    smb_mkdir "${DIR_PREFIX}/sub2" >/dev/null 2>&1

    local tmpfile="${_HELPERS_TMPDIR}/dir_recur_$$"
    echo "content" > "$tmpfile"

    _smbclient_cmd "
        put \"$tmpfile\" \"${DIR_PREFIX}/file1.txt\";
        put \"$tmpfile\" \"${DIR_PREFIX}/sub1/file2.txt\";
        put \"$tmpfile\" \"${DIR_PREFIX}/sub2/file3.txt\"
    " >/dev/null 2>&1
    rm -f "$tmpfile"

    # Recursive delete: clean up inner files and dirs
    _smbclient_cmd "
        del \"${DIR_PREFIX}/sub1/file2.txt\";
        del \"${DIR_PREFIX}/sub2/file3.txt\";
        rmdir \"${DIR_PREFIX}/sub1\";
        rmdir \"${DIR_PREFIX}/sub2\";
        del \"${DIR_PREFIX}/file1.txt\";
        rmdir \"${DIR_PREFIX}\"
    " >/dev/null 2>&1

    # Verify everything is gone
    local output
    output=$(smb_ls "${DIR_PREFIX}" 2>&1)
    if echo "$output" | grep -qE "NO_SUCH_FILE|NOT_FOUND|OBJECT_NAME_NOT_FOUND"; then
        return 0
    fi
    # Directory might just show . and ..
    if echo "$output" | grep -q "D.*${DIR_PREFIX}" && ! echo "$output" | grep -qE "NO_SUCH|NOT_FOUND"; then
        echo "Directory still exists after recursive delete" >&2
        _dir_cleanup
        return 1
    fi

    return 0
}
