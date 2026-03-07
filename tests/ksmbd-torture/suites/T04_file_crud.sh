#!/bin/bash
# T04_file_crud.sh -- Basic file CRUD operations
#
# Tests create, read, write, rename, and delete operations on files
# and directories through smbclient.

CRUD_PREFIX="torture_crud_$$"

_crud_cleanup() {
    smb_delete "${CRUD_PREFIX}_*" 2>/dev/null
    smb_rmdir "${CRUD_PREFIX}_dir" 2>/dev/null
    smb_delete "${CRUD_PREFIX}_renamed" 2>/dev/null
    smb_delete "${CRUD_PREFIX}_file" 2>/dev/null
    smb_delete "${CRUD_PREFIX}_rw" 2>/dev/null
}

# ============================================================================
# Test 1: Create file and verify it exists
# ============================================================================
test_file_create_verify() {
    local desc="Create file and verify it exists"
    _crud_cleanup 2>/dev/null

    # Create a small file
    local tmpfile="${_HELPERS_TMPDIR}/crud_create_$$"
    echo "hello world" > "$tmpfile"

    local output
    output=$(smb_put_file "$tmpfile" "${CRUD_PREFIX}_file")
    local rc=$?
    rm -f "$tmpfile"

    if [[ $rc -ne 0 ]]; then
        # smbclient put returns non-zero sometimes even on success; check listing
        :
    fi

    # Verify file exists by listing
    output=$(smb_ls "${CRUD_PREFIX}_file")
    assert_contains "$output" "${CRUD_PREFIX}_file" "File should appear in listing" || {
        _crud_cleanup
        return 1
    }

    _crud_cleanup
}

# ============================================================================
# Test 2: Write data, read back, verify content
# ============================================================================
test_file_write_read_verify() {
    local desc="Write data, read back, verify content matches"
    _crud_cleanup 2>/dev/null

    local test_content="The quick brown fox jumps over the lazy dog. $(random_string 32)"
    local tmpfile="${_HELPERS_TMPDIR}/crud_write_$$"
    printf '%s' "$test_content" > "$tmpfile"

    # Upload
    smb_put_file "$tmpfile" "${CRUD_PREFIX}_rw" >/dev/null 2>&1

    # Download to different file
    local dlfile="${_HELPERS_TMPDIR}/crud_read_$$"
    smb_get_file "${CRUD_PREFIX}_rw" "$dlfile" >/dev/null 2>&1
    local rc=$?

    if [[ ! -f "$dlfile" ]]; then
        echo "Downloaded file does not exist" >&2
        rm -f "$tmpfile"
        _crud_cleanup
        return 1
    fi

    local uploaded_hash downloaded_hash
    uploaded_hash=$(file_checksum "$tmpfile")
    downloaded_hash=$(file_checksum "$dlfile")

    rm -f "$tmpfile" "$dlfile"

    if [[ "$uploaded_hash" != "$downloaded_hash" ]]; then
        echo "Content mismatch: uploaded=$uploaded_hash downloaded=$downloaded_hash" >&2
        _crud_cleanup
        return 1
    fi

    _crud_cleanup
}

# ============================================================================
# Test 3: Rename file
# ============================================================================
test_file_rename() {
    local desc="Rename file and verify new name exists"
    _crud_cleanup 2>/dev/null

    # Create a file
    local tmpfile="${_HELPERS_TMPDIR}/crud_rename_$$"
    echo "rename test" > "$tmpfile"
    smb_put_file "$tmpfile" "${CRUD_PREFIX}_file" >/dev/null 2>&1
    rm -f "$tmpfile"

    # Rename it
    local output
    output=$(smb_rename "${CRUD_PREFIX}_file" "${CRUD_PREFIX}_renamed")

    # Verify new name exists
    output=$(smb_ls "${CRUD_PREFIX}_renamed")
    assert_contains "$output" "${CRUD_PREFIX}_renamed" "Renamed file should exist" || {
        _crud_cleanup
        return 1
    }

    # Verify old name is gone
    output=$(smb_ls "${CRUD_PREFIX}_file" 2>&1)
    if echo "$output" | grep -q "${CRUD_PREFIX}_file" && ! echo "$output" | grep -q "NO_SUCH_FILE\|NOT_FOUND"; then
        echo "Old filename should not exist after rename" >&2
        _crud_cleanup
        return 1
    fi

    _crud_cleanup
}

# ============================================================================
# Test 4: Delete file
# ============================================================================
test_file_delete() {
    local desc="Delete file and verify it is gone"
    _crud_cleanup 2>/dev/null

    # Create a file
    local tmpfile="${_HELPERS_TMPDIR}/crud_del_$$"
    echo "delete me" > "$tmpfile"
    smb_put_file "$tmpfile" "${CRUD_PREFIX}_file" >/dev/null 2>&1
    rm -f "$tmpfile"

    # Verify it exists
    local output
    output=$(smb_ls "${CRUD_PREFIX}_file")
    assert_contains "$output" "${CRUD_PREFIX}_file" "File should exist before delete" || {
        _crud_cleanup
        return 1
    }

    # Delete it
    smb_delete "${CRUD_PREFIX}_file" >/dev/null 2>&1

    # Verify it is gone
    output=$(smb_ls "${CRUD_PREFIX}_file" 2>&1)
    if echo "$output" | grep -q "${CRUD_PREFIX}_file" && ! echo "$output" | grep -qE "NO_SUCH_FILE|NOT_FOUND|OBJECT_NAME_NOT_FOUND"; then
        echo "File should not exist after delete" >&2
        _crud_cleanup
        return 1
    fi

    _crud_cleanup
}

# ============================================================================
# Test 5: Create directory, list contents, remove
# ============================================================================
test_directory_create_list_remove() {
    local desc="Create directory, list contents, remove it"
    _crud_cleanup 2>/dev/null

    # Create directory
    smb_mkdir "${CRUD_PREFIX}_dir" >/dev/null 2>&1

    # Verify directory exists
    local output
    output=$(smb_ls)
    assert_contains "$output" "${CRUD_PREFIX}_dir" "Directory should appear in listing" || {
        _crud_cleanup
        return 1
    }

    # Put a file inside it
    local tmpfile="${_HELPERS_TMPDIR}/crud_dirfile_$$"
    echo "inside directory" > "$tmpfile"
    smb_put_file "$tmpfile" "${CRUD_PREFIX}_dir/inner_file" >/dev/null 2>&1
    rm -f "$tmpfile"

    # List directory contents
    output=$(smb_ls "${CRUD_PREFIX}_dir/*")
    assert_contains "$output" "inner_file" "File inside directory should be listed" || {
        _crud_cleanup
        return 1
    }

    # Clean up: delete inner file, then directory
    smb_delete "${CRUD_PREFIX}_dir/inner_file" >/dev/null 2>&1
    smb_rmdir "${CRUD_PREFIX}_dir" >/dev/null 2>&1

    # Verify directory is gone
    output=$(smb_ls "${CRUD_PREFIX}_dir" 2>&1)
    if echo "$output" | grep -q "D.*${CRUD_PREFIX}_dir" && ! echo "$output" | grep -qE "NO_SUCH_FILE|NOT_FOUND"; then
        echo "Directory should not exist after removal" >&2
        return 1
    fi
}
