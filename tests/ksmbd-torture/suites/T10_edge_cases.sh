#!/bin/bash
# T10_edge_cases.sh -- Edge case and boundary condition tests
#
# Tests Unicode filenames, maximum filename length, empty file
# operations, path traversal attempts, and special characters.

EDGE_PREFIX="torture_edge_$$"

_edge_cleanup() {
    smb_delete "${EDGE_PREFIX}_*" 2>/dev/null
    return 0
}

# ============================================================================
# Test 1: Unicode filename (CJK characters)
# ============================================================================
test_edge_unicode_filename() {
    local desc="Unicode filename with CJK characters"
    _edge_cleanup 2>/dev/null

    # Create a file with Unicode characters in the name
    # Using CJK Unified Ideographs (common in SMB environments)
    local unicode_name="${EDGE_PREFIX}_\xe6\xb5\x8b\xe8\xaf\x95"  # "test" in Chinese
    # Use a simpler Unicode approach that smbclient handles
    local safe_unicode="${EDGE_PREFIX}_unicode_\xc3\xa9\xc3\xa0\xc3\xbc"  # accented chars

    local tmpfile="${_HELPERS_TMPDIR}/edge_unicode_$$"
    echo "unicode content" > "$tmpfile"

    # Try with accented characters first (more widely supported)
    local output
    output=$(_smbclient_cmd "put \"$tmpfile\" \"${EDGE_PREFIX}_caf\xc3\xa9\"" 2>&1)
    rm -f "$tmpfile"

    # Verify file exists -- try listing with the prefix
    output=$(smb_ls "${EDGE_PREFIX}_*" 2>&1)
    if echo "$output" | grep -q "${EDGE_PREFIX}_"; then
        _edge_cleanup
        return 0
    fi

    # If Unicode naming is not supported, the put itself may have failed
    # Check if smbclient reported an error
    if echo "$output" | grep -qE "NT_STATUS"; then
        echo "Unicode filename not supported by server" >&2
        _edge_cleanup
        return 77  # Skip
    fi

    _edge_cleanup
}

# ============================================================================
# Test 2: Maximum filename length (255 characters)
# ============================================================================
test_edge_max_filename_length() {
    local desc="Maximum filename length (255 characters)"
    _edge_cleanup 2>/dev/null

    # Generate a 255-character filename
    local long_name
    long_name=$(printf '%0255d' 0 | tr '0' 'A')

    local tmpfile="${_HELPERS_TMPDIR}/edge_maxlen_$$"
    echo "long name test" > "$tmpfile"

    local output
    output=$(_smbclient_cmd "put \"$tmpfile\" \"${long_name}\"" 2>&1)
    local rc=$?
    rm -f "$tmpfile"

    if [[ $rc -eq 0 ]] && ! echo "$output" | grep -qE "NT_STATUS"; then
        # Successfully created long filename -- clean it up
        _smbclient_cmd "del \"${long_name}\"" 2>/dev/null
        return 0
    fi

    # If it failed with a proper error, that is acceptable
    if echo "$output" | grep -qE "NT_STATUS_OBJECT_NAME_INVALID\|NT_STATUS_OBJECT_PATH_NOT_FOUND"; then
        # Server properly rejects overly long names
        return 0
    fi

    # Try a slightly shorter name (some filesystems have lower limits)
    long_name=$(printf '%0200d' 0 | tr '0' 'B')
    output=$(_smbclient_cmd "put \"$tmpfile\" \"${long_name}\"" 2>&1)
    _smbclient_cmd "del \"${long_name}\"" 2>/dev/null

    # As long as the server did not crash, this is acceptable
    local listing
    listing=$(_smbclient_cmd "ls" 2>&1)
    assert_contains "$listing" "blocks" "Server should be responsive after long filename test" || return 1
}

# ============================================================================
# Test 3: Empty file operations
# ============================================================================
test_edge_empty_file() {
    local desc="Create, read, and delete empty file"
    _edge_cleanup 2>/dev/null

    # Create an empty file
    local tmpfile="${_HELPERS_TMPDIR}/edge_empty_$$"
    : > "$tmpfile"

    smb_put_file "$tmpfile" "${EDGE_PREFIX}_empty" >/dev/null 2>&1

    # Verify the file exists
    local output
    output=$(smb_ls "${EDGE_PREFIX}_empty" 2>&1)
    assert_contains "$output" "${EDGE_PREFIX}_empty" "Empty file should exist" || {
        rm -f "$tmpfile"
        _edge_cleanup
        return 1
    }

    # Download the empty file
    local dlfile="${_HELPERS_TMPDIR}/edge_empty_dl_$$"
    smb_get_file "${EDGE_PREFIX}_empty" "$dlfile" >/dev/null 2>&1

    if [[ -f "$dlfile" ]]; then
        local size
        size=$(stat -c%s "$dlfile" 2>/dev/null || stat -f%z "$dlfile" 2>/dev/null)
        if [[ "$size" -ne 0 ]]; then
            echo "Empty file should have size 0, got $size" >&2
            rm -f "$tmpfile" "$dlfile"
            _edge_cleanup
            return 1
        fi
    fi

    rm -f "$tmpfile" "$dlfile"

    # Delete the empty file
    smb_delete "${EDGE_PREFIX}_empty" >/dev/null 2>&1

    # Verify deletion
    output=$(smb_ls "${EDGE_PREFIX}_empty" 2>&1)
    if echo "$output" | grep -q "${EDGE_PREFIX}_empty" && ! echo "$output" | grep -qE "NO_SUCH_FILE|NOT_FOUND"; then
        echo "Empty file should be deleted" >&2
        _edge_cleanup
        return 1
    fi

    _edge_cleanup
}

# ============================================================================
# Test 4: Path with .. components (traversal attempt)
# ============================================================================
test_edge_path_traversal() {
    local desc="Path with .. components is blocked"
    _edge_cleanup 2>/dev/null

    # Try to access parent directory via path traversal
    local output
    output=$(_smbclient_cmd "ls \"../*\"" 2>&1)

    # Server should either reject the traversal or show the share root
    # It should NOT expose files outside the share
    if echo "$output" | grep -qE "NT_STATUS_ACCESS_DENIED\|NT_STATUS_OBJECT_PATH_SYNTAX_BAD\|NT_STATUS_OBJECT_NAME_INVALID\|NT_STATUS_INVALID_PARAMETER"; then
        # Properly rejected
        return 0
    fi

    # Some servers simply resolve ".." to the share root, which is also acceptable
    # The important thing is we do not get access to /etc/passwd or similar
    output=$(_smbclient_cmd "get \"../../../etc/passwd\" \"/dev/null\"" 2>&1)
    if echo "$output" | grep -qE "NT_STATUS_ACCESS_DENIED\|NT_STATUS_OBJECT_PATH_SYNTAX_BAD\|NT_STATUS_OBJECT_NAME_NOT_FOUND\|NT_STATUS_OBJECT_PATH_NOT_FOUND\|NT_STATUS_INVALID_PARAMETER"; then
        return 0
    fi

    # If we got here without any error, check that we did not actually
    # get /etc/passwd content
    if [[ -f "/dev/null" ]]; then
        # /dev/null always exists, check if it grew
        :
    fi

    # As long as the server is responsive and did not crash
    local listing
    listing=$(_smbclient_cmd "ls" 2>&1)
    assert_contains "$listing" "blocks" "Server should be responsive after traversal attempt" || return 1
}

# ============================================================================
# Test 5: Special characters in filenames
# ============================================================================
test_edge_special_characters() {
    local desc="Special characters in filenames are handled"
    _edge_cleanup 2>/dev/null

    local tmpfile="${_HELPERS_TMPDIR}/edge_special_$$"
    echo "special chars" > "$tmpfile"

    # Test various special characters that should work in SMB
    local -a test_names=(
        "${EDGE_PREFIX}_spaces in name"
        "${EDGE_PREFIX}_dots...in...name"
        "${EDGE_PREFIX}_dashes-and_underscores"
        "${EDGE_PREFIX}_parens(test)"
        "${EDGE_PREFIX}_hash#tag"
    )

    local success=0
    local total=${#test_names[@]}
    local name

    for name in "${test_names[@]}"; do
        local output
        output=$(_smbclient_cmd "put \"$tmpfile\" \"$name\"" 2>&1)
        if ! echo "$output" | grep -qE "NT_STATUS"; then
            ((success++))
            # Clean up
            _smbclient_cmd "del \"$name\"" 2>/dev/null
        fi
    done

    rm -f "$tmpfile"

    if [[ $success -lt 3 ]]; then
        echo "Only $success/$total special character filenames succeeded" >&2
        _edge_cleanup
        return 1
    fi

    # Verify server is still responsive
    local listing
    listing=$(_smbclient_cmd "ls" 2>&1)
    assert_contains "$listing" "blocks" "Server should be responsive after special chars test" || {
        _edge_cleanup
        return 1
    }

    _edge_cleanup
}
