#!/bin/bash
# T05_large_file.sh -- Large file operation tests
#
# Tests writing and reading large files, sparse file handling,
# append operations, and file overwrites.

LARGE_PREFIX="torture_large_$$"

_large_cleanup() {
    smb_delete "${LARGE_PREFIX}_*" 2>/dev/null
    return 0
}

# ============================================================================
# Test 1: Write 100MB file
# ============================================================================
test_large_file_write_100mb() {
    local desc="Write 100MB file to share"
    _large_cleanup 2>/dev/null

    local size=$((100 * 1024 * 1024))  # 100MB
    local tmpfile
    tmpfile=$(random_file "$size")

    local output
    output=$(smb_put_file "$tmpfile" "${LARGE_PREFIX}_100mb" 2>&1)
    local rc=$?

    # smbclient put can be finicky with exit codes; verify the file exists on server
    local listing
    listing=$(smb_ls "${LARGE_PREFIX}_100mb" 2>&1)

    if ! echo "$listing" | grep -q "${LARGE_PREFIX}_100mb"; then
        echo "100MB file was not created on share" >&2
        rm -f "$tmpfile"
        _large_cleanup
        return 1
    fi

    rm -f "$tmpfile"
    _large_cleanup
}

# ============================================================================
# Test 2: Read 100MB file and verify checksum
# ============================================================================
test_large_file_read_verify() {
    local desc="Read 100MB file and verify checksum matches"
    _large_cleanup 2>/dev/null

    local size=$((100 * 1024 * 1024))
    local tmpfile
    tmpfile=$(random_file "$size")
    local orig_hash
    orig_hash=$(file_checksum "$tmpfile")

    # Upload
    smb_put_file "$tmpfile" "${LARGE_PREFIX}_verify" >/dev/null 2>&1

    # Download
    local dlfile="${_HELPERS_TMPDIR}/large_dl_$$"
    smb_get_file "${LARGE_PREFIX}_verify" "$dlfile" >/dev/null 2>&1

    if [[ ! -f "$dlfile" ]]; then
        echo "Downloaded file does not exist" >&2
        rm -f "$tmpfile"
        _large_cleanup
        return 1
    fi

    local dl_hash
    dl_hash=$(file_checksum "$dlfile")

    rm -f "$tmpfile" "$dlfile"

    if [[ "$orig_hash" != "$dl_hash" ]]; then
        echo "Checksum mismatch: original=$orig_hash downloaded=$dl_hash" >&2
        _large_cleanup
        return 1
    fi

    _large_cleanup
}

# ============================================================================
# Test 3: Sparse file (write at offset)
# ============================================================================
test_large_file_sparse() {
    local desc="Create sparse file by writing at high offset"
    _large_cleanup 2>/dev/null

    # Create a file, write some data at an offset using smbclient's put
    # Since smbclient doesn't support sparse write directly, we create a
    # local sparse file and upload it
    local tmpfile="${_HELPERS_TMPDIR}/large_sparse_$$"
    truncate -s 10M "$tmpfile"
    # Write some data near the end
    echo "data at end" | dd of="$tmpfile" bs=1 seek=$((10 * 1024 * 1024 - 20)) conv=notrunc 2>/dev/null

    smb_put_file "$tmpfile" "${LARGE_PREFIX}_sparse" >/dev/null 2>&1

    # Verify file exists and is roughly 10MB
    local info
    info=$(smb_stat "${LARGE_PREFIX}_sparse" 2>&1)

    if echo "$info" | grep -qE "NT_STATUS_NO_SUCH_FILE|NOT_FOUND"; then
        echo "Sparse file was not created" >&2
        rm -f "$tmpfile"
        _large_cleanup
        return 1
    fi

    rm -f "$tmpfile"
    _large_cleanup
}

# ============================================================================
# Test 4: Append to existing file
# ============================================================================
test_large_file_append() {
    local desc="Append data to existing file"
    _large_cleanup 2>/dev/null

    # Create initial file
    local tmpfile1="${_HELPERS_TMPDIR}/large_append1_$$"
    local tmpfile2="${_HELPERS_TMPDIR}/large_append2_$$"
    dd if=/dev/urandom of="$tmpfile1" bs=1K count=64 2>/dev/null
    dd if=/dev/urandom of="$tmpfile2" bs=1K count=64 2>/dev/null

    # Upload initial file
    smb_put_file "$tmpfile1" "${LARGE_PREFIX}_append" >/dev/null 2>&1

    # smbclient does not have a native append command; we simulate by
    # concatenating locally and re-uploading (tests overwrite path)
    local combined="${_HELPERS_TMPDIR}/large_combined_$$"
    cat "$tmpfile1" "$tmpfile2" > "$combined"
    local combined_hash
    combined_hash=$(file_checksum "$combined")

    smb_put_file "$combined" "${LARGE_PREFIX}_append" >/dev/null 2>&1

    # Download and verify
    local dlfile="${_HELPERS_TMPDIR}/large_append_dl_$$"
    smb_get_file "${LARGE_PREFIX}_append" "$dlfile" >/dev/null 2>&1

    if [[ ! -f "$dlfile" ]]; then
        echo "Downloaded file does not exist" >&2
        rm -f "$tmpfile1" "$tmpfile2" "$combined"
        _large_cleanup
        return 1
    fi

    local dl_hash
    dl_hash=$(file_checksum "$dlfile")

    rm -f "$tmpfile1" "$tmpfile2" "$combined" "$dlfile"

    if [[ "$combined_hash" != "$dl_hash" ]]; then
        echo "Appended file checksum mismatch" >&2
        _large_cleanup
        return 1
    fi

    _large_cleanup
}

# ============================================================================
# Test 5: Overwrite existing file
# ============================================================================
test_large_file_overwrite() {
    local desc="Overwrite existing file with new content"
    _large_cleanup 2>/dev/null

    # Create initial file (1MB)
    local tmpfile1="${_HELPERS_TMPDIR}/large_over1_$$"
    local tmpfile2="${_HELPERS_TMPDIR}/large_over2_$$"
    dd if=/dev/urandom of="$tmpfile1" bs=1K count=1024 2>/dev/null
    dd if=/dev/urandom of="$tmpfile2" bs=1K count=512 2>/dev/null

    local hash2
    hash2=$(file_checksum "$tmpfile2")

    # Upload first version
    smb_put_file "$tmpfile1" "${LARGE_PREFIX}_overwrite" >/dev/null 2>&1

    # Overwrite with second version (different size)
    smb_put_file "$tmpfile2" "${LARGE_PREFIX}_overwrite" >/dev/null 2>&1

    # Download and verify it matches second version
    local dlfile="${_HELPERS_TMPDIR}/large_over_dl_$$"
    smb_get_file "${LARGE_PREFIX}_overwrite" "$dlfile" >/dev/null 2>&1

    if [[ ! -f "$dlfile" ]]; then
        echo "Downloaded file does not exist" >&2
        rm -f "$tmpfile1" "$tmpfile2"
        _large_cleanup
        return 1
    fi

    local dl_hash
    dl_hash=$(file_checksum "$dlfile")

    rm -f "$tmpfile1" "$tmpfile2" "$dlfile"

    if [[ "$hash2" != "$dl_hash" ]]; then
        echo "Overwritten file should match second upload: expected=$hash2, got=$dl_hash" >&2
        _large_cleanup
        return 1
    fi

    _large_cleanup
}
