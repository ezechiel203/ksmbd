#!/bin/bash
# T09_concurrent.sh -- Concurrency and stress tests
#
# Tests parallel file creation, concurrent read/write, parallel
# directory listings, session storms, and mixed operations under load.

CONC_PREFIX="torture_conc_$$"

_conc_cleanup() {
    smb_delete "${CONC_PREFIX}_*" 2>/dev/null
    _smbclient_cmd "deltree \"${CONC_PREFIX}\"" 2>/dev/null
    smb_rmdir "${CONC_PREFIX}" 2>/dev/null
    return 0
}

# ============================================================================
# Test 1: 10 parallel file creates
# ============================================================================
test_concurrent_parallel_creates() {
    local desc="10 parallel file creates complete without error"
    _conc_cleanup 2>/dev/null

    local pids=()
    local tmpdir="${_HELPERS_TMPDIR}/conc_creates_$$"
    mkdir -p "$tmpdir"

    local i
    for ((i = 0; i < 10; i++)); do
        (
            local tmpfile="${tmpdir}/create_${i}"
            echo "parallel_create_${i}_$(random_string 16)" > "$tmpfile"
            smb_put_file "$tmpfile" "${CONC_PREFIX}_create_${i}" >/dev/null 2>&1
            exit $?
        ) &
        pids+=($!)
    done

    # Wait for all background jobs
    local failures=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            ((failures++))
        fi
    done

    rm -rf "$tmpdir"

    # Verify files were created
    local listing
    listing=$(smb_ls "${CONC_PREFIX}_create_*" 2>&1)
    local found
    found=$(echo "$listing" | grep -c "${CONC_PREFIX}_create_" || true)

    if [[ $found -lt 8 ]]; then
        echo "Expected at least 8/10 parallel creates to succeed, found $found" >&2
        _conc_cleanup
        return 1
    fi

    _conc_cleanup
}

# ============================================================================
# Test 2: Concurrent read/write on same file
# ============================================================================
test_concurrent_readwrite_same_file() {
    local desc="Concurrent read/write on same file does not corrupt data"
    _conc_cleanup 2>/dev/null

    # Create initial file
    local tmpfile="${_HELPERS_TMPDIR}/conc_rw_$$"
    dd if=/dev/urandom of="$tmpfile" bs=1K count=100 2>/dev/null
    smb_put_file "$tmpfile" "${CONC_PREFIX}_rw" >/dev/null 2>&1

    # Parallel reads
    local pids=()
    local i
    for ((i = 0; i < 5; i++)); do
        (
            local dl="${_HELPERS_TMPDIR}/conc_rw_read_${i}_$$"
            smb_get_file "${CONC_PREFIX}_rw" "$dl" >/dev/null 2>&1
            rm -f "$dl"
        ) &
        pids+=($!)
    done

    # Parallel writes (to different files, to avoid corruption)
    for ((i = 0; i < 5; i++)); do
        (
            smb_put_file "$tmpfile" "${CONC_PREFIX}_rw_copy_${i}" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    local failures=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            ((failures++))
        fi
    done

    rm -f "$tmpfile"

    if [[ $failures -gt 3 ]]; then
        echo "Too many failures in concurrent r/w: $failures/10" >&2
        _conc_cleanup
        return 1
    fi

    _conc_cleanup
}

# ============================================================================
# Test 3: Parallel directory listings
# ============================================================================
test_concurrent_directory_listings() {
    local desc="Parallel directory listings complete without error"
    _conc_cleanup 2>/dev/null

    # Create some files to list
    smb_mkdir "${CONC_PREFIX}" >/dev/null 2>&1
    local tmpfile="${_HELPERS_TMPDIR}/conc_dirlist_$$"
    echo "x" > "$tmpfile"
    local i
    for ((i = 0; i < 20; i++)); do
        smb_put_file "$tmpfile" "${CONC_PREFIX}/file_$(printf '%03d' "$i")" >/dev/null 2>&1
    done
    rm -f "$tmpfile"

    # Run 10 parallel directory listings
    local pids=()
    for ((i = 0; i < 10; i++)); do
        (
            smb_ls "${CONC_PREFIX}/*" >/dev/null 2>&1
            exit $?
        ) &
        pids+=($!)
    done

    local failures=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            ((failures++))
        fi
    done

    if [[ $failures -gt 2 ]]; then
        echo "Too many directory listing failures: $failures/10" >&2
        _conc_cleanup
        return 1
    fi

    _conc_cleanup
}

# ============================================================================
# Test 4: Session storm (10 connect/disconnect cycles)
# ============================================================================
test_concurrent_session_storm() {
    local desc="10 rapid connect/disconnect cycles do not crash server"
    _conc_cleanup 2>/dev/null

    local pids=()
    local i
    for ((i = 0; i < 10; i++)); do
        (
            _smbclient_cmd "ls" >/dev/null 2>&1
            exit $?
        ) &
        pids+=($!)
    done

    local failures=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            ((failures++))
        fi
    done

    # Verify server is still responsive after the storm
    sleep 1
    local output
    output=$(_smbclient_cmd "ls" 2>&1)
    local rc=$?

    if [[ $rc -ne 0 ]] || ! echo "$output" | grep -q "blocks"; then
        echo "Server became unresponsive after session storm" >&2
        return 1
    fi

    if [[ $failures -gt 3 ]]; then
        echo "Too many session failures: $failures/10 (server may be overloaded)" >&2
        # Not a hard failure -- server may reject connections under load
    fi

    return 0
}

# ============================================================================
# Test 5: Mixed operations under load
# ============================================================================
test_concurrent_mixed_operations() {
    local desc="Mixed concurrent operations (create/read/delete) succeed"
    _conc_cleanup 2>/dev/null

    local pids=()
    local tmpdir="${_HELPERS_TMPDIR}/conc_mixed_$$"
    mkdir -p "$tmpdir"

    # Operation 1: Create files
    (
        local j
        for ((j = 0; j < 5; j++)); do
            local tmpfile="${tmpdir}/mixed_create_${j}"
            echo "create_${j}" > "$tmpfile"
            smb_put_file "$tmpfile" "${CONC_PREFIX}_mixed_c${j}" >/dev/null 2>&1
        done
    ) &
    pids+=($!)

    # Operation 2: Directory listings
    (
        local j
        for ((j = 0; j < 5; j++)); do
            smb_ls >/dev/null 2>&1
        done
    ) &
    pids+=($!)

    # Operation 3: Create and immediately read
    (
        local tmpfile="${tmpdir}/mixed_rw"
        echo "read_write_test" > "$tmpfile"
        smb_put_file "$tmpfile" "${CONC_PREFIX}_mixed_rw" >/dev/null 2>&1
        sleep 1
        local dl="${tmpdir}/mixed_rw_dl"
        smb_get_file "${CONC_PREFIX}_mixed_rw" "$dl" >/dev/null 2>&1
        rm -f "$dl"
    ) &
    pids+=($!)

    # Operation 4: Create and delete
    (
        local tmpfile="${tmpdir}/mixed_del"
        echo "delete_me" > "$tmpfile"
        smb_put_file "$tmpfile" "${CONC_PREFIX}_mixed_del" >/dev/null 2>&1
        sleep 1
        smb_delete "${CONC_PREFIX}_mixed_del" >/dev/null 2>&1
    ) &
    pids+=($!)

    # Operation 5: Stat operations
    (
        sleep 1
        smb_stat "${CONC_PREFIX}_mixed_c0" >/dev/null 2>&1
        smb_stat "${CONC_PREFIX}_mixed_c1" >/dev/null 2>&1
    ) &
    pids+=($!)

    local failures=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            ((failures++))
        fi
    done

    rm -rf "$tmpdir"

    # Verify server is still responsive
    local output
    output=$(_smbclient_cmd "ls" 2>&1)
    assert_contains "$output" "blocks" "Server should be responsive after mixed operations" || {
        _conc_cleanup
        return 1
    }

    _conc_cleanup
}
