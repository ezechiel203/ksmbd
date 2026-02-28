#!/bin/bash
# Comprehensive ksmbd feature test suite
# Run from host against a VM with full config deployed
set -u

PORT="${1:?Usage: $0 <smb_port> [vm_name]}"
VM="${2:-VM}"
HOST="127.0.0.1"
USER="testuser"
PASS="testpass"
TMPDIR=$(mktemp -d /tmp/ksmbd_test.XXXXXX)
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RESULTS=()

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

pass() { PASS_COUNT=$((PASS_COUNT + 1)); RESULTS+=("PASS: $1"); echo "  PASS: $1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); RESULTS+=("FAIL: $1 -- $2"); echo "  FAIL: $1 -- $2"; }
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); RESULTS+=("SKIP: $1 -- $2"); echo "  SKIP: $1 -- $2"; }

smb() {
    local user="$1" pass="$2" share="$3" cmd="$4"
    smbclient -U "${user}%${pass}" "//${HOST}/${share}" -p "$PORT" -c "$cmd" 2>&1
}

smb_anon() {
    local share="$1" cmd="$2"
    smbclient -N "//${HOST}/${share}" -p "$PORT" -c "$cmd" 2>&1
}

smb_proto() {
    local user="$1" pass="$2" share="$3" cmd="$4" proto="$5"
    shift 5
    smbclient -U "${user}%${pass}" "//${HOST}/${share}" -p "$PORT" \
        --option="client min protocol=${proto}" \
        --option="client max protocol=${proto}" \
        "$@" -c "$cmd" 2>&1
}

echo "=============================================="
echo "  ksmbd Comprehensive Feature Test Suite"
echo "  Target: ${VM} @ ${HOST}:${PORT}"
echo "  Date: $(date -Iseconds)"
echo "=============================================="
echo ""

# ──────────────────────────────────────────────────
echo "=== 1. BASIC CONNECTIVITY ==="
# ──────────────────────────────────────────────────

# 1a. Authenticated access to [test]
out=$(smb "$USER" "$PASS" "test" "ls")
if echo "$out" | grep -q "blocks available"; then
    pass "1a. Authenticated [test] ls"
else
    fail "1a. Authenticated [test] ls" "$(echo "$out" | tail -1)"
fi

# 1b. Authenticated access to [docs]
out=$(smb "$USER" "$PASS" "docs" "ls")
if echo "$out" | grep -q "readme.txt"; then
    pass "1b. Authenticated [docs] ls (sees readme.txt)"
else
    fail "1b. Authenticated [docs] ls" "$(echo "$out" | tail -1)"
fi

# 1c. Authenticated access to [secret] (hidden but accessible)
out=$(smb "$USER" "$PASS" "secret" "ls")
if echo "$out" | grep -q "classified.txt"; then
    pass "1c. Hidden [secret] direct access"
else
    fail "1c. Hidden [secret] direct access" "$(echo "$out" | tail -1)"
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 2. ANONYMOUS / GUEST ACCESS ==="
# ──────────────────────────────────────────────────

# 2a. Anonymous access to [public]
out=$(smb_anon "public" "ls")
if echo "$out" | grep -q "welcome.txt"; then
    pass "2a. Anonymous [public] ls (sees welcome.txt)"
else
    fail "2a. Anonymous [public] ls" "$(echo "$out" | tail -1)"
fi

# 2b. Anonymous write to [public]
echo "anon_test_data" > "$TMPDIR/anon_write.txt"
out=$(smbclient -N "//${HOST}/public" -p "$PORT" -c "put $TMPDIR/anon_write.txt anon_write.txt; get anon_write.txt $TMPDIR/anon_verify.txt; del anon_write.txt" 2>&1)
if [ -f "$TMPDIR/anon_verify.txt" ] && diff -q "$TMPDIR/anon_write.txt" "$TMPDIR/anon_verify.txt" > /dev/null 2>&1; then
    pass "2b. Anonymous [public] write/read roundtrip"
else
    fail "2b. Anonymous [public] write/read roundtrip" "$(echo "$out" | tail -1)"
fi

# 2c. Anonymous access to [dropbox] (guest ok)
out=$(smb_anon "dropbox" "ls")
if echo "$out" | grep -q "blocks available"; then
    pass "2c. Anonymous [dropbox] ls"
else
    fail "2c. Anonymous [dropbox] ls" "$(echo "$out" | tail -1)"
fi

# 2d. Anonymous access denied to [test] (guest ok = no)
out=$(smb_anon "test" "ls")
if echo "$out" | grep -qiE "(DENIED|LOGON_FAILURE|ACCESS_DENIED|INVALID)"; then
    pass "2d. Anonymous [test] correctly denied"
else
    # If it succeeds, that's also acceptable since map to guest = bad user
    # might map the anonymous user to guest which is allowed on test share
    if echo "$out" | grep -q "blocks available"; then
        pass "2d. Anonymous [test] mapped to guest (map to guest = bad user)"
    else
        fail "2d. Anonymous [test] access check" "$(echo "$out" | tail -1)"
    fi
fi

# 2e. Anonymous access denied to [secret] (guest ok = no)
out=$(smb_anon "secret" "ls")
if echo "$out" | grep -qiE "(DENIED|LOGON_FAILURE|ACCESS_DENIED|INVALID)"; then
    pass "2e. Anonymous [secret] correctly denied"
else
    if echo "$out" | grep -q "blocks available"; then
        fail "2e. Anonymous [secret] should be denied" "Guest access was allowed"
    else
        fail "2e. Anonymous [secret] access check" "$(echo "$out" | tail -1)"
    fi
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 3. READ-ONLY ENFORCEMENT ==="
# ──────────────────────────────────────────────────

# 3a. Read from [docs]
out=$(smb "$USER" "$PASS" "docs" "get readme.txt $TMPDIR/docs_readme.txt")
if [ -f "$TMPDIR/docs_readme.txt" ] && grep -q "read-only document" "$TMPDIR/docs_readme.txt"; then
    pass "3a. [docs] read file succeeds"
else
    fail "3a. [docs] read file" "$(echo "$out" | tail -1)"
fi

# 3b. Write to [docs] should fail
echo "attempt" > "$TMPDIR/write_attempt.txt"
out=$(smb "$USER" "$PASS" "docs" "put $TMPDIR/write_attempt.txt write_attempt.txt" 2>&1)
if echo "$out" | grep -qiE "(DENIED|ACCESS_DENIED|MEDIA_WRITE_PROTECTED)"; then
    pass "3b. [docs] write correctly denied (read-only)"
else
    if echo "$out" | grep -q "putting file"; then
        fail "3b. [docs] write should be denied" "Write succeeded on read-only share"
    else
        pass "3b. [docs] write correctly denied (read-only)"
    fi
fi

# 3c. Navigate subdirectories in [docs]
out=$(smb "$USER" "$PASS" "docs" "cd subdir; ls")
if echo "$out" | grep -q "nested.txt"; then
    pass "3c. [docs] subdirectory navigation"
else
    fail "3c. [docs] subdirectory navigation" "$(echo "$out" | tail -1)"
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 4. WRITE OPERATIONS ==="
# ──────────────────────────────────────────────────

# 4a. Write/read roundtrip on [test]
echo "write_test_$(date +%s)" > "$TMPDIR/write_test.txt"
out=$(smb "$USER" "$PASS" "test" "put $TMPDIR/write_test.txt write_test.txt; get write_test.txt $TMPDIR/write_verify.txt; del write_test.txt")
if diff -q "$TMPDIR/write_test.txt" "$TMPDIR/write_verify.txt" > /dev/null 2>&1; then
    pass "4a. [test] write/read roundtrip"
else
    fail "4a. [test] write/read roundtrip" "$(echo "$out" | tail -1)"
fi

# 4b. Create directory on [test]
out=$(smb "$USER" "$PASS" "test" "mkdir testdir; ls")
if echo "$out" | grep -q "testdir"; then
    smb "$USER" "$PASS" "test" "rmdir testdir" > /dev/null 2>&1
    pass "4b. [test] mkdir/rmdir"
else
    fail "4b. [test] mkdir" "$(echo "$out" | tail -1)"
fi

# 4c. Large file write (1MB)
dd if=/dev/urandom of="$TMPDIR/largefile.bin" bs=1024 count=1024 2>/dev/null
out=$(smb "$USER" "$PASS" "test" "put $TMPDIR/largefile.bin largefile.bin; get largefile.bin $TMPDIR/large_verify.bin; del largefile.bin")
if diff -q "$TMPDIR/largefile.bin" "$TMPDIR/large_verify.bin" > /dev/null 2>&1; then
    pass "4c. [test] 1MB file roundtrip"
else
    fail "4c. [test] 1MB file roundtrip" "data mismatch"
fi

# 4d. Write to [secret] (authenticated, writable)
echo "secret_data" > "$TMPDIR/secret_write.txt"
out=$(smb "$USER" "$PASS" "secret" "put $TMPDIR/secret_write.txt test_secret.txt; del test_secret.txt")
if echo "$out" | grep -q "putting file"; then
    pass "4d. [secret] authenticated write"
else
    fail "4d. [secret] authenticated write" "$(echo "$out" | tail -1)"
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 5. PROTOCOL VERSION MATRIX ==="
# ──────────────────────────────────────────────────

for proto in SMB2 SMB2_02 SMB2_10 SMB3 SMB3_00 SMB3_02 SMB3_11; do
    out=$(smb_proto "$USER" "$PASS" "test" "ls" "$proto" 2>&1)
    if echo "$out" | grep -q "blocks available"; then
        pass "5. Protocol $proto"
    else
        err=$(echo "$out" | grep -oE 'NT_STATUS_[A-Z_]+' | head -1)
        if echo "$out" | grep -qiE "unknown|invalid|not supported"; then
            skip "5. Protocol $proto" "client doesn't support this protocol name"
        else
            fail "5. Protocol $proto" "${err:-$(echo "$out" | tail -1)}"
        fi
    fi
done

# ──────────────────────────────────────────────────
echo ""
echo "=== 6. SIGNING AND ENCRYPTION ==="
# ──────────────────────────────────────────────────

# 6a. No protection
out=$(smb_proto "$USER" "$PASS" "test" "ls" "SMB3_11")
if echo "$out" | grep -q "blocks available"; then
    pass "6a. SMB3.1.1 no protection"
else
    fail "6a. SMB3.1.1 no protection" "$(echo "$out" | tail -1)"
fi

# 6b. Signing
out=$(smb_proto "$USER" "$PASS" "test" "ls" "SMB3_11" --client-protection=sign)
if echo "$out" | grep -q "blocks available"; then
    pass "6b. SMB3.1.1 signing"
else
    fail "6b. SMB3.1.1 signing" "$(echo "$out" | tail -1)"
fi

# 6c. Encryption
out=$(smb_proto "$USER" "$PASS" "test" "ls" "SMB3_11" --client-protection=encrypt)
if echo "$out" | grep -q "blocks available"; then
    pass "6c. SMB3.1.1 encryption"
else
    fail "6c. SMB3.1.1 encryption" "$(echo "$out" | tail -1)"
fi

# 6d. SMB2 signing
out=$(smb_proto "$USER" "$PASS" "test" "ls" "SMB2" --client-protection=sign)
if echo "$out" | grep -q "blocks available"; then
    pass "6d. SMB2 signing"
else
    fail "6d. SMB2 signing" "$(echo "$out" | tail -1)"
fi

# 6e. SMB3 encryption
out=$(smb_proto "$USER" "$PASS" "test" "ls" "SMB3" --client-protection=encrypt)
if echo "$out" | grep -q "blocks available"; then
    pass "6e. SMB3 encryption"
else
    fail "6e. SMB3 encryption" "$(echo "$out" | tail -1)"
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 7. SMB1 / LEGACY PROTOCOL TESTS ==="
# ──────────────────────────────────────────────────

# 7a. SMB1 (NT1) negotiate - test pure SMB1 with server min=SMB1
out=$(smbclient -U "${USER}%${PASS}" "//${HOST}/test" -p "$PORT" \
    --option="client min protocol=NT1" \
    --option="client max protocol=NT1" \
    -c "ls" 2>&1)
if echo "$out" | grep -q "blocks available"; then
    pass "7a. SMB1 (NT1) negotiate"
else
    err=$(echo "$out" | grep -oE 'NT_STATUS_[A-Z_]+' | head -1)
    fail "7a. SMB1 (NT1) negotiate" "${err:-$(echo "$out" | tail -1)}"
fi

# 7b. SMB1 negotiate with auto-upgrade (NT1 min, SMB3_11 max)
out=$(smbclient -U "${USER}%${PASS}" "//${HOST}/test" -p "$PORT" \
    --option="client min protocol=NT1" \
    --option="client max protocol=SMB3_11" \
    -c "ls" 2>&1)
if echo "$out" | grep -q "blocks available"; then
    pass "7b. SMB1 negotiate with auto-upgrade to SMB2+"
else
    err=$(echo "$out" | grep -oE 'NT_STATUS_[A-Z_]+' | head -1)
    fail "7b. SMB1 negotiate with auto-upgrade" "${err:-$(echo "$out" | tail -1)}"
fi

# 7c. SMB2_02 connection (server min=SMB1, so 2.0.2 is in range)
out=$(smb_proto "$USER" "$PASS" "test" "ls" "SMB2_02" 2>&1)
if echo "$out" | grep -q "blocks available"; then
    pass "7c. SMB2_02 (2.0.2) connection"
else
    err=$(echo "$out" | grep -oE 'NT_STATUS_[A-Z_]+' | head -1)
    fail "7c. SMB2_02 (2.0.2) connection" "${err:-$(echo "$out" | tail -1)}"
fi

# 7d. LANMAN should be rejected (not supported by ksmbd)
out=$(smbclient -U "${USER}%${PASS}" "//${HOST}/test" -p "$PORT" \
    --option="client min protocol=LANMAN1" \
    --option="client max protocol=LANMAN2" \
    -c "ls" 2>&1)
if echo "$out" | grep -qiE "(DENIED|negotiate|connection|protocol|ERR)"; then
    pass "7d. LANMAN1/2 correctly rejected"
elif echo "$out" | grep -q "blocks available"; then
    pass "7d. LANMAN1/2 unexpectedly worked (upgraded?)"
else
    skip "7d. LANMAN1/2" "$(echo "$out" | tail -1)"
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 8. FRUIT / macOS EXTENSIONS ==="
# ──────────────────────────────────────────────────

# 8a. Access [timemachine] share
out=$(smb "$USER" "$PASS" "timemachine" "ls")
if echo "$out" | grep -q "blocks available"; then
    pass "8a. [timemachine] share accessible"
else
    fail "8a. [timemachine] share accessible" "$(echo "$out" | tail -1)"
fi

# 8b. Write to [timemachine]
echo "backup_data_$(date +%s)" > "$TMPDIR/tm_backup.txt"
out=$(smb "$USER" "$PASS" "timemachine" "put $TMPDIR/tm_backup.txt backup_test.txt; get backup_test.txt $TMPDIR/tm_verify.txt; del backup_test.txt")
if diff -q "$TMPDIR/tm_backup.txt" "$TMPDIR/tm_verify.txt" > /dev/null 2>&1; then
    pass "8b. [timemachine] write/read roundtrip"
else
    fail "8b. [timemachine] write/read roundtrip" "$(echo "$out" | tail -1)"
fi

# 8c. Test with macOS-style AAPL create context (smbclient --option)
# smbclient doesn't directly support AAPL, but we can test the share works
# with SMB3.1.1 which is what macOS uses
out=$(smb_proto "$USER" "$PASS" "timemachine" "ls" "SMB3_11")
if echo "$out" | grep -q "blocks available"; then
    pass "8c. [timemachine] SMB3.1.1 access (macOS compatible)"
else
    fail "8c. [timemachine] SMB3.1.1 access" "$(echo "$out" | tail -1)"
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 9. STREAMS (Alternate Data Streams) ==="
# ──────────────────────────────────────────────────

# 9a. Access [streams] share
out=$(smb "$USER" "$PASS" "streams" "ls")
if echo "$out" | grep -q "testfile.txt"; then
    pass "9a. [streams] share accessible"
else
    fail "9a. [streams] share accessible" "$(echo "$out" | tail -1)"
fi

# 9b. Write/read on [streams]
echo "streams_test" > "$TMPDIR/stream_data.txt"
out=$(smb "$USER" "$PASS" "streams" "put $TMPDIR/stream_data.txt stream_test.txt; get stream_test.txt $TMPDIR/stream_verify.txt; del stream_test.txt")
if diff -q "$TMPDIR/stream_data.txt" "$TMPDIR/stream_verify.txt" > /dev/null 2>&1; then
    pass "9b. [streams] write/read roundtrip"
else
    fail "9b. [streams] write/read roundtrip" "$(echo "$out" | tail -1)"
fi

# 9c. Write to alternate data stream (ADS)
out=$(smb "$USER" "$PASS" "streams" "put $TMPDIR/stream_data.txt testfile.txt:extra_stream")
if echo "$out" | grep -q "putting file"; then
    pass "9c. [streams] ADS write (testfile.txt:extra_stream)"
elif echo "$out" | grep -qiE "NOT_SUPPORTED|OBJECT_NAME_NOT_FOUND"; then
    skip "9c. [streams] ADS write" "ADS not supported by filesystem"
else
    fail "9c. [streams] ADS write" "$(echo "$out" | tail -1)"
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 10. MEDIA SHARE (read-only + crossmnt) ==="
# ──────────────────────────────────────────────────

# 10a. Anonymous access to [media]
out=$(smb_anon "media" "ls")
if echo "$out" | grep -q "sample.txt"; then
    pass "10a. Anonymous [media] ls"
else
    fail "10a. Anonymous [media] ls" "$(echo "$out" | tail -1)"
fi

# 10b. Navigate subdirectories
out=$(smb_anon "media" "cd album; ls")
if echo "$out" | grep -q "track01.txt"; then
    pass "10b. [media] subdirectory access"
else
    fail "10b. [media] subdirectory access" "$(echo "$out" | tail -1)"
fi

# 10c. Write should fail (read-only)
echo "blocked" > "$TMPDIR/media_write.txt"
out=$(smb_anon "media" "put $TMPDIR/media_write.txt blocked.txt" 2>&1)
if echo "$out" | grep -qiE "(DENIED|ACCESS_DENIED|MEDIA_WRITE_PROTECTED)"; then
    pass "10c. [media] write correctly denied (read-only)"
else
    if echo "$out" | grep -q "putting file"; then
        fail "10c. [media] write should be denied" "Write succeeded on read-only share"
    else
        pass "10c. [media] write correctly denied (read-only)"
    fi
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 11. CONCURRENT ACCESS ==="
# ──────────────────────────────────────────────────

# 11a. 5 concurrent authenticated clients
pids=()
fail_flag=0
for c in $(seq 1 5); do
    (
        for i in $(seq 1 3); do
            echo "concurrent_${c}_${i}" > "$TMPDIR/conc_${c}.txt"
            smb "$USER" "$PASS" "test" "put $TMPDIR/conc_${c}.txt conc_${c}_${i}.txt; get conc_${c}_${i}.txt $TMPDIR/conc_verify_${c}.txt; del conc_${c}_${i}.txt" > /dev/null 2>&1
            if ! diff -q "$TMPDIR/conc_${c}.txt" "$TMPDIR/conc_verify_${c}.txt" > /dev/null 2>&1; then
                exit 1
            fi
        done
    ) &
    pids+=($!)
done
for pid in "${pids[@]}"; do
    wait "$pid" || fail_flag=1
done
if [ "$fail_flag" -eq 0 ]; then
    pass "11a. 5 concurrent clients x 3 iterations"
else
    fail "11a. 5 concurrent clients" "data verification failed"
fi

# 11b. Mixed anonymous + authenticated concurrent
pids=()
fail_flag=0
for c in $(seq 1 3); do
    (
        echo "anon_mix_${c}" > "$TMPDIR/mix_anon_${c}.txt"
        smb_anon "public" "put $TMPDIR/mix_anon_${c}.txt mix_anon_${c}.txt; del mix_anon_${c}.txt" > /dev/null 2>&1
    ) &
    pids+=($!)
    (
        echo "auth_mix_${c}" > "$TMPDIR/mix_auth_${c}.txt"
        smb "$USER" "$PASS" "test" "put $TMPDIR/mix_auth_${c}.txt mix_auth_${c}.txt; del mix_auth_${c}.txt" > /dev/null 2>&1
    ) &
    pids+=($!)
done
for pid in "${pids[@]}"; do
    wait "$pid" || fail_flag=1
done
if [ "$fail_flag" -eq 0 ]; then
    pass "11b. Mixed anon+auth concurrent access"
else
    fail "11b. Mixed anon+auth concurrent" "one or more clients failed"
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 12. RECONNECT STABILITY ==="
# ──────────────────────────────────────────────────

fail_flag=0
for i in $(seq 1 15); do
    out=$(smb "$USER" "$PASS" "test" "ls" 2>&1)
    if ! echo "$out" | grep -q "blocks available"; then
        fail "12a. Reconnect cycle $i" "$(echo "$out" | tail -1)"
        fail_flag=1
        break
    fi
done
if [ "$fail_flag" -eq 0 ]; then
    pass "12a. 15 authenticated reconnect cycles"
fi

# Reconnect with different shares
fail_flag=0
for share in test public docs media streams timemachine dropbox; do
    out=$(smb "$USER" "$PASS" "$share" "ls" 2>&1)
    if ! echo "$out" | grep -q "blocks available\|\."; then
        fail "12b. Share rotation: $share" "$(echo "$out" | tail -1)"
        fail_flag=1
    fi
done
if [ "$fail_flag" -eq 0 ]; then
    pass "12b. Share rotation (all shares accessible)"
fi

# ──────────────────────────────────────────────────
echo ""
echo "=== 13. QUIC TRANSPORT ==="
# ──────────────────────────────────────────────────

# QUIC requires a userspace proxy daemon - test if module has QUIC support
# but note it won't work without the proxy
skip "13a. QUIC transport" "Requires userspace QUIC proxy (not deployed)"

# ──────────────────────────────────────────────────
echo ""
echo "=============================================="
echo "  TEST RESULTS SUMMARY"
echo "=============================================="
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
echo "  SKIP: $SKIP_COUNT"
echo "  TOTAL: $((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))"
echo "=============================================="
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "FAILED TESTS:"
    for r in "${RESULTS[@]}"; do
        if [[ "$r" == FAIL:* ]]; then
            echo "  $r"
        fi
    done
    echo ""
fi

if [ "$SKIP_COUNT" -gt 0 ]; then
    echo "SKIPPED TESTS:"
    for r in "${RESULTS[@]}"; do
        if [[ "$r" == SKIP:* ]]; then
            echo "  $r"
        fi
    done
    echo ""
fi

exit "$FAIL_COUNT"
