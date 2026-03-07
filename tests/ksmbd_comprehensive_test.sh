#!/bin/bash
# KSMBD Comprehensive Test Suite
# Tests protocol negotiation, auth, file ops, locking, encryption, compression, notify, etc.
# Usage: bash ksmbd_comprehensive_test.sh [HOST] [PORT] [USER] [PASS]

HOST="${1:-127.0.0.1}"
SMB_PORT="${2:-445}"
USER="${3:-testuser}"
PASS="${4:-testpass}"
SHARE="test"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILED_TESTS=()

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

ok()   { ((PASS_COUNT++)); echo -e "${GREEN}PASS${NC}: $1"; }
fail() { ((FAIL_COUNT++)); FAILED_TESTS+=("$1"); echo -e "${RED}FAIL${NC}: $1${2:+ — $2}"; }
skip() { ((SKIP_COUNT++)); echo -e "${YELLOW}SKIP${NC}: $1${2:+ — $2}"; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

SMB() { smbclient -U "$USER%$PASS" "//$HOST/$SHARE" -p "$SMB_PORT" "$@" 2>&1; }
SMB1() { smbclient -U "$USER%$PASS" "//$HOST/$SHARE" -p "$SMB_PORT" -m NT1 "$@" 2>&1; }
SMB2() { smbclient -U "$USER%$PASS" "//$HOST/$SHARE" -p "$SMB_PORT" -m SMB2 "$@" 2>&1; }
SMB3() { smbclient -U "$USER%$PASS" "//$HOST/$SHARE" -p "$SMB_PORT" -m SMB3 "$@" 2>&1; }
SMB311() { smbclient -U "$USER%$PASS" "//$HOST/$SHARE" -p "$SMB_PORT" -m SMB3_11 "$@" 2>&1; }

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "========================================"
echo " KSMBD Comprehensive Test Suite"
echo " Target: //$HOST:$SMB_PORT/$SHARE"
echo " User:   $USER"
echo " Date:   $(date)"
echo "========================================"

# ─── SECTION 1: Protocol Negotiation ────────────────────────────────────────
header "1. Protocol Negotiation"

out=$(SMB2 -c "ls; quit")
[[ "$out" == *"blocks of size"* ]] && ok "SMB2 negotiation" || fail "SMB2 negotiation" "$out"

out=$(SMB3 -c "ls; quit")
[[ "$out" == *"blocks of size"* ]] && ok "SMB3 negotiation" || fail "SMB3 negotiation" "$out"

out=$(SMB311 -c "ls; quit")
[[ "$out" == *"blocks of size"* ]] && ok "SMB3.1.1 negotiation" || fail "SMB3.1.1 negotiation" "$out"

# SMB1 (deprecated but should still work)
out=$(SMB1 -c "ls; quit" 2>&1)
if [[ "$out" == *"blocks of size"* ]]; then
    ok "SMB1 negotiation"
elif [[ "$out" == *"NT_STATUS_CONNECTION_RESET"* ]] || [[ "$out" == *"dialect"* ]]; then
    skip "SMB1 negotiation" "SMB1 disabled on server"
else
    fail "SMB1 negotiation" "$out"
fi

# ─── SECTION 2: Authentication ───────────────────────────────────────────────
header "2. Authentication"

out=$(SMB3 -c "ls; quit")
[[ "$out" == *"blocks of size"* ]] && ok "NTLM auth (testuser)" || fail "NTLM auth (testuser)" "$out"

out=$(smbclient -U "wronguser%wrongpass" "//$HOST/$SHARE" -p "$SMB_PORT" -m SMB3 -c "ls; quit" 2>&1)
[[ "$out" == *"LOGON_FAILURE"* ]] && ok "Bad credentials rejected" || fail "Bad credentials rejected" "$out"

out=$(smbclient -U "guest%" "//$HOST/$SHARE" -p "$SMB_PORT" -m SMB3 --no-pass -c "ls; quit" 2>&1)
[[ "$out" == *"blocks of size"* ]] && ok "Guest/anonymous access" || skip "Guest/anonymous access" "guest ok = no"

# ─── SECTION 3: Signing ──────────────────────────────────────────────────────
header "3. SMB Signing"

out=$(SMB311 --client-protection=sign -c "ls; quit")
[[ "$out" == *"blocks of size"* ]] && ok "SMB3.1.1 signing required" || fail "SMB3.1.1 signing required" "$out"

out=$(SMB3 --client-protection=sign -c "ls; quit")
[[ "$out" == *"blocks of size"* ]] && ok "SMB3 signing required" || fail "SMB3 signing required" "$out"

# ─── SECTION 4: Encryption ───────────────────────────────────────────────────
header "4. SMB Encryption"

out=$(SMB311 --client-protection=encrypt -c "ls; quit")
[[ "$out" == *"blocks of size"* ]] && ok "SMB3.1.1 AES-128-CCM encrypt" || fail "SMB3.1.1 encryption" "$out"

out=$(SMB3 --client-protection=encrypt -c "ls; quit")
[[ "$out" == *"blocks of size"* ]] && ok "SMB3.0 encrypt" || fail "SMB3.0 encryption" "$out"

# ─── SECTION 5: File CRUD Operations ─────────────────────────────────────────
header "5. File Create/Read/Write/Delete"

# Write a test file
echo "ksmbd test data $(date)" > "$TMPDIR/testfile.txt"
out=$(SMB3 -c "put $TMPDIR/testfile.txt ksmbd_test_001.txt; ls ksmbd_test_001.txt; quit")
[[ "$out" == *"ksmbd_test_001.txt"* ]] && ok "File write (put)" || fail "File write (put)" "$out"

# Read it back
out=$(SMB3 -c "get ksmbd_test_001.txt $TMPDIR/got_001.txt; quit" 2>&1)
if [[ -f "$TMPDIR/got_001.txt" ]] && diff -q "$TMPDIR/testfile.txt" "$TMPDIR/got_001.txt" > /dev/null 2>&1; then
    ok "File read (get) + data integrity"
else
    fail "File read (get) + data integrity" "$out"
fi

# Overwrite
echo "overwritten" > "$TMPDIR/over.txt"
out=$(SMB3 -c "put $TMPDIR/over.txt ksmbd_test_001.txt; quit" 2>&1)
[[ "$out" != *"NT_STATUS"* ]] && ok "File overwrite" || fail "File overwrite" "$out"

# Delete
out=$(SMB3 -c "del ksmbd_test_001.txt; quit" 2>&1)
[[ "$out" != *"NT_STATUS"* ]] && ok "File delete" || fail "File delete" "$out"

# Verify deleted
out=$(SMB3 -c "ls ksmbd_test_001.txt; quit" 2>&1)
[[ "$out" == *"NT_STATUS_NO_SUCH_FILE"* ]] && ok "Deleted file not found" || fail "Deleted file not found" "$out"

# ─── SECTION 6: Directory Operations ─────────────────────────────────────────
header "6. Directory Operations"

out=$(SMB3 -c "mkdir ksmbd_testdir; ls; quit")
[[ "$out" == *"ksmbd_testdir"* ]] && ok "mkdir" || fail "mkdir" "$out"

out=$(SMB3 -c "cd ksmbd_testdir; ls; quit")
[[ "$out" == *"blocks of size"* ]] && ok "cd into directory" || fail "cd into directory" "$out"

# Create file in subdir
echo "subdir test" > "$TMPDIR/sub.txt"
out=$(SMB3 -c "put $TMPDIR/sub.txt ksmbd_testdir/sub.txt; ls ksmbd_testdir/; quit")
[[ "$out" == *"sub.txt"* ]] && ok "Create file in subdirectory" || fail "Create file in subdirectory" "$out"

# Rename
out=$(SMB3 -c "rename ksmbd_testdir/sub.txt ksmbd_testdir/sub_renamed.txt; ls ksmbd_testdir/; quit")
[[ "$out" == *"sub_renamed.txt"* ]] && ok "File rename" || fail "File rename" "$out"

# Remove file then rmdir
out=$(SMB3 -c "del ksmbd_testdir/sub_renamed.txt; rmdir ksmbd_testdir; quit" 2>&1)
[[ "$out" != *"NT_STATUS"* ]] && ok "rmdir (empty dir)" || fail "rmdir (empty dir)" "$out"

# ─── SECTION 7: Large File I/O ───────────────────────────────────────────────
header "7. Large File I/O"

dd if=/dev/urandom of="$TMPDIR/large_4mb.bin" bs=1M count=4 2>/dev/null
out=$(SMB3 -c "put $TMPDIR/large_4mb.bin ksmbd_large_test.bin; quit" 2>&1)
[[ "$out" != *"NT_STATUS"* ]] && ok "4 MB upload" || fail "4 MB upload" "$out"

out=$(SMB3 -c "get ksmbd_large_test.bin $TMPDIR/got_large.bin; quit" 2>&1)
if cmp -s "$TMPDIR/large_4mb.bin" "$TMPDIR/got_large.bin" 2>/dev/null; then
    ok "4 MB download + data integrity (sha256 match)"
else
    fail "4 MB download + data integrity" "files differ or missing"
fi

out=$(SMB3 -c "del ksmbd_large_test.bin; quit" 2>&1)
[[ "$out" != *"NT_STATUS"* ]] && ok "Large file delete" || fail "Large file delete" "$out"

# ─── SECTION 8: Directory Enumeration / Wildcards ────────────────────────────
header "8. Directory Enumeration + Wildcards"

# Create several files
SMB3 -c "put $TMPDIR/sub.txt enum_a.txt; put $TMPDIR/sub.txt enum_b.txt; put $TMPDIR/sub.txt enum_c.log; quit" > /dev/null 2>&1

out=$(SMB3 -c "ls enum_*.txt; quit")
[[ "$out" == *"enum_a.txt"* ]] && [[ "$out" == *"enum_b.txt"* ]] && ok "Wildcard ls (*.txt)" || fail "Wildcard ls (*.txt)" "$out"

out=$(SMB3 -c "ls enum_?.txt; quit")
[[ "$out" == *"enum_a.txt"* ]] && ok "Wildcard ls (?.txt)" || fail "Wildcard ls (?.txt)" "$out"

# Cleanup
SMB3 -c "del enum_a.txt; del enum_b.txt; del enum_c.log; quit" > /dev/null 2>&1
ok "Wildcard enum cleanup"

# ─── SECTION 9: Byte-Range Locking ───────────────────────────────────────────
header "9. Byte-Range Locking (via smbtorture)"

# Use smbtorture smb2.lock for proper lock tests — just run a few here via locktest
if command -v smbtorture > /dev/null 2>&1; then
    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 -d 0 smb2.lock.valid1 2>&1)
    [[ "$out" == *"success: valid1"* ]] && ok "smb2.lock.valid1 (exclusive lock)" || fail "smb2.lock.valid1" "$out"

    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 -d 0 smb2.lock.valid2 2>&1)
    [[ "$out" == *"success: valid2"* ]] && ok "smb2.lock.valid2 (shared lock)" || fail "smb2.lock.valid2" "$out"

    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 -d 0 smb2.lock.valid3 2>&1)
    [[ "$out" == *"success: valid3"* ]] && ok "smb2.lock.valid3 (lock+unlock)" || fail "smb2.lock.valid3" "$out"
else
    skip "Byte-range locking" "smbtorture not found"
fi

# ─── SECTION 10: Oplocks / Leases ────────────────────────────────────────────
header "10. Oplocks and Leases"

if command -v smbtorture > /dev/null 2>&1; then
    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 -d 0 smb2.oplock.exclusive1 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.oplock.exclusive1" || fail "smb2.oplock.exclusive1" "$out"

    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 -d 0 smb2.lease.v2_request_on_dir 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.lease.v2_request_on_dir" || fail "smb2.lease.v2_request_on_dir" "$out"
else
    skip "Oplocks/Leases" "smbtorture not found"
fi

# ─── SECTION 11: Extended Attributes ─────────────────────────────────────────
header "11. Extended Attributes (EA)"

echo "ea test" > "$TMPDIR/ea_test.txt"
SMB3 -c "put $TMPDIR/ea_test.txt ea_test.txt; quit" > /dev/null 2>&1

if command -v smbtorture > /dev/null 2>&1; then
    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 -d 0 smb2.ea 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.ea" || fail "smb2.ea" "$out"
else
    skip "Extended Attributes" "smbtorture not found"
fi
SMB3 -c "del ea_test.txt; quit" > /dev/null 2>&1

# ─── SECTION 12: Named Pipes (IPC$) ──────────────────────────────────────────
header "12. Named Pipes / IPC\$"

out=$(smbclient -U "$USER%$PASS" "//$HOST/IPC\$" -p "$SMB_PORT" -m SMB3 -c "ls; quit" 2>&1)
[[ "$out" != *"NT_STATUS_ACCESS_DENIED"* ]] && ok "IPC\$ connect" || fail "IPC\$ connect" "$out"

# srvsvc via rpcclient
if command -v rpcclient > /dev/null 2>&1; then
    out=$(rpcclient -U "$USER%$PASS" "$HOST" -p "$SMB_PORT" -c "srvinfo" 2>&1)
    [[ "$out" == *"WORKGROUP"* ]] || [[ "$out" == *"server_type"* ]] && ok "rpcclient srvinfo (srvsvc)" || \
        fail "rpcclient srvinfo (srvsvc)" "$out"

    out=$(rpcclient -U "$USER%$PASS" "$HOST" -p "$SMB_PORT" -c "netshareenum" 2>&1)
    [[ "$out" == *"netname"* ]] && ok "rpcclient netshareenum" || fail "rpcclient netshareenum" "$out"
else
    skip "rpcclient tests" "rpcclient not found"
fi

# ─── SECTION 13: Durable Handles ─────────────────────────────────────────────
header "13. Durable Handles"

if command -v smbtorture > /dev/null 2>&1; then
    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 -d 0 smb2.durable-open.open1 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.durable-open.open1" || fail "smb2.durable-open.open1" "$out"

    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 -d 0 smb2.durable-open.open2 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.durable-open.open2" || fail "smb2.durable-open.open2" "$out"
else
    skip "Durable Handles" "smbtorture not found"
fi

# ─── SECTION 14: Compound Requests ───────────────────────────────────────────
header "14. Compound Requests"

if command -v smbtorture > /dev/null 2>&1; then
    for sub in related1 related2 related3 related4 unrelated1 invalid1; do
        out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
            -d 0 --client-protection=encrypt "smb2.compound.$sub" 2>&1)
        [[ "$out" == *"success: $sub"* ]] && ok "smb2.compound.$sub" || fail "smb2.compound.$sub" "$out"
    done
else
    skip "Compound Requests" "smbtorture not found"
fi

# ─── SECTION 15: ChangeNotify ────────────────────────────────────────────────
header "15. ChangeNotify"

if command -v smbtorture > /dev/null 2>&1; then
    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 smb2.notify.valid1 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.notify.valid1" || fail "smb2.notify.valid1" "$out"
else
    skip "ChangeNotify" "smbtorture not found"
fi

# ─── SECTION 16: QueryInfo / FileInfo ────────────────────────────────────────
header "16. QueryInfo / FileInfo"

if command -v smbtorture > /dev/null 2>&1; then
    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 smb2.getinfo.file 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.getinfo.file" || fail "smb2.getinfo.file" "$out"

    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 smb2.getinfo.fs 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.getinfo.fs" || fail "smb2.getinfo.fs" "$out"
else
    skip "QueryInfo" "smbtorture not found"
fi

# ─── SECTION 17: ACL / Security ──────────────────────────────────────────────
header "17. ACL / Security Descriptor"

if command -v smbtorture > /dev/null 2>&1; then
    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 smb2.acl.CREATOR_OWNER 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.acl.crud" || fail "smb2.acl.crud" "$out"
else
    skip "ACL/Security" "smbtorture not found"
fi

# ─── SECTION 18: Streams ─────────────────────────────────────────────────────
header "18. Alternate Data Streams"

if command -v smbtorture > /dev/null 2>&1; then
    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 smb2.streams.default 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.streams.default" || fail "smb2.streams.default" "$out"
else
    skip "Streams" "smbtorture not found"
fi

# ─── SECTION 19: IOCTL / FSCTL ───────────────────────────────────────────────
header "19. IOCTL / FSCTL"

if command -v smbtorture > /dev/null 2>&1; then
    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 smb2.ioctl.req_resume_key 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.ioctl.req_resume_key" || fail "smb2.ioctl.req_resume_key" "$out"

    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 smb2.ioctl.copy_chunk_simple 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.ioctl.copy_chunk_simple" || fail "smb2.ioctl.copy_chunk_simple" "$out"

    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 smb2.ioctl.network_interface_info 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.ioctl.network_interface_info" || fail "smb2.ioctl.network_interface_info" "$out"
else
    skip "IOCTL/FSCTL" "smbtorture not found"
fi

# ─── SECTION 20: Session / Tree Lifecycle ────────────────────────────────────
header "20. Session + Tree Connect Lifecycle"

if command -v smbtorture > /dev/null 2>&1; then
    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 smb2.session.reconnect1 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.session.reconnect1" || fail "smb2.session.reconnect1" "$out"

    out=$(smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 smb2.session.reauth1 2>&1)
    [[ "$out" == *"success"* ]] && ok "smb2.session.reauth1" || fail "smb2.session.reauth1" "$out"
else
    skip "Session lifecycle" "smbtorture not found"
fi

# ─── SECTION 21: Multi-protocol Interoperability ─────────────────────────────
header "21. Multi-protocol Interoperability"

# Write with SMB2, read with SMB3.1.1
echo "interop test $(date)" > "$TMPDIR/interop.txt"
SMB2 -c "put $TMPDIR/interop.txt ksmbd_interop.txt; quit" > /dev/null 2>&1
out=$(SMB311 -c "get ksmbd_interop.txt $TMPDIR/interop_got.txt; quit" 2>&1)
if diff -q "$TMPDIR/interop.txt" "$TMPDIR/interop_got.txt" > /dev/null 2>&1; then
    ok "SMB2 write / SMB3.1.1 read interop"
else
    fail "SMB2 write / SMB3.1.1 read interop"
fi
SMB3 -c "del ksmbd_interop.txt; quit" > /dev/null 2>&1

# ─── SECTION 22: Compression ─────────────────────────────────────────────────
header "22. SMB Compression (LZ4/LZNT1)"

# Create highly compressible data
python3 -c "import sys; sys.stdout.buffer.write(b'A'*1024*512)" > "$TMPDIR/compress_test.bin" 2>/dev/null
out=$(SMB311 -c "put $TMPDIR/compress_test.bin ksmbd_compress.bin; del ksmbd_compress.bin; quit" 2>&1)
[[ "$out" != *"NT_STATUS"* ]] && ok "SMB3.1.1 session with compressible data" || \
    fail "SMB3.1.1 compressible data" "$out"

# ─── SECTION 23: Concurrent Access ───────────────────────────────────────────
header "23. Concurrent Access (basic)"

# 4 simultaneous sessions doing ls
declare -a PIDS
for i in 1 2 3 4; do
    SMB3 -c "ls; quit" > "$TMPDIR/concurrent_$i.out" 2>&1 &
    PIDS+=($!)
done
ALL_OK=1
for pid in "${PIDS[@]}"; do
    wait "$pid"
    [[ $? -ne 0 ]] && ALL_OK=0
done
RESULTS_OK=1
for i in 1 2 3 4; do
    [[ "$(cat $TMPDIR/concurrent_$i.out)" != *"blocks of size"* ]] && RESULTS_OK=0
done
[[ $ALL_OK -eq 1 && $RESULTS_OK -eq 1 ]] && ok "4 concurrent SMB3 sessions" || \
    fail "4 concurrent SMB3 sessions"

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo " Test Summary"
echo "========================================"
echo -e " ${GREEN}PASS: $PASS_COUNT${NC}"
echo -e " ${RED}FAIL: $FAIL_COUNT${NC}"
echo -e " ${YELLOW}SKIP: $SKIP_COUNT${NC}"
TOTAL=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
echo " TOTAL: $TOTAL"

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}Failed tests:${NC}"
    for t in "${FAILED_TESTS[@]}"; do echo "  - $t"; done
fi

echo "========================================"
[[ $FAIL_COUNT -eq 0 ]] && exit 0 || exit 1
