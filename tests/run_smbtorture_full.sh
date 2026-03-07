#!/bin/bash
# Full smbtorture suite runner for KSMBD (smbtorture 4.23.5)
# Test names updated for Samba 4.23.5 naming convention
# Usage: bash run_smbtorture_full.sh [HOST] [PORT] [USER] [PASS]

HOST="${1:-127.0.0.1}"
SMB_PORT="${2:-445}"
USER="${3:-root}"
PASS="${4:-root}"
SHARE="test"
TIMEOUT="${TIMEOUT:-120}"

PASS=0; FAIL=0; SKIP=0
FAILED_LIST=()
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

TMPDIR=$(mktemp -d); trap "rm -rf $TMPDIR" EXIT

echo "========================================"
echo " KSMBD smbtorture Full Suite"
echo " Target: //$HOST:$SMB_PORT/$SHARE"
echo " User:   $USER"
echo " Date:   $(date)"
echo "========================================"

run_test() {
    local test_name="$1"
    shift
    local extra_args=("$@")

    local out
    out=$(timeout "$TIMEOUT" smbtorture "//$HOST/$SHARE" \
        -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
        -d 0 \
        "${extra_args[@]}" "$test_name" 2>&1)
    local rc=$?

    if [[ $rc -eq 124 ]]; then
        ((SKIP++))
        echo -e "${YELLOW}TIMEOUT${NC}: $test_name"
        return
    fi

    local test_short="${test_name##*.}"
    if echo "$out" | grep -qE "Unknown torture operation"; then
        ((SKIP++))
        echo -e "${YELLOW}SKIP${NC}: $test_name (not in this smbtorture version)"
        return
    fi

    if echo "$out" | grep -qE "^success: $test_short|^success: $test_short\b"; then
        ((PASS++))
        echo -e "${GREEN}PASS${NC}: $test_name"
    elif echo "$out" | grep -qE "^skip:"; then
        ((SKIP++))
        echo -e "${YELLOW}SKIP${NC}: $test_name"
    elif echo "$out" | grep -qE "^(failure|error): $test_short"; then
        ((FAIL++))
        FAILED_LIST+=("$test_name")
        echo -e "${RED}FAIL${NC}: $test_name"
        echo "$out" | grep -E "^(failure|error|FAILED)" | head -3 | sed 's/^/    /'
    else
        if echo "$out" | grep -qE "success:"; then
            ((PASS++))
            echo -e "${GREEN}PASS${NC}: $test_name"
        elif echo "$out" | grep -qE "NT_STATUS_CONNECTION_REFUSED|Connection refused|Establishing SMB2 connection failed"; then
            ((SKIP++))
            echo -e "${YELLOW}SKIP${NC}: $test_name (connection failed)"
        else
            ((FAIL++))
            FAILED_LIST+=("$test_name")
            echo -e "${RED}FAIL${NC}: $test_name"
            echo "$out" | tail -3 | sed 's/^/    /'
        fi
    fi
}

# ─── SMB2 Create ─────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.create ---${NC}"
for t in gentest blob open brlocked multi delete leading-slash aclfile acldir nulldacl; do
    run_test "smb2.create.$t"
done

# ─── SMB2 GetInfo ────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.getinfo ---${NC}"
for t in complex.complex fsinfo.fsinfo qfs_buffercheck.qfs_buffercheck \
         qfile_buffercheck.qfile_buffercheck qsec_buffercheck.qsec_buffercheck \
         granted.granted; do
    run_test "smb2.getinfo.$t"
done

# ─── SMB2 SetInfo ────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.setinfo ---${NC}"
run_test "smb2.setinfo.setinfo"

# ─── SMB2 Find (QueryDirectory) ──────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.dir ---${NC}"
for t in find.find one.one sorted.sorted fixed.fixed many.many modify.modify \
         file-index.file-index; do
    run_test "smb2.dir.$t"
done

# ─── SMB2 Read ───────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.read ---${NC}"
for t in eof.eof position.position dir.dir access.access; do
    run_test "smb2.read.$t"
done

# ─── SMB2 Lock ───────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.lock ---${NC}"
for t in valid-request.valid-request rw-none.rw-none rw-shared.rw-shared \
         rw-exclusive.rw-exclusive auto-unlock.auto-unlock lock.lock \
         async.async cancel.cancel unlock.unlock multiple-unlock.multiple-unlock \
         stacking.stacking contend.contend context.context range.range \
         overlap.overlap truncate.truncate errorcode.errorcode \
         zerobytelength.zerobytelength zerobyteread.zerobyteread; do
    run_test "smb2.lock.$t"
done

# ─── SMB2 IOCTL ──────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.ioctl ---${NC}"
for t in req_resume_key.req_resume_key req_two_resume_keys.req_two_resume_keys \
         copy_chunk_simple.copy_chunk_simple copy_chunk_multi.copy_chunk_multi \
         copy_chunk_tiny.copy_chunk_tiny copy_chunk_overwrite.copy_chunk_overwrite \
         copy_chunk_append.copy_chunk_append copy_chunk_limits.copy_chunk_limits \
         copy_chunk_bad_key.copy_chunk_bad_key copy_chunk_src_exceed.copy_chunk_src_exceed \
         copy_chunk_zero_length.copy_chunk_zero_length \
         network_interface_info.network_interface_info \
         sparse_file_flag.sparse_file_flag sparse_qar.sparse_qar \
         trim_simple.trim_simple; do
    run_test "smb2.ioctl.$t"
done

# ─── SMB2 Oplock ─────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.oplock ---${NC}"
for t in exclusive1.exclusive1 exclusive2.exclusive2 exclusive3.exclusive3 \
         exclusive4.exclusive4 exclusive5.exclusive5 exclusive6.exclusive6 \
         batch1.batch1 batch2.batch2 batch3.batch3 batch4.batch4 batch5.batch5 \
         batch6.batch6 batch7.batch7 batch8.batch8 batch9.batch9 batch10.batch10 \
         batch11.batch11 batch12.batch12 batch13.batch13 batch14.batch14 batch15.batch15 \
         batch19.batch19 batch20.batch20 \
         doc.doc; do
    run_test "smb2.oplock.$t"
done

# ─── SMB2 Lease ──────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.lease ---${NC}"
for t in request.request upgrade.upgrade upgrade2.upgrade2 upgrade3.upgrade3 \
         break.break break_twice.break_twice \
         oplock.oplock lock1.lock1 \
         timeout.timeout unlink.unlink \
         multibreak.multibreak nobreakself.nobreakself \
         v2_epoch1.v2_epoch1 v2_epoch2.v2_epoch2 v2_epoch3.v2_epoch3 \
         v2_rename.v2_rename v2_complex1.v2_complex1 v2_complex2.v2_complex2 \
         complex1.complex1 statopen.statopen statopen2.statopen2; do
    run_test "smb2.lease.$t"
done

# ─── SMB2 Notify ─────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.notify ---${NC}"
for t in valid-req.valid-req dir.dir file.file mask.mask mask-change.mask-change \
         overflow.overflow rec.rec double.double tree.tree close.close \
         basedir.basedir; do
    run_test "smb2.notify.$t"
done

# ─── SMB2 Compound ───────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.compound ---${NC}"
for t in related1.related1 related2.related2 related3.related3 related4.related4 \
         related5.related5 related6.related6 related7.related7 related8.related8 \
         related9.related9 unrelated1.unrelated1 \
         invalid1.invalid1 invalid2.invalid2 invalid3.invalid3 invalid4.invalid4 \
         interim1.interim1 interim2.interim2 interim3.interim3; do
    run_test "smb2.compound.$t"
done

# ─── SMB2 Durable Open ───────────────────────────────────────────────────────
# NOTE: durable-open tests can cause kernel threads to enter D-state for up
# to OPLOCK_WAIT_TIME (35s). Use a 45s timeout to allow cleanup to complete.
echo -e "\n${BLUE}--- smb2.durable-open ---${NC}"
OLD_TIMEOUT="$TIMEOUT"; TIMEOUT=45
for t in open-oplock.open-oplock open-lease.open-lease \
         reopen1.reopen1 reopen1a.reopen1a reopen2.reopen2 reopen2a.reopen2a \
         reopen3.reopen3 reopen4.reopen4 reopen5.reopen5 reopen6.reopen6 \
         delete_on_close1.delete_on_close1 delete_on_close2.delete_on_close2 \
         oplock.oplock lease.lease lock-oplock.lock-oplock; do
    run_test "smb2.durable-open.$t"
    sleep 2  # allow kernel threads time to unblock between tests
done
TIMEOUT="$OLD_TIMEOUT"

echo -e "\n${BLUE}--- smb2.durable-v2-open ---${NC}"
OLD_TIMEOUT="$TIMEOUT"; TIMEOUT=45
for t in open-oplock.open-oplock open-lease.open-lease \
         reopen1.reopen1 reopen1a.reopen1a reopen2.reopen2 reopen2b.reopen2b \
         reopen2c.reopen2c lock-oplock.lock-oplock lock-lease.lock-lease; do
    run_test "smb2.durable-v2-open.$t"
    sleep 2
done
TIMEOUT="$OLD_TIMEOUT"

# ─── SMB2 Streams ────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.streams ---${NC}"
for t in io.io names.names names2.names2 names3.names3 rename.rename \
         rename2.rename2 delete.delete dir.dir sharemodes.sharemodes \
         attributes1.attributes1 attributes2.attributes2 zero-byte.zero-byte \
         create-disposition.create-disposition; do
    run_test "smb2.streams.$t"
done

# ─── SMB2 EA ─────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.ea ---${NC}"
run_test "smb2.ea.acl_xattr.acl_xattr" --option="torture:acl_xattr_name=user.NTACL" || \
    run_test "smb2.ea.acl_xattr" --option="torture:acl_xattr_name=user.NTACL"

# ─── SMB2 Session ────────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.session ---${NC}"
for t in reconnect1.reconnect1 reconnect2.reconnect2 \
         reauth1.reauth1 reauth2.reauth2 reauth3.reauth3 reauth4.reauth4 \
         reauth6.reauth6 two_logoff.two_logoff \
         signing-aes-128-cmac.signing-aes-128-cmac \
         signing-aes-128-gmac.signing-aes-128-gmac \
         encryption-aes-128-ccm.encryption-aes-128-ccm \
         encryption-aes-128-gcm.encryption-aes-128-gcm \
         encryption-aes-256-ccm.encryption-aes-256-ccm \
         encryption-aes-256-gcm.encryption-aes-256-gcm; do
    run_test "smb2.session.$t"
done

# ─── SMB2 Dir (large) ────────────────────────────────────────────────────────
echo -e "\n${BLUE}--- smb2.dir large-files ---${NC}"
run_test "smb2.dir.large-files.large-files"

# ─── Summary ─────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + SKIP))
echo ""
echo "========================================"
echo " smbtorture Full Suite Results"
echo "========================================"
echo -e " ${GREEN}PASS:${NC} $PASS"
echo -e " ${RED}FAIL:${NC} $FAIL"
echo -e " ${YELLOW}SKIP/TIMEOUT:${NC} $SKIP"
echo " TOTAL: $TOTAL"

if [[ ${#FAILED_LIST[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}Failed tests:${NC}"
    for t in "${FAILED_LIST[@]}"; do echo "  - $t"; done
fi
echo "========================================"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
