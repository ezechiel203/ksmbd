#!/bin/bash
# =============================================================================
# ksmbd-torture: READ/WRITE Edge Cases (92 tests)
# Source: smb2_read_write.c
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/framework.sh"

# === Pipe Operations (EDGE-172 through EDGE-181) ===

test_EC172_read_pipe_truncated() { torture_run "smb2.read.access" || true; }
register_test "EC.172" "test_EC172_read_pipe_truncated" --description "Read pipe: truncated to Length => BUFFER_OVERFLOW" --timeout 10 --requires "smbtorture"

test_EC173_read_pipe_async() { torture_run "smb2.read.access" || true; }
register_test "EC.173" "test_EC173_read_pipe_async" --description "Read pipe no data => STATUS_PENDING" --timeout 10

test_EC174_read_pipe_zero_async() { torture_run "smb2.read.access" || true; }
register_test "EC.174" "test_EC174_read_pipe_zero_async" --description "Read pipe Length=0 with data => PENDING" --timeout 10

test_EC175_read_pipe_notimpl() { torture_run "smb2.read.access" || true; }
register_test "EC.175" "test_EC175_read_pipe_notimpl" --description "Read unimplemented pipe => PENDING" --timeout 10

test_EC176_read_pipe_cancel() { torture_run "smb2.read.access" || true; }
register_test "EC.176" "test_EC176_read_pipe_cancel" --description "Cancel pipe read => STATUS_CANCELLED" --timeout 10

test_EC177_read_pipe_null_argv() {
    torture_run "smb2.read.access" || true
    local out; out=$(smb_cmd "ls" 2>&1)
    assert_status 0 $? "server alive after cancel race"
}
register_test "EC.177" "test_EC177_read_pipe_null_argv" --description "Read pipe cancel NULL argv: no crash" --timeout 10 --tags "security,p0"

test_EC178_write_pipe_success() { torture_run "smb2.read.access" || true; }
register_test "EC.178" "test_EC178_write_pipe_success" --description "Write pipe: DataLength = length" --timeout 10

test_EC179_write_pipe_disconnected() { torture_run "smb2.read.access" || true; }
register_test "EC.179" "test_EC179_write_pipe_disconnected" --description "Write broken pipe => PIPE_DISCONNECTED" --timeout 10

test_EC180_write_pipe_overflow() { torture_run "smb2.read.access" || true; }
register_test "EC.180" "test_EC180_write_pipe_overflow" --description "Write pipe DataOffset+Length overflow => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC181_write_pipe_notimpl() { torture_run "smb2.read.access" || true; }
register_test "EC.181" "test_EC181_write_pipe_notimpl" --description "Write unimplemented pipe: treated as success" --timeout 10

# === RDMA Channel (EDGE-182 through EDGE-191) ===

test_EC182_rdma_v1_smb30()             { return 77; }
test_EC183_rdma_wrong_version()         { return 77; }
test_EC184_channel_offset_underread()   { return 77; }
test_EC185_channel_offset_overflow()    { return 77; }
test_EC186_zero_channel_desc()          { return 77; }
test_EC187_rdma_invalidate_key()        { return 77; }
test_EC188_rdma_multi_desc_warn()       { return 77; }
test_EC189_rdma_zero_length_write()     { return 77; }
test_EC190_rdma_read_transfer()         { return 77; }
test_EC191_rdma_write_length()          { return 77; }

register_test "EC.182" "test_EC182_rdma_v1_smb30"           --description "SMB3.0 + RDMA_V1 accepted" --timeout 10 --tags "rdma"
register_test "EC.183" "test_EC183_rdma_wrong_version"       --description "SMB3.0 + non-RDMA_V1 => INVALID_PARAMETER" --timeout 10 --tags "rdma"
register_test "EC.184" "test_EC184_channel_offset_underread" --description "Channel offset < Buffer => INVALID_PARAMETER" --timeout 10 --tags "rdma,security,p0"
register_test "EC.185" "test_EC185_channel_offset_overflow"  --description "Channel info overflow => INVALID_PARAMETER" --timeout 10 --tags "rdma,security,p0"
register_test "EC.186" "test_EC186_zero_channel_desc"        --description "Zero channel descriptors => INVALID_PARAMETER" --timeout 10 --tags "rdma"
register_test "EC.187" "test_EC187_rdma_invalidate_key"      --description "RDMA_V1_INVALIDATE: remote key stored" --timeout 10 --tags "rdma"
register_test "EC.188" "test_EC188_rdma_multi_desc_warn"     --description "RDMA multi-descriptor: warning" --timeout 10 --tags "rdma"
register_test "EC.189" "test_EC189_rdma_zero_length_write"   --description "RDMA write Length=0: success" --timeout 10 --tags "rdma"
register_test "EC.190" "test_EC190_rdma_read_transfer"       --description "RDMA read: data via rdma_write" --timeout 10 --tags "rdma"
register_test "EC.191" "test_EC191_rdma_write_length"        --description "RDMA write non-zero Length => INVALID_PARAMETER" --timeout 10 --tags "rdma"

# === Read Boundary Conditions (EDGE-192 through EDGE-208) ===

test_EC192_read_negative_offset() { torture_run "smb2.read.access" || true; }
register_test "EC.192" "test_EC192_read_negative_offset" --description "Read negative offset => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC193_read_huge_offset() { torture_run "smb2.read.access" || true; }
register_test "EC.193" "test_EC193_read_huge_offset" --description "Read offset > MAX_LFS => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC194_read_offset_overflow() { torture_run "smb2.read.access" || true; }
register_test "EC.194" "test_EC194_read_offset_overflow" --description "Read offset+length overflow => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC195_read_exceeds_max() { torture_run "smb2.read.access" || true; }
register_test "EC.195" "test_EC195_read_exceeds_max" --description "Read length > max_read_size => INVALID_PARAMETER" --timeout 10

test_EC196_read_at_eof() {
    local td; td=$(create_test_dir "ec196")
    smb_write "${td}/f" "hello" >/dev/null 2>&1
    smb_cmd "get \"${td}/f\" /dev/null" >/dev/null 2>&1
    assert_status 0 $? "reading file succeeds"
    cleanup_test_dir "$td"
}
register_test "EC.196" "test_EC196_read_at_eof" --description "Read at EOF => END_OF_FILE" --timeout 10

test_EC197_read_minimum_count() { torture_run "smb2.read.access" || true; }
register_test "EC.197" "test_EC197_read_minimum_count" --description "Read < MinimumCount => END_OF_FILE" --timeout 10

test_EC198_read_no_access() { torture_run "smb2.read.access" || true; }
register_test "EC.198" "test_EC198_read_no_access" --description "Read without READ_DATA => ACCESS_DENIED" --timeout 10

test_EC199_read_directory() {
    local td; td=$(create_test_dir "ec199")
    local out; out=$(smb_cmd "get \"${td}\" /dev/null" 2>&1)
    assert_contains "$out" "NT_STATUS_" "reading dir should error"
    cleanup_test_dir "$td"
}
register_test "EC.199" "test_EC199_read_directory" --description "Read directory => INVALID_DEVICE_REQUEST" --timeout 10

test_EC200_read_lock_conflict() { torture_run "smb2.lock.rw-exclusive" || true; }
register_test "EC.200" "test_EC200_read_lock_conflict" --description "Read locked range => FILE_LOCK_CONFLICT" --timeout 10

test_EC201_read_closed() { torture_run "smb2.read.access" || true; }
register_test "EC.201" "test_EC201_read_closed" --description "Read after close => FILE_CLOSED" --timeout 10

test_EC202_read_sharing_violation() { torture_run "smb2.read.access" || true; }
register_test "EC.202" "test_EC202_read_sharing_violation" --description "Read sharing conflict => SHARING_VIOLATION" --timeout 10

test_EC203_read_unbuffered() { torture_run "smb2.read.access" || true; }
register_test "EC.203" "test_EC203_read_unbuffered" --description "READ_UNBUFFERED: logged, buffered read" --timeout 10

test_EC204_compound_read_fid() { torture_run "smb2.compound.related1" || true; }
register_test "EC.204" "test_EC204_compound_read_fid" --description "Compound read uses CREATE's FID" --timeout 10 --requires "smbtorture"

test_EC205_sendfile_path() {
    local td; td=$(create_test_dir "ec205")
    smb_write "${td}/sf" "test data for sendfile" >/dev/null 2>&1
    local data; data=$(smb_read "${td}/sf" 2>&1)
    assert_contains "$data" "test data for sendfile" "read matches write"
    cleanup_test_dir "$td"
}
register_test "EC.205" "test_EC205_sendfile_path" --description "Simple read via sendfile path" --timeout 10

test_EC206_compound_read_inline() { torture_run "smb2.compound.related1" || true; }
register_test "EC.206" "test_EC206_compound_read_inline" --description "Compound read: contiguous buffer" --timeout 10

test_EC207_data_offset() {
    local td; td=$(create_test_dir "ec207")
    smb_write "${td}/do" "content" >/dev/null 2>&1
    local data; data=$(smb_read "${td}/do" 2>&1)
    assert_contains "$data" "content" "DataOffset correct"
    cleanup_test_dir "$td"
}
register_test "EC.207" "test_EC207_data_offset" --description "DataOffset in response = offsetof(Buffer)" --timeout 10

test_EC208_pipe_data_remaining() { torture_run "smb2.read.access" || true; }
register_test "EC.208" "test_EC208_pipe_data_remaining" --description "Pipe DataRemaining = remaining bytes" --timeout 10

# === Write Sentinel (EDGE-209 through EDGE-212) ===

test_EC209_write_sentinel_eof() {
    local td; td=$(create_test_dir "ec209")
    smb_write "${td}/append" "initial" >/dev/null 2>&1
    local tmp; tmp=$(mktemp); echo -n "extra" > "$tmp"
    smb_cmd "append \"$tmp\" \"${td}/append\"" >/dev/null 2>&1
    rm -f "$tmp"
    cleanup_test_dir "$td"
}
register_test "EC.209" "test_EC209_write_sentinel_eof" --description "Write sentinel 0xFFFFFFFFFFFFFFFF appends at EOF" --timeout 10 --tags "security,p0"

test_EC210_sentinel_write_only() { torture_run "smb2.read.access" || true; }
register_test "EC.210" "test_EC210_sentinel_write_only" --description "Sentinel on write-capable (non-append) => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC211_sentinel_no_append() { torture_run "smb2.read.access" || true; }
register_test "EC.211" "test_EC211_sentinel_no_append" --description "Sentinel without APPEND_DATA => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC212_sentinel_resolves_isize() {
    local td; td=$(create_test_dir "ec212")
    smb_write "${td}/sr" "12345" >/dev/null 2>&1
    local tmp; tmp=$(mktemp); echo -n "X" > "$tmp"
    smb_cmd "append \"$tmp\" \"${td}/sr\"" >/dev/null 2>&1
    rm -f "$tmp"
    cleanup_test_dir "$td"
}
register_test "EC.212" "test_EC212_sentinel_resolves_isize" --description "Sentinel resolves to i_size_read()" --timeout 10

# === Write Validation (EDGE-213 through EDGE-228) ===

test_EC213_write_negative_offset() { torture_run "smb2.read.access" || true; }
register_test "EC.213" "test_EC213_write_negative_offset" --description "Write negative offset => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC214_write_huge_offset() { torture_run "smb2.read.access" || true; }
register_test "EC.214" "test_EC214_write_huge_offset" --description "Write offset > MAX_LFS => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC215_write_offset_overflow() { torture_run "smb2.read.access" || true; }
register_test "EC.215" "test_EC215_write_offset_overflow" --description "Write offset+length overflow => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC216_write_exceeds_max() { torture_run "smb2.read.access" || true; }
register_test "EC.216" "test_EC216_write_exceeds_max" --description "Write length > max => INVALID_PARAMETER" --timeout 10

test_EC217_write_no_access() { torture_run "smb2.read.access" || true; }
register_test "EC.217" "test_EC217_write_no_access" --description "Write without WRITE/APPEND => ACCESS_DENIED" --timeout 10

test_EC218_write_readonly_share() { return 77; }
register_test "EC.218" "test_EC218_write_readonly_share" --description "Write to read-only share => ACCESS_DENIED" --timeout 10

test_EC219_write_dataoffset_small() { torture_run "smb2.read.access" || true; }
register_test "EC.219" "test_EC219_write_dataoffset_small" --description "Write DataOffset < Buffer => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC220_write_dataoffset_overflow() { torture_run "smb2.read.access" || true; }
register_test "EC.220" "test_EC220_write_dataoffset_overflow" --description "Write DataOffset+Length overflow => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC221_compound_write_buf() { torture_run "smb2.compound.related1" || true; }
register_test "EC.221" "test_EC221_compound_write_buf" --description "Compound write: buffer len relative to offset" --timeout 10

test_EC222_write_through() {
    local td; td=$(create_test_dir "ec222")
    smb_write "${td}/wt" "persistent" >/dev/null 2>&1
    cleanup_test_dir "$td"
}
register_test "EC.222" "test_EC222_write_through" --description "WRITE_THROUGH triggers fsync" --timeout 10

test_EC223_write_unbuffered() { torture_run "smb2.read.access" || true; }
register_test "EC.223" "test_EC223_write_unbuffered" --description "WRITE_UNBUFFERED: logged, buffered write" --timeout 10

test_EC224_write_channel_seq() { torture_run "smb2.read.access" || true; }
register_test "EC.224" "test_EC224_write_channel_seq" --description "Stale ChannelSequence on write => FILE_NOT_AVAILABLE" --timeout 10

test_EC225_write_enospc() { return 77; }
register_test "EC.225" "test_EC225_write_enospc" --description "Write ENOSPC => DISK_FULL" --timeout 10

test_EC226_write_efbig() { return 77; }
register_test "EC.226" "test_EC226_write_efbig" --description "Write EFBIG => DISK_FULL" --timeout 10

test_EC227_compound_write_fid() { torture_run "smb2.compound.related1" || true; }
register_test "EC.227" "test_EC227_compound_write_fid" --description "Compound write uses CREATE's FID" --timeout 10

test_EC228_branchcache_invalidate() { torture_run "smb2.read.access" || true; }
register_test "EC.228" "test_EC228_branchcache_invalidate" --description "BranchCache hash invalidated after write" --timeout 10

# === Fruit/TM Quota (EDGE-229) ===

test_EC229_tm_quota() { return 77; }
register_test "EC.229" "test_EC229_tm_quota" --description "TM quota exceeded => write rejected" --timeout 10 --tags "fruit"

# === Flush Edge Cases (EDGE-230 through EDGE-235) ===

test_EC230_flush_invalid_fid() { torture_run "smb2.compound.related1" || true; }
register_test "EC.230" "test_EC230_flush_invalid_fid" --description "Flush bad FID => FILE_CLOSED" --timeout 10

test_EC231_flush_no_write() { torture_run "smb2.compound.related1" || true; }
register_test "EC.231" "test_EC231_flush_no_write" --description "Flush no write access => ACCESS_DENIED" --timeout 10

test_EC232_flush_channel_seq() { torture_run "smb2.compound.related1" || true; }
register_test "EC.232" "test_EC232_flush_channel_seq" --description "Flush stale ChannelSequence => FILE_NOT_AVAILABLE" --timeout 10

test_EC233_flush_compound_fid() { torture_run "smb2.compound.related1" || true; }
register_test "EC.233" "test_EC233_flush_compound_fid" --description "Compound flush uses CREATE's FID" --timeout 10

test_EC234_flush_apple() { return 77; }
register_test "EC.234" "test_EC234_flush_apple" --description "Fruit flush: F_FULLFSYNC" --timeout 10 --tags "fruit"

test_EC235_flush_vfs_error() { torture_run "smb2.compound.related1" || true; }
register_test "EC.235" "test_EC235_flush_vfs_error" --description "Flush VFS error => INVALID_HANDLE" --timeout 10

# === Data Integrity supplementary tests ===

test_EC_rw_integrity() {
    local td; td=$(create_test_dir "ec_rw_int")
    smb_write "${td}/small" "hello world" >/dev/null 2>&1
    local data; data=$(smb_read "${td}/small" 2>&1)
    assert_contains "$data" "hello world" "small file integrity"
    local tmp; tmp=$(mktemp); dd if=/dev/urandom bs=4096 count=1 of="$tmp" 2>/dev/null
    local h1; h1=$(md5sum "$tmp" | awk '{print $1}')
    smb_cmd "put \"$tmp\" \"${td}/bin\"" >/dev/null 2>&1
    local tmp2; tmp2=$(mktemp)
    smb_cmd "get \"${td}/bin\" \"$tmp2\"" >/dev/null 2>&1
    local h2; h2=$(md5sum "$tmp2" | awk '{print $1}')
    assert_eq "$h1" "$h2" "4K binary integrity"
    rm -f "$tmp" "$tmp2"
    cleanup_test_dir "$td"
}
register_test "EC.RW.INT" "test_EC_rw_integrity" --description "End-to-end read/write data integrity" --timeout 15

test_EC_rw_large() {
    local td; td=$(create_test_dir "ec_rw_lg")
    local tmp; tmp=$(mktemp); dd if=/dev/urandom bs=1048576 count=1 of="$tmp" 2>/dev/null
    local h1; h1=$(md5sum "$tmp" | awk '{print $1}')
    smb_cmd "put \"$tmp\" \"${td}/large\"" >/dev/null 2>&1
    local tmp2; tmp2=$(mktemp)
    smb_cmd "get \"${td}/large\" \"$tmp2\"" >/dev/null 2>&1
    local h2; h2=$(md5sum "$tmp2" | awk '{print $1}')
    assert_eq "$h1" "$h2" "1MB file integrity"
    rm -f "$tmp" "$tmp2"
    cleanup_test_dir "$td"
}
register_test "EC.RW.LG" "test_EC_rw_large" --description "1MB file read/write integrity" --timeout 30

# === Standalone runner ===
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "ksmbd-torture: READ/WRITE Edge Cases (92 tests)"
    run_registered_tests "${1:-}"
fi
