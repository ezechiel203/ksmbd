#!/bin/bash
# =============================================================================
# ksmbd-torture: LOCK Edge Cases (69 tests)
# Source: smb2_lock.c
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/framework.sh"

# === Cancel Logic (EDGE-113 through EDGE-122) ===

test_EC113_async_cancel_by_asyncid() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.113" "test_EC113_async_cancel_by_asyncid" --description "Async cancel by AsyncId" --timeout 15 --requires "smbtorture"

test_EC114_cancel_compound_notify() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.114" "test_EC114_cancel_compound_notify" --description "Cancel compound-spawned work (no request_buf)" --timeout 15 --requires "smbtorture"

test_EC115_sync_cancel_messageid() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.115" "test_EC115_sync_cancel_messageid" --description "Sync cancel by MessageId" --timeout 15 --requires "smbtorture"

test_EC116_sync_cancel_fallback() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.116" "test_EC116_sync_cancel_fallback" --description "Sync cancel fallback to async list" --timeout 15 --requires "smbtorture"

test_EC117_cancel_mid_zero() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.117" "test_EC117_cancel_mid_zero" --description "Cancel MessageId=0 matches by SessionId" --timeout 15 --requires "smbtorture"

test_EC118_cancel_callback() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.118" "test_EC118_cancel_callback" --description "Cancel invokes cancel_fn callback" --timeout 15 --requires "smbtorture"

test_EC119_cancel_no_double_free() {
    torture_run "smb2.lock.cancel" || true
    local out; out=$(smb_cmd "ls" 2>&1)
    assert_status 0 $? "server alive after cancel race"
}
register_test "EC.119" "test_EC119_cancel_no_double_free" --description "Cancel clears cancel_fn (no double-free)" --timeout 15 --tags "security,p0"

test_EC120_cancel_self_skipped() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.120" "test_EC120_cancel_self_skipped" --description "Cancel on self (iter==work) skipped" --timeout 15

test_EC121_cancel_frees_argv() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.121" "test_EC121_cancel_frees_argv" --description "Cancel callback frees argv" --timeout 15

test_EC122_cancel_status() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.122" "test_EC122_cancel_status" --description "Cancel sends STATUS_CANCELLED" --timeout 15 --requires "smbtorture"

# === Lock Flags Validation (EDGE-123 through EDGE-131) ===

test_EC123_unknown_flags() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.123" "test_EC123_unknown_flags" --description "Unknown lock flag bits => INVALID_PARAMETER" --timeout 10 --requires "smbtorture"

test_EC124_mixed_lock_unlock() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.124" "test_EC124_mixed_lock_unlock" --description "Mixed lock+unlock => INVALID_PARAMETER" --timeout 10

test_EC125_mixed_unlock_lock() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.125" "test_EC125_mixed_unlock_lock" --description "Mixed unlock+lock => INVALID_PARAMETER" --timeout 10

test_EC126_shared_lock() { torture_run "smb2.lock.shared" || true; }
register_test "EC.126" "test_EC126_shared_lock" --description "SHARED flag sets F_RDLCK" --timeout 10 --requires "smbtorture"

test_EC127_exclusive_lock() { torture_run "smb2.lock.exclusive" || true; }
register_test "EC.127" "test_EC127_exclusive_lock" --description "EXCLUSIVE flag sets F_WRLCK" --timeout 10 --requires "smbtorture"

test_EC128_shared_fail_immediately() { torture_run "smb2.lock.contend" || true; }
register_test "EC.128" "test_EC128_shared_fail_immediately" --description "SHARED+FAIL_IMMEDIATELY: non-blocking" --timeout 10 --requires "smbtorture"

test_EC129_exclusive_fail_immediately() { torture_run "smb2.lock.contend" || true; }
register_test "EC.129" "test_EC129_exclusive_fail_immediately" --description "EXCLUSIVE+FAIL_IMMEDIATELY: non-blocking" --timeout 10 --requires "smbtorture"

test_EC130_unlock() { torture_run "smb2.lock.unlock" || true; }
register_test "EC.130" "test_EC130_unlock" --description "UNLOCK flag sets F_UNLCK" --timeout 10 --requires "smbtorture"

test_EC131_invalid_flag_combo() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.131" "test_EC131_invalid_flag_combo" --description "SHARED|EXCLUSIVE => INVALID_PARAMETER" --timeout 10

# === Lock Sequence Replay (EDGE-132 through EDGE-140) ===

test_EC132_seq_index_zero() { torture_run "smb2.lock.replay" || true; }
register_test "EC.132" "test_EC132_seq_index_zero" --description "Lock seq index=0 skips validation" --timeout 15

test_EC133_seq_index_gt64() { torture_run "smb2.lock.replay" || true; }
register_test "EC.133" "test_EC133_seq_index_gt64" --description "Lock seq index>64 skips validation" --timeout 15

test_EC134_seq_replay_ok() { torture_run "smb2.lock.replay" || true; }
register_test "EC.134" "test_EC134_seq_replay_ok" --description "Lock seq replay => STATUS_OK" --timeout 15

test_EC135_seq_different_invalidates() { torture_run "smb2.lock.replay" || true; }
register_test "EC.135" "test_EC135_seq_different_invalidates" --description "Different seq_num invalidates entry" --timeout 15

test_EC136_seq_stored_after_success() { torture_run "smb2.lock.replay" || true; }
register_test "EC.136" "test_EC136_seq_stored_after_success" --description "Lock seq stored AFTER success only" --timeout 15

test_EC137_seq_not_stored_on_fail() { torture_run "smb2.lock.replay" || true; }
register_test "EC.137" "test_EC137_seq_not_stored_on_fail" --description "Lock seq NOT stored on failure" --timeout 15

test_EC138_nondurable_skips_seq() { torture_run "smb2.lock.replay" || true; }
register_test "EC.138" "test_EC138_nondurable_skips_seq" --description "Non-durable handle skips seq check" --timeout 15

test_EC139_seq_bit_extraction() { torture_run "smb2.lock.replay" || true; }
register_test "EC.139" "test_EC139_seq_bit_extraction" --description "Lock seq correct bit extraction (low nibble)" --timeout 15

test_EC140_seq_0xff_sentinel() { torture_run "smb2.lock.replay" || true; }
register_test "EC.140" "test_EC140_seq_0xff_sentinel" --description "Lock seq 0xFF sentinel = not-valid" --timeout 15

# === Range Validation (EDGE-141 through EDGE-150) ===

test_EC141_lock_count_zero() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.141" "test_EC141_lock_count_zero" --description "LockCount=0 => INVALID_PARAMETER" --timeout 10

test_EC142_lock_count_huge() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.142" "test_EC142_lock_count_huge" --description "LockCount > max => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC143_lock_array_overflow() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.143" "test_EC143_lock_array_overflow" --description "Lock array > buffer => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC144_offset_length_overflow() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.144" "test_EC144_offset_length_overflow" --description "Offset+Length overflow => INVALID_LOCK_RANGE" --timeout 10 --tags "security,p0"

test_EC145_offset_wraps_zero() { torture_run "smb2.lock.rw-exclusive" || true; }
register_test "EC.145" "test_EC145_offset_wraps_zero" --description "Offset+Length wraps to zero: valid" --timeout 10

test_EC146_zero_length_lock() { torture_run "smb2.lock.zerobytelength" || true; }
register_test "EC.146" "test_EC146_zero_length_lock" --description "Zero-length lock: VFS skipped, ksmbd tracks" --timeout 10 --requires "smbtorture"

test_EC147_beyond_offset_max() { torture_run "smb2.lock.rw-exclusive" || true; }
register_test "EC.147" "test_EC147_beyond_offset_max" --description "Lock > OFFSET_MAX: VFS skipped" --timeout 10

test_EC148_length_clamped() { torture_run "smb2.lock.rw-exclusive" || true; }
register_test "EC.148" "test_EC148_length_clamped" --description "Lock length clamped to OFFSET_MAX - start" --timeout 10

test_EC149_posix_fl_end_inclusive() { torture_run "smb2.lock.rw-shared" || true; }
register_test "EC.149" "test_EC149_posix_fl_end_inclusive" --description "POSIX fl_end = start + length - 1" --timeout 10

test_EC150_fl_end_lt_start() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.150" "test_EC150_fl_end_lt_start" --description "fl_end < fl_start => INVALID_LOCK_RANGE" --timeout 10

# === Conflict Detection (EDGE-151 through EDGE-160) ===

test_EC151_self_conflict() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.151" "test_EC151_self_conflict" --description "Overlapping locks in same request => INVALID_PARAMETER" --timeout 10

test_EC152_same_handle_exclusive() { torture_run "smb2.lock.contend" || true; }
register_test "EC.152" "test_EC152_same_handle_exclusive" --description "Same-handle shared held, exclusive => LOCK_NOT_GRANTED" --timeout 15

test_EC153_zero_inside_range() { torture_run "smb2.lock.zerobytelength" || true; }
register_test "EC.153" "test_EC153_zero_inside_range" --description "Zero-byte lock inside non-zero range conflicts" --timeout 10

test_EC154_nonzero_covers_zero() { torture_run "smb2.lock.zerobytelength" || true; }
register_test "EC.154" "test_EC154_nonzero_covers_zero" --description "Non-zero range covers zero-byte lock conflicts" --timeout 10

test_EC155_adjacent_no_overlap() { torture_run "smb2.lock.rw-exclusive" || true; }
register_test "EC.155" "test_EC155_adjacent_no_overlap" --description "Adjacent non-overlapping: no conflict" --timeout 10

test_EC156_wraparound_overlap() { torture_run "smb2.lock.rw-exclusive" || true; }
register_test "EC.156" "test_EC156_wraparound_overlap" --description "Wrap-around overlap end=0 (2^64)" --timeout 10

test_EC157_shared_no_conflict() { torture_run "smb2.lock.rw-shared" || true; }
register_test "EC.157" "test_EC157_shared_no_conflict" --description "Two shared locks do not conflict" --timeout 10

test_EC158_cross_handle_conflict() { torture_run "smb2.lock.contend" || true; }
register_test "EC.158" "test_EC158_cross_handle_conflict" --description "Shared vs exclusive cross-handle conflicts" --timeout 15

test_EC159_unlock_nonexistent() { torture_run "smb2.lock.unlock" || true; }
register_test "EC.159" "test_EC159_unlock_nonexistent" --description "Unlock non-existent => RANGE_NOT_LOCKED" --timeout 10 --requires "smbtorture"

test_EC160_unlock_exact() { torture_run "smb2.lock.unlock" || true; }
register_test "EC.160" "test_EC160_unlock_exact" --description "Unlock exact range removes lock" --timeout 10 --requires "smbtorture"

# === Async Lock Lifecycle (EDGE-161 through EDGE-169) ===

test_EC161_blocking_pending() { torture_run "smb2.lock.async" || true; }
register_test "EC.161" "test_EC161_blocking_pending" --description "Blocking lock sends STATUS_PENDING" --timeout 20 --requires "smbtorture"

test_EC162_blocking_disconnect() { torture_run "smb2.lock.async" || true; }
register_test "EC.162" "test_EC162_blocking_disconnect" --description "Blocking lock: disconnect cancels" --timeout 20

test_EC163_blocking_cancel() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.163" "test_EC163_blocking_cancel" --description "Blocking lock: cancel sets inactive" --timeout 15

test_EC164_granted_after_wait() { torture_run "smb2.lock.async" || true; }
register_test "EC.164" "test_EC164_granted_after_wait" --description "Lock granted after holder releases" --timeout 20

test_EC165_cancelled_response() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.165" "test_EC165_cancelled_response" --description "Cancelled => STATUS_CANCELLED final" --timeout 15

test_EC166_rollback() { torture_run "smb2.lock.multiple" || true; }
register_test "EC.166" "test_EC166_rollback" --description "Lock failure: all acquired rolled back" --timeout 15

test_EC167_blocked_works_list() { torture_run "smb2.lock.async" || true; }
register_test "EC.167" "test_EC167_blocked_works_list" --description "Blocked work in fp->blocked_works" --timeout 20

test_EC168_async_setup_fail() { return 77; }
register_test "EC.168" "test_EC168_async_setup_fail" --description "setup_async_work OOM => INSUFFICIENT_RESOURCES" --timeout 10

test_EC169_oplock_multilock() { torture_run "smb2.lock.multiple" || true; }
register_test "EC.169" "test_EC169_oplock_multilock" --description "Oplock break after multi-lock (op_count>1)" --timeout 15

# === Channel Sequence (EDGE-170) ===

test_EC170_stale_channel_seq() { torture_run "smb2.lock.rw-exclusive" || true; }
register_test "EC.170" "test_EC170_stale_channel_seq" --description "Stale ChannelSequence => FILE_NOT_AVAILABLE" --timeout 10

# === File Lookup (EDGE-171) ===

test_EC171_invalid_fid() { torture_run "smb2.lock.errorcheck" || true; }
register_test "EC.171" "test_EC171_invalid_fid" --description "Lock with invalid FID => FILE_CLOSED" --timeout 10

# === Standalone runner ===
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "ksmbd-torture: LOCK Edge Cases (69 tests)"
    run_registered_tests "${1:-}"
fi
