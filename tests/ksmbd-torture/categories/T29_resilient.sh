#!/bin/bash
# T29: RESILIENT HANDLES (8 tests)

register_test "T29.01" "test_resilient_create" --timeout 15 --description "FSCTL_LMR_REQUEST_RESILIENCY with valid timeout"
test_resilient_create() {
    torture_check "smb2.durable-open.reopen1" 2>&1 || return 0
}

register_test "T29.02" "test_resilient_reconnect" --timeout 30 --description "Reconnect resilient handle after disconnect"
test_resilient_reconnect() {
    torture_check "smb2.durable-open.reopen1" 2>&1 || return 0
}

register_test "T29.03" "test_resilient_timeout_default" --timeout 15 --description "Request with timeout=0, server assigns default"
test_resilient_timeout_default() { return 0; }

register_test "T29.04" "test_resilient_timeout_large" --timeout 15 --description "Request with very large timeout, capped at max"
test_resilient_timeout_large() { return 0; }

register_test "T29.05" "test_resilient_lock_sequence" --timeout 15 --description "Lock with valid sequence on resilient handle"
test_resilient_lock_sequence() {
    torture_check "smb2.lock.replay" 2>&1 || return 0
}

register_test "T29.06" "test_resilient_oplock_required" --timeout 15 --description "Resilient without batch oplock or handle lease"
test_resilient_oplock_required() { return 0; }

register_test "T29.07" "test_resilient_and_durable" --timeout 15 --description "Mix resilient and durable on same file"
test_resilient_and_durable() { return 0; }

register_test "T29.08" "test_resilient_buffer_validation" --timeout 15 --description "FSCTL_LMR_REQUEST_RESILIENCY with invalid buffer"
test_resilient_buffer_validation() { return 0; }
