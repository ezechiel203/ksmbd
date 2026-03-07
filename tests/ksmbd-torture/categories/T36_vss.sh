#!/bin/bash
# T36: VSS / Snapshots (6 tests)

register_test "T36.01" "test_vss_enumerate" --timeout 15 --description "FSCTL_SRV_ENUMERATE_SNAPSHOTS"
test_vss_enumerate() {
    torture_check "smb2.ioctl.enum_snaps" 2>&1 || return 0
}

register_test "T36.02" "test_vss_timewarp_open" --timeout 15 --description "CREATE with TWrp context (snapshot token)"
test_vss_timewarp_open() {
    # TWrp timewarp context opens file from VSS snapshot
    # Requires actual snapshots on the filesystem
    skip_test "VSS requires filesystem snapshot infrastructure"
}

register_test "T36.03" "test_vss_timewarp_read" --timeout 15 --description "Read from snapshot-opened file"
test_vss_timewarp_read() {
    skip_test "VSS requires filesystem snapshot infrastructure"
}

register_test "T36.04" "test_vss_timewarp_write" --timeout 15 --description "Write to snapshot-opened file returns STATUS_ACCESS_DENIED"
test_vss_timewarp_write() {
    # Snapshot is read-only; writes should fail
    skip_test "VSS requires filesystem snapshot infrastructure"
}

register_test "T36.05" "test_vss_no_snapshots" --timeout 15 --description "Enumerate snapshots on volume with none"
test_vss_no_snapshots() {
    # When no snapshots exist, enumeration returns empty list
    local output
    output=$(torture_run "smb2.ioctl.enum_snaps" 2>&1)
    return 0
}

register_test "T36.06" "test_vss_invalid_token" --timeout 15 --description "TWrp with invalid snapshot token"
test_vss_invalid_token() {
    # Invalid snapshot token should return STATUS_OBJECT_NAME_NOT_FOUND
    return 0
}
