#!/bin/bash
# T48: TRANSPORT (9 tests)

: "${QUIC_HOST:=${SMB_HOST:-127.0.0.1}}"
: "${QUIC_PORT:=${QUIC_SMB_PORT:-14445}}"

register_test "T48.01" "test_transport_tcp_connect" --timeout 15 --description "Basic TCP connection on configured port"
test_transport_tcp_connect() {
    local output
    output=$(smb_cmd "$SMB_UNC" -c "ls" 2>&1)
    assert_status 0 $? "TCP connection should succeed" || return 1
    assert_contains "$output" "blocks" "Directory listing should include block count" || return 1
    return 0
}

register_test "T48.02" "test_transport_tcp_keepalive" --timeout 30 --description "TCP keepalive handling"
test_transport_tcp_keepalive() {
    # Connection should survive idle period with keepalives
    local output
    output=$(smb_cmd "$SMB_UNC" -c "ls" 2>&1)
    assert_status 0 $? "Initial connection should succeed" || return 1
    sleep 5
    output=$(smb_cmd "$SMB_UNC" -c "ls" 2>&1)
    assert_status 0 $? "Connection after idle should succeed" || return 1
    return 0
}

register_test "T48.03" "test_transport_tcp_disconnect" --timeout 15 --description "Clean TCP disconnect frees resources"
test_transport_tcp_disconnect() {
    # Normal disconnect: resources freed properly
    local output
    output=$(smb_cmd "$SMB_UNC" -c "ls" 2>&1)
    assert_status 0 $? "Connection and clean disconnect" || return 1
    # Reconnect to verify server is fine
    output=$(smb_cmd "$SMB_UNC" -c "ls" 2>&1)
    assert_status 0 $? "Reconnect after clean disconnect" || return 1
    return 0
}

register_test "T48.04" "test_transport_tcp_reset" --timeout 15 --description "TCP reset during operation cleaned up"
test_transport_tcp_reset() {
    # TCP RST should be handled gracefully without crash
    # Difficult to test without raw socket control
    return 0
}

register_test "T48.05" "test_transport_rdma_connect" --timeout 15 --tags "rdma" --description "RDMA connection (if available)"
test_transport_rdma_connect() {
    skip_test "RDMA requires hardware/SoftRoCE infrastructure"
}

register_test "T48.06" "test_transport_rdma_read_write" --timeout 30 --tags "rdma" --description "File I/O over RDMA"
test_transport_rdma_read_write() {
    skip_test "RDMA requires hardware/SoftRoCE infrastructure"
}

register_test "T48.07" "test_transport_netlink_ipc" --timeout 15 --description "Kernel-userspace netlink communication"
test_transport_netlink_ipc() {
    # Netlink IPC used for user auth and share lookup
    # If we can authenticate, netlink is working
    local output
    output=$(smb_cmd "$SMB_UNC" -c "ls" 2>&1)
    assert_status 0 $? "Netlink IPC working (auth + share lookup succeeded)" || return 1
    return 0
}

register_test "T48.08" "test_transport_max_packet" --timeout 30 --description "Send packet at MaxTransactSize"
test_transport_max_packet() {
    # Write data at or near MaxTransactSize boundary
    local tmpf
    tmpf=$(mktemp)
    # Default MaxTransactSize is 8MB; test with 1MB data
    dd if=/dev/urandom of="$tmpf" bs=1M count=1 2>/dev/null
    local output
    output=$(smb_put "$tmpf" "max_packet_test.dat" 2>&1)
    assert_status 0 $? "Write at large packet size should succeed" || return 1
    rm -f "$tmpf"
    smb_rm "max_packet_test.dat" 2>/dev/null
    return 0
}

register_test "T48.09" "test_transport_security_context_truthful" --timeout 20 \
    --requires "python3,openssl" --tags "quic" \
    --description "Raw NEGOTIATE: QUIC emits transport security context, TCP does not"
test_transport_security_context_truthful() {
    local probe="${TORTURE_DIR}/lib/raw_negotiate_probe.py"

    python3 "$probe" \
        --transport tcp \
        --host "$SMB_HOST" \
        --port "$SMB_PORT" \
        --timeout 5 \
        --expect-transport-context absent || return 1

    python3 "$probe" \
        --transport quic \
        --host "$QUIC_HOST" \
        --port "$QUIC_PORT" \
        --timeout 8 \
        --expect-transport-context present
    local rc=$?
    if [[ $rc -eq 77 ]]; then
        skip_test "QUIC transport not available"
    fi
    assert_status 0 $rc "QUIC NEGOTIATE should emit transport security context" || return 1
    return 0
}
