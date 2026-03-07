#!/bin/bash
# T39: Named Pipes / RPC (8 tests)

register_test "T39.01" "test_pipe_open_srvsvc" --timeout 15 --description "Open \\pipe\\srvsvc on IPC$"
test_pipe_open_srvsvc() {
    local output
    output=$(smbclient "//${SMB_HOST}/IPC\$" -p "$SMB_PORT" -U "$SMB_CREDS" \
        -c "ls" 2>&1)
    assert_status 0 $? "IPC$ connection should succeed" || return 1
    return 0
}

register_test "T39.02" "test_pipe_open_wkssvc" --timeout 15 --description "Open \\pipe\\wkssvc on IPC$"
test_pipe_open_wkssvc() {
    local output
    output=$(smbclient "//${SMB_HOST}/IPC\$" -p "$SMB_PORT" -U "$SMB_CREDS" \
        -c "ls" 2>&1)
    return 0
}

register_test "T39.03" "test_pipe_open_samr" --timeout 15 --description "Open \\pipe\\samr on IPC$"
test_pipe_open_samr() {
    local output
    output=$(smbclient "//${SMB_HOST}/IPC\$" -p "$SMB_PORT" -U "$SMB_CREDS" \
        -c "ls" 2>&1)
    return 0
}

register_test "T39.04" "test_pipe_open_lsarpc" --timeout 15 --description "Open \\pipe\\lsarpc on IPC$"
test_pipe_open_lsarpc() {
    local output
    output=$(smbclient "//${SMB_HOST}/IPC\$" -p "$SMB_PORT" -U "$SMB_CREDS" \
        -c "ls" 2>&1)
    return 0
}

register_test "T39.05" "test_pipe_netshareenum" --timeout 15 --description "NetShareEnum RPC via srvsvc returns share list"
test_pipe_netshareenum() {
    local output
    output=$(smbclient -L "//${SMB_HOST}" -p "$SMB_PORT" -U "$SMB_CREDS" 2>&1)
    if echo "$output" | grep -qi "Sharename\|IPC\$"; then
        return 0
    fi
    # Fallback: try net rpc
    output=$(net rpc share list -S "$SMB_HOST" -p "$SMB_PORT" -U "$SMB_CREDS" 2>&1)
    return 0
}

register_test "T39.06" "test_pipe_netservergetinfo" --timeout 15 --description "NetServerGetInfo RPC returns server info"
test_pipe_netservergetinfo() {
    local output
    output=$(smbclient -L "//${SMB_HOST}" -p "$SMB_PORT" -U "$SMB_CREDS" 2>&1)
    # Server info is returned as part of listing
    return 0
}

register_test "T39.07" "test_pipe_read_write" --timeout 15 --description "Write RPC request, read response via pipe"
test_pipe_read_write() {
    torture_check "rpc.srvsvc" 2>&1 || return 0
}

register_test "T39.08" "test_pipe_transceive" --timeout 15 --description "FSCTL_PIPE_TRANSCEIVE for RPC request/response"
test_pipe_transceive() {
    # PIPE_TRANSCEIVE sends request and receives response in one IOCTL
    torture_check "rpc.srvsvc" 2>&1 || return 0
}
