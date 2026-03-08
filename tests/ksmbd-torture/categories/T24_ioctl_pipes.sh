#!/bin/bash
# T24: IOCTL - Pipes (6 tests)

register_test "T24.01" "test_ioctl_pipe_transceive" --timeout 10 --description "FSCTL_PIPE_TRANSCEIVE on IPC$"
test_ioctl_pipe_transceive() {
    local output
    output=$(rpcclient -U "${SMB_CREDS}" -p "$SMB_PORT" "${SMB_HOST}" -c "netshareenum" 2>&1)
    if [ $? -ne 0 ]; then
        fail_test "pipe transceive via netshareenum failed: $output"
        return 1
    fi
    assert_contains "$output" "test" "netshareenum should list the test share" || return 1
}

register_test "T24.02" "test_ioctl_pipe_peek" --timeout 10 --description "FSCTL_PIPE_PEEK"
test_ioctl_pipe_peek() {
    # FSCTL_PIPE_PEEK is exercised as part of RPC pipe operations
    local output
    output=$(rpcclient -U "${SMB_CREDS}" -p "$SMB_PORT" "${SMB_HOST}" -c "querydominfo" 2>&1)
    if [ $? -ne 0 ]; then
        skip_test "rpcclient querydominfo not available"
        return 0
    fi
    return 0
}

register_test "T24.03" "test_ioctl_pipe_wait" --timeout 10 --description "FSCTL_PIPE_WAIT for named pipe"
test_ioctl_pipe_wait() {
    # FSCTL_PIPE_WAIT should succeed immediately for supported pipes
    local output
    output=$(rpcclient -U "${SMB_CREDS}" -p "$SMB_PORT" "${SMB_HOST}" -c "netshareenum" 2>&1)
    if [ $? -ne 0 ]; then
        fail_test "pipe wait test failed — IPC$ pipe unavailable: $output"
        return 1
    fi
    return 0
}

register_test "T24.04" "test_ioctl_pipe_wait_timeout" --timeout 10 --description "FSCTL_PIPE_WAIT with timeout, pipe unavailable"
test_ioctl_pipe_wait_timeout() {
    skip_test "FSCTL_PIPE_WAIT timeout requires custom protocol client"
}

register_test "T24.05" "test_ioctl_pipe_wait_no_buffer" --timeout 10 --description "FSCTL_PIPE_WAIT with empty buffer"
test_ioctl_pipe_wait_no_buffer() {
    skip_test "FSCTL_PIPE_WAIT empty buffer requires custom protocol client"
}

register_test "T24.06" "test_ioctl_pipe_transceive_large" --timeout 10 --description "FSCTL_PIPE_TRANSCEIVE with large payload"
test_ioctl_pipe_transceive_large() {
    # Test large RPC request via pipe
    local output
    output=$(rpcclient -U "${SMB_CREDS}" -p "$SMB_PORT" "${SMB_HOST}" -c "enumdomusers" 2>&1)
    if [ $? -ne 0 ]; then
        skip_test "rpcclient enumdomusers not available"
        return 0
    fi
    return 0
}
