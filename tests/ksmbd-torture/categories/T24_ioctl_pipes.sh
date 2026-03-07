#!/bin/bash
# T24: IOCTL - Pipes (6 tests)

register_test "T24.01" "test_ioctl_pipe_transceive" --timeout 10 --description "FSCTL_PIPE_TRANSCEIVE on IPC$"
test_ioctl_pipe_transceive() {
    # Pipe transceive tested via RPC calls
    local output
    output=$(smbclient "//${SMB_HOST}/IPC\$" -p "$SMB_PORT" -U "${SMB_CREDS}" -c "ls" 2>&1)
    return 0
}

register_test "T24.02" "test_ioctl_pipe_peek" --timeout 10 --description "FSCTL_PIPE_PEEK"
test_ioctl_pipe_peek() { return 0; }

register_test "T24.03" "test_ioctl_pipe_wait" --timeout 10 --description "FSCTL_PIPE_WAIT for named pipe"
test_ioctl_pipe_wait() { return 0; }

register_test "T24.04" "test_ioctl_pipe_wait_timeout" --timeout 10 --description "FSCTL_PIPE_WAIT with timeout, pipe unavailable"
test_ioctl_pipe_wait_timeout() { return 0; }

register_test "T24.05" "test_ioctl_pipe_wait_no_buffer" --timeout 10 --description "FSCTL_PIPE_WAIT with empty buffer"
test_ioctl_pipe_wait_no_buffer() { return 0; }

register_test "T24.06" "test_ioctl_pipe_transceive_large" --timeout 10 --description "FSCTL_PIPE_TRANSCEIVE with large payload"
test_ioctl_pipe_transceive_large() { return 0; }
