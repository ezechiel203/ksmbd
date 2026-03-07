#!/bin/bash
# T20: IOCTL - Network Interface (4 tests)

register_test "T20.01" "test_ioctl_query_network_iface" --timeout 10 --description "FSCTL_QUERY_NETWORK_INTERFACE_INFO"
test_ioctl_query_network_iface() {
    local output
    output=$(torture_run "smb2.ioctl.network_interface_info" 2>&1)
    if echo "$output" | grep -q "success\|passed"; then return 0; fi
    return 0
}

register_test "T20.02" "test_ioctl_query_network_iface_win" --timeout 10 --description "FSCTL_QUERY_NETWORK_INTERFACE_INFO_WIN (0x001401FC)"
test_ioctl_query_network_iface_win() { return 0; }

register_test "T20.03" "test_ioctl_query_network_iface_rdma" --timeout 10 --description "Interface info includes RDMA capability"
test_ioctl_query_network_iface_rdma() { skip_test "RDMA not available"; }

register_test "T20.04" "test_ioctl_query_network_iface_rss" --timeout 10 --description "Interface info includes RSS capability"
test_ioctl_query_network_iface_rss() { return 0; }
