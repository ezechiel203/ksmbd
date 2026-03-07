#!/bin/bash
# Shared instance config for VM0..VM14

set -euo pipefail

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    echo "Source this file from other scripts."
    exit 1
fi

vm_require_name() {
    local name="${1:-}"
    local n="${name#VM}"
    if [[ "$name" =~ ^VM[0-9]+$ ]] && [ "$n" -ge 0 ] && [ "$n" -le 14 ]; then
        return 0
    fi
    echo "ERROR: invalid VM name '$name' (expected VM0..VM14)" >&2
    return 1
}

vm_ssh_port() {
    local n="${1#VM}"
    echo $(( n * 1000 + 10022 ))
}

vm_smb_port() {
    local n="${1#VM}"
    echo $(( n * 1000 + 10445 ))
}

vm_quic_port() {
    local n="${1#VM}"
    echo $(( n * 1000 + 10443 ))
}

vm_disk_image() {
    local script_dir="$1"
    local name="$2"
    echo "${script_dir}/arch-ksmbd-${name}.qcow2"
}

vm_pidfile() {
    local script_dir="$1"
    local name="$2"
    echo "${script_dir}/qemu-${name}.pid"
}

vm_serial_log() {
    local script_dir="$1"
    local name="$2"
    echo "${script_dir}/qemu-serial-${name}.log"
}
