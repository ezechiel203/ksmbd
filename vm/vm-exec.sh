#!/bin/bash
# vm-exec.sh - Run a command inside the ksmbd VM over forwarded SSH
#
# Usage:
#   ./vm/vm-exec.sh dmesg -T | tail -n 80
#   ./vm/vm-exec.sh journalctl -u ksmbd -b --no-pager

set -euo pipefail

VM_HOST="${VM_HOST:-127.0.0.1}"
VM_SSH_PORT="${VM_SSH_PORT:-10022}"
VM_USER="${VM_USER:-root}"
VM_PASS="${VM_PASS:-root}"

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <command> [args...]"
    exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
    echo "ERROR: sshpass is required on the host."
    echo "Install it (Arch): sudo pacman -S sshpass"
    exit 1
fi

exec sshpass -p "$VM_PASS" \
    ssh \
    -p "$VM_SSH_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o ConnectTimeout=5 \
    "${VM_USER}@${VM_HOST}" \
    "$@"
