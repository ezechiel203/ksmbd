#!/bin/bash
# vm-exec-instance.sh - Execute command on a named VM instance over SSH

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/vm-instance-config.sh"

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 VM0|VM1|VM2|VM3|VM4 <command> [args...]"
    exit 1
fi

VM_NAME="$1"
shift
vm_require_name "$VM_NAME"

export VM_HOST=127.0.0.1
export VM_SSH_PORT
VM_SSH_PORT="$(vm_ssh_port "$VM_NAME")"
export VM_USER=root
export VM_PASS=root

exec "$SCRIPT_DIR/vm-exec.sh" "$@"
