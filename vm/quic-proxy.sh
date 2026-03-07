#!/bin/bash
# quic-proxy.sh - Manage QUIC proxy emulator inside VM instances

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 <start|stop|status> VM0|VM1|VM2|VM3|VM4
EOF
}

cmd="${1:-}"
vm="${2:-}"

if [ -z "$cmd" ] || [ -z "$vm" ]; then
    usage
    exit 1
fi

case "$cmd" in
    start)
        "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /bin/bash /mnt/ksmbd/vm/quic-proxy-guest.sh start
        ;;
    stop)
        "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /bin/bash /mnt/ksmbd/vm/quic-proxy-guest.sh stop
        ;;
    status)
        "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /bin/bash /mnt/ksmbd/vm/quic-proxy-guest.sh status
        ;;
    logs)
        "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /bin/bash /mnt/ksmbd/vm/quic-proxy-guest.sh logs
        ;;
    *)
        usage
        exit 1
        ;;
esac
