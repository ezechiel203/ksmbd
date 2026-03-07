#!/bin/bash
# quic-real-proxy.sh - Manage real QUIC proxy daemon inside VM

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 <install|start|stop|status|logs> VM0|VM1|VM2|VM3|VM4
EOF
}

cmd="${1:-}"
vm="${2:-}"

if [ -z "$cmd" ] || [ -z "$vm" ]; then
    usage
    exit 1
fi

case "$cmd" in
    install)
        "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /bin/bash /mnt/ksmbd/vm/quic-real-proxy-guest.sh install
        ;;
    start)
        "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /bin/bash /mnt/ksmbd/vm/quic-real-proxy-guest.sh start
        ;;
    stop)
        "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /bin/bash /mnt/ksmbd/vm/quic-real-proxy-guest.sh stop
        ;;
    status)
        "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /bin/bash /mnt/ksmbd/vm/quic-real-proxy-guest.sh status
        ;;
    logs)
        "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /bin/bash /mnt/ksmbd/vm/quic-real-proxy-guest.sh logs
        ;;
    *)
        usage
        exit 1
        ;;
esac
