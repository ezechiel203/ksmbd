#!/bin/bash
# quic-proxy-guest.sh - manage TCP bridge emulator inside VM

set -euo pipefail

cmd="${1:-}"

case "$cmd" in
    start)
        pkill -f quic-real-proxy.py || true
        pkill -f quic-proxy-emulator.py || true
        nohup /usr/bin/python3 -u /mnt/ksmbd/vm/quic-proxy-emulator.py --tls-verified >/root/quic-proxy.log 2>&1 </dev/null &
        ;;
    stop)
        pkill -f quic-proxy-emulator.py || true
        ;;
    status)
        ps -ef | grep '[q]uic-proxy-emulator.py' || true
        ss -ltn | grep ':443' || true
        ;;
    logs)
        tail -n 120 /root/quic-proxy.log 2>/dev/null || true
        ;;
    *)
        echo "Usage: $0 <start|stop|status|logs>"
        exit 1
        ;;
esac
