#!/bin/bash
# quic-real-proxy-guest.sh - Run inside VM

set -euo pipefail

cmd="${1:-}"

case "$cmd" in
    install)
        /usr/bin/python3 -m pip install --upgrade --break-system-packages aioquic
        /bin/bash /mnt/ksmbd/vm/quic-pki-setup.sh
        ;;
    start)
        pkill -f quic-proxy-emulator.py || true
        pkill -f quic-real-proxy.py || true
        if [ "${KSMBD_QUIC_REQUIRE_CLIENT_CERT:-0}" = "1" ]; then
            nohup /usr/bin/python3 -u /mnt/ksmbd/vm/quic-real-proxy.py --tls-verified --require-client-cert >/root/quic-real-proxy.log 2>&1 </dev/null &
        else
            nohup /usr/bin/python3 -u /mnt/ksmbd/vm/quic-real-proxy.py --tls-verified >/root/quic-real-proxy.log 2>&1 </dev/null &
        fi
        ;;
    start-noverify)
        pkill -f quic-proxy-emulator.py || true
        pkill -f quic-real-proxy.py || true
        nohup /usr/bin/python3 -u /mnt/ksmbd/vm/quic-real-proxy.py >/root/quic-real-proxy.log 2>&1 </dev/null &
        ;;
    validate-noverify-flag)
        sleep 1
        dmesg -C
        /usr/bin/python3 /mnt/ksmbd/vm/quic-smb2-negotiate-client.py --host 127.0.0.1 --port 443 --insecure >/dev/null 2>&1 || true
        dmesg | grep -q "QUIC: rejecting unverified TLS proxy connection"
        ;;
    validate-nonroot-reject)
        dmesg -C
        setpriv --reuid=65534 --regid=65534 --clear-groups /usr/bin/python3 /mnt/ksmbd/vm/quic-inject-nonroot.py >/dev/null 2>&1 || true
        dmesg | grep -q "QUIC: rejecting non-root peer"
        ;;
    stop)
        pkill -f quic-real-proxy.py || true
        ;;
    status)
        ps -ef | grep '[q]uic-real-proxy.py' || true
        ss -lun | grep ':443' || true
        ;;
    logs)
        tail -n 120 /root/quic-real-proxy.log 2>/dev/null || true
        ;;
    *)
        echo "Usage: $0 <install|start|stop|status|logs>"
        exit 1
        ;;
esac
