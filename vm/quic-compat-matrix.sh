#!/bin/bash
# quic-compat-matrix.sh - Run QUIC compatibility checks on VM0..VM2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pass=0
fail=0

ok() {
    echo "PASS: $1"
    pass=$((pass + 1))
}

bad() {
    echo "FAIL: $1"
    fail=$((fail + 1))
}

for vm in VM0 VM1 VM2; do
    if "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /usr/bin/python3 /mnt/ksmbd/vm/quic-smb2-negotiate-client.py --host 127.0.0.1 --port 443 >/tmp/quic_probe_${vm}.out 2>&1; then
        ok "$vm QUIC probe with real proxy"
    else
        bad "$vm QUIC probe with real proxy"
    fi
done

for vm in VM0 VM1 VM2; do
    if "$SCRIPT_DIR/vm-exec-instance.sh" "$vm" /bin/bash /mnt/ksmbd/vm/quic-real-proxy-guest.sh validate-nonroot-reject; then
        ok "$vm kernel rejects non-root QUIC bridge peer"
    else
        bad "$vm kernel rejects non-root QUIC bridge peer"
    fi
done

# VM0: validate TLS_VERIFIED flag enforcement by running proxy without --tls-verified.
if "$SCRIPT_DIR/vm-exec-instance.sh" VM0 /bin/bash /mnt/ksmbd/vm/quic-real-proxy-guest.sh start-noverify && "$SCRIPT_DIR/vm-exec-instance.sh" VM0 /bin/bash /mnt/ksmbd/vm/quic-real-proxy-guest.sh validate-noverify-flag; then
    ok "VM0 kernel enforces TLS_VERIFIED proxy flag"
else
    bad "VM0 kernel enforces TLS_VERIFIED proxy flag"
fi

# Restore default proxy mode.
"$SCRIPT_DIR/quic-real-proxy.sh" start VM0 >/dev/null 2>&1 || true

for pair in "VM0 10445" "VM1 11445" "VM2 12445"; do
    set -- $pair
    vm="$1"
    port="$2"
    if smbclient -s /dev/null -U testuser%testpass -m SMB3_11 --client-protection=encrypt -p "$port" -L //127.0.0.1 >/tmp/smb_sanity_${vm}.out 2>&1; then
        ok "$vm SMB3 encrypted sanity"
    else
        bad "$vm SMB3 encrypted sanity"
    fi
done

echo
echo "QUIC compatibility matrix: PASS=$pass FAIL=$fail"
if [ "$fail" -ne 0 ]; then
    exit 1
fi
