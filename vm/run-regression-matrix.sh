#!/bin/bash
# run-regression-matrix.sh - Deploy ksmbd.ko and run smoke matrix on VM0..VM4.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

KSMBD_KO="${KSMBD_KO:-$PROJECT_DIR/ksmbd.ko}"
SSH_PASS="${SSH_PASS:-root}"
SSH_USER="${SSH_USER:-root}"
SSH_HOST="${SSH_HOST:-127.0.0.1}"
SMB_USER="${SMB_USER:-testuser}"
SMB_PASS="${SMB_PASS:-testpass}"
SMB_SHARE="${SMB_SHARE:-test}"

source "$SCRIPT_DIR/vm-instance-config.sh"

usage() {
    cat <<EOF
Usage: $0 [--build] [--vms VM0,VM1,...]

Options:
  --build         Rebuild ksmbd.ko before deploy
  --vms LIST      Comma-separated subset (default: VM0,VM1,VM2,VM3,VM4)
EOF
}

BUILD=false
VM_LIST="VM0,VM1,VM2,VM3,VM4"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --build)
            BUILD=true
            shift
            ;;
        --vms)
            VM_LIST="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

if [ "$BUILD" = true ]; then
    make -C "$PROJECT_DIR" -j"$(nproc)" EXTERNAL_SMBDIRECT=n
fi

if [ ! -f "$KSMBD_KO" ]; then
    echo "ERROR: module not found: $KSMBD_KO"
    exit 1
fi

IFS=',' read -r -a VMS <<<"$VM_LIST"

ssh_run() {
    local port="$1"
    shift
    timeout 40s sshpass -p "$SSH_PASS" ssh \
        -p "$port" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "${SSH_USER}@${SSH_HOST}" "$@"
}

echo "== Deploy and restart =="
for vm in "${VMS[@]}"; do
    vm_require_name "$vm"
    ssh_port="$(vm_ssh_port "$vm")"
    echo "-- $vm ssh:${ssh_port} --"
    timeout 40s sshpass -p "$SSH_PASS" scp \
        -P "$ssh_port" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$KSMBD_KO" "${SSH_USER}@${SSH_HOST}:/root/ksmbd.ko"

    ssh_run "$ssh_port" "
        set -e
        kver=\$(uname -r)
        mkdir -p /lib/modules/\$kver/updates
        cp -f /root/ksmbd.ko /lib/modules/\$kver/updates/ksmbd.ko
        depmod -a
        dmesg -C || true
        ksmbdctl stop || true
        modprobe -r ksmbd || true
        modprobe rdma_cm || true
        modprobe ib_core || true
        modprobe libdes || true
        modprobe lz4_compress || true
        modprobe ksmbd
        timeout 15s ksmbdctl start >/tmp/ksmbd-start.log 2>&1
        sleep 1
        ksmbdctl status
        echo expected_src=\$(modinfo /root/ksmbd.ko | sed -n 's/^srcversion:[[:space:]]*//p' | head -n1)
        echo loaded_src=\$(modinfo ksmbd | sed -n 's/^srcversion:[[:space:]]*//p' | head -n1)
    "
done

echo "== SMB matrix =="
for vm in "${VMS[@]}"; do
    smb_port="$(vm_smb_port "$vm")"
    echo "-- $vm smb:${smb_port} --"

    set +e
    anon_out="$(smbclient -s /dev/null -N -m SMB3 -p "$smb_port" -L //127.0.0.1 2>&1)"
    anon_rc=$?
    set -e
    echo "anon_rc=$anon_rc"
    echo "$anon_out" | tail -n 2

    smbclient -s /dev/null \
        -U "${SMB_USER}%${SMB_PASS}" \
        -m SMB3 \
        -p "$smb_port" \
        -L //127.0.0.1 >/tmp/"${vm}"_auth_list.txt
    echo "auth_list_ok"

    payload="/tmp/${vm}_payload.txt"
    out="/tmp/${vm}_payload.out"
    echo "${vm}-payload-$(date +%s)" >"$payload"
    smbclient -s /dev/null \
        -U "${SMB_USER}%${SMB_PASS}" \
        -m SMB3 \
        -p "$smb_port" \
        //127.0.0.1/"$SMB_SHARE" \
        -c "put $payload ci-${vm}.txt; get ci-${vm}.txt $out; del ci-${vm}.txt" >/tmp/"${vm}"_rw.txt
    diff -u "$payload" "$out" >/dev/null
    rm -f "$payload" "$out"
    echo "rw_ok"
done

echo "== dmesg scan =="
for vm in "${VMS[@]}"; do
    ssh_port="$(vm_ssh_port "$vm")"
    echo "-- $vm --"
    ssh_run "$ssh_port" \
        "dmesg -T | grep -nE 'soft lockup|BUG:|KFENCE|KASAN|PDU length\\(|cli req too short|SESSION_SETUP extension read failed|Unknown symbol' || true"
done

echo "== Done =="
