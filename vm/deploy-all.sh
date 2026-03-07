#!/bin/bash
# deploy-all.sh - Deploy ksmbd module + config to VMs and start daemon
# Usage: ./vm/deploy-all.sh [VM5 VM6 ...]  (default: all running VMs)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

source "$SCRIPT_DIR/vm-instance-config.sh"

MODULE="$PROJECT_DIR/ksmbd.ko"
GUEST_SCRIPT="$SCRIPT_DIR/vm-guest-prepare.sh"

if [ ! -f "$MODULE" ]; then
    echo "ERROR: ksmbd.ko not found. Build first: make EXTERNAL_SMBDIRECT=n all"
    exit 1
fi

if [ ! -f "$GUEST_SCRIPT" ]; then
    echo "ERROR: vm-guest-prepare.sh not found"
    exit 1
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o LogLevel=ERROR"

deploy_vm() {
    local vm="$1"
    local ssh_port
    ssh_port="$(vm_ssh_port "$vm")"

    echo "==> Deploying to $vm (SSH $ssh_port)..."

    # Check SSH connectivity
    if ! sshpass -p root ssh -p "$ssh_port" $SSH_OPTS root@127.0.0.1 'true' 2>/dev/null; then
        echo "  SKIP: $vm not reachable"
        return 1
    fi

    # Copy module to guest (via virtfs mount or scp)
    sshpass -p root scp -P "$ssh_port" $SSH_OPTS "$MODULE" root@127.0.0.1:/root/ksmbd.ko 2>/dev/null

    # Copy and execute guest prepare script
    sshpass -p root scp -P "$ssh_port" $SSH_OPTS "$GUEST_SCRIPT" root@127.0.0.1:/tmp/vm-guest-prepare.sh 2>/dev/null
    sshpass -p root ssh -p "$ssh_port" $SSH_OPTS root@127.0.0.1 '
        # Use /root/ksmbd.ko instead of virtfs mount
        sed -i "s|/mnt/ksmbd/ksmbd.ko|/root/ksmbd.ko|g" /tmp/vm-guest-prepare.sh
        bash /tmp/vm-guest-prepare.sh
    ' 2>/dev/null

    # Verify ksmbd is running
    if sshpass -p root ssh -p "$ssh_port" $SSH_OPTS root@127.0.0.1 'ss -tlnp | grep -q 445' 2>/dev/null; then
        echo "  OK: $vm ksmbd running on port 445"
    else
        echo "  WARN: $vm port 445 not listening, retrying..."
        sshpass -p root ssh -p "$ssh_port" $SSH_OPTS root@127.0.0.1 '
            rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock
            ksmbdctl start 2>&1
            sleep 3
        ' 2>/dev/null
        if sshpass -p root ssh -p "$ssh_port" $SSH_OPTS root@127.0.0.1 'ss -tlnp | grep -q 445' 2>/dev/null; then
            echo "  OK: $vm ksmbd running on port 445 (retry)"
        else
            echo "  FAIL: $vm ksmbd NOT running"
            return 1
        fi
    fi
}

if [ $# -gt 0 ]; then
    VMS=("$@")
else
    # Deploy to all running VMs
    mapfile -t ALL < <(vm_all_names)
    VMS=()
    for vm in "${ALL[@]}"; do
        pidfile="$(vm_pidfile "$SCRIPT_DIR" "$vm")"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            VMS+=("$vm")
        fi
    done
fi

if [ ${#VMS[@]} -eq 0 ]; then
    echo "No VMs to deploy to."
    exit 0
fi

echo "Deploying ksmbd to: ${VMS[*]}"
echo ""

FAIL=0
for vm in "${VMS[@]}"; do
    deploy_vm "$vm" || FAIL=$((FAIL + 1))
done

echo ""
echo "Done. ${#VMS[@]} VMs targeted, $FAIL failed."
