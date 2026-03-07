#!/bin/bash
# vm-fleet.sh - Manage VM0..VM4 as a fleet

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/vm-instance-config.sh"

usage() {
    cat <<EOF
Usage: $0 <command>

Commands:
  start-all    Start VM0..VM4 (daemonized)
  status       Show instance pid and ssh reachability
  stop-all     Stop all running instance qemu processes
EOF
}

start_all() {
    "$SCRIPT_DIR/create-vm-overlays.sh"
    for vm in VM0 VM1 VM2 VM3 VM4; do
        pidfile="$(vm_pidfile "$SCRIPT_DIR" "$vm")"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            echo "==> $vm already running (PID $(cat "$pidfile"))"
            continue
        fi
        "$SCRIPT_DIR/run-vm-instance.sh" --vm "$vm"
    done
}

status() {
    for vm in VM0 VM1 VM2 VM3 VM4; do
        pidfile="$(vm_pidfile "$SCRIPT_DIR" "$vm")"
        ssh_port="$(vm_ssh_port "$vm")"
        quic_port="$(vm_quic_port "$vm")"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            printf "%s: running (PID %s, ssh %s, quic %s)\n" "$vm" "$(cat "$pidfile")" "$ssh_port" "$quic_port"
        else
            printf "%s: stopped (ssh %s, quic %s)\n" "$vm" "$ssh_port" "$quic_port"
        fi
    done
}

stop_all() {
    for vm in VM0 VM1 VM2 VM3 VM4; do
        pidfile="$(vm_pidfile "$SCRIPT_DIR" "$vm")"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            echo "Stopping $vm (PID $(cat "$pidfile"))"
            kill "$(cat "$pidfile")"
        fi
    done
}

case "${1:-}" in
    start-all) start_all ;;
    status) status ;;
    stop-all) stop_all ;;
    *) usage; exit 1 ;;
esac
