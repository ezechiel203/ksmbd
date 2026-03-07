#!/bin/bash
# debug-workflow.sh - Host-side helpers for repeatable ksmbd debug cycles

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VM_EXEC="$SCRIPT_DIR/vm-exec.sh"
ARTIFACT_DIR="$SCRIPT_DIR/artifacts"

usage() {
    cat << 'EOF'
Usage: ./vm/debug-workflow.sh <command>

Commands:
  collect-logs        Collect dmesg/journalctl/module info into vm/artifacts/<ts>/
  quick-trace         Record 15s function_graph trace for ksmbd symbols
  perf-sample         Record 20s system-wide perf profile in VM
  smoke               Run a lightweight status check in VM
EOF
}

require_vm_exec() {
    if [ ! -x "$VM_EXEC" ]; then
        echo "ERROR: $VM_EXEC not found/executable."
        exit 1
    fi
}

collect_logs() {
    local ts out
    ts="$(date +%Y%m%d-%H%M%S)"
    out="$ARTIFACT_DIR/$ts"
    mkdir -p "$out"

    "$VM_EXEC" 'uname -a' > "$out/uname.txt"
    "$VM_EXEC" 'lsmod | grep -E "^ksmbd|^snd"' > "$out/lsmod.txt" || true
    "$VM_EXEC" 'dmesg -T | tail -n 500' > "$out/dmesg-tail.txt"
    "$VM_EXEC" 'journalctl -k -b --no-pager -n 800' > "$out/journal-kernel.txt"
    "$VM_EXEC" 'journalctl -u ksmbd -b --no-pager -n 500' > "$out/journal-ksmbd.txt" || true
    "$VM_EXEC" 'cat /proc/sys/kernel/yama/ptrace_scope /proc/sys/kernel/perf_event_paranoid /proc/sys/kernel/dmesg_restrict' > "$out/debug-sysctl.txt"

    echo "Collected logs in: $out"
}

quick_trace() {
    "$VM_EXEC" "trace-cmd reset || true"
    "$VM_EXEC" "trace-cmd record -p function_graph -l 'ksmbd_*' -- sleep 15"
    "$VM_EXEC" "trace-cmd report | tail -n 400"
}

perf_sample() {
    "$VM_EXEC" "perf record -a -g -- sleep 20"
    "$VM_EXEC" "perf report --stdio --no-children --sort comm,dso,symbol | head -n 120"
}

smoke() {
    "$VM_EXEC" 'echo "VM up: $(hostname)"; uname -r; systemctl is-active sshd'
    "$VM_EXEC" 'command -v trace-cmd bpftrace perf gdb drgn crash valgrind'
}

require_vm_exec
mkdir -p "$ARTIFACT_DIR"

case "${1:-}" in
    collect-logs)
        collect_logs
        ;;
    quick-trace)
        quick_trace
        ;;
    perf-sample)
        perf_sample
        ;;
    smoke)
        smoke
        ;;
    *)
        usage
        exit 1
        ;;
esac
