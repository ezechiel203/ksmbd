#!/bin/bash
# lib/vm_control.sh -- VM management: SSH exec, module reload, daemon control, reachability
#
# All VM operations go through SSH. Configuration is inherited from the
# environment or the main runner's CLI parsing.
#
# Requires: sshpass, ssh

# ---------------------------------------------------------------------------
# Configuration (set by caller or environment)
# ---------------------------------------------------------------------------
: "${VM_HOST:=127.0.0.1}"
: "${VM_SSH_PORT:=13022}"
: "${VM_USER:=root}"
: "${VM_PASS:=root}"
: "${SMB_PORT:=13445}"
: "${VM_NAME:=VM3}"

# SSH command template (reused across all vm_* functions)
_VM_SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10"

# ---------------------------------------------------------------------------
# Core SSH Execution
# ---------------------------------------------------------------------------

# vm_exec CMD... -- Execute command on VM via SSH, return output + exit code
vm_exec() {
    sshpass -p "$VM_PASS" ssh $_VM_SSH_OPTS \
        -p "$VM_SSH_PORT" "${VM_USER}@${VM_HOST}" "$@" 2>/dev/null
}

# vm_exec_bg CMD... -- Execute command on VM in background (no wait)
vm_exec_bg() {
    sshpass -p "$VM_PASS" ssh $_VM_SSH_OPTS \
        -p "$VM_SSH_PORT" "${VM_USER}@${VM_HOST}" \
        "nohup $* </dev/null >/dev/null 2>&1 &"
}

# vm_exec_timeout SECONDS CMD... -- Execute with a timeout
vm_exec_timeout() {
    local seconds="$1"
    shift
    timeout "${seconds}s" sshpass -p "$VM_PASS" ssh $_VM_SSH_OPTS \
        -p "$VM_SSH_PORT" "${VM_USER}@${VM_HOST}" "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
# File Transfer
# ---------------------------------------------------------------------------

# vm_copy_to LOCAL REMOTE -- scp file to VM
vm_copy_to() {
    local local_path="$1" remote_path="$2"
    sshpass -p "$VM_PASS" scp $_VM_SSH_OPTS \
        -P "$VM_SSH_PORT" "$local_path" "${VM_USER}@${VM_HOST}:${remote_path}" 2>/dev/null
}

# vm_copy_from REMOTE LOCAL -- scp file from VM
vm_copy_from() {
    local remote_path="$1" local_path="$2"
    sshpass -p "$VM_PASS" scp $_VM_SSH_OPTS \
        -P "$VM_SSH_PORT" "${VM_USER}@${VM_HOST}:${remote_path}" "$local_path" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Module and Daemon Control
# ---------------------------------------------------------------------------

# vm_reload_ksmbd -- Full module reload cycle:
#   ksmbdctl stop -> kill daemon -> rmmod -> modprobe deps -> insmod -> start
vm_reload_ksmbd() {
    # Graceful stop
    vm_exec "ksmbdctl stop" 2>/dev/null
    sleep 1

    # Kill lingering daemon processes
    vm_exec "kill \$(pgrep -x ksmbdctl) 2>/dev/null" 2>/dev/null
    sleep 1

    # Remove module (may fail if still busy, retry)
    local i
    for i in 1 2 3; do
        if vm_exec "rmmod ksmbd" 2>/dev/null; then
            break
        fi
        sleep 2
    done

    # Load dependencies
    vm_modprobe_deps

    # Load ksmbd module
    if ! vm_exec "insmod /mnt/ksmbd/ksmbd.ko 2>/dev/null"; then
        # Fallback: try modprobe if insmod fails
        vm_exec "modprobe ksmbd" 2>/dev/null
    fi
    sleep 1

    # Clean up stale lock/fifo files
    vm_exec "rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock /run/ksmbd.fifo*" 2>/dev/null

    # Start daemon
    vm_exec "ksmbdctl start &" 2>/dev/null
    sleep 3

    # Wait for SMB port to be ready
    health_wait_ready 30
}

# vm_stop_ksmbd -- Stop ksmbd daemon and unload module
vm_stop_ksmbd() {
    vm_exec "ksmbdctl stop" 2>/dev/null
    sleep 1
    vm_exec "kill \$(pgrep -x ksmbdctl) 2>/dev/null" 2>/dev/null
    sleep 1
    vm_exec "rmmod ksmbd" 2>/dev/null
}

# vm_start_ksmbd -- Load module and start daemon (assumes module is not loaded)
vm_start_ksmbd() {
    vm_modprobe_deps
    if ! vm_exec "insmod /mnt/ksmbd/ksmbd.ko 2>/dev/null"; then
        vm_exec "modprobe ksmbd" 2>/dev/null
    fi
    sleep 1
    vm_exec "rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock" 2>/dev/null
    vm_exec "ksmbdctl start &" 2>/dev/null
    sleep 3
    health_wait_ready 30
}

# vm_modprobe_deps -- Load kernel module dependencies
vm_modprobe_deps() {
    vm_exec "modprobe libdes 2>/dev/null; \
             modprobe lz4_compress 2>/dev/null; \
             modprobe crypto_user 2>/dev/null; \
             modprobe hkdf 2>/dev/null; \
             modprobe lz4 2>/dev/null; \
             modprobe des_generic 2>/dev/null" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Reachability Checks
# ---------------------------------------------------------------------------

# vm_is_reachable -- Check both SSH and SMB port are responsive
vm_is_reachable() {
    # Check SSH
    if ! vm_exec_timeout 5 "echo ok" 2>/dev/null | grep -q ok; then
        return 1
    fi

    # Check SMB port is listening (check from inside the VM)
    if ! vm_exec "ss -tlnp | grep -q ':445 '" 2>/dev/null; then
        return 1
    fi

    return 0
}

# vm_ssh_reachable -- Check only SSH connectivity
vm_ssh_reachable() {
    vm_exec_timeout 5 "echo ok" 2>/dev/null | grep -q ok
}

# vm_smb_port_open -- Check SMB port is listening on VM
vm_smb_port_open() {
    vm_exec "ss -tlnp | grep -q ':445 '" 2>/dev/null
}

# health_wait_ready TIMEOUT -- Wait for ksmbd to accept connections
health_wait_ready() {
    local timeout="${1:-30}"
    local i
    for i in $(seq 1 "$timeout"); do
        if vm_smb_port_open; then
            return 0
        fi
        sleep 1
    done
    echo "ksmbd did not become ready within ${timeout}s" >&2
    return 1
}

# ---------------------------------------------------------------------------
# dmesg Utilities
# ---------------------------------------------------------------------------

# vm_dmesg_tail N -- Last N lines of dmesg
vm_dmesg_tail() {
    local n="${1:-50}"
    vm_exec "dmesg | tail -n $n"
}

# vm_dmesg_mark -- Write a unique marker to kernel log, return the marker
vm_dmesg_mark() {
    local marker="KSMBD_TORTURE_MARK_$(date +%s%N)_$$"
    vm_exec "echo '$marker' > /dev/kmsg" 2>/dev/null
    echo "$marker"
}

# vm_dmesg_since MARKER -- Return dmesg lines after marker
vm_dmesg_since() {
    local marker="$1"
    vm_exec "dmesg" 2>/dev/null | sed -n "/${marker}/,\$p" | tail -n +2
}

# vm_dmesg_errors MARKER -- Return only BUG/WARN/OOPS/RCU lines after marker
vm_dmesg_errors() {
    local marker="$1"
    vm_dmesg_since "$marker" | grep -iE 'BUG|WARN|OOPS|RCU|panic|use.after.free|ksmbd.*error'
}

# ---------------------------------------------------------------------------
# Server-Side File Management
# ---------------------------------------------------------------------------

# vm_create_test_file PATH [SIZE_BYTES] -- Create a file with random data on VM
vm_create_test_file() {
    local path="$1" size="${2:-1024}"
    vm_exec "dd if=/dev/urandom of='$path' bs=1 count=$size 2>/dev/null"
}

# vm_file_exists PATH -- Check if file exists on VM
vm_file_exists() {
    vm_exec "test -e '$1'"
}

# vm_file_absent PATH -- Check if file does NOT exist on VM
vm_file_absent() {
    vm_exec "test ! -e '$1'"
}

# vm_file_size PATH -- Return file size on VM
vm_file_size() {
    vm_exec "stat -c%s '$1'" 2>/dev/null
}

# vm_cleanup PATH -- Remove path recursively on VM
vm_cleanup() {
    local path="$1"
    vm_exec "rm -rf '$path'" 2>/dev/null
}

# vm_create_dir PATH -- Create directory on VM
vm_create_dir() {
    vm_exec "mkdir -p '$1'"
}

# ---------------------------------------------------------------------------
# Server Info
# ---------------------------------------------------------------------------

# vm_kernel_version -- Return running kernel version
vm_kernel_version() {
    vm_exec "uname -r"
}

# vm_ksmbd_version -- Return ksmbd module version
vm_ksmbd_version() {
    vm_exec "modinfo ksmbd 2>/dev/null | grep ^version | awk '{print \$2}'" 2>/dev/null
}

# vm_ksmbd_loaded -- Check if ksmbd module is loaded
vm_ksmbd_loaded() {
    vm_exec "lsmod | grep -q '^ksmbd '"
}

# vm_uptime -- Return VM uptime
vm_uptime() {
    vm_exec "uptime -p"
}
