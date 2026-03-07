#!/bin/bash
# lib/server_health.sh -- Server health monitoring
#
# Monitors ksmbd server state between test groups:
#   - dmesg for BUG/WARN/OOPS/RCU stalls
#   - Slab statistics for ksmbd-specific cache growth
#   - Open FD count for kernel threads
#   - Connection count
#   - Memory info (MemFree, Slab, SUnreclaim)
#
# All operations go through SSH to the VM via vm_exec().

# ---------------------------------------------------------------------------
# Baseline Snapshot
# ---------------------------------------------------------------------------

# health_snapshot -- Capture baseline: dmesg marker, slab counts, FD count, meminfo
# Returns a colon-separated string: MARKER:SLAB_COUNT:FD_COUNT:MEM_SLAB
health_snapshot() {
    local marker
    marker=$(vm_dmesg_mark)

    local slab_count
    slab_count=$(health_slab_count)

    local fd_count
    fd_count=$(health_fd_count)

    local mem_slab
    mem_slab=$(health_meminfo_slab)

    echo "${marker}:${slab_count}:${fd_count}:${mem_slab}"
}

# health_parse_snapshot SNAPSHOT FIELD -- Extract field from snapshot string
# Fields: marker, slab, fd, memslab
health_parse_snapshot() {
    local snapshot="$1" field="$2"
    IFS=':' read -r marker slab fd memslab <<< "$snapshot"
    case "$field" in
        marker)  echo "$marker" ;;
        slab)    echo "$slab" ;;
        fd)      echo "$fd" ;;
        memslab) echo "$memslab" ;;
    esac
}

# ---------------------------------------------------------------------------
# Health Check (Delta Analysis)
# ---------------------------------------------------------------------------

# health_check [SNAPSHOT] -- Compare current state to baseline
# Returns "OK" or a description of problems found
health_check() {
    local snapshot="${1:-}"
    local issues=()

    # Check dmesg for errors
    if [[ -n "$snapshot" ]]; then
        local marker
        marker=$(health_parse_snapshot "$snapshot" "marker")
        local errors
        errors=$(health_dmesg_errors "$marker")
        if [[ -n "$errors" ]]; then
            issues+=("DMESG: $(echo "$errors" | head -3 | tr '\n' '; ')")
        fi
    fi

    # Check for crash indicators
    local crash
    crash=$(vm_exec "dmesg | tail -50 | grep -iE 'BUG|OOPS|panic|Kernel panic'" 2>/dev/null)
    if [[ -n "$crash" ]]; then
        issues+=("CRASH: $(echo "$crash" | head -1)")
    fi

    # Check if ksmbd module is still loaded
    if ! vm_exec "lsmod | grep -q '^ksmbd '" 2>/dev/null; then
        issues+=("MODULE: ksmbd not loaded")
    fi

    # Check if SMB port is still listening
    if ! vm_smb_port_open 2>/dev/null; then
        issues+=("PORT: SMB port not listening")
    fi

    # Check slab growth if baseline provided
    if [[ -n "$snapshot" ]]; then
        local base_slab
        base_slab=$(health_parse_snapshot "$snapshot" "slab")
        local current_slab
        current_slab=$(health_slab_count)
        local slab_delta=$(( current_slab - base_slab ))
        # Warn if slab grew by more than 500 objects
        if [[ $slab_delta -gt 500 ]]; then
            issues+=("SLAB: grew by $slab_delta objects (${base_slab} -> ${current_slab})")
        fi
    fi

    # Check connection count (should be near zero between test groups)
    local conn_count
    conn_count=$(health_conn_count)
    if [[ "${conn_count:-0}" -gt 10 ]]; then
        issues+=("CONN: $conn_count active connections")
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "OK"
    else
        local IFS='; '
        echo "${issues[*]}"
    fi
}

# ---------------------------------------------------------------------------
# dmesg Monitoring
# ---------------------------------------------------------------------------

# health_dmesg_since MARKER -- Return new dmesg lines since marker
health_dmesg_since() {
    local marker="$1"
    vm_exec "dmesg" 2>/dev/null | sed -n "/${marker}/,\$p" | tail -n +2
}

# health_dmesg_errors MARKER -- Return only BUG/WARN/OOPS/RCU lines since marker
health_dmesg_errors() {
    local marker="$1"
    health_dmesg_since "$marker" | \
        grep -iE 'BUG|WARN|OOPS|RCU|panic|use.after.free|refcount|ksmbd.*error' | \
        grep -v 'ksmbd.*deprecat'  # Exclude deprecation warnings (expected for SMB1 tests)
}

# health_dmesg_crash MARKER -- Check specifically for crashes since marker
health_dmesg_crash() {
    local marker="$1"
    health_dmesg_since "$marker" | \
        grep -iE 'BUG|OOPS|panic|Kernel panic|unable to handle|general protection fault'
}

# ---------------------------------------------------------------------------
# Slab Statistics
# ---------------------------------------------------------------------------

# health_slab_count -- Return total slab object count for ksmbd caches
health_slab_count() {
    vm_exec "cat /proc/slabinfo 2>/dev/null | grep ksmbd" 2>/dev/null | \
        awk '{sum+=$2} END {print sum+0}'
}

# health_slab_detail -- Return per-cache slab counts
health_slab_detail() {
    vm_exec "cat /proc/slabinfo 2>/dev/null | head -2; \
             cat /proc/slabinfo 2>/dev/null | grep ksmbd" 2>/dev/null
}

# health_slab_delta BASELINE -- Return slab object count delta
health_slab_delta() {
    local baseline="$1"
    local current
    current=$(health_slab_count)
    echo $(( current - baseline ))
}

# ---------------------------------------------------------------------------
# File Descriptor Tracking
# ---------------------------------------------------------------------------

# health_fd_count -- Return number of open FDs for ksmbd kernel threads
health_fd_count() {
    local pid
    pid=$(vm_exec "pgrep -x ksmbd | head -1" 2>/dev/null)
    if [[ -n "$pid" ]]; then
        vm_exec "ls /proc/$pid/fd 2>/dev/null | wc -l" 2>/dev/null
    else
        echo "0"
    fi
}

# ---------------------------------------------------------------------------
# Connection Count
# ---------------------------------------------------------------------------

# health_conn_count -- Return active SMB connection count
health_conn_count() {
    local count
    count=$(vm_exec "ss -tnp 2>/dev/null | grep -c ':445 '" 2>/dev/null)
    echo "${count:-0}"
}

# ---------------------------------------------------------------------------
# Memory Info
# ---------------------------------------------------------------------------

# health_meminfo_slab -- Return Slab memory usage in kB
health_meminfo_slab() {
    vm_exec "grep '^Slab:' /proc/meminfo 2>/dev/null | awk '{print \$2}'" 2>/dev/null
}

# health_meminfo_sunreclaim -- Return SUnreclaim memory in kB
health_meminfo_sunreclaim() {
    vm_exec "grep '^SUnreclaim:' /proc/meminfo 2>/dev/null | awk '{print \$2}'" 2>/dev/null
}

# health_meminfo_memfree -- Return MemFree in kB
health_meminfo_memfree() {
    vm_exec "grep '^MemFree:' /proc/meminfo 2>/dev/null | awk '{print \$2}'" 2>/dev/null
}

# health_meminfo_delta BASELINE_SLAB -- Return memory delta for Slab
health_meminfo_delta() {
    local baseline="$1"
    local current
    current=$(health_meminfo_slab)
    echo $(( ${current:-0} - ${baseline:-0} ))
}

# ---------------------------------------------------------------------------
# Emergency Recovery
# ---------------------------------------------------------------------------

# health_force_restart -- Emergency: kill daemon, rmmod, insmod, restart
health_force_restart() {
    echo "EMERGENCY: Force-restarting ksmbd..." >&2
    vm_reload_ksmbd
}

# health_attempt_recovery -- Try to recover from a detected issue
# Returns 0 if recovery succeeded, 1 if it failed
health_attempt_recovery() {
    # Check if module is still loaded
    if ! vm_exec "lsmod | grep -q '^ksmbd '" 2>/dev/null; then
        echo "Recovery: ksmbd module gone, attempting full reload..." >&2
        health_force_restart
        return $?
    fi

    # Check if port is still up
    if ! vm_smb_port_open 2>/dev/null; then
        echo "Recovery: SMB port down, attempting daemon restart..." >&2
        vm_exec "ksmbdctl stop 2>/dev/null; kill \$(pgrep -x ksmbdctl) 2>/dev/null" 2>/dev/null
        sleep 2
        vm_exec "ksmbdctl start &" 2>/dev/null
        sleep 3
        health_wait_ready 15
        return $?
    fi

    return 0
}
