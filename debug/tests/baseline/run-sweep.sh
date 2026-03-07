#!/bin/bash
# Full smbtorture sweep on VM2 (port 12445)
# Run from host

BASEDIR="/home/ezechiel203/ksmbd/debug/tests/baseline"
VM_SSH="sshpass -p root ssh -p 12022 -o StrictHostKeyChecking=no root@127.0.0.1"
SMB_TARGET="//127.0.0.1/test"
SMB_CREDS="-U testuser%1234"
SMB_PORT="-p 12445"

# Heavy suites that need restart after
HEAVY_SUITES="lease oplock durable-open durable-v2-open replay session lock ioctl credits streams getinfo create delete-on-close-perms dir dirlease"

# All suites in order
ALL_SUITES="compound compound_async compound_find connect create credits delete-on-close-perms dir dirlease dosmode durable-open durable-v2-open getinfo ioctl lease lock maxfid maximum_allowed mkdir mux notify openattr oplock read rename replay rw secleak session setinfo streams zero-data-ioctl"

restart_ksmbd() {
    echo "  >> Restarting ksmbd on VM2..."
    $VM_SSH '
      ksmbdctl stop 2>/dev/null; sleep 2; kill $(pgrep -x ksmbdctl) 2>/dev/null; sleep 1
      for i in 1 2 3; do rmmod ksmbd 2>/dev/null && break; sleep 2; done
      modprobe hkdf 2>/dev/null; modprobe des_generic 2>/dev/null; modprobe lz4 2>/dev/null
      insmod /root/ksmbd.ko 2>/dev/null
      echo all > /sys/class/ksmbd-control/debug
      rm -f /etc/ksmbd/ksmbdpwd.db /run/ksmbd.lock
      ksmbdctl start & sleep 3
      ksmbdctl user add -p 1234 testuser 2>/dev/null
      ksmbdctl user add -p root root 2>/dev/null
      rm -rf /srv/smb/test/*
    ' 2>/dev/null
    sleep 2
    echo "  >> Restart done"
}

is_heavy() {
    local suite="$1"
    for h in $HEAVY_SUITES; do
        if [ "$suite" = "$h" ]; then
            return 0
        fi
    done
    return 1
}

get_timeout() {
    local suite="$1"
    case "$suite" in
        dir) echo 300 ;;
        lease|oplock|durable-open|durable-v2-open|replay|session|notify) echo 180 ;;
        *) echo 120 ;;
    esac
}

echo "============================================"
echo "KSMBD smbtorture sweep - VM2 (port 12445)"
echo "Started: $(date)"
echo "============================================"

for suite in $ALL_SUITES; do
    tout=$(get_timeout "$suite")
    logfile="$BASEDIR/${suite}.log"

    echo ""
    echo "[$(date +%H:%M:%S)] Running smb2.${suite} (timeout=${tout}s)..."

    timeout ${tout} smbtorture $SMB_TARGET $SMB_CREDS $SMB_PORT "smb2.${suite}" > "$logfile" 2>&1
    exit_code=$?

    # Quick summary
    pass=$(grep -c 'success:' "$logfile" 2>/dev/null || echo 0)
    fail=$(grep -c 'failure:' "$logfile" 2>/dev/null || echo 0)
    skip=$(grep -c 'skip:' "$logfile" 2>/dev/null || echo 0)

    if [ $exit_code -eq 124 ]; then
        echo "  TIMEOUT after ${tout}s - pass=$pass fail=$fail skip=$skip"
    else
        echo "  exit=$exit_code - pass=$pass fail=$fail skip=$skip"
    fi

    # Restart after heavy suites
    if is_heavy "$suite"; then
        restart_ksmbd
    fi
done

echo ""
echo "============================================"
echo "Sweep completed: $(date)"
echo "============================================"
