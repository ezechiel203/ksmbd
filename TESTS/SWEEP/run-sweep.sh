#!/bin/bash
# Full smb2.* smbtorture sweep with per-suite timeout
# Usage: ./run-sweep.sh [SMB_PORT] [TIMEOUT_SECS]

set -u

PORT="${1:-13445}"
TIMEOUT="${2:-15}"
SSH_PORT="${3:-13022}"
DIR="$(cd "$(dirname "$0")" && pwd)"
LOGDIR="$DIR/logs"
SUMMARY="$DIR/summary.txt"

mkdir -p "$LOGDIR"

# Suites to skip (hold/bench/multichannel don't complete normally)
SKIP_SUITES="smb2.hold-oplock smb2.hold-sharemode smb2.bench smb2.multichannel smb2.aio_delay"

# Get all top-level suites
SUITES=$(smbtorture --list 2>/dev/null | grep '^smb2\.' | awk -F. '{print $1"."$2}' | sort -u)

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
TOTAL_TIMEOUT=0
TOTAL_CONN_FAIL=0
SUITE_COUNT=0

# Server health check: try smb2.connect, restart ksmbd if needed
check_server() {
    local retries=0
    while [ $retries -lt 5 ]; do
        if timeout 5 smbtorture "//127.0.0.1/test" -U testuser%1234 -p "$PORT" \
            --option=torture:progress=no smb2.connect >/dev/null 2>&1; then
            return 0
        fi
        retries=$((retries + 1))
        echo "  [health] server check failed (attempt $retries/5), waiting 5s..."
        sleep 5

        # Try to restart ksmbd via SSH if we have access
        if [ $retries -ge 3 ] && [ -n "$SSH_PORT" ]; then
            echo "  [health] attempting ksmbd restart via SSH..."
            sshpass -p root ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@127.0.0.1 \
                'ksmbdctl stop 2>/dev/null; sleep 1; kill $(pgrep -x ksmbdctl) 2>/dev/null; sleep 1; rm -f /run/ksmbd.lock; ksmbdctl start 2>/dev/null; sleep 1; ksmbdctl user update -p 1234 testuser 2>/dev/null' \
                2>/dev/null
            sleep 3
        fi
    done
    return 1
}

echo "smbtorture sweep -- $(date)" > "$SUMMARY"
echo "Port: $PORT | Timeout: ${TIMEOUT}s per suite" >> "$SUMMARY"
echo "========================================" >> "$SUMMARY"
printf "%-45s %5s %5s %5s %s\n" "SUITE" "PASS" "FAIL" "SKIP" "NOTE" >> "$SUMMARY"
echo "----------------------------------------" >> "$SUMMARY"

for suite in $SUITES; do
    # Check skip list
    skip=0
    for s in $SKIP_SUITES; do
        if [ "$suite" = "$s" ]; then
            skip=1
            break
        fi
    done
    if [ "$skip" = "1" ]; then
        printf "%-45s %5s %5s %5s %s\n" "$suite" "-" "-" "-" "SKIPPED" >> "$SUMMARY"
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        echo "[SKIP] $suite"
        continue
    fi

    SUITE_COUNT=$((SUITE_COUNT + 1))
    LOGFILE="$LOGDIR/${suite}.log"

    # Special options and timeouts for specific suites
    EXTRA_OPTS=""
    SUITE_TIMEOUT="$TIMEOUT"
    case "$suite" in
        smb2.create)
            EXTRA_OPTS="--target=win7"
            ;;
        smb2.dir)
            SUITE_TIMEOUT=300
            ;;
        smb2.oplock|smb2.lease|smb2.dirlease|smb2.durable-v2-open|smb2.replay)
            SUITE_TIMEOUT=120
            ;;
        smb2.session)
            SUITE_TIMEOUT=180
            ;;
        smb2.notify|smb2.change_notify_disabled)
            SUITE_TIMEOUT=120
            ;;
    esac

    echo -n "[$SUITE_COUNT] $suite ... "

    timeout "$SUITE_TIMEOUT" smbtorture \
        "//127.0.0.1/test" \
        -U testuser%1234 \
        -p "$PORT" \
        --option=torture:progress=no \
        $EXTRA_OPTS \
        "$suite" \
        > "$LOGFILE" 2>&1
    RC=$?

    PASS=$(grep -c '^success:' "$LOGFILE" 2>/dev/null || true)
    PASS=${PASS:-0}
    FAIL=$(grep -c '^failure:' "$LOGFILE" 2>/dev/null || true)
    FAIL=${FAIL:-0}
    SKIP_T=$(grep -c '^skip:' "$LOGFILE" 2>/dev/null || true)
    SKIP_T=${SKIP_T:-0}

    NOTE=""
    if [ "$RC" = "124" ]; then
        NOTE="TIMEOUT"
        TOTAL_TIMEOUT=$((TOTAL_TIMEOUT + 1))
    elif grep -q "Establishing SMB2 connection failed" "$LOGFILE" 2>/dev/null; then
        NOTE="CONN_FAIL"
        TOTAL_CONN_FAIL=$((TOTAL_CONN_FAIL + 1))
    fi

    printf "%-45s %5d %5d %5d %s\n" "$suite" "$PASS" "$FAIL" "$SKIP_T" "$NOTE" >> "$SUMMARY"
    echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP_T $NOTE"

    TOTAL_PASS=$((TOTAL_PASS + PASS))
    TOTAL_FAIL=$((TOTAL_FAIL + FAIL))

    # If we got CONN_FAIL, check server health before continuing
    if [ -n "$NOTE" ] && [ "$NOTE" = "CONN_FAIL" ]; then
        echo "  [recovery] connection failed, checking server health..."
        if ! check_server; then
            echo "  [FATAL] server unrecoverable after 5 attempts, aborting sweep"
            break
        fi
        echo "  [recovery] server OK, continuing"
    fi

    # Brief pause between suites to let server recover
    sleep 2
done

echo "========================================" >> "$SUMMARY"
printf "%-45s %5d %5d %5s\n" "TOTAL" "$TOTAL_PASS" "$TOTAL_FAIL" "" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Suites run: $SUITE_COUNT" >> "$SUMMARY"
echo "Suites skipped: $TOTAL_SKIP" >> "$SUMMARY"
echo "Suites timed out: $TOTAL_TIMEOUT" >> "$SUMMARY"
echo "Suites conn failed: $TOTAL_CONN_FAIL" >> "$SUMMARY"
echo "Completed: $(date)" >> "$SUMMARY"

echo ""
echo "=== SWEEP COMPLETE ==="
echo "PASS: $TOTAL_PASS | FAIL: $TOTAL_FAIL | Timeouts: $TOTAL_TIMEOUT | ConnFail: $TOTAL_CONN_FAIL"
echo "Summary: $SUMMARY"
