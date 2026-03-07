#!/bin/bash
# stop-vm-instance.sh - Stop a named VM lane launched by run-vm-instance.sh

set -euo pipefail

usage() {
    echo "Usage: $0 --lane <A|B|C|D|E> [--force]"
}

LANE=""
FORCE=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --lane)
            LANE="${2:-}"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
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

if [ -z "$LANE" ]; then
    usage
    exit 1
fi

LANE="$(printf '%s' "$LANE" | tr '[:lower:]' '[:upper:]')"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDFILE="$SCRIPT_DIR/qemu-lane${LANE}.pid"

if [ ! -f "$PIDFILE" ]; then
    echo "No pidfile for lane ${LANE}: $PIDFILE"
    exit 0
fi

PID="$(cat "$PIDFILE")"
if [ -z "$PID" ] || ! ps -p "$PID" >/dev/null 2>&1; then
    echo "Lane ${LANE} is not running (stale pidfile)."
    rm -f "$PIDFILE"
    exit 0
fi

kill "$PID" || true
sleep 1
if ps -p "$PID" >/dev/null 2>&1; then
    if [ "$FORCE" = true ]; then
        kill -9 "$PID" || true
    else
        echo "Lane ${LANE} still running; use --force to SIGKILL"
        exit 1
    fi
fi

rm -f "$PIDFILE"
echo "Stopped lane ${LANE}"
