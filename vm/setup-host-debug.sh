#!/bin/bash
# setup-host-debug.sh - Install host-side tooling for ksmbd VM debugging
#
# Arch Linux focused (uses pacman).

set -euo pipefail

if ! command -v pacman >/dev/null 2>&1; then
    echo "ERROR: pacman not found. This script currently supports Arch Linux hosts."
    exit 1
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "ERROR: run as root or install sudo."
        exit 1
    fi
fi

REQUIRED_PKGS=(
    qemu-base
    openssh
    sshpass
    gdb
    perf
    trace-cmd
    bpftrace
    drgn
    crash
    pahole
    python
    git
    ripgrep
)

echo "==> Installing required host debug packages..."
$SUDO pacman -S --needed --noconfirm "${REQUIRED_PKGS[@]}"

echo "==> Host debug tooling is ready."
echo "   Next: launch VM and use ./vm/vm-exec.sh / ./vm/debug-workflow.sh"
