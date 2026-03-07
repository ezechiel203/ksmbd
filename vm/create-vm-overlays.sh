#!/bin/bash
# create-vm-overlays.sh - Create VM0..VM4 overlays from base image

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_IMAGE="$SCRIPT_DIR/arch-ksmbd.qcow2"

source "$SCRIPT_DIR/vm-instance-config.sh"

if [ ! -f "$BASE_IMAGE" ]; then
    echo "ERROR: Base image missing: $BASE_IMAGE"
    echo "Run sudo ./vm/setup-vm.sh first."
    exit 1
fi

if ! command -v qemu-img >/dev/null 2>&1; then
    echo "ERROR: qemu-img not found"
    exit 1
fi

for vm in VM0 VM1 VM2 VM3 VM4; do
    disk="$(vm_disk_image "$SCRIPT_DIR" "$vm")"
    if [ -f "$disk" ]; then
        echo "==> $vm overlay already exists: $disk"
        continue
    fi

    echo "==> Creating $vm overlay: $disk"
    qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$disk"
done

echo "Done. Overlays ready for VM0..VM4."
