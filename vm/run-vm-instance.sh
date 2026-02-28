#!/bin/bash
# run-vm-instance.sh - Launch one named VM instance (VM0..VM4)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
KERNEL="$SCRIPT_DIR/vmlinuz"
INITRD="$SCRIPT_DIR/initramfs.img"
BASE_IMAGE="$SCRIPT_DIR/arch-ksmbd.qcow2"

source "$SCRIPT_DIR/vm-instance-config.sh"

VM_NAME=""
REBUILD=false
GDB_MODE="off"
DAEMONIZE=true

usage() {
    cat <<EOF
Usage: $0 --vm VM0|VM1|VM2|VM3|VM4 [--rebuild] [--gdb|--gdb-nowait] [--foreground]

Defaults:
  - daemonized mode
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --vm)
            VM_NAME="${2:-}"
            shift 2
            ;;
        --rebuild)
            REBUILD=true
            shift
            ;;
        --gdb)
            GDB_MODE="wait"
            DAEMONIZE=false
            shift
            ;;
        --gdb-nowait)
            GDB_MODE="nowait"
            DAEMONIZE=false
            shift
            ;;
        --foreground)
            DAEMONIZE=false
            shift
            ;;
        --help|-h)
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

if [ -z "$VM_NAME" ]; then
    echo "ERROR: --vm is required"
    usage
    exit 1
fi

vm_require_name "$VM_NAME"

DISK_IMAGE="$(vm_disk_image "$SCRIPT_DIR" "$VM_NAME")"
QEMU_PIDFILE="$(vm_pidfile "$SCRIPT_DIR" "$VM_NAME")"
QEMU_SERIAL_LOG="$(vm_serial_log "$SCRIPT_DIR" "$VM_NAME")"
HOST_SMB_PORT="$(vm_smb_port "$VM_NAME")"
HOST_SSH_PORT="$(vm_ssh_port "$VM_NAME")"

if [ ! -f "$DISK_IMAGE" ]; then
    echo "ERROR: Instance disk image not found: $DISK_IMAGE"
    echo "Run ./vm/create-vm-overlays.sh first."
    exit 1
fi

if [ ! -f "$BASE_IMAGE" ] || [ ! -f "$KERNEL" ] || [ ! -f "$INITRD" ]; then
    echo "ERROR: Base VM artifacts missing under vm/"
    exit 1
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "ERROR: qemu-system-x86_64 not found"
    exit 1
fi

if [ "$REBUILD" = true ]; then
    KDIR="/lib/modules/$(uname -r)/build"
    make -C "$KDIR" M="$PROJECT_DIR" modules
fi

if [ -w /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
else
    KVM_FLAG=""
fi

QEMU_GDB_FLAGS=()
case "$GDB_MODE" in
    wait) QEMU_GDB_FLAGS=(-s -S) ;;
    nowait) QEMU_GDB_FLAGS=(-s) ;;
esac

QEMU_EXTRA_FLAGS=()
if [ "$DAEMONIZE" = true ]; then
    rm -f "$QEMU_PIDFILE"
    QEMU_EXTRA_FLAGS+=(
        -display none
        -monitor none
        -serial "file:${QEMU_SERIAL_LOG}"
        -pidfile "$QEMU_PIDFILE"
        -daemonize
    )
else
    QEMU_EXTRA_FLAGS+=(-nographic)
fi

echo "==> Starting $VM_NAME"
echo "  Disk:       $DISK_IMAGE"
echo "  SMB:        localhost:${HOST_SMB_PORT} -> 445"
echo "  SSH:        localhost:${HOST_SSH_PORT} -> 22"
echo "  Serial log: $QEMU_SERIAL_LOG"

exec qemu-system-x86_64 \
    $KVM_FLAG \
    -cpu host \
    -m 2G \
    -smp 2 \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "root=/dev/vda1 rw console=ttyS0,115200 loglevel=7" \
    -drive "file=${DISK_IMAGE},format=qcow2,if=virtio" \
    -virtfs "local,path=${PROJECT_DIR},mount_tag=ksmbd_src,security_model=mapped-xattr,id=ksmbd_share" \
    -netdev "user,id=net0,hostfwd=tcp::${HOST_SMB_PORT}-:445,hostfwd=tcp::${HOST_SSH_PORT}-:22" \
    -device "virtio-net-pci,netdev=net0" \
    "${QEMU_GDB_FLAGS[@]}" \
    "${QEMU_EXTRA_FLAGS[@]}"
