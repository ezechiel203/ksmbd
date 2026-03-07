#!/bin/bash
# run-vm.sh - Launch the ksmbd test VM with QEMU
#
# No root required. Boots Arch Linux with the project directory
# shared via 9p/virtfs and SMB port forwarded to host:10445.
#
# Usage:
#   ./vm/run-vm.sh              # Just launch the VM
#   ./vm/run-vm.sh --rebuild    # Rebuild ksmbd.ko before launching
#   ./vm/run-vm.sh --gdb         # Launch paused with QEMU gdbstub on :1234
#   ./vm/run-vm.sh --gdb-nowait  # Launch with QEMU gdbstub on :1234 (running)
#   ./vm/run-vm.sh --daemonize   # Run VM in background with serial log
#
# Inside the VM:
#   /root/start-ksmbd.sh        # Load module + start server
#   /root/reload-ksmbd.sh       # Reload module after rebuild
#
# From the host (while VM is running):
#   smbclient //localhost/test -p 10445 -U testuser%testpass

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DISK_IMAGE="$SCRIPT_DIR/arch-ksmbd.qcow2"

# Use the VM's own kernel/initramfs (extracted by setup-vm.sh)
# These include virtio + 9p modules baked into the initramfs
KERNEL="$SCRIPT_DIR/vmlinuz"
INITRD="$SCRIPT_DIR/initramfs.img"

VM_MEMORY="2G"
VM_CPUS="2"
HOST_SMB_PORT="10445"
HOST_SSH_PORT="10022"
QEMU_PIDFILE="${SCRIPT_DIR}/qemu.pid"
QEMU_SERIAL_LOG="${SCRIPT_DIR}/qemu-serial.log"

# ── Parse arguments ──────────────────────────────────────────────────

REBUILD=false
GDB_MODE="off"
DAEMONIZE=false
for arg in "$@"; do
    case "$arg" in
        --rebuild)
            REBUILD=true
            ;;
        --gdb)
            GDB_MODE="wait"
            ;;
        --gdb-nowait)
            GDB_MODE="nowait"
            ;;
        --daemonize)
            DAEMONIZE=true
            ;;
        --help|-h)
            echo "Usage: $0 [--rebuild] [--gdb|--gdb-nowait] [--daemonize] [--help]"
            echo ""
            echo "  --rebuild    Rebuild ksmbd.ko before launching the VM"
            echo "  --gdb        Open QEMU gdbstub on localhost:1234 and wait for gdb attach"
            echo "  --gdb-nowait Open QEMU gdbstub on localhost:1234 without pausing boot"
            echo "  --daemonize  Run in background; logs to vm/qemu-serial.log"
            echo "  --help       Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--rebuild] [--gdb|--gdb-nowait] [--daemonize] [--help]"
            exit 1
            ;;
    esac
done

QEMU_GDB_FLAGS=()
case "$GDB_MODE" in
    wait)
        QEMU_GDB_FLAGS=(-s -S)
        ;;
    nowait)
        QEMU_GDB_FLAGS=(-s)
        ;;
esac

# ── Preflight checks ────────────────────────────────────────────────

if [ ! -f "$DISK_IMAGE" ]; then
    echo "ERROR: Disk image not found: $DISK_IMAGE"
    echo "Run 'sudo ./vm/setup-vm.sh' first to create it."
    exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "ERROR: Kernel not found: $KERNEL"
    exit 1
fi

if [ ! -f "$INITRD" ]; then
    echo "ERROR: Initramfs not found: $INITRD"
    exit 1
fi

if ! command -v qemu-system-x86_64 &>/dev/null; then
    echo "ERROR: qemu-system-x86_64 not found."
    echo "Install with: sudo pacman -S qemu-base"
    exit 1
fi

# Check KVM availability
if [ ! -w /dev/kvm ]; then
    echo "WARNING: /dev/kvm not accessible. VM will run without hardware acceleration (slow)."
    echo "         Add your user to the 'kvm' group: sudo usermod -aG kvm $(whoami)"
    KVM_FLAG=""
else
    KVM_FLAG="-enable-kvm"
fi

# ── Rebuild ksmbd.ko if requested ────────────────────────────────────

if [ "$REBUILD" = true ]; then
    echo "==> Rebuilding ksmbd.ko..."
    KDIR="/lib/modules/$(uname -r)/build"
    if [ ! -d "$KDIR" ]; then
        echo "ERROR: Kernel headers not found at $KDIR"
        echo "Install with: sudo pacman -S linux-headers"
        exit 1
    fi
    make -C "$KDIR" M="$PROJECT_DIR" modules
    echo "==> Build complete."
    echo ""
fi

# ── Launch QEMU ──────────────────────────────────────────────────────

echo "==> Starting ksmbd test VM..."
echo ""
echo "  SMB port:     localhost:${HOST_SMB_PORT} -> VM:445"
echo "  SSH port:     localhost:${HOST_SSH_PORT} -> VM:22"
if [ "$GDB_MODE" != "off" ]; then
    echo "  GDB stub:     localhost:1234"
fi
echo "  Shared dir:   ${PROJECT_DIR} -> /mnt/ksmbd (9p)"
echo "  Console:      serial (this terminal)"
if [ "$DAEMONIZE" = true ]; then
    echo "  Mode:         daemonized (serial log: ${QEMU_SERIAL_LOG})"
fi
echo ""
echo "  To exit:      Type 'poweroff' in the VM, or press Ctrl-A then X"
echo ""

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

exec qemu-system-x86_64 \
    $KVM_FLAG \
    -cpu host \
    -m "$VM_MEMORY" \
    -smp "$VM_CPUS" \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "root=/dev/vda1 rw console=ttyS0,115200 loglevel=7" \
    -drive "file=${DISK_IMAGE},format=qcow2,if=virtio" \
    -virtfs "local,path=${PROJECT_DIR},mount_tag=ksmbd_src,security_model=mapped-xattr,id=ksmbd_share" \
    -netdev "user,id=net0,hostfwd=tcp::${HOST_SMB_PORT}-:445,hostfwd=tcp::${HOST_SSH_PORT}-:22" \
    -device "virtio-net-pci,netdev=net0" \
    "${QEMU_GDB_FLAGS[@]}" \
    "${QEMU_EXTRA_FLAGS[@]}"
