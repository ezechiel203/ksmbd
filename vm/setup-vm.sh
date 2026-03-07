#!/bin/bash
# setup-vm.sh - Create an Arch Linux QEMU disk image for ksmbd development/testing
#
# Must be run as root (for pacstrap, qemu-nbd, mount).
# Creates vm/arch-ksmbd.qcow2 (~12GB sparse).
# Extracts vm/vmlinuz and vm/initramfs.img for direct kernel boot.
#
# Prerequisites (installed automatically if missing):
#   - qemu-img, qemu-nbd  (qemu-base)
#   - pacstrap, arch-chroot (arch-install-scripts)
#
# Usage:
#   sudo ./vm/setup-vm.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DISK_IMAGE="$SCRIPT_DIR/arch-ksmbd.qcow2"
DISK_SIZE="12G"
MOUNT_POINT="/tmp/ksmbd-vm-rootfs"
NBD_DEV="/dev/nbd0"

# ── Preflight ──────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (for pacstrap/mount)."
    echo "Usage: sudo $0"
    exit 1
fi

# Check / install prerequisites
for pkg in qemu-base arch-install-scripts; do
    if ! pacman -Qi "$pkg" &>/dev/null; then
        echo "Installing $pkg..."
        pacman -S --noconfirm "$pkg"
    fi
done

for cmd in qemu-img qemu-nbd pacstrap arch-chroot; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found even after package install."
        exit 1
    fi
done

if [ -f "$DISK_IMAGE" ]; then
    echo "Disk image already exists: $DISK_IMAGE"
    read -rp "Overwrite? [y/N] " ans
    [ "$ans" = "y" ] || [ "$ans" = "Y" ] || exit 0
    rm -f "$DISK_IMAGE"
fi

# ── Create disk image ────────────────────────────────────────────────

echo "==> Creating ${DISK_SIZE} qcow2 disk image..."
qemu-img create -f qcow2 "$DISK_IMAGE" "$DISK_SIZE"

# ── Attach via NBD ───────────────────────────────────────────────────

echo "==> Attaching disk via NBD..."
modprobe nbd max_part=8
qemu-nbd --disconnect "$NBD_DEV" 2>/dev/null || true
sleep 0.5
qemu-nbd --connect="$NBD_DEV" "$DISK_IMAGE"
sleep 1

# ── Partition and format ─────────────────────────────────────────────

echo "==> Partitioning and formatting..."
parted "$NBD_DEV" --script -- \
    mklabel gpt \
    mkpart primary ext4 1MiB 100%

sleep 1
mkfs.ext4 -q "${NBD_DEV}p1"

# ── Mount ────────────────────────────────────────────────────────────

echo "==> Mounting rootfs..."
mkdir -p "$MOUNT_POINT"
mount "${NBD_DEV}p1" "$MOUNT_POINT"

# ── Cleanup trap ─────────────────────────────────────────────────────

cleanup() {
    echo "==> Cleaning up..."
    umount -R "$MOUNT_POINT" 2>/dev/null || true
    qemu-nbd --disconnect "$NBD_DEV" 2>/dev/null || true
    rmdir "$MOUNT_POINT" 2>/dev/null || true
}
trap cleanup EXIT

# ── pacstrap ─────────────────────────────────────────────────────────

echo "==> Installing Arch Linux base system (this may take a few minutes)..."
pacstrap -c "$MOUNT_POINT" \
    base linux linux-headers \
    base-devel \
    glib2 libnl \
    autoconf automake gcc make pkg-config libtool \
    clang llvm lld \
    meson ninja cmake \
    gdb valgrind strace ltrace \
    cppcheck sparse shellcheck \
    perf trace-cmd bpftrace \
    crash drgn kexec-tools kernelshark \
    pahole bc bison flex elfutils \
    git python python-pip \
    iproute2 iputils \
    openssh \
    cifs-utils \
    vim

# ── fstab ────────────────────────────────────────────────────────────

echo "==> Generating fstab..."
cat > "$MOUNT_POINT/etc/fstab" << 'EOF'
# /dev/vda1 - root filesystem
/dev/vda1       /               ext4    rw,relatime     0 1

# 9p virtfs share - ksmbd project directory from host
ksmbd_src       /mnt/ksmbd      9p      trans=virtio,version=9p2000.L,msize=104857600,nofail 0 0
EOF

# ── Chroot configuration ────────────────────────────────────────────

echo "==> Configuring the VM..."

# Hostname
echo 'ksmbd-vm' > "$MOUNT_POINT/etc/hostname"

# Locale
echo 'en_US.UTF-8 UTF-8' > "$MOUNT_POINT/etc/locale.gen"
arch-chroot "$MOUNT_POINT" locale-gen
echo 'LANG=en_US.UTF-8' > "$MOUNT_POINT/etc/locale.conf"

# Timezone
arch-chroot "$MOUNT_POINT" ln -sf /usr/share/zoneinfo/UTC /etc/localtime

# Console keymap (required by sd-vconsole initramfs hook)
echo 'KEYMAP=de-latin1-nodeadkeys' > "$MOUNT_POINT/etc/vconsole.conf"

# Root password (simple for testing)
echo 'root:root' | arch-chroot "$MOUNT_POINT" chpasswd

# 9p mount point
mkdir -p "$MOUNT_POINT/mnt/ksmbd"

# Serial console auto-login as root
mkdir -p "$MOUNT_POINT/etc/systemd/system/serial-getty@ttyS0.service.d"
cat > "$MOUNT_POINT/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" << 'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I 115200 linux
EOF

# Enable serial console
arch-chroot "$MOUNT_POINT" systemctl enable serial-getty@ttyS0.service

# Networking via systemd-networkd (DHCP on all interfaces)
mkdir -p "$MOUNT_POINT/etc/systemd/network"
cat > "$MOUNT_POINT/etc/systemd/network/20-wired.network" << 'EOF'
[Match]
Name=en* eth*

[Network]
DHCP=yes
EOF

arch-chroot "$MOUNT_POINT" systemctl enable systemd-networkd systemd-resolved
arch-chroot "$MOUNT_POINT" systemctl enable sshd

# Allow root password login over SSH for local host-forwarded VM access
mkdir -p "$MOUNT_POINT/etc/ssh/sshd_config.d"
cat > "$MOUNT_POINT/etc/ssh/sshd_config.d/10-ksmbd-vm.conf" << 'EOF'
PermitRootLogin yes
PasswordAuthentication yes
EOF

# Debug-friendly defaults for an isolated local VM
mkdir -p "$MOUNT_POINT/etc/sysctl.d"
cat > "$MOUNT_POINT/etc/sysctl.d/90-ksmbd-dev.conf" << 'EOF'
kernel.dmesg_restrict = 0
kernel.kptr_restrict = 0
kernel.perf_event_paranoid = -1
kernel.yama.ptrace_scope = 0
kernel.sysrq = 1
EOF

# Enable coredumps for userspace tools (ksmbd.mountd, ksmbdctl, etc.)
mkdir -p "$MOUNT_POINT/etc/systemd/coredump.conf.d"
cat > "$MOUNT_POINT/etc/systemd/coredump.conf.d/90-ksmbd-dev.conf" << 'EOF'
[Coredump]
Storage=external
Compress=yes
ProcessSizeMax=8G
ExternalSizeMax=8G
EOF

# Blacklist the in-tree ksmbd so it doesn't autoload at boot
# (we load our out-of-tree module manually via insmod)
cat > "$MOUNT_POINT/etc/modprobe.d/ksmbd-blacklist.conf" << 'EOF'
blacklist ksmbd
EOF

# Ensure 9p and virtio modules are in initramfs
cat > "$MOUNT_POINT/etc/mkinitcpio.conf.d/ksmbd-vm.conf" << 'EOF'
# Extra modules for QEMU VM: virtio drivers + 9p filesystem
MODULES=(virtio virtio_blk virtio_pci virtio_net 9p 9pnet 9pnet_virtio ext4)
EOF

# Regenerate initramfs with the extra modules
echo "==> Regenerating initramfs (including virtio + 9p modules)..."
arch-chroot "$MOUNT_POINT" mkinitcpio -P

# ── Extract kernel and initramfs for direct boot ─────────────────────

echo "==> Extracting VM kernel and initramfs for direct boot..."
cp "$MOUNT_POINT/boot/vmlinuz-linux" "$SCRIPT_DIR/vmlinuz"
cp "$MOUNT_POINT/boot/initramfs-linux.img" "$SCRIPT_DIR/initramfs.img"
echo "    Saved: vm/vmlinuz, vm/initramfs.img"

# ── Helper scripts inside VM ────────────────────────────────────────

# /root/start-ksmbd.sh - one-command ksmbd startup
cat > "$MOUNT_POINT/root/start-ksmbd.sh" << 'SCRIPT'
#!/bin/bash
set -euo pipefail

build_ksmbd_tools_if_needed() {
    local src="/mnt/ksmbd/ksmbd-tools"
    local mountd_bin="/usr/sbin/ksmbd.mountd"
    local needs_build=0

    if [ ! -x "$mountd_bin" ]; then
        needs_build=1
    elif find "$src" -type f \
        \( -name '*.c' -o -name '*.h' -o -name '*.am' -o -name '*.ac' -o -name '*.m4' -o -name 'meson.build' \) \
        -newer "$mountd_bin" -print -quit | grep -q .; then
        needs_build=1
    fi

    if [ "$needs_build" -eq 0 ]; then
        return
    fi

    echo "==> Building ksmbd-tools..."
    cd "$src"
    ./autogen.sh
    ./configure --prefix=/usr --sysconfdir=/etc --runstatedir=/run
    make -j"$(nproc)"
    make install
    echo "    ksmbd-tools installed/updated."
}

echo "==> Loading ksmbd module..."

# Load dependencies that might be needed
modprobe libdes 2>/dev/null || true
modprobe lz4_compress 2>/dev/null || true
modprobe crypto_user 2>/dev/null || true

# Load ksmbd from the 9p share
if [ -f /mnt/ksmbd/ksmbd.ko ]; then
    insmod /mnt/ksmbd/ksmbd.ko
    echo "    Loaded /mnt/ksmbd/ksmbd.ko"
else
    echo "    ERROR: /mnt/ksmbd/ksmbd.ko not found!"
    echo "    Make sure the 9p share is mounted and ksmbd.ko is built."
    exit 1
fi

build_ksmbd_tools_if_needed

# Create test share directory
mkdir -p /srv/smb/test
chmod 0777 /srv/smb/test

# Create config if missing
if [ ! -f /etc/ksmbd/ksmbd.conf ]; then
    mkdir -p /etc/ksmbd
    cat > /etc/ksmbd/ksmbd.conf << 'CONF'
[global]
    netbios name = KSMBD-VM
    server string = ksmbd test server
    workgroup = WORKGROUP
    server min protocol = SMB2_10
    server max protocol = SMB3_11
    map to guest = bad user

[test]
    path = /srv/smb/test
    comment = Test Share
    read only = no
    guest ok = yes
    browseable = yes
    create mask = 0666
    directory mask = 0777
CONF
    echo "    Created /etc/ksmbd/ksmbd.conf"
fi

# Add test user (ignore if already exists)
echo "==> Adding test user..."
echo -e "testpass\ntestpass" | ksmbdctl user add testuser 2>/dev/null || true

# Ensure stale userspace state does not break restart attempts
ksmbdctl stop 2>/dev/null || true
mkdir -p /run /var/run /usr/var/run
rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock
rm -f /run/ksmbd.fifo*

# Start daemon
echo "==> Starting ksmbdctl..."
echo ""
echo "  Server is running. Connect from the host:"
echo "    smbclient //localhost/test -p 10445 -U testuser%testpass"
echo ""
echo "  Press Ctrl+C to stop."
echo ""
exec ksmbdctl start --nodetach
SCRIPT
chmod +x "$MOUNT_POINT/root/start-ksmbd.sh"

# /root/reload-ksmbd.sh - quick module reload for iterative development
cat > "$MOUNT_POINT/root/reload-ksmbd.sh" << 'SCRIPT'
#!/bin/bash
set -euo pipefail

build_ksmbd_tools_if_needed() {
    local src="/mnt/ksmbd/ksmbd-tools"
    local mountd_bin="/usr/sbin/ksmbd.mountd"
    local needs_build=0

    if [ ! -x "$mountd_bin" ]; then
        needs_build=1
    elif find "$src" -type f \
        \( -name '*.c' -o -name '*.h' -o -name '*.am' -o -name '*.ac' -o -name '*.m4' -o -name 'meson.build' \) \
        -newer "$mountd_bin" -print -quit | grep -q .; then
        needs_build=1
    fi

    if [ "$needs_build" -eq 0 ]; then
        return
    fi

    echo "==> Building ksmbd-tools..."
    cd "$src"
    ./autogen.sh
    ./configure --prefix=/usr --sysconfdir=/etc --runstatedir=/run
    make -j"$(nproc)"
    make install
    echo "    ksmbd-tools installed/updated."
}

echo "==> Stopping ksmbd server..."
ksmbdctl stop 2>/dev/null || true
sleep 1

echo "==> Unloading ksmbd module..."
rmmod ksmbd 2>/dev/null || true
sleep 0.5

echo "==> Loading updated ksmbd module..."
modprobe libdes 2>/dev/null || true
modprobe lz4_compress 2>/dev/null || true
insmod /mnt/ksmbd/ksmbd.ko

build_ksmbd_tools_if_needed
mkdir -p /run /var/run /usr/var/run
rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock
rm -f /run/ksmbd.fifo*

echo "==> Restarting ksmbdctl..."
echo ""
echo "  Server reloaded. Connect from the host:"
echo "    smbclient //localhost/test -p 10445 -U testuser%testpass"
echo ""
exec ksmbdctl start --nodetach
SCRIPT
chmod +x "$MOUNT_POINT/root/reload-ksmbd.sh"

# /root/.bash_profile - show help on login
cat > "$MOUNT_POINT/root/.bash_profile" << 'PROFILE'
ulimit -c unlimited
export DEBUGINFOD_URLS="https://debuginfod.archlinux.org"

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║         ksmbd Test VM                        ║"
echo "  ╠══════════════════════════════════════════════╣"
echo "  ║  /root/start-ksmbd.sh   - Start server      ║"
echo "  ║  /root/reload-ksmbd.sh  - Reload module      ║"
echo "  ║  /root/dev-info.sh      - Debug/analysis info║"
echo "  ║  /mnt/ksmbd/            - Shared source      ║"
echo "  ║  poweroff                - Shutdown VM        ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""
PROFILE

# /root/dev-info.sh - quick reference for analysis/debug commands
cat > "$MOUNT_POINT/root/dev-info.sh" << 'SCRIPT'
#!/bin/bash
set -euo pipefail

cat << 'EOF'
ksmbd VM dev/debug quick reference

Static analysis:
  cd /mnt/ksmbd
  make W=1
  make C=2 CF='-Wbitwise'
  sparse -Wsparse-all src/**/*.c
  cppcheck --enable=all --inconclusive --std=c11 src/

Dynamic/userspace analysis:
  valgrind --leak-check=full --track-origins=yes ksmbd.mountd -n
  strace -ff -o /tmp/trace.ksmbd ksmbdctl start --nodetach
  coredumpctl list
  coredumpctl info <PID>

Kernel/module debugging:
  dmesg -w
  journalctl -k -b --no-pager
  trace-cmd list -e | head
  trace-cmd record -p function_graph -l ksmbd_* -- sleep 10
  trace-cmd report | less
  bpftrace -e 'kprobe:ksmbd_* { @[probe] = count(); } interval:s:5 { exit(); }'
  perf top
  perf record -a -g -- sleep 20 && perf report
  crash /usr/lib/modules/$(uname -r)/vmlinuz /proc/kcore
  drgn

Note: valgrind does not instrument kernel modules. Use it for userspace
tools (ksmbd.mountd/ksmbdctl). For ksmbd.ko issues use dmesg, ftrace, perf,
and QEMU+GDB kernel debugging.
EOF
SCRIPT
chmod +x "$MOUNT_POINT/root/dev-info.sh"

# ── Fix ownership ────────────────────────────────────────────────────

# setup-vm.sh runs as root, so the created files are owned by root.
# Change ownership to the calling user so run-vm.sh works without sudo.
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "")}"
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
    echo "==> Setting ownership to $REAL_USER..."
    chown "$REAL_USER":"$REAL_USER" "$DISK_IMAGE" "$SCRIPT_DIR/vmlinuz" "$SCRIPT_DIR/initramfs.img"
fi

# ── Done ─────────────────────────────────────────────────────────────

echo ""
echo "==> VM disk image created successfully: $DISK_IMAGE"
echo ""
echo "  Next steps:"
echo "    1. Build ksmbd.ko:  make KDIR=/lib/modules/\$(uname -r)/build"
echo "    2. Launch the VM:   ./vm/run-vm.sh"
echo "    3. Inside the VM:   /root/start-ksmbd.sh"
echo ""
