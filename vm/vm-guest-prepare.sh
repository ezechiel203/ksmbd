#!/bin/bash
# Run inside VM: prepare ksmbd module/config/users without launching daemon

set -euo pipefail

# Graceful shutdown: tell kernel to close all SMB sessions, then stop daemon.
# Using ksmbdctl stop avoids a race where rmmod fails because the kernel module
# is still holding references from active connections.  pgrep -x matches the
# exact process name so it cannot accidentally kill this script's shell even
# when the script path contains 'ksmbdctl' in its argument list.
ksmbdctl stop 2>/dev/null || true
sleep 1
kill $(pgrep -x ksmbdctl) 2>/dev/null || true
sleep 1
timeout -s KILL 5s rmmod ksmbd 2>/dev/null || true

modprobe libdes 2>/dev/null || true
modprobe lz4_compress 2>/dev/null || true
modprobe crypto_user 2>/dev/null || true
modprobe hkdf 2>/dev/null || insmod /mnt/ksmbd/vm/hkdf.ko.zst 2>/dev/null || true

# Optional transport dependencies when ksmbd is built with
# SMB Direct (RDMA) support.
modprobe ib_core 2>/dev/null || true
modprobe ib_uverbs 2>/dev/null || true
modprobe ib_umad 2>/dev/null || true
modprobe rdma_ucm 2>/dev/null || true
modprobe rdma_cm 2>/dev/null || true
modprobe ib_cm 2>/dev/null || true
modprobe iw_cm 2>/dev/null || true

if ! insmod /mnt/ksmbd/ksmbd.ko 2>/dev/null; then
    lsmod | grep -q '^ksmbd ' || exit 1
fi

mkdir -p /run /var/run /usr/var/run
rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock
rm -f /run/ksmbd.fifo*

mkdir -p /srv/smb/test /etc/ksmbd
# Clean stale test files so each run starts with a fresh share state.
# This prevents leftover DACLs / security xattrs from previous runs from
# causing spurious OBJECT_NAME_NOT_FOUND / ACCESS_DENIED failures.
find /srv/smb/test -mindepth 1 -delete 2>/dev/null || true
chmod 0777 /srv/smb/test

cat > /etc/ksmbd/ksmbd.conf << 'CONF'
[global]
    netbios name = KSMBD-VM
    server string = ksmbd test server
    workgroup = WORKGROUP
    server min protocol = SMB2_10
    server max protocol = SMB3_11
    map to guest = bad user
    max ip connections = 256
    smb2 leases = yes
    durable handles = yes

[test]
    path = /srv/smb/test
    comment = Test Share
    read only = no
    guest ok = yes
    browseable = yes
    create mask = 0777
    directory mask = 0777
    acl xattr = yes
    oplocks = yes
    streams = yes
CONF

printf 'testpass\ntestpass\n' | ksmbdctl user add testuser 2>/dev/null || true
# Write the correct NT hash BEFORE starting the daemon.
# NT hash = MD4(UTF-16LE("testpass")) = base64("Ncy6kWix1cpgk7S31Wxhmw==")
# ksmbdctl user add via piped stdin produces a wrong hash, so we overwrite.
printf 'testuser:Ncy6kWix1cpgk7S31Wxhmw==\n' > /etc/ksmbd/ksmbdpwd.db
ksmbdctl start
