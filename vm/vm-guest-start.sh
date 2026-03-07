#!/bin/bash
# Run inside VM: restart ksmbd without rebuilding ksmbd-tools

set -euo pipefail

pkill -f 'ksmbdctl start' 2>/dev/null || true
pkill -f 'ksmbd.mountd' 2>/dev/null || true
timeout -s KILL 5s rmmod ksmbd 2>/dev/null || true

modprobe libdes 2>/dev/null || true
modprobe lz4_compress 2>/dev/null || true
modprobe crypto_user 2>/dev/null || true

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
chmod 0777 /srv/smb/test

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
    create mask = 0777
    directory mask = 0777
CONF

echo -e "testpass\ntestpass" | ksmbdctl user add testuser 2>/dev/null || true

exec ksmbdctl start --nodetach
