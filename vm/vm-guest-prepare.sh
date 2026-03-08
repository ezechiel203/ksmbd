#!/bin/bash
# Run inside VM: prepare ksmbd config/users and restart daemon
# Does NOT do rmmod/insmod - the module is loaded at boot by start-ksmbd.sh.
# Prefer copied /root artifacts so guest setup does not depend on executing
# binaries from the shared source mount.

set -euo pipefail

# Kill existing daemon (serial-getty may restart it, but we'll race it)
killall -9 ksmbdctl 2>/dev/null || true
sleep 1

# Ensure module is loaded (start-ksmbd.sh should have done this at boot)
if ! lsmod | grep -q '^ksmbd '; then
    modprobe libdes 2>/dev/null || true
    modprobe lz4_compress 2>/dev/null || true
    modprobe crypto_user 2>/dev/null || true
    modprobe hkdf 2>/dev/null ||
        insmod /root/hkdf.ko.zst 2>/dev/null ||
        insmod /mnt/ksmbd/vm/hkdf.ko.zst 2>/dev/null || true
    insmod /root/ksmbd.ko 2>/dev/null ||
        insmod /mnt/ksmbd/ksmbd.ko 2>/dev/null || true
fi

mkdir -p /run /var/run /usr/var/run /var/local/run
rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock /var/local/run/ksmbd.lock
rm -f /run/ksmbd.fifo*

# Use the freshest copied ksmbdctl first, then fall back to the shared tree.
if [ -x /root/ksmbdctl ]; then
    KSMBDCTL=/root/ksmbdctl
elif [ -x /mnt/ksmbd/ksmbd-tools/build-codex/tools/ksmbdctl ]; then
    KSMBDCTL=/mnt/ksmbd/ksmbd-tools/build-codex/tools/ksmbdctl
elif [ -x /mnt/ksmbd/ksmbd-tools/tools/ksmbdctl ]; then
    KSMBDCTL=/mnt/ksmbd/ksmbd-tools/tools/ksmbdctl
else
    KSMBDCTL=ksmbdctl
fi

mkdir -p /srv/smb/test /etc/ksmbd

# Clean stale test files
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
    server multi channel support = yes
    smb2 leases = yes
    durable handles = yes
    max async credits = 512
    quic handshake delegate = no

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

# Write the correct NT hash directly (avoids piped-stdin hash bug)
# NT hash = MD4(UTF-16LE("testpass")) = base64("Ncy6kWix1cpgk7S31Wxhmw==")
printf 'testuser:Ncy6kWix1cpgk7S31Wxhmw==\n' > /etc/ksmbd/ksmbdpwd.db

# Install new ksmbdctl as system binary so serial-getty also uses it
cp "$KSMBDCTL" /usr/bin/ksmbdctl 2>/dev/null || true

$KSMBDCTL -C /etc/ksmbd/ksmbd.conf -P /etc/ksmbd/ksmbdpwd.db start
