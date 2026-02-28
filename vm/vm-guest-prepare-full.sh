#!/bin/sh
# Run inside VM: prepare ksmbd with comprehensive config for full feature testing
set -e

echo "=== Stopping existing ksmbd ==="
ksmbdctl stop 2>/dev/null || true
rmmod ksmbd 2>/dev/null || true
sleep 0.5

echo "=== Loading kernel module ==="
modprobe libdes 2>/dev/null || true
modprobe lz4_compress 2>/dev/null || true
modprobe crypto_user 2>/dev/null || true
insmod /mnt/ksmbd/ksmbd.ko
echo "  srcversion: $(cat /sys/module/ksmbd/srcversion)"

echo "=== Creating share directories ==="
mkdir -p /run /var/run /usr/var/run
rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock
rm -f /run/ksmbd.fifo*

# Create all share directories
for dir in test public docs secret timemachine dropbox streams media; do
    mkdir -p /srv/smb/$dir
done

# Set permissions - writable shares need 0777 for non-root SMB users
chmod 0777 /srv/smb/test /srv/smb/public /srv/smb/dropbox /srv/smb/secret /srv/smb/timemachine /srv/smb/streams
chmod 0755 /srv/smb/docs /srv/smb/media

echo "=== Populating test data ==="

# Docs share: read-only content
echo "This is a read-only document." > /srv/smb/docs/readme.txt
echo "Another documentation file." > /srv/smb/docs/guide.txt
mkdir -p /srv/smb/docs/subdir
echo "Nested file." > /srv/smb/docs/subdir/nested.txt

# Media share: some sample files
echo "Sample media content." > /srv/smb/media/sample.txt
mkdir -p /srv/smb/media/album
echo "Track 1" > /srv/smb/media/album/track01.txt

# Secret share: hidden content
echo "TOP SECRET DATA" > /srv/smb/secret/classified.txt

# Streams share: base file for ADS testing
echo "Main stream content." > /srv/smb/streams/testfile.txt

# Public share: anonymous-accessible content
echo "Welcome to the public share." > /srv/smb/public/welcome.txt

echo "=== Installing configuration ==="
cp /mnt/ksmbd/vm/ksmbd-full.conf /etc/ksmbd/ksmbd.conf

echo "=== Setting up users ==="
echo -e "testpass\ntestpass" | ksmbdctl user add testuser 2>/dev/null || true
echo -e "admin123\nadmin123" | ksmbdctl user add admin 2>/dev/null || true
echo -e "readonly1\nreadonly1" | ksmbdctl user add reader 2>/dev/null || true

echo "=== Starting ksmbd daemon ==="
ksmbdctl start
sleep 1

echo "=== Verifying ==="
ksmbdctl status
echo ""
echo "Shares configured:"
ksmbdctl share list 2>/dev/null || grep '^\[' /etc/ksmbd/ksmbd.conf
echo ""
echo "=== VM ready for testing ==="
