#!/bin/bash

# Apple SMB Compilation Test Script
# This script checks for common compilation errors in the Apple SMB code

echo "=== Apple SMB Compilation Test ==="
echo

# Check if we can at least parse the C syntax without kernel headers
echo "1. Checking C syntax parsing..."

# Try to compile just the preprocessing stage
gcc -E -I. -I./mgmt -I./vfs_cache -I./unicode -I./auth -I./misc -I./smbacl \
    -I./smbfsctl -I./smberr -I./ntlmssp -I./ndr -I./asn1 -I./crypto_ctx \
    -I./compat -I./server -I./smb_common -I./connection -I./ksmbd_work \
    -I./oplock -I./transport_tcp -I./transport_rdma -I./transport_ipc \
    -I./glob -I./xattr -I./unicode -I./netmisc -I./nterr -I./oplock \
    -I./unicode -I./uniupr -I./vfs_cache -I./vfs -I./smb2_aapl.h \
    smb2pdu.c -o smb2pdu.i 2>&1 | head -20

if [ $? -eq 0 ]; then
    echo "✓ Preprocessing successful"
else
    echo "✗ Preprocessing failed"
fi

echo
echo "2. Checking for common compilation errors..."

# Check for undefined constants
echo "Checking for undefined constants..."
grep -n "SMB2_REOPEN_ORIGINAL\|SMB2_REOPEN_POSITION\|KSMBD_DIR_INFO_REQ_XATTR_BATCH" smb2pdu.c | head -10

# Check for structure field access issues
echo
echo "Checking for structure field access issues..."
grep -n "\.flags\|\.entry_count\|\.BufferLength" smb2pdu.c | grep -v "d_info\.flags" | head -10

# Check for function prototype issues
echo
echo "Checking for missing function prototypes..."
grep -n "aapl_supports_capability\|process_query_dir_entries" smb2pdu.c | head -5

echo
echo "3. Checking include dependencies..."

# Check if all required includes are present
echo "Checking smb2_aapl.h include..."
grep -n "#include.*smb2_aapl" smb2pdu.c

echo
echo "Checking other required includes..."
grep -n "#include.*ksmbd" smb2pdu.c | head -5

echo
echo "=== Test Complete ==="