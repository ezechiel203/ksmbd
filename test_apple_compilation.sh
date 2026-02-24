#!/bin/bash

# Apple SMB Compilation Test Script
# This script checks for common compilation errors in the Apple SMB code

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRUIT_SRC="$ROOT_DIR/src/protocol/smb2/smb2fruit.c"
FRUIT_HDR="$ROOT_DIR/src/include/protocol/smb2fruit.h"

echo "=== Apple SMB Compilation Test ==="
echo

# Check if we can at least parse the C syntax without kernel headers
echo "1. Checking C syntax parsing..."

if [[ ! -f "$FRUIT_SRC" || ! -f "$FRUIT_HDR" ]]; then
    echo "✗ Required Fruit source files are missing"
    echo "  Expected:"
    echo "    $FRUIT_SRC"
    echo "    $FRUIT_HDR"
    exit 1
fi

echo "✓ Found Fruit source and header files"

# Try to run preprocessing against the relocated source tree
if gcc -E \
    -I"$ROOT_DIR/src" \
    -I"$ROOT_DIR/src/include/core" \
    -I"$ROOT_DIR/src/include/fs" \
    -I"$ROOT_DIR/src/include/protocol" \
    -I"$ROOT_DIR/src/include/transport" \
    -I"$ROOT_DIR/src/include/encoding" \
    "$FRUIT_SRC" -o /tmp/ksmbd_fruit.i 2>/tmp/ksmbd_fruit_preprocess.log; then
    echo "✓ Preprocessing successful"
else
    echo "✗ Preprocessing failed"
    head -20 /tmp/ksmbd_fruit_preprocess.log
fi

echo
echo "2. Checking for common compilation errors..."

# Check for expected symbol usage
echo "Checking for expected Apple SMB symbols..."
grep -n "fruit_process_server_query\\|fruit_debug_capabilities\\|smb2_read_dir_attr" "$FRUIT_SRC" | head -10

# Check for structure field usage sanity
echo
echo "Checking for structure field access issues..."
grep -n "\.flags\\|\.entry_count\\|\.BufferLength" "$FRUIT_SRC" | grep -v "d_info\\.flags" | head -10

# Check for function prototype issues
echo
echo "Checking for missing function prototypes..."
grep -n "fruit_process_server_query\\|fruit_debug_capabilities\\|smb2_read_dir_attr" "$FRUIT_HDR" | head -10

echo
echo "3. Checking include dependencies..."

echo "Checking key include usage..."
grep -n "#include.*smb2fruit.h" "$FRUIT_SRC" || true

echo
echo "Checking other required includes..."
grep -n "#include.*connection.h\\|#include.*oplock.h" "$FRUIT_SRC" | head -10

echo
echo "=== Test Complete ==="
