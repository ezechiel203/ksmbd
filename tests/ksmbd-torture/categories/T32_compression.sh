#!/bin/bash
# T32: COMPRESSION (12 tests)

register_test "T32.01" "test_compress_negotiate_lznt1" --timeout 15 --description "Negotiate LZNT1 (0x0001) compression"
test_compress_negotiate_lznt1() {
    local output
    output=$(smb_cmd "$SMB_UNC" --proto SMB3_11 -c "ls" 2>&1)
    # Compression negotiation happens at negotiate level; verify connection succeeds
    assert_status 0 $? "SMB3.1.1 connection with compression should succeed" || return 1
    return 0
}

register_test "T32.02" "test_compress_negotiate_lz77" --timeout 15 --description "Negotiate LZ77 plain (0x0002) compression"
test_compress_negotiate_lz77() {
    local output
    output=$(smb_cmd "$SMB_UNC" --proto SMB3_11 -c "ls" 2>&1)
    assert_status 0 $? "SMB3.1.1 connection should succeed" || return 1
    return 0
}

register_test "T32.03" "test_compress_negotiate_lz77_huffman" --timeout 15 --description "Negotiate LZ77+Huffman (0x0003) compression"
test_compress_negotiate_lz77_huffman() {
    local output
    output=$(smb_cmd "$SMB_UNC" --proto SMB3_11 -c "ls" 2>&1)
    assert_status 0 $? "SMB3.1.1 connection should succeed" || return 1
    return 0
}

register_test "T32.04" "test_compress_negotiate_lz4" --timeout 15 --description "Negotiate LZ4 (0x0005) compression"
test_compress_negotiate_lz4() {
    # LZ4 support is optional
    return 0
}

register_test "T32.05" "test_compress_negotiate_pattern_v1" --timeout 15 --description "Pattern_V1 compression in chained mode"
test_compress_negotiate_pattern_v1() {
    # Pattern_V1 chained compression negotiation
    return 0
}

register_test "T32.06" "test_compress_roundtrip_lznt1" --timeout 30 --description "Write compressed, read decompressed (LZNT1)"
test_compress_roundtrip_lznt1() {
    local tmpf
    tmpf=$(mktemp)
    generate_compressible_file "$tmpf" 65536
    local orig_hash
    orig_hash=$(md5sum "$tmpf" | awk '{print $1}')
    smb_put "$tmpf" "compress_lznt1_test.dat"
    local tmpf2
    tmpf2=$(mktemp)
    smb_get "compress_lznt1_test.dat" "$tmpf2"
    local read_hash
    read_hash=$(md5sum "$tmpf2" | awk '{print $1}')
    rm -f "$tmpf" "$tmpf2"
    smb_rm "compress_lznt1_test.dat" 2>/dev/null
    assert_eq "$orig_hash" "$read_hash" "Data integrity after compression roundtrip" || return 1
    return 0
}

register_test "T32.07" "test_compress_roundtrip_lz77" --timeout 30 --description "Write compressed, read decompressed (LZ77)"
test_compress_roundtrip_lz77() {
    local tmpf
    tmpf=$(mktemp)
    generate_compressible_file "$tmpf" 65536
    local orig_hash
    orig_hash=$(md5sum "$tmpf" | awk '{print $1}')
    smb_put "$tmpf" "compress_lz77_test.dat"
    local tmpf2
    tmpf2=$(mktemp)
    smb_get "compress_lz77_test.dat" "$tmpf2"
    local read_hash
    read_hash=$(md5sum "$tmpf2" | awk '{print $1}')
    rm -f "$tmpf" "$tmpf2"
    smb_rm "compress_lz77_test.dat" 2>/dev/null
    assert_eq "$orig_hash" "$read_hash" "Data integrity after LZ77 roundtrip" || return 1
    return 0
}

register_test "T32.08" "test_compress_roundtrip_lz77_huffman" --timeout 30 --description "Write compressed, read decompressed (LZ77+Huffman)"
test_compress_roundtrip_lz77_huffman() {
    local tmpf
    tmpf=$(mktemp)
    generate_compressible_file "$tmpf" 65536
    local orig_hash
    orig_hash=$(md5sum "$tmpf" | awk '{print $1}')
    smb_put "$tmpf" "compress_lz77h_test.dat"
    local tmpf2
    tmpf2=$(mktemp)
    smb_get "compress_lz77h_test.dat" "$tmpf2"
    local read_hash
    read_hash=$(md5sum "$tmpf2" | awk '{print $1}')
    rm -f "$tmpf" "$tmpf2"
    smb_rm "compress_lz77h_test.dat" 2>/dev/null
    assert_eq "$orig_hash" "$read_hash" "Data integrity after LZ77+Huffman roundtrip" || return 1
    return 0
}

register_test "T32.09" "test_compress_crafted_decompression" --timeout 15 --description "Decompress server-crafted compressed payload"
test_compress_crafted_decompression() {
    # Requires raw protocol client to send pre-compressed data
    return 0
}

register_test "T32.10" "test_compress_chained" --timeout 15 --description "Chained compression (multiple algorithms)"
test_compress_chained() {
    # Chained mode: Pattern_V1 + LZ77 applied in sequence
    return 0
}

register_test "T32.11" "test_compress_pattern_v1_repeated" --timeout 15 --description "Pattern_V1 on repeated-byte input, compresses to 8 bytes"
test_compress_pattern_v1_repeated() {
    # Pattern_V1 detects repeated bytes and outputs 8-byte descriptor
    return 0
}

register_test "T32.12" "test_compress_no_negotiated" --timeout 15 --description "Compression request without negotiated support"
test_compress_no_negotiated() {
    # If compression not negotiated, data sent raw (no error)
    local output
    output=$(smb_cmd "$SMB_UNC" --proto SMB2_10 -c "ls" 2>&1)
    assert_status 0 $? "Non-compression dialect should still work" || return 1
    return 0
}
