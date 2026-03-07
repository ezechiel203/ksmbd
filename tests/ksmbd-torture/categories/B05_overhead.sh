#!/bin/bash
# B05: OVERHEAD BENCHMARKS (4 benchmarks)

register_test "B05.01" "bench_signing_overhead" --timeout 180 --tags "benchmark,overhead,slow" --description "Throughput with vs. without signing"
bench_signing_overhead() {
    local mount_point
    mount_point=$(bench_mount 2>/dev/null)
    if [[ -z "$mount_point" ]]; then
        skip_test "CIFS mount not available for benchmark"
        return 0
    fi

    echo "BENCH signing_overhead: comparing throughput with and without signing"

    # Test without signing
    local output_nosign
    output_nosign=$(bench_fio "${mount_point}" "nosign" \
        --rw=read --bs=1M --size=256M --numjobs=1 --runtime=20 2>&1)
    local bw_nosign
    bw_nosign=$(echo "$output_nosign" | grep -oP 'bw=\K[0-9.]+' | head -1)

    bench_unmount "$mount_point" 2>/dev/null

    # Remount with signing required
    mount_point=$(bench_mount "--option=sec=krb5i" 2>/dev/null)
    if [[ -n "$mount_point" ]]; then
        local output_sign
        output_sign=$(bench_fio "${mount_point}" "sign" \
            --rw=read --bs=1M --size=256M --numjobs=1 --runtime=20 2>&1)
        local bw_sign
        bw_sign=$(echo "$output_sign" | grep -oP 'bw=\K[0-9.]+' | head -1)
        echo "  without_signing: ${bw_nosign:-N/A} MB/s"
        echo "  with_signing: ${bw_sign:-N/A} MB/s"
        bench_unmount "$mount_point" 2>/dev/null
    else
        echo "  without_signing: ${bw_nosign:-N/A} MB/s"
        echo "  with_signing: N/A (mount with signing failed)"
    fi

    return 0
}

register_test "B05.02" "bench_encryption_overhead" --timeout 180 --tags "benchmark,overhead,slow" --description "Throughput with vs. without encryption"
bench_encryption_overhead() {
    echo "BENCH encryption_overhead: comparing throughput with and without encryption"

    # Test without encryption via smbclient
    local tmpf
    tmpf=$(mktemp)
    dd if=/dev/urandom of="$tmpf" bs=1M count=50 2>/dev/null
    local orig_hash
    orig_hash=$(md5sum "$tmpf" | awk '{print $1}')

    local start_time end_time elapsed_ms

    # Unencrypted transfer
    start_time=$(date +%s%N)
    smb_put "$tmpf" "bench_noenc.dat" >/dev/null 2>&1
    end_time=$(date +%s%N)
    elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    echo "  unencrypted_write_50MB: ${elapsed_ms}ms"

    # Encrypted transfer
    start_time=$(date +%s%N)
    smb_cmd "$SMB_UNC" --encrypt required -c "put $tmpf bench_enc.dat" >/dev/null 2>&1
    end_time=$(date +%s%N)
    elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    echo "  encrypted_write_50MB: ${elapsed_ms}ms"

    rm -f "$tmpf"
    smb_rm "bench_noenc.dat" 2>/dev/null
    smb_rm "bench_enc.dat" 2>/dev/null
    return 0
}

register_test "B05.03" "bench_compression_overhead" --timeout 180 --tags "benchmark,overhead,slow" --description "Throughput with vs. without compression"
bench_compression_overhead() {
    echo "BENCH compression_overhead: comparing throughput with compressible data"

    local tmpf
    tmpf=$(mktemp)
    generate_compressible_file "$tmpf" $((50 * 1024 * 1024))
    local start_time end_time elapsed_ms

    # Transfer compressible data (compression may or may not be active)
    start_time=$(date +%s%N)
    smb_put "$tmpf" "bench_compress.dat" >/dev/null 2>&1
    end_time=$(date +%s%N)
    elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    echo "  compressible_write_50MB: ${elapsed_ms}ms"

    # Transfer random data (incompressible)
    dd if=/dev/urandom of="$tmpf" bs=1M count=50 2>/dev/null
    start_time=$(date +%s%N)
    smb_put "$tmpf" "bench_nocompress.dat" >/dev/null 2>&1
    end_time=$(date +%s%N)
    elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    echo "  random_write_50MB: ${elapsed_ms}ms"

    rm -f "$tmpf"
    smb_rm "bench_compress.dat" 2>/dev/null
    smb_rm "bench_nocompress.dat" 2>/dev/null
    return 0
}

register_test "B05.04" "bench_quic_vs_tcp" --timeout 180 --tags "benchmark,overhead,quic,slow" --description "Throughput QUIC vs. TCP"
bench_quic_vs_tcp() {
    echo "BENCH quic_vs_tcp: comparing throughput over TCP and QUIC"

    local tmpf
    tmpf=$(mktemp)
    dd if=/dev/urandom of="$tmpf" bs=1M count=50 2>/dev/null
    local start_time end_time elapsed_ms

    # TCP transfer
    start_time=$(date +%s%N)
    smb_put "$tmpf" "bench_tcp.dat" >/dev/null 2>&1
    end_time=$(date +%s%N)
    elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    echo "  tcp_write_50MB: ${elapsed_ms}ms"
    smb_rm "bench_tcp.dat" 2>/dev/null

    # QUIC transfer (if available)
    : "${QUIC_HOST:=${SMB_HOST:-127.0.0.1}}"
    : "${QUIC_PORT:=${QUIC_SMB_PORT:-14445}}"
    start_time=$(date +%s%N)
    local output
    output=$(smb_cmd "//${QUIC_HOST}/test" --port "$QUIC_PORT" --proto SMB3_11 \
        -c "put $tmpf bench_quic.dat" 2>&1)
    end_time=$(date +%s%N)
    if [[ $? -eq 0 ]]; then
        elapsed_ms=$(( (end_time - start_time) / 1000000 ))
        echo "  quic_write_50MB: ${elapsed_ms}ms"
        smb_cmd "//${QUIC_HOST}/test" --port "$QUIC_PORT" --proto SMB3_11 \
            -c "del bench_quic.dat" 2>/dev/null
    else
        echo "  quic_write_50MB: N/A (QUIC not available)"
    fi

    rm -f "$tmpf"
    return 0
}
