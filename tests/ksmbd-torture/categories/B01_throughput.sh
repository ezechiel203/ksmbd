#!/bin/bash
# B01: THROUGHPUT BENCHMARKS (6 benchmarks)

register_test "B01.01" "bench_seq_read_1m" --timeout 120 --tags "benchmark,throughput" --description "Sequential read, 1MB blocks"
bench_seq_read_1m() {
    local mount_point
    mount_point=$(bench_mount 2>/dev/null)
    if [[ -z "$mount_point" ]]; then
        skip_test "CIFS mount not available for benchmark"
        return 0
    fi

    # Create test file
    dd if=/dev/urandom of="${mount_point}/bench_seq_read_1m.dat" bs=1M count=256 2>/dev/null

    # Run fio sequential read
    local output
    output=$(bench_fio "${mount_point}" "seq_read_1m" \
        --rw=read --bs=1M --size=256M --numjobs=1 --runtime=30 2>&1)
    bench_report "B01.01" "seq_read_1m" "$output"

    rm -f "${mount_point}/bench_seq_read_1m.dat" 2>/dev/null
    bench_unmount "$mount_point" 2>/dev/null
    return 0
}

register_test "B01.02" "bench_seq_write_1m" --timeout 120 --tags "benchmark,throughput" --description "Sequential write, 1MB blocks"
bench_seq_write_1m() {
    local mount_point
    mount_point=$(bench_mount 2>/dev/null)
    if [[ -z "$mount_point" ]]; then
        skip_test "CIFS mount not available for benchmark"
        return 0
    fi

    local output
    output=$(bench_fio "${mount_point}" "seq_write_1m" \
        --rw=write --bs=1M --size=256M --numjobs=1 --runtime=30 2>&1)
    bench_report "B01.02" "seq_write_1m" "$output"

    bench_unmount "$mount_point" 2>/dev/null
    return 0
}

register_test "B01.03" "bench_seq_read_64k" --timeout 120 --tags "benchmark,throughput" --description "Sequential read, 64KB blocks"
bench_seq_read_64k() {
    local mount_point
    mount_point=$(bench_mount 2>/dev/null)
    if [[ -z "$mount_point" ]]; then
        skip_test "CIFS mount not available for benchmark"
        return 0
    fi

    dd if=/dev/urandom of="${mount_point}/bench_seq_read_64k.dat" bs=64k count=4096 2>/dev/null
    local output
    output=$(bench_fio "${mount_point}" "seq_read_64k" \
        --rw=read --bs=64k --size=256M --numjobs=1 --runtime=30 2>&1)
    bench_report "B01.03" "seq_read_64k" "$output"

    rm -f "${mount_point}/bench_seq_read_64k.dat" 2>/dev/null
    bench_unmount "$mount_point" 2>/dev/null
    return 0
}

register_test "B01.04" "bench_seq_write_64k" --timeout 120 --tags "benchmark,throughput" --description "Sequential write, 64KB blocks"
bench_seq_write_64k() {
    local mount_point
    mount_point=$(bench_mount 2>/dev/null)
    if [[ -z "$mount_point" ]]; then
        skip_test "CIFS mount not available for benchmark"
        return 0
    fi

    local output
    output=$(bench_fio "${mount_point}" "seq_write_64k" \
        --rw=write --bs=64k --size=256M --numjobs=1 --runtime=30 2>&1)
    bench_report "B01.04" "seq_write_64k" "$output"

    bench_unmount "$mount_point" 2>/dev/null
    return 0
}

register_test "B01.05" "bench_random_read_4k" --timeout 120 --tags "benchmark,throughput" --description "Random read, 4KB blocks"
bench_random_read_4k() {
    local mount_point
    mount_point=$(bench_mount 2>/dev/null)
    if [[ -z "$mount_point" ]]; then
        skip_test "CIFS mount not available for benchmark"
        return 0
    fi

    dd if=/dev/urandom of="${mount_point}/bench_rand_read_4k.dat" bs=1M count=256 2>/dev/null
    local output
    output=$(bench_fio "${mount_point}" "rand_read_4k" \
        --rw=randread --bs=4k --size=256M --numjobs=1 --runtime=30 2>&1)
    bench_report "B01.05" "rand_read_4k" "$output"

    rm -f "${mount_point}/bench_rand_read_4k.dat" 2>/dev/null
    bench_unmount "$mount_point" 2>/dev/null
    return 0
}

register_test "B01.06" "bench_random_write_4k" --timeout 120 --tags "benchmark,throughput" --description "Random write, 4KB blocks"
bench_random_write_4k() {
    local mount_point
    mount_point=$(bench_mount 2>/dev/null)
    if [[ -z "$mount_point" ]]; then
        skip_test "CIFS mount not available for benchmark"
        return 0
    fi

    local output
    output=$(bench_fio "${mount_point}" "rand_write_4k" \
        --rw=randwrite --bs=4k --size=256M --numjobs=1 --runtime=30 2>&1)
    bench_report "B01.06" "rand_write_4k" "$output"

    bench_unmount "$mount_point" 2>/dev/null
    return 0
}
