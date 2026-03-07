#!/bin/bash
# B02: LATENCY BENCHMARKS (4 benchmarks)

register_test "B02.01" "bench_open_close_latency" --timeout 120 --tags "benchmark,latency" --description "Open + close cycle latency"
bench_open_close_latency() {
    smb_write_file "bench_latency_oc.txt" "latency test file"
    local iterations=1000
    local start_time end_time elapsed_us
    start_time=$(date +%s%N)

    local i
    for i in $(seq 1 "$iterations"); do
        smb_stat "bench_latency_oc.txt" >/dev/null 2>&1
    done

    end_time=$(date +%s%N)
    elapsed_us=$(( (end_time - start_time) / 1000 ))
    local per_op_us=$(( elapsed_us / iterations ))

    echo "BENCH open_close_latency: ${per_op_us}us per op (${iterations} iterations)"
    smb_rm "bench_latency_oc.txt" 2>/dev/null
    return 0
}

register_test "B02.02" "bench_create_delete_latency" --timeout 120 --tags "benchmark,latency" --description "Create + delete cycle latency"
bench_create_delete_latency() {
    local iterations=500
    local start_time end_time elapsed_us
    start_time=$(date +%s%N)

    local i
    for i in $(seq 1 "$iterations"); do
        smb_write_file "bench_cd_${i}.txt" "data" >/dev/null 2>&1
        smb_rm "bench_cd_${i}.txt" >/dev/null 2>&1
    done

    end_time=$(date +%s%N)
    elapsed_us=$(( (end_time - start_time) / 1000 ))
    local per_op_us=$(( elapsed_us / iterations ))

    echo "BENCH create_delete_latency: ${per_op_us}us per op (${iterations} iterations)"
    return 0
}

register_test "B02.03" "bench_getattr_latency" --timeout 120 --tags "benchmark,latency" --description "QUERY_INFO (basic) latency"
bench_getattr_latency() {
    smb_write_file "bench_getattr.txt" "getattr test"
    local iterations=1000
    local start_time end_time elapsed_us
    start_time=$(date +%s%N)

    local i
    for i in $(seq 1 "$iterations"); do
        smb_stat "bench_getattr.txt" >/dev/null 2>&1
    done

    end_time=$(date +%s%N)
    elapsed_us=$(( (end_time - start_time) / 1000 ))
    local per_op_us=$(( elapsed_us / iterations ))

    echo "BENCH getattr_latency: ${per_op_us}us per op (${iterations} iterations)"
    smb_rm "bench_getattr.txt" 2>/dev/null
    return 0
}

register_test "B02.04" "bench_small_read_latency" --timeout 120 --tags "benchmark,latency" --description "1-byte read latency (metadata path)"
bench_small_read_latency() {
    smb_write_file "bench_small_read.txt" "x"
    local iterations=1000
    local start_time end_time elapsed_us
    start_time=$(date +%s%N)

    local tmpf
    tmpf=$(mktemp)
    local i
    for i in $(seq 1 "$iterations"); do
        smb_cmd "$SMB_UNC" -c "get bench_small_read.txt $tmpf" >/dev/null 2>&1
    done

    end_time=$(date +%s%N)
    elapsed_us=$(( (end_time - start_time) / 1000 ))
    local per_op_us=$(( elapsed_us / iterations ))

    echo "BENCH small_read_latency: ${per_op_us}us per op (${iterations} iterations)"
    rm -f "$tmpf"
    smb_rm "bench_small_read.txt" 2>/dev/null
    return 0
}
