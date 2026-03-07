#!/bin/bash
# B03: METADATA BENCHMARKS (4 benchmarks)

register_test "B03.01" "bench_readdir_100" --timeout 120 --tags "benchmark,metadata" --description "Enumerate 100-file directory"
bench_readdir_100() {
    # Create 100 files in a directory
    smb_mkdir "bench_readdir_100" 2>/dev/null
    local i
    for i in $(seq 1 100); do
        smb_write_file "bench_readdir_100/file_${i}.txt" "data_${i}" >/dev/null 2>&1
    done

    local iterations=100
    local start_time end_time elapsed_ms
    start_time=$(date +%s%N)

    for i in $(seq 1 "$iterations"); do
        smb_ls "bench_readdir_100/*" >/dev/null 2>&1
    done

    end_time=$(date +%s%N)
    elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    local per_op_ms=$(( elapsed_ms / iterations ))

    echo "BENCH readdir_100: ${per_op_ms}ms per enumeration (${iterations} iterations)"
    smb_deltree "bench_readdir_100" 2>/dev/null
    return 0
}

register_test "B03.02" "bench_readdir_10000" --timeout 300 --tags "benchmark,metadata,slow" --description "Enumerate 10000-file directory"
bench_readdir_10000() {
    # Create directory with 10000 files on VM directly for speed
    local dir="${SHARE_ROOT}/bench_readdir_10k"
    vm_exec "mkdir -p '$dir' && for i in \$(seq 1 10000); do echo data > '$dir/file_\$i.txt'; done" 2>/dev/null

    local iterations=10
    local start_time end_time elapsed_ms
    start_time=$(date +%s%N)

    local i
    for i in $(seq 1 "$iterations"); do
        smb_ls "bench_readdir_10k/*" >/dev/null 2>&1
    done

    end_time=$(date +%s%N)
    elapsed_ms=$(( (end_time - start_time) / 1000000 ))
    local per_op_ms=$(( elapsed_ms / iterations ))

    echo "BENCH readdir_10000: ${per_op_ms}ms per enumeration (${iterations} iterations)"
    vm_exec "rm -rf '$dir'" 2>/dev/null
    return 0
}

register_test "B03.03" "bench_stat_storm" --timeout 120 --tags "benchmark,metadata" --description "10000 QUERY_INFO requests in burst"
bench_stat_storm() {
    smb_write_file "bench_stat_storm.txt" "stat test"
    local iterations=10000
    local start_time end_time elapsed_s
    start_time=$(date +%s%N)

    local i
    for i in $(seq 1 "$iterations"); do
        smb_stat "bench_stat_storm.txt" >/dev/null 2>&1
    done

    end_time=$(date +%s%N)
    elapsed_s=$(( (end_time - start_time) / 1000000000 ))
    [[ $elapsed_s -eq 0 ]] && elapsed_s=1
    local ops_per_sec=$(( iterations / elapsed_s ))

    echo "BENCH stat_storm: ${ops_per_sec} ops/sec (${iterations} operations)"
    smb_rm "bench_stat_storm.txt" 2>/dev/null
    return 0
}

register_test "B03.04" "bench_create_storm" --timeout 120 --tags "benchmark,metadata" --description "10000 CREATE+CLOSE in burst"
bench_create_storm() {
    smb_mkdir "bench_create_storm" 2>/dev/null
    local iterations=10000
    local start_time end_time elapsed_s
    start_time=$(date +%s%N)

    local i
    for i in $(seq 1 "$iterations"); do
        smb_write_file "bench_create_storm/f_${i}.txt" "d" >/dev/null 2>&1
    done

    end_time=$(date +%s%N)
    elapsed_s=$(( (end_time - start_time) / 1000000000 ))
    [[ $elapsed_s -eq 0 ]] && elapsed_s=1
    local ops_per_sec=$(( iterations / elapsed_s ))

    echo "BENCH create_storm: ${ops_per_sec} ops/sec (${iterations} operations)"
    smb_deltree "bench_create_storm" 2>/dev/null
    return 0
}
