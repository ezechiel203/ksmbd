#!/bin/bash
# B04: SCALABILITY BENCHMARKS (4 benchmarks)

register_test "B04.01" "bench_connections_scaling" --timeout 180 --tags "benchmark,scalability,slow" --description "Throughput vs. number of connections (1-100)"
bench_connections_scaling() {
    local mount_point
    mount_point=$(bench_mount 2>/dev/null)
    if [[ -z "$mount_point" ]]; then
        skip_test "CIFS mount not available for benchmark"
        return 0
    fi

    echo "BENCH connections_scaling: measuring throughput at different connection counts"
    for num_conns in 1 5 10 25 50 100; do
        local output
        output=$(bench_fio "${mount_point}" "conn_scale_${num_conns}" \
            --rw=read --bs=64k --size=64M --numjobs="$num_conns" --runtime=10 2>&1)
        local bw
        bw=$(echo "$output" | grep -oP 'bw=\K[0-9.]+[KMG]i?B/s' | head -1)
        echo "  connections=$num_conns bw=$bw"
    done

    bench_unmount "$mount_point" 2>/dev/null
    return 0
}

register_test "B04.02" "bench_session_scaling" --timeout 120 --tags "benchmark,scalability" --description "Session setup rate (concurrent)"
bench_session_scaling() {
    local iterations=200
    local start_time end_time elapsed_s
    start_time=$(date +%s%N)

    local pids=()
    local i
    for i in $(seq 1 "$iterations"); do
        (smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1) &
        pids+=($!)
        # Batch in groups of 20
        if (( i % 20 == 0 )); then
            for pid in "${pids[@]}"; do
                wait "$pid" 2>/dev/null
            done
            pids=()
        fi
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    end_time=$(date +%s%N)
    elapsed_s=$(( (end_time - start_time) / 1000000000 ))
    [[ $elapsed_s -eq 0 ]] && elapsed_s=1
    local rate=$(( iterations / elapsed_s ))

    echo "BENCH session_scaling: ${rate} sessions/sec (${iterations} sessions)"
    return 0
}

register_test "B04.03" "bench_file_handle_scaling" --timeout 120 --tags "benchmark,scalability" --description "Throughput vs. open file handles (10-10000)"
bench_file_handle_scaling() {
    local mount_point
    mount_point=$(bench_mount 2>/dev/null)
    if [[ -z "$mount_point" ]]; then
        skip_test "CIFS mount not available for benchmark"
        return 0
    fi

    echo "BENCH file_handle_scaling: measuring throughput with increasing open handles"
    for num_files in 10 100 1000 5000; do
        # Create files
        local i
        for i in $(seq 1 "$num_files"); do
            echo "data" > "${mount_point}/scale_${i}.txt" 2>/dev/null
        done
        local output
        output=$(bench_fio "${mount_point}" "handle_scale_${num_files}" \
            --rw=read --bs=4k --size=1M --numjobs=4 --runtime=5 2>&1)
        local bw
        bw=$(echo "$output" | grep -oP 'bw=\K[0-9.]+[KMG]i?B/s' | head -1)
        echo "  open_files=$num_files bw=$bw"
        # Cleanup
        for i in $(seq 1 "$num_files"); do
            rm -f "${mount_point}/scale_${i}.txt" 2>/dev/null
        done
    done

    bench_unmount "$mount_point" 2>/dev/null
    return 0
}

register_test "B04.04" "bench_lock_contention_scaling" --timeout 120 --tags "benchmark,scalability" --description "Lock acquisition rate under contention"
bench_lock_contention_scaling() {
    echo "BENCH lock_contention_scaling: measuring lock throughput under contention"
    for contenders in 1 2 5 10; do
        local pids=()
        local start_time end_time elapsed_s
        local ops_per_contender=100
        start_time=$(date +%s%N)

        local i
        for i in $(seq 1 "$contenders"); do
            (
                torture_run "smb2.lock.lock" >/dev/null 2>&1
            ) &
            pids+=($!)
        done
        for pid in "${pids[@]}"; do
            wait "$pid" 2>/dev/null
        done

        end_time=$(date +%s%N)
        elapsed_s=$(( (end_time - start_time) / 1000000000 ))
        [[ $elapsed_s -eq 0 ]] && elapsed_s=1
        echo "  contenders=$contenders elapsed=${elapsed_s}s"
    done
    return 0
}
