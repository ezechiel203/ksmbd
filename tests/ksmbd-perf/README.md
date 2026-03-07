# ksmbd Performance Regression Baseline System

A comprehensive performance benchmarking and regression tracking system for
the ksmbd in-kernel SMB server.

## Overview

This suite provides three tools:

- **perf_baseline.sh** -- Run standardized benchmarks, produce JSON results
- **perf_compare.sh** -- Compare two baselines, detect regressions
- **perf_track.sh** -- Maintain history, show trends, suggest bisect ranges

## Quick Start

```bash
# 1. Run a benchmark against VM3
./perf_baseline.sh --vm VM3

# 2. Make code changes, rebuild, redeploy...

# 3. Run another benchmark
./perf_baseline.sh --vm VM3

# 4. Compare the two baselines
./perf_compare.sh baselines/baseline_FIRST.json baselines/baseline_SECOND.json

# 5. Record to history for long-term tracking
./perf_track.sh record baselines/baseline_SECOND.json
```

## Running Benchmarks

### Full Suite

```bash
./perf_baseline.sh --vm VM3
```

This runs all benchmark categories:
- Sequential read/write throughput (1MB, 10MB, 100MB)
- Random 4KB read/write IOPS
- Directory enumeration (100, 1000, 10000 files)
- File creation rate (1000 files)
- Metadata operations rate (stat 1000 files)
- Small file transfer (1000 x 4KB)
- Connection establishment rate
- Concurrent client throughput (1, 2, 4, 8 clients)

### Quick Mode

```bash
./perf_baseline.sh --vm VM3 --quick
```

Reduced parameters for faster iteration during development.

### Selective Benchmarks

```bash
# Only throughput tests
./perf_baseline.sh --vm VM3 --only throughput

# Skip IOPS and directory tests
./perf_baseline.sh --vm VM3 --skip-iops --skip-dir
```

### Custom Output

```bash
./perf_baseline.sh --vm VM3 --output /path/to/results.json
```

## Comparing Results

### Basic Comparison

```bash
./perf_compare.sh baseline_A.json baseline_B.json
```

Produces a table showing each metric's baseline value, current value, delta
percentage, and status (REGRESSION, IMPROVEMENT, or ok).

### Threshold Modes

```bash
# Default: flag regressions > 10%
./perf_compare.sh baseline_A.json baseline_B.json

# Strict: any regression is a failure
./perf_compare.sh --strict baseline_A.json baseline_B.json

# Lenient: only flag regressions > 20%
./perf_compare.sh --lenient baseline_A.json baseline_B.json

# Custom threshold
./perf_compare.sh --threshold 5 baseline_A.json baseline_B.json
```

### JSON Output

```bash
./perf_compare.sh --json comparison.json baseline_A.json baseline_B.json
```

### CI Integration

The exit code indicates whether regressions were detected:
- Exit 0: No regressions (within threshold)
- Exit 1: Regressions detected
- Exit 2: Input error

```bash
if ./perf_compare.sh --strict baseline.json current.json; then
    echo "Performance OK"
else
    echo "Performance regression detected!"
fi
```

## Tracking History

### Recording Baselines

```bash
# Record an existing baseline file
./perf_track.sh record baselines/baseline_20260304T120000Z.json

# Run benchmarks and record in one step
./perf_track.sh record
```

### Viewing History

```bash
# List all recorded baselines
./perf_track.sh list

# Show trend for a specific metric
./perf_track.sh history --metric seq_write_10MB

# Show details of a specific record
./perf_track.sh show 3              # by index
./perf_track.sh show abc1234        # by commit prefix

# Show the latest baseline
./perf_track.sh latest
```

### Finding Regressions

```bash
# Get bisect suggestions for a regressed metric
./perf_track.sh bisect-hint seq_read_100MB
```

This identifies the pair of consecutive baselines with the largest drop
and suggests a `git bisect` command range.

### Exporting Data

```bash
# Export as CSV for graphing
./perf_track.sh export --csv history.csv
```

### Cleanup

```bash
# Keep only the 10 most recent baselines
./perf_track.sh clean --keep 10
```

## Metric Descriptions

### Throughput Metrics

| Metric | Unit | Description |
|--------|------|-------------|
| `seq_write_1MB` | MB/s | Sequential write throughput, 1MB file |
| `seq_write_10MB` | MB/s | Sequential write throughput, 10MB file |
| `seq_write_100MB` | MB/s | Sequential write throughput, 100MB file |
| `seq_read_1MB` | MB/s | Sequential read throughput, 1MB file |
| `seq_read_10MB` | MB/s | Sequential read throughput, 10MB file |
| `seq_read_100MB` | MB/s | Sequential read throughput, 100MB file |

### IOPS Metrics

| Metric | Unit | Description |
|--------|------|-------------|
| `rand_read_4k_iops` | IOPS | Random 4KB read I/O operations per second |
| `rand_write_4k_iops` | IOPS | Random 4KB write I/O operations per second |

### Directory Metrics

| Metric | Unit | Description |
|--------|------|-------------|
| `dir_enum_100` | entries/s | Directory listing speed, 100 files |
| `dir_enum_1000` | entries/s | Directory listing speed, 1000 files |
| `dir_enum_10000` | entries/s | Directory listing speed, 10000 files |

### File Operation Metrics

| Metric | Unit | Description |
|--------|------|-------------|
| `file_creation_rate` | files/s | File create+close throughput |
| `metadata_stat_rate` | ops/s | Metadata query (allinfo) throughput |
| `small_file_upload_rate` | files/s | Upload rate for 4KB files |
| `small_file_download_rate` | files/s | Download rate for 4KB files |

### Connection Metrics

| Metric | Unit | Description |
|--------|------|-------------|
| `connection_rate` | conn/s | New connection establishment rate |

### Concurrency Metrics

| Metric | Unit | Description |
|--------|------|-------------|
| `concurrent_1c_aggregate` | MB/s | Total throughput, 1 client |
| `concurrent_1c_perclient` | MB/s | Per-client throughput, 1 client |
| `concurrent_2c_aggregate` | MB/s | Total throughput, 2 clients |
| `concurrent_2c_perclient` | MB/s | Per-client throughput, 2 clients |
| `concurrent_4c_aggregate` | MB/s | Total throughput, 4 clients |
| `concurrent_4c_perclient` | MB/s | Per-client throughput, 4 clients |
| `concurrent_8c_aggregate` | MB/s | Total throughput, 8 clients |
| `concurrent_8c_perclient` | MB/s | Per-client throughput, 8 clients |

## What Affects Results

### Factors That Cause Variability

1. **Host system load** -- Other processes competing for CPU/disk/network
2. **VM resource allocation** -- CPU cores, memory assigned to the VM
3. **Disk I/O contention** -- Shared host storage between VMs
4. **Network stack state** -- TCP buffer sizes, socket backlog
5. **Kernel page cache** -- Warm vs. cold cache between runs
6. **smbclient overhead** -- Per-command fork+exec cost adds noise to small operations

### Tips for Consistent Results

1. **Dedicate the VM** -- Do not run other VMs during benchmarks
2. **Warm up first** -- The suite includes warmup runs; do not skip them
3. **Use multiple iterations** -- Default is 3 iterations with median selection
4. **Avoid quick mode for baselines** -- Quick mode is for development only
5. **Use mount.cifs for throughput** -- Set `--client mount.cifs` for more accurate
   sequential throughput numbers (requires host root access)
6. **Use fio for IOPS** -- Install fio on the host for accurate random I/O metrics
7. **Same kernel version** -- Compare baselines recorded on the same kernel
8. **Clean server state** -- The suite cleans up artifacts, but a fresh ksmbd
   module load between baselines ensures no stale state

### Recommended Hardware/OS Setup

- Dedicated host (no contention from other users)
- SSD storage for both host and VM disk images
- At least 4GB RAM assigned to the test VM
- Fixed CPU governor (`performance` mode, not `powersave`)
- Disable CPU frequency scaling: `cpupower frequency-set -g performance`
- Use the same kernel build for both baseline and comparison runs

## JSON Output Format

Each baseline is a JSON file with this structure:

```json
{
  "version": 1,
  "timestamp": "20260304T120000Z",
  "timestamp_epoch": 1772755200,
  "system_info": {
    "kernel_version": "6.18.9-arch1-2",
    "arch": "x86_64",
    "hostname": "ksmbd-vm3",
    "cpu_model": "AMD EPYC ...",
    "cpu_cores": 4,
    "memory_kb": 4194304,
    "ksmbd_version": "3.5.3"
  },
  "git_info": {
    "commit": "abc1234",
    "branch": "phase1-security-hardening",
    "dirty": false
  },
  "config": { ... },
  "summary": {
    "total_benchmarks": 20,
    "passed": 18,
    "failed": 2,
    "skipped": 0
  },
  "results": [
    {
      "name": "seq_write_10MB",
      "value": 123.456,
      "unit": "MB/s",
      "category": "throughput",
      "error": false
    }
  ]
}
```

## File Layout

```
tests/ksmbd-perf/
  perf_baseline.sh      Main benchmark runner
  perf_compare.sh       Two-file comparison tool
  perf_track.sh         History tracking and bisect helper
  perf_config.sh        Shared configuration defaults
  README.md             This file
  baselines/            Stored baseline JSON files
    .gitkeep
    registry.jsonl      History index (JSON-lines format)
    baseline_*.json     Individual baseline results
```
