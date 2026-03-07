#!/bin/bash
# perf_track.sh -- Performance baseline history tracking for ksmbd
#
# Maintains a history of performance baselines, shows trends, and identifies
# commits that may have introduced regressions.
#
# Usage:
#   ./perf_track.sh <command> [OPTIONS]
#
# Commands:
#   record [FILE]         Save a baseline to the history. If FILE is omitted,
#                         runs perf_baseline.sh first to generate one.
#   history [--metric M]  Show history of baselines and trend data.
#   show <ID>             Show details of a specific baseline record.
#   latest                Show the most recent baseline.
#   bisect-hint <METRIC>  Suggest git commits to investigate for a regression
#                         in the given metric.
#   list                  List all recorded baselines.
#   clean [--keep N]      Remove old baselines, keeping the N most recent.
#   export [--csv FILE]   Export history data as CSV for external graphing.
#
# Options:
#   --baselines-dir DIR   Override baselines directory
#   --help                Show this help
#
# Exit codes:
#   0  Success
#   1  Command-specific error
#   2  Usage error

set -uo pipefail

# ---------------------------------------------------------------------------
# Script location and configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/perf_config.sh"

# Registry file: JSON-lines index of all recorded baselines
REGISTRY_FILE="${PERF_BASELINES_DIR}/registry.jsonl"

# ---------------------------------------------------------------------------
# Ensure baselines directory exists
# ---------------------------------------------------------------------------
mkdir -p "$PERF_BASELINES_DIR"

# ---------------------------------------------------------------------------
# CLI Parsing
# ---------------------------------------------------------------------------
usage() {
    sed -n '2,/^$/s/^# //p' "$0"
}

COMMAND=""
POSITIONAL=()
METRIC_FILTER=""
KEEP_COUNT=10
CSV_FILE=""

if [[ $# -eq 0 ]]; then
    usage
    exit 2
fi

COMMAND="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --baselines-dir)  PERF_BASELINES_DIR="$2"; REGISTRY_FILE="${PERF_BASELINES_DIR}/registry.jsonl"; shift 2 ;;
        --metric)         METRIC_FILTER="$2"; shift 2 ;;
        --keep)           KEEP_COUNT="$2"; shift 2 ;;
        --csv)            CSV_FILE="$2"; shift 2 ;;
        --help|-h)        usage; exit 0 ;;
        -*)               echo "Unknown option: $1" >&2; exit 2 ;;
        *)                POSITIONAL+=("$1"); shift ;;
    esac
done

# Verify python3 is available
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Registry Helpers
# ---------------------------------------------------------------------------

# Append a record to the registry (JSON-lines format)
registry_append() {
    local json="$1"
    echo "$json" >> "$REGISTRY_FILE"
}

# Read all registry records as a JSON array
registry_read_all() {
    if [[ ! -f "$REGISTRY_FILE" ]]; then
        echo "[]"
        return
    fi
    python3 -c "
import sys, json
records = []
for line in open('$REGISTRY_FILE'):
    line = line.strip()
    if line:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
print(json.dumps(records))
"
}

# Extract metadata from a baseline JSON file and create a registry entry
create_registry_entry() {
    local json_file="$1"
    python3 -c "
import json, os

with open('$json_file') as f:
    data = json.load(f)

entry = {
    'file': os.path.basename('$json_file'),
    'timestamp': data.get('timestamp', 'unknown'),
    'timestamp_epoch': data.get('timestamp_epoch', 0),
    'git_commit': data.get('git_info', {}).get('commit', 'unknown'),
    'git_branch': data.get('git_info', {}).get('branch', 'unknown'),
    'git_dirty': data.get('git_info', {}).get('dirty', False),
    'kernel_version': data.get('system_info', {}).get('kernel_version', 'unknown'),
    'vm_name': data.get('config', {}).get('vm_name', 'unknown'),
    'total_benchmarks': data.get('summary', {}).get('total_benchmarks', 0),
    'passed': data.get('summary', {}).get('passed', 0),
    'failed': data.get('summary', {}).get('failed', 0),
    'metrics': {}
}

for r in data.get('results', []):
    if not r.get('error', False) and r.get('value') is not None:
        entry['metrics'][r['name']] = {
            'value': float(r['value']),
            'unit': r.get('unit', '')
        }

print(json.dumps(entry))
"
}

# ---------------------------------------------------------------------------
# Command: record
# ---------------------------------------------------------------------------
cmd_record() {
    local json_file="${POSITIONAL[0]:-}"

    if [[ -z "$json_file" ]]; then
        echo "No baseline file specified. Running perf_baseline.sh to generate one..."
        "${SCRIPT_DIR}/perf_baseline.sh" "$@"
        # Find the most recently generated file
        json_file=$(ls -t "${PERF_BASELINES_DIR}"/baseline_*.json 2>/dev/null | head -1)
        if [[ -z "$json_file" ]]; then
            echo "Error: perf_baseline.sh did not produce an output file" >&2
            return 1
        fi
    fi

    if [[ ! -f "$json_file" ]]; then
        echo "Error: File not found: $json_file" >&2
        return 1
    fi

    # Validate JSON structure
    if ! python3 -c "import json; json.load(open('$json_file'))" 2>/dev/null; then
        echo "Error: Invalid JSON in $json_file" >&2
        return 1
    fi

    # Copy to baselines directory if not already there
    local basename
    basename=$(basename "$json_file")
    local dest="${PERF_BASELINES_DIR}/${basename}"

    if [[ "$json_file" != "$dest" ]]; then
        cp "$json_file" "$dest"
    fi

    # Create and append registry entry
    local entry
    entry=$(create_registry_entry "$dest")
    if [[ -z "$entry" ]]; then
        echo "Error: Failed to parse baseline metadata" >&2
        return 1
    fi

    registry_append "$entry"

    local commit branch timestamp
    commit=$(echo "$entry" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['git_commit'])")
    branch=$(echo "$entry" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['git_branch'])")
    timestamp=$(echo "$entry" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['timestamp'])")

    echo "Recorded baseline: ${basename}"
    echo "  Timestamp: ${timestamp}"
    echo "  Commit:    ${commit} (${branch})"
    echo "  File:      ${dest}"

    # If there is a previous baseline, run comparison
    local prev_file
    prev_file=$(ls -t "${PERF_BASELINES_DIR}"/baseline_*.json 2>/dev/null | grep -v "$basename" | head -1)
    if [[ -n "$prev_file" ]]; then
        echo ""
        echo "Comparison with previous baseline:"
        "${SCRIPT_DIR}/perf_compare.sh" "$prev_file" "$dest" || true
    fi
}

# ---------------------------------------------------------------------------
# Command: history
# ---------------------------------------------------------------------------
cmd_history() {
    local all_records
    all_records=$(registry_read_all)

    local record_count
    record_count=$(echo "$all_records" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")

    if [[ "$record_count" == "0" ]]; then
        echo "No baselines recorded yet. Run: $0 record <file.json>"
        return 0
    fi

    if [[ -n "$METRIC_FILTER" ]]; then
        # Show trend for a specific metric
        echo "=== Trend for metric: ${METRIC_FILTER} ==="
        echo ""

        python3 -c "
import json, sys

records = json.loads('''$(echo "$all_records")''')
metric = '$METRIC_FILTER'

# Sort by timestamp_epoch
records.sort(key=lambda r: r.get('timestamp_epoch', 0))

has_data = False
prev_val = None

print(f'  {\"TIMESTAMP\":<22} {\"COMMIT\":<10} {\"BRANCH\":<25} {\"VALUE\":>12} {\"UNIT\":<10} {\"DELTA\":>10}')
print(f'  {\"-\"*22} {\"-\"*10} {\"-\"*25} {\"-\"*12} {\"-\"*10} {\"-\"*10}')

for r in records:
    metrics = r.get('metrics', {})
    if metric in metrics:
        has_data = True
        val = metrics[metric]['value']
        unit = metrics[metric]['unit']
        ts = r.get('timestamp', 'unknown')
        commit = r.get('git_commit', '?')
        branch = r.get('git_branch', '?')

        if prev_val is not None and prev_val != 0:
            delta_pct = ((val - prev_val) / abs(prev_val)) * 100.0
            delta_str = f'{delta_pct:+.1f}%'
        else:
            delta_str = 'N/A'

        print(f'  {ts:<22} {commit:<10} {branch:<25} {val:>12.3f} {unit:<10} {delta_str:>10}')
        prev_val = val

if not has_data:
    print(f'  No data found for metric: {metric}')
    print(f'  Available metrics:', file=sys.stderr)
    all_metrics = set()
    for r in records:
        all_metrics.update(r.get('metrics', {}).keys())
    for m in sorted(all_metrics):
        print(f'    - {m}', file=sys.stderr)
"
    else
        # Show overview of all baselines
        echo "=== Baseline History ==="
        echo ""

        python3 -c "
import json, sys

records = json.loads('''$(echo "$all_records")''')
records.sort(key=lambda r: r.get('timestamp_epoch', 0))

print(f'  {\"#\":<4} {\"TIMESTAMP\":<22} {\"COMMIT\":<10} {\"BRANCH\":<25} {\"KERNEL\":<20} {\"PASS\":>4}/{\"TOTAL\":<4}')
print(f'  {\"-\"*4} {\"-\"*22} {\"-\"*10} {\"-\"*25} {\"-\"*20} {\"-\"*10}')

for i, r in enumerate(records, 1):
    ts = r.get('timestamp', 'unknown')
    commit = r.get('git_commit', '?')
    branch = r.get('git_branch', '?')
    kernel = r.get('kernel_version', '?')
    passed = r.get('passed', 0)
    total = r.get('total_benchmarks', 0)

    print(f'  {i:<4} {ts:<22} {commit:<10} {branch:<25} {kernel:<20} {passed:>4}/{total:<4}')

print(f'')
print(f'  Total baselines: {len(records)}')
print(f'')
print(f'  To see trends for a specific metric:')
print(f'    $0 history --metric <metric_name>')
print(f'')

# List available metrics from the most recent record
if records:
    last = records[-1]
    print(f'  Available metrics (from latest baseline):')
    for name in sorted(last.get('metrics', {}).keys()):
        info = last['metrics'][name]
        print(f'    - {name} ({info[\"unit\"]})')
"
    fi
}

# ---------------------------------------------------------------------------
# Command: show
# ---------------------------------------------------------------------------
cmd_show() {
    local target="${POSITIONAL[0]:-}"

    if [[ -z "$target" ]]; then
        echo "Usage: $0 show <ID|filename>" >&2
        return 2
    fi

    local all_records
    all_records=$(registry_read_all)

    python3 -c "
import json, sys

records = json.loads('''$(echo "$all_records")''')
target = '$target'

# Find record by index (1-based) or filename
found = None
records.sort(key=lambda r: r.get('timestamp_epoch', 0))

if target.isdigit():
    idx = int(target) - 1
    if 0 <= idx < len(records):
        found = records[idx]
elif target.startswith('baseline_'):
    for r in records:
        if r.get('file', '') == target or r.get('file', '') == target + '.json':
            found = r
            break
else:
    # Search by commit hash prefix
    for r in records:
        if r.get('git_commit', '').startswith(target):
            found = r

if found is None:
    print(f'No baseline found for: {target}', file=sys.stderr)
    sys.exit(1)

print(f'=== Baseline Details ===')
print(f'  File:      {found.get(\"file\", \"unknown\")}')
print(f'  Timestamp: {found.get(\"timestamp\", \"unknown\")}')
print(f'  Commit:    {found.get(\"git_commit\", \"unknown\")} ({found.get(\"git_branch\", \"unknown\")})')
print(f'  Kernel:    {found.get(\"kernel_version\", \"unknown\")}')
print(f'  VM:        {found.get(\"vm_name\", \"unknown\")}')
print(f'  Results:   {found.get(\"passed\", 0)} passed / {found.get(\"total_benchmarks\", 0)} total')
if found.get('git_dirty', False):
    print(f'  WARNING:   Working tree was dirty when this baseline was recorded')
print()

metrics = found.get('metrics', {})
if metrics:
    print(f'  {\"METRIC\":<35} {\"VALUE\":>15} {\"UNIT\":<10}')
    print(f'  {\"-\"*35} {\"-\"*15} {\"-\"*10}')
    for name in sorted(metrics.keys()):
        info = metrics[name]
        print(f'  {name:<35} {info[\"value\"]:>15.3f} {info[\"unit\"]:<10}')
"
}

# ---------------------------------------------------------------------------
# Command: latest
# ---------------------------------------------------------------------------
cmd_latest() {
    local all_records
    all_records=$(registry_read_all)

    local record_count
    record_count=$(echo "$all_records" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")

    if [[ "$record_count" == "0" ]]; then
        echo "No baselines recorded yet."
        return 0
    fi

    # Reuse cmd_show with the latest index
    POSITIONAL=("$record_count")
    cmd_show
}

# ---------------------------------------------------------------------------
# Command: list
# ---------------------------------------------------------------------------
cmd_list() {
    cmd_history
}

# ---------------------------------------------------------------------------
# Command: bisect-hint
# ---------------------------------------------------------------------------
cmd_bisect_hint() {
    local metric="${POSITIONAL[0]:-${METRIC_FILTER:-}}"

    if [[ -z "$metric" ]]; then
        echo "Usage: $0 bisect-hint <metric_name>" >&2
        echo "       $0 bisect-hint --metric <metric_name>" >&2
        return 2
    fi

    local all_records
    all_records=$(registry_read_all)

    python3 -c "
import json, sys

records = json.loads('''$(echo "$all_records")''')
metric = '$metric'
threshold = float('$PERF_REGRESSION_THRESHOLD')

# Sort by timestamp
records.sort(key=lambda r: r.get('timestamp_epoch', 0))

# Filter records that have this metric
data_points = []
for r in records:
    m = r.get('metrics', {})
    if metric in m:
        data_points.append({
            'timestamp': r.get('timestamp', 'unknown'),
            'commit': r.get('git_commit', 'unknown'),
            'branch': r.get('git_branch', 'unknown'),
            'value': m[metric]['value'],
            'unit': m[metric]['unit']
        })

if len(data_points) < 2:
    print(f'Not enough data points for metric \"{metric}\" (need >= 2, have {len(data_points)})')
    if len(data_points) == 0:
        print(f'')
        print(f'Available metrics:')
        all_metrics = set()
        for r in records:
            all_metrics.update(r.get('metrics', {}).keys())
        for m in sorted(all_metrics):
            print(f'  - {m}')
    sys.exit(1)

# Find the largest regression between consecutive data points
print(f'=== Bisect Hint for: {metric} ===')
print()

# Current vs best historical
best_val = max(dp['value'] for dp in data_points)
latest_val = data_points[-1]['value']
overall_delta = ((latest_val - best_val) / abs(best_val)) * 100.0 if best_val != 0 else 0

print(f'  Current value:  {latest_val:.3f} {data_points[-1][\"unit\"]}')
print(f'  Best recorded:  {best_val:.3f} {data_points[-1][\"unit\"]}')
print(f'  Overall change: {overall_delta:+.1f}%')
print()

# Find consecutive pair with largest drop
worst_drop = 0
worst_pair = None
for i in range(1, len(data_points)):
    prev = data_points[i-1]
    curr = data_points[i]
    if prev['value'] != 0:
        delta = ((curr['value'] - prev['value']) / abs(prev['value'])) * 100.0
        if delta < worst_drop:
            worst_drop = delta
            worst_pair = (prev, curr)

if worst_pair is not None and worst_drop < -threshold:
    before, after = worst_pair
    print(f'  Largest regression found between:')
    print(f'    BEFORE: commit {before[\"commit\"]} ({before[\"branch\"]}) -- value: {before[\"value\"]:.3f}')
    print(f'    AFTER:  commit {after[\"commit\"]} ({after[\"branch\"]}) -- value: {after[\"value\"]:.3f}')
    print(f'    Drop:   {worst_drop:.1f}%')
    print()
    print(f'  Suggested git bisect range:')
    print(f'    git bisect start')
    print(f'    git bisect bad {after[\"commit\"]}')
    print(f'    git bisect good {before[\"commit\"]}')
    print()
    print(f'  To test each commit during bisect, run:')
    print(f'    make EXTERNAL_SMBDIRECT=n all && <deploy to VM> && \\\\')
    print(f'    tests/ksmbd-perf/perf_baseline.sh --quick --only <relevant-bench>')
elif overall_delta < -threshold:
    print(f'  Regression is spread across multiple commits (no single large drop).')
    print(f'  Review the full trend:')
    print(f'    $0 history --metric {metric}')
else:
    print(f'  No significant regression detected (threshold: -{threshold}%).')
    print(f'  Current performance is within acceptable range.')
"
}

# ---------------------------------------------------------------------------
# Command: clean
# ---------------------------------------------------------------------------
cmd_clean() {
    local all_records
    all_records=$(registry_read_all)

    local record_count
    record_count=$(echo "$all_records" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")

    if [[ "$record_count" -le "$KEEP_COUNT" ]]; then
        echo "Only ${record_count} baselines exist (keeping ${KEEP_COUNT}). Nothing to clean."
        return 0
    fi

    local to_remove=$((record_count - KEEP_COUNT))
    echo "Removing ${to_remove} old baseline(s) (keeping ${KEEP_COUNT})..."

    # Get files to remove (oldest first)
    local files_to_remove
    files_to_remove=$(python3 -c "
import json, sys

records = json.loads('''$(echo "$all_records")''')
records.sort(key=lambda r: r.get('timestamp_epoch', 0))

keep = int('$KEEP_COUNT')
to_remove = records[:len(records) - keep]

for r in to_remove:
    print(r.get('file', ''))
")

    local removed=0
    while IFS= read -r fname; do
        if [[ -n "$fname" ]]; then
            local full_path="${PERF_BASELINES_DIR}/${fname}"
            if [[ -f "$full_path" ]]; then
                rm -f "$full_path"
                echo "  Removed: $fname"
                ((removed++))
            fi
        fi
    done <<< "$files_to_remove"

    # Rebuild registry with only kept records
    python3 -c "
import json

records = json.loads('''$(echo "$all_records")''')
records.sort(key=lambda r: r.get('timestamp_epoch', 0))

keep = int('$KEEP_COUNT')
kept = records[len(records) - keep:] if len(records) > keep else records

with open('$REGISTRY_FILE', 'w') as f:
    for r in kept:
        f.write(json.dumps(r) + '\n')
"

    echo "Removed ${removed} baseline file(s). Registry updated."
}

# ---------------------------------------------------------------------------
# Command: export
# ---------------------------------------------------------------------------
cmd_export() {
    local all_records
    all_records=$(registry_read_all)

    local output_file="${CSV_FILE:-/dev/stdout}"

    python3 -c "
import json, sys, csv, io

records = json.loads('''$(echo "$all_records")''')
records.sort(key=lambda r: r.get('timestamp_epoch', 0))

if not records:
    print('No baselines to export.', file=sys.stderr)
    sys.exit(0)

# Collect all metric names
all_metrics = set()
for r in records:
    all_metrics.update(r.get('metrics', {}).keys())

all_metrics = sorted(all_metrics)

# Write CSV
output_file = '$output_file'
if output_file == '/dev/stdout':
    f = sys.stdout
else:
    f = open(output_file, 'w', newline='')

writer = csv.writer(f)
header = ['timestamp', 'commit', 'branch', 'kernel'] + all_metrics
writer.writerow(header)

for r in records:
    row = [
        r.get('timestamp', ''),
        r.get('git_commit', ''),
        r.get('git_branch', ''),
        r.get('kernel_version', '')
    ]
    metrics = r.get('metrics', {})
    for m in all_metrics:
        if m in metrics:
            row.append(f\"{metrics[m]['value']:.6f}\")
        else:
            row.append('')
    writer.writerow(row)

if output_file != '/dev/stdout':
    f.close()
    print(f'Exported {len(records)} baselines to {output_file}', file=sys.stderr)
"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "$COMMAND" in
    record)       cmd_record ;;
    history)      cmd_history ;;
    show)         cmd_show ;;
    latest)       cmd_latest ;;
    list)         cmd_list ;;
    bisect-hint)  cmd_bisect_hint ;;
    clean)        cmd_clean ;;
    export)       cmd_export ;;
    --help|-h)    usage; exit 0 ;;
    *)
        echo "Unknown command: $COMMAND" >&2
        echo "Run: $0 --help" >&2
        exit 2
        ;;
esac
