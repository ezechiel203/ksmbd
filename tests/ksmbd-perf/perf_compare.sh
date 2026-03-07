#!/bin/bash
# perf_compare.sh -- Compare two ksmbd performance baseline JSON files
#
# Computes deltas for each metric, flags regressions and improvements,
# and produces a summary report.
#
# Usage:
#   ./perf_compare.sh [OPTIONS] <baseline.json> <current.json>
#
# Options:
#   --threshold N       Regression threshold percentage (default: 10)
#   --improvement N     Improvement threshold percentage (default: 10)
#   --strict            Any regression is a failure (threshold=0)
#   --lenient           Only flag regressions >20%
#   --json FILE         Write comparison results as JSON
#   --no-color          Disable color output
#   --quiet             Only print summary line
#   --help              Show this help
#
# Exit codes:
#   0  No regressions detected (within threshold)
#   1  Regressions detected
#   2  Input file error

set -uo pipefail

# ---------------------------------------------------------------------------
# Determine script location
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source configuration for default thresholds
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/perf_config.sh"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
REGRESSION_THRESHOLD="$PERF_REGRESSION_THRESHOLD"
IMPROVEMENT_THRESHOLD="$PERF_IMPROVEMENT_THRESHOLD"
JSON_OUTPUT=""
NO_COLOR="no"
QUIET="no"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
setup_colors() {
    if [[ "$NO_COLOR" == "yes" ]] || [[ ! -t 1 ]]; then
        RED="" GREEN="" YELLOW="" BLUE="" BOLD="" RESET=""
    else
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[0;33m'
        BLUE='\033[0;34m'
        BOLD='\033[1m'
        RESET='\033[0m'
    fi
}

# ---------------------------------------------------------------------------
# CLI Parsing
# ---------------------------------------------------------------------------
usage() {
    sed -n '2,/^$/s/^# //p' "$0"
}

BASELINE_FILE=""
CURRENT_FILE=""
POSITIONAL=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --threshold)    REGRESSION_THRESHOLD="$2"; shift 2 ;;
        --improvement)  IMPROVEMENT_THRESHOLD="$2"; shift 2 ;;
        --strict)       REGRESSION_THRESHOLD=0; shift ;;
        --lenient)      REGRESSION_THRESHOLD="$PERF_LENIENT_THRESHOLD"; shift ;;
        --json)         JSON_OUTPUT="$2"; shift 2 ;;
        --no-color)     NO_COLOR="yes"; shift ;;
        --quiet)        QUIET="yes"; shift ;;
        --help|-h)      usage; exit 0 ;;
        -*)             echo "Unknown option: $1" >&2; exit 2 ;;
        *)              POSITIONAL+=("$1"); shift ;;
    esac
done

if [[ ${#POSITIONAL[@]} -lt 2 ]]; then
    echo "Usage: $0 [OPTIONS] <baseline.json> <current.json>" >&2
    exit 2
fi

BASELINE_FILE="${POSITIONAL[0]}"
CURRENT_FILE="${POSITIONAL[1]}"

setup_colors

# ---------------------------------------------------------------------------
# Validate Inputs
# ---------------------------------------------------------------------------
if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "Error: Baseline file not found: $BASELINE_FILE" >&2
    exit 2
fi

if [[ ! -f "$CURRENT_FILE" ]]; then
    echo "Error: Current file not found: $CURRENT_FILE" >&2
    exit 2
fi

# Verify python3 is available for JSON parsing
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required for JSON parsing" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Comparison Logic (delegated to Python for robust JSON handling)
# ---------------------------------------------------------------------------
COMPARISON_OUTPUT=$(python3 -c "
import json
import sys

baseline_file = '$BASELINE_FILE'
current_file = '$CURRENT_FILE'
regression_threshold = float('$REGRESSION_THRESHOLD')
improvement_threshold = float('$IMPROVEMENT_THRESHOLD')

try:
    with open(baseline_file) as f:
        baseline = json.load(f)
    with open(current_file) as f:
        current = json.load(f)
except (json.JSONDecodeError, FileNotFoundError) as e:
    print(f'JSON_ERROR:{e}', file=sys.stderr)
    sys.exit(2)

# Build lookup from baseline results
base_metrics = {}
for r in baseline.get('results', []):
    if not r.get('error', False) and r.get('value') is not None:
        base_metrics[r['name']] = {
            'value': float(r['value']),
            'unit': r.get('unit', ''),
            'category': r.get('category', '')
        }

# Compare with current results
comparisons = []
regressions = 0
improvements = 0
unchanged = 0
new_metrics = 0
missing_metrics = 0

for r in current.get('results', []):
    name = r['name']
    unit = r.get('unit', '')
    category = r.get('category', '')

    if r.get('error', False) or r.get('value') is None:
        if name in base_metrics:
            comparisons.append({
                'name': name,
                'baseline': base_metrics[name]['value'],
                'current': None,
                'delta_pct': None,
                'unit': unit,
                'category': category,
                'status': 'error'
            })
            regressions += 1
        continue

    current_val = float(r['value'])

    if name not in base_metrics:
        comparisons.append({
            'name': name,
            'baseline': None,
            'current': current_val,
            'delta_pct': None,
            'unit': unit,
            'category': category,
            'status': 'new'
        })
        new_metrics += 1
        continue

    base_val = base_metrics[name]['value']

    if base_val == 0:
        if current_val == 0:
            delta_pct = 0.0
        else:
            delta_pct = 100.0
    else:
        delta_pct = ((current_val - base_val) / abs(base_val)) * 100.0

    # For all our metrics, higher is better (throughput, IOPS, ops/s, conn/s)
    if delta_pct < -regression_threshold:
        status = 'regression'
        regressions += 1
    elif delta_pct > improvement_threshold:
        status = 'improvement'
        improvements += 1
    else:
        status = 'unchanged'
        unchanged += 1

    comparisons.append({
        'name': name,
        'baseline': base_val,
        'current': current_val,
        'delta_pct': round(delta_pct, 2),
        'unit': unit,
        'category': category,
        'status': status
    })

    # Remove from base_metrics to track missing
    del base_metrics[name]

# Metrics in baseline but not in current
for name, info in base_metrics.items():
    comparisons.append({
        'name': name,
        'baseline': info['value'],
        'current': None,
        'delta_pct': None,
        'unit': info['unit'],
        'category': info['category'],
        'status': 'missing'
    })
    missing_metrics += 1

# Output as JSON for shell to parse
result = {
    'comparisons': comparisons,
    'summary': {
        'regressions': regressions,
        'improvements': improvements,
        'unchanged': unchanged,
        'new_metrics': new_metrics,
        'missing_metrics': missing_metrics,
        'total': len(comparisons),
        'regression_threshold': regression_threshold,
        'improvement_threshold': improvement_threshold
    },
    'baseline_info': {
        'timestamp': baseline.get('timestamp', 'unknown'),
        'git_commit': baseline.get('git_info', {}).get('commit', 'unknown'),
        'git_branch': baseline.get('git_info', {}).get('branch', 'unknown')
    },
    'current_info': {
        'timestamp': current.get('timestamp', 'unknown'),
        'git_commit': current.get('git_info', {}).get('commit', 'unknown'),
        'git_branch': current.get('git_info', {}).get('branch', 'unknown')
    }
}

print(json.dumps(result))
" 2>&1)

rc=$?
if [[ $rc -ne 0 ]]; then
    echo "Error parsing JSON files: $COMPARISON_OUTPUT" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Output JSON comparison if requested
# ---------------------------------------------------------------------------
if [[ -n "$JSON_OUTPUT" ]]; then
    echo "$COMPARISON_OUTPUT" | python3 -m json.tool > "$JSON_OUTPUT" 2>/dev/null
fi

# ---------------------------------------------------------------------------
# Text Report
# ---------------------------------------------------------------------------
python3 -c "
import json
import sys

data = json.loads('''$COMPARISON_OUTPUT''')

no_color = '$NO_COLOR' == 'yes' or not sys.stderr.isatty()
quiet = '$QUIET' == 'yes'

if no_color:
    RED = GREEN = YELLOW = BLUE = BOLD = RESET = ''
else:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

summary = data['summary']
comparisons = data['comparisons']
base_info = data['baseline_info']
curr_info = data['current_info']

if not quiet:
    print(f'{BOLD}=== ksmbd Performance Comparison ==={RESET}', file=sys.stderr)
    print(f'', file=sys.stderr)
    print(f'  Baseline: {base_info[\"timestamp\"]} (commit {base_info[\"git_commit\"]}, branch {base_info[\"git_branch\"]})', file=sys.stderr)
    print(f'  Current:  {curr_info[\"timestamp\"]} (commit {curr_info[\"git_commit\"]}, branch {curr_info[\"git_branch\"]})', file=sys.stderr)
    print(f'  Regression threshold: -{summary[\"regression_threshold\"]}%', file=sys.stderr)
    print(f'  Improvement threshold: +{summary[\"improvement_threshold\"]}%', file=sys.stderr)
    print(f'', file=sys.stderr)

    # Table header
    print(f'  {\"METRIC\":<35} {\"BASELINE\":>12} {\"CURRENT\":>12} {\"DELTA\":>10} {\"STATUS\":<15}', file=sys.stderr)
    print(f'  {\"-\"*35} {\"-\"*12} {\"-\"*12} {\"-\"*10} {\"-\"*15}', file=sys.stderr)

    # Sort: regressions first, then improvements, then unchanged
    status_order = {'regression': 0, 'error': 1, 'missing': 2, 'improvement': 3, 'unchanged': 4, 'new': 5}
    sorted_comp = sorted(comparisons, key=lambda x: (status_order.get(x['status'], 9), x['name']))

    for c in sorted_comp:
        name = c['name']
        base_str = f\"{c['baseline']:.3f}\" if c['baseline'] is not None else 'N/A'
        curr_str = f\"{c['current']:.3f}\" if c['current'] is not None else 'N/A'

        if c['delta_pct'] is not None:
            delta_str = f\"{c['delta_pct']:+.1f}%\"
        else:
            delta_str = 'N/A'

        status = c['status']
        if status == 'regression':
            color = RED
            tag = 'REGRESSION'
        elif status == 'improvement':
            color = GREEN
            tag = 'IMPROVEMENT'
        elif status == 'error':
            color = RED
            tag = 'ERROR'
        elif status == 'missing':
            color = YELLOW
            tag = 'MISSING'
        elif status == 'new':
            color = BLUE
            tag = 'NEW'
        else:
            color = ''
            tag = 'ok'

        print(f'  {name:<35} {base_str:>12} {curr_str:>12} {delta_str:>10} {color}{tag}{RESET}', file=sys.stderr)

    print(f'', file=sys.stderr)

# Summary line (always printed)
r = summary['regressions']
i = summary['improvements']
u = summary['unchanged']
n = summary['new_metrics']
m = summary['missing_metrics']

if r > 0:
    status_color = RED
    verdict = 'REGRESSIONS DETECTED'
else:
    status_color = GREEN
    verdict = 'NO REGRESSIONS'

print(f'{status_color}{BOLD}{verdict}{RESET}: {r} regression(s), {i} improvement(s), {u} unchanged, {n} new, {m} missing', file=sys.stderr)
" 2>&1

# ---------------------------------------------------------------------------
# Exit Code
# ---------------------------------------------------------------------------
HAS_REGRESSIONS=$(echo "$COMPARISON_OUTPUT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(data['summary']['regressions'])
" 2>/dev/null)

if [[ "${HAS_REGRESSIONS:-0}" -gt 0 ]]; then
    exit 1
fi
exit 0
