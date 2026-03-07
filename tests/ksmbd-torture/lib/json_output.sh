#!/bin/bash
# lib/json_output.sh -- Compatibility shim for reporting.sh
#
# This file exists for backward compatibility. The authoritative reporting
# library is lib/reporting.sh. New code should source reporting.sh directly.

_JSON_SHIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Avoid double-sourcing
if [[ -z "${_REPORTING_LOADED:-}" ]]; then
    # shellcheck disable=SC1091
    source "${_JSON_SHIM_DIR}/reporting.sh"
    _REPORTING_LOADED=1
fi

# Legacy alias
json_generate_report() {
    generate_json_report "$@"
}
