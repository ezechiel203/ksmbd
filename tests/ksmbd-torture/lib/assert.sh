#!/bin/bash
# lib/assert.sh -- Compatibility shim for assertions.sh
#
# This file exists for backward compatibility. The authoritative assertion
# library is lib/assertions.sh. New code should source assertions.sh directly.

_ASSERT_SHIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Avoid double-sourcing
if [[ -z "${_ASSERTIONS_LOADED:-}" ]]; then
    # shellcheck disable=SC1091
    source "${_ASSERT_SHIM_DIR}/assertions.sh"
    _ASSERTIONS_LOADED=1
fi
