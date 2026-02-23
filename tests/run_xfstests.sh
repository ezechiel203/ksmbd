#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# xfstests runner for ksmbd
#
# This script is a self-contained runner that sets up ksmbd, mounts
# CIFS shares, runs xfstests, and reports results.
#
# Prerequisites:
#   - ksmbd kernel module (loaded or loadable)
#   - ksmbd-tools (ksmbd.mountd, ksmbd.adduser, ksmbd.control)
#   - xfstests-dev (built from cifsd-test-result or installed)
#   - cifs-utils (for mount.cifs)
#   - fsgqa and 123456-fsgqa user accounts
#   - Root privileges
#
# Usage:
#   sudo ./run_xfstests.sh [OPTIONS]
#
# Options:
#   --quick          Run a quick subset (~20 core tests)
#   --test TESTID    Run a single test (e.g., generic/001)
#   --list           List all tests
#   --help, -h       Show this help message
#

set -e
set -u

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KSMBD_CONF_DIR="/etc/ksmbd"
KSMBD_CONF="${KSMBD_CONF_DIR}/ksmbd.conf"
KSMBD_CONF_BACKUP=""
TEST_USER="testuser"
TEST_PASS="1234"
XFSTESTS_DIR=""
MNT_TEST1="/mnt/test1"
MNT_TEST2="/mnt/test2"
MNT_TEST3="/mnt/test3"
MNT_1="/mnt/1"
MNT_2="/mnt/2"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_COUNT=0
QUICK_MODE=0
LIST_MODE=0
SINGLE_TEST=""

# ---------------------------------------------------------------------------
# Color output helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_head()  { echo -e "${BOLD}${CYAN}=== $* ===${NC}"; }

# ---------------------------------------------------------------------------
# Test result tracking
# ---------------------------------------------------------------------------
test_pass() {
	PASS_COUNT=$((PASS_COUNT + 1))
	TOTAL_COUNT=$((TOTAL_COUNT + 1))
	echo -e "  ${GREEN}PASS${NC}: $1"
}

test_fail() {
	FAIL_COUNT=$((FAIL_COUNT + 1))
	TOTAL_COUNT=$((TOTAL_COUNT + 1))
	echo -e "  ${RED}FAIL${NC}: $1"
}

test_skip() {
	SKIP_COUNT=$((SKIP_COUNT + 1))
	TOTAL_COUNT=$((TOTAL_COUNT + 1))
	echo -e "  ${YELLOW}SKIP${NC}: $1"
}

# ---------------------------------------------------------------------------
# Complete xfstests lists from the ksmbd CI pipeline
# ---------------------------------------------------------------------------
XFSTESTS_CIFS=(
	"cifs/001"
)

XFSTESTS_GENERIC=(
	"generic/001"
	"generic/002"
	"generic/005"
	"generic/006"
	"generic/007"
	"generic/008"
	"generic/010"
	"generic/011"
	"generic/014"
	"generic/023"
	"generic/024"
	"generic/028"
	"generic/029"
	"generic/030"
	"generic/032"
	"generic/033"
	"generic/036"
	"generic/037"
	"generic/043"
	"generic/044"
	"generic/045"
	"generic/046"
	"generic/051"
	"generic/069"
	"generic/071"
	"generic/072"
	"generic/074"
	"generic/080"
	"generic/084"
	"generic/086"
	"generic/091"
	"generic/095"
	"generic/098"
	"generic/100"
	"generic/103"
	"generic/109"
	"generic/113"
	"generic/117"
	"generic/124"
	"generic/125"
	"generic/129"
	"generic/130"
	"generic/132"
	"generic/133"
	"generic/135"
	"generic/141"
	"generic/169"
	"generic/198"
	"generic/207"
	"generic/208"
	"generic/210"
	"generic/211"
	"generic/212"
	"generic/214"
	"generic/215"
	"generic/221"
	"generic/225"
	"generic/228"
	"generic/236"
	"generic/239"
	"generic/241"
	"generic/245"
	"generic/246"
	"generic/247"
	"generic/248"
	"generic/249"
	"generic/257"
	"generic/258"
	"generic/263"
	"generic/308"
	"generic/309"
	"generic/310"
	"generic/313"
	"generic/315"
	"generic/316"
	"generic/323"
	"generic/337"
	"generic/339"
	"generic/340"
	"generic/344"
	"generic/345"
	"generic/346"
	"generic/349"
	"generic/350"
	"generic/354"
	"generic/360"
	"generic/377"
	"generic/391"
	"generic/393"
	"generic/394"
	"generic/406"
	"generic/412"
	"generic/420"
	"generic/428"
	"generic/430"
	"generic/431"
	"generic/432"
	"generic/433"
	"generic/436"
	"generic/437"
	"generic/438"
	"generic/439"
	"generic/443"
	"generic/445"
	"generic/446"
	"generic/448"
	"generic/451"
	"generic/452"
	"generic/454"
	"generic/460"
	"generic/461"
	"generic/464"
	"generic/465"
	"generic/469"
	"generic/504"
	"generic/523"
	"generic/524"
	"generic/528"
	"generic/532"
	"generic/533"
	"generic/539"
	"generic/565"
	"generic/567"
	"generic/568"
	"generic/599"
)

# Quick subset: ~20 core tests covering basic functionality
XFSTESTS_QUICK=(
	"cifs/001"
	"generic/001"
	"generic/002"
	"generic/005"
	"generic/006"
	"generic/007"
	"generic/008"
	"generic/010"
	"generic/014"
	"generic/023"
	"generic/028"
	"generic/029"
	"generic/032"
	"generic/036"
	"generic/043"
	"generic/080"
	"generic/084"
	"generic/100"
	"generic/117"
	"generic/245"
)

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
	case "$1" in
		--quick)
			QUICK_MODE=1
			shift
			;;
		--test)
			if [ $# -lt 2 ]; then
				log_error "--test requires a test ID argument (e.g., generic/001)"
				exit 1
			fi
			SINGLE_TEST="$2"
			shift 2
			;;
		--list)
			LIST_MODE=1
			shift
			;;
		--help|-h)
			echo "Usage: $0 [OPTIONS]"
			echo ""
			echo "Options:"
			echo "  --quick          Run a quick subset (~20 core tests)"
			echo "  --test TESTID    Run a single test (e.g., generic/001)"
			echo "  --list           List all available tests"
			echo "  --help, -h       Show this help message"
			exit 0
			;;
		*)
			log_error "Unknown option: $1"
			exit 1
			;;
	esac
done

# ---------------------------------------------------------------------------
# List mode
# ---------------------------------------------------------------------------
if [ "${LIST_MODE}" -eq 1 ]; then
	echo ""
	log_head "xfstests Test List for ksmbd"
	echo ""
	echo "CIFS tests (${#XFSTESTS_CIFS[@]}):"
	for t in "${XFSTESTS_CIFS[@]}"; do
		echo "  ${t}"
	done
	echo ""
	echo "Generic tests (${#XFSTESTS_GENERIC[@]}):"
	for t in "${XFSTESTS_GENERIC[@]}"; do
		echo "  ${t}"
	done
	echo ""
	local_total=$(( ${#XFSTESTS_CIFS[@]} + ${#XFSTESTS_GENERIC[@]} ))
	echo "Total: ${local_total} tests"
	echo ""
	exit 0
fi

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------
check_prerequisites() {
	log_info "Checking prerequisites..."
	local missing=0

	# Check for root
	if [ "$(id -u)" -ne 0 ]; then
		log_error "This script must be run as root"
		exit 1
	fi

	# Check for ksmbd module
	if ! modinfo ksmbd > /dev/null 2>&1; then
		log_error "ksmbd module not found. Build and install it first."
		missing=1
	fi

	# Check for cifs module
	if ! modinfo cifs > /dev/null 2>&1; then
		log_warn "cifs module not found. mount.cifs may not work."
	fi

	# Check for ksmbd-tools
	if ! command -v ksmbd.mountd > /dev/null 2>&1; then
		log_error "ksmbd.mountd not found. Install ksmbd-tools."
		missing=1
	fi

	if ! command -v ksmbd.adduser > /dev/null 2>&1; then
		log_error "ksmbd.adduser not found. Install ksmbd-tools."
		missing=1
	fi

	# Check for cifs-utils
	if ! command -v mount.cifs > /dev/null 2>&1; then
		log_error "mount.cifs not found. Install cifs-utils."
		missing=1
	fi

	# Check for fsgqa user (required by xfstests)
	if ! id fsgqa > /dev/null 2>&1; then
		log_warn "User 'fsgqa' does not exist. Creating..."
		useradd fsgqa 2>/dev/null || true
	fi

	if ! id 123456-fsgqa > /dev/null 2>&1; then
		log_warn "User '123456-fsgqa' does not exist. Creating..."
		useradd 123456-fsgqa 2>/dev/null || true
	fi

	# Find xfstests
	XFSTESTS_DIR=""
	local search_paths=(
		"${SCRIPT_DIR}/../cifsd-test-result/testsuites/xfstests-cifsd"
		"/opt/xfstests"
		"/usr/lib/xfstests"
		"${SCRIPT_DIR}/xfstests-cifsd"
	)
	for path in "${search_paths[@]}"; do
		if [ -d "${path}" ] && [ -x "${path}/check" ]; then
			XFSTESTS_DIR="${path}"
			break
		fi
	done

	if [ -z "${XFSTESTS_DIR}" ]; then
		log_error "xfstests not found. Searched: ${search_paths[*]}"
		log_error "Clone and build from: https://github.com/cifsd-team/cifsd-test-result"
		missing=1
	fi

	if [ $missing -ne 0 ]; then
		log_error "Missing prerequisites. Aborting."
		exit 1
	fi

	log_info "All prerequisites satisfied (xfstests: ${XFSTESTS_DIR})"
}

# ---------------------------------------------------------------------------
# Setup test environment
# ---------------------------------------------------------------------------
setup_environment() {
	log_info "Setting up test environment..."

	# Create mount and share directories
	mkdir -p "${MNT_TEST1}" && chmod 777 "${MNT_TEST1}"
	mkdir -p "${MNT_TEST2}" && chmod 777 "${MNT_TEST2}"
	mkdir -p "${MNT_TEST3}" && chmod 777 "${MNT_TEST3}"
	mkdir -p "${MNT_1}"
	mkdir -p "${MNT_2}"

	# Backup existing ksmbd configuration if present
	if [ -f "${KSMBD_CONF}" ]; then
		KSMBD_CONF_BACKUP="${KSMBD_CONF}.bak.$$"
		cp "${KSMBD_CONF}" "${KSMBD_CONF_BACKUP}"
		log_info "Backed up existing config to ${KSMBD_CONF_BACKUP}"
	fi

	# Create smb.conf for xfstests
	# This mirrors the CI configuration used in c-cpp.yml
	mkdir -p "${KSMBD_CONF_DIR}"
	cat > "${KSMBD_CONF}" <<-'SMBCONF'
	[global]
		workgroup = TESTGROUP
		server string = ksmbd xfstests server
		netbios name = KSMBDTEST

	[cifsd-test1]
		path = /mnt/test1
		read only = no
		browseable = yes
		guest ok = no
		force user = root

	[cifsd-test2]
		path = /mnt/test2
		read only = no
		browseable = yes
		guest ok = no
		force user = root

	[cifsd-test3]
		path = /mnt/test3
		read only = no
		browseable = yes
		guest ok = no
		force user = root
	SMBCONF
	log_info "Installed xfstests SMB configuration"

	# Set up password database
	echo "${TEST_PASS}" | ksmbd.adduser -a "${TEST_USER}" 2>/dev/null || true
	log_info "Added test user: ${TEST_USER}"

	# Load required kernel modules
	if ! lsmod | grep -q "^ksmbd"; then
		modprobe ksmbd
		log_info "Loaded ksmbd module"
	else
		log_info "ksmbd module already loaded"
	fi

	if ! lsmod | grep -q "^cifs"; then
		modprobe cifs 2>/dev/null || log_warn "Could not load cifs module"
	fi

	# Apply generic/011 patch to reduce test duration (as CI does)
	if [ -d "${XFSTESTS_DIR}" ]; then
		local test011="${XFSTESTS_DIR}/tests/generic/011"
		local test011out="${XFSTESTS_DIR}/tests/generic/011.out"
		if [ -f "${test011}" ]; then
			sed -e "s/count=1000/count=100/" -e "s/-p 5/-p 3/" "${test011}" > "${test011}.new"
			mv "${test011}.new" "${test011}"
			log_info "Patched generic/011 for faster execution"
		fi
		if [ -f "${test011out}" ]; then
			sed -e "s/-p 5/-p 3/" "${test011out}" > "${test011out}.new"
			mv "${test011out}.new" "${test011out}"
		fi
	fi
}

# ---------------------------------------------------------------------------
# Start ksmbd daemon
# ---------------------------------------------------------------------------
start_daemon() {
	log_info "Starting ksmbd.mountd daemon..."

	# Stop any existing instance
	ksmbd.control -s 2>/dev/null || true
	sleep 1

	# Kill any lingering mountd processes
	pkill -f ksmbd.mountd 2>/dev/null || true
	sleep 1

	# Start the daemon in the background
	ksmbd.mountd -n &
	local daemon_pid=$!
	sleep 2

	# Verify it's running
	if kill -0 "${daemon_pid}" 2>/dev/null; then
		log_info "ksmbd.mountd started (PID: ${daemon_pid})"
	else
		log_error "Failed to start ksmbd.mountd"
		return 1
	fi
}

# ---------------------------------------------------------------------------
# Run a single xfstest
# ---------------------------------------------------------------------------
run_single_xfstest() {
	local test_id="$1"

	log_info "Running xfstest: ${test_id}..."
	if (cd "${XFSTESTS_DIR}" && sudo ./check "${test_id}" 2>&1); then
		test_pass "${test_id}"
	else
		test_fail "${test_id}"
	fi
}

# ---------------------------------------------------------------------------
# Run all requested tests
# ---------------------------------------------------------------------------
run_tests() {
	local tests_to_run=()

	if [ -n "${SINGLE_TEST}" ]; then
		# Single test mode
		tests_to_run=("${SINGLE_TEST}")
	elif [ "${QUICK_MODE}" -eq 1 ]; then
		# Quick mode
		tests_to_run=("${XFSTESTS_QUICK[@]}")
	else
		# Full run: cifs + generic
		tests_to_run=("${XFSTESTS_CIFS[@]}" "${XFSTESTS_GENERIC[@]}")
	fi

	log_head "Running ${#tests_to_run[@]} xfstests"
	echo ""

	for test_id in "${tests_to_run[@]}"; do
		run_single_xfstest "${test_id}"
	done
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
	log_info "Cleaning up..."

	# Unmount any CIFS mounts
	umount "${MNT_1}" 2>/dev/null || true
	umount "${MNT_2}" 2>/dev/null || true

	# Stop ksmbd daemon
	ksmbd.control -s 2>/dev/null || true
	sleep 1

	# Kill any lingering mountd processes
	pkill -f ksmbd.mountd 2>/dev/null || true

	# Remove test user
	ksmbd.adduser -d "${TEST_USER}" 2>/dev/null || true

	# Restore original configuration
	if [ -n "${KSMBD_CONF_BACKUP}" ] && [ -f "${KSMBD_CONF_BACKUP}" ]; then
		mv "${KSMBD_CONF_BACKUP}" "${KSMBD_CONF}"
		log_info "Restored original configuration"
	else
		rm -f "${KSMBD_CONF}"
	fi

	# Clean up share directories
	rm -rf "${MNT_TEST1:?}"/* 2>/dev/null || true
	rm -rf "${MNT_TEST2:?}"/* 2>/dev/null || true
	rm -rf "${MNT_TEST3:?}"/* 2>/dev/null || true

	log_info "Cleanup complete."
}

# ---------------------------------------------------------------------------
# Report results
# ---------------------------------------------------------------------------
report_results() {
	echo ""
	log_head "xfstests Results"
	echo ""
	echo -e "  ${GREEN}PASSED:${NC}  ${PASS_COUNT}"
	echo -e "  ${RED}FAILED:${NC}  ${FAIL_COUNT}"
	echo -e "  ${YELLOW}SKIPPED:${NC} ${SKIP_COUNT}"
	echo -e "  TOTAL:   ${TOTAL_COUNT}"
	echo ""

	if [ "${FAIL_COUNT}" -gt 0 ]; then
		echo -e "  ${RED}RESULT: FAILURE${NC}"
		return 1
	else
		echo -e "  ${GREEN}RESULT: SUCCESS${NC}"
		return 0
	fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
	log_head "ksmbd xfstests Runner"
	echo ""

	# Ensure cleanup runs on exit
	trap cleanup EXIT

	check_prerequisites
	setup_environment
	start_daemon
	run_tests

	# Report results (cleanup happens via trap)
	report_results
}

main "$@"
