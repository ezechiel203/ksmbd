#!/bin/bash
# shellcheck disable=SC2034  # TORTURE_SUITES_* arrays are accessed via nameref
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Comprehensive smbtorture test runner for ksmbd
#
# This script is a self-contained runner that sets up ksmbd, executes
# smbtorture test suites organized by category, and reports results.
#
# Prerequisites:
#   - ksmbd kernel module (loaded or loadable)
#   - ksmbd-tools (ksmbd.mountd, ksmbd.adduser, ksmbd.control)
#   - smbtorture (from Samba or cifsd-test-result)
#   - Root privileges
#
# Usage:
#   sudo ./run_smbtorture.sh [OPTIONS]
#
# Options:
#   --category CATEGORY  Run only the specified category
#   --quick              Run only connect, read, dir, create categories
#   --list               List all categories and test counts
#   --json               Output results in JSON format
#   --help, -h           Show this help message
#

set -e
set -u

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARE_DIR="/mnt/test3"
KSMBD_CONF_DIR="/etc/ksmbd"
KSMBD_CONF="${KSMBD_CONF_DIR}/ksmbd.conf"
KSMBD_CONF_BACKUP=""
SERVER="127.0.0.1"
SHARE_NAME="cifsd-test3"
TEST_USER="testuser"
TEST_PASS="1234"
SMBTORTURE_BIN=""
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_COUNT=0
RUN_CATEGORY=""
QUICK_MODE=0
LIST_MODE=0
JSON_OUTPUT=0
RESULTS_FILE=""
JSON_RESULTS=()

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

stop_ksmbd_daemon() {
	# Avoid hanging forever if control path gets wedged.
	if command -v timeout >/dev/null 2>&1; then
		timeout 10 ksmbd.control -s >/dev/null 2>&1 || true
	else
		ksmbd.control -s >/dev/null 2>&1 || true
	fi
	sleep 1
	pkill -x ksmbd.mountd >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Test result tracking
# ---------------------------------------------------------------------------
test_pass() {
	PASS_COUNT=$((PASS_COUNT + 1))
	TOTAL_COUNT=$((TOTAL_COUNT + 1))
	echo -e "  ${GREEN}PASS${NC}: $1"
	if [ "${JSON_OUTPUT}" -eq 1 ]; then
		JSON_RESULTS+=("{\"test\":\"$1\",\"result\":\"pass\"}")
	fi
}

test_fail() {
	FAIL_COUNT=$((FAIL_COUNT + 1))
	TOTAL_COUNT=$((TOTAL_COUNT + 1))
	echo -e "  ${RED}FAIL${NC}: $1"
	if [ "${JSON_OUTPUT}" -eq 1 ]; then
		JSON_RESULTS+=("{\"test\":\"$1\",\"result\":\"fail\"}")
	fi
}

test_skip() {
	SKIP_COUNT=$((SKIP_COUNT + 1))
	TOTAL_COUNT=$((TOTAL_COUNT + 1))
	echo -e "  ${YELLOW}SKIP${NC}: $1"
	if [ "${JSON_OUTPUT}" -eq 1 ]; then
		JSON_RESULTS+=("{\"test\":\"$1\",\"result\":\"skip\"}")
	fi
}

# ---------------------------------------------------------------------------
# SMB2 torture test suites organized by category
# Complete list extracted from the ksmbd CI pipeline
# Accessed via nameref in get_category_tests() / get_category_count()
# ---------------------------------------------------------------------------
TORTURE_SUITES_CONNECT=(
	"smb2.connect"
)

TORTURE_SUITES_READ=(
	"smb2.read.eof"
	"smb2.read.position"
	"smb2.read.dir"
	"smb2.read.access"
)

TORTURE_SUITES_SCAN=(
	"smb2.scan.scan"
	"smb2.scan.getinfo"
	"smb2.scan.setinfo"
	"smb2.scan.find"
)

TORTURE_SUITES_DIR=(
	"smb2.dir.find"
	"smb2.dir.fixed"
	"smb2.dir.many"
	"smb2.dir.modify"
	"smb2.dir.sorted"
	"smb2.dir.file-index"
	"smb2.dir.large-files"
)

TORTURE_SUITES_RENAME=(
	"smb2.rename.simple"
	"smb2.rename.simple_nodelete"
	"smb2.rename.no_sharing"
	"smb2.rename.share_delete_and_delete_access"
	"smb2.rename.no_share_delete_but_delete_access"
	"smb2.rename.share_delete_no_delete_access"
	"smb2.rename.msword"
	"smb2.rename.rename_dir_bench"
)

TORTURE_SUITES_MAXFID=(
	"smb2.maxfid"
)

TORTURE_SUITES_SHAREMODE=(
	"smb2.sharemode.sharemode-access"
	"smb2.sharemode.access-sharemode"
)

TORTURE_SUITES_COMPOUND=(
	"smb2.compound.related1"
	"smb2.compound.related2"
	"smb2.compound.related3"
	"smb2.compound.unrelated1"
	"smb2.compound.invalid1"
	"smb2.compound.invalid2"
	"smb2.compound.invalid3"
	"smb2.compound.interim2"
	"smb2.compound.compound-break"
	"smb2.compound.compound-padding"
)

TORTURE_SUITES_STREAMS=(
	"smb2.streams.dir"
	"smb2.streams.io"
	"smb2.streams.sharemodes"
	"smb2.streams.names"
	"smb2.streams.names2"
	"smb2.streams.names3"
	"smb2.streams.rename"
	"smb2.streams.rename2"
	"smb2.streams.create-disposition"
	"smb2.streams.zero-byte"
	"smb2.streams.basefile-rename-with-open-stream"
)

TORTURE_SUITES_CREATE=(
	"smb2.create.open"
	"smb2.create.brlocked"
	"smb2.create.multi"
	"smb2.create.delete"
	"smb2.create.leading-slash"
	"smb2.create.impersonation"
	"smb2.create.dir-alloc-size"
	"smb2.create.aclfile"
	"smb2.create.acldir"
	"smb2.create.nulldacl"
)

TORTURE_SUITES_DELETE_ON_CLOSE=(
	"smb2.delete-on-close-perms.OVERWRITE_IF"
	"smb2.delete-on-close-perms.OVERWRITE_IF Existing"
	"smb2.delete-on-close-perms.CREATE"
	"smb2.delete-on-close-perms.CREATE Existing"
	"smb2.delete-on-close-perms.CREATE_IF"
	"smb2.delete-on-close-perms.CREATE_IF Existing"
	"smb2.delete-on-close-perms.FIND_and_set_DOC"
)

TORTURE_SUITES_OPLOCK=(
	"smb2.oplock.exclusive1"
	"smb2.oplock.exclusive2"
	"smb2.oplock.exclusive3"
	"smb2.oplock.exclusive4"
	"smb2.oplock.exclusive5"
	"smb2.oplock.exclusive6"
	"smb2.oplock.exclusive9"
	"smb2.oplock.batch1"
	"smb2.oplock.batch2"
	"smb2.oplock.batch3"
	"smb2.oplock.batch4"
	"smb2.oplock.batch5"
	"smb2.oplock.batch6"
	"smb2.oplock.batch7"
	"smb2.oplock.batch8"
	"smb2.oplock.batch9"
	"smb2.oplock.batch9a"
	"smb2.oplock.batch10"
	"smb2.oplock.batch11"
	"smb2.oplock.batch12"
	"smb2.oplock.batch13"
	"smb2.oplock.batch14"
	"smb2.oplock.batch15"
	"smb2.oplock.batch16"
	"smb2.oplock.batch19"
	"smb2.oplock.batch20"
	"smb2.oplock.batch21"
	"smb2.oplock.batch22a"
	"smb2.oplock.batch23"
	"smb2.oplock.batch24"
	"smb2.oplock.batch25"
	"smb2.oplock.batch26"
	"smb2.oplock.doc"
	"smb2.oplock.brl1"
	"smb2.oplock.brl2"
	"smb2.oplock.brl3"
	"smb2.oplock.levelii500"
	"smb2.oplock.levelii501"
	"smb2.oplock.levelii502"
)

TORTURE_SUITES_SESSION=(
	"smb2.session.reconnect1"
	"smb2.session.reconnect2"
	"smb2.session.reauth1"
	"smb2.session.reauth2"
	"smb2.session.reauth3"
	"smb2.session.reauth4"
)

TORTURE_SUITES_LOCK=(
	"smb2.lock.valid-request"
	"smb2.lock.rw-shared"
	"smb2.lock.rw-exclusive"
	"smb2.lock.auto-unlock"
	"smb2.lock.async"
	"smb2.lock.cancel"
	"smb2.lock.cancel-tdis"
	"smb2.lock.cancel-logoff"
	"smb2.lock.zerobytelength"
	"smb2.lock.zerobyteread"
	"smb2.lock.unlock"
	"smb2.lock.multiple-unlock"
	"smb2.lock.stacking"
	"smb2.lock.contend"
	"smb2.lock.context"
	"smb2.lock.truncate"
)

TORTURE_SUITES_LEASE=(
	"smb2.lease.request"
	"smb2.lease.nobreakself"
	"smb2.lease.statopen"
	"smb2.lease.statopen2"
	"smb2.lease.statopen3"
	"smb2.lease.upgrade"
	"smb2.lease.upgrade2"
	"smb2.lease.upgrade3"
	"smb2.lease.break"
	"smb2.lease.oplock"
	"smb2.lease.multibreak"
	"smb2.lease.breaking1"
	"smb2.lease.breaking2"
	"smb2.lease.breaking3"
	"smb2.lease.breaking5"
	"smb2.lease.breaking6"
	"smb2.lease.lock1"
	"smb2.lease.complex1"
	"smb2.lease.timeout"
	"smb2.lease.v2_request_parent"
	"smb2.lease.v2_request"
	"smb2.lease.v2_epoch1"
	"smb2.lease.v2_epoch2"
	"smb2.lease.v2_epoch3"
	"smb2.lease.v2_complex2"
	"smb2.lease.v2_rename"
)

TORTURE_SUITES_ACLS=(
	"smb2.acls.CREATOR"
	"smb2.acls.GENERIC"
	"smb2.acls.OWNER"
	"smb2.acls.INHERITANCE"
	"smb2.acls.INHERITFLAGS"
	"smb2.acls.DYNAMIC"
)

TORTURE_SUITES_CREDITS=(
	"smb2.credits.session_setup_credits_granted"
	"smb2.credits.single_req_credits_granted"
	"smb2.credits.skipped_mid"
)

TORTURE_SUITES_DURABLE=(
	"smb2.durable-open.open-oplock"
	"smb2.durable-open.open-lease"
	"smb2.durable-open.reopen1"
	"smb2.durable-open.reopen1a"
	"smb2.durable-open.reopen1a-lease"
	"smb2.durable-open.reopen2"
	"smb2.durable-open.reopen2a"
	"smb2.durable-open.reopen2-lease"
	"smb2.durable-open.reopen2-lease-v2"
	"smb2.durable-open.reopen3"
	"smb2.durable-open.reopen4"
	"smb2.durable-open.delete_on_close2"
	"smb2.durable-open.file-position"
	"smb2.durable-open.lease"
	"smb2.durable-open.alloc-size"
	"smb2.durable-open.read-only"
	"smb2.durable-v2-open.create-blob"
	"smb2.durable-v2-open.open-oplock"
	"smb2.durable-v2-open.open-lease"
	"smb2.durable-v2-open.reopen1"
	"smb2.durable-v2-open.reopen1a"
	"smb2.durable-v2-open.reopen1a-lease"
	"smb2.durable-v2-open.reopen2"
	"smb2.durable-v2-open.reopen2b"
	"smb2.durable-v2-open.reopen2c"
	"smb2.durable-v2-open.reopen2-lease"
	"smb2.durable-v2-open.reopen2-lease-v2"
)

# Map category names to their array variable names
ALL_CATEGORIES=(
	"connect"
	"read"
	"scan"
	"dir"
	"rename"
	"maxfid"
	"sharemode"
	"compound"
	"streams"
	"create"
	"delete_on_close"
	"oplock"
	"session"
	"lock"
	"lease"
	"acls"
	"credits"
	"durable"
)

QUICK_CATEGORIES=("connect" "read" "dir" "create")

# ---------------------------------------------------------------------------
# Get the test array for a given category
# ---------------------------------------------------------------------------
get_category_tests() {
	local category="$1"
	local varname="TORTURE_SUITES_${category^^}"
	local -n arr="${varname}" 2>/dev/null || {
		log_error "Unknown category: ${category}"
		return 1
	}
	echo "${arr[@]}"
}

get_category_count() {
	local category="$1"
	local varname="TORTURE_SUITES_${category^^}"
	local -n arr="${varname}" 2>/dev/null || {
		echo "0"
		return
	}
	echo "${#arr[@]}"
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
	case "$1" in
		--category)
			if [ $# -lt 2 ]; then
				log_error "--category requires an argument"
				exit 1
			fi
			RUN_CATEGORY="$2"
			shift 2
			;;
		--quick)
			QUICK_MODE=1
			shift
			;;
		--list)
			LIST_MODE=1
			shift
			;;
		--json)
			JSON_OUTPUT=1
			shift
			;;
		--help|-h)
			echo "Usage: $0 [OPTIONS]"
			echo ""
			echo "Options:"
			echo "  --category CATEGORY  Run only the specified category"
			echo "  --quick              Run only connect, read, dir, create categories"
			echo "  --list               List all categories and test counts"
			echo "  --json               Output results in JSON format"
			echo "  --help, -h           Show this help message"
			echo ""
			echo "Categories: ${ALL_CATEGORIES[*]}"
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
	log_head "smbtorture Test Categories"
	echo ""
	local_total=0
	printf "  ${BOLD}%-20s %s${NC}\n" "CATEGORY" "TESTS"
	printf "  %-20s %s\n" "--------" "-----"
	for cat in "${ALL_CATEGORIES[@]}"; do
		count=$(get_category_count "${cat}")
		local_total=$((local_total + count))
		printf "  %-20s %d\n" "${cat}" "${count}"
	done
	echo ""
	printf "  ${BOLD}%-20s %d${NC}\n" "TOTAL" "${local_total}"
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

	# Check for ksmbd-tools
	if ! command -v ksmbd.mountd > /dev/null 2>&1; then
		log_error "ksmbd.mountd not found. Install ksmbd-tools."
		missing=1
	fi

	if ! command -v ksmbd.adduser > /dev/null 2>&1; then
		log_error "ksmbd.adduser not found. Install ksmbd-tools."
		missing=1
	fi

	# Check for smbtorture
	SMBTORTURE_BIN=""
	if command -v smbtorture > /dev/null 2>&1; then
		SMBTORTURE_BIN="smbtorture"
	elif [ -x "./bin/smbtorture" ]; then
		SMBTORTURE_BIN="./bin/smbtorture"
	elif [ -x "${SCRIPT_DIR}/../samba-cifsd/bin/smbtorture" ]; then
		SMBTORTURE_BIN="${SCRIPT_DIR}/../samba-cifsd/bin/smbtorture"
	fi

	if [ -z "${SMBTORTURE_BIN}" ]; then
		log_error "smbtorture not found. Install samba or build from cifsd-test-result."
		missing=1
	fi

	if [ $missing -ne 0 ]; then
		log_error "Missing prerequisites. Aborting."
		exit 1
	fi

	log_info "All prerequisites satisfied (smbtorture: ${SMBTORTURE_BIN})"
}

# ---------------------------------------------------------------------------
# Setup test environment
# ---------------------------------------------------------------------------
setup_environment() {
	log_info "Setting up test environment..."

	# Create share directory
	mkdir -p "${SHARE_DIR}"
	chmod 777 "${SHARE_DIR}"

	# Backup existing ksmbd configuration if present
	if [ -f "${KSMBD_CONF}" ]; then
		KSMBD_CONF_BACKUP="${KSMBD_CONF}.bak.$$"
		cp "${KSMBD_CONF}" "${KSMBD_CONF_BACKUP}"
		log_info "Backed up existing config to ${KSMBD_CONF_BACKUP}"
	fi

	# Create smb.conf for smbtorture tests
	mkdir -p "${KSMBD_CONF_DIR}"
	cat > "${KSMBD_CONF}" <<-SMBCONF
	[global]
		workgroup = TESTGROUP
		server string = ksmbd smbtorture test server
		netbios name = KSMBDTEST

	[${SHARE_NAME}]
		path = ${SHARE_DIR}
		read only = no
		browseable = yes
		guest ok = no
		force user = root
	SMBCONF
	log_info "Installed smbtorture test configuration"

	# Add/update test user with non-interactive password input
	ksmbd.adduser -a -p "${TEST_PASS}" "${TEST_USER}" 2>/dev/null || \
		ksmbd.adduser -u -p "${TEST_PASS}" "${TEST_USER}" 2>/dev/null || true
	log_info "Added test user: ${TEST_USER}"

	# Load ksmbd module if not already loaded
	if ! lsmod | grep -q "^ksmbd"; then
		modprobe ksmbd
		log_info "Loaded ksmbd module"
	else
		log_info "ksmbd module already loaded"
	fi

	# Create results file
	RESULTS_FILE="/tmp/smbtorture_results_$$.txt"
	: > "${RESULTS_FILE}"
}

# ---------------------------------------------------------------------------
# Start ksmbd daemon
# ---------------------------------------------------------------------------
start_daemon() {
	log_info "Starting ksmbd.mountd daemon..."

	# Stop any existing instance
	stop_ksmbd_daemon
	sleep 1

	# Start the daemon
	ksmbd.mountd &
	local daemon_pid=$!
	sleep 2

	# Verify it's running. ksmbd.mountd can daemonize and exit parent.
	local running_pid
	running_pid="$(pgrep -x ksmbd.mountd | head -n1 || true)"
	if [ -n "${running_pid}" ]; then
		log_info "ksmbd.mountd started (PID: ${running_pid})"
	else
		log_error "Failed to start ksmbd.mountd"
		return 1
	fi
}

# ---------------------------------------------------------------------------
# Run a single smbtorture test
# ---------------------------------------------------------------------------
run_single_test() {
	local test_name="$1"

	if "${SMBTORTURE_BIN}" "//${SERVER}/${SHARE_NAME}" \
		-U "${TEST_USER}%${TEST_PASS}" \
		"${test_name}" 2>&1; then
		test_pass "${test_name}"
	else
		test_fail "${test_name}"
	fi

	# Clean up share directory between tests (as CI does)
	rm -rf "${SHARE_DIR:?}"/*
}

# ---------------------------------------------------------------------------
# Run a category of tests
# ---------------------------------------------------------------------------
run_category() {
	local category="$1"
	local varname="TORTURE_SUITES_${category^^}"
	local -n tests="${varname}" 2>/dev/null || {
		log_error "Unknown category: ${category}"
		return 1
	}

	log_head "Category: ${category} (${#tests[@]} tests)"

	for test_name in "${tests[@]}"; do
		run_single_test "${test_name}"
	done
}

# ---------------------------------------------------------------------------
# Run all requested tests
# ---------------------------------------------------------------------------
run_tests() {
	local categories_to_run=()

	if [ -n "${RUN_CATEGORY}" ]; then
		# Single category mode
		categories_to_run=("${RUN_CATEGORY}")
	elif [ "${QUICK_MODE}" -eq 1 ]; then
		# Quick mode
		categories_to_run=("${QUICK_CATEGORIES[@]}")
	else
		# Full run
		categories_to_run=("${ALL_CATEGORIES[@]}")
	fi

	local total_tests=0
	for cat in "${categories_to_run[@]}"; do
		count=$(get_category_count "${cat}")
		total_tests=$((total_tests + count))
	done

	log_head "Running ${total_tests} smbtorture tests across ${#categories_to_run[@]} categories"
	echo ""

	for cat in "${categories_to_run[@]}"; do
		run_category "${cat}"
		echo ""
	done
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
	log_info "Cleaning up..."

	# Stop ksmbd daemon
	stop_ksmbd_daemon

	# Remove test user
	ksmbd.adduser -d "${TEST_USER}" 2>/dev/null || true

	# Restore original configuration
	if [ -n "${KSMBD_CONF_BACKUP}" ] && [ -f "${KSMBD_CONF_BACKUP}" ]; then
		mv "${KSMBD_CONF_BACKUP}" "${KSMBD_CONF}"
		log_info "Restored original configuration"
	else
		rm -f "${KSMBD_CONF}"
	fi

	# Clean up share directory
	rm -rf "${SHARE_DIR:?}"/*

	log_info "Cleanup complete."
}

# ---------------------------------------------------------------------------
# Report results
# ---------------------------------------------------------------------------
report_results() {
	echo ""
	log_head "smbtorture Test Results"
	echo ""
	echo -e "  ${GREEN}PASSED:${NC}  ${PASS_COUNT}"
	echo -e "  ${RED}FAILED:${NC}  ${FAIL_COUNT}"
	echo -e "  ${YELLOW}SKIPPED:${NC} ${SKIP_COUNT}"
	echo -e "  TOTAL:   ${TOTAL_COUNT}"
	echo ""

	if [ "${JSON_OUTPUT}" -eq 1 ]; then
		local json_file="/tmp/smbtorture_results_$$.json"
		{
			echo "{"
			echo "  \"summary\": {"
			echo "    \"passed\": ${PASS_COUNT},"
			echo "    \"failed\": ${FAIL_COUNT},"
			echo "    \"skipped\": ${SKIP_COUNT},"
			echo "    \"total\": ${TOTAL_COUNT}"
			echo "  },"
			echo "  \"tests\": ["
			local first=1
			for entry in "${JSON_RESULTS[@]}"; do
				if [ "${first}" -eq 1 ]; then
					first=0
				else
					echo ","
				fi
				echo -n "    ${entry}"
			done
			echo ""
			echo "  ]"
			echo "}"
		} > "${json_file}"
		log_info "JSON results written to: ${json_file}"
	fi

	# Write text results file
	if [ -n "${RESULTS_FILE}" ]; then
		{
			echo "smbtorture Test Results"
			echo "======================"
			echo "PASSED:  ${PASS_COUNT}"
			echo "FAILED:  ${FAIL_COUNT}"
			echo "SKIPPED: ${SKIP_COUNT}"
			echo "TOTAL:   ${TOTAL_COUNT}"
		} > "${RESULTS_FILE}"
		log_info "Text results written to: ${RESULTS_FILE}"
	fi

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
	log_head "ksmbd smbtorture Test Runner"
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
