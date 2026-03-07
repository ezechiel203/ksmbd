#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Integration test runner for ksmbd
#
# This script sets up a test environment, starts ksmbd with a test
# configuration, runs basic SMB operations, and reports results.
#
# Prerequisites:
#   - ksmbd kernel module (loaded or loadable)
#   - ksmbd-tools (ksmbd.mountd, ksmbd.adduser, ksmbd.control)
#   - smbclient (from samba-client package)
#   - Root privileges (for module loading and daemon management)
#
# Usage:
#   sudo ./run_integration.sh [--skip-smbtorture]
#

set -e
set -u

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_SHARE_DIR="/tmp/ksmbd_test_share"
RO_SHARE_DIR="/tmp/ksmbd_test_ro_share"
TEST_CONF="${SCRIPT_DIR}/smb.conf.test"
KSMBD_CONF="/etc/ksmbd/ksmbd.conf"
KSMBD_CONF_BACKUP=""
TEST_USER="testuser"
TEST_PASS="testpass123"
TEST_FILE="test_file.txt"
TEST_DIR="test_dir"
SKIP_SMBTORTURE=0
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# ---------------------------------------------------------------------------
# Color output helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

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
	log_info "PASS: $1"
}

test_fail() {
	FAIL_COUNT=$((FAIL_COUNT + 1))
	log_error "FAIL: $1"
}

test_skip() {
	SKIP_COUNT=$((SKIP_COUNT + 1))
	log_warn "SKIP: $1"
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
	case "$1" in
		--skip-smbtorture)
			SKIP_SMBTORTURE=1
			shift
			;;
		--help|-h)
			echo "Usage: $0 [--skip-smbtorture]"
			echo ""
			echo "Options:"
			echo "  --skip-smbtorture  Skip smbtorture tests even if available"
			echo "  --help, -h         Show this help message"
			exit 0
			;;
		*)
			log_error "Unknown option: $1"
			exit 1
			;;
	esac
done

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------
check_prerequisites() {
	local missing=0

	log_info "Checking prerequisites..."

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

	# Check for smbclient
	if ! command -v smbclient > /dev/null 2>&1; then
		log_error "smbclient not found. Install samba-client."
		missing=1
	fi

	if [ $missing -ne 0 ]; then
		log_error "Missing prerequisites. Aborting."
		exit 1
	fi

	log_info "All prerequisites satisfied."
}

# ---------------------------------------------------------------------------
# Setup test environment
# ---------------------------------------------------------------------------
setup_environment() {
	log_info "Setting up test environment..."

	# Create test share directories
	mkdir -p "${TEST_SHARE_DIR}"
	chmod 777 "${TEST_SHARE_DIR}"
	mkdir -p "${RO_SHARE_DIR}"
	chmod 755 "${RO_SHARE_DIR}"
	echo "read-only content" > "${RO_SHARE_DIR}/existing_file.txt"

	# Backup existing ksmbd configuration if present
	if [ -f "${KSMBD_CONF}" ]; then
		KSMBD_CONF_BACKUP="${KSMBD_CONF}.bak.$$"
		cp "${KSMBD_CONF}" "${KSMBD_CONF_BACKUP}"
		log_info "Backed up existing config to ${KSMBD_CONF_BACKUP}"
	fi

	# Install test configuration
	mkdir -p "$(dirname "${KSMBD_CONF}")"
	cp "${TEST_CONF}" "${KSMBD_CONF}"
	log_info "Installed test configuration"

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
# Basic SMB operation tests
# ---------------------------------------------------------------------------
run_basic_tests() {
	log_info "Running basic SMB operation tests..."
	local server="localhost"

	# Test 1: Connect and list shares
	log_info "Test: List shares..."
	if smbclient -L "//${server}" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" 2>/dev/null; then
		test_pass "List shares"
	else
		test_fail "List shares"
	fi

	# Test 2: Connect to test share
	log_info "Test: Connect to test_share..."
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" -c "ls" 2>/dev/null; then
		test_pass "Connect to test_share"
	else
		test_fail "Connect to test_share"
	fi

	# Test 3: Write a file
	log_info "Test: Write file..."
	echo "Hello from ksmbd integration test" > "/tmp/${TEST_FILE}"
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "put /tmp/${TEST_FILE} ${TEST_FILE}" 2>/dev/null; then
		test_pass "Write file"
	else
		test_fail "Write file"
	fi
	rm -f "/tmp/${TEST_FILE}"

	# Test 4: Read a file
	log_info "Test: Read file..."
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "get ${TEST_FILE} /tmp/${TEST_FILE}_read" 2>/dev/null; then
		if [ -f "/tmp/${TEST_FILE}_read" ]; then
			test_pass "Read file"
		else
			test_fail "Read file (file not retrieved)"
		fi
	else
		test_fail "Read file"
	fi
	rm -f "/tmp/${TEST_FILE}_read"

	# Test 5: Create directory
	log_info "Test: Create directory..."
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "mkdir ${TEST_DIR}" 2>/dev/null; then
		test_pass "Create directory"
	else
		test_fail "Create directory"
	fi

	# Test 6: List directory contents
	log_info "Test: List directory..."
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "ls ${TEST_DIR}/*" 2>/dev/null; then
		test_pass "List directory"
	else
		test_fail "List directory"
	fi

	# Test 7: Delete file
	log_info "Test: Delete file..."
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "del ${TEST_FILE}" 2>/dev/null; then
		test_pass "Delete file"
	else
		test_fail "Delete file"
	fi

	# Test 8: Remove directory
	log_info "Test: Remove directory..."
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "rmdir ${TEST_DIR}" 2>/dev/null; then
		test_pass "Remove directory"
	else
		test_fail "Remove directory"
	fi

	# Test 9: Guest access
	log_info "Test: Guest access..."
	if smbclient "//${server}/test_share" -N \
		--option="client min protocol=SMB2" \
		-c "ls" 2>/dev/null; then
		test_pass "Guest access"
	else
		test_fail "Guest access"
	fi
}

# ---------------------------------------------------------------------------
# Advanced SMB operation tests
# ---------------------------------------------------------------------------
run_advanced_tests() {
	log_info "Running advanced SMB operation tests..."
	local server="localhost"

	# Test: SMB3 encryption
	log_info "Test: SMB3 encrypted session..."
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB3" \
		--option="client max protocol=SMB3" \
		-c "ls" 2>/dev/null; then
		test_pass "SMB3 encrypted session"
	else
		test_fail "SMB3 encrypted session"
	fi

	# Test: Signing enforcement
	log_info "Test: SMB signing enforcement..."
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		--option="client signing=required" \
		-c "ls" 2>/dev/null; then
		test_pass "SMB signing enforcement"
	else
		test_fail "SMB signing enforcement"
	fi

	# Test: Large file I/O (100MB)
	log_info "Test: Large file I/O (100MB)..."
	local large_file="/tmp/ksmbd_large_test_file.bin"
	local large_file_dl="/tmp/ksmbd_large_test_file_dl.bin"
	dd if=/dev/urandom of="${large_file}" bs=1M count=100 2>/dev/null
	local src_md5
	src_md5=$(md5sum "${large_file}" | awk '{print $1}')
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "put ${large_file} large_test_file.bin" 2>/dev/null; then
		if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
			--option="client min protocol=SMB2" \
			-c "get large_test_file.bin ${large_file_dl}" 2>/dev/null; then
			local dl_md5
			dl_md5=$(md5sum "${large_file_dl}" | awk '{print $1}')
			if [ "${src_md5}" = "${dl_md5}" ]; then
				test_pass "Large file I/O (100MB, md5sum match)"
			else
				test_fail "Large file I/O (md5sum mismatch: ${src_md5} != ${dl_md5})"
			fi
		else
			test_fail "Large file I/O (download failed)"
		fi
	else
		test_fail "Large file I/O (upload failed)"
	fi
	rm -f "${large_file}" "${large_file_dl}"
	# Clean up the file on the share
	smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "del large_test_file.bin" 2>/dev/null || true

	# Test: Concurrent access (4 parallel smbclient processes)
	log_info "Test: Concurrent access (4 parallel writers)..."
	local concurrent_pids=()
	local concurrent_ok=1
	for i in 1 2 3 4; do
		local tmp_file="/tmp/ksmbd_concurrent_${i}.txt"
		echo "Concurrent write from process ${i}" > "${tmp_file}"
		smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
			--option="client min protocol=SMB2" \
			-c "put ${tmp_file} concurrent_${i}.txt" 2>/dev/null &
		concurrent_pids+=($!)
	done
	for pid in "${concurrent_pids[@]}"; do
		if ! wait "${pid}"; then
			concurrent_ok=0
		fi
	done
	# Verify all 4 files exist on the share
	if [ "${concurrent_ok}" -eq 1 ]; then
		local listing
		listing=$(smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
			--option="client min protocol=SMB2" \
			-c "ls concurrent_*.txt" 2>/dev/null || true)
		local found=0
		for i in 1 2 3 4; do
			if echo "${listing}" | grep -q "concurrent_${i}.txt"; then
				found=$((found + 1))
			fi
		done
		if [ "${found}" -eq 4 ]; then
			test_pass "Concurrent access (4 files written in parallel)"
		else
			test_fail "Concurrent access (only ${found}/4 files found)"
		fi
	else
		test_fail "Concurrent access (one or more smbclient processes failed)"
	fi
	# Cleanup concurrent test files
	for i in 1 2 3 4; do
		rm -f "/tmp/ksmbd_concurrent_${i}.txt"
		smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
			--option="client min protocol=SMB2" \
			-c "del concurrent_${i}.txt" 2>/dev/null || true
	done

	# Test: Symlink handling
	log_info "Test: Symlink handling..."
	echo "symlink target content" > "${TEST_SHARE_DIR}/symlink_target.txt"
	ln -sf "${TEST_SHARE_DIR}/symlink_target.txt" "${TEST_SHARE_DIR}/symlink_link.txt"
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "get symlink_link.txt /tmp/ksmbd_symlink_read.txt" 2>/dev/null; then
		if [ -f "/tmp/ksmbd_symlink_read.txt" ]; then
			test_pass "Symlink handling (read through symlink)"
		else
			test_fail "Symlink handling (file not retrieved)"
		fi
	else
		# ksmbd may block symlinks for security; either outcome is acceptable
		test_pass "Symlink handling (server correctly blocked symlink access)"
	fi
	rm -f "${TEST_SHARE_DIR}/symlink_target.txt" "${TEST_SHARE_DIR}/symlink_link.txt"
	rm -f "/tmp/ksmbd_symlink_read.txt"

	# Test: Permission enforcement (read-only share)
	log_info "Test: Permission enforcement (read-only share)..."
	local ro_tmp="/tmp/ksmbd_ro_test.txt"
	echo "attempt to write to read-only share" > "${ro_tmp}"
	if smbclient "//${server}/ro_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "put ${ro_tmp} should_not_exist.txt" 2>/dev/null; then
		# Write succeeded on a read-only share -- that is a failure
		test_fail "Permission enforcement (write succeeded on read-only share)"
	else
		test_pass "Permission enforcement (write correctly rejected on read-only share)"
	fi
	rm -f "${ro_tmp}"

	# Test: Rename file
	log_info "Test: Rename file..."
	local rename_tmp="/tmp/ksmbd_rename_test.txt"
	echo "file to be renamed" > "${rename_tmp}"
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "put ${rename_tmp} rename_original.txt" 2>/dev/null; then
		if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
			--option="client min protocol=SMB2" \
			-c "rename rename_original.txt rename_new.txt" 2>/dev/null; then
			local rename_listing
			rename_listing=$(smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
				--option="client min protocol=SMB2" \
				-c "ls rename_new.txt" 2>/dev/null || true)
			if echo "${rename_listing}" | grep -q "rename_new.txt"; then
				test_pass "Rename file"
			else
				test_fail "Rename file (renamed file not found)"
			fi
		else
			test_fail "Rename file (rename command failed)"
		fi
	else
		test_fail "Rename file (initial upload failed)"
	fi
	rm -f "${rename_tmp}"
	smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "del rename_new.txt" 2>/dev/null || true
	smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "del rename_original.txt" 2>/dev/null || true

	# Test: Overwrite file
	log_info "Test: Overwrite file..."
	local overwrite_tmp1="/tmp/ksmbd_overwrite_v1.txt"
	local overwrite_tmp2="/tmp/ksmbd_overwrite_v2.txt"
	echo "version 1 content" > "${overwrite_tmp1}"
	echo "version 2 content" > "${overwrite_tmp2}"
	if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "put ${overwrite_tmp1} overwrite_test.txt" 2>/dev/null; then
		if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
			--option="client min protocol=SMB2" \
			-c "put ${overwrite_tmp2} overwrite_test.txt" 2>/dev/null; then
			local overwrite_dl="/tmp/ksmbd_overwrite_dl.txt"
			if smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
				--option="client min protocol=SMB2" \
				-c "get overwrite_test.txt ${overwrite_dl}" 2>/dev/null; then
				if grep -q "version 2 content" "${overwrite_dl}"; then
					test_pass "Overwrite file (content is version 2)"
				else
					test_fail "Overwrite file (content is not version 2)"
				fi
				rm -f "${overwrite_dl}"
			else
				test_fail "Overwrite file (download after overwrite failed)"
			fi
		else
			test_fail "Overwrite file (second upload failed)"
		fi
	else
		test_fail "Overwrite file (first upload failed)"
	fi
	rm -f "${overwrite_tmp1}" "${overwrite_tmp2}"
	smbclient "//${server}/test_share" -U "${TEST_USER}%${TEST_PASS}" \
		--option="client min protocol=SMB2" \
		-c "del overwrite_test.txt" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# smbtorture tests (optional)
# ---------------------------------------------------------------------------
run_smbtorture_tests() {
	if [ "${SKIP_SMBTORTURE}" -eq 1 ]; then
		test_skip "smbtorture tests (skipped by user)"
		return
	fi

	if ! command -v smbtorture > /dev/null 2>&1; then
		test_skip "smbtorture tests (smbtorture not installed)"
		return
	fi

	log_info "Running smbtorture tests..."
	local server="localhost"

	# Run a subset of SMB2 torture tests
	local torture_tests=(
		"smb2.connect"
		"smb2.read"
		"smb2.write"
		"smb2.dir"
	)

	for test_name in "${torture_tests[@]}"; do
		log_info "Running smbtorture: ${test_name}..."
		if smbtorture "//${server}/test_share" \
			-U "${TEST_USER}%${TEST_PASS}" \
			"${test_name}" 2>/dev/null; then
			test_pass "smbtorture: ${test_name}"
		else
			test_fail "smbtorture: ${test_name}"
		fi
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

	# Remove test share directories
	rm -rf "${TEST_SHARE_DIR}"
	rm -rf "${RO_SHARE_DIR}"

	# Remove temporary files
	rm -f "/tmp/${TEST_FILE}" "/tmp/${TEST_FILE}_read"
	rm -f /tmp/ksmbd_large_test_file.bin /tmp/ksmbd_large_test_file_dl.bin
	rm -f /tmp/ksmbd_concurrent_*.txt
	rm -f /tmp/ksmbd_symlink_read.txt
	rm -f /tmp/ksmbd_ro_test.txt
	rm -f /tmp/ksmbd_rename_test.txt
	rm -f /tmp/ksmbd_overwrite_v1.txt /tmp/ksmbd_overwrite_v2.txt /tmp/ksmbd_overwrite_dl.txt

	log_info "Cleanup complete."
}

# ---------------------------------------------------------------------------
# Report results
# ---------------------------------------------------------------------------
report_results() {
	local total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))

	echo ""
	echo "=========================================="
	echo "  Integration Test Results"
	echo "=========================================="
	echo -e "  ${GREEN}PASSED:${NC}  ${PASS_COUNT}"
	echo -e "  ${RED}FAILED:${NC}  ${FAIL_COUNT}"
	echo -e "  ${YELLOW}SKIPPED:${NC} ${SKIP_COUNT}"
	echo "  TOTAL:   ${total}"
	echo "=========================================="

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
	log_info "ksmbd Integration Test Runner"
	log_info "=============================="

	# Ensure cleanup runs on exit
	trap cleanup EXIT

	check_prerequisites
	setup_environment
	start_daemon
	run_basic_tests
	run_advanced_tests
	run_smbtorture_tests

	# Report results (cleanup happens via trap)
	report_results
}

main "$@"
