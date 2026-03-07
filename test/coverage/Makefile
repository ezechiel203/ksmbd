# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for ksmbd gcov/lcov code coverage
#
# This Makefile orchestrates building ksmbd with gcov instrumentation,
# running KUnit tests, collecting coverage data, and generating reports.
#
# Usage (from the repository root):
#   make -f test/coverage/Makefile coverage-build
#   make -f test/coverage/Makefile coverage-run
#   make -f test/coverage/Makefile coverage-report
#   make -f test/coverage/Makefile coverage-clean
#   make -f test/coverage/Makefile coverage-all    # build + run + report
#
# Environment variables:
#   LINUX_SRC     Full kernel source tree (required for kunit.py)
#   KDIR          Kernel build directory (default: /lib/modules/$(uname -r)/build)
#   GCOV_OUTPUT   Output directory for coverage data (default: test/coverage/output)
#   MIN_LINE_COV  Minimum line coverage threshold in percent (optional)

SHELL := /bin/bash

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
COVERAGE_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
REPO_ROOT    := $(realpath $(COVERAGE_DIR)/../..)
TEST_DIR     := $(REPO_ROOT)/test
COVERAGE_SRC := $(COVERAGE_DIR)

KDIR         ?= /lib/modules/$(shell uname -r)/build
LINUX_SRC    ?=
GCOV_OUTPUT  ?= $(COVERAGE_DIR)/output
MIN_LINE_COV ?=

# ---------------------------------------------------------------------------
# Kernel gcov data path
# ---------------------------------------------------------------------------
# When the kernel is built with CONFIG_GCOV_KERNEL=y, gcov data appears under
# /sys/kernel/debug/gcov/<build-path>/. The exact path depends on whether
# the build was in-tree or out-of-tree.
GCOV_SYSFS   := /sys/kernel/debug/gcov

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

.PHONY: coverage-all coverage-build coverage-run coverage-report coverage-clean help

help:
	@echo "ksmbd Code Coverage Targets"
	@echo "==========================="
	@echo ""
	@echo "  coverage-build   Build ksmbd with gcov instrumentation"
	@echo "  coverage-run     Run KUnit tests to generate coverage data"
	@echo "  coverage-report  Collect gcov data and generate HTML report"
	@echo "  coverage-clean   Remove all generated coverage artifacts"
	@echo "  coverage-all     Build, run tests, and generate report"
	@echo ""
	@echo "Environment variables:"
	@echo "  LINUX_SRC=$(LINUX_SRC)"
	@echo "  KDIR=$(KDIR)"
	@echo "  GCOV_OUTPUT=$(GCOV_OUTPUT)"
	@echo "  MIN_LINE_COV=$(MIN_LINE_COV)"

# ---------------------------------------------------------------------------
# coverage-build: Build ksmbd with gcov instrumentation
# ---------------------------------------------------------------------------
# Two strategies:
#   1. In-tree build via kunit.py (preferred, uses LINUX_SRC)
#   2. External module build (uses KDIR, compile-check only)
#
# For in-tree builds, we copy ksmbd into the kernel source tree, apply the
# gcov kunitconfig, and run kunit.py configure+build.
# ---------------------------------------------------------------------------

coverage-build:
	@echo "=== Building ksmbd with gcov instrumentation ==="
ifneq ($(LINUX_SRC),)
	@# Strategy 1: In-tree build via kunit.py
	@if [ ! -f "$(LINUX_SRC)/tools/testing/kunit/kunit.py" ]; then \
		echo "ERROR: kunit.py not found in LINUX_SRC=$(LINUX_SRC)"; \
		exit 1; \
	fi
	@echo "Using in-tree build (LINUX_SRC=$(LINUX_SRC))"
	@# Copy ksmbd into the kernel tree
	@mkdir -p "$(LINUX_SRC)/fs/ksmbd/test/coverage" "$(LINUX_SRC)/fs/ksmbd/mgmt"
	@cp -a $(REPO_ROOT)/*.c $(REPO_ROOT)/*.h $(REPO_ROOT)/*.asn1 \
		$(REPO_ROOT)/Kconfig $(REPO_ROOT)/Makefile \
		"$(LINUX_SRC)/fs/ksmbd/" 2>/dev/null || true
	@cp -a $(REPO_ROOT)/mgmt/* "$(LINUX_SRC)/fs/ksmbd/mgmt/" 2>/dev/null || true
	@cp -a $(TEST_DIR)/*.c $(TEST_DIR)/Makefile \
		"$(LINUX_SRC)/fs/ksmbd/test/" 2>/dev/null || true
	@cp -a $(COVERAGE_SRC)/kunit_gcov.kunitconfig \
		"$(LINUX_SRC)/fs/ksmbd/test/coverage/" 2>/dev/null || true
	@# Wire into fs/ if not already done
	@if ! grep -q 'fs/ksmbd/Kconfig' "$(LINUX_SRC)/fs/Kconfig" 2>/dev/null; then \
		echo 'source "fs/ksmbd/Kconfig"' >> "$(LINUX_SRC)/fs/Kconfig"; \
	fi
	@if ! grep -q 'ksmbd' "$(LINUX_SRC)/fs/Makefile" 2>/dev/null; then \
		echo 'obj-$$(CONFIG_SMB_SERVER) += ksmbd/' >> "$(LINUX_SRC)/fs/Makefile"; \
	fi
	@# Apply GCOV_PROFILE to the ksmbd Makefile in the kernel tree
	@if ! grep -q 'GCOV_PROFILE' "$(LINUX_SRC)/fs/ksmbd/Makefile" 2>/dev/null; then \
		sed -i '1a GCOV_PROFILE := y' "$(LINUX_SRC)/fs/ksmbd/Makefile"; \
	fi
	@echo "Building with kunit.py configure..."
	cd "$(LINUX_SRC)" && python3 tools/testing/kunit/kunit.py config \
		--kunitconfig=fs/ksmbd/test/coverage/kunit_gcov.kunitconfig \
		--arch=um
	cd "$(LINUX_SRC)" && python3 tools/testing/kunit/kunit.py build \
		--kunitconfig=fs/ksmbd/test/coverage/kunit_gcov.kunitconfig \
		--arch=um \
		--jobs=$$(nproc)
	@echo "=== Build complete ==="
else
	@# Strategy 2: External module build (gcov requires full kernel tree)
	@echo "WARNING: External module build does not support gcov."
	@echo "Set LINUX_SRC=/path/to/linux for full gcov coverage."
	@echo ""
	@echo "Performing compile-check with CONFIG_KSMBD_KUNIT_TEST=m..."
	$(MAKE) -C "$(KDIR)" M="$(REPO_ROOT)" \
		CONFIG_SMB_SERVER=m \
		CONFIG_SMB_INSECURE_SERVER=y \
		CONFIG_KSMBD_KUNIT_TEST=m \
		GCOV_PROFILE_ksmbd=y \
		modules
	@echo "=== Compile-check complete (no gcov data without in-tree build) ==="
endif

# ---------------------------------------------------------------------------
# coverage-run: Run KUnit tests to generate coverage data
# ---------------------------------------------------------------------------

coverage-run:
	@echo "=== Running KUnit tests for coverage ==="
ifneq ($(LINUX_SRC),)
	@if [ ! -f "$(LINUX_SRC)/tools/testing/kunit/kunit.py" ]; then \
		echo "ERROR: kunit.py not found. Run coverage-build first."; \
		exit 1; \
	fi
	cd "$(LINUX_SRC)" && python3 tools/testing/kunit/kunit.py run \
		--kunitconfig=fs/ksmbd/test/coverage/kunit_gcov.kunitconfig \
		--arch=um \
		--timeout=600 \
		--raw_output=all 2>&1 | tee "$(GCOV_OUTPUT)/kunit_run.log"
	@echo "=== KUnit tests complete ==="
else
	@echo "ERROR: LINUX_SRC is required to run KUnit tests with coverage."
	@echo "Set LINUX_SRC=/path/to/linux"
	@exit 1
endif

# ---------------------------------------------------------------------------
# coverage-report: Collect gcov data and produce HTML report
# ---------------------------------------------------------------------------

coverage-report:
	@echo "=== Generating coverage report ==="
	@mkdir -p "$(GCOV_OUTPUT)"
	$(COVERAGE_SRC)/collect_coverage.sh \
		--output-dir "$(GCOV_OUTPUT)" \
		$(if $(LINUX_SRC),--linux-src "$(LINUX_SRC)") \
		$(if $(MIN_LINE_COV),--min-line-coverage $(MIN_LINE_COV))
	@echo "=== Report generated at $(GCOV_OUTPUT)/coverage_html/index.html ==="

# ---------------------------------------------------------------------------
# coverage-all: Full pipeline (build + run + report)
# ---------------------------------------------------------------------------

coverage-all: coverage-build coverage-run coverage-report
	@echo ""
	@echo "=== Coverage pipeline complete ==="
	@echo "Open $(GCOV_OUTPUT)/coverage_html/index.html in a browser."

# ---------------------------------------------------------------------------
# coverage-clean: Remove generated artifacts
# ---------------------------------------------------------------------------

coverage-clean:
	@echo "=== Cleaning coverage artifacts ==="
	rm -rf "$(GCOV_OUTPUT)"
	rm -f "$(COVERAGE_DIR)"/*.info
	rm -f "$(COVERAGE_DIR)"/*.log
	@# Clean gcov instrumentation from in-tree build if applicable
ifneq ($(LINUX_SRC),)
	@if grep -q 'GCOV_PROFILE' "$(LINUX_SRC)/fs/ksmbd/Makefile" 2>/dev/null; then \
		sed -i '/^GCOV_PROFILE/d' "$(LINUX_SRC)/fs/ksmbd/Makefile"; \
		echo "Removed GCOV_PROFILE from kernel tree Makefile"; \
	fi
endif
	@echo "=== Clean complete ==="
