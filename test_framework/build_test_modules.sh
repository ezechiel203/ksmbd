#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
#   Copyright (C) 2023 ksmbd Contributors
#
#   Build script for Apple SMB Extensions test modules

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_DIR="${ROOT_DIR}/test_framework"
BUILD_DIR="${TEST_DIR}/build"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in a kernel source tree with ksmbd
check_kernel_source() {
    if [[ ! -f "${ROOT_DIR}/Makefile" ]]; then
        log_error "This doesn't appear to be a kernel source directory"
        return 1
    fi

    if [[ ! -d "${ROOT_DIR}/fs/ksmbd" ]]; then
        log_error "ksmbd source not found. This script must be run from the ksmbd root directory"
        return 1
    fi

    return 0
}

# Check build dependencies
check_dependencies() {
    log_info "Checking build dependencies..."

    local missing_deps=()

    command -v gcc >/dev/null 2>&1 || missing_deps+=("gcc")
    command -v make >/dev/null 2>&1 || missing_deps+=("make")
    command -v awk >/dev/null 2>&1 || missing_deps+=("awk")
    command -v grep >/dev/null 2>&1 || missing_deps+=("grep")

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi

    log_success "All build dependencies found"
    return 0
}

# Create build directory
setup_build_environment() {
    log_info "Setting up build environment..."

    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"

    # Create symlink to main ksmbd source for building
    ln -sf "${ROOT_DIR}" ksmbd_source

    log_success "Build environment ready"
}

# Prepare kernel configuration
prepare_kernel_config() {
    log_info "Preparing kernel configuration..."

    if [[ ! -f "${ROOT_DIR}/.config" ]]; then
        log_info "No kernel config found, creating default config..."
        make defconfig
    fi

    # Enable ksmbd in kernel config
    if ! grep -q "CONFIG_SMB_SERVER=m" "${ROOT_DIR}/.config"; then
        log_info "Enabling ksmbd module in kernel config..."
        echo "CONFIG_SMB_SERVER=m" >> "${ROOT_DIR}/.config"
        echo "CONFIG_SMB_SERVER_SMBDIRECT=y" >> "${ROOT_DIR}/.config"
        echo "CONFIG_SMB_SERVER_CHECK_CAP_NET_ADMIN=y" >> "${ROOT_DIR}/.config"
        echo "CONFIG_SMB_SERVER_KERBEROS5=y" >> "${ROOT_DIR}/.config"
    fi

    # Enable debug symbols
    if ! grep -q "CONFIG_DEBUG_INFO=y" "${ROOT_DIR}/.config"; then
        echo "CONFIG_DEBUG_INFO=y" >> "${ROOT_DIR}/.config"
    fi

    # Enable required modules for testing
    local required_modules=(
        "CONFIG_CRYPTO_HMAC"
        "CONFIG_CRYPTO_MD4"
        "CONFIG_CRYPTO_MD5"
        "CONFIG_CRYPTO_SHA256"
        "CONFIG_CRYPTO_SHA512"
        "CONFIG_CRYPTO_AES"
        "CONFIG_CRYPTO_CCM"
        "CONFIG_CRYPTO_GCM"
        "CONFIG_CRYPTO_CMAC"
        "CONFIG_CRYPTO_ECB"
        "CONFIG_CRYPTO_CTR"
        "CONFIG_CRYPTO_PCBC"
        "CONFIG_CRYPTO_KRB5"
        "CONFIG_CRYPTO_USER"
        "CONFIG_CRYPTO_USER_API_HASH"
        "CONFIG_CRYPTO_USER_API_SKCIPHER"
        "CONFIG_CRYPTO_USER_API_RNG"
        "CONFIG_CRYPTO_USER_API_AEAD"
    )

    for module in "${required_modules[@]}"; do
        if ! grep -q "${module}=y" "${ROOT_DIR}/.config" && ! grep -q "${module}=m" "${ROOT_DIR}/.config"; then
            echo "${module}=y" >> "${ROOT_DIR}/.config"
        fi
    done

    log_success "Kernel configuration prepared"
}

# Create Makefile for test modules
create_test_makefile() {
    log_info "Creating test Makefile..."

    cat > "${BUILD_DIR}/Makefile" << 'EOF'
# Makefile for Apple SMB Extensions test modules

obj-m += unit_test_framework.o
obj-m += integration_test_framework.o
obj-m += performance_test_framework.o

KSMBD_SOURCE_DIR := ksmbd_source
ccflags-y := -I$(KSMBD_SOURCE_DIR) -I$(KSMBD_SOURCE_DIR)/mgmt

# Enable debug and test-specific flags
ccflags-y += -DDEBUG -g -O0
ccflags-y += -Wno-unused-function -Wno-unused-variable

# Build rules
all:
	$(MAKE) -C $(KSMBD_SOURCE_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KSMBD_SOURCE_DIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod.o .*.cmd *.symvers *.order
	rm -rf .tmp_versions

install:
	$(MAKE) -C $(KSMBD_SOURCE_DIR) M=$(PWD) modules_install

.PHONY: all clean install
EOF

    log_success "Test Makefile created"
}

# Build test modules
build_test_modules() {
    log_info "Building test modules..."

    # Build the main ksmbd modules first
    log_info "Building ksmbd modules..."
    cd "${ROOT_DIR}"
    make M=fs/ksmbd

    if [[ $? -ne 0 ]]; then
        log_error "Failed to build ksmbd modules"
        return 1
    fi

    log_success "ksmbd modules built successfully"

    # Build test modules
    cd "${BUILD_DIR}"
    log_info "Building test modules..."
    make

    if [[ $? -ne 0 ]]; then
        log_error "Failed to build test modules"
        return 1
    fi

    log_success "Test modules built successfully"
    return 0
}

# Validate built modules
validate_modules() {
    log_info "Validating built modules..."

    local modules=(
        "unit_test_framework.ko"
        "integration_test_framework.ko"
        "performance_test_framework.ko"
    )

    for module in "${modules[@]}"; do
        if [[ ! -f "${BUILD_DIR}/${module}" ]]; then
            log_error "Module ${module} not found"
            return 1
        fi

        # Check module info
        local modinfo_output=$(modinfo "${BUILD_DIR}/${module}" 2>/dev/null || true)
        if [[ -z "$modinfo_output" ]]; then
            log_error "Module ${module} is invalid"
            return 1
        fi

        log_info "Module ${module} is valid"
    done

    log_success "All modules validated successfully"
    return 0
}

# Copy modules to test framework directory
deploy_modules() {
    log_info "Deploying modules to test framework..."

    local modules=(
        "unit_test_framework.ko"
        "integration_test_framework.ko"
        "performance_test_framework.ko"
    )

    for module in "${modules[@]}"; do
        if [[ -f "${BUILD_DIR}/${module}" ]]; then
            cp "${BUILD_DIR}/${module}" "${TEST_DIR}/"
            log_success "Deployed ${module}"
        else
            log_warning "Module ${module} not found, skipping"
        fi
    done

    # Copy built ksmbd modules
    if [[ -d "${ROOT_DIR}/fs/ksmbd" ]]; then
        cp "${ROOT_DIR}/fs/ksmbd"/*.ko "${TEST_DIR}/" 2>/dev/null || true
        log_success "Deployed ksmbd modules"
    fi
}

# Generate build report
generate_build_report() {
    local report_file="${BUILD_DIR}/build_report.txt"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "${report_file}" << EOF
Apple SMB Extensions Test Modules Build Report
=============================================

Build Time: ${timestamp}
Build Directory: ${BUILD_DIR}
Test Directory: ${TEST_DIR}
Source Directory: ${ROOT_DIR}

Built Modules:
EOF

    for module in "${BUILD_DIR}"/*.ko; do
        if [[ -f "$module" ]]; then
            local module_name=$(basename "$module")
            local module_size=$(stat -c%s "$module")
            local modinfo=$(modinfo "$module" 2>/dev/null || echo "Unable to get module info")

            echo "- ${module_name} (${module_size} bytes)" >> "${report_file}"
            echo "  ${modinfo}" | sed 's/^/    /' >> "${report_file}"
            echo "" >> "${report_file}"
        fi
    done

    echo "Build Status: SUCCESS" >> "${report_file}"

    log_success "Build report generated: ${report_file}"
}

# Main build function
main() {
    log_info "Starting Apple SMB Extensions test modules build..."
    log_info "Source directory: ${ROOT_DIR}"
    log_info "Test directory: ${TEST_DIR}"
    log_info "Build directory: ${BUILD_DIR}"

    # Check requirements
    check_kernel_source || exit 1
    check_dependencies || exit 1

    # Setup and build
    setup_build_environment || exit 1
    prepare_kernel_config || exit 1
    create_test_makefile || exit 1
    build_test_modules || exit 1
    validate_modules || exit 1
    deploy_modules || exit 1
    generate_build_report || exit 1

    log_success "Test modules build completed successfully!"
    log_info "Test modules are available in: ${TEST_DIR}"
    log_info "Build artifacts are in: ${BUILD_DIR}"

    return 0
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi