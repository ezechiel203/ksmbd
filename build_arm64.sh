#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-or-later
#
# build_arm64.sh - Build script for KSMBD kernel module on ARM64
#
# This script builds the KSMBD kernel module for Linux ARM64 on macOS ARM64.
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
KERNEL_VERSION="${KERNEL_VERSION:-6.1.0}"
ARCH="arm64"
BUILD_DIR="$PROJECT_ROOT/build-arm64"
KERNEL_HEADERS_DIR="$BUILD_DIR/linux-headers-$KERNEL_VERSION-arm64"

# Build configuration
CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"
CC="${CROSS_COMPILE}gcc"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
DEBUG="${DEBUG:-0}"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to load build environment
load_build_env() {
    if [ -f "$PROJECT_ROOT/build.env" ]; then
        print_info "Loading build environment..."
        source "$PROJECT_ROOT/build.env"
        print_success "Build environment loaded"
    else
        print_warning "No build environment found, using defaults"
    fi
}

# Function to verify prerequisites
verify_prerequisites() {
    print_info "Verifying build prerequisites..."

    # Check cross-compiler
    if ! command_exists "$CC"; then
        print_error "Cross-compiler $CC not found!"
        print_info "Please run: ./setup_arm64_build.sh"
        return 1
    fi

    # Check kernel headers
    if [ ! -d "$KERNEL_HEADERS_DIR" ]; then
        print_error "Kernel headers not found at $KERNEL_HEADERS_DIR!"
        print_info "Please run: ./setup_arm64_build.sh"
        return 1
    fi

    # Check essential kernel header files
    local essential_headers=(
        "$KERNEL_HEADERS_DIR/include/linux/module.h"
        "$KERNEL_HEADERS_DIR/include/linux/fs.h"
        "$KERNEL_HEADERS_DIR/include/generated/autoconf.h"
    )

    for header in "${essential_headers[@]}"; do
        if [ ! -f "$header" ]; then
            print_error "Essential kernel header missing: $header"
            print_info "Kernel headers may not be properly prepared"
            return 1
        fi
    done

    # Check source files
    if [ ! -f "$PROJECT_ROOT/smb2pdu.c" ] || [ ! -f "$PROJECT_ROOT/Makefile" ]; then
        print_error "KSMBD source files not found!"
        return 1
    fi

    print_success "Prerequisites verified"
    return 0
}

# Function to show build information
show_build_info() {
    print_info "=== KSMBD ARM64 Build Configuration ==="
    echo "Target Architecture: $ARCH"
    echo "Cross-compiler: $CC"
    echo "Kernel Version: $KERNEL_VERSION"
    echo "Kernel Headers: $KERNEL_HEADERS_DIR"
    echo "Source Directory: $PROJECT_ROOT"
    echo "Build Jobs: $JOBS"
    echo "Debug Build: $([ "$DEBUG" = "1" ] && echo "Yes" || echo "No")"
    echo "Build Directory: $BUILD_DIR"
    echo ""
}

# Function to prepare build
prepare_build() {
    print_info "Preparing build environment..."

    # Load build environment
    load_build_env

    # Verify prerequisites
    if ! verify_prerequisites; then
        return 1
    fi

    # Clean previous builds if requested
    if [ "$CLEAN" = "1" ]; then
        print_info "Cleaning previous builds..."
        rm -f "$PROJECT_ROOT"/*.ko "$PROJECT_ROOT"/*.o "$PROJECT_ROOT"/*.mod.*
        rm -rf "$PROJECT_ROOT/.tmp_versions"
    fi

    # Create build directory structure
    mkdir -p "$BUILD_DIR/build"

    print_success "Build preparation complete"
    return 0
}

# Function to configure kernel
configure_kernel() {
    print_info "Configuring kernel build..."

    cd "$KERNEL_HEADERS_DIR"

    # Create minimal configuration for module building
    cat > .config << EOF
CONFIG_ARM64=y
CONFIG_64BIT=y
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
CONFIG_NET=y
CONFIG_INET=y
CONFIG_FILE_LOCKING=y
CONFIG_CRYPTO=y
CONFIG_CRYPTO_MD5=y
CONFIG_CRYPTO_SHA1=y
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_AES=y
CONFIG_CRYPTO_CMAC=y
CONFIG_CRYPTO_HMAC=y
CONFIG_CRYPTO_ECB=y
CONFIG_CRYPTO_CBC=y
CONFIG_CRYPTO_CCM=y
CONFIG_CRYPTO_GCM=y
CONFIG_CRYPTO_CFB=y
CONFIG_CRYPTO_CTR=y
CONFIG_CRYPTO_XTS=y
CONFIG_KEYS=y
CONFIG_SMB_SERVER=m
CONFIG_SMB_INSECURE_SERVER=y
CONFIG_SMB_SERVER_SMBDIRECT=n
CONFIG_DEBUG_INFO_BTF=n
CONFIG_LOCALVERSION_AUTO=n
CONFIG_LOCALVERSION=""
EOF

    # Update configuration
    make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE olddefconfig

    print_success "Kernel configuration complete"
}

# Function to build module
build_module() {
    print_info "Building KSMBD kernel module..."

    cd "$PROJECT_ROOT"

    # Set build environment variables
    export ARCH=$ARCH
    export CROSS_COMPILE=$CROSS_COMPILE
    export CC=$CC
    export KERNELRELEASE=$KERNEL_VERSION

    # Configure module options
    export CONFIG_SMB_SERVER=m
    export CONFIG_SMB_INSECURE_SERVER=y
    export CONFIG_SMB_SERVER_SMBDIRECT=n

    # Build flags
    local make_flags="-C $KERNEL_HEADERS_DIR M=$PROJECT_ROOT ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE CC=$CC"

    if [ "$DEBUG" = "1" ]; then
        make_flags="$make_flags EXTRA_CFLAGS='-g -DDEBUG'"
        print_info "Building with debug symbols"
    fi

    # Add parallel build
    make_flags="$make_flags -j$JOBS"

    print_info "Build command: make $make_flags modules"

    # Execute build
    if make $make_flags modules; then
        print_success "Module build completed successfully"
    else
        print_error "Module build failed"
        return 1
    fi

    # Check if module was built
    if [ -f "$PROJECT_ROOT/ksmbd.ko" ]; then
        local module_size=$(ls -lh "$PROJECT_ROOT/ksmbd.ko" | awk '{print $5}')
        print_success "Module built: ksmbd.ko ($module_size)"

        # Show module information
        print_info "Module information:"
        file "$PROJECT_ROOT/ksmbd.ko" || true
        ${CROSS_COMPILE}objdump -h "$PROJECT_ROOT/ksmbd.ko" | head -10 || true
    else
        print_error "Module file not found after build"
        return 1
    fi

    return 0
}

# Function to verify module
verify_module() {
    print_info "Verifying built module..."

    local module_file="$PROJECT_ROOT/ksmbd.ko"

    if [ ! -f "$module_file" ]; then
        print_error "Module file not found: $module_file"
        return 1
    fi

    # Check module architecture
    local module_arch=$(file "$module_file")
    if [[ ! "$module_arch" =~ "ARM aarch64" ]]; then
        print_error "Module architecture incorrect: $module_arch"
        return 1
    fi

    # Check for required symbols
    if command_exists "${CROSS_COMPILE}nm"; then
        local missing_symbols=$("${CROSS_COMPILE}nm" "$module_file" | grep -E " U " | wc -l)
        if [ "$missing_symbols" -gt 0 ]; then
            print_warning "Module has $missing_symbols undefined symbols"
            print_info "This is normal for kernel modules"
        fi
    fi

    # Check module info
    if command_exists "${CROSS_COMPILE}modinfo"; then
        print_info "Module information:"
        "${CROSS_COMPILE}modinfo" "$module_file" || true
    fi

    print_success "Module verification complete"
    return 0
}

# Function to show usage
show_usage() {
    echo "KSMBD ARM64 Build Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -j, --jobs N         Number of parallel build jobs (default: $JOBS)"
    echo "  -c, --clean          Clean before building"
    echo "  -d, --debug          Build with debug symbols"
    echo "  -v, --version VER    Set kernel version (default: $KERNEL_VERSION)"
    echo "  --cc PREFIX          Set cross-compiler prefix"
    echo "  --verify-only        Only verify existing build"
    echo ""
    echo "Environment Variables:"
    echo "  KERNEL_VERSION       Linux kernel version"
    echo "  CROSS_COMPILE        Cross-compiler prefix"
    echo "  JOBS                 Number of build jobs"
    echo "  DEBUG                Enable debug build (1=enabled)"
    echo "  CLEAN                Clean before build (1=enabled)"
    echo ""
    echo "Examples:"
    echo "  $0                   # Build with defaults"
    echo "  $0 -j 8 -d          # Build with 8 jobs and debug"
    echo "  $0 -c               # Clean and build"
    echo "  $0 --verify-only    # Only verify existing module"
}

# Main function
main() {
    local verify_only=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -j|--jobs)
                JOBS="$2"
                shift 2
                ;;
            -c|--clean)
                CLEAN=1
                shift
                ;;
            -d|--debug)
                DEBUG=1
                shift
                ;;
            -v|--version)
                KERNEL_VERSION="$2"
                KERNEL_HEADERS_DIR="$BUILD_DIR/linux-headers-$KERNEL_VERSION-arm64"
                shift 2
                ;;
            --cc)
                CROSS_COMPILE="$2"
                CC="${CROSS_COMPILE}gcc"
                shift 2
                ;;
            --verify-only)
                verify_only=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    print_info "KSMBD ARM64 Build Script"
    print_info "========================"

    # Show build information
    show_build_info

    # If only verifying, skip build
    if [ "$verify_only" = true ]; then
        if verify_prerequisites && verify_module; then
            print_success "Module verification passed"
            exit 0
        else
            print_error "Module verification failed"
            exit 1
        fi
    fi

    # Prepare build environment
    if ! prepare_build; then
        print_error "Build preparation failed"
        exit 1
    fi

    # Configure kernel
    if ! configure_kernel; then
        print_error "Kernel configuration failed"
        exit 1
    fi

    # Build module
    if ! build_module; then
        print_error "Module build failed"
        exit 1
    fi

    # Verify module
    if ! verify_module; then
        print_error "Module verification failed"
        exit 1
    fi

    print_success "=== Build Complete ==="
    echo ""
    print_info "Built module: $PROJECT_ROOT/ksmbd.ko"
    print_info "Ready for deployment on ARM64 Linux systems"
    echo ""
    print_info "Deployment instructions:"
    print_info "1. Copy ksmbd.ko to target ARM64 Linux system"
    print_info "2. Load module: sudo insmod ksmbd.ko"
    print_info "3. Verify: lsmod | grep ksmbd"
    print_info "4. Configure: sudo ksmbd.adduser -a <username>"
    print_info "5. Start daemon: sudo ksmbd.mountd"
}

# Run main function
main "$@"