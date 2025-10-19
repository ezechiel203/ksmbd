#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-or-later
#
# setup_arm64_build.sh - Setup script for cross-compiling KSMBD on macOS ARM64
#
# This script sets up the environment needed to build KSMBD kernel module
# for Linux ARM64 on macOS ARM64 systems.
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
BUILD_DIR="$PROJECT_ROOT/build-arm64"
KERNEL_VERSION="${KERNEL_VERSION:-6.1.0}"
ARCH="arm64"
CROSS_COMPILE="aarch64-linux-gnu-"

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

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Homebrew if not present
install_homebrew() {
    if ! command_exists brew; then
        print_info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        print_success "Homebrew is already installed"
    fi
}

# Function to install cross-compiler
install_cross_compiler() {
    print_info "Checking for ARM64 cross-compiler..."

    if command_exists aarch64-linux-gnu-gcc; then
        print_success "aarch64-linux-gnu-gcc found"
        CROSS_COMPILE="aarch64-linux-gnu-"
        return 0
    fi

    if command_exists aarch64-elf-gcc; then
        print_warning "Found aarch64-elf-gcc, but aarch64-linux-gnu-gcc is recommended"
        print_info "Installing aarch64-linux-gnu-gcc via Homebrew..."
        brew install aarch64-linux-gnu-binutils
        if command_exists aarch64-linux-gnu-gcc; then
            print_success "aarch64-linux-gnu-gcc installed successfully"
            CROSS_COMPILE="aarch64-linux-gnu-"
            return 0
        fi
    fi

    print_error "No suitable ARM64 cross-compiler found!"
    print_info "Please install aarch64-linux-gnu-gcc using:"
    print_info "  brew install aarch64-linux-gnu-binutils"
    print_info "Or download from: https://developer.arm.com/downloads/-/gnu-a"
    return 1
}

# Function to check dependencies
check_dependencies() {
    print_info "Checking dependencies..."

    local missing_deps=()

    if ! command_exists curl; then
        missing_deps+=("curl")
    fi

    if ! command_exists tar; then
        missing_deps+=("tar")
    fi

    if ! command_exists make; then
        missing_deps+=("make")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_info "Please install missing dependencies using Homebrew:"
        print_info "  brew install ${missing_deps[*]}"
        return 1
    fi

    print_success "All dependencies are satisfied"
    return 0
}

# Function to download Linux kernel headers
download_kernel_headers() {
    print_info "Setting up Linux kernel headers for ARM64..."

    local kernel_dir="$BUILD_DIR/linux-headers-$KERNEL_VERSION-arm64"

    if [ -d "$kernel_dir" ]; then
        print_success "Linux kernel headers already exist at $kernel_dir"
        return 0
    fi

    print_info "Creating build directory..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Determine kernel major version for URL
    local kernel_major=$(echo "$KERNEL_VERSION" | cut -d. -f1,2)

    print_info "Downloading Linux kernel source v$KERNEL_VERSION..."

    # Try multiple mirror sites
    local urls=(
        "https://cdn.kernel.org/pub/linux/kernel/v$kernel_major.x/linux-$KERNEL_VERSION.tar.xz"
        "https://mirrors.edge.kernel.org/pub/linux/kernel/v$kernel_major.x/linux-$KERNEL_VERSION.tar.xz"
        "https://kernel.org/pub/linux/kernel/v$kernel_major.x/linux-$KERNEL_VERSION.tar.xz"
    )

    local downloaded=false
    for url in "${urls[@]}"; do
        print_info "Trying to download from: $url"
        if curl -L --fail -o "linux-$KERNEL_VERSION.tar.xz" "$url"; then
            downloaded=true
            break
        else
            print_warning "Failed to download from $url"
        fi
    done

    if [ "$downloaded" = false ]; then
        print_error "Failed to download Linux kernel source"
        return 1
    fi

    print_info "Extracting kernel source..."
    if ! tar xf "linux-$KERNEL_VERSION.tar.xz"; then
        print_error "Failed to extract kernel source"
        return 1
    fi

    mv "linux-$KERNEL_VERSION" "linux-headers-$KERNEL_VERSION-arm64"
    cd "$kernel_dir"

    print_info "Configuring kernel for ARM64..."

    # Create minimal config for module building
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
EOF

    print_info "Preparing kernel build environment..."
    make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE silentoldconfig
    make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE modules_prepare

    print_success "Linux kernel headers setup complete"
    return 0
}

# Function to create build configuration
create_build_config() {
    print_info "Creating build configuration..."

    # Create build environment file
    cat > "$PROJECT_ROOT/build.env" << EOF
# KSMBD ARM64 Build Environment
export ARCH="arm64"
export CROSS_COMPILE="$CROSS_COMPILE"
export KERNEL_VERSION="$KERNEL_VERSION"
export BUILD_DIR="$BUILD_DIR"
export KERNEL_HEADERS_DIR="$BUILD_DIR/linux-headers-$KERNEL_VERSION-arm64"
export EXTRA_CFLAGS="-I$PROJECT_ROOT -D__KERNEL__ -Wall -mgeneral-regs-only -mstrict-align"
EOF

    print_success "Build configuration created"
}

# Function to verify setup
verify_setup() {
    print_info "Verifying build setup..."

    # Check cross-compiler
    if ! command_exists "${CROSS_COMPILE}gcc"; then
        print_error "Cross-compiler ${CROSS_COMPILE}gcc not found"
        return 1
    fi

    # Check kernel headers
    local kernel_dir="$BUILD_DIR/linux-headers-$KERNEL_VERSION-arm64"
    if [ ! -d "$kernel_dir" ]; then
        print_error "Kernel headers not found at $kernel_dir"
        return 1
    fi

    # Check essential header files
    local essential_headers=(
        "$kernel_dir/include/linux/module.h"
        "$kernel_dir/include/linux/fs.h"
        "$kernel_dir/include/linux/net.h"
        "$kernel_dir/arch/arm64/include/generated/uapi/asm/unistd.h"
    )

    for header in "${essential_headers[@]}"; do
        if [ ! -f "$header" ]; then
            print_warning "Essential header missing: $header"
        fi
    done

    print_success "Build setup verification complete"
    return 0
}

# Function to show usage
show_usage() {
    echo "KSMBD ARM64 Cross-Compilation Setup Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -v, --version VER    Set kernel version (default: 6.1.0)"
    echo "  -c, --check-only     Only check dependencies, don't install"
    echo "  -f, --force          Force reinstallation of components"
    echo "  --skip-deps          Skip dependency installation"
    echo ""
    echo "Environment Variables:"
    echo "  KERNEL_VERSION       Linux kernel version to use"
    echo ""
    echo "Examples:"
    echo "  $0                   # Setup with default kernel 6.1.0"
    echo "  $0 -v 5.15.0        # Setup with kernel 5.15.0"
    echo "  $0 -c               # Only check dependencies"
    echo "  $0 -f               # Force reinstallation"
}

# Main function
main() {
    local check_only=false
    local force_reinstall=false
    local skip_deps=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                KERNEL_VERSION="$2"
                shift 2
                ;;
            -c|--check-only)
                check_only=true
                shift
                ;;
            -f|--force)
                force_reinstall=true
                shift
                ;;
            --skip-deps)
                skip_deps=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    print_info "KSMBD ARM64 Cross-Compilation Setup"
    print_info "===================================="
    print_info "Kernel Version: $KERNEL_VERSION"
    print_info "Architecture: $ARCH"
    print_info "Cross-compiler: $CROSS_COMPILE"
    echo ""

    # Check if running on macOS ARM64
    if [[ "$(uname)" != "Darwin" ]] || [[ "$(uname -m)" != "arm64" ]]; then
        print_warning "This script is designed for macOS ARM64 systems"
        print_warning "It may not work correctly on other platforms"
    fi

    # Install dependencies if needed
    if [ "$skip_deps" = false ]; then
        install_homebrew

        if ! check_dependencies; then
            print_error "Dependency check failed"
            exit 1
        fi

        if ! install_cross_compiler; then
            print_error "Cross-compiler installation failed"
            exit 1
        fi
    else
        print_info "Skipping dependency installation"
    fi

    # Exit early if only checking
    if [ "$check_only" = true ]; then
        print_success "Dependency check complete"
        exit 0
    fi

    # Setup kernel headers
    if [ "$force_reinstall" = true ]; then
        print_info "Force reinstall requested, cleaning existing headers..."
        rm -rf "$BUILD_DIR"
    fi

    if ! download_kernel_headers; then
        print_error "Kernel headers setup failed"
        exit 1
    fi

    # Create build configuration
    create_build_config

    # Verify setup
    if ! verify_setup; then
        print_error "Setup verification failed"
        exit 1
    fi

    print_success "Setup completed successfully!"
    echo ""
    print_info "Next steps:"
    print_info "1. Build the module: make -f Makefile.arm64"
    print_info "2. Or use the build script: ./build_arm64.sh"
    print_info "3. Copy ksmbd.ko to your ARM64 Linux system"
    print_info "4. Load the module: sudo insmod ksmbd.ko"
    echo ""
    print_info "For more information, see ARM64_BUILD_INSTRUCTIONS.md"
}

# Run main function
main "$@"