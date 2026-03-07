# KSMBD ARM64 Cross-Compilation Guide

This guide provides comprehensive instructions for building the KSMBD kernel module for Linux ARM64 on macOS ARM64 systems.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Detailed Setup](#detailed-setup)
5. [Build Process](#build-process)
6. [Advanced Configuration](#advanced-configuration)
7. [Deployment](#deployment)
8. [Troubleshooting](#troubleshooting)
9. [Alternative Approaches](#alternative-approaches)

## Overview

This setup enables you to cross-compile the KSMBD kernel module from macOS ARM64 to Linux ARM64. The solution addresses the main challenges:

- **Linux Headers**: Downloads appropriate Linux kernel headers for ARM64
- **Cross-Compiler**: Uses aarch64-linux-gnu-gcc for proper cross-compilation
- **Build System**: Adapts the Linux kernel build system for cross-compilation
- **Environment Setup**: Handles all dependencies and configuration

### Key Components

- **`setup_arm64_build.sh`**: Automated setup script
- **`build_arm64.sh`**: Build script for compilation
- **`Makefile.arm64`**: Cross-compilation Makefile
- **Linux kernel headers**: Downloaded and configured automatically

## Prerequisites

### System Requirements

- **macOS ARM64** (Apple Silicon Mac)
- **Xcode Command Line Tools** (for basic build tools)
- **Homebrew** (package manager)
- **Internet connection** (for downloading kernel headers)
- **4GB+ free disk space** (for kernel source and build artifacts)

### Required Tools

The setup script will automatically install these if missing:

- `aarch64-linux-gnu-gcc` - ARM64 cross-compiler
- `curl` - For downloading kernel headers
- `tar` - For extracting archives
- `make` - Build system

### Checking Current Environment

```bash
# Check macOS version and architecture
uname -a
# Should show: Darwin ... arm64

# Check for Homebrew
which brew

# Check for existing cross-compilers
which aarch64-linux-gnu-gcc || which aarch64-elf-gcc
```

## Quick Start

For users who want to get started immediately:

### 1. Run Setup Script

```bash
# Clone or navigate to ksmbd directory
cd /Users/alexandrebetry/Projects/ksmbd

# Run the automated setup
./setup_arm64_build.sh

# Or with specific kernel version
./setup_arm64_build.sh -v 5.15.0
```

### 2. Build the Module

```bash
# Build with default settings
./build_arm64.sh

# Or build with custom options
./build_arm64.sh -j 8 -d  # 8 jobs, debug build
```

### 3. Deploy to ARM64 Linux System

```bash
# Copy the built module to target system
scp ksmbd.ko user@arm64-linux-system:/tmp/

# On the ARM64 Linux system:
sudo insmod /tmp/ksmbd.ko
sudo depmod -a
lsmod | grep ksmbd
```

## Detailed Setup

### Step 1: Install Dependencies

#### Install Homebrew (if not present)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
eval "$(/opt/homebrew/bin/brew shellenv)"
```

#### Install Cross-Compiler

```bash
# Install ARM64 cross-compiler toolchain
brew install aarch64-linux-gnu-binutils

# Verify installation
aarch64-linux-gnu-gcc --version
```

#### Install Additional Tools

```bash
# Install required build tools
brew install make curl tar

# Verify Xcode Command Line Tools
xcode-select --install
```

### Step 2: Configure Build Environment

#### Choose Kernel Version

The default kernel version is 6.1.0. You can choose a different version:

```bash
# List available kernel versions
curl -s https://cdn.kernel.org/pub/linux/kernel/v6.x/ | grep -o 'linux-6\.[0-9]\+\.[0-9]\+\.tar\.xz' | sort -V

# Set environment variable
export KERNEL_VERSION=5.15.0  # Example: Use LTS kernel
```

#### Run Setup Script

```bash
# Basic setup
./setup_arm64_build.sh

# With custom kernel version
./setup_arm64_build.sh -v 5.15.0

# Force reinstall
./setup_arm64_build.sh -f

# Check dependencies only
./setup_arm64_build.sh -c
```

The setup script will:

1. **Verify Dependencies**: Check for required tools
2. **Install Cross-Compiler**: Install aarch64-linux-gnu-gcc if missing
3. **Download Kernel Headers**: Download and prepare Linux kernel headers
4. **Configure Build Environment**: Create configuration files

### Step 3: Verify Setup

```bash
# Check that kernel headers were downloaded
ls -la build-arm64/linux-headers-*/

# Verify cross-compiler works
aarch64-linux-gnu-gcc --version

# Check build environment
cat build.env
```

## Build Process

### Basic Build

```bash
# Simple build
./build_arm64.sh

# Verbose build with progress
./build_arm64.sh -j $(nproc)
```

### Build Options

```bash
# Build with debug symbols
./build_arm64.sh -d

# Clean build
./build_arm64.sh -c

# Specify number of parallel jobs
./build_arm64.sh -j 8

# Use custom cross-compiler
./build_arm64.sh --cc aarch64-none-linux-gnu-

# Build specific kernel version
./build_arm64.sh -v 5.15.0
```

### Using Makefile Directly

For more control, you can use the Makefile directly:

```bash
# Show build configuration
make -f Makefile.arm64 info

# Setup headers only
make -f Makefile.arm64 setup-headers

# Configure kernel
make -f Makefile.arm64 kernel-config

# Build module
make -f Makefile.arm64 build-module

# Clean build
make -f Makefile.arm64 clean

# Show help
make -f Makefile.arm64 help
```

### Build Output

Successful build produces:

```
ksmbd.ko                    # The kernel module
Module information:
  Size: ~2-3MB
  Architecture: ARM aarch64
  Format: ELF 64-bit LSB relocatable
```

## Advanced Configuration

### Custom Kernel Configuration

For specific kernel features, modify the configuration:

```bash
# Edit kernel configuration
cd build-arm64/linux-headers-*/
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- menuconfig

# Navigate to:
# -> File systems
#   -> Network File Systems
#     -> SMB server (CIFS) support (as module)
```

### Build Variants

#### Debug Build

```bash
# Enable debug symbols and verbose logging
export DEBUG=1
./build_arm64.sh -d

# This adds:
# - Debug symbols (-g)
# - Debug logging enabled
# - Additional assertions
```

#### Minimal Build

```bash
# Disable insecure SMB1 support
export CONFIG_SMB_INSECURE_SERVER=n
make -f Makefile.arm64 build-module
```

#### Performance Build

```bash
# Optimize for performance
export EXTRA_CFLAGS="-O3 -mcpu=cortex-a72"
./build_arm64.sh
```

### Cross-Compiler Variants

#### Using Different Cross-Compilers

```bash
# ARM official toolchain
export CROSS_COMPILE=aarch64-none-linux-gnu-
./build_arm64.sh

# LLVM/Clang based toolchain
export CROSS_COMPILE=aarch64-linux-gnu-
export CC=aarch64-linux-gnu-clang
./build_arm64.sh
```

#### Installing Custom Toolchain

```bash
# Download ARM GNU toolchain
curl -L "https://developer.arm.com/-/media/Files/downloads/gnu-a/11.2-2022.02/binrel/gcc-arm-11.2-2022.02-x86_64-aarch64-none-linux-gnu.tar.xz" | tar xJ

# Add to PATH
export PATH="$PWD/gcc-arm-11.2-2022.02-x86_64-aarch64-none-linux-gnu/bin:$PATH"
export CROSS_COMPILE=aarch64-none-linux-gnu-
```

## Deployment

### Preparing for Deployment

#### Package the Module

```bash
# Create deployment package
mkdir -p ksmbd-arm64-deployment
cp ksmbd.ko ksmbd-arm64-deployment/
cp README.md ksmbd-arm64-deployment/
cp ARM64_BUILD_INSTRUCTIONS.md ksmbd-arm64-deployment/

# Create installation script
cat > ksmbd-arm64-deployment/install.sh << 'EOF'
#!/bin/bash
# KSMBD ARM64 Installation Script

set -e

MODULE_FILE="ksmbd.ko"
MODULE_NAME="ksmbd"

echo "Installing KSMBD module for ARM64..."

# Check if running on ARM64 Linux
if [[ "$(uname)" != "Linux" ]] || [[ "$(uname -m)" != "aarch64" ]]; then
    echo "Error: This script must be run on ARM64 Linux system"
    exit 1
fi

# Check kernel version compatibility
KERNEL_VERSION=$(uname -r)
echo "Target kernel version: $KERNEL_VERSION"

# Install module
sudo insmod $MODULE_FILE
echo "Module loaded successfully"

# Update module dependencies
sudo depmod -a

# Verify installation
if lsmod | grep -q $MODULE_NAME; then
    echo "KSMBD module is installed and running"
    echo "Use 'dmesg | tail' to check for module messages"
else
    echo "Warning: Module may not be loaded correctly"
fi

echo "Installation complete!"
EOF

chmod +x ksmbd-arm64-deployment/install.sh

# Create archive
tar czf ksmbd-arm64-$(date +%Y%m%d).tar.gz ksmbd-arm64-deployment/
```

### Manual Deployment Steps

#### On Target ARM64 Linux System

```bash
# 1. Copy module to system
scp ksmbd.ko user@target-system:/tmp/

# 2. SSH to target system
ssh user@target-system

# 3. Check kernel compatibility
uname -r
# Should match or be compatible with the kernel version used for build

# 4. Load the module
sudo insmod /tmp/ksmbd.ko

# 5. Verify installation
lsmod | grep ksmbd
dmesg | tail -10  # Check for module messages

# 6. Install to proper location (optional)
sudo cp /tmp/ksmbd.ko /lib/modules/$(uname -r)/kernel/fs/ksmbd/
sudo depmod -a

# 7. Configure KSMBD
sudo ksmbd.adduser -a yourusername
sudo ksmbd.addshare -a sharename /path/to/share "Share Description"

# 8. Start the daemon
sudo ksmbd.mountd

# 9. Enable on boot (optional)
sudo systemctl enable ksmbd
sudo systemctl start ksmbd
```

### System Integration

#### systemd Service Configuration

```bash
# Create systemd service file
sudo tee /etc/systemd/system/ksmbd.service << 'EOF'
[Unit]
Description=KSMBD kernel server
After=network.target

[Service]
Type=forking
ExecStart=/usr/sbin/ksmbd.mountd
ExecStop=/usr/bin/killall ksmbd.mountd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable ksmbd
sudo systemctl start ksmbd
```

## Troubleshooting

### Common Issues

#### Build Failures

**Issue: Cross-compiler not found**

```bash
# Error: aarch64-linux-gnu-gcc: command not found
# Solution:
brew install aarch64-linux-gnu-binutils
export PATH="/opt/homebrew/bin:$PATH"
```

**Issue: Kernel headers missing**

```bash
# Error: No such file or directory: linux/module.h
# Solution:
./setup_arm64_build.sh -f  # Force reinstall headers
```

**Issue: Architecture mismatch**

```bash
# Error: Architecture mismatch
# Solution: Ensure ARCH is set correctly
export ARCH=arm64
make -f Makefile.arm64 clean
make -f Makefile.arm64 build-module
```

#### Runtime Issues

**Issue: Module fails to load**

```bash
# Check kernel version compatibility
uname -r
modinfo ksmbd.ko | grep vermagic

# Check for missing symbols
dmesg | grep -i "ksmbd\|unknown symbol"
```

**Issue: Permission denied**

```bash
# Use sudo for module operations
sudo insmod ksmbd.ko
sudo lsmod | grep ksmbd
```

### Debug Build

For troubleshooting, build with debug symbols:

```bash
# Debug build
./build_arm64.sh -d

# On target system, enable debug logging
echo 'module ksmbd +p' > /sys/kernel/debug/dynamic_debug/control
dmesg -w | grep ksmbd
```

### Log Analysis

```bash
# Check kernel logs for KSMBD messages
dmesg | grep -i ksmbd

# Check system logs
journalctl -u ksmbd -f

# Monitor module activity
cat /proc/fs/ksmbd/controls  # If control interface available
```

### Performance Issues

```bash
# Check module statistics
cat /proc/modules | grep ksmbd

# Monitor system resources
top -p $(pgrep ksmbd)
iostat -x 1
```

## Alternative Approaches

### Docker-based Build

For users who prefer containerized builds:

```dockerfile
# Dockerfile for KSMBD ARM64 build
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    crossbuild-essential-arm64 \
    curl \
    tar \
    bc \
    flex \
    bison \
    libssl-dev \
    libelf-dev

WORKDIR /build
COPY . .

RUN ./setup_arm64_build.sh
RUN ./build_arm64.sh

CMD ["bash"]
```

### Cloud-based Build

For users without local resources:

```bash
# Use AWS Graviton (ARM64) instance
aws ec2 run-instances \
    --image-id ami-0abcdef1234567890 \
    --instance-type t4g.medium \
    --key-name my-key-pair

# Build directly on ARM64 Linux
git clone https://github.com/cifsd-team/ksmbd.git
cd ksmbd
make
```

### CI/CD Pipeline

GitHub Actions example:

```yaml
name: Build KSMBD ARM64
on: [push, pull_request]

jobs:
  build-arm64:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install cross-compiler
      run: sudo apt-get install gcc-aarch64-linux-gnu
    - name: Build
      run: |
        export ARCH=arm64
        export CROSS_COMPILE=aarch64-linux-gnu-
        make
```

## Support and Resources

### Documentation

- **KSMBD Project**: https://github.com/cifsd-team/ksmbd
- **Linux Kernel Documentation**: https://www.kernel.org/doc/
- **ARM64 Architecture**: https://developer.arm.com/architectures/armv8-a

### Community

- **Linux Kernel Mailing List**: linux-kernel@vger.kernel.org
- **KSMBD Issues**: https://github.com/cifsd-team/ksmbd/issues

### Tools and References

- **Cross-Compiler Toolchains**: https://developer.arm.com/downloads/-/gnu-a
- **Linux Kernel Config**: https://kernel.org/doc/html/latest/kbuild/kconfig.html
- **Module Development**: https://tldp.org/LDP/lkmpg/2.6/html/

## Version History

- **v1.0**: Initial ARM64 cross-compilation support
- **v1.1**: Added automated setup script
- **v1.2**: Enhanced debugging and verification
- **v1.3**: Added multiple kernel version support

---

**Note**: This setup is specifically designed for macOS ARM64 building Linux ARM64 modules. The resulting kernel module is intended for ARM64 Linux systems and will not work on macOS or other architectures.