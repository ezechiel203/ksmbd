# KSMBD ARM64 Cross-Compilation Troubleshooting Guide

This guide provides comprehensive troubleshooting steps for common issues when cross-compiling KSMBD from macOS ARM64 to Linux ARM64.

## Table of Contents

1. [Quick Diagnostic Checklist](#quick-diagnostic-checklist)
2. [Environment Issues](#environment-issues)
3. [Build Problems](#build-problems)
4. [Cross-Compiler Issues](#cross-compiler-issues)
5. [Kernel Header Problems](#kernel-header-problems)
6. [Module Issues](#module-issues)
7. [Runtime Problems](#runtime-problems)
8. [Performance Issues](#performance-issues)
9. [Debugging Techniques](#debugging-techniques)
10. [Recovery Procedures](#recovery-procedures)

## Quick Diagnostic Checklist

Before diving into detailed troubleshooting, run this quick diagnostic:

```bash
#!/bin/bash
# Quick diagnostic script

echo "=== KSMBD ARM64 Build Diagnostic ==="
echo

# 1. Check system
echo "1. System Information:"
echo "   OS: $(uname -s)"
echo "   Arch: $(uname -m)"
echo "   Kernel: $(uname -r)"
echo

# 2. Check cross-compiler
echo "2. Cross-Compiler Check:"
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    echo "   ✓ aarch64-linux-gnu-gcc found: $(aarch64-linux-gnu-gcc --version | head -1)"
else
    echo "   ✗ aarch64-linux-gnu-gcc not found"
fi

if command -v aarch64-elf-gcc >/dev/null 2>&1; then
    echo "   ✓ aarch64-elf-gcc found: $(aarch64-elf-gcc --version | head -1)"
else
    echo "   ✗ aarch64-elf-gcc not found"
fi
echo

# 3. Check build directory
echo "3. Build Directory Check:"
if [ -d "build-arm64" ]; then
    echo "   ✓ build-arm64 directory exists"
    if [ -d "build-arm64/linux-headers-"*"-arm64" ]; then
        echo "   ✓ Kernel headers found"
    else
        echo "   ✗ Kernel headers not found"
    fi
else
    echo "   ✗ build-arm64 directory not found"
fi
echo

# 4. Check module
echo "4. Module Check:"
if [ -f "ksmbd.ko" ]; then
    echo "   ✓ ksmbd.ko exists"
    echo "   Size: $(ls -lh ksmbd.ko | awk '{print $5}')"
    echo "   Type: $(file ksmbd.ko | cut -d: -f2-)"
else
    echo "   ✗ ksmbd.ko not found"
fi
echo

# 5. Check environment
echo "5. Environment Variables:"
echo "   ARCH: ${ARCH:-not set}"
echo "   CROSS_COMPILE: ${CROSS_COMPILE:-not set}"
echo "   KERNEL_VERSION: ${KERNEL_VERSION:-not set}"
echo "   DEBUG: ${DEBUG:-not set}"
```

Save this as `diagnostic.sh` and run it to quickly identify issues.

## Environment Issues

### Issue: macOS Version Compatibility

**Symptoms**: Build tools not working, strange compiler errors

**Diagnosis**:
```bash
# Check macOS version
sw_vers

# Check for Xcode tools
xcode-select --print-path
```

**Solutions**:

1. **Update Xcode Command Line Tools**:
   ```bash
   sudo xcode-select --install
   sudo xcode-select --reset
   ```

2. **Verify Homebrew Installation**:
   ```bash
   which brew
   brew --version
   ```

3. **Update PATH**:
   ```bash
   # Add to ~/.zshrc or ~/.bash_profile
   export PATH="/opt/homebrew/bin:$PATH"
   export PATH="/opt/homebrew/sbin:$PATH"
   ```

### Issue: Permission Problems

**Symptoms**: Permission denied errors during build or setup

**Diagnosis**:
```bash
# Check file permissions
ls -la setup_arm64_build.sh build_arm64.sh Makefile.arm64

# Check directory permissions
ls -la .
```

**Solutions**:

1. **Fix Script Permissions**:
   ```bash
   chmod +x setup_arm64_build.sh build_arm64.sh
   ```

2. **Fix Directory Permissions**:
   ```bash
   # Ensure ownership is correct
   sudo chown -R $(whoami) .
   chmod -R u+rwX .
   ```

3. **Check SIP Status**:
   ```bash
   csrutil status
   # If disabled, you may need to re-enable it
   ```

## Build Problems

### Issue: Build Fails with "No such file or directory"

**Common Error Messages**:
```
fatal error: linux/module.h: No such file or directory
make: *** No rule to make target 'modules'. Stop.
```

**Diagnosis**:
```bash
# Check if kernel headers exist
ls -la build-arm64/linux-headers-*/include/linux/module.h

# Check build configuration
cat build.env

# Verify kernel version compatibility
echo $KERNEL_VERSION
```

**Solutions**:

1. **Reinstall Kernel Headers**:
   ```bash
   ./setup_arm64_build.sh -f
   ```

2. **Check Kernel Headers Preparation**:
   ```bash
   cd build-arm64/linux-headers-*/
   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_prepare
   ```

3. **Verify Kernel Configuration**:
   ```bash
   cd build-arm64/linux-headers-*/
   grep -E "CONFIG_SMB_SERVER|CONFIG_MODULES" .config
   ```

### Issue: Architecture Mismatch Errors

**Common Error Messages**:
```
cc1: error: -mgeneral-regs-only not supported
arch/arm64/Makefile: No such file or directory
```

**Diagnosis**:
```bash
# Check ARCH variable
echo $ARCH

# Check if arm64 architecture is supported
aarch64-linux-gnu-gcc -v 2>&1 | grep -i arm
```

**Solutions**:

1. **Set Architecture Correctly**:
   ```bash
   export ARCH=arm64
   make -f Makefile.arm64 clean
   make -f Makefile.arm64 build-module
   ```

2. **Use Correct Cross-Compiler**:
   ```bash
   export CROSS_COMPILE=aarch64-linux-gnu-
   export CC=${CROSS_COMPILE}gcc
   ```

3. **Verify Cross-Compiler Capabilities**:
   ```bash
   aarch64-linux-gnu-gcc -march=armv8-a -Q --help=target | head
   ```

### Issue: Compilation Errors with Specific Files

**Common Issues**:

1. **ASN.1 Compilation Errors**:
   ```
   error: 'ksmbd_spnego_negtokeninit.h' file not found
   ```

   **Solution**:
   ```bash
   # Generate ASN.1 files first
   make -f Makefile.arm64 clean
   cd build-arm64/linux-headers-*/
   make scripts
   cd -
   make -f Makefile.arm64 build-module
   ```

2. **Crypto-related Errors**:
   ```
   error: implicit declaration of function 'crypto_shash'
   ```

   **Solution**:
   ```bash
   # Check crypto configuration
   cd build-arm64/linux-headers-*/
   grep -E "CONFIG_CRYPTO" .config
   make menuconfig  # Enable needed crypto options
   ```

3. **Missing Symbol Errors**:
   ```
   undefined reference to `some_kernel_function'
   ```

   **Solution**:
   ```bash
   # Check kernel version compatibility
   modinfo kernel/smp.ko 2>/dev/null | grep vermagic
   grep -E "VERSION|PATCHLEVEL" build-arm64/linux-headers-*/Makefile
   ```

## Cross-Compiler Issues

### Issue: Cross-Compiler Not Found

**Symptoms**: `aarch64-linux-gnu-gcc: command not found`

**Diagnosis**:
```bash
# Check for cross-compilers
which aarch64-linux-gnu-gcc
which aarch64-elf-gcc
which aarch64-none-linux-gnu-gcc

# Check PATH
echo $PATH | tr ':' '\n' | grep -i arm
```

**Solutions**:

1. **Install via Homebrew**:
   ```bash
   brew update
   brew install aarch64-linux-gnu-binutils
   ```

2. **Manual Installation**:
   ```bash
   # Download ARM official toolchain
   curl -L "https://developer.arm.com/-/media/Files/downloads/gnu-a/11.2-2022.02/binrel/gcc-arm-11.2-2022.02-x86_64-aarch64-none-linux-gnu.tar.xz" | tar xJ

   # Add to PATH
   export PATH="$PWD/gcc-arm-11.2-2022.02-x86_64-aarch64-none-linux-gnu/bin:$PATH"
   ```

3. **Verify Installation**:
   ```bash
   aarch64-linux-gnu-gcc --version
   aarch64-linux-gnu-gcc -dumpmachine
   ```

### Issue: Cross-Compiler Produces Wrong Architecture

**Symptoms**: Module builds but has wrong architecture

**Diagnosis**:
```bash
# Check built module architecture
file ksmbd.ko

# Check cross-compiler target
aarch64-linux-gnu-gcc -dumpmachine
```

**Solutions**:

1. **Verify Cross-Compiler Target**:
   ```bash
   aarch64-linux-gnu-gcc -v 2>&1 | grep Target
   # Should show: Target: aarch64-linux-gnu
   ```

2. **Check Build Flags**:
   ```bash
   # Make sure correct flags are being used
   grep -r "CROSS_COMPILE\|ARCH" Makefile.arm64
   ```

3. **Force Correct Architecture**:
   ```bash
   export ARCH=arm64
   export CROSS_COMPILE=aarch64-linux-gnu-
   make -f Makefile.arm64 clean all
   ```

## Kernel Header Problems

### Issue: Kernel Headers Download Fails

**Symptoms**: Network timeouts, checksum errors

**Diagnosis**:
```bash
# Test network connectivity
curl -I https://cdn.kernel.org/pub/linux/kernel/v6.x/

# Check available versions
curl -s https://cdn.kernel.org/pub/linux/kernel/v6.x/ | grep -o 'linux-6\.[0-9]\+\.[0-9]\+\.tar\.xz'
```

**Solutions**:

1. **Try Different Mirror**:
   ```bash
   # Edit setup_arm64_build.sh to use alternative mirrors
   # Add these URLs to the urls array:
   "https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz"
   "https://kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz"
   ```

2. **Manual Download**:
   ```bash
   mkdir -p build-arm64
   cd build-arm64
   wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.0.tar.xz
   tar xf linux-6.1.0.tar.xz
   mv linux-6.1.0 linux-headers-6.1.0-arm64
   ```

3. **Use Different Kernel Version**:
   ```bash
   ./setup_arm64_build.sh -v 5.15.0
   ```

### Issue: Kernel Headers Preparation Fails

**Symptoms**: `make modules_prepare` fails

**Diagnosis**:
```bash
cd build-arm64/linux-headers-*/
make V=1 modules_prepare 2>&1 | head -20
```

**Solutions**:

1. **Check Required Tools**:
   ```bash
   # Ensure these tools are available
   which bc bison flex libssl-dev libelf-dev

   # Install missing tools
   brew install bc bison flex openssl
   ```

2. **Minimal Configuration**:
   ```bash
   cd build-arm64/linux-headers-*/
   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- allnoconfig
   echo "CONFIG_MODULES=y" >> .config
   echo "CONFIG_ARM64=y" >> .config
   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_prepare
   ```

3. **Fix Permissions**:
   ```bash
   cd build-arm64/linux-headers-*/
   chmod -R u+w .
   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_prepare
   ```

## Module Issues

### Issue: Module Builds But Has Warnings

**Common Warnings**:
```
warning: 'CONFIG_SMB_SERVER_SMBDIRECT' is not defined
warning: function declaration isn't a prototype
```

**Diagnosis**:
```bash
# Check configuration
grep -E "CONFIG_SMB" build-arm64/linux-headers-*/.config

# Build with verbose output
make -f Makefile.arm64 build-module V=1 2>&1 | grep -i warning
```

**Solutions**:

1. **Fix Configuration**:
   ```bash
   cd build-arm64/linux-headers-*/
   echo "CONFIG_SMB_SERVER_SMBDIRECT=n" >> .config
   make olddefconfig
   ```

2. **Suppress Warnings**:
   ```bash
   export EXTRA_CFLAGS="$EXTRA_CFLAGS -Wno-implicit-function-declaration"
   ```

3. **Update Source**:
   ```bash
   git pull origin master
   ./build_arm64.sh -c
   ```

### Issue: Module File Size is Wrong

**Symptoms**: Module is too small (<1MB) or too large (>10MB)

**Diagnosis**:
```bash
# Check module size
ls -lh ksmbd.ko

# Check what's included
${CROSS_COMPILE}objdump -h ksmbd.ko
${CROSS_COMPILE}nm ksmbd.ko | wc -l
```

**Solutions**:

1. **Debug Build Check**:
   ```bash
   # Debug builds are larger
   file ksmbd.ko | grep -i "not stripped"

   # Strip debug symbols if needed
   ${CROSS_COMPILE}strip ksmbd.ko
   ```

2. **Check Build Configuration**:
   ```bash
   # Make sure all required components are built
   grep -E "ksmbd-y.*=" Makefile.arm64

   # Check for missing objects
   ls -la *.o | grep ksmbd
   ```

3. **Rebuild Completely**:
   ```bash
   make -f Makefile.arm64 distclean
   ./setup_arm64_build.sh -f
   ./build_arm64.sh -c
   ```

## Runtime Problems

### Issue: Module Fails to Load on Target System

**Common Error Messages**:
```
insmod: ERROR: could not insert module ksmbd.ko: Invalid module format
Unknown symbol in module
```

**Diagnosis**:
```bash
# On target system
uname -r
modinfo ksmbd.ko | grep vermagic

# Check for symbol mismatches
dmesg | tail -10 | grep -i "unknown symbol"
```

**Solutions**:

1. **Check Kernel Version Compatibility**:
   ```bash
   # Target kernel version must match build kernel version
   # If they don't match, rebuild with correct version:
   TARGET_KERNEL_VERSION="5.15.0-76-generic"  # Example
   ./setup_arm64_build.sh -v ${TARGET_KERNEL_VERSION%%-*}
   ./build_arm64.sh
   ```

2. **Check Symbol Dependencies**:
   ```bash
   # On build system
   ${CROSS_COMPILE}nm -u ksmbd.ko | head -20

   # On target system
   grep -E "function_name" /proc/kallsyms
   ```

3. **Use Compatible Build**:
   ```bash
   # Build for generic kernel if target is unknown
   export EXTRA_CFLAGS="$EXTRA_CFLAGS -DCONFIG_GENERIC_CPU"
   ./build_arm64.sh
   ```

### Issue: Module Loads But Doesn't Work

**Symptoms**: Module appears in lsmod but KSMBD functionality missing

**Diagnosis**:
```bash
# Check if module is actually functional
lsmod | grep ksmbd
dmesg | grep -i ksmbd

# Check if required daemons are running
ps aux | grep ksmbd
systemctl status ksmbd 2>/dev/null || echo "No systemd service found"
```

**Solutions**:

1. **Check Userspace Components**:
   ```bash
   # KSMBD requires userspace daemon
   which ksmbd.mountd

   # If missing, install or build userspace tools
   git clone https://github.com/cifsd-team/ksmbd-tools.git
   cd ksmbd-tools
   ./bootstrap
   ./configure
   make
   sudo make install
   ```

2. **Check Configuration**:
   ```bash
   # Create necessary users and shares
   sudo ksmbd.adduser -a $(whoami)
   sudo ksmbd.addshare -a public /tmp/public "Public Share"
   ```

3. **Start Services Manually**:
   ```bash
   # Start kernel server
   sudo ksmbd.control -s
   sudo ksmbd.control -c "all"

   # Start userspace daemon
   sudo ksmbd.mountd
   ```

## Performance Issues

### Issue: Slow Performance or High CPU Usage

**Diagnosis**:
```bash
# Check module performance
top -p $(pgrep ksmbd)
iostat -x 1 5

# Check network performance
iperf3 -c target_server -t 30
```

**Solutions**:

1. **Enable Optimizations**:
   ```bash
   # Rebuild with optimizations
   export EXTRA_CFLAGS="$EXTRA_CFLAGS -O3 -mcpu=cortex-a72"
   ./build_arm64.sh -c
   ```

2. **Check Configuration**:
   ```bash
   # Tune KSMBD settings
   echo "max connections=100" | sudo tee /sys/module/ksmbd/parameters/...
   ```

3. **Enable Caching**:
   ```bash
   # Check if oplocks are enabled
   grep -i oplock /proc/fs/ksmbd/* 2>/dev/null || echo "No oplock interface"
   ```

## Debugging Techniques

### Enable Debug Build

```bash
# Build with debug symbols
./build_arm64.sh -d

# On target system, enable debug logging
echo 'module ksmbd +p' > /sys/kernel/debug/dynamic_debug/control
```

### Use GDB for Remote Debugging

```bash
# On build system - create debug symbols
${CROSS_COMPILE}objdump -g ksmbd.ko > ksmbd.debug

# On target system - enable KGDB
echo 'kgdboc=ttyS0,115200' > /sys/module/kgdboc/parameters/kgdboc
echo 'kgdbcon' > /sys/module/kgdboc/parameters/kgdbcon
```

### Kernel Tracing

```bash
# On target system
# Enable trace events
echo 1 > /sys/kernel/debug/tracing/events/ksmbd/enable

# View traces
cat /sys/kernel/debug/tracing/trace_pipe

# Use perf for performance analysis
perf record -g -p $(pgrep ksmbd) sleep 30
perf report
```

### Memory Debugging

```bash
# Check for memory leaks
echo 'module ksmbd +p' > /sys/kernel/debug/dynamic_debug/control
dmesg | grep -i "kmalloc\|kfree"

# Use kmemleak if enabled
echo scan > /sys/kernel/debug/kmemleak
cat /sys/kernel/debug/kmemleak
```

## Recovery Procedures

### Complete Reset

If everything is broken, start fresh:

```bash
# 1. Clean all build artifacts
make -f Makefile.arm64 distclean
rm -rf build-arm64/
rm -f build.env

# 2. Reset environment
unset ARCH CROSS_COMPILE CC KERNEL_VERSION
unset DEBUG CLEAN JOBS

# 3. Remove any installed cross-compilers (optional)
# brew uninstall aarch64-linux-gnu-binutils

# 4. Start fresh setup
./setup_arm64_build.sh -f
```

### Backup and Restore Working Build

```bash
# Create backup of working build
tar czf ksmbd-arm64-backup-$(date +%Y%m%d).tar.gz \
    build-arm64/ \
    ksmbd.ko \
    build.env \
    Makefile.arm64

# Restore from backup
tar xzf ksmbd-arm64-backup-YYYYMMDD.tar.gz
source build.env
```

### Automated Recovery Script

```bash
#!/bin/bash
# recovery.sh - Automated recovery script

set -e

echo "Starting KSMBD ARM64 build recovery..."

# 1. Check environment
echo "1. Checking environment..."
if [[ "$(uname -s)" != "Darwin" ]] || [[ "$(uname -m)" != "arm64" ]]; then
    echo "Error: This script must be run on macOS ARM64"
    exit 1
fi

# 2. Clean previous build
echo "2. Cleaning previous build..."
make -f Makefile.arm64 distclean 2>/dev/null || true
rm -rf build-arm64/ 2>/dev/null || true

# 3. Reset environment
echo "3. Resetting environment..."
unset ARCH CROSS_COMPILE CC KERNEL_VERSION
unset DEBUG CLEAN JOBS

# 4. Setup fresh build
echo "4. Setting up fresh build..."
./setup_arm64_build.sh -f

# 5. Build module
echo "5. Building module..."
./build_arm64.sh -c

# 6. Verify build
echo "6. Verifying build..."
if [ -f "ksmbd.ko" ]; then
    echo "✓ Build successful!"
    echo "Module: ksmbd.ko ($(ls -lh ksmbd.ko | awk '{print $5}'))"
    echo "Architecture: $(file ksmbd.ko | cut -d: -f2-)"
else
    echo "✗ Build failed!"
    exit 1
fi

echo "Recovery complete!"
```

Save this as `recovery.sh` and make it executable:
```bash
chmod +x recovery.sh
```

## Getting Help

### Collecting Diagnostic Information

Before seeking help, collect this information:

```bash
#!/bin/bash
# collect_info.sh - Gather diagnostic information

echo "=== KSMBD ARM64 Build Diagnostic Information ==="
echo "Generated: $(date)"
echo

echo "=== System Information ==="
uname -a
sw_vers
echo

echo "=== Development Tools ==="
echo "Homebrew:"
brew --version 2>/dev/null || echo "Homebrew not found"
echo

echo "Cross-compilers:"
aarch64-linux-gnu-gcc --version 2>/dev/null || echo "aarch64-linux-gnu-gcc not found"
aarch64-elf-gcc --version 2>/dev/null || echo "aarch64-elf-gcc not found"
echo

echo "=== Build Environment ==="
echo "Environment variables:"
env | grep -E "ARCH|CROSS|KERNEL|DEBUG" || echo "No relevant environment variables"
echo

echo "=== Build Directory ==="
if [ -d "build-arm64" ]; then
    echo "build-arm64 contents:"
    ls -la build-arm64/
    echo

    if [ -d "build-arm64/linux-headers-"*"-arm64" ]; then
        echo "Kernel headers:"
        ls -la build-arm64/linux-headers-*/include/ | head -10
    else
        echo "Kernel headers not found"
    fi
else
    echo "build-arm64 directory not found"
fi
echo

echo "=== Build Output ==="
if [ -f "ksmbd.ko" ]; then
    echo "Module file:"
    ls -lh ksmbd.ko
    file ksmbd.ko
    echo

    echo "Module symbols:"
    aarch64-linux-gnu-nm ksmbd.ko | wc -l
    echo "total symbols"
else
    echo "ksmbd.ko not found"
fi
echo

echo "=== Recent Build Log ==="
if [ -f "build.log" ]; then
    echo "Last 20 lines of build log:"
    tail -20 build.log
else
    echo "No build.log found"
fi
```

### Reporting Issues

When reporting issues, include:

1. **System Information**: macOS version, hardware
2. **Build Configuration**: Kernel version, cross-compiler version
3. **Error Messages**: Full error output
4. **Steps Taken**: What you've already tried
5. **Diagnostic Output**: Run `./collect_info.sh`

### Community Resources

- **GitHub Issues**: https://github.com/cifsd-team/ksmbd/issues
- **Linux Kernel Mailing List**: linux-kernel@vger.kernel.org
- **Stack Overflow**: Tag with `ksmbd` and `cross-compilation`

---

This troubleshooting guide should help resolve most common issues with KSMBD ARM64 cross-compilation. Remember to work systematically through the diagnostic checklist before diving into specific solutions.