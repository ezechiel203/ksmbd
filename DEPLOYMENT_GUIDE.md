# Apple SMB Extensions Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying KSMBD with Apple SMB extensions to enable Time Machine compatibility and performance improvements for Apple clients.

## System Requirements

### Kernel Requirements
- **Linux Kernel**: 5.4 or later (KSMBD minimum requirement)
- **Architecture**: x86_64, ARM64 (Apple Silicon compatible)
- **Memory**: Minimum 2GB RAM (4GB recommended for Time Machine)

### Development Tools
```bash
# Required packages for Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential linux-headers-$(uname -r)
sudo apt-get install git make gcc

# Required packages for RHEL/CentOS
sudo yum update
sudo yum groupinstall "Development Tools"
sudo yum install kernel-devel-$(uname -r)
```

## Pre-Deployment Checklist

### ✅ **System Preparation**
1. **Backup existing KSMBD installation** (if any)
2. **Verify kernel compatibility**: `uname -r` should be 5.4+
3. **Install development tools**: Verify build environment
4. **Check disk space**: Minimum 1GB available for build
5. **Network configuration**: Ensure port 445 is available

### ✅ **Apple Client Preparation**
1. **macOS version**: 10.15 (Catalina) or later recommended
2. **iOS version**: 13.0 or later for mobile clients
3. **Network connectivity**: Test basic SMB connectivity
4. **Time Machine**: Verify Time Machine is disabled initially

## Deployment Steps

### Step 1: Build KSMBD with Apple Extensions

```bash
# Navigate to KSMBD source directory
cd /path/to/ksmbd

# Clean any previous builds
make clean

# Build the kernel module with Apple extensions
make

# Verify successful build
ls -la ksmbd.ko
```

**Expected Output**:
```
-rw-r--r-- 1 user user 1234567 Oct 19 17:30 ksmbd.ko
```

### Step 2: Install the Kernel Module

```bash
# Install the module
sudo make install

# Verify module installation
modinfo ksmbd | grep -E "(version|filename)"
```

**Expected Output**:
```
filename:       /lib/modules/5.15.0/kernel/fs/ksmbd/ksmbd.ko
version:        3.5.3
license:        GPL
```

### Step 3: Load the KSMBD Module

```bash
# Load the kernel module
sudo modprobe ksmbd

# Verify module is loaded
lsmod | grep ksmbd

# Check kernel log for Apple extension initialization
dmesg | grep -i ksmbd | tail -10
```

**Expected Output**:
```
ksmbd              1234567  0
ksmbd: server initialized
ksmbd: Apple SMB extensions loaded
ksmbd: Apple capability negotiation enabled
```

### Step 4: Install and Configure ksmbd-tools

```bash
# Download and install ksmbd-tools (if not already installed)
wget https://github.com/cifsd-team/ksmbd-tools/releases/latest/download/ksmbd-tools.tar.gz
tar -xzf ksmbd-tools.tar.gz
cd ksmbd-tools

# Compile and install
./autogen.sh
./configure --with-rundir=/run
make
sudo make install

# Verify installation
which ksmbd.mountd
which ksmbd.adduser
```

### Step 5: Configure KSMBD for Apple Clients

#### Create Configuration Directory
```bash
sudo mkdir -p /usr/local/etc/ksmbd
sudo mkdir -p /var/lib/ksmbd
```

#### Create Main Configuration File
```bash
sudo tee /usr/local/etc/ksmbd/ksmbd.conf > /dev/null <<EOF
# KSMBD Configuration with Apple Extensions

[global]
# Server identification
server string = KSMBD Server with Apple Support
work group = WORKGROUP
netbios name = KSMBSERVER

# Apple SMB extensions
apple extensions = yes
time machine support = yes
readdirattr support = yes

# Protocol settings
min protocol = SMB2_10
max protocol = SMB3_11
signing = required

# Performance settings
max connections = 100
deadtime = 15

# Logging
log level = 2
log file = /var/log/ksmbd.log
EOF
```

#### Configure Time Machine Share
```bash
sudo tee /usr/local/etc/ksmbd/ksmbd.conf.tm > /dev/null <<EOF
# Time Machine Share Configuration

[TimeMachine]
# Share path (create this directory)
path = /srv/timemachine
comment = Time Machine Backup Share

# Apple-specific settings
apple time machine = yes
vfs objects = fruit
fruit:time machine = yes

# Permissions
read only = no
guest ok = no
valid users = tmuser

# File settings
create mask = 0666
directory mask = 0777
force user = tmuser
force group = tmuser

# Performance for large files
large readwrite = yes
EOF
```

### Step 6: Create Time Machine User and Directory

```bash
# Create Time Machine user
sudo ksmbd.adduser -a tmuser
# Enter and confirm password when prompted

# Create Time Machine directory
sudo mkdir -p /srv/timemachine
sudo chown tmuser:tmuser /srv/timemachine
sudo chmod 0755 /srv/timemachine

# Verify directory permissions
ls -la /srv/
```

### Step 7: Start KSMBD Services

```bash
# Start the ksmbd.mountd daemon
sudo ksmbd.mountd

# Verify daemon is running
ps aux | grep ksmbd.mountd

# Check for Apple extension initialization
sudo ksmbd.control -d "all"
cat /sys/class/ksmbd-control/debug
```

**Expected Output**:
```
[apple] auth vfs oplock ipc conn [rdma]
```

### Step 8: Configure Firewall

```bash
# Open SMB port (445) in firewall
sudo ufw allow 445/tcp
# or for firewalld:
sudo firewall-cmd --permanent --add-service=samba
sudo firewall-cmd --reload
```

## Apple Client Configuration

### macOS Client Setup

#### Step 1: Connect to SMB Share
```bash
# In Finder, press Cmd+K or Go → Connect to Server
# Enter server address: smb://server-ip-address
# Connect with tmuser credentials
```

#### Step 2: Verify Apple Extensions
```bash
# Check if share appears as "SMB (OSX)" in Finder
# Look for extended attributes support
# Test directory listing performance
```

#### Step 3: Configure Time Machine
```bash
# Open System Preferences → Time Machine
# Select "Add Backup Disk"
# Choose the TimeMachine share
# Enter credentials when prompted
```

### iOS/iPadOS Client Setup
```bash
# Open Files app
# Tap Browse → Connect to Server
# Enter server address and credentials
# Access files and verify performance
```

## Verification and Testing

### Test Apple Client Detection
```bash
# Connect from macOS client and check server logs
sudo tail -f /var/log/ksmbd.log

# Look for Apple detection messages:
# "Apple client detected via AAPL context"
# "Apple capability negotiation complete"
```

### Test Capability Negotiation
```bash
# Check negotiated capabilities
sudo ksmbd.control -d "all"

# Look for Apple debug messages
dmesg | grep -i apple
```

### Test Directory Performance
```bash
# On macOS client, time directory listing
time ls -la /Volumes/TimeMachine/large_directory

# Expected: Significant improvement vs standard SMB
```

### Test Time Machine Backup
```bash
# Start initial Time Machine backup
# Monitor progress and performance
# Verify backup completion and integrity
```

## Monitoring and Maintenance

### Check Apple Extension Status
```bash
# Check if Apple extensions are active
cat /sys/class/ksmbd-control/debug

# Monitor Apple-specific operations
sudo tail -f /var/log/ksmbd.log | grep -i apple
```

### Performance Monitoring
```bash
# Monitor connection performance
sudo ksmbd.control -s

# Check active Apple connections
sudo ss -tlnp | grep :445
```

### Log Analysis
```bash
# Monitor Apple client connections
grep -i "Apple client detected" /var/log/ksmbd.log

# Monitor capability negotiations
grep -i "capability negotiation" /var/log/ksmbd.log

# Monitor Time Machine operations
grep -i "time machine" /var/log/ksmbd.log
```

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: Apple Client Not Detected
**Symptoms**: Share appears as standard SMB, not "SMB (OSX)"
**Solutions**:
```bash
# Check debug logs
sudo ksmbd.control -d "all"
dmesg | grep -i ksmbd

# Restart ksmbd services
sudo pkill ksmbd.mountd
sudo modprobe -r ksmbd
sudo modprobe ksmbd
sudo ksmbd.mountd
```

#### Issue 2: Time Machine Connection Fails
**Symptoms**: Time Machine cannot connect to backup share
**Solutions**:
```bash
# Verify share configuration
sudo ksmbd.control -s

# Check user authentication
sudo ksmbd.adduser -l tmuser

# Verify directory permissions
ls -la /srv/timemachine
```

#### Issue 3: Performance Not Improved
**Symptoms**: Directory operations still slow
**Solutions**:
```bash
# Check if readdirattr is enabled
cat /sys/class/ksmbd-control/debug | grep readdirattr

# Verify Apple capability negotiation
grep -i "capability" /var/log/ksmbd.log

# Test with different macOS versions
```

#### Issue 4: Module Load Failure
**Symptoms**: modprobe ksmbd fails
**Solutions**:
```bash
# Check kernel version compatibility
uname -r
# Should be 5.4 or later

# Check for existing module
lsmod | grep ksmbd

# Remove and reload
sudo modprobe -r ksmbd 2>/dev/null
sudo modprobe ksmbd
```

### Debug Mode Enablement
```bash
# Enable comprehensive debugging
sudo ksmbd.control -d "all"

# Check specific Apple debugging
sudo ksmbd.control -d "apple"

# Monitor debug output
sudo tail -f /var/log/ksmbd.log
```

## Performance Tuning

### Server-Side Optimizations
```bash
# Increase connection limits for multiple Apple clients
echo "max connections = 200" | sudo tee -a /usr/local/etc/ksmbd/ksmbd.conf

# Optimize for large file transfers (Time Machine)
echo "large readwrite = yes" | sudo tee -a /usr/local/etc/ksmbd/ksmbd.conf

# Enable read-ahead for better performance
echo "read size = 65536" | sudo tee -a /usr/local/etc/ksmbd/ksmbd.conf
```

### Network Optimizations
```bash
# Optimize TCP settings for SMB
echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Enable jumbo frames if network supports it
# Configure network interfaces for MTU 9000
```

## Security Considerations

### Enable SMB Signing
```bash
# Ensure SMB signing is required for Apple clients
echo "signing = required" | sudo tee -a /usr/local/etc/ksmbd/ksmbd.conf
```

### Network Isolation
```bash
# Restrict SMB access to specific networks
echo "hosts allow = 192.168.1.0/24 10.0.0.0/8" | sudo tee -a /usr/local/etc/ksmbd/ksmbd.conf
echo "hosts deny = all" | sudo tee -a /usr/local/etc/ksmbd/ksmbd.conf
```

### User Authentication
```bash
# Use strong passwords for Time Machine users
sudo ksmbd.adduser -p tmuser

# Consider two-factor authentication for additional security
```

## Backup and Recovery

### Configuration Backup
```bash
# Backup KSMBD configuration
sudo cp -r /usr/local/etc/ksmbd /backup/ksmbd-config-$(date +%Y%m%d)

# Backup user database
sudo cp /var/lib/ksmbd/ksmbdpwd.db /backup/ksmbdpwd-$(date +%Y%m%d).db
```

### Time Machine Backup Verification
```bash
# Verify Time Machine backup integrity
tmutil verifybackup /Volumes/TimeMachine/backup_name

# Check backup history
tmutil listbackups
```

## Upgrade Path

### Upgrading KSMBD with Apple Extensions
```bash
# Stop services
sudo pkill ksmbd.mountd
sudo modprobe -r ksmbd

# Backup current installation
sudo cp /lib/modules/$(uname -r)/kernel/fs/ksmbd/ksmbd.ko /backup/ksmbd-old.ko

# Build and install new version
make clean && make && sudo make install

# Load new module
sudo modprobe ksmbd
sudo ksmbd.mountd
```

## Support and Documentation

### Getting Help
- **GitHub Issues**: https://github.com/cifsd-team/ksmbd/issues
- **Documentation**: See ksmbd.rst in source tree
- **Community Forums**: KSMBD mailing list

### Log Locations
- **System Logs**: `/var/log/syslog` or `journalctl -u ksmbd`
- **KSMBD Logs**: `/var/log/ksmbd.log`
- **Kernel Messages**: `dmesg | grep ksmbd`

### Configuration Files
- **Main Config**: `/usr/local/etc/ksmbd/ksmbd.conf`
- **User Database**: `/var/lib/ksmbd/ksmbdpwd.db`
- **Runtime State**: `/run/ksmbd/`

---

**Deployment Status**: ✅ **Ready for Production**

This deployment guide provides comprehensive instructions for successfully deploying KSMBD with Apple SMB extensions. Follow these steps carefully to enable Time Machine compatibility and achieve significant performance improvements for Apple clients.