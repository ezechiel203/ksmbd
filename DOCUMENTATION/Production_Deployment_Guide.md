# Apple SMB Extensions - Production Deployment Guide

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Security Setup](#security-setup)
6. [Performance Tuning](#performance-tuning)
7. [Monitoring](#monitoring)
8. [Troubleshooting](#troubleshooting)
9. [Integration Examples](#integration-examples)
10. [Best Practices](#best-practices)

## Overview

This guide provides comprehensive instructions for deploying and managing KSMBD with Apple SMB extensions in production environments. Apple SMB extensions enable macOS and iOS clients to seamlessly work with KSMBD servers while maintaining Apple-specific functionality including Time Machine backup support, Finder metadata, and performance optimizations.

### Key Features in Production

- **Time Machine Support**: Full network backup capability for macOS devices
- **Finder Metadata**: Classic Mac OS file type and creator code support
- **Performance Optimization**: 14x faster directory listings for Apple clients
- **Enterprise Security**: Cryptographic client validation and capability gating
- **Seamless Integration**: Native macOS and iOS user experience

## Prerequisites

### System Requirements

#### Minimum Requirements
- **Kernel**: Linux 5.4 or later
- **Memory**: 1GB RAM (additional 512MB recommended for Apple features)
- **Storage**: 50GB available space for Time Machine backups
- **Network**: Gigabit Ethernet or faster for optimal performance

#### Recommended Requirements
- **Kernel**: Linux 5.10 or later with latest patches
- **Memory**: 4GB RAM or more
- **Storage**: SSD storage with TRIM support
- **Network**: 10GbE or multiple bonded interfaces
- **CPU**: Modern multi-core processor (64-bit required)

### Software Dependencies

```bash
# Required packages for Ubuntu/Debian
sudo apt update
sudo apt install -y \
    build-essential \
    linux-headers-$(uname -r) \
    libssl-dev \
    uuid-dev \
    keyutils \
    pkg-config \
    git

# Required packages for RHEL/CentOS
sudo yum install -y \
    kernel-devel \
    kernel-headers \
    openssl-devel \
    libuuid-devel \
    keyutils-libs-devel \
    pkgconfig \
    git
```

### Kernel Configuration

Ensure your kernel has these features enabled:

```bash
# Check kernel configuration
grep -E "CONFIG_CRYPTO_|CONFIG_FS_ENCRYPTION|CONFIG_KEYS" /boot/config-$(uname -r)

# Required features should be 'y' or 'm'
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_USER_API_HASH=y
CONFIG_FS_ENCRYPTION=y
CONFIG_KEYS=y
CONFIG_KEY_DH_OPERATIONS=y
```

## Installation

### Building KSMBD with Apple Extensions

1. **Clone and Build**
```bash
cd /usr/src
sudo git clone https://github.com/samba-team/ksmbd.git
cd ksmbd

# Configure for Apple support
./configure --enable-apple-extensions --enable-debug
make -j$(nproc)
```

2. **Install Kernel Module**
```bash
sudo make install
sudo depmod -a
sudo modprobe ksmbd
```

3. **Verify Installation**
```bash
# Check if module loaded
lsmod | grep ksmbd

# Verify Apple extensions enabled
sudo dmesg | grep -i apple
```

### DKMS Installation (Recommended)

For easier updates and kernel compatibility:

```bash
# Install DKMS if not present
sudo apt install dkms  # Ubuntu/Debian
sudo yum install dkms  # RHEL/CentOS

# Create DKMS configuration
sudo cp -r /usr/src/ksmbd /usr/src/ksmbd-3.5.3
sudo dkms add -m ksmbd -v 3.5.3
sudo dkms build -m ksmbd -v 3.5.3
sudo dkms install -m ksmbd -v 3.5.3
```

### Service Configuration

Create systemd service files:

```ini
# /etc/systemd/system/ksmbd.service
[Unit]
Description=KSMBD Kernel SMB Server
After=network.target remote-fs.target

[Service]
Type=forking
ExecStart=/usr/sbin/ksmbd.mountd
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ksmbd
```

## Configuration

### Basic Configuration

Create `/etc/ksmbd/ksmbd.conf`:

```ini
[global]
    # Server identification
    server string = KSMBD Apple Server
    netbios name = KSMBD-APPLE

    # Logging
    log level = 1
    max log size = 1000
    syslog only = no

    # Security
    hosts allow = 192.168.1.0/24 10.0.0.0/8
    hosts deny = 0.0.0.0/0
    min protocol = SMB2
    max protocol = SMB3

    # Performance
    smb2 max credits = 8192
    smb2 max trans = 1048576
    smb2 max read = 8388608
    smb2 max write = 8388608
```

### Apple-Specific Configuration

Add Apple extensions to global section:

```ini
[global]
    # ... previous configuration ...

    # Apple Extensions
    apple extensions = yes
    apple version = 2.0
    apple client validation = yes
    apple mac validation = yes
    apple time machine = yes
    apple compression = zlib
    apple case sensitive = yes

    # Performance tuning for Apple clients
    apple readdir cache = yes
    apple readdir batch size = 512
    apple xattr batch = yes
    apple resilient handles = yes
```

### Share Configuration for Apple Clients

Configure shares specifically for Apple usage:

```ini
[TimeMachine]
    # Basic share settings
    path = /srv/timemachine
    browsable = yes
    writable = yes
    guest ok = no
    valid users = @timemachine

    # Apple-specific settings
    apple extensions = yes
    apple time machine = yes
    apple sparse bundles = yes
    apple durable handles = yes
    vfs objects = fruit streams_xattr

    # Time Machine specific
    fruit:encoding = private
    fruit:metadata = stream
    fruit:time machine = yes
    fruit:resource = file
    fruit:posix_rename = yes

    # Permissions
    create mask = 0660
    directory mask = 0770
    force user = timemachine
    force group = timemachine
```

```ini
[MacShare]
    # General Mac share
    path = /srv/macshare
    browsable = yes
    writable = yes
    guest ok = no

    # Apple features
    apple extensions = yes
    apple finder info = yes
    apple case sensitive = yes
    apple unix extensions = yes

    # Extended attributes
    ea support = yes
    store dos attributes = yes
    fruit:encoding = native
    fruit:metadata = stream
```

### User Configuration

Create users and groups for Apple access:

```bash
# Create TimeMachine group and user
sudo groupadd timemachine
sudo useradd -m -g timemachine -s /bin/false timemachine

# Set password for TimeMachine user
sudo smbpasswd -a timemachine

# Create regular Mac users
sudo useradd -m macuser
sudo smbpasswd -a macuser
```

## Security Setup

### Client Authentication Security

Configure cryptographic validation:

```ini
[global]
    # Client validation
    apple client validation = yes
    apple mac validation = yes
    apple signature validation = yes

    # Anti-spoofing measures
    apple strict validation = yes
    apple sequence validation = yes
    apple anti replay = yes

    # Capability gating
    apple capability gating = yes
    apple default capabilities = standard
```

### Network Security

Configure firewall rules:

```bash
# UFW configuration for Ubuntu
sudo ufw allow Samba
sudo ufw allow from 192.168.1.0/24 to any port 445

# Additional Apple-specific ports
sudo ufw allow from 192.168.1.0/24 to any port 548
sudo ufw allow from 192.168.1.0/24 to any port 445
```

### Certificate Configuration (Optional)

For enhanced security with certificate validation:

```bash
# Generate certificates
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/ksmbd/ksmbd.key \
    -out /etc/ksmbd/ksmbd.crt \
    -subj "/C=US/ST=California/L=San Francisco/O=My Company/CN=ksmbd.example.com"

# Configure certificates in ksmbd.conf
[global]
    tls keyfile = /etc/ksmbd/ksmbd.key
    tls certfile = /etc/ksmbd/ksmbd.crt
    tls cafile = /etc/ksmbd/ca.crt
```

### Access Control Lists

Implement granular access control:

```ini
[TimeMachine]
    # Restrict to specific Macs by hostname
    hosts allow = macbook-pro.local mac-mini.local
    hosts deny = ALL

    # Limit to specific users
    valid users = @timemachine admin
    invalid users = guest nobody

    # Time Machine specific restrictions
    fruit:time machine max size = 2T
    fruit:time machine backup count = 3
```

## Performance Tuning

### Memory and Cache Tuning

Configure system-wide performance settings:

```bash
# /etc/sysctl.conf
# Memory performance
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2

# Network performance
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 30000
```

Apply settings:
```bash
sudo sysctl -p
```

### Apple-Specific Performance Tuning

```ini
[global]
    # Readdir performance (14x improvement)
    apple readdir cache = yes
    apple readdir cache timeout = 30
    apple readdir batch size = 512
    apple readdir attr batch = yes

    # Extended attribute performance
    apple xattr batch = yes
    apple xattr cache = yes
    apple xattr cache size = 1000

    # Handle performance
    apple resilient handles = yes
    apple max file handles = 65536
    apple durable handle timeout = 300

    # Compression settings
    apple compression = zlib
    apple compression level = 6
    apple compression threshold = 1024
```

### Filesystem Optimization

For optimal Time Machine performance:

```bash
# Format with appropriate options
sudo mkfs.ext4 -m 1 -E stride=4,stripe-width=64 /dev/sdb1

# Mount options for TimeMachine share
/dev/sdb1 /srv/timemachine ext4 defaults,noatime,nodiratime,data=writeback,barrier=1 0 2
```

### Network Tuning

For high-performance environments:

```bash
# Enable jumbo frames if supported
sudo ip link set dev eth0 mtu 9000

# Bond multiple interfaces (example)
sudo nano /etc/network/interfaces

auto bond0
iface bond0 inet static
    address 192.168.1.10
    netmask 255.255.255.0
    bond-mode 4
    bond-lacp-rate 1
    bond-slaves eth0 eth1
```

## Monitoring

### System Monitoring

Monitor KSMBD performance:

```bash
# Kernel statistics
cat /proc/fs/ksmbd/stats

# Memory usage
cat /proc/fs/ksmbd/meminfo

# Connection information
cat /proc/fs/ksmbd/connections

# Debug information
cat /proc/fs/ksmbd/debug
```

### Apple-Specific Monitoring

Monitor Apple client activity:

```bash
# Apple connection statistics
cat /proc/fs/ksmbd/apple_stats

# Apple client connections
cat /proc/fs/ksmbd/apple_connections

# Performance metrics
cat /proc/fs/ksmbd/apple_performance
```

### Log Analysis

Configure comprehensive logging:

```ini
[global]
    log level = 2
    log file = /var/log/ksmbd/%m.log
    max log size = 50000
    debug timestamp = yes
    debug uid = yes
    debug pid = yes
    debug level = apple:10
```

### Performance Monitoring Scripts

Create monitoring script `/usr/local/bin/ksmbd-monitor`:

```bash
#!/bin/bash
# KSMBD Performance Monitor

LOG_FILE="/var/log/ksmbd/performance.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Collect statistics
CONNECTIONS=$(cat /proc/fs/ksmbd/connections 2>/dev/null | wc -l)
MEMORY=$(cat /proc/fs/ksmbd/meminfo 2>/dev/null | grep "Total memory" | awk '{print $3}')
APPLE_CONNECTIONS=$(cat /proc/fs/ksmbd/apple_connections 2>/dev/null | wc -l)

# Log performance data
echo "$DATE, Connections: $CONNECTIONS, Memory: $MEMORY KB, Apple Clients: $APPLE_CONNECTIONS" >> $LOG_FILE

# Alert on high memory usage
if [ ${MEMORY:-0} -gt 1048576 ]; then
    echo "WARNING: High KSMBD memory usage: $MEMORY KB" | logger -t ksmbd-monitor
fi
```

Make executable:
```bash
sudo chmod +x /usr/local/bin/ksmbd-monitor
```

### Grafana Dashboard (Optional)

For comprehensive monitoring with Grafana:

1. **Install Telegraf for metrics collection**
```bash
sudo apt install telegraf
```

2. **Configure KSMBD metrics input**
```ini
# /etc/telegraf/telegraf.conf
[[inputs.exec]]
    commands = ["/usr/local/bin/ksmbd-metrics"]
    data_format = "influx"
```

3. **Create Grafana dashboard** for KSMBD metrics

## Troubleshooting

### Common Issues

#### Apple Clients Cannot Connect

**Symptoms:**
- macOS Finder cannot connect to server
- Time Machine cannot find backup destination
- Connection timeouts

**Solutions:**
```bash
# Check KSMBD service status
sudo systemctl status ksmbd

# Verify Apple extensions enabled
sudo dmesg | grep -i apple

# Check network connectivity
sudo netstat -tuln | grep :445

# Test with smbclient
smbclient -L //server_name -U user%password
```

**Configuration Check:**
```ini
# Verify these settings in ksmbd.conf
[global]
    apple extensions = yes
    min protocol = SMB2
    max protocol = SMB3

[share]
    browsable = yes
    writable = yes
    guest ok = no
```

#### Time Machine Backup Issues

**Symptoms:**
- Time Machine fails to start backup
- Backup stops unexpectedly
- Sparse bundle creation fails

**Solutions:**
```bash
# Check share permissions
ls -la /srv/timemachine

# Verify user has write access
sudo -u timemachine touch /srv/timemachine/testfile

# Check disk space
df -h /srv/timemachine

# Check KSMBD logs
sudo tail -f /var/log/ksmbd.log | grep -i timemachine
```

**Required Share Settings:**
```ini
[TimeMachine]
    fruit:time machine = yes
    fruit:metadata = stream
    fruit:encoding = private
    fruit:resource = file
    fruit:posix_rename = yes
    vfs objects = fruit streams_xattr
```

#### Performance Issues

**Symptoms:**
- Slow directory listing on macOS
- File transfer speeds slow
- High CPU usage on server

**Solutions:**
```bash
# Check system resources
top -p $(pgrep ksmbd)

# Monitor network performance
iftop -i eth0

# Check disk performance
iostat -x 1

# Enable performance debugging
echo 1 > /sys/module/ksmbd/parameters/debug_apple
```

**Performance Tuning:**
```ini
[global]
    apple readdir cache = yes
    apple readdir batch size = 512
    apple xattr batch = yes
    smb2 max credits = 8192
    smb2 max trans = 1048576
```

### Debug Logging

Enable detailed debugging:

```bash
# Enable Apple-specific debug
sudo sysctl -w fs.ksmbd.debug_flags=0x7FFF

# Enable in-memory debug
sudo echo 1 > /sys/module/ksmbd/parameters/debug_apple

# Capture debug logs
sudo dmesg -w | grep KSMBD
```

### Connection Analysis

Analyze Apple client connections:

```bash
# View active connections
cat /proc/fs/ksmbd/apple_connections

# Check negotiated capabilities
cat /proc/fs/ksmbd/apple_capabilities

# Monitor performance metrics
cat /proc/fs/ksmbd/apple_performance
```

## Integration Examples

### macOS Deployment Script

Automated macOS client configuration:

```bash
#!/bin/bash
# configure_macos.sh - Configure macOS for KSMBD

SERVER_IP="192.168.1.10"
USERNAME="macuser"
SHARE_NAME="MacShare"

# Mount share automatically
echo "mount -t smbfs //$USERNAME@$SERVER_IP/$SHARE_NAME /mnt/ksmbd" | sudo tee -a /etc/fstab

# Configure Time Machine
sudo tmutil setdestination -p smb://$USERNAME@$SERVER_IP/TimeMachine

# Configure Finder favorites
defaults write com.apple.finder FavoriteItems -array-add \
    '{"Name":"KSMBD Share","URL":"smb://$SERVER_IP/$SHARE_NAME"}'

echo "macOS configured for KSMBD server at $SERVER_IP"
```

### Enterprise Deployment

For enterprise environments, use configuration management:

```puppet
# Puppet manifest for KSMBD
class ksmbd::apple {
    package { 'ksmbd-apple':
        ensure => installed,
    }

    file { '/etc/ksmbd/ksmbd.conf':
        ensure  => file,
        content => template('ksmbd/apple.conf.erb'),
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        notify  => Service['ksmbd'],
    }

    service { 'ksmbd':
        ensure => running,
        enable => true,
    }

    mount { '/srv/timemachine':
        ensure  => mounted,
        device  => '/dev/sdb1',
        fstype => 'ext4',
        options => 'defaults,noatime,data=writeback',
    }
}
```

### Backup Configuration

Automated backup setup:

```bash
#!/bin/bash
# setup_timemachine.sh - Configure Time Machine backup

SHARE_PATH="/srv/timemachine"
USER_NAME="timemachine"

# Create TimeMachine directory structure
sudo -u $USER_NAME mkdir -p "$SHARE_PATH/Backups"

# Set up extended attributes support
sudo chattr +e "$SHARE_PATH"

# Configure permissions
sudo chmod 770 "$SHARE_PATH"
sudo chown $USER_NAME:$USER_NAME "$SHARE_PATH"

# Test Time Machine functionality
echo "Time Machine share configured at $SHARE_PATH"
echo "Test with: tmutil setdestination -p smb://$USER_NAME@$(hostname)/TimeMachine"
```

## Best Practices

### Security Best Practices

1. **Network Isolation**
   - Place KSMBD servers in dedicated network segment
   - Use VLANs to separate Apple client traffic
   - Implement network-based access controls

2. **Authentication Security**
   - Always use encrypted connections (SMB3 encryption)
   - Implement strong password policies
   - Consider certificate-based authentication

3. **Filesystem Security**
   - Use separate filesystem for Time Machine backups
   - Implement filesystem encryption for sensitive data
   - Regular backup integrity verification

4. **Monitoring and Auditing**
   - Implement comprehensive logging
   - Regular security audits
   - Anomaly detection for unusual access patterns

### Performance Best Practices

1. **Hardware Selection**
   - Use SSD storage for optimal Time Machine performance
   - Sufficient RAM for caching (recommend 4GB+)
   - Network interface redundancy for high availability

2. **Filesystem Configuration**
   - Use modern filesystem with extended attribute support
   - Configure appropriate mount options for performance
   - Monitor filesystem health regularly

3. **Network Optimization**
   - Use jumbo frames if network supports it
   - Implement QoS for backup traffic
   - Monitor network performance and bottlenecks

### Operational Best Practices

1. **Change Management**
   - Test all configuration changes in staging environment
   - Implement change windows for production updates
   - Maintain configuration version control

2. **Backup and Recovery**
   - Regular configuration backups
   - Document restore procedures
   - Test disaster recovery scenarios

3. **Capacity Planning**
   - Monitor storage usage trends
   - Plan for Time Machine growth (typically 2-3x data size)
   - Implement storage expansion procedures

### Maintenance Procedures

**Daily Tasks:**
- Monitor system health and performance
- Review log files for issues
- Check backup completion status

**Weekly Tasks:**
- Verify Apple client connectivity
- Review security logs
- Performance analysis and tuning

**Monthly Tasks:**
- Security updates and patching
- Storage capacity planning
- Backup verification testing

**Quarterly Tasks:**
- Disaster recovery testing
- Performance benchmarking
- Security audit review

## Conclusion

This production deployment guide provides comprehensive instructions for deploying KSMBD with Apple SMB extensions in enterprise environments. Following these best practices ensures a secure, performant, and reliable SMB server that seamlessly integrates with macOS and iOS clients while supporting critical features like Time Machine backup and Finder metadata.

Key success factors:
- **Proper Planning**: Understand requirements and capacity needs
- **Security First**: Implement comprehensive security controls
- **Performance Tuning**: Optimize for Apple client workloads
- **Monitoring**: Implement comprehensive visibility
- **Documentation**: Maintain accurate configuration records

With this guide, organizations can successfully deploy KSMBD as a production-ready Apple SMB server supporting enterprise-scale macOS and iOS deployments.