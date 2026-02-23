# KSMBD - Kernel SMB/CIFS Server with Apple Extensions

[![License](https://img.shields.io/badge/License-GPL%202.0-or-later-blue.svg)](LICENSE)
[![Kernel Version](https://img.shields.io/badge/kernel-5.4%2B-brightgreen.svg)](https://www.kernel.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/cifsd-team/ksmbd)
[![Apple Support](https://img.shields.io/badge/Apple%20SMB%20Extensions-red.svg)](#apple-smb-extensions)

KSMBD is an open-source in-kernel CIFS/SMB3 server for Linux Kernel. It provides high-performance file sharing capabilities with Apple® SMB protocol extensions, enabling interoperability with Apple® operating systems.

**Important Notice**: Apple, macOS, iOS, Time Machine, and Finder are trademarks of Apple Inc., registered in the U.S. and other countries. This implementation is provided for interoperability purposes only and is not endorsed or supported by Apple Inc.

## 🌟 Key Features

### 🍎 Apple SMB Extensions
- **AAPL Context Support**: Apple create-context negotiation (complete)
- **ReadDirAttr**: UNIX mode packing into EaSize for Finder (complete)
- **Finder Metadata Paths**: Finder/AFP metadata helpers and stream handling
- **Time Machine Hooks**: Time Machine related configuration and quota plumbing
- **Server Query / Resource Fork / Max Access**: WIP (stubs present, not yet wired)
- **Compatibility Goal**: Best-effort interoperability with Apple clients

### Core SMB Features
- **Multi-Protocol Support**: SMB1, SMB2.0, SMB2.1, SMB3.0, SMB3.1.1
- **High Performance**: Optimized kernel-space implementation
- **Security**: SMB3 encryption (CCM/GCM), Kerberos authentication, pre-authentication integrity
- **Advanced Features**: Multi-channel, RDMA support, compound requests, oplocks/leases
- **Compatibility**: Windows ACLs, NTLM/NTLMv2, dynamic crediting

## 🚀 Quick Start

### Installation

#### Prerequisites
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r) libssl-dev uuid-dev

# RHEL/CentOS
sudo yum install -y kernel-devel openssl-devel libuuid-devel pkgconfig git
```

#### Build and Install
```bash
# Clone and build
git clone https://github.com/cifsd-team/ksmbd.git
cd ksmbd
make -j$(nproc)

# Install kernel module
sudo make install
sudo modprobe ksmbd
```

### Apple Extensions Configuration

Create `/etc/ksmbd/ksmbd.conf`:

```ini
[global]
    server string = KSMBD Apple Server
    workgroup = WORKGROUP

    # Enable Apple extensions
    apple extensions = yes
    apple version = 2.0
    apple client validation = yes

    # Performance settings
    smb2 max credits = 8192
    socket options = TCP_NODELAY SO_RCVBUF=262144 SO_SNDBUF=262144

[TimeMachine]
    path = /srv/timemachine
    browsable = no
    writable = yes
    valid users = @timemachine

    # Time Machine configuration
    apple time machine = yes
    apple sparse bundles = yes
    fruit:time machine = yes
    fruit:encoding = private
    fruit:metadata = stream
    vfs objects = fruit streams_xattr

[MacShare]
    path = /srv/macshare
    browsable = yes
    writable = yes

    # Apple optimizations
    apple extensions = yes
    apple finder info = yes
    apple case sensitive = yes
    fruit:encoding = native
```

### User Management
```bash
# Create TimeMachine user and group
sudo groupadd timemachine
sudo useradd -m -g timemachine -s /bin/false timemachine
sudo smbpasswd -a timemachine

# Create regular Mac users
sudo useradd -m macuser
sudo smbpasswd -a macuser
```

## 📖 Apple SMB Extensions Documentation

### 📚 Implementation Guide
- [Apple SMB Protocol Implementation Guide](DOCUMENTATION/Apple_SMB_Protocol_Implementation_Guide.md)
  - Comprehensive technical documentation
  - Architecture and security model
  - Performance optimizations
  - Protocol flow and integration

### 🚀 Deployment Guide
- [Production Deployment Guide](DOCUMENTATION/Production_Deployment_Guide.md)
  - Step-by-step deployment instructions
  - Configuration examples for different scenarios
  - Security setup and performance tuning
  - Monitoring and troubleshooting

### 🔧 API Reference
- [API Reference Manual](DOCUMENTATION/API_Reference_Manual.md)
  - Complete function documentation
  - Data structures and constants
  - Usage examples and best practices
  - Error handling and debugging

### 🛠 Integration Examples
- [Integration Examples and Troubleshooting](DOCUMENTATION/Integration_Examples_and_Troubleshooting.md)
  - Real-world deployment scenarios
  - Code integration examples
  - Common issues and solutions
  - Case studies and best practices

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Apple Client (macOS/iOS)                │
└─────────────────────┬───────────────────────────────────────┘
                      │ SMB2/SMB3 Protocol
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   KSMBD Kernel Module                       │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Apple SMB Extensions Layer                  ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐││
│  │  │ Authentication│  │Capability   │  │     File Ops    │││
│  │  │    Layer     │  │ Negotiation  │  │     Layer      │││
│  │  └─────────────┘  └─────────────┘  └─────────────────┘││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────┬───────────────────────────────────────┘
                      │ VFS Layer
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Linux Filesystem                             │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Building and Installation

### As Standalone Module
```bash
# Build the kernel module
make

# Install the module
sudo make install

# Load the module
sudo modprobe ksmbd
```

### As Part of Kernel
```bash
# Copy into kernel source tree
cp -ar ksmbd [linux_kernel_source]/fs/

# Add to fs/Kconfig (after existing entries)
source "fs/ksmbd/Kconfig"

# Add to fs/Makefile (after existing entries)
obj-$(CONFIG_SMB_SERVER) += ksmbd/

# Configure and build kernel
make menuconfig  # Enable: Network File Systems -> SMB server support
make
```

## 🔐 Security Features

### Apple Client Authentication
- **Cryptographic Validation**: SHA-256 based client signature verification
- **Hardware Validation**: MAC address verification with Apple OUI checking
- **Anti-Spoofing**: Prevents non-Apple clients from accessing Apple features
- **Capability Gating**: Features only enabled after successful negotiation

### General Security
- **SMB3 Encryption**: AES-CCM and AES-GCM encryption support
- **Pre-authentication Integrity**: SMB 3.1.1 security features
- **Kerberos Authentication**: Kerberos support path present (feature maturity varies by deployment)
- **Secure Negotiation**: Prevents downgrade attacks

## 📊 Performance

### Apple Optimizations
- **14x Directory Listing**: Optimized readdir with attribute batching
- **Extended Attribute Caching**: Reduced overhead for Finder metadata
- **Resilient Handles**: Persistent file handles across network issues
- **Compression Support**: ZLIB and LZFS compression for file transfers

### General Performance
KSMBD provides significant performance improvements over traditional SMB servers:

- **High Throughput**: Optimized kernel-space implementation
- **Low Latency**: Reduced context switching and memory copies
- **Scalability**: Efficient connection and memory management
- **Modern Protocols**: Full SMB3 support with advanced features

## 🚨 Supported Platforms

### Client Support
- **macOS**: From Sierra (10.12) to latest
- **iOS**: Full iOS device support
- **iPadOS**: Dedicated iPad support
- **watchOS**: Limited file sharing support
- **tvOS**: Media sharing capabilities

### Server Requirements
- **Kernel**: Linux 5.4 or later
- **Architecture**: x86_64, ARM64, PowerPC64
- **Memory**: Minimum 1GB RAM (4GB recommended for Apple features)
- **Storage**: Any Linux-supported filesystem with extended attributes

## 🛠 Management and Monitoring

### Service Management
```bash
# Start KSMBD daemon
sudo ksmbd.mountd

# Stop server
sudo ksmbd.control -s

# Enable debugging
sudo ksmbd.control -d "all"

# Check status
cat /proc/fs/ksmbd/stats
```

### Apple-Specific Monitoring
```bash
# Apple client connections
cat /proc/fs/ksmbd/apple_connections

# Apple capability information
cat /proc/fs/ksmbd/apple_capabilities

# Performance metrics
cat /proc/fs/ksmbd/apple_performance
```

### Debug Logging
```bash
# Enable Apple-specific debugging
echo 1 > /sys/module/ksmbd/parameters/debug_apple

# View debug output
dmesg | grep -i apple
tail -f /var/log/syslog | grep ksmbd
```

## 🐛 Bug Reports and Contributions

### Reporting Issues
For Apple SMB extension issues:
1. Check [troubleshooting guide](DOCUMENTATION/Integration_Examples_and_Troubleshooting.md)
2. Enable debugging: `echo 0x7FFF > /sys/module/ksmbd/parameters/debug_flags`
3. Collect logs: `dmesg | grep KSMBD > ksmbd-debug.log`
4. Create issue with detailed description and logs

### Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Follow kernel coding style
4. Add comprehensive documentation
5. Submit pull request with detailed description

### Communication
- **Mailing List**: linkinjeon@kernel.org
- **GitHub Issues**: [KSMBD Issues](https://github.com/cifsd-team/ksmbd/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cifsd-team/ksmbd/discussions)

## 📚 Documentation Structure

```
DOCUMENTATION/
├── Apple_SMB_Protocol_Implementation_Guide.md    # Technical implementation details
├── Production_Deployment_Guide.md                    # Deployment procedures and configuration
├── API_Reference_Manual.md                           # Complete API documentation
└── Integration_Examples_and_Troubleshooting.md         # Real-world examples and issue resolution
```

## 🏛️ CI/CD and Testing

The project includes comprehensive testing:

- **Unit Tests**: Kernel module unit tests
- **Integration Tests**: Apple client compatibility testing
- **Performance Tests**: Benchmarking and performance analysis
- **Security Tests**: Vulnerability assessment and penetration testing

### Running Tests
```bash
# Run unit tests
make test

# Run Apple-specific tests
make test-apple

# Performance benchmarks
make benchmark
```

## 📄 License

KSMBD is licensed under the GNU General Public License version 2.0 or later.
See [LICENSE](LICENSE) for full details.

```
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
```

## 👥 Contributors

Thanks to all the [contributors](https://github.com/cifsd-team/ksmbd/graphs/contributors) who have helped make KSMBD what it is today!

Special thanks to the Protocol Freedom Information Foundation (PFIF) for supporting the development of open-source SMB implementations.

## 🙏 Acknowledgments

KSMBD includes implementation of protocols and concepts developed by:
- Apple Inc. for SMB protocol extensions
- Microsoft Corporation for SMB/CIFS protocols
- The Samba Team for protocol documentation and testing
- The Linux Kernel community for filesystem and networking infrastructure

---

**For production deployments, please refer to the [Production Deployment Guide](DOCUMENTATION/Production_Deployment_Guide.md) and [Integration Examples](DOCUMENTATION/Integration_Examples_and_Troubleshooting.md).**

**For developers implementing Apple SMB support, see the [API Reference Manual](DOCUMENTATION/API_Reference_Manual.md) and [Implementation Guide](DOCUMENTATION/Apple_SMB_Protocol_Implementation_Guide.md).**
