# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

KSMBD is an open-source in-kernel CIFS/SMB3 server implementation for Linux Kernel. It provides high-performance file sharing capabilities with SMB1, SMB2, and SMB3 protocol support through a sophisticated kernel-userspace architecture.

## Build System and Development Commands

### Building as Standalone Module
```bash
# Build the kernel module
make

# Install the module
sudo make install

# Load the module
sudo modprobe ksmbd
```

### Building as Part of Kernel
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

### Development Commands
```bash
# Clean build artifacts
make clean

# Install using DKMS (for kernel module development)
sudo make dkms-install

# Uninstall DKMS
sudo make dkms-uninstall

# Remove module
sudo make uninstall
```

## Architecture Overview

### Core Design Principles
- **Dual-space architecture**: Performance-critical operations in kernel, management in userspace
- **Multi-protocol support**: SMB1, SMB2.0, SMB2.1, SMB3.0, SMB3.0.2, SMB3.1.1
- **Layered design**: Clear separation between transport, protocol, authentication, and VFS layers
- **Asynchronous processing**: Work queue-based request handling

### Key Components

#### Kernel Space (ksmbd module)
- **Connection Management** (`connection.c/h`): TCP/RDMA transport, connection lifecycle
- **Protocol Processing** (`smb1pdu.c`, `smb2pdu.c`): SMB command parsing and response generation
- **Authentication** (`auth.c/h`): NTLM/NTLMv2/Kerberos authentication
- **VFS Integration** (`vfs.c/h`, `vfs_cache.c`): File system operations and caching
- **Oplock/Lease** (`oplock.c/h`): Client-side caching coordination
- **Work Queue** (`ksmbd_work.c/h`): Asynchronous request processing

#### Userspace (ksmbd.mountd daemon)
- **User Management**: Account database and credential verification
- **Share Configuration**: Share definitions and access controls
- **RPC Services**: DCE/RPC operations (NetShareEnum, NetServerGetInfo, etc.)
- **Netlink Communication**: Kernel-userspace messaging

#### Management Layer (`mgmt/` directory)
- **User Configuration** (`user_config.c/h`): User account management
- **Share Configuration** (`share_config.c/h`): Share definition management
- **Session Management** (`user_session.c/h`): Session lifecycle
- **Tree Connect** (`tree_connect.c/h`): Share connection management
- **IDA Management** (`ksmbd_ida.c/h`): Identifier allocation

### Data Flow Architecture
```
Client → Transport Layer → Protocol Processing → Authentication → Session/Tree Management → VFS Operations
   ↑                           ↑                        ↑                      ↑
Netlink IPC                Command Dispatch        User/Share Config      File System
(ksmbd.mountd)            (Work Queue)           (mgmt/)                (Linux VFS)
```

## Key Configuration Files

### Server Configuration (`server.h`)
- Global server settings (max connections, protocols, signing)
- Runtime configuration through netlink interface
- Server state management (starting, running, resetting, shutdown)

### Protocol Configuration (`smb_common.h`)
- SMB protocol version definitions and negotiation
- Command constants and error codes
- Multi-protocol compatibility settings

## Critical Interfaces

### Netlink Interface (`ksmbd_netlink.h`)
- **Purpose**: Kernel-userspace communication
- **Operations**: User authentication, share configuration, session management
- **Daemon**: `ksmbd.mountd` handles complex operations and RPC calls

### Transport Interface
- **TCP**: Standard SMB transport (`transport_tcp.c`)
- **RDMA**: High-performance SMB Direct (`transport_rdma.c`)
- **IPC**: Kernel-userspace messaging (`transport_ipc.c`)

### VFS Interface (`vfs.h`)
- **Integration**: Linux VFS layer abstraction
- **Operations**: File I/O, attribute management, permission handling
- **Caching**: File handle and attribute caching for performance

## Development Guidelines

### Protocol Implementation
- **Multi-version support**: Maintain compatibility across SMB protocol versions
- **Security first**: Proper authentication, signing, and encryption implementation
- **Performance focus**: Minimize kernel-userspace transitions for hot paths
- **Standards compliance**: Follow MS-SMB2 and related protocol specifications

### Authentication Flow
1. Protocol negotiation determines authentication capabilities
2. User authentication via netlink to `ksmbd.mountd`
3. Session establishment with appropriate signing/encryption
4. Tree connect for share access with permission validation

### Request Processing Pipeline
1. Connection accepts SMB request
2. Protocol layer parses command
3. Authentication/authorization validation
4. VFS operation execution
5. Response generation and transmission

## Testing and Debugging

### Debug Controls
```bash
# Enable all debug components
sudo ksmbd.control -d "all"

# Enable specific component (smb, auth, vfs, oplock, ipc, conn, rdma)
sudo ksmbd.control -d "smb"

# Check enabled debug components
cat /sys/class/ksmbd-control/debug
```

### Server Management
```bash
# Start ksmbd daemon
sudo ksmbd.mountd

# Stop server
sudo ksmbd.control -s
```

## Security Considerations

### Authentication Security
- **Multi-protocol support**: NTLM, NTLMv2, Kerberos via SPNEGO
- **Pre-authentication integrity**: SMB3.1.1 PAI support
- **Signing enforcement**: Configurable SMB signing requirements
- **Encryption support**: SMB3 encryption (CCM/GCM)

### Access Control
- **Share-based permissions**: Path-based access controls
- **User authentication**: Centralized user account management
- **VFS integration**: Linux permission model compatibility
- **ACL support**: Windows-style ACLs (partial implementation)

## Performance Features

### Optimization Techniques
- **Zero-copy operations**: Direct memory access where possible
- **Asynchronous I/O**: Work queue-based request handling
- **Connection multiplexing**: Multi-channel support
- **Oplock/lease coordination**: Client-side caching optimization
- **RDMA support**: High-performance SMB Direct implementation

### Resource Management
- **Connection limits**: Configurable max connections per IP
- **Request throttling**: Credit-based flow control
- **Memory efficiency**: Reference counting and proper cleanup
- **Work queue balancing**: Dynamic worker thread management