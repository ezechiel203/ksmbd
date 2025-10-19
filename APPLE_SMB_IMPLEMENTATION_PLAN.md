# Apple SMB Extensions Implementation Plan

## Overview
This document outlines the comprehensive implementation plan for adding Apple SMB extensions to KSMBD to enable Time Machine compatibility and improve macOS/iOS client support.

## Current State Analysis

### Existing Apple Detection
- **Location**: `connection.h:118` - `bool is_aapl;` field
- **Detection**: `smb2pdu.c` around line 3200+ - checks for `SMB2_CREATE_AAPL` context
- **Usage**: Currently limited to basic Apple client detection

### Current Implementation Gaps
1. **Limited AAPL context handling** - only detection, no response processing
2. **No readdirattr extensions** - missing bulk directory reading optimizations
3. **No FinderInfo support** - missing Apple metadata handling
4. **No F_FULLFSYNC** - missing Apple-specific sync extension
5. **No Time Machine features** - missing durable handle v2, etc.
6. **No capability advertising** - clients can't discover Apple features

## Implementation Architecture

### 1. Apple Client Detection Enhancement

**Files to modify:**
- `connection.h` - Add Apple-specific capabilities
- `smb2pdu.c` - Enhance detection logic
- `auth.c` - Add user-agent string analysis

**Changes:**
```c
// connection.h additions
struct ksmbd_conn {
    // ... existing fields ...

    // Apple client detection
    bool is_aapl;
    u8 aapl_version;          // macOS/iOS version detection
    bool supports_aapl_ext;   // Full Apple extensions support
    bool supports_tm;         // Time Machine support
    bool supports_readdirattr; // Bulk directory reading

    // Apple capabilities
    u64 aapl_server_caps;     // Server capability flags
    u64 aapl_client_caps;     // Client capability flags
};
```

### 2. AAPL Create Context Handling

**New files:**
- `smb2_aapl.h` - Apple-specific data structures
- `smb2_aapl.c` - Apple context handling functions

**Files to modify:**
- `smb2pdu.h` - Add Apple context structures
- `smb2pdu.c` - Add AAPL context processing
- `oplock.c` - Integrate with create context handling

**Key structures:**
```c
// smb2pdu.h additions
#define SMB2_CREATE_AAPL_SERVER_QUERY    0x00000001
#define SMB2_CREATE_AAPL_CLIENT_QUERY    0x00000002

struct create_aapl_req {
    __le64  capabilities;
    __le32  command;
    __le32  reserved;
    __le64  flags;
};

struct create_aapl_rsp {
    __le64  capabilities;
    __le32  command;
    __le32  reserved;
    __le64  flags;
};

// Apple capability flags
#define AAPL_SUPPORTS_UNIX_BASED        0x0000000000000001
#define AAPL_SUPPORTS_FULL_SYNC         0x0000000000000004
#define AAPL_SUPPORTS_READDIR_ATTR      0x0000000000000020
#define AAPL_SUPPORTS_TIME_MACHINE      0x0000000000000040
```

### 3. readdirattr Extensions Implementation

**New files:**
- `smb2_readdirattr.h` - readdirattr data structures
- `smb2_readdirattr.c` - readdirattr implementation

**Files to modify:**
- `smb2pdu.c` - Add readdirattr handling in QUERY_DIRECTORY
- `vfs.c` - Add VFS operations for bulk attribute reading
- `vfs.h` - Add readdirattr VFS interfaces

**Key functions:**
```c
// smb2_readdirattr.c
int smb2_read_dir_attr(struct ksmbd_work *work);
int smb2_encode_finder_info(struct ksmbd_file *fp, char *buf, int *buflen);
int smb2_get_unix_perms(struct ksmbd_file *fp, char *buf, int *buflen);
```

### 4. FinderInfo and Resource Fork Support

**New files:**
- `smb2_finderinfo.h` - FinderInfo data structures
- `smb2_finderinfo.c` - FinderInfo handling

**Files to modify:**
- `vfs.c` - Add extended attribute handling for Apple metadata
- `vfs.h` - Add Apple metadata VFS interfaces
- `smb2pdu.c` - Integrate FinderInfo in file operations

**Key structures:**
```c
// smb2_finderinfo.h
struct AFPInfo {
    __le32  magic;          // 0x41444942 ("ADIB")
    __le32  version;
    __be32  finder_info[8]; // 32 bytes of Finder info
    __le32  reserved;
    __le16  comment_id;
    __le16  comment_length;
};

struct AFPResourceStream {
    __le32  magic;          // 0x4150504c ("APPL")
    __le32  version;
    __le64  resource_size;
    __le64  data_size;
};
```

### 5. F_FULLFSYNC Extension

**Files to modify:**
- `smb2pdu.c` - Modify `smb2_flush()` function
- `smb2pdu.h` - Add F_FULLFSYNC structures
- `vfs.c` - Add full sync VFS operation

**Implementation:**
```c
// smb2pdu.c modification in smb2_flush()
int smb2_flush(struct ksmbd_work *work)
{
    struct smb2_flush_req *req;
    struct smb2_flush_rsp *rsp;
    int err;

    WORK_BUFFERS(work, req, rsp);

    // Check for Apple F_FULLFSYNC
    if (work->conn->is_aapl && req->Reserved1 == 0xFFFF) {
        ksmbd_debug(SMB, "Apple F_FULLFSYNC request\n");
        err = ksmbd_vfs_full_sync(work, req->VolatileFileId, req->PersistentFileId);
    } else {
        err = ksmbd_vfs_fsync(work, req->VolatileFileId, req->PersistentFileId);
    }

    // ... rest of function
}
```

### 6. Time Machine Specific Functionality

**Files to modify:**
- `smb2pdu.c` - Add Time Machine create contexts
- `oplock.c` - Add durable handle v2 support for TM
- `vfs.c` - Add TM-specific file operations

**Key features:**
- `.com.apple.timemachine.supported` file creation
- Durable handle v2 with timeout=0
- Compound CREATE/SET_INFO/CLOSE requests
- Enhanced oplock support for TM operations

### 7. Capability Advertising

**Files to modify:**
- `smb2pdu.c` - Add capability negotiation
- `connection.c` - Initialize Apple capabilities
- `server.c` - Add server configuration for Apple features

## Implementation Steps

### Phase 1: Foundation (Week 1-2)
1. **Create Apple-specific headers** - `smb2_aapl.h`, `smb2_finderinfo.h`
2. **Enhance connection structure** - Add Apple capability fields
3. **Improve client detection** - Version detection, capability negotiation
4. **Basic AAPL context handling** - Query/response processing

### Phase 2: Core Features (Week 3-4)
1. **readdirattr implementation** - Bulk directory reading
2. **FinderInfo support** - Basic metadata handling
3. **F_FULLFSYNC extension** - Apple-specific sync
4. **Extended attribute support** - Apple metadata storage

### Phase 3: Time Machine (Week 5-6)
1. **Durable handle v2** - Enhanced for TM operations
2. **TM validation sequence** - Complete Apple TM protocol
3. **Compound request support** - CREATE/SET_INFO/CLOSE
4. **Enhanced oplock handling** - TM-specific optimizations

### Phase 4: Testing & Validation (Week 7-8)
1. **Comprehensive testing** - macOS/iOS client testing
2. **Performance validation** - Directory traversal benchmarks
3. **Time Machine testing** - Backup/restore validation
4. **Compatibility testing** - Multiple macOS versions

## Files to Create

### New Header Files
1. `smb2_aapl.h` - Apple SMB extensions definitions
2. `smb2_finderinfo.h` - FinderInfo data structures
3. `smb2_readdirattr.h` - readdirattr extensions

### New Source Files
1. `smb2_aapl.c` - Apple context handling
2. `smb2_finderinfo.c` - FinderInfo operations
3. `smb2_readdirattr.c` - readdirattr implementation

## Files to Modify

### Core Protocol Files
1. `smb2pdu.h` - Add Apple data structures, extend existing ones
2. `smb2pdu.c` - Integrate Apple features in protocol handling
3. `oplock.c` - Enhance create context handling for AAPL
4. `smb2ops.c` - Add Apple operation dispatch

### Connection & Session Files
1. `connection.h` - Add Apple capability fields
2. `connection.c` - Initialize Apple capabilities
3. `mgmt/user_session.c` - Propagate Apple capabilities to sessions

### VFS Layer Files
1. `vfs.h` - Add Apple metadata VFS interfaces
2. `vfs.c` - Implement Apple metadata operations
3. `vfs_cache.c` - Cache Apple metadata for performance

### Build System
1. `Makefile` - Add new Apple-specific source files

## Key Constants and Values

### Apple Create Context Tags
```c
#define SMB2_CREATE_AAPL               "AAPL"
#define SMB2_CREATE_AAPL_SERVER_QUERY  0x00000001
#define SMB2_CREATE_AAPL_CLIENT_QUERY  0x00000002
```

### Apple Capability Flags
```c
#define AAPL_SUPPORTS_UNIX_BASED       0x0000000000000001
#define AAPL_SUPPORTS_FULL_SYNC        0x0000000000000004
#define AAPL_SUPPORTS_READDIR_ATTR     0x0000000000000020
#define AAPL_SUPPORTS_TIME_MACHINE     0x0000000000000040
```

### FinderInfo Constants
```c
#define AFP_INFO_MAGIC                 0x41444942
#define AFP_RESOURCE_MAGIC             0x4150504c
#define AFP_INFO_SIZE                  60
```

### F_FULLFSYNC Constants
```c
#define SMB2_FLUSH_RESERVED_FULL_SYNC  0xFFFF
```

## Testing Strategy

### Unit Testing
1. **Apple context parsing** - Test AAPL create context handling
2. **FinderInfo operations** - Test metadata read/write
3. **readdirattr functionality** - Test bulk directory reading

### Integration Testing
1. **macOS client compatibility** - Test with various macOS versions
2. **Time Machine operations** - Test backup/restore workflows
3. **Performance validation** - Compare directory traversal speeds

### Compatibility Testing
1. **Multiple Apple OS versions** - macOS 10.15+, iOS 13+
2. **Network conditions** - Test over different network types
3. **Concurrent operations** - Test multiple Apple clients

## Performance Expectations

Based on the GitHub issue, expected improvements:
- **Directory traversal**: 28 seconds → 2 seconds (14x improvement)
- **Time Machine compatibility**: Full support for backup/restore
- **Finder operations**: Native macOS Finder integration

## Security Considerations

1. **Input validation** - Validate all Apple-specific inputs
2. **Resource limits** - Prevent abuse of bulk operations
3. **Access control** - Ensure Apple features respect share permissions
4. **Memory safety** - Proper bounds checking for Apple metadata

## Backward Compatibility

1. **Feature detection** - Only enable Apple features for Apple clients
2. **Graceful degradation** - Fall back to standard SMB for non-Apple clients
3. **Configuration options** - Allow disabling Apple features if needed

## Documentation Updates

1. **README.md** - Document Apple SMB extensions
2. **CLAUDE.md** - Update development guidance
3. **ksmbd.rst** - Add Apple features documentation
4. **Man pages** - Document Apple-specific configuration options

This implementation plan provides a comprehensive roadmap for adding Apple SMB extensions to KSMBD, enabling Time Machine compatibility and significantly improving performance for Apple clients.