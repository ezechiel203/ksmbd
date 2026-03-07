# SMB1 Protocol Compliance Upgrade Plan
## NT_TRANSACT, Locking, Oplocks, Cancel, Echo, and Attribute Commands

**Repository:** `/home/ezechiel203/ksmbd`
**Branch:** `phase1-security-hardening`
**Primary files analyzed:**
- `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1pdu.c`
- `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1ops.c`
- `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1misc.c`
- `/home/ezechiel203/ksmbd/src/include/protocol/smb1pdu.h`
- `/home/ezechiel203/ksmbd/src/fs/oplock.c`

---

## Executive Summary

The following MS-SMB protocol areas require work to reach full compliance. The items are ordered by criticality: the NT_TRANSACT dispatcher (0xA0) is the most impactful missing piece because eight subcommands are completely unreachable. Locking has a partial but correct implementation with three known gaps. Oplock break machinery is present but disabled. The remaining items are behavioral gaps or missing secondary commands.

---

## 1. SMB_COM_NT_TRANSACT (0xA0) — Dispatcher Completely Missing

### Current State

The dispatch table in `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1ops.c` has **no entry** for `SMB_COM_NT_TRANSACT` at line 49–78. The constant `SMB_COM_NT_TRANSACT = 0xA0` is defined in `smb1pdu.h` (line 149), and the eight subcommand codes `NT_TRANSACT_CREATE` through `NT_TRANSACT_SET_USER_QUOTA` are defined (lines 78–85), but there is no handler function and no dispatch function in `smb1pdu.c`.

The `smb1misc.c` message validator (`smb1_req_struct_size`, line 116 default case) returns `-EOPNOTSUPP` for `SMB_COM_NT_TRANSACT`, which causes `ksmbd_smb1_check_message()` to log "Not support cmd 0xa0" and drop the packet silently. The client receives no error response — a protocol violation that causes hangs in real clients.

**Impact:** Windows clients using NT_TRANSACT for security descriptor access (e.g., Explorer right-click → Properties → Security) will hang or fail. Applications using `NtCreateFile` with an initial security descriptor also fail. Change notification via SMB1 is entirely unavailable.

### Required Changes

#### 1.1 Wire Up the Dispatcher

**File:** `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1ops.c`

Add to `smb1_server_cmds[]`:
```c
[SMB_COM_NT_TRANSACT]           = { .proc = smb_nt_transact, },
[SMB_COM_NT_TRANSACT_SECONDARY] = { .proc = smb_nt_transact_secondary, },
```

**File:** `/home/ezechiel203/ksmbd/src/protocol/smb1/smb1misc.c`

Add to `smb1_req_struct_size()` switch statement. Per MS-SMB §2.2.4.62.1, the request WordCount is 19 (0x13) for NT_TRANSACT and 18 (0x12) for NT_TRANSACT_SECONDARY:
```c
case SMB_COM_NT_TRANSACT:
    if (wc != 0x13)
        return -EINVAL;
    break;
case SMB_COM_NT_TRANSACT_SECONDARY:
    if (wc != 0x12)
        return -EINVAL;
    break;
```

Add to `smb1_get_byte_count()`: NT_TRANSACT ByteCount is variable (>= 0). The data spans from `DataOffset` to `DataOffset + DataCount`, so add to `smb1_get_data_len()` a case similar to the TRANSACTION2 case.

#### 1.2 Wire Up NT_TRANSACT Structures in smb1pdu.h

The following structures are **missing from** `/home/ezechiel203/ksmbd/src/include/protocol/smb1pdu.h` and must be added:

```c
/*
 * SMB_COM_NT_TRANSACT request — MS-SMB §2.2.4.62.1
 * WordCount = 19 (0x13)
 */
struct smb_com_ntransact_req {
    struct smb_hdr hdr;         /* wct = 19 */
    __u8  MaxSetupCount;
    __u8  Reserved[2];
    __le32 TotalParameterCount;
    __le32 TotalDataCount;
    __le32 MaxParameterCount;
    __le32 MaxDataCount;
    __le32 ParameterCount;
    __le32 ParameterOffset;
    __le32 DataCount;
    __le32 DataOffset;
    __u8  SetupCount;
    __u8  Reserved2;
    __le16 Function;            /* NT_TRANSACT_* subcommand */
    /* Setup[] follows: variable, SetupCount WORDs */
    __le16 ByteCount;
    /* Pad + Parameters + Data follow */
} __packed;

/*
 * SMB_COM_NT_TRANSACT response — MS-SMB §2.2.4.62.2
 * WordCount = 18 (0x12)
 */
struct smb_com_ntransact_rsp {
    struct smb_hdr hdr;         /* wct = 18 */
    __u8  Reserved[3];
    __le32 TotalParameterCount;
    __le32 TotalDataCount;
    __le32 ParameterCount;
    __le32 ParameterOffset;
    __le32 ParameterDisplacement;
    __le32 DataCount;
    __le32 DataOffset;
    __le32 DataDisplacement;
    __u8  SetupCount;
    __le16 ByteCount;
    /* Pad + Parameters + Data follow */
} __packed;

/*
 * SMB_COM_NT_TRANSACT_SECONDARY request — MS-SMB §2.2.4.63.1
 * WordCount = 18 (0x12)
 */
struct smb_com_ntransact_secondary_req {
    struct smb_hdr hdr;         /* wct = 18 */
    __u8  Reserved[3];
    __le32 TotalParameterCount;
    __le32 TotalDataCount;
    __le32 ParameterCount;
    __le32 ParameterOffset;
    __le32 ParameterDisplacement;
    __le32 DataCount;
    __le32 DataOffset;
    __le32 DataDisplacement;
    __u8  FunctionCode;         /* must match original Function */
    __le16 ByteCount;
} __packed;
```

#### 1.3 NT_TRANSACT top-level Dispatcher in smb1pdu.c

The dispatcher must:
1. Parse the `Function` field from the NT_TRANSACT header.
2. Handle multi-part requests (NT_TRANSACT_SECONDARY reassembly, same as TRANSACTION2_SECONDARY). For the initial phase, reject SECONDARY with STATUS_NOT_SUPPORTED — correct handling requires the same reassembly buffer mechanism used by `smb_trans2()`.
3. Route to per-subcommand handlers.
4. Handle the `SetupCount` validation — for most subcommands it is 0.

```c
int smb_nt_transact(struct ksmbd_work *work)
{
    struct smb_com_ntransact_req *req = work->request_buf;
    struct smb_hdr *rsp_hdr = work->response_buf;
    u16 function;
    int err;

    /* SetupCount must be 0 for all standard NT_TRANSACT subcommands */
    if (req->SetupCount > 0) {
        rsp_hdr->Status.CifsError = STATUS_INVALID_PARAMETER;
        return -EINVAL;
    }

    function = le16_to_cpu(req->Function);
    ksmbd_debug(SMB, "NT_TRANSACT subcommand 0x%x\n", function);

    switch (function) {
    case NT_TRANSACT_CREATE:
        err = smb_nt_transact_create(work);
        break;
    case NT_TRANSACT_IOCTL:
        err = smb_nt_transact_ioctl(work);
        break;
    case NT_TRANSACT_SET_SECURITY_DESC:
        err = smb_nt_transact_set_security_desc(work);
        break;
    case NT_TRANSACT_NOTIFY_CHANGE:
        err = smb_nt_transact_notify_change(work);
        break;
    case NT_TRANSACT_RENAME:
        err = smb_nt_transact_rename(work);
        break;
    case NT_TRANSACT_QUERY_SECURITY_DESC:
        err = smb_nt_transact_query_security_desc(work);
        break;
    case NT_TRANSACT_GET_USER_QUOTA:
        err = smb_nt_transact_get_user_quota(work);
        break;
    case NT_TRANSACT_SET_USER_QUOTA:
        err = smb_nt_transact_set_user_quota(work);
        break;
    default:
        pr_err("NT_TRANSACT subcommand 0x%x not supported\n", function);
        rsp_hdr->Status.CifsError = STATUS_NOT_SUPPORTED;
        return -EOPNOTSUPP;
    }

    /* Map errno to NTSTATUS */
    if (err) {
        if (!rsp_hdr->Status.CifsError)
            set_smb_rsp_status(work, map_errno_to_ntstatus(err));
    }
    return err;
}

int smb_nt_transact_secondary(struct ksmbd_work *work)
{
    struct smb_hdr *rsp_hdr = work->response_buf;
    /*
     * MS-SMB §2.2.4.63: NT_TRANSACT_SECONDARY is sent when the
     * original NT_TRANSACT did not fit in one packet.  KSMBD does
     * not currently implement reassembly for this.  Return an error
     * so the client knows to retry differently.
     */
    rsp_hdr->Status.CifsError = STATUS_NOT_SUPPORTED;
    return -EOPNOTSUPP;
}
```

---

### 1.4 NT_TRANSACT_CREATE (0x0001)

**Spec:** MS-SMB §2.2.4.62.5 / §2.2.4.62.6

This is a superset of `SMB_COM_NT_CREATE_ANDX` that additionally accepts:
- An initial **SecurityDescriptor** (SD) embedded in the Parameters buffer.
- An initial **Extended Attributes** (EA) list in the Data buffer.
- `SDLength`: byte count of the security descriptor.
- `EALength`: byte count of the EA list.
- All other parameters identical to NT_CREATE_ANDX: `OpLockLevel`, `RootDirectoryFid`, `CreateOptions`, `CreateDisposition`, `DesiredAccess`, `AllocationSize`, `FileAttributes`, `ShareAccess`, `ImpersonationLevel`, `SecurityFlags`.

**Parameter buffer layout (NT_TRANSACT_CREATE_REQ_PARAMS):**
```
Offset  Size  Field
0       4     OpLockLevel (DWORD, not byte — full flags)
4       4     RootDirectoryFid
8       4     CreateDisposition
12      4     ImpersonationLevel
16      4     SecurityFlags
20      4     DesiredAccess
24      4     AllocationSizeLow
28      4     AllocationSizeHigh
32      4     FileAttributes
36      4     ShareAccess
40      4     CreateOptions
44      4     SDLength
48      4     EALength
52      4     NameLength
56      1     SecurityFlags (byte)
57      N     Name (Unicode if Flags2 bit set)
```

**Data buffer layout:**
```
Offset  Size  Field
0       SDLength  SecurityDescriptor (SECURITY_DESCRIPTOR)
SDLength  EALength  EaList (FILE_FULL_EA_INFORMATION[])
```

**Implementation Strategy:**

The function `smb_nt_create_andx()` already exists and handles the core file-open path. `smb_nt_transact_create()` should:

1. Parse the Parameters buffer from the NT_TRANSACT envelope (at `req->ParameterOffset` bytes from the start of the SMB header).
2. Validate that `ParameterCount >= 57` (minimum without name) and that `DataCount >= SDLength + EALength`.
3. Call the same VFS open path used by `smb_nt_create_andx()`.
4. After successful open, if `SDLength > 0`, call `ksmbd_vfs_set_sd_xattr()` (already implemented in `vfs.c:2676`) to apply the initial security descriptor using the same path used by SMB2 CREATE with security context.
5. If `EALength > 0`, validate and apply the EA list via `ksmbd_vfs_setxattr()`.
6. Build the NT_TRANSACT response in the standard envelope. The Parameters buffer of the response is identical to the `smb_com_open_rsp` fields (OplockLevel, Fid, CreateAction, times, attributes, sizes, FileType, DeviceState, DirectoryFlag).

**Response Parameters buffer layout (NT_TRANSACT_CREATE_RSP_PARAMS):**
```
Offset  Size  Field
0       1     OplockLevel
1       1     Reserved
2       2     Fid
4       4     CreateAction
8       8     CreationTime
16      8     LastAccessTime
24      8     LastWriteTime
32      8     ChangeTime
40      4     FileAttributes
44      8     AllocationSize
52      8     EndOfFile
60      2     FileType
62      2     DeviceState
64      1     DirectoryFlag
```

**Missing structures to add to smb1pdu.h:**
```c
struct nt_transact_create_req_params {
    __le32 OplockLevel;
    __le32 RootDirectoryFid;
    __le32 CreateDisposition;
    __le32 ImpersonationLevel;
    __le32 SecurityFlags;
    __le32 DesiredAccess;
    __le32 AllocationSizeLow;
    __le32 AllocationSizeHigh;
    __le32 FileAttributes;
    __le32 ShareAccess;
    __le32 CreateOptions;
    __le32 SDLength;
    __le32 EALength;
    __le32 NameLength;
    __u8   SecurityFlags2;
    /* Name follows (NameLength bytes) */
} __packed;

struct nt_transact_create_rsp_params {
    __u8   OplockLevel;
    __u8   Reserved;
    __le16 Fid;
    __le32 CreateAction;
    __le64 CreationTime;
    __le64 LastAccessTime;
    __le64 LastWriteTime;
    __le64 ChangeTime;
    __le32 FileAttributes;
    __le64 AllocationSize;
    __le64 EndOfFile;
    __le16 FileType;
    __le16 DeviceState;
    __u8   DirectoryFlag;
} __packed;
```

---

### 1.5 NT_TRANSACT_IOCTL (0x0002)

**Spec:** MS-SMB §2.2.4.62.9 / §2.2.4.62.10

**Parameters buffer layout:**
```
Offset  Size  Field
0       4     FunctionCode  (FSCTL code)
4       2     Fid
6       1     IsFsctl       (1 = FSCTL, 0 = IOCTL)
7       1     IsFlags       (0x01 = root directory flag)
```

**Data buffer:** Input data passed to the FSCTL/IOCTL.

**Implementation Strategy:**

This maps directly to the SMB2 IOCTL infrastructure that already exists. The `ksmbd_dispatch_fsctl()` function in `/home/ezechiel203/ksmbd/src/include/fs/ksmbd_fsctl.h` provides a registered handler dispatch table.

```c
int smb_nt_transact_ioctl(struct ksmbd_work *work)
{
    struct smb_com_ntransact_req *req = work->request_buf;
    char *params;
    u32 function_code;
    u16 fid;
    u8  is_fsctl;
    struct ksmbd_file *fp;
    unsigned int out_len = 0;
    int err;

    if (le32_to_cpu(req->ParameterCount) < 8) {
        rsp->Status.CifsError = STATUS_INVALID_PARAMETER;
        return -EINVAL;
    }

    params = (char *)req + le32_to_cpu(req->ParameterOffset);
    function_code = get_unaligned_le32(params);
    fid = get_unaligned_le16(params + 4);
    is_fsctl = params[6];

    fp = ksmbd_lookup_fd_fast(work, fid);
    if (!fp)
        return -ENOENT;

    if (is_fsctl) {
        /* Route through the same FSCTL dispatch table used by SMB2 */
        err = ksmbd_dispatch_fsctl(work, function_code,
                                   fp->volatile_id,
                                   /* in_buf */ ...,
                                   /* in_buf_len */ ...,
                                   /* max_out_len */ ...,
                                   /* rsp */ ...,
                                   &out_len);
    } else {
        /* Generic IOCTL: currently not supported */
        err = -EOPNOTSUPP;
    }

    ksmbd_fd_put(work, fp);

    /* Build NT_TRANSACT response envelope around the FSCTL output */
    ...
}
```

**Supported FSCTLs** (already implemented in `smb2_ioctl.c` at the indicated lines):
- `FSCTL_SET_SPARSE` (line 588): sparse file flag.
- `FSCTL_SET_ZERO_DATA` (line 599): zero range.
- `FSCTL_QUERY_ALLOCATED_RANGES` (line 649): query sparse ranges.

**FSCTLs that need SMB1 wrapping** (the SMB2 logic exists, just needs adapter):
- `FSCTL_GET_COMPRESSION` / `FSCTL_SET_COMPRESSION`: return STATUS_NOT_SUPPORTED for Linux (no kernel NTFS compression via VFS). Must return a well-formed response with `CompressionFormat = COMPRESSION_FORMAT_NONE` for GET.
- `FSCTL_SET_COMPRESSION`: accept and silently succeed (no-op) or return STATUS_NOT_SUPPORTED.

**Adapter note:** The SMB2 IOCTL handler builds a `smb2_ioctl_rsp` directly. The NT_TRANSACT handler must instead place the FSCTL output data into the NT_TRANSACT Data buffer in the NT_TRANSACT response envelope. The handler must allocate a temporary buffer, run the FSCTL logic, then serialise the result into the NT_TRANSACT response.

---

### 1.6 NT_TRANSACT_SET_SECURITY_DESC (0x0003)

**Spec:** MS-SMB §2.2.4.62.11 / §2.2.4.62.12

**Parameters buffer layout:**
```
Offset  Size  Field
0       2     Fid
2       2     Reserved
4       4     SecurityInformation  (bit flags below)
```

**SecurityInformation flags (MS-DTYP §2.4.7):**
```c
#define OWNER_SECURITY_INFORMATION  0x00000001
#define GROUP_SECURITY_INFORMATION  0x00000002
#define DACL_SECURITY_INFORMATION   0x00000004
#define SACL_SECURITY_INFORMATION   0x00000008
#define LABEL_SECURITY_INFORMATION  0x00000010
#define ATTRIBUTE_SECURITY_INFORMATION 0x00000020
#define SCOPE_SECURITY_INFORMATION  0x00000040
#define PROCESS_TRUST_LABEL_SECURITY_INFORMATION 0x00000080
#define BACKUP_SECURITY_INFORMATION 0x00010000
#define PROTECTED_DACL_SECURITY_INFORMATION 0x80000000
#define UNPROTECTED_DACL_SECURITY_INFORMATION 0x20000000
#define PROTECTED_SACL_SECURITY_INFORMATION  0x40000000
#define UNPROTECTED_SACL_SECURITY_INFORMATION 0x10000000
```

**Data buffer:** The SECURITY_DESCRIPTOR structure.

**Implementation Strategy:**

The VFS infrastructure already exists:
- `ksmbd_vfs_set_sd_xattr()` at `vfs.c:2676`
- `smb_check_perm_dacl()` in `smbacl.c`
- The SMB2 equivalent is `smb2_set_info()` with `SMB2_O_INFO_SECURITY` info type, processed in `smb2_query_set.c`.

```c
int smb_nt_transact_set_security_desc(struct ksmbd_work *work)
{
    struct smb_com_ntransact_req *req = work->request_buf;
    char *params, *data;
    u16 fid;
    u32 security_info;
    struct smb_ntsd *pntsd;
    unsigned int pntsd_size;
    struct ksmbd_file *fp;
    struct path path;
    int err;

    params = (char *)req + le32_to_cpu(req->ParameterOffset);
    fid = get_unaligned_le16(params);
    security_info = get_unaligned_le32(params + 4);

    fp = ksmbd_lookup_fd_fast(work, fid);
    if (!fp)
        return -EBADF;

    pntsd = (struct smb_ntsd *)((char *)req +
                                le32_to_cpu(req->DataOffset));
    pntsd_size = le32_to_cpu(req->DataCount);

    /*
     * Validate the SD. Must be at least sizeof(struct smb_ntsd).
     * smb_check_perm_dacl() validates the DACL structure.
     */
    if (pntsd_size < sizeof(struct smb_ntsd)) {
        ksmbd_fd_put(work, fp);
        return -EINVAL;
    }

    /*
     * Access check: setting DACL/OWNER/GROUP requires WRITE_DAC /
     * WRITE_OWNER on the handle. SACL requires SE_SECURITY privilege.
     */
    if ((security_info & DACL_SECURITY_INFORMATION) &&
        !(fp->daccess & (WRITE_DAC | GENERIC_ALL | GENERIC_WRITE))) {
        ksmbd_fd_put(work, fp);
        return -EACCES;
    }
    if ((security_info & (OWNER_SECURITY_INFORMATION |
                          GROUP_SECURITY_INFORMATION)) &&
        !(fp->daccess & (WRITE_OWNER | GENERIC_ALL))) {
        ksmbd_fd_put(work, fp);
        return -EACCES;
    }

    path.dentry = fp->filp->f_path.dentry;
    path.mnt    = fp->filp->f_path.mnt;

    err = ksmbd_vfs_set_sd_xattr(work->conn,
                                  mnt_idmap(path.mnt),
                                  path.dentry,
                                  pntsd, pntsd_size, false);

    ksmbd_fd_put(work, fp);

    if (!err) {
        /* Response: NT_TRANSACT with no parameters, no data */
        build_nt_transact_success_rsp(work, 0, 0);
    }
    return err;
}
```

---

### 1.7 NT_TRANSACT_NOTIFY_CHANGE (0x0004)

**Spec:** MS-SMB §2.2.4.62.13 / §2.2.4.62.14

**Parameters buffer layout:**
```
Offset  Size  Field
0       4     CompletionFilter (FILE_NOTIFY_CHANGE_* flags)
4       2     Fid
6       1     WatchTree (0 = this dir only, 1 = recursive)
7       1     Reserved
```

**CompletionFilter flags:**
```c
#define FILE_NOTIFY_CHANGE_FILE_NAME    0x00000001
#define FILE_NOTIFY_CHANGE_DIR_NAME     0x00000002
#define FILE_NOTIFY_CHANGE_ATTRIBUTES   0x00000004
#define FILE_NOTIFY_CHANGE_SIZE         0x00000008
#define FILE_NOTIFY_CHANGE_LAST_WRITE   0x00000010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS  0x00000020
#define FILE_NOTIFY_CHANGE_CREATION     0x00000040
#define FILE_NOTIFY_CHANGE_EA           0x00000080
#define FILE_NOTIFY_CHANGE_SECURITY     0x00000100
#define FILE_NOTIFY_CHANGE_STREAM_NAME  0x00000200
#define FILE_NOTIFY_CHANGE_STREAM_SIZE  0x00000400
#define FILE_NOTIFY_CHANGE_STREAM_WRITE 0x00000800
```

**Response:** Asynchronous. The server returns no immediate response. When a filesystem event matching the filter occurs, the server sends an NT_TRANSACT response (with the original MID) containing `FILE_NOTIFY_INFORMATION` entries in the Data buffer.

**FILE_NOTIFY_INFORMATION structure:**
```c
struct file_notify_information {
    __le32 NextEntryOffset;  /* 0 if last entry */
    __le32 Action;           /* FILE_ACTION_* */
    __le32 FileNameLength;
    __le16 FileName[1];      /* Unicode, relative path */
} __packed;

/* Action values */
#define FILE_ACTION_ADDED              0x00000001
#define FILE_ACTION_REMOVED            0x00000002
#define FILE_ACTION_MODIFIED           0x00000003
#define FILE_ACTION_RENAMED_OLD_NAME   0x00000004
#define FILE_ACTION_RENAMED_NEW_NAME   0x00000005
```

**Implementation Strategy:**

The SMB2 change notify infrastructure is already implemented in `ksmbd_notify.c` using Linux fsnotify. The key insight is that the SMB1 NT_TRANSACT_NOTIFY_CHANGE path can reuse this infrastructure. The differences from SMB2 are only in the wire format of the request and response.

```c
int smb_nt_transact_notify_change(struct ksmbd_work *work)
{
    struct smb_com_ntransact_req *req = work->request_buf;
    char *params;
    u32 completion_filter;
    u16 fid;
    u8  watch_tree;
    struct ksmbd_file *fp;

    params = (char *)req + le32_to_cpu(req->ParameterOffset);
    completion_filter = get_unaligned_le32(params);
    fid = get_unaligned_le16(params + 4);
    watch_tree = params[6];

    fp = ksmbd_lookup_fd_fast(work, fid);
    if (!fp)
        return -EBADF;

    if (!S_ISDIR(file_inode(fp->filp)->i_mode)) {
        ksmbd_fd_put(work, fp);
        rsp->Status.CifsError = STATUS_INVALID_PARAMETER;
        return -EINVAL;
    }

    /*
     * Mark the work as async (no immediate response).
     * ksmbd_notify_watch() from ksmbd_notify.c registers a fsnotify
     * mark and stores the work struct for completion when an event fires.
     * For SMB1 the completion callback must build an NT_TRANSACT rsp
     * (not SMB2) using the MID from the original request header.
     */
    work->send_no_response = 1;
    return ksmbd_smb1_notify_watch(work, fp, completion_filter,
                                   watch_tree);
}
```

**Note:** `ksmbd_smb1_notify_watch()` does not yet exist. It needs to be added to `ksmbd_notify.c`, mirroring the SMB2 watch registration but with an SMB1 response builder. The completion path in `__smb1_oplock_break_noti` provides a template for sending unsolicited SMB1 frames.

**SMB_COM_NT_CANCEL interaction:** When the client cancels a pending NOTIFY_CHANGE (see section 3), `smb_nt_cancel()` must also cancel queued fsnotify watches. The current `smb_nt_cancel()` implementation (line 8183) sets `send_no_response = 1` and removes the work from `conn->requests` but does NOT call the fsnotify teardown. This must be extended to call `ksmbd_notify_cancel(work)`.

---

### 1.8 NT_TRANSACT_RENAME (0x0005)

**Spec:** MS-SMB §2.2.4.62.15 / §2.2.4.62.16

**Parameters buffer layout:**
```
Offset  Size  Field
0       2     Fid             (open file handle to rename)
2       2     Flags
4       N     NewName         (Unicode if Flags2 set)
```

**Flags:**
```c
#define NT_RENAME_REPLACE_IF_EXISTS  0x0001
```

This differs from `SMB_COM_RENAME` (path-based) and `SMB_COM_NT_RENAME` (hard link, `0xA5`). NT_TRANSACT_RENAME renames by open FID, bypassing path lookup entirely — it is equivalent to setting `FileRenameInformation` via `TRANS2_SET_FILE_INFORMATION`.

**Implementation Strategy:**

```c
int smb_nt_transact_rename(struct ksmbd_work *work)
{
    struct smb_com_ntransact_req *req = work->request_buf;
    char *params;
    u16 fid, flags;
    char *new_name;
    size_t new_name_len;
    struct ksmbd_file *fp;
    int err, replace;

    params = (char *)req + le32_to_cpu(req->ParameterOffset);
    fid   = get_unaligned_le16(params);
    flags = get_unaligned_le16(params + 2);
    replace = !!(flags & NT_RENAME_REPLACE_IF_EXISTS);

    fp = ksmbd_lookup_fd_fast(work, fid);
    if (!fp)
        return -EBADF;

    /* NewName immediately follows flags at offset 4 */
    if (is_smbreq_unicode(&req->hdr)) {
        new_name = smb_strndup_from_utf16(params + 4,
                                           le32_to_cpu(req->ParameterCount) - 4,
                                           true,
                                           work->conn->local_nls);
    } else {
        new_name = kstrndup(params + 4,
                            le32_to_cpu(req->ParameterCount) - 4,
                            KSMBD_DEFAULT_GFP);
    }

    if (IS_ERR_OR_NULL(new_name)) {
        ksmbd_fd_put(work, fp);
        return -ENOMEM;
    }

    /*
     * ksmbd_vfs_fp_rename() does not yet exist as a named function,
     * but ksmbd_vfs_rename() handles the path case.  The FID case
     * can be served by constructing the full target path from
     * work->tcon->share_conf->path + new_name and calling
     * ksmbd_vfs_rename(). The source dentry is fp->filp->f_path.dentry.
     */
    err = ksmbd_vfs_rename_by_dentry(work, fp->filp->f_path.dentry,
                                     new_name, replace);

    kfree(new_name);
    ksmbd_fd_put(work, fp);

    if (!err)
        build_nt_transact_success_rsp(work, 0, 0);
    return err;
}
```

**Required VFS helper:** A new function `ksmbd_vfs_rename_by_dentry(work, old_dentry, new_name, replace)` that resolves the target path relative to the share root and calls `vfs_rename()`. This function should be added to `vfs.c`.

---

### 1.9 NT_TRANSACT_QUERY_SECURITY_DESC (0x0006)

**Spec:** MS-SMB §2.2.4.62.17 / §2.2.4.62.18

**Parameters buffer layout:**
```
Offset  Size  Field
0       2     Fid
2       2     Reserved
4       4     SecurityInformation
```

**Response:**
- If the buffer is large enough: Parameters contains `LengthNeeded` (4 bytes), Data contains the SECURITY_DESCRIPTOR.
- If the buffer is too small: `STATUS_BUFFER_TOO_SMALL`, Parameters contains `LengthNeeded`, no Data.

**Implementation Strategy:**

```c
int smb_nt_transact_query_security_desc(struct ksmbd_work *work)
{
    struct smb_com_ntransact_req *req = work->request_buf;
    char *params;
    u16 fid;
    u32 security_info;
    struct ksmbd_file *fp;
    struct smb_ntsd *pntsd = NULL;
    unsigned int pntsd_size;
    u32 max_data = le32_to_cpu(req->MaxDataCount);
    int err;

    params = (char *)req + le32_to_cpu(req->ParameterOffset);
    fid = get_unaligned_le16(params);
    security_info = get_unaligned_le32(params + 4);

    fp = ksmbd_lookup_fd_fast(work, fid);
    if (!fp)
        return -EBADF;

    /*
     * Access check: reading DACL/OWNER/GROUP requires READ_CONTROL.
     * Reading SACL requires SE_SECURITY privilege.
     */
    if (!(fp->daccess & (READ_CONTROL | GENERIC_ALL | GENERIC_READ))) {
        ksmbd_fd_put(work, fp);
        return -EACCES;
    }

    pntsd_size = ksmbd_vfs_get_sd_xattr(work->conn,
                                         mnt_idmap(fp->filp->f_path.mnt),
                                         fp->filp->f_path.dentry,
                                         &pntsd);

    if (pntsd_size < 0) {
        /*
         * No stored SD: synthesise one from mode bits (same logic
         * as smb2_query_info() SECURITY_INFO path).
         */
        err = smb_build_mode_sd(work->conn,
                                fp->filp->f_path.dentry,
                                security_info,
                                &pntsd, &pntsd_size);
        if (err) {
            ksmbd_fd_put(work, fp);
            return err;
        }
    }

    ksmbd_fd_put(work, fp);

    /* Parameters response: LengthNeeded (4 bytes) */
    if (pntsd_size > max_data) {
        /* MS-SMB §2.2.4.62.18: return STATUS_BUFFER_TOO_SMALL */
        build_nt_transact_error_rsp(work,
                                    STATUS_BUFFER_TOO_SMALL,
                                    pntsd_size);
        kfree(pntsd);
        return 0; /* Not an error at the caller level */
    }

    build_nt_transact_sd_rsp(work, pntsd, pntsd_size);
    kfree(pntsd);
    return 0;
}
```

**Important:** The `STATUS_BUFFER_TOO_SMALL` path is a normal operation, not an error. The client uses it to query the required size before allocating a buffer and retrying. The response must still be sent with `LengthNeeded` in the Parameters buffer.

---

### 1.10 NT_TRANSACT_GET_USER_QUOTA (0x0007)

**Spec:** MS-SMB §2.2.4.62.19 / §2.2.4.62.20

**Parameters buffer layout:**
```
Offset  Size  Field
0       2     Fid
2       1     ReturnSingleEntry
3       1     RestartScan
4       4     SidListLength    (length of SID list in Data buffer)
5       4     StartSidLength   (for restart, length of StartSid)
9       4     StartSidOffset
```

**Data buffer:** List of SIDs to query (when `SidListLength > 0`).

**Response Data:** `FILE_QUOTA_INFORMATION[]` entries.

**Implementation Strategy:**

The quota infrastructure exists in `/home/ezechiel203/ksmbd/src/fs/ksmbd_quota.c`. The function `ksmbd_quota_query()` is designed for the SMB2 InfoType `SMB2_O_INFO_QUOTA` path. For SMB1, the mapping is:

1. Parse the SID list from the Data buffer.
2. For each SID, convert to a Linux UID using `ksmbd_lookup_user_by_sid()`.
3. Call `ksmbd_fill_quota_info()` to get the quota data.
4. Package as `FILE_QUOTA_INFORMATION[]` in the NT_TRANSACT response Data buffer.

If `CONFIG_QUOTA` is not set, return `STATUS_NOT_SUPPORTED`.

---

### 1.11 NT_TRANSACT_SET_USER_QUOTA (0x0008)

**Spec:** MS-SMB §2.2.4.62.21

**Data buffer:** `FILE_QUOTA_INFORMATION[]` entries to set.

**Implementation Strategy:**

Map each entry's SID to a Linux UID, then call `vfs_set_dqblk()` (via the `ksmbd_quota.c` infrastructure). Requires `CONFIG_QUOTA`. If not configured, return `STATUS_NOT_SUPPORTED`.

---

## 2. SMB_COM_LOCKING_ANDX (0x24) — Gaps and Bugs

### Current State

Handler `smb_locking_andx()` is present and registered (`smb1ops.c:58`). The core byte-range locking path is substantially correct. The following specific gaps exist:

### 2.1 LOCKING_ANDX_CANCEL_LOCK — Silently Ignored

**Location:** `smb1pdu.c:1769`

```c
if (req->LockType & LOCKING_ANDX_CANCEL_LOCK)
    pr_err("lock type: LOCKING_ANDX_CANCEL_LOCK\n");
```

**Spec requirement (MS-SMB §2.2.4.26):** When `LOCKING_ANDX_CANCEL_LOCK` is set, the Locks[] array contains lock ranges to cancel. The server must locate any pending (deferred) lock request on the same FID and byte range and cancel it, returning `STATUS_CANCELLED` to the pending lock response. The CANCEL_LOCK request itself succeeds with an empty response.

**Required implementation:**

```c
if (req->LockType & LOCKING_ANDX_CANCEL_LOCK) {
    /*
     * For each range in Locks[], find any pending work item on
     * this connection that is sleeping in ksmbd_vfs_posix_lock_wait_timeout()
     * for an overlapping range on the same FID, and wake it with
     * a cancellation signal.
     *
     * The pending work's response should be STATUS_CANCELLED.
     * The current CANCEL_LOCK request succeeds immediately.
     */
    err = smb_cancel_lock_ranges(work, fp, lock_ele32, lock_ele64,
                                  lock_count);
    /* Fall through: send success response for the CANCEL request */
    goto build_response;
}
```

The function `smb_cancel_lock_ranges()` must walk `work->conn->lock_list` looking for `ksmbd_lock` entries whose `fl->fl_file == filp` and whose range overlaps with the cancel list. It must call `ksmbd_vfs_posix_lock_unblock()` or set a cancellation flag on the waiting work and wake it.

### 2.2 Timeout = -1 Not Handled (Wait Forever)

**Location:** `smb1pdu.c:1918–1929`

**Spec requirement:** `Timeout = 0xFFFFFFFF` (-1 as signed 32-bit) means wait indefinitely. The current code calls `msleep(timeout)` where `timeout` is a positive millisecond value. When `timeout = -1` (0xFFFFFFFF unsigned), this wraps to `msleep(4294967295)` — over 49 days — which is incorrect.

**Current code:**
```c
timeout = le32_to_cpu(req->Timeout);
...
if (timeout) {
    msleep(timeout);
}
```

**Required fix:**

```c
/* MS-SMB §2.2.4.26: Timeout 0 = don't wait, 0xFFFFFFFF = wait forever */
timeout = (s32)le32_to_cpu(req->Timeout);
```

Then the locking path must handle `timeout < 0` (wait forever) by using `ksmbd_vfs_posix_lock_wait()` without a timeout, and `timeout > 0` by using `ksmbd_vfs_posix_lock_wait_timeout(flock, msecs_to_jiffies(timeout))`. The current spin-wait in the `wait:` label uses a 10ms poll loop, which does not honour the timeout at all — it keeps retrying indefinitely until the lock succeeds. This is a functional bug for `Timeout = 0`.

**Required rewrite of the deferred lock path:**

```c
retry:
    err = vfs_lock_file(filp, smb_lock->cmd, flock, NULL);
    if (err == FILE_LOCK_DEFERRED) {
        if (timeout == 0) {
            /* Don't wait — return immediately */
            rsp->hdr.Status.CifsError = STATUS_LOCK_NOT_GRANTED;
            locks_free_lock(flock);
            goto out;
        }
        /* Register for deferred completion */
        spin_lock(&work->conn->llist_lock);
        list_add_tail(&smb_lock->clist, &work->conn->lock_list);
        spin_unlock(&work->conn->llist_lock);
        list_add(&smb_lock->llist, &rollback_list);
        if (timeout > 0) {
            err = ksmbd_vfs_posix_lock_wait_timeout(flock,
                                            msecs_to_jiffies(timeout));
        } else { /* timeout < 0 = wait forever */
            err = wait_event_interruptible(flock->fl_wait,
                                           !flock->fl_blocker);
        }
        if (err) {
            /* Timed out or interrupted */
            rsp->hdr.Status.CifsError = STATUS_FILE_LOCK_CONFLICT;
            goto out;
        }
        goto retry;
    }
```

### 2.3 LOCKING_ANDX_CHANGE_LOCKTYPE — Returns DOS Error Instead of NTSTATUS

**Location:** `smb1pdu.c:1761–1766`

```c
if (req->LockType & LOCKING_ANDX_CHANGE_LOCKTYPE) {
    rsp->hdr.Status.DosError.ErrorClass = ERRDOS;
    rsp->hdr.Status.DosError.Error = cpu_to_le16(ERRnoatomiclocks);
    rsp->hdr.Flags2 &= ~SMBFLG2_ERR_STATUS;
    goto out;
}
```

**Issue:** The response is in DOS error format, but modern clients (NT-style) negotiate NTSTATUS errors via `SMBFLG2_ERR_STATUS` in the negotiated Flags2. If the session was negotiated with `SMBFLG2_ERR_STATUS`, the response should be `STATUS_NOT_SUPPORTED` (or `STATUS_NOT_IMPLEMENTED`) in NTSTATUS format. The code clears the `SMBFLG2_ERR_STATUS` flag, which the server should not modify in a response.

**Required fix:**
```c
if (req->LockType & LOCKING_ANDX_CHANGE_LOCKTYPE) {
    rsp->hdr.Status.CifsError = STATUS_NOT_SUPPORTED;
    goto out;
}
```

### 2.4 Mixed Lock+Unlock Order Not Enforced

**Spec requirement (MS-SMB §2.2.4.26):** When both locks and unlocks are present in the same request, unlocks are processed first, then locks. If an unlock fails, the entire request fails without processing the locks.

**Current code:** Locks are processed first (lines 1772–1990), then unlocks (lines 2001–2095). This is backwards.

**Required fix:** Swap the processing order: process unlocks first, then locks.

### 2.5 Unlock Array Offset Calculation Bug

**Location:** `smb1pdu.c:1992–1999`

```c
if (req->LockType & LOCKING_ANDX_LARGE_FILES)
    unlock_ele64 = (struct locking_andx_range64 *)(req->Locks +
            (sizeof(struct locking_andx_range64) * lock_count));
else
    unlock_ele32 = (struct locking_andx_range32 *)(req->Locks +
            (sizeof(struct locking_andx_range32) * lock_count));
```

**Bug:** The offset calculation is correct only when both arrays have the same element size, which happens to be true (64-bit uses RANGE64, 32-bit uses RANGE32). However, `req->Locks` is declared as `char *Locks[1]` (a pointer array, not a byte array). The arithmetic should use `(u8 *)req->Locks` to avoid UB. This is a type-safety issue.

**Also missing:** The spec requires that when `NumberOfUnlocks > 0` and `NumberOfLocks > 0`, the Unlocks array comes first in the Locks buffer (unlocks at offset 0, locks follow). The current code places Locks first and Unlocks second. This is another violation of §2.2.4.26 wire format.

Per MS-SMB §2.2.4.26.1:
```
Unlocks[NumberOfUnlocks]  { LOCKING_ANDX_RANGE }
Locks[NumberOfLocks]      { LOCKING_ANDX_RANGE }
```

The current code treats Locks[] as coming first in the byte stream, which is wrong when `NumberOfUnlocks > 0`.

**Required fix:**
```c
/* Spec: Unlocks come FIRST in the Locks buffer, then Locks */
if (req->LockType & LOCKING_ANDX_LARGE_FILES) {
    unlock_ele64 = (struct locking_andx_range64 *)
                   ((u8 *)req + sizeof(*req) - 1);
    lock_ele64 = unlock_ele64 + unlock_count;
} else {
    unlock_ele32 = (struct locking_andx_range32 *)
                   ((u8 *)req + sizeof(*req) - 1);
    lock_ele32 = unlock_ele32 + unlock_count;
}
```

---

## 3. SMB_COM_NT_CANCEL (0xA4) — Incomplete Implementation

### Current State

Handler `smb_nt_cancel()` is present and registered. The implementation (line 8183) walks `conn->requests` and sets `send_no_response = 1` on the matching work item. This is correct for cancelling a pending command that has not yet started processing, but has the following gaps:

### 3.1 Already-Blocked Work Not Cancelled

If the target work item has already been dispatched and is blocked inside a VFS operation (e.g., `ksmbd_vfs_posix_lock_wait_timeout()` in `smb_locking_andx()`), it will not be in `conn->requests` anymore, so the cancel will silently do nothing.

**Required fix:** After walking `conn->requests`, also walk a "pending lock" list (`conn->lock_list` already exists) to find any `ksmbd_lock` entries associated with the MID to cancel. Signal the waiter via `ksmbd_vfs_posix_lock_unblock()`.

### 3.2 NOTIFY_CHANGE Cancellation Not Implemented

When cancelling a pending `NT_TRANSACT_NOTIFY_CHANGE`, the server must:
1. Remove the fsnotify watch from the group.
2. Send `STATUS_CANCELLED` as the response to the original notify request.

The current `smb_nt_cancel()` does neither. A call to `ksmbd_notify_cancel_by_mid(conn, mid)` must be added (this function also needs to be created).

### 3.3 Sequence Number Decrement May Race

**Location:** `smb1pdu.c:8200`

```c
new_work->sess->sequence_number--;
```

This is done under `conn->request_lock` but without the session lock. If the session is accessed concurrently (e.g., another request on the same session), this is a data race.

**Required fix:** Either use atomic decrement or hold the session lock when modifying `sequence_number`.

---

## 4. Oplock Machinery — Present but Disabled

### Current State

- `smb1_oplock_enable` is declared at `smb1pdu.c:118` as `static int smb1_oplock_enable = false`.
- The oplock break notification path is fully implemented in `oplock.c:777` (`__smb1_oplock_break_noti()`).
- The grant path `smb_grant_oplock()` is called in `smb_nt_create_andx()` (line 2834), `smb_open_andx()` (line 5293), and `smb_trans2_spi()` (line 8593) — but only when `smb1_oplock_enable` is true.
- The acknowledge path `lock_oplock_release()` (line 1637) handles all three downgrade transitions correctly: Exclusive→None, Batch→None, Exclusive/Batch→Read, Read→None.

### 4.1 Enable Path Not Exposed

`smb1_oplock_enable` is a static variable with no module parameter and no sysfs or procfs knob. There is no way to enable it at runtime. The variable should be converted to a module parameter or a server config option.

**Required change:** Add to server configuration (`ksmbd_config.c`) or expose as a module parameter:
```c
module_param(smb1_oplock_enable, bool, 0644);
MODULE_PARM_DESC(smb1_oplock_enable, "Enable SMB1 oplock support (default: false)");
```

### 4.2 Oplock Break Notification Missing FID Validation

**Location:** `oplock.c:817` (`__smb1_oplock_break_noti()`)

```c
req->Fid = opinfo->fid;
```

The `opinfo->fid` is the `volatile_id` of the ksmbd file descriptor. This is correct for SMB1 since SMB1 uses 16-bit FIDs. However, there is no validation that `opinfo->fid` fits in a `u16`. If the FID table has grown beyond 65535 entries (unlikely in practice but possible with long uptime), this silently truncates.

**Required fix:**
```c
if (opinfo->fid > 0xFFFF) {
    pr_err("SMB1 oplock break: FID 0x%llx exceeds SMB1 range\n",
           opinfo->fid);
    goto out;
}
req->Fid = (u16)opinfo->fid;
```

### 4.3 Level II (Read) Oplock Grant Not Supported

**Current code:** `smb_grant_oplock()` is called with `oplock_flags` from the request, but the SMB1 oplock request mechanism in `smb_nt_create_andx()` maps `REQ_OPLOCK` to exclusive and `REQ_BATCHOPLOCK` to batch. There is no path to grant a Level II oplock at open time — the client must explicitly request it by sending a separate `LOCKING_ANDX` with `OPLOCK_READ` acknowledgement.

**Spec requirement (MS-SMB §3.3.4):** The server should grant Level II (read) oplock when the file is opened by a second client while the first client holds an exclusive/batch oplock, and the first client has acknowledged the break to Level II. The current `opinfo_write_to_read()` path handles the transition correctly, but the grant of initial Level II is not wired into the SMB1 open path.

### 4.4 Oplock Break Response Ignored on `smb_open_andx()`

**Location:** `smb1pdu.c:8593`

When `smb1_oplock_enable` is true and a second open triggers an oplock break, the `smb_grant_oplock()` call can fail with `-EINVAL` if the break acknowledgement is not received promptly. The current code uses `if (err) goto free_path` which closes the FP and returns an error to the client. This is correct but the client will retry the open without oplock, so this is not a bug — just a note that oplock contention on SMB1 opens causes a retry.

---

## 5. SMB_COM_ECHO (0x2B) — Behavioral Gap

### Current State

Handler `smb_echo()` is present (line 3535). The spec compliance is mostly correct. One gap:

### 5.1 EchoCount = 0 Handling

**Current code:**
```c
if (!echo_count) {
    work->send_no_response = true;
    return 0;
}
```

**Spec requirement (MS-SMB §2.2.4.35.2):** When `EchoCount = 0`, the server must send no response. The current code correctly sets `send_no_response = true`. This is compliant.

### 5.2 EchoCount Clamping Not Spec-Compliant

**Current code:**
```c
if (echo_count > 10)
    echo_count = 10;
```

**Spec:** There is no explicit cap in MS-SMB. The ECHO_DATA_MAX (`1024` bytes) is the data cap. The echo count cap is a KSMBD-specific anti-DoS measure, which is fine — but the limit of 10 is arbitrary. Consider documenting this as an intentional server-policy cap. The implementation is functionally correct.

### 5.3 SequenceNumber Off-By-One

**Current code (lines 3569–3574):**
```c
for (i = 1; i < echo_count && !work->send_no_response; i++) {
    rsp->SequenceNumber = cpu_to_le16(i);
    ksmbd_conn_write(work);
}
/* Last echo response */
rsp->SequenceNumber = cpu_to_le16(i);
```

**Spec requirement:** The `SequenceNumber` in each response must be the response index, starting from 1. The final `ksmbd_conn_write()` is handled by the caller framework. The last `rsp->SequenceNumber` is set to `i` after the loop — when `echo_count > 1`, `i == echo_count` at the end. This is correct. When `echo_count == 1`, the loop body is skipped and `i = 1`, which is also correct. The first response sent inline (before the loop) uses `SequenceNumber = 1` implicitly via the `i = 1` initial state — actually looking more carefully, the loop starts at `i = 1` and the first loop iteration sends `SequenceNumber = 1`. The pre-loop response at the top of the function (not shown in this snippet) would have `SequenceNumber = 0` (the zeroed struct). Let me clarify:

Actually reviewing the full echo handler: the initial memcpy and struct initialisation sets `rsp->SequenceNumber` to 0 implicitly. The loop sends responses 1 through `echo_count - 1`. The final `i = echo_count` sets the last response. The first response (`SequenceNumber = 0`) is wrong — the spec says responses are numbered 1 through EchoCount.

**Required fix:** Set `rsp->SequenceNumber = cpu_to_le16(1)` before the first implicit send, and start the loop at `i = 2`.

---

## 6. SMB_COM_QUERY_INFORMATION (0x08) — Attribute Mapping Gap

### Current State

Handler `smb_query_info()` is present (line 8324). The response WordCount=10 format is correct. The following gaps exist:

### 6.1 ATTR_ARCHIVE Not Mapped

**Current code (lines 8347–8353):**
```c
if (st.mode & S_ISVTX)
    attr |= (ATTR_HIDDEN | ATTR_SYSTEM);
if (!(st.mode & 0222))
    attr |= ATTR_READONLY;
if (S_ISDIR(st.mode))
    attr |= ATTR_DIRECTORY;
```

**Spec requirement (MS-SMB §2.2.4.8.2):** The `ATTR_ARCHIVE` bit (0x0020) should be set on all regular files by default. In Windows, archive means "this file has been modified since last backup." On Linux, we can conservatively set it for all regular files.

**Required fix:**
```c
if (S_ISREG(st.mode))
    attr |= ATTR_ARCHIVE;
```

### 6.2 LastWriteTime Units

**Current code (line 8355):**
```c
rsp->last_write_time = cpu_to_le32(st.mtime.tv_sec);
```

**Spec requirement (MS-SMB §2.2.4.8.2):** `LastWriteTime` is in seconds since 1970-01-01 00:00:00 UTC in the local timezone. This is exactly `st.mtime.tv_sec` in UTC. However, some clients expect it in local time. The correct value is UTC seconds, which is what is returned. This is spec-compliant but may cause display issues on timezone-naive clients. No change required, but document the behaviour.

### 6.3 FileSize Truncation for Large Files

**Current code (line 8356):**
```c
rsp->size = cpu_to_le32((u32)st.size);
```

**Spec requirement (MS-SMB §2.2.4.8.2):** `FileSize` is 32-bit. For files >= 4GB, this truncates silently. The spec says the response is `SMB_COM_QUERY_INFORMATION` which is inherently limited to 32-bit sizes. For large files, clients should use `TRANS2_QUERY_PATH_INFORMATION` or `TRANS2_QUERY_FILE_INFORMATION` which support 64-bit sizes. No fix is needed, but a log warning would help:

```c
if (st.size > U32_MAX)
    ksmbd_debug(SMB, "QUERY_INFO: truncating file size %lld to 32-bit\n",
                st.size);
rsp->size = cpu_to_le32((u32)st.size);
```

---

## 7. SMB_COM_SETATTR (0x09) — Gaps

### Current State

Handler `smb_setattr()` is present (line 8742). The following gaps exist:

### 7.1 LastWriteTime = 0 vs. 0xFFFFFFFF Semantics

**Current code (lines 8788–8789):**
```c
attrs.ia_mtime.tv_sec = le32_to_cpu(req->LastWriteTime);
attrs.ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET);
```

**Spec requirement (MS-SMB §2.2.4.9.1):**
- `LastWriteTime = 0`: do not change the modification time.
- `LastWriteTime = 0xFFFFFFFF`: set to server's current time.
- Any other value: set to that time.

**Required fix:**
```c
u32 write_time = le32_to_cpu(req->LastWriteTime);
if (write_time == 0) {
    /* Do not change mtime */
} else if (write_time == 0xFFFFFFFF) {
    attrs.ia_mtime = current_time(d_inode(path.dentry));
    attrs.ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET);
} else {
    attrs.ia_mtime.tv_sec = write_time;
    attrs.ia_mtime.tv_nsec = 0;
    attrs.ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET);
}
```

### 7.2 ATTR_READONLY Only Attribute Mapped

**Current code (lines 8778–8786):**

Only `ATTR_READONLY` is mapped to the Linux mode. The full SMB attribute set includes:
- `ATTR_HIDDEN` (0x0002): no Linux equivalent; can be stored in xattr.
- `ATTR_SYSTEM` (0x0004): no Linux equivalent; can be stored in xattr.
- `ATTR_ARCHIVE` (0x0020): no Linux equivalent; can be stored in xattr.

When `KSMBD_SHARE_FLAG_STORE_DOS_ATTRS` is set, these should be stored via `ksmbd_vfs_set_dos_attrib_xattr()` (the same function used by `set_path_info()` for `TRANS2_SET_PATH_INFORMATION`).

---

## 8. SMB_COM_QUERY_INFORMATION2 (0x23) and SMB_COM_SET_INFORMATION2 (0x22) — Completely Missing

### Current State

**Neither command has a handler.** Both `SMB_COM_QUERY_INFORMATION2` (0x23) and `SMB_COM_SET_INFORMATION2` (0x22) are absent from `smb1_server_cmds[]` in `smb1ops.c`. There are no corresponding handler functions in `smb1pdu.c`. There are no corresponding structures in `smb1pdu.h`.

When a client sends either command, `ksmbd_smb1_check_message()` returns 1 (error) because `smb1_req_struct_size()` hits the `default: return -EOPNOTSUPP` case (line 116 in `smb1misc.c`).

### 8.1 SMB_COM_QUERY_INFORMATION2 (0x23)

**Spec:** MS-SMB §2.2.4.24

**Request format (WordCount = 1):**
```c
struct smb_com_query_info2_req {
    struct smb_hdr hdr;  /* wct = 1 */
    __u16 Fid;
    __le16 ByteCount;    /* 0 */
} __packed;
```

**Response format (WordCount = 11):**
```c
struct smb_com_query_info2_rsp {
    struct smb_hdr hdr;        /* wct = 11 */
    __le16 CreateDate;         /* SMB Date */
    __le16 CreateTime;         /* SMB Time */
    __le16 LastAccessDate;
    __le16 LastAccessTime;
    __le16 LastWriteDate;
    __le16 LastWriteTime;
    __le32 FileDataSize;       /* EOF, 32-bit */
    __le32 FileAllocationSize;
    __le16 FileAttributes;
    __le16 ByteCount;          /* 0 */
} __packed;
```

**SMB Date/Time format:** These use the legacy DOS date/time format, not NTFS FILETIME or Unix time:
```
SMB Date: bits [15:9] = year-1980, bits [8:5] = month (1–12), bits [4:0] = day (1–31)
SMB Time: bits [15:11] = hours (0–23), bits [10:5] = minutes (0–59), bits [4:0] = seconds/2 (0–29)
```

Conversion function required:
```c
static __le16 unix_to_smb_date(time64_t t)
{
    struct tm tm;
    time64_to_tm(t, 0, &tm);
    return cpu_to_le16(((tm.tm_year - 80) << 9) |
                       ((tm.tm_mon + 1) << 5) |
                       tm.tm_mday);
}

static __le16 unix_to_smb_time(time64_t t)
{
    struct tm tm;
    time64_to_tm(t, 0, &tm);
    return cpu_to_le16((tm.tm_hour << 11) |
                       (tm.tm_min << 5) |
                       (tm.tm_sec / 2));
}
```

**Handler:**
```c
int smb_query_information2(struct ksmbd_work *work)
{
    struct smb_com_query_info2_req *req = work->request_buf;
    struct smb_com_query_info2_rsp *rsp = work->response_buf;
    struct ksmbd_file *fp;
    struct kstat st;
    int err;

    fp = ksmbd_lookup_fd_fast(work, req->Fid);
    if (!fp) {
        rsp->hdr.Status.CifsError = STATUS_INVALID_HANDLE;
        return -EINVAL;
    }

    err = vfs_getattr(&fp->filp->f_path, &st, STATX_BASIC_STATS,
                      AT_STATX_SYNC_AS_STAT);
    ksmbd_fd_put(work, fp);
    if (err) {
        rsp->hdr.Status.CifsError = STATUS_INVALID_HANDLE;
        return err;
    }

    rsp->hdr.Status.CifsError = STATUS_SUCCESS;
    rsp->hdr.WordCount = 11;

    /* Creation time (use btime if available, else ctime) */
    time64_t ctime = (st.result_mask & STATX_BTIME) ?
                     st.btime.tv_sec : st.ctime.tv_sec;
    rsp->CreateDate = unix_to_smb_date(ctime);
    rsp->CreateTime = unix_to_smb_time(ctime);

    rsp->LastAccessDate = unix_to_smb_date(st.atime.tv_sec);
    rsp->LastAccessTime = unix_to_smb_time(st.atime.tv_sec);
    rsp->LastWriteDate  = unix_to_smb_date(st.mtime.tv_sec);
    rsp->LastWriteTime  = unix_to_smb_time(st.mtime.tv_sec);

    rsp->FileDataSize       = cpu_to_le32((u32)st.size);
    rsp->FileAllocationSize = cpu_to_le32((u32)st.blksize * st.blocks / 512);

    __u16 attr = 0;
    if (!(st.mode & 0222))
        attr |= ATTR_READONLY;
    if (S_ISDIR(st.mode))
        attr |= ATTR_DIRECTORY;
    if (S_ISREG(st.mode))
        attr |= ATTR_ARCHIVE;
    rsp->FileAttributes = cpu_to_le16(attr);
    rsp->ByteCount = 0;

    inc_rfc1001_len(&rsp->hdr, rsp->hdr.WordCount * 2);
    return 0;
}
```

**Register in smb1ops.c:**
```c
[SMB_COM_QUERY_INFORMATION2] = { .proc = smb_query_information2, },
```

**Register in smb1misc.c** (`smb1_req_struct_size()`):
```c
case SMB_COM_QUERY_INFORMATION2:
    if (wc != 0x1)
        return -EINVAL;
    break;
```

### 8.2 SMB_COM_SET_INFORMATION2 (0x22)

**Spec:** MS-SMB §2.2.4.23

**Request format (WordCount = 7):**
```c
struct smb_com_set_info2_req {
    struct smb_hdr hdr;         /* wct = 7 */
    __u16 Fid;
    __le16 CreateDate;
    __le16 CreateTime;
    __le16 LastAccessDate;
    __le16 LastAccessTime;
    __le16 LastWriteDate;
    __le16 LastWriteTime;
    __le16 ByteCount;           /* 0 */
} __packed;
```

**Response format (WordCount = 0):**
```c
struct smb_com_set_info2_rsp {
    struct smb_hdr hdr;         /* wct = 0 */
    __le16 ByteCount;           /* 0 */
} __packed;
```

**Spec rule:** `Date = 0` or `Time = 0` means "do not change." Only set the timestamp if both the Date and Time fields are non-zero.

**Handler:**
```c
int smb_set_information2(struct ksmbd_work *work)
{
    struct smb_com_set_info2_req *req = work->request_buf;
    struct smb_com_set_info2_rsp *rsp = work->response_buf;
    struct ksmbd_file *fp;
    struct iattr attrs = {};
    int err;

    fp = ksmbd_lookup_fd_fast(work, req->Fid);
    if (!fp) {
        rsp->hdr.Status.CifsError = STATUS_INVALID_HANDLE;
        return -EINVAL;
    }

    /*
     * Spec: set timestamp only if both Date and Time are non-zero.
     * CreateDate/Time: no POSIX equivalent for birth time setting.
     */
    if (req->LastAccessDate && req->LastAccessTime) {
        attrs.ia_atime.tv_sec = smb_date_time_to_unix(
                                    le16_to_cpu(req->LastAccessDate),
                                    le16_to_cpu(req->LastAccessTime));
        attrs.ia_atime.tv_nsec = 0;
        attrs.ia_valid |= ATTR_ATIME | ATTR_ATIME_SET;
    }

    if (req->LastWriteDate && req->LastWriteTime) {
        attrs.ia_mtime.tv_sec = smb_date_time_to_unix(
                                    le16_to_cpu(req->LastWriteDate),
                                    le16_to_cpu(req->LastWriteTime));
        attrs.ia_mtime.tv_nsec = 0;
        attrs.ia_valid |= ATTR_MTIME | ATTR_MTIME_SET;
    }

    if (attrs.ia_valid) {
        err = notify_change(mnt_idmap(fp->filp->f_path.mnt),
                            fp->filp->f_path.dentry,
                            &attrs, NULL);
    } else {
        err = 0;
    }

    ksmbd_fd_put(work, fp);

    if (!err) {
        rsp->hdr.Status.CifsError = STATUS_SUCCESS;
        rsp->hdr.WordCount = 0;
        rsp->ByteCount = 0;
        inc_rfc1001_len(&rsp->hdr, 0);
    } else {
        rsp->hdr.Status.CifsError = STATUS_ACCESS_DENIED;
    }
    return err;
}
```

**Required helper:**
```c
static time64_t smb_date_time_to_unix(__u16 date, __u16 time)
{
    struct tm tm = {
        .tm_year = ((date >> 9) & 0x7f) + 80,
        .tm_mon  = ((date >> 5) & 0x0f) - 1,
        .tm_mday = date & 0x1f,
        .tm_hour = (time >> 11) & 0x1f,
        .tm_min  = (time >> 5) & 0x3f,
        .tm_sec  = (time & 0x1f) * 2,
    };
    return mktime64(1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec);
}
```

**Register in smb1ops.c:**
```c
[SMB_COM_SET_INFORMATION2] = { .proc = smb_set_information2, },
```

**Register in smb1misc.c** (`smb1_req_struct_size()`):
```c
case SMB_COM_SET_INFORMATION2:
    if (wc != 0x7)
        return -EINVAL;
    break;
```

---

## 9. Response Envelope Helper Functions

All NT_TRANSACT handlers share a common response building pattern. The following helper functions must be added to avoid code duplication:

```c
/**
 * smb_build_nt_transact_rsp() - Build NT_TRANSACT response envelope
 * @work:           current work
 * @param_buf:     parameter buffer to embed (may be NULL)
 * @param_len:     length of param_buf in bytes
 * @data_buf:      data buffer to embed (may be NULL)
 * @data_len:      length of data_buf in bytes
 *
 * Fills in the NT_TRANSACT response header (WordCount=18) and copies
 * param_buf and data_buf into the response, properly aligned.
 * The response is placed at work->response_buf.
 */
static int smb_build_nt_transact_rsp(struct ksmbd_work *work,
                                      const void *param_buf, u32 param_len,
                                      const void *data_buf, u32 data_len)
{
    struct smb_com_ntransact_rsp *rsp = work->response_buf;
    unsigned int hdr_size = sizeof(struct smb_hdr) - 4;
    unsigned int fixed_size = sizeof(struct smb_com_ntransact_rsp);
    unsigned int total = fixed_size + 3 /* pad */ + param_len +
                         (param_len % 4 ? 4 - (param_len % 4) : 0) +
                         data_len;

    /* Verify buffer is large enough */
    if (total > work->response_sz)
        return -ENOMEM;

    /* Fill NT_TRANSACT response header fields */
    rsp->hdr.WordCount = 18;
    rsp->TotalParameterCount = cpu_to_le32(param_len);
    rsp->TotalDataCount      = cpu_to_le32(data_len);
    rsp->ParameterCount      = cpu_to_le32(param_len);

    /* Parameter offset: from start of SMB header */
    unsigned int param_off = fixed_size + 3 /* pad */ - 4 /* smb_buf_len */;
    rsp->ParameterOffset      = cpu_to_le32(param_off);
    rsp->ParameterDisplacement = 0;

    unsigned int param_aligned = param_len + (param_len % 4 ?
                                               4 - (param_len % 4) : 0);
    rsp->DataCount             = cpu_to_le32(data_len);
    rsp->DataOffset            = cpu_to_le32(param_off + param_aligned);
    rsp->DataDisplacement      = 0;
    rsp->SetupCount            = 0;
    rsp->ByteCount             = cpu_to_le16(3 + param_len + param_aligned +
                                             data_len - param_len);

    u8 *out = (u8 *)rsp + fixed_size;
    memset(out, 0, 3);
    out += 3;

    if (param_buf && param_len)
        memcpy(out, param_buf, param_len);
    out += param_aligned;

    if (data_buf && data_len)
        memcpy(out, data_buf, data_len);

    inc_rfc1001_len(&rsp->hdr, (rsp->hdr.WordCount * 2) +
                    le16_to_cpu(rsp->ByteCount));
    rsp->hdr.Status.CifsError = STATUS_SUCCESS;
    return 0;
}
```

---

## 10. Implementation Phases

### Phase A — Critical (Blocks real client usage)

| Item | Files | Effort |
|------|-------|--------|
| NT_TRANSACT dispatcher (§1.3) | `smb1ops.c`, `smb1misc.c`, `smb1pdu.c` | 4h |
| NT_TRANSACT wire structures (§1.2) | `smb1pdu.h` | 2h |
| NT_TRANSACT_QUERY_SECURITY_DESC (§1.9) | `smb1pdu.c` | 3h |
| NT_TRANSACT_SET_SECURITY_DESC (§1.8) | `smb1pdu.c` | 3h |
| SMB_COM_QUERY_INFORMATION2 (§8.1) | `smb1ops.c`, `smb1misc.c`, `smb1pdu.c`, `smb1pdu.h` | 3h |
| SMB_COM_SET_INFORMATION2 (§8.2) | `smb1ops.c`, `smb1misc.c`, `smb1pdu.c`, `smb1pdu.h` | 3h |
| Response envelope helper (§9) | `smb1pdu.c` | 2h |

### Phase B — Correctness (Breaks real workloads under load)

| Item | Files | Effort |
|------|-------|--------|
| Locking: unlock-before-lock ordering (§2.4) | `smb1pdu.c` | 1h |
| Locking: Timeout -1 / 0 semantics (§2.2) | `smb1pdu.c` | 2h |
| Locking: CANCEL_LOCK (§2.1) | `smb1pdu.c` | 4h |
| Locking: Locks[] array offset bug (§2.5) | `smb1pdu.c` | 1h |
| LOCKING_ANDX_CHANGE_LOCKTYPE NTSTATUS fix (§2.3) | `smb1pdu.c` | 30m |
| NT_CANCEL: blocked work cancellation (§3.1) | `smb1pdu.c` | 3h |
| SETATTR: LastWriteTime 0/FFFFFFFF (§7.1) | `smb1pdu.c` | 1h |
| QUERY_INFO: ATTR_ARCHIVE mapping (§6.1) | `smb1pdu.c` | 30m |

### Phase C — Feature Complete

| Item | Files | Effort |
|------|-------|--------|
| NT_TRANSACT_CREATE (§1.4) | `smb1pdu.c`, `smb1pdu.h` | 6h |
| NT_TRANSACT_IOCTL (§1.5) | `smb1pdu.c` | 4h |
| NT_TRANSACT_RENAME (§1.6) | `smb1pdu.c`, `vfs.c` | 3h |
| NT_TRANSACT_NOTIFY_CHANGE (§1.7) | `smb1pdu.c`, `ksmbd_notify.c` | 8h |
| NT_CANCEL: NOTIFY_CHANGE cancellation (§3.2) | `smb1pdu.c`, `ksmbd_notify.c` | 3h |
| Oplock: enable module parameter (§4.1) | `smb1pdu.c`, `ksmbd_config.c` | 1h |

### Phase D — Optional/Infrastructure

| Item | Files | Effort |
|------|-------|--------|
| NT_TRANSACT_GET_USER_QUOTA (§1.10) | `smb1pdu.c`, `ksmbd_quota.c` | 4h |
| NT_TRANSACT_SET_USER_QUOTA (§1.11) | `smb1pdu.c`, `ksmbd_quota.c` | 3h |
| NT_TRANSACT_SECONDARY reassembly | `smb1pdu.c` | 8h |
| Echo SequenceNumber off-by-one (§5.3) | `smb1pdu.c` | 30m |
| SETATTR: xattr-backed DOS attrs (§7.2) | `smb1pdu.c` | 2h |
| NT_CANCEL: sequence_number race (§3.3) | `smb1pdu.c` | 1h |
| Oplock: FID overflow check (§4.2) | `oplock.c` | 30m |

---

## 11. Testing Checklist

For each implemented item, test with:

```bash
# NT_TRANSACT security descriptor (requires working SMB1 client)
smbclient //server/share -U user -m NT1 -c "ls"
# Then use Windows XP or wine's smbclient to exercise NT_TRANSACT

# Lock tests
locktest -N 100 //server/share

# Echo test
smbtorture //server/share SMB-BENCH-LOCK

# Attribute tests (legacy DOS client behaviour)
smbclient //server/share -U user -m NT1 -c "allinfo filename"
```

Wireshark dissection of captured traffic against a reference Windows 2003 Server implementation is the definitive validator for NT_TRANSACT wire format conformance.

---

## 12. Spec References

| Section | Topic |
|---------|-------|
| MS-SMB §2.2.4.62 | SMB_COM_NT_TRANSACT request/response format |
| MS-SMB §2.2.4.62.5–6 | NT_TRANSACT_CREATE request/response |
| MS-SMB §2.2.4.62.9–10 | NT_TRANSACT_IOCTL request/response |
| MS-SMB §2.2.4.62.11–12 | NT_TRANSACT_SET_SECURITY_DESC |
| MS-SMB §2.2.4.62.13–14 | NT_TRANSACT_NOTIFY_CHANGE |
| MS-SMB §2.2.4.62.15–16 | NT_TRANSACT_RENAME |
| MS-SMB §2.2.4.62.17–18 | NT_TRANSACT_QUERY_SECURITY_DESC |
| MS-SMB §2.2.4.62.19–20 | NT_TRANSACT_GET_USER_QUOTA |
| MS-SMB §2.2.4.62.21 | NT_TRANSACT_SET_USER_QUOTA |
| MS-SMB §2.2.4.26 | SMB_COM_LOCKING_ANDX |
| MS-SMB §2.2.4.65 | SMB_COM_NT_CANCEL |
| MS-SMB §2.2.4.35 | SMB_COM_ECHO |
| MS-SMB §2.2.4.8 | SMB_COM_QUERY_INFORMATION |
| MS-SMB §2.2.4.9 | SMB_COM_SETATTR |
| MS-SMB §2.2.4.23 | SMB_COM_SET_INFORMATION2 |
| MS-SMB §2.2.4.24 | SMB_COM_QUERY_INFORMATION2 |
| MS-SMB §3.3.4 | Oplock break semantics |
| MS-DTYP §2.4.7 | SECURITY_INFORMATION flags |
| MS-FSCC §2.4.33 | FILE_QUOTA_INFORMATION |
| MS-FSCC §2.7 | FSCTL codes |
